//! PHASE 4BU — BFT API hardening: signature authorisation, lock encapsulation,
//! provisional unlock removal.
//!
//! # What is under test
//!
//! Mission BT measured three open API boundaries in the safety layer:
//!
//! * P1 — `BftState::persisted` was a public field, so any caller could erase the
//!   in-memory lock and sign a contradictory value (`bt_16`);
//! * P2 — `l2persist::sign_vote` was callable on its own, so the `A4'` guard that
//!   lives in `BftState::check_prevote_admissible` could be skipped (`bt_15`);
//! * P3 — `apply_provisional_unlock` / `apply_and_persist` were public and moved
//!   the lock, although `AW-LOCK-5` forbids unlocking (`bt_17`).
//!
//! BU closes all three: the field is private behind `persisted()`, `sign_vote`
//! requires a [`VoteAuthorization`] whose only constructors re-run the full rule,
//! and the unlock functions were deleted.
//!
//! # How the sixteen scenarios of §6 are covered
//!
//! | §6 | Here | Kind |
//! |---|---|---|
//! | 1 signature without authorisation | `bu_01`, CF-3 | runtime + compile |
//! | 2 direct `VoteAuthorization` construction | `bu_02`, CF-1 | runtime + compile |
//! | 3 writing `persisted` | `bu_03`, CF-2 | runtime + compile |
//! | 4 other height | `bu_04` | runtime |
//! | 5 other generation | `bu_05` | runtime |
//! | 6 other round | `bu_06` | runtime |
//! | 7 other value | `bu_07` | runtime |
//! | 8 other phase | `bu_08` | runtime |
//! | 9 POL absent | `bu_09` | runtime |
//! | 10 POL invalid | `bu_10` | runtime |
//! | 11 POL of another generation | `bu_11` | runtime |
//! | 12 POL with insufficient quorum | `bu_12` | runtime |
//! | 13 valid POL authorises the change | `bu_13` | runtime |
//! | 14 restart after a lock change | `bu_14` | runtime |
//! | 15 direct `apply_provisional_unlock` | `bu_15`, CF-4 | runtime + compile |
//! | 16 race between contradictory authorisations | `bu_16` | runtime |
//!
//! The `CF-*` column names the snippets of `scripts/compile-fail-bu.sh`, which
//! compiles each one against the real rlib and requires a specific error code. A
//! runtime test cannot show that something does not compile; the script is the
//! evidence for §7, and `security-tests.md` records its output.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{
    restore_engine, BftError, BftState, PrevoteCertificate, ProofOfLock, VoteOutcome,
};
use aether_unified::l2crypto::qc::QuorumCertificate;
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::{
    open_sealed, sign_vote, AtomicSlotStore, CasStore, EmitError, MemoryAtomicSlotStore,
    PersistentConsensusState, SlotKey, SlotReservation, VoteAuthorization, SLOT_PREFIX, STATE_KEY,
};

const NET: u64 = 43;
const ANCHOR: [u8; 32] = [0x5A; 32];
const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];
const C: [u8; 32] = [0xC3; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn gen() -> GenerationId {
    GenerationId([7u8; 32])
}

fn reg() -> ValidatorRegistry {
    registry_for([7u8; 32])
}

/// Four validators of weight 10: quorum is 27 of 40, so three signers are needed
/// and two can never certify anything.
fn registry_for(generation: [u8; 32]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = [(1u8, 10u64), (2, 10), (3, 10), (4, 10)]
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(generation), &entries).expect("registry")
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn vote(
    generation: [u8; 32],
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
    seed: u8,
) -> ConsensusVote {
    let mut v = ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: GenerationId(generation),
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        checkpoint_id: value,
        validator: vid(seed),
        signature: [0u8; 64],
    };
    v.signature = sk(seed).sign(&v.signing_bytes()).to_bytes();
    v
}

/// The same vote, still unsigned: what a caller hands to `sign_vote`.
fn unsigned(
    generation: [u8; 32],
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
    seed: u8,
) -> ConsensusVote {
    let mut v = vote(generation, height, round, phase, value, seed);
    v.signature = [0u8; 64];
    v
}

fn engine_with(registry: &ValidatorRegistry, height: u64) -> BftState {
    BftState::new(NET, registry, CheckpointHeight(height), ANCHOR)
}

/// A quorate prevote certificate for `value` at `round`, produced by a real
/// engine with real Ed25519 keys: validator 1 signs through the engine, 2 and 3
/// are injected as received votes.
fn prevote_certificate_at(
    engine: &mut BftState,
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    height: u64,
    round: u32,
    value: [u8; 32],
) -> PrevoteCertificate {
    if engine.round.get() < round {
        engine.begin_round(Round(round)).expect("round");
    }
    engine.propose(value).expect("propose");
    engine
        .prevote(value, vid(1), registry, store, sign_with(1))
        .expect("own prevote");
    for seed in [2u8, 3u8] {
        let v = vote(
            registry.generation().0,
            height,
            round,
            VotePhase::Prevote,
            value,
            seed,
        );
        assert!(matches!(
            engine.accept_vote(&v, registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    engine
        .certify_prevotes_for(value, registry)
        .expect("quorate prevote certificate")
}

/// Lock `value` at `round` through the precommit path (`AW-LOCK-2`).
fn lock_at(
    engine: &mut BftState,
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    height: u64,
    round: u32,
    value: [u8; 32],
) -> ProofOfLock {
    let certificate = prevote_certificate_at(engine, store, registry, height, round, value);
    engine
        .precommit(&certificate, vid(1), registry, store, sign_with(1))
        .expect("precommit writes the lock");
    ProofOfLock::from_prevote(certificate)
}

/// The durable vote, if any, for one position of validator 1.
fn durable_vote(
    store: &dyn AtomicSlotStore,
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
) -> Option<ConsensusVote> {
    let key = SlotKey {
        generation: gen().0,
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        validator: vid(1),
    };
    store
        .load(&key)
        .expect("load")
        .and_then(|record| record.vote)
        .filter(|v| v.checkpoint_id == value)
}

fn assert_never_signed(
    store: &dyn AtomicSlotStore,
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
) {
    assert!(
        durable_vote(store, height, round, phase, value).is_none(),
        "no signature may exist for {phase} {round} at height {height}"
    );
}

fn slots(store: &dyn AtomicSlotStore) -> Vec<SlotReservation> {
    store
        .scan(SLOT_PREFIX)
        .expect("scan")
        .into_iter()
        .map(|(_, bytes)| {
            SlotReservation::decode(open_sealed(&bytes).expect("envelope")).expect("slot record")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// §6.1 — a signature cannot be produced without an authorisation.
// ---------------------------------------------------------------------------

/// BT-15's exact vote: state locked on `A` at round 1, prevote for `B` at round
/// 2. `signing_check` alone still admits it — that is the gap BT measured — but
/// no [`VoteAuthorization`] can be built for it, and `sign_vote` is unreachable
/// without one (compile-fail CF-3).
#[test]
fn bu_01_a_caller_without_an_authorization_cannot_sign() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    let state = engine.persisted().clone();

    let contradictory = vote(gen().0, 0, 2, VotePhase::Prevote, B, 1);
    // The primitive's own guard, unchanged, still admits this vote.
    assert!(
        state.signing_check(&contradictory).is_ok(),
        "signing_check admits a contradiction above lockR, by design"
    );
    // The authorisation is what refuses it.
    match VoteAuthorization::for_prevote(&state, &contradictory, None, &registry) {
        Err(EmitError::NotAuthorized(reason)) => {
            assert!(reason.contains("proof of lock"), "reason: {reason}");
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);
    assert_eq!(state.locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// §6.2 — an authorisation cannot be fabricated, and it is bound to its state.
// ---------------------------------------------------------------------------

/// `VoteAuthorization` has private fields and no `Default`/`Deserialize`; the
/// snippets CF-1 and CF-5 show that a caller cannot write one or decode one.
///
/// What can be done at runtime is this: tamper with a **record** and try to get
/// permission out of it. A record is not an authorisation — every constructor
/// re-reads the lock, so a forged lock grants nothing.
#[test]
fn bu_02_a_forged_state_record_yields_no_authorization() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // The bytes on disk, decoded and tampered: the lock now claims `B`.
    let genuine = engine.persisted().clone();
    let mut forged = PersistentConsensusState::decode(&genuine.encode()).expect("decode");
    forged.locked = Some(aether_unified::l2persist::LockedValue {
        checkpoint_id: B,
        round: Round(2),
        height: CheckpointHeight(0),
    });

    // A forged record grants exactly one thing: permission to sign the value it
    // claims to be locked on. It cannot bless the value the tamper displaced.
    let for_a = unsigned(gen().0, 0, 3, VotePhase::Prevote, A, 1);
    match VoteAuthorization::for_prevote(&forged, &for_a, None, &registry) {
        Err(EmitError::NotAuthorized(reason)) => {
            assert!(reason.contains("proof of lock"), "reason: {reason}");
        }
        other => panic!("expected NotAuthorized for the displaced value, got {other:?}"),
    }

    // For `B` the record does authorise — but only as "the locked value", with no
    // POL and with the honest lock named. That is not a value *change*: it is the
    // record contradicting itself, and the retained proof still names `A`.
    let for_b = unsigned(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    let authorization = VoteAuthorization::for_prevote(&forged, &for_b, None, &registry)
        .expect("the declared lock is signable");
    assert_eq!(authorization.lock_value(), B);
    assert_eq!(authorization.pol_qc_id(), None, "no POL was ever supplied");
    assert_eq!(
        genuine.proof_of_lock.as_ref().map(|p| p.qc_id).is_some(),
        true
    );

    assert_never_signed(&store, 0, 3, VotePhase::Prevote, A);
    assert_never_signed(&store, 0, 3, VotePhase::Prevote, B);

    // The genuine record was never touched by any of this.
    assert_eq!(genuine.locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// §6.3 — `persisted` is read-only from outside.
// ---------------------------------------------------------------------------

/// The engine's memory and the durable record never disagree: `persisted()`
/// exposes the very state the engine persists, and no caller can assign it
/// (CF-2). The accessor is the only window, and it returns `&`.
#[test]
fn bu_03_the_persisted_state_is_read_only_and_matches_the_record() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    assert!(engine.persisted().locked.is_none());

    lock_at(&mut engine, &store, &registry, 0, 1, A);

    let view = engine.persisted();
    assert_eq!(view.locked.map(|l| l.checkpoint_id), Some(A));
    assert_eq!(view.locked.map(|l| l.round), Some(Round(1)));
    assert_eq!(view.generation, gen());
    assert!(view.proof_of_lock.is_some(), "the POL is recorded");

    // The durable record decoded back says exactly the same thing.
    let bytes = store
        .get(STATE_KEY)
        .expect("state read")
        .expect("state present");
    let durable =
        PersistentConsensusState::decode(open_sealed(&bytes).expect("envelope")).expect("decode");
    assert_eq!(durable.locked, view.locked);
    assert_eq!(durable.generation, view.generation);
    assert_eq!(durable.status, view.status);
}

// ---------------------------------------------------------------------------
// §6.4 - §6.8 — the authorisation is bound to every signed field.
// ---------------------------------------------------------------------------

/// One valid authorisation, then five attempts to use it elsewhere. All five are
/// refused by `covers`, before the store is even consulted, and none leaves a
/// durable signature.
#[test]
fn bu_04_to_bu_08_an_authorization_is_bound_to_height_generation_round_value_and_phase() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let state = PersistentConsensusState::fresh(NET, gen(), ANCHOR);
    let signed = unsigned(gen().0, 0, 0, VotePhase::Prevote, A, 1);
    let authorization =
        VoteAuthorization::for_prevote(&state, &signed, None, &registry).expect("admitted");

    // The control: the same vote is accepted.
    assert!(authorization.covers(&signed));

    let cases: [(&str, ConsensusVote, u64); 5] = [
        (
            "bu_04 other height",
            unsigned(gen().0, 1, 0, VotePhase::Prevote, A, 1),
            1,
        ),
        (
            "bu_05 other generation",
            unsigned([8u8; 32], 0, 0, VotePhase::Prevote, A, 1),
            0,
        ),
        (
            "bu_06 other round",
            unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1),
            0,
        ),
        (
            "bu_07 other value",
            unsigned(gen().0, 0, 0, VotePhase::Prevote, B, 1),
            0,
        ),
        (
            "bu_08 other phase",
            unsigned(gen().0, 0, 0, VotePhase::Precommit, A, 1),
            0,
        ),
    ];

    let refused = Arc::new(AtomicUsize::new(0));
    for (label, other, height) in cases {
        assert!(
            !authorization.covers(&other),
            "{label}: covers must be false"
        );
        match sign_vote(
            &state,
            &store,
            &registry,
            &other,
            &authorization,
            sign_with(1),
        ) {
            Err(EmitError::NotAuthorized(reason)) => {
                assert!(
                    reason.contains("another vote"),
                    "{label}: unexpected reason {reason}"
                );
                refused.fetch_add(1, Ordering::SeqCst);
            }
            other => panic!("{label}: expected NotAuthorized, got {other:?}"),
        }
        assert_never_signed(
            &store,
            height,
            other.round.get(),
            other.phase,
            other.checkpoint_id,
        );
    }
    assert_eq!(refused.load(Ordering::SeqCst), 5);
    // The authorisation itself is untouched and still usable for its own vote.
    assert!(authorization.covers(&signed));
}

// ---------------------------------------------------------------------------
// §6.9 — no proof of lock.
// ---------------------------------------------------------------------------

#[test]
fn bu_09_a_missing_pol_is_refused_by_the_authorization() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    let state = engine.persisted().clone();

    let candidate = vote(gen().0, 0, 2, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(&state, &candidate, None, &registry) {
        Err(EmitError::NotAuthorized(reason)) => {
            assert!(reason.contains("proof of lock"), "reason: {reason}");
            assert!(
                reason.contains("round 1"),
                "the lock round is named: {reason}"
            );
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);

    // And the engine path agrees, one layer above.
    engine.begin_round(Round(2)).expect("round 2");
    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

// ---------------------------------------------------------------------------
// §6.10 — an invalid POL cannot exist.
// ---------------------------------------------------------------------------

/// A POL is a `ProofOfLock`, and its only constructor takes a verified
/// `PrevoteCertificate`. A tampered certificate therefore cannot become a POL in
/// the first place, so there is no "invalid POL" to hand to the authorisation.
#[test]
fn bu_10_a_tampered_certificate_never_becomes_a_pol() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let genuine = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);

    let mut qc = QuorumCertificate::decode(&genuine.encode()).expect("decode");
    qc.votes[1].signature[3] ^= 0xFF;
    let error = PrevoteCertificate::from_bytes(&qc.encode(), &registry, NET)
        .expect_err("a flipped signature byte is not a signature");
    let text = format!("{error:?}");
    assert!(
        text.contains("bad vote signature"),
        "expected BadSignature, got {text}"
    );

    // A signature from a validator outside the set is refused the same way.
    let mut unknown = QuorumCertificate::decode(&genuine.encode()).expect("decode");
    unknown.votes[1].validator = vid(9);
    assert!(PrevoteCertificate::from_bytes(&unknown.encode(), &registry, NET).is_err());
    // The genuine certificate still verifies, so the refusals above are about the
    // tampering and nothing else.
    assert!(genuine.re_verify(&registry, NET).is_ok());
}

// ---------------------------------------------------------------------------
// §6.11 — a POL from another generation.
// ---------------------------------------------------------------------------

#[test]
fn bu_11_a_pol_of_another_generation_authorises_nothing() {
    let foreign = registry_for([8u8; 32]);
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = BftState::new(NET, &foreign, CheckpointHeight(0), ANCHOR);
    let certificate = prevote_certificate_at(&mut producer, &producer_store, &foreign, 0, 2, B);
    let foreign_pol = ProofOfLock::from_prevote(certificate);
    assert_eq!(foreign_pol.generation, GenerationId([8u8; 32]));

    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    let state = engine.persisted().clone();

    let candidate = vote(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(&state, &candidate, Some(&foreign_pol), &registry) {
        Err(EmitError::NotAuthorized(reason)) => {
            assert!(reason.contains("re-verify"), "reason: {reason}");
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert_never_signed(&store, 0, 3, VotePhase::Prevote, B);

    engine.begin_round(Round(3)).expect("round 3");
    assert!(matches!(
        engine.prevote_with_proof(
            B,
            Some(&foreign_pol),
            vid(1),
            &registry,
            &store,
            sign_with(1)
        ),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

// ---------------------------------------------------------------------------
// §6.12 — a POL below quorum.
// ---------------------------------------------------------------------------

#[test]
fn bu_12_a_pol_below_quorum_cannot_be_built() {
    let registry = reg();
    // Two of four validators of weight 10: 20 of 40, below the 27 quorum.
    let votes = vec![
        vote(gen().0, 0, 2, VotePhase::Prevote, B, 1),
        vote(gen().0, 0, 2, VotePhase::Prevote, B, 2),
    ];
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(0),
        Round(2),
        VotePhase::Prevote,
        B,
        votes,
    );
    let error =
        PrevoteCertificate::certify(qc, &registry, NET).expect_err("20 of 40 is not a quorum");
    let text = format!("{error:?}");
    assert!(
        text.to_lowercase().contains("quorum") || text.contains("weight"),
        "expected a weight refusal, got {text}"
    );

    // Consequently there is no POL for the authorisation to accept: with a lock
    // on A and no valid proof for B, the refusal is the missing proof itself.
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    let state = engine.persisted().clone();
    let candidate = vote(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    assert!(VoteAuthorization::for_prevote(&state, &candidate, None, &registry).is_err());
    assert_never_signed(&store, 0, 3, VotePhase::Prevote, B);
}

// ---------------------------------------------------------------------------
// §6.13 — a valid POL authorises a prevote for the new value, and nothing more.
// ---------------------------------------------------------------------------

#[test]
fn bu_13_a_valid_pol_authorizes_the_new_value_and_leaves_the_lock_alone() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let certificate = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);
    let pol = ProofOfLock::from_prevote(certificate);

    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    engine.begin_round(Round(3)).expect("round 3");

    // The authorisation is issued for B at round 3, and names the POL that
    // justified it.
    let candidate = vote(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, Some(&pol), &registry)
            .expect("a valid POL authorises the new value");
    assert!(authorization.covers(&candidate));
    assert_eq!(authorization.pol_qc_id(), Some(pol.certificate().id()));
    assert_eq!(authorization.lock_value(), A);
    assert_eq!(authorization.lock_round(), Some(Round(1)));

    // Through the engine, the same vote is signed and the lock is untouched.
    let prevote = engine
        .prevote_with_proof(B, Some(&pol), vid(1), &registry, &store, sign_with(1))
        .expect("A4' is satisfied");
    prevote
        .vote()
        .verify(&registry, NET)
        .expect("a real signature");
    assert_eq!(prevote.vote().checkpoint_id, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
    assert_eq!(engine.persisted().locked.map(|l| l.round), Some(Round(1)));
    assert!(durable_vote(&store, 0, 3, VotePhase::Prevote, B).is_some());
}

// ---------------------------------------------------------------------------
// §6.14 — a lock written by the hardened path survives a restart.
// ---------------------------------------------------------------------------

#[test]
fn bu_14_a_lock_written_under_the_new_api_survives_a_restart() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 2, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(B));
    assert_eq!(engine.persisted().locked.map(|l| l.round), Some(Round(2)));

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.report.may_sign(),
        "findings: {:?}",
        restored.report.findings
    );
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.checkpoint_id),
        Some(B)
    );
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.round),
        Some(Round(2))
    );
    assert!(restored.state.persisted().proof_of_lock.is_some());

    // The restored node still refuses a contradiction, and still signs its lock.
    let mut state = restored.state;
    assert!(matches!(
        state.prevote(A, vid(1), &registry, &store_after_restart(), sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

/// A store the restored node can write to: the durable slots of the restart.
fn store_after_restart() -> MemoryAtomicSlotStore {
    MemoryAtomicSlotStore::new()
}

// ---------------------------------------------------------------------------
// §6.15 — the provisional unlock is gone.
// ---------------------------------------------------------------------------

/// A legacy record can still carry `unlock_rule_provisional`, and it is still
/// refused: the flag survives decoding, and the recovery gate blocks it. What no
/// longer exists is the function that set it (CF-4).
#[test]
fn bu_15_a_provisional_unlock_record_is_still_refused_and_can_no_longer_be_produced() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    let mut legacy = engine.persisted().clone();
    legacy.unlock_rule_provisional = true;
    let legacy_store = MemoryAtomicSlotStore::new();
    legacy
        .persist(&legacy_store)
        .expect("persist legacy record");

    let restored = restore_engine(
        &legacy_store,
        &registry,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert!(
        restored.state.may_sign().is_err(),
        "a state that recorded a provisional unlock must never be operable"
    );

    // The authorisation refuses it too, before any signature is considered.
    let candidate = vote(gen().0, 0, 0, VotePhase::Prevote, A, 1);
    match VoteAuthorization::for_prevote(restored.state.persisted(), &candidate, None, &registry) {
        Err(EmitError::RecoveryRequired(_)) => {}
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// §6.16 — two contradictory authorisations, one signature.
// ---------------------------------------------------------------------------

/// Two threads each hold a valid authorisation for the **same** slot, for
/// different values. Reuse cannot cause equivocation: the slot's
/// compare-and-swap does, and exactly one of them wins.
#[test]
fn bu_16_two_contradictory_authorizations_produce_exactly_one_signature() {
    let registry = reg();
    let state = Arc::new(PersistentConsensusState::fresh(NET, gen(), ANCHOR));
    let store = Arc::new(MemoryAtomicSlotStore::new());
    let barrier = Arc::new(Barrier::new(2));

    let mut handles = Vec::new();
    for value in [A, B] {
        let store = Arc::clone(&store);
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        let registry = registry_for([7u8; 32]);
        handles.push(thread::spawn(move || {
            let candidate = unsigned(gen().0, 0, 0, VotePhase::Prevote, value, 1);
            let authorization = VoteAuthorization::for_prevote(&state, &candidate, None, &registry)
                .expect("no lock: this position is admissible for either value");
            let key = sk(1);
            barrier.wait();
            (
                value,
                sign_vote(
                    &state,
                    &*store,
                    &registry,
                    &candidate,
                    &authorization,
                    |msg: &[u8]| key.sign(msg).to_bytes(),
                ),
            )
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();

    let signed = results.iter().filter(|(_, r)| r.is_ok()).count();
    let refused = results
        .iter()
        .filter(|(_, r)| matches!(r, Err(EmitError::Equivocation { .. })))
        .count();
    assert_eq!(signed, 1, "exactly one value may be signed");
    assert_eq!(
        refused, 1,
        "the loser must be refused, not silently accepted"
    );

    let records = slots(&*store);
    assert_eq!(records.len(), 1, "one slot, one record");
    let recorded = records[0]
        .vote
        .as_ref()
        .expect("the record carries its vote");
    recorded
        .verify(&registry_for([7u8; 32]), NET)
        .expect("real signature");
    let winner = results
        .iter()
        .find(|(_, r)| r.is_ok())
        .map(|(value, _)| *value)
        .expect("one winner");
    assert_eq!(recorded.checkpoint_id, winner);
    assert!(
        winner == A || winner == B,
        "the durable value is one of the two proposals"
    );
}
