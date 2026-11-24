//! PHASE 4BT — safety audit of the BFT lock and of the proof of lock (POL).
//!
//! Mission BS left one residual risk open (`R-BS-2`):
//!
//! > `l2persist::signing_check` admits a contradiction at a higher round with
//! > no proof of lock.
//!
//! This suite attacks that statement from the outside. Every test uses real
//! Ed25519 keys, the production registry, the production vote/QC encodings and
//! the production persistence layer. No test calls a private helper or
//! re-implements a rule: the question is exactly whether the production code
//! refuses what it must refuse.
//!
//! The scenarios are the fifteen required by mission BT §4. Their numbering is
//! `bt_01` … `bt_15`; `bt_15b` is the control for `bt_15`, because the finding
//! it records is a **difference between two layers**, and a difference needs
//! both sides measured in the same test file.
//!
//! What these tests can claim: *this* implementation refuses these fifteen
//! attacks, at the layer each test names. What they cannot claim: the safety
//! theorem itself (a paper proof), nor anything about a caller that mutates the
//! public fields of `BftState` directly — `bt_15` measures that boundary instead
//! of pretending it does not exist.

use std::sync::{Arc, Barrier, Mutex};
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
    open_sealed, sign_vote, AtomicSlotStore, EmitError, LockAction, MemoryAtomicSlotStore,
    PersistentConsensusState, SledAtomicSlotStore, SlotKey, SlotReservation, SlotState,
    VoteAuthorization, SLOT_PREFIX,
};

const NET: u64 = 41;
const ANCHOR: [u8; 32] = [0x5A; 32];
const OTHER_ANCHOR: [u8; 32] = [0x5B; 32];
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

/// Four validators of weight 10: quorum is 27 of 40, so three signers are
/// needed and two can never certify anything.
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

fn engine_with(registry: &ValidatorRegistry, height: u64) -> BftState {
    BftState::new(NET, registry, CheckpointHeight(height), ANCHOR)
}

/// A quorate prevote certificate for `value` at `round`, in `registry`'s
/// generation and at `height`. Validator 1 signs through `engine` (so its slot
/// exists on `store`); validators 2 and 3 are injected as received votes.
#[allow(clippy::too_many_arguments)]
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

/// Every durable slot on the store, decoded through the production envelope.
fn all_slots(store: &dyn AtomicSlotStore) -> Vec<SlotReservation> {
    store
        .scan(SLOT_PREFIX)
        .expect("scan")
        .into_iter()
        .map(|(_, bytes)| {
            SlotReservation::decode(open_sealed(&bytes).expect("envelope")).expect("slot record")
        })
        .collect()
}

/// The durable vote, if any, for one position.
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

// ---------------------------------------------------------------------------
// BT-01. Lock A at round 1, vote A at round 1 (and again at round 2).
// ---------------------------------------------------------------------------

#[test]
fn bt_01_the_locked_value_stays_signable() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    let at_one = durable_vote(&store, 0, 1, VotePhase::Prevote, A).expect("prevote A r1");
    at_one.verify(&registry, NET).expect("real signature, r1");
    let precommit = durable_vote(&store, 0, 1, VotePhase::Precommit, A).expect("precommit A r1");
    precommit
        .verify(&registry, NET)
        .expect("real signature, r1");

    engine.begin_round(Round(2)).expect("round 2");
    let signed = engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("the locked value is always signable");
    signed
        .vote()
        .verify(&registry, NET)
        .expect("real signature, r2");

    let at_two = durable_vote(&store, 0, 2, VotePhase::Prevote, A).expect("prevote A r2");
    assert_eq!(at_two.checkpoint_id, A);
    assert_eq!(
        engine.persisted().locked.map(|l| l.checkpoint_id),
        Some(A),
        "voting the locked value never moves the lock"
    );
    assert_eq!(engine.persisted().locked.map(|l| l.round), Some(Round(1)));
}

// ---------------------------------------------------------------------------
// BT-02. Lock A at round 1, proposal B at round 2 with no POL.
// ---------------------------------------------------------------------------

#[test]
fn bt_02_a_higher_round_alone_does_not_authorise_a_contradictory_prevote() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    engine.begin_round(Round(2)).expect("round 2");
    engine
        .propose(B)
        .expect("a proposal is not a signature and carries no authority");
    assert_eq!(engine.round_state.proposal, Some(B));

    match engine.prevote(B, vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::PrevoteNotJustified {
            lock_round: 1,
            value,
            locked,
        }) => {
            assert_eq!(value, hex::encode(B));
            assert_eq!(locked, hex::encode(A));
        }
        other => panic!("a bare higher round must not authorise B, got {other:?}"),
    }

    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
    assert_eq!(
        engine.persisted().proof_of_lock.as_ref().map(|p| p.round),
        Some(Round(1)),
        "the persisted proof is still the one that locked A"
    );
}

// ---------------------------------------------------------------------------
// BT-03. Lock A at round 1, POL that does not certify B.
// ---------------------------------------------------------------------------

#[test]
fn bt_03_a_proof_for_another_value_cannot_authorise_b() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    // A perfectly valid proof — for C, not for B.
    let pol_c = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut producer,
        &producer_store,
        &registry,
        0,
        2,
        C,
    ));
    assert_eq!(pol_c.checkpoint_id, C);

    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    engine.begin_round(Round(3)).expect("round 3");

    assert!(!pol_c.accepted_for(&B, &engine.context(VotePhase::Prevote), Round(1)));
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol_c), vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 3, VotePhase::Prevote, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// BT-04. Lock A at round 1, valid POL for B at round 2.
// ---------------------------------------------------------------------------

#[test]
fn bt_04_a_valid_proof_for_b_authorises_only_a_strictly_later_round() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let pol_b2 = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut producer,
        &producer_store,
        &registry,
        0,
        2,
        B,
    ));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // In round 2 the proof is the proof *of the round being voted*: refused.
    engine.begin_round(Round(2)).expect("round 2");
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol_b2), vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);

    // In round 3 the same proof sits in `[lockR, r)`: authorised.
    engine.begin_round(Round(3)).expect("round 3");
    engine
        .prevote_with_proof(B, Some(&pol_b2), vid(1), &registry, &store, sign_with(1))
        .expect("lockR = 1 <= 2 < 3");
    let emitted = durable_vote(&store, 0, 3, VotePhase::Prevote, B).expect("signed B at r3");
    emitted.verify(&registry, NET).expect("real signature");
    assert_eq!(
        engine.persisted().locked.map(|l| l.checkpoint_id),
        Some(A),
        "a proof authorises one prevote; it never unlocks"
    );
    assert_eq!(
        engine.persisted().proof_of_lock.as_ref().map(|p| p.round),
        Some(Round(1)),
        "the lock evidence is untouched by an authorised prevote"
    );
}

// ---------------------------------------------------------------------------
// BT-05. Lock A at round 1, valid POL for B at round 3.
// ---------------------------------------------------------------------------

#[test]
fn bt_05_a_future_proof_authorises_nothing_before_its_round() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let pol_b3 = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut producer,
        &producer_store,
        &registry,
        0,
        3,
        B,
    ));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    engine.begin_round(Round(2)).expect("round 2");
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol_b3), vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);

    engine.begin_round(Round(4)).expect("round 4");
    engine
        .prevote_with_proof(B, Some(&pol_b3), vid(1), &registry, &store, sign_with(1))
        .expect("lockR = 1 <= 3 < 4");
    durable_vote(&store, 0, 4, VotePhase::Prevote, B)
        .expect("signed B at r4")
        .verify(&registry, NET)
        .expect("real signature");
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// BT-06. POL of another height.
// ---------------------------------------------------------------------------

#[test]
fn bt_06_a_proof_of_another_height_is_refused() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 1);
    let pol_h1 = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut producer,
        &producer_store,
        &registry,
        1,
        3,
        B,
    ));
    assert_eq!(pol_h1.height, CheckpointHeight(1));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    engine.begin_round(Round(4)).expect("round 4");

    assert!(!pol_h1.is_valid_for(&engine.context(VotePhase::Prevote)));
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol_h1), vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 4, VotePhase::Prevote, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// BT-07. POL of another generation.
// ---------------------------------------------------------------------------

#[test]
fn bt_07_a_proof_of_another_generation_is_refused() {
    let foreign_generation = [9u8; 32];
    let foreign_registry = registry_for(foreign_generation);
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&foreign_registry, 0);
    let pol_foreign = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut producer,
        &producer_store,
        &foreign_registry,
        0,
        3,
        B,
    ));
    assert_eq!(pol_foreign.generation, GenerationId(foreign_generation));

    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    engine.begin_round(Round(4)).expect("round 4");

    assert!(!pol_foreign.is_valid_for(&engine.context(VotePhase::Prevote)));
    assert!(matches!(
        engine.prevote_with_proof(
            B,
            Some(&pol_foreign),
            vid(1),
            &registry,
            &store,
            sign_with(1)
        ),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 4, VotePhase::Prevote, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// BT-08. POL with insufficient quorum.
// ---------------------------------------------------------------------------

#[test]
fn bt_08_a_pol_below_quorum_cannot_even_be_built() {
    let registry = reg();
    // 20 of 40 with quorum 27: two signers are not a quorum.
    let votes: Vec<ConsensusVote> = [1u8, 2u8]
        .iter()
        .map(|seed| vote([7u8; 32], 0, 3, VotePhase::Prevote, B, *seed))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(0),
        Round(3),
        VotePhase::Prevote,
        B,
        votes,
    );
    assert_eq!(qc.support_weight.get(), 20);

    match PrevoteCertificate::certify(qc, &registry, NET) {
        Err(BftError::NotQuorate {
            support,
            quorum,
            total,
        }) => {
            assert_eq!((support, quorum, total), (20, 27, 40));
        }
        other => panic!("a 20/40 certificate must not certify, got {other:?}"),
    }

    // Same conclusion on the wire path: a decoded certificate is re-verified.
    let bytes = {
        let votes: Vec<ConsensusVote> = [1u8, 2u8]
            .iter()
            .map(|seed| vote([7u8; 32], 0, 3, VotePhase::Prevote, B, *seed))
            .collect();
        QuorumCertificate::new(
            NET,
            &registry,
            CheckpointHeight(0),
            Round(3),
            VotePhase::Prevote,
            B,
            votes,
        )
        .encode()
    };
    assert!(PrevoteCertificate::from_bytes(&bytes, &registry, NET).is_err());
}

// ---------------------------------------------------------------------------
// BT-09. POL with falsified weights.
// ---------------------------------------------------------------------------

#[test]
fn bt_09_a_pol_that_lies_about_its_weight_is_rejected() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let genuine = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);
    let mut qc = QuorumCertificate::decode(&genuine.encode()).expect("decode");
    qc.support_weight = ValidatorWeight(40);

    let err = PrevoteCertificate::from_bytes(&qc.encode(), &registry, NET)
        .expect_err("declared support 40 cannot match the recomputation");
    let text = format!("{err:?}");
    assert!(
        text.contains("declared weights"),
        "expected DeclaredWeightMismatch, got {text}"
    );

    let mut qc_total = QuorumCertificate::decode(&genuine.encode()).expect("decode");
    qc_total.total_weight = ValidatorWeight(1000);
    assert!(PrevoteCertificate::from_bytes(&qc_total.encode(), &registry, NET).is_err());
}

// ---------------------------------------------------------------------------
// BT-10. POL with invalid signatures.
// ---------------------------------------------------------------------------

#[test]
fn bt_10_a_pol_with_a_broken_signature_is_rejected() {
    let registry = reg();
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let genuine = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);

    let mut qc = QuorumCertificate::decode(&genuine.encode()).expect("decode");
    qc.votes[1].signature[7] ^= 0xFF;
    let err = PrevoteCertificate::from_bytes(&qc.encode(), &registry, NET)
        .expect_err("a flipped signature byte is not a signature");
    let text = format!("{err:?}");
    assert!(
        text.contains("bad vote signature"),
        "expected BadSignature, got {text}"
    );

    // A signer that is not in the registry is not a signer either.
    let mut unknown = QuorumCertificate::decode(&genuine.encode()).expect("decode");
    unknown.votes[1].validator = vid(9);
    assert!(PrevoteCertificate::from_bytes(&unknown.encode(), &registry, NET).is_err());
}

// ---------------------------------------------------------------------------
// BT-11. Lock restored after a restart.
// ---------------------------------------------------------------------------

#[test]
fn bt_11_a_lock_survives_a_restart() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &store, &registry, 0, 1, A);
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.report.may_sign(), "{:?}", restored.report.findings);
    assert!(restored.state.may_sign().is_ok());
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.checkpoint_id),
        Some(A)
    );
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.round),
        Some(Round(1))
    );
    assert!(
        restored.report.signed >= 2,
        "the prevote and the precommit of round 1 are on disk"
    );
    assert_eq!(
        restored.state.active_lock().map(|l| l.checkpoint_id),
        Some(A)
    );
}

// ---------------------------------------------------------------------------
// BT-12. Contradictory proposal after a restart.
// ---------------------------------------------------------------------------

#[test]
fn bt_12_a_restored_lock_refuses_a_contradictory_proposal() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &store, &registry, 0, 1, A);
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let mut engine =
        restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0)).state;
    engine.begin_round(Round(2)).expect("round 2");
    engine.propose(B).expect("propose is not a signature");

    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));

    // The control: the restored node still votes its own locked value.
    engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("the lock is binding, not paralysing");
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// BT-13. Round change concurrent with signing.
// ---------------------------------------------------------------------------

#[test]
fn bt_13_a_concurrent_round_change_cannot_launder_a_contradictory_vote() {
    let registry = reg();
    for attempt in 0..48u32 {
        let store = Arc::new(MemoryAtomicSlotStore::new());
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &*store, &registry, 0, 1, A);
        let engine = Arc::new(Mutex::new(engine));

        let barrier = Arc::new(Barrier::new(2));
        let changer = {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut engine = engine.lock().expect("poisoned");
                let _ = engine.begin_round(Round(2));
            })
        };
        let signer = {
            let engine = Arc::clone(&engine);
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let registry = reg();
                let mut engine = engine.lock().expect("poisoned");
                engine.prevote(B, vid(1), &registry, &*store, sign_with(1))
            })
        };
        changer.join().expect("changer");
        let outcome = signer.join().expect("signer");
        assert!(
            outcome.is_err(),
            "attempt {attempt}: a round change must not authorise B without a POL"
        );
        assert_never_signed(&*store, 0, 1, VotePhase::Prevote, B);
        assert_never_signed(&*store, 0, 2, VotePhase::Prevote, B);
        let engine = engine.lock().expect("poisoned");
        assert_eq!(
            engine.persisted().locked.map(|l| l.checkpoint_id),
            Some(A),
            "attempt {attempt}: the lock never moves"
        );
    }
}

// ---------------------------------------------------------------------------
// BT-14. Two contradictory values signed at one slot, simultaneously.
// ---------------------------------------------------------------------------

#[test]
fn bt_14_two_simultaneous_contradictory_votes_yield_exactly_one_signature() {
    for attempt in 0..32u32 {
        let store = Arc::new(MemoryAtomicSlotStore::new());
        let state = Arc::new(PersistentConsensusState::fresh(NET, gen(), ANCHOR));
        let barrier = Arc::new(Barrier::new(2));

        let mut handles = Vec::new();
        for value in [A, B] {
            let store = Arc::clone(&store);
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            // Both threads sign the *same* slot (round 0, prevote, validator 1)
            // so the anti-equivocation rule is what decides, not the lock.
            handles.push(thread::spawn(move || {
                let mut v = ConsensusVote {
                    version: CONSENSUS_VOTE_VERSION,
                    network: NET,
                    generation: gen(),
                    height: CheckpointHeight(0),
                    round: Round(0),
                    phase: VotePhase::Prevote,
                    checkpoint_id: value,
                    validator: vid(1),
                    signature: [0u8; 64],
                };
                let key = sk(1);
                v.signature = [0u8; 64];
                barrier.wait();
                // BU: each thread needs its own authorisation, built by the
                // validated constructor from the shared state.
                let registry = reg();
                let authorization = VoteAuthorization::for_prevote(&state, &v, None, &registry)
                    .expect("no lock: this position is admissible for either value");
                sign_vote(
                    &state,
                    &*store,
                    &registry,
                    &v,
                    &authorization,
                    move |msg: &[u8]| key.sign(msg).to_bytes(),
                )
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect();

        let signed = results.iter().filter(|r| r.is_ok()).count();
        let equivocations = results
            .iter()
            .filter(|r| matches!(r, Err(EmitError::Equivocation { .. })))
            .count();
        assert_eq!(
            signed, 1,
            "attempt {attempt}: exactly one value wins a slot"
        );
        assert_eq!(
            equivocations, 1,
            "attempt {attempt}: the loser must be refused"
        );

        let slots = all_slots(&*store);
        assert_eq!(
            slots.len(),
            1,
            "attempt {attempt}: evidence is never overwritten"
        );
        assert_eq!(slots[0].state, SlotState::Signed);
        let recorded = slots[0]
            .vote
            .as_ref()
            .expect("signed record carries its vote");
        recorded.verify(&reg(), NET).expect("real signature");
        assert!(recorded.checkpoint_id == A || recorded.checkpoint_id == B);
    }
}

// ---------------------------------------------------------------------------
// BT-15. Direct call of the persistence API, without the engine.
// ---------------------------------------------------------------------------

/// `R-BS-2`, now closed at the primitive.
///
/// BT measured that `l2persist::sign_vote`, given the state the engine had just
/// persisted (locked on `A` at round 1), signed a prevote for `B` at round 2
/// without any proof of lock, because `signing_check` only refuses a
/// contradiction at `round <= lockR`.
///
/// Mission BU makes the primitive require a `VoteAuthorization`, and the only
/// constructors of that value re-run the whole rule, so this test now asserts the
/// refusal at exactly the layer where BT saw the defect. `bt_15b` remains the
/// control: the identical vote through the engine is refused one layer above.
#[test]
fn bt_15_the_storage_primitive_alone_refuses_a_contradiction_without_a_pol() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // Exactly the safety state the engine wrote and flushed.
    let persisted = engine.persisted().clone();
    assert_eq!(persisted.locked.map(|l| l.checkpoint_id), Some(A));
    assert_eq!(persisted.locked.map(|l| l.round), Some(Round(1)));

    let contradictory = ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: gen(),
        height: CheckpointHeight(0),
        round: Round(2),
        phase: VotePhase::Prevote,
        checkpoint_id: B,
        validator: vid(1),
        signature: [0u8; 64],
    };

    // No authorisation exists for this vote, so the primitive is unreachable.
    match VoteAuthorization::for_prevote(&persisted, &contradictory, None, &registry) {
        Err(EmitError::NotAuthorized(reason)) => assert!(
            reason.contains("proof of lock"),
            "expected the missing POL to be named, got {reason}"
        ),
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);
    assert_eq!(
        persisted.locked.map(|l| l.checkpoint_id),
        Some(A),
        "nothing moved the lock"
    );
}

/// Control for `bt_15`: the same vote, through the engine, is refused.
#[test]
fn bt_15b_the_engine_refuses_the_very_same_contradictory_vote() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    engine.begin_round(Round(2)).expect("round 2");

    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_never_signed(&store, 0, 2, VotePhase::Prevote, B);

    // The difference between the two tests is the engine guard, not the state,
    // not the keys and not the storage: both used the same `ANCHOR` and network.
    let restored = restore_engine(
        &store,
        &registry,
        Some(OTHER_ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert!(
        !restored.report.may_sign(),
        "a foreign anchor still blocks signing"
    );
}

// ---------------------------------------------------------------------------
// BT-16 / BT-17 became compile-time cases in mission BU.
//
// BT-16 drove `engine.persisted().locked = None`: `BftState::persisted` is now a
// private field read through `persisted()`, so the test does not compile
// (E0616). BT-17 called `apply_provisional_unlock`, which no longer exists
// (E0599), and `apply_and_persist`, which no longer exists either (E0432).
//
// Deleting them here is the point of BU: an API that cannot be reached cannot be
// misused, and a runtime test asserting a defect that has been compiled away
// would only re-open it. The four negations are now enforced by
// `scripts/compile-fail-bu.sh`, which compiles each snippet against the real
// rlib and requires the expected error code, and by
// `tests/phase4bu_api_hardening.rs`, which exercises every legitimate path plus
// the sixteen runtime scenarios of mission BU §6.
