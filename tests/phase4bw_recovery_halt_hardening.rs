//! PHASE 4BW — recovery after a legitimate lock change, and HALT at the
//! signature frontier.
//!
//! Mission BV measured two risks. This file tests their correction, without
//! changing the consensus rules:
//!
//! | Risk | What BW changes | Tests |
//! |---|---|---|
//! | R-BV-1: a POL-authorised lock change blocked its own restart | the recovery audit compares rounds, and refuses a proof that cannot justify the lock | `bw_01` - `bw_07` |
//! | R-BV-2: an authorisation issued before a HALT still signed | `sign_vote` reads the durable halt record before the authorisation and again before the signature | `bw_08` - `bw_13` |
//!
//! Every scenario is deterministic: fixed keys, fixed votes, no clock and no
//! network. "Crash" and "restart" mean dropping the engine or the store handle
//! and reopening the same directory.
//!
//! Two limits are deliberate and reported:
//!
//! - an altered proof costs the ability to *propose* the locked value; it never
//!   unlocks anything, and the lock keeps refusing contradictory signatures;
//! - the double halt check narrows the race to the instructions between the last
//!   read and `sign()`. A signature that was already past both checks when the
//!   halt was committed is a pre-halt signature; every attempt started after
//!   `halt_with` returns is refused.

use std::sync::{Barrier, Mutex};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{
    restore_engine, BftError, BftState, HaltReason, PrevoteCertificate, ProofOfLock, VoteOutcome,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::{
    restore, seal, sign_vote, AtomicSlotStore, CasStore, EmitError, LockedValue,
    MemoryAtomicSlotStore, PersistentConsensusState, ProofOfLock as PersistedProof, RecoveryReason,
    RecoveryStatus, Settlement, SledAtomicSlotStore, SlotKey, VoteAuthorization, HALT_KEY,
    SLOT_PREFIX,
};

const NET: u64 = 43;
const ANCHOR: [u8; 32] = [0x5A; 32];
const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];
const OTHER_GENERATION: [u8; 32] = [8u8; 32];

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

/// Four validators of weight 10: quorum is 27 of 40, so three signers are needed.
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

fn unsigned(
    generation: [u8; 32],
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
    seed: u8,
) -> ConsensusVote {
    ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: GenerationId(generation),
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        checkpoint_id: value,
        validator: vid(seed),
        signature: [0u8; 64],
    }
}

fn signed(
    generation: [u8; 32],
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
    seed: u8,
) -> ConsensusVote {
    let mut vote = unsigned(generation, height, round, phase, value, seed);
    vote.signature = sk(seed).sign(&vote.signing_bytes()).to_bytes();
    vote
}

fn engine_with(registry: &ValidatorRegistry, height: u64) -> BftState {
    BftState::new(NET, registry, CheckpointHeight(height), ANCHOR)
}

/// A quorate prevote certificate for `value` at `round`, with real signatures.
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
        let vote = signed(
            registry.generation().0,
            height,
            round,
            VotePhase::Prevote,
            value,
            seed,
        );
        assert!(matches!(
            engine.accept_vote(&vote, registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    engine
        .certify_prevotes_for(value, registry)
        .expect("quorate prevote certificate")
}

/// Collect the two remaining prevotes at the engine's current round and certify.
fn certify_peers_at(
    engine: &mut BftState,
    registry: &ValidatorRegistry,
    height: u64,
    round: u32,
    value: [u8; 32],
) -> PrevoteCertificate {
    for seed in [2u8, 3u8] {
        let vote = signed(
            registry.generation().0,
            height,
            round,
            VotePhase::Prevote,
            value,
            seed,
        );
        assert!(matches!(
            engine.accept_vote(&vote, registry),
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
        .filter(|vote| vote.checkpoint_id == value)
}

fn slot_count(store: &dyn AtomicSlotStore) -> usize {
    store.scan(SLOT_PREFIX).expect("scan").len()
}

/// A persisted state with a lock and an arbitrary proof, for structural tests.
fn state_with_proof(
    store: &MemoryAtomicSlotStore,
    lock: LockedValue,
    proof: PersistedProof,
) -> PersistentConsensusState {
    let mut state = PersistentConsensusState::fresh(NET, gen(), ANCHOR);
    state.locked = Some(lock);
    state.proof_of_lock = Some(proof);
    state.persist(store).expect("persist crafted state");
    state
}

fn proof(round: Round, proposed: LockedValue) -> PersistedProof {
    PersistedProof {
        round,
        qc_id: [0x11; 32],
        support: 30,
        total: 40,
        signers: 3,
        proposed,
        encoded_qc: vec![0xEE; 8],
    }
}

// ---------------------------------------------------------------------------
// R-BV-1 — a legitimate lock change is accepted after a restart.
// ---------------------------------------------------------------------------

#[test]
fn bw_01_a_pol_authorized_lock_change_survives_a_real_restart() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open real store");
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &store, &registry, 0, 1, A);
        assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));

        // A valid POL for B at round 2, produced by a real quorum:
        // `lockR = 1 <= 2 < 3` justifies a prevote for B at round 3.
        let producer_store = MemoryAtomicSlotStore::new();
        let mut producer = engine_with(&registry, 0);
        let certificate =
            prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);
        let pol = ProofOfLock::from_prevote(certificate);
        assert!(pol.certificate().re_verify(&registry, NET).is_ok());

        // The change: prevote B at round 3 with the round-2 POL, certify B at
        // round 3, precommit — which writes the new lock before signing
        // (`AW-LOCK-2`).
        engine.begin_round(Round(3)).expect("round 3");
        engine.propose(B).expect("propose B");
        engine
            .prevote_with_proof(B, Some(&pol), vid(1), &registry, &store, sign_with(1))
            .expect("A4' is satisfied by the POL");
        let certificate = certify_peers_at(&mut engine, &registry, 0, 3, B);
        engine
            .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
            .expect("precommit writes the new lock");
        assert_eq!(
            engine
                .persisted()
                .locked
                .map(|l| (l.checkpoint_id, l.round)),
            Some((B, Round(3)))
        );
        assert_eq!(
            engine.persisted().proof_of_lock.as_ref().map(|p| p.round),
            Some(Round(3))
        );
    }

    // Restart after the change. The round-1 votes for A are prior history that
    // `A4'` allowed; they must not look like a contradiction.
    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen after restart");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.report.may_sign(),
        "a POL-authorised lock change must not block its own restart: {:?} / {:?}",
        restored.report.status,
        restored.report.findings
    );
    assert!(matches!(restored.report.status, RecoveryStatus::Clean));
    assert!(
        !restored
            .report
            .findings
            .iter()
            .any(|f| f.contains("contradicts the lock")),
        "findings: {:?}",
        restored.report.findings
    );
    let persisted = restored.state.persisted();
    assert_eq!(
        persisted.locked.map(|l| (l.checkpoint_id, l.round)),
        Some((B, Round(3))),
        "the authorised lock change is durable"
    );
    assert_eq!(
        persisted.proof_of_lock.as_ref().map(|p| p.round),
        Some(Round(3))
    );
    assert!(durable_vote(&store, 0, 3, VotePhase::Precommit, B).is_some());

    // The restored node signs the locked value, and never the replaced one.
    let mut state = restored.state;
    assert!(state.may_sign().is_ok());
    state.begin_round(Round(4)).expect("round 4");
    state.propose(B).expect("propose B");
    let prevote = state
        .prevote(B, vid(1), &registry, &store, sign_with(1))
        .expect("the locked value stays signable after the restart");
    prevote
        .vote()
        .verify(&registry, NET)
        .expect("a real signature");
    assert!(durable_vote(&store, 0, 4, VotePhase::Prevote, B).is_some());
    let stale = unsigned(gen().0, 0, 4, VotePhase::Prevote, A, 1);
    assert!(matches!(
        VoteAuthorization::for_prevote(state.persisted(), &stale, None, &registry),
        Err(EmitError::NotAuthorized(_))
    ));
}

#[test]
fn bw_02_a_value_change_without_a_pol_is_refused_before_any_signature() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);
    engine.begin_round(Round(2)).expect("round 2");

    let candidate = unsigned(gen().0, 0, 2, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry) {
        Err(EmitError::NotAuthorized(text)) => {
            assert!(text.contains("proof of lock"), "reason: {text}");
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert!(
        durable_vote(&store, 0, 2, VotePhase::Prevote, B).is_none(),
        "no signature exists without a POL"
    );
    assert_eq!(
        engine
            .persisted()
            .locked
            .map(|l| (l.checkpoint_id, l.round)),
        Some((A, Round(1))),
        "the lock never moves on a refused change"
    );
}

#[test]
fn bw_03_a_pol_outside_its_round_window_is_refused() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // Real certificates for B at round 0 (below the lock) and round 2 (the
    // round being voted in the strictness check).
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let cert_0 = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 0, B);
    let cert_2 = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);
    let pol_0 = ProofOfLock::from_prevote(cert_0);
    let pol_2 = ProofOfLock::from_prevote(cert_2);

    // `lockR <= rho` fails: the certificate predates the lock.
    let at_two = unsigned(gen().0, 0, 2, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(engine.persisted(), &at_two, Some(&pol_0), &registry) {
        Err(EmitError::NotAuthorized(text)) => {
            assert!(text.contains("does not justify"), "reason: {text}")
        }
        other => panic!("expected NotAuthorized below lockR, got {other:?}"),
    }

    // `rho < r` fails strictly: the proof is for the round being voted.
    match VoteAuthorization::for_prevote(engine.persisted(), &at_two, Some(&pol_2), &registry) {
        Err(EmitError::NotAuthorized(text)) => {
            assert!(text.contains("does not justify"), "reason: {text}")
        }
        other => panic!("expected NotAuthorized at rho == r, got {other:?}"),
    }

    // Control: the same proof at the next round satisfies both bounds.
    let at_three = unsigned(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &at_three, Some(&pol_2), &registry)
            .expect("lockR <= 2 < 3");
    assert!(authorization.covers(&at_three));
    assert_eq!(authorization.pol_qc_id(), Some(pol_2.certificate().id()));
    assert!(durable_vote(&store, 0, 3, VotePhase::Prevote, B).is_none());
}

#[test]
fn bw_04_a_pol_from_another_generation_is_refused() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // A genuine quorum certificate, but for the next generation's validator set.
    let foreign_registry = registry_for(OTHER_GENERATION);
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&foreign_registry, 0);
    let foreign =
        prevote_certificate_at(&mut producer, &producer_store, &foreign_registry, 0, 2, B);
    let pol = ProofOfLock::from_prevote(foreign);

    let candidate = unsigned(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(engine.persisted(), &candidate, Some(&pol), &registry) {
        Err(EmitError::NotAuthorized(text)) => {
            assert!(text.contains("re-verify"), "reason: {text}");
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol), vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert!(durable_vote(&store, 0, 3, VotePhase::Prevote, B).is_none());
}

#[test]
fn bw_05_a_pol_from_another_height_is_refused() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // A genuine certificate for B at height 1, while the vote is at height 0.
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 1);
    let certificate = prevote_certificate_at(&mut producer, &producer_store, &registry, 1, 2, B);
    let pol = ProofOfLock::from_prevote(certificate);
    assert!(pol.certificate().re_verify(&registry, NET).is_ok());

    let candidate = unsigned(gen().0, 0, 3, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(engine.persisted(), &candidate, Some(&pol), &registry) {
        Err(EmitError::NotAuthorized(text)) => {
            assert!(text.contains("does not justify"), "reason: {text}");
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert!(durable_vote(&store, 0, 3, VotePhase::Prevote, B).is_none());
}

#[test]
fn bw_06_a_regressive_or_incoherent_lock_record_fails_closed() {
    // A proof from an earlier round cannot have authorised the lock.
    let store = MemoryAtomicSlotStore::new();
    let lock = LockedValue {
        checkpoint_id: B,
        height: CheckpointHeight(0),
        round: Round(3),
    };
    state_with_proof(
        &store,
        lock,
        proof(
            Round(1),
            LockedValue {
                checkpoint_id: B,
                height: CheckpointHeight(0),
                round: Round(1),
            },
        ),
    );
    let report = restore(&store, Some(ANCHOR), NET);
    assert!(!report.may_sign(), "a regressive proof must fail closed");
    match report.status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::ContradictoryLock(text)) => {
            assert!(text.contains("does not justify"), "reason: {text}")
        }
        other => panic!("expected ContradictoryLock, got {other:?}"),
    }

    // Two values at the lock's own round are `AW-LOCK-10`'s forbidden shape.
    let store = MemoryAtomicSlotStore::new();
    state_with_proof(
        &store,
        lock,
        proof(
            Round(3),
            LockedValue {
                checkpoint_id: A,
                height: CheckpointHeight(0),
                round: Round(3),
            },
        ),
    );
    assert!(matches!(
        restore(&store, Some(ANCHOR), NET).status,
        RecoveryStatus::RecoveryRequired(RecoveryReason::ContradictoryLock(_))
    ));

    // A proof for another height cannot justify this lock either.
    let store = MemoryAtomicSlotStore::new();
    state_with_proof(
        &store,
        lock,
        proof(
            Round(3),
            LockedValue {
                checkpoint_id: B,
                height: CheckpointHeight(1),
                round: Round(3),
            },
        ),
    );
    assert!(matches!(
        restore(&store, Some(ANCHOR), NET).status,
        RecoveryStatus::RecoveryRequired(RecoveryReason::ContradictoryLock(_))
    ));
}

#[test]
fn bw_07_an_absent_or_altered_proof_is_never_evidence() {
    let registry = reg();

    // Absent: a lock without its proof is incomplete and cannot sign.
    let store = MemoryAtomicSlotStore::new();
    let lock = LockedValue {
        checkpoint_id: B,
        height: CheckpointHeight(3),
        round: Round(3),
    };
    let mut state = PersistentConsensusState::fresh(NET, gen(), ANCHOR);
    state.locked = Some(lock);
    state.proof_of_lock = None;
    state.persist(&store).expect("persist");
    match restore(&store, Some(ANCHOR), NET).status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::IncompleteState(text)) => {
            assert!(text.contains("lock"), "reason: {text}")
        }
        other => panic!("expected IncompleteState, got {other:?}"),
    }

    // Altered: the structural record is coherent, but its certificate bytes do
    // not verify. The engine drops the proof and keeps the lock; the altered
    // bytes can never authorise a lock change or a proposal.
    let store = MemoryAtomicSlotStore::new();
    let mut altered = proof(
        Round(3),
        LockedValue {
            checkpoint_id: B,
            height: CheckpointHeight(3),
            round: Round(3),
        },
    );
    altered.encoded_qc = vec![0xDE, 0xAD, 0xBE, 0xEF];
    state_with_proof(&store, lock, altered.clone());
    assert!(PrevoteCertificate::from_bytes(&altered.encoded_qc, &registry, NET).is_err());

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(3));
    assert!(matches!(restored.report.status, RecoveryStatus::Clean));
    assert!(
        restored.state.persisted().proof_of_lock.is_none(),
        "the engine must drop a proof it cannot re-verify"
    );
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.checkpoint_id),
        Some(B),
        "dropping the proof never drops the lock"
    );
    assert!(restored.state.may_sign().is_ok());

    // The lock still governs signatures: B is admissible, A is not.
    let mut state = restored.state;
    state.begin_round(Round(4)).expect("round 4");
    let b_vote = unsigned(gen().0, 3, 4, VotePhase::Prevote, B, 1);
    VoteAuthorization::for_prevote(state.persisted(), &b_vote, None, &registry)
        .expect("the locked value is always signable");
    let a_vote = unsigned(gen().0, 3, 4, VotePhase::Prevote, A, 1);
    assert!(matches!(
        VoteAuthorization::for_prevote(state.persisted(), &a_vote, None, &registry),
        Err(EmitError::NotAuthorized(_))
    ));
}

// ---------------------------------------------------------------------------
// R-BV-2 — an authorisation cannot outlive a HALT.
// ---------------------------------------------------------------------------

#[test]
fn bw_08_an_authorization_cannot_outlive_a_halt() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    engine.begin_round(Round(1)).expect("round 1");
    engine.propose(A).expect("propose A");

    let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
            .expect("admissible before the halt");
    engine.persisted().persist(&store).expect("persist state");

    engine
        .halt_with(HaltReason::Persisted("bw halt drill".to_string()), &store)
        .expect("halt is written and flushed");
    assert!(engine.is_halted());

    // The authorisation was obtained before the halt. It must not sign now.
    match sign_vote(
        engine.persisted(),
        &store,
        &registry,
        &candidate,
        &authorization,
        sign_with(1),
    ) {
        Err(EmitError::Halted(_)) => {}
        other => panic!("expected Halted, got {other:?}"),
    }
    assert!(matches!(
        engine.prevote(A, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::Halted(_))
    ));
    assert!(
        slot_count(&store) == 0,
        "a refused signature reserves no slot"
    );
    assert!(durable_vote(&store, 0, 1, VotePhase::Prevote, A).is_none());
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), None);
}

#[test]
fn bw_09_a_halt_before_the_authorization_refuses_to_issue_one() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    engine.begin_round(Round(1)).expect("round 1");
    engine.propose(A).expect("propose A");
    engine.persisted().persist(&store).expect("persist state");
    engine
        .halt_with(HaltReason::Persisted("halt first".to_string()), &store)
        .expect("halt");

    let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
    match VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry) {
        Err(EmitError::RecoveryRequired(_)) => {}
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
    assert!(matches!(
        engine.prevote(A, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::Halted(_))
    ));
    assert_eq!(slot_count(&store), 0);
}

#[test]
fn bw_10_a_concurrent_signature_cannot_slip_past_a_committed_halt() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    engine.begin_round(Round(1)).expect("round 1");
    engine.propose(A).expect("propose A");

    let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
            .expect("admissible before the halt");
    // Every thread keeps the pre-halt snapshot: the refusal must come from the
    // durable record, not from the in-memory status.
    let snapshot = engine.persisted().clone();
    engine.persisted().persist(&store).expect("persist state");
    engine
        .halt_with(
            HaltReason::Persisted("concurrent drill".to_string()),
            &store,
        )
        .expect("halt is durable");

    let barrier = Barrier::new(9);
    let outcomes = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                let outcome = sign_vote(
                    &snapshot,
                    &store,
                    &registry,
                    &candidate,
                    &authorization,
                    sign_with(1),
                );
                outcomes.lock().expect("outcomes").push(outcome);
            });
        }
        barrier.wait();
    });

    let outcomes = outcomes.into_inner().expect("outcomes");
    assert_eq!(outcomes.len(), 8);
    for outcome in outcomes {
        match outcome {
            Err(EmitError::Halted(_)) => {}
            other => panic!("a halted node signed: {other:?}"),
        }
    }
    assert_eq!(slot_count(&store), 0, "no slot was reserved");
    assert!(durable_vote(&store, 0, 1, VotePhase::Prevote, A).is_none());
}

#[test]
fn bw_11_a_halt_survives_a_restart_and_refuses_a_restored_signer() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");

    let (candidate, authorization) = {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = engine_with(&registry, 0);
        engine.begin_round(Round(1)).expect("round 1");
        engine.propose(A).expect("propose A");
        let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
        let authorization =
            VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
                .expect("admissible before the halt");
        engine.persisted().persist(&store).expect("persist state");
        engine
            .halt_with(HaltReason::Persisted("restart drill".to_string()), &store)
            .expect("halt is durable");
        (candidate, authorization)
    };

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.is_halted());
    assert!(restored.state.may_sign().is_err());
    // The safety record itself is clean: the refusal is the durable halt.
    assert!(matches!(restored.report.status, RecoveryStatus::Clean));

    match sign_vote(
        restored.state.persisted(),
        &store,
        &registry,
        &candidate,
        &authorization,
        sign_with(1),
    ) {
        Err(EmitError::Halted(_)) => {}
        other => panic!("expected Halted after restart, got {other:?}"),
    }
    assert_eq!(slot_count(&store), 0);
    assert!(durable_vote(&store, 0, 1, VotePhase::Prevote, A).is_none());
}

#[test]
fn bw_12_an_authorization_from_before_a_restart_never_signs_twice() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");

    let (candidate, authorization, first) = {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = engine_with(&registry, 0);
        engine.begin_round(Round(1)).expect("round 1");
        engine.propose(A).expect("propose A");
        let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
        let authorization =
            VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
                .expect("admissible");
        engine.persisted().persist(&store).expect("persist state");
        let prevote = engine
            .prevote(A, vid(1), &registry, &store, sign_with(1))
            .expect("first signature");
        (candidate, authorization, prevote.vote().clone())
    };

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.may_sign().is_ok());
    let outcome = sign_vote(
        restored.state.persisted(),
        &store,
        &registry,
        &candidate,
        &authorization,
        sign_with(1),
    )
    .expect("replaying the same authorisation is idempotent");
    assert_eq!(outcome.settlement, Settlement::AlreadySigned);
    assert_eq!(outcome.vote.id(), first.id());
    assert_eq!(slot_count(&store), 1, "one slot, one signature");
}

#[test]
fn bw_13_a_missing_or_corrupt_halt_record_is_handled_fail_closed() {
    let registry = reg();

    // Absent: signing is allowed. The gate is specific, not a blanket refusal.
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    engine.begin_round(Round(1)).expect("round 1");
    engine.propose(A).expect("propose A");
    let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
            .expect("admissible");
    engine.persisted().persist(&store).expect("persist");
    sign_vote(
        engine.persisted(),
        &store,
        &registry,
        &candidate,
        &authorization,
        sign_with(1),
    )
    .expect("no halt record: nothing blocks the signature");

    // Corrupt, not even an envelope: presence alone is a halt.
    let store = MemoryAtomicSlotStore::new();
    engine.persisted().persist(&store).expect("persist");
    store
        .cas(HALT_KEY, None, b"not a sealed halt record")
        .expect("write raw halt");
    let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
            .expect("the authorisation constructor cannot see the store");
    match sign_vote(
        engine.persisted(),
        &store,
        &registry,
        &candidate,
        &authorization,
        sign_with(1),
    ) {
        Err(EmitError::Halted(text)) => assert!(text.contains("halt"), "text: {text}"),
        other => panic!("a corrupt halt record must still stop signing: {other:?}"),
    }
    assert_eq!(slot_count(&store), 0);

    // Corrupt, valid envelope with a broken digest: still a halt.
    let store = MemoryAtomicSlotStore::new();
    engine.persisted().persist(&store).expect("persist");
    let mut sealed = seal(b"halt");
    sealed[0] ^= 0xFF;
    store.cas(HALT_KEY, None, &sealed).expect("write halt");
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
            .expect("admissible");
    assert!(matches!(
        sign_vote(
            engine.persisted(),
            &store,
            &registry,
            &candidate,
            &authorization,
            sign_with(1)
        ),
        Err(EmitError::Halted(_))
    ));
    assert_eq!(slot_count(&store), 0);
}
