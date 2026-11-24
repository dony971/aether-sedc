//! PHASE 4CY — crash boundaries, restore safety and the `AW-LOCK-11(c)` audit.
//!
//! Mission AY closes the gap AX documented: a **durable precommit without a
//! restored lock** used to be invisible, so a node could restart with `lockV = 0`
//! and prevote a contradictory value. These tests build that exact evidence on
//! disk and require the engine to refuse to sign.
//!
//! Every test is deterministic: fixed registry, fixed keys, fixed votes, no
//! clock, no network, no randomness. A "crash" is modelled by keeping the store
//! and dropping the in-memory engine — nothing else.

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{
    restore_engine, BftError, BftState, PrevoteCertificate, ProofOfLock, VoteOutcome,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::{
    AtomicSlotStore, CasStore, MemoryAtomicSlotStore, SlotKey, SLOT_PREFIX,
};

const NET: u64 = 11;
const ANCHOR: [u8; 32] = [0x5A; 32];
const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn gen_id() -> GenerationId {
    GenerationId([7u8; 32])
}

fn reg() -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = [(1u8, 10u64), (2, 10), (3, 10), (4, 10)]
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(gen_id(), &entries).expect("registry")
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn vote(height: u64, round: u32, phase: VotePhase, value: [u8; 32], seed: u8) -> ConsensusVote {
    let mut v = ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: gen_id(),
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

fn new_engine(height: u64) -> BftState {
    BftState::new(NET, &reg(), CheckpointHeight(height), ANCHOR)
}

/// A quorate prevote certificate for `value` at `round`: validator 1 signs
/// through the engine (so its slot exists), validators 2 and 3 are injected
/// (weight 30 >= 27).
fn prevote_certificate_at(
    engine: &mut BftState,
    store: &dyn AtomicSlotStore,
    round: u32,
    value: [u8; 32],
) -> PrevoteCertificate {
    let registry = reg();
    if engine.round.get() < round {
        engine.begin_round(Round(round)).expect("round");
    }
    engine.propose(value).expect("propose");
    engine
        .prevote(value, vid(1), &registry, store, sign_with(1))
        .expect("own prevote");
    for seed in [2u8, 3u8] {
        let v = vote(engine.height.get(), round, VotePhase::Prevote, value, seed);
        assert!(matches!(
            engine.accept_vote(&v, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    engine
        .certify_prevotes_for(value, &registry)
        .expect("quorate prevote certificate")
}

/// Lock `value` at `round` through the precommit path (`AW-LOCK-2`).
fn lock_at(
    engine: &mut BftState,
    store: &dyn AtomicSlotStore,
    round: u32,
    value: [u8; 32],
) -> ProofOfLock {
    let certificate = prevote_certificate_at(engine, store, round, value);
    engine
        .precommit(&certificate, vid(1), &reg(), store, sign_with(1))
        .expect("precommit establishes the lock");
    ProofOfLock::from_prevote(certificate)
}

fn precommit_slot(height: u64, round: u32, seed: u8) -> SlotKey {
    SlotKey {
        generation: gen_id().0,
        height: CheckpointHeight(height),
        round: Round(round),
        phase: VotePhase::Precommit,
        validator: vid(seed),
    }
}

/// Write a durable **signed** precommit into `store`, with no engine involved.
///
/// This is the crash artefact: the signature is on disk, whoever produced the
/// lock record is gone.
fn plant_signed_precommit(store: &dyn AtomicSlotStore, height: u64, round: u32, value: [u8; 32]) {
    let slot = precommit_slot(height, round, 1);
    store.reserve(&slot, &value).expect("reserve");
    store
        .record_signed(&vote(height, round, VotePhase::Precommit, value, 1))
        .expect("record signature");
    store.flush().expect("flush");
}

/// A store holding the lock state of `engine` and **no vote slots at all**.
///
/// Models a crash where the lock (written first) is durable but the signature
/// never reached the slot, and gives tests a lock they can combine with
/// hand-written evidence.
fn store_with_state_only(engine: &BftState) -> MemoryAtomicSlotStore {
    let store = MemoryAtomicSlotStore::new();
    engine.persisted().persist(&store).expect("persist state");
    store
}

fn blocked(state: &BftState) -> bool {
    state.may_sign().is_err()
}

// ---------------------------------------------------------------------------
// AY-01 / AY-02. The two crash artefacts that must block.
// ---------------------------------------------------------------------------

#[test]
fn ay_01_a_durable_precommit_without_a_lock_blocks_signing() {
    // Case G: the signature survived, the lock record did not. No persisted
    // state at all, so AU's anchor gate is silenced (`expected_anchor = None`)
    // and only the engine's own evidence audit can catch it.
    let store = MemoryAtomicSlotStore::new();
    plant_signed_precommit(&store, 0, 0, A);

    let restored = restore_engine(&store, &reg(), None, NET, CheckpointHeight(0));
    assert!(
        blocked(&restored.state),
        "AW-LOCK-11(c): a durable precommit with no lock must block signing"
    );
    match &restored.state.persisted().status {
        aether_unified::l2persist::RecoveryStatus::RecoveryRequired(
            aether_unified::l2persist::RecoveryReason::ContradictoryLock(text),
        ) => assert!(text.contains("without a lock record"), "{text}"),
        other => panic!("expected ContradictoryLock, got {other:?}"),
    }
    // Evidence is evidence: the slot is still there, untouched.
    assert_eq!(store.scan_slots().expect("scan").len(), 1);
    assert_eq!(restored.state.persisted().locked, None);
}

#[test]
fn ay_02_a_reserved_precommit_without_a_lock_blocks_signing() {
    // Case B: killed after `reserve` + flush, before the signature. The
    // reservation itself is not a signature, but a reservation at this height
    // means the lock (written first) was lost, so the state is not trustworthy.
    let store = MemoryAtomicSlotStore::new();
    store
        .reserve(&precommit_slot(0, 0, 1), &A)
        .expect("reserve");
    store.flush().expect("flush");

    let restored = restore_engine(&store, &reg(), None, NET, CheckpointHeight(0));
    assert!(
        blocked(&restored.state),
        "reservation without lock must block"
    );
    assert!(matches!(
        &restored.state.persisted().status,
        aether_unified::l2persist::RecoveryStatus::RecoveryRequired(
            aether_unified::l2persist::RecoveryReason::ContradictoryLock(_)
        )
    ));
}

// ---------------------------------------------------------------------------
// AY-03 / AY-04. Contradictory and stale summaries.
// ---------------------------------------------------------------------------

#[test]
fn ay_03_two_values_at_the_same_round_block_signing() {
    // Case I: the lock says A@0, the slots say B@0. Under `A1` this cannot
    // happen; observing it is a halt condition, never an arbitration.
    let first = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &first, 0, A);
    assert_eq!(
        engine.active_lock().map(|l| l.checkpoint_id),
        Some(A),
        "precondition: the lock is A@0"
    );

    let store = store_with_state_only(&engine);
    plant_signed_precommit(&store, 0, 0, B);
    assert_eq!(store.scan_slots().expect("scan").len(), 1);

    let restored = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        blocked(&restored.state),
        "contradictory evidence must block"
    );
    // AU's own slot cross-check catches this pair first
    // ("signature contradicts the locked value"); the engine's audit uses the
    // same verdict when AU cannot see it (AY-01, AY-02, AY-04). What matters here
    // is that the state is blocked and the evidence kept.
    match &restored.state.persisted().status {
        aether_unified::l2persist::RecoveryStatus::RecoveryRequired(
            aether_unified::l2persist::RecoveryReason::ContradictoryLock(_),
        ) => {}
        other => panic!("expected ContradictoryLock, got {other:?}"),
    }
    // Neither side is deleted: the lock keeps A, the slot keeps B.
    assert_eq!(
        restored.state.active_lock().map(|l| l.checkpoint_id),
        Some(A)
    );
    assert_eq!(store.scan_slots().expect("scan").len(), 1);
}

#[test]
fn ay_04_a_lock_older_than_the_evidence_blocks_signing() {
    // The summary is stale: a precommit at round 1 exists, the lock still says
    // round 0. `I-2` (`lockR >= r` of every own precommit) is violated.
    let first = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &first, 0, A);

    let store = store_with_state_only(&engine);
    plant_signed_precommit(&store, 0, 1, A);

    let restored = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(blocked(&restored.state), "a stale lock must block");
    assert!(matches!(
        &restored.state.persisted().status,
        aether_unified::l2persist::RecoveryStatus::RecoveryRequired(
            aether_unified::l2persist::RecoveryReason::ContradictoryLock(text)
        ) if text.contains("disagrees with the durable precommit")
    ));
}

// ---------------------------------------------------------------------------
// AY-05 / AY-06. Coherent restores must stay permissive.
// ---------------------------------------------------------------------------

#[test]
fn ay_05_a_lock_without_any_signature_still_constrains_the_next_prevote() {
    // Case C: the lock (written before the signature) is durable, the signature
    // never was. No evidence contradicts the summary, so the restore is clean —
    // and the lock still refuses a contradictory prevote.
    let first = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &first, 0, A);
    let store = store_with_state_only(&engine);
    assert!(store.scan_slots().expect("scan").is_empty());

    let restored = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.state.may_sign().is_ok(),
        "a lock alone is coherent: {:?}",
        restored.state.persisted().status
    );
    assert_eq!(
        restored.state.active_lock().map(|l| l.checkpoint_id),
        Some(A)
    );

    let mut engine = restored.state;
    engine.begin_round(Round(1)).expect("round 1");
    assert!(matches!(
        engine.prevote(B, vid(1), &reg(), &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    engine
        .prevote(A, vid(1), &reg(), &store, sign_with(1))
        .expect("the locked value stays signable");
}

#[test]
fn ay_06_a_nil_precommit_never_makes_a_lock_look_stale() {
    // `AW-LOCK-3`: a Nil precommit establishes nothing. It must not block a
    // restore, and it must not authorize anything either.
    let first = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &first, 0, A);
    let store = store_with_state_only(&engine);

    let nil = aether_unified::l2bft::NIL_VALUE;
    let slot = precommit_slot(0, 1, 1);
    store.reserve(&slot, &nil).expect("reserve");
    store
        .record_signed(&vote(0, 1, VotePhase::Precommit, nil, 1))
        .expect("record");

    let restored = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.state.may_sign().is_ok(),
        "a Nil precommit is not evidence of a lock: {:?}",
        restored.state.persisted().status
    );
    assert_eq!(
        restored.state.active_lock().map(|l| l.checkpoint_id),
        Some(A)
    );
}

// ---------------------------------------------------------------------------
// AY-07 / AY-08. Unreadable evidence and the forbidden unlock path.
// ---------------------------------------------------------------------------

#[test]
fn ay_07_an_undecodable_slot_blocks_signing() {
    // An unreadable commitment is not an absent one: fail closed.
    let store = MemoryAtomicSlotStore::new();
    let key = format!("{SLOT_PREFIX}vandalised");
    store.cas(&key, None, b"not an envelope").expect("write");

    let restored = restore_engine(&store, &reg(), None, NET, CheckpointHeight(0));
    assert!(blocked(&restored.state), "garbage evidence must block");
    // AU reports a corrupt slot as `IncoherentSlot`; an unreadable record is
    // never read as an absent one.
    assert!(matches!(
        &restored.state.persisted().status,
        aether_unified::l2persist::RecoveryStatus::RecoveryRequired(
            aether_unified::l2persist::RecoveryReason::IncoherentSlot(_)
                | aether_unified::l2persist::RecoveryReason::CorruptState(_)
        )
    ));
}

#[test]
fn ay_08_a_provisionally_unlocked_state_is_refused_by_the_engine() {
    // `AW-LOCK-5`: no unlock. `l2persist` still exposes the primitive, so the
    // engine must refuse to operate from a state that recorded one — even with
    // every slot coherent.
    let first = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &first, 0, A);
    // BU removed `apply_provisional_unlock`; a legacy store can still carry the
    // flag, and the engine must refuse it. `unlock_rule_provisional` is set on a
    // clone of the record, never through the engine's own state.
    let mut provisional = engine.persisted().clone();
    provisional.unlock_rule_provisional = true;
    let store = MemoryAtomicSlotStore::new();
    provisional
        .persist(&store)
        .expect("persist the legacy provisional state");

    let restored = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        blocked(&restored.state),
        "a provisional unlock must not be operable"
    );
    assert!(matches!(
        &restored.state.persisted().status,
        aether_unified::l2persist::RecoveryStatus::RecoveryRequired(
            aether_unified::l2persist::RecoveryReason::IncompleteState(text)
        ) if text.contains("provisional unlock")
    ));
}

// ---------------------------------------------------------------------------
// AY-09 / AY-10. What a blocked restore may and may not do.
// ---------------------------------------------------------------------------

#[test]
fn ay_09_a_blocked_restore_never_writes_a_new_slot() {
    let store = MemoryAtomicSlotStore::new();
    plant_signed_precommit(&store, 0, 0, A);
    let before = store.scan_slots().expect("scan").len();

    let mut engine = restore_engine(&store, &reg(), None, NET, CheckpointHeight(0)).state;
    assert!(matches!(
        engine.begin_round(Round(1)),
        Err(BftError::RecoveryRequired(_))
    ));
    assert!(matches!(
        engine.prevote(A, vid(1), &reg(), &store, sign_with(1)),
        Err(BftError::RecoveryRequired(_))
    ));
    assert_eq!(
        store.scan_slots().expect("scan").len(),
        before,
        "a refused vote writes nothing"
    );
}

#[test]
fn ay_10_crashes_before_any_vote_leave_a_clean_restore() {
    // Case A: killed before the reservation. Nothing on disk is nothing to
    // recover, and a fresh store must not be blocked by the audit.
    let store = MemoryAtomicSlotStore::new();
    let restored = restore_engine(&store, &reg(), None, NET, CheckpointHeight(0));
    assert!(
        restored.state.may_sign().is_ok(),
        "{:?}",
        restored.state.persisted().status
    );
    let mut engine = restored.state;
    engine
        .prevote(A, vid(1), &reg(), &store, sign_with(1))
        .expect("a clean store signs");
}

#[test]
fn ay_11_restoration_is_deterministic() {
    let first = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &first, 0, A);
    let store = store_with_state_only(&engine);
    plant_signed_precommit(&store, 0, 0, B);

    let one = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    let two = restore_engine(&store, &reg(), Some(ANCHOR), NET, CheckpointHeight(0));
    assert_eq!(one.state.persisted().status, two.state.persisted().status);
    assert_eq!(one.state.persisted().locked, two.state.persisted().locked);
    assert_eq!(one.state.lock_proof_absent, two.state.lock_proof_absent);
    assert_eq!(one.decisions.len(), two.decisions.len());
}
