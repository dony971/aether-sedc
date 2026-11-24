//! PHASE 4BX — HALT atomicity, persistence concurrency and durability.
//!
//! Mission BX closes the four risks left open by BW, without touching the
//! consensus rules:
//!
//! | Risk | What BX changes | Tests |
//! |---|---|---|
//! | R-BW-2: a signature could be *released* after a HALT | a third durable read, after the signature is recorded, turns a crossing HALT into `SignedButHalted` (the vote is never returned for broadcast) | `bx_01` - `bx_04` |
//! | R-BW-3: `persist` = get + CAS could overwrite a newer record | `persist` refuses any snapshot that would move a monotone safety field backwards | `bx_07` - `bx_11` |
//! | R-BW-4: `highest_signed_round` was never advanced | it becomes an audit summary, scoped to one height and re-derived from the slot records at restore; the unsound "signed round below the watermark" block is removed | `bx_14` |
//! | R-BW-5: recovery after an altered proof | the lock survives, the proof is dropped, nothing unlocks, and the proof can be re-established from a certificate | `bx_15`, `bx_16` |
//!
//! The races are deterministic: every interleaving is forced by a store hook or
//! a `Barrier`, never by timing. Keys, votes and signatures are fixed. "Crash"
//! means dropping the handle; "restart" means reopening the same directory.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{
    restore_engine, BftState, HaltReason, PrevoteCertificate, ProofOfLock, VoteOutcome,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::{
    restore, seal, sign_vote, AtomicSlotStore, CasStore, EmitError, LastValidCertificate,
    LockedValue, MemoryAtomicSlotStore, PersistentConsensusState, RecoveryReason, RecoveryStatus,
    Settlement, SledAtomicSlotStore, SlotKey, SlotState, SlotStoreError, VoteAuthorization,
    HALT_KEY, SLOT_PREFIX, STATE_KEY,
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
    let entries: Vec<RegistryEntry> = [(1u8, 10u64), (2, 10), (3, 10), (4, 10)]
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(gen(), &entries).expect("registry")
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn unsigned(height: u64, round: u32, phase: VotePhase, value: [u8; 32]) -> ConsensusVote {
    ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: gen(),
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        checkpoint_id: value,
        validator: vid(1),
        signature: [0u8; 64],
    }
}

fn signed(height: u64, round: u32, phase: VotePhase, value: [u8; 32], seed: u8) -> ConsensusVote {
    let mut vote = ConsensusVote {
        validator: vid(seed),
        ..unsigned(height, round, phase, value)
    };
    vote.signature = sk(seed).sign(&vote.signing_bytes()).to_bytes();
    vote
}

fn engine_with(height: u64) -> BftState {
    BftState::new(NET, &reg(), CheckpointHeight(height), ANCHOR)
}

fn fresh_state() -> PersistentConsensusState {
    PersistentConsensusState::fresh(NET, gen(), ANCHOR)
}

fn halt(store: &dyn CasStore, text: &str) {
    assert!(
        store
            .cas(HALT_KEY, None, &seal(text.as_bytes()))
            .expect("write halt"),
        "halt written once"
    );
}

fn slot_of(height: u64, round: u32, phase: VotePhase) -> SlotKey {
    SlotKey {
        generation: gen().0,
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        validator: vid(1),
    }
}

fn slot_count(store: &dyn AtomicSlotStore) -> usize {
    store.scan(SLOT_PREFIX).expect("scan").len()
}

fn signed_slots(store: &dyn AtomicSlotStore) -> usize {
    store
        .scan_slots()
        .expect("scan")
        .iter()
        .filter(|record| matches!(record.state, SlotState::Signed))
        .count()
}

/// A quorate prevote certificate at `round`, from the engine's own prevote and
/// two peers.
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
        assert!(matches!(
            engine.accept_vote(
                &signed(height, round, VotePhase::Prevote, value, seed),
                registry
            ),
            VoteOutcome::Accepted { .. }
        ));
    }
    engine
        .certify_prevotes_for(value, registry)
        .expect("quorate prevote certificate")
}

/// Lock `value` at `round`; returns the proof the lock was written with.
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

/// Memory store that writes the HALT record on its **first** `flush`.
///
/// In `sign_vote` the first flush is the durability barrier that follows the
/// reservation — exactly the window R-BW-2 is about.
struct HaltOnFirstFlush {
    inner: MemoryAtomicSlotStore,
    flushes: AtomicUsize,
}

impl HaltOnFirstFlush {
    fn new() -> Self {
        Self {
            inner: MemoryAtomicSlotStore::new(),
            flushes: AtomicUsize::new(0),
        }
    }
}

impl CasStore for HaltOnFirstFlush {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        self.inner.get(key)
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        self.inner.cas(key, expected, new)
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.inner.scan(prefix)
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        if self.flushes.fetch_add(1, Ordering::SeqCst) == 0 {
            halt(&self.inner, "halt between reservation and signature");
        }
        self.inner.flush()
    }

    fn backend(&self) -> &'static str {
        "halt-on-first-flush"
    }
}

impl AtomicSlotStore for HaltOnFirstFlush {}

/// Memory store that writes the HALT record just before the `Reserved -> Signed`
/// swap, i.e. after the signature exists but before it is recorded.
struct HaltBeforeRecord {
    inner: MemoryAtomicSlotStore,
    armed: AtomicBool,
}

impl HaltBeforeRecord {
    fn new() -> Self {
        Self {
            inner: MemoryAtomicSlotStore::new(),
            armed: AtomicBool::new(true),
        }
    }
}

impl CasStore for HaltBeforeRecord {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        self.inner.get(key)
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        if key.starts_with(SLOT_PREFIX)
            && expected.is_some()
            && self.armed.swap(false, Ordering::SeqCst)
        {
            halt(&self.inner, "halt between signature and record");
        }
        self.inner.cas(key, expected, new)
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.inner.scan(prefix)
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        self.inner.flush()
    }

    fn backend(&self) -> &'static str {
        "halt-before-record"
    }
}

impl AtomicSlotStore for HaltBeforeRecord {}

/// Memory store whose first two `STATE_KEY` reads rendezvous, so two `persist`
/// calls decide on the same record before either swaps.
struct RendezvousStore {
    inner: MemoryAtomicSlotStore,
    reads: AtomicUsize,
    barrier: Barrier,
}

impl RendezvousStore {
    fn new() -> Self {
        Self {
            inner: MemoryAtomicSlotStore::new(),
            reads: AtomicUsize::new(0),
            barrier: Barrier::new(2),
        }
    }
}

impl CasStore for RendezvousStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        let read = self.inner.get(key)?;
        if key == STATE_KEY && self.reads.fetch_add(1, Ordering::SeqCst) < 2 {
            self.barrier.wait();
        }
        Ok(read)
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        self.inner.cas(key, expected, new)
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.inner.scan(prefix)
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        self.inner.flush()
    }

    fn backend(&self) -> &'static str {
        "rendezvous"
    }
}

impl AtomicSlotStore for RendezvousStore {}

// ---------------------------------------------------------------------------
// R-BW-2 — HALT and the signature frontier
// ---------------------------------------------------------------------------

/// A HALT that exists before the call stops it before anything is reserved.
#[test]
fn bx_01_a_halt_before_the_call_creates_no_slot() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let state = fresh_state();
    halt(&store, "operator halt");
    let vote = unsigned(0, 1, VotePhase::Prevote, A);
    let auth = VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");

    match sign_vote(&state, &store, &registry, &vote, &auth, sign_with(1)) {
        Err(EmitError::Halted(reason)) => assert!(reason.contains("operator halt")),
        other => panic!("expected Halted, got {other:?}"),
    }
    assert_eq!(slot_count(&store), 0, "no slot may exist after a halt");
}

/// HALT committed between the durable reservation and `sign()`: the second read
/// observes it, so no signature is produced.
#[test]
fn bx_02_a_halt_after_the_reservation_stops_the_signature() {
    let registry = reg();
    let store = HaltOnFirstFlush::new();
    let state = fresh_state();
    let vote = unsigned(0, 1, VotePhase::Prevote, A);
    let auth = VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");

    match sign_vote(&state, &store, &registry, &vote, &auth, sign_with(1)) {
        Err(EmitError::Halted(_)) => {}
        other => panic!("expected Halted, got {other:?}"),
    }
    let record = store
        .load(&slot_of(0, 1, VotePhase::Prevote))
        .expect("load")
        .expect("the reservation is durable");
    assert_eq!(record.state, SlotState::Reserved);
    assert!(record.vote.is_none(), "no signature may exist");
    assert_eq!(
        store.flushes.load(Ordering::SeqCst),
        1,
        "the halt was observed at the post-reservation gate"
    );
}

/// HALT committed while `sign()` runs: the signature exists, is recorded, and is
/// **not released**. The durable slot is the crash-equivalent evidence.
#[test]
fn bx_03_a_halt_during_the_signature_is_never_released() {
    let registry = reg();
    let store = Arc::new(MemoryAtomicSlotStore::new());
    let state = fresh_state();
    let vote = unsigned(0, 1, VotePhase::Prevote, A);
    let auth = VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");
    let key = sk(1);
    let writer = Arc::clone(&store);

    let result = sign_vote(&state, &*store, &registry, &vote, &auth, move |msg| {
        halt(&*writer, "halt during signature");
        key.sign(msg).to_bytes()
    });
    match result {
        Err(EmitError::SignedButHalted(reason)) => {
            assert!(reason.contains("halt during signature"), "{reason}")
        }
        other => panic!("expected SignedButHalted, got {other:?}"),
    }
    let record = store
        .load(&slot_of(0, 1, VotePhase::Prevote))
        .expect("load")
        .expect("slot");
    assert_eq!(record.state, SlotState::Signed);
    assert!(
        record.vote.is_some(),
        "the signature is durable evidence, never a released vote"
    );
}

/// HALT committed between `sign()` and the `Reserved -> Signed` swap: same
/// outcome, and the caller is told not to broadcast.
#[test]
fn bx_04_a_halt_before_the_record_is_never_released() {
    let registry = reg();
    let store = HaltBeforeRecord::new();
    let state = fresh_state();
    let vote = unsigned(0, 1, VotePhase::Prevote, A);
    let auth = VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");

    match sign_vote(&state, &store, &registry, &vote, &auth, sign_with(1)) {
        Err(EmitError::SignedButHalted(_)) => {}
        other => panic!("expected SignedButHalted, got {other:?}"),
    }
    let record = store
        .load(&slot_of(0, 1, VotePhase::Prevote))
        .expect("load")
        .expect("slot");
    assert_eq!(record.state, SlotState::Signed);
}

/// A crash between the reservation and the signature is reported at restart, and
/// the same value can be signed again: the reservation already commits it.
#[test]
fn bx_05_a_crash_after_the_reservation_is_crash_equivalent() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let state = fresh_state();
    state.persist(&store).expect("persist the clean state");
    let vote = unsigned(0, 1, VotePhase::Prevote, A);
    assert!(matches!(
        store.reserve(&SlotKey::of(&vote), &A).expect("reserve"),
        aether_unified::l2persist::ReserveOutcome::Granted(_)
    ));
    store.flush().expect("flush");

    let report = restore(&store, Some(ANCHOR), NET);
    assert_eq!(report.reservations_without_signature, 1);
    assert!(
        report.may_sign(),
        "a pre-signature crash is not a lock loss"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("without signature")),
        "{:?}",
        report.findings
    );

    let auth = VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");
    let outcome = sign_vote(&state, &store, &registry, &vote, &auth, sign_with(1))
        .expect("the reserved slot still commits this value");
    assert_eq!(outcome.settlement, Settlement::FreshlySigned);
    assert_eq!(slot_count(&store), 1, "the reservation was reused");
}

/// Two threads sign the same slot for different values: exactly one signature.
#[test]
fn bx_06_two_concurrent_signers_produce_one_signature() {
    let registry = Arc::new(reg());
    let store = Arc::new(MemoryAtomicSlotStore::new());
    let state = Arc::new(fresh_state());
    let barrier = Arc::new(Barrier::new(2));

    let mut handles = Vec::new();
    for value in [A, B] {
        let registry = Arc::clone(&registry);
        let store = Arc::clone(&store);
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let vote = unsigned(0, 1, VotePhase::Prevote, value);
            let auth =
                VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");
            barrier.wait();
            sign_vote(&*state, &*store, &*registry, &vote, &auth, sign_with(1))
        }));
    }
    let results: Vec<Result<_, EmitError>> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one value wins the slot"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(EmitError::Equivocation { .. })))
            .count(),
        1,
        "the other is refused as equivocation, never signed"
    );
    assert_eq!(signed_slots(&*store), 1);
}

// ---------------------------------------------------------------------------
// R-BW-3 — persist and concurrent writers
// ---------------------------------------------------------------------------

/// The lost update: a snapshot taken before another writer's lock, persisted
/// after it, used to replace the record. It is refused now.
#[test]
fn bx_07_a_stale_unlocked_snapshot_cannot_replace_a_lock() {
    let store = MemoryAtomicSlotStore::new();
    let mut locked = fresh_state();
    let lock = LockedValue {
        checkpoint_id: B,
        height: CheckpointHeight(0),
        round: Round(4),
    };
    locked.locked = Some(lock);
    locked.proof_of_lock = Some(proof_for(lock));
    locked.persist(&store).expect("the lock is durable");

    let stale = fresh_state();
    assert_eq!(
        stale.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter)
    );
    let durable = PersistentConsensusState::load(&store)
        .expect("load")
        .expect("record");
    assert_eq!(durable.locked, Some(lock), "the lock was not overwritten");
    assert!(durable.proof_of_lock.is_some());
}

/// A lock may not move backwards in height or round, and two values may not hold
/// one round.
#[test]
fn bx_08_a_lock_only_moves_forward() {
    let store = MemoryAtomicSlotStore::new();
    let mut durable = fresh_state();
    let newer = LockedValue {
        checkpoint_id: B,
        height: CheckpointHeight(2),
        round: Round(5),
    };
    durable.locked = Some(newer);
    durable.proof_of_lock = Some(proof_for(newer));
    durable.persist(&store).expect("persist");

    let mut older_round = durable.clone();
    older_round.locked = Some(LockedValue {
        checkpoint_id: newer.checkpoint_id,
        height: newer.height,
        round: Round(3),
    });
    assert_eq!(
        older_round.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter)
    );

    let mut older_height = durable.clone();
    older_height.locked = Some(LockedValue {
        checkpoint_id: newer.checkpoint_id,
        height: CheckpointHeight(1),
        round: newer.round,
    });
    assert_eq!(
        older_height.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter)
    );

    let other = LockedValue {
        checkpoint_id: A,
        height: newer.height,
        round: newer.round,
    };
    let mut other_value = durable.clone();
    other_value.locked = Some(other);
    other_value.proof_of_lock = Some(proof_for(other));
    assert_eq!(
        other_value.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter),
        "AW-LOCK-10: two values cannot hold one round"
    );

    // A legitimate advance, at a later round of the same height, is accepted.
    let mut forward = durable.clone();
    let moved = LockedValue {
        checkpoint_id: newer.checkpoint_id,
        height: newer.height,
        round: Round(7),
    };
    forward.locked = Some(moved);
    forward.proof_of_lock = Some(proof_for(moved));
    forward
        .persist(&store)
        .expect("a forward lock is legitimate");
    assert_eq!(
        PersistentConsensusState::load(&store)
            .expect("load")
            .expect("record")
            .locked,
        Some(moved)
    );
}

/// Dropping the **lock** is a safety regression. Dropping the proof is not: it
/// costs proposability, is recoverable from a certificate, and refusing it would
/// freeze a node that restored with an unverifiable proof.
#[test]
fn bx_09_a_lock_is_never_dropped_by_a_stale_snapshot() {
    let store = MemoryAtomicSlotStore::new();
    let mut durable = fresh_state();
    let lock = LockedValue {
        checkpoint_id: C,
        height: CheckpointHeight(1),
        round: Round(2),
    };
    durable.locked = Some(lock);
    durable.proof_of_lock = Some(proof_for(lock));
    durable.persist(&store).expect("persist");

    let mut no_proof = durable.clone();
    no_proof.proof_of_lock = None;
    no_proof
        .persist(&store)
        .expect("a dropped proof is a recoverable proposability loss");
    let after = PersistentConsensusState::load(&store)
        .expect("load")
        .expect("record");
    assert_eq!(after.locked, Some(lock), "the lock survives the proof loss");
    assert!(after.proof_of_lock.is_none());

    let mut no_lock = after.clone();
    no_lock.locked = None;
    no_lock.proof_of_lock = None;
    assert_eq!(
        no_lock.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter)
    );

    assert_eq!(
        PersistentConsensusState::load(&store)
            .expect("load")
            .expect("record")
            .locked,
        Some(lock)
    );
}

/// The last valid certificate only advances, and the provisional-unlock flag is
/// sticky.
#[test]
fn bx_10_the_certified_position_only_advances() {
    let store = MemoryAtomicSlotStore::new();
    let mut durable = fresh_state();
    durable.last_valid_certificate = Some(certificate(Round(5)));
    durable.persist(&store).expect("persist");

    let mut older = durable.clone();
    older.last_valid_certificate = Some(certificate(Round(3)));
    assert_eq!(
        older.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter)
    );

    let mut removed = durable.clone();
    removed.last_valid_certificate = None;
    assert_eq!(
        removed.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter)
    );

    let mut forward = durable.clone();
    forward.last_valid_certificate = Some(certificate(Round(9)));
    forward.persist(&store).expect("forward certificate");

    // A provisional unlock is sticky: it can never be silently cleared.
    let lock = LockedValue {
        checkpoint_id: B,
        height: CheckpointHeight(0),
        round: Round(2),
    };
    let mut provisional = fresh_state();
    provisional.locked = Some(lock);
    provisional.proof_of_lock = Some(proof_for(lock));
    provisional.last_valid_certificate = Some(certificate(Round(9)));
    provisional.unlock_rule_provisional = true;
    provisional.persist(&store).expect("provisional record");

    let mut cleared = provisional.clone();
    cleared.unlock_rule_provisional = false;
    assert_eq!(
        cleared.persist(&store),
        Err(aether_unified::l2persist::StateError::ConcurrentWriter),
        "a provisional unlock is never silently cleared"
    );
}

/// Two writers that both read the same record: one swaps, the other is told.
#[test]
fn bx_11_concurrent_persists_have_one_durable_winner() {
    let store = Arc::new(RendezvousStore::new());
    let barrier = Arc::new(Barrier::new(2));
    let mut left = fresh_state();
    left.last_valid_certificate = Some(certificate(Round(5)));
    let mut right = fresh_state();
    right.last_valid_certificate = Some(certificate(Round(7)));

    let mut handles = Vec::new();
    for (label, state) in [("left", left), ("right", right)] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            (label, state.persist(&*store))
        }));
    }
    let results: Vec<(&str, Result<(), _>)> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(
        results.iter().filter(|(_, r)| r.is_ok()).count(),
        1,
        "one writer wins"
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, r)| matches!(
                r,
                Err(aether_unified::l2persist::StateError::ConcurrentWriter)
            ))
            .count(),
        1
    );
    let winner = results
        .iter()
        .find(|(_, r)| r.is_ok())
        .map(|(label, _)| *label)
        .expect("winner");
    let durable = PersistentConsensusState::load(&*store)
        .expect("load")
        .expect("record");
    let expected = if winner == "left" { Round(5) } else { Round(7) };
    assert_eq!(
        durable.last_valid_certificate.map(|c| c.round),
        Some(expected),
        "the durable record is the winner's, whole"
    );
}

// ---------------------------------------------------------------------------
// Durability — the Sled backend
// ---------------------------------------------------------------------------

/// HALT, signature and state survive a close/reopen on the real backend.
#[test]
fn bx_12_sled_reopen_keeps_the_signature_and_the_halt() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = engine_with(0);
        engine.begin_round(Round(1)).expect("round");
        engine.propose(A).expect("propose");
        engine
            .prevote(A, vid(1), &registry, &store, sign_with(1))
            .expect("prevote");
        engine.persisted().persist(&store).expect("persist state");
        engine
            .halt_with(HaltReason::Persisted("durable halt".to_string()), &store)
            .expect("halt");
        assert_eq!(signed_slots(&store), 1);
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    assert_eq!(signed_slots(&store), 1, "the signature survived");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.is_halted(), "the halt survived");
    assert!(
        restored.state.may_sign().is_err(),
        "the engine refuses every signature after the halt"
    );
    assert_eq!(
        restored.state.persisted().highest_signed_round,
        Round(1),
        "the summary is re-derived from the durable slot"
    );
}

/// Four threads race for one durable slot on Sled: one signature, and it is
/// still one after reopening.
#[test]
fn bx_13_sled_concurrent_signers_leave_one_signature() {
    let registry = Arc::new(reg());
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(SledAtomicSlotStore::open(dir.path()).expect("open"));
    let state = Arc::new(fresh_state());
    let barrier = Arc::new(Barrier::new(4));

    let mut handles = Vec::new();
    for value in [A, B, C, [0xD4u8; 32]] {
        let registry = Arc::clone(&registry);
        let store = Arc::clone(&store);
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let vote = unsigned(0, 1, VotePhase::Prevote, value);
            let auth =
                VoteAuthorization::for_prevote(&state, &vote, None, &registry).expect("admissible");
            barrier.wait();
            sign_vote(&*state, &*store, &*registry, &vote, &auth, sign_with(1))
        }));
    }
    let results: Vec<Result<_, EmitError>> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(signed_slots(&*store), 1);
    drop(store);

    let reopened = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    assert_eq!(signed_slots(&reopened), 1);
    let records = reopened.scan_slots().expect("scan");
    assert_eq!(records.len(), 1);
    assert!(records[0].vote.is_some());
}

// ---------------------------------------------------------------------------
// R-BW-4 — highest_signed_round
// ---------------------------------------------------------------------------

/// The summary is derived from the signed slots, not trusted from the record; a
/// signed vote *below* it does not block (normal round progression), while a
/// summary that no slot proves does.
#[test]
fn bx_14_the_signed_round_summary_is_derived_and_unprovable_claims_block() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(0);
    engine.begin_round(Round(1)).expect("round 1");
    engine.propose(A).expect("propose");
    engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("prevote in round 1");
    engine.begin_round(Round(5)).expect("round 5");
    engine.propose(B).expect("propose");
    engine
        .prevote(B, vid(1), &registry, &store, sign_with(1))
        .expect("prevote in round 5");
    engine.persisted().persist(&store).expect("persist");

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.report.may_sign(), "{:?}", restored.report.findings);
    assert_eq!(restored.state.persisted().highest_signed_round, Round(5));
    assert_eq!(
        signed_slots(&store),
        2,
        "a lower-round signature is history, not a contradiction"
    );

    // A record claiming a round no slot proves means a vote record is missing.
    let mut forged = restored.state.persisted().clone();
    forged.highest_signed_round = Round(9);
    forged
        .persist(&store)
        .expect("the summary is not an ordering input");
    let blocked = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        blocked.state.may_sign().is_err(),
        "the engine refuses a signature its store cannot prove (report: {:?})",
        blocked.report.findings
    );
    match &blocked.state.persisted().status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::IncompleteState(text)) => {
            assert!(text.contains("no signed slot"), "reason: {text}")
        }
        other => panic!("expected IncompleteState, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R-BW-5 — recovery after an altered proof
// ---------------------------------------------------------------------------

fn proof_for(lock: LockedValue) -> aether_unified::l2persist::ProofOfLock {
    aether_unified::l2persist::ProofOfLock {
        round: lock.round,
        qc_id: [0x11; 32],
        support: 30,
        total: 40,
        signers: 3,
        proposed: lock,
        encoded_qc: vec![0x01, 0x02],
    }
}

fn certificate(round: Round) -> LastValidCertificate {
    LastValidCertificate {
        height: CheckpointHeight(0),
        round,
        phase: VotePhase::Precommit,
        checkpoint_id: B,
        qc_id: [round.get() as u8; 32],
    }
}

/// A proof whose bytes no longer verify costs proposability, never the lock; the
/// lock keeps refusing a contradictory signature, and the proof can be
/// re-established from a certificate at the same round.
#[test]
fn bx_15_an_altered_proof_never_unlocks_and_can_be_re_established() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let signing = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(0);
    let certificate = prevote_certificate_at(&mut engine, &signing, &registry, 0, 2, B);
    engine
        .precommit(&certificate, vid(1), &registry, &signing, sign_with(1))
        .expect("lock");

    let mut state = engine.persisted().clone();
    // The votes of this scenario were signed into a scratch store, so the record
    // must not claim a signature the restored store cannot prove (R-BX-4). Only
    // the proof is under test here.
    state.highest_signed_round = Round(0);
    let proof = state.proof_of_lock.as_mut().expect("proof");
    proof.encoded_qc[7] ^= 0x40;
    state.persist(&store).expect("persist the altered proof");

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.report.may_sign(), "{:?}", restored.report.findings);
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.checkpoint_id),
        Some(B),
        "the lock survives the altered proof"
    );
    assert!(
        restored.state.persisted().proof_of_lock.is_none(),
        "a proof that does not re-verify is dropped"
    );
    assert!(restored.state.lock_proof_absent);

    let mut recovered = restored.state;
    // Still locked: another value is refused.
    assert!(recovered
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .is_err());
    // The locked value stays signable, and a certificate at the same round
    // re-establishes the proof without moving the lock.
    recovered.begin_round(Round(2)).expect("round 2");
    recovered.propose(B).expect("propose the locked value");
    recovered
        .prevote(B, vid(1), &registry, &store, sign_with(1))
        .expect("the lock authorises its own value");
    for seed in [2u8, 3u8] {
        assert!(matches!(
            recovered.accept_vote(&signed(0, 2, VotePhase::Prevote, B, seed), &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let fresh_certificate = recovered
        .certify_prevotes_for(B, &registry)
        .expect("certificate");
    fresh_certificate
        .re_verify(&registry, NET)
        .expect("the recovered certificate verifies on its own");
    if let Err(error) =
        recovered.precommit(&fresh_certificate, vid(1), &registry, &store, sign_with(1))
    {
        panic!("the proof could not be written again: {error:?}");
    }
    assert_eq!(
        recovered.persisted().locked.map(|l| l.checkpoint_id),
        Some(B)
    );
    assert!(recovered.persisted().proof_of_lock.is_some());
    assert!(!recovered.lock_proof_absent);
}

/// A truncated state record fails closed: no state, no signature, no unlock.
#[test]
fn bx_16_a_truncated_record_fails_closed() {
    let store = MemoryAtomicSlotStore::new();
    let mut state = fresh_state();
    let lock = LockedValue {
        checkpoint_id: B,
        height: CheckpointHeight(0),
        round: Round(2),
    };
    state.locked = Some(lock);
    state.proof_of_lock = Some(proof_for(lock));
    let bytes = seal(&state.encode());
    let truncated = &bytes[..bytes.len() - 9];
    assert!(store.cas(STATE_KEY, None, truncated).expect("write"));

    let report = restore(&store, Some(ANCHOR), NET);
    assert!(matches!(
        report.status,
        RecoveryStatus::RecoveryRequired(RecoveryReason::CorruptState(_))
    ));
    assert!(report.state.is_none());
    assert!(!report.may_sign());
    assert!(report
        .findings
        .iter()
        .any(|f| f.contains("consensus state unreadable")));
}
