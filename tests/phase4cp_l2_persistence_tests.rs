//! PHASE 4CP-AU — persistent L2 safety: atomic slots, locks, recovery.
//!
//! Every test is deterministic except the concurrency ones, which use a real
//! `Barrier` and real threads, and the multi-process one, which spawns a second
//! OS process running this same test binary.
//!
//! # What these tests are allowed to claim
//!
//! They exercise the primitives that exist: `sled` compare-and-swap, an
//! exclusive lock file, `flush()`. They do **not** demonstrate liveness, finality
//! or power-loss durability.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::PrevoteCertificate;
use aether_unified::l2crypto::qc::{QuorumCertificate, QC_FORMAT_VERSION};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::slotlock::SLOT_PREFIX;
use aether_unified::l2persist::state::PersistentConsensusState;
use aether_unified::l2persist::{
    observe_and_persist, open_sealed, restore, seal, sign_vote, AtomicSlotStore, CasStore,
    EmitError, LockAction, MemoryAtomicSlotStore, RecoveryReason, RecoveryStatus, Settlement,
    SledAtomicSlotStore, SlotKey, SlotReservation, SlotState, SlotStoreError, SlotStoreGuard,
    VoteAuthorization, STATE_KEY,
};

const NET: u64 = 7;
const ANCHOR: [u8; 32] = [0xAA; 32];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn gen_id() -> GenerationId {
    GenerationId([3u8; 32])
}

fn ckpt(b: u8) -> [u8; 32] {
    [b; 32]
}

fn registry_with(members: &[(u8, u64)]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = members
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(gen_id(), &entries).expect("registry builds")
}

/// Two validators of weight 10 each: quorum is 14, so one signer is not enough.
fn registry() -> ValidatorRegistry {
    registry_with(&[(1, 10), (2, 10)])
}

fn unsigned_vote(
    height: u64,
    round: u32,
    phase: VotePhase,
    checkpoint: [u8; 32],
    signer: u8,
) -> ConsensusVote {
    ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: gen_id(),
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        checkpoint_id: checkpoint,
        validator: vid(signer),
        signature: [0u8; 64],
    }
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn fresh_state() -> PersistentConsensusState {
    PersistentConsensusState::fresh(NET, gen_id(), ANCHOR)
}

// ---------------------------------------------------------------------------
// BU: authorised signing through the public, validated constructors.
//
// `sign_vote` now requires a `VoteAuthorization`. These helpers build one with
// the production constructors only: `for_prevote` applies `A4'`, `for_precommit`
// applies `N-PC-1`/`AW-LOCK-8` (a re-verified prevote certificate and this
// validator's own prevote). Any refusal is returned unchanged, so a test that
// asserted `EmitError::LockedValueConflict` against `sign_vote` still asserts it.
// ---------------------------------------------------------------------------

fn signed_vote(
    height: u64,
    round: u32,
    phase: VotePhase,
    checkpoint: [u8; 32],
    signer: u8,
) -> ConsensusVote {
    let unsigned = unsigned_vote(height, round, phase, checkpoint, signer);
    let mut vote = unsigned.clone();
    vote.signature = sk(signer).sign(&unsigned.signing_bytes()).to_bytes();
    vote
}

fn seed_of(validator: ValidatorId) -> u8 {
    (1u8..=2)
        .find(|seed| vid(*seed) == validator)
        .expect("the fixture only knows validators 1 and 2")
}

fn prevote_certificate(
    registry: &ValidatorRegistry,
    height: u64,
    round: u32,
    checkpoint: [u8; 32],
) -> PrevoteCertificate {
    let votes = vec![
        signed_vote(height, round, VotePhase::Prevote, checkpoint, 1),
        signed_vote(height, round, VotePhase::Prevote, checkpoint, 2),
    ];
    let qc = QuorumCertificate::new(
        NET,
        registry,
        CheckpointHeight(height),
        Round(round),
        VotePhase::Prevote,
        checkpoint,
        votes,
    );
    PrevoteCertificate::certify(qc, registry, NET).expect("quorate prevote certificate")
}

fn sign_authorized(
    state: &PersistentConsensusState,
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    vote: &ConsensusVote,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<aether_unified::l2persist::SignedOutcome, EmitError> {
    let authorization = if vote.phase == VotePhase::Prevote {
        VoteAuthorization::for_prevote(state, vote, None, registry)
    } else {
        let certificate = prevote_certificate(
            registry,
            vote.height.get(),
            vote.round.get(),
            vote.checkpoint_id,
        );
        let own_prevote = signed_vote(
            vote.height.get(),
            vote.round.get(),
            VotePhase::Prevote,
            vote.checkpoint_id,
            seed_of(vote.validator),
        );
        VoteAuthorization::for_precommit(state, vote, &certificate, &own_prevote, registry)
    };
    match authorization {
        Ok(authorization) => sign_vote(state, store, registry, vote, &authorization, sign),
        Err(error) => Err(error),
    }
}

fn slot_of(height: u64, round: u32, phase: VotePhase, signer: u8) -> SlotKey {
    SlotKey {
        generation: gen_id().0,
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        validator: vid(signer),
    }
}

/// A certificate over `signers`, with the declared weights computed honestly.
fn make_qc(
    registry: &ValidatorRegistry,
    height: u64,
    round: u32,
    checkpoint: [u8; 32],
    signers: &[u8],
) -> QuorumCertificate {
    let votes: Vec<ConsensusVote> = signers
        .iter()
        .map(|seed| {
            let unsigned = unsigned_vote(height, round, VotePhase::Precommit, checkpoint, *seed);
            let mut vote = unsigned.clone();
            vote.signature = sk(*seed).sign(&unsigned.signing_bytes()).to_bytes();
            vote
        })
        .collect();
    let support: u64 = signers
        .iter()
        .map(|seed| {
            registry
                .get(&vid(*seed))
                .map(|e| e.weight.get())
                .unwrap_or(0)
        })
        .sum();
    QuorumCertificate {
        version: QC_FORMAT_VERSION,
        network: NET,
        generation: gen_id(),
        height: CheckpointHeight(height),
        round: Round(round),
        phase: VotePhase::Precommit,
        checkpoint_id: checkpoint,
        validator_set_root: registry.set_root(),
        registry_root: registry.root(),
        total_weight: ValidatorWeight(registry.total_voting_weight().get()),
        support_weight: ValidatorWeight(support),
        votes,
    }
}

// ---------------------------------------------------------------------------
// 1. Atomic reservation
// ---------------------------------------------------------------------------

#[test]
fn first_reservation_wins_and_repeats_are_idempotent() {
    let store = MemoryAtomicSlotStore::new();
    let slot = slot_of(5, 1, VotePhase::Prevote, 1);

    match store.reserve(&slot, &ckpt(0x11)).expect("reserve") {
        aether_unified::l2persist::ReserveOutcome::Granted(r) => {
            assert_eq!(r.checkpoint_id, ckpt(0x11));
            assert_eq!(r.state, SlotState::Reserved);
            assert!(r.vote.is_none());
        }
        other => panic!("expected Granted, got {other:?}"),
    }

    // Same value: idempotent, still the first commitment.
    match store.reserve(&slot, &ckpt(0x11)).expect("reserve") {
        aether_unified::l2persist::ReserveOutcome::Idempotent(r) => {
            assert_eq!(r.checkpoint_id, ckpt(0x11));
        }
        other => panic!("expected Idempotent, got {other:?}"),
    }
    assert_eq!(store.len(), 1);
}

#[test]
fn conflicting_value_never_overwrites_the_first_commitment() {
    let store = MemoryAtomicSlotStore::new();
    let slot = slot_of(5, 1, VotePhase::Prevote, 1);
    store.reserve(&slot, &ckpt(0x11)).expect("first");

    match store.reserve(&slot, &ckpt(0x22)).expect("second") {
        aether_unified::l2persist::ReserveOutcome::Conflicting(r) => {
            assert_eq!(r.checkpoint_id, ckpt(0x11), "evidence preserved");
        }
        other => panic!("expected Conflicting, got {other:?}"),
    }

    // Third attempt still sees the original value.
    let read = store.load(&slot).expect("load").expect("present");
    assert_eq!(read.checkpoint_id, ckpt(0x11));
}

#[test]
fn slot_key_encoding_is_canonical_and_strict() {
    let slot = slot_of(9, 3, VotePhase::Precommit, 2);
    let enc = slot.encode();
    assert_eq!(enc.len(), 77);
    assert_eq!(SlotKey::decode(&enc).expect("decode"), slot);

    assert!(SlotKey::decode(&enc[..76]).is_err());
    let mut extended = enc.clone();
    extended.push(0);
    assert!(SlotKey::decode(&extended).is_err());

    let mut bad_phase = enc.clone();
    bad_phase[44] = 9;
    assert!(SlotKey::decode(&bad_phase).is_err());

    // Content addressing: different slots, different keys.
    assert_ne!(
        slot.storage_key(),
        slot_of(10, 3, VotePhase::Precommit, 2).storage_key()
    );
    assert_ne!(
        slot.storage_key(),
        slot_of(9, 4, VotePhase::Precommit, 2).storage_key()
    );
    assert_ne!(
        slot.storage_key(),
        slot_of(9, 3, VotePhase::Prevote, 2).storage_key()
    );
    assert_ne!(
        slot.storage_key(),
        slot_of(9, 3, VotePhase::Precommit, 1).storage_key()
    );
    assert!(slot.storage_key().starts_with(SLOT_PREFIX));
}

#[test]
fn forged_record_is_rejected_by_the_envelope() {
    let payload = SlotReservation {
        slot: slot_of(1, 0, VotePhase::Prevote, 1),
        checkpoint_id: ckpt(0x11),
        state: SlotState::Reserved,
        vote: None,
    }
    .encode();

    let sealed = seal(&payload);
    assert_eq!(open_sealed(&sealed).expect("valid"), payload.as_slice());

    let mut flipped = sealed.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(matches!(
        open_sealed(&flipped),
        Err(SlotStoreError::Corrupt(_))
    ));

    let mut truncated = sealed.clone();
    truncated.truncate(sealed.len() - 1);
    assert!(matches!(
        open_sealed(&truncated),
        Err(SlotStoreError::Corrupt(_))
    ));

    // Signed record without its vote must not decode.
    let lying = SlotReservation {
        slot: slot_of(1, 0, VotePhase::Prevote, 1),
        checkpoint_id: ckpt(0x11),
        state: SlotState::Signed,
        vote: None,
    };
    assert!(SlotReservation::decode(&lying.encode()).is_err());
}

// ---------------------------------------------------------------------------
// 2. Real thread concurrency
// ---------------------------------------------------------------------------

#[test]
fn racing_threads_with_distinct_values_have_exactly_one_winner() {
    for attempt in 0..16u8 {
        let store = Arc::new(MemoryAtomicSlotStore::new());
        let barrier = Arc::new(Barrier::new(8));
        let slot = slot_of(4, 2, VotePhase::Precommit, 1);
        let granted = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for i in 0..8u8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let granted = Arc::clone(&granted);
            let value = if i % 2 == 0 { ckpt(0x11) } else { ckpt(0x22) };
            handles.push(thread::spawn(move || {
                barrier.wait();
                match store.reserve(&slot, &value).expect("reserve") {
                    aether_unified::l2persist::ReserveOutcome::Granted(_) => {
                        granted.fetch_add(1, Ordering::SeqCst);
                    }
                    aether_unified::l2persist::ReserveOutcome::Idempotent(r) => {
                        // Same value already committed: the record is ours.
                        assert_eq!(r.checkpoint_id, value);
                    }
                    aether_unified::l2persist::ReserveOutcome::Conflicting(r) => {
                        // A conflict never overwrites: it reports the winner's
                        // value, which proves this thread lost the race.
                        assert_ne!(r.checkpoint_id, value);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        assert_eq!(
            granted.load(Ordering::SeqCst),
            1,
            "attempt {attempt}: exactly one thread may win the slot"
        );
        assert_eq!(store.len(), 1, "one slot, one record");
        let stored = store.load(&slot).expect("load").expect("present");
        assert!(
            stored.checkpoint_id == ckpt(0x11) || stored.checkpoint_id == ckpt(0x22),
            "stored value must be one of the racing values"
        );
    }
}

#[test]
fn racing_threads_with_the_same_value_all_succeed_idempotently() {
    let store = Arc::new(MemoryAtomicSlotStore::new());
    let barrier = Arc::new(Barrier::new(6));
    let slot = slot_of(6, 0, VotePhase::Prevote, 2);

    let mut handles = Vec::new();
    for _ in 0..6 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            match store.reserve(&slot, &ckpt(0x33)).expect("reserve") {
                aether_unified::l2persist::ReserveOutcome::Granted(_)
                | aether_unified::l2persist::ReserveOutcome::Idempotent(_) => {}
                other => panic!("same value must never conflict: {other:?}"),
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    assert_eq!(store.len(), 1);
}

// ---------------------------------------------------------------------------
// 3. Real second process
// ---------------------------------------------------------------------------

/// Helper executed in a child process; does nothing unless `AU_CHILD_DIR` is set.
#[test]
fn __au_child_tries_to_open_the_store() {
    let Ok(dir) = std::env::var("AU_CHILD_DIR") else {
        return;
    };
    match SledAtomicSlotStore::open(&dir) {
        Err(SlotStoreError::StoreLocked { .. }) => println!("AU_CHILD=LOCKED"),
        Ok(_) => println!("AU_CHILD=OPENED"),
        Err(e) => println!("AU_CHILD=OTHER:{e}"),
    }
}

#[test]
fn a_second_process_cannot_open_the_vote_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SledAtomicSlotStore::open(dir.path()).expect("parent opens store");
    assert!(store.lock_path().exists());

    let exe = std::env::current_exe().expect("test binary");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "__au_child_tries_to_open_the_store",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("AU_CHILD_DIR", dir.path())
        .output()
        .expect("spawn child");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(output.status.success(), "child failed: {stdout}");
    assert!(
        stdout.contains("AU_CHILD=LOCKED"),
        "second process must fail closed, got: {stdout}"
    );

    // The parent still owns the store.
    let slot = slot_of(1, 0, VotePhase::Prevote, 1);
    store
        .reserve(&slot, &ckpt(0x11))
        .expect("parent still works");
}

#[test]
fn a_stale_lock_file_blocks_sign_in_until_released() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let _store = SledAtomicSlotStore::open(dir.path()).expect("first open");
    } // dropped: lock file removed

    // Simulate a crash: leave a lock file behind.
    std::fs::write(dir.path().join("l2-bft.lock"), "999999").expect("stale lock");
    match SledAtomicSlotStore::open(dir.path()) {
        Err(SlotStoreError::StoreLocked { pid }) => assert_eq!(pid, 999999),
        Ok(_) => panic!("must fail closed while a lock file exists"),
        Err(e) => panic!("unexpected error: {e}"),
    }

    // Explicit operator release, then it works again.
    let pid = SlotStoreGuard::release_stale(dir.path()).expect("release");
    assert_eq!(pid, 999999);
    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen after release");
    store
        .reserve(&slot_of(1, 0, VotePhase::Prevote, 1), &ckpt(0x11))
        .expect("works after release");
}

// ---------------------------------------------------------------------------
// 4. Signing order and durability barrier
// ---------------------------------------------------------------------------

#[test]
fn the_reservation_is_flushed_before_the_signature_exists() {
    struct Counting {
        inner: MemoryAtomicSlotStore,
        flushes_at_sign: AtomicU64,
        flushed_before_sign: std::sync::atomic::AtomicBool,
    }

    impl CasStore for Counting {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
            self.inner.get(key)
        }
        fn cas(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            new: &[u8],
        ) -> Result<bool, SlotStoreError> {
            self.inner.cas(key, expected, new)
        }
        fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
            self.inner.scan(prefix)
        }
        fn flush(&self) -> Result<(), SlotStoreError> {
            self.inner.flush()
        }
        fn backend(&self) -> &'static str {
            "counting"
        }
    }
    impl AtomicSlotStore for Counting {}

    let reg = registry();
    let state = fresh_state();
    let store = Counting {
        inner: MemoryAtomicSlotStore::new(),
        flushes_at_sign: AtomicU64::new(0),
        flushed_before_sign: std::sync::atomic::AtomicBool::new(false),
    };
    let store_ref = &store;

    let unsigned = unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1);
    let key = sk(1);
    let outcome = sign_authorized(&state, store_ref, &reg, &unsigned, move |msg| {
        let count = store_ref.inner.flush_count();
        store_ref.flushes_at_sign.store(count, Ordering::SeqCst);
        store_ref
            .flushed_before_sign
            .store(count >= 1, Ordering::SeqCst);
        key.sign(msg).to_bytes()
    })
    .expect("signed");

    assert_eq!(outcome.settlement, Settlement::FreshlySigned);
    assert!(outcome.flushed_before_signing);
    assert!(
        store.flushed_before_sign.load(Ordering::SeqCst),
        "a flush must have happened before signing"
    );
    assert!(
        store.flushes_at_sign.load(Ordering::SeqCst) >= 1,
        "reservation flush observed at signing time"
    );
}

#[test]
fn signing_twice_is_idempotent_and_never_resigns() {
    let reg = registry();
    let state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let unsigned = unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1);

    let first = sign_authorized(&state, &store, &reg, &unsigned, sign_with(1)).expect("first");
    assert_eq!(first.settlement, Settlement::FreshlySigned);

    let second = sign_authorized(&state, &store, &reg, &unsigned, sign_with(1)).expect("second");
    assert_eq!(second.settlement, Settlement::AlreadySigned);
    assert!(!second.flushed_before_signing, "nothing was signed again");
    assert_eq!(first.vote.id(), second.vote.id());
    assert_eq!(store.len(), 1);
}

#[test]
fn a_conflicting_signature_is_refused_at_the_slot() {
    let reg = registry();
    let state = fresh_state();
    let store = MemoryAtomicSlotStore::new();

    sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1),
        sign_with(1),
    )
    .expect("first signs");

    let err = sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x55), 1),
        sign_with(1),
    )
    .expect_err("equivocation must be refused");

    match err {
        EmitError::Equivocation {
            existing_checkpoint,
        } => assert_eq!(existing_checkpoint, ckpt(0x44)),
        other => panic!("expected Equivocation, got {other:?}"),
    }

    // Evidence intact.
    let stored = store
        .load(&slot_of(3, 0, VotePhase::Precommit, 1))
        .expect("load")
        .expect("present");
    assert_eq!(stored.checkpoint_id, ckpt(0x44));
}

#[test]
fn a_vote_that_already_carries_a_signature_is_rejected() {
    let reg = registry();
    let state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let mut signed = unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1);
    signed.signature = [9u8; 64];

    match sign_authorized(&state, &store, &reg, &signed, sign_with(1)) {
        Err(EmitError::NotUnsigned) => {}
        other => panic!("expected NotUnsigned, got {other:?}"),
    }
    assert!(store.is_empty(), "nothing may be reserved");
}

#[test]
fn a_vote_for_another_network_or_generation_is_refused() {
    let reg = registry();
    let state = fresh_state();
    let store = MemoryAtomicSlotStore::new();

    let mut wrong_net = unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1);
    wrong_net.network = NET + 1;
    match sign_authorized(&state, &store, &reg, &wrong_net, sign_with(1)) {
        Err(EmitError::NetworkMismatch { .. }) => {}
        other => panic!("expected NetworkMismatch, got {other:?}"),
    }

    let mut wrong_gen = unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1);
    wrong_gen.generation = GenerationId([99u8; 32]);
    match sign_authorized(&state, &store, &reg, &wrong_gen, sign_with(1)) {
        Err(EmitError::GenerationMismatch) => {}
        other => panic!("expected GenerationMismatch, got {other:?}"),
    }
    assert!(store.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Crash windows
// ---------------------------------------------------------------------------

#[test]
fn crash_between_reservation_and_signature_still_blocks_a_second_value() {
    let reg = registry();
    let state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let slot = slot_of(3, 0, VotePhase::Precommit, 1);

    // Simulate: reserved, flushed, then the process died before signing.
    store.reserve(&slot, &ckpt(0x44)).expect("reserve");
    store.flush().expect("flush");
    assert!(store.load(&slot).expect("load").unwrap().vote.is_none());

    // A different value can never be signed afterwards.
    match sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x55), 1),
        sign_with(1),
    ) {
        Err(EmitError::Equivocation { .. }) => {}
        other => panic!("expected Equivocation, got {other:?}"),
    }

    // The same value is safe: identical commitment, so no equivocation.
    let outcome = sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(3, 0, VotePhase::Precommit, ckpt(0x44), 1),
        sign_with(1),
    )
    .expect("same value signs");
    assert_eq!(outcome.settlement, Settlement::FreshlySigned);
    assert!(outcome.reservation.vote.is_some());
}

#[test]
fn a_signature_survives_a_reopen_of_the_durable_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let reg = registry();
    let state = fresh_state();
    let unsigned = unsigned_vote(4, 1, VotePhase::Precommit, ckpt(0x66), 2);
    let slot = SlotKey::of(&unsigned);

    let vote_id = {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let outcome =
            sign_authorized(&state, &store, &reg, &unsigned, sign_with(2)).expect("signed");
        state.persist(&store).expect("state persisted");
        outcome.vote.id()
    };

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let record = store.load(&slot).expect("load").expect("present");
    assert_eq!(record.state, SlotState::Signed);
    assert_eq!(record.vote.expect("vote").id(), vote_id);

    let report = restore(&store, Some(ANCHOR), NET);
    assert_eq!(report.slots, 1);
    assert_eq!(report.signed, 1);
    assert_eq!(report.reservations_without_signature, 0);
    assert!(report.may_sign(), "findings: {:?}", report.findings);
}

// ---------------------------------------------------------------------------
// 6. Locks
// ---------------------------------------------------------------------------

#[test]
fn a_certificate_establishes_a_lock_and_never_unlocks_automatically() {
    let reg = registry();
    let mut state = fresh_state();
    let store = MemoryAtomicSlotStore::new();

    let qc_a = make_qc(&reg, 10, 1, ckpt(0xA1), &[1, 2]);
    match observe_and_persist(&mut state, &store, &qc_a, &reg, NET).expect("observe") {
        LockAction::Locked { round } => assert_eq!(round, Round(1)),
        other => panic!("expected Locked, got {other:?}"),
    }
    assert_eq!(state.locked.expect("locked").checkpoint_id, ckpt(0xA1));

    // A later-round certificate for another value records evidence only.
    let qc_b = make_qc(&reg, 10, 3, ckpt(0xB2), &[1, 2]);
    match observe_and_persist(&mut state, &store, &qc_b, &reg, NET).expect("observe") {
        LockAction::UnlockRequiresOperator { current, proposed } => {
            assert_eq!(current.checkpoint_id, ckpt(0xA1));
            assert_eq!(proposed.checkpoint_id, ckpt(0xB2));
        }
        other => panic!("expected UnlockRequiresOperator, got {other:?}"),
    }
    assert_eq!(
        state.locked.expect("still locked").checkpoint_id,
        ckpt(0xA1),
        "safety: nothing unlocked without an explicit operator call"
    );

    // BU: the proof is evidence only. `apply_provisional_unlock` and
    // `apply_and_persist` were removed because `AW-LOCK-5` forbids unlocking, so
    // no public call can move the lock from here — the removal is the assertion.
    assert!(
        state.proof_of_lock.is_some(),
        "the later certificate stays recorded as evidence"
    );
    assert_eq!(
        state.locked.expect("still locked").checkpoint_id,
        ckpt(0xA1),
        "nothing unlocks, not even with a valid higher-round proof"
    );
    assert!(!state.unlock_rule_provisional);
}

#[test]
fn an_older_round_certificate_for_another_value_is_refused() {
    let reg = registry();
    let mut state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let qc_a = make_qc(&reg, 10, 5, ckpt(0xA1), &[1, 2]);
    observe_and_persist(&mut state, &store, &qc_a, &reg, NET).expect("lock");

    let qc_old = make_qc(&reg, 10, 2, ckpt(0xC3), &[1, 2]);
    match observe_and_persist(&mut state, &store, &qc_old, &reg, NET).expect("observe") {
        LockAction::Refused { .. } => {}
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn signing_a_value_that_contradicts_the_lock_is_refused() {
    let reg = registry();
    let mut state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let qc_a = make_qc(&reg, 10, 2, ckpt(0xA1), &[1, 2]);
    observe_and_persist(&mut state, &store, &qc_a, &reg, NET).expect("lock");

    // Same height, different checkpoint, round <= locked round.
    let err = sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(10, 2, VotePhase::Precommit, ckpt(0xDE), 1),
        sign_with(1),
    )
    .expect_err("locked conflict must be refused");
    match err {
        EmitError::LockedValueConflict { locked, requested } => {
            assert_eq!(locked, ckpt(0xA1));
            assert_eq!(requested, ckpt(0xDE));
        }
        other => panic!("expected LockedValueConflict, got {other:?}"),
    }
    // The refusal must leave no vote slot behind, while the lock itself is
    // already persisted under `STATE_KEY` (AW-LOCK-4: a durable lock is what a
    // restart must find). "Empty store" is therefore not the observable;
    // "no slot record" is.
    assert!(
        store.scan_slots().expect("scan").is_empty(),
        "nothing was reserved"
    );
    assert!(
        store.get(STATE_KEY).expect("state").is_some(),
        "the lock itself is persisted"
    );

    // The locked value itself is fine.
    sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(10, 2, VotePhase::Precommit, ckpt(0xA1), 1),
        sign_with(1),
    )
    .expect("locked value signs");
}

#[test]
fn nothing_can_move_the_lock_after_the_provisional_unlock_was_removed() {
    let reg = registry();
    let mut state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let qc_a = make_qc(&reg, 10, 1, ckpt(0xA1), &[1, 2]);
    observe_and_persist(&mut state, &store, &qc_a, &reg, NET).expect("lock");
    let qc_b = make_qc(&reg, 10, 4, ckpt(0xB2), &[1, 2]);
    observe_and_persist(&mut state, &store, &qc_b, &reg, NET).expect("evidence");

    // BU removed the only function that could take a proof identifier, so there
    // is no call left to make with a wrong one. What remains to verify is that
    // observing never moved the lock by itself.
    assert!(
        state.proof_of_lock.is_some(),
        "the higher certificate is recorded, not applied"
    );
    assert_eq!(state.locked.expect("unchanged").checkpoint_id, ckpt(0xA1));
}

// ---------------------------------------------------------------------------
// 7. Recovery
// ---------------------------------------------------------------------------

#[test]
fn missing_data_is_never_read_as_absence_of_a_vote() {
    let store = MemoryAtomicSlotStore::new();
    let report = restore(&store, Some(ANCHOR), NET);
    assert_eq!(
        report.status,
        RecoveryStatus::RecoveryRequired(RecoveryReason::MissingAnchor)
    );
    assert!(!report.may_sign());
    assert_eq!(report.slots, 0);

    // Without an expected anchor, the same emptiness is reported, not resolved.
    let lenient = restore(&store, None, NET);
    assert!(lenient.may_sign());
    assert_eq!(lenient.state, None);
}

#[test]
fn a_foreign_store_is_detected_by_its_anchor() {
    let store = MemoryAtomicSlotStore::new();
    let state = fresh_state();
    state.persist(&store).expect("persist");

    let other = [0xBB; 32];
    match restore(&store, Some(other), NET).status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::ForeignAnchor { expected, found }) => {
            assert_eq!(expected, other);
            assert_eq!(found, ANCHOR);
        }
        other_status => panic!("expected ForeignAnchor, got {other_status:?}"),
    }
}

#[test]
fn corrupt_slot_metadata_blocks_signing() {
    let store = MemoryAtomicSlotStore::new();
    let slot = slot_of(2, 0, VotePhase::Prevote, 1);
    store.reserve(&slot, &ckpt(0x11)).expect("reserve");

    // Overwrite with bytes that fail the envelope digest.
    let key = slot.storage_key();
    let current = store.get(&key).expect("get").expect("present");
    let garbage = vec![0u8; 32];
    assert!(store.cas(&key, Some(&current), &garbage).expect("cas"));

    let report = restore(&store, None, NET);
    match report.status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::CorruptState(_)) => {}
        RecoveryStatus::RecoveryRequired(RecoveryReason::IncoherentSlot(_)) => {}
        other => panic!("corruption must block signing, got {other:?}"),
    }
    assert!(!report.may_sign());
}

#[test]
fn a_reservation_left_by_a_crash_is_reported_and_still_safe() {
    let store = MemoryAtomicSlotStore::new();
    let slot = slot_of(2, 0, VotePhase::Prevote, 1);
    store.reserve(&slot, &ckpt(0x11)).expect("reserve");
    store.flush().expect("flush");

    let report = restore(&store, Some(ANCHOR), NET);
    // No state record yet, so the anchor check fires; the reservation is counted.
    assert_eq!(report.slots, 1);
    assert_eq!(report.reservations_without_signature, 1);
    assert_eq!(report.signed, 0);

    let state = fresh_state();
    let reg = registry();
    // Even with a clean state, the recorded reservation cannot be replaced.
    match sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(2, 0, VotePhase::Prevote, ckpt(0x22), 1),
        sign_with(1),
    ) {
        Err(EmitError::Equivocation { .. }) => {}
        other => panic!("expected Equivocation, got {other:?}"),
    }
}

#[test]
fn a_lock_without_its_proof_is_incomplete() {
    let store = MemoryAtomicSlotStore::new();
    let mut state = fresh_state();
    state.locked = Some(aether_unified::l2persist::LockedValue {
        checkpoint_id: ckpt(0xA1),
        height: CheckpointHeight(10),
        round: Round(1),
    });
    state.proof_of_lock = None;
    state.persist(&store).expect("persist");

    match restore(&store, Some(ANCHOR), NET).status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::IncompleteState(msg)) => {
            assert!(msg.contains("lock"), "reason: {msg}");
        }
        other => panic!("expected IncompleteState, got {other:?}"),
    }
}

#[test]
fn contradictory_locks_and_certificates_are_detected() {
    let reg = registry();
    let mut state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let qc_a = make_qc(&reg, 10, 3, ckpt(0xA1), &[1, 2]);
    observe_and_persist(&mut state, &store, &qc_a, &reg, NET).expect("lock");

    // Forge a persisted state whose certificate names another value at the same round.
    state.last_valid_certificate = Some(aether_unified::l2persist::LastValidCertificate {
        height: CheckpointHeight(10),
        round: Round(3),
        phase: VotePhase::Precommit,
        checkpoint_id: ckpt(0xBB),
        qc_id: ckpt(0xBB),
    });
    state.persist(&store).expect("persist forged state");

    match restore(&store, Some(ANCHOR), NET).status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::ContradictoryLock(_)) => {}
        other => panic!("expected ContradictoryLock, got {other:?}"),
    }
}

#[test]
fn a_signature_contradicting_the_lock_blocks_recovery() {
    let reg = registry();
    let mut state = fresh_state();
    let store = MemoryAtomicSlotStore::new();
    let qc_a = make_qc(&reg, 10, 2, ckpt(0xA1), &[1, 2]);
    observe_and_persist(&mut state, &store, &qc_a, &reg, NET).expect("lock");
    state.persist(&store).expect("state");

    // A signed vote at the same height and at the lock's own round for another
    // value: a real contradiction, refused. (BW, R-BV-1: a vote at a round
    // *below* the lock round is prior history that `A4'` allows.)
    let other = unsigned_vote(10, 2, VotePhase::Prevote, ckpt(0xCC), 1);
    let slot = SlotKey::of(&other);
    store.reserve(&slot, &ckpt(0xCC)).expect("reserve");
    let mut signed = other.clone();
    signed.signature = sk(1).sign(&other.signing_bytes()).to_bytes();
    store.record_signed(&signed).expect("record");

    match restore(&store, Some(ANCHOR), NET).status {
        RecoveryStatus::RecoveryRequired(RecoveryReason::ContradictoryLock(_)) => {}
        other => panic!("expected ContradictoryLock, got {other:?}"),
    }
}

#[test]
fn an_uncertain_restoration_refuses_every_new_signature() {
    let store = MemoryAtomicSlotStore::new();
    let reg = registry();
    let report = restore(&store, Some(ANCHOR), NET);
    assert!(!report.may_sign());

    let mut state = report.state.unwrap_or_else(fresh_state);
    state.status = report.status.clone();

    let err = sign_authorized(
        &state,
        &store,
        &reg,
        &unsigned_vote(1, 0, VotePhase::Prevote, ckpt(0x11), 1),
        sign_with(1),
    )
    .expect_err("uncertain state must not sign");
    assert!(matches!(err, EmitError::RecoveryRequired(_)));
    assert!(store.is_empty(), "nothing may be written while uncertain");
}

#[test]
fn recovery_counts_a_clean_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let reg = registry();
    let state = fresh_state();
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        state.persist(&store).expect("persist");
        sign_authorized(
            &state,
            &store,
            &reg,
            &unsigned_vote(1, 0, VotePhase::Prevote, ckpt(0x11), 1),
            sign_with(1),
        )
        .expect("sign");
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let report = restore(&store, Some(ANCHOR), NET);
    assert!(report.may_sign(), "findings: {:?}", report.findings);
    assert_eq!(report.slots, 1);
    assert_eq!(report.signed, 1);
    let restored = report.state.expect("state");
    assert_eq!(restored.anchor, ANCHOR);
    assert_eq!(restored.network, NET);
}

// ---------------------------------------------------------------------------
// 8. Backend agreement
// ---------------------------------------------------------------------------

#[test]
fn memory_and_sled_backends_reach_the_same_decisions() {
    let mem = MemoryAtomicSlotStore::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let disk = SledAtomicSlotStore::open(dir.path()).expect("open");
    let slot = slot_of(7, 1, VotePhase::Precommit, 2);

    let a = mem.reserve(&slot, &ckpt(0x11)).expect("mem");
    let b = disk.reserve(&slot, &ckpt(0x11)).expect("disk");
    assert!(matches!(
        a,
        aether_unified::l2persist::ReserveOutcome::Granted(_)
    ));
    assert!(matches!(
        b,
        aether_unified::l2persist::ReserveOutcome::Granted(_)
    ));

    let a = mem.reserve(&slot, &ckpt(0x11)).expect("mem");
    let b = disk.reserve(&slot, &ckpt(0x11)).expect("disk");
    assert!(matches!(
        a,
        aether_unified::l2persist::ReserveOutcome::Idempotent(_)
    ));
    assert!(matches!(
        b,
        aether_unified::l2persist::ReserveOutcome::Idempotent(_)
    ));

    let a = mem.reserve(&slot, &ckpt(0x22)).expect("mem");
    let b = disk.reserve(&slot, &ckpt(0x22)).expect("disk");
    match (a, b) {
        (
            aether_unified::l2persist::ReserveOutcome::Conflicting(x),
            aether_unified::l2persist::ReserveOutcome::Conflicting(y),
        ) => {
            assert_eq!(x.checkpoint_id, ckpt(0x11));
            assert_eq!(y.checkpoint_id, ckpt(0x11));
        }
        other => panic!("backends disagree: {other:?}"),
    }

    // Persisted state round-trips identically on both.
    let state = fresh_state();
    state.persist(&mem).expect("mem persist");
    state.persist(&disk).expect("disk persist");
    assert_eq!(
        PersistentConsensusState::load(&mem).expect("load mem"),
        PersistentConsensusState::load(&disk).expect("load disk")
    );
    assert!(mem.get(STATE_KEY).expect("get").is_some());
}
