//! PHASE 4BV — independent validation of the BU BFT API hardening.
//!
//! This file adds no rule and changes no production code. It measures, on the
//! **real** sled-backed store, the four claims BU made:
//!
//! 1. an authorisation is rebuilt from verified state and proofs, never restored
//!    from storage (`bv_01`, `bv_03`);
//! 2. a lock written under the hardened API survives a restart, and a lock change
//!    authorised by a POL survives one too (`bv_01`, `bv_02`);
//! 3. read/write failures fail closed, before any signature exists (`bv_04`);
//! 4. concurrent authorisations cannot equivocate, and concurrent writers cannot
//!    leave a mixed lock/proof record (`bv_05` - `bv_09`).
//!
//! `bv_10` records the HALT boundary. In BV the engine's HALT stopped the
//! engine but not the raw primitive, because the flag lived in the engine and
//! not in the persisted state. Mission BW closed that gap (`sign_vote` now reads
//! the durable halt record), so `bv_02` and `bv_10` assert the corrected
//! behaviour; the change is documented in the BW report rather than hidden.
//!
//! BW also made `bv_09` deterministic: `PersistentConsensusState::persist` is a
//! read-then-CAS, so a writer that reads *after* another wrote legitimately
//! succeeds on the new bytes. The test now forces both writers to observe the
//! same (empty) record, which is the interleaving it means to test.
//!
//! Every count and iteration number used below is reported in
//! `persistence-and-restart.md` and `concurrency-results.md`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
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
    open_sealed, restore, sign_vote, AtomicSlotStore, CasStore, EmitError, LastValidCertificate,
    MemoryAtomicSlotStore, PersistentConsensusState, RecoveryReason, RecoveryStatus, Settlement,
    SledAtomicSlotStore, SlotKey, SlotReservation, SlotStoreError, StateError, VoteAuthorization,
    SLOT_PREFIX, STATE_KEY,
};

const NET: u64 = 43;
const ANCHOR: [u8; 32] = [0x5A; 32];
const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];

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

/// Collect the two remaining prevotes at the engine's current round and certify.
fn certify_peers_at(
    engine: &mut BftState,
    registry: &ValidatorRegistry,
    height: u64,
    round: u32,
    value: [u8; 32],
) -> PrevoteCertificate {
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

fn slot_count(store: &dyn AtomicSlotStore) -> usize {
    store
        .scan(SLOT_PREFIX)
        .expect("scan")
        .into_iter()
        .map(|(_, bytes)| {
            SlotReservation::decode(open_sealed(&bytes).expect("envelope")).expect("slot record")
        })
        .count()
}

// ---------------------------------------------------------------------------
// §4.1 - §4.6 — a lock written under the hardened API survives a real restart,
// and the authorisation is not part of what comes back.
// ---------------------------------------------------------------------------

#[test]
fn bv_01_a_real_restart_restores_the_lock_but_never_an_authorization() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");

    let persisted_bytes = {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open real store");
        let mut engine = engine_with(&registry, 0);

        // 1. An authorisation is created for this node's first prevote.
        engine.begin_round(Round(1)).expect("round 1");
        engine.propose(A).expect("propose A");
        let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
        let authorization =
            VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
                .expect("fresh node: the first prevote is admissible");
        assert!(authorization.covers(&candidate));
        assert_eq!(authorization.lock_value(), [0u8; 32]);
        assert_eq!(authorization.pol_qc_id(), None);

        // 2. The prevote is signed through the engine, on the real store.
        let prevote = engine
            .prevote(A, vid(1), &registry, &store, sign_with(1))
            .expect("prevote signed");
        prevote
            .vote()
            .verify(&registry, NET)
            .expect("a real Ed25519 signature");

        // The same authorisation, used again for the same vote, cannot produce a
        // second signature: the slot is idempotent.
        let replay = sign_vote(
            engine.persisted(),
            &store,
            &registry,
            &candidate,
            &authorization,
            sign_with(1),
        )
        .expect("reuse of the same vote is harmless");
        assert_eq!(replay.settlement, Settlement::AlreadySigned);
        assert_eq!(replay.vote.signature, prevote.vote().signature);

        // 3. The lock is persisted by the precommit path, before the signature.
        for seed in [2u8, 3u8] {
            let v = vote(gen().0, 0, 1, VotePhase::Prevote, A, seed);
            assert!(matches!(
                engine.accept_vote(&v, &registry),
                VoteOutcome::Accepted { .. }
            ));
        }
        let certificate = engine
            .certify_prevotes_for(A, &registry)
            .expect("quorate prevote certificate");
        engine
            .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
            .expect("precommit writes the lock");
        assert_eq!(
            engine
                .persisted()
                .locked
                .map(|l| (l.checkpoint_id, l.round)),
            Some((A, Round(1)))
        );
        assert!(engine.persisted().proof_of_lock.is_some());
        let state_bytes = store
            .get(STATE_KEY)
            .expect("state read")
            .expect("state is durable before the restart");
        let durable =
            PersistentConsensusState::decode(open_sealed(&state_bytes).expect("envelope"))
                .expect("decode");
        assert_eq!(durable.locked, engine.persisted().locked);
        state_bytes
    };

    // 4. Restart: the store is reopened from disk, not from memory.
    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen after restart");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.report.may_sign(),
        "findings: {:?}",
        restored.report.findings
    );
    assert_eq!(restored.report.slots, 2, "prevote and precommit slots");
    assert_eq!(restored.report.signed, 2);

    // 5. The lock and its proof came back intact.
    let state = restored.state.persisted();
    assert_eq!(
        state.locked.map(|l| (l.checkpoint_id, l.round, l.height)),
        Some((A, Round(1), CheckpointHeight(0)))
    );
    let proof = state.proof_of_lock.as_ref().expect("the POL is restored");
    assert_eq!(proof.proposed.checkpoint_id, A);
    assert_eq!(proof.round, Round(1));

    // The record is byte-identical to what was written: nothing about an
    // authorisation was added on the way through storage.
    assert_eq!(
        store.get(STATE_KEY).expect("read").expect("present"),
        persisted_bytes,
        "the persisted state is exactly the safety record, with no authorisation in it"
    );

    // 6. A contradictory vote at the next round is refused, and reconstructing an
    // authorisation for it fails at the constructor, not at the signer.
    let mut engine = restored.state;
    engine.begin_round(Round(2)).expect("round 2");
    engine.propose(B).expect("propose B");
    let contradictory = unsigned(gen().0, 0, 2, VotePhase::Prevote, B, 1);
    match VoteAuthorization::for_prevote(engine.persisted(), &contradictory, None, &registry) {
        Err(EmitError::NotAuthorized(reason)) => {
            assert!(reason.contains("proof of lock"), "reason: {reason}");
            assert!(
                reason.contains("round 1"),
                "the lock round is named: {reason}"
            );
        }
        other => panic!("expected NotAuthorized, got {other:?}"),
    }
    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert!(durable_vote(&store, 0, 2, VotePhase::Prevote, B).is_none());
    assert_eq!(
        engine.persisted().locked.map(|l| l.checkpoint_id),
        Some(A),
        "no failed attempt moved the lock"
    );
}

// ---------------------------------------------------------------------------
// §4.7 - §4.10 — a POL authorises a lock change, the change survives a restart,
// and a precommit after the restart is still authorised end to end.
// ---------------------------------------------------------------------------

#[test]
fn bv_02_a_pol_authorizes_the_lock_change_and_the_restart_flags_its_own_history() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open real store");
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &store, &registry, 0, 1, A);
        assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(A));

        // 7. A valid POL for B at round 2, produced by a real quorum: with
        // `lockR = 1 <= 2 < 3` it justifies a prevote for B at round 3.
        let producer_store = MemoryAtomicSlotStore::new();
        let mut producer = engine_with(&registry, 0);
        let certificate =
            prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);
        let pol = ProofOfLock::from_prevote(certificate);
        assert!(pol.certificate().re_verify(&registry, NET).is_ok());

        // 8. The lock change: prevote B with the POL, certify B at round 3, and
        // precommit — which writes the new lock before signing (`AW-LOCK-2`).
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

        // 10 (same process): a precommit at round 4 is authorised again from
        // scratch — the caller rebuilds the certificate; nothing is reused.
        engine.begin_round(Round(4)).expect("round 4");
        let certificate = prevote_certificate_at(&mut engine, &store, &registry, 0, 4, B);
        let precommit = engine
            .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
            .expect("precommit authorised after the lock change");
        precommit
            .vote()
            .verify(&registry, NET)
            .expect("a real signature");
        assert_eq!(precommit.vote().round, Round(4));
        assert_eq!(
            engine
                .persisted()
                .locked
                .map(|l| (l.checkpoint_id, l.round)),
            Some((B, Round(4))),
            "UPD-SAME refreshes the lock round"
        );
    }

    // 9. Restart after the change. BW (R-BV-1): the recovery audit compares the
    // round of each signed vote with the round of the lock, so the node's own
    // round-1 votes for A are accepted as history and the restart is clean.
    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen after restart");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.report.may_sign(),
        "a POL-authorised lock change must not block its own restart: {:?}",
        restored.report.status
    );
    assert!(
        !restored
            .report
            .findings
            .iter()
            .any(|f| f.contains("contradicts the lock")),
        "findings: {:?}",
        restored.report.findings
    );

    // The authorised change itself is intact on disk.
    assert_eq!(
        restored
            .state
            .persisted()
            .locked
            .map(|l| (l.checkpoint_id, l.round)),
        Some((B, Round(4))),
        "the authorised lock change is durable"
    );
    assert_eq!(
        restored
            .state
            .persisted()
            .proof_of_lock
            .as_ref()
            .map(|p| p.round),
        Some(Round(4))
    );
    assert!(durable_vote(&store, 0, 4, VotePhase::Precommit, B).is_some());

    // The restored node signs the locked value and never the replaced one.
    let mut restored = restored.state;
    assert!(restored.may_sign().is_ok());
    restored.begin_round(Round(5)).expect("round 5");
    restored.propose(B).expect("propose B");
    let prevote = restored
        .prevote(B, vid(1), &registry, &store, sign_with(1))
        .expect("the locked value stays signable after the restart");
    prevote
        .vote()
        .verify(&registry, NET)
        .expect("a real signature");
    assert!(durable_vote(&store, 0, 5, VotePhase::Prevote, B).is_some());
    let stale = unsigned(gen().0, 0, 5, VotePhase::Prevote, A, 1);
    assert!(matches!(
        VoteAuthorization::for_prevote(restored.persisted(), &stale, None, &registry),
        Err(EmitError::NotAuthorized(_))
    ));
}

// ---------------------------------------------------------------------------
// §4 extra — an authorisation issued before a lock change does not become valid
// again afterwards.
// ---------------------------------------------------------------------------

#[test]
fn bv_03_a_stale_authorization_cannot_outlive_a_lock_change() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    lock_at(&mut engine, &store, &registry, 0, 1, A);

    // Issued while the lock was on A: signing A at round 2 is admissible.
    let for_a = unsigned(gen().0, 0, 2, VotePhase::Prevote, A, 1);
    let stale = VoteAuthorization::for_prevote(engine.persisted(), &for_a, None, &registry)
        .expect("the locked value is signable");

    // The lock moves to B at round 3, authorised by a real POL.
    let producer_store = MemoryAtomicSlotStore::new();
    let mut producer = engine_with(&registry, 0);
    let certificate = prevote_certificate_at(&mut producer, &producer_store, &registry, 0, 2, B);
    let pol = ProofOfLock::from_prevote(certificate);
    engine.begin_round(Round(3)).expect("round 3");
    engine
        .prevote_with_proof(B, Some(&pol), vid(1), &registry, &store, sign_with(1))
        .expect("prevote B");
    let certificate = certify_peers_at(&mut engine, &registry, 0, 3, B);
    engine
        .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
        .expect("lock B");
    assert_eq!(engine.persisted().locked.map(|l| l.checkpoint_id), Some(B));

    // The old authorisation still covers its own vote — that is only a byte
    // comparison — but the state now refuses the vote, so no signature appears.
    assert!(stale.covers(&for_a));
    match sign_vote(
        engine.persisted(),
        &store,
        &registry,
        &for_a,
        &stale,
        sign_with(1),
    ) {
        Err(EmitError::LockedValueConflict { locked, requested }) => {
            assert_eq!(locked, B);
            assert_eq!(requested, A);
        }
        other => panic!("expected LockedValueConflict, got {other:?}"),
    }
    assert!(durable_vote(&store, 0, 2, VotePhase::Prevote, A).is_none());

    // A fresh authorisation is rebuilt from the verified state and the POL, and
    // only for the value the lock now names.
    let for_b = unsigned(gen().0, 0, 4, VotePhase::Prevote, B, 1);
    let fresh = VoteAuthorization::for_prevote(engine.persisted(), &for_b, Some(&pol), &registry)
        .expect("B is the locked value, so no POL is even needed");
    assert!(fresh.covers(&for_b));
    assert_eq!(fresh.lock_value(), B);
}

// ---------------------------------------------------------------------------
// §4 — read and write failures fail closed.
// ---------------------------------------------------------------------------

/// A store that can be told to fail one operation. Used to show that a failing
/// flush happens **before** the signature, so no signature can exist for a
/// reservation that never became durable.
struct FlakyStore {
    inner: MemoryAtomicSlotStore,
    fail_flush: bool,
    fail_get: bool,
    flushes: AtomicUsize,
}

impl FlakyStore {
    fn new(fail_flush: bool, fail_get: bool) -> Self {
        Self {
            inner: MemoryAtomicSlotStore::new(),
            fail_flush,
            fail_get,
            flushes: AtomicUsize::new(0),
        }
    }
}

impl CasStore for FlakyStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        if self.fail_get {
            return Err(SlotStoreError::Storage("injected read failure".to_string()));
        }
        self.inner.get(key)
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        self.inner.cas(key, expected, new)
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        if self.fail_get {
            return Err(SlotStoreError::Storage("injected scan failure".to_string()));
        }
        self.inner.scan(prefix)
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        if self.fail_flush {
            return Err(SlotStoreError::Storage(
                "injected flush failure".to_string(),
            ));
        }
        self.inner.flush()
    }

    fn backend(&self) -> &'static str {
        "flaky-test-store"
    }
}

impl AtomicSlotStore for FlakyStore {}

#[test]
fn bv_04_read_and_write_failures_fail_closed_before_any_signature() {
    let registry = reg();

    // (a) A record that is not a sealed state: recovery refuses, signing is off.
    let garbage = MemoryAtomicSlotStore::new();
    garbage
        .cas(STATE_KEY, None, b"this is not a sealed consensus state")
        .expect("write garbage");
    let report = restore(&garbage, Some(ANCHOR), NET);
    assert!(!report.may_sign());
    assert!(report.state.is_none());
    assert!(matches!(report.status, RecoveryStatus::RecoveryRequired(_)));
    assert!(
        report.findings.iter().any(|f| f.contains("unreadable")),
        "findings: {:?}",
        report.findings
    );

    // (b) A tampered envelope: the digest no longer matches.
    let tampered = MemoryAtomicSlotStore::new();
    let genuine = PersistentConsensusState::fresh(NET, gen(), ANCHOR);
    genuine.persist(&tampered).expect("persist genuine state");
    let mut bytes = tampered.get(STATE_KEY).expect("read").expect("present");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let current = genuine_read(&tampered);
    assert!(tampered
        .cas(STATE_KEY, Some(current.as_slice()), &bytes)
        .expect("replace with tampered bytes"));
    let tampered_report = restore(&tampered, Some(ANCHOR), NET);
    assert!(!tampered_report.may_sign());
    assert!(tampered_report.state.is_none());
    assert!(
        tampered_report
            .findings
            .iter()
            .any(|f| f.contains("unreadable")),
        "findings: {:?}",
        tampered_report.findings
    );

    // (c) A write failure at the durability barrier: the reservation is flushed
    // before signing, so the signature never happens.
    let flaky = FlakyStore::new(true, false);
    let state = PersistentConsensusState::fresh(NET, gen(), ANCHOR);
    let candidate = unsigned(gen().0, 0, 0, VotePhase::Prevote, A, 1);
    let authorization = VoteAuthorization::for_prevote(&state, &candidate, None, &registry)
        .expect("first prevote of a fresh state");
    let sign_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&sign_calls);
    match sign_vote(
        &state,
        &flaky,
        &registry,
        &candidate,
        &authorization,
        move |msg: &[u8]| {
            calls.fetch_add(1, Ordering::SeqCst);
            sk(1).sign(msg).to_bytes()
        },
    ) {
        Err(EmitError::Store(SlotStoreError::Storage(text))) => {
            assert!(text.contains("flush"), "unexpected: {text}");
        }
        other => panic!("expected a store error, got {other:?}"),
    }
    assert_eq!(
        sign_calls.load(Ordering::SeqCst),
        0,
        "the signer must not run when the reservation could not be flushed"
    );
    assert_eq!(flaky.flushes.load(Ordering::SeqCst), 1);
    // The reservation was written but never flushed, and nothing was signed: the
    // restart sees exactly that, and the slot can never take another value.
    let after = restore(&flaky, None, NET);
    assert_eq!(after.slots, 1);
    assert_eq!(after.signed, 0);
    assert_eq!(after.reservations_without_signature, 1);
    assert!(durable_vote(&flaky, 0, 0, VotePhase::Prevote, A).is_none());
    assert_eq!(slot_count(&flaky), 1);

    // (d) A read failure during recovery: state unreadable, no signature possible.
    let blind = FlakyStore::new(false, true);
    let report = restore(&blind, Some(ANCHOR), NET);
    assert!(!report.may_sign());
    assert!(report.state.is_none());
    assert!(report.findings.iter().any(|f| f.contains("unreadable")));

    // (e) Two processes on one directory: the second fails closed.
    let dir = tempfile::tempdir().expect("tempdir");
    let first = SledAtomicSlotStore::open(dir.path()).expect("first opens");
    match SledAtomicSlotStore::open(dir.path()) {
        Err(SlotStoreError::StoreLocked { .. }) => {}
        Err(other) => panic!("expected StoreLocked, got {other:?}"),
        Ok(_) => panic!("a second writer must not be allowed on one store"),
    }
    drop(first);
    SledAtomicSlotStore::open(dir.path()).expect("the lock is released on drop");
}

/// Current bytes of the state key, for a compare-and-swap that replaces them.
fn genuine_read(store: &MemoryAtomicSlotStore) -> Vec<u8> {
    store.get(STATE_KEY).expect("read").expect("present")
}

// ---------------------------------------------------------------------------
// §6 — concurrency.
// ---------------------------------------------------------------------------

/// Two contradictory authorisations for one slot: the store's compare-and-swap
/// decides once, and no round of the repetition produces two signatures.
#[test]
fn bv_05_two_contradictory_authorizations_sign_once_in_every_round() {
    const ROUNDS: usize = 40;
    let mut winners = 0usize;

    for _ in 0..ROUNDS {
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
                let authorization =
                    VoteAuthorization::for_prevote(&state, &candidate, None, &registry)
                        .expect("no lock: either value is admissible");
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
        assert_eq!(
            results.iter().filter(|(_, r)| r.is_ok()).count(),
            1,
            "exactly one signature per slot"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, r)| matches!(r, Err(EmitError::Equivocation { .. })))
                .count(),
            1,
            "the loser is refused, never silently accepted"
        );
        assert_eq!(slot_count(&*store), 1);
        let winner = results
            .iter()
            .find(|(_, r)| r.is_ok())
            .map(|(value, _)| *value)
            .expect("one winner");
        winners += 1;
        assert!(durable_vote(&*store, 0, 0, VotePhase::Prevote, winner).is_some());
    }
    assert_eq!(winners, ROUNDS);
}

/// Eight threads, one slot, the same value: all of them may proceed, and the
/// durable record is one signed vote, identical for every caller.
#[test]
fn bv_06_eight_threads_on_one_slot_produce_one_identical_signature() {
    const THREADS: usize = 8;
    const ROUNDS: usize = 25;

    for _ in 0..ROUNDS {
        let state = Arc::new(PersistentConsensusState::fresh(NET, gen(), ANCHOR));
        let store = Arc::new(MemoryAtomicSlotStore::new());
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let store = Arc::clone(&store);
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            let registry = registry_for([7u8; 32]);
            handles.push(thread::spawn(move || {
                let candidate = unsigned(gen().0, 0, 0, VotePhase::Prevote, A, 1);
                let authorization =
                    VoteAuthorization::for_prevote(&state, &candidate, None, &registry)
                        .expect("admissible");
                let key = sk(1);
                barrier.wait();
                sign_vote(
                    &state,
                    &*store,
                    &registry,
                    &candidate,
                    &authorization,
                    |msg: &[u8]| key.sign(msg).to_bytes(),
                )
                .expect("the same vote may be emitted by any number of callers")
                .vote
                .signature
            }));
        }
        let signatures: Vec<[u8; 64]> = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect();
        assert!(
            signatures.iter().all(|s| *s == signatures[0]),
            "all callers must read the same signature"
        );
        assert_eq!(slot_count(&*store), 1, "one slot, one record");
        assert!(durable_vote(&*store, 0, 0, VotePhase::Prevote, A).is_some());
    }
}

/// A round change between issuing an authorisation and using it: the vote that
/// arrives afterwards is refused by `covers`, and only the authorised round is
/// ever signed.
#[test]
fn bv_07_a_round_change_during_a_signing_request_invalidates_the_authorization() {
    const ROUNDS: usize = 20;
    let registry = reg();

    for _ in 0..ROUNDS {
        let state = Arc::new(PersistentConsensusState::fresh(NET, gen(), ANCHOR));
        let store = Arc::new(MemoryAtomicSlotStore::new());
        let engine = Arc::new(Mutex::new(engine_with(&registry, 0)));
        let barrier = Arc::new(Barrier::new(2));

        let authorising = {
            let state = Arc::clone(&state);
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            let registry = registry_for([7u8; 32]);
            thread::spawn(move || {
                let authorised = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
                let authorization =
                    VoteAuthorization::for_prevote(&state, &authorised, None, &registry)
                        .expect("round 1 is admissible");
                barrier.wait();
                (authorised, authorization)
            })
        };
        let round_changing = {
            let engine = Arc::clone(&engine);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                engine
                    .lock()
                    .expect("engine lock")
                    .begin_round(Round(2))
                    .expect("round 2 opens while the signature is being requested");
            })
        };
        let (authorised, authorization) = authorising.join().expect("authorising thread");
        round_changing.join().expect("round thread");

        let later = unsigned(gen().0, 0, 2, VotePhase::Prevote, A, 1);
        assert!(!authorization.covers(&later));
        match sign_vote(
            &state,
            &*store,
            &registry,
            &later,
            &authorization,
            sign_with(1),
        ) {
            Err(EmitError::NotAuthorized(reason)) => {
                assert!(reason.contains("another vote"), "reason: {reason}")
            }
            other => panic!("expected NotAuthorized, got {other:?}"),
        }
        assert!(durable_vote(&*store, 0, 2, VotePhase::Prevote, A).is_none());

        // The authorised vote itself is still signable: the refusal above was
        // about the position, not about a broken authorisation.
        let outcome = sign_vote(
            &state,
            &*store,
            &registry,
            &authorised,
            &authorization,
            sign_with(1),
        )
        .expect("the authorised round is still signable");
        assert_eq!(outcome.settlement, Settlement::FreshlySigned);
        assert!(durable_vote(&*store, 0, 1, VotePhase::Prevote, A).is_some());
        assert_eq!(slot_count(&*store), 1);
    }
}

/// Six readers restore the same real store while a writer replaces the record:
/// every read is internally consistent, and every reader may sign.
///
/// BX (R-BX-2) note: the writer used to publish a snapshot with the lock and the
/// proof **removed**, which is exactly the lost update `persist` now refuses.
/// The writer therefore supersedes the record instead: the lock and its proof
/// stay whole and only the audit summary moves, so the test still exercises
/// record replacement under concurrent readers.
#[test]
fn bv_08_simultaneous_restores_never_observe_a_mixed_record() {
    const READERS: usize = 6;
    const ROUNDS: usize = 10;
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(SledAtomicSlotStore::open(dir.path()).expect("open real store"));

    let locked_state = {
        let mem = MemoryAtomicSlotStore::new();
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &mem, &registry, 0, 2, B);
        engine
            .persisted()
            .persist(&*store)
            .expect("seed the durable state");
        engine.persisted().clone()
    };
    let locked_ok = Arc::new(AtomicUsize::new(0));
    let writer_done = Arc::new(AtomicBool::new(false));
    // Phase A: every reader restores the locked record before the writer moves.
    // Phase B: the writer replaces the record while the readers keep restoring.
    let phase_a = Arc::new(Barrier::new(READERS + 1));

    let writer = {
        let store = Arc::clone(&store);
        let mut writer_state = locked_state.clone();
        let done = Arc::clone(&writer_done);
        let phase_a = Arc::clone(&phase_a);
        thread::spawn(move || {
            phase_a.wait();
            for i in 0..ROUNDS {
                writer_state.last_valid_certificate = Some(LastValidCertificate {
                    height: CheckpointHeight(0),
                    round: Round(3 + i as u32),
                    phase: VotePhase::Precommit,
                    checkpoint_id: B,
                    qc_id: [i as u8 + 1; 32],
                });
                let result = writer_state.persist(&*store);
                assert!(
                    result.is_ok(),
                    "the only writer must never see a concurrent writer: {result:?}"
                );
                if i % 2 == 0 {
                    thread::yield_now();
                }
            }
            done.store(true, Ordering::SeqCst);
        })
    };

    let mut readers = Vec::new();
    for _ in 0..READERS {
        let store = Arc::clone(&store);
        let registry = registry_for([7u8; 32]);
        let locked_ok = Arc::clone(&locked_ok);
        let phase_a = Arc::clone(&phase_a);
        readers.push(thread::spawn(move || {
            for round in 0..ROUNDS {
                if round == 1 {
                    phase_a.wait();
                }
                let report =
                    restore_engine(&*store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
                assert!(
                    report.report.may_sign(),
                    "a consistent record must always restore: {:?}",
                    report.report.findings
                );
                let state = report.state.persisted();
                assert_eq!(
                    state.locked.is_some(),
                    state.proof_of_lock.is_some(),
                    "a lock and its proof are replaced in one record, never torn"
                );
                if let (Some(lock), Some(proof)) = (state.locked, state.proof_of_lock.as_ref()) {
                    assert_eq!(lock.checkpoint_id, proof.proposed.checkpoint_id);
                    assert_eq!(lock.round, proof.round);
                    locked_ok.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }
    for reader in readers {
        reader.join().expect("reader");
    }
    writer.join().expect("writer");
    assert!(writer_done.load(Ordering::SeqCst));
    assert!(
        locked_ok.load(Ordering::SeqCst) > 0,
        "at least one reader must have observed the locked record"
    );

    // The final state is the writer's, whole.
    let final_report = restore_engine(&*store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(final_report.report.may_sign());
    let final_state = final_report.state.persisted();
    assert!(
        final_state.locked.is_some(),
        "the writer never dropped the lock"
    );
    assert_eq!(
        final_state.last_valid_certificate.map(|c| c.round),
        Some(Round(2 + ROUNDS as u32))
    );
    // The votes of this test were signed into a memory store; the Sled record
    // only carries the state. The summary is re-derived from the slot records of
    // the restored store, so with no signed slot here it is zero — the persisted
    // field has no authority.
    assert_eq!(final_state.highest_signed_round, Round(0));
}

/// A memory store whose first two `STATE_KEY` reads rendezvous.
///
/// `persist` reads the record and then CASes on exactly those bytes. The reads
/// are captured *before* the barrier, so both writers decide on the same empty
/// record. Since BX (R-BX-2) one of the two states (the one without the lock) is
/// refused by the monotone guard whichever way the race falls, so the test no
/// longer depends on scheduling to have exactly one winner; the rendezvous keeps
/// both writers deciding on the same bytes.
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
        "rendezvous-memory"
    }
}

impl AtomicSlotStore for RendezvousStore {}

/// Two writers persist different safety states: one wins, the loser is told.
#[test]
fn bv_09_concurrent_state_writes_have_exactly_one_winner() {
    const ROUNDS: usize = 25;
    let registry = reg();

    for _ in 0..ROUNDS {
        let mem = MemoryAtomicSlotStore::new();
        let mut engine = engine_with(&registry, 0);
        lock_at(&mut engine, &mem, &registry, 0, 1, A);
        let locked = engine.persisted().clone();
        let mut free = locked.clone();
        free.locked = None;
        free.proof_of_lock = None;

        let store = Arc::new(RendezvousStore::new());
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for (label, state) in [("locked", locked), ("free", free)] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                (label, state.persist(&*store))
            }));
        }
        let results: Vec<(&str, Result<(), StateError>)> = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect();
        assert_eq!(
            results.iter().filter(|(_, r)| r.is_ok()).count(),
            1,
            "one writer wins"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, r)| matches!(r, Err(StateError::ConcurrentWriter)))
                .count(),
            1,
            "the other is told, not overwritten"
        );
        let winner = results
            .iter()
            .find(|(_, r)| r.is_ok())
            .map(|(label, _)| *label)
            .expect("winner");
        let bytes = store.get(STATE_KEY).expect("read").expect("present");
        let durable = PersistentConsensusState::decode(open_sealed(&bytes).expect("envelope"))
            .expect("decode");
        assert_eq!(
            durable.locked.is_some(),
            winner == "locked",
            "the durable record is the winner's, whole"
        );
    }
}

/// HALT stops the engine **and** the raw primitive: `sign_vote` reads the
/// durable halt record (mission BW, R-BV-2).
#[test]
fn bv_10_halt_stops_the_engine_and_the_signature_frontier() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = engine_with(&registry, 0);
    engine.begin_round(Round(1)).expect("round 1");
    engine.propose(A).expect("propose A");

    let candidate = unsigned(gen().0, 0, 1, VotePhase::Prevote, A, 1);
    let authorization =
        VoteAuthorization::for_prevote(engine.persisted(), &candidate, None, &registry)
            .expect("admissible before the halt");

    // The safety record exists and is clean before the halt: otherwise the
    // restart would block on the missing anchor and the HALT gap could not be
    // told apart from a recovery block.
    engine
        .persisted()
        .persist(&store)
        .expect("persist the state");
    engine
        .halt_with(HaltReason::Persisted("bv halt drill".to_string()), &store)
        .expect("halt is written and flushed");
    assert!(engine.is_halted());

    // The engine refuses every signature, with the durable halt reason.
    assert!(matches!(
        engine.prevote(A, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::Halted(_))
    ));
    assert!(durable_vote(&store, 0, 1, VotePhase::Prevote, A).is_none());

    // A restart reloads the halt and still refuses.
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.is_halted());
    assert!(restored.state.may_sign().is_err());
    assert!(durable_vote(&store, 0, 1, VotePhase::Prevote, A).is_none());

    // BW (R-BV-2): the durable halt record is read at the signature frontier, so
    // an authorisation that predates the HALT cannot produce a signature.
    let error = sign_vote(
        restored.state.persisted(),
        &store,
        &registry,
        &candidate,
        &authorization,
        sign_with(1),
    )
    .expect_err("a HALT must stop the raw primitive");
    assert!(matches!(error, EmitError::Halted(_)), "error: {error:?}");
    assert!(durable_vote(&store, 0, 1, VotePhase::Prevote, A).is_none());
    assert!(
        store.scan_slots().expect("scan").is_empty(),
        "a refused signature reserves nothing"
    );
    assert_eq!(
        restored.state.persisted().locked.map(|l| l.checkpoint_id),
        None
    );
}
