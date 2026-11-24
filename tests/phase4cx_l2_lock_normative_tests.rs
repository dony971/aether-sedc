//! PHASE 4CX — the normative lock rule (`R-LOCK-1..5`, `AW-LOCK-1..14`).
//!
//! These are the acceptance tests of mission AW (`acceptance-tests.md`), run
//! against the engine of mission AX. They are deterministic: no clock, no
//! network, no randomness — every input is a fixed registry and fixed votes.
//!
//! What they can claim: *this implementation* keeps the rule. What they cannot
//! claim: the safety theorem itself (`A0, A1, A2, A3-ord, A4', LOCK-UPD,
//! LOCK-EXC, LOCK-DUR, A8a` ⇒ no two conflicting QC), which is a paper proof, and
//! liveness, which is conditional (`T-AA`, H1-H7) and needs proposer rotation
//! outside this engine.

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
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
use aether_unified::l2persist::{AtomicSlotStore, MemoryAtomicSlotStore, SledAtomicSlotStore};

const NET: u64 = 11;
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

fn gen_id() -> GenerationId {
    GenerationId([7u8; 32])
}

fn reg() -> ValidatorRegistry {
    registry_with_gen([7u8; 32], &[(1, 10), (2, 10), (3, 10), (4, 10)])
}

fn registry_with_gen(gen: [u8; 32], members: &[(u8, u64)]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = members
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(gen), &entries).expect("registry")
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn signed_vote(
    gen: [u8; 32],
    height: u64,
    round: u32,
    phase: VotePhase,
    value: [u8; 32],
    seed: u8,
) -> ConsensusVote {
    let mut vote = ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: GenerationId(gen),
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        checkpoint_id: value,
        validator: vid(seed),
        signature: [0u8; 64],
    };
    vote.signature = sk(seed).sign(&vote.signing_bytes()).to_bytes();
    vote
}

fn signed(height: u64, round: u32, phase: VotePhase, value: [u8; 32], seed: u8) -> ConsensusVote {
    signed_vote([7u8; 32], height, round, phase, value, seed)
}

fn new_engine(height: u64) -> BftState {
    BftState::new(NET, &reg(), CheckpointHeight(height), ANCHOR)
}

fn checkpoint(height: u64, parent: [u8; 32], state_root: [u8; 32]) -> Checkpoint {
    Checkpoint::new(
        gen_id(),
        CheckpointHeight(height),
        parent,
        state_root,
        [0x22u8; 32],
        reg().set_root(),
        None,
    )
    .expect("checkpoint")
}

/// Drive a quorate prevote certificate for `value` at `round`, signing as
/// validator 1 and injecting validators 2 and 3 (weight 30 >= 27).
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
        let vote = signed(engine.height.get(), round, VotePhase::Prevote, value, seed);
        assert!(matches!(
            engine.accept_vote(&vote, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    engine
        .certify_prevotes_for(value, &registry)
        .expect("quorate prevote certificate")
}

/// Lock `value` through the **precommit** path (`AW-LOCK-2`), returning the
/// proof of lock that now justifies it.
fn lock_at(
    engine: &mut BftState,
    store: &dyn AtomicSlotStore,
    round: u32,
    value: [u8; 32],
) -> ProofOfLock {
    let registry = reg();
    let certificate = prevote_certificate_at(engine, store, round, value);
    engine
        .precommit(&certificate, vid(1), &registry, store, sign_with(1))
        .expect("precommit writes the lock");
    ProofOfLock::from_prevote(certificate)
}

/// `AW-LOCK-14`, invariants I-1 to I-3, checked after every transition.
fn assert_lock_invariants(engine: &BftState) {
    match engine.persisted().locked {
        None => assert!(
            engine.persisted().proof_of_lock.is_none(),
            "I-1: no lock implies no proof"
        ),
        Some(lock) => {
            let proof = engine
                .persisted()
                .proof_of_lock
                .as_ref()
                .expect("I-2: a lock always carries the proof that justifies it");
            assert_eq!(
                proof.round.get(),
                lock.round.get(),
                "I-2: proof round = lockR"
            );
            assert_eq!(
                proof.proposed.checkpoint_id, lock.checkpoint_id,
                "I-2: proof value = lockV"
            );
            assert_eq!(
                proof.proposed.height, lock.height,
                "I-3: proof belongs to the lock's height"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// AT-01. A prevote never locks (CE-AW-01)
// ---------------------------------------------------------------------------

#[test]
fn at_01_an_isolated_prevote_does_not_lock_the_height() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);

    // 10 of 40 with quorum 27: a lone prevote that can never reach quorum.
    let prevote = engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("prevote");
    assert_eq!(prevote.checkpoint_id(), A);
    assert!(
        engine.active_lock().is_none(),
        "AW-LOCK-2: a prevote must not write the lock"
    );
    assert!(engine.persisted().proof_of_lock.is_none());
    assert_lock_invariants(&engine);

    // And the abandoned value constrains nothing in the next round.
    engine.begin_round(Round(1)).expect("round 1");
    engine
        .prevote(B, vid(1), &registry, &store, sign_with(1))
        .expect("no lock, so any value is signable at the next round");
    assert!(engine.active_lock().is_none());
}

// ---------------------------------------------------------------------------
// AT-02. A lock is untouched by round changes (LOCK-EXC)
// ---------------------------------------------------------------------------

#[test]
fn at_02_round_changes_never_touch_the_lock() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);
    assert_lock_invariants(&engine);
    let before = engine.persisted().locked.expect("lock");
    let proof_before = engine.persisted().proof_of_lock.clone().expect("proof");

    for round in 1..4u32 {
        engine.begin_round(Round(round)).expect("round");
        assert_eq!(engine.persisted().locked, Some(before), "AW-LOCK-3");
        assert_eq!(engine.persisted().proof_of_lock, Some(proof_before.clone()));
        assert_lock_invariants(&engine);
    }

    // Voting the locked value is always possible; voting another one is not.
    engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("the locked value stays signable");
    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { lock_round: 0, .. })
    ));
}

// ---------------------------------------------------------------------------
// AT-03 / AT-07 / AT-08. The two bounds of A4'
// ---------------------------------------------------------------------------

#[test]
fn at_03_a_valid_proof_authorises_the_window() {
    // A proof `POL(B, g, 5)` exists, produced elsewhere.
    let mut producer = new_engine(0);
    let producer_store = MemoryAtomicSlotStore::new();
    let pol =
        ProofOfLock::from_prevote(prevote_certificate_at(&mut producer, &producer_store, 5, B));

    // This node is locked on A at round 3.
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 3, A);
    assert_eq!(engine.active_lock().map(|l| l.round), Some(Round(3)));

    engine.begin_round(Round(6)).expect("round 6");
    let prevote = engine
        .prevote_with_proof(B, Some(&pol), vid(1), &registry(), &store, sign_with(1))
        .expect("lockR = 3 <= 5 < 6: authorised");
    assert_eq!(prevote.checkpoint_id(), B);
    assert_eq!(
        engine.active_lock().map(|l| l.checkpoint_id),
        Some(A),
        "a proof authorises one prevote; it never unlocks"
    );
}

fn registry() -> ValidatorRegistry {
    reg()
}

#[test]
fn at_07_a_proof_of_the_current_round_is_rejected() {
    let mut producer = new_engine(0);
    let producer_store = MemoryAtomicSlotStore::new();
    let pol =
        ProofOfLock::from_prevote(prevote_certificate_at(&mut producer, &producer_store, 3, B));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);

    // Same round as the proof: `r_pol < r` fails.
    engine.begin_round(Round(3)).expect("round 3");
    let ctx = engine.context(VotePhase::Prevote);
    assert!(
        !pol.accepted_for(&B, &ctx, Round(0)),
        "upper bound is strict"
    );
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol), vid(1), &reg(), &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

#[test]
fn at_08_a_proof_older_than_the_lock_is_rejected() {
    let mut producer = new_engine(0);
    let producer_store = MemoryAtomicSlotStore::new();
    let pol =
        ProofOfLock::from_prevote(prevote_certificate_at(&mut producer, &producer_store, 3, B));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 5, A);

    engine.begin_round(Round(6)).expect("round 6");
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol), vid(1), &reg(), &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { lock_round: 5, .. })
    ));
}

// ---------------------------------------------------------------------------
// AT-04 / AT-05 / AT-06. Rejected proofs
// ---------------------------------------------------------------------------

#[test]
fn at_04_a_forged_proof_is_rejected() {
    let mut producer = new_engine(0);
    let producer_store = MemoryAtomicSlotStore::new();
    let genuine =
        ProofOfLock::from_prevote(prevote_certificate_at(&mut producer, &producer_store, 2, B));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);
    engine.begin_round(Round(4)).expect("round 4");

    // The round of a proof is the signed one; rewriting the public field must
    // not widen its window.
    let mut rewritten = genuine.clone();
    rewritten.round = Round(3);
    assert!(!rewritten.accepted_for(&B, &engine.context(VotePhase::Prevote), Round(0)));

    // A proof attached to another value proves nothing for this one.
    let mut mismatched = genuine.clone();
    mismatched.checkpoint_id = C;
    assert!(!mismatched.accepted_for(&B, &engine.context(VotePhase::Prevote), Round(0)));

    // A proof whose bytes are corrupted is not a proof at all: `from_bytes`
    // re-verifies from scratch and refuses to produce a certificate.
    assert!(PrevoteCertificate::from_bytes(&[0u8; 8], &reg(), NET).is_err());
}

#[test]
fn at_05_a_proof_of_another_generation_is_rejected() {
    let other = [9u8; 32];
    let other_registry = registry_with_gen(other, &[(1, 10), (2, 10), (3, 10), (4, 10)]);
    let votes: Vec<ConsensusVote> = [1u8, 2, 3]
        .iter()
        .map(|seed| signed_vote(other, 0, 2, VotePhase::Prevote, B, *seed))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &other_registry,
        CheckpointHeight(0),
        Round(2),
        VotePhase::Prevote,
        B,
        votes,
    );
    let foreign = ProofOfLock::from_prevote(
        PrevoteCertificate::certify(qc, &other_registry, NET).expect("foreign proof"),
    );

    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);
    engine.begin_round(Round(3)).expect("round 3");
    assert!(!foreign.accepted_for(&B, &engine.context(VotePhase::Prevote), Round(0)));
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&foreign), vid(1), &reg(), &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

#[test]
fn at_06_a_proof_of_another_height_is_rejected() {
    let mut producer = new_engine(1);
    let producer_store = MemoryAtomicSlotStore::new();
    let pol =
        ProofOfLock::from_prevote(prevote_certificate_at(&mut producer, &producer_store, 2, B));
    assert_eq!(pol.height, CheckpointHeight(1));

    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);
    engine.begin_round(Round(3)).expect("round 3");
    assert!(!pol.accepted_for(&B, &engine.context(VotePhase::Prevote), Round(0)));
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&pol), vid(1), &reg(), &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

// ---------------------------------------------------------------------------
// AT-09 / AT-10. Persistence of the proof
// ---------------------------------------------------------------------------

#[test]
fn at_09_a_lock_without_its_proof_keeps_the_lock_and_loses_the_proposal() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = new_engine(0);
        lock_at(&mut engine, &store, 0, A);
        // Simulate a lost proof: the lock record survives, the bytes do not.
        let mut lost = engine.persisted().clone();
        lost.proof_of_lock = None;
        lost.persist(&store).expect("persist");
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert_eq!(
        restored.state.active_lock().map(|l| l.checkpoint_id),
        Some(A),
        "AW-LOCK-11(b): the lock is never dropped"
    );
    assert!(
        restored.state.lock_proof_absent,
        "AW-LOCK-11(b): the missing proof must be reported"
    );
    assert!(restored.state.persisted().proof_of_lock.is_none());

    // AY: the lock lost the evidence that justifies it, so the whole state is
    // fail-closed. AU's recovery gate refuses every signature, and the engine's
    // `AW-LOCK-11(c)` audit runs on top of it. Signing the locked value is
    // therefore refused until the store is inspected — a liveness cost on an
    // already-corrupt state, never a safety one. (AX expected the locked value to
    // stay signable; the executed test showed the gate closes first.)
    assert!(
        !restored.report.may_sign(),
        "a lock without its proof must block signing: {:?}",
        restored.report.findings
    );
    let mut engine = restored.state;
    assert!(matches!(
        engine.begin_round(Round(1)),
        Err(BftError::RecoveryRequired(_))
    ));
}

#[test]
fn at_10_the_lock_and_its_proof_survive_a_restart() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = new_engine(0);
        lock_at(&mut engine, &store, 0, A);
        assert_lock_invariants(&engine);
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.report.may_sign(), "{:?}", restored.report.findings);
    assert_eq!(
        restored.state.active_lock(),
        Some(aether_unified::l2persist::state::LockedValue {
            checkpoint_id: A,
            height: CheckpointHeight(0),
            round: Round(0),
        }),
        "AW-LOCK-4: the lock is restored exactly"
    );
    assert!(!restored.state.lock_proof_absent);
    let proof = restored
        .state
        .persisted()
        .proof_of_lock
        .as_ref()
        .expect("the proof is restored");
    assert_eq!(proof.round, Round(0));
    assert_eq!(proof.proposed.checkpoint_id, A);
    assert_lock_invariants(&restored.state);
}

// ---------------------------------------------------------------------------
// AT-11 / AT-12. Changing value: with a proof, and without
// ---------------------------------------------------------------------------

#[test]
fn at_11_a_value_change_is_authorised_by_a_valid_proof() {
    let mut producer = new_engine(0);
    let producer_store = MemoryAtomicSlotStore::new();
    let pol =
        ProofOfLock::from_prevote(prevote_certificate_at(&mut producer, &producer_store, 1, B));

    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);
    engine.begin_round(Round(2)).expect("round 2");

    // This node prevotes B under the proof (`0 <= 1 < 2`).
    engine
        .prevote_with_proof(B, Some(&pol), vid(1), &registry, &store, sign_with(1))
        .expect("authorised");
    for seed in [2u8, 3u8] {
        let vote = signed(0, 2, VotePhase::Prevote, B, seed);
        assert!(matches!(
            engine.accept_vote(&vote, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let certificate = engine
        .certify_prevotes_for(B, &registry)
        .expect("progress: a quorate prevote certificate for B exists");
    assert!(certificate.support().get() >= certificate.quorum().get());

    // The lock is still on A until a precommit for B is signed.
    assert_eq!(engine.active_lock().map(|l| l.checkpoint_id), Some(A));
}

#[test]
fn at_12_a_value_change_without_a_proof_is_refused_and_writes_nothing() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 0, A);
    let slots_before = store.scan_slots().expect("scan").len();

    engine.begin_round(Round(2)).expect("round 2");
    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_eq!(
        store.scan_slots().expect("scan").len(),
        slots_before,
        "a refused prevote signs nothing"
    );
    assert_eq!(engine.active_lock().map(|l| l.checkpoint_id), Some(A));
}

// ---------------------------------------------------------------------------
// AT-13. A precommit always follows this node's own prevote (A3-ord)
// ---------------------------------------------------------------------------

#[test]
fn at_13_a_precommit_without_an_own_prevote_is_refused() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();

    // Build a quorate prevote certificate for B using *other* validators.
    let mut producer = new_engine(0);
    let producer_store = MemoryAtomicSlotStore::new();
    let certificate = prevote_certificate_at(&mut producer, &producer_store, 0, B);

    // This node never prevoted B in this round, so it may not precommit it.
    let mut engine = new_engine(0);
    engine.propose(B).expect("propose");
    assert!(matches!(
        engine.precommit(&certificate, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteRequired)
    ));
    assert!(
        engine.active_lock().is_none(),
        "a refused precommit writes no lock"
    );
    assert!(store.scan_slots().expect("scan").is_empty());
}

// ---------------------------------------------------------------------------
// AT-14. Successive rounds: UPD-SAME refreshes lockR monotonically
// ---------------------------------------------------------------------------

#[test]
fn at_14_lock_round_is_monotone_across_rounds() {
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    let mut last = None;
    for round in 0..3u32 {
        let certificate = prevote_certificate_at(&mut engine, &store, round, A);
        engine
            .precommit(&certificate, vid(1), &reg(), &store, sign_with(1))
            .expect("precommit");
        let lock = engine.active_lock().expect("lock");
        assert_eq!(lock.round, Round(round), "UPD-SAME sets lockR := r");
        if let Some(previous) = last {
            assert!(
                lock.round.get() >= previous,
                "R-LOCK-4: lockR never decreases"
            );
        }
        last = Some(lock.round.get());
        assert_lock_invariants(&engine);
    }
}

// ---------------------------------------------------------------------------
// AT-15. Byzantine behaviour: equivocation, forged evidence
// ---------------------------------------------------------------------------

#[test]
fn at_15_equivocation_produces_no_quorum_and_no_lock() {
    let registry = reg();
    let mut engine = new_engine(0);

    // Two groups prevote different values: 20 vs 10, neither reaches 27.
    let groups: [([u8; 32], &[u8]); 2] = [(B, &[2u8, 3u8]), (C, &[4u8])];
    for (value, seeds) in groups {
        for &seed in seeds {
            let vote = signed(0, 0, VotePhase::Prevote, value, seed);
            assert!(matches!(
                engine.accept_vote(&vote, &registry),
                VoteOutcome::Accepted { .. }
            ));
        }
    }
    assert!(engine.certify_prevotes_for(B, &registry).is_err());
    assert!(engine.certify_prevotes_for(C, &registry).is_err());
    assert!(engine.active_lock().is_none());
    assert!(engine.finality.is_none());
}

// ---------------------------------------------------------------------------
// AT-16. Progress after an abandoned value (the essential test)
// ---------------------------------------------------------------------------

#[test]
fn at_16a_an_abandoned_round_leaves_no_lock_then_the_next_round_decides() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);

    // Round 0: A prevotes v1 (10), B and C prevote v2 (20). 20 < 27: abandoned,
    // and — because only precommits lock — nothing is locked.
    engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("prevote A");
    for seed in [2u8, 3u8] {
        let vote = signed(0, 0, VotePhase::Prevote, B, seed);
        assert!(matches!(
            engine.accept_vote(&vote, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    assert!(engine.certify_prevotes_for(B, &registry).is_err());
    assert!(engine.active_lock().is_none(), "no precommit, no lock");

    // Round 1: the same node signs v2 without any proof of lock.
    engine.begin_round(Round(1)).expect("round 1");
    engine
        .prevote(B, vid(1), &registry, &store, sign_with(1))
        .expect("branch 1 of A4': lockV = 0");
}

#[test]
fn at_16b_a_lock_without_quorum_is_escaped_by_its_own_proof_not_by_unlocking() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);

    // Round 0: B and C precommit v1 (20 < 27, no decision). This node is locked
    // but the value has no quorum.
    let certificate = prevote_certificate_at(&mut engine, &store, 0, A);
    engine
        .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
        .expect("precommit");
    let pol = ProofOfLock::from_prevote(certificate);
    assert_eq!(engine.active_lock().map(|l| l.checkpoint_id), Some(A));

    // Round 1: another value cannot be prevoted without a proof.
    engine.begin_round(Round(1)).expect("round 1");
    assert!(matches!(
        engine.prevote(B, vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    // ...but `Nil` always is (abstention).
    engine
        .prevote(
            aether_unified::l2bft::NIL_VALUE,
            vid(1),
            &registry,
            &store,
            sign_with(1),
        )
        .expect("Nil is always signable");

    // Round 2: the locked node proposes its own value with its own proof
    // (`POL(A, 0)`, window `[0, 2)`), and a quorum forms without any unlock.
    engine.begin_round(Round(2)).expect("round 2");
    engine
        .propose_certified(A, pol)
        .expect("P2: the proposal carries the proof");
    let prevote = engine
        .prevote(A, vid(1), &registry, &store, sign_with(1))
        .expect("the locked value is always signable");
    assert_eq!(prevote.checkpoint_id(), A);
    for seed in [2u8, 3u8] {
        let vote = signed(0, 2, VotePhase::Prevote, A, seed);
        assert!(matches!(
            engine.accept_vote(&vote, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let certificate = engine
        .certify_prevotes_for(A, &registry)
        .expect("30 >= 27: the height can progress on its locked value");
    assert!(certificate.support().get() >= certificate.quorum().get());
    assert_eq!(
        engine.active_lock().map(|l| l.checkpoint_id),
        Some(A),
        "progress came from the proof, never from an unlock"
    );
}

#[test]
fn at_16c_a_stale_proof_blocks_one_round_and_the_max_lock_round_escapes() {
    // The stale proof: `POL(B, 3)`.
    let mut stale_producer = new_engine(0);
    let stale_store = MemoryAtomicSlotStore::new();
    let stale = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut stale_producer,
        &stale_store,
        3,
        B,
    ));

    // The fresh proof: `POL(B, 5)`, which is the lock round of this node.
    let mut fresh_producer = new_engine(0);
    let fresh_store = MemoryAtomicSlotStore::new();
    let fresh = ProofOfLock::from_prevote(prevote_certificate_at(
        &mut fresh_producer,
        &fresh_store,
        5,
        B,
    ));

    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    lock_at(&mut engine, &store, 5, A);
    engine.begin_round(Round(6)).expect("round 6");

    // `3 < lockR = 5`: the round is lost, and that is correct (safety).
    assert!(matches!(
        engine.prevote_with_proof(B, Some(&stale), vid(1), &registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { lock_round: 5, .. })
    ));

    // `5 <= 5 < 6`: the same round as the lock still qualifies — this is exactly
    // why the lower bound must stay inclusive (`AA-2`).
    engine
        .prevote_with_proof(B, Some(&fresh), vid(1), &registry, &store, sign_with(1))
        .expect("the max-lock-round proof escapes the stall");
}

// ---------------------------------------------------------------------------
// AT-17. Finality still halts on contradictory certificates
// ---------------------------------------------------------------------------

#[test]
fn at_17_contradictory_finality_still_halts() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp_a = checkpoint(0, [0u8; 32], [0x11u8; 32]);
    let other = checkpoint(0, [0u8; 32], [0x99u8; 32]);
    assert_ne!(cp_a.id(), other.id());

    let certificate = prevote_certificate_at(&mut new_engine(0), &store, 0, cp_a.id());
    let mut engine = new_engine(0);
    // AY: `A3-ord` (AW-LOCK-8) requires this node's **own** prevote first.
    // AX built the precommit straight from an injected certificate, which the
    // executed test correctly rejected with `PrevoteRequired`.
    engine
        .prevote(cp_a.id(), vid(1), &registry, &store, sign_with(1))
        .expect("own prevote");
    engine
        .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
        .expect("precommit");
    // A precommit certificate needs the three precommits of the same round.
    for seed in [2u8, 3u8] {
        let vote = signed(0, 0, VotePhase::Precommit, cp_a.id(), seed);
        assert!(matches!(
            engine.accept_vote(&vote, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let precommit_certificate = engine
        .certify_precommits_for(cp_a.id(), &registry)
        .expect("quorate");
    engine
        .finalize(&precommit_certificate, &cp_a, None, &registry, &store)
        .expect("height 0 decided");

    // The same height with another checkpoint: refused, and the first stands.
    assert!(matches!(
        engine.finalize(&precommit_certificate, &other, None, &registry, &store),
        Err(BftError::ContextMismatch { field: "value" })
    ));
    assert_eq!(
        engine.finality.map(|d| d.checkpoint_id),
        Some(cp_a.id()),
        "finality is not revisable"
    );
}

// ---------------------------------------------------------------------------
// AT-18. Determinism
// ---------------------------------------------------------------------------

#[test]
fn at_18_identical_inputs_give_identical_results() {
    let run = || {
        let registry = reg();
        let store = MemoryAtomicSlotStore::new();
        let mut engine = new_engine(0);
        let certificate = prevote_certificate_at(&mut engine, &store, 0, A);
        engine
            .precommit(&certificate, vid(1), &registry, &store, sign_with(1))
            .expect("precommit");
        let prevote = engine
            .prevote(A, vid(1), &registry, &store, sign_with(1))
            .expect("repeat");
        (prevote.checkpoint_id(), engine.persisted().locked)
    };
    assert_eq!(
        run(),
        run(),
        "same inputs, same outcome — no clock, no random"
    );
}
