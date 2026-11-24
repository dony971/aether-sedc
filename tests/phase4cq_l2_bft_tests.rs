//! PHASE 4CP-AV — BFT engine: rounds, prevotes, precommits, locks, finality.
//!
//! Coverage: the 18 required scenarios, multi-round sequences (not only isolated
//! units), and the property list of §11.
//!
//! # What these tests can and cannot claim
//!
//! They exercise the engine's own decisions on a fixed registry. They do **not**
//! prove `N-SAFE-1` as a theorem (that needs the AL/AN proofs and `F ≤ I − 1`);
//! they show that *this implementation* refuses every path that would violate it
//! under the stated hypotheses. See `security-tests.md`.

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{
    restore_engine, BftError, BftState, PrecommitCertificate, ProofOfLock, RoundChange,
    RoundChangeOutcome, VoteOutcome,
};
use aether_unified::l2crypto::qc::QuorumCertificate;
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::state::LockedValue;
use aether_unified::l2persist::{
    AtomicSlotStore, CasStore, MemoryAtomicSlotStore, SledAtomicSlotStore,
};

const NET: u64 = 11;
const ANCHOR: [u8; 32] = [0x5A; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn gen_id() -> GenerationId {
    GenerationId([7u8; 32])
}

/// Four validators of weight 10: total 40, quorum 27, so three signers are
/// enough and two are not.
fn reg() -> ValidatorRegistry {
    registry_with(&[(1, 10), (2, 10), (3, 10), (4, 10)])
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
    ValidatorRegistry::new(gen_id(), &entries).expect("registry")
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn unsigned(height: u64, round: u32, phase: VotePhase, value: [u8; 32], seed: u8) -> ConsensusVote {
    ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: gen_id(),
        height: CheckpointHeight(height),
        round: Round(round),
        phase,
        checkpoint_id: value,
        validator: vid(seed),
        signature: [0u8; 64],
    }
}

fn signed(height: u64, round: u32, phase: VotePhase, value: [u8; 32], seed: u8) -> ConsensusVote {
    let v = unsigned(height, round, phase, value, seed);
    let mut v = v;
    v.signature = sk(seed).sign(&v.signing_bytes()).to_bytes();
    v
}

fn new_engine(height: u64) -> BftState {
    BftState::new(NET, &reg(), CheckpointHeight(height), ANCHOR)
}

/// A different checkpoint at the same height: another state root, another id.
fn checkpoint_alt(height: u64, parent: [u8; 32], state_root: [u8; 32]) -> Checkpoint {
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

fn checkpoint(height: u64, parent: [u8; 32]) -> Checkpoint {
    Checkpoint::new(
        gen_id(),
        CheckpointHeight(height),
        parent,
        [0x11u8; 32],
        [0x22u8; 32],
        reg().set_root(),
        None,
    )
    .expect("checkpoint")
}

/// Drive one full round to a precommit certificate for `value`, with the engine
/// signing as validator 1 and validators 2 and 3 injected.
fn reach_precommit_certificate(
    engine: &mut BftState,
    store: &dyn AtomicSlotStore,
    value: [u8; 32],
) -> PrecommitCertificate {
    let registry = reg();
    engine.propose(value).expect("propose");
    engine
        .prevote(value, vid(1), &registry, store, sign_with(1))
        .expect("own prevote");
    for seed in [2u8, 3u8] {
        let v = signed(
            engine.height.get(),
            engine.round.get(),
            VotePhase::Prevote,
            value,
            seed,
        );
        assert!(matches!(
            engine.accept_vote(&v, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let prevote_cert = engine
        .certify_prevotes_for(value, &registry)
        .expect("prevote certificate");
    engine
        .precommit(&prevote_cert, vid(1), &registry, store, sign_with(1))
        .expect("own precommit");
    for seed in [2u8, 3u8] {
        let v = signed(
            engine.height.get(),
            engine.round.get(),
            VotePhase::Precommit,
            value,
            seed,
        );
        assert!(matches!(
            engine.accept_vote(&v, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    engine
        .certify_precommits_for(value, &registry)
        .expect("precommit certificate")
}

// ---------------------------------------------------------------------------
// 1-2. Finality and quorum
// ---------------------------------------------------------------------------

#[test]
fn finality_with_a_valid_quorum_is_recorded_and_reloadable() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);

    let cert = reach_precommit_certificate(&mut engine, &store, cp.id());
    assert!(cert.support().get() >= cert.quorum().get(), "quorate");

    let decision = engine
        .finalize(&cert, &cp, None, &registry, &store)
        .expect("finalised");
    assert_eq!(decision.checkpoint_id, cp.id());
    assert_eq!(decision.height, CheckpointHeight(0));
    assert_eq!(decision.support, 30);
    assert_eq!(decision.quorum, 27);
    assert_eq!(decision.certificate_id, cert.id());

    // Persisted, not just in memory.
    let stored = store
        .get(&aether_unified::l2bft::finality_key(CheckpointHeight(0)))
        .expect("get")
        .expect("present");
    assert!(!stored.is_empty());

    // Idempotent: same certificate again returns the same decision.
    let again = engine
        .finalize(&cert, &cp, None, &registry, &store)
        .expect("idempotent");
    assert_eq!(again, decision);
}

#[test]
fn below_quorum_never_produces_a_certificate() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);

    engine
        .prevote(cp.id(), vid(1), &registry, &store, sign_with(1))
        .expect("prevote");
    let v = signed(0, 0, VotePhase::Prevote, cp.id(), 2);
    assert!(matches!(
        engine.accept_vote(&v, &registry),
        VoteOutcome::Accepted { .. }
    ));

    // 20 of 40 < 27.
    match engine.certify_prevotes_for(cp.id(), &registry) {
        Err(BftError::NotQuorate {
            support,
            quorum,
            total,
        }) => {
            assert_eq!(support, 20);
            assert_eq!(quorum, 27);
            assert_eq!(total, 40);
        }
        other => panic!("expected NotQuorate, got {other:?}"),
    }

    // And no precommit certificate at all.
    assert!(engine.certify_precommits_for(cp.id(), &registry).is_err());
}

// ---------------------------------------------------------------------------
// 3-5. Wrong context
// ---------------------------------------------------------------------------

#[test]
fn a_vote_from_another_generation_is_rejected() {
    let registry = reg();
    let mut engine = new_engine(0);
    let mut vote = signed(0, 0, VotePhase::Prevote, [0x11; 32], 1);
    vote.generation = GenerationId([9u8; 32]);

    match engine.accept_vote(&vote, &registry) {
        VoteOutcome::ForeignContext { field, .. } => assert_eq!(field, "generation"),
        other => panic!("expected ForeignContext, got {other:?}"),
    }
}

#[test]
fn a_vote_from_another_height_is_rejected() {
    let registry = reg();
    let mut engine = new_engine(3);
    let vote = signed(2, 0, VotePhase::Prevote, [0x11; 32], 1);

    match engine.accept_vote(&vote, &registry) {
        VoteOutcome::ForeignContext { field, .. } => assert_eq!(field, "height"),
        other => panic!("expected ForeignContext, got {other:?}"),
    }
}

#[test]
fn a_vote_wrapped_in_the_wrong_phase_is_rejected() {
    // A precommit vote cannot be wrapped as a prevote, and vice versa.
    let precommit_vote = signed(0, 0, VotePhase::Precommit, [0x11; 32], 1);
    match aether_unified::l2bft::Prevote::new(precommit_vote, reg().set_root()) {
        Err(BftError::ContextMismatch { field }) => assert_eq!(field, "phase"),
        other => panic!("expected phase mismatch, got {other:?}"),
    }

    let prevote_vote = signed(0, 0, VotePhase::Prevote, [0x11; 32], 1);
    match aether_unified::l2bft::Precommit::new(prevote_vote, reg().set_root()) {
        Err(BftError::ContextMismatch { field }) => assert_eq!(field, "phase"),
        other => panic!("expected phase mismatch, got {other:?}"),
    }
}

#[test]
fn a_certificate_cannot_be_moved_to_another_context() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);
    let cert = reach_precommit_certificate(&mut engine, &store, cp.id());

    let elsewhere = engine.context(VotePhase::Precommit).with_round(Round(1));
    match cert.require_context(&elsewhere) {
        Err(BftError::ContextMismatch { field }) => assert_eq!(field, "round"),
        other => panic!("expected round mismatch, got {other:?}"),
    }
    // And a certificate for the prevote phase is not a precommit certificate.
    let prevote_cert = engine
        .certify_prevotes_for(cp.id(), &registry)
        .expect("prevote cert");
    let as_precommit = QuorumCertificate::decode(&prevote_cert.encode()).expect("decode");
    assert!(PrecommitCertificate::certify(as_precommit, &registry, NET).is_err());
}

// ---------------------------------------------------------------------------
// 6-7. Double votes
// ---------------------------------------------------------------------------

#[test]
fn a_double_prevote_is_refused_and_the_first_commitment_stands() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);

    engine
        .prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1))
        .expect("first prevote");

    // Same value again: idempotent, not a second signature.
    let again = engine
        .prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1))
        .expect("repeat is idempotent");
    assert_eq!(again.checkpoint_id(), [0xA1; 32]);

    // Different value in the same slot: refused by A2 before any signature.
    match engine.prevote([0xB2; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::LockRetained { .. }) => {}
        other => panic!("expected LockRetained, got {other:?}"),
    }
    // AW-LOCK-1: a prevote does not write the lock, so there is none yet.
    assert!(
        engine.active_lock().is_none(),
        "a lone prevote must not lock the height"
    );
}

#[test]
fn a_double_precommit_is_refused() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp_a = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);

    // Reach a quorate prevote certificate for A, then precommit twice.
    engine.propose(cp_a.id()).expect("propose");
    engine
        .prevote(cp_a.id(), vid(1), &registry, &store, sign_with(1))
        .expect("prevote");
    for seed in [2u8, 3u8] {
        let v = signed(0, 0, VotePhase::Prevote, cp_a.id(), seed);
        engine.accept_vote(&v, &registry);
    }
    let prevote_cert = engine
        .certify_prevotes_for(cp_a.id(), &registry)
        .expect("prevote certificate");

    let first = engine
        .precommit(&prevote_cert, vid(1), &registry, &store, sign_with(1))
        .expect("first precommit");
    // The identical call is idempotent, not a second signature.
    let again = engine
        .precommit(&prevote_cert, vid(1), &registry, &store, sign_with(1))
        .expect("repeat is idempotent");
    assert_eq!(again.checkpoint_id(), first.checkpoint_id());

    // A second, different value is refused before any signature.
    let cp_b = checkpoint_alt(0, [0u8; 32], [0x99u8; 32]);
    match engine.check_value_against_lock(&cp_b.id()) {
        Err(BftError::PrevoteNotJustified {
            lock_round, locked, ..
        }) => {
            assert_eq!(lock_round, 0);
            assert_eq!(locked, hex::encode(cp_a.id()));
        }
        other => panic!("expected PrevoteNotJustified, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 8-10. Locks and proof of lock
// ---------------------------------------------------------------------------

#[test]
fn changing_value_without_a_proof_of_lock_is_refused() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    // AW-LOCK-2: the lock is written by a precommit, never by a prevote.
    reach_precommit_certificate(&mut engine, &store, [0xA1; 32]);
    assert_eq!(
        engine.active_lock().map(|l| l.checkpoint_id),
        Some([0xA1; 32])
    );

    for round in 1..4u32 {
        engine.begin_round(Round(round)).expect("round change");
        match engine.prevote([0xB2; 32], vid(1), &registry, &store, sign_with(1)) {
            Err(BftError::PrevoteNotJustified { lock_round, .. }) => {
                assert_eq!(lock_round, 0);
            }
            other => panic!("round {round}: expected refusal, got {other:?}"),
        }
    }
    assert_eq!(
        engine.active_lock().map(|l| l.checkpoint_id),
        Some([0xA1; 32])
    );
}

#[test]
fn a_valid_proof_of_lock_authorises_the_prevote_window() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);

    // Build a genuine, quorate prevote certificate for value B in round 2 —
    // this is exactly a proof of lock: `POL(B, 0, g, 2)`.
    engine.begin_round(Round(2)).expect("round 2");
    engine.propose([0xB2; 32]).expect("propose B");
    engine
        .prevote([0xB2; 32], vid(1), &registry, &store, sign_with(1))
        .expect("prevote B");
    for seed in [2u8, 3u8] {
        let v = signed(0, 2, VotePhase::Prevote, [0xB2; 32], seed);
        assert!(matches!(
            engine.accept_vote(&v, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let cert = engine
        .certify_prevotes_for([0xB2; 32], &registry)
        .expect("quorate prevote certificate");
    assert!(cert.support().get() >= cert.quorum().get());

    let pol = ProofOfLock::from_prevote(cert);
    assert_eq!(pol.checkpoint_id, [0xB2; 32]);
    assert_eq!(pol.round, Round(2));
    assert!(pol.is_valid_for(&engine.context(VotePhase::Prevote)));

    // AW-LOCK-1, both bounds, checked on their own:
    let at_round_3 = engine.context(VotePhase::Prevote).with_round(Round(3));
    assert!(
        pol.accepted_for(&[0xB2u8; 32], &at_round_3, Round(0)),
        "lockR <= r_pol < r: inclusive below, strict above"
    );
    assert!(
        pol.accepted_for(&[0xB2u8; 32], &at_round_3, Round(2)),
        "the proof's own round is a valid lower bound"
    );
    assert!(
        !pol.accepted_for(&[0xB2u8; 32], &at_round_3, Round(3)),
        "a lock newer than the proof is not covered"
    );
    let at_round_2 = engine.context(VotePhase::Prevote).with_round(Round(2));
    assert!(
        !pol.accepted_for(&[0xB2u8; 32], &at_round_2, Round(0)),
        "the upper bound is strict: r_pol = r proves nothing"
    );

    // A second engine locked on A at round 0 can now prevote B at round 3,
    // because 0 <= 2 < 3. The lock itself does not move.
    //
    // Each engine has its own store: a round position belongs to exactly one
    // node, and the first engine has already written round 2 into `store`.
    let store_b = MemoryAtomicSlotStore::new();
    let mut engine_b = new_engine(0);
    reach_precommit_certificate(&mut engine_b, &store_b, [0xA1; 32]);
    assert_eq!(
        engine_b.active_lock().map(|l| l.checkpoint_id),
        Some([0xA1; 32])
    );
    engine_b.begin_round(Round(3)).expect("round 3");
    let prevote = engine_b
        .prevote_with_proof(
            [0xB2; 32],
            Some(&pol),
            vid(1),
            &registry,
            &store_b,
            sign_with(1),
        )
        .expect("a valid proof authorises the prevote");
    assert_eq!(prevote.checkpoint_id(), [0xB2; 32]);
    assert_eq!(
        engine_b.active_lock().map(|l| l.checkpoint_id),
        Some([0xA1; 32]),
        "a proof authorises one prevote; it never unlocks"
    );
}

#[test]
fn a_proof_of_lock_from_a_lower_round_covers_nothing() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    engine
        .prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1))
        .expect("prevote");
    for seed in [2u8, 3u8] {
        let v = signed(0, 0, VotePhase::Prevote, [0xA1; 32], seed);
        engine.accept_vote(&v, &registry);
    }
    let cert = engine
        .certify_prevotes_for([0xA1; 32], &registry)
        .expect("cert");
    let pol = ProofOfLock::from_prevote(cert);

    assert!(pol.covers_value(&[0xA1; 32], Round(0)));
    assert!(!pol.covers_value(&[0xA1; 32], Round(1)), "lower round");
    assert!(!pol.covers_value(&[0xB2; 32], Round(0)), "other value");
}

// ---------------------------------------------------------------------------
// 11-12. Forged certificates and weights
// ---------------------------------------------------------------------------

#[test]
fn a_forged_certificate_is_rejected() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);
    let cert = reach_precommit_certificate(&mut engine, &store, cp.id());

    // Flip the declared support upward: AT recomputes and refuses.
    let mut qc = QuorumCertificate::decode(&cert.encode()).expect("decode");
    qc.support_weight = ValidatorWeight(40);
    assert!(PrecommitCertificate::certify(qc, &registry, NET).is_err());

    // Point the registry root elsewhere: refused before any weight is believed.
    let mut qc2 = QuorumCertificate::decode(&cert.encode()).expect("decode");
    qc2.registry_root = [0u8; 32];
    assert!(PrecommitCertificate::certify(qc2, &registry, NET).is_err());

    // Drop a signature: the votes no longer form a quorum.
    let mut qc3 = QuorumCertificate::decode(&cert.encode()).expect("decode");
    qc3.votes.pop();
    match PrecommitCertificate::certify(qc3, &registry, NET) {
        Err(BftError::NotQuorate { .. }) | Err(BftError::Rejected(_)) => {}
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn declared_weights_are_never_trusted() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);
    let cert = reach_precommit_certificate(&mut engine, &store, cp.id());

    let honest_support = cert.support().get();
    let mut qc = QuorumCertificate::decode(&cert.encode()).expect("decode");
    qc.total_weight = ValidatorWeight(10); // pretend the electorate is tiny
    qc.support_weight = ValidatorWeight(10);
    assert!(
        PrecommitCertificate::certify(qc, &registry, NET).is_err(),
        "declared weights must not change the computed support ({honest_support})"
    );

    // The honest certificate, re-verified from bytes, reports the recomputed value.
    let re = PrecommitCertificate::from_bytes(&cert.encode(), &registry, NET).expect("reverify");
    assert_eq!(re.support().get(), honest_support);
    assert_eq!(re.total().get(), 40);
    assert_eq!(re.quorum().get(), 27);
}

// ---------------------------------------------------------------------------
// 13-14. Restart and uncertain restoration
// ---------------------------------------------------------------------------

#[test]
fn a_lock_survives_a_restart_and_still_refuses_another_value() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = new_engine(0);
        // AW-LOCK-2: the lock, and the proof that justifies it, come from a
        // precommit.
        reach_precommit_certificate(&mut engine, &store, [0xA1; 32]);
        engine.persisted().persist(&store).expect("persist");
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.report.may_sign(),
        "findings: {:?}",
        restored.report.findings
    );
    assert_eq!(
        restored.state.active_lock().map(|l| l.checkpoint_id),
        Some([0xA1; 32]),
        "the lock must survive the restart"
    );
    assert!(
        restored.state.persisted().proof_of_lock.is_some(),
        "AW-LOCK-4: the proof must survive the restart"
    );
    assert!(
        !restored.state.lock_proof_absent,
        "AW-LOCK-11: the restored proof must re-verify"
    );

    let mut engine = restored.state;
    match engine.prevote([0xB2; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::PrevoteNotJustified { .. }) => {}
        other => panic!("expected refusal after restart, got {other:?}"),
    }
}

#[test]
fn an_uncertain_restoration_blocks_every_signature() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    // Empty store, but an anchor is expected: absence proves nothing.
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(!restored.report.may_sign());

    let mut engine = restored.state;
    match engine.prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::RecoveryRequired(_)) => {}
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
    assert!(store.is_empty(), "nothing may be written while uncertain");
}

#[test]
fn a_halt_record_from_a_previous_run_blocks_signing() {
    let registry = reg();
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let engine = new_engine(0);
        engine.persisted().persist(&store).expect("persist state");
        // Simulate a halt that was persisted by an earlier run.
        let bytes = aether_unified::l2persist::seal(b"conflicting finality at height 0");
        store
            .cas(aether_unified::l2bft::HALT_KEY, None, &bytes)
            .expect("halt record");
    }

    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.halt.is_some());
    let mut engine = restored.state;
    match engine.prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::Halted(_)) => {}
        other => panic!("expected Halted, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 15-16. Contradictions
// ---------------------------------------------------------------------------

#[test]
fn two_contradictory_certificates_are_detected() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp_a = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);
    let cert_a = reach_precommit_certificate(&mut engine, &store, cp_a.id());

    // Another value at the same position, carried by peer votes only: validator
    // 1 already signed the first slot above and could not sign again.
    let cp_b = checkpoint_alt(0, [0u8; 32], [0x99u8; 32]);
    let value_b = cp_b.id();
    assert_ne!(value_b, cp_a.id());
    let mut other = new_engine(0);
    other.propose(value_b).expect("propose");
    for seed in [2u8, 3u8, 4u8] {
        let v = signed(0, 0, VotePhase::Prevote, value_b, seed);
        assert!(matches!(
            other.accept_vote(&v, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let prevote_b = other
        .certify_prevotes_for(value_b, &registry)
        .expect("cert");
    assert!(prevote_b.support().get() >= 27);
    for seed in [2u8, 3u8, 4u8] {
        let v = signed(0, 0, VotePhase::Precommit, value_b, seed);
        other.accept_vote(&v, &registry);
    }
    let cert_b = other
        .certify_precommits_for(value_b, &registry)
        .expect("cert B");

    // AT states the contradiction explicitly.
    assert!(cert_a.qc().conflicts_with(cert_b.qc()));
    assert!(!cert_a.qc().conflicts_with(cert_a.qc()));
    assert_ne!(cert_a.checkpoint_id(), cert_b.checkpoint_id());
}

#[test]
fn two_contradictory_finalities_halt_and_keep_the_evidence() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp_a = checkpoint(0, [0u8; 32]);
    let mut first = new_engine(0);
    let cert_a = reach_precommit_certificate(&mut first, &store, cp_a.id());
    first
        .finalize(&cert_a, &cp_a, None, &registry, &store)
        .expect("first finality");

    // A second engine over the same store decides another value at the same
    // height: that is a double finality. The votes come from peers, because
    // validator 1 already consumed its slot.
    let cp_b = checkpoint_alt(0, [0u8; 32], [0x99u8; 32]);
    let value_b = cp_b.id();
    let mut second = new_engine(0);
    second.propose(value_b).expect("propose");
    for seed in [2u8, 3u8, 4u8] {
        let v = signed(0, 0, VotePhase::Prevote, value_b, seed);
        assert!(matches!(
            second.accept_vote(&v, &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let _prevote_b = second
        .certify_prevotes_for(value_b, &registry)
        .expect("cert");
    for seed in [2u8, 3u8, 4u8] {
        let v = signed(0, 0, VotePhase::Precommit, value_b, seed);
        second.accept_vote(&v, &registry);
    }
    let cert_b = second
        .certify_precommits_for(value_b, &registry)
        .expect("cert B");

    match second.finalize(&cert_b, &cp_b, None, &registry, &store) {
        Err(BftError::ConflictingFinality { .. }) => {}
        other => panic!("expected ConflictingFinality, got {other:?}"),
    }
    assert!(second.halt.is_some(), "HALT must be set");
    // Both values are preserved in the halt reason.
    let text = second.halt.as_ref().unwrap().describe();
    assert!(text.contains(&hex::encode(cp_a.id())));
    assert!(text.contains(&hex::encode(value_b)));
    // And nothing more can be signed.
    match second.prevote([0xCC; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::Halted(_)) => {}
        other => panic!("expected Halted, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 17. Crash window
// ---------------------------------------------------------------------------

#[test]
fn a_reservation_without_signature_still_blocks_the_other_value() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let slot = aether_unified::l2persist::SlotKey {
        generation: gen_id().0,
        height: CheckpointHeight(0),
        round: Round(0),
        phase: VotePhase::Prevote,
        validator: vid(1),
    };
    // Crash happened after the reservation and the flush, before the signature.
    store.reserve(&slot, &[0xA1; 32]).expect("reserve");
    store.flush().expect("flush");

    let mut engine = new_engine(0);
    match engine.prevote([0xB2; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::Emit(msg)) => assert!(msg.contains("equivocation") || msg.contains("slot")),
        other => panic!("expected a slot refusal, got {other:?}"),
    }
    // The same value is still safe: identical commitment.
    engine
        .prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1))
        .expect("same value signs");
}

// ---------------------------------------------------------------------------
// 18. Round changes
// ---------------------------------------------------------------------------

fn round_change(seed: u8, from: u32, to: u32, locked: Option<LockedValue>) -> RoundChange {
    RoundChange::unsigned(
        NET,
        gen_id(),
        CheckpointHeight(0),
        Round(from),
        Round(to),
        vid(seed),
        reg().set_root(),
        locked,
    )
    .sign_with(&sk(seed))
}

#[test]
fn a_round_change_without_a_lock_is_recorded_then_adopted() {
    let registry = reg();
    let mut engine = new_engine(0);

    // Below threshold: recorded, not adopted.
    match engine
        .process_round_change(round_change(1, 0, 1, None), &registry, NET)
        .expect("recorded")
    {
        RoundChangeOutcome::Recorded { support, quorum } => {
            assert_eq!(support.get(), 10);
            assert_eq!(quorum.get(), 27);
        }
        other => panic!("expected Recorded, got {other:?}"),
    }
    assert_eq!(engine.round, Round(0));

    // Two more reach 30 >= 27: adopted.
    engine
        .process_round_change(round_change(2, 0, 1, None), &registry, NET)
        .expect("ok");
    match engine
        .process_round_change(round_change(3, 0, 1, None), &registry, NET)
        .expect("ok")
    {
        RoundChangeOutcome::Adopted { from, to, evidence } => {
            assert_eq!(from, Round(0));
            assert_eq!(to, Round(1));
            assert!(evidence.support.get() >= 27);
        }
        other => panic!("expected Adopted, got {other:?}"),
    }
    assert_eq!(engine.round, Round(1));
}

#[test]
fn a_round_change_carries_the_lock_and_never_clears_it() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    // AW-LOCK-2: lock from a precommit, as the rule requires.
    reach_precommit_certificate(&mut engine, &store, [0xA1; 32]);

    let lock = Some(LockedValue {
        checkpoint_id: [0xA1; 32],
        height: CheckpointHeight(0),
        round: Round(0),
    });
    for seed in [1u8, 2u8, 3u8] {
        engine
            .process_round_change(round_change(seed, 0, 1, lock), &registry, NET)
            .expect("round change");
    }
    assert_eq!(engine.round, Round(1));
    assert_eq!(
        engine.active_lock().map(|l| l.checkpoint_id),
        Some([0xA1; 32]),
        "a round change must not unlock"
    );

    // After the round change the same value is still signable (new slot), and
    // another value is still refused.
    engine
        .prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1))
        .expect("same value in a new round");
    match engine.prevote([0xB2; 32], vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::PrevoteNotJustified { .. }) => {}
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn an_incomplete_round_change_history_is_refused() {
    let registry = reg();
    let mut engine = new_engine(0);

    // A round change with a forged signature is rejected outright.
    let mut forged = round_change(1, 0, 2, None);
    forged.signature = [0u8; 64];
    match engine.process_round_change(forged, &registry, NET) {
        Err(BftError::Rejected(_)) => {}
        other => panic!("expected a rejection, got {other:?}"),
    }

    // A round change for an old round is refused as a no-op.
    // (Current round 0, target 0 is not ahead.)
    let stale = RoundChange::unsigned(
        NET,
        gen_id(),
        CheckpointHeight(0),
        Round(0),
        Round(0),
        vid(1),
        reg().set_root(),
        None,
    )
    .sign_with(&sk(1));
    assert!(engine.process_round_change(stale, &registry, NET).is_err());

    // A round change claiming a lock for another height is refused.
    let wrong_height_lock = RoundChange::unsigned(
        NET,
        gen_id(),
        CheckpointHeight(0),
        Round(0),
        Round(1),
        vid(1),
        reg().set_root(),
        Some(LockedValue {
            checkpoint_id: [0xA1; 32],
            height: CheckpointHeight(9),
            round: Round(0),
        }),
    )
    .sign_with(&sk(1));
    assert!(engine
        .process_round_change(wrong_height_lock, &registry, NET)
        .is_err());

    // Only one valid message: still below threshold.
    match engine
        .process_round_change(round_change(1, 0, 1, None), &registry, NET)
        .expect("recorded")
    {
        RoundChangeOutcome::Recorded { .. } => {}
        other => panic!("expected Recorded, got {other:?}"),
    }
    assert_eq!(
        engine.round,
        Round(0),
        "incomplete history must not advance"
    );
}

// ---------------------------------------------------------------------------
// Multi-round sequences
// ---------------------------------------------------------------------------

#[test]
fn a_multi_round_sequence_never_double_signs_a_height() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);

    // AW-LOCK-2: round 0 locks A through a precommit.
    reach_precommit_certificate(&mut engine, &store, [0xA1; 32]);

    for round in 1..6u32 {
        engine.begin_round(Round(round)).expect("begin round");
        // A is signable in every round (same value, new slot).
        let p = engine
            .prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1))
            .expect("same value each round");
        assert_eq!(p.context().round, Round(round));
        // B never is: no proof of lock authorises it.
        for value in [[0xB2u8; 32], [0xC3u8; 32]] {
            assert!(matches!(
                engine.prevote(value, vid(1), &registry, &store, sign_with(1)),
                Err(BftError::PrevoteNotJustified { .. })
            ));
        }
    }

    // Every signed slot is for A: one prevote and one precommit in round 0,
    // then one prevote per round in 1..6.
    let slots = store.scan_slots().expect("scan");
    assert_eq!(slots.len(), 7);
    for slot in &slots {
        assert_eq!(slot.checkpoint_id, [0xA1; 32]);
    }
}

#[test]
fn a_full_sequence_across_two_heights_resets_the_lock_only_on_height_change() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp0 = checkpoint(0, [0u8; 32]);
    let cp1 = checkpoint(1, cp0.id());
    let mut engine = new_engine(0);

    let cert_a = reach_precommit_certificate(&mut engine, &store, cp0.id());
    let d0 = engine
        .finalize(&cert_a, &cp0, None, &registry, &store)
        .expect("height 0 final");
    assert_eq!(d0.checkpoint_id, cp0.id());

    // Height 1: the lock becomes inert by scope (R-LOCK-1) but is *kept*
    // (R-LOCK-2) — it is never erased.
    engine
        .advance_height(CheckpointHeight(1), &store)
        .expect("advance");
    assert!(engine.active_lock().is_none(), "out of scope: inert");
    assert!(
        engine.persisted().locked.is_some(),
        "R-LOCK-2: an inert lock is never erased"
    );
    assert_eq!(engine.round, Round(0));

    let cert_b = reach_precommit_certificate(&mut engine, &store, cp1.id());
    let d1 = engine
        .finalize(&cert_b, &cp1, Some(&cp0), &registry, &store)
        .expect("height 1 final");
    assert_eq!(d1.checkpoint_id, cp1.id());
    assert_eq!(d1.parent, cp0.id());
}

#[test]
fn a_checkpoint_without_a_valid_parent_is_not_finalised() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp0 = checkpoint(0, [0u8; 32]);
    let cp1 = checkpoint(1, cp0.id());
    let mut engine = new_engine(1);

    // Height 1 without a parent link: refused even with a quorate certificate.
    let cert = reach_precommit_certificate(&mut engine, &store, cp1.id());
    match engine.finalize(&cert, &cp1, None, &registry, &store) {
        Err(BftError::ParentNotFinalized(_)) => {}
        other => panic!("expected ParentNotFinalized, got {other:?}"),
    }

    // With the right parent it succeeds.
    engine
        .finalize(&cert, &cp1, Some(&cp0), &registry, &store)
        .expect("valid parent");

    // A certificate for a different checkpoint than the record is refused, on a
    // fresh store so the slot is available.
    let fresh = MemoryAtomicSlotStore::new();
    let other_cp = checkpoint_alt(1, cp0.id(), [0x99u8; 32]);
    let third = checkpoint_alt(1, cp0.id(), [0x77u8; 32]);
    let mut engine2 = new_engine(1);
    let cert2 = reach_precommit_certificate(&mut engine2, &fresh, other_cp.id());
    match engine2.finalize(&cert2, &third, Some(&cp0), &registry, &fresh) {
        Err(BftError::ContextMismatch { field }) => assert_eq!(field, "value"),
        other => panic!("expected value mismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Properties (§11)
// ---------------------------------------------------------------------------

#[test]
fn property_no_signature_is_ever_emitted_from_recovery_required() {
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = new_engine(0);
    // BU: the verdict is read-only from outside; `block_recovery` is the
    // legitimate way to record one, and it can only block, never clear.
    engine.block_recovery(aether_unified::l2persist::RecoveryReason::MissingAnchor);

    assert!(matches!(
        engine.prevote([0xA1; 32], vid(1), &registry, &store, sign_with(1)),
        Err(BftError::RecoveryRequired(_))
    ));
    assert!(matches!(
        engine.begin_round(Round(1)),
        Err(BftError::RecoveryRequired(_))
    ));
    assert!(store.is_empty());
}

#[test]
fn property_two_values_cannot_be_finalised_at_one_height() {
    // The engine refuses the second decision and halts; this is the local
    // counterpart of `N-SAFE-1`, not a proof of it.
    let registry = reg();
    let store = MemoryAtomicSlotStore::new();
    let cp_a = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);
    let cert_a = reach_precommit_certificate(&mut engine, &store, cp_a.id());
    engine
        .finalize(&cert_a, &cp_a, None, &registry, &store)
        .expect("final A");

    // Same engine, another checkpoint at the same height: the certificate and the
    // record disagree, so nothing is decided and the first decision stands.
    let cp_b = checkpoint_alt(0, [0u8; 32], [0x99u8; 32]);
    match engine.finalize(&cert_a, &cp_b, None, &registry, &store) {
        Err(BftError::ContextMismatch { field }) => assert_eq!(field, "value"),
        other => panic!("expected a value mismatch, got {other:?}"),
    }
    assert_eq!(
        engine.finality.map(|d| d.checkpoint_id),
        Some(cp_a.id()),
        "the first finality must not be revised"
    );
}

#[test]
fn property_signatures_are_bound_to_their_context() {
    let registry = reg();
    let base = signed(0, 0, VotePhase::Prevote, [0x11; 32], 1);
    assert!(base.verify(&registry, NET).is_ok());

    for mutate in 0..5u8 {
        let mut tampered = base.clone();
        match mutate {
            0 => tampered.height = CheckpointHeight(1),
            1 => tampered.round = Round(3),
            2 => tampered.phase = VotePhase::Precommit,
            3 => tampered.checkpoint_id = [0x22; 32],
            _ => tampered.generation = GenerationId([5u8; 32]),
        }
        assert!(
            tampered.verify(&registry, NET).is_err(),
            "mutation {mutate} must invalidate the signature"
        );
    }
}

#[test]
fn property_locks_and_weights_are_recomputed_on_every_path() {
    let registry = reg();
    // A registry with different weights produces a different set root, so no
    // object certified against the first one can be reused against it.
    let other = registry_with(&[(1, 30), (2, 10), (3, 10), (4, 10)]);
    assert_ne!(registry.set_root(), other.set_root());

    let store = MemoryAtomicSlotStore::new();
    let cp = checkpoint(0, [0u8; 32]);
    let mut engine = new_engine(0);
    let cert = reach_precommit_certificate(&mut engine, &store, cp.id());

    assert_eq!(cert.total().get(), 40);
    assert!(PrecommitCertificate::from_bytes(&cert.encode(), &other, NET).is_err());
}
