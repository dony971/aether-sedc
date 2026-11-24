//! L2 foundations — acceptance tests for A-06.6-AS.
//!
//! Integration tests (discovered by Cargo) so that `src/tests/mod.rs` is not
//! touched. Every test states the rule it checks and, where relevant, what it
//! deliberately does **not** claim.

use aether_unified::consensus::checkpoint::CheckpointError;
use aether_unified::consensus::generation::{GenerationError, GenerationState};
use aether_unified::consensus::l2_store::{commit_key, L2StoreError};
use aether_unified::consensus::*;
use aether_unified::storage::Storage;

// ---------------------------------------------------------------- helpers

fn vid(b: u8) -> ValidatorId {
    ValidatorId([b; 32])
}

fn pairs(spec: &[(u8, u64)]) -> Vec<(ValidatorId, ValidatorWeight)> {
    spec.iter()
        .map(|(b, w)| (vid(*b), ValidatorWeight(*w)))
        .collect()
}

/// Four equal validators: total 40, quorum ⌈80/3⌉ = 27.
fn gen_basic() -> Generation {
    Generation::new(0, 100, &pairs(&[(1, 10), (2, 10), (3, 10), (4, 10)])).unwrap()
}

fn ckpt(g: &Generation, h: u64, parent: [u8; 32]) -> Checkpoint {
    Checkpoint::new(
        g.id(),
        CheckpointHeight(h),
        parent,
        [0x11; 32],
        [0x22; 32],
        g.set_root(),
        None,
    )
    .unwrap()
}

// ------------------------------------------------- 1. deterministic generation

#[test]
fn generation_is_deterministic_and_order_independent() {
    let a = Generation::new(7, 42, &pairs(&[(1, 10), (2, 20), (3, 30)])).unwrap();
    let b = Generation::new(7, 42, &pairs(&[(3, 30), (1, 10), (2, 20)])).unwrap();
    let c = Generation::new(7, 42, &pairs(&[(2, 20), (3, 30), (1, 10)])).unwrap();

    assert_eq!(a.id(), b.id());
    assert_eq!(a.id(), c.id());
    assert_eq!(a.set_root(), b.set_root());
    assert_eq!(a.encode(), b.encode());
    assert_eq!(a.encode(), c.encode());
    assert_eq!(a.total_weight(), ValidatorWeight(60));
    assert_eq!(a.quorum(), quorum_threshold(ValidatorWeight(60)));
}

#[test]
fn generation_identity_changes_with_content() {
    let base = Generation::new(7, 42, &pairs(&[(1, 10), (2, 20)])).unwrap();
    let other_number = Generation::new(8, 42, &pairs(&[(1, 10), (2, 20)])).unwrap();
    let other_epoch = Generation::new(7, 43, &pairs(&[(1, 10), (2, 20)])).unwrap();
    let other_weight = Generation::new(7, 42, &pairs(&[(1, 10), (2, 21)])).unwrap();

    assert_ne!(base.id(), other_number.id());
    assert_ne!(base.id(), other_epoch.id());
    assert_ne!(base.id(), other_weight.id());
}

#[test]
fn generation_rejects_invalid_sets() {
    assert_eq!(
        Generation::new(0, 0, &[]),
        Err(GenerationError::EmptyValidatorSet)
    );
    assert_eq!(
        Generation::new(0, 0, &pairs(&[(1, 0)])),
        Err(GenerationError::ZeroWeight(vid(1)))
    );
    assert_eq!(
        Generation::new(0, 0, &pairs(&[(1, 5), (1, 5)])),
        Err(GenerationError::DuplicateValidator(vid(1)))
    );
}

// ------------------------------------------- 2. canonical serialisation

#[test]
fn generation_encoding_roundtrips_and_is_stable() {
    let g = gen_basic();
    let bytes = g.encode();
    let back = Generation::decode(&bytes).unwrap();
    assert_eq!(g, back);
    assert_eq!(g.id(), back.id());
    assert_eq!(bytes, back.encode());
}

#[test]
fn generation_decoding_rejects_non_canonical_bytes() {
    let g = gen_basic();
    let mut bytes = g.encode();

    // Truncated.
    let short = &bytes[..bytes.len() - 1];
    assert!(matches!(
        Generation::decode(short),
        Err(GenerationError::MalformedEncoding { .. })
    ));

    // Trailing byte.
    bytes.push(0);
    assert!(matches!(
        Generation::decode(&bytes),
        Err(GenerationError::MalformedEncoding { .. })
    ));

    // Unknown version.
    let mut bad = g.encode();
    bad[0] = 9;
    assert_eq!(
        Generation::decode(&bad),
        Err(GenerationError::UnsupportedVersion(9))
    );

    // Unknown state byte (offset: 1 + 8 + 8).
    let mut bad_state = g.encode();
    bad_state[17] = 200;
    assert_eq!(
        Generation::decode(&bad_state),
        Err(GenerationError::UnknownState(200))
    );
}

// ------------------------------------------- 6a. invalid checkpoints rejected

#[test]
fn checkpoint_encoding_roundtrips() {
    let g = gen_basic();
    let cp = ckpt(&g, 5, [0xAA; 32]);
    let bytes = cp.encode();
    let back = Checkpoint::decode(&bytes).unwrap();
    assert_eq!(cp, back);
    assert_eq!(cp.id(), back.id());
    assert!(!cp.is_chain_root());
    assert!(ckpt(&g, 0, [0; 32]).is_chain_root());
}

#[test]
fn checkpoint_rejects_invalid_encodings() {
    let g = gen_basic();
    let cp = ckpt(&g, 5, [0xAA; 32]);
    let bytes = cp.encode();

    // Bad version.
    let mut b = bytes.clone();
    b[0] = 2;
    assert_eq!(
        Checkpoint::decode(&b),
        Err(CheckpointError::UnsupportedVersion(2))
    );

    // Bad option tag.
    let mut b = bytes.clone();
    let tag_index = 1 + 32 + 8 + 32 + 32 + 32 + 32;
    b[tag_index] = 7;
    assert_eq!(
        Checkpoint::decode(&b),
        Err(CheckpointError::NonCanonicalOptionTag(7))
    );

    // Truncated.
    assert!(matches!(
        Checkpoint::decode(&bytes[..bytes.len() - 1]),
        Err(CheckpointError::MalformedEncoding { .. })
    ));

    // Trailing bytes.
    let mut b = bytes.clone();
    b.push(0);
    assert!(matches!(
        Checkpoint::decode(&b),
        Err(CheckpointError::MalformedEncoding { .. })
    ));

    // Zero transition identifier is not representable.
    let zero = Checkpoint::new(
        g.id(),
        CheckpointHeight(1),
        [0; 32],
        [1; 32],
        [2; 32],
        g.set_root(),
        Some([0; 32]),
    );
    assert_eq!(zero, Err(CheckpointError::ZeroTransitionId));
}

#[test]
fn checkpoint_link_validation_is_strict() {
    let g = gen_basic();
    let c0 = ckpt(&g, 0, [0; 32]);
    let c1 = ckpt(&g, 1, c0.id());
    assert!(c1.validate_link(&c0).is_ok());

    // Wrong parent id.
    let stray = ckpt(&g, 1, [0x99; 32]);
    assert_eq!(
        stray.validate_link(&c0),
        Err(CheckpointError::ParentIdMismatch)
    );

    // Height jump.
    let jump = ckpt(&g, 2, c0.id());
    assert!(matches!(
        jump.validate_link(&c0),
        Err(CheckpointError::HeightNotSequential { .. })
    ));
}

// ------------------------------------------------- 3/4/5. roots

#[test]
fn same_state_yields_same_roots_regardless_of_order() {
    let a = vec![(vid(1), ValidatorWeight(10)), (vid(2), ValidatorWeight(20))];
    let b = vec![(vid(2), ValidatorWeight(20)), (vid(1), ValidatorWeight(10))];
    assert_eq!(validator_set_root(&a), validator_set_root(&b));

    let e1 = FinalityEntry {
        sender: [1; 32],
        nonce: 7,
        winner: [9; 32],
        epoch: 3,
        supporting_weight: 30,
        eligible_total: 40,
        votes_root: [4; 32],
    };
    let e2 = FinalityEntry {
        sender: [2; 32],
        nonce: 8,
        winner: [9; 32],
        epoch: 3,
        supporting_weight: 30,
        eligible_total: 40,
        votes_root: [4; 32],
    };
    assert_eq!(finalized_root(&[e1, e2]), finalized_root(&[e2, e1]));

    // Insertion order in a merkle set does not matter either.
    let leaves = vec![[3u8; 32], [1u8; 32], [2u8; 32]];
    let mut shuffled = leaves.clone();
    shuffled.reverse();
    assert_eq!(merkle_root(&leaves), merkle_root(&shuffled));
}

#[test]
fn different_state_yields_different_roots() {
    let a = validator_set_root(&[(vid(1), ValidatorWeight(10))]);
    let b = validator_set_root(&[(vid(1), ValidatorWeight(11))]);
    let c = validator_set_root(&[(vid(2), ValidatorWeight(10))]);
    assert_ne!(a, b);
    assert_ne!(a, c);

    let s1 = state_root([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
    let s2 = state_root([1; 32], [2; 32], [3; 32], [4; 32], [6; 32]);
    assert_ne!(s1, s2);
}

#[test]
fn domains_are_separated() {
    // The same bytes hashed under different domains must not collide, and an
    // empty merkle set must not equal a zero hash.
    let leaf = hash_parts(b"A", &[&[1u8, 2, 3][..]]);
    let other = hash_parts(b"B", &[&[1u8, 2, 3][..]]);
    assert_ne!(leaf, other);
    assert_ne!(merkle_root(&[]), [0u8; 32]);

    // Length prefixing removes concatenation ambiguity.
    let x = hash_parts(b"D", &[&[1u8, 2][..], &[3u8][..]]);
    let y = hash_parts(b"D", &[&[1u8][..], &[2u8, 3][..]]);
    assert_ne!(x, y);
}

// ------------------------------------------------- 12. ACTIVE / LIVE separation

#[test]
fn lifecycle_distinguishes_protocol_states_from_observed_ones() {
    assert!(GenerationState::Candidate.is_protocol_decidable());
    assert!(GenerationState::Ready.is_protocol_decidable());
    assert!(GenerationState::TransitionDecided.is_protocol_decidable());
    assert!(GenerationState::Installed.is_protocol_decidable());
    assert!(GenerationState::Active.is_protocol_decidable());

    // Observed only: no artefact can prove them.
    assert!(!GenerationState::Live.is_protocol_decidable());
    assert!(!GenerationState::Degraded.is_protocol_decidable());
    assert!(!GenerationState::Halted.is_protocol_decidable());
}

#[test]
fn lifecycle_rejects_invalid_transitions() {
    let mut g = gen_basic();
    assert_eq!(g.state(), GenerationState::Candidate);

    // No skipping.
    assert!(matches!(
        g.transition_to(GenerationState::Active),
        Err(GenerationError::InvalidTransition { .. })
    ));
    // Candidate cannot be halted directly.
    assert!(matches!(
        g.transition_to(GenerationState::Halted),
        Err(GenerationError::InvalidTransition { .. })
    ));

    g.transition_to(GenerationState::Ready).unwrap();
    g.transition_to(GenerationState::TransitionDecided).unwrap();
    g.transition_to(GenerationState::Installed).unwrap();
    g.transition_to(GenerationState::Active).unwrap();
    g.transition_to(GenerationState::Live).unwrap();
    g.transition_to(GenerationState::Degraded).unwrap();
    g.transition_to(GenerationState::Live).unwrap(); // availability returned
    g.transition_to(GenerationState::Degraded).unwrap();
    g.transition_to(GenerationState::Halted).unwrap();

    // Halted is terminal.
    assert!(g.state().is_terminal());
    assert!(matches!(
        g.transition_to(GenerationState::Live),
        Err(GenerationError::InvalidTransition { .. })
    ));
}

#[test]
fn state_survives_generation_encoding() {
    let mut g = gen_basic();
    g.transition_to(GenerationState::Ready).unwrap();
    let back = Generation::decode(&g.encode()).unwrap();
    assert_eq!(back.state(), GenerationState::Ready);
    // Identity is content-based and unaffected by lifecycle.
    assert_eq!(back.id(), g.id());
}

// ------------------------------------------------- quorum and margin

#[test]
fn quorum_predicate_matches_threshold_everywhere() {
    for total in 1..=60u64 {
        let t = ValidatorWeight(total);
        let q = quorum_threshold(t);
        for support in 0..=total {
            let s = ValidatorWeight(support);
            assert_eq!(quorum_met(s, t), support >= q.get(), "S={} T={}", support, total);
        }
    }
    assert!(!quorum_met(ValidatorWeight(0), ValidatorWeight(0)));
}

#[test]
fn sigma_min_never_drops_below_one() {
    let p = MarginParams::non_normative_test_default();
    for total in 0..=100u64 {
        let sigma = p.sigma_min(ValidatorWeight(total));
        assert!(sigma.get() >= 1, "total {}", total);
    }
    // rho = 1/6: ceil(600/6) = 100.
    assert_eq!(p.sigma_min(ValidatorWeight(600)), ValidatorWeight(100));
    // A degenerate denominator must not panic and must keep the floor.
    let bad = MarginParams::new(1, 0);
    assert!(!bad.is_valid());
    assert_eq!(bad.sigma_min(ValidatorWeight(10)), ValidatorWeight(1));
}

#[test]
fn margin_admissibility_is_fail_closed() {
    let p = MarginParams::non_normative_test_default();
    // total 40 -> q 27 -> budget 13 -> sigma 7 -> byzantine headroom 6.
    assert!(p.admissibility_margin_ok(ValidatorWeight(40), ValidatorWeight(6)));
    assert!(!p.admissibility_margin_ok(ValidatorWeight(40), ValidatorWeight(7)));
    // Absurd declared byzantine weight must fail, not overflow.
    assert!(!p.admissibility_margin_ok(ValidatorWeight(40), ValidatorWeight(u64::MAX)));
}

// ------------------------------------------------- 7/8/9. READY

fn expectation(g_src: &Generation, cand: &Generation, h_close: u64) -> ReadyExpectation {
    ReadyExpectation {
        network: 7,
        generation: g_src.id(),
        candidate: [0xC1; 32],
        new_set_root: cand.set_root(),
        h_close: CheckpointHeight(h_close),
    }
}

fn att(
    exp: &ReadyExpectation,
    signer: u8,
    weight: u64,
    height: u64,
    sequence: u64,
) -> ReadyAttestation {
    ReadyAttestation::new(
        exp.network,
        exp.generation,
        exp.candidate,
        exp.new_set_root,
        CheckpointHeight(height),
        sequence,
        vid(signer),
        ValidatorWeight(weight),
    )
}

#[test]
fn ready_is_bound_to_its_candidate() {
    let src = gen_basic();
    let cand = Generation::new(1, 200, &pairs(&[(1, 10), (2, 10), (3, 10), (4, 10)])).unwrap();
    let exp = expectation(&src, &cand, 10);
    let cfg = ReadinessConfig::non_normative_test_default();

    let good = vec![
        att(&exp, 1, 10, 9, 1),
        att(&exp, 2, 10, 9, 1),
        att(&exp, 3, 10, 9, 1),
    ];
    let outcome = evaluate(&good, &exp, &cand, &cfg);
    assert!(outcome.reached);
    assert_eq!(outcome.weight, ValidatorWeight(30));
    assert_eq!(outcome.distinct_signers, 3);

    // Same attestations against another candidate give nothing.
    let mut other = exp;
    other.candidate = [0xD2; 32];
    let outcome = evaluate(&good, &other, &cand, &cfg);
    assert!(!outcome.reached);
    assert_eq!(outcome.weight, ValidatorWeight(0));
}

#[test]
fn ready_rejects_stale_and_future_attestations() {
    let src = gen_basic();
    let cand = gen_basic();
    let cfg = ReadinessConfig::new(3);
    let exp = expectation(&src, &cand, 10);

    // h_close = 10, d_ready = 3 -> h_ready >= 7 is fresh.
    let fresh = att(&exp, 1, 10, 7, 1);
    let stale = att(&exp, 2, 10, 6, 1);
    let future = att(&exp, 3, 10, 11, 1);

    let outcome = evaluate(&[fresh, stale, future], &exp, &cand, &cfg);
    assert_eq!(outcome.accepted, vec![vid(1)]);
    assert_eq!(outcome.weight, ValidatorWeight(10));
    assert!(outcome
        .rejected
        .contains(&(vid(2), ReadyRejection::Stale)));
    assert!(outcome
        .rejected
        .contains(&(vid(3), ReadyRejection::FutureHeight)));
}

#[test]
fn ready_deduplicates_and_keeps_highest_sequence() {
    let src = gen_basic();
    let cand = gen_basic();
    let cfg = ReadinessConfig::non_normative_test_default();
    let exp = expectation(&src, &cand, 10);

    // Same signer twice: only the highest sequence counts, weight not doubled.
    let one = att(&exp, 1, 10, 9, 1);
    let two = att(&exp, 1, 10, 9, 2);
    let outcome = evaluate(&[one, two], &exp, &cand, &cfg);
    assert_eq!(outcome.weight, ValidatorWeight(10));
    assert_eq!(outcome.distinct_signers, 1);
    assert!(!outcome.reached);

    // Same sequence, different content: neither side is counted.
    let a = att(&exp, 2, 10, 9, 5);
    let mut b = a;
    b.sequence = 5;
    b.height = CheckpointHeight(8);
    let outcome = evaluate(&[a, b], &exp, &cand, &cfg);
    // Different digests at equal sequence -> conflicting, weight 0.
    assert_eq!(outcome.weight, ValidatorWeight(0));
    assert!(outcome
        .rejected
        .contains(&(vid(2), ReadyRejection::ConflictingSequence)));
}

#[test]
fn ready_rejects_non_members_and_weight_mismatch() {
    let src = gen_basic();
    let cand = gen_basic();
    let cfg = ReadinessConfig::non_normative_test_default();
    let exp = expectation(&src, &cand, 10);

    let outsider = att(&exp, 9, 10, 9, 1); // not in the candidate set
    let liar = att(&exp, 1, 999, 9, 1); // claims more than the pinned weight
    let outcome = evaluate(&[outsider, liar], &exp, &cand, &cfg);
    assert_eq!(outcome.weight, ValidatorWeight(0));
    assert!(outcome
        .rejected
        .contains(&(vid(9), ReadyRejection::NonMember)));
    assert!(outcome
        .rejected
        .contains(&(vid(1), ReadyRejection::WeightMismatch)));
}

#[test]
fn ready_is_not_a_liveness_proof() {
    let src = gen_basic();
    let cand = gen_basic();
    let cfg = ReadinessConfig::non_normative_test_default();
    let exp = expectation(&src, &cand, 10);

    let all = vec![
        att(&exp, 1, 10, 10, 1),
        att(&exp, 2, 10, 10, 1),
        att(&exp, 3, 10, 10, 1),
    ];
    let outcome = evaluate(&all, &exp, &cand, &cfg);
    assert!(outcome.reached);
    // ... and yet: the actual liveness condition is observed online weight,
    // which is zero here. READY says nothing about it.
    assert!(!quorum_met(ValidatorWeight(0), cand.total_weight()));
    assert!(outcome.is_past_intent_only());
}

#[test]
fn ready_digest_is_domain_separated_and_stable() {
    let src = gen_basic();
    let cand = gen_basic();
    let exp = expectation(&src, &cand, 10);
    let a = att(&exp, 1, 10, 9, 1);
    let b = a;
    assert_eq!(a.digest(), b.digest());
    let mut c = a;
    c.sequence = 2;
    assert_ne!(a.digest(), c.digest());

    // An attestation digest never equals a checkpoint id over the same bytes
    // shape: domains differ.
    let cp = ckpt(&cand, 1, [0; 32]);
    assert_ne!(a.digest(), cp.id());

    // Canonical roundtrip.
    let back = ReadyAttestation::decode(&a.encode()).unwrap();
    assert_eq!(a, back);
    assert_eq!(back.digest(), a.digest());
}

// ------------------------------------------------- 10/11. persistence

#[test]
fn l2_commit_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let g = gen_basic();
    let cp = ckpt(&g, 0, [0; 32]);
    let commit = L2Commit::new(g.clone(), cp).unwrap();

    {
        let storage = Storage::open(dir.path()).unwrap();
        let store = L2Store::new(&storage);
        store.write_commit(&commit).unwrap();
        assert_eq!(store.head().unwrap(), Some(CheckpointHeight(0)));
        store.verify_consistency().unwrap();
    }

    // Reopen the same data directory.
    let storage = Storage::open(dir.path()).unwrap();
    let store = L2Store::new(&storage);
    store.verify_consistency().unwrap();
    let loaded = store.read_head_commit().unwrap().unwrap();
    assert_eq!(loaded.generation.id(), g.id());
    assert_eq!(loaded.checkpoint.id(), cp.id());
    assert_eq!(loaded.encode(), commit.encode());
    assert_eq!(store.head_generation_id().unwrap(), Some(g.id()));
}

#[test]
fn l2_commit_chain_is_validated_across_heights() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let store = L2Store::new(&storage);
    let g = gen_basic();

    let c0 = ckpt(&g, 0, [0; 32]);
    store.write_commit(&L2Commit::new(g.clone(), c0).unwrap()).unwrap();
    let c1 = ckpt(&g, 1, c0.id());
    store.write_commit(&L2Commit::new(g.clone(), c1).unwrap()).unwrap();
    assert_eq!(store.head().unwrap(), Some(CheckpointHeight(1)));
    store.verify_consistency().unwrap();

    // Non-monotonic write is refused.
    let again = ckpt(&g, 1, c0.id());
    assert!(matches!(
        store.write_commit(&L2Commit::new(g.clone(), again).unwrap()),
        Err(L2StoreError::NonMonotonicHeight { .. })
    ));
}

#[test]
fn l2_commit_rejects_mismatched_pairing() {
    let g = gen_basic();
    let other = Generation::new(3, 300, &pairs(&[(1, 10)])).unwrap();
    // Checkpoint names another generation than the paired one.
    let cp = ckpt(&other, 0, [0; 32]);
    assert_eq!(
        L2Commit::new(g.clone(), cp),
        Err(L2StoreError::GenerationMismatch)
    );

    // Checkpoint commits another set root.
    let mut cp = ckpt(&g, 0, [0; 32]);
    cp.validator_set_root = [0x77; 32];
    assert_eq!(
        L2Commit::new(g, cp),
        Err(L2StoreError::SetRootMismatch)
    );
}

#[test]
fn corrupted_metadata_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let store = L2Store::new(&storage);
    let g = gen_basic();
    let commit = L2Commit::new(g.clone(), ckpt(&g, 0, [0; 32])).unwrap();
    store.write_commit(&commit).unwrap();

    // Overwrite the commit with garbage.
    storage
        .put_metadata(&commit_key(CheckpointHeight(0)), b"not-a-commit")
        .unwrap();
    assert!(store.read_commit(CheckpointHeight(0)).is_err());
    assert!(store.verify_consistency().is_err());
}

#[test]
fn inconsistent_states_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let store = L2Store::new(&storage);
    let g = gen_basic();

    // Head pointing at a missing commit.
    storage.put_metadata("l2/v1/head", &5u64.to_le_bytes()).unwrap();
    assert_eq!(store.verify_consistency(), Err(L2StoreError::MissingHeadCommit(5)));

    // Commit above the head (simulates a crash between the two writes).
    let dir2 = tempfile::tempdir().unwrap();
    let storage2 = Storage::open(dir2.path()).unwrap();
    let store2 = L2Store::new(&storage2);
    let c0 = ckpt(&g, 0, [0; 32]);
    store2.write_commit(&L2Commit::new(g.clone(), c0).unwrap()).unwrap();
    let c1 = ckpt(&g, 1, c0.id());
    storage2
        .put_metadata(&commit_key(CheckpointHeight(1)), &L2Commit::new(g.clone(), c1).unwrap().encode())
        .unwrap();
    // Head still 0.
    assert_eq!(store2.head().unwrap(), Some(CheckpointHeight(0)));
    assert_eq!(
        store2.verify_consistency(),
        Err(L2StoreError::OrphanCommit { head: 0, found: 1 })
    );
}

#[test]
fn broken_chain_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let store = L2Store::new(&storage);
    let g = gen_basic();

    let c0 = ckpt(&g, 0, [0; 32]);
    store.write_commit(&L2Commit::new(g.clone(), c0).unwrap()).unwrap();
    // Wrong parent identifier: valid on its own, invalid as a successor.
    let c1 = ckpt(&g, 1, [0x55; 32]);
    store.write_commit(&L2Commit::new(g.clone(), c1).unwrap()).unwrap();
    assert_eq!(store.verify_consistency(), Err(L2StoreError::BrokenChain(1)));
}

#[test]
fn empty_store_is_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let store = L2Store::new(&storage);
    assert_eq!(store.head().unwrap(), None);
    assert!(store.read_head_commit().unwrap().is_none());
    store.verify_consistency().unwrap();
}
