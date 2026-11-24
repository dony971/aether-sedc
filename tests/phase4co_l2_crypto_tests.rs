//! L2 cryptographic layer — acceptance tests for A-06.6-AT.
//!
//! Every test states what it proves and, where relevant, what it does NOT prove.
//! Deterministic throughout: Ed25519 keys are derived from fixed seeds, no RNG,
//! no wall clock, no shared state.

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::{
    quorum_met, quorum_threshold, CheckpointHeight, Generation, GenerationId, Round, ValidatorId,
    ValidatorWeight,
};
use aether_unified::l2crypto::ready::SIGNED_READY_LEN;
use aether_unified::l2crypto::registry::{validator_id, RegistryError};
use aether_unified::l2crypto::vote::{VoteVerifyError, DOMAIN_VOTE};
use aether_unified::l2crypto::*;
use aether_unified::storage::Storage;

const NET: u64 = 7;

// ------------------------------------------------------------- helpers

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(seed: u8) -> [u8; 32] {
    sk(seed).verifying_key().to_bytes()
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&pk(seed))
}

fn entry(seed: u8, weight: u64) -> RegistryEntry {
    RegistryEntry::new(pk(seed), ValidatorWeight(weight), Admissibility::Eligible)
}

/// Four validators, weight 10 each: total 40, quorum ⌈80/3⌉ = 27.
fn spec() -> &'static [(u8, u64)] {
    &[(1, 10), (2, 10), (3, 10), (4, 10)]
}

fn registry_with(generation: GenerationId, spec: &[(u8, u64)]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = spec.iter().map(|(s, w)| entry(*s, *w)).collect();
    ValidatorRegistry::new(generation, &entries).unwrap()
}

/// A generation record and its registry, asserted to agree on the set root.
///
/// This is the bridge that lets a QC be tied to an existing generation.
fn triple(spec: &[(u8, u64)]) -> (Generation, ValidatorRegistry) {
    let pairs: Vec<(ValidatorId, ValidatorWeight)> = spec
        .iter()
        .map(|(s, w)| (vid(*s), ValidatorWeight(*w)))
        .collect();
    let generation = Generation::new(0, 100, &pairs).unwrap();
    let registry = registry_with(generation.id(), spec);
    assert_eq!(
        registry.set_root(),
        generation.set_root(),
        "registry and generation must agree on the set root"
    );
    (generation, registry)
}

fn make_vote(
    generation: GenerationId,
    height: u64,
    round: u32,
    phase: VotePhase,
    checkpoint_id: [u8; 32],
    seed: u8,
) -> ConsensusVote {
    let vote = ConsensusVote::new(
        NET,
        generation,
        CheckpointHeight(height),
        Round(round),
        phase,
        checkpoint_id,
        vid(seed),
    );
    let sig = sk(seed).sign(&vote.signing_bytes());
    vote.with_signature(sig.to_bytes())
}

fn ckpt() -> [u8; 32] {
    [0xC0; 32]
}

// ================================================================ LOT 3
// Signature verification

#[test]
fn valid_signature_is_accepted_with_registry_weight() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let vote = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);

    let verified = vote.verify(&registry, NET).unwrap();
    assert_eq!(verified.signer, vid(1));
    // Weight comes from the registry, never from the vote.
    assert_eq!(verified.weight, ValidatorWeight(10));
}

#[test]
fn invalid_signature_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let mut vote = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);
    vote.signature[0] ^= 0xFF;
    assert_eq!(
        vote.verify(&registry, NET),
        Err(VoteVerifyError::BadSignature)
    );

    // All-zero signature is rejected too.
    let zeroed = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1).with_signature([0u8; 64]);
    assert_eq!(
        zeroed.verify(&registry, NET),
        Err(VoteVerifyError::BadSignature)
    );
}

#[test]
fn unknown_key_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    // Seed 9 is not registered.
    let vote = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 9);
    assert_eq!(
        vote.verify(&registry, NET),
        Err(VoteVerifyError::UnknownValidator(vid(9)))
    );
}

#[test]
fn usurped_validator_id_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());

    // A valid signature by an unrelated key, presented under validator 1's id.
    let mut vote = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);
    let forged_sig = sk(42).sign(&vote.signing_bytes());
    vote.signature = forged_sig.to_bytes();

    assert_eq!(
        vote.verify(&registry, NET),
        Err(VoteVerifyError::BadSignature),
        "the id alone must never authenticate"
    );
}

#[test]
fn wrong_generation_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let other = make_vote(GenerationId([8u8; 32]), 5, 0, VotePhase::Prevote, ckpt(), 1);
    assert_eq!(
        other.verify(&registry, NET),
        Err(VoteVerifyError::GenerationMismatch)
    );
}

#[test]
fn wrong_network_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let vote = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);
    assert_eq!(vote.verify(&registry, NET + 1), Err(VoteVerifyError::WrongNetwork));
}

#[test]
fn ineligible_validator_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let entries = vec![
        RegistryEntry::new(pk(1), ValidatorWeight(10), Admissibility::Suspended),
        entry(2, 10),
    ];
    let registry = ValidatorRegistry::new(gen, &entries).unwrap();
    let vote = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);
    assert_eq!(
        vote.verify(&registry, NET),
        Err(VoteVerifyError::IneligibleValidator(vid(1)))
    );
}

// ================================================================ LOT 1
// Registry

#[test]
fn registry_rejects_zero_weight() {
    let gen = GenerationId([7u8; 32]);
    let entries = vec![entry(1, 0)];
    assert_eq!(
        ValidatorRegistry::new(gen, &entries),
        Err(RegistryError::ZeroWeight(vid(1)))
    );
}

#[test]
fn registry_rejects_duplicate_identity_and_duplicate_key() {
    let gen = GenerationId([7u8; 32]);

    // Same key twice -> same derived id twice.
    let dup = vec![entry(1, 10), entry(1, 20)];
    assert!(matches!(
        ValidatorRegistry::new(gen, &dup),
        Err(RegistryError::DuplicateValidatorId(_))
    ));

    // Same key under two different ids.
    let mut a = entry(1, 10);
    let mut b = entry(1, 10);
    a.id = vid(1);
    b.id = vid(9);
    assert!(matches!(
        ValidatorRegistry::new(gen, &[a, b]),
        Err(RegistryError::DuplicatePublicKey(_))
    ));
}

#[test]
fn registry_rejects_id_key_mismatch() {
    let gen = GenerationId([7u8; 32]);
    let mut bad = entry(1, 10);
    bad.id = vid(2); // id does not derive from the stored key
    assert!(matches!(
        ValidatorRegistry::new(gen, &[bad]),
        Err(RegistryError::IdKeyMismatch { .. })
    ));
}

#[test]
fn registry_rejects_overflowing_total() {
    let gen = GenerationId([7u8; 32]);
    let half = u64::MAX / 2 + 1;
    let entries = vec![entry(1, half), entry(2, half)];
    assert_eq!(
        ValidatorRegistry::new(gen, &entries),
        Err(RegistryError::TotalWeightOverflow)
    );
}

#[test]
fn registry_root_changes_with_every_voting_factor() {
    let gen = GenerationId([7u8; 32]);
    let base = registry_with(gen, &[(1, 10)]).root();

    // weight
    assert_ne!(base, registry_with(gen, &[(1, 11)]).root());
    // key
    assert_ne!(base, registry_with(gen, &[(2, 10)]).root());
    // generation
    let other_gen = GenerationId([8u8; 32]);
    assert_ne!(base, registry_with(other_gen, &[(1, 10)]).root());
    // admissibility
    let suspended = vec![RegistryEntry::new(
        pk(1),
        ValidatorWeight(10),
        Admissibility::Suspended,
    )];
    let reg = ValidatorRegistry::new(gen, &suspended).unwrap();
    assert_ne!(base, reg.root());
    // ... and suspension also removes weight from the denominator.
    assert_eq!(reg.total_voting_weight(), ValidatorWeight(0));
    assert_eq!(reg.voting_weight(&vid(1)), None);
}

#[test]
fn registry_is_order_independent_and_roundtrips() {
    let gen = GenerationId([7u8; 32]);
    let a = registry_with(gen, &[(1, 10), (2, 20), (3, 30)]);
    let b = registry_with(gen, &[(3, 30), (1, 10), (2, 20)]);
    assert_eq!(a.root(), b.root());
    assert_eq!(a.encode(), b.encode());
    assert_eq!(a.total_voting_weight(), ValidatorWeight(60));
    assert_eq!(a.set_root(), b.set_root());

    let back = ValidatorRegistry::decode(&a.encode()).unwrap();
    assert_eq!(back, a);
    assert_eq!(back.root(), a.root());
}

#[test]
fn registry_decoding_rejects_non_canonical_bytes() {
    let gen = GenerationId([7u8; 32]);
    let reg = registry_with(gen, spec());
    let bytes = reg.encode();

    // Truncated / trailing.
    assert!(ValidatorRegistry::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ValidatorRegistry::decode(&trailing).is_err());

    // Unknown version.
    let mut bad = bytes.clone();
    bad[0] = 99;
    assert_eq!(
        ValidatorRegistry::decode(&bad),
        Err(RegistryError::UnsupportedVersion(99))
    );

    // Unknown admissibility byte: status of the first entry.
    let mut bad_status = bytes.clone();
    bad_status[37 + 72] = 7;
    assert_eq!(
        ValidatorRegistry::decode(&bad_status),
        Err(RegistryError::UnknownAdmissibility(7))
    );

    // Two entries with the same id violate strict ordering.
    let two = registry_with(gen, &[(1, 10), (2, 10)]);
    let mut dup = two.encode();
    let second = 37 + 73;
    let first_id: Vec<u8> = dup[37..37 + 32].to_vec();
    dup[second..second + 32].copy_from_slice(&first_id);
    assert_eq!(
        ValidatorRegistry::decode(&dup),
        Err(RegistryError::NonCanonicalOrder)
    );
}

// ================================================================ LOT 4
// Quorum certificates

#[test]
fn qc_at_exact_quorum_is_accepted() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2, 3]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );

    let verified = qc.verify_with_generation(&registry, &generation, NET).unwrap();
    assert_eq!(verified.support, ValidatorWeight(30));
    assert_eq!(verified.total, ValidatorWeight(40));
    assert_eq!(verified.quorum, quorum_threshold(ValidatorWeight(40)));
    assert!(quorum_met(verified.support, verified.total));
    // `VerifiedQc::signers` is canonical: sorted by id (qc.rs `signers.sort()`),
    // independent of the order the votes were supplied in.
    let mut expected = vec![vid(1), vid(2), vid(3)];
    expected.sort();
    assert_eq!(verified.signers, expected);
}

#[test]
fn qc_below_quorum_is_rejected() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );
    // 20 < 27: the certificate is internally consistent but not quorate.
    assert_eq!(
        qc.verify(&registry, NET),
        Err(QcError::NotQuorate {
            support: 20,
            quorum: 27,
            total: 40
        })
    );
}

#[test]
fn qc_with_falsified_declared_support_is_rejected() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let mut qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );
    // Claim a quorum that the signatures do not support.
    qc.support_weight = ValidatorWeight(40);
    assert_eq!(
        qc.verify(&registry, NET),
        Err(QcError::DeclaredWeightMismatch {
            declared_support: 40,
            declared_total: 40,
            computed_support: 20,
            computed_total: 40
        })
    );
}

#[test]
fn qc_with_falsified_declared_total_is_rejected() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2, 3]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let mut qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );
    // Shrink the denominator to make 30 look quorate against a smaller set.
    qc.total_weight = ValidatorWeight(30);
    assert!(matches!(
        qc.verify(&registry, NET),
        Err(QcError::DeclaredWeightMismatch { .. })
    ));
}

#[test]
fn qc_with_wrong_registry_root_is_rejected() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2, 3]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let mut qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );
    qc.registry_root = [0xAB; 32];
    assert_eq!(qc.verify(&registry, NET), Err(QcError::RegistryRootMismatch));
}

#[test]
fn qc_against_a_modified_registry_is_rejected() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );

    // Same generation id, different weights: the root no longer matches.
    let tampered = registry_with(generation.id(), &[(1, 10), (2, 10), (3, 9), (4, 10)]);
    assert_eq!(
        qc.verify(&tampered, NET),
        Err(QcError::RegistryRootMismatch)
    );
}

#[test]
fn qc_with_duplicate_signer_is_rejected() {
    let (generation, registry) = triple(spec());
    let v1 = make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), 1);
    let v2 = make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), 2);
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        vec![v1, v2, v1], // validator 1 counted twice
    );
    assert_eq!(qc.verify(&registry, NET), Err(QcError::DuplicateSigner(vid(1))));
}

#[test]
fn qc_with_mixed_context_is_rejected() {
    let (generation, registry) = triple(spec());

    // Wrong checkpoint inside the vote set.
    let good = make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), 1);
    let other_ckpt = make_vote(generation.id(), 5, 0, VotePhase::Precommit, [0xD1; 32], 2);
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        vec![good, other_ckpt],
    );
    assert_eq!(qc.verify(&registry, NET), Err(QcError::MixedContext));

    // Wrong round.
    let wrong_round = make_vote(generation.id(), 5, 3, VotePhase::Precommit, ckpt(), 2);
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        vec![good, wrong_round],
    );
    assert_eq!(qc.verify(&registry, NET), Err(QcError::MixedContext));

    // Wrong phase.
    let wrong_phase = make_vote(generation.id(), 5, 0, VotePhase::Prevote, ckpt(), 2);
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        vec![good, wrong_phase],
    );
    assert_eq!(qc.verify(&registry, NET), Err(QcError::MixedContext));

    // Wrong height.
    let wrong_height = make_vote(generation.id(), 6, 0, VotePhase::Precommit, ckpt(), 2);
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        vec![good, wrong_height],
    );
    assert_eq!(qc.verify(&registry, NET), Err(QcError::MixedContext));
}

#[test]
fn empty_qc_is_rejected() {
    let (_generation, registry) = triple(spec());
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        vec![],
    );
    assert_eq!(qc.verify(&registry, NET), Err(QcError::NoVotes));
}

#[test]
fn contradictory_certificates_are_detected() {
    let (generation, registry) = triple(spec());
    let build = |cp: [u8; 32]| {
        let votes: Vec<ConsensusVote> = [1u8, 2, 3]
            .iter()
            .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, cp, *s))
            .collect();
        QuorumCertificate::new(
            NET,
            &registry,
            CheckpointHeight(5),
            Round(0),
            VotePhase::Precommit,
            cp,
            votes,
        )
    };
    let a = build([0x01; 32]);
    let b = build([0x02; 32]);
    assert!(a.conflicts_with(&b));
    assert!(b.conflicts_with(&a));
    assert!(!a.conflicts_with(&a));
}

#[test]
fn qc_encoding_roundtrips_and_is_strict() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2, 3]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );
    let bytes = qc.encode();
    let back = QuorumCertificate::decode(&bytes).unwrap();
    assert_eq!(back, qc);
    assert_eq!(back.id(), qc.id());
    qc.verify(&registry, NET).unwrap();

    // Trailing byte and truncation are rejected.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(QuorumCertificate::decode(&trailing).is_err());
    assert!(QuorumCertificate::decode(&bytes[..bytes.len() - 1]).is_err());

    // Unknown version.
    let mut bad = bytes.clone();
    bad[0] = 42;
    assert_eq!(
        QuorumCertificate::decode(&bad),
        Err(QcError::UnsupportedVersion(42))
    );
}

#[test]
fn qc_requires_a_matching_generation_record() {
    let (generation, registry) = triple(spec());
    let votes: Vec<ConsensusVote> = [1u8, 2, 3]
        .iter()
        .map(|s| make_vote(generation.id(), 5, 0, VotePhase::Precommit, ckpt(), *s))
        .collect();
    let qc = QuorumCertificate::new(
        NET,
        &registry,
        CheckpointHeight(5),
        Round(0),
        VotePhase::Precommit,
        ckpt(),
        votes,
    );
    // A different generation record cannot vouch for this certificate.
    let other_pairs: Vec<(ValidatorId, ValidatorWeight)> =
        vec![(vid(1), ValidatorWeight(10)), (vid(2), ValidatorWeight(10))];
    let other = Generation::new(1, 200, &other_pairs).unwrap();
    assert_eq!(
        qc.verify_with_generation(&registry, &other, NET),
        Err(QcError::GenerationRecordMismatch)
    );
}

// ================================================================ LOT 2
// Vote format

#[test]
fn vote_context_is_cryptographically_bound() {
    let gen = GenerationId([7u8; 32]);
    let base = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);
    let registry = registry_with(gen, spec());

    // Mutating any context field invalidates the signature.
    let mutators: Vec<Box<dyn Fn(&mut ConsensusVote)>> = vec![
        Box::new(|v| v.height = CheckpointHeight(6)),
        Box::new(|v| v.round = Round(1)),
        Box::new(|v| v.phase = VotePhase::Precommit),
        Box::new(|v| v.checkpoint_id = [0xBA; 32]),
        Box::new(|v| v.network = NET + 1),
        Box::new(|v| v.generation = GenerationId([9u8; 32])),
    ];
    for mutate in mutators {
        let mut tampered = base;
        mutate(&mut tampered);
        assert!(
            tampered.verify(&registry, NET).is_err(),
            "a mutated context must not verify"
        );
    }

    // The domain tag is part of the signed message.
    assert!(base.signing_bytes().starts_with(&(DOMAIN_VOTE.len() as u32).to_le_bytes()));
}

#[test]
fn vote_encoding_roundtrips_and_is_strict() {
    let gen = GenerationId([7u8; 32]);
    let vote = make_vote(gen, 5, 2, VotePhase::Precommit, ckpt(), 3);
    let bytes = vote.encode();
    assert_eq!(bytes.len(), VOTE_LEN);
    assert_eq!(ConsensusVote::decode(&bytes).unwrap(), vote);

    assert!(ConsensusVote::decode(&bytes[..VOTE_LEN - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ConsensusVote::decode(&trailing).is_err());

    let mut bad_phase = bytes.clone();
    bad_phase[53] = 9;
    assert_eq!(
        ConsensusVote::decode(&bad_phase),
        Err(VoteError::UnknownPhase(9))
    );

    let mut bad_version = bytes;
    bad_version[0] = 5;
    assert_eq!(
        ConsensusVote::decode(&bad_version),
        Err(VoteError::UnsupportedVersion(5))
    );
}

#[test]
fn frame_has_no_concatenation_ambiguity() {
    let a = frame(b"D", &[&b"ab"[..], &b"c"[..]]);
    let b = frame(b"D", &[&b"a"[..], &b"bc"[..]]);
    assert_ne!(a, b);
    assert_ne!(
        frame(b"D", &[&b"x"[..]]),
        frame(b"E", &[&b"x"[..]])
    );
    assert_eq!(frame(b"D", &[&b"x"[..]]), frame(b"D", &[&b"x"[..]]));
}

// ================================================================ LOT 5
// Authenticated READY

fn ready_expectation(generation: GenerationId, registry: &ValidatorRegistry) -> SignedReadyExpectation {
    SignedReadyExpectation {
        network: NET,
        generation,
        candidate: [0xC1; 32],
        new_set_root: registry.set_root(),
        reference_checkpoint: [0xCC; 32],
        h_close: CheckpointHeight(10),
        d_ready: 6,
    }
}

fn make_ready(
    exp: &SignedReadyExpectation,
    seed: u8,
    h_ready: u64,
    sequence: u64,
) -> SignedReady {
    let ready = SignedReady::new(
        exp.network,
        exp.generation,
        exp.candidate,
        exp.new_set_root,
        exp.reference_checkpoint,
        CheckpointHeight(h_ready),
        sequence,
        vid(seed),
    );
    let sig = sk(seed).sign(&ready.signing_bytes());
    ready.with_signature(sig.to_bytes())
}

#[test]
fn signed_ready_authenticates_and_uses_registry_weight() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);

    let attestations: Vec<SignedReady> = [1u8, 2, 3]
        .iter()
        .map(|s| make_ready(&exp, *s, 9, 1))
        .collect();

    let outcome = evaluate_signed(&attestations, &exp, &registry);
    assert!(outcome.reached);
    assert_eq!(outcome.weight, ValidatorWeight(30));
    assert_eq!(outcome.distinct_signers, 3);
    assert!(outcome.rejected.is_empty());
}

#[test]
fn ready_for_another_candidate_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);

    let mut wrong = make_ready(&exp, 1, 9, 1);
    wrong.candidate = [0xD9; 32];
    let sig = sk(1).sign(&wrong.signing_bytes());
    wrong.signature = sig.to_bytes();

    let outcome = evaluate_signed(&[wrong], &exp, &registry);
    assert!(!outcome.reached);
    assert_eq!(
        outcome.rejected,
        vec![(vid(1), ReadyReject::WrongCandidate)]
    );
}

#[test]
fn expired_ready_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry); // h_close = 10, d_ready = 6

    let fresh = make_ready(&exp, 1, 4, 1); // 10 - 4 = 6, boundary, accepted
    let stale = make_ready(&exp, 2, 3, 1); // 10 - 3 = 7 > 6, rejected
    let future = make_ready(&exp, 3, 11, 1);

    let outcome = evaluate_signed(&[fresh, stale, future], &exp, &registry);
    assert_eq!(outcome.accepted, vec![vid(1)]);
    assert!(outcome.rejected.contains(&(vid(2), ReadyReject::Stale)));
    assert!(outcome
        .rejected
        .contains(&(vid(3), ReadyReject::FutureHeight)));
}

#[test]
fn ready_from_a_non_member_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);
    let outsider = make_ready(&exp, 9, 9, 1);
    let outcome = evaluate_signed(&[outsider], &exp, &registry);
    assert!(!outcome.reached);
    assert_eq!(outcome.rejected, vec![(vid(9), ReadyReject::NonMember)]);
}

#[test]
fn ready_with_a_foreign_signature_is_rejected() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);

    // Claim validator 1's id, sign with another key.
    let mut forged = make_ready(&exp, 1, 9, 1);
    let sig = sk(77).sign(&forged.signing_bytes());
    forged.signature = sig.to_bytes();

    let outcome = evaluate_signed(&[forged], &exp, &registry);
    assert!(!outcome.reached);
    assert_eq!(outcome.rejected, vec![(vid(1), ReadyReject::BadSignature)]);
}

#[test]
fn ready_deduplicates_and_keeps_highest_sequence() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);

    let one = make_ready(&exp, 1, 9, 1);
    let two = make_ready(&exp, 1, 9, 2);
    let outcome = evaluate_signed(&[one, two], &exp, &registry);
    assert_eq!(outcome.distinct_signers, 1);
    assert_eq!(outcome.weight, ValidatorWeight(10));
    assert!(!outcome.reached);
}

#[test]
fn ready_is_not_a_liveness_proof() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);

    let all: Vec<SignedReady> = [1u8, 2, 3, 4]
        .iter()
        .map(|s| make_ready(&exp, *s, 10, 1))
        .collect();
    let outcome = evaluate_signed(&all, &exp, &registry);

    assert!(outcome.reached);
    assert_eq!(outcome.weight, ValidatorWeight(40));
    // ... and yet the actual liveness condition — observed online weight — is
    // still zero. No signature establishes availability.
    assert!(!quorum_met(ValidatorWeight(0), registry.total_voting_weight()));
    assert!(outcome.is_past_intent_only());
}

#[test]
fn signed_ready_encoding_roundtrips() {
    let gen = GenerationId([7u8; 32]);
    let registry = registry_with(gen, spec());
    let exp = ready_expectation(gen, &registry);
    let ready = make_ready(&exp, 1, 9, 3);

    let bytes = ready.encode();
    assert_eq!(bytes.len(), SIGNED_READY_LEN);
    assert_eq!(SignedReady::decode(&bytes).unwrap(), ready);
    assert!(SignedReady::decode(&bytes[..SIGNED_READY_LEN - 1]).is_err());

    let mut bad = bytes;
    bad[0] = 3;
    assert_eq!(
        SignedReady::decode(&bad),
        Err(SignedReadyError::UnsupportedVersion(3))
    );
    // The magnitude of replay protection: changing any field changes the
    // signed bytes.
    let mut changed = ready;
    changed.sequence = 4;
    assert_ne!(changed.signing_bytes(), ready.signing_bytes());
}

// ================================================================ LOT 6
// Slots and equivocation

#[test]
fn contradictory_double_vote_is_detected_and_evidence_kept() {
    let gen = GenerationId([7u8; 32]);
    let store = MemoryLockStore::new();

    let a = make_vote(gen, 5, 0, VotePhase::Prevote, [0x01; 32], 1);
    assert_eq!(commit_vote(&a, &store).unwrap(), SlotOutcome::Fresh);

    // Same vote again: idempotent.
    assert_eq!(commit_vote(&a, &store).unwrap(), SlotOutcome::Duplicate);

    // Different checkpoint, same slot: equivocation.
    let b = make_vote(gen, 5, 0, VotePhase::Prevote, [0x02; 32], 1);
    match commit_vote(&b, &store).unwrap() {
        SlotOutcome::Equivocation { existing } => {
            assert_eq!(existing.checkpoint_id, [0x01; 32]);
            assert_eq!(existing.vote_id, a.id());
        }
        other => panic!("expected equivocation, got {:?}", other),
    }

    // The first commitment was not overwritten.
    assert_eq!(store.len(), 1);
    let reloaded = store.load(&a.slot_id()).unwrap().unwrap();
    assert_eq!(reloaded.checkpoint_id, [0x01; 32]);
}

#[test]
fn distinct_slots_do_not_collide() {
    let gen = GenerationId([7u8; 32]);
    let store = MemoryLockStore::new();

    let base = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 1);
    let other_round = make_vote(gen, 5, 1, VotePhase::Prevote, ckpt(), 1);
    let other_phase = make_vote(gen, 5, 0, VotePhase::Precommit, ckpt(), 1);
    let other_validator = make_vote(gen, 5, 0, VotePhase::Prevote, ckpt(), 2);

    assert_ne!(base.slot_id(), other_round.slot_id());
    assert_ne!(base.slot_id(), other_phase.slot_id());
    assert_ne!(base.slot_id(), other_validator.slot_id());

    for vote in [base, other_round, other_phase, other_validator] {
        assert_eq!(commit_vote(&vote, &store).unwrap(), SlotOutcome::Fresh);
    }
    assert_eq!(store.len(), 4);
}

#[test]
fn durable_slot_store_survives_restart_and_detects_equivocation() {
    let dir = tempfile::tempdir().unwrap();
    let gen = GenerationId([7u8; 32]);
    let a = make_vote(gen, 5, 0, VotePhase::Precommit, [0x0A; 32], 1);
    let b = make_vote(gen, 5, 0, VotePhase::Precommit, [0x0B; 32], 1);

    {
        let storage = Storage::open(dir.path()).unwrap();
        let store = StorageLockStore::new(&storage);
        assert_eq!(commit_vote(&a, &store).unwrap(), SlotOutcome::Fresh);
        // Same-process equivocation is caught.
        assert!(matches!(
            commit_vote(&b, &store).unwrap(),
            SlotOutcome::Equivocation { .. }
        ));
    }

    // Reopen: the commitment survived, so the equivocation is still detectable
    // after a restart.
    let storage = Storage::open(dir.path()).unwrap();
    let store = StorageLockStore::new(&storage);
    let reloaded = store.load(&a.slot_id()).unwrap().unwrap();
    assert_eq!(reloaded.checkpoint_id, [0x0A; 32]);
    assert!(matches!(
        commit_vote(&b, &store).unwrap(),
        SlotOutcome::Equivocation { .. }
    ));
}

#[test]
fn withdrawn_vote_slot_returns_fresh_for_another_validator() {
    let gen = GenerationId([7u8; 32]);
    let store = MemoryLockStore::new();
    let a = make_vote(gen, 5, 0, VotePhase::Prevote, [0x01; 32], 1);
    let b = make_vote(gen, 5, 0, VotePhase::Prevote, [0x02; 32], 2);
    assert_eq!(commit_vote(&a, &store).unwrap(), SlotOutcome::Fresh);
    // Validator 2 is a different slot: no conflict with validator 1.
    assert_eq!(commit_vote(&b, &store).unwrap(), SlotOutcome::Fresh);
}
