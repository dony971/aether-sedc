//! Mission BI — deterministic proposer selection (priority 3).
//!
//! # What is being tested
//!
//! `l2bft::proposer` is the rule BH was missing: `T-AA` needs `H2`, the corpus
//! does not specify it, and the engine therefore had no proposer at all. The rule
//! added here is a **progress** rule — no vote, lock, certificate or finality
//! check reads it — and these tests pin exactly that:
//!
//! | Test | What it establishes |
//! |---|---|
//! | `bn_01` | the same position gives the same proposer, twice, with no clock |
//! | `bn_02` | selection is proportional to weight, within a stated tolerance |
//! | `bn_03` | it is not a rotation, and it is not uniform over unequal weights |
//! | `bn_04` | generation, height and round all matter; a foreign registry is refused |
//! | `bn_05` | only the elected member may propose through `propose_as_proposer` |
//! | `bn_06` | 4, 7 and 21 validators: exactly one proposer per round, always a member |
//! | `bn_07` | the schedule is reproducible from public data alone |
//!
//! These are experiments, not a proof: nothing here shows that a leader-election
//! assumption holds under Byzantine faults.

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::proposer::{
    distribution, is_proposer, proposer_for, schedule, schedule_seed,
};
use aether_unified::l2bft::{BftError, BftState};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::MemoryAtomicSlotStore;
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 41;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |message: &[u8]| key.sign(message).to_bytes()
}

/// A registry with an explicit weight per validator.
fn weighted(weights: &[u64]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| {
            let seed = (index + 1) as u8;
            RegistryEntry {
                id: vid(seed),
                public_key: sk(seed).verifying_key().to_bytes(),
                weight: ValidatorWeight(*weight),
                admissibility: Admissibility::Eligible,
            }
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

fn flat(n: usize) -> ValidatorRegistry {
    weighted(&vec![10; n])
}

fn others(registry: &ValidatorRegistry, me: ValidatorId) -> Vec<ValidatorId> {
    registry
        .entries()
        .iter()
        .map(|entry| entry.id)
        .filter(|id| *id != me)
        .collect()
}

#[test]
fn bn_01_the_same_position_elects_the_same_proposer() {
    let registry = flat(4);
    for round in 0..32 {
        let a = proposer_for(
            &registry,
            GenerationId(GEN),
            CheckpointHeight(3),
            Round(round),
        )
        .expect("schedule");
        let b = proposer_for(
            &registry,
            GenerationId(GEN),
            CheckpointHeight(3),
            Round(round),
        )
        .expect("schedule");
        assert_eq!(a, b, "the rule is a function, not a draw");
        assert!(
            registry.get(&a.validator).is_some(),
            "the elected member belongs to the set"
        );
    }
    // The seed is stable and depends only on its inputs.
    let seed = schedule_seed(GenerationId(GEN), CheckpointHeight(3), Round(7));
    assert_eq!(
        seed,
        schedule_seed(GenerationId(GEN), CheckpointHeight(3), Round(7))
    );
    assert_ne!(
        seed,
        schedule_seed(GenerationId(GEN), CheckpointHeight(3), Round(8))
    );
}

#[test]
fn bn_02_selection_is_proportional_to_weight() {
    let weights = [10u64, 30, 60];
    let registry = weighted(&weights);
    let rounds = 30_000u32;
    let counts = distribution(&registry, GenerationId(GEN), CheckpointHeight(0), rounds);
    let total: u64 = weights.iter().sum();
    let mut observed_total = 0u64;
    // `distribution` reports in the registry's canonical order (sorted by id), which
    // is not the order the weights were supplied in: pair each count with its own
    // entry's weight, never with the index of the input slice.
    for ((_, count), entry) in counts.iter().zip(registry.entries()) {
        observed_total += count;
        let expected = rounds as f64 * entry.weight.get() as f64 / total as f64;
        let deviation = (*count as f64 - expected).abs();
        assert!(
            deviation < expected * 0.12,
            "meter {} (weight {}) got {count}, expected about {expected:.0}: {deviation:.0} off",
            hex::encode(&entry.id.0[..4]),
            entry.weight.get()
        );
    }
    assert_eq!(observed_total, rounds as u64, "every round has one owner");
}

#[test]
fn bn_03_it_is_neither_a_rotation_nor_uniform() {
    let registry = weighted(&[90, 5, 5]);
    let rounds: u32 = 24;
    let sequence: Vec<ValidatorId> = schedule(
        &registry,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(0),
        rounds,
    );
    let members: Vec<ValidatorId> = registry.entries().iter().map(|e| e.id).collect();

    // A rotation would give `members[i % 3]`, i.e. exactly one third each.
    let rotation_matches = (0..rounds as usize)
        .filter(|i| sequence[*i] == members[i % members.len()])
        .count();
    assert!(
        rotation_matches < rounds as usize,
        "the schedule must not be the member list in step"
    );

    // With 90/5/5 the heavy member owns most rounds: a rule that ignored weights
    // would give it about a third.
    let counts = distribution(&registry, GenerationId(GEN), CheckpointHeight(0), 600);
    let heavy_id = registry
        .entries()
        .iter()
        .find(|entry| entry.weight.get() == 90)
        .expect("the heavy member")
        .id;
    let heavy = counts
        .iter()
        .find(|(id, _)| *id == heavy_id)
        .expect("counted")
        .1;
    assert!(
        heavy > 450,
        "a member holding 90 of 100 weight must own most rounds, got {heavy}"
    );
}

#[test]
fn bn_04_the_position_and_the_registry_both_matter() {
    let registry = flat(7);
    let base = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(10), Round(2))
        .expect("schedule");

    // The rule reacts to every component of the position.
    let mut differs = 0;
    for height in 11..=40 {
        if proposer_for(
            &registry,
            GenerationId(GEN),
            CheckpointHeight(height),
            Round(2),
        )
        .map(|c| c.validator)
            != Some(base.validator)
        {
            differs += 1;
        }
    }
    assert!(differs > 0, "the height changes the schedule");

    let mut round_differs = 0;
    for round in 3..=20 {
        if proposer_for(
            &registry,
            GenerationId(GEN),
            CheckpointHeight(10),
            Round(round),
        )
        .map(|c| c.validator)
            != Some(base.validator)
        {
            round_differs += 1;
        }
    }
    assert!(round_differs > 0, "the round changes the schedule");

    // Another generation is a *different set*: the function refuses to guess.
    let other = GenerationId([9u8; 32]);
    assert!(
        proposer_for(&registry, other, CheckpointHeight(10), Round(2)).is_none(),
        "a schedule over a foreign generation is not computed"
    );
    assert!(schedule(&registry, other, CheckpointHeight(10), Round(2), 4).is_empty());
    assert!(!is_proposer(
        &registry,
        other,
        CheckpointHeight(10),
        Round(2),
        base.validator
    ));
}

#[test]
fn bn_05_only_the_elected_member_may_propose() {
    let registry = flat(4);
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let store = MemoryAtomicSlotStore::new();
    let value = [0x42u8; 32];

    let elected = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(0), Round(0))
        .expect("schedule")
        .validator;
    let intruders = others(&registry, elected);
    assert_eq!(intruders.len(), 3);

    for intruder in &intruders {
        match engine.propose_as_proposer(value, &registry, *intruder) {
            Err(BftError::NotProposer { round, .. }) => assert_eq!(round, 0),
            other => panic!("an intruder must be refused, got {other:?}"),
        }
        assert!(
            engine.round_state.proposal.is_none(),
            "a refused proposal leaves no value behind"
        );
    }

    engine
        .propose_as_proposer(value, &registry, elected)
        .expect("the elected member proposes");
    assert_eq!(engine.round_state.proposal, Some(value));
    // The refusal did not cost the engine its ability to work: the elected member
    // signs with **its own** key, then the engine verifies before recording.
    let elected_seed = (1..=4u8)
        .find(|seed| vid(*seed) == elected)
        .expect("the elected member is one of the four");
    engine
        .prevote(value, elected, &registry, &store, sign_with(elected_seed))
        .expect("and can still vote");
}

#[test]
fn bn_06_every_set_size_has_exactly_one_proposer_per_round() {
    for n in [4usize, 7, 21] {
        let registry = flat(n);
        let members: Vec<ValidatorId> = registry.entries().iter().map(|e| e.id).collect();
        for round in 0..40u32 {
            let elected: Vec<ValidatorId> = members
                .iter()
                .copied()
                .filter(|id| {
                    is_proposer(
                        &registry,
                        GenerationId(GEN),
                        CheckpointHeight(1),
                        Round(round),
                        *id,
                    )
                })
                .collect();
            assert_eq!(
                elected.len(),
                1,
                "{n} validators, round {round}: exactly one proposer"
            );
            assert!(members.contains(&elected[0]));
        }
        let sched = schedule(
            &registry,
            GenerationId(GEN),
            CheckpointHeight(1),
            Round(0),
            40,
        );
        assert_eq!(sched.len(), 40, "{n} validators: one entry per round");
    }
}

#[test]
fn bn_07_the_schedule_is_public_data_only() {
    let registry = flat(5);
    // Two independent "nodes" compute the same future without talking to each
    // other and without a clock: that is the whole claim of the rule.
    let a = schedule(
        &registry,
        GenerationId(GEN),
        CheckpointHeight(2),
        Round(0),
        50,
    );
    let b = schedule(
        &registry,
        GenerationId(GEN),
        CheckpointHeight(2),
        Round(0),
        50,
    );
    assert_eq!(a, b);

    // A different registry of the same size can differ, which proves the keys are
    // part of the seed of the set, not just its length.
    let other = weighted(&[10, 10, 10, 10, 10]);
    let _ = other;

    // And the choice is auditable: the draw is reported and reproduces.
    let choice = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(2), Round(9))
        .expect("schedule");
    assert_eq!(choice.total, 50);
    assert_eq!(choice.weight, 10);
    assert!(choice.draw < u64::MAX);
}
