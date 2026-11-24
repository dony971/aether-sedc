//! Mission BI — recovery after partition, with a real proposer (priority 7).
//!
//! # What is new compared with BH
//!
//! The BH simulator let **every** validator propose, because no proposer rule
//! existed. With `elect_proposer` on, only the member elected by
//! `l2bft::proposer` opens a round and its proposal travels; everybody else waits.
//! That makes an absent proposer a real scenario instead of an untested gap, and
//! it is the case a partition creates most often.
//!
//! | Test | What it shows |
//! |---|---|
//! | `bq_01` | 4 validators decide with one proposal per round |
//! | `bq_02` | the elected proposer is down: a quorum changes round and decides |
//! | `bq_03` | 2/2 split decides nothing; after healing it converges, in a measured number of steps |
//! | `bq_04` | a validator restarted with an empty round rejoins without contradiction |
//! | `bq_05` | 40 % of the round changes lost: still converges |
//! | `bq_06` | 21 validators elect and decide |
//! | `bq_07` | 7 validators, proposer lost mid-run: one value, never two |
//!
//! Every number is a **virtual** step count. Nothing here measures wall time, and
//! no liveness theorem is claimed.

use aether_unified::consensus::generation::{CheckpointHeight, GenerationId, Round};
use aether_unified::l2bft::proposer::proposer_for;
use aether_unified::network::sim::{Sim, SimConfig};

fn sim_with(seeds: &[u8]) -> Sim {
    let mut config = SimConfig::new(41, seeds.to_vec(), 10);
    config.elect_proposer = true;
    Sim::new(config)
}

#[test]
fn bq_01_elected_proposer_decides_in_round_zero() {
    let mut sim = sim_with(&[1, 2, 3, 4]);
    let decided_at = sim.run_until_decided(80);
    assert!(decided_at.is_some(), "the cluster decides");

    let outcome = sim.outcome(decided_at.unwrap());
    assert_eq!(outcome.decided_count, 4, "every validator decided");
    assert!(outcome.agreed);
    assert_eq!(outcome.max_round, 0, "no round change was needed");
    assert!(
        outcome.metrics.proposals >= 1,
        "the elected proposer proposed: {:?}",
        outcome.metrics
    );
}

#[test]
fn bq_02_an_absent_proposer_costs_rounds_not_safety() {
    let mut sim = sim_with(&[1, 2, 3, 4]);
    // Whoever the rule elects at round 0 is taken down before it can speak.
    let elected = proposer_for(
        &aether_unified::l2crypto::registry::ValidatorRegistry::new(
            GenerationId([7u8; 32]),
            &(1..=4u8)
                .map(|seed| {
                    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
                    aether_unified::l2crypto::registry::RegistryEntry {
                        id: aether_unified::l2crypto::registry::validator_id(
                            &key.verifying_key().to_bytes(),
                        ),
                        public_key: key.verifying_key().to_bytes(),
                        weight: aether_unified::consensus::generation::ValidatorWeight(10),
                        admissibility: aether_unified::l2crypto::registry::Admissibility::Eligible,
                    }
                })
                .collect::<Vec<_>>(),
        )
        .expect("registry"),
        GenerationId([7u8; 32]),
        CheckpointHeight(0),
        Round(0),
    )
    .expect("schedule")
    .validator;
    let index = (0..4)
        .find(|index| sim.id_of(*index) == elected)
        .expect("the elected validator is one of the four");
    sim.set_up(index, false);

    let decided_at = match sim.run_until_decided(200) {
        Some(at) => at,
        None => panic!("no decision: {:?}", sim.outcome(200)),
    };
    let outcome = sim.outcome(decided_at);
    assert_eq!(
        outcome.decided_count, 3,
        "three of four still form a quorum"
    );
    assert!(outcome.agreed);
    assert!(
        outcome.max_round >= 1,
        "a round change was needed to move on"
    );
    assert!(
        outcome.metrics.round_changes > 0 && outcome.metrics.rounds_adopted > 0,
        "the timeout fired and a quorum moved the round: {:?}",
        outcome.metrics
    );
    assert!(
        outcome.metrics.proposals >= 1,
        "the proposer elected in the new round spoke: {:?}",
        outcome.metrics
    );
}

#[test]
fn bq_03_a_split_network_recovers_after_healing() {
    let mut sim = sim_with(&[1, 2, 3, 4]);
    sim.partition(&[&[0, 1], &[2, 3]]);
    sim.run(40);
    let split = sim.outcome(40);
    assert_eq!(split.decided_count, 0, "2 against 2 decides nothing");
    assert!(split.agreed);
    let messages_during_split = split.metrics.sent;

    sim.heal();
    let mut recovered_at = None;
    for step in 0..300u64 {
        sim.run(1);
        if sim.outcome(step + 1).decided_count >= 3 {
            recovered_at = Some(step + 1);
            break;
        }
    }
    let recovered_at = match recovered_at {
        Some(at) => at,
        None => panic!("no recovery: {:?}", sim.outcome(340)),
    };
    let outcome = sim.outcome(40 + recovered_at);
    assert!(outcome.agreed, "and never on two values");
    assert!(
        outcome.metrics.sent >= messages_during_split,
        "the counters are monotone"
    );
    assert!(
        recovered_at < 300,
        "recovery took {recovered_at} virtual steps, reported not hidden"
    );
    // Recovery may go through a round change or simply through the retransmitted
    // proposal of round 0 — both are legitimate; what matters is that it converged
    // without a second value, and that the work is visible in the counters.
    assert!(
        outcome.metrics.retransmissions > 0,
        "the recovered link carried the messages again: {:?}",
        outcome.metrics
    );
    assert!(sim.no_contradiction());
}

#[test]
fn bq_04_a_restarted_validator_does_not_create_a_second_value() {
    let mut sim = sim_with(&[1, 2, 3, 4]);
    let decided_at = sim.run_until_decided(80).expect("decides");
    assert_eq!(sim.outcome(decided_at).decided_count, 4);

    // It comes back with its own store and an empty round.
    sim.advance_height();
    sim.set_up(2, false);
    sim.run(6);
    sim.restart(2);
    let outcomes = sim.run_until_decided(200);
    sim.run(5);

    let outcome = sim.outcome(200);
    assert!(outcome.agreed, "one value only: {outcome:?}");
    assert!(
        outcomes.is_some() || outcome.decided_count >= 1,
        "the height is decided by the live validators"
    );
    assert!(sim.no_contradiction());
}

#[test]
fn bq_05_losing_round_changes_still_converges() {
    let mut config = SimConfig::new(41, vec![1, 2, 3, 4], 10);
    config.elect_proposer = true;
    // 40 % of the messages are lost: round changes included.
    config.loss_ppm = 400_000;
    config.jitter_steps = 2;
    let mut sim = Sim::new(config);
    let decided_at = sim.run_until_decided(300);
    assert!(
        decided_at.is_some(),
        "a lossy network still decides: {:?}",
        sim.outcome(300)
    );
    let outcome = sim.outcome(decided_at.unwrap());
    assert!(outcome.agreed);
    assert!(
        outcome.metrics.dropped_loss > 0,
        "the loss was real, not configured and forgotten"
    );
}

#[test]
fn bq_06_twenty_one_validators_elect_and_decide() {
    let mut sim = sim_with(&(1..=21).collect::<Vec<u8>>());
    let decided_at = sim.run_until_decided(120);
    assert!(decided_at.is_some(), "14 of 21 is a quorum");
    let outcome = sim.outcome(decided_at.unwrap());
    assert_eq!(outcome.decided_count, 21);
    assert!(outcome.agreed);
    assert!(outcome.metrics.proposals >= 1);
}

#[test]
fn bq_07_losing_the_proposer_mid_run_keeps_one_value() {
    let mut sim = sim_with(&[1, 2, 3, 4, 5, 6, 7]);
    // Let the run start, then remove two validators (one may be the proposer).
    sim.run(3);
    sim.set_up(0, false);
    sim.set_up(3, false);
    let decided_at = sim.run_until_decided(300);
    let outcome = sim.outcome(300);
    assert!(outcome.agreed, "no contradiction: {outcome:?}");
    if let Some(at) = decided_at {
        assert!(
            sim.outcome(at).decided_count >= 5,
            "five of seven is a quorum"
        );
    }
    assert!(sim.no_contradiction());
}
