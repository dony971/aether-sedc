//! Mission BH — deterministic network simulator (priority 4).
//!
//! Every test here builds a [`Sim`], which advances a **virtual** step counter and
//! moves real `BftState` messages through a queue. Nothing reads a clock, so a run
//! is reproducible: the same configuration produces the same counters.
//!
//! | Test | Setup | Expected |
//! |---|---|---|
//! | `bj_01` | 4 validators, no faults | decision, no contradiction |
//! | `bj_02` | 4 validators, 2 vs 2 | **stalls**, then decides after healing |
//! | `bj_03` | 4 validators, 3 vs 1 | the majority decides alone |
//! | `bj_04` | 5 validators, 3 vs 2 | stalls (3 < quorum 4), heals |
//! | `bj_05` | 7 validators, 5 vs 2 | the majority decides (50 ≥ 47) |
//! | `bj_06` | 21 validators, 14 vs 7 | decides; 13 vs 8 would not |
//! | `bj_07` | 5 validators, 8 % loss + duplication | still decides, counters prove the faults |
//! | `bj_08` | 4 validators, four singleton partitions | no decision at all, ever |
//!
//! The simulator states no liveness theorem: a run that decides is an observation
//! of that run. What it can show — and does — is that a minority partition never
//! decides and that no two validators ever decide differently.

use aether_unified::network::sim::{seeds, Sim, SimConfig};

fn sim(n: usize) -> Sim {
    Sim::new(SimConfig::new(41, seeds(n), 10).with_seed(0xB0B0_0001))
}

#[test]
fn bj_01_four_validators_decide_without_faults() {
    let mut sim = sim(4);
    let decided_at = sim.run_until_decided(60);
    let outcome = sim.outcome(60);
    assert!(decided_at.is_some(), "the cluster must decide: {outcome:?}");
    assert_eq!(outcome.decided_count, 4, "every validator decided");
    assert!(outcome.agreed, "no two validators decided differently");
    assert_eq!(outcome.max_round, 0, "no round change was needed");
    assert!(outcome.metrics.delivered > 0);
    assert_eq!(outcome.metrics.dropped_loss, 0);
    assert_eq!(outcome.metrics.round_changes, 0);
}

#[test]
fn bj_02_split_two_against_two_stalls_then_recovers() {
    let mut sim = sim(4);
    sim.partition(&[&[0, 1], &[2, 3]]);
    sim.run(40);
    let stalled = sim.outcome(40);
    assert_eq!(
        stalled.decided_count, 0,
        "2 of 4 is below the quorum of 3, so nothing can be decided: {stalled:?}"
    );
    assert!(stalled.agreed);
    assert!(
        stalled.metrics.dropped_partition > 0,
        "cross-partition traffic was dropped"
    );
    assert!(
        stalled.metrics.round_changes > 0,
        "the timers fired while the network was split, which is what a round change is for"
    );
    assert_eq!(
        stalled.max_round, 0,
        "and it cannot even adopt a round change: 2 of 4 is not a quorum for that either"
    );

    sim.heal();
    let recovered = sim.run_until_decided(200);
    sim.run(5);
    let outcome = sim.outcome(205);
    assert!(
        recovered.is_some(),
        "after healing the four validators must converge: {outcome:?}"
    );
    assert_eq!(outcome.decided_count, 4);
    assert!(outcome.agreed);
}

#[test]
fn bj_03_three_against_one_lets_the_majority_decide() {
    let mut sim = sim(4);
    sim.partition(&[&[0, 1, 2], &[3]]);
    let decided_at = sim.run_until_decided(120);
    let outcome = sim.outcome(120);
    assert!(
        decided_at.is_some(),
        "3 of 4 is a quorum, so the majority must decide: {outcome:?}"
    );
    assert_eq!(outcome.decided_count, 3, "only the majority decided");
    let values = sim.decided_values();
    assert!(values[0].is_some() && values[1].is_some() && values[2].is_some());
    assert_eq!(
        values[3], None,
        "the isolated validator cannot decide alone, and must not pretend to"
    );
    assert!(outcome.agreed);
}

#[test]
fn bj_04_five_validators_need_four() {
    let mut sim = sim(5);
    sim.partition(&[&[0, 1, 2], &[3, 4]]);
    sim.run(60);
    assert_eq!(
        sim.outcome(60).decided_count,
        0,
        "3 of 5 is below the quorum of 4"
    );

    sim.heal();
    let outcome = {
        let decided_at = sim.run_until_decided(200);
        assert!(decided_at.is_some(), "healing must let the cluster decide");
        sim.outcome(200)
    };
    assert_eq!(outcome.decided_count, 5);
    assert!(outcome.agreed);
}

#[test]
fn bj_05_seven_validators_majority_of_five_decides() {
    let mut sim = sim(7);
    sim.partition(&[&[0, 1, 2, 3, 4], &[5, 6]]);
    let decided_at = sim.run_until_decided(200);
    let outcome = sim.outcome(200);
    assert!(
        decided_at.is_some(),
        "5 of 7 carries a quorum of 47/70: {outcome:?}"
    );
    assert_eq!(outcome.decided_count, 5);
    assert!(outcome.agreed);
}

#[test]
fn bj_06_twenty_one_validators_split_fourteen_seven() {
    let mut sim = sim(21);
    sim.partition(&[&(0..14).collect::<Vec<_>>(), &[14, 15, 16, 17, 18, 19, 20]]);
    let decided_at = sim.run_until_decided(300);
    let outcome = sim.outcome(300);
    assert!(
        decided_at.is_some(),
        "14 of 21 is a quorum (140/210): {outcome:?}"
    );
    assert_eq!(outcome.decided_count, 14);
    assert!(outcome.agreed);
}

#[test]
fn bj_07_loss_and_duplication_do_not_break_agreement() {
    let mut sim = Sim::new(
        SimConfig::new(41, seeds(5), 10)
            .with_seed(0xD15E_A5E5)
            .with_latency(2, 3)
            .with_faults(80_000, 20_000),
    );
    let decided_at = sim.run_until_decided(400);
    let outcome = sim.outcome(400);
    assert!(
        decided_at.is_some(),
        "8 % loss and 2 % duplication must delay, not prevent: {outcome:?}"
    );
    assert!(outcome.agreed, "no contradictory finality");
    assert!(
        outcome.metrics.dropped_loss > 0,
        "the loss actually happened: {outcome:?}"
    );
    assert!(
        outcome.metrics.duplicated > 0,
        "the duplication actually happened: {outcome:?}"
    );
    assert!(outcome.metrics.reordered > 0, "jitter reorders deliveries");
}

#[test]
fn bj_08_four_isolated_validators_never_decide() {
    let mut sim = sim(4);
    sim.partition(&[&[0], &[1], &[2], &[3]]);
    sim.run(150);
    let outcome = sim.outcome(150);
    assert_eq!(
        outcome.decided_count, 0,
        "no partition holds a quorum, so nothing is decided however long it runs"
    );
    assert!(outcome.agreed, "and nobody decides contradictorily");
    assert!(
        outcome.metrics.round_changes > 0,
        "the timers kept firing even though nothing can be decided"
    );
    assert_eq!(
        outcome.max_round, 0,
        "no isolation group can collect enough changes to enter a new round"
    );
}

#[test]
fn bj_09_a_stopped_validator_does_not_stop_the_quorum() {
    let mut sim = sim(7);
    sim.set_up(6, false);
    for index in 0..6 {
        sim.set_up(index, true);
    }
    let decided_at = sim.run_until_decided(300);
    let outcome = sim.outcome(300);
    assert!(
        decided_at.is_some(),
        "6 of 7 still votes, so the cluster decides: {outcome:?}"
    );
    assert_eq!(
        outcome.decided_count, 6,
        "the stopped validator decided nothing"
    );
    assert!(outcome.agreed);
}

#[test]
fn bj_10_a_restarted_validator_recovers_its_own_store_and_can_sign() {
    let mut sim = sim(4);
    sim.run_until_decided(80);
    sim.run(3);
    assert_eq!(sim.outcome(90).decided_count, 4);

    sim.advance_height();
    sim.set_up(1, false);
    sim.run(5);
    sim.restart(1);

    // The recovered engine stands at the current height, is not halted and may
    // sign: that is what `restore_engine` has to produce, and it is what the
    // persistent-restart tests check on real files.
    assert_eq!(sim.engines[1].height, sim.height);
    assert!(!sim.engines[1].is_halted());
    assert!(
        sim.engines[1].may_sign().is_ok(),
        "a restarted validator must be able to sign again: {:?}",
        sim.engines[1].persisted().status
    );

    // It does **not** catch up on its own: the simulator's driver stops a validator
    // once it has decided, and there is no pull-sync in this model (the sync path is
    // covered by `phase4bl`). So the three that decided first stay the only ones,
    // and nobody ever decides a second, different value.
    let decided_at = sim.run_until_decided(200);
    sim.run(5);
    let outcome = sim.outcome(205);
    assert!(
        decided_at.is_some(),
        "the height is still decided by the others: {outcome:?}"
    );
    assert_eq!(outcome.decided_count, 3);
    assert!(outcome.agreed, "and never contradicted");
}
