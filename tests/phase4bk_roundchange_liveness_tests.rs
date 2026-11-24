//! Mission BH — automatic round change (priority 5).
//!
//! # The finding this file is built on
//!
//! BG proved a `RoundChange` **travels** and is **verified**. It could not show one
//! being *emitted*: there is no timeout mechanism in `l2bft` or `network` — no
//! `Instant`, no `Duration`, no deadline. A round change could only come from a
//! test driver.
//!
//! BH adds one thing and nothing else: [`RoundTimer`], which counts **steps
//! supplied by the caller**. It does not read a clock, so two runs agree. The
//! message it produces is byte-for-byte the one BG already transported
//! (`ROUND_CHANGE_VERSION = 1`, `DOMAIN_ROUND_CHANGE`), verified and adopted by the
//! existing engine path.
//!
//! | Test | Validators | What it shows |
//! |---|---|---|
//! | `bk_01` | — | the budget is deterministic and doubles, bounded |
//! | `bk_02` | 4 | four timers fire, a quorum adopts round 1 |
//! | `bk_03` | 7 | the same with a larger set; two of seven are not enough |
//! | `bk_04` | 21 | a quorum of 14 out of 21 adopts; 13 do not |
//! | `bk_05` | 4 | a lock is carried as evidence and is **not** cleared |
//! | `bk_06` | 4 | a forged change with a wrong target round is refused |
//!
//! No liveness theorem is claimed: see `roundchange-liveness.md`.

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::timer::{round_change_for, RoundTimer, MAX_BACKOFF_SHIFT};
use aether_unified::l2bft::{BftState, RoundChangeOutcome};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::MemoryAtomicSlotStore;
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 41;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const WEIGHT: u64 = 10;

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

fn registry(n: usize) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = (1..=n)
        .map(|seed| RegistryEntry {
            id: vid(seed as u8),
            public_key: sk(seed as u8).verifying_key().to_bytes(),
            weight: ValidatorWeight(WEIGHT),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

fn value() -> [u8; 32] {
    [0x42; 32]
}

#[test]
fn bk_01_the_budget_is_deterministic_and_bounded() {
    let mut timer = RoundTimer::new(8);
    assert_eq!(timer.budget(), 8, "round 0 costs the base budget");
    assert_eq!(timer.tick(7), None, "seven steps are not eight");
    assert_eq!(
        timer.tick(1),
        Some(Round(1)),
        "the eighth step times the round out"
    );
    assert_eq!(
        timer.tick(0),
        None,
        "one request per round: it does not fire again in the same round"
    );
    assert_eq!(timer.tick(5), None, "still quiet after five more steps");

    timer.sync_round(Round(1));
    assert_eq!(timer.elapsed(), 0, "an adopted round restarts the counter");
    assert_eq!(timer.budget(), 16, "round 1 doubles the budget");
    assert_eq!(
        timer.tick(16),
        Some(Round(2)),
        "and the timer is armed again for the new round"
    );
    timer.sync_round(Round(3));
    assert_eq!(timer.budget(), 64);

    // Bounded: a node alone for a long time must not keep doubling for ever.
    timer.sync_round(Round(64));
    assert_eq!(timer.budget(), 8u64 << MAX_BACKOFF_SHIFT);

    // And the same sequence gives the same answers twice.
    let mut a = RoundTimer::new(5);
    let mut b = RoundTimer::new(5);
    let first: Vec<_> = (0..25).map(|_| a.tick(1)).collect();
    let second: Vec<_> = (0..25).map(|_| b.tick(1)).collect();
    assert_eq!(first, second, "no clock, no dependency, no drift");
}

/// Drive `n` engines through one timeout, delivering the round changes in order.
fn one_timeout(n: usize, timeout: u64, deliver: usize) -> (Vec<BftState>, Vec<Round>) {
    let registry = registry(n);
    let mut engines: Vec<BftState> = (0..n)
        .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
        .collect();
    let stores: Vec<MemoryAtomicSlotStore> = (0..n).map(|_| MemoryAtomicSlotStore::new()).collect();
    let mut timers: Vec<RoundTimer> = (0..n).map(|_| RoundTimer::new(timeout)).collect();

    // Every validator votes, so a node has a position to leave.
    for index in 0..n {
        let seed = (index + 1) as u8;
        let _ = engines[index]
            .prevote(
                value(),
                vid(seed),
                &registry,
                &stores[index],
                sign_with(seed),
            )
            .expect("prevote");
    }

    // Advance the logical clock until every timer fires, then collect the changes.
    let mut changes = Vec::new();
    for _ in 0..(timeout + 1) {
        for index in 0..n {
            timers[index].sync_round(engines[index].round);
            if let Some(target) = timers[index].tick(1) {
                let change = round_change_for(&engines[index], target, &sk((index + 1) as u8));
                changes.push((index, change));
            }
        }
    }
    assert_eq!(changes.len(), n, "every timer fired exactly once");

    // The first `deliver` changes reach everybody, including their own engine.
    let mut rounds = Vec::new();
    for (index, change) in changes.iter().take(deliver) {
        for engine in engines.iter_mut() {
            let _ = engine.process_round_change(change.clone(), &registry, NET);
        }
        let _ = index;
    }
    for engine in &mut engines {
        rounds.push(engine.round);
    }
    (engines, rounds)
}

#[test]
fn bk_02_four_validators_adopt_round_one() {
    let (engines, rounds) = one_timeout(4, 8, 3);
    assert_eq!(
        rounds,
        vec![Round(1), Round(1), Round(1), Round(1)],
        "3 of 4 changes carry a quorum, so every engine adopts round 1"
    );
    for (index, engine) in engines.iter().enumerate() {
        assert_eq!(engine.round, Round(1));
        assert!(
            engine.round_state.round_changes.len() >= 3,
            "engine {index} kept the evidence"
        );
        assert_eq!(engine.height, CheckpointHeight(0), "no height moved");
    }
}

#[test]
fn bk_03_seven_validators_need_a_quorum() {
    // Two changes are not a quorum of seven.
    let (two, rounds) = one_timeout(7, 8, 2);
    assert!(
        rounds.iter().all(|round| *round == Round(0)),
        "2 of 7 must adopt nothing: {rounds:?}"
    );
    assert!(two
        .iter()
        .all(|engine| engine.round_change_evidence(Round(1), &registry(7)).is_ok()));

    // Five of seven is.
    let (_, rounds) = one_timeout(7, 8, 5);
    assert_eq!(
        rounds,
        vec![Round(1); 7],
        "5 of 7 adopts round 1 everywhere"
    );
}

#[test]
fn bk_04_twenty_one_validators_need_fourteen() {
    let (_, thirteen) = one_timeout(21, 8, 13);
    assert!(
        thirteen.iter().all(|round| *round == Round(0)),
        "13 of 21 is below 140/210: nothing adopted"
    );
    let (engines, fourteen) = one_timeout(21, 8, 14);
    assert_eq!(fourteen, vec![Round(1); 21], "14 of 21 adopts round 1");
    assert_eq!(engines.len(), 21);
}

#[test]
fn bk_05_the_lock_travels_as_evidence_and_is_never_cleared() {
    let registry = registry(4);
    let seed = 1u8;
    let mut engines: Vec<BftState> = (0..4)
        .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
        .collect();
    let stores: Vec<MemoryAtomicSlotStore> = (0..4).map(|_| MemoryAtomicSlotStore::new()).collect();

    // Validator 1 locks on the value: prevote, quorum, precommit.
    let mut votes = Vec::new();
    for index in 0..4 {
        let vote = engines[index]
            .prevote(
                value(),
                vid((index + 1) as u8),
                &registry,
                &stores[index],
                sign_with((index + 1) as u8),
            )
            .expect("prevote");
        votes.push(vote.vote().clone());
    }
    for engine in engines.iter_mut() {
        for vote in &votes {
            engine.accept_vote(vote, &registry);
        }
    }
    let pol = engines[0]
        .certify_prevotes_for(value(), &registry)
        .expect("prevote quorum");
    let locked = engines[0]
        .precommit(&pol, vid(seed), &registry, &stores[0], sign_with(seed))
        .expect("precommit");
    assert_eq!(locked.checkpoint_id(), value());
    assert_eq!(
        engines[0].active_lock().map(|lock| lock.checkpoint_id),
        Some(value())
    );

    // The round change it emits carries the lock…
    let change = round_change_for(&engines[0], Round(1), &sk(seed));
    assert_eq!(
        change.locked.map(|lock| lock.checkpoint_id),
        Some(value()),
        "the lock travels as evidence"
    );

    // …and accepting it on another node does not unlock anything.
    let _ = engines[1].process_round_change(change, &registry, NET);
    assert_eq!(
        engines[1].active_lock(),
        None,
        "a round change never writes another node's lock"
    );
    assert_eq!(
        engines[0].active_lock().map(|lock| lock.checkpoint_id),
        Some(value()),
        "the sender's own lock is untouched by the message it sent"
    );
}

#[test]
fn bk_06_a_forged_change_is_refused() {
    let registry = registry(4);
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let store = MemoryAtomicSlotStore::new();
    let _ = engine
        .prevote(value(), vid(1), &registry, &store, sign_with(1))
        .expect("prevote");

    // A change signed by validator 1 but claiming to come from validator 2.
    let honest = round_change_for(&engine, Round(1), &sk(1));
    let mut forged = honest.clone();
    forged.validator = vid(2);
    assert!(matches!(
        engine.process_round_change(forged, &registry, NET),
        Err(_)
    ));

    // A change whose signature no longer matches its body.
    let mut tampered = honest.clone().encode();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(aether_unified::l2bft::round::RoundChange::decode(&tampered, &registry, NET).is_err());

    // The honest one is recorded, and the round does not move on one change.
    assert!(matches!(
        engine.process_round_change(honest, &registry, NET),
        Ok(RoundChangeOutcome::Recorded { .. })
    ));
    assert_eq!(engine.round, Round(0));
}
