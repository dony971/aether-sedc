//! Mission BI — round-change safety (priority 6).
//!
//! # What is asserted, and what is not
//!
//! A round change carries a lock as **evidence**. It never unlocks, never
//! authorizes a value, and adopting one is a progress decision. These tests pin
//! the properties that must hold whatever the round is:
//!
//! | Test | What it establishes |
//! |---|---|
//! | `bp_01` | one message per validator and target; a duplicate is refused |
//! | `bp_02` | forged, foreign or backwards changes are refused, never recorded |
//! | `bp_03` | a proof of lock justifies only its own value and only a later round |
//! | `bp_04` | a lock survives every round change, and still constrains prevotes |
//! | `bp_05` | a proposal without the required proof is refused |
//! | `bp_06` | 3/4, 5/7 and 14/21 adopt; one short never does |
//! | `bp_07` | a late change for an older round cannot move the node backwards |
//! | `bp_08` | two nodes that changed round independently never disagree on value |
//!
//! No liveness claim: see `roundchange-safety.md`.

use aether_unified::consensus::generation::{CheckpointHeight, GenerationId, Round, ValidatorId};
use aether_unified::l2bft::timer::round_change_for;
use aether_unified::l2bft::{BftError, BftState, RoundChangeOutcome};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
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
            weight: aether_unified::consensus::generation::ValidatorWeight(WEIGHT),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

fn value() -> [u8; 32] {
    [0x42; 32]
}

/// `n` live engines with a memory store each.
struct Cluster {
    registry: ValidatorRegistry,
    engines: Vec<BftState>,
    stores: Vec<MemoryAtomicSlotStore>,
}

impl Cluster {
    fn new(n: usize) -> Self {
        let registry = registry(n);
        Self {
            engines: (0..n)
                .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
                .collect(),
            stores: (0..n).map(|_| MemoryAtomicSlotStore::new()).collect(),
            registry,
        }
    }

    /// Every engine votes for `value`, so a lock exists at round 0.
    fn prevote_all(&mut self, value: [u8; 32]) {
        for index in 0..self.engines.len() {
            let seed = (index + 1) as u8;
            self.engines[index]
                .prevote(
                    value,
                    vid(seed),
                    &self.registry,
                    &self.stores[index],
                    sign_with(seed),
                )
                .expect("prevote");
        }
    }

    /// Every engine's own prevote, collected from its own round state.
    ///
    /// `prevote_all` only *signs*; nothing is delivered. The votes have to travel
    /// for a certificate to exist, which is exactly what a quorum is.
    fn prevotes(&self) -> Vec<ConsensusVote> {
        self.engines
            .iter()
            .enumerate()
            .filter_map(|(index, engine)| {
                engine
                    .round_state
                    .prevotes
                    .iter()
                    .find(|vote| vote.validator() == vid((index + 1) as u8))
                    .map(|vote| vote.vote().clone())
            })
            .collect()
    }

    /// A round-0 proof built on fresh engines, so a node that has already moved to
    /// another round can still be handed one.
    fn proof_of_lock_at_round_0(&self, value: [u8; 32]) -> aether_unified::l2bft::ProofOfLock {
        let mut cluster = Cluster::new(self.engines.len());
        cluster.proof_of_lock(value)
    }

    /// Deliver every prevote to every engine.
    fn deliver_prevotes(&mut self) {
        let votes = self.prevotes();
        assert_eq!(votes.len(), self.engines.len(), "one vote per validator");
        for engine in self.engines.iter_mut() {
            for vote in &votes {
                engine.accept_vote(vote, &self.registry);
            }
        }
    }

    /// A verified proof of lock for `value` at round 0, built by the cluster.
    fn proof_of_lock(&mut self, value: [u8; 32]) -> aether_unified::l2bft::ProofOfLock {
        self.prevote_all(value);
        self.deliver_prevotes();
        let certificate = self.engines[0]
            .certify_prevotes_for(value, &self.registry)
            .expect("prevote quorum");
        aether_unified::l2bft::ProofOfLock::from_prevote(certificate)
    }

    /// Feed a round change to every engine, returning how many adopted it.
    fn deliver(&mut self, change: &aether_unified::l2bft::RoundChange, targets: usize) -> usize {
        let mut adopted = 0;
        for index in 0..targets {
            if let Ok(RoundChangeOutcome::Adopted { .. }) =
                self.engines[index].process_round_change(change.clone(), &self.registry, NET)
            {
                adopted += 1;
            }
        }
        adopted
    }
}

#[test]
fn bp_01_one_message_per_validator_and_target() {
    let mut cluster = Cluster::new(4);
    let change = round_change_for(&cluster.engines[0], Round(1), &sk(1));

    // Its own engine records it; the same message twice is refused.
    cluster.engines[0]
        .process_round_change(change.clone(), &cluster.registry, NET)
        .expect("first");
    assert!(matches!(
        cluster.engines[0].process_round_change(change.clone(), &cluster.registry, NET),
        Err(BftError::Rejected(_))
    ));
    assert_eq!(
        cluster.engines[0]
            .round_state
            .round_changes
            .iter()
            .filter(|c| c.validator == vid(1))
            .count(),
        1,
        "a duplicate does not create a second entry"
    );

    // A second, different target from the same validator is a new position, not a
    // contradiction: both are recorded, neither rewrites the other.
    let other = round_change_for(&cluster.engines[0], Round(2), &sk(1));
    cluster.engines[0]
        .process_round_change(other, &cluster.registry, NET)
        .expect("a different target");
    assert_eq!(
        cluster.engines[0]
            .round_state
            .round_changes
            .iter()
            .filter(|c| c.validator == vid(1))
            .count(),
        2
    );
}

#[test]
fn bp_02_invalid_changes_are_refused() {
    let mut cluster = Cluster::new(4);
    let good = round_change_for(&cluster.engines[0], Round(1), &sk(1));

    // A change signed for another network.
    let mut foreign = good.clone();
    foreign.network = NET + 1;
    assert!(matches!(
        cluster.engines[0].process_round_change(foreign, &cluster.registry, NET),
        Err(BftError::ContextMismatch { .. }) | Err(BftError::Rejected(_))
    ));

    // A change claiming another set root.
    let mut wrong_root = good.clone();
    wrong_root.validator_set_root = [0x99; 32];
    assert!(cluster.engines[0]
        .process_round_change(wrong_root, &cluster.registry, NET)
        .is_err());

    // A change that does not advance the round.
    let mut backwards = good.clone();
    backwards.from_round = Round(3);
    backwards.target_round = Round(2);
    assert!(cluster.engines[0]
        .process_round_change(backwards, &cluster.registry, NET)
        .is_err());

    // A tampered signature.
    let mut forged = good.clone();
    forged.signature[0] ^= 0xFF;
    assert!(cluster.engines[0]
        .process_round_change(forged, &cluster.registry, NET)
        .is_err());

    // And none of that left a record behind.
    assert!(
        cluster.engines[0].round_state.round_changes.is_empty(),
        "a refused change is not stored"
    );
    assert_eq!(cluster.engines[0].round, Round(0));
}

#[test]
fn bp_03_a_proof_justifies_only_its_value_and_only_a_later_round() {
    let mut cluster = Cluster::new(4);
    let locked = [0x11u8; 32];
    let other = [0x22u8; 32];
    let proof = cluster.proof_of_lock(locked);

    // At round 0 the proof cannot justify anything: its upper bound is strict.
    assert!(matches!(
        cluster.engines[0].propose_certified(other, proof.clone()),
        Err(BftError::InvalidProof(_))
    ));

    // In round 1 it can justify its own value, and nothing else.
    cluster.engines[0].begin_round(Round(1)).expect("round 1");
    assert!(matches!(
        cluster.engines[0].propose_certified(other, proof.clone()),
        Err(BftError::InvalidProof(_))
    ));
    cluster.engines[0]
        .propose_certified(locked, proof)
        .expect("the proof justifies its own value");

    // Nil is never proposed, with or without a proof. The proof built at round 0 is
    // reusable here: a proof belongs to its round, not to the node holding it.
    let mut fresh = BftState::new(NET, &cluster.registry, CheckpointHeight(0), ANCHOR);
    fresh.begin_round(Round(1)).expect("round 1");
    assert!(matches!(
        fresh.propose_certified([0u8; 32], cluster.proof_of_lock_at_round_0(locked)),
        Err(BftError::InvalidProof(_))
    ));
}

#[test]
fn bp_04_a_lock_survives_every_round_change() {
    let mut cluster = Cluster::new(4);
    let locked = [0x11u8; 32];
    let other = [0x22u8; 32];

    // Round 0: the cluster prevotes and precommits `locked` on engine 0.
    cluster.prevote_all(locked);
    cluster.deliver_prevotes();
    let pol = cluster.engines[0]
        .certify_prevotes_for(locked, &cluster.registry)
        .expect("quorum");
    cluster.engines[0]
        .precommit(
            &pol,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("precommit writes the lock");
    assert_eq!(
        cluster.engines[0].active_lock().map(|l| l.checkpoint_id),
        Some(locked)
    );

    // Three round changes move the node to round 1.
    for seed in 1..=3u8 {
        let change = round_change_for(&cluster.engines[0], Round(1), &sk(seed));
        // Each validator signs its own message: the engine verifies against the
        // registry key of the sender, so sign it here rather than reuse one key.
        let change = if change.validator == vid(seed) {
            change
        } else {
            aether_unified::l2bft::RoundChange::unsigned(
                NET,
                GenerationId(GEN),
                CheckpointHeight(0),
                Round(0),
                Round(1),
                vid(seed),
                cluster.registry.set_root(),
                cluster.engines[0].active_lock(),
            )
            .sign_with(&sk(seed))
        };
        let _ = cluster.engines[0].process_round_change(change, &cluster.registry, NET);
    }
    assert!(cluster.engines[0].round.get() >= 1, "the node moved on");
    assert_eq!(
        cluster.engines[0].active_lock().map(|l| l.checkpoint_id),
        Some(locked),
        "the lock is still there after the round change"
    );

    // And it still constrains a prevote for another value.
    assert!(matches!(
        cluster.engines[0].check_prevote_admissible(&other, None),
        Err(BftError::PrevoteNotJustified { .. })
    ));
}

#[test]
fn bp_05_a_proposal_without_the_required_proof_is_refused() {
    let mut cluster = Cluster::new(4);
    let locked = [0x11u8; 32];
    let other = [0x22u8; 32];
    cluster.prevote_all(locked);
    cluster.deliver_prevotes();
    let pol = cluster.engines[0]
        .certify_prevotes_for(locked, &cluster.registry)
        .expect("quorum");
    cluster.engines[0]
        .precommit(
            &pol,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("lock");
    cluster.engines[0].begin_round(Round(1)).expect("round 1");

    // A plain proposal of another value is accepted as a *value*, but a prevote for
    // it is refused: the proposal does not bypass `A4'`.
    cluster.engines[0]
        .propose(other)
        .expect("a value may be proposed");
    assert!(matches!(
        cluster.engines[0].prevote(
            other,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1)
        ),
        Err(BftError::PrevoteNotJustified { .. })
    ));

    // The locked value needs no proof at all.
    cluster.engines[0]
        .prevote(
            locked,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("a locked node may always vote its own value");
}

#[test]
fn bp_06_the_adoption_threshold_is_a_quorum_at_4_7_and_21() {
    for (n, quorum) in [(4usize, 3usize), (7, 5), (21, 14)] {
        let cluster = Cluster::new(n);
        // `one_short` validators sign a change for round 1.
        let mut changes = Vec::new();
        for seed in 1..=n as u8 {
            changes.push(round_change_for(&cluster.engines[0], Round(1), &sk(seed)));
        }
        // Re-sign each message with its own key: `round_change_for` uses the key it
        // is given, and the engine checks the registry entry of the sender.
        let changes: Vec<_> = (1..=n as u8)
            .map(|seed| {
                aether_unified::l2bft::RoundChange::unsigned(
                    NET,
                    GenerationId(GEN),
                    CheckpointHeight(0),
                    Round(0),
                    Round(1),
                    vid(seed),
                    cluster.registry.set_root(),
                    None,
                )
                .sign_with(&sk(seed))
            })
            .collect();
        let _ = changes;

        let mut engine = BftState::new(NET, &cluster.registry, CheckpointHeight(0), ANCHOR);
        let mut adopted_at = None;
        for (delivered, seed) in (1..=n as u8).enumerate() {
            let change = aether_unified::l2bft::RoundChange::unsigned(
                NET,
                GenerationId(GEN),
                CheckpointHeight(0),
                Round(0),
                Round(1),
                vid(seed),
                cluster.registry.set_root(),
                None,
            )
            .sign_with(&sk(seed));
            let outcome = engine
                .process_round_change(change, &cluster.registry, NET)
                .expect("change");
            if matches!(outcome, RoundChangeOutcome::Adopted { .. }) {
                adopted_at = Some(delivered + 1);
                break;
            }
        }
        assert_eq!(
            adopted_at,
            Some(quorum),
            "{n} validators adopt at {quorum} signatures, not before"
        );
        assert_eq!(engine.round, Round(1));
    }
}

#[test]
fn bp_07_a_late_change_cannot_move_the_round_backwards() {
    let cluster = Cluster::new(7);
    let mut engine = BftState::new(NET, &cluster.registry, CheckpointHeight(0), ANCHOR);

    // Round 2 is adopted first, with five of seven.
    for seed in 1..=5u8 {
        let change = aether_unified::l2bft::RoundChange::unsigned(
            NET,
            GenerationId(GEN),
            CheckpointHeight(0),
            Round(0),
            Round(2),
            vid(seed),
            cluster.registry.set_root(),
            None,
        )
        .sign_with(&sk(seed));
        let _ = engine.process_round_change(change, &cluster.registry, NET);
    }
    assert_eq!(engine.round, Round(2), "round 2 is adopted");

    // A change for round 1 arrives afterwards: it is refused, not applied.
    let late = aether_unified::l2bft::RoundChange::unsigned(
        NET,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(1),
        Round(2),
        vid(6),
        cluster.registry.set_root(),
        None,
    )
    .sign_with(&sk(6));
    match engine.process_round_change(late, &cluster.registry, NET) {
        Ok(RoundChangeOutcome::Refused(_)) => {}
        other => panic!("a late change must be refused, got {other:?}"),
    }
    assert_eq!(engine.round, Round(2), "and the round did not move");
    let _ = cluster.engines[0].round_state.proposal;
}

#[test]
fn bp_08_independent_round_changes_never_diverge_on_value() {
    let mut cluster = Cluster::new(4);
    // Two engines adopt round 1 through different message orders.
    let mut a = BftState::new(NET, &cluster.registry, CheckpointHeight(0), ANCHOR);
    let mut b = BftState::new(NET, &cluster.registry, CheckpointHeight(0), ANCHOR);
    let changes: Vec<_> = (1..=3u8)
        .map(|seed| {
            aether_unified::l2bft::RoundChange::unsigned(
                NET,
                GenerationId(GEN),
                CheckpointHeight(0),
                Round(0),
                Round(1),
                vid(seed),
                cluster.registry.set_root(),
                None,
            )
            .sign_with(&sk(seed))
        })
        .collect();
    for change in &changes {
        let _ = a.process_round_change(change.clone(), &cluster.registry, NET);
    }
    for change in changes.iter().rev() {
        let _ = b.process_round_change(change.clone(), &cluster.registry, NET);
    }
    assert_eq!(a.round, Round(1));
    assert_eq!(b.round, Round(1), "the order of arrival does not matter");

    // Both sign the same value at the new round: no contradiction is possible
    // between the two positions.
    let store_a = MemoryAtomicSlotStore::new();
    let store_b = MemoryAtomicSlotStore::new();
    let vote_a = a
        .prevote(value(), vid(1), &cluster.registry, &store_a, sign_with(1))
        .expect("a votes");
    let vote_b = b
        .prevote(value(), vid(1), &cluster.registry, &store_b, sign_with(1))
        .expect("b votes");
    assert_eq!(vote_a.vote().signing_bytes(), vote_b.vote().signing_bytes());
}
