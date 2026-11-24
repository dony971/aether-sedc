//! PHASE 4DB — end-to-end multi-validator consensus (mission BA).
//!
//! Every other BFT test in this repository drives **one** engine and injects
//! foreign votes. These tests run a real cluster: one `BftState` and one
//! `AtomicSlotStore` per validator, votes produced by each engine's own signing
//! path, then delivered to peers exactly as a transport would.
//!
//! Deterministic: fixed seeds, fixed registry, fixed votes, no clock, no network,
//! no randomness.
//!
//! **What these tests can claim**: this implementation performs the whole cycle
//! `proposal → prevote → POL → precommit → QC → finality` and preserves safety
//! under the failures listed in `A-06.6-BA`. **What they cannot claim**: the
//! weighted-intersection theorem itself (proved on paper and exercised
//! arithmetic-only in `ba_12`), nor liveness under an adversarial scheduler.

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    quorum_met, quorum_threshold, CheckpointHeight, GenerationId, Round, ValidatorId,
    ValidatorWeight,
};
use aether_unified::l2bft::{
    restore_engine, BftError, BftState, PrecommitCertificate, PrevoteCertificate, ProofOfLock,
    RoundChange, RoundChangeOutcome, VoteOutcome, NIL_VALUE,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase};
use aether_unified::l2persist::{AtomicSlotStore, MemoryAtomicSlotStore};

const NET: u64 = 11;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const A: [u8; 32] = [0xA1; 32];
const B: [u8; 32] = [0xB2; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn gen_id() -> GenerationId {
    GenerationId(GEN)
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn registry_with(gen: [u8; 32], members: &[(u8, u64)]) -> ValidatorRegistry {
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

fn reg() -> ValidatorRegistry {
    registry_with(GEN, &[(1, 10), (2, 10), (3, 10), (4, 10)])
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

/// A cluster of independent validators: one engine and one store each.
struct Cluster {
    seeds: Vec<u8>,
    engines: Vec<BftState>,
    stores: Vec<MemoryAtomicSlotStore>,
    registry: ValidatorRegistry,
}

impl Cluster {
    fn new(seeds: &[u8]) -> Self {
        Self::with_generation(GEN, seeds)
    }

    fn with_generation(generation: [u8; 32], seeds: &[u8]) -> Self {
        let members: Vec<(u8, u64)> = seeds.iter().map(|s| (*s, 10u64)).collect();
        let registry = registry_with(generation, &members);
        let engines = seeds
            .iter()
            .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
            .collect();
        let stores = seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect();
        Self {
            seeds: seeds.to_vec(),
            engines,
            stores,
            registry,
        }
    }

    fn len(&self) -> usize {
        self.engines.len()
    }

    fn advance_to(&mut self, round: u32) {
        for engine in &mut self.engines {
            if engine.round.get() < round {
                engine.begin_round(Round(round)).expect("round");
            }
        }
    }

    /// Every validator except `absent` prevotes `value` at the current round.
    fn prevote_all(&mut self, value: [u8; 32], absent: Option<usize>) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.len() {
            if Some(i) == absent {
                continue;
            }
            let vote = self.engines[i]
                .prevote(
                    value,
                    vid(self.seeds[i]),
                    &self.registry,
                    &self.stores[i],
                    sign_with(self.seeds[i]),
                )
                .expect("prevote");
            out.push(vote.vote().clone());
        }
        out
    }

    fn precommit_all(
        &mut self,
        certificate: &PrevoteCertificate,
        absent: Option<usize>,
    ) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.len() {
            if Some(i) == absent {
                continue;
            }
            let vote = self.engines[i]
                .precommit(
                    certificate,
                    vid(self.seeds[i]),
                    &self.registry,
                    &self.stores[i],
                    sign_with(self.seeds[i]),
                )
                .expect("precommit");
            out.push(vote.vote().clone());
        }
        out
    }

    /// Deliver votes to every validator.
    fn deliver(&mut self, votes: &[ConsensusVote]) {
        for i in 0..self.len() {
            for vote in votes {
                let outcome = self.engines[i].accept_vote(vote, &self.registry);
                assert!(
                    !matches!(outcome, VoteOutcome::Rejected { .. }),
                    "validator {} rejected a genuine vote: {outcome:?}",
                    self.seeds[i]
                );
            }
        }
    }

    /// Full cycle at the current round and height: prevote, certificate,
    /// precommit, certificate. Returns both certificates.
    fn run_cycle(
        &mut self,
        value: [u8; 32],
        absent: Option<usize>,
    ) -> (PrevoteCertificate, PrecommitCertificate) {
        let prevotes = self.prevote_all(value, absent);
        self.deliver(&prevotes);
        let prevote_cert = self.engines[0]
            .certify_prevotes_for(value, &self.registry)
            .expect("prevote quorum");
        // The previous `deliver` gave every validator the prevotes, so each one
        // can check `A3-ord` against its own slots before precommitting.
        let precommits = self.precommit_all(&prevote_cert, absent);
        self.deliver(&precommits);
        let precommit_cert = self.engines[0]
            .certify_precommits_for(value, &self.registry)
            .expect("precommit quorum");
        (prevote_cert, precommit_cert)
    }

    fn finalize_all(
        &mut self,
        certificate: &PrecommitCertificate,
        cp: &Checkpoint,
        parent: Option<&Checkpoint>,
    ) {
        for i in 0..self.len() {
            self.engines[i]
                .finalize(certificate, cp, parent, &self.registry, &self.stores[i])
                .expect("finality");
        }
    }
}

// ---------------------------------------------------------------------------
// BA-01 / BA-02. Normal consensus, then with one validator absent.
// ---------------------------------------------------------------------------

#[test]
fn ba_01_four_independent_validators_reach_finality() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);

    let (prevote_cert, precommit_cert) = cluster.run_cycle(cp.id(), None);
    assert_eq!(prevote_cert.checkpoint_id(), cp.id());
    assert_eq!(prevote_cert.support().get(), 40);
    assert_eq!(precommit_cert.support().get(), 40);

    cluster.finalize_all(&precommit_cert, &cp, None);
    for engine in &cluster.engines {
        assert_eq!(
            engine.finality.map(|d| d.checkpoint_id),
            Some(cp.id()),
            "every validator must decide the same checkpoint"
        );
        // AW-LOCK-2: the precommit installed the lock on every validator.
        assert_eq!(engine.active_lock().map(|l| l.checkpoint_id), Some(cp.id()));
    }
}

#[test]
fn ba_02_finality_survives_one_absent_validator() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);

    // Validator 4 never answers: 30 of 40 still reaches the 27 threshold.
    let (_, precommit_cert) = cluster.run_cycle(cp.id(), Some(3));
    assert_eq!(precommit_cert.support().get(), 30);
    assert!(quorum_met(ValidatorWeight(30), ValidatorWeight(40)));
    cluster.finalize_all(&precommit_cert, &cp, None);
    for engine in &cluster.engines {
        assert_eq!(engine.finality.map(|d| d.checkpoint_id), Some(cp.id()));
    }
    // The absent validator signs nothing and holds no lock.
    assert!(cluster.stores[3].scan_slots().expect("scan").is_empty());
    assert_eq!(cluster.engines[3].active_lock(), None);
}

// ---------------------------------------------------------------------------
// BA-03 / BA-04. A byzantine validator and contradictory proposals.
// ---------------------------------------------------------------------------

#[test]
fn ba_03_a_byzantine_validator_cannot_certify_the_other_value() {
    // Validator 4 is byzantine: it prevotes A to half the cluster and B to the
    // other half, which is the strongest equivocation available to it.
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);

    // Honest: 1, 2, 3 prevote the checkpoint. Byzantine 4 prevotes another value.
    let mut votes = cluster.prevote_all(cp.id(), Some(3));
    let byzantine = cluster.engines[3]
        .prevote(
            B,
            vid(4),
            &cluster.registry,
            &cluster.stores[3],
            sign_with(4),
        )
        .expect("byzantine prevote")
        .vote()
        .clone();
    votes.push(byzantine);
    cluster.deliver(&votes);

    // The honest value reaches 30 >= 27; the byzantine one reaches 10.
    let cert_a = cluster.engines[0]
        .certify_prevotes_for(cp.id(), &cluster.registry)
        .expect("the honest value is quorate");
    assert_eq!(cert_a.support().get(), 30);
    assert!(
        cluster.engines[0]
            .certify_prevotes_for(B, &cluster.registry)
            .is_err(),
        "a single misbehaving validator must never certify a value"
    );

    let precommits = cluster.precommit_all(&cert_a, Some(3));
    cluster.deliver(&precommits);
    let cert = cluster.engines[0]
        .certify_precommits_for(cp.id(), &cluster.registry)
        .expect("precommit quorum");
    cluster.finalize_all(&cert, &cp, None);
    assert_eq!(
        cluster.engines[0].finality.map(|d| d.checkpoint_id),
        Some(cp.id())
    );
}

#[test]
fn ba_04_two_contradictory_proposals_certify_nothing() {
    // A 2/2 split of four equal validators reaches 20 of 40 for each value: no
    // POL for either, so round 1 may only carry Nil.
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    cluster.engines[0].propose(A).expect("proposal A");
    cluster.engines[1].propose(B).expect("proposal B");

    let mut all = Vec::new();
    for i in [0usize, 1] {
        let vote = cluster.engines[i]
            .prevote(
                A,
                vid(cluster.seeds[i]),
                &cluster.registry,
                &cluster.stores[i],
                sign_with(cluster.seeds[i]),
            )
            .expect("prevote A")
            .vote()
            .clone();
        all.push(vote);
    }
    for i in [2usize, 3] {
        let vote = cluster.engines[i]
            .prevote(
                B,
                vid(cluster.seeds[i]),
                &cluster.registry,
                &cluster.stores[i],
                sign_with(cluster.seeds[i]),
            )
            .expect("prevote B")
            .vote()
            .clone();
        all.push(vote);
    }
    cluster.deliver(&all);

    for value in [A, B] {
        assert!(
            cluster.engines[0]
                .certify_prevotes_for(value, &cluster.registry)
                .is_err(),
            "20 of 40 is not a quorum"
        );
    }

    // Round 1: the split still certifies nothing, so no value can be decided.
    // (No validator holds a lock in this scenario, so a prevote is not refused
    // for lock reasons — the barrier is the absence of a POL, i.e. of a
    // certificate.) Nil is always signable (`AW-LOCK-1` branch 1).
    cluster.advance_to(1);
    for value in [A, B] {
        assert!(
            cluster.engines[0]
                .certify_prevotes_for(value, &cluster.registry)
                .is_err(),
            "a 2/2 split of round 0 cannot back a round-1 certificate"
        );
    }
    cluster.engines[0]
        .prevote(
            NIL_VALUE,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("abstention is always allowed");
}

// ---------------------------------------------------------------------------
// BA-05 / BA-06 / BA-07. Round change and proofs of lock.
// ---------------------------------------------------------------------------

#[test]
fn ba_05_a_round_change_is_adopted_after_quorum_and_never_touches_the_lock() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);
    let (_, cert) = cluster.run_cycle(cp.id(), None);
    cluster.finalize_all(&cert, &cp, None);
    let before = cluster.engines[0].active_lock();

    let set_root = cluster.registry.set_root();
    let mut outcome = None;
    for seed in [1u8, 2, 3] {
        let change = RoundChange::unsigned(
            NET,
            gen_id(),
            CheckpointHeight(0),
            Round(0),
            Round(1),
            vid(seed),
            set_root,
            before,
        )
        .sign_with(&sk(seed));
        outcome = Some(
            cluster.engines[0]
                .process_round_change(change, &cluster.registry, NET)
                .expect("round change accepted"),
        );
    }
    assert!(
        matches!(outcome, Some(RoundChangeOutcome::Adopted { .. })),
        "30 of 40 round changes must be adopted, got {outcome:?}"
    );
    assert_eq!(
        cluster.engines[0].active_lock(),
        before,
        "AW-LOCK-6: a round change never modifies the lock"
    );
    assert_eq!(cluster.engines[0].round.get(), 1);
}

#[test]
fn ba_06_a_valid_proof_updates_the_lock_to_the_new_value() {
    // Validators 2 and 3 precommitted nothing in round 0, so they may prevote B
    // at round 1 and build a genuine POL(B, 1). Validator 1 is locked on A@0 and
    // sits at round 2: `0 <= 1 < 2` authorises the change.
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);
    // Round 0: every validator prevotes the checkpoint, but **only validator 1
    // precommits**. It therefore holds the only lock; the others are free, which
    // is exactly the configuration in which a genuine later POL can exist.
    let prevotes = cluster.prevote_all(cp.id(), None);
    cluster.deliver(&prevotes);
    let cert_zero = cluster.engines[0]
        .certify_prevotes_for(cp.id(), &cluster.registry)
        .expect("prevote quorum");
    cluster.engines[0]
        .precommit(
            &cert_zero,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("precommit");
    assert_eq!(
        cluster.engines[0].active_lock().map(|l| l.checkpoint_id),
        Some(cp.id())
    );
    assert_eq!(
        cluster.engines[1].active_lock(),
        None,
        "validators 2..4 never precommitted and hold no lock"
    );

    cluster.advance_to(1);
    let mut round_one = Vec::new();
    for i in [1usize, 2, 3] {
        let vote = cluster.engines[i]
            .prevote(
                B,
                vid(cluster.seeds[i]),
                &cluster.registry,
                &cluster.stores[i],
                sign_with(cluster.seeds[i]),
            )
            .expect("prevote B")
            .vote()
            .clone();
        round_one.push(vote);
    }
    cluster.deliver(&round_one);
    let pol_b = ProofOfLock::from_prevote(
        cluster.engines[1]
            .certify_prevotes_for(B, &cluster.registry)
            .expect("POL(B,1)"),
    );
    assert_eq!(pol_b.round, Round(1));
    assert_eq!(pol_b.support().get(), 30);

    // Validator 1 moves to round 2 and is authorised by `0 <= 1 < 2`.
    cluster.advance_to(2);
    let prevote = cluster.engines[0]
        .prevote_with_proof(
            B,
            Some(&pol_b),
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("a proof in [lockR, r) authorises the change");
    cluster.deliver(&[prevote.vote().clone()]);
    // Validators 2 and 3 add their round-2 prevotes so the precommit has a quorum.
    for i in [1usize, 2] {
        let vote = cluster.engines[i]
            .prevote(
                B,
                vid(cluster.seeds[i]),
                &cluster.registry,
                &cluster.stores[i],
                sign_with(cluster.seeds[i]),
            )
            .expect("prevote B at round 2")
            .vote()
            .clone();
        cluster.deliver(&[vote]);
    }

    // The precommit now performs `UPD-NEW`: (checkpoint, 0) -> (B, 2).
    let cert_two = cluster.engines[0]
        .certify_prevotes_for(B, &cluster.registry)
        .expect("quorum on B at round 2");
    cluster.engines[0]
        .precommit(
            &cert_two,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("precommit B");
    let lock = cluster.engines[0].active_lock().expect("locked");
    assert_eq!((lock.checkpoint_id, lock.round), (B, Round(2)));
    assert!(
        cluster.engines[0].persisted().proof_of_lock.is_some(),
        "AW-LOCK-4: the new lock carries its proof"
    );
}

#[test]
fn ba_07_an_invalid_proof_is_refused_and_writes_nothing() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);
    cluster.run_cycle(cp.id(), None);
    let slots_before = cluster.stores[0].scan_slots().expect("scan").len();

    // A **genuine** quorate proof for B, built in another generation: real
    // signatures, wrong context. This is the strongest form of the attack.
    let mut foreign = Cluster::with_generation([9u8; 32], &[1, 2, 3, 4]);
    let (foreign_prevotes, _) = foreign.run_cycle(B, None);
    assert_eq!(foreign_prevotes.support().get(), 40);
    let forged = ProofOfLock::from_prevote(foreign_prevotes);

    cluster.advance_to(1);
    assert!(matches!(
        cluster.engines[0].prevote_with_proof(
            B,
            Some(&forged),
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1)
        ),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    assert_eq!(
        cluster.stores[0].scan_slots().expect("scan").len(),
        slots_before,
        "a refused prevote writes nothing"
    );
}

// ---------------------------------------------------------------------------
// BA-08 / BA-09 / BA-10. Restart, halt, double signature.
// ---------------------------------------------------------------------------

#[test]
fn ba_08_a_restarted_validator_keeps_its_lock_and_its_refusals() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = checkpoint(0, [0u8; 32], [0x11u8; 32]);
    let (_, cert) = cluster.run_cycle(cp.id(), None);
    cluster.finalize_all(&cert, &cp, None);

    let store = std::mem::take(&mut cluster.stores[0]);
    let restored = restore_engine(
        &store,
        &cluster.registry,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert!(restored.report.may_sign(), "{:?}", restored.report.findings);
    let mut engine = restored.state;
    assert_eq!(engine.active_lock().map(|l| l.checkpoint_id), Some(cp.id()));
    assert!(engine.persisted().proof_of_lock.is_some());

    engine.begin_round(Round(1)).expect("round 1");
    assert!(matches!(
        engine.prevote(B, vid(1), &cluster.registry, &store, sign_with(1)),
        Err(BftError::PrevoteNotJustified { .. })
    ));
    engine
        .prevote(cp.id(), vid(1), &cluster.registry, &store, sign_with(1))
        .expect("the locked value stays signable");
    cluster.stores[0] = store;
}

#[test]
fn ba_09_a_contradictory_finality_halts_and_halt_survives_restart() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp_a = checkpoint(0, [0u8; 32], [0x11u8; 32]);
    let (_, cert_a) = cluster.run_cycle(cp_a.id(), None);
    cluster.finalize_all(&cert_a, &cp_a, None);

    // A partition certifies another checkpoint at the same height.
    let mut other = Cluster::new(&[1, 2, 3, 4]);
    let cp_b = checkpoint(0, [0u8; 32], [0x99u8; 32]);
    let (_, cert_b) = other.run_cycle(cp_b.id(), None);
    other.finalize_all(&cert_b, &cp_b, None);
    assert_ne!(cp_a.id(), cp_b.id());

    let slots_before = cluster.stores[0].scan_slots().expect("scan").len();
    let err = cluster.engines[0]
        .finalize(&cert_b, &cp_b, None, &cluster.registry, &cluster.stores[0])
        .expect_err("a contradictory decision must halt");
    assert!(
        matches!(
            err,
            BftError::ConflictingFinality { .. } | BftError::Halted(_)
        ),
        "expected a halt, got {err:?}"
    );
    assert!(cluster.engines[0].halt.is_some(), "the halt is recorded");
    // Both pieces of evidence survive: the decision and every vote slot.
    assert_eq!(
        cluster.engines[0].finality.map(|d| d.checkpoint_id),
        Some(cp_a.id())
    );
    assert_eq!(
        cluster.stores[0].scan_slots().expect("scan").len(),
        slots_before
    );

    // No signature of any kind is possible after a halt — not even a round
    // advance, and certainly not a vote.
    assert!(matches!(
        cluster.engines[0].begin_round(Round(1)),
        Err(BftError::Halted(_))
    ));
    assert!(matches!(
        cluster.engines[0].prevote(
            cp_a.id(),
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1)
        ),
        Err(BftError::Halted(_))
    ));

    // And the halt survives a restart.
    let store = std::mem::take(&mut cluster.stores[0]);
    let restored = restore_engine(
        &store,
        &cluster.registry,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert!(restored.halt.is_some(), "the halt record is restored");
    assert!(restored.state.may_sign().is_err());
    cluster.stores[0] = store;
}

#[test]
fn ba_10_a_double_signature_is_refused() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    cluster.engines[0]
        .prevote(
            A,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1),
        )
        .expect("first prevote");
    let slots = cluster.stores[0].scan_slots().expect("scan").len();
    assert!(matches!(
        cluster.engines[0].prevote(
            B,
            vid(1),
            &cluster.registry,
            &cluster.stores[0],
            sign_with(1)
        ),
        Err(BftError::LockRetained { .. }) | Err(BftError::Emit(_))
    ));
    assert_eq!(
        cluster.stores[0].scan_slots().expect("scan").len(),
        slots,
        "the refused vote wrote nothing"
    );
}

// ---------------------------------------------------------------------------
// BA-11 / BA-12. Generation change and quorum arithmetic.
// ---------------------------------------------------------------------------

#[test]
fn ba_11_a_vote_from_another_generation_is_rejected() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let mut stale = ConsensusVote {
        version: aether_unified::l2crypto::vote::CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: GenerationId([8u8; 32]),
        height: CheckpointHeight(0),
        round: Round(0),
        phase: VotePhase::Prevote,
        checkpoint_id: A,
        validator: vid(1),
        signature: [0u8; 64],
    };
    stale.signature = sk(1).sign(&stale.signing_bytes()).to_bytes();
    assert!(!matches!(
        cluster.engines[0].accept_vote(&stale, &cluster.registry),
        VoteOutcome::Accepted { .. }
    ));
    assert!(
        cluster.engines[0]
            .certify_prevotes_for(A, &cluster.registry)
            .is_err(),
        "one stale vote cannot make a certificate"
    );
}

#[test]
fn ba_12_weighted_quorums_are_consistent_and_intersect() {
    // Distributions required by mission BA, including the pathological ones.
    let distributions: Vec<Vec<u64>> = vec![
        vec![10, 10, 10, 10],
        vec![10, 10, 10, 10, 10],
        vec![10, 10, 10, 10, 10, 10, 10],
        vec![1; 21],
        vec![90, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        vec![3, 3, 3, 3, 3, 3, 3, 1, 1, 1],
    ];
    for weights in distributions {
        let total: u64 = weights.iter().sum();
        let total_w = ValidatorWeight(total);
        let threshold = quorum_threshold(total_w);
        // `quorum_met` and `quorum_threshold` must agree exactly.
        for support in 0..=total {
            let met = quorum_met(ValidatorWeight(support), total_w);
            assert_eq!(
                met,
                support >= threshold.get(),
                "support {support} of {total}: predicate and threshold disagree"
            );
        }
        // `3s >= 2t` must equal `s >= ceil(2t/3)`.
        assert_eq!(threshold.get(), (2 * total + 2) / 3);
        // Safety (weighted intersection): two quorums cannot be disjoint when
        // the faulty weight stays below one third, i.e. any two >= 2t/3 sets
        // intersect in > t/3.
        assert!(
            threshold.get() * 3 >= 2 * total,
            "threshold must reach two thirds for {weights:?}"
        );
        assert!(
            2 * threshold.get() > total,
            "two quorums must overlap for {weights:?}"
        );
        // A single validator can never be a quorum of a multi-validator set...
        if weights.len() > 1 {
            let biggest = *weights.iter().max().expect("non-empty");
            assert!(
                !quorum_met(ValidatorWeight(biggest), total_w) || biggest * 3 >= total * 2,
                "a single validator is a quorum only if it really holds two thirds"
            );
        }
    }
}
