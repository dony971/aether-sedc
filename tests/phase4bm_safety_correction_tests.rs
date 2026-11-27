//! Mission BM — independent regression tests for the three corrections.
//!
//! | Test | Finding |
//! |---|---|
//! | `bm_01` .. `bm_04` | N-2 — the admitted faulty weight is strictly below `W/3` |
//! | `bm_05` .. `bm_11` | N-6 — a decided closure blocks progression until installed |
//! | `bm_20` .. `bm_22` | E-1 — an ineligible entry is never elected proposer |
//!
//! Every engine test drives [`BftState`] directly (votes, certificates,
//! `finalize`, `close_generation`, `advance_height`, `restore_engine`), not a
//! network path. Fixtures are deterministic: fixed seeds, real Ed25519 keys, a
//! memory store, no clock and no randomness.

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    quorum_met, quorum_threshold, CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    candidate_id, AdmittedSet, CandidateOperator, GenerationClosure, SetPolicy, TransitionError,
};
use aether_unified::l2bft::{
    distribution, proposer_for, restore_engine, BftError, BftState, PrecommitCertificate,
    VoteOutcome,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::MemoryAtomicSlotStore;
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NET: u64 = 91;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const PARENT0: [u8; 32] = [0u8; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn registry_with(generation: [u8; 32], members: &[(u8, u64)]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = members
        .iter()
        .map(|(seed, weight)| {
            RegistryEntry::new(
                sk(*seed).verifying_key().to_bytes(),
                ValidatorWeight(*weight),
                Admissibility::Eligible,
            )
        })
        .collect();
    ValidatorRegistry::new(GenerationId(generation), &entries).expect("registry")
}

fn policy(churn: u64) -> SetPolicy {
    SetPolicy {
        min_deposit: 0,
        deposit_unit: 1,
        maturity_blocks: 0,
        min_weight: 1,
        max_weight: 1_000,
        w_max: 100_000,
        n_min: 1,
        n_max: 64,
        churn_max_weight: churn,
        f_b_new: 0,
        d_ready: 1_000,
    }
}

fn candidates(seeds: &[u8], weight: u64) -> Vec<CandidateOperator> {
    seeds
        .iter()
        .map(|seed| CandidateOperator {
            operator: [*seed; 32],
            public_key: sk(*seed).verifying_key().to_bytes(),
            deposit: weight,
            maturity_blocks: 0,
            unbonding: false,
            jailed: false,
        })
        .collect()
}

/// Build an admitted set from per-seed weights, with a declared faulty weight.
fn admit(
    weights: &[(u8, u64)],
    f_b_new: u64,
    w_max: u64,
    min_weight: u64,
) -> Result<AdmittedSet, TransitionError> {
    let declared: Vec<CandidateOperator> = weights
        .iter()
        .map(|(seed, weight)| CandidateOperator {
            operator: [*seed; 32],
            public_key: sk(*seed).verifying_key().to_bytes(),
            deposit: *weight,
            maturity_blocks: 0,
            unbonding: false,
            jailed: false,
        })
        .collect();
    let mut policy = policy(u64::MAX);
    policy.w_max = w_max;
    policy.min_weight = min_weight;
    policy.max_weight = w_max;
    policy.f_b_new = f_b_new;
    AdmittedSet::admit(&policy, &declared, 1, 0, None)
}

// ---------------------------------------------------------------------------
// A small cluster for the transition tests (no READY: the engine-level
// transition decision is what N-6 constrains).
// ---------------------------------------------------------------------------

struct Cluster {
    seeds: Vec<u8>,
    engines: Vec<BftState>,
    stores: Vec<MemoryAtomicSlotStore>,
    registry: ValidatorRegistry,
    height: CheckpointHeight,
    last: Option<Checkpoint>,
}

impl Cluster {
    fn new(generation: [u8; 32], seeds: &[u8], weight: u64) -> Self {
        let members: Vec<(u8, u64)> = seeds.iter().map(|seed| (*seed, weight)).collect();
        let registry = registry_with(generation, &members);
        Self {
            seeds: seeds.to_vec(),
            engines: seeds
                .iter()
                .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
                .collect(),
            stores: seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect(),
            registry,
            height: CheckpointHeight(0),
            last: None,
        }
    }

    fn len(&self) -> usize {
        self.engines.len()
    }

    fn prevote_all(&mut self, value: [u8; 32]) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.len() {
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

    fn precommit_all(&mut self, certificate: &PrevoteCertificateOf) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.len() {
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

    fn run_cycle(&mut self, value: [u8; 32]) -> PrecommitCertificate {
        let prevotes = self.prevote_all(value);
        self.deliver(&prevotes);
        let prevote_cert = self.engines[0]
            .certify_prevotes_for(value, &self.registry)
            .expect("prevote quorum");
        let precommits = self.precommit_all(&prevote_cert);
        self.deliver(&precommits);
        self.engines[0]
            .certify_precommits_for(value, &self.registry)
            .expect("precommit quorum")
    }

    fn checkpoint(&self, height: u64, transition: Option<[u8; 32]>) -> Checkpoint {
        let parent = if height == 0 {
            PARENT0
        } else {
            self.last.as_ref().expect("a parent checkpoint").id()
        };
        Checkpoint::new(
            self.registry.generation(),
            CheckpointHeight(height),
            parent,
            [0x22u8 ^ height as u8; 32],
            [0x33u8 ^ height as u8; 32],
            self.registry.set_root(),
            transition,
        )
        .expect("checkpoint")
    }

    fn finalize_all(&mut self, certificate: &PrecommitCertificate, cp: &Checkpoint) {
        let parent = self.last.clone();
        for i in 0..self.len() {
            self.engines[i]
                .finalize(
                    certificate,
                    cp,
                    parent.as_ref(),
                    &self.registry,
                    &self.stores[i],
                )
                .expect("finality");
        }
        self.last = Some(cp.clone());
    }

    fn close_all(&mut self, closure: GenerationClosure, next: &ValidatorRegistry) {
        for i in 0..self.len() {
            self.engines[i]
                .close_generation(closure, next, &self.stores[i])
                .expect("installation");
        }
        self.registry = next.clone();
        self.height = closure.height.next();
        for i in 0..self.len() {
            self.engines[i]
                .advance_height(self.height, &self.stores[i])
                .expect("advance");
        }
    }

    fn advance_all(&mut self, height: CheckpointHeight) {
        for i in 0..self.len() {
            self.engines[i]
                .advance_height(height, &self.stores[i])
                .expect("advance");
        }
        self.height = height;
    }
}

type PrevoteCertificateOf = aether_unified::l2bft::PrevoteCertificate;

/// Build the next registry at `generation_number`, keeping every seed.
fn next_registry(
    old: &ValidatorRegistry,
    seeds: &[u8],
    weight: u64,
    generation_number: u64,
) -> (ValidatorRegistry, [u8; 32]) {
    let mut declared = policy(old.total_voting_weight().get());
    declared.f_b_new = 0;
    let set = AdmittedSet::admit(
        &declared,
        &candidates(seeds, weight),
        generation_number,
        0,
        Some(old),
    )
    .expect("admissible next set");
    let candidate = set.candidate_id(old.generation(), CheckpointHeight(0), old.set_root());
    (set.registry().clone(), candidate)
}

/// Transition candidate for an explicit closing height.
fn candidate_at(
    old: &ValidatorRegistry,
    next: &ValidatorRegistry,
    height: CheckpointHeight,
) -> [u8; 32] {
    candidate_id(old.generation(), height, next.set_root(), old.set_root())
}

fn closure_at(
    old: &ValidatorRegistry,
    next: &ValidatorRegistry,
    height: CheckpointHeight,
    candidate: [u8; 32],
    value_id: [u8; 32],
) -> GenerationClosure {
    GenerationClosure {
        height,
        generation: old.generation(),
        value_id,
        candidate_id: candidate,
        new_set_root: next.set_root(),
    }
}

// ---------------------------------------------------------------------------
// N-2 — the strict byzantine bound
// ---------------------------------------------------------------------------

#[test]
fn bm_01_composition_bound_is_strict_at_w_divisible_by_three() {
    // W = 3: floor((3 - 1) / 3) = 0. The old bound `W - Q = 3 - 2 = 1`
    // admitted a fully byzantine set at the boundary.
    assert!(admit(&[(1, 1), (2, 1), (3, 1)], 0, 100, 1).is_ok());
    assert!(matches!(
        admit(&[(1, 1), (2, 1), (3, 1)], 1, 100, 1),
        Err(TransitionError::Composition {
            declared: 1,
            bound: 0
        })
    ));

    // W = 6: floor(5 / 3) = 1. The old bound `W - Q = 2` admitted f = 2 = W/3.
    assert!(admit(&[(1, 2), (2, 2), (3, 2)], 1, 100, 1).is_ok());
    assert!(matches!(
        admit(&[(1, 2), (2, 2), (3, 2)], 2, 100, 1),
        Err(TransitionError::Composition {
            declared: 2,
            bound: 1
        })
    ));

    // W = 9: floor(8 / 3) = 2, while W/3 = 3 is refused.
    assert!(admit(&[(1, 3), (2, 3), (3, 3)], 2, 100, 1).is_ok());
    assert!(matches!(
        admit(&[(1, 3), (2, 3), (3, 3)], 3, 100, 1),
        Err(TransitionError::Composition {
            declared: 3,
            bound: 2
        })
    ));
}

#[test]
fn bm_02_composition_bound_handles_indivisible_totals_and_dominant_weights() {
    // W = 4: floor(3 / 3) = 1.
    assert!(admit(&[(1, 1), (2, 1), (3, 1), (4, 1)], 1, 100, 1).is_ok());
    assert!(matches!(
        admit(&[(1, 1), (2, 1), (3, 1), (4, 1)], 2, 100, 1),
        Err(TransitionError::Composition {
            declared: 2,
            bound: 1
        })
    ));

    // W = 5: floor(4 / 3) = 1.
    assert!(matches!(
        admit(&[(1, 2), (2, 2), (3, 1)], 2, 100, 1),
        Err(TransitionError::Composition {
            declared: 2,
            bound: 1
        })
    ));

    // Dominant validator, W = 9: a declared faulty weight of 7 (the dominant
    // validator alone) is refused; the bound is floor(8/3) = 2.
    let dominant = [(1u8, 7u64), (2, 1), (3, 1)];
    assert!(matches!(
        admit(&dominant, 7, 100, 1),
        Err(TransitionError::Composition {
            declared: 7,
            bound: 2
        })
    ));
    assert!(admit(&dominant, 2, 100, 1).is_ok());

    // W = 13, weights 10/1/1/1: the bound is a *weight* (4), not the number of
    // validators minus one (3). Declaring 4 is safe: 3·4 = 12 < 13.
    let skewed = [(1u8, 10u64), (2, 1), (3, 1), (4, 1)];
    assert!(admit(&skewed, 4, 100, 1).is_ok());
    assert!(matches!(
        admit(&skewed, 5, 100, 1),
        Err(TransitionError::Composition {
            declared: 5,
            bound: 4
        })
    ));
}

#[test]
fn bm_03_zero_weight_and_overflow_are_refused() {
    // A zero-weight member is not silently included: the registry cannot carry
    // a validator that never contributes to a quorum.
    assert!(matches!(
        admit(&[(1, 1), (2, 0), (3, 1)], 0, 100, 0),
        Err(TransitionError::Ledger(_))
    ));

    // A total above `u64::MAX` is refused, not wrapped.
    let half = u64::MAX / 2 + 1;
    assert!(matches!(
        admit(&[(1, half), (2, half)], 0, u64::MAX, 1),
        Err(TransitionError::TotalWeightOutOfRange { .. })
    ));

    // Weights close to `u64::MAX` still produce an exact strict bound, with no
    // intermediate division or multiplication overflow.
    let m = (u64::MAX - 1) / 3;
    let total = 3 * m;
    let bound = (total - 1) / 3;
    assert!(admit(&[(1, m), (2, m), (3, m)], bound, u64::MAX, 1).is_ok());
    assert!(matches!(
        admit(&[(1, m), (2, m), (3, m)], bound + 1, u64::MAX, 1),
        Err(TransitionError::Composition { .. })
    ));
    assert!(3 * bound < total);
}

#[test]
fn bm_04_decision_quorums_intersect_above_the_strict_third() {
    for total in 1u64..500 {
        let weight = ValidatorWeight(total);
        let quorum = quorum_threshold(weight).get();
        assert!(quorum_met(ValidatorWeight(quorum), weight));
        // Two decision quorums intersect in at least `2Q - W`.
        let intersection = 2 * quorum as i128 - total as i128;
        assert!(intersection >= 1, "W={total} Q={quorum}");
        // `Q = ceil(2W/3)` implies `2Q - W >= ceil(W/3) > floor((W-1)/3)`.
        let bound = (total - 1) / 3;
        assert!(3 * bound < total);
        assert!(
            intersection > bound as i128,
            "W={total} Q={quorum} intersection={intersection} f={bound}"
        );
        // At 3 | W the old boundary f = W/3 equals the intersection, which is
        // exactly why the strict bound is required.
        if total % 3 == 0 {
            assert_eq!(intersection, (total / 3) as i128);
            assert_eq!(bound, total / 3 - 1);
        }
    }
}

// ---------------------------------------------------------------------------
// N-6 — installation is mandatory before the next height
// ---------------------------------------------------------------------------

/// Decide a transition at height 0 on every engine, without installing it.
fn decided_transition() -> (
    Cluster,
    ValidatorRegistry,
    [u8; 32],
    Checkpoint,
    PrecommitCertificate,
) {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (next, _) = next_registry(&old, &[1, 2, 3, 4], 10, 1);
    let candidate = candidate_at(&old, &next, CheckpointHeight(0));
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    (cluster, next, candidate, cp, cert)
}

#[test]
fn bm_05_decided_closure_blocks_advance_and_direct_decision() {
    let (mut cluster, next, candidate, cp, cert) = decided_transition();
    let old = cluster.registry.clone();

    // Every engine refuses to move above the closing height.
    for i in 0..cluster.len() {
        match cluster.engines[i].advance_height(CheckpointHeight(1), &cluster.stores[i]) {
            Err(BftError::InstallationRequired { height: 1 }) => {}
            other => panic!("validator {i}: expected InstallationRequired, got {other:?}"),
        }
    }

    // A caller that forces the height anyway cannot decide at h_close + 1: the
    // engine guard runs before any certificate check.
    let mut forced = cluster.engines[0].clone();
    forced.height = CheckpointHeight(1);
    let cp1 = Checkpoint::new(
        cluster.registry.generation(),
        CheckpointHeight(1),
        cp.id(),
        [0x44u8; 32],
        [0x55u8; 32],
        cluster.registry.set_root(),
        None,
    )
    .expect("checkpoint");
    match forced.finalize(
        &cert,
        &cp1,
        Some(&cp),
        &cluster.registry,
        &cluster.stores[0],
    ) {
        Err(BftError::InstallationRequired { height: 1 }) => {}
        other => panic!("expected InstallationRequired, got {other:?}"),
    }
    // ... and it cannot sign either, even with the old generation still active
    // in the ledger.
    assert!(matches!(
        forced.may_sign(),
        Err(BftError::InstallationRequired { .. })
    ));

    // The obligation is installable and yields the next generation.
    cluster.engines[0]
        .close_generation(
            closure_at(&old, &next, CheckpointHeight(0), candidate, cp.id()),
            &next,
            &cluster.stores[0],
        )
        .expect("installation");
    assert_eq!(cluster.engines[0].generation, next.generation());
    assert!(cluster.engines[0].may_sign().is_err(), "closed at h_close");
    cluster.engines[0]
        .advance_height(CheckpointHeight(1), &cluster.stores[0])
        .expect("activation height");
    assert!(cluster.engines[0].may_sign().is_ok());
}

#[test]
fn bm_06_installation_requires_the_certified_candidate() {
    let (mut cluster, next, candidate, cp, _cert) = decided_transition();
    let old = cluster.registry.clone();

    // A different registry for the same position: its candidate id is not the
    // one the decided checkpoint committed, so the closure is refused.
    let (foreign, _) = next_registry(&old, &[5, 6, 7, 8], 10, 1);
    assert!(matches!(
        cluster.engines[0].close_generation(
            closure_at(&old, &foreign, CheckpointHeight(0), candidate, [0u8; 32]),
            &foreign,
            &cluster.stores[0]
        ),
        Err(BftError::Rejected(_))
    ));
    assert_eq!(cluster.engines[0].generation, old.generation());

    // A closure with an arbitrary candidate id for the right registry is also
    // refused.
    assert!(matches!(
        cluster.engines[0].close_generation(
            GenerationClosure {
                candidate_id: [0xEEu8; 32],
                ..closure_at(&old, &next, CheckpointHeight(0), candidate, [0u8; 32])
            },
            &next,
            &cluster.stores[0]
        ),
        Err(BftError::Rejected(_))
    ));

    // Clearing the in-memory obligation does not authorize a closure: the
    // engine has no certified pending installation to compare against.
    let mut forged = cluster.engines[0].clone();
    forged.pending_installs.clear();
    assert!(matches!(
        forged.close_generation(
            closure_at(&old, &next, CheckpointHeight(0), candidate, [0u8; 32]),
            &next,
            &cluster.stores[0]
        ),
        Err(BftError::Rejected(_))
    ));

    // The correct closure installs exactly once; a replay naming the closed
    // generation is refused before anything else happens.
    cluster.engines[0]
        .close_generation(
            closure_at(&old, &next, CheckpointHeight(0), candidate, cp.id()),
            &next,
            &cluster.stores[0],
        )
        .expect("installation");
    assert!(matches!(
        cluster.engines[0].close_generation(
            closure_at(&old, &next, CheckpointHeight(0), candidate, [0u8; 32]),
            &next,
            &cluster.stores[0]
        ),
        Err(BftError::ContextMismatch {
            field: "generation"
        })
    ));
    assert_eq!(cluster.engines[0].generation, next.generation());
}

#[test]
fn bm_07_restart_between_decision_and_installation_blocks_signing() {
    let (cluster, next, _candidate, cp, _cert) = decided_transition();

    // Restart at h_close + 1 with the old registry: the obligation survives,
    // and the engine refuses to sign.
    let restored = restore_engine(
        &cluster.stores[0],
        &cluster.registry,
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert_eq!(restored.state.generation, cluster.registry.generation());
    assert!(matches!(
        restored.state.may_sign(),
        Err(BftError::InstallationRequired { .. })
    ));
    assert!(restored
        .state
        .pending_installs
        .contains_key(&CheckpointHeight(0)));

    // Restart at h_close, then try to advance: still refused.
    let mut restored = restore_engine(
        &cluster.stores[0],
        &cluster.registry,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert!(matches!(
        restored
            .state
            .advance_height(CheckpointHeight(1), &cluster.stores[0]),
        Err(BftError::InstallationRequired { .. })
    ));

    // The installed registry is the successor, but it is not sufficient while
    // the ledger has no closure.
    let restored = restore_engine(
        &cluster.stores[0],
        &next,
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert!(restored.state.may_sign().is_err());
}

#[test]
fn bm_08_restart_after_installation_restores_the_new_generation() {
    let (mut cluster, next, candidate, cp, _cert) = decided_transition();
    let old = cluster.registry.clone();
    cluster.engines[0]
        .close_generation(
            closure_at(&old, &next, CheckpointHeight(0), candidate, cp.id()),
            &next,
            &cluster.stores[0],
        )
        .expect("installation");
    cluster.engines[0]
        .advance_height(CheckpointHeight(1), &cluster.stores[0])
        .expect("advance");

    let restored = restore_engine(
        &cluster.stores[0],
        &next,
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert_eq!(restored.state.generation, next.generation());
    assert_eq!(restored.state.set_root, next.set_root());
    assert_eq!(restored.state.ledger.closures.len(), 1);
    assert!(restored.state.may_sign().is_ok());

    // The same store handed the closed generation is refused, not rolled back.
    let stale = restore_engine(
        &cluster.stores[0],
        &old,
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert!(stale.state.may_sign().is_err());
}

#[test]
fn bm_09_a_normal_checkpoint_creates_no_installation_obligation() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let cp = cluster.checkpoint(0, None);
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);

    assert!(cluster.engines[0].pending_installs.is_empty());
    cluster.advance_all(CheckpointHeight(1));
    assert!(cluster.engines[0].may_sign().is_ok());
    assert!(cluster.engines[0]
        .finalize(&cert, &cp, None, &cluster.registry, &cluster.stores[0])
        .is_err());
}

#[test]
fn bm_10_three_generations_keep_one_obligation_per_closure() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let gen0 = cluster.registry.clone();

    // Generation 0 closes at height 0.
    let (gen1, _) = next_registry(&gen0, &[1, 2, 3, 4], 10, 1);
    let cand0 = candidate_at(&gen0, &gen1, CheckpointHeight(0));
    let cp0 = cluster.checkpoint(0, Some(cand0));
    let cert0 = cluster.run_cycle(cp0.id());
    cluster.finalize_all(&cert0, &cp0);
    cluster.close_all(closure_at(&gen0, &gen1, CheckpointHeight(0), cand0, cp0.id()), &gen1);

    // A normal checkpoint at height 1 does not close anything.
    let cp1 = cluster.checkpoint(1, None);
    let cert1 = cluster.run_cycle(cp1.id());
    cluster.finalize_all(&cert1, &cp1);
    cluster.advance_all(CheckpointHeight(2));

    // Generation 1 closes at height 2.
    let (gen2, _) = next_registry(&gen1, &[1, 2, 3, 4], 10, 2);
    let cand1 = candidate_at(&gen1, &gen2, CheckpointHeight(2));
    let cp2 = cluster.checkpoint(2, Some(cand1));
    let cert2 = cluster.run_cycle(cp2.id());
    cluster.finalize_all(&cert2, &cp2);
    cluster.close_all(closure_at(&gen1, &gen2, CheckpointHeight(2), cand1, cp2.id()), &gen2);

    assert_eq!(cluster.height, CheckpointHeight(3));
    assert_eq!(cluster.engines[0].ledger.closures.len(), 2);
    assert_eq!(cluster.engines[0].generation, gen2.generation());
    assert!(cluster.engines[0].may_sign().is_ok());
    assert!(cluster.engines[0]
        .pending_installs
        .values()
        .all(|record| record.installed));
    assert_eq!(cluster.engines[0].pending_installs.len(), 2);

    let restored = restore_engine(
        &cluster.stores[0],
        &gen2,
        Some(ANCHOR),
        NET,
        CheckpointHeight(3),
    );
    assert_eq!(restored.state.ledger.closures.len(), 2);
    assert_eq!(restored.state.generation, gen2.generation());
    assert!(restored.state.may_sign().is_ok());
}

// ---------------------------------------------------------------------------
// E-1 — an ineligible entry is never elected
// ---------------------------------------------------------------------------

fn registry_with_status(
    generation: [u8; 32],
    members: &[(u8, u64, Admissibility)],
) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = members
        .iter()
        .map(|(seed, weight, status)| {
            RegistryEntry::new(
                sk(*seed).verifying_key().to_bytes(),
                ValidatorWeight(*weight),
                *status,
            )
        })
        .collect();
    ValidatorRegistry::new(GenerationId(generation), &entries).expect("registry")
}

fn mark_first_ineligible(entries: &mut [RegistryEntry], status: Admissibility) -> ValidatorId {
    entries.sort_by_key(|entry| entry.id);
    entries[0].admissibility = status;
    entries[0].id
}

#[test]
fn bm_20_ineligible_entries_are_never_elected() {
    let mut entries: Vec<RegistryEntry> = [1u8, 2, 3, 4]
        .iter()
        .map(|seed| {
            RegistryEntry::new(
                sk(*seed).verifying_key().to_bytes(),
                ValidatorWeight(if *seed == 1 { 100 } else { 1 }),
                Admissibility::Eligible,
            )
        })
        .collect();
    let ineligible = mark_first_ineligible(&mut entries, Admissibility::Suspended);
    let registry = ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry");
    let eligible_total = registry.total_voting_weight().get();

    for round in 0..500u32 {
        let choice = proposer_for(
            &registry,
            registry.generation(),
            CheckpointHeight(0),
            aether_unified::consensus::generation::Round(round),
        )
        .expect("a proposer");
        assert_ne!(choice.validator, ineligible, "round {round}");
        assert!(registry.voting_weight(&choice.validator).is_some());
        assert_eq!(choice.total, eligible_total);
        assert_eq!(
            choice.weight,
            registry.voting_weight(&choice.validator).unwrap().get()
        );
    }

    // Every eligible member keeps its correct share; the ineligible one gets 0.
    let counts = distribution(&registry, registry.generation(), CheckpointHeight(0), 2_000);
    let mut eligible_sum = 0u64;
    for (id, count) in &counts {
        if *id == ineligible {
            assert_eq!(*count, 0);
        } else {
            eligible_sum += *count;
        }
    }
    assert_eq!(eligible_sum, 2_000);
}

#[test]
fn bm_21_an_ineligible_dominant_entry_cannot_shadow_the_only_eligible() {
    // The old rule walked every entry while dividing by the eligible weight.
    // With one eligible weight-1 entry and one ineligible weight-100 entry,
    // every slot fell in the ineligible interval. It must never be elected now.
    let mut entries = vec![
        RegistryEntry::new(
            sk(9).verifying_key().to_bytes(),
            ValidatorWeight(100),
            Admissibility::Eligible,
        ),
        RegistryEntry::new(
            sk(3).verifying_key().to_bytes(),
            ValidatorWeight(1),
            Admissibility::Eligible,
        ),
    ];
    // The dominant entry is the ineligible one, whatever the canonical order.
    let ineligible = entries
        .iter_mut()
        .find(|entry| entry.weight.get() == 100)
        .map(|entry| {
            entry.admissibility = Admissibility::Removed;
            entry.id
        })
        .expect("the dominant entry");
    let registry = ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry");
    for round in 0..2_000u32 {
        let choice = proposer_for(
            &registry,
            registry.generation(),
            CheckpointHeight(0),
            aether_unified::consensus::generation::Round(round),
        )
        .expect("a proposer");
        assert_ne!(choice.validator, ineligible);
        assert_eq!(choice.total, 1);
        assert_eq!(choice.weight, 1);
    }
}

#[test]
fn bm_22_every_slot_has_exactly_one_eligible_owner() {
    let mut entries: Vec<RegistryEntry> = (1u8..=6)
        .map(|seed| {
            RegistryEntry::new(
                sk(seed).verifying_key().to_bytes(),
                ValidatorWeight(seed as u64),
                Admissibility::Eligible,
            )
        })
        .collect();
    let ineligible = mark_first_ineligible(&mut entries, Admissibility::Suspended);
    let registry = ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry");
    let total = registry.total_voting_weight().get();
    // Each position is a deterministic draw; across enough positions every slot
    // range is exercised. Every answer is eligible and within the registry.
    let mut seen = std::collections::BTreeSet::new();
    for round in 0..10_000u32 {
        let choice = proposer_for(
            &registry,
            registry.generation(),
            CheckpointHeight(u64::from(round % 7)),
            aether_unified::consensus::generation::Round(round),
        )
        .expect("a proposer");
        assert_ne!(choice.validator, ineligible);
        assert!(choice.index < registry.len());
        assert!(choice.draw % choice.total == choice.draw % total);
        seen.insert(choice.validator);
    }
    assert_eq!(seen.len(), registry.len() - 1);
}
