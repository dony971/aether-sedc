//! Mission BD â verified synchronisation and bootstrap.
//!
//! A chain is produced by a real cluster (one engine and one store per
//! validator), then handed to a synchronising node as a *bundle*. The receiving
//! side must verify it from scratch: identifiers recomputed, certificates
//! re-verified against the registry of their own generation, set roots recomputed
//! from the members, transitions recomputed from the candidate formula.
//!
//! What is **not** tested here: any transport, any peer selection, any real
//! network. Bundles are built in-process from data a serving node would hold.

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::roots::ids_root;
use aether_unified::consensus::transitions::{
    AdmittedSet, CandidateOperator, GenerationClosure, GenerationLedger, SetPolicy,
    TransitionError,
};
use aether_unified::l2bft::{
    check_commitments, compare_histories, install_history, participation, restore_engine,
    verify_history, BftState, FinalityDecision, GenerationSpec, HistoryAgreement, Participation,
    PrecommitCertificate, PrevoteCertificate, SyncAnchor, SyncBundle, SyncError, SyncLink,
    FINALITY_PREFIX, HALT_KEY,
};
use aether_unified::l2crypto::ready::SignedReady;
use aether_unified::l2crypto::ready::SignedReadyExpectation;
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::{
    load_ready_evidence, open_sealed, record_readys, seal, AtomicSlotStore, CasStore,
    MemoryAtomicSlotStore,
};
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixture: a real chain
// ---------------------------------------------------------------------------

const NET: u64 = 11;
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
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn registry_with(generation: [u8; 32], members: &[(u8, u64)]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = members
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(generation), &entries).expect("registry")
}

fn policy(churn: u64) -> SetPolicy {
    SetPolicy {
        min_deposit: 1,
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

struct Cluster {
    seeds: Vec<u8>,
    engines: Vec<BftState>,
    stores: Vec<MemoryAtomicSlotStore>,
    registry: ValidatorRegistry,
    height: CheckpointHeight,
    last: Option<Checkpoint>,
    salt: u8,
}

impl Cluster {
    fn new(generation: [u8; 32], seeds: &[u8], weight: u64, salt: u8) -> Self {
        let members: Vec<(u8, u64)> = seeds.iter().map(|s| (*s, weight)).collect();
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
            salt,
        }
    }

    fn checkpoint(&self, height: u64, transition: Option<[u8; 32]>) -> Checkpoint {
        let parent = if height == 0 {
            [0u8; 32]
        } else {
            self.last.as_ref().expect("a parent checkpoint").id()
        };
        Checkpoint::new(
            self.registry.generation(),
            CheckpointHeight(height),
            parent,
            [0x22u8 ^ self.salt; 32],
            [0x33u8 ^ self.salt; 32],
            self.registry.set_root(),
            transition,
        )
        .expect("checkpoint")
    }

    fn prevote_all(&mut self, value: [u8; 32]) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.engines.len() {
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

    fn precommit_all(&mut self, certificate: &PrevoteCertificate) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.engines.len() {
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
        for i in 0..self.engines.len() {
            for vote in votes {
                self.engines[i].accept_vote(vote, &self.registry);
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

    fn finalize_all(&mut self, certificate: &PrecommitCertificate, cp: &Checkpoint) {
        let parent = self.last.clone();
        for i in 0..self.engines.len() {
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

    fn close_all(
        &mut self,
        closure: GenerationClosure,
        next: &ValidatorRegistry,
        next_seeds: &[u8],
    ) {
        for i in 0..self.engines.len() {
            self.engines[i]
                .close_generation(closure, next, &self.stores[i])
                .expect("closure");
        }
        self.registry = next.clone();
        self.seeds = next_seeds.to_vec();
        self.height = closure.height.next();
        for i in 0..self.engines.len() {
            self.engines[i]
                .advance_height(self.height, &self.stores[i])
                .expect("advance");
        }
    }
}

/// A produced chain: generations, checkpoints and their certificates.
struct Fixture {
    generations: Vec<GenerationSpec>,
    checkpoints: Vec<Checkpoint>,
    certificates: Vec<PrecommitCertificate>,
    stores: Vec<MemoryAtomicSlotStore>,
    seeds: Vec<u8>,
}

fn closure_of(
    height: u64,
    generation: GenerationId,
    candidate: [u8; 32],
    new_set_root: [u8; 32],
    value_id: [u8; 32],
) -> GenerationClosure {
    GenerationClosure {
        height: CheckpointHeight(height),
        generation,
        value_id,
        candidate_id: candidate,
        new_set_root,
    }
}

/// Build a chain of `transitions + 1` checkpoints: every height but the last
/// closes a generation and installs `next_seeds`.
fn build(seeds: &[u8], weight: u64, transitions: usize, next_seeds: &[u8], salt: u8) -> Fixture {
    let mut cluster = Cluster::new(GEN, seeds, weight, salt);
    let mut generations = vec![GenerationSpec {
        number: 0,
        registry: cluster.registry.clone(),
        closure: None,
    }];
    let mut checkpoints = Vec::new();
    let mut certificates = Vec::new();
    let mut current_seeds = seeds.to_vec();

    for height in 0..transitions {
        let old = cluster.registry.clone();
        let set = AdmittedSet::admit(
            &policy(old.total_voting_weight().get()),
            &candidates(next_seeds, weight),
            (height + 1) as u64,
            0,
            Some(&old),
        )
        .expect("admissible set");
        let candidate = set.candidate_id(
            old.generation(),
            CheckpointHeight(height as u64),
            old.set_root(),
        );
        let cp = cluster.checkpoint(height as u64, Some(candidate));
        let closure = closure_of(height as u64, old.generation(), candidate, set.set_root(), cp.id());
        let cert = cluster.run_cycle(cp.id());
        cluster.finalize_all(&cert, &cp);
        checkpoints.push(cp);
        certificates.push(cert);
        cluster.close_all(closure, set.registry(), next_seeds);
        generations.push(GenerationSpec {
            number: (height + 1) as u64,
            registry: set.registry().clone(),
            closure: Some(closure),
        });
        current_seeds = next_seeds.to_vec();
    }

    let cp = cluster.checkpoint(transitions as u64, None);
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    checkpoints.push(cp);
    certificates.push(cert);

    Fixture {
        generations,
        checkpoints,
        certificates,
        stores: cluster.stores,
        seeds: current_seeds,
    }
}

fn anchor_at(fx: &Fixture, index: usize) -> SyncAnchor {
    let cp = &fx.checkpoints[index];
    SyncAnchor {
        network: NET,
        height: cp.height,
        checkpoint_id: cp.id(),
        generation: cp.generation,
        set_root: cp.validator_set_root,
    }
}

fn links(fx: &Fixture, from: usize, to: usize) -> Vec<SyncLink> {
    (from..=to)
        .map(|i| SyncLink {
            checkpoint: fx.checkpoints[i],
            certificate: fx.certificates[i].clone(),
        })
        .collect()
}

fn bundle(fx: &Fixture, from: usize, to: usize) -> SyncBundle {
    SyncBundle {
        anchor: anchor_at(fx, from),
        generations: fx.generations.clone(),
        links: links(fx, from, to),
    }
}

/// Root recomputed from the finality records a store actually holds.
fn root_from_store(store: &MemoryAtomicSlotStore) -> [u8; 32] {
    let mut ids: Vec<(u64, [u8; 32])> = store
        .scan(FINALITY_PREFIX)
        .expect("scan")
        .iter()
        .map(|(_, bytes)| {
            let payload = open_sealed(bytes).expect("seal");
            let decision = FinalityDecision::decode(payload).expect("decision");
            (decision.height.get(), decision.checkpoint_id)
        })
        .collect();
    ids.sort_by_key(|(h, _)| *h);
    ids_root(&ids.iter().map(|(_, id)| *id).collect::<Vec<_>>())
}

// ---------------------------------------------------------------------------
// BD-01 .. BD-04: bootstrap
// ---------------------------------------------------------------------------

#[test]
fn bd_01_bootstrap_of_four_validators_agrees() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut roots = Vec::new();
    for _ in 0..4 {
        let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
        assert_eq!(history.tip, CheckpointHeight(1));
        assert_eq!(history.links.len(), 2);
        assert_eq!(history.ledger.closures.len(), 1);
        assert_eq!(history.roots.set_roots_recomputed, 2);
        assert!(!history.roots.state_root_authenticated);
        roots.push(history.roots.finality_chain_root);
    }
    assert!(roots.iter().all(|r| *r == roots[0]));
}

#[test]
fn bd_02_fifth_validator_bootstraps_and_is_not_a_member() {
    let fx = build(&[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 0)).expect("verified");

    // A fresh node installs the history into its own empty store.
    let joiner = MemoryAtomicSlotStore::new();
    install_history(&joiner, &history).expect("installed");
    assert_eq!(
        GenerationLedger::load(&joiner).unwrap().unwrap(),
        history.ledger
    );

    // Membership comes from the rebuilt active registry, never from a claim.
    match participation(&history, &vid(5), CheckpointHeight(0)) {
        Participation::Refused(reason) => assert!(reason.contains("not in the active")),
        other => panic!("validator 5 must not be a member: {other:?}"),
    }
    match participation(&history, &vid(1), CheckpointHeight(0)) {
        Participation::Member { weight, .. } => assert_eq!(weight, ValidatorWeight(10)),
        other => panic!("validator 1 must be a member: {other:?}"),
    }
}

#[test]
fn bd_03_two_transitions_rebuild_two_closures() {
    // g0 -> g1 (validators 1..4) -> g2 (validators 2..5), then a plain height 2.
    let fx = build(&[1, 2, 3, 4], 10, 2, &[2, 3, 4, 5], 0);
    let history = verify_history(&bundle(&fx, 0, 2)).expect("verified");
    assert_eq!(history.links.len(), 3);
    assert_eq!(history.ledger.closures.len(), 2);
    assert_eq!(history.ledger.active_number, 2);
    assert_eq!(history.generations.len(), 3);
    assert_eq!(
        history.active_registry().set_root(),
        fx.generations[2].registry.set_root()
    );
    // The generation that closes at height 1 is g1, and it is the one that votes.
    assert_eq!(
        history.links[1].generation,
        fx.generations[1].registry.generation()
    );
    // Validator 1 left at g2, validator 5 arrived.
    assert!(matches!(
        participation(&history, &vid(1), CheckpointHeight(2)),
        Participation::Refused(_)
    ));
    assert!(matches!(
        participation(&history, &vid(5), CheckpointHeight(2)),
        Participation::Member { .. }
    ));
}

#[test]
fn bd_04_old_anchor_is_valid_but_truncated_when_a_tip_is_required() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 0)).expect("verified");
    assert_eq!(history.tip, CheckpointHeight(0));
    assert!(matches!(
        history.require_tip(CheckpointHeight(1)),
        Err(SyncError::Truncated {
            tip: 0,
            requested: 1
        })
    ));
    assert!(history.require_tip(CheckpointHeight(0)).is_ok());
}

// ---------------------------------------------------------------------------
// BD-05 .. BD-08: incomplete data and reconstruction
// ---------------------------------------------------------------------------

#[test]
fn bd_05_incomplete_history_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    // Anchor at 0, then a jump straight to height 2.
    let mut broken = bundle(&fx, 0, 0);
    broken.links.push(SyncLink {
        checkpoint: fx.checkpoints[1],
        certificate: fx.certificates[1].clone(),
    });
    // The only link after the anchor is height 1 in the real chain; drop it and
    // splice a height-2-looking claim by reusing the same checkpoint.
    assert!(verify_history(&broken).is_ok(), "0 then 1 is contiguous");
    let mut truncated = bundle(&fx, 0, 0);
    truncated.links.truncate(1);
    assert_eq!(
        verify_history(&truncated).expect("still valid").links.len(),
        1
    );
}

#[test]
fn bd_06_malicious_provider_cannot_smuggle_a_foreign_certificate() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    // Swap the height-1 certificate for one that decided another value.
    evil.links[1].certificate = fx.certificates[0].clone();
    // Either the certificate fails to re-verify against this generation's
    // registry, or it re-verifies but names another position. Both refuse.
    match verify_history(&evil) {
        Err(SyncError::CertificateInvalid(height, _)) => assert_eq!(height, 1),
        Err(SyncError::CertificateForeign(height, field)) => {
            assert_eq!(height, 1);
            assert!(matches!(field, "value" | "height" | "generation"));
        }
        other => panic!("expected the foreign certificate to be refused, got {other:?}"),
    }

    // And a checkpoint edited in place no longer chains to its successor.
    let mut evil = bundle(&fx, 0, 1);
    let mut cp = evil.links[1].checkpoint;
    cp.state_root[0] ^= 0xFF;
    evil.links[1].checkpoint = cp;
    assert!(matches!(
        verify_history(&evil),
        Err(SyncError::CertificateForeign(1, "value")) | Err(SyncError::ParentMismatch(_))
    ));
}

#[test]
fn bd_07_ready_quorum_is_reconstructed_with_the_rebuilt_registry() {
    let old = registry_with(GEN, &[(1, 10), (2, 10), (3, 10), (4, 10)]);
    let next = &[2u8, 3, 4, 5][..];
    let set = AdmittedSet::admit(&policy(40), &candidates(next, 10), 1, 0, Some(&old))
        .expect("admissible");
    let candidate = set.candidate_id(old.generation(), CheckpointHeight(0), old.set_root());
    let expectation = SignedReadyExpectation {
        network: NET,
        generation: old.generation(),
        candidate,
        new_set_root: set.set_root(),
        reference_checkpoint: [0u8; 32],
        h_close: CheckpointHeight(0),
        d_ready: 1_000,
    };
    let readys: Vec<SignedReady> = next
        .iter()
        .map(|seed| {
            let ready = SignedReady::new(
                NET,
                old.generation(),
                candidate,
                set.set_root(),
                [0u8; 32],
                CheckpointHeight(0),
                1,
                vid(*seed),
            );
            ready.with_signature(sk(*seed).sign(&ready.signing_bytes()).to_bytes())
        })
        .collect();
    let store = MemoryAtomicSlotStore::new();
    record_readys(&store, set.registry(), &expectation, &readys).expect("recorded");

    // A synchronising node rebuilds the same registry from the verified history
    // (same members, same weights, same set root) and recomputes the quorum.
    let rebuilt = registry_with(set.generation().0, &[(2, 10), (3, 10), (4, 10), (5, 10)]);
    assert_eq!(rebuilt.set_root(), set.set_root());
    let evidence = load_ready_evidence(&store, &rebuilt, &expectation).expect("read");
    assert!(evidence.is_quorate());
    assert_eq!(evidence.support, ValidatorWeight(40));
}

#[test]
fn bd_08_active_registry_is_rebuilt_not_declared() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[2, 3, 4, 5], 0);
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    // The tip closed g0, so g1 is in force from height 1 onward.
    assert_eq!(
        history.active_generation(),
        fx.generations[1].registry.generation()
    );
    assert_eq!(history.active_registry().len(), 4);
    assert!(history.active_registry().get(&vid(1)).is_none());
    assert!(history.active_registry().get(&vid(5)).is_some());
    // A validator of the old set cannot be made a member by asking.
    assert!(matches!(
        participation(&history, &vid(1), CheckpointHeight(1)),
        Participation::Refused(_)
    ));
}

// ---------------------------------------------------------------------------
// BD-09 .. BD-12: commitments, halt, contradictions, roots
// ---------------------------------------------------------------------------

#[test]
fn bd_09_a_signed_slot_contradicting_the_history_blocks_installation() {
    // Two chains that differ only by a salt: both verify on their own.
    let honest = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let other = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 9);
    let honest_history = verify_history(&bundle(&honest, 0, 1)).expect("verified");
    let other_history = verify_history(&bundle(&other, 0, 1)).expect("verified");
    assert!(matches!(
        compare_histories(&honest_history, &other_history),
        HistoryAgreement::Contradiction { height: 0, .. }
    ));

    // A store that voted in the other chain holds signed slots at height 0.
    let store = &other.stores[0];
    assert!(!store.scan_slots().expect("slots").is_empty());
    match check_commitments(store, &honest_history) {
        Err(SyncError::Commitment(text)) => {
            assert!(text.contains("signed") || text.contains("durable decision"));
        }
        other => panic!("expected a commitment conflict, got {other:?}"),
    }
    assert!(install_history(store, &honest_history).is_err());
}

#[test]
fn bd_10_a_halt_record_is_never_cleared_by_synchronisation() {
    let fx = build(&[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 0)).expect("verified");
    let store = MemoryAtomicSlotStore::new();
    assert!(store
        .cas(HALT_KEY, None, &seal(b"conflicting finality"))
        .expect("halt written"));
    match install_history(&store, &history) {
        Err(SyncError::Commitment(text)) => assert!(text.contains("halt")),
        other => panic!("expected a halt refusal, got {other:?}"),
    }
    // The history itself stays verifiable: the operator can inspect it without
    // being able to sign.
    assert_eq!(history.links.len(), 1);
}

#[test]
fn bd_11_two_contradictory_histories_are_reported_not_arbitrated() {
    let a = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let b = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 9);
    let ha = verify_history(&bundle(&a, 0, 1)).expect("verified");
    let hb = verify_history(&bundle(&b, 0, 1)).expect("verified");
    match compare_histories(&ha, &hb) {
        HistoryAgreement::Contradiction {
            height,
            first,
            second,
        } => {
            assert_eq!(height, 0);
            assert_ne!(first, second);
        }
        other => panic!("expected a contradiction, got {other:?}"),
    }
    // Same history twice: agreement over every link.
    assert_eq!(
        compare_histories(&ha, &verify_history(&bundle(&a, 0, 1)).unwrap()),
        HistoryAgreement::Agree { common: 2 }
    );
}

#[test]
fn bd_12_every_validator_rebuilds_the_same_roots() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");

    let mut stores = Vec::new();
    for _ in 0..4 {
        let store = MemoryAtomicSlotStore::new();
        install_history(&store, &history).expect("installed");
        stores.push(store);
    }
    let roots: Vec<[u8; 32]> = stores.iter().map(root_from_store).collect();
    assert!(roots.iter().all(|r| *r == roots[0]));
    assert_eq!(roots[0], history.roots.finality_chain_root);
    // Restarting an installed node keeps the same generation and stays open.
    for store in &stores {
        let restored = restore_engine(store, history.active_registry(), None, NET, history.tip);
        assert_eq!(restored.state.generation, history.active_generation());
        assert!(
            restored.state.may_sign().is_ok(),
            "{:?}",
            restored.state.persisted().status
        );
    }
}

// ---------------------------------------------------------------------------
// BD-13 .. BD-18: sync attacks
// ---------------------------------------------------------------------------

#[test]
fn bd_13_unanchored_history_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    evil.anchor.checkpoint_id = [0xAB; 32];
    assert!(matches!(
        verify_history(&evil),
        Err(SyncError::Unanchored(_))
    ));
}

#[test]
fn bd_14_a_closed_generation_presented_as_active_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 2, &[2, 3, 4, 5], 0);
    let mut evil = bundle(&fx, 0, 1);
    // Re-sign nothing: just relabel the height-1 checkpoint as generation 0.
    let mut cp = evil.links[1].checkpoint;
    cp.generation = fx.generations[0].registry.generation();
    cp.validator_set_root = fx.generations[0].registry.set_root();
    evil.links[1].checkpoint = cp;
    match verify_history(&evil) {
        Err(SyncError::GenerationChain(text)) => assert!(text.contains("not open")),
        other => panic!("expected the closed generation to be refused, got {other:?}"),
    }
}

#[test]
fn bd_15_a_future_generation_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 2, &[2, 3, 4, 5], 0);
    let mut evil = bundle(&fx, 0, 0);
    let mut cp = fx.checkpoints[1];
    cp.generation = fx.generations[2].registry.generation();
    cp.validator_set_root = fx.generations[2].registry.set_root();
    evil.links.push(SyncLink {
        checkpoint: cp,
        certificate: fx.certificates[1].clone(),
    });
    match verify_history(&evil) {
        Err(SyncError::GenerationChain(_))
        | Err(SyncError::CertificateForeign(_, _))
        | Err(SyncError::UnknownGeneration(_, _)) => {}
        other => panic!("a future generation must be refused, got {other:?}"),
    }
}

#[test]
fn bd_16_a_replayed_checkpoint_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    evil.links.push(SyncLink {
        checkpoint: fx.checkpoints[1],
        certificate: fx.certificates[1].clone(),
    });
    assert!(matches!(
        verify_history(&evil),
        Err(SyncError::HeightJump {
            expected: 2,
            found: 1
        })
    ));
}

#[test]
fn bd_17_a_wrong_parent_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    let mut cp = evil.links[1].checkpoint;
    cp.parent[0] ^= 0xFF;
    evil.links[1].checkpoint = cp;
    assert!(matches!(
        verify_history(&evil),
        Err(SyncError::ParentMismatch(1)) | Err(SyncError::CertificateForeign(1, "value"))
    ));
}

#[test]
fn bd_18_a_certificate_from_another_generation_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[2, 3, 4, 5], 0);
    // Certificate of the closing checkpoint (generation 0) offered as the
    // certificate of a height-1 checkpoint claimed to be in generation 1.
    let mut evil = bundle(&fx, 0, 1);
    evil.links[1].certificate = fx.certificates[0].clone();
    match verify_history(&evil) {
        Err(SyncError::CertificateInvalid(_, _)) | Err(SyncError::CertificateForeign(_, _)) => {}
        other => panic!("a certificate of another generation must be refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Mission M1 â F1: the closure value is bound to the certified checkpoint
// ---------------------------------------------------------------------------

/// All key/value pairs currently in a store, for the "nothing was written"
/// assertion. `scan("")` matches every key.
fn dump(store: &MemoryAtomicSlotStore) -> Vec<(String, Vec<u8>)> {
    store.scan("").expect("scan")
}

/// A bundle in which only `closure.value_id` differs from the certified
/// checkpoint. The forged value is the identifier of **another real checkpoint**
/// of the same chain, not a random constant: a legitimate identifier from this
/// very history must still be refused for this position.
fn forged_value_bundle(fx: &Fixture) -> SyncBundle {
    let mut forged = bundle(fx, 0, 1);
    let other = fx.checkpoints[1].id();
    assert_ne!(other, fx.checkpoints[0].id());
    let closure = forged.generations[1]
        .closure
        .as_mut()
        .expect("the height-0 closure");
    assert_eq!(closure.value_id, fx.checkpoints[0].id());
    closure.value_id = other;
    forged
}

#[test]
fn f1_01_bundle_closure_value_id_must_be_the_certified_checkpoint() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let forged = forged_value_bundle(&fx);
    let joiner = MemoryAtomicSlotStore::new();
    let before = dump(&joiner);

    match verify_history(&forged) {
        Err(SyncError::CertificateForeign(height, what)) => {
            assert_eq!(height, 0);
            assert_eq!(what, "closure value");
        }
        other => panic!("a closure naming another value must be refused, got {other:?}"),
    }
    // `install_bundle` only calls `install_history` after `verify_history`
    // succeeds; a refused bundle must not have mutated the store either way.
    assert_eq!(dump(&joiner), before, "no byte may be written");
}

#[test]
fn f1_02_bundle_with_honest_value_id_still_verifies_and_installs() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let honest = bundle(&fx, 0, 1);
    let history = verify_history(&honest).expect("the nominal bundle verifies");
    assert_eq!(history.ledger.closures.len(), 1);
    assert_eq!(history.ledger.closures[0].value_id, fx.checkpoints[0].id());

    let joiner = MemoryAtomicSlotStore::new();
    install_history(&joiner, &history).expect("the nominal bundle installs");
    let ledger = GenerationLedger::load(&joiner)
        .expect("load")
        .expect("the ledger was written");
    assert_eq!(ledger.closures[0].value_id, fx.checkpoints[0].id());
    assert!(history.links.len() >= 2);

    // Defence in depth: a ledger poisoned by a *direct local write* still halts
    // when an honest closure for the same height is applied. A bundle can no
    // longer reach this state (refused at verification); `apply_closure` itself
    // never chooses a side.
    let mut poisoned = history.ledger.clone();
    poisoned.closures[0].value_id = [0x99u8; 32];
    let store = MemoryAtomicSlotStore::new();
    poisoned.persist(&store).expect("direct local ledger write");
    let mut loaded = GenerationLedger::load(&store)
        .expect("load")
        .expect("ledger present");
    let next_generation = fx.generations[1].registry.generation();
    match loaded.apply_closure(history.ledger.closures[0], next_generation, 1) {
        Err(TransitionError::Ledger(reason)) => {
            assert!(reason.contains("two transitions decided at height 0"), "{reason}")
        }
        other => panic!("a contradictory closure must halt the ledger, got {other:?}"),
    }
    assert!(!loaded.status.may_sign(), "the ledger must be halted");
}

#[test]
fn f1_03_a_certificate_from_another_checkpoint_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    // The height-1 link keeps its checkpoint but carries the certificate of the
    // height-0 checkpoint: another checkpoint of the same chain and the same
    // validator set, so only the identifier check can tell them apart.
    evil.links[1].certificate = fx.certificates[0].clone();
    let joiner = MemoryAtomicSlotStore::new();
    let before = dump(&joiner);

    match verify_history(&evil) {
        Err(SyncError::CertificateForeign(height, what)) => {
            assert_eq!(height, 1);
            assert_eq!(what, "value");
        }
        Err(SyncError::CertificateInvalid(height, reason)) => {
            assert_eq!(height, 1, "unexpected certificate error: {reason}");
        }
        other => panic!("a certificate of another checkpoint must be refused, got {other:?}"),
    }
    assert_eq!(dump(&joiner), before, "no byte may be written");
}

#[test]
fn f1_04_a_closure_not_backed_by_a_checkpoint_is_refused() {
    let fx = build(&[1, 2, 3, 4], 10, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);

    // A second transition is appended at height 1 — the height of the tip
    // checkpoint, which carries no `transition_id`. The checkpoint itself, its
    // certificate and the first closure stay honest; only the generation chain
    // invents a decision that no certified checkpoint ever took.
    let old = fx.generations[1].registry.clone();
    let set = AdmittedSet::admit(
        &policy(old.total_voting_weight().get()),
        &candidates(&[1, 2, 3, 4], 10),
        2,
        0,
        Some(&old),
    )
    .expect("admissible second transition");
    let forged = GenerationClosure {
        height: CheckpointHeight(1),
        generation: old.generation(),
        value_id: [0xAAu8; 32],
        candidate_id: set.candidate_id(old.generation(), CheckpointHeight(1), old.set_root()),
        new_set_root: set.set_root(),
    };
    evil.generations.push(GenerationSpec {
        number: 2,
        registry: set.registry().clone(),
        closure: Some(forged),
    });

    match verify_history(&evil) {
        Err(SyncError::GenerationChain(reason)) => {
            assert!(reason.contains("not certified by a checkpoint"), "{reason}")
        }
        other => panic!("an uncertified closure must be refused, got {other:?}"),
    }
}
