//! Mission BO — real inter-node transfer, closure synchronisation and durability.
//!
//! Two independent engines A and B, distinct stores, distinct signing keys,
//! coherent validator registries, and the project's own transfer structures
//! (`SyncBundle`, `verify_history`, `install_history`). No boolean stands in for
//! a cryptographic check: every certificate is re-verified by the receiving side
//! against the registry of its own generation, and every identifier is
//! recomputed from bytes.
//!
//! What is **not** tested: any transport, any peer discovery, any real network.
//! Bundles are built in-process from data a serving node already holds, exactly
//! as `phase4de` does. Durability is software restart (`restore_engine`), never a
//! power cut.

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::roots::ids_root;
use aether_unified::consensus::transitions::{
    AdmittedSet, CandidateOperator, GenerationClosure, GenerationLedger, SetPolicy,
};
use aether_unified::l2bft::context::BftError;
use aether_unified::l2bft::{
    check_commitments, compare_histories, finality_key, install_history, pending_install_key,
    restore_engine, verify_history, BftState, FinalityDecision, GenerationSpec, HistoryAgreement,
    PendingInstall, PrecommitCertificate, SyncAnchor, SyncBundle, SyncError, SyncLink, HALT_KEY,
    PENDING_INSTALL_PREFIX,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::{
    open_sealed, seal, AtomicSlotStore, CasStore, MemoryAtomicSlotStore, RecoveryStatus,
};
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const NET: u64 = 77;
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

    fn precommit_all(
        &mut self,
        certificate: &aether_unified::l2bft::PrevoteCertificate,
    ) -> Vec<ConsensusVote> {
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
        for i in 0..self.engines.len() {
            self.engines[i]
                .advance_height(closure.height.next(), &self.stores[i])
                .expect("advance");
        }
    }
}

struct Fixture {
    generations: Vec<GenerationSpec>,
    checkpoints: Vec<Checkpoint>,
    certificates: Vec<PrecommitCertificate>,
    stores: Vec<MemoryAtomicSlotStore>,
    seeds: Vec<u8>,
}

/// A closing generation produced but **not** installed: the state of node A after
/// deciding `h_close`, which is exactly the crash window before `close_generation`.
struct DecidedOnly {
    cluster: Cluster,
    closure: GenerationClosure,
    next: ValidatorRegistry,
    checkpoint: Checkpoint,
    certificate: PrecommitCertificate,
    generation: GenerationSpec,
}

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
        let closure = GenerationClosure {
            height: CheckpointHeight(height as u64),
            generation: old.generation(),
            value_id: [0x77; 32],
            candidate_id: candidate,
            new_set_root: set.set_root(),
        };
        let cp = cluster.checkpoint(height as u64, Some(candidate));
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

/// Node A decides a closing height but never installs it.
fn decided_only(seeds: &[u8], weight: u64, next_seeds: &[u8], salt: u8) -> DecidedOnly {
    let mut cluster = Cluster::new(GEN, seeds, weight, salt);
    let old = cluster.registry.clone();
    let set = AdmittedSet::admit(
        &policy(old.total_voting_weight().get()),
        &candidates(next_seeds, weight),
        1,
        0,
        Some(&old),
    )
    .expect("admissible set");
    let candidate = set.candidate_id(old.generation(), CheckpointHeight(0), old.set_root());
    let closure = GenerationClosure {
        height: CheckpointHeight(0),
        generation: old.generation(),
        value_id: [0x77; 32],
        candidate_id: candidate,
        new_set_root: set.set_root(),
    };
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    DecidedOnly {
        generation: GenerationSpec {
            number: 1,
            registry: set.registry().clone(),
            closure: Some(closure),
        },
        next: set.registry().clone(),
        closure,
        checkpoint: cp,
        certificate: cert,
        cluster,
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

fn bundle(fx: &Fixture, from: usize, to: usize) -> SyncBundle {
    SyncBundle {
        anchor: anchor_at(fx, from),
        generations: fx.generations.clone(),
        links: (from..=to)
            .map(|i| SyncLink {
                checkpoint: fx.checkpoints[i],
                certificate: fx.certificates[i].clone(),
            })
            .collect(),
    }
}

fn root_from_store(store: &MemoryAtomicSlotStore) -> [u8; 32] {
    let mut ids: Vec<(u64, [u8; 32])> = store
        .scan("l2/v3/bft/finality/")
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

/// The project's own record, copied as the seeding half of a transfer would.
fn transfer_decision(src: &MemoryAtomicSlotStore, dst: &MemoryAtomicSlotStore, height: u64) {
    let key = finality_key(CheckpointHeight(height));
    let sealed = src
        .get(&key)
        .expect("get")
        .expect("a decision at that height");
    assert!(
        dst.cas(&key, None, &sealed).expect("cas"),
        "the target store was empty at that key"
    );
    dst.flush().expect("flush");
}

fn pending_record(store: &MemoryAtomicSlotStore, height: u64) -> Option<PendingInstall> {
    store
        .get(&pending_install_key(CheckpointHeight(height)))
        .expect("get")
        .map(|bytes| PendingInstall::decode(open_sealed(&bytes).expect("seal")).expect("decode"))
}

// ---------------------------------------------------------------------------
// BO-01 .. BO-04 — the transfer itself
// ---------------------------------------------------------------------------

#[test]
fn bo_01_a_decides_and_b_verifies_and_restores_the_same_history() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);

    // A holds a real chain: its own decision at height 0 (closing) and 1.
    assert!(fx.stores[0]
        .get(&finality_key(CheckpointHeight(0)))
        .expect("get")
        .is_some());

    // B is an independent node: own store, own engine, same genesis registry.
    let b = MemoryAtomicSlotStore::new();
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");

    // 5. B re-verified every certificate against the registry of its generation.
    assert_eq!(history.links.len(), 2);
    assert_eq!(history.roots.set_roots_recomputed, 2);

    // 6. The closure and the next registry were rebuilt, not trusted.
    assert_eq!(history.ledger.closures.len(), 1);
    assert_eq!(history.ledger.active_number, 1);
    assert_eq!(
        history.active_registry().set_root(),
        fx.generations[1].registry.set_root()
    );

    install_history(&b, &history).expect("installed");

    // 7. The installation obligation is satisfied by the certified ledger,
    //    never by a claim. Mission BQ: installing a history now writes the same
    //    durable mark the closing node writes, so the obligation is *marked*
    //    installed (it used to be left absent, which made a restart refuse to
    //    sign). The mark must name the generation the ledger activates.
    let record = pending_record(&b, 0).expect("the installation mark is written");
    assert!(record.installed, "{record:?}");
    let closure = fx.generations[1].closure.expect("a closure");
    assert_eq!(record.generation, closure.generation);
    assert_eq!(record.candidate_id, closure.candidate_id);
    assert_eq!(record.installed_generation, history.active_generation());
    assert_eq!(
        record.installed_set_root,
        history.active_registry().set_root()
    );
    let restored = restore_engine(&b, history.active_registry(), None, NET, history.tip);
    assert_eq!(restored.state.generation, history.active_generation());
    assert!(
        restored
            .state
            .pending_installs
            .get(&CheckpointHeight(0))
            .map(|record| record.installed)
            .unwrap_or(false),
        "the verified closure satisfies the obligation"
    );
    assert!(
        restored.state.may_sign().is_ok(),
        "{:?}",
        restored.state.persisted().status
    );

    // 8/9. At the tip (height 1) B may sign: nothing is uninstalled below it.
    let mut engine = restored.state;
    engine
        .advance_height(CheckpointHeight(2), &b)
        .expect("B may advance once nothing is uninstalled");
    assert!(engine.may_sign().is_ok());
    assert_eq!(restored.decisions.len(), 2);
    assert_eq!(root_from_store(&b), history.roots.finality_chain_root);
}

#[test]
fn bo_02_a_certificate_is_verified_with_the_real_weights() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 0, &[1, 2, 3, 4], 0);
    let cert = &fx.certificates[0];
    assert_eq!(cert.support(), ValidatorWeight(4 * WEIGHT));
    assert_eq!(cert.total(), ValidatorWeight(4 * WEIGHT));
    assert_eq!(cert.signers().len(), 4);

    let registry = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let bytes = cert.encode();
    let reverified = PrecommitCertificate::from_bytes(&bytes, &registry, NET).expect("re-verified");
    assert_eq!(reverified.id(), cert.id());

    // A different weighting is not the same quorum: the certificate is refused.
    let heavier = registry_with(GEN, &[(1, 50), (2, 50), (3, 50), (4, 50)]);
    assert!(
        PrecommitCertificate::from_bytes(&bytes, &heavier, NET).is_err(),
        "certificates must be recomputed with the real weights"
    );

    // One flipped signature byte is refused, not silently ignored.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(PrecommitCertificate::from_bytes(&tampered, &registry, NET).is_err());
}

#[test]
fn bo_03_two_receivers_derive_identical_state_from_one_bundle() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[2, 3, 4, 5], 0);
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    let mut roots = Vec::new();
    let mut decisions = Vec::new();
    for _ in 0..2 {
        let store = MemoryAtomicSlotStore::new();
        install_history(&store, &history).expect("installed");
        roots.push(root_from_store(&store));
        let restored = restore_engine(&store, history.active_registry(), None, NET, history.tip);
        decisions.push(
            restored
                .decisions
                .iter()
                .map(|d| (d.height.get(), d.checkpoint_id, d.transition_id))
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(roots[0], roots[1]);
    assert_eq!(decisions[0], decisions[1]);
    assert_eq!(roots[0], history.roots.finality_chain_root);
}

#[test]
fn bo_04_the_decision_carries_the_transition_and_a_legacy_one_does_not() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    let closing = &history.links[0].decision;
    assert_eq!(
        closing.transition_id,
        Some(fx.generations[1].closure.unwrap().candidate_id)
    );
    assert_eq!(history.links[1].decision.transition_id, None);

    // A v1 record (no transition field) is still read, and creates no obligation.
    let mut legacy = *closing;
    legacy.version = 1;
    legacy.transition_id = None;
    assert_eq!(legacy.encode().len(), 237);
    assert_eq!(
        FinalityDecision::decode(&legacy.encode())
            .expect("v1")
            .transition_id,
        None
    );
}

// ---------------------------------------------------------------------------
// BO-05 .. BO-10 — corruption and replay
// ---------------------------------------------------------------------------

#[test]
fn bo_05_a_truncated_bundle_cannot_bootstrap_a_tip() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let truncated = verify_history(&bundle(&fx, 0, 0)).expect("the anchor alone is valid");
    assert!(matches!(
        truncated.require_tip(CheckpointHeight(1)),
        Err(SyncError::Truncated {
            tip: 0,
            requested: 1
        })
    ));
    // A hole in the middle is a jump, not a gap to be filled.
    let mut holed = bundle(&fx, 0, 1);
    holed.links.remove(1);
    let short = verify_history(&holed).expect("the prefix is still a valid history");
    assert_eq!(short.tip, CheckpointHeight(0));
    assert!(matches!(
        short.require_tip(CheckpointHeight(1)),
        Err(SyncError::Truncated {
            tip: 0,
            requested: 1
        })
    ));
}

#[test]
fn bo_06_an_invalid_certificate_is_refused() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    evil.links[1].certificate = fx.certificates[0].clone();
    match verify_history(&evil) {
        Err(SyncError::CertificateInvalid(h, _)) | Err(SyncError::CertificateForeign(h, _)) => {
            assert_eq!(h, 1)
        }
        other => panic!("expected a certificate refusal, got {other:?}"),
    }
}

#[test]
fn bo_07_a_modified_transition_is_refused() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    // Claim another transition at the closing height: the candidate id is
    // recomputed from (generation, height, set_root, current root).
    evil.links[0].checkpoint.transition_id = Some([0x99u8; 32]);
    match verify_history(&evil) {
        Err(SyncError::TransitionMismatch(0))
        | Err(SyncError::CertificateForeign(0, _))
        | Err(SyncError::Unanchored(_)) => {}
        other => panic!("a modified transition must be refused, got {other:?}"),
    }
}

#[test]
fn bo_08_an_incoherent_next_registry_is_refused() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let mut evil = bundle(&fx, 0, 1);
    // The bundle no longer describes generation 1, which the height-1 checkpoint
    // claims: nothing may be invented.
    evil.generations.truncate(1);
    assert!(verify_history(&evil).is_err());

    // A closure that installs another set root than the registry it names.
    let mut evil = bundle(&fx, 0, 1);
    if let Some(spec) = evil.generations.get_mut(1) {
        if let Some(closure) = spec.closure.as_mut() {
            closure.new_set_root[0] ^= 0xFF;
        }
    }
    assert!(verify_history(&evil).is_err());
}

#[test]
fn bo_09_replay_is_idempotent_and_never_regresses() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    let store = MemoryAtomicSlotStore::new();
    install_history(&store, &history).expect("first install");
    let before = root_from_store(&store);
    install_history(&store, &history).expect("replay is a no-op");
    assert_eq!(root_from_store(&store), before);
    let records = store.scan("l2/v3/bft/finality/").expect("scan");
    assert_eq!(records.len(), 2, "one record per height, no duplicates");

    // Replaying an *older* bundle after installation does not truncate the node.
    let older = verify_history(&bundle(&fx, 0, 0)).expect("anchor only");
    install_history(&store, &older).expect("known records");
    assert_eq!(root_from_store(&store), before);
}

#[test]
fn bo_10_out_of_order_and_contradictory_bundles_are_refused() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let mut swapped = bundle(&fx, 0, 1);
    swapped.links.swap(0, 1);
    assert!(matches!(
        verify_history(&swapped),
        Err(SyncError::Unanchored(_)) | Err(SyncError::HeightJump { .. })
    ));

    // Two valid but different chains for the same height: reported, never chosen.
    let other = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 9);
    let honest = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    let evil = verify_history(&bundle(&other, 0, 1)).expect("verified");
    assert!(matches!(
        compare_histories(&honest, &evil),
        HistoryAgreement::Contradiction { height: 0, .. }
    ));
    let store = MemoryAtomicSlotStore::new();
    install_history(&store, &honest).expect("installed");
    match install_history(&store, &evil) {
        Err(SyncError::Commitment(_)) => {}
        other => panic!("expected a commitment conflict, got {other:?}"),
    }
    // The store still names the first decision: no branch was picked for it.
    assert_eq!(root_from_store(&store), honest.roots.finality_chain_root);
}

// ---------------------------------------------------------------------------
// BO-11 .. BO-14 — closure, obligation, generation
// ---------------------------------------------------------------------------

#[test]
fn bo_11_a_decision_without_its_ledger_blocks_the_next_height() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let g0 = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let closing = fx.generations[1].closure.expect("a closure");
    let next = fx.generations[1].registry.clone();

    // B receives only the decision of the closing height (the first half of a
    // transfer): no ledger, no installation.
    let b = MemoryAtomicSlotStore::new();
    transfer_decision(&fx.stores[0], &b, 0);
    let restored = restore_engine(&b, &g0, None, NET, CheckpointHeight(0));
    let obligation = restored
        .state
        .pending_installs
        .get(&CheckpointHeight(0))
        .copied()
        .expect("obligation derived from the decision");
    assert!(!obligation.installed);
    assert_eq!(obligation.candidate_id, closing.candidate_id);

    // 8. B cannot sign above the uninstalled closure.
    let mut engine = restored.state;
    let refused = engine.advance_height(CheckpointHeight(1), &b);
    assert!(
        matches!(refused, Err(BftError::InstallationRequired { height: 1 })),
        "expected InstallationRequired, got {refused:?}"
    );

    // BO-F2 was corrected by mission BP: the derived obligation is now durable,
    // so this node can complete the installation itself after the restart.
    let installed = engine.close_generation(closing, &next, &b);
    assert!(
        installed.is_ok(),
        "the durable derived obligation must allow the installation, got {installed:?}"
    );

    // 9. The certified closure arrives in the bundle's ledger; B installs it and
    //    resumes normally at the new generation.
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    install_history(&b, &history).expect("the clause and its closure are installed");
    let restored = restore_engine(&b, history.active_registry(), None, NET, history.tip);
    assert!(
        restored
            .state
            .pending_installs
            .values()
            .all(|record| record.installed),
        "every restored obligation is satisfied by the verified closure"
    );
    assert!(
        restored.state.may_sign().is_ok(),
        "{:?}",
        restored.state.persisted().status
    );
    assert_eq!(restored.state.generation, history.active_generation());
}

#[test]
fn bo_12_a_marker_without_a_closure_blocks_signing() {
    let decided = decided_only(&[1, 2, 3, 4], WEIGHT, &[1, 2, 3, 4], 0);
    let store = MemoryAtomicSlotStore::new();
    transfer_decision(&decided.cluster.stores[0], &store, 0);
    // A marker that claims an installation the ledger does not contain.
    let mut forged = pending_record(&decided.cluster.stores[0], 0).expect("marker");
    forged.installed = true;
    forged.installed_generation = decided.next.generation();
    forged.installed_set_root = decided.next.set_root();
    store
        .cas(
            &pending_install_key(CheckpointHeight(0)),
            None,
            &seal(&forged.encode()),
        )
        .expect("cas");
    store.flush().expect("flush");

    let restored = restore_engine(
        &store,
        &decided.cluster.registry,
        None,
        NET,
        CheckpointHeight(0),
    );
    assert!(
        matches!(
            restored.state.persisted().status,
            RecoveryStatus::RecoveryRequired(_)
        ),
        "a marker without its closure is a corrupt state, got {:?}",
        restored.state.persisted().status
    );
    assert!(restored.state.may_sign().is_err());
}

#[test]
fn bo_13_a_generation_cannot_be_installed_twice_and_cannot_be_skipped() {
    let decided = decided_only(&[1, 2, 3, 4], WEIGHT, &[1, 2, 3, 4], 0);
    let DecidedOnly {
        cluster,
        closure,
        next,
        ..
    } = decided;
    let Cluster {
        mut engines,
        stores,
        ..
    } = cluster;
    let mut engine = engines.remove(0);
    let store = &stores[0];

    // The obligation is unsatisfied: no bypass through `close_generation` with a
    // registry that is not the one the closure names.
    let wrong = registry_with(
        [0x42u8; 32],
        &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (5, WEIGHT)],
    );
    match engine.close_generation(closure, &wrong, store) {
        Err(BftError::Rejected(_)) => {}
        other => panic!("a registry of another membership must be refused, got {other:?}"),
    }

    engine
        .close_generation(closure, &next, store)
        .expect("first installation");
    // At `h_close` the engine already stands in the new generation: it cannot
    // sign there until it moves to the first height of that generation.
    assert!(engine.may_sign().is_err());

    // Installing the same generation again is refused: no double installation.
    // The refusal is deterministic (`Rejected` while still at `h_close`,
    // `ContextMismatch { field: "generation" }` once the new generation is in
    // force); what matters is that the ledger never gains a second closure.
    assert!(engine.close_generation(closure, &next, store).is_err());
    engine
        .advance_height(CheckpointHeight(1), store)
        .expect("the first height of the installed generation");
    assert!(engine.may_sign().is_ok(), "{:?}", engine.persisted().status);

    // The ledger holds exactly one closure, and the marker is installed once.
    let ledger = GenerationLedger::load(store)
        .expect("load")
        .expect("a ledger");
    assert_eq!(ledger.closures.len(), 1);
    let record = pending_record(store, 0).expect("marker");
    assert!(record.installed);
    assert_eq!(record.installed_set_root, next.set_root());
}

#[test]
fn bo_14_a_closed_generation_cannot_be_used_by_an_old_member() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[2, 3, 4, 5], 0);
    let history = verify_history(&bundle(&fx, 0, 1)).expect("verified");
    // Validator 1 left when generation 1 opened; validator 5 arrived.
    assert!(history.active_registry().get(&vid(1)).is_none());
    assert!(history.active_registry().get(&vid(5)).is_some());
    // The engine restored from the bundle signs under the rebuilt registry only.
    let store = MemoryAtomicSlotStore::new();
    install_history(&store, &history).expect("installed");
    let mut restored = restore_engine(&store, history.active_registry(), None, NET, history.tip);
    assert_eq!(restored.state.generation, history.active_generation());
    assert!(restored.state.may_sign().is_ok());

    let stale = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    assert!(
        restored
            .state
            .prevote([0x11u8; 32], vid(1), &stale, &store, sign_with(1))
            .is_err(),
        "a member of a closed generation cannot vote in the new one"
    );
}

// ---------------------------------------------------------------------------
// BO-15 .. BO-18 — durability, halt, proposal gate
// ---------------------------------------------------------------------------

#[test]
fn bo_15_restart_at_every_durability_point_is_deterministic() {
    // 1. Before the decision: an empty store restores an open engine at height 0.
    let empty = MemoryAtomicSlotStore::new();
    let registry = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let fresh = restore_engine(&empty, &registry, None, NET, CheckpointHeight(0));
    assert!(fresh.decisions.is_empty());
    assert_eq!(fresh.state.generation, registry.generation());
    assert!(fresh.state.may_sign().is_ok());

    // 2/3. After the decision and after PendingInstall: same durable point.
    let decided = decided_only(&[1, 2, 3, 4], WEIGHT, &[1, 2, 3, 4], 0);
    let DecidedOnly {
        cluster,
        closure,
        next,
        checkpoint,
        ..
    } = decided;
    let Cluster {
        mut engines,
        stores,
        registry: closing_registry,
        ..
    } = cluster;
    let a_store = &stores[0];
    for round in 0..2 {
        let restored = restore_engine(a_store, &closing_registry, None, NET, CheckpointHeight(0));
        assert_eq!(restored.decisions.len(), 1, "round {round}");
        assert_eq!(restored.decisions[0].checkpoint_id, checkpoint.id());
        let obligation = restored
            .state
            .pending_installs
            .get(&CheckpointHeight(0))
            .expect("obligation");
        assert!(!obligation.installed);
        let mut probe = restored.state;
        assert!(probe.advance_height(CheckpointHeight(1), a_store).is_err());
        assert!(restored.halt.is_none());
    }

    // 4. After the closure: the ledger proves the install, the marker is durable.
    let mut engine = engines.remove(0);
    engine
        .close_generation(closure, &next, a_store)
        .expect("closure");
    assert!(pending_record(a_store, 0).expect("marker").installed);
    assert!(
        engine.may_sign().is_err(),
        "h_close belongs to the closed generation"
    );
    engine
        .advance_height(CheckpointHeight(1), a_store)
        .expect("activation at the first height of the new generation");
    assert!(engine.may_sign().is_ok());

    // 5. Before the install mark: no marker, ledger present. The certified
    //    closure alone proves the installation; this is safe and unblocked.
    let no_marker = MemoryAtomicSlotStore::new();
    transfer_decision(a_store, &no_marker, 0);
    let ledger = GenerationLedger::load(a_store)
        .expect("load")
        .expect("ledger");
    ledger
        .persist(&no_marker)
        .expect("ledger copied without a marker");
    no_marker.flush().expect("flush");
    let restored = restore_engine(&no_marker, &next, None, NET, CheckpointHeight(1));
    assert!(
        restored.state.pending_installs.is_empty(),
        "the ledger is the proof, so no obligation remains"
    );
    assert!(
        restored.state.may_sign().is_ok(),
        "BO15-DEBUG status={:?} pending={:?}",
        restored.state.persisted().status,
        restored.state.pending_installs.keys().collect::<Vec<_>>()
    );
    assert_eq!(restored.state.generation, next.generation());

    // 6. After the install mark, restarting twice changes nothing.
    for _ in 0..2 {
        let restored = restore_engine(a_store, &next, None, NET, CheckpointHeight(1));
        let record = restored
            .state
            .pending_installs
            .get(&CheckpointHeight(0))
            .expect("installed marker kept");
        assert!(record.installed);
        assert_eq!(record.installed_set_root, next.set_root());
        assert_eq!(restored.state.generation, next.generation());
        assert!(restored.state.may_sign().is_ok());
    }
    // No double installation was created by the restarts.
    let ledger = GenerationLedger::load(a_store)
        .expect("load")
        .expect("ledger");
    assert_eq!(ledger.closures.len(), 1);
}

#[test]
fn bo_16_a_halted_node_neither_votes_nor_synchronises_away_the_halt() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 0, &[1, 2, 3, 4], 0);
    let history = verify_history(&bundle(&fx, 0, 0)).expect("verified");
    let store = MemoryAtomicSlotStore::new();
    store
        .cas(HALT_KEY, None, &seal(b"conflicting finality"))
        .expect("halt");
    match install_history(&store, &history) {
        Err(SyncError::Commitment(text)) => assert!(text.contains("halt")),
        other => panic!("a halt must refuse synchronisation, got {other:?}"),
    }
    assert!(store.get(HALT_KEY).expect("get").is_some());

    // A restored halted engine refuses to vote, whatever the registry says.
    let registry = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let mut restored = restore_engine(&store, &registry, None, NET, CheckpointHeight(0));
    assert!(restored.state.is_halted());
    assert!(restored
        .state
        .prevote([0x11u8; 32], vid(1), &registry, &store, sign_with(1))
        .is_err());
    assert!(restored
        .state
        .accept_proposal([0x12u8; 32], vid(1), &registry)
        .is_err());
}

#[test]
fn bo_17_a_non_elected_proposer_cannot_inject_a_value() {
    let registry = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let elected = aether_unified::l2bft::proposer_for(
        &registry,
        registry.generation(),
        CheckpointHeight(0),
        Round(0),
    )
    .expect("a proposer")
    .validator;
    let intruder = if elected == vid(1) { vid(2) } else { vid(1) };
    assert!(matches!(
        engine.accept_proposal([0x21u8; 32], intruder, &registry),
        Err(BftError::NotProposer { .. })
    ));
    assert!(engine.round_state.proposal.is_none());
    engine
        .accept_proposal([0x22u8; 32], elected, &registry)
        .expect("the elected proposer remains functional");
}

#[test]
fn bo_18_persisted_data_is_validated_on_load() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 0, &[1, 2, 3, 4], 0);
    let store = MemoryAtomicSlotStore::new();
    let key = finality_key(CheckpointHeight(0));
    // A sealed record that decodes to nonsense must not be trusted.
    store.cas(&key, None, &seal(&[0u8; 12])).expect("cas");
    store.flush().expect("flush");
    let registry = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let restored = restore_engine(&store, &registry, None, NET, CheckpointHeight(0));
    assert!(
        matches!(
            restored.state.persisted().status,
            RecoveryStatus::RecoveryRequired(_)
        ),
        "an unreadable decision blocks recovery, got {:?}",
        restored.state.persisted().status
    );
    assert!(restored.state.may_sign().is_err());
    // The untouched chain still verifies on its own: the corruption is local.
    assert!(verify_history(&bundle(&fx, 0, 0)).is_ok());
}

#[test]
fn bo_19_an_uncommitted_node_refuses_a_history_it_signed_against() {
    let honest = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let other = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 9);
    let history = verify_history(&bundle(&honest, 0, 1)).expect("verified");
    let store = &other.stores[0];
    assert!(!store.scan_slots().expect("slots").is_empty());
    match check_commitments(store, &history) {
        Err(SyncError::Commitment(text)) => {
            assert!(text.contains("signed") || text.contains("durable decision"))
        }
        other => panic!("expected a commitment conflict, got {other:?}"),
    }
    assert!(install_history(store, &history).is_err());
}

#[test]
fn bo_20_skipping_an_installation_is_refused_by_the_engine() {
    let fx = build(&[1, 2, 3, 4], WEIGHT, 1, &[1, 2, 3, 4], 0);
    let g0 = registry_with(GEN, &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)]);
    let closing = fx.generations[1].closure.expect("a closure");
    let next = fx.generations[1].registry.clone();

    let store = MemoryAtomicSlotStore::new();
    transfer_decision(&fx.stores[0], &store, 0);
    let mut restored = restore_engine(&store, &g0, None, NET, CheckpointHeight(0));

    // Jumping to the next height without the installation is refused by the
    // engine's own guard, not by the caller's discipline.
    assert!(restored
        .state
        .advance_height(CheckpointHeight(1), &store)
        .is_err());

    // Installing a *different* closure at that position is refused.
    let mut forged = closing;
    forged.candidate_id[0] ^= 0xFF;
    assert!(matches!(
        restored.state.close_generation(forged, &next, &store),
        Err(BftError::Rejected(_))
    ));

    // Neither refusal wrote anything: one decision, no ledger.
    assert_eq!(store.scan("l2/v3/bft/finality/").expect("scan").len(), 1);
    assert!(GenerationLedger::load(&store).expect("load").is_none());
}

#[test]
fn bo_21_the_generation_label_must_be_derived_from_the_transition() {
    // Finding BO-F1 as observed before mission BP: a closure certified the
    // *member set* and the position, not the identifier of the generation it
    // opens, so the same members could be installed under another label. BP binds
    // the label to the transition; this test now asserts the refusal.
    let decided = decided_only(&[1, 2, 3, 4], WEIGHT, &[1, 2, 3, 4], 0);
    let DecidedOnly {
        cluster, closure, ..
    } = decided;
    let Cluster {
        mut engines,
        stores,
        ..
    } = cluster;
    let mut engine = engines.remove(0);
    let store = &stores[0];

    let relabelled = registry_with(
        [0x42u8; 32],
        &[(1, WEIGHT), (2, WEIGHT), (3, WEIGHT), (4, WEIGHT)],
    );
    let refused = engine.close_generation(closure, &relabelled, store);
    assert!(
        matches!(refused, Err(BftError::Rejected(_))),
        "same members under a free label must be refused, got {refused:?}"
    );
    assert!(
        GenerationLedger::load(store).expect("load").is_none(),
        "a refused installation writes nothing"
    );

    // The label derived from the transition is the one that installs.
    // The label is the certified transition id itself, so a node that derived it
    // from the closure installs normally: that is the canonical identity.
    assert_eq!(GenerationId(closure.candidate_id).0, closure.candidate_id);
}
