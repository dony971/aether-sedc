//! Mission BP — generation identity binding (BO-F1) and durable derived
//! obligations (BO-F2).
//!
//! Every test drives the production paths (`finalize`, `close_generation`,
//! `restore_engine`, `verify_history`, `install_history`) with real Ed25519 keys
//! and real certificates. Nothing here re-implements a rule.

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    AdmittedSet, CandidateOperator, GenerationClosure, GenerationLedger, SetPolicy,
};
use aether_unified::l2bft::context::BftError;
use aether_unified::l2bft::{
    finality_key, install_history, pending_install_key, restore_engine, verify_history, BftState,
    GenerationSpec, PendingInstall, PrecommitCertificate, SyncAnchor, SyncBundle, SyncLink,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::{
    open_sealed, seal, CasStore, MemoryAtomicSlotStore, RecoveryStatus,
};
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 89;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const WEIGHT: u64 = 10;
const SEEDS: [u8; 4] = [1, 2, 3, 4];

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

fn registry_with(generation: [u8; 32], seeds: &[u8]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = seeds
        .iter()
        .map(|seed| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(WEIGHT),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(generation), &entries).expect("registry")
}

fn policy() -> SetPolicy {
    SetPolicy {
        min_deposit: 1,
        deposit_unit: 1,
        maturity_blocks: 0,
        min_weight: 1,
        max_weight: 1_000,
        w_max: 100_000,
        n_min: 1,
        n_max: 64,
        churn_max_weight: (SEEDS.len() as u64) * WEIGHT,
        f_b_new: 0,
        d_ready: 1_000,
    }
}

fn candidates(seeds: &[u8]) -> Vec<CandidateOperator> {
    seeds
        .iter()
        .map(|seed| CandidateOperator {
            operator: [*seed; 32],
            public_key: sk(*seed).verifying_key().to_bytes(),
            deposit: WEIGHT,
            maturity_blocks: 0,
            unbonding: false,
            jailed: false,
        })
        .collect()
}

/// A decided closing height, with the two admissible identities for the
/// generation it opens.
struct Closing {
    engine: BftState,
    store: MemoryAtomicSlotStore,
    registry: ValidatorRegistry,
    closure: GenerationClosure,
    /// Label derived from the transition itself (`AdmittedSet::registry_for`).
    next_canonical: ValidatorRegistry,
    /// Label derived from the position (`generation_id_from(number, 0, root)`).
    next_legacy: ValidatorRegistry,
    checkpoint: Checkpoint,
    certificate: PrecommitCertificate,
    generation: GenerationSpec,
}

fn closing(seeds: &[u8], next_seeds: &[u8], salt: u8) -> Closing {
    let registry = registry_with(GEN, seeds);
    let mut engines: Vec<BftState> = seeds
        .iter()
        .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
        .collect();
    let mut stores: Vec<MemoryAtomicSlotStore> =
        seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect();

    let set = AdmittedSet::admit(&policy(), &candidates(next_seeds), 1, 0, Some(&registry))
        .expect("admissible set");
    let candidate = set.candidate_id(
        registry.generation(),
        CheckpointHeight(0),
        registry.set_root(),
    );
    let mut closure = GenerationClosure {
        height: CheckpointHeight(0),
        generation: registry.generation(),
        value_id: [0u8; 32],
        candidate_id: candidate,
        new_set_root: set.set_root(),
    };
    let cp = Checkpoint::new(
        registry.generation(),
        CheckpointHeight(0),
        [0u8; 32],
        [0x22u8 ^ salt; 32],
        [0x33u8 ^ salt; 32],
        registry.set_root(),
        Some(candidate),
    )
    .expect("checkpoint");
    closure.value_id = cp.id();

    // One real round: prevotes, certificate, precommits, certificate, finality.
    let mut prevotes: Vec<ConsensusVote> = Vec::new();
    for i in 0..engines.len() {
        let vote = engines[i]
            .prevote(
                cp.id(),
                vid(seeds[i]),
                &registry,
                &stores[i],
                sign_with(seeds[i]),
            )
            .expect("prevote");
        prevotes.push(vote.vote().clone());
    }
    for engine in engines.iter_mut() {
        for vote in &prevotes {
            engine.accept_vote(vote, &registry);
        }
    }
    let prevote_cert = engines[0]
        .certify_prevotes_for(cp.id(), &registry)
        .expect("prevote quorum");
    let mut precommits: Vec<ConsensusVote> = Vec::new();
    for i in 0..engines.len() {
        let vote = engines[i]
            .precommit(
                &prevote_cert,
                vid(seeds[i]),
                &registry,
                &stores[i],
                sign_with(seeds[i]),
            )
            .expect("precommit");
        precommits.push(vote.vote().clone());
    }
    for engine in engines.iter_mut() {
        for vote in &precommits {
            engine.accept_vote(vote, &registry);
        }
    }
    let certificate = engines[0]
        .certify_precommits_for(cp.id(), &registry)
        .expect("precommit quorum");
    for i in 0..engines.len() {
        engines[i]
            .finalize(&certificate, &cp, None, &registry, &stores[i])
            .expect("finality");
    }

    let next_canonical = set
        .registry_for(&registry, CheckpointHeight(0))
        .expect("canonical identity");
    let next_legacy = set.registry().clone();
    Closing {
        engine: engines.remove(0),
        store: stores.remove(0),
        registry,
        closure,
        next_canonical,
        next_legacy,
        checkpoint: cp,
        certificate,
        generation: GenerationSpec {
            number: 1,
            registry: set.registry().clone(),
            closure: Some(closure),
        },
    }
}

fn pending_at(store: &MemoryAtomicSlotStore, height: u64) -> Option<PendingInstall> {
    store
        .get(&pending_install_key(CheckpointHeight(height)))
        .expect("get")
        .map(|bytes| PendingInstall::decode(open_sealed(&bytes).expect("seal")).expect("decode"))
}

// ---------------------------------------------------------------------------
// BO-F1 — the generation identity is derived from the transition
// ---------------------------------------------------------------------------

#[test]
fn bp_01_a_closure_bound_to_its_transition_is_accepted() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("canonical identity installs");
    assert_eq!(c.engine.generation, c.next_canonical.generation());
    assert_eq!(
        c.engine.generation,
        GenerationId(c.closure.candidate_id),
        "the active generation is the certified transition"
    );
    let ledger = GenerationLedger::load(&c.store)
        .expect("load")
        .expect("ledger");
    assert_eq!(ledger.closures.len(), 1);
    assert_eq!(ledger.active, GenerationId(c.closure.candidate_id));
    assert!(pending_at(&c.store, 0).expect("marker").installed);
}

#[test]
fn bp_02_a_modified_next_generation_identifier_is_refused() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    let relabelled = registry_with([0x42u8; 32], &SEEDS);
    let refused = c.engine.close_generation(c.closure, &relabelled, &c.store);
    assert!(
        matches!(refused, Err(BftError::Rejected(_))),
        "a free label must be refused, got {refused:?}"
    );
    assert!(GenerationLedger::load(&c.store).expect("load").is_none());
}

#[test]
fn bp_03_a_modified_previous_generation_is_refused() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    let mut forged = c.closure;
    forged.generation = GenerationId([0x11u8; 32]);
    assert!(matches!(
        c.engine
            .close_generation(forged, &c.next_canonical, &c.store),
        Err(BftError::ContextMismatch {
            field: "generation"
        }) | Err(BftError::Rejected(_))
    ));
    assert!(GenerationLedger::load(&c.store).expect("load").is_none());
}

#[test]
fn bp_04_a_modified_closing_height_is_refused() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    let mut forged = c.closure;
    forged.height = CheckpointHeight(1);
    assert!(matches!(
        c.engine
            .close_generation(forged, &c.next_canonical, &c.store),
        Err(BftError::ContextMismatch { field: "height" }) | Err(BftError::Rejected(_))
    ));
}

#[test]
fn bp_05_a_modified_set_root_is_refused() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    let mut forged = c.closure;
    forged.new_set_root[0] ^= 0xFF;
    assert!(matches!(
        c.engine
            .close_generation(forged, &c.next_canonical, &c.store),
        Err(BftError::Rejected(_))
    ));
}

#[test]
fn bp_06_a_modified_transition_identifier_is_refused() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    let mut forged = c.closure;
    forged.candidate_id[0] ^= 0xFF;
    assert!(matches!(
        c.engine
            .close_generation(forged, &c.next_canonical, &c.store),
        Err(BftError::Rejected(_))
    ));
}

#[test]
fn bp_07_a_closure_cannot_be_replayed_under_another_identity() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("first installation");
    // Same transition, another label: refused before any state is touched.
    let before = GenerationLedger::load(&c.store).expect("load");
    assert!(c
        .engine
        .close_generation(c.closure, &c.next_legacy, &c.store)
        .is_err());
    assert_eq!(GenerationLedger::load(&c.store).expect("load"), before);
}

#[test]
fn bp_08_an_old_certificate_does_not_validate_under_the_new_registry() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let bytes = c.certificate.encode();
    assert!(PrecommitCertificate::from_bytes(&bytes, &c.registry, NET).is_ok());
    assert!(
        PrecommitCertificate::from_bytes(&bytes, &c.next_canonical, NET).is_err(),
        "the closing certificate belongs to the generation that closes"
    );
    assert!(PrecommitCertificate::from_bytes(&bytes, &c.next_legacy, NET).is_err());
}

#[test]
fn bp_09_the_same_transition_received_twice_is_not_installed_twice() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("first installation");
    assert!(c
        .engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .is_err());
    let ledger = GenerationLedger::load(&c.store)
        .expect("load")
        .expect("ledger");
    assert_eq!(ledger.closures.len(), 1);
    let marker = pending_at(&c.store, 0).expect("marker");
    assert!(marker.installed);
    assert_eq!(marker.installed_set_root, c.next_canonical.set_root());
}

#[test]
fn bp_10_the_position_derived_label_is_still_accepted_for_compatibility() {
    // Legacy nodes label the generation from its position and set root. That is
    // still a deterministic function of authenticated data, so it installs; the
    // canonical (transition) identity remains the preferred one.
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_legacy, &c.store)
        .expect("legacy identity installs");
    assert_eq!(c.engine.generation, c.next_legacy.generation());
    assert_ne!(
        c.next_legacy.generation(),
        GenerationId(c.closure.candidate_id)
    );
}

#[test]
fn bp_11_a_bundle_that_relabels_the_generation_is_refused() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let anchor = SyncAnchor {
        network: NET,
        height: CheckpointHeight(0),
        checkpoint_id: c.checkpoint.id(),
        generation: c.registry.generation(),
        set_root: c.registry.set_root(),
    };
    let mk = |next: ValidatorRegistry| SyncBundle {
        anchor,
        generations: vec![
            GenerationSpec {
                number: 0,
                registry: c.registry.clone(),
                closure: None,
            },
            GenerationSpec {
                number: 1,
                registry: next,
                closure: Some(c.closure),
            },
        ],
        links: vec![SyncLink {
            checkpoint: c.checkpoint,
            certificate: c.certificate.clone(),
        }],
    };
    // Canonical label: the history verifies.
    assert!(verify_history(&mk(c.next_canonical.clone())).is_ok());
    // Same members, same transition, another label: refused.
    let relabelled = registry_with([0x42u8; 32], &SEEDS);
    assert!(
        verify_history(&mk(relabelled)).is_err(),
        "a relabelled generation must not verify"
    );
}

// ---------------------------------------------------------------------------
// BO-F2 — the derived obligation survives a restart and can be completed
// ---------------------------------------------------------------------------

#[test]
fn bp_12_a_decision_alone_creates_an_obligation_and_blocks_progress() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let fresh = MemoryAtomicSlotStore::new();
    let key = finality_key(CheckpointHeight(0));
    let sealed = c.store.get(&key).expect("get").expect("decision");
    assert!(fresh.cas(&key, None, &sealed).expect("cas"));
    fresh.flush().expect("flush");

    let mut restored = restore_engine(&fresh, &c.registry, None, NET, CheckpointHeight(0));
    let obligation = restored
        .state
        .pending_installs
        .get(&CheckpointHeight(0))
        .copied()
        .expect("obligation");
    assert!(!obligation.installed);
    assert!(matches!(
        restored.state.advance_height(CheckpointHeight(1), &fresh),
        Err(BftError::InstallationRequired { height: 1 })
    ));
}

#[test]
fn bp_13_the_derived_obligation_is_durable_across_restarts() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let fresh = MemoryAtomicSlotStore::new();
    let key = finality_key(CheckpointHeight(0));
    let sealed = c.store.get(&key).expect("get").expect("decision");
    fresh.cas(&key, None, &sealed).expect("cas");
    fresh.flush().expect("flush");
    assert!(
        pending_at(&fresh, 0).is_none(),
        "nothing is derived before the restore"
    );

    let _ = restore_engine(&fresh, &c.registry, None, NET, CheckpointHeight(0));
    let written = pending_at(&fresh, 0).expect("the derived obligation is durable");
    assert!(!written.installed);
    assert_eq!(written.candidate_id, c.closure.candidate_id);
    assert_eq!(written.value_id, c.checkpoint.id());

    // A second restore reads it back instead of deriving it again, and still
    // refuses progression.
    let mut again = restore_engine(&fresh, &c.registry, None, NET, CheckpointHeight(0));
    assert!(again
        .state
        .pending_installs
        .contains_key(&CheckpointHeight(0)));
    assert!(again
        .state
        .advance_height(CheckpointHeight(1), &fresh)
        .is_err());
}

#[test]
fn bp_14_installation_is_refused_while_the_closure_is_absent() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let fresh = MemoryAtomicSlotStore::new();
    let key = finality_key(CheckpointHeight(0));
    let sealed = c.store.get(&key).expect("get").expect("decision");
    fresh.cas(&key, None, &sealed).expect("cas");
    fresh.flush().expect("flush");
    let mut restored = restore_engine(&fresh, &c.registry, None, NET, CheckpointHeight(0));

    let mut forged = c.closure;
    forged.candidate_id[0] ^= 0xFF;
    assert!(matches!(
        restored
            .state
            .close_generation(forged, &c.next_canonical, &fresh),
        Err(BftError::Rejected(_))
    ));
    assert!(GenerationLedger::load(&fresh).expect("load").is_none());
}

#[test]
fn bp_15_the_certified_closure_can_arrive_later_and_resume_the_node() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let fresh = MemoryAtomicSlotStore::new();
    let key = finality_key(CheckpointHeight(0));
    let sealed = c.store.get(&key).expect("get").expect("decision");
    fresh.cas(&key, None, &sealed).expect("cas");
    fresh.flush().expect("flush");

    // Blocked state, then the certified closure and registry arrive.
    let mut restored = restore_engine(&fresh, &c.registry, None, NET, CheckpointHeight(0));
    assert!(restored
        .state
        .advance_height(CheckpointHeight(1), &fresh)
        .is_err());
    restored
        .state
        .close_generation(c.closure, &c.next_canonical, &fresh)
        .expect("installation against the certified closure");
    restored
        .state
        .advance_height(CheckpointHeight(1), &fresh)
        .expect("the node resumes at the first height of the new generation");
    assert!(restored.state.may_sign().is_ok());
}

#[test]
fn bp_16_an_invalid_next_registry_is_refused() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let fresh = MemoryAtomicSlotStore::new();
    let key = finality_key(CheckpointHeight(0));
    let sealed = c.store.get(&key).expect("get").expect("decision");
    fresh.cas(&key, None, &sealed).expect("cas");
    fresh.flush().expect("flush");
    let mut restored = restore_engine(&fresh, &c.registry, None, NET, CheckpointHeight(0));

    // Another membership with a legitimate label: refused by the set root.
    let other_members = registry_with(c.next_canonical.generation().0, &[2, 3, 4, 5]);
    assert!(matches!(
        restored
            .state
            .close_generation(c.closure, &other_members, &fresh),
        Err(BftError::Rejected(_))
    ));
    assert!(GenerationLedger::load(&fresh).expect("load").is_none());
}

#[test]
fn bp_17_restart_after_the_installation_is_coherent() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("closure");
    c.engine
        .advance_height(CheckpointHeight(1), &c.store)
        .expect("activation");

    let restored = restore_engine(&c.store, &c.next_canonical, None, NET, CheckpointHeight(1));
    assert_eq!(restored.state.generation, c.next_canonical.generation());
    let marker = restored
        .state
        .pending_installs
        .get(&CheckpointHeight(0))
        .copied()
        .expect("marker kept");
    assert!(marker.installed);
    assert_eq!(marker.installed_set_root, c.next_canonical.set_root());
    assert!(restored.state.may_sign().is_ok());
}

#[test]
fn bp_18_a_restart_before_the_final_mark_recovers_deterministically() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("closure");

    // Rewind the marker to "written, not yet acknowledged" while the ledger keeps
    // the certified closure -- the crash window between the two writes.
    let key = pending_install_key(CheckpointHeight(0));
    let bytes = c.store.get(&key).expect("get").expect("marker");
    let mut record = PendingInstall::decode(open_sealed(&bytes).expect("seal")).expect("decode");
    record.installed = false;
    record.installed_generation = GenerationId([0u8; 32]);
    record.installed_set_root = [0u8; 32];
    assert!(c
        .store
        .cas(&key, Some(&bytes), &seal(&record.encode()))
        .expect("cas"));

    for _ in 0..2 {
        let restored = restore_engine(&c.store, &c.next_canonical, None, NET, CheckpointHeight(1));
        let marker = restored
            .state
            .pending_installs
            .get(&CheckpointHeight(0))
            .copied()
            .expect("obligation");
        assert!(
            marker.installed,
            "the certified closure proves the installation"
        );
        assert_eq!(marker.installed_set_root, c.next_canonical.set_root());
        assert!(restored.state.may_sign().is_ok());
    }
}

#[test]
fn bp_19_restart_after_the_final_mark_never_double_installs() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("closure");
    for _ in 0..2 {
        let mut restored =
            restore_engine(&c.store, &c.next_canonical, None, NET, CheckpointHeight(0));
        assert!(restored
            .state
            .close_generation(c.closure, &c.next_canonical, &c.store)
            .is_err());
        assert!(
            restored.state.may_sign().is_ok()
                || restored.state.persisted().status != RecoveryStatus::Clean
        );
    }
    let ledger = GenerationLedger::load(&c.store)
        .expect("load")
        .expect("ledger");
    assert_eq!(ledger.closures.len(), 1);
    assert!(pending_at(&c.store, 0).expect("marker").installed);
}

#[test]
fn bp_20_the_same_bundle_received_twice_is_idempotent() {
    let c = closing(&SEEDS, &SEEDS, 0);
    let anchor = SyncAnchor {
        network: NET,
        height: CheckpointHeight(0),
        checkpoint_id: c.checkpoint.id(),
        generation: c.registry.generation(),
        set_root: c.registry.set_root(),
    };
    let bundle = SyncBundle {
        anchor,
        generations: vec![
            GenerationSpec {
                number: 0,
                registry: c.registry.clone(),
                closure: None,
            },
            GenerationSpec {
                number: 1,
                registry: c.next_canonical.clone(),
                closure: Some(c.closure),
            },
        ],
        links: vec![SyncLink {
            checkpoint: c.checkpoint,
            certificate: c.certificate,
        }],
    };
    let history = verify_history(&bundle).expect("verified");
    let store = MemoryAtomicSlotStore::new();
    install_history(&store, &history).expect("first install");
    let first: Vec<(String, Vec<u8>)> = store
        .scan("l2/v3/bft/")
        .expect("scan")
        .into_iter()
        .collect();
    install_history(&store, &history).expect("replay is a no-op");
    let second: Vec<(String, Vec<u8>)> = store
        .scan("l2/v3/bft/")
        .expect("scan")
        .into_iter()
        .collect();
    assert_eq!(first, second);
}

#[test]
fn bp_21_two_contradictory_closures_block_instead_of_being_merged() {
    let c = closing(&SEEDS, &SEEDS, 0);
    // A second, different transition at the same position: another membership.
    let other_set = AdmittedSet::admit(
        &policy(),
        &candidates(&[2, 3, 4, 5]),
        1,
        0,
        Some(&c.registry),
    )
    .expect("admissible");
    let mut other_closure = c.closure;
    other_closure.candidate_id = other_set.candidate_id(
        c.registry.generation(),
        CheckpointHeight(0),
        c.registry.set_root(),
    );
    other_closure.new_set_root = other_set.set_root();

    let mut engine = c.engine;
    engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("first closure");
    assert!(engine
        .close_generation(
            other_closure,
            &other_set
                .registry_for(&c.registry, CheckpointHeight(0))
                .expect("label"),
            &c.store
        )
        .is_err());

    // A marker that names another transition than the ledger's closure is a
    // contradiction: the restore blocks instead of choosing a side.
    let key = pending_install_key(CheckpointHeight(0));
    let bytes = c.store.get(&key).expect("get").expect("marker");
    let mut forged = PendingInstall::decode(open_sealed(&bytes).expect("seal")).expect("decode");
    forged.candidate_id = other_closure.candidate_id;
    assert!(c
        .store
        .cas(&key, Some(&bytes), &seal(&forged.encode()))
        .expect("cas"));
    let restored = restore_engine(&c.store, &c.next_canonical, None, NET, CheckpointHeight(1));
    assert!(
        matches!(
            restored.state.persisted().status,
            RecoveryStatus::RecoveryRequired(_)
        ),
        "contradictory installation evidence must block, got {:?}",
        restored.state.persisted().status
    );
    assert!(restored.state.may_sign().is_err());
}

// Silence the unused-import warning for `vid` when a build has no secrets.
#[allow(dead_code)]
fn member_ids() -> Vec<ValidatorId> {
    SEEDS.iter().map(|seed| vid(*seed)).collect()
}

// ---------------------------------------------------------------------------
// Mission M1 — F1: the local closure path binds the decided value
// ---------------------------------------------------------------------------

#[test]
fn f1_05_close_generation_refuses_another_value() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    let mut forged = c.closure;
    forged.value_id = [0x99u8; 32];

    let refused = c
        .engine
        .close_generation(forged, &c.next_canonical, &c.store);
    assert!(
        matches!(refused, Err(BftError::Rejected(_))),
        "a closure not carrying the decided value must be refused, got {refused:?}"
    );
    assert!(
        GenerationLedger::load(&c.store).expect("load").is_none(),
        "no ledger byte may be written before the guard passes"
    );
    let pending = pending_at(&c.store, 0).expect("the obligation exists from finality");
    assert!(!pending.installed, "the obligation must not be marked installed");
    assert_eq!(pending.value_id, c.checkpoint.id());
    assert_eq!(
        c.engine.generation,
        c.registry.generation(),
        "the engine stays in the closing generation"
    );
}

#[test]
fn f1_06_restore_after_honest_install_is_clean() {
    let mut c = closing(&SEEDS, &SEEDS, 0);
    assert_eq!(c.closure.value_id, c.checkpoint.id());
    c.engine
        .close_generation(c.closure, &c.next_canonical, &c.store)
        .expect("honest closure installs");
    let decision = c.engine.finality.expect("decided");

    // The ledger, the durable mark and the decision name the same value.
    let ledger = GenerationLedger::load(&c.store)
        .expect("load")
        .expect("ledger");
    let pending = pending_at(&c.store, 0).expect("marker");
    assert_eq!(ledger.closures.len(), 1);
    assert_eq!(ledger.closures[0].value_id, pending.value_id);
    assert_eq!(pending.value_id, decision.checkpoint_id);
    assert_eq!(decision.checkpoint_id, c.checkpoint.id());
    assert!(pending.installed, "the mark proves this exact closure");
    assert_eq!(pending.installed_set_root, c.next_canonical.set_root());

    c.engine
        .advance_height(CheckpointHeight(1), &c.store)
        .expect("activation");
    assert_eq!(ledger.closures[0].value_id, decision.checkpoint_id);

    let restored = restore_engine(&c.store, &c.next_canonical, None, NET, CheckpointHeight(1));
    assert_eq!(restored.state.generation, c.next_canonical.generation());
    assert!(
        restored.state.may_sign().is_ok(),
        "an honest install must restart clean, got {:?}",
        restored.state.persisted().status
    );
    let marker = restored
        .state
        .pending_installs
        .get(&CheckpointHeight(0))
        .copied()
        .expect("marker kept");
    assert!(marker.installed);
    assert_eq!(marker.value_id, decision.checkpoint_id);
}
