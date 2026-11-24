//! Mission BN — independent tests for the residual risks left after BM.
//!
//! | Test | Finding |
//! |---|---|
//! | `bn_01` .. `bn_04` | N-1 — who may inject a proposal, and when |
//! | `bn_05` .. `bn_07` | N-4 — the two durable halt sources agree or the node stays stopped |
//! | `bn_08` .. `bn_09` | R-1 — a decided transition without a marker blocks progression |
//! | `bn_10` | finality record versions (v1 read-only, v2 carries the transition) |
//!
//! Every test drives [`BftState`] and the durable store directly, with real
//! Ed25519 keys, a memory store, no clock and no randomness.

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::context::BftError;
use aether_unified::l2bft::{
    finality_key, proposer_for, restore_engine, BftState, FinalityDecision, HaltReason,
    FINALITY_FORMAT_VERSION, HALT_KEY,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::{CasStore, MemoryAtomicSlotStore, RoundPosition};
use ed25519_dalek::SigningKey;

const NET: u64 = 91;
const ANCHOR: [u8; 32] = [0x3C; 32];
const GEN: [u8; 32] = [9u8; 32];
const WEIGHT: u64 = 10;
const SEEDS: [u8; 4] = [11, 12, 13, 14];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn registry_with(seeds: &[u8], generation: [u8; 32]) -> ValidatorRegistry {
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

fn registry() -> ValidatorRegistry {
    registry_with(&SEEDS, GEN)
}

fn state(registry: &ValidatorRegistry) -> BftState {
    BftState::new(NET, registry, CheckpointHeight(0), ANCHOR)
}

fn elected(registry: &ValidatorRegistry, height: CheckpointHeight, round: Round) -> ValidatorId {
    proposer_for(registry, registry.generation(), height, round)
        .expect("a proposer")
        .validator
}

fn other_than(registry: &ValidatorRegistry, chosen: ValidatorId) -> ValidatorId {
    registry
        .entries()
        .iter()
        .map(|entry| entry.id)
        .find(|id| *id != chosen)
        .expect("another member")
}

fn decision(
    height: u64,
    checkpoint_id: [u8; 32],
    registry: &ValidatorRegistry,
    transition_id: Option<[u8; 32]>,
) -> FinalityDecision {
    FinalityDecision {
        version: FINALITY_FORMAT_VERSION,
        network: NET,
        generation: registry.generation(),
        height: CheckpointHeight(height),
        round: Round(0),
        checkpoint_id,
        parent: [0u8; 32],
        validator_set_root: registry.set_root(),
        registry_root: registry.root(),
        support: 4 * WEIGHT,
        total: 4 * WEIGHT,
        quorum: 3 * WEIGHT,
        certificate_id: [0x44u8; 32],
        transition_id,
    }
}

fn store_decision(store: &MemoryAtomicSlotStore, decision: &FinalityDecision) {
    let sealed = aether_unified::l2persist::seal(&decision.encode());
    store
        .cas(&finality_key(decision.height), None, &sealed)
        .expect("cas");
    store.flush().expect("flush");
}

// ---------------------------------------------------------------------------
// N-1 — proposal ingress
// ---------------------------------------------------------------------------

#[test]
fn bn_01_a_non_proposer_cannot_inject_a_proposal() {
    let registry = registry();
    let mut engine = state(&registry);
    let proposer = elected(&registry, CheckpointHeight(0), Round(0));
    let intruder = other_than(&registry, proposer);

    let refused = engine.accept_proposal([0xA1u8; 32], intruder, &registry);
    assert!(
        matches!(refused, Err(BftError::NotProposer { .. })),
        "expected NotProposer, got {refused:?}"
    );
    assert!(
        engine.round_state.proposal.is_none(),
        "a refused proposal must not become the round's value"
    );

    // A second attempt by another non-proposer is refused too: there is no
    // "first pair wins" rule at this boundary.
    let another = registry
        .entries()
        .iter()
        .map(|entry| entry.id)
        .find(|id| *id != proposer && *id != intruder)
        .expect("third member");
    assert!(engine
        .accept_proposal([0xA2u8; 32], another, &registry)
        .is_err());
    assert!(engine.round_state.proposal.is_none());
}

#[test]
fn bn_02_the_elected_proposer_is_accepted_once_and_cannot_be_replaced() {
    let registry = registry();
    let mut engine = state(&registry);
    let proposer = elected(&registry, CheckpointHeight(0), Round(0));

    engine
        .accept_proposal([0xB1u8; 32], proposer, &registry)
        .expect("the elected proposer's proposal is receivable");
    assert_eq!(engine.round_state.proposal, Some([0xB1u8; 32]));

    // The same value again is idempotent.
    engine
        .accept_proposal([0xB1u8; 32], proposer, &registry)
        .expect("idempotent");

    // A different value in the same round is refused, even from the proposer:
    // a round carries one proposed value.
    let replaced = engine.accept_proposal([0xB2u8; 32], proposer, &registry);
    assert!(
        matches!(replaced, Err(BftError::ContextMismatch { field: "value" })),
        "expected ContextMismatch, got {replaced:?}"
    );
    assert_eq!(engine.round_state.proposal, Some([0xB1u8; 32]));
}

#[test]
fn bn_03_a_registry_of_another_generation_schedules_nobody() {
    let current = registry();
    let mut engine = state(&current);
    let foreign = registry_with(&SEEDS, [0x77u8; 32]);
    // Whoever is elected in the foreign generation is irrelevant here: the
    // schedule of the engine's own generation cannot be computed from it.
    assert!(
        proposer_for(
            &foreign,
            current.generation(),
            CheckpointHeight(0),
            Round(0)
        )
        .is_none(),
        "a registry of another generation has no schedule for this position"
    );
    let refused = engine.accept_proposal(
        [0xC1u8; 32],
        elected(&foreign, CheckpointHeight(0), Round(0)),
        &foreign,
    );
    assert!(
        matches!(refused, Err(BftError::Rejected(_))),
        "expected Rejected, got {refused:?}"
    );
    assert!(engine.round_state.proposal.is_none());
}

#[test]
fn bn_04_a_halted_engine_accepts_no_proposal_from_anyone() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    let mut engine = state(&registry);
    let proposer = elected(&registry, CheckpointHeight(0), Round(0));
    engine
        .halt_with(HaltReason::Persisted("operator stop".to_string()), &store)
        .expect("halt");
    assert!(engine.is_halted());

    let refused = engine.accept_proposal([0xD1u8; 32], proposer, &registry);
    assert!(
        matches!(refused, Err(BftError::Halted(_))),
        "a halted engine must refuse every proposal, got {refused:?}"
    );
    assert!(engine.round_state.proposal.is_none());
}

// ---------------------------------------------------------------------------
// N-4 — one halt, two durable witnesses
// ---------------------------------------------------------------------------

fn halted_position(registry: &ValidatorRegistry) -> RoundPosition {
    let mut position = RoundPosition::fresh(NET, registry.generation(), CheckpointHeight(0));
    position.halted = true;
    position
}

#[test]
fn bn_05_a_halt_in_both_sources_survives_restart_and_keeps_its_reason() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    let canonical = aether_unified::l2persist::seal(b"conflicting finality at height 3");
    store.cas(HALT_KEY, None, &canonical).expect("halt record");
    halted_position(&registry)
        .persist(&store)
        .expect("position");
    store.flush().expect("flush");

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.is_halted());
    assert!(restored.state.may_sign().is_err());
    // The canonical record is a fact: a restart never rewrites it.
    assert_eq!(
        store.get(HALT_KEY).expect("get"),
        Some(canonical),
        "the canonical halt record must not be replaced"
    );
}

#[test]
fn bn_06_a_halt_only_in_the_position_is_reestablished_in_the_canonical_record() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    halted_position(&registry)
        .persist(&store)
        .expect("position");
    store.flush().expect("flush");
    assert!(store.get(HALT_KEY).expect("get").is_none());

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.state.is_halted(),
        "the position alone stops the node"
    );
    assert!(restored.state.may_sign().is_err());
    assert!(
        store.get(HALT_KEY).expect("get").is_some(),
        "the two witnesses must agree after a restart"
    );

    // And the agreement is stable: a second restart is still halted.
    let again = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(again.state.is_halted());
}

#[test]
fn bn_07_a_halt_only_in_the_canonical_record_stops_the_node() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    let sealed = aether_unified::l2persist::seal(b"lock proof missing");
    store.cas(HALT_KEY, None, &sealed).expect("halt record");
    store.flush().expect("flush");

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.is_halted());
    assert!(restored.state.may_sign().is_err());
    assert_eq!(restored.halt, restored.state.halt.clone());
}

// ---------------------------------------------------------------------------
// R-1 — a decided transition without a marker still blocks progression
// ---------------------------------------------------------------------------

#[test]
fn bn_08_a_decided_transition_without_a_marker_blocks_the_next_height() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    let transition = [0x5Eu8; 32];
    let decided = decision(0, [0x60u8; 32], &registry, Some(transition));
    store_decision(&store, &decided);

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    let pending = restored
        .state
        .pending_installs
        .get(&CheckpointHeight(0))
        .copied()
        .expect("an obligation derived from the decided transition");
    assert!(!pending.installed, "nothing is ever inferred as installed");
    assert_eq!(pending.candidate_id, transition);
    assert_eq!(pending.value_id, [0x60u8; 32]);

    // The obligation is load-bearing: progression is refused.
    let mut engine = restored.state;
    let advanced = engine.advance_height(CheckpointHeight(1), &store);
    assert!(
        advanced.is_err(),
        "signing above an uninstalled closure must be refused, got {advanced:?}"
    );
    assert!(engine.may_sign().is_err() || engine.height == CheckpointHeight(0));
}

#[test]
fn bn_09_a_legacy_v1_record_decodes_and_derives_no_obligation() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    let mut legacy = decision(0, [0x61u8; 32], &registry, None);
    legacy.version = 1;
    // A v1 record is 237 bytes: it cannot carry a transition.
    assert_eq!(legacy.encode().len(), 237);
    let decoded = FinalityDecision::decode(&legacy.encode()).expect("v1 still decodes");
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.transition_id, None);
    store_decision(&store, &legacy);

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        !restored
            .state
            .pending_installs
            .contains_key(&CheckpointHeight(0)),
        "a record that cannot name a transition cannot create an obligation"
    );
}

#[test]
fn bn_10_finality_records_are_versioned_and_round_trip() {
    let registry = registry();
    let v2 = decision(2, [0x62u8; 32], &registry, Some([0x63u8; 32]));
    let bytes = v2.encode();
    assert_eq!(bytes.len(), 270, "v2 carries the transition: 270 bytes");
    let decoded = FinalityDecision::decode(&bytes).expect("v2 decodes");
    assert_eq!(decoded, v2);

    let mut v1 = v2;
    v1.version = 1;
    v1.transition_id = None;
    assert_eq!(v1.encode().len(), 237);
    assert_eq!(FinalityDecision::decode(&v1.encode()).expect("v1"), v1);

    // Neither a truncated record nor an unknown version is accepted.
    assert!(FinalityDecision::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut unknown = v1.encode();
    unknown[0] = 9;
    assert!(FinalityDecision::decode(&unknown).is_err());

    // A version that disagrees with the length is refused, not repaired.
    let mut mismatched = v2.encode();
    mismatched[0] = 1;
    assert!(FinalityDecision::decode(&mismatched).is_err());
}
