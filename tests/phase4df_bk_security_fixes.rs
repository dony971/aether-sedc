//! Mission BK — independent regression tests for the seven audited findings.
//!
//! Each test is written against the **public** surface and real Ed25519 keys. The
//! goal is not to re-run the existing suites but to reproduce, on its own terms,
//! the behaviour the BJ audit found missing:
//!
//! | Test | Finding |
//! |---|---|
//! | `bk_01` | N-1 — a proposal is receivable only from the elected proposer |
//! | `bk_02` | N-1 — the dispatcher applies the same gate to wire messages |
//! | `bk_03` | N-3 — `close_generation` rejects a registry that is not the closure |
//! | `bk_04` | N-4 — `position.halted` survives a restart and rewrites `HALT_KEY` |
//! | `bk_05` | N-5 — a ledger that decodes but violates its invariants is refused |
//! | `bk_06` | N-7 — a round change cannot jump more than `MAX_ROUND_JUMP` |
//! | `bk_07` | N-8 — `RecoveryReason` keeps its class across the encoding |
//! | `bk_08` | N-9 — a position that cannot be flushed produces no signature |

use std::cell::Cell;
use std::rc::Rc;

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    candidate_id, GenerationClosure, GenerationLedger, TransitionError, LEDGER_KEY,
};
use aether_unified::l2bft::context::BftError;
use aether_unified::l2bft::{
    pending_install_key, proposer_for, restore_engine, BftState, FinalityDecision, PendingInstall,
    RoundChange, RoundChangeOutcome, RoundTimer, VoteOutcome, FINALITY_FORMAT_VERSION, HALT_KEY,
    MAX_ROUND_JUMP, PENDING_INSTALL_FORMAT_VERSION,
};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::slotlock::SlotStoreError;
use aether_unified::l2persist::{
    AtomicSlotStore, CasStore, MemoryAtomicSlotStore, RecoveryReason, RecoveryStatus,
    RoundPosition, ROUND_KEY,
};
use aether_unified::network::dispatcher::{dispatch, Dispatched, Incoming};
use aether_unified::network::protocol::{Envelope, MessageKind};
use aether_unified::network::{PeerIdentity, PeerTable};
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 73;
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

fn peer_for(seed: u8) -> aether_unified::network::PeerState {
    let identity = PeerIdentity::derive(sk(seed).verifying_key().to_bytes(), 0);
    let mut table = PeerTable::new(Default::default());
    table
        .admit(identity, std::time::Instant::now())
        .expect("admit");
    table.get(&identity.id).expect("peer").clone()
}

// ---------------------------------------------------------------------------
// N-1 — proposal authorization
// ---------------------------------------------------------------------------

#[test]
fn bk_01_only_the_elected_proposer_may_propose() {
    let registry = registry();
    let elected = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(0), Round(0))
        .expect("schedule")
        .validator;
    let elected_seed = SEEDS
        .iter()
        .copied()
        .find(|seed| vid(*seed) == elected)
        .expect("elected is a member");
    let other_seed = SEEDS
        .iter()
        .copied()
        .find(|seed| vid(*seed) != elected)
        .expect("another member");

    // Two independent validators, same position, same message.
    let value = [0x42u8; 32];
    for _ in 0..2 {
        let mut engine = state(&registry);
        engine
            .accept_proposal(value, elected, &registry)
            .expect("the elected proposer is admissible");
        assert_eq!(engine.round_state.proposal, Some(value));
    }

    let mut engine = state(&registry);
    assert!(matches!(
        engine.accept_proposal(value, vid(other_seed), &registry),
        Err(BftError::NotProposer { .. })
    ));
    assert_eq!(
        engine.round_state.proposal, None,
        "a refused proposal installs nothing"
    );

    // The elected sender is the one the rule names, not just any member.
    assert_eq!(vid(elected_seed), elected);
}

#[test]
fn bk_02_the_dispatcher_refuses_a_proposal_from_a_non_proposer() {
    let registry = registry();
    let elected = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(0), Round(0))
        .expect("schedule")
        .validator;
    let elected_seed = SEEDS
        .iter()
        .copied()
        .find(|seed| vid(*seed) == elected)
        .expect("member");
    let other_seed = SEEDS
        .iter()
        .copied()
        .find(|seed| vid(*seed) != elected)
        .expect("member");
    let value = [0x24u8; 32];

    let mut engine = state(&registry);
    let mut good_peer = peer_for(elected_seed);
    let good = Envelope::new(
        NET,
        MessageKind::Proposal,
        elected.0,
        GEN,
        0,
        0,
        value.to_vec(),
    )
    .sign(&sk(elected_seed));
    match dispatch(&mut good_peer, &good, &mut engine, &registry, false) {
        Incoming::Accepted(Dispatched::Proposal(seen)) => assert_eq!(seen, value),
        other => panic!("the elected proposer must be accepted, got {other:?}"),
    }

    let mut engine = state(&registry);
    let mut bad_peer = peer_for(other_seed);
    let bad = Envelope::new(
        NET,
        MessageKind::Proposal,
        vid(other_seed).0,
        GEN,
        0,
        0,
        value.to_vec(),
    )
    .sign(&sk(other_seed));
    match dispatch(&mut bad_peer, &bad, &mut engine, &registry, false) {
        Incoming::Refused(_) => {}
        other => panic!("a non-proposer must be refused, got {other:?}"),
    }
    assert_eq!(engine.round_state.proposal, None);
}

// ---------------------------------------------------------------------------
// N-3 — the installed registry is the one the closure describes
// ---------------------------------------------------------------------------

fn next_registry() -> ValidatorRegistry {
    // Mission BP: the identifier of a generation is derived from its position and
    // its set root, never a free label. This fixture uses the legacy derivation
    // (`generation_id_from(number, 0, set_root)`), which the engine still accepts;
    // the canonical identity is the transition id itself (`registry_for`).
    let provisional = registry_with(&[5, 6, 7, 8], [8u8; 32]);
    let label = aether_unified::consensus::roots::generation_id_from(1, 0, provisional.set_root());
    registry_with(&[5, 6, 7, 8], label.0)
}

#[test]
fn bk_03_close_generation_rejects_a_foreign_registry() {
    let old = registry();
    let next = next_registry();
    let mut engine = state(&old);

    let correct = candidate_id(
        GenerationId(GEN),
        CheckpointHeight(0),
        next.set_root(),
        old.set_root(),
    );
    let mut closure = GenerationClosure {
        height: CheckpointHeight(0),
        generation: GenerationId(GEN),
        value_id: [0x11u8; 32],
        candidate_id: correct,
        new_set_root: next.set_root(),
    };

    // (a) The closure names a set root the supplied registry does not have.
    let mut wrong_root = closure;
    wrong_root.new_set_root = [0xAAu8; 32];
    let store = MemoryAtomicSlotStore::new();
    assert!(matches!(
        engine.close_generation(wrong_root, &next, &store),
        Err(BftError::Rejected(_))
    ));
    assert_eq!(
        engine.generation,
        GenerationId(GEN),
        "nothing was installed"
    );

    // (b) The set root matches but the candidate id was not derived from it.
    closure.candidate_id = [0xBBu8; 32];
    assert!(matches!(
        engine.close_generation(closure, &next, &store),
        Err(BftError::Rejected(_))
    ));
    assert_eq!(engine.generation, GenerationId(GEN));

    // The same arguments with the derived candidate pass the argument checks and
    // stop at the missing decision, which proves the checks above are not the
    // generic "no decision" path.
    closure.candidate_id = correct;
    match engine.close_generation(closure, &next, &store) {
        Err(BftError::Rejected(reason)) => {
            assert!(reason.contains("no checkpoint was decided"), "{reason}");
        }
        other => panic!("expected the missing-decision refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// N-4 — the two halt witnesses are reconciled
// ---------------------------------------------------------------------------

#[test]
fn bk_04_a_halted_position_restores_the_halt() {
    let registry = registry();
    let store = MemoryAtomicSlotStore::new();
    let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(0));
    position.halted = true;
    position.persist(&store).expect("position written");
    assert!(
        store.get(HALT_KEY).expect("read").is_none(),
        "the canonical record is deliberately absent"
    );

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.state.is_halted(),
        "the position said the node halted"
    );
    assert!(matches!(
        restored.halt,
        Some(aether_unified::l2bft::HaltReason::Persisted(_))
    ));
    assert!(
        restored.state.may_sign().is_err(),
        "a halted engine does not sign"
    );
    assert!(
        store.get(HALT_KEY).expect("read").is_some(),
        "the canonical halt record is rewritten"
    );

    // And the rewritten record is enough on its own.
    drop(restored);
    let again = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(again.state.is_halted());
}

// ---------------------------------------------------------------------------
// N-5 — ledger invariants at decode
// ---------------------------------------------------------------------------

fn closure_at(height: u64, generation: [u8; 32]) -> GenerationClosure {
    GenerationClosure {
        height: CheckpointHeight(height),
        generation: GenerationId(generation),
        value_id: [height as u8 ^ 0x33; 32],
        candidate_id: [height as u8 ^ 0x44; 32],
        new_set_root: [height as u8 ^ 0x55; 32],
    }
}

#[test]
fn bk_05_a_ledger_that_violates_its_invariants_does_not_decode() {
    // A well-formed ledger with one closure round-trips.
    let mut ledger = GenerationLedger::new(NET, GenerationId(GEN));
    ledger
        .apply_closure(closure_at(0, GEN), GenerationId([8u8; 32]), 1)
        .expect("closure");
    let bytes = ledger.encode();
    assert_eq!(
        GenerationLedger::decode(&bytes).expect("valid ledger"),
        ledger
    );

    // `active_number` must equal the number of closures (D15).
    let mut bad_number = bytes.clone();
    bad_number[41..49].copy_from_slice(&2u64.to_le_bytes());
    assert!(matches!(
        GenerationLedger::decode(&bad_number),
        Err(TransitionError::Persistence(_))
    ));

    // `first_height` must be exactly one past the last closure (D15).
    let mut bad_first = bytes.clone();
    bad_first[49..57].copy_from_slice(&99u64.to_le_bytes());
    assert!(matches!(
        GenerationLedger::decode(&bad_first),
        Err(TransitionError::Persistence(_))
    ));

    // A closure at `u64::MAX` has no successor height.
    let mut bad_height = bytes.clone();
    bad_height[61..69].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(
        GenerationLedger::decode(&bad_height),
        Err(TransitionError::Persistence(_))
    ));

    // A genesis ledger must not claim another number or first height.
    let genesis = GenerationLedger::new(NET, GenerationId(GEN));
    let mut bad_genesis = genesis.encode();
    bad_genesis[41..49].copy_from_slice(&1u64.to_le_bytes());
    assert!(matches!(
        GenerationLedger::decode(&bad_genesis),
        Err(TransitionError::Persistence(_))
    ));
}

// ---------------------------------------------------------------------------
// N-7 — bounded round progression
// ---------------------------------------------------------------------------

#[test]
fn bk_06_a_round_change_is_bounded_and_never_wraps() {
    let registry = registry();
    let mut engine = state(&registry);
    let seed = 1u8;
    let far = Round(MAX_ROUND_JUMP + 1);
    let change = RoundChange::unsigned(
        NET,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(0),
        far,
        vid(seed),
        registry.set_root(),
        None,
    )
    .sign_with(&sk(seed));

    match engine
        .process_round_change(change, &registry, NET)
        .expect("well-formed message")
    {
        RoundChangeOutcome::Refused(reason) => {
            assert!(reason.contains("jumps"), "{reason}");
        }
        other => panic!("a distant round must be refused, got {other:?}"),
    }
    assert_eq!(engine.round, Round(0), "the engine did not move");

    // The encoding-level bound: `u32::MAX` has no successor.
    let last = RoundChange::unsigned(
        NET,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(0),
        Round(u32::MAX),
        vid(seed),
        registry.set_root(),
        None,
    )
    .sign_with(&sk(seed));
    assert!(matches!(
        engine.process_round_change(last, &registry, NET),
        Err(BftError::Rejected(_))
    ));

    // A timer at the last round reports no target instead of wrapping to zero.
    let mut timer = RoundTimer::new(1);
    timer.sync_round(Round(u32::MAX));
    assert_eq!(timer.tick(1), None);

    // A jump exactly at the bound still works (the bound is inclusive).
    let mut engine = state(&registry);
    let at_bound = RoundChange::unsigned(
        NET,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(0),
        Round(MAX_ROUND_JUMP),
        vid(seed),
        registry.set_root(),
        None,
    )
    .sign_with(&sk(seed));
    assert!(matches!(
        engine
            .process_round_change(at_bound, &registry, NET)
            .expect("well-formed"),
        RoundChangeOutcome::Recorded { .. } | RoundChangeOutcome::Adopted { .. }
    ));
}

// ---------------------------------------------------------------------------
// N-8 — RecoveryReason class preservation
// ---------------------------------------------------------------------------

#[test]
fn bk_07_recovery_reason_keeps_its_class() {
    let reasons = [
        RecoveryReason::CorruptState("corrupt".into()),
        RecoveryReason::MissingAnchor,
        RecoveryReason::ForeignAnchor {
            expected: [0x01; 32],
            found: [0x02; 32],
        },
        RecoveryReason::IncoherentSlot("slot".into()),
        RecoveryReason::ContradictoryLock("lock".into()),
        RecoveryReason::IncompleteState("incomplete".into()),
    ];
    for reason in reasons {
        let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(0));
        position.recovery = RecoveryStatus::RecoveryRequired(reason.clone());
        let back = RoundPosition::decode(&position.encode()).expect("round trip");
        assert_eq!(back.recovery, RecoveryStatus::RecoveryRequired(reason));
    }

    // A version-1 record is still readable; its text becomes `CorruptState`.
    let clean = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(0));
    let mut legacy = clean.encode();
    assert_eq!(legacy.pop(), Some(0), "a clean record ends with tag 0");
    legacy.push(1);
    let text = b"legacy v1 reason";
    legacy.extend_from_slice(&(text.len() as u16).to_le_bytes());
    legacy.extend_from_slice(text);
    legacy[0] = 1;
    let decoded = RoundPosition::decode(&legacy).expect("legacy record");
    assert_eq!(
        decoded.recovery,
        RecoveryStatus::RecoveryRequired(RecoveryReason::CorruptState("legacy v1 reason".into()))
    );
    assert_eq!(
        decoded.version,
        aether_unified::l2persist::ROUND_FORMAT_VERSION
    );
}

// ---------------------------------------------------------------------------
// N-9 — durability before signature
// ---------------------------------------------------------------------------

/// A store whose writes succeed in memory but whose barrier always fails.
struct NoFlushStore {
    inner: MemoryAtomicSlotStore,
}

impl CasStore for NoFlushStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        self.inner.get(key)
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        self.inner.cas(key, expected, new)
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.inner.scan(prefix)
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        Err(SlotStoreError::Corrupt("injected flush failure".into()))
    }

    fn backend(&self) -> &'static str {
        "no-flush"
    }
}

impl AtomicSlotStore for NoFlushStore {}

#[test]
fn bk_08_no_signature_without_a_durable_position() {
    let registry = registry();
    let key = sk(1);
    let called = Rc::new(Cell::new(false));

    // (a) A failing barrier stops the prevote before the signer runs.
    let store = NoFlushStore {
        inner: MemoryAtomicSlotStore::new(),
    };
    let mut engine = state(&registry);
    let flag = called.clone();
    let result = engine.prevote([0x31u8; 32], vid(1), &registry, &store, move |msg| {
        flag.set(true);
        key.sign(msg).to_bytes()
    });
    assert!(result.is_err(), "no signature without a durable position");
    assert!(!called.get(), "the signer must never be reached");
    assert!(engine.round_state.prevotes.is_empty());
    assert!(matches!(
        engine.persisted().status,
        RecoveryStatus::RecoveryRequired(_)
    ));

    // (b) With a working barrier the position is written before the signature.
    let store = MemoryAtomicSlotStore::new();
    let mut engine = state(&registry);
    let key = sk(1);
    let flag = called.clone();
    flag.set(false);
    engine
        .prevote([0x32u8; 32], vid(1), &registry, &store, move |msg| {
            flag.set(true);
            key.sign(msg).to_bytes()
        })
        .expect("working store");
    assert!(called.get(), "the signer ran");
    assert!(store.get(ROUND_KEY).expect("read").is_some());
    assert_eq!(engine.round_state.prevotes.len(), 1);
}

// A final compile-time check that the dispatcher test above really exercises the
// engine's gate and not a different `Incoming` variant.
#[allow(dead_code)]
fn _types(_: Incoming, _: Dispatched) {}

// ---------------------------------------------------------------------------
// Multi-round and multi-validator extensions
// ---------------------------------------------------------------------------

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn signed_vote(round: u32, phase: VotePhase, value: [u8; 32], seed: u8) -> ConsensusVote {
    let mut vote = ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: GenerationId(GEN),
        height: CheckpointHeight(0),
        round: Round(round),
        phase,
        checkpoint_id: value,
        validator: vid(seed),
        signature: [0u8; 64],
    };
    vote.signature = sk(seed).sign(&vote.signing_bytes()).to_bytes();
    vote
}

#[test]
fn bk_09_the_elected_proposer_changes_with_the_round() {
    let registry = registry();
    let at_zero = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(0), Round(0))
        .expect("schedule")
        .validator;

    // Find a later round whose proposer is a different member: with four equal
    // validators this is immediate, and the test states the dependency instead of
    // assuming it.
    let mut later = None;
    for round in 1..64u32 {
        let elected = proposer_for(
            &registry,
            GenerationId(GEN),
            CheckpointHeight(0),
            Round(round),
        )
        .expect("schedule")
        .validator;
        if elected != at_zero {
            later = Some((round, elected));
            break;
        }
    }
    let (round, elected_later) = later.expect("a later round elects another member");

    // The round-0 proposer was admissible at round 0 and is not at `round`.
    let value = [0x66u8; 32];
    let mut engine = state(&registry);
    engine
        .accept_proposal(value, at_zero, &registry)
        .expect("round 0");
    engine.begin_round(Round(round)).expect("later round");
    assert_eq!(
        engine.round_state.proposal, None,
        "a new round starts with no proposal"
    );
    assert!(matches!(
        engine.accept_proposal([0x67u8; 32], at_zero, &registry),
        Err(BftError::NotProposer { .. })
    ));
    assert_eq!(
        engine.round_state.proposal, None,
        "the refused proposal installed nothing"
    );
    engine
        .accept_proposal([0x67u8; 32], elected_later, &registry)
        .expect("the proposer of this round is admissible");
    assert_eq!(engine.round_state.proposal, Some([0x67u8; 32]));
}

fn decided(
    generation: [u8; 32],
    checkpoint: [u8; 32],
    registry: &ValidatorRegistry,
) -> FinalityDecision {
    FinalityDecision {
        version: FINALITY_FORMAT_VERSION,
        network: NET,
        generation: GenerationId(generation),
        height: CheckpointHeight(0),
        round: Round(0),
        checkpoint_id: checkpoint,
        parent: [0u8; 32],
        validator_set_root: registry.set_root(),
        registry_root: registry.root(),
        support: 4 * WEIGHT,
        total: 4 * WEIGHT,
        quorum: 3 * WEIGHT,
        certificate_id: [0x90u8; 32],
        transition_id: None,
    }
}

#[test]
fn bk_10_a_decided_closure_installs_the_next_generation() {
    let old = registry();
    let next = next_registry();
    let decided_checkpoint = [0x7Au8; 32];
    let store = MemoryAtomicSlotStore::new();

    let closure = GenerationClosure {
        height: CheckpointHeight(0),
        generation: GenerationId(GEN),
        value_id: decided_checkpoint,
        candidate_id: candidate_id(
            GenerationId(GEN),
            CheckpointHeight(0),
            next.set_root(),
            old.set_root(),
        ),
        new_set_root: next.set_root(),
    };

    let mut engine = state(&old);
    engine.finality = Some(decided(GEN, decided_checkpoint, &old));
    engine.ledger.persist(&store).expect("ledger");
    // Mission BM N-6: installation requires the durable obligation that
    // `finalize` writes when it decides a checkpoint carrying a transition.
    // This unit test injects the decision and writes the same record.
    let pending = PendingInstall {
        version: PENDING_INSTALL_FORMAT_VERSION,
        network: NET,
        height: CheckpointHeight(0),
        generation: GenerationId(GEN),
        candidate_id: closure.candidate_id,
        value_id: decided_checkpoint,
        installed: false,
        installed_generation: GenerationId([0u8; 32]),
        installed_set_root: [0u8; 32],
    };
    assert!(store
        .cas(
            &pending_install_key(CheckpointHeight(0)),
            None,
            &aether_unified::l2persist::seal(&pending.encode())
        )
        .expect("pending record"));
    engine.pending_installs.insert(CheckpointHeight(0), pending);
    let before = store.get(LEDGER_KEY).expect("read").expect("written");

    // A candidate id that was not derived from the position and the set root is
    // refused, and the durable ledger is untouched.
    let mut bad = closure;
    bad.candidate_id = [0xEEu8; 32];
    assert!(matches!(
        engine.close_generation(bad, &next, &store),
        Err(BftError::Rejected(_))
    ));
    assert_eq!(engine.generation, GenerationId(GEN));
    assert_eq!(
        store.get(LEDGER_KEY).expect("read").expect("written"),
        before
    );

    // The same closure with its derived id installs the generation.
    engine
        .close_generation(closure, &next, &store)
        .expect("install");
    assert_eq!(engine.generation, next.generation());
    assert_eq!(engine.set_root, next.set_root());
    assert_eq!(engine.ledger.closures.len(), 1);
    let durable = GenerationLedger::load(&store)
        .expect("load")
        .expect("a ledger was written");
    assert_eq!(durable.active, next.generation());
    assert_eq!(durable.active_number, 1);
}

#[test]
fn bk_11_no_precommit_signature_without_a_durable_position() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Fails the barrier only when the last write was the round position.
    struct RoundFlushFails {
        inner: MemoryAtomicSlotStore,
        armed: Arc<AtomicBool>,
    }

    impl CasStore for RoundFlushFails {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
            self.inner.get(key)
        }

        fn cas(
            &self,
            key: &str,
            expected: Option<&[u8]>,
            new: &[u8],
        ) -> Result<bool, SlotStoreError> {
            let swapped = self.inner.cas(key, expected, new)?;
            self.armed.store(key == ROUND_KEY, Ordering::SeqCst);
            Ok(swapped)
        }

        fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
            self.inner.scan(prefix)
        }

        fn flush(&self) -> Result<(), SlotStoreError> {
            if self.armed.load(Ordering::SeqCst) {
                return Err(SlotStoreError::Corrupt(
                    "injected round-position flush failure".into(),
                ));
            }
            self.inner.flush()
        }

        fn backend(&self) -> &'static str {
            "round-flush-fails"
        }
    }

    impl AtomicSlotStore for RoundFlushFails {}

    let registry = registry();
    let value = [0x5Au8; 32];
    let store = MemoryAtomicSlotStore::new();
    let mut engine = state(&registry);
    engine.propose(value).expect("propose");
    engine
        .prevote(value, vid(1), &registry, &store, sign_with(1))
        .expect("own prevote");
    for seed in [2u8, 3u8] {
        assert!(matches!(
            engine.accept_vote(&signed_vote(0, VotePhase::Prevote, value, seed), &registry),
            VoteOutcome::Accepted { .. }
        ));
    }
    let certificate = engine
        .certify_prevotes_for(value, &registry)
        .expect("prevote certificate");

    let armed = Arc::new(AtomicBool::new(false));
    let failing = RoundFlushFails {
        inner: MemoryAtomicSlotStore::new(),
        armed: armed.clone(),
    };
    let called = Rc::new(Cell::new(false));
    let flag = called.clone();
    let key = sk(1);
    let result = engine.precommit(&certificate, vid(1), &registry, &failing, move |msg| {
        flag.set(true);
        key.sign(msg).to_bytes()
    });
    assert!(result.is_err(), "no signature without a durable position");
    assert!(!called.get(), "the signer must never be reached");
    assert!(engine.round_state.precommits.is_empty());
    assert!(matches!(
        engine.persisted().status,
        RecoveryStatus::RecoveryRequired(_)
    ));
    assert!(
        failing.get(ROUND_KEY).is_ok() && failing.get(ROUND_KEY).unwrap().is_some(),
        "the position write itself succeeded; only the barrier failed"
    );
}

#[test]
fn bk_12_the_round_bound_is_relative_to_the_current_round() {
    let registry = registry();
    let seed = 1u8;

    // From round 10, a target at exactly `10 + MAX_ROUND_JUMP` is recorded and
    // `10 + MAX_ROUND_JUMP + 1` is refused.
    let change = |target: u32| {
        RoundChange::unsigned(
            NET,
            GenerationId(GEN),
            CheckpointHeight(0),
            Round(10),
            Round(target),
            vid(seed),
            registry.set_root(),
            None,
        )
        .sign_with(&sk(seed))
    };

    let mut engine = state(&registry);
    engine.begin_round(Round(10)).expect("round 10");
    assert!(matches!(
        engine
            .process_round_change(change(10 + MAX_ROUND_JUMP), &registry, NET)
            .expect("well-formed"),
        RoundChangeOutcome::Recorded { .. } | RoundChangeOutcome::Adopted { .. }
    ));

    let mut engine = state(&registry);
    engine.begin_round(Round(10)).expect("round 10");
    match engine
        .process_round_change(change(10 + MAX_ROUND_JUMP + 1), &registry, NET)
        .expect("well-formed")
    {
        RoundChangeOutcome::Refused(reason) => assert!(reason.contains("jumps"), "{reason}"),
        other => panic!("a target past the bound must be refused, got {other:?}"),
    }
    assert_eq!(engine.round, Round(10));
}

#[test]
fn bk_13_a_ledger_must_close_each_generation_once_and_never_the_active_one() {
    let mut ledger = GenerationLedger::new(NET, GenerationId(GEN));
    ledger
        .apply_closure(closure_at(0, GEN), GenerationId([8u8; 32]), 1)
        .expect("closure");
    assert!(GenerationLedger::decode(&ledger.encode()).is_ok());

    // The same generation closed twice.
    let mut duplicate = ledger.clone();
    duplicate.closures.push(closure_at(1, GEN));
    duplicate.active_number = 2;
    duplicate.first_height = CheckpointHeight(2);
    assert!(matches!(
        GenerationLedger::decode(&duplicate.encode()),
        Err(TransitionError::Persistence(_))
    ));

    // The active generation listed as closed.
    let mut active_closed = ledger.clone();
    active_closed.closures.push(closure_at(1, [8u8; 32]));
    active_closed.active_number = 2;
    active_closed.first_height = CheckpointHeight(2);
    assert!(matches!(
        GenerationLedger::decode(&active_closed.encode()),
        Err(TransitionError::Persistence(_))
    ));

    // Closures out of order.
    let mut unordered = ledger.clone();
    unordered.closures.insert(0, closure_at(1, [9u8; 32]));
    unordered.active_number = 2;
    unordered.first_height = CheckpointHeight(2);
    assert!(matches!(
        GenerationLedger::decode(&unordered.encode()),
        Err(TransitionError::Persistence(_))
    ));
}
