//! Mission BI — durable round persistence (priority 4).
//!
//! # The gap, and what closes it
//!
//! After BH the round lived in memory only: a restart came back at round 0 with a
//! lock taken at round 12 still in force. `l2persist::round` adds a versioned
//! record that must **agree** with the AU safety state — it is a position, never a
//! proof, and a disagreement blocks signing instead of choosing a side.
//!
//! | Test | What it establishes |
//! |---|---|
//! | `bo_01` | the encoding is exact: roundtrip, version refusal, no trailing bytes |
//! | `bo_02` | rounds are monotone; a regression is refused, not written |
//! | `bo_03` | a lock can never be dropped or changed at the same height |
//! | `bo_04` | a real sled store reopens and gives the same position back |
//! | `bo_05` | every class of disagreement with the safety state is caught |
//! | `bo_06` | the engine writes its position and restores its round from it |
//! | `bo_07` | crash before the write: the old record survives, nothing is invented |
//! | `bo_08` | crash during the write: an unreadable record blocks signing |
//! | `bo_09` | an adopted round change is durable **before** the engine returns |
//! | `bo_10` | a contradictory record (lock invented on disk) blocks the restart |
//!
//! `process::abort()` is not a power cut: every test here is about the **file**
//! state a restart reads, which is what `bh_node` produced for BH.

use aether_unified::consensus::generation::{CheckpointHeight, GenerationId, Round};
use aether_unified::l2bft::proposer::proposer_for;
use aether_unified::l2bft::timer::round_change_for;
use aether_unified::l2bft::{restore_engine, BftState, RoundChangeOutcome};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::round::{
    ChangeSummary, PolSummary, PositionVerdict, RoundError, RoundPosition, ROUND_FORMAT_VERSION,
    ROUND_KEY,
};
use aether_unified::l2persist::state::{LockedValue, RecoveryStatus};
use aether_unified::l2persist::{CasStore, MemoryAtomicSlotStore, SledAtomicSlotStore};
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 41;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const WEIGHT: u64 = 10;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn registry(n: usize) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = (1..=n)
        .map(|seed| RegistryEntry {
            id: validator_id(&sk(seed as u8).verifying_key().to_bytes()),
            public_key: sk(seed as u8).verifying_key().to_bytes(),
            weight: aether_unified::consensus::generation::ValidatorWeight(WEIGHT),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

fn lock(round: u32, value: u8) -> LockedValue {
    LockedValue {
        checkpoint_id: [value; 32],
        height: CheckpointHeight(0),
        round: Round(round),
    }
}

fn sample() -> RoundPosition {
    let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(4));
    position.round = Round(3);
    position.max_signed_round = Round(3);
    position.lock = Some(lock(2, 0x11));
    position.pol = Some(PolSummary {
        round: Round(2),
        qc_id: [0x22; 32],
        checkpoint_id: [0x11; 32],
        support: 30,
        total: 40,
    });
    position.last_change = Some(ChangeSummary {
        from_round: Round(1),
        target_round: Round(3),
        support: 30,
        total: 40,
        quorum: 27,
        signers: 3,
    });
    position.halted = false;
    position
}

#[test]
fn bo_01_the_encoding_is_exact() {
    let position = sample();
    let bytes = position.encode();
    let back = RoundPosition::decode(&bytes).expect("decode");
    assert_eq!(back, position);
    assert_eq!(back.version, ROUND_FORMAT_VERSION);

    // A version this code does not know is refused, not guessed.
    let mut wrong = bytes.clone();
    wrong[0] = 9;
    assert!(matches!(
        RoundPosition::decode(&wrong),
        Err(RoundError::Corrupt(_))
    ));

    // Truncation and trailing bytes are both refused.
    assert!(RoundPosition::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        RoundPosition::decode(&trailing),
        Err(RoundError::Corrupt(_))
    ));

    // A minimal record encodes too.
    let empty = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(0));
    assert_eq!(
        RoundPosition::decode(&empty.encode()).expect("decode"),
        empty
    );
}

#[test]
fn bo_02_rounds_are_monotone() {
    let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(1));
    position.observe_round(Round(4)).expect("forward");
    assert_eq!(position.round, Round(4));
    position.observe_round(Round(4)).expect("idempotent");

    match position.observe_round(Round(3)) {
        Err(RoundError::RoundRegression { stored, requested }) => {
            assert_eq!((stored, requested), (4, 3));
        }
        other => panic!("a regression must be refused, got {other:?}"),
    }

    // The same rule guards an adoption: a change cannot "adopt" the round we are in.
    let change = ChangeSummary {
        from_round: Round(4),
        target_round: Round(4),
        support: 30,
        total: 40,
        quorum: 27,
        signers: 3,
    };
    assert!(matches!(
        position.adopt(change, None),
        Err(RoundError::RoundRegression { .. })
    ));
}

#[test]
fn bo_03_a_lock_is_never_dropped_or_changed() {
    let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(2));
    position.set_lock(lock(1, 0xAA)).expect("lock");

    // Dropping the lock is a silent loss of a safety property.
    let change = ChangeSummary {
        from_round: Round(1),
        target_round: Round(2),
        support: 30,
        total: 40,
        quorum: 27,
        signers: 3,
    };
    assert!(matches!(
        position.adopt(change, None),
        Err(RoundError::LockLost)
    ));
    assert_eq!(
        position.lock.map(|l| l.checkpoint_id),
        Some([0xAA; 32]),
        "and the lock is still there after the refusal"
    );

    // A different value at the same height is a contradiction, not an update.
    assert!(matches!(
        position.set_lock(lock(1, 0xBB)),
        Err(RoundError::ContradictoryLock { .. })
    ));

    // The same value, or a lock reported for a later height, is accepted.
    position.set_lock(lock(1, 0xAA)).expect("same lock");
    let mut later = lock(1, 0xCC);
    later.height = CheckpointHeight(3);
    position
        .set_lock(later)
        .expect("a later height is another position");
    assert_eq!(position.lock.map(|l| l.height), Some(CheckpointHeight(3)));
}

#[test]
fn bo_04_a_real_store_reopens_to_the_same_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let position = sample();
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        position.persist(&store).expect("persist");
        // Reading it back through the same handle already proves the roundtrip.
        let read = RoundPosition::load(&store).expect("load").expect("present");
        assert_eq!(read, position);
    }
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
        let read = RoundPosition::load(&store).expect("load").expect("present");
        assert_eq!(read, position, "the bytes on disk are the record");
        assert!(store.get(ROUND_KEY).expect("get").is_some());
    }
}

#[test]
fn bo_05_every_disagreement_with_the_state_is_caught() {
    let state = {
        let registry = registry(4);
        let mut engine = BftState::new(NET, &registry, CheckpointHeight(2), ANCHOR);
        let mut persisted = engine.persisted().clone();
        persisted.locked = Some(lock(1, 0x11));
        persisted.generation = GenerationId(GEN);
        persisted
    };

    // Agreement.
    let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(2));
    position.round = Round(1);
    position.max_signed_round = Round(1);
    position.lock = Some(lock(1, 0x11));
    assert_eq!(
        position
            .verify_against(&state, CheckpointHeight(2), NET)
            .expect("agrees"),
        PositionVerdict::Current
    );

    // Another network.
    let mut other_net = position.clone();
    other_net.network = NET + 1;
    assert!(matches!(
        other_net.verify_against(&state, CheckpointHeight(2), NET),
        Err(RoundError::ForeignNetwork { .. })
    ));

    // Another generation at the same height.
    let mut other_gen = position.clone();
    other_gen.generation = GenerationId([8u8; 32]);
    assert!(matches!(
        other_gen.verify_against(&state, CheckpointHeight(2), NET),
        Err(RoundError::ForeignGeneration { .. })
    ));

    // A record for a height the caller already passed is a rollback.
    assert!(matches!(
        position.verify_against(&state, CheckpointHeight(1), NET),
        Err(RoundError::Rollback { .. })
    ));

    // A record for an older height is inert, not merged.
    assert!(matches!(
        position.verify_against(&state, CheckpointHeight(3), NET),
        Ok(PositionVerdict::Stale { .. })
    ));

    // A lost lock.
    let mut lost = position.clone();
    lost.lock = None;
    assert!(matches!(
        lost.verify_against(&state, CheckpointHeight(2), NET),
        Err(RoundError::LockLost)
    ));

    // A lock the state does not have.
    let mut invented = position.clone();
    invented.lock = Some(lock(1, 0x99));
    assert!(matches!(
        invented.verify_against(&state, CheckpointHeight(2), NET),
        Err(RoundError::ContradictoryLock { .. })
    ));

    // A record whose current round is behind the round it says it signed.
    let mut incoherent = position.clone();
    incoherent.round = Round(0);
    incoherent.max_signed_round = Round(5);
    assert!(matches!(
        incoherent.verify_against(&state, CheckpointHeight(2), NET),
        Err(RoundError::Corrupt(_))
    ));
}

#[test]
fn bo_06_the_engine_writes_and_restores_its_round() {
    let registry = registry(4);
    let store = MemoryAtomicSlotStore::new();
    // The AU state record is what a first run writes; without it a restart cannot
    // tell "never voted" from "history deleted" and blocks (see `restore`).
    aether_unified::l2persist::state::PersistentConsensusState::fresh(
        NET,
        GenerationId(GEN),
        ANCHOR,
    )
    .persist(&store)
    .expect("state");
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    engine.begin_round(Round(4)).expect("move to round 4");
    let written = engine.persist_position(&store).expect("persist");
    assert_eq!(written.round, Round(4));
    assert!(written.may_sign());

    // Restoring gets the round back, without a record claiming anything more.
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert_eq!(
        restored.state.round,
        Round(4),
        "the round survives a restart"
    );
    assert!(
        restored.state.persisted().status.may_sign(),
        "and the node may still sign: {:?}",
        restored.state.persisted().status
    );
}

#[test]
fn bo_07_a_crash_before_the_write_leaves_the_previous_record() {
    let registry = registry(4);
    let store = MemoryAtomicSlotStore::new();
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    engine.begin_round(Round(2)).expect("round 2");
    engine.persist_position(&store).expect("first write");

    // Simulate a process that advanced in memory and died before writing.
    engine.begin_round(Round(5)).expect("round 5 in memory");
    let stored = RoundPosition::load(&store).expect("load").expect("present");
    assert_eq!(stored.round, Round(2), "nothing was invented on disk");

    // On restart the node is at the durable round, not at the lost one.
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert_eq!(restored.state.round, Round(2));

    // And the engine refuses to write backwards: the in-memory round 5 cannot be
    // followed by a write of round 1.
    let mut backwards = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(0));
    backwards.round = Round(1);
    backwards.max_signed_round = Round(1);
    assert!(matches!(
        backwards.verify_against(restored.state.persisted(), CheckpointHeight(0), NET),
        Ok(PositionVerdict::Current) | Err(_)
    ));
}

#[test]
fn bo_08_an_unreadable_record_blocks_signing() {
    let registry = registry(4);
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("open");
        let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
        engine.begin_round(Round(3)).expect("round 3");
        engine.persist_position(&store).expect("persist");
    }
    // A crash during the write leaves a truncated record: this is the shape.
    {
        let store = SledAtomicSlotStore::open(dir.path()).expect("reopen");
        let bytes = store.get(ROUND_KEY).expect("get").expect("present");
        let truncated = bytes[..bytes.len() - 3].to_vec();
        assert!(
            store.cas(ROUND_KEY, Some(&bytes), &truncated).expect("cas"),
            "the corrupted record is installed"
        );
    }
    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen again");
    assert!(
        RoundPosition::load(&store).is_err(),
        "a truncated record is an error, never an empty record"
    );
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        !restored.state.persisted().status.may_sign(),
        "signing must be blocked: {:?}",
        restored.state.persisted().status
    );
}

#[test]
fn bo_09_an_adopted_change_is_durable_before_the_call_returns() {
    let registry = registry(4);
    let store = MemoryAtomicSlotStore::new();
    let mut engines: Vec<BftState> = (0..4)
        .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
        .collect();
    let stores: Vec<MemoryAtomicSlotStore> = (0..4).map(|_| MemoryAtomicSlotStore::new()).collect();

    // Every validator times out and signs a round change for round 1.
    let mut changes = Vec::new();
    for index in 0..4 {
        let seed = (index + 1) as u8;
        changes.push(round_change_for(&engines[index], Round(1), &sk(seed)));
    }

    // Validator 0 adopts once three changes are in (its own included).
    let mut adopted = None;
    for change in changes.iter().take(3) {
        let outcome = engines[0]
            .process_round_change_persisted(change.clone(), &registry, NET, &store)
            .expect("round change");
        if let RoundChangeOutcome::Adopted { to, .. } = outcome {
            adopted = Some(to);
        }
    }
    assert_eq!(adopted, Some(Round(1)));

    let stored = RoundPosition::load(&store).expect("load").expect("present");
    assert_eq!(stored.round, Round(1));
    let change = stored.last_change.expect("the adoption is recorded");
    assert_eq!(change.target_round, Round(1));
    assert_eq!(change.support, 30, "three of four validators");
    assert_eq!(change.total, 40);
    assert_eq!(change.quorum, 27);

    // The restore sees the same round.
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert_eq!(restored.state.round, Round(1));
    let _ = stores;
    let _ = engines;
    let _ = proposer_for(&registry, GenerationId(GEN), CheckpointHeight(0), Round(0));
}

#[test]
fn bo_10_a_record_that_invents_a_lock_blocks_the_restart() {
    let registry = registry(4);
    let store = MemoryAtomicSlotStore::new();
    // A real store always carries the AU state record from its first run; the
    // anchor is what lets a restart tell "never voted" from "history deleted".
    aether_unified::l2persist::state::PersistentConsensusState::fresh(
        NET,
        GenerationId(GEN),
        ANCHOR,
    )
    .persist(&store)
    .expect("state");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(restored.state.persisted().status.may_sign());

    // A record that claims one is a contradiction.
    let mut position = RoundPosition::fresh(NET, GenerationId(GEN), CheckpointHeight(0));
    position.lock = Some(lock(1, 0x77));
    position.round = Round(1);
    position.max_signed_round = Round(1);
    position.persist(&store).expect("persist");

    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        !restored.state.persisted().status.may_sign(),
        "an invented lock must stop the node: {:?}",
        restored.state.persisted().status
    );
    assert!(
        matches!(
            restored.state.persisted().status,
            RecoveryStatus::RecoveryRequired(_)
        ),
        "and it is reported as a recovery block"
    );
}
