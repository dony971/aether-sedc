//! Mission BH — real process restart over a persistent store (priority 3).
//!
//! Every scenario here runs `bh_node`, which opens a real `SledAtomicSlotStore`,
//! reaches a durable point, journals it, and then calls `std::process::abort()`.
//! No destructor runs, the database is not closed, the lock file stays behind.
//! A **second process** then reopens the directory and reports what it can prove.
//!
//! | Test | Stops after | Must show after restart |
//! |---|---|---|
//! | `bh_01` | a signed prevote | signing works, the same vote is returned |
//! | `bh_02` | a precommit + lock | the lock is restored, no second signature |
//! | `bh_03` | a certified prevote quorum | nothing durable, signing permitted |
//! | `bh_04` | a finality decision | the decision survives, equivocation refused |
//! | `bh_05` | a generation closure | the active generation is the new one |
//! | `bh_06` | a halt record | still halted, signing refused |
//! | `bh_07` | — | an incomplete store is refused, never "repaired" |
//! | `bh_08` | — | contradictory records block signing |
//! | `bh_09` | **inside** a slot write | a reserved slot with no lock blocks signing |
//! | `bh_10` | four validators at once | all recover the same decision |
//!
//! What is **not** claimed: that a decision cannot be lost on a device that loses
//! an fsync. See `remaining-risks.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{restore_engine, BftState};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::VotePhase;
use aether_unified::l2persist::state::{PersistentConsensusState, RecoveryReason, RecoveryStatus};
use aether_unified::l2persist::{
    open_sealed, seal, CasStore, MemoryAtomicSlotStore, SledAtomicSlotStore, SlotStoreGuard,
    STATE_KEY,
};
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 71;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const SEEDS: [u8; 4] = [1, 2, 3, 4];
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

fn registry() -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = SEEDS
        .iter()
        .map(|seed| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(WEIGHT),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

fn value() -> [u8; 32] {
    [0x42; 32]
}

fn store_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp store dir");
    dir
}

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_bh_node")
}

fn run_child(dir: &Path, scenario: &str, seed: u8) -> Output {
    Command::new(exe())
        .arg("run")
        .arg(dir)
        .arg(scenario)
        .arg(seed.to_string())
        .output()
        .expect("spawn bh_node run")
}

fn resume_child(dir: &Path, scenario: &str, seed: u8) -> Output {
    Command::new(exe())
        .arg("resume")
        .arg(dir)
        .arg(scenario)
        .arg(seed.to_string())
        .output()
        .expect("spawn bh_node resume")
}

fn release(dir: &Path) -> Output {
    Command::new(exe())
        .arg("release")
        .arg(dir)
        .output()
        .expect("spawn bh_node release")
}

fn fields(output: &Output) -> BTreeMap<String, String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            line.split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
        })
        .collect()
}

fn journal(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("journal.log")).unwrap_or_default()
}

/// Run the scenario to its crash, then prove the crashed store fails closed.
fn crash(dir: &Path, scenario: &str, seed: u8) -> String {
    let crashed = run_child(dir, scenario, seed);
    assert!(
        !crashed.status.success(),
        "{scenario}: the child must die abruptly, not exit cleanly"
    );
    let text = journal(dir);
    assert!(
        !text.trim().is_empty(),
        "{scenario}: the state before the stop must be journaled"
    );
    let refused = resume_child(dir, scenario, seed);
    assert_eq!(
        refused.status.code(),
        Some(3),
        "{scenario}: a crashed store must be refused until the lock is released"
    );
    assert!(fields(&refused)
        .get("RESULT")
        .map(|value| value == "locked")
        .unwrap_or(false));
    let released = release(dir);
    assert!(String::from_utf8_lossy(&released.stdout).contains("RELEASED="));
    text
}

fn recovered(dir: &Path, scenario: &str, seed: u8) -> BTreeMap<String, String> {
    let output = resume_child(dir, scenario, seed);
    assert!(
        output.status.success(),
        "{scenario}: resume failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let map = fields(&output);
    assert_eq!(map.get("RESULT").map(String::as_str), Some("opened"));
    assert_eq!(map.get("BACKEND").map(String::as_str), Some("sled-cas"));
    map
}

// ---------------------------------------------------------------------------
// BH-01 .. BH-06: one validator, six durable points
// ---------------------------------------------------------------------------

#[test]
fn bh_01_restart_after_a_prevote_keeps_the_signature() {
    let dir = store_dir("bh01");
    let text = crash(&dir, "prevote", 1);
    assert!(text.contains("prevote_signed"), "journal: {text}");
    assert!(!text.contains("checkpoint_decided"));

    let map = recovered(&dir, "prevote", 1);
    assert_eq!(map["MAY_SIGN"], "1");
    assert_eq!(map["LOCK"], "none", "a prevote never writes the lock");
    assert_eq!(map["DECISIONS"], "0");
    assert_eq!(map["HALT"], "0");
    assert_eq!(
        map["REPLAY"], "ok-same",
        "the same vote is returned, not a new signature"
    );
    assert!(
        map["EQUIVOCATION"].starts_with("refused"),
        "a contradictory vote at the same slot is impossible: {}",
        map["EQUIVOCATION"]
    );
}

#[test]
fn bh_02_restart_after_a_precommit_keeps_the_lock() {
    let dir = store_dir("bh02");
    let text = crash(&dir, "precommit", 1);
    assert!(text.contains("precommit_signed"), "journal: {text}");

    let map = recovered(&dir, "precommit", 1);
    assert_eq!(map["MAY_SIGN"], "1");
    assert_eq!(
        map["LOCK"], map["VALUE"],
        "the restored lock names the value the durable precommit signed"
    );
    assert_eq!(map["LOCK_ROUND"], "0");
    assert_eq!(map["DECISIONS"], "0");
    assert_eq!(map["REPLAY"], "ok-same");
    assert!(map["EQUIVOCATION"].starts_with("refused"));
}

#[test]
fn bh_03_restart_after_a_qc_leaves_a_usable_node() {
    let dir = store_dir("bh03");
    let text = crash(&dir, "qc", 1);
    assert!(text.contains("qc_certified"), "journal: {text}");

    let map = recovered(&dir, "qc", 1);
    assert_eq!(map["MAY_SIGN"], "1");
    assert_eq!(map["DECISIONS"], "0", "a QC is not a decision");
    assert_eq!(map["LOCK"], "none");
    assert_eq!(map["REPLAY"], "ok-same");
    assert!(map["EQUIVOCATION"].starts_with("refused"));
}

#[test]
fn bh_04_restart_after_a_decision_keeps_it() {
    let dir = store_dir("bh04");
    let text = crash(&dir, "checkpoint", 1);
    assert!(text.contains("checkpoint_decided"), "journal: {text}");

    let map = recovered(&dir, "checkpoint", 1);
    assert_eq!(map["DECISIONS"], "1");
    assert_eq!(map["TIP"], "0");
    assert_ne!(map["FINALITY"], "none");
    assert_eq!(map["MAY_SIGN"], "1");
    assert!(map["EQUIVOCATION"].starts_with("refused"));
}

#[test]
fn bh_05_restart_after_a_generation_transition_keeps_the_new_generation() {
    let dir = store_dir("bh05");
    let text = crash(&dir, "transition", 1);
    assert!(text.contains("generation_closed"), "journal: {text}");
    assert!(text.contains("first_height=1"), "journal: {text}");

    let map = recovered(&dir, "transition", 1);
    assert_eq!(map["HEIGHT"], "1");
    assert_eq!(map["DECISIONS"], "1");
    assert_ne!(
        map["GENERATION"],
        hex::encode(GenerationId(GEN).0),
        "the restored generation must be the installed one"
    );
    assert_eq!(map["MAY_SIGN"], "1");
}

#[test]
fn bh_06_restart_after_a_halt_record_stays_halted() {
    let dir = store_dir("bh06");
    let text = crash(&dir, "halt", 1);
    assert!(text.contains("halt_recorded"), "journal: {text}");

    let map = recovered(&dir, "halt", 1);
    assert_eq!(map["HALT"], "1");
    assert!(
        map["MAY_SIGN"] == "0",
        "a halted node signs nothing after a restart: {}",
        map["MAY_SIGN"]
    );
    assert!(
        map["SIGN_AFTER_RESTORE"] == "refused",
        "no signature may survive a halt"
    );
}

// ---------------------------------------------------------------------------
// BH-07 .. BH-08: damaged stores, in process, on the same durable backend
// ---------------------------------------------------------------------------

/// A real lock + precommit at height 0, written to disk and closed.
fn durable_precommit(dir: &Path) {
    let registry = registry();
    let store = SledAtomicSlotStore::open(dir).expect("open");
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let own = engine
        .prevote(value(), vid(1), &registry, &store, sign_with(1))
        .expect("prevote");
    let mut votes = vec![own.vote().clone()];
    for seed in [2u8, 3, 4] {
        let mut peer = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
        let peer_store = MemoryAtomicSlotStore::new();
        let vote = peer
            .prevote(value(), vid(seed), &registry, &peer_store, sign_with(seed))
            .expect("peer prevote");
        votes.push(vote.vote().clone());
    }
    for vote in &votes {
        engine.accept_vote(vote, &registry);
    }
    let pol = engine
        .certify_prevotes_for(value(), &registry)
        .expect("prevote quorum");
    for seed in [2u8, 3, 4] {
        let mut peer = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
        let peer_store = MemoryAtomicSlotStore::new();
        for vote in engine.round_state.prevotes.iter() {
            peer.accept_vote(vote.vote(), &registry);
        }
        let precommit = peer
            .precommit(&pol, vid(seed), &registry, &peer_store, sign_with(seed))
            .expect("peer precommit");
        votes.push(precommit.vote().clone());
    }
    engine
        .precommit(&pol, vid(1), &registry, &store, sign_with(1))
        .expect("own precommit");
    store.flush().expect("flush");
}

#[test]
fn bh_07_incomplete_store_is_refused_not_repaired() {
    let dir = store_dir("bh07");
    durable_precommit(&dir);

    // (a) The store belongs to another installation.
    {
        let store = SledAtomicSlotStore::open(&dir).expect("open");
        let restored = restore_engine(
            &store,
            &registry(),
            Some([0xEE; 32]),
            NET,
            CheckpointHeight(0),
        );
        assert!(
            !restored.state.may_sign().is_ok(),
            "a foreign anchor must block signing"
        );
        match &restored.state.persisted().status {
            RecoveryStatus::RecoveryRequired(RecoveryReason::ForeignAnchor { .. }) => {}
            other => panic!("expected ForeignAnchor, got {other:?}"),
        }
    }

    // (b) A state record that cannot be decoded is not "no prior vote".
    {
        let store = SledAtomicSlotStore::open(&dir).expect("open");
        let sealed = store.get(STATE_KEY).expect("read").expect("state record");
        let truncated = seal(&[0x01u8, 0x02, 0x03]);
        assert!(store
            .cas(STATE_KEY, Some(&sealed), &truncated)
            .expect("cas"));
        store.flush().expect("flush");
    }
    {
        let store = SledAtomicSlotStore::open(&dir).expect("open");
        let restored = restore_engine(&store, &registry(), Some(ANCHOR), NET, CheckpointHeight(0));
        assert!(
            !restored.state.may_sign().is_ok(),
            "an undecodable state record must block signing"
        );
        match &restored.state.persisted().status {
            RecoveryStatus::RecoveryRequired(RecoveryReason::CorruptState(_)) => {}
            other => panic!("expected CorruptState, got {other:?}"),
        }
    }
    let _ = SlotStoreGuard::release_stale(&dir);
}

#[test]
fn bh_08_contradictory_records_block_signing() {
    let dir = store_dir("bh08");
    durable_precommit(&dir);

    // Rewrite the lock so it names a value the durable precommit does not.
    {
        let store = SledAtomicSlotStore::open(&dir).expect("open");
        let sealed = store.get(STATE_KEY).expect("read").expect("state record");
        let payload = open_sealed(&sealed).expect("sealed").to_vec();
        let mut state = PersistentConsensusState::decode(&payload).expect("decodable");
        state
            .locked
            .as_mut()
            .expect("a lock was written")
            .checkpoint_id = [0x77; 32];
        let forged = seal(&state.encode());
        assert!(store.cas(STATE_KEY, Some(&sealed), &forged).expect("cas"));
        store.flush().expect("flush");
    }
    {
        let store = SledAtomicSlotStore::open(&dir).expect("open");
        let restored = restore_engine(&store, &registry(), Some(ANCHOR), NET, CheckpointHeight(0));
        assert!(
            !restored.state.may_sign().is_ok(),
            "a lock that contradicts the vote slots must block signing"
        );
        match &restored.state.persisted().status {
            RecoveryStatus::RecoveryRequired(RecoveryReason::ContradictoryLock(_)) => {}
            other => panic!("expected ContradictoryLock, got {other:?}"),
        }
    }
    let _ = SlotStoreGuard::release_stale(&dir);
}

// ---------------------------------------------------------------------------
// BH-09 .. BH-10
// ---------------------------------------------------------------------------

#[test]
fn bh_09_crash_during_a_slot_write_blocks_signing() {
    let dir = store_dir("bh09");
    let text = crash(&dir, "reserved", 1);
    assert!(text.contains("slot_reserved"), "journal: {text}");
    assert!(
        !text.contains("precommit_signed"),
        "no signature may exist at this point"
    );

    let map = recovered(&dir, "reserved", 1);
    assert!(
        map["MAY_SIGN"] == "0",
        "a reserved precommit with no lock is not a state to sign from: {}",
        map["STATUS"]
    );
    assert!(
        map["STATUS"].contains("RecoveryRequired"),
        "status: {}",
        map["STATUS"]
    );
    assert_eq!(
        map["SIGN_AFTER_RESTORE"], "refused",
        "and no signature is produced"
    );
}

#[test]
fn bh_10_simultaneous_restart_of_four_validators_converges() {
    let dirs: Vec<PathBuf> = (1..=4u8)
        .map(|seed| store_dir(&format!("bh10-{seed}")))
        .collect();

    // Four independent processes reach a durable decision, each in its own store,
    // and all four are killed without unwinding.
    let mut children: Vec<_> = dirs
        .iter()
        .enumerate()
        .map(|(index, dir)| {
            Command::new(exe())
                .arg("run")
                .arg(dir)
                .arg("checkpoint")
                .arg((index + 1).to_string())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn")
        })
        .collect();
    for child in &mut children {
        let status = child.wait().expect("wait");
        assert!(
            !status.success(),
            "each validator must die abruptly, not exit cleanly"
        );
    }

    // All four are restarted at the same time, in their own stores.
    for dir in &dirs {
        let _ = release(dir);
    }
    let mut restarted: Vec<_> = dirs
        .iter()
        .enumerate()
        .map(|(index, dir)| {
            Command::new(exe())
                .arg("resume")
                .arg(dir)
                .arg("checkpoint")
                .arg((index + 1).to_string())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn resume")
        })
        .collect();
    let mut maps = Vec::new();
    for child in restarted {
        let output = child.wait_with_output().expect("wait_with_output");
        assert!(output.status.success(), "resume failed");
        maps.push(fields(&output));
    }

    let mut finalities = Vec::new();
    for map in &maps {
        assert_eq!(
            map.get("DECISIONS").map(String::as_str),
            Some("1"),
            "resume output: {map:?}"
        );
        assert_eq!(
            map.get("MAY_SIGN").map(String::as_str),
            Some("1"),
            "{map:?}"
        );
        assert_eq!(map["HALT"], "0");
        assert_eq!(map["REPLAY"], "ok-same");
        assert!(map["EQUIVOCATION"].starts_with("refused"));
        finalities.push(map["FINALITY"].clone());
    }
    assert!(
        finalities.windows(2).all(|pair| pair[0] == pair[1]),
        "four simultaneous restarts must recover the same decision: {finalities:?}"
    );
}

// Keep the unused-import checker honest about the API this file documents.
#[allow(dead_code)]
fn _phase(vote: &aether_unified::l2crypto::vote::ConsensusVote) -> VotePhase {
    vote.phase
}

#[allow(dead_code)]
fn _sealed(bytes: &[u8]) -> bool {
    open_sealed(bytes).is_ok()
}

#[allow(dead_code)]
fn _id(seed: u8) -> ValidatorId {
    vid(seed)
}

#[allow(dead_code)]
fn _slot_api(store: &SledAtomicSlotStore) -> bool {
    let _ = store.backend();
    true
}
