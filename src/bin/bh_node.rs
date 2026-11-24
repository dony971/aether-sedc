//! Crash/restart harness for mission BH, priority 3.
//!
//! This is **not** a node. It is the child process the persistence tests spawn so
//! that "restart" means what it says: a second operating-system process, on a
//! directory that outlived the first one.
//!
//! ```text
//! bh_node run     <store-dir> <scenario> [seed]
//! bh_node resume  <store-dir> <scenario> [seed]
//! bh_node release <store-dir>
//! ```
//!
//! `run` opens a real `SledAtomicSlotStore`, executes the scenario's steps,
//! journaling each durable one to `<store-dir>/journal.log`, and then calls
//! `std::process::abort()`: no destructor runs, the store lock file is left behind.
//! `resume` opens the same directory and reports what the new process can prove.
//! `release` performs the operator action `SlotStoreGuard::release_stale`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::exit;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    AdmittedSet, CandidateOperator, GenerationClosure, SetPolicy,
};
use aether_unified::l2bft::engine::HaltReason;
use aether_unified::l2bft::{restore_engine, BftState};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::VotePhase;
use aether_unified::l2persist::state::PersistentConsensusState;
use aether_unified::l2persist::{
    AtomicSlotStore, CasStore, MemoryAtomicSlotStore, SledAtomicSlotStore, SlotKey, SlotStoreGuard,
    STATE_KEY,
};

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

fn admitted() -> AdmittedSet {
    let old = registry();
    AdmittedSet::admit(
        &policy(old.total_voting_weight().get()),
        &candidates(&SEEDS, WEIGHT),
        1,
        0,
        Some(&old),
    )
    .expect("admissible set")
}

fn transition_candidate() -> [u8; 32] {
    let old = registry();
    admitted().candidate_id(old.generation(), CheckpointHeight(0), old.set_root())
}

fn transition_for(scenario: &str) -> Option<[u8; 32]> {
    if scenario == "transition" {
        Some(transition_candidate())
    } else {
        None
    }
}

/// The checkpoint the scenario decides at height 0.
fn checkpoint(transition: Option<[u8; 32]>) -> Checkpoint {
    Checkpoint::new(
        registry().generation(),
        CheckpointHeight(0),
        [0u8; 32],
        [0x22; 32],
        [0x33; 32],
        registry().set_root(),
        transition,
    )
    .expect("checkpoint")
}

/// The value every vote commits to: the checkpoint's own identifier.
///
/// `finalize` requires the certified value to be exactly `checkpoint.id()`, so the
/// harness votes the identifier and never an arbitrary salt.
fn value_for(scenario: &str) -> [u8; 32] {
    checkpoint(transition_for(scenario)).id()
}

fn other_value() -> [u8; 32] {
    [0x99; 32]
}

fn journal(dir: &Path, line: &str) {
    let path = dir.join("journal.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("journal");
    writeln!(file, "{line}").expect("journal write");
    file.sync_all().expect("journal sync");
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

/// A prevote quorum, using in-memory peer engines.
///
/// The peers are simulated inside this process: what must be durable is **this**
/// validator's own state, and a second process holding a peer's vote would not make
/// the store any more or less persistent.
fn prevote_quorum(
    engine: &mut BftState,
    store: &SledAtomicSlotStore,
    seed: u8,
    value: [u8; 32],
) -> aether_unified::l2bft::PrevoteCertificate {
    let registry = registry();
    let own = engine
        .prevote(value, vid(seed), &registry, store, sign_with(seed))
        .expect("own prevote");
    let mut votes = vec![own.vote().clone()];
    let mut peers: Vec<BftState> = Vec::new();
    for peer in SEEDS.iter().filter(|candidate| **candidate != seed) {
        let mut peer_engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
        let peer_store = MemoryAtomicSlotStore::new();
        let vote = peer_engine
            .prevote(value, vid(*peer), &registry, &peer_store, sign_with(*peer))
            .expect("peer prevote");
        votes.push(vote.vote().clone());
        peers.push(peer_engine);
    }
    for vote in &votes {
        engine.accept_vote(vote, &registry);
    }
    engine
        .certify_prevotes_for(value, &registry)
        .expect("prevote quorum")
}

fn precommit_quorum(
    engine: &mut BftState,
    store: &SledAtomicSlotStore,
    seed: u8,
    value: [u8; 32],
) -> aether_unified::l2bft::PrecommitCertificate {
    let registry = registry();
    let pol = prevote_quorum(engine, store, seed, value);
    let own = engine
        .precommit(&pol, vid(seed), &registry, store, sign_with(seed))
        .expect("own precommit");
    let mut votes = vec![own.vote().clone()];
    for peer in SEEDS.iter().filter(|candidate| **candidate != seed) {
        let mut peer_engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
        let peer_store = MemoryAtomicSlotStore::new();
        for vote in engine.round_state.prevotes.iter() {
            peer_engine.accept_vote(vote.vote(), &registry);
        }
        let precommit = peer_engine
            .precommit(&pol, vid(*peer), &registry, &peer_store, sign_with(*peer))
            .expect("peer precommit");
        votes.push(precommit.vote().clone());
    }
    for vote in &votes {
        engine.accept_vote(vote, &registry);
    }
    engine
        .certify_precommits_for(value, &registry)
        .expect("precommit quorum")
}

fn restore_height(scenario: &str) -> CheckpointHeight {
    if scenario == "transition" {
        CheckpointHeight(1)
    } else {
        CheckpointHeight(0)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: bh_node <run|resume|release> <store-dir> [scenario] [seed]");
        exit(2);
    }
    let command = args[0].as_str();
    let dir = Path::new(&args[1]).to_path_buf();

    if command == "release" {
        match SlotStoreGuard::release_stale(&dir) {
            Ok(pid) => println!("RELEASED={pid}"),
            Err(error) => println!("RELEASE_ERROR={error}"),
        }
        return;
    }

    let scenario = args.get(2).map(|value| value.as_str()).unwrap_or("prevote");
    let seed: u8 = args
        .get(3)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);

    match command {
        "run" => crash_run(&dir, scenario, seed),
        "resume" => report(&dir, scenario, seed),
        other => {
            eprintln!("unknown command {other}");
            exit(2);
        }
    }
}

fn crash_run(dir: &Path, scenario: &str, seed: u8) {
    let store = match SledAtomicSlotStore::open(dir) {
        Ok(store) => store,
        Err(error) => {
            println!("RESULT=locked");
            println!("ERROR={error}");
            exit(3);
        }
    };
    let registry = registry();

    // The store identity must exist before any vote, otherwise a restart cannot
    // tell "never voted" from "vote history lost".
    let init = PersistentConsensusState::fresh(NET, registry.generation(), ANCHOR);
    store
        .cas(
            STATE_KEY,
            None,
            &aether_unified::l2persist::seal(&init.encode()),
        )
        .expect("initial state record");
    store.flush().expect("flush");
    journal(dir, "store_initialised");

    if scenario == "reserved" {
        // BH-09: the slot is reserved and flushed, and no signature exists yet.
        let key = SlotKey {
            generation: registry.generation().0,
            height: CheckpointHeight(0),
            round: Round(0),
            phase: VotePhase::Precommit,
            validator: vid(seed),
        };
        let value = value_for(scenario);
        store.reserve(&key, &value).expect("reserve");
        store.flush().expect("flush");
        journal(dir, "slot_reserved");
        std::process::abort();
    }

    if scenario == "halt" {
        let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
        engine
            .halt_with(
                HaltReason::Persisted("bh scenario: operator visible".to_string()),
                &store,
            )
            .expect("halt");
        journal(dir, "halt_recorded");
        std::process::abort();
    }

    let value = value_for(scenario);
    let mut engine = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let own = engine
        .prevote(value, vid(seed), &registry, &store, sign_with(seed))
        .expect("prevote");
    journal(
        dir,
        &format!("prevote_signed id={}", hex::encode(own.checkpoint_id())),
    );
    if scenario == "prevote" {
        std::process::abort();
    }

    if scenario == "qc" {
        let _pol = prevote_quorum(&mut engine, &store, seed, value);
        journal(dir, "qc_certified");
        std::process::abort();
    }

    let qc = precommit_quorum(&mut engine, &store, seed, value);
    let lock = engine
        .persisted()
        .locked
        .expect("a precommit writes the lock before the signature");
    journal(
        dir,
        &format!(
            "precommit_signed lock={} round={}",
            hex::encode(lock.checkpoint_id),
            lock.round.get()
        ),
    );
    if scenario == "precommit" {
        std::process::abort();
    }

    let cp = checkpoint(transition_for(scenario));
    let decision = engine
        .finalize(&qc, &cp, None, &registry, &store)
        .expect("finality");
    journal(
        dir,
        &format!(
            "checkpoint_decided id={} height={}",
            hex::encode(decision.checkpoint_id),
            decision.height.get()
        ),
    );
    if scenario == "checkpoint" {
        std::process::abort();
    }

    if scenario == "transition" {
        let old = registry.clone();
        let set = admitted();
        let candidate = transition_candidate();
        // Mission BQ: the production path installs the **canonical** identity —
        // the registry whose generation id is the transition the quorum signed
        // (`AdmittedSet::registry_for`), not the position-derived legacy label.
        let next = set
            .registry_for(&old, CheckpointHeight(0))
            .expect("canonical registry");
        let closure = GenerationClosure {
            height: CheckpointHeight(0),
            generation: old.generation(),
            value_id: cp.id(),
            candidate_id: candidate,
            new_set_root: next.set_root(),
        };
        engine
            .close_generation(closure, &next, &store)
            .expect("closure");
        engine
            .advance_height(CheckpointHeight(1), &store)
            .expect("advance");
        journal(
            dir,
            &format!(
                "generation_closed to={} canonical={} first_height=1",
                hex::encode(engine.generation.0),
                hex::encode(next.generation().0)
            ),
        );
        std::process::abort();
    }

    journal(dir, "scenario_complete");
    std::process::abort();
}

fn report(dir: &Path, scenario: &str, seed: u8) {
    let store = match SledAtomicSlotStore::open(dir) {
        Ok(store) => store,
        Err(error) => {
            // Fail closed: a crashed store is refused exactly like a live one.
            println!("RESULT=locked");
            println!("ERROR={error}");
            exit(3);
        }
    };
    // After a transition the generation in force is the installed one: a restore
    // with the old registry would be refused as "not in force". The installed
    // identity is the canonical one (mission BQ).
    let registry = if scenario == "transition" {
        let old = registry();
        admitted()
            .registry_for(&old, CheckpointHeight(0))
            .expect("canonical registry")
    } else {
        registry()
    };
    let height = restore_height(scenario);
    let value = value_for(scenario);
    let mut restored = restore_engine(&store, &registry, Some(ANCHOR), NET, height);

    println!("RESULT=opened");
    println!("STATUS={:?}", restored.state.persisted().status);
    println!("MAY_SIGN={}", u8::from(restored.state.may_sign().is_ok()));
    println!("GENERATION={}", hex::encode(restored.state.generation.0));
    match &restored.state.persisted().locked {
        Some(lock) => {
            println!("LOCK={}", hex::encode(lock.checkpoint_id));
            println!("LOCK_ROUND={}", lock.round.get());
            println!("LOCK_HEIGHT={}", lock.height.get());
        }
        None => {
            println!("LOCK=none");
            println!("LOCK_ROUND=none");
            println!("LOCK_HEIGHT=none");
        }
    }
    println!("HALT={}", u8::from(restored.halt.is_some()));
    println!("DECISIONS={}", restored.decisions.len());
    println!(
        "TIP={}",
        restored
            .decisions
            .last()
            .map(|decision| decision.height.get().to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "FINALITY={}",
        restored
            .decisions
            .last()
            .map(|decision| hex::encode(decision.checkpoint_id))
            .unwrap_or_else(|| "none".to_string())
    );
    println!("VALUE={}", hex::encode(value));
    println!("HEIGHT={}", height.get());
    println!("BACKEND={}", store.backend());

    // Replay the exact vote already signed: it must come back as the same vote.
    match restored
        .state
        .prevote(value, vid(seed), &registry, &store, sign_with(seed))
    {
        Ok(vote) if vote.checkpoint_id() == value => println!("REPLAY=ok-same"),
        Ok(_) => println!("REPLAY=other-value"),
        Err(error) => println!("REPLAY=refused:{}", one_line(&error.to_string())),
    }

    // A contradictory signature at the same height and round must be impossible.
    match restored
        .state
        .prevote(other_value(), vid(seed), &registry, &store, sign_with(seed))
    {
        Ok(_) => println!("EQUIVOCATION=accepted"),
        Err(error) => println!("EQUIVOCATION=refused:{}", one_line(&error.to_string())),
    }

    let signed = restored
        .state
        .prevote([0x11; 32], vid(seed), &registry, &store, sign_with(seed));
    println!(
        "SIGN_AFTER_RESTORE={}",
        if signed.is_ok() { "ok" } else { "refused" }
    );
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
