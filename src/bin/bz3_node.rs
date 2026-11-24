//! Mission BZ.3 §9 — a real validator process.
//!
//! One operating-system process, one `SledAtomicSlotStore`, one Ed25519 key, one
//! listening socket. Four of these run at once; nothing is simulated inside a
//! single process. Every consensus action goes through the `Node` interface added
//! by this mission: the driver never touches `BftState` fields, never signs with
//! the engine's internals, and never re-implements a rule.
//!
//! ```text
//! bz3_node run     <seed> <listen> <store-dir> <peer,peer,...>
//! bz3_node resume  <seed> <listen> <store-dir> <peer,peer,...>
//! bz3_node release <store-dir>
//! ```
//!
//! `run` starts from a fresh store. `resume` restores the store first and reports
//! what the new process can prove before it continues. `release` performs the
//! operator action `SlotStoreGuard::release_stale` on a directory left locked by a
//! killed process.
//!
//! Environment:
//! - `BZ3_HEIGHTS`         how many heights to decide (default 1);
//! - `BZ3_ROUND_AFTER_MS`  stall before asking for a round change (0 = never);
//! - `BZ3_SECONDS`         deadline for the whole run (default 20);
//! - `BZ3_SYNC`            `1` asks each peer for its history and stops after
//!                         installing it, so a later `resume` can prove catch-up.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::restore_engine;
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::state::PersistentConsensusState;
use aether_unified::l2persist::{seal, CasStore, SledAtomicSlotStore, SlotStoreGuard, STATE_KEY};
use aether_unified::network::{MessageKind, Node, PeerLimits};

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

/// The checkpoint decided at `height`, chained on `parent`.
///
/// The value every vote commits to is the checkpoint's own identifier: `finalize`
/// requires the certified value to be exactly `checkpoint.id()`, so the driver
/// votes the identifier and never an arbitrary salt.
fn checkpoint(height: u64, parent: Option<&Checkpoint>) -> Checkpoint {
    let registry = registry();
    Checkpoint::new(
        registry.generation(),
        CheckpointHeight(height),
        parent.map(|previous| previous.id()).unwrap_or([0u8; 32]),
        [0x22; 32],
        [0x33; 32],
        registry.set_root(),
        None,
    )
    .expect("checkpoint")
}

fn chain(heights: u64) -> Vec<Checkpoint> {
    let mut chain = Vec::new();
    let mut parent: Option<Checkpoint> = None;
    for height in 0..heights {
        let next = checkpoint(height, parent.as_ref());
        parent = Some(next);
        chain.push(next);
    }
    chain
}

fn limits() -> PeerLimits {
    PeerLimits {
        read_timeout: Duration::from_millis(20),
        write_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(15),
        max_messages_per_second: 2_000,
        ..PeerLimits::default()
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: bz3_node <run|resume|release> <store-dir> [seed] [listen] [peers]");
        exit(2);
    }
    let command = args[0].as_str();

    if command == "release" {
        let dir = PathBuf::from(&args[1]);
        match SlotStoreGuard::release_stale(&dir) {
            Ok(pid) => println!("RELEASED={pid}"),
            Err(error) => println!("RELEASE_ERROR={error}"),
        }
        return;
    }

    let seed: u8 = args
        .get(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let listen: SocketAddr = args
        .get(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:7101".parse().expect("address"));
    let dir = PathBuf::from(args.get(3).cloned().unwrap_or_default());
    let peers: Vec<SocketAddr> = args
        .get(4)
        .map(|value| {
            value
                .split(',')
                .filter(|part| !part.is_empty())
                .filter_map(|part| part.parse().ok())
                .collect()
        })
        .unwrap_or_default();

    match command {
        "run" => drive(&dir, seed, listen, &peers, false),
        "resume" => drive(&dir, seed, listen, &peers, true),
        other => {
            eprintln!("unknown command {other}");
            exit(2);
        }
    }
}

/// Open the store, releasing a lock left behind by a killed process.
///
/// The release is the documented operator action, not a bypass: it refuses a
/// directory whose owner is still alive, so a live validator is never stolen.
fn open_store(dir: &Path) -> SledAtomicSlotStore {
    // A process killed with `abort()` releases its handles as the OS tears it down,
    // and on Windows a reopen can hit the half-closed directory for a moment. The
    // retry is bounded and every attempt still goes through the documented release,
    // which refuses a live owner, so this cannot steal a running validator's store.
    let mut last = String::new();
    for _ in 0..20 {
        match SledAtomicSlotStore::open(dir) {
            Ok(store) => return store,
            Err(error) => {
                last = error.to_string();
                match SlotStoreGuard::release_stale(dir) {
                    Ok(pid) => println!("STALE_LOCK_RELEASED={pid} after: {error}"),
                    Err(release) => {
                        if std::env::var("BZ3_TRACE").is_ok() {
                            println!("RELEASE_WAIT={release}");
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    println!("RESULT=locked");
    println!("ERROR={last}");
    exit(3);
}

fn drive(dir: &Path, seed: u8, listen: SocketAddr, peers: &[SocketAddr], resume: bool) {
    let store = open_store(dir);
    let registry = registry();
    let heights = env_u64("BZ3_HEIGHTS").unwrap_or(1).max(1);
    let chain = chain(heights);
    let deadline = Instant::now() + Duration::from_secs(env_u64("BZ3_SECONDS").unwrap_or(20));
    let round_after = env_u64("BZ3_ROUND_AFTER_MS")
        .filter(|value| *value > 0)
        .map(Duration::from_millis);

    // A brand-new store must name the network and the anchor **before** any
    // signature: the engine refuses to sign without them, which is the difference
    // between "never voted" and "vote history lost".
    let init = PersistentConsensusState::fresh(NET, registry.generation(), ANCHOR);
    let _ = store.cas(STATE_KEY, None, &seal(&init.encode()));
    let _ = store.flush();

    // Restore first: a restarted validator must know what it already signed before
    // it is allowed to sign anything else.
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    let mut state = restored.state;
    let decided_before = restored.decisions.len();
    let finality_before = restored
        .decisions
        .last()
        .map(|decision| hex::encode(decision.checkpoint_id))
        .unwrap_or_else(|| "none".to_string());
    if resume || decided_before > 0 {
        println!("PROC=p{seed} RESTORED decisions={decided_before} finality={finality_before} halt={} may_sign={}",
            u8::from(restored.halt.is_some()),
            u8::from(state.may_sign().is_ok()));
    }

    // The restored height is the one after the last decision, so the chain the
    // driver votes continues where the store stopped rather than at genesis.
    let start_height = restored
        .decisions
        .last()
        .map(|decision| decision.height.get() + 1)
        .unwrap_or(0);
    if start_height > 0 {
        let _ = state.advance_height(CheckpointHeight(start_height), &store);
    }

    let mut node = match Node::bind_with_limits(listen, NET, sk(seed), state, registry, limits()) {
        Ok(node) => node,
        Err(error) => {
            println!("RESULT=bind_failed");
            println!("ERROR={error}");
            exit(3);
        }
    };
    node.attach_store(Box::new(store));
    println!(
        "PROC=p{seed} BOUND addr={} id={} height={} round={}",
        node.addr(),
        hex::encode(&node.id().0[..4]),
        node.status().height.get(),
        node.status().round.get()
    );

    connect(&mut node, peers, deadline);

    if std::env::var("BZ3_SYNC").ok().as_deref() == Some("1") {
        sync(&mut node, deadline);
        let status = node.status();
        println!(
            "PROC=p{seed} SYNC_DONE peers={} refusals={:?}",
            status.peers, node.refusals
        );
        return;
    }

    let remaining: Vec<Checkpoint> = chain
        .iter()
        .filter(|cp| cp.height.get() >= start_height)
        .copied()
        .collect();
    if remaining.is_empty() {
        println!("PROC=p{seed} NOTHING_TO_DECIDE");
        summarize(&node, seed);
        return;
    }
    let round_at = env_u64("BZ3_ROUND_AT_HEIGHT");
    for cp in &remaining {
        if round_at == Some(cp.height.get()) {
            force_round_change(&mut node, deadline);
        }
        // The engine requires the parent of a non-genesis checkpoint to be the one
        // already finalised: a height is never decided against an invented history.
        let parent = cp
            .height
            .get()
            .checked_sub(1)
            .and_then(|index| chain.get(index as usize));
        decide(&mut node, cp, parent, peers, deadline, round_after);
    }
    summarize(&node, seed);

    // A validator that decided does not vanish: staying up is what lets a restarted
    // peer fetch the history it missed.
    let linger = env_u64("BZ3_LINGER_MS").unwrap_or(0);
    if linger > 0 {
        let until = Instant::now() + Duration::from_millis(linger);
        while Instant::now() < until {
            service(&mut node, 4);
        }
    }
}

/// Move the node to the next round at a chosen height, **with a quorum**.
///
/// The call is the engine's: `propose_round_change` records the position, signs the
/// change carrying this node's lock, verifies every peer's change and adopts only at
/// the round-change quorum. The driver only decides *when* to ask.
fn force_round_change(node: &mut Node, deadline: Instant) {
    let before = node.status().round;
    let target = node.next_round();
    match node.propose_round_change(target) {
        Ok(outcome) => println!(
            "PROC={} ROUND_CHANGE_ASKED from={} target={} outcome={:?}",
            short(node),
            before.get(),
            target.get(),
            outcome
        ),
        Err(error) => println!("PROC={} ROUND_CHANGE_REFUSED {error}", short(node)),
    }
    let until = deadline.min(Instant::now() + Duration::from_secs(2));
    while Instant::now() < until && node.status().round == before {
        service(node, 3);
    }
    println!(
        "PROC={} ROUND_CHANGE_ADOPTED round={} (asked in round {})",
        short(node),
        node.status().round.get(),
        before.get()
    );
}

fn summarize(node: &Node, seed: u8) {
    let status = node.status();
    let finality = node
        .decisions()
        .last()
        .map(|decision| hex::encode(decision.checkpoint_id))
        .unwrap_or_else(|| "none".to_string());
    println!(
        "PROC=p{seed} DECIDED={} FINALITY={} HEIGHT={} ROUND={} PEERS={} REFUSALS={:?}",
        node.decisions().len(),
        finality,
        status.height.get(),
        status.round.get(),
        status.peers,
        node.refusals
    );
    println!(
        "PROC=p{seed} LOCKS lock={} halt={} links={} duplicates={}",
        status.lock.is_some(),
        status.halted,
        node.links(),
        node.duplicate_connections_closed()
    );
}

/// Mission BH's crash harness, reused: `BZ3_KILL_AFTER_MS` stops this process with
/// `abort()`, so no destructor runs and the Sled lock file is left behind exactly as
/// after a power cut. A driver-side `kill` would kill the shell wrapper, not the
/// validator, and would prove nothing about the store.
fn maybe_die() {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    if let Some(millis) = env_u64("BZ3_KILL_AFTER_MS").filter(|millis| *millis > 0) {
        if start.elapsed() >= Duration::from_millis(millis) {
            println!("PROC=abort KILL_AFTER_MS={millis} (no destructor, store left locked)");
            std::process::abort();
        }
    }
}

/// Poll, accept and finish handshakes without ever blocking for long.
fn service(node: &mut Node, ticks: usize) {
    maybe_die();
    for _ in 0..ticks {
        let _ = node.poll(Duration::from_millis(2));
    }
    let _ = node.accept_one(Duration::from_millis(2));
    node.finish_dials();
}

/// Bring up the mesh.
///
/// Every node dials every peer, which is exactly the crossed-dial case the dedup
/// rule settles: both sides keep the socket opened by the lower identity, so the
/// pair converges on one link without exchanging anything. A restarted validator
/// finds its peers again the same way.
fn connect(node: &mut Node, peers: &[SocketAddr], deadline: Instant) {
    if peers.is_empty() {
        return;
    }
    let mut attempts = 0;
    while Instant::now() < deadline && node.peers().len() < peers.len() && attempts < 200 {
        for address in peers {
            let _ = node.dial(*address);
        }
        let _ = node.accept_one(Duration::from_millis(20));
        node.finish_dials();
        attempts += 1;
        std::thread::sleep(Duration::from_millis(20));
    }
    let connected: BTreeSet<ValidatorId> = node.peers().into_iter().collect();
    println!(
        "PROC={} CONNECTED peers={} duplicates={}",
        hex::encode(&node.id().0[..4]),
        connected.len(),
        node.duplicate_connections_closed()
    );
}

fn sync(node: &mut Node, deadline: Instant) {
    let peers = node.peers();
    for peer in peers {
        let _ = node.request_history(peer, CheckpointHeight(0), 32);
    }
    let until = deadline.min(Instant::now() + Duration::from_secs(3));
    while Instant::now() < until {
        service(node, 5);
    }
}

/// Decide one checkpoint, entirely through the `Node` interface.
///
/// Four steps, each one a single call: propose, prevote, precommit, finalize. A
/// refused propose is normal — only the elected proposer may propose, and the
/// others still vote the value they were given. The stall timer is the only
/// policy here, and it asks the engine for a round change rather than forcing one.
fn decide(
    node: &mut Node,
    cp: &Checkpoint,
    parent: Option<&Checkpoint>,
    peers: &[SocketAddr],
    deadline: Instant,
    round_after: Option<Duration>,
) {
    let value = cp.id();
    let mut stage = 0u8;
    let mut proposed = false;
    let mut last_progress = Instant::now();
    let mut round_changes = 0u64;
    let mut last_dial = Instant::now() - Duration::from_secs(5);

    while Instant::now() < deadline {
        // A peer that restarted cannot be dialled by anyone who already gave up on
        // it: re-dialling when the mesh is short is what makes reconnection work.
        if !peers.is_empty()
            && node.peers().len() < peers.len()
            && last_dial.elapsed() > Duration::from_millis(500)
        {
            for address in peers {
                let _ = node.dial(*address);
            }
            last_dial = Instant::now();
        }
        service(node, 3);

        match stage {
            0 => {
                if !proposed {
                    // Failure means "not elected this round": not an error.
                    proposed = node.propose_value(value).is_ok();
                }
                match node.prevote_value(value) {
                    Ok(prevote) => {
                        let _ = node.broadcast(MessageKind::Prevote, prevote.vote().encode());
                        println!(
                            "PROC={} PREVOTE height={} round={} value={}",
                            short(node),
                            cp.height.get(),
                            node.status().round.get(),
                            &hex::encode(value)[..16]
                        );
                        stage = 1;
                    }
                    Err(error) => {
                        if std::env::var("BZ3_TRACE").is_ok() {
                            println!("PROC={} PREVOTE_WAIT {error}", short(node));
                        }
                    }
                }
            }
            1 => match node.certify_prevotes(value) {
                Ok(pol) => match node.precommit_value(&pol) {
                    Ok(precommit) => {
                        let _ = node.broadcast(MessageKind::Precommit, precommit.vote().encode());
                        println!(
                            "PROC={} PRECOMMIT height={} round={}",
                            short(node),
                            cp.height.get(),
                            node.status().round.get()
                        );
                        stage = 2;
                    }
                    Err(error) => println!("PROC={} PRECOMMIT_REFUSED {error}", short(node)),
                },
                Err(_) => {}
            },
            _ => match node.certify_precommits(value) {
                Ok(qc) => match node.finalize_height(&qc, cp, parent) {
                    Ok(decision) => {
                        println!(
                            "PROC={} DECIDED height={} id={}",
                            short(node),
                            decision.height.get(),
                            hex::encode(decision.checkpoint_id)
                        );
                        // What this validator decided is what it can serve: a
                        // restarting peer asks for it and installs it under the same
                        // verification the API uses.
                        if let Some(bundle) = node.build_history() {
                            let links = bundle.links.len();
                            node.serve_history(bundle);
                            println!(
                                "PROC={} SERVING height={} links={links}",
                                short(node),
                                cp.height.get()
                            );
                        }
                        let _ = node.advance_height(CheckpointHeight(cp.height.get() + 1));
                        return;
                    }
                    Err(error) => println!("PROC={} FINALIZE_REFUSED {error}", short(node)),
                },
                Err(_) => {}
            },
        }

        if let Some(after) = round_after {
            if last_progress.elapsed() > after {
                let target = node.next_round();
                match node.propose_round_change(target) {
                    Ok(outcome) => {
                        round_changes += 1;
                        println!(
                            "PROC={} ROUND_CHANGE target={} outcome={:?} changes={round_changes}",
                            short(node),
                            target.get(),
                            outcome
                        );
                        stage = 0;
                        proposed = false;
                        last_progress = Instant::now();
                    }
                    Err(error) => println!("PROC={} ROUND_CHANGE_REFUSED {error}", short(node)),
                }
            }
        }
    }
    println!(
        "PROC={} HEIGHT_INCOMPLETE height={} round={}",
        short(node),
        cp.height.get(),
        node.status().round.get()
    );
}

fn short(node: &Node) -> String {
    hex::encode(&node.id().0[..4])
}
