//! Mission BQ - two independent operating-system processes talking over TCP.
//!
//! This binary is the child process the BQ integration test spawns. It is **not**
//! a node: it exists so that "two processes" means what it says, with distinct
//! directories, distinct Ed25519 keys and a real loopback socket between them.
//!
//! ```text
//! bq_peer produce <store-dir>                    # decide + close, write bundle.bin
//! bq_peer serve   <store-dir> <addr> <stop-file> [relabel]
//! bq_peer fetch   <store-dir> <addr>
//! bq_peer resume  <store-dir>
//! ```
//!
//! `produce` runs a real election (four prevotes, four precommits), finalizes the
//! checkpoint that carries a transition, and installs the next generation with
//! the **canonical** identity (`AdmittedSet::registry_for`: the label is the
//! transition id the quorum signed). It then encodes the resulting `SyncBundle`
//! to `<store-dir>/bundle.bin`.
//!
//! `serve` offers that bundle over the existing `network::Node` TCP transport.
//! `relabel` rewrites the second generation's identifier in the served bundle -"
//! the BO-F1 attack -" without touching the certificate.
//!
//! `fetch` dials, asks for history, and lets the dispatcher verify and install
//! it. `resume` reopens the same sled directory in a new process and reports
//! whether the restored engine may sign, and with which registry.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    AdmittedSet, CandidateOperator, GenerationClosure, GenerationLedger, SetPolicy,
};
use aether_unified::l2bft::sync::{SyncAnchor, SyncBundle, SyncLink};
use aether_unified::l2bft::{restore_engine, BftState};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::state::PersistentConsensusState;
use aether_unified::l2persist::{AtomicSlotStore, CasStore, SledAtomicSlotStore, STATE_KEY};
use aether_unified::network::transport::FramedStream;
use aether_unified::network::{MessageKind, Node, PeerLimits, SyncRequest};

const NET: u64 = 41;
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

fn checkpoint() -> Checkpoint {
    let old = registry();
    let candidate = admitted().candidate_id(old.generation(), CheckpointHeight(0), old.set_root());
    Checkpoint::new(
        old.generation(),
        CheckpointHeight(0),
        [0u8; 32],
        [0x22; 32],
        [0x33; 32],
        old.set_root(),
        Some(candidate),
    )
    .expect("checkpoint")
}

fn limits() -> PeerLimits {
    // A perturbed link must be slower than the transport's default budget, so
    // the timeout is part of the experiment (BQ_READ_TIMEOUT_MS), never a retry
    // that hides a lost frame.
    let read_timeout = std::env::var("BQ_READ_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);
    PeerLimits {
        read_timeout: Duration::from_millis(read_timeout),
        write_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(5),
        max_messages_per_second: 500,
        ..PeerLimits::default()
    }
}

/// A real precommit certificate for `value`, from four live engines.
fn certify(
    engines: &mut [BftState],
    stores: &[aether_unified::l2persist::MemoryAtomicSlotStore],
    registry: &ValidatorRegistry,
    value: [u8; 32],
) -> aether_unified::l2bft::PrecommitCertificate {
    let mut prevotes: Vec<ConsensusVote> = Vec::new();
    for index in 0..SEEDS.len() {
        prevotes.push(
            engines[index]
                .prevote(
                    value,
                    vid(SEEDS[index]),
                    registry,
                    &stores[index],
                    sign_with(SEEDS[index]),
                )
                .expect("prevote")
                .vote()
                .clone(),
        );
    }
    for engine in engines.iter_mut() {
        for vote in &prevotes {
            engine.accept_vote(vote, registry);
        }
    }
    let pol = engines[0]
        .certify_prevotes_for(value, registry)
        .expect("prevote quorum");
    let mut precommits: Vec<ConsensusVote> = Vec::new();
    for index in 0..SEEDS.len() {
        precommits.push(
            engines[index]
                .precommit(
                    &pol,
                    vid(SEEDS[index]),
                    registry,
                    &stores[index],
                    sign_with(SEEDS[index]),
                )
                .expect("precommit")
                .vote()
                .clone(),
        );
    }
    for engine in engines.iter_mut() {
        for vote in &precommits {
            engine.accept_vote(vote, registry);
        }
    }
    engines[0]
        .certify_precommits_for(value, registry)
        .expect("precommit quorum")
}

fn open_store(dir: &Path) -> SledAtomicSlotStore {
    match SledAtomicSlotStore::open(dir) {
        Ok(store) => store,
        Err(error) => {
            println!("RESULT=locked");
            println!("ERROR={error}");
            exit(3);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: bq_peer <produce|serve|fetch|resume> <store-dir> [args]");
        exit(2);
    }
    let dir = Path::new(&args[1]).to_path_buf();
    match args[0].as_str() {
        "produce" => produce(&dir, true),
        "decide" => produce(&dir, false),
        "serve" => {
            let addr: SocketAddr = args[2].parse().expect("listen address");
            let stop = PathBuf::from(&args[3]);
            let relabel = args.get(4).map(|flag| flag == "relabel").unwrap_or(false);
            serve(&dir, addr, &stop, relabel);
        }
        "fetch" | "fetch-retry" => {
            let addr: SocketAddr = args[2].parse().expect("peer address");
            fetch(&dir, addr, args[0] == "fetch-retry");
        }
        "resume" => resume(&dir),
        other => {
            eprintln!("unknown command {other}");
            exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// produce
// ---------------------------------------------------------------------------

fn produce(dir: &Path, install: bool) {
    let store = open_store(dir);
    let old = registry();
    let init = PersistentConsensusState::fresh(NET, old.generation(), ANCHOR);
    let _ = store.cas(
        STATE_KEY,
        None,
        &aether_unified::l2persist::seal(&init.encode()),
    );
    store.flush().expect("flush");

    let mut engines: Vec<BftState> = SEEDS
        .iter()
        .map(|_| BftState::new(NET, &old, CheckpointHeight(0), ANCHOR))
        .collect();
    let memory: Vec<aether_unified::l2persist::MemoryAtomicSlotStore> = SEEDS
        .iter()
        .map(|_| aether_unified::l2persist::MemoryAtomicSlotStore::new())
        .collect();

    let cp = checkpoint();
    let certificate = certify(&mut engines, &memory, &old, cp.id());
    let decision = engines[0]
        .finalize(&certificate, &cp, None, &old, &store)
        .expect("finality");
    store.flush().expect("flush");

    if !install {
        // Decision only: the obligation is durable, the generation is not
        // installed, and the process exits here.
        println!("DECIDED={}", hex::encode(decision.checkpoint_id));
        println!("INSTALLED=0");
        return;
    }

    let set = admitted();
    let canonical = set
        .registry_for(&old, CheckpointHeight(0))
        .expect("canonical registry");
    let closure = GenerationClosure {
        height: CheckpointHeight(0),
        generation: old.generation(),
        value_id: cp.id(),
        candidate_id: decision
            .transition_id
            .expect("a transition checkpoint carries its id"),
        new_set_root: canonical.set_root(),
    };
    engines[0]
        .close_generation(closure, &canonical, &store)
        .expect("closure installs the canonical generation");
    engines[0]
        .advance_height(CheckpointHeight(1), &store)
        .expect("advance");
    store.flush().expect("flush");

    let bundle = SyncBundle {
        anchor: SyncAnchor {
            network: NET,
            height: cp.height,
            checkpoint_id: cp.id(),
            generation: cp.generation,
            set_root: cp.validator_set_root,
        },
        generations: vec![
            aether_unified::l2bft::sync::GenerationSpec {
                number: 0,
                registry: old.clone(),
                closure: None,
            },
            aether_unified::l2bft::sync::GenerationSpec {
                number: 1,
                registry: canonical.clone(),
                closure: Some(closure),
            },
        ],
        links: vec![SyncLink {
            checkpoint: cp,
            certificate,
        }],
    };
    let bytes = bundle.encode().expect("bundle encoding");
    std::fs::write(dir.join("bundle.bin"), &bytes).expect("bundle file");

    let ledger = GenerationLedger::load(&store)
        .expect("ledger")
        .expect("written");
    println!("GENERATION={}", hex::encode(engines[0].generation.0));
    println!("LEDGER_ACTIVE={}", hex::encode(ledger.active.0));
    println!("CANONICAL={}", hex::encode(canonical.generation().0));
    println!("BUNDLE_BYTES={}", bytes.len());
    println!("DECIDED={}", hex::encode(decision.checkpoint_id));
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn serve(dir: &Path, addr: SocketAddr, stop: &Path, relabel: bool) {
    let bytes = std::fs::read(dir.join("bundle.bin")).expect("bundle file");
    let mut bundle = SyncBundle::decode(&bytes).expect("bundle decoding");
    if relabel {
        // The BO-F1 attack: same members, same root, same certificate, a free
        // label. Nothing about the certificate changes.
        if let Some(spec) = bundle.generations.last_mut() {
            spec.registry = rebrand(&spec.registry, [0x42; 32]);
        }
    }
    let old = registry();
    let mut node = Node::bind_with_limits(
        addr,
        NET,
        sk(1),
        BftState::new(NET, &old, CheckpointHeight(0), ANCHOR),
        old,
        limits(),
    )
    .expect("bind");
    node.serve_history(bundle);

    // Publish the bound address so the parent does not have to guess a free
    // port (or race another test for one).
    let ready = PathBuf::from(format!("{}.ready", stop.display()));
    std::fs::write(&ready, format!("ADDR={}\n", node.addr())).expect("ready file");

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut served = 0u64;
    while Instant::now() < deadline && !stop.exists() {
        if let Ok(Some(_)) = node.accept_one(Duration::from_millis(20)) {
            continue;
        }
        match node.poll(Duration::from_millis(20)) {
            Ok(Some(_)) => served += 1,
            Ok(None) => {}
            Err(_) => {}
        }
    }
    println!("SERVED_MSG={served}");
    println!("SERVED_REQUESTS={}", node.sync_requests_served);
    println!("SERVED_BYTES={}", node.sync_bytes_served);
    println!("SERVED_REFUSED={}", node.sync_refused);
}

fn rebrand(registry: &ValidatorRegistry, label: [u8; 32]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = registry
        .entries()
        .iter()
        .map(|entry| RegistryEntry::new(entry.public_key, entry.weight, entry.admissibility))
        .collect();
    ValidatorRegistry::new(GenerationId(label), &entries).expect("rebranded registry")
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

/// Dial with a bounded retry: a listening socket whose backlog is momentarily
/// full costs an attempt, never the process.
fn connect(
    node: &mut Node,
    addr: SocketAddr,
) -> aether_unified::consensus::generation::ValidatorId {
    let mut last = None;
    for _ in 0..10 {
        match node.connect(addr) {
            Ok(id) => return id,
            Err(error) => {
                last = Some(error);
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    panic!("connect: {}", last.expect("an attempt"));
}

fn fetch(dir: &Path, addr: SocketAddr, retry: bool) {
    let store = open_store(dir);
    let old = registry();
    let init = PersistentConsensusState::fresh(NET, old.generation(), ANCHOR);
    let _ = store.cas(
        STATE_KEY,
        None,
        &aether_unified::l2persist::seal(&init.encode()),
    );
    store.flush().expect("flush");

    let mut node = Node::bind_with_limits(
        "127.0.0.1:0".parse().expect("addr"),
        NET,
        sk(2),
        BftState::new(NET, &old, CheckpointHeight(0), ANCHOR),
        old,
        limits(),
    )
    .expect("bind");
    node.attach_store(Box::new(store));

    // `fetch-retry` drops the first connection, lets the server notice the EOF,
    // then reconnects: a disconnect costs one attempt, not the process.
    let mut peer = connect(&mut node, addr);
    if retry {
        let _ = node.disconnect(&peer);
        // The server drops the stale stream when it reads the EOF; the retry
        // gives it that time instead of failing the process.
        let mut attempt = 0;
        loop {
            std::thread::sleep(Duration::from_millis(300));
            match node.connect(addr) {
                Ok(id) => {
                    peer = id;
                    break;
                }
                Err(error) if attempt < 5 => {
                    attempt += 1;
                    let _ = error;
                }
                Err(error) => panic!("reconnect: {error}"),
            }
        }
    }

    // A lossy link may swallow a request or its answer: re-ask, bounded. This is
    // the same `SyncRequest` message, not a new protocol.
    let mut rounds = 0;
    while node.installed_links == 0 && rounds < 4 {
        node.send_to(
            peer,
            MessageKind::SyncRequest,
            SyncRequest {
                network: NET,
                from_height: CheckpointHeight(0),
                max_links: 8,
            }
            .encode(),
        )
        .expect("request");
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && node.installed_links == 0 {
            match node.poll(Duration::from_millis(100)) {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(_) => break,
            }
        }
        rounds += 1;
    }
    println!("ACCEPTED={}", node.accepted);
    println!("INSTALLED_LINKS={}", node.installed_links);
    println!(
        "REFUSALS={}",
        node.refusals
            .iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    drop(node);

    let reopened = open_store(dir);
    match GenerationLedger::load(&reopened).expect("ledger") {
        Some(ledger) => {
            println!("LEDGER_ACTIVE={}", hex::encode(ledger.active.0));
            println!("LEDGER_NUMBER={}", ledger.active_number);
            println!("LEDGER_CLOSURES={}", ledger.closures.len());
            println!("LEDGER_FIRST_HEIGHT={}", ledger.first_height.get());
        }
        None => println!("LEDGER_ACTIVE=none"),
    }
    if let Ok(Some(bytes)) = reopened.get(&aether_unified::l2bft::pending_install_key(
        CheckpointHeight(0),
    )) {
        println!("PENDING_PRESENT={}", bytes.len());
    } else {
        println!("PENDING_PRESENT=none");
    }
}

// ---------------------------------------------------------------------------
// resume
// ---------------------------------------------------------------------------

fn resume(dir: &Path) {
    let store = open_store(dir);
    let old = registry();
    let canonical = admitted()
        .registry_for(&old, CheckpointHeight(0))
        .expect("canonical registry");
    let mut restored = restore_engine(&store, &canonical, Some(ANCHOR), NET, CheckpointHeight(1));
    println!("STATUS={:?}", restored.state.persisted().status);
    println!(
        "PENDING={}",
        u8::from(
            restored
                .state
                .pending_installs
                .contains_key(&CheckpointHeight(0))
        )
    );
    println!("GENERATION={}", hex::encode(restored.state.generation.0));
    println!("CANONICAL={}", hex::encode(canonical.generation().0));
    println!("MAY_SIGN={}", u8::from(restored.state.may_sign().is_ok()));
    println!("DECISIONS={}", restored.decisions.len());
    println!(
        "TIP={}",
        restored
            .decisions
            .last()
            .map(|decision| decision.height.get().to_string())
            .unwrap_or_else(|| "none".to_string())
    );

    // Signing at the restored height, with the generation in force.
    let value = [0x44u8; 32];
    match restored
        .state
        .prevote(value, vid(2), &canonical, &store, sign_with(2))
    {
        Ok(_) => println!("SIGN_TIP=ok"),
        Err(error) => println!("SIGN_TIP=refused:{}", one_line(&error.to_string())),
    }
    // The **superseded** registry cannot even restore this store: the ledger's
    // active generation is not the one that registry names.
    let stale = restore_engine(&store, &old, Some(ANCHOR), NET, CheckpointHeight(0));
    println!("STALE_STATUS={:?}", stale.state.persisted().status);
    println!(
        "STALE_MAY_SIGN={}",
        u8::from(stale.state.may_sign().is_ok())
    );
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
