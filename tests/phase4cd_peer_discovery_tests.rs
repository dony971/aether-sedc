//! PHASE 4CD: peer rediscovery after partition + frontier convergence.
//!
//! All loopback, no remote hosts, no public network. Ports 44781-44787 are
//! test-unique. The two tests in this file use DISTINCT ports and can run in
//! parallel threads.
//!
//! AUDIT OUTCOME (p2p.rs, verified live below — see §2 of the 4CD brief):
//! - PEX SEND side (`pex_sample`) does NOT filter loopback (R4: LAN relay).
//!   B therefore really announces C=127.0.0.1:port to A in every wave.
//! - PEX RECEIVE side (`P2PMessage::Peers` arm, `!is_private_or_reserved`)
//!   DROPS loopback hints before ingress (D6/R4 anti-LAN-steering). A never
//!   learns C from PEX on loopback — by design, not by defect.
//! - Failed dials to entry-less addresses create NOTHING (`record_failure`
//!   is a no-op without an entry); configured seeds are always retried via
//!   the `redial_candidates` seed tail; PEX-ingressed entries are retried
//!   with per-candidate backoff (1,2,4..60s) inside the 5s redial cycle.
//! - Inbound connections have NO private-address gate: C dialing A directly
//!   is the legitimate loopback discovery path (plus configured bootnodes).
//! - Address change is NOT supported: sessions, entries and scores are all
//!   keyed by SocketAddr with no migration path (new addr = new identity).
//!
//! Honesty boundaries: REAL P2P (keys, 20-bit PoW, Ed25519, validate_pure
//! Historical, validated DAG insert, Sled persist). C is never added to A's
//! bootnodes; no address is ever inserted into A's tables directly. Sets and
//! byte identities are asserted, never arrival order. Unfunded senders: DAG
//! admission proven, ledger transfers not.

use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::ledger::Ledger;
use aether_unified::p2p::{P2PConfig, P2PNetwork, P2PProtocolMode};
use aether_unified::parent_selection::DAG;
use aether_unified::stake::{current_epoch, StakeRegistry};
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const REDISCOVERY_TIMEOUT: Duration = Duration::from_secs(40);
/// PEX waves run every [15s,19s): 25s covers >= 1 wave with margin.
const PEX_WINDOW: Duration = Duration::from_secs(25);

async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(timeout, async {
        loop {
            if cond().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT waiting for: {}", what));
}

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn make_valid_tx(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    account_nonce: u64,
    timestamp: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        [0xAAu8; 32],
        1000,
        1,
        timestamp,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Historical)
        .expect("fresh tx must pass the pure gate");
    tx
}

fn record_tx(
    dag: &mut DAG,
    store: &Storage,
    processor: &TransactionProcessor,
    tx: &Transaction,
) -> Result<(), String> {
    processor
        .validate_pure(tx, ValidationMode::Historical)
        .map_err(|e| format!("pure gate: {:?}", e))?;
    dag.add_transaction_validated(tx.clone())
        .map_err(|e| format!("dag insert: {}", e))?;
    store
        .put_transaction(tx)
        .map_err(|e| format!("persist: {}", e))?;
    store
        .mark_applied(tx.id)
        .map_err(|e| format!("applied mark: {}", e))?;
    Ok(())
}

fn fingerprint(dag: &DAG, ledger: &Ledger) -> String {
    let mut ids: Vec<[u8; 32]> = dag.transactions().keys().copied().collect();
    ids.sort();
    let mut tips: Vec<[u8; 32]> = dag
        .transactions()
        .keys()
        .filter(|id| !dag.children().contains_key(*id))
        .copied()
        .collect();
    tips.sort();
    format!(
        "n={} tips={:?} supply={} balances={} nonces={}",
        ids.len(),
        tips,
        ledger.total_supply(),
        ledger.balances.len(),
        ledger.nonces.len()
    )
}

fn rebuild_ledger_like_boot(dag: &DAG) -> Ledger {
    let reg = StakeRegistry::new();
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag_v6(dag, &reg, current_epoch());
    ledger
}

fn block_on_sync<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("rt")
                .block_on(fut)
        })
        .join()
        .expect("join")
    })
}

struct TestNode {
    storage: Arc<RwLock<Storage>>,
    dag: Arc<RwLock<DAG>>,
    p2p: Arc<P2PNetwork>,
    rx: mpsc::UnboundedReceiver<Transaction>,
}

async fn boot_node(
    port: u16,
    bootnodes: Vec<std::net::SocketAddr>,
    dag: Arc<RwLock<DAG>>,
    storage: Arc<RwLock<Storage>>,
) -> TestNode {
    let (tx_sender, rx) = mpsc::unbounded_channel::<Transaction>();
    let dag_c = dag.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        block_on_sync(async {
            dag_c
                .read()
                .await
                .transactions()
                .keys()
                .map(|id| id.to_vec())
                .collect()
        })
    });
    let dag_c = dag.clone();
    let storage_c = storage.clone();
    let get_tx: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(move |hash| {
        block_on_sync(async {
            if let Ok(id) = <[u8; 32]>::try_from(hash) {
                if let Ok(g) = dag_c.try_read() {
                    if let Some(tx) = g.transactions().get(&id) {
                        return Some(tx.clone());
                    }
                }
                if let Ok(s) = storage_c.try_read() {
                    if let Ok(tx) = s.get_transaction(id) {
                        return Some(tx);
                    }
                }
            }
            None
        })
    });
    let dag_c = dag.clone();
    let get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        block_on_sync(async {
            let g = dag_c.read().await;
            g.transactions()
                .keys()
                .filter(|id| !g.children().contains_key(*id))
                .map(|id| id.to_vec())
                .collect()
        })
    });
    let p2p = Arc::new(P2PNetwork::new(
        P2PConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            bootnodes,
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: DEFAULT_NETWORK_ID,
        },
        tx_sender,
        get_hashes,
        get_tx,
        get_tips,
        Arc::new(aether_unified::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    // 4CP-W: the P2P protocol mode is an explicit prerequisite for start().
    p2p.set_protocol_mode(P2PProtocolMode::LegacyV5);
    tokio::time::timeout(REDISCOVERY_TIMEOUT, p2p.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds");
    TestNode {
        storage,
        dag,
        p2p,
        rx,
    }
}

async fn shutdown_node(node: TestNode, name: &str) {
    tokio::time::timeout(SHUTDOWN_TIMEOUT, node.p2p.shutdown())
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT: {} shutdown hung", name))
        .unwrap_or_else(|e| panic!("{} shutdown reported: {}", name, e));
    wait_for(
        &format!("{} peer_count==0", name),
        SHUTDOWN_TIMEOUT,
        || async { node.p2p.peer_count().await == 0 },
    )
    .await;
    node.storage.read().await.flush().expect("flush");
    drop(node);
}

async fn peers_of(node: &TestNode) -> HashSet<std::net::SocketAddr> {
    node.p2p.get_peers().await.into_iter().collect()
}

/// Collect rx until `want` ids are covered (dedup by id; sources and order
/// unspecified). Returns the covered transactions.
async fn collect_cover(
    rx: &mut mpsc::UnboundedReceiver<Transaction>,
    want: &HashSet<[u8; 32]>,
    what: &str,
) -> HashMap<[u8; 32], Transaction> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut got: HashMap<[u8; 32], Transaction> = HashMap::new();
    tokio::time::timeout(PROPAGATE_TIMEOUT, async {
        while !want.is_subset(&seen) {
            let r = rx.recv().await.expect("live");
            seen.insert(r.id);
            got.entry(r.id).or_insert(r);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT covering {} (want {:?})", what, want));
    got
}

async fn record_in_order(
    order: &[Transaction],
    got: &HashMap<[u8; 32], Transaction>,
    node: &TestNode,
    processor: &TransactionProcessor,
    what: &str,
) {
    for want in order {
        let tx = got.get(&want.id).expect("covered above");
        let mut done = false;
        for _ in 0..20 {
            let r = {
                let mut dag = node.dag.write().await;
                let store = node.storage.read().await;
                record_tx(&mut dag, &store, processor, tx)
            };
            if r.is_ok() {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(done, "{} records {:?}", what, tx.id);
    }
}

// ---- Test 1 (§3 + §5): PEX gate, inbound path, redial attribution ---------
//
// SESSION MODEL (observed live, by construction): sessions are keyed per
// SOCKET direction. The dialer keys the session by the peer's LISTEN address
// (the dial target); the accepter keys it by the peer's EPHEMERAL port (the
// accepted socket). Mutual dial therefore yields exactly 2 sessions per side
// — stable, since redial skips connected listen-addrs and dials to dead
// ephemerals fail fast with no session. Assertions below are written against
// this model: `contains(listen_addr)` + counts, never exact ephemeral sets.
//
// A bootnodes=[B], B bootnodes=[A]. C dials ONLY B: B's PEX waves to A
// necessarily carry C (send side unfiltered per R4, table of 2) yet A must
// NOT connect C within a full PEX window (receive-side D6 gate, proven by
// elimination). Then C dials A directly (A's config untouched) → connected
// (inbound has no private gate). Then B dies and restarts PASSIVE
// (bootnodes=[], fresh tables, dials nobody): A redials B from its
// dialer-side Outbound entry (attribution airtight — B cannot have dialed).
// Shutdown of all three stays clean after PEX exposure.

#[tokio::test]
async fn cd01_pex_gate_inbound_then_redial_reconnect() {
    const PA: u16 = 44781;
    const PB: u16 = 44782;
    const PC: u16 = 44783;
    let addr_a: std::net::SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let addr_b: std::net::SocketAddr = format!("127.0.0.1:{}", PB).parse().unwrap();
    let addr_c: std::net::SocketAddr = format!("127.0.0.1:{}", PC).parse().unwrap();
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let dir_c = tempfile::tempdir().expect("dirC");
    let path_b = dir_b.path().to_path_buf();

    // Mutual bootnodes: both dial at once. Per-direction sessions: exactly 2
    // per side (outbound keyed by listen-addr, inbound by ephemeral), stable
    // across redial cycles (no unbounded duplicate sessions).
    let node_a = boot_node(
        PA,
        vec![addr_b],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A"))),
    )
    .await;
    let node_b = boot_node(
        PB,
        vec![addr_a],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_b.path()).expect("open B"))),
    )
    .await;
    wait_for("A<->B peered", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_secs(6)).await; // racing dials + a redial cycle settle
    let pa = peers_of(&node_a).await;
    let pb = peers_of(&node_b).await;
    assert_eq!(
        pa.len(),
        2,
        "A holds exactly 2 A<->B direction sessions, got {:?}",
        pa
    );
    assert!(
        pa.contains(&addr_b),
        "A's outbound session is keyed by B's listen addr"
    );
    assert_eq!(
        pb.len(),
        2,
        "B holds exactly 2 A<->B direction sessions, got {:?}",
        pb
    );
    assert!(
        pb.contains(&addr_a),
        "B's outbound session is keyed by A's listen addr"
    );

    // C appears, dialing ONLY B. B accepts → B knows C → B's PEX waves to A
    // necessarily include C (send side unfiltered per R4, table of 2).
    let node_c = boot_node(
        PC,
        vec![addr_b],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_c.path()).expect("open C"))),
    )
    .await;
    wait_for("B<->C peered", CONNECT_TIMEOUT, || async {
        peers_of(&node_b).await.len() == 3
    })
    .await;
    // Session-model proof: B keys C's inbound session by C's EPHEMERAL port,
    // never by C's listen addr (which no peer was ever told).
    assert!(
        !peers_of(&node_b).await.contains(&addr_c),
        "inbound sessions are keyed by ephemeral port, not listen addr"
    );
    assert!(
        peers_of(&node_b).await.contains(&addr_a),
        "B still holds A while serving C"
    );

    // A never learns C from PEX: a full PEX window ([15s,19s) cadence, 25s
    // wait covers >= 1 wave) with zero new sessions on A. A's config is
    // unchanged (bootnodes=[B]); no direct insertion was performed.
    tokio::time::sleep(PEX_WINDOW).await;
    let pa2 = peers_of(&node_a).await;
    assert_eq!(
        pa2.len(),
        2,
        "A must NOT connect C via PEX on loopback (D6 receive gate), got {:?}",
        pa2
    );
    assert!(pa2.contains(&addr_b), "A still keyed on B's listen addr");
    // Repeated re-announces cause no duplicate sessions anywhere.
    assert_eq!(
        peers_of(&node_b).await.len(),
        3,
        "B holds exactly A(x2)+C, no dup sessions"
    );

    // Legitimate loopback path: C dials A directly (inbound has no private
    // gate). Shut C down first, restart it with bootnodes=[A] (A untouched).
    shutdown_node(node_c, "C-phase1").await;
    let store_c2 = Arc::new(RwLock::new(Storage::open(dir_c.path()).expect("reopen C")));
    let dag_c2 = Arc::new(RwLock::new(DAG::new()));
    let mut node_c2 = boot_node(PC, vec![addr_a], dag_c2.clone(), store_c2.clone()).await;
    wait_for("A<->C inbound connected", CONNECT_TIMEOUT, || async {
        peers_of(&node_a).await.len() == 3
    })
    .await;
    // A↔C over a fresh window: still exactly one A-side session for C (no
    // dup dials from redial vs PEX vs inbound racing; A never learns
    // C_listen so A never dials C).
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        peers_of(&node_a).await.len(),
        3,
        "no duplicate A-C sessions"
    );

    // B dies; B restarts PASSIVE (bootnodes=[], fresh tables, dials nobody,
    // same port+dir). A still holds B_listen as a dialer-side Outbound
    // entry → A's redial must reconnect B. B cannot have dialed: attribution
    // to A's redial path is airtight. (An inbound-only peer's listen addr is
    // never learned — that complementary gap is documented, not retested.)
    shutdown_node(node_b, "B-phase2").await;
    wait_for("A observes B gone", CONNECT_TIMEOUT, || async {
        peers_of(&node_a).await.len() == 1
    })
    .await;
    let store_b2 = Arc::new(RwLock::new(Storage::open(&path_b).expect("reopen B")));
    let dag_b2 = Arc::new(RwLock::new(DAG::new()));
    let node_b2 = boot_node(PB, vec![], dag_b2.clone(), store_b2.clone()).await;
    wait_for("A redials passive B", REDISCOVERY_TIMEOUT, || async {
        peers_of(&node_a).await.contains(&addr_b)
    })
    .await;
    // Passive B is peered, and A's session is keyed by B's LISTEN addr —
    // the dialer-side proof that A placed the call.
    wait_for("passive B sees A", CONNECT_TIMEOUT, || async {
        node_b2.p2p.peer_count().await >= 1
    })
    .await;

    // Honest sync still works across the rediscovered topology.
    let wallet = wallet_n(711001);
    let processor = TransactionProcessor::new();
    let tx = make_valid_tx(&wallet, [[0u8; 32], [0u8; 32]], 800, 1_780_000_000);
    {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        record_tx(&mut dag, &store, &processor, &tx).expect("A records");
    }
    node_a.p2p.broadcast_transaction(tx.clone()).await;
    let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_c2.rx.recv())
        .await
        .expect("C delivery after rediscovery")
        .expect("live");
    assert_eq!(tx.id, r.id, "gossip intact after PEX/redial churn");

    // Shutdown stays clean after full PEX exposure (§5 discovery×shutdown).
    shutdown_node(node_a, "A-cd01").await;
    shutdown_node(node_c2, "C-cd01").await;
    shutdown_node(node_b2, "B-cd01").await;
    // Drop outer handle clones (sled exclusive lock per live handle).
    drop(store_c2);
    drop(dag_c2);
    drop(store_b2);
    drop(dag_b2);
    for (d, name) in [
        (dir_a.path(), "A"),
        (dir_b.path(), "B"),
        (dir_c.path(), "C"),
    ] {
        let probe = Storage::open(d).unwrap_or_else(|_| panic!("{} dir reopens", name));
        drop(probe);
    }
}

// ---- Test 2 (§4): partition → heal with measured convergence --------------
//
// A↔B peered, C dials A. Converge n=1. Two cycles: kill B (prove staleness
// from its persisted bytes), create a NEW tx (existence window post-kill),
// heal B on the SAME dir+port, measure t_reconnect / t_data / t_converge
// from observable events. No averages: each cycle reported individually.

#[tokio::test]
async fn cd02_partition_heal_frontier_converges_measured() {
    const PA: u16 = 44785;
    const PB: u16 = 44786;
    const PC: u16 = 44787;
    let addr_a: std::net::SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let addr_b: std::net::SocketAddr = format!("127.0.0.1:{}", PB).parse().unwrap();
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let dir_c = tempfile::tempdir().expect("dirC");
    let path_b = dir_b.path().to_path_buf();
    let wallet = wallet_n(712001);
    let processor = TransactionProcessor::new();

    let rebuild_from = |path: &Path| -> DAG {
        let store = Storage::open(path).expect("reopen (leak if fails)");
        let mut txs = store.get_all_transactions().expect("read");
        for o in store.get_all_orphans().expect("orphans") {
            if !txs.iter().any(|t| t.id == o.id) {
                txs.push(o);
            }
        }
        drop(store);
        let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
        let (ins, sk, orph) =
            aether_unified::parent_selection::rebuild_dag_topological(&mut dag, txs);
        assert_eq!(sk, 0, "no silent skips");
        assert!(orph.is_empty(), "no orphans on healthy store");
        dag.rebuild_tips();
        dag
    };

    // Initial mesh + convergence n=1 (tx0 via A gossip).
    let mut prev = [0u8; 32];
    let tx0 = make_valid_tx(&wallet, [prev, [0u8; 32]], 900, 1_780_001_000);
    prev = tx0.id;
    let mut node_a = boot_node(
        PA,
        vec![addr_b],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A"))),
    )
    .await;
    let mut node_b = boot_node(
        PB,
        vec![addr_a],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_b.path()).expect("open B"))),
    )
    .await;
    let mut node_c = boot_node(
        PC,
        vec![addr_a],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_c.path()).expect("open C"))),
    )
    .await;
    wait_for("mesh peered", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 2 && node_b.p2p.peer_count().await >= 1
    })
    .await;
    {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        record_tx(&mut dag, &store, &processor, &tx0).expect("A records tx0");
    }
    node_a.p2p.broadcast_transaction(tx0.clone()).await;
    for (node, name) in [(&mut node_b, "B"), (&mut node_c, "C")] {
        let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node.rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{} gets tx0", name))
            .expect("live");
        assert_eq!(tx0.id, r.id);
        let mut dag = node.dag.write().await;
        let store = node.storage.read().await;
        record_tx(&mut dag, &store, &processor, &r)
            .unwrap_or_else(|e| panic!("{} records tx0: {}", name, e));
    }
    // Convergence n=1 on all three (ids + relations + frontier + ledger).
    {
        let fps: Vec<String> = {
            let mut v = Vec::new();
            for n in [&node_a, &node_b, &node_c] {
                let dag = n.dag.read().await;
                v.push(fingerprint(&dag, &rebuild_ledger_like_boot(&dag)));
            }
            v
        };
        assert_eq!(fps[0], fps[1]);
        assert_eq!(fps[1], fps[2], "initial convergence n=1");
        assert!(fps[0].starts_with("n=1 "), "got {}", fps[0]);
    }

    for cycle in 1..=2usize {
        let t_cycle = Instant::now();
        // PARTITION: clean-kill B, drop its handles, prove staleness from
        // the persisted bytes (B's dir holds exactly `cycle` txs).
        shutdown_node(node_b, &format!("B-partition{}", cycle)).await;
        let stale = Storage::open(&path_b).expect("B dir reopens while partitioned");
        assert_eq!(
            stale.get_all_transactions().expect("read").len(),
            cycle,
            "cycle {}: B stale at n={} during partition",
            cycle,
            cycle
        );
        drop(stale);
        // NEW data during partition (existence window): only A+C can hold it.
        let tx = make_valid_tx(
            &wallet,
            [prev, [0u8; 32]],
            900 + cycle as u64,
            1_780_002_000 + cycle as u64,
        );
        prev = tx.id;
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, &tx).expect("A records partition tx");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_c.rx.recv())
            .await
            .unwrap_or_else(|_| panic!("cycle {}: C gets partition tx", cycle))
            .expect("live");
        assert_eq!(tx.id, r.id);
        {
            let mut dag = node_c.dag.write().await;
            let store = node_c.storage.read().await;
            record_tx(&mut dag, &store, &processor, &r).expect("C records");
        }
        // HEAL: same dir + same port, DAG rebuilt from B's own bytes.
        let t_heal = Instant::now();
        let dag_b_built = rebuild_from(&path_b);
        assert_eq!(
            dag_b_built.transaction_count(),
            cycle,
            "B rebuilds stale state"
        );
        let store_b = Arc::new(RwLock::new(Storage::open(&path_b).expect("B heal open")));
        let dag_b = Arc::new(RwLock::new(dag_b_built));
        let mut healed_b = boot_node(PB, vec![addr_a], dag_b.clone(), store_b.clone()).await;
        wait_for(
            &format!("cycle {} reconnect", cycle),
            CONNECT_TIMEOUT,
            || async { healed_b.p2p.peer_count().await >= 1 },
        )
        .await;
        let t_reconnect = t_heal.elapsed();
        // Missing data reaches B (gossip rebroadcast + sync backfill race;
        // first delivery wins, dedup by id). Then B records in chain order.
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        let want: HashSet<[u8; 32]> = HashSet::from([tx.id]);
        let got = collect_cover(&mut healed_b.rx, &want, &format!("cycle {}", cycle)).await;
        let t_data = t_heal.elapsed() - t_reconnect;
        {
            let dag = healed_b.dag.read().await;
            assert!(
                !dag.transactions().contains_key(&tx.id),
                "cycle {}: heal tx genuinely missing pre-delivery",
                cycle
            );
        }
        record_in_order(
            std::slice::from_ref(&tx),
            &got,
            &healed_b,
            &processor,
            &format!("B-heal{}", cycle),
        )
        .await;
        // Convergence: full fingerprints (ids, relations, frontier, ledger).
        let t_conv_start = Instant::now();
        wait_for(
            &format!("cycle {} converge", cycle),
            CONNECT_TIMEOUT,
            || async {
                let (da, db, dc) = (
                    node_a.dag.read().await,
                    healed_b.dag.read().await,
                    node_c.dag.read().await,
                );
                let (fa, fb, fc) = (
                    fingerprint(&da, &rebuild_ledger_like_boot(&da)),
                    fingerprint(&db, &rebuild_ledger_like_boot(&db)),
                    fingerprint(&dc, &rebuild_ledger_like_boot(&dc)),
                );
                fa == fb && fb == fc && fa.starts_with(&format!("n={} ", cycle + 1))
            },
        )
        .await;
        let t_converge = t_conv_start.elapsed();
        // No duplicates on the healed node.
        assert_eq!(
            healed_b.dag.read().await.transaction_count(),
            cycle + 1,
            "cycle {}: healed B has exact history",
            cycle
        );
        println!(
            "CYCLE {}: partitioned_stale_n={} reconnect={:?} data_after_reconnect={:?} converge_after_data={:?} total={:?}",
            cycle,
            cycle,
            t_reconnect,
            t_data,
            t_converge,
            t_cycle.elapsed()
        );
        node_b = healed_b;
    }

    shutdown_node(node_a, "A-cd02").await;
    shutdown_node(node_b, "B-cd02").await;
    shutdown_node(node_c, "C-cd02").await;
    for (d, name) in [
        (dir_a.path(), "A"),
        (dir_b.path(), "B"),
        (dir_c.path(), "C"),
    ] {
        let probe = Storage::open(d).unwrap_or_else(|_| panic!("{} dir reopens", name));
        assert_eq!(
            probe.get_all_transactions().expect("read").len(),
            3,
            "{} holds full history",
            name
        );
        drop(probe);
    }
}
