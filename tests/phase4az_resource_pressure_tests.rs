//! PHASE 4AZ: resource limits, backpressure and overload resilience.
//!
//! Every node is a REAL in-process node: real TCP P2P (P2PNetwork), real
//! 20-bit PoW, real Ed25519 signatures, real Sled stores. The suite drives
//! the production receive path (gossip Transaction arm / sync arms) and the
//! production ingestion funnel mirror (pure gate + DAG admission + persist +
//! applied mark), and reads the REAL backpressure-adjacent counters that the
//! code exposes: the tx channel length (`UnboundedSender::len`), the sync
//! frontier snapshot (pending/inflight/total), the sync stats snapshot, the
//! live session table (`peer_count`), the authenticated session registry
//! (`session_auth_len`) and `propagation_inflight`.
//!
//! WHAT THE CODE BOUNDS (measured here, not assumed):
//! - At the time this suite was written, `tx_channel` (node.rs) and every
//!   session's outbound queue (p2p.rs) were UNBOUNDED mpsc channels. 4CP-BA
//!   has since bounded them (256 msgs / 32 MiB ingress; 64 msgs / 32 MiB per
//!   session). This suite stays below those capacities, so its backlog
//!   assertions (az01/az05) still measure the real queue length and prove
//!   exact drain (no silent loss).
//! - Session I/O is bounded in TIME, not by queue size: FRAME_TIMEOUT=30s,
//!   HANDSHAKE_TIMEOUT=10s, SESSION_WRITE_TIMEOUT=15s (p2p.rs:1718-1735).
//! - Per-session ingress is rate-limited at MAX_MSGS_PER_SEC=400 frames and
//!   MAX_MESSAGE_SIZE=16 MiB (p2p.rs:47/711); sessions beyond MAX_PEERS=128
//!   (MAX_PEERS_PER_SUBNET=4) are refused at accept (p2p.rs:96/99).
//! - Receipt dedup: seen_transactions/propagation_state are capped at
//!   MAX_SEEN_TXS=50k with TTL-based eviction (p2p.rs:289/2970). Duplicate
//!   receipts can still reach the CHANNEL (byte-cache only, plus a benign
//!   check-then-act window between concurrent arrivals); the no-double-apply
//!   guarantee is the funnel, which this suite verifies on every delivery.
//! - Sync progress structures are capped: frontier 100k entries / 64
//!   in-flight (sync_stats.rs:240-243), parent requests 4096
//!   (MAX_INFLIGHT_PARENTS), orphans 50k (rpc.rs:46), inventory≤1000,
//!   SyncResponse page≤100, closure≤1000, topo cache cap 50k.
//! - No "synced" flag exists: convergence is asserted as exact DAG identity
//!   and queue/frontier drain, never as a self-reported status.
//!
//! HONESTY BOUNDARIES (read before citing results):
//! - Recording mirrors the production acceptance funnel; mempool/RPC
//!   scaffolding is out of scope, senders are unfunded, and no ledger state
//!   is applied. "Applied" below means DAG admission (the only place a
//!   duplicate can be double-applied); duplicate refusal is the same
//!   `add_transaction_validated` the node uses.
//! - Exact RSS is not observable in this harness. We report structural
//!   measures (queue length, frontier counters, session counts, task
//!   registry teardown) and state that memory itself was not sampled.
//! - Volumes are deliberately moderate (tens of transactions) because
//!   mining is real 20-bit PoW. The unbounded channels ARE visible at this
//!   volume (backlog equals sent count); a sustained-overload OOM is NOT
//!   claimed to be reproduced.
//! - Ports 44821-44836 are test-unique; the five tests use disjoint ports and
//!   can run in parallel threads.

use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::p2p::{
    IngressTx, P2PConfig, P2PNetwork, P2PProtocolMode, TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::parent_selection::{rebuild_dag_topological, DAG};
use aether_unified::storage::Storage;
use aether_unified::sync_stats::SyncContext;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(25);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(25);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);
const CATCHUP_TIMEOUT: Duration = Duration::from_secs(90);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const START_TIMEOUT: Duration = Duration::from_secs(40);
/// Pre-activation timestamp base (Historical mode skips wall-clock bounds);
/// well below the 4CP migration boundary used by the suite history.
const TS0: u64 = 1_700_000_000_000;

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aether-4az-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

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
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT waiting for: {}", what));
}

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

/// Real creation path: key + 20-bit PoW (pre-activation policy) + signature.
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
        .expect("freshly mined+signed tx must pass the pure gate");
    tx
}

/// Chain of `depth` txs for one wallet, parents-first (nonces start at 1).
fn mine_chain(wallet: &Wallet, base_ts: u64, depth: usize) -> Vec<Transaction> {
    let mut prev = [0u8; 32];
    let mut out = Vec::with_capacity(depth);
    for i in 0..depth {
        let tx = make_valid_tx(
            wallet,
            [prev, [0u8; 32]],
            1 + i as u64,
            base_ts + i as u64 * 1000,
        );
        prev = tx.id;
        out.push(tx);
    }
    out
}

/// Synthetic invalid payloads: a real mined/signed tx with a corrupted
/// signature and a recomputed id. `validate_pure` rejects each one (asserted
/// by the caller), so they are definitionally invalid by Aether's own rules.
fn invalid_variants(base: &Transaction, n: usize) -> Vec<Transaction> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut v = base.clone();
        v.signature[0] = v.signature[0].wrapping_add(1 + i as u8);
        v.id = v.compute_hash();
        out.push(v);
    }
    out
}

/// Record path mirroring production acceptance (pure gate + DAG admission
/// + Sled persist + applied mark). No mempool/RPC scaffolding by design.
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

async fn record_now(
    dag: &Arc<RwLock<DAG>>,
    store: &Arc<RwLock<Storage>>,
    processor: &TransactionProcessor,
    tx: &Transaction,
) -> Result<(), String> {
    let mut d = dag.write().await;
    let s = store.read().await;
    record_tx(&mut d, &s, processor, tx)
}

fn seed_store(dir: &Path, txs: &[Transaction], processor: &TransactionProcessor) {
    let store = Storage::open(dir).expect("seed open");
    let mut dag = DAG::new();
    for tx in txs {
        record_tx(&mut dag, &store, processor, tx).expect("seed record");
    }
    store.flush().expect("seed flush");
}

/// Production boot rebuild: genesis seed + topological insert of the exact
/// persisted bytes (+ persisted orphans, kept for fidelity) + tips rebuild.
fn rebuild_dag_from_disk(path: &Path) -> (DAG, usize) {
    let store = Storage::open(path).expect("reopen store");
    let mut txs = store.get_all_transactions().expect("read txs");
    for o in store.get_all_orphans().expect("read orphans") {
        if !txs.iter().any(|t| t.id == o.id) {
            txs.push(o);
        }
    }
    drop(store);
    let n = txs.len();
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (_ins, sk, orph) = rebuild_dag_topological(&mut dag, txs);
    assert_eq!(sk, 0, "no silent skips on rebuild");
    assert!(orph.is_empty(), "no orphans on healthy store");
    dag.rebuild_tips();
    (dag, n)
}

/// Bridge sync closures to async state (production closures are sync).
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
    /// Consumer side; `None` once moved into a recorder task. Its `len()` is
    /// the REAL ingestion backlog (unbounded channel).
    rx: Option<mpsc::Receiver<IngressTx>>,
    /// The same SyncContext handed to P2P; exposes frontier/stats snapshots.
    sync: Arc<SyncContext>,
    /// Tx count rebuilt from this node's store at boot.
    rebuilt_n: usize,
}

async fn boot_node(dir: PathBuf, port: u16, bootnodes: Vec<SocketAddr>) -> TestNode {
    let (dag, rebuilt_n) = rebuild_dag_from_disk(&dir);
    let dag = Arc::new(RwLock::new(dag));
    let storage = Arc::new(RwLock::new(Storage::open(&dir).expect("open store")));
    let (tx_sender, rx) = mpsc::channel::<IngressTx>(TX_INGRESS_CAPACITY_MSGS);
    let sync = Arc::new(SyncContext::default());

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
        sync.clone(),
        Arc::new(|_| false),
    ));
    p2p.set_protocol_mode(P2PProtocolMode::LegacyV5);
    tokio::time::timeout(START_TIMEOUT, p2p.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds");
    TestNode {
        storage,
        dag,
        p2p,
        rx: Some(rx),
        sync,
        rebuilt_n,
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

fn probe_dir(path: &Path, expect_n: usize, name: &str) {
    let store = Storage::open(path).unwrap_or_else(|_| panic!("{} dir reopens", name));
    assert_eq!(
        store.get_all_transactions().expect("read").len(),
        expect_n,
        "{} persisted count after shutdown",
        name
    );
}

async fn dag_count(node: &TestNode) -> usize {
    node.dag.read().await.transaction_count()
}

async fn dag_contains(node: &TestNode, id: &[u8; 32]) -> bool {
    node.dag.read().await.transactions().contains_key(id)
}

/// One delivery through the real funnel, classified like the production
/// consumer: known id -> duplicate; ingest refusal -> rejected; else applied.
async fn record_classified(
    tx: Transaction,
    node: &TestNode,
    processor: &TransactionProcessor,
    counters: &mut Counters,
) {
    if dag_contains(node, &tx.id).await {
        counters.duplicate.fetch_add(1, Ordering::Relaxed);
        return;
    }
    match record_now(&node.dag, &node.storage, processor, &tx).await {
        Ok(()) => {
            counters.applied.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            counters.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn store_count(node: &TestNode) -> usize {
    node.storage
        .read()
        .await
        .get_all_transactions()
        .expect("read store")
        .len()
}

async fn peer_state(node: &TestNode) -> (usize, usize) {
    (
        node.p2p.peer_count().await,
        node.p2p.session_auth_len().await,
    )
}

#[derive(Default)]
struct Counters {
    applied: AtomicUsize,
    duplicate: AtomicUsize,
    rejected: AtomicUsize,
}

/// Continuous consumer that mirrors the production ingestion funnel. Every
/// delivery is classified: known id -> duplicate refusal; pure-invalid or
/// parent-missing -> rejected; otherwise applied.
fn spawn_recorder(
    mut rx: mpsc::Receiver<IngressTx>,
    dag: Arc<RwLock<DAG>>,
    storage: Arc<RwLock<Storage>>,
) -> (tokio::task::JoinHandle<()>, Arc<Counters>) {
    let stats = Arc::new(Counters::default());
    let stats_c = stats.clone();
    let handle = tokio::spawn(async move {
        let processor = TransactionProcessor::new();
        while let Some(item) = rx.recv().await {
            let tx = item.into_tx();
            let known = dag.read().await.transactions().contains_key(&tx.id);
            if known {
                stats_c.duplicate.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let r = record_now(&dag, &storage, &processor, &tx).await;
            if r.is_ok() {
                stats_c.applied.fetch_add(1, Ordering::Relaxed);
            } else {
                stats_c.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    (handle, stats)
}

async fn drain_n(
    rx: &mut mpsc::Receiver<IngressTx>,
    n: usize,
    timeout: Duration,
    what: &str,
) -> Vec<Transaction> {
    let mut out = Vec::with_capacity(n);
    tokio::time::timeout(timeout, async {
        while out.len() < n {
            out.push(rx.recv().await.expect("channel live").into_tx());
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT draining {} ({}/{})", what, out.len(), n));
    out
}

/// Collect until `want` is covered, re-issuing SyncRequest every `every`
/// while waiting (the production maintenance loop's mechanism, driven
/// explicitly so the test stays event-based).
async fn collect_cover_with_resync(
    rx: &mut mpsc::Receiver<IngressTx>,
    want: &HashSet<[u8; 32]>,
    p2p: &Arc<P2PNetwork>,
    every: Duration,
    timeout: Duration,
    what: &str,
) -> HashMap<[u8; 32], Transaction> {
    let mut got: HashMap<[u8; 32], Transaction> = HashMap::new();
    tokio::time::timeout(timeout, async {
        let mut tick = tokio::time::interval(every);
        loop {
            tokio::select! {
                r = rx.recv() => {
                    let tx = r.expect("channel live").into_tx();
                    got.entry(tx.id).or_insert(tx);
                    if want.is_subset(&got.keys().copied().collect()) {
                        return;
                    }
                }
                _ = tick.tick() => { p2p.request_full_sync().await; }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT covering {} ({}/{})", what, got.len(), want.len()));
    got
}

/// Record `order` entries that were collected, in dependency order. Entries
/// absent from `got` are skipped (they must arrive later); already-known
/// entries count as satisfied. Returns how many order entries are in the DAG.
async fn record_covered(
    order: &[Transaction],
    got: &HashMap<[u8; 32], Transaction>,
    dag: &Arc<RwLock<DAG>>,
    storage: &Arc<RwLock<Storage>>,
    processor: &TransactionProcessor,
    what: &str,
) -> usize {
    let mut recorded = 0usize;
    for want in order {
        if dag.read().await.transactions().contains_key(&want.id) {
            recorded += 1;
            continue;
        }
        let tx = match got.get(&want.id) {
            Some(t) => t,
            None => continue,
        };
        let mut done = false;
        for _ in 0..20 {
            if record_now(dag, storage, processor, tx).await.is_ok() {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(done, "{} records {:02x?}", what, &tx.id[..4]);
        recorded += 1;
    }
    recorded
}

/// Drain for a bounded window and enforce the no-double-apply contract:
/// every delivery must be an ALREADY-KNOWN id and its record attempt must be
/// rejected by the funnel. Any new id or successful insert is a hard failure.
async fn drain_verify_known_only(
    rx: &mut mpsc::Receiver<IngressTx>,
    dag: &Arc<RwLock<DAG>>,
    storage: &Arc<RwLock<Storage>>,
    processor: &TransactionProcessor,
    window: Duration,
    ctx: &str,
) -> usize {
    let deadline = Instant::now() + window;
    let mut extra = 0usize;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, rx.recv()).await {
            Err(_) => break,
            Ok(None) => panic!("{}: channel closed", ctx),
            Ok(Some(item)) => {
                let tx = item.into_tx();
                extra += 1;
                assert!(
                    dag.read().await.transactions().contains_key(&tx.id),
                    "{}: NEW id {:02x?} delivered after convergence",
                    ctx,
                    &tx.id[..4]
                );
                let r = record_now(dag, storage, processor, &tx).await;
                assert!(
                    r.is_err(),
                    "{}: duplicate {:02x?} was ACCEPTED by the funnel",
                    ctx,
                    &tx.id[..4]
                );
            }
        }
    }
    extra
}

fn chain_order(chains: &[Vec<Transaction>]) -> Vec<Transaction> {
    chains.iter().flatten().cloned().collect()
}

fn ids_of(txs: &[Transaction]) -> HashSet<[u8; 32]> {
    txs.iter().map(|t| t.id).collect()
}

// ===========================================================================
// az01 - burst of valid txs while the consumer is stalled.
//
// FAIL CRITERIA: any lost tx, any duplicate applied, any tx outside the sent
// universe delivered, producer side blocked (broadcast calls hang), queue not
// draining after the stall, or inbound dedup not suppressing a re-send of an
// already-received payload. Pass = backlog equals the exact sent set, then
// 60/60 applied and 0 extras.
// ===========================================================================
#[tokio::test]
async fn az01_burst_backlog_is_exact_and_recoverable() {
    let dir_c = unique_dir("az01-c");
    let dir_p1 = unique_dir("az01-p1");
    let dir_p2 = unique_dir("az01-p2");
    let dir_p3 = unique_dir("az01-p3");
    let (pc, pp1, pp2, pp3): (u16, u16, u16, u16) = (44821, 44822, 44823, 44824);

    // Mine BEFORE any session exists: mining is blocking CPU work and a live
    // session would be starved past its frame timeout while the only runtime
    // thread is busy.
    let chains: Vec<Vec<Transaction>> = std::thread::scope(|s| {
        let handles: Vec<_> = [910001u64, 910002, 910003]
            .into_iter()
            .enumerate()
            .map(|(i, w)| s.spawn(move || mine_chain(&wallet_n(w), TS0 + 100_000 * i as u64, 20)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mine"))
            .collect()
    });
    let all = chain_order(&chains);
    assert_eq!(all.len(), 60);
    let universe = ids_of(&all);

    let mut node_c = boot_node(dir_c.clone(), pc, vec![]).await;
    let node_p1 = boot_node(
        dir_p1.clone(),
        pp1,
        vec![format!("127.0.0.1:{}", pc).parse().unwrap()],
    )
    .await;
    let node_p2 = boot_node(
        dir_p2.clone(),
        pp2,
        vec![format!("127.0.0.1:{}", pc).parse().unwrap()],
    )
    .await;
    let node_p3 = boot_node(
        dir_p3.clone(),
        pp3,
        vec![format!("127.0.0.1:{}", pc).parse().unwrap()],
    )
    .await;
    wait_for("az01 C peers==3", CONNECT_TIMEOUT, || async {
        node_c.p2p.peer_count().await == 3
    })
    .await;
    for p in [&node_p1, &node_p2, &node_p3] {
        wait_for("az01 provider peer==1", CONNECT_TIMEOUT, || async {
            p.p2p.peer_count().await == 1
        })
        .await;
    }
    let (peers, auth) = peer_state(&node_c).await;
    assert_eq!((peers, auth), (3, 3), "three authenticated sessions");
    assert_eq!(node_c.rx.is_some(), true, "consumer not yet active");

    // Stall the consumer, then broadcast the full burst from three peers.
    let t_send = Instant::now();
    for tx in &chains[0] {
        node_p1.p2p.broadcast_transaction(tx.clone()).await;
    }
    for tx in &chains[1] {
        node_p2.p2p.broadcast_transaction(tx.clone()).await;
    }
    for tx in &chains[2] {
        node_p3.p2p.broadcast_transaction(tx.clone()).await;
    }
    let send_elapsed = t_send.elapsed();
    assert!(
        send_elapsed < Duration::from_secs(5),
        "producers must not be blocked by the stalled consumer (took {:?})",
        send_elapsed
    );

    // Backlog is observable and exact: the unbounded channel holds every tx.
    wait_for("az01 backlog==60", DELIVERY_TIMEOUT, || async {
        node_c.rx.as_ref().unwrap().len() >= 60
    })
    .await;
    let backlog = node_c.rx.as_ref().unwrap().len();
    assert_eq!(backlog, 60, "channel backlog must equal the sent universe");

    // Inbound dedup: re-broadcast 5 known payloads from a DIFFERENT peer.
    // They are byte-identical and already in C's seen cache, so the queue
    // must not move. (The cache's check-then-act window is exercised in
    // az02 with concurrent arrivals; here suppression must be exact.)
    for tx in chains[0].iter().take(5) {
        node_p2.p2p.broadcast_transaction(tx.clone()).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        node_c.rx.as_ref().unwrap().len(),
        60,
        "re-sent known payloads must be deduped before the channel"
    );
    for p in [&node_p1, &node_p2, &node_p3] {
        wait_for("az01 jitter tasks drained", SETTLE_TIMEOUT, || async {
            p.p2p.propagation_inflight() == 0
        })
        .await;
    }

    // Drain and apply through the real funnel. Exactly 60, no extras.
    let mut rx = node_c.rx.take().unwrap();
    let drained = drain_n(&mut rx, 60, SETTLE_TIMEOUT, "az01 burst").await;
    let got: HashMap<[u8; 32], Transaction> = drained.into_iter().map(|t| (t.id, t)).collect();
    assert_eq!(got.len(), 60, "each id delivered exactly once");
    assert_eq!(got.keys().copied().collect::<HashSet<_>>(), universe);
    let processor = TransactionProcessor::new();
    let recorded = record_covered(
        &all,
        &got,
        &node_c.dag,
        &node_c.storage,
        &processor,
        "az01 burst",
    )
    .await;
    assert_eq!(recorded, 60);
    assert_eq!(dag_count(&node_c).await, 60);
    assert_eq!(store_count(&node_c).await, 60);
    let extras = drain_verify_known_only(
        &mut rx,
        &node_c.dag,
        &node_c.storage,
        &processor,
        Duration::from_millis(700),
        "az01 settle",
    )
    .await;
    assert_eq!(extras, 0);
    assert_eq!(rx.len(), 0, "queue fully drained");

    println!(
        "AZ01: sent=60 send_elapsed={:?} backlog_while_stalled=60 applied=60 extras={} peers={} auth={}",
        send_elapsed, extras, peers, auth
    );

    shutdown_node(node_p1, "az01 p1").await;
    shutdown_node(node_p2, "az01 p2").await;
    shutdown_node(node_p3, "az01 p3").await;
    shutdown_node(node_c, "az01 c").await;
    probe_dir(&dir_c, 60, "az01 C");
    probe_dir(&dir_p1, 0, "az01 P1");
}

// ===========================================================================
// az02 - duplicates and invalid txs from several peers.
//
// FAIL CRITERIA: any invalid tx applied/persisted, any duplicate applied,
// any delivered id outside the known+invalid universe, channel/loss
// mismatch, or state change after the storm. Transports may deliver
// duplicates (byte-cache + concurrent-arrival window); APPLYING one is the
// only failure.
// ===========================================================================
#[tokio::test]
async fn az02_duplicate_invalid_storm_never_applies() {
    let dir_c = unique_dir("az02-c");
    let dir_p1 = unique_dir("az02-p1");
    let dir_p2 = unique_dir("az02-p2");
    let dir_p3 = unique_dir("az02-p3");
    let (pc, pp1, pp2, pp3): (u16, u16, u16, u16) = (44825, 44826, 44827, 44828);

    let processor = TransactionProcessor::new();
    let known: Vec<Transaction> = mine_chain(&wallet_n(920001), TS0 + 200_000, 15);
    let invalid_bases: Vec<Transaction> = mine_chain(&wallet_n(920002), TS0 + 210_000, 10);
    let invalid: Vec<Transaction> = invalid_bases
        .iter()
        .flat_map(|b| invalid_variants(b, 3))
        .collect();
    assert_eq!(invalid.len(), 30);
    for v in &invalid {
        assert!(
            processor
                .validate_pure(v, ValidationMode::Historical)
                .is_err(),
            "corrupted signature must fail the pure gate"
        );
    }
    seed_store(&dir_c, &known, &processor);
    // Providers own the same history BEFORE boot: their inventory diff with C
    // is empty (no sync delivery records `source`), so a later broadcast is a
    // genuine local relay to C -- which must dedup it at ingress and the
    // funnel must refuse to apply it.
    for d in [&dir_p1, &dir_p2, &dir_p3] {
        seed_store(d, &known, &processor);
    }

    let mut node_c = boot_node(dir_c.clone(), pc, vec![]).await;
    assert_eq!(node_c.rebuilt_n, 15, "C reboots with the known set");
    let node_p1 = boot_node(
        dir_p1.clone(),
        pp1,
        vec![format!("127.0.0.1:{}", pc).parse().unwrap()],
    )
    .await;
    let node_p2 = boot_node(
        dir_p2.clone(),
        pp2,
        vec![format!("127.0.0.1:{}", pc).parse().unwrap()],
    )
    .await;
    let node_p3 = boot_node(
        dir_p3.clone(),
        pp3,
        vec![format!("127.0.0.1:{}", pc).parse().unwrap()],
    )
    .await;
    wait_for("az02 C peers==3", CONNECT_TIMEOUT, || async {
        node_c.p2p.peer_count().await == 3
    })
    .await;

    let providers = [&node_p1, &node_p2, &node_p3];
    let known_set = ids_of(&known);
    let invalid_set = ids_of(&invalid);

    // Wire sends: 45 known copies (15 payloads x 3 peers) + 30 unique invalid.
    for p in providers {
        for tx in &known {
            p.p2p.broadcast_transaction(tx.clone()).await;
        }
    }
    for (i, p) in providers.iter().enumerate() {
        for tx in invalid.iter().skip(i).step_by(3) {
            p.p2p.broadcast_transaction(tx.clone()).await;
        }
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut rx = node_c.rx.take().unwrap();
    let mut delivered = Vec::new();
    while let Ok(item) = rx.try_recv() {
        delivered.push(item.into_tx());
    }
    let delivered_known = delivered
        .iter()
        .filter(|t| known_set.contains(&t.id))
        .count();
    let delivered_invalid = delivered
        .iter()
        .filter(|t| invalid_set.contains(&t.id))
        .count();
    let delivered_unknown = delivered.len() - delivered_known - delivered_invalid;
    assert_eq!(delivered_unknown, 0, "no id outside the storm universe");
    assert_eq!(
        delivered_invalid, 30,
        "every unique invalid payload is queued"
    );
    assert!(
        (15..=45).contains(&delivered_known),
        "known duplicates delivered after receipt dedup: {} (expected 15..=45)",
        delivered_known
    );

    // Apply attempts: every duplicate must be refused, every invalid rejected.
    let mut dup_rejected = 0usize;
    let mut invalid_rejected = 0usize;
    for tx in &delivered {
        let known_before = dag_contains(&node_c, &tx.id).await;
        assert_eq!(
            known_before,
            known_set.contains(&tx.id),
            "invalid ids must never enter the DAG"
        );
        let r = record_now(&node_c.dag, &node_c.storage, &processor, tx).await;
        assert!(
            r.is_err(),
            "storm delivery {:02x?} must be refused",
            &tx.id[..4]
        );
        if known_set.contains(&tx.id) {
            dup_rejected += 1;
        } else {
            invalid_rejected += 1;
        }
    }
    assert_eq!(invalid_rejected, 30);
    assert_eq!(dup_rejected, delivered_known);
    assert_eq!(dag_count(&node_c).await, 15, "no new tx applied");
    assert_eq!(store_count(&node_c).await, 15);
    for id in &invalid_set {
        assert!(!dag_contains(&node_c, id).await);
    }

    println!(
        "AZ02: wire_sends={} delivered={} (dup_known={} invalid=30) funnel_dup_rejected={} funnel_invalid_rejected={} applied_new=0 dag=15",
        45 + 30,
        delivered.len(),
        delivered_known,
        dup_rejected,
        invalid_rejected
    );

    shutdown_node(node_p1, "az02 p1").await;
    shutdown_node(node_p2, "az02 p2").await;
    shutdown_node(node_p3, "az02 p3").await;
    shutdown_node(node_c, "az02 c").await;
    probe_dir(&dir_c, 15, "az02 C");
}

// ===========================================================================
// az03 - slow consumer + stalled pre-handshake session vs a healthy peer.
//
// FAIL CRITERIA: the healthy peer's txs not applied within the explicit
// timeout, the stalled raw session not released after close, the slow
// consumer's backlog not draining to an exact 52-tx convergence, or any
// duplicate applied. Fairness is REPORTED (latencies), not inferred from a
// single sample; every healthy tx must simply make progress.
// ===========================================================================
#[tokio::test]
async fn az03_slow_consumer_isolation_and_stalled_session_release() {
    let dir_a = unique_dir("az03-a");
    let dir_b = unique_dir("az03-b");
    let dir_c = unique_dir("az03-c");
    let (pa, pb, pc): (u16, u16, u16) = (44829, 44830, 44831);

    let processor = TransactionProcessor::new();
    let history: Vec<Transaction> = mine_chain(&wallet_n(930001), TS0 + 300_000, 40);
    seed_store(&dir_a, &history, &processor);
    let mut node_a = boot_node(dir_a.clone(), pa, vec![]).await;
    let (rec_a, _counters_a) = {
        let rx = node_a.rx.take().unwrap();
        spawn_recorder(rx, node_a.dag.clone(), node_a.storage.clone())
    };
    assert_eq!(dag_count(&node_a).await, 40);

    let node_b = boot_node(
        dir_b.clone(),
        pb,
        vec![format!("127.0.0.1:{}", pa).parse().unwrap()],
    )
    .await;
    wait_for("az03 A-B peers", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await == 1
    })
    .await;

    let b1: Vec<Transaction> = mine_chain(&wallet_n(930002), TS0 + 310_000, 6);
    let b2: Vec<Transaction> = mine_chain(&wallet_n(930003), TS0 + 320_000, 6);
    for tx in &b1 {
        record_now(&node_b.dag, &node_b.storage, &processor, tx)
            .await
            .expect("B records b1");
    }
    for tx in &b2 {
        record_now(&node_b.dag, &node_b.storage, &processor, tx)
            .await
            .expect("B records b2");
    }

    // Baseline: B alone, A's consumer healthy.
    let mut latency_base = Vec::new();
    for tx in &b1 {
        let t = Instant::now();
        node_b.p2p.broadcast_transaction(tx.clone()).await;
        wait_for("az03 b1 applied", DELIVERY_TIMEOUT, || async {
            dag_contains(&node_a, &tx.id).await
        })
        .await;
        latency_base.push(t.elapsed());
    }

    // C joins and its consumer is STALLED (rx not drained) -> backlog grows.
    let mut node_c = boot_node(
        dir_c.clone(),
        pc,
        vec![format!("127.0.0.1:{}", pa).parse().unwrap()],
    )
    .await;
    wait_for("az03 C backlog>=30", CATCHUP_TIMEOUT, || async {
        node_c.p2p.peer_count().await == 1 && node_c.rx.as_ref().unwrap().len() >= 30
    })
    .await;
    let c_backlog = node_c.rx.as_ref().unwrap().len();

    // A stalled pre-handshake socket: registered in the peer table, never
    // authenticated, never consumes a protocol message.
    let stall = TcpStream::connect(format!("127.0.0.1:{}", pa))
        .await
        .expect("raw connect");
    wait_for(
        "az03 stalled session registered",
        SETTLE_TIMEOUT,
        || async { node_a.p2p.peer_count().await == 3 },
    )
    .await;
    let (peers_stalled, auth_stalled) = peer_state(&node_a).await;
    assert_eq!(peers_stalled, 3, "B + C + stalled raw session");
    assert_eq!(auth_stalled, 2, "only B and C completed a handshake");

    // Healthy peer under the slow consumer + stalled session.
    let mut latency_pressure = Vec::new();
    for tx in &b2 {
        let t = Instant::now();
        node_b.p2p.broadcast_transaction(tx.clone()).await;
        wait_for(
            "az03 b2 applied under pressure",
            DELIVERY_TIMEOUT,
            || async { dag_contains(&node_a, &tx.id).await },
        )
        .await;
        latency_pressure.push(t.elapsed());
    }
    assert_eq!(dag_count(&node_a).await, 52, "A applied 40 + 12");

    // Reaping: closing the stalled socket releases its session entry.
    drop(stall);
    wait_for("az03 stalled session released", SETTLE_TIMEOUT, || async {
        node_a.p2p.peer_count().await == 2
    })
    .await;
    let (peers_after, auth_after) = peer_state(&node_a).await;
    assert_eq!((peers_after, auth_after), (2, 2));

    // Slow consumer catches up to the exact 52-tx state.
    let mut all_order = history.clone();
    all_order.extend(b1.clone());
    all_order.extend(b2.clone());
    let want = ids_of(&all_order);
    let mut rx_c = node_c.rx.take().unwrap();
    let got = collect_cover_with_resync(
        &mut rx_c,
        &want,
        &node_c.p2p,
        Duration::from_secs(2),
        CATCHUP_TIMEOUT,
        "az03 C catch-up",
    )
    .await;
    let recorded = record_covered(
        &all_order,
        &got,
        &node_c.dag,
        &node_c.storage,
        &processor,
        "az03 C catch-up",
    )
    .await;
    assert_eq!(recorded, 52);
    assert_eq!(dag_count(&node_c).await, 52);
    assert_eq!(store_count(&node_c).await, 52);
    let extras = drain_verify_known_only(
        &mut rx_c,
        &node_c.dag,
        &node_c.storage,
        &processor,
        Duration::from_millis(700),
        "az03 C settle",
    )
    .await;
    assert_eq!(extras, 0);
    assert_eq!(rx_c.len(), 0, "C backlog fully drained");

    let med = |v: &Vec<Duration>| {
        let mut s = v.clone();
        s.sort();
        s[s.len() / 2]
    };
    println!(
        "AZ03: c_backlog_while_stalled={} peers(stalled)={} auth(stalled)={} peers_after={} base_median={:?} base_max={:?} pressure_median={:?} pressure_max={:?} applied_A=52 C=52 extras={}",
        c_backlog,
        peers_stalled,
        auth_stalled,
        peers_after,
        med(&latency_base),
        latency_base.iter().max().unwrap(),
        med(&latency_pressure),
        latency_pressure.iter().max().unwrap(),
        extras
    );

    shutdown_node(node_b, "az03 b").await;
    shutdown_node(node_c, "az03 c").await;
    shutdown_node(node_a, "az03 a").await;
    rec_a.abort();
    tokio::task::yield_now().await;
    probe_dir(&dir_a, 52, "az03 A");
    probe_dir(&dir_c, 52, "az03 C");
}

// ===========================================================================
// az04 - connection churn and stale-session ownership.
//
// FAIL CRITERIA: the peer table/session registry not returning to the live
// set after churn, a stale pre-handshake connection blocking or evicting the
// healthy session, or a new real session failing to exchange a tx. Pass =
// baseline restored and both B and D progress.
// ===========================================================================
#[tokio::test]
async fn az04_reconnect_churn_releases_session_resources() {
    let dir_a = unique_dir("az04-a");
    let dir_b = unique_dir("az04-b");
    let dir_d = unique_dir("az04-d");
    let (pa, pb, pd): (u16, u16, u16) = (44832, 44833, 44834);
    let processor = TransactionProcessor::new();

    let mut node_a = boot_node(dir_a.clone(), pa, vec![]).await;
    let (rec_a, _counters_a) = {
        let rx = node_a.rx.take().unwrap();
        spawn_recorder(rx, node_a.dag.clone(), node_a.storage.clone())
    };
    let node_b = boot_node(
        dir_b.clone(),
        pb,
        vec![format!("127.0.0.1:{}", pa).parse().unwrap()],
    )
    .await;
    wait_for("az04 A-B peers", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await == 1 && node_b.p2p.peer_count().await == 1
    })
    .await;
    assert_eq!(peer_state(&node_a).await, (1, 1));

    // 20 pre-handshake connect/close cycles.
    for _ in 0..20 {
        let s = TcpStream::connect(format!("127.0.0.1:{}", pa))
            .await
            .expect("churn connect");
        drop(s);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    wait_for(
        "az04 baseline restored after churn",
        SETTLE_TIMEOUT,
        || async { peer_state(&node_a).await == (1, 1) },
    )
    .await;

    // The healthy session still works after churn.
    let tx_b = mine_chain(&wallet_n(940001), TS0 + 400_000, 1).remove(0);
    record_now(&node_b.dag, &node_b.storage, &processor, &tx_b)
        .await
        .expect("B records");
    node_b.p2p.broadcast_transaction(tx_b.clone()).await;
    wait_for("az04 B tx after churn", DELIVERY_TIMEOUT, || async {
        dag_contains(&node_a, &tx_b.id).await
    })
    .await;

    // A fresh real session (D) is accepted and both newcomers progress.
    let node_d = boot_node(
        dir_d.clone(),
        pd,
        vec![format!("127.0.0.1:{}", pa).parse().unwrap()],
    )
    .await;
    wait_for("az04 D session", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await == 2
            && node_a.p2p.session_auth_len().await == 2
            && node_d.p2p.peer_count().await == 1
    })
    .await;
    let tx_d = mine_chain(&wallet_n(940002), TS0 + 410_000, 1).remove(0);
    record_now(&node_d.dag, &node_d.storage, &processor, &tx_d)
        .await
        .expect("D records");
    node_d.p2p.broadcast_transaction(tx_d.clone()).await;
    wait_for("az04 D tx applied", DELIVERY_TIMEOUT, || async {
        dag_contains(&node_a, &tx_d.id).await
    })
    .await;
    assert_eq!(dag_count(&node_a).await, 2);
    let peers_now = node_a.p2p.get_peers().await;
    assert_eq!(peers_now.len(), 2, "no stale raw endpoint survives");

    println!(
        "AZ04: churn_cycles=20 peers_after_churn=(1,1) peers_final={} auth_final={} tx_after_churn=applied tx_new_session=applied",
        node_a.p2p.peer_count().await,
        node_a.p2p.session_auth_len().await
    );

    shutdown_node(node_d, "az04 d").await;
    shutdown_node(node_b, "az04 b").await;
    shutdown_node(node_a, "az04 a").await;
    rec_a.abort();
    tokio::task::yield_now().await;
    probe_dir(&dir_a, 2, "az04 A");
}

// ===========================================================================
// az05 - tip-first delivery (waiting -> drop -> re-request) under a request
// storm, then quiescence.
//
// FAIL CRITERIA: convergence not reached, frontier pending/inflight left
// non-zero after settle, channel backlog not returning to zero, a repeated
// request applying anything twice, or any NEW id after convergence. The
// waiting-drop path is exercised by construction: the handshake's
// GetInventory answer serves the TIP directly, BEFORE its ancestors, so the
// receiver's dependency fixpoint drops it and the next inventory round
// re-requests the closed set.
// ===========================================================================
#[tokio::test]
async fn az05_waiting_retry_loop_is_bounded_and_converges() {
    let dir_a = unique_dir("az05-a");
    let dir_b = unique_dir("az05-b");
    let (pa, pb): (u16, u16) = (44835, 44836);
    let processor = TransactionProcessor::new();

    let chain: Vec<Transaction> = mine_chain(&wallet_n(950001), TS0 + 500_000, 40);
    seed_store(&dir_a, &chain, &processor);
    let node_a = boot_node(dir_a.clone(), pa, vec![]).await;

    let mut node_b = boot_node(
        dir_b.clone(),
        pb,
        vec![format!("127.0.0.1:{}", pa).parse().unwrap()],
    )
    .await;
    let mut rx_b = node_b.rx.take().unwrap();
    let mut counters = Counters::default();
    wait_for("az05 B peer", CONNECT_TIMEOUT, || async {
        node_b.p2p.peer_count().await == 1
    })
    .await;

    // Request storm while the catch-up is in flight.
    for _ in 0..60 {
        node_b.p2p.request_full_sync().await;
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let t_start = Instant::now();
    let mut peak_backlog = 0usize;
    let converged = tokio::time::timeout(CATCHUP_TIMEOUT, async {
        loop {
            peak_backlog = peak_backlog.max(rx_b.len());
            while let Ok(item) = rx_b.try_recv() {
                record_classified(item.into_tx(), &node_b, &processor, &mut counters).await;
            }
            if dag_count(&node_b).await == 40 {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(20), rx_b.recv()).await {
                Ok(Some(item)) => {
                    peak_backlog = peak_backlog.max(rx_b.len() + 1);
                    record_classified(item.into_tx(), &node_b, &processor, &mut counters).await;
                }
                Ok(None) => panic!("AZ05: tx channel closed unexpectedly"),
                Err(_) => {}
            }
        }
    })
    .await;
    assert!(converged.is_ok(), "TIMEOUT: B did not converge");
    let t_converge = t_start.elapsed();
    tokio::time::sleep(Duration::from_millis(500)).await;
    peak_backlog = peak_backlog.max(rx_b.len());
    while let Ok(item) = rx_b.try_recv() {
        record_classified(item.into_tx(), &node_b, &processor, &mut counters).await;
    }
    assert_eq!(rx_b.len(), 0, "channel quiescent after settle");
    assert_eq!(dag_count(&node_b).await, 40);
    assert_eq!(store_count(&node_b).await, 40);
    assert_eq!(counters.applied.load(Ordering::Relaxed), 40);
    assert_eq!(
        counters.rejected.load(Ordering::Relaxed),
        0,
        "no valid delivery may be rejected"
    );

    let snap = node_b.sync.stats.snapshot();
    let frontier = node_b.sync.frontier.read().await.snapshot();
    assert_eq!(frontier.pending, 0, "no request left pending after settle");
    assert_eq!(
        frontier.inflight, 0,
        "no request left in flight after settle"
    );
    assert_eq!(
        frontier.total_tracked, 40,
        "frontier tracked exactly the history"
    );
    assert_eq!(frontier.applied, 40);
    assert!(frontier.total_tracked <= 100_000, "frontier cap respected");

    // Repeated full-sync requests on a converged node must be silent: the
    // sync arm dedups against the DAG before queueing, the recorder stays at
    // 40 applied, and the channel drains to zero.
    for _ in 0..5 {
        node_b.p2p.request_full_sync().await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(rx_b.len(), 0, "no tx after convergence");
    assert_eq!(dag_count(&node_b).await, 40);
    assert_eq!(counters.applied.load(Ordering::Relaxed), 40);
    let extras = 0usize;

    println!(
        "AZ05: converged_40 in {:?} peak_channel_backlog={} sync_batches={} response_items={} duplicate_ignored={} frontier(pending={}, inflight={}, tracked={}, applied={}) repeats_extras={}",
        t_converge,
        peak_backlog,
        snap.sync_batches,
        snap.sync_response_items,
        snap.duplicate_ignored,
        frontier.pending,
        frontier.inflight,
        frontier.total_tracked,
        frontier.applied,
        extras
    );

    shutdown_node(node_b, "az05 b").await;
    shutdown_node(node_a, "az05 a").await;
    probe_dir(&dir_b, 40, "az05 B");
    probe_dir(&dir_a, 40, "az05 A");
}
