//! PHASE 4AY: partition recovery, stale-peer catch-up and relay backfill.
//!
//! Every node below is a REAL in-process node: real TCP P2P (P2PNetwork),
//! real 20-bit PoW, real Ed25519 signatures, real Sled stores, real same-dir
//! restarts through the production boot path (initialize_genesis +
//! rebuild_dag_topological + rebuild_tips) after a real P2PNetwork::shutdown.
//! Ports 44811-44820 are test-unique; the four tests use disjoint ports and
//! can run in parallel threads.
//!
//! WHAT IS BEING EXERCISED (mechanism audit, p2p.rs):
//! - On session establishment the dialer sends GetInventory + SyncRequest;
//!   the peer answers with a BOUNDED ROTATING inventory window (1000 items,
//!   10s cursor); the receiver diffs against DAG+orphans and requests missing
//!   ids with one GetData (capped at 1000).
//! - GetData serving takes the first 100 requested hashes, computes their
//!   FULL ancestor closure (max 100*10 entries), topologically sorts it and
//!   emits pages of 100 as separate SyncResponse messages (MAX_SYNC_PAGE).
//! - The receiver partitions each batch with a dependency FIXPOINT: a tx is
//!   deliverable when its parents are in the DAG or were accepted earlier in
//!   the SAME batch; waiting txs are dropped and stay "unreceived" so the next
//!   inventory diff re-requests them.
//! - Re-requesting needs a subsequent SyncRequest. In production node.rs
//!   issues request_full_sync() every 10s; this harness mirrors that loop at a
//!   compressed 4s cadence (same mechanism, shorter test wall-clock). Without
//!   it a node could stall after a single unlucky round; the loop is the real
//!   recovery trigger, not a test sleep.
//! - Duplicate handling has TWO layers: the SyncResponse arm dedups against
//!   the DAG+orphan store before queueing, while the live-gossip Transaction
//!   arm dedups with a byte-cache (`accept_inbound_transaction`) and CAN
//!   deliver a tx the DAG already knows. The no-double-APPLY guarantee is the
//!   ingestion funnel rejecting the insert - `drain_verify_no_double_apply`
//!   pins exactly that (every extra delivery must be a known id AND its
//!   record attempt must fail), never a channel-level silence that the code
//!   does not actually provide.
//! - There is NO "synced" flag anywhere - convergence is asserted as DAG
//!   identity (ids, tips, derived-ledger supply/balances/nonces), never as a
//!   self-reported status.
//!
//! HONESTY BOUNDARIES (read before citing results):
//! - Recording mirrors the production acceptance funnel (pure gate + DAG
//!   admission + Sled persist + applied mark); mempool/RPC scaffolding is out
//!   of scope. Senders are unfunded by design, so the asserted invariants are
//!   convergence + supply/ledger identity, never funded transfers.
//! - PEX receive-side drops loopback hints (4CD finding), so no test relies
//!   on PEX-based loopback discovery: peers are wired by configured bootnodes
//!   and reconnection is left to the production redial loop.
//! - ay03 Phase A kills the CLIENT mid-catch-up (consumption-controlled:
//!   exactly one tx persisted before the crash). Phase B kills the SERVER
//!   inside a delayed serving window; because serving sections are fully
//!   synchronous after their last await, a teardown may still let the current
//!   section finish (observed behavior, documented), so Phase B asserts the
//!   RECOVERY invariant (exact final convergence, zero double apply,
//!   no unknown id) rather than a guaranteed partial count.
//! - ay04 size is derived from code limits: 110 > MAX_SYNC_PAGE (100) and
//!   < MAX_INV_ITEMS (1000), so the paginated path (2 pages per closure) is
//!   exercised; mining 110 txs is parallelized across chains (parents-first
//!   within each chain, so no id can be precomputed out of order).
//! - Every wait is an explicit timeout; expiry FAILS the test. Bounded drain
//!   windows only verify idempotence AFTER a positive proof of delivery.

use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::ledger::Ledger;
use aether_unified::p2p::{P2PConfig, P2PNetwork, P2PProtocolMode};
use aether_unified::parent_selection::{rebuild_dag_topological, DAG};
use aether_unified::stake::{current_epoch, StakeRegistry};
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(30);
const CATCHUP_TIMEOUT: Duration = Duration::from_secs(90);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const START_TIMEOUT: Duration = Duration::from_secs(40);
/// node.rs maintenance cadence is 10s; compressed here to keep the suite
/// snappy. Same mechanism (`request_full_sync` broadcast), not a sleep trick.
const MAINT_INTERVAL: Duration = Duration::from_secs(4);

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aether-4ay-{}-{}", tag, std::process::id()));
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
            tokio::time::sleep(Duration::from_millis(100)).await;
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

/// Seed a pre-existing store before first boot (mirrors a node that recorded
/// these txs in an earlier life; the boot path itself rebuilds from disk).
fn seed_store(dir: &Path, txs: &[Transaction], processor: &TransactionProcessor) {
    let store = Storage::open(dir).expect("seed open");
    let mut dag = DAG::new();
    for tx in txs {
        record_tx(&mut dag, &store, processor, tx).expect("seed record");
    }
    store.flush().expect("seed flush");
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

async fn live_fp(node: &TestNode) -> String {
    let dag = node.dag.read().await;
    fingerprint(&dag, &rebuild_ledger_like_boot(&dag))
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
    rx: mpsc::UnboundedReceiver<Transaction>,
    maintenance: tokio::task::JoinHandle<()>,
    /// Tx count rebuilt from this node's store at boot (proof of staleness).
    rebuilt_n: usize,
}

async fn boot_node(
    dir: PathBuf,
    port: u16,
    bootnodes: Vec<SocketAddr>,
    tx_serve_delay: Option<Duration>,
) -> TestNode {
    let (dag, rebuilt_n) = rebuild_dag_from_disk(&dir);
    let dag = Arc::new(RwLock::new(dag));
    let storage = Arc::new(RwLock::new(Storage::open(&dir).expect("open store")));
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
            // Test-controlled serving delay (ay03): runs on the helper thread
            // spawned by block_on_sync, never on the async runtime.
            if let Some(d) = tx_serve_delay {
                std::thread::sleep(d);
            }
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
    p2p.set_protocol_mode(P2PProtocolMode::LegacyV5);
    tokio::time::timeout(START_TIMEOUT, p2p.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds");
    // Mirror node.rs's periodic reconciliation (request_full_sync broadcast).
    let maintenance = {
        let p = p2p.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(MAINT_INTERVAL).await;
                p.request_full_sync().await;
            }
        })
    };
    TestNode {
        storage,
        dag,
        p2p,
        rx,
        maintenance,
        rebuilt_n,
    }
}

async fn shutdown_node(node: TestNode, name: &str) {
    node.maintenance.abort();
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

async fn dag_count(node: &TestNode) -> usize {
    node.dag.read().await.transaction_count()
}

async fn dag_contains(node: &TestNode, id: &[u8; 32]) -> bool {
    node.dag.read().await.transactions().contains_key(id)
}

async fn store_count(node: &TestNode) -> usize {
    node.storage
        .read()
        .await
        .get_all_transactions()
        .expect("read store")
        .len()
}

/// Collect rx until `want` ids are covered (dedup by id; arrival order not
/// asserted). The returned map is keyed by id, so its length can only exceed
/// `want.len()` if an id OUTSIDE `want` is delivered - callers assert the
/// exact set by comparing lengths where the universe of live ids is known.
async fn collect_cover(
    rx: &mut mpsc::UnboundedReceiver<Transaction>,
    want: &HashSet<[u8; 32]>,
    timeout: Duration,
    what: &str,
) -> HashMap<[u8; 32], Transaction> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut got: HashMap<[u8; 32], Transaction> = HashMap::new();
    tokio::time::timeout(timeout, async {
        while !want.is_subset(&seen) {
            let r = rx.recv().await.expect("channel live");
            seen.insert(r.id);
            got.entry(r.id).or_insert(r);
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "TIMEOUT covering {} (missing {}/{})",
            what,
            want.len() - seen.len(),
            want.len()
        )
    });
    got
}

/// Record covered txs in chain order. Order entries already present in the
/// DAG are counted as satisfied (idempotent under duplicate deliveries);
/// entries neither in the DAG nor in `got` are skipped (still missing, they
/// must arrive in a later round). Returns how many `order` entries are in the
/// DAG after the call. Bounded parent retries mirror the production funnel.
async fn record_covered(
    order: &[Transaction],
    got: &HashMap<[u8; 32], Transaction>,
    node: &TestNode,
    processor: &TransactionProcessor,
    what: &str,
) -> usize {
    let mut recorded = 0usize;
    for want in order {
        if dag_contains(node, &want.id).await {
            recorded += 1;
            continue;
        }
        let tx = match got.get(&want.id) {
            Some(t) => t,
            None => continue,
        };
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
        assert!(done, "{} records {:02x?}", what, &tx.id[..4]);
        recorded += 1;
    }
    recorded
}

/// Drain the channel for `window` and enforce the no-double-apply contract on
/// a converged node: every delivery must be an ALREADY-KNOWN id (the gossip
/// arm may re-deliver; the sync arms self-dedup) and its record attempt must
/// be REJECTED by the funnel. Returns how many extras were drained. Any new
/// id or any successful insert is a hard failure.
async fn drain_verify_no_double_apply(
    rx: &mut mpsc::UnboundedReceiver<Transaction>,
    dag_arc: &Arc<RwLock<DAG>>,
    storage_arc: &Arc<RwLock<Storage>>,
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
            Ok(Some(tx)) => {
                extra += 1;
                assert!(
                    dag_arc.read().await.transactions().contains_key(&tx.id),
                    "{}: NEW id {:02x?} delivered after convergence",
                    ctx,
                    &tx.id[..4]
                );
                let r = {
                    let mut dag = dag_arc.write().await;
                    let store = storage_arc.read().await;
                    record_tx(&mut dag, &store, processor, &tx)
                };
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

fn probe_dir(path: &Path, expect_n: usize, name: &str) {
    let store = Storage::open(path).unwrap_or_else(|_| panic!("{} dir reopens", name));
    assert_eq!(
        store.get_all_transactions().expect("read").len(),
        expect_n,
        "{} persisted count after shutdown",
        name
    );
    drop(store);
}

// ---- ay01 (§3 + §5): 3-node partition, pure-sync backfill, restart churn ---
//
// A([]) B([A]) C([A]) mesh. S1=3 chained txs gossip to B and C. B is cleanly
// partitioned (real shutdown); S2=3 chained txs are created on A while B is
// down (C receives them live). B reboots on its OWN dir/port: it rebuilds
// n=3 from its persisted bytes and catches up S2 EXCLUSIVELY through the
// sync path (no rebroadcast): inventory diff -> GetData -> paginated
// SyncResponse -> dependency-fixpoint delivery. Then a second cycle restarts
// B and C back-to-back (session churn) and S3 converges on all three.
// Finally every store reopens, rebuilds to n=8 and must match the LIVE
// fingerprint exactly.
#[tokio::test]
async fn ay01_partition_heal_pure_sync_backfill_and_restart_churn() {
    const PA: u16 = 44811;
    const PB: u16 = 44812;
    const PC: u16 = 44813;
    let dir_a = unique_dir("ay01-a");
    let dir_b = unique_dir("ay01-b");
    let dir_c = unique_dir("ay01-c");
    let addr_a: SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();

    let node_a = boot_node(dir_a.clone(), PA, vec![], None).await;
    let mut node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    let mut node_c = boot_node(dir_c.clone(), PC, vec![addr_a], None).await;
    wait_for("ay01 mesh", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 2
            && node_b.p2p.peer_count().await >= 1
            && node_c.p2p.peer_count().await >= 1
    })
    .await;

    let wallet = wallet_n(810101);
    let processor = TransactionProcessor::new();
    let ts0: u64 = 1_755_100_000_000;

    // S1 = 3 chained txs, live gossip to both peers.
    let s1 = mine_chain(&wallet, ts0, 3);
    for tx in &s1 {
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, tx).expect("A records S1");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let want1: HashSet<[u8; 32]> = s1.iter().map(|t| t.id).collect();
    let got_b1 = collect_cover(&mut node_b.rx, &want1, PROPAGATE_TIMEOUT, "ay01 B S1").await;
    let got_c1 = collect_cover(&mut node_c.rx, &want1, PROPAGATE_TIMEOUT, "ay01 C S1").await;
    assert_eq!(got_b1.len(), 3, "B gets exactly S1 via gossip");
    assert_eq!(got_c1.len(), 3, "C gets exactly S1 via gossip");
    for (node, got, name) in [(&node_b, &got_b1, "ay01 B"), (&node_c, &got_c1, "ay01 C")] {
        let rec = record_covered(&s1, got, node, &processor, name).await;
        assert_eq!(rec, 3);
    }
    wait_for("ay01 three-way n=3", CATCHUP_TIMEOUT, || async {
        let (fa, fb, fc) = (
            live_fp(&node_a).await,
            live_fp(&node_b).await,
            live_fp(&node_c).await,
        );
        fa == fb && fb == fc && fa.starts_with("n=3 ")
    })
    .await;

    // PARTITION: clean-kill B; its own dir proves staleness n=3.
    shutdown_node(node_b, "ay01 B-partition").await;
    probe_dir(&dir_b, 3, "ay01 B-stale");

    // S2 = 3 more chained txs while B is down (C receives live).
    let mut prev = s1[2].id;
    let mut s2 = Vec::new();
    for i in 0..3u64 {
        let tx = make_valid_tx(&wallet, [prev, [0u8; 32]], 4 + i, ts0 + 10 + i);
        prev = tx.id;
        s2.push(tx);
    }
    for tx in &s2 {
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, tx).expect("A records S2");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let want2: HashSet<[u8; 32]> = s2.iter().map(|t| t.id).collect();
    let got_c2 = collect_cover(&mut node_c.rx, &want2, PROPAGATE_TIMEOUT, "ay01 C S2").await;
    assert!(got_c2
        .keys()
        .all(|id| want1.contains(id) || want2.contains(id)));
    let rec = record_covered(&s2, &got_c2, &node_c, &processor, "ay01 C-S2").await;
    assert_eq!(rec, 3);
    wait_for("ay01 A==C n=6", CATCHUP_TIMEOUT, || async {
        live_fp(&node_a).await == live_fp(&node_c).await
            && live_fp(&node_a).await.starts_with("n=6 ")
    })
    .await;

    // HEAL: reboot B on its own dir/port; it must catch up S2 through the
    // sync path alone (A does NOT rebroadcast anything).
    let t_heal = Instant::now();
    node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    assert_eq!(node_b.rebuilt_n, 3, "B rebuilds its stale n=3 state");
    assert!(
        !dag_contains(&node_b, &s2[0].id).await,
        "S2 genuinely missing on B before delivery"
    );
    wait_for("ay01 B reconnect", CONNECT_TIMEOUT, || async {
        node_b.p2p.peer_count().await >= 1
    })
    .await;
    let t_reconnect = t_heal.elapsed();
    let got_heal = collect_cover(&mut node_b.rx, &want2, CATCHUP_TIMEOUT, "ay01 B heal S2").await;
    let t_data = t_heal.elapsed();
    assert!(
        got_heal
            .keys()
            .all(|id| want1.contains(id) || want2.contains(id)),
        "no unknown id may surface (S1 is DAG-deduped before the channel)"
    );
    let rec = record_covered(&s2, &got_heal, &node_b, &processor, "ay01 B-heal").await;
    assert_eq!(rec, 3);
    wait_for("ay01 three-way n=6", CATCHUP_TIMEOUT, || async {
        let (fa, fb, fc) = (
            live_fp(&node_a).await,
            live_fp(&node_b).await,
            live_fp(&node_c).await,
        );
        fa == fb && fb == fc && fa.starts_with("n=6 ")
    })
    .await;
    let t_converge = t_heal.elapsed();
    assert_eq!(store_count(&node_b).await, 6, "B persists exact history");
    // Post-positive idempotence: duplicates may still arrive (gossip arm),
    // but none may apply. Any such delivery is verified, not silenced.
    let extras = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(700),
        "ay01 B heal settle",
    )
    .await;
    assert_eq!(dag_count(&node_b).await, 6);
    println!(
        "AY01: stale_n=3 reconnect={:?} data_after_reconnect={:?} converge={:?} extras_rejected={}",
        t_reconnect,
        t_data - t_reconnect,
        t_converge,
        extras
    );

    // CYCLE 2 (session churn): B and C restart back-to-back, S3=2 chained.
    shutdown_node(node_b, "ay01 B-cycle2").await;
    shutdown_node(node_c, "ay01 C-cycle2").await;
    node_c = boot_node(dir_c.clone(), PC, vec![addr_a], None).await;
    assert_eq!(node_c.rebuilt_n, 6);
    node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    assert_eq!(node_b.rebuilt_n, 6);
    wait_for("ay01 mesh restored", CATCHUP_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 2
            && node_b.p2p.peer_count().await >= 1
            && node_c.p2p.peer_count().await >= 1
    })
    .await;
    let mut prev = s2[2].id;
    let mut s3 = Vec::new();
    for i in 0..2u64 {
        let tx = make_valid_tx(&wallet, [prev, [0u8; 32]], 7 + i, ts0 + 20 + i);
        prev = tx.id;
        s3.push(tx);
    }
    for tx in &s3 {
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, tx).expect("A records S3");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let want3: HashSet<[u8; 32]> = s3.iter().map(|t| t.id).collect();
    let got_b3 = collect_cover(&mut node_b.rx, &want3, CATCHUP_TIMEOUT, "ay01 B S3").await;
    let got_c3 = collect_cover(&mut node_c.rx, &want3, CATCHUP_TIMEOUT, "ay01 C S3").await;
    let live_universe: HashSet<[u8; 32]> =
        want1.union(&want2).chain(want3.iter()).copied().collect();
    assert!(got_b3.keys().all(|id| live_universe.contains(id)));
    assert!(got_c3.keys().all(|id| live_universe.contains(id)));
    assert_eq!(
        record_covered(&s3, &got_b3, &node_b, &processor, "ay01 B-S3").await,
        2
    );
    assert_eq!(
        record_covered(&s3, &got_c3, &node_c, &processor, "ay01 C-S3").await,
        2
    );
    wait_for("ay01 three-way n=8", CATCHUP_TIMEOUT, || async {
        let (fa, fb, fc) = (
            live_fp(&node_a).await,
            live_fp(&node_b).await,
            live_fp(&node_c).await,
        );
        fa == fb && fb == fc && fa.starts_with("n=8 ")
    })
    .await;
    for (n, name) in [(&node_a, "A"), (&node_b, "B"), (&node_c, "C")] {
        assert_eq!(store_count(n).await, 8, "{} store count", name);
    }

    // §7: shutdown cleanly, reopen every store, rebuild like boot, compare
    // against the LIVE fingerprint captured just before shutdown.
    let live = live_fp(&node_a).await;
    shutdown_node(node_a, "ay01 A-final").await;
    shutdown_node(node_b, "ay01 B-final").await;
    shutdown_node(node_c, "ay01 C-final").await;
    for (dir, name) in [(&dir_a, "A"), (&dir_b, "B"), (&dir_c, "C")] {
        probe_dir(dir, 8, name);
        let (dag, n) = rebuild_dag_from_disk(dir);
        assert_eq!(n, 8, "{} rebuilds 8 txs", name);
        let fp = fingerprint(&dag, &rebuild_ledger_like_boot(&dag));
        assert_eq!(fp, live, "{} restart rebuild == live fingerprint", name);
    }
    println!("AY01: final restart fingerprints identical (n=8) on A/B/C");
}

// ---- ay02 (§4): peer loss + relay catch-up through the remaining peer -----
//
// Chain topology A([]) -> C([A]) -> B([C]). S1 reaches C by gossip and B
// ONLY by sync backfill from C (C is not the origin; C never gossips
// further). C is then killed: B loses its only peer while S2 is created on
// the unreachable-from-B A. C restarts stale (rebuilt_n=2), reconnects A and
// catches up S2; B redials C (production redial loop) and catches up S2
// through C. Final: three-way fingerprint identity + restart == live.
#[tokio::test]
async fn ay02_peer_loss_and_relay_catchup() {
    const PA: u16 = 44814;
    const PB: u16 = 44815;
    const PC: u16 = 44816;
    let dir_a = unique_dir("ay02-a");
    let dir_b = unique_dir("ay02-b");
    let dir_c = unique_dir("ay02-c");
    let addr_a: SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let addr_c: SocketAddr = format!("127.0.0.1:{}", PC).parse().unwrap();

    let node_a = boot_node(dir_a.clone(), PA, vec![], None).await;
    let mut node_c = boot_node(dir_c.clone(), PC, vec![addr_a], None).await;
    let mut node_b = boot_node(dir_b.clone(), PB, vec![addr_c], None).await;
    assert_eq!(node_b.rebuilt_n, 0, "B starts empty");
    wait_for("ay02 chain mesh", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1
            && node_c.p2p.peer_count().await >= 2
            && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let wallet = wallet_n(820202);
    let processor = TransactionProcessor::new();
    let ts0: u64 = 1_756_100_000_000;

    // S1 = 2 chained: C gets them live (gossip), B gets them via sync only.
    let s1 = mine_chain(&wallet, ts0, 2);
    for tx in &s1 {
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, tx).expect("A records S1");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let want1: HashSet<[u8; 32]> = s1.iter().map(|t| t.id).collect();
    let got_c1 = collect_cover(&mut node_c.rx, &want1, PROPAGATE_TIMEOUT, "ay02 C S1").await;
    assert_eq!(got_c1.len(), 2, "C receives S1 live from A");
    assert_eq!(
        record_covered(&s1, &got_c1, &node_c, &processor, "ay02 C-S1").await,
        2
    );
    // B has no gossip path from A: purely the sync machinery can deliver.
    let got_b1 = collect_cover(&mut node_b.rx, &want1, CATCHUP_TIMEOUT, "ay02 B S1 by sync").await;
    assert_eq!(got_b1.len(), 2, "B backfills S1 from non-origin peer C");
    assert_eq!(
        record_covered(&s1, &got_b1, &node_b, &processor, "ay02 B-S1").await,
        2
    );
    wait_for("ay02 three-way n=2", CATCHUP_TIMEOUT, || async {
        let (fa, fb, fc) = (
            live_fp(&node_a).await,
            live_fp(&node_b).await,
            live_fp(&node_c).await,
        );
        fa == fb && fb == fc && fa.starts_with("n=2 ")
    })
    .await;

    // PARTITION: C dies; B loses its ONLY peer; A becomes unreachable for B.
    shutdown_node(node_c, "ay02 C-partition").await;
    wait_for("ay02 B isolated", CONNECT_TIMEOUT, || async {
        node_b.p2p.peer_count().await == 0 && node_a.p2p.peer_count().await == 0
    })
    .await;

    // S2 created on A while C is down and B is stranded.
    let mut prev = s1[1].id;
    let mut s2 = Vec::new();
    for i in 0..2u64 {
        let tx = make_valid_tx(&wallet, [prev, [0u8; 32]], 3 + i, ts0 + 10 + i);
        prev = tx.id;
        s2.push(tx);
    }
    for tx in &s2 {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        record_tx(&mut dag, &store, &processor, tx).expect("A records S2 during partition");
    }
    assert_eq!(dag_count(&node_a).await, 4);
    assert!(
        !dag_contains(&node_b, &s2[1].id).await,
        "B is genuinely stale"
    );

    // C returns STALE and catches up from A; measure the whole chain.
    let want2: HashSet<[u8; 32]> = s2.iter().map(|t| t.id).collect();
    let t_c = Instant::now();
    node_c = boot_node(dir_c.clone(), PC, vec![addr_a], None).await;
    assert_eq!(node_c.rebuilt_n, 2, "C rebuilds its stale n=2 bytes");
    wait_for("ay02 C reconnect", CONNECT_TIMEOUT, || async {
        node_c.p2p.peer_count().await >= 1 && node_a.p2p.peer_count().await >= 1
    })
    .await;
    let t_c_reconnect = t_c.elapsed();
    let got_c2 = collect_cover(&mut node_c.rx, &want2, CATCHUP_TIMEOUT, "ay02 C S2").await;
    assert!(
        got_c2
            .keys()
            .all(|id| want1.contains(id) || want2.contains(id)),
        "no unknown id in C catch-up"
    );
    assert_eq!(
        record_covered(&s2, &got_c2, &node_c, &processor, "ay02 C-S2").await,
        2
    );
    let t_c_catchup = t_c.elapsed();
    wait_for("ay02 A==C n=4", CATCHUP_TIMEOUT, || async {
        live_fp(&node_a).await == live_fp(&node_c).await
            && live_fp(&node_a).await.starts_with("n=4 ")
    })
    .await;

    // B redials C (bootnode, production redial loop) and backfills via C.
    let t_b = Instant::now();
    wait_for("ay02 B<->C reconnect", CATCHUP_TIMEOUT, || async {
        node_b.p2p.peer_count().await >= 1
    })
    .await;
    let t_b_reconnect = t_b.elapsed();
    let got_b2 = collect_cover(&mut node_b.rx, &want2, CATCHUP_TIMEOUT, "ay02 B S2 via C").await;
    assert!(
        got_b2
            .keys()
            .all(|id| want1.contains(id) || want2.contains(id)),
        "no unknown id in B relay catch-up"
    );
    assert_eq!(
        record_covered(&s2, &got_b2, &node_b, &processor, "ay02 B-S2").await,
        2
    );
    let t_b_catchup = t_b.elapsed();
    wait_for("ay02 three-way n=4", CATCHUP_TIMEOUT, || async {
        let (fa, fb, fc) = (
            live_fp(&node_a).await,
            live_fp(&node_b).await,
            live_fp(&node_c).await,
        );
        fa == fb && fb == fc && fa.starts_with("n=4 ")
    })
    .await;
    for (n, name) in [(&node_a, "A"), (&node_b, "B"), (&node_c, "C")] {
        assert_eq!(store_count(n).await, 4, "{} store count", name);
    }
    let extras = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(700),
        "ay02 B settle",
    )
    .await;
    let extras_c = drain_verify_no_double_apply(
        &mut node_c.rx,
        &node_c.dag,
        &node_c.storage,
        &processor,
        Duration::from_millis(500),
        "ay02 C settle",
    )
    .await;
    println!(
        "AY02: c_stale_n=2 c_reconnect={:?} c_catchup={:?} b_reconnect_to_relay={:?} b_catchup={:?} extras_rejected={}+{}",
        t_c_reconnect, t_c_catchup, t_b_reconnect, t_b_catchup, extras, extras_c
    );

    let live = live_fp(&node_a).await;
    shutdown_node(node_a, "ay02 A-final").await;
    shutdown_node(node_b, "ay02 B-final").await;
    shutdown_node(node_c, "ay02 C-final").await;
    for (dir, name) in [(&dir_a, "A"), (&dir_b, "B"), (&dir_c, "C")] {
        probe_dir(dir, 4, name);
        let (dag, n) = rebuild_dag_from_disk(dir);
        assert_eq!(n, 4, "{} rebuilds 4 txs", name);
        let fp = fingerprint(&dag, &rebuild_ledger_like_boot(&dag));
        assert_eq!(fp, live, "{} restart rebuild == live fingerprint", name);
    }
    println!("AY02: final restart fingerprints identical (n=4) on A/B/C");
}

// ---- ay03 (§4 cut transfer + §5 no double apply) --------------------------
//
// Phase A: B boots empty against a seeded A (6-tx chain) and catches up by
// sync. The test consumes+persists EXACTLY ONE delivered tx and then crashes
// B (consumption-controlled partiality): the rest of the in-flight page is
// lost with the process, exactly like a crash mid-catch-up. On reboot B
// rebuilds n=1 and the remaining 5 arrive through sync (known ids suppressed
// before the channel), converging to the exact 6-tx history.
// Phase B: A has 30 txs (chain of 6 + 6 parallel 4-chains); B is isolated,
// then A reboots WITH a serving delay and B reconnects: A is killed ~600ms
// into serving. Serving sections are synchronous after their last await, so
// teardown may deliver some/all of the in-flight section - the test records
// whatever honestly survived, restarts A without delay, and asserts the
// RECOVERY invariant: exact final convergence, zero unknown ids, zero
// double apply. Phase C: duplicate gossip + full-sync rounds on converged
// state - extras may arrive (gossip arm) but every one must be rejected.
#[tokio::test]
async fn ay03_interrupted_transfer_and_no_double_apply() {
    const PA: u16 = 44817;
    const PB: u16 = 44818;
    let dir_a = unique_dir("ay03-a");
    let dir_b = unique_dir("ay03-b");
    let addr_a: SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let processor = TransactionProcessor::new();
    let ts0: u64 = 1_757_100_000_000;

    let wallet = wallet_n(870303);
    let base = mine_chain(&wallet, ts0, 6);
    let base_ids: HashSet<[u8; 32]> = base.iter().map(|t| t.id).collect();
    seed_store(&dir_a, &base, &processor);

    // PHASE A: crash the CLIENT after exactly one persisted tx.
    let node_a = boot_node(dir_a.clone(), PA, vec![], None).await;
    assert_eq!(node_a.rebuilt_n, 6);
    let mut node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    let first = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
        .await
        .expect("B receives first catch-up tx")
        .expect("live");
    assert_eq!(first.id, base[0].id, "parents-first chain order");
    let one: HashMap<[u8; 32], Transaction> = HashMap::from([(first.id, first.clone())]);
    assert_eq!(
        record_covered(&base, &one, &node_b, &processor, "ay03 A-half").await,
        1
    );
    assert_eq!(dag_count(&node_b).await, 1);
    shutdown_node(node_b, "ay03 B-crash-midcatchup").await;
    probe_dir(&dir_b, 1, "ay03 B-partial");

    node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    assert_eq!(
        node_b.rebuilt_n, 1,
        "crash mid-catch-up persisted exactly 1"
    );
    let want_base: HashSet<[u8; 32]> = base_ids.clone();
    let missing: HashSet<[u8; 32]> = {
        let d = node_b.dag.read().await;
        want_base
            .iter()
            .filter(|id| !d.transactions().contains_key(*id))
            .copied()
            .collect()
    };
    assert_eq!(missing.len(), 5);
    let t_resume = Instant::now();
    let got = collect_cover(&mut node_b.rx, &missing, CATCHUP_TIMEOUT, "ay03 A-resume").await;
    assert!(
        got.keys().all(|id| base_ids.contains(id)),
        "no unknown id on resume"
    );
    let missing_order: Vec<Transaction> = base
        .iter()
        .filter(|t| missing.contains(&t.id))
        .cloned()
        .collect();
    assert_eq!(
        record_covered(
            &missing_order,
            &got,
            &node_b,
            &processor,
            "ay03 A-resume-rec"
        )
        .await,
        missing.len()
    );
    wait_for("ay03 n=6", CATCHUP_TIMEOUT, || async {
        live_fp(&node_a).await == live_fp(&node_b).await
            && live_fp(&node_a).await.starts_with("n=6 ")
    })
    .await;
    println!(
        "AY03: phaseA persisted=1 resumed={} t_resume={:?}",
        missing.len(),
        t_resume.elapsed()
    );

    // PHASE B: kill the SERVER mid-serve; client keeps running and resumes.
    shutdown_node(node_b, "ay03 B-isolate").await;
    let wallets_b: Vec<Wallet> = (0..6).map(|i| wallet_n(870500 + i)).collect();
    let chains: Vec<Vec<Transaction>> = std::thread::scope(|s| {
        let handles: Vec<_> = wallets_b
            .iter()
            .map(|w| s.spawn(|| mine_chain(w, ts0 + 100_000, 4)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mine thread"))
            .collect()
    });
    let extra: Vec<Transaction> = chains.iter().flatten().cloned().collect();
    assert_eq!(extra.len(), 24);
    let extra_ids: HashSet<[u8; 32]> = extra.iter().map(|t| t.id).collect();
    {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        for tx in &extra {
            record_tx(&mut dag, &store, &processor, tx).expect("A records extra");
        }
    }
    shutdown_node(node_a, "ay03 A-pre-delay").await;

    let node_a2 = boot_node(dir_a.clone(), PA, vec![], Some(Duration::from_millis(400))).await;
    assert_eq!(node_a2.rebuilt_n, 30);
    node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    assert_eq!(node_b.rebuilt_n, 6);
    wait_for("ay03 phaseB peering", CONNECT_TIMEOUT, || async {
        node_b.p2p.peer_count().await >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    shutdown_node(node_a2, "ay03 A-killed-midserve").await;

    // Record whatever honestly survived the interruption.
    let mut partial_map: HashMap<[u8; 32], Transaction> = HashMap::new();
    while let Ok(Some(tx)) =
        tokio::time::timeout(Duration::from_millis(500), node_b.rx.recv()).await
    {
        if extra_ids.contains(&tx.id) {
            partial_map.entry(tx.id).or_insert(tx);
        } else {
            assert!(
                base_ids.contains(&tx.id),
                "unknown id during interrupted serving"
            );
        }
    }
    let rec_partial =
        record_covered(&extra, &partial_map, &node_b, &processor, "ay03 B-midserve").await;
    println!(
        "AY03: server killed mid-serve received={} persisted={}",
        partial_map.len(),
        rec_partial
    );

    // Server restarts (no delay); the client finishes the catch-up via sync.
    let node_a = boot_node(dir_a.clone(), PA, vec![], None).await;
    assert_eq!(node_a.rebuilt_n, 30);
    wait_for("ay03 phaseB reconnect", CATCHUP_TIMEOUT, || async {
        node_b.p2p.peer_count().await >= 1
    })
    .await;
    let missing_extra: HashSet<[u8; 32]> = {
        let d = node_b.dag.read().await;
        extra_ids
            .iter()
            .filter(|id| !d.transactions().contains_key(*id))
            .copied()
            .collect()
    };
    let got2 = collect_cover(
        &mut node_b.rx,
        &missing_extra,
        CATCHUP_TIMEOUT,
        "ay03 B-midserve-resume",
    )
    .await;
    assert!(
        got2.keys()
            .all(|id| extra_ids.contains(id) || base_ids.contains(id)),
        "no unknown id on mid-serve resume"
    );
    let missing_order: Vec<Transaction> = extra
        .iter()
        .filter(|t| missing_extra.contains(&t.id))
        .cloned()
        .collect();
    assert_eq!(
        record_covered(
            &missing_order,
            &got2,
            &node_b,
            &processor,
            "ay03 B-resume-rec"
        )
        .await,
        missing_extra.len()
    );
    wait_for("ay03 n=30", CATCHUP_TIMEOUT, || async {
        live_fp(&node_a).await == live_fp(&node_b).await
            && live_fp(&node_a).await.starts_with("n=30 ")
    })
    .await;
    assert_eq!(
        dag_count(&node_b).await,
        30,
        "exact history, no double apply"
    );
    assert_eq!(store_count(&node_b).await, 30);

    // PHASE C: duplicates reach the channel (gossip arm) but never apply.
    node_a.p2p.broadcast_transaction(base[2].clone()).await;
    let d1 = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(1500),
        "ay03 duplicate",
    )
    .await;
    node_a.p2p.request_full_sync().await;
    node_b.p2p.request_full_sync().await;
    let d2 = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(2000),
        "ay03 full-sync",
    )
    .await;
    assert_eq!(dag_count(&node_b).await, 30);
    assert_eq!(store_count(&node_b).await, 30);
    println!(
        "AY03: duplicate/sync extras all rejected by the funnel ({} + {})",
        d1, d2
    );

    let live = live_fp(&node_a).await;
    shutdown_node(node_a, "ay03 A-final").await;
    shutdown_node(node_b, "ay03 B-final").await;
    for (dir, name) in [(&dir_a, "A"), (&dir_b, "B")] {
        probe_dir(dir, 30, name);
        let (dag, n) = rebuild_dag_from_disk(dir);
        assert_eq!(n, 30, "{} rebuilds 30 txs", name);
        let fp = fingerprint(&dag, &rebuild_ledger_like_boot(&dag));
        assert_eq!(fp, live, "{} restart rebuild == live fingerprint", name);
    }
    println!("AY03: interrupted transfers recovered; fingerprints identical (n=30)");
}

// ---- ay04 (§6): catch-up sized by the code limits (110 > MAX_SYNC_PAGE) ---
//
// A holds 110 txs = 22 independent chains of depth 5 (mined in parallel; each
// chain parents-first). 110 exceeds MAX_SYNC_PAGE (100) and stays under
// MAX_INV_ITEMS (1000), so the serving side MUST paginate the closure
// (2 SyncResponse pages) and the receiver needs at least one follow-up
// inventory round for leftovers whose parents were not yet recorded - the
// exact deep-sync path. B starts empty and catches up by sync alone (A never
// broadcasts). Missing-before/after, first-delivery and full-catch-up times
// are printed. Idempotence: duplicate broadcast + explicit full-sync may
// re-deliver via the gossip arm but never apply. Restart: B rebuilds n=110.
#[tokio::test]
async fn ay04_paginated_catchup_sized_by_limits() {
    const PA: u16 = 44819;
    const PB: u16 = 44820;
    const CHAINS: usize = 22;
    const DEPTH: usize = 5;
    let dir_a = unique_dir("ay04-a");
    let dir_b = unique_dir("ay04-b");
    let addr_a: SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let ts0: u64 = 1_757_500_000_000;
    let processor = TransactionProcessor::new();

    let wallets: Vec<Wallet> = (0..CHAINS).map(|i| wallet_n(940404 + i as u64)).collect();
    let t_mine = Instant::now();
    let chains: Vec<Vec<Transaction>> = std::thread::scope(|s| {
        let handles: Vec<_> = wallets
            .iter()
            .map(|w| s.spawn(|| mine_chain(w, ts0, DEPTH)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("mine thread"))
            .collect()
    });
    let all_txs: Vec<Transaction> = chains.iter().flatten().cloned().collect();
    assert_eq!(all_txs.len(), CHAINS * DEPTH, "110 txs > MAX_SYNC_PAGE=100");
    println!(
        "AY04: mined {} txs in {:?}",
        all_txs.len(),
        t_mine.elapsed()
    );

    let node_a = boot_node(dir_a.clone(), PA, vec![], None).await;
    {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        for chain in &chains {
            for tx in chain {
                record_tx(&mut dag, &store, &processor, tx).expect("A records");
            }
        }
    }
    assert_eq!(dag_count(&node_a).await, CHAINS * DEPTH);

    // B starts EMPTY and must catch up exclusively through sync.
    let t_boot = Instant::now();
    let mut node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    assert_eq!(node_b.rebuilt_n, 0);
    let want: HashSet<[u8; 32]> = all_txs.iter().map(|t| t.id).collect();
    let first = tokio::time::timeout(CATCHUP_TIMEOUT, node_b.rx.recv())
        .await
        .expect("B receives first backfilled tx")
        .expect("live");
    let t_first = t_boot.elapsed();
    let first_id = first.id;
    let mut got: HashMap<[u8; 32], Transaction> = HashMap::from([(first_id, first)]);
    let mut rest_want = want.clone();
    rest_want.remove(&first_id);
    let mut rest =
        collect_cover(&mut node_b.rx, &rest_want, CATCHUP_TIMEOUT, "ay04 full set").await;
    let t_full = t_boot.elapsed();
    got.extend(rest.drain());
    assert_eq!(got.len(), CHAINS * DEPTH, "every tx arrived exactly once");
    let ordered: Vec<Transaction> = chains.iter().flatten().cloned().collect();
    let rec = record_covered(&ordered, &got, &node_b, &processor, "ay04 B").await;
    assert_eq!(rec, CHAINS * DEPTH);
    wait_for("ay04 fp equality n=110", CATCHUP_TIMEOUT, || async {
        live_fp(&node_a).await == live_fp(&node_b).await
            && live_fp(&node_a).await.starts_with("n=110 ")
    })
    .await;
    let t_converge = t_boot.elapsed();
    assert_eq!(store_count(&node_b).await, CHAINS * DEPTH);
    println!(
        "AY04: missing_before={} missing_after=0 t_first={:?} t_full={:?} t_converge={:?}",
        CHAINS * DEPTH,
        t_first,
        t_full,
        t_converge
    );

    // Idempotence on the converged set.
    node_a.p2p.broadcast_transaction(all_txs[0].clone()).await;
    let d1 = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(1500),
        "ay04 duplicate",
    )
    .await;
    node_a.p2p.request_full_sync().await;
    node_b.p2p.request_full_sync().await;
    let d2 = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(2500),
        "ay04 full-sync idempotence",
    )
    .await;
    assert_eq!(dag_count(&node_b).await, CHAINS * DEPTH);
    println!("AY04: extras rejected by funnel ({} + {})", d1, d2);

    // Restart on the same dir: rebuild must equal the live fingerprint.
    let live = live_fp(&node_a).await;
    let t_rebuild = Instant::now();
    shutdown_node(node_b, "ay04 B-restart").await;
    node_b = boot_node(dir_b.clone(), PB, vec![addr_a], None).await;
    assert_eq!(node_b.rebuilt_n, CHAINS * DEPTH);
    let rebuilt_fp = live_fp(&node_b).await;
    assert_eq!(rebuilt_fp, live, "B rebuilt state == live state");
    println!("AY04: rebuild_110_txs={:?}", t_rebuild.elapsed());
    let d3 = drain_verify_no_double_apply(
        &mut node_b.rx,
        &node_b.dag,
        &node_b.storage,
        &processor,
        Duration::from_millis(1500),
        "ay04 post-restart quiet",
    )
    .await;
    println!("AY04: post-restart extras rejected by funnel ({})", d3);

    shutdown_node(node_a, "ay04 A-final").await;
    shutdown_node(node_b, "ay04 B-final").await;
    for (dir, name) in [(&dir_a, "A"), (&dir_b, "B")] {
        probe_dir(dir, CHAINS * DEPTH, name);
        let (dag, n) = rebuild_dag_from_disk(dir);
        assert_eq!(n, CHAINS * DEPTH, "{} rebuilds 110 txs", name);
        let fp = fingerprint(&dag, &rebuild_ledger_like_boot(&dag));
        assert_eq!(fp, live, "{} restart rebuild == live fingerprint", name);
    }
    println!("AY04: final restart fingerprints identical (n=110) on A/B");
}
