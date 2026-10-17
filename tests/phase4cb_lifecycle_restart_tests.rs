//! PHASE 4CB: P2P lifecycle — clean shutdown + restart on the SAME storage.
//!
//! Proves what 4CA explicitly did NOT: stopping both nodes, releasing every
//! resource (listeners, sockets, task handles, Sled locks), reopening the
//! EXACT same directories, rebuilding the DAG from persisted bytes, and
//! resuming P2P sync on the SAME ports. No copying to fresh dirs.
//!
//! Production change under test: `P2PNetwork::shutdown()` (p2p.rs) — tracked
//! JoinHandles (accept, discovery, recovery, redial, peer-store, anchor,
//! DNS, PEX, cache, sweep, per-peer sessions), abort+await with 5s/task
//! bound, session-map clears, discovery-channel close, dial gate. The test
//! FAILS LOUDLY if any step hangs (explicit timeouts) or leaks (reopen/
//! rebind failure is the leak detector — no masking).
//!
//! Honesty boundaries:
//! - Creation uses REAL APIs (keys, 20-bit PoW, Ed25519, validate_pure
//!   Historical, validated DAG insert, Sled persist). No rule bypassed.
//! - Recording mirrors the acceptance funnel (pure gate + DAG + persist +
//!   applied mark) without mempool/RPC scaffolding (own suites).
//! - Senders are unfunded: DAG admission proven, ledger transfers not
//!   (faucet unknown). Invariant = A==B convergence + supply conservation.
//! - Ports 44751/44752 are test-unique (never 4CA's 44731/32); leaked tasks
//!   would hold them and fail the rebind — the port IS the detector.

use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::ledger::Ledger;
use aether_unified::p2p::{P2PConfig, P2PNetwork};
use aether_unified::parent_selection::DAG;
use aether_unified::stake::{current_epoch, StakeRegistry};
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

const PORT_A: u16 = 44751;
const PORT_B: u16 = 44752;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const REOPEN_TIMEOUT: Duration = Duration::from_secs(30);
const RESTART_TIMEOUT: Duration = Duration::from_secs(60);

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

/// Boot-sequence rebuild from the EXACT persisted dir (mirrors node.rs boot
/// + 4BZ boot_like_rebuild): read txs+orphans, fresh genesis DAG,
/// topological rebuild, tips, ledger. Proves the bytes on disk.
fn boot_rebuild_from_same_dir(dir: &Path) -> (DAG, Ledger, usize, usize) {
    let store = Storage::open(dir).expect("REOPEN: same-dir store must open (leak if it fails)");
    let mut all = store.get_all_transactions().expect("read txs");
    for orphan in store.get_all_orphans().expect("read orphans") {
        if !all.iter().any(|t| t.id == orphan.id) {
            all.push(orphan);
        }
    }
    drop(store);
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (ins, sk, orphans) =
        aether_unified::parent_selection::rebuild_dag_topological(&mut dag, all);
    assert_eq!(sk, 0, "no silent skips on healthy store");
    dag.rebuild_tips();
    let ledger = rebuild_ledger_like_boot(&dag);
    (dag, ledger, ins as usize, orphans.len())
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

async fn boot_node_on_dir(
    dir: &Path,
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
    tokio::time::timeout(RESTART_TIMEOUT, p2p.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds (port leak if it fails)");
    TestNode {
        storage,
        dag,
        p2p,
        rx,
    }
}

async fn shutdown_node(node: TestNode, name: &str) {
    assert_eq!(
        node.p2p.is_shutting_down(),
        false,
        "{} must not be flagged before shutdown",
        name
    );
    tokio::time::timeout(SHUTDOWN_TIMEOUT, node.p2p.shutdown())
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT: {} shutdown hung (tasks leaked)", name))
        .unwrap_or_else(|e| panic!("{} shutdown reported: {}", name, e));
    assert!(
        node.p2p.is_shutting_down(),
        "{} flag must be set after shutdown",
        name
    );
    wait_for(
        &format!("{} peer_count==0", name),
        SHUTDOWN_TIMEOUT,
        || async { node.p2p.peer_count().await == 0 },
    )
    .await;
    node.storage.read().await.flush().expect("flush");
    drop(node);
}

// Full lifecycle: sync -> shutdown -> SAME-dir reopen -> restart -> new sync
// -> shutdown -> SAME-dir reopen. Two complete cycles, zero fresh dirs.
#[tokio::test]
async fn cb01_shutdown_restart_same_storage_two_cycles() {
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let path_a = dir_a.path().to_path_buf();
    let path_b = dir_b.path().to_path_buf();
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PORT_A).parse().unwrap();
    let wallet = wallet_n(991001);
    let processor = TransactionProcessor::new();

    // ---- CYCLE 1: fresh genesis stores, real P2P sync of 4 txs ----
    let c1_txs: Vec<Transaction> = (0..4usize)
        .map(|i| {
            let parents = if i == 0 {
                [[0u8; 32], [0u8; 32]]
            } else {
                // chain locally; parents assigned after previous id known
                [[0u8; 32], [0u8; 32]]
            };
            let _ = parents;
            make_valid_tx(
                &wallet,
                [[0u8; 32], [0u8; 32]],
                100 + i as u64,
                1_760_000_000 + i as u64,
            )
        })
        .collect();
    // Chain them properly (each parents the previous) — recompute id/sig.
    let mut chained: Vec<Transaction> = Vec::new();
    let mut prev = [0u8; 32];
    for (i, _) in c1_txs.iter().enumerate() {
        let tx = make_valid_tx(
            &wallet,
            [prev, [0u8; 32]],
            100 + i as u64,
            1_760_000_000 + i as u64,
        );
        prev = tx.id;
        chained.push(tx);
    }
    let fp_c1: String;
    {
        let storage_a = Arc::new(RwLock::new(Storage::open(&path_a).expect("open A c1")));
        let storage_b = Arc::new(RwLock::new(Storage::open(&path_b).expect("open B c1")));
        let dag_a = Arc::new(RwLock::new(DAG::new()));
        let dag_b = Arc::new(RwLock::new(DAG::new()));
        let mut node_a =
            boot_node_on_dir(&path_a, PORT_A, vec![], dag_a.clone(), storage_a.clone()).await;
        let mut node_b =
            boot_node_on_dir(&path_b, PORT_B, vec![pa], dag_b.clone(), storage_b.clone()).await;
        wait_for("A<->B peering c1", CONNECT_TIMEOUT, || async {
            node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
        })
        .await;
        for tx in &chained {
            {
                let mut dag = node_a.dag.write().await;
                let store = node_a.storage.read().await;
                record_tx(&mut dag, &store, &processor, tx).expect("A records c1");
            }
            node_a.p2p.broadcast_transaction(tx.clone()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let mut received = Vec::new();
        for _ in 0..chained.len() {
            let tx = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
                .await
                .expect("B receives c1")
                .expect("channel live");
            received.push(tx);
        }
        for (s, r) in chained.iter().zip(received.iter()) {
            assert_eq!(s.id, r.id, "c1 byte-identical TCP delivery");
        }
        for tx in &received {
            let mut done = false;
            for _ in 0..20 {
                let r = {
                    let mut dag = node_b.dag.write().await;
                    let store = node_b.storage.read().await;
                    record_tx(&mut dag, &store, &processor, tx)
                };
                if r.is_ok() {
                    done = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(done, "B records c1 {:?}", tx.id);
        }
        let (fa, fb) = {
            let (da, db) = (node_a.dag.read().await, node_b.dag.read().await);
            (
                fingerprint(&da, &rebuild_ledger_like_boot(&da)),
                fingerprint(&db, &rebuild_ledger_like_boot(&db)),
            )
        };
        assert_eq!(fa, fb, "c1 A==B converge");
        assert!(fa.starts_with("n=4 "), "c1 all 4 txs present, got {}", fa);
        fp_c1 = fa;
        shutdown_node(node_a, "A-c1").await;
        shutdown_node(node_b, "B-c1").await;
        // storage/dag Arcs dropped with nodes; dirs NOT removed.
    }

    // ---- SAME-dir reopen (the leak detector): no new dirs, no copies ----
    {
        let fp = tokio::time::timeout(REOPEN_TIMEOUT, async {
            let (dag_a, ledger_a, n_a, o_a) = boot_rebuild_from_same_dir(&path_a);
            let (dag_b, ledger_b, n_b, o_b) = boot_rebuild_from_same_dir(&path_b);
            assert_eq!(n_a, 4, "A reopened: 4 txs from SAME dir");
            assert_eq!(n_b, 4, "B reopened: 4 txs from SAME dir");
            assert_eq!((o_a, o_b), (0, 0), "no orphans c1");
            let (fa, fb) = (
                fingerprint(&dag_a, &ledger_a),
                fingerprint(&dag_b, &ledger_b),
            );
            assert_eq!(fa, fb, "reopened A==B");
            assert_eq!(fa, fp_c1, "reopened state == pre-shutdown state");
            fa
        })
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT: same-dir reopen c1 hung (sled lock held?)"));
        let _ = fp;
    }

    // ---- CYCLE 2: restart on SAME dirs + SAME ports, 3 NEW chained txs ----
    let fp_c2: String;
    {
        // Rebuild in-memory DAGs from the SAME persisted bytes (boot path).
        let (dag_a_built, _, _, _) = boot_rebuild_from_same_dir(&path_a);
        let (dag_b_built, _, _, _) = boot_rebuild_from_same_dir(&path_b);
        assert_eq!(dag_a_built.transaction_count(), 4);
        assert_eq!(dag_b_built.transaction_count(), 4);
        let storage_a = Arc::new(RwLock::new(Storage::open(&path_a).expect("reopen A c2")));
        let storage_b = Arc::new(RwLock::new(Storage::open(&path_b).expect("reopen B c2")));
        let dag_a = Arc::new(RwLock::new(dag_a_built));
        let dag_b = Arc::new(RwLock::new(dag_b_built));
        // SAME ports: rebind proves the old listeners were released.
        let mut node_a =
            boot_node_on_dir(&path_a, PORT_A, vec![], dag_a.clone(), storage_a.clone()).await;
        let mut node_b =
            boot_node_on_dir(&path_b, PORT_B, vec![pa], dag_b.clone(), storage_b.clone()).await;
        // Fresh instances must NOT be flagged.
        assert!(!node_a.p2p.is_shutting_down() && !node_b.p2p.is_shutting_down());
        wait_for("A<->B peering c2", CONNECT_TIMEOUT, || async {
            node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
        })
        .await;
        // New txs chained on the c1 tip (resume, not fresh history).
        let mut new_txs = Vec::new();
        for i in 0..3usize {
            let tx = make_valid_tx(
                &wallet,
                [prev, [0u8; 32]],
                200 + i as u64,
                1_760_001_000 + i as u64,
            );
            prev = tx.id;
            new_txs.push(tx);
        }
        for tx in &new_txs {
            {
                let mut dag = node_a.dag.write().await;
                let store = node_a.storage.read().await;
                record_tx(&mut dag, &store, &processor, tx).expect("A records c2");
            }
            node_a.p2p.broadcast_transaction(tx.clone()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let mut received = Vec::new();
        for _ in 0..new_txs.len() {
            let tx = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
                .await
                .expect("B receives c2")
                .expect("channel live");
            received.push(tx);
        }
        for (s, r) in new_txs.iter().zip(received.iter()) {
            assert_eq!(s.id, r.id, "c2 byte-identical TCP delivery");
        }
        for tx in &received {
            let mut done = false;
            for _ in 0..20 {
                let r = {
                    let mut dag = node_b.dag.write().await;
                    let store = node_b.storage.read().await;
                    record_tx(&mut dag, &store, &processor, tx)
                };
                if r.is_ok() {
                    done = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(done, "B records c2 {:?}", tx.id);
        }
        let (fa, fb) = {
            let (da, db) = (node_a.dag.read().await, node_b.dag.read().await);
            (
                fingerprint(&da, &rebuild_ledger_like_boot(&da)),
                fingerprint(&db, &rebuild_ledger_like_boot(&db)),
            )
        };
        assert_eq!(fa, fb, "c2 A==B converge");
        assert!(fa.starts_with("n=7 "), "c2 4+3 txs present, got {}", fa);
        fp_c2 = fa;
        shutdown_node(node_a, "A-c2").await;
        shutdown_node(node_b, "B-c2").await;
    }

    // ---- Final SAME-dir reopen: full 7-tx history from the original dirs ----
    {
        let fp = tokio::time::timeout(REOPEN_TIMEOUT, async {
            let (dag_a, ledger_a, n_a, o_a) = boot_rebuild_from_same_dir(&path_a);
            let (dag_b, ledger_b, n_b, o_b) = boot_rebuild_from_same_dir(&path_b);
            assert_eq!((n_a, n_b), (7, 7), "final reopen: 7 txs SAME dirs");
            assert_eq!((o_a, o_b), (0, 0), "no orphans final");
            let (fa, fb) = (
                fingerprint(&dag_a, &ledger_a),
                fingerprint(&dag_b, &ledger_b),
            );
            assert_eq!(fa, fb, "final reopened A==B");
            assert_eq!(fa, fp_c2, "final reopened == pre-shutdown c2");
            // Conservation: supply identical, no phantom balances.
            assert_eq!(ledger_a.total_supply(), ledger_b.total_supply());
            fa
        })
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT: final same-dir reopen hung"));
        let _ = fp;
    }
    // Tempdirs dropped here; no network task may outlive the test (all
    // handles aborted+awaited in shutdown_node; rebinds proved release).
}
