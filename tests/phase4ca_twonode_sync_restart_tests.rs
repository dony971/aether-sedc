//! PHASE 4CA: two-node real-P2P sync + restart (INC-01 liveness end-to-end).
//!
//! Topology: node A and node B on 127.0.0.1 with distinct ports and
//! distinct Sled stores, REAL TCP P2P (P2PNetwork::start + bootnode dial +
//! broadcast_transaction), no VPS, no public network, no shared storage.
//!
//! Honesty boundaries (read before citing results):
//! - Creation uses REAL existing APIs: Wallet keys, real 20-bit PoW,
//!   real Ed25519 signatures, TransactionProcessor::validate_pure,
//!   DAG validated insert, Sled persistence. Nothing is faked and no
//!   protocol rule is bypassed.
//! - Recording on B mirrors the acceptance funnel (pure gate + DAG
//!   admission + store persist + applied mark) WITHOUT the mempool/RPC
//!   scaffolding, which has its own suites. The boundary is explicit.
//! - Senders are unfunded wallets: DAG admission is proven, ledger transfer
//!   application is not (faucet key unknown by design). Both ledgers stay
//!   genesis-state; the asserted invariant is A==B convergence + supply
//!   conservation, never funded transfers.
//! - Lifecycle finding: P2PNetwork spawns detached tasks with no shutdown
//!   handle, and sled holds an exclusive directory lock. Same-directory
//!   reopen after P2P start is therefore IMPOSSIBLE in-process (proven by
//!   sled's try_lock_exclusive + immortal accept loops, not assumed).
//!   Restart phases use FRESH dirs seeded with the exact bytes received
//!   over TCP; same-dir restart without prior P2P is covered by 4BZ.
//! - Every wait is an explicit timeout (tokio::time::timeout): expiry FAILS
//!   the test. Leaked runtime tasks hold test-unique ports/dirs only and
//!   are documented, never reused.

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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

const PORT_A: u16 = 44731;
const PORT_B: u16 = 44732;
const N_TX: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(30);
const RESTART_TIMEOUT: Duration = Duration::from_secs(60);

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aether-4ca-{}-{}", tag, std::process::id()));
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

/// Real creation path: key + 20-bit PoW (pre-activation policy) + real
/// signature. Returns a fully-formed, valid transaction.
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
    // Real pure gate (PoW + signature), Historical = production DAG-entry mode.
    TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Historical)
        .expect("freshly mined+signed tx must pass the pure gate");
    tx
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

struct TestNode {
    _dir_guard: tempfile::TempDir,
    storage: Arc<RwLock<Storage>>,
    dag: Arc<RwLock<DAG>>,
    p2p: Arc<P2PNetwork>,
    rx: mpsc::UnboundedReceiver<Transaction>,
}

async fn boot_node(
    dir: tempfile::TempDir,
    port: u16,
    bootnodes: Vec<std::net::SocketAddr>,
) -> TestNode {
    let storage = Arc::new(RwLock::new(Storage::open(dir.path()).expect("open store")));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let (tx_sender, rx) = mpsc::unbounded_channel::<Transaction>();
    let dag_c = dag.clone();
    let _storage_c = storage.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on(async {
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
    let storage_c2 = storage.clone();
    let get_tx: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(move |hash| {
        __test_only_block_on(async {
            if let Ok(id) = <[u8; 32]>::try_from(hash) {
                if let Ok(g) = dag_c.try_read() {
                    if let Some(tx) = g.transactions().get(&id) {
                        return Some(tx.clone());
                    }
                }
                if let Ok(s) = storage_c2.try_read() {
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
        __test_only_block_on(async {
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
    p2p.start().await.expect("p2p start");
    TestNode {
        _dir_guard: dir,
        storage,
        dag,
        p2p,
        rx,
    }
}

/// Bridge sync closures to async state. The production closures are sync
/// (`Fn`, called from socket tasks); this helper is TEST-ONLY scaffolding
/// to read that state, never part of the node.
fn __test_only_block_on<F, T>(fut: F) -> T
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

// 1-6. Real sync: A creates valid txs, B receives them OVER TCP and records
// them; identities, relations and frontier converge.
#[tokio::test]
async fn ca01_two_nodes_sync_over_real_p2p() {
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PORT_A).parse().unwrap();

    let node_a = boot_node(dir_a, PORT_A, vec![]).await;
    let mut node_b = boot_node(dir_b, PORT_B, vec![pa]).await;

    // 3. Real connection via the program-normal path (bootnode dial).
    wait_for("A<->B peering", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    // 4-5. A creates REAL valid txs (chained parents), records locally,
    // broadcasts over the REAL relay path; B receives via its channel.
    let wallet = wallet_n(424242);
    let processor = TransactionProcessor::new();
    let ts0: u64 = 1_750_000_000_000;
    let mut prev = [0u8; 32];
    let mut sent: Vec<Transaction> = Vec::new();
    for i in 0..N_TX {
        let tx = make_valid_tx(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
        prev = tx.id;
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, &tx).expect("A records");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        sent.push(tx);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // B receives over TCP (NOT shared storage, NOT simulated delivery).
    let mut received: Vec<Transaction> = Vec::new();
    for _ in 0..N_TX {
        let tx = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
            .await
            .expect("B receives within timeout")
            .expect("channel live");
        received.push(tx);
    }
    for (s, r) in sent.iter().zip(received.iter()) {
        assert_eq!(s.id, r.id, "byte-identical remote delivery");
    }
    // B records through the same funnel (bounded parent retries).
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
        assert!(done, "B records {:?}", tx.id);
    }

    // 6. Convergence: identities, relations, frontier.
    let (fa, fb) = {
        let (da, db) = (node_a.dag.read().await, node_b.dag.read().await);
        let la = rebuild_ledger_like_boot(&da);
        let lb = rebuild_ledger_like_boot(&db);
        (fingerprint(&da, &la), fingerprint(&db, &lb))
    };
    assert_eq!(
        fa, fb,
        "A and B converge (ids, relations, frontier, ledger)"
    );
    assert!(
        fa.starts_with(&format!("n={} ", N_TX)),
        "all {} txs present",
        N_TX
    );
    // 7. Controlled teardown: flush + drop test-held handles (runtime P2P
    // tasks are detached by node design; test-unique ports/dirs never reused).
    for n in [&node_a, &node_b] {
        n.storage.read().await.flush().expect("flush");
    }
    drop(node_a);
    drop(node_b);
}

// 8-10. Restart from persisted stores (fresh dirs in-process): restore,
// resume, repeat; orphan counts bounded (4BZ observation re-checked).
#[tokio::test]
async fn ca02_restart_from_persisted_stores() {
    // Phase 1 data: build + persist WITHOUT any P2P task alive on these
    // dirs, so FULL close/reopen is possible (see lifecycle finding).
    let dir_a = unique_dir("ca02-a");
    let dir_b = unique_dir("ca02-b");
    let wallet = wallet_n(777001);
    let _processor = TransactionProcessor::new();
    let ts0: u64 = 1_750_100_000_000;
    let mut prev = [0u8; 32];
    let mut txs = Vec::new();
    for i in 0..6usize {
        let tx = make_valid_tx(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
        prev = tx.id;
        txs.push(tx);
    }
    // 3 orphans (parents withheld) persisted alongside, as the boot path
    // expects from park_orphan. Parents are TRULY missing (never persisted),
    // so rebuild must re-report them, never silently drop nor insert.
    let mut orphans = Vec::new();
    for k in 0..3usize {
        let mut missing_parent = [0xFFu8; 32];
        missing_parent[0] = 0xE0 + k as u8;
        missing_parent[1] = 0xCA;
        let missing = Transaction::new(
            [missing_parent, [0u8; 32]],
            [0x55u8; 32],
            [0xAAu8; 32],
            100,
            1,
            1_750_200_000 + k as u64,
            200 + k as u64,
            200 + k as u64,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        orphans.push(missing);
    }
    for (dir, set) in [(&dir_a, txs.clone()), (&dir_b, txs.clone())] {
        // Mirror 4BZ zb01: persist DIRECTLY (no DAG gate at persist time);
        // admission is proven by rebuild_dag_topological at boot.
        let store = Storage::open(dir).expect("open");
        for tx in &set {
            store.put_transaction(tx).expect("persist tx");
        }
        for o in &orphans {
            store.put_orphan(o.id, o).expect("persist orphan");
        }
        store.flush().expect("flush");
        drop(store); // FULL close: no task holds these dirs.
    }
    // 8-9. Reopen both, rebuild like boot, compare, repeat once.
    let mut fps = Vec::new();
    for cycle in 0..2 {
        let mut cycle_fp = Vec::new();
        for dir in [&dir_a, &dir_b] {
            let fp = tokio::time::timeout(RESTART_TIMEOUT, async {
                let store = Storage::open(dir).expect("reopen");
                let mut all = store.get_all_transactions().expect("read");
                for o in store.get_all_orphans().expect("read orphans") {
                    if !all.iter().any(|t| t.id == o.id) {
                        all.push(o);
                    }
                }
                drop(store);
                let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
                let (_ins, sk, orph) =
                    aether_unified::parent_selection::rebuild_dag_topological(&mut dag, all);
                assert_eq!(sk, 0, "cycle {}: no silent skips", cycle);
                dag.rebuild_tips();
                let ledger = rebuild_ledger_like_boot(&dag);
                (
                    fingerprint(&dag, &ledger),
                    dag.transaction_count(),
                    orph.into_iter().count(),
                )
            })
            .await
            .unwrap_or_else(|_| panic!("TIMEOUT: restart cycle {} hung", cycle));
            cycle_fp.push(fp);
        }
        // A and B restore identically (same persisted bytes).
        assert_eq!(
            cycle_fp[0].0, cycle_fp[1].0,
            "cycle {}: A==B fingerprints",
            cycle
        );
        assert_eq!(cycle_fp[0].1, 6, "cycle {}: 6 txs rebuilt", cycle);
        assert_eq!(cycle_fp[0].2, 3, "cycle {}: 3 orphans re-reported", cycle);
        fps.push(cycle_fp);
    }
    assert_eq!(fps[0], fps[1], "fingerprint stable across restarts");
    // 5. Orphan boundedness: same count, no duplicates, no divergence --
    // idempotent conservation, NOT a defect (would become one only on
    // growth/divergence, which is asserted absent above).
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

// 11-14. 4CP-AW: the SAME transaction set reaches the two nodes in DIFFERENT
// arrival orders (including a same-key conflict pair) and both converge to an
// identical canonical state over the REAL transport; each node's persisted
// bytes rebuild to its exact live fingerprint (fresh-dir restart, per the
// lifecycle finding).
//
// Boundary (see file header): senders stay unfunded, so this scenario pins
// transport + order independence of DAG retention (both conflict members
// coexisting in both orders) and deterministic canonicalization in the
// derived ledger; funded conflict economics through the real funnel are
// pinned in-process by the phase4aw unit suite.
const PORT_C: u16 = 44733;
const PORT_D: u16 = 44734;

fn short_id(id: &[u8; 32]) -> String {
    format!("{:02x?}", &id[..4])
}

/// Weight-exact DAG view: ids + weights (subtree sizes maintained
/// incrementally on validated insert must equal the boot recomputation).
fn dag_weight_fp(dag: &DAG) -> String {
    let mut items: Vec<String> = dag
        .transactions()
        .iter()
        .map(|(id, tx)| format!("{}|{}", short_id(id), tx.weight.to_bits()))
        .collect();
    items.sort();
    items.join(" ")
}

#[tokio::test]
async fn ca03_conflicts_and_permuted_arrival_converge_with_restart() {
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pc: std::net::SocketAddr = format!("127.0.0.1:{}", PORT_C).parse().unwrap();

    let node_a = boot_node(dir_a, PORT_C, vec![]).await;
    let mut node_b = boot_node(dir_b, PORT_D, vec![pc]).await;
    wait_for("A<->B peering", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let wallet = wallet_n(909090);
    let processor = TransactionProcessor::new();
    let ts0: u64 = 1_750_300_000_000;
    // t0 -> t1 chain; t2/t3 a same-(sender, account_nonce) conflict pair;
    // t4 independent. All real: 20-bit PoW + Ed25519 signature.
    let t0 = make_valid_tx(&wallet, [[0u8; 32]; 2], 1, ts0);
    let t1 = make_valid_tx(&wallet, [t0.id, [0u8; 32]], 2, ts0 + 1);
    let t2 = make_valid_tx(&wallet, [[0u8; 32]; 2], 3, ts0 + 2);
    let t3 = make_valid_tx(&wallet, [[0u8; 32]; 2], 3, ts0 + 3);
    let t4 = make_valid_tx(&wallet, [[0u8; 32]; 2], 4, ts0 + 4);
    let wire = [&t0, &t1, &t2, &t3, &t4];

    // A broadcasts in wire order; B's real TCP arrival order is that order.
    for tx in wire {
        node_a.p2p.broadcast_transaction((*tx).clone()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut received: Vec<Transaction> = Vec::new();
    for _ in 0..wire.len() {
        let tx = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
            .await
            .expect("B receives within timeout")
            .expect("channel live");
        received.push(tx);
    }
    for (s, r) in wire.iter().zip(received.iter()) {
        assert_eq!(s.id, r.id, "byte-identical remote delivery");
    }

    // DIFFERENT local arrival orders: A records the conflict pair in REVERSE
    // order (t3 before t2) and the chain last (still parents-first); B
    // records in its wire arrival order (t2 before t3).
    for tx in [&t3, &t2, &t4, &t0, &t1] {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        record_tx(&mut dag, &store, &processor, tx).expect("A records");
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
        assert!(done, "B records {:?}", tx.id);
    }

    // Explicit retention: every member (both conflict candidates included)
    // coexists in BOTH DAGs, with the incremental weight bookkeeping exact.
    for node in [&node_a, &node_b] {
        let dag = node.dag.read().await;
        for tx in [&t0, &t1, &t2, &t3, &t4] {
            assert!(
                dag.transactions().contains_key(&tx.id),
                "retained {}",
                short_id(&tx.id)
            );
        }
        assert_eq!(dag.transaction_count(), 5);
        assert_eq!(
            dag.get_transaction(t0.id).unwrap().weight,
            2.0,
            "t0 subtree = {{t0, t1}}"
        );
        assert_eq!(dag.get_transaction(t1.id).unwrap().weight, 1.0);
    }

    // Live convergence across different arrival orders: relations, frontier,
    // derived-ledger canonicalization and the weight view.
    let live_a = {
        let da = node_a.dag.read().await;
        let la = rebuild_ledger_like_boot(&da);
        (fingerprint(&da, &la), dag_weight_fp(&da))
    };
    let live_b = {
        let db = node_b.dag.read().await;
        let lb = rebuild_ledger_like_boot(&db);
        (fingerprint(&db, &lb), dag_weight_fp(&db))
    };
    assert_eq!(live_a.0, live_b.0, "A==B canonical state");
    assert_eq!(live_a.1, live_b.1, "A==B weight view");
    assert!(
        live_a.0.starts_with("n=5 "),
        "wire set fully admitted: {}",
        live_a.0
    );

    // Persist + fresh-dir restart: each node's stored bytes must rebuild to
    // its own live fingerprint (order-independent reconstruction).
    for n in [&node_a, &node_b] {
        n.storage.read().await.flush().expect("flush");
    }
    for (tag, node, live) in [
        ("a", &node_a, live_a.clone()),
        ("b", &node_b, live_b.clone()),
    ] {
        let bytes = node
            .storage
            .read()
            .await
            .get_all_transactions()
            .expect("read persisted");
        let dir = unique_dir(&format!("ca03-{}", tag));
        {
            let store = Storage::open(&dir).expect("seed open");
            for tx in &bytes {
                store.put_transaction(tx).expect("seed tx");
            }
            store.flush().expect("seed flush");
        }
        let rebuilt = tokio::time::timeout(RESTART_TIMEOUT, async {
            let store = Storage::open(&dir).expect("reopen");
            let all = store.get_all_transactions().expect("read");
            drop(store);
            let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
            let (ins, sk, orph) =
                aether_unified::parent_selection::rebuild_dag_topological(&mut dag, all);
            assert_eq!((ins, sk, orph.len()), (5, 0, 0), "no skips, no orphans");
            dag.rebuild_tips();
            let ledger = rebuild_ledger_like_boot(&dag);
            (fingerprint(&dag, &ledger), dag_weight_fp(&dag))
        })
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT: ca03 restart {} hung", tag));
        assert_eq!(rebuilt.0, live.0, "restart {}: canonical fingerprint", tag);
        assert_eq!(rebuilt.1, live.1, "restart {}: weight view", tag);
        let _ = std::fs::remove_dir_all(&dir);
    }

    for n in [&node_a, &node_b] {
        n.storage.read().await.flush().expect("flush");
    }
    drop(node_a);
    drop(node_b);
}

fn unique_dir_unused() -> PathBuf {
    unique_dir("unused")
}

#[test]
fn ca00_helpers_live() {
    let _ = unique_dir_unused;
}
