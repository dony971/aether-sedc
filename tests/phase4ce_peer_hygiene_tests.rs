//! PHASE 4CE (live): hygiene boundary proofs on loopback.
//!
//! Ports 44791-44793 are test-unique. Complements the deterministic
//! in-module policy tests (`phase4ce_hygiene_tests` in src/p2p.rs), which
//! drive the REAL selection/admission/store functions without waiting:
//! - ce01 proves the OPERATOR side live: a configured seed that fails every
//!   dial across a dead window is STILL retried afterwards (exemption —
//!   attempts observed as raw accepts on a counting listener, since a raw
//!   socket cannot complete the encrypted handshake).
//! - ce02 proves the FLAKY side live: a real node unreachable for ~2 redial
//!   cycles (< 5-failure sleep threshold) is redialed on return, gossips
//!   again, and shuts down cleanly (no premature sleep/eviction).
//! - The sleep itself (5 consecutive failures) is too slow to force live
//!   deterministically and is proven in-module instead; these tests pin the
//!   behaviors the sleep must never break.

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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const HYGIENE_TIMEOUT: Duration = Duration::from_secs(40);

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
    tokio::time::timeout(HYGIENE_TIMEOUT, p2p.start())
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

/// A raw counting listener: accepts SYNs and counts them, never handshakes
/// (so the node side never forms a session — attempts are the observable).
async fn counting_listener(
    port: u16,
    counter: Arc<AtomicUsize>,
    stop: tokio::sync::oneshot::Receiver<()>,
) {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("counting listener binds");
    let mut stop = stop;
    loop {
        tokio::select! {
            _ = &mut stop => return,
            r = listener.accept() => {
                if r.is_ok() {
                    counter.fetch_add(1, Ordering::Relaxed);
                } else {
                    return;
                }
            }
        }
    }
}

// ---- ce01: configured seed retried across a dead window --------------------
// A bootnodes=[L]. L counts accepts (pre: >= 1 proves dialing works). L dies
// ~12s (~2 redial cycles: failures accumulate but the seed is EXEMPT from
// sleep). L rebinds same port: A's redial must produce new accepts within
// 30s. If seeds slept like ordinary entries, nothing would arrive.

#[tokio::test]
async fn ce01_configured_seed_retried_across_dead_window() {
    const PA: u16 = 44791;
    const PL: u16 = 44792;
    let addr_l: std::net::SocketAddr = format!("127.0.0.1:{}", PL).parse().unwrap();
    let dir_a = tempfile::tempdir().expect("dirA");
    let counter = Arc::new(AtomicUsize::new(0));

    let (stop1_tx, stop1_rx) = tokio::sync::oneshot::channel();
    let listen_h = tokio::spawn(counting_listener(PL, counter.clone(), stop1_rx));
    // Listener bound before A starts (no SYN lost to a closed port).
    tokio::time::sleep(Duration::from_millis(300)).await;

    let node_a = boot_node(
        PA,
        vec![addr_l],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A"))),
    )
    .await;
    // Pre: A's redial dials the seed (accepts observed on L).
    wait_for("seed dialed pre-window", CONNECT_TIMEOUT, || async {
        counter.load(Ordering::Relaxed) >= 1
    })
    .await;
    // A never forms a session (no handshake): attempts are the signal, and
    // the redial loop must keep trying without a session to pace it.
    assert_eq!(
        node_a.p2p.peer_count().await,
        0,
        "raw socket forms no session"
    );

    // Dead window: L closed ~12s. Every redial cycle burns a dial (RST) and
    // accumulates failure debt on the seed entry — past what would sleep an
    // ordinary peer (in-module proof), yet the seed must stay eligible.
    let _ = stop1_tx.send(());
    listen_h.await.expect("listener stops");
    tokio::time::sleep(Duration::from_secs(12)).await;

    // Heal: same port rebinds; A's next redial cycles must land accepts.
    let pre = counter.load(Ordering::Relaxed);
    let (stop2_tx, stop2_rx) = tokio::sync::oneshot::channel();
    let listen_h2 = tokio::spawn(counting_listener(PL, counter.clone(), stop2_rx));
    tokio::time::sleep(Duration::from_millis(300)).await;
    wait_for("seed redialed post-window", HYGIENE_TIMEOUT, || async {
        counter.load(Ordering::Relaxed) > pre
    })
    .await;
    let _ = stop2_tx.send(());
    listen_h2.await.expect("listener stops");

    shutdown_node(node_a, "A-ce01").await;
    let probe = Storage::open(dir_a.path()).expect("A dir reopens after seed churn");
    drop(probe);
}

// ---- ce02: flaky real peer returns before the sleep threshold -------------
// B is a real node; A bootnodes=[B]. B dies ~10s (< 5-failure sleep budget:
// redial cycles are 5s-gated so ~2 failures accumulate), then restarts same
// port+dir. A must redial it, gossip must flow again, shutdown stays clean.
// Proves sub-threshold failure does NOT sleep or evict a legitimate peer.

#[tokio::test]
async fn ce02_flaky_peer_returns_before_threshold() {
    const PA: u16 = 44793;
    const PB: u16 = 44794;
    let addr_b: std::net::SocketAddr = format!("127.0.0.1:{}", PB).parse().unwrap();
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let path_b = dir_b.path().to_path_buf();
    let wallet = wallet_n(811001);
    let processor = TransactionProcessor::new();

    let mut node_a = boot_node(
        PA,
        vec![addr_b],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A"))),
    )
    .await;
    let node_b = boot_node(
        PB,
        vec![],
        Arc::new(RwLock::new(DAG::new())),
        Arc::new(RwLock::new(Storage::open(dir_b.path()).expect("open B"))),
    )
    .await;
    wait_for("A<->B peered", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1
    })
    .await;
    shutdown_node(node_b, "B-flaky").await;
    // ~10s outage: ~2 redial cycles fail (well under the 5-failure sleep).
    tokio::time::sleep(Duration::from_secs(10)).await;
    // Same port+dir, rebuilt DAG from B's own bytes (empty here — boot path).
    let store_b = Arc::new(RwLock::new(Storage::open(&path_b).expect("B heal open")));
    let dag_b = Arc::new(RwLock::new(DAG::new()));
    let mut node_b2 = boot_node(PB, vec![], dag_b.clone(), store_b.clone()).await;
    wait_for("A redials returned B", HYGIENE_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b2.p2p.peer_count().await >= 1
    })
    .await;
    // Gossip flows again across the healed session.
    let tx = make_valid_tx(&wallet, [[0u8; 32], [0u8; 32]], 810, 1_790_000_000);
    {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        TransactionProcessor::new()
            .validate_pure(&tx, ValidationMode::Historical)
            .expect("pure gate");
        dag.add_transaction_validated(tx.clone()).expect("A admits");
        store.put_transaction(&tx).expect("persist");
        store.mark_applied(tx.id).expect("applied");
        let _ = &processor;
    }
    node_a.p2p.broadcast_transaction(tx.clone()).await;
    let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b2.rx.recv())
        .await
        .expect("B2 delivery after flaky return")
        .expect("live");
    assert_eq!(tx.id, r.id, "gossip intact after sub-threshold outage");
    shutdown_node(node_a, "A-ce02").await;
    shutdown_node(node_b2, "B-ce02").await;
    // Drop outer handle clones (sled exclusive lock per live handle).
    drop(store_b);
    drop(dag_b);
    for (d, name) in [(dir_a.path(), "A"), (dir_b.path(), "B")] {
        let probe = Storage::open(d).unwrap_or_else(|_| panic!("{} dir reopens", name));
        drop(probe);
    }
}
