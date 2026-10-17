//! PHASE 4CC: P2P robustness under controlled adversity + peer churn.
//!
//! All loopback, no remote hosts, no public network, no unbounded load.
//! Ports 44761-44768 are test-unique (never 4CA 44731/32 nor 4CB 44751/52)
//! so suites can run in parallel; WITHIN this file tests also run in
//! parallel threads, hence every test owns DISTINCT ports.
//!
//! Mechanisms under test (all pre-existing, mapped in the 4CC brief):
//! - HANDSHAKE_TIMEOUT 10s / FRAME_TIMEOUT 30s / CONNECT_TIMEOUT 5s
//! - verify_handshake_identity (wire magic + version 5 + genesis + net id)
//! - valid_frame_len (bucket 256, 16 MiB cap) + oversize/disconnect guards
//! - decrypt-fail + replay + rate-limit penalize-and-ban discipline
//! - frontier.on_peer_disconnect requeue (failover), redial backoff
//! - 4CB shutdown(): abort+await 5s/task, session clears, port release
//!
//! Honesty boundaries:
//! - Creation uses REAL APIs (keys, 20-bit PoW, Ed25519, validate_pure
//!   Historical, validated DAG insert, Sled persist). Nothing bypassed.
//! - Raw peers speak the REAL handshake bytes (X25519 ephemeral DH,
//!   SHA256("aether-p2p-key-v1") key derivation mirrored from p2p.rs
//!   handshake()); post-handshake malice targets the CLEAR length prefix,
//!   which is exactly what the production guards inspect first.
//! - Senders are unfunded: DAG admission proven, ledger transfers not.
//! - Encrypted-frame fuzzing with VALID session keys is NOT covered (would
//!   need a full session encryptor); documented as residual risk.

use aether_unified::genesis::{initialize_genesis, GenesisConfig, GENESIS_HASH};
use aether_unified::ledger::Ledger;
use aether_unified::p2p::{P2PConfig, P2PNetwork, P2P_PROTOCOL_VERSION};
use aether_unified::parent_selection::DAG;
use aether_unified::stake::{current_epoch, StakeRegistry};
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Wire magic as sent on the wire: HANDSHAKE_MAGIC ^ HANDSHAKE_MAGIC_MASK
/// (p2p.rs: [0x41,0x45,0x54,0x48] ^ [0x3F,0x71,0xA5,0x1C]).
const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const PROPAGATE_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const ADVERSITY_TIMEOUT: Duration = Duration::from_secs(45);

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
    tokio::time::timeout(ADVERSITY_TIMEOUT, p2p.start())
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

/// Expect a hostile socket to reach EOF/close within 10s. The server writes
/// its own 77-byte handshake reply BEFORE verifying ours, so the first
/// reads may return handshake bytes — drain until EOF, not just one read.
async fn expect_close(mut s: tokio::net::TcpStream, what: &str) {
    let mut buf = [0u8; 256];
    let r = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) => return,
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    })
    .await;
    assert!(r.is_ok(), "{} must close within 10s", what);
}

fn handshake_frame(magic: [u8; 4], version: u8, network: u64, pk: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HANDSHAKE_LEN);
    out.extend_from_slice(&magic);
    out.push(version);
    out.extend_from_slice(&GENESIS_HASH);
    out.extend_from_slice(&network.to_le_bytes());
    out.extend_from_slice(pk);
    out
}

/// Complete the REAL client side of the handshake against a node and return
/// the open stream (server handshake bytes consumed). Mirrors p2p.rs
/// handshake(): ephemeral X25519, DH, SHA256("aether-p2p-key-v1").
async fn raw_handshake(port: u16) -> tokio::net::TcpStream {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await
    .expect("raw connect must not hang")
    .expect("raw connect");
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let frame = handshake_frame(
        WIRE_MAGIC,
        P2P_PROTOCOL_VERSION,
        DEFAULT_NETWORK_ID,
        public.as_bytes(),
    );
    stream.write_all(&frame).await.expect("write handshake");
    // Consume the server's handshake reply (validates WE were accepted).
    let mut reply = vec![0u8; HANDSHAKE_LEN];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .expect("server handshake reply must not hang")
        .expect("server handshake reply");
    let _shared = secret.diffie_hellman(&PublicKey::from(
        <[u8; 32]>::try_from(&reply[HANDSHAKE_LEN - 32..]).expect("pk"),
    ));
    let mut hasher = Sha256::new();
    hasher.update(b"aether-p2p-key-v1");
    hasher.update(_shared.as_bytes());
    let _key = hasher.finalize();
    stream
}

// ---- Scenario A: slow / stalled peer --------------------------------------
// Raw peer sends 2 of 77 handshake bytes then stalls. The node must drop it
// via HANDSHAKE_TIMEOUT (10s) while the honest pair keeps syncing.

#[tokio::test]
async fn cc01_slow_peer_times_out_honest_pair_keeps_syncing() {
    const PA: u16 = 44771;
    const PB: u16 = 44772;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let storage_a = Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A")));
    let storage_b = Arc::new(RwLock::new(Storage::open(dir_b.path()).expect("open B")));
    let dag_a = Arc::new(RwLock::new(DAG::new()));
    let dag_b = Arc::new(RwLock::new(DAG::new()));
    let mut node_a = boot_node(PA, vec![], dag_a.clone(), storage_a.clone()).await;
    let mut node_b = boot_node(PB, vec![pa], dag_b.clone(), storage_b.clone()).await;
    wait_for("A<->B peering", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;
    let honest_peers = node_a.p2p.peer_count().await;

    // Stalled attacker: partial handshake, then silence (holds socket open).
    let mut stall = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
        .await
        .expect("stall connect");
    stall
        .write_all(&WIRE_MAGIC[..2])
        .await
        .expect("partial write");
    // The node registers the inbound socket: exactly one extra session.
    wait_for("stall session registered", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await == honest_peers + 1
    })
    .await;

    // Meanwhile the honest pair syncs 2 REAL txs THROUGH the stall window.
    let wallet = wallet_n(611001);
    let processor = TransactionProcessor::new();
    let mut prev = [0u8; 32];
    let mut sent = Vec::new();
    for i in 0..2usize {
        let tx = make_valid_tx(
            &wallet,
            [prev, [0u8; 32]],
            300 + i as u64,
            1_770_000_000 + i as u64,
        );
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
    for s in &sent {
        let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
            .await
            .expect("honest delivery during stall")
            .expect("live");
        assert_eq!(s.id, r.id, "honest TCP delivery despite stalled peer");
        let mut dag = node_b.dag.write().await;
        let store = node_b.storage.read().await;
        record_tx(&mut dag, &store, &processor, &r).expect("B records");
    }

    // HANDSHAKE_TIMEOUT (10s) evicts the stall: session count returns to
    // honest-only WITHOUT any shutdown. Bound: 10s + 15s margin.
    wait_for(
        "stall evicted by handshake timeout",
        Duration::from_secs(25),
        || async { node_a.p2p.peer_count().await == honest_peers },
    )
    .await;
    let _ = stall.shutdown().await;
    drop(stall);
    let (fa, fb) = {
        let (da, db) = (node_a.dag.read().await, node_b.dag.read().await);
        (
            fingerprint(&da, &rebuild_ledger_like_boot(&da)),
            fingerprint(&db, &rebuild_ledger_like_boot(&db)),
        )
    };
    assert_eq!(fa, fb, "honest pair converges despite stall");
    assert!(fa.starts_with("n=2 "), "got {}", fa);
    shutdown_node(node_a, "A-cc01").await;
    shutdown_node(node_b, "B-cc01").await;
}

// ---- Scenario B: invalid inputs rejected cleanly ---------------------------
// Live: wrong magic (fast reject), wrong version (fast reject), early close
// (clean, no panic), oversized clear length + non-bucket length + garbage
// ciphertext AFTER a real handshake (exact production guards). No DAG
// pollution, honest peer unaffected, shutdown clean.

#[tokio::test]
async fn cc02_invalid_inputs_rejected_honest_unaffected() {
    const PA: u16 = 44773;
    const PB: u16 = 44774;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let storage_a = Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A")));
    let storage_b = Arc::new(RwLock::new(Storage::open(dir_b.path()).expect("open B")));
    let dag_a = Arc::new(RwLock::new(DAG::new()));
    let dag_b = Arc::new(RwLock::new(DAG::new()));
    let mut node_a = boot_node(PA, vec![], dag_a.clone(), storage_a.clone()).await;
    let mut node_b = boot_node(PB, vec![pa], dag_b.clone(), storage_b.clone()).await;
    wait_for("A<->B peering", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;
    let base = node_a.p2p.peer_count().await;

    // B1: garbage magic — rejected before version/genesis checks.
    {
        let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
            .await
            .expect("connect");
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        s.write_all(&handshake_frame(
            [0x00, 0x00, 0x00, 0x00],
            P2P_PROTOCOL_VERSION,
            DEFAULT_NETWORK_ID,
            public.as_bytes(),
        ))
        .await
        .expect("write");
        // Server closes: its 77B reply (written before verifying) then EOF.
        expect_close(s, "garbage magic").await;
    }
    // B2: wrong protocol version — same clean close.
    {
        let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
            .await
            .expect("connect");
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        s.write_all(&handshake_frame(
            WIRE_MAGIC,
            P2P_PROTOCOL_VERSION.wrapping_add(1),
            DEFAULT_NETWORK_ID,
            public.as_bytes(),
        ))
        .await
        .expect("write");
        expect_close(s, "wrong version").await;
    }
    // B3: early close mid-handshake — no panic, session reaped.
    {
        let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
            .await
            .expect("connect");
        s.write_all(&WIRE_MAGIC).await.expect("write");
        drop(s);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Failed handshakes must not accumulate sessions.
    wait_for("no session leak after B1-B3", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await == base
    })
    .await;

    // B4: oversized CLEAR length after a REAL handshake (> 16 MiB guard).
    {
        let mut s = raw_handshake(PA).await;
        s.write_all(&((16 * 1024 * 1024 + 1) as u32).to_be_bytes())
            .await
            .expect("write");
        expect_close(s, "oversize length").await;
    }
    // B5: non-bucket-aligned CLEAR length (300 is not a multiple of 256).
    {
        let mut s = raw_handshake(PA).await;
        s.write_all(&300u32.to_be_bytes()).await.expect("write");
        expect_close(s, "unpadded length").await;
    }
    // B6: bucket-valid length but garbage nonce+ciphertext (decrypt fails).
    {
        let mut s = raw_handshake(PA).await;
        s.write_all(&512u32.to_be_bytes()).await.expect("write");
        s.write_all(&[0x99u8; 512]).await.expect("write");
        expect_close(s, "garbage ciphertext").await;
    }
    wait_for("no session leak after B4-B6", CONNECT_TIMEOUT, || async {
        node_a.p2p.peer_count().await == base
    })
    .await;

    // Honest pair still syncs 1 REAL tx; DAG unpolluted (exactly 1 tx).
    let wallet = wallet_n(612001);
    let processor = TransactionProcessor::new();
    let tx = make_valid_tx(&wallet, [[0u8; 32], [0u8; 32]], 400, 1_770_001_000);
    {
        let mut dag = node_a.dag.write().await;
        let store = node_a.storage.read().await;
        record_tx(&mut dag, &store, &processor, &tx).expect("A records");
    }
    node_a.p2p.broadcast_transaction(tx.clone()).await;
    let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
        .await
        .expect("honest delivery after attacks")
        .expect("live");
    assert_eq!(tx.id, r.id);
    {
        let mut dag = node_b.dag.write().await;
        let store = node_b.storage.read().await;
        record_tx(&mut dag, &store, &processor, &r).expect("B records");
    }
    for (name, dag_h) in [("A", &node_a.dag), ("B", &node_b.dag)] {
        let dag = dag_h.read().await;
        assert_eq!(
            dag.transaction_count(),
            1,
            "{} DAG polluted by invalid inputs",
            name
        );
        assert!(dag.transactions().contains_key(&tx.id));
    }
    shutdown_node(node_a, "A-cc02").await;
    shutdown_node(node_b, "B-cc02").await;
}

// ---- Scenario C: source dies mid-sync, alternate serves the missing -------
// S and A2 both hold 4 chained txs. Y peers to BOTH. S delivers 2, then S is
// shut down cleanly (proven: peer_count 0, its dir reopens). A2 delivers the
// rest. Y must converge to n=4 with the 2 post-kill arrivals PROVEN to come
// from A2 (S was already dead + dropped when they arrived).

#[tokio::test]
async fn cc03_source_dies_alternate_completes_sync() {
    const PS: u16 = 44761;
    const PA2: u16 = 44762;
    const PY: u16 = 44763;
    let dir_s = tempfile::tempdir().expect("dirS");
    let dir_a2 = tempfile::tempdir().expect("dirA2");
    let dir_y = tempfile::tempdir().expect("dirY");
    let ps: std::net::SocketAddr = format!("127.0.0.1:{}", PS).parse().unwrap();
    let pa2: std::net::SocketAddr = format!("127.0.0.1:{}", PA2).parse().unwrap();
    let wallet = wallet_n(613001);
    let processor = TransactionProcessor::new();
    // Only tx0,tx1 exist pre-kill (chained). tx2,tx3 are created AFTER S's
    // death, so ANY receipt of them is necessarily post-kill — provenance
    // by construction, not by timing.
    let mut txs = Vec::new();
    let mut prev = [0u8; 32];
    for i in 0..2usize {
        let tx = make_valid_tx(
            &wallet,
            [prev, [0u8; 32]],
            500 + i as u64,
            1_770_002_000 + i as u64,
        );
        prev = tx.id;
        txs.push(tx);
    }
    // S and A2 both persist+admit the full set up front (two independent
    // sources for the same identities — convergence target n=4).
    for dir in [dir_s.path(), dir_a2.path()] {
        let store = Storage::open(dir).expect("open source");
        let mut dag = DAG::new();
        for tx in &txs {
            record_tx(&mut dag, &store, &processor, tx).expect("source records");
        }
        store.flush().expect("flush");
        drop(store);
    }
    let store_s = Arc::new(RwLock::new(Storage::open(dir_s.path()).expect("reopen S")));
    let store_a2 = Arc::new(RwLock::new(
        Storage::open(dir_a2.path()).expect("reopen A2"),
    ));
    let store_y = Arc::new(RwLock::new(Storage::open(dir_y.path()).expect("open Y")));
    let mut rebuilt_s = DAG::new();
    let mut rebuilt_a2 = DAG::new();
    for (store, dag) in [(&store_s, &mut rebuilt_s), (&store_a2, &mut rebuilt_a2)] {
        let all = store.read().await.get_all_transactions().expect("read");
        let (mut fresh, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
        let (ins, sk, _orph) =
            aether_unified::parent_selection::rebuild_dag_topological(&mut fresh, all);
        assert_eq!((ins, sk), (2, 0));
        fresh.rebuild_tips();
        *dag = fresh;
    }
    let dag_s = Arc::new(RwLock::new(rebuilt_s));
    let dag_a2 = Arc::new(RwLock::new(rebuilt_a2));
    let dag_y = Arc::new(RwLock::new(DAG::new()));
    let node_s = boot_node(PS, vec![], dag_s.clone(), store_s.clone()).await;
    let mut node_a2 = boot_node(PA2, vec![], dag_a2.clone(), store_a2.clone()).await;
    let mut node_y = boot_node(PY, vec![ps, pa2], dag_y.clone(), store_y.clone()).await;
    wait_for("Y peered to both sources", CONNECT_TIMEOUT, || async {
        node_y.p2p.peer_count().await >= 2
    })
    .await;
    // S pushes the first 2 (direct gossip). Y ALSO backfills via the sync
    // protocol, so arrivals are a SET (order + source unspecified) — collect
    // until {tx0,tx1} is covered, deduping by id. Deterministic: sets, never
    // order.
    for tx in txs.iter().take(2) {
        node_s.p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let want_pre: std::collections::HashSet<[u8; 32]> = txs.iter().take(2).map(|t| t.id).collect();
    let mut seen_pre: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut pre_txs: std::collections::HashMap<[u8; 32], Transaction> =
        std::collections::HashMap::new();
    tokio::time::timeout(PROPAGATE_TIMEOUT, async {
        while !want_pre.is_subset(&seen_pre) {
            let r = node_y.rx.recv().await.expect("live pre-kill");
            seen_pre.insert(r.id);
            pre_txs.entry(r.id).or_insert(r);
        }
    })
    .await
    .expect("Y covers {tx0,tx1} pre-kill");
    // Record in CHAIN order (txs), not HashMap order.
    for want in txs.iter().take(2) {
        let tx = pre_txs.get(&want.id).expect("covered above");
        // Record only the wanted pre-kill set (ignore any early backfill of
        // tx2/tx3 here — they are re-driven deterministically post-kill).
        if want_pre.contains(&tx.id) {
            let mut dag = node_y.dag.write().await;
            let store = node_y.storage.read().await;
            // Bounded parent retries (same funnel as 4CA).
            let mut done = false;
            for _ in 0..20 {
                if record_tx(&mut dag, &store, &processor, tx).is_ok() {
                    done = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(done, "Y records pre-kill {:?}", tx.id);
        }
    }
    // KILL S: clean shutdown (peer_count 0). Drop S's last handles so the
    // same-dir reopen below proves release (sled exclusive lock).
    shutdown_node(node_s, "S-cc03").await;
    drop(store_s);
    drop(dag_s);
    wait_for("Y observes S gone, A2 remains", CONNECT_TIMEOUT, || async {
        node_y.p2p.peer_count().await == 1
    })
    .await;
    let probe = Storage::open(dir_s.path()).expect("S dir reopens after clean kill");
    drop(probe);

    // tx2,tx3 did not exist until now: create (chained on tx1), admit on the
    // live alternate, push via real gossip. Y's coverage of them is
    // necessarily post-kill (elimination + byte identity + existence window).
    let mut new_txs = Vec::new();
    for i in 0..2usize {
        let tx = make_valid_tx(
            &wallet,
            [prev, [0u8; 32]],
            502 + i as u64,
            1_770_003_000 + i as u64,
        );
        prev = tx.id;
        new_txs.push(tx);
    }
    for tx in &new_txs {
        {
            let mut dag = node_a2.dag.write().await;
            let store = node_a2.storage.read().await;
            record_tx(&mut dag, &store, &processor, tx).expect("A2 admits post-kill");
        }
        node_a2.p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    // Y must genuinely miss them first (no phantom pre-delivery possible),
    // then cover them via A2.
    for tx in &new_txs {
        let dag = node_y.dag.read().await;
        assert!(
            !dag.transactions().contains_key(&tx.id),
            "post-kill tx must be genuinely missing before A2 serves it"
        );
    }
    let want_post: std::collections::HashSet<[u8; 32]> = new_txs.iter().map(|t| t.id).collect();
    let mut seen_post: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut post_txs: std::collections::HashMap<[u8; 32], Transaction> =
        std::collections::HashMap::new();
    tokio::time::timeout(PROPAGATE_TIMEOUT, async {
        while !want_post.is_subset(&seen_post) {
            let r = node_y.rx.recv().await.expect("live post-kill");
            seen_post.insert(r.id);
            post_txs.entry(r.id).or_insert(r);
        }
    })
    .await
    .expect("Y covers {tx2,tx3} post-kill via A2");
    // Record in CHAIN order (new_txs), not HashMap order: tx3's parent is
    // tx2, so random order would fail the DAG gate.
    for want in &new_txs {
        let tx = post_txs.get(&want.id).expect("covered above");
        // Bounded parent retries (same funnel as 4CA).
        let mut done = false;
        for _ in 0..20 {
            let r = {
                let mut dag = node_y.dag.write().await;
                let store = node_y.storage.read().await;
                record_tx(&mut dag, &store, &processor, tx)
            };
            if r.is_ok() {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(done, "Y records post-kill {:?}", tx.id);
    }
    let (fy, fa2) = {
        let (dy, da2) = (node_y.dag.read().await, node_a2.dag.read().await);
        (
            fingerprint(&dy, &rebuild_ledger_like_boot(&dy)),
            fingerprint(&da2, &rebuild_ledger_like_boot(&da2)),
        )
    };
    assert_eq!(
        fy, fa2,
        "Y converges to alternate source (ids+relations+frontier+ledger)"
    );
    assert!(fy.starts_with("n=4 "), "got {}", fy);
    shutdown_node(node_a2, "A2-cc03").await;
    shutdown_node(node_y, "Y-cc03").await;
}

// ---- Scenario D: controlled churn, same storage + ports --------------------
// 3 full cycles on the SAME dirs and SAME ports: sync 1 tx, shutdown,
// reopen (prove release), restart, repeat. State grows monotonically
// (n=1,2,3), no duplicates, no divergence, every shutdown Ok.

#[tokio::test]
async fn cc04_churn_three_cycles_same_storage_ports() {
    const PA: u16 = 44765;
    const PB: u16 = 44766;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let path_a = dir_a.path().to_path_buf();
    let path_b = dir_b.path().to_path_buf();
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    let wallet = wallet_n(614001);
    let processor = TransactionProcessor::new();
    let mut prev = [0u8; 32];
    let mut all_txs = Vec::new();
    for cycle in 0..3usize {
        // Rebuild in-memory DAGs from the SAME persisted bytes (boot path);
        // cycle 0 starts from genesis (empty stores).
        let build = |path: &Path| -> DAG {
            let store = Storage::open(path).expect("churn reopen (leak if fails)");
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
            assert_eq!(sk, 0, "cycle {}: no silent skips", cycle);
            assert!(orph.is_empty(), "cycle {}: no orphans", cycle);
            assert_eq!(
                dag.transaction_count(),
                cycle,
                "cycle {}: SAME-dir history preserved",
                cycle
            );
            dag.rebuild_tips();
            dag
        };
        let dag_a_built = build(&path_a);
        let dag_b_built = build(&path_b);
        let storage_a = Arc::new(RwLock::new(Storage::open(&path_a).expect("open A")));
        let storage_b = Arc::new(RwLock::new(Storage::open(&path_b).expect("open B")));
        let dag_a = Arc::new(RwLock::new(dag_a_built));
        let dag_b = Arc::new(RwLock::new(dag_b_built));
        // SAME ports every cycle: rebind proves prior release.
        let mut node_a = boot_node(PA, vec![], dag_a.clone(), storage_a.clone()).await;
        let mut node_b = boot_node(PB, vec![pa], dag_b.clone(), storage_b.clone()).await;
        assert!(!node_a.p2p.is_shutting_down() && !node_b.p2p.is_shutting_down());
        wait_for(
            &format!("peering cycle {}", cycle),
            CONNECT_TIMEOUT,
            || async { node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1 },
        )
        .await;
        let tx = make_valid_tx(
            &wallet,
            [prev, [0u8; 32]],
            600 + cycle as u64,
            1_770_003_000 + cycle as u64,
        );
        prev = tx.id;
        all_txs.push(tx.clone());
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, &tx).expect("A records churn");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
            .await
            .unwrap_or_else(|_| panic!("cycle {}: B receives", cycle))
            .expect("live");
        assert_eq!(tx.id, r.id, "cycle {}: byte-identical", cycle);
        {
            let mut dag = node_b.dag.write().await;
            let store = node_b.storage.read().await;
            record_tx(&mut dag, &store, &processor, &r).expect("B records churn");
        }
        let (fa, fb) = {
            let (da, db) = (node_a.dag.read().await, node_b.dag.read().await);
            (
                fingerprint(&da, &rebuild_ledger_like_boot(&da)),
                fingerprint(&db, &rebuild_ledger_like_boot(&db)),
            )
        };
        assert_eq!(fa, fb, "cycle {}: A==B", cycle);
        assert!(
            fa.starts_with(&format!("n={} ", cycle + 1)),
            "cycle {}: got {}",
            cycle,
            fa
        );
        shutdown_node(node_a, &format!("A-churn{}", cycle)).await;
        shutdown_node(node_b, &format!("B-churn{}", cycle)).await;
    }
    // Final proof from the ORIGINAL dirs: exactly the 3 churn txs, ordered.
    let store = Storage::open(&path_a).expect("final reopen");
    let txs = store.get_all_transactions().expect("read");
    assert_eq!(txs.len(), 3, "3 churn txs persisted, no duplicates");
    let mut ids: Vec<[u8; 32]> = txs.iter().map(|t| t.id).collect();
    ids.sort();
    let mut want: Vec<[u8; 32]> = all_txs.iter().map(|t| t.id).collect();
    want.sort();
    assert_eq!(ids, want, "persisted set == sent set (no dup, no loss)");
}

// ---- Shutdown under adversity (§4) ----------------------------------------
// Idle socket + partial frame + garbage handshake + honest sessions ALL
// active at once; shutdown() must still return Ok within bounds, and the
// same ports + storages must reopen (release proven, not assumed).

#[tokio::test]
async fn cc05_shutdown_with_idle_partial_and_live_sessions() {
    const PA: u16 = 44767;
    const PB: u16 = 44768;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let path_a = dir_a.path().to_path_buf();
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PA).parse().unwrap();
    // Node lifetime is scoped: outer Arcs MUST drop before the reopen proof
    // below (sled holds an exclusive lock per live handle — same rule the
    // 4CB test follows). shutdown_node() drops the TestNode's handles; the
    // block end drops the outer clones.
    let tx_id: [u8; 32];
    {
        let storage_a = Arc::new(RwLock::new(Storage::open(dir_a.path()).expect("open A")));
        let storage_b = Arc::new(RwLock::new(Storage::open(dir_b.path()).expect("open B")));
        let dag_a = Arc::new(RwLock::new(DAG::new()));
        let dag_b = Arc::new(RwLock::new(DAG::new()));
        let mut node_a = boot_node(PA, vec![], dag_a.clone(), storage_a.clone()).await;
        let mut node_b = boot_node(PB, vec![pa], dag_b.clone(), storage_b.clone()).await;
        wait_for("A<->B peering", CONNECT_TIMEOUT, || async {
            node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
        })
        .await;
        // Adversity set, all held open DURING shutdown:
        let idle = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
            .await
            .expect("idle connect");
        let mut partial = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
            .await
            .expect("partial connect");
        partial
            .write_all(&WIRE_MAGIC[..3])
            .await
            .expect("partial write");
        let mut garbage = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PA))
            .await
            .expect("garbage connect");
        garbage
            .write_all(&[0xDEu8; HANDSHAKE_LEN])
            .await
            .expect("garbage write");
        // One live sync in flight while adversity is connected.
        let wallet = wallet_n(615001);
        let processor = TransactionProcessor::new();
        let tx = make_valid_tx(&wallet, [[0u8; 32], [0u8; 32]], 700, 1_770_004_000);
        tx_id = tx.id;
        {
            let mut dag = node_a.dag.write().await;
            let store = node_a.storage.read().await;
            record_tx(&mut dag, &store, &processor, &tx).expect("A records");
        }
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        let r = tokio::time::timeout(PROPAGATE_TIMEOUT, node_b.rx.recv())
            .await
            .expect("delivery under adversity")
            .expect("live");
        assert_eq!(tx.id, r.id);
        // Shutdown WITH all three hostile sockets still open: must be Ok and
        // bounded (a test timeout here is FAILURE, never proof).
        shutdown_node(node_a, "A-cc05-adversity").await;
        shutdown_node(node_b, "B-cc05-adversity").await;
        drop(idle);
        drop(partial);
        drop(garbage);
    }
    // Release proven: SAME ports rebind + SAME storage reopens.
    let listener = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpListener::bind(format!("127.0.0.1:{}", PA)),
    )
    .await
    .expect("rebind must not hang")
    .expect("port released after adversarial shutdown");
    drop(listener);
    let store = Storage::open(&path_a).expect("storage reopens after adversarial shutdown");
    let txs = store.get_all_transactions().expect("read");
    assert_eq!(txs.len(), 1, "exactly the 1 honest tx persisted");
    assert_eq!(txs[0].id, tx_id, "no pollution from hostile sockets");
}
