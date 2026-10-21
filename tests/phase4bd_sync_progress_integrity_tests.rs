//! PHASE 4CP-BD: sync progress integrity over the real P2P ingress and the
//! production mempool/drainer path.

use aether_unified::genesis::GENESIS_HASH;
use aether_unified::ledger::Ledger;
use aether_unified::p2p::{
    IngressTx, P2PConfig, P2PMessage, P2PNetwork, P2PProtocolMode, P2P_PROTOCOL_VERSION,
    TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::parent_selection::DAG;
use aether_unified::rpc::{AetherRpcImpl, Mempool};
use aether_unified::storage::Storage;
use aether_unified::sync_stats::{FrontierSnapshot, PageState, SyncContext};
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::transport::{
    BoxFuture, PeerAddr, TcpTransport, Transport, TransportError, TransportListener,
    TransportStream,
};
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use x25519_dalek::{EphemeralSecret, PublicKey};

const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;

struct RejectAllTransport;

impl Transport for RejectAllTransport {
    fn dial(&self, _addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
        Box::pin(async move {
            Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "4BD test transport: outbound dial refused",
            )))
        })
    }
    fn bind(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>> {
        let transport = TcpTransport::new();
        let endpoint = *addr;
        Box::pin(async move { transport.bind(&endpoint).await })
    }
}

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn historical_tx(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    tag: u64,
    amount: u64,
    fee: u64,
    account_nonce: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        [0xB4u8; 32],
        amount,
        fee,
        Transaction::DIFFICULTY_MIGRATION_TS - 3_600_000 + tag,
        account_nonce,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_hash());
    assert!(
        TransactionProcessor::new()
            .validate_pure(&tx, ValidationMode::Historical)
            .is_ok(),
        "fixture must pass the Historical pure gate"
    );
    tx
}

fn corrupt_signature(tx: &Transaction) -> Transaction {
    let mut bad = tx.clone();
    bad.signature[0] ^= 0x80;
    bad.id = bad.compute_hash();
    assert!(bad.verify_hash(), "corrupted id must stay wire-compatible");
    assert!(
        TransactionProcessor::new()
            .validate_pure(&bad, ValidationMode::Historical)
            .is_err(),
        "fixture must fail the pure gate"
    );
    bad
}

fn nonce_bytes(counter: u64, dir: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n[8] = dir;
    n
}

fn wire_frame(key: &[u8; 32], dir: u8, counter: u64, padded: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_bytes(counter, dir);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), padded)
        .expect("seal");
    let total_len = 12 + ciphertext.len();
    assert_eq!(total_len % 256, 0, "frame must be bucket-aligned");
    let mut out = Vec::with_capacity(4 + total_len);
    out.extend_from_slice(&(total_len as u32).to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

fn pad_payload(payload: &[u8]) -> Vec<u8> {
    let unpadded = 30 + payload.len();
    let pad = (256 - (unpadded % 256)) % 256;
    let mut padded = Vec::with_capacity(payload.len() + pad + 2);
    padded.extend_from_slice(payload);
    padded.resize(payload.len() + pad, 0u8);
    padded.extend_from_slice(&(pad as u16).to_le_bytes());
    padded
}

struct RawPeer {
    writer: tokio::net::tcp::OwnedWriteHalf,
    _reader: tokio::net::tcp::OwnedReadHalf,
    key: [u8; 32],
    dir: u8,
    counter: u64,
}

impl RawPeer {
    async fn connect(port: u16) -> Self {
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await
        .expect("raw connect must not hang")
        .expect("raw connect");
        let (mut reader, mut writer) = stream.into_split();

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut outgoing = Vec::with_capacity(HANDSHAKE_LEN);
        outgoing.extend_from_slice(&WIRE_MAGIC);
        outgoing.push(P2P_PROTOCOL_VERSION);
        outgoing.extend_from_slice(&GENESIS_HASH);
        outgoing.extend_from_slice(&DEFAULT_NETWORK_ID.to_le_bytes());
        outgoing.extend_from_slice(public.as_bytes());
        writer.write_all(&outgoing).await.expect("hs write");

        let mut incoming = [0u8; HANDSHAKE_LEN];
        tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut incoming))
            .await
            .expect("server handshake reply must not hang")
            .expect("server handshake reply");
        let mut peer_pk = [0u8; 32];
        peer_pk.copy_from_slice(&incoming[HANDSHAKE_LEN - 32..]);
        let shared = secret.diffie_hellman(&PublicKey::from(peer_pk));
        let mut hasher = Sha256::new();
        hasher.update(b"aether-p2p-key-v1");
        hasher.update(shared.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        let dir = if public.as_bytes() < &peer_pk {
            0x01
        } else {
            0x02
        };
        Self {
            writer,
            _reader: reader,
            key,
            dir,
            counter: 0,
        }
    }

    async fn send(&mut self, msg: &P2PMessage) {
        let payload = bincode::serialize(msg).expect("serialize");
        let padded = pad_payload(&payload);
        self.counter += 1;
        let frame = wire_frame(&self.key, self.dir, self.counter, &padded);
        self.writer.write_all(&frame).await.expect("frame write");
    }
}

struct Node {
    net: Arc<P2PNetwork>,
    dag: Arc<RwLock<DAG>>,
    ledger: Arc<RwLock<Ledger>>,
    storage: Arc<RwLock<Storage>>,
    orphans: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    rpc: Arc<AetherRpcImpl>,
    sync_ctx: Arc<SyncContext>,
    consumer: tokio::task::JoinHandle<()>,
}

async fn boot_node(port: u16, dir: &std::path::Path) -> Node {
    let storage = Arc::new(RwLock::new(
        Storage::open(dir.join("sled")).expect("open sled"),
    ));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let ledger = Arc::new(RwLock::new(
        Ledger::new_with_storage(storage.clone())
            .await
            .expect("ledger"),
    ));
    let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
    let orphans: Arc<RwLock<HashMap<[u8; 32], Transaction>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let sync_ctx = Arc::new(SyncContext::default());
    let (tx_sender, mut tx_receiver) = mpsc::channel::<IngressTx>(TX_INGRESS_CAPACITY_MSGS);

    let dag_hashes = dag.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        dag_hashes
            .try_read()
            .map(|g| g.transactions().keys().map(|id| id.to_vec()).collect())
            .unwrap_or_default()
    });
    let dag_tx = dag.clone();
    let get_tx: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
        Arc::new(move |hash: &[u8]| {
            let id = <[u8; 32]>::try_from(hash).ok()?;
            dag_tx.try_read().ok()?.transactions().get(&id).cloned()
        });
    let tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| Vec::new());
    let orphans_lookup = orphans.clone();
    let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(move |hash: &[u8]| {
        let Ok(id) = <[u8; 32]>::try_from(hash) else {
            return false;
        };
        orphans_lookup
            .try_read()
            .map(|o| o.contains_key(&id))
            .unwrap_or(false)
    });

    let net = Arc::new(P2PNetwork::new_with_transport(
        P2PConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: DEFAULT_NETWORK_ID,
        },
        tx_sender,
        get_hashes,
        get_tx,
        tips,
        sync_ctx.clone(),
        is_orphan,
        Arc::new(RejectAllTransport),
    ));
    net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    tokio::time::timeout(Duration::from_secs(20), net.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds");

    let rpc = Arc::new(AetherRpcImpl::new(
        dag.clone(),
        ledger.clone(),
        storage.clone(),
        dir.join("ledger.json"),
        mempool.clone(),
        net.clone(),
        Arc::new(RwLock::new(true)),
        orphans.clone(),
        sync_ctx.clone(),
    ));

    let consumer_rpc = rpc.clone();
    let consumer_ctx = sync_ctx.clone();
    let consumer = tokio::spawn(async move {
        while let Some(item) = tx_receiver.recv().await {
            let tx = item.into_tx();
            let mode = consumer_ctx.take_ingress_mode(tx.id).await;
            match consumer_rpc.process_transaction(tx, "P2P", mode).await {
                Ok(_) => {
                    consumer_rpc.process_orphans().await;
                }
                Err(_) => {}
            }
        }
    });

    Node {
        net,
        dag,
        ledger,
        storage,
        orphans,
        rpc,
        sync_ctx,
        consumer,
    }
}

async fn shutdown(node: Node) {
    node.consumer.abort();
    let _ = tokio::time::timeout(Duration::from_secs(30), node.net.shutdown()).await;
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
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT waiting for: {}", what));
}

async fn wait_state(node: &Node, id: &[u8; 32], want: PageState) {
    wait_for(
        &format!("frontier state {:?}", want),
        Duration::from_secs(15),
        || async { node.sync_ctx.frontier.read().await.entry_state(id) == Some(want) },
    )
    .await;
}

async fn wait_not_requested(node: &Node, id: &[u8; 32]) -> PageState {
    wait_for(
        "SyncResponse disposition",
        Duration::from_secs(15),
        || async {
            matches!(
                node.sync_ctx.frontier.read().await.entry_state(id),
                Some(PageState::Received) | Some(PageState::Applied) | Some(PageState::Rejected)
            )
        },
    )
    .await;
    node.sync_ctx
        .frontier
        .read()
        .await
        .entry_state(id)
        .expect("tracked")
}

async fn request(node: &Node, peer: &mut RawPeer, ids: &[&[u8; 32]]) {
    let hashes = ids.iter().map(|id| id.to_vec()).collect();
    peer.send(&P2PMessage::Inventory(hashes)).await;
    for id in ids {
        wait_state(node, id, PageState::Requested).await;
    }
}

async fn send_sync(peer: &mut RawPeer, txs: &[&Transaction]) {
    let items = txs
        .iter()
        .map(|tx| bincode::serialize(*tx).expect("tx bytes"))
        .collect();
    peer.send(&P2PMessage::SyncResponse(items)).await;
}

async fn frontier_snapshot(node: &Node) -> FrontierSnapshot {
    node.sync_ctx.frontier.read().await.snapshot()
}

fn sync_progress(node: &Node) -> u64 {
    node.sync_ctx.stats.sync_progress.load(Ordering::Relaxed)
}

async fn fund(node: &Node, wallet: &Wallet, amount: u64) {
    node.ledger
        .write()
        .await
        .set_balance(&wallet.address(), amount);
}

// ---------------------------------------------------------------------------
// bd01 - a queued sync tx is Received, never Applied before the DAG insertion.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bd01_queued_sync_tx_is_not_applied_before_dag_insertion() {
    const PORT: u16 = 44921;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path()).await;
    let wallet = wallet_n(4_000_001);
    fund(&node, &wallet, 1_000_000).await;
    let tx = historical_tx(&wallet, [[0u8; 32]; 2], 1, 1000, 10, 1);
    let mut peer = RawPeer::connect(PORT).await;

    request(&node, &mut peer, &[&tx.id]).await;
    send_sync(&mut peer, &[&tx]).await;
    let state = wait_not_requested(&node, &tx.id).await;

    wait_for("mempool admission", Duration::from_secs(15), || async {
        node.rpc.mempool_stats().await.added == 1
    })
    .await;

    assert_eq!(
        state,
        PageState::Received,
        "queued sync data must not be presented as Applied"
    );
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Received),
        "the state must remain Received until the drainer inserts into the DAG"
    );
    assert_eq!(
        sync_progress(&node),
        0,
        "queue admission is not DAG progress"
    );
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 0);
    assert_eq!(node.sync_ctx.stats.sync_frontier.load(Ordering::Relaxed), 0);
    assert_eq!(node.dag.read().await.transaction_count(), 0);

    node.rpc.drain_mempool().await;

    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Applied)
    );
    assert_eq!(sync_progress(&node), 1);
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 1);
    assert_eq!(node.sync_ctx.stats.sync_frontier.load(Ordering::Relaxed), 1);
    assert_eq!(node.dag.read().await.transaction_count(), 1);

    drop(peer);
    shutdown(node).await;
}

// ---------------------------------------------------------------------------
// bd02 - invalid sync data reaches Rejected and never Applied.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bd02_invalid_sync_tx_is_never_applied() {
    const PORT: u16 = 44922;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path()).await;
    let wallet = wallet_n(4_000_002);
    let tx = corrupt_signature(&historical_tx(&wallet, [[0u8; 32]; 2], 2, 1000, 1, 1));
    let mut peer = RawPeer::connect(PORT).await;

    request(&node, &mut peer, &[&tx.id]).await;
    send_sync(&mut peer, &[&tx]).await;
    wait_state(&node, &tx.id, PageState::Rejected).await;
    wait_for("pure rejection", Duration::from_secs(15), || async {
        node.rpc.mempool_stats().await.rejected == 1
    })
    .await;

    assert_eq!(node.rpc.mempool_stats().await.added, 0);
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 0);

    node.rpc.drain_mempool().await;

    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Rejected)
    );
    assert_eq!(sync_progress(&node), 0);
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 0);
    assert!(frontier_snapshot(&node).await.pages_rejected >= 1);
    assert_eq!(node.dag.read().await.transaction_count(), 0);
    assert!(node
        .storage
        .read()
        .await
        .get_all_transactions()
        .expect("read all")
        .is_empty());

    drop(peer);
    shutdown(node).await;
}

// ---------------------------------------------------------------------------
// bd03 - a mixed batch is classified per item, not as a whole.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bd03_mixed_batch_applies_only_the_valid_item() {
    const PORT: u16 = 44923;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path()).await;
    let funded = wallet_n(4_000_003);
    let unfunded = wallet_n(4_000_004);
    fund(&node, &funded, 1_000_000).await;
    let valid = historical_tx(&funded, [[0u8; 32]; 2], 3, 1000, 10, 1);
    let invalid = corrupt_signature(&historical_tx(&unfunded, [[0u8; 32]; 2], 4, 1000, 1, 1));
    let mut peer = RawPeer::connect(PORT).await;

    request(&node, &mut peer, &[&valid.id, &invalid.id]).await;
    send_sync(&mut peer, &[&valid, &invalid]).await;
    let valid_state = wait_not_requested(&node, &valid.id).await;
    wait_state(&node, &invalid.id, PageState::Rejected).await;
    wait_for("one queue admission", Duration::from_secs(15), || async {
        node.rpc.mempool_stats().await.added == 1
    })
    .await;

    assert_eq!(valid_state, PageState::Received);
    assert_eq!(sync_progress(&node), 0);

    node.rpc.drain_mempool().await;

    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&valid.id),
        Some(PageState::Applied)
    );
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&invalid.id),
        Some(PageState::Rejected)
    );
    let dag = node.dag.read().await;
    assert_eq!(dag.transaction_count(), 1);
    assert!(dag.get_transaction(valid.id).is_some());
    assert!(dag.get_transaction(invalid.id).is_none());
    drop(dag);
    assert_eq!(sync_progress(&node), 1);
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 1);
    assert_eq!(frontier_snapshot(&node).await.pages_rejected, 1);

    drop(peer);
    shutdown(node).await;
}

// ---------------------------------------------------------------------------
// bd04 - a child whose parent is absent stays unapplied, then recovers.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bd04_partial_batch_waits_and_recovers_without_false_apply() {
    const PORT: u16 = 44924;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path()).await;
    let wallet = wallet_n(4_000_005);
    fund(&node, &wallet, 1_000_000).await;
    let parent = historical_tx(&wallet, [[0u8; 32]; 2], 5, 1000, 10, 1);
    let child = historical_tx(&wallet, [parent.id, [0u8; 32]], 6, 500, 1, 2);
    let mut peer = RawPeer::connect(PORT).await;

    request(&node, &mut peer, &[&child.id]).await;
    send_sync(&mut peer, &[&child]).await;
    wait_for(
        "first SyncResponse recorded",
        Duration::from_secs(15),
        || async { node.sync_ctx.stats.snapshot().sync_received >= 1 },
    )
    .await;
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&child.id),
        Some(PageState::Requested)
    );
    assert_eq!(node.rpc.mempool_stats().await.added, 0);
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 0);

    request(&node, &mut peer, &[&parent.id]).await;
    send_sync(&mut peer, &[&parent, &child]).await;
    let parent_state = wait_not_requested(&node, &parent.id).await;
    let child_state = wait_not_requested(&node, &child.id).await;
    wait_for("two queue admissions", Duration::from_secs(15), || async {
        node.rpc.mempool_stats().await.added == 2
    })
    .await;

    assert_eq!(parent_state, PageState::Received);
    assert_eq!(child_state, PageState::Received);
    assert_eq!(sync_progress(&node), 0);

    node.rpc.drain_mempool().await;

    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&parent.id),
        Some(PageState::Applied)
    );
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&child.id),
        Some(PageState::Applied)
    );
    let dag = node.dag.read().await;
    assert_eq!(dag.transaction_count(), 2);
    assert!(dag.get_transaction(parent.id).is_some());
    assert!(dag.get_transaction(child.id).is_some());
    drop(dag);
    assert_eq!(sync_progress(&node), 2);
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 2);

    drop(peer);
    shutdown(node).await;
}

// ---------------------------------------------------------------------------
// bd05 - duplicate responses: DAG duplicate may resolve, orphan duplicate may not.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bd05_duplicate_of_orphan_is_not_presented_as_applied() {
    const PORT: u16 = 44925;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path()).await;
    let wallet = wallet_n(4_000_006);
    let known = historical_tx(&wallet, [[0u8; 32]; 2], 7, 1000, 10, 1);
    let orphan = historical_tx(&wallet, [[0x55u8; 32], [0u8; 32]], 8, 1000, 1, 2);

    node.dag
        .write()
        .await
        .add_transaction_validated(known.clone())
        .expect("seed DAG");
    node.sync_ctx
        .frontier
        .write()
        .await
        .add_pending(known.id.to_vec());
    node.sync_ctx
        .frontier
        .write()
        .await
        .mark_requested(&known.id, "10.0.0.1:25565".parse().unwrap());
    let mut peer = RawPeer::connect(PORT).await;

    node.orphans.write().await.insert(orphan.id, orphan.clone());

    node.sync_ctx
        .frontier
        .write()
        .await
        .add_pending(orphan.id.to_vec());
    node.sync_ctx
        .frontier
        .write()
        .await
        .mark_requested(&orphan.id, "10.0.0.1:25565".parse().unwrap());

    send_sync(&mut peer, &[&known, &orphan]).await;
    wait_for(
        "both duplicate dispositions",
        Duration::from_secs(15),
        || async { frontier_snapshot(&node).await.pages_received == 2 },
    )
    .await;

    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&known.id),
        Some(PageState::Applied),
        "a DAG duplicate is already applied"
    );
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&orphan.id),
        Some(PageState::Received),
        "an orphan duplicate is tracked but not applied"
    );
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 1);
    assert_eq!(sync_progress(&node), 0);
    assert_eq!(
        node.rpc.mempool_stats().await.added,
        0,
        "a duplicate must not be admitted"
    );
    assert_eq!(node.dag.read().await.transaction_count(), 1);

    drop(peer);
    shutdown(node).await;
}

// ---------------------------------------------------------------------------
// bd06 - peer disconnect requeues the request; a new session can complete it.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bd06_disconnect_requeues_without_false_apply_and_session_recovers() {
    const PORT: u16 = 44926;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path()).await;
    let wallet = wallet_n(4_000_007);
    fund(&node, &wallet, 1_000_000).await;
    let tx = historical_tx(&wallet, [[0u8; 32]; 2], 9, 1000, 10, 1);

    let mut peer = RawPeer::connect(PORT).await;
    request(&node, &mut peer, &[&tx.id]).await;
    drop(peer);
    wait_for("peer removal", Duration::from_secs(15), || async {
        node.net.peer_count().await == 0
    })
    .await;
    wait_state(&node, &tx.id, PageState::Pending).await;
    assert_eq!(frontier_snapshot(&node).await.pages_applied, 0);
    assert_eq!(sync_progress(&node), 0);
    assert_eq!(node.dag.read().await.transaction_count(), 0);

    let mut peer = RawPeer::connect(PORT).await;
    request(&node, &mut peer, &[&tx.id]).await;
    send_sync(&mut peer, &[&tx]).await;
    assert_eq!(wait_not_requested(&node, &tx.id).await, PageState::Received);
    wait_for("mempool admission", Duration::from_secs(15), || async {
        node.rpc.mempool_stats().await.added == 1
    })
    .await;

    node.rpc.drain_mempool().await;

    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Applied)
    );
    assert_eq!(sync_progress(&node), 1);
    assert_eq!(node.dag.read().await.transaction_count(), 1);

    drop(peer);
    shutdown(node).await;
}
