//! PHASE 4CP-BE: end-to-end transaction lifecycle and cross-layer coherence.

use aether_unified::genesis::{initialize_genesis, GenesisConfig, GENESIS_HASH};
use aether_unified::ledger::{Ledger, FEE_BURN_ADDRESS};
use aether_unified::p2p::{
    IngressTx, P2PConfig, P2PMessage, P2PNetwork, P2PProtocolMode, P2P_PROTOCOL_VERSION,
    TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::parent_selection::{rebuild_dag_topological, DAG};
use aether_unified::rpc::{AetherRpcImpl, Mempool};
use aether_unified::storage::Storage;
use aether_unified::sync_stats::{PageState, SyncContext};
use aether_unified::transaction::{Transaction, TransactionId, DEFAULT_NETWORK_ID};
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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use x25519_dalek::{EphemeralSecret, PublicKey};

const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;
const WAIT: Duration = Duration::from_secs(20);

struct RejectAllTransport;

impl Transport for RejectAllTransport {
    fn dial(&self, _addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
        Box::pin(async move {
            Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "4BE test transport: outbound dial refused",
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
        Transaction::DIFFICULTY_MIGRATION_TS - 7_200_000 + tag,
        account_nonce,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_hash());
    assert!(TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Historical)
        .is_ok());
    tx
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn live_tx(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    amount: u64,
    fee: u64,
    account_nonce: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        [0xA7u8; 32],
        amount,
        fee,
        now_ms().saturating_sub(5_000),
        account_nonce,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(24);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_hash());
    assert!(TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Fresh)
        .is_ok());
    tx
}

fn corrupt_signature(tx: &Transaction) -> Transaction {
    let mut bad = tx.clone();
    bad.signature[0] ^= 0x80;
    bad.id = bad.compute_hash();
    assert!(bad.verify_hash());
    assert!(TransactionProcessor::new()
        .validate_pure(&bad, ValidationMode::Historical)
        .is_err());
    bad
}

fn nonce_bytes(counter: u64, dir: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n[8] = dir;
    n
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

fn wire_frame(key: &[u8; 32], dir: u8, counter: u64, padded: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_bytes(counter, dir);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), padded)
        .expect("seal");
    let total_len = 12 + ciphertext.len();
    assert_eq!(total_len % 256, 0);
    let mut out = Vec::with_capacity(4 + total_len);
    out.extend_from_slice(&(total_len as u32).to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
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
    mempool: Arc<RwLock<Mempool>>,
    orphans: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    rpc: Arc<AetherRpcImpl>,
    sync_ctx: Arc<SyncContext>,
    ingested: Arc<AtomicU64>,
    consumer: tokio::task::JoinHandle<()>,
}

async fn open_store(path: &Path) -> Storage {
    const MAX_ATTEMPTS: u32 = 60;
    for attempt in 1..=MAX_ATTEMPTS {
        match Storage::open(path) {
            Ok(store) => return store,
            Err(e) => {
                let msg = e.to_string();
                let locked = msg.contains("could not acquire lock")
                    || msg.contains("Resource temporarily unavailable");
                if locked && attempt < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                panic!("open sled {:?} failed: {}", path, e);
            }
        }
    }
    unreachable!()
}

async fn boot_with_state(
    port: u16,
    storage: Arc<RwLock<Storage>>,
    dag: Arc<RwLock<DAG>>,
    ledger: Arc<RwLock<Ledger>>,
    mempool: Arc<RwLock<Mempool>>,
    orphans: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
) -> Node {
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
    let tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(Vec::new);
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
    tokio::time::timeout(WAIT, net.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds");

    let rpc = Arc::new(AetherRpcImpl::new(
        dag.clone(),
        ledger.clone(),
        storage.clone(),
        PathBuf::new().join("ledger.json"),
        mempool.clone(),
        net.clone(),
        Arc::new(RwLock::new(true)),
        orphans.clone(),
        sync_ctx.clone(),
    ));

    let ingested = Arc::new(AtomicU64::new(0));
    let consumer_rpc = rpc.clone();
    let consumer_ctx = sync_ctx.clone();
    let consumer_ingested = ingested.clone();
    let consumer = tokio::spawn(async move {
        while let Some(item) = tx_receiver.recv().await {
            let tx = item.into_tx();
            let mode = consumer_ctx.take_ingress_mode(tx.id).await;
            match consumer_rpc.process_transaction(tx, "P2P", mode).await {
                Ok(_) => consumer_rpc.process_orphans().await,
                Err(_) => {}
            }
            consumer_ingested.fetch_add(1, Ordering::Relaxed);
        }
    });

    Node {
        net,
        dag,
        ledger,
        storage,
        mempool,
        orphans,
        rpc,
        sync_ctx,
        ingested,
        consumer,
    }
}

async fn boot_node(port: u16, dir: &Path, mempool_capacity: usize) -> Node {
    let storage = Arc::new(RwLock::new(open_store(&dir.join("sled")).await));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let ledger = Arc::new(RwLock::new(
        Ledger::new_with_storage(storage.clone())
            .await
            .expect("ledger"),
    ));
    let mempool = Arc::new(RwLock::new(Mempool::new(mempool_capacity, 10)));
    let orphans = Arc::new(RwLock::new(HashMap::new()));
    boot_with_state(port, storage, dag, ledger, mempool, orphans).await
}

async fn reboot_node(port: u16, dir: &Path, mempool_capacity: usize) -> Node {
    let storage = Arc::new(RwLock::new(open_store(&dir.join("sled")).await));
    let persisted_txs = storage
        .read()
        .await
        .get_all_transactions()
        .expect("read persisted txs");
    let persisted_orphans = storage
        .read()
        .await
        .get_all_orphans()
        .expect("read persisted orphans");

    let (mut dag, _balances, _orphans, _missing) = initialize_genesis(GenesisConfig::default());
    let mut all = persisted_txs;
    for orphan in &persisted_orphans {
        if !all.iter().any(|tx| tx.id == orphan.id) {
            all.push(orphan.clone());
        }
    }
    let (_inserted, skipped, orphaned) = rebuild_dag_topological(&mut dag, all);
    dag.rebuild_tips();

    let mut ledger = Ledger::new_with_storage(storage.clone())
        .await
        .expect("ledger reload");
    let persisted_supply = ledger.total_supply();
    let mut orphan_map: HashMap<[u8; 32], Transaction> =
        orphaned.into_iter().map(|tx| (tx.id, tx)).collect();
    if skipped == 0 && orphan_map.is_empty() {
        let mut derived = ledger.clone();
        derived.rebuild_from_dag(&dag);
        if persisted_supply == 0 || derived.total_supply() <= persisted_supply {
            ledger = derived;
            let _ = ledger.save().await;
        }
    }
    for orphan in persisted_orphans {
        orphan_map.entry(orphan.id).or_insert(orphan);
    }

    let mut mempool = Mempool::new(mempool_capacity, 10);
    {
        let stored = storage
            .read()
            .await
            .load_mempool_txs()
            .expect("read persisted mempool");
        let dag_ids: BTreeSet<TransactionId> = dag.transactions().keys().copied().collect();
        for tx in stored {
            if !dag_ids.contains(&tx.id) {
                mempool.enqueue(tx, 0).expect("reload mempool");
            }
        }
    }

    boot_with_state(
        port,
        storage,
        Arc::new(RwLock::new(dag)),
        Arc::new(RwLock::new(ledger)),
        Arc::new(RwLock::new(mempool)),
        Arc::new(RwLock::new(orphan_map)),
    )
    .await
}

async fn shutdown(node: Node) {
    let Node {
        consumer,
        net,
        storage,
        ..
    } = node;
    consumer.abort();
    let _ = consumer.await;
    let _ = tokio::time::timeout(Duration::from_secs(30), net.shutdown()).await;
    let _ = storage.read().await.flush();
}

async fn wait_for<F, Fut>(what: &str, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(WAIT, async {
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

async fn wait_ingested(node: &Node, want: u64) {
    wait_for(&format!("{} ingested", want), || async {
        node.ingested.load(Ordering::Relaxed) == want
    })
    .await;
}

async fn wait_state(node: &Node, id: &[u8; 32], want: PageState) {
    wait_for(&format!("frontier {:?}", want), || async {
        node.sync_ctx.frontier.read().await.entry_state(id) == Some(want)
    })
    .await;
}

async fn wait_peer(node: &Node) {
    wait_for("peer connected", || async { node.net.peer_count().await == 1 }).await;
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

async fn gossip(peer: &mut RawPeer, tx: &Transaction) {
    peer.send(&P2PMessage::Transaction(
        bincode::serialize(tx).expect("tx bytes"),
    ))
    .await;
}

async fn fund(node: &Node, wallet: &Wallet, amount: u64) {
    node.ledger
        .write()
        .await
        .set_balance(&wallet.address(), amount);
}

async fn baseline(node: &Node) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    let ledger = node.ledger.read().await;
    (
        ledger.balances.clone().into_iter().collect(),
        ledger.nonces.clone().into_iter().collect(),
    )
}

async fn drain_until(node: &Node, dag_txs: usize, max_cycles: usize) {
    for _ in 0..max_cycles {
        node.rpc.drain_mempool().await;
        let dag_count = node.dag.read().await.transaction_count();
        let queue = node.mempool.read().await.size();
        if dag_count == dag_txs && queue == 0 {
            return;
        }
    }
    let dag_count = node.dag.read().await.transaction_count();
    let queue = node.mempool.read().await.size();
    panic!(
        "drain did not converge: dag={} queue={} wanted dag={}",
        dag_count, queue, dag_txs
    );
}

async fn assert_lifecycle(
    node: &Node,
    base: &(BTreeMap<String, u64>, BTreeMap<String, u64>),
    applied: &[Transaction],
    queued: &[Transaction],
    orphans: &[Transaction],
    rejected: &[Transaction],
    tracked: &[(TransactionId, PageState)],
) {
    let dag_ids: BTreeSet<TransactionId> =
        node.dag.read().await.transactions().keys().copied().collect();
    let applied_ids: BTreeSet<TransactionId> =
        node.ledger.read().await.applied.iter().copied().collect();
    let queue_ids: BTreeSet<TransactionId> = node
        .mempool
        .read()
        .await
        .get_transaction_ids()
        .into_iter()
        .collect();
    let orphan_ids: BTreeSet<TransactionId> =
        node.orphans.read().await.keys().copied().collect();
    let persisted_ids: BTreeSet<TransactionId> = node
        .storage
        .read()
        .await
        .get_all_transactions()
        .expect("read txs")
        .into_iter()
        .map(|tx| tx.id)
        .collect();
    let persisted_mempool: BTreeSet<TransactionId> = node
        .storage
        .read()
        .await
        .load_mempool_txs()
        .expect("read mempool")
        .into_iter()
        .map(|tx| tx.id)
        .collect();
    let persisted_orphans: BTreeSet<TransactionId> = node
        .storage
        .read()
        .await
        .get_all_orphans()
        .expect("read orphans")
        .into_iter()
        .map(|tx| tx.id)
        .collect();

    let expect_applied: BTreeSet<TransactionId> = applied.iter().map(|tx| tx.id).collect();
    let expect_queued: BTreeSet<TransactionId> = queued.iter().map(|tx| tx.id).collect();
    let expect_orphans: BTreeSet<TransactionId> = orphans.iter().map(|tx| tx.id).collect();

    assert_eq!(dag_ids, expect_applied, "DAG membership drift");
    assert_eq!(applied_ids, expect_applied, "ledger applied-set drift");
    assert_eq!(persisted_ids, expect_applied, "persisted tx-set drift");
    assert_eq!(queue_ids, expect_queued, "mempool queue drift");
    assert_eq!(
        persisted_mempool, expect_queued,
        "persisted mempool drift"
    );
    assert_eq!(orphan_ids, expect_orphans, "orphan memory drift");
    assert_eq!(
        persisted_orphans, expect_orphans,
        "persisted orphan drift"
    );

    for id in &expect_applied {
        assert!(!expect_queued.contains(id), "tx both applied and queued");
        assert!(!expect_orphans.contains(id), "tx both applied and orphan");
    }
    for id in &expect_queued {
        assert!(!expect_orphans.contains(id), "tx both queued and orphan");
    }

    for tx in rejected {
        assert!(!dag_ids.contains(&tx.id), "rejected tx is in DAG");
        assert!(!applied_ids.contains(&tx.id), "rejected tx is applied");
        assert!(!persisted_ids.contains(&tx.id), "rejected tx is persisted");
        assert!(!queue_ids.contains(&tx.id), "rejected tx is queued");
        assert!(!orphan_ids.contains(&tx.id), "rejected tx is an orphan");
    }

    {
        let frontier = node.sync_ctx.frontier.read().await;
        for (id, want) in tracked {
            let got = frontier.entry_state(id);
            assert_eq!(got, Some(*want), "frontier state for {}", hex::encode(&id[..4]));
        }
    }

    let mut expected_balances: BTreeMap<String, u64> = base.0.clone();
    let mut expected_nonces = base.1.clone();
    let burn_hex = hex::encode(FEE_BURN_ADDRESS);
    for tx in applied {
        let sender = hex::encode(tx.sender);
        let receiver = hex::encode(tx.receiver);
        let debit = tx.amount + tx.fee;
        let sender_balance = expected_balances.get_mut(&sender).expect("sender balance");
        *sender_balance = sender_balance
            .checked_sub(debit)
            .expect("fixture cannot overdraw");
        *expected_balances.entry(receiver).or_insert(0) += tx.amount;
        *expected_balances.entry(burn_hex.clone()).or_insert(0) += tx.fee;
        let nonce = expected_nonces.entry(sender).or_insert(0);
        *nonce = (*nonce).max(tx.account_nonce);
    }

    let ledger = node.ledger.read().await;
    let actual_balances: BTreeMap<String, u64> = ledger.balances.clone().into_iter().collect();
    let actual_nonces: BTreeMap<String, u64> = ledger.nonces.clone().into_iter().collect();
    assert_eq!(
        actual_balances, expected_balances,
        "balances are not the independent replay"
    );
    assert_eq!(
        actual_nonces, expected_nonces,
        "nonces are not the independent replay"
    );
    let expected_supply: u64 = expected_balances
        .iter()
        .filter(|(addr, _)| **addr != burn_hex)
        .map(|(_, balance)| *balance)
        .sum();
    assert_eq!(
        ledger.total_supply(),
        expected_supply,
        "supply does not follow fee burns"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn be01_child_before_parent_parks_then_resolves_exactly_once() {
    const PORT: u16 = 44931;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path(), 100).await;
    let wallet = wallet_n(5_000_001);
    fund(&node, &wallet, 2_000_000).await;
    let base = baseline(&node).await;
    let parent = live_tx(&wallet, [[0u8; 32]; 2], 1_000, 10, 1);
    let child = live_tx(&wallet, [parent.id, [0u8; 32]], 500, 5, 2);

    let mut peer = RawPeer::connect(PORT).await;
    wait_peer(&node).await;
    gossip(&mut peer, &child).await;
    wait_ingested(&node, 1).await;
    wait_for("child queued", || async {
        node.mempool.read().await.size() == 1
    })
    .await;

    node.rpc.drain_mempool().await;
    assert_eq!(node.mempool.read().await.size(), 0);
    assert!(node.orphans.read().await.contains_key(&child.id));
    assert_eq!(node.dag.read().await.transaction_count(), 0);

    gossip(&mut peer, &parent).await;
    wait_ingested(&node, 2).await;
    drain_until(&node, 2, 6).await;

    assert_lifecycle(
        &node,
        &base,
        &[parent.clone(), child.clone()],
        &[],
        &[],
        &[],
        &[],
    )
    .await;

    drop(peer);
    shutdown(node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn be02_three_sources_one_identity_one_application() {
    const PORT: u16 = 44932;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path(), 100).await;
    let wallet = wallet_n(5_000_002);
    fund(&node, &wallet, 2_000_000).await;
    let base = baseline(&node).await;
    let tx = live_tx(&wallet, [[0u8; 32]; 2], 1_000, 10, 1);

    let mut peer = RawPeer::connect(PORT).await;
    wait_peer(&node).await;
    request(&node, &mut peer, &[&tx.id]).await;
    gossip(&mut peer, &tx).await;
    wait_ingested(&node, 1).await;
    wait_for("gossip queued", || async {
        node.mempool.read().await.size() == 1
    })
    .await;
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Received)
    );

    let rpc_dup = node
        .rpc
        .process_transaction(tx.clone(), "RPC", ValidationMode::Fresh)
        .await;
    assert!(rpc_dup.is_err(), "RPC duplicate must not be re-queued");

    send_sync(&mut peer, &[&tx]).await;
    wait_ingested(&node, 2).await;

    node.rpc.drain_mempool().await;

    assert_lifecycle(
        &node,
        &base,
        &[tx.clone()],
        &[],
        &[],
        &[],
        &[(tx.id, PageState::Applied)],
    )
    .await;
    assert_eq!(node.rpc.mempool_stats().await.added, 1);
    assert_eq!(node.rpc.mempool_stats().await.included, 1);
    assert_eq!(node.sync_ctx.stats.sync_progress.load(Ordering::Relaxed), 1);

    drop(peer);
    shutdown(node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn be03_saturation_is_transient_and_retry_reaches_applied() {
    const PORT: u16 = 44933;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path(), 1).await;
    let wallet_a = wallet_n(5_000_003);
    let wallet_b = wallet_n(5_000_004);
    fund(&node, &wallet_a, 2_000_000).await;
    fund(&node, &wallet_b, 2_000_000).await;
    let base = baseline(&node).await;
    let first = historical_tx(&wallet_a, [[0u8; 32]; 2], 3, 1_000, 10, 1);
    let second = historical_tx(&wallet_b, [[0u8; 32]; 2], 4, 1_000, 9, 1);

    let mut peer = RawPeer::connect(PORT).await;
    wait_peer(&node).await;
    request(&node, &mut peer, &[&first.id, &second.id]).await;
    send_sync(&mut peer, &[&first, &second]).await;
    wait_ingested(&node, 2).await;
    wait_for("one admitted and one refused", || async {
        let stats = node.rpc.mempool_stats().await;
        stats.added == 1 && stats.rejected == 1
    })
    .await;

    node.rpc.drain_mempool().await;
    assert_eq!(node.dag.read().await.transaction_count(), 1);
    assert!(node.dag.read().await.get_transaction(first.id).is_some());

    peer.send(&P2PMessage::Inventory(vec![second.id.to_vec()]))
        .await;
    send_sync(&mut peer, &[&second]).await;
    wait_ingested(&node, 3).await;

    drain_until(&node, 2, 4).await;

    assert_lifecycle(
        &node,
        &base,
        &[first.clone(), second.clone()],
        &[],
        &[],
        &[],
        &[
            (first.id, PageState::Applied),
            (second.id, PageState::Applied),
        ],
    )
    .await;
    assert_eq!(node.rpc.mempool_stats().await.added, 2);

    drop(peer);
    shutdown(node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn be04_partial_sync_waits_then_dependency_closes_the_page() {
    const PORT: u16 = 44934;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path(), 100).await;
    let wallet = wallet_n(5_000_005);
    fund(&node, &wallet, 2_000_000).await;
    let base = baseline(&node).await;
    let parent = historical_tx(&wallet, [[0u8; 32]; 2], 5, 1_000, 10, 1);
    let child = historical_tx(&wallet, [parent.id, [0u8; 32]], 6, 500, 5, 2);

    let mut peer = RawPeer::connect(PORT).await;
    wait_peer(&node).await;
    request(&node, &mut peer, &[&child.id]).await;
    send_sync(&mut peer, &[&child]).await;
    wait_for("child response observed", || async {
        node.sync_ctx.stats.snapshot().sync_received >= 1
    })
    .await;
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&child.id),
        Some(PageState::Requested)
    );
    assert_eq!(node.mempool.read().await.size(), 0);
    assert_eq!(node.dag.read().await.transaction_count(), 0);

    request(&node, &mut peer, &[&parent.id]).await;
    send_sync(&mut peer, &[&parent, &child]).await;
    wait_ingested(&node, 2).await;
    drain_until(&node, 2, 4).await;

    assert_lifecycle(
        &node,
        &base,
        &[parent.clone(), child.clone()],
        &[],
        &[],
        &[],
        &[
            (parent.id, PageState::Applied),
            (child.id, PageState::Applied),
        ],
    )
    .await;
    assert_eq!(node.sync_ctx.stats.sync_progress.load(Ordering::Relaxed), 2);

    drop(peer);
    shutdown(node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn be05_restart_keeps_received_not_applied_then_redelivery_converges() {
    const PORT: u16 = 44935;
    const RESTART_PORT: u16 = 44936;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path(), 100).await;
    let wallet = wallet_n(5_000_006);
    fund(&node, &wallet, 2_000_000).await;
    node.ledger.write().await.save().await.expect("save ledger");
    let tx = historical_tx(&wallet, [[0u8; 32]; 2], 7, 1_000, 10, 1);

    let mut peer = RawPeer::connect(PORT).await;
    wait_peer(&node).await;
    request(&node, &mut peer, &[&tx.id]).await;
    send_sync(&mut peer, &[&tx]).await;
    wait_ingested(&node, 1).await;
    wait_for("tx admitted before restart", || async {
        node.mempool.read().await.size() == 1
    })
    .await;
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Received)
    );
    assert_eq!(node.dag.read().await.transaction_count(), 0);
    drop(peer);
    shutdown(node).await;

    let node = reboot_node(RESTART_PORT, dir.path(), 100).await;
    assert_eq!(node.dag.read().await.transaction_count(), 0);
    assert_eq!(node.mempool.read().await.size(), 1);
    assert!(node
        .storage
        .read()
        .await
        .load_mempool_txs()
        .expect("mempool")
        .iter()
        .any(|stored| stored.id == tx.id));
    let base = baseline(&node).await;

    let mut peer = RawPeer::connect(RESTART_PORT).await;
    wait_peer(&node).await;
    request(&node, &mut peer, &[&tx.id]).await;
    send_sync(&mut peer, &[&tx]).await;
    wait_ingested(&node, 1).await;
    drain_until(&node, 1, 4).await;

    assert_lifecycle(
        &node,
        &base,
        &[tx.clone()],
        &[],
        &[],
        &[],
        &[(tx.id, PageState::Applied)],
    )
    .await;

    drop(peer);
    shutdown(node).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn be06_permanent_rejection_is_not_retried_and_transient_debt_is() {
    const PORT: u16 = 44937;
    let dir = tempfile::tempdir().expect("dir");
    let node = boot_node(PORT, dir.path(), 100).await;
    let funded = wallet_n(5_000_007);
    let unfunded = wallet_n(5_000_008);
    let invalid = corrupt_signature(&historical_tx(
        &funded,
        [[0u8; 32]; 2],
        8,
        1_000,
        10,
        1,
    ));
    let debt = historical_tx(&unfunded, [[0u8; 32]; 2], 9, 1_000, 10, 1);

    let mut peer = RawPeer::connect(PORT).await;
    wait_peer(&node).await;
    request(&node, &mut peer, &[&invalid.id, &debt.id]).await;
    send_sync(&mut peer, &[&invalid, &debt]).await;
    wait_ingested(&node, 2).await;
    wait_state(&node, &invalid.id, PageState::Rejected).await;
    wait_for("debt queued", || async {
        node.mempool.read().await.size() == 1
    })
    .await;

    node.rpc.drain_mempool().await;
    assert_eq!(node.dag.read().await.transaction_count(), 0);
    assert_eq!(node.mempool.read().await.size(), 1);
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&debt.id),
        Some(PageState::Received)
    );
    assert_eq!(node.sync_ctx.stats.sync_progress.load(Ordering::Relaxed), 0);

    node.rpc.drain_mempool().await;
    assert_eq!(node.mempool.read().await.size(), 1);
    assert_eq!(node.dag.read().await.transaction_count(), 0);

    fund(&node, &funded, 2_000_000).await;
    fund(&node, &unfunded, 2_000_000).await;
    let base = baseline(&node).await;
    drain_until(&node, 1, 4).await;

    assert_lifecycle(
        &node,
        &base,
        &[debt.clone()],
        &[],
        &[],
        &[invalid.clone()],
        &[
            (debt.id, PageState::Applied),
            (invalid.id, PageState::Rejected),
        ],
    )
    .await;
    assert_eq!(node.rpc.mempool_stats().await.expired, 0);

    drop(peer);
    shutdown(node).await;
}
