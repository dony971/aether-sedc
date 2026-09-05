//! # P2P Networking Module
//!
//! Implements peer-to-peer networking for the Aether DAG with efficient inventory synchronization.
//! Uses tip-based synchronization and hash comparison for inventory management.
//! Supports DNS-based peer discovery and peer exchange (PEX).

use crate::transaction::Transaction;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::sync_stats::{SyncContext, TOPO_ORDER_CAP};

/// P2P handshake magic bytes ("AETH")
const HANDSHAKE_MAGIC: [u8; 4] = [0x41, 0x45, 0x54, 0x48];

/// Maximum accepted encrypted message size (16 MiB). The length prefix is a
/// u32: without this cap a peer could advertise a 4 GiB frame and force a
/// giant allocation (memory DoS, V-09).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of concurrently connected peers (V-10)
const MAX_PEERS: usize = 128;

/// Maximum number of known peer addresses retained (PEX/DNS growth bound)
const MAX_KNOWN_PEERS: usize = 1000;

/// Maximum entries in the seen-transaction cache (memory bound)
const MAX_SEEN_TXS: usize = 50_000;

/// Maximum items accepted from a single Inventory/GetData/GetInventory/Peers
/// message (vector-of-vectors amplification bound)
const MAX_INV_ITEMS: usize = 1000;

/// Maximum frames accepted from a peer per second (rate limit)
const MAX_MSGS_PER_SEC: u64 = 400;

// H2: network timeouts. A peer that connects and never speaks (slow-loris),
// stalls mid-frame, or points at a black-holed address must be released
// instead of holding a task + socket forever.
/// Handshake (magic + X25519) must complete within this budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Inactivity budget for reading a single frame (length/nonce/ciphertext).
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
/// Outbound connect budget (black-holed addresses must not stall discovery).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// H4/V-24: network identity in the P2P handshake. Two networks with
// different genesis hashes must NOT interconnect (cross-network gossip and
// inventory pollution). The genesis hash (public constant) identifies the
// network; the protocol version guards the wire format. This is a BREAKING
// protocol change (the handshake frame grew from 36 to 69 bytes): every node
// on the network must run the same binary — safe here because the testnet is
// not yet public and the genesis ceremony purges all node data dirs.
// v2 → v3 (WEIGHT): `tx.weight` is now DAG-maintained (subtree size) and
// Stable/practically_final became reachable. Status semantics changed, so
// mixed-version peers would disagree on finality — the version bump splits
// old and new networks. Deployment MUST rotate the genesis (ceremony) so the
// new network starts from a clean state.
/// Wire format version of the P2P handshake.
const P2P_PROTOCOL_VERSION: u8 = 3;
/// Handshake frame: magic(4) | version(1) | genesis hash(32) | ephemeral key(32)
const HANDSHAKE_FRAME_LEN: usize = 4 + 1 + 32 + 32;

/// Insert into the seen-transaction cache, evicting old entries once the
/// cache is full so memory stays bounded under flood.
async fn insert_seen(seen: &RwLock<HashMap<Vec<u8>, SeenTxEntry>>, tx_bytes: Vec<u8>) {
    let mut map = seen.write().await;
    if map.len() >= MAX_SEEN_TXS {
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.timestamp) < Duration::from_secs(300));
        if map.len() >= MAX_SEEN_TXS {
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        }
    }
    map.insert(
        tx_bytes,
        SeenTxEntry {
            timestamp: Instant::now(),
        },
    );
}

/// P2P network configuration
#[derive(Clone)]
pub struct P2PConfig {
    /// Local address to bind to
    pub listen_addr: SocketAddr,
    /// Bootstrap nodes to connect to
    pub bootnodes: Vec<SocketAddr>,
    /// DNS seed domains for peer discovery (e.g. "seed.aether.network")
    pub dns_seeds: Vec<String>,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap_or_else(|_| {
                tracing::warn!("Failed to parse default P2P address, using fallback");
                "127.0.0.1:30333"
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
            }),
            bootnodes: Vec::new(),
            dns_seeds: Vec::new(),
        }
    }
}

/// P2P network message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum P2PMessage {
    /// Transaction gossip
    Transaction(Vec<u8>),
    /// Inventory - list of transaction hashes
    Inventory(Vec<Vec<u8>>),
    /// GetData - request specific transactions by hash
    GetData(Vec<Vec<u8>>),
    /// GetInventory - request inventory based on tips
    GetInventory {
        /// Tips of the requesting node
        tips: Vec<Vec<u8>>,
    },
    /// SyncRequest - request full inventory from peer (legacy)
    SyncRequest,
    /// SyncResponse - send transactions (with pagination support)
    SyncResponse(Vec<Vec<u8>>),
    /// Ping message for keepalive
    Ping,
    /// Pong response
    Pong,
    /// Peer exchange - list of known peer addresses
    Peers(Vec<SocketAddr>),
}

/// Seen transaction entry with timestamp for LRU eviction
#[derive(Clone)]
struct SeenTxEntry {
    timestamp: Instant,
}

/// P2P network manager
#[derive(Clone)]
pub struct P2PNetwork {
    config: P2PConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
    known_peers: Arc<RwLock<HashSet<SocketAddr>>>,
    tx_channel: mpsc::UnboundedSender<Transaction>,
    peer_discovery_tx: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedSender<SocketAddr>>>>,
    get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
    get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
    /// B4: shared bootstrap state (counters, parent-request dedup, orphan TTL)
    sync_ctx: Arc<SyncContext>,
    /// B4: true when the hash is already in the orphan store (sync dedup)
    is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
}

impl P2PNetwork {
    /// Create a new P2P network manager
    pub fn new(
        config: P2PConfig,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            known_peers: Arc::new(RwLock::new(HashSet::new())),
            tx_channel,
            peer_discovery_tx: Arc::new(tokio::sync::Mutex::new(None)),
            get_dag_hashes,
            get_transaction_by_hash,
            get_tips,
            seen_transactions: Arc::new(RwLock::new(HashMap::new())),
            sync_ctx,
            is_orphan,
        }
    }

    /// Start the P2P network
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting P2P network on {}", self.config.listen_addr);

        // Start listening for incoming connections
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let peers = self.peers.clone();
        let tx_channel = self.tx_channel.clone();
        let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
        let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
        let get_tips = Arc::clone(&self.get_tips);
        let seen_transactions = Arc::clone(&self.seen_transactions);
        let sync_ctx = Arc::clone(&self.sync_ctx);
        let is_orphan = Arc::clone(&self.is_orphan);
        let local_addr = self.config.listen_addr;
        let known_peers = self.known_peers.clone();
        let (peer_discovery_tx, mut peer_discovery_rx) = mpsc::unbounded_channel::<SocketAddr>();
        {
            let mut tx_lock = self.peer_discovery_tx.lock().await;
            *tx_lock = Some(peer_discovery_tx.clone());
        }
        let p2p_discovery = self.clone();
        tokio::spawn(async move {
            while let Some(addr) = peer_discovery_rx.recv().await {
                p2p_discovery.connect_to_peer(addr).await;
            }
        });
        tokio::spawn(async move {
            Self::accept_loop(
                listener,
                peers,
                local_addr,
                known_peers,
                tx_channel,
                get_dag_hashes,
                get_transaction_by_hash,
                get_tips,
                seen_transactions,
                peer_discovery_tx,
                sync_ctx,
                is_orphan,
            )
            .await;
        });

        // Connect to bootnodes
        for bootnode in &self.config.bootnodes {
            self.connect_to_peer(*bootnode).await;
        }

        // Discover peers from DNS seeds
        self.discover_from_dns().await;

        // Start heartbeat task
        self.start_heartbeat().await;

        // Start reconnection task for bootnodes
        self.start_reconnection_task().await;

        // Start periodic DNS discovery
        self.start_dns_discovery().await;

        // Start periodic peer exchange (PEX)
        self.start_pex().await;

        // Start cache cleanup task
        self.start_cache_cleanup().await;

        Ok(())
    }

    /// Start heartbeat task to check peer connections and reconnect if needed
    async fn start_heartbeat(&self) {
        let peers = self.peers.clone();
        let bootnodes = self.config.bootnodes.clone();
        let p2p_network = self.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

                let peer_count = {
                    let peers_read = peers.read().await;
                    peers_read.len()
                };

                if peer_count == 0 && !bootnodes.is_empty() {
                    warn!("No connected peers, attempting to reconnect to bootnodes...");
                    for bootnode in &bootnodes {
                        info!("Reconnecting to bootnode: {}", bootnode);
                        p2p_network.connect_to_peer(*bootnode).await;
                    }
                } else {
                    debug!("Heartbeat: {} connected peers", peer_count);
                }
            }
        });
    }

    /// Start reconnection task for bootnodes with exponential backoff
    async fn start_reconnection_task(&self) {
        let peers = self.peers.clone();
        let bootnodes = self.config.bootnodes.clone();
        let p2p_network = self.clone();

        tokio::spawn(async move {
            let mut retry_counts: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            loop {
                for bootnode in &bootnodes {
                    let bootnode_addr = bootnode.clone();
                    let connected = {
                        let current_peers = peers.read().await;
                        current_peers.contains_key(&bootnode_addr)
                    };

                    if !connected {
                        let retry_count =
                            *retry_counts.entry(bootnode_addr.to_string()).or_insert(0);
                        let delay = std::cmp::min(2u64.pow(retry_count), 60); // Max 60 seconds
                        info!(
                            "Bootnode {} disconnected, reconnecting in {}s (attempt {})",
                            bootnode_addr,
                            delay,
                            retry_count + 1
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;

                        p2p_network.connect_to_peer(bootnode_addr.clone()).await;
                        retry_counts.insert(
                            bootnode_addr.to_string(),
                            std::cmp::min(retry_count + 1, 6), // Cap at 6 (max delay 64s)
                        );
                    } else {
                        retry_counts.insert(bootnode_addr.to_string(), 0); // Reset retry count if connected
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    /// Start cache cleanup task to evict old seen transactions
    async fn start_cache_cleanup(&self) {
        let seen_transactions = self.seen_transactions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let now = Instant::now();
                let mut seen = seen_transactions.write().await;
                let before = seen.len();
                seen.retain(|_, entry| {
                    now.duration_since(entry.timestamp) < Duration::from_secs(3600)
                });
                let after = seen.len();
                if before != after {
                    debug!(
                        "Cache cleanup: removed {} entries ({} -> {})",
                        before - after,
                        before,
                        after
                    );
                }
            }
        });
    }

    /// Resolve DNS seeds to peer addresses
    async fn discover_from_dns(&self) {
        let dns_seeds = self.config.dns_seeds.clone();
        let default_port = self.config.listen_addr.port();
        let known_peers = self.known_peers.clone();
        let p2p = self.clone();

        tokio::spawn(async move {
            for seed in &dns_seeds {
                match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                    Ok(addrs) => {
                        let addrs: Vec<SocketAddr> = addrs.collect();
                        info!("🌐 DNS seed {} resolved to {} addresses", seed, addrs.len());
                        for addr in &addrs {
                            let mut known = known_peers.write().await;
                            if known.len() >= MAX_KNOWN_PEERS {
                                break;
                            }
                            known.insert(*addr);
                            if !p2p.is_connected(*addr).await {
                                p2p.connect_to_peer(*addr).await;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ DNS seed {} resolution failed: {}", seed, e);
                    }
                }
            }
        });
    }

    /// Periodically re-resolve DNS seeds to discover new peers
    async fn start_dns_discovery(&self) {
        let dns_seeds = self.config.dns_seeds.clone();
        let default_port = self.config.listen_addr.port();
        let known_peers = self.known_peers.clone();
        let p2p = self.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(120)).await; // Every 2 minutes
                for seed in &dns_seeds {
                    match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                        Ok(addrs) => {
                            for addr in addrs {
                                let mut known = known_peers.write().await;
                                if known.len() >= MAX_KNOWN_PEERS {
                                    break;
                                }
                                if known.insert(addr) && !p2p.is_connected(addr).await {
                                    let p2p_clone = p2p.clone();
                                    tokio::spawn(async move {
                                        p2p_clone.connect_to_peer(addr).await;
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            debug!("DNS seed {} re-resolution failed: {}", seed, e);
                        }
                    }
                }
            }
        });
    }

    /// Periodically broadcast known peers to connected peers (PEX)
    async fn start_pex(&self) {
        let peers = self.peers.clone();
        let known_peers = self.known_peers.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await; // Every 15 seconds for fast peer discovery
                let peer_list: Vec<SocketAddr> = {
                    let known = known_peers.read().await;
                    known.iter().copied().collect()
                };
                if peer_list.is_empty() {
                    continue;
                }
                let msg = P2PMessage::Peers(peer_list);
                if let Ok(bytes) = bincode::serialize(&msg) {
                    let peers = peers.read().await;
                    for (_, sender) in peers.iter() {
                        let _ = sender.send(bytes.clone());
                    }
                }
            }
        });
    }

    /// Check if a peer address is currently connected
    async fn is_connected(&self, addr: SocketAddr) -> bool {
        self.peers.read().await.contains_key(&addr)
    }

    /// Accept loop for incoming connections
    async fn accept_loop(
        listener: TcpListener,
        peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        local_addr: SocketAddr,
        known_peers: Arc<RwLock<HashSet<SocketAddr>>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) {
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    {
                        let peers_guard = peers.read().await;
                        if peers_guard.len() >= MAX_PEERS {
                            warn!(
                                "Rejecting incoming peer {}: connection limit reached ({})",
                                addr, MAX_PEERS
                            );
                            drop(socket);
                            continue;
                        }
                    }
                    info!("New peer connected: {}", addr);
                    let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                    {
                        let mut peers = peers.write().await;
                        peers.insert(addr, msg_sender.clone());
                    }

                    let peers_clone = peers.clone();
                    let tx_channel = tx_channel.clone();
                    let get_dag_hashes = Arc::clone(&get_dag_hashes);
                    let get_transaction_by_hash = Arc::clone(&get_transaction_by_hash);
                    let get_tips = Arc::clone(&get_tips);
                    let seen_transactions = Arc::clone(&seen_transactions);
                    let peer_discovery_tx = peer_discovery_tx.clone();
                    let known_peers = known_peers.clone();
                    let sync_ctx = Arc::clone(&sync_ctx);
                    let is_orphan = Arc::clone(&is_orphan);
                    tokio::spawn(async move {
                        Self::handle_peer(
                            socket,
                            addr,
                            peers_clone,
                            local_addr,
                            known_peers,
                            tx_channel,
                            get_dag_hashes,
                            get_transaction_by_hash,
                            get_tips,
                            seen_transactions,
                            msg_sender,
                            msg_receiver,
                            peer_discovery_tx,
                            sync_ctx,
                            is_orphan,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Build a 12-byte nonce from a u64 counter
    fn build_nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// H2: read exactly `buf.len()` bytes with an inactivity timeout, so a
    /// stalled or silent peer is disconnected instead of holding the task and
    /// socket forever. The timeout error surfaces as io::ErrorKind::TimedOut.
    async fn read_exact_timeout<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        buf: &mut [u8],
        budget: Duration,
    ) -> std::io::Result<()> {
        match tokio::time::timeout(budget, reader.read_exact(buf)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "P2P read timed out",
            )),
        }
    }

    /// H4/V-24: verify the network identity of a received handshake frame
    /// (magic + protocol version + genesis hash). Unit-testable pure check.
    fn verify_handshake_identity(incoming: &[u8]) -> Result<(), &'static str> {
        if incoming.len() < HANDSHAKE_FRAME_LEN {
            return Err("Short P2P handshake frame");
        }
        if incoming[..4] != HANDSHAKE_MAGIC {
            return Err("Invalid P2P handshake magic — not an Aether node");
        }
        if incoming[4] != P2P_PROTOCOL_VERSION {
            return Err("Incompatible P2P protocol version — upgrade the node");
        }
        if incoming[5..37] != crate::genesis::GENESIS_HASH {
            return Err("Network mismatch: peer genesis hash differs from ours");
        }
        Ok(())
    }

    /// Perform X25519 handshake and derive AES-256-GCM key
    async fn handshake(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let our_secret = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_secret);

        let mut outgoing = Vec::with_capacity(HANDSHAKE_FRAME_LEN);
        outgoing.extend_from_slice(&HANDSHAKE_MAGIC);
        outgoing.push(P2P_PROTOCOL_VERSION);
        outgoing.extend_from_slice(&crate::genesis::GENESIS_HASH);
        outgoing.extend_from_slice(our_public.as_bytes());
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&outgoing))
            .await
            .is_err()
        {
            return Err("P2P handshake write timed out".into());
        }

        let mut incoming = [0u8; HANDSHAKE_FRAME_LEN];
        Self::read_exact_timeout(reader, &mut incoming, HANDSHAKE_TIMEOUT)
            .await
            .map_err(|e| format!("P2P handshake read failed: {}", e))?;
        Self::verify_handshake_identity(&incoming)?;

        let mut peer_pk_bytes = [0u8; 32];
        peer_pk_bytes.copy_from_slice(&incoming[HANDSHAKE_FRAME_LEN - 32..]);
        let peer_public = PublicKey::from(peer_pk_bytes);
        let shared_secret = our_secret.diffie_hellman(&peer_public);

        let mut hasher = Sha256::new();
        hasher.update(b"aether-p2p-key-v1");
        hasher.update(shared_secret.as_bytes());
        let key_bytes = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&key_bytes);
        Ok(result)
    }

    /// Handle a peer connection
    async fn handle_peer(
        socket: TcpStream,
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        local_addr: SocketAddr,
        known_peers: Arc<RwLock<HashSet<SocketAddr>>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        msg_sender: mpsc::UnboundedSender<Vec<u8>>,
        msg_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) {
        // Split socket into read and write halves
        let (mut reader, mut writer) = socket.into_split();

        // Perform encrypted handshake (X25519 key exchange)
        let key_bytes = match Self::handshake(&mut reader, &mut writer)
            .await
            .map_err(|e| e.to_string())
        {
            Ok(k) => {
                info!("🔐 P2P encrypted handshake complete with {}", addr);
                k
            }
            Err(msg) => {
                warn!("❌ P2P handshake failed with {}: {}", addr, msg);
                {
                    let mut peers_lock = peers.write().await;
                    peers_lock.remove(&addr);
                }
                known_peers.write().await.remove(&addr);
                return;
            }
        };
        let key_enc = Arc::new(key_bytes);
        let key_dec = Arc::clone(&key_enc);

        // Spawn task to handle outgoing messages (encrypted)
        let mut msg_receiver = msg_receiver;
        let send_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let send_counter_clone = Arc::clone(&send_counter);
        tokio::spawn(async move {
            while let Some(msg) = msg_receiver.recv().await {
                let cipher = {
                    let key = Key::from_slice(key_enc.as_ref());
                    ChaCha20Poly1305::new(key)
                };
                let nonce_val =
                    send_counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let nonce_bytes = Self::build_nonce(nonce_val);
                let nonce = Nonce::from_slice(&nonce_bytes);
                match cipher.encrypt(nonce, msg.as_ref()) {
                    Ok(ciphertext) => {
                        let total_len = 12 + ciphertext.len();
                        if writer
                            .write_all(&(total_len as u32).to_be_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if writer.write_all(nonce).await.is_err() {
                            break;
                        }
                        if writer.write_all(&ciphertext).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Encryption failed for {}: {:?}", addr, e);
                        break;
                    }
                }
            }
        });

        // Send GetInventory with tips on connection
        let our_tips = get_tips();
        if let Ok(getinv_msg) = bincode::serialize(&P2PMessage::GetInventory {
            tips: our_tips.clone(),
        }) {
            info!(
                "[Sync] Sending GetInventory with {} tips to {}",
                our_tips.len(),
                addr
            );
            let _ = msg_sender.send(getinv_msg);
        }

        // Also request the full inventory: tip-based sync can miss unconfirmed
        // (weight-0) tips, so fetch the peer's complete hash set to reconcile.
        if let Ok(sync_req) = bincode::serialize(&P2PMessage::SyncRequest) {
            let _ = msg_sender.send(sync_req);
        }

        // Mark peer as known
        known_peers.write().await.insert(addr);

        let mut msg_count: u64 = 0;
        let mut window_start = Instant::now();

        loop {
            // Read encrypted message length (4 bytes)
            // H2: inactivity timeout so a peer that stops mid-stream is
            // disconnected instead of holding the task + socket forever.
            let mut len_buf = [0u8; 4];
            match Self::read_exact_timeout(&mut reader, &mut len_buf, FRAME_TIMEOUT).await {
                Ok(()) => {}
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        warn!(
                            "Peer {} idle for {:?}, disconnecting (frame timeout)",
                            addr, FRAME_TIMEOUT
                        );
                    } else {
                        warn!("Peer {} disconnected: {}", addr, e);
                    }
                    break;
                }
            }

            // Per-second rate limit: count every frame BEFORE decrypt/alloc
            let now = Instant::now();
            if now.duration_since(window_start) >= Duration::from_secs(1) {
                window_start = now;
                msg_count = 0;
            }
            msg_count += 1;
            if msg_count > MAX_MSGS_PER_SEC {
                warn!(
                    "Peer {} exceeded message rate limit ({} msgs/s), disconnecting",
                    addr, MAX_MSGS_PER_SEC
                );
                break;
            }

            let total_len = u32::from_be_bytes(len_buf) as usize;
            if total_len < 12 {
                warn!("Peer {} sent invalid message length {}", addr, total_len);
                break;
            }
            if total_len > MAX_MESSAGE_SIZE {
                warn!(
                    "Peer {} sent oversized message ({} bytes > {}), disconnecting",
                    addr, total_len, MAX_MESSAGE_SIZE
                );
                break;
            }

            // Read nonce (12 bytes)
            let mut nonce_buf = [0u8; 12];
            if Self::read_exact_timeout(&mut reader, &mut nonce_buf, FRAME_TIMEOUT)
                .await
                .is_err()
            {
                warn!("Failed to read nonce from {}", addr);
                break;
            }

            // Read ciphertext
            let ciphertext_len = total_len - 12;
            let mut ciphertext = vec![0u8; ciphertext_len];
            if Self::read_exact_timeout(&mut reader, &mut ciphertext, FRAME_TIMEOUT)
                .await
                .is_err()
            {
                warn!("Failed to read ciphertext from {}", addr);
                break;
            }

            // Decrypt
            let cipher = {
                let key = Key::from_slice(key_dec.as_ref());
                ChaCha20Poly1305::new(key)
            };
            let nonce = Nonce::from_slice(&nonce_buf);
            let plaintext = match cipher.decrypt(nonce, ciphertext.as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Decryption failed for {}: {:?}", addr, e);
                    break;
                }
            };

            // Deserialize message
            match bincode::deserialize::<P2PMessage>(&plaintext) {
                Ok(msg) => {
                    match msg {
                        P2PMessage::Transaction(tx_bytes) => {
                            // Deduplication: check if we've seen this transaction
                            {
                                let seen = seen_transactions.read().await;
                                if seen.contains_key(&tx_bytes) {
                                    continue;
                                }
                            }

                            // Deserialize transaction
                            if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                // Mark as seen with timestamp and source (Network) before sending to channel
                                insert_seen(&seen_transactions, tx_bytes.clone()).await;

                                info!("Received transaction from {}: {}", addr, hex::encode(tx.id));
                                let _ = tx_channel.send(tx);

                                // Forward transaction to all other connected peers (relay)
                                let relay_msg = P2PMessage::Transaction(tx_bytes.clone());
                                if let Ok(relay_bytes) = bincode::serialize(&relay_msg) {
                                    let peers_guard = peers.read().await;
                                    for (peer_addr, sender) in peers_guard.iter() {
                                        if *peer_addr != addr {
                                            let _ = sender.send(relay_bytes.clone());
                                        }
                                    }
                                }
                            } else {
                                warn!("Failed to deserialize transaction from {}", addr);
                            }
                        }
                        P2PMessage::Inventory(hashes) => {
                            // Determine which hashes we need (bounded by MAX_INV_ITEMS).
                            // B4: dedup against the DAG AND the orphan store: a tx
                            // parked as an orphan is already tracked (its parents are
                            // being requested), re-requesting it is pure waste.
                            let our_hashes = get_dag_hashes();
                            let our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();
                            // PHASE D live-campaign fix: the MAX_INV_ITEMS cap
                            // used to apply to the PEER's raw inventory, which
                            // hid every tx beyond the first 1000 from a joining
                            // node (the diff came out empty, sync_requested=0,
                            // bootstrap stuck a few txs short of the tip). The
                            // cap now bounds the REQUEST (the real diff) so a
                            // late joiner still asks for the whole missing set.
                            let missing_hashes: Vec<Vec<u8>> = hashes
                                .into_iter()
                                .filter(|h| !our_hash_set.contains(h) && !is_orphan(h.as_slice()))
                                .take(MAX_INV_ITEMS)
                                .collect();

                            // Request missing transactions via GetData
                            if !missing_hashes.is_empty() {
                                sync_ctx.stats.sync_requested.fetch_add(
                                    missing_hashes.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                info!(
                                    "Requesting {} missing transactions from {}",
                                    missing_hashes.len(),
                                    addr
                                );
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_hashes))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                            }
                        }
                        P2PMessage::GetInventory { tips: peer_tips } => {
                            // Get our hashes and tips
                            let our_hashes = get_dag_hashes();
                            let our_tips = get_tips();
                            let _our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();

                            // Find transactions we have that peer doesn't have (compare tips),
                            // bounded by MAX_INV_ITEMS on the peer-supplied list.
                            let peer_tips_set: HashSet<Vec<u8>> =
                                peer_tips.into_iter().take(MAX_INV_ITEMS).collect();
                            let our_tips_set: HashSet<Vec<u8>> = our_tips.into_iter().collect();

                            // Transactions we need from peer (tips we don't have)
                            let missing_for_us: Vec<Vec<u8>> =
                                peer_tips_set.difference(&our_tips_set).cloned().collect();

                            // Transactions peer might need from us (tips we have that they don't)
                            let missing_for_peer: Vec<Vec<u8>> =
                                our_tips_set.difference(&peer_tips_set).cloned().collect();

                            info!("[Sync] GetInventory from {}: we need {} tips, peer might need {} tips", 
                                addr, missing_for_us.len(), missing_for_peer.len());

                            // Send our tips that peer doesn't have (with pagination)
                            if !missing_for_peer.is_empty() {
                                const PAGE_SIZE: usize = 100;
                                let mut tx_bytes_list = Vec::new();

                                for hash in missing_for_peer.iter().take(PAGE_SIZE) {
                                    if let Some(tx) = get_transaction_by_hash(hash) {
                                        if let Ok(bytes) = bincode::serialize(&tx) {
                                            tx_bytes_list.push(bytes);
                                        }
                                    }
                                }

                                if !tx_bytes_list.is_empty() {
                                    info!(
                                        "[Sync] Sending {} transactions to {}",
                                        tx_bytes_list.len(),
                                        addr
                                    );
                                    if let Ok(sync_resp_msg) =
                                        bincode::serialize(&P2PMessage::SyncResponse(tx_bytes_list))
                                    {
                                        let _ = msg_sender.send(sync_resp_msg);
                                    }
                                }
                            }

                            // Request missing transactions from peer
                            if !missing_for_us.is_empty() {
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_for_us))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                            }
                        }
                        P2PMessage::GetData(hashes) => {
                            // B4: serve the requested transactions in DETERMINISTIC
                            // DEPENDENCY order (parents before children, Kahn's
                            // algorithm over the local DAG). Batches therefore
                            // arrive ancestor-first no matter the request order, so
                            // a joining node inserts most of them immediately
                            // instead of parking deep chains of orphans.
                            // C2-004: the order is CACHED by DAG length. Sorting
                            // the whole DAG per GetData collapsed serving nodes
                            // at ~10k txs; the cache makes repeat requests O(1).
                            const PAGE_SIZE: usize = 100;
                            let all_hashes = get_dag_hashes();
                            let topo: Option<Vec<Vec<u8>>> = {
                                let cache = sync_ctx.topo_cache.read().await;
                                match cache.as_ref() {
                                    Some((len, order)) if *len as usize == all_hashes.len() => {
                                        sync_ctx
                                            .stats
                                            .topo_cache_hits
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        Some(order.clone())
                                    }
                                    _ => {
                                        sync_ctx
                                            .stats
                                            .topo_cache_miss
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        None
                                    }
                                }
                            };
                            let topo = match topo {
                                Some(order) => Some(order),
                                None => {
                                    let order = Self::topological_order(
                                        all_hashes,
                                        &*get_transaction_by_hash,
                                    );
                                    if let Some(ref o) = order {
                                        let mut cache = sync_ctx.topo_cache.write().await;
                                        *cache = Some((o.len() as u64, o.clone()));
                                    }
                                    order
                                }
                            };
                            let mut requested: Vec<Vec<u8>> =
                                hashes.iter().take(PAGE_SIZE).cloned().collect();
                            if let Some(order) = topo {
                                let pos: HashMap<&Vec<u8>, usize> =
                                    order.iter().enumerate().map(|(i, h)| (h, i)).collect();
                                requested
                                    .sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
                            }
                            let mut tx_bytes_list = Vec::new();

                            for hash in requested {
                                if let Some(tx) = get_transaction_by_hash(&hash) {
                                    if let Ok(bytes) = bincode::serialize(&tx) {
                                        tx_bytes_list.push(bytes);
                                    }
                                }
                            }

                            if !tx_bytes_list.is_empty() {
                                info!(
                                    "[Sync] Sending {} transactions to {}",
                                    tx_bytes_list.len(),
                                    addr
                                );
                                if let Ok(sync_resp_msg) =
                                    bincode::serialize(&P2PMessage::SyncResponse(tx_bytes_list))
                                {
                                    let _ = msg_sender.send(sync_resp_msg);
                                }
                            }
                        }
                        P2PMessage::SyncRequest => {
                            // Respond with full inventory
                            let our_hashes = get_dag_hashes();
                            info!(
                                "[Sync] Sending inventory with {} hashes to {}",
                                our_hashes.len(),
                                addr
                            );
                            if let Ok(inv_msg) =
                                bincode::serialize(&P2PMessage::Inventory(our_hashes))
                            {
                                let _ = msg_sender.send(inv_msg);
                            }
                        }
                        P2PMessage::SyncResponse(tx_bytes_list) => {
                            // B4: download and add transactions in dependency order
                            // (bounded by MAX_INV_ITEMS to avoid amplification).
                            // 1. Dedup against the DAG AND the orphan store: an
                            //    orphan is already tracked and retried by the
                            //    resolver (fixpoint in process_orphans), so
                            //    re-delivering it is pure waste (this was the B4
                            //    re-request amplification loop).
                            // 2. Split the batch into (deliverable now) / (parents
                            //    still missing) with dependency-aware passes: a tx
                            //    whose parents are in the DAG or accepted earlier in
                            //    this SAME batch is delivered immediately. The
                            //    remaining txs go through the normal pipeline where
                            //    they are parked as orphans and their parents are
                            //    requested (bounded by the parent-request dedup).
                            let mut pending: Vec<(Vec<u8>, Transaction)> = Vec::new();
                            for tx_bytes in tx_bytes_list.into_iter().take(MAX_INV_ITEMS) {
                                if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                    if get_transaction_by_hash(&tx.id).is_some()
                                        || is_orphan(&tx.id)
                                    {
                                        sync_ctx
                                            .stats
                                            .duplicate_ignored
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        continue;
                                    }
                                    pending.push((tx_bytes, tx));
                                }
                            }
                            sync_ctx.stats.sync_received.fetch_add(
                                pending.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            sync_ctx
                                .stats
                                .sync_batches
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let (deliverable, waiting) =
                                Self::partition_batch(pending, &*get_transaction_by_hash);

                            // Deliver in dependency order (throttled so the ledger
                            // can breathe).
                            for (tx_bytes, tx) in deliverable.into_iter().chain(waiting) {
                                insert_seen(&seen_transactions, tx_bytes).await;
                                let _ = tx_channel.send(tx);
                                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            }
                        }
                        P2PMessage::Ping => {
                            // Respond with pong - skip for now, need sender
                        }
                        P2PMessage::Pong => {
                            // Ignore pong
                        }
                        P2PMessage::Peers(peer_list) => {
                            let to_add: Vec<SocketAddr> = {
                                let known = known_peers.read().await;
                                let peers_read = peers.read().await;
                                peer_list
                                    .iter()
                                    .take(MAX_INV_ITEMS)
                                    .filter(|p| {
                                        !known.contains(p)
                                            && **p != local_addr
                                            && !peers_read.contains_key(p)
                                    })
                                    .copied()
                                    .collect()
                            };
                            for peer_addr in to_add {
                                let mut known = known_peers.write().await;
                                if known.len() >= MAX_KNOWN_PEERS {
                                    warn!(
                                        "Known-peer table full ({}), ignoring new peers",
                                        MAX_KNOWN_PEERS
                                    );
                                    break;
                                }
                                known.insert(peer_addr);
                                let _ = peer_discovery_tx.send(peer_addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize message from {}: {}", addr, e);
                }
            }
        }

        // Remove peer from peers map on disconnect
        {
            let mut peers_lock = peers.write().await;
            peers_lock.remove(&addr);
        }
        known_peers.write().await.remove(&addr);
        info!("Peer {} removed from peers map", addr);
    }

    /// Connect to a peer
    async fn connect_to_peer(&self, addr: SocketAddr) {
        info!("Tentative de connexion au bootnode: {}", addr);

        {
            let peers_guard = self.peers.read().await;
            if peers_guard.len() >= MAX_PEERS {
                warn!(
                    "Skipping connect to {}: connection limit reached ({})",
                    addr, MAX_PEERS
                );
                return;
            }
        }

        // H2: bound the connect attempt so a black-holed or unroutable peer
        // address cannot stall the outbound discovery loop indefinitely.
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(socket)) => {
                info!("Connected to peer: {}", addr);
                let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                {
                    let mut peers = self.peers.write().await;
                    peers.insert(addr, msg_sender.clone());
                }

                let peers = self.peers.clone();
                let known_peers = self.known_peers.clone();
                let local_addr = self.config.listen_addr;
                let tx_channel = self.tx_channel.clone();
                let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
                let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
                let get_tips = Arc::clone(&self.get_tips);
                let seen_transactions = Arc::clone(&self.seen_transactions);
                let sync_ctx = Arc::clone(&self.sync_ctx);
                let is_orphan = Arc::clone(&self.is_orphan);
                let peer_discovery_tx = {
                    let guard = self.peer_discovery_tx.lock().await;
                    guard.clone().unwrap_or_else(|| {
                        let (tx, _) = mpsc::unbounded_channel();
                        tx
                    })
                };
                tokio::spawn(async move {
                    Self::handle_peer(
                        socket,
                        addr,
                        peers,
                        local_addr,
                        known_peers,
                        tx_channel,
                        get_dag_hashes,
                        get_transaction_by_hash,
                        get_tips,
                        seen_transactions,
                        msg_sender,
                        msg_receiver,
                        peer_discovery_tx,
                        sync_ctx,
                        is_orphan,
                    )
                    .await;
                });
            }
            Ok(Err(e)) => {
                warn!("Failed to connect to {}: {}", addr, e);
            }
            Err(_) => {
                warn!("Connect timeout to {} after {:?}", addr, CONNECT_TIMEOUT);
            }
        }
    }

    /// Broadcast a transaction to all connected peers
    pub async fn broadcast_transaction(&self, tx: Transaction) {
        let tx_bytes = match bincode::serialize(&tx) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize transaction: {}", e);
                return;
            }
        };

        // Mark as seen with Local source before broadcasting to avoid rebroadcast loops
        insert_seen(&self.seen_transactions, tx_bytes.clone()).await;

        let msg = P2PMessage::Transaction(tx_bytes.clone());
        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize P2P message: {}", e);
                return;
            }
        };

        let peers = self.peers.read().await;
        let peers: &std::collections::HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = &*peers;
        for (addr, sender) in peers.iter() {
            let sender: &mpsc::UnboundedSender<Vec<u8>> = sender;
            if sender.send(msg_bytes.clone()).is_err() {
                warn!("Failed to send transaction to {}: channel closed", addr);
            }
        }
    }

    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get the list of connected peers
    pub async fn get_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let peers: &std::collections::HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = &*peers;
        peers.keys().copied().collect()
    }

    /// B4: deterministic dependency order of the local DAG (parents before
    /// children, Kahn's algorithm with a sorted queue for a stable result).
    /// Returns None above `TOPO_ORDER_CAP` (cost guard): the caller then falls
    /// back to the request order.
    fn topological_order(
        hashes: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Option<Vec<Vec<u8>>> {
        if hashes.is_empty() || hashes.len() > TOPO_ORDER_CAP {
            return None;
        }
        let mut indeg: HashMap<Vec<u8>, usize> = hashes.iter().map(|h| (h.clone(), 0)).collect();
        let mut children: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
        for h in &hashes {
            if let Some(tx) = get_transaction_by_hash(h) {
                for parent in tx.parents.iter() {
                    if *parent == [0u8; 32] {
                        continue;
                    }
                    if indeg.contains_key(parent.as_slice()) {
                        *indeg.get_mut(parent.as_slice()).unwrap() += 1;
                    }
                    children.entry(parent.to_vec()).or_default().push(h.clone());
                }
            }
        }
        let mut queue: Vec<Vec<u8>> = indeg
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(h, _)| h.clone())
            .collect();
        queue.sort();
        let mut order = Vec::with_capacity(hashes.len());
        while let Some(h) = queue.pop() {
            order.push(h.clone());
            if let Some(kids) = children.get(&h) {
                for kid in kids {
                    let d = indeg.get_mut(kid).unwrap();
                    *d -= 1;
                    if *d == 0 {
                        queue.push(kid.clone());
                    }
                }
            }
        }
        if order.len() != hashes.len() {
            // Cyclic references cannot exist (validation rejects them), but
            // never return a partial order: fall back to the caller's order.
            return None;
        }
        Some(order)
    }

    /// B4: split a sync batch into (deliverable now) / (waiting for parents)
    /// using dependency-aware passes. A tx is deliverable when BOTH parents
    /// are in the DAG or were accepted earlier in this batch (a parent that
    /// is itself still waiting keeps the child waiting too). The result is
    /// INDEPENDENT of the batch order: any permutation of the same tx set
    /// with the same DAG yields the same partition.
    fn partition_batch(
        batch: Vec<(Vec<u8>, Transaction)>,
        has_in_dag: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> (Vec<(Vec<u8>, Transaction)>, Vec<(Vec<u8>, Transaction)>) {
        use std::collections::HashSet;
        let mut inserted: HashSet<[u8; 32]> = HashSet::new();
        let mut pending = batch;
        let mut deliverable = Vec::new();
        loop {
            let before = pending.len();
            let mut still = Vec::new();
            for item in pending {
                let (_, tx) = &item;
                let p0_ok = tx.parents[0] == [0u8; 32]
                    || inserted.contains(&tx.parents[0])
                    || has_in_dag(tx.parents[0].as_slice()).is_some();
                let p1_ok = tx.parents[1] == [0u8; 32]
                    || inserted.contains(&tx.parents[1])
                    || has_in_dag(tx.parents[1].as_slice()).is_some();
                if p0_ok && p1_ok {
                    inserted.insert(tx.id);
                    deliverable.push(item);
                } else {
                    still.push(item);
                }
            }
            pending = still;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        (deliverable, pending)
    }

    /// Request a specific transaction by hash from all peers.
    ///
    /// B4: bounded + backoff. The missing-parent set is deduplicated so a
    /// parent is re-requested at most once per cooldown (escalating 2s/5s/15s
    /// by attempt count). Previously every parked orphan re-requested its
    /// parents unconditionally: the resulting 1-tx GetData flood starved the
    /// real sync batches and the bootstrap froze (B4 livelock).
    pub async fn request_transaction(&self, hash: Vec<u8>) {
        {
            let mut reqs = self.sync_ctx.requested_parents.write().await;
            if reqs.len() >= crate::sync_stats::MAX_INFLIGHT_PARENTS {
                // Evict the least recently requested entry (bounded memory).
                let oldest_key: Option<Vec<u8>> = reqs
                    .iter()
                    .min_by_key(|(_, (last, _))| *last)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    reqs.remove(&key);
                }
            }
            let now = Instant::now();
            if let Some((last, attempts)) = reqs.get_mut(&hash) {
                let cooldown = crate::sync_stats::SyncContext::backoff_for(*attempts);
                if now.duration_since(*last) < cooldown {
                    self.sync_ctx
                        .stats
                        .parent_already_known
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                *last = now;
                *attempts += 1;
            } else {
                reqs.insert(hash.clone(), (now, 1));
            }
        }

        self.sync_ctx
            .stats
            .parent_requested
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let msg = P2PMessage::GetData(vec![hash.clone()]);
        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize GetData message: {}", e);
                return;
            }
        };

        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            if sender.send(msg_bytes.clone()).is_err() {
                warn!("Failed to send GetData request to {}: channel closed", addr);
            }
        }
    }

    /// V-22 FIX: request the FULL inventory from every connected peer.
    ///
    /// The peer answers with `Inventory(all its transaction hashes)`, we
    /// diff it against our DAG and fetch what we are missing via GetData.
    /// Called periodically (see the node's 10s maintenance loop) and after
    /// boot, so a node that missed transactions while offline - or received
    /// a stale inventory at handshake time - keeps reconciling until it
    /// converges to the exact same transaction set as its peers. This never
    /// assumes the node already knows the parents: missing ancestors are
    /// fetched recursively through the orphan flow.
    pub async fn request_full_sync(&self) {
        let msg = match bincode::serialize(&P2PMessage::SyncRequest) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize SyncRequest: {}", e);
                return;
            }
        };
        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            debug!("[Sync] Requesting full inventory from {}", addr);
            if sender.send(msg.clone()).is_err() {
                warn!("Failed to send SyncRequest to {}: channel closed", addr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transaction;
    use tokio::sync::mpsc;

    #[test]
    fn test_seen_tx_entry() {
        // The seen cache holds a timestamp for eviction decisions.
        let now = Instant::now();
        let entry = SeenTxEntry {
            timestamp: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
        };
        // 60s-old entry must be evictable (older than the 30s cleanup window).
        assert!(now.duration_since(entry.timestamp) >= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_seen_transactions_deduplication() {
        // Test that seen_transactions correctly tracks and deduplicates
        let seen = Arc::new(RwLock::new(HashMap::new()));

        let tx_bytes = vec![1u8, 2, 3, 4];

        // First insert should succeed
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                },
            );
        }

        // Check that it's present
        {
            let seen_read = seen.read().await;
            assert!(seen_read.contains_key(&tx_bytes));
            assert_eq!(seen_read.len(), 1);
        }

        // Second insert should not duplicate (just update)
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                },
            );
        }

        // Should still be only one entry
        {
            let seen_read = seen.read().await;
            assert_eq!(seen_read.len(), 1);
        }
    }

    /// H2: read_exact_timeout must fail with ErrorKind::TimedOut when the peer
    /// sends nothing, and succeed when the bytes arrive. A stalled peer can no
    /// longer hold a task + socket forever (slow-loris guard).
    #[tokio::test]
    async fn test_read_exact_timeout() {
        // A duplex stream with no writer activity: the read must time out.
        let (mut reader, _silent_writer) = tokio::io::duplex(64);
        let mut buf = [0u8; 36];
        let err = P2PNetwork::read_exact_timeout(&mut reader, &mut buf, Duration::from_millis(100))
            .await
            .expect_err("silent peer must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // A duplex stream that delivers the bytes: the read must succeed.
        let (mut reader2, mut writer2) = tokio::io::duplex(64);
        writer2.write_all(&[0xAAu8; 36]).await.unwrap();
        P2PNetwork::read_exact_timeout(&mut reader2, &mut buf, Duration::from_secs(5))
            .await
            .expect("bytes must be read within the budget");
        assert_eq!(buf, [0xAAu8; 36]);

        // A stream that closes mid-read: an io error, not a timeout.
        let (mut reader3, mut writer3) = tokio::io::duplex(64);
        writer3.write_all(&[0xBBu8; 4]).await.unwrap();
        drop(writer3);
        let err = P2PNetwork::read_exact_timeout(&mut reader3, &mut buf, Duration::from_secs(5))
            .await
            .expect_err("truncated frame must error");
        assert_ne!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn test_seen_transactions_cleanup() {
        // Test that old entries are evicted
        let seen = Arc::new(RwLock::new(HashMap::new()));

        let tx_bytes1 = vec![1u8, 2, 3, 4];
        let tx_bytes2 = vec![5u8, 6, 7, 8];

        // Insert one entry with old timestamp (use smaller duration to avoid overflow)
        {
            let mut seen_write = seen.write().await;
            let now = Instant::now();
            seen_write.insert(
                tx_bytes1.clone(),
                SeenTxEntry {
                    timestamp: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
                },
            );
            seen_write.insert(tx_bytes2.clone(), SeenTxEntry { timestamp: now });
        }

        // Simulate cleanup (remove entries older than 30 seconds)
        let now = Instant::now();
        {
            let mut seen_write = seen.write().await;
            seen_write.retain(|_, entry| {
                now.checked_duration_since(entry.timestamp)
                    .map_or(false, |d| d < Duration::from_secs(30))
            });
        }

        // Old entry should be removed, new entry should remain
        {
            let seen_read = seen.read().await;
            assert!(!seen_read.contains_key(&tx_bytes1));
            assert!(seen_read.contains_key(&tx_bytes2));
            assert_eq!(seen_read.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_seen_cache_bounded() {
        // insert_seen must keep the cache bounded: once at MAX_SEEN_TXS it
        // evicts before inserting.
        let seen = Arc::new(RwLock::new(HashMap::new()));

        // Fill past the cap with fresh entries (eviction removes one per insert
        // once the cap is reached).
        for i in 0..(MAX_SEEN_TXS + 100) {
            insert_seen(&seen, vec![(i % 256) as u8; 4]).await;
        }

        let size = seen.read().await.len();
        assert!(size <= MAX_SEEN_TXS);
    }

    #[tokio::test]
    async fn test_seen_cache_dedup_preserved_under_cap() {
        let seen = Arc::new(RwLock::new(HashMap::new()));
        let key = vec![7u8; 4];
        insert_seen(&seen, key.clone()).await;
        insert_seen(&seen, key.clone()).await;
        let map = seen.read().await;
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_limit_constants_sane() {
        // A 16 MiB frame cap + 400 msgs/s caps per-peer throughput at ~6.4 GiB/s
        // worst case, but more importantly caps single-allocation size.
        assert!(MAX_MESSAGE_SIZE <= 16 * 1024 * 1024);
        assert!(MAX_MSGS_PER_SEC >= 1);
        assert!(MAX_PEERS >= 1);
        assert!(MAX_INV_ITEMS >= 1);
    }

    /// H4/V-24: handshake identity check — a peer from another network
    /// (different genesis hash) or another protocol version must be rejected,
    /// while a same-network frame passes.
    #[test]
    fn test_handshake_identity_mismatch_rejected() {
        let mut frame = vec![0u8; HANDSHAKE_FRAME_LEN];
        frame[..4].copy_from_slice(&HANDSHAKE_MAGIC);
        frame[4] = P2P_PROTOCOL_VERSION;
        frame[5..37].copy_from_slice(&crate::genesis::GENESIS_HASH);

        // Correct same-network frame passes.
        assert!(
            P2PNetwork::verify_handshake_identity(&frame).is_ok(),
            "a same-network frame must pass"
        );

        // Wrong magic is rejected.
        let mut wrong_magic = frame.clone();
        wrong_magic[0] = 0x00;
        let err = P2PNetwork::verify_handshake_identity(&wrong_magic).unwrap_err();
        assert!(err.contains("magic"), "got: {}", err);

        // Version mismatch is rejected.
        let mut wrong_version = frame.clone();
        wrong_version[4] = P2P_PROTOCOL_VERSION + 1;
        let err = P2PNetwork::verify_handshake_identity(&wrong_version).unwrap_err();
        assert!(err.contains("version"), "got: {}", err);

        // Genesis (network) mismatch is rejected.
        let mut wrong_genesis = frame.clone();
        wrong_genesis[5] = 0x42;
        let err = P2PNetwork::verify_handshake_identity(&wrong_genesis).unwrap_err();
        assert!(err.contains("genesis"), "got: {}", err);

        // Truncated frame is rejected.
        assert!(P2PNetwork::verify_handshake_identity(&frame[..8]).is_err());
    }

    /// H4/V-24: two ends of the SAME network complete the X25519 handshake
    /// and derive the SAME session key.
    #[tokio::test]
    async fn test_handshake_derives_shared_key() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer);
        let (key_a, key_b) = tokio::join!(a, b);

        let key_a = key_a.expect("side A handshake must succeed");
        let key_b = key_b.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
    }

    #[tokio::test]
    async fn test_broadcast_marks_as_local() {
        // Test that broadcast_transaction marks tx as Local before sending
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            Arc::new(crate::sync_stats::SyncContext::default()),
            Arc::new(|_| false),
        );

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );

        let tx_bytes = bincode::serialize(&tx).unwrap();

        // Broadcast should mark as seen
        p2p.broadcast_transaction(tx.clone()).await;

        // Check that it's in seen_transactions
        let seen = p2p.seen_transactions.read().await;
        assert!(seen.contains_key(&tx_bytes));
    }

    /// B4: partition_batch must be ORDER-INDEPENDENT. A chain A->B->C->D is
    /// fully deliverable in parent-first order, and the same set in
    /// child-first order must yield the SAME deliverable set (parents first).
    #[test]
    fn test_partition_batch_order_independent() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [b.id, genesis]);
        let d = mk(4, [c.id, genesis]);

        // DAG already contains genesis (and nothing else): lookup by id.
        let has_in_dag = |id: &[u8]| -> Option<Transaction> {
            let ids: [[u8; 32]; 4] = [a.id, b.id, c.id, d.id];
            if ids.iter().any(|x| x.as_slice() == id) {
                None
            } else {
                Some(a.clone())
            }
        };
        let serialize = |tx: &Transaction| bincode::serialize(tx).unwrap();

        // Parent-first order: everything deliverable.
        let (del, wait) = P2PNetwork::partition_batch(
            vec![
                (serialize(&a), a.clone()),
                (serialize(&b), b.clone()),
                (serialize(&c), c.clone()),
                (serialize(&d), d.clone()),
            ],
            &has_in_dag,
        );
        assert_eq!(del.len(), 4, "parent-first chain must be fully deliverable");
        assert!(wait.is_empty());

        // Child-first order: the SAME deliverable set. The head (a) is
        // deliverable (parents = genesis); once inserted in-batch, b, c and d
        // unlock in the same passes -> identical partition, no orphans.
        let (del2, wait2) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
                (serialize(&a), a.clone()),
            ],
            &has_in_dag,
        );
        assert_eq!(del2.len(), 4, "child-first chain must also fully resolve");
        assert!(wait2.is_empty());
        let mut del_ids: Vec<[u8; 32]> = del.into_iter().map(|(_, t)| t.id).collect();
        let mut del2_ids: Vec<[u8; 32]> = del2.into_iter().map(|(_, t)| t.id).collect();
        del_ids.sort();
        del2_ids.sort();
        assert_eq!(
            del_ids, del2_ids,
            "deliverable set must be order-independent"
        );

        // Without the head (a missing from the DAG AND the batch): everything
        // waits. Parents are requested via the orphan flow instead.
        let (del3, wait3) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
            ],
            &has_in_dag,
        );
        assert!(del3.is_empty(), "no head -> nothing deliverable in-batch");
        assert_eq!(wait3.len(), 3, "all members wait for the missing parent");
    }

    /// B4: a diamond A->(B,C)->D: B and C are both deliverable once A is in
    /// the DAG; D waits for both.
    #[test]
    fn test_partition_batch_diamond() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [a.id, genesis]);
        let d = mk(4, [b.id, c.id]);

        let has_in_dag = |id: &[u8]| -> Option<Transaction> {
            let known: Vec<[u8; 32]> = vec![a.id, b.id, c.id, d.id];
            if known.iter().any(|x| x.as_slice() == id) {
                None
            } else {
                Some(a.clone())
            }
        };
        let serialize = |tx: &Transaction| bincode::serialize(tx).unwrap();

        // Arrive in worst order: D, C, B, A.
        let (del, wait) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
                (serialize(&a), a.clone()),
            ],
            &has_in_dag,
        );
        // After the passes: A deliverable (parents=genesis); then B and C
        // (parent A now inserted in-batch); D still waits for C/B? No: B and C
        // are inserted, so D becomes deliverable in the same pass chain.
        assert_eq!(del.len(), 4, "diamond must resolve fully in-batch");
        assert!(wait.is_empty());
    }

    /// B4: parent-request dedup. Two immediate requests for the same parent
    /// must produce ONE actual request; the second is counted as
    /// already-known (backoff).
    #[tokio::test]
    async fn test_request_transaction_dedup() {
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let ctx = Arc::new(crate::sync_stats::SyncContext::default());
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            ctx.clone(),
            Arc::new(|_| false),
        );

        let hash = vec![0xABu8; 32];
        p2p.request_transaction(hash.clone()).await;
        p2p.request_transaction(hash.clone()).await;
        p2p.request_transaction(hash).await;

        let snap = ctx.stats.snapshot();
        assert_eq!(snap.parent_requested, 1, "only the first request is sent");
        assert_eq!(
            snap.parent_already_known, 2,
            "repeats within the cooldown are deduplicated"
        );
    }
}
