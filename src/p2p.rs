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

/// P2P handshake magic bytes ("AETH")
const HANDSHAKE_MAGIC: [u8; 4] = [0x41, 0x45, 0x54, 0x48];

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
    source: TxSource,
}

/// Transaction source for better deduplication logic
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxSource {
    Local,   // Transaction created locally via RPC
    Network, // Transaction received from P2P network
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
    get_balance: Arc<dyn Fn(&[u8; 32]) -> u64 + Send + Sync>,
    save_dag: Arc<dyn Fn() + Send + Sync>,
    process_orphans: Arc<dyn Fn() + Send + Sync>,
    get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
}

impl P2PNetwork {
    /// Create a new P2P network manager
    pub fn new(
        config: P2PConfig,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_balance: Arc<dyn Fn(&[u8; 32]) -> u64 + Send + Sync>,
        save_dag: Arc<dyn Fn() + Send + Sync>,
        process_orphans: Arc<dyn Fn() + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    ) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            known_peers: Arc::new(RwLock::new(HashSet::new())),
            tx_channel,
            peer_discovery_tx: Arc::new(tokio::sync::Mutex::new(None)),
            get_dag_hashes,
            get_transaction_by_hash,
            get_balance,
            save_dag,
            process_orphans,
            get_tips,
            seen_transactions: Arc::new(RwLock::new(HashMap::new())),
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
        let get_balance = Arc::clone(&self.get_balance);
        let save_dag = Arc::clone(&self.save_dag);
        let process_orphans = Arc::clone(&self.process_orphans);
        let get_tips = Arc::clone(&self.get_tips);
        let seen_transactions = Arc::clone(&self.seen_transactions);
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
                get_balance,
                save_dag,
                process_orphans,
                get_tips,
                seen_transactions,
                peer_discovery_tx,
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
                            known_peers.write().await.insert(*addr);
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
        get_balance: Arc<dyn Fn(&[u8; 32]) -> u64 + Send + Sync>,
        save_dag: Arc<dyn Fn() + Send + Sync>,
        process_orphans: Arc<dyn Fn() + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
    ) {
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
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
                    let get_balance = Arc::clone(&get_balance);
                    let save_dag = Arc::clone(&save_dag);
                    let process_orphans = Arc::clone(&process_orphans);
                    let get_tips = Arc::clone(&get_tips);
                    let seen_transactions = Arc::clone(&seen_transactions);
                    let peer_discovery_tx = peer_discovery_tx.clone();
                    let known_peers = known_peers.clone();
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
                            get_balance,
                            save_dag,
                            process_orphans,
                            get_tips,
                            seen_transactions,
                            msg_sender,
                            msg_receiver,
                            peer_discovery_tx,
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

    /// Perform X25519 handshake and derive AES-256-GCM key
    async fn handshake(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
    ) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let our_secret = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_secret);

        let mut outgoing = Vec::with_capacity(36);
        outgoing.extend_from_slice(&HANDSHAKE_MAGIC);
        outgoing.extend_from_slice(our_public.as_bytes());
        writer.write_all(&outgoing).await?;

        let mut incoming = [0u8; 36];
        reader.read_exact(&mut incoming).await?;
        if incoming[..4] != HANDSHAKE_MAGIC {
            return Err("Invalid P2P handshake magic — not an Aether node".into());
        }

        let mut peer_pk_bytes = [0u8; 32];
        peer_pk_bytes.copy_from_slice(&incoming[4..]);
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
        get_balance: Arc<dyn Fn(&[u8; 32]) -> u64 + Send + Sync>,
        save_dag: Arc<dyn Fn() + Send + Sync>,
        process_orphans: Arc<dyn Fn() + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        msg_sender: mpsc::UnboundedSender<Vec<u8>>,
        msg_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
    ) {
        // Split socket into read and write halves
        let (mut reader, mut writer) = socket.into_split();

        // Perform encrypted handshake (X25519 key exchange)
        let key_bytes = match Self::handshake(&mut reader, &mut writer).await {
            Ok(k) => {
                info!("🔐 P2P encrypted handshake complete with {}", addr);
                k
            }
            Err(e) => {
                warn!("❌ P2P handshake failed with {}: {}", addr, e);
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

        // Mark peer as known
        known_peers.write().await.insert(addr);

        let mut recv_counter: u64 = 0;

        loop {
            // Read encrypted message length (4 bytes)
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Peer {} disconnected: {}", addr, e);
                    break;
                }
            }
            let total_len = u32::from_be_bytes(len_buf) as usize;
            if total_len < 12 {
                warn!("Peer {} sent invalid message length {}", addr, total_len);
                break;
            }

            // Read nonce (12 bytes)
            let mut nonce_buf = [0u8; 12];
            if reader.read_exact(&mut nonce_buf).await.is_err() {
                warn!("Failed to read nonce from {}", addr);
                break;
            }

            // Read ciphertext
            let ciphertext_len = total_len - 12;
            let mut ciphertext = vec![0u8; ciphertext_len];
            if reader.read_exact(&mut ciphertext).await.is_err() {
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
            recv_counter += 1;

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
                                seen_transactions.write().await.insert(
                                    tx_bytes.clone(),
                                    SeenTxEntry {
                                        timestamp: Instant::now(),
                                        source: TxSource::Network,
                                    },
                                );

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
                            // Determine which hashes we need
                            let our_hashes = get_dag_hashes();
                            let our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();
                            let missing_hashes: Vec<Vec<u8>> = hashes
                                .into_iter()
                                .filter(|h| !our_hash_set.contains(h))
                                .collect();

                            // Request missing transactions via GetData
                            if !missing_hashes.is_empty() {
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

                            // Find transactions we have that peer doesn't have (compare tips)
                            let peer_tips_set: HashSet<Vec<u8>> = peer_tips.into_iter().collect();
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
                            // Send requested transactions with pagination (max 100 per response)
                            const PAGE_SIZE: usize = 100;
                            let mut tx_bytes_list = Vec::new();

                            for hash in hashes.iter().take(PAGE_SIZE) {
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
                            // Download and add transactions in chronological order
                            let mut downloaded_count = 0;
                            let mut transactions: Vec<Transaction> = Vec::new();

                            for tx_bytes in tx_bytes_list {
                                // Deduplication check with new structure
                                {
                                    let seen = seen_transactions.read().await;
                                    if seen.contains_key(&tx_bytes) {
                                        continue;
                                    }
                                }

                                if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                    transactions.push(tx);
                                    downloaded_count += 1;
                                }
                            }

                            // Sort by timestamp (chronological order)
                            transactions.sort_by_key(|tx| tx.timestamp);

                            // Add to DAG via channel (full validation will be done in main.rs)
                            for tx in transactions {
                                if let Ok(tx_bytes) = bincode::serialize(&tx) {
                                    seen_transactions.write().await.insert(
                                        tx_bytes,
                                        SeenTxEntry {
                                            timestamp: Instant::now(),
                                            source: TxSource::Network,
                                        },
                                    );
                                }
                                let _ = tx_channel.send(tx);

                                // Throttle: wait 50ms after each transaction to let ledger breathe
                                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                            }

                            if downloaded_count > 0 {
                                info!(
                                    "[Sync] Downloaded {} missing transactions from {}",
                                    downloaded_count, addr
                                );
                                // Note: process_orphans is now handled by the validation logic in main.rs
                            }
                        }
                        P2PMessage::Ping => {
                            // Respond with pong - skip for now, need sender
                        }
                        P2PMessage::Pong => {
                            // Ignore pong
                        }
                        P2PMessage::Peers(peer_list) => {
                            let known = known_peers.read().await;
                            for peer_addr in &peer_list {
                                if !known.contains(peer_addr)
                                    && *peer_addr != local_addr
                                    && !peers.read().await.contains_key(peer_addr)
                                {
                                    known_peers.write().await.insert(*peer_addr);
                                    let _ = peer_discovery_tx.send(*peer_addr);
                                }
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

        match TcpStream::connect(addr).await {
            Ok(socket) => {
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
                let get_balance = Arc::clone(&self.get_balance);
                let save_dag = Arc::clone(&self.save_dag);
                let process_orphans = Arc::clone(&self.process_orphans);
                let get_tips = Arc::clone(&self.get_tips);
                let seen_transactions = Arc::clone(&self.seen_transactions);
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
                        get_balance,
                        save_dag,
                        process_orphans,
                        get_tips,
                        seen_transactions,
                        msg_sender,
                        msg_receiver,
                        peer_discovery_tx,
                    )
                    .await;
                });
            }
            Err(e) => {
                warn!("Failed to connect to {}: {}", addr, e);
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
        self.seen_transactions.write().await.insert(
            tx_bytes.clone(),
            SeenTxEntry {
                timestamp: Instant::now(),
                source: TxSource::Local,
            },
        );

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

    /// Request a specific transaction by hash from all peers
    pub async fn request_transaction(&self, hash: Vec<u8>) {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transaction;
    use tokio::sync::mpsc;

    #[test]
    fn test_seen_tx_entry_source() {
        // Test that TxSource enum works correctly
        let local = TxSource::Local;
        let network = TxSource::Network;

        assert_eq!(local, TxSource::Local);
        assert_eq!(network, TxSource::Network);
        assert_ne!(local, network);
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
                    source: TxSource::Network,
                },
            );
        }

        // Check that it's present
        {
            let seen_read = seen.read().await;
            assert!(seen_read.contains_key(&tx_bytes));
            let entry = seen_read.get(&tx_bytes).unwrap();
            assert_eq!(entry.source, TxSource::Network);
        }

        // Second insert should not duplicate (just update)
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                    source: TxSource::Local,
                },
            );
        }

        // Should still be only one entry
        {
            let seen_read = seen.read().await;
            assert_eq!(seen_read.len(), 1);
            let entry = seen_read.get(&tx_bytes).unwrap();
            // Source should be updated to Local
            assert_eq!(entry.source, TxSource::Local);
        }
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
                    source: TxSource::Network,
                },
            );
            seen_write.insert(
                tx_bytes2.clone(),
                SeenTxEntry {
                    timestamp: now,
                    source: TxSource::Local,
                },
            );
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
    async fn test_broadcast_marks_as_local() {
        // Test that broadcast_transaction marks tx as Local before sending
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|_| 0),
            Arc::new(|| {}),
            Arc::new(|| {}),
            Arc::new(|| vec![]),
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

        // Broadcast should mark as Local
        p2p.broadcast_transaction(tx.clone()).await;

        // Check that it's marked as Local in seen_transactions
        let seen = p2p.seen_transactions.read().await;
        assert!(seen.contains_key(&tx_bytes));
        let entry = seen.get(&tx_bytes).unwrap();
        assert_eq!(entry.source, TxSource::Local);
    }
}
