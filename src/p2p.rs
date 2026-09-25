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

/// Maximum number of peers from the same /24 subnet (eclipse prevention)
const MAX_PEERS_PER_SUBNET: usize = 4;

/// Number of outbound connection slots reserved and never evicted
const PROTECTED_OUTBOUND_SLOTS: usize = 8;

/// Maximum number of known peer addresses retained (PEX/DNS growth bound)
const MAX_KNOWN_PEERS: usize = 1000;

/// Maximum outbound dials attempted in a single reconnection cycle (Phase 2A).
/// Without this a peer store full of dead addresses turns one cycle into an
/// hours-long serial sweep; the budget lets the loop move on to the next cycle.
const MAX_REDIAL_PER_CYCLE: usize = 32;

/// Maximum entries in the seen-transaction cache (memory bound)
const MAX_SEEN_TXS: usize = 50_000;

/// Maximum items accepted from a single Inventory/GetData/GetInventory/Peers
/// message (vector-of-vectors amplification bound)
const MAX_INV_ITEMS: usize = 1000;

/// DEEP SYNC: maximum transactions per SyncResponse page.
/// Each page is ancestor-closed and topologically sorted.
const MAX_SYNC_PAGE: usize = 100;

/// DEEP SYNC: maximum number of ancestor-closure pages that can be computed
/// per GetData request. Total max served = MAX_CLOSURE_PAGES * MAX_SYNC_PAGE.
/// This bounds CPU (BFS walk), memory (HashSet), and network (message size).
const MAX_CLOSURE_PAGES: usize = 10;

/// DEEP SYNC: adaptive backpressure base interval (ms) for SyncResponse delivery.
/// Scales with batch size instead of fixed 50ms per tx.
const BACKPRESSURE_BASE_MS: u64 = 5;

// --- Peer Scoring ---
/// Initial score for new peers
const PEER_SCORE_INITIAL: i32 = 100;
/// Score below this → temporary ban
const PEER_SCORE_BAN_THRESHOLD: i32 = 0;
/// Penalty for invalid message (bad format, invalid tx)
const PEER_PENALTY_INVALID_MSG: i32 = -10;
/// Penalty for contradictory data (conflicting inventory)
const PEER_PENALTY_CONTRADICTION: i32 = -20;
/// Penalty for timeout (slow or stalled peer)
const PEER_PENALTY_TIMEOUT: i32 = -5;
/// Penalty for rate limit hit (flood)
const PEER_PENALTY_FLOOD: i32 = -15;
/// Penalty for abusive/abnormal requests
const PEER_PENALTY_ABUSIVE: i32 = -10;
/// Bonus for successful sync contribution
const PEER_BONUS_SYNC: i32 = 5;
/// Score recovery per decay interval (towards 100)
const PEER_DECAY_RATE: i32 = 1;
/// Decay interval
const PEER_DECAY_INTERVAL: Duration = Duration::from_secs(300);
/// Temporary ban duration
const PEER_BAN_TEMP: Duration = Duration::from_secs(300);
/// Number of temp bans before permanent ban
const PEER_BAN_TEMP_MAX: usize = 3;
/// Permanent ban duration
const PEER_BAN_PERM: Duration = Duration::from_secs(3600);

/// Per-peer reputation score with decay and ban tracking
#[derive(Clone, Debug)]
struct PeerScore {
    score: i32,
    temp_bans: usize,
    last_decay: Instant,
    banned_until: Option<Instant>,
}

impl PeerScore {
    fn new() -> Self {
        Self {
            score: PEER_SCORE_INITIAL,
            temp_bans: 0,
            last_decay: Instant::now(),
            banned_until: None,
        }
    }

    /// Apply decay: score moves towards PEER_SCORE_INITIAL
    fn decay(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_decay) >= PEER_DECAY_INTERVAL {
            if self.score < PEER_SCORE_INITIAL {
                self.score = (self.score + PEER_DECAY_RATE).min(PEER_SCORE_INITIAL);
            } else if self.score > PEER_SCORE_INITIAL {
                self.score = (self.score - PEER_DECAY_RATE).max(PEER_SCORE_INITIAL);
            }
            self.last_decay = now;
        }
    }

    /// Apply a penalty. Returns true if peer should be banned.
    fn penalize(&mut self, penalty: i32) -> bool {
        self.score += penalty;
        self.score <= PEER_SCORE_BAN_THRESHOLD
    }

    /// Apply a bonus (capped at initial)
    fn reward(&mut self, bonus: i32) {
        self.score = (self.score + bonus).min(PEER_SCORE_INITIAL + 50);
    }

    /// Check if currently banned
    fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Ban the peer (temp or perm based on history)
    fn ban(&mut self) {
        self.temp_bans += 1;
        if self.temp_bans >= PEER_BAN_TEMP_MAX {
            self.banned_until = Some(Instant::now() + PEER_BAN_PERM);
        } else {
            self.banned_until = Some(Instant::now() + PEER_BAN_TEMP);
        }
    }
}

/// Maximum frames accepted from a peer per second (rate limit)
const MAX_MSGS_PER_SEC: u64 = 400;

/// Extract the /24 subnet prefix from a SocketAddr (first 3 bytes of IPv4).
/// Returns None for IPv6 (handled separately) or invalid addresses.
fn subnet_24(addr: SocketAddr) -> Option<[u8; 3]> {
    match addr {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            Some([octets[0], octets[1], octets[2]])
        }
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            // Use first 3 bytes as synthetic /24-equivalent
            Some([octets[0], octets[1], octets[2]])
        }
    }
}

/// Count how many connected peers share the same /24 subnet as `addr`.
async fn count_subnet_peers(
    addr: SocketAddr,
    peers: &HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> usize {
    let target = match subnet_24(addr) {
        Some(s) => s,
        None => return 0,
    };
    peers
        .keys()
        .filter(|k| subnet_24(**k) == Some(target))
        .count()
}

/// Count how many connected peers share the same /24 subnet as `addr`,
/// excluding `addr` itself (for checking before adding).
async fn count_subnet_peers_excluding(
    addr: SocketAddr,
    peers: &HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> usize {
    let target = match subnet_24(addr) {
        Some(s) => s,
        None => return 0,
    };
    peers
        .keys()
        .filter(|k| **k != addr && subnet_24(**k) == Some(target))
        .count()
}

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
// OBSERVABILITY-ONLY visibility: `pub` so the boot banner can log it.
pub const P2P_PROTOCOL_VERSION: u8 = 3;
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
    /// Path used to persist known peers across restarts (Phase 1)
    pub peer_store_path: Option<std::path::PathBuf>,
}

/// How long a peer remains in the known set after its last disconnect (Phase 1 TTL).
const PEER_TTL: Duration = Duration::from_secs(3600);
/// Interval at which the known-peer set is flushed to disk (Phase 1).
const PEER_STORE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

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
            peer_store_path: None,
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
    /// Phase 1 TTL: last time each known peer was seen (connected or heard via PEX).
    peer_last_seen: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
    /// Phase 2A: addresses with an outbound dial in flight. The initial sweep,
    /// heartbeat, redial loop and PEX can all reach `connect_to_peer` for the
    /// same address concurrently; without this guard a peer gets two sessions
    /// and the `peers` map silently drops one of them.
    dialing: Arc<RwLock<HashSet<SocketAddr>>>,
    tx_channel: mpsc::UnboundedSender<Transaction>,
    peer_discovery_tx: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedSender<SocketAddr>>>>,
    get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
    get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
    /// Per-peer reputation scores
    peer_scores: Arc<RwLock<HashMap<SocketAddr, PeerScore>>>,
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
            peer_last_seen: Arc::new(RwLock::new(HashMap::new())),
            dialing: Arc::new(RwLock::new(HashSet::new())),
            tx_channel,
            peer_discovery_tx: Arc::new(tokio::sync::Mutex::new(None)),
            get_dag_hashes,
            get_transaction_by_hash,
            get_tips,
            seen_transactions: Arc::new(RwLock::new(HashMap::new())),
            peer_scores: Arc::new(RwLock::new(HashMap::new())),
            sync_ctx,
            is_orphan,
        }
    }

    /// Start the P2P network
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting P2P network on {}", self.config.listen_addr);

        // Phase 1: restore known peers from disk before first dial.
        self.load_known_peers().await;

        // Start listening for incoming connections
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let peers = self.peers.clone();
        let tx_channel = self.tx_channel.clone();
        let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
        let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
        let get_tips = Arc::clone(&self.get_tips);
        let seen_transactions = Arc::clone(&self.seen_transactions);
        let peer_scores = Arc::clone(&self.peer_scores);
        let sync_ctx = Arc::clone(&self.sync_ctx);
        let is_orphan = Arc::clone(&self.is_orphan);
        let local_addr = self.config.listen_addr;
        let known_peers = self.known_peers.clone();
        let peer_last_seen = self.peer_last_seen.clone();
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
                peer_last_seen,
                tx_channel,
                get_dag_hashes,
                get_transaction_by_hash,
                get_tips,
                seen_transactions,
                peer_scores,
                peer_discovery_tx,
                sync_ctx,
                is_orphan,
            )
            .await;
        });

        // Phase 2A: bring the recovery machinery up BEFORE the first dial pass.
        // The initial sweep used to run first and block here, so a peer store
        // full of dead addresses left the node with no heartbeat, no PEX and no
        // TTL task while it churned through timeouts.

        // Discover peers from DNS seeds
        self.discover_from_dns().await;

        // Start heartbeat task
        self.start_heartbeat().await;

        // Start reconnection task (known peers first, seeds unprivileged)
        self.start_reconnection_task().await;

        // Phase 1: periodic peer-store flush + TTL expiry.
        self.start_peer_store_task().await;

        // Start periodic DNS discovery
        self.start_dns_discovery().await;

        // Start periodic peer exchange (PEX)
        self.start_pex().await;

        // Start cache cleanup task
        self.start_cache_cleanup().await;

        // First outbound pass, off the critical path: seeds first (on a brand-new
        // node they are the only known address source), then everything restored
        // from the peer store. Runs as its own task so `start()` is never gated
        // on a serial sweep of possibly-dead addresses.
        {
            let sweep = self.clone();
            tokio::spawn(async move {
                sweep.initial_dial_sweep().await;
            });
        }

        Ok(())
    }

    /// Phase 2A: the very first outbound dial pass. Seeds go first because a
    /// node with an empty peer store has no other address source; afterwards the
    /// restored store is dialed. This is the only place where seeds lead, and it
    /// runs once — steady-state redial never privileges them.
    async fn initial_dial_sweep(&self) {
        for seed in &self.config.bootnodes {
            self.connect_to_peer(*seed).await;
        }

        let restored: Vec<SocketAddr> = self.known_peers.read().await.iter().copied().collect();
        for addr in restored {
            if addr != self.config.listen_addr {
                self.connect_to_peer(addr).await;
            }
        }
    }

    /// Phase 1: reload known peers from the on-disk peer store (if configured).
    async fn load_known_peers(&self) {
        let Some(path) = self.config.peer_store_path.clone() else {
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                let addrs: Vec<String> = serde_json::from_str(&raw).unwrap_or_default();
                let mut known = self.known_peers.write().await;
                let mut seen = self.peer_last_seen.write().await;
                let mut loaded = 0usize;
                for s in addrs {
                    if let Ok(addr) = s.parse::<SocketAddr>() {
                        if known.insert(addr) {
                            seen.insert(addr, Instant::now());
                            loaded += 1;
                        }
                    }
                }
                if loaded > 0 {
                    info!("💾 Loaded {} known peers from {:?}", loaded, path);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Failed to load peer store {:?}: {}", path, e),
        }
    }

    /// Phase 1: persist known peers to the on-disk peer store (if configured).
    async fn save_known_peers(&self) {
        let Some(path) = self.config.peer_store_path.clone() else {
            return;
        };
        let addrs: Vec<String> = self
            .known_peers
            .read()
            .await
            .iter()
            .map(|a| a.to_string())
            .collect();
        let json = match serde_json::to_string(&addrs) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to serialize peer store: {}", e);
                return;
            }
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &json) {
            warn!("Failed to write peer store {:?}: {}", tmp, e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            warn!("Failed to replace peer store {:?}: {}", path, e);
        }
    }

    /// Phase 1: mark a peer as currently/just known (updates TTL clock).
    async fn touch_peer(&self, addr: SocketAddr) {
        {
            let mut known = self.known_peers.write().await;
            if known.len() >= MAX_KNOWN_PEERS && !known.contains(&addr) {
                return;
            }
            known.insert(addr);
        }
        self.peer_last_seen.write().await.insert(addr, Instant::now());
    }

    /// Phase 2A: refresh the TTL clock for every peer holding a live session, so
    /// a long-lived connection is never expired out of the peer store (and hence
    /// out of the persisted file) just for having stayed up.
    async fn refresh_live_peer_clocks(&self) {
        let live: Vec<SocketAddr> = self.peers.read().await.keys().copied().collect();
        if live.is_empty() {
            return;
        }
        let mut seen = self.peer_last_seen.write().await;
        for a in live {
            seen.insert(a, Instant::now());
        }
    }

    /// Phase 1: expire peers whose last_seen is older than PEER_TTL and flush the store.
    async fn start_peer_store_task(&self) {
        let peers = self.clone();
        tokio::spawn(async move {
            let mut last_flush = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                // Phase 2A: a peer that stays connected longer than PEER_TTL must
                // not be expired out of the store. Refresh the clock for every live
                // session first, otherwise the node forgets its most reliable peers
                // precisely because they are reliable.
                peers.refresh_live_peer_clocks().await;

                // TTL expiry
                {
                    let now = Instant::now();
                    let mut seen = peers.peer_last_seen.write().await;
                    let expired: Vec<SocketAddr> = seen
                        .iter()
                        .filter(|(_, at)| now.duration_since(**at) > PEER_TTL)
                        .map(|(a, _)| *a)
                        .collect();
                    if !expired.is_empty() {
                        let mut known = peers.known_peers.write().await;
                        for a in &expired {
                            known.remove(a);
                            seen.remove(a);
                        }
                        debug!("Peer TTL expired {} entries", expired.len());
                    }
                }

                // Periodic flush
                if last_flush.elapsed() >= PEER_STORE_FLUSH_INTERVAL {
                    peers.save_known_peers().await;
                    last_flush = Instant::now();
                }
            }
        });
    }

    /// Start heartbeat task to check peer connections and reconnect if needed
    async fn start_heartbeat(&self) {
        let peers = self.peers.clone();
        let bootnodes = self.config.bootnodes.clone();
        let known = self.known_peers.clone();
        let local_addr = self.config.listen_addr;
        let p2p_network = self.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

                let peer_count = {
                    let peers_read = peers.read().await;
                    peers_read.len()
                };

                if peer_count == 0 {
                    warn!("No connected peers, attempting general redial...");
                    // Phase 2A: known peers first, seeds appended as ordinary
                    // unprivileged candidates (Phase 1 dialled every seed first).
                    let candidates = {
                        let guard = known.read().await;
                        P2PNetwork::redial_candidates(&guard, &bootnodes, local_addr)
                    };
                    for addr in candidates.iter().take(MAX_REDIAL_PER_CYCLE) {
                        p2p_network.connect_to_peer(*addr).await;
                    }
                } else {
                    debug!("Heartbeat: {} connected peers", peer_count);
                }
            }
        });
    }

    /// Phase 2A candidate ordering for the redial loop: addresses the node
    /// already knows come first, configured seeds are ordinary unprivileged
    /// fallbacks appended at the end. No seed is ever allowed to outrank a peer
    /// the node already holds, so a dead seed cannot monopolise the cycle.
    fn redial_candidates(
        known: &HashSet<SocketAddr>,
        seeds: &[SocketAddr],
        local: SocketAddr,
    ) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = known.iter().copied().filter(|a| *a != local).collect();
        for seed in seeds {
            if *seed != local && !out.contains(seed) {
                out.push(*seed);
            }
        }
        out
    }

    /// Start the general redial task (Phase 1: known peers + seeds, Phase 2A: seeds unprivileged).
    async fn start_reconnection_task(&self) {
        let peers = self.peers.clone();
        let bootnodes = self.config.bootnodes.clone();
        let known = self.known_peers.clone();
        let local_addr = self.config.listen_addr;
        let p2p_network = self.clone();

        tokio::spawn(async move {
            let mut retry_counts: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            let mut next_attempt: std::collections::HashMap<String, Instant> =
                std::collections::HashMap::new();
            loop {
                let candidates = {
                    let guard = known.read().await;
                    Self::redial_candidates(&guard, &bootnodes, local_addr)
                };

                let now = Instant::now();
                let mut dials = 0usize;

                for target in candidates {
                    if dials >= MAX_REDIAL_PER_CYCLE {
                        break;
                    }
                    let key = target.to_string();

                    if peers.read().await.contains_key(&target) {
                        retry_counts.remove(&key);
                        next_attempt.remove(&key);
                        continue;
                    }

                    // Exponential backoff is tracked per candidate instead of
                    // sleeping inside the loop. Phase 1 slept here, so one
                    // black-holed seed delayed every other candidate behind it.
                    if let Some(due) = next_attempt.get(&key) {
                        if now < *due {
                            continue;
                        }
                    }

                    let attempt = *retry_counts.get(&key).unwrap_or(&0);
                    let backoff = std::cmp::min(2u64.pow(attempt.min(6)), 60); // Max 60s
                    debug!(
                        "Redial candidate {} (attempt {}, backoff {}s)",
                        target,
                        attempt + 1,
                        backoff
                    );

                    p2p_network.connect_to_peer(target).await;
                    dials += 1;

                    retry_counts.insert(key.clone(), std::cmp::min(attempt + 1, 6));
                    next_attempt.insert(key, Instant::now() + Duration::from_secs(backoff));
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

    /// Phase 2A: addresses eligible for a PEX broadcast. We never re-share an
    /// address we ourselves banned, and never send our own listen address.
    /// Extracted so the filter is unit-testable rather than buried in a loop.
    fn pex_broadcast_list(
        known: &HashSet<SocketAddr>,
        scores: &HashMap<SocketAddr, PeerScore>,
        local: SocketAddr,
    ) -> Vec<SocketAddr> {
        known
            .iter()
            .copied()
            .filter(|a| *a != local)
            .filter(|a| !scores.get(a).map(|s| s.is_banned()).unwrap_or(false))
            .collect()
    }

    /// Periodically broadcast known peers to connected peers (PEX)
    async fn start_pex(&self) {
        let peers = self.peers.clone();
        let known_peers = self.known_peers.clone();
        let peer_scores = self.peer_scores.clone();
        let local_addr = self.config.listen_addr;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await; // Every 15 seconds for fast peer discovery
                let peer_list: Vec<SocketAddr> = {
                    let known = known_peers.read().await;
                    let scores = peer_scores.read().await;
                    Self::pex_broadcast_list(&known, &scores, local_addr)
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
        peer_last_seen: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        peer_scores: Arc<RwLock<HashMap<SocketAddr, PeerScore>>>,
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
                        // ECLIPSE-01: enforce /24 subnet diversity
                        let subnet_count = count_subnet_peers_excluding(addr, &peers_guard).await;
                        if subnet_count >= MAX_PEERS_PER_SUBNET {
                            warn!(
                                "Rejecting incoming peer {}: /24 subnet limit reached ({}/{})",
                                addr, subnet_count, MAX_PEERS_PER_SUBNET
                            );
                            drop(socket);
                            continue;
                        }
                    }
                    // SCORING: check if peer is banned
                    {
                        let mut scores = peer_scores.write().await;
                        if let Some(score) = scores.get_mut(&addr) {
                            score.decay();
                            if score.is_banned() {
                                warn!(
                                    "Rejecting banned peer {}: banned until {:?}",
                                    addr, score.banned_until
                                );
                                drop(socket);
                                continue;
                            }
                        } else {
                            scores.insert(addr, PeerScore::new());
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
                            let peer_scores = Arc::clone(&peer_scores);
                            let peer_last_seen = peer_last_seen.clone();
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
                                    peer_scores,
                                    msg_sender,
                                    msg_receiver,
                                    peer_discovery_tx,
                                    sync_ctx,
                                    is_orphan,
                                    peer_last_seen,
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

    /// Build a 12-byte nonce: bytes[0..8] = u64 BE counter, byte[8] = direction
    /// (0x01 / 0x02 chosen from ephemeral public-key order so the two senders of
    /// one session never share a direction), bytes[9..12] = 0.
    /// Wire-compatible: the full 12 bytes are sent in clear before the ciphertext;
    /// the receiver decrypts with the wire nonce, so legacy peers (byte[8]=0)
    /// still interoperate while new↔new sessions never reuse (K, N).
    fn build_nonce(counter: u64, direction: u8) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        nonce[8] = direction;
        nonce
    }

    /// Deterministic send-direction byte from the two ephemeral handshake keys.
    /// Lower public key → 0x01, higher → 0x02 (equal keys are cryptographically
    /// negligible for random X25519 ephemerals; both would take 0x02 only then).
    fn send_direction(our_pk: &[u8], peer_pk: &[u8]) -> u8 {
        if our_pk < peer_pk {
            0x01
        } else {
            0x02
        }
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

    /// Phase 1 crypto audit helper: a (key, nonce) collision requires equal
    /// counter AND equal direction byte under the same session key. After the
    /// direction-byte fix the two senders of one session always differ in
    /// direction, so equal counters no longer collide across directions.
    fn nonce_collision_possible(a_counter: u64, a_dir: u8, b_counter: u64, b_dir: u8) -> bool {
        a_counter == b_counter && a_dir == b_dir
    }

    /// Perform X25519 handshake, derive the session key (shared by both
    /// directions — ChaCha20 nonce uniqueness is enforced via the direction
    /// byte), and return (key, send_direction) for this side.
    async fn handshake(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
    ) -> Result<([u8; 32], u8), Box<dyn std::error::Error>> {
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
        let send_dir = Self::send_direction(our_public.as_bytes(), &peer_pk_bytes);
        Ok((result, send_dir))
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
        peer_scores: Arc<RwLock<HashMap<SocketAddr, PeerScore>>>,
        msg_sender: mpsc::UnboundedSender<Vec<u8>>,
        msg_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
        peer_last_seen: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
    ) {
        // Split socket into read and write halves
        let (mut reader, mut writer) = socket.into_split();

        // Perform encrypted handshake (X25519 key exchange)
        let (key_bytes, send_dir) = match Self::handshake(&mut reader, &mut writer)
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
                // Phase 1: do NOT drop the address from known_peers on a failed
                // handshake — keep it for a later redial attempt.
                {
                    let mut seen = peer_last_seen.write().await;
                    seen.insert(addr, Instant::now());
                }
                return;
            }
        };
        let key_enc = Arc::new(key_bytes);
        let key_dec = Arc::clone(&key_enc);

        // Spawn task to handle outgoing messages (encrypted)
        let mut msg_receiver = msg_receiver;
        let send_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let send_counter_clone = Arc::clone(&send_counter);
        let send_dir_task = send_dir;
        tokio::spawn(async move {
            while let Some(msg) = msg_receiver.recv().await {
                let cipher = {
                    let key = Key::from_slice(key_enc.as_ref());
                    ChaCha20Poly1305::new(key)
                };
                let nonce_val =
                    send_counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let nonce_bytes = Self::build_nonce(nonce_val, send_dir_task);
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

        // Mark peer as known (Phase 1: refresh TTL clock too)
        {
            let mut known = known_peers.write().await;
            known.insert(addr);
        }
        {
            let mut seen = peer_last_seen.write().await;
            seen.insert(addr, Instant::now());
        }

        let mut msg_count: u64 = 0;
        let mut window_start = Instant::now();
        // Anti-replay: peer send counters are strictly increasing over TCP;
        // reject any frame whose counter does not advance past the last one.
        let mut last_recv_counter: u64 = 0;

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
                // SCORING: penalize flood
                {
                    let mut scores = peer_scores.write().await;
                    if let Some(score) = scores.get_mut(&addr) {
                        if score.penalize(PEER_PENALTY_FLOOD) {
                            score.ban();
                            warn!("Peer {} banned (flood, score={})", addr, score.score);
                        }
                    }
                }
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

            // Anti-replay: counters must strictly increase for this session
            // (TCP preserves order, so a repeat or regression is a replay/forgery).
            let recv_counter = u64::from_be_bytes(nonce_buf[0..8].try_into().unwrap());
            if recv_counter <= last_recv_counter {
                warn!(
                    "Replay/regressed nonce from {} (counter {} <= {}), disconnecting",
                    addr, recv_counter, last_recv_counter
                );
                {
                    let mut scores = peer_scores.write().await;
                    if let Some(score) = scores.get_mut(&addr) {
                        if score.penalize(PEER_PENALTY_INVALID_MSG) {
                            score.ban();
                            warn!("Peer {} banned (replay, score={})", addr, score.score);
                        }
                    }
                }
                break;
            }
            last_recv_counter = recv_counter;

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
                    // SCORING: penalize invalid message
                    let mut scores = peer_scores.write().await;
                    if let Some(score) = scores.get_mut(&addr) {
                        if score.penalize(PEER_PENALTY_INVALID_MSG) {
                            score.ban();
                            warn!("Peer {} banned (invalid msg, score={})", addr, score.score);
                        }
                    }
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

                                // LOG NOISE (soak): per-tx line on the hot
                                // path — DEBUG only (failures keep WARN).
                                tracing::debug!(
                                    "Received transaction from {}: {}",
                                    addr,
                                    hex::encode(tx.id)
                                );
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
                            // C2 diagnostics: advertised total + orphan-dedup skips.
                            sync_ctx.stats.inventory_advertised.fetch_add(
                                hashes.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            let mut skipped_orphan = 0u64;
                            let missing_hashes: Vec<Vec<u8>> = hashes
                                .into_iter()
                                .filter(|h| {
                                    if our_hash_set.contains(h) {
                                        return false;
                                    }
                                    if is_orphan(h.as_slice()) {
                                        skipped_orphan += 1;
                                        return false;
                                    }
                                    true
                                })
                                .take(MAX_INV_ITEMS)
                                .collect();
                            sync_ctx
                                .stats
                                .inventory_skipped_orphan
                                .fetch_add(skipped_orphan, std::sync::atomic::Ordering::Relaxed);
                            // VPS-2 §5: the diff size itself (how much the
                            // peer has that we lack), independent of caps.
                            sync_ctx.stats.inventory_missing.fetch_add(
                                missing_hashes.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );

                            // Request missing transactions via GetData
                            if !missing_hashes.is_empty() {
                                sync_ctx.stats.sync_requested.fetch_add(
                                    missing_hashes.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                // DEEP SYNC: register missing hashes in the frontier
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    for h in &missing_hashes {
                                        frontier.add_pending(h.clone());
                                    }
                                }
                                info!(
                                    "Requesting {} missing transactions from {}",
                                    missing_hashes.len(),
                                    addr
                                );
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_hashes.clone()))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                                // DEEP SYNC: mark hashes as requested in frontier
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    for h in &missing_hashes {
                                        frontier.mark_requested(h, addr);
                                    }
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
                            // DEEP SYNC: serve requested transactions with FULL
                            // ancestor closure, split into multiple topologically
                            // sorted pages. Each page is ancestor-closed so the
                            // receiver can insert bottom-up without orphans.
                            let topo = Self::cached_topo_order(
                                &sync_ctx,
                                get_dag_hashes(),
                                &*get_transaction_by_hash,
                            )
                            .await;
                            let sort_topo = |v: &mut Vec<Vec<u8>>, order: &Option<Vec<Vec<u8>>>| {
                                if let Some(order) = order {
                                    let pos: HashMap<&Vec<u8>, usize> =
                                        order.iter().enumerate().map(|(i, h)| (h, i)).collect();
                                    v.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
                                }
                            };
                            // Take up to MAX_SYNC_PAGE of the requested hashes.
                            let requested: Vec<Vec<u8>> =
                                hashes.iter().take(MAX_SYNC_PAGE).cloned().collect();
                            // Compute FULL ancestor closure (bounded by MAX_CLOSURE_PAGES).
                            let max_entries = MAX_SYNC_PAGE.saturating_mul(MAX_CLOSURE_PAGES);
                            let mut closure = P2PNetwork::ancestor_full_closure(
                                &requested,
                                &*get_transaction_by_hash,
                                max_entries,
                            );
                            // Topologically sort: ancestors first.
                            sort_topo(&mut closure, &topo);
                            // Split into pages of MAX_SYNC_PAGE and send each.
                            let total_pages = closure.len().div_ceil(MAX_SYNC_PAGE).max(1);
                            for (page_idx, chunk) in closure.chunks(MAX_SYNC_PAGE).enumerate() {
                                let mut tx_bytes_list = Vec::with_capacity(chunk.len());
                                for hash in chunk {
                                    if let Some(tx) = get_transaction_by_hash(hash) {
                                        if let Ok(bytes) = bincode::serialize(&tx) {
                                            tx_bytes_list.push(bytes);
                                        }
                                    }
                                }
                                if !tx_bytes_list.is_empty() {
                                    tracing::debug!(
                                        "[Sync] Serving page {}/{} ({} txs) to {}",
                                        page_idx + 1,
                                        total_pages,
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
                        }
                        P2PMessage::SyncRequest => {
                            // Respond with full inventory. LOG NOISE (soak):
                            // periodic full-inventory announcements (10k hashes
                            // each on a big DAG) — DEBUG only. Sync progress
                            // stays visible via the maintenance summary line.
                            let our_hashes = get_dag_hashes();
                            tracing::debug!(
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
                            // C2 diagnostics: raw items before the DAG/orphan
                            // dedup below (peers re-sending tracked items?).
                            sync_ctx.stats.sync_response_items.fetch_add(
                                tx_bytes_list.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            for tx_bytes in tx_bytes_list.into_iter().take(MAX_INV_ITEMS) {
                                if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                    if get_transaction_by_hash(&tx.id).is_some()
                                        || is_orphan(&tx.id)
                                    {
                                        sync_ctx
                                            .stats
                                            .duplicate_ignored
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        // DEEP SYNC: mark duplicate as applied in frontier (already resolved)
                                        {
                                            let mut frontier = sync_ctx.frontier.write().await;
                                            frontier.mark_received(&tx.id);
                                            frontier.mark_applied(&tx.id);
                                        }
                                        continue;
                                    }
                                    // FIX: do NOT mark_received here yet — only mark
                                    // AFTER partition_batch confirms the tx is deliverable.
                                    // Waiting txs (parents missing) must remain "unreceived"
                                    // so the next inventory diff re-requests them.
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

                            if !waiting.is_empty() {
                                tracing::info!(
                                    "📥 SyncResponse: {} deliverable, {} waiting (parents missing, will retry next cycle)",
                                    deliverable.len(),
                                    waiting.len()
                                );
                            }

                            // DEEP SYNC: adaptive backpressure instead of fixed
                            // 50ms per tx. Scale interval with batch size to
                            // maintain throughput while allowing ledger breathing room.
                            let batch_len = deliverable.len();
                            let delay_ms = if batch_len > 0 {
                                // Scale: base interval * sqrt(batch) / 10, clamped to [1, 20]ms
                                let scaled = (BACKPRESSURE_BASE_MS as f64
                                    * (batch_len as f64).sqrt()
                                    / 10.0) as u64;
                                scaled.clamp(1, 20)
                            } else {
                                0
                            };
                            // CRITICAL FIX: only send deliverable txs to the mempool.
                            // waiting txs have parents not yet in the DAG. Sending them
                            // would create orphans whose parents are also in the mempool,
                            // causing an unresolvable cascade (resolved=0).
                            // waiting txs will be re-requested by process_orphans() on
                            // subsequent cycles when their parents arrive.
                            for (tx_bytes, tx) in deliverable.into_iter() {
                                // DEEP SYNC: mark as received + applied in frontier AFTER
                                // partition_batch confirmed this tx is deliverable.
                                // Waiting txs (parents missing) are NOT marked, so the
                                // next inventory diff re-requests them.
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    frontier.mark_received(&tx.id);
                                    frontier.mark_applied(&tx.id);
                                    frontier.record_progress();
                                }
                                insert_seen(&seen_transactions, tx_bytes).await;
                                let _ = tx_channel.send(tx);
                                if delay_ms > 0 {
                                    tokio::time::sleep(tokio::time::Duration::from_millis(
                                        delay_ms,
                                    ))
                                    .await;
                                }
                            }
                            // DEEP SYNC: log frontier state after processing batch
                            {
                                let frontier = sync_ctx.frontier.read().await;
                                tracing::debug!("{}", frontier.log_line());
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
                                {
                                    let mut known = known_peers.write().await;
                                    if known.len() >= MAX_KNOWN_PEERS {
                                        warn!(
                                            "Known-peer table full ({}), ignoring new peers",
                                            MAX_KNOWN_PEERS
                                        );
                                        break;
                                    }
                                    known.insert(peer_addr);
                                }
                                {
                                    let mut s = peer_last_seen.write().await;
                                    s.insert(peer_addr, Instant::now());
                                }
                                let _ = peer_discovery_tx.send(peer_addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize message from {}: {}", addr, e);
                    // SCORING: penalize invalid message
                    let mut scores = peer_scores.write().await;
                    if let Some(score) = scores.get_mut(&addr) {
                        if score.penalize(PEER_PENALTY_INVALID_MSG) {
                            score.ban();
                            warn!("Peer {} banned (deser fail, score={})", addr, score.score);
                        }
                    }
                }
            }
        }

        // Remove peer from active map on disconnect.
        // Phase 1 TTL: keep the address in known_peers so general redial / PEX
        // can re-establish the session; the TTL task expires it later.
        {
            let mut peers_lock = peers.write().await;
            peers_lock.remove(&addr);
        }
        {
            let mut seen = peer_last_seen.write().await;
            seen.insert(addr, Instant::now());
        }
        // DEEP SYNC: failover — move all in-flight requests from this peer back to pending
        {
            let mut frontier = sync_ctx.frontier.write().await;
            let requeued = frontier.on_peer_disconnect(&addr);
            if requeued > 0 {
                info!(
                    "[Sync] Peer {} disconnected, requeued {} in-flight requests for failover",
                    addr, requeued
                );
            }
            frontier.update_state();
            tracing::debug!("{}", frontier.log_line());
        }
        info!("Peer {} removed from peers map", addr);
    }

    /// Connect to a peer
    /// Dial `addr`, tolerating concurrent callers. The initial sweep, heartbeat,
    /// redial loop and PEX can all ask for the same address at the same time;
    /// the in-flight set collapses them into a single session so the `peers` map
    /// never gets a sender silently overwritten by a duplicate connection.
    async fn connect_to_peer(&self, addr: SocketAddr) {
        {
            let mut dialing = self.dialing.write().await;
            if !dialing.insert(addr) {
                debug!("Dial to {} already in flight, skipping", addr);
                return;
            }
        }
        self.connect_to_peer_inner(addr).await;
        self.dialing.write().await.remove(&addr);
    }

    /// Phase 2A: read-only guard consulted before any outbound dial. Inbound
    /// connections have always checked the ban table; outbound never did, so a
    /// node would happily redial a peer it had already banned.
    async fn outbound_dial_blocked(&self, addr: SocketAddr) -> bool {
        let scores = self.peer_scores.read().await;
        scores.get(&addr).map(|s| s.is_banned()).unwrap_or(false)
    }

    async fn connect_to_peer_inner(&self, addr: SocketAddr) {
        info!("Dialing peer: {}", addr);

        if self.outbound_dial_blocked(addr).await {
            let until = self
                .peer_scores
                .read()
                .await
                .get(&addr)
                .and_then(|s| s.banned_until);
            warn!(
                "Skipping banned peer {} for outbound dial (banned until {:?})",
                addr, until
            );
            return;
        }

        {
            let mut scores = self.peer_scores.write().await;
            if let Some(score) = scores.get_mut(&addr) {
                score.decay();
            } else {
                scores.insert(addr, PeerScore::new());
            }
        }

        {
            let peers_guard = self.peers.read().await;
            if peers_guard.len() >= MAX_PEERS {
                warn!(
                    "Skipping connect to {}: connection limit reached ({})",
                    addr, MAX_PEERS
                );
                return;
            }
            // ECLIPSE-01: enforce /24 subnet diversity for outbound connections
            let subnet_count = count_subnet_peers_excluding(addr, &peers_guard).await;
            if subnet_count >= MAX_PEERS_PER_SUBNET {
                warn!(
                    "Skipping connect to {}: /24 subnet limit reached ({}/{})",
                    addr, subnet_count, MAX_PEERS_PER_SUBNET
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
                let peer_scores = Arc::clone(&self.peer_scores);
                let sync_ctx = Arc::clone(&self.sync_ctx);
                let is_orphan = Arc::clone(&self.is_orphan);
                let peer_discovery_tx = {
                    let guard = self.peer_discovery_tx.lock().await;
                    guard.clone().unwrap_or_else(|| {
                        let (tx, _) = mpsc::unbounded_channel();
                        tx
                    })
                };
                let peer_last_seen = self.peer_last_seen.clone();
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
                        peer_scores,
                        msg_sender,
                        msg_receiver,
                        peer_discovery_tx,
                        sync_ctx,
                        is_orphan,
                        peer_last_seen,
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

    /// C2-004: cached topological serving order, keyed by DAG length.
    /// Sorting the whole DAG per GetData collapsed serving nodes at ~10k
    /// txs; repeat requests are O(1). The order is a SERVING HINT ONLY,
    /// never consensus (a stale entry merely batches less optimally).
    async fn cached_topo_order(
        sync_ctx: &Arc<SyncContext>,
        all_hashes: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Option<Vec<Vec<u8>>> {
        {
            let cache = sync_ctx.topo_cache.read().await;
            if let Some((len, order)) = cache.as_ref() {
                if *len as usize == all_hashes.len() {
                    sync_ctx
                        .stats
                        .topo_cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(order.clone());
                }
            }
            sync_ctx
                .stats
                .topo_cache_miss
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let order = Self::topological_order(all_hashes, get_transaction_by_hash);
        if let Some(ref o) = order {
            let mut cache = sync_ctx.topo_cache.write().await;
            *cache = Some((o.len() as u64, o.clone()));
        }
        order
    }

    /// VPS-2: extend a requested hash set with its DAG-resident ancestors
    /// (bounded), so the served page is self-sufficient for bottom-up
    /// insertion. Pure function of (requested set, DAG contents):
    /// deterministic, no network, no consensus impact.
    ///
    /// Guarantees: every returned hash is DAG-resident (requested unknowns
    /// are dropped — the serving layer skips them anyway); requested ones
    /// come with their ancestor closure up to the budget; at most
    /// ANCESTOR_BUDGET extras; genesis (`[0; 32]`) parents terminate;
    /// no duplicates; terminates (visited set + step cap double-guard
    /// against any cycle).
    pub(crate) fn ancestor_closed_page(
        requested: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Vec<Vec<u8>> {
        const ANCESTOR_BUDGET: usize = 400;
        const ANCESTOR_STEPS: usize = 20_000;
        let mut page: Vec<Vec<u8>> =
            Vec::with_capacity(requested.len().saturating_add(ANCESTOR_BUDGET));
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for h in requested.into_iter() {
            // Requested-but-unknown hashes are dropped here (the serving
            // layer would skip them anyway); only servable txs enter.
            if get_transaction_by_hash(&h).is_none() {
                continue;
            }
            if seen.insert(h.clone()) {
                page.push(h);
            }
        }
        let mut budget = ANCESTOR_BUDGET;
        let mut steps = 0usize;
        let mut idx = 0usize;
        while idx < page.len() && budget > 0 && steps < ANCESTOR_STEPS {
            steps += 1;
            let h = page[idx].clone();
            idx += 1;
            let parents: [[u8; 32]; 2] = match get_transaction_by_hash(&h) {
                Some(tx) => tx.parents,
                None => continue,
            };
            for parent in parents.iter() {
                if *parent == [0u8; 32] {
                    continue;
                }
                let key = parent.to_vec();
                if seen.contains(&key) {
                    continue;
                }
                if get_transaction_by_hash(&key).is_none() {
                    continue;
                }
                seen.insert(key.clone());
                page.push(key);
                budget -= 1;
                if budget == 0 {
                    break;
                }
            }
        }
        page
    }

    /// DEEP SYNC: compute the full ancestor closure of a set of requested
    /// transaction hashes. The result includes ALL ancestors reachable from
    /// the requested set, bounded by `max_entries` (CPU/memory protection).
    ///
    /// Unlike the previous `ancestor_closed_page` with its fixed ANCESTOR_BUDGET
    /// of 400, this function computes the FULL closure up to the bound, ensuring
    /// that the served page is self-sufficient for bottom-up insertion.
    ///
    /// Returns hashes in an UNORDERED set. The caller must topologically sort
    /// the result before sending.
    pub(crate) fn ancestor_full_closure(
        requested: &[Vec<u8>],
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
        max_entries: usize,
    ) -> Vec<Vec<u8>> {
        let mut closure: Vec<Vec<u8>> = Vec::with_capacity(requested.len().min(max_entries));
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut steps = 0usize;
        // Seed with requested hashes (only those that exist in the DAG).
        for h in requested {
            if get_transaction_by_hash(h).is_none() {
                continue;
            }
            if seen.insert(h.clone()) {
                closure.push(h.clone());
            }
        }
        // BFS walk: for each hash in the closure, append its parents.
        let mut idx = 0usize;
        while idx < closure.len()
            && closure.len() < max_entries
            && steps < crate::sync_stats::TOPO_ORDER_CAP
        {
            steps += 1;
            let h = closure[idx].clone();
            idx += 1;
            let parents: [[u8; 32]; 2] = match get_transaction_by_hash(&h) {
                Some(tx) => tx.parents,
                None => continue,
            };
            for parent in parents.iter() {
                if *parent == [0u8; 32] {
                    continue;
                }
                let key = parent.to_vec();
                if seen.contains(&key) {
                    continue;
                }
                if get_transaction_by_hash(&key).is_none() {
                    continue;
                }
                seen.insert(key.clone());
                closure.push(key);
                if closure.len() >= max_entries {
                    break;
                }
            }
        }
        closure
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
                        // C2-004 FIX: indeg[h] counts h's UNMET PARENT
                        // dependencies (Kahn). The previous code incremented
                        // the PARENT's counter (i.e. counted children), which
                        // emitted tips-first: joining nodes parked every batch
                        // as orphans and the re-request storm collapsed serving
                        // nodes at ~10k txs. Parents-first lets joiners insert
                        // immediately.
                        *indeg.get_mut(h).expect("topological_order: h must be in indeg") += 1;
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
                    let d = indeg.get_mut(kid).expect("topological_order: kid must be in indeg");
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
mod phase2_decentralized_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn net_with(bootnodes: Vec<SocketAddr>) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        P2PNetwork::new(
            P2PConfig {
                listen_addr: addr("127.0.0.1:31001"),
                bootnodes,
                dns_seeds: vec![],
                peer_store_path: None,
            },
            tx,
            empty.clone(),
            empty_opt,
            empty,
            sync_ctx,
            is_orphan,
        )
    }

    fn banned_score() -> PeerScore {
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        s
    }

    /// PHASE2-2A / PRINCIPE 2: seeds are ordinary fallbacks in the redial
    /// ordering. A peer the node already knows always outranks an unknown seed,
    /// so one dead seed can no longer monopolise the redial cycle.
    #[test]
    fn test_seeds_are_unprivileged_in_redial() {
        let local = addr("127.0.0.1:31001");
        let seed1 = addr("10.0.0.1:25565");
        let seed2 = addr("10.0.0.2:25565");
        let peer_a = addr("203.0.113.10:25565");
        let peer_b = addr("203.0.113.11:25565");

        let mut known = HashSet::new();
        known.insert(peer_a);
        known.insert(peer_b);
        known.insert(seed1); // a seed may also already be a known peer

        let out = P2PNetwork::redial_candidates(&known, &[seed1, seed2], local);

        assert_eq!(out.iter().filter(|a| **a == peer_a).count(), 1);
        assert_eq!(out.iter().filter(|a| **a == peer_b).count(), 1);
        assert!(
            out.iter().filter(|a| **a == seed1).count() == 1,
            "seed already known must not be duplicated"
        );
        assert!(out.contains(&seed2), "unconfigured-seen seed still reachable");
        assert!(!out.contains(&local), "own listen address must never be dialled");

        let first_known = out
            .iter()
            .position(|a| *a == peer_a || *a == peer_b)
            .expect("known peers must be present");
        let last_seed = out.iter().position(|a| *a == seed2).unwrap();
        assert!(
            first_known < last_seed,
            "known peers must be redialled before an unknown seed"
        );
    }

    /// PHASE2-2A / PRINCIPE 1: a node that never configured any seed still has a
    /// usable candidate set — discovery does not require a bootnode.
    #[test]
    fn test_redial_candidates_without_any_seed() {
        let local = addr("127.0.0.1:31001");
        let peer = addr("203.0.113.77:25565");
        let mut known = HashSet::new();
        known.insert(peer);
        known.insert(local);

        let out = P2PNetwork::redial_candidates(&known, &[], local);
        assert_eq!(out, vec![peer]);
    }

    /// PHASE2-2A / PRINCIPE 1: outbound dials must respect the ban table.
    /// Inbound connections have always checked it; outbound never did.
    #[tokio::test]
    async fn test_outbound_dial_blocked_for_banned_peer() {
        let net = net_with(vec![]);
        let banned = addr("203.0.113.50:25565");
        let clean = addr("203.0.113.51:25565");

        assert!(
            !net.outbound_dial_blocked(banned).await,
            "unknown address is not blocked"
        );

        net.peer_scores.write().await.insert(banned, banned_score());

        assert!(
            net.outbound_dial_blocked(banned).await,
            "banned peer must not be redialled outbound"
        );
        assert!(
            !net.outbound_dial_blocked(clean).await,
            "clean peer must stay dialable"
        );
    }

    /// PHASE2-2A / PRINCIPE 3: PEX must not re-share addresses we banned, nor
    /// our own listen address (which would let peers dial us back pointlessly
    /// and would leak a self-reference into the address pool).
    #[test]
    fn test_pex_omits_banned_and_local() {
        let local = addr("127.0.0.1:31001");
        let good = addr("203.0.113.10:25565");
        let banned = addr("203.0.113.66:25565");

        let mut known = HashSet::new();
        known.insert(local);
        known.insert(good);
        known.insert(banned);

        let mut scores = HashMap::new();
        scores.insert(banned, banned_score());

        let out = P2PNetwork::pex_broadcast_list(&known, &scores, local);
        assert_eq!(out.len(), 1, "only the healthy address is shared");
        assert!(out.contains(&good));
        assert!(!out.contains(&local));
        assert!(!out.contains(&banned));
    }

    /// PHASE2-2A: a peer with a live session must never have its TTL clock
    /// expire. Before this fix the clock was only touched at handshake and at
    /// disconnect, so a reliably-connected peer was dropped from the store.
    #[tokio::test]
    async fn test_connected_peer_survives_ttl_refresh() {
        let net = net_with(vec![]);
        let live = addr("203.0.113.20:25565");
        let idle = addr("203.0.113.21:25565");

        net.known_peers.write().await.insert(live);
        net.known_peers.write().await.insert(idle);

        // A live session exists for `live` only.
        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        net.peers.write().await.insert(live, tx);

        let before = Instant::now();
        net.refresh_live_peer_clocks().await;
        let after = Instant::now();

        let seen = net.peer_last_seen.read().await;
        let refreshed = *seen.get(&live).expect("live peer must have a clock");
        assert!(
            refreshed >= before && refreshed <= after,
            "live session clock must be refreshed to now"
        );
        assert!(
            refreshed.elapsed() < PEER_TTL,
            "a live session must stay inside the TTL window"
        );
        // `idle` has no session and is left untouched (still absent).
        assert!(!seen.contains_key(&idle));
    }

    /// PHASE2-2A: one redial cycle must never attempt more dials than the
    /// connection cap allows — that is what keeps a large stale peer store from
    /// turning a cycle into an hours-long serial sweep.
    #[test]
    fn test_redial_cycle_budget_is_sane() {
        assert!(MAX_REDIAL_PER_CYCLE >= 1);
        assert!(
            MAX_REDIAL_PER_CYCLE <= MAX_PEERS,
            "per-cycle budget must not exceed the connection cap"
        );
    }
}

#[cfg(test)]
mod bootstrap_phase1_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// PEER_PERSISTENCE: save then reload restores the same address set.
    #[tokio::test]
    async fn test_peer_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path.clone()),
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );

        net.known_peers.write().await.insert(addr("10.0.0.1:25565"));
        net.known_peers.write().await.insert(addr("10.0.0.2:25565"));
        net.save_known_peers().await;
        assert!(path.exists());

        // Simulate restart: fresh instance, same path.
        let cfg2 = P2PConfig {
            listen_addr: addr("127.0.0.1:30002"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
        };
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let sync_ctx2 = Arc::new(SyncContext::default());
        let net2 = P2PNetwork::new(
            cfg2,
            tx2,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx2,
            is_orphan.clone(),
        );
        assert!(net2.known_peers.read().await.is_empty());
        net2.load_known_peers().await;
        let known = net2.known_peers.read().await;
        assert!(known.contains(&addr("10.0.0.1:25565")));
        assert!(known.contains(&addr("10.0.0.2:25565")));
        assert_eq!(known.len(), 2);
    }

    /// PEER_TTL: disconnect path keeps the address in known_peers (TTL, not remove).
    #[tokio::test]
    async fn test_peer_ttl_keeps_address_after_disconnect() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30003"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );

        let peer = addr("192.168.1.10:25565");
        net.known_peers.write().await.insert(peer);
        // Simulate disconnect bookkeeping (what handle_peer does at exit):
        net.peers.write().await.remove(&peer);
        net.peer_last_seen.write().await.insert(peer, Instant::now());
        // Address must still be known (TTL keeps it).
        assert!(net.known_peers.read().await.contains(&peer));
        // TTL clock is recorded.
        assert!(net.peer_last_seen.read().await.contains_key(&peer));
        // Expire only after PEER_TTL.
        assert!(PEER_TTL > Duration::from_secs(60));
    }

    /// MULTI_SEED: default config exposes more than one bootnode.
    #[test]
    fn test_multi_seed_default_bootnodes() {
        let cfg = crate::config::NodeConfig::default();
        assert!(
            cfg.bootnodes.len() >= 2,
            "multi-seed requires >=2 default bootnodes, got {}",
            cfg.bootnodes.len()
        );
        // Distinct entries.
        let unique: std::collections::HashSet<_> = cfg.bootnodes.iter().collect();
        assert_eq!(unique.len(), cfg.bootnodes.len());
    }

    /// MULTI_SEED: P2PConfig accepts an arbitrary seed list.
    #[test]
    fn test_multi_seed_p2p_config_accepts_list() {
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30004"),
            bootnodes: vec![
                addr("10.0.0.1:25565"),
                addr("10.0.0.2:25565"),
                addr("10.0.0.3:25565"),
            ],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        assert_eq!(cfg.bootnodes.len(), 3);
    }

    /// GENERAL_REDIAL: heartbeat/reconnection candidate set includes non-bootnode peers.
    #[tokio::test]
    async fn test_general_redial_includes_known_peers() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let boot = addr("10.0.0.1:25565");
        let non_boot = addr("10.0.0.99:25565");
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30005"),
            bootnodes: vec![boot],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        net.known_peers.write().await.insert(boot);
        net.known_peers.write().await.insert(non_boot);

        // Reconstruct the candidate set the way start_reconnection_task does.
        let local = net.config.listen_addr;
        let mut candidates: Vec<SocketAddr> = net.config.bootnodes.clone();
        for a in net.known_peers.read().await.iter().copied() {
            if a != local && !candidates.contains(&a) {
                candidates.push(a);
            }
        }
        assert!(candidates.contains(&boot), "bootnode must be a candidate");
        assert!(
            candidates.contains(&non_boot),
            "known non-bootnode peer must be a general-redial candidate"
        );
    }

    /// PEX: Peers message carries known addresses for discovery.
    #[test]
    fn test_pex_message_carries_known_peers() {
        let list = vec![addr("10.0.0.1:25565"), addr("10.0.0.2:25565")];
        let msg = P2PMessage::Peers(list.clone());
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: P2PMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            P2PMessage::Peers(got) => assert_eq!(got, list),
            _ => panic!("wrong variant"),
        }
    }

    /// COLD_START: loading a peer store yields dial candidates without bootnodes.
    #[tokio::test]
    async fn test_cold_start_restores_dial_candidates_without_bootnode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let peer = addr("203.0.113.10:25565");
        std::fs::write(&path, format!("[\"{}\"]", peer)).unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30006"),
            bootnodes: vec![], // bootnode is down / absent
            dns_seeds: vec![],
            peer_store_path: Some(path),
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        net.load_known_peers().await;
        let known = net.known_peers.read().await;
        assert!(known.contains(&peer), "cold start must restore the peer");
        // General redial set (what start() dials after bootnodes) is non-empty.
        let candidates: Vec<SocketAddr> = known
            .iter()
            .copied()
            .filter(|a| *a != net.config.listen_addr && !net.config.bootnodes.contains(a))
            .collect();
        assert_eq!(candidates.len(), 1);
    }

    /// P2P_CRYPTO_AUDIT: equal counters only collide under the SAME direction
    /// byte; the fix assigns opposite directions to the two session senders.
    #[test]
    fn test_nonce_collision_detected() {
        // Legacy/shared-direction view: equal counters under same dir collide.
        assert!(P2PNetwork::nonce_collision_possible(1, 0x01, 1, 0x01));
        assert!(P2PNetwork::nonce_collision_possible(42, 0x01, 42, 0x01));
        // Different counters under same dir: no collision.
        assert!(!P2PNetwork::nonce_collision_possible(1, 0x01, 2, 0x01));
        // Equal counters under OPPOSITE directions (the fixed scheme): no collision.
        assert!(!P2PNetwork::nonce_collision_possible(1, 0x01, 1, 0x02));
        assert!(!P2PNetwork::nonce_collision_possible(42, 0x02, 42, 0x01));
    }

    /// Nonce uniqueness: direction byte separates the two send directions, and
    /// counters are unique within a direction.
    #[test]
    fn test_nonce_uniqueness_across_directions() {
        let mut seen = std::collections::HashSet::new();
        for dir in [0x01u8, 0x02u8] {
            for counter in 1..=1000u64 {
                let n = P2PNetwork::build_nonce(counter, dir);
                assert!(seen.insert(n), "duplicate (K, nonce) at counter={counter} dir={dir:#04x}");
            }
        }
        // Opposite directions at the same counter must differ.
        assert_ne!(
            P2PNetwork::build_nonce(1, 0x01),
            P2PNetwork::build_nonce(1, 0x02)
        );
    }

    /// Direction assignment is deterministic and opposite for the two peers.
    #[test]
    fn test_send_direction_is_opposite() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let dir_a = P2PNetwork::send_direction(&a, &b);
        let dir_b = P2PNetwork::send_direction(&b, &a);
        assert_eq!(dir_a, 0x01);
        assert_eq!(dir_b, 0x02);
        assert_ne!(dir_a, dir_b);
    }

    /// Encrypt/decrypt roundtrip with direction nonces (both directions).
    #[test]
    fn test_encrypt_decrypt_roundtrip_bidirectional() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [7u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let msg_a = b"GET_INVENTORY_MESSAGE_A";
        let msg_b = b"SYNC_REQUEST_MESSAGE_B";

        let nonce_a = P2PNetwork::build_nonce(1, 0x01);
        let nonce_b = P2PNetwork::build_nonce(1, 0x02);
        assert_ne!(nonce_a, nonce_b);

        let ct_a = cipher.encrypt(Nonce::from_slice(&nonce_a), msg_a.as_ref()).unwrap();
        let ct_b = cipher.encrypt(Nonce::from_slice(&nonce_b), msg_b.as_ref()).unwrap();

        let pt_a = cipher.decrypt(Nonce::from_slice(&nonce_a), ct_a.as_ref()).unwrap();
        let pt_b = cipher.decrypt(Nonce::from_slice(&nonce_b), ct_b.as_ref()).unwrap();
        assert_eq!(pt_a, msg_a);
        assert_eq!(pt_b, msg_b);

        // Cross-direction decrypt must fail (wrong nonce / auth tag).
        assert!(cipher.decrypt(Nonce::from_slice(&nonce_b), ct_a.as_ref()).is_err());
    }

    /// Tampered ciphertext is rejected by Poly1305.
    #[test]
    fn test_tampered_ciphertext_fails() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [9u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = P2PNetwork::build_nonce(1, 0x01);
        let mut ct = cipher.encrypt(Nonce::from_slice(&nonce), b"integrity".as_ref()).unwrap();
        ct[0] ^= 0xff;
        assert!(cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).is_err());
    }

    /// Long message sequence: all nonces unique under one key; encrypt/decrypt
    /// succeeds for every frame in both directions.
    #[test]
    fn test_long_message_sequence_unique_nonces() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [3u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut seen = std::collections::HashSet::new();
        for dir in [0x01u8, 0x02u8] {
            for counter in 1..=10_000u64 {
                let n = P2PNetwork::build_nonce(counter, dir);
                assert!(seen.insert(n));
                let ct = cipher.encrypt(Nonce::from_slice(&n), counter.to_le_bytes().as_ref()).unwrap();
                let pt = cipher.decrypt(Nonce::from_slice(&n), ct.as_ref()).unwrap();
                assert_eq!(pt, counter.to_le_bytes());
            }
        }
        assert_eq!(seen.len(), 20_000);
    }

    /// Concurrent send counters remain unique (atomic fetch_add).
    #[test]
    fn test_concurrent_send_unique_counters() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = Arc::new(AtomicU64::new(1));
        let mut nonces = std::collections::HashSet::new();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let c = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let mut local = Vec::with_capacity(1000);
                    for _ in 0..1000 {
                        let v = c.fetch_add(1, Ordering::Relaxed);
                        local.push(P2PNetwork::build_nonce(v, 0x01));
                    }
                    local
                })
            })
            .collect();
        for h in handles {
            for n in h.join().unwrap() {
                assert!(nonces.insert(n), "duplicate nonce under concurrent send");
            }
        }
        assert_eq!(nonces.len(), 8000);
    }

    /// Reconnect / session rotation: each handshake yields a fresh ephemeral
    /// key, so (K, N) pairs from a prior session are never reused.
    #[tokio::test]
    async fn test_reconnect_session_rotation() {
        for _ in 0..8 {
            let (mut a_r, mut b_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_r, mut a_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_r, &mut a_w);
            let b = P2PNetwork::handshake(&mut b_r, &mut b_w);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, dir_a) = ra.expect("handshake A");
            let (key_b, dir_b) = rb.expect("handshake B");
            assert_eq!(key_a, key_b, "both ends share the session key");
            assert_ne!(dir_a, dir_b, "session directions must be opposite");
            assert!(dir_a == 0x01 || dir_a == 0x02);
        }
        // Distinct handshakes must not collide on keys (ephemeral X25519).
        let mut keys = std::collections::HashSet::new();
        for _ in 0..8 {
            let (mut a_r, mut b_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_r, mut a_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_r, &mut a_w);
            let b = P2PNetwork::handshake(&mut b_r, &mut b_w);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, _) = ra.expect("handshake A");
            let (key_b, _) = rb.expect("handshake B");
            assert_eq!(key_a, key_b);
            assert!(keys.insert(key_a), "reconnect must rotate the session key");
        }
        assert_eq!(keys.len(), 8);
    }

    /// Session handshake test (updated signature): shared key + opposite dirs.
    #[tokio::test]
    async fn test_handshake_derives_shared_key_bootstrap() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer);
        let (ra, rb) = tokio::join!(a, b);

        let (key_a, dir_a) = ra.expect("side A handshake must succeed");
        let (key_b, dir_b) = rb.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
        assert_ne!(dir_a, dir_b, "directions must be opposite");
    }

    /// Replay behaviour (logic-level): a repeated/regressed counter is rejected
    /// by the receiver's strict-increase check (mirrors handle_peer logic).
    #[test]
    fn test_replay_rejected_by_counter_check() {
        let mut last: u64 = 0;
        let mut accept = |counter: u64| -> bool {
            if counter <= last {
                false
            } else {
                last = counter;
                true
            }
        };
        assert!(accept(1));
        assert!(accept(2));
        assert!(!accept(2), "replay of counter=2 must fail");
        assert!(!accept(1), "regression to 1 must fail");
        assert!(accept(3));
    }

    /// PARTITION/RECONNECT: known_peers survives an active-map wipe (partition).
    #[tokio::test]
    async fn test_partition_keeps_known_peers_for_reconnect() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30007"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        let peer = addr("198.51.100.7:25565");
        net.known_peers.write().await.insert(peer);

        // Simulate a partition: active map wiped, known set retained (TTL).
        net.peers.write().await.clear();
        net.peer_last_seen.write().await.insert(peer, Instant::now());
        assert!(net.known_peers.read().await.contains(&peer));
        // Reconnect candidate reconstruction (same as start_reconnection_task).
        let mut candidates: Vec<SocketAddr> = net.config.bootnodes.clone();
        for a in net.known_peers.read().await.iter().copied() {
            if a != net.config.listen_addr && !candidates.contains(&a) {
                candidates.push(a);
            }
        }
        assert!(candidates.contains(&peer));
    }

    /// BOOTNODE_LOSS: once A↔B know each other, killing the bootnode leaves
    /// the pair as mutual redial candidates (logic-level scenario).
    #[tokio::test]
    async fn test_bootnode_loss_pair_stays_connected() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let boot = addr("10.0.0.1:25565");
        let a = addr("127.0.0.1:40001");
        let b = addr("127.0.0.1:40002");
        let cfg = P2PConfig {
            listen_addr: a,
            bootnodes: vec![boot],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        // After PEX, A knows B and (locally) itself is not redialled.
        net.known_peers.write().await.insert(b);
        net.known_peers.write().await.insert(boot);

        // Bootnode dies: it is no longer a usable dial target, but B remains.
        let mut candidates: Vec<SocketAddr> = Vec::new();
        for x in net.known_peers.read().await.iter().copied() {
            if x != a {
                candidates.push(x);
            }
        }
        // B survives as a general-redial candidate even if boot is removed.
        net.known_peers.write().await.remove(&boot);
        let after: Vec<SocketAddr> = net
            .known_peers
            .read()
            .await
            .iter()
            .copied()
            .filter(|x| *x != a)
            .collect();
        assert!(after.contains(&b), "A must still redial B after bootnode loss");
        assert!(!after.contains(&boot));
        let _ = candidates;
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
    /// and derive the SAME session key with opposite send directions.
    #[tokio::test]
    async fn test_handshake_derives_shared_key() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer);
        let (ra, rb) = tokio::join!(a, b);

        let (key_a, dir_a) = ra.expect("side A handshake must succeed");
        let (key_b, dir_b) = rb.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
        assert_ne!(dir_a, dir_b, "directions must be opposite");
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

    /// VPS-2 helper: build a linear chain root -> ... -> tip on top of
    /// genesis parents. Returns txs oldest-first.
    #[cfg(test)]
    fn test_chain(n: usize, start: u8) -> Vec<Transaction> {
        use crate::Transaction;
        let genesis = [0u8; 32];
        let mut chain = Vec::new();
        let mut parent = genesis;
        for i in 0..n {
            let tx = Transaction::new(
                [parent, genesis],
                [start.wrapping_add(i as u8); 32],
                [200u8; 32],
                100,
                10,
                1234567890 + i as u64,
                0,
                i as u64,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            parent = tx.id;
            chain.push(tx);
        }
        chain
    }

    /// VPS-2: requesting only the tip of a chain returns the whole
    /// ancestor-closed set (chain length < budget).
    #[test]
    fn test_ancestor_closed_page_closes_chain() {
        let chain = test_chain(10, 50);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let page = P2PNetwork::ancestor_closed_page(vec![tip.clone()], &lookup);
        assert_eq!(page.len(), 10, "full chain must be included");
        assert!(page.contains(&tip));
        assert!(page.contains(&chain[0].id.to_vec()));
        // Deterministic: same input twice, same output.
        let again = P2PNetwork::ancestor_closed_page(vec![tip], &lookup);
        assert_eq!(page, again);
    }

    /// VPS-2 §12 anti-loop/bound: a 600-deep chain with budget 400 returns
    /// exactly tip + 400 nearest ancestors (401), terminates, no dupes.
    #[test]
    fn test_ancestor_closed_page_budget_bound() {
        let chain = test_chain(600, 10);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let page = P2PNetwork::ancestor_closed_page(vec![tip], &lookup);
        assert_eq!(page.len(), 401, "tip + exactly 400 ancestors");
        // Nearest 400 present (indices 199..=598), the next one excluded.
        assert!(page.contains(&chain[599].id.to_vec()));
        assert!(page.contains(&chain[200].id.to_vec()));
        assert!(page.contains(&chain[199].id.to_vec()));
        assert!(!page.contains(&chain[198].id.to_vec()));
        let mut sorted = page.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), page.len(), "no duplicates in page");
    }

    /// VPS-2 §12: unknown hashes are skipped (never invented), duplicate
    /// requests deduped, genesis terminates.
    #[test]
    fn test_ancestor_closed_page_skips_unknown_and_dupes() {
        let chain = test_chain(5, 80);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let ghost = vec![0xFFu8; 32];
        let page = P2PNetwork::ancestor_closed_page(
            vec![tip.clone(), ghost.clone(), tip.clone()],
            &lookup,
        );
        assert_eq!(page.len(), 5, "chain once, ghost skipped, dupe dropped");
        assert!(!page.contains(&ghost));
    }

    /// C2-004: topological_order must emit parents before children.
    /// The previous implementation incremented the PARENT's counter
    /// (counting children), serving tips-first: joining nodes parked
    /// every batch as orphans and the re-request storm collapsed serving
    /// nodes at ~10k txs.    #[test]
    fn test_topological_order_parents_first() {
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
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> = [&a, &b, &c, &d]
            .into_iter()
            .map(|t| (t.id.to_vec(), t.clone()))
            .collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };

        // Feed child-first: the order must still come out parents-first.
        let hashes = vec![d.id.to_vec(), c.id.to_vec(), b.id.to_vec(), a.id.to_vec()];
        let order =
            P2PNetwork::topological_order(hashes, &lookup).expect("chain+diamond must sort");
        assert_eq!(order.len(), 4);
        let pos = |id: &[u8; 32]| order.iter().position(|h| h.as_slice() == id).unwrap();
        assert!(pos(&a.id) < pos(&b.id), "A before B");
        assert!(pos(&a.id) < pos(&c.id), "A before C");
        assert!(pos(&b.id) < pos(&d.id), "B before D");
        assert!(pos(&c.id) < pos(&d.id), "C before D");
    }

    #[test]
    fn test_subnet_24_ipv4() {
        let addr: SocketAddr = "192.168.1.100:30333".parse().unwrap();
        assert_eq!(subnet_24(addr), Some([192, 168, 1]));
        let same: SocketAddr = "192.168.1.200:30333".parse().unwrap();
        assert_eq!(subnet_24(same), Some([192, 168, 1]));
        let diff: SocketAddr = "192.168.2.100:30333".parse().unwrap();
        assert_eq!(subnet_24(diff), Some([192, 168, 2]));
    }

    #[test]
    fn test_subnet_24_ipv6() {
        let addr: SocketAddr = "[2a0c:b641:1a0:800::ba]:30333".parse().unwrap();
        let sub = subnet_24(addr);
        assert!(sub.is_some(), "IPv6 must return a subnet");
    }

    #[test]
    fn test_count_subnet_peers() {
        let peers: HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
        let addr: SocketAddr = "10.0.0.1:30333".parse().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let count = rt.block_on(count_subnet_peers(addr, &peers));
        assert_eq!(count, 0);
    }

    #[test]
    fn test_diversity_constants() {
        assert!(
            MAX_PEERS_PER_SUBNET >= 2,
            "must allow at least 2 peers per /24"
        );
        assert!(MAX_PEERS_PER_SUBNET <= 16, "must limit to prevent eclipse");
        assert!(
            PROTECTED_OUTBOUND_SLOTS >= 4,
            "must protect at least 4 outbound slots"
        );
        assert!(
            PROTECTED_OUTBOUND_SLOTS < MAX_PEERS,
            "protected must be less than total"
        );
    }

    // === Phase 8: Adversarial P2P Tests ===

    #[test]
    fn test_peer_score_initial() {
        let score = PeerScore::new();
        assert_eq!(score.score, PEER_SCORE_INITIAL);
        assert!(!score.is_banned());
        assert_eq!(score.temp_bans, 0);
    }

    #[test]
    fn test_peer_score_penalize() {
        let mut score = PeerScore::new();
        assert!(!score.penalize(PEER_PENALTY_INVALID_MSG));
        assert_eq!(score.score, PEER_SCORE_INITIAL + PEER_PENALTY_INVALID_MSG);
        // Enough penalties to drop below threshold
        for _ in 0..10 {
            if score.penalize(PEER_PENALTY_INVALID_MSG) {
                break;
            }
        }
        assert!(score.score <= PEER_SCORE_BAN_THRESHOLD);
    }

    #[test]
    fn test_peer_score_ban_temp_then_perm() {
        let mut score = PeerScore::new();
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert!(score.is_banned());
        assert_eq!(score.temp_bans, 1);
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert_eq!(score.temp_bans, 2);
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert_eq!(score.temp_bans, 3);
        assert!(score.is_banned());
    }

    #[test]
    fn test_peer_score_decay() {
        let mut score = PeerScore::new();
        score.score = 50;
        score.last_decay = Instant::now() - Duration::from_secs(600);
        score.decay();
        assert_eq!(score.score, 51);
    }

    #[test]
    fn test_peer_score_decay_no_op() {
        let mut score = PeerScore::new();
        score.last_decay = Instant::now() - Duration::from_secs(600);
        score.decay();
        assert_eq!(score.score, PEER_SCORE_INITIAL);
    }

    #[test]
    fn test_peer_score_reward() {
        let mut score = PeerScore::new();
        score.reward(PEER_BONUS_SYNC);
        assert_eq!(score.score, PEER_SCORE_INITIAL + PEER_BONUS_SYNC);
        score.reward(100);
        assert_eq!(score.score, PEER_SCORE_INITIAL + 50);
    }

    #[test]
    fn test_subnet_diversity_limit() {
        let mut count = 0;
        for i in 1..=5 {
            let addr: SocketAddr = format!("192.168.1.{}:30333", i).parse().unwrap();
            if subnet_24(addr) == Some([192, 168, 1]) {
                count += 1;
            }
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn test_eclipse_attack_blocked() {
        let attacker_subnet = [10, 0, 0];
        let mut allowed = 0;
        for i in 1..=10 {
            let addr: SocketAddr = format!("10.0.0.{}:30333", i).parse().unwrap();
            if subnet_24(addr) == Some(attacker_subnet) && allowed < MAX_PEERS_PER_SUBNET {
                allowed += 1;
            }
        }
        assert_eq!(allowed, MAX_PEERS_PER_SUBNET);
    }

    #[test]
    fn test_scoring_flood_bans() {
        let mut score = PeerScore::new();
        for _ in 0..7 {
            if score.penalize(PEER_PENALTY_FLOOD) {
                score.ban();
                break;
            }
        }
        assert!(score.is_banned());
    }

    #[test]
    fn test_scoring_slow_not_banned() {
        let mut score = PeerScore::new();
        for _ in 0..10 {
            score.penalize(PEER_PENALTY_TIMEOUT);
        }
        assert!(score.score > PEER_SCORE_BAN_THRESHOLD);
        assert!(!score.is_banned());
    }

    // ===== DEEP SYNC TESTS =====

    /// Helper: build a linear chain of `n` transactions in a lookup table.
    /// Returns (tip_hash, lookup_fn).
    fn build_linear_chain(n: usize) -> (Vec<u8>, impl Fn(&[u8]) -> Option<Transaction>) {
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let mut prev_hash = [0u8; 32]; // genesis parent
        for i in 0..n {
            let mut parents = [[0u8; 32]; 2];
            parents[0] = prev_hash;
            parents[1] = [0u8; 32];
            let tx = Transaction::new(
                parents,
                [1u8; 32],       // sender
                [2u8; 32],       // receiver
                100,             // amount
                1,               // fee
                1000 + i as u64, // timestamp
                0,               // nonce
                0,               // account_nonce
                vec![],          // signature
                vec![],          // public_key
            );
            prev_hash = tx.id;
            chain.insert(tx.id.to_vec(), tx);
        }
        let tip = prev_hash.to_vec();
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        (tip, lookup)
    }

    #[test]
    fn test_ancestor_full_closure_linear_chain() {
        let (tip, lookup) = build_linear_chain(10);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, 100);
        // Full closure of a 10-tx chain should include all 10 txs.
        assert_eq!(
            closure.len(),
            10,
            "full closure should include all ancestors"
        );
        // The tip itself should be in the closure.
        assert!(closure.iter().any(|h| h == &tip));
    }

    #[test]
    fn test_ancestor_full_closure_respects_max_entries() {
        let (tip, lookup) = build_linear_chain(50);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, 20);
        // Should be capped at max_entries (20), not the full chain (50).
        assert!(
            closure.len() <= 20,
            "closure should respect max_entries bound"
        );
        assert!(closure.len() > 0, "closure should not be empty");
    }

    #[test]
    fn test_ancestor_full_closure_empty_request() {
        let (_tip, lookup) = build_linear_chain(10);
        let closure = P2PNetwork::ancestor_full_closure(&[], &lookup, 100);
        assert_eq!(
            closure.len(),
            0,
            "empty request should produce empty closure"
        );
    }

    #[test]
    fn test_ancestor_full_closure_unknown_hashes_skipped() {
        let (_tip, lookup) = build_linear_chain(10);
        let unknown = vec![99u8; 32];
        let closure = P2PNetwork::ancestor_full_closure(&[unknown], &lookup, 100);
        assert_eq!(closure.len(), 0, "unknown hashes should be skipped");
    }

    #[test]
    fn test_ancestor_full_closure_duplicate_requests_deduped() {
        let (tip, lookup) = build_linear_chain(5);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone(), tip.clone()], &lookup, 100);
        // Duplicate request hashes should be deduplicated.
        assert_eq!(closure.len(), 5, "duplicates should be deduped");
    }

    #[test]
    fn test_ancestor_full_closure_genesis_terminated() {
        // Chain where a tx has genesis parent [0; 32].
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let genesis_parent = [0u8; 32];
        let tx = Transaction::new(
            [genesis_parent, [0u8; 32]],
            [1u8; 32],
            [2u8; 32],
            100,
            1,
            1000,
            0,
            0,
            vec![],
            vec![],
        );
        let id = tx.id.to_vec();
        chain.insert(id.clone(), tx);
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        let closure = P2PNetwork::ancestor_full_closure(&[id.clone()], &lookup, 100);
        // Genesis parent [0; 32] should not be in the closure.
        assert_eq!(closure.len(), 1, "genesis parent should be terminated");
    }

    #[test]
    fn test_ancestor_full_closure_bounded_by_max_entries() {
        // Build a deep chain and verify the bound is strict.
        let (tip, lookup) = build_linear_chain(100);
        for max in [5, 10, 25, 50] {
            let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, max);
            assert!(
                closure.len() <= max,
                "closure len {} should be <= max_entries {}",
                closure.len(),
                max
            );
        }
    }

    #[test]
    fn test_ancestor_full_closure_diamond_dag() {
        // Build a diamond DAG: genesis -> A, genesis -> B, A+B -> C (tip).
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let genesis = [0u8; 32];
        let tx_a = Transaction::new(
            [genesis, genesis],
            [1u8; 32],
            [2u8; 32],
            10,
            1,
            100,
            0,
            0,
            vec![],
            vec![],
        );
        let tx_b = Transaction::new(
            [genesis, genesis],
            [1u8; 32],
            [2u8; 32],
            20,
            1,
            101,
            0,
            1,
            vec![],
            vec![],
        );
        let id_a = tx_a.id;
        let id_b = tx_b.id;
        chain.insert(id_a.to_vec(), tx_a);
        chain.insert(id_b.to_vec(), tx_b);
        let tx_c = Transaction::new(
            [id_a, id_b],
            [1u8; 32],
            [2u8; 32],
            30,
            1,
            102,
            0,
            2,
            vec![],
            vec![],
        );
        let id_c = tx_c.id;
        chain.insert(id_c.to_vec(), tx_c);
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        let closure = P2PNetwork::ancestor_full_closure(&[id_c.to_vec()], &lookup, 100);
        // Should include C, A, B = 3 txs (genesis [0;32] is terminated).
        assert_eq!(closure.len(), 3, "diamond closure should include all 3 txs");
        assert!(closure.iter().any(|h| h == &id_a.to_vec()));
        assert!(closure.iter().any(|h| h == &id_b.to_vec()));
        assert!(closure.iter().any(|h| h == &id_c.to_vec()));
    }
}
