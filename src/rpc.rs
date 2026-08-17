//! # RPC Module
//!
//! Implements JSON-RPC server for external communication using jsonrpsee with Axum integration.

use crate::ledger::Ledger;
use crate::parent_selection::DAG;
use crate::transaction::{Address, Transaction, TransactionId};
use crate::transaction_processor::{ProcessingError, TransactionProcessor};
use crate::validation::ValidationError;
use axum::{
    extract::{ConnectInfo, State},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, Semaphore};
use tower_http::cors::CorsLayer;

/// Token bucket rate limiter (sliding window per key)
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Max requests per window
    max_requests: u32,
    /// Window duration in seconds
    window_secs: u64,
    /// Per-key state: (count, window_start)
    buckets: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
}

/// Maximum serialized transaction size accepted via RPC (memory DoS guard).
/// A legitimate signed transaction is a few hundred bytes (1 MiB is generous).
const MAX_RPC_TX_SIZE: usize = 1024 * 1024;

/// H1: maximum number of parked orphans (memory + Sled). Orphans are only
/// stored AFTER the pure validation gate (PoW + signature), but the store
/// must still be bounded so a determined attacker cannot grow it forever.
const MAX_ORPHANS: usize = 50_000;

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_secs,
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a request from `key` is allowed.
    /// Returns `Ok(())` if allowed, `Err(retry_after_secs)` if rate limited.
    pub async fn check(&self, key: String) -> Result<(), u64> {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();
        let entry = buckets.entry(key).or_insert((0, now));
        if entry.1.elapsed().as_secs() >= self.window_secs {
            *entry = (0, now);
        }
        if entry.0 >= self.max_requests {
            let elapsed = entry.1.elapsed().as_secs();
            let retry_after = self.window_secs.saturating_sub(elapsed);
            return Err(retry_after);
        }
        entry.0 += 1;
        Ok(())
    }
}

/// Custom RPC error
#[derive(Debug)]
pub struct RpcError(String);

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RpcError {}

/// Balance response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub address: Address,
    pub balance: u64,
    // §J (purged): `mining_rewards` was always 0 (no mining rewards exist in
    // this tokenomics — zero emission); removed from the RPC surface.
}

/// Transaction response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    pub tx_id: TransactionId,
    pub status: String,
    pub message: String,
}

/// DAG stats response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagStatsResponse {
    pub current_tps: f64,
    pub total_transactions: u64,
    pub tip_count: usize,
    pub epoch: u64,
    pub connected_peers: u32,
}

// §J (purged): HashrateResponse + get_network_hashrate were placeholders
// returning a fixed string — no caller (explorer, GUI, harness) used them.

/// Global status - canonical status all nodes converge on
/// Economic policy: quorum-based weighted convergence for safety + liveness
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GlobalStatus {
    /// Transaction unknown to querying node (may exist elsewhere)
    /// Economic impact: unknown - not rejected, just not seen
    Unknown,

    /// Transaction pending (in mempool or orphan, not yet in DAG)
    /// Economic impact: not yet accepted, may be resolved
    Pending,

    /// Transaction in DAG but insufficient references/weight
    /// Economic impact: visible but not stable, may be reorganized
    Unconfirmed,

    /// Transaction in DAG with sufficient references (≥3)
    /// Economic impact: stable, reorganization unlikely but possible
    Confirmed,

    /// Transaction economically stable (weight ≥5.0)
    /// Economic impact: reorganization extremely unlikely, practically final
    Stable,

    /// Transaction finalized by VQV consensus votes
    /// Economic impact: irreversible, guaranteed by protocol
    Finalized,
}

// §J (purged): NodeStatusReport + GlobalStatusResolver::reconcile_quorum were
// VQV vestiges — never called by any production code path. Only the single-
// node reconciliation (GlobalStatus::reconcile_single) is live (see
// get_transaction_status). GlobalStatus itself remains, as it is part of the
// transaction status RPC surface.
impl GlobalStatus {
    /// Minimum number of references for "confirmed" status
    pub const MIN_CONFIRMATIONS: usize = 3;

    /// Minimum cumulative weight for "stable" status
    pub const STABILITY_THRESHOLD: f64 = 5.0;

    /// Check if status is considered "final" for practical purposes
    pub fn is_practically_final(&self) -> bool {
        matches!(self, Self::Stable | Self::Finalized)
    }

    /// Convert to string for RPC response
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Pending => "pending",
            Self::Unconfirmed => "unconfirmed",
            Self::Confirmed => "confirmed",
            Self::Stable => "stable",
            Self::Finalized => "finalized",
        }
    }

    /// Reconcile local and consensus status into global status (single node)
    /// Economic policy: conservative convergence - choose minimum certainty
    pub fn reconcile(local: LocalStatus, consensus: ConsensusStatus) -> Self {
        Self::reconcile_single(local, consensus)
    }

    /// Reconcile single node's local and consensus status
    /// Economic policy: conservative convergence for single node
    pub fn reconcile_single(local: LocalStatus, consensus: ConsensusStatus) -> Self {
        match local {
            LocalStatus::Unknown => Self::Unknown,
            LocalStatus::Orphan => Self::Pending,
            LocalStatus::InMempool => Self::Pending,
            LocalStatus::InLocalDag => match consensus {
                ConsensusStatus::Unconfirmed => Self::Unconfirmed,
                ConsensusStatus::Confirmed => Self::Confirmed,
                ConsensusStatus::Stable => Self::Stable,
                ConsensusStatus::Finalized => Self::Finalized,
            },
        }
    }
}

impl std::fmt::Display for GlobalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Local status of a transaction from this node's perspective
/// Economic policy: reflects what this node knows, not global consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalStatus {
    /// Transaction unknown to this node (may exist elsewhere)
    /// Economic impact: unknown - not rejected, just not seen
    Unknown,

    /// Transaction is waiting for missing parents (orphan)
    /// Economic impact: not yet accepted, may be resolved when parents arrive
    Orphan,

    /// Transaction accepted locally (in mempool) but not yet in DAG
    /// Economic impact: ledger committed, but may be reorganized
    InMempool,

    /// Transaction is in this node's DAG
    /// Economic impact: visible locally, consensus status separate
    InLocalDag,
}

impl LocalStatus {
    /// Convert to string for RPC response
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Orphan => "orphan",
            Self::InMempool => "in_mempool",
            Self::InLocalDag => "in_local_dag",
        }
    }
}

impl std::fmt::Display for LocalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Consensus status of a transaction from network perspective
/// Economic policy: reflects global stability, not local knowledge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusStatus {
    /// Not yet confirmed by network (insufficient references/weight)
    /// Economic impact: may be reorganized
    Unconfirmed,

    /// Confirmed by sufficient references
    /// Economic policy: confirmed = at least MIN_CONFIRMATIONS references
    /// Economic impact: stable, reorganization unlikely but possible
    Confirmed,

    /// Economically stable (high weight/references)
    /// Economic policy: economically_stable = weight above STABILITY_THRESHOLD
    /// Economic impact: reorganization extremely unlikely, practically final
    Stable,

    /// Finalized by consensus mechanism
    /// Economic impact: irreversible, guaranteed by protocol (VQV votes)
    Finalized,
}

impl ConsensusStatus {
    /// Minimum number of references for "confirmed" status
    pub const MIN_CONFIRMATIONS: usize = 3;

    /// Minimum cumulative weight for "stable" status
    pub const STABILITY_THRESHOLD: f64 = 5.0;

    /// Check if status is considered "final" for practical purposes
    pub fn is_practically_final(&self) -> bool {
        matches!(self, Self::Stable | Self::Finalized)
    }

    /// Convert to string for RPC response
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unconfirmed => "unconfirmed",
            Self::Confirmed => "confirmed",
            Self::Stable => "stable",
            Self::Finalized => "finalized",
        }
    }
}

impl std::fmt::Display for ConsensusStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Combined transaction status for distributed environment
/// Economic policy: separates local knowledge from global consensus with resolution layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatus {
    pub local_status: LocalStatus,
    pub consensus_status: ConsensusStatus,
    pub global_status: GlobalStatus,
    pub practically_final: bool,
}

impl TransactionStatus {
    /// Create new transaction status with global reconciliation
    pub fn new(local_status: LocalStatus, consensus_status: ConsensusStatus) -> Self {
        let global_status = GlobalStatus::reconcile(local_status, consensus_status);
        let practically_final = global_status.is_practically_final();
        Self {
            local_status,
            consensus_status,
            global_status,
            practically_final,
        }
    }

    /// Convert to string for RPC response (combined status)
    pub fn as_str(&self) -> String {
        format!(
            "{}:{}:{}",
            self.local_status.as_str(),
            self.consensus_status.as_str(),
            self.global_status.as_str()
        )
    }
}

/// Transaction status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatusResponse {
    pub tx_id: TransactionId,
    pub local_status: String,
    pub consensus_status: String,
    pub global_status: String,
    pub confirmed: bool,
    pub practically_final: bool,
    pub block_height: Option<u64>,
    pub timestamp: Option<u64>,
    pub reference_count: usize,
    pub weight: f64,
}

/// Transaction history item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryItem {
    pub hash: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub timestamp: u64,
    pub is_incoming: bool,
}

/// Transaction history response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryResponse {
    pub transactions: Vec<TransactionHistoryItem>,
    pub total_count: usize,
}

// §J (purged): StakingResponse / StakingInfoResponse were VQV vestiges — no
// RPC dispatch, no caller anywhere in the tree.

/// Account nonce response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountNonceResponse {
    pub address: Address,
    pub current_nonce: u64,
    pub next_nonce: u64,
}

/// Mempool for transaction queuing with economic priority
/// Economic policy: transactions are prioritized by fee rate (fee per unit of work)
pub struct Mempool {
    queue: VecDeque<Transaction>,
    max_size: usize,
    semaphore: Arc<Semaphore>,
    /// Minimum fee required for a transaction to be accepted
    min_fee: u64,
}

impl Mempool {
    /// Create new mempool with max size and minimum fee
    pub fn new(max_size: usize, max_concurrent: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(max_size),
            max_size,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            min_fee: 1, // Minimum fee of 1 unit (anti-spam)
        }
    }

    /// Set minimum fee
    pub fn set_min_fee(&mut self, min_fee: u64) {
        self.min_fee = min_fee;
    }

    /// Get minimum fee
    pub fn min_fee(&self) -> u64 {
        self.min_fee
    }

    /// Add transaction to mempool with economic validation
    /// Economic policy: transaction must meet minimum fee requirement
    /// When mempool is full, lower-fee transactions may be evicted to make room for higher-fee ones
    /// Add transaction to mempool (INTERNAL USE ONLY)
    /// 🔒 ZERO TRUST: This method is private. Use TransactionProcessor for all mempool operations.
    pub async fn add_internal(&mut self, tx: Transaction) -> Result<(), RpcError> {
        // Economic validation: check minimum fee
        if tx.fee < self.min_fee {
            return Err(RpcError(format!(
                "Insufficient fee: {} < minimum {}",
                tx.fee, self.min_fee
            )));
        }

        // If mempool is full, try to evict lower-fee transactions
        if self.queue.len() >= self.max_size {
            // Check if this transaction has higher fee than the lowest in mempool
            let min_fee_in_pool = self.queue.iter().map(|t| t.fee).min().unwrap_or(0);

            if tx.fee > min_fee_in_pool {
                // Evict the lowest-fee transaction to make room
                if let Some(pos) = self.queue.iter().position(|t| t.fee == min_fee_in_pool) {
                    self.queue.remove(pos);
                    tracing::info!("🔄 Evicted low-fee transaction (fee: {}) to make room for higher-fee (fee: {})", min_fee_in_pool, tx.fee);
                }
            } else {
                return Err(RpcError(
                    "Mempool full (consider higher fee for priority)".to_string(),
                ));
            }
        }

        self.queue.push_back(tx);
        Ok(())
    }

    /// Get transaction semaphore for rate limiting
    pub fn semaphore(&self) -> Arc<Semaphore> {
        self.semaphore.clone()
    }

    /// Get queue size
    pub fn size(&self) -> usize {
        self.queue.len()
    }

    /// Get max size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Pop transaction from mempool (FIFO)
    pub fn pop_front(&mut self) -> Option<Transaction> {
        self.queue.pop_front()
    }

    /// Remove transaction by ID (for rollback)
    pub fn remove_transaction(&mut self, tx_id: &TransactionId) {
        self.queue.retain(|tx| &tx.id != tx_id);
    }

    /// Get all transaction IDs in mempool (for testing)
    pub fn get_transaction_ids(&self) -> Vec<TransactionId> {
        self.queue.iter().map(|tx| tx.id).collect()
    }
}

/// Recent transactions response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentTransactionsResponse {
    pub transactions: Vec<TransactionInfo>,
    pub total_count: u64,
}

/// Transaction info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub tx_id: TransactionId,
    pub sender: Address,
    pub receiver: Address,
    pub amount: u64,
    pub fee: u64,
    pub parents: [TransactionId; 2],
    pub timestamp: u64,
    pub status: String,
}

/// DAG graph response for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagGraphResponse {
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
    pub total_transactions: usize,
}

/// DAG node for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub tx_id: TransactionId,
    pub sender: Address,
    pub receiver: Address,
    pub amount: u64,
    pub timestamp: u64,
    pub weight: f64,
}

/// DAG edge for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagEdge {
    pub from: TransactionId,
    pub to: TransactionId,
}

/// Tips response
/// V-20 FIX: tips are canonical hex strings (see transaction::encode_id),
/// NEVER raw byte arrays. Numeric arrays broke every client (CLI, GUI) which
/// silently fell back to genesis parents [0,0] and turned the DAG into a star.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipsResponse {
    pub tips: Vec<String>,
    pub count: usize,
}

/// DAG snapshot response for explorer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagSnapshotResponse {
    pub transactions: Vec<TransactionSnapshot>,
    pub count: usize,
}

/// Transaction snapshot with weight and signature validity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSnapshot {
    pub hash: String,
    pub parents: Vec<String>,
    pub cumulative_weight: f64,
    pub signature_valid: bool,
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub timestamp: u64,
}

/// Mining status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningStatusResponse {
    pub is_mining: bool,
    pub hashrate: String,
}

/// Faucet response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetResponse {
    pub success: bool,
    pub amount: u64,
    pub message: String,
}

/// Create account response (private key NEVER returned over RPC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountResponse {
    pub success: bool,
    pub address: String,
    pub public_key: String,
    pub message: String,
}

/// RPC server implementation
pub struct AetherRpcImpl {
    dag: Arc<RwLock<DAG>>,
    ledger: Arc<RwLock<Ledger>>,
    storage: Arc<RwLock<crate::storage::Storage>>,
    mempool: Arc<RwLock<Mempool>>,
    p2p_network: Arc<crate::p2p::P2PNetwork>,
    mining_enabled: Arc<RwLock<bool>>,
    orphans: Arc<RwLock<std::collections::HashMap<[u8; 32], Transaction>>>,
    faucet_cooldowns: Arc<RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>>,
    fee_oracle: Arc<RwLock<FeeOracle>>,
    /// Faucet signing key, loaded from a SERVER-ONLY file (`data_dir/faucet.key`)
    /// at startup. `None` means the faucet is disabled (no secret in the source).
    faucet_key: Option<SigningKey>,
    rate_limiter: RateLimiter,
    /// H3: per-client-IP budget so a single attacker cannot exhaust the shared
    /// per-method budget (which would DoS every other client).
    rate_limiter_per_ip: RateLimiter,
    start_time: std::time::Instant,
}

struct FeeOracle {
    base_fee: u64,
    last_adjustment: std::time::Instant,
}

impl FeeOracle {
    fn new() -> Self {
        Self {
            base_fee: 1,
            last_adjustment: std::time::Instant::now(),
        }
    }

    fn adjust(&mut self, mempool_occupancy: f64) {
        if self.last_adjustment.elapsed() < std::time::Duration::from_secs(10) {
            return;
        }
        self.last_adjustment = std::time::Instant::now();
        if mempool_occupancy > 0.8 {
            self.base_fee = (self.base_fee * 2).min(100);
        } else if mempool_occupancy > 0.5 {
            self.base_fee = (self.base_fee as f64 * 1.5) as u64;
        } else if mempool_occupancy < 0.2 && self.base_fee > 1 {
            self.base_fee = (self.base_fee / 2).max(1);
        }
    }

    fn current_fee(&self) -> u64 {
        self.base_fee
    }
}

impl AetherRpcImpl {
    /// Create new RPC implementation
    pub fn new(
        dag: Arc<RwLock<DAG>>,
        ledger: Arc<RwLock<Ledger>>,
        storage: Arc<RwLock<crate::storage::Storage>>,
        ledger_path: std::path::PathBuf,
        mempool: Arc<RwLock<Mempool>>,
        p2p_network: Arc<crate::p2p::P2PNetwork>,
        mining_enabled: Arc<RwLock<bool>>,
        orphans: Arc<RwLock<std::collections::HashMap<[u8; 32], Transaction>>>,
    ) -> Self {
        // Load the faucet secret key from a SERVER-ONLY file. The secret is
        // NEVER in the source code or distributed binary. Without the file the
        // faucet endpoint is disabled. The genesis still funds FAUCET_ADDRESS
        // (public), but only an operator holding the key can spend it.
        let faucet_key = Self::load_faucet_key(&ledger_path);
        Self {
            dag,
            ledger,
            storage,
            mempool,
            p2p_network,
            mining_enabled,
            orphans,
            faucet_cooldowns: Arc::new(RwLock::new(std::collections::HashMap::new())),
            fee_oracle: Arc::new(RwLock::new(FeeOracle::new())),
            faucet_key,
            rate_limiter: RateLimiter::new(200, 10), // 200 requests per 10s window
            rate_limiter_per_ip: RateLimiter::new(40, 10), // 40 requests per 10s per client IP
            start_time: std::time::Instant::now(),
        }
    }

    /// Load the faucet signing key from `data_dir/faucet.key` (a 64-char hex
    /// Ed25519 secret key, one line). Returns `None` (faucet disabled) if the
    /// file is absent, invalid, or does NOT match the genesis faucet address.
    /// The genesis credits `FAUCET_ADDRESS` (a public constant): only the key
    /// whose public key derives to that exact address can spend those funds.
    ///
    /// Warning messages are emitted at most once per key file path so that
    /// repeated constructions (per-RPC-request impls) cannot flood the logs.
    pub(crate) fn load_faucet_key(ledger_path: &std::path::Path) -> Option<SigningKey> {
        use std::sync::OnceLock;
        static WARNED: OnceLock<std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>> =
            OnceLock::new();
        fn warn_once(key_file: &std::path::Path, msg: String) {
            let warned = WARNED.get_or_init(Default::default);
            let mut set = warned.lock().unwrap_or_else(|e| e.into_inner());
            if set.insert(key_file.to_path_buf()) {
                tracing::warn!("{msg}");
            }
        }

        let data_dir = ledger_path.parent()?;
        let key_file = data_dir.join("faucet.key");
        let Ok(content) = std::fs::read_to_string(&key_file) else {
            warn_once(
                &key_file,
                format!("🔒 Faucet disabled: no faucet.key at {:?}", key_file),
            );
            return None;
        };
        let trimmed = content.trim();
        let Ok(seed_hex) = hex::decode(trimmed) else {
            warn_once(
                &key_file,
                "🔒 Faucet disabled: invalid faucet.key hex".to_string(),
            );
            return None;
        };
        if seed_hex.len() != 32 {
            warn_once(
                &key_file,
                "🔒 Faucet disabled: faucet.key must be 32 bytes".to_string(),
            );
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&seed_hex);
        let key = SigningKey::from_bytes(&bytes);

        // The faucet can only spend the GENESIS faucet balance. The provided
        // key must therefore derive to FAUCET_ADDRESS; otherwise every faucet
        // transaction would be rejected (address with zero balance).
        let verifying_key = key.verifying_key();
        let mut derived_addr = [0u8; 32];
        derived_addr.copy_from_slice(&verifying_key.to_bytes()[..32]);
        let expected_addr: [u8; 32] = match hex::decode(crate::genesis::FAUCET_ADDRESS) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&bytes);
                a
            }
            _ => {
                warn_once(
                    &key_file,
                    "🔒 Faucet disabled: invalid genesis FAUCET_ADDRESS constant".to_string(),
                );
                return None;
            }
        };
        if derived_addr != expected_addr {
            warn_once(
                &key_file,
                format!(
                    "🔒 Faucet disabled: faucet.key does not match genesis FAUCET_ADDRESS (derived {}, expected {})\n   The genesis credits FAUCET_ADDRESS; only the original genesis key can spend it.",
                    hex::encode(derived_addr),
                    crate::genesis::FAUCET_ADDRESS
                ),
            );
            return None;
        }
        tracing::info!("🔑 Faucet key loaded from {:?}", key_file);
        Some(key)
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: Address) -> Result<BalanceResponse, RpcError> {
        let ledger = self.ledger.read().await;

        let balance = ledger.get_balance(&address);
        Ok(BalanceResponse { address, balance })
    }

    /// Send a transaction
    pub async fn send_transaction(
        &self,
        params: serde_json::Value,
    ) -> Result<TransactionResponse, RpcError> {
        tracing::debug!("RAW RPC PARAMS RECEIVED: {:?}", params);

        // Parse params manually - expect array with single string
        let tx_data: String = match params {
            serde_json::Value::Array(arr) if arr.len() == 1 => match &arr[0] {
                serde_json::Value::String(s) => s.clone(),
                _ => {
                    tracing::error!("❌ Expected string in params array, got: {:?}", arr[0]);
                    return Err(RpcError(
                        "Invalid params: expected string in array".to_string(),
                    ));
                }
            },
            serde_json::Value::String(s) => s.clone(),
            _ => {
                tracing::error!("❌ Expected array or string, got: {:?}", params);
                return Err(RpcError(format!(
                    "Invalid params: expected array with string or string, got {:?}",
                    params
                )));
            }
        };

        tracing::info!("📨 Received RPC send_transaction request");
        tracing::debug!("Transaction data length: {} bytes", tx_data.len());

        // H7: the full payload only at debug level (log-amplification guard:
        // an attacker flooding invalid submissions must not balloon the logs).
        tracing::debug!("Raw hex: {}", tx_data);
        tracing::debug!("Payload RPC reçu: {}", tx_data);

        // Step 1: Reception - Parse transaction from hex string (SDK sends hex-encoded bincode)
        let tx_bytes = match hex::decode(&tx_data) {
            Ok(bytes) => {
                tracing::debug!("✅ Reception: {} bytes decoded from hex", bytes.len());
                bytes
            }
            Err(e) => {
                tracing::error!("❌ Reception - Erreur hex decode: {}", e);
                tracing::error!("Données reçues: {}", tx_data);
                return Err(RpcError(format!("Invalid hex data: {}", e)));
            }
        };

        // Size cap BEFORE deserialization: a legitimate Aether transaction is a
        // few hundred bytes. Reject oversized submissions (memory DoS guard).
        if tx_bytes.len() > MAX_RPC_TX_SIZE {
            tracing::warn!(
                "❌ Reception - Oversized transaction: {} bytes (max {})",
                tx_bytes.len(),
                MAX_RPC_TX_SIZE
            );
            return Err(RpcError(format!(
                "Transaction too large: {} bytes (max {})",
                tx_bytes.len(),
                MAX_RPC_TX_SIZE
            )));
        }

        // Step 2: Parsing - Deserialize transaction using bincode (same format as GUI)
        let tx: Transaction = match bincode::deserialize::<Transaction>(&tx_bytes) {
            Ok(transaction) => {
                tracing::info!(
                    "✅ Parsing: Transaction désérialisée pour {}",
                    hex::encode(transaction.sender)
                );
                transaction
            }
            Err(e) => {
                tracing::error!("❌ Parsing - Erreur deserialize: {}", e);
                tracing::error!("Taille des données: {} bytes", tx_bytes.len());

                // Hex Dump of first 16 bytes for debugging
                let hex_dump = if tx_bytes.len() >= 16 {
                    format!("{}", hex::encode(&tx_bytes[..16]))
                } else {
                    format!("{}", hex::encode(&tx_bytes))
                };
                tracing::error!("HEX DUMP (first 16 bytes): {}", hex_dump);

                return Err(RpcError(format!("Invalid transaction data: {}", e)));
            }
        };

        // Use common validation and processing logic
        self.process_transaction(tx, "RPC").await
    }

    /// Common transaction validation and processing logic (used by both RPC and P2P)
    /// 🔒 ZERO TRUST: Uses TransactionProcessor as single entry point
    /// Economic policy: validation BEFORE any state modification, atomic rollback on failure
    pub async fn process_transaction(
        &self,
        tx: Transaction,
        source: &str,
    ) -> Result<TransactionResponse, RpcError> {
        // CONSENSUS ACCEPTANCE RULES:
        // - VALID BUT NOT ACCEPTABLE: Transaction passes basic checks (PoW, signature) but has missing parents -> orphaned
        // - DEFINITIVELY INVALID: Invalid PoW, signature, balance, nonce, duplicate, double spend, sender conflict -> rejected
        // - TEMPORARILY DEFERRED: Mempool full, lock contention -> retry later
        // - ACCEPTED: Passes all validation, committed to ledger and DAG -> pending confirmation

        // Validation logs (H7: debug level — 8 info lines per tx was a
        // log-amplification vector under sustained invalid submissions).
        tracing::debug!(
            "🔍 Processing transaction [{}] - Sender: {}",
            source,
            hex::encode(tx.sender)
        );
        tracing::debug!(
            "🔍 Processing transaction [{}] - Receiver: {}",
            source,
            hex::encode(tx.receiver)
        );
        tracing::debug!(
            "🔍 Processing transaction [{}] - Amount: {}",
            source,
            tx.amount
        );
        tracing::debug!("🔍 Processing transaction [{}] - Fee: {}", source, tx.fee);
        tracing::debug!(
            "🔍 Processing transaction [{}] - Parents: [{}, {}]",
            source,
            hex::encode(tx.parents[0]),
            hex::encode(tx.parents[1])
        );
        tracing::debug!(
            "🔍 Processing transaction [{}] - PoW Nonce: {}",
            source,
            tx.nonce
        );
        tracing::debug!(
            "🔍 Processing transaction [{}] - Account Nonce: {}",
            source,
            tx.account_nonce
        );

        // STEP 2: USE TRANSACTION PROCESSOR (ZERO TRUST SINGLE ENTRY POINT)
        // 🔒 All validation and state mutations go through TransactionProcessor.
        // 🪙 Monetary policy: ZERO EMISSION - the processor never mints tokens.
        // H1: orphan handling (missing parents) now lives INSIDE the processor,
        // AFTER the pure validation gate (PoW + signature). It returns
        // ProcessingError::Orphan(missing) and we park it below — never
        // before, so unvalidated garbage cannot fill the orphan store.
        let processor = TransactionProcessor::new();
        let mempool = self.mempool.read().await;
        let mempool_occupancy = mempool.size() as f64 / mempool.max_size() as f64;
        let min_fee = {
            let mut oracle = self.fee_oracle.write().await;
            oracle.adjust(mempool_occupancy);
            oracle.current_fee()
        };
        drop(mempool);
        // Sync fee to mempool (acquire write lock separately to avoid deadlock)
        {
            let mut mempool_write = self.mempool.write().await;
            mempool_write.set_min_fee(min_fee);
        }

        // V-22 FIX: retry transient LOCK CONTENTION instead of dropping the
        // transaction. The processor uses try_write() so it can fail with
        // LockError whenever another task (P2P channel, orphan solver, another
        // RPC send) holds the DAG/ledger/mempool locks. Before this fix the
        // tx was lost forever: it never entered the DAG, and the peer-side
        // seen-transactions dedup meant a later resync never re-delivered it.
        let mut lock_attempts = 0;
        let result = loop {
            match processor
                .process(tx.clone(), &self.dag, &self.ledger, &self.mempool, min_fee)
                .await
            {
                Ok(_) => break Ok(()),
                Err(ProcessingError::LockError(_)) if lock_attempts < 20 => {
                    lock_attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(25 * lock_attempts as u64))
                        .await;
                }
                Err(e) => break Err(e),
            }
        };
        if lock_attempts > 0 {
            tracing::info!(
                "🔁 Lock contention retried {} time(s) for tx {}",
                lock_attempts,
                hex::encode(tx.id)
            );
        }

        match result {
            Ok(_) => {
                tracing::info!("✅ Transaction processed successfully via TransactionProcessor");
                // 💾 Persist to mempool storage
                if let Ok(storage) = self.storage.try_read() {
                    let _ = storage.put_mempool_tx(&tx);
                }
                // 🔄 Broadcast to P2P peers
                self.p2p_network.broadcast_transaction(tx.clone()).await;
                Ok(TransactionResponse {
                    tx_id: tx.id,
                    status: "in_mempool".to_string(),
                    message: "Transaction accepted locally (in mempool, not yet in DAG)"
                        .to_string(),
                })
            }
            Err(ProcessingError::Orphan(missing_parents)) => {
                // H1: the transaction passed the pure gate (PoW + signature)
                // but its parents are not in the DAG yet. Park it (bounded)
                // and re-request the parents over P2P.
                if self.park_orphan(tx, &missing_parents).await {
                    Err(RpcError(format!(
                        "Transaction has {} missing parent(s). Stored as orphan and requesting via P2P. Please retry in a few seconds.",
                        missing_parents.len()
                    )))
                } else {
                    Err(RpcError(format!(
                        "Orphan limit reached ({}). Transaction rejected.",
                        MAX_ORPHANS
                    )))
                }
            }
            Err(ProcessingError::ValidationFailed(ValidationError::MissingParent {
                parent_id,
                ..
            })) => {
                // Defensive: unreachable in the current flow (the orphan gate
                // and validate_dag run under the same DAG read lock), but keep
                // the behavior identical if a future refactor reorders them.
                let missing = vec![parent_id];
                if self.park_orphan(tx, &missing).await {
                    Err(RpcError(format!(
                        "Transaction has {} missing parent(s). Stored as orphan and requesting via P2P. Please retry in a few seconds.",
                        missing.len()
                    )))
                } else {
                    Err(RpcError(format!(
                        "Orphan limit reached ({}). Transaction rejected.",
                        MAX_ORPHANS
                    )))
                }
            }
            Err(e) => {
                tracing::error!("❌ Transaction processing failed: {}", e);
                Err(RpcError(e.to_string()))
            }
        }
    }

    /// H1: persist a pure-validated orphan (PoW + signature already checked by
    /// the processor) under a hard cap, and request the missing parents over
    /// P2P. Returns false when the orphan store is full (nothing persisted).
    async fn park_orphan(&self, tx: Transaction, missing_parents: &[[u8; 32]]) -> bool {
        // Cap: never let the orphan store grow without bound.
        {
            let orphans = self.orphans.read().await;
            if orphans.len() >= MAX_ORPHANS {
                tracing::warn!(
                    "⛔ Orphan limit reached ({}), rejecting orphan {}",
                    MAX_ORPHANS,
                    hex::encode(&tx.id[..8])
                );
                return false;
            }
        }

        // Persist to disk (survives restart). Use the main storage
        // (data_dir/sled_db), NOT a fresh sled at ledger_path.parent() which
        // silently opened a different database at the data-dir root, leaving
        // orphans invisible to the node's DAG.
        if let Ok(storage_guard) = self.storage.try_read() {
            if let Err(e) = storage_guard.put_orphan(tx.id, &tx) {
                tracing::error!("❌ Failed to persist orphan to storage: {}", e);
            }
        }

        // Also keep in memory for fast access.
        {
            let mut orphans = self.orphans.write().await;
            orphans.insert(tx.id, tx.clone());
        }

        // Request the missing parents via P2P (each in its own task so one
        // slow peer cannot block the others).
        for parent in missing_parents {
            let p2p = self.p2p_network.clone();
            let parent_hash = parent.to_vec();
            tokio::spawn(async move {
                p2p.request_transaction(parent_hash).await;
            });
        }

        tracing::info!(
            "📦 Orphan stored: {} (missing {} parent(s)) - persisted to disk",
            hex::encode(&tx.id),
            missing_parents.len()
        );
        true
    }

    /// Process orphans - retry transactions that were waiting for parents
    pub async fn process_orphans(&self) {
        let mut orphans_to_process = Vec::new();

        // Load orphans from disk on startup
        // 🔧 FIX: use the main storage (data_dir/sled_db), NOT a new sled at
        // ledger_path.parent() which silently opened a different database at
        // the data-dir root.
        if let Ok(storage_guard) = self.storage.try_read() {
            if let Ok(disk_orphans) = storage_guard.get_all_orphans() {
                tracing::info!("📦 Loaded {} orphans from disk", disk_orphans.len());
                for orphan in disk_orphans {
                    let mut orphans = self.orphans.write().await;
                    if !orphans.contains_key(&orphan.id) {
                        orphans.insert(orphan.id, orphan.clone());
                    }
                }
            }
        }

        // Check which orphans can now be processed (parents available)
        {
            let orphans = self.orphans.read().await;
            let dag = self.dag.read().await;

            for (tx_id, orphan) in orphans.iter() {
                let parent0_ok = orphan.parents[0] == [0u8; 32]
                    || dag.transactions().contains_key(&orphan.parents[0]);
                let parent1_ok = orphan.parents[1] == [0u8; 32]
                    || dag.transactions().contains_key(&orphan.parents[1]);

                if parent0_ok && parent1_ok {
                    tracing::info!(
                        "🔗 Orphan {} resolved - parents now available",
                        hex::encode(&tx_id[..8])
                    );
                    orphans_to_process.push((*tx_id, orphan.clone()));
                }
            }
        }

        // 🔧 FIX: Re-request missing parents of unresolved orphans via P2P.
        // Previously parents were only requested once when the orphan was
        // first received - if that GetData was lost (peer not connected at
        // that exact moment), the orphan stayed stuck forever. Re-request
        // every cycle so chains converge.
        {
            let missing_parent_hashes: Vec<[u8; 32]> = {
                let orphans = self.orphans.read().await;
                let dag = self.dag.read().await;
                let mut hashes: Vec<[u8; 32]> = Vec::new();
                for (_tx_id, orphan) in orphans.iter() {
                    for parent in orphan.parents.iter() {
                        if *parent != [0u8; 32]
                            && !dag.transactions().contains_key(parent)
                            && !hashes.contains(parent)
                        {
                            hashes.push(*parent);
                        }
                        if hashes.len() >= 32 {
                            break;
                        }
                    }
                    if hashes.len() >= 32 {
                        break;
                    }
                }
                hashes
            };

            if !missing_parent_hashes.is_empty() {
                for parent_hash in missing_parent_hashes {
                    tracing::info!(
                        "📡 Orphan Solver - Re-requesting missing parent via P2P: {}",
                        hex::encode(&parent_hash[..8])
                    );
                    self.p2p_network
                        .request_transaction(parent_hash.to_vec())
                        .await;
                    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
                }
            }
        }

        // Process resolved orphans
        for (tx_id, orphan) in orphans_to_process {
            tracing::info!(
                "🔄 Re-processing orphan transaction: {}",
                hex::encode(&tx_id[..8])
            );
            match self.process_transaction(orphan, "Orphan").await {
                Ok(_) => {
                    tracing::info!(
                        "✅ Orphan transaction successfully processed: {}",
                        hex::encode(&tx_id[..8])
                    );
                    // Remove from orphans on success
                    let mut orphans = self.orphans.write().await;
                    orphans.remove(&tx_id);

                    // Also remove from disk
                    if let Ok(storage_guard) = self.storage.try_read() {
                        let _ = storage_guard.remove_orphan(tx_id);
                    }
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    // Check if error is permanent (replay, double spend, etc.)
                    let is_permanent = error_msg.contains("Duplicate transaction")
                        || error_msg.contains("Double spend")
                        || error_msg.contains("Sender conflict");

                    if is_permanent {
                        tracing::warn!(
                            "🗑️ Orphan {} permanently invalid, removing from queue",
                            hex::encode(&tx_id[..8])
                        );
                        let mut orphans = self.orphans.write().await;
                        orphans.remove(&tx_id);

                        // Also remove from disk
                        if let Ok(storage_guard) = self.storage.try_read() {
                            let _ = storage_guard.remove_orphan(tx_id);
                        }
                    } else {
                        // Temporary error (mempool full, lock error, etc.) - keep in queue
                        tracing::info!(
                            "📦 Orphan {} kept in queue (temporary error)",
                            hex::encode(&tx_id[..8])
                        );
                    }
                }
            }
        }
    }

    /// Get DAG statistics
    pub async fn get_dag_stats(&self) -> Result<DagStatsResponse, RpcError> {
        let dag = self.dag.read().await;

        let total_transactions = dag.transaction_count() as u64;
        let tip_count = dag.tip_count();
        // Height = number of accepted transactions in the DAG (each accepted tx
        // is one consensus step). The DAG is the single source of truth.
        let height = total_transactions;
        let epoch = 0u64;
        let connected_peers = self.p2p_network.peer_count().await as u32;

        let current_tps = if height > 0 {
            total_transactions as f64 / height.max(1) as f64
        } else {
            0.0
        };

        Ok(DagStatsResponse {
            current_tps,
            total_transactions,
            tip_count,
            epoch,
            connected_peers,
        })
    }

    /// Determine transaction status based on actual protocol state
    /// Economic policy: separates local knowledge from global consensus
    pub async fn determine_transaction_status(&self, tx_id: TransactionId) -> TransactionStatus {
        // Step 1: Determine local status (what this node knows)
        let local_status = {
            // Check if in orphans (waiting for parents)
            {
                let orphans = self.orphans.read().await;
                if orphans.contains_key(&tx_id) {
                    LocalStatus::Orphan
                } else {
                    // Check if in mempool (accepted locally but not in DAG)
                    let mempool = self.mempool.read().await;
                    if mempool.get_transaction_ids().contains(&tx_id) {
                        LocalStatus::InMempool
                    } else {
                        // Check if in DAG
                        let dag = self.dag.read().await;
                        if dag.get_transaction(tx_id).is_some() {
                            LocalStatus::InLocalDag
                        } else {
                            // Unknown to this node (may exist elsewhere)
                            LocalStatus::Unknown
                        }
                    }
                }
            }
        };

        // Step 2: Determine consensus status (global stability)
        // Only meaningful if transaction is in local DAG
        let consensus_status = if local_status == LocalStatus::InLocalDag {
            let dag = self.dag.read().await;
            if let Some(tx) = dag.get_transaction(tx_id) {
                let reference_count = dag
                    .children()
                    .get(&tx_id)
                    .map(|children| children.len())
                    .unwrap_or(0);

                // Check for finalized status (VQV consensus votes)
                // For now, we don't have a finalized mechanism, so we skip this
                // In future, this would check VQV votes or other consensus confirmation

                // Check for stable status (high weight)
                if tx.weight >= ConsensusStatus::STABILITY_THRESHOLD {
                    ConsensusStatus::Stable
                } else if reference_count >= ConsensusStatus::MIN_CONFIRMATIONS {
                    ConsensusStatus::Confirmed
                } else {
                    ConsensusStatus::Unconfirmed
                }
            } else {
                // Should not happen if local_status is InLocalDag
                ConsensusStatus::Unconfirmed
            }
        } else {
            // Not in local DAG, so consensus status is unknown/unconfirmed
            ConsensusStatus::Unconfirmed
        };

        TransactionStatus::new(local_status, consensus_status)
    }

    /// Get transaction status
    pub async fn get_transaction_status(
        &self,
        hash: TransactionId,
    ) -> Result<TransactionStatusResponse, RpcError> {
        let status = self.determine_transaction_status(hash).await;

        let dag = self.dag.read().await;
        let (reference_count, weight, timestamp) = match dag.get_transaction(hash) {
            Some(tx) => {
                let ref_count = dag
                    .children()
                    .get(&hash)
                    .map(|children| children.len())
                    .unwrap_or(0);
                (ref_count, tx.weight, Some(tx.timestamp))
            }
            None => (0, 0.0, None),
        };

        Ok(TransactionStatusResponse {
            tx_id: hash,
            local_status: status.local_status.as_str().to_string(),
            consensus_status: status.consensus_status.as_str().to_string(),
            global_status: status.global_status.as_str().to_string(),
            confirmed: status.global_status == GlobalStatus::Confirmed
                || status.global_status == GlobalStatus::Stable
                || status.global_status == GlobalStatus::Finalized,
            practically_final: status.practically_final,
            block_height: Some(0), // DAG doesn't have block heights
            timestamp,
            reference_count,
            weight,
        })
    }

    /// Get recent transactions for explorer
    pub async fn get_recent_transactions(
        &self,
        limit: u64,
    ) -> Result<RecentTransactionsResponse, RpcError> {
        let dag = self.dag.read().await;
        let transactions: Vec<&Transaction> = dag.transactions().values().collect();

        let limit = limit.min(50) as usize;
        let recent_txs: Vec<TransactionInfo> = transactions
            .iter()
            .take(limit)
            .map(|tx| TransactionInfo {
                tx_id: tx.id,
                sender: tx.sender,
                receiver: tx.receiver,
                amount: tx.amount,
                fee: tx.fee,
                parents: tx.parents,
                timestamp: tx.timestamp,
                status: "confirmed".to_string(),
            })
            .collect();

        Ok(RecentTransactionsResponse {
            transactions: recent_txs,
            total_count: transactions.len() as u64,
        })
    }

    /// Get transaction history for a specific address
    /// H3: bounded result — an optional `limit` (default 100, max 1000) caps
    /// the response size so repeated calls cannot amplify memory usage on a
    /// large DAG. The total match count is still reported exactly.
    pub async fn get_transaction_history(
        &self,
        address: String,
        limit: Option<u64>,
    ) -> Result<TransactionHistoryResponse, RpcError> {
        let dag = self.dag.read().await;

        // Decode address from hex
        let address_bytes =
            hex::decode(&address).map_err(|_| RpcError("Invalid address hex".to_string()))?;
        let address_array: [u8; 32] = address_bytes
            .try_into()
            .map_err(|_| RpcError("Invalid address length".to_string()))?;

        let limit = limit.unwrap_or(100).min(1000) as usize;

        // Filter transactions where address is sender or receiver
        let transactions: Vec<TransactionHistoryItem> = dag
            .transactions()
            .values()
            .filter(|tx| tx.sender == address_array || tx.receiver == address_array)
            .take(limit)
            .map(|tx| {
                let is_incoming = tx.receiver == address_array;
                TransactionHistoryItem {
                    hash: hex::encode(tx.id),
                    sender: hex::encode(tx.sender),
                    receiver: hex::encode(tx.receiver),
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    is_incoming,
                }
            })
            .collect();

        let total_count = dag
            .transactions()
            .values()
            .filter(|tx| tx.sender == address_array || tx.receiver == address_array)
            .count();

        Ok(TransactionHistoryResponse {
            transactions,
            total_count,
        })
    }

    /// Get account nonce for an address
    pub async fn get_account_nonce(
        &self,
        address: &Address,
    ) -> Result<AccountNonceResponse, RpcError> {
        let ledger = self.ledger.read().await;
        let current_nonce = ledger.get_nonce(address);
        let next_nonce = current_nonce + 1;
        drop(ledger);

        Ok(AccountNonceResponse {
            address: *address,
            current_nonce,
            next_nonce,
        })
    }

    /// Get DAG graph for visualization
    /// H3: bounded result — an optional `limit` (default 500, max 5000) caps
    /// the number of nodes serialized so one caller cannot force an O(DAG)
    /// response on a large graph. Edges reference included nodes only.
    pub async fn get_dag_graph(&self, limit: Option<u64>) -> Result<DagGraphResponse, RpcError> {
        let dag = self.dag.read().await;
        let limit = limit.unwrap_or(500).min(5000) as usize;
        let transactions: Vec<&Transaction> = dag.transactions().values().take(limit).collect();
        let included: std::collections::HashSet<TransactionId> =
            transactions.iter().map(|tx| tx.id).collect();

        let nodes: Vec<DagNode> = transactions
            .iter()
            .map(|tx| DagNode {
                tx_id: tx.id,
                sender: tx.sender,
                receiver: tx.receiver,
                amount: tx.amount,
                timestamp: tx.timestamp,
                weight: tx.weight,
            })
            .collect();

        let mut edges: Vec<DagEdge> = Vec::new();
        for tx in transactions.iter() {
            for parent in &tx.parents {
                if !parent.is_empty() && included.contains(parent) {
                    edges.push(DagEdge {
                        from: *parent,
                        to: tx.id,
                    });
                }
            }
        }

        Ok(DagGraphResponse {
            nodes,
            edges,
            total_transactions: transactions.len(),
        })
    }

    /// Get tips from the DAG
    pub async fn get_tips(&self) -> Result<TipsResponse, RpcError> {
        let dag = self.dag.read().await;

        // Get tips (transactions with no children)
        // Only return transactions that exist in the DAG and have no children
        let mut tips: Vec<TransactionId> = dag
            .transactions()
            .values()
            .filter(|tx| !dag.children().contains_key(&tx.id))
            .map(|tx| tx.id)
            .collect();

        // If no tips found, return GENESIS_HASH as default tip
        if tips.is_empty() {
            tracing::warn!("get_tips: No tips found in DAG, returning GENESIS_HASH as default");
            tips.push([0u8; 32]); // GENESIS_HASH
        }

        // V-20 FIX: serialize tips in the canonical hex form so the CLI, the
        // GUI and any external tool can decode them losslessly. Raw byte
        // arrays made `tip.as_str()` return None on every client, which
        // silently fell back to genesis parents and star-shaped DAGs.
        let tips: Vec<String> = tips.iter().map(crate::transaction::encode_id).collect();

        let count = tips.len();

        tracing::debug!(
            "get_tips: Returning {} tips out of {} total transactions",
            count,
            dag.transaction_count()
        );

        Ok(TipsResponse { tips, count })
    }

    /// Get DAG snapshot for explorer
    pub async fn get_dag_snapshot(&self) -> Result<DagSnapshotResponse, RpcError> {
        let dag = self.dag.read().await;

        // Cumulative weight is maintained on the DAG itself (tx.weight =
        // subtree size), so the snapshot reads the stored value directly.
        // Get last 100 transactions
        let transactions: Vec<TransactionSnapshot> = dag
            .transactions()
            .values()
            .take(100)
            .map(|tx| {
                let cumulative_weight = tx.weight.max(0.0);
                let signature_valid = crate::wallet::Wallet::verify_transaction(tx);

                TransactionSnapshot {
                    hash: hex::encode(tx.id),
                    parents: tx.parents.iter().map(|p| hex::encode(p)).collect(),
                    cumulative_weight,
                    signature_valid,
                    sender: hex::encode(tx.sender),
                    receiver: hex::encode(tx.receiver),
                    amount: tx.amount,
                    fee: tx.fee,
                    nonce: tx.nonce,
                    timestamp: tx.timestamp,
                }
            })
            .collect();

        let snapshots = transactions;
        let count = snapshots.len();

        tracing::debug!("get_dag_snapshot: Returning {} transactions", count);

        Ok(DagSnapshotResponse {
            transactions: snapshots,
            count,
        })
    }

    /// Get mining status
    pub async fn get_mining_status(&self) -> Result<MiningStatusResponse, RpcError> {
        let is_mining = *self.mining_enabled.read().await;
        // For now, return a placeholder hashrate
        let hashrate = if is_mining { "1000 H/s" } else { "0 H/s" };

        Ok(MiningStatusResponse {
            is_mining,
            hashrate: hashrate.to_string(),
        })
    }

    /// H5: check a faucet cooldown while evicting all entries older than the
    /// window (bounded memory: the map can only hold one entry per distinct
    /// address active within the window). Returns the remaining seconds if the
    /// address is still cooling down, `None` otherwise.
    fn check_and_evict_cooldowns(
        cooldowns: &mut std::collections::HashMap<[u8; 32], std::time::Instant>,
        address: &Address,
        window: std::time::Duration,
    ) -> Option<u64> {
        let now = std::time::Instant::now();
        cooldowns.retain(|_, last| now.duration_since(*last) < window);
        cooldowns
            .get(address)
            .map(|last| window.as_secs().saturating_sub(last.elapsed().as_secs()))
    }

    /// Faucet - give test funds via a real DAG transaction
    pub async fn faucet(&self, address: Address) -> Result<FaucetResponse, RpcError> {
        // The faucet secret key lives in a server-only file. Without it the
        // faucet is disabled: no operator has handed us the key, so we must
        // not issue funds (fixes V-01: key removed from source).
        let faucet_key = match self.faucet_key.as_ref() {
            Some(k) => k,
            None => {
                return Err(RpcError(
                    "Faucet disabled: no faucet.key on this node".to_string(),
                ))
            }
        };

        // Rate limit: one request per 60s per address.
        // H5: stale entries are evicted on every check so the map is bounded
        // by the number of DISTINCT addresses claimed within the last window
        // (itself bounded by the faucet rate) instead of growing forever.
        {
            let mut cooldowns = self.faucet_cooldowns.write().await;
            if let Some(remaining) = Self::check_and_evict_cooldowns(
                &mut cooldowns,
                &address,
                std::time::Duration::from_secs(60),
            ) {
                return Err(RpcError(format!(
                    "Rate limited. Try again in {}s",
                    remaining
                )));
            }
            cooldowns.insert(address, std::time::Instant::now());
        }

        let amount = 100_000_000_000u64; // 10 AETH in smallest unit
        let fee = 1u64;

        // Get faucet address and public key (derived from the loaded key).
        let verifying_key = faucet_key.verifying_key();
        let faucet_pk_bytes = verifying_key.to_bytes();
        let mut faucet_addr = [0u8; 32];
        faucet_addr.copy_from_slice(&faucet_pk_bytes[..32]);

        // Get DAG tips for parents
        let dag = self.dag.read().await;
        let tips: Vec<TransactionId> = dag
            .transactions()
            .values()
            .filter(|tx| !dag.children().contains_key(&tx.id))
            .map(|tx| tx.id)
            .collect();
        drop(dag);

        let parents: [TransactionId; 2] = if tips.len() >= 2 {
            [tips[0], tips[1]]
        } else if tips.len() == 1 {
            [tips[0], [0u8; 32]]
        } else {
            [[0u8; 32], [0u8; 32]]
        };

        // Get account nonce for faucet
        let ledger = self.ledger.read().await;
        let account_nonce = ledger.get_nonce(&faucet_addr) + 1;
        drop(ledger);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs()
            * 1000;

        // Create transaction with placeholder nonce and signature (to be filled)
        let mut tx = Transaction::new(
            parents,
            faucet_addr,
            address,
            amount,
            fee,
            timestamp,
            0, // placeholder nonce
            account_nonce,
            vec![0u8; 64], // placeholder signature
            faucet_pk_bytes.to_vec(),
        );

        // Mine PoW
        let difficulty = Transaction::default_difficulty();
        let nonce = tx.mine_nonce(difficulty);
        tx.nonce = nonce;
        tx.id = tx.compute_hash();

        // Sign with faucet key
        let signing_hash = tx.compute_signing_hash();
        let signature = faucet_key.sign(&signing_hash);
        tx.signature = signature.to_bytes().to_vec();
        tx.id = tx.compute_hash();

        // Submit via process_transaction (validates, adds to mempool, broadcasts via P2P)
        let _response = self.process_transaction(tx.clone(), "Faucet").await?;

        tracing::info!(
            "💰 Faucet: Sent {} to {} via real DAG tx {}",
            amount,
            hex::encode(address),
            hex::encode(tx.id)
        );

        Ok(FaucetResponse {
            success: true,
            amount,
            message: format!(
                "Successfully sent {} AETH to {} (tx: {})",
                amount / 10_000_000_000,
                hex::encode(address),
                hex::encode(tx.id)
            ),
        })
    }

    /// Create a new account (wallet)
    pub async fn create_account(&self) -> Result<CreateAccountResponse, RpcError> {
        use crate::wallet::Wallet;

        let wallet = Wallet::new();
        let address = hex::encode(wallet.address());
        let public_key = hex::encode(wallet.public_key_bytes());

        tracing::info!("🔑 New account created: {}", address);

        Ok(CreateAccountResponse {
            success: true,
            address,
            public_key,
            message: "Account created successfully. Use CLI 'wallet create' or 'wallet restore' to manage keys.".to_string(),
        })
    }
}

/// Start RPC server
pub async fn start_rpc_server(
    addr: SocketAddr,
    dag: Arc<RwLock<DAG>>,
    ledger: Arc<RwLock<Ledger>>,
    storage: Arc<RwLock<crate::storage::Storage>>,
    ledger_path: std::path::PathBuf,
    mempool: Arc<RwLock<Mempool>>,
    p2p_network: Arc<crate::p2p::P2PNetwork>,
    mining_enabled: Arc<RwLock<bool>>,
    orphans: Arc<RwLock<std::collections::HashMap<[u8; 32], Transaction>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_impl = Arc::new(AetherRpcImpl::new(
        dag,
        ledger,
        storage,
        ledger_path,
        mempool.clone(),
        p2p_network,
        mining_enabled,
        orphans,
    ));

    // Log mempool config
    let mempool_config = {
        let mempool_read = mempool.read().await;
        (
            mempool_read.max_size(),
            mempool_read.semaphore().available_permits(),
        )
    };

    tracing::info!("🚀 Starting RPC server on http://{}", addr);
    tracing::info!(
        "📊 Mempool: max_size={}, available_permits={}",
        mempool_config.0,
        mempool_config.1
    );

    // 1. RPC Route - POST only for JSON-RPC
    let rpc_route = Router::new()
        .route("/", post(handle_rpc))
        .with_state(rpc_impl.clone());

    // 2. UI Route - GET only for explorer
    let ui_route = Router::new()
        .route("/explorer", get(handle_explorer))
        .fallback(get(handle_fallback))
        .with_state(rpc_impl.clone());

    // 3. Metrics route
    let metrics_route = Router::new()
        .route("/metrics", get(handle_metrics))
        .with_state(rpc_impl.clone());

    // 4. Merge routes without conflict
    let app = Router::new()
        .merge(rpc_route)
        .merge(metrics_route)
        .merge(ui_route)
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("✅ RPC + Explorer server listening on http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Handle JSON-RPC POST requests
async fn handle_rpc(
    State(rpc_impl): State<Arc<AetherRpcImpl>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    let method = payload
        .get("method")
        .and_then(|m: &serde_json::Value| m.as_str())
        .unwrap_or("");
    let id = payload
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // H3: rate limit per client IP first (a single attacker must not be able
    // to exhaust the shared per-method budget), then per method globally.
    let ip_key = format!("{}|{}", remote_addr.ip(), method);
    if let Err(retry_after) = rpc_impl.rate_limiter_per_ip.check(ip_key).await {
        return Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": format!("Rate limited. Retry after {}s", retry_after)
            },
            "id": id,
        }));
    }

    // Rate limiting per method (global shared budget, defense in depth)
    if let Err(retry_after) = rpc_impl.rate_limiter.check(method.to_string()).await {
        return Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": format!("Rate limited. Retry after {}s", retry_after)
            },
            "id": id,
        }));
    }

    let result = match method {
        "aether_getBalance" => {
            let addr = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
                .and_then(|a: &serde_json::Value| a.as_str());
            match addr {
                Some(addr_str) => match hex::decode(addr_str) {
                    Ok(bytes) => match bytes.try_into() {
                        Ok(addr) => match rpc_impl.get_balance(addr).await {
                            Ok(response) => {
                                serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                            }
                            Err(e) => Err(e),
                        },
                        Err(_) => Err(RpcError("Invalid address".to_string())),
                    },
                    Err(_) => Err(RpcError("Invalid hex address".to_string())),
                },
                None => Err(RpcError("Missing address parameter".to_string())),
            }
        }
        "aether_sendTransaction" => {
            let params = payload
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![]));
            match rpc_impl.send_transaction(params).await {
                Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
                Err(e) => Err(e),
            }
        }
        "aether_getDagStats" => match rpc_impl.get_dag_stats().await {
            Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
            Err(e) => Err(e),
        },
        "aether_getTransactionStatus" => {
            let hash = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
                .and_then(|h: &serde_json::Value| h.as_str());
            match hash {
                Some(hash_str) => match hex::decode(hash_str) {
                    Ok(bytes) => match bytes.try_into() {
                        Ok(hash) => match rpc_impl.get_transaction_status(hash).await {
                            Ok(response) => {
                                serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                            }
                            Err(e) => Err(e),
                        },
                        Err(_) => Err(RpcError("Invalid hash".to_string())),
                    },
                    Err(_) => Err(RpcError("Invalid hex hash".to_string())),
                },
                None => Err(RpcError("Missing hash parameter".to_string())),
            }
        }
        "aether_getRecentTransactions" => {
            let limit = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
                .and_then(|l: &serde_json::Value| l.as_u64())
                .unwrap_or(10);
            match rpc_impl.get_recent_transactions(limit).await {
                Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
                Err(e) => Err(e),
            }
        }
        "aether_getTransactionHistory" => {
            let address = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
                .and_then(|a: &serde_json::Value| a.as_str());
            // H3: optional limit (index 1), e.g. params:["<addr>", 100].
            let limit = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(1))
                .and_then(|l: &serde_json::Value| l.as_u64());
            match address {
                Some(addr_str) => {
                    match rpc_impl
                        .get_transaction_history(addr_str.to_string(), limit)
                        .await
                    {
                        Ok(response) => {
                            serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                        }
                        Err(e) => Err(e),
                    }
                }
                None => Err(RpcError("Missing address parameter".to_string())),
            }
        }
        "aether_getDagGraph" => {
            // H3: optional limit, e.g. params:[50] (the explorer already
            // sends this). No params means the default (500).
            let limit = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
                .and_then(|l: &serde_json::Value| l.as_u64());
            match rpc_impl.get_dag_graph(limit).await {
                Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
                Err(e) => Err(e),
            }
        }
        "aether_getAccountNonce" => {
            let addr = payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
                .and_then(|a: &serde_json::Value| a.as_str());
            match addr {
                Some(addr_str) => match hex::decode(addr_str) {
                    Ok(bytes) => match bytes.try_into() {
                        Ok(addr) => match rpc_impl.get_account_nonce(&addr).await {
                            Ok(response) => {
                                serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                            }
                            Err(e) => Err(e),
                        },
                        Err(_) => Err(RpcError("Invalid address".to_string())),
                    },
                    Err(_) => Err(RpcError("Invalid hex address".to_string())),
                },
                None => Err(RpcError("Missing address parameter".to_string())),
            }
        }
        "aether_getTips" => match rpc_impl.get_tips().await {
            Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
            Err(e) => Err(e),
        },
        "aether_getDagSnapshot" => match rpc_impl.get_dag_snapshot().await {
            Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
            Err(e) => Err(e),
        },
        "aether_getMiningStatus" => match rpc_impl.get_mining_status().await {
            Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
            Err(e) => Err(e),
        },
        "aether_faucet" => {
            match payload
                .get("params")
                .and_then(|p: &serde_json::Value| p.get(0))
            {
                Some(address_str) => match hex::decode(address_str.as_str().unwrap_or("")) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut address = [0u8; 32];
                        address.copy_from_slice(&bytes);
                        match rpc_impl.faucet(address).await {
                            Ok(response) => {
                                serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => Err(RpcError("Invalid address format".to_string())),
                },
                None => Err(RpcError("Missing address parameter".to_string())),
            }
        }
        "aether_createAccount" => match rpc_impl.create_account().await {
            Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
            Err(e) => Err(e),
        },
        _ => Err(RpcError(format!("Method not found: {}", method))),
    };

    match result {
        Ok(response) => Json(serde_json::json!({
            "jsonrpc": "2.0",
            "result": response,
            "id": id
        })),
        Err(e) => Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -1,
                "message": e.0
            },
            "id": id
        })),
    }
}

/// Handle explorer GET request
async fn handle_explorer(State(state): State<Arc<AetherRpcImpl>>) -> Html<String> {
    // Fetch live stats
    let stats = state.get_dag_stats().await.unwrap_or(DagStatsResponse {
        current_tps: 0.0,
        total_transactions: 0,
        tip_count: 0,
        epoch: 0,
        connected_peers: 0,
    });
    let recent_txs =
        state
            .get_recent_transactions(10)
            .await
            .unwrap_or_else(|_| RecentTransactionsResponse {
                transactions: vec![],
                total_count: 0,
            });

    let stats_json = serde_json::to_string(&stats).unwrap_or_default();
    let txs_json = serde_json::to_string(&recent_txs.transactions).unwrap_or_default();

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AETHER SEDC Explorer</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0d1117; color:#c9d1d9; }}
.header {{ background:#161b22; border-bottom:1px solid #30363d; padding:1rem 2rem; display:flex; align-items:center; gap:1rem; }}
.header h1 {{ color:#58a6ff; font-size:1.5rem; }}
.header span {{ color:#8b949e; font-size:0.9rem; }}
.container {{ max-width:1200px; margin:0 auto; padding:2rem; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem; }}
.stat-card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1.25rem; text-align:center; }}
.stat-card .value {{ font-size:1.8rem; font-weight:700; color:#58a6ff; }}
.stat-card .label {{ font-size:0.8rem; color:#8b949e; margin-top:0.25rem; }}
.section {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:1.5rem; margin-bottom:2rem; }}
.section h2 {{ color:#f0f6fc; font-size:1.1rem; margin-bottom:1rem; }}
table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
th {{ text-align:left; padding:0.5rem; color:#8b949e; border-bottom:2px solid #30363d; }}
td {{ padding:0.5rem; border-bottom:1px solid #21262d; }}
.hash {{ font-family:monospace; color:#58a6ff; font-size:0.8rem; }}
.addr {{ font-family:monospace; color:#d2a8ff; }}
.status {{ display:inline-block; padding:0.1rem 0.4rem; border-radius:4px; font-size:0.75rem; }}
.status.confirmed {{ background:#1b4721; color:#3fb950; }}
.status.pending {{ background:#492d00; color:#d29922; }}
.footer {{ text-align:center; color:#8b949e; font-size:0.8rem; padding:2rem; border-top:1px solid #30363d; }}
</style>
</head>
<body>
<div class="header">
<h1>🔷 AETHER SEDC</h1>
<span>Self-Evolving DAG Consensus — Live Explorer</span>
</div>
<div class="container">

<div class="stats" id="stats">
<div class="stat-card"><div class="value">{total}</div><div class="label">Transactions</div></div>
<div class="stat-card"><div class="value">{tips}</div><div class="label">Tips</div></div>
<div class="stat-card"><div class="value">{tps}</div><div class="label">TPS</div></div>
<div class="stat-card"><div class="value">{epoch}</div><div class="label">Epoch</div></div>
<div class="stat-card"><div class="value">{peers}</div><div class="label">Peers</div></div>
</div>

<div class="section">
<h2>📋 Recent Transactions</h2>
<table>
<thead><tr><th>Hash</th><th>From</th><th>To</th><th>Amount (AETH)</th><th>Fee</th><th>Status</th></tr></thead>
<tbody id="tx-table">{tx_rows}</tbody>
</table>
</div>

<div class="section">
<h2>🔍 Address Lookup</h2>
<p style="margin-bottom:0.75rem;color:#8b949e;">Paste an address to check balance and history.</p>
<div style="display:flex;gap:0.5rem;">
<input id="addr-input" type="text" placeholder="3d17ace653283dbd9aeb..." style="flex:1;padding:0.5rem;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-family:monospace;">
<button onclick="lookup()" style="padding:0.5rem 1rem;background:#238636;border:none;border-radius:6px;color:#fff;cursor:pointer;">Lookup</button>
</div>
<pre id="addr-result" style="margin-top:0.75rem;background:#0d1117;padding:0.75rem;border-radius:6px;font-size:0.8rem;display:none;"></pre>
</div>

<div class="section">
<h2>🧭 DAG Visualization</h2>
<p style="color:#8b949e;margin-bottom:0.75rem;">Latest {dag_count} transactions rendered as a DAG.</p>
<canvas id="dag-canvas" width="1100" height="400" style="background:#0d1117;border:1px solid #30363d;border-radius:6px;width:100%;height:400px;"></canvas>
</div>

</div>
<div class="footer">AETHER SEDC v1.0.1 — 0 unsafe — VQV Consensus</div>

<script>
const STATS = {stats_json};
const TXS = {txs_json};

function toHex(arr) {{
    if (!arr || !arr.map) return '';
    return arr.map(b => (b >>> 0).toString(16).padStart(2,'0')).join('');
}}

function renderStats() {{
    document.getElementById('stats').innerHTML = `
        <div class="stat-card"><div class="value">${{STATS.total_transactions}}</div><div class="label">Transactions</div></div>
        <div class="stat-card"><div class="value">${{STATS.tip_count}}</div><div class="label">Tips</div></div>
        <div class="stat-card"><div class="value">${{STATS.current_tps.toFixed(2)}}</div><div class="label">TPS</div></div>
        <div class="stat-card"><div class="value">${{STATS.epoch}}</div><div class="label">Epoch</div></div>
        <div class="stat-card"><div class="value">${{STATS.connected_peers}}</div><div class="label">Peers</div></div>
    `;
}}

function renderTxs() {{
    const tbody = document.getElementById('tx-table');
    if (!TXS.length) {{
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#8b949e;padding:1rem;">No transactions yet</td></tr>';
        return;
    }}
    tbody.innerHTML = TXS.map(tx => `
        <tr>
            <td class="hash">${{toHex(tx.tx_id).slice(0,16)}}...</td>
            <td class="addr">${{toHex(tx.sender).slice(0,16)}}...</td>
            <td class="addr">${{toHex(tx.receiver).slice(0,16)}}...</td>
            <td>${{tx.amount / 10000000000}}</td>
            <td>${{tx.fee}}</td>
            <td><span class="status confirmed">Confirmed</span></td>
        </tr>
    `).join('');
}}

async function lookup() {{
    const addr = document.getElementById('addr-input').value.trim();
    if (!addr) return;
    const pre = document.getElementById('addr-result');
    pre.style.display = 'block';
    pre.textContent = 'Loading...';
    try {{
        const r = await fetch('/', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{jsonrpc:'2.0',method:'aether_getBalance',params:[addr],id:1}}) }});
        const j = await r.json();
        const bal = j.result ? (j.result.balance / 10000000000) + ' AETH' : 'Error: ' + JSON.stringify(j.error);
        pre.textContent = 'Balance: ' + bal;
    }} catch(e) {{ pre.textContent = 'Error: ' + e.message; }}
}}

async function renderDag() {{
    const canvas = document.getElementById('dag-canvas');
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0,0,canvas.width,canvas.height);
    try {{
        const r = await fetch('/', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{jsonrpc:'2.0',method:'aether_getDagGraph',params:[50],id:1}}) }});
        const j = await r.json();
        if (!j.result || !j.result.nodes) return;
        const nodes = j.result.nodes;
        const edges = j.result.edges || [];
        const n = nodes.length;
        const cx = canvas.width / 2, cy = canvas.height / 2;
        const radius = Math.min(cx, cy) - 60;
        const positions = {{}};
        nodes.forEach((node,i) => {{
            const angle = (i / n) * 2 * Math.PI - Math.PI/2;
            const x = cx + radius * Math.cos(angle);
            const y = cy + radius * Math.sin(angle);
            const key = toHex(node.tx_id);
            positions[key] = {{x,y}};
        }});
        ctx.strokeStyle = '#30363d';
        ctx.lineWidth = 1;
        edges.forEach(e => {{
            const fromKey = toHex(e.from);
            const toKey = toHex(e.to);
            const from = positions[fromKey], to = positions[toKey];
            if (from && to) {{
                ctx.beginPath(); ctx.moveTo(from.x,from.y); ctx.lineTo(to.x,to.y); ctx.stroke();
            }}
        }});
        const colors = ['#58a6ff','#d2a8ff','#3fb950','#d29922','#f85149'];
        nodes.forEach((node,i) => {{
            const key = toHex(node.tx_id);
            const p = positions[key];
            if (!p) return;
            ctx.beginPath(); ctx.arc(p.x,p.y,6,0,2*Math.PI);
            ctx.fillStyle = colors[i % colors.length];
            ctx.fill();
            ctx.strokeStyle = '#fff'; ctx.lineWidth=0.5; ctx.stroke();
            ctx.fillStyle = '#8b949e'; ctx.font='9px monospace';
            ctx.textAlign='center'; ctx.fillText(key.slice(0,8), p.x, p.y-10);
        }});
    }} catch(e) {{ console.log('DAG render error:',e); }}
}}

renderStats();
renderTxs();
renderDag();
setInterval(async () => {{
    try {{
        const r = await fetch('/', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify({{jsonrpc:'2.0',method:'aether_getDagStats',params:[],id:1}}) }});
        const j = await r.json();
        if (j.result) Object.assign(STATS, j.result);
        renderStats();
    }} catch(e) {{}}
}}, 5000);
</script>
</body>
</html>"#,
        total = stats.total_transactions,
        tips = stats.tip_count,
        tps = format!("{:.2}", stats.current_tps),
        epoch = stats.epoch,
        peers = stats.connected_peers,
        tx_rows = if recent_txs.transactions.is_empty() {
            r#"<tr><td colspan="6" style="text-align:center;color:#8b949e;padding:1rem;">No transactions yet</td></tr>"#.to_string()
        } else {
            recent_txs.transactions.iter().map(|tx| {
        let hash = hex::encode(&tx.tx_id);
        let sender = hex::encode(&tx.sender);
        let receiver = hex::encode(&tx.receiver);
        let amount = tx.amount / 10_000_000_000;
        format!(r#"<tr><td class="hash">{:.16}...</td><td class="addr">{:.16}...</td><td class="addr">{:.16}...</td><td>{}</td><td>{}</td><td><span class="status confirmed">Confirmed</span></td></tr>"#,
            hash, sender, receiver, amount, tx.fee)
    }).collect::<Vec<_>>().join("\n")
        },
        stats_json = stats_json,
        txs_json = txs_json,
        dag_count = stats.total_transactions.min(50),
    ))
}

/// Prometheus metrics endpoint
async fn handle_metrics(State(state): State<Arc<AetherRpcImpl>>) -> String {
    let uptime = state.start_time.elapsed().as_secs();
    let dag = state.dag.read().await;
    let tx_count = dag.transaction_count();
    let tip_count = dag.tip_count();
    drop(dag);
    let peer_count = state.p2p_network.peer_count().await;
    let mempool = state.mempool.read().await;
    let mempool_size = mempool.size();
    drop(mempool);

    format!(
        "# HELP aether_transactions_total Total transactions in DAG\n\
         # TYPE aether_transactions_total counter\n\
         aether_transactions_total {tx_count}\n\
         \n\
         # HELP aether_tips_current Current number of DAG tips\n\
         # TYPE aether_tips_current gauge\n\
         aether_tips_current {tip_count}\n\
         \n\
         # HELP aether_peers_connected Number of connected P2P peers\n\
         # TYPE aether_peers_connected gauge\n\
         aether_peers_connected {peer_count}\n\
         \n\
         # HELP aether_mempool_size Current mempool transaction count\n\
         # TYPE aether_mempool_size gauge\n\
         aether_mempool_size {mempool_size}\n\
         \n\
         # HELP aether_uptime_seconds Node uptime in seconds\n\
         # TYPE aether_uptime_seconds counter\n\
         aether_uptime_seconds {uptime}\n\
         \n\
         # HELP aether_node_info Static node metadata\n\
         # TYPE aether_node_info gauge\n\
         aether_node_info{{node_type=\"full\",version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Handle fallback - redirect to explorer
async fn handle_fallback() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="0;url=/explorer"></head>
<body>Redirecting to explorer...</body>
</html>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::P2PConfig;
    use crate::parent_selection::DAG;
    use crate::transaction::Transaction;
    use crate::P2PNetwork;

    fn test_rpc_impl(dir: &std::path::Path) -> AetherRpcImpl {
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let storage = Arc::new(RwLock::new(
            crate::storage::Storage::open(dir.join("sled")).unwrap(),
        ));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
        let (tx_channel, _rx) = tokio::sync::mpsc::unbounded_channel::<Transaction>();
        let p2p = Arc::new(P2PNetwork::new(
            P2PConfig {
                listen_addr: "0.0.0.0:0".parse().unwrap(),
                bootnodes: vec![],
                dns_seeds: vec![],
            },
            tx_channel,
            Arc::new(|| Vec::new()),
            Arc::new(|_| None),
            Arc::new(|| Vec::new()),
        ));
        AetherRpcImpl::new(
            dag,
            ledger,
            storage,
            dir.join("ledger.json"),
            mempool,
            p2p,
            Arc::new(RwLock::new(true)),
            Arc::new(RwLock::new(HashMap::new())),
        )
    }

    /// V-20: aether_getTips must return canonical hex strings, never raw
    /// byte arrays. The JSON shape must be exactly what the CLI and the GUI
    /// parse (`tip.as_str()` + hex decode), so tips can be used as parents
    /// of a new transaction without lossy conversion.
    #[tokio::test]
    async fn test_get_tips_returns_hex_strings() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        // Empty DAG: the genesis fallback is still a canonical hex string.
        let resp = rpc.get_tips().await.unwrap();
        assert_eq!(resp.count, 1);
        assert_eq!(resp.tips.len(), 1);
        assert_eq!(resp.tips[0], "00".repeat(32));

        // JSON serialization: strings, never numeric arrays (the V-20 bug).
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["tips"][0].is_string());

        // A real transaction: the tip is its id in canonical hex form.
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        rpc.dag
            .write()
            .await
            .add_transaction_validated(tx.clone())
            .unwrap();

        let resp2 = rpc.get_tips().await.unwrap();
        assert_eq!(resp2.tips.len(), 1);
        assert_eq!(resp2.tips[0], crate::transaction::encode_id(&tx.id));

        // Round-trip: hex tip -> bytes -> used as parent of a new tx.
        let tip_bytes = crate::transaction::decode_id(&resp2.tips[0]).unwrap();
        assert_eq!(tip_bytes, tx.id);
        let child = Transaction::new(
            [tip_bytes, [0u8; 32]],
            [3u8; 32],
            [4u8; 32],
            10,
            1,
            2,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        rpc.dag
            .write()
            .await
            .add_transaction_validated(child.clone())
            .unwrap();
        assert_eq!(child.parents[0], tx.id);
    }

    /// V-20: a node compatibility check - two nodes holding the same DAG
    /// must return the exact same tips payload (byte-for-byte identical
    /// JSON after serialization).
    #[tokio::test]
    async fn test_get_tips_identical_across_nodes() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let rpc1 = test_rpc_impl(dir1.path());
        let rpc2 = test_rpc_impl(dir2.path());

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        rpc1.dag
            .write()
            .await
            .add_transaction_validated(tx.clone())
            .unwrap();
        rpc2.dag
            .write()
            .await
            .add_transaction_validated(tx)
            .unwrap();

        let resp1 = rpc1.get_tips().await.unwrap();
        let resp2 = rpc2.get_tips().await.unwrap();
        assert_eq!(
            serde_json::to_string(&resp1).unwrap(),
            serde_json::to_string(&resp2).unwrap()
        );
    }

    /// H1: a transaction with missing parents and NO valid PoW/signature must
    /// be rejected by process_transaction WITHOUT being parked as an orphan
    /// (neither in memory nor on disk). Before H1 this exact payload was
    /// persisted forever, letting anyone fill disk/memory and spam P2P.
    #[tokio::test]
    async fn test_orphan_without_pow_not_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        // Missing parents + NO PoW (nonce 0) + NO valid signature.
        let tx = Transaction::new(
            [[0xAAu8; 32], [0xBBu8; 32]],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        let result = rpc.process_transaction(tx, "RPC-test").await;
        assert!(result.is_err());
        assert!(
            !result.err().unwrap().to_string().contains("orphan"),
            "a garbage transaction must not be treated as an orphan"
        );

        // Nothing parked in memory...
        let orphans = rpc.orphans.read().await;
        assert_eq!(orphans.len(), 0, "no orphan may be parked without PoW");
        drop(orphans);

        // ...and nothing persisted to disk.
        let storage = rpc.storage.read().await;
        let disk = storage.get_all_orphans().unwrap();
        assert_eq!(disk.len(), 0, "no orphan may be persisted without PoW");
    }

    /// H1: a transaction with missing parents that PASSES the pure gate
    /// (valid PoW + signature) is parked as an orphan (memory + disk) and the
    /// friendly error is returned to the submitter.
    #[tokio::test]
    async fn test_valid_orphan_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        let tx = crate::tests::signed_mined_orphan_tx();

        let result = rpc.process_transaction(tx.clone(), "RPC-test").await;
        let err = result.expect_err("missing parents must not be accepted");
        assert!(
            err.to_string().contains("missing parent"),
            "expected the friendly orphan error, got: {}",
            err
        );

        let orphans = rpc.orphans.read().await;
        assert!(
            orphans.contains_key(&tx.id),
            "valid orphan must be parked in memory"
        );
        drop(orphans);

        let storage = rpc.storage.read().await;
        let disk = storage.get_all_orphans().unwrap();
        assert!(
            disk.iter().any(|o| o.id == tx.id),
            "valid orphan must be persisted to disk"
        );
    }

    /// H1: the orphan store is capped — beyond MAX_ORPHANS entries, new
    /// orphans are rejected and NOT persisted anywhere.
    #[tokio::test]
    async fn test_orphan_cap_rejects_beyond_limit() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        // Pre-fill the in-memory orphan map up to the cap (direct insertion;
        // the PoW gate itself is covered by the tests above).
        {
            let mut orphans = rpc.orphans.write().await;
            for i in 0..MAX_ORPHANS {
                let mut key = [0u8; 32];
                key[..8].copy_from_slice(&(i as u64).to_le_bytes());
                orphans.insert(
                    key,
                    Transaction::new(
                        [[0u8; 32]; 2],
                        key,
                        [2u8; 32],
                        1,
                        1,
                        i as u64,
                        0,
                        i as u64,
                        vec![0u8; 64],
                        vec![0u8; 64],
                    ),
                );
            }
        }

        // A valid orphan (PoW + signature) submitted when the store is full.
        let tx = crate::tests::signed_mined_orphan_tx();

        let result = rpc.process_transaction(tx.clone(), "RPC-test").await;
        let err = result.expect_err("orphan must be rejected when the store is full");
        assert!(
            err.to_string().to_lowercase().contains("orphan limit"),
            "expected an orphan-limit rejection, got: {}",
            err
        );

        // Nothing new in memory...
        let orphans = rpc.orphans.read().await;
        assert_eq!(orphans.len(), MAX_ORPHANS, "orphan store must stay capped");
        assert!(
            !orphans.contains_key(&tx.id),
            "the overflowing orphan must not be parked"
        );
        drop(orphans);

        // ...and nothing persisted to disk.
        let storage = rpc.storage.read().await;
        let disk = storage.get_all_orphans().unwrap();
        assert!(
            !disk.iter().any(|o| o.id == tx.id),
            "the overflowing orphan must not be persisted"
        );
    }

    /// H3: the per-IP rate limiter isolates clients — one IP exhausting its
    /// budget must NOT affect another IP.
    #[tokio::test]
    async fn test_per_ip_rate_limit_isolation() {
        let limiter = RateLimiter::new(3, 10);
        let ip_a = format!("{}|aether_getDagStats", "192.0.2.1");
        let ip_b = format!("{}|aether_getDagStats", "192.0.2.2");

        // IP A exhausts its budget (3/10s).
        assert!(limiter.check(ip_a.clone()).await.is_ok());
        assert!(limiter.check(ip_a.clone()).await.is_ok());
        assert!(limiter.check(ip_a.clone()).await.is_ok());
        assert!(limiter.check(ip_a.clone()).await.is_err());

        // IP B is unaffected.
        assert!(limiter.check(ip_b.clone()).await.is_ok());
        assert!(limiter.check(ip_b.clone()).await.is_ok());
        assert!(limiter.check(ip_b.clone()).await.is_ok());
        assert!(limiter.check(ip_b).await.is_err());

        // A different method from IP A has its own bucket.
        let other_method = format!("{}|aether_getBalance", "192.0.2.1");
        assert!(limiter.check(other_method).await.is_ok());
    }

    /// P1+WEIGHT: the consensus path with the REAL weight implemented. The DAG
    /// maintains `tx.weight` = subtree size (itself + all descendants) on
    /// every mutation. The status ladder is now fully reachable:
    /// Unconfirmed (0 refs) → Confirmed (≥3 direct refs) → Stable (weight ≥ 5).
    /// This pins the honest ladder end-to-end on the real status API.
    #[tokio::test]
    async fn test_consensus_path_real_status_ladder() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        // A valid tx added through the DAG acceptance API.
        let sender = [0x31u8; 32];
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [0x32u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        let tx_id = tx.id;
        rpc.dag
            .write()
            .await
            .add_transaction_validated(tx.clone())
            .unwrap();

        // 1) Freshly accepted: InLocalDag + Unconfirmed (0 references),
        //    weight = 1 (own subtree).
        let status = rpc.determine_transaction_status(tx_id).await;
        assert_eq!(status.local_status, LocalStatus::InLocalDag);
        assert_eq!(status.consensus_status, ConsensusStatus::Unconfirmed);
        assert!(!status.practically_final);
        {
            let dag = rpc.dag.read().await;
            assert_eq!(dag.get_transaction(tx_id).unwrap().weight, 1.0);
        }

        // 2) Three children referencing it → weight 4 → Confirmed (3 refs,
        //    still < STABILITY_THRESHOLD 5).
        for i in 0..3u8 {
            let child = Transaction::new(
                [tx_id, [0u8; 32]],
                [0x41u8 + i; 32],
                [0x51u8; 32],
                10,
                10,
                1234567890,
                0,
                1,
                vec![0u8; 64],
                vec![1u8; 64],
            );
            rpc.dag
                .write()
                .await
                .add_transaction_validated(child)
                .unwrap();
        }
        let status = rpc.determine_transaction_status(tx_id).await;
        assert_eq!(status.consensus_status, ConsensusStatus::Confirmed);
        assert!(!status.practically_final);
        {
            let dag = rpc.dag.read().await;
            assert_eq!(dag.get_transaction(tx_id).unwrap().weight, 4.0);
        }

        // 3) A fourth child pushes the subtree to 5 → Stable, organically
        //    (the DAG wrote the weight, no code special-cased it).
        let fourth = Transaction::new(
            [tx_id, [0u8; 32]],
            [0x44u8; 32],
            [0x52u8; 32],
            10,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        let fourth_id = fourth.id;
        rpc.dag
            .write()
            .await
            .add_transaction_validated(fourth)
            .unwrap();
        let status = rpc.determine_transaction_status(tx_id).await;
        assert_eq!(status.consensus_status, ConsensusStatus::Stable);
        assert!(
            status.practically_final,
            "practically_final = Stable|Finalized — Stable is now reachable"
        );
        {
            let dag = rpc.dag.read().await;
            assert_eq!(dag.get_transaction(tx_id).unwrap().weight, 5.0);
        }

        // 4) A grandchild under one child propagates: tx → 6, child → 2.
        let grandchild = Transaction::new(
            [fourth_id, [0u8; 32]],
            [0x61u8; 32],
            [0x62u8; 32],
            10,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        rpc.dag
            .write()
            .await
            .add_transaction_validated(grandchild)
            .unwrap();
        let dag = rpc.dag.read().await;
        assert_eq!(dag.get_transaction(tx_id).unwrap().weight, 6.0);
        assert_eq!(dag.get_transaction(fourth_id).unwrap().weight, 2.0);
    }

    /// P3: orphan auto-resubmission cycle. An orphan parked by the RPC path is
    /// automatically re-processed by `process_orphans` once its parents arrive
    /// in the DAG (node.rs triggers it after every accepted P2P transaction
    /// and every 10s periodic cycle). The re-processing goes through the FULL
    /// gate again (PoW + signature + DAG + ledger) and success removes the
    /// orphan from memory AND from Sled.
    #[tokio::test]
    async fn test_orphan_auto_resubmission_cycle() {
        use crate::wallet::Wallet;
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();

        // Fund the sender through the real DAG -> ledger path (faucet -> sender).
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap();
        let funding = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            sender,
            5000,
            5,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        rpc.dag
            .write()
            .await
            .add_transaction_validated(funding.clone())
            .unwrap();
        let dag_read = rpc.dag.read().await;
        rpc.ledger.write().await.rebuild_from_dag(&dag_read);
        drop(dag_read);
        assert_eq!(rpc.ledger.read().await.get_balance(&sender), 5000);

        // Parent P: a transaction that will arrive LATER. Its id is
        // deterministic (hash of all fields), so the orphan can reference it
        // before it exists.
        let parent = Transaction::new(
            [[0u8; 32]; 2],
            [0x33u8; 32],
            [0x44u8; 32],
            1,
            1,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );

        // Orphan O references the not-yet-arrived parent P (mined + signed).
        let mut orphan = Transaction::new(
            [parent.id, [0u8; 32]],
            sender,
            [0x22u8; 32],
            100,
            1000,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            pk,
        );
        orphan.nonce = orphan.mine_nonce(20);
        orphan.signature = wallet.sign_transaction(&orphan).expect("sign");
        orphan.id = orphan.compute_hash();
        assert!(orphan.verify_pow(20));
        assert!(Wallet::verify_transaction(&orphan));

        // 1) Park: O is rejected as an orphan and persisted (memory + Sled).
        let result = rpc.process_transaction(orphan.clone(), "Test").await;
        assert!(result.is_err(), "missing parents must reject the tx");
        {
            let orphans = rpc.orphans.read().await;
            assert!(
                orphans.contains_key(&orphan.id),
                "orphan must be parked in memory"
            );
        }
        assert!(
            rpc.dag.read().await.get_transaction(orphan.id).is_none(),
            "orphan must NOT enter the DAG while its parents are missing"
        );
        {
            let storage = rpc.storage.read().await;
            assert!(
                storage.get_orphan(orphan.id).unwrap().is_some(),
                "orphan must be persisted to Sled"
            );
        }

        // 2) The parent finally arrives (P2P delivery / full sync).
        rpc.dag
            .write()
            .await
            .add_transaction_validated(parent.clone())
            .unwrap();

        // 3) Auto-resubmission: process_orphans re-processes O through the
        // FULL gate and clears it from memory and disk.
        rpc.process_orphans().await;

        assert!(
            rpc.dag.read().await.get_transaction(orphan.id).is_some(),
            "orphan must now be in the DAG"
        );
        {
            let orphans = rpc.orphans.read().await;
            assert!(
                !orphans.contains_key(&orphan.id),
                "resolved orphan must be removed from memory"
            );
        }
        {
            let storage = rpc.storage.read().await;
            assert!(
                storage.get_orphan(orphan.id).unwrap().is_none(),
                "resolved orphan must be removed from Sled"
            );
        }
        assert_eq!(
            rpc.ledger.read().await.get_balance(&sender),
            5000 - 100 - 1000,
            "the resolved orphan must be applied to the ledger"
        );

        // 4) The consensus status now reports the tx as in the local DAG.
        let status = rpc.determine_transaction_status(orphan.id).await;
        assert_eq!(
            status.local_status,
            LocalStatus::InMempool,
            "an accepted tx is in both mempool and DAG; the status precedence \
             is orphans -> mempool -> DAG, so InMempool is the honest result"
        );
    }

    /// H5: faucet cooldown eviction — stale entries are purged on every check,
    /// so the map cannot grow unbounded, and a cooled-down address is allowed.
    #[test]
    fn test_faucet_cooldown_evicts_stale() {
        use std::collections::HashMap;
        let mut cooldowns: HashMap<[u8; 32], std::time::Instant> = HashMap::new();
        let addr_a = [0xAAu8; 32];
        let addr_b = [0xBBu8; 32];

        // A stale entry (older than the window) plus a fresh one.
        let now = std::time::Instant::now();
        cooldowns.insert(addr_a, now - std::time::Duration::from_secs(61));
        cooldowns.insert(addr_b, now);
        assert_eq!(cooldowns.len(), 2);

        // Checking addr_a evicts it and reports no cooldown.
        let window = std::time::Duration::from_secs(60);
        let remaining = AetherRpcImpl::check_and_evict_cooldowns(&mut cooldowns, &addr_a, window);
        assert!(remaining.is_none(), "stale entry must be evicted");
        assert_eq!(
            cooldowns.len(),
            1,
            "stale entry must be removed from the map"
        );

        // The fresh entry still cools down.
        let remaining = AetherRpcImpl::check_and_evict_cooldowns(&mut cooldowns, &addr_b, window);
        assert!(remaining.is_some(), "fresh entry must still be in cooldown");
        assert!(remaining.unwrap() <= 60);
    }

    /// H3: get_dag_graph is bounded — a limit larger than the DAG returns the
    /// whole DAG, a small limit returns at most that many nodes, and edges
    /// never reference nodes outside the returned set.
    #[tokio::test]
    async fn test_get_dag_graph_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        // Insert 20 txs chained on a genesis root.
        let mut prev = [0u8; 32];
        for i in 0..20u8 {
            let tx = Transaction::new(
                [prev, [0u8; 32]],
                [0x11u8; 32],
                [0x22u8; 32],
                1,
                1,
                i as u64,
                0,
                i as u64,
                vec![0u8; 64],
                vec![0u8; 64],
            );
            prev = tx.id;
            rpc.dag.write().await.add_transaction_validated(tx).unwrap();
        }

        // No limit: whole DAG (20 nodes).
        let full = rpc.get_dag_graph(None).await.unwrap();
        assert_eq!(full.nodes.len(), 20);
        assert_eq!(full.total_transactions, 20);

        // Small limit: at most that many nodes, edges only among them.
        let small = rpc.get_dag_graph(Some(10)).await.unwrap();
        assert!(small.nodes.len() <= 10);
        assert_eq!(small.total_transactions, small.nodes.len());
        let included: std::collections::HashSet<[u8; 32]> =
            small.nodes.iter().map(|n| n.tx_id).collect();
        for edge in &small.edges {
            assert!(included.contains(&edge.from), "edge.from must be included");
            assert!(included.contains(&edge.to), "edge.to must be included");
        }
    }

    /// H3: get_transaction_history is bounded — a small limit caps the
    /// returned items while total_count stays exact.
    #[tokio::test]
    async fn test_get_transaction_history_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let rpc = test_rpc_impl(dir.path());

        // 25 transactions from the same sender.
        let sender = [0xABu8; 32];
        let mut prev = [0u8; 32];
        for i in 0..25u8 {
            let tx = Transaction::new(
                [prev, [0u8; 32]],
                sender,
                [0xCDu8; 32],
                1,
                1,
                i as u64,
                0,
                i as u64,
                vec![0u8; 64],
                vec![0u8; 64],
            );
            prev = tx.id;
            rpc.dag.write().await.add_transaction_validated(tx).unwrap();
        }

        let addr_hex = hex::encode(sender);
        let full = rpc
            .get_transaction_history(addr_hex.clone(), None)
            .await
            .unwrap();
        assert_eq!(full.total_count, 25);
        assert_eq!(full.transactions.len(), 25);

        let bounded = rpc
            .get_transaction_history(addr_hex.clone(), Some(5))
            .await
            .unwrap();
        assert_eq!(bounded.total_count, 25, "total must stay exact");
        assert_eq!(bounded.transactions.len(), 5, "response must be capped");
    }
}
