//! # RPC Module
//!
//! Implements JSON-RPC server for external communication using jsonrpsee with Axum integration.

use crate::consensus::VQVConsensus;
use crate::consensus::Validator;
use crate::genesis::FAUCET_SECRET_KEY;
use crate::ledger::Ledger;
use crate::parent_selection::DAG;
use crate::transaction::{Address, Transaction, TransactionId};
use crate::transaction_processor::TransactionProcessor;
use crate::SyncEvent;
use axum::{
    extract::State,
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
use tokio::sync::{mpsc, RwLock, Semaphore};
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
    pub mining_rewards: u64,
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

/// Hashrate response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashrateResponse {
    pub hashrate: String,
    pub difficulty: u64,
}

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

/// Node status report for quorum-based reconciliation
#[derive(Debug, Clone, Copy)]
pub struct NodeStatusReport {
    pub weight: f64,
    pub local_status: LocalStatus,
    pub consensus_status: ConsensusStatus,
}

/// Quorum-based global status resolver
/// Economic policy: safety via quorum, liveness via majority fallback
pub struct GlobalStatusResolver {
    /// Minimum weight required for quorum (default 2/3)
    quorum_threshold: f64,
    /// Minimum weight required for majority fallback (default 1/2)
    majority_threshold: f64,
}

impl GlobalStatusResolver {
    /// Create new resolver with default thresholds
    pub fn new() -> Self {
        Self {
            quorum_threshold: 0.67,   // 2/3 for safety
            majority_threshold: 0.50, // 1/2 for liveness
        }
    }

    /// Create resolver with custom thresholds
    pub fn with_thresholds(quorum: f64, majority: f64) -> Self {
        Self {
            quorum_threshold: quorum,
            majority_threshold: majority,
        }
    }

    /// Reconcile multiple node statuses into single global status
    /// Economic policy: quorum-based weighted convergence
    pub fn reconcile_quorum(&self, reports: &[NodeStatusReport]) -> GlobalStatus {
        if reports.is_empty() {
            return GlobalStatus::Unknown;
        }

        let total_weight: f64 = reports.iter().map(|r| r.weight).sum();
        if total_weight == 0.0 {
            return GlobalStatus::Unknown;
        }

        // Calculate weight for each status level (ascending)
        let mut weight_unknown = 0.0;
        let mut weight_pending = 0.0;
        let mut weight_unconfirmed = 0.0;
        let mut weight_confirmed = 0.0;
        let mut weight_stable = 0.0;
        let mut weight_finalized = 0.0;

        for report in reports {
            let global = GlobalStatusResolver::reconcile_single(
                report.local_status,
                report.consensus_status,
            );
            match global {
                GlobalStatus::Unknown => weight_unknown += report.weight,
                GlobalStatus::Pending => weight_pending += report.weight,
                GlobalStatus::Unconfirmed => weight_unconfirmed += report.weight,
                GlobalStatus::Confirmed => weight_confirmed += report.weight,
                GlobalStatus::Stable => weight_stable += report.weight,
                GlobalStatus::Finalized => weight_finalized += report.weight,
            }
        }

        // Normalize weights
        let w_unknown = weight_unknown / total_weight;
        let w_pending = weight_pending / total_weight;
        let w_unconfirmed = weight_unconfirmed / total_weight;
        let w_confirmed = weight_confirmed / total_weight;
        let w_stable = weight_stable / total_weight;
        let w_finalized = weight_finalized / total_weight;

        // Check for quorum at each level (highest first)
        // Finalized requires explicit VQV votes - not just weight
        if w_finalized >= self.quorum_threshold {
            GlobalStatus::Finalized
        } else if w_stable >= self.quorum_threshold {
            GlobalStatus::Stable
        } else if w_confirmed >= self.quorum_threshold {
            GlobalStatus::Confirmed
        } else if w_unconfirmed >= self.quorum_threshold {
            GlobalStatus::Unconfirmed
        } else if w_pending >= self.quorum_threshold {
            GlobalStatus::Pending
        } else if w_unknown >= self.quorum_threshold {
            GlobalStatus::Unknown
        } else {
            // No quorum - use majority fallback for liveness
            if w_finalized >= self.majority_threshold {
                GlobalStatus::Finalized
            } else if w_stable >= self.majority_threshold {
                GlobalStatus::Stable
            } else if w_confirmed >= self.majority_threshold {
                GlobalStatus::Confirmed
            } else if w_unconfirmed >= self.majority_threshold {
                GlobalStatus::Unconfirmed
            } else if w_pending >= self.majority_threshold {
                GlobalStatus::Pending
            } else {
                // Default to unknown if no majority
                GlobalStatus::Unknown
            }
        }
    }

    /// Reconcile single node's local and consensus status
    /// Economic policy: conservative convergence for single node
    pub fn reconcile_single(local: LocalStatus, consensus: ConsensusStatus) -> GlobalStatus {
        match local {
            LocalStatus::Unknown => GlobalStatus::Unknown,
            LocalStatus::Orphan => GlobalStatus::Pending,
            LocalStatus::InMempool => GlobalStatus::Pending,
            LocalStatus::InLocalDag => match consensus {
                ConsensusStatus::Unconfirmed => GlobalStatus::Unconfirmed,
                ConsensusStatus::Confirmed => GlobalStatus::Confirmed,
                ConsensusStatus::Stable => GlobalStatus::Stable,
                ConsensusStatus::Finalized => GlobalStatus::Finalized,
            },
        }
    }
}

impl Default for GlobalStatusResolver {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// For multi-node reconciliation, use GlobalStatusResolver::reconcile_quorum
    pub fn reconcile(local: LocalStatus, consensus: ConsensusStatus) -> Self {
        GlobalStatusResolver::reconcile_single(local, consensus)
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

/// Staking response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingResponse {
    pub address: Address,
    pub staked_amount: u64,
    pub rewards_earned: u64,
    pub success: bool,
}

/// Staking info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingInfoResponse {
    pub staked_amount: u64,
    pub rewards_earned: u64,
    pub has_staked: bool,
}

/// Account nonce response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountNonceResponse {
    pub address: Address,
    pub current_nonce: u64,
    pub next_nonce: u64,
}

/// Transaction finality states (practical finality semantics)
/// Economic policy: transactions progress through these states as they gain consensus confidence
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionFinality {
    /// Accepted locally: in mempool and DAG, but not yet confirmed by network
    /// Economic impact: ledger committed, fees burned, but may be reorganized
    Accepted,
    /// Visible in DAG: confirmed by network, but not yet final
    /// Economic impact: stable, but theoretical reorganization possible
    Confirmed,
    /// Economically stable: sufficient tips/confirmations for practical finality
    /// Economic impact: reorganization extremely unlikely, can be considered final for most use cases
    EconomicallyStable,
    /// Finalized: confirmed by consensus mechanism (VQV votes)
    /// Economic impact: irreversible, guaranteed by protocol
    Finalized,
}

impl TransactionFinality {
    /// Check if transaction is considered "final" for practical purposes
    /// Economic policy: EconomicallyStable and Finalized are both practically final
    pub fn is_practically_final(&self) -> bool {
        matches!(self, Self::EconomicallyStable | Self::Finalized)
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipsResponse {
    pub tips: Vec<TransactionId>,
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
    consensus: Arc<RwLock<VQVConsensus>>,
    dag: Arc<RwLock<DAG>>,
    ledger: Arc<RwLock<Ledger>>,
    storage: Arc<RwLock<crate::storage::Storage>>,
    ledger_path: std::path::PathBuf,
    mempool: Arc<RwLock<Mempool>>,
    p2p_network: Arc<crate::p2p::P2PNetwork>,
    save_tx: mpsc::Sender<SyncEvent>,
    mining_enabled: Arc<RwLock<bool>>,
    miner_address: Option<Address>,
    orphans: Arc<RwLock<std::collections::HashMap<[u8; 32], Transaction>>>,
    faucet_cooldowns: Arc<RwLock<std::collections::HashMap<[u8; 32], std::time::Instant>>>,
    fee_oracle: Arc<RwLock<FeeOracle>>,
    faucet_key: SigningKey,
    rate_limiter: RateLimiter,
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
        consensus: Arc<RwLock<VQVConsensus>>,
        dag: Arc<RwLock<DAG>>,
        ledger: Arc<RwLock<Ledger>>,
        storage: Arc<RwLock<crate::storage::Storage>>,
        ledger_path: std::path::PathBuf,
        mempool: Arc<RwLock<Mempool>>,
        p2p_network: Arc<crate::p2p::P2PNetwork>,
        save_tx: mpsc::Sender<SyncEvent>,
        mining_enabled: Arc<RwLock<bool>>,
        miner_address: Option<Address>,
        orphans: Arc<RwLock<std::collections::HashMap<[u8; 32], Transaction>>>,
    ) -> Self {
        let faucet_seed = hex::decode(FAUCET_SECRET_KEY).expect("Invalid faucet secret key hex");
        let mut faucet_key_bytes = [0u8; 32];
        faucet_key_bytes.copy_from_slice(&faucet_seed);
        let faucet_key = SigningKey::from_bytes(&faucet_key_bytes);
        Self {
            consensus,
            dag,
            ledger,
            storage,
            ledger_path,
            mempool,
            p2p_network,
            save_tx,
            mining_enabled,
            miner_address,
            orphans,
            faucet_cooldowns: Arc::new(RwLock::new(std::collections::HashMap::new())),
            fee_oracle: Arc::new(RwLock::new(FeeOracle::new())),
            faucet_key,
            rate_limiter: RateLimiter::new(200, 10), // 200 requests per 10s window
            start_time: std::time::Instant::now(),
        }
    }

    /// Get balance for an address
    pub async fn get_balance(&self, address: Address) -> Result<BalanceResponse, RpcError> {
        let ledger = self.ledger.read().await;

        let balance = ledger.get_balance(&address);
        Ok(BalanceResponse {
            address,
            balance,
            mining_rewards: 0,
        })
    }

    /// Send a transaction
    pub async fn send_transaction(
        &self,
        params: serde_json::Value,
    ) -> Result<TransactionResponse, RpcError> {
        tracing::error!("RAW RPC PARAMS RECEIVED: {:?}", params);

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

        // Log raw hex payload
        tracing::info!("Raw hex: {}", tx_data);
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

        // Validation logs
        tracing::info!(
            "🔍 Processing transaction [{}] - Sender: {}",
            source,
            hex::encode(tx.sender)
        );
        tracing::info!(
            "🔍 Processing transaction [{}] - Receiver: {}",
            source,
            hex::encode(tx.receiver)
        );
        tracing::info!(
            "🔍 Processing transaction [{}] - Amount: {}",
            source,
            tx.amount
        );
        tracing::info!("🔍 Processing transaction [{}] - Fee: {}", source, tx.fee);
        tracing::info!(
            "🔍 Processing transaction [{}] - Parents: [{}, {}]",
            source,
            hex::encode(tx.parents[0]),
            hex::encode(tx.parents[1])
        );
        tracing::info!(
            "🔍 Processing transaction [{}] - PoW Nonce: {}",
            source,
            tx.nonce
        );
        tracing::info!(
            "🔍 Processing transaction [{}] - Account Nonce: {}",
            source,
            tx.account_nonce
        );

        // STEP 1: CHECK FOR MISSING PARENTS (orphan handling - before full validation)
        // This is a special case: valid transactions with missing parents are stored as orphans
        let dag = match self.dag.try_read() {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("❌ DAG lock error: {}", e);
                return Err(RpcError("DAG lock error".to_string()));
            }
        };

        let mut missing_parents = Vec::new();
        for (i, parent) in tx.parents.iter().enumerate() {
            let is_genesis = *parent == [0u8; 32];
            if !is_genesis && !dag.transactions().contains_key(parent) {
                tracing::warn!(
                    "⚠️ Parent {} missing: {} - requesting via P2P",
                    i,
                    hex::encode(parent)
                );
                missing_parents.push((i, parent.clone()));

                // Request missing parent via P2P
                let parent_hash = parent.to_vec();
                let p2p = self.p2p_network.clone();
                tokio::spawn(async move {
                    tracing::info!(
                        "📡 P2P - Requesting missing parent: {}",
                        hex::encode(&parent_hash)
                    );
                    p2p.request_transaction(parent_hash).await;
                });
            }
        }

        // VALID BUT NOT ACCEPTABLE: If parents are missing, store as orphan
        if !missing_parents.is_empty() {
            drop(dag);

            // Persist orphan to disk (survives restart)
            // 🔧 FIX: use the main storage (data_dir/sled_db), NOT a new sled at
            // ledger_path.parent() which silently opened a different database at
            // the data-dir root, leaving orphans invisible to the node's DAG.
            if let Ok(storage_guard) = self.storage.try_read() {
                if let Err(e) = storage_guard.put_orphan(tx.id, &tx) {
                    tracing::error!("❌ Failed to persist orphan to storage: {}", e);
                }
            }

            // Also keep in memory for fast access
            {
                let mut orphans = self.orphans.write().await;
                orphans.insert(tx.id, tx.clone());
                tracing::info!(
                    "📦 Orphan stored: {} (missing {} parent(s)) - persisted to disk",
                    hex::encode(tx.id),
                    missing_parents.len()
                );
            }

            return Err(RpcError(format!(
                "Transaction has {} missing parent(s). Stored as orphan and requesting via P2P. Please retry in a few seconds.",
                missing_parents.len()
            )));
        }
        drop(dag);

        // STEP 2: USE TRANSACTION PROCESSOR (ZERO TRUST SINGLE ENTRY POINT)
        // 🔒 All validation and state mutations go through TransactionProcessor
        // 🔒 CRITICAL: Block reward uses consensus state (single source of truth for height)
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

        let miner_addr = self.miner_address.as_ref();

        // Get consensus state (single source of truth for block height)
        let mut consensus = self.consensus.write().await;
        let consensus_state = consensus.state_mut();
        // Use transaction ID as block ID (in production, this should be the actual block ID from consensus)
        let block_id = Some(tx.id);

        match processor
            .process(
                tx.clone(),
                &self.dag,
                &self.ledger,
                &self.mempool,
                min_fee,
                miner_addr,
                consensus_state,
                block_id,
            )
            .await
        {
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
            Err(e) => {
                tracing::error!("❌ Transaction processing failed: {}", e);
                Err(RpcError(e.to_string()))
            }
        }
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
        let consensus = self.consensus.read().await;

        let total_transactions = dag.transaction_count() as u64;
        let tip_count = dag.tip_count();
        let epoch = consensus.current_epoch();
        let connected_peers = self.p2p_network.peer_count().await as u32;

        let height = consensus.state().get_height();
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

    /// Get network hashrate (simplified placeholder for now)
    pub async fn get_network_hashrate(&self) -> Result<HashrateResponse, RpcError> {
        // For now, return a placeholder based on base difficulty
        // In production, this would calculate from recent transaction nonces
        let estimated_hashrate = 100 * 1000; // difficulty * 1000

        Ok(HashrateResponse {
            hashrate: format!("{} H/s", estimated_hashrate),
            difficulty: 100, // Base difficulty
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
    pub async fn get_transaction_history(
        &self,
        address: String,
    ) -> Result<TransactionHistoryResponse, RpcError> {
        let dag = self.dag.read().await;

        // Decode address from hex
        let address_bytes =
            hex::decode(&address).map_err(|_| RpcError("Invalid address hex".to_string()))?;
        let address_array: [u8; 32] = address_bytes
            .try_into()
            .map_err(|_| RpcError("Invalid address length".to_string()))?;

        // Filter transactions where address is sender or receiver
        let transactions: Vec<TransactionHistoryItem> = dag
            .transactions()
            .values()
            .filter(|tx| tx.sender == address_array || tx.receiver == address_array)
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

        let total_count = transactions.len();

        Ok(TransactionHistoryResponse {
            transactions,
            total_count,
        })
    }

    /// Stake tokens for an address
    pub async fn stake_tokens(
        &self,
        address: &Address,
        amount: u64,
    ) -> Result<StakingResponse, RpcError> {
        tracing::info!(
            "🔒 Stake request: address={}, amount={}",
            hex::encode(address),
            amount
        );

        // Phase 1: lock funds in the ledger (single source of truth for balances)
        {
            let mut ledger = self.ledger.write().await;
            if let Err(e) = ledger.subtract_balance(address, amount) {
                tracing::error!("❌ Stake failed: {}", e);
                return Ok(StakingResponse {
                    address: *address,
                    staked_amount: 0,
                    rewards_earned: 0,
                    success: false,
                });
            }
        }

        // Phase 2: track staking position in storage
        let storage = self.storage.read().await;
        match storage.stake_tokens(*address, amount) {
            Ok(_) => {
                let staked_amount = storage.get_staked_amount(*address).unwrap_or(0);
                let rewards = storage.calculate_staking_reward(*address).unwrap_or(0);
                // Bridge to VQV consensus — register as validator if min stake met
                let min_stake = {
                    let c = self.consensus.read().await;
                    c.min_stake()
                };
                let max_stake = {
                    let c = self.consensus.read().await;
                    c.max_stake()
                };
                if staked_amount >= min_stake && staked_amount <= max_stake {
                    let mut cons = self.consensus.write().await;
                    let validator = Validator::new(*address, staked_amount, address.to_vec());
                    if let Err(e) = cons.register_validator(validator) {
                        tracing::warn!("⚠️ Validator registration skipped: {}", e);
                    } else {
                        tracing::info!(
                            "✅ Address registered as VQV validator: {}",
                            hex::encode(address)
                        );
                    }
                }
                tracing::info!(
                    "✅ Stake successful: staked_amount={}, rewards={}",
                    staked_amount,
                    rewards
                );
                Ok(StakingResponse {
                    address: *address,
                    staked_amount,
                    rewards_earned: rewards,
                    success: true,
                })
            }
            Err(e) => {
                // Rollback the ledger lock (position tracking failed)
                let mut ledger = self.ledger.write().await;
                let _ = ledger.add_balance(address, amount);
                tracing::error!("❌ Stake failed: {}", e);
                Ok(StakingResponse {
                    address: *address,
                    staked_amount: 0,
                    rewards_earned: 0,
                    success: false,
                })
            }
        }
    }

    /// Unstake tokens for an address
    pub async fn unstake_tokens(&self, address: &Address) -> Result<StakingResponse, RpcError> {
        // Phase 1: close the staking position and compute total return
        let total_return = {
            let storage = self.storage.read().await;
            match storage.unstake_tokens(*address) {
                Ok(total_return) => total_return,
                Err(e) => {
                    tracing::error!("❌ Unstake failed: {}", e);
                    return Ok(StakingResponse {
                        address: *address,
                        staked_amount: 0,
                        rewards_earned: 0,
                        success: false,
                    });
                }
            }
        };

        // Phase 2: credit the ledger (single source of truth for balances)
        let mut ledger = self.ledger.write().await;
        if let Err(e) = ledger.add_balance(address, total_return) {
            tracing::error!("❌ Unstake credit failed: {}", e);
            return Ok(StakingResponse {
                address: *address,
                staked_amount: 0,
                rewards_earned: 0,
                success: false,
            });
        }
        drop(ledger);

        // Unregister from VQV consensus
        self.consensus.write().await.unregister_validator(*address);
        tracing::info!("✅ Validator unregistered: {}", hex::encode(address));
        tracing::info!("✅ Unstake successful: returned {}", total_return);
        Ok(StakingResponse {
            address: *address,
            staked_amount: 0,
            rewards_earned: total_return,
            success: true,
        })
    }

    /// Get staking info for an address
    pub async fn get_staking_info(
        &self,
        address: &Address,
    ) -> Result<StakingInfoResponse, RpcError> {
        let storage = self.storage.read().await;

        if storage.has_staked_tokens(*address) {
            let staked_amount = storage.get_staked_amount(*address).unwrap_or(0);
            let rewards = storage.calculate_staking_reward(*address).unwrap_or(0);
            Ok(StakingInfoResponse {
                staked_amount,
                rewards_earned: rewards,
                has_staked: true,
            })
        } else {
            Ok(StakingInfoResponse {
                staked_amount: 0,
                rewards_earned: 0,
                has_staked: false,
            })
        }
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
    pub async fn get_dag_graph(&self) -> Result<DagGraphResponse, RpcError> {
        let dag = self.dag.read().await;
        let transactions: Vec<&Transaction> = dag.transactions().values().collect();

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
                if !parent.is_empty() {
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

        // Helper function to calculate cumulative weight
        fn calculate_cumulative_weight(id: TransactionId, dag: &DAG) -> f64 {
            let mut visited = std::collections::HashSet::new();
            let mut queue = vec![id];
            let mut weight = 0u64;

            while let Some(current_id) = queue.pop() {
                if !visited.insert(current_id) {
                    continue;
                }

                weight += 1;

                // Add children to queue
                if let Some(children) = dag.children().get(&current_id) {
                    for child in children {
                        queue.push(*child);
                    }
                }
            }

            weight as f64
        }

        // Get last 100 transactions
        let transactions: Vec<TransactionSnapshot> = dag
            .transactions()
            .values()
            .take(100)
            .map(|tx| {
                let cumulative_weight = calculate_cumulative_weight(tx.id, &dag);
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

    /// Start mining
    pub async fn start_mining(&self) -> Result<String, RpcError> {
        let mut mining = self.mining_enabled.write().await;
        *mining = true;
        Ok("Mining started".to_string())
    }

    /// Stop mining
    pub async fn stop_mining(&self) -> Result<String, RpcError> {
        let mut mining = self.mining_enabled.write().await;
        *mining = false;
        Ok("Mining stopped".to_string())
    }

    /// Faucet - give test funds via a real DAG transaction
    pub async fn faucet(&self, address: Address) -> Result<FaucetResponse, RpcError> {
        // Rate limit: one request per 60s per address
        {
            let mut cooldowns = self.faucet_cooldowns.write().await;
            if let Some(last) = cooldowns.get(&address) {
                if last.elapsed() < std::time::Duration::from_secs(60) {
                    let remaining = 60 - last.elapsed().as_secs();
                    return Err(RpcError(format!(
                        "Rate limited. Try again in {}s",
                        remaining
                    )));
                }
            }
            cooldowns.insert(address, std::time::Instant::now());
        }

        let amount = 100_000_000_000u64; // 10 AETH in smallest unit
        let fee = 1u64;

        // Get faucet address and public key
        let verifying_key = self.faucet_key.verifying_key();
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
        let signature = self.faucet_key.sign(&signing_hash);
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
    consensus: Arc<RwLock<VQVConsensus>>,
    dag: Arc<RwLock<DAG>>,
    ledger: Arc<RwLock<Ledger>>,
    storage: Arc<RwLock<crate::storage::Storage>>,
    ledger_path: std::path::PathBuf,
    mempool: Arc<RwLock<Mempool>>,
    p2p_network: Arc<crate::p2p::P2PNetwork>,
    save_tx: mpsc::Sender<SyncEvent>,
    mining_enabled: Arc<RwLock<bool>>,
    miner_address: Option<Address>,
    orphans: Arc<RwLock<std::collections::HashMap<[u8; 32], Transaction>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let rpc_impl = Arc::new(AetherRpcImpl::new(
        consensus,
        dag,
        ledger,
        storage,
        ledger_path,
        mempool.clone(),
        p2p_network,
        save_tx,
        mining_enabled,
        miner_address,
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

    axum::serve(listener, app).await?;

    Ok(())
}

/// Handle JSON-RPC POST requests
async fn handle_rpc(
    State(rpc_impl): State<Arc<AetherRpcImpl>>,
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

    // Rate limiting per method
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

    let result =
        match method {
            "aether_getBalance" => {
                let addr = payload
                    .get("params")
                    .and_then(|p: &serde_json::Value| p.get(0))
                    .and_then(|a: &serde_json::Value| a.as_str());
                match addr {
                    Some(addr_str) => match hex::decode(addr_str) {
                        Ok(bytes) => match bytes.try_into() {
                            Ok(addr) => match rpc_impl.get_balance(addr).await {
                                Ok(response) => serde_json::to_value(response)
                                    .map_err(|e| RpcError(e.to_string())),
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
                    Ok(response) => {
                        serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                    }
                    Err(e) => Err(e),
                }
            }
            "aether_getDagStats" => match rpc_impl.get_dag_stats().await {
                Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
                Err(e) => Err(e),
            },
            "aether_getNetworkHashrate" => match rpc_impl.get_network_hashrate().await {
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
                                Ok(response) => serde_json::to_value(response)
                                    .map_err(|e| RpcError(e.to_string())),
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
                    Ok(response) => {
                        serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                    }
                    Err(e) => Err(e),
                }
            }
            "aether_getTransactionHistory" => {
                let address = payload
                    .get("params")
                    .and_then(|p: &serde_json::Value| p.get(0))
                    .and_then(|a: &serde_json::Value| a.as_str());
                match address {
                    Some(addr_str) => {
                        match rpc_impl.get_transaction_history(addr_str.to_string()).await {
                            Ok(response) => {
                                serde_json::to_value(response).map_err(|e| RpcError(e.to_string()))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    None => Err(RpcError("Missing address parameter".to_string())),
                }
            }
            "aether_getDagGraph" => match rpc_impl.get_dag_graph().await {
                Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
                Err(e) => Err(e),
            },
            "aether_stakeTokens" => {
                tracing::info!("🔒 Received aether_stakeTokens RPC call");
                let addr = payload
                    .get("params")
                    .and_then(|p: &serde_json::Value| p.get(0))
                    .and_then(|a: &serde_json::Value| a.as_str());
                let amount = payload
                    .get("params")
                    .and_then(|p: &serde_json::Value| p.get(1))
                    .and_then(|a: &serde_json::Value| a.as_u64());
                tracing::info!("🔒 Parsed params: addr={:?}, amount={:?}", addr, amount);
                match (addr, amount) {
                    (Some(addr_str), Some(amt)) => match hex::decode(addr_str) {
                        Ok(bytes) => match bytes.try_into() {
                            Ok(addr) => {
                                tracing::info!("🔒 Calling stake_tokens implementation");
                                match rpc_impl.stake_tokens(&addr, amt).await {
                                    Ok(response) => {
                                        tracing::info!("🔒 stake_tokens returned: {:?}", response);
                                        serde_json::to_value(response)
                                            .map_err(|e| RpcError(e.to_string()))
                                    }
                                    Err(e) => {
                                        tracing::error!("🔒 stake_tokens error: {:?}", e);
                                        Err(e)
                                    }
                                }
                            }
                            Err(_) => {
                                tracing::error!("🔒 Invalid address conversion");
                                Err(RpcError("Invalid address".to_string()))
                            }
                        },
                        Err(_) => {
                            tracing::error!("🔒 Invalid hex address");
                            Err(RpcError("Invalid hex address".to_string()))
                        }
                    },
                    _ => {
                        tracing::error!("🔒 Missing address or amount parameter");
                        Err(RpcError("Missing address or amount parameter".to_string()))
                    }
                }
            }
            "aether_unstakeTokens" => {
                let addr = payload
                    .get("params")
                    .and_then(|p: &serde_json::Value| p.get(0))
                    .and_then(|a: &serde_json::Value| a.as_str());
                match addr {
                    Some(addr_str) => match hex::decode(addr_str) {
                        Ok(bytes) => match bytes.try_into() {
                            Ok(addr) => match rpc_impl.unstake_tokens(&addr).await {
                                Ok(response) => serde_json::to_value(response)
                                    .map_err(|e| RpcError(e.to_string())),
                                Err(e) => Err(e),
                            },
                            Err(_) => Err(RpcError("Invalid address".to_string())),
                        },
                        Err(_) => Err(RpcError("Invalid hex address".to_string())),
                    },
                    None => Err(RpcError("Missing address parameter".to_string())),
                }
            }
            "aether_getStakingInfo" => {
                let addr = payload
                    .get("params")
                    .and_then(|p: &serde_json::Value| p.get(0))
                    .and_then(|a: &serde_json::Value| a.as_str());
                match addr {
                    Some(addr_str) => match hex::decode(addr_str) {
                        Ok(bytes) => match bytes.try_into() {
                            Ok(addr) => match rpc_impl.get_staking_info(&addr).await {
                                Ok(response) => serde_json::to_value(response)
                                    .map_err(|e| RpcError(e.to_string())),
                                Err(e) => Err(e),
                            },
                            Err(_) => Err(RpcError("Invalid address".to_string())),
                        },
                        Err(_) => Err(RpcError("Invalid hex address".to_string())),
                    },
                    None => Err(RpcError("Missing address parameter".to_string())),
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
                                Ok(response) => serde_json::to_value(response)
                                    .map_err(|e| RpcError(e.to_string())),
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
            "aether_startMining" => match rpc_impl.start_mining().await {
                Ok(response) => serde_json::to_value(response).map_err(|e| RpcError(e.to_string())),
                Err(e) => Err(e),
            },
            "aether_stopMining" => match rpc_impl.stop_mining().await {
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
                                Ok(response) => serde_json::to_value(response)
                                    .map_err(|e| RpcError(e.to_string())),
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
         aether_node_info{{node_type=\"miner\",version=\"1.0.0\"}} 1\n"
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
