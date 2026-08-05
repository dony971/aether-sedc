//! # AETHER SEDC - Self-Evolving DAG Consensus - Unified Implementation
//!
//! This crate implements the complete AETHER SEDC protocol including:
//! - Blockless DAG architecture (no sequential blocks)
//! - Heavy Subgraph Consensus (leaderless consensus)
//! - Adaptive probabilistic finality
//! - Dynamic reputation system
//! - Consensus-linked economics
//! - Zero-trust transaction processing
//! - Persistent orphan recovery
//! - Fork-safe reward distribution

pub mod config;
pub mod consensus;
pub mod economics;
pub mod explorer_api;
pub mod genesis;
pub mod json_storage;
pub mod ledger;
pub mod node;
pub mod p2p;
pub mod parent_selection;
pub mod pow;
pub mod reputation;
pub mod rpc;
pub mod security_audit;
pub mod storage;
pub mod transaction;
pub mod transaction_processor;
pub mod validation;
pub mod wallet;

#[cfg(test)]
mod tests;

pub use consensus::{ConsensusError, ConsensusState, VQVConsensus, Validator, Vote};
pub use economics::{
    EconomicsError, EmissionCurve, RewardCalculator, TokenAmount, TokenBalance, HARD_CAP,
};
pub use explorer_api::{DagEdge, DagGraph, DagNode, ExplorerApi};
pub use genesis::{
    genesis_hash, initialize_genesis, GenesisBlock, GenesisConfig, GENESIS_HASH, GENESIS_MESSAGE,
};
pub use ledger::Ledger;
pub use p2p::{P2PConfig, P2PMessage, P2PNetwork};
pub use parent_selection::{ParentSelectionAlgorithm, TipSet, DAG};
pub use pow::{DifficultyAdjuster, MicroPoW};
pub use reputation::{Reputation, ReputationConfig, ReputationStore};
pub use rpc::{
    start_rpc_server, AetherRpcImpl, BalanceResponse, DagEdge as RpcDagEdge, DagGraphResponse,
    DagNode as RpcDagNode, DagStatsResponse, Mempool, MiningStatusResponse, RpcError, TipsResponse,
    TransactionResponse,
};
pub use security_audit::{
    DoubleSpendAttempt, ParasiteChain, SecurityAudit, SecurityAuditor, SlashReason, ValidatorSlash,
};
pub use storage::{BatchOperation, Storage, StorageError, TreeName};
pub use transaction::{Address, Transaction, TransactionId};
pub use transaction_processor::{ProcessingError, TransactionProcessor};
pub use validation::{TransactionValidator, ValidationError};
pub use wallet::Wallet;

/// Events for the save worker MPSC channel
#[derive(Debug, Clone)]
pub enum SyncEvent {
    SaveRequested,
}
