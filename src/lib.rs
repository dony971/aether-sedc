//! # AETHER SEDC - Self-Evolving DAG Consensus - Unified Implementation
//!
//! This crate implements the complete AETHER SEDC protocol including:
//! - Blockless DAG architecture (no sequential blocks)
//! - Deterministic acceptance rules (the DAG is the consensus)
//! - Zero-trust transaction processing
//! - Deterministic double-spend conflict resolution
//! - Zero-emission monetary policy (fixed genesis supply, fees burned)

pub mod config;
pub mod genesis;
pub mod json_storage;
pub mod ledger;
pub mod node;
pub mod p2p;
pub mod parent_selection;
pub mod rpc;
pub mod storage;
pub mod transaction;
pub mod transaction_processor;
pub mod validation;
pub mod wallet;

#[cfg(test)]
mod tests;

pub use genesis::{
    genesis_hash, initialize_genesis, GenesisBlock, GenesisConfig, GENESIS_HASH, GENESIS_MESSAGE,
};
pub use ledger::Ledger;
pub use p2p::{P2PConfig, P2PMessage, P2PNetwork};
pub use parent_selection::{ParentSelectionAlgorithm, TipSet, DAG};
pub use rpc::{
    start_rpc_server, AetherRpcImpl, BalanceResponse, DagEdge as RpcDagEdge, DagGraphResponse,
    DagNode as RpcDagNode, DagStatsResponse, Mempool, MiningStatusResponse, RpcError, TipsResponse,
    TransactionResponse,
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
