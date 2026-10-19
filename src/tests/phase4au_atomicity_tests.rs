//! PHASE 4CP-AU — persistence atomicity and recovery after storage errors.
//!
//! Deterministic fault injection (test-only seam on `Storage`, see
//! `StorageFault`) exercised through the REAL acceptance path:
//! `process_transaction` (accept funnel) -> mempool + mempool Sled tree ->
//! `drain_mempool()` -> `TransactionProcessor::process` -> Sled.
//!
//! Fault matrix covered here:
//!   au1 `PutTransaction` — window A: the tx row write fails at STEP 8.
//!   au2 `PutBalance`     — window B: the row write succeeds, the ledger
//!                          delta write fails.
//!   au3 `MarkApplied`    — window B variant: pre-fix `save_dirty` wrote
//!                          balances one-by-one, so this fault left a
//!                          PARTIAL durable delta (debits+credits+burn
//!                          written, applied marks and nonces missing)
//!                          while the processor reported failure.
//!   au4 `Flush`          — fsync failure at end of drain: log-only.
//!   au5 restart image    — after a failed window-B accept, the reopened
//!                          Sled must hold the PRE-APPLY world, with the
//!                          accepted tx still in the persisted mempool
//!                          tree (the boot reload re-enqueues it).
//!
//! Why window B used to diverge (the 4CP-AU defect, RED before the fix):
//! `process` rolls memory back and returns `PersistenceError`; the drainer
//! requeues (transient). But the tx row written before the failed save
//! stayed in Sled, and STEP-1c routing rule #3 reads "id persisted in
//! store ⟹ effects present" (the pre-tracking-upgrade backstop). On the
//! retry the tx is routed to `process_recovery_insert` — a DAG-only heal
//! with NO transfer — although the rolled-back ledger never applied the
//! effects: the live ledger then disagrees with `rebuild(DAG)` until the
//! next boot heals forward. The retry requires `account_nonce <=
//! ledger_nonce` (nonce-slot not ahead), which is exactly the genesis /
//! migration / catch-up arrival shape these tests pin.
//!
//! The fix (both parts required, see the report):
//!   * `Storage::apply_ledger_delta` — the whole STEP-8 ledger delta
//!     (balances + nonces + locks + applied marks) commits in ONE Sled
//!     transaction, so a failure leaves the durable ledger untouched;
//!   * every STEP-8 failure arm deletes the partially persisted tx row
//!     (best-effort) — restoring rule #3's premise by construction, so
//!     the drainer's retry replays the normal path and fully re-applies.
//! Without the atomic delta, deleting the row would be UNSAFE: a partial
//! durable balances prefix with the row gone and the mark gone would
//! double-apply the transfer when the tx re-arrives (au3 proves the
//! partial write existed pre-fix).

use crate::ledger::{Ledger, FEE_BURN_ADDRESS};
use crate::parent_selection::DAG;
use crate::rpc::{AetherRpcImpl, Mempool};
use crate::storage::{Storage, StorageFault};
use crate::transaction::Transaction;
use crate::validation::ValidationMode;
use crate::wallet::Wallet;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;

const AU_RECEIVER: [u8; 32] = [0x42u8; 32];

struct AuNode {
    rpc: AetherRpcImpl,
    storage: Arc<RwLock<Storage>>,
    ledger: Arc<RwLock<Ledger>>,
    dag: Arc<RwLock<DAG>>,
    mempool: Arc<RwLock<Mempool>>,
}

async fn boot_au_node(dir: &std::path::Path) -> AuNode {
    let storage = Arc::new(RwLock::new(Storage::open(dir.join("sled")).unwrap()));
    let ledger = Arc::new(RwLock::new(
        Ledger::new_with_storage(storage.clone())
            .await
            .expect("ledger with storage"),
    ));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
    let (tx_channel, _rx) = tokio::sync::mpsc::unbounded_channel::<Transaction>();
    let p2p = Arc::new(crate::P2PNetwork::new(
        crate::p2p::P2PConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: crate::transaction::DEFAULT_NETWORK_ID,
        },
        tx_channel,
        Arc::new(|| Vec::new()),
        Arc::new(|_| None),
        Arc::new(|| Vec::new()),
        Arc::new(crate::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    let rpc = AetherRpcImpl::new(
        dag.clone(),
        ledger.clone(),
        storage.clone(),
        dir.join("ledger.json"),
        mempool.clone(),
        p2p,
        Arc::new(RwLock::new(true)),
        Arc::new(RwLock::new(std::collections::HashMap::new())),
        Arc::new(crate::sync_stats::SyncContext::default()),
    );
    AuNode {
        rpc,
        storage,
        ledger,
        dag,
        mempool,
    }
}

fn au_wallet() -> Wallet {
    Wallet::from_secret_key("6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef")
        .expect("fixed test key")
}

/// Pre-migration timestamp -> 20-bit PoW (mined once per test, ~fast).
/// Historical mode matches the sync/reload/orphan ingress shape a retry
/// of an accepted-but-unpersisted tx takes in production.
fn build_pre_migration_tx(
    wallet: &Wallet,
    receiver: [u8; 32],
    amount: u64,
    fee: u64,
    account_nonce: u64,
) -> Transaction {
    let ts = Transaction::DIFFICULTY_MIGRATION_TS - 3_600_000;
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        wallet.address(),
        receiver,
        amount,
        fee,
        ts,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_pow(20));
    tx
}

/// Fund the sender AND persist the baseline, so any later durable balance
/// difference is evidence about the fault window only.
async fn fund_and_persist(node: &AuNode, sender: &[u8; 32], amount: u64) {
    {
        let mut ledger = node.ledger.write().await;
        ledger.set_balance(sender, amount);
        ledger.save_dirty().await.expect("baseline persist");
    }
    assert_eq!(
        node.storage.read().await.get_balance(*sender).unwrap(),
        amount,
        "baseline balance must be durable before the fault window"
    );
}

/// Full post-success fingerprint (memory + durable + queue), shared by the
/// retry assertions of au1/au2/au3/au4.
async fn assert_applied_world(node: &AuNode, tx: &Transaction, sender: &[u8; 32]) {
    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(sender), 9_890, "sender debited once");
        assert_eq!(ledger.get_balance(&AU_RECEIVER), 100, "receiver credited");
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), 10, "fee burned once");
        assert!(ledger.is_applied(&tx.id));
    }
    assert!(node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 0, "queue drained");
    {
        let storage = node.storage.read().await;
        assert!(storage.transaction_exists(tx.id).unwrap());
        assert_eq!(storage.get_balance(*sender).unwrap(), 9_890);
        assert_eq!(storage.get_balance(AU_RECEIVER).unwrap(), 100);
        assert_eq!(storage.get_balance(FEE_BURN_ADDRESS).unwrap(), 10);
        assert!(storage.is_applied(tx.id).unwrap(), "durable applied mark");
    }
    let stats = node.rpc.mempool_stats().await;
    assert_eq!(stats.included, 1, "exactly one FINAL inclusion");
    assert_eq!(stats.rejected, 0);
}

/// au1 — window A: `put_transaction` fails. The rollback must report the
/// failure (requeue), leave nothing durable, and the retry must re-apply
/// exactly once through the normal path.
#[tokio::test]
async fn au1_window_a_put_transaction_failure_recovered_by_retry() {
    let dir = tempdir().unwrap();
    let node = boot_au_node(dir.path()).await;
    let wallet = au_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, AU_RECEIVER, 100, 10, 0);
    node.rpc
        .process_transaction(tx.clone(), "AU-Test", ValidationMode::Historical)
        .await
        .expect("accept");
    assert_eq!(node.mempool.read().await.size(), 1);

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutTransaction);
    node.rpc.drain_mempool().await;

    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(&sender), 10_000, "memory rolled back");
        assert_eq!(ledger.get_balance(&AU_RECEIVER), 0);
        assert!(!ledger.is_applied(&tx.id));
    }
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 1, "requeued (transient)");
    {
        let storage = node.storage.read().await;
        assert!(!storage.transaction_exists(tx.id).unwrap(), "row absent");
        assert_eq!(storage.get_balance(sender).unwrap(), 10_000);
        assert_eq!(storage.get_balance(AU_RECEIVER).unwrap_or(0), 0);
        assert!(!storage.is_applied(tx.id).unwrap());
    }

    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;

    // Extra cycle: the queue is empty, nothing double-applies.
    node.rpc.drain_mempool().await;
    assert_eq!(node.ledger.read().await.get_balance(&sender), 9_890);
}

/// au2 — window B: the tx row persists, the ledger delta fails. Core RED
/// test: pre-fix the row survives the rollback and the retry is routed to
/// the DAG-only recovery insert (no transfer ever applied live).
#[tokio::test]
async fn au2_window_b_save_failure_compensated_and_reapplied() {
    let dir = tempdir().unwrap();
    let node = boot_au_node(dir.path()).await;
    let wallet = au_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, AU_RECEIVER, 100, 10, 0);
    node.rpc
        .process_transaction(tx.clone(), "AU-Test", ValidationMode::Historical)
        .await
        .expect("accept");

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutBalance);
    node.rpc.drain_mempool().await;

    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(&sender), 10_000, "memory rolled back");
        assert!(!ledger.is_applied(&tx.id));
    }
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 1, "requeued (transient)");
    {
        let storage = node.storage.read().await;
        assert!(
            !storage.transaction_exists(tx.id).unwrap(),
            "rolled-back accept must not leave a durable tx row (STEP-1c rule #3 evidence)"
        );
        assert_eq!(
            storage.get_balance(sender).unwrap(),
            10_000,
            "no delta persisted"
        );
        assert_eq!(storage.get_balance(AU_RECEIVER).unwrap_or(0), 0);
        assert!(!storage.is_applied(tx.id).unwrap());
    }

    // Retry: row absent => effects absent => NORMAL path re-applies fully.
    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;

    // Extra cycle: no double apply.
    node.rpc.drain_mempool().await;
    assert_eq!(node.ledger.read().await.get_balance(&sender), 9_890);
    assert_eq!(node.ledger.read().await.get_balance(&AU_RECEIVER), 100);
    assert_eq!(node.mempool.read().await.size(), 0);
}

/// au3 — atomicity of the ledger delta. The fault fires at the APPLIED
/// MARK stage (last write of `save_dirty`): pre-fix, every balance write
/// had already landed durably before the failure (partial delta).
#[tokio::test]
async fn au3_ledger_delta_commits_atomically_or_not_at_all() {
    let dir = tempdir().unwrap();
    let node = boot_au_node(dir.path()).await;
    let wallet = au_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, AU_RECEIVER, 100, 10, 0);
    node.rpc
        .process_transaction(tx.clone(), "AU-Test", ValidationMode::Historical)
        .await
        .expect("accept");

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::MarkApplied);
    node.rpc.drain_mempool().await;

    // RED pre-fix: sender debited / receiver credited / fee burned were
    // durably written while the accept declared failure and memory rolled
    // back — a durable prefix referencing a transaction the failure path
    // is about to remove.
    {
        let storage = node.storage.read().await;
        assert_eq!(
            storage.get_balance(sender).unwrap(),
            10_000,
            "no partial debit (delta must be all-or-nothing)"
        );
        assert_eq!(
            storage.get_balance(AU_RECEIVER).unwrap_or(0),
            0,
            "no partial credit"
        );
        assert_eq!(
            storage.get_balance(FEE_BURN_ADDRESS).unwrap_or(0),
            0,
            "no partial burn"
        );
        assert!(!storage.transaction_exists(tx.id).unwrap());
        assert!(!storage.is_applied(tx.id).unwrap());
    }
    assert_eq!(node.mempool.read().await.size(), 1);

    // Retry succeeds end-to-end (nothing partial to corrupt the re-apply).
    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;
}

/// au4 — flush failure at the end of the drain batch is log-only by
/// design (INC-01 keeps the flush, durability is covered by Sled
/// auto-flush + boot rebuild): it must not roll back or corrupt anything.
#[tokio::test]
async fn au4_flush_failure_is_log_only_and_state_stays_consistent() {
    let dir = tempdir().unwrap();
    let node = boot_au_node(dir.path()).await;
    let wallet = au_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, AU_RECEIVER, 100, 10, 0);
    node.rpc
        .process_transaction(tx.clone(), "AU-Test", ValidationMode::Historical)
        .await
        .expect("accept");

    node.storage.write().await.arm_fault(StorageFault::Flush);
    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;

    // Empty-cycle drain: no-op, no double apply.
    node.rpc.drain_mempool().await;
    assert_eq!(node.ledger.read().await.get_balance(&sender), 9_890);
    assert_eq!(node.mempool.read().await.size(), 0);
}

/// au5 — restart image after a failed window-B accept: the reopened Sled
/// holds the PRE-APPLY world (no row, no delta, no mark) and the accepted
/// tx survives in the persisted mempool tree, which is exactly what the
/// boot reload (node.rs) re-enqueues for a clean replay.
#[tokio::test]
async fn au5_failed_accept_leaves_pre_apply_crash_image_and_mempool_recovery_source() {
    let dir = tempdir().unwrap();
    let node = boot_au_node(dir.path()).await;
    let wallet = au_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, AU_RECEIVER, 100, 10, 0);
    node.rpc
        .process_transaction(tx.clone(), "AU-Test", ValidationMode::Historical)
        .await
        .expect("accept");

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutBalance);
    node.rpc.drain_mempool().await;

    // Crash image: reopen the same database fresh (node temoin).
    drop(node);
    let storage = Storage::open(dir.path().join("sled")).unwrap();
    assert!(
        !storage.transaction_exists(tx.id).unwrap(),
        "pre-apply image: no rolled-back tx row"
    );
    assert_eq!(storage.get_balance(sender).unwrap(), 10_000);
    assert_eq!(storage.get_balance(AU_RECEIVER).unwrap_or(0), 0);
    assert_eq!(storage.get_balance(FEE_BURN_ADDRESS).unwrap_or(0), 0);
    assert!(!storage.is_applied(tx.id).unwrap());
    let mempool_txs = storage.load_mempool_txs().unwrap();
    assert!(
        mempool_txs.iter().any(|t| t.id == tx.id),
        "accepted tx survives in the persisted mempool tree (boot re-enqueues it)"
    );
}
