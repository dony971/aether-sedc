use crate::ledger::{Ledger, FEE_BURN_ADDRESS};
use crate::parent_selection::{rebuild_dag_topological, DAG};
use crate::rpc::{AetherRpcImpl, Mempool};
use crate::storage::{Storage, StorageFault};
use crate::sync_stats::{PageState, SyncContext};
use crate::transaction::Transaction;
use crate::transaction_processor::{ProcessingError, TransactionProcessor};
use crate::validation::ValidationMode;
use crate::wallet::Wallet;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;

const BI_RECEIVER: [u8; 32] = [0x42u8; 32];

struct BiNode {
    rpc: AetherRpcImpl,
    storage: Arc<RwLock<Storage>>,
    ledger: Arc<RwLock<Ledger>>,
    dag: Arc<RwLock<DAG>>,
    mempool: Arc<RwLock<Mempool>>,
    sync_ctx: Arc<SyncContext>,
}

async fn boot_bi_node(dir: &std::path::Path) -> BiNode {
    let storage = Arc::new(RwLock::new(Storage::open(dir.join("sled")).unwrap()));
    let ledger = Arc::new(RwLock::new(
        Ledger::new_with_storage(storage.clone())
            .await
            .expect("ledger with storage"),
    ));

    let mut dag = DAG::new();
    {
        let storage_read = storage.read().await;
        let persisted = storage_read.get_all_transactions().expect("load txs");
        rebuild_dag_topological(&mut dag, persisted);
    }
    dag.rebuild_tips();

    let mut mempool = Mempool::new(1000, 10);
    {
        let storage_read = storage.read().await;
        if let Ok(persisted) = storage_read.load_mempool_txs() {
            for tx in persisted {
                if dag.transactions().contains_key(&tx.id) {
                    continue;
                }
                if mempool.size() < mempool.max_size() {
                    let _ = mempool.enqueue(tx, 0);
                }
            }
        }
    }

    let dag = Arc::new(RwLock::new(dag));
    let mempool = Arc::new(RwLock::new(mempool));
    let sync_ctx = Arc::new(SyncContext::default());
    let (tx_channel, _rx) =
        tokio::sync::mpsc::channel::<crate::p2p::IngressTx>(crate::p2p::TX_INGRESS_CAPACITY_MSGS);
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
        sync_ctx.clone(),
    );
    BiNode {
        rpc,
        storage,
        ledger,
        dag,
        mempool,
        sync_ctx,
    }
}

fn bi_wallet() -> Wallet {
    Wallet::from_secret_key("6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef")
        .expect("fixed test key")
}

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

async fn fund_and_persist(node: &BiNode, sender: &[u8; 32], amount: u64) {
    {
        let mut ledger = node.ledger.write().await;
        ledger.set_balance(sender, amount);
        ledger.save_dirty().await.expect("baseline persist");
    }
    node.storage.read().await.flush().expect("baseline flush");
    assert_eq!(
        node.storage.read().await.get_balance(*sender).unwrap(),
        amount
    );
}

async fn seed_ledger_ahead(node: &BiNode, tx: &Transaction, sender: &[u8; 32]) {
    {
        let mut ledger = node.ledger.write().await;
        ledger
            .transfer_internal(sender, &tx.receiver, tx.amount, tx.fee)
            .expect("seed transfer");
        ledger.mark_applied(&tx.id);
        ledger.set_nonce(sender, tx.account_nonce + 1);
        ledger.save_dirty().await.expect("seed ledger persist");
    }
    node.storage.read().await.flush().expect("seed flush");

    let storage = node.storage.read().await;
    assert!(!storage.transaction_exists(tx.id).unwrap());
    assert_eq!(storage.address_index_len_for(sender).unwrap(), 0);
    assert_eq!(storage.address_index_len_for(&BI_RECEIVER).unwrap(), 0);
    assert!(storage.is_applied(tx.id).unwrap());
    assert_eq!(storage.get_balance(*sender).unwrap(), 9_890);
    assert_eq!(storage.get_balance(BI_RECEIVER).unwrap(), 100);
    assert_eq!(storage.get_balance(FEE_BURN_ADDRESS).unwrap(), 10);
}

async fn assert_applied_world(node: &BiNode, tx: &Transaction, sender: &[u8; 32]) {
    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(sender), 9_890);
        assert_eq!(ledger.get_balance(&BI_RECEIVER), 100);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), 10);
        assert!(ledger.is_applied(&tx.id));
    }
    assert!(node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 0);
    {
        let storage = node.storage.read().await;
        assert!(storage.transaction_exists(tx.id).unwrap());
        assert_eq!(storage.address_index_len_for(sender).unwrap(), 1);
        assert_eq!(storage.address_index_len_for(&BI_RECEIVER).unwrap(), 1);
        assert_eq!(storage.get_balance(*sender).unwrap(), 9_890);
        assert_eq!(storage.get_balance(BI_RECEIVER).unwrap(), 100);
        assert_eq!(storage.get_balance(FEE_BURN_ADDRESS).unwrap(), 10);
        assert!(storage.is_applied(tx.id).unwrap());
    }
    let stats = node.rpc.mempool_stats().await;
    assert_eq!(stats.included, 1);
    assert_eq!(stats.rejected, 0);
}

#[tokio::test]
async fn bi3_recovery_insert_reports_persistence_error() {
    let dir = tempdir().unwrap();
    let node = boot_bi_node(dir.path()).await;
    let wallet = bi_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, BI_RECEIVER, 100, 10, 0);
    seed_ledger_ahead(&node, &tx, &sender).await;

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutTransaction);
    let result = TransactionProcessor::new()
        .process(
            tx.clone(),
            &node.dag,
            &node.ledger,
            &node.mempool,
            0,
            ValidationMode::Historical,
        )
        .await;

    assert!(matches!(result, Err(ProcessingError::PersistenceError(_))));
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    {
        let storage = node.storage.read().await;
        assert!(!storage.transaction_exists(tx.id).unwrap());
        assert_eq!(storage.address_index_len_for(&sender).unwrap(), 0);
        assert_eq!(storage.address_index_len_for(&BI_RECEIVER).unwrap(), 0);
    }
    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(&sender), 9_890);
        assert_eq!(ledger.get_balance(&BI_RECEIVER), 100);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), 10);
        assert!(ledger.is_applied(&tx.id));
    }
}

#[tokio::test]
async fn bi1_recovery_persist_failure_requeues_and_restart_retries_once() {
    let dir = tempdir().unwrap();
    let node = boot_bi_node(dir.path()).await;
    let wallet = bi_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, BI_RECEIVER, 100, 10, 0);
    seed_ledger_ahead(&node, &tx, &sender).await;
    assert!(node
        .sync_ctx
        .frontier
        .write()
        .await
        .add_pending(tx.id.to_vec()));
    node.rpc
        .process_transaction(tx.clone(), "BI-Test", ValidationMode::Historical)
        .await
        .expect("accept");
    assert_eq!(node.mempool.read().await.size(), 1);
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Received)
    );

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutTransaction);
    node.rpc.drain_mempool().await;

    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(&sender), 9_890);
        assert_eq!(ledger.get_balance(&BI_RECEIVER), 100);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), 10);
        assert!(ledger.is_applied(&tx.id));
    }
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(
        node.mempool.read().await.size(),
        1,
        "persistence failure must requeue"
    );
    {
        let storage = node.storage.read().await;
        assert!(!storage.transaction_exists(tx.id).unwrap());
        assert_eq!(storage.address_index_len_for(&sender).unwrap(), 0);
        assert_eq!(storage.address_index_len_for(&BI_RECEIVER).unwrap(), 0);
        assert!(storage.is_applied(tx.id).unwrap());
        assert_eq!(storage.get_balance(sender).unwrap(), 9_890);
    }
    assert_eq!(node.rpc.mempool_stats().await.included, 0);
    assert_eq!(
        node.sync_ctx.frontier.read().await.entry_state(&tx.id),
        Some(PageState::Received)
    );
    assert_eq!(node.sync_ctx.frontier.read().await.applied_count(), 0);

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutTransaction);
    node.rpc.drain_mempool().await;
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 1);
    assert!(!node.storage.read().await.transaction_exists(tx.id).unwrap());
    assert_eq!(node.ledger.read().await.get_balance(&sender), 9_890);
    assert_eq!(node.rpc.mempool_stats().await.included, 0);

    drop(node);

    let node = boot_bi_node(dir.path()).await;
    assert_eq!(
        node.mempool.read().await.size(),
        1,
        "persisted mempool row must reload after restart"
    );
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    {
        let storage = node.storage.read().await;
        assert!(!storage.transaction_exists(tx.id).unwrap());
        assert_eq!(storage.address_index_len_for(&sender).unwrap(), 0);
        assert_eq!(storage.address_index_len_for(&BI_RECEIVER).unwrap(), 0);
    }
    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(&sender), 9_890);
        assert!(ledger.is_applied(&tx.id));
    }

    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;

    node.rpc.drain_mempool().await;
    assert_eq!(node.ledger.read().await.get_balance(&sender), 9_890);

    drop(node);

    let reopened = Storage::open(dir.path().join("sled")).unwrap();
    assert!(reopened.transaction_exists(tx.id).unwrap());
    assert_eq!(reopened.address_index_len_for(&sender).unwrap(), 1);
    assert_eq!(reopened.address_index_len_for(&BI_RECEIVER).unwrap(), 1);
    assert!(reopened.is_applied(tx.id).unwrap());
    assert_eq!(reopened.get_balance(sender).unwrap(), 9_890);
    assert_eq!(reopened.get_balance(BI_RECEIVER).unwrap(), 100);
    assert_eq!(reopened.get_balance(FEE_BURN_ADDRESS).unwrap(), 10);
}

#[tokio::test]
async fn bi2_recovery_existing_row_survives_put_failure() {
    let dir = tempdir().unwrap();
    let node = boot_bi_node(dir.path()).await;
    let wallet = bi_wallet();
    let sender = wallet.address();
    fund_and_persist(&node, &sender, 10_000).await;

    let tx = build_pre_migration_tx(&wallet, BI_RECEIVER, 100, 10, 0);
    seed_ledger_ahead(&node, &tx, &sender).await;
    node.storage
        .read()
        .await
        .put_transaction(&tx)
        .expect("pre-existing durable row");
    node.storage.read().await.flush().unwrap();
    assert!(node.storage.read().await.transaction_exists(tx.id).unwrap());

    node.rpc
        .process_transaction(tx.clone(), "BI-Test", ValidationMode::Historical)
        .await
        .expect("accept");
    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutTransaction);
    node.rpc.drain_mempool().await;

    assert_applied_world(&node, &tx, &sender).await;

    drop(node);

    let reopened = Storage::open(dir.path().join("sled")).unwrap();
    assert!(reopened.transaction_exists(tx.id).unwrap());
    assert!(reopened.is_applied(tx.id).unwrap());
    assert_eq!(reopened.get_balance(sender).unwrap(), 9_890);
}
