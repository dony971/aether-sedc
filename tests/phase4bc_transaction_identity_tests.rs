use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::json_storage::{DagStore, StoredTransaction};
use aether_unified::parent_selection::rebuild_dag_topological;
use aether_unified::storage::Storage;
use aether_unified::transaction::Transaction;
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

const TEST_TIMESTAMP: u64 = Transaction::DIFFICULTY_MIGRATION_TS - 1_000_000;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("fixed test key")
}

fn signed_canonical_tx(wallet: &Wallet, tag: u64) -> Transaction {
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        wallet.address(),
        [0xAAu8; 32],
        1_000,
        1,
        TEST_TIMESTAMP + tag,
        0,
        1,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_hash());
    tx
}

fn legacy_cli_tx(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    account_nonce: u64,
    tag: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        [0xAAu8; 32],
        1_000,
        1,
        TEST_TIMESTAMP + tag,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    let legacy_id = tx.compute_hash();
    assert_eq!(legacy_id, tx.compute_legacy_hash());
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = legacy_id;
    assert!(!tx.verify_hash());
    assert!(tx.verify_hash_compatible());
    tx
}

fn open_store(path: &Path) -> Storage {
    for attempt in 0..50 {
        match Storage::open(path) {
            Ok(store) => return store,
            Err(e) => {
                let retryable = e.to_string().contains("could not acquire lock")
                    || e.to_string().contains("Resource temporarily unavailable");
                if !retryable || attempt == 49 {
                    panic!("open store at {}: {}", path.display(), e);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    unreachable!()
}

#[test]
fn bc01_producer_must_hash_after_signing() {
    let wallet = wallet_n(0xBC01);
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        wallet.address(),
        [0xAAu8; 32],
        1_000,
        1,
        TEST_TIMESTAMP,
        0,
        1,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);

    let pre_signature_id = tx.compute_hash();
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = pre_signature_id;

    assert!(!tx.verify_hash());
    assert_eq!(tx.id, tx.compute_legacy_hash());
    assert!(tx.verify_hash_compatible());

    tx.id = tx.compute_hash();
    assert!(tx.verify_hash());
    TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Historical)
        .expect("hashing after signing must pass the pure gate");
}

#[test]
fn bc02_persisted_forged_id_not_adopted_at_rebuild() {
    let wallet = wallet_n(0xBC02);
    let canonical = signed_canonical_tx(&wallet, 2);
    let mut forged = canonical.clone();
    let forged_id = [0xBCu8; 32];
    forged.id = forged_id;
    assert!(!forged.verify_hash());

    let dir = tempdir().expect("tempdir");
    {
        let store = open_store(dir.path());
        store
            .put_transaction(&canonical)
            .expect("persist canonical");
        store.put_transaction(&forged).expect("persist forged");
        store.flush().expect("flush");
    }

    let persisted = {
        let store = open_store(dir.path());
        let txs = store.get_all_transactions().expect("read persisted txs");
        drop(store);
        txs
    };
    assert_eq!(persisted.len(), 2);

    let (mut dag, _balances, _orphans, _missing) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, remaining) = rebuild_dag_topological(&mut dag, persisted);

    assert_eq!(inserted, 1, "only the canonical identity is admissible");
    assert_eq!(skipped, 1, "the forged identity must be skipped explicitly");
    assert!(remaining.is_empty());
    assert!(dag.transactions().contains_key(&canonical.id));
    assert!(!dag.transactions().contains_key(&forged_id));
}

#[test]
fn bc03_legacy_cli_id_survives_restart_and_history_replay() {
    let wallet = wallet_n(0xBC03);
    let legacy = legacy_cli_tx(&wallet, [[0u8; 32]; 2], 1, 3);
    TransactionProcessor::new()
        .validate_pure(&legacy, ValidationMode::Historical)
        .expect("historical replay must accept the legacy CLI identity");

    let dir = tempdir().expect("tempdir");
    {
        let store = open_store(dir.path());
        store.put_transaction(&legacy).expect("persist legacy");
        store.flush().expect("flush");
    }

    let persisted = {
        let store = open_store(dir.path());
        let txs = store.get_all_transactions().expect("read persisted txs");
        drop(store);
        txs
    };
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].id, legacy.id);

    let (mut dag, _balances, _orphans, _missing) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, remaining) = rebuild_dag_topological(&mut dag, persisted);

    assert_eq!(inserted, 1);
    assert_eq!(skipped, 0);
    assert!(remaining.is_empty());
    assert!(dag.transactions().contains_key(&legacy.id));
}

#[tokio::test]
async fn bc04_legacy_json_migration_preserves_ids_and_parent_links() {
    let wallet = wallet_n(0xBC04);
    let first = legacy_cli_tx(&wallet, [[0u8; 32]; 2], 1, 4);
    let second = legacy_cli_tx(&wallet, [first.id, [0u8; 32]], 2, 5);

    let dir = tempdir().expect("tempdir");
    let legacy = dir.path().join("legacy");
    std::fs::create_dir_all(&legacy).expect("mkdir legacy");
    let json = serde_json::to_vec(&DagStore {
        transactions: vec![
            StoredTransaction::from(&first),
            StoredTransaction::from(&second),
        ],
        children: Vec::new(),
    })
    .expect("serialize legacy dag");
    std::fs::write(legacy.join("dag.json"), json).expect("write legacy dag");

    let sled_dir = dir.path().join("sled");
    let store = open_store(&sled_dir);
    store
        .migrate_from_json(&legacy)
        .await
        .expect("migration succeeds");

    let migrated = store.get_all_transactions().expect("read migrated");
    assert_eq!(migrated.len(), 2);
    let first_id = first.id;
    let second_id = second.id;
    assert!(store.get_transaction(first_id).is_ok());
    assert!(store.get_transaction(second_id).is_ok());
    assert_eq!(
        store.get_transaction(second_id).unwrap().parents[0],
        first_id
    );

    let (mut dag, _balances, _orphans, _missing) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, remaining) = rebuild_dag_topological(&mut dag, migrated);
    assert_eq!(inserted, 2);
    assert_eq!(skipped, 0);
    assert!(remaining.is_empty());
    assert!(dag.transactions().contains_key(&first_id));
    assert!(dag.transactions().contains_key(&second_id));
}

#[tokio::test]
async fn bc05_migration_rejects_arbitrary_declared_id() {
    let wallet = wallet_n(0xBC05);
    let tx = signed_canonical_tx(&wallet, 6);
    let forged_id = [0xBCu8; 32];

    let dir = tempdir().expect("tempdir");
    let legacy = dir.path().join("legacy");
    std::fs::create_dir_all(&legacy).expect("mkdir legacy");
    let mut stored = StoredTransaction::from(&tx);
    stored.id = hex::encode(forged_id);
    let json = serde_json::to_vec(&DagStore {
        transactions: vec![stored],
        children: Vec::new(),
    })
    .expect("serialize legacy dag");
    std::fs::write(legacy.join("dag.json"), json).expect("write legacy dag");

    let sled_dir = dir.path().join("sled");
    let store = open_store(&sled_dir);
    store
        .migrate_from_json(&legacy)
        .await
        .expect_err("migration must not rewrite an arbitrary declared id");
    assert_eq!(store.transaction_count().unwrap(), 0);
}
