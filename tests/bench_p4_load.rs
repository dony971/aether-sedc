//! P4 Load Test — realistic throughput measurement for save_dirty().
//! Run: cargo test --release --test bench_p4_load -- --nocapture

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tempfile::tempdir;
use aether_unified::DAG;
use aether_unified::ledger::Ledger;
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::storage::Storage;
use aether_unified::transaction::Transaction;
use aether_unified::Mempool;
use aether_unified::validation::ValidationMode;

fn make_tx(
    sender: &[u8; 32],
    receiver: &[u8; 32],
    account_nonce: u64,
    amount: u64,
    fee: u64,
    parents: [[u8; 32]; 2],
) -> Transaction {
    Transaction::new(
        parents,
        *sender,
        *receiver,
        amount,
        fee,
        1234567890 + account_nonce,
        0,
        account_nonce,
        vec![0u8; 64],
        vec![1u8; 64],
    )
}

async fn run_load_test(n_txs: usize) {
    let dir = tempdir().unwrap();
    let _storage = Storage::open(dir.path()).unwrap();
    let _storage_arc = Arc::new(RwLock::new(_storage));

    let dag = Arc::new(RwLock::new(DAG::new()));
    let ledger = Arc::new(RwLock::new(Ledger::new()));
    let mempool = Arc::new(RwLock::new(Mempool::new(10_000, 10)));
    let processor = TransactionProcessor::new();

    {
        let mut l = ledger.write().await;
        let mut sender = [0u8; 32];
        sender[3] = 1;
        l.set_balance(&sender, 1_000_000_000);
        l.save().await.unwrap();
    }

    let mut total_persist_time = Duration::ZERO;
    let mut errors = 0u64;
    let mut accepted = 0u64;
    let start = Instant::now();

    let mut last_tip = [0u8; 32];

    for i in 0..n_txs {
        let mut sender = [0u8; 32];
        sender[3] = 1;
        let mut receiver = [0u8; 32];
        receiver[3] = (i % 250 + 2) as u8;

        let parents = [[0u8; 32], last_tip];
        let tx = make_tx(&sender, &receiver, i as u64, 100, 10, parents);

        let tx_id = tx.id;
        {
            let mut d = dag.write().await;
            d.add_transaction_validated(tx.clone());
            last_tip = tx_id;
        }

        let result = processor.process(
            tx, &dag, &ledger, &mempool, 1000, ValidationMode::Fresh,
        ).await;

        match result {
            Ok(()) => { accepted += 1; }
            Err(_) => { errors += 1; }
        }

        if i % 100 == 0 && i > 0 {
            let p_start = Instant::now();
            {
                let mut l = ledger.write().await;
                let _ = l.save_dirty().await;
            }
            total_persist_time += p_start.elapsed();
        }
    }

    let elapsed = start.elapsed();
    let tps = n_txs as f64 / elapsed.as_secs_f64();
    let persist_count = (n_txs / 100) as f64;
    let avg_persist = if persist_count > 0.0 {
        total_persist_time.as_micros() as f64 / persist_count
    } else {
        0.0
    };

    let db_size: u64 = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum();

    println!(
        "  {:>6} TXs | TPS: {:>8.1} | persist/100tx: {:>8.1}us | accepted: {:>5} | errors: {:>4} | DB: {:>10} bytes | elapsed: {:>7.2?}",
        n_txs, tps, avg_persist, accepted, errors, db_size, elapsed
    );
}

#[tokio::test]
async fn bench_p4_load_100() { run_load_test(100).await; }

#[tokio::test]
async fn bench_p4_load_500() { run_load_test(500).await; }

#[tokio::test]
async fn bench_p4_load_1k() { run_load_test(1_000).await; }

#[tokio::test]
async fn bench_p4_load_5k() { run_load_test(5_000).await; }

#[tokio::test]
async fn bench_p4_load_10k() { run_load_test(10_000).await; }
