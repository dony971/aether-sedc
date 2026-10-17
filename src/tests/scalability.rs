//! Scalability measurement: DAG insertion, rebuild, and memory at scale.
//!
//! Tests at 10k, 25k, 50k, and 100k transactions to find practical limits.

use crate::genesis::FAUCET_ADDRESS;
use crate::parent_selection::DAG;
use crate::transaction::{Transaction, TransactionId};
use std::time::Instant;

/// Faucet address as bytes.
fn faucet() -> [u8; 32] {
    let bytes = hex::decode(FAUCET_ADDRESS).unwrap();
    bytes.try_into().unwrap()
}

/// Simple address.
fn addr(n: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = n;
    a
}

/// Fund tx from faucet.
fn fund_tx(receiver: [u8; 32], amount: u64, nonce: u64) -> Transaction {
    Transaction::new(
        [[0u8; 32]; 2],
        faucet(),
        receiver,
        amount,
        0,
        1000 + nonce,
        0,
        nonce,
        vec![0u8; 64],
        vec![0u8; 64],
    )
}

/// Transfer tx.
fn transfer_tx(
    parents: [TransactionId; 2],
    sender: [u8; 32],
    receiver: [u8; 32],
    amount: u64,
    fee: u64,
    nonce: u64,
) -> Transaction {
    Transaction::new(
        parents,
        sender,
        receiver,
        amount,
        fee,
        2000 + nonce,
        0,
        nonce,
        vec![0u8; 64],
        vec![0u8; 64],
    )
}

/// Build a DAG with `n` transactions in a linear chain.
/// Returns (dag, build_time_us, insert_time_us_total).
fn build_chain_dag(n: usize) -> (DAG, u128, u128) {
    let mut dag = DAG::new();
    let w = addr(0x11);
    let r = addr(0x22);

    let fund = fund_tx(w, n as u64 * 100, 0);
    dag.inject_transaction_raw(fund.clone());

    let mut prev = fund.id;
    let mut total_insert_us = 0u128;

    let build_start = Instant::now();
    for i in 1..=n as u64 {
        let tx = transfer_tx([prev, [0u8; 32]], w, r, 10, 1, i);
        let start = Instant::now();
        dag.inject_transaction_raw(tx.clone());
        total_insert_us += start.elapsed().as_micros();
        prev = tx.id;
    }
    let build_time = build_start.elapsed().as_micros();

    (dag, build_time, total_insert_us)
}

/// Build a DAG with `n` transactions in a tree (branched).
fn build_tree_dag(n: usize) -> (DAG, u128) {
    let mut dag = DAG::new();
    let w = addr(0x11);

    let fund = fund_tx(w, n as u64 * 100, 0);
    dag.inject_transaction_raw(fund.clone());

    let mut parents = vec![fund.id];

    let build_start = Instant::now();
    for i in 1..=n as u64 {
        // Branch: pick random parent from pool
        let parent_idx = (i as usize) % parents.len();
        let tx = transfer_tx(
            [parents[parent_idx], [0u8; 32]],
            w,
            addr((i % 254 + 1) as u8),
            10,
            1,
            i,
        );
        dag.inject_transaction_raw(tx.clone());
        parents.push(tx.id);

        // Limit pool size to avoid O(n²) memory
        if parents.len() > 1000 {
            parents.drain(..500);
        }
    }
    let build_time = build_start.elapsed().as_micros();

    (dag, build_time)
}

/// Measure rebuild time for a DAG.
fn measure_rebuild(dag: &DAG) -> (u128, u64) {
    let start = Instant::now();
    let mut ledger = crate::ledger::Ledger::new();
    ledger.rebuild_from_dag(dag);
    let rebuild_us = start.elapsed().as_micros();
    let tx_count = dag.transactions().len() as u64;
    (rebuild_us, tx_count)
}

/// Test: scalability at 10k transactions (linear chain)
#[test]
fn test_scalability_10k_chain() {
    let n = 10_000;
    println!("=== Scalability: {} txs (linear chain) ===", n);

    let (dag, build_us, insert_us) = build_chain_dag(n);
    let (rebuild_us, _) = measure_rebuild(&dag);
    let tx_count = dag.transactions().len();

    println!("  Transactions: {}", tx_count);
    println!("  Build time:   {:.2} ms", build_us as f64 / 1000.0);
    println!(
        "  Avg insert:   {:.2} us/tx",
        insert_us as f64 / tx_count as f64
    );
    println!("  Rebuild time: {:.2} ms", rebuild_us as f64 / 1000.0);
    println!(
        "  Rebuild rate:  {:.0} tx/s",
        tx_count as f64 / (rebuild_us as f64 / 1_000_000.0)
    );

    assert_eq!(tx_count, n + 1); // n transfers + 1 fund
}

/// Test: scalability at 25k transactions
#[test]
fn test_scalability_25k_chain() {
    let n = 25_000;
    println!("=== Scalability: {} txs (linear chain) ===", n);

    let (dag, build_us, insert_us) = build_chain_dag(n);
    let (rebuild_us, _) = measure_rebuild(&dag);
    let tx_count = dag.transactions().len();

    println!("  Transactions: {}", tx_count);
    println!("  Build time:   {:.2} ms", build_us as f64 / 1000.0);
    println!(
        "  Avg insert:   {:.2} us/tx",
        insert_us as f64 / tx_count as f64
    );
    println!("  Rebuild time: {:.2} ms", rebuild_us as f64 / 1000.0);
    println!(
        "  Rebuild rate:  {:.0} tx/s",
        tx_count as f64 / (rebuild_us as f64 / 1_000_000.0)
    );
}

/// Test: scalability at 50k transactions
#[test]
fn test_scalability_50k_chain() {
    let n = 50_000;
    println!("=== Scalability: {} txs (linear chain) ===", n);

    let (dag, build_us, insert_us) = build_chain_dag(n);
    let (rebuild_us, _) = measure_rebuild(&dag);
    let tx_count = dag.transactions().len();

    println!("  Transactions: {}", tx_count);
    println!("  Build time:   {:.2} ms", build_us as f64 / 1000.0);
    println!(
        "  Avg insert:   {:.2} us/tx",
        insert_us as f64 / tx_count as f64
    );
    println!("  Rebuild time: {:.2} ms", rebuild_us as f64 / 1000.0);
    println!(
        "  Rebuild rate:  {:.0} tx/s",
        tx_count as f64 / (rebuild_us as f64 / 1_000_000.0)
    );
}

/// Test: scalability at 100k transactions
#[test]
fn test_scalability_100k_chain() {
    let n = 100_000;
    println!("=== Scalability: {} txs (linear chain) ===", n);

    let (dag, build_us, insert_us) = build_chain_dag(n);
    let (rebuild_us, _) = measure_rebuild(&dag);
    let tx_count = dag.transactions().len();

    println!("  Transactions: {}", tx_count);
    println!("  Build time:   {:.2} ms", build_us as f64 / 1000.0);
    println!(
        "  Avg insert:   {:.2} us/tx",
        insert_us as f64 / tx_count as f64
    );
    println!("  Rebuild time: {:.2} ms", rebuild_us as f64 / 1000.0);
    println!(
        "  Rebuild rate:  {:.0} tx/s",
        tx_count as f64 / (rebuild_us as f64 / 1_000_000.0)
    );
}

/// Test: tree DAG scalability at 50k (tests branch weight computation)
#[test]
fn test_scalability_50k_tree() {
    let n = 50_000;
    println!("=== Scalability: {} txs (tree DAG) ===", n);

    let (dag, build_us) = build_tree_dag(n);
    let (rebuild_us, _) = measure_rebuild(&dag);
    let tx_count = dag.transactions().len();

    println!("  Transactions: {}", tx_count);
    println!("  Build time:   {:.2} ms", build_us as f64 / 1000.0);
    println!("  Rebuild time: {:.2} ms", rebuild_us as f64 / 1000.0);
    println!(
        "  Rebuild rate:  {:.0} tx/s",
        tx_count as f64 / (rebuild_us as f64 / 1_000_000.0)
    );
}

/// Test: rebuild cost scaling curve
#[test]
fn test_rebuild_curve() {
    println!("=== Rebuild Cost Curve ===");
    println!("| Txs      | Build (ms) | Rebuild (ms) | Rate (tx/s) |");
    println!("|----------|------------|--------------|-------------|");

    let sizes = [1_000, 5_000, 10_000, 25_000, 50_000, 100_000];

    for &n in &sizes {
        let (dag, build_us, _) = build_chain_dag(n);
        let (rebuild_us, _) = measure_rebuild(&dag);
        let tx_count = dag.transactions().len();
        let rate = tx_count as f64 / (rebuild_us as f64 / 1_000_000.0);

        println!(
            "| {:>8} | {:>10.2} | {:>12.2} | {:>11.0} |",
            n,
            build_us as f64 / 1000.0,
            rebuild_us as f64 / 1000.0,
            rate
        );
    }
}

/// Test: rebuild rate degradation detection
#[test]
fn test_rebuild_degradation() {
    let sizes = [1_000, 10_000, 50_000, 100_000];
    let mut prev_rate = f64::MAX;

    println!("=== Rebuild Degradation Analysis ===");

    for &n in &sizes {
        let (dag, _, _) = build_chain_dag(n);
        let (rebuild_us, _) = measure_rebuild(&dag);
        let tx_count = dag.transactions().len() as f64;
        let rate = tx_count / (rebuild_us as f64 / 1_000_000.0);

        let degradation = if prev_rate < f64::MAX {
            ((prev_rate - rate) / prev_rate * 100.0)
        } else {
            0.0
        };

        println!(
            "  {:>8} txs: {:.0} tx/s (degradation: {:.1}%)",
            n, rate, degradation
        );

        prev_rate = rate;
    }
}
