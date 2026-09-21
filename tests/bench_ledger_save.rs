//! Benchmark: Ledger save() vs save_dirty() performance
//! Run with: cargo test --release --test bench_ledger_save -- --nocapture

use std::time::Instant;
use aether_unified::ledger::Ledger;
use aether_unified::storage::Storage;
use std::sync::Arc;
use tokio::sync::RwLock;
use tempfile::tempdir;

/// Seed the ledger with `n` funded accounts.
fn seed_accounts(ledger: &mut Ledger, n: usize) {
    for i in 0..n {
        let mut addr = [0u8; 32];
        addr[0] = ((i >> 24) & 0xFF) as u8;
        addr[1] = ((i >> 16) & 0xFF) as u8;
        addr[2] = ((i >> 8) & 0xFF) as u8;
        addr[3] = (i & 0xFF) as u8;
        ledger.set_balance(&addr, 1_000_000);
    }
}

/// Benchmark: full save() — O(N) write of ALL accounts.
#[tokio::test]
async fn bench_full_save() {
    let counts = [100, 500, 1_000, 5_000, 10_000];
    println!("\n=== bench_full_save() — O(N) full sweep ===\n");

    for n in &counts {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let storage_arc = Arc::new(RwLock::new(storage));

        let mut ledger = Ledger::new_with_storage(storage_arc.clone()).await.unwrap();
        seed_accounts(&mut ledger, *n);

        let start = Instant::now();
        ledger.save().await.unwrap();
        let elapsed = start.elapsed();

        let tps = *n as f64 / elapsed.as_secs_f64();
        println!(
            "  N={:>5}: save() took {:>10.3?}  ({} accounts written, {:.0} writes/s)",
            n, elapsed, n, tps
        );
    }
}

/// Benchmark: incremental save_dirty() — O(K) write of only modified accounts.
#[tokio::test]
async fn bench_incremental_save() {
    let counts = [100, 500, 1_000, 5_000, 10_000];
    println!("\n=== bench_incremental_save() — O(K) delta ===\n");

    for n in &counts {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let storage_arc = Arc::new(RwLock::new(storage));

        // Phase 1: seed N accounts with full save()
        let mut ledger = Ledger::new_with_storage(storage_arc.clone()).await.unwrap();
        seed_accounts(&mut ledger, *n);
        ledger.save().await.unwrap();

        // Phase 2: modify exactly 3 accounts (simulate transfer: sender + receiver + burn)
        let mut ledger = Ledger::new_with_storage(storage_arc.clone()).await.unwrap();
        let mut sender = [0u8; 32];
        let mut receiver = [0u8; 32];
        receiver[3] = 1;
        ledger.set_balance(&sender, ledger.get_balance(&sender) - 110);
        ledger.set_balance(&receiver, ledger.get_balance(&receiver) + 100);
        let burn = aether_unified::ledger::FEE_BURN_ADDRESS;
        ledger.set_balance(&burn, ledger.get_balance(&burn) + 10);

        let start = Instant::now();
        ledger.save_dirty().await.unwrap();
        let elapsed = start.elapsed();

        let tps = 1.0 / elapsed.as_secs_f64();
        println!(
            "  N={:>5}: save_dirty() took {:>10.3?}  (3 accounts written, {:.0} writes/s)",
            n, elapsed, tps
        );
    }
}
