//! PoW attack economics: CPU benchmarks and GPU cost model.
//!
//! Measures actual PoW cost at different difficulty levels and builds
//! an attack cost model. GPU estimates use published data only.

use crate::transaction::Transaction;

/// Run PoW benchmarks at multiple difficulty levels and return results.
/// Returns Vec of (difficulty, median_ns, hashes_per_sec, hashes_needed).
fn bench_pow_curve() -> Vec<(u8, u128, f64, u64)> {
    let iterations = 20;
    let difficulties = [16, 18, 20, 22, 24, 26, 28];

    let mut results = Vec::new();

    for &diff in &difficulties {
        let (avg, median, p95, hps) = Transaction::bench_pow(diff, iterations);
        let hashes_needed = (1u64 << diff) as f64; // expected ~2^d / 2 hashes
        results.push((diff, median, hps, hashes_needed as u64));

        println!(
            "  difficulty={}: median={:.2}ms, p95={:.2}ms, hps={:.0}, ~{} hashes",
            diff,
            median as f64 / 1_000_000.0,
            p95 as f64 / 1_000_000.0,
            hps,
            hashes_needed as u64
        );
    }

    results
}

/// Test: benchmark PoW at the current default difficulty (24 bits)
#[test]
fn test_pow_benchmark_24bit() {
    let (avg, median, p95, hps) = Transaction::bench_pow(24, 20);
    let cost_per_tx_ms = median as f64 / 1_000_000.0;

    println!("=== PoW Benchmark (24 bits) ===");
    println!("  average:  {:.2} ms", avg as f64 / 1_000_000.0);
    println!("  median:   {:.2} ms", median as f64 / 1_000_000.0);
    println!("  p95:      {:.2} ms", p95 as f64 / 1_000_000.0);
    println!("  hps:      {:.0}", hps);
    println!("  cost/tx:  {:.2} ms", cost_per_tx_ms);

    // Sanity: 24-bit should take at least 500ms median on this CPU
    assert!(median > 500_000_000, "24-bit PoW too fast: {}ns", median);

    // Cost for 1k, 10k, 100k, 1M txs
    let costs = [1_000, 10_000, 100_000, 1_000_000];
    println!("\n=== CPU Cost Model (24 bits) ===");
    for &n in &costs {
        let total_sec = cost_per_tx_ms * n as f64 / 1000.0;
        let total_min = total_sec / 60.0;
        let total_hours = total_min / 60.0;
        println!(
            "  {} tx: {:.1}s ({:.1}min, {:.2}h)",
            n, total_sec, total_min, total_hours
        );
    }

    // Single core TPS
    let tps = 1000.0 / cost_per_tx_ms;
    println!("\n  Single-core TPS: {:.2}", tps);
}

/// Test: full PoW curve across all difficulty levels
#[test]
fn test_pow_curve() {
    println!("=== PoW Difficulty Curve ===");
    let results = bench_pow_curve();

    // Print comparison table
    println!("\n=== Attack Economics Model ===");
    println!("Assumptions:");
    println!("  CPU: Intel/AMD single core (measured)");
    println!("  GPU: RTX 4090 = 5.16 GH/s BLAKE3 (ESTIMATED from public data)");
    println!("  1 AETH = 10^10 base units");
    println!();

    for (diff, median, hps, hashes) in &results {
        let cost_ms = *median as f64 / 1_000_000.0;
        let gpu_hps = 5_160_000_000.0_f64; // RTX 4090 estimated
        let gpu_advantage = gpu_hps / *hps;

        println!("--- {} bits ---", diff);
        println!("  CPU: {:.2} ms/tx, {:.0} hps", cost_ms, hps);
        println!(
            "  GPU (est): {:.2} ms/tx, {:.0} hps",
            (*hashes as f64 / gpu_hps * 1000.0),
            gpu_hps
        );
        println!("  GPU speedup: {:.0}x", gpu_advantage);

        // Cost for 1M txs
        let cpu_1m = cost_ms * 1_000_000.0 / 1000.0;
        let gpu_1m = *hashes as f64 / gpu_hps * 1_000_000.0;
        println!("  1M tx CPU:  {:.0}s ({:.1}h)", cpu_1m, cpu_1m / 3600.0);
        println!("  1M tx GPU:  {:.1}s ({:.2}h)", gpu_1m, gpu_1m / 3600.0);
        println!();
    }
}

/// Test: cost model for 24-bit difficulty at various volumes
#[test]
fn test_pow_cost_model() {
    let (_, median, hps, _) = Transaction::bench_pow(24, 30);
    let cost_ms = median as f64 / 1_000_000.0;
    let gpu_hps = 5_160_000_000.0; // RTX 4090 (ESTIMATED)
    let gpu_hashes = (1u64 << 24) as f64;

    println!("=== 24-bit PoW Attack Cost Model ===");
    println!("CPU measured: {:.2} ms/tx ({:.0} hps)", cost_ms, hps);
    println!("GPU estimated: RTX 4090 = 5.16 GH/s (public benchmarks)");
    println!();

    let volumes = [100, 1_000, 10_000, 100_000, 1_000_000];
    println!("| Volume  | CPU Time      | GPU Time (est) | GPU Speedup |");
    println!("|---------|---------------|----------------|-------------|");

    for &n in &volumes {
        let cpu_sec = cost_ms * n as f64 / 1000.0;
        let gpu_sec = gpu_hashes / gpu_hps * n as f64;

        let cpu_str = format_time(cpu_sec);
        let gpu_str = format_time(gpu_sec);
        let speedup = cpu_sec / gpu_sec;

        println!(
            "| {:>7} | {:>13} | {:>14} | {:>11.1}x |",
            format!("{:}", n),
            cpu_str,
            gpu_str,
            speedup
        );
    }

    println!();
    println!("=== Verdict ===");
    println!("24-bit PoW is an ANTI-SPAM measure, NOT a consensus security measure.");
    println!(
        "A GPU attacker can generate ~{:.0} tx/s vs CPU {:.2} tx/s.",
        gpu_hps / gpu_hashes,
        1000.0 / cost_ms
    );
    println!(
        "For consensus security, DAG weight + finality + peer reputation are the real defenses."
    );
}

/// Test: PoW verification cost (should be much cheaper than mining)
#[test]
fn test_pow_verification_cost() {
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        [1u8; 32],
        [2u8; 32],
        100,
        10,
        1234567890,
        0,
        1,
        vec![0u8; 64],
        vec![0u8; 32],
    );
    tx.nonce = tx.mine_nonce(24);

    // Verify 10000 times
    let iterations = 10_000;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = tx.verify_pow(Transaction::default_difficulty());
    }
    let elapsed = start.elapsed();
    let verify_ns = elapsed.as_nanos() / iterations;

    println!(
        "=== PoW Verification Cost ===\n  {} verifications in {:?}\n  per-verify: {} ns ({:.2} us)",
        iterations,
        elapsed,
        verify_ns,
        verify_ns as f64 / 1000.0
    );

    // Verify is at least 100x cheaper than mine
    let (_, median, _, _) = Transaction::bench_pow(24, 10);
    let ratio = median / verify_ns as u128;
    println!("  verify/mine ratio: 1:{:.0}", ratio);
    assert!(
        ratio > 100,
        "verify should be at least 100x cheaper than mine"
    );
}

fn format_time(seconds: f64) -> String {
    if seconds < 0.001 {
        format!("{:.2} us", seconds * 1_000_000.0)
    } else if seconds < 1.0 {
        format!("{:.2} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.2} s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} min", seconds / 60.0)
    } else {
        format!("{:.1} h", seconds / 3600.0)
    }
}
