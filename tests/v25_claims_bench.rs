//! 4CP-BX v2.5 (PHASE 4): claim-table measurement harness.
//!
//! Measures the cost of processing ONE Inventory frame of 1 000 hashes against
//! a claim table already holding 10 000 / 50 000 / 100 000 live claims — the
//! exact shape that made the v2.4 `retain`-per-claim path quadratic.
//!
//! Run it with:
//!   cargo test --release --test v25_claims_bench -- --ignored --nocapture --test-threads=1
//!
//! Caller shape (identical to `src/p2p.rs`, Inventory arm):
//!   1. if the table is at capacity, sweep the expired claims ONCE;
//!   2. then claim each hash of the frame.
//! On the v2.4 tree the sweep did not exist and `claim_request` retained the
//! whole table on every call; the "before" numbers were produced by running the
//! same measurement with that old caller shape (sweep line disabled), so the
//! two figures differ only by the optimisation under test.

use std::time::{Duration, Instant};

use aether_unified::sync_stats::SyncFrontier;

/// Horizon used by the P2P Inventory path (`INFLIGHT_REQUEST_HORIZON`).
const HORIZON: Duration = Duration::from_secs(30);
/// One `GetData` frame carries at most this many hashes (`MAX_INV_ITEMS`).
const FRAME_HASHES: usize = 1_000;

fn hash(domain: u8, n: u64) -> Vec<u8> {
    let mut h = vec![0u8; 32];
    h[0] = domain;
    h[1..9].copy_from_slice(&n.to_le_bytes());
    h
}

/// Fill the claim table with `size` LIVE claims (each one just taken).
fn frontier_with_live_claims(size: usize) -> SyncFrontier {
    let mut f = SyncFrontier::new();
    for i in 0..size {
        let h = hash(0xC1, i as u64);
        assert!(
            f.claim_request(&h, HORIZON),
            "filling the table must succeed below the cap"
        );
    }
    assert_eq!(f.claimed_requests(), size, "table holds exactly `size` claims");
    f
}

fn measure(size: usize) {
    let mut f = frontier_with_live_claims(size);

    // A frame of 1 000 hashes the node has never seen: every one of them is a
    // candidate claim, exactly as the Inventory diff produces.
    let frame: Vec<Vec<u8>> = (0..FRAME_HASHES)
        .map(|i| hash(0xC2, i as u64))
        .collect();

    // v2.5 caller shape: at most ONE sweep per frame, and only at capacity.
    let sweeps_before = f.claim_sweeps();
    let sweep_start = Instant::now();
    let at_capacity = f.claim_table_at_capacity();
    if at_capacity {
        f.sweep_expired_claims(Instant::now(), HORIZON);
    }
    let sweep_elapsed = sweep_start.elapsed();

    let frame_start = Instant::now();
    let mut claimed = 0usize;
    for h in &frame {
        if f.claim_request(h, HORIZON) {
            claimed += 1;
        }
    }
    let frame_elapsed = frame_start.elapsed();
    let total = sweep_elapsed + frame_elapsed;

    println!(
        "BENCH_CLAIMS size={} at_capacity={} sweeps={} frame_hashes={} claimed={} sweep_us={} frame_us={} total_us={} per_hash_ns={}",
        size,
        at_capacity,
        f.claim_sweeps() - sweeps_before,
        FRAME_HASHES,
        claimed,
        sweep_elapsed.as_micros(),
        frame_elapsed.as_micros(),
        total.as_micros(),
        total.as_nanos() / FRAME_HASHES as u128
    );

    // Contract: live claims are never evicted to make room, and the table never
    // exceeds its cap.
    assert!(
        f.claimed_requests() >= size,
        "a live claim must never be evicted to free capacity"
    );
    assert!(
        f.claimed_requests() <= aether_unified::sync_stats::MAX_FRONTIER_ENTRIES,
        "the claim table is bounded"
    );
    assert!(
        f.claim_sweeps() - sweeps_before <= 1,
        "at most ONE sweep per frame"
    );
}

#[test]
#[ignore = "measurement harness: run with --release --ignored"]
fn v25_claims_frame_cost() {
    for size in [10_000usize, 50_000, 100_000] {
        measure(size);
    }
}
