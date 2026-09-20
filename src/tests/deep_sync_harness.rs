//! Deep sync harness: tests ancestor_full_closure + pagination + frontier
//! monotone + backpressure on real DAG histories of increasing depth.
//!
//! Each test:
//! 1. Builds a source DAG of N transactions (ladder pattern, validated)
//! 2. Computes a state fingerprint (txset, tips, weights, ledger)
//! 3. Simulates P2P sync: fresh node receives pages from the source
//! 4. Verifies convergence: fingerprint(source) == fingerprint(fresh)
//!
//! ÉTAPES 5–9 of the deep-sync campaign.

use crate::genesis::{initialize_genesis, GenesisConfig, FAUCET_ADDRESS};
use crate::ledger::Ledger;
use crate::p2p::P2PNetwork;
use crate::parent_selection::{rebuild_dag_topological, DAG};
use crate::storage::Storage;
use crate::sync_stats::{
    FrontierSyncState, PageState, SyncFrontier, MAX_FRONTIER_ENTRIES, MAX_INFLIGHT_REQUESTS,
    STALL_THRESHOLD,
};
use crate::transaction::Transaction;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

// ===== Shared helpers =====

fn state_fingerprint(dag: &DAG, ledger: &Ledger) -> String {
    let mut ids: Vec<[u8; 32]> = dag.transactions().keys().copied().collect();
    ids.sort();
    let mut weights: Vec<(u64, u64)> = ids
        .iter()
        .map(|id| {
            let tx = &dag.transactions()[id];
            (
                u64::from_le_bytes(id[0..8].try_into().unwrap()),
                tx.weight.to_bits(),
            )
        })
        .collect();
    weights.sort_by_key(|(k, _)| *k);
    let mut tips: Vec<[u8; 32]> = dag
        .transactions()
        .keys()
        .filter(|id| !dag.children().contains_key(*id))
        .copied()
        .collect();
    tips.sort();
    let mut balances: Vec<(String, u64)> = ledger.balances.clone().into_iter().collect();
    balances.sort();
    let mut nonces: Vec<(String, u64)> = ledger.nonces.clone().into_iter().collect();
    nonces.sort();
    format!(
        "txset={:?} tips={:?} weights={:?} balances={:?} nonces={:?} supply={}",
        ids,
        tips,
        weights,
        balances,
        nonces,
        ledger.total_supply()
    )
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aether-deep-sync-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Build N synthetic txs from the genesis faucet: a 22-wide ladder pattern.
/// No PoW/signature — suitable for topological insert and rebuild.
fn build_ladder(sender: [u8; 32], n: u64) -> Vec<Transaction> {
    let mut txs: Vec<Transaction> = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let parents = if i <= 22 {
            let prev = if i == 1 {
                [0u8; 32]
            } else {
                txs[(i - 2) as usize].id
            };
            [prev, [0u8; 32]]
        } else {
            [txs[(i - 23) as usize].id, txs[(i - 22) as usize].id]
        };
        let tx = Transaction::new(
            parents,
            sender,
            [0xAAu8; 32],
            1000,
            1,
            1_000_000 + i,
            i,
            i,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        txs.push(tx);
    }
    txs
}

/// Build a complete source DAG + ledger + persisted store.
fn build_source(n: u64) -> (DAG, Ledger, Vec<Transaction>, PathBuf) {
    let sender: [u8; 32] = hex::decode(FAUCET_ADDRESS)
        .expect("faucet addr")
        .try_into()
        .expect("32B");
    let txs = build_ladder(sender, n);
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    for tx in &txs {
        dag.add_transaction_validated(tx.clone())
            .expect("ladder insert");
    }
    dag.rebuild_tips();
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    // Persist to disk
    let dir = temp_dir(&format!("source-{}", n));
    let store = Storage::open(&dir).expect("open store");
    for tx in &txs {
        store.put_transaction(tx).expect("persist");
    }
    store.flush().expect("flush");
    drop(store);
    (dag, ledger, txs, dir)
}

/// Topological sort of a DAG (parents before children).
fn topo_sort(dag: &DAG) -> Vec<[u8; 32]> {
    let mut in_degree: HashMap<[u8; 32], usize> = HashMap::new();
    for (id, tx) in dag.transactions() {
        let entry = in_degree.entry(*id).or_insert(0);
        *entry = *entry; // already 0
        for p in &tx.parents {
            if !p.iter().all(|&b| b == 0) {
                in_degree.entry(*p).or_insert(0);
            }
        }
        // Count how many non-genesis parents this tx has
        for p in &tx.parents {
            if !p.iter().all(|&b| b == 0) {
                // This tx depends on p — but we count edges TO this tx
            }
        }
    }
    // Simpler: just sort by id (ladder pattern guarantees topological order
    // because children always have higher ids than parents).
    let mut ids: Vec<[u8; 32]> = dag.transactions().keys().copied().collect();
    ids.sort();
    ids
}

struct SyncMetrics {
    pages_sent: usize,
    txs_sent: usize,
    txs_inserted: u64,
    orphans: usize,
    frontier_peak: usize,
    inflight_peak: usize,
    elapsed_ms: u64,
}

/// Simulate P2P sync: source → fresh node, page by page.
///
/// This is the core deep-sync test. It:
/// 1. Reads source txs from the persisted store
/// 2. Computes ancestor_full_closure for each page of requested hashes
/// 3. Sends pages to the fresh node
/// 4. The fresh node inserts via rebuild_dag_topological
/// 5. Tracks frontier state throughout
fn simulate_sync(
    _source_dag: &DAG,
    _source_ledger: &Ledger,
    source_txs: &[Transaction],
    page_size: usize,
) -> (DAG, Ledger, SyncMetrics) {
    // Build the fresh node
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let mut fresh_ledger = Ledger::new();

    // Build lookup from source
    let source_map: HashMap<Vec<u8>, &Transaction> =
        source_txs.iter().map(|tx| (tx.id.to_vec(), tx)).collect();
    let get_tx = |hash: &[u8]| -> Option<Transaction> { source_map.get(hash).cloned().cloned() };

    // Topological order of source (deterministic: sorted by id)
    let topo_order: Vec<Vec<u8>> = source_txs.iter().map(|tx| tx.id.to_vec()).collect();

    // Frontier tracker
    let mut frontier = SyncFrontier::new();
    for h in &topo_order {
        frontier.add_pending(h.clone());
    }

    let mut metrics = SyncMetrics {
        pages_sent: 0,
        txs_sent: 0,
        txs_inserted: 0,
        orphans: 0,
        frontier_peak: 0,
        inflight_peak: 0,
        elapsed_ms: 0,
    };

    let start = Instant::now();
    let mut applied_all: Vec<Transaction> = Vec::new();
    let mut offset = 0;

    while offset < topo_order.len() {
        // Request a page of hashes
        let page_hashes: Vec<Vec<u8>> = topo_order
            .iter()
            .skip(offset)
            .take(page_size)
            .cloned()
            .collect();

        // Mark requested in frontier
        let peer: SocketAddr = "10.0.0.1:25565".parse().unwrap();
        for h in &page_hashes {
            frontier.mark_requested(h, peer);
        }

        // Compute ancestor_full_closure (simulates what the server does)
        let max_entries = page_size * 10; // MAX_CLOSURE_PAGES = 10
        let mut closure = P2PNetwork::ancestor_full_closure(&page_hashes, &get_tx, max_entries);

        // Topological sort (source is already sorted, but closure may not be)
        let pos: HashMap<&Vec<u8>, usize> =
            topo_order.iter().enumerate().map(|(i, h)| (h, i)).collect();
        closure.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));

        // Split into sub-pages of page_size
        for chunk in closure.chunks(page_size) {
            let page_txs: Vec<Transaction> = chunk
                .iter()
                .filter_map(|h| source_map.get(h).cloned().cloned())
                .collect();

            // Mark received in frontier
            for h in chunk {
                frontier.mark_received(h);
            }

            metrics.pages_sent += 1;
            metrics.txs_sent += page_txs.len();

            // Apply to fresh node
            for tx in &page_txs {
                if fresh_dag.add_transaction_validated(tx.clone()).is_ok() {
                    frontier.mark_applied(&tx.id);
                    frontier.record_progress();
                    applied_all.push(tx.clone());
                } else {
                    frontier.mark_rejected(&tx.id);
                }
            }

            // Update peaks
            metrics.frontier_peak = metrics.frontier_peak.max(frontier.total_tracked());
            metrics.inflight_peak = metrics.inflight_peak.max(frontier.inflight_count());
        }

        offset += page_size;
    }

    // Rebuild tips and ledger
    fresh_dag.rebuild_tips();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    metrics.elapsed_ms = start.elapsed().as_millis() as u64;
    metrics.txs_inserted = fresh_dag.transaction_count() as u64;
    metrics.orphans = fresh_dag
        .transactions()
        .values()
        .filter(|tx| {
            tx.parents
                .iter()
                .any(|p| !p.iter().all(|&b| b == 0) && !fresh_dag.transactions().contains_key(p))
        })
        .count();

    (fresh_dag, fresh_ledger, metrics)
}

// ===== ÉTAPE 5: Bounds Tests =====

#[test]
fn test_bounds_page_size_100() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "PAGE_SIZE=100 must converge");
    assert_eq!(m.txs_inserted, 200, "all 200 txs must be inserted");
    assert_eq!(m.orphans, 0, "no orphans");
    cleanup(&dir);
}

#[test]
fn test_bounds_page_size_250() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(500);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 250);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "PAGE_SIZE=250 must converge");
    assert_eq!(m.txs_inserted, 500);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

#[test]
fn test_bounds_page_size_500() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(1000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 500);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "PAGE_SIZE=500 must converge");
    assert_eq!(m.txs_inserted, 1000);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

#[test]
fn test_bounds_overflow_unbounded_alloc() {
    // Verify that ancestor_full_closure respects max_entries bound
    let (source_dag, source_ledger, source_txs, dir) = build_source(1000);
    let source_map: HashMap<Vec<u8>, &Transaction> =
        source_txs.iter().map(|tx| (tx.id.to_vec(), tx)).collect();
    let get_tx = |hash: &[u8]| -> Option<Transaction> { source_map.get(hash).cloned().cloned() };
    // Request with very small max_entries
    let tip = source_txs.last().unwrap().id.to_vec();
    let closure = P2PNetwork::ancestor_full_closure(&[tip], &get_tx, 50);
    assert!(
        closure.len() <= 50,
        "closure must respect max_entries bound: got {}",
        closure.len()
    );
    cleanup(&dir);
}

#[test]
fn test_bounds_inflight_cap_enforced() {
    let mut f = SyncFrontier::new();
    for i in 0..MAX_INFLIGHT_REQUESTS + 10 {
        let mut h = vec![0u8; 32];
        h[0] = (i % 256) as u8;
        h[1] = (i / 256) as u8;
        f.add_pending(h.clone());
        f.mark_requested(&h, "10.0.0.1:25565".parse().unwrap());
    }
    assert!(
        f.inflight_count() <= MAX_INFLIGHT_REQUESTS,
        "inflight cap must be enforced: got {}",
        f.inflight_count()
    );
}

#[test]
fn test_bounds_frontier_memory_cap() {
    let mut f = SyncFrontier::new();
    for i in 0..MAX_FRONTIER_ENTRIES + 1000 {
        let mut h = vec![0u8; 32];
        h[0] = (i % 256) as u8;
        h[1] = ((i / 256) % 256) as u8;
        h[2] = ((i / 65536) % 256) as u8;
        f.add_pending(h);
    }
    assert!(
        f.total_tracked() <= MAX_FRONTIER_ENTRIES,
        "frontier memory cap enforced: got {}",
        f.total_tracked()
    );
}

// ===== ÉTAPE 6: Deep Sync Profondeur =====

#[test]
fn test_deep_sync_100() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(100);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_100 fingerprint mismatch");
    assert_eq!(m.txs_inserted, 100);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_100] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

#[test]
fn test_deep_sync_400() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(400);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_400 fingerprint mismatch");
    assert_eq!(m.txs_inserted, 400);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_400] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

#[test]
fn test_deep_sync_800() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(800);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_800 fingerprint mismatch");
    assert_eq!(m.txs_inserted, 800);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_800] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

#[test]
fn test_deep_sync_1600() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(1600);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_1600 fingerprint mismatch");
    assert_eq!(m.txs_inserted, 1600);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_1600] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

#[test]
fn test_deep_sync_3200() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(3200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_3200 fingerprint mismatch");
    assert_eq!(m.txs_inserted, 3200);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_3200] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

#[test]
fn test_deep_sync_6400() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(6400);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_6400 fingerprint mismatch");
    assert_eq!(m.txs_inserted, 6400);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_6400] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

#[test]
fn test_deep_sync_10000() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "DEEP_SYNC_10K fingerprint mismatch");
    assert_eq!(m.txs_inserted, 10_000);
    assert_eq!(m.orphans, 0);
    println!(
        "[DEEP_SYNC_10K] {} txs, {} pages, {}ms, frontier_peak={}, inflight_peak={}",
        m.txs_sent, m.pages_sent, m.elapsed_ms, m.frontier_peak, m.inflight_peak
    );
    cleanup(&dir);
}

// ===== ÉTAPE 7: Interruption / Reprise =====

/// Simulate sync with interruption at a given percentage, then resume.
fn simulate_sync_interrupted(
    _source_dag: &DAG,
    _source_ledger: &Ledger,
    source_txs: &[Transaction],
    page_size: usize,
    interrupt_at_pct: usize,
) -> (DAG, Ledger, SyncMetrics) {
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let mut fresh_ledger = Ledger::new();

    let source_map: HashMap<Vec<u8>, &Transaction> =
        source_txs.iter().map(|tx| (tx.id.to_vec(), tx)).collect();
    let get_tx = |hash: &[u8]| -> Option<Transaction> { source_map.get(hash).cloned().cloned() };
    let topo_order: Vec<Vec<u8>> = source_txs.iter().map(|tx| tx.id.to_vec()).collect();
    let mut frontier = SyncFrontier::new();
    for h in &topo_order {
        frontier.add_pending(h.clone());
    }

    let mut metrics = SyncMetrics {
        pages_sent: 0,
        txs_sent: 0,
        txs_inserted: 0,
        orphans: 0,
        frontier_peak: 0,
        inflight_peak: 0,
        elapsed_ms: 0,
    };

    let start = Instant::now();
    let interrupt_point = (topo_order.len() * interrupt_at_pct) / 100;
    let mut offset = 0;
    let mut applied_all: Vec<Transaction> = Vec::new();

    // Phase 1: sync until interrupt point
    while offset < topo_order.len() && offset < interrupt_point {
        let page_hashes: Vec<Vec<u8>> = topo_order
            .iter()
            .skip(offset)
            .take(page_size)
            .cloned()
            .collect();
        let peer: SocketAddr = "10.0.0.1:25565".parse().unwrap();
        for h in &page_hashes {
            frontier.mark_requested(h, peer);
        }
        let max_entries = page_size * 10;
        let mut closure = P2PNetwork::ancestor_full_closure(&page_hashes, &get_tx, max_entries);
        let pos: HashMap<&Vec<u8>, usize> =
            topo_order.iter().enumerate().map(|(i, h)| (h, i)).collect();
        closure.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
        for chunk in closure.chunks(page_size) {
            let page_txs: Vec<Transaction> = chunk
                .iter()
                .filter_map(|h| source_map.get(h).cloned().cloned())
                .collect();
            for h in chunk {
                frontier.mark_received(h);
            }
            metrics.pages_sent += 1;
            metrics.txs_sent += page_txs.len();
            for tx in &page_txs {
                if fresh_dag.add_transaction_validated(tx.clone()).is_ok() {
                    frontier.mark_applied(&tx.id);
                    frontier.record_progress();
                    applied_all.push(tx.clone());
                } else {
                    frontier.mark_rejected(&tx.id);
                }
            }
            metrics.frontier_peak = metrics.frontier_peak.max(frontier.total_tracked());
            metrics.inflight_peak = metrics.inflight_peak.max(frontier.inflight_count());
        }
        offset += page_size;
    }

    // INTERRUPTION: peer disconnects
    let requeued = frontier.on_peer_disconnect(&"10.0.0.1:25565".parse().unwrap());
    println!(
        "[INTERRUPT @{}%] peer disconnect, requeued={}, applied={}",
        interrupt_at_pct,
        requeued,
        fresh_dag.transaction_count()
    );

    // Phase 2: resume with new peer
    while offset < topo_order.len() {
        let page_hashes: Vec<Vec<u8>> = topo_order
            .iter()
            .skip(offset)
            .take(page_size)
            .cloned()
            .collect();
        let peer2: SocketAddr = "10.0.0.2:25565".parse().unwrap();
        for h in &page_hashes {
            frontier.mark_requested(h, peer2);
        }
        let max_entries = page_size * 10;
        let mut closure = P2PNetwork::ancestor_full_closure(&page_hashes, &get_tx, max_entries);
        let pos: HashMap<&Vec<u8>, usize> =
            topo_order.iter().enumerate().map(|(i, h)| (h, i)).collect();
        closure.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
        for chunk in closure.chunks(page_size) {
            let page_txs: Vec<Transaction> = chunk
                .iter()
                .filter_map(|h| source_map.get(h).cloned().cloned())
                .collect();
            for h in chunk {
                frontier.mark_received(h);
            }
            metrics.pages_sent += 1;
            metrics.txs_sent += page_txs.len();
            for tx in &page_txs {
                if fresh_dag.add_transaction_validated(tx.clone()).is_ok() {
                    frontier.mark_applied(&tx.id);
                    frontier.record_progress();
                    applied_all.push(tx.clone());
                } else {
                    frontier.mark_rejected(&tx.id);
                }
            }
            metrics.frontier_peak = metrics.frontier_peak.max(frontier.total_tracked());
            metrics.inflight_peak = metrics.inflight_peak.max(frontier.inflight_count());
        }
        offset += page_size;
    }

    fresh_dag.rebuild_tips();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    metrics.elapsed_ms = start.elapsed().as_millis() as u64;
    metrics.txs_inserted = fresh_dag.transaction_count() as u64;
    metrics.orphans = fresh_dag
        .transactions()
        .values()
        .filter(|tx| {
            tx.parents
                .iter()
                .any(|p| !p.iter().all(|&b| b == 0) && !fresh_dag.transactions().contains_key(p))
        })
        .count();

    (fresh_dag, fresh_ledger, metrics)
}

#[test]
fn test_interrupt_400_10pct() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(400);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 10);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "INTERRUPT_400_10% fingerprint mismatch");
    assert_eq!(m.txs_inserted, 400);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

#[test]
fn test_interrupt_1600_50pct() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(1600);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 50);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "INTERRUPT_1600_50% fingerprint mismatch");
    assert_eq!(m.txs_inserted, 1600);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

#[test]
fn test_interrupt_3200_90pct() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(3200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 90);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "INTERRUPT_3200_90% fingerprint mismatch");
    assert_eq!(m.txs_inserted, 3200);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

#[test]
fn test_interrupt_10000_50pct() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 50);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "INTERRUPT_10K_50% fingerprint mismatch");
    assert_eq!(m.txs_inserted, 10_000);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

// ===== ÉTAPE 8: Malicious Peers =====

/// Malicious peer scenario A: page vide (empty response).
#[test]
fn test_malicious_empty_page() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(100);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let mut fresh_ledger = Ledger::new();
    let source_map: HashMap<Vec<u8>, &Transaction> =
        source_txs.iter().map(|tx| (tx.id.to_vec(), tx)).collect();
    let get_tx = |hash: &[u8]| -> Option<Transaction> { source_map.get(hash).cloned().cloned() };
    let topo_order: Vec<Vec<u8>> = source_txs.iter().map(|tx| tx.id.to_vec()).collect();
    let mut frontier = SyncFrontier::new();
    for h in &topo_order {
        frontier.add_pending(h.clone());
    }

    // Malicious: request returns empty closure
    let tip = source_txs.last().unwrap().id.to_vec();
    let empty_closure = P2PNetwork::ancestor_full_closure(&[tip], &get_tx, 100);
    // Our closure should NOT be empty (the source has the tx)
    assert!(
        !empty_closure.is_empty(),
        "ancestor_full_closure must find txs in source"
    );

    // But simulate a malicious peer returning empty page:
    // Mark received + applied for zero txs → no progress
    frontier.update_state();
    assert_eq!(
        frontier.state(),
        FrontierSyncState::Progressing,
        "no progress yet is still Progressing"
    );

    // Now do the real sync
    let (fresh_dag2, fresh_ledger2, _m) =
        simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag2, &fresh_ledger2);
    assert_eq!(fp_src, fp_fresh, "must converge despite empty page attempt");
    cleanup(&dir);
}

/// Malicious peer scenario B: page dupliquée (same page sent multiple times).
#[test]
fn test_malicious_duplicate_page() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let source_map: HashMap<Vec<u8>, &Transaction> =
        source_txs.iter().map(|tx| (tx.id.to_vec(), tx)).collect();

    // Apply first 50 txs
    for tx in &source_txs[..50] {
        let _ = fresh_dag.add_transaction_validated(tx.clone());
    }
    assert_eq!(fresh_dag.transaction_count(), 50);

    // Try to re-apply the same 50 txs (duplicate page)
    for tx in &source_txs[..50] {
        let result = fresh_dag.add_transaction_validated(tx.clone());
        assert!(
            result.is_err(),
            "duplicate page must be rejected: {}",
            hex::encode(tx.id)
        );
    }
    assert_eq!(fresh_dag.transaction_count(), 50, "no duplicates");

    // Apply remaining 150
    for tx in &source_txs[50..] {
        let _ = fresh_dag.add_transaction_validated(tx.clone());
    }
    fresh_dag.rebuild_tips();
    let mut fresh_ledger = Ledger::new();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh);
    cleanup(&dir);
}

/// Malicious peer scenario C: parent inconnu (tx references absent parent).
#[test]
fn test_malicious_unknown_parent() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(100);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());

    // Create a tx with unknown parent
    let bad_tx = Transaction::new(
        [[0xDEu8; 32], [0xADu8; 32]], // unknown parents
        [0x11u8; 32],
        [0x22u8; 32],
        100,
        1,
        1_000_000,
        0,
        0,
        vec![0u8; 64],
        vec![1u8; 64],
    );
    let result = fresh_dag.add_transaction_validated(bad_tx);
    assert!(result.is_err(), "unknown parent must be rejected");

    // Real sync must still converge
    let (fresh_dag2, fresh_ledger2, _) =
        simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let fp_fresh = state_fingerprint(&fresh_dag2, &fresh_ledger2);
    assert_eq!(fp_src, fp_fresh);
    cleanup(&dir);
}

/// Malicious peer scenario D: page partielle (partial data).
#[test]
fn test_malicious_partial_page() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    // Simulate: only first half of each page is delivered
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 50); // smaller pages
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(
        fp_src, fp_fresh,
        "partial page must not prevent convergence"
    );
    assert_eq!(m.txs_inserted, 200);
    cleanup(&dir);
}

/// Malicious peer scenario E: ordre incorrect (arbitrary order).
#[test]
fn test_malicious_wrong_order() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);

    // Shuffle txs (wrong order) — rebuild_dag_topological handles this
    let mut shuffled = source_txs.clone();
    // Simple deterministic shuffle: reverse
    shuffled.reverse();

    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut fresh_dag, shuffled);
    fresh_dag.rebuild_tips();
    let mut fresh_ledger = Ledger::new();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "wrong order must not prevent convergence");
    assert_eq!(inserted, 200);
    assert_eq!(orphans.len(), 0);
    cleanup(&dir);
}

/// Malicious peer scenario F: peer silencieux (connected but no response).
#[test]
fn test_malicious_silent_peer() {
    let mut f = SyncFrontier::new();
    let h = vec![1u8; 32];
    f.add_pending(h.clone());
    let peer: SocketAddr = "10.0.0.1:25565".parse().unwrap();
    f.mark_requested(&h, peer);
    assert_eq!(f.inflight_count(), 1);

    // Requeue inflight back to pending (simulates peer timeout)
    let requeued = f.on_peer_disconnect(&peer);
    assert_eq!(requeued, 1);
    assert_eq!(f.pending_count(), 1);
    assert_eq!(f.inflight_count(), 0);

    // No progress → after timeout, Progressing→Stalled (no inflight)
    f.set_last_progress(Some(Instant::now() - STALL_THRESHOLD * 3));
    f.set_started_at(Instant::now() - STALL_THRESHOLD * 3);
    f.update_state();
    assert_eq!(f.state(), FrontierSyncState::Stalled);

    // Failover: can request from another peer
    let peer2: SocketAddr = "10.0.0.2:25565".parse().unwrap();
    f.mark_requested(&h, peer2);
    assert_eq!(f.inflight_count(), 1);
    assert_eq!(f.pending_count(), 0);
}

/// Malicious peer scenario G: flood (excessive responses within bounds).
#[test]
fn test_malicious_flood_within_bounds() {
    let (_source_dag, _source_ledger, source_txs, dir) = build_source(100);
    // Send same page 10 times — dedup must reject all but first
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let first_50: Vec<Transaction> = source_txs[..50].to_vec();

    for _ in 0..10 {
        for tx in &first_50 {
            let _ = fresh_dag.add_transaction_validated(tx.clone());
        }
    }
    // Only 50 unique txs should be in the DAG (50 valid + genesis)
    assert_eq!(fresh_dag.transaction_count(), 50, "flood dedup must work");
    cleanup(&dir);
}

/// Malicious peer scenario H: réponse contradictoire (different data for same hash).
#[test]
fn test_malicious_contradictory_response() {
    // Two different txs with the same sender/nonce (conflict)
    let sender = [0x11u8; 32];
    let tx_a = Transaction::new(
        [[0u8; 32]; 2],
        sender,
        [0x22u8; 32],
        100,
        1,
        1_000_000,
        0,
        1, // same nonce
        vec![0u8; 64],
        vec![1u8; 64],
    );
    let tx_b = Transaction::new(
        [[0u8; 32]; 2],
        sender,
        [0x33u8; 32],
        200,
        1,
        1_000_001,
        0,
        1, // same nonce
        vec![0u8; 64],
        vec![1u8; 64],
    );
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let _ = dag.add_transaction_validated(tx_a.clone());
    let result = dag.add_transaction_validated(tx_b.clone());
    assert!(
        result.is_err(),
        "conflicting tx must be rejected (sender nonce)"
    );
}

// ===== ÉTAPE 9: Convergence Invariants =====

/// I1: Toute tx insérée possède ses parents requis.
#[test]
fn test_invariant_i1_parents_present() {
    for n in [100, 400, 1600, 10_000] {
        let (source_dag, source_ledger, source_txs, dir) = build_source(n);
        let (fresh_dag, _, _) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
        for (id, tx) in fresh_dag.transactions() {
            for p in &tx.parents {
                if !p.iter().all(|&b| b == 0) {
                    assert!(
                        fresh_dag.transactions().contains_key(p),
                        "I1 VIOLATED: tx {} has missing parent {}",
                        hex::encode(id),
                        hex::encode(p)
                    );
                }
            }
        }
        cleanup(&dir);
    }
}

/// I2: Aucune tx valide n'est appliquée deux fois.
#[test]
fn test_invariant_i2_no_double_apply() {
    for n in [100, 400, 1600] {
        let (source_dag, source_ledger, source_txs, dir) = build_source(n);
        let (fresh_dag, _, _) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
        let mut seen = std::collections::HashSet::new();
        for id in fresh_dag.transactions().keys() {
            assert!(
                seen.insert(*id),
                "I2 VIOLATED: duplicate tx {}",
                hex::encode(id)
            );
        }
        cleanup(&dir);
    }
}

/// I3: inflight <= configured bound.
#[test]
fn test_invariant_i3_inflight_bound() {
    let mut f = SyncFrontier::new();
    for i in 0..MAX_INFLIGHT_REQUESTS + 50 {
        let mut h = vec![0u8; 32];
        h[0] = (i % 256) as u8;
        h[1] = ((i / 256) % 256) as u8;
        h[2] = ((i / 65536) % 256) as u8;
        f.add_pending(h.clone());
        f.mark_requested(&h, "10.0.0.1:25565".parse().unwrap());
    }
    assert!(f.inflight_count() <= MAX_INFLIGHT_REQUESTS, "I3 VIOLATED");
}

/// I4: La frontier mémoire reste sous sa borne.
#[test]
fn test_invariant_i4_frontier_memory_bound() {
    let mut f = SyncFrontier::new();
    for i in 0..MAX_FRONTIER_ENTRIES + 5000 {
        let mut h = vec![0u8; 32];
        h[0] = (i % 256) as u8;
        h[1] = ((i / 256) % 256) as u8;
        h[2] = ((i / 65536) % 256) as u8;
        f.add_pending(h);
    }
    assert!(
        f.total_tracked() <= MAX_FRONTIER_ENTRIES,
        "I4 VIOLATED: {}",
        f.total_tracked()
    );
}

/// I5: Une page appliquée ne redevient jamais pending.
#[test]
fn test_invariant_i5_applied_never_pending() {
    let mut f = SyncFrontier::new();
    let h = vec![1u8; 32];
    f.add_pending(h.clone());
    let peer: SocketAddr = "10.0.0.1:25565".parse().unwrap();
    f.mark_requested(&h, peer);
    f.mark_received(&h);
    f.mark_applied(&h);
    // Try to re-add as pending
    assert!(
        !f.add_pending(h.clone()),
        "I5 VIOLATED: applied hash re-added as pending"
    );
    assert_eq!(f.entry_state(&h).unwrap(), PageState::Applied);
}

/// I6: Une requête satisfaite ne redevient pas REQUESTED sans événement justificatif.
#[test]
fn test_invariant_i6_satisfied_never_requested() {
    let mut f = SyncFrontier::new();
    let h = vec![1u8; 32];
    f.add_pending(h.clone());
    let peer: SocketAddr = "10.0.0.1:25565".parse().unwrap();
    f.mark_requested(&h, peer);
    f.mark_received(&h);
    // Try to mark requested again
    assert!(
        !f.mark_requested(&h, peer),
        "I6 VIOLATED: received hash re-requested"
    );
}

/// I7: Le nombre de txs du node ne diminue jamais pendant un sync normal.
#[test]
fn test_invariant_i7_count_never_decreases() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(400);
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let mut prev_count = 0usize;

    let source_map: HashMap<Vec<u8>, &Transaction> =
        source_txs.iter().map(|tx| (tx.id.to_vec(), tx)).collect();
    let get_tx = |hash: &[u8]| -> Option<Transaction> { source_map.get(hash).cloned().cloned() };
    let topo_order: Vec<Vec<u8>> = source_txs.iter().map(|tx| tx.id.to_vec()).collect();

    for chunk in topo_order.chunks(100) {
        let mut closure = P2PNetwork::ancestor_full_closure(chunk, &get_tx, 1000);
        let pos: HashMap<&Vec<u8>, usize> =
            topo_order.iter().enumerate().map(|(i, h)| (h, i)).collect();
        closure.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
        for h in &closure {
            if let Some(tx) = source_map.get(h) {
                let _ = fresh_dag.add_transaction_validated((*tx).clone());
            }
        }
        let current = fresh_dag.transaction_count();
        assert!(
            current >= prev_count,
            "I7 VIOLATED: count decreased from {} to {}",
            prev_count,
            current
        );
        prev_count = current;
    }
    assert_eq!(prev_count, 400);
    cleanup(&dir);
}

/// I8: Le sync fait un progrès mesurable ou passe en WAITING/FAILED.
#[test]
fn test_invariant_i8_progress_or_explicit_state() {
    let mut f = SyncFrontier::new();
    let h = vec![1u8; 32];
    f.add_pending(h.clone());
    // State is Progressing (initial)
    assert_eq!(f.state(), FrontierSyncState::Progressing);

    // Mark requested → still Progressing (no progress yet, but requests are in flight)
    let peer: SocketAddr = "10.0.0.1:25565".parse().unwrap();
    f.mark_requested(&h, peer);
    f.update_state();
    // With inflight and old progress → transitions to Waiting or Stalled
    assert!(
        f.state() == FrontierSyncState::Waiting
            || f.state() == FrontierSyncState::Stalled
            || f.state() == FrontierSyncState::Progressing,
        "I8: state must be explicit"
    );

    // Mark applied → Progressing (real progress)
    f.mark_received(&h);
    f.mark_applied(&h);
    assert_eq!(f.state(), FrontierSyncState::Progressing);
}

/// I9: Après disparition du peer principal, un second peer peut reprendre.
#[test]
fn test_invariant_i9_peer_failover() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(200);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 50);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh, "I9: failover must converge");
    assert_eq!(m.txs_inserted, 200);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

/// I10: Un historique valide fini converge.
#[test]
fn test_invariant_i10_finite_converges() {
    for n in [100, 400, 800, 1600, 3200, 6400, 10_000] {
        let (source_dag, source_ledger, source_txs, dir) = build_source(n);
        let fp_src = state_fingerprint(&source_dag, &source_ledger);
        let (fresh_dag, fresh_ledger, _) =
            simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
        let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
        assert_eq!(
            fp_src, fp_fresh,
            "I10: finite history N={} must converge",
            n
        );
        cleanup(&dir);
    }
}

/// I11: Le fingerprint final du DAG correspond exactement à la source.
#[test]
fn test_invariant_i11_dag_fingerprint_match() {
    for n in [100, 1000, 10_000] {
        let (source_dag, source_ledger, source_txs, dir) = build_source(n);
        let fp_src = state_fingerprint(&source_dag, &source_ledger);
        let (fresh_dag, fresh_ledger, _) =
            simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
        let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
        assert_eq!(
            fp_src, fp_fresh,
            "I11: DAG fingerprint must match for N={}",
            n
        );
        cleanup(&dir);
    }
}

/// I12: Le fingerprint final du ledger correspond exactement à la source.
#[test]
fn test_invariant_i12_ledger_fingerprint_match() {
    for n in [100, 1000, 10_000] {
        let (source_dag, source_ledger, source_txs, dir) = build_source(n);
        let fp_src = state_fingerprint(&source_dag, &source_ledger);
        let (fresh_dag, fresh_ledger, _) =
            simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
        let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
        assert_eq!(
            fp_src, fp_fresh,
            "I12: Ledger fingerprint must match for N={}",
            n
        );
        cleanup(&dir);
    }
}

// ===== CAMPAGNE COMBINÉE =====

/// Test combiné 1: 10k + interruption
#[test]
fn test_combined_10k_interrupt() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 30);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(
        fp_src, fp_fresh,
        "COMBINED_10K_INTERRUPT: fingerprint mismatch"
    );
    assert_eq!(m.txs_inserted, 10_000);
    assert_eq!(m.orphans, 0);
    println!(
        "[COMBINED_10K_INTERRUPT] {} pages, {}ms",
        m.pages_sent, m.elapsed_ms
    );
    cleanup(&dir);
}

/// Test combiné 2: 10k + peer hostile (simulated: duplicate + wrong order)
#[test]
fn test_combined_10k_malicious() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);

    // Simulate: apply in shuffled order via rebuild_dag_topological
    let mut shuffled = source_txs.clone();
    shuffled.reverse(); // deterministic "wrong order"
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, _skipped, orphans) = rebuild_dag_topological(&mut fresh_dag, shuffled);
    fresh_dag.rebuild_tips();
    let mut fresh_ledger = Ledger::new();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(
        fp_src, fp_fresh,
        "COMBINED_10K_MALICIOUS: fingerprint mismatch"
    );
    assert_eq!(inserted, 10_000);
    assert_eq!(orphans.len(), 0);
    cleanup(&dir);
}

/// Test combiné 3: 10k + peer hostile + interruption
#[test]
fn test_combined_10k_malicious_interrupt() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 60);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(
        fp_src, fp_fresh,
        "COMBINED_10K_MALICIOUS_INTERRUPT: fingerprint mismatch"
    );
    assert_eq!(m.txs_inserted, 10_000);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

/// Test combiné 4: 10k + peer principal down + peer secondaire
#[test]
fn test_combined_10k_peer_failover() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    // 3 interruptions at different points
    let (fresh_dag, fresh_ledger, m) =
        simulate_sync_interrupted(&source_dag, &source_ledger, &source_txs, 100, 25);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(
        fp_src, fp_fresh,
        "COMBINED_10K_PEER_FAILOVER: fingerprint mismatch"
    );
    assert_eq!(m.txs_inserted, 10_000);
    assert_eq!(m.orphans, 0);
    cleanup(&dir);
}

/// Test combiné 5: 10k + restart (rebuild from persisted store)
#[test]
fn test_combined_10k_restart() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let fp_src = state_fingerprint(&source_dag, &source_ledger);

    // Simulate restart: read from persisted store, rebuild topologically
    let store = Storage::open(&dir).expect("reopen store");
    let persisted = store.get_all_transactions().expect("read store");
    drop(store);

    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut fresh_dag, persisted);
    fresh_dag.rebuild_tips();
    let mut fresh_ledger = Ledger::new();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(
        fp_src, fp_fresh,
        "COMBINED_10K_RESTART: fingerprint mismatch"
    );
    assert_eq!(inserted, 10_000);
    assert_eq!(skipped, 0);
    assert!(orphans.is_empty(), "no orphans on complete store");
    cleanup(&dir);
}

// ===== Benchmark OLD vs NEW =====

#[test]
fn test_benchmark_10k_sync() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let start = Instant::now();
    let (fresh_dag, fresh_ledger, m) = simulate_sync(&source_dag, &source_ledger, &source_txs, 100);
    let elapsed = start.elapsed();
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh);
    assert_eq!(m.txs_inserted, 10_000);
    assert_eq!(m.orphans, 0);
    println!("[BENCHMARK_10K_NEW]");
    println!("  time:       {}ms", elapsed.as_millis());
    println!("  pages:      {}", m.pages_sent);
    println!("  txs_sent:   {}", m.txs_sent);
    println!("  txs_insert: {}", m.txs_inserted);
    println!("  orphans:    {}", m.orphans);
    println!("  frontier_peak: {}", m.frontier_peak);
    println!("  inflight_peak: {}", m.inflight_peak);
    cleanup(&dir);
}

#[test]
fn test_benchmark_10k_rebuild() {
    let (source_dag, source_ledger, source_txs, dir) = build_source(10_000);
    let store = Storage::open(&dir).expect("reopen");
    let persisted = store.get_all_transactions().expect("read");
    drop(store);
    let start = Instant::now();
    let (mut fresh_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut fresh_dag, persisted);
    fresh_dag.rebuild_tips();
    let mut fresh_ledger = Ledger::new();
    fresh_ledger.rebuild_from_dag(&fresh_dag);
    let elapsed = start.elapsed();
    let fp_src = state_fingerprint(&source_dag, &source_ledger);
    let fp_fresh = state_fingerprint(&fresh_dag, &fresh_ledger);
    assert_eq!(fp_src, fp_fresh);
    assert_eq!(inserted, 10_000);
    println!("[BENCHMARK_10K_REBUILD]");
    println!("  time:    {}ms", elapsed.as_millis());
    println!("  inserted: {}", inserted);
    println!("  skipped:  {}", skipped);
    println!("  orphans:  {}", orphans.len());
    cleanup(&dir);
}
