//! PHASE 4BZ: restart-rebuild regression tests (INC-01 liveness).
//!
//! Faithful to the boot sequence in `src/node.rs`: persist to Sled,
//! FULL close (drop every handle), reopen from the same directory,
//! rebuild via `rebuild_dag_topological` on a fresh genesis DAG,
//! rebuild tips (frontier), rebuild the ledger exactly like boot
//! (`rebuild_from_dag_v6` with the loaded registry, as node.rs does),
//! then resume. Covers what the inc01 unit tests do NOT: orphan
//! round-trip through a REAL close/reopen boundary, repeated-restart
//! fingerprint stability, and termination under a real watchdog.
//!
//! Watchdog design (deliberate): the rebuild call is synchronous CPU
//! work on local data, so a scoped thread + channel join with a timeout
//! IS an effective non-termination detector here -- unlike wrapping an
//! async op in a bare delay, which the 4BZ brief rightly rejects.
//! A timeout fails the test loudly; it never masks a hang as a pass.

use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::inventory::walk_release_root;
use aether_unified::ledger::Ledger;
use aether_unified::parent_selection::{rebuild_dag_topological, DAG};
use aether_unified::stake::{current_epoch, StakeRegistry};
use aether_unified::storage::Storage;
use aether_unified::transaction::Transaction;
use std::path::{Path, PathBuf};
use std::time::Duration;

const WATCHDOG_SECS: u64 = 120;

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aether-4bz-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// Small deterministic ladder (mirrors inc01 fixtures, fewer txs for speed).
fn build_ladder(sender: [u8; 32], n: u64, t0: u64) -> Vec<Transaction> {
    let mut txs: Vec<Transaction> = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let parents = if i == 1 {
            [[0u8; 32], [0u8; 32]]
        } else {
            [txs[(i - 2) as usize].id, [0u8; 32]]
        };
        txs.push(Transaction::new(
            parents, sender, [0xAAu8; 32], 1000, 1, t0 + i, i, i,
            vec![0u8; 64], vec![1u8; 64],
        ));
    }
    txs
}

fn faucet() -> [u8; 32] {
    hex::decode(aether_unified::genesis::FAUCET_ADDRESS)
        .expect("faucet addr")
        .try_into()
        .expect("32B")
}

/// Full state fingerprint: txset + frontier (tips) + weights + balances +
/// nonces + supply. Byte-stable across reboots for the same tx set.
fn fingerprint(dag: &DAG, ledger: &Ledger) -> String {
    let mut ids: Vec<[u8; 32]> = dag.transactions().keys().copied().collect();
    ids.sort();
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
        "n={} tips={:?} balances={:?} nonces={:?} supply={}",
        ids.len(),
        tips,
        balances,
        nonces,
        ledger.total_supply()
    )
}

/// Ledger rebuild exactly like boot: v6 path with the loaded registry.
/// Empty registry + pre-V6 DAG decides bit-identically to legacy.
fn rebuild_ledger_like_boot(dag: &DAG) -> Ledger {
    let reg = StakeRegistry::new();
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag_v6(dag, &reg, current_epoch());
    ledger
}

/// Rebuild under a real watchdog: fails closed on non-termination.
/// Sound here because the rebuild is synchronous CPU work on local data.
fn rebuild_watched(dag: &mut DAG, txs: Vec<Transaction>) -> (u64, u64, Vec<Transaction>) {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|s| {
        // Scoped borrow: the rebuild runs on the caller's DAG directly;
        // the channel carries the result back across the join boundary.
        s.spawn(|| {
            let _ = done_tx.send(rebuild_dag_topological(dag, txs));
        });
        match done_rx.recv_timeout(Duration::from_secs(WATCHDOG_SECS)) {
            Ok(r) => r,
            Err(_) => panic!(
                "WATCHDOG: rebuild_dag_topological did not terminate within {}s",
                WATCHDOG_SECS
            ),
        }
    })
}

fn boot_like_rebuild(store_dir: &Path) -> (DAG, Ledger, Vec<Transaction>, Vec<Transaction>) {
    // Mirrors node.rs boot: read persisted txs + orphans (dedup), rebuild
    // into a FRESH genesis DAG, rebuild tips, rebuild ledger like boot.
    let store = Storage::open(store_dir).expect("reopen store");
    let mut all = store.get_all_transactions().expect("read txs");
    for orphan in store.get_all_orphans().expect("read orphans") {
        if !all.iter().any(|tx| tx.id == orphan.id) {
            all.push(orphan);
        }
    }
    drop(store);
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut dag, all.clone());
    assert_eq!(skipped, 0, "no silent skips on a healthy store");
    dag.rebuild_tips();
    let ledger = rebuild_ledger_like_boot(&dag);
    let _ = inserted;
    (dag, ledger, all, orphans)
}

// 1. Orphans survive a REAL close/reopen, are re-reported (never dropped),
//    then resolve when their parents arrive: resume works.
#[test]
fn zb01_restart_orphans_survive_and_resolve() {
    let dir = unique_dir("orphan-restart");
    let sender = faucet();
    let txs = build_ladder(sender, 60, 1_000_000);
    // Withhold the last 5 as missing parents; orphans point at them.
    let (present, missing) = txs.split_at(55);
    let mut orphans = Vec::new();
    for (k, m) in missing.iter().enumerate() {
        orphans.push(Transaction::new(
            [m.id, [0u8; 32]], [0x55u8; 32], [0xAAu8; 32], 100, 1,
            2_000_000 + k as u64, 100 + k as u64, 100 + k as u64,
            vec![0u8; 64], vec![1u8; 64],
        ));
    }
    // Persist txs + orphans, flush, FULL close (drop everything).
    {
        let store = Storage::open(&dir).expect("open store");
        for tx in present {
            store.put_transaction(tx).expect("persist tx");
        }
        for o in &orphans {
            store.put_orphan(o.id, o).expect("persist orphan");
        }
        store.flush().expect("flush");
    }
    // REBOOT 1: orphans must be re-reported, present txs inserted.
    let (dag1, _l1, _all1, orphans1) = boot_like_rebuild(&dir);
    assert_eq!(dag1.transaction_count(), 55, "present txs rebuild");
    assert_eq!(orphans1.len(), orphans.len(), "orphans re-reported, never dropped");
    // Parents arrive (pushed by sync later): persist them, reboot again.
    // The orphan entries themselves stay in the store across the reboot
    // (boot never deletes; the runtime drainer removes them on success,
    // TTL purges them otherwise) -- the test mirrors that exactly.
    {
        let store = Storage::open(&dir).expect("reopen store");
        for m in missing {
            store.put_transaction(m).expect("persist parent");
        }
        store.flush().expect("flush");
    }
    // REBOOT 2: everything resolves, frontier/ledger match a direct build.
    let (dag2, ledger2, _all2, orphans2) = boot_like_rebuild(&dir);
    assert!(orphans2.is_empty(), "all orphans resolved after parents arrive");
    assert_eq!(dag2.transaction_count(), 60 + orphans.len());
    let (mut ref_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let mut ref_txs = txs.clone();
    ref_txs.extend(orphans.iter().cloned());
    let (ins, sk, orph) = rebuild_dag_topological(&mut ref_dag, ref_txs);
    assert_eq!(sk, 0);
    assert!(orph.is_empty());
    ref_dag.rebuild_tips();
    let ref_ledger = rebuild_ledger_like_boot(&ref_dag);
    assert_eq!(ins as usize, dag2.transaction_count());
    assert_eq!(
        fingerprint(&dag2, &ledger2),
        fingerprint(&ref_dag, &ref_ledger),
        "rebooted state identical to direct build (identities, relations, frontier, ledger)"
    );
    // Heal cycle complete: the runtime drainer removes store orphans on
    // success (rpc.rs success arm); replicate that and prove the store is
    // clean afterwards -- no stale entries survive a healed reboot.
    {
        let store = Storage::open(&dir).expect("reopen store");
        for o in &orphans {
            store.remove_orphan(o.id).expect("drainer removes on success");
        }
        store.flush().expect("flush");
        drop(store);
        let store = Storage::open(&dir).expect("reopen store");
        assert!(
            store.get_all_orphans().expect("read orphans").is_empty(),
            "no stale orphan entries after healing"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// 2. Repeated restarts keep a byte-stable fingerprint (no drift).
#[test]
fn zb02_repeated_restarts_stable() {
    let dir = unique_dir("repeat-restart");
    let txs = build_ladder(faucet(), 150, 3_000_000);
    {
        let store = Storage::open(&dir).expect("open");
        for tx in &txs {
            store.put_transaction(tx).expect("persist");
        }
        store.flush().expect("flush");
    }
    let mut fps = Vec::new();
    for cycle in 0..3 {
        let (dag, ledger, _all, orphans) = boot_like_rebuild(&dir);
        assert!(orphans.is_empty(), "cycle {}: no orphans on healthy store", cycle);
        assert_eq!(dag.transaction_count(), 150, "cycle {}: full DAG", cycle);
        fps.push(fingerprint(&dag, &ledger));
        // Full close between cycles (drop everything; reopen next loop).
        let store = Storage::open(&dir).expect("reopen");
        drop(store);
    }
    assert_eq!(fps[0], fps[1]);
    assert_eq!(fps[1], fps[2], "three restarts, one fingerprint");
    let _ = std::fs::remove_dir_all(&dir);
}

// 3. Rebuild terminates under a real watchdog (order-independent).
#[test]
fn zb03_rebuild_terminates_watched() {
    let txs = build_ladder(faucet(), 300, 4_000_000);
    let (mut dag_a, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (ins_a, sk_a, orph_a) = rebuild_watched(&mut dag_a, txs.clone());
    assert_eq!(ins_a, 300);
    assert_eq!(sk_a, 0);
    assert!(orph_a.is_empty());
    dag_a.rebuild_tips();
    // Reversed arrival order terminates identically (fixpoint, not order).
    let mut rev = txs.clone();
    rev.reverse();
    let (mut dag_b, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (ins_b, _sk_b, orph_b) = rebuild_watched(&mut dag_b, rev);
    assert_eq!(ins_b, 300);
    assert!(orph_b.is_empty());
    dag_b.rebuild_tips();
    let la = rebuild_ledger_like_boot(&dag_a);
    let lb = rebuild_ledger_like_boot(&dag_b);
    assert_eq!(fingerprint(&dag_a, &la), fingerprint(&dag_b, &lb));
}

// 4. Partial store after close/reopen: guard inputs reproduced at the
//    primitive level (derived supply from partial DAG exceeds the full
//    persisted ledger supply, so boot must KEEP the persisted ledger).
#[test]
fn zb04_partial_store_guard_inputs() {
    let dir = unique_dir("partial-guard");
    let txs = build_ladder(faucet(), 200, 5_000_000);
    {
        let store = Storage::open(&dir).expect("open");
        for tx in &txs {
            store.put_transaction(tx).expect("persist");
        }
        store.flush().expect("flush");
    }
    // Simulate crash-truncation INSIDE the store: reopen and delete the tail.
    {
        let store = Storage::open(&dir).expect("reopen");
        for tx in txs.iter().skip(20) {
            store.delete_transaction(tx.id).expect("truncate");
        }
        store.flush().expect("flush");
    }
    // Reboot sees 20 txs, 0 orphans, 0 skips -- the incident trap.
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let store = Storage::open(&dir).expect("reopen2");
    let persisted = store.get_all_transactions().expect("read");
    drop(store);
    assert_eq!(persisted.len(), 20);
    let (ins, sk, orph) = rebuild_dag_topological(&mut dag, persisted);
    assert_eq!((ins, sk), (20, 0));
    assert!(orph.is_empty());
    dag.rebuild_tips();
    let partial = rebuild_ledger_like_boot(&dag);
    let (mut full_dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (fi, _fsk, _fo) = rebuild_dag_topological(&mut full_dag, txs);
    assert_eq!(fi, 200);
    let full = rebuild_ledger_like_boot(&full_dag);
    assert!(
        partial.total_supply() > full.total_supply(),
        "guard input reproduced: partial {} > full {}",
        partial.total_supply(),
        full.total_supply()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// 5. Inventory digit stability is orthogonal: canonical digest of the
//    release tree is unaffected by DAG work (contract 4AQ witness).
#[test]
fn zb05_inventory_untouched_by_restart_work() {
    let root = unique_dir("inventory-orthogonal");
    std::fs::write(root.join("pkg.bin"), b"release-bytes").expect("write");
    let before = walk_release_root(&root, &[], None).expect("walk");
    let d1 = aether_unified::inventory::inventory_digest(&before.entries);
    // Heavy DAG+ledger churn beside the inventory must not move its digest.
    let txs = build_ladder(faucet(), 100, 6_000_000);
    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let _ = rebuild_dag_topological(&mut dag, txs);
    let after = walk_release_root(&root, &[], None).expect("walk");
    assert_eq!(aether_unified::inventory::inventory_digest(&after.entries), d1);
    let _ = std::fs::remove_dir_all(&root);
}
