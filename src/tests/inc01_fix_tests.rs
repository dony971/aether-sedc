//! INC-01 fix tests: boot rebuild / ledger guard / crash recovery.
//!
//! These tests demonstrate the INC-01 mandate rule: "After any restart or
//! crash, a node can rebuild EXACTLY the same DAG and the same ledger from
//! its persisted data, without depending on a peer for what it already
//! possesses locally."
//!
//! - test_inc01_rebuild_10000_restores_exact_state: STORE=10000 -> REBUILD ->
//!   DAG = exactly 10000, and the full state (txset hash, DAG hash, tips,
//!   weights, ledger, balances, nonces, supply) is byte-identical.
//! - test_inc01_rebuild_truncated_store_counts_orphans: a crash-truncated
//!   store (incident numbers: 20 txs + 326 orphans) rebuilds into exactly
//!   those buckets with 0 silent drops, and the truncated DAG derives a
//!   HIGHER supply than the full persisted ledger (the boot guard keeps the
//!   persisted ledger — never overwrites it with a partial derivation).
//! - test_inc01_rebuild_truncated_no_orphans_derives_higher_supply: the
//!   incident's exact state — tree truncated to 20 with no orphans left —
//!   still derives a higher supply than the full ledger, so even a
//!   "complete-looking" store cannot destroy the persisted ledger.
//! - test_inc01_recovery_insert_ledger_ahead: a transaction whose effects
//!   are already in the ledger (crash: ledger ahead of the DAG) is inserted
//!   into the DAG WITHOUT replaying the ledger (no double-debit), healing
//!   the node back to the pre-crash state.

use crate::genesis::{initialize_genesis, GenesisConfig};
use crate::ledger::Ledger;
use crate::parent_selection::{rebuild_dag_topological, DAG};
use crate::storage::Storage;
use crate::transaction::Transaction;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Deterministic state fingerprint of a (DAG, ledger) pair: sorted tx ids,
/// sorted tip ids, sorted (id, weight) pairs, sorted balances, sorted
/// nonces, supply. Byte-identical across nodes/reboots for the same tx set.
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
    // Deterministic tip set: transactions with no children (what rebuild_tips()
    // computes). get_tips_with_selector() is NON-DETERMINISTIC (random walk)
    // and must never be used in a consensus fingerprint.
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

fn temp_store_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("aether-inc01-test-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Build N synthetic txs from the genesis faucet: a 22-wide ladder
/// (tx i parents = tx(i-1) for i<=22, then [tx(i-23), tx(i-22)]), unique
/// (sender, account_nonce) pairs, no PoW/signature (the boot rebuild does
/// not re-validate those — pure topological insert).
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

fn build_full_dag_and_ledger(n: u64) -> (DAG, Ledger, Vec<Transaction>) {
    let sender: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
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
    (dag, ledger, txs)
}

#[test]
fn test_inc01_rebuild_10000_restores_exact_state() {
    const N: u64 = 10_000;
    let (dag_a, ledger_a, txs) = build_full_dag_and_ledger(N);
    let fp_a = state_fingerprint(&dag_a, &ledger_a);
    assert_eq!(dag_a.transaction_count(), N as usize);
    assert!(
        ledger_a.total_supply() < crate::genesis::MAX_SUPPLY,
        "fees must have been burned"
    );

    // Persist the full store (Sled), flush, close, REOPEN (a real reboot).
    let dir = temp_store_dir("rebuild10000");
    let store = Storage::open(&dir).expect("open store");
    for tx in &txs {
        store.put_transaction(tx).expect("persist");
    }
    store.flush().expect("flush");
    drop(store);
    let store = Storage::open(&dir).expect("reopen store");

    // REBOOT: fresh DAG + fresh ledger, rebuild from the persisted store.
    let (mut dag_b, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let persisted = store.get_all_transactions().expect("read store");
    assert_eq!(persisted.len(), N as usize, "store must hold exactly N txs");
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut dag_b, persisted);
    dag_b.rebuild_tips();
    assert_eq!(inserted, N, "every persisted tx must be inserted");
    assert_eq!(skipped, 0, "no silent skips");
    assert!(orphans.is_empty(), "no orphans on a complete store");
    assert_eq!(dag_b.transaction_count(), N as usize);

    let mut ledger_b = Ledger::new();
    ledger_b.rebuild_from_dag(&dag_b);
    let fp_b = state_fingerprint(&dag_b, &ledger_b);
    assert_eq!(
        fp_a, fp_b,
        "reboot must restore EXACTLY the same txset/tips/weights/ledger/balances/nonces/supply"
    );
    cleanup(&dir);
}

#[test]
fn test_inc01_rebuild_truncated_store_counts_orphans() {
    // Incident numbers: 10004 built, only the first 20 survive + 326 orphans
    // whose parents are among the lost txs.
    let sender: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
        .expect("faucet addr")
        .try_into()
        .expect("32B");
    let all = build_ladder(sender, 10_004);
    let mut surviving: Vec<Transaction> = all[..20].to_vec();
    let mut orphan_ids: Vec<[u8; 32]> = Vec::new();
    for i in (2000..2326).step_by(1) {
        // Independent orphans: parents = lost txs (not in the surviving set),
        // unique sender -> no (sender, nonce) collision with the 20.
        let tx = Transaction::new(
            [all[i].id, all[i + 1].id],
            [0x55u8; 32],
            [0xAAu8; 32],
            100,
            1,
            2_000_000 + i as u64,
            i as u64,
            i as u64,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        orphan_ids.push(tx.id);
        surviving.push(tx);
    }
    assert_eq!(surviving.len(), 20 + 326);
    assert!(!orphan_ids.is_empty());

    // REBOOT with the truncated store.
    let (mut dag_b, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut dag_b, surviving.clone());
    dag_b.rebuild_tips();
    assert_eq!(inserted, 20, "only the resolvable prefix inserts");
    assert_eq!(skipped, 0, "no silent drops");
    assert_eq!(
        orphans.len(),
        326,
        "every unreachable tx reported as orphan"
    );

    // The truncated DAG derives a HIGHER supply than the full ledger (fewer
    // fees burned) — the boot guard's keep-condition.
    let (_, ledger_full, _) = build_full_dag_and_ledger(10_004);
    let mut ledger_partial = Ledger::new();
    ledger_partial.rebuild_from_dag(&dag_b);
    assert!(
        ledger_partial.total_supply() > ledger_full.total_supply(),
        "partial derivation must exceed the full persisted ledger supply ({} > {})",
        ledger_partial.total_supply(),
        ledger_full.total_supply()
    );
}

#[test]
fn test_inc01_rebuild_truncated_no_orphans_derives_higher_supply() {
    // The incident's exact trap: the tree is truncated to the first 20 txs
    // and NOTHING else survives (no orphan entries). The rebuild looks
    // complete (0 orphans, 0 skips) but derives a HIGHER supply than the
    // full persisted ledger — the guard must keep the persisted ledger.
    let sender: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
        .expect("faucet addr")
        .try_into()
        .expect("32B");
    let all = build_ladder(sender, 10_004);
    let surviving: Vec<Transaction> = all[..20].to_vec();

    let (_, ledger_full, _) = build_full_dag_and_ledger(10_004);
    let (mut dag_b, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut dag_b, surviving);
    dag_b.rebuild_tips();
    assert_eq!(inserted, 20);
    assert_eq!(skipped, 0);
    assert!(orphans.is_empty());

    let mut ledger_partial = Ledger::new();
    ledger_partial.rebuild_from_dag(&dag_b);
    assert!(
        ledger_partial.total_supply() > ledger_full.total_supply(),
        "complete-looking truncated store must NOT fool the guard ({} > {})",
        ledger_partial.total_supply(),
        ledger_full.total_supply()
    );
}

#[tokio::test]
async fn test_inc01_recovery_insert_ledger_ahead() {
    // Crash state: the DAG is truncated (the tx is NOT in the DAG) but the
    // ledger already contains its effects (nonce committed). The runtime
    // anti-replay would reject it; the recovery insert must heal the DAG
    // without replaying the ledger (no double-debit).
    let processor = crate::transaction_processor::TransactionProcessor::new();
    let dag = Arc::new(RwLock::new(DAG::new()));
    let ledger = Arc::new(RwLock::new(Ledger::new()));
    let mempool = Arc::new(RwLock::new(crate::rpc::Mempool::new(1000, 10)));

    // The two parent txs of the signed/mined helper tx, added to the DAG.
    // They must have distinct (sender, nonce) pairs — add_transaction_validated
    // rejects duplicates on (sender, account_nonce).
    let parent_tx = |sender: [u8; 32], nonce: u64| {
        Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [0x22u8; 32],
            10,
            1,
            1_234_000,
            0,
            nonce,
            vec![0u8; 64],
            vec![1u8; 64],
        )
    };
    let mut p1 = parent_tx([0x11u8; 32], 1);
    p1.id = [0xCAu8; 32];
    let mut p2 = parent_tx([0x12u8; 32], 1);
    p2.id = [0xFEu8; 32];
    dag.write().await.add_transaction_validated(p1).expect("p1");
    dag.write().await.add_transaction_validated(p2).expect("p2");

    // The helper tx: valid PoW + signature, account_nonce 1, parents above.
    let tx = crate::tests::signed_mined_orphan_tx();
    let sender = tx.sender;
    // The ledger is AHEAD: the effects are already applied (nonce 1
    // committed, sender debited).
    {
        let mut l = ledger.write().await;
        l.set_balance(&sender, 10_000);
        l.commit_nonce(&sender, 1);
    }

    let result = processor
        .process(tx.clone(), &dag, &ledger, &mempool, 1000)
        .await;
    assert!(result.is_ok(), "recovery insert must succeed: {:?}", result);

    // The tx is in the DAG...
    assert!(dag.read().await.transactions().contains_key(&tx.id));
    // ...but the ledger was NOT replayed: no double-debit, nonce unchanged.
    let l = ledger.read().await;
    assert_eq!(l.get_balance(&sender), 10_000, "no double-debit");
    assert_eq!(l.get_nonce(&sender), 1, "nonce unchanged");
    drop(l);

    // Idempotence: a second delivery is a no-op (duplicate in DAG).
    let again = processor
        .process(tx.clone(), &dag, &ledger, &mempool, 1000)
        .await;
    assert!(again.is_err(), "duplicate must be rejected");
    assert_eq!(dag.read().await.transaction_count(), 3);
}
