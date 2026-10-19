//! PHASE 4CP-AX — DAG consensus selection robustness: activation boundary,
//! incremental-vs-rebuilt weights, multi-candidate conflicts and permutation
//! convergence. Legacy CDW path only (V6 is dormant; `ACTIVATION_ALLOWED=NO`
//! untouched). No production configuration is changed and no 24-bit PoW is
//! mined: `add_transaction_validated` is the real DAG admission path and it
//! never validates work, so all fixtures are fast, deterministic and derived
//! from the exact predicates in the code.
//!
//! Contract verified here (parent_selection.rs):
//! - `resolve_conflict_key` grandfathers a key ONLY when EVERY resident
//!   member has `timestamp < Transaction::CDW_ACTIVATION_TS` (strict): the
//!   min-id member wins and later work cannot change it.
//! - Otherwise (any member at/after the constant, including exactly at it)
//!   the max subtree WORK wins, min-id on exact ties. Subtree work =
//!   SUM of `work_credit()` over the UNIQUE descendant closure (self
//!   included), recomputed fresh on every call from stored fields.
//! - `tx.weight` is a DIFFERENT quantity: the incrementally maintained
//!   subtree SIZE used by parent-selection weighting. Conflict resolution
//!   never reads it. Both are checked here against test-local independent
//!   references (explicit bit walk, closure built from `tx.parents`), never
//!   against the implementation's own helpers.
//! - Losing candidates stay resident but never receive economic effects;
//!   a child of a retained loser still applies (parent is "handled").

use crate::ledger::Ledger;
use crate::parent_selection::{rebuild_dag_topological, DAG};
use crate::storage::Storage;
use crate::transaction::{Transaction, TransactionId};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

fn ts_pre() -> u64 {
    Transaction::CDW_ACTIVATION_TS - 3_600_000
}

fn ts_below() -> u64 {
    Transaction::CDW_ACTIVATION_TS - 1
}

fn ts_at() -> u64 {
    Transaction::CDW_ACTIVATION_TS
}

fn ts_after() -> u64 {
    Transaction::CDW_ACTIVATION_TS + 1
}

fn ts_post() -> u64 {
    Transaction::CDW_ACTIVATION_TS + 3_600_000
}

fn shaped(
    parents: [TransactionId; 2],
    sender: [u8; 32],
    receiver: [u8; 32],
    amount: u64,
    fee: u64,
    timestamp: u64,
    pow_nonce: u64,
    account_nonce: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        sender,
        receiver,
        amount,
        fee,
        timestamp,
        pow_nonce,
        account_nonce,
        vec![0u8; 64],
        vec![0u8; 32],
    );
    tx.id = tx.compute_hash();
    tx
}

fn seed_receiver(tag: u8, i: u64) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[0] = tag;
    r[1..9].copy_from_slice(&i.to_le_bytes());
    r
}

fn faucet() -> [u8; 32] {
    hex::decode(crate::genesis::FAUCET_ADDRESS)
        .expect("faucet hex")
        .try_into()
        .expect("32B")
}

fn fund_dag(dag: &mut DAG, receivers: &[([u8; 32], u64)]) {
    let f = faucet();
    for (i, (receiver, amount)) in receivers.iter().enumerate() {
        let tx = shaped(
            [[0u8; 32]; 2],
            f,
            *receiver,
            *amount,
            100,
            ts_pre(),
            0,
            i as u64,
        );
        dag.add_transaction_validated(tx).expect("funding inserts");
    }
}

fn short(id: &TransactionId) -> String {
    format!("{:02x?}", &id[..4])
}

// ---------------------------------------------------------------------------
// Independent references (deliberately NOT the implementation's helpers).
// ---------------------------------------------------------------------------

/// Leading zero bits by explicit bit tests (no `u8::leading_zeros`).
fn ref_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    'bytes: for b in hash.iter() {
        for bit in 0..8u32 {
            if b & (0x80u8 >> bit) == 0 {
                n += 1;
            } else {
                break 'bytes;
            }
        }
    }
    n
}

/// Credit = 2^bits, saturating at u64::MAX (checked shifts, no wrap).
fn ref_credit(hash: &[u8; 32]) -> u64 {
    let bits = ref_leading_zero_bits(hash);
    if bits >= 64 {
        u64::MAX
    } else {
        1u64 << bits
    }
}

fn ref_tx_credit(tx: &Transaction) -> u64 {
    ref_credit(&tx.calculate_pow_hash(tx.nonce))
}

fn snapshot(dag: &DAG) -> HashMap<TransactionId, Transaction> {
    dag.transactions().clone()
}

/// Children adjacency built from `Transaction.parents` (never `dag.children`).
fn ref_closure(
    txs: &HashMap<TransactionId, Transaction>,
    root: TransactionId,
) -> HashSet<TransactionId> {
    let mut children: HashMap<TransactionId, Vec<TransactionId>> = HashMap::new();
    for (id, tx) in txs {
        for p in &tx.parents {
            if !p.iter().all(|&b| b == 0) {
                children.entry(*p).or_default().push(*id);
            }
        }
    }
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(cs) = children.get(&id) {
            stack.extend(cs.iter().copied());
        }
    }
    seen
}

fn ref_subtree_work(txs: &HashMap<TransactionId, Transaction>, root: TransactionId) -> u64 {
    ref_closure(txs, root)
        .into_iter()
        .filter_map(|id| txs.get(&id))
        .fold(0u64, |acc, tx| acc.saturating_add(ref_tx_credit(tx)))
}

/// Subtree SIZE expected by `tx.weight` (present nodes only; root included).
fn ref_subtree_size(txs: &HashMap<TransactionId, Transaction>, root: TransactionId) -> f64 {
    ref_closure(txs, root)
        .into_iter()
        .filter(|id| txs.contains_key(id))
        .count() as f64
}

/// Post-activation rule alone: max subtree work, min-id on exact ties.
fn ref_max_work_winner(
    txs: &HashMap<TransactionId, Transaction>,
    members: &[TransactionId],
) -> TransactionId {
    *members
        .iter()
        .min_by(|a, b| {
            let wa = ref_subtree_work(txs, **a);
            let wb = ref_subtree_work(txs, **b);
            wb.cmp(&wa).then_with(|| a.cmp(b))
        })
        .expect("members present")
}

/// Full independent reference of `resolve_conflict_key`: min-id while ALL
/// members are pre-activation (`timestamp < CDW_ACTIVATION_TS`, strict;
/// missing member counts as pre), otherwise max subtree work with min-id
/// tiebreak.
fn ref_winner(
    txs: &HashMap<TransactionId, Transaction>,
    members: &[TransactionId],
) -> TransactionId {
    let pre = members.iter().all(|id| {
        txs.get(id)
            .map(|t| t.timestamp < Transaction::CDW_ACTIVATION_TS)
            .unwrap_or(true)
    });
    if pre {
        *members.iter().min().expect("members present")
    } else {
        ref_max_work_winner(txs, members)
    }
}

fn assert_weights_match_ref(dag: &DAG, stage: &str) {
    let txs = snapshot(dag);
    for (id, tx) in &txs {
        assert_eq!(
            tx.weight,
            ref_subtree_size(&txs, *id),
            "{stage}: incremental weight != independent subtree size for {}",
            short(id)
        );
    }
}

fn assert_work_matches_ref(dag: &DAG, stage: &str) {
    let txs = snapshot(dag);
    for id in txs.keys() {
        assert_eq!(
            dag.subtree_work(*id),
            ref_subtree_work(&txs, *id),
            "{stage}: impl subtree_work != independent closure work for {}",
            short(id)
        );
    }
}

fn assert_winner_matches_ref(dag: &DAG, sender: [u8; 32], key_nonce: u64, stage: &str) {
    let members = dag.find_sender_nonce_conflicts(&sender, key_nonce);
    assert!(members.len() >= 2, "{stage}: expected a conflict group");
    let txs = snapshot(dag);
    let expect = ref_winner(&txs, &members);
    let got = dag
        .resolve_conflict_key(&sender, key_nonce)
        .expect("group resolves");
    assert_eq!(
        got,
        expect,
        "{stage}: implementation winner differs from independent reference \
         (members {:?})",
        members.iter().map(short).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Candidate fixtures (deterministic nonce grinding; no 20/24-bit mining).
// ---------------------------------------------------------------------------

fn cand_bits_ge(
    sender: [u8; 32],
    tag: u8,
    ts: u64,
    account_nonce: u64,
    min_bits: u32,
) -> Transaction {
    for nonce in 0..500_000u64 {
        let tx = shaped(
            [[0u8; 32]; 2],
            sender,
            seed_receiver(tag, nonce),
            100,
            10,
            ts,
            nonce,
            account_nonce,
        );
        if ref_leading_zero_bits(&tx.calculate_pow_hash(nonce)) >= min_bits {
            return tx;
        }
    }
    panic!("no candidate with >= {} bits", min_bits);
}

fn cand_bits_lt(
    sender: [u8; 32],
    tag: u8,
    ts: u64,
    account_nonce: u64,
    max_bits: u32,
) -> Transaction {
    for nonce in 0..4096u64 {
        let tx = shaped(
            [[0u8; 32]; 2],
            sender,
            seed_receiver(tag, nonce),
            100,
            10,
            ts,
            nonce,
            account_nonce,
        );
        if ref_leading_zero_bits(&tx.calculate_pow_hash(nonce)) < max_bits {
            return tx;
        }
    }
    panic!("no candidate with < {} bits", max_bits);
}

/// Three candidates for one key with strictly increasing work
/// (low < mid < high), guaranteed non-vacuous: the max-work member is NOT
/// the min-id member, so the pre/post rules MUST disagree.
fn divergent_three(sender: [u8; 32], ts: u64, account_nonce: u64) -> Vec<Transaction> {
    for attempt in 0..64u8 {
        let low = cand_bits_lt(sender, 0x10 + attempt, ts, account_nonce, 2);
        let mid = cand_bits_ge(sender, 0x30 + attempt, ts, account_nonce, 8);
        let high = cand_bits_ge(sender, 0x50 + attempt, ts, account_nonce, 12);
        let mut group = vec![low, mid, high];
        let txs: HashMap<TransactionId, Transaction> =
            group.iter().map(|t| (t.id, t.clone())).collect();
        let members: Vec<TransactionId> = group.iter().map(|t| t.id).collect();
        let by_work = ref_max_work_winner(&txs, &members);
        let min_id = *members.iter().min().unwrap();
        let low_credit = ref_tx_credit(&group[0]);
        if by_work != min_id && ref_tx_credit(&group[2]) > low_credit {
            group.sort_by_key(|t| t.id);
            return group;
        }
    }
    panic!("could not build a divergent 3-candidate fixture");
}

/// Two candidates with EQUAL work (same leading-zero-bit count, at least
/// `min_bits`) and distinct ids, plus the observed bit count.
fn tied_pair(
    sender: [u8; 32],
    ts: u64,
    account_nonce: u64,
    min_bits: u32,
) -> (Transaction, Transaction, u32) {
    let mut seen: HashMap<u32, Transaction> = HashMap::new();
    for nonce in 0..4096u64 {
        let tx = shaped(
            [[0u8; 32]; 2],
            sender,
            seed_receiver(0x70, nonce),
            100,
            10,
            ts,
            nonce,
            account_nonce,
        );
        let bits = ref_leading_zero_bits(&tx.calculate_pow_hash(nonce));
        if bits < min_bits {
            continue;
        }
        if let Some(prev) = seen.get(&bits) {
            if prev.id != tx.id {
                return (prev.clone(), tx, bits);
            }
        } else {
            seen.insert(bits, tx);
        }
    }
    panic!("no tied pair within bound");
}

fn heavy_child(
    parent: TransactionId,
    sender: [u8; 32],
    tag: u8,
    ts: u64,
    account_nonce: u64,
) -> Transaction {
    for nonce in 0..500_000u64 {
        let tx = shaped(
            [parent, [0u8; 32]],
            sender,
            seed_receiver(tag, nonce),
            10,
            1,
            ts,
            nonce,
            account_nonce,
        );
        if ref_leading_zero_bits(&tx.calculate_pow_hash(nonce)) >= 10 {
            return tx;
        }
    }
    panic!("no heavy child");
}

// ---------------------------------------------------------------------------
// Persistence helpers.
// ---------------------------------------------------------------------------

fn open_with_retry(path: &Path) -> Storage {
    let mut last = None;
    for _ in 0..40 {
        match Storage::open(path) {
            Ok(s) => return s,
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    panic!("storage reopen failed: {:?}", last);
}

fn ledger_fp(ledger: &Ledger) -> String {
    let mut balances: Vec<(String, u64)> = ledger
        .balances
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    balances.sort();
    let mut nonces: Vec<(String, u64)> =
        ledger.nonces.iter().map(|(k, v)| (k.clone(), *v)).collect();
    nonces.sort();
    let mut applied: Vec<String> = ledger.applied.iter().map(short).collect();
    applied.sort();
    format!(
        "supply={} burned={} balances={:?} nonces={:?} applied=[{}]",
        ledger.total_supply(),
        ledger.total_fees_burned,
        balances,
        nonces,
        applied.join(",")
    )
}

/// Persist the exact set, reopen from Sled, rebuild with a deterministic
/// input order (`descending` = id-sorted forward or reversed; both are
/// worst-case for naive order dependence), and return the reconstructed DAG
/// + derived ledger. The store handle is dropped before the tempdir goes out
/// of scope by the caller.
fn persist_and_rebuild(txs: &[Transaction], path: &Path, descending: bool) -> (DAG, Ledger) {
    {
        let store = Storage::open(path).expect("open store");
        for tx in txs {
            store.put_transaction(tx).expect("persist tx");
        }
        store.flush().expect("flush");
    }
    let store = open_with_retry(path);
    let mut all = store.get_all_transactions().expect("read txs");
    drop(store);
    all.sort_by_key(|t| t.id);
    if descending {
        all.reverse();
    }
    let mut dag = DAG::new();
    let (inserted, skipped, orphans) = rebuild_dag_topological(&mut dag, all);
    assert_eq!(inserted as usize, txs.len(), "all persisted txs rebuilt");
    assert_eq!(skipped, 0, "no silent skips at boot");
    assert!(orphans.is_empty(), "no orphans in a closed set");
    dag.rebuild_tips();
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    (dag, ledger)
}

// ---------------------------------------------------------------------------
// ax01 — activation boundary and timestamp extremes.
// ---------------------------------------------------------------------------

#[test]
fn ax01_activation_boundary_below_at_after_and_extremes() {
    let sender = [0xA1u8; 32];

    // All strictly below: min-id wins even though another member has far
    // more work (grandfathering is frozen).
    let pre_group = divergent_three(sender, ts_below() - 10_000, 21);
    let mut dag = DAG::new();
    for tx in &pre_group {
        dag.add_transaction_validated(tx.clone()).unwrap();
    }
    let min_id = pre_group.iter().map(|t| t.id).min().expect("members");
    let txs = snapshot(&dag);
    let by_work = ref_max_work_winner(&txs, &dag.find_sender_nonce_conflicts(&sender, 21));
    assert_ne!(
        by_work, min_id,
        "fixture: work rule must differ from min-id"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 21),
        Some(min_id),
        "all members strictly below the constant => frozen min-id"
    );
    assert_winner_matches_ref(&dag, sender, 21, "ax01 pre");

    // Exactly below (CDW-1) and exactly at (CDW) in the SAME key: the
    // boundary member is at/after -> whole group resolves by work.
    // Grind until below.id < at.id so min-id (the pre rule) differs from the
    // heavier `at` member: this makes both "min-work pick" and "<= boundary"
    // regressions deterministically observable.
    let (below, at) = {
        let mut found = None;
        for attempt in 0..64u8 {
            let b = cand_bits_lt(sender, 0x90 + attempt, ts_below(), 22, 2);
            let a = cand_bits_ge(sender, 0xA0 + attempt, ts_at(), 22, 12);
            if b.id < a.id {
                found = Some((b, a));
                break;
            }
        }
        found.expect("boundary pair with below.id < at.id")
    };
    let mut dag = DAG::new();
    dag.add_transaction_validated(below.clone()).unwrap();
    dag.add_transaction_validated(at.clone()).unwrap();
    let txs = snapshot(&dag);
    assert!(
        ref_tx_credit(&at) > ref_tx_credit(&below),
        "fixture: boundary member heavier"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 22),
        Some(at.id),
        "timestamp == CDW_ACTIVATION_TS is post-activation (strict <)"
    );
    assert_winner_matches_ref(&dag, sender, 22, "ax01 at-boundary");

    // Just after the boundary (CDW+1) also resolves by work (same idiom).
    let (light, after) = {
        let mut found = None;
        for attempt in 0..64u8 {
            let l = cand_bits_lt(sender, 0xB0 + attempt, ts_after(), 23, 2);
            let a = cand_bits_ge(sender, 0xC0 + attempt, ts_after(), 23, 12);
            if l.id < a.id {
                found = Some((l, a));
                break;
            }
        }
        found.expect("after-boundary pair with light.id < after.id")
    };
    let mut dag = DAG::new();
    dag.add_transaction_validated(light.clone()).unwrap();
    dag.add_transaction_validated(after.clone()).unwrap();
    assert_eq!(
        dag.resolve_conflict_key(&sender, 23),
        Some(after.id),
        "CDW+1 resolves by work"
    );
    assert_winner_matches_ref(&dag, sender, 23, "ax01 after");

    // Extremes: timestamp 0 is pre; u64::MAX is post (no panic/overflow).
    let zero_heavy = cand_bits_ge(sender, 0x94, 0, 24, 12);
    let zero_light = cand_bits_lt(sender, 0x95, 0, 24, 2);
    let mut dag = DAG::new();
    dag.add_transaction_validated(zero_light.clone()).unwrap();
    dag.add_transaction_validated(zero_heavy.clone()).unwrap();
    assert_eq!(
        dag.resolve_conflict_key(&sender, 24),
        Some(zero_light.id.min(zero_heavy.id)),
        "timestamp 0 is pre-activation even with work divergence"
    );
    let max_heavy = cand_bits_ge(sender, 0x96, u64::MAX, 25, 12);
    let max_light = cand_bits_lt(sender, 0x97, u64::MAX, 25, 2);
    let mut dag = DAG::new();
    dag.add_transaction_validated(max_light.clone()).unwrap();
    dag.add_transaction_validated(max_heavy.clone()).unwrap();
    assert_eq!(
        dag.resolve_conflict_key(&sender, 25),
        Some(max_heavy.id),
        "u64::MAX timestamp resolves by work without overflow"
    );

    // Degenerate groups: single member / unknown key => None.
    let solo = cand_bits_lt(sender, 0x98, ts_at(), 26, 2);
    let mut dag = DAG::new();
    dag.add_transaction_validated(solo.clone()).unwrap();
    assert_eq!(dag.resolve_conflict_key(&sender, 26), None);
    assert_eq!(dag.resolve_conflict_key(&sender, 999), None);
}

// ---------------------------------------------------------------------------
// ax02 — incremental weight vs independent reference, removal, and the
// separation between bookkeeping weight and consensus work.
// ---------------------------------------------------------------------------

#[test]
fn ax02_incremental_weight_reference_removal_and_winner_independence() {
    let a = [0xB0u8; 32];
    let mut dag = DAG::new();
    let r = shaped([[0u8; 32]; 2], a, [0xB1u8; 32], 1, 1, ts_post(), 0, 1);
    dag.add_transaction_validated(r.clone()).unwrap();
    let b = shaped([r.id, [0u8; 32]], a, [0xB2u8; 32], 1, 1, ts_post(), 1, 2);
    dag.add_transaction_validated(b.clone()).unwrap();
    let c = shaped([r.id, [0u8; 32]], a, [0xB3u8; 32], 1, 1, ts_post(), 2, 3);
    dag.add_transaction_validated(c.clone()).unwrap();
    let d = shaped([b.id, [0u8; 32]], a, [0xB4u8; 32], 1, 1, ts_post(), 3, 4);
    dag.add_transaction_validated(d.clone()).unwrap();
    let e = shaped([b.id, [0u8; 32]], a, [0xB5u8; 32], 1, 1, ts_post(), 4, 5);
    dag.add_transaction_validated(e.clone()).unwrap();
    let f = shaped([c.id, [0u8; 32]], a, [0xB6u8; 32], 1, 1, ts_post(), 5, 6);
    dag.add_transaction_validated(f.clone()).unwrap();
    // Diamond: G has TWO parents under the same branch (D and E) -> the
    // unique closure must count G, B, R once each.
    let g = shaped([d.id, e.id], a, [0xB7u8; 32], 1, 1, ts_post(), 6, 7);
    dag.add_transaction_validated(g.clone()).unwrap();

    assert_weights_match_ref(&dag, "ax02 after inserts");
    assert_work_matches_ref(&dag, "ax02 after inserts");
    assert_eq!(dag.get_transaction(r.id).unwrap().weight, 7.0);
    assert_eq!(dag.get_transaction(b.id).unwrap().weight, 4.0);
    assert_eq!(dag.get_transaction(c.id).unwrap().weight, 2.0);
    assert_eq!(dag.get_transaction(d.id).unwrap().weight, 2.0);
    assert_eq!(dag.get_transaction(e.id).unwrap().weight, 2.0);
    assert_eq!(dag.get_transaction(f.id).unwrap().weight, 1.0);
    assert_eq!(dag.get_transaction(g.id).unwrap().weight, 1.0);

    // Removal decrements each surviving ancestor exactly once.
    dag.remove_transaction(&g.id);
    assert_weights_match_ref(&dag, "ax02 after remove G");
    assert_eq!(dag.get_transaction(r.id).unwrap().weight, 6.0);
    assert_eq!(dag.get_transaction(b.id).unwrap().weight, 3.0);
    assert_eq!(dag.get_transaction(d.id).unwrap().weight, 1.0);
    // Cascade prune of B removes D and E; R and C survive.
    let pruned = dag.prune_subtree(b.id);
    assert_eq!(pruned.len(), 3, "B + D + E");
    assert_weights_match_ref(&dag, "ax02 after prune B");
    assert_eq!(dag.get_transaction(r.id).unwrap().weight, 3.0);
    assert_eq!(dag.get_transaction(c.id).unwrap().weight, 2.0);

    // Consensus work never reads `weight`: overwrite a candidate's weight
    // through the test-only raw injector and show the winner/work unchanged.
    let sender = [0xB8u8; 32];
    let heavy = cand_bits_ge(sender, 0x11, ts_post(), 30, 10);
    let light = cand_bits_lt(sender, 0x12, ts_post(), 30, 2);
    let mut dag = DAG::new();
    dag.add_transaction_validated(heavy.clone()).unwrap();
    dag.add_transaction_validated(light.clone()).unwrap();
    let winner_before = dag.resolve_conflict_key(&sender, 30).expect("resolves");
    let work_before = dag.subtree_work(heavy.id);
    let mut corrupted = heavy.clone();
    corrupted.weight = 123_456.0;
    dag.inject_transaction_raw(corrupted);
    assert_eq!(
        dag.get_transaction(heavy.id).unwrap().weight,
        123_456.0,
        "weight field really overwritten"
    );
    assert_eq!(
        dag.subtree_work(heavy.id),
        work_before,
        "consensus work is hash-derived, not the weight field"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 30),
        Some(winner_before),
        "selection cannot be changed by corrupting the bookkeeping weight"
    );
}

// ---------------------------------------------------------------------------
// ax03 — persisted rebuild equals live incremental state and references.
// ---------------------------------------------------------------------------

#[test]
fn ax03_persisted_rebuild_matches_incremental_and_reference() {
    let sender = [0xC0u8; 32];
    let other = [0xC1u8; 32];
    let mut live = DAG::new();
    fund_dag(&mut live, &[(sender, 200_000), (other, 50_000)]);

    // Post-activation group with a chain and a diamond.
    let group = divergent_three(sender, ts_post(), 40);
    for tx in &group {
        live.add_transaction_validated(tx.clone()).unwrap();
    }
    let winner = live
        .resolve_conflict_key(&sender, 40)
        .expect("group resolves");
    let loser = group
        .iter()
        .find(|t| t.id != winner)
        .expect("a loser exists")
        .id;
    let child_loser = heavy_child(loser, other, 0x91, ts_post(), 1);
    live.add_transaction_validated(child_loser.clone()).unwrap();
    let winner_tx = group.iter().find(|t| t.id == winner).unwrap().clone();
    let on_winner = heavy_child(winner, other, 0x92, ts_post(), 2);
    live.add_transaction_validated(on_winner.clone()).unwrap();
    let diamond = shaped(
        [on_winner.id, child_loser.id],
        other,
        [0xC2u8; 32],
        5,
        1,
        ts_post(),
        77,
        3,
    );
    live.add_transaction_validated(diamond.clone()).unwrap();

    assert_weights_match_ref(&live, "ax03 live");
    assert_work_matches_ref(&live, "ax03 live");
    let live_winner = live.resolve_conflict_key(&sender, 40);
    let mut live_ledger = Ledger::new();
    live_ledger.rebuild_from_dag(&live);
    let live_fp = ledger_fp(&live_ledger);

    let txs: Vec<Transaction> = live.transactions().values().cloned().collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let (rebuilt, rebuilt_ledger) = persist_and_rebuild(&txs, dir.path(), true);

    assert_weights_match_ref(&rebuilt, "ax03 rebuilt");
    assert_work_matches_ref(&rebuilt, "ax03 rebuilt");
    assert_eq!(
        rebuilt.resolve_conflict_key(&sender, 40),
        live_winner,
        "boot rebuild keeps the same canonical winner"
    );
    assert_winner_matches_ref(&rebuilt, sender, 40, "ax03 rebuilt");
    let mut rebuilt_sorted: Vec<TransactionId> = rebuilt.transactions().keys().copied().collect();
    let mut live_sorted: Vec<TransactionId> = live.transactions().keys().copied().collect();
    rebuilt_sorted.sort();
    live_sorted.sort();
    assert_eq!(rebuilt_sorted, live_sorted);
    for id in &live_sorted {
        assert_eq!(
            rebuilt.get_transaction(*id).map(|t| t.weight),
            live.get_transaction(*id).map(|t| t.weight)
        );
        assert_eq!(rebuilt.subtree_work(*id), live.subtree_work(*id));
    }
    assert_eq!(ledger_fp(&rebuilt_ledger), live_fp, "restart ledger equal");

    // Second rebuild from the same bytes in the OTHER order: identical.
    let (rebuilt2, ledger2) = persist_and_rebuild(&txs, dir.path(), false);
    assert_eq!(ledger_fp(&ledger2), live_fp);
    assert_eq!(
        rebuilt2.resolve_conflict_key(&sender, 40),
        live_winner,
        "rebuild order is irrelevant"
    );
}

// ---------------------------------------------------------------------------
// ax04 — three-candidate groups: distinct work, exact ties, frozen pre-era,
// arrival permutations, duplicates, ranking flips and loser descendants.
// ---------------------------------------------------------------------------

#[test]
fn ax04_three_candidates_distinct_tie_pre_and_permutations() {
    let sender = [0xD0u8; 32];

    // Distinct work: max wins.
    let group = divergent_three(sender, ts_post(), 50);
    let orders: [[usize; 3]; 3] = [[0, 1, 2], [2, 1, 0], [1, 2, 0]];
    let mut winners = Vec::new();
    for order in orders {
        let mut dag = DAG::new();
        for i in order {
            dag.add_transaction_validated(group[i].clone()).unwrap();
        }
        assert_eq!(dag.transaction_count(), 3, "all candidates retained");
        assert_eq!(
            dag.find_sender_nonce_conflicts(&sender, 50).len(),
            3,
            "three-member group"
        );
        assert_winner_matches_ref(&dag, sender, 50, "ax04 distinct");
        let w = dag.resolve_conflict_key(&sender, 50).unwrap();
        winners.push(w);
        // Duplicate re-delivery: refused, set and winner unchanged.
        let dup = dag.add_transaction_validated(group[0].clone());
        assert!(dup.is_err(), "duplicate id must be refused");
        assert_eq!(dag.transaction_count(), 3);
        assert_eq!(dag.resolve_conflict_key(&sender, 50), Some(w));
    }
    assert!(
        winners.windows(2).all(|w| w[0] == w[1]),
        "arrival order must not change the 3-candidate winner"
    );
    let txs: HashMap<TransactionId, Transaction> =
        group.iter().map(|t| (t.id, t.clone())).collect();
    assert_eq!(
        winners[0],
        ref_winner(&txs, &group.iter().map(|t| t.id).collect::<Vec<_>>())
    );

    // Exact top tie between two members, third strictly lower: min-id of the
    // tied pair wins. Insert the tie pair so that id order != insertion
    // order (proves the tiebreak is explicit, not insertion order).
    let (t1, t2, bits) = tied_pair(sender, ts_post(), 51, 2);
    let third = cand_bits_lt(sender, 0x71, ts_post(), 51, bits);
    let (first_in, second_in) = if t1.id < t2.id {
        (&t1, &t2)
    } else {
        (&t2, &t1)
    };
    let mut dag = DAG::new();
    dag.add_transaction_validated(second_in.clone()).unwrap();
    dag.add_transaction_validated(first_in.clone()).unwrap();
    dag.add_transaction_validated(third.clone()).unwrap();
    let txs = snapshot(&dag);
    let members = dag.find_sender_nonce_conflicts(&sender, 51);
    assert_eq!(members.len(), 3);
    let tied_min = t1.id.min(t2.id);
    assert_eq!(
        dag.resolve_conflict_key(&sender, 51),
        Some(tied_min),
        "exact tie between two max-work members -> min-id"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 51),
        Some(ref_winner(&txs, &members)),
        "tie winner agrees with independent reference"
    );

    // All-pre three candidates: frozen min-id even with a work leader.
    let pre_group = divergent_three(sender, ts_pre(), 52);
    let mut dag = DAG::new();
    for tx in &pre_group {
        dag.add_transaction_validated(tx.clone()).unwrap();
    }
    let txs = snapshot(&dag);
    let members = dag.find_sender_nonce_conflicts(&sender, 52);
    let min_id = *members.iter().min().unwrap();
    assert_ne!(
        ref_max_work_winner(&txs, &members),
        min_id,
        "fixture non-vacuous"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 52),
        Some(min_id),
        "all-pre 3-candidate group is frozen to min-id"
    );
    assert_winner_matches_ref(&dag, sender, 52, "ax04 pre");
}

#[test]
fn ax04_three_candidate_flip_loser_child_and_restart() {
    let sender = [0xE0u8; 32];
    let spender = [0xE1u8; 32];
    let grinder = [0xE2u8; 32];
    let key = 60;
    let mut dag = DAG::new();
    fund_dag(
        &mut dag,
        &[(sender, 100_000), (spender, 50_000), (grinder, 50_000)],
    );

    // A starts heavy, B light, C light.
    let a = cand_bits_ge(sender, 0x21, ts_post(), key, 10);
    let b = cand_bits_lt(sender, 0x22, ts_post(), key, 2);
    let c = cand_bits_lt(sender, 0x23, ts_post(), key, 2);
    for tx in [&a, &b, &c] {
        dag.add_transaction_validated(tx.clone()).unwrap();
    }
    assert_eq!(dag.resolve_conflict_key(&sender, key), Some(a.id));
    assert_winner_matches_ref(&dag, sender, key, "ax04 flip stage 0");

    // New descendants on B (and C) change the ranking; the winner must flip
    // exactly when the independent reference says so.
    let mut added_to_b = 0usize;
    let mut idx = 0u64;
    while ref_subtree_work(&snapshot(&dag), b.id) <= ref_subtree_work(&snapshot(&dag), a.id) {
        let child = heavy_child(b.id, grinder, 0x30 + (idx % 32) as u8, ts_post(), 10 + idx);
        dag.add_transaction_validated(child).unwrap();
        added_to_b += 1;
        idx += 1;
        assert!(added_to_b <= 32, "bounded flip construction");
        assert_winner_matches_ref(&dag, sender, key, "ax04 flip towards B");
    }
    assert_eq!(
        dag.resolve_conflict_key(&sender, key),
        Some(b.id),
        "work overtake flips the winner to B"
    );
    assert_weights_match_ref(&dag, "ax04 flip live");
    assert_work_matches_ref(&dag, "ax04 flip live");

    // Heavy descendants on C overtake BOTH; then on A; winner follows work.
    let mut idx = 100u64;
    while ref_subtree_work(&snapshot(&dag), c.id) <= ref_subtree_work(&snapshot(&dag), b.id) {
        let child = heavy_child(c.id, grinder, 0x50 + (idx % 32) as u8, ts_post(), idx);
        dag.add_transaction_validated(child).unwrap();
        idx += 1;
        assert!(idx < 200, "bounded flip construction C");
        assert_winner_matches_ref(&dag, sender, key, "ax04 flip towards C");
    }
    assert_eq!(
        dag.resolve_conflict_key(&sender, key),
        Some(c.id),
        "second overtake flips the winner to C"
    );

    // Retained losers never receive economic effects; a child of a retained
    // loser DOES apply (parent handled, no transfer).
    let loser = [a.id, b.id]
        .into_iter()
        .find(|id| {
            dag.resolve_conflict_key(&sender, key)
                .map(|w| w != *id)
                .unwrap_or(false)
        })
        .expect("a loser exists");
    let loser_receiver = dag.get_transaction(loser).unwrap().receiver;
    let child_of_loser = shaped(
        [loser, [0u8; 32]],
        spender,
        [0xE9u8; 32],
        7,
        1,
        ts_post(),
        500,
        77,
    );
    dag.add_transaction_validated(child_of_loser.clone())
        .unwrap();
    let winner = dag.resolve_conflict_key(&sender, key).unwrap();
    let winner_receiver = dag.get_transaction(winner).unwrap().receiver;

    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    assert!(ledger.is_applied(&winner));
    assert!(ledger.is_applied(&child_of_loser.id));
    assert_eq!(winner, c.id, "winner is still C after the child insert");
    assert!(!ledger.is_applied(&a.id));
    assert!(!ledger.is_applied(&b.id));
    assert_eq!(ledger.get_balance(&winner_receiver), 100);
    assert_eq!(ledger.get_balance(&loser_receiver), 0);
    assert_eq!(ledger.get_balance(&[0xE9u8; 32]), 7);
    assert_eq!(
        ledger.get_balance(&sender),
        100_000 - 100 - 10,
        "exactly one candidate debit"
    );
    assert_eq!(
        ledger.get_balance(&spender),
        50_000 - 7 - 1,
        "child of loser pays its own fee"
    );
    let live_fp = ledger_fp(&ledger);

    // Persisted restart reproduces winner, applied marks and ledger.
    let txs: Vec<Transaction> = dag.transactions().values().cloned().collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let (rebuilt, rebuilt_ledger) = persist_and_rebuild(&txs, dir.path(), true);
    assert_eq!(
        rebuilt.resolve_conflict_key(&sender, key),
        Some(winner),
        "restart keeps the flipped winner"
    );
    assert_eq!(ledger_fp(&rebuilt_ledger), live_fp);
    assert!(rebuilt_ledger.is_applied(&winner));
    assert!(rebuilt_ledger.is_applied(&child_of_loser.id));
    assert!(!rebuilt_ledger.is_applied(&loser));
    assert_weights_match_ref(&rebuilt, "ax04 restart");
    assert_work_matches_ref(&rebuilt, "ax04 restart");
}

// ---------------------------------------------------------------------------
// ax05 — multi-group permutation convergence with full semantic fingerprint.
// ---------------------------------------------------------------------------

fn dag_semantics(dag: &DAG, keys: &[([u8; 32], u64)]) -> String {
    let txs = snapshot(dag);
    let mut lines: Vec<String> = txs
        .iter()
        .map(|(id, tx)| {
            let mut parents: Vec<String> = tx
                .parents
                .iter()
                .map(|p| {
                    if p.iter().all(|&b| b == 0) {
                        "genesis".to_string()
                    } else {
                        short(p)
                    }
                })
                .collect();
            parents.sort();
            format!(
                "{}|{}|size={}|work={}",
                short(id),
                parents.join(","),
                tx.weight,
                ref_tx_credit(tx)
            )
        })
        .collect();
    lines.sort();
    let mut tips: Vec<String> = txs
        .keys()
        .filter(|id| !txs.values().any(|t| t.parents.contains(id)))
        .map(short)
        .collect();
    tips.sort();
    let mut winners: Vec<String> = keys
        .iter()
        .map(|(s, n)| {
            format!(
                "{}:{}",
                short(s),
                dag.resolve_conflict_key(s, *n)
                    .map(|w| short(&w))
                    .unwrap_or_else(|| "none".into())
            )
        })
        .collect();
    winners.sort();
    format!(
        "n={} tips=[{}] winners=[{}] {{{}}}",
        lines.len(),
        tips.join(","),
        winners.join(","),
        lines.join("; ")
    )
}

#[test]
fn ax05_multi_group_permutation_convergence() {
    let s1 = [0xF0u8; 32];
    let s2 = [0xF1u8; 32];
    let mut base = DAG::new();
    fund_dag(&mut base, &[(s1, 300_000), (s2, 100_000)]);

    let g1 = divergent_three(s1, ts_post(), 70);
    let g2_pair = {
        let low = cand_bits_lt(s1, 0x31, ts_pre(), 71, 2);
        let high = cand_bits_ge(s1, 0x32, ts_pre(), 71, 10);
        vec![low, high]
    };
    let (t1, t2, _bits) = tied_pair(s2, ts_post(), 72, 0);
    let loser1 = g1[0].id;
    let child = shaped(
        [loser1, [0u8; 32]],
        s2,
        [0xF2u8; 32],
        11,
        1,
        ts_post(),
        600,
        80,
    );
    let independent = shaped([[0u8; 32]; 2], s2, [0xF3u8; 32], 13, 1, ts_post(), 601, 81);

    let mut all: Vec<Transaction> = base.transactions().values().cloned().collect();
    all.extend(g1.iter().cloned());
    all.extend(g2_pair.iter().cloned());
    all.extend([t1.clone(), t2.clone(), child.clone(), independent.clone()]);

    // Three explicit, dependency-respecting arrival orders (funding txs
    // first, conflict candidates before the child of a loser).
    let funding: Vec<Transaction> = base.transactions().values().cloned().collect();
    let orders: [Vec<Transaction>; 3] = [
        {
            let mut v = funding.clone();
            v.extend(g1.iter().cloned());
            v.extend(g2_pair.iter().cloned());
            v.extend([t1.clone(), t2.clone(), child.clone(), independent.clone()]);
            v
        },
        {
            let mut v = funding.clone();
            v.extend([t2.clone(), t1.clone()]);
            v.extend(g2_pair.iter().rev().cloned());
            v.extend(g1.iter().rev().cloned());
            v.extend([independent.clone(), child.clone()]);
            v
        },
        {
            let mut v = funding.clone();
            v.extend([g1[1].clone(), t1.clone(), g2_pair[1].clone()]);
            v.extend([g1[2].clone(), t2.clone(), g1[0].clone()]);
            v.extend([child.clone(), g2_pair[0].clone(), independent.clone()]);
            v
        },
    ];

    let keys = [(s1, 70u64), (s1, 71), (s2, 72)];
    let mut semantic_fps = Vec::new();
    let mut ledger_fps = Vec::new();
    for (i, order) in orders.iter().enumerate() {
        let mut dag = DAG::new();
        for tx in order {
            dag.add_transaction_validated(tx.clone())
                .unwrap_or_else(|e| panic!("order {i}: insert {}: {e}", short(&tx.id)));
        }
        assert_eq!(dag.transaction_count(), all.len(), "order {i}: full set");
        assert_weights_match_ref(&dag, &format!("ax05 order {i}"));
        assert_work_matches_ref(&dag, &format!("ax05 order {i}"));
        for (s, n) in keys {
            assert_winner_matches_ref(&dag, s, n, &format!("ax05 order {i}"));
        }
        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(&dag);
        semantic_fps.push(dag_semantics(&dag, &keys));
        ledger_fps.push(ledger_fp(&ledger));
    }
    assert_eq!(semantic_fps[0], semantic_fps[1], "order 1 == order 0");
    assert_eq!(semantic_fps[0], semantic_fps[2], "order 2 == order 0");
    assert_eq!(ledger_fps[0], ledger_fps[1]);
    assert_eq!(ledger_fps[0], ledger_fps[2]);

    // Persisted restart of the same set reproduces semantics and ledger.
    let dir = tempfile::tempdir().expect("tempdir");
    let (rebuilt, rebuilt_ledger) = persist_and_rebuild(&all, dir.path(), true);
    assert_eq!(dag_semantics(&rebuilt, &keys), semantic_fps[0]);
    assert_eq!(ledger_fp(&rebuilt_ledger), ledger_fps[0]);
    assert_weights_match_ref(&rebuilt, "ax05 rebuilt");
    assert_work_matches_ref(&rebuilt, "ax05 rebuilt");
}
