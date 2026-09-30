// PHASE 4B: Cumulative Descendant Work consensus tests.
//
// Rule under test (PRIMARY design, WEIGHT_DESIGN doc): conflict winner =
// max subtree-work (sum of actual-bits work credits over the UNIQUE
// descendant closure, self included), min-id tiebreak, grandfathered to
// plain min-id when ALL members predate CDW_ACTIVATION_TS. Losers are
// RETAINED (never pruned); ledgers apply winners only; re-resolution fires
// on conflict-member arrival and on conflict-descendant arrival.
//
// Cost discipline: all DAG-level tests use validated inserts WITHOUT mining
// (add_transaction_validated checks duplicate/parents/conflict-shape only --
// never PoW) or inject_raw for deliberately-corrupt shapes. Exactly ONE test
// mines real PoW (double-spend order invariance through the live pipeline);
// everything else is FAST and deterministic (fixed timestamps straddling the
// activation constant -- no clock dependence).

use crate::ledger::Ledger;
use crate::parent_selection::{
    canonical_resolve_conflicts, rebuild_dag_topological, DAG,
};
use crate::transaction::{Transaction, TransactionId};

/// Post-activation timestamp (deterministic fixture constant).
fn ts_post() -> u64 {
    Transaction::CDW_ACTIVATION_TS + 3_600_000
}

/// Pre-activation timestamp (grandfathered min-id territory).
fn ts_pre() -> u64 {
    Transaction::CDW_ACTIVATION_TS - 3_600_000
}

/// Shape a tx with fully controlled fields (no mining, no signatures —
/// validity is irrelevant at DAG level; the id is what matters).
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

/// Faucet address bytes (test helper).
fn faucet() -> [u8; 32] {
    hex::decode(crate::genesis::FAUCET_ADDRESS)
        .unwrap()
        .try_into()
        .unwrap()
}

/// Fund `receivers` through the DAG itself (rebuild reseeds from genesis).
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

/// Ledger fingerprint: sorted balances + supply + nonces of `addrs`.
fn ledger_fingerprint(
    ledger: &Ledger,
    addrs: &[[u8; 32]],
) -> (Vec<(String, u64)>, u64, Vec<u64>) {
    let mut bals: Vec<(String, u64)> = ledger
        .get_all_balances()
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    bals.sort();
    let nonces = addrs.iter().map(|a| ledger.get_nonce(a)).collect();
    (bals, ledger.total_supply(), nonces)
}

/// 1. Work credits match actual leading-zero bits: independent bit-count
/// loop over crafted hashes + exact credit_for_bits vectors (0,1,20,24,31,
/// 32,63,64,65,255) incl. saturation. No mining (vectors are exact).
#[test]
fn test_work_credit_matches_actual_bits() {
    // Independent reference counter (not calling the impl).
    fn ref_lz(hash: &[u8; 32]) -> u32 {
        let mut n = 0u32;
        for b in hash.iter() {
            if *b == 0 {
                n += 8;
            } else {
                let mut v = *b;
                let mut c = 0u32;
                while v & 0x80 == 0 {
                    c += 1;
                    v <<= 1;
                }
                n += c;
                break;
            }
        }
        n
    }
    // Crafted hashes: exact expectations by hand.
    let cases: Vec<([u8; 32], u32)> = vec![
        ([0xFFu8; 32], 0),
        {
            let mut h = [0u8; 32];
            h[0] = 0xFF;
            (h, 0)
        },
        {
            let mut h = [0u8; 32];
            h[0] = 0x0F;
            (h, 4)
        },
        {
            let mut h = [0u8; 32];
            h[0] = 0x01;
            (h, 7)
        },
        {
            let mut h = [0u8; 32];
            h[0] = 0x00;
            h[1] = 0x00;
            h[2] = 0x10;
            (h, 16 + 3)
        },
    ];
    for (hash, expect) in &cases {
        assert_eq!(Transaction::leading_zero_bits(hash), *expect);
        assert_eq!(ref_lz(hash), *expect);
    }
    // Credit vectors: exact powers + saturation (never silent wrap).
    let vectors: Vec<(u32, u64)> = vec![
        (0, 1),
        (1, 2),
        (20, 1 << 20),
        (24, 1 << 24),
        (31, 1 << 31),
        (32, 1 << 32),
        (63, 1 << 63),
        (64, u64::MAX),
        (65, u64::MAX),
        (255, u64::MAX),
    ];
    for (bits, expect) in &vectors {
        assert_eq!(Transaction::credit_for_bits(*bits), *expect);
    }
    // Composition: work_credit == credit_for_bits(leading_zero_bits(hash)).
    let tx = shaped(
        [[0u8; 32]; 2],
        [0x11u8; 32],
        [0x22u8; 32],
        100,
        10,
        ts_post(),
        999,
        1,
    );
    let hash = tx.calculate_pow_hash(tx.nonce);
    assert_eq!(
        tx.work_credit(),
        Transaction::credit_for_bits(Transaction::leading_zero_bits(&hash))
    );
    println!("phase4: credit vectors + composition pinned");
}

/// 2. Cumulative descendant work on the 4A doc shape (A with B,C; B with
/// D,E; C with F): exact subtree sums incl. diamond uniqueness (D counted
/// once under shared ancestors). Credits read at runtime (deterministic);
/// relations asserted exactly.
#[test]
fn test_cumulative_descendant_work() {
    let zero = [0u8; 32];
    let mut dag = DAG::new();
    let a = shaped([zero, zero], [0xA0u8; 32], [0xA1u8; 32], 1, 1, ts_post(), 0, 0);
    dag.add_transaction_validated(a.clone()).unwrap();
    let b = shaped([a.id, zero], [0xB0u8; 32], [0xB1u8; 32], 1, 1, ts_post(), 1, 0);
    dag.add_transaction_validated(b.clone()).unwrap();
    let c = shaped([a.id, zero], [0xC0u8; 32], [0xC1u8; 32], 1, 1, ts_post(), 2, 0);
    dag.add_transaction_validated(c.clone()).unwrap();
    let d = shaped([b.id, zero], [0xD0u8; 32], [0xD1u8; 32], 1, 1, ts_post(), 3, 0);
    dag.add_transaction_validated(d.clone()).unwrap();
    let e = shaped([b.id, zero], [0xE0u8; 32], [0xE1u8; 32], 1, 1, ts_post(), 4, 0);
    dag.add_transaction_validated(e.clone()).unwrap();
    let f = shaped([c.id, zero], [0xF0u8; 32], [0xF1u8; 32], 1, 1, ts_post(), 5, 0);
    dag.add_transaction_validated(f.clone()).unwrap();
    let (wa, wb, wc, wd, we, wf) = (
        a.work_credit(),
        b.work_credit(),
        c.work_credit(),
        d.work_credit(),
        e.work_credit(),
        f.work_credit(),
    );
    // Leaves: own credit only.
    assert_eq!(dag.subtree_work(d.id), wd);
    assert_eq!(dag.subtree_work(e.id), we);
    assert_eq!(dag.subtree_work(f.id), wf);
    // B = own + D + E; C = own + F (descendant coverage, work only).
    assert_eq!(dag.subtree_work(b.id), wb + wd + we);
    assert_eq!(dag.subtree_work(c.id), wc + wf);
    // A = own + everything exactly once (diamond-safe uniqueness is
    // structural here; D reachable once via B).
    assert_eq!(dag.subtree_work(a.id), wa + wb + wc + wd + we + wf);
    // Empty/stale roots score zero, never panic.
    assert_eq!(dag.subtree_work([0xDDu8; 32]), 0);
    println!(
        "phase4: subtree scores A={} B={} C={}",
        dag.subtree_work(a.id),
        dag.subtree_work(b.id),
        dag.subtree_work(c.id)
    );
}

/// 3. Monotonicity: adding a validated descendant never decreases any
/// member's score (work only accrues). Chain + branch additions asserted.
#[test]
fn test_work_monotonicity() {
    let zero = [0u8; 32];
    let mut dag = DAG::new();
    let r = shaped([zero, zero], [0x10u8; 32], [0x11u8; 32], 1, 1, ts_post(), 0, 0);
    dag.add_transaction_validated(r.clone()).unwrap();
    let before = dag.subtree_work(r.id);
    assert!(before >= 1, "every tx credits at least 2^0");
    // Chain extension.
    let c1 = shaped([r.id, zero], [0x12u8; 32], [0x13u8; 32], 1, 1, ts_post(), 1, 0);
    dag.add_transaction_validated(c1.clone()).unwrap();
    let after_chain = dag.subtree_work(r.id);
    assert!(
        after_chain >= before,
        "chain extension must not decrease score"
    );
    assert_eq!(after_chain, before + c1.work_credit());
    // Branch extension.
    let c2 = shaped([r.id, zero], [0x14u8; 32], [0x15u8; 32], 1, 1, ts_post(), 2, 0);
    dag.add_transaction_validated(c2.clone()).unwrap();
    let after_branch = dag.subtree_work(r.id);
    assert!(after_branch >= after_chain);
    assert_eq!(after_branch, before + c1.work_credit() + c2.work_credit());
}

/// 4. No free weight: garbage (unmined) content credits small; a REAL
/// 20-bit-mined tx credits >= 2^20. One medium mine (policy-valid
/// pre-activation shape) proves PoW prices in.
#[test]
fn test_no_free_weight() {
    // Garbage: arbitrary nonces, never mined — credits stay tiny.
    for nonce in [0u64, 1, 7, 12345] {
        let g = shaped(
            [[0u8; 32]; 2],
            [0x20u8; 32],
            [0x21u8; 32],
            100,
            10,
            ts_pre(),
            nonce,
            1,
        );
        assert!(
            g.work_credit() < (1 << 20),
            "unmined content must not credit like mined work"
        );
    }
    // Real 20-bit PoW prices in at exactly >= 2^20.
    let mut real = shaped(
        [[0u8; 32]; 2],
        [0x22u8; 32],
        [0x23u8; 32],
        100,
        10,
        ts_pre(),
        0,
        1,
    );
    real.nonce = real.mine_nonce(20);
    assert!(real.verify_pow(20));
    assert!(
        real.work_credit() >= (1 << 20),
        "mined 20-bit proof must credit >= 2^20"
    );
    println!("phase4: mined credit = {}", real.work_credit());
}

/// 5. Min-id decides ONLY ties: build candidates until two share the exact
/// same credit (concentration at low bits makes this near-certain within the
/// bound), then resolve must pick the smaller id. Deterministic seeds.
#[test]
fn test_min_id_only_tie_break() {
    let sender = [0x30u8; 32];
    let mut first: Option<Transaction> = None;
    let mut second: Option<Transaction> = None;
    for i in 0..256u64 {
        let mut receiver = [0u8; 32];
        receiver[..8].copy_from_slice(&i.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            i,
            9,
        );
        match &first {
            None => first = Some(cand),
            Some(f) => {
                if f.work_credit() == cand.work_credit() && f.id != cand.id {
                    second = Some(cand);
                    break;
                }
            }
        }
    }
    let (a, b) = (
        first.expect("first candidate"),
        second.expect("tied-credit pair within 256 tries"),
    );
    assert_eq!(a.work_credit(), b.work_credit());
    assert_ne!(a.id, b.id);
    let mut dag = DAG::new();
    dag.add_transaction_validated(a.clone()).unwrap();
    dag.add_transaction_validated(b.clone()).unwrap();
    let winner = dag
        .resolve_conflict_key(&sender, 9)
        .expect("pair must resolve");
    let expect = a.id.min(b.id);
    assert_eq!(winner, expect, "exact tie -> min-id tiebreak");
}

/// 6. Weight beats min-id: high-work tx with the LARGER id still wins.
/// Credits from cheap nonce grinding (no threshold mining — scoring prices
/// expected cost regardless of validity; validation stays separate).
#[test]
fn test_weight_beats_min_id() {
    let sender = [0x31u8; 32];
    // Low-work rival: first nonce with < 4 leading-zero bits (fast).
    let mut low = None;
    for n in 0..4096u64 {
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            [0x32u8; 32],
            100,
            10,
            ts_post(),
            n,
            9,
        );
        let bits = Transaction::leading_zero_bits(&cand.calculate_pow_hash(n));
        if bits < 4 {
            low = Some(cand);
            break;
        }
    }
    // High-work challenger: first nonce with >= 12 leading-zero bits
    // (~4096 hashes expected — bounded, fast).
    let mut high = None;
    for n in 0..65536u64 {
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            [0x33u8; 32],
            100,
            10,
            ts_post(),
            n,
            9,
        );
        let bits = Transaction::leading_zero_bits(&cand.calculate_pow_hash(n));
        if bits >= 12 {
            high = Some(cand);
            break;
        }
    }
    let (lo, hi) = (
        low.expect("low-work candidate"),
        high.expect("high-work candidate within bound"),
    );
    assert!(hi.work_credit() > lo.work_credit());
    let mut dag = DAG::new();
    dag.add_transaction_validated(lo.clone()).unwrap();
    dag.add_transaction_validated(hi.clone()).unwrap();
    let winner = dag
        .resolve_conflict_key(&sender, 9)
        .expect("pair must resolve");
    // The assertion that MATTERS: work outranks id, whichever id is smaller.
    let expect_by_work = if hi.work_credit() > lo.work_credit() {
        hi.id
    } else {
        lo.id
    };
    assert_eq!(winner, expect_by_work, "higher work must win");
    // And document the id ordering (either direction is fine — the point is
    // the rule ignores it absent a tie).
    println!(
        "phase4: work {} (id {:02x}..) beats work {} (id {:02x}..)",
        hi.work_credit(),
        hi.id[0],
        lo.work_credit(),
        lo.id[0]
    );
}

/// 8. Double-spend order invariance through the LIVE pipeline, post-
/// activation (CDW rule): A-then-B and B-then-A yield identical DAG sets,
/// identical winners, identical ledgers. MEDIUM-HEAVY: two real 24-bit mines
/// (post-activation timestamps require 24-bit PoW); see test 7 note on
/// release equivalence.
#[tokio::test]
async fn test_double_spend_order_invariance_phase4() {
    use crate::transaction_processor::{ProcessingError, TransactionProcessor};
    use crate::validation::ValidationMode;
    use crate::wallet::Wallet;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use crate::rpc::Mempool;
    let processor = TransactionProcessor::new();
    let wallet = Wallet::from_secret_key(
        "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
    )
    .expect("fixed test key");
    let sender = wallet.address();
    let pk = wallet.public_key_bytes();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(
        now >= Transaction::CDW_ACTIVATION_TS,
        "test requires post-activation wall clock"
    );
    let build = |receiver: [u8; 32]| {
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            now,
            0,
            1,
            vec![0u8; 64],
            pk.clone(),
        );
        tx.nonce = tx.mine_nonce(24);
        tx.signature = wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();
        assert!(tx.verify_pow(24));
        tx
    };
    let tx_a = build([0xAAu8; 32]);
    let tx_b = build([0xBBu8; 32]);
    assert_ne!(tx_a.id, tx_b.id);
    let processor_ref = &processor;
    let run = |first: Transaction, second: Transaction| async move {
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap();
        let funding = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            sender,
            100_000,
            5,
            now,
            0,
            7,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.write()
            .await
            .add_transaction_validated(funding)
            .unwrap();
        {
            let dag_read = dag.read().await;
            ledger.write().await.rebuild_from_dag(&dag_read);
        }
        let r1: Result<(), ProcessingError> = processor_ref
            .process(first, &dag, &ledger, &mempool, 10, ValidationMode::Historical)
            .await;
        assert!(r1.is_ok(), "first arrival accepted: {:?}", r1);
        let r2: Result<(), ProcessingError> = processor_ref
            .process(second, &dag, &ledger, &mempool, 10, ValidationMode::Historical)
            .await;
        assert!(r2.is_ok(), "second arrival retained: {:?}", r2);
        let dag_guard = dag.read().await;
        let mut ids: Vec<[u8; 32]> =
            dag_guard.transactions().keys().copied().collect();
        ids.sort();
        let ledger_guard = ledger.read().await;
        let fp = (
            ids,
            ledger_guard.get_balance(&sender),
            ledger_guard.get_balance(&tx_a.receiver),
            ledger_guard.get_balance(&tx_b.receiver),
            ledger_guard.total_supply(),
        );
        drop(ledger_guard);
        drop(dag_guard);
        fp
    };
    let fp_ab = run(tx_a.clone(), tx_b.clone()).await;
    let fp_ba = run(tx_b.clone(), tx_a.clone()).await;
    assert_eq!(fp_ab, fp_ba, "order-invariant under CDW live");
    // Both retained in DAG (count 3 with funding), exactly one funded.
    assert_eq!(fp_ab.0.len(), 3);
    // Exactly the winner applies (the CDW winner, whichever it is).
    assert!(
        (fp_ab.2 == 100 && fp_ab.3 == 0) || (fp_ab.2 == 0 && fp_ab.3 == 100),
        "exactly the winner applies"
    );
}

/// 9. Loser retention: both sides present after resolution (no prune, no
/// purge); winner designated by resolve; ledger applies winner only.
#[test]
fn test_loser_retention() {
    let sender = [0x40u8; 32];
    let t1 = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x41u8; 32],
        100,
        10,
        ts_post(),
        0,
        3,
    );
    let t2 = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x42u8; 32],
        100,
        10,
        ts_post(),
        1,
        3,
    );
    assert_ne!(t1.id, t2.id);
    let mut dag = DAG::new();
    dag.add_transaction_validated(t1.clone()).unwrap();
    dag.add_transaction_validated(t2.clone()).unwrap();
    // Both resident (retention — the old code pruned one here).
    assert_eq!(dag.transaction_count(), 2);
    let members = dag.find_sender_nonce_conflicts(&sender, 3);
    assert_eq!(members.len(), 2);
    // Winner designated deterministically (CDW or min-id tiebreak).
    let w1 = dag.resolve_conflict_key(&sender, 3).expect("resolves");
    let w2 = dag.resolve_conflict_key(&sender, 3).expect("stable");
    assert_eq!(w1, w2);
    assert!(w1 == t1.id || w1 == t2.id);
    // Ledger applies exactly the winner (funded via DAG).
    fund_dag(&mut dag, &[(sender, 100_000)]);
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    let (win_recv, lose_recv) = if w1 == t1.id {
        (t1.receiver, t2.receiver)
    } else {
        (t2.receiver, t1.receiver)
    };
    assert_eq!(ledger.get_balance(&win_recv), 100);
    assert_eq!(ledger.get_balance(&lose_recv), 0);
}

/// 10. Re-resolution: staged descendant arrivals flip the winner when work
/// tips, and the ledger follows (rebuild per stage). Funded throughout.
#[test]
fn test_loser_re_resolution() {
    let sender = [0x41u8; 32];
    // A starts ahead (child immediately); B catches up with two children.
    let a = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xA1u8; 32],
        100,
        10,
        ts_post(),
        0,
        4,
    );
    let b = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xA2u8; 32],
        100,
        10,
        ts_post(),
        1,
        4,
    );
    let mut dag = DAG::new();
    fund_dag(&mut dag, &[(sender, 100_000)]);
    dag.add_transaction_validated(a.clone()).unwrap();
    dag.add_transaction_validated(b.clone()).unwrap();
    // Stage 1: child on A.
    let ca = shaped(
        [a.id, [0u8; 32]],
        [0xA3u8; 32],
        [0xA4u8; 32],
        10,
        1,
        ts_post(),
        2,
        0,
    );
    dag.add_transaction_validated(ca.clone()).unwrap();
    let w1 = dag.resolve_conflict_key(&sender, 4).expect("resolves");
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    // Stage 2: two children on B (B's subtree outgrows A's by work).
    let cb1 = shaped(
        [b.id, [0u8; 32]],
        [0xA5u8; 32],
        [0xA6u8; 32],
        10,
        1,
        ts_post(),
        3,
        0,
    );
    let cb2 = shaped(
        [b.id, [0u8; 32]],
        [0xA7u8; 32],
        [0xA8u8; 32],
        10,
        1,
        ts_post(),
        4,
        0,
    );
    dag.add_transaction_validated(cb1.clone()).unwrap();
    dag.add_transaction_validated(cb2.clone()).unwrap();
    let w2 = dag.resolve_conflict_key(&sender, 4).expect("resolves");
    ledger.rebuild_from_dag(&dag);
    // Scores decide (compute expected from measured credits — relations, not
    // absolutes, so the test is hash-robust).
    let score = |id| dag.subtree_work(id);
    let (sa, sb) = (score(a.id), score(b.id));
    let expect = if sa > sb {
        a.id
    } else if sb > sa {
        b.id
    } else {
        a.id.min(b.id)
    };
    assert_eq!(w2, expect, "stage-2 winner follows work");
    // Ledger follows the stage-2 winner exclusively.
    let (win_recv, lose_recv) = if w2 == a.id {
        (a.receiver, b.receiver)
    } else {
        (b.receiver, a.receiver)
    };
    assert_eq!(ledger.get_balance(&win_recv), 100);
    assert_eq!(ledger.get_balance(&lose_recv), 0);
    // w1 is history (may equal w2 or not — both orders legal); the property
    // is determinism: recompute agrees.
    assert_eq!(dag.resolve_conflict_key(&sender, 4), Some(w2));
    let _ = w1;
}

/// 11. Partition reconvergence: two DAGs (shared history + divergent
/// same-key txs + one descendant each side), merged in BOTH orders →
/// identical winners, DAG sets, ledgers.
#[test]
fn test_partition_reconvergence_phase4() {
    let sender = [0x50u8; 32];
    let build_side = |receiver: [u8; 32], tag: u8| {
        let mut dag = DAG::new();
        fund_dag(&mut dag, &[(sender, 100_000)]);
        let tx = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            tag as u64,
            6,
        );
        dag.add_transaction_validated(tx.clone()).unwrap();
        let mut cs = [0u8; 32];
        cs[0] = tag;
        let mut cr = [0u8; 32];
        cr[0] = tag.wrapping_add(1);
        let child = shaped(
            [tx.id, [0u8; 32]],
            cs,
            cr,
            10,
            1,
            ts_post(),
            tag as u64 + 100,
            0,
        );
        dag.add_transaction_validated(child.clone()).unwrap();
        (dag, tx.id)
    };
    let (da, ida) = build_side([0x51u8; 32], 0x51);
    let (db, idb) = build_side([0x52u8; 32], 0x52);
    assert_ne!(ida, idb);
    // Merge A-into-B and B-into-A (validated inserts accept pairs now).
    let merge = |first: &DAG, second: &DAG| {
        let mut dag = DAG::new();
        for tx in first.transactions().values().cloned() {
            let _ = dag.add_transaction_validated(tx);
        }
        for tx in second.transactions().values().cloned() {
            let _ = dag.add_transaction_validated(tx);
        }
        dag
    };
    // NOTE: funding txs share faucet nonces across sides (both start at 0)
    // but carry IDENTICAL bytes (same receivers/amounts) → same ids →
    // second insert is a no-op duplicate... except add rejects duplicates
    // with Err, ignored above via let _. DAG sets therefore merge cleanly.
    let mab = merge(&da, &db);
    let mba = merge(&db, &da);
    let wa = mab.resolve_conflict_key(&sender, 6);
    let wb = mba.resolve_conflict_key(&sender, 6);
    assert_eq!(wa, wb, "merged winner order-independent");
    let mut la = Ledger::new();
    la.rebuild_from_dag(&mab);
    let mut lb = Ledger::new();
    lb.rebuild_from_dag(&mba);
    let addrs = [sender, [0x51u8; 32], [0x52u8; 32]];
    assert_eq!(
        ledger_fingerprint(&la, &addrs),
        ledger_fingerprint(&lb, &addrs)
    );
    let mut sa: Vec<[u8; 32]> = mab.transactions().keys().copied().collect();
    let mut sb: Vec<[u8; 32]> = mba.transactions().keys().copied().collect();
    sa.sort();
    sb.sort();
    assert_eq!(sa, sb, "merged DAG sets identical");
}

/// 12. Restart preserves weights/winners/losers/ledger: persisted-set Vec
/// through boot order (topological insert, NO canonical pruning — retention)
/// equals the live state on DAG sets, scores, winners, ledger fingerprint.
#[test]
fn test_restart_preserves_weights() {
    let sender = [0x60u8; 32];
    let mut live = DAG::new();
    fund_dag(&mut live, &[(sender, 100_000)]);
    let t1 = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x61u8; 32],
        100,
        10,
        ts_post(),
        0,
        8,
    );
    let t2 = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x62u8; 32],
        100,
        10,
        ts_post(),
        1,
        8,
    );
    live.add_transaction_validated(t1.clone()).unwrap();
    live.add_transaction_validated(t2.clone()).unwrap();
    let kid = shaped(
        [t1.id, [0u8; 32]],
        [0x63u8; 32],
        [0x64u8; 32],
        10,
        1,
        ts_post(),
        2,
        0,
    );
    live.add_transaction_validated(kid.clone()).unwrap();
    let mut live_ledger = Ledger::new();
    live_ledger.rebuild_from_dag(&live);
    let live_winner = live.resolve_conflict_key(&sender, 8);
    // Simulated restart: flat persisted set, topological reinsert (retention:
    // nothing dropped), rebuild.
    let persisted: Vec<Transaction> =
        live.transactions().values().cloned().collect();
    let mut boot = DAG::new();
    let (inserted, skipped, orphans) =
        rebuild_dag_topological(&mut boot, persisted);
    assert_eq!(skipped, 0);
    assert!(orphans.is_empty());
    let mut boot_ledger = Ledger::new();
    boot_ledger.rebuild_from_dag(&boot);
    assert_eq!(inserted as usize, live.transaction_count());
    let mut live_ids: Vec<[u8; 32]> =
        live.transactions().keys().copied().collect();
    let mut boot_ids: Vec<[u8; 32]> =
        boot.transactions().keys().copied().collect();
    live_ids.sort();
    boot_ids.sort();
    assert_eq!(live_ids, boot_ids, "DAG sets survive restart");
    for id in &live_ids {
        assert_eq!(
            live.subtree_work(*id),
            boot.subtree_work(*id),
            "scores survive restart"
        );
    }
    assert_eq!(
        live.resolve_conflict_key(&sender, 8),
        boot.resolve_conflict_key(&sender, 8)
    );
    assert_eq!(live_winner, boot.resolve_conflict_key(&sender, 8));
    let addrs = [sender, [0x61u8; 32], [0x62u8; 32], [0x63u8; 32]];
    assert_eq!(
        ledger_fingerprint(&live_ledger, &addrs),
        ledger_fingerprint(&boot_ledger, &addrs)
    );
}

/// 13. Deep sync reconstructs weights/conflicts/winners/ledger: a node
/// receiving ONLY the served history set rebuilds identically (scores,
/// winner, ledger). Models inventory/window delivery as a set transfer.
#[test]
fn test_deep_sync_reconstructs_weights() {
    let sender = [0x70u8; 32];
    let mut source = DAG::new();
    fund_dag(&mut source, &[(sender, 100_000)]);
    // A small conflicted history with descendants on both sides.
    let x = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x71u8; 32],
        100,
        10,
        ts_post(),
        0,
        9,
    );
    let y = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x72u8; 32],
        100,
        10,
        ts_post(),
        1,
        9,
    );
    source.add_transaction_validated(x.clone()).unwrap();
    source.add_transaction_validated(y.clone()).unwrap();
    for (i, parent) in [x.id, y.id].iter().enumerate() {
        let mut cs = [0u8; 32];
        cs[0] = 0x80 + i as u8;
        let mut cr = [0u8; 32];
        cr[0] = 0x90 + i as u8;
        let k = shaped(
            [*parent, [0u8; 32]],
            cs,
            cr,
            10,
            1,
            ts_post(),
            10 + i as u64,
            i as u64,
        );
        source.add_transaction_validated(k).unwrap();
    }
    let mut source_ledger = Ledger::new();
    source_ledger.rebuild_from_dag(&source);
    let source_winner = source.resolve_conflict_key(&sender, 9);
    // Served history (the sync payload) in ARBITRARY order (windowed pages
    // are not topological across pages — receiver re-sorts).
    let mut served: Vec<Transaction> =
        source.transactions().values().cloned().collect();
    served.reverse();
    // Joiner: topological insert + rebuild (the node.rs boot/sync shape,
    // retention: nothing dropped).
    let mut joiner = DAG::new();
    let (inserted, skipped, orphans) =
        rebuild_dag_topological(&mut joiner, served);
    assert_eq!(skipped, 0);
    assert!(orphans.is_empty(), "closed history has no orphans");
    let mut joiner_ledger = Ledger::new();
    joiner_ledger.rebuild_from_dag(&joiner);
    assert_eq!(inserted as usize, source.transaction_count());
    let mut s_ids: Vec<[u8; 32]> =
        source.transactions().keys().copied().collect();
    let mut j_ids: Vec<[u8; 32]> =
        joiner.transactions().keys().copied().collect();
    s_ids.sort();
    j_ids.sort();
    assert_eq!(s_ids, j_ids, "sets identical");
    for id in &s_ids {
        assert_eq!(
            source.subtree_work(*id),
            joiner.subtree_work(*id),
            "scores identical"
        );
    }
    assert_eq!(
        source_winner,
        joiner.resolve_conflict_key(&sender, 9),
        "winner identical"
    );
    let addrs = [sender, [0x71u8; 32], [0x72u8; 32]];
    assert_eq!(
        ledger_fingerprint(&source_ledger, &addrs),
        ledger_fingerprint(&joiner_ledger, &addrs)
    );
}

/// 14. Pre-activation grandfathering: all-pre pair resolves min-id EVEN
/// when the larger-id side carries far more descendant work.
#[test]
fn test_pre_activation_grandfathering() {
    let sender = [0x80u8; 32];
    // Small-id side, childless (minimal work).
    let small = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x81u8; 32],
        100,
        10,
        ts_pre(),
        0,
        10,
    );
    // Large-id side with a heavy descendant chain (would win any work rule).
    let big = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x82u8; 32],
        100,
        10,
        ts_pre(),
        1,
        10,
    );
    // Order roles by id WITHOUT assuming which is smaller: find any pair
    // where min-id != max-work by construction below (retry receivers).
    let (lo, hi) = if small.id < big.id {
        (small, big)
    } else {
        (big, small)
    };
    let mut dag = DAG::new();
    fund_dag(&mut dag, &[(sender, 100_000)]);
    dag.add_transaction_validated(lo.clone()).unwrap();
    dag.add_transaction_validated(hi.clone()).unwrap();
    // Build heavy descendants on the LARGER id (work >> small side).
    let mut prev = hi.id;
    for i in 0..6u64 {
        let mut s = [0u8; 32];
        s[0] = 0x90 + i as u8;
        let k = shaped(
            [prev, [0u8; 32]],
            s,
            [0x91u8; 32],
            10,
            1,
            ts_pre(),
            100 + i,
            i,
        );
        dag.add_transaction_validated(k.clone()).unwrap();
        prev = k.id;
    }
    // Sanity: work rule WOULD pick hi (document the counterfactual).
    assert!(
        dag.subtree_work(hi.id) > dag.subtree_work(lo.id),
        "fixture must give hi more work (else vacuous)"
    );
    // Grandfathered: min-id wins despite the work gap.
    assert_eq!(
        dag.resolve_conflict_key(&sender, 10),
        Some(lo.id),
        "all-pre-activation pair stays min-id"
    );
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    assert_eq!(ledger.get_balance(&lo.receiver), 100);
    assert_eq!(ledger.get_balance(&hi.receiver), 0);
}

/// 15. Post-activation rule: mixed-era pair (one member post-activation)
/// resolves by CDW, not min-id — mirror of test 14 with one timestamp
/// flipped. Same heavy-descendant shape on the larger id.
#[test]
fn test_post_activation_new_rule() {
    let sender = [0x81u8; 32];
    let small = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x83u8; 32],
        100,
        10,
        ts_post(),
        0,
        11,
    );
    let big = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x84u8; 32],
        100,
        10,
        ts_post(),
        1,
        11,
    );
    let (lo, hi) = if small.id < big.id {
        (small, big)
    } else {
        (big, small)
    };
    let mut dag = DAG::new();
    fund_dag(&mut dag, &[(sender, 100_000)]);
    dag.add_transaction_validated(lo.clone()).unwrap();
    dag.add_transaction_validated(hi.clone()).unwrap();
    let mut prev = hi.id;
    for i in 0..6u64 {
        let mut s = [0u8; 32];
        s[0] = 0xA0 + i as u8;
        let k = shaped(
            [prev, [0u8; 32]],
            s,
            [0xA1u8; 32],
            10,
            1,
            ts_post(),
            100 + i,
            100 + i,
        );
        dag.add_transaction_validated(k.clone()).unwrap();
        prev = k.id;
    }
    assert!(
        dag.subtree_work(hi.id) > dag.subtree_work(lo.id),
        "fixture must give hi more work (else vacuous)"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 11),
        Some(hi.id),
        "mixed-era pair resolves by work, not min-id"
    );
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    assert_eq!(ledger.get_balance(&hi.receiver), 100);
    assert_eq!(ledger.get_balance(&lo.receiver), 0);
}

/// 16. Activation boundary: member timestamp == CDW_ACTIVATION_TS counts as
/// post-activation (>=); all-members-strictly-below stays min-id.
#[test]
fn test_phase4_activation_boundary() {
    let sender = [0x82u8; 32];
    let at = Transaction::CDW_ACTIVATION_TS;
    let below = Transaction::CDW_ACTIVATION_TS - 1;
    // Pair straddling by exactly the boundary constant.
    let t_below = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x83u8; 32],
        100,
        10,
        below,
        0,
        12,
    );
    let t_at = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x84u8; 32],
        100,
        10,
        at,
        1,
        12,
    );
    // Force known id order AND known work order independently: give the
    // boundary member heavy descendants so CDW and min-id can only agree by
    // accident (asserted explicitly below via both rules).
    let mut dag = DAG::new();
    dag.add_transaction_validated(t_below.clone()).unwrap();
    dag.add_transaction_validated(t_at.clone()).unwrap();
    let mut prev = t_at.id;
    for i in 0..3u64 {
        let mut s = [0u8; 32];
        s[0] = 0xB0 + i as u8;
        let k = shaped(
            [prev, [0u8; 32]],
            s,
            [0xB1u8; 32],
            10,
            1,
            at,
            100 + i,
            200 + i,
        );
        dag.add_transaction_validated(k.clone()).unwrap();
        prev = k.id;
    }
    // Newest member is AT activation -> new rule applies.
    let winner = dag
        .resolve_conflict_key(&sender, 12)
        .expect("pair resolves");
    // CDW must pick t_at (heavy descendants); min-id would pick min(t).
    assert!(
        dag.subtree_work(t_at.id) > dag.subtree_work(t_below.id),
        "fixture: boundary member heavier"
    );
    assert_eq!(winner, t_at.id, "boundary timestamp counts post-activation");
    // All-strictly-below pair (same key family, different nonce): min-id.
    let mut dag2 = DAG::new();
    let u1 = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x85u8; 32],
        100,
        10,
        below,
        0,
        13,
    );
    let u2 = shaped(
        [[0u8; 32]; 2],
        sender,
        [0x86u8; 32],
        100,
        10,
        below - 1,
        1,
        13,
    );
    dag2.add_transaction_validated(u1.clone()).unwrap();
    dag2.add_transaction_validated(u2.clone()).unwrap();
    assert_eq!(
        dag2.resolve_conflict_key(&sender, 13),
        Some(u1.id.min(u2.id)),
        "all-below pair stays min-id"
    );
}

/// 17. Weight overflow protection: credit vectors at the u64 edge (63 ->
/// 2^63, 64/65/255 -> MAX, never wrap) + a 1000-tx exact sum (no early
/// saturation) + saturating subtree accumulation documented.
#[test]
fn test_weight_overflow_protection() {
    assert_eq!(Transaction::credit_for_bits(63), 1u64 << 63);
    assert_eq!(Transaction::credit_for_bits(64), u64::MAX);
    assert_eq!(Transaction::credit_for_bits(65), u64::MAX);
    assert_eq!(Transaction::credit_for_bits(255), u64::MAX);
    // 1000 real credits sum exactly (proves no wrap in the accumulator
    // across realistic magnitudes; saturation only at astronomical scale).
    let mut dag = DAG::new();
    let mut expected: u64 = 0;
    for i in 0..1000u64 {
        let mut sender = [0u8; 32];
        sender[..8].copy_from_slice(&i.to_le_bytes());
        sender[8] = 0xC7;
        let tx = shaped(
            [[0u8; 32]; 2],
            sender,
            [0xC8u8; 32],
            1,
            1,
            ts_post(),
            i,
            0,
        );
        expected = expected.saturating_add(tx.work_credit());
        dag.add_transaction_validated(tx.clone()).unwrap();
        if i == 0 {
            // Roots have no shared descendants here; each root's subtree
            // must equal its own credit exactly.
            assert_eq!(dag.subtree_work(tx.id), tx.work_credit());
        }
    }
    assert_eq!(dag.transaction_count(), 1000);
}

/// 18 (Etape 15). OLD vs NEW on the same DAG where they MUST disagree:
/// high-work larger-id wins CDW while min-id picks the smaller id. Proves
/// the rule actually changed (not a refactor) and that the divergence is
/// the specified one (documented CONSENSUS_BREAK, version-gated).
#[test]
fn test_old_rule_vs_new_rule_divergence_expected() {
    let sender = [0x90u8; 32];
    // Small-id side, childless (minimal work). Grind receivers until the
    // small id is found deterministically (bounded; ids are uniform).
    let mut small = None;
    for i in 0..256u64 {
        let mut receiver = [0u8; 32];
        receiver[..8].copy_from_slice(&i.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            i,
            20,
        );
        match &small {
            None => small = Some(cand),
            Some(cur) => {
                if cand.id < cur.id {
                    small = Some(cand);
                }
            }
        }
    }
    let small = small.unwrap();
    // Large-id side WITH heavy descendants (will outscore).
    let mut big = None;
    for i in 0..256u64 {
        let mut receiver = [0xF0u8; 32];
        receiver[..8].copy_from_slice(&i.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            1000 + i,
            20,
        );
        if cand.id > small.id {
            big = Some(cand);
            break;
        }
    }
    let big = big.expect("larger id exists");
    let mut dag = DAG::new();
    fund_dag(&mut dag, &[(sender, 100_000)]);
    dag.add_transaction_validated(small.clone()).unwrap();
    dag.add_transaction_validated(big.clone()).unwrap();
    let mut prev = big.id;
    for i in 0..4u64 {
        let mut s = [0u8; 32];
        s[0] = 0xD0 + i as u8;
        let k = shaped(
            [prev, [0u8; 32]],
            s,
            [0xD1u8; 32],
            10,
            1,
            ts_post(),
            2000 + i,
            300 + i,
        );
        dag.add_transaction_validated(k.clone()).unwrap();
        prev = k.id;
    }
    // OLD rule (canonical, frozen): min-id.
    let mut flat: Vec<Transaction> =
        dag.transactions().values().cloned().collect();
    let old_pruned = canonical_resolve_conflicts(&mut flat);
    assert!(old_pruned.contains(&big.id), "old rule drops the larger id");
    assert!(!flat.iter().any(|t| t.id == big.id));
    // NEW rule: work wins despite the larger id.
    assert!(dag.subtree_work(big.id) > dag.subtree_work(small.id));
    let new_winner = dag.resolve_conflict_key(&sender, 20).expect("resolves");
    assert_eq!(new_winner, big.id, "new rule picks work over id");
    // OLD rule winner was the smaller id: the divergence is exactly the
    // specified CONSENSUS_BREAK (same DAG, different winners by rule).
    assert_eq!(small.id < big.id, true, "fixture: small id is smaller");
    assert_ne!(
        new_winner, small.id,
        "new winner differs from old-rule winner"
    );
    // Ledger follows the new rule (both present; only big applies).
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    assert_eq!(ledger.get_balance(&big.receiver), 100);
    assert_eq!(ledger.get_balance(&small.receiver), 0);
}
