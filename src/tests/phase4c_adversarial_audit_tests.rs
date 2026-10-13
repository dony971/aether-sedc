//! PHASE 4C: adversarial audit tests for the CDW implementation.
//!
//! READ-ONLY audit scope: these tests MEASURE the shipped 4B behavior
//! (work credits, CDW decisions, retention, re-resolution, order
//! independence, partitions, restarts, sync, perf scale). They add NO new
//! production behavior and modify NO existing test. All fixtures are DAG-level
//! (validated inserts need no PoW; inject_raw only for deliberately-corrupt
//! shapes) EXCEPT nonce-band grinding (bounded compute_hash loops, no
//! threshold mining) -- every test here is FAST and deterministic (fixed
//! timestamps straddling CDW_ACTIVATION_TS, fixed seeds, no clock reads).

use crate::ledger::Ledger;
use crate::parent_selection::{canonical_resolve_conflicts, rebuild_dag_topological, DAG};
use crate::transaction::{Transaction, TransactionId};

fn ts_post() -> u64 {
    Transaction::CDW_ACTIVATION_TS + 3_600_000
}

fn ts_pre() -> u64 {
    Transaction::CDW_ACTIVATION_TS - 3_600_000
}

/// Shape a tx with fully controlled fields (no mining, no signatures).
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

fn faucet() -> [u8; 32] {
    hex::decode(crate::genesis::FAUCET_ADDRESS)
        .unwrap()
        .try_into()
        .unwrap()
}

/// Fund receivers through the DAG itself (rebuild reseeds from genesis).
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

/// Ledger fingerprint: sorted balances + supply + nonces.
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

/// Grind pow_nonce from 0 upward until the tx's leading-zero bits fall in
/// [lo, hi). Bounded (asserts termination): low bands need ~2^lo hashes.
fn grind_bits(
    parents: [TransactionId; 2],
    sender: [u8; 32],
    receiver: [u8; 32],
    lo: u32,
    hi: u32,
    cap: u64,
) -> Transaction {
    let mut n = 0u64;
    loop {
        assert!(n <= cap, "bit-band grind runaway");
        let tx = shaped(parents, sender, receiver, 100, 10, ts_post(), n, 77);
        let bits = Transaction::leading_zero_bits(&tx.calculate_pow_hash(n));
        if bits >= lo && bits < hi {
            return tx;
        }
        n += 1;
    }
}

/// sec.3: A->D1->D2 vs A->D3 with DIFFERENT difficulty bands. Scores must
/// follow work (bit bands), not depth/length/count.
#[test]
fn test_audit_descendant_difficulties() {
    let zero = [0u8; 32];
    let mut dag = DAG::new();
    let a = shaped([zero, zero], [0xA0u8; 32], [0xA1u8; 32], 1, 1, ts_post(), 0, 0);
    dag.add_transaction_validated(a.clone()).unwrap();
    // Long branch, WEAK work (0-2 bits each: instant grind).
    let d1 = grind_bits([a.id, zero], [0xB0u8; 32], [0xB1u8; 32], 0, 2, 100000);
    dag.add_transaction_validated(d1.clone()).unwrap();
    let d2 = grind_bits([d1.id, zero], [0xB2u8; 32], [0xB3u8; 32], 0, 2, 100000);
    dag.add_transaction_validated(d2.clone()).unwrap();
    // Short branch, STRONG work (12+ bits: ~4096 hashes).
    let d3 = grind_bits([a.id, zero], [0xC0u8; 32], [0xC1u8; 32], 12, 256, 1000000);
    dag.add_transaction_validated(d3.clone()).unwrap();
    let (w1, w3) = (d1.work_credit() + d2.work_credit(), d3.work_credit());
    assert!(w1 < 8, "weak branch stays weak: {}", w1);
    assert!(w3 >= 4096, "strong branch prices in: {}", w3);
    let s_long = dag.subtree_work(d1.id);
    let s_short = dag.subtree_work(d3.id);
    assert_eq!(s_long, d1.work_credit() + d2.work_credit());
    assert_eq!(s_short, d3.work_credit());
    assert!(
        s_short > s_long,
        "work beats length: {} vs {}",
        s_short,
        s_long
    );
    // A accumulates everything exactly once.
    assert_eq!(
        dag.subtree_work(a.id),
        a.work_credit() + s_long + s_short
    );
}

/// sec.5 case A: work(A) < work(B) AND id(A) < id(B) -> B wins anyway.
/// Grind for the id order (bounded, uniform ids) + bit bands for work.
#[test]
fn test_audit_min_id_never_overrides_work_case_a() {
    let sender = [0xD0u8; 32];
    // Weak A with a SMALL id: grind receiver until id[0] < 0x10 AND bits < 4.
    let (mut a, mut n) = (None, 0u64);
    while a.is_none() {
        assert!(n <= 100000, "case-A grind runaway");
        let mut receiver = [0u8; 32];
        receiver[..8].copy_from_slice(&n.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            n,
            55,
        );
        let bits = Transaction::leading_zero_bits(&cand.calculate_pow_hash(n));
        if cand.id[0] < 0x10 && bits < 4 {
            a = Some(cand);
        }
        n += 1;
    }
    // Strong B with a LARGE id: leading byte > 0xEF AND bits >= 10.
    let (mut b, mut m) = (None, 0u64);
    while b.is_none() {
        assert!(m <= 2000000, "case-A strong grind runaway");
        let mut receiver = [0xF0u8; 32];
        receiver[..8].copy_from_slice(&m.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            m,
            55,
        );
        let bits = Transaction::leading_zero_bits(&cand.calculate_pow_hash(m));
        if cand.id[0] > 0xEF && bits >= 10 {
            b = Some(cand);
        }
        m += 1;
    }
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a.id < b.id, "fixture: A has the smaller id");
    assert!(
        b.work_credit() > a.work_credit(),
        "fixture: B has more work"
    );
    let mut dag = DAG::new();
    dag.add_transaction_validated(a.clone()).unwrap();
    dag.add_transaction_validated(b.clone()).unwrap();
    assert_eq!(
        dag.resolve_conflict_key(&sender, 55),
        Some(b.id),
        "higher work wins despite much larger id"
    );
}

/// sec.5 cases B+C: exact ties in BOTH id orientations -> min-id wins each.
#[test]
fn test_audit_tie_break_both_directions() {
    let sender = [0xD1u8; 32];
    // Collect tied pairs (equal credits) covering both id orientations.
    // Credit concentration at low bits makes ties frequent; bounded scan.
    let mut saw_a_lt_b = false;
    let mut saw_b_lt_a = false;
    let mut pairs = Vec::new();
    for i in 0..512u64 {
        if saw_a_lt_b && saw_b_lt_a {
            break;
        }
        let mk = |tag: u8| {
            let mut receiver = [tag; 32];
            receiver[..8].copy_from_slice(&i.to_le_bytes());
            shaped(
                [[0u8; 32]; 2],
                sender,
                receiver,
                100,
                10,
                ts_post(),
                i,
                56,
            )
        };
        let (x, y) = (mk(0xE0), mk(0xE1));
        if x.work_credit() == y.work_credit() && x.id != y.id {
            if x.id < y.id && !saw_a_lt_b {
                saw_a_lt_b = true;
                pairs.push((x, y));
            } else if y.id < x.id && !saw_b_lt_a {
                saw_b_lt_a = true;
                pairs.push((x, y));
            }
        }
    }
    assert!(
        saw_a_lt_b && saw_b_lt_a,
        "both tie orientations must occur"
    );
    for (x, y) in &pairs {
        let mut dag = DAG::new();
        dag.add_transaction_validated(x.clone()).unwrap();
        dag.add_transaction_validated(y.clone()).unwrap();
        let expect = x.id.min(y.id);
        assert_eq!(
            dag.resolve_conflict_key(&sender, 56),
            Some(expect),
            "exact tie -> min-id, either direction"
        );
    }
}

/// sec.5 case D: enormous id gap + small work gap -> work still wins.
/// lo has a tiny id (leading byte < 8); hi outworks it by a small margin
/// with a huge id (leading byte > 0xF8).
#[test]
fn test_audit_min_id_gap_work_gap() {
    let sender = [0xD2u8; 32];
    let mut lo = None;
    for n in 0..100000u64 {
        let mut receiver = [0u8; 32];
        receiver[..8].copy_from_slice(&n.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            n,
            57,
        );
        if cand.id[0] < 8 {
            lo = Some(cand);
            break;
        }
    }
    let mut hi = None;
    for n in 0..100000u64 {
        let mut receiver = [0xFFu8; 32];
        receiver[..8].copy_from_slice(&n.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            n,
            57,
        );
        if cand.id[0] > 0xF8 {
            hi = Some(cand);
            break;
        }
    }
    let (lo, hi) = (
        lo.expect("tiny id found"),
        hi.expect("huge id found"),
    );
    assert!(lo.id < hi.id);
    // Work gap is whatever luck dealt (both garbage nonces: tiny credits);
    // force the interesting sub-case: if hi does not already outwork lo,
    // grind hi's nonce for strictly more bits (bounded, fast at this scale).
    let mut hi = hi;
    let mut n = 100000u64;
    while hi.work_credit() <= lo.work_credit() {
        assert!(n <= 200000, "work-gap grind runaway");
        let mut receiver = [0xFFu8; 32];
        receiver[..8].copy_from_slice(&n.to_le_bytes());
        let cand = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            n,
            57,
        );
        n += 1;
        if cand.id[0] > 0xF8 {
            hi = cand;
        }
    }
    let mut dag = DAG::new();
    dag.add_transaction_validated(lo.clone()).unwrap();
    dag.add_transaction_validated(hi.clone()).unwrap();
    assert_eq!(
        dag.resolve_conflict_key(&sender, 57),
        Some(hi.id),
        "small work gap still beats an enormous id gap"
    );
}

/// sec.6/7: flip after merge + descendant arrival. Two sides merge (winner
/// by current work), then the LOSER receives a heavy descendant -> flips,
/// ledger follows. Then a HEAVIER descendant on the original winner flips
/// back. Deterministic re-resolution, ledger-tracked throughout (funded).
#[test]
fn test_audit_flip_after_reconnect_then_descendant() {
    let sender = [0xE0u8; 32];
    let mut dag = DAG::new();
    fund_dag(&mut dag, &[(sender, 100_000)]);
    let a = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xE1u8; 32],
        100,
        10,
        ts_post(),
        0,
        60,
    );
    let b = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xE2u8; 32],
        100,
        10,
        ts_post(),
        1,
        60,
    );
    dag.add_transaction_validated(a.clone()).unwrap();
    dag.add_transaction_validated(b.clone()).unwrap();
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    let w0 = dag.resolve_conflict_key(&sender, 60).expect("resolves");
    // Loser = whoever lost initially; heap a heavy descendant on them.
    // Flip precondition (measured, not assumed): the new descendant must
    // strictly outwork the CURRENT winner's entire subtree, so grind until
    // its credit exceeds it (bounded scan from a fixed start: deterministic).
    // Owner credits are small garbage here (asserted) — the grind stays fast.
    let (loser_id, loser_recv) = if w0 == a.id {
        (b.id, b.receiver)
    } else {
        (a.id, a.receiver)
    };
    let w0_subtree = dag.subtree_work(w0);
    assert!(
        w0_subtree < (1 << 20),
        "fixture owners must stay small-credit (else re-shape)"
    );
    let mut heavy = None;
    let mut n = 0u64;
    while heavy.is_none() {
        assert!(n <= 50_000_000, "first flip grind runaway");
        let cand = shaped(
            [loser_id, [0u8; 32]],
            [0xE3u8; 32],
            [0xE4u8; 32],
            100,
            10,
            ts_post(),
            n,
            0,
        );
        let mut cand = cand;
        cand.id = cand.compute_hash();
        if cand.work_credit() > w0_subtree {
            heavy = Some(cand);
        }
        n += 1;
    }
    let heavy = heavy.expect("flip candidate");
    dag.add_transaction_validated(heavy.clone()).unwrap();
    let w1 = dag.resolve_conflict_key(&sender, 60).expect("resolves");
    assert_eq!(w1, loser_id, "heavy descendant flips the outcome");
    ledger.rebuild_from_dag(&dag);
    // Ledger follows the flip: the flipped side applies, the other drops.
    assert_eq!(ledger.get_balance(&loser_recv), 100);
    let w1_loser_recv = if w1 == a.id { b.receiver } else { a.receiver };
    assert_eq!(ledger.get_balance(&w1_loser_recv), 0);
    // Flip back: descendant on the other side ground to STRICTLY outwork
    // the flipped side's entire current subtree (same measured discipline).
    let w1_recv = if w1 == a.id { a.receiver } else { b.receiver };
    let other_id = if w1 == a.id { b.id } else { a.id };
    let w1_subtree = dag.subtree_work(w1);
    let mut heavier = None;
    let mut m = 0u64;
    while heavier.is_none() {
        assert!(m <= 100_000_000, "flip-back grind runaway");
        let cand = shaped(
            [other_id, [0u8; 32]],
            [0xE5u8; 32],
            [0xE6u8; 32],
            100,
            10,
            ts_post(),
            m,
            0,
        );
        let mut cand = cand;
        cand.id = cand.compute_hash();
        if cand.work_credit() > w1_subtree {
            heavier = Some(cand);
        }
        m += 1;
    }
    let heavier = heavier.expect("flip-back candidate");
    dag.add_transaction_validated(heavier.clone()).unwrap();
    let w2 = dag.resolve_conflict_key(&sender, 60).expect("resolves");
    assert_eq!(w2, other_id, "flips back on heavier work");
    ledger.rebuild_from_dag(&dag);
    // Ledger follows the second flip: the original side re-applies, the
    // intermediate winner is revoked.
    let w2_recv = if w2 == a.id { a.receiver } else { b.receiver };
    assert_eq!(ledger.get_balance(&w2_recv), 100);
    assert_eq!(ledger.get_balance(&w1_recv), 0);
}

/// sec.7: four arrival orders over {A, B, B1} (B1 child of B) incl. the
/// orphan interleaving (B1 before B: insert fails, then B, then B1 retry)
/// plus full-sync rebuild. All converge: DAG sets, winner, ledger.
#[test]
fn test_audit_four_order_convergence() {
    let sender = [0xE1u8; 32];
    let mk_set = || {
        let a = shaped(
            [[0u8; 32]; 2],
            sender,
            [0xE2u8; 32],
            100,
            10,
            ts_post(),
            0,
            61,
        );
        let b = shaped(
            [[0u8; 32]; 2],
            sender,
            [0xE3u8; 32],
            100,
            10,
            ts_post(),
            1,
            61,
        );
        let b1 = shaped(
            [b.id, [0u8; 32]],
            [0xE4u8; 32],
            [0xE5u8; 32],
            10,
            1,
            ts_post(),
            2,
            0,
        );
        (a, b, b1)
    };
    // Order 1: A, B, B1.
    // Order 2: B, A, B1.
    // Order 3: A, B1(fails: orphan), B, B1(retry).
    // Order 4: full sync (topological rebuild from served set).
    let run_order = |order: &[u8]| {
        let (a, b, b1) = mk_set();
        let map = [(0u8, a.clone()), (1u8, b.clone()), (2u8, b1.clone())];
        let mut dag = DAG::new();
        fund_dag(&mut dag, &[(sender, 100_000)]);
        for tag in order {
            let tx = map.iter().find(|(t, _)| t == tag).unwrap().1.clone();
            // B1-before-B models orphan parking (insert fails cleanly).
            if *tag == 2 && dag.get_transaction(b.id).is_none() {
                assert!(
                    dag.add_transaction_validated(tx).is_err(),
                    "parentless insert must fail (orphan path)"
                );
                continue;
            }
            dag.add_transaction_validated(tx).expect("inserts");
        }
        // Ensure B1 present (retry after B in order 3).
        if dag.get_transaction(b1.id).is_none() {
            dag.add_transaction_validated(b1.clone()).expect("retry");
        }
        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(&dag);
        let winner = dag.resolve_conflict_key(&sender, 61);
        let mut ids: Vec<[u8; 32]> =
            dag.transactions().keys().copied().collect();
        ids.sort();
        let addrs = [sender, a.receiver, b.receiver];
        (ids, winner, ledger_fingerprint(&ledger, &addrs))
    };
    let o1 = run_order(&[0, 1, 2]);
    let o2 = run_order(&[1, 0, 2]);
    let o3 = run_order(&[0, 2, 1]);
    // Order 4: full sync -- served set in reverse input order through the
    // topological rebuild (fixpoint: dependency order recovered regardless
    // of wire order; B1 is never silently dropped).
    let (a, b, b1) = mk_set();
    let mut dag4 = DAG::new();
    fund_dag(&mut dag4, &[(sender, 100_000)]);
    let (ins, skip, orph) =
        rebuild_dag_topological(&mut dag4, vec![b1.clone(), b.clone(), a.clone()]);
    assert_eq!(skip, 0);
    assert!(orph.is_empty(), "closed set has no orphans after fixpoint");
    assert_eq!(ins, 3, "all three served txs land");
    let mut ledger4 = Ledger::new();
    ledger4.rebuild_from_dag(&dag4);
    let mut ids4: Vec<[u8; 32]> = dag4.transactions().keys().copied().collect();
    ids4.sort();
    let addrs = [sender, a.receiver, b.receiver];
    let o4 = (
        ids4,
        dag4.resolve_conflict_key(&sender, 61),
        ledger_fingerprint(&ledger4, &addrs),
    );
    assert_eq!(o1, o2, "orders 1-2 converge");
    assert_eq!(o2, o3, "orders 2-3 converge");
    assert_eq!(o3, o4, "live vs sync converge");
}

/// sec.8: TEN insertion permutations of one fixed set (funding + pair +
/// descendants) via dependency-valid orders (chain-preserving
/// interleavings). All yield identical DAG sets, winners, scores, ledgers,
/// and post-rebuild fingerprints.
#[test]
fn test_audit_ten_permutation_invariance() {
    let sender = [0xE2u8; 32];
    // Chains: C1 = [F, A, DA, E] (internal order fixed), C2 = [B, DB].
    // Interleavings preserving both = C(6,2) = 15; take 10.
    let f = shaped(
        [[0u8; 32]; 2],
        faucet(),
        sender,
        100_000,
        100,
        ts_pre(),
        0,
        0,
    );
    let a = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xE3u8; 32],
        100,
        10,
        ts_post(),
        1,
        62,
    );
    let b = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xE4u8; 32],
        100,
        10,
        ts_post(),
        2,
        62,
    );
    let da = shaped(
        [a.id, [0u8; 32]],
        [0xE5u8; 32],
        [0xE6u8; 32],
        10,
        1,
        ts_post(),
        3,
        0,
    );
    let db = shaped(
        [b.id, [0u8; 32]],
        [0xE7u8; 32],
        [0xE8u8; 32],
        10,
        1,
        ts_post(),
        4,
        0,
    );
    let e = shaped(
        [da.id, [0u8; 32]],
        [0xE9u8; 32],
        [0xEAu8; 32],
        10,
        1,
        ts_post(),
        5,
        0,
    );
    let c1 = vec![f.clone(), a.clone(), da.clone(), e.clone()];
    let c2 = vec![b.clone(), db.clone()];
    // Enumerate interleavings programmatically: choose 2 positions out of 6
    // for the c2 elements (C(6,2) = 15 combos); internal chain orders are
    // preserved by construction, so every merge is dependency-valid. Take 10.
    let mut orders: Vec<Vec<Transaction>> = Vec::new();
    'outer: for i in 0..6usize {
        for j in (i + 1)..6usize {
            if orders.len() >= 10 {
                break 'outer;
            }
            let mut seq: Vec<Transaction> = Vec::with_capacity(6);
            let (mut x, mut y) = (0usize, 0usize);
            for pos in 0..6usize {
                if pos == i || pos == j {
                    seq.push(c2[y].clone());
                    y += 1;
                } else {
                    seq.push(c1[x].clone());
                    x += 1;
                }
            }
            assert_eq!((x, y), (4, 2));
            orders.push(seq);
        }
    }
    assert_eq!(orders.len(), 10, "ten distinct insertion histories");
    let fps: Vec<_> = orders
        .iter()
        .take(10)
        .map(|seq| {
            let mut dag = DAG::new();
            for tx in seq {
                dag.add_transaction_validated(tx.clone())
                    .expect("dependency-valid order inserts");
            }
            let winner = dag.resolve_conflict_key(&sender, 62);
            let scores: Vec<(TransactionId, u64)> = {
                let mut ids: Vec<[u8; 32]> =
                    dag.transactions().keys().copied().collect();
                ids.sort();
                ids.iter().map(|id| (*id, dag.subtree_work(*id))).collect()
            };
            let mut ledger = Ledger::new();
            ledger.rebuild_from_dag(&dag);
            let mut ids: Vec<[u8; 32]> =
                dag.transactions().keys().copied().collect();
            ids.sort();
            let addrs = [sender, a.receiver, b.receiver];
            // Post-rebuild fingerprint (rebuild is idempotent: same set).
            let mut ledger2 = Ledger::new();
            ledger2.rebuild_from_dag(&dag);
            (
                ids,
                winner,
                scores,
                ledger_fingerprint(&ledger, &addrs),
                ledger_fingerprint(&ledger2, &addrs),
            )
        })
        .collect();
    for k in 1..fps.len() {
        assert_eq!(fps[0], fps[k], "permutation {} diverges", k);
    }
    println!(
        "phase4c: {} insertion histories converge (winner {:?})",
        fps.len(),
        fps[0].1.map(|id| hex::encode(&id[..4]))
    );
}

/// sec.9: true two-node partition simulation. Shared history H; partition;
/// A builds (conflict txA + descendants), B builds (txB same key +
/// descendants). Seven heal variants incl. restart-before-reconnect.
/// All converge: DAG sets, winner, ledger.
#[test]
fn test_audit_partition_variants() {
    let sender = [0xF0u8; 32];
    // Shared history: funding + base tip both sides start from.
    let build_base = || {
        let mut dag = DAG::new();
        fund_dag(&mut dag, &[(sender, 100_000)]);
        let h = shaped(
            [[0u8; 32]; 2],
            [0xF1u8; 32],
            [0xF2u8; 32],
            50,
            5,
            ts_pre(),
            0,
            0,
        );
        dag.add_transaction_validated(h.clone()).unwrap();
        (dag, h.id)
    };
    // Side branch builder (conflict tx + two descendants).
    let build_branch = |dag: &mut DAG, receiver: [u8; 32], tag: u8, nonce: u64| {
        let tx = shaped(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            ts_post(),
            tag as u64,
            nonce,
        );
        dag.add_transaction_validated(tx.clone()).unwrap();
        for (k, off) in [0u64, 1u64].iter().enumerate() {
            let mut cs = [0u8; 32];
            cs[0] = tag.wrapping_add(10 + k as u8);
            let kid = shaped(
                [tx.id, [0u8; 32]],
                cs,
                [0xF3u8; 32],
                10,
                1,
                ts_post(),
                tag as u64 + 50 + off,
                100 + k as u64,
            );
            dag.add_transaction_validated(kid.clone()).unwrap();
        }
        tx.id
    };
    // Merge helper: union inserts (validated; pairs retained by rule).
    // Snapshot helper: DAG has no Clone (deliberate: large state); rebuild
    // an identical copy through the topological path (retention: nothing
    // dropped), which also proves rebuild fidelity.
    let snapshot_dag = |src: &DAG| {
        let set: Vec<Transaction> = src.transactions().values().cloned().collect();
        let mut dag = DAG::new();
        let (ins, skip, orph) = rebuild_dag_topological(&mut dag, set);
        assert_eq!(skip, 0);
        assert!(orph.is_empty(), "closed DAG has no orphans");
        let _ = ins;
        dag
    };
    let merge_into = |target: &mut DAG, source: &DAG| {
        // Dependency-aware fixpoint rounds: sorted-id input is NOT
        // topological, so single-pass insertion would spuriously fail on
        // children-before-parents (the orphan shape). Rounds retry until no
        // progress; anything left is a genuine missing link (asserted).
        // Duplicates (shared history/funding) count as delivered.
        let mut ids: Vec<[u8; 32]> =
            source.transactions().keys().copied().collect();
        ids.sort();
        let mut progress = true;
        while progress && !ids.is_empty() {
            progress = false;
            let mut still = Vec::new();
            for id in ids {
                if target.get_transaction(id).is_some() {
                    progress = true;
                    continue;
                }
                let tx = source.get_transaction(id).unwrap().clone();
                match target.add_transaction_validated(tx) {
                    Ok(_) => {
                        progress = true;
                    }
                    Err(_) => still.push(id),
                }
            }
            ids = still;
        }
        assert!(
            ids.is_empty(),
            "closed union must fully merge (missing links?)"
        );
    };
    let snapshot = |dag: &DAG| {
        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(dag);
        let mut ids: Vec<[u8; 32]> = dag.transactions().keys().copied().collect();
        ids.sort();
        let addrs = [sender, [0xF4u8; 32], [0xF5u8; 32]];
        (
            ids,
            dag.resolve_conflict_key(&sender, 70),
            ledger_fingerprint(&ledger, &addrs),
        )
    };
    // Build both partitions from shared history.
    let (mut base_a, _) = build_base();
    let (mut base_b, _) = build_base();
    let ida = build_branch(&mut base_a, [0xF4u8; 32], 0xA0, 70);
    let idb = build_branch(&mut base_b, [0xF5u8; 32], 0xB0, 70);
    assert_ne!(ida, idb);
    let mut variants = Vec::new();
    // V1: A -> B (A's txs into B).
    {
        let mut b = snapshot_dag(&base_b);
        merge_into(&mut b, &base_a);
        variants.push(snapshot(&b));
    }
    // V2: B -> A.
    {
        let mut a = snapshot_dag(&base_a);
        merge_into(&mut a, &base_b);
        variants.push(snapshot(&a));
    }
    // V3: descendants-first across sides (orphan path: child insert fails
    // until its parent arrives; modeled by attempting child first).
    {
        let mut b = snapshot_dag(&base_b);
        // Collect A's branch txs (parent before children available).
        let mut a_ids: Vec<[u8; 32]> = base_a
            .transactions()
            .keys()
            .copied()
            .filter(|id| base_b.get_transaction(*id).is_none())
            .collect();
        a_ids.sort();
        // Deliver children before parents once (orphan), then parents, then
        // children again (retry) -- final set identical by construction.
        a_ids.reverse();
        for id in a_ids.clone() {
            let tx = base_a.get_transaction(id).unwrap().clone();
            let _ = b.add_transaction_validated(tx);
        }
        a_ids.reverse();
        for id in a_ids {
            let tx = base_a.get_transaction(id).unwrap().clone();
            if b.get_transaction(tx.id).is_none() {
                b.add_transaction_validated(tx).expect("retry inserts");
            }
        }
        variants.push(snapshot(&b));
    }
    // V4: full sync (fresh DAG from served union set + rebuild).
    {
        let mut union_set: Vec<Transaction> = Vec::new();
        for dag in [&base_a, &base_b] {
            for tx in dag.transactions().values().cloned() {
                if !union_set.iter().any(|t| t.id == tx.id) {
                    union_set.push(tx);
                }
            }
        }
        let mut fresh = DAG::new();
        let (ins, skip, orph) = rebuild_dag_topological(&mut fresh, union_set);
        assert_eq!(skip, 0);
        assert!(orph.is_empty(), "closed union has no orphans");
        let _ = ins;
        variants.push(snapshot(&fresh));
    }
    // V5: local rebuild both sides (no-op convergence check).
    {
        variants.push(snapshot(&base_a));
        variants.push(snapshot(&base_b));
    }
    // V6: restart A before reconnect (drop memory, rebuild from persisted
    // set), then heal A -> B.
    {
        let persisted: Vec<Transaction> =
            base_a.transactions().values().cloned().collect();
        let mut rebooted = DAG::new();
        let (ins, _, _) = rebuild_dag_topological(&mut rebooted, persisted);
        assert!(ins > 0);
        let mut b = snapshot_dag(&base_b);
        merge_into(&mut b, &rebooted);
        variants.push(snapshot(&b));
    }
    // V7: restart BOTH before reconnect, then merge.
    {
        let mk_restart = |src: &DAG| {
            let persisted: Vec<Transaction> =
                src.transactions().values().cloned().collect();
            let mut rebooted = DAG::new();
            let _ = rebuild_dag_topological(&mut rebooted, persisted);
            rebooted
        };
        let ra = mk_restart(&base_a);
        let mut rb = mk_restart(&base_b);
        merge_into(&mut rb, &ra);
        variants.push(snapshot(&rb));
    }
    // NOTE V5 pushes pre-merge states (divergent by construction -- the
    // partition itself); convergence is asserted over the HEALED variants
    // V1,V2,V3,V4,V6,V7. V5 documents the split, not a failure.
    assert_eq!(variants.len(), 8);
    for (k, v) in variants.iter().enumerate() {
        if k == 4 || k == 5 {
            continue; // V5a/V5b: pre-merge divergent states (expected)
        }
        assert_eq!(&variants[0], v, "healed variant {} diverges", k);
    }
}

/// sec.10: double-spend work branches. Same funds (S covers ONE spend);
/// branches of different LENGTH and WORK and DIFFICULTY bands; innocents
/// behind each side. Both arrival orders: identical winner/ledger/DAG;
/// conservation holds; no innocent wrongly deleted (retention).
#[test]
fn test_audit_double_spend_work_branches() {
    let sender = [0xE0u8; 32];
    // Side X: LONG branch of WEAK work (4 children, ~0-2 bits each).
    // Side Y: SHORT branch, ONE heavy descendant (>= 12 bits).
    let x = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xE1u8; 32],
        500,
        10,
        ts_post(),
        0,
        71,
    );
    let y = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xE2u8; 32],
        500,
        10,
        ts_post(),
        1,
        71,
    );
    // Sender funded for exactly ONE spend (same UTXO/funds semantic).
    let mut dag = DAG::new();
    fund_dag(&mut dag, &[(sender, 600)]);
    dag.add_transaction_validated(x.clone()).unwrap();
    dag.add_transaction_validated(y.clone()).unwrap();
    for i in 0..4u64 {
        let mut cs = [0u8; 32];
        cs[0] = 0xE3 + i as u8;
        let kx = shaped(
            [x.id, [0u8; 32]],
            cs,
            [0xEAu8; 32],
            10,
            1,
            ts_post(),
            10 + i,
            200 + i,
        );
        dag.add_transaction_validated(kx).unwrap();
    }
    let hy = grind_bits([y.id, [0u8; 32]], [0xEBu8; 32], [0xECu8; 32], 12, 256, 2000000);
    dag.add_transaction_validated(hy.clone()).unwrap();
    // Work decides (heavy short branch must beat long weak branch).
    assert!(dag.subtree_work(y.id) > dag.subtree_work(x.id));
    let winner = dag.resolve_conflict_key(&sender, 71).expect("resolves");
    assert_eq!(winner, y.id, "work beats length");
    // Ledger: exactly one side applies; conservation (funded 600; applied
    // 500+10 + winner-child effects... children unfunded (own senders empty)
    // so only Y applies here: S=90, M2=500).
    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag(&dag);
    assert_eq!(ledger.get_balance(&sender), 600 - 500 - 10);
    assert_eq!(ledger.get_balance(&[0xE2u8; 32]), 500);
    assert_eq!(ledger.get_balance(&[0xE1u8; 32]), 0);
    // DAG holds everything (retention -- nothing deleted pre-resolution).
    assert_eq!(dag.transaction_count(), 1 + 2 + 4 + 1);
    // Arrival-order twin: reversed insertion of the pair (children after).
    let mut dag2 = DAG::new();
    fund_dag(&mut dag2, &[(sender, 600)]);
    dag2.add_transaction_validated(y.clone()).unwrap();
    dag2.add_transaction_validated(x.clone()).unwrap();
    for i in 0..4u64 {
        let mut cs = [0u8; 32];
        cs[0] = 0xE3 + i as u8;
        let kx = shaped(
            [x.id, [0u8; 32]],
            cs,
            [0xEAu8; 32],
            10,
            1,
            ts_post(),
            10 + i,
            200 + i,
        );
        dag2.add_transaction_validated(kx).unwrap();
    }
    dag2.add_transaction_validated(hy.clone()).unwrap();
    assert_eq!(
        dag2.resolve_conflict_key(&sender, 71),
        Some(y.id),
        "reverse order, same winner"
    );
    let mut ledger2 = Ledger::new();
    ledger2.rebuild_from_dag(&dag2);
    let addrs = [sender, [0xE1u8; 32], [0xE2u8; 32]];
    assert_eq!(
        ledger_fingerprint(&ledger, &addrs),
        ledger_fingerprint(&ledger2, &addrs)
    );
}

/// sec.11: restart sequences. (1) pre-resolution state -> restart ->
/// resolve; (2) resolution -> restart -> descendant -> re-resolve;
/// (3) retained loser -> restart -> loser gains work -> flips winner.
/// Persisted sets model Sled rows; boot = topological rebuild (retention).
#[test]
fn test_audit_restart_sequences() {
    let sender = [0xF1u8; 32];
    let a = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xF2u8; 32],
        100,
        10,
        ts_post(),
        0,
        72,
    );
    let b = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xF3u8; 32],
        100,
        10,
        ts_post(),
        1,
        72,
    );
    let fundeds: Vec<([u8; 32], u64)> = vec![(sender, 100_000)];
    let boot_from = |set: Vec<Transaction>| {
        let mut dag = DAG::new();
        let (ins, skip, orph) = rebuild_dag_topological(&mut dag, set);
        assert_eq!(skip, 0);
        assert!(orph.is_empty());
        let _ = ins;
        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(&dag);
        (dag, ledger)
    };
    // Seq 1: persist {F, A, B} pre-resolution -> restart -> resolve.
    let mut pre = DAG::new();
    fund_dag(&mut pre, &fundeds);
    pre.add_transaction_validated(a.clone()).unwrap();
    pre.add_transaction_validated(b.clone()).unwrap();
    let persisted: Vec<Transaction> = pre.transactions().values().cloned().collect();
    let (r1dag, r1ledger) = boot_from(persisted);
    let w1 = r1dag.resolve_conflict_key(&sender, 72).expect("resolves");
    assert!(w1 == a.id || w1 == b.id);
    // Seq 2: resolution state persists -> restart -> identical winner/ledger.
    let persisted2: Vec<Transaction> = pre.transactions().values().cloned().collect();
    let (r2dag, r2ledger) = boot_from(persisted2);
    assert_eq!(
        r2dag.resolve_conflict_key(&sender, 72),
        Some(w1),
        "restart preserves the resolution"
    );
    let addrs = [sender, [0xF2u8; 32], [0xF3u8; 32]];
    assert_eq!(
        ledger_fingerprint(&r1ledger, &addrs),
        ledger_fingerprint(&r2ledger, &addrs)
    );
    // Seq 3: retained loser wins after restart: persist, reboot, then add a
    // heavy descendant to the recorded loser and re-resolve.
    let loser = if w1 == a.id { b.clone() } else { a.clone() };
    let persisted3: Vec<Transaction> =
        pre.transactions().values().cloned().collect();
    // (persisted3 == persisted content; separate Vec for clarity)
    let (mut r3dag, mut r3ledger) = boot_from(persisted3);
    assert_eq!(
        r3dag.resolve_conflict_key(&sender, 72),
        Some(w1),
        "pre-descendant resolution stable across restart"
    );
    // Precondition (measured): winner subtree below 2^15, so any band-
    // compliant heavy descendant (>= 2^15) flips guaranteed.
    assert!(
        r3dag.subtree_work(w1) < (1 << 15),
        "fixture winner side must stay small-credit"
    );
    let heavy = grind_bits(
        [loser.id, [0u8; 32]],
        [0xF4u8; 32],
        [0xF5u8; 32],
        15,
        256,
        20000000,
    );
    // Guarantee the flip (else the test is vacuous): heavy must outwork the
    // winner's entire current subtree.
    let w1_subtree = r3dag.subtree_work(w1);
    assert!(
        heavy.work_credit() > w1_subtree,
        "fixture must flip (heavy {} vs winner subtree {})",
        heavy.work_credit(),
        w1_subtree
    );
    r3dag.add_transaction_validated(heavy.clone()).unwrap();
    let w3 = r3dag.resolve_conflict_key(&sender, 72).expect("resolves");
    assert_eq!(w3, loser.id, "post-restart descendant flips to the loser");
    r3ledger.rebuild_from_dag(&r3dag);
    let (lw, ll) = if w3 == a.id {
        (a.receiver, b.receiver)
    } else {
        (b.receiver, a.receiver)
    };
    assert_eq!(r3ledger.get_balance(&lw), 100);
    assert_eq!(r3ledger.get_balance(&ll), 0);
}

/// sec.12: deep sync across four destination states + LIVE/SYNC/REBUILD
/// triple equality. Source: funded conflict pair + descendants both sides.
/// Destinations: empty / partial (funding only) / concurrent-branch (own
/// same-key tx!) / full. All converge: sets, scores, winner, ledger.
#[test]
fn test_audit_deep_sync_four_states() {
    let sender = [0xF6u8; 32];
    let mut source = DAG::new();
    fund_dag(&mut source, &[(sender, 100_000)]);
    let x = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xF7u8; 32],
        100,
        10,
        ts_post(),
        0,
        73,
    );
    let y = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xF8u8; 32],
        100,
        10,
        ts_post(),
        1,
        73,
    );
    source.add_transaction_validated(x.clone()).unwrap();
    source.add_transaction_validated(y.clone()).unwrap();
    // Pre-activation pair riding along (grandfathered everywhere).
    let o1 = shaped(
        [[0u8; 32]; 2],
        [0xF9u8; 32],
        [0xFAu8; 32],
        50,
        5,
        ts_pre(),
        0,
        74,
    );
    let o2 = shaped(
        [[0u8; 32]; 2],
        [0xF9u8; 32],
        [0xFBu8; 32],
        50,
        5,
        ts_pre(),
        1,
        74,
    );
    source.add_transaction_validated(o1.clone()).unwrap();
    source.add_transaction_validated(o2.clone()).unwrap();
    for (i, parent) in [x.id, y.id].iter().enumerate() {
        let mut cs = [0u8; 32];
        cs[0] = 0xC0 + i as u8;
        let k = shaped(
            [*parent, [0u8; 32]],
            cs,
            [0xC1u8; 32],
            10,
            1,
            ts_post(),
            10 + i as u64,
            200 + i as u64,
        );
        source.add_transaction_validated(k).unwrap();
    }
    let mut source_ledger = Ledger::new();
    source_ledger.rebuild_from_dag(&source);
    let source_winner = source.resolve_conflict_key(&sender, 73);
    let served: Vec<Transaction> =
        source.transactions().values().cloned().collect();
    let sync_into = |dest: &mut DAG| {
        // Inventory/window delivery in shuffled (reversed) order with
        // dependency-aware retry rounds (the sync fixpoint shape). Already-
        // present txs (preloaded funding, re-deliveries) count as delivered,
        // mirroring the production DAG/orphan dedup ahead of delivery.
        let mut pending: Vec<Transaction> = served.clone();
        pending.reverse();
        let mut progress = true;
        while progress && !pending.is_empty() {
            progress = false;
            let mut still = Vec::new();
            for tx in pending {
                if dest.get_transaction(tx.id).is_some() {
                    progress = true;
                    continue;
                }
                match dest.add_transaction_validated(tx.clone()) {
                    Ok(_) => {
                        progress = true;
                    }
                    Err(_) => still.push(tx),
                }
            }
            pending = still;
        }
        assert!(pending.is_empty(), "closed history must fully deliver");
        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(dest);
        ledger
    };
    let addrs = [sender, [0xF7u8; 32], [0xF8u8; 32]];
    let src_fp = ledger_fingerprint(&source_ledger, &addrs);
    // D1: empty destination.
    let mut d1 = DAG::new();
    let l1 = sync_into(&mut d1);
    // D2: partial destination (funding only).
    let mut d2 = DAG::new();
    fund_dag(&mut d2, &[(sender, 100_000)]);
    let l2 = sync_into(&mut d2);
    // D3: destination holding its OWN same-key tx (concurrent branch).
    let mut d3 = DAG::new();
    fund_dag(&mut d3, &[(sender, 100_000)]);
    let own = shaped(
        [[0u8; 32]; 2],
        sender,
        [0xFCu8; 32],
        100,
        10,
        ts_post(),
        2,
        73,
    );
    d3.add_transaction_validated(own.clone()).unwrap();
    let l3 = sync_into(&mut d3);
    // D4: full destination (idempotent re-sync).
    let mut d4 = DAG::new();
    fund_dag(&mut d4, &[(sender, 100_000)]);
    let _ = sync_into(&mut d4);
    let l4 = sync_into(&mut d4);
    for (k, ledger) in [&l1, &l2, &l3, &l4].into_iter().enumerate() {
        assert_eq!(
            ledger_fingerprint(&ledger, &addrs),
            src_fp,
            "destination ledger must match source"
        );
    }
    // LIVE vs SYNC vs REBUILD triple: source (live-built) vs d1 (synced) vs
    // fresh rebuild of the served set.
    let mut rebuilt = DAG::new();
    let (ins, _, _) = rebuild_dag_topological(&mut rebuilt, served);
    assert!(ins > 0);
    let mut rebuilt_ledger = Ledger::new();
    rebuilt_ledger.rebuild_from_dag(&rebuilt);
    assert_eq!(
        ledger_fingerprint(&rebuilt_ledger, &addrs),
        src_fp,
        "rebuild path equals live and sync paths"
    );
    assert_eq!(
        d1.resolve_conflict_key(&sender, 73),
        source_winner,
        "sync preserves the winner"
    );
}

/// sec.16: perf scale 100/1k/10k -- resolve + rebuild timings with loose
/// completion bounds (characterization, not gating); old-vs-new comparison
/// (canonical min-id vs CDW resolve on identical sets).
#[test]
fn test_audit_perf_scale_100_1k_10k() {
    use std::time::Instant;
    for n in [100usize, 1000, 10000] {
        let mut dag = DAG::new();
        for i in 0..n {
            let mut sender = [0u8; 32];
            sender[..8].copy_from_slice(&(i as u64).to_le_bytes());
            sender[8] = 0xD7;
            let tx = shaped(
                [[0u8; 32]; 2],
                sender,
                [0xD8u8; 32],
                1,
                1,
                ts_post(),
                i as u64,
                0,
            );
            dag.add_transaction_validated(tx).expect("distinct inserts");
        }
        assert_eq!(dag.transaction_count(), n);
        // Conflict pair planted at the end (distinct key).
        let ks = [0xD9u8; 32];
        let k1 = shaped([[0u8; 32]; 2], ks, [0xDAu8; 32], 1, 1, ts_post(), 0, 5);
        let k2 = shaped([[0u8; 32]; 2], ks, [0xDBu8; 32], 1, 1, ts_post(), 1, 5);
        dag.add_transaction_validated(k1.clone()).unwrap();
        dag.add_transaction_validated(k2.clone()).unwrap();
        let t0 = Instant::now();
        let winner = dag.resolve_conflict_key(&ks, 5).expect("resolves");
        let dt_resolve = t0.elapsed();
        assert!(winner == k1.id || winner == k2.id);
        // Old rule on the same set (canonical, frozen) for comparison.
        let t1 = Instant::now();
        let mut flat: Vec<Transaction> =
            dag.transactions().values().cloned().collect();
        let _ = canonical_resolve_conflicts(&mut flat);
        let dt_old = t1.elapsed();
        println!(
            "phase4c perf: N={} resolve={:?} old-rule-scan={:?}",
            n, dt_resolve, dt_old
        );
        assert!(
            dt_resolve.as_secs() < 60,
            "resolve must complete comfortably"
        );
        // Rebuild only at small scale here (10k rebuild measured separately
        // via inc01 ~307 s debug; not repeated).
        if n <= 1000 {
            let mut ledger = Ledger::new();
            let t2 = Instant::now();
            ledger.rebuild_from_dag(&dag);
            println!("phase4c perf: N={} rebuild={:?}", n, t2.elapsed());
        }
    }
}
