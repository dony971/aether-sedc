//! M2 / F13 — vote indexation and complexity regression tests.
//!
//! ORACLE = `support_breakdown_reference` / `try_finalize_reference`
//! (test-only whole-registry scans, untouched by the optimization).
//! OPTIMIZED = production `support_breakdown` / `try_finalize` reading the
//! epoch-ordered `vote_index`.
//!
//! Every test fails on the slightest divergence (weights, vote-id sets,
//! winner, certificate, snapshot bytes, index invariant).

use crate::stake::{StakeRegistry, BOND_MATURATION_EPOCHS, MIN_STAKE};
use crate::transaction::{Vote, VOTE_FORMAT_VERSION};

const AT: u64 = 100;

fn addr(i: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0..8].copy_from_slice(&(i + 1).to_le_bytes());
    a
}

fn key_j(j: u64) -> ([u8; 32], u64) {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&j.to_le_bytes());
    s[8] = 0xCC;
    (s, j)
}

fn side(tag: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = tag;
    s
}

fn vote_of(validator: u64, epoch: u64, conflict: u64, side_tag: u8, tag: u64) -> Vote {
    let k = key_j(conflict);
    Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: 0,
        validator: addr(validator),
        epoch,
        conflict_sender: k.0,
        conflict_nonce: k.1,
        side: side(side_tag),
        stake_epoch: epoch,
        stake_amount: MIN_STAKE,
        parents: [[0u8; 32]; 2],
        signature: {
            let mut s = [0u8; 64];
            s[0..8].copy_from_slice(&tag.to_le_bytes());
            s[1..9].copy_from_slice(&(tag ^ 0xF13).to_le_bytes());
            s
        },
    }
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn bonded(n: u64, amount: u64) -> StakeRegistry {
    let mut reg = StakeRegistry::new();
    for i in 0..n {
        reg.apply_bond(addr(i), amount, 0).expect("bond");
    }
    reg
}

fn assert_opt_eq_ref<F>(reg: &StakeRegistry, key: ([u8; 32], u64), at: u64, desc: F)
where
    F: Fn(&[u8; 32]) -> bool + Copy,
{
    for s in [side(0), side(1), side(2), side(42)] {
        let oracle = reg.support_breakdown_reference(key, &s, at, desc);
        let opt = reg.support_breakdown(key, &s, at, desc);
        assert_eq!(oracle, opt, "oracle/optimized diverged at at={at}");
        assert_eq!(opt.0, reg.support_for(key, &s, at, desc));
    }
}

// ---------------------------------------------------------------------------
// 1. Oracle equivalence on deterministic pseudo-random datasets.
// ---------------------------------------------------------------------------
#[test]
fn f13_01_oracle_equivalence_random() {
    let mut reg = bonded(40, MIN_STAKE);
    let mut lcg = Lcg(0xF13_0001);
    for tag in 0..300u64 {
        let validator = lcg.below(40);
        let conflict = lcg.below(5);
        let epoch = 90 + lcg.below(13); // 90..=102, incl. future relative to AT
        let side_tag = match lcg.below(10) {
            0 => 42, // side inside the descendant closure of side(0)
            1 => 1,
            2 => 2,
            _ => 0,
        };
        reg.insert_vote(vote_of(validator, epoch, conflict, side_tag, tag));
    }
    assert!(reg.vote_index_is_consistent_for_test());
    let closure = |txid: &[u8; 32]| txid[0] == 42;
    for at in [89, 95, 99, 100, 101, 102, 110] {
        for conflict in 0..5 {
            assert_opt_eq_ref(&reg, key_j(conflict), at, closure);
        }
    }
    // Same data, arrival order reversed: identical decisions.
    let mut reversed = bonded(40, MIN_STAKE);
    let mut votes: Vec<Vote> = Vec::new();
    let mut lcg = Lcg(0xF13_0001);
    for tag in 0..300u64 {
        let validator = lcg.below(40);
        let conflict = lcg.below(5);
        let epoch = 90 + lcg.below(13);
        let side_tag = match lcg.below(10) {
            0 => 42,
            1 => 1,
            2 => 2,
            _ => 0,
        };
        votes.push(vote_of(validator, epoch, conflict, side_tag, tag));
    }
    for v in votes.into_iter().rev() {
        reversed.insert_vote(v);
    }
    assert_eq!(reg.snapshot(), reversed.snapshot(), "arrival order changed state");
    for at in [99, 100, 101] {
        for conflict in 0..5 {
            assert_opt_eq_ref(&reversed, key_j(conflict), at, closure);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Duplicates: same triple, same side (same or different bytes).
// ---------------------------------------------------------------------------
#[test]
fn f13_02_duplicates_keep_answer_and_canonical_slot() {
    let mut reg = bonded(3, 1000);
    let v1 = vote_of(0, AT, 7, 0, 11);
    let v2 = vote_of(0, AT, 7, 0, 22); // same triple+side, different signature
    assert_ne!(v1.id(), v2.id());
    assert_eq!(
        reg.insert_vote(v1.clone()),
        crate::stake::VoteInsertOutcome::Accepted
    );
    assert_eq!(
        reg.insert_vote(v1.clone()),
        crate::stake::VoteInsertOutcome::Duplicate
    );
    assert_eq!(
        reg.insert_vote(v2.clone()),
        crate::stake::VoteInsertOutcome::Duplicate
    );
    assert!(reg.vote_index_is_consistent_for_test());
    assert_eq!(reg.vote_index_epoch_len_for_test(), 1);
    let expected_id = std::cmp::min(v1.id(), v2.id());
    let (total, ids) = reg.support_breakdown(key_j(7), &side(0), AT, |_| false);
    assert_eq!(total, 1000);
    assert_eq!(ids, vec![expected_id], "canonical smallest id must win");
}

// ---------------------------------------------------------------------------
// 3. Votes from unbonded validators contribute nothing (not "admissible").
// ---------------------------------------------------------------------------
#[test]
fn f13_03_unbonded_validator_weight_zero() {
    let mut reg = bonded(2, 1000);
    // Never bonded: stored at registry level, weight zero at read time. Its
    // vote id still appears in the breakdown (the id set is "votes that
    // point at the side", weight is read live), exactly like the oracle.
    reg.insert_vote(vote_of(99, AT, 1, 0, 1));
    reg.insert_vote(vote_of(0, AT, 1, 0, 2));
    let (total, ids) = reg.support_breakdown(key_j(1), &side(0), AT, |_| false);
    assert_eq!(total, 1000, "unbonded validator must not add weight");
    assert_eq!(ids.len(), 2, "both sides' vote ids are listed");
    assert_eq!(
        reg.support_breakdown_reference(key_j(1), &side(0), AT, |_| false),
        (total, ids)
    );
}

// ---------------------------------------------------------------------------
// 4. Out-of-epoch votes: future never shadows, past selected by predecessor.
// ---------------------------------------------------------------------------
#[test]
fn f13_04_epoch_ordering_and_future_vote() {
    let mut reg = bonded(2, 1000);
    for (i, epoch) in [97u64, 98, 99, 100, 101].iter().enumerate() {
        reg.insert_vote(vote_of(0, *epoch, 3, (10 + i) as u8, *epoch));
    }
    let expected = |epoch: u64| -> Vec<[u8; 32]> {
        vec![vote_of(0, epoch, 3, (10 + (epoch - 97) as u8) as u8, epoch).id()]
    };
    for at in [97u64, 98, 99, 100, 101] {
        let (total, ids) = reg.support_breakdown(key_j(3), &side(10 + (at - 97) as u8), at, |_| false);
        assert_eq!(total, 1000, "at={at}");
        assert_eq!(ids, expected(at), "at={at}");
    }
    // Nothing at or before epoch 96.
    assert_eq!(
        reg.support_breakdown(key_j(3), &side(10), 96, |_| false),
        (0, Vec::new())
    );
    // Future vote (101) is inadmissible at 100 but admissible at 101.
    assert_eq!(
        reg.support_breakdown(key_j(3), &side(14), 100, |_| false),
        (0, Vec::new())
    );
    assert_eq!(
        reg.support_breakdown(key_j(3), &side(14), 101, |_| false),
        (1000, expected(101))
    );
    assert!(reg.vote_index_is_consistent_for_test());
}

// ---------------------------------------------------------------------------
// 5. Arrival order: covered in test 1 as well; here with equivocation.
// ---------------------------------------------------------------------------
#[test]
fn f13_05_arrival_order_with_equivocation() {
    let a = vote_of(0, AT, 5, 0, 1);
    let b = vote_of(0, AT, 5, 1, 2);
    let mut forward = bonded(3, 1000);
    let mut backward = bonded(3, 1000);
    forward.insert_vote(a.clone());
    forward.insert_vote(b.clone());
    backward.insert_vote(b);
    backward.insert_vote(a);
    assert_eq!(forward.snapshot(), backward.snapshot());
    for s in [side(0), side(1)] {
        assert_eq!(
            forward.support_breakdown(key_j(5), &s, AT, |_| false),
            backward.support_breakdown(key_j(5), &s, AT, |_| false)
        );
    }
    assert!(forward.vote_index_is_consistent_for_test());
    assert!(backward.vote_index_is_consistent_for_test());
    assert_eq!(forward.evidence_count(), 1);
    assert_eq!(backward.evidence_count(), 1);
}

// ---------------------------------------------------------------------------
// 6. Validator generation changes (maturation, unbond, re-bond).
// ---------------------------------------------------------------------------
#[test]
fn f13_06_validator_generation_changes() {
    let mut reg = StakeRegistry::new();
    reg.apply_bond(addr(0), 1000, 0).expect("bond");
    reg.insert_vote(vote_of(0, 0, 9, 0, 1));
    assert_eq!(
        reg.support_breakdown(key_j(9), &side(0), 0, |_| false).0,
        0,
        "bond not matured"
    );
    assert_eq!(
        reg.support_breakdown(key_j(9), &side(0), BOND_MATURATION_EPOCHS, |_| false)
            .0,
        1000
    );
    reg.apply_unbond(addr(0), 60).expect("unbond");
    assert_eq!(
        reg.support_breakdown(key_j(9), &side(0), 60, |_| false).0,
        0,
        "unbonding validator never weighs"
    );
    reg.apply_bond(addr(0), 1000, 61).expect("re-bond");
    assert_eq!(
        reg.support_breakdown(key_j(9), &side(0), 62, |_| false).0,
        0,
        "re-bond matures again"
    );
    assert_eq!(
        reg.support_breakdown(key_j(9), &side(0), 63, |_| false).0,
        2000,
        "both bonds weigh once matured"
    );
    assert_opt_eq_ref(&reg, key_j(9), 63, |_| false);
    assert_opt_eq_ref(&reg, key_j(9), 60, |_| false);
}

// ---------------------------------------------------------------------------
// 7. Quorum exactly reached.
// ---------------------------------------------------------------------------
#[test]
fn f13_07_quorum_exactly_reached() {
    let mut opt = bonded(3, 100);
    let mut oracle = bonded(3, 100);
    for i in 0..2 {
        opt.insert_vote(vote_of(i, 10, 2, 0, i));
        oracle.insert_vote(vote_of(i, 10, 2, 0, i));
    }
    let ro = oracle.try_finalize_reference(key_j(2), &[side(0)], 10, |_, _| false);
    let oo = opt.try_finalize(key_j(2), &[side(0)], 10, |_, _| false);
    assert_eq!(oo, ro);
    let rec = oo.expect("3*200 >= 2*300, quorum must be met");
    assert_eq!(rec.supporting_weight, 200);
    assert_eq!(rec.eligible_total, 300);
    assert_eq!(rec.supporting_votes.len(), 2);
    assert!(StakeRegistry::quorum_met(200, 300));
}

// ---------------------------------------------------------------------------
// 8. Quorum not reached.
// ---------------------------------------------------------------------------
#[test]
fn f13_08_quorum_not_reached() {
    let mut opt = bonded(3, 100);
    let mut oracle = bonded(3, 100);
    opt.insert_vote(vote_of(0, 10, 2, 0, 1));
    oracle.insert_vote(vote_of(0, 10, 2, 0, 1));
    let ro = oracle.try_finalize_reference(key_j(2), &[side(0)], 10, |_, _| false);
    let oo = opt.try_finalize(key_j(2), &[side(0)], 10, |_, _| false);
    assert_eq!(oo, ro);
    assert!(oo.is_none());
    assert!(!StakeRegistry::quorum_met(100, 300));
}

// ---------------------------------------------------------------------------
// 9. Contradictory votes (equivocation): evidence, slash, zero weight.
// ---------------------------------------------------------------------------
#[test]
fn f13_09_contradictory_votes() {
    let mut reg = bonded(4, 1000);
    reg.insert_vote(vote_of(1, 10, 4, 0, 1));
    let outcome = reg.insert_vote(vote_of(1, 10, 4, 1, 2));
    let evidence_id = match outcome {
        crate::stake::VoteInsertOutcome::Equivocated { evidence_id } => evidence_id,
        other => panic!("expected equivocation, got {other:?}"),
    };
    let evidence = reg.get_evidence(&evidence_id).expect("evidence kept");
    let (a, b) = evidence.votes().expect("both votes preserved");
    assert_ne!(a.side, b.side);
    assert_eq!(reg.evidence_count(), 1);
    assert_eq!(
        reg.validator_state(&addr(1)),
        Some(crate::stake::ValidatorState::Slashed)
    );
    // No double counting, no weight for the slashed validator. The canonical
    // slot vote (smallest id) may still be listed, but weighs zero.
    let (t0, ids0) = reg.support_breakdown(key_j(4), &side(0), 10, |_| false);
    let (t1, ids1) = reg.support_breakdown(key_j(4), &side(1), 10, |_| false);
    assert_eq!(t0, 0);
    assert_eq!(t1, 0);
    assert!(ids0.len() <= 1 && ids1.len() <= 1);
    assert_eq!(ids0.len() + ids1.len(), 1, "exactly one canonical slot vote");
    assert!(reg.vote_index_is_consistent_for_test());
    assert_opt_eq_ref(&reg, key_j(4), 10, |_| false);
}

// ---------------------------------------------------------------------------
// 10. Index reconstruction after a torn/partial update (fail-closed).
// ---------------------------------------------------------------------------
#[test]
fn f13_10_index_error_recovery() {
    let mut reg = bonded(4, 1000);
    for i in 0..4 {
        reg.insert_vote(vote_of(i, AT, 0, 0, i));
        reg.insert_vote(vote_of(i, AT, 1, 1, 10 + i));
    }
    let before = reg.support_breakdown(key_j(0), &side(0), AT, |_| false);
    assert!(before.0 > 0);
    let other = reg.support_breakdown(key_j(1), &side(1), AT, |_| false);
    // Simulate an index update torn for one key only.
    reg.drop_vote_index_for_key_for_test(key_j(0));
    assert!(!reg.vote_index_is_consistent_for_test());
    assert_eq!(
        reg.support_breakdown(key_j(0), &side(0), AT, |_| false),
        (0, Vec::new()),
        "missing index fails closed, never invents weight"
    );
    assert_eq!(
        reg.support_breakdown(key_j(1), &side(1), AT, |_| false),
        other,
        "other keys unaffected"
    );
    // Reconstruction from the authoritative map restores exact results.
    reg.rebuild_vote_index_for_test();
    assert!(reg.vote_index_is_consistent_for_test());
    assert_eq!(
        reg.support_breakdown(key_j(0), &side(0), AT, |_| false),
        before
    );
    assert_opt_eq_ref(&reg, key_j(0), AT, |_| false);
}

// ---------------------------------------------------------------------------
// 11. Persistence / restart: snapshot -> restore -> identical decisions.
// ---------------------------------------------------------------------------
#[test]
fn f13_11_snapshot_restore_and_restart() {
    let mut reg = bonded(6, 1000);
    // Controlled dataset: one vote per (validator, key, epoch), no accidental
    // canonical-slot replacement (which is a pre-existing restore edge case
    // outside F13; see F13-SECURITY-REVIEW.md).
    for validator in 0..6u64 {
        for conflict in 0..3u64 {
            for epoch in [95u64, 99, 100, 101] {
                reg.insert_vote(vote_of(
                    validator,
                    epoch,
                    conflict,
                    0,
                    validator * 1000 + conflict * 10 + (epoch - 90),
                ));
            }
        }
    }
    // An equivocation must survive the restart with its evidence (no further
    // vote is inserted on this triple afterwards).
    reg.insert_vote(vote_of(0, AT, 9, 0, 900));
    reg.insert_vote(vote_of(0, AT, 9, 1, 901));
    let before = reg.snapshot();
    let restored = StakeRegistry::restore(before.clone()).expect("restore");
    assert_eq!(restored.snapshot(), before, "snapshot bytes changed");
    assert_eq!(restored.evidence_count(), 1);
    assert_eq!(restored.evidence_count(), reg.evidence_count());
    assert!(restored.vote_index_is_consistent_for_test());
    for conflict in 0..3 {
        for at in [94u64, 95, 99, 100, 101] {
            for s in [side(0), side(1)] {
                assert_eq!(
                    restored.support_breakdown(key_j(conflict), &s, at, |_| false),
                    reg.support_breakdown(key_j(conflict), &s, at, |_| false)
                );
            }
        }
    }
    assert_opt_eq_ref(&restored, key_j(0), AT, |_| false);
}

// ---------------------------------------------------------------------------
// 12. Restored index is rebuilt consistently even if dropped beforehand.
// ---------------------------------------------------------------------------
#[test]
fn f13_12_restore_rebuilds_index() {
    let mut reg = bonded(5, 1000);
    for i in 0..5 {
        reg.insert_vote(vote_of(i, AT, 2, 0, i));
    }
    let expected = reg.support_breakdown(key_j(2), &side(0), AT, |_| false);
    reg.drop_vote_index_for_test();
    let restored = StakeRegistry::restore(reg.snapshot()).expect("restore");
    assert!(restored.vote_index_is_consistent_for_test());
    assert_eq!(
        restored.support_breakdown(key_j(2), &side(0), AT, |_| false),
        expected
    );
}

// ---------------------------------------------------------------------------
// 13. try_finalize on a large population matches the oracle.
// ---------------------------------------------------------------------------
#[test]
fn f13_13_try_finalize_large_population() {
    const N: u64 = 50_000;
    const KEYS: u64 = 5_000; // 10 validators per key
    let mut opt = bonded(N, MIN_STAKE);
    let mut oracle = bonded(N, MIN_STAKE);
    for i in 0..N {
        let conflict = i % KEYS;
        let v = vote_of(i, AT, conflict, (i % 3) as u8, i);
        opt.insert_vote(v.clone());
        oracle.insert_vote(v);
    }
    // One valid future vote (grace) on the probed key: formerly forced the
    // whole-registry fallback on every member for every finalize attempt.
    opt.insert_vote(vote_of(0, AT + 1, 0, 2, N + 1));
    oracle.insert_vote(vote_of(0, AT + 1, 0, 2, N + 1));
    let members: Vec<[u8; 32]> = (0..10u64).map(|j| side((j % 3) as u8)).collect();
    let ro = oracle.try_finalize_reference(key_j(0), &members, AT, |_, _| false);
    let oo = opt.try_finalize(key_j(0), &members, AT, |_, _| false);
    assert_eq!(oo, ro, "finalize decision diverged at N={N}");
    assert!(opt.vote_index_is_consistent_for_test());
}

// ---------------------------------------------------------------------------
// 14. Non-amplification: traversal count independent of |votes|.
// ---------------------------------------------------------------------------
#[test]
fn f13_14_traversal_count_independent_of_population() {
    fn probes_for(n: u64) -> (usize, (u64, Vec<crate::transaction::VoteId>)) {
        let keys = std::cmp::max(1, n / 10);
        let mut reg = bonded(n, MIN_STAKE);
        for i in 0..n {
            reg.insert_vote(vote_of(i, AT, i % keys, 0, i));
        }
        // One valid future vote on key 0: the F13 trigger.
        reg.insert_vote(vote_of(0, AT + 1, 0, 1, n + 1));
        let (total, ids, probes) =
            reg.support_breakdown_counted_for_test(key_j(0), &side(0), AT, |_| false);
        (probes, (total, ids))
    }
    let (p_small, r_small) = probes_for(100);
    let (p_large, r_large) = probes_for(50_000);
    assert_eq!(p_small, p_large, "traversal count grew with |votes|");
    assert_eq!(p_large, 10, "exactly one probe per validator of the key");
    // Same weight and same number of contributing validators, independent of
    // population (10 voters/key, all side 0; the future vote is excluded at
    // AT). Vote ids differ because they hash the validator/epoch fields.
    assert_eq!(r_small.0, r_large.0);
    assert_eq!(r_small.1.len(), r_large.1.len());
    assert_eq!(r_large.0, 10 * MIN_STAKE);
    assert_eq!(r_large.1.len(), 10);
}

// ---------------------------------------------------------------------------
// 15. Ingestion scaling (explicitly ignored; run with --ignored in release).
// ---------------------------------------------------------------------------
#[test]
#[ignore = "timing test: run explicitly with --ignored"]
fn f13_15_ingestion_scales_linearly() {
    use std::time::Instant;
    fn ingest(n: u64) -> f64 {
        let mut reg = bonded(n, MIN_STAKE);
        let start = Instant::now();
        for i in 0..n {
            reg.insert_vote(vote_of(i, AT, i % 100, 0, i));
        }
        start.elapsed().as_secs_f64()
    }
    let t1 = ingest(20_000);
    let t2 = ingest(40_000);
    let ratio = t2 / t1.max(0.000_001);
    // Former implementation was quadratic (ratio ~4+); targeted inserts are
    // O(log e) each, so doubling the population must stay near 2.
    assert!(ratio < 2.6, "ingestion not near-linear: t1={t1:.3}s t2={t2:.3}s ratio={ratio:.2}");
}
