//! L1 (A-06.3j lot L1): deterministic decision epochs for stake + support.
//!
//! SCOPE: Rule B (a vote from a FUTURE epoch never weighs) and the
//! epoch-purity of the decision API (`support_for`, `support_breakdown`,
//! `try_finalize`, `eligible_stake_total`, `voting_weight`).
//!
//! WHY THIS FILE EXISTS: the admission window tolerates `at_epoch +/-`
//! `EPOCH_GRACE`, so a vote stamped one epoch ahead used to be counted
//! IMMEDIATELY in support. Support then depended on the sender's clock
//! rather than on the decision epoch, which made a decision depend on
//! arrival order. These tests pin the corrected behaviour at the registry
//! layer: every fixture fixes its epochs, no test asserts anything about
//! the wall clock except the one that proves the clock is NOT consulted.
//!
//! NOT covered here (out of L1 scope, tracked in A-06.3j): the source of
//! `at_epoch` at the processor edge. No authenticated checkpoint parent
//! with a timestamp exists yet (`V6Anchor` has no `timestamp` field), so
//! the processor still derives `at_epoch` from `current_epoch()`. These
//! tests prove the decision layer is ready for a deterministic epoch; they
//! do not claim the processor already supplies one.

use crate::stake::{
    current_epoch, FinalizedRecord, StakeRegistry, VoteInsertOutcome, BOND_MATURATION_EPOCHS,
    MIN_STAKE,
};
use crate::transaction::{Vote, VOTE_FORMAT_VERSION};
use crate::wallet::Wallet;

/// Decision epoch used by the fixed-epoch fixtures.
const AT: u64 = 10;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("fixed key")
}

fn key_j(j: u64) -> ([u8; 32], u64) {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&j.to_le_bytes());
    s[8] = 0xE1;
    (s, j)
}

fn side_x() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xAA;
    s
}

fn side_y() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xBB;
    s
}

/// Build a REAL signed vote (signature verifies against the validator
/// address). Mirrors the helper convention of phase4q/phase4g.
fn signed_vote(w: &Wallet, epoch: u64, key: ([u8; 32], u64), side: [u8; 32]) -> Vote {
    let mut v = Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: 0,
        validator: w.address(),
        epoch,
        conflict_sender: key.0,
        conflict_nonce: key.1,
        side,
        stake_epoch: epoch,
        stake_amount: MIN_STAKE,
        parents: [[0u8; 32]; 2],
        signature: [0u8; 64],
    };
    let sig = w.sign_transaction_hash(&v.signing_bytes()).expect("sign");
    v.signature = sig.to_bytes();
    assert!(v.verify_signature(), "fixture vote must verify");
    v
}

/// Two validators bonded at `bond_epoch`, each at exactly MIN_STAKE.
fn registry_two(bond_epoch: u64) -> (StakeRegistry, Wallet, Wallet) {
    let a = wallet_n(11);
    let b = wallet_n(12);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(a.address(), MIN_STAKE, bond_epoch)
        .expect("bond a");
    reg.apply_bond(b.address(), MIN_STAKE, bond_epoch)
        .expect("bond b");
    (reg, a, b)
}

/// L1-1: same registry, same votes, same `at_epoch` => same decision.
/// (Reproducibility as a pure function of the inputs.)
#[test]
fn l1_same_inputs_same_decision() {
    let k = key_j(1);
    let members = [side_x(), side_y()];

    let build = || {
        let (mut reg, a, b) = registry_two(8);
        let _ = reg.insert_vote(signed_vote(&a, AT, k, side_x()));
        let _ = reg.insert_vote(signed_vote(&b, AT, k, side_x()));
        reg
    };

    let mut r1 = build();
    let mut r2 = build();
    let d1 = r1.try_finalize(k, &members, AT, |_, _| false);
    let d2 = r2.try_finalize(k, &members, AT, |_, _| false);

    let d1 = d1.expect("quorum at AT");
    let d2 = d2.expect("quorum at AT");
    assert_eq!(d1.winner, d2.winner);
    assert_eq!(d1.supporting_weight, d2.supporting_weight);
    assert_eq!(d1.eligible_total, d2.eligible_total);
    assert_eq!(d1.supporting_votes, d2.supporting_votes);
    assert_eq!(d1.epoch, AT);
}

/// L1-2: maturation follows `bonded_epoch + BOND_MATURATION_EPOCHS <=
/// at_epoch`, evaluated at the SUPPLIED epoch for every validator.
#[test]
fn l1_maturation_boundary_is_epoch_pure() {
    assert_eq!(BOND_MATURATION_EPOCHS, 2, "maturation constant pinned");

    let a = wallet_n(21);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(a.address(), MIN_STAKE, 9).expect("bond");

    // 9 + 2 = 11: immature at 10, mature at 11.
    assert_eq!(reg.voting_weight(&a.address(), 10), 0);
    assert_eq!(reg.voting_weight(&a.address(), 11), MIN_STAKE);
    assert_eq!(reg.eligible_stake_total(10), 0);
    assert_eq!(reg.eligible_stake_total(11), MIN_STAKE);
    // Strictly before the boundary the validator is never eligible.
    assert_eq!(reg.eligible_stake_total(9), 0);
}

/// L1-3 (RULE B): a vote stamped `at_epoch + 1` is admitted to the map but
/// does NOT weigh at `at_epoch`. This is the regression this lot exists for.
#[test]
fn l1_future_vote_never_weighs() {
    let k = key_j(3);
    let members = [side_x(), side_y()];
    let (mut reg, a, b) = registry_two(8);

    let _ = reg.insert_vote(signed_vote(&a, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&b, AT + 1, k, side_x())); // FUTURE

    // Only the current-epoch vote weighs.
    assert_eq!(
        reg.support_for(k, &side_x(), AT, |_| false),
        MIN_STAKE,
        "a future vote must not contribute at AT"
    );
    // 1/2 of the eligible total is below 2/3: no certificate.
    assert!(
        reg.try_finalize(k, &members, AT, |_, _| false).is_none(),
        "a future vote must not create a quorum at AT"
    );

    // At its own epoch the same vote does weigh.
    assert_eq!(
        reg.support_for(k, &side_x(), AT + 1, |_| false),
        2 * MIN_STAKE
    );
    assert!(reg
        .try_finalize(k, &members, AT + 1, |_, _| false)
        .is_some());
}

/// L1-4: a vote stamped exactly at the decision epoch weighs.
#[test]
fn l1_vote_at_decision_epoch_weighs() {
    let k = key_j(4);
    let (mut reg, a, _b) = registry_two(8);
    let _ = reg.insert_vote(signed_vote(&a, AT, k, side_x()));
    assert_eq!(reg.support_for(k, &side_x(), AT, |_| false), MIN_STAKE);
}

/// L1-5: an OLD vote weighs, provided its author is eligible at the
/// decision epoch (unchanged eligibility rule, no new age cut-off).
#[test]
fn l1_past_vote_weighs_if_eligible() {
    let k = key_j(5);
    let (mut reg, a, _b) = registry_two(8);
    let _ = reg.insert_vote(signed_vote(&a, AT - 2, k, side_x()));
    assert_eq!(reg.support_for(k, &side_x(), AT, |_| false), MIN_STAKE);
}

/// L1-6: a restart (snapshot -> restore) reproduces the decision exactly
/// at the same explicit epoch. No epoch is reconstructed from a clock.
#[test]
fn l1_restore_reproduces_decision() {
    let k = key_j(6);
    let members = [side_x(), side_y()];
    let (mut reg, a, b) = registry_two(8);
    // Third validator supplies a FUTURE vote so the restart also proves the
    // future-epoch exclusion survives snapshot -> restore.
    let c = wallet_n(13);
    reg.apply_bond(c.address(), MIN_STAKE, 8).expect("bond c");
    let _ = reg.insert_vote(signed_vote(&a, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&b, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&c, AT + 1, k, side_x())); // FUTURE

    let before = reg
        .try_finalize(k, &members, AT, |_, _| false)
        .expect("quorum at AT");
    // Quorum from a+b only; c's future vote inflates neither side.
    assert_eq!(before.supporting_weight, 2 * MIN_STAKE);
    assert_eq!(before.eligible_total, 3 * MIN_STAKE);

    let snap = reg.snapshot();
    let mut restored = StakeRegistry::restore(snap).expect("restore");

    let after = restored
        .try_finalize(k, &members, AT, |_, _| false)
        .expect("quorum at AT after restore");
    assert_eq!(before.winner, after.winner);
    assert_eq!(before.supporting_weight, after.supporting_weight);
    assert_eq!(before.eligible_total, after.eligible_total);
    assert_eq!(before.supporting_votes, after.supporting_votes);

    // The future vote is still not counted after the restart.
    assert_eq!(
        restored.support_for(k, &side_x(), AT, |_| false),
        2 * MIN_STAKE
    );
}

/// L1-7: the decision API uses the SUPPLIED epoch, never the wall clock.
/// The fixture bonds at an epoch ~500 ahead of `current_epoch()`, so the
/// validators are INELIGIBLE at the clock and ELIGIBLE at the decision
/// epoch. Any hidden `current_epoch()` read inside a decision function
/// would make the quorum impossible and this test fail.
#[test]
fn l1_decision_epoch_is_not_the_wall_clock() {
    let far = current_epoch().saturating_add(500);
    let k = key_j(7);
    let members = [side_x(), side_y()];

    let a = wallet_n(31);
    let b = wallet_n(32);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(a.address(), MIN_STAKE, far).expect("bond a");
    reg.apply_bond(b.address(), MIN_STAKE, far).expect("bond b");

    // Ineligible at the clock: the bond is not matured there.
    assert_eq!(reg.eligible_stake_total(current_epoch()), 0);

    // Eligible at the explicit decision epoch.
    assert_eq!(reg.eligible_stake_total(far + 2), 2 * MIN_STAKE);

    let _ = reg.insert_vote(signed_vote(&a, far + 2, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&b, far + 2, k, side_x()));
    let rec = reg.try_finalize(k, &members, far + 2, |_, _| false);
    assert!(
        rec.is_some(),
        "the decision must use the explicit epoch, not the wall clock"
    );
    assert_eq!(rec.expect("quorum").eligible_total, 2 * MIN_STAKE);
}

// ---------------------------------------------------------------------------
// L1.1-C: filter-before-selection (Rule B) regression suite.
//
// The L1.1 tests above prove that a future vote does not weigh. They do NOT
// prove that a future vote leaves the same validator's older admissible vote
// intact, because no fixture has two votes from ONE validator at different
// epochs. The tests below pin that distinction explicitly: strategy A (select
// then filter) would give 0 at E=10 in T1/T2/T3, while strategy B gives w.
// ---------------------------------------------------------------------------

/// T1 (L1.1-C): a future vote must not erase the historical vote from the
/// same validator. X votes A@10 then B@11.
#[test]
fn l1c_future_vote_does_not_shadow_historical_vote() {
    let k = key_j(101);
    let (mut reg, x, _y) = registry_two(8);
    let v10 = signed_vote(&x, AT, k, side_x());
    let v11 = signed_vote(&x, AT + 1, k, side_y());
    let id10 = v10.id();
    assert_eq!(reg.insert_vote(v10), VoteInsertOutcome::Accepted);
    assert_eq!(reg.insert_vote(v11), VoteInsertOutcome::Accepted);

    // E = 10: the admissible vote X@10 weighs for A; X@11 never does.
    let (total_a, ids_a) = reg.support_breakdown(k, &side_x(), AT, |_| false);
    assert_eq!(total_a, MIN_STAKE, "X@10 must still weigh at E=10");
    assert_eq!(ids_a, vec![id10], "E=10 must pin X@10, not X@11");
    assert_eq!(
        reg.support_breakdown(k, &side_y(), AT, |_| false).0,
        0,
        "X@11 must not weigh for B at E=10"
    );
    assert_eq!(reg.support_for(k, &side_x(), AT, |_| false), MIN_STAKE);

    // E = 11: the newest admissible vote now wins for B.
    assert_eq!(
        reg.support_breakdown(k, &side_y(), AT + 1, |_| false).0,
        MIN_STAKE,
        "X@11 must weigh for B at E=11"
    );
    assert_eq!(
        reg.support_breakdown(k, &side_x(), AT + 1, |_| false).0,
        0,
        "X's latest admissible vote moved to B at E=11"
    );
}

/// T2 (L1.1-C): liveness. Two validators back A at E=10; one moves to B at
/// E=11. Under strategy A the E=10 support collapses to w (< 2/3), under B
/// it stays 2w and the quorum is still reached.
#[test]
fn l1c_future_vote_does_not_break_quorum_liveness() {
    let k = key_j(102);
    let members = [side_x(), side_y()];
    let (mut reg, x, y) = registry_two(8);
    let _ = reg.insert_vote(signed_vote(&x, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&y, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&x, AT + 1, k, side_y()));

    assert_eq!(
        reg.support_for(k, &side_x(), AT, |_| false),
        2 * MIN_STAKE,
        "X@10 + Y@10 must both weigh at E=10"
    );
    let rec = reg
        .try_finalize(k, &members, AT, |_, _| false)
        .expect("quorum at E=10 must still be reached");
    assert_eq!(rec.winner, side_x());
    assert_eq!(rec.supporting_weight, 2 * MIN_STAKE);
    assert_eq!(rec.eligible_total, 2 * MIN_STAKE);
}

/// T3 (L1.1-C): the support at a fixed epoch is invariant to a future vote
/// arriving later (insertion order must not change a past decision).
#[test]
fn l1c_support_at_fixed_epoch_is_invariant_to_future_vote() {
    let k = key_j(103);
    let (mut reg, x, y) = registry_two(8);
    let _ = reg.insert_vote(signed_vote(&x, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&y, AT, k, side_x()));

    let before = reg.support_breakdown(k, &side_x(), AT, |_| false);
    let _ = reg.insert_vote(signed_vote(&x, AT + 1, k, side_y()));
    let after = reg.support_breakdown(k, &side_x(), AT, |_| false);

    assert_eq!(before, after, "future vote must not change support at E=10");
    assert_eq!(
        reg.support_breakdown_reference(k, &side_x(), AT, |_| false),
        after,
        "the reference path must agree after the future vote"
    );
}

/// T4 (L1.1-C): optimized and reference paths agree on totals AND ids with
/// mixed epochs, ancient votes, future votes and a second key.
#[test]
fn l1c_optimized_and_reference_agree_with_future_votes() {
    let k = key_j(104);
    let k2 = key_j(105);
    let build = || {
        let mut reg = StakeRegistry::new();
        let a = wallet_n(41);
        let b = wallet_n(42);
        let c = wallet_n(43);
        for w in [&a, &b, &c] {
            reg.apply_bond(w.address(), MIN_STAKE, 8).expect("bond");
        }
        let _ = reg.insert_vote(signed_vote(&a, AT - 2, k, side_x())); // old
        let _ = reg.insert_vote(signed_vote(&b, AT, k, side_x())); // current
        let _ = reg.insert_vote(signed_vote(&a, AT + 1, k, side_y())); // future
        let _ = reg.insert_vote(signed_vote(&c, AT + 1, k, side_x())); // future
        let _ = reg.insert_vote(signed_vote(&c, AT - 1, k2, side_y())); // other key
        reg
    };
    let reg = build();
    for e in [AT - 2, AT - 1, AT, AT + 1, AT + 2] {
        for s in [side_x(), side_y()] {
            let opt = reg.support_breakdown(k, &s, e, |_| false);
            let reference = reg.support_breakdown_reference(k, &s, e, |_| false);
            assert_eq!(opt, reference, "ref/opt diverged on K at epoch {}", e);
        }
        let opt2 = reg.support_breakdown(k2, &side_y(), e, |_| false);
        let reference2 = reg.support_breakdown_reference(k2, &side_y(), e, |_| false);
        assert_eq!(opt2, reference2, "ref/opt diverged on K2 at epoch {}", e);
    }

    // Decision-level equivalence on independent registries.
    let members = [side_x(), side_y()];
    let mut opt_reg = build();
    let mut ref_reg = build();
    let opt_decision = opt_reg.try_finalize(k, &members, AT, |_, _| false);
    let ref_decision = ref_reg.try_finalize_reference(k, &members, AT, |_, _| false);
    assert_eq!(
        opt_decision, ref_decision,
        "finalize ref/opt diverged for the same vote set"
    );
}

/// T5 (L1.1-C): arrival-order permutations of the same multi-epoch vote set
/// produce the same support at E=10/E=11 and the same finality decision.
#[test]
fn l1c_future_vote_permutations_converge() {
    let k = key_j(106);
    let members = [side_x(), side_y()];
    // Index 0/2 belong to X, 1/3 to Y: A@AT for both, then B@AT+1 for both.
    let votes = [(AT, false), (AT, false), (AT + 1, true), (AT + 1, true)];
    let orders: [[usize; 4]; 6] = [
        [0, 1, 2, 3],
        [0, 2, 1, 3],
        [2, 0, 3, 1],
        [3, 2, 1, 0],
        [1, 3, 0, 2],
        [2, 3, 0, 1],
    ];
    let mut results: Vec<(
        (u64, Vec<[u8; 32]>),
        (u64, Vec<[u8; 32]>),
        Option<FinalizedRecord>,
    )> = Vec::new();

    for order in orders {
        let (mut reg, x, y) = registry_two(8);
        for idx in order {
            let (epoch, side_b) = votes[idx];
            let wallet = if idx % 2 == 0 { &x } else { &y };
            let side = if side_b { side_y() } else { side_x() };
            let _ = reg.insert_vote(signed_vote(wallet, epoch, k, side));
        }
        let s10 = reg.support_breakdown(k, &side_x(), AT, |_| false);
        let s11 = reg.support_breakdown(k, &side_y(), AT + 1, |_| false);
        let decision = reg.try_finalize(k, &members, AT, |_, _| false);
        results.push((s10, s11, decision));
    }

    assert_eq!(results[0].0 .0, 2 * MIN_STAKE);
    assert_eq!(results[0].1 .0, 2 * MIN_STAKE);
    assert!(results[0].2.is_some());
    for (i, r) in results.iter().enumerate().skip(1) {
        assert_eq!(r, &results[0], "permutation {} diverged", i);
    }
}

/// T6 (L1.1-C): snapshots preserve BOTH epochs; after restore the older
/// admissible vote still weighs at E=10 and the newer one at E=11.
#[test]
fn l1c_restore_preserves_multi_epoch_votes() {
    let k = key_j(107);
    let (mut reg, x, _y) = registry_two(8);
    let _ = reg.insert_vote(signed_vote(&x, AT, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&x, AT + 1, k, side_y()));

    let snapshot = reg.snapshot();
    assert_eq!(snapshot.votes.len(), 2, "both epochs must be snapshotted");
    let restored = StakeRegistry::restore(snapshot).expect("restore");
    assert_eq!(restored.snapshot().votes.len(), 2, "restore must keep both");

    assert_eq!(
        restored.support_for(k, &side_x(), AT, |_| false),
        MIN_STAKE,
        "X@10 must survive snapshot -> restore"
    );
    assert_eq!(restored.support_for(k, &side_y(), AT, |_| false), 0);
    assert_eq!(
        restored.support_for(k, &side_y(), AT + 1, |_| false),
        MIN_STAKE
    );
    assert_eq!(restored.support_for(k, &side_x(), AT + 1, |_| false), 0);
    assert_eq!(
        restored.support_breakdown(k, &side_x(), AT, |_| false),
        restored.support_breakdown_reference(k, &side_x(), AT, |_| false),
        "restore must not change the reference result"
    );
}

/// T7 (L1.1-C): same-epoch equivocation still slashes; a later vote cannot
/// resurrect the removed weight.
#[test]
fn l1c_equivocation_slash_survives_future_vote() {
    let k = key_j(108);
    let (mut reg, x, _y) = registry_two(8);
    let _ = reg.insert_vote(signed_vote(&x, AT, k, side_x()));
    match reg.insert_vote(signed_vote(&x, AT, k, side_y())) {
        VoteInsertOutcome::Equivocated { .. } => {}
        other => panic!("expected equivocation, got {:?}", other),
    }
    assert_eq!(reg.voting_weight(&x.address(), AT), 0);
    assert_eq!(reg.voting_weight(&x.address(), AT + 1), 0);

    let _ = reg.insert_vote(signed_vote(&x, AT + 1, k, side_x()));
    assert_eq!(reg.support_for(k, &side_x(), AT, |_| false), 0);
    assert_eq!(reg.support_for(k, &side_x(), AT + 1, |_| false), 0);
}

/// T8 (L1.1-C): the support functions use only the supplied epoch. Bonds are
/// placed far in the future so any hidden wall-clock read yields 0.
#[test]
fn l1c_support_uses_only_explicit_epoch() {
    let far = current_epoch().saturating_add(500);
    let k = key_j(109);
    let a = wallet_n(51);
    let b = wallet_n(52);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(a.address(), MIN_STAKE, far).expect("bond a");
    reg.apply_bond(b.address(), MIN_STAKE, far).expect("bond b");
    let _ = reg.insert_vote(signed_vote(&a, far + 2, k, side_x()));
    let _ = reg.insert_vote(signed_vote(&b, far + 2, k, side_x()));

    // At the wall clock these bonds are immature and the votes are future.
    assert_eq!(
        reg.support_breakdown(k, &side_x(), current_epoch(), |_| false)
            .0,
        0
    );
    assert_eq!(
        reg.support_breakdown_reference(k, &side_x(), current_epoch(), |_| false)
            .0,
        0
    );
    // At the explicit decision epoch both weigh.
    assert_eq!(
        reg.support_breakdown(k, &side_x(), far + 2, |_| false).0,
        2 * MIN_STAKE
    );
    assert_eq!(
        reg.support_breakdown_reference(k, &side_x(), far + 2, |_| false)
            .0,
        2 * MIN_STAKE
    );
    assert_eq!(
        reg.support_for(k, &side_x(), far + 2, |_| false),
        2 * MIN_STAKE
    );
}

/// T9 (L1.1-C): the pinned ids (certificate) at E=10 contain only the
/// admissible votes, never the future one.
#[test]
fn l1c_ids_never_reference_future_vote() {
    let k = key_j(110);
    let members = [side_x(), side_y()];
    let (mut reg, x, y) = registry_two(8);
    let vx10 = signed_vote(&x, AT, k, side_x());
    let vy10 = signed_vote(&y, AT, k, side_x());
    let vx11 = signed_vote(&x, AT + 1, k, side_y());
    let (idx10, idy10, idx11) = (vx10.id(), vy10.id(), vx11.id());
    let _ = reg.insert_vote(vx10);
    let _ = reg.insert_vote(vy10);
    let _ = reg.insert_vote(vx11);

    let (total, ids) = reg.support_breakdown(k, &side_x(), AT, |_| false);
    assert_eq!(total, 2 * MIN_STAKE);
    let mut expected = vec![idx10, idy10];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(
        !ids.contains(&idx11),
        "E=10 must never pin the future vote id"
    );

    let cert = reg
        .try_finalize(k, &members, AT, |_, _| false)
        .expect("quorum at E=10");
    assert_eq!(cert.supporting_votes, expected);
    assert!(!cert.supporting_votes.contains(&idx11));
}

/// Performance probe (ignored by default; not part of the correctness gate).
/// Measures the L1.1-C fallback: every validator's cached vote is future, so
/// `support_breakdown` at E=10 must rebuild the admissible winners from the
/// authoritative map once, then evaluate. The E=11 call is the plain indexed
/// path (no fallback) and serves as the comparison point.
///
/// Run with:
/// `cargo test l1c_fallback_cost_probe -- --ignored --nocapture`
#[test]
#[ignore]
fn l1c_fallback_cost_probe() {
    let k = key_j(900);
    let n = 1_000u64;
    let mut reg = StakeRegistry::new();
    for i in 0..n {
        let w = wallet_n(10_000 + i);
        reg.apply_bond(w.address(), MIN_STAKE, 8).expect("bond");
        let _ = reg.insert_vote(signed_vote(&w, AT, k, side_x()));
        let _ = reg.insert_vote(signed_vote(&w, AT + 1, k, side_y()));
    }

    let t_index = std::time::Instant::now();
    let (total_index, ids_index) = reg.support_breakdown(k, &side_y(), AT + 1, |_| false);
    let index_elapsed = t_index.elapsed();

    let t_fallback = std::time::Instant::now();
    let (total_fallback, ids_fallback) = reg.support_breakdown(k, &side_x(), AT, |_| false);
    let fallback_elapsed = t_fallback.elapsed();

    assert_eq!(total_index, n * MIN_STAKE);
    assert_eq!(total_fallback, n * MIN_STAKE);
    assert_eq!(ids_index.len() as u64, n);
    assert_eq!(ids_fallback.len() as u64, n);
    println!(
        "L1.1-C probe: n={} indexed={:?} fallback={:?} \
         (fallback per validator: {:?})",
        n,
        index_elapsed,
        fallback_elapsed,
        fallback_elapsed / n as u32
    );
}
