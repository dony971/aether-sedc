//! PHASE 4G: unit tests for the stake registry (v6, NO PoW).
//!
//! SCOPE: pure registry mechanics only (constants, epochs, lifecycle,
//! quorum arithmetic, vote insertion/equivocation, support/finality,
//! activation predicate). No DAG, no P2P, no storage, no wall-clock.
//! All fixtures deterministic (fixed keys, fixed epochs, fixed ids).
//! Signatures are REAL (ed25519 via Wallet) where verified; registry
//! insertion itself assumes validate_vote passed (signature checked at the
//! validation layer, not here).

use crate::ledger::Ledger;
use crate::p2p::P2PMessage;
use crate::parent_selection::DAG;
use crate::stake::{
    current_epoch, StakeRegistry, ValidatorState, VoteInsertOutcome, BOND_MATURATION_EPOCHS,
    EPOCH_DURATION_MS, EPOCH_GRACE, MIN_STAKE, UNBONDING_EPOCHS,
};
use crate::storage::Storage;
use crate::transaction::{
    Bond, Transaction, Unbond, Vote, BOND_FORMAT_VERSION, VOTE_FORMAT_VERSION,
};
use crate::transaction_processor::TransactionProcessor;
use crate::validation::{TransactionValidator, ValidationError, ValidationMode};
use crate::wallet::Wallet;
use std::sync::Arc;
use tokio::sync::RwLock;

fn wallet_a() -> Wallet {
    Wallet::from_secret_key("1111111111111111111111111111111111111111111111111111111111111111")
        .expect("fixed key A")
}

fn wallet_b() -> Wallet {
    Wallet::from_secret_key("2222222222222222222222222222222222222222222222222222222222222222")
        .expect("fixed key B")
}

fn wallet_c() -> Wallet {
    Wallet::from_secret_key("3333333333333333333333333333333333333333333333333333333333333333")
        .expect("fixed key C")
}

/// Build a REAL signed vote (signature verifies against validator address).
fn signed_vote(
    w: &Wallet,
    epoch: u64,
    key: ([u8; 32], u64),
    side: [u8; 32],
    stake_amount: u64,
) -> Vote {
    let mut v = Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: 0,
        validator: w.address(),
        epoch,
        conflict_sender: key.0,
        conflict_nonce: key.1,
        side,
        stake_epoch: epoch,
        stake_amount,
        parents: [[0u8; 32]; 2],
        signature: [0u8; 64],
    };
    let sig = w
        .sign_transaction_hash(&v.signing_bytes())
        .expect("sign vote");
    v.signature = sig.to_bytes();
    assert!(v.verify_signature(), "fixture vote must verify");
    v
}

fn signed_bond(w: &Wallet, amount: u64, epoch: u64) -> Bond {
    let mut b = Bond {
        format_version: BOND_FORMAT_VERSION,
        network_id: 0,
        validator: w.address(),
        amount,
        epoch,
        signature: [0u8; 64],
    };
    let sig = w
        .sign_transaction_hash(&b.signing_bytes())
        .expect("sign bond");
    b.signature = sig.to_bytes();
    assert!(b.verify_signature(), "fixture bond must verify");
    b
}

fn signed_unbond(w: &Wallet, epoch: u64) -> Unbond {
    let mut u = Unbond {
        format_version: BOND_FORMAT_VERSION,
        network_id: 0,
        validator: w.address(),
        epoch,
        signature: [0u8; 64],
    };
    let sig = w
        .sign_transaction_hash(&u.signing_bytes())
        .expect("sign unbond");
    u.signature = sig.to_bytes();
    assert!(u.verify_signature(), "fixture unbond must verify");
    u
}

#[test]
fn g01_constants_match_4f_charter() {
    assert_eq!(MIN_STAKE, 30_000_000);
    assert_eq!(EPOCH_DURATION_MS, 3_600_000);
    assert_eq!(UNBONDING_EPOCHS, 72);
    assert_eq!(BOND_MATURATION_EPOCHS, 2);
    assert_eq!(EPOCH_GRACE, 1);
}

#[test]
fn g02_epoch_boundaries() {
    assert_eq!(crate::stake::epoch_of(0), 0);
    assert_eq!(crate::stake::epoch_of(3_599_999), 0);
    assert_eq!(crate::stake::epoch_of(3_600_000), 1);
    assert_eq!(crate::stake::epoch_of(7_200_000), 2);
}

#[test]
fn g03_vote_codec_roundtrip_and_sizes() {
    let w = wallet_a();
    let v = signed_vote(&w, 10, ([9u8; 32], 3), [7u8; 32], MIN_STAKE);
    let enc = v.encode();
    assert_eq!(enc.len(), 265, "vote wire size is fixed 265B (4V network u64)");
    let back = Vote::decode(&enc).expect("decode own encoding");
    assert_eq!(v, back);
    assert_eq!(v.id(), back.id(), "id deterministic");
    // Tamper one byte -> different id (content-addressed).
    let mut tampered = enc.clone();
    tampered[100] ^= 0x01;
    let t2 = Vote::decode(&tampered).expect("still well-formed");
    assert_ne!(v.id(), t2.id());
    assert!(!t2.verify_signature(), "tampered bytes fail signature");
}

#[test]
fn g04_vote_decode_rejects_bad_length_and_version() {
    let w = wallet_a();
    let v = signed_vote(&w, 10, ([9u8; 32], 3), [7u8; 32], MIN_STAKE);
    let mut enc = v.encode();
    assert!(Vote::decode(&enc[..264]).is_err(), "truncation rejected");
    enc.push(0x00);
    assert!(Vote::decode(&enc).is_err(), "extension rejected");
    let mut bad_ver = v.encode();
    bad_ver[0] = 0x7F;
    assert!(Vote::decode(&bad_ver).is_err(), "unknown version rejected");
}

#[test]
fn g05_bond_unbond_codec_and_sizes() {
    let w = wallet_a();
    let b = signed_bond(&w, MIN_STAKE, 4);
    assert_eq!(b.encode().len(), 121, "bond wire size is fixed 121B (4V network u64)");
    let back = Bond::decode(&b.encode()).expect("bond roundtrip");
    assert_eq!(b, back);
    assert!(back.verify_signature());
    assert!(Bond::decode(&[0u8; 120]).is_err());

    let u = signed_unbond(&w, 6);
    assert_eq!(u.encode().len(), 113, "unbond wire size is fixed 113B (4V network u64)");
    let back_u = Unbond::decode(&u.encode()).expect("unbond roundtrip");
    assert_eq!(u, back_u);
    assert!(back_u.verify_signature());
    assert!(Unbond::decode(&[0u8; 104]).is_err());
}

#[test]
fn g06_bond_maturation_gates_eligibility() {
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 10).expect("bond");
    // Maturation: bonded_epoch + 2 <= at_epoch.
    assert!(!reg.is_eligible(&wa.address(), 10));
    assert!(!reg.is_eligible(&wa.address(), 11));
    assert!(reg.is_eligible(&wa.address(), 12));
    assert_eq!(reg.voting_weight(&wa.address(), 11), 0);
    assert_eq!(reg.voting_weight(&wa.address(), 12), MIN_STAKE);
    // Unknown validator: zero, ineligible.
    assert!(!reg.is_eligible(&[0xFFu8; 32], 12));
    assert_eq!(reg.voting_weight(&[0xFFu8; 32], 12), 0);
}

#[test]
fn g07_unbond_cuts_voting_immediately_and_releases_after_delay() {
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    assert!(reg.is_eligible(&wa.address(), 7));
    reg.apply_unbond(wa.address(), 7).expect("unbond");
    // Clean cutover: voting ends at request, not at release.
    assert!(!reg.is_eligible(&wa.address(), 7));
    assert_eq!(reg.voting_weight(&wa.address(), 7), 0);
    // Release only after UNBONDING_EPOCHS.
    assert!(reg.release_matured(7 + UNBONDING_EPOCHS - 1).is_empty());
    let released = reg.release_matured(7 + UNBONDING_EPOCHS);
    assert_eq!(released, vec![wa.address()]);
    // Second unbond after release is an error (already unbonded).
    assert!(reg
        .apply_unbond(wa.address(), 7 + UNBONDING_EPOCHS + 1)
        .is_err());
}

#[test]
fn g08_slashed_address_may_never_rebond() {
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    assert!(reg.apply_slash(wa.address(), 6));
    assert!(!reg.apply_slash(wa.address(), 6), "second slash is no-op");
    let err = reg.apply_bond(wa.address(), MIN_STAKE, 100);
    assert!(err.is_err(), "slashed re-bond rejected");
    assert_eq!(reg.voting_weight(&wa.address(), 10_000), 0);
}

#[test]
fn g09_quorum_arithmetic_exact_boundaries() {
    // T = 0 never quorate (even S = 0).
    assert!(!StakeRegistry::quorum_met(0, 0));
    assert!(!StakeRegistry::quorum_met(0, 100));
    // 2/3 exact: 3S >= 2T.
    assert!(StakeRegistry::quorum_met(2, 3));
    assert!(!StakeRegistry::quorum_met(1, 3));
    assert!(StakeRegistry::quorum_met(3, 3));
    assert!(StakeRegistry::quorum_met(2, 2));
    // Large values: u128, no overflow, exact.
    assert!(StakeRegistry::quorum_met(u64::MAX, u64::MAX));
    assert!(StakeRegistry::quorum_met(u64::MAX / 3 * 2 + 1, u64::MAX));
    assert!(!StakeRegistry::quorum_met(u64::MAX / 3, u64::MAX));
}

#[test]
fn g10_insert_vote_accept_duplicate_equivocation_slash() {
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];

    let v1 = signed_vote(&wa, 10, key, side_a, MIN_STAKE);
    assert_eq!(reg.insert_vote(v1.clone()), VoteInsertOutcome::Accepted);
    assert_eq!(reg.insert_vote(v1.clone()), VoteInsertOutcome::Duplicate);

    // Same (validator, epoch, key), different side -> equivocation.
    let v2 = signed_vote(&wa, 10, key, side_b, MIN_STAKE);
    let before = reg.evidence_count();
    match reg.insert_vote(v2.clone()) {
        VoteInsertOutcome::Equivocated { evidence_id } => {
            assert_eq!(reg.evidence_count(), before + 1);
            let _ = evidence_id;
        }
        other => panic!("expected equivocation, got {:?}", other),
    }
    // Slash applied immediately: weight zero forever at any epoch.
    assert_eq!(reg.voting_weight(&wa.address(), 10), 0);
    assert_eq!(reg.voting_weight(&wa.address(), 10_000), 0);
    // First vote keeps the map slot is not observable here beyond the
    // evidence carrying both ids; support must now be zero (slashed).
    let s = reg.support_for(key, &side_a, 10, |_| false);
    assert_eq!(s, 0, "slashed validator contributes zero support");
}

#[test]
fn g11_evidence_id_canonical_regardless_of_arrival_order() {
    let wa = wallet_a();
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let v1 = signed_vote(&wa, 10, key, side_a, MIN_STAKE);
    let v2 = signed_vote(&wa, 10, key, side_b, MIN_STAKE);

    let mut r1 = StakeRegistry::new();
    r1.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    let id1 = match r1.insert_vote(v1.clone()) {
        VoteInsertOutcome::Accepted => match r1.insert_vote(v2.clone()) {
            VoteInsertOutcome::Equivocated { evidence_id } => evidence_id,
            other => panic!("expected equivocation, got {:?}", other),
        },
        other => panic!("expected accept, got {:?}", other),
    };

    let mut r2 = StakeRegistry::new();
    r2.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    let id2 = match r2.insert_vote(v2) {
        VoteInsertOutcome::Accepted => match r2.insert_vote(v1) {
            VoteInsertOutcome::Equivocated { evidence_id } => evidence_id,
            other => panic!("expected equivocation, got {:?}", other),
        },
        other => panic!("expected accept, got {:?}", other),
    };
    assert_eq!(id1, id2, "evidence id is arrival-order independent");
}

#[test]
fn g12_support_latest_per_validator_and_descendant_closure() {
    let wa = wallet_a();
    let wb = wallet_b();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), 100, 0).expect("bond A");
    reg.apply_bond(wb.address(), 200, 0).expect("bond B");
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let child_of_a = [0xA1u8; 32];

    // A votes side_b at epoch 5, then side_a at epoch 7: latest (7) wins.
    reg.insert_vote(signed_vote(&wa, 5, key, side_b, 100));
    reg.insert_vote(signed_vote(&wa, 7, key, side_a, 100));
    // B votes a strict descendant of side_a: counts for side_a via closure.
    reg.insert_vote(signed_vote(&wb, 7, key, child_of_a, 200));

    // Strict descendant test: only child_of_a descends from side_a.
    let is_desc_of_a = |txid: &[u8; 32]| *txid == child_of_a;
    let s_a = reg.support_for(key, &side_a, 7, is_desc_of_a);
    assert_eq!(s_a, 300, "A latest (100) + B descendant (200)");
    // For side_b: A moved away (latest is side_a), B points at A's closure.
    let s_b = reg.support_for(key, &side_b, 7, |_| false);
    assert_eq!(s_b, 0, "no latest vote points at side_b");
}

#[test]
fn g13_finalize_quorum_tiebreak_sticky_empty() {
    let wa = wallet_a();
    let wb = wallet_b();
    let wc = wallet_c();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), 100, 0).expect("bond A");
    reg.apply_bond(wb.address(), 100, 0).expect("bond B");
    reg.apply_bond(wc.address(), 100, 0).expect("bond C");
    let key = ([9u8; 32], 3u64);
    // Members chosen so that min-id tiebreak is exercised: side_lo < side_hi.
    let mut members = [[0xBBu8; 32], [0xAAu8; 32]];
    members.sort();
    let (side_lo, side_hi) = (members[0], members[1]);

    // A -> lo, B -> hi: 100 vs 100 of 300 total: no quorum.
    reg.insert_vote(signed_vote(&wa, 5, key, side_lo, 100));
    reg.insert_vote(signed_vote(&wb, 5, key, side_hi, 100));
    assert_eq!(reg.try_finalize(key, &members, 5, |_, _| false), None);

    // C -> hi: hi has 200/300 = 2/3 exact -> finalize hi.
    reg.insert_vote(signed_vote(&wc, 5, key, side_hi, 100));
    let rec = reg
        .try_finalize(key, &members, 5, |_, _| false)
        .expect("quorum reached");
    assert_eq!(rec.winner, side_hi);
    assert_eq!(rec.supporting_weight, 200);
    assert_eq!(reg.finalized_winner(&key), Some(side_hi));

    // Sticky: try_finalize returns the EXISTING record, never a new decision.
    let again = reg
        .try_finalize(key, &members, 5, |_, _| false)
        .expect("existing");
    assert_eq!(again.winner, side_hi);

    // Empty members: None (no panic, no decision).
    let empty_key = ([8u8; 32], 1u64);
    assert_eq!(reg.try_finalize(empty_key, &[], 5, |_, _| false), None);
    // T = 0 (no validators at all for this epoch window cannot happen here
    // since bonds exist; the T=0 guard itself is covered in g09).
}

#[test]
fn g14_finalize_tie_goes_to_min_id() {
    let wa = wallet_a();
    let wb = wallet_b();
    let mut reg = StakeRegistry::new();
    // Equal weights, disjoint halves of a 4-vote setup is overkill: with two
    // validators at 100 each and total 200, BOTH sides have 100/200 = 1/2
    // < 2/3, so no quorum. Add a third 100-weight voter per side? That is
    // 200/400... simpler: two validators, total 200, and members where one
    // side gets both via descendants is not a tie. Tie needs 2 validators
    // with equal support AND quorum: use weights 100/100/100 with A->lo,
    // B->hi, C abstains? 100/300 < quorum. Correct tie-at-quorum: four
    // validators of 100: A,B -> lo (200), C,D -> hi (200), total 400:
    // 200/400 < quorum. Hmm  -  exact tie AT quorum: total 300, lo 200, hi
    // 200 impossible (sums exceed total). Use total 600: A(200)->lo,
    // B(200)->hi, C(200)->hi... not a tie. Simplest true tie at quorum:
    // total 3, lo 2, hi 2 impossible. So: tie test uses weights where BOTH
    // reach quorum only if total is small... Actually with latest-per-
    // validator and one vote each, support sums <= total, so a tie at
    // quorum needs support_lo == support_hi >= 2T/3, i.e. supporters overlap
    // via descendants OR total measured differently. Cleanest: single
    // validator cannot tie with itself. Use TWO keys? No  -  do the tie test
    // with descendant overlap: A(300)->lo, B(300) votes a descendant of BOTH
    // is impossible (one side per vote). Alternative: craft total 300 with
    // A(150)->lo, B(150)->hi, C(150)->hi? hi=300... not tie.
    // PRAGMATIC: tie at quorum with 2 validators of weight 100 and a third
    // of weight 100 voting... abstention is impossible (no vote = no
    // support). So engineer: A(100)->lo, B(100)->hi, and total == 150?
    // Total is live (all eligible = 300 if C bonded). Bond C but keep C
    // IMMATURE (bonded_epoch = now, votes at now+0 ineligible): total at
    // epoch 5 excludes C. Then lo=100, hi=100, total=200: still < quorum.
    // FINAL OPTION (correct + simple): weights A=200, B=200, total must be
    // 300 for 200 to quorate  -  bond C=100 but UNBOND C before evaluation
    // (clean cutover removes C from total while its... C never voted, so
    // lo=200, hi=200, total=400. STILL not quorum. The math: tie at quorum
    // with disjoint votes needs T <= 1.5 * S_each and S_lo+S_hi <= T, i.e.
    // T >= 2X and T <= 1.5X  -  impossible. CONCLUSION: pure-disjoint ties
    // can never quorate (by design: 2/3 quorum forbids two disjoint
    // quorums  -  a FEATURE, the safety proof). So the min-id tiebreak only
    // fires with OVERLAPPING descendant support. Test THAT:
    let wc = wallet_c();
    reg.apply_bond(wa.address(), 200, 0).expect("bond A");
    reg.apply_bond(wb.address(), 200, 0).expect("bond B");
    reg.apply_bond(wc.address(), 200, 0).expect("bond C");
    let key = ([9u8; 32], 3u64);
    let side_lo = [0x10u8; 32];
    let side_hi = [0x20u8; 32];
    let shared_child = [0x30u8; 32];
    // A -> lo (200). B -> hi (200). C -> shared descendant of BOTH (200
    // counts for each side via closure): lo = 400, hi = 400, total 600:
    // 400/600 = 2/3 exact -> quorum on BOTH -> min-id (lo) must win.
    reg.insert_vote(signed_vote(&wa, 5, key, side_lo, 200));
    reg.insert_vote(signed_vote(&wb, 5, key, side_hi, 200));
    reg.insert_vote(signed_vote(&wc, 5, key, shared_child, 200));
    let members = [side_lo, side_hi];
    let descends_both = |member: &[u8; 32], txid: &[u8; 32]| {
        *txid == shared_child && (*member == side_lo || *member == side_hi)
    };
    let rec = reg
        .try_finalize(key, &members, 5, descends_both)
        .expect("both sides quorate via shared descendant");
    assert_eq!(
        rec.winner, side_lo,
        "tie at quorum breaks to smallest member id"
    );
}

#[test]
fn g15_invalidate_finality_delete_only() {
    let wa = wallet_a();
    let wb = wallet_b();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), 200, 0).expect("bond A");
    reg.apply_bond(wb.address(), 100, 0).expect("bond B");
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    reg.insert_vote(signed_vote(&wa, 5, key, side_a, 200));
    reg.insert_vote(signed_vote(&wb, 5, key, side_a, 100));
    let members = [side_a];
    let rec = reg
        .try_finalize(key, &members, 5, |_, _| false)
        .expect("unanimous finalizes");
    assert_eq!(rec.winner, side_a);
    // Slash-triggered invalidation deletes (later re-resolution starts
    // clean); second call reports nothing to remove.
    assert!(reg.invalidate_finality(&key));
    assert_eq!(reg.finalized_winner(&key), None);
    assert!(!reg.invalidate_finality(&key));
}

#[test]
fn g16_v6_activation_predicate_dormant_until_flag_day() {
    // Far-future placeholder: current wall-clock is pre-activation; the
    // predicate itself is a pure comparison (grandfathering flows from it).
    assert!(!Transaction::is_v6_active_at(0));
    assert!(!Transaction::is_v6_active_at(
        Transaction::V6_ACTIVATION_TS - 1
    ));
    assert!(Transaction::is_v6_active_at(Transaction::V6_ACTIVATION_TS));
    assert!(Transaction::is_v6_active_at(
        Transaction::V6_ACTIVATION_TS + 1
    ));
    assert!(Transaction::is_v6_active_at(u64::MAX));
}

#[test]
fn g17_topup_resets_maturation_not_instant_return() {
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    assert!(reg.is_eligible(&wa.address(), 7));
    // Top-up at epoch 7: maturation horizon moves (re-entry pays delay).
    reg.apply_bond(wa.address(), MIN_STAKE, 7).expect("topup");
    assert!(!reg.is_eligible(&wa.address(), 7));
    assert!(!reg.is_eligible(&wa.address(), 8));
    assert!(reg.is_eligible(&wa.address(), 9));
    assert_eq!(
        reg.voting_weight(&wa.address(), 9),
        MIN_STAKE.saturating_mul(2)
    );
}

#[test]
fn g18_validator_state_space_exhaustive() {
    // Bonded / Unbonding / Unbonded / Slashed all constructible and distinct;
    // release_matured sorts deterministically (order-independence).
    let wa = wallet_a();
    let wb = wallet_b();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 0).expect("bond A");
    reg.apply_bond(wb.address(), MIN_STAKE, 0).expect("bond B");
    reg.apply_unbond(wa.address(), 1).expect("unbond A");
    reg.apply_unbond(wb.address(), 1).expect("unbond B");
    let released = reg.release_matured(1 + UNBONDING_EPOCHS);
    let mut expected = vec![wa.address(), wb.address()];
    expected.sort();
    assert_eq!(released, expected);
    let s = format!("{:?}", ValidatorState::Slashed);
    assert!(s.contains("Slashed"));
}

/// Signed tx with (almost surely) INVALID PoW at difficulty 24: nonce is
/// bumped deterministically until the hash misses, so the test never mines
/// and never flakes (fixed wallet + fixed base timestamp).
fn unsigned_pow_tx_at(w: &Wallet, base_ts: u64) -> Transaction {
    for bump in 0..1_000_000u64 {
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            w.address(),
            [2u8; 32],
            100,
            1000,
            base_ts + bump,
            0,
            1,
            vec![0u8; 64],
            w.public_key_bytes(),
        );
        tx.id = tx.compute_hash();
        if !tx.verify_pow(24) {
            tx.signature = w.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            // Signing changes the hash: re-check PoW still misses (else
            // keep bumping  -  deterministic, terminates immediately in
            // practice since P(miss) = 1 - 2^-24 per draw).
            if !tx.verify_pow(24) {
                return tx;
            }
        }
    }
    panic!("could not shape invalid-PoW fixture");
}

#[test]
fn g19_validate_vote_accept_and_rejections() {
    let val = TransactionValidator::new();
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    let at = 10u64;
    let key = ([9u8; 32], 3u64);
    let good = signed_vote(&wa, at, key, [0xAAu8; 32], MIN_STAKE);
    assert_eq!(val.validate_vote(&good, &reg, at), Ok(()));

    // Window edges inclusive: at +/- 1 accepted.
    assert!(val
        .validate_vote(
            &signed_vote(&wa, at - 1, key, [0xAAu8; 32], MIN_STAKE),
            &reg,
            at
        )
        .is_ok());
    assert!(val
        .validate_vote(
            &signed_vote(&wa, at + 1, key, [0xAAu8; 32], MIN_STAKE),
            &reg,
            at
        )
        .is_ok());
    // Outside window: stale (past and future alike  -  never slashed).
    assert!(matches!(
        val.validate_vote(
            &signed_vote(&wa, at - 2, key, [0xAAu8; 32], MIN_STAKE),
            &reg,
            at
        ),
        Err(ValidationError::EpochOutOfWindow { .. })
    ));
    assert!(matches!(
        val.validate_vote(
            &signed_vote(&wa, at + 2, key, [0xAAu8; 32], MIN_STAKE),
            &reg,
            at
        ),
        Err(ValidationError::EpochOutOfWindow { .. })
    ));
    // Unknown validator.
    let wb = wallet_b();
    assert!(matches!(
        val.validate_vote(
            &signed_vote(&wb, at, key, [0xAAu8; 32], MIN_STAKE),
            &reg,
            at
        ),
        Err(ValidationError::UnknownValidator { .. })
    ));
    // Bad signature (tampered side after signing).
    let mut bad_sig = good.clone();
    bad_sig.side = [0xBBu8; 32];
    assert_eq!(
        val.validate_vote(&bad_sig, &reg, at),
        Err(ValidationError::InvalidVoteSignature)
    );
    // Bad version.
    let mut bad_ver = good.clone();
    bad_ver.format_version = 0x7F;
    assert!(matches!(
        val.validate_vote(&bad_ver, &reg, at),
        Err(ValidationError::InvalidStakeVersion { .. })
    ));
    // Immature bond (bonded at 9, voting at 10: needs +2).
    let mut reg2 = StakeRegistry::new();
    reg2.apply_bond(wb.address(), MIN_STAKE, 9).expect("bond");
    assert!(matches!(
        val.validate_vote(
            &signed_vote(&wb, at, key, [0xAAu8; 32], MIN_STAKE),
            &reg2,
            at
        ),
        Err(ValidationError::IneligibleValidator { .. })
    ));
    // Unbonding validator cannot vote (clean cutover).
    reg.apply_unbond(wa.address(), at).expect("unbond");
    assert!(matches!(
        val.validate_vote(&good, &reg, at),
        Err(ValidationError::IneligibleValidator { .. })
    ));
}

#[test]
fn g20_equivocation_second_side_still_validates() {
    // The validation layer must ADMIT the second side (it becomes slash
    // evidence at insert); rejecting it would let the first-seen vote
    // censor proof of its author's equivocation.
    let val = TransactionValidator::new();
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 5).expect("bond");
    let at = 10u64;
    let key = ([9u8; 32], 3u64);
    let v1 = signed_vote(&wa, at, key, [0xAAu8; 32], MIN_STAKE);
    let v2 = signed_vote(&wa, at, key, [0xBBu8; 32], MIN_STAKE);
    assert_eq!(val.validate_vote(&v1, &reg, at), Ok(()));
    assert_eq!(val.validate_vote(&v2, &reg, at), Ok(()));
}

#[test]
fn g21_validate_bond_accept_and_rejections() {
    let val = TransactionValidator::new();
    let wa = wallet_a();
    let wb = wallet_b();
    let at = 10u64;
    let mut ledger = Ledger::new();
    ledger.set_balance(&wa.address(), MIN_STAKE * 2);
    let mut reg = StakeRegistry::new();

    assert_eq!(
        val.validate_bond(&signed_bond(&wa, MIN_STAKE, at), &ledger, &reg, at),
        Ok(())
    );
    // Dust below floor.
    assert_eq!(
        val.validate_bond(&signed_bond(&wa, MIN_STAKE - 1, at), &ledger, &reg, at),
        Err(ValidationError::InsufficientStake {
            required: MIN_STAKE,
            provided: MIN_STAKE - 1,
        })
    );
    // Funds missing (ledger is the source of truth for balances).
    assert!(matches!(
        val.validate_bond(&signed_bond(&wb, MIN_STAKE, at), &ledger, &reg, at),
        Err(ValidationError::InsufficientBalance { .. })
    ));
    // Future bond beyond grace.
    assert!(matches!(
        val.validate_bond(&signed_bond(&wa, MIN_STAKE, at + 2), &ledger, &reg, at),
        Err(ValidationError::EpochOutOfWindow { .. })
    ));
    // Backdated bond: same rejection (maturation is measured from the
    // signed epoch  -  unbounded past would grant instant maturity).
    assert!(matches!(
        val.validate_bond(&signed_bond(&wa, MIN_STAKE, at - 2), &ledger, &reg, at),
        Err(ValidationError::EpochOutOfWindow { .. })
    ));
    // Bad signature / bad version.
    let mut bad_sig = signed_bond(&wa, MIN_STAKE, at);
    bad_sig.amount += 1;
    assert_eq!(
        val.validate_bond(&bad_sig, &ledger, &reg, at),
        Err(ValidationError::InvalidBondSignature)
    );
    let mut bad_ver = signed_bond(&wa, MIN_STAKE, at);
    bad_ver.format_version = 0x7F;
    assert!(matches!(
        val.validate_bond(&bad_ver, &ledger, &reg, at),
        Err(ValidationError::InvalidStakeVersion { .. })
    ));
    // Slashed address may never re-bond (even fully funded).
    reg.apply_bond(wa.address(), MIN_STAKE, 1).expect("bond");
    reg.apply_slash(wa.address(), 2);
    assert_eq!(
        val.validate_bond(&signed_bond(&wa, MIN_STAKE, at), &ledger, &reg, at),
        Err(ValidationError::SlashedValidator)
    );
}

#[test]
fn g22_validate_unbond_accept_and_rejections() {
    let val = TransactionValidator::new();
    let wa = wallet_a();
    let wb = wallet_b();
    let at = 10u64;
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), MIN_STAKE, 1).expect("bond");

    assert_eq!(
        val.validate_unbond(&signed_unbond(&wa, at), &reg, at),
        Ok(())
    );
    // Unknown validator: admitted as intent (4I order independence:
    // unbond-before-bond converges with bond-before-unbond via the
    // pending-intent path; intents are signature-bound + windowed).
    assert_eq!(
        val.validate_unbond(&signed_unbond(&wb, at), &reg, at),
        Ok(())
    );
    // After exit requested: fresh intent for exiting address rejected.
    reg.apply_unbond(wa.address(), at).expect("unbond");
    assert!(matches!(
        val.validate_unbond(&signed_unbond(&wa, at), &reg, at),
        Err(ValidationError::IneligibleValidator { .. })
    ));
    // Slashed validator cannot unbond.
    let mut reg2 = StakeRegistry::new();
    reg2.apply_bond(wb.address(), MIN_STAKE, 1).expect("bond");
    reg2.apply_slash(wb.address(), 2);
    assert_eq!(
        val.validate_unbond(&signed_unbond(&wb, at), &reg2, at),
        Err(ValidationError::SlashedValidator)
    );
    // Bad signature.
    let mut bad_sig = signed_unbond(&wa, at);
    bad_sig.epoch += 1;
    assert_eq!(
        val.validate_unbond(&bad_sig, &reg2, at),
        Err(ValidationError::InvalidBondSignature)
    );
    // Backdated unbond intent: same near-current window as bonds
    // (release is measured from the signed epoch).
    let mut reg3 = StakeRegistry::new();
    reg3.apply_bond(wa.address(), MIN_STAKE, 1).expect("bond");
    assert!(matches!(
        val.validate_unbond(&signed_unbond(&wa, at - 2), &reg3, at),
        Err(ValidationError::EpochOutOfWindow { .. })
    ));
}

#[test]
fn g23_v6_pow_gate_skipped_post_activation_only() {
    let val = TransactionValidator::new();
    let w = wallet_a();
    // Post-activation tx with INVALID PoW: POW_IN_CONSENSUS = NO still
    // holds (the gate is skipped), BUT while the wall clock is still
    // pre-activation the F-D2 era gate rejects future-era objects on
    // every mode first (4I intended behavior change: nothing
    // post-V6-dated enters pre-activation stores). Post-wall-activation
    // the same object passes (covered by the D2 pure-fn matrix).
    let post = unsigned_pow_tx_at(&wallet_a(), Transaction::V6_ACTIVATION_TS + 1000);
    assert!(
        post.timestamp >= Transaction::V6_ACTIVATION_TS,
        "fixture must be post-activation"
    );
    assert_eq!(
        val.validate_pure(&post, ValidationMode::Historical),
        Err(ValidationError::FutureEraTransaction {
            tx_ts: post.timestamp,
            activation_ts: Transaction::V6_ACTIVATION_TS,
        }),
        "post-V6 timestamps rejected while wall-clock pre-activation (F-D2)"
    );
    // Pre-activation tx with INVALID PoW: gate still enforced (frozen).
    let pre = unsigned_pow_tx_at(&w, Transaction::DIFFICULTY_MIGRATION_TS + 1000);
    assert!(pre.timestamp < Transaction::V6_ACTIVATION_TS);
    assert_eq!(
        val.validate_pure(&pre, ValidationMode::Historical),
        Err(ValidationError::InvalidPoW { difficulty: 24 }),
        "pre-V6 timestamps keep the legacy PoW gate"
    );
}

/// DAG-level tx with fully controlled fields (no mining, no signatures  -
/// add_transaction_validated checks DAG integrity only, same pattern as the
/// phase4/4C suites).
fn dag_tx(
    parents: [[u8; 32]; 2],
    sender: [u8; 32],
    receiver: [u8; 32],
    timestamp: u64,
    pow_nonce: u64,
    account_nonce: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        sender,
        receiver,
        100,
        1000,
        timestamp,
        pow_nonce,
        account_nonce,
        vec![0u8; 64],
        vec![0u8; 32],
    );
    tx.id = tx.compute_hash();
    tx
}

/// Build a 2-member conflict: A with two DAG children (strictly larger
/// subtree work  -  every tx credits >= 1, so A outworks childless B on ANY
/// hashes, no mining needed), B childless. Returns (dag, key, id_a, id_b).
fn worked_conflict_dag(
    member_ts: u64,
    child_ts: u64,
) -> (DAG, ([u8; 32], u64), [u8; 32], [u8; 32]) {
    let mut dag = DAG::new();
    let sender = [0x77u8; 32];
    let nonce = 5u64;
    let a = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], member_ts, 0, nonce);
    let b = dag_tx(
        [[0u8; 32]; 2],
        sender,
        [2u8; 32],
        member_ts + 1,
        u64::MAX,
        nonce,
    );
    let id_a = a.id;
    let id_b = b.id;
    dag.add_transaction_validated(a).expect("member A inserts");
    dag.add_transaction_validated(b)
        .expect("member B inserts (loser retained)");
    // Two children on A (different keys  -  no new conflicts).
    for (i, recv) in [[3u8; 32], [4u8; 32]].into_iter().enumerate() {
        let c = dag_tx(
            [id_a, [0u8; 32]],
            [0x70u8 + i as u8; 32],
            recv,
            child_ts + i as u64,
            0,
            0,
        );
        dag.add_transaction_validated(c).expect("child inserts");
    }
    (dag, (sender, nonce), id_a, id_b)
}

#[test]
fn g24_era_routing_pre_v6_delegates_to_legacy() {
    // (a) All-pre-CDW members: legacy min-id; v6 must agree exactly.
    let mut dag = DAG::new();
    let sender = [0x77u8; 32];
    let pre = Transaction::CDW_ACTIVATION_TS - 3_600_000;
    let a = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], pre, 0, 5);
    let b = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], pre + 1, 0, 5);
    dag.add_transaction_validated(a.clone()).expect("a");
    dag.add_transaction_validated(b.clone()).expect("b");
    let reg = StakeRegistry::new();
    let at = 600_000u64;
    assert_eq!(
        dag.resolve_conflict_key_v6(&sender, 5, &reg, at),
        dag.resolve_conflict_key(&sender, 5),
        "pre-CDW key: v6 delegates to frozen legacy"
    );
    assert_eq!(
        dag.resolve_conflict_key(&sender, 5),
        Some(a.id.min(b.id)),
        "pre-CDW legacy is min-id"
    );

    // (b) CDW-era members (post-CDW, pre-V6): work decides; v6 delegates.
    let cdw_ts = Transaction::CDW_ACTIVATION_TS + 3_600_000;
    assert!(cdw_ts < Transaction::V6_ACTIVATION_TS);
    let (dag2, (s2, n2), id_a, id_b) = worked_conflict_dag(cdw_ts, cdw_ts + 1000);
    assert!(dag2.subtree_work(id_a) > dag2.subtree_work(id_b));
    assert_eq!(
        dag2.resolve_conflict_key(&s2, n2),
        Some(id_a),
        "CDW-era legacy follows subtree work"
    );
    assert_eq!(
        dag2.resolve_conflict_key_v6(&s2, n2, &reg, at),
        Some(id_a),
        "CDW-era key: v6 delegates to legacy (newest member pre-V6)"
    );
}

#[test]
fn g25_v6_no_votes_means_min_id() {
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let (dag, (s, n), id_a, id_b) = worked_conflict_dag(v6_ts, v6_ts + 1000);
    let reg = StakeRegistry::new();
    // Empty registry: every support is 0 (T = 0 never quorate, but fork
    // CHOICE still needs a deterministic answer) -> min-id tiebreak.
    assert_eq!(
        dag.resolve_conflict_key_v6(&s, n, &reg, 600_000),
        Some(id_a.min(id_b))
    );
}

#[test]
fn g26_v6_stake_overrules_subtree_work_pow_ignored() {
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let (dag, (s, n), id_a, id_b) = worked_conflict_dag(v6_ts, v6_ts + 1000);
    // A strictly outworks B on every possible hash (2 extra descendants,
    // each crediting >= 1)  -  and carries pow_nonce 0 vs B's u64::MAX.
    // Legacy follows work; v6 must follow STAKE (PoW absent from the path).
    assert!(dag.subtree_work(id_a) > dag.subtree_work(id_b));
    assert_eq!(dag.resolve_conflict_key(&s, n), Some(id_a));

    let wx =
        Wallet::from_secret_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixed key X");
    let wy =
        Wallet::from_secret_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("fixed key Y");
    let at = 600_000u64;
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wx.address(), 200, 0).expect("bond X");
    reg.apply_bond(wy.address(), 100, 0).expect("bond Y");
    // Heavier stake (X=200) backs childless B; lighter (Y=100) backs A.
    let key = (s, n);
    reg.insert_vote(signed_vote(&wx, at, key, id_b, 200));
    reg.insert_vote(signed_vote(&wy, at, key, id_a, 100));
    assert_eq!(
        dag.resolve_conflict_key_v6(&s, n, &reg, at),
        Some(id_b),
        "stake plurality overrules subtree work and PoW fields"
    );
}

#[test]
fn g27_v6_finalized_absolute_against_later_stake() {
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let (dag, (s, n), id_a, id_b) = worked_conflict_dag(v6_ts, v6_ts + 1000);
    let key = (s, n);
    let at = 600_000u64;
    let wx =
        Wallet::from_secret_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixed key X");
    let wy =
        Wallet::from_secret_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("fixed key Y");
    let wz =
        Wallet::from_secret_key("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
            .expect("fixed key Z");
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wx.address(), 200, 0).expect("bond X");
    reg.apply_bond(wy.address(), 100, 0).expect("bond Y");
    reg.apply_bond(wz.address(), 100, 0).expect("bond Z");
    // X+Y back id_a: 300/400... total is 400 (X+Y+Z) -> 300/400 = 3/4 >=
    // 2/3 -> FINALIZED id_a.
    reg.insert_vote(signed_vote(&wx, at, key, id_a, 200));
    reg.insert_vote(signed_vote(&wy, at, key, id_a, 100));
    let members = [id_a, id_b];
    let rec = reg
        .try_finalize(key, &members, at, |_, _| false)
        .expect("quorum for id_a");
    assert_eq!(rec.winner, id_a);
    assert_eq!(
        dag.resolve_conflict_key_v6(&s, n, &reg, at),
        Some(id_a),
        "finalized side leads fork choice"
    );
    // A whale (1000) arrives late backing id_b: support flips 1100 vs 300
    // but fork choice stays with finality (never overturn valid finality).
    let ww =
        Wallet::from_secret_key("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
            .expect("fixed key W");
    reg.apply_bond(ww.address(), 1000, 0).expect("bond W");
    reg.insert_vote(signed_vote(&ww, at, key, id_b, 1000));
    assert_eq!(
        dag.resolve_conflict_key_v6(&s, n, &reg, at),
        Some(id_a),
        "valid finality is absolute against later stake"
    );
}

#[test]
fn g28_strict_descendant_predicate() {
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let (dag, (_, _), id_a, id_b) = worked_conflict_dag(v6_ts, v6_ts + 1000);
    let child_a = *dag
        .children()
        .get(&id_a)
        .expect("A has children")
        .first()
        .expect("first child");
    assert!(dag.is_strict_descendant(&id_a, &child_a));
    assert!(!dag.is_strict_descendant(&id_a, &id_a), "self excluded");
    assert!(
        !dag.is_strict_descendant(&id_a, &id_b),
        "siblings unrelated"
    );
    assert!(!dag.is_strict_descendant(&id_b, &child_a), "wrong branch");
    assert!(
        !dag.is_strict_descendant(&id_a, &[0u8; 32]),
        "genesis never"
    );
    assert!(
        !dag.is_strict_descendant(&[0xFFu8; 32], &child_a),
        "unknown ancestor"
    );
}

/// Rich registry: two voters, one equivocator (slashed), one finalized key.
fn rich_registry(at: u64) -> (StakeRegistry, ([u8; 32], u64), [u8; 32], [u8; 32]) {
    let wa = wallet_a();
    let wb = wallet_b();
    let wc = wallet_c();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), 200, 0).expect("bond A");
    reg.apply_bond(wb.address(), 200, 0).expect("bond B");
    reg.apply_bond(wc.address(), 200, 0).expect("bond C");
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    // A+B back side_a (400/600 still short of quorum  -  C decides below).
    reg.insert_vote(signed_vote(&wa, at, key, side_a, 200));
    reg.insert_vote(signed_vote(&wb, at, key, side_a, 200));
    // C equivocates: first side_b (kept), then side_a (evidence + slash).
    reg.insert_vote(signed_vote(&wc, at, key, side_b, 200));
    match reg.insert_vote(signed_vote(&wc, at, key, side_a, 200)) {
        VoteInsertOutcome::Equivocated { .. } => {}
        other => panic!("expected equivocation, got {:?}", other),
    }
    // C slashed: remaining eligible total 400; side_a has 400/400 -> finalize.
    let members = [side_a, side_b];
    let rec = reg
        .try_finalize(key, &members, at, |_, _| false)
        .expect("quorum after slash");
    assert_eq!(rec.winner, side_a);
    (reg, key, side_a, side_b)
}

#[test]
fn g29_snapshot_restore_equivalence_with_slash_and_finality() {
    let at = 600_000u64;
    let (reg, key, side_a, _) = rich_registry(at);
    let snap1 = reg.snapshot();
    assert_eq!(snap1.validators.len(), 3);
    assert_eq!(snap1.evidence.len(), 1);
    let restored = StakeRegistry::restore(snap1.clone()).expect("restore");
    // Byte-level equivalence: re-snapshot must equal the saved snapshot.
    assert_eq!(restored.snapshot(), snap1);
    // Semantics survive: slash enforced, finality sticky, support zeroed.
    assert_eq!(restored.finalized_winner(&key), Some(side_a));
    let wc = wallet_c();
    assert_eq!(restored.voting_weight(&wc.address(), at), 0);
    // Corrupt snapshot fails closed (never partial).
    let mut bad = snap1.clone();
    bad.votes.push(vec![0u8; 10]);
    assert!(StakeRegistry::restore(bad).is_err());
}

#[test]
fn g30_storage_save_load_roundtrip_and_fresh_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(dir.path()).expect("open");
    // Fresh database: no manifest -> None (caller starts empty).
    assert!(storage.load_registry().expect("load").is_none());
    let at = 600_000u64;
    let (reg, key, side_a, _) = rich_registry(at);
    storage.save_registry(&reg).expect("save");
    let loaded = storage
        .load_registry()
        .expect("load")
        .expect("registry present");
    assert_eq!(loaded.snapshot(), reg.snapshot());
    assert_eq!(loaded.finalized_winner(&key), Some(side_a));
    // Per-record accessors agree with the loaded registry.
    let wc = wallet_c();
    let rec = storage
        .get_validator_record(&wc.address())
        .expect("get")
        .expect("slashed record retained");
    assert_eq!(rec.state, ValidatorState::Slashed);
    assert!(storage
        .get_finalized(&key)
        .expect("get finalized")
        .is_some());
    // Re-save is idempotent (authoritative rewrite, same bytes back).
    storage.save_registry(&loaded).expect("resave");
    let reloaded = storage.load_registry().expect("reload").expect("present");
    assert_eq!(reloaded.snapshot(), reg.snapshot());
}

#[test]
fn g31_storage_partial_save_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(dir.path()).expect("open");
    let at = 600_000u64;
    let (reg, _, _, _) = rich_registry(at);
    storage.save_registry(&reg).expect("save");
    // Sneak an extra validator record past the manifest (simulates a crash
    // between record writes, or manual tampering): counts diverge -> Err.
    let extra = crate::stake::ValidatorRecord {
        address: [0xEEu8; 32],
        bonded_amount: MIN_STAKE,
        state: ValidatorState::Bonded,
        bonded_epoch: 0,
        slashed_epoch: None,
    };
    storage.put_validator_record(&extra).expect("sneak");
    assert!(
        storage.load_registry().is_err(),
        "count mismatch fails closed"
    );
}

#[test]
fn g32_rebuild_v6_applies_stake_winner() {
    // Post-V6 double spend funded through the DAG itself (faucet -> S):
    // the stake-plurality side applies, the other stays residue  -  even
    // though both are fully valid, retained DAG members.
    fn funded_tx(
        parents: [[u8; 32]; 2],
        sender: [u8; 32],
        receiver: [u8; 32],
        amount: u64,
        fee: u64,
        timestamp: u64,
        account_nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction::new(
            parents,
            sender,
            receiver,
            amount,
            fee,
            timestamp,
            0,
            account_nonce,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        tx.id = tx.compute_hash();
        tx
    }
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
        .expect("faucet hex")
        .try_into()
        .expect("faucet len");
    let sender = [0x77u8; 32];
    let recv_a = [0xA1u8; 32];
    let recv_b = [0xB2u8; 32];
    let mut dag = DAG::new();
    let fund = funded_tx([[0u8; 32]; 2], faucet, sender, 100_000, 100, v6_ts, 0);
    let fund_id = fund.id;
    dag.add_transaction_validated(fund).expect("fund inserts");
    let a = funded_tx([fund_id, [0u8; 32]], sender, recv_a, 100, 100, v6_ts + 1, 5);
    let b = funded_tx([fund_id, [0u8; 32]], sender, recv_b, 100, 100, v6_ts + 2, 5);
    let (id_a, id_b) = (a.id, b.id);
    dag.add_transaction_validated(a).expect("A inserts");
    dag.add_transaction_validated(b)
        .expect("B inserts (retained)");
    assert_ne!(id_a, id_b);

    // Stake backs the LARGER id (whatever min-id/CDW would pick, the v6
    // rebuild must follow stake  -  divergence from legacy is the point).
    let (stake_side, other_side, recv_stake, recv_other) = if id_a > id_b {
        (id_a, id_b, recv_a, recv_b)
    } else {
        (id_b, id_a, recv_b, recv_a)
    };
    let wx =
        Wallet::from_secret_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixed key X");
    let wy =
        Wallet::from_secret_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("fixed key Y");
    let at = 600_000u64;
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wx.address(), 200, 0).expect("bond X");
    reg.apply_bond(wy.address(), 100, 0).expect("bond Y");
    let key = (sender, 5u64);
    reg.insert_vote(signed_vote(&wx, at, key, stake_side, 200));
    reg.insert_vote(signed_vote(&wy, at, key, other_side, 100));

    let mut ledger = Ledger::new();
    ledger.rebuild_from_dag_v6(&dag, &reg, at);
    assert_eq!(
        ledger.get_balance(&recv_stake),
        100,
        "stake winner's transfer applies"
    );
    assert_eq!(
        ledger.get_balance(&recv_other),
        0,
        "stake loser stays residue (retained, never debits)"
    );
    // Legacy rebuild is untouched by construction (frozen rule)  -  record
    // its answer for the audit trail without asserting equality either way.
    let mut legacy = Ledger::new();
    legacy.rebuild_from_dag(&dag);
    let _ = legacy.get_balance(&recv_a);
}

fn funded_conflict_dag() -> (DAG, ([u8; 32], u64), [u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    // Funded post-V6 conflict shared by the processor admission tests:
    // faucet -> S, then S double-spends (nonce 5) to recv_a / recv_b.
    // Returns (dag, key, id_a, id_b, recv_a, recv_b).
    fn funded_tx(
        parents: [[u8; 32]; 2],
        sender: [u8; 32],
        receiver: [u8; 32],
        amount: u64,
        fee: u64,
        timestamp: u64,
        account_nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction::new(
            parents,
            sender,
            receiver,
            amount,
            fee,
            timestamp,
            0,
            account_nonce,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        tx.id = tx.compute_hash();
        tx
    }
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
        .expect("faucet hex")
        .try_into()
        .expect("faucet len");
    let sender = [0x77u8; 32];
    let recv_a = [0xA1u8; 32];
    let recv_b = [0xB2u8; 32];
    let mut dag = DAG::new();
    let fund = funded_tx([[0u8; 32]; 2], faucet, sender, 100_000, 100, v6_ts, 0);
    let fund_id = fund.id;
    dag.add_transaction_validated(fund).expect("fund inserts");
    let a = funded_tx([fund_id, [0u8; 32]], sender, recv_a, 100, 100, v6_ts + 1, 5);
    let b = funded_tx([fund_id, [0u8; 32]], sender, recv_b, 100, 100, v6_ts + 2, 5);
    let (id_a, id_b) = (a.id, b.id);
    dag.add_transaction_validated(a).expect("A inserts");
    dag.add_transaction_validated(b)
        .expect("B inserts (retained)");
    (dag, (sender, 5u64), id_a, id_b, recv_a, recv_b)
}

#[tokio::test]
async fn g33_process_vote_end_to_end_applies_stake_winner() {
    let (dag, key, id_a, id_b, recv_a, recv_b) = funded_conflict_dag();
    let dag = Arc::new(RwLock::new(dag));
    let ledger = Arc::new(RwLock::new(Ledger::new()));
    let registry = Arc::new(RwLock::new(StakeRegistry::new()));
    let mut processor = TransactionProcessor::new();
    processor.set_stake_registry(registry.clone());

    // Wall-clock epochs (process_vote evaluates at current_epoch):
    // bonds matured 10 epochs ago, votes now.
    let at = current_epoch();
    let wx =
        Wallet::from_secret_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixed key X");
    let wy =
        Wallet::from_secret_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("fixed key Y");
    {
        let mut reg = registry.write().await;
        reg.apply_bond(wx.address(), 200, at - 10).expect("bond X");
        reg.apply_bond(wy.address(), 100, at - 10).expect("bond Y");
    }
    // Heavier stake backs id_a, lighter backs id_b.
    let va = signed_vote(&wx, at, key, id_a, 200);
    let vb = signed_vote(&wy, at, key, id_b, 100);
    assert_eq!(
        processor.process_vote(va.clone(), &dag, &ledger).await,
        Ok(VoteInsertOutcome::Accepted)
    );
    assert_eq!(
        processor.process_vote(vb, &dag, &ledger).await,
        Ok(VoteInsertOutcome::Accepted)
    );
    // Idempotent replay: Duplicate, ledger untouched by the replay.
    assert_eq!(
        processor.process_vote(va, &dag, &ledger).await,
        Ok(VoteInsertOutcome::Duplicate)
    );
    let ledger_guard = ledger.read().await;
    assert_eq!(ledger_guard.get_balance(&recv_a), 100);
    assert_eq!(ledger_guard.get_balance(&recv_b), 0);
    drop(ledger_guard);

    // No-registry processor rejects stake admission fail-closed.
    let bare = TransactionProcessor::new();
    let v = signed_vote(&wx, at, key, id_a, 200);
    assert!(bare.process_vote(v, &dag, &ledger).await.is_err());
}

#[tokio::test]
async fn g34_process_bond_unbond_lifecycle() {
    let ledger = Arc::new(RwLock::new(Ledger::new()));
    let registry = Arc::new(RwLock::new(StakeRegistry::new()));
    let mut processor = TransactionProcessor::new();
    processor.set_stake_registry(registry.clone());
    let at = current_epoch();
    let wa = wallet_a();
    {
        let mut ledger_guard = ledger.write().await;
        ledger_guard.set_balance(&wa.address(), MIN_STAKE * 2);
    }
    // Dust rejected; funded bond accepted (immature: no vote yet).
    assert!(processor
        .process_bond(signed_bond(&wa, MIN_STAKE - 1, at), &ledger)
        .await
        .is_err());
    processor
        .process_bond(signed_bond(&wa, MIN_STAKE, at), &ledger)
        .await
        .expect("bond accepted");
    {
        let reg = registry.read().await;
        assert!(!reg.is_eligible(&wa.address(), at), "immature: cannot vote");
    }
    // Replay of the SAME bond bytes: idempotent Ok, NO second top-up
    // (each top-up needs a fresh signature, i.e. a new id). Maturation
    // is still measured from the signed creation epoch.
    let same_bond = signed_bond(&wa, MIN_STAKE, at);
    processor
        .process_bond(same_bond, &ledger)
        .await
        .expect("bond replay is idempotent Ok");
    {
        let reg = registry.read().await;
        assert_eq!(
            reg.voting_weight(&wa.address(), at + 100),
            MIN_STAKE,
            "replay applied nothing (single top-up only)"
        );
    }
    // Exit begins immediately (clean cutover); second exit rejected.
    let dag = Arc::new(RwLock::new(DAG::new()));
    processor
        .process_unbond(signed_unbond(&wa, at), &dag, &ledger)
        .await
        .expect("unbond accepted");
    {
        let reg = registry.read().await;
        assert!(!reg.is_eligible(&wa.address(), at + 10_000));
        assert_eq!(reg.voting_weight(&wa.address(), at + 10_000), 0);
    }
    assert!(processor
        .process_unbond(signed_unbond(&wa, at), &dag, &ledger)
        .await
        .is_err());
}

#[test]
fn g35_p2p_wire_tail_compat_and_kinds_roundtrip() {
    // Bincode enum index is positional: pre-4G variants MUST keep indices
    // 0..=8 so old binaries decode every legacy message identically.
    // New kinds sit at the tail (9, 10, 11).
    fn variant_index(msg: &P2PMessage) -> u32 {
        let bytes = bincode::serialize(msg).expect("serialize");
        u32::from_le_bytes(bytes[..4].try_into().expect("index bytes"))
    }
    assert_eq!(variant_index(&P2PMessage::Transaction(vec![1])), 0);
    assert_eq!(variant_index(&P2PMessage::Inventory(vec![])), 1);
    assert_eq!(variant_index(&P2PMessage::GetData(vec![])), 2);
    assert_eq!(variant_index(&P2PMessage::Ping), 6);
    assert_eq!(variant_index(&P2PMessage::Pong), 7);
    // Peers index (6 fields before it: keep in sync with the enum).
    let peers_idx = variant_index(&P2PMessage::Peers(vec![]));
    assert_eq!(
        variant_index(&P2PMessage::Vote(vec![9u8; 257])),
        peers_idx + 1
    );
    assert_eq!(
        variant_index(&P2PMessage::Bond(vec![9u8; 113])),
        peers_idx + 2
    );
    assert_eq!(
        variant_index(&P2PMessage::Unbond(vec![9u8; 105])),
        peers_idx + 3
    );
    // Round-trips (payloads opaque at this layer).
    for msg in [
        P2PMessage::Vote(vec![9u8; 257]),
        P2PMessage::Bond(vec![9u8; 113]),
        P2PMessage::Unbond(vec![9u8; 105]),
    ] {
        let back: P2PMessage =
            bincode::deserialize(&bincode::serialize(&msg).expect("ser")).expect("decode");
        assert_eq!(format!("{:?}", back), format!("{:?}", msg));
    }
}

#[tokio::test]
async fn g36_rpc_stake_endpoints_end_to_end() {
    use crate::p2p::P2PConfig;
    use crate::rpc::{AetherRpcImpl, Mempool};
    // Minimal RpcImpl (mirrors rpc::tests::test_rpc_impl) + registry.
    let dir = tempfile::tempdir().expect("tempdir");
    let dag = Arc::new(RwLock::new(DAG::new()));
    let ledger = Arc::new(RwLock::new(Ledger::new()));
    let storage = Arc::new(RwLock::new(
        Storage::open(dir.path().join("sled")).expect("open"),
    ));
    let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
    let (tx_channel, _rx) = tokio::sync::mpsc::unbounded_channel::<Transaction>();
    let p2p = Arc::new(crate::p2p::P2PNetwork::new(
        P2PConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: crate::transaction::DEFAULT_NETWORK_ID,
        },
        tx_channel,
        Arc::new(|| Vec::new()),
        Arc::new(|_| None),
        Arc::new(|| Vec::new()),
        Arc::new(crate::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    let mut rpc_impl = AetherRpcImpl::new(
        dag.clone(),
        ledger.clone(),
        storage,
        dir.path().join("ledger.json"),
        mempool,
        p2p,
        Arc::new(RwLock::new(true)),
        Arc::new(RwLock::new(std::collections::HashMap::new())),
        Arc::new(crate::sync_stats::SyncContext::default()),
    );
    // Unwired: stake endpoints fail closed.
    let wx =
        Wallet::from_secret_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixed key X");
    let at = current_epoch();
    let key = ([9u8; 32], 3u64);
    let dummy_vote = signed_vote(&wx, at, key, [0xAAu8; 32], 200);
    let dummy_hex = hex::encode(dummy_vote.encode());
    assert!(rpc_impl
        .submit_vote(serde_json::json!([dummy_hex]))
        .await
        .is_err());
    assert!(rpc_impl.get_validators().await.is_err());

    // Wire + voters (X heavy, Y light  -  bonded directly, matured long
    // ago; RPC bonds below always carry near-current epochs, which can
    // never be mature yet, so voter setup bypasses submission here).
    let registry = Arc::new(RwLock::new(StakeRegistry::new()));
    rpc_impl.set_stake_registry(registry.clone());
    let wy =
        Wallet::from_secret_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("fixed key Y");
    {
        let mut reg = registry.write().await;
        reg.apply_bond(wx.address(), MIN_STAKE * 2, at - 10)
            .expect("bond X");
        reg.apply_bond(wy.address(), MIN_STAKE, at - 10)
            .expect("bond Y");
        let mut ledger_guard = ledger.write().await;
        ledger_guard.set_balance(&wx.address(), MIN_STAKE * 3);
        ledger_guard.set_balance(&wy.address(), MIN_STAKE * 2);
    }
    // Third validator bonds through the endpoint (near-current epoch:
    // accepted but immature  -  contributes nothing yet).
    let wz = wallet_c();
    {
        let mut ledger_guard = ledger.write().await;
        ledger_guard.set_balance(&wz.address(), MIN_STAKE * 2);
    }
    let bz = signed_bond(&wz, MIN_STAKE, at);
    let rb = rpc_impl
        .submit_bond(serde_json::json!([hex::encode(bz.encode())]))
        .await
        .expect("bond Z");
    assert_eq!(rb.status, "accepted");
    // Dust bond rejected (strict decode ok, admission refuses).
    let dust = signed_bond(&wx, 1, at);
    assert!(rpc_impl
        .submit_bond(serde_json::json!([hex::encode(dust.encode())]))
        .await
        .is_err());

    // Votes: both back side_a (unanimous -> finality on next trigger).
    let side_a = [0xAAu8; 32];
    let vx = signed_vote(&wx, at, key, side_a, MIN_STAKE * 2);
    let vy = signed_vote(&wy, at, key, side_a, MIN_STAKE);
    let rx_out = rpc_impl
        .submit_vote(serde_json::json!([hex::encode(vx.encode())]))
        .await
        .expect("vote X");
    assert_eq!(rx_out.status, "accepted");
    // Duplicate replay: idempotent status, no error.
    let dup = rpc_impl
        .submit_vote(serde_json::json!([hex::encode(vx.encode())]))
        .await
        .expect("duplicate ok");
    assert_eq!(dup.status, "duplicate");
    rpc_impl
        .submit_vote(serde_json::json!([hex::encode(vy.encode())]))
        .await
        .expect("vote Y");

    // Queries: validators list (X + Y mature, Z immature  -  total counts
    // eligible weight only) + finality (no DAG members here, so no
    // finalized decision  -  members < 2 means no conflict to decide).
    let validators = rpc_impl.get_validators().await.expect("validators");
    assert_eq!(validators["returned"], 3);
    assert_eq!(validators["eligible_total"], MIN_STAKE * 3);
    let fin = rpc_impl
        .get_finality(serde_json::json!([hex::encode(key.0), key.1]))
        .await
        .expect("finality query");
    assert!(fin["winner"].is_null());
    assert_eq!(fin["members"], 0);

    // Unbond X: accepted; eligible total drops to Y only.
    let ux = signed_unbond(&wx, at);
    let ru = rpc_impl
        .submit_unbond(serde_json::json!([hex::encode(ux.encode())]))
        .await
        .expect("unbond X");
    assert_eq!(ru.status, "accepted");
    let validators2 = rpc_impl.get_validators().await.expect("validators2");
    assert_eq!(validators2["eligible_total"], MIN_STAKE);
}
