//! PHASE 4N: checkpoint / long-range / weak-subjectivity harness.
//!
//! The code has NO checkpoint type: the falsifiable trust object is the
//! F-D4 finality certificate (FinalizedRecord + quorum votes, verified by
//! StakeRegistry::verify_certificate). These tests pin exactly what a lone
//! certificate proves and what it does NOT prove (epoch advisory, pinned
//! weights/denominator are claims, no state-root binding), plus a
//! registry-level long-range scenario (real vs alternate history
//! indistinguishability without an anchor). All fixtures deterministic.

use crate::stake::{StakeRegistry, ValidatorState};
use crate::transaction::{Vote, VOTE_FORMAT_VERSION};
use crate::wallet::Wallet;

const AT: u64 = 600_000;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn signed_vote(w: &Wallet, epoch: u64, key: ([u8; 32], u64), side: [u8; 32]) -> Vote {
    let mut v = Vote {
        format_version: VOTE_FORMAT_VERSION,
        validator: w.address(),
        epoch,
        conflict_sender: key.0,
        conflict_nonce: key.1,
        side,
        stake_epoch: epoch,
        stake_amount: 1000,
        parents: [[0u8; 32]; 2],
        signature: [0u8; 64],
    };
    let sig = w.sign_transaction_hash(&v.signing_bytes()).expect("sign");
    v.signature = sig.to_bytes();
    assert!(v.verify_signature());
    v
}

fn key_j(j: u64) -> ([u8; 32], u64) {
    let mut s = [0u8; 32];
    s[0..8].copy_from_slice(&j.to_le_bytes());
    s[8] = 0xCE;
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

/// Four bonded validators voting X on key 71, finalized. Returns the
/// registry plus the exact quorum vote vec used in the certificate.
fn finalized_x4() -> (StakeRegistry, Vec<Vote>) {
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(900_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote(&w, AT, key_j(71), side_x());
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    let rec = reg
        .try_finalize(key_j(71), &[side_x(), side_y()], AT, |_, _| false)
        .expect("quorum 4/4");
    assert_eq!(rec.supporting_weight, 4000);
    (reg, votes)
}

#[test]
fn n01_valid_certificate_verifies() {
    let (reg, votes) = finalized_x4();
    let cert = reg.finalized_record(&key_j(71)).expect("record");
    let t0 = std::time::Instant::now();
    let r = StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &votes,
        |_, _| false,
    );
    let dt = t0.elapsed();
    assert!(r.is_ok(), "valid cert must verify: {:?}", r);
    eprintln!("4N CERT verify 4 votes: {:?}", dt);
}

#[test]
fn n02_tampered_winner_rejected() {
    let (reg, votes) = finalized_x4();
    let mut cert = reg.finalized_record(&key_j(71)).expect("record");
    cert.winner = side_y();
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &votes,
        |_, _| false
    )
    .is_err());
}

#[test]
fn n03_tampered_numbers_rejected() {
    let (reg, votes) = finalized_x4();
    let cert = reg.finalized_record(&key_j(71)).expect("record");
    // Inflate the denominator: pinned quorum no longer holds.
    let mut bad = cert.clone();
    bad.eligible_total = cert.eligible_total.saturating_add(1_000_000);
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &bad,
        &votes,
        |_, _| false
    )
    .is_err());
    // Deflate the weight below quorum: rejected as well.
    let mut bad2 = cert.clone();
    bad2.supporting_weight = 1;
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &bad2,
        &votes,
        |_, _| false
    )
    .is_err());
}

#[test]
fn n04_truncated_or_padded_set_rejected() {
    let (reg, votes) = finalized_x4();
    let cert = reg.finalized_record(&key_j(71)).expect("record");
    // Drop one vote: set no longer matches the pinned set.
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &votes[..3],
        |_, _| false
    )
    .is_err());
    // Pad with a duplicate-validator vote: distinct-validators rule fires.
    let mut padded = votes.clone();
    padded.push(votes[0].clone());
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &padded,
        |_, _| false
    )
    .is_err());
}

#[test]
fn n05_wrong_key_or_closure_vote_rejected() {
    let (reg, votes) = finalized_x4();
    let cert = reg.finalized_record(&key_j(71)).expect("record");
    // Swap in a vote for another conflict key.
    let w = wallet_n(900_000);
    let mut wrong = votes.clone();
    wrong[0] = signed_vote(&w, AT, key_j(72), side_x());
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &wrong,
        |_, _| false
    )
    .is_err());
    // Swap in a vote pointing outside the winner closure.
    let mut outside = votes.clone();
    outside[1] = signed_vote(&wallet_n(900_001), AT, key_j(71), side_y());
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &outside,
        |_, _| false
    )
    .is_err());
}

#[test]
fn n06_bad_signature_rejected() {
    let (reg, votes) = finalized_x4();
    let cert = reg.finalized_record(&key_j(71)).expect("record");
    let mut bad = votes.clone();
    let mut v0 = bad[0].clone();
    v0.signature[0] ^= 0xFF;
    bad[0] = v0;
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &bad,
        |_, _| false
    )
    .is_err());
}

#[test]
fn n07_epoch_is_advisory_documents_residual() {
    // The verifier never compares cert.epoch (or vote epochs) against
    // anything: a lone certificate carries no trustworthy time. This test
    // pins that behavior as a documented residual, NOT as approval.
    let (reg, votes) = finalized_x4();
    let mut cert = reg.finalized_record(&key_j(71)).expect("record");
    cert.epoch = cert.epoch.saturating_add(1_000_000);
    assert!(
        StakeRegistry::verify_certificate(
            key_j(71),
            &[side_x(), side_y()],
            &cert,
            &votes,
            |_, _| false
        )
        .is_ok(),
        "epoch is currently advisory: altered epoch still verifies (residual)"
    );
}

#[test]
fn n08_denominator_is_a_claim_documents_residual() {
    // Pinned weights/denominator are node claims: a deflated denominator
    // that still satisfies quorum verifies. A lone cert therefore cannot
    // prove its own denominator; the anchor must come with the epoch's
    // validator set (weak subjectivity). Pinned as documented residual.
    let (reg, votes) = finalized_x4();
    let mut cert = reg.finalized_record(&key_j(71)).expect("record");
    cert.eligible_total = cert.supporting_weight; // claim: unanimity
    assert!(
        StakeRegistry::verify_certificate(
            key_j(71),
            &[side_x(), side_y()],
            &cert,
            &votes,
            |_, _| false
        )
        .is_ok(),
        "deflated denominator still verifies (residual: claims, not proof)"
    );
}

#[test]
fn n09_no_state_root_bound_documents_residual() {
    // verify_certificate takes NO ledger/state parameter by construction:
    // certificates prove which branch won with what weight, never what the
    // resulting state is. State comes only from ledger replay. A valid cert
    // verifies with zero state context.
    let (reg, votes) = finalized_x4();
    let cert = reg.finalized_record(&key_j(71)).expect("record");
    assert!(StakeRegistry::verify_certificate(
        key_j(71),
        &[side_x(), side_y()],
        &cert,
        &votes,
        |_, _| false
    )
    .is_ok());
}

#[test]
fn n10_nonexistent_finality_is_none() {
    // No votes, no quorum, no record: nothing to anchor to.
    let mut reg = StakeRegistry::new();
    assert!(reg.finalized_record(&key_j(73)).is_none());
    assert!(reg
        .try_finalize(key_j(73), &[side_x(), side_y()], AT, |_, _| false)
        .is_none());
}

#[test]
fn n11_long_range_real_vs_alternate() {
    // Set A (5 validators) finalizes F1. Then A unbonds/releases and set B
    // bonds. An attacker holding A's old keys builds an alternate history
    // with different votes. Both histories are internally consistent: a
    // new node cannot tell them apart without an anchor.
    let key = key_j(74);
    let mut real = StakeRegistry::new();
    for i in 0..5u64 {
        real.apply_bond(wallet_n(910_000 + i).address(), 1000, 0).expect("bond");
    }
    for i in 0..5u64 {
        let w = wallet_n(910_000 + i);
        real.insert_vote(signed_vote(&w, AT, key, side_x()));
    }
    let f1 = real
        .try_finalize(key, &[side_x(), side_y()], AT, |_, _| false)
        .expect("F1");
    assert_eq!(f1.winner, side_x());
    // Validator-set change: A exits, B enters.
    for i in 0..5u64 {
        real.apply_unbond(wallet_n(910_000 + i).address(), AT).expect("unbond");
    }
    assert_eq!(real.release_matured(AT + 1_000_000).len(), 5);
    for i in 0..5u64 {
        real.apply_bond(wallet_n(920_000 + i).address(), 1000, AT + 999_000).expect("bond B");
    }
    // Alternate history with the SAME old keys, different votes, no X ever.
    let mut alt = StakeRegistry::new();
    for i in 0..5u64 {
        alt.apply_bond(wallet_n(910_000 + i).address(), 1000, 0).expect("bond");
    }
    for i in 0..5u64 {
        let w = wallet_n(910_000 + i);
        alt.insert_vote(signed_vote(&w, AT, key, side_y()));
    }
    let f1p = alt
        .try_finalize(key, &[side_x(), side_y()], AT, |_, _| false)
        .expect("F1p");
    assert_eq!(f1p.winner, side_y());
    assert_ne!(f1.supporting_votes, f1p.supporting_votes);
    // New node N1 replays the real history (bonds + X votes only).
    let mut n1 = StakeRegistry::new();
    for i in 0..5u64 {
        n1.apply_bond(wallet_n(910_000 + i).address(), 1000, 0).expect("bond");
        let w = wallet_n(910_000 + i);
        n1.insert_vote(signed_vote(&w, AT, key, side_x()));
    }
    let n1f = n1.try_finalize(key, &[side_x(), side_y()], AT, |_, _| false).expect("N1");
    assert_eq!(n1f, f1);
    // New node N2 fed only the alternate history converges on F1-prime.
    let mut n2 = StakeRegistry::new();
    for i in 0..5u64 {
        n2.apply_bond(wallet_n(910_000 + i).address(), 1000, 0).expect("bond");
        let w = wallet_n(910_000 + i);
        n2.insert_vote(signed_vote(&w, AT, key, side_y()));
    }
    let n2f = n2.try_finalize(key, &[side_x(), side_y()], AT, |_, _| false).expect("N2");
    assert_eq!(n2f, f1p);
    assert_ne!(n1f.winner, n2f.winner, "indistinguishable without anchor");
}

#[test]
fn n12_anchor_decides() {
    // N3 holds the real quorum votes: the real certificate verifies, the
    // alternate one does not (id-set mismatch), and vice versa. The anchor
    // (certificate + its quorum votes), not the key material, decides.
    let key = key_j(74);
    let mut real_votes = Vec::new();
    let mut real = StakeRegistry::new();
    for i in 0..5u64 {
        let w = wallet_n(910_000 + i);
        real.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote(&w, AT, key, side_x());
        real.insert_vote(v.clone());
        real_votes.push(v);
    }
    let f1 = real.try_finalize(key, &[side_x(), side_y()], AT, |_, _| false).expect("F1");
    let mut alt_votes = Vec::new();
    let mut alt = StakeRegistry::new();
    for i in 0..5u64 {
        let w = wallet_n(910_000 + i);
        alt.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote(&w, AT, key, side_y());
        alt.insert_vote(v.clone());
        alt_votes.push(v);
    }
    let f1p = alt.try_finalize(key, &[side_x(), side_y()], AT, |_, _| false).expect("F1p");
    // Correct anchor verifies.
    assert!(StakeRegistry::verify_certificate(key, &[side_x(), side_y()], &f1, &real_votes, |_, _| false).is_ok());
    // Cross anchors fail both ways.
    assert!(StakeRegistry::verify_certificate(key, &[side_x(), side_y()], &f1p, &real_votes, |_, _| false).is_err());
    assert!(StakeRegistry::verify_certificate(key, &[side_x(), side_y()], &f1, &alt_votes, |_, _| false).is_err());
    // Slashed-state sanity on the real registry path is untouched.
    assert!(real.validator_state(&wallet_n(910_000).address()) != Some(ValidatorState::Slashed));
}
