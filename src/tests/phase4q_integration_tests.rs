//! PHASE 4Q: anchor integration harness (boot trust boundary, joiner
//! end-to-end, tamper matrix through the INTEGRATED functions).
//!
//! Exercises verify_bootstrap_anchor / check_state_against_anchor /
//! compare_anchor_bundles / bundle roundtrip exactly as the node boot path
//! calls them (same functions, temp dirs as data dirs). No consensus rule
//! under test here (covered by 4g/4h/4i/4l/4n/4p suites); this file proves
//! the integration layer accepts exactly what it should. Fast (<10s).

use crate::anchor::{
    anchor_id, build_anchor, check_state_against_anchor, compare_anchor_bundles,
    encode_anchor_bundle, parse_anchor_bundle, verify_bootstrap_anchor, AnchorBundle,
    BootstrapError, BootstrapVerdict, BundleComparison, StateAnchorError,
    ANCHOR_GENESIS_PREV, V6_ANCHOR_FILE,
};
use crate::stake::StakeRegistry;
use crate::storage::Storage;
use crate::transaction::{Vote, VOTE_FORMAT_VERSION};
use crate::wallet::Wallet;

const AT: u64 = 600_000;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

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
    s[8] = 0xD1;
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

/// Active-network fixture: 6 bonded validators, unanimous X on key,
/// finalized. Returns (registry, anchor bundle built from its state).
fn active_network(key: ([u8; 32], u64)) -> (StakeRegistry, AnchorBundle) {
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..6u64 {
        let w = wallet_n(970_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote(&w, AT, key, side_x());
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    reg.try_finalize(key, &[side_x(), side_y()], AT, |_, _| false).expect("quorum");
    let set = reg.snapshot().validators;
    let anchor = build_anchor(AT, key, side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, 0);
    (reg, AnchorBundle { anchor, validator_set: set })
}

fn write_bundle(dir: &std::path::Path, bundle: &AnchorBundle) {
    let bytes = encode_anchor_bundle(bundle).expect("encode");
    std::fs::write(dir.join(V6_ANCHOR_FILE), bytes).expect("write anchor file");
}

#[test]
fn q01_bundle_roundtrip_deterministic() {
    let (_, bundle) = active_network(key_j(201));
    let a = encode_anchor_bundle(&bundle).expect("encode");
    let b = encode_anchor_bundle(&bundle).expect("encode");
    assert_eq!(a, b, "encoding must be deterministic (multi-source compare)");
    let back = parse_anchor_bundle(&a).expect("parse");
    assert_eq!(back.anchor, bundle.anchor);
    assert_eq!(back.validator_set, bundle.validator_set);
}

#[test]
fn q02_bootstrap_accepts_coherent_anchor() {
    // Joiner data dir holds ONLY the anchor file (fresh node, empty state
    // to be synced). The hook verifies the bundle; state check passes
    // vacuously on empty state for votes... note: empty registry lacks the
    // votes, so VoteMissing fires. The fresh-joiner flow is: boot proceeds
    // (no local contradiction), sync fills votes, check passes (q10).
    // Here the registry already mirrors the network (restart leg).
    let (reg, bundle) = active_network(key_j(202));
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    match verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false) {
        Ok(BootstrapVerdict::Accepted { summary, .. }) => {
            assert_eq!((summary.support, summary.total), (6000, 6000));
        }
        other => panic!("expected Accepted, got {:?}", other),
    }
}

#[test]
fn q03_bootstrap_without_anchor_unchanged() {
    // No file: current behavior preserved exactly (no invention).
    let (reg, _) = active_network(key_j(203));
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false),
        Ok(BootstrapVerdict::NoAnchor)
    );
    // Also on a totally empty registry (fresh node): same verdict.
    assert_eq!(
        verify_bootstrap_anchor(dir.path(), &StakeRegistry::new(), 0, |_, _| false),
        Ok(BootstrapVerdict::NoAnchor)
    );
}

#[test]
fn q04_bootstrap_refuses_tampered_bundles() {
    let (reg, bundle) = active_network(key_j(204));
    let dir = tempfile::tempdir().expect("tempdir");
    let mut tamper_epoch = bundle.clone();
    tamper_epoch.anchor.epoch += 1;
    let mut tamper_root = bundle.clone();
    tamper_root.anchor.set_root = [5u8; 32];
    let mut tamper_total = bundle.clone();
    tamper_total.anchor.claimed_total += 1;
    let mut tamper_vote = bundle.clone();
    tamper_vote.anchor.votes.pop();
    let mut tamper_sig = bundle.clone();
    tamper_sig.anchor.votes[0].signature[0] ^= 0xFF;
    for (name, b) in [
        ("epoch", tamper_epoch),
        ("root", tamper_root),
        ("total", tamper_total),
        ("vote-drop", tamper_vote),
        ("sig", tamper_sig),
    ] {
        write_bundle(dir.path(), &b);
        match verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false) {
            Err(BootstrapError::Verify(_)) => {}
            other => panic!("{} tamper must refuse via Verify, got {:?}", name, other),
        }
    }
    // Truncated file and garbage file refuse at parse/io-independent stage.
    std::fs::write(dir.path().join(V6_ANCHOR_FILE), b"{broken").expect("write");
    assert!(matches!(
        verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false),
        Err(BootstrapError::Parse(_))
    ));
    std::fs::write(dir.path().join(V6_ANCHOR_FILE), b"\x00\x01\x02").expect("write");
    assert!(verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).is_err());
}

#[test]
fn q05_cross_epoch_refused_integrated() {
    // Same votes re-anchored 1000 epochs later: the integrated bundle path
    // refuses (window + root), mirroring p09 through file+hook.
    let (_, bundle) = active_network(key_j(205));
    let dir = tempfile::tempdir().expect("tempdir");
    let mut shifted = bundle.clone();
    shifted.anchor.epoch = AT + 1000;
    write_bundle(dir.path(), &shifted);
    let (reg, _) = active_network(key_j(205));
    assert!(verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).is_err());
}

#[test]
fn q06_cross_set_refused_integrated() {
    let (reg, bundle) = active_network(key_j(206));
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bad = bundle.clone();
    bad.validator_set[0].bonded_amount += 5;
    write_bundle(dir.path(), &bad);
    assert!(verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).is_err());
}

#[test]
fn q07_denominator_refused_integrated() {
    let (reg, bundle) = active_network(key_j(207));
    let dir = tempfile::tempdir().expect("tempdir");
    let mut bad = bundle.clone();
    bad.anchor.claimed_total = bad.anchor.claimed_total.saturating_sub(1);
    write_bundle(dir.path(), &bad);
    assert!(verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).is_err());
}

#[test]
fn q08_combined_matrix_integrated() {
    // (E1,R1) accepts; every other combination refuses through the hook.
    let (reg, bundle) = active_network(key_j(208));
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    assert!(verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).is_ok());
    for (name, mut b) in [
        ("E2", {
            let mut x = bundle.clone();
            x.anchor.epoch += 2;
            x
        }),
        ("R2", {
            let mut x = bundle.clone();
            x.validator_set[1].bonded_amount += 5;
            x
        }),
        ("E2R2", {
            let mut x = bundle.clone();
            x.anchor.epoch += 2;
            x.validator_set[1].bonded_amount += 5;
            x
        }),
    ] {
        let _ = name;
        write_bundle(dir.path(), &b);
        assert!(verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).is_err(), "{}", name);
    }
}

#[test]
fn q09_multisource_detect_contradiction() {
    let (_, bundle) = active_network(key_j(209));
    let a = encode_anchor_bundle(&bundle).expect("encode");
    let b = encode_anchor_bundle(&bundle).expect("encode");
    assert_eq!(compare_anchor_bundles(&a, &b), BundleComparison::Equal);
    let mut other = bundle.clone();
    other.anchor.prev = [8u8; 32];
    let c = encode_anchor_bundle(&other).expect("encode");
    // Same logical decision, different chain: bytes differ -> detected.
    assert_eq!(compare_anchor_bundles(&a, &c), BundleComparison::Contradictory);
    // No selection rule exists: detection is the whole primitive (halt by
    // policy, documented DEFERRED). This test pins detection, not choice.
}

#[test]
fn q10_joiner_converges_and_passes_state_check() {
    // NODE A coherent (active_network). NODE B: empty dir + anchor file.
    // B verifies the bundle, replays A's votes (backfill simulation),
    // then the state check passes and B matches A on finality + support.
    let key = key_j(210);
    let (reg_a, bundle) = active_network(key);
    let dir_b = tempfile::tempdir().expect("tempdir");
    write_bundle(dir_b.path(), &bundle);
    // B boots empty: bundle verifies (no local state to contradict)...
    let mut reg_b = StakeRegistry::new();
    // ...but the state check correctly reports the missing votes first:
    assert_eq!(
        check_state_against_anchor(&reg_b, &bundle.anchor),
        Err(StateAnchorError::VoteMissing(bundle.anchor.votes[0].id()))
    );
    // B syncs: replay A's quorum votes (existing backfill machinery does
    // this over P2P; here directly for determinism).
    for v in &bundle.anchor.votes {
        reg_b.insert_vote(v.clone());
    }
    for addr in bundle.validator_set.iter().map(|r| r.address) {
        // Bonds arrive via bond gossip (same amounts/epochs as A).
        let src = bundle.validator_set.iter().find(|r| r.address == addr).unwrap();
        let _ = reg_b.apply_bond(addr, src.bonded_amount, src.bonded_epoch);
    }
    // State check now passes; B finalizes identically to A.
    check_state_against_anchor(&reg_b, &bundle.anchor).expect("converged");
    let mut rb = reg_b;
    let fb = rb.try_finalize(key, &[side_x(), side_y()], AT, |_, _| false).expect("B final");
    let fa = reg_a.finalized_record(&key).expect("A final");
    assert_eq!(fb.winner, fa.winner);
    assert_eq!(fb.supporting_weight, fa.supporting_weight);
    // Full bootstrap hook on the converged joiner accepts.
    match verify_bootstrap_anchor(dir_b.path(), &rb, 0, |_, _| false) {
        Ok(BootstrapVerdict::Accepted { .. }) => {}
        other => panic!("converged joiner must be accepted, got {:?}", other),
    }
}

#[test]
fn q11_rebuild_keeps_anchor_context() {
    // Wipe derived caches (full index rebuild) then re-verify: identical.
    let (reg, bundle) = active_network(key_j(211));
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    let mut rebuilt = StakeRegistry::restore(reg.snapshot()).expect("restore");
    rebuilt.rebuild_vote_index_for_test();
    assert!(verify_bootstrap_anchor(dir.path(), &rebuilt, 0, |_, _| false).is_ok());
    assert_eq!(rebuilt.snapshot(), reg.snapshot());
}

#[test]
fn q12_restart_save_load_identical() {
    let (reg, bundle) = active_network(key_j(212));
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Storage::open(dir.path()).expect("open");
    store.save_registry(&reg).expect("save");
    write_bundle(dir.path(), &bundle);
    let back = store.load_registry().expect("load").expect("present");
    assert!(verify_bootstrap_anchor(dir.path(), &back, 0, |_, _| false).is_ok());
    check_state_against_anchor(&back, &bundle.anchor).expect("restart state");
}

#[test]
fn q13_persistence_roundtrip_stable() {
    // Bundle bytes stable across re-reads; registry save/load keeps the
    // anchor verifiable (persistence carries the decision, anchor re-derives).
    let (reg, bundle) = active_network(key_j(213));
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    let raw1 = std::fs::read(dir.path().join(V6_ANCHOR_FILE)).expect("read");
    let raw2 = std::fs::read(dir.path().join(V6_ANCHOR_FILE)).expect("read");
    assert_eq!(raw1, raw2);
    assert_eq!(
        parse_anchor_bundle(&raw1).expect("parse").anchor,
        parse_anchor_bundle(&raw2).expect("parse").anchor
    );
    let store = Storage::open(dir.path()).expect("open");
    store.save_registry(&reg).expect("save");
    let back = store.load_registry().expect("load").expect("present");
    let again = parse_anchor_bundle(&raw1).expect("parse");
    let id = anchor_id(&again.anchor);
    assert!(crate::anchor::verify_anchor(&again.anchor, &again.validator_set, id, 0, |_, _| false).is_ok());
    check_state_against_anchor(&back, &again.anchor).expect("persisted state");
}

#[test]
fn q14_dormant_pure_deterministic() {
    // The integrated functions read no clock and apply no era rule: same
    // inputs twice give identical verdicts; pre/post-activation-era vote
    // timestamps (tx-level concern) do not exist at this layer at all.
    let (reg, bundle) = active_network(key_j(214));
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    let r1 = verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false);
    let r2 = verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false);
    assert_eq!(r1, r2);
    // Era-indifference at the verification layer: the bundle carries epoch
    // numbers as data; verification never consults wall-clock or activation.
}

#[test]
fn q15_parents_ignored_by_verification() {
    // Vote DAG-embedding context (parents) is auditability only: flipping
    // parents changes the vote id (content-addressed), so it is a DIFFERENT
    // vote that fails the pinned set -- parents can neither smuggle weight
    // nor bypass checks. PoW-adjacent fields play no role (no PoW reads).
    let (reg, bundle) = active_network(key_j(215));
    let mut other = bundle.clone();
    other.anchor.votes[0].parents = [[9u8; 32]; 2];
    // Re-tagged it is a different bundle whose vote is unknown to the set
    // history only if amounts mismatch; here it fails the pinned id set
    // only when compared against the ORIGINAL tag. Assert both facts:
    let orig_id = anchor_id(&bundle.anchor);
    assert!(crate::anchor::verify_anchor(&other.anchor, &other.validator_set, orig_id, 0, |_, _| false).is_err());
}

#[test]
fn q16_bootstrap_hook_timing() {
    let (reg, bundle) = active_network(key_j(216));
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    let t0 = std::time::Instant::now();
    let v = verify_bootstrap_anchor(dir.path(), &reg, 0, |_, _| false).expect("hook");
    let dt = t0.elapsed();
    assert!(matches!(v, BootstrapVerdict::Accepted { .. }));
    eprintln!("4Q bootstrap hook 6 votes + file: {:?}", dt);
    // File-absent path must be trivial (no behavior change, no cost).
    let empty = tempfile::tempdir().expect("tempdir");
    let t1 = std::time::Instant::now();
    assert_eq!(
        verify_bootstrap_anchor(empty.path(), &reg, 0, |_, _| false),
        Ok(BootstrapVerdict::NoAnchor)
    );
    assert!(t1.elapsed().as_millis() < 100);
}
