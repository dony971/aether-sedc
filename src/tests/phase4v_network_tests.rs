//! PHASE 4V: network identity isolation harness (16 charter items).
//!
//! Proves cross-network separation at every bound layer (handshake is
//! covered inside p2p.rs tests, which alone can reach the private frame
//! helpers): admission (validator+processor+RPC), anchor bundles,
//! certificates, storage marker, and dormant-V6 behavior. All fixtures
//! deterministic; networks 7/9 are arbitrary non-default ids (0 = legacy).

use crate::anchor::{
    anchor_id, build_anchor, compare_anchor_bundles,
    encode_anchor_bundle, parse_anchor_bundle, verify_anchor, verify_bootstrap_anchor, AnchorBundle,
    AnchorError, BootstrapVerdict, BundleComparison, ANCHOR_GENESIS_PREV,
    V6_ANCHOR_FILE,
};
use crate::stake::{StakeRegistry, MIN_STAKE};
use crate::transaction::{Vote, VOTE_FORMAT_VERSION, DEFAULT_NETWORK_ID};
use crate::transaction_processor::TransactionProcessor;
use crate::validation::{TransactionValidator, ValidationError};
use crate::wallet::Wallet;

const AT: u64 = 600_000;
const NET_A: u64 = 7;
const NET_B: u64 = 9;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn signed_vote_net(w: &Wallet, epoch: u64, key: ([u8; 32], u64), side: [u8; 32], network: u64, stake: u64) -> Vote {
    let mut v = Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: network,
        validator: w.address(),
        epoch,
        conflict_sender: key.0,
        conflict_nonce: key.1,
        side,
        stake_epoch: epoch,
        stake_amount: stake,
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
    s[8] = 0xD4;
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

/// Validator expecting `network`, registry with one bonded validator.
fn bonded_setup(network: u64) -> (TransactionValidator, StakeRegistry, Wallet) {
    let mut val = TransactionValidator::new();
    val.set_network_id(network);
    let w = wallet_n(400_000 + network);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(w.address(), MIN_STAKE, 5).expect("bond");
    (val, reg, w)
}

#[test]
fn v04_vote_a_on_a() {
    let (val, reg, w) = bonded_setup(NET_A);
    let at = 10u64;
    let good = signed_vote_net(&w, at, key_j(501), side_x(), NET_A, MIN_STAKE);
    assert_eq!(val.validate_vote(&good, &reg, at), Ok(()));
}

#[test]
fn v05_vote_a_on_b_rejected() {
    let (val, reg, w) = bonded_setup(NET_B);
    let at = 10u64;
    // Same keys, same stake, same epoch, valid signature -- wrong network.
    let foreign = signed_vote_net(&w, at, key_j(501), side_x(), NET_A, MIN_STAKE);
    assert!(foreign.verify_signature(), "crypto valid, context wrong");
    assert_eq!(
        val.validate_vote(&foreign, &reg, at),
        Err(ValidationError::WrongNetwork { expected: NET_B, found: NET_A })
    );
}

#[test]
fn v06_anchor_a_on_a() {
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(410_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote_net(&w, AT, key_j(502), side_x(), NET_A, 1000);
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    let set = reg.snapshot().validators;
    let anchor = build_anchor(AT, key_j(502), side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, NET_A);
    let id = anchor_id(&anchor);
    let sum = verify_anchor(&anchor, &set, id, NET_A, |_, _| false).expect("anchor A on A");
    assert_eq!((sum.support, sum.total), (4000, 4000));
    let _ = reg;
}

#[test]
fn v07_anchor_a_on_b_rejected() {
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(420_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote_net(&w, AT, key_j(503), side_x(), NET_A, 1000);
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    let set = reg.snapshot().validators;
    let anchor = build_anchor(AT, key_j(503), side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, NET_A);
    let id = anchor_id(&anchor);
    assert_eq!(
        verify_anchor(&anchor, &set, id, NET_B, |_, _| false),
        Err(AnchorError::WrongNetwork { expected: NET_B, found: NET_A })
    );
}

#[test]
fn v08_certificate_a_on_b_rejected() {
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(430_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote_net(&w, AT, key_j(504), side_x(), NET_A, 1000);
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    let rec = reg.try_finalize(key_j(504), &[side_x(), side_y()], AT, |_, _| false).expect("quorum");
    // Same certificate, foreign expected network: deterministic rejection.
    assert!(StakeRegistry::verify_certificate(key_j(504), &[side_x(), side_y()], &rec, &votes, NET_B, |_, _| false).is_err());
    // ...while its own network verifies (control).
    assert!(StakeRegistry::verify_certificate(key_j(504), &[side_x(), side_y()], &rec, &votes, NET_A, |_, _| false).is_ok());
}

#[test]
fn v09_malformed_network_rejected() {
    // Old 265B-less encodings are length-rejected (never reinterpreted);
    // unknown wire versions rejected; bootstrap bundle without network_id
    // fails parse (required field).
    let (_, _, w) = bonded_setup(0);
    let v = signed_vote_net(&w, AT, key_j(505), side_x(), 0, MIN_STAKE);
    let enc = v.encode();
    assert!(Vote::decode(&enc[..264]).is_err(), "truncation (dropped network tail) rejected");
    let mut bad_ver = enc.clone();
    bad_ver[0] = 0x7F;
    assert!(Vote::decode(&bad_ver).is_err());
    // Previous wire version (v1, pre-network field) is explicitly unknown now.
    let mut old_ver = enc.clone();
    old_ver[0] = 1;
    assert!(Vote::decode(&old_ver).is_err(), "v1 bytes must not parse as v2");
    // Anchor bundle JSON missing network_id: strict parse failure.
    let dir = tempfile::tempdir().expect("tempdir");
    // Bundle JSON without the required network_id field: strict parse failure.
    let raw = br#"{"format":1,"epoch":600000}"#;
    std::fs::write(dir.path().join(V6_ANCHOR_FILE), raw).expect("write");
    let empty = StakeRegistry::new();
    assert!(verify_bootstrap_anchor(dir.path(), &empty, 0, |_, _| false).is_err());
}

#[test]
fn v10_restart_isolation() {
    // Marker claimed by 7: same-7 reboot passes, reboot-as-9 refuses.
    let dir = tempfile::tempdir().expect("tempdir");
    crate::node::verify_data_dir_network(dir.path(), NET_A).expect("fresh claim");
    crate::node::verify_data_dir_network(dir.path(), NET_A).expect("same-network restart");
    assert!(crate::node::verify_data_dir_network(dir.path(), NET_B).is_err());
}

#[tokio::test]
async fn v11_sync_isolation_processor() {
    // P2P-sync admission path (processor with node network): foreign vote
    // rejected before insert/persist/relay; error names the network.
    use crate::ledger::Ledger;
    use crate::parent_selection::DAG;
    use std::sync::Arc;
    let at_now = crate::stake::current_epoch();
    let mut processor = TransactionProcessor::new();
    let mut reg = StakeRegistry::new();
    let w = wallet_n(440_000);
    reg.apply_bond(w.address(), MIN_STAKE, at_now.saturating_sub(10)).expect("bond");
    let reg = Arc::new(tokio::sync::RwLock::new(reg));
    processor.set_stake_registry(reg.clone());
    processor.set_network_id(NET_A);
    let dag = Arc::new(tokio::sync::RwLock::new(DAG::new()));
    let ledger = Arc::new(tokio::sync::RwLock::new(Ledger::new()));
    let foreign = signed_vote_net(&w, at_now, key_j(506), side_x(), NET_B, MIN_STAKE);
    let err = processor
        .process_vote(foreign, &dag, &ledger)
        .await
        .expect_err("foreign vote must not admit");
    assert!(
        matches!(
            err,
            crate::transaction_processor::ProcessingError::ValidationFailed(
                ValidationError::WrongNetwork { expected: NET_A, found: NET_B }
            )
        ),
        "got: {:?}",
        err
    );
}

#[test]
fn v12_storage_isolation_matrix() {
    use crate::node::verify_data_dir_network;
    // Fresh dir adopts caller's network.
    let d0 = tempfile::tempdir().expect("tempdir");
    verify_data_dir_network(d0.path(), 0).expect("legacy adopts 0");
    // Same network reboots pass.
    verify_data_dir_network(d0.path(), 0).expect("same passes");
    // Different network refuses (no silent merge).
    assert!(verify_data_dir_network(d0.path(), NET_A).is_err());
    // Corrupt marker refuses (fail closed, never reinterpreted).
    let d1 = tempfile::tempdir().expect("tempdir");
    std::fs::write(d1.path().join(crate::anchor::NETWORK_MARKER_FILE), b"short").expect("write");
    assert!(verify_data_dir_network(d1.path(), 0).is_err());
    // Pre-4V dir without marker adopts once, then pins.
    let d2 = tempfile::tempdir().expect("tempdir");
    verify_data_dir_network(d2.path(), NET_B).expect("adopt B");
    verify_data_dir_network(d2.path(), NET_B).expect("pinned B");
    assert!(verify_data_dir_network(d2.path(), NET_A).is_err());
}

#[tokio::test]
async fn v13_rpc_isolation() {
    // submitVote for a foreign-network vote is rejected; a same-network
    // vote follows the normal path (accepted here: bonded fixture).
    use crate::ledger::Ledger;
    use crate::parent_selection::DAG;
    use crate::p2p::{P2PConfig, P2PNetwork};
    use crate::rpc::{AetherRpcImpl, Mempool};
    use std::sync::Arc;
    let dir = tempfile::tempdir().expect("tempdir");
    let dag = Arc::new(tokio::sync::RwLock::new(DAG::new()));
    let ledger = Arc::new(tokio::sync::RwLock::new(Ledger::new()));
    let storage = Arc::new(tokio::sync::RwLock::new(
        crate::storage::Storage::open(dir.path().join("sled")).expect("open"),
    ));
    let mempool = Arc::new(tokio::sync::RwLock::new(Mempool::new(1000, 10)));
    let (tx_channel, _rx) =
        tokio::sync::mpsc::channel::<crate::p2p::IngressTx>(crate::p2p::TX_INGRESS_CAPACITY_MSGS);
    let p2p = Arc::new(P2PNetwork::new(
        P2PConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: NET_A,
        },
        tx_channel,
        Arc::new(|| Vec::new()),
        Arc::new(|_| None),
        Arc::new(|| Vec::new()),
        Arc::new(crate::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    let at_now = crate::stake::current_epoch();
    let mut rpc_impl = AetherRpcImpl::new(
        dag.clone(),
        ledger.clone(),
        storage,
        dir.path().join("ledger.json"),
        mempool,
        p2p,
        Arc::new(tokio::sync::RwLock::new(true)),
        Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        Arc::new(crate::sync_stats::SyncContext::default()),
    );
    let mut reg = StakeRegistry::new();
    let w = wallet_n(450_000);
    reg.apply_bond(w.address(), MIN_STAKE, at_now.saturating_sub(10)).expect("bond");
    rpc_impl.set_stake_registry(Arc::new(tokio::sync::RwLock::new(reg)));
    rpc_impl.set_network_id(NET_A);
    let foreign = signed_vote_net(&w, at_now, key_j(507), side_x(), NET_B, MIN_STAKE);
    let params = serde_json::Value::String(hex::encode(foreign.encode()));
    assert!(rpc_impl.submit_vote(params).await.is_err(), "RPC must reject foreign vote");
    let local = signed_vote_net(&w, at_now, key_j(507), side_x(), NET_A, MIN_STAKE);
    let params = serde_json::Value::String(hex::encode(local.encode()));
    assert!(rpc_impl.submit_vote(params).await.is_ok(), "RPC accepts same-network vote");
}

#[test]
fn v14_dormant_v6_isolation() {
    // Default (legacy) fixtures validate exactly as before: network 0 is
    // the neutral element (0 == 0 everywhere). Consensus math is
    // network-blind by construction: identical votes differing ONLY in
    // network give identical support totals on the reference path (the
    // network gate lives strictly at admission/verification).
    let val = TransactionValidator::new();
    let (_, reg, w) = bonded_setup(DEFAULT_NETWORK_ID);
    let at = 10u64;
    let v0 = signed_vote_net(&w, at, key_j(508), side_x(), 0, MIN_STAKE);
    assert_eq!(val.validate_vote(&v0, &reg, at), Ok(()));
    // Support identical across networks (admission-layer only).
    let mut r0 = StakeRegistry::new();
    let mut r7 = StakeRegistry::new();
    for (reg, net) in [(&mut r0, 0u64), (&mut r7, NET_A)] {
        for i in 0..4u64 {
            let w = wallet_n(460_000 + i);
            reg.apply_bond(w.address(), 1000, 0).expect("bond");
            reg.insert_vote(signed_vote_net(&w, AT, key_j(509), side_x(), net, 1000));
        }
    }
    let (t0, _) = r0.support_breakdown(key_j(509), &side_x(), AT, |_| false);
    let (t7, _) = r7.support_breakdown(key_j(509), &side_x(), AT, |_| false);
    assert_eq!((t0, t7), (4000, 4000));
    // Era routing untouched by network (predicate has no network input):
    // pre/post activation classify identically (rehearsal s01 pattern).
    assert!(!crate::transaction::Transaction::is_v6_active_at(
        crate::transaction::Transaction::V6_ACTIVATION_TS - 1
    ));
}

#[test]
fn v15_bond_unbond_cross_rejected() {
    let mut val = TransactionValidator::new();
    val.set_network_id(NET_A);
    let w = wallet_n(470_000);
    let at = 10u64;
    // Bond signed for B presented to A: rejected with WrongNetwork.
    let mut b = crate::transaction::Bond {
        format_version: crate::transaction::BOND_FORMAT_VERSION,
        network_id: NET_B,
        validator: w.address(),
        amount: MIN_STAKE,
        epoch: at,
        signature: [0u8; 64],
    };
    let sig = w.sign_transaction_hash(&b.signing_bytes()).expect("sign");
    b.signature = sig.to_bytes();
    let reg = StakeRegistry::new();
    let ledger = crate::ledger::Ledger::new();
    assert_eq!(
        val.validate_bond(&b, &ledger, &reg, at),
        Err(ValidationError::WrongNetwork { expected: NET_A, found: NET_B })
    );
    // Unbond likewise (grief-lock vector closed).
    let mut u = crate::transaction::Unbond {
        format_version: crate::transaction::BOND_FORMAT_VERSION,
        network_id: NET_B,
        validator: w.address(),
        epoch: at,
        signature: [0u8; 64],
    };
    let sig = w.sign_transaction_hash(&u.signing_bytes()).expect("sign");
    u.signature = sig.to_bytes();
    assert_eq!(
        val.validate_unbond(&u, &reg, at),
        Err(ValidationError::WrongNetwork { expected: NET_A, found: NET_B })
    );
}

#[test]
fn v17_bootstrap_hook_enforces_node_network() {
    // The production boot path passes the NODE's network (not the bundle's
    // claim): a coherent net-7 bundle is Accepted under 7 and refused under
    // 9 through verify_bootstrap_anchor (same function run_node calls).
    let (reg, bundle) = {
        let mut reg = StakeRegistry::new();
        let mut votes = Vec::new();
        for i in 0..4u64 {
            let w = wallet_n(490_000 + i);
            reg.apply_bond(w.address(), 1000, 0).expect("bond");
            let v = signed_vote_net(&w, AT, key_j(512), side_x(), NET_A, 1000);
            reg.insert_vote(v.clone());
            votes.push(v);
        }
        let set = reg.snapshot().validators;
        let anchor = build_anchor(AT, key_j(512), side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, NET_A);
        (reg, AnchorBundle { anchor, validator_set: set })
    };
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join(V6_ANCHOR_FILE),
        encode_anchor_bundle(&bundle).expect("encode"),
    )
    .expect("write");
    match verify_bootstrap_anchor(dir.path(), &reg, NET_A, |_, _| false) {
        Ok(BootstrapVerdict::Accepted { .. }) => {}
        other => panic!("hook(7) must accept, got {:?}", other),
    }
    assert!(verify_bootstrap_anchor(dir.path(), &reg, NET_B, |_, _| false).is_err());
}

#[test]
fn v16_timing_handshake_vote_anchor() {
    // Cost sanity: network checks are O(1) field compares + 8-byte copies;
    // verification stays signature-dominated (no new bottleneck).
    let t0 = std::time::Instant::now();
    let mut frame = vec![0u8; 77];
    frame[37..45].copy_from_slice(&NET_A.to_le_bytes());
    let dt_frame = t0.elapsed();
    let (_, _, w) = bonded_setup(NET_A);
    let v = signed_vote_net(&w, AT, key_j(510), side_x(), NET_A, MIN_STAKE);
    let t1 = std::time::Instant::now();
    assert!(v.verify_signature());
    let dt_sig = t1.elapsed();
    eprintln!("4V timing frame-build={:?} vote-verify={:?}", dt_frame, dt_sig);
    // Anchor bundle roundtrip determinism (multi-source comparison basis).
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(480_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote_net(&w, AT, key_j(511), side_x(), NET_A, 1000);
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    let set = reg.snapshot().validators;
    let a = build_anchor(AT, key_j(511), side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, NET_A);
    let e1 = encode_anchor_bundle(&AnchorBundle { anchor: a.clone(), validator_set: set.clone() }).expect("encode");
    let e2 = encode_anchor_bundle(&AnchorBundle { anchor: a, validator_set: set }).expect("encode");
    assert_eq!(e1, e2);
    assert_eq!(compare_anchor_bundles(&e1, &e2), BundleComparison::Equal);
    let back = parse_anchor_bundle(&e1).expect("parse");
    let id = anchor_id(&back.anchor);
    assert!(verify_anchor(&back.anchor, &back.validator_set, id, NET_A, |_, _| false).is_ok());
}
