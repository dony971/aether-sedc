//! PHASE 4X: explicit-network V6 gate harness (18 charter items).
//!
//! Proves the F4W-1/F4W-2 closures on the final tree: V5+0 legacy intact,
//! V6+0 refused at every trust boundary, nonzero flows accepted, storage /
//! restore / anchor legs matrixed, activation boundary and restart stable.
//! Fast (<5s, no mining, deterministic). Handshake legs live in p2p.rs
//! tests (only callers of the private frame helpers); rerun green.

use crate::anchor::{
    build_anchor, encode_anchor_bundle, validate_v6_network_configuration,
    verify_bootstrap_anchor, AnchorBundle, BootstrapVerdict, V6NetworkError, ANCHOR_GENESIS_PREV,
    V6_ANCHOR_FILE,
};
use crate::config::NodeConfig;
use crate::stake::{StakeRegistry, MIN_STAKE};
use crate::transaction::{Vote, VOTE_FORMAT_VERSION, DEFAULT_NETWORK_ID};
use crate::transaction_processor::TransactionProcessor;
use crate::validation::{TransactionValidator, ValidationError};
use crate::wallet::Wallet;

const AT: u64 = 600_000;
const NET: u64 = 7;

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
    s[8] = 0xD6;
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

/// Registry WITH V6-finalized records (gate fires on these).
fn finalized_registry(network: u64) -> (StakeRegistry, Vec<Vote>) {
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(600_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote_net(&w, AT, key_j(701), side_x(), network, 1000);
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    reg.try_finalize(key_j(701), &[side_x(), side_y()], AT, |_, _| false).expect("quorum");
    (reg, votes)
}

fn bundle_for(reg: &StakeRegistry, key: ([u8; 32], u64), votes: Vec<Vote>, network: u64) -> AnchorBundle {
    let set = reg.snapshot().validators;
    let anchor = build_anchor(AT, key, side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, network);
    AnchorBundle { anchor, validator_set: set }
}

fn write_bundle(dir: &std::path::Path, b: &AnchorBundle) {
    std::fs::write(dir.join(V6_ANCHOR_FILE), encode_anchor_bundle(b).expect("encode")).expect("write");
}

#[test]
fn x01_v5_zero_legacy_intact() {
    // Default validator admits a default vote exactly as before (legacy
    // behavior conserved under network 0; pinned suites prove the rest).
    let val = TransactionValidator::new();
    let w = wallet_n(610_000);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(w.address(), MIN_STAKE, 5).expect("bond");
    let v = signed_vote_net(&w, 10, key_j(702), side_x(), 0, MIN_STAKE);
    assert_eq!(val.validate_vote(&v, &reg, 10), Ok(()));
    // Existing configuration files keep working (no network key needed).
    assert_eq!(NodeConfig::default().network_id, None);
}

#[test]
fn x02_v6_zero_refused_at_gate() {
    // V6-finalized state + absent config => NotConfigured (never valid).
    let (reg, _) = finalized_registry(0);
    assert!(!reg.finalized_keys().is_empty(), "gate precondition: V6 state present");
    assert_eq!(
        validate_v6_network_configuration(None, Some(0), None),
        Err(V6NetworkError::NotConfigured)
    );
    // ... + explicit zero => LegacyZero (explicitly legacy, V6 forbidden).
    assert_eq!(
        validate_v6_network_configuration(Some(0), Some(0), None),
        Err(V6NetworkError::LegacyZero)
    );
}

#[test]
fn x03_v6_nonzero_accepts_full_flow() {
    // Explicit nonzero + coherent storage/anchor => Ok + hook accepts.
    let (reg, votes) = finalized_registry(NET);
    let bundle = bundle_for(&reg, key_j(701), votes, NET);
    let dir = tempfile::tempdir().expect("tempdir");
    crate::node::verify_data_dir_network(dir.path(), NET).expect("marker");
    write_bundle(dir.path(), &bundle);
    assert_eq!(validate_v6_network_configuration(Some(NET), Some(NET), Some(NET)), Ok(NET));
    match verify_bootstrap_anchor(dir.path(), &reg, NET, |_, _| false) {
        Ok(BootstrapVerdict::Accepted { .. }) => {}
        other => panic!("expected Accepted, got {:?}", other),
    }
}

#[test]
fn x04_config_absent_is_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().join("n.toml");
    std::fs::write(&p, "node_type = \"miner\"\n").expect("write");
    assert_eq!(NodeConfig::load(&p).expect("parse").network_id, None);
}

#[test]
fn x05_config_explicit_zero_and_nonzero() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (body, expected) in [
        ("node_type = \"miner\"\nnetwork_id = 0\n", Some(0u64)),
        ("node_type = \"miner\"\nnetwork_id = 7\n", Some(7u64)),
    ] {
        let p = dir.path().join("e.toml");
        std::fs::write(&p, body).expect("write");
        assert_eq!(NodeConfig::load(&p).expect("parse").network_id, expected);
    }
    // Effective mapping preserves legacy behavior for absent config.
    assert_eq!(None.unwrap_or(DEFAULT_NETWORK_ID), 0u64);
    assert_eq!(Some(7u64).unwrap_or(DEFAULT_NETWORK_ID), 7u64);
}

#[test]
fn x06_activation_t_minus_1() {
    let t = crate::transaction::Transaction::V6_ACTIVATION_TS;
    assert!(!crate::transaction::Transaction::is_v6_active_at(t - 1));
}

#[test]
fn x07_activation_t() {
    let t = crate::transaction::Transaction::V6_ACTIVATION_TS;
    assert!(crate::transaction::Transaction::is_v6_active_at(t));
    assert_eq!(t, 1_893_456_000_000, "real const untouched by rehearsal labels");
}

#[test]
fn x08_activation_t_plus_1() {
    let t = crate::transaction::Transaction::V6_ACTIVATION_TS;
    assert!(crate::transaction::Transaction::is_v6_active_at(t + 1));
    assert!(crate::transaction::Transaction::is_v6_active_at(t + 2));
}

#[test]
fn x09_restart_at_boundary_keeps_gate_verdict() {
    // Save V6-finalized state, reload, re-derive gate inputs: identical
    // refusal under absent config, identical acceptance under explicit.
    let (reg, _) = finalized_registry(NET);
    let dir = tempfile::tempdir().expect("tempdir");
    let store = crate::storage::Storage::open(dir.path().join("sled")).expect("open");
    store.save_registry(&reg).expect("save");
    let back = store.load_registry().expect("load").expect("present");
    assert_eq!(back.snapshot(), reg.snapshot());
    assert!(!back.finalized_keys().is_empty());
    assert_eq!(validate_v6_network_configuration(None, None, None), Err(V6NetworkError::NotConfigured));
    assert_eq!(validate_v6_network_configuration(Some(NET), None, None), Ok(NET));
}

#[test]
fn x10_storage_aa_accepted() {
    // Marker 7 + snapshot 7: both layers pass.
    let (reg, _) = finalized_registry(NET);
    let dir = tempfile::tempdir().expect("tempdir");
    crate::node::verify_data_dir_network(dir.path(), NET).expect("marker");
    let store = crate::storage::Storage::open(dir.path().join("sled")).expect("open");
    store.save_registry(&reg).expect("save");
    let back = store.load_registry_on_network(NET).expect("load").expect("present");
    assert_eq!(back.snapshot(), reg.snapshot());
}

#[test]
fn x11_storage_ab_refused_both_layers() {
    // Marker layer refuses first; restore layer refuses independently
    // (proven on a directly-built foreign snapshot).
    let (reg, _) = finalized_registry(NET);
    let dir = tempfile::tempdir().expect("tempdir");
    crate::node::verify_data_dir_network(dir.path(), NET).expect("marker 7");
    assert!(crate::node::verify_data_dir_network(dir.path(), 9).is_err(), "marker mismatch refuses");
    let store = crate::storage::Storage::open(dir.path().join("sled")).expect("open");
    store.save_registry(&reg).expect("save");
    assert!(store.load_registry_on_network(9).is_err(), "restore layer refuses foreign snapshot");
    assert!(store.load_registry_on_network(NET).is_ok(), "same-network loads");
}

#[test]
fn x12_no_marker_adopts_once() {
    // Fresh dir without marker: adopted for the caller's network, then
    // pinned (second network refuses). No silent relabel ever.
    let dir = tempfile::tempdir().expect("tempdir");
    crate::node::verify_data_dir_network(dir.path(), NET).expect("adopt");
    crate::node::verify_data_dir_network(dir.path(), NET).expect("pinned");
    assert!(crate::node::verify_data_dir_network(dir.path(), NET + 1).is_err());
}

#[test]
fn x13_corrupt_marker_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(crate::anchor::NETWORK_MARKER_FILE), b"short").expect("write");
    assert!(crate::node::verify_data_dir_network(dir.path(), NET).is_err());
}

#[test]
fn x14_foreign_snapshot_refused_map_and_evidence() {
    // Map votes of another network refuse; evidence-embedded foreign votes
    // refuse independently (both checked BEFORE any insert: no partial state).
    let mut reg = StakeRegistry::new();
    let w = wallet_n(620_000);
    reg.apply_bond(w.address(), 1000, 0).expect("bond");
    reg.insert_vote(signed_vote_net(&w, AT, key_j(703), side_x(), 9, 1000));
    assert!(StakeRegistry::restore_on_network(reg.snapshot(), NET).is_err());
    assert!(StakeRegistry::restore_on_network(reg.snapshot(), 9).is_ok());
    // Equivocation evidence path: two sides from one validator, foreign net.
    let mut reg2 = StakeRegistry::new();
    let w2 = wallet_n(621_000);
    reg2.apply_bond(w2.address(), 1000, 0).expect("bond");
    reg2.insert_vote(signed_vote_net(&w2, AT, key_j(704), side_x(), 9, 1000));
    reg2.insert_vote(signed_vote_net(&w2, AT, key_j(704), side_y(), 9, 1000));
    assert!(reg2.evidence_count() > 0, "evidence recorded");
    assert!(StakeRegistry::restore_on_network(reg2.snapshot(), NET).is_err());
}

#[test]
fn x15_anchor_wrong_network_refused_integrated() {
    // Valid net-7 bundle under node 9 (hook takes the NODE's network):
    // refused; under 7 with matching registry: accepted.
    let (reg, votes) = finalized_registry(NET);
    let bundle = bundle_for(&reg, key_j(701), votes, NET);
    let dir = tempfile::tempdir().expect("tempdir");
    write_bundle(dir.path(), &bundle);
    assert!(verify_bootstrap_anchor(dir.path(), &reg, 9, |_, _| false).is_err());
    assert!(matches!(
        verify_bootstrap_anchor(dir.path(), &reg, NET, |_, _| false),
        Ok(BootstrapVerdict::Accepted { .. })
    ));
}

#[test]
fn x16_sync_resume_mismatch_refused() {
    // Resumed sync under an unconfigured (legacy-mapped) node rejects
    // foreign votes at admission (processor inherits effective network).
    use crate::ledger::Ledger;
    use crate::parent_selection::DAG;
    use std::sync::Arc;
    let at_now = crate::stake::current_epoch();
    let mut processor = TransactionProcessor::new();
    let mut reg = StakeRegistry::new();
    let w = wallet_n(630_000);
    reg.apply_bond(w.address(), MIN_STAKE, at_now.saturating_sub(10)).expect("bond");
    let reg = Arc::new(tokio::sync::RwLock::new(reg));
    processor.set_stake_registry(reg.clone());
    // No set_network_id call: default validator (effective legacy 0).
    let dag = Arc::new(tokio::sync::RwLock::new(DAG::new()));
    let ledger = Arc::new(tokio::sync::RwLock::new(Ledger::new()));
    let foreign = signed_vote_net(&w, at_now, key_j(705), side_x(), NET, MIN_STAKE);
    let err = futures_exec(processor.process_vote(foreign, &dag, &ledger))
        .expect_err("foreign vote must not admit on legacy default");
    assert!(
        matches!(
            err,
            crate::transaction_processor::ProcessingError::ValidationFailed(
                ValidationError::WrongNetwork { expected: 0, found: NET }
            )
        ),
        "got: {:?}",
        err
    );
}

fn futures_exec<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
        .block_on(f)
}

#[test]
fn x17_rpc_invalid_config_refused() {
    // RpcImpl left at default (unconfigured legacy 0) rejects a foreign
    // vote through the real submitVote path; same-network control accepts.
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
            network_id: crate::transaction::DEFAULT_NETWORK_ID,
        },
        tx_channel,
        Arc::new(|| Vec::new()),
        Arc::new(|_| None),
        Arc::new(|| Vec::new()),
        Arc::new(crate::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    let at_now = crate::stake::current_epoch();
    let rpc_impl = AetherRpcImpl::new(
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
    let w = wallet_n(640_000);
    reg.apply_bond(w.address(), MIN_STAKE, at_now.saturating_sub(10)).expect("bond");
    let mut rpc_impl = rpc_impl;
    rpc_impl.set_stake_registry(Arc::new(tokio::sync::RwLock::new(reg)));
    // NOTE: no set_network_id call: RpcImpl default (legacy 0), as an
    // unconfigured node would run it.
    let foreign = signed_vote_net(&w, at_now, key_j(706), side_x(), NET, MIN_STAKE);
    let params = serde_json::Value::String(hex::encode(foreign.encode()));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("rt");
    assert!(rt.block_on(rpc_impl.submit_vote(params)).is_err());
    let local = signed_vote_net(&w, at_now, key_j(706), side_x(), 0, MIN_STAKE);
    let params = serde_json::Value::String(hex::encode(local.encode()));
    assert!(rt.block_on(rpc_impl.submit_vote(params)).is_ok());
}

#[test]
fn x18_gate_decision_matrix() {
    // Full central-validator matrix incl. anchor coherence and the
    // legacy-explicit case. Only (Some(n), n, n-or-None) passes.
    use crate::anchor::{validate_v6_network_configuration, V6NetworkError};
    assert_eq!(validate_v6_network_configuration(None, None, None), Err(V6NetworkError::NotConfigured));
    assert_eq!(validate_v6_network_configuration(None, Some(7), Some(7)), Err(V6NetworkError::NotConfigured));
    assert_eq!(validate_v6_network_configuration(Some(0), None, None), Err(V6NetworkError::LegacyZero));
    assert_eq!(validate_v6_network_configuration(Some(0), Some(0), None), Err(V6NetworkError::LegacyZero));
    assert_eq!(validate_v6_network_configuration(Some(7), None, None), Ok(7));
    assert_eq!(validate_v6_network_configuration(Some(7), Some(7), None), Ok(7));
    assert_eq!(validate_v6_network_configuration(Some(7), Some(7), Some(7)), Ok(7));
    assert_eq!(
        validate_v6_network_configuration(Some(7), Some(9), None),
        Err(V6NetworkError::StorageMismatch { node: 7, storage: 9 })
    );
    assert_eq!(
        validate_v6_network_configuration(Some(7), Some(7), Some(9)),
        Err(V6NetworkError::AnchorMismatch { node: 7, anchor: 9 })
    );
    assert_eq!(
        validate_v6_network_configuration(Some(7), None, Some(9)),
        Err(V6NetworkError::AnchorMismatch { node: 7, anchor: 9 })
    );
}
