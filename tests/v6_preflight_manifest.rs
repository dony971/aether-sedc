//! PHASE 4Z: preflight fixture matrix (20 cases, black-box via binary).
//!
//! Deterministic, explicitly fictitious values (network 7/9, test keys,
//! temp git repos). No fixture here is, or may become, a governance
//! manifest. The binary under test never writes: fixture 17 asserts input
//! files are byte-identical after a PASS run.

use aether_unified::anchor::{build_anchor, AnchorBundle, ANCHOR_GENESIS_PREV};
use aether_unified::stake::StakeRegistry;
use aether_unified::transaction::{Vote, VOTE_FORMAT_VERSION};
use aether_unified::wallet::Wallet;
use std::path::PathBuf;

const AT: u64 = 600_000;
const NET: u64 = 7;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn signed_vote(w: &Wallet, epoch: u64, key: ([u8; 32], u64), side: [u8; 32]) -> Vote {
    let mut v = Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: NET,
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
    s[8] = 0xD8;
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

struct Ctx {
    dir: tempfile::TempDir,
    repo: PathBuf,
    commit: String,
    artifact: String,
    artifact_sha: String,
    anchor_json: serde_json::Value,
    set_json: serde_json::Value,
}

/// Temp git repo with one committed artifact + coherent V6 fixture data.
/// All values explicitly fictitious (documented in every manifest).
fn setup() -> Ctx {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).expect("mkdir");
    let git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .expect("git binary required for preflight fixtures");
        assert!(out.status.success(), "git {:?} failed", args);
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "fixture"]);
    std::fs::write(repo.join("artifact.bin"), b"v6-testnet-artifact-bytes").expect("write");
    git(&["add", "."]);
    git(&["commit", "-qm", "fixture release commit"]);
    let commit = git(&["rev-parse", "HEAD"]);
    let artifact = "artifact.bin".to_string();
    let bytes = std::fs::read(repo.join(&artifact)).expect("read");
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&bytes);
    let artifact_sha = hex::encode(hasher.finalize());
    // Coherent anchor: 4 bonded validators, unanimous X, network 7.
    let mut reg = StakeRegistry::new();
    let mut votes = Vec::new();
    for i in 0..4u64 {
        let w = wallet_n(800_000 + i);
        reg.apply_bond(w.address(), 1000, 0).expect("bond");
        let v = signed_vote(&w, AT, key_j(901), side_x());
        reg.insert_vote(v.clone());
        votes.push(v);
    }
    let set = reg.snapshot().validators;
    let anchor = build_anchor(
        AT, key_j(901), side_x(), vec![side_x(), side_y()], votes, &set, ANCHOR_GENESIS_PREV, NET,
    );
    let bundle = AnchorBundle { anchor, validator_set: set };
    let bundle_bytes = aether_unified::anchor::encode_anchor_bundle(&bundle).expect("encode");
    let anchor_json: serde_json::Value = serde_json::from_slice(&bundle_bytes).expect("bundle json");
    let set_json = serde_json::to_value(&bundle.validator_set).expect("set json");
    Ctx { dir, repo, commit, artifact, artifact_sha, anchor_json, set_json }
}

fn manifest_text(ctx: &Ctx, patch: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut m = serde_json::json!({
        "format": 1,
        "activation_ts": 1900000000000u64,
        "network_id": NET,
        "release_version": "v9.9.9-v6testnet0",
        "release_commit": ctx.commit,
        "validator_set": ctx.set_json,
        "stake": { "claimed_eligible_total": 4000u64 },
        "anchor": ctx.anchor_json,
        "artifacts": [{ "path": ctx.artifact, "sha256": ctx.artifact_sha }],
    });
    patch(&mut m);
    serde_json::to_string(&m).expect("manifest json")
}

fn run_tool(ctx: &Ctx, manifest: &str) -> (i32, String) {
    let path = ctx.dir.path().join("manifest.json");
    std::fs::write(&path, manifest).expect("write manifest");
    let bin = env!("CARGO_BIN_EXE_v6_preflight");
    let out = std::process::Command::new(bin)
        .arg("--manifest")
        .arg(&path)
        .arg("--repo")
        .arg(&ctx.repo)
        .output()
        .expect("run preflight binary");
    let code = out.status.code().unwrap_or(99);
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (code, text)
}

fn valid_manifest(ctx: &Ctx) -> String {
    manifest_text(ctx, |_| {})
}

#[test]
fn f01_empty_manifest() {
    let ctx = setup();
    let (code, out) = run_tool(&ctx, "");
    assert_eq!(code, 2, "empty manifest is unusable");
    assert!(out.contains("E_INPUT"), "out: {}", out);
}

#[test]
fn f02_missing_anchor_field() {
    let ctx = setup();
    let mut m: serde_json::Value = serde_json::from_str(&valid_manifest(&ctx)).expect("parse");
    m.as_object_mut().unwrap().remove("anchor");
    let (code, out) = run_tool(&ctx, &serde_json::to_string(&m).expect("json"));
    assert_eq!(code, 2, "missing input is unusable, not a soft fail");
    assert!(out.contains("E_INPUT"), "out: {}", out);
}

#[test]
fn f03_network_id_absent() {
    let ctx = setup();
    let mut m: serde_json::Value = serde_json::from_str(&valid_manifest(&ctx)).expect("parse");
    m.as_object_mut().unwrap().remove("network_id");
    let (code, out) = run_tool(&ctx, &serde_json::to_string(&m).expect("json"));
    assert_eq!(code, 2);
    assert!(out.contains("E_INPUT"), "out: {}", out);
}

#[test]
fn f04_network_zero_rejected_as_governance() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m.as_object_mut().unwrap()["network_id"] = serde_json::json!(0u64);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_NETWORK_ZERO"), "out: {}", out);
    assert!(!out.contains("GOVERNANCE_READY: YES"), "zero must never govern");
}

#[test]
fn f05_explicit_nonzero_network_accepted_as_value() {
    // The value class is accepted (no E_NETWORK_ZERO); full PASS is asserted
    // separately by f17. Here only the network gate must be silent.
    let ctx = setup();
    let (code, out) = run_tool(&ctx, &valid_manifest(&ctx));
    assert!(!out.contains("E_NETWORK_ZERO"), "explicit nonzero must pass the network gate. out: {}", out);
    let _ = code;
}

#[test]
fn f06_activation_ts_absent() {
    let ctx = setup();
    let mut m: serde_json::Value = serde_json::from_str(&valid_manifest(&ctx)).expect("parse");
    m.as_object_mut().unwrap().remove("activation_ts");
    let (code, out) = run_tool(&ctx, &serde_json::to_string(&m).expect("json"));
    assert_eq!(code, 2);
    assert!(out.contains("E_INPUT"), "out: {}", out);
}

#[test]
fn f07_nonexistent_commit() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m.as_object_mut().unwrap()["release_commit"] = serde_json::json!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_COMMIT_MISSING"), "out: {}", out);
}

#[test]
fn f08_bad_artifact_checksum() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m["artifacts"][0]["sha256"] = serde_json::json!("00".repeat(32));
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_ARTIFACT_CHECKSUM"), "out: {}", out);
}

#[test]
fn f09_duplicate_validator_address() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        let arr = m["validator_set"].as_array().unwrap().clone();
        let mut v = arr.clone();
        v.push(arr[0].clone());
        m.as_object_mut().unwrap()["validator_set"] = serde_json::Value::Array(v);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_SET_DUPLICATE"), "out: {}", out);
}

#[test]
fn f10_incoherent_claimed_total() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m["stake"]["claimed_eligible_total"] = serde_json::json!(3999u64);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_STAKE_MISMATCH"), "out: {}", out);
}

#[test]
fn f11_tampered_set_root() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m["anchor"]["set_root"] = serde_json::json!("ff".repeat(32));
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_SET_ROOT"), "out: {}", out);
}

#[test]
fn f12_tampered_denominator() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m["anchor"]["claimed_total"] = serde_json::json!(1u64);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_ANCHOR_VERIFY") || out.contains("E_STAKE_MISMATCH"), "out: {}", out);
}

#[test]
fn f13_empty_votes_anchor() {
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m["anchor"]["votes"] = serde_json::json!([]);
        m["anchor"]["supporting"] = serde_json::json!([]);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_ANCHOR_VERIFY"), "out: {}", out);
}

#[test]
fn f14_corrupted_vote_signature() {
    // Flip one signature byte inside the anchor's first vote encoding.
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        let enc = m["anchor"]["votes"][0].as_str().unwrap().to_string();
        let mut raw = hex::decode(&enc).expect("hex");
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        m["anchor"]["votes"][0] = serde_json::json!(hex::encode(&raw));
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_ANCHOR"), "out: {}", out);
}

#[test]
fn f15_other_network_anchor() {
    // Bundle built for network 9 presented under manifest network 7.
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        // Rebuild votes for network 9 by re-signing is complex here; the
        // tool-level mismatch (bundle network vs manifest network) already
        // fails deterministically before signature checks.
        m["anchor"]["network_id"] = serde_json::json!(9u64);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_NETWORK_MISMATCH"), "out: {}", out);
}

#[test]
fn f16_votes_outside_window() {
    // Anchor epoch far above the votes' epochs: window rejects.
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m["anchor"]["epoch"] = serde_json::json!(AT + 1000);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_ANCHOR_VERIFY"), "out: {}", out);
}

#[test]
fn f17_coherent_manifest_passes_and_changes_nothing() {
    let ctx = setup();
    let before: Vec<(PathBuf, Vec<u8>)> = walk(&ctx.dir);
    let (code, out) = run_tool(&ctx, &valid_manifest(&ctx));
    assert_eq!(code, 0, "coherent manifest must PASS. out: {}", out);
    for line in [
        "A INPUTS_COMPLETE",
        "B CRYPTOGRAPHIC_CHECKS: PASS",
        "C CONFIGURATION_COHERENCE: PASS",
        "D RELEASE_ARTIFACT_CHECKS: PASS",
        "E GOVERNANCE_READY: YES",
        "G OPERATIONAL_READY: NO",
        "SCOPE:",
    ] {
        assert!(out.contains(line), "missing verdict line {:?}. out: {}", line, out);
    }
    // Dry-run safety: every file under the temp dir byte-identical after.
    for (path, _) in walk(&ctx.dir) {
        if path.file_name().map(|n| n == "manifest.json").unwrap_or(false) {
            continue;
        }
        let now = std::fs::read(&path).expect("reread");
        let old = before.iter().find(|(p, _)| p == &path).expect("tracked");
        assert_eq!(now, old.1, "tool modified {:?}", path);
    }
}

fn walk(dir: &tempfile::TempDir) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.path().to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d).expect("readdir");
        for e in entries {
            let e = e.expect("entry");
            let p = e.path();
            if p.is_dir() {
                // Skip .git internals (lock churn); track the rest.
                if p.file_name().map(|n| n == ".git").unwrap_or(false) {
                    continue;
                }
                stack.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).expect("read")));
            }
        }
    }
    out
}

#[test]
fn f18_truncated_input_file() {
    let ctx = setup();
    let mut text = valid_manifest(&ctx);
    text.truncate(text.len() / 2);
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 2);
    assert!(out.contains("E_INPUT"), "out: {}", out);
}

#[test]
fn f19_duplicate_key_and_ambiguous_type() {
    let ctx = setup();
    // Duplicate top-level key: strict rejection (serde_json is last-wins).
    let mut text = valid_manifest(&ctx);
    text.pop();
    text.push_str(",\"network_id\":7}");
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 2);
    assert!(out.contains("E_INPUT_DUPLICATE"), "out: {}", out);
    // Ambiguous type: network as string instead of u64.
    let text2 = manifest_text(&ctx, |m| {
        m.as_object_mut().unwrap()["network_id"] = serde_json::json!("7");
    });
    let (code2, out2) = run_tool(&ctx, &text2);
    assert_eq!(code2, 2);
    assert!(out2.contains("E_INPUT_FORMAT"), "out: {}", out2);
}

#[test]
fn f20_default_as_decision_rejected() {
    // network 0 with everything else valid: exit 1 repairs nothing, and
    // the output never claims governance readiness.
    let ctx = setup();
    let text = manifest_text(&ctx, |m| {
        m.as_object_mut().unwrap()["network_id"] = serde_json::json!(0u64);
    });
    let (code, out) = run_tool(&ctx, &text);
    assert_eq!(code, 1);
    assert!(out.contains("E_NETWORK_ZERO"), "out: {}", out);
    assert!(!out.contains("GOVERNANCE_READY: YES"), "zero must never govern. out: {}", out);
}

#[test]
fn f99_no_activate_subcommand() {
    // The tool exposes no mutating subcommand: unknown verbs fail closed.
    let ctx = setup();
    let bin = env!("CARGO_BIN_EXE_v6_preflight");
    for verb in ["activate", "deploy", "publish", "start-network"] {
        let out = std::process::Command::new(bin)
            .arg(verb)
            .output()
            .expect("run");
        assert!(!out.status.success(), "{} must not exist", verb);
    }
    let _ = ctx;
}
