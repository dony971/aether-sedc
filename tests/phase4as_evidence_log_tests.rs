//! PHASE 4AS: evidence-log tests (F4AN-3, 20 items).
//!
//! Deterministic, isolated, offline. All trees under `tempfile::TempDir`;
//! no repo file outside temp dirs is modified. Binary legs use a minimal
//! UNUSABLE manifest (empty file, exit 2) so no governance fixture can be
//! mistaken for a real release. Anything untestable here records NOT_RUN
//! with the exact limit instead of an invented result.

use aether_unified::evidence_log::{
    build_log, pending_retention, validate_log, write_log_file, CheckRecord, CheckStatus,
    EvidenceInput, OpStatus, CHECKLIST_VERSION, OPERATIONAL_STATUSES, REGISTRY, SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};

fn pass_check(id: &'static str) -> CheckRecord {
    CheckRecord {
        id,
        status: CheckStatus::Pass,
        reason: None,
        code: "EVALUATED".to_string(),
        detail: "ok".to_string(),
        evidence_ref: "test".to_string(),
    }
}

fn unverified_status(name: &'static str) -> OpStatus {
    OpStatus {
        name,
        verified: false,
        proof_ref: "none".to_string(),
        method: "none (not observable offline)".to_string(),
        explanation: "test: no proof mechanism".to_string(),
    }
}

fn full_input() -> EvidenceInput {
    EvidenceInput {
        run_id: "run-4as-test".to_string(),
        package_id: "pkg:9.9.9:t0".to_string(),
        manifest_digest: Some("m".repeat(64)),
        inventory_digest: Some("i".repeat(64)),
        binary_name: "v6_preflight".to_string(),
        binary_version: "test".to_string(),
        binary_sha256: "b".repeat(64),
        operator_id: None,
        ci_reference: None,
        started_unix_secs: 1_791_849_600,
        finished_unix_secs: 1_791_849_605,
        checks: REGISTRY.iter().map(|id| pass_check(id)).collect(),
        statuses: OPERATIONAL_STATUSES.iter().map(|n| unverified_status(n)).collect(),
        retention: pending_retention("out.jsonl"),
        evaluated: true,
        preflight_valid: true,
        governance_note: "V6 activation NOT authorized by this log".to_string(),
    }
}

// 1. Deterministic JSONL serialization.
#[test]
fn s01_deterministic_serialization() {
    let a = build_log(&full_input()).expect("build");
    let b = build_log(&full_input()).expect("build");
    assert_eq!(a, b, "same input must serialize identically");
    assert!(a.is_ascii());
    assert!(!a.contains('\r'));
    assert!(a.ends_with('\n'));
}

// 2. Header creation + validation (explicit tokens, no invented values).
#[test]
fn s02_header_tokens_and_no_secrets() {
    let t = build_log(&full_input()).expect("build");
    let first: serde_json::Value = serde_json::from_str(t.lines().next().unwrap()).expect("json");
    let body = &first["body"];
    assert_eq!(body["operator_identity"], "NOT_PROVIDED");
    assert_eq!(body["ci_reference"], "NOT_PROVIDED");
    assert_eq!(body["schema_version"], SCHEMA_VERSION);
    assert_eq!(body["checklist_version"], CHECKLIST_VERSION);
    assert!(body["started_at"].as_str().unwrap().ends_with('Z'));
    let flat = serde_json::to_string(body).unwrap().to_lowercase();
    for secret_word in ["private_key", "secret", "password", "token", "env"] {
        assert!(!flat.contains(secret_word), "no secret-like field: {}", secret_word);
    }
    validate_log(&t).expect("valid");
}

// 3. Complete registry (1 header + 6 checks + 5 statuses + retention + decision).
#[test]
fn s03_complete_registry_and_sequence() {
    let t = build_log(&full_input()).expect("build");
    let s = validate_log(&t).expect("valid");
    assert_eq!(s.lines, 14);
    assert_eq!(s.checks_pass, 6);
    let seqs: Vec<u64> = t
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (1..=14).collect::<Vec<u64>>());
}

// 4. Missing check detected.
#[test]
fn s04_missing_check_detected() {
    let t = build_log(&full_input()).expect("build");
    let mut lines: Vec<&str> = t.lines().collect();
    lines.remove(3); // drop a check event
    let broken = lines.join("\n") + "\n";
    let errs = validate_log(&broken).expect_err("must be incomplete");
    assert!(errs.iter().any(|e| e.contains("registry") || e.contains("1..M") || e.contains("prev-link")),
        "unexpected errors: {:?}", errs);
}

// 5. Duplicate detected.
#[test]
fn s05_duplicate_detected() {
    let t = build_log(&full_input()).expect("build");
    let mut lines: Vec<String> = t.lines().map(|s| s.to_string()).collect();
    lines.insert(4, lines[3].clone()); // duplicate a check line (seq reused)
    let broken = lines.join("\n") + "\n";
    let errs = validate_log(&broken).expect_err("must fail");
    assert!(errs.iter().any(|e| e.contains("1..M") || e.contains("prev-link") || e.contains("registry")),
        "unexpected errors: {:?}", errs);
}

// 6. Sequence gap detected.
#[test]
fn s06_sequence_gap_detected() {
    let t = build_log(&full_input()).expect("build");
    let mut lines: Vec<String> = t.lines().map(|s| s.to_string()).collect();
    lines.remove(8); // drop a status event -> gap + set mismatch
    let broken = lines.join("\n") + "\n";
    let errs = validate_log(&broken).expect_err("must fail");
    assert!(errs.iter().any(|e| e.contains("1..M") || e.contains("status set") || e.contains("prev-link")),
        "unexpected errors: {:?}", errs);
}

// 7. NOT_RUN without reason refused at build time.
#[test]
fn s07_not_run_without_reason_refused() {
    let mut i = full_input();
    let pos = i.checks.iter().position(|c| c.id == "INVENTORY_EXHAUSTIVENESS").unwrap();
    i.checks[pos].status = CheckStatus::NotRun;
    i.checks[pos].reason = None;
    assert!(build_log(&i).is_err(), "builder must refuse reason-less NOT_RUN");
    i.checks[pos].reason = Some("inventory opt-in not requested (--inventory-root absent)".to_string());
    let t = build_log(&i).expect("build with reason");
    validate_log(&t).expect("valid");
}

// 8. Event modification detected (hash mismatch).
#[test]
fn s08_modification_detected() {
    let t = build_log(&full_input()).expect("build");
    let mut lines: Vec<String> = t.lines().map(|s| s.to_string()).collect();
    let mut v: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
    v["body"]["detail"] = serde_json::Value::String("tampered".to_string());
    lines[2] = serde_json::to_string(&v).unwrap();
    let broken = lines.join("\n") + "\n";
    let errs = validate_log(&broken).expect_err("must fail");
    assert!(errs.iter().any(|e| e.contains("hash mismatch")), "unexpected errors: {:?}", errs);
}

// 9. Deletion/reorder detected (prev-link break).
#[test]
fn s09_deletion_reorder_detected() {
    let t = build_log(&full_input()).expect("build");
    let mut lines: Vec<String> = t.lines().map(|s| s.to_string()).collect();
    lines.swap(2, 3); // reorder two check events
    let broken = lines.join("\n") + "\n";
    let errs = validate_log(&broken).expect_err("must fail");
    assert!(errs.iter().any(|e| e.contains("prev-link") || e.contains("registry") || e.contains("1..M")),
        "unexpected errors: {:?}", errs);
}

// 10. Honest chain validates.
#[test]
fn s10_chain_validates() {
    let t = build_log(&full_input()).expect("build");
    let s = validate_log(&t).expect("honest log must validate");
    assert!(s.log_complete);
    assert_eq!(s.decision, "INCOMPLETE"); // operational statuses unverified
}

// 11. Overwrite of an existing log refused.
#[test]
fn s11_overwrite_refused() {
    let d = tempfile::tempdir().expect("tempdir");
    let p = d.path().join("ev.jsonl");
    let t = build_log(&full_input()).expect("build");
    write_log_file(&p, &t).expect("first write");
    let err = write_log_file(&p, &t).expect_err("overwrite must be refused");
    assert!(err.contains("overwrite"), "explicit refusal: {}", err);
    assert_eq!(std::fs::read_to_string(&p).unwrap(), t, "original bytes intact");
}

// 12. Inaccessible destination fails cleanly.
#[test]
fn s12_inaccessible_destination_clean_error() {
    let d = tempfile::tempdir().expect("tempdir");
    let p = d.path().join("no-such-dir").join("ev.jsonl");
    let t = build_log(&full_input()).expect("build");
    let err = write_log_file(&p, &t).expect_err("must fail");
    assert!(err.contains("write failed"), "clean error, no panic: {}", err);
}

// 13. Retention unverified without external proof.
#[test]
fn s13_retention_pending_without_external_proof() {
    let t = build_log(&full_input()).expect("build");
    let lines: Vec<serde_json::Value> =
        t.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let ret = lines.iter().find(|v| v["type"] == "retention").expect("retention event");
    assert_eq!(ret["body"]["external_copy"], "PENDING");
    assert_eq!(ret["body"]["external_digest"], "NOT_VERIFIED");
    let op = lines.iter().find(|v| v["type"] == "status" && v["body"]["name"] == "OPERATOR_EVIDENCE_RETAINED").unwrap();
    assert_eq!(op["body"]["value"], "UNVERIFIED");
}

// 14. No false PASS in the five operational statuses.
#[test]
fn s14_no_false_pass_in_statuses() {
    // Even with every check PASS, the three unobservable statuses stay
    // UNVERIFIED and the decision is INCOMPLETE, never GO.
    let t = build_log(&full_input()).expect("build");
    let s = validate_log(&t).expect("valid");
    assert_ne!(s.decision, "GO");
    let lines: Vec<serde_json::Value> =
        t.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    for name in ["CONCURRENT_WRITES_PREVENTED", "POST_VALIDATION_MUTATION_PROHIBITED", "OPERATOR_EVIDENCE_RETAINED"] {
        let st = lines.iter().find(|v| v["body"].get("name").map(|n| n == name).unwrap_or(false)).unwrap();
        assert_eq!(st["body"]["value"], "UNVERIFIED", "{}", name);
        assert!(!st["body"]["explanation"].as_str().unwrap().is_empty(), "{}", name);
    }
}

// 15. Decision coherence (NO_GO on failure, INCOMPLETE on gaps, GO guarded).
#[test]
fn s15_decision_coherence() {
    // Failed preflight -> NO_GO.
    let mut i = full_input();
    i.preflight_valid = false;
    i.checks[0].status = CheckStatus::Fail;
    i.checks[0].code = "E_INPUT_FORMAT".to_string();
    let t = build_log(&i).expect("build");
    assert_eq!(validate_log(&t).expect("valid").decision, "NO_GO");
    // Valid preflight + NOT_RUN inventory -> INCOMPLETE.
    let mut j = full_input();
    let pos = j.checks.iter().position(|c| c.id == "INVENTORY_EXHAUSTIVENESS").unwrap();
    j.checks[pos].status = CheckStatus::NotRun;
    j.checks[pos].reason = Some("inventory opt-in not requested".to_string());
    let t2 = build_log(&j).expect("build");
    assert_eq!(validate_log(&t2).expect("valid").decision, "INCOMPLETE");
}

fn run_bin(dir: &tempfile::TempDir, extra: &[&str]) -> (i32, String, PathBuf) {
    run_bin_cwd(dir, extra, None)
}

fn run_bin_cwd(
    dir: &tempfile::TempDir,
    extra: &[&str],
    cwd: Option<&Path>,
) -> (i32, String, PathBuf) {
    let m = dir.path().join("manifest.json");
    if !m.exists() {
        std::fs::write(&m, b"").expect("write empty manifest (unusable by design)");
    }
    let bin = env!("CARGO_BIN_EXE_v6_preflight");
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--manifest").arg(&m).arg("--repo").arg(dir.path());
    for a in extra {
        cmd.arg(a);
    }
    if let Some(wd) = cwd {
        cmd.current_dir(wd);
    }
    let out = cmd.output().expect("run binary");
    let code = out.status.code().unwrap_or(99);
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (code, text, m)
}

/// Schema-valid manifest whose anchor bundle is unparsable: inputs parse,
/// evaluation aborts at E_ANCHOR_FORMAT before any artifact check, with one
/// artifact DECLARED but unchecked (4AT F1 abort path, no crypto needed).
fn anchor_failing_manifest(dir: &tempfile::TempDir) -> PathBuf {
    let m = dir.path().join("manifest.json");
    let text = serde_json::json!({
        "format": 1,
        "activation_ts": 1900000000000u64,
        "network_id": 7u64,
        "release_version": "v9.9.9-4au-probe",
        "release_commit": "ab".repeat(20),
        "validator_set": [],
        "stake": { "claimed_eligible_total": 0u64 },
        "anchor": {},
        "artifacts": [{ "path": "a.bin", "sha256": "00".repeat(32) }],
    });
    std::fs::write(&m, serde_json::to_string(&text).unwrap()).unwrap();
    m
}

// 16. Default behavior preserved (no flag -> no log, same failures).
#[test]
fn s16_default_behavior_preserved() {
    let d = tempfile::tempdir().expect("tempdir");
    let (code, out, _) = run_bin(&d, &[]);
    assert_eq!(code, 2, "unusable manifest keeps exit 2");
    assert!(out.contains("A INPUTS_COMPLETE: NOT_EVALUATED"), "verdicts kept:\n{}", out);
    assert!(!out.contains("evidence log:"), "no evidence note without flag");
    assert!(std::fs::read_dir(d.path()).unwrap().count() <= 2, "no extra file created");
}

// 17. Verdicts and exit codes preserved when logging is enabled.
#[test]
fn s17_verdicts_and_exit_codes_preserved() {
    let d = tempfile::tempdir().expect("tempdir");
    let dest = d.path().join("other").join("ev.jsonl");
    let dest_s = dest.to_str().unwrap().to_string();
    std::fs::create_dir_all(d.path().join("other")).unwrap();
    let (code0, out0, _) = run_bin(&d, &[]);
    let (code1, out1, _) = run_bin(&d, &[&"--evidence-log", &dest_s]);
    assert_eq!(code0, code1, "exit code unchanged by logging");
    for line in ["A INPUTS_COMPLETE:", "B CRYPTOGRAPHIC_CHECKS:", "G OPERATIONAL_READY: NO"] {
        assert!(out1.contains(line), "verdict kept {:?}:\n{}", line, out1);
    }
    // Only additive difference allowed: the evidence note.
    let strip = |s: &str| {
        s.lines().filter(|l| !l.contains("evidence log:")).collect::<Vec<_>>().join("\n")
    };
    // Note: run_id/timestamps differ per run, but verdict lines must match.
    for line in out0.lines().filter(|l| l.starts_with(['A', 'B', 'C', 'D', 'E', 'F', 'G']) || l.starts_with("E_")) {
        assert!(strip(&out1).contains(line), "lost line {:?}:\n{}", line, out1);
    }
}

// 18. Release package untouched by evidence emission.
#[test]
fn s18_release_package_untouched() {
    let d = tempfile::tempdir().expect("tempdir");
    let root = d.path().join("pkg");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("a.bin"), b"bytes").unwrap();
    let before: Vec<(PathBuf, Vec<u8>)> = walk_files(&root);
    let dest = d.path().join("ev.jsonl");
    let dest_s = dest.to_str().unwrap().to_string();
    let root_s = root.to_str().unwrap().to_string();
    let m = d.path().join("manifest.json");
    std::fs::write(&m, b"").unwrap();
    let bin = env!("CARGO_BIN_EXE_v6_preflight");
    let out = std::process::Command::new(bin)
        .arg("--manifest").arg(&m)
        .arg("--repo").arg(d.path())
        .arg("--inventory-root").arg(&root_s)
        .arg("--package-id").arg("t:1:x")
        .arg("--evidence-log").arg(&dest_s)
        .output().expect("run");
    let _ = out;
    assert_eq!(walk_files(&root), before, "inventoried package byte-identical");
    assert_eq!(std::fs::read(&m).unwrap(), b"", "manifest byte-identical");
    // Log itself is OUTSIDE the inventoried root.
    assert!(!dest.starts_with(&root));
    let text = std::fs::read_to_string(&dest).expect("log written");
    aether_unified::evidence_log::validate_log(&text).expect("log validates");
}

fn walk_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap() {
            let e = e.unwrap();
            let q = e.path();
            if q.is_dir() {
                stack.push(q);
            } else {
                out.push((q.clone(), std::fs::read(&q).unwrap()));
            }
        }
    }
    out.sort();
    out
}

// 19. 4AQ regression (deterministic digest + T0/T1 classes via handle reads).
#[test]
fn s19_inventory_4aq_regression() {
    let d = tempfile::tempdir().expect("tempdir");
    std::fs::write(d.path().join("a.txt"), b"A").unwrap();
    let t0 = aether_unified::inventory::walk_release_root(d.path(), &[], None).expect("t0");
    let t0b = aether_unified::inventory::walk_release_root(d.path(), &[], None).expect("t0b");
    assert_eq!(
        aether_unified::inventory::inventory_digest(&t0.entries),
        aether_unified::inventory::inventory_digest(&t0b.entries)
    );
    std::fs::write(d.path().join("b.txt"), b"B").unwrap();
    let t1 = aether_unified::inventory::walk_release_root(d.path(), &[], None).expect("t1");
    let diff = aether_unified::inventory::diff_inventories(&t0.entries, &t1.entries);
    assert_eq!(diff.unexpected, vec!["b.txt".to_string()]);
    assert!(diff.missing.is_empty() && diff.changed.is_empty());
}

// 20. 4AR regression (handle identity + stable double read, no mtime proof).
#[test]
fn s20_file_identity_4ar_regression() {
    let d = tempfile::tempdir().expect("tempdir");
    let f = d.path().join("f.bin");
    std::fs::write(&f, b"v1-payload").unwrap();
    let pre = std::fs::symlink_metadata(&f).unwrap();
    let r = aether_unified::inventory::read_file_via_handle(&f, &pre).expect("handle read");
    assert_eq!(r.bytes, b"v1-payload");
    let s = aether_unified::inventory::read_file_stable_2x(&f).expect("stable read");
    assert_eq!(s.bytes, r.bytes);
    #[cfg(windows)]
    assert!(r.identity_best_effort, "windows best-effort residual still marked");
    // Same-size rewrite changes the bytes (mtime/size are not proof).
    std::fs::write(&f, b"v2-payload").unwrap();
    assert_eq!(b"v1-payload".len(), b"v2-payload".len());
    let pre2 = std::fs::symlink_metadata(&f).unwrap();
    let r2 = aether_unified::inventory::read_file_via_handle(&f, &pre2).expect("read2");
    assert_ne!(r2.bytes, r.bytes);
}

#[test]
fn u01_bare_filename_with_inventory_succeeds() {
    let d = tempfile::tempdir().expect("tempdir");
    let pkg = d.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("a.bin"), b"bytes").unwrap();
    let root_s = pkg.to_str().unwrap().to_string();
    let dest = "bare-ev.jsonl";
    let (code, out, _) = run_bin_cwd(
        &d,
        &[&"--inventory-root", &root_s, &"--package-id", "u:1:x", &"--evidence-log", dest],
        Some(d.path()),
    );
    assert_eq!(code, 2, "unusable manifest keeps exit 2:\n{}", out);
    assert!(!out.contains("E_EVIDENCE_WRITE"), "bare name must not be falsely refused:\n{}", out);
    let p = d.path().join(dest);
    assert!(p.exists(), "log created next to working dir");
    let text = std::fs::read_to_string(&p).unwrap();
    aether_unified::evidence_log::validate_log(&text).expect("log validates");
}

#[test]
fn u02_abort_reason_declared_but_unchecked() {
    let d = tempfile::tempdir().expect("tempdir");
    let m = anchor_failing_manifest(&d);
    let dest = d.path().join("ev.jsonl");
    let dest_s = dest.to_str().unwrap().to_string();
    let bin = env!("CARGO_BIN_EXE_v6_preflight");
    let out = std::process::Command::new(bin)
        .arg("--manifest").arg(&m)
        .arg("--repo").arg(d.path())
        .arg("--evidence-log").arg(&dest_s)
        .output().expect("run");
    let code = out.status.code().unwrap_or(99);
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    assert_eq!(code, 2, "aborted evaluation keeps exit 2:\n{}", text);
    assert!(text.contains("E_ANCHOR_FORMAT"), "anchor abort:\n{}", text);
    let log = std::fs::read_to_string(&dest).unwrap();
    let lines: Vec<serde_json::Value> =
        log.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let fid = lines
        .iter()
        .find(|v| v["type"] == "check" && v["body"]["check_id"] == "FILE_IDENTITY_HANDLES")
        .expect("identity check present");
    assert_eq!(fid["body"]["status"], "NOT_RUN");
    let reason = fid["body"]["reason"].as_str().unwrap();
    assert!(reason.contains("declared but unchecked"), "interrupted, not vague: {}", reason);
    assert!(reason.contains("1 artifact"), "stable count: {}", reason);
    let inputs = lines
        .iter()
        .find(|v| v["type"] == "check" && v["body"]["check_id"] == "INPUTS_COMPLETE")
        .unwrap();
    assert_eq!(inputs["body"]["status"], "FAIL");
    let dec = lines.last().unwrap();
    assert_eq!(dec["body"]["final_decision"], "NO_GO");
    aether_unified::evidence_log::validate_log(&log).expect("log validates");
    let header = &lines[0]["body"];
    let expect = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(std::fs::read(&m).unwrap());
        hex::encode(h.finalize())
    };
    assert_eq!(header["manifest_digest"], expect, "header binds the checked bytes (F4 single source)");
}

#[test]
fn u03_in_scope_destination_still_refused() {
    let d = tempfile::tempdir().expect("tempdir");
    let pkg = d.path().join("pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("a.bin"), b"bytes").unwrap();
    let root_s = pkg.to_str().unwrap().to_string();
    let dest = pkg.join("ev-inside.jsonl");
    let dest_s = dest.to_str().unwrap().to_string();
    let (code, out, _) = run_bin(&d, &[&"--inventory-root", &root_s, &"--evidence-log", &dest_s]);
    assert_eq!(code, 2);
    assert!(out.contains("inside the inventoried scope"), "confinement kept:\n{}", out);
    assert!(!dest.exists(), "nothing written inside the scope");
}

#[test]
fn u04_exclusive_create_and_symlink_dest() {
    let d = tempfile::tempdir().expect("tempdir");
    let p = d.path().join("race.jsonl");
    let t1 = "line-one\n".to_string();
    let t2 = "line-two\n".to_string();
    let (r1, r2) = std::thread::scope(|s| {
        let a = s.spawn(|| aether_unified::evidence_log::write_log_file(&p, &t1));
        let b = s.spawn(|| aether_unified::evidence_log::write_log_file(&p, &t2));
        (a.join().unwrap(), b.join().unwrap())
    });
    assert!(r1.is_ok() ^ r2.is_ok(), "exactly one creator wins: {:?} {:?}", r1, r2);
    let body = std::fs::read_to_string(&p).unwrap();
    assert!(body == t1 || body == t2, "winner bytes intact, never mixed");
    let err = if r1.is_err() { r1.unwrap_err() } else { r2.unwrap_err() };
    assert!(err.contains("overwrite"), "loser refused explicitly: {}", err);
    #[cfg(unix)]
    {
        let target = d.path().join("real-target.jsonl");
        std::fs::write(&target, b"existing").unwrap();
        let link = d.path().join("link-dest.jsonl");
        if std::os::unix::fs::symlink(&target, &link).is_err() {
            eprintln!("NOT_RUN: symlink creation unavailable on this runner");
            return;
        }
        let err = aether_unified::evidence_log::write_log_file(&link, "x\n").expect_err("symlink dest refused");
        assert!(err.contains("symlink"), "explicit: {}", err);
        assert_eq!(std::fs::read(&target).unwrap(), b"existing", "link target untouched");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;
        let target = d.path().join("real-target.jsonl");
        std::fs::write(&target, b"existing").unwrap();
        let link = d.path().join("link-dest.jsonl");
        if symlink_file(&target, &link).is_err() {
            eprintln!("NOT_RUN: symlink creation unavailable on this runner");
            return;
        }
        let err = aether_unified::evidence_log::write_log_file(&link, "x\n").expect_err("symlink dest refused");
        assert!(err.contains("symlink"), "explicit: {}", err);
        assert_eq!(std::fs::read(&target).unwrap(), b"existing", "link target untouched");
    }
}
