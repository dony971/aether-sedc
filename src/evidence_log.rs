//! PHASE 4AS: operational evidence log (F4AN-3).
//!
//! JSONL execution log for `v6_preflight`: which checks ran, their results,
//! what they refer to, the five operational statuses, and the final
//! decision. Omissions are VISIBLE (closed versioned registry, gapless
//! sequence, hash chain, self-validation). The log is tamper-EVIDENT, never
//! tamper-proof: a local hash chain cannot stop whoever controls the whole
//! file from rewriting it (4AN 5.3). No signature, no external anchor and
//! no authenticity claim here.
//!
//! Design source: `docs/AETHER_PHASE4AN_OPERATIONAL_EVIDENCE_DESIGN.md`
//! section 5. Check semantics are REUSED from the existing binary (same
//! E_ code predicates as the A-D verdicts), never reinvented.
//!
//! Canonical form: one JSON object per line, UTF-8, LF-terminated.
//! Objects are built with `serde_json` (sorted keys, no floats, ASCII
//! strings only). `hash` = SHA-256 hex over the compact JSON bytes of
//! `{"body","prev","seq","type"}` (sorted keys); `prev` = previous line's
//! `hash` (`GENESIS` for seq 1). `log_digest` (decision body) = hash of the
//! preceding (retention) line. Timestamps are UTC `Z` ISO-8601 rendered
//! from `SystemTime` without any date dependency (no chrono in tree).
//! Absent values use explicit tokens (`NOT_PROVIDED`, `UNAVAILABLE`,
//! `PENDING`, `NOT_VERIFIED`); nothing absent is ever invented.
//! No secrets, private keys, raw sensitive content or environment dumps
//! are ever recorded.

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Schema + closed check registry versions.
pub const SCHEMA_VERSION: u32 = 1;
pub const CHECKLIST_VERSION: &str = "4AS-v1";

/// The closed registry: EXACTLY these check ids, once each, in this order.
/// Granularity = the binary's real verdict-level controls (A-D predicates)
/// plus the two opt-in evidence controls (4AQ inventory, 4AR handles).
pub const REGISTRY: [&str; 6] = [
    "INPUTS_COMPLETE",
    "CRYPTOGRAPHIC_CHECKS",
    "CONFIGURATION_COHERENCE",
    "RELEASE_ARTIFACT_CHECKS",
    "INVENTORY_EXHAUSTIVENESS",
    "FILE_IDENTITY_HANDLES",
];

/// The five operational statuses (fixed names).
pub const OPERATIONAL_STATUSES: [&str; 5] = [
    "ARTIFACT_DIRECTORY_CONTROLLED",
    "CONCURRENT_WRITES_PREVENTED",
    "MANIFEST_ARTIFACTS_BOUND",
    "POST_VALIDATION_MUTATION_PROHIBITED",
    "OPERATOR_EVIDENCE_RETAINED",
];

/// Explicit missing-value tokens (never invented content).
pub const NOT_PROVIDED: &str = "NOT_PROVIDED";
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// Check status. Subset of the 4AN set: only PASS/FAIL/NOT_RUN are emitted;
/// anything else is rejected by the validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    NotRun,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Fail => "FAIL",
            CheckStatus::NotRun => "NOT_RUN",
        }
    }
    fn from_str(s: &str) -> Option<CheckStatus> {
        match s {
            "PASS" => Some(CheckStatus::Pass),
            "FAIL" => Some(CheckStatus::Fail),
            "NOT_RUN" => Some(CheckStatus::NotRun),
            _ => None,
        }
    }
}

/// One registry check outcome for the log.
#[derive(Debug, Clone)]
pub struct CheckRecord {
    pub id: &'static str,
    pub status: CheckStatus,
    /// Mandatory non-empty reason when status is NotRun.
    pub reason: Option<String>,
    /// Stable E_ code family or marker (e.g. `E_INPUT_*`, `EVALUATED`).
    pub code: String,
    /// Machine-readable detail (counts, digests, seq refs).
    pub detail: String,
    /// Provenance reference (relative path, digest, or explicit token).
    pub evidence_ref: String,
}

/// One operational status entry. UNVERIFIED stays UNVERIFIED: presence of a
/// value is never proof of its truth.
#[derive(Debug, Clone)]
pub struct OpStatus {
    pub name: &'static str,
    pub verified: bool,
    pub proof_ref: String,
    pub method: String,
    /// Mandatory non-empty explanation when not verified.
    pub explanation: String,
}

/// External-retention reference. Only independently proven copies count;
/// at emission time the state is always pending (never claimed).
#[derive(Debug, Clone)]
pub struct Retention {
    pub primary_path: String,
    pub external_copy: String,
    pub external_digest: String,
    pub protection: String,
    pub retention_period: String,
}

impl Retention {
    pub fn pending(primary: &str) -> Retention {
        Retention {
            primary_path: primary.to_string(),
            external_copy: "PENDING".to_string(),
            external_digest: "NOT_VERIFIED".to_string(),
            protection:
                "local hash chain only; tamper-evident, not tamper-proof; no signature"
                    .to_string(),
            retention_period: NOT_PROVIDED.to_string(),
        }
    }
}

/// Full input for one log build.
#[derive(Debug, Clone)]
pub struct EvidenceInput {
    pub run_id: String,
    pub package_id: String,
    pub manifest_digest: Option<String>,
    pub inventory_digest: Option<String>,
    pub binary_name: String,
    pub binary_version: String,
    pub binary_sha256: String,
    pub operator_id: Option<String>,
    pub ci_reference: Option<String>,
    pub started_unix_secs: u64,
    pub finished_unix_secs: u64,
    pub checks: Vec<CheckRecord>,
    pub statuses: Vec<OpStatus>,
    pub retention: Retention,
    /// Did the preflight evaluation complete (manifest usable)?
    pub evaluated: bool,
    /// Preflight verdict: true when evaluated && zero failures.
    pub preflight_valid: bool,
    /// Governance/activation state line (must never authorize activation).
    pub governance_note: String,
}

/// Render unix epoch seconds as UTC ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`
/// (Howard Hinnant days-from-civil algorithm; no date dependency).
pub fn unix_secs_to_iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as i64;
    // days -> civil date.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        m,
        d,
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Compact canonical JSON (sorted keys via serde_json's Map).
fn canonical(obj: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(obj).expect("json serialize")
}

fn non_empty(s: &str) -> bool {
    !s.trim().is_empty()
}

/// Build the canonical JSONL text. Fails closed on: unknown/duplicate
/// registry ids, missing registry entries, NOT_RUN without reason,
/// wrong status count/names, empty mandatory fields. On success the text
/// is self-validated (`validate_log`) before return: a log that is not
/// complete is never presented as complete.
pub fn build_log(input: &EvidenceInput) -> Result<String, String> {
    // --- registry closure checks (4AN 5.2) ---
    if input.checks.len() != REGISTRY.len() {
        return Err(format!(
            "registry must hold exactly {} checks, got {}",
            REGISTRY.len(),
            input.checks.len()
        ));
    }
    {
        let mut seen = HashSet::new();
        for (i, c) in input.checks.iter().enumerate() {
            if c.id != REGISTRY[i] {
                return Err(format!(
                    "registry order/identity violated at position {}: expected {}, got {}",
                    i, REGISTRY[i], c.id
                ));
            }
            if !seen.insert(c.id) {
                return Err(format!("duplicate check {}", c.id));
            }
            if c.status == CheckStatus::NotRun
                && c.reason.as_deref().map(non_empty).unwrap_or(false) == false
            {
                return Err(format!("NOT_RUN without reason: {}", c.id));
            }
            if !non_empty(&c.code) || !non_empty(&c.detail) || !non_empty(&c.evidence_ref) {
                return Err(format!("empty mandatory field in check {}", c.id));
            }
        }
    }
    if input.statuses.len() != OPERATIONAL_STATUSES.len() {
        return Err(format!(
            "exactly {} operational statuses required, got {}",
            OPERATIONAL_STATUSES.len(),
            input.statuses.len()
        ));
    }
    {
        let mut seen = HashSet::new();
        for (i, s) in input.statuses.iter().enumerate() {
            if s.name != OPERATIONAL_STATUSES[i] {
                return Err(format!(
                    "status order/identity violated at position {}: expected {}, got {}",
                    i, OPERATIONAL_STATUSES[i], s.name
                ));
            }
            if !seen.insert(s.name) {
                return Err(format!("duplicate status {}", s.name));
            }
            if !non_empty(&s.proof_ref) || !non_empty(&s.method) {
                return Err(format!("empty mandatory field in status {}", s.name));
            }
            if !s.verified && !non_empty(&s.explanation) {
                return Err(format!("UNVERIFIED without explanation: {}", s.name));
            }
        }
    }
    if !non_empty(&input.run_id) || !non_empty(&input.binary_sha256) {
        return Err("empty run_id or binary_sha256".to_string());
    }
    if input.finished_unix_secs < input.started_unix_secs {
        return Err("finished_at precedes started_at".to_string());
    }

    // --- event bodies (seq assigned in emission order) ---
    let header_body = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "run_id": input.run_id,
        "package_id": if non_empty(&input.package_id) { input.package_id.clone() } else { NOT_PROVIDED.to_string() },
        "manifest_digest": input.manifest_digest.clone().unwrap_or_else(|| UNAVAILABLE.to_string()),
        "inventory_digest_t0": input.inventory_digest.clone().unwrap_or_else(|| NOT_PROVIDED.to_string()),
        "inventory_tool": "v6_preflight built-in 4AQ walk",
        "preflight_binary": { "name": input.binary_name, "version": input.binary_version, "sha256": input.binary_sha256 },
        "operator_identity": input.operator_id.clone().unwrap_or_else(|| NOT_PROVIDED.to_string()),
        "ci_reference": input.ci_reference.clone().unwrap_or_else(|| NOT_PROVIDED.to_string()),
        "started_at": unix_secs_to_iso8601_utc(input.started_unix_secs),
        "finished_at": unix_secs_to_iso8601_utc(input.finished_unix_secs),
        "scope_declaration_digest": "NOT_PROVIDED (no SCOPE_DECLARATION artifact in this version)",
        "checklist_version": CHECKLIST_VERSION,
        "quiescence_declaration": "NOT_PROVIDED (O3 procedural only, no enforcement)",
        "storage_freeze_state": "absent (O5 not implemented)",
    });
    let mut events: Vec<(&str, serde_json::Value)> = Vec::new();
    events.push(("header", header_body));
    for c in &input.checks {
        let mut o = serde_json::Map::new();
        o.insert("check_id".to_string(), serde_json::Value::String(c.id.to_string()));
        o.insert("status".to_string(), serde_json::Value::String(c.status.as_str().to_string()));
        o.insert("code".to_string(), serde_json::Value::String(c.code.clone()));
        o.insert("detail".to_string(), serde_json::Value::String(c.detail.clone()));
        o.insert("evidence_ref".to_string(), serde_json::Value::String(c.evidence_ref.clone()));
        if c.status == CheckStatus::NotRun {
            o.insert(
                "reason".to_string(),
                serde_json::Value::String(c.reason.clone().unwrap_or_default()),
            );
        }
        events.push(("check", serde_json::Value::Object(o)));
    }
    for s in &input.statuses {
        events.push((
            "status",
            serde_json::json!({
                "name": s.name,
                "value": if s.verified { "VERIFIED" } else { "UNVERIFIED" },
                "proof_ref": s.proof_ref,
                "method": s.method,
                "explanation": if s.verified { String::new() } else { s.explanation.clone() },
            }),
        ));
    }
    events.push((
        "retention",
        serde_json::json!({
            "primary_path": input.retention.primary_path,
            "external_copy": input.retention.external_copy,
            "external_digest": input.retention.external_digest,
            "protection": input.retention.protection,
            "retention_period": input.retention.retention_period,
        }),
    ));
    // Decision: derived, coherent with real results. GO requires preflight
    // valid AND complete log AND all five statuses verified (currently
    // unreachable without O3/O5/external anchor -- documented, never faked).
    let non_pass: Vec<u64> = input
        .checks
        .iter()
        .enumerate()
        .filter(|(_, c)| c.status != CheckStatus::Pass)
        .map(|(i, _)| (i as u64) + 2) // seq of check events
        .collect();
    let all_verified = input.statuses.iter().all(|s| s.verified);
    let operational_met = all_verified;
    let has_fail = input.checks.iter().any(|c| c.status == CheckStatus::Fail);
    let decision = if input.preflight_valid && non_pass.is_empty() && operational_met {
        "GO"
    } else if !input.evaluated || has_fail {
        "NO_GO"
    } else {
        // Valid preflight with NOT_RUN (never FAIL) checks: detectably
        // incomplete, never a positive decision.
        "INCOMPLETE"
    };
    // Seq numbers: header=1, checks=2..7, statuses=8..12, retention=13,
    // decision=14 for the 6+5 registry (seq assigned at emission).
    let justification = format!(
        "preflight_valid={} evaluated={} non_pass_seqs={:?} operational_met={} gov={}",
        input.preflight_valid,
        input.evaluated,
        non_pass,
        operational_met,
        input.governance_note
    );
    // log_digest filled after chaining (hash of retention line).
    events.push((
        "decision",
        serde_json::json!({
            "final_decision": decision,
            "justification": justification,
            "non_pass_seqs": non_pass,
            "governance": input.governance_note,
            "log_digest": "PENDING_CHAIN",
        }),
    ));

    // --- hash chain emission ---
    let mut lines: Vec<String> = Vec::new();
    let mut prev = "GENESIS".to_string();
    for (idx, (typ, body)) in events.iter().enumerate() {
        let seq = (idx as u64) + 1;
        let payload = serde_json::json!({
            "body": body, "prev": prev, "seq": seq, "type": typ,
        });
        let raw = canonical(&payload);
        let hash = sha_hex(&raw);
        let line_obj = serde_json::json!({
            "body": body, "hash": hash, "prev": prev, "seq": seq, "type": typ,
        });
        lines.push(String::from_utf8(canonical(&line_obj)).expect("utf8"));
        prev = hash;
    }
    // Patch decision.log_digest = hash of retention line (chain head before
    // decision), then re-emit ONLY the decision line (its own hash covers
    // the patched body; prev still links to retention).
    let head_hash = lines
        .len()
        .checked_sub(2)
        .and_then(|ri| serde_json::from_str::<serde_json::Value>(&lines[ri]).ok())
        .and_then(|v| v.get("hash").and_then(|h| h.as_str()).map(|s| s.to_string()))
        .ok_or("chain head unreadable")?;
    {
        let n = lines.len() - 1;
        let mut v: serde_json::Value = serde_json::from_str(&lines[n]).map_err(|e| e.to_string())?;
        if let Some(d) = v.get_mut("body").and_then(|b| b.get_mut("log_digest")) {
            *d = serde_json::Value::String(head_hash.clone());
        }
        // Recompute payload hash over the patched body.
        let payload = serde_json::json!({
            "body": v.get("body").unwrap().clone(),
            "prev": v.get("prev").unwrap().clone(),
            "seq": v.get("seq").unwrap().clone(),
            "type": v.get("type").unwrap().clone(),
        });
        let hash = sha_hex(&canonical(&payload));
        v["hash"] = serde_json::Value::String(hash);
        lines[n] = String::from_utf8(canonical(&v)).expect("utf8");
        // Fix justification echo: none needed (justification has no digest).
    }
    let mut text = lines.join("\n");
    text.push('\n');
    // Self-validation: an incomplete log is never presented as complete.
    match validate_log(&text) {
        Ok(_) => Ok(text),
        Err(errs) => Err(format!("self-validation failed: {}", errs.join("; "))),
    }
}

/// Resolve the directory that will contain `dest` for scope comparison.
/// A parent-less path (bare filename) resolves against the process working
/// directory: an empty parent must NOT become the unresolvable "" (4AT F2).
pub fn evidence_parent_dir(dest: &Path) -> std::path::PathBuf {
    match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    }
}

/// Write the log to `dest` with exclusive creation as the final authority
/// (4AT F3): `create_new(true)` makes AlreadyExists a refusal without ever
/// overwriting. A pre-existing symlink destination is refused explicitly
/// (exclusive create would otherwise follow a dangling link and create the
/// target elsewhere). LF-only ASCII required. Parent dir must exist (no dir
/// creation: an inaccessible destination fails cleanly). A concurrent
/// creator between any check and creation loses via AlreadyExists; alias
/// races involving a planted final-component symlink remain a documented
/// residual (no TOCTOU-free primitive in stable std).
pub fn write_log_file(dest: &Path, text: &str) -> Result<(), String> {
    if !text.is_ascii() {
        return Err("log text is not ASCII".to_string());
    }
    if text.contains('\r') {
        return Err("log text must be LF-only".to_string());
    }
    match std::fs::symlink_metadata(dest) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(format!("refusing symlink destination {:?}", dest))
        }
        Ok(_) => {
            return Err(format!("refusing to overwrite existing file {:?}", dest))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("cannot verify destination {:?}: {}", dest, e))
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dest)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("refusing to overwrite existing file {:?}", dest)
            } else {
                format!("write failed for {:?}: {}", dest, e)
            }
        })?;
    {
        use std::io::Write;
        f.write_all(text.as_bytes())
            .map_err(|e| format!("write failed for {:?}: {}", dest, e))?;
    }
    Ok(())
}

/// Validation summary for a log text.
#[derive(Debug)]
pub struct ValidationSummary {
    pub lines: usize,
    pub checks_pass: usize,
    pub checks_fail: usize,
    pub checks_not_run: usize,
    pub decision: String,
    pub log_complete: bool,
}

/// Verify a log text (4AN C1-C3, C5-chain subset + false-GO guard).
/// Returns Ok(summary) when the log is COMPLETE, Err(list) otherwise.
/// An incomplete log is reported, never upgraded.
pub fn validate_log(text: &str) -> Result<ValidationSummary, Vec<String>> {
    let mut errs: Vec<String> = Vec::new();
    if text.is_empty() {
        return Err(vec!["empty log".to_string()]);
    }
    if text.contains('\r') {
        errs.push("CR found: log must be LF-only".to_string());
    }
    let raw_lines: Vec<&str> = text.lines().collect();
    let mut seqs: Vec<u64> = Vec::new();
    let mut prev_expected = "GENESIS".to_string();
    let mut check_ids: Vec<String> = Vec::new();
    let mut status_names: Vec<String> = Vec::new();
    let mut any_unverified = false;
    let mut types: Vec<String> = Vec::new();
    let mut check_status: HashMap<String, String> = HashMap::new();
    let mut not_run_reasons: HashMap<String, bool> = HashMap::new();
    let mut decision_val = String::new();
    let mut decision_non_pass: Vec<u64> = Vec::new();
    let mut decision_just = String::new();
    let mut decision_digest = String::new();
    let mut decision_seen = 0u32;
    let mut header_seen = 0u32;
    let mut retention_seen = 0u32;
    for (i, line) in raw_lines.iter().enumerate() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                errs.push(format!("line {}: invalid JSON: {}", i + 1, e));
                continue;
            }
        };
        let seq = v.get("seq").and_then(|s| s.as_u64());
        let typ = v.get("type").and_then(|s| s.as_str()).unwrap_or("").to_string();
        let prev = v.get("prev").and_then(|s| s.as_str()).unwrap_or("").to_string();
        let hash = v.get("hash").and_then(|s| s.as_str()).unwrap_or("").to_string();
        let body = v.get("body").cloned().unwrap_or(serde_json::Value::Null);
        match seq {
            Some(s) => seqs.push(s),
            None => errs.push(format!("line {}: missing seq", i + 1)),
        }
        types.push(typ.clone());
        // Self-hash check.
        let payload = serde_json::json!({
            "body": body, "prev": prev, "seq": seq.unwrap_or(0), "type": typ,
        });
        if sha_hex(&canonical(&payload)) != hash {
            errs.push(format!("line {}: hash mismatch (edited?)", i + 1));
        }
        if prev != prev_expected {
            errs.push(format!("line {}: prev-link break (deleted/reordered?)", i + 1));
        }
        prev_expected = hash.clone();
        match typ.as_str() {
            "header" => {
                header_seen += 1;
                for f in [
                    "schema_version", "run_id", "package_id", "manifest_digest",
                    "inventory_digest_t0", "preflight_binary", "started_at",
                    "finished_at", "checklist_version",
                ] {
                    if body.get(f).is_none() {
                        errs.push(format!("header: missing field {}", f));
                    }
                }
                if body.get("started_at").and_then(|s| s.as_str()).map(|s| s.contains('T')).unwrap_or(false) == false {
                    errs.push("header: started_at not ISO-8601".to_string());
                }
            }
            "check" => {
                let id = body.get("check_id").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let st = body.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string();
                check_ids.push(id.clone());
                if CheckStatus::from_str(&st).is_none() {
                    errs.push(format!("check {}: unknown status {:?}", id, st));
                } else {
                    check_status.insert(id.clone(), st.clone());
                    if st == "NOT_RUN" {
                        let ok = body
                            .get("reason")
                            .and_then(|s| s.as_str())
                            .map(non_empty)
                            .unwrap_or(false);
                        not_run_reasons.insert(id.clone(), ok);
                        if !ok {
                            errs.push(format!("check {}: NOT_RUN without reason", id));
                        }
                    }
                }
                for f in ["code", "detail", "evidence_ref"] {
                    if body.get(f).and_then(|s| s.as_str()).map(non_empty).unwrap_or(false) == false {
                        errs.push(format!("check {}: empty/missing {}", id, f));
                    }
                }
            }
            "status" => {
                let name = body.get("name").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let val = body.get("value").and_then(|s| s.as_str()).unwrap_or("").to_string();
                status_names.push(name.clone());
                if val != "VERIFIED" && val != "UNVERIFIED" {
                    errs.push(format!("status {}: bad value {:?}", name, val));
                }
                if val == "UNVERIFIED" {
                    any_unverified = true;
                }
                if val == "UNVERIFIED"
                    && body.get("explanation").and_then(|s| s.as_str()).map(non_empty).unwrap_or(false) == false
                {
                    errs.push(format!("status {}: UNVERIFIED without explanation", name));
                }
            }
            "retention" => {
                retention_seen += 1;
                for f in ["primary_path", "external_copy", "external_digest", "protection", "retention_period"] {
                    if body.get(f).is_none() {
                        errs.push(format!("retention: missing field {}", f));
                    }
                }
            }
            "decision" => {
                decision_seen += 1;
                decision_val.clear();
                decision_val.push_str(body.get("final_decision").and_then(|s| s.as_str()).unwrap_or(""));
                decision_digest.clear();
                decision_digest.push_str(body.get("log_digest").and_then(|s| s.as_str()).unwrap_or(""));
                decision_just.clear();
                decision_just.push_str(body.get("justification").and_then(|s| s.as_str()).unwrap_or(""));
                if let Some(arr) = body.get("non_pass_seqs").and_then(|a| a.as_array()) {
                    for x in arr {
                        if let Some(n) = x.as_u64() {
                            decision_non_pass.push(n);
                        }
                    }
                }
                if !["GO", "NO_GO", "INCOMPLETE"].contains(&decision_val.as_str()) {
                    errs.push(format!("decision: bad value {:?}", decision_val));
                }
                if decision_just.trim().is_empty() {
                    errs.push("decision: empty justification".to_string());
                }
            }
            other => errs.push(format!("line {}: unknown type {:?}", i + 1, other)),
        }
    }
    // Sequence 1..M, header first, decision last.
    let m = raw_lines.len() as u64;
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    if sorted != (1..=m).collect::<Vec<u64>>() {
        errs.push("sequence is not exactly 1..M (gap/duplicate/reuse)".to_string());
    }
    if types.first().map(|s| s.as_str()) != Some("header") {
        errs.push("first event must be header".to_string());
    }
    if types.last().map(|s| s.as_str()) != Some("decision") {
        errs.push("last event must be decision".to_string());
    }
    if header_seen != 1 {
        errs.push(format!("exactly one header required, got {}", header_seen));
    }
    if retention_seen != 1 {
        errs.push(format!("exactly one retention event required, got {}", retention_seen));
    }
    if decision_seen != 1 {
        errs.push(format!("exactly one decision event required, got {}", decision_seen));
    }
    // Closed registry.
    let reg: Vec<String> = REGISTRY.iter().map(|s| s.to_string()).collect();
    if check_ids != reg {
        errs.push(format!(
            "check registry mismatch: expected {:?}, got {:?}",
            reg, check_ids
        ));
    }
    let ops: Vec<String> = OPERATIONAL_STATUSES.iter().map(|s| s.to_string()).collect();
    if status_names != ops {
        errs.push(format!(
            "status set mismatch: expected {:?}, got {:?}",
            ops, status_names
        ));
    }
    // Decision coherence: non_pass_seqs recomputed; GO guard.
    let mut recomputed: Vec<u64> = Vec::new();
    for (i, id) in check_ids.iter().enumerate() {
        if check_status.get(id).map(|s| s.as_str()) != Some("PASS") {
            recomputed.push((i as u64) + 2);
        }
    }
    let mut sorted_rec = recomputed.clone();
    sorted_rec.sort_unstable();
    let mut given = decision_non_pass.clone();
    given.sort_unstable();
    if given != sorted_rec {
        errs.push(format!(
            "decision non_pass_seqs {:?} != recomputed {:?}",
            given, sorted_rec
        ));
    }
    // log_digest must equal the hash of the retention (previous) line.
    if raw_lines.len() >= 2 {
        let prev_line = raw_lines[raw_lines.len() - 2];
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(prev_line) {
            let h = v.get("hash").and_then(|x| x.as_str()).unwrap_or("");
            if decision_digest != h {
                errs.push("decision log_digest != previous line hash".to_string());
            }
        }
    }
    // False-GO guard: GO requires all checks PASS and all statuses VERIFIED.
    if decision_val == "GO" {
        if !recomputed.is_empty() {
            errs.push("false GO: non-PASS checks present".to_string());
        }
        if any_unverified {
            errs.push("false GO: unverified operational status present".to_string());
        }
        if status_names.len() != ops.len() {
            errs.push("false GO: status set incomplete".to_string());
        }
    }
    if errs.is_empty() {
        let mut p = 0;
        let mut f = 0;
        let mut n = 0;
        for id in &check_ids {
            match check_status.get(id).map(|s| s.as_str()) {
                Some("PASS") => p += 1,
                Some("FAIL") => f += 1,
                _ => n += 1,
            }
        }
        Ok(ValidationSummary {
            lines: raw_lines.len(),
            checks_pass: p,
            checks_fail: f,
            checks_not_run: n,
            decision: decision_val,
            log_complete: true,
        })
    } else {
        Err(errs)
    }
}

/// Build the standard retention pending block for a destination path.
pub fn pending_retention(dest: &str) -> Retention {
    Retention::pending(dest)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn sample_input() -> EvidenceInput {
        EvidenceInput {
            run_id: "run-test-1".to_string(),
            package_id: "pkg:1:test".to_string(),
            manifest_digest: Some("aa".to_string()),
            inventory_digest: Some("bb".to_string()),
            binary_name: "v6_preflight".to_string(),
            binary_version: "test".to_string(),
            binary_sha256: "cc".to_string(),
            operator_id: None,
            ci_reference: None,
            started_unix_secs: 1_790_000_000,
            finished_unix_secs: 1_790_000_005,
            checks: REGISTRY
                .iter()
                .map(|id| CheckRecord {
                    id,
                    status: CheckStatus::Pass,
                    reason: None,
                    code: "EVALUATED".to_string(),
                    detail: "ok".to_string(),
                    evidence_ref: "unit".to_string(),
                })
                .collect(),
            statuses: OPERATIONAL_STATUSES
                .iter()
                .map(|n| OpStatus {
                    name: n,
                    verified: false,
                    proof_ref: "none".to_string(),
                    method: "none".to_string(),
                    explanation: "unit: no proof mechanism".to_string(),
                })
                .collect(),
            retention: Retention::pending("out.jsonl"),
            evaluated: true,
            preflight_valid: true,
            governance_note: "V6 activation NOT authorized by this log".to_string(),
        }
    }

    #[test]
    fn build_validates_roundtrip() {
        let t = build_log(&sample_input()).expect("build");
        let s = validate_log(&t).expect("validate");
        assert_eq!(s.lines, 1 + 6 + 5 + 1 + 1);
        assert_eq!(s.decision, "INCOMPLETE"); // operational unverified
    }

    #[test]
    fn not_run_without_reason_rejected() {
        let mut i = sample_input();
        i.checks[4].status = CheckStatus::NotRun;
        i.checks[4].reason = None;
        assert!(build_log(&i).is_err());
    }

    #[test]
    fn iso8601_known_value() {
        // 2026-10-13T00:00:00Z = 1791849600 (verified with datetime).
        assert_eq!(unix_secs_to_iso8601_utc(1_791_849_600), "2026-10-13T00:00:00Z");
        assert_eq!(unix_secs_to_iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn parent_dir_bare_and_nested() {
        use std::path::{Path, PathBuf};
        // 4AT F2: a bare filename resolves against "." (never "").
        assert_eq!(evidence_parent_dir(Path::new("ev.jsonl")), PathBuf::from("."));
        assert_eq!(evidence_parent_dir(Path::new("sub/ev.jsonl")), PathBuf::from("sub"));
        assert_eq!(
            evidence_parent_dir(Path::new("/abs/dir/ev.jsonl")),
            PathBuf::from("/abs/dir")
        );
    }
}
