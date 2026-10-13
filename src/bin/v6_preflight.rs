//! V6 offline release preflight (Phase 4Z).
//!
//! Read-only pre-verification of a governance release manifest. Never
//! writes, never contacts the network, never activates V6, never mutates
//! node state. All filesystem access is reads (manifest, anchor bytes,
//! artifact files for hashing); all git access is read-only plumbing
//! (rev-parse, cat-file, status). Exit 0 = every verifiable check passed;
//! exit 1 = one or more checks failed; exit 2 = manifest unusable.
//!
//! A PASS evaluates the MANIFEST's internal coherence only. It does NOT
//! prove value authenticity or authority: governance must confirm
//! provenance out of band (printed on every run, see SCOPE_NOTE).

use aether_unified::anchor::{
    anchor_id, validator_set_root, verify_anchor,
};
use aether_unified::evidence_log as ev;
use aether_unified::inventory as inv;
use aether_unified::stake::{StakeRegistry, ValidatorRecord};
use aether_unified::transaction::Vote;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const TOOL_MANIFEST_FORMAT: u64 = 1;
const HISTORICAL_TAG: &str = "v1.4.0-testnet";
const HISTORICAL_COMMIT: &str = "ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316";

const SCOPE_NOTE: &str = "SCOPE: this tool checks manifest coherence only (formats, recomputation, local git objects, file hashes). It cannot prove value authenticity or governance authority: provenance must be confirmed out of band.";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    code: &'static str,
    detail: String,
}

struct Report {
    errors: Vec<Finding>,
    notes: Vec<String>,
    // PHASE 4AS: structured evidence counters (no output change by itself;
    // read by the opt-in evidence-log builder only).
    artifacts_total: u32,
    artifacts_verified: u32,
    // PHASE 4AU F1: declared count known right after manifest parse, so an
    // abort can report "declared but unchecked" instead of "none declared".
    artifacts_declared: Option<usize>,
    // PHASE 4AU F4: exact manifest bytes checked by run(), single source
    // for the evidence header digest (no second read of the manifest).
    manifest_bytes: Option<Vec<u8>>,
    inventory_requested: bool,
    inventory_digest: Option<(String, usize)>,
    inventory_expected: Option<String>,
    inventory_failed: bool,
}

impl Report {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            notes: Vec::new(),
            artifacts_total: 0,
            artifacts_verified: 0,
            artifacts_declared: None,
            manifest_bytes: None,
            inventory_requested: false,
            inventory_digest: None,
            inventory_expected: None,
            inventory_failed: false,
        }
    }
    fn fail(&mut self, code: &'static str, detail: String) {
        self.errors.push(Finding { code, detail });
    }
    fn note(&mut self, s: String) {
        self.notes.push(s);
    }
    fn has_failures(&self) -> bool {
        !self.errors.is_empty()
    }
}

// --- strict JSON: duplicate keys rejected (serde_json is last-wins) ---

fn reject_duplicate_keys(text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut stack: Vec<HashSet<String>> = Vec::new();
    let mut i = 0usize;
    while i < n {
        let c = bytes[i] as char;
        if c.is_whitespace() || c == ',' {
            i += 1;
            continue;
        }
        if c == '{' {
            stack.push(HashSet::new());
            i += 1;
            continue;
        }
        if c == '}' || c == ']' {
            if c == '}' {
                stack.pop();
            }
            i += 1;
            continue;
        }
        if c == '[' {
            i += 1;
            continue;
        }
        if c == '"' {
            let mut s = String::new();
            let mut j = i + 1;
            let mut esc = false;
            loop {
                if j >= n {
                    return Err("E_INPUT_FORMAT: unterminated string".to_string());
                }
                let d = bytes[j] as char;
                if esc {
                    s.push(d);
                    esc = false;
                } else if d == '\\' {
                    esc = true;
                } else if d == '"' {
                    break;
                } else {
                    s.push(d);
                }
                j += 1;
            }
            // Look ahead for ':' (key) vs value position.
            let mut k = j + 1;
            while k < n && ((bytes[k] as char).is_whitespace()) {
                k += 1;
            }
            if k < n && bytes[k] as char == ':' {
                if let Some(set) = stack.last_mut() {
                    if !set.insert(s.clone()) {
                        return Err(format!("E_INPUT_DUPLICATE: duplicate key {:?}", s));
                    }
                }
            }
            i = j + 1;
            continue;
        }
        if c == ':' {
            i += 1;
            continue;
        }
        // numbers, true/false/null: skip one token.
        i += 1;
    }
    Ok(())
}

// --- manifest schema (tool input contract, documented, not a protocol) ---

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u64,
    activation_ts: u64,
    network_id: u64,
    release_version: String,
    release_commit: String,
    validator_set: Vec<ValidatorRecord>,
    stake: StakeSection,
    anchor: serde_json::Value,
    artifacts: Vec<Artifact>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StakeSection {
    claimed_eligible_total: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("git unavailable: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// PHASE 4AB: lexical artifact-path contract (pure, host-independent: it
/// must reject Windows forms even when the tool runs on Linux, so no
/// `std::path` host semantics are used here -- only byte-level rules).
/// Accepted: relative paths with no escape, e.g. `artifact.bin`,
/// `sub/dir/file`. Rejected: empty paths, POSIX absolutes (`/...`),
/// Windows rooted (`\...`), drive prefixes (`C:`, `C:\`, `C:/`), UNC and
/// device prefixes (`\\server\..`, `\\?\..`, `\\.\..`, and `//...`), and any
/// `..` component under either separator (including mixed `../..\`).
/// `.` components are allowed (canonical confinement below normalizes them;
/// they cannot escape). Reserved device names need no rule: reads fail
/// closed as missing/unreadable.
fn validate_artifact_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("empty artifact path".to_string());
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(format!("absolute/rooted artifact path {:?}", path));
    }
    let bytes = path.as_bytes();
    // Drive prefix `X:` (covers `C:\`, `C:/`, bare `C:`).
    if bytes.len() >= 2 && bytes[1] == b':' && (bytes[0] as char).is_ascii_alphabetic() {
        return Err(format!("drive-prefixed artifact path {:?}", path));
    }
    // UNC / device / POSIX-double-slash prefixes.
    if path.starts_with("\\\\") || path.starts_with("//") {
        return Err(format!("UNC/device artifact path {:?}", path));
    }
    // `..` under either separator (forward, backslash, or mixed).
    if path.split(['/', '\\']).any(|p| p == "..") {
        return Err(format!("parent-traversal artifact path {:?}", path));
    }
    Ok(())
}

/// Confinement failures, kept distinct so callers map them to stable
/// codes (missing/unreadable vs escape attempt) without string sniffing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfineError {
    Missing(String),
    Escape(String),
}

/// PHASE 4AB: confinement of a lexically valid path to the release root.
/// Canonicalizes BOTH sides (the root itself may involve symlinks, e.g.
/// macOS /private aliases or Windows junctions) and requires the target to
/// stay inside. Symlinks pointing outside are rejected here; symlinks
/// resolving inside are accepted (same content guarantee as a direct file:
/// the hash covers the bytes actually read).
/// TOCTOU note: std offers no openat2-style primitive, so a hostile writer
/// with access to these operator paths could swap a symlink between this
/// check and the read below. Impact stays read-only (a hash over bytes into
/// a local report). Documented, not pretended away.
fn confine_artifact_path(repo: &Path, path: &str) -> Result<PathBuf, ConfineError> {
    validate_artifact_path(path).map_err(ConfineError::Escape)?;
    let root = repo
        .canonicalize()
        .map_err(|e| ConfineError::Missing(format!("release root unresolvable: {}", e)))?;
    let joined = root.join(path);
    let target = joined
        .canonicalize()
        .map_err(|_| ConfineError::Missing(format!("artifact {:?} absent or unreadable", path)))?;
    if !target.starts_with(&root) {
        return Err(ConfineError::Escape(format!(
            "artifact {:?} escapes the release root",
            path
        )));
    }
    Ok(target)
}

fn check_artifact(repo: &Path, art: &Artifact, rep: &mut Report) {
    rep.artifacts_total += 1;
    if !is_hex(&art.sha256, 64) {
        rep.fail("E_ARTIFACT_FORMAT", format!("artifact {:?} sha256 must be 64 hex chars", art.path));
        return;
    }
    // PHASE 4AB: lexical gate, then confined resolution (symlink-aware),
    // then a SINGLE read whose bytes are both hashed and reported. The hash
    // always covers the file actually read; no re-read, no replacement.
    if let Err(e) = validate_artifact_path(&art.path) {
        rep.fail("E_ARTIFACT_PATH", e);
        return;
    }
    let full = match confine_artifact_path(repo, &art.path) {
        Ok(p) => p,
        Err(ConfineError::Missing(e)) => {
            rep.fail("E_ARTIFACT_MISSING", format!("artifact {:?} unreadable: {}", art.path, e));
            return;
        }
        Err(ConfineError::Escape(e)) => {
            rep.fail("E_ARTIFACT_PATH", e);
            return;
        }
    };
    // PHASE 4AR (F4AN-2, O2+O4): artifacts are sensitive files. Hash the
    // bytes read FROM the open handle with a second controlled read from
    // the SAME handle (no path re-resolution between verify and use).
    // mtime is never consulted. Any identity divergence or read
    // instability refuses the artifact explicitly.
    let dread = match inv::read_file_stable_2x(&full) {
        Ok(r) => r,
        Err(e) => {
            rep.fail("E_ARTIFACT_MISSING", format!("artifact {:?} unreadable: {}", art.path, e));
            return;
        }
    };
    rep.note(format!(
        "artifact {:?} handle identity: {}{}",
        art.path,
        dread.identity,
        if dread.identity_best_effort { " (best-effort, Windows)" } else { "" }
    ));
    let bytes = dread.bytes;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&bytes);
    let got = hex::encode(hasher.finalize());
    if got != art.sha256.to_lowercase() {
        rep.fail(
            "E_ARTIFACT_CHECKSUM",
            format!("artifact {:?} checksum mismatch (manifest declares {}, file is {})", art.path, art.sha256, got),
        );
        return;
    }
    rep.artifacts_verified += 1;
}

fn run(manifest_path: &Path, repo: &Path, rep: &mut Report) -> bool {
    // Returns true when evaluation completed (even with failures).
    let text = match std::fs::read_to_string(manifest_path) {
        Ok(t) => t,
        Err(e) => {
            rep.fail("E_INPUT_UNREADABLE", format!("cannot read manifest: {}", e));
            return false;
        }
    };
    // PHASE 4AU F4: keep the exact checked bytes for the evidence header.
    rep.manifest_bytes = Some(text.as_bytes().to_vec());
    if let Err(e) = reject_duplicate_keys(&text) {
        rep.fail("E_INPUT_DUPLICATE", e);
        return false;
    }
    let m: Manifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            rep.fail("E_INPUT_FORMAT", format!("manifest parse failed: {}", e));
            return false;
        }
    };
    // PHASE 4AU F1: declared artifacts known even if evaluation aborts later.
    rep.artifacts_declared = Some(m.artifacts.len());
    if m.format != TOOL_MANIFEST_FORMAT {
        rep.fail(
            "E_INPUT_FORMAT",
            format!("manifest format {} != tool format {}", m.format, TOOL_MANIFEST_FORMAT),
        );
        return false;
    }

    // A. inputs present + well-formed (serde guarantees shape; rules below).
    if m.activation_ts == 0 {
        rep.fail("E_TS_MISSING", "activation_ts must be an explicit nonzero unix-ms timestamp".to_string());
    }
    if m.release_version.is_empty() {
        rep.fail("E_VERSION_MISSING", "release_version must be a nonempty string".to_string());
    }
    if !is_hex(&m.release_commit, 40) {
        rep.fail("E_COMMIT_FORMAT", "release_commit must be 40 hex chars".to_string());
    }
    if m.validator_set.is_empty() {
        rep.fail("E_SET_EMPTY", "validator_set must list at least one validator".to_string());
    }
    // Network: present u64 is guaranteed by schema; zero never governs.
    if m.network_id == 0 {
        rep.fail("E_NETWORK_ZERO", "network_id 0 is legacy-neutral and never satisfies a V6 prerequisite".to_string());
    }

    // Validator set structural checks (no policy invented beyond recompute).
    {
        let mut seen = HashSet::new();
        for r in &m.validator_set {
            if !seen.insert(r.address) {
                rep.fail("E_SET_DUPLICATE", "validator_set contains a duplicate address".to_string());
                break;
            }
            if r.bonded_amount == 0 {
                rep.fail("E_SET_ZERO_STAKE", "validator with zero bonded_amount".to_string());
            }
        }
    }

    // Anchor bundle parse (existing format, strict).
    let anchor_bytes = serde_json::to_vec(&m.anchor).unwrap_or_default();
    let bundle = match aether_unified::anchor::parse_anchor_bundle(&anchor_bytes) {
        Ok(b) => b,
        Err(e) => {
            // Anchor unparsable: crypto checks cannot run at all -> the
            // manifest is unusable for its core purpose (exit 2 path).
            rep.fail("E_ANCHOR_FORMAT", format!("anchor bundle parse failed: {:?}", e));
            return false;
        }
    };

    // B/C. cryptographic + coherence checks over recomputation.
    // Set root recomputed at the anchor epoch; totals recomputed.
    let (root, total) = validator_set_root(&bundle.validator_set, bundle.anchor.epoch);
    if root != bundle.anchor.set_root {
        rep.fail("E_SET_ROOT", "anchor set_root does not match recomputation from validator_set".to_string());
    }
    if total != bundle.anchor.claimed_total {
        rep.fail(
            "E_STAKE_MISMATCH",
            format!("claimed_total {} != recomputed eligible total {}", bundle.anchor.claimed_total, total),
        );
    }
    if m.stake.claimed_eligible_total != total {
        rep.fail(
            "E_STAKE_MISMATCH",
            format!(
                "stake.claimed_eligible_total {} != recomputed {} (validator set at anchor epoch {})",
                m.stake.claimed_eligible_total, total, bundle.anchor.epoch
            ),
        );
    }
    // Anchor network must equal manifest network (cross-network bundle).
    if bundle.anchor.network_id != m.network_id {
        rep.fail(
            "E_NETWORK_MISMATCH",
            format!("anchor network {} != manifest network {}", bundle.anchor.network_id, m.network_id),
        );
    }
    // Full anchor verification (structure/encoding/epoch/network/root/
    // votes/signatures/quorum/chain/tag via existing verifier).
    let id = anchor_id(&bundle.anchor);
    match verify_anchor(&bundle.anchor, &bundle.validator_set, id, m.network_id, |_, _| false) {
        Ok(sum) => {
            rep.note(format!(
                "anchor verifies: support {}/{} votes {} winner {}",
                sum.support,
                sum.total,
                sum.vote_count,
                hex::encode(sum.winner)
            ));
        }
        Err(e) => {
            rep.fail("E_ANCHOR_VERIFY", format!("anchor verification failed: {:?}", e));
        }
    }

    // D. release commit + artifacts (local git objects + files only).
    match git(repo, &["cat-file", "-t", &m.release_commit]) {
        Ok(t) if t == "commit" => {}
        Ok(other) => {
            rep.fail("E_COMMIT_TYPE", format!("{} is a {}, not a commit", m.release_commit, other));
        }
        Err(e) => {
            rep.fail("E_COMMIT_MISSING", format!("release commit not found locally: {}", e));
        }
    }
    if m.release_commit == HISTORICAL_COMMIT {
        rep.fail("E_COMMIT_HISTORICAL", "release commit is the historical ad08e30 object".to_string());
    }
    if m.release_version == HISTORICAL_TAG {
        rep.fail("E_VERSION_HISTORICAL", "release version collides with v1.4.0-testnet".to_string());
    }
    // Source correspondence, best effort, honestly bounded: HEAD equality +
    // clean tree proves the CHECKED-OUT source matches, never that a
    // shipped binary was built from it (reproducibility NOT claimed).
    match git(repo, &["rev-parse", "HEAD"]) {
        Ok(head) if head == m.release_commit => match git(repo, &["status", "--porcelain"]) {
            Ok(s) if s.is_empty() => {
                rep.note("source correspondence: HEAD equals release commit with clean tree".to_string());
            }
            Ok(_) => {
                rep.fail("E_SOURCE_DIRTY", "working tree dirty: checked-out source differs from release commit".to_string());
            }
            Err(e) => {
                rep.fail("E_GIT", format!("git status failed: {}", e));
            }
        },
        Ok(head) => {
            rep.fail(
                "E_SOURCE_MISMATCH",
                format!("checked-out HEAD {} != release commit {}", head, m.release_commit),
            );
        }
        Err(e) => {
            rep.fail("E_GIT", format!("git rev-parse failed: {}", e));
        }
    }
    for art in &m.artifacts {
        check_artifact(repo, art, rep);
    }
    if m.artifacts.is_empty() {
        rep.note("no artifacts declared: nothing hashed (explicitly allowed, recorded)".to_string());
    }

    // Evaluation COMPLETED (findings, if any, are in the report and drive
    // exit 1 via has_failures; only the early returns above mean NOT_EVALUATED).
    true
}

fn print_verdicts(rep: &Report, evaluated: bool) {
    fn is_input_code(code: &str) -> bool {
        matches!(
            code,
            "E_INPUT_UNREADABLE"
                | "E_INPUT_DUPLICATE"
                | "E_INPUT_FORMAT"
                | "E_TS_MISSING"
                | "E_VERSION_MISSING"
                | "E_COMMIT_FORMAT"
                | "E_SET_EMPTY"
                | "E_NETWORK_ZERO"
                | "E_SET_DUPLICATE"
                | "E_SET_ZERO_STAKE"
        )
    }
    let input_fail = rep.errors.iter().any(|f| is_input_code(f.code));
    println!("V6_RELEASE_PREFLIGHT verdicts");
    println!(
        "A INPUTS_COMPLETE: {}",
        if !evaluated {
            "NOT_EVALUATED"
        } else if input_fail {
            "FAIL"
        } else {
            "PASS"
        }
    );
    let crypto_fail = rep.errors.iter().any(|f| f.code.starts_with("E_ANCHOR") || f.code.starts_with("E_SET") || f.code == "E_STAKE_MISMATCH");
    println!("B CRYPTOGRAPHIC_CHECKS: {}", if crypto_fail { "FAIL" } else { "PASS" });
    let coherence_fail = rep.errors.iter().any(|f| f.code.starts_with("E_NETWORK") || f.code.starts_with("E_STAKE") || f.code.starts_with("E_TS") || f.code.starts_with("E_VERSION"));
    println!("C CONFIGURATION_COHERENCE: {}", if coherence_fail { "FAIL" } else { "PASS" });
    let release_fail = rep.errors.iter().any(|f| f.code.starts_with("E_COMMIT") || f.code.starts_with("E_SOURCE") || f.code.starts_with("E_ARTIFACT") || f.code.starts_with("E_GIT"));
    println!("D RELEASE_ARTIFACT_CHECKS: {}", if release_fail { "FAIL" } else { "PASS" });
    let gov_fail = rep.errors.iter().any(|f| f.code == "E_NETWORK_ZERO" || f.code.starts_with("E_INPUT") || f.code.starts_with("E_TS") || f.code.starts_with("E_VERSION") || f.code.starts_with("E_COMMIT") || f.code.starts_with("E_SET_EMPTY"));
    println!("E GOVERNANCE_READY: {}", if gov_fail || !evaluated { "NO" } else { "YES (inputs complete+consistent; authenticity NOT proven offline)" });
    println!("F TECHNICAL_READY: {}", if rep.has_failures() || !evaluated { "NO" } else { "YES (checks green; suite evidence separate, cited in 4R)" });
    println!("G OPERATIONAL_READY: NO (preflight cannot observe operations; nothing deployed)");
    println!("{}", SCOPE_NOTE);
    for f in &rep.errors {
        println!("{}: {}", f.code, f.detail);
    }
    for n in &rep.notes {
        println!("note: {}", n);
    }
}

/// PHASE 4AQ (F4AN-1): opt-in deterministic inventory check.
/// Runs ONLY when `--inventory-root` is supplied; otherwise behavior is
/// byte-identical to the pre-4AQ tool (all existing fixtures unaffected).
/// Read-only: delegates to `inventory::walk_release_root` (no writes).
fn check_inventory_opt(
    root: &str,
    package_id: &str,
    expected_digest: Option<&str>,
    expected_manifest_digest: Option<&str>,
    manifest_path: &Path,
    exclusions: &[String],
    rep: &mut Report,
) {
    let root_path = Path::new(root);
    // PHASE 4AS: structured evidence recording (read by the opt-in log
    // builder; no output change by itself).
    rep.inventory_requested = true;
    rep.inventory_expected = expected_digest.map(|s| s.to_string());
    let inventory = match inv::walk_release_root(root_path, exclusions, None) {
        Ok(i) => i,
        Err(e) => {
            rep.fail("E_INVENTORY_UNREADABLE", format!("inventory walk failed: {}", e));
            rep.inventory_failed = true;
            return;
        }
    };
    if inventory.entries.is_empty() {
        rep.fail("E_INVENTORY_EMPTY", "inventory is empty (no entries under root)".to_string());
        rep.inventory_failed = true;
        return;
    }
    // Any unreadable entry fails closed as INCOMPLETE (never silent).
    let unread: Vec<&str> = inventory
        .entries
        .iter()
        .filter(|e| e.kind == inv::EntryKind::Unreadable)
        .map(|e| e.normalized_path.as_str())
        .collect();
    if !unread.is_empty() {
        rep.fail(
            "E_INVENTORY_INCOMPLETE",
            format!("unreadable entries ({}): {}", unread.len(), unread.join(",")),
        );
        rep.inventory_failed = true;
    }
    // PHASE 4BB: unexplained hardlink references are never silently
    // resolved. `exterior:` (no exclusions: necessarily outside the scope)
    // fails closed under the existing INCOMPLETE code; `ambiguous:`
    // (exclusions may explain the gap) is a recorded note, never claimed
    // exterior. No new E_ code, no verdict-shape change.
    let exterior: Vec<&String> = inventory
        .warnings
        .external_link_refs
        .iter()
        .filter(|s| s.starts_with("exterior:"))
        .collect();
    if !exterior.is_empty() {
        let joined = exterior.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",");
        rep.fail(
            "E_INVENTORY_INCOMPLETE",
            format!("unexplained hardlink references ({}): {}", exterior.len(), joined),
        );
        rep.inventory_failed = true;
    }
    for a in inventory
        .warnings
        .external_link_refs
        .iter()
        .filter(|s| s.starts_with("ambiguous:"))
    {
        rep.note(format!("inventory ambiguous hardlink references (exclusions present): {}", a));
    }
    for s in &inventory.warnings.specials {
        rep.note(format!("inventory special file (recorded, not hashed): {}", s));
    }
    for c in &inventory.warnings.case_collisions {
        rep.note(format!("inventory case-collision (portability warning): {}", c));
    }
    for l in &inventory.warnings.external_links {
        rep.note(format!("inventory external symlink (never followed): {}", l));
    }
    let digest = inv::inventory_digest(&inventory.entries);
    rep.note(format!("inventory digest: {} (entries={})", digest, inventory.entries.len()));
    rep.inventory_digest = Some((digest.clone(), inventory.entries.len()));
    if !package_id.is_empty() {
        rep.note(format!("inventory package: {}", package_id));
    }
    if let Some(exp) = expected_digest {
        if digest != exp.to_lowercase() {
            rep.fail(
                "E_INVENTORY_MISMATCH",
                format!("inventory digest mismatch (expected {}, got {})", exp, digest),
            );
            rep.inventory_failed = true;
        }
    }
    if let Some(exp_m) = expected_manifest_digest {
        match std::fs::read(manifest_path) {
            Ok(bytes) => {
                let got = inv::manifest_digest(&bytes);
                if got != exp_m.to_lowercase() {
                    rep.fail(
                        "E_MANIFEST_DIGEST_MISMATCH",
                        format!("manifest digest mismatch (expected {}, got {})", exp_m, got),
                    );
                }
            }
            Err(e) => {
                rep.fail("E_INVENTORY_UNREADABLE", format!("cannot re-read manifest for digest: {}", e));
            }
        }
    }
}

/// PHASE 4AS (F4AN-3): derive the closed 4AS-v1 registry from a finished
/// Report. Code predicates are the SAME as the A-D verdicts (reuse, never
/// reinvented semantics). Unrun downstream checks after an early abort are
/// NOT_RUN with reason, never invented PASS.
fn derive_evidence_checks(rep: &Report, evaluated: bool) -> Vec<ev::CheckRecord> {
    fn any(rep: &Report, pred: impl Fn(&str) -> bool) -> Vec<String> {
        let mut v: Vec<String> = rep
            .errors
            .iter()
            .filter(|f| pred(f.code))
            .map(|f| f.code.to_string())
            .collect();
        v.sort();
        v.dedup();
        v
    }
    fn is_input(code: &str) -> bool {
        matches!(
            code,
            "E_INPUT_UNREADABLE"
                | "E_INPUT_DUPLICATE"
                | "E_INPUT_FORMAT"
                | "E_TS_MISSING"
                | "E_VERSION_MISSING"
                | "E_COMMIT_FORMAT"
                | "E_SET_EMPTY"
                | "E_NETWORK_ZERO"
                | "E_SET_DUPLICATE"
                | "E_SET_ZERO_STAKE"
        )
    }
    let aborted = "evaluation aborted before this check (manifest unusable)";
    let mut out = Vec::new();
    // 1. INPUTS_COMPLETE (verdict A predicate).
    let c: Vec<String> = any(rep, is_input);
    out.push(ev::CheckRecord {
        id: "INPUTS_COMPLETE",
        status: if c.is_empty() { ev::CheckStatus::Pass } else { ev::CheckStatus::Fail },
        reason: None,
        code: if c.is_empty() { "EVALUATED".to_string() } else { c.join(",") },
        detail: format!("input failures={}", c.len()),
        evidence_ref: "manifest (--manifest)".to_string(),
    });
    // 2. CRYPTOGRAPHIC_CHECKS (verdict B predicate).
    let c: Vec<String> = any(rep, |code| {
        code.starts_with("E_ANCHOR") || code.starts_with("E_SET") || code == "E_STAKE_MISMATCH"
    });
    out.push(ev::CheckRecord {
        id: "CRYPTOGRAPHIC_CHECKS",
        status: if !c.is_empty() {
            ev::CheckStatus::Fail
        } else if !evaluated {
            ev::CheckStatus::NotRun
        } else {
            ev::CheckStatus::Pass
        },
        reason: if c.is_empty() && !evaluated { Some(aborted.to_string()) } else { None },
        code: if c.is_empty() { "EVALUATED".to_string() } else { c.join(",") },
        detail: format!("crypto failures={}", c.len()),
        evidence_ref: "anchor bundle in manifest".to_string(),
    });
    // 3. CONFIGURATION_COHERENCE (verdict C predicate).
    let c: Vec<String> = any(rep, |code| {
        code.starts_with("E_NETWORK")
            || code.starts_with("E_STAKE")
            || code.starts_with("E_TS")
            || code.starts_with("E_VERSION")
    });
    out.push(ev::CheckRecord {
        id: "CONFIGURATION_COHERENCE",
        status: if !c.is_empty() {
            ev::CheckStatus::Fail
        } else if !evaluated {
            ev::CheckStatus::NotRun
        } else {
            ev::CheckStatus::Pass
        },
        reason: if c.is_empty() && !evaluated { Some(aborted.to_string()) } else { None },
        code: if c.is_empty() { "EVALUATED".to_string() } else { c.join(",") },
        detail: format!("coherence failures={}", c.len()),
        evidence_ref: "manifest fields".to_string(),
    });
    // 4. RELEASE_ARTIFACT_CHECKS (verdict D predicate).
    let c: Vec<String> = any(rep, |code| {
        code.starts_with("E_COMMIT")
            || code.starts_with("E_SOURCE")
            || code.starts_with("E_ARTIFACT")
            || code.starts_with("E_GIT")
    });
    out.push(ev::CheckRecord {
        id: "RELEASE_ARTIFACT_CHECKS",
        status: if !c.is_empty() {
            ev::CheckStatus::Fail
        } else if !evaluated {
            ev::CheckStatus::NotRun
        } else {
            ev::CheckStatus::Pass
        },
        reason: if c.is_empty() && !evaluated { Some(aborted.to_string()) } else { None },
        code: if c.is_empty() { "EVALUATED".to_string() } else { c.join(",") },
        detail: format!(
            "release failures={} artifacts_verified={}/{}",
            c.len(),
            rep.artifacts_verified,
            rep.artifacts_total
        ),
        evidence_ref: "release commit + artifacts in manifest".to_string(),
    });
    // 5. INVENTORY_EXHAUSTIVENESS (4AQ opt-in; E_ inventory family).
    let c: Vec<String> = any(rep, |code| {
        code.starts_with("E_INVENTORY") || code == "E_MANIFEST_DIGEST_MISMATCH"
    });
    out.push(ev::CheckRecord {
        id: "INVENTORY_EXHAUSTIVENESS",
        status: if !rep.inventory_requested {
            ev::CheckStatus::NotRun
        } else if !c.is_empty() || rep.inventory_failed {
            ev::CheckStatus::Fail
        } else {
            ev::CheckStatus::Pass
        },
        reason: if !rep.inventory_requested {
            Some("inventory opt-in not requested (--inventory-root absent)".to_string())
        } else {
            None
        },
        code: if c.is_empty() { "EVALUATED".to_string() } else { c.join(",") },
        detail: match &rep.inventory_digest {
            Some((d, n)) => format!("digest={} entries={}", d, n),
            None => "no inventory produced".to_string(),
        },
        evidence_ref: "inventory root (--inventory-root)".to_string(),
    });
    // 6. FILE_IDENTITY_HANDLES (4AR stable_2x over declared artifacts).
    // PHASE 4AU F1: explicit abort taxonomy -- not-started (aborted),
    // interrupted (declared but unchecked), not-applicable (none declared).
    // Interrupted/absent is never PASS.
    let art_fail: Vec<String> = any(rep, |code| code.starts_with("E_ARTIFACT"));
    let declared = rep.artifacts_declared.unwrap_or(0);
    let interrupted = rep.artifacts_total == 0 && declared > 0 && !evaluated;
    out.push(ev::CheckRecord {
        id: "FILE_IDENTITY_HANDLES",
        status: if rep.artifacts_total == 0 {
            ev::CheckStatus::NotRun
        } else if !art_fail.is_empty() {
            ev::CheckStatus::Fail
        } else if !evaluated {
            ev::CheckStatus::NotRun
        } else {
            ev::CheckStatus::Pass
        },
        reason: if interrupted {
            Some(format!(
                "evaluation aborted after manifest parse; {} artifact(s) declared but unchecked (interrupted)",
                declared
            ))
        } else if rep.artifacts_total == 0 {
            Some("no artifacts declared".to_string())
        } else if art_fail.is_empty() && !evaluated {
            Some(aborted.to_string())
        } else {
            None
        },
        code: if art_fail.is_empty() { "HANDLE_STABLE_2X".to_string() } else { art_fail.join(",") },
        detail: format!(
            "handle-verified={}/{} declared",
            rep.artifacts_verified, rep.artifacts_total
        ),
        evidence_ref: "artifact paths in manifest".to_string(),
    });
    out
}

/// Derive the five operational statuses. A status that was not effectively
/// verified stays UNVERIFIED with an explanation: presence of a value is
/// never proof of its truth, and operator declaration alone never yields
/// PASS.
fn derive_evidence_statuses(rep: &Report, dest: &str) -> Vec<ev::OpStatus> {
    let release_ok = rep.errors.iter().all(|f| {
        !(f.code.starts_with("E_COMMIT")
            || f.code.starts_with("E_SOURCE")
            || f.code.starts_with("E_ARTIFACT")
            || f.code.starts_with("E_GIT"))
    });
    let inventory_ok = rep.inventory_requested && !rep.inventory_failed && rep.inventory_digest.is_some();
    let anchored = match (&rep.inventory_digest, &rep.inventory_expected) {
        (Some((got, _)), Some(exp)) => got == &exp.to_lowercase(),
        _ => false,
    };
    vec![
        ev::OpStatus {
            name: "ARTIFACT_DIRECTORY_CONTROLLED",
            verified: inventory_ok && anchored,
            proof_ref: match &rep.inventory_digest {
                Some((d, n)) => format!("inventory_digest={} entries={}", d, n),
                None => "none (no inventory produced)".to_string(),
            },
            method: "deterministic 4AQ walk, digest-anchored to expected value".to_string(),
            explanation: if inventory_ok && anchored {
                String::new()
            } else if !rep.inventory_requested {
                "inventory opt-in not requested; directory control not observed".to_string()
            } else if rep.inventory_failed {
                "inventory failed; control not established".to_string()
            } else {
                "digest recorded but unanchored (no --expected-digest supplied)".to_string()
            },
        },
        ev::OpStatus {
            name: "CONCURRENT_WRITES_PREVENTED",
            verified: false,
            proof_ref: "none (not observed)".to_string(),
            method: "none (not observable offline)".to_string(),
            explanation: "no quiescence enforcement in tool (O3 procedural only); 4AR TOCTOU residual applies"
                .to_string(),
        },
        ev::OpStatus {
            name: "MANIFEST_ARTIFACTS_BOUND",
            verified: release_ok && rep.artifacts_total > 0 && rep.artifacts_verified == rep.artifacts_total,
            proof_ref: format!(
                "artifacts_verified={}/{} declared",
                rep.artifacts_verified, rep.artifacts_total
            ),
            method: "handle-bound SHA-256 double read (stable_2x, 4AR), confined to release root".to_string(),
            explanation: if release_ok && rep.artifacts_total > 0 && rep.artifacts_verified == rep.artifacts_total {
                String::new()
            } else if rep.artifacts_total == 0 {
                "no artifacts declared; nothing bound".to_string()
            } else {
                "release artifact checks failed; binding not established".to_string()
            },
        },
        ev::OpStatus {
            name: "POST_VALIDATION_MUTATION_PROHIBITED",
            verified: false,
            proof_ref: "none (no immutable store)".to_string(),
            method: "none (O5 absent)".to_string(),
            explanation: "no immutable/frozen storage (O5 not implemented); post-run mutation possible"
                .to_string(),
        },
        ev::OpStatus {
            name: "OPERATOR_EVIDENCE_RETAINED",
            verified: false,
            proof_ref: format!("primary={} external=PENDING", dest),
            method: "local hash chain only".to_string(),
            explanation: "no external-copy proof at emission; retention PENDING (never claimed)".to_string(),
        },
    ]
}

fn now_secs() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("clock unavailable: {}", e))
}

/// PHASE 4AS (F4AN-3): opt-in evidence-log emission. Runs ONLY when
/// `--evidence-log PATH` is supplied. The log destination is never inside
/// the inventoried scope, existing files are never overwritten, and the
/// release package stays read-only. Any emission problem fails closed as
/// E_EVIDENCE_WRITE (never converts FAIL/NOT_RUN into PASS; exit codes
/// keep their existing meaning).
#[allow(clippy::too_many_arguments)]
fn emit_evidence_log(
    dest: &str,
    package_id: &str,
    operator_id: Option<&str>,
    ci_reference: Option<&str>,
    inventory_root: Option<&str>,
    started_secs: Option<u64>,
    rep: &mut Report,
    evaluated: bool,
) {
    let dest_path = PathBuf::from(dest);
    if dest_path.exists() {
        rep.fail(
            "E_EVIDENCE_WRITE",
            format!("refusing to overwrite existing file {:?}", dest_path),
        );
        return;
    }
    // The log must never land inside the inventoried scope (it would
    // perturb the inventory it documents). PHASE 4AU F2: parent resolution
    // goes through evidence_parent_dir so a bare filename resolves against
    // "." instead of becoming the unresolvable "".
    if let Some(root) = inventory_root {
        let parent = ev::evidence_parent_dir(&dest_path);
        match (parent.canonicalize(), Path::new(root).canonicalize()) {
            (Ok(p), Ok(r)) if p.starts_with(&r) || p == r => {
                rep.fail(
                    "E_EVIDENCE_WRITE",
                    "evidence destination inside the inventoried scope (refused)".to_string(),
                );
                return;
            }
            (Err(e), _) | (_, Err(e)) => {
                rep.fail(
                    "E_EVIDENCE_WRITE",
                    format!("cannot prove destination outside inventoried scope: {}", e),
                );
                return;
            }
            _ => {}
        }
    }
    let started = match started_secs {
        Some(s) => s,
        None => {
            rep.fail("E_EVIDENCE_WRITE", "start timestamp unavailable".to_string());
            return;
        }
    };
    let finished = match now_secs() {
        Ok(s) => s,
        Err(e) => {
            rep.fail("E_EVIDENCE_WRITE", e);
            return;
        }
    };
    // PHASE 4AU F4: digest of the exact bytes checked by run() (stored
    // there); no second read of the manifest, so the header cannot bind
    // different bytes than the checks. Falls back to UNAVAILABLE exactly
    // when run() could not read the manifest either.
    let manifest_digest = rep.manifest_bytes.as_deref().map(inv::manifest_digest);
    let exe_sha = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(&b);
            hex::encode(h.finalize())
        });
    let exe_sha = match exe_sha {
        Some(s) => s,
        None => {
            rep.fail("E_EVIDENCE_WRITE", "cannot hash preflight binary".to_string());
            return;
        }
    };
    let run_id = format!("v6ev-{}-{}", finished, std::process::id());
    let input = ev::EvidenceInput {
        run_id,
        package_id: package_id.to_string(),
        manifest_digest,
        inventory_digest: rep.inventory_digest.clone().map(|(d, _)| d),
        binary_name: "v6_preflight".to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        binary_sha256: exe_sha,
        operator_id: operator_id.map(|s| s.to_string()),
        ci_reference: ci_reference.map(|s| s.to_string()),
        started_unix_secs: started,
        finished_unix_secs: finished,
        checks: derive_evidence_checks(rep, evaluated),
        statuses: derive_evidence_statuses(rep, dest),
        retention: ev::pending_retention(dest),
        evaluated,
        preflight_valid: evaluated && !rep.has_failures(),
        governance_note: "V6 activation NOT authorized by this log; seven governance parameters untouched"
            .to_string(),
    };
    let text = match ev::build_log(&input) {
        Ok(t) => t,
        Err(e) => {
            rep.fail("E_EVIDENCE_WRITE", format!("log build failed: {}", e));
            return;
        }
    };
    match ev::write_log_file(&dest_path, &text) {
        Ok(()) => {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(text.as_bytes());
            rep.note(format!("evidence log: {} sha256={}", dest, hex::encode(h.finalize())));
        }
        Err(e) => {
            rep.fail("E_EVIDENCE_WRITE", e);
        }
    }
}

fn main() {
    let mut manifest: Option<String> = None;
    let mut repo = String::from(".");
    // PHASE 4AQ opt-in flags (absent = legacy behavior, no inventory).
    let mut inventory_root: Option<String> = None;
    let mut package_id = String::new();
    let mut expected_digest: Option<String> = None;
    let mut expected_manifest_digest: Option<String> = None;
    let mut inventory_excludes: Vec<String> = Vec::new();
    // PHASE 4AS opt-in flags (absent = legacy behavior, no log).
    let mut evidence_log: Option<String> = None;
    let mut operator_id: Option<String> = None;
    let mut ci_reference: Option<String> = None;
    // Start timestamp for the evidence log (only used when requested).
    let t_start = now_secs().ok();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--manifest" => manifest = args.next(),
            "--repo" => {
                if let Some(r) = args.next() {
                    repo = r;
                }
            }
            "--inventory-root" => inventory_root = args.next(),
            "--package-id" => {
                if let Some(v) = args.next() {
                    package_id = v;
                }
            }
            "--expected-digest" => expected_digest = args.next(),
            "--expected-manifest-digest" => expected_manifest_digest = args.next(),
            "--inventory-exclude" => {
                if let Some(v) = args.next() {
                    inventory_excludes.push(v);
                }
            }
            "--evidence-log" => evidence_log = args.next(),
            "--operator-id" => operator_id = args.next(),
            "--ci-reference" => ci_reference = args.next(),
            "--help" | "-h" => {
                println!("v6-preflight: offline V6 release-manifest pre-verification (dry-run only).");
                println!("usage: v6-preflight --manifest <path> [--repo <path>] [--inventory-root <dir> --package-id <id> --expected-digest <hex> --expected-manifest-digest <hex> --inventory-exclude <glob>]... [--evidence-log <path> --operator-id <id> --ci-reference <ref>]...");
                println!("Reads only. Exit 0 = all checks pass; 1 = checks failed; 2 = manifest unusable.");
                println!("{}", SCOPE_NOTE);
                return;
            }
            other => {
                eprintln!("unknown argument (no activate/deploy/publish/start-network subcommands exist): {}", other);
                std::process::exit(2);
            }
        }
    }
    let manifest_path = match manifest {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("E_INPUT_MISSING: --manifest <path> is required");
            std::process::exit(2);
        }
    };
    let mut rep = Report::new();
    let evaluated = run(&manifest_path, Path::new(&repo), &mut rep);
    // PHASE 4AQ: additive inventory evidence (opt-in only).
    if let Some(root) = inventory_root.as_deref() {
        check_inventory_opt(
            root,
            &package_id,
            expected_digest.as_deref(),
            expected_manifest_digest.as_deref(),
            &manifest_path,
            &inventory_excludes,
            &mut rep,
        );
    }
    // PHASE 4AS: additive evidence log (opt-in only; verdicts A-G below are
    // printed unchanged, exit codes keep their existing meaning).
    if let Some(dest) = evidence_log.as_deref() {
        emit_evidence_log(
            dest,
            &package_id,
            operator_id.as_deref(),
            ci_reference.as_deref(),
            inventory_root.as_deref(),
            t_start,
            &mut rep,
            evaluated,
        );
    }
    print_verdicts(&rep, evaluated);
    if !evaluated {
        std::process::exit(2);
    }
    if rep.has_failures() {
        std::process::exit(1);
    }
}

#[allow(dead_code)]
fn _use_types() {
    // Keep imports referenced under all feature sets.
    let _ = std::mem::size_of::<StakeRegistry>();
    let _ = std::mem::size_of::<Vote>();
}

#[cfg(test)]
mod path_tests {
    use super::validate_artifact_path;

    #[test]
    fn legitimate_relative_paths_accepted() {
        for good in [
            "artifact.bin",
            "sub/dir/file.bin",
            "a/./b.bin",
            ".hidden",
            "deep/nested/ok.dat",
        ] {
            assert!(validate_artifact_path(good).is_ok(), "must accept {:?}", good);
        }
    }

    #[test]
    fn posix_absolute_and_parent_rejected() {
        for bad in ["/abs.bin", "/etc/passwd", "../outside.bin", "sub/../../outside.bin", "//server/share.bin"] {
            assert!(validate_artifact_path(bad).is_err(), "must reject {:?}", bad);
        }
    }

    #[test]
    fn windows_drive_forms_rejected() {
        // Host-independent: lexical rules, never Path semantics.
        for bad in [
            "C:\\outside.bin",
            "C:/outside.bin",
            "C:outside.bin",
            "c:\\x\\y.bin",
            "D:/artifact.bin",
        ] {
            assert!(validate_artifact_path(bad).is_err(), "must reject {:?}", bad);
        }
    }

    #[test]
    fn windows_unc_device_rooted_rejected() {
        for bad in [
            "\\\\server\\share\\artifact.bin",
            "\\\\?\\C:\\artifact.bin",
            "\\\\.\\C:\\artifact.bin",
            "\\rooted.bin",
        ] {
            assert!(validate_artifact_path(bad).is_err(), "must reject {:?}", bad);
        }
    }

    #[test]
    fn backslash_and_mixed_traversal_rejected() {
        for bad in [
            "..\\outside.bin",
            "sub\\..\\..\\outside.bin",
            "../..\\outside.bin",
            "..\\/../outside.bin",
            "sub/..\\outside.bin",
        ] {
            assert!(validate_artifact_path(bad).is_err(), "must reject {:?}", bad);
        }
    }

    #[test]
    fn empty_and_dot_segments_rejected_or_safe() {
        assert!(validate_artifact_path("").is_err(), "empty path rejected");
        // A lone ".." is a traversal attempt, not a file.
        assert!(validate_artifact_path("..").is_err());
    }
}
