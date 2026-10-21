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
use aether_unified::inventory::{
    normalize_relative_path, verify_release_inventory, walk_release_root,
};
use aether_unified::stake::{StakeRegistry, ValidatorRecord};
use aether_unified::transaction::Vote;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const TOOL_MANIFEST_FORMAT: u64 = 1;
const HISTORICAL_TAG: &str = "v1.4.0-testnet";
const HISTORICAL_COMMIT: &str = "ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316";

const SCOPE_NOTE: &str = "SCOPE: this tool checks manifest coherence only (formats, recomputation, local git objects, file hashes; optional release-root inventory). It cannot prove value authenticity or governance authority: provenance must be confirmed out of band.";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    code: &'static str,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryStatus {
    NotRun,
    Pass,
    Fail,
}

struct InventoryOptions {
    root: PathBuf,
    excludes: Vec<String>,
}

struct Report {
    errors: Vec<Finding>,
    notes: Vec<String>,
    inventory: InventoryStatus,
}

impl Report {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            notes: Vec::new(),
            inventory: InventoryStatus::NotRun,
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
    let bytes = match std::fs::read(&full) {
        Ok(b) => b,
        Err(e) => {
            rep.fail("E_ARTIFACT_MISSING", format!("artifact {:?} unreadable: {}", art.path, e));
            return;
        }
    };
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&bytes);
    let got = hex::encode(hasher.finalize());
    if got != art.sha256.to_lowercase() {
        rep.fail(
            "E_ARTIFACT_CHECKSUM",
            format!("artifact {:?} checksum mismatch (manifest declares {}, file is {})", art.path, art.sha256, got),
        );
    }
}

fn check_inventory(opts: &InventoryOptions, artifacts: &[Artifact], rep: &mut Report) {
    let inventory = match walk_release_root(&opts.root, &opts.excludes, None) {
        Ok(inv) => inv,
        Err(e) => {
            rep.inventory = InventoryStatus::Fail;
            rep.fail(
                "E_INVENTORY_WALK",
                format!("inventory root {:?} unusable: {}", opts.root, e),
            );
            return;
        }
    };
    let mut expected: Vec<(String, String)> = Vec::new();
    for art in artifacts {
        match normalize_relative_path(&art.path) {
            Ok(path) => expected.push((path, art.sha256.clone())),
            Err(e) => {
                rep.inventory = InventoryStatus::Fail;
                rep.fail(
                    "E_INVENTORY_PATH",
                    format!("artifact {:?} cannot be normalized: {}", art.path, e),
                );
                return;
            }
        }
    }
    match verify_release_inventory(&inventory, &expected, &[]) {
        Ok(()) => {
            rep.inventory = InventoryStatus::Pass;
            rep.note(format!(
                "inventory verified: {} entries against {} declared artifact(s)",
                inventory.entries.len(),
                expected.len()
            ));
        }
        Err(e) => {
            rep.inventory = InventoryStatus::Fail;
            rep.fail("E_INVENTORY_VERIFY", e);
        }
    }
}

fn run(
    manifest_path: &Path,
    repo: &Path,
    inventory: Option<&InventoryOptions>,
    require_inventory: bool,
    rep: &mut Report,
) -> bool {
    // Returns true when evaluation completed (even with failures).
    let text = match std::fs::read_to_string(manifest_path) {
        Ok(t) => t,
        Err(e) => {
            rep.fail("E_INPUT_UNREADABLE", format!("cannot read manifest: {}", e));
            return false;
        }
    };
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
    if m.format != TOOL_MANIFEST_FORMAT {
        rep.fail(
            "E_INPUT_FORMAT",
            format!("manifest format {} != tool format {}", m.format, TOOL_MANIFEST_FORMAT),
        );
        return false;
    }
    if require_inventory && inventory.is_none() {
        rep.inventory = InventoryStatus::Fail;
        rep.fail(
            "E_INVENTORY_CONFIG",
            "--require-inventory needs an explicit --inventory-root (no implicit release root is assumed)".to_string(),
        );
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
    if let Some(opts) = inventory {
        check_inventory(opts, &m.artifacts, rep);
    } else if !require_inventory {
        rep.note(
            "inventory checks not requested: NOT_RUN (no implicit release root or gate invented)"
                .to_string(),
        );
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
    println!(
        "H INVENTORY_CHECKS: {}",
        match rep.inventory {
            InventoryStatus::NotRun => "NOT_RUN",
            InventoryStatus::Pass => "PASS",
            InventoryStatus::Fail => "FAIL",
        }
    );
    println!("{}", SCOPE_NOTE);
    for f in &rep.errors {
        println!("{}: {}", f.code, f.detail);
    }
    for n in &rep.notes {
        println!("note: {}", n);
    }
}

fn main() {
    let mut manifest: Option<String> = None;
    let mut repo = String::from(".");
    let mut inventory_root: Option<String> = None;
    let mut inventory_excludes: Vec<String> = Vec::new();
    let mut require_inventory = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--manifest" => manifest = args.next(),
            "--repo" => {
                if let Some(r) = args.next() {
                    repo = r;
                }
            }
            "--inventory-root" => match args.next() {
                Some(r) => inventory_root = Some(r),
                None => {
                    eprintln!("E_INPUT_MISSING: --inventory-root requires a path");
                    std::process::exit(2);
                }
            },
            "--inventory-exclude" => match args.next() {
                Some(g) => inventory_excludes.push(g),
                None => {
                    eprintln!("E_INPUT_MISSING: --inventory-exclude requires a glob");
                    std::process::exit(2);
                }
            },
            "--require-inventory" => require_inventory = true,
            "--help" | "-h" => {
                println!("v6-preflight: offline V6 release-manifest pre-verification (dry-run only).");
                println!("usage: v6-preflight --manifest <path> [--repo <path>] [--inventory-root <path>] [--inventory-exclude <glob>]... [--require-inventory]");
                println!("Reads only. Exit 0 = all checks pass; 1 = checks failed; 2 = manifest unusable.");
                println!("The inventory gate is opt-in: without --inventory-root it reports NOT_RUN and does not invent a release root.");
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
    if inventory_root.is_none() && !inventory_excludes.is_empty() {
        eprintln!("E_INVENTORY_CONFIG: --inventory-exclude requires --inventory-root");
        std::process::exit(2);
    }
    let inventory = inventory_root.map(|root| InventoryOptions {
        root: PathBuf::from(root),
        excludes: inventory_excludes,
    });
    let mut rep = Report::new();
    let evaluated = run(
        &manifest_path,
        Path::new(&repo),
        inventory.as_ref(),
        require_inventory,
        &mut rep,
    );
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
