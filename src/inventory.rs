//! PHASE 4AQ: deterministic release-artifact inventory (F4AN-1).
//!
//! Implements the F4AN-1 design from
//! `docs/AETHER_PHASE4AN_OPERATIONAL_EVIDENCE_DESIGN.md`, section 3 only.
//! Offline and read-only: this module only reads the filesystem (walk,
//! metadata, file bytes, link targets). It never writes, never follows a
//! symlink for content, never contacts the network, never activates V6.
//!
//! Contract applied (4AN D1-D5):
//! 1. Recursive walk of an explicit RELEASE_ROOT minus an explicit
//!    exclusion allowlist (no implicit skips).
//! 2. Deterministic order: records sorted by byte-wise lexicographic order
//!    of the UTF-8 normalized path. Walk order cannot affect output.
//! 3. Relative paths are normalized with host path semantics and `/`
//!    separators; a literal backslash in a Unix filename is preserved.
//! 4. Symlinks are NEVER followed for content. Each symlink is recorded
//!    with its stored target string; targets escaping the root are flagged
//!    `external-link`. Dereferencing through a symlink is forbidden here.
//! 5. Special files, case collisions, hardlink groups, duplicates and
//!    unreadable entries are signalled explicitly, never skipped silently.
//! 6. T0/T1 comparison yields missing / unexpected / changed-binding.
//! 7. Canonical record: `<hash> <kind> <size> <mode> <path>` (LF only).
//! 8. INVENTORY_DIGEST = SHA-256 over the canonical byte stream.
//! 9. Binding triple PACKAGE_ID + MANIFEST_DIGEST + INVENTORY_DIGEST.
//!
//! Serialization gaps fixed BEFORE implementation (no silent change of the
//! `hash kind size mode path` representation):
//! G1. Paths containing `\n` or `\r` are UNSUPPORTED: LF-delimited stream
//!     cannot represent them unambiguously. They become `unreadable`
//!     entries with reason `unsupported-newline-in-path` (explicit refusal).
//! G2. Non-UTF-8 paths are UNSUPPORTED on this version: they become
//!     `unreadable` entries with reason `non-utf8-path` (explicit refusal,
//!     never lossy replacement inside the digest).
//! G3. Unicode NFC is NOT applied (no normalization dependency vendored):
//!     paths are preserved byte-identical, case preserved exactly. The
//!     case-fold key uses `char::to_lowercase` (documented approximation of
//!     simple case folding). Recorded limitation, not a silent match.
//! G4. Mode token is a fixed per-kind token for portability (permission
//!     bits excluded): `f` file, `d` dir, `l` symlink, `s` special
//!     (`s:<subtype>` on unix where known: fifo/socket/block/char/other),
//!     `u` unreadable. No permission-bit comparison across OSes.
//! G5. Content hash field: file = 64 lowercase hex of SHA-256(file bytes);
//!     dir = `none`; symlink = `link:<hex>` where hex is SHA-256 over the
//!     stored target string bytes (UTF-8, unresolved); special = `none`;
//!     unreadable = `none`.
//! G6. Spaces in paths are ALLOWED: the canonical line is parsed with
//!     `splitn(5)` (first four spaces delimit; remainder is the path).
//! G7. Exclusion allowlist uses a minimal glob: `*` matches any sequence
//!     (including `/`), `?` matches exactly one char, all else literal.
//!     Documented in `matches_exclusion`.
//! G8. Hardlink identity: full on unix (dev+ino); on Windows via native
//!     GetFileInformationByHandle on the open handle (4BB, option B:
//!     windows-sys 0.61.2, Windows-only, minimal features): identity key
//!     (volume serial, 64-bit file index), link count for
//!     exterior-reference detection. API failure or zero index (FAT/exFAT/
//!     network shares) stays per-file UNAVAILABLE with an explicit reason:
//!     `hardlink-detection=unavailable-on-windows:<reason>`.
//! G9. Unreadable OS error text is kept in sidecar diagnostics
//!     (`diagnostics: Vec<String>`), NOT in the hashed canonical line, so
//!     the digest stays stable across hosts/locales. Presence of any
//!     unreadable entry still fails verification (INCOMPLETE).
//!
//! What this module does NOT prove (stated limits, 4AN 3.3):
//! - Exhaustiveness of the CHOSEN scope (an omitted directory is invisible).
//! - Hidden mounts/views or privileged hiding.
//! - Transient create-delete between T0 and T1, or mutation DURING a walk
//!   (TOCTOU, subject of F4AN-2, not F4AN-1).
//! - Authenticity/provenance (hashes prove WHAT, not WHO; no signature here).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};

/// Entry kind, serialized as `file|dir|symlink|special|unreadable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
    Special,
    Unreadable,
}

impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
            EntryKind::Symlink => "symlink",
            EntryKind::Special => "special",
            EntryKind::Unreadable => "unreadable",
        }
    }
}

/// One canonical inventory record plus machine-readable flags.
/// `diagnostic` carries human context (symlink target, special subtype,
/// unreadable reason, collision flags). It is NOT hashed (see G9), except
/// for the symlink-target hash which IS bound via the `link:<hex>` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    /// Normalized relative path (`/` separators, case preserved).
    pub normalized_path: String,
    pub kind: EntryKind,
    /// File byte length; 0 for non-files.
    pub size: u64,
    /// Normalized mode token (G4).
    pub mode: String,
    /// Content binding (G5).
    pub content_hash: String,
    /// Non-hashed flags, e.g. `external-link`, `case-collision:<other>`,
    /// `hardlink-group:<id>`, `special:<subtype>`, `unreadable:<reason>`.
    pub flags: Vec<String>,
    /// Non-hashed diagnostic detail (OS error text, target string, ...).
    pub diagnostic: String,
}

/// Warnings that do not fail the walk but must be surfaced.
#[derive(Debug, Clone, Default)]
pub struct WalkWarnings {
    pub case_collisions: Vec<String>,
    pub external_links: Vec<String>,
    pub specials: Vec<String>,
    pub unreadables: Vec<String>,
    pub hardlink_groups: Vec<String>,
    /// System link counts above in-scope references (Unix metadata and
    /// Windows native identity). Entries are
    /// `exterior:<id>:links=<n>:found=<m>` (no exclusions: the surplus is
    /// necessarily outside the scope) or
    /// `ambiguous:<id>:links=<n>:found=<m>:exclusions-present` (excluded
    /// paths may explain the gap; NOT claimed exterior). Sorted.
    pub external_link_refs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Inventory {
    pub entries: Vec<InventoryEntry>,
    pub warnings: WalkWarnings,
    /// Per-entry diagnostics in walk order (same length as entries).
    pub diagnostics: Vec<String>,
}

/// Minimal glob: `*` = any sequence (incl `/`), `?` = one char.
pub fn matches_exclusion(pattern: &str, path: &str) -> bool {
    let pb = pattern.as_bytes();
    let sb = path.as_bytes();
    let (mut i, mut j) = (0usize, 0usize);
    let mut star_i: Option<usize> = None;
    let mut star_j = 0usize;
    while j < sb.len() {
        if i < pb.len() && (pb[i] == b'?' || pb[i] == sb[j]) {
            i += 1;
            j += 1;
        } else if i < pb.len() && pb[i] == b'*' {
            star_i = Some(i);
            star_j = j;
            i += 1;
        } else if let Some(si) = star_i {
            i = si + 1;
            star_j += 1;
            j = star_j;
        } else {
            return false;
        }
    }
    while i < pb.len() && pb[i] == b'*' {
        i += 1;
    }
    i == pb.len()
}

fn normalize_relative(rel: &Path) -> Result<String, String> {
    // Use the host path parser instead of a blind `\` -> `/` replacement:
    // on Unix a backslash is a legal literal filename character, so rewriting
    // it would invent a different path and could collide with `a/b`.
    let mut parts: Vec<&str> = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| "non-utf8-path".to_string())?;
                if part.is_empty() {
                    return Err("empty-component".to_string());
                }
                parts.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir => return Err("parent-traversal".to_string()),
            Component::RootDir | Component::Prefix(_) => {
                return Err("absolute-path".to_string())
            }
        }
    }
    if parts.is_empty() {
        return Err("empty-path".to_string());
    }
    let out = parts.join("/");
    if out.contains('\n') || out.contains('\r') {
        return Err("unsupported-newline-in-path".to_string());
    }
    Ok(out)
}

/// Public form of the inventory path normalizer. Manifest paths are lexical
/// strings; consumers that compare them with walked entries must apply the
/// same host semantics (`.`, repeated separators, Windows separators) first.
pub fn normalize_relative_path(path: &str) -> Result<String, String> {
    normalize_relative(Path::new(path))
}

/// Stable text binding for a symlink's stored target. On Unix a backslash is
/// a literal target character and must not be rewritten; on Windows it is a
/// separator and is normalized to `/` for a host-stable representation.
fn link_target_text(target: &Path) -> String {
    #[cfg(windows)]
    {
        target.to_string_lossy().replace('\\', "/")
    }
    #[cfg(not(windows))]
    {
        target.to_string_lossy().into_owned()
    }
}

/// Deterministic, newline-free placeholder for a path that cannot enter the
/// canonical stream. The raw OS bytes are hashed so non-UTF-8 names do not
/// collapse to the same lossy string; the result never contains LF/CR.
fn unreadable_placeholder(rel: &Path) -> String {
    #[cfg(unix)]
    let raw = {
        use std::os::unix::ffi::OsStrExt;
        rel.as_os_str().as_bytes().to_vec()
    };
    #[cfg(windows)]
    let raw = {
        use std::os::windows::ffi::OsStrExt;
        rel.as_os_str()
            .encode_wide()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<u8>>()
    };
    #[cfg(not(any(unix, windows)))]
    let raw = rel.to_string_lossy().as_bytes().to_vec();
    format!("unreadable:{}", sha_hex(&raw))
}

fn case_fold_key(s: &str) -> String {
    s.chars().flat_map(|c| c.to_lowercase()).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// --- PHASE 4AR (F4AN-2): handle-bound identity and integrity ---------------
//
// mtime and size are NEVER accepted as proof (4AN 4.1): they are forgeable,
// coarse and collision-prone. The proof is SHA-256 over the bytes read FROM
// the open handle, plus a handle-vs-path identity comparison before and
// after the read. Any divergence or error refuses the file explicitly.
//
// * Unix (std only, no new dependency): object key = `dev:ino` via
//   `MetadataExt`; size/mode are consistency signals beside it.
// * Windows (stable std only): no file-index/volume API exists in the
//   installed toolchain, so identity is BEST-EFFORT
//   (`attributes:size:creation:lastwrite`); a same-size same-timestamp
//   swap can pass the identity check and is only caught by a second
//   controlled read (O4) or not at all -- documented, never hidden.
//   `identity_best_effort == true` marks every Windows result.
// * `File::open` follows a trailing symlink: the caller must have classified
//   the path as a regular file via `symlink_metadata` first, and the
//   post-read check requires the path to STILL resolve to a regular file,
//   so a metadata->open symlink swap is detected (refused), though not
//   prevented (no O_NOFOLLOW in stable std without a new libc dependency;
//   adding one was explicitly out of scope: see report 4AR).
// * A second controlled read (O4, `read_file_stable_2x`) NARROWS the
//   stale-hash window for sensitive files; it does NOT eliminate TOCTOU.

/// Bytes read from one open handle plus the handle-bound identity.
#[derive(Debug)]
pub struct HandleRead {
    pub bytes: Vec<u8>,
    /// Full identity string (object key + size), handle-bound.
    pub identity: String,
    /// True where the identity is best-effort only (Windows stable std).
    pub identity_best_effort: bool,
    /// Native Windows physical identity from the SAME open handle (4BB).
    /// None on non-Windows builds. Ok = (volume, index, link count);
    /// Err(reason) = explicit per-file UNAVAILABLE, never silent.
    #[cfg(windows)]
    pub win_physical: Result<WinPhysicalId, String>,
}

/// Native Windows physical file identity (4BB, option B): volume serial +
/// 64-bit file index + link count from GetFileInformationByHandle.
/// Grouping key = (volume, index). `nlinks` enables exterior-reference
/// detection (system count vs in-scope reference count).
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinPhysicalId {
    pub volume: u32,
    pub index: u64,
    pub nlinks: u32,
}

/// Query the native identity FROM an open handle (4BB). No extra open, no
/// path re-resolution: the caller passes its live `File`.
#[cfg(windows)]
fn win_physical_id(file: &std::fs::File) -> Result<WinPhysicalId, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY (4BB, reviewed scope): `file` is a live open File borrowed
    // for this call only. `as_raw_handle` is a borrowed handle: never
    // stored, never closed, never transferred. `info` is a valid zeroed
    // BY_HANDLE_FILE_INFORMATION buffer owned by this frame, written only
    // by the kernel during the call. The return value is checked (0 =
    // failure => no identity claimed). No lifetime is extended and no
    // hand-rolled ABI types are used (struct + signature from
    // windows-sys, the approved minimal dependency).
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // HANDLE is *mut c_void on both msvc and gnu targets: RawHandle converts.
    let ok =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return Err("GetFileInformationByHandle failed".to_string());
    }
    let index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
    if index == 0 {
        // FAT/exFAT/network filesystems expose no stable file index:
        // explicit per-file UNAVAILABLE, never a PASS.
        return Err("no-stable-index".to_string());
    }
    Ok(WinPhysicalId {
        volume: info.dwVolumeSerialNumber,
        index,
        nlinks: info.nNumberOfLinks,
    })
}

/// Platform object key WITHOUT size (stable across appends/truncates of the
/// same object; changes on delete+recreate / rename swap).
#[cfg(unix)]
fn object_key(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{}:{}", meta.dev(), meta.ino())
}

/// Best-effort object key on Windows stable std (no file index available).
/// Creation time changes on delete+recreate in practice, but it is NOT a
/// kernel object id: documented approximation (see module header).
#[cfg(windows)]
fn object_key(meta: &std::fs::Metadata) -> String {
    use std::os::windows::fs::MetadataExt;
    format!("{}:{}", meta.file_attributes(), meta.creation_time())
}

#[cfg(unix)]
fn full_identity(meta: &std::fs::Metadata) -> (String, bool) {
    use std::os::unix::fs::MetadataExt;
    (format!("{}:{}:{}", meta.dev(), meta.ino(), meta.size()), false)
}

#[cfg(windows)]
fn full_identity(meta: &std::fs::Metadata) -> (String, bool) {
    use std::os::windows::fs::MetadataExt;
    (
        format!(
            "{}:{}:{}:{}",
            meta.file_attributes(),
            meta.file_size(),
            meta.creation_time(),
            meta.last_write_time()
        ),
        true,
    )
}

#[cfg(not(any(unix, windows)))]
fn object_key(_meta: &std::fs::Metadata) -> String {
    "unknown-platform".to_string()
}

#[cfg(not(any(unix, windows)))]
fn full_identity(_meta: &std::fs::Metadata) -> (String, bool) {
    ("unknown-platform".to_string(), true)
}

/// Open `abs` and read its content FROM the open handle; verify the handle
/// against the pre-open classification and re-verify the path afterwards.
/// `pre_meta` must be a fresh `symlink_metadata` the caller took: the path
/// must classify as a regular file there, and must STILL do so after the
/// read. Read-only; no writes, no network.
pub fn read_file_via_handle(
    abs: &Path,
    pre_meta: &std::fs::Metadata,
) -> Result<HandleRead, String> {
    use std::io::Read;
    if !pre_meta.file_type().is_file() {
        return Err("identity-precondition: not a regular file".to_string());
    }
    let pre_key = object_key(pre_meta);
    let mut file =
        std::fs::File::open(abs).map_err(|e| format!("open failed: {}", e))?;
    let hmeta = file
        .metadata()
        .map_err(|e| format!("handle metadata failed: {}", e))?;
    if !hmeta.file_type().is_file() {
        return Err("identity-diverged: handle is not a regular file".to_string());
    }
    if object_key(&hmeta) != pre_key {
        return Err(format!(
            "identity-diverged: path re-bound between stat and open (object key changed)"
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("handle read failed: {}", e))?;
    let (identity, best_effort) = full_identity(&hmeta);
    // Post-verify: the PATH must still resolve to the same object, and the
    // object size must match what the handle reported (catches
    // delete+recreate, rename swap, symlink swap, truncation/extension).
    let post_meta = std::fs::symlink_metadata(abs)
        .map_err(|e| format!("post-verification: path vanished or unreadable: {}", e))?;
    if !post_meta.file_type().is_file() {
        return Err(
            "identity-diverged: path is no longer a regular file after read".to_string(),
        );
    }
    if object_key(&post_meta) != object_key(&hmeta) {
        return Err(
            "identity-diverged: path resolves to a different object after read (replaced)"
                .to_string(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if post_meta.size() != hmeta.size() || bytes.len() as u64 != hmeta.size() {
            return Err("content-unstable: size changed during handle read".to_string());
        }
    }
    #[cfg(not(unix))]
    {
        if bytes.len() as u64 != hmeta.len() {
            return Err("content-unstable: size changed during handle read".to_string());
        }
        let (post_id, _) = full_identity(&post_meta);
        if post_id != identity {
            return Err(
                "identity-diverged: path metadata changed during handle read".to_string(),
            );
        }
    }
    // 4BB: native identity from the SAME open handle (no extra open).
    #[cfg(windows)]
    let win_physical = win_physical_id(&file);
    Ok(HandleRead {
        bytes,
        identity,
        identity_best_effort: best_effort,
        #[cfg(windows)]
        win_physical,
    })
}

/// Second controlled read for SENSITIVE files (4AN O4): re-reads from the
/// SAME open handle (seek(0), no path re-resolution) and requires
/// byte-equality. Detects tearing/mutation between two passes; does NOT
/// prove absence of TOCTOU races (a change before the first read, or after
/// the second, is out of view by construction).
pub fn read_file_stable_2x(abs: &Path) -> Result<HandleRead, String> {
    use std::io::{Read, Seek};
    let pre_meta =
        std::fs::symlink_metadata(abs).map_err(|e| format!("open failed: {}", e))?;
    if !pre_meta.file_type().is_file() {
        return Err("identity-precondition: not a regular file".to_string());
    }
    let pre_key = object_key(&pre_meta);
    let mut file =
        std::fs::File::open(abs).map_err(|e| format!("open failed: {}", e))?;
    let hmeta = file
        .metadata()
        .map_err(|e| format!("handle metadata failed: {}", e))?;
    if !hmeta.file_type().is_file() || object_key(&hmeta) != pre_key {
        return Err("identity-diverged: path re-bound between stat and open".to_string());
    }
    let mut first = Vec::new();
    file.read_to_end(&mut first)
        .map_err(|e| format!("handle read failed: {}", e))?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| format!("handle seek failed: {}", e))?;
    let mut second = Vec::new();
    file.read_to_end(&mut second)
        .map_err(|e| format!("handle second read failed: {}", e))?;
    if first != second {
        return Err("content-unstable: two handle reads disagree".to_string());
    }
    let (identity, best_effort) = full_identity(&hmeta);
    let post_meta = std::fs::symlink_metadata(abs)
        .map_err(|e| format!("post-verification: path vanished or unreadable: {}", e))?;
    if !post_meta.file_type().is_file() || object_key(&post_meta) != object_key(&hmeta) {
        return Err("identity-diverged: path resolves elsewhere after read".to_string());
    }
    #[cfg(windows)]
    let win_physical = win_physical_id(&file);
    Ok(HandleRead {
        bytes: first,
        identity,
        identity_best_effort: best_effort,
        #[cfg(windows)]
        win_physical,
    })
}

/// Walk RELEASE_ROOT without following symlinks. Read-only.
pub fn walk_release_root(
    root: &Path,
    exclusions: &[String],
    max_depth: Option<usize>,
) -> Result<Inventory, String> {
    let canon_root = root
        .canonicalize()
        .map_err(|e| format!("release root unresolvable: {}", e))?;
    let mut entries: Vec<InventoryEntry> = Vec::new();
    let mut warnings = WalkWarnings::default();
    let mut diagnostics: Vec<String> = Vec::new();
    // Stack of (absolute path, relative path, depth).
    let mut stack: Vec<(PathBuf, PathBuf, usize)> = vec![(canon_root.clone(), PathBuf::new(), 0)];
    // For duplicate-path detection (should not happen from a single walk,
    // but enforced per 4AN D2).
    let mut seen: HashMap<String, usize> = HashMap::new();

    while let Some((abs, rel, depth)) = stack.pop() {
        if let Some(limit) = max_depth {
            if depth > limit {
                return Err(format!("depth-limit-reached at {:?}", rel));
            }
        }
        // The root itself is not recorded as an entry (only its children);
        // subdirectories ARE recorded.
        let meta = std::fs::symlink_metadata(&abs)
            .map_err(|e| format!("metadata failed for {:?}: {}", abs, e))?;
        if depth > 0 {
            let norm = match normalize_relative(&rel) {
                Ok(n) => n,
                Err(reason) => {
                    let p = unreadable_placeholder(&rel);
                    entries.push(InventoryEntry {
                        normalized_path: p.clone(),
                        kind: EntryKind::Unreadable,
                        size: 0,
                        mode: "u".to_string(),
                        content_hash: "none".to_string(),
                        flags: vec![format!("unreadable:{}", reason)],
                        diagnostic: reason.clone(),
                    });
                    if seen.insert(p.clone(), entries.len() - 1).is_some() {
                        return Err(format!("duplicate-path: {}", p));
                    }
                    warnings.unreadables.push(p.clone());
                    diagnostics.push(format!("{}: {}", p, reason));
                    continue;
                }
            };
            if exclusions.iter().any(|g| matches_exclusion(g, &norm)) {
                continue;
            }
            let ft = meta.file_type();
            if ft.is_symlink() {
                // Keep the native PathBuf for resolution; target_str is only
                // the stable diagnostic/hash representation.
                let target = std::fs::read_link(&abs);
                let target_str = target
                    .as_ref()
                    .map(|p| link_target_text(p))
                    .unwrap_or_else(|e| format!("<read-link-failed:{}>", e));
                let hex = sha_hex(target_str.as_bytes());
                // Classify by the resolved destination, not lexical spelling:
                // an absolute target (or one containing `..`) may still resolve
                // inside RELEASE_ROOT. Symlinks are never followed for content.
                let mut is_external = false;
                if let (Some(parent), Ok(target)) = (abs.parent(), target.as_ref()) {
                    let cand = parent.join(target);
                    if let (Ok(r), Ok(t)) = (canon_root.canonicalize(), cand.canonicalize()) {
                        is_external = !t.starts_with(&r);
                    }
                    // If resolution fails, leave classification to the explicit
                    // dangling-target check below; do not guess externality.
                }
                // Dangling detection (best effort, no follow for content).
                let dangling = target
                    .as_ref()
                    .map(|t| {
                        let cand = abs.parent().map(|p| p.join(t)).unwrap_or_else(|| t.clone());
                        cand.symlink_metadata().is_err()
                    })
                    .unwrap_or(true);
                let mut flags = Vec::new();
                if is_external {
                    flags.push("external-link".to_string());
                    warnings.external_links.push(norm.clone());
                }
                if dangling {
                    flags.push("dangling-target".to_string());
                }
                entries.push(InventoryEntry {
                    normalized_path: norm.clone(),
                    kind: EntryKind::Symlink,
                    size: 0,
                    mode: "l".to_string(),
                    content_hash: format!("link:{}", hex),
                    flags,
                    diagnostic: format!("target={}", target_str),
                });
                if let Some(prev) = seen.insert(norm.clone(), entries.len() - 1) {
                    let _ = prev;
                    return Err(format!("duplicate-path: {}", norm));
                }
                continue;
            } else if ft.is_dir() {
                entries.push(InventoryEntry {
                    normalized_path: norm.clone(),
                    kind: EntryKind::Dir,
                    size: 0,
                    mode: "d".to_string(),
                    content_hash: "none".to_string(),
                    flags: Vec::new(),
                    diagnostic: String::new(),
                });
                if seen.insert(norm.clone(), entries.len() - 1).is_some() {
                    return Err(format!("duplicate-path: {}", norm));
                }
                // Recurse (depth-first; order normalized later by sort).
                let rd = match std::fs::read_dir(&abs) {
                    Ok(r) => r,
                    Err(e) => {
                        entries.push(InventoryEntry {
                            normalized_path: norm.clone(),
                            kind: EntryKind::Unreadable,
                            size: 0,
                            mode: "u".to_string(),
                            content_hash: "none".to_string(),
                            flags: vec![format!("unreadable:readdir:{}", e)],
                            diagnostic: format!("readdir failed: {}", e),
                        });
                        warnings.unreadables.push(norm.clone());
                        continue;
                    }
                };
                let mut children: Vec<(PathBuf, PathBuf)> = Vec::new();
                for e in rd {
                    match e {
                        Ok(en) => {
                            let name = en.file_name();
                            children.push((en.path(), rel.join(name)));
                        }
                        Err(e) => {
                            entries.push(InventoryEntry {
                                normalized_path: norm.clone(),
                                kind: EntryKind::Unreadable,
                                size: 0,
                                mode: "u".to_string(),
                                content_hash: "none".to_string(),
                                flags: vec![format!("unreadable:readdir-entry:{}", e)],
                                diagnostic: format!("readdir entry failed: {}", e),
                            });
                            warnings.unreadables.push(norm.clone());
                        }
                    }
                }
                for (c_abs, c_rel) in children {
                    stack.push((c_abs, c_rel, depth + 1));
                }
                continue;
            } else if ft.is_file() {
                // PHASE 4AR (F4AN-2): hash the bytes read FROM the open
                // handle with pre/post identity verification. mtime is never
                // consulted; size is only a consistency signal inside the
                // handle diagnosis. Any divergence refuses the file.
                let dread = match read_file_via_handle(&abs, &meta) {
                    Ok(r) => r,
                    Err(e) => {
                        entries.push(InventoryEntry {
                            normalized_path: norm.clone(),
                            kind: EntryKind::Unreadable,
                            size: 0,
                            mode: "u".to_string(),
                            content_hash: "none".to_string(),
                            flags: vec![format!("unreadable:{}", e)],
                            diagnostic: e.clone(),
                        });
                        warnings.unreadables.push(norm.clone());
                        diagnostics.push(format!("{}: {}", norm, e));
                        continue;
                    }
                };
                let bytes = dread.bytes;
                // Hardlink identity (unix: dev+ino; windows: native
                // volume+index from the SAME open handle, 4BB option B).
                let mut flags = Vec::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let id = format!("{}:{}", meta.dev(), meta.ino());
                    flags.push(format!("hardlink-id:{}", id));
                    flags.push(format!("hardlink-nlinks:{}", meta.nlink()));
                }
                #[cfg(windows)]
                {
                    match &dread.win_physical {
                        Ok(id) => {
                            flags.push(format!("hardlink-id:{}:{}", id.volume, id.index));
                            flags.push(format!("hardlink-nlinks:{}", id.nlinks));
                        }
                        Err(reason) => {
                            flags.push(format!(
                                "hardlink-detection=unavailable-on-windows:{}",
                                reason
                            ));
                        }
                    }
                }
                entries.push(InventoryEntry {
                    normalized_path: norm.clone(),
                    kind: EntryKind::File,
                    size: bytes.len() as u64,
                    mode: "f".to_string(),
                    content_hash: sha_hex(&bytes),
                    flags,
                    diagnostic: String::new(),
                });
                if seen.insert(norm.clone(), entries.len() - 1).is_some() {
                    return Err(format!("duplicate-path: {}", norm));
                }
                continue;
            } else {
                // Special file (fifo/socket/device/other). Never hashed.
                #[cfg(unix)]
                let subtype = {
                    use std::os::unix::fs::FileTypeExt;
                    if ft.is_fifo() {
                        "fifo"
                    } else if ft.is_socket() {
                        "socket"
                    } else if ft.is_block_device() {
                        "block"
                    } else if ft.is_char_device() {
                        "char"
                    } else {
                        "other"
                    }
                };
                #[cfg(not(unix))]
                let subtype = "other";
                entries.push(InventoryEntry {
                    normalized_path: norm.clone(),
                    kind: EntryKind::Special,
                    size: 0,
                    mode: format!("s:{}", subtype),
                    content_hash: "none".to_string(),
                    flags: vec!["special".to_string()],
                    diagnostic: format!("special:{}", subtype),
                });
                warnings.specials.push(norm.clone());
                if seen.insert(norm.clone(), entries.len() - 1).is_some() {
                    return Err(format!("duplicate-path: {}", norm));
                }
                continue;
            }
        } else {
            // depth == 0: expand root children.
            let rd = std::fs::read_dir(&abs)
                .map_err(|e| format!("release root unreadable: {}", e))?;
            let mut children: Vec<(PathBuf, PathBuf)> = Vec::new();
            for e in rd {
                match e {
                    Ok(en) => {
                        let name = en.file_name();
                        children.push((en.path(), rel.join(name)));
                    }
                    Err(e) => {
                        let p = "<root-entry>".to_string();
                        entries.push(InventoryEntry {
                            normalized_path: p.clone(),
                            kind: EntryKind::Unreadable,
                            size: 0,
                            mode: "u".to_string(),
                            content_hash: "none".to_string(),
                            flags: vec![format!("unreadable:readdir-entry:{}", e)],
                            diagnostic: format!("readdir entry failed: {}", e),
                        });
                        warnings.unreadables.push(p);
                    }
                }
            }
            for (c_abs, c_rel) in children {
                stack.push((c_abs, c_rel, depth + 1));
            }
        }
    }

    // Deterministic order: byte-wise sort of UTF-8 normalized path.
    entries.sort_by(|a, b| a.normalized_path.as_bytes().cmp(b.normalized_path.as_bytes()));

    // Case-collision detection over the sorted set.
    {
        let mut fold_map: HashMap<String, String> = HashMap::new();
        for e in entries.iter_mut() {
            let key = case_fold_key(&e.normalized_path);
            if let Some(first) = fold_map.get(&key) {
                if first != &e.normalized_path {
                    e.flags.push(format!("case-collision:{}", first));
                    warnings.case_collisions.push(e.normalized_path.clone());
                }
            } else {
                fold_map.insert(key, e.normalized_path.clone());
            }
        }
    }
    // Hardlink groups (unix dev:ino, windows native volume:index): group by
    // hardlink-id flag. Deterministic: member paths and warning lines sorted.
    {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for e in &entries {
            for f in &e.flags {
                if let Some(id) = f.strip_prefix("hardlink-id:") {
                    groups.entry(id.to_string()).or_default().push(e.normalized_path.clone());
                }
            }
        }
        for paths in groups.values_mut() {
            paths.sort();
        }
        let mut group_lines: Vec<String> = groups
            .iter()
            .filter(|(_, p)| p.len() > 1)
            .map(|(id, paths)| format!("{}:{}", id, paths.join(",")))
            .collect();
        group_lines.sort();
        warnings.hardlink_groups = group_lines;
        // Annotate members (second pass, after borrow ends).
        let multi: Vec<String> = groups
            .iter()
            .filter(|(_, p)| p.len() > 1)
            .map(|(id, _)| id.clone())
            .collect();
        for e in entries.iter_mut() {
            let hid = e.flags.iter().find_map(|f| f.strip_prefix("hardlink-id:").map(|s| s.to_string()));
            if let Some(id) = hid {
                if multi.contains(&id) {
                    e.flags.push(format!("hardlink-group:{}", id));
                }
            }
        }
        // Exterior-reference detection from native link counts. Unix and
        // Windows both expose a link count on the same handle/metadata used
        // for identity. A count above the in-scope member count is either an
        // excluded path (ambiguous, exclusions present) or necessarily
        // exterior (no exclusions). A singleton group is NOT skipped: a file
        // with nlink=2 and no second in-scope path is exactly the external
        // hardlink case this check must surface. Exterior is NEVER silently
        // resolved.
        let mut refs: Vec<String> = Vec::new();
        let mut exterior_ids: Vec<String> = Vec::new();
        let mut ambiguous_ids: Vec<String> = Vec::new();
        for (id, paths) in &groups {
            let mut nlinks: Option<u32> = None;
            for e in &entries {
                let is_member = e.flags.iter().any(|f| f == &format!("hardlink-id:{}", id));
                if !is_member {
                    continue;
                }
                for f in &e.flags {
                    if let Some(n) = f.strip_prefix("hardlink-nlinks:") {
                        if let Ok(v) = n.parse::<u32>() {
                            nlinks = Some(nlinks.map_or(v, |m: u32| m.max(v)));
                        }
                    }
                }
            }
            if let Some(n) = nlinks {
                if (n as usize) > paths.len() {
                    if exclusions.is_empty() {
                        refs.push(format!("exterior:{}:links={}:found={}", id, n, paths.len()));
                        exterior_ids.push(id.clone());
                    } else {
                        refs.push(format!(
                            "ambiguous:{}:links={}:found={}:exclusions-present",
                            id,
                            n,
                            paths.len()
                        ));
                        ambiguous_ids.push(id.clone());
                    }
                }
            }
        }
        refs.sort();
        warnings.external_link_refs = refs;
        for e in entries.iter_mut() {
            let hid = e.flags.iter().find_map(|f| f.strip_prefix("hardlink-id:").map(|s| s.to_string()));
            if let Some(id) = hid {
                if exterior_ids.contains(&id) {
                    e.flags.push(format!("unexplained-link-ref:{}", id));
                } else if ambiguous_ids.contains(&id) {
                    e.flags.push(format!("unresolved-link-ref:{}", id));
                }
            }
        }
    }

    diagnostics.push(format!("entries={}", entries.len()));
    Ok(Inventory { entries, warnings, diagnostics })
}

/// Canonical line for one entry (LF-terminated by the caller stream).
/// Format: `<hash> <kind> <size> <mode> <path>` (G6: splitn(5) to parse).
pub fn canonical_line(e: &InventoryEntry) -> String {
    format!(
        "{} {} {} {} {}",
        e.content_hash,
        e.kind.as_str(),
        e.size,
        e.mode,
        e.normalized_path
    )
}

/// Canonical byte stream: sorted lines joined with LF, final LF included.
/// Empty set yields an empty stream (caller decides allow_empty policy).
/// Sorting is enforced here (not only in the walk) so a caller-provided
/// slice cannot make the digest depend on insertion order.
pub fn canonical_bytes(entries: &[InventoryEntry]) -> Vec<u8> {
    let mut sorted: Vec<&InventoryEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        a.normalized_path
            .as_bytes()
            .cmp(b.normalized_path.as_bytes())
    });
    let mut v = Vec::new();
    for e in sorted {
        v.extend_from_slice(canonical_line(e).as_bytes());
        v.push(b'\n');
    }
    v
}

/// INVENTORY_DIGEST = SHA-256 hex over the canonical stream.
pub fn inventory_digest(entries: &[InventoryEntry]) -> String {
    sha_hex(&canonical_bytes(entries))
}

/// Parse one canonical line (inverse of `canonical_line`).
pub fn parse_canonical_line(line: &str) -> Result<(String, String, u64, String, String), String> {
    let mut parts = line.splitn(5, ' ');
    let hash = parts.next().ok_or("missing hash")?.to_string();
    let kind = parts.next().ok_or("missing kind")?.to_string();
    let size_s = parts.next().ok_or("missing size")?.to_string();
    let mode = parts.next().ok_or("missing mode")?.to_string();
    let path = parts.next().ok_or("missing path")?.to_string();
    if !["file", "dir", "symlink", "special", "unreadable"].contains(&kind.as_str()) {
        return Err(format!("unknown kind {:?}", kind));
    }
    let size: u64 = size_s.parse().map_err(|_| format!("bad size {:?}", size_s))?;
    if hash.is_empty() || mode.is_empty() || path.is_empty() {
        return Err("empty field".to_string());
    }
    Ok((hash, kind, size, mode, path))
}

#[derive(Debug, Clone, Default)]
pub struct InventoryDiff {
    pub missing: Vec<String>,
    pub unexpected: Vec<String>,
    pub changed: Vec<String>,
}

impl InventoryDiff {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.unexpected.is_empty() && self.changed.is_empty()
    }
}

fn sorted_flags(e: &InventoryEntry) -> Vec<&str> {
    let mut flags: Vec<&str> = e.flags.iter().map(String::as_str).collect();
    flags.sort_unstable();
    flags.dedup();
    flags
}

/// T0/T1 comparison by normalized path. Changed = any of hash/kind/size/
/// mode/flags differs. Flags are compared because topology and security
/// metadata (hardlink groups, external references, collisions) are not in
/// the content digest. Conservative: every unexpected is also an
/// added-after-freeze candidate when birth time is unavailable.
pub fn diff_inventories(t0: &[InventoryEntry], t1: &[InventoryEntry]) -> InventoryDiff {
    let m0: BTreeMap<&str, &InventoryEntry> = t0.iter().map(|e| (e.normalized_path.as_str(), e)).collect();
    let m1: BTreeMap<&str, &InventoryEntry> = t1.iter().map(|e| (e.normalized_path.as_str(), e)).collect();
    let mut d = InventoryDiff::default();
    for (p, e0) in &m0 {
        match m1.get(p) {
            None => d.missing.push(p.to_string()),
            Some(e1) => {
                if e0.content_hash != e1.content_hash
                    || e0.kind != e1.kind
                    || e0.size != e1.size
                    || e0.mode != e1.mode
                    || sorted_flags(e0) != sorted_flags(e1)
                {
                    d.changed.push(p.to_string());
                }
            }
        }
    }
    for (p, _) in &m1 {
        if !m0.contains_key(p) {
            d.unexpected.push(p.to_string());
        }
    }
    d.missing.sort();
    d.unexpected.sort();
    d.changed.sort();
    d
}

/// SHA-256 hex over raw manifest bytes (4AN D5: manifest canonical form =
/// the shipped bytes; no re-serialization, no silent transform).
pub fn manifest_digest(manifest_bytes: &[u8]) -> String {
    sha_hex(manifest_bytes)
}

#[derive(Debug, Clone)]
pub struct PackageBinding {
    pub package_id: String,
    pub manifest_digest: String,
    pub inventory_digest: String,
}

impl PackageBinding {
    pub fn verify(
        &self,
        recomputed_inventory: &str,
        recomputed_manifest: &str,
    ) -> Result<(), String> {
        if recomputed_inventory != self.inventory_digest {
            return Err(format!(
                "inventory digest mismatch: expected {} got {}",
                self.inventory_digest, recomputed_inventory
            ));
        }
        if recomputed_manifest != self.manifest_digest {
            return Err(format!(
                "manifest digest mismatch: expected {} got {}",
                self.manifest_digest, recomputed_manifest
            ));
        }
        if self.package_id.is_empty() {
            return Err("empty package_id".to_string());
        }
        Ok(())
    }
}

fn hardlink_violation(e: &InventoryEntry) -> Option<String> {
    for flag in &e.flags {
        if flag.starts_with("hardlink-group:")
            || flag.starts_with("unexplained-link-ref:")
            || flag.starts_with("unresolved-link-ref:")
            || flag.starts_with("hardlink-detection=unavailable")
        {
            return Some(flag.clone());
        }
        if let Some(n) = flag.strip_prefix("hardlink-nlinks:") {
            match n.parse::<u32>() {
                Ok(1) => {}
                _ => return Some(flag.clone()),
            }
        }
    }
    None
}

fn validate_release_entry(e: &InventoryEntry) -> Result<(), String> {
    if e.flags
        .iter()
        .any(|f| f.starts_with("case-collision:"))
    {
        return Err(format!("manifest-case-collision: {}", e.normalized_path));
    }
    if let Some(flag) = hardlink_violation(e) {
        return Err(format!(
            "manifest-hardlink: {} ({})",
            e.normalized_path, flag
        ));
    }
    match e.kind {
        EntryKind::File | EntryKind::Dir => Ok(()),
        EntryKind::Symlink => Err(format!("manifest-symlink: {}", e.normalized_path)),
        EntryKind::Special => Err(format!("manifest-special: {}", e.normalized_path)),
        EntryKind::Unreadable => Err(format!("manifest-unreadable: {}", e.normalized_path)),
    }
}

/// Verify an inventory against an expected manifest file set.
/// `expected`: (normalized_path, expected_hex) pairs from the manifest.
/// `allow_generated`: inventory paths allowed beyond the manifest (declared
/// generated files). Directories are structural and allowed; symlinks,
/// special files, unreadables, hardlink groups/external references and case
/// collisions are refused for every path, declared or generated.
pub fn verify_against_manifest(
    inventory: &[InventoryEntry],
    expected: &[(String, String)],
    allow_generated: &[String],
) -> Result<(), String> {
    let mut inv_by_path: BTreeMap<&str, &InventoryEntry> = BTreeMap::new();
    for e in inventory {
        validate_release_entry(e)?;
        if inv_by_path
            .insert(e.normalized_path.as_str(), e)
            .is_some()
        {
            return Err(format!("inventory-duplicate-path: {}", e.normalized_path));
        }
    }
    let mut expected_paths: BTreeSet<&str> = BTreeSet::new();
    for (p, h) in expected {
        if !expected_paths.insert(p.as_str()) {
            return Err(format!("manifest-duplicate: {}", p));
        }
        match inv_by_path.get(p.as_str()) {
            None => return Err(format!("manifest-missing: {}", p)),
            Some(e) if e.kind != EntryKind::File => {
                return Err(format!("manifest-not-file: {}", p));
            }
            Some(e) => {
                if !e.content_hash.eq_ignore_ascii_case(h) {
                    return Err(format!("manifest-changed: {}", p));
                }
            }
        }
    }
    for e in inventory {
        if e.kind != EntryKind::File {
            continue;
        }
        let p = e.normalized_path.as_str();
        let in_manifest = expected_paths.contains(p);
        let allowed = allow_generated.iter().any(|g| matches_exclusion(g, p));
        if !in_manifest && !allowed {
            return Err(format!("manifest-unexpected: {}", p));
        }
    }
    Ok(())
}

/// Full release inventory verification: walk-level topology warnings are
/// refused before the per-entry manifest binding. This is the strict gate
/// contract: a clean file set is necessary but not sufficient; the tree must
/// also be free of links, collisions, specials and unreadables.
pub fn verify_release_inventory(
    inventory: &Inventory,
    expected: &[(String, String)],
    allow_generated: &[String],
) -> Result<(), String> {
    if let Some(p) = inventory.warnings.unreadables.first() {
        return Err(format!("inventory-unreadable: {}", p));
    }
    if let Some(p) = inventory.warnings.external_links.first() {
        return Err(format!("inventory-external-link: {}", p));
    }
    if let Some(line) = inventory.warnings.hardlink_groups.first() {
        return Err(format!("inventory-hardlink-group: {}", line));
    }
    if let Some(line) = inventory.warnings.external_link_refs.first() {
        return Err(format!("inventory-link-reference: {}", line));
    }
    if let Some(p) = inventory.warnings.case_collisions.first() {
        return Err(format!("inventory-case-collision: {}", p));
    }
    if let Some(p) = inventory.warnings.specials.first() {
        return Err(format!("inventory-special: {}", p));
    }
    verify_against_manifest(&inventory.entries, expected, allow_generated)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(matches_exclusion("*.log", "a.log"));
        assert!(matches_exclusion("tmp/*", "tmp/a/b"));
        assert!(!matches_exclusion("tmp/*", "other/a"));
        assert!(matches_exclusion("exact", "exact"));
        assert!(!matches_exclusion("exact", "exact2"));
    }

    #[test]
    fn normalize_rejects_escape_and_absolute_forms() {
        assert!(normalize_relative(Path::new("../x")).is_err());
        assert!(normalize_relative(Path::new("a/../../x")).is_err());
        assert!(normalize_relative(Path::new("/x")).is_err());
        assert!(normalize_relative(Path::new("")).is_err());
        assert!(normalize_relative(Path::new("a\nb")).is_err());
        assert_eq!(normalize_relative(Path::new("./a//b")).unwrap(), "a/b");
    }

    #[test]
    #[cfg(unix)]
    fn normalize_preserves_unix_backslash_literals() {
        assert_eq!(normalize_relative(Path::new("a\\b")).unwrap(), "a\\b");
        assert_ne!(
            normalize_relative(Path::new("a\\b")).unwrap(),
            normalize_relative(Path::new("a/b")).unwrap()
        );
    }

    #[test]
    fn canonical_roundtrip_with_spaces() {
        let e = InventoryEntry {
            normalized_path: "sub/dir/my file.bin".to_string(),
            kind: EntryKind::File,
            size: 3,
            mode: "f".to_string(),
            content_hash: "aa".to_string(),
            flags: vec![],
            diagnostic: String::new(),
        };
        let line = canonical_line(&e);
        let (h, k, s, m, p) = parse_canonical_line(&line).unwrap();
        assert_eq!((h, k, s, m, p), ("aa".to_string(), "file".to_string(), 3, "f".to_string(), "sub/dir/my file.bin".to_string()));
    }
}
