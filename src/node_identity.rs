//! # Node Identity Module (PHASE 4CN)
//!
//! Local, persistent network identity for an Aether node.
//!
//! This module is deliberately **self-contained**: it defines a durable
//! Ed25519 identity that is independent of the node's IP address, its port and
//! its wallet keys. It is **not** wired into the P2P handshake, PEX, the peer
//! store or the wallet in this phase. Those integrations are scheduled for
//! later phases (handshake binding in 4CO, peer-store migration later).
//!
//! ## What this provides
//! - [`NodeId`]: the 32-byte Ed25519 public key that names the node. It is
//!   stable across restarts and independent of transport addresses.
//! - [`NodeIdentity`]: the long-lived Ed25519 secret kept on disk, with a
//!   minimal sign/verify surface.
//! - [`load_or_create`] / [`load`]: explicit, error-surfacing persistence.
//!
//! ## What this is NOT
//! - It is **not** an authentication of remote peers or of the session. A
//!   later phase must bind this identity to the handshake with a signature
//!   over the session transcript.
//! - It is **not** the wallet identity. The network key is stored in its own
//!   file and must never be reused as an account key (and vice versa).
//!
//! ## Persistence format (versioned)
//! A JSON object written to `node_identity.json` inside the configured data
//! directory:
//! ```json
//! { "version": 1, "node_id": "<64 hex chars>", "secret_key": "<64 hex chars>" }
//! ```
//! On load the file is validated: the version must be supported, both hex
//! fields must decode to exactly 32 bytes, and the public key derived from
//! `secret_key` must equal `node_id`. Any violation is reported as an error;
//! a corrupt or unreadable identity is **never** silently regenerated.
//!
//! ## Creation, atomicity and hygiene (4CP-AE)
//! Creation writes a fully-formed, private *staging* file in the same directory
//! as the destination and publishes it with a no-replace hard link, so a
//! concurrent creator can never be clobbered and the final name is never
//! observable in a half-written state. The staging file is created private
//! (mode `0600` on Unix, a protected DACL on Windows) **before** any secret
//! byte is written, and is removed on every exit path, including a failure.
//! If the filesystem cannot publish atomically without replacement, creation
//! fails explicitly: there is **no** non-atomic fallback (4CPT-09).
//!
//! Orphaned staging files left by a crashed creator are swept at startup, but
//! only when the owning process is **provably gone**; a file whose owner is
//! alive, or whose liveness cannot be established, is always kept.
//!
//! ## Directory protection (4CP-AG / AF-2, 4CP-AI / AH-1, AH-2)
//! The identity file lives **directly** in the node data directory (which also
//! holds `dag.json`, the sled store and other node-private state). The single
//! secure-creation entry point [`ensure_secure_data_dir`] is used at the FIRST
//! point the directory is needed in each entry path (the file-logging bootstrap
//! in `main`, the node startup via [`crate::json_storage::ensure_data_dir`], and
//! identity loading), so the directory is **never** first created with ordinary
//! permissions and hardened afterwards:
//!
//! - the whole path is validated first ([`validate_directory_path`]): every
//!   existing ancestor must be a directory that an untrusted third party cannot
//!   replace (Unix: not group/world-writable without the sticky bit; Windows: not
//!   a reparse point and owned by a trusted principal);
//! - a new directory and any missing ancestors are created with restrictive
//!   permissions **at creation** (Unix `0700`; Windows a protected owner-only
//!   DACL applied by `CreateDirectoryW`, never created broadly then narrowed);
//! - an existing directory is inspected (must be a real directory, not a symlink
//!   or reparse point) and hardened to the owner-only policy;
//! - if the path is unsafe or the directory cannot be secured (symlink,
//!   non-directory, owned by another user, or a filesystem that ignores the
//!   policy), loading or creating the identity **fails explicitly** rather than
//!   trusting the fragile assumption "no third party can modify this directory".
//!
//! With the directory owner-only, another local user cannot replace the name
//! between the symlink check and the open. A process running **as the same user**
//! is outside this model — it can already read the key.
//!
//! ### Path preconditions
//! Only the leaf (the data directory) is *enforced* owner-only; ancestors are
//! *validated* but their permissions are not rewritten. On Windows a full ACL
//! walk is deliberately not performed (it is not portably meaningful and risks
//! rejecting valid standard paths), so the operator precondition is: the data
//! directory must live under a directory writable only by the current user,
//! SYSTEM and Administrators (the default `%APPDATA%` / `%LOCALAPPDATA%` layout
//! satisfies this). The path check is inherently racy against a third party who
//! can already modify an accepted component, but such components are *rejected*.
//!
//! ## Atomicity, race-safety and durability (4CP-AE / 4CP-AG / AF-1)
//! Three distinct properties, deliberately not conflated:
//! 1. **Atomic visibility** — the final name appears only once the complete file
//!    exists, published by a no-replace hard link; readers never observe a
//!    half-written identity. *(provided)*
//! 2. **Race-safety** — a concurrent creator can never be clobbered; the loser
//!    loads and validates the winner's file. *(provided)*
//! 3. **Crash / power-loss durability** — the staging bytes are flushed and
//!    `sync_all`ed before publication, and on Unix the directory entry is synced
//!    after publication. This is **best-effort**: `std` exposes no portable
//!    directory fsync on Windows, and no implementation can promise survival of
//!    an arbitrary power loss. *(best-effort, not guaranteed)*
//!
//! ## Filesystem requirements (4CP-AG / AF-3)
//! Publication requires a filesystem that supports **hard links** (NTFS, ext4,
//! APFS, ...). On a filesystem without them (FAT/exFAT, some network shares)
//! creation fails with an explicit error — there is **no** non-atomic fallback.
//!
//! ## Documented limitations
//! - The symlink/non-regular-file check uses `symlink_metadata` before a normal
//!   open; the residual window is closed by the owner-only directory policy
//!   above, **not** by the check alone. A same-user attacker is out of scope.
//! - The orphan sweep is best-effort hygiene, not a guaranteed purge: it only
//!   recognises the exact staging-name shape and only removes files whose owner
//!   liveness can be probed (Linux `/proc`, Windows `OpenProcess`). On other
//!   platforms liveness is `Unknown` and nothing is removed.
//! - Liveness by pid is subject to pid reuse: a recycled pid can make an orphan
//!   look alive, which only ever leaves a stale file behind, never deletes a
//!   live one.
//! - Directories created **above** the data directory use the ambient `umask`
//!   on Unix and inherit the parent ACL on Windows; they are only *validated*
//!   (see path preconditions), not rewritten. Only the data directory itself is
//!   enforced owner-only.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// File name of the on-disk network identity, placed inside the node data
/// directory alongside `dag.json`, `ledger.json` and `network.id`.
pub const NODE_IDENTITY_FILE_NAME: &str = "node_identity.json";

/// Schema version of [`NodeIdentityFile`]. Bumping this is a persistent-format
/// change and must be accompanied by an explicit migration path.
pub const NODE_IDENTITY_FILE_VERSION: u32 = 1;

/// Errors surfaced by the identity module. Every variant is intended to be
/// actionable by an operator; none of them causes a silent key replacement.
#[derive(Debug)]
pub enum IdentityError {
    /// Filesystem failure (read, create, permissions, rename, ...).
    Io(std::io::Error),
    /// The file exists but is not the expected JSON shape.
    Malformed(String),
    /// The file declares a schema version this binary does not understand.
    UnsupportedVersion(u32),
    /// The file parses but its contents are internally inconsistent or the
    /// stored key material is not a valid Ed25519 secret.
    Corrupt(String),
}

impl IdentityError {
    fn io(e: std::io::Error) -> Self {
        IdentityError::Io(e)
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Note: never embed file *contents* here, only the reason.
            IdentityError::Io(e) => write!(f, "node identity I/O error: {}", e),
            IdentityError::Malformed(reason) => {
                write!(f, "node identity file is malformed: {}", reason)
            }
            IdentityError::UnsupportedVersion(v) => write!(
                f,
                "node identity file version {} is not supported by this binary",
                v
            ),
            IdentityError::Corrupt(reason) => {
                write!(f, "node identity file is corrupt: {}", reason)
            }
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IdentityError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        IdentityError::Io(e)
    }
}

/// The public, persistent name of a node: its raw 32-byte Ed25519 public key.
///
/// The raw bytes are the canonical representation. Hexadecimal exists only for
/// display and diagnostics; no other encoding is introduced.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Wrap raw bytes as a node id.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }

    /// Borrow the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal rendering (display/diagnostics only).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.to_hex())
    }
}

/// A long-lived local network identity.
///
/// `Debug` is implemented manually so the secret key is never emitted in logs
/// or diagnostics; only the public [`NodeId`] is printed.
pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl NodeIdentity {
    /// Generate a fresh, unpersisted identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        // Best-effort scrub of the local buffer; the key itself lives inside
        // `SigningKey` (no zeroize dependency is introduced in this phase).
        secret = [0u8; 32];
        NodeIdentity { signing_key }
    }

    /// The public [`NodeId`] derived from the secret key.
    pub fn node_id(&self) -> NodeId {
        NodeId(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign an arbitrary message with the network identity.
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verify a signature produced by [`NodeIdentity::sign_message`] against the
/// public key named by `node_id`.
pub fn verify_message(node_id: &NodeId, message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(node_id.as_bytes()) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message, &sig).is_ok()
}

/// Whether an identity was found on disk or freshly created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOutcome {
    /// An existing identity was validated and loaded.
    Loaded,
    /// No identity existed; one was created and persisted.
    Created,
}

/// Path of the identity file inside a data directory.
pub fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join(NODE_IDENTITY_FILE_NAME)
}

/// Ensure the node data directory exists and is **owner-only**.
///
/// This is the **single secure-creation entry point** for the node data
/// directory (4CP-AI / AH-2). It is called at the FIRST point the directory is
/// needed in each entry path — the file-logging bootstrap in `main`, the node
/// startup ([`crate::json_storage::ensure_data_dir`]) and identity loading — so
/// the directory is never first created with ordinary permissions and hardened
/// afterwards.
///
/// It validates every existing component of the path (see
/// [`validate_directory_path`]), creates any missing component with restrictive
/// permissions **at creation** (Unix `0700`; Windows a protected DACL applied by
/// `CreateDirectoryW`), then enforces and verifies the owner-only policy on the
/// leaf. It fails explicitly, with an actionable message, if the path is unsafe
/// or the policy cannot be established — it never silently proceeds.
pub fn ensure_secure_data_dir(dir: &Path) -> Result<(), IdentityError> {
    validate_directory_path(dir)?;
    ensure_private_directory(dir, true)
}

/// Validate that no existing component of `dir` (the leaf and every ancestor up
/// to the filesystem root) can be written to by a third party, so the data
/// directory cannot be replaced before or after it is used (4CP-AI / AH-2).
///
/// Unix: a component that is group- or world-writable is refused unless it also
/// carries the sticky bit (which prevents other users from removing or renaming
/// our entry — e.g. `/tmp`). System directories (not writable by others) and
/// standard user paths (`~/.local/share/...`) pass.
///
/// Windows: a reparse point (junction / symlink) anywhere in the chain is
/// refused, and every existing component must be owned by the current user,
/// SYSTEM, Administrators or a service SID (e.g. TrustedInstaller). A full
/// Windows ACL walk is deliberately **not** performed — see the module's path
/// preconditions.
///
/// The check is inherently racy against a third party who can already modify an
/// *accepted* component; such components are rejected, so the residual window is
/// documented rather than silently assumed closed.
fn validate_directory_path(dir: &Path) -> Result<(), IdentityError> {
    let mut cur = Some(dir);
    while let Some(p) = cur {
        match std::fs::symlink_metadata(p) {
            Ok(_) => validate_path_component(p)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(IdentityError::Io(e)),
        }
        cur = p.parent().filter(|parent| parent.as_os_str() != p.as_os_str());
    }
    Ok(())
}

/// Unix: follow symlinks (a symlinked ancestor such as macOS `/var` is fine as
/// long as its target is not writable by others) and reject any component that
/// another user could write to without the sticky bit.
#[cfg(unix)]
fn validate_path_component(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(IdentityError::Io)?;
    if !meta.is_dir() {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing data directory path: {} is not a directory",
                path.display()
            ),
        )));
    }
    let mode = meta.mode();
    if (mode & 0o022) != 0 && (mode & 0o1000) == 0 {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing data directory path: {} is group- or world-writable without the \
                 sticky bit, so another local user could replace the data directory",
                path.display()
            ),
        )));
    }
    Ok(())
}

/// Windows: reject a reparse point (junction / symlink) in the chain and require
/// the component to be owned by a trusted principal.
#[cfg(windows)]
fn validate_path_component(path: &Path) -> Result<(), IdentityError> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let meta = std::fs::symlink_metadata(path).map_err(IdentityError::Io)?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing data directory path: {} is a reparse point, so the data directory \
                 could be redirected to an attacker-chosen location",
                path.display()
            ),
        )));
    }
    if !meta.is_dir() {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing data directory path: {} is not a directory",
                path.display()
            ),
        )));
    }
    win_acl::verify_trusted_owner(path)
        .map_err(|e| IdentityError::Io(std::io::Error::new(e.kind(), format!("{}", e))))
}

/// No portable path policy exists on this platform: accept (the module documents
/// that only the leaf is enforced there).
#[cfg(not(any(unix, windows)))]
fn validate_path_component(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// Ensure `dir` exists (when `create`) and is **owner-only**.
///
/// The identity file lives directly in the node data directory, so this is the
/// directory whose protection closes the time-of-check/time-of-use window that
/// [`reject_unexpected_identity_type`] alone cannot (4CP-AG / AF-2).
///
/// Refuses a symlink, a reparse point or any non-directory, and fails explicitly
/// — with an actionable message — if the owner-only policy cannot be
/// established. It never silently proceeds on an unsecurable configuration.
fn ensure_private_directory(dir: &Path, create: bool) -> Result<(), IdentityError> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(IdentityError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to use {} as the node identity directory: it is a symbolic link",
                        dir.display()
                    ),
                )));
            }
            if !ft.is_dir() {
                return Err(IdentityError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to use {} as the node identity directory: not a directory",
                        dir.display()
                    ),
                )));
            }
            #[cfg(windows)]
            {
                // A directory junction / mount point is a reparse point that
                // `FileType::is_symlink` does not always report; reject it so the
                // key cannot be redirected to an attacker-chosen location.
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(IdentityError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "refusing to use {} as the node identity directory: it is a reparse point",
                            dir.display()
                        ),
                    )));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Err(IdentityError::Io(e));
            }
            create_dir_tree_private(dir).map_err(IdentityError::Io)?;
        }
        Err(e) => return Err(IdentityError::Io(e)),
    }

    enforce_private_directory(dir)
}

/// Create `dir` and any missing ancestors with restrictive permissions applied
/// **at creation** — never created widely and then narrowed.
///
/// Unix: a single recursive `mkdir` with mode `0700` (the `umask` can only clear
/// bits). Windows: each missing level is created with `CreateDirectoryW` and a
/// `SECURITY_ATTRIBUTES` carrying the protected owner-only DACL, so the
/// directory exists with its restrictive ACL from the first instant (4CP-AI /
/// AH-1) rather than being created broadly and hardened afterwards.
#[cfg(unix)]
fn create_dir_tree_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    // `mode(0o700)` is applied at `mkdir` time; `umask` can only remove bits.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(windows)]
fn create_dir_tree_private(dir: &Path) -> std::io::Result<()> {
    // Collect the chain of missing components, then create them from the top
    // down so each is born with the protected DACL.
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cur = dir.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&cur) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        missing.push(cur.clone());
        match cur.parent() {
            Some(parent) if parent.as_os_str() != cur.as_os_str() => {
                cur = parent.to_path_buf();
            }
            _ => break,
        }
    }
    for p in missing.iter().rev() {
        win_acl::create_private_directory(p)?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_dir_tree_private(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Enforce the owner-only directory policy (Unix: `0700`).
#[cfg(unix)]
fn enforce_private_directory(dir: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        IdentityError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "cannot secure the node identity directory {} to owner-only (0700): {}; \
                 refusing to run where another local user could modify the directory",
                dir.display(),
                e
            ),
        ))
    })?;

    // Verify the policy actually took effect: some filesystems ignore or reject
    // mode changes, and a silent no-op would defeat the whole guarantee.
    let mode = std::fs::metadata(dir)
        .map_err(IdentityError::Io)?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "node identity directory {} is still accessible to group/other (mode {:o}); \
                 refusing to store the node identity there",
                dir.display(),
                mode
            ),
        )));
    }
    Ok(())
}

/// Enforce the owner-only directory policy (Windows: a protected DACL).
#[cfg(windows)]
fn enforce_private_directory(dir: &Path) -> Result<(), IdentityError> {
    win_acl::harden_directory(dir).map_err(|e| {
        IdentityError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "cannot secure the node identity directory {} with a protected DACL: {}; \
                 refusing to run where another local user could modify the directory",
                dir.display(),
                e
            ),
        ))
    })
}

/// No portable owner-only policy exists on this platform: refuse explicitly
/// rather than pretend the directory is protected.
#[cfg(not(any(unix, windows)))]
fn enforce_private_directory(dir: &Path) -> Result<(), IdentityError> {
    Err(IdentityError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "cannot establish owner-only permissions for the node identity directory {} on this platform",
            dir.display()
        ),
    )))
}

/// Load an existing identity, or create and persist one if none exists.
///
/// The creation path is race-safe and never clobbers an existing identity: it
/// writes a fully-formed, private staging file in the SAME directory as the
/// destination, then publishes it with a no-replace hard link. If a concurrent
/// process wins the race, the winner's file is loaded instead.
///
/// There is **no** non-atomic fallback: if the filesystem cannot publish the
/// final name atomically without replacement, an explicit error is returned
/// rather than writing the secret directly to `node_identity.json` (4CP-AE /
/// 4CPT-09).
///
/// A present-but-invalid file is an error: the caller must resolve it. This
/// function never regenerates over an identity it could not parse.
pub fn load_or_create(data_dir: &Path) -> Result<(NodeIdentity, IdentityOutcome), IdentityError> {
    // 4CP-AG (AF-2) / 4CP-AI (AH-2): the identity directory must be owner-only
    // BEFORE any secret is written, its path must not be replaceable by a third
    // party, and (when it does not exist yet) it must be created owner-only at
    // creation. This replaces the fragile assumption that no third party can
    // modify the directory with an enforced, or explicitly refused, policy.
    ensure_secure_data_dir(data_dir)?;
    let path = identity_path(data_dir);

    // 4CP-AE (4CPT-08): best-effort sweep of staging files left by a creator
    // whose process is provably gone. A staging file whose owner is alive, or
    // whose liveness cannot be established, is ALWAYS kept, so a concurrent
    // creation is never disturbed. This is hygiene, not a guaranteed purge.
    let _ = sweep_orphan_staging_files(data_dir);

    // Fast path: an identity already exists. A symbolic link or any other
    // non-regular file at the final path is rejected, never followed.
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            reject_unexpected_identity_type(&meta, &path)?;
            return Ok((load(data_dir)?, IdentityOutcome::Loaded));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(IdentityError::Io(e)),
    }

    let identity = NodeIdentity::generate();
    let contents = serialize_identity(&identity)?;
    if persist_new(&path, &contents)? {
        return Ok((identity, IdentityOutcome::Created));
    }

    // Lost the race: another process published first. Load the winner.
    Ok((load(data_dir)?, IdentityOutcome::Loaded))
}

/// Load and validate an existing identity. Returns an error (never a
/// replacement) if the file is missing, unreadable, a symbolic link or any
/// non-regular file, malformed, of an unsupported version, or internally
/// inconsistent.
pub fn load(data_dir: &Path) -> Result<NodeIdentity, IdentityError> {
    // 4CP-AG (AF-2) / 4CP-AI (AH-2): never read the key out of a directory a
    // third party could have modified or replaced; an unsecurable or unsafe path
    // is refused (never created here).
    validate_directory_path(data_dir)?;
    ensure_private_directory(data_dir, false)?;
    let path = identity_path(data_dir);
    let raw = read_identity_string(&path)?;
    parse_identity(&raw)
}

/// Reject an identity path that is a symbolic link or any non-regular file.
///
/// The check uses `symlink_metadata`, so a symlink is detected without being
/// followed. The small time-of-check/time-of-use window between this check and
/// the later open is closed by [`ensure_private_directory`], which requires the
/// containing directory to be owner-only (4CP-AG / AF-2) — a third party cannot
/// replace the name in between. A true no-follow open would close the window by
/// itself but is not portable without a platform dependency; the directory
/// policy is used instead.
fn reject_unexpected_identity_type(
    meta: &std::fs::Metadata,
    path: &Path,
) -> Result<(), IdentityError> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to use {}: it is a symbolic link", path.display()),
        )));
    }
    if !ft.is_file() {
        return Err(IdentityError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to use {}: not a regular file", path.display()),
        )));
    }
    Ok(())
}

/// Read the identity file, refusing a symbolic link or non-regular file at the
/// final path so the private key of an arbitrary symlink target is never read.
fn read_identity_string(path: &Path) -> Result<String, IdentityError> {
    let meta = std::fs::symlink_metadata(path)?;
    reject_unexpected_identity_type(&meta, path)?;
    std::fs::read_to_string(path).map_err(IdentityError::Io)
}

// ---------------------------------------------------------------------------
// Persistence internals
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct NodeIdentityFile {
    version: u32,
    node_id: String,
    secret_key: String,
}

fn serialize_identity(identity: &NodeIdentity) -> Result<String, IdentityError> {
    let file = NodeIdentityFile {
        version: NODE_IDENTITY_FILE_VERSION,
        node_id: identity.node_id().to_hex(),
        secret_key: hex::encode(identity.signing_key.to_bytes()),
    };
    serde_json::to_string(&file).map_err(|e| {
        // `e` is a serializer error; it contains no key material.
        IdentityError::Corrupt(format!("could not serialize identity: {}", e))
    })
}

fn parse_identity(raw: &str) -> Result<NodeIdentity, IdentityError> {
    let file: NodeIdentityFile = serde_json::from_str(raw)
        .map_err(|e| IdentityError::Malformed(format!("not valid identity JSON: {}", e)))?;

    if file.version != NODE_IDENTITY_FILE_VERSION {
        return Err(IdentityError::UnsupportedVersion(file.version));
    }

    let secret_bytes = hex::decode(&file.secret_key)
        .map_err(|_| IdentityError::Corrupt("secret_key is not valid hex".into()))?;
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Corrupt("secret_key is not 32 bytes".into()))?;

    let stored_id = hex::decode(&file.node_id)
        .map_err(|_| IdentityError::Corrupt("node_id is not valid hex".into()))?;
    let stored_id: [u8; 32] = stored_id
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::Corrupt("node_id is not 32 bytes".into()))?;

    let signing_key = SigningKey::from_bytes(&secret);
    let derived = signing_key.verifying_key().to_bytes();
    if derived != stored_id {
        return Err(IdentityError::Corrupt(
            "node_id does not match the public key derived from secret_key".into(),
        ));
    }

    Ok(NodeIdentity { signing_key })
}

/// Publish `contents` to `path` without overwriting an existing file.
/// Returns `true` if this call created the file, `false` if it already existed.
///
/// Publication is a no-replace hard link from a same-directory staging file. If
/// that cannot be done, an explicit error is returned — the secret is never
/// written non-atomically to the final path (4CP-AE / 4CPT-09).
fn persist_new(path: &Path, contents: &str) -> Result<bool, IdentityError> {
    let created = persist_new_impl(path, contents, &write_private_new, &|src, dst| {
        std::fs::hard_link(src, dst)
    })?;
    if created {
        // 4CP-AG (AF-1): persist the new directory entry (best-effort, Unix only).
        sync_parent_directory(path);
    }
    Ok(created)
}

/// Testable core of [`persist_new`]. `write_staging` and `link` are injectable
/// so a test can exercise cleanup after a partial write and refusal on a
/// filesystem without an atomic no-replace publish, without needing a real
/// failing filesystem.
fn persist_new_impl(
    path: &Path,
    contents: &str,
    write_staging: &dyn Fn(&Path, &str) -> std::io::Result<()>,
    link: &dyn Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<bool, IdentityError> {
    let tmp = temp_sibling(path);
    // 4CP-AE (4CPT-08): the staging file is private BEFORE any secret byte is
    // written (`write_staging` applies the restrictive mode/ACL at creation),
    // and the guard removes it on EVERY exit path — including a partial write
    // that returns an error — so no key copy is left behind.
    let _tmp_guard = TempFileGuard::new(tmp.clone());

    write_staging(&tmp, contents).map_err(IdentityError::Io)?;

    match link(&tmp, path) {
        Ok(()) => Ok(true),
        // Another creator published first; keep their file untouched.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        // 4CP-AE (4CPT-09): never fall back to a direct, non-atomic write of
        // `node_identity.json`. Refuse explicitly so the operator learns that
        // this storage cannot host a securely-created identity.
        Err(e) => Err(IdentityError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "cannot publish the node identity atomically on this filesystem \
                 (hard link to {:?} failed: {}); refusing a non-atomic fallback",
                path, e
            ),
        ))),
    }
}

/// RAII guard that removes a staging file on drop.
///
/// A failure to remove the file is **not** swallowed silently: it is logged as
/// a warning (the *path* is safe to log; the file *contents* never are).
struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %e,
                    "could not remove the temporary node-identity staging file"
                );
            }
        }
    }
}

/// A unique sibling path for the temporary staging file.
///
/// 4CP-S: uniqueness must not rely on the clock alone — on Windows the system
/// clock is coarse enough that several threads of the same process can read the
/// SAME `nanos` and collide on the staging name, which made concurrent creation
/// fail with `AlreadyExists` (Windows error 80) instead of converging on the
/// winner. A process-wide monotonic counter guarantees distinct names within a
/// process; the pid keeps distinct processes apart.
fn temp_sibling(path: &Path) -> PathBuf {
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "node_identity".to_string());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    parent.join(format!(
        "{}.{}.{}.{}.tmp",
        name,
        std::process::id(),
        nanos,
        seq
    ))
}

// ---------------------------------------------------------------------------
// Orphaned staging-file sweep (4CP-AE / 4CPT-08)
// ---------------------------------------------------------------------------

/// Liveness of the process that owns a staging file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerLiveness {
    /// The owning process is still running: its staging file is in active use.
    Alive,
    /// The owning process is provably gone: the staging file is an orphan.
    Gone,
    /// Liveness cannot be established on this platform or for this process.
    Unknown,
}

/// Remove staging files left in `dir` by a creator whose process is provably
/// gone. Returns the number of files removed.
///
/// Only names matching the exact staging format are considered, only regular
/// files are removed (symbolic links and every other file type are skipped,
/// never followed), and a file whose owner is `Alive` **or** `Unknown` is always
/// kept. The sweep is therefore safe with respect to a concurrent creator; it is
/// hygiene, not a guaranteed purge (see the module's limitations).
fn sweep_orphan_staging_files(dir: &Path) -> usize {
    sweep_orphan_staging_files_with(dir, process_liveness)
}

fn sweep_orphan_staging_files_with(dir: &Path, owner_state: impl Fn(u32) -> OwnerLiveness) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(pid) = parse_staging_name(file_name) else {
            continue;
        };
        // `DirEntry::metadata` does NOT follow symlinks, so a symlink is seen as
        // a symlink and skipped rather than having its target inspected.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let ft = meta.file_type();
        if ft.is_symlink() || !ft.is_file() {
            continue;
        }
        if owner_state(pid) != OwnerLiveness::Gone {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    path = %entry.path().display(),
                    error = %e,
                    "could not remove an orphaned node-identity staging file"
                );
            }
        }
    }
    removed
}

/// Parse a staging file name of the exact form
/// `<NODE_IDENTITY_FILE_NAME>.<pid>.<nanos>.<seq>.tmp`, returning the pid.
///
/// Returns `None` for anything else, so an unrelated file in the data directory
/// can never be mistaken for an Aether staging file (and thus never removed).
fn parse_staging_name(file_name: &str) -> Option<u32> {
    let prefix = format!("{}.", NODE_IDENTITY_FILE_NAME);
    let core = file_name.strip_prefix(&prefix)?.strip_suffix(".tmp")?;
    let mut parts = core.split('.');
    let pid = parts.next()?;
    let nanos = parts.next()?;
    let seq = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let decimal = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !decimal(pid) || !decimal(nanos) || !decimal(seq) {
        return None;
    }
    pid.parse::<u32>().ok()
}

/// Best-effort, conservative liveness probe for a process id.
///
/// Deliberately biased toward `Unknown` (which is treated as "keep the file"),
/// so a probe that cannot be answered never causes data loss.
fn process_liveness(pid: u32) -> OwnerLiveness {
    if pid == 0 {
        return OwnerLiveness::Gone;
    }
    if pid == std::process::id() {
        return OwnerLiveness::Alive;
    }
    #[cfg(target_os = "linux")]
    {
        let proc = Path::new("/proc").join(pid.to_string());
        match std::fs::symlink_metadata(&proc) {
            Ok(_) => OwnerLiveness::Alive,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => OwnerLiveness::Gone,
            Err(_) => OwnerLiveness::Unknown,
        }
    }
    #[cfg(windows)]
    {
        windows_process_liveness(pid)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        OwnerLiveness::Unknown
    }
}

/// Windows liveness probe: open the process and test whether it has signalled
/// exit. A process that cannot be opened because it does not exist is `Gone`;
/// one that cannot be opened for any other reason is `Unknown` (kept).
#[cfg(windows)]
fn windows_process_liveness(pid: u32) -> OwnerLiveness {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        );
        if handle.is_null() {
            return match std::io::Error::last_os_error().raw_os_error() {
                // ERROR_INVALID_PARAMETER: there is no process with this id.
                Some(87) => OwnerLiveness::Gone,
                // ERROR_ACCESS_DENIED: the process exists but is protected.
                Some(5) => OwnerLiveness::Alive,
                _ => OwnerLiveness::Unknown,
            };
        }
        let wait = WaitForSingleObject(handle, 0);
        CloseHandle(handle);
        match wait {
            WAIT_OBJECT_0 => OwnerLiveness::Gone,
            WAIT_TIMEOUT => OwnerLiveness::Alive,
            _ => OwnerLiveness::Unknown,
        }
    }
}

/// Create `path` exclusively (fails if it exists) and write `contents` with the
/// most restrictive permissions the platform allows.
///
/// On Unix the file is created with mode `0600` (owner read/write only) and the
/// mode is re-asserted after writing. On non-Unix platforms the Unix mode bits
/// do not exist; the file is created through the same path but this function
/// makes **no** claim about ACLs there — see `write_private_new` limitations.
fn write_private_new(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.flush()?;
        // Durability (4CP-AG / AF-1): the secret bytes must reach the disk
        // before the name is published, not merely the OS cache.
        f.sync_all()?;
        Ok(())
    }
    #[cfg(windows)]
    {
        win_acl::create_private_new(path, contents)
    }
    #[cfg(not(any(unix, windows)))]
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    }
}

/// Best-effort: flush the directory entry so a just-published name survives a
/// crash (4CP-AG / AF-1). Unix-only: `std` exposes no portable directory fsync
/// on Windows, so durability there is limited to the staging file's `sync_all`.
fn sync_parent_directory(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::File::open(parent).and_then(|d| d.sync_all()) {
                tracing::warn!(
                    path = %parent.display(),
                    error = %e,
                    "could not fsync the node-identity directory after publishing"
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Windows-specific hardening: create the file with an explicit **protected
/// DACL** applied by the kernel at creation time, before a single secret byte
/// is written.
///
/// The DACL grants full access to exactly three principals — local SYSTEM, the
/// built-in Administrators group and the current user's SID — and is marked
/// protected (`D:P`) so no ACE is inherited from the parent directory. Generic
/// principals (`Everyone`, `Users`, `Authenticated Users`) receive no access.
///
/// This is a native `CreateFileW` with a `SECURITY_ATTRIBUTES` descriptor built
/// from an SDDL string, so there is no window where the file exists without the
/// restrictive ACL. `set_permissions` is **not** used: on Windows it cannot
/// express a DACL.
#[cfg(windows)]
mod win_acl {
    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn to_wide(s: &OsStr) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_wide().collect();
        v.push(0);
        v
    }

    fn to_wide_str(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    /// Read a NUL-terminated UTF-16 string from a raw pointer.
    unsafe fn read_wide_z(p: *const u16) -> String {
        let mut n = 0usize;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    /// The current user's SID as an SDDL string (e.g. `S-1-5-21-...-1001`).
    fn current_user_sid_string() -> io::Result<String> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            // First call probes the required buffer size.
            let mut len: u32 = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            if len == 0 {
                let e = io::Error::last_os_error();
                CloseHandle(token);
                return Err(e);
            }
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                len,
                &mut len,
            );
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut str_ptr: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(token_user.User.Sid, &mut str_ptr) == 0 {
                return Err(io::Error::last_os_error());
            }
            let sid = read_wide_z(str_ptr);
            LocalFree(str_ptr as HLOCAL);
            Ok(sid)
        }
    }

    /// Build a self-relative security descriptor whose DACL is protected and
    /// grants full access only to SYSTEM, Administrators and the current user.
    fn build_protected_sd() -> io::Result<PSECURITY_DESCRIPTOR> {
        let user_sid = current_user_sid_string()?;
        let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{})", user_sid);
        let wide = to_wide_str(&sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sd)
    }

    /// Create `path` exclusively (fails if it already exists) with the protected
    /// DACL applied by `CreateFileW` at creation, then write `contents`.
    pub(super) fn create_private_new(path: &Path, contents: &str) -> io::Result<()> {
        use std::io::Write as _;

        let sd = build_protected_sd()?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let wide = to_wide(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                0,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let e = io::Error::last_os_error();
            unsafe { LocalFree(sd as HLOCAL) };
            return Err(e);
        }

        // `File` takes ownership of the handle and closes it on drop; the
        // security descriptor is freed once the handle no longer needs it.
        let mut file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
        let result = (|| -> io::Result<()> {
            file.write_all(contents.as_bytes())?;
            file.flush()?;
            // Durability (4CP-AG / AF-1): make the secret bytes reach the disk
            // before the name is published, not merely the OS cache.
            file.sync_all()?;
            Ok(())
        })();
        drop(file);
        unsafe { LocalFree(sd as HLOCAL) };
        result
    }

    /// Apply the protected, owner-only DACL to a **directory** (4CP-AG / AF-2).
    ///
    /// The DACL is the same in intent as the file DACL — SYSTEM, Administrators
    /// and the current user, `D:P`, no generic principals — but it is applied to
    /// the *directory* so no third party can create, rename or replace entries
    /// inside it (in particular `node_identity.json`).
    ///
    /// Inheritance flags (`OI`/`CI`) are deliberately **not** added: every
    /// identity file is created with its own explicit protected DACL, so the
    /// directory does not need to propagate one (and propagating one could
    /// surprise unrelated node data). The whole descriptor (with the protected
    /// bit set by `D:P`) is applied with `SetFileSecurityW`; setting a protected
    /// DACL by pointer with `SetNamedSecurityInfoW` is refused with
    /// `ERROR_ACCESS_DENIED` on this host, so it is not used.
    pub(super) fn harden_directory(path: &Path) -> io::Result<()> {
        use windows_sys::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };

        let sd = build_protected_sd()?;
        let wide = to_wide(path.as_os_str());
        let ok = unsafe {
            SetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd,
            )
        };
        let err = if ok == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe { LocalFree(sd as HLOCAL) };
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Create a **directory** with the protected owner-only DACL applied by the
    /// kernel at creation (4CP-AI / AH-1), so there is no window in which the
    /// directory exists with inherited (possibly broad) permissions.
    ///
    /// A directory that already exists is not an error here: creation races and
    /// pre-existing directories are resolved by the caller, which re-validates
    /// and hardens the winner.
    pub(super) fn create_private_directory(path: &Path) -> io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

        let sd = build_protected_sd()?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let wide = to_wide(path.as_os_str());
        let ok = unsafe { CreateDirectoryW(wide.as_ptr(), &sa) };
        let err = if ok == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        unsafe { LocalFree(sd as HLOCAL) };
        match err {
            // ERROR_ALREADY_EXISTS (183): a concurrent creator, or a directory
            // that already existed; the caller validates/hardens it.
            Some(e) if e.raw_os_error() == Some(183) => Ok(()),
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// The owner SID (SDDL string) of `path`, read from the kernel.
    fn owner_sid_string(path: &Path) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
        unsafe {
            let wide = to_wide(path.as_os_str());
            let mut owner: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let err = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            let mut str_ptr: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(owner, &mut str_ptr) == 0 {
                let e = io::Error::last_os_error();
                LocalFree(sd as HLOCAL);
                return Err(e);
            }
            let sid = read_wide_z(str_ptr);
            LocalFree(str_ptr as HLOCAL);
            LocalFree(sd as HLOCAL);
            Ok(sid)
        }
    }

    /// Refuse a directory owned by a principal other than the current user,
    /// SYSTEM, Administrators or a service SID (e.g. TrustedInstaller): such a
    /// shared directory could be replaced by another local user (4CP-AI / AH-2).
    pub(super) fn verify_trusted_owner(path: &Path) -> io::Result<()> {
        let owner = owner_sid_string(path)?;
        let current = current_user_sid_string()?;
        let trusted = owner == current
            || owner == "S-1-5-18" // LOCAL SYSTEM
            || owner == "S-1-5-32-544" // BUILTIN\Administrators
            || owner.starts_with("S-1-5-80-"); // service SIDs (e.g. TrustedInstaller)
        if !trusted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is owned by {}, which is not the current user, SYSTEM or Administrators",
                    path.display(),
                    owner
                ),
            ));
        }
        Ok(())
    }

    /// Test-only: the current user's SID string.
    #[cfg(test)]
    pub(super) fn current_user_sid() -> io::Result<String> {
        current_user_sid_string()
    }

    /// Test-only: read back the DACL of an existing file from the kernel.
    /// Returns `(dacl_protected, dacl_sddl_string)`.
    #[cfg(test)]
    pub(super) fn read_dacl(path: &Path) -> io::Result<(bool, String)> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{
            GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        };
        unsafe {
            let wide = to_wide(path.as_os_str());
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let err = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            if err != 0 {
                return Err(io::Error::from_raw_os_error(err as i32));
            }

            let mut control: u16 = 0;
            let mut revision: u32 = 0;
            let protected = GetSecurityDescriptorControl(sd, &mut control, &mut revision) != 0
                && (control & SE_DACL_PROTECTED) != 0;

            let mut str_ptr: *mut u16 = std::ptr::null_mut();
            let mut str_len: u32 = 0;
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut str_ptr,
                &mut str_len,
            );
            if ok == 0 {
                let e = io::Error::last_os_error();
                LocalFree(sd as HLOCAL);
                return Err(e);
            }
            let sddl = read_wide_z(str_ptr);
            LocalFree(str_ptr as HLOCAL);
            LocalFree(sd as HLOCAL);
            Ok((protected, sddl))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn read_identity_file(dir: &Path) -> String {
        std::fs::read_to_string(identity_path(dir)).expect("identity file must exist")
    }

    #[test]
    fn creates_identity_in_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, outcome) = load_or_create(dir.path()).unwrap();
        assert_eq!(outcome, IdentityOutcome::Created);
        assert!(identity_path(dir.path()).exists());
        // The on-disk id must match the in-memory id.
        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.node_id(), identity.node_id());
    }

    #[test]
    fn node_id_is_stable_across_repeated_loads() {
        let dir = tempfile::tempdir().unwrap();
        let (first, _) = load_or_create(dir.path()).unwrap();
        for _ in 0..5 {
            let again = load(dir.path()).unwrap();
            assert_eq!(again.node_id(), first.node_id());
        }
    }

    #[test]
    fn node_id_is_stable_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let (identity, _) = load_or_create(dir.path()).unwrap();
            identity.node_id()
        };
        // Drop everything, then reopen from disk only.
        let (reopened, outcome) = load_or_create(dir.path()).unwrap();
        assert_eq!(outcome, IdentityOutcome::Loaded);
        assert_eq!(reopened.node_id(), id);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let message = b"phase-4cn test message";
        let sig = identity.sign_message(message);
        assert!(verify_message(&identity.node_id(), message, &sig));
    }

    #[test]
    fn rejects_incorrect_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let id = identity.node_id();

        // Wrong message.
        let sig = identity.sign_message(b"alpha");
        assert!(!verify_message(&id, b"beta", &sig));

        // Flipped signature byte.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify_message(&id, b"alpha", &bad));

        // Wrong key.
        let other = NodeIdentity::generate();
        assert!(!verify_message(&other.node_id(), b"alpha", &sig));
    }

    #[test]
    fn network_identity_is_separate_from_wallet_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();

        // A wallet keypair is a distinct identity and must not collide with the
        // network identity.
        let wallet = crate::wallet::Wallet::new();
        let wallet_pub = wallet.public_key_bytes();
        assert_eq!(wallet_pub.len(), 32);
        assert_ne!(
            identity.node_id().as_bytes().as_slice(),
            wallet_pub.as_slice()
        );

        // The network identity lives in its own file, never a wallet path.
        let path = identity_path(dir.path());
        assert_eq!(path.file_name().unwrap(), NODE_IDENTITY_FILE_NAME);
        assert!(!path.to_string_lossy().contains("wallet"));
    }

    #[test]
    fn rejects_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(identity_path(dir.path()), "this is not json").unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Malformed(_)), "got {:?}", err);
    }

    #[test]
    fn rejects_truncated_file() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let full = read_identity_file(dir.path());
        // Truncate mid-JSON.
        std::fs::write(identity_path(dir.path()), &full[..full.len() / 2]).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Malformed(_)), "got {:?}", err);
        // The id must still be derivable from the in-memory copy.
        drop(identity);
    }

    #[test]
    fn rejects_unsupported_version() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let secret = hex::encode(identity.signing_key.to_bytes());
        let id = identity.node_id().to_hex();
        let forged = format!(
            "{{\"version\":999,\"node_id\":\"{}\",\"secret_key\":\"{}\"}}",
            id, secret
        );
        std::fs::write(identity_path(dir.path()), forged).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(
            matches!(err, IdentityError::UnsupportedVersion(999)),
            "got {:?}",
            err
        );
    }

    #[test]
    fn rejects_inconsistent_node_id() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let secret = hex::encode(identity.signing_key.to_bytes());
        // Valid hex, 32 bytes, but does not match the secret.
        let wrong_id = hex::encode([7u8; 32]);
        let forged = format!(
            "{{\"version\":{},\"node_id\":\"{}\",\"secret_key\":\"{}\"}}",
            NODE_IDENTITY_FILE_VERSION, wrong_id, secret
        );
        std::fs::write(identity_path(dir.path()), forged).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Corrupt(_)), "got {:?}", err);
    }

    #[test]
    fn rejects_wrong_length_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let id = identity.node_id().to_hex();
        let forged = format!(
            "{{\"version\":{},\"node_id\":\"{}\",\"secret_key\":\"abcd\"}}",
            NODE_IDENTITY_FILE_VERSION, id
        );
        std::fs::write(identity_path(dir.path()), forged).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Corrupt(_)), "got {:?}", err);
    }

    #[test]
    fn invalid_identity_is_not_silently_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        let corrupt = "{\"version\":1,\"node_id\":\"zz\",\"secret_key\":\"zz\"}";
        std::fs::write(&path, corrupt).unwrap();
        let before = std::fs::read(&path).unwrap();

        let err = load_or_create(dir.path()).unwrap_err();
        assert!(
            matches!(err, IdentityError::Corrupt(_) | IdentityError::Malformed(_)),
            "got {:?}",
            err
        );

        // File bytes must be untouched: no silent replacement.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after, "corrupt identity must not be overwritten");
    }

    #[test]
    fn preserves_existing_private_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (first, _) = load_or_create(dir.path()).unwrap();
        let bytes_before = std::fs::read(identity_path(dir.path())).unwrap();
        let secret_before = hex::encode(first.signing_key.to_bytes());
        drop(first);

        let (second, outcome) = load_or_create(dir.path()).unwrap();
        assert_eq!(outcome, IdentityOutcome::Loaded);
        let bytes_after = std::fs::read(identity_path(dir.path())).unwrap();
        assert_eq!(bytes_before, bytes_after, "existing identity bytes changed");
        assert_eq!(secret_before, hex::encode(second.signing_key.to_bytes()));
    }

    #[test]
    fn concurrent_creation_is_race_safe() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf());
        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    load_or_create(&path).unwrap().0.node_id()
                })
            })
            .collect();

        let ids: Vec<NodeId> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // All contenders must converge on the single winner on disk.
        for id in &ids {
            assert_eq!(*id, ids[0], "concurrent creators disagreed on the node id");
        }
        let on_disk = load(&path).unwrap().node_id();
        assert_eq!(on_disk, ids[0]);
    }

    #[test]
    fn diagnostics_never_expose_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let (identity, _) = load_or_create(dir.path()).unwrap();
        let secret_hex = hex::encode(identity.signing_key.to_bytes());

        let debug = format!("{:?}", identity);
        let display_id = format!("{}", identity.node_id());
        assert!(!debug.contains(&secret_hex), "Debug leaked the secret key");
        assert!(!display_id.contains(&secret_hex));
        assert!(debug.contains("<redacted>"));

        // Error paths must not embed file contents either.
        std::fs::write(identity_path(dir.path()), &secret_hex).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(!format!("{}", err).contains(&secret_hex));
        assert!(!format!("{:?}", err).contains(&secret_hex));
    }

    /// Unix-only: assert the identity file is owner-only (0600).
    ///
    /// On Windows the Unix mode bits do not exist, so this test is compiled out
    /// and reported as NOT EXECUTED there rather than counted as a pass.
    #[test]
    #[cfg(unix)]
    fn permissions_are_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _ = load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(identity_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "identity file must be 0600, got {:o}", mode);
    }

    /// Assert a read-back Windows DACL grants only the intended principals and
    /// denies the generic ones. Inspects the actual DACL, not an API's return
    /// code.
    #[cfg(windows)]
    fn assert_windows_dacl_is_restricted(sddl: &str, protected: bool) {
        assert!(
            protected,
            "DACL must be protected against inheritance, got SDDL: {}",
            sddl
        );

        let user = super::win_acl::current_user_sid().unwrap();
        assert!(
            sddl.contains(&user),
            "current user SID ({}) must be granted, got SDDL: {}",
            user,
            sddl
        );

        let grants_system = sddl.contains(";;;SY)") || sddl.contains("S-1-5-18");
        let grants_admins = sddl.contains(";;;BA)") || sddl.contains("S-1-5-32-544");
        assert!(grants_system, "SYSTEM must be granted, got SDDL: {}", sddl);
        assert!(
            grants_admins,
            "Administrators must be granted, got SDDL: {}",
            sddl
        );

        let grants_everyone = sddl.contains(";;;WD)") || sddl.contains("S-1-1-0");
        let grants_users = sddl.contains(";;;BU)") || sddl.contains("S-1-5-32-545");
        let grants_auth_users = sddl.contains(";;;AU)") || sddl.contains("S-1-5-11");
        assert!(
            !grants_everyone,
            "Everyone must be denied, got SDDL: {}",
            sddl
        );
        assert!(!grants_users, "Users must be denied, got SDDL: {}", sddl);
        assert!(
            !grants_auth_users,
            "Authenticated Users must be denied, got SDDL: {}",
            sddl
        );

        // Exactly the three intended ACEs; no extra inherited/allow entries.
        let ace_count = sddl.matches("(A;").count();
        assert_eq!(ace_count, 3, "expected 3 allow ACEs, got SDDL: {}", sddl);
    }

    /// Windows-only: the persisted identity file must carry a protected,
    /// restricted DACL, inspected from the kernel.
    #[test]
    #[cfg(windows)]
    fn windows_identity_file_has_protected_restricted_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let _ = load_or_create(dir.path()).unwrap();
        let (protected, sddl) = super::win_acl::read_dacl(&identity_path(dir.path())).unwrap();
        assert_windows_dacl_is_restricted(&sddl, protected);
    }

    /// Windows-only: the staging temporary must be protected *before* the
    /// secret is written. This exercises the same creation primitive the atomic
    /// publish path uses.
    #[test]
    #[cfg(windows)]
    fn windows_staging_file_is_protected_before_publish() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join(".node_identity.staging.tmp");
        super::win_acl::create_private_new(&staging, "staging-bytes").unwrap();
        let (protected, sddl) = super::win_acl::read_dacl(&staging).unwrap();
        assert_windows_dacl_is_restricted(&sddl, protected);
    }

    /// Windows-only: concurrent creation must not weaken the published file's
    /// protection, and must not overwrite the winner.
    #[test]
    #[cfg(windows)]
    fn windows_concurrent_creation_keeps_protection() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf());
        let threads = 6usize;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    load_or_create(&path).unwrap().0.node_id()
                })
            })
            .collect();
        let ids: Vec<NodeId> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for id in &ids {
            assert_eq!(*id, ids[0]);
        }
        let (protected, sddl) = super::win_acl::read_dacl(&identity_path(&path)).unwrap();
        assert_windows_dacl_is_restricted(&sddl, protected);
    }

    // -----------------------------------------------------------------------
    // 4CP-AE: staging-file hygiene, atomic-publish guarantees, symlink refusal
    // -----------------------------------------------------------------------

    /// Names in `dir` that match the exact staging-file format.
    fn staging_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                parse_staging_name(&name).map(|_| name)
            })
            .collect()
    }

    fn staging_name(pid: u32, nanos: u64, seq: u64) -> String {
        format!("{}.{}.{}.{}.tmp", NODE_IDENTITY_FILE_NAME, pid, nanos, seq)
    }

    /// The parser must accept exactly the produced shape and nothing else, so an
    /// unrelated file can never be mistaken for (or deleted as) a staging file.
    #[test]
    fn staging_name_parser_is_strict() {
        assert_eq!(parse_staging_name(&staging_name(1234, 99, 7)), Some(1234));
        assert_eq!(parse_staging_name(NODE_IDENTITY_FILE_NAME), None);
        assert_eq!(parse_staging_name("node_identity.json.tmp"), None);
        assert_eq!(parse_staging_name("node_identity.json.12.34.tmp"), None);
        assert_eq!(parse_staging_name("node_identity.json.a.34.5.tmp"), None);
        assert_eq!(parse_staging_name("node_identity.json.12.34.5.6.tmp"), None);
        assert_eq!(parse_staging_name("node_identity.json.12.34.-5.tmp"), None);
        assert_eq!(parse_staging_name("dag.12.34.5.tmp"), None);
        assert_eq!(parse_staging_name("node_identity.json.12.34.5.tmp.bak"), None);
    }

    /// A failed (partial) staging write must leave no staging file and must
    /// never create the final file.
    #[test]
    fn partial_write_failure_cleans_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        let err = persist_new_impl(
            &path,
            "secret",
            &|tmp, _contents| {
                // Simulate a write that created the file, wrote a few bytes, then
                // failed before completion.
                std::fs::write(tmp, b"partial").unwrap();
                Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "injected write failure",
                ))
            },
            &|src, dst| std::fs::hard_link(src, dst),
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        assert!(!path.exists(), "no final file may be created on failure");
        assert!(
            staging_files(dir.path()).is_empty(),
            "the staging file must be cleaned up after a partial write"
        );
    }

    /// A staging file owned by a provably-gone process is removed; one owned by
    /// a live process is kept; unrelated files are never touched.
    #[test]
    fn orphan_staging_removed_but_active_and_unrelated_kept() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir.path().join(staging_name(424242, 1, 0));
        let active = dir.path().join(staging_name(777, 2, 1));
        let unrelated = dir.path().join("dag.json");
        std::fs::write(&orphan, b"orphan").unwrap();
        std::fs::write(&active, b"active").unwrap();
        std::fs::write(&unrelated, b"{}").unwrap();

        let removed = sweep_orphan_staging_files_with(dir.path(), |pid| {
            if pid == 424242 {
                OwnerLiveness::Gone
            } else {
                OwnerLiveness::Alive
            }
        });

        assert_eq!(removed, 1);
        assert!(!orphan.exists(), "orphan must be removed");
        assert!(active.exists(), "a live creator's staging file must be kept");
        assert!(unrelated.exists(), "unrelated files must never be touched");
    }

    /// If liveness cannot be established, the staging file is ALWAYS kept.
    #[test]
    fn unknown_owner_staging_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join(staging_name(7, 3, 2));
        std::fs::write(&f, b"x").unwrap();
        let removed = sweep_orphan_staging_files_with(dir.path(), |_| OwnerLiveness::Unknown);
        assert_eq!(removed, 0);
        assert!(f.exists(), "an unknown owner must never cause deletion");
    }

    /// The real liveness probe (not the injectable one) must see the current
    /// process as alive and a just-exited child as gone.
    #[test]
    #[cfg(any(target_os = "linux", windows))]
    fn process_liveness_detects_exited_child_as_gone() {
        use std::process::Command;
        #[cfg(windows)]
        let mut child = Command::new("cmd")
            .args(["/C", "exit", "0"])
            .spawn()
            .expect("spawn child");
        #[cfg(unix)]
        let mut child = Command::new("true").spawn().expect("spawn child");
        let pid = child.id();
        child.wait().expect("wait child");

        assert_eq!(
            process_liveness(std::process::id()),
            OwnerLiveness::Alive,
            "the current process must be seen as alive"
        );
        assert_eq!(
            process_liveness(pid),
            OwnerLiveness::Gone,
            "an exited child must be seen as gone"
        );
    }

    /// Concurrent creation must converge on one winner AND leave no staging
    /// file behind (the losing candidates are cleaned up).
    #[test]
    fn concurrent_creation_leaves_no_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().to_path_buf());
        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    load_or_create(&path).unwrap().0.node_id()
                })
            })
            .collect();
        let ids: Vec<NodeId> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for id in &ids {
            assert_eq!(*id, ids[0], "concurrent creators disagreed on the node id");
        }
        assert!(
            staging_files(dir.path()).is_empty(),
            "no staging file may survive creation"
        );
    }

    /// A filesystem without an atomic no-replace publish must be refused
    /// explicitly: the final file is never written non-atomically, and the
    /// staging file is still cleaned up.
    #[test]
    fn publish_without_atomic_no_replace_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        let err = persist_new_impl(
            &path,
            "secret-bytes",
            &write_private_new,
            &|_src, _dst| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "no hard links on this filesystem",
                ))
            },
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        assert!(
            !path.exists(),
            "no non-atomic fallback may create the final file"
        );
        assert!(
            staging_files(dir.path()).is_empty(),
            "staging must be cleaned even when publish is refused"
        );
    }

    /// A directory (any non-regular file) at the identity path is refused.
    #[test]
    fn rejects_non_regular_identity_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        std::fs::create_dir(&path).unwrap();

        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        let err2 = load_or_create(dir.path()).unwrap_err();
        assert!(matches!(err2, IdentityError::Io(_)), "got {:?}", err2);
        assert!(path.is_dir(), "the path must not be replaced");
    }

    /// A symlink at the identity path is refused without reading the target.
    ///
    /// Unix-only: creating a symlink is unconditional there. Windows symlink
    /// creation needs a privilege (or Developer Mode), so the Windows variant
    /// documents a skip instead of faking a pass.
    #[test]
    #[cfg(unix)]
    fn rejects_symlinked_identity_file_without_reading_target() {
        use std::os::unix::fs::symlink;

        let victim = tempfile::tempdir().unwrap();
        let (victim_id, _) = load_or_create(victim.path()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        symlink(identity_path(victim.path()), identity_path(dir.path())).unwrap();

        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        let err2 = load_or_create(dir.path()).unwrap_err();
        assert!(matches!(err2, IdentityError::Io(_)), "got {:?}", err2);

        // The target identity is untouched and the symlink was not replaced.
        assert_eq!(load(victim.path()).unwrap().node_id(), victim_id.node_id());
        assert!(std::fs::symlink_metadata(identity_path(dir.path()))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// Windows variant: verify symlink refusal only if the symlink could really
    /// be created.
    #[test]
    #[cfg(windows)]
    fn rejects_symlinked_identity_file_without_reading_target_windows() {
        use std::os::windows::fs::symlink_file;

        let victim = tempfile::tempdir().unwrap();
        let (victim_id, _) = load_or_create(victim.path()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        if let Err(e) = symlink_file(identity_path(victim.path()), identity_path(dir.path())) {
            eprintln!(
                "SKIP rejects_symlinked_identity_file_without_reading_target_windows: cannot \
                 create a symlink on this host ({}); Windows symlink rejection is NOT verified \
                 here (it is covered by the Unix test on hosts that permit symlinks).",
                e
            );
            return;
        }

        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        let err2 = load_or_create(dir.path()).unwrap_err();
        assert!(matches!(err2, IdentityError::Io(_)), "got {:?}", err2);
        assert_eq!(load(victim.path()).unwrap().node_id(), victim_id.node_id());
    }

    // -----------------------------------------------------------------------
    // 4CP-AG: identity directory protection (AF-2)
    // -----------------------------------------------------------------------

    /// The identity directory path being a regular file (any non-directory) is
    /// refused, on every platform.
    #[test]
    fn rejects_identity_directory_that_is_a_file() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("not-a-directory");
        std::fs::write(&dir, b"x").unwrap();

        let err = load_or_create(&dir).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        let err2 = load(&dir).unwrap_err();
        assert!(matches!(err2, IdentityError::Io(_)), "got {:?}", err2);
        assert!(dir.is_file(), "the path must not be replaced");
    }

    /// An existing directory that is traversable but not writable by group or
    /// other (0755) passes the unsafe-path policy and is then hardened to
    /// owner-only by `load_or_create` (AF-2). A directory that IS writable by
    /// group or other (0777) without the sticky bit is refused instead, see
    /// `refuses_group_writable_identity_directory_without_sticky_on_unix`.
    #[test]
    #[cfg(unix)]
    fn identity_directory_is_hardened_to_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let _ = load_or_create(dir.path()).unwrap();

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "identity directory must be 0700, got {:o}", mode);
    }

    /// A group/world-writable directory without the sticky bit (0777) is refused
    /// **before** any secret is written or read (fail-closed policy, 4CP-AG /
    /// AF-2): no staging or identity file is created, and a pre-existing
    /// identity is neither read, replaced nor altered.
    #[test]
    #[cfg(unix)]
    fn refuses_group_writable_identity_directory_without_sticky_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = identity_path(dir.path());
        // A pre-existing artifact at the identity path that must survive the
        // refused attempt byte-for-byte.
        let sentinel = b"pre-existing-identity-must-not-be-touched";
        std::fs::write(&path, sentinel).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let err = load_or_create(dir.path()).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);

        assert_eq!(
            std::fs::read(&path).unwrap(),
            sentinel,
            "a refused directory must not alter an existing identity"
        );
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(NODE_IDENTITY_FILE_NAME)],
            "a refused directory must not gain any file, got {:?}",
            entries
        );
    }

    /// `load` also refuses an unsecurable (here: symlinked) directory and never
    /// follows it to create or read anything.
    #[test]
    #[cfg(unix)]
    fn refuses_symlinked_identity_directory_on_unix() {
        use std::os::unix::fs::symlink;
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("identity-dir-link");
        symlink(real.path(), &link).unwrap();

        let err = load_or_create(&link).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        assert!(
            !identity_path(real.path()).exists(),
            "nothing may be created through a symlinked directory"
        );
        assert!(load(&link).is_err());
    }

    /// A brand-new (nested) identity directory is created owner-only.
    #[test]
    #[cfg(unix)]
    fn creates_new_identity_directory_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("nested").join("data");

        let _ = load_or_create(&dir).unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "created identity directory must be 0700, got {:o}",
            mode
        );
    }

    /// Windows: the identity directory must carry a protected, restricted DACL.
    #[test]
    #[cfg(windows)]
    fn windows_identity_directory_has_protected_restricted_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let _ = load_or_create(dir.path()).unwrap();
        let (protected, sddl) = super::win_acl::read_dacl(dir.path()).unwrap();
        assert_windows_dacl_is_restricted(&sddl, protected);
    }

    /// Windows: a directory symlink at the identity path is refused. Skipped
    /// (explicitly) when the host cannot create a directory symlink.
    #[test]
    #[cfg(windows)]
    fn windows_refuses_reparse_point_identity_directory() {
        use std::os::windows::fs::symlink_dir;
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("identity-dir-link");
        if let Err(e) = symlink_dir(real.path(), &link) {
            eprintln!(
                "SKIP windows_refuses_reparse_point_identity_directory: cannot create a \
                 directory symlink on this host ({}); reparse-point rejection is NOT verified \
                 here (it is covered by the Unix test on hosts that permit symlinks).",
                e
            );
            return;
        }
        let err = load_or_create(&link).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        assert!(!identity_path(real.path()).exists());
    }

    // -----------------------------------------------------------------------
    // 4CP-AI (AH-1 / AH-2): secure creation at the real startup point, and the
    // path/ancestor policy.
    // -----------------------------------------------------------------------

    /// A brand-new directory is protected **at creation** by the single secure
    /// entry point: Unix `0700`, Windows a protected restricted DACL read back
    /// from the kernel (4CP-AI / AH-1).
    #[test]
    fn ensure_secure_data_dir_protects_a_new_directory() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("fresh-data");

        ensure_secure_data_dir(&dir).unwrap();
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "new data dir must be 0700, got {:o}", mode);
        }
        #[cfg(windows)]
        {
            let (protected, sddl) = super::win_acl::read_dacl(&dir).unwrap();
            assert_windows_dacl_is_restricted(&sddl, protected);
        }
    }

    /// Windows: the creation primitive itself (no post-hoc hardening) must yield
    /// a protected, restricted DACL, proving the ACL is applied **at creation**
    /// (4CP-AI / AH-1, test 1).
    #[test]
    #[cfg(windows)]
    fn windows_create_private_directory_applies_dacl_at_creation() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("created-at-once");

        super::win_acl::create_private_directory(&dir).unwrap();

        let (protected, sddl) = super::win_acl::read_dacl(&dir).unwrap();
        assert_windows_dacl_is_restricted(&sddl, protected);
    }

    /// The node startup's real creation point (`ensure_data_dir`) must not
    /// create the directory with ordinary permissions and harden it afterwards
    /// (4CP-AI / AH-2, test 4).
    #[tokio::test]
    async fn startup_creation_point_is_protected() {
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("startup-data");

        crate::json_storage::ensure_data_dir(&dir).await.unwrap();
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "startup data dir must be 0700, got {:o}", mode);
        }
        #[cfg(windows)]
        {
            let (protected, sddl) = super::win_acl::read_dacl(&dir).unwrap();
            assert_windows_dacl_is_restricted(&sddl, protected);
        }
    }

    /// An existing valid identity survives a re-secure unchanged (test 6).
    #[test]
    fn ensure_secure_data_dir_preserves_an_existing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (first, outcome) = load_or_create(dir.path()).unwrap();
        assert_eq!(outcome, IdentityOutcome::Created);

        ensure_secure_data_dir(dir.path()).unwrap();

        let (second, outcome2) = load_or_create(dir.path()).unwrap();
        assert_eq!(outcome2, IdentityOutcome::Loaded);
        assert_eq!(first.node_id(), second.node_id());
        assert!(identity_path(dir.path()).exists());
    }

    /// A parent that is a regular file is refused on every platform (test 5).
    #[test]
    fn refuses_parent_that_is_a_file() {
        let parent = tempfile::tempdir().unwrap();
        let file = parent.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let dir = file.join("data");

        let err = ensure_secure_data_dir(&dir).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
    }

    /// Unix: a group/world-writable parent without the sticky bit is refused
    /// (test 5). NOT EXECUTED on Windows.
    #[test]
    #[cfg(unix)]
    fn refuses_group_writable_parent_without_sticky_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let holder = tempfile::tempdir().unwrap();
        let unsafe_parent = holder.path().join("unsafe");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let dir = unsafe_parent.join("data");

        let err = ensure_secure_data_dir(&dir).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        assert!(!dir.exists(), "nothing may be created under an unsafe parent");
    }

    /// Unix: a sticky world-writable parent (e.g. `/tmp`) is accepted, and the
    /// created leaf is still owner-only (test 5). NOT EXECUTED on Windows.
    #[test]
    #[cfg(unix)]
    fn allows_sticky_world_writable_parent_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let holder = tempfile::tempdir().unwrap();
        let sticky = holder.path().join("sticky");
        std::fs::create_dir(&sticky).unwrap();
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let dir = sticky.join("data");

        ensure_secure_data_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "created leaf must be 0700, got {:o}", mode);
    }

    /// Windows: a reparse point anywhere in the path is refused. Skipped
    /// (explicitly) when the host cannot create a reparse point.
    #[test]
    #[cfg(windows)]
    fn windows_refuses_reparse_point_parent() {
        use std::os::windows::fs::symlink_dir;
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("reparse-parent");
        if let Err(e) = symlink_dir(real.path(), &link) {
            eprintln!(
                "SKIP windows_refuses_reparse_point_parent: cannot create a reparse point on \
                 this host ({}); reparse-point path rejection is NOT verified here.",
                e
            );
            return;
        }
        let dir = link.join("data");
        let err = ensure_secure_data_dir(&dir).unwrap_err();
        assert!(matches!(err, IdentityError::Io(_)), "got {:?}", err);
        assert!(!dir.exists());
    }
}
