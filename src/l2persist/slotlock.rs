//! Atomic vote-slot reservation.
//!
//! # The defect this replaces
//!
//! Mission AT persisted a vote commitment with `Storage::put_metadata`, which is
//! an unconditional `sled` insert, and decided *before* writing:
//!
//! ```text
//! load(slot) -> None -> record(slot)        // two writers both see None
//! ```
//!
//! Two concurrent writers therefore both observe an empty slot, both write, and
//! the second silently replaces the first: one process keeps equivocating and
//! the evidence is destroyed. Sharing an in-process `Mutex` does not help across
//! processes and a `load` before `record` does not help across threads.
//!
//! # What replaces it
//!
//! One key per slot, one record per key, and every transition is a **single**
//! compare-and-swap (`sled::Tree::compare_and_swap`, exposed as
//! `Storage::compare_and_swap_metadata`):
//!
//! | Transition | CAS |
//! |---|---|
//! | empty -> reserved | expected `None`, new `Reserved` |
//! | reserved -> signed | expected `Reserved` bytes, new `Signed` bytes |
//!
//! Exactly one racing writer can observe the expected value, so exactly one
//! decision wins. The loser learns the winner's value and reports
//! [`ReserveOutcome::Conflicting`] — it never overwrites it, so evidence is
//! never destroyed.
//!
//! # Cross-process
//!
//! `sled` is a single-process database: two processes opening one directory is
//! undefined behaviour, so per-process CAS is not enough. [`SledAtomicSlotStore`]
//! therefore takes an **exclusive lock file** before opening the database and
//! **fails closed** ([`SlotStoreError::StoreLocked`]) if another process holds
//! it. This is exclusion, not a distributed CAS, and it is claimed as nothing
//! more: the second process cannot reserve anything at all.
//!
//! # Corruption
//!
//! Every record is sealed in an envelope carrying its length and a BLAKE3
//! digest, so truncated or bit-rotted records are detected instead of being
//! decoded into a plausible-looking reservation.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, Round, ValidatorId};
use crate::l2crypto::vote::{ConsensusVote, VotePhase};
use crate::storage::{Storage, StorageError};

/// Version of the slot record encoding.
pub const SLOT_FORMAT_VERSION: u8 = 1;

/// Metadata key prefix for slot records.
///
/// Namespaced `v2` so it cannot collide with AT's `l2crypto/v1/lock/` keys,
/// which stay readable for forensics.
pub const SLOT_PREFIX: &str = "l2/v2/atomic/";

/// Name of the exclusive-access lock file inside the store directory.
pub const STORE_LOCK_FILE: &str = "l2-bft.lock";

/// Compare-and-swap attempts before a store gives up.
///
/// A conflict means another writer won between our read and our swap. With a
/// single logical writer a retry almost always succeeds on the second attempt;
/// a store that keeps losing is reported rather than spun on forever.
pub const CAS_ATTEMPTS: u32 = 16;

const ENVELOPE_MAGIC: &[u8; 4] = b"AU01";
const ENVELOPE_HEADER: usize = 4 + 4 + 32;

/// Failures of the slot layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlotStoreError {
    /// Underlying storage failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// Stored bytes are not a valid, self-consistent record.
    #[error("corrupt slot record: {0}")]
    Corrupt(String),

    /// Another process holds the store.
    #[error("vote store is held by another process (pid {pid})")]
    StoreLocked {
        /// PID recorded in the lock file, `0` if unreadable.
        pid: u32,
    },

    /// The compare-and-swap never settled.
    #[error("compare-and-swap did not settle after {attempts} attempts")]
    CasUnstable {
        /// Attempts made.
        attempts: u32,
    },
}

/// Seal a payload in a length-and-digest envelope.
pub fn seal(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_HEADER + payload.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(blake3::hash(payload).as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Open a sealed envelope, verifying magic, length and digest.
///
/// Any mismatch is [`SlotStoreError::Corrupt`]: a half-written or rotted record
/// must never be read as a valid reservation.
pub fn open_sealed(bytes: &[u8]) -> Result<&[u8], SlotStoreError> {
    if bytes.len() < ENVELOPE_HEADER {
        return Err(SlotStoreError::Corrupt(format!(
            "envelope shorter than header ({} bytes)",
            bytes.len()
        )));
    }
    if &bytes[0..4] != ENVELOPE_MAGIC {
        return Err(SlotStoreError::Corrupt("bad envelope magic".to_string()));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[4..8]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if bytes.len() != ENVELOPE_HEADER + len {
        return Err(SlotStoreError::Corrupt(format!(
            "envelope length {} does not match payload length {}",
            bytes.len(),
            len
        )));
    }
    let payload = &bytes[ENVELOPE_HEADER..];
    if blake3::hash(payload).as_bytes() != &bytes[8..40] {
        return Err(SlotStoreError::Corrupt(
            "envelope digest does not match payload".to_string(),
        ));
    }
    Ok(payload)
}

/// The five fields that define a vote slot.
///
/// A validator may commit **one** checkpoint id per slot. `checkpoint_id` is
/// deliberately absent: two votes for different checkpoints in one slot are the
/// very thing this type exists to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotKey {
    /// Generation the vote belongs to.
    pub generation: [u8; 32],
    /// Checkpoint height.
    pub height: CheckpointHeight,
    /// Round.
    pub round: Round,
    /// Phase.
    pub phase: VotePhase,
    /// Voting validator.
    pub validator: ValidatorId,
}

impl SlotKey {
    /// Derive the slot of a vote.
    pub fn of(vote: &ConsensusVote) -> Self {
        Self {
            generation: vote.generation.0,
            height: vote.height,
            round: vote.round,
            phase: vote.phase,
            validator: vote.validator,
        }
    }

    /// Canonical encoding: `gen(32) ‖ height(8) ‖ round(4) ‖ phase(1) ‖ validator(32)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(77);
        out.extend_from_slice(&self.generation);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.round.get().to_le_bytes());
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.validator.0);
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, SlotStoreError> {
        if bytes.len() != 77 {
            return Err(SlotStoreError::Corrupt(format!(
                "slot key length {} != 77",
                bytes.len()
            )));
        }
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[0..32]);
        let mut h = [0u8; 8];
        h.copy_from_slice(&bytes[32..40]);
        let mut r = [0u8; 4];
        r.copy_from_slice(&bytes[40..44]);
        let phase = VotePhase::from_u8(bytes[44])
            .ok_or_else(|| SlotStoreError::Corrupt(format!("unknown phase {}", bytes[44])))?;
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&bytes[45..77]);
        Ok(Self {
            generation,
            height: CheckpointHeight(u64::from_le_bytes(h)),
            round: Round(u32::from_le_bytes(r)),
            phase,
            validator: ValidatorId(validator),
        })
    }

    /// Storage key: the content address of the slot.
    pub fn storage_key(&self) -> String {
        format!(
            "{}{}",
            SLOT_PREFIX,
            hex::encode(blake3::hash(&self.encode()).as_bytes())
        )
    }
}

/// Whether the record holds only a reservation or also the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// Reserved, possibly signed by a process that died before recording.
    Reserved,
    /// Signed and recorded.
    Signed,
}

impl SlotState {
    fn as_u8(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::Signed => 1,
        }
    }

    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Reserved,
            1 => Self::Signed,
            _ => return None,
        })
    }
}

/// One slot record: what was reserved, and the signature if it was emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotReservation {
    /// Slot.
    pub slot: SlotKey,
    /// Checkpoint the validator committed to.
    pub checkpoint_id: [u8; 32],
    /// Reservation vs signed.
    pub state: SlotState,
    /// The signed vote, present exactly when `state` is [`SlotState::Signed`].
    pub vote: Option<ConsensusVote>,
}

impl SlotReservation {
    /// Version byte of the payload encoding.
    pub const VERSION: u8 = SLOT_FORMAT_VERSION;

    /// Canonical payload encoding:
    /// `version(1) ‖ slot(77) ‖ checkpoint(32) ‖ state(1) ‖ vote_len(4) ‖ vote`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 77 + 32 + 1 + 4 + 182);
        out.push(Self::VERSION);
        out.extend_from_slice(&self.slot.encode());
        out.extend_from_slice(&self.checkpoint_id);
        out.push(self.state.as_u8());
        match &self.vote {
            Some(v) => {
                let enc = v.encode();
                out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
                out.extend_from_slice(&enc);
            }
            None => out.extend_from_slice(&0u32.to_le_bytes()),
        }
        out
    }

    /// Strict canonical decoding, including the record's own invariants.
    ///
    /// Cross-checks that make a forged or inconsistent record detectable:
    /// the state must agree with the presence of a vote, the vote must belong to
    /// this exact slot and commit this exact checkpoint.
    pub fn decode(bytes: &[u8]) -> Result<Self, SlotStoreError> {
        if bytes.len() < 1 + 77 + 32 + 1 + 4 {
            return Err(SlotStoreError::Corrupt("slot record too short".to_string()));
        }
        if bytes[0] != Self::VERSION {
            return Err(SlotStoreError::Corrupt(format!(
                "unknown slot record version {}",
                bytes[0]
            )));
        }
        let slot = SlotKey::decode(&bytes[1..78])?;
        let mut checkpoint_id = [0u8; 32];
        checkpoint_id.copy_from_slice(&bytes[78..110]);
        let state = SlotState::from_u8(bytes[110])
            .ok_or_else(|| SlotStoreError::Corrupt(format!("unknown slot state {}", bytes[110])))?;
        let mut l = [0u8; 4];
        l.copy_from_slice(&bytes[111..115]);
        let vote_len = u32::from_le_bytes(l) as usize;
        let rest = &bytes[115..];
        if rest.len() != vote_len {
            return Err(SlotStoreError::Corrupt(
                "slot record length does not close the record".to_string(),
            ));
        }
        let vote = if vote_len == 0 {
            None
        } else {
            Some(
                ConsensusVote::decode(rest)
                    .map_err(|e| SlotStoreError::Corrupt(format!("embedded vote: {e}")))?,
            )
        };
        match (state, &vote) {
            (SlotState::Signed, None) => {
                return Err(SlotStoreError::Corrupt(
                    "signed record without a vote".to_string(),
                ))
            }
            (SlotState::Reserved, Some(_)) => {
                return Err(SlotStoreError::Corrupt(
                    "reserved record carrying a vote".to_string(),
                ))
            }
            _ => {}
        }
        if let Some(v) = &vote {
            if SlotKey::of(v) != slot {
                return Err(SlotStoreError::Corrupt(
                    "embedded vote does not belong to this slot".to_string(),
                ));
            }
            if v.checkpoint_id != checkpoint_id {
                return Err(SlotStoreError::Corrupt(
                    "embedded vote commits another checkpoint".to_string(),
                ));
            }
        }
        Ok(Self {
            slot,
            checkpoint_id,
            state,
            vote,
        })
    }
}

/// Result of asking to reserve a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// Nothing was recorded; this caller's value is now the slot's value.
    Granted(SlotReservation),
    /// The slot already holds **this same** checkpoint (idempotent).
    Idempotent(SlotReservation),
    /// The slot holds a **different** checkpoint. Never overwritten.
    Conflicting(SlotReservation),
}

/// Minimal atomic key/value surface needed by the reservation logic.
///
/// Split out so the CAS protocol is written **once** and every backend only has
/// to provide a genuinely atomic primitive.
pub trait CasStore: Send + Sync {
    /// Read a key.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError>;

    /// Install `new` only if the stored value still equals `expected`.
    ///
    /// Must be atomic: `Ok(false)` means "someone else won", never "retry
    /// blindly".
    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError>;

    /// All key/value pairs under `prefix`.
    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError>;

    /// Ask the backing store to persist what it has accepted.
    fn flush(&self) -> Result<(), SlotStoreError>;

    /// Human-readable backend name, for reports.
    fn backend(&self) -> &'static str;
}

/// Reservation protocol, implemented once over [`CasStore`].
pub trait AtomicSlotStore: CasStore {
    /// Reserve `slot` for `checkpoint_id`.
    ///
    /// The decision and the write are one compare-and-swap, so two racing
    /// writers cannot both be [`ReserveOutcome::Granted`].
    fn reserve(
        &self,
        slot: &SlotKey,
        checkpoint_id: &[u8; 32],
    ) -> Result<ReserveOutcome, SlotStoreError> {
        let key = slot.storage_key();
        for _ in 0..CAS_ATTEMPTS {
            let current = match self.get(&key)? {
                None => None,
                Some(bytes) => Some(SlotReservation::decode(open_sealed(&bytes)?)?),
            };
            if let Some(record) = current {
                // Never overwrite: a conflicting value is the evidence.
                return Ok(if record.checkpoint_id == *checkpoint_id {
                    ReserveOutcome::Idempotent(record)
                } else {
                    ReserveOutcome::Conflicting(record)
                });
            }
            let fresh = SlotReservation {
                slot: *slot,
                checkpoint_id: *checkpoint_id,
                state: SlotState::Reserved,
                vote: None,
            };
            if self.cas(&key, None, &seal(&fresh.encode()))? {
                return Ok(ReserveOutcome::Granted(fresh));
            }
            // Lost the race: loop and read the winner's value.
        }
        Err(SlotStoreError::CasUnstable {
            attempts: CAS_ATTEMPTS,
        })
    }

    /// Attach the signature to a reservation: `Reserved -> Signed`.
    ///
    /// Idempotent for the identical vote. Refuses to replace one signature with
    /// another, so a slot can never accumulate two different signed votes.
    fn record_signed(&self, vote: &ConsensusVote) -> Result<SlotReservation, SlotStoreError> {
        let slot = SlotKey::of(vote);
        let key = slot.storage_key();
        for _ in 0..CAS_ATTEMPTS {
            let bytes = self.get(&key)?.ok_or_else(|| {
                SlotStoreError::Corrupt("signed vote without a prior reservation".to_string())
            })?;
            let current = SlotReservation::decode(open_sealed(&bytes)?)?;
            if current.checkpoint_id != vote.checkpoint_id {
                return Err(SlotStoreError::Corrupt(
                    "signing a checkpoint the slot never reserved".to_string(),
                ));
            }
            if let Some(existing) = &current.vote {
                return if existing.id() == vote.id() {
                    Ok(current)
                } else {
                    Err(SlotStoreError::Corrupt(
                        "slot already holds a different signature".to_string(),
                    ))
                };
            }
            let next = SlotReservation {
                slot: current.slot,
                checkpoint_id: current.checkpoint_id,
                state: SlotState::Signed,
                vote: Some(vote.clone()),
            };
            if self.cas(&key, Some(&bytes), &seal(&next.encode()))? {
                return Ok(next);
            }
        }
        Err(SlotStoreError::CasUnstable {
            attempts: CAS_ATTEMPTS,
        })
    }

    /// Read one slot.
    fn load(&self, slot: &SlotKey) -> Result<Option<SlotReservation>, SlotStoreError> {
        match self.get(&slot.storage_key())? {
            None => Ok(None),
            Some(bytes) => Ok(Some(SlotReservation::decode(open_sealed(&bytes)?)?)),
        }
    }

    /// Read every slot record, for startup recovery.
    ///
    /// Also verifies that each record sits under the key derived from its own
    /// slot: a record stored under the wrong key would otherwise hide a
    /// reservation and let the node vote twice.
    fn scan_slots(&self) -> Result<Vec<SlotReservation>, SlotStoreError> {
        let mut out = Vec::new();
        for (key, bytes) in self.scan(SLOT_PREFIX)? {
            let record = SlotReservation::decode(open_sealed(&bytes)?)?;
            if record.slot.storage_key() != key {
                return Err(SlotStoreError::Corrupt(format!(
                    "record for slot {} is stored under {}",
                    hex::encode(record.slot.encode()),
                    key
                )));
            }
            out.push(record);
        }
        Ok(out)
    }
}

/// In-memory CAS store.
///
/// **Atomic**: the whole read-compare-write runs under one mutex, which is what
/// makes it a genuine compare-and-swap for threads. **Not durable and not
/// multi-process** — tests and simulation only.
#[derive(Debug, Default)]
pub struct MemoryAtomicSlotStore {
    inner: Mutex<BTreeMap<String, Vec<u8>>>,
    flushes: Mutex<u64>,
}

impl MemoryAtomicSlotStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of accepted `flush` calls (used to prove ordering in tests).
    pub fn flush_count(&self) -> u64 {
        self.flushes.lock().map(|g| *g).unwrap_or(0)
    }

    /// Number of stored keys.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CasStore for MemoryAtomicSlotStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SlotStoreError::Storage("poisoned memory store".to_string()))?;
        Ok(guard.get(key).cloned())
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SlotStoreError::Storage("poisoned memory store".to_string()))?;
        match (guard.get(key), expected) {
            (None, None) => {
                guard.insert(key.to_string(), new.to_vec());
                Ok(true)
            }
            (None, Some(_)) => Ok(false),
            (Some(_), None) => Ok(false),
            (Some(current), Some(want)) => {
                if current.as_slice() == want {
                    guard.insert(key.to_string(), new.to_vec());
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| SlotStoreError::Storage("poisoned memory store".to_string()))?;
        Ok(guard
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        let mut guard = self
            .flushes
            .lock()
            .map_err(|_| SlotStoreError::Storage("poisoned flush counter".to_string()))?;
        *guard += 1;
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "memory-cas"
    }
}

impl AtomicSlotStore for MemoryAtomicSlotStore {}

/// Exclusive-access guard on a store directory.
///
/// Acquired by creating a lock file with `create_new`, which is atomic on every
/// supported platform: exactly one process can create it. Released on drop.
///
/// A crashed process leaves the file behind. That is deliberate: the next start
/// **fails closed** instead of assuming the previous writer is gone. Clearing it
/// is an explicit operator action ([`SlotStoreGuard::release_stale`]), because a
/// node that silently steals a live lock is exactly how two writers end up in
/// one database.
#[derive(Debug)]
pub struct SlotStoreGuard {
    path: PathBuf,
}

impl SlotStoreGuard {
    /// Take the exclusive lock on `dir`.
    pub fn acquire(dir: &Path) -> Result<Self, SlotStoreError> {
        std::fs::create_dir_all(dir).map_err(|e| SlotStoreError::Storage(e.to_string()))?;
        let path = dir.join(STORE_LOCK_FILE);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let _ = write!(file, "{}", std::process::id());
                let _ = file.sync_all();
                Ok(Self { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let pid = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0);
                Err(SlotStoreError::StoreLocked { pid })
            }
            Err(e) => Err(SlotStoreError::Storage(e.to_string())),
        }
    }

    /// Path of the lock file, for operator reports.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove a lock file left by a process known to be dead.
    ///
    /// Deliberately manual: no automatic staleness test exists that cannot be
    /// wrong (PID reuse, containers, network filesystems). Returns the PID that
    /// was recorded.
    pub fn release_stale(dir: &Path) -> Result<u32, SlotStoreError> {
        let path = dir.join(STORE_LOCK_FILE);
        let pid = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(pid),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(pid),
            Err(e) => Err(SlotStoreError::Storage(e.to_string())),
        }
    }
}

impl Drop for SlotStoreGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Durable atomic store: `sled` compare-and-swap behind an exclusive lock.
///
/// Guarantees, exactly:
///
/// - **atomicity** for every reservation, across threads, via CAS;
/// - **exclusive access** across processes, via [`SlotStoreGuard`], failing
///   closed;
/// - **durability up to `flush()`**, which is what [`crate::l2persist::state`]
///   calls before any signature is produced.
///
/// It does not claim power-loss durability beyond the platform's fsync, and it
/// does not claim to be a distributed store.
pub struct SledAtomicSlotStore {
    storage: Storage,
    guard: SlotStoreGuard,
}

impl SledAtomicSlotStore {
    /// Open (or create) a vote store rooted at `dir`.
    ///
    /// Fails with [`SlotStoreError::StoreLocked`] if another process holds it.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, SlotStoreError> {
        let dir = dir.as_ref();
        let guard = SlotStoreGuard::acquire(dir)?;
        let storage = Storage::open(dir.join("db")).map_err(|e| {
            SlotStoreError::Storage(format!("opening vote store at {}: {e}", dir.display()))
        })?;
        Ok(Self { storage, guard })
    }

    /// Lock file path, for operator tooling.
    pub fn lock_path(&self) -> &Path {
        self.guard.path()
    }

    /// Underlying storage, for inspection only.
    pub fn storage(&self) -> &Storage {
        &self.storage
    }
}

impl CasStore for SledAtomicSlotStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        match self.storage.get_metadata(key) {
            Ok(v) => Ok(Some(v)),
            Err(StorageError::KeyNotFound) => Ok(None),
            Err(e) => Err(SlotStoreError::Storage(e.to_string())),
        }
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        self.storage
            .compare_and_swap_metadata(key, expected, new)
            .map_err(|e| SlotStoreError::Storage(e.to_string()))
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.storage
            .scan_metadata_prefix(prefix)
            .map_err(|e| SlotStoreError::Storage(e.to_string()))
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        self.storage
            .flush()
            .map_err(|e| SlotStoreError::Storage(e.to_string()))
    }

    fn backend(&self) -> &'static str {
        "sled-cas"
    }
}

impl AtomicSlotStore for SledAtomicSlotStore {}
