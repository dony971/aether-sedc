//! Vote slots and anti-equivocation commitments.
//!
//! # What a slot is
//!
//! A slot is `(network, generation, height, round, phase, validator)`. A
//! validator may commit **one** checkpoint id per slot. Two different checkpoint
//! ids in one slot is equivocation, and the first commitment is kept as
//! evidence.
//!
//! # Persistence ordering
//!
//! [`commit_vote`] writes the commitment **before** returning `Fresh`. A caller
//! that then broadcasts has already recorded its own vote, so a crash cannot
//! produce a vote that was emitted but not remembered.
//!
//! # What this does NOT guarantee
//!
//! The `Storage`-backed store is **read-then-write**, not compare-and-swap:
//! `Storage::put_metadata` exposes no atomic conditional insert. Two processes
//! sharing one data directory, or a crash between the read and the write, can
//! therefore race. This is stated here rather than papered over:
//!
//! - single-process, single-writer operation is safe;
//! - a multi-process deployment needs an atomic compare-and-swap in the storage
//!   layer (next mission);
//! - the trait exists so that backend can be swapped without touching callers.
//!
//! An in-memory check alone is explicitly **not** sufficient: that is why the
//! trait is the only entry point and why the durable implementation is the
//! default.

use std::collections::BTreeMap;
use std::sync::Mutex;

use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, Round, ValidatorId};
use crate::l2crypto::frame::{frame_hash, le32, le64};
use crate::l2crypto::vote::{ConsensusVote, VotePhase};
use crate::storage::{Storage, StorageError};

/// Version of the commitment encoding.
pub const COMMITMENT_VERSION: u8 = 1;

/// Domain tag for a commitment identifier.
pub const DOMAIN_COMMITMENT: &[u8] = b"AETHER-L2-COMMIT-v1";

/// Encoded size: `1+32+32+32+8+4+1+32`.
const COMMITMENT_LEN: usize = 142;

/// A persisted record that a validator voted in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteCommitment {
    /// Encoding version.
    pub version: u8,
    /// Slot identifier.
    pub slot_id: [u8; 32],
    /// Identifier of the vote that was emitted.
    pub vote_id: [u8; 32],
    /// Checkpoint that was voted for.
    pub checkpoint_id: [u8; 32],
    /// Height.
    pub height: CheckpointHeight,
    /// Round.
    pub round: Round,
    /// Phase.
    pub phase: VotePhase,
    /// Validator.
    pub validator: ValidatorId,
}

impl VoteCommitment {
    /// Build a commitment from a vote.
    pub fn from_vote(vote: &ConsensusVote) -> Self {
        Self {
            version: COMMITMENT_VERSION,
            slot_id: vote.slot_id(),
            vote_id: vote.id(),
            checkpoint_id: vote.checkpoint_id,
            height: vote.height,
            round: vote.round,
            phase: vote.phase,
            validator: vote.validator,
        }
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMMITMENT_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.slot_id);
        out.extend_from_slice(&self.vote_id);
        out.extend_from_slice(&self.checkpoint_id);
        out.extend_from_slice(&le64(self.height.get()));
        out.extend_from_slice(&le32(self.round.get()));
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.validator.0);
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, LockError> {
        if bytes.len() != COMMITMENT_LEN {
            return Err(LockError::Malformed(format!(
                "commitment length {} != {}",
                bytes.len(),
                COMMITMENT_LEN
            )));
        }
        if bytes[0] != COMMITMENT_VERSION {
            return Err(LockError::Malformed(format!(
                "unknown commitment version {}",
                bytes[0]
            )));
        }
        let mut slot_id = [0u8; 32];
        slot_id.copy_from_slice(&bytes[1..33]);
        let mut vote_id = [0u8; 32];
        vote_id.copy_from_slice(&bytes[33..65]);
        let mut checkpoint_id = [0u8; 32];
        checkpoint_id.copy_from_slice(&bytes[65..97]);
        let mut h = [0u8; 8];
        h.copy_from_slice(&bytes[97..105]);
        let mut r = [0u8; 4];
        r.copy_from_slice(&bytes[105..109]);
        let phase = VotePhase::from_u8(bytes[109])
            .ok_or_else(|| LockError::Malformed(format!("unknown phase {}", bytes[109])))?;
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&bytes[110..142]);
        Ok(Self {
            version: bytes[0],
            slot_id,
            vote_id,
            checkpoint_id,
            height: CheckpointHeight(u64::from_le_bytes(h)),
            round: Round(u32::from_le_bytes(r)),
            phase,
            validator: ValidatorId(validator),
        })
    }
}

/// Lock-layer failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LockError {
    /// Storage backend failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// Stored bytes are not a valid commitment.
    #[error("malformed commitment: {0}")]
    Malformed(String),
}

/// Durable slot store.
///
/// Implemented by [`StorageLockStore`] (durable, single-writer) and
/// [`MemoryLockStore`] (tests only). A future atomic backend implements the same
/// two methods.
pub trait VoteLockStore {
    /// Read the commitment in `slot_id`, if any.
    fn load(&self, slot_id: &[u8; 32]) -> Result<Option<VoteCommitment>, LockError>;

    /// Persist a commitment.
    ///
    /// Callers must only invoke this for a slot that `load` reported empty.
    fn record(&self, commitment: &VoteCommitment) -> Result<(), LockError>;
}

/// Outcome of asking to emit a vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotOutcome {
    /// No prior commitment: the vote is new and has been persisted.
    Fresh,
    /// The same vote, or another vote for the same checkpoint, was already
    /// recorded. Idempotent.
    Duplicate,
    /// The slot already holds a commitment for a **different** checkpoint.
    Equivocation {
        /// The commitment recorded first.
        existing: VoteCommitment,
    },
}

/// Check a vote against the slot store, persisting it when new.
///
/// Order: load, decide, and — only for [`SlotOutcome::Fresh`] — record, before
/// returning. Never overwrites an existing commitment, so equivocation evidence
/// cannot be destroyed by a later vote.
pub fn commit_vote(
    vote: &ConsensusVote,
    store: &dyn VoteLockStore,
) -> Result<SlotOutcome, LockError> {
    let slot = vote.slot_id();
    match store.load(&slot)? {
        None => {
            let commitment = VoteCommitment::from_vote(vote);
            store.record(&commitment)?;
            Ok(SlotOutcome::Fresh)
        }
        Some(existing) => {
            if existing.vote_id == vote.id() || existing.checkpoint_id == vote.checkpoint_id {
                Ok(SlotOutcome::Duplicate)
            } else {
                Ok(SlotOutcome::Equivocation { existing })
            }
        }
    }
}

/// In-memory store.
///
/// **Not durable, not multi-process.** Provided so tests can exercise
/// [`commit_vote`] without a database, never for production use.
#[derive(Debug, Default)]
pub struct MemoryLockStore {
    inner: Mutex<BTreeMap<[u8; 32], VoteCommitment>>,
}

impl MemoryLockStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of recorded slots.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Whether nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl VoteLockStore for MemoryLockStore {
    fn load(&self, slot_id: &[u8; 32]) -> Result<Option<VoteCommitment>, LockError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| LockError::Storage("poisoned lock store".to_string()))?;
        Ok(guard.get(slot_id).copied())
    }

    fn record(&self, commitment: &VoteCommitment) -> Result<(), LockError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| LockError::Storage("poisoned lock store".to_string()))?;
        guard
            .entry(commitment.slot_id)
            .or_insert(*commitment);
        Ok(())
    }
}

/// Durable store over `Storage` metadata.
///
/// Keys are `l2crypto/v1/lock/<slot hex>`. The insert is unconditional, which is
/// why [`commit_vote`] only calls it when the slot is empty; see the module note
/// on the read-then-write race.
pub struct StorageLockStore<'a> {
    storage: &'a Storage,
}

impl<'a> StorageLockStore<'a> {
    /// Wrap a storage handle.
    pub fn new(storage: &'a Storage) -> Self {
        Self { storage }
    }

    /// Key for a slot.
    pub fn key_for(slot_id: &[u8; 32]) -> String {
        format!("l2crypto/v1/lock/{}", hex::encode(slot_id))
    }
}

impl<'a> VoteLockStore for StorageLockStore<'a> {
    fn load(&self, slot_id: &[u8; 32]) -> Result<Option<VoteCommitment>, LockError> {
        match self.storage.get_metadata(&Self::key_for(slot_id)) {
            Ok(bytes) => Ok(Some(VoteCommitment::decode(&bytes)?)),
            Err(StorageError::KeyNotFound) => Ok(None),
            Err(e) => Err(LockError::Storage(e.to_string())),
        }
    }

    fn record(&self, commitment: &VoteCommitment) -> Result<(), LockError> {
        self.storage
            .put_metadata(&Self::key_for(&commitment.slot_id), &commitment.encode())
            .map_err(|e| LockError::Storage(e.to_string()))
    }
}

/// Commitment identifier (content address), useful for evidence bundles.
pub fn commitment_id(commitment: &VoteCommitment) -> [u8; 32] {
    frame_hash(DOMAIN_COMMITMENT, &[&commitment.encode()[..]])
}
