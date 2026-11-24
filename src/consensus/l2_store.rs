//! L2 persistence over the existing metadata tree.
//!
//! # Why metadata and not a new tree
//!
//! `crate::storage::TreeName` is a closed enum with an exhaustive `name()`
//! match, and `BatchOperation` only covers transactions and balances. Adding
//! variants would change an existing public interface — explicitly out of
//! scope for this lot. `Storage::put_metadata` / `get_metadata` already exist
//! and are sufficient.
//!
//! # Atomicity
//!
//! One commit is **one key**, so one `put_metadata` call. Nothing is split
//! across keys except the head pointer, which is written last. A crash between
//! the two leaves a commit above the head, which
//! [`L2Store::verify_consistency`] detects and refuses.
//!
//! # Durability: what is NOT claimed
//!
//! `put_metadata` maps onto a `sled` insert. That gives crash consistency for
//! the database, **not** durability against power loss: `sled` flushes in the
//! background unless `flush()` is called. This module never claims that a
//! written commit survives a power cut. Do not read "atomic" as "durable".
//!
//! # Scope
//!
//! Persistence and consistency checking only. No voting, no QC, no finality,
//! no migration.

use thiserror::Error;

use crate::consensus::checkpoint::{Checkpoint, CheckpointError};
use crate::consensus::generation::{CheckpointHeight, Generation, GenerationError, GenerationId};
use crate::storage::{Storage, StorageError};

/// Version of the L2 commit encoding.
pub const L2_COMMIT_VERSION: u8 = 1;

const KEY_HEAD: &str = "l2/v1/head";
const KEY_COMMIT_PREFIX: &str = "l2/v1/commit/";

/// Key holding the commit at `height`.
pub fn commit_key(height: CheckpointHeight) -> String {
    format!("{}{:016x}", KEY_COMMIT_PREFIX, height.get())
}

/// One persisted L2 state: a generation plus the checkpoint that establishes
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Commit {
    /// Encoding version.
    pub version: u8,
    /// Generation in force at this checkpoint.
    pub generation: Generation,
    /// Checkpoint for this height.
    pub checkpoint: Checkpoint,
}

impl L2Commit {
    /// Build a commit at the current version and validate the pairing.
    pub fn new(generation: Generation, checkpoint: Checkpoint) -> Result<Self, L2StoreError> {
        let commit = Self {
            version: L2_COMMIT_VERSION,
            generation,
            checkpoint,
        };
        commit.cross_check()?;
        Ok(commit)
    }

    /// The checkpoint must really belong to the paired generation.
    pub fn cross_check(&self) -> Result<(), L2StoreError> {
        self.checkpoint.validate()?;
        if self.checkpoint.generation != self.generation.id() {
            return Err(L2StoreError::GenerationMismatch);
        }
        if self.checkpoint.validator_set_root != self.generation.set_root() {
            return Err(L2StoreError::SetRootMismatch);
        }
        Ok(())
    }

    /// Height of this commit.
    pub fn height(&self) -> CheckpointHeight {
        self.checkpoint.height
    }

    /// Canonical encoding:
    /// `version(1) ‖ gen_len(4) ‖ gen ‖ ckpt_len(4) ‖ ckpt`.
    pub fn encode(&self) -> Vec<u8> {
        let gen = self.generation.encode();
        let ckpt = self.checkpoint.encode();
        let mut out = Vec::with_capacity(1 + 4 + gen.len() + 4 + ckpt.len());
        out.push(self.version);
        out.extend_from_slice(&(gen.len() as u32).to_le_bytes());
        out.extend_from_slice(&gen);
        out.extend_from_slice(&(ckpt.len() as u32).to_le_bytes());
        out.extend_from_slice(&ckpt);
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, L2StoreError> {
        if bytes.len() < 5 {
            return Err(L2StoreError::MalformedCommit {
                reason: "shorter than header".to_string(),
            });
        }
        let version = bytes[0];
        if version != L2_COMMIT_VERSION {
            return Err(L2StoreError::UnsupportedVersion(version));
        }
        let mut p = 1usize;
        let gen_len = read_u32(bytes, &mut p)? as usize;
        if bytes.len() < p + gen_len + 4 {
            return Err(L2StoreError::MalformedCommit {
                reason: "generation length exceeds record".to_string(),
            });
        }
        let generation = Generation::decode(&bytes[p..p + gen_len])?;
        p += gen_len;
        let ckpt_len = read_u32(bytes, &mut p)? as usize;
        if bytes.len() != p + ckpt_len {
            return Err(L2StoreError::MalformedCommit {
                reason: "checkpoint length does not close the record".to_string(),
            });
        }
        let checkpoint = Checkpoint::decode(&bytes[p..p + ckpt_len])?;
        let commit = Self {
            version,
            generation,
            checkpoint,
        };
        commit.cross_check()?;
        Ok(commit)
    }
}

fn read_u32(bytes: &[u8], p: &mut usize) -> Result<u32, L2StoreError> {
    if bytes.len() < *p + 4 {
        return Err(L2StoreError::MalformedCommit {
            reason: "truncated length field".to_string(),
        });
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*p..*p + 4]);
    *p += 4;
    Ok(u32::from_le_bytes(buf))
}

/// L2 store failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum L2StoreError {
    /// Underlying storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Head pointer exists but its commit is absent.
    #[error("inconsistent L2 state: head {0} has no commit")]
    MissingHeadCommit(u64),

    /// A commit exists above the head pointer.
    #[error("inconsistent L2 state: commit at {found} above head {head}")]
    OrphanCommit {
        /// Recorded head.
        head: u64,
        /// Commit found above it.
        found: u64,
    },

    /// The chain is broken below the head.
    #[error("inconsistent L2 state: chain broken below head {0}")]
    BrokenChain(u64),

    /// Attempt to write a height that does not advance the head.
    #[error("refusing non-monotonic commit: current head {current}, attempted {attempted}")]
    NonMonotonicHeight {
        /// Current head.
        current: u64,
        /// Attempted height.
        attempted: u64,
    },

    /// Checkpoint names another generation than the one it is paired with.
    #[error("checkpoint generation does not match the paired generation")]
    GenerationMismatch,

    /// Checkpoint commits another validator set than the paired generation.
    #[error("checkpoint validator set root does not match the paired generation")]
    SetRootMismatch,

    /// Record bytes are not decodable as a commit.
    #[error("malformed L2 commit: {reason}")]
    MalformedCommit {
        /// Human-readable reason.
        reason: String,
    },

    /// Unknown commit version.
    #[error("unsupported L2 commit version {0}")]
    UnsupportedVersion(u8),

    /// Generation record failed its own validation.
    #[error("generation error: {0}")]
    Generation(#[from] GenerationError),

    /// Checkpoint record failed its own validation.
    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),
}

impl L2StoreError {
    fn from_storage(e: StorageError) -> Self {
        L2StoreError::Storage(e.to_string())
    }
}

/// Read/write access to persisted L2 commits.
pub struct L2Store<'a> {
    storage: &'a Storage,
}

impl<'a> L2Store<'a> {
    /// Wrap a storage handle.
    pub fn new(storage: &'a Storage) -> Self {
        Self { storage }
    }

    /// Current head height, if any L2 state exists.
    pub fn head(&self) -> Result<Option<CheckpointHeight>, L2StoreError> {
        match self.storage.get_metadata(KEY_HEAD) {
            Ok(bytes) => {
                if bytes.len() != 8 {
                    return Err(L2StoreError::MalformedCommit {
                        reason: "head pointer is not 8 bytes".to_string(),
                    });
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                Ok(Some(CheckpointHeight(u64::from_le_bytes(buf))))
            }
            Err(StorageError::KeyNotFound) => Ok(None),
            Err(e) => Err(L2StoreError::from_storage(e)),
        }
    }

    /// Persist one commit and advance the head.
    ///
    /// Order: commit first, head last. A crash in between is detectable
    /// (`OrphanCommit`), never silently accepted.
    pub fn write_commit(&self, commit: &L2Commit) -> Result<(), L2StoreError> {
        commit.cross_check()?;
        let height = commit.height();
        if let Some(current) = self.head()? {
            if height.get() <= current.get() {
                return Err(L2StoreError::NonMonotonicHeight {
                    current: current.get(),
                    attempted: height.get(),
                });
            }
        }
        self.storage
            .put_metadata(&commit_key(height), &commit.encode())
            .map_err(L2StoreError::from_storage)?;
        self.storage
            .put_metadata(KEY_HEAD, &height.get().to_le_bytes())
            .map_err(L2StoreError::from_storage)?;
        Ok(())
    }

    /// Read the commit at `height`, if present.
    pub fn read_commit(&self, height: CheckpointHeight) -> Result<Option<L2Commit>, L2StoreError> {
        match self.storage.get_metadata(&commit_key(height)) {
            Ok(bytes) => Ok(Some(L2Commit::decode(&bytes)?)),
            Err(StorageError::KeyNotFound) => Ok(None),
            Err(e) => Err(L2StoreError::from_storage(e)),
        }
    }

    /// Read the commit designated by the head pointer.
    pub fn read_head_commit(&self) -> Result<Option<L2Commit>, L2StoreError> {
        match self.head()? {
            None => Ok(None),
            Some(h) => match self.read_commit(h)? {
                Some(c) => Ok(Some(c)),
                None => Err(L2StoreError::MissingHeadCommit(h.get())),
            },
        }
    }

    /// Full consistency check, intended to run at startup.
    ///
    /// Detects: head without commit, commit above head (interrupted write),
    /// broken `+1` height chain, and any record that fails canonical decoding
    /// or cross-validation.
    pub fn verify_consistency(&self) -> Result<(), L2StoreError> {
        let head = match self.head()? {
            None => return Ok(()),
            Some(h) => h,
        };
        let head_commit = match self.read_commit(head)? {
            Some(c) => c,
            None => return Err(L2StoreError::MissingHeadCommit(head.get())),
        };
        if head_commit.height() != head {
            return Err(L2StoreError::BrokenChain(head.get()));
        }
        // A commit one above the head means the process died between the two
        // writes: refuse rather than guess which side is authoritative.
        if self
            .read_commit(CheckpointHeight(head.get().saturating_add(1)))?
            .is_some()
        {
            return Err(L2StoreError::OrphanCommit {
                head: head.get(),
                found: head.get().saturating_add(1),
            });
        }
        if head.get() > 0 {
            let prev_height = CheckpointHeight(head.get() - 1);
            let prev = match self.read_commit(prev_height)? {
                Some(c) => c,
                None => return Err(L2StoreError::BrokenChain(head.get())),
            };
            head_commit
                .checkpoint
                .validate_link(&prev.checkpoint)
                .map_err(|_| L2StoreError::BrokenChain(head.get()))?;
        }
        Ok(())
    }

    /// Convenience: generation identifier at the head, if any.
    pub fn head_generation_id(&self) -> Result<Option<GenerationId>, L2StoreError> {
        Ok(self.read_head_commit()?.map(|c| c.generation.id()))
    }
}
