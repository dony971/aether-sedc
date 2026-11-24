//! L2 checkpoint format (A-06.6-AQ `N-CKPT-1..5`).
//!
//! A checkpoint is the only object L2 finalises. It commits the ledger state,
//! the L1 finality set and the validator set of its generation, chained to its
//! parent by identifier.
//!
//! # Scope of this module
//!
//! Format, canonical serialisation, strict decoding and identity. **No**
//! voting, **no** QC, **no** finality: a checkpoint existing here proves
//! nothing about acceptance.
//!
//! # Encoding discipline
//!
//! Hand-rolled fixed-layout encoding, not `bincode`: `bincode` accepts
//! alternative framings for the same value, which would let two byte strings
//! map to one logical checkpoint. Here every byte position is fixed, the
//! `Option` tag must be exactly `0` or `1`, trailing bytes are rejected, and
//! lengths are checked before slicing.

use std::fmt;

use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, GenerationId};
use crate::consensus::roots::hash_parts;

/// Current checkpoint encoding version.
pub const CHECKPOINT_FORMAT_VERSION: u8 = 1;

/// Domain tag for checkpoint identifiers.
pub const DOMAIN_CHECKPOINT: &[u8] = b"AETHER-L2-CKPT-v1";

/// Fixed size without the optional transition identifier.
const CKPT_BASE_LEN: usize = 1 + 32 + 8 + 32 + 32 + 32 + 32 + 1;
/// Full size with a transition identifier.
const CKPT_FULL_LEN: usize = CKPT_BASE_LEN + 32;

/// Checkpoint errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointError {
    /// Unknown format version.
    #[error("unsupported checkpoint version {0}")]
    UnsupportedVersion(u8),

    /// Length disagrees with the declared content.
    #[error("malformed checkpoint encoding (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// The optional-transition tag was neither `0` nor `1`.
    #[error("non-canonical encoding: option tag {0}")]
    NonCanonicalOptionTag(u8),

    /// A transition identifier of all zeros is not representable.
    #[error("transition identifier must not be zero")]
    ZeroTransitionId,

    /// Parent height is not `self.height - 1`.
    #[error("height {got} does not follow parent height {parent}")]
    HeightNotSequential {
        /// Parent height.
        parent: u64,
        /// This height.
        got: u64,
    },

    /// `parent` field does not name the parent's identifier.
    #[error("parent identifier does not match the supplied parent checkpoint")]
    ParentIdMismatch,

    /// Two checkpoints of the same generation at the same height differ.
    #[error("conflicting checkpoint at the same height")]
    ConflictingCheckpoint,
}

/// A single L2 checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Encoding version.
    pub version: u8,
    /// Generation this checkpoint belongs to.
    pub generation: GenerationId,
    /// Height inside the checkpoint chain.
    pub height: CheckpointHeight,
    /// Parent checkpoint identifier (`[0u8; 32]` only for a chain root).
    pub parent: [u8; 32],
    /// Ledger state root.
    pub state_root: [u8; 32],
    /// Commitment over the L1 finality records (`finalized_root`).
    pub finality_root: [u8; 32],
    /// Validator-set root of `generation`.
    pub validator_set_root: [u8; 32],
    /// Transition identifier, when this checkpoint closes a generation.
    pub transition_id: Option<[u8; 32]>,
}

impl Checkpoint {
    /// Build a checkpoint at the current format version.
    pub fn new(
        generation: GenerationId,
        height: CheckpointHeight,
        parent: [u8; 32],
        state_root: [u8; 32],
        finality_root: [u8; 32],
        validator_set_root: [u8; 32],
        transition_id: Option<[u8; 32]>,
    ) -> Result<Self, CheckpointError> {
        let cp = Self {
            version: CHECKPOINT_FORMAT_VERSION,
            generation,
            height,
            parent,
            state_root,
            finality_root,
            validator_set_root,
            transition_id,
        };
        cp.validate()?;
        Ok(cp)
    }

    /// True when this checkpoint opens the chain (no parent).
    pub fn is_chain_root(&self) -> bool {
        self.parent == [0u8; 32]
    }

    /// Field validation independent of any other object.
    ///
    /// Deliberately minimal: a checkpoint cannot decide on its own whether it
    /// is `H_conv` (its parent may legitimately be absent), so ordering rules
    /// live in [`Self::validate_link`].
    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.version != CHECKPOINT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedVersion(self.version));
        }
        if let Some(id) = self.transition_id {
            if id == [0u8; 32] {
                return Err(CheckpointError::ZeroTransitionId);
            }
        }
        Ok(())
    }

    /// Chain validation against the parent checkpoint.
    ///
    /// Enforces `N-CKPT-1`: strict `+1` height and a parent identifier that
    /// really names the supplied parent.
    pub fn validate_link(&self, parent: &Checkpoint) -> Result<(), CheckpointError> {
        self.validate()?;
        if self.height.get() != parent.height.get().saturating_add(1) {
            return Err(CheckpointError::HeightNotSequential {
                parent: parent.height.get(),
                got: self.height.get(),
            });
        }
        if self.parent != parent.id() {
            return Err(CheckpointError::ParentIdMismatch);
        }
        Ok(())
    }

    /// Canonical encoding (fixed layout, little-endian integers).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CKPT_FULL_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.finality_root);
        out.extend_from_slice(&self.validator_set_root);
        match self.transition_id {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id);
            }
        }
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() < CKPT_BASE_LEN {
            return Err(CheckpointError::MalformedEncoding {
                expected: CKPT_BASE_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != CHECKPOINT_FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedVersion(version));
        }
        let mut p = 1usize;
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut height_buf = [0u8; 8];
        height_buf.copy_from_slice(&bytes[p..p + 8]);
        let height = CheckpointHeight(u64::from_le_bytes(height_buf));
        p += 8;
        let mut parent = [0u8; 32];
        parent.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut finality_root = [0u8; 32];
        finality_root.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut validator_set_root = [0u8; 32];
        validator_set_root.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let tag = bytes[p];
        p += 1;
        let transition_id = match tag {
            0 => {
                if bytes.len() != CKPT_BASE_LEN {
                    return Err(CheckpointError::MalformedEncoding {
                        expected: CKPT_BASE_LEN,
                        actual: bytes.len(),
                    });
                }
                None
            }
            1 => {
                if bytes.len() != CKPT_FULL_LEN {
                    return Err(CheckpointError::MalformedEncoding {
                        expected: CKPT_FULL_LEN,
                        actual: bytes.len(),
                    });
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes[p..p + 32]);
                Some(id)
            }
            other => return Err(CheckpointError::NonCanonicalOptionTag(other)),
        };
        let cp = Self {
            version,
            generation: GenerationId(generation),
            height,
            parent,
            state_root,
            finality_root,
            validator_set_root,
            transition_id,
        };
        cp.validate()?;
        Ok(cp)
    }

    /// Content-addressed identifier.
    pub fn id(&self) -> [u8; 32] {
        hash_parts(DOMAIN_CHECKPOINT, &[&self.encode()[..]])
    }
}

impl fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ckpt[h={}, gen={}, id={}]",
            self.height.get(),
            self.generation,
            hex::encode(&self.id()[..6])
        )
    }
}
