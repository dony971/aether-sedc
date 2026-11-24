//! L2 consensus votes (`ConsensusVote`).
//!
//! # What a vote is
//!
//! A validator's signature over one (generation, height, round, phase,
//! checkpoint) tuple. The signed message is domain-tagged and length-framed, so
//! a vote can never be replayed as another message type, in another generation,
//! at another height, in another round, or in another phase.
//!
//! # What a vote is NOT
//!
//! A valid signature proves **authorship**, not legitimacy. It says: "the holder
//! of this key signed this tuple". It says nothing about whether the signer had
//! any weight (that comes from the registry), whether the checkpoint is a
//! legitimate successor (that is the acceptance rules), or whether the signer is
//! an independent operator (`A-INDEP`, undecided).
//!
//! **A vote never carries its own weight.** [`ConsensusVote::verify`] returns
//! the weight looked up in the registry, and any weight a caller might attach
//! elsewhere is not represented in the type at all.

use std::fmt;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight};
use crate::l2crypto::frame::{frame, frame_hash, le32, le64};
use crate::l2crypto::registry::ValidatorRegistry;

/// Current vote encoding version.
pub const CONSENSUS_VOTE_VERSION: u8 = 1;

/// Domain tag for a vote signature.
pub const DOMAIN_VOTE: &[u8] = b"AETHER-L2-VOTE-v1";
/// Domain tag for a vote identifier.
pub const DOMAIN_VOTE_ID: &[u8] = b"AETHER-L2-VOTEID-v1";
/// Domain tag for a vote slot identifier.
pub const DOMAIN_VOTE_SLOT: &[u8] = b"AETHER-L2-SLOT-v1";

/// Encoded size of a vote: `1+8+32+8+4+1+32+32+64`.
pub const VOTE_LEN: usize = 182;

/// Consensus phase.
///
/// An explicit enum, not a string and not a `u8`: two phases cannot be confused
/// at the type level, and the wire value is fixed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VotePhase {
    /// First phase: "I would accept this checkpoint".
    Prevote,
    /// Second phase: "I commit to this checkpoint".
    Precommit,
}

impl VotePhase {
    /// Stable wire encoding.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Prevote => 0,
            Self::Precommit => 1,
        }
    }

    /// Strict inverse of [`Self::as_u8`].
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Prevote,
            1 => Self::Precommit,
            _ => return None,
        })
    }
}

impl fmt::Display for VotePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Prevote => "prevote",
            Self::Precommit => "precommit",
        })
    }
}

/// Decoding failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VoteError {
    /// Length disagrees with the fixed layout.
    #[error("malformed vote encoding (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Unknown encoding version.
    #[error("unsupported vote version {0}")]
    UnsupportedVersion(u8),

    /// Unknown phase byte.
    #[error("unknown vote phase {0}")]
    UnknownPhase(u8),
}

/// Verification failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VoteVerifyError {
    /// Wrong encoding version.
    #[error("unsupported vote version {0}")]
    UnsupportedVersion(u8),

    /// Vote belongs to another network.
    #[error("vote for another network")]
    WrongNetwork,

    /// Vote belongs to another generation than the registry.
    #[error("vote generation does not match the registry")]
    GenerationMismatch,

    /// Signer is not registered at all.
    #[error("unknown validator {0}")]
    UnknownValidator(ValidatorId),

    /// Signer is registered but not admissible.
    #[error("validator {0} is not admissible")]
    IneligibleValidator(ValidatorId),

    /// The signature does not verify against the registry key.
    #[error("bad vote signature")]
    BadSignature,
}

/// A signed consensus vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusVote {
    /// Encoding version.
    pub version: u8,
    /// Network discriminator.
    pub network: u64,
    /// Generation the vote belongs to.
    pub generation: GenerationId,
    /// Height the vote refers to.
    pub height: CheckpointHeight,
    /// Round the vote refers to.
    pub round: Round,
    /// Consensus phase.
    pub phase: VotePhase,
    /// Checkpoint being voted on.
    pub checkpoint_id: [u8; 32],
    /// Signer identifier.
    pub validator: ValidatorId,
    /// Ed25519 signature over [`Self::signing_bytes`].
    pub signature: [u8; 64],
}

impl ConsensusVote {
    /// Build a vote with an empty signature.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: u64,
        generation: GenerationId,
        height: CheckpointHeight,
        round: Round,
        phase: VotePhase,
        checkpoint_id: [u8; 32],
        validator: ValidatorId,
    ) -> Self {
        Self {
            version: CONSENSUS_VOTE_VERSION,
            network,
            generation,
            height,
            round,
            phase,
            checkpoint_id,
            validator,
            signature: [0u8; 64],
        }
    }

    /// Attach a signature.
    pub fn with_signature(mut self, signature: [u8; 64]) -> Self {
        self.signature = signature;
        self
    }

    /// The exact byte string that is signed.
    ///
    /// Domain-tagged and length-framed: a vote over (generation `g`, height
    /// `h`, round `r`, phase `p`) cannot verify as a vote over any other
    /// context, because every one of those fields is inside the framed message.
    pub fn signing_bytes(&self) -> Vec<u8> {
        frame(
            DOMAIN_VOTE,
            &[
                &[self.version][..],
                &le64(self.network)[..],
                &self.generation.0[..],
                &le64(self.height.get())[..],
                &le32(self.round.get())[..],
                &[self.phase.as_u8()][..],
                &self.checkpoint_id[..],
                &self.validator.0[..],
            ],
        )
    }

    /// Canonical encoding: signing bytes' fields in a fixed layout plus the
    /// signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VOTE_LEN);
        out.push(self.version);
        out.extend_from_slice(&le64(self.network));
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&le64(self.height.get()));
        out.extend_from_slice(&le32(self.round.get()));
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.checkpoint_id);
        out.extend_from_slice(&self.validator.0);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, VoteError> {
        if bytes.len() != VOTE_LEN {
            return Err(VoteError::MalformedEncoding {
                expected: VOTE_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != CONSENSUS_VOTE_VERSION {
            return Err(VoteError::UnsupportedVersion(bytes[0]));
        }
        let version = bytes[0];
        let network = read_u64(bytes, 1);
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[9..41]);
        let height = CheckpointHeight(read_u64(bytes, 41));
        let round = Round(read_u32(bytes, 49));
        let phase = VotePhase::from_u8(bytes[53]).ok_or(VoteError::UnknownPhase(bytes[53]))?;
        let mut checkpoint_id = [0u8; 32];
        checkpoint_id.copy_from_slice(&bytes[54..86]);
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&bytes[86..118]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[118..182]);
        Ok(Self {
            version,
            network,
            generation: GenerationId(generation),
            height,
            round,
            phase,
            checkpoint_id,
            validator: ValidatorId(validator),
            signature,
        })
    }

    /// Content-addressed identifier (includes the signature).
    pub fn id(&self) -> [u8; 32] {
        frame_hash(DOMAIN_VOTE_ID, &[&self.encode()[..]])
    }

    /// Slot identifier: what a validator may sign **once**.
    ///
    /// Includes the validator, so two validators' votes at the same position are
    /// different slots; excludes the checkpoint, so two different checkpoints at
    /// the same position collide — which is exactly the equivocation case
    /// `l2crypto::slots` detects.
    pub fn slot_id(&self) -> [u8; 32] {
        frame_hash(
            DOMAIN_VOTE_SLOT,
            &[
                &le64(self.network)[..],
                &self.generation.0[..],
                &le64(self.height.get())[..],
                &le32(self.round.get())[..],
                &[self.phase.as_u8()][..],
                &self.validator.0[..],
            ],
        )
    }

    /// Verify the signature against `registry` and return the **registry-derived**
    /// weight.
    ///
    /// The signature is checked against the public key stored in the registry
    /// for `self.validator` — never against the identifier itself. A vote that
    /// claims another validator's id but is signed by a different key therefore
    /// fails, even if the signature is otherwise valid.
    pub fn verify(
        &self,
        registry: &ValidatorRegistry,
        expected_network: u64,
    ) -> Result<VerifiedVote, VoteVerifyError> {
        if self.version != CONSENSUS_VOTE_VERSION {
            return Err(VoteVerifyError::UnsupportedVersion(self.version));
        }
        if self.network != expected_network {
            return Err(VoteVerifyError::WrongNetwork);
        }
        if registry.generation() != self.generation {
            return Err(VoteVerifyError::GenerationMismatch);
        }
        let entry = registry
            .get(&self.validator)
            .ok_or(VoteVerifyError::UnknownValidator(self.validator))?;
        if !entry.admissibility.may_vote() {
            return Err(VoteVerifyError::IneligibleValidator(self.validator));
        }
        let key = VerifyingKey::from_bytes(&entry.public_key)
            .map_err(|_| VoteVerifyError::BadSignature)?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&self.signing_bytes(), &sig)
            .map_err(|_| VoteVerifyError::BadSignature)?;
        Ok(VerifiedVote {
            vote: *self,
            signer: entry.id,
            weight: entry.weight,
        })
    }
}

/// A vote whose signature and membership were checked.
///
/// The weight here is the one the registry assigns. Nothing in this struct can
/// be supplied by the vote itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedVote {
    /// The verified vote.
    pub vote: ConsensusVote,
    /// Registered signer.
    pub signer: ValidatorId,
    /// Registry weight of the signer at verification time.
    pub weight: ValidatorWeight,
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(buf)
}
