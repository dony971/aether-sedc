//! Cryptographic proof of conflicting finality (mission BF, R-BE-3 / R-BE-5).
//!
//! # The distinction this module exists to make
//!
//! | Thing | What it means |
//! |---|---|
//! | a HALT **alert** from a peer | "I saw something wrong" — no authority |
//! | a verified HALT **proof** | two certificates that cannot both be right |
//! | the persisted **HALT state** | the engine refuses to sign until an operator acts |
//!
//! BE carried a 32-byte alert and logged it. That is kept, and it still stops
//! nothing. Only a [`HaltProof`] — two `PrecommitCertificate`s that both verify,
//! for the same network, the same generation and the same height, over two
//! **different** checkpoints — can move the engine into its HALT state.
//!
//! # Why two certificates are enough to be sure
//!
//! A precommit certificate is quorum-signed. Two quorum-signed certificates over
//! different values at one height cannot both be produced by honest validators
//! under any quorum rule this repository implements: at least one signer would
//! have to sign twice in the same round, which `R-LOCK`/`AW-LOCK` forbid. So the
//! proof is not an opinion, it is a witness of equivocation.
//!
//! # What a proof does not establish
//!
//! - that the *local* node is honest, or that anyone will be punished;
//! - that the two checkpoints' `state_root`s are meaningful — those stay
//!   unauthenticated (mission BD), so a proof can be built over a checkpoint whose
//!   state root is wrong. It still proves the **vote** conflict, which is the
//!   safety violation.

use thiserror::Error;

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::{CheckpointHeight, GenerationId};
use crate::l2bft::cert::PrecommitCertificate;
use crate::l2bft::engine::HaltReason;
use crate::l2crypto::registry::ValidatorRegistry;

/// Tag of the proof payload on the wire.
pub const HALT_PROOF_TAG: u8 = 0x01;

/// Version of the proof encoding.
pub const HALT_PROOF_VERSION: u8 = 1;

/// Largest accepted encoded proof.
pub const MAX_HALT_PROOF_BYTES: usize = 64 * 1024;

/// Why a proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HaltProofError {
    /// The payload is not a proof (an alert, or garbage).
    #[error("not a halt proof: {0}")]
    NotAProof(&'static str),

    /// The encoding is truncated, over-long, or has trailing bytes.
    #[error("malformed proof: {0}")]
    Malformed(&'static str),

    /// The version is not the one this codec speaks.
    #[error("unsupported halt-proof version {0}")]
    Version(u8),

    /// A certificate did not verify from its bytes.
    #[error("certificate does not verify: {0}")]
    Certificate(String),

    /// The two halves disagree about which violation they witness.
    #[error("proof halves disagree on {0}")]
    Position(&'static str),

    /// Both halves name the same value, so nothing is contradicted.
    #[error("the two checkpoints are identical: no conflict")]
    NoConflict,

    /// A certificate does not certify the checkpoint it is paired with.
    #[error("certificate does not certify its checkpoint")]
    CertificateMismatch,

    /// A checkpoint record is structurally invalid.
    #[error("checkpoint invalid: {0}")]
    Checkpoint(String),
}

/// Two certificates that cannot both be right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaltProof {
    /// Network the conflict happened on.
    pub network: u64,
    /// Generation in force.
    pub generation: GenerationId,
    /// Height at which two values were decided.
    pub height: CheckpointHeight,
    /// First checkpoint and the certificate that decided it.
    pub first: (Checkpoint, PrecommitCertificate),
    /// Second checkpoint and the certificate that decided it.
    pub second: (Checkpoint, PrecommitCertificate),
}

impl HaltProof {
    /// Verify both halves and the conflict itself.
    ///
    /// This is the only place that decides a proof is a proof. It checks, in this
    /// order: both certificates against the registry of **this** generation and
    /// this network, both checkpoints structurally, both positions (generation,
    /// height) agreeing with the proof, each certificate naming its own checkpoint,
    /// and finally that the two checkpoint identifiers differ.
    pub fn verify(&self, registry: &ValidatorRegistry) -> Result<HaltReason, HaltProofError> {
        if registry.generation() != self.generation {
            return Err(HaltProofError::Position("generation"));
        }
        for (checkpoint, certificate) in [&self.first, &self.second] {
            checkpoint
                .validate()
                .map_err(|error| HaltProofError::Checkpoint(error.to_string()))?;
            if checkpoint.generation != self.generation {
                return Err(HaltProofError::Position("checkpoint generation"));
            }
            if checkpoint.height != self.height {
                return Err(HaltProofError::Position("checkpoint height"));
            }
        }
        for (checkpoint, certificate) in [&self.first, &self.second] {
            // Re-verify from the certificate's own bytes: a `PrecommitCertificate`
            // value could have been built by code that skipped a check, so the
            // proof never trusts the struct it was handed.
            let bytes = certificate.encode();
            let re_verified = PrecommitCertificate::from_bytes(&bytes, registry, self.network)
                .map_err(|error| HaltProofError::Certificate(error.to_string()))?;
            if re_verified.checkpoint_id() != checkpoint.id() {
                return Err(HaltProofError::CertificateMismatch);
            }
        }
        let first = self.first.0.id();
        let second = self.second.0.id();
        if first == second {
            return Err(HaltProofError::NoConflict);
        }
        Ok(HaltReason::ConflictingFinality {
            height: self.height,
            first,
            second,
        })
    }

    /// Encode: `tag ‖ version ‖ network(8) ‖ generation(32) ‖ height(8) ‖ halves`.
    ///
    /// Each half is `checkpoint_len(u32) ‖ checkpoint ‖ cert_len(u32) ‖ cert`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.push(HALT_PROOF_TAG);
        out.push(HALT_PROOF_VERSION);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        for (checkpoint, certificate) in [&self.first, &self.second] {
            let bytes = checkpoint.encode();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
            let bytes = certificate.encode();
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        out
    }

    /// Strict decoding. Certificates are re-verified here, so a decoded proof has
    /// already passed the cryptographic half of [`Self::verify`].
    pub fn decode(bytes: &[u8], registry: &ValidatorRegistry) -> Result<Self, HaltProofError> {
        if bytes.len() > MAX_HALT_PROOF_BYTES {
            return Err(HaltProofError::Malformed("longer than the limit"));
        }
        if bytes.first() != Some(&HALT_PROOF_TAG) {
            return Err(HaltProofError::NotAProof("missing tag"));
        }
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8], HaltProofError> {
            let end = at
                .checked_add(n)
                .ok_or(HaltProofError::Malformed("length"))?;
            if end > bytes.len() {
                return Err(HaltProofError::Malformed("truncated"));
            }
            let slice = &bytes[at..end];
            at = end;
            Ok(slice)
        };
        let mut u32_at = |slice: &[u8]| -> u32 {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(slice);
            u32::from_le_bytes(raw)
        };
        let mut u64_at = |slice: &[u8]| -> u64 {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(slice);
            u64::from_le_bytes(raw)
        };
        let mut id_at = |slice: &[u8]| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(slice);
            out
        };

        take(1)?; // tag, already checked
        let version = take(1)?[0];
        if version != HALT_PROOF_VERSION {
            return Err(HaltProofError::Version(version));
        }
        let network = u64_at(take(8)?);
        let generation = GenerationId(id_at(take(32)?));
        let height = CheckpointHeight(u64_at(take(8)?));

        let mut halves = Vec::with_capacity(2);
        for _ in 0..2 {
            let len = u32_at(take(4)?) as usize;
            if len > MAX_HALT_PROOF_BYTES {
                return Err(HaltProofError::Malformed("checkpoint too large"));
            }
            let checkpoint = Checkpoint::decode(take(len)?)
                .map_err(|error| HaltProofError::Checkpoint(error.to_string()))?;
            let len = u32_at(take(4)?) as usize;
            if len > MAX_HALT_PROOF_BYTES {
                return Err(HaltProofError::Malformed("certificate too large"));
            }
            let bytes = take(len)?;
            let certificate = PrecommitCertificate::from_bytes(bytes, registry, network)
                .map_err(|error| HaltProofError::Certificate(error.to_string()))?;
            halves.push((checkpoint, certificate));
        }
        if at != bytes.len() {
            return Err(HaltProofError::Malformed("trailing bytes"));
        }
        let second = halves
            .pop()
            .ok_or(HaltProofError::Malformed("second half"))?;
        let first = halves
            .pop()
            .ok_or(HaltProofError::Malformed("first half"))?;
        Ok(Self {
            network,
            generation,
            height,
            first,
            second,
        })
    }
}
