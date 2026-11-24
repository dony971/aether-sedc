//! L2 quorum certificates.
//!
//! # The rule this module enforces
//!
//! **No weight carried by a certificate is ever used.** Everything is recomputed
//! from the registry and from the signatures:
//!
//! 1. registry root and set root, recomputed from the registry bytes;
//! 2. every signature, against the registry's public key;
//! 3. signer uniqueness;
//! 4. per-signer weight, read from the registry;
//! 5. total weight = sum over **admissible** registry entries;
//! 6. support weight = sum over distinct signers;
//! 7. quorum, as `3·support ≥ 2·total`.
//!
//! The `total_weight` and `support_weight` fields exist in the wire format so a
//! reader can see what the producer claimed. They are compared against the
//! recomputation and a mismatch is a **hard error** (`DeclaredWeightMismatch`),
//! never a correction: a certificate that lies about its own weight is rejected,
//! not silently fixed.
//!
//! # What a verified QC does NOT establish
//!
//! - that the checkpoint is a legitimate successor (acceptance rules);
//! - that the signers are independent operators (`A-INDEP`, undecided);
//! - that the network is live, or that the certificate's existence implies
//!   future progress.
//!
//! A QC proves that a set of keys, whose weights the registry fixes, signed the
//! same tuple and that those weights reach the threshold. Nothing more.

use std::fmt;

use thiserror::Error;

use crate::consensus::generation::{
    quorum_met, quorum_threshold, CheckpointHeight, Generation, GenerationId, Round, ValidatorId,
    ValidatorWeight,
};
use crate::l2crypto::frame::{frame_hash, le32, le64};
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::{ConsensusVote, VoteError, VotePhase, VoteVerifyError, VOTE_LEN};

/// Current QC encoding version.
pub const QC_FORMAT_VERSION: u8 = 1;

/// Domain tag for a QC identifier.
pub const DOMAIN_QC: &[u8] = b"AETHER-L2-QC-v1";

/// Fixed size of a QC without votes: `1+8+32+8+4+1+32+32+32+8+8+4`.
const QC_HEADER_LEN: usize = 170;

/// QC construction and decoding failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QcError {
    /// Length disagrees with the declared vote count.
    #[error("malformed QC encoding (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Unknown encoding version.
    #[error("unsupported QC version {0}")]
    UnsupportedVersion(u8),

    /// A certificate with no vote is not a certificate.
    #[error("QC carries no vote")]
    NoVotes,

    /// Unknown phase byte.
    #[error("unknown phase byte {0}")]
    UnknownPhase(u8),

    /// QC generation differs from the registry's.
    #[error("QC generation does not match the registry")]
    GenerationMismatch,

    /// Recomputing the registry root does not reproduce the committed value.
    #[error("QC registry root does not match the recomputed registry")]
    RegistryRootMismatch,

    /// The committed set root is not the one of the supplied registry.
    #[error("QC validator set root does not match the recomputed registry")]
    SetRootMismatch,

    /// A vote did not verify.
    #[error("vote rejected: {0}")]
    Vote(#[from] VoteVerifyError),

    /// A vote could not be decoded.
    #[error("vote decoding failed: {0}")]
    VoteDecode(#[from] VoteError),

    /// The same validator signed twice.
    #[error("duplicate signer {0}")]
    DuplicateSigner(ValidatorId),

    /// A vote refers to another position than the certificate.
    #[error("vote does not belong to the certificate context")]
    MixedContext,

    /// The declared weights do not match the recomputation.
    #[error("declared weights {declared_support}/{declared_total} do not match recomputed {computed_support}/{computed_total}")]
    DeclaredWeightMismatch {
        /// Declared support.
        declared_support: u64,
        /// Declared total.
        declared_total: u64,
        /// Recomputed support.
        computed_support: u64,
        /// Recomputed total.
        computed_total: u64,
    },

    /// Support stays below the threshold.
    #[error("QC support {support} below quorum {quorum} of {total}")]
    NotQuorate {
        /// Recomputed support.
        support: u64,
        /// Required threshold.
        quorum: u64,
        /// Recomputed total.
        total: u64,
    },

    /// Support weight does not fit in `u64`.
    #[error("support weight overflow")]
    WeightOverflow,

    /// The pairing generation does not agree with the certificate.
    #[error("generation record does not match the certificate")]
    GenerationRecordMismatch,

    /// A generation record was paired with a mismatching registry.
    #[error("registry does not describe the paired generation")]
    RegistryGenerationMismatch,
}

/// A quorum certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    /// Encoding version.
    pub version: u8,
    /// Network discriminator.
    pub network: u64,
    /// Generation.
    pub generation: GenerationId,
    /// Height.
    pub height: CheckpointHeight,
    /// Round.
    pub round: Round,
    /// Phase.
    pub phase: VotePhase,
    /// Certified checkpoint.
    pub checkpoint_id: [u8; 32],
    /// Set root over `(id, weight)` — bridges to the AS generation/checkpoint.
    pub validator_set_root: [u8; 32],
    /// Registry root over keys, weights, admissibility and generation.
    pub registry_root: [u8; 32],
    /// Weight claimed by the producer. **Never trusted.**
    pub total_weight: ValidatorWeight,
    /// Support claimed by the producer. **Never trusted.**
    pub support_weight: ValidatorWeight,
    /// Signed votes.
    pub votes: Vec<ConsensusVote>,
}

/// Recomputed result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQc {
    /// Support weight, recomputed.
    pub support: ValidatorWeight,
    /// Total admissible weight, recomputed.
    pub total: ValidatorWeight,
    /// Required threshold for this total.
    pub quorum: ValidatorWeight,
    /// Distinct signers, sorted by id.
    pub signers: Vec<ValidatorId>,
}

impl QuorumCertificate {
    /// Build a certificate, computing the roots from `registry`.
    ///
    /// The declared weights are filled from the votes so a freshly built
    /// certificate verifies; producers that lie will be rejected on verify.
    pub fn new(
        network: u64,
        registry: &ValidatorRegistry,
        height: CheckpointHeight,
        round: Round,
        phase: VotePhase,
        checkpoint_id: [u8; 32],
        votes: Vec<ConsensusVote>,
    ) -> Self {
        let total = registry.total_voting_weight();
        let mut support: u64 = 0;
        let mut seen: Vec<ValidatorId> = Vec::new();
        for vote in &votes {
            if seen.contains(&vote.validator) {
                continue;
            }
            if let Some(w) = registry.voting_weight(&vote.validator) {
                seen.push(vote.validator);
                support = support.saturating_add(w.get());
            }
        }
        Self {
            version: QC_FORMAT_VERSION,
            network,
            generation: registry.generation(),
            height,
            round,
            phase,
            checkpoint_id,
            validator_set_root: registry.set_root(),
            registry_root: registry.root(),
            total_weight: total,
            support_weight: ValidatorWeight(support),
            votes,
        }
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(QC_HEADER_LEN + VOTE_LEN * self.votes.len());
        out.push(self.version);
        out.extend_from_slice(&le64(self.network));
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&le64(self.height.get()));
        out.extend_from_slice(&le32(self.round.get()));
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.checkpoint_id);
        out.extend_from_slice(&self.validator_set_root);
        out.extend_from_slice(&self.registry_root);
        out.extend_from_slice(&le64(self.total_weight.get()));
        out.extend_from_slice(&le64(self.support_weight.get()));
        out.extend_from_slice(&(self.votes.len() as u32).to_le_bytes());
        for vote in &self.votes {
            out.extend_from_slice(&vote.encode());
        }
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, QcError> {
        if bytes.len() < QC_HEADER_LEN {
            return Err(QcError::MalformedEncoding {
                expected: QC_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != QC_FORMAT_VERSION {
            return Err(QcError::UnsupportedVersion(bytes[0]));
        }
        let version = bytes[0];
        let network = rd_u64(bytes, 1);
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[9..41]);
        let height = CheckpointHeight(rd_u64(bytes, 41));
        let round = Round(rd_u32(bytes, 49));
        let phase = VotePhase::from_u8(bytes[53]).ok_or(QcError::UnknownPhase(bytes[53]))?;
        let mut checkpoint_id = [0u8; 32];
        checkpoint_id.copy_from_slice(&bytes[54..86]);
        let mut validator_set_root = [0u8; 32];
        validator_set_root.copy_from_slice(&bytes[86..118]);
        let mut registry_root = [0u8; 32];
        registry_root.copy_from_slice(&bytes[118..150]);
        let total_weight = ValidatorWeight(rd_u64(bytes, 150));
        let support_weight = ValidatorWeight(rd_u64(bytes, 158));
        let count = rd_u32(bytes, 166) as usize;
        let expected = QC_HEADER_LEN
            .checked_add(
                VOTE_LEN
                    .checked_mul(count)
                    .ok_or(QcError::MalformedEncoding {
                        expected: usize::MAX,
                        actual: bytes.len(),
                    })?,
            )
            .ok_or(QcError::MalformedEncoding {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if bytes.len() != expected {
            return Err(QcError::MalformedEncoding {
                expected,
                actual: bytes.len(),
            });
        }
        let mut votes = Vec::with_capacity(count);
        let mut p = QC_HEADER_LEN;
        for _ in 0..count {
            votes.push(ConsensusVote::decode(&bytes[p..p + VOTE_LEN])?);
            p += VOTE_LEN;
        }
        Ok(Self {
            version,
            network,
            generation: GenerationId(generation),
            height,
            round,
            phase,
            checkpoint_id,
            validator_set_root,
            registry_root,
            total_weight,
            support_weight,
            votes,
        })
    }

    /// Content-addressed identifier.
    pub fn id(&self) -> [u8; 32] {
        frame_hash(DOMAIN_QC, &[&self.encode()[..]])
    }

    /// Whether two certificates certify different checkpoints at the same
    /// position.
    ///
    /// This is the "contradictory certificate" case: same generation, height,
    /// round and phase, different `checkpoint_id`. Both cannot be legitimate
    /// under the safety assumption `F ≤ I − 1`.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.height == other.height
            && self.round == other.round
            && self.phase == other.phase
            && self.checkpoint_id != other.checkpoint_id
    }

    /// Full verification against a registry.
    ///
    /// Recomputes every value; the declared weights must match or the
    /// certificate is rejected.
    pub fn verify(
        &self,
        registry: &ValidatorRegistry,
        expected_network: u64,
    ) -> Result<VerifiedQc, QcError> {
        if self.version != QC_FORMAT_VERSION {
            return Err(QcError::UnsupportedVersion(self.version));
        }
        if self.votes.is_empty() {
            return Err(QcError::NoVotes);
        }
        if registry.generation() != self.generation {
            return Err(QcError::GenerationMismatch);
        }
        // 1. Roots, recomputed from the registry bytes.
        if self.registry_root != registry.root() {
            return Err(QcError::RegistryRootMismatch);
        }
        // 2. The committed set root must be the registry's own.
        if self.validator_set_root != registry.set_root() {
            return Err(QcError::SetRootMismatch);
        }
        // 3-4. Every signature, against the registry key.
        let mut signers: Vec<ValidatorId> = Vec::with_capacity(self.votes.len());
        let mut support: u128 = 0;
        for vote in &self.votes {
            if vote.network != expected_network
                || vote.generation != self.generation
                || vote.height != self.height
                || vote.round != self.round
                || vote.phase != self.phase
                || vote.checkpoint_id != self.checkpoint_id
            {
                return Err(QcError::MixedContext);
            }
            let verified = vote.verify(registry, expected_network)?;
            if signers.contains(&verified.signer) {
                return Err(QcError::DuplicateSigner(verified.signer));
            }
            signers.push(verified.signer);
            support += verified.weight.get() as u128;
            if support > u64::MAX as u128 {
                return Err(QcError::WeightOverflow);
            }
        }
        // 5-6. Totals.
        let total = registry.total_voting_weight();
        let support_w = ValidatorWeight(support as u64);
        // 6b. The producer must not have lied about its own numbers.
        if self.total_weight.get() != total.get() || self.support_weight.get() != support_w.get() {
            return Err(QcError::DeclaredWeightMismatch {
                declared_support: self.support_weight.get(),
                declared_total: self.total_weight.get(),
                computed_support: support_w.get(),
                computed_total: total.get(),
            });
        }
        // 7. Quorum.
        if !quorum_met(support_w, total) {
            return Err(QcError::NotQuorate {
                support: support_w.get(),
                quorum: quorum_threshold(total).get(),
                total: total.get(),
            });
        }
        signers.sort();
        Ok(VerifiedQc {
            support: support_w,
            total,
            quorum: quorum_threshold(total),
            signers,
        })
    }

    /// Verification that additionally proves the certificate describes an
    /// existing generation record.
    ///
    /// The AS layer's `Generation` commits `set_root` over `(id, weight)`; this
    /// check ties the certificate to it, so a QC cannot name a generation that
    /// does not exist.
    pub fn verify_with_generation(
        &self,
        registry: &ValidatorRegistry,
        generation: &Generation,
        expected_network: u64,
    ) -> Result<VerifiedQc, QcError> {
        if generation.id() != self.generation {
            return Err(QcError::GenerationRecordMismatch);
        }
        if generation.set_root() != self.validator_set_root {
            return Err(QcError::GenerationRecordMismatch);
        }
        if generation.set_root() != registry.set_root() {
            return Err(QcError::RegistryGenerationMismatch);
        }
        self.verify(registry, expected_network)
    }
}

impl fmt::Display for QuorumCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "qc[h={}, r={}, {}, support={}/{}, votes={}]",
            self.height.get(),
            self.round.get(),
            self.phase,
            self.support_weight,
            self.total_weight,
            self.votes.len()
        )
    }
}

fn rd_u64(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

fn rd_u32(bytes: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(buf)
}
