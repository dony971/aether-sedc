//! L2 READY attestations (`N-READY-*`, `N-GATE-8`).
//!
//! # The four notions, kept separate
//!
//! | Notion | Meaning | Established by |
//! |---|---|---|
//! | `READY` | a validator signs an intent to participate in a transition | this module |
//! | `INSTALLED` | the new set is applied locally | node storage |
//! | `ACTIVE` | the new set is authorised by the protocol | checkpoint at `h_close + 1` |
//! | `LIVE` | the new set is operationally able to make progress | **observation only** |
//!
//! **`READY` is not a proof of future availability.** It is a signed statement
//! about the past: "at height `h_ready` I was willing to join". Between that
//! signature and the moment the new generation must produce a quorum, any
//! signer may go offline. A satisfied READY quorum therefore says nothing
//! about whether the installed set will reach quorum — that requires observed
//! online weight, which no attestation can provide.
//!
//! # Signatures
//!
//! A [`ReadyAttestation`] carries a digest to sign, but **no signature is
//! verified in this module**: L2 has no key registry yet (votes are a later
//! lot). Consequently a `Reached` outcome here means "the claimed weight of
//! well-formed, correctly-bound attestations reaches quorum", not "these
//! attestations are authentic". This limitation is recorded in the mission
//! deviations.

use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

use crate::consensus::generation::{
    quorum_met, CheckpointHeight, Generation, GenerationId, ValidatorId, ValidatorWeight,
};
use crate::consensus::roots::{hash_parts, DOMAIN_READY};

/// Current READY encoding version.
pub const READY_VERSION: u8 = 1;

/// Errors produced while decoding an attestation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadyError {
    /// Unknown version.
    #[error("unsupported ready version {0}")]
    UnsupportedVersion(u8),

    /// Length disagrees with the declared content.
    #[error("malformed ready encoding (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
}

/// Encoded size of a READY attestation.
const READY_LEN: usize = 1 + 8 + 32 + 32 + 32 + 8 + 8 + 32 + 8;

/// One validator's signed readiness intent for a transition candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyAttestation {
    /// Encoding version.
    pub version: u8,
    /// Network discriminator (cross-network replay guard).
    pub network: u64,
    /// Source generation `g_src`.
    pub generation: GenerationId,
    /// Candidate transition identifier.
    pub candidate: [u8; 32],
    /// Validator-set root the signer commits to.
    pub new_set_root: [u8; 32],
    /// Height at which the intent was signed (`h_ready`).
    pub height: CheckpointHeight,
    /// Monotone per-`(signer, candidate)` sequence (`N-READY-4`).
    pub sequence: u64,
    /// Signer.
    pub signer: ValidatorId,
    /// Weight the signer claims (checked against the pinned weight).
    pub claimed_weight: ValidatorWeight,
}

impl ReadyAttestation {
    /// Build an attestation at the current version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: u64,
        generation: GenerationId,
        candidate: [u8; 32],
        new_set_root: [u8; 32],
        height: CheckpointHeight,
        sequence: u64,
        signer: ValidatorId,
        claimed_weight: ValidatorWeight,
    ) -> Self {
        Self {
            version: READY_VERSION,
            network,
            generation,
            candidate,
            new_set_root,
            height,
            sequence,
            signer,
            claimed_weight,
        }
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(READY_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.candidate);
        out.extend_from_slice(&self.new_set_root);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.signer.0);
        out.extend_from_slice(&self.claimed_weight.get().to_le_bytes());
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReadyError> {
        if bytes.len() != READY_LEN {
            return Err(ReadyError::MalformedEncoding {
                expected: READY_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != READY_VERSION {
            return Err(ReadyError::UnsupportedVersion(version));
        }
        let mut p = 1usize;
        let network = take_u64(bytes, &mut p);
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut new_set_root = [0u8; 32];
        new_set_root.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let height = CheckpointHeight(take_u64(bytes, &mut p));
        let sequence = take_u64(bytes, &mut p);
        let mut signer = [0u8; 32];
        signer.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let claimed_weight = ValidatorWeight(take_u64(bytes, &mut p));
        Ok(Self {
            version,
            network,
            generation: GenerationId(generation),
            candidate,
            new_set_root,
            height,
            sequence,
            signer: ValidatorId(signer),
            claimed_weight,
        })
    }

    /// Digest the signer is expected to sign.
    ///
    /// Domain-separated and versioned: a signature over a READY digest can
    /// never be replayed as a vote or a checkpoint signature.
    pub fn digest(&self) -> [u8; 32] {
        hash_parts(DOMAIN_READY, &[&self.encode()[..]])
    }
}

fn take_u64(bytes: &[u8], p: &mut usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*p..*p + 8]);
    *p += 8;
    u64::from_le_bytes(buf)
}

/// What a READY set is being evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyExpectation {
    /// Expected network.
    pub network: u64,
    /// Expected source generation.
    pub generation: GenerationId,
    /// Expected candidate identifier.
    pub candidate: [u8; 32],
    /// Expected new-set root.
    pub new_set_root: [u8; 32],
    /// Closing height of the source generation.
    pub h_close: CheckpointHeight,
}

/// Readiness parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessConfig {
    /// Freshness window in heights (`N-GATE-8(a)`).
    ///
    /// Undecided: A-06.6-AR `§1.2` derives `D_ready = 2·Δ_min`, which needs
    /// the transition cooldown, which needs the round timing. Kept explicit
    /// and configurable rather than baked in.
    pub d_ready: u64,
}

impl ReadinessConfig {
    /// Build a configuration.
    pub const fn new(d_ready: u64) -> Self {
        Self { d_ready }
    }

    /// A configuration usable only in tests and examples.
    ///
    /// **Not normative.**
    pub const fn non_normative_test_default() -> Self {
        Self { d_ready: 6 }
    }

    /// Whether an attestation signed at `h_ready` is still fresh at `h_close`.
    pub fn is_fresh(&self, h_close: CheckpointHeight, h_ready: CheckpointHeight) -> bool {
        h_close.since(h_ready) <= self.d_ready
    }
}

/// Why an attestation did not contribute weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadyRejection {
    /// Wrong version byte.
    VersionMismatch,
    /// Different network.
    WrongNetwork,
    /// Different source generation.
    WrongGeneration,
    /// Different candidate.
    WrongCandidate,
    /// Different new-set root.
    WrongSetRoot,
    /// Signed for a height in the future relative to `h_close`.
    FutureHeight,
    /// Outside the freshness window.
    Stale,
    /// Signer is not a member of the candidate set.
    NonMember,
    /// Claimed weight differs from the pinned weight.
    WeightMismatch,
    /// Two different attestations for the same signer and sequence.
    ConflictingSequence,
}

impl fmt::Display for ReadyRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::VersionMismatch => "version mismatch",
            Self::WrongNetwork => "wrong network",
            Self::WrongGeneration => "wrong generation",
            Self::WrongCandidate => "wrong candidate",
            Self::WrongSetRoot => "wrong set root",
            Self::FutureHeight => "future height",
            Self::Stale => "stale",
            Self::NonMember => "non-member",
            Self::WeightMismatch => "weight mismatch",
            Self::ConflictingSequence => "conflicting sequence",
        };
        f.write_str(s)
    }
}

/// Result of evaluating a set of attestations.
///
/// [`Self::reached`] means a quorum of **declared** weight was reached by
/// well-formed attestations. It does **not** mean the signers are currently
/// online, nor that the installed generation will be able to progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessOutcome {
    /// Whether the READY quorum was reached.
    pub reached: bool,
    /// Sum of pinned weights of counted signers.
    pub weight: ValidatorWeight,
    /// Number of distinct counted signers.
    pub distinct_signers: usize,
    /// Signers that contributed weight (sorted by id).
    pub accepted: Vec<ValidatorId>,
    /// Rejected attestations (sorted by signer, then reason).
    pub rejected: Vec<(ValidatorId, ReadyRejection)>,
}

impl ReadinessOutcome {
    /// Whether the outcome is *only* evidence of a past intent.
    ///
    /// Always true: kept as an explicit call site reminder that this value
    /// must never be consumed as a liveness signal.
    pub fn is_past_intent_only(&self) -> bool {
        true
    }
}

/// Evaluate attestations against an expectation and a candidate generation.
///
/// Deterministic: signers are grouped in a `BTreeMap`, so the outcome does not
/// depend on arrival order.
pub fn evaluate(
    attestations: &[ReadyAttestation],
    expected: &ReadyExpectation,
    candidate_generation: &Generation,
    config: &ReadinessConfig,
) -> ReadinessOutcome {
    let mut rejected: Vec<(ValidatorId, ReadyRejection)> = Vec::new();
    let mut by_signer: BTreeMap<ValidatorId, ReadyAttestation> = BTreeMap::new();
    let mut conflicted: BTreeMap<ValidatorId, ReadyRejection> = BTreeMap::new();

    for att in attestations {
        if att.version != READY_VERSION {
            rejected.push((att.signer, ReadyRejection::VersionMismatch));
            continue;
        }
        if att.network != expected.network {
            rejected.push((att.signer, ReadyRejection::WrongNetwork));
            continue;
        }
        if att.generation != expected.generation {
            rejected.push((att.signer, ReadyRejection::WrongGeneration));
            continue;
        }
        if att.candidate != expected.candidate {
            rejected.push((att.signer, ReadyRejection::WrongCandidate));
            continue;
        }
        if att.new_set_root != expected.new_set_root {
            rejected.push((att.signer, ReadyRejection::WrongSetRoot));
            continue;
        }
        if att.height.get() > expected.h_close.get() {
            rejected.push((att.signer, ReadyRejection::FutureHeight));
            continue;
        }
        if !config.is_fresh(expected.h_close, att.height) {
            rejected.push((att.signer, ReadyRejection::Stale));
            continue;
        }
        match candidate_generation.weight_of(&att.signer) {
            None => {
                rejected.push((att.signer, ReadyRejection::NonMember));
                continue;
            }
            Some(pinned) => {
                if pinned.get() != att.claimed_weight.get() {
                    rejected.push((att.signer, ReadyRejection::WeightMismatch));
                    continue;
                }
            }
        }

        match by_signer.get(&att.signer) {
            None => {
                by_signer.insert(att.signer, *att);
            }
            Some(existing) => {
                if att.sequence > existing.sequence {
                    by_signer.insert(att.signer, *att);
                } else if att.sequence == existing.sequence && att.digest() != existing.digest() {
                    // Same signer, same sequence, different content: the
                    // attestation cannot be counted either way.
                    conflicted.insert(att.signer, ReadyRejection::ConflictingSequence);
                }
                // Lower sequence: superseded, silently dropped (N-GATE-8(b)).
            }
        }
    }

    let mut accepted: Vec<ValidatorId> = Vec::new();
    let mut weight: u64 = 0;
    for (signer, att) in &by_signer {
        if let Some(reason) = conflicted.get(signer) {
            rejected.push((*signer, *reason));
            continue;
        }
        accepted.push(*signer);
        weight = weight.saturating_add(att.claimed_weight.get());
    }

    rejected.sort_by_key(|(id, reason)| (*id, *reason));

    let weight = ValidatorWeight(weight);
    ReadinessOutcome {
        reached: quorum_met(weight, candidate_generation.total_weight()),
        weight,
        distinct_signers: accepted.len(),
        accepted,
        rejected,
    }
}
