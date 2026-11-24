//! Authenticated READY attestations — the correction of AS deviation **D-5**.
//!
//! # Difference from `consensus::readiness`
//!
//! `consensus::readiness::ReadyAttestation` carries a `claimed_weight` field and
//! verifies **no signature**. That type remains in place because the AS test
//! suite depends on it, but it must never drive a decision. This module provides
//! the authenticated path:
//!
//! | Property | `readiness::ReadyAttestation` | `SignedReady` (here) |
//! |---|---|---|
//! | signature | none | Ed25519 over a domain-tagged frame |
//! | weight | declared by the signer | **looked up in the candidate registry** |
//! | signer binding | by id, unchecked | id → registry public key |
//! | replay across contexts | prevented only by field checks | cryptographically bound |
//!
//! There is no weight field at all in [`SignedReady`]: the type cannot carry a
//! number a signer chose.
//!
//! # The invariant this module protects
//!
//! **An authentic READY is still not a promise of future availability.** It is a
//! signed statement about the past: "at height `h_ready` I held this key and was
//! willing to join". The signer may go offline one second later. Nothing here,
//! and nothing anywhere in L2, converts signatures into observed uptime. Liveness
//! requires witnessed online weight, which is an observation, not an artefact.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

use crate::consensus::generation::{
    quorum_met, CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use crate::l2crypto::frame::{frame, le64};
use crate::l2crypto::registry::ValidatorRegistry;

/// Current signed-READY version.
pub const SIGNED_READY_VERSION: u8 = 1;

/// Domain tag for a signed READY.
pub const DOMAIN_READY: &[u8] = b"AETHER-L2-READY2-v1";

/// Encoded size: `1+8+32+32+32+32+8+8+32+64`.
pub const SIGNED_READY_LEN: usize = 249;

/// Decoding failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignedReadyError {
    /// Length disagrees with the fixed layout.
    #[error("malformed signed READY (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Unknown version.
    #[error("unsupported signed READY version {0}")]
    UnsupportedVersion(u8),
}

/// Why an attestation was not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadyReject {
    /// Wrong version byte.
    VersionMismatch,
    /// Another network.
    WrongNetwork,
    /// Another source generation.
    WrongGeneration,
    /// Another transition candidate.
    WrongCandidate,
    /// Another new-set root.
    WrongSetRoot,
    /// Another reference checkpoint.
    WrongReference,
    /// Signed at a height after the closing height.
    FutureHeight,
    /// Outside the freshness window.
    Stale,
    /// Signer absent from the candidate registry.
    NonMember,
    /// Signer present but not admissible.
    Ineligible,
    /// Signature does not verify against the registry key.
    BadSignature,
    /// Two different attestations for one signer at the same sequence.
    ConflictingSequence,
}

/// A signed readiness intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedReady {
    /// Encoding version.
    pub version: u8,
    /// Network discriminator.
    pub network: u64,
    /// Source generation `g_src`.
    pub generation: GenerationId,
    /// Transition candidate identifier.
    pub candidate: [u8; 32],
    /// Root of the set the signer commits to.
    pub new_set_root: [u8; 32],
    /// Checkpoint the intent refers to.
    pub reference_checkpoint: [u8; 32],
    /// Height at which the intent was signed (`h_ready`).
    pub h_ready: CheckpointHeight,
    /// Monotone per-`(signer, candidate)` sequence.
    pub sequence: u64,
    /// Signer.
    pub signer: ValidatorId,
    /// Ed25519 signature over [`Self::signing_bytes`].
    pub signature: [u8; 64],
}

impl SignedReady {
    /// Build an attestation with an empty signature.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: u64,
        generation: GenerationId,
        candidate: [u8; 32],
        new_set_root: [u8; 32],
        reference_checkpoint: [u8; 32],
        h_ready: CheckpointHeight,
        sequence: u64,
        signer: ValidatorId,
    ) -> Self {
        Self {
            version: SIGNED_READY_VERSION,
            network,
            generation,
            candidate,
            new_set_root,
            reference_checkpoint,
            h_ready,
            sequence,
            signer,
            signature: [0u8; 64],
        }
    }

    /// Attach a signature.
    pub fn with_signature(mut self, signature: [u8; 64]) -> Self {
        self.signature = signature;
        self
    }

    /// The exact byte string that is signed.
    pub fn signing_bytes(&self) -> Vec<u8> {
        frame(
            DOMAIN_READY,
            &[
                &[self.version][..],
                &le64(self.network)[..],
                &self.generation.0[..],
                &self.candidate[..],
                &self.new_set_root[..],
                &self.reference_checkpoint[..],
                &le64(self.h_ready.get())[..],
                &le64(self.sequence)[..],
                &self.signer.0[..],
            ],
        )
    }

    /// Canonical encoding (signing fields plus signature, fixed layout).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_READY_LEN);
        out.push(self.version);
        out.extend_from_slice(&le64(self.network));
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.candidate);
        out.extend_from_slice(&self.new_set_root);
        out.extend_from_slice(&self.reference_checkpoint);
        out.extend_from_slice(&le64(self.h_ready.get()));
        out.extend_from_slice(&le64(self.sequence));
        out.extend_from_slice(&self.signer.0);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignedReadyError> {
        if bytes.len() != SIGNED_READY_LEN {
            return Err(SignedReadyError::MalformedEncoding {
                expected: SIGNED_READY_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != SIGNED_READY_VERSION {
            return Err(SignedReadyError::UnsupportedVersion(bytes[0]));
        }
        let version = bytes[0];
        let network = rd_u64(bytes, 1);
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[9..41]);
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&bytes[41..73]);
        let mut new_set_root = [0u8; 32];
        new_set_root.copy_from_slice(&bytes[73..105]);
        let mut reference_checkpoint = [0u8; 32];
        reference_checkpoint.copy_from_slice(&bytes[105..137]);
        let h_ready = CheckpointHeight(rd_u64(bytes, 137));
        let sequence = rd_u64(bytes, 145);
        let mut signer = [0u8; 32];
        signer.copy_from_slice(&bytes[153..185]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[185..249]);
        Ok(Self {
            version,
            network,
            generation: GenerationId(generation),
            candidate,
            new_set_root,
            reference_checkpoint,
            h_ready,
            sequence,
            signer: ValidatorId(signer),
            signature,
        })
    }

    /// Verify against the **candidate** registry and an expectation.
    ///
    /// Returns the weight the registry assigns to the signer in the new set. A
    /// signer absent from that set, or whose registry key does not verify the
    /// signature, is rejected — the claimed identity alone is worthless.
    pub fn verify(
        &self,
        candidate_registry: &ValidatorRegistry,
        expected: &SignedReadyExpectation,
    ) -> Result<ValidatorWeight, ReadyReject> {
        if self.version != SIGNED_READY_VERSION {
            return Err(ReadyReject::VersionMismatch);
        }
        if self.network != expected.network {
            return Err(ReadyReject::WrongNetwork);
        }
        if self.generation != expected.generation {
            return Err(ReadyReject::WrongGeneration);
        }
        if self.candidate != expected.candidate {
            return Err(ReadyReject::WrongCandidate);
        }
        if self.new_set_root != expected.new_set_root {
            return Err(ReadyReject::WrongSetRoot);
        }
        if self.reference_checkpoint != expected.reference_checkpoint {
            return Err(ReadyReject::WrongReference);
        }
        if self.h_ready.get() > expected.h_close.get() {
            return Err(ReadyReject::FutureHeight);
        }
        if expected.h_close.since(self.h_ready) > expected.d_ready {
            return Err(ReadyReject::Stale);
        }
        let entry = candidate_registry
            .get(&self.signer)
            .ok_or(ReadyReject::NonMember)?;
        if !entry.admissibility.may_vote() {
            return Err(ReadyReject::Ineligible);
        }
        let key =
            VerifyingKey::from_bytes(&entry.public_key).map_err(|_| ReadyReject::BadSignature)?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&self.signing_bytes(), &sig)
            .map_err(|_| ReadyReject::BadSignature)?;
        Ok(entry.weight)
    }
}

/// What a signed READY is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedReadyExpectation {
    /// Network.
    pub network: u64,
    /// Source generation.
    pub generation: GenerationId,
    /// Candidate identifier.
    pub candidate: [u8; 32],
    /// Candidate set root.
    pub new_set_root: [u8; 32],
    /// Reference checkpoint.
    pub reference_checkpoint: [u8; 32],
    /// Closing height of the source generation.
    pub h_close: CheckpointHeight,
    /// Freshness window in heights (undecided: A-06.6-AR §1.2).
    pub d_ready: u64,
}

/// Result of evaluating a set of authenticated attestations.
///
/// [`Self::reached`] means a quorum of **registry weight** signed. It does not
/// mean the signers are online, reachable, or independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReadinessOutcome {
    /// Whether the READY quorum was reached.
    pub reached: bool,
    /// Registered weight of counted signers.
    pub weight: ValidatorWeight,
    /// Distinct counted signers.
    pub distinct_signers: usize,
    /// Counted signers (sorted).
    pub accepted: Vec<ValidatorId>,
    /// Rejections (sorted by signer then reason).
    pub rejected: Vec<(ValidatorId, ReadyReject)>,
}

impl SignedReadinessOutcome {
    /// Reminder kept as a call site: this value is evidence of a past intent.
    pub fn is_past_intent_only(&self) -> bool {
        true
    }
}

/// Evaluate authenticated attestations against the candidate registry.
///
/// Deterministic: signers are grouped in a `BTreeMap`, so arrival order does not
/// matter. The candidate registry must match the expected set root; otherwise
/// every attestation is rejected as `WrongSetRoot`.
pub fn evaluate_signed(
    attestations: &[SignedReady],
    expected: &SignedReadyExpectation,
    candidate_registry: &ValidatorRegistry,
) -> SignedReadinessOutcome {
    let registry_matches = candidate_registry.set_root() == expected.new_set_root;
    let mut rejected: Vec<(ValidatorId, ReadyReject)> = Vec::new();
    let mut by_signer: BTreeMap<ValidatorId, SignedReady> = BTreeMap::new();
    let mut conflicted: BTreeMap<ValidatorId, ReadyReject> = BTreeMap::new();

    for att in attestations {
        if !registry_matches {
            rejected.push((att.signer, ReadyReject::WrongSetRoot));
            continue;
        }
        match att.verify(candidate_registry, expected) {
            Ok(_) => {}
            Err(reason) => {
                rejected.push((att.signer, reason));
                continue;
            }
        }
        match by_signer.get(&att.signer) {
            None => {
                by_signer.insert(att.signer, *att);
            }
            Some(existing) => {
                if att.sequence > existing.sequence {
                    by_signer.insert(att.signer, *att);
                } else if att.sequence == existing.sequence
                    && att.signing_bytes() != existing.signing_bytes()
                {
                    conflicted.insert(att.signer, ReadyReject::ConflictingSequence);
                }
            }
        }
    }

    let mut accepted: Vec<ValidatorId> = Vec::new();
    let mut weight: u64 = 0;
    for signer in by_signer.keys() {
        if let Some(reason) = conflicted.get(signer) {
            rejected.push((*signer, *reason));
            continue;
        }
        if let Some(w) = candidate_registry.voting_weight(signer) {
            accepted.push(*signer);
            weight = weight.saturating_add(w.get());
        }
    }
    rejected.sort_by_key(|(id, reason)| (*id, *reason));

    let weight = ValidatorWeight(weight);
    SignedReadinessOutcome {
        reached: quorum_met(weight, candidate_registry.total_voting_weight()),
        weight,
        distinct_signers: accepted.len(),
        accepted,
        rejected,
    }
}

fn rd_u64(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}
