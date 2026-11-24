//! Phase certificates and proof of lock.
//!
//! # Certificates are AT quorum certificates, not a second implementation
//!
//! [`QuorumCertificate`] already recomputes, on every verification: both set
//! roots, every signature against the registry key, signer uniqueness, every
//! weight, the total, the support, and the threshold — and rejects a certificate
//! whose **declared** weights diverge from the recomputation
//! (`QcError::DeclaredWeightMismatch`). Re-implementing that here would create a
//! second, divergent definition of "quorate".
//!
//! So [`PrevoteCertificate`] and [`PrecommitCertificate`] are **phase-typed
//! wrappers around a verified `QuorumCertificate`**. They cannot be constructed
//! without a successful verification, and the stored [`VerifiedQc`] is the
//! recomputation that justified it.
//!
//! # Independence of verification
//!
//! "Verifiable independently" means: given the bytes and a registry, anyone can
//! re-run the check without trusting the producer. [`PrevoteCertificate::from_bytes`]
//! and [`PrevoteCertificate::re_verify`] exist for exactly that; nothing in a
//! certificate is taken on faith.

use crate::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use crate::l2bft::context::{BftContext, BftError};
use crate::l2crypto::qc::{QcError, QuorumCertificate, VerifiedQc};
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::VotePhase;

fn map_qc_error(e: QcError) -> BftError {
    match e {
        QcError::NotQuorate {
            support,
            quorum,
            total,
        } => BftError::NotQuorate {
            support,
            quorum,
            total,
        },
        other => BftError::Rejected(other.to_string()),
    }
}

fn certify(
    qc: QuorumCertificate,
    registry: &ValidatorRegistry,
    network: u64,
    phase: VotePhase,
) -> Result<(QuorumCertificate, VerifiedQc), BftError> {
    if qc.phase != phase {
        return Err(BftError::ContextMismatch { field: "phase" });
    }
    if qc.network != network {
        return Err(BftError::ContextMismatch { field: "network" });
    }
    if qc.generation != registry.generation() {
        return Err(BftError::ContextMismatch {
            field: "generation",
        });
    }
    if qc.validator_set_root != registry.set_root() {
        return Err(BftError::ContextMismatch { field: "set_root" });
    }
    let verified = qc.verify(registry, network).map_err(map_qc_error)?;
    Ok((qc, verified))
}

macro_rules! phase_certificate {
    ($name:ident, $phase:expr, $phase_name:literal) => {
        /// A verified certificate for one phase, bound to one value.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            qc: QuorumCertificate,
            verified: VerifiedQc,
        }

        impl $name {
            /// Certify a quorum certificate at this phase.
            ///
            /// Fails unless the certificate really is quorate for the registry:
            /// signatures, identities, weights, uniqueness and threshold are all
            /// recomputed by AT.
            pub fn certify(
                qc: QuorumCertificate,
                registry: &ValidatorRegistry,
                network: u64,
            ) -> Result<Self, BftError> {
                let (qc, verified) = certify(qc, registry, network, $phase)?;
                Ok(Self { qc, verified })
            }

            /// Verify a certificate from its bytes, without trusting the sender.
            pub fn from_bytes(
                bytes: &[u8],
                registry: &ValidatorRegistry,
                network: u64,
            ) -> Result<Self, BftError> {
                let qc = QuorumCertificate::decode(bytes)
                    .map_err(|e| BftError::Rejected(format!("certificate decode: {e}")))?;
                Self::certify(qc, registry, network)
            }

            /// Canonical bytes, suitable for persistence or transport.
            pub fn encode(&self) -> Vec<u8> {
                self.qc.encode()
            }

            /// Underlying quorum certificate.
            pub fn qc(&self) -> &QuorumCertificate {
                &self.qc
            }

            /// Recomputation that justified acceptance.
            pub fn verified(&self) -> &VerifiedQc {
                &self.verified
            }

            /// The one value this certificate is bound to.
            pub fn checkpoint_id(&self) -> [u8; 32] {
                self.qc.checkpoint_id
            }

            /// Height.
            pub fn height(&self) -> CheckpointHeight {
                self.qc.height
            }

            /// Round.
            pub fn round(&self) -> Round {
                self.qc.round
            }

            /// Generation.
            pub fn generation(&self) -> GenerationId {
                self.qc.generation
            }

            /// Validator-set root.
            pub fn set_root(&self) -> [u8; 32] {
                self.qc.validator_set_root
            }

            /// Recomputed support.
            pub fn support(&self) -> ValidatorWeight {
                self.verified.support
            }

            /// Recomputed total admissible weight.
            pub fn total(&self) -> ValidatorWeight {
                self.verified.total
            }

            /// Required threshold.
            pub fn quorum(&self) -> ValidatorWeight {
                self.verified.quorum
            }

            /// Distinct signers, sorted by identifier.
            pub fn signers(&self) -> &[ValidatorId] {
                &self.verified.signers
            }

            /// Content address.
            pub fn id(&self) -> [u8; 32] {
                self.qc.id()
            }

            /// Phase marker, for reports.
            pub fn phase_name(&self) -> &'static str {
                $phase_name
            }

            /// Does this certificate sit exactly in `ctx`?
            pub fn matches(&self, ctx: &BftContext) -> bool {
                self.qc.network == ctx.network
                    && self.qc.generation == ctx.generation
                    && self.qc.height == ctx.height
                    && self.qc.round == ctx.round
                    && self.qc.phase == ctx.phase
                    && self.qc.validator_set_root == ctx.validator_set_root
            }

            /// Require an exact position, reporting the first difference.
            pub fn require_context(&self, ctx: &BftContext) -> Result<(), BftError> {
                BftContext::of_vote(
                    &crate::l2crypto::vote::ConsensusVote {
                        version: self.qc.version,
                        network: self.qc.network,
                        generation: self.qc.generation,
                        height: self.qc.height,
                        round: self.qc.round,
                        phase: self.qc.phase,
                        checkpoint_id: self.qc.checkpoint_id,
                        validator: ValidatorId([0u8; 32]),
                        signature: [0u8; 64],
                    },
                    self.qc.validator_set_root,
                )
                .require_same_position(ctx)
            }

            /// Re-run the whole verification from the stored bytes.
            pub fn re_verify(
                &self,
                registry: &ValidatorRegistry,
                network: u64,
            ) -> Result<VerifiedQc, BftError> {
                self.qc.verify(registry, network).map_err(map_qc_error)
            }
        }
    };
}

phase_certificate!(PrevoteCertificate, VotePhase::Prevote, "prevote");
phase_certificate!(PrecommitCertificate, VotePhase::Precommit, "precommit");

/// Evidence that a value was prevoted by a quorum in one round.
///
/// # Status: verifiable, and usable only through `A4'`
///
/// A proof of lock is what it provably is — a valid prevote certificate for a
/// value at a round. `AW-LOCK-1` accepts it for exactly one purpose: authorizing
/// a prevote for a value **other than the lock**, when its round sits in
/// `[lockR, r)`. It never changes the lock; only a non-Nil precommit does
/// (`AW-LOCK-2`).
///
/// Two bounds, deliberately asymmetric:
///
/// - `lockR <= proof.round` is **inclusive**: the node holding the highest `lockR`
///   owns the proof that qualifies every other honest node (`AA-2`).
/// - `proof.round < r` is **strict**: using the proof of the round being voted is
///   a safety violation (`neg a4p nonstrict n3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOfLock {
    /// Round of the certificate.
    pub round: Round,
    /// Value certified.
    pub checkpoint_id: [u8; 32],
    /// Height.
    pub height: CheckpointHeight,
    /// Generation.
    pub generation: GenerationId,
    /// Validator-set root.
    pub set_root: [u8; 32],
    certificate: PrevoteCertificate,
}

impl ProofOfLock {
    /// Build a proof from an already verified prevote certificate.
    ///
    /// There is no other constructor: the support figure in a proof is always the
    /// recomputed one, never a declared one.
    pub fn from_prevote(certificate: PrevoteCertificate) -> Self {
        Self {
            round: certificate.round(),
            checkpoint_id: certificate.checkpoint_id(),
            height: certificate.height(),
            generation: certificate.generation(),
            set_root: certificate.set_root(),
            certificate,
        }
    }

    /// The prevote certificate backing this proof.
    pub fn certificate(&self) -> &PrevoteCertificate {
        &self.certificate
    }

    /// Recomputed support weight.
    pub fn support(&self) -> ValidatorWeight {
        self.certificate.support()
    }

    /// Recomputed total admissible weight.
    pub fn total(&self) -> ValidatorWeight {
        self.certificate.total()
    }

    /// Is this proof about the same position as `ctx`?
    pub fn is_valid_for(&self, ctx: &BftContext) -> bool {
        self.generation == ctx.generation
            && self.height == ctx.height
            && self.set_root == ctx.validator_set_root
            && self.certificate.qc().phase == VotePhase::Prevote
    }

    /// Does this proof show `value` prevoted at `round` or later for this height?
    pub fn covers_value(&self, value: &[u8; 32], round: Round) -> bool {
        self.checkpoint_id == *value && self.round.get() >= round.get()
    }

    /// The single decision point of `AW-LOCK-1`.
    ///
    /// A proof authorizes a prevote for `value` in `ctx` when it belongs to the
    /// same position, certifies that value, and satisfies
    /// `lock_round <= self.round < ctx.round`. The upper bound is strict on
    /// purpose; the lower bound is inclusive on purpose.
    pub fn accepted_for(&self, value: &[u8; 32], ctx: &BftContext, lock_round: Round) -> bool {
        // The round that counts is the one **inside the certificate**, never the
        // public field: a field can be rewritten, a signed round cannot.
        let certified_round = self.certificate.round();
        self.round == certified_round
            && self.certificate.qc().network == ctx.network
            && self.is_valid_for(ctx)
            && self.checkpoint_id == *value
            && certified_round.get() >= lock_round.get()
            && certified_round.get() < ctx.round.get()
    }
}
