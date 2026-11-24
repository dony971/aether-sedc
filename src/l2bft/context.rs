//! BFT voting context, prevotes and precommits.
//!
//! # Every object engages its position
//!
//! A vote is only meaningful inside one position: `(network, generation, height,
//! round, phase, checkpoint, validator-set root)`. [`BftContext`] is that
//! position, and [`Prevote`] / [`Precommit`] **cannot be constructed** without
//! matching it.
//!
//! # The set root: engaged by verification, not by the signature
//!
//! AT's `ConsensusVote` signs `(version, network, generation, height, round,
//! phase, checkpoint, validator)` — it does **not** sign a validator-set root.
//! Rather than fork the AT encoding (which would break AU's `sign_vote` ordering
//! guarantee), the set root is bound **by verification**:
//!
//! 1. the wrapper carries the expected root;
//! 2. every acceptance path requires `wrapper.set_root == registry.set_root()`
//!    (`BftError::ContextMismatch { field: "set_root" }`).
//!
//! This is **equivalent to signing it** for one reason, and only because of that
//! reason: `N-GEN-1` fixes the member set inside a generation, so the set root is
//! constant for a given generation, and the generation **is** signed. Relabeling
//! a vote to another set root inside the same generation therefore cannot change
//! anything the vote authorizes; across generations it is rejected by the
//! generation check. Remove `N-GEN-1` and this equivalence disappears — that is
//! stated here rather than assumed silently.

use thiserror::Error;

use crate::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use crate::l2crypto::frame::frame_hash;
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::{ConsensusVote, VotePhase, VoteVerifyError};
use crate::l2persist::slotlock::SlotStoreError;
use crate::l2persist::state::StateError;
use crate::l2persist::EmitError;

/// Domain tag for a context identifier.
pub const DOMAIN_BFT_CONTEXT: &[u8] = b"AETHER-L2-BFTCTX-v1";

/// Failures of the BFT engine.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BftError {
    /// An object does not belong to the position it is used in.
    #[error("context mismatch on {field}")]
    ContextMismatch {
        /// Which field disagreed: `network`, `generation`, `height`, `round`,
        /// `phase`, `set_root`, `value`.
        field: &'static str,
    },

    /// Cryptographic or registry rejection, with the underlying reason.
    #[error("rejected: {0}")]
    Rejected(String),

    /// Certificate support below the AQ/AR threshold.
    #[error("not quorate: support {support} < quorum {quorum} of {total}")]
    NotQuorate {
        /// Recomputed support weight.
        support: u64,
        /// Required threshold.
        quorum: u64,
        /// Recomputed total weight.
        total: u64,
    },

    /// A different value was requested while a lock is held.
    #[error("lock retained: committed to {locked}, asked for {requested}")]
    LockRetained {
        /// Locked checkpoint, hex.
        locked: String,
        /// Requested checkpoint, hex.
        requested: String,
    },

    /// A prevote is not justified by the lock, the value, or a proof of lock.
    ///
    /// This is `AW-LOCK-1` (`A4'`): a prevote for another value is allowed only
    /// with a verified `POL` whose round sits in `[lockR, r)`. Without one, the
    /// engine signs `Nil`, never the value and never an error that would prevent
    /// abstention.
    #[error("prevote not justified: value {value}, lock {locked} at round {lock_round}")]
    PrevoteNotJustified {
        /// Requested value, hex.
        value: String,
        /// Locked checkpoint, hex.
        locked: String,
        /// Round the lock was written at.
        lock_round: u32,
    },

    /// `A3-ord`: a precommit must follow this node's own prevote of the same
    /// value in the same round.
    #[error("precommit refused: no own prevote of this value in this round")]
    PrevoteRequired,

    /// Mission BI: this validator is not the elected proposer for the round.
    ///
    /// A progress refusal, never a safety one: the proposer rule decides who may
    /// open a round, and a node that is not elected simply waits (or times out).
    #[error("not the proposer of round {round}: the schedule elects {elected}")]
    NotProposer {
        /// Round being opened.
        round: u32,
        /// Identity the schedule elects, hex.
        elected: String,
    },

    /// Two verifiable proofs of lock at one round for different values.
    ///
    /// Impossible under `A0`, `A1`, `A2` and `A8a` (`AW-LOCK-10`); observing it is
    /// a hypothesis violation, so the engine halts instead of choosing.
    #[error("conflicting proofs of lock at round {round}: {first} vs {second}")]
    ConflictingProof {
        /// Round both proofs claim.
        round: u32,
        /// Value of the first proof, hex.
        first: String,
        /// Value of the second proof, hex.
        second: String,
    },

    /// A proof of lock does not justify the value or position it is attached to.
    #[error("proof of lock rejected: {0}")]
    InvalidProof(&'static str),

    /// Signing blocked because the restored state is uncertain.
    #[error("signing blocked: {0}")]
    RecoveryRequired(String),

    /// The generation that would sign or decide is not in force at this height
    /// (`R-TRANS-4`, `R-TRANS-7`; mission BC).
    #[error("generation closed: {0}")]
    GenerationClosed(String),

    /// A decided transition has not been installed yet (`N-TRN-7`; mission BM
    /// `N-6`). Signing or deciding above the closing height is refused until the
    /// new generation is installed.
    #[error("installation required before height {height}")]
    InstallationRequired {
        /// Height whose signature or decision was refused.
        height: u64,
    },

    /// A decision was attempted at a height after the next one.
    #[error("height not sequential: last decided {last}, requested {requested}")]
    HeightNotSequential {
        /// Last height decided.
        last: u64,
        /// Height requested.
        requested: u64,
    },

    /// The engine halted after a safety violation.
    #[error("engine halted: {0}")]
    Halted(String),

    /// A required input was not supplied.
    #[error("missing dependency: {0}")]
    MissingDependency(&'static str),

    /// Two different checkpoints were certified at the same height.
    #[error("conflicting finality: {first} vs {second}")]
    ConflictingFinality {
        /// First decision, hex.
        first: String,
        /// Second decision, hex.
        second: String,
    },

    /// The height is already final; re-deciding it with another value is refused.
    #[error("already final: {0:?}")]
    AlreadyFinal([u8; 32]),

    /// The checkpoint record itself is invalid, independently of any certificate.
    #[error("checkpoint invalid: {0}")]
    CheckpointInvalid(String),

    /// The parent of the checkpoint is not final (or absent).
    #[error("parent not finalised: {0}")]
    ParentNotFinalized(String),

    /// Round-change evidence is below the adoption threshold.
    #[error("insufficient round-change weight: {support} < {quorum}")]
    InsufficientRoundChange {
        /// Collected weight.
        support: u64,
        /// Required weight.
        quorum: u64,
    },

    /// Slot store failure.
    #[error("slot store error: {0}")]
    Store(String),

    /// Signature refusal from the persistence layer.
    #[error("emit error: {0}")]
    Emit(String),
}

impl From<SlotStoreError> for BftError {
    fn from(e: SlotStoreError) -> Self {
        BftError::Store(e.to_string())
    }
}

impl From<StateError> for BftError {
    fn from(e: StateError) -> Self {
        BftError::Store(e.to_string())
    }
}

impl From<EmitError> for BftError {
    fn from(e: EmitError) -> Self {
        BftError::Emit(e.to_string())
    }
}

impl From<VoteVerifyError> for BftError {
    fn from(e: VoteVerifyError) -> Self {
        BftError::Rejected(e.to_string())
    }
}

/// The position a BFT object lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BftContext {
    /// Network discriminant.
    pub network: u64,
    /// Generation.
    pub generation: GenerationId,
    /// Height.
    pub height: CheckpointHeight,
    /// Round.
    pub round: Round,
    /// Phase.
    pub phase: VotePhase,
    /// Validator-set root of the generation.
    pub validator_set_root: [u8; 32],
}

impl BftContext {
    /// Build a context.
    pub fn new(
        network: u64,
        generation: GenerationId,
        height: CheckpointHeight,
        round: Round,
        phase: VotePhase,
        validator_set_root: [u8; 32],
    ) -> Self {
        Self {
            network,
            generation,
            height,
            round,
            phase,
            validator_set_root,
        }
    }

    /// Context of an AT vote, taking the set root from the registry.
    pub fn of_vote(vote: &ConsensusVote, validator_set_root: [u8; 32]) -> Self {
        Self {
            network: vote.network,
            generation: vote.generation,
            height: vote.height,
            round: vote.round,
            phase: vote.phase,
            validator_set_root,
        }
    }

    /// Same position except the phase.
    pub fn with_phase(&self, phase: VotePhase) -> Self {
        Self { phase, ..*self }
    }

    /// Same position except the round.
    pub fn with_round(&self, round: Round) -> Self {
        Self { round, ..*self }
    }

    /// Canonical encoding: `version(1) ‖ network(8) ‖ gen(32) ‖ height(8) ‖ round(4) ‖ phase(1) ‖ set_root(32)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(86);
        out.push(1u8);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.round.get().to_le_bytes());
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.validator_set_root);
        out
    }

    /// Content address of the position.
    pub fn id(&self) -> [u8; 32] {
        frame_hash(DOMAIN_BFT_CONTEXT, &[&self.encode()[..]])
    }

    /// Check the non-round, non-phase fields against a registry.
    pub fn check_registry(&self, registry: &ValidatorRegistry) -> Result<(), BftError> {
        if registry.generation() != self.generation {
            return Err(BftError::ContextMismatch {
                field: "generation",
            });
        }
        if registry.set_root() != self.validator_set_root {
            return Err(BftError::ContextMismatch { field: "set_root" });
        }
        Ok(())
    }

    /// Compare two contexts field by field, reporting the first difference.
    pub fn require_same_position(&self, other: &Self) -> Result<(), BftError> {
        if self.network != other.network {
            return Err(BftError::ContextMismatch { field: "network" });
        }
        if self.generation != other.generation {
            return Err(BftError::ContextMismatch {
                field: "generation",
            });
        }
        if self.height != other.height {
            return Err(BftError::ContextMismatch { field: "height" });
        }
        if self.round != other.round {
            return Err(BftError::ContextMismatch { field: "round" });
        }
        if self.phase != other.phase {
            return Err(BftError::ContextMismatch { field: "phase" });
        }
        if self.validator_set_root != other.validator_set_root {
            return Err(BftError::ContextMismatch { field: "set_root" });
        }
        Ok(())
    }
}

/// Shared body of a phase vote.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PhaseVote {
    vote: ConsensusVote,
    validator_set_root: [u8; 32],
}

impl PhaseVote {
    fn build(vote: ConsensusVote, set_root: [u8; 32], phase: VotePhase) -> Result<Self, BftError> {
        if vote.phase != phase {
            return Err(BftError::ContextMismatch { field: "phase" });
        }
        Ok(Self {
            vote,
            validator_set_root: set_root,
        })
    }

    fn context(&self) -> BftContext {
        BftContext::of_vote(&self.vote, self.validator_set_root)
    }

    fn verify(
        &self,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<ValidatorWeight, BftError> {
        let ctx = self.context();
        if ctx.network != network {
            return Err(BftError::ContextMismatch { field: "network" });
        }
        ctx.check_registry(registry)?;
        // AT verifies version, network, generation, membership, admissibility and
        // the signature over the domain-framed message. The weight comes from the
        // registry, never from the vote.
        Ok(self.vote.verify(registry, network)?.weight)
    }
}

/// A prevote: phase `Prevote`, bound to one context and one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prevote {
    inner: PhaseVote,
}

impl Prevote {
    /// Wrap an AT vote that is in the prevote phase.
    pub fn new(vote: ConsensusVote, validator_set_root: [u8; 32]) -> Result<Self, BftError> {
        Ok(Self {
            inner: PhaseVote::build(vote, validator_set_root, VotePhase::Prevote)?,
        })
    }

    /// The underlying AT vote.
    pub fn vote(&self) -> &ConsensusVote {
        &self.inner.vote
    }

    /// Position of this prevote.
    pub fn context(&self) -> BftContext {
        self.inner.context()
    }

    /// Certified value.
    pub fn checkpoint_id(&self) -> [u8; 32] {
        self.inner.vote.checkpoint_id
    }

    /// Signer.
    pub fn validator(&self) -> ValidatorId {
        self.inner.vote.validator
    }

    /// Verify against the registry; returns the **registry** weight.
    pub fn verify(
        &self,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<ValidatorWeight, BftError> {
        self.inner.verify(registry, network)
    }
}

/// A precommit: phase `Precommit`, bound to one context and one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Precommit {
    inner: PhaseVote,
}

impl Precommit {
    /// Wrap an AT vote that is in the precommit phase.
    pub fn new(vote: ConsensusVote, validator_set_root: [u8; 32]) -> Result<Self, BftError> {
        Ok(Self {
            inner: PhaseVote::build(vote, validator_set_root, VotePhase::Precommit)?,
        })
    }

    /// The underlying AT vote.
    pub fn vote(&self) -> &ConsensusVote {
        &self.inner.vote
    }

    /// Position of this precommit.
    pub fn context(&self) -> BftContext {
        self.inner.context()
    }

    /// Certified value.
    pub fn checkpoint_id(&self) -> [u8; 32] {
        self.inner.vote.checkpoint_id
    }

    /// Signer.
    pub fn validator(&self) -> ValidatorId {
        self.inner.vote.validator
    }

    /// Verify against the registry; returns the **registry** weight.
    pub fn verify(
        &self,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<ValidatorWeight, BftError> {
        self.inner.verify(registry, network)
    }
}

/// Result of offering a vote to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    /// Accepted and recorded for the current round.
    Accepted {
        /// Signer.
        validator: ValidatorId,
        /// Weight from the registry.
        weight: ValidatorWeight,
    },
    /// Already known for this round; nothing changed.
    Duplicate {
        /// Signer.
        validator: ValidatorId,
    },
    /// Well formed and signed, but for another position.
    ForeignContext {
        /// Which field disagreed.
        field: &'static str,
        /// Round the vote belongs to.
        round: Round,
    },
    /// Rejected outright.
    Rejected {
        /// Reason.
        reason: String,
    },
}
