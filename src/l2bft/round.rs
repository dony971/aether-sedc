//! Round changes.
//!
//! # What a round change is, and is not
//!
//! A round change is an authenticated statement: *"validator `v` wants to leave
//! round `r` for this height, and this is the lock it was holding"*. It exists to
//! carry lock **evidence** across rounds, never to relax it.
//!
//! Two things are deliberately separated:
//!
//! | Question | Where it is answered | Status |
//! |---|---|---|
//! | Is this message authentic and for the right position? | [`RoundChange::verify`] | **proved** by AT primitives |
//! | Should the engine move to a new round? | [`RoundChangeEvidence::is_sufficient`] | **provisional policy**, not a safety rule |
//!
//! Moving to a new round is a *progress* decision. No AQ/AR rule specifies its
//! threshold, so the engine uses the same quorum predicate as everything else
//! (`quorum_met`) and marks the choice provisional. Getting it wrong costs
//! liveness; it cannot cost safety, because a round change **never** touches a
//! lock and never authorizes a value.
//!
//! # What it explicitly does not do
//!
//! - it does not unlock: a validator that changes round keeps its lock exactly as
//!   it was, proof included (`AW-LOCK-6`, `R-LOCK-2`);
//! - it does not authorize a new value by itself: a proof of lock is checked by
//!   the engine (`AW-LOCK-1`), never here;
//! - it does not prove liveness. Nothing here claims that rounds make progress.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::consensus::generation::{
    quorum_met, quorum_threshold, CheckpointHeight, GenerationId, Round, ValidatorId,
    ValidatorWeight,
};
use crate::l2bft::context::BftError;
use crate::l2crypto::frame::{frame, frame_hash, le32, le64};
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2persist::state::LockedValue;

/// Version of the round-change encoding.
pub const ROUND_CHANGE_VERSION: u8 = 1;

/// Domain tag for a round-change signature.
pub const DOMAIN_ROUND_CHANGE: &[u8] = b"AETHER-L2-ROUNDCHANGE-v1";

/// Domain tag for a round-change identifier.
pub const DOMAIN_ROUND_CHANGE_ID: &[u8] = b"AETHER-L2-RCID-v1";

/// How far ahead of the current round a round change may target (mission BK, N-7).
///
/// A quorum could otherwise impose an arbitrary large round and burn the round
/// space in one step. This is a **progress** bound, not a safety rule: adopting a
/// far round cannot breach the lock, it only wastes rounds. It is relative to the
/// receiver's current round, so it belongs to the engine that receives the change;
/// `RoundChange::verify` can only reject the encoding-level absurdity
/// `target_round == u32::MAX`.
pub const MAX_ROUND_JUMP: u32 = 16;

fn locked_bytes(locked: &Option<LockedValue>) -> Vec<u8> {
    match locked {
        None => vec![0u8],
        Some(l) => {
            let mut out = Vec::with_capacity(45);
            out.push(1u8);
            out.extend_from_slice(&l.checkpoint_id);
            out.extend_from_slice(&le64(l.height.get()));
            out.extend_from_slice(&le32(l.round.get()));
            out
        }
    }
}

/// An authenticated request to move to `target_round`, carrying the sender's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundChange {
    /// Encoding version.
    pub version: u8,
    /// Network.
    pub network: u64,
    /// Generation.
    pub generation: GenerationId,
    /// Height.
    pub height: CheckpointHeight,
    /// Round the sender wants to leave.
    pub from_round: Round,
    /// Round the sender wants to enter.
    pub target_round: Round,
    /// Sender.
    pub validator: ValidatorId,
    /// Validator-set root.
    pub validator_set_root: [u8; 32],
    /// Lock the sender claims to hold. **Evidence only**: never trusted to move
    /// anyone else's lock, and never used to unlock.
    pub locked: Option<LockedValue>,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}

impl RoundChange {
    /// Build an unsigned round change.
    pub fn unsigned(
        network: u64,
        generation: GenerationId,
        height: CheckpointHeight,
        from_round: Round,
        target_round: Round,
        validator: ValidatorId,
        validator_set_root: [u8; 32],
        locked: Option<LockedValue>,
    ) -> Self {
        Self {
            version: ROUND_CHANGE_VERSION,
            network,
            generation,
            height,
            from_round,
            target_round,
            validator,
            validator_set_root,
            locked,
            signature: [0u8; 64],
        }
    }

    /// Bytes the sender signs.
    ///
    /// Domain-framed and length-prefixed like every other L2 message, so a round
    /// change cannot be replayed as a vote, a READY or a certificate.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let locked = locked_bytes(&self.locked);
        frame(
            DOMAIN_ROUND_CHANGE,
            &[
                &[self.version],
                &le64(self.network),
                &self.generation.0,
                &le64(self.height.get()),
                &le32(self.from_round.get()),
                &le32(self.target_round.get()),
                &self.validator.0,
                &self.validator_set_root,
                &locked,
            ],
        )
    }

    /// Sign with a private key, returning the complete message.
    pub fn sign_with(mut self, key: &ed25519_dalek::SigningKey) -> Self {
        self.signature = key.sign(&self.signing_bytes()).to_bytes();
        self
    }

    /// Content address.
    pub fn id(&self) -> [u8; 32] {
        frame_hash(
            DOMAIN_ROUND_CHANGE_ID,
            &[&self.signing_bytes()[..], &self.signature],
        )
    }

    /// Verify authenticity and position.
    ///
    /// Checks the version, the network, the generation, the set root against the
    /// registry, the sender's membership and admissibility, and the signature —
    /// over the domain-framed message, with the sender's **registry** key.
    pub fn verify(
        &self,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<ValidatorWeight, BftError> {
        if self.version != ROUND_CHANGE_VERSION {
            return Err(BftError::Rejected(format!(
                "unsupported round-change version {}",
                self.version
            )));
        }
        if self.network != network {
            return Err(BftError::ContextMismatch { field: "network" });
        }
        if self.generation != registry.generation() {
            return Err(BftError::ContextMismatch {
                field: "generation",
            });
        }
        if self.validator_set_root != registry.set_root() {
            return Err(BftError::ContextMismatch { field: "set_root" });
        }
        if self.target_round.get() <= self.from_round.get() {
            return Err(BftError::Rejected(
                "round change must advance the round".to_string(),
            ));
        }
        // N-7: `u32::MAX` has no successor and can never be entered; refuse it at
        // the encoding boundary instead of letting it reach round arithmetic.
        if self.target_round.get() == u32::MAX {
            return Err(BftError::Rejected(
                "round change targets the last representable round".to_string(),
            ));
        }
        if let Some(locked) = &self.locked {
            if locked.height != self.height {
                return Err(BftError::Rejected(
                    "round change carries a lock for another height".to_string(),
                ));
            }
        }
        let entry = registry.get(&self.validator).ok_or_else(|| {
            BftError::Rejected("round change from an unknown validator".to_string())
        })?;
        if !entry.admissibility.may_vote() {
            return Err(BftError::Rejected(
                "round change from an ineligible validator".to_string(),
            ));
        }
        let key = VerifyingKey::from_bytes(&entry.public_key)
            .map_err(|_| BftError::Rejected("invalid registry key".to_string()))?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify(&self.signing_bytes(), &signature)
            .map_err(|_| BftError::Rejected("bad round-change signature".to_string()))?;
        Ok(entry.weight)
    }
}

/// A set of round-change messages for one height and one target round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundChangeSet {
    /// Height.
    pub height: CheckpointHeight,
    /// Round the senders want to enter.
    pub target_round: Round,
    /// Messages, one per validator.
    pub changes: Vec<RoundChange>,
}

impl RoundChangeSet {
    /// Empty set.
    pub fn new(height: CheckpointHeight, target_round: Round) -> Self {
        Self {
            height,
            target_round,
            changes: Vec::new(),
        }
    }

    /// Add a message; refuses duplicates and messages for another position.
    pub fn push(&mut self, change: RoundChange) -> Result<(), BftError> {
        if change.height != self.height {
            return Err(BftError::ContextMismatch { field: "height" });
        }
        if change.target_round != self.target_round {
            return Err(BftError::ContextMismatch { field: "round" });
        }
        if self.changes.iter().any(|c| c.validator == change.validator) {
            return Err(BftError::Rejected(
                "duplicate validator in round-change set".to_string(),
            ));
        }
        self.changes.push(change);
        Ok(())
    }

    /// Verify every message and compute the available weight.
    ///
    /// A single invalid message rejects the whole set: a set that needs an invalid
    /// member to reach the threshold is not a valid set.
    pub fn verify(
        &self,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<RoundChangeEvidence, BftError> {
        let mut support: u64 = 0;
        let mut signers: Vec<ValidatorId> = Vec::new();
        let mut locked_values: Vec<(ValidatorId, [u8; 32])> = Vec::new();
        for change in &self.changes {
            let weight = change.verify(registry, network)?;
            if signers.contains(&change.validator) {
                return Err(BftError::Rejected(
                    "duplicate validator in round-change set".to_string(),
                ));
            }
            signers.push(change.validator);
            support = support.saturating_add(weight.get());
            if let Some(locked) = &change.locked {
                locked_values.push((change.validator, locked.checkpoint_id));
            }
        }
        let total = registry.total_voting_weight();
        Ok(RoundChangeEvidence {
            height: self.height,
            target_round: self.target_round,
            support: ValidatorWeight(support),
            total,
            quorum: quorum_threshold(total),
            signers,
            locked_values,
        })
    }
}

/// Verified round-change weight for one target round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundChangeEvidence {
    /// Height.
    pub height: CheckpointHeight,
    /// Target round.
    pub target_round: Round,
    /// Weight of the senders.
    pub support: ValidatorWeight,
    /// Total admissible weight.
    pub total: ValidatorWeight,
    /// Required threshold.
    pub quorum: ValidatorWeight,
    /// Distinct signers.
    pub signers: Vec<ValidatorId>,
    /// Locks claimed by the senders. **Evidence only** — nothing here may unlock
    /// anything.
    pub locked_values: Vec<(ValidatorId, [u8; 32])>,
}

impl RoundChangeEvidence {
    /// Whether the adoption policy's threshold is met.
    ///
    /// **Provisional policy**, not a safety rule: see the module note.
    pub fn is_sufficient(&self) -> bool {
        quorum_met(self.support, self.total)
    }

    /// Distinct lock values reported by the senders, when more than one.
    ///
    /// This is a *report*, not a resolution: the engine refuses to derive any
    /// safety conclusion from it.
    pub fn reported_lock_values(&self) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = Vec::new();
        for (_, value) in &self.locked_values {
            if !out.contains(value) {
                out.push(*value);
            }
        }
        out
    }
}

/// What the engine did with a round change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundChangeOutcome {
    /// Recorded, below the adoption threshold.
    Recorded {
        /// Weight collected so far.
        support: ValidatorWeight,
        /// Weight needed.
        quorum: ValidatorWeight,
    },
    /// Recorded **and** the round advanced.
    Adopted {
        /// Round left.
        from: Round,
        /// Round entered.
        to: Round,
        /// Evidence that justified it.
        evidence: Box<RoundChangeEvidence>,
    },
    /// Rejected, with the reason.
    Refused(String),
}
