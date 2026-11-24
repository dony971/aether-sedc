//! Authorisation to emit exactly one BFT signature (mission BU).
//!
//! # Why this type exists
//!
//! Mission BT showed (`bt_15`) that the storage primitive alone signed a
//! prevote contradicting the lock at a higher round, because
//! [`PersistentConsensusState::signing_check`] only refuses a contradiction at
//! `round <= lockR`. The rule `A4'` lived one layer above, in
//! `BftState::check_prevote_admissible`, so the rule depended on the caller
//! calling the right function first. A comment cannot enforce that; a type can.
//!
//! [`VoteAuthorization`] is that type. It has **no public field and no
//! `Default`/`Deserialize`**, and it can only be produced by one of two
//! constructors, both of which re-run the whole rule against a real
//! [`PersistentConsensusState`] and a real registry:
//!
//! | Constructor | Rule enforced |
//! |---|---|
//! | [`VoteAuthorization::for_prevote`] | `AW-LOCK-1` / `A4'`: Nil (always), no lock, the locked value, or a **re-verified** POL with `lockR <= rho < round` |
//! | [`VoteAuthorization::for_precommit`] | `AW-LOCK-8` / `N-PC-1`: a re-verified prevote certificate in this exact position, and this node's own prevote of that value in that round |
//!
//! Both start with [`PersistentConsensusState::signing_check`], so recovery,
//! network and generation are checked first, exactly as before.
//!
//! # What the authorisation binds
//!
//! `(network, generation, height, round, phase, checkpoint_id)` and the lock
//! state that justified it — the locked value and round, plus the identifier of
//! the POL when a value change was authorised. [`Self::covers`] compares all six
//! vote fields, so an authorisation can never be used for another position or
//! another value.
//!
//! # Reuse
//!
//! The type is `Copy`: reusing it to sign the **same** vote twice is safe and
//! idempotent (`Settlement::AlreadySigned`). Reusing it for anything else is
//! refused by [`Self::covers`], and two contradictory votes at one slot are
//! still separated by the store's compare-and-swap. Reuse therefore cannot
//! produce equivocation, and it cannot change parameters.
//!
//! # What this does not do
//!
//! It does not replace the engine's checks: the engine still runs them, and
//! `sign_vote` still runs `signing_check`. The authorisation is a third,
//! independent gate that no caller can skip.

use crate::consensus::generation::{CheckpointHeight, GenerationId, Round};
use crate::l2bft::cert::{PrevoteCertificate, ProofOfLock};
use crate::l2bft::context::BftContext;
use crate::l2bft::NIL_VALUE;
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::{ConsensusVote, VotePhase};
use crate::l2persist::state::{EmitError, PersistentConsensusState};

/// Proof that one exact signature has been authorised at one exact position.
///
/// Deliberately opaque: every field is private and there is no way to build one
/// except through the two validating constructors below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteAuthorization {
    network: u64,
    generation: GenerationId,
    height: CheckpointHeight,
    round: Round,
    phase: VotePhase,
    checkpoint_id: [u8; 32],
    lock_value: [u8; 32],
    lock_round: Option<Round>,
    pol_qc_id: Option<[u8; 32]>,
}

fn bind(
    vote: &ConsensusVote,
    lock_value: [u8; 32],
    lock_round: Option<Round>,
    pol_qc_id: Option<[u8; 32]>,
) -> VoteAuthorization {
    VoteAuthorization {
        network: vote.network,
        generation: vote.generation,
        height: vote.height,
        round: vote.round,
        phase: vote.phase,
        checkpoint_id: vote.checkpoint_id,
        lock_value,
        lock_round,
        pol_qc_id,
    }
}

fn not_authorized(reason: impl Into<String>) -> EmitError {
    EmitError::NotAuthorized(reason.into())
}

impl VoteAuthorization {
    /// Authorise a **prevote** under `A4'`.
    ///
    /// `state` is the engine's safety state; `proof` is the POL the caller
    /// intends to rely on, and it is re-verified here even if the caller
    /// already verified it.
    ///
    /// Same three branches, in the same order, as
    /// `BftState::check_prevote_admissible`: `Nil` is always admissible (an
    /// abstention never contradicts a lock), the locked value is admissible, and
    /// any other value needs a proof with `lockR <= rho < round`. The `Nil`
    /// branch is not an exception added here — it is `A4'` itself, and dropping
    /// it would change the consensus semantics by forbidding abstention.
    pub fn for_prevote(
        state: &PersistentConsensusState,
        vote: &ConsensusVote,
        proof: Option<&ProofOfLock>,
        registry: &ValidatorRegistry,
    ) -> Result<Self, EmitError> {
        if vote.phase != VotePhase::Prevote {
            return Err(not_authorized(
                "a prevote authorisation cannot sign a precommit",
            ));
        }
        state.signing_check(vote)?;
        let lock = state.locked.filter(|lock| lock.height == vote.height);
        if vote.checkpoint_id == NIL_VALUE {
            // `A4'` branch 1: abstention is always admissible.
            return Ok(bind(
                vote,
                lock.map_or([0u8; 32], |lock| lock.checkpoint_id),
                lock.map(|lock| lock.round),
                None,
            ));
        }
        let Some(lock) = lock else {
            return Ok(bind(vote, [0u8; 32], None, None));
        };
        if lock.checkpoint_id == vote.checkpoint_id {
            return Ok(bind(vote, lock.checkpoint_id, Some(lock.round), None));
        }
        let proof = proof.ok_or_else(|| {
            not_authorized(format!(
                "locked on {} at round {}: a proof of lock is required to sign {}",
                hex::encode(lock.checkpoint_id),
                lock.round.get(),
                hex::encode(vote.checkpoint_id)
            ))
        })?;
        // The POL must still verify from its own bytes against this registry.
        proof
            .certificate()
            .re_verify(registry, vote.network)
            .map_err(|e| not_authorized(format!("proof of lock does not re-verify: {e}")))?;
        let ctx = BftContext::new(
            vote.network,
            vote.generation,
            vote.height,
            vote.round,
            VotePhase::Prevote,
            proof.set_root,
        );
        if !proof.accepted_for(&vote.checkpoint_id, &ctx, lock.round) {
            return Err(not_authorized(format!(
                "proof of lock does not justify {} in round {} for lock round {}",
                hex::encode(vote.checkpoint_id),
                vote.round.get(),
                lock.round.get()
            )));
        }
        Ok(bind(
            vote,
            lock.checkpoint_id,
            Some(lock.round),
            Some(proof.certificate().id()),
        ))
    }

    /// Authorise a **precommit** under `AW-LOCK-8` / `N-PC-1`.
    ///
    /// Requires a prevote certificate for exactly this `(network, generation,
    /// height, round, value, set root)` that still verifies, **and** this
    /// node's own prevote of the same value in the same round. `state` is the
    /// engine's safety state *after* the lock update, which is the order the
    /// engine uses (`AW-LOCK-2`: the lock is durable before the signature).
    pub fn for_precommit(
        state: &PersistentConsensusState,
        vote: &ConsensusVote,
        certificate: &PrevoteCertificateLike,
        own_prevote: &ConsensusVote,
        registry: &ValidatorRegistry,
    ) -> Result<Self, EmitError> {
        if vote.phase != VotePhase::Precommit {
            return Err(not_authorized(
                "a precommit authorisation cannot sign a prevote",
            ));
        }
        state.signing_check(vote)?;
        if certificate.checkpoint_id() != vote.checkpoint_id {
            return Err(not_authorized(
                "the prevote certificate names another value than the precommit",
            ));
        }
        if certificate.height() != vote.height
            || certificate.round() != vote.round
            || certificate.generation() != vote.generation
        {
            return Err(not_authorized(
                "the prevote certificate sits in another position",
            ));
        }
        certificate
            .re_verify(registry, vote.network)
            .map_err(|e| not_authorized(format!("prevote certificate does not re-verify: {e}")))?;
        if own_prevote.phase != VotePhase::Prevote
            || own_prevote.validator != vote.validator
            || own_prevote.height != vote.height
            || own_prevote.round != vote.round
            || own_prevote.checkpoint_id != vote.checkpoint_id
        {
            return Err(not_authorized(
                "no own prevote of this value in this round (A3-ord)",
            ));
        }
        own_prevote
            .verify(registry, vote.network)
            .map_err(|e| not_authorized(format!("own prevote does not verify: {e}")))?;
        let lock = state.locked.filter(|lock| lock.height == vote.height);
        Ok(bind(
            vote,
            lock.map_or([0u8; 32], |lock| lock.checkpoint_id),
            lock.map(|lock| lock.round),
            None,
        ))
    }

    /// Whether this authorisation was issued for exactly `vote`.
    ///
    /// All six signed fields are compared; a mismatch is
    /// [`EmitError::NotAuthorized`] at the signing site.
    pub fn covers(&self, vote: &ConsensusVote) -> bool {
        self.network == vote.network
            && self.generation == vote.generation
            && self.height == vote.height
            && self.round == vote.round
            && self.phase == vote.phase
            && self.checkpoint_id == vote.checkpoint_id
    }

    /// Network the authorisation belongs to.
    pub fn network(&self) -> u64 {
        self.network
    }

    /// Generation the authorisation belongs to.
    pub fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Height the authorisation belongs to.
    pub fn height(&self) -> CheckpointHeight {
        self.height
    }

    /// Round the authorisation belongs to.
    pub fn round(&self) -> Round {
        self.round
    }

    /// Phase the authorisation belongs to.
    pub fn phase(&self) -> VotePhase {
        self.phase
    }

    /// Value the authorisation belongs to.
    pub fn checkpoint_id(&self) -> [u8; 32] {
        self.checkpoint_id
    }

    /// Value that was locked when the authorisation was issued (`[0; 32]` if none).
    pub fn lock_value(&self) -> [u8; 32] {
        self.lock_value
    }

    /// Round of the lock that was in force, if any.
    pub fn lock_round(&self) -> Option<Round> {
        self.lock_round
    }

    /// Identifier of the POL that justified a value change, if any.
    pub fn pol_qc_id(&self) -> Option<[u8; 32]> {
        self.pol_qc_id
    }
}

/// Alias that keeps the constructor readable without exporting a second type.
///
/// A precommit is justified by a **prevote** certificate, which is why the
/// parameter is a [`PrevoteCertificate`]: `N-PC-1` requires the certificate of
/// the prevote phase for the same value and round.
pub type PrevoteCertificateLike = PrevoteCertificate;
