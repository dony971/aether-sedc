//! Persistent consensus safety state: BFT locks, signing order, recovery.
//!
//! # The invariant this module exists to keep
//!
//! > A validator must never sign two different checkpoints at the same height and
//! > round. Ever, including across a crash.
//!
//! Two things are needed for that, and neither is optional:
//!
//! 1. **Order** — the slot reservation is flushed **before** the signature
//!    exists ([`sign_vote`] does this, and nothing else in this type does).
//! 2. **Refusal** — if recovery cannot establish what was signed before, the
//!    node must not sign at all ([`RecoveryStatus::RecoveryRequired`]).
//!
//! # The lock
//!
//! [`LockedValue`] records the checkpoint a validator is committed to at a
//! height. [`ProofOfLock`] stores the verified certificate that justified it,
//! with enough bytes to re-verify later. `last_valid_certificate` records the
//! newest certified position.
//!
//! A later-round certificate for another value is *recorded as evidence* but
//! does **not** unlock anything ([`PROVISIONAL_UNLOCK_RULE`]). Mission BU
//! **removed** `apply_provisional_unlock` and `apply_and_persist`: `AW-LOCK-5`
//! forbids unlocking, the engine never called them, and a public method that
//! moved a lock was a boundary with no legitimate caller. A state that carries
//! the historical `unlock_rule_provisional` flag is still decoded and still
//! refused by recovery, so old stores keep their meaning.
//!
//! # Signature authorisation (mission BU)
//!
//! [`sign_vote`] now requires a [`crate::l2persist::VoteAuthorization`]. The
//! primitive alone is no longer enough: the caller must hold a value that only
//! `A4'` (prevote) or `AW-LOCK-8` (precommit) can produce, re-verified against
//! this very state. The check remains below as defence in depth.
//!
//! # HALT at the signature frontier (mission BW)
//!
//! [`sign_vote`] refuses to produce a signature while a durable halt record
//! ([`HALT_KEY`]) exists. The engine's in-memory flag is not enough: an
//! authorisation obtained before a HALT — or before a restart — would otherwise
//! still reach the primitive. A corrupt halt record refuses too: its *presence*
//! is the fact that matters, not whether it decodes.
//!
//! # Recovery after a legitimate lock change (mission BW)
//!
//! `AW-LOCK-1` (`A4'`) lets a node prevote a different value **before** its lock
//! moves, and `AW-LOCK-2` moves the lock at the round of the precommit that
//! justifies it. A signed vote for another value at a **lower** round is
//! therefore legitimate history, not a contradiction; only a vote at or after
//! the lock round contradicts the lock. The recovery audit compares rounds as
//! well as values, and refuses a stored proof that cannot justify the stored
//! lock.
//!
//! # Missing data is not proof of absence
//!
//! An empty database is indistinguishable from a deleted one. [`restore`] takes
//! an optional **expected anchor** — a store identity written on first init. If
//! the caller expects an anchor and none is found, recovery returns
//! `RecoveryRequired(MissingAnchor)` rather than "no prior vote". Without that
//! argument, absence is only reported, never interpreted.
//!
//! # Out of scope
//!
//! Full finality, generation transitions, prevote/precommit protocol, slashing,
//! liveness. Locks are recorded; the protocol that uses them is not implemented.

use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, GenerationId, Round};
use crate::l2crypto::qc::QuorumCertificate;
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::{ConsensusVote, VotePhase};
use crate::l2persist::slotlock::{
    open_sealed, seal, AtomicSlotStore, CasStore, ReserveOutcome, SlotKey, SlotReservation,
    SlotState, SlotStoreError,
};

/// Version of the persisted consensus-state encoding.
pub const STATE_FORMAT_VERSION: u8 = 1;

/// Metadata key holding the single consensus-state record.
pub const STATE_KEY: &str = "l2/v2/consensus-state";

/// Metadata key holding the durable HALT record.
///
/// The canonical definition lives in this layer because [`sign_vote`] — the
/// signature frontier — must consult it. `l2bft` re-exports the same name and
/// value; the engine writes the record, and nothing ever removes it.
pub const HALT_KEY: &str = "l2/v3/bft/halt";

/// Description of the unlock rule, carried in every report.
///
/// A-06.6 does not prove a safe unlock rule, so this layer never applies one
/// implicitly.
pub const PROVISIONAL_UNLOCK_RULE: &str = "PROVISIONAL: a verified certificate for another value in a higher round is recorded as evidence but does not unlock the value; an explicit operator call is required (A-06.6 conclusion: unlock rule not proved)";

/// The checkpoint a validator is locked on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedValue {
    /// Checkpoint the validator is committed to.
    pub checkpoint_id: [u8; 32],
    /// Height of that checkpoint.
    pub height: CheckpointHeight,
    /// Round in which the commitment was made.
    pub round: Round,
}

/// Verified certificate that justified a lock (or a proposed unlock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOfLock {
    /// Round of the certificate.
    pub round: Round,
    /// Certificate identifier.
    pub qc_id: [u8; 32],
    /// Support weight reported by the verified certificate.
    pub support: u64,
    /// Total weight reported by the verified certificate.
    pub total: u64,
    /// Number of distinct signers.
    pub signers: u32,
    /// Value this certificate would justify.
    pub proposed: LockedValue,
    /// Full certificate encoding, kept for re-verification after restart.
    pub encoded_qc: Vec<u8>,
}

/// Newest certified position this validator has seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastValidCertificate {
    /// Height.
    pub height: CheckpointHeight,
    /// Round.
    pub round: Round,
    /// Phase.
    pub phase: VotePhase,
    /// Checkpoint certified.
    pub checkpoint_id: [u8; 32],
    /// Certificate identifier.
    pub qc_id: [u8; 32],
}

/// Whether the persisted state can be trusted to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Nothing known to be wrong.
    Clean,
    /// Safety cannot be established: **do not sign**.
    RecoveryRequired(RecoveryReason),
}

/// Why signing is blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    /// State record cannot be decoded or fails its digest.
    CorruptState(String),
    /// Caller expected an anchor and found none: cannot distinguish
    /// "never voted" from "vote history lost".
    MissingAnchor,
    /// Store belongs to another installation.
    ForeignAnchor {
        /// Anchor the caller expected.
        expected: [u8; 32],
        /// Anchor found in the record.
        found: [u8; 32],
    },
    /// A slot record is inconsistent with its own key or contents.
    IncoherentSlot(String),
    /// Locks and certificates disagree.
    ContradictoryLock(String),
    /// Fields that must agree do not.
    IncompleteState(String),
}

impl RecoveryStatus {
    /// Whether signing is permitted.
    pub fn may_sign(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// Persistent consensus safety state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentConsensusState {
    /// Network discriminant.
    pub network: u64,
    /// Generation in force.
    pub generation: GenerationId,
    /// Store identity written on first init.
    pub anchor: [u8; 32],
    /// Current lock, if any.
    pub locked: Option<LockedValue>,
    /// Evidence backing the lock, or a proposed unlock.
    pub proof_of_lock: Option<ProofOfLock>,
    /// Newest certified position observed.
    pub last_valid_certificate: Option<LastValidCertificate>,
    /// Highest round in which a vote was signed.
    pub highest_signed_round: Round,
    /// Set once a provisional unlock has been applied.
    pub unlock_rule_provisional: bool,
    /// Recovery verdict; `Clean` on a freshly built state.
    pub status: RecoveryStatus,
}

/// What observing a certificate did to the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockAction {
    /// No lock existed; this certificate established one.
    Locked {
        /// Round of the certificate.
        round: Round,
    },
    /// Certificate confirms the value already locked.
    Reaffirmed {
        /// Round of the certificate.
        round: Round,
    },
    /// A higher-round certificate names another value. Evidence recorded,
    /// nothing unlocked.
    UnlockRequiresOperator {
        /// Current lock.
        current: LockedValue,
        /// Value the certificate would justify.
        proposed: LockedValue,
    },
    /// Certificate is for an older round and a different value: rejected.
    Refused {
        /// Current lock.
        current: LockedValue,
        /// Round of the rejected certificate.
        conflicting_round: Round,
    },
}

/// Failures of the state layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    /// Storage failure.
    #[error("storage error: {0}")]
    Storage(String),

    /// Record cannot be decoded.
    #[error("corrupt consensus state: {0}")]
    Corrupt(String),

    /// Certificate failed verification.
    #[error("certificate rejected: {0}")]
    Certificate(String),

    /// Certificate belongs to another network.
    #[error("certificate for another network ({found} != {expected})")]
    NetworkMismatch {
        /// Expected network.
        expected: u64,
        /// Found network.
        found: u64,
    },

    /// Signing attempted while recovery is uncertain.
    #[error("signing blocked: {0}")]
    RecoveryRequired(String),

    /// Another writer changed the state between read and swap.
    #[error("state changed concurrently; refusing to overwrite")]
    ConcurrentWriter,

    /// No such proof of lock.
    #[error("no proof of lock matching the given certificate")]
    UnknownProof,
}

impl From<SlotStoreError> for StateError {
    fn from(e: SlotStoreError) -> Self {
        StateError::Storage(e.to_string())
    }
}

/// Failures when emitting a signature.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EmitError {
    /// Input vote already carries a signature.
    #[error("vote already carries a signature")]
    NotUnsigned,

    /// Signing blocked by a durable HALT record.
    #[error("signing blocked: node is halted ({0})")]
    Halted(String),

    /// Signing blocked by recovery.
    #[error("signing blocked: {0}")]
    RecoveryRequired(String),

    /// No valid BFT authorisation for this signature.
    #[error("signature not authorised: {0}")]
    NotAuthorized(String),

    /// Vote for another network.
    #[error("vote for another network ({found} != {expected})")]
    NetworkMismatch {
        /// Expected network.
        expected: u64,
        /// Found network.
        found: u64,
    },

    /// Vote for another generation.
    #[error("vote generation does not match the persisted generation")]
    GenerationMismatch,

    /// Vote contradicts the current lock.
    #[error("locked value conflict: committed to {locked:?}, asked to sign {requested:?}")]
    LockedValueConflict {
        /// Checkpoint currently locked.
        locked: [u8; 32],
        /// Checkpoint the caller wants to sign.
        requested: [u8; 32],
    },

    /// Slot already holds another checkpoint.
    #[error("equivocation refused: slot already reserved for another checkpoint")]
    Equivocation {
        /// Checkpoint already recorded.
        existing_checkpoint: [u8; 32],
    },

    /// Store failure.
    #[error("slot store error: {0}")]
    Store(#[from] SlotStoreError),

    /// The produced signature does not verify.
    #[error("produced signature does not verify: {0}")]
    InvalidSignature(String),

    /// Signature produced but the record failed: **do not broadcast**.
    #[error("signed but not recorded, do not broadcast: {0}")]
    SignedButNotRecorded(String),

    /// Record written but flush failed: **do not broadcast**.
    #[error("durability uncertain after signing, do not broadcast: {0}")]
    DurabilityUncertain(String),

    /// Signature produced and recorded, but a HALT was observed before this
    /// call could release it: **do not broadcast** (BX, R-BX-1).
    #[error("signed and recorded, but the node halted before the vote was released (do not broadcast): {0}")]
    SignedButHalted(String),
}

/// Whether the returned vote was signed now or already existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// This call produced the signature.
    FreshlySigned,
    /// The slot already held the identical signed vote; nothing was re-signed.
    AlreadySigned,
}

/// Result of a successful [`sign_vote`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedOutcome {
    /// The signed vote.
    pub vote: ConsensusVote,
    /// Slot record after the call.
    pub reservation: SlotReservation,
    /// Whether this call signed.
    pub settlement: Settlement,
    /// Whether a flush happened after the reservation and before signing.
    pub flushed_before_signing: bool,
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StateError> {
        if self.bytes.len() < self.pos + n {
            return Err(StateError::Corrupt(format!(
                "truncated at {}: need {} more bytes",
                self.pos, n
            )));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, StateError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, StateError> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, StateError> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn arr32(&mut self) -> Result<[u8; 32], StateError> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn done(&self) -> Result<(), StateError> {
        if self.pos != self.bytes.len() {
            return Err(StateError::Corrupt(format!(
                "{} trailing bytes",
                self.bytes.len() - self.pos
            )));
        }
        Ok(())
    }
}

const FLAG_LOCKED: u8 = 1 << 0;
const FLAG_PROOF: u8 = 1 << 1;
const FLAG_LAST_CERT: u8 = 1 << 2;
const FLAG_PROVISIONAL: u8 = 1 << 3;

impl PersistentConsensusState {
    /// A fresh, clean state with a new anchor.
    pub fn fresh(network: u64, generation: GenerationId, anchor: [u8; 32]) -> Self {
        Self {
            network,
            generation,
            anchor,
            locked: None,
            proof_of_lock: None,
            last_valid_certificate: None,
            highest_signed_round: Round(0),
            unlock_rule_provisional: false,
            status: RecoveryStatus::Clean,
        }
    }

    /// Canonical encoding of the state.
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = 0u8;
        if self.locked.is_some() {
            flags |= FLAG_LOCKED;
        }
        if self.proof_of_lock.is_some() {
            flags |= FLAG_PROOF;
        }
        if self.last_valid_certificate.is_some() {
            flags |= FLAG_LAST_CERT;
        }
        if self.unlock_rule_provisional {
            flags |= FLAG_PROVISIONAL;
        }
        let mut out = Vec::with_capacity(256);
        out.push(STATE_FORMAT_VERSION);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.anchor);
        out.push(flags);
        if let Some(l) = &self.locked {
            out.extend_from_slice(&l.checkpoint_id);
            out.extend_from_slice(&l.height.get().to_le_bytes());
            out.extend_from_slice(&l.round.get().to_le_bytes());
        }
        if let Some(p) = &self.proof_of_lock {
            out.extend_from_slice(&p.round.get().to_le_bytes());
            out.extend_from_slice(&p.qc_id);
            out.extend_from_slice(&p.support.to_le_bytes());
            out.extend_from_slice(&p.total.to_le_bytes());
            out.extend_from_slice(&p.signers.to_le_bytes());
            out.extend_from_slice(&p.proposed.checkpoint_id);
            out.extend_from_slice(&p.proposed.height.get().to_le_bytes());
            out.extend_from_slice(&p.proposed.round.get().to_le_bytes());
            out.extend_from_slice(&(p.encoded_qc.len() as u32).to_le_bytes());
            out.extend_from_slice(&p.encoded_qc);
        }
        if let Some(c) = &self.last_valid_certificate {
            out.extend_from_slice(&c.height.get().to_le_bytes());
            out.extend_from_slice(&c.round.get().to_le_bytes());
            out.push(c.phase.as_u8());
            out.extend_from_slice(&c.checkpoint_id);
            out.extend_from_slice(&c.qc_id);
        }
        out.extend_from_slice(&self.highest_signed_round.get().to_le_bytes());
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != STATE_FORMAT_VERSION {
            return Err(StateError::Corrupt(format!(
                "unsupported state version {version}"
            )));
        }
        let network = r.u64()?;
        let generation = GenerationId(r.arr32()?);
        let anchor = r.arr32()?;
        let flags = r.u8()?;
        let locked = if flags & FLAG_LOCKED != 0 {
            Some(LockedValue {
                checkpoint_id: r.arr32()?,
                height: CheckpointHeight(r.u64()?),
                round: Round(r.u32()?),
            })
        } else {
            None
        };
        let proof_of_lock = if flags & FLAG_PROOF != 0 {
            let round = Round(r.u32()?);
            let qc_id = r.arr32()?;
            let support = r.u64()?;
            let total = r.u64()?;
            let signers = r.u32()?;
            let proposed = LockedValue {
                checkpoint_id: r.arr32()?,
                height: CheckpointHeight(r.u64()?),
                round: Round(r.u32()?),
            };
            let len = r.u32()? as usize;
            let encoded_qc = r.take(len)?.to_vec();
            Some(ProofOfLock {
                round,
                qc_id,
                support,
                total,
                signers,
                proposed,
                encoded_qc,
            })
        } else {
            None
        };
        let last_valid_certificate = if flags & FLAG_LAST_CERT != 0 {
            let height = CheckpointHeight(r.u64()?);
            let round = Round(r.u32()?);
            let phase_byte = r.u8()?;
            let phase = VotePhase::from_u8(phase_byte)
                .ok_or_else(|| StateError::Corrupt(format!("unknown phase {phase_byte}")))?;
            let checkpoint_id = r.arr32()?;
            let qc_id = r.arr32()?;
            Some(LastValidCertificate {
                height,
                round,
                phase,
                checkpoint_id,
                qc_id,
            })
        } else {
            None
        };
        let highest_signed_round = Round(r.u32()?);
        r.done()?;
        if flags & FLAG_PROVISIONAL != 0 && proof_of_lock.is_none() {
            return Err(StateError::Corrupt(
                "provisional unlock flag without a proof of lock".to_string(),
            ));
        }
        Ok(Self {
            network,
            generation,
            anchor,
            locked,
            proof_of_lock,
            last_valid_certificate,
            highest_signed_round,
            unlock_rule_provisional: flags & FLAG_PROVISIONAL != 0,
            status: RecoveryStatus::Clean,
        })
    }

    /// Read the persisted state, if any.
    pub fn load(store: &dyn CasStore) -> Result<Option<Self>, StateError> {
        match store.get(STATE_KEY)? {
            None => Ok(None),
            Some(bytes) => {
                let payload = open_sealed(&bytes)?;
                Ok(Some(Self::decode(payload)?))
            }
        }
    }

    /// Persist the state with a compare-and-swap, then flush.
    ///
    /// A concurrent writer is reported ([`StateError::ConcurrentWriter`]) rather
    /// than silently overwritten: two writers on one safety state is itself a
    /// condition that must not be papered over.
    pub fn persist(&self, store: &dyn CasStore) -> Result<(), StateError> {
        let current = store.get(STATE_KEY)?;
        // BX (R-BX-2): the byte CAS below only detects a write that lands
        // between **this** read and the swap. It cannot detect that `self` is a
        // snapshot older than the record it is about to replace: a serialised
        // stale writer reads the newer record, swaps itself over it, and the
        // swap succeeds. Nothing on disk orders two snapshots, so the record is
        // required to be a **superseding** one: no monotone safety field may
        // move backwards, and two values cannot occupy one lock round. A
        // refused write is reported, never repaired — the caller must reload.
        if let Some(bytes) = &current {
            let durable = Self::decode(open_sealed(bytes)?)?;
            if self.regresses(&durable).is_some() {
                return Err(StateError::ConcurrentWriter);
            }
        }
        let sealed = seal(&self.encode());
        if !store.cas(STATE_KEY, current.as_deref(), &sealed)? {
            return Err(StateError::ConcurrentWriter);
        }
        store.flush()?;
        Ok(())
    }

    /// Whether this snapshot would move a monotone safety field backwards
    /// (`R-BX-2`).
    ///
    /// Monotone by rule, never by convention: a lock is never removed
    /// (`AW-LOCK-5`/`AW-LOCK-11`), a lock round only advances at one height
    /// (`AW-LOCK-2`, `AW-LOCK-10`), the last valid certificate only advances
    /// (`AW-LOCK-6`), and a provisional unlock is sticky. `generation` is
    /// deliberately not compared:
    /// a generation change is persisted after the ledger write and is
    /// cross-checked against the ledger by `restore_engine`. `status` is not
    /// encoded. `highest_signed_round` is an audit summary re-derived from the
    /// slot records at restore, so it is not an ordering input here.
    fn regresses(&self, durable: &Self) -> Option<&'static str> {
        if self.network != durable.network {
            return Some("network");
        }
        if self.anchor != durable.anchor {
            return Some("anchor");
        }
        match (&durable.locked, &self.locked) {
            (Some(_), None) => return Some("lock removed"),
            (Some(old), Some(new)) => {
                if new.height < old.height {
                    return Some("lock height");
                }
                if new.height == old.height {
                    if new.round < old.round {
                        return Some("lock round");
                    }
                    if new.round == old.round && new.checkpoint_id != old.checkpoint_id {
                        return Some("contradictory lock at one round");
                    }
                }
            }
            (None, _) => {}
        }
        // A missing proof is deliberately **not** a regression: the lock is the
        // safety object, and a proof can be re-established from a certificate at
        // the same round (BX, `bx_15`). Refusing it would freeze a node that
        // restored with a proof it could not re-verify, because every later
        // write — including `advance_height` — carries the dropped proof.
        match (
            &durable.last_valid_certificate,
            &self.last_valid_certificate,
        ) {
            (Some(_), None) => return Some("last valid certificate removed"),
            (Some(old), Some(new)) => {
                if (new.height.get(), new.round.get()) < (old.height.get(), old.round.get()) {
                    return Some("last valid certificate");
                }
            }
            (None, _) => {}
        }
        if durable.unlock_rule_provisional && !self.unlock_rule_provisional {
            return Some("provisional unlock flag cleared");
        }
        None
    }

    /// Whether a vote may be signed, and why not if not.
    ///
    /// Refuses when recovery is uncertain, when the vote targets another network
    /// or generation, and when it contradicts the current lock at the same
    /// height.
    pub fn signing_check(&self, vote: &ConsensusVote) -> Result<(), EmitError> {
        if let RecoveryStatus::RecoveryRequired(reason) = &self.status {
            return Err(EmitError::RecoveryRequired(format!("{reason:?}")));
        }
        if vote.network != self.network {
            return Err(EmitError::NetworkMismatch {
                expected: self.network,
                found: vote.network,
            });
        }
        if vote.generation != self.generation {
            return Err(EmitError::GenerationMismatch);
        }
        if let Some(locked) = &self.locked {
            if locked.height == vote.height
                && locked.checkpoint_id != vote.checkpoint_id
                && vote.round.get() <= locked.round.get()
            {
                return Err(EmitError::LockedValueConflict {
                    locked: locked.checkpoint_id,
                    requested: vote.checkpoint_id,
                });
            }
        }
        Ok(())
    }

    /// Apply a verified certificate to the lock state.
    ///
    /// The certificate is verified against `registry` first: an unverified
    /// certificate cannot move a lock. Nothing is unlocked automatically; a
    /// higher-round certificate for another value only records the evidence.
    pub fn observe_certificate(
        &mut self,
        qc: &QuorumCertificate,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<LockAction, StateError> {
        if !self.status.may_sign() {
            return Err(StateError::RecoveryRequired(format!("{:?}", self.status)));
        }
        let verified = qc
            .verify(registry, network)
            .map_err(|e| StateError::Certificate(e.to_string()))?;
        if qc.network != self.network {
            return Err(StateError::NetworkMismatch {
                expected: self.network,
                found: qc.network,
            });
        }
        let candidate = LockedValue {
            checkpoint_id: qc.checkpoint_id,
            height: qc.height,
            round: qc.round,
        };
        let proof = ProofOfLock {
            round: qc.round,
            qc_id: qc.id(),
            support: verified.support.get(),
            total: verified.total.get(),
            signers: verified.signers.len() as u32,
            proposed: candidate,
            encoded_qc: qc.encode(),
        };
        let cert = LastValidCertificate {
            height: qc.height,
            round: qc.round,
            phase: qc.phase,
            checkpoint_id: qc.checkpoint_id,
            qc_id: qc.id(),
        };
        let advance_cert = match &self.last_valid_certificate {
            None => true,
            Some(c) => (qc.height.get(), qc.round.get()) > (c.height.get(), c.round.get()),
        };
        if advance_cert {
            self.last_valid_certificate = Some(cert);
        }
        match &self.locked {
            None => {
                self.locked = Some(candidate);
                self.proof_of_lock = Some(proof);
                Ok(LockAction::Locked { round: qc.round })
            }
            Some(current) if current.checkpoint_id == qc.checkpoint_id => {
                if proof.round.get() > current.round.get() {
                    self.proof_of_lock = Some(proof);
                }
                Ok(LockAction::Reaffirmed { round: qc.round })
            }
            Some(current) => {
                let current = *current;
                if qc.round.get() > current.round.get() {
                    // Evidence only: see PROVISIONAL_UNLOCK_RULE.
                    self.proof_of_lock = Some(proof);
                    Ok(LockAction::UnlockRequiresOperator {
                        current,
                        proposed: candidate,
                    })
                } else {
                    Ok(LockAction::Refused {
                        current,
                        conflicting_round: qc.round,
                    })
                }
            }
        }
    }
}

/// Refuse to sign while a durable HALT record exists.
///
/// Presence is the signal: a record that no longer decodes is still a HALT, and
/// a read failure must not look like "no halt". Nothing is deleted or rewritten.
fn halt_gate(store: &dyn CasStore) -> Result<(), EmitError> {
    match store.get(HALT_KEY) {
        Ok(None) => Ok(()),
        Ok(Some(bytes)) => {
            let text = open_sealed(&bytes)
                .map(|payload| String::from_utf8_lossy(payload).to_string())
                .unwrap_or_else(|error| format!("unreadable halt record: {error}"));
            Err(EmitError::Halted(text))
        }
        Err(error) => Err(EmitError::Halted(format!(
            "halt record unreadable: {error}"
        ))),
    }
}

/// Emit a signature, in the only order that is safe.
///
/// 0. refuse if a durable HALT record exists ([`HALT_KEY`]); the check is
///    repeated just before signing, so an authorisation obtained before the
///    halt cannot produce a signature after it;
/// 1. refuse without a matching [`crate::l2persist::VoteAuthorization`], if
///    recovery is uncertain, or if the vote contradicts the lock;
/// 2. **reserve** the slot (atomic CAS) — a conflicting slot is refused here;
/// 3. **flush** the reservation, so it survives a crash before the signature;
/// 4. sign;
/// 5. verify the produced signature against the registry;
/// 6. record it (`Reserved -> Signed`, CAS) and flush again;
/// 7. refuse to **release** it if a durable HALT exists now
///    ([`EmitError::SignedButHalted`], BX): the vote is recorded but never
///    returned for broadcast.
///
/// Steps 3 and 6 are not reorderable: if the process dies between 3 and 5 the
/// slot stays reserved and can never take a different value; if it dies between
/// 5 and 6 the same holds, and the operator is told
/// ([`EmitError::SignedButNotRecorded`]) not to broadcast.
///
/// Step 7 cannot un-sign a signature that already exists; it guarantees that a
/// HALT which completed before this call returns is never followed by a released
/// vote. See `linearization-guarantees.md` (mission BX).
pub fn sign_vote<F>(
    state: &PersistentConsensusState,
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    unsigned: &ConsensusVote,
    auth: &crate::l2persist::VoteAuthorization,
    sign: F,
) -> Result<SignedOutcome, EmitError>
where
    F: FnOnce(&[u8]) -> [u8; 64],
{
    if unsigned.signature != [0u8; 64] {
        return Err(EmitError::NotUnsigned);
    }
    // BW (R-BV-2): the durable HALT is the first gate, before the authorisation
    // and before any slot exists. An authorisation built before the halt is
    // still only an authorisation.
    halt_gate(store)?;
    // BU: the authorisation is the gate on the vote itself. It is bound to all six signed
    // fields, so it cannot be reused for another position or another value.
    if !auth.covers(unsigned) {
        return Err(EmitError::NotAuthorized(
            "the authorisation was issued for another vote".to_string(),
        ));
    }
    state.signing_check(unsigned)?;

    let slot = SlotKey::of(unsigned);
    match store.reserve(&slot, &unsigned.checkpoint_id)? {
        ReserveOutcome::Granted(_) => {}
        ReserveOutcome::Idempotent(r) => {
            if let Some(existing) = r.vote.clone() {
                // Already signed, identically. Re-signing would add nothing and
                // the recorded vote is the one already emitted.
                //
                // BZ (R-BZ-1): an already-signed vote is still a *release*.
                // A HALT durable at this point must stop it exactly as it stops
                // a fresh signature: the slot stays as durable evidence, and the
                // caller is told not to broadcast.
                if let Err(EmitError::Halted(reason)) = halt_gate(store) {
                    return Err(EmitError::SignedButHalted(reason));
                }
                return Ok(SignedOutcome {
                    vote: existing,
                    reservation: r,
                    settlement: Settlement::AlreadySigned,
                    flushed_before_signing: false,
                });
            }
            // Reserved but never signed (crash between flush and sign): the
            // slot already commits this exact checkpoint, so signing now cannot
            // equivocate — proceed.
        }
        ReserveOutcome::Conflicting(r) => {
            return Err(EmitError::Equivocation {
                existing_checkpoint: r.checkpoint_id,
            })
        }
    }

    // Durability barrier: the anti-equivocation commitment must be persisted
    // before any signature exists.
    store.flush()?;

    // BW (R-BV-2): second halt check, immediately before the signature exists.
    // A halt committed while this call was reserving is still observed. If the
    // reservation was already made it stays as crash-equivalent evidence — it
    // can never take another value — and `restore` reports it.
    halt_gate(store)?;

    let signature = sign(&unsigned.signing_bytes());
    let mut vote = unsigned.clone();
    vote.signature = signature;
    vote.verify(registry, state.network)
        .map_err(|e| EmitError::InvalidSignature(e.to_string()))?;

    let recorded = store
        .record_signed(&vote)
        .map_err(|e| EmitError::SignedButNotRecorded(format!("slot {slot:?}: {e}")))?;
    store
        .flush()
        .map_err(|e| EmitError::DurabilityUncertain(e.to_string()))?;

    // BX (R-BX-1): third and last read, once the signature is durable. A HALT
    // that completed while this call was signing cannot un-sign the vote, but it
    // must stop the vote from being **released**: returning `Ok` would hand the
    // caller a signature produced across a halt, and it would be broadcast. The
    // slot record stays as durable evidence (`reserved -> signed`), and the
    // caller is told not to broadcast.
    if let Err(EmitError::Halted(reason)) = halt_gate(store) {
        return Err(EmitError::SignedButHalted(reason));
    }

    Ok(SignedOutcome {
        vote,
        reservation: recorded,
        settlement: Settlement::FreshlySigned,
        flushed_before_signing: true,
    })
}

/// Apply a certificate and persist the state in one step.
pub fn observe_and_persist(
    state: &mut PersistentConsensusState,
    store: &dyn CasStore,
    qc: &QuorumCertificate,
    registry: &ValidatorRegistry,
    network: u64,
) -> Result<LockAction, StateError> {
    let action = state.observe_certificate(qc, registry, network)?;
    state.persist(store)?;
    Ok(action)
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Outcome of a startup restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Verdict.
    pub status: RecoveryStatus,
    /// State restored, if the record could be read.
    pub state: Option<PersistentConsensusState>,
    /// Slot records found on disk.
    pub slots: usize,
    /// Slot records holding a signature.
    pub signed: usize,
    /// Reservations with no signature (a crash between reserve and sign).
    pub reservations_without_signature: usize,
    /// Human-readable anomalies.
    pub findings: Vec<String>,
}

impl RecoveryReport {
    /// Whether signing is allowed after this restore.
    pub fn may_sign(&self) -> bool {
        self.status.may_sign()
    }
}

fn block(status: &mut RecoveryStatus, reason: RecoveryReason) {
    if status.may_sign() {
        *status = RecoveryStatus::RecoveryRequired(reason);
    }
}

/// Restore safety state from disk and decide whether signing is allowed.
///
/// `expected_anchor`: the store identity the caller knows it provisioned. When
/// supplied and absent, recovery **fails closed** — a deleted database and a
/// database that never voted look identical otherwise.
///
/// Checks: record integrity, anchor, network, lock/certificate coherence, every
/// slot record against its own key, annotations left by a crash between reserve
/// and sign, and contradictory signatures.
pub fn restore(
    store: &dyn AtomicSlotStore,
    expected_anchor: Option<[u8; 32]>,
    network: u64,
) -> RecoveryReport {
    let mut findings: Vec<String> = Vec::new();
    let mut status = RecoveryStatus::Clean;

    let mut loaded = match PersistentConsensusState::load(store) {
        Ok(v) => v,
        Err(e) => {
            return RecoveryReport {
                status: RecoveryStatus::RecoveryRequired(RecoveryReason::CorruptState(
                    e.to_string(),
                )),
                state: None,
                slots: 0,
                signed: 0,
                reservations_without_signature: 0,
                findings: vec![format!("consensus state unreadable: {e}")],
            }
        }
    };

    if let Some(expected) = expected_anchor {
        match &loaded {
            None => {
                findings.push(
                    "no persisted state although an anchor was expected: absence is not evidence of no prior vote"
                        .to_string(),
                );
                block(&mut status, RecoveryReason::MissingAnchor);
            }
            Some(s) if s.anchor != expected => {
                findings.push("anchor mismatch: store belongs to another installation".to_string());
                block(
                    &mut status,
                    RecoveryReason::ForeignAnchor {
                        expected,
                        found: s.anchor,
                    },
                );
            }
            _ => {}
        }
    }

    if let Some(s) = &loaded {
        if s.network != network {
            findings.push(format!(
                "state network {} does not match configured {}",
                s.network, network
            ));
            block(
                &mut status,
                RecoveryReason::IncompleteState("network mismatch".to_string()),
            );
        }
        if s.locked.is_some() != s.proof_of_lock.is_some() {
            findings.push("lock without proof, or proof without lock".to_string());
            block(
                &mut status,
                RecoveryReason::IncompleteState("lock/proof mismatch".to_string()),
            );
        }
        if let (Some(lock), Some(proof)) = (&s.locked, &s.proof_of_lock) {
            // BW (R-BV-1): the retained proof must be able to justify the
            // retained lock. A proof from another height, or from an earlier
            // round than the lock, cannot have authorised it; a proof at the
            // lock's own round must name the locked value (`AW-LOCK-10`). A
            // proof at a *later* round is the recorded, unapplied evidence of
            // `PROVISIONAL_UNLOCK_RULE` and is allowed here: it never moves the
            // lock.
            let incoherent = proof.proposed.height != lock.height
                || proof.round.get() < lock.round.get()
                || (proof.round.get() == lock.round.get()
                    && proof.proposed.checkpoint_id != lock.checkpoint_id);
            if incoherent {
                findings.push(format!(
                    "proof of lock ({}@{}) cannot justify lock {}@{}",
                    hex::encode(proof.proposed.checkpoint_id),
                    proof.round.get(),
                    hex::encode(lock.checkpoint_id),
                    lock.round.get()
                ));
                block(
                    &mut status,
                    RecoveryReason::ContradictoryLock(
                        "proof does not justify the lock".to_string(),
                    ),
                );
            }
        }
        if s.unlock_rule_provisional && s.proof_of_lock.is_none() {
            findings.push("provisional unlock recorded without proof".to_string());
            block(
                &mut status,
                RecoveryReason::IncompleteState("provisional unlock without proof".to_string()),
            );
        }
        if let (Some(l), Some(c)) = (&s.locked, &s.last_valid_certificate) {
            if l.round.get() == c.round.get() && l.checkpoint_id != c.checkpoint_id {
                findings.push(
                    "locked value and last valid certificate disagree at the same round"
                        .to_string(),
                );
                block(
                    &mut status,
                    RecoveryReason::ContradictoryLock(format!(
                        "lock {} vs certificate {}",
                        hex::encode(l.checkpoint_id),
                        hex::encode(c.checkpoint_id)
                    )),
                );
            }
        }
    }

    let (mut slots, mut signed, mut unsigned) = (0usize, 0usize, 0usize);
    match store.scan_slots() {
        Ok(records) => {
            slots = records.len();
            for record in &records {
                match (&record.state, &record.vote) {
                    (SlotState::Signed, Some(vote)) => {
                        signed += 1;
                        // A `Nil` vote commits to no checkpoint, so it can neither
                        // contradict a lock nor a certified value (`AW-LOCK-3`:
                        // abstention is neutral). Treating it as a contradiction
                        // would block, forever, a node that abstained while
                        // locked — which is precisely how restarts push operators
                        // toward an unauthorised unlock.
                        let neutral = vote.checkpoint_id == [0u8; 32];
                        if let Some(s) = &loaded {
                            if let Some(l) = &s.locked {
                                // BW (R-BV-1): compare the **round** as well as
                                // the value. `A4'` lets a node prevote another
                                // value before its lock moves, and `AW-LOCK-2`
                                // moves the lock at the round of the precommit
                                // that justifies it. A vote for another value at
                                // a round strictly below the lock's is therefore
                                // history, not a contradiction; a vote at or
                                // after the lock round is one.
                                if !neutral
                                    && l.height == vote.height
                                    && l.checkpoint_id != vote.checkpoint_id
                                    && vote.round.get() >= l.round.get()
                                {
                                    findings.push(format!(
                                        "signed vote in round {} contradicts the lock written in round {} at height {}",
                                        vote.round.get(),
                                        l.round.get(),
                                        l.height.get()
                                    ));
                                    block(
                                        &mut status,
                                        RecoveryReason::ContradictoryLock(format!(
                                            "signature in round {} contradicts the locked value (lock round {})",
                                            vote.round.get(),
                                            l.round.get()
                                        )),
                                    );
                                }
                            }
                            // BW (R-BV-1): a signed vote at or before a
                            // certificate is not a contradiction by itself.
                            // `A4'` allows a prevote for another value before
                            // the certified round, and a certificate older than
                            // the lock is stale evidence of an unapplied change.
                            // The lock rule above is the sound oracle; the
                            // remaining certificate check is the same-round one
                            // at the top of this function.
                            //
                            // BX (R-BX-4): the former check here compared a
                            // signed vote's round with `highest_signed_round` and
                            // blocked when it was lower. That rule is unsound, not
                            // merely inert: rounds advance during normal
                            // operation, so a node that signed in round 3 and then
                            // round 5 would block its own restart, and the field
                            // carries no height to compare across heights. It is
                            // removed; the field is re-derived from the slot
                            // records in `restore_engine`, where the restored
                            // height is known.
                        }
                    }
                    (SlotState::Reserved, None) => {
                        unsigned += 1;
                        findings.push(format!(
                            "reservation without signature under {}",
                            record.slot.storage_key()
                        ));
                    }
                    _ => {
                        findings.push(format!(
                            "slot record state/contents disagree under {}",
                            record.slot.storage_key()
                        ));
                        block(
                            &mut status,
                            RecoveryReason::IncoherentSlot(
                                "state and contents disagree".to_string(),
                            ),
                        );
                    }
                }
            }
        }
        Err(SlotStoreError::Corrupt(msg)) => {
            findings.push(format!("slot scan failed: {msg}"));
            block(&mut status, RecoveryReason::IncoherentSlot(msg));
        }
        Err(e) => {
            findings.push(format!("slot scan unreadable: {e}"));
            block(&mut status, RecoveryReason::CorruptState(e.to_string()));
        }
    }

    if let Some(s) = &mut loaded {
        s.status = status.clone();
    }

    RecoveryReport {
        status,
        state: loaded,
        slots,
        signed,
        reservations_without_signature: unsigned,
        findings,
    }
}
