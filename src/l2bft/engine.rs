//! The local BFT engine: rounds, votes, locks, finality.
//!
//! # The rule that governs every line here
//!
//! `R-LOCK-1..5` and `AW-LOCK-1..14` from mission AW, which consolidate
//! `LOCK-UPD`, `A4'`, `LOCK-EXC` and `LOCK-DUR` (A-06.6-S §4.2) with the
//! proposal rule `P2`/`P3` (A-06.6-AA §5):
//!
//! > The lock is written by a **non-Nil precommit** and by nothing else. A
//! > prevote never locks. A validated proof of lock authorizes a prevote outside
//! > the lock when its round sits in `[lockR, r)` — it never unlocks.
//!
//! There is **no unlock operation**, and adding one would be unsafe: resetting
//! `lockV` destroys `lockR`, which `L4` uses to exclude the prevoters of the
//! other value (A-06.6-X `A9-5`).
//!
//! # Order of every signature
//!
//! Every signature goes through [`crate::l2persist::sign_vote`], which reserves
//! the slot atomically, flushes, signs, verifies and records. The engine adds its
//! own checks **before** that call:
//!
//! ```text
//! halt?  -> recovery uncertain?  -> registry matches context?
//!   -> lock permits this value?  -> AU: reserve -> flush -> sign -> verify -> record
//! ```
//!
//! The engine's `A4'` check comes first and is authoritative: AU's own rule
//! (`round <= lockR`) only ever refuses votes that `A4'` already refuses, so it
//! can never block a justified one.
//!
//! # Finality is not a certificate
//!
//! `N-CKPT-2` says a height is decided when a quorum certificate exists. That is
//! necessary, not sufficient: the checkpoint record itself must validate
//! (`Checkpoint::validate`), it must chain to its parent (`validate_link`), and
//! its parent must be the one this node finalised. [`BftState::finalize`] checks
//! all three separately — a valid QC over an invalid checkpoint finalises
//! nothing.

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::{CheckpointHeight, GenerationId, Round, ValidatorId};
use crate::consensus::transitions::{GenerationClosure, GenerationLedger};
use crate::l2bft::cert::{PrecommitCertificate, PrevoteCertificate, ProofOfLock};
use crate::l2bft::context::{BftContext, BftError, Precommit, Prevote, VoteOutcome};
use crate::l2bft::round::{
    RoundChange, RoundChangeEvidence, RoundChangeOutcome, RoundChangeSet, MAX_ROUND_JUMP,
};
use crate::l2crypto::qc::QuorumCertificate;
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use crate::l2persist::round::{ChangeSummary, PositionVerdict, RoundPosition};
use crate::l2persist::state::{
    LockedValue, PersistentConsensusState, ProofOfLock as PersistedProofOfLock, RecoveryReason,
    RecoveryStatus,
};
use crate::l2persist::{
    open_sealed, seal, AtomicSlotStore, CasStore, RecoveryReport, SlotReservation, SlotState,
    SLOT_PREFIX,
};
use std::collections::BTreeMap;

/// Version of the persisted finality encoding.
///
/// v2 (mission BN, `R-1`) appends the decided transition as `[tag][32 bytes]` and
/// is 270 bytes; v1 was 237 bytes and is still decoded, with
/// `transition_id: None` because those bytes could not carry it.
pub const FINALITY_FORMAT_VERSION: u8 = 2;

/// Version 1 of the persisted finality encoding (read-only compatibility).
pub const FINALITY_FORMAT_VERSION_V1: u8 = 1;

/// Encoded length of a v1 finality record.
pub const FINALITY_RECORD_LEN_V1: usize = 237;

/// Encoded length of a v2 finality record.
pub const FINALITY_RECORD_LEN_V2: usize = 270;

/// Metadata key prefix for finality decisions.
pub const FINALITY_PREFIX: &str = "l2/v3/bft/finality/";

/// Metadata key holding the halt record, once a safety violation was seen.
///
/// Re-exported from [`crate::l2persist::HALT_KEY`] so the engine and the
/// signature frontier cannot drift apart (mission BW: `sign_vote` reads the same
/// key the engine writes).
pub const HALT_KEY: &str = crate::l2persist::HALT_KEY;

/// The abstention value (`Nil`).
///
/// The wire format has no sum type: `Nil` is the all-zero checkpoint id, which no
/// real checkpoint can take. It is always signable (`AW-LOCK-1` branch 1) and it
/// never installs a lock (`AW-LOCK-3`, `Nil` neutral).
pub const NIL_VALUE: [u8; 32] = [0u8; 32];

/// Key of the finality decision at `height`.
pub fn finality_key(height: CheckpointHeight) -> String {
    format!("{}{:016x}", FINALITY_PREFIX, height.get())
}

/// Metadata key prefix for pending generation installations (`N-TRN-7`).
///
/// The record is written **before** the finality record of a checkpoint that
/// closes a generation, so a crash can never leave a decided closure without a
/// durable obligation to install the next generation.
pub const PENDING_INSTALL_PREFIX: &str = "l2/v3/bft/pending-install/";

/// Encoding version of [`PendingInstall`].
pub const PENDING_INSTALL_FORMAT_VERSION: u8 = 1;

/// Key of the installation obligation created by the closure at `height`.
pub fn pending_install_key(height: CheckpointHeight) -> String {
    format!("{}{:016x}", PENDING_INSTALL_PREFIX, height.get())
}

/// A decided transition whose next generation has not been installed yet.
///
/// Mission BM (`N-6` / `N-TRN-7`): closing a generation is a decision, and a
/// decision is not an installation. The engine records the obligation here, at
/// the moment the closing checkpoint becomes final, and refuses to sign or
/// decide **above** `height` until [`BftState::close_generation`] has installed
/// exactly this closure. `installed` is a fact read back from the certified
/// closure in the generation ledger, never a caller's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingInstall {
    /// Encoding version.
    pub version: u8,
    /// Network.
    pub network: u64,
    /// Height of the decided closing checkpoint (`h_close`).
    pub height: CheckpointHeight,
    /// Generation that closes.
    pub generation: GenerationId,
    /// `candidate_id` committed by the checkpoint's transition identifier.
    pub candidate_id: [u8; 32],
    /// Identifier of the decided closing checkpoint.
    pub value_id: [u8; 32],
    /// Whether the ledger proves that this exact closure was applied.
    pub installed: bool,
    /// Generation installed by that closure; zero while not installed.
    pub installed_generation: GenerationId,
    /// Set root installed by that closure; zero while not installed.
    pub installed_set_root: [u8; 32],
}

impl PendingInstall {
    /// Canonical encoding: fixed layout, little-endian integers.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(178);
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.candidate_id);
        out.extend_from_slice(&self.value_id);
        out.push(u8::from(self.installed));
        out.extend_from_slice(&self.installed_generation.0);
        out.extend_from_slice(&self.installed_set_root);
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, BftError> {
        if bytes.len() != 178 {
            return Err(BftError::Rejected(format!(
                "pending-install record length {} != 178",
                bytes.len()
            )));
        }
        let mut p = 0usize;
        let take = |n: usize, p: &mut usize| -> Vec<u8> {
            let out = bytes[*p..*p + n].to_vec();
            *p += n;
            out
        };
        let version = take(1, &mut p)[0];
        if version != PENDING_INSTALL_FORMAT_VERSION {
            return Err(BftError::Rejected(format!(
                "unsupported pending-install version {version}"
            )));
        }
        let u64_at = |p: &mut usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&take(8, p));
            u64::from_le_bytes(b)
        };
        let network = u64_at(&mut p);
        let height = CheckpointHeight(u64_at(&mut p));
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&take(32, &mut p));
        let mut candidate_id = [0u8; 32];
        candidate_id.copy_from_slice(&take(32, &mut p));
        let mut value_id = [0u8; 32];
        value_id.copy_from_slice(&take(32, &mut p));
        let installed = match take(1, &mut p)[0] {
            0 => false,
            1 => true,
            other => {
                return Err(BftError::Rejected(format!(
                    "non-canonical pending-install flag {other}"
                )))
            }
        };
        let mut installed_generation = [0u8; 32];
        installed_generation.copy_from_slice(&take(32, &mut p));
        let mut installed_set_root = [0u8; 32];
        installed_set_root.copy_from_slice(&take(32, &mut p));
        let record = Self {
            version,
            network,
            height,
            generation: GenerationId(generation),
            candidate_id,
            value_id,
            installed,
            installed_generation: GenerationId(installed_generation),
            installed_set_root,
        };
        if !record.installed
            && (record.installed_generation.0 != [0u8; 32]
                || record.installed_set_root != [0u8; 32])
        {
            return Err(BftError::Rejected(
                "pending installation carries an installed generation without being installed"
                    .to_string(),
            ));
        }
        Ok(record)
    }
}

/// A final, persisted decision about one height.
///
/// Carries everything needed to re-derive the claim: the exact certificate
/// identifier and the recomputed weights. It is not revocable by local
/// re-evaluation (`N-SAFE-4`): once written, the only way out is a contradictory
/// decision, which halts the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityDecision {
    /// Encoding version.
    pub version: u8,
    /// Network.
    pub network: u64,
    /// Generation.
    pub generation: GenerationId,
    /// Height decided.
    pub height: CheckpointHeight,
    /// Round that decided it.
    pub round: Round,
    /// The decided checkpoint.
    pub checkpoint_id: [u8; 32],
    /// Parent the checkpoint claimed.
    pub parent: [u8; 32],
    /// Validator-set root in force.
    pub validator_set_root: [u8; 32],
    /// Registry root in force.
    pub registry_root: [u8; 32],
    /// Recomputed support weight.
    pub support: u64,
    /// Recomputed total weight.
    pub total: u64,
    /// Required threshold.
    pub quorum: u64,
    /// Identifier of the precommit certificate.
    pub certificate_id: [u8; 32],
    /// Candidate identifier of the transition this checkpoint decided, if any.
    ///
    /// `Some` only for a checkpoint that closes a generation (`N-6` / `R-1`), and
    /// only from a v2 record. `None` for an ordinary checkpoint and for a legacy
    /// v1 record, whose bytes could not carry the field.
    pub transition_id: Option<[u8; 32]>,
}

impl FinalityDecision {
    /// Canonical encoding: fixed layout, little-endian integers.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(if self.version >= FINALITY_FORMAT_VERSION {
            FINALITY_RECORD_LEN_V2
        } else {
            FINALITY_RECORD_LEN_V1
        });
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.round.get().to_le_bytes());
        out.extend_from_slice(&self.checkpoint_id);
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.validator_set_root);
        out.extend_from_slice(&self.registry_root);
        out.extend_from_slice(&self.support.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.quorum.to_le_bytes());
        out.extend_from_slice(&self.certificate_id);
        // v2 (mission BN, R-1): the decided transition, so that a decided closure
        // is recognisable as an installation obligation at restore. A v1 record is
        // re-encoded as v1, byte for byte, so its identifier stays stable.
        if self.version >= FINALITY_FORMAT_VERSION {
            match self.transition_id {
                Some(id) => {
                    out.push(1);
                    out.extend_from_slice(&id);
                }
                None => {
                    out.push(0);
                    out.extend_from_slice(&[0u8; 32]);
                }
            }
        }
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, BftError> {
        if bytes.len() != FINALITY_RECORD_LEN_V1 && bytes.len() != FINALITY_RECORD_LEN_V2 {
            return Err(BftError::Rejected(format!(
                "finality record length {} is neither v1 ({}) nor v2 ({})",
                bytes.len(),
                FINALITY_RECORD_LEN_V1,
                FINALITY_RECORD_LEN_V2
            )));
        }
        let mut p = 0usize;
        let take = |n: usize, p: &mut usize| -> Vec<u8> {
            let out = bytes[*p..*p + n].to_vec();
            *p += n;
            out
        };
        let version = take(1, &mut p)[0];
        let expected_len = match version {
            FINALITY_FORMAT_VERSION_V1 => FINALITY_RECORD_LEN_V1,
            FINALITY_FORMAT_VERSION => FINALITY_RECORD_LEN_V2,
            other => {
                return Err(BftError::Rejected(format!(
                    "unsupported finality version {other}"
                )))
            }
        };
        if bytes.len() != expected_len {
            return Err(BftError::Rejected(format!(
                "finality version {version} expects {expected_len} bytes, got {}",
                bytes.len()
            )));
        }
        let u64_at = |p: &mut usize| -> u64 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&take(8, p));
            u64::from_le_bytes(b)
        };
        let network = u64_at(&mut p);
        let mut g = [0u8; 32];
        g.copy_from_slice(&take(32, &mut p));
        let height = CheckpointHeight(u64_at(&mut p));
        let mut r = [0u8; 4];
        r.copy_from_slice(&take(4, &mut p));
        let round = Round(u32::from_le_bytes(r));
        let mut checkpoint_id = [0u8; 32];
        checkpoint_id.copy_from_slice(&take(32, &mut p));
        let mut parent = [0u8; 32];
        parent.copy_from_slice(&take(32, &mut p));
        let mut validator_set_root = [0u8; 32];
        validator_set_root.copy_from_slice(&take(32, &mut p));
        let mut registry_root = [0u8; 32];
        registry_root.copy_from_slice(&take(32, &mut p));
        let support = u64_at(&mut p);
        let total = u64_at(&mut p);
        let quorum = u64_at(&mut p);
        let mut certificate_id = [0u8; 32];
        certificate_id.copy_from_slice(&take(32, &mut p));
        let transition_id = if version >= FINALITY_FORMAT_VERSION {
            let tag = take(1, &mut p)[0];
            let mut id = [0u8; 32];
            id.copy_from_slice(&take(32, &mut p));
            match tag {
                0 => None,
                1 => Some(id),
                other => {
                    return Err(BftError::Rejected(format!(
                        "unknown transition tag {other} in finality record"
                    )))
                }
            }
        } else {
            None
        };
        Ok(Self {
            version,
            network,
            generation: GenerationId(g),
            height,
            round,
            checkpoint_id,
            parent,
            validator_set_root,
            registry_root,
            support,
            total,
            quorum,
            certificate_id,
            transition_id,
        })
    }

    /// Content address.
    pub fn id(&self) -> [u8; 32] {
        blake3::hash(&self.encode()).into()
    }
}

/// Why the engine stopped accepting anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    /// A previously persisted halt record was found at startup. The engine does
    /// not reinterpret it: it refuses to sign until an operator investigates.
    Persisted(String),
    /// Two different checkpoints were decided at one height.
    ConflictingFinality {
        /// Height involved.
        height: CheckpointHeight,
        /// First decision.
        first: [u8; 32],
        /// Second decision.
        second: [u8; 32],
    },
    /// Two persisted decisions disagree about the chain.
    BrokenFinalityChain {
        /// Height of the child record.
        height: CheckpointHeight,
    },
    /// A precommit was signed but its lock could not be made durable.
    ///
    /// Continuing with a lost lock would let this node prevote another value
    /// later, so the engine stops instead.
    LockNotDurable {
        /// Height involved.
        height: CheckpointHeight,
        /// Value that could not be locked, hex.
        value: [u8; 32],
    },
}

impl HaltReason {
    /// Human-readable description, with both values preserved.
    pub fn describe(&self) -> String {
        match self {
            Self::Persisted(text) => format!("previous halt record: {text}"),
            Self::ConflictingFinality {
                height,
                first,
                second,
            } => format!(
                "conflicting finality at height {}: {} vs {}",
                height.get(),
                hex::encode(first),
                hex::encode(second)
            ),
            Self::BrokenFinalityChain { height } => {
                format!("finality chain broken at height {}", height.get())
            }
            Self::LockNotDurable { height, value } => format!(
                "lock not durable at height {}: {}",
                height.get(),
                hex::encode(value)
            ),
        }
    }
}

/// Votes observed in the current round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundState {
    /// Round these votes belong to.
    pub round: Round,
    /// Value proposed in this round, if any.
    pub proposal: Option<[u8; 32]>,
    /// Proof of lock carried with the proposal (`AW-LOCK-9`, `P2`).
    pub proposal_proof: Option<ProofOfLock>,
    /// Prevotes observed.
    pub prevotes: Vec<Prevote>,
    /// Precommits observed.
    pub precommits: Vec<Precommit>,
    /// Round-change messages collected for the current height.
    pub round_changes: Vec<RoundChange>,
}

impl RoundState {
    fn new(round: Round) -> Self {
        Self {
            round,
            proposal: None,
            proposal_proof: None,
            prevotes: Vec::new(),
            precommits: Vec::new(),
            round_changes: Vec::new(),
        }
    }
}

/// The local engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BftState {
    /// Network.
    pub network: u64,
    /// Generation in force.
    pub generation: GenerationId,
    /// Current height.
    pub height: CheckpointHeight,
    /// Current round.
    pub round: Round,
    /// Validator-set root in force.
    pub set_root: [u8; 32],
    /// Votes of the current round.
    pub round_state: RoundState,
    /// Persisted safety state from AU: lock, anchor, recovery status.
    ///
    /// Private since mission BU: an external caller may read it through
    /// [`Self::persisted`] but cannot assign a lock, clear one, or clear a
    /// recovery verdict. `bt_16` (BT) had shown that a public field let a caller
    /// erase the lock in memory and sign a contradictory value.
    persisted: PersistentConsensusState,
    /// Decision about the current height, once taken.
    pub finality: Option<FinalityDecision>,
    /// Set when a safety violation was detected; never cleared at runtime.
    pub halt: Option<HaltReason>,
    /// Generation ledger in force (mission BC, `R-TRANS-4`/`R-TRANS-7`).
    ///
    /// Never optional: an engine always opens a ledger at its own generation, so
    /// no constructor can produce an engine without the closure guard, and no
    /// caller can make a `generation` field alone authorize a signature. The only
    /// path that changes [`Self::generation`] is [`Self::close_generation`], which
    /// goes through this ledger.
    pub ledger: GenerationLedger,

    /// The restored lock has no valid proof (`AW-LOCK-11` case b).
    ///
    /// The lock is kept and stays binding; only the ability to *propose* it with
    /// a certificate is lost. Never blocks voting the locked value itself.
    pub lock_proof_absent: bool,

    /// Last height this engine **decided**, for `N-TRN-7` sequentiality.
    ///
    /// Distinct from [`Self::finality`], which [`Self::advance_height`] clears:
    /// a decision must be followed by the next height, never by a jump.
    pub last_decided: Option<CheckpointHeight>,

    /// Installation obligations created by decided closures, by closing height.
    ///
    /// Written before the finality record and satisfied only by
    /// [`Self::close_generation`] applying exactly that closure. While an entry
    /// at height `h` is unsatisfied, every signature and decision at a height
    /// above `h` is refused.
    pub pending_installs: BTreeMap<CheckpointHeight, PendingInstall>,
}

impl BftState {
    /// Build an engine at `height`, round 0, with no lock.
    pub fn new(
        network: u64,
        registry: &ValidatorRegistry,
        height: CheckpointHeight,
        anchor: [u8; 32],
    ) -> Self {
        let generation = registry.generation();
        Self {
            network,
            generation,
            height,
            round: Round(0),
            set_root: registry.set_root(),
            round_state: RoundState::new(Round(0)),
            persisted: PersistentConsensusState::fresh(network, generation, anchor),
            finality: None,
            halt: None,
            ledger: GenerationLedger::new(network, generation),
            lock_proof_absent: false,
            last_decided: None,
            pending_installs: BTreeMap::new(),
        }
    }

    /// Context of the current position at `phase`.
    pub fn context(&self, phase: VotePhase) -> BftContext {
        BftContext::new(
            self.network,
            self.generation,
            self.height,
            self.round,
            phase,
            self.set_root,
        )
    }

    /// Read-only view of the persisted safety state.
    ///
    /// Every legitimate reader (round position, operator tools, tests) needs the
    /// lock, the proof and the recovery verdict. None of them needs to write:
    /// the only mutation paths are the engine's own validated operations.
    pub fn persisted(&self) -> &PersistentConsensusState {
        &self.persisted
    }

    /// The lock in force **at the current height**.
    ///
    /// AU stores one lock record; a record for another height is history, not a
    /// constraint on this height. This function is the only place that decides
    /// that, so no call site can accidentally read a stale lock as active.
    pub fn active_lock(&self) -> Option<LockedValue> {
        match &self.persisted.locked {
            Some(l) if l.height == self.height => Some(*l),
            _ => None,
        }
    }

    /// Record a recovery verdict, keeping the **first** reason found.
    ///
    /// The first verdict is the one with the most context; a later check must
    /// neither overwrite it nor ever clear it.
    pub fn block_recovery(&mut self, reason: RecoveryReason) {
        if matches!(self.persisted.status, RecoveryStatus::Clean) {
            self.persisted.status = RecoveryStatus::RecoveryRequired(reason);
        }
    }

    /// `AW-LOCK-11(c)`: audit this node's own precommit evidence on disk.
    ///
    /// The lock record is a **summary**; the vote slots are the evidence. A signed
    /// precommit for `v` at round `r` at this height implies `lockV = v` and
    /// `lockR >= r` (`AW-LOCK-2`, invariant `I-2`). If the summary disagrees with
    /// the evidence, the restored state must not sign: it would prevote a
    /// contradictory value with `lockV = 0`, which is exactly what `A4'` forbids.
    ///
    /// Four conditions block, and **none of them is repaired by deleting
    /// evidence** — the slots and the proof are left exactly as found:
    ///
    /// - a durable non-Nil precommit with no lock record: the lock is lost, not
    ///   absent;
    /// - a lock whose round or value is not the one of the **highest** durable
    ///   precommit: the summary is stale, or names another value;
    /// - two different values durable at that highest round: `A1` is broken, which
    ///   is a halt condition, never an arbitration;
    /// - an undecodable slot, or a state that records a provisional unlock: an
    ///   unreadable commitment is not an absent one.
    ///
    /// A precommit for `Nil` is ignored: it establishes no lock (`AW-LOCK-3`), so
    /// it can never make a lock look stale.
    fn audit_own_precommit_evidence(&mut self, store: &dyn CasStore, registry: &ValidatorRegistry) {
        if self.persisted.unlock_rule_provisional {
            self.block_recovery(RecoveryReason::IncompleteState(
                "state records a provisional unlock, which AW-LOCK-5 does not authorise"
                    .to_string(),
            ));
        }
        let records = match store.scan(SLOT_PREFIX) {
            Ok(records) => records,
            Err(e) => {
                self.block_recovery(RecoveryReason::CorruptState(format!(
                    "vote slots unreadable: {e}"
                )));
                return;
            }
        };
        let generation = registry.generation().0;
        let mut signed: Vec<([u8; 32], Round)> = Vec::new();
        let mut reserved: usize = 0;
        for (_, bytes) in records {
            let record = match open_sealed(&bytes).and_then(SlotReservation::decode) {
                Ok(record) => record,
                Err(e) => {
                    self.block_recovery(RecoveryReason::CorruptState(format!(
                        "undecodable vote slot: {e}"
                    )));
                    return;
                }
            };
            if record.slot.generation != generation
                || record.slot.height != self.height
                || record.slot.phase != VotePhase::Precommit
            {
                continue;
            }
            match record.state {
                SlotState::Signed => {
                    if record.checkpoint_id != NIL_VALUE {
                        signed.push((record.checkpoint_id, record.slot.round));
                    }
                }
                SlotState::Reserved => reserved += 1,
            }
        }
        let lock = self.active_lock();
        if signed.is_empty() {
            if reserved > 0 && lock.is_none() {
                self.block_recovery(RecoveryReason::ContradictoryLock(format!(
                    "a precommit slot was reserved at height {} without a lock record",
                    self.height.get()
                )));
            }
            return;
        }
        let max_round = signed
            .iter()
            .map(|(_, round)| *round)
            .max()
            .expect("signed is not empty");
        let values: Vec<[u8; 32]> = signed
            .iter()
            .filter(|(_, round)| *round == max_round)
            .map(|(value, _)| *value)
            .collect();
        let first = values[0];
        if let Some(other) = values.iter().find(|value| **value != first) {
            self.block_recovery(RecoveryReason::ContradictoryLock(format!(
                "two precommitted values at round {} for height {}: {} and {}",
                max_round.get(),
                self.height.get(),
                hex::encode(first),
                hex::encode(other)
            )));
            return;
        }
        match lock {
            None => self.block_recovery(RecoveryReason::ContradictoryLock(format!(
                "durable precommit at round {} for height {} without a lock record: the lock is lost, not absent",
                max_round.get(),
                self.height.get()
            ))),
            Some(current) if current.round != max_round || current.checkpoint_id != first => {
                self.block_recovery(RecoveryReason::ContradictoryLock(format!(
                    "lock {}@{} disagrees with the durable precommit {}@{} at height {}",
                    hex::encode(current.checkpoint_id),
                    current.round.get(),
                    hex::encode(first),
                    max_round.get(),
                    self.height.get()
                )));
            }
            Some(_) => {}
        }
    }

    /// Whether signing is permitted right now, at the current position.
    ///
    /// BC (`R-BB-1`): the generation ledger is consulted **here**, so a closed
    /// generation cannot sign anything — prevote, precommit, proposal, round
    /// change. This is the single authorization site; the `generation` field of
    /// an engine never authorizes a signature on its own.
    pub fn may_sign(&self) -> Result<(), BftError> {
        self.may_sign_at(self.height)
    }

    /// Whether signing is permitted at `height`.
    ///
    /// [`Self::advance_height`] uses this: after a closure the engine stands on
    /// `h_close` while the active generation already starts at `h_close + 1`, and
    /// requiring `may_sign()` there would make activation impossible.
    fn may_sign_at(&self, height: CheckpointHeight) -> Result<(), BftError> {
        if let Some(halt) = &self.halt {
            return Err(BftError::Halted(halt.describe()));
        }
        if let RecoveryStatus::RecoveryRequired(reason) = &self.persisted.status {
            return Err(BftError::RecoveryRequired(format!("{reason:?}")));
        }
        // N-TRN-7 / BM N-6: a decided closure whose next generation is not
        // installed forbids every signature **above** the closing height. The
        // closing height itself stays reachable so the installation can happen.
        self.require_installation_clear_at(height)?;
        self.ledger
            .may_vote(self.generation, height)
            .map_err(|e| BftError::GenerationClosed(e.to_string()))?;
        Ok(())
    }

    /// Refuse a position above an unsatisfied, certified installation.
    fn require_installation_clear_at(&self, height: CheckpointHeight) -> Result<(), BftError> {
        for (closing, record) in &self.pending_installs {
            if height.get() > closing.get() && !record.installed {
                return Err(BftError::InstallationRequired {
                    height: height.get(),
                });
            }
        }
        Ok(())
    }

    /// Record the installation obligation of a checkpoint that closes a
    /// generation, **before** its finality record is written.
    ///
    /// Idempotent for the same `(height, generation, candidate_id, value)`; a
    /// different record at the same height is ambiguous and blocks the engine
    /// instead of being overwritten.
    fn record_pending_install(
        &mut self,
        checkpoint: &Checkpoint,
        store: &dyn CasStore,
    ) -> Result<(), BftError> {
        let Some(candidate_id) = checkpoint.transition_id else {
            return Ok(());
        };
        let wanted = PendingInstall {
            version: PENDING_INSTALL_FORMAT_VERSION,
            network: self.network,
            height: checkpoint.height,
            generation: checkpoint.generation,
            candidate_id,
            value_id: checkpoint.id(),
            installed: false,
            installed_generation: GenerationId([0u8; 32]),
            installed_set_root: [0u8; 32],
        };
        let same = |record: &PendingInstall| {
            record.height == wanted.height
                && record.generation == wanted.generation
                && record.candidate_id == wanted.candidate_id
                && record.value_id == wanted.value_id
        };
        if let Some(existing) = self.pending_installs.get(&checkpoint.height) {
            if same(existing) {
                return Ok(());
            }
            self.block_recovery(RecoveryReason::IncompleteState(format!(
                "height {} has two pending installations: {} and {}",
                checkpoint.height.get(),
                hex::encode(existing.candidate_id),
                hex::encode(candidate_id)
            )));
            return Err(BftError::Rejected(
                "pending installation contradicts the decided checkpoint".to_string(),
            ));
        }
        let key = pending_install_key(checkpoint.height);
        if let Some(bytes) = store.get(&key)? {
            let stored = PendingInstall::decode(open_sealed(&bytes)?)?;
            if same(&stored) {
                self.pending_installs.insert(checkpoint.height, stored);
                return Ok(());
            }
            self.block_recovery(RecoveryReason::IncompleteState(format!(
                "durable pending installation at height {} belongs to another transition",
                checkpoint.height.get()
            )));
            return Err(BftError::Rejected(
                "durable pending installation contradicts the decided checkpoint".to_string(),
            ));
        }
        let sealed = seal(&wanted.encode());
        if !store.cas(&key, None, &sealed)? {
            let bytes = store.get(&key)?.ok_or_else(|| {
                BftError::Rejected("pending installation vanished during installation".to_string())
            })?;
            let stored = PendingInstall::decode(open_sealed(&bytes)?)?;
            if !same(&stored) {
                self.block_recovery(RecoveryReason::IncompleteState(format!(
                    "a concurrent pending installation was written at height {}",
                    checkpoint.height.get()
                )));
                return Err(BftError::Rejected(
                    "a concurrent pending installation was written".to_string(),
                ));
            }
            self.pending_installs.insert(checkpoint.height, stored);
            return Ok(());
        }
        store.flush()?;
        self.pending_installs.insert(checkpoint.height, wanted);
        Ok(())
    }

    /// Mark an obligation satisfied once the ledger durably contains its
    /// closure. The write is compare-and-swap on the record just read: a
    /// concurrent, different record blocks instead of being acknowledged.
    fn mark_install_recorded(
        &mut self,
        height: CheckpointHeight,
        installed: &ValidatorRegistry,
        store: &dyn CasStore,
    ) -> Result<(), BftError> {
        let key = pending_install_key(height);
        let bytes = store.get(&key)?.ok_or_else(|| {
            BftError::Rejected("the pending installation record disappeared".to_string())
        })?;
        let mut record = PendingInstall::decode(open_sealed(&bytes)?)?;
        if record.height != height || record.generation != self.generation {
            self.block_recovery(RecoveryReason::IncompleteState(format!(
                "pending installation at height {} does not belong to the closing generation",
                height.get()
            )));
            return Err(BftError::Rejected(
                "pending installation record does not match the closure".to_string(),
            ));
        }
        record.installed = true;
        record.installed_generation = installed.generation();
        record.installed_set_root = installed.set_root();
        if !store.cas(&key, Some(&bytes), &seal(&record.encode()))? {
            self.block_recovery(RecoveryReason::IncompleteState(format!(
                "pending installation at height {} changed concurrently",
                height.get()
            )));
            return Err(BftError::Rejected(
                "pending installation changed concurrently".to_string(),
            ));
        }
        store.flush()?;
        self.pending_installs.insert(height, record);
        Ok(())
    }

    fn check_operational(&self, registry: &ValidatorRegistry) -> Result<(), BftError> {
        self.may_sign()?;
        self.context(VotePhase::Prevote).check_registry(registry)
    }

    /// Write the lock: `LOCK-UPD = UPD-NEW ∪ UPD-SAME` (`AW-LOCK-2`).
    ///
    /// Called after this node's own prevote and before its precommit is signed and
    /// emitted, with the prevote certificate that justifies it
    /// (`POL(value, round)`) — see the ordering note in [`Self::precommit`].
    /// A different value replaces the lock (`UPD-NEW`); the same value only
    /// refreshes `lockR` (`UPD-SAME`). There is no path that removes a lock.
    fn apply_lock_update(
        &mut self,
        value: [u8; 32],
        round: Round,
        proof: ProofOfLock,
        store: &dyn CasStore,
    ) -> Result<(), BftError> {
        if value == NIL_VALUE {
            return Err(BftError::InvalidProof("Nil installs no lock"));
        }
        if proof.checkpoint_id != value || proof.round != round {
            return Err(BftError::InvalidProof(
                "proof does not match the value or the round",
            ));
        }
        if !proof.is_valid_for(&self.context(VotePhase::Prevote)) {
            return Err(BftError::InvalidProof(
                "proof belongs to another height, generation or set",
            ));
        }
        // AW-LOCK-10: two proofs at one round for different values cannot both
        // exist under A1. Seeing it is a hypothesis violation: refuse, do not
        // choose, and keep every element of evidence for the caller.
        if let Some(current) = self.active_lock() {
            if current.round == round && current.checkpoint_id != value {
                return Err(BftError::ConflictingProof {
                    round: round.get(),
                    first: hex::encode(current.checkpoint_id),
                    second: hex::encode(value),
                });
            }
        }
        self.persisted.locked = Some(LockedValue {
            checkpoint_id: value,
            height: self.height,
            round,
        });
        self.persisted.proof_of_lock = Some(Self::persistable_proof(&proof));
        self.lock_proof_absent = false;
        self.persisted.persist(store)?;
        Ok(())
    }

    /// Convert a verified proof into the persisted record (`AW-LOCK-4`).
    ///
    /// The bytes of the certificate are stored with it, so a restart re-verifies
    /// the proof from scratch instead of trusting the disk.
    fn persistable_proof(proof: &ProofOfLock) -> PersistedProofOfLock {
        PersistedProofOfLock {
            round: proof.round,
            qc_id: proof.certificate().id(),
            support: proof.support().get(),
            total: proof.total().get(),
            signers: proof.certificate().signers().len() as u32,
            proposed: LockedValue {
                checkpoint_id: proof.checkpoint_id,
                height: proof.height,
                round: proof.round,
            },
            encoded_qc: proof.certificate().encode(),
        }
    }

    /// `AW-LOCK-1` (`A4'`): may this node prevote `value`?
    ///
    /// The single authorization site. Three branches, in this order:
    ///
    /// 1. `Nil` — always allowed (abstention, `Nil` neutral);
    /// 2. `lockV ∈ {0, value}` — no lock, or the locked value itself;
    /// 3. a verified proof of lock with `lockR <= proof.round < r`.
    ///
    /// Branches 1 and 2 are why the lock no longer needs to be defeated: a
    /// locked node can always vote its own value, and can always abstain.
    pub fn check_prevote_admissible(
        &self,
        value: &[u8; 32],
        proof: Option<&ProofOfLock>,
    ) -> Result<(), BftError> {
        if *value == NIL_VALUE {
            return Ok(());
        }
        let lock = match self.active_lock() {
            Some(lock) => lock,
            None => return Ok(()),
        };
        if lock.checkpoint_id == *value {
            return Ok(());
        }
        if let Some(proof) = proof {
            if proof.accepted_for(value, &self.context(VotePhase::Prevote), lock.round) {
                return Ok(());
            }
        }
        Err(BftError::PrevoteNotJustified {
            value: hex::encode(value),
            locked: hex::encode(lock.checkpoint_id),
            lock_round: lock.round.get(),
        })
    }

    /// A prevote for `value` with no proof supplied.
    ///
    /// Kept as an explicit, narrow view of [`Self::check_prevote_admissible`]: it
    /// is the `P3` case, where the node knows no admissible proof at all.
    pub fn check_value_against_lock(&self, value: &[u8; 32]) -> Result<(), BftError> {
        self.check_prevote_admissible(value, None)
    }

    /// `AW-LOCK-8` (`A3-ord`): a precommit requires this node's **own** prevote
    /// of the same value in the same round.
    fn require_own_prevote(&self, value: [u8; 32], signer: ValidatorId) -> Result<(), BftError> {
        match self
            .round_state
            .prevotes
            .iter()
            .find(|p| p.validator() == signer)
        {
            Some(prevote) if prevote.checkpoint_id() == value => Ok(()),
            _ => Err(BftError::PrevoteRequired),
        }
    }

    /// Announce the value proposed for this round.
    ///
    /// This entry point is **schedule-agnostic**: it does not check who proposes.
    /// Every message that arrives from the network must go through
    /// [`Self::accept_proposal`], which enforces the elected proposer (mission BK,
    /// N-1). Tests and drivers that implement their own schedule may keep using
    /// this method, but no network path may.
    pub fn propose(&mut self, value: [u8; 32]) -> Result<(), BftError> {
        self.may_sign()?;
        match self.round_state.proposal {
            Some(existing) if existing != value => {
                Err(BftError::ContextMismatch { field: "value" })
            }
            _ => {
                self.round_state.proposal = Some(value);
                // AW-LOCK-9 P3: a fallback carries no proof, by construction.
                self.round_state.proposal_proof = None;
                Ok(())
            }
        }
    }

    /// `AW-LOCK-9` (`P2`): propose the value of a verified proof, with the proof.
    ///
    /// The upper bound is strict — a proof of the round being proposed cannot
    /// justify it — and the proof must belong to this position. The caller is
    /// responsible for having chosen the highest-round proof it knows; this method
    /// only refuses a proof that cannot justify anything here.
    pub fn propose_certified(
        &mut self,
        value: [u8; 32],
        proof: ProofOfLock,
    ) -> Result<(), BftError> {
        self.may_sign()?;
        if value == NIL_VALUE {
            return Err(BftError::InvalidProof("Nil is not a value to propose"));
        }
        if proof.checkpoint_id != value {
            return Err(BftError::InvalidProof("proof certifies another value"));
        }
        if proof.certificate().qc().network != self.network
            || !proof.is_valid_for(&self.context(VotePhase::Prevote))
        {
            return Err(BftError::InvalidProof(
                "proof belongs to another height, generation or set",
            ));
        }
        if proof.round.get() >= self.round.get() {
            return Err(BftError::InvalidProof(
                "proof round is not strictly below the proposed round",
            ));
        }
        match self.round_state.proposal {
            Some(existing) if existing != value => {
                Err(BftError::ContextMismatch { field: "value" })
            }
            _ => {
                self.round_state.proposal = Some(value);
                self.round_state.proposal_proof = Some(proof);
                Ok(())
            }
        }
    }

    /// Emit a prevote for `value` with no proof of lock.
    ///
    /// This is the `P3` path: the node knows no admissible proof for another
    /// value. A node that does know one must call [`Self::prevote_with_proof`].
    pub fn prevote<F>(
        &mut self,
        value: [u8; 32],
        signer: ValidatorId,
        registry: &ValidatorRegistry,
        store: &dyn AtomicSlotStore,
        sign: F,
    ) -> Result<Prevote, BftError>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        self.prevote_with_proof(value, None, signer, registry, store, sign)
    }

    /// Emit a prevote justified by `proof` when the lock points elsewhere.
    ///
    /// Order, all enforced before this returns: `A4'` check → AU's
    /// `reserve → flush → sign → verify → record`. The lock is **not** touched:
    /// a prevote never writes it.
    pub fn prevote_with_proof<F>(
        &mut self,
        value: [u8; 32],
        proof: Option<&ProofOfLock>,
        signer: ValidatorId,
        registry: &ValidatorRegistry,
        store: &dyn AtomicSlotStore,
        sign: F,
    ) -> Result<Prevote, BftError>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        self.check_operational(registry)?;
        self.check_prevote_admissible(&value, proof)?;

        if let Some(existing) = self
            .round_state
            .prevotes
            .iter()
            .find(|p| p.validator() == signer)
        {
            if existing.checkpoint_id() == value {
                return Ok(existing.clone());
            }
            return Err(BftError::LockRetained {
                locked: hex::encode(existing.checkpoint_id()),
                requested: hex::encode(value),
            });
        }

        // N-9: the position in which this vote will be signed is durable before
        // the signature exists.
        self.ensure_position_durable(store)?;

        let unsigned = ConsensusVote {
            version: CONSENSUS_VOTE_VERSION,
            network: self.network,
            generation: self.generation,
            height: self.height,
            round: self.round,
            phase: VotePhase::Prevote,
            checkpoint_id: value,
            validator: signer,
            signature: [0u8; 64],
        };
        // BU: the authorisation re-runs `A4'` against this exact state, so the
        // primitive cannot be reached with a vote the rule refuses.
        let auth = crate::l2persist::VoteAuthorization::for_prevote(
            &self.persisted,
            &unsigned,
            proof,
            registry,
        )
        .map_err(|e| BftError::Rejected(e.to_string()))?;
        let outcome =
            crate::l2persist::sign_vote(&self.persisted, store, registry, &unsigned, &auth, sign)?;
        // BX (R-BX-4): audit summary, scoped to this height: the highest round
        // in which this node signed. It is never read as a safety input and is
        // re-derived from the slot records at restore.
        if outcome.vote.round.get() > self.persisted.highest_signed_round.get() {
            self.persisted.highest_signed_round = outcome.vote.round;
        }
        let prevote = Prevote::new(outcome.vote, self.set_root)?;
        // AW-LOCK-1 / AW-LOCK-3: a prevote never writes the lock.
        self.round_state.prevotes.push(prevote.clone());
        Ok(prevote)
    }

    /// Emit a precommit, which requires a valid prevote certificate for the same
    /// value, round, generation and validator set, **and** this node's own prevote
    /// of that value in that round (`AW-LOCK-8`, `A3-ord`).
    ///
    /// The lock is written here and nowhere else (`AW-LOCK-2`).
    pub fn precommit<F>(
        &mut self,
        prevote_certificate: &PrevoteCertificate,
        signer: ValidatorId,
        registry: &ValidatorRegistry,
        store: &dyn AtomicSlotStore,
        sign: F,
    ) -> Result<Precommit, BftError>
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        self.check_operational(registry)?;
        // Dependency 1: the certificate sits exactly in this position.
        prevote_certificate.require_context(&self.context(VotePhase::Prevote))?;
        // Dependency 2: it still verifies independently.
        prevote_certificate.re_verify(registry, self.network)?;
        // Dependency 3: same validator set.
        if prevote_certificate.set_root() != self.set_root {
            return Err(BftError::ContextMismatch { field: "set_root" });
        }
        let value = prevote_certificate.checkpoint_id();
        // AW-LOCK-8 (A3-ord): no precommit without this node's own prevote.
        self.require_own_prevote(value, signer)?;

        if let Some(existing) = self
            .round_state
            .precommits
            .iter()
            .find(|p| p.validator() == signer)
        {
            if existing.checkpoint_id() == value {
                return Ok(existing.clone());
            }
            return Err(BftError::LockRetained {
                locked: hex::encode(existing.checkpoint_id()),
                requested: hex::encode(value),
            });
        }

        let unsigned = ConsensusVote {
            version: CONSENSUS_VOTE_VERSION,
            network: self.network,
            generation: self.generation,
            height: self.height,
            round: self.round,
            phase: VotePhase::Precommit,
            checkpoint_id: value,
            validator: signer,
            signature: [0u8; 64],
        };
        // AW-LOCK-2: LOCK-UPD = UPD-NEW ∪ UPD-SAME, with the proof in hand.
        //
        // Written **before** the signature, not after. A crash must never leave a
        // durable precommit whose lock was not written: that node would restart
        // with `lockV = 0` and could prevote another value at the next round.
        // Locking first is strictly more conservative than the vote it announces,
        // which costs liveness at worst and never safety.
        let proof = ProofOfLock::from_prevote(prevote_certificate.clone());
        if let Err(error) = self.apply_lock_update(value, self.round, proof, store) {
            // A lock that did not become durable is a state this node must not
            // keep signing from.
            self.halt = Some(HaltReason::LockNotDurable {
                height: self.height,
                value,
            });
            self.block_signing_after_halt();
            let _ = self.persist_halt(store);
            return Err(error);
        }
        // N-9: now that the lock is durable and part of the state, record the
        // position that contains it before the signature exists. Doing this before
        // `apply_lock_update` would leave a position without the lock on disk and
        // a restart would (correctly) see a lost lock.
        self.ensure_position_durable(store)?;
        let own_prevote = self
            .round_state
            .prevotes
            .iter()
            .find(|p| p.validator() == signer)
            .map(|p| *p.vote())
            .ok_or(BftError::PrevoteRequired)?;
        // BU: `N-PC-1` and `AW-LOCK-8` are re-checked here, by the constructor
        // of the authorisation, so a precommit signature cannot exist without a
        // certified prevote of the same value in this round.
        let auth = crate::l2persist::VoteAuthorization::for_precommit(
            &self.persisted,
            &unsigned,
            prevote_certificate,
            &own_prevote,
            registry,
        )
        .map_err(|e| BftError::Rejected(e.to_string()))?;
        let outcome =
            crate::l2persist::sign_vote(&self.persisted, store, registry, &unsigned, &auth, sign)?;
        // BX (R-BX-4): same audit summary as in `prevote`.
        if outcome.vote.round.get() > self.persisted.highest_signed_round.get() {
            self.persisted.highest_signed_round = outcome.vote.round;
        }
        let precommit = Precommit::new(outcome.vote, self.set_root)?;
        self.round_state.precommits.push(precommit.clone());
        Ok(precommit)
    }

    /// Build a prevote certificate for `value` from the votes seen this round.
    pub fn certify_prevotes_for(
        &self,
        value: [u8; 32],
        registry: &ValidatorRegistry,
    ) -> Result<PrevoteCertificate, BftError> {
        let votes: Vec<ConsensusVote> = self
            .round_state
            .prevotes
            .iter()
            .filter(|p| p.checkpoint_id() == value)
            .map(|p| p.vote().clone())
            .collect();
        if votes.is_empty() {
            return Err(BftError::MissingDependency("no prevote for this value"));
        }
        let qc = QuorumCertificate::new(
            self.network,
            registry,
            self.height,
            self.round,
            VotePhase::Prevote,
            value,
            votes,
        );
        PrevoteCertificate::certify(qc, registry, self.network)
    }

    /// Build a precommit certificate for `value` from the votes seen this round.
    pub fn certify_precommits_for(
        &self,
        value: [u8; 32],
        registry: &ValidatorRegistry,
    ) -> Result<PrecommitCertificate, BftError> {
        let votes: Vec<ConsensusVote> = self
            .round_state
            .precommits
            .iter()
            .filter(|p| p.checkpoint_id() == value)
            .map(|p| p.vote().clone())
            .collect();
        if votes.is_empty() {
            return Err(BftError::MissingDependency("no precommit for this value"));
        }
        let qc = QuorumCertificate::new(
            self.network,
            registry,
            self.height,
            self.round,
            VotePhase::Precommit,
            value,
            votes,
        );
        PrecommitCertificate::certify(qc, registry, self.network)
    }

    /// Decide a height.
    ///
    /// Three independent checks, none of which subsumes the others:
    ///
    /// 1. the **precommit certificate** is quorate and sits in this position;
    /// 2. the **checkpoint record** validates on its own and chains to `parent`;
    /// 3. the **parent** is the checkpoint this node already finalised.
    ///
    /// A valid certificate over an invalid checkpoint decides nothing, and a valid
    /// checkpoint without a quorum certificate decides nothing either.
    pub fn finalize(
        &mut self,
        certificate: &PrecommitCertificate,
        checkpoint: &Checkpoint,
        parent: Option<&Checkpoint>,
        registry: &ValidatorRegistry,
        store: &dyn AtomicSlotStore,
    ) -> Result<FinalityDecision, BftError> {
        if let Some(halt) = &self.halt {
            return Err(BftError::Halted(halt.describe()));
        }
        // N-TRN-7 (BM N-6): a decided closure whose installation is still
        // missing blocks every decision above the closing height, even if the
        // old ledger would still accept a vote there.
        self.require_installation_clear_at(checkpoint.height)?;
        // Decisions are sequential: after `h`, the only decidable height is
        // `h + 1`. Together with the installation guard this forbids reaching
        // `h_close + 1` by skipping over an uninstalled closure.
        if let Some(last) = self.last_decided {
            let expected = last.get().saturating_add(1);
            if checkpoint.height.get() > expected {
                return Err(BftError::HeightNotSequential {
                    last: last.get(),
                    requested: checkpoint.height.get(),
                });
            }
        }
        // BC (`R-BB-1`): a checkpoint is decidable only if the generation that
        // would decide it is in force at that height. Checked against the
        // **checkpoint's own** generation, so a stale engine cannot decide for a
        // generation it no longer embodies.
        self.ledger
            .may_vote(checkpoint.generation, checkpoint.height)
            .map_err(|e| BftError::GenerationClosed(e.to_string()))?;
        // (1) certificate
        certificate.require_context(&self.context(VotePhase::Precommit))?;
        certificate.re_verify(registry, self.network)?;
        if certificate.checkpoint_id() != checkpoint.id() {
            return Err(BftError::ContextMismatch { field: "value" });
        }
        // (2) checkpoint record
        checkpoint
            .validate()
            .map_err(|e| BftError::CheckpointInvalid(e.to_string()))?;
        if checkpoint.generation != self.generation {
            return Err(BftError::ContextMismatch {
                field: "generation",
            });
        }
        if checkpoint.height != self.height {
            return Err(BftError::ContextMismatch { field: "height" });
        }
        if checkpoint.validator_set_root != self.set_root {
            return Err(BftError::ContextMismatch { field: "set_root" });
        }
        if checkpoint.height.get() > 0 {
            let parent = parent.ok_or(BftError::ParentNotFinalized(
                "no parent checkpoint supplied".to_string(),
            ))?;
            checkpoint
                .validate_link(parent)
                .map_err(|e| BftError::CheckpointInvalid(e.to_string()))?;
            // (3) lineage: the parent must be the decision this node took
            if let Some(previous) = &self.finality {
                if previous.height.get().saturating_add(1) == checkpoint.height.get()
                    && previous.checkpoint_id != parent.id()
                {
                    // BW: copy the id before the halt takes `&mut self`.
                    let previous_id = previous.checkpoint_id;
                    self.halt = Some(HaltReason::BrokenFinalityChain {
                        height: checkpoint.height,
                    });
                    self.block_signing_after_halt();
                    self.persist_halt(store)?;
                    return Err(BftError::ParentNotFinalized(format!(
                        "parent {} is not the finalised checkpoint {}",
                        hex::encode(parent.id()),
                        hex::encode(previous_id)
                    )));
                }
            }
        }

        // A durable decision already exists for this height?
        let key = finality_key(checkpoint.height);
        if let Some(bytes) = store.get(&key)? {
            let payload = open_sealed(&bytes)?;
            let stored = FinalityDecision::decode(payload)?;
            if stored.checkpoint_id != checkpoint.id() {
                self.halt = Some(HaltReason::ConflictingFinality {
                    height: checkpoint.height,
                    first: stored.checkpoint_id,
                    second: checkpoint.id(),
                });
                self.block_signing_after_halt();
                self.persist_halt(store)?;
                return Err(BftError::ConflictingFinality {
                    first: hex::encode(stored.checkpoint_id),
                    second: hex::encode(checkpoint.id()),
                });
            }
            self.finality = Some(stored);
            self.record_pending_install(checkpoint, store)?;
            self.last_decided = Some(checkpoint.height);
            return Ok(stored);
        }

        if let Some(existing) = self.finality {
            if existing.height == checkpoint.height {
                if existing.checkpoint_id != checkpoint.id() {
                    self.halt = Some(HaltReason::ConflictingFinality {
                        height: checkpoint.height,
                        first: existing.checkpoint_id,
                        second: checkpoint.id(),
                    });
                    self.block_signing_after_halt();
                    self.persist_halt(store)?;
                    return Err(BftError::ConflictingFinality {
                        first: hex::encode(existing.checkpoint_id),
                        second: hex::encode(checkpoint.id()),
                    });
                }
                self.record_pending_install(checkpoint, store)?;
                self.last_decided = Some(checkpoint.height);
                return Ok(existing);
            }
        }

        let verified = certificate.verified();
        let decision = FinalityDecision {
            version: FINALITY_FORMAT_VERSION,
            network: self.network,
            generation: self.generation,
            height: checkpoint.height,
            round: certificate.round(),
            checkpoint_id: checkpoint.id(),
            parent: checkpoint.parent,
            validator_set_root: self.set_root,
            registry_root: certificate.qc().registry_root,
            support: verified.support.get(),
            total: verified.total.get(),
            quorum: verified.quorum.get(),
            certificate_id: certificate.id(),
            transition_id: checkpoint.transition_id,
        };
        // The installation obligation is written **before** the decision so a
        // crash can never leave a final transition without a durable reason to
        // install its successor (N-6). A crash between the two records leaves an
        // obligation without a decision: the engine is blocked, never unsafe.
        self.record_pending_install(checkpoint, store)?;
        // Persist before reporting: a decision that cannot be re-read is not final.
        let sealed = seal(&decision.encode());
        if !store.cas(&key, None, &sealed)? {
            return Err(BftError::Rejected(
                "finality record changed concurrently".to_string(),
            ));
        }
        store.flush()?;
        self.finality = Some(decision);
        self.last_decided = Some(checkpoint.height);
        Ok(decision)
    }

    /// Enter the persistent HALT state from **verified** evidence (mission BF).
    ///
    /// This is the single controlled entry point for a halt that did not come from
    /// the engine's own checks. The caller must have verified a [`HaltProof`]
    /// first: this method does not authenticate anything by itself, and it is
    /// deliberately the only public way to set `halt` from outside.
    ///
    /// Rules, all structural:
    ///
    /// - an existing halt is **never replaced or cleared**: a second, different
    ///   proof cannot overwrite the first record, and no ordinary message can undo
    ///   it;
    /// - the record is written to the store and flushed, so a restart reloads it as
    ///   [`HaltReason::Persisted`];
    /// - if the write fails, the in-memory halt is kept anyway: the node stays
    ///   stopped rather than continuing with an unpersisted stop;
    /// - **BZ.5 (A2):** the returned `Result` is the durability verdict. A repeated
    ///   request is still a request: it re-runs the write and the read-back, so a
    ///   caller that retries after a failure is told whether the record is now
    ///   durable instead of receiving a silent `Ok(())`.
    pub fn halt_with(
        &mut self,
        reason: HaltReason,
        store: &dyn AtomicSlotStore,
    ) -> Result<(), BftError> {
        self.halt_in_memory(reason);
        // The first reason is kept; `persist_halt` refuses to replace a different
        // durable record and verifies what it wrote.
        self.persist_halt(store)
    }

    /// Enter the HALT state with no durable record.
    ///
    /// BZ.5 (A2): this is the explicit behaviour for a node that has no store to
    /// write to. The engine really stops — it refuses signatures and consensus
    /// work — but nothing survives a restart, so callers must not report this as
    /// durable. It never replaces an existing reason and never clears one.
    pub(crate) fn halt_in_memory(&mut self, reason: HaltReason) {
        if self.halt.is_none() {
            self.halt = Some(reason);
            self.block_signing_after_halt();
        }
    }

    /// Whether this engine refuses to sign.
    pub fn is_halted(&self) -> bool {
        self.halt.is_some()
    }

    /// Whether the durable halt record exists **and** matches this engine's halt.
    ///
    /// BZ.5 (A2): this is a read-back of the store, not an inference from
    /// [`Self::is_halted`]. `Ok(false)` means no matching record (absent, or a
    /// different record); an unreadable store is an error, never "not halted".
    pub fn halt_is_durable(&self, store: &dyn AtomicSlotStore) -> Result<bool, BftError> {
        let halt = match &self.halt {
            Some(halt) => halt,
            None => return Ok(false),
        };
        let expected = seal(&halt.describe().into_bytes());
        match store.get(HALT_KEY) {
            Ok(Some(bytes)) => Ok(bytes == expected),
            Ok(None) => Ok(false),
            Err(error) => Err(BftError::Rejected(format!(
                "halt record unreadable: {error}"
            ))),
        }
    }

    /// Make the in-memory safety state refuse signatures as well (BW, R-BV-2).
    ///
    /// The durable halt record is the primary gate — [`crate::l2persist::sign_vote`]
    /// reads it. This verdict covers the narrow case where the record could not
    /// be written, and makes an authorisation constructor refuse after a halt
    /// rather than issue a token that only the frontier would reject.
    fn block_signing_after_halt(&mut self) {
        if self.persisted.status.may_sign() {
            self.persisted.status = RecoveryStatus::RecoveryRequired(
                RecoveryReason::IncompleteState("engine halted".to_string()),
            );
        }
    }

    fn persist_halt(&self, store: &dyn AtomicSlotStore) -> Result<(), BftError> {
        if let Some(halt) = &self.halt {
            let bytes = halt.describe().into_bytes();
            let sealed = seal(&bytes);
            // BZ.5 (A2): the CAS verdict is no longer discarded. `false` means a
            // record is already present; that is acceptable only when it is the
            // same record this halt would write, never a silent overwrite.
            if !store.cas(HALT_KEY, None, &sealed)? {
                match store.get(HALT_KEY)? {
                    Some(existing) if existing == sealed => {}
                    Some(_) => {
                        return Err(BftError::Rejected(
                            "a different halt record is already durable".to_string(),
                        ))
                    }
                    None => {
                        return Err(BftError::Rejected(
                            "halt write was not accepted and no record is readable".to_string(),
                        ))
                    }
                }
            }
            store.flush()?;
            // BZ.5 (A2): durable means written, flushed and read back identical.
            match store.get(HALT_KEY)? {
                Some(written) if written == sealed => Ok(()),
                Some(_) => Err(BftError::Rejected(
                    "halt record read back differs from the record written".to_string(),
                )),
                None => Err(BftError::Rejected(
                    "halt record missing after the write".to_string(),
                )),
            }
        } else {
            Ok(())
        }
    }

    /// Offer a vote from the network to the engine.
    pub fn accept_vote(
        &mut self,
        vote: &ConsensusVote,
        registry: &ValidatorRegistry,
    ) -> VoteOutcome {
        if vote.network != self.network {
            return VoteOutcome::ForeignContext {
                field: "network",
                round: vote.round,
            };
        }
        if vote.generation != self.generation {
            return VoteOutcome::ForeignContext {
                field: "generation",
                round: vote.round,
            };
        }
        // BC: a vote from a generation that is closed at that height is foreign,
        // even if some other field made it look current.
        if self.ledger.may_vote(vote.generation, vote.height).is_err() {
            return VoteOutcome::ForeignContext {
                field: "generation",
                round: vote.round,
            };
        }
        if vote.height != self.height {
            return VoteOutcome::ForeignContext {
                field: "height",
                round: vote.round,
            };
        }
        if vote.round != self.round {
            return VoteOutcome::ForeignContext {
                field: "round",
                round: vote.round,
            };
        }
        // AT verifies the signature against the registry key, the generation and
        // the network; the weight comes from the registry.
        let weight = match vote.verify(registry, self.network) {
            Ok(verified) => verified.weight,
            Err(e) => {
                return VoteOutcome::Rejected {
                    reason: e.to_string(),
                }
            }
        };
        match vote.phase {
            VotePhase::Prevote => {
                if self
                    .round_state
                    .prevotes
                    .iter()
                    .any(|p| p.validator() == vote.validator)
                {
                    return VoteOutcome::Duplicate {
                        validator: vote.validator,
                    };
                }
                match Prevote::new(vote.clone(), self.set_root) {
                    Ok(prevote) => {
                        self.round_state.prevotes.push(prevote);
                        VoteOutcome::Accepted {
                            validator: vote.validator,
                            weight,
                        }
                    }
                    Err(e) => VoteOutcome::Rejected {
                        reason: e.to_string(),
                    },
                }
            }
            VotePhase::Precommit => {
                if self
                    .round_state
                    .precommits
                    .iter()
                    .any(|p| p.validator() == vote.validator)
                {
                    return VoteOutcome::Duplicate {
                        validator: vote.validator,
                    };
                }
                match Precommit::new(vote.clone(), self.set_root) {
                    Ok(precommit) => {
                        self.round_state.precommits.push(precommit);
                        VoteOutcome::Accepted {
                            validator: vote.validator,
                            weight,
                        }
                    }
                    Err(e) => VoteOutcome::Rejected {
                        reason: e.to_string(),
                    },
                }
            }
        }
    }

    /// Move to `round`, keeping the lock.
    ///
    /// The lock is deliberately **not** cleared: a round change is not evidence of
    /// anything about values. No proof of lock is consulted, because no normative
    /// rule authorizes using one.
    pub fn begin_round(&mut self, round: Round) -> Result<(), BftError> {
        self.may_sign()?;
        if round.get() <= self.round.get() {
            return Err(BftError::ContextMismatch { field: "round" });
        }
        self.round = round;
        let changes = std::mem::take(&mut self.round_state.round_changes);
        self.round_state = RoundState::new(round);
        self.round_state.round_changes = changes;
        Ok(())
    }

    /// Move to `height`, keeping the lock record and resetting the round.
    ///
    /// `R-LOCK-2` / `AW-LOCK-11`: the record is **not** erased. It becomes inert
    /// by scope (`R-LOCK-1`) — [`Self::active_lock`] ignores a record from another
    /// height — and is kept for audit and recovery. `N-CKPT-1` already forbids two
    /// values at one height, so an inert record constrains nothing.
    pub fn advance_height(
        &mut self,
        height: CheckpointHeight,
        store: &dyn CasStore,
    ) -> Result<(), BftError> {
        // BC: scoped to the **target** height, not to the current one.
        self.may_sign_at(height)?;
        if height.get() <= self.height.get() {
            return Err(BftError::ContextMismatch { field: "height" });
        }
        self.height = height;
        self.round = Round(0);
        self.round_state = RoundState::new(Round(0));
        self.finality = None;
        // BX (R-BX-4): the summary is scoped to one height; rounds restart at
        // zero, so keeping the old value would claim a round this height never
        // signed. The lock record stays (R-LOCK-2).
        self.persisted.highest_signed_round = Round(0);
        // R-LOCK-2: never erase a lock; its scope makes it inert.
        self.persisted.persist(store)?;
        Ok(())
    }

    /// Close the generation in force and install the next one (`R-TRANS-6`).
    ///
    /// This is the **only** path that changes [`Self::generation`]. It requires
    /// the closing checkpoint to be the one decided at this height by the current
    /// generation, applies the closure through the generation ledger
    /// (non-overlap, no skipped number, no contradictory closure), and persists
    /// the ledger **before** the engine's own state.
    ///
    /// The ordering is the safety argument: a crash after the ledger write leaves
    /// the new generation active and this node unable to sign at `h_close` —
    /// blocked, never unsafe. The opposite order would leave a closed generation
    /// free to sign at `h_close + 1`.
    pub fn close_generation(
        &mut self,
        closure: GenerationClosure,
        next_registry: &ValidatorRegistry,
        store: &dyn CasStore,
    ) -> Result<(), BftError> {
        if let Some(halt) = &self.halt {
            return Err(BftError::Halted(halt.describe()));
        }
        if closure.height != self.height {
            return Err(BftError::ContextMismatch { field: "height" });
        }
        if closure.generation != self.generation {
            return Err(BftError::ContextMismatch {
                field: "generation",
            });
        }
        if next_registry.generation() == self.generation {
            return Err(BftError::Rejected(
                "installation must move to another generation".to_string(),
            ));
        }
        // N-3: the registry that is installed must be the one the decided closure
        // describes. `set_root` binds (id, weight) and `candidate_id` binds the
        // transition position; neither is trusted from the caller. Checked before
        // the finality requirement so a malformed argument is never mistaken for a
        // state problem.
        if next_registry.set_root() != closure.new_set_root {
            return Err(BftError::Rejected(format!(
                "closure installs set root {} but the supplied registry has {}",
                hex::encode(closure.new_set_root),
                hex::encode(next_registry.set_root())
            )));
        }
        let expected_candidate = crate::consensus::transitions::candidate_id(
            closure.generation,
            closure.height,
            next_registry.set_root(),
            self.set_root,
        );
        if expected_candidate != closure.candidate_id {
            return Err(BftError::Rejected(
                "closure candidate id is not derived from its position and set root".to_string(),
            ));
        }
        // BO-F1 (mission BP): the identifier of the generation that becomes active
        // is **derived from the certified position**, not a free label. Two
        // derivations are admissible and nothing else:
        //
        //   1. the canonical one: the label *is* the transition id, so it is the
        //      exact value the quorum signed at `h_close` (`AdmittedSet::registry_for`);
        //   2. the legacy one: `generation_id_from(next_number, 0, set_root)`, the
        //      identity older nodes computed from the same position and set root.
        //      It is still a function of authenticated data, so it cannot be chosen,
        //      and it has no pin freedom (a non-zero pin is refused).
        //
        // A registry with the same members under any other label is refused: that
        // was defect BO-F1.
        let canonical = crate::consensus::generation::GenerationId(expected_candidate);
        let legacy = crate::consensus::roots::generation_id_from(
            self.ledger.active_number.saturating_add(1),
            0,
            next_registry.set_root(),
        );
        if next_registry.generation() != canonical && next_registry.generation() != legacy {
            return Err(BftError::Rejected(format!(
                "closure installs generation {} but its transition certifies {} (or {})",
                hex::encode(next_registry.generation().0),
                hex::encode(canonical.0),
                hex::encode(legacy.0)
            )));
        }
        let total = next_registry.total_voting_weight();
        let quorum = crate::consensus::generation::quorum_threshold(total);
        if total.get() == 0 || quorum.get() == 0 || quorum.get() > total.get() {
            return Err(BftError::Rejected(
                "the supplied registry has no usable quorum".to_string(),
            ));
        }
        // A proposal alone installs nothing: this node must have **decided** the
        // closing height, under the generation that closes. A crash after the
        // decision but before the installation is covered by the restored
        // finality record.
        let decided = self
            .finality
            .as_ref()
            .filter(|d| d.height == closure.height && d.generation == self.generation)
            .map(|d| d.checkpoint_id);
        if decided.is_none() {
            return Err(BftError::Rejected(
                "no checkpoint was decided at this height for the generation in force".to_string(),
            ));
        }
        let decided = decided.unwrap();
        // F1: the closure must carry the identifier of the decided checkpoint.
        if closure.value_id != decided {
            return Err(BftError::Rejected(
                "the closure does not carry the decided value".to_string(),
            ));
        }
        // N-6: a closure is installable only if its installation obligation was
        // created when it was decided. The obligation binds the exact decided
        // checkpoint (`value_id`) and candidate (`candidate_id`), so a caller
        // cannot install a different registry for the same position. A missing
        // obligation is not repaired here: this node must not decide by itself
        // that an installation was certified.
        let pending = match self.pending_installs.get(&closure.height).copied() {
            Some(pending) => pending,
            None => {
                return Err(BftError::Rejected(
                    "no certified pending installation exists at this height".to_string(),
                ))
            }
        };
        if pending.generation != closure.generation || pending.candidate_id != closure.candidate_id
        {
            return Err(BftError::Rejected(
                "the installation does not match the decided transition".to_string(),
            ));
        }
        // F1: the durable obligation must carry the same decided value.
        if pending.value_id != decided {
            self.block_recovery(RecoveryReason::IncompleteState(
                "the pending installation does not carry the decided value".to_string(),
            ));
            return Err(BftError::Rejected(
                "the pending installation does not carry the decided value".to_string(),
            ));
        }
        if pending.installed {
            return Err(BftError::Rejected(
                "this generation was already installed".to_string(),
            ));
        }
        let next_number = self.ledger.active_number.saturating_add(1);
        // Apply on a clone: a closure that halts the ledger must not leave a
        // half-applied record in the engine's own state.
        let mut next_ledger = self.ledger.clone();
        if let Err(error) =
            next_ledger.apply_closure(closure, next_registry.generation(), next_number)
        {
            // A ledger that refuses a closure is a state this node must not sign
            // from. The ledger is left exactly as found: no side is chosen.
            self.block_recovery(RecoveryReason::IncompleteState(error.to_string()));
            return Err(BftError::GenerationClosed(error.to_string()));
        }
        next_ledger
            .persist(store)
            .map_err(|e| BftError::Store(e.to_string()))?;
        // The ledger now proves the closure. Mark the obligation satisfied
        // **before** the engine adopts the new generation: a crash between the
        // two leaves a durable, certified installation and an engine restored
        // from the ledger (see `restore_engine`).
        if let Err(error) = self.mark_install_recorded(closure.height, next_registry, store) {
            self.block_recovery(RecoveryReason::IncompleteState(format!(
                "the certified installation at height {} could not be recorded: {error}",
                closure.height.get()
            )));
            return Err(error);
        }
        self.ledger = next_ledger;
        self.generation = next_registry.generation();
        self.set_root = next_registry.set_root();
        self.persisted.generation = next_registry.generation();
        self.persisted.persist(store)?;
        Ok(())
    }

    /// Record a round-change message, adopting the round once the (provisional)
    /// threshold is reached.
    ///
    /// Adoption is a progress decision; it never touches the lock and never
    /// authorizes a value.
    pub fn process_round_change(
        &mut self,
        change: RoundChange,
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<RoundChangeOutcome, BftError> {
        self.may_sign()?;
        if network != self.network {
            return Err(BftError::ContextMismatch { field: "network" });
        }
        change.verify(registry, network)?;
        if change.height != self.height {
            return Err(BftError::ContextMismatch { field: "height" });
        }
        if change.target_round.get() <= self.round.get() {
            return Ok(RoundChangeOutcome::Refused(format!(
                "target round {} is not ahead of current round {}",
                change.target_round.get(),
                self.round.get()
            )));
        }
        // N-7: a round change may not skip more than `MAX_ROUND_JUMP` rounds.
        // Adoption stays a progress decision; the bound only refuses a quorum
        // imposing an arbitrarily distant round.
        if change.target_round.get() - self.round.get() > MAX_ROUND_JUMP {
            return Ok(RoundChangeOutcome::Refused(format!(
                "target round {} jumps more than {} rounds ahead of {}",
                change.target_round.get(),
                MAX_ROUND_JUMP,
                self.round.get()
            )));
        }
        if self
            .round_state
            .round_changes
            .iter()
            .any(|c| c.validator == change.validator && c.target_round == change.target_round)
        {
            return Err(BftError::Rejected(
                "duplicate round change for this validator and round".to_string(),
            ));
        }
        self.round_state.round_changes.push(change.clone());

        let mut set = RoundChangeSet::new(self.height, change.target_round);
        for c in self
            .round_state
            .round_changes
            .iter()
            .filter(|c| c.target_round == change.target_round)
        {
            set.push(c.clone())?;
        }
        let evidence = set.verify(registry, network)?;
        if !evidence.is_sufficient() {
            return Ok(RoundChangeOutcome::Recorded {
                support: evidence.support,
                quorum: evidence.quorum,
            });
        }
        let from = self.round;
        self.begin_round(change.target_round)?;
        Ok(RoundChangeOutcome::Adopted {
            from,
            to: change.target_round,
            evidence: Box::new(evidence),
        })
    }

    /// Read-only view of the round-change evidence for a target round.
    pub fn round_change_evidence(
        &self,
        target_round: Round,
        registry: &ValidatorRegistry,
    ) -> Result<RoundChangeEvidence, BftError> {
        let mut set = RoundChangeSet::new(self.height, target_round);
        for c in self
            .round_state
            .round_changes
            .iter()
            .filter(|c| c.target_round == target_round)
        {
            set.push(c.clone())?;
        }
        set.verify(registry, self.network)
    }

    /// The current position, as a persistable record.
    ///
    /// Everything here comes from state the engine already holds: the round, the
    /// lock, the halt flag and AU's verdict. Nothing is inferred from a clock or
    /// from the record being written.
    pub fn position(&self) -> RoundPosition {
        let mut position = RoundPosition::fresh(self.network, self.generation, self.height);
        position.round = self.round;
        position.max_signed_round = self.round;
        position.lock = self.active_lock();
        position.halted = self.halt.is_some();
        position.recovery = self.persisted.status.clone();
        position
    }

    /// Persist the current round position (mission BI, priority 4).
    ///
    /// Loads the record first so the monotone rules apply across restarts: a round
    /// below the stored one, a dropped lock or a different value at the same height
    /// is refused and blocks signing. A refused write is never a warning: a
    /// position that cannot be recorded is a position the node must not act on.
    pub fn persist_position(&self, store: &dyn AtomicSlotStore) -> Result<RoundPosition, BftError> {
        let mut position = match RoundPosition::load(store) {
            Ok(Some(existing))
                if existing.height == self.height && existing.network == self.network =>
            {
                existing
            }
            Ok(_) => RoundPosition::fresh(self.network, self.generation, self.height),
            Err(error) => return Err(BftError::Store(error.to_string())),
        };
        position
            .observe_round(self.round)
            .map_err(|e| BftError::Store(e.to_string()))?;
        if self.persisted.highest_signed_round.get() > 0 {
            position
                .note_signature(self.persisted.highest_signed_round)
                .map_err(|e| BftError::Store(e.to_string()))?;
        }
        if let Some(lock) = self.active_lock() {
            // The safety state is authoritative: it has already written and
            // flushed this lock through `LOCK-UPD`. The position is a second
            // witness and follows it (N-9).
            position.record_authoritative_lock(lock);
        }
        if let Some(proof) = &self.persisted.proof_of_lock {
            position.pol = Some(crate::l2persist::round::PolSummary {
                round: proof.round,
                qc_id: proof.qc_id,
                checkpoint_id: proof.proposed.checkpoint_id,
                support: proof.support,
                total: proof.total,
            });
        }
        position.halted = self.halt.is_some();
        position.recovery = self.persisted.status.clone();
        position
            .persist(store)
            .map_err(|e| BftError::Store(e.to_string()))?;
        Ok(position)
    }

    /// Make the current position durable before a signature (mission BK, N-9).
    ///
    /// The rule "the round is durable before any signature in that round" is
    /// enforced here, in the engine, not left to the caller: every signing path
    /// calls this immediately before [`crate::l2persist::sign_vote`]. A position
    /// that cannot be written blocks recovery and the signature is never produced.
    ///
    /// Durability is `flush()` on the store, as everywhere in this crate; the
    /// backend must supply a `flush()` that survives a power cut (untested here).
    fn ensure_position_durable(&mut self, store: &dyn AtomicSlotStore) -> Result<(), BftError> {
        if let Err(error) = self.persist_position(store) {
            self.block_recovery(RecoveryReason::CorruptState(format!(
                "current round position could not be made durable: {error}"
            )));
            return Err(error);
        }
        store.flush()?;
        Ok(())
    }

    /// Adopt a round change and write the new position **before** returning.
    ///
    /// This is the durable-before-signature path: the record names the round the
    /// node is about to vote in, so a crash right after the adoption cannot make it
    /// look as if it never left round `r`. If the write fails, the engine blocks its
    /// own recovery and reports the failure; it does not adopt in memory only.
    pub fn process_round_change_persisted(
        &mut self,
        change: RoundChange,
        registry: &ValidatorRegistry,
        network: u64,
        store: &dyn AtomicSlotStore,
    ) -> Result<RoundChangeOutcome, BftError> {
        let from = self.round;
        let outcome = self.process_round_change(change, registry, network)?;
        if let RoundChangeOutcome::Adopted { to, evidence, .. } = &outcome {
            let summary = ChangeSummary {
                from_round: from,
                target_round: *to,
                support: evidence.support.get(),
                total: evidence.total.get(),
                quorum: evidence.quorum.get(),
                signers: evidence.signers.len() as u32,
            };
            let mut position = match RoundPosition::load(store) {
                Ok(Some(existing))
                    if existing.height == self.height && existing.network == self.network =>
                {
                    existing
                }
                Ok(_) => RoundPosition::fresh(self.network, self.generation, self.height),
                Err(error) => {
                    self.block_recovery(RecoveryReason::CorruptState(error.to_string()));
                    return Err(BftError::Store(error.to_string()));
                }
            };
            if let Err(error) = position.adopt(summary, self.active_lock()) {
                self.block_recovery(RecoveryReason::CorruptState(error.to_string()));
                return Err(BftError::Store(error.to_string()));
            }
            position.halted = self.halt.is_some();
            position.recovery = self.persisted.status.clone();
            if let Err(error) = position.persist(store) {
                self.block_recovery(RecoveryReason::CorruptState(error.to_string()));
                return Err(BftError::Store(error.to_string()));
            }
        }
        Ok(outcome)
    }

    /// Propose, but only if this validator is the elected proposer (mission BI).
    ///
    /// The rule lives in [`crate::l2bft::proposer`] and is a progress rule: a wrong
    /// proposer costs rounds, never safety. This entry point lets an operational
    /// driver enforce it; [`Self::propose`] keeps its old meaning for callers that
    /// run their own schedule, so nothing that already works changes.
    pub fn propose_as_proposer(
        &mut self,
        value: [u8; 32],
        registry: &ValidatorRegistry,
        me: ValidatorId,
    ) -> Result<(), BftError> {
        let elected = crate::l2bft::proposer::proposer_for(
            registry,
            self.generation,
            self.height,
            self.round,
        )
        .ok_or_else(|| {
            BftError::Rejected("no proposer schedule for this generation".to_string())
        })?;
        if elected.validator != me {
            return Err(BftError::NotProposer {
                round: self.round.get(),
                elected: hex::encode(elected.validator.0),
            });
        }
        self.propose(value)
    }

    /// Accept a proposal arriving from `sender` (mission BK, N-1).
    ///
    /// A proposal is receivable only if `sender` is the validator elected for
    /// `(generation, height, round)` by
    /// [`crate::l2bft::proposer::proposer_for`]. This is the entry point every
    /// network path must use; [`Self::propose`] stays available to in-process
    /// drivers that implement their own schedule, but it is not a boundary.
    pub fn accept_proposal(
        &mut self,
        value: [u8; 32],
        sender: ValidatorId,
        registry: &ValidatorRegistry,
    ) -> Result<(), BftError> {
        let elected = crate::l2bft::proposer::proposer_for(
            registry,
            self.generation,
            self.height,
            self.round,
        )
        .ok_or_else(|| {
            BftError::Rejected("no proposer schedule for this generation".to_string())
        })?;
        if elected.validator != sender {
            return Err(BftError::NotProposer {
                round: self.round.get(),
                elected: hex::encode(elected.validator.0),
            });
        }
        self.propose(value)
    }
}

/// Engine restored from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredEngine {
    /// Engine, with the recovery verdict already applied to `persisted.status`.
    pub state: BftState,
    /// Full recovery report from AU.
    pub report: RecoveryReport,
    /// Finality decisions read back, ordered by height.
    pub decisions: Vec<FinalityDecision>,
    /// Halt record, if a previous run stopped on a safety violation.
    pub halt: Option<HaltReason>,
}

/// Restore an engine from disk.
///
/// Reads the AU safety state (anchor, lock, status), every vote slot, every
/// finality decision and the halt record, then cross-checks the finality chain.
/// A single inconsistency leaves the engine in `RecoveryRequired`, which blocks
/// every signature.
/// Whether the durable installation mark proves this closure was installed as
/// the generation the ledger activates.
///
/// Used only by the restore path, to tell a **lagging** safety-state witness (a
/// node that installed a closure from a bundle and never rewrote its own state
/// record) from a **contradictory** one. Any doubt is a refusal: an absent,
/// unreadable or disagreeing mark is `false`.
fn installed_mark_agrees(
    store: &dyn AtomicSlotStore,
    ledger: &GenerationLedger,
    closure: &GenerationClosure,
) -> bool {
    let key = pending_install_key(closure.height);
    let Some(bytes) = store.get(&key).ok().flatten() else {
        return false;
    };
    let Some(payload) = open_sealed(&bytes).ok() else {
        return false;
    };
    let Ok(record) = PendingInstall::decode(payload) else {
        return false;
    };
    record.installed
        && record.height == closure.height
        && record.generation == closure.generation
        && record.candidate_id == closure.candidate_id
        && record.value_id == closure.value_id
        && record.installed_generation == ledger.active
        && record.installed_set_root == closure.new_set_root
}

pub fn restore_engine(
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    expected_anchor: Option<[u8; 32]>,
    network: u64,
    height: CheckpointHeight,
) -> RestoredEngine {
    let report = crate::l2persist::restore(store, expected_anchor, network);
    let mut state = BftState::new(network, registry, height, [0u8; 32]);
    let mut decisions: Vec<FinalityDecision> = Vec::new();
    let mut chain_error = None;
    // N-4: remember whether the canonical halt record exists, so a halt recovered
    // from the round position can be written back.
    let durable_halt = store.get(HALT_KEY).ok().flatten().is_some();

    if let Some(bytes) = store.get(HALT_KEY).ok().flatten() {
        let text = open_sealed(&bytes)
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_else(|e| format!("unreadable halt record: {e}"));
        // The engine does not re-derive the reason: a halt record means a human
        // must look, and the safest reading is the durable one.
        state.halt = Some(HaltReason::Persisted(text));
    }

    match store.scan(FINALITY_PREFIX) {
        Ok(records) => {
            for (_, bytes) in records {
                match open_sealed(&bytes).and_then(|p| {
                    FinalityDecision::decode(p)
                        .map_err(|e| crate::l2persist::SlotStoreError::Corrupt(e.to_string()))
                }) {
                    Ok(decision) => decisions.push(decision),
                    Err(e) => {
                        chain_error = Some(e.to_string());
                    }
                }
            }
            decisions.sort_by_key(|d| d.height.get());
            for pair in decisions.windows(2) {
                let (parent, child) = (&pair[0], &pair[1]);
                if child.height.get() == parent.height.get().saturating_add(1)
                    && child.parent != parent.checkpoint_id
                {
                    chain_error.get_or_insert_with(|| {
                        format!("finality chain broken at {}", child.height.get())
                    });
                }
            }
        }
        Err(e) => {
            chain_error.get_or_insert_with(|| e.to_string());
        }
    }

    if let Some(parent) = decisions.last() {
        state.finality = Some(*parent);
    }
    if let Some(anchor) = expected_anchor {
        state.persisted.anchor = anchor;
    }
    if let Some(reason) = &chain_error {
        state.persisted.status = RecoveryStatus::RecoveryRequired(
            crate::l2persist::RecoveryReason::CorruptState(reason.clone()),
        );
    } else {
        state.persisted.status = report.status.clone();
    }

    // BC (`R-BB-1`, requirement 7): recompute the active generation from the
    // verified ledger, never from a caller-supplied field. An unreadable ledger, a
    // registry that is not the generation in force, or a height restored below the
    // activation of that generation all block signing; none of them is repaired.
    // The safety state is a second witness: it records the generation that last
    // signed at this store. A ledger that disagrees with it, or an absent ledger
    // next to a state that knows another generation, blocks — a selectively
    // deleted ledger key must not look like "never transitioned".
    let stored_generation = report.state.as_ref().map(|s| s.generation);
    match GenerationLedger::load(store) {
        Ok(Some(ledger)) => {
            if let Some(known) = stored_generation {
                let lagging = known != ledger.active
                    && ledger.closures.last().map_or(false, |closure| {
                        known == closure.generation
                            && installed_mark_agrees(store, &ledger, closure)
                    });
                if !lagging {
                    if known != ledger.active {
                        state.block_recovery(RecoveryReason::CorruptState(format!(
                            "the safety state records generation {} but the ledger installs {}",
                            hex::encode(known.0),
                            hex::encode(ledger.active.0)
                        )));
                    }
                } else {
                    // BQ: a node that installed the closure from a peer's bundle
                    // kept its safety state at the *closing* generation. The
                    // ledger and the durable installation mark agree, so this is
                    // a lagging witness of the same installation, not a
                    // contradiction: the generation is derived, not repaired.
                    state.persisted.generation = ledger.active;
                }
            }
            if ledger.network != network {
                state.block_recovery(RecoveryReason::CorruptState(format!(
                    "generation ledger belongs to network {} (expected {network})",
                    ledger.network
                )));
            } else {
                if ledger.active != registry.generation() {
                    state.block_recovery(RecoveryReason::IncompleteState(format!(
                        "generation {} is not in force; the registry supplied is {}",
                        hex::encode(ledger.active.0),
                        hex::encode(registry.generation().0)
                    )));
                }
                if height.get() < ledger.first_height.get() {
                    state.block_recovery(RecoveryReason::IncompleteState(format!(
                        "height {} restored below the activation of the active generation at {}",
                        height.get(),
                        ledger.first_height.get()
                    )));
                }
                // BO-F1 (mission BP): the ledger activates the generation opened by
                // its last closure. That generation must *be* the transition the
                // closure carries; a ledger whose label was written beside the
                // transition is not a ledger this node may sign from.
                if let Some(last) = ledger.closures.last() {
                    let canonical = crate::consensus::generation::GenerationId(last.candidate_id);
                    // Legacy ledgers (pre-BP) label the generation by its position;
                    // that derivation is still accepted, anything else blocks.
                    let legacy = crate::consensus::roots::generation_id_from(
                        ledger.closures.len() as u64,
                        0,
                        last.new_set_root,
                    );
                    if ledger.active != canonical && ledger.active != legacy {
                        state.block_recovery(RecoveryReason::CorruptState(format!(
                            "the active generation is not derived from the transition that opened it at height {}",
                            last.height.get()
                        )));
                    }
                }
                state.generation = ledger.active;
                state.persisted.generation = ledger.active;
                state.ledger = ledger;
            }
        }
        Ok(None) => {
            if let Some(known) = stored_generation {
                if known != registry.generation() {
                    state.block_recovery(RecoveryReason::IncompleteState(format!(
                        "the safety state records generation {} but no transition ledger exists and the registry supplied is {}",
                        hex::encode(known.0),
                        hex::encode(registry.generation().0)
                    )));
                }
            }
        }
        Err(e) => state.block_recovery(RecoveryReason::CorruptState(format!(
            "generation ledger unreadable: {e}"
        ))),
    }

    // BM N-6: restore the installation obligations before anything can sign.
    // The durable record is the primary witness; the ledger closure is the
    // second one. A closure that exactly matches an obligation proves the
    // installation even if the process died before rewriting the marker. A
    // marker that claims an installation the ledger does not contain is a
    // corrupt state and blocks signing.
    if let Some(last) = decisions.last() {
        state.last_decided = Some(last.height);
    }
    match store.scan(PENDING_INSTALL_PREFIX) {
        Ok(records) => {
            for (_, bytes) in records {
                let decoded = open_sealed(&bytes).and_then(|payload| {
                    PendingInstall::decode(payload)
                        .map_err(|e| crate::l2persist::SlotStoreError::Corrupt(e.to_string()))
                });
                let mut record = match decoded {
                    Ok(record) => record,
                    Err(error) => {
                        state.block_recovery(RecoveryReason::CorruptState(format!(
                            "pending installation unreadable: {error}"
                        )));
                        continue;
                    }
                };
                if record.network != network {
                    state.block_recovery(RecoveryReason::CorruptState(format!(
                        "pending installation at height {} belongs to network {}",
                        record.height.get(),
                        record.network
                    )));
                    continue;
                }
                let closure = state
                    .ledger
                    .closures
                    .iter()
                    .find(|closure| {
                        closure.height == record.height
                            && closure.generation == record.generation
                            && closure.candidate_id == record.candidate_id
                    })
                    .copied();
                match closure {
                    Some(closure) => {
                        if !record.installed {
                            // The ledger write precedes the marker rewrite; the
                            // certified closure alone is enough to conclude that
                            // this exact installation happened.
                            record.installed = true;
                            record.installed_generation = GenerationId([0u8; 32]);
                            record.installed_set_root = closure.new_set_root;
                        }
                        if record.installed_set_root != closure.new_set_root {
                            state.block_recovery(RecoveryReason::CorruptState(format!(
                                "installed set root at height {} is not the one the ledger closed",
                                record.height.get()
                            )));
                        }
                        if state.ledger.closures.last().map(|last| last.height)
                            == Some(record.height)
                            && record.installed_generation.0 != [0u8; 32]
                            && record.installed_generation != state.ledger.active
                        {
                            state.block_recovery(RecoveryReason::CorruptState(format!(
                                "the marker installs generation {} but the ledger activates {}",
                                hex::encode(record.installed_generation.0),
                                hex::encode(state.ledger.active.0)
                            )));
                        }
                    }
                    None => {
                        if record.installed {
                            state.block_recovery(RecoveryReason::CorruptState(format!(
                                "height {} is marked installed but the ledger has no closure for it",
                                record.height.get()
                            )));
                        }
                    }
                }
                state.pending_installs.insert(record.height, record);
            }
        }
        Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
            "pending installations unreadable: {error}"
        ))),
    }

    // R-1 (mission BN): a **decided transition** is evidence of an installation
    // obligation even when no marker exists -- a record written by a binary that
    // predates `PendingInstall`, or a marker lost after the decision. The
    // obligation is derived from the decision itself, never from a claim:
    // `installed` stays false, so every signature and decision above `h_close` is
    // refused until `close_generation` installs exactly this closure against a
    // certified registry. Nothing is ever inferred as installed, and a legacy v1
    // record (no `transition_id`) cannot create a false obligation.
    for decision in &decisions {
        let Some(candidate) = decision.transition_id else {
            continue;
        };
        if state
            .ledger
            .closures
            .iter()
            .any(|closure| closure.height == decision.height)
        {
            continue;
        }
        if state.pending_installs.contains_key(&decision.height) {
            continue;
        }
        // BO-F2 (mission BP): the derived obligation is made **durable** here, so
        // a node that received only the decision can still complete the
        // installation after a restart. It is written once, compare-and-swap, and
        // never overwrites a different record: an inconsistency blocks instead of
        // being repaired silently.
        let derived = PendingInstall {
            version: PENDING_INSTALL_FORMAT_VERSION,
            network,
            height: decision.height,
            generation: decision.generation,
            candidate_id: candidate,
            value_id: decision.checkpoint_id,
            installed: false,
            installed_generation: GenerationId([0u8; 32]),
            installed_set_root: [0u8; 32],
        };
        let key = pending_install_key(decision.height);
        let same = |record: &PendingInstall| {
            record.height == derived.height
                && record.generation == derived.generation
                && record.candidate_id == derived.candidate_id
                && record.value_id == derived.value_id
        };
        match store.get(&key) {
            Ok(Some(bytes)) => {
                match open_sealed(&bytes).and_then(|payload| {
                    PendingInstall::decode(payload).map_err(|e| {
                        crate::l2persist::SlotStoreError::Corrupt(e.to_string())
                    })
                }) {
                    Ok(existing) if same(&existing) => {
                        state.pending_installs.insert(decision.height, existing);
                    }
                    Ok(_) => state.block_recovery(RecoveryReason::CorruptState(format!(
                        "a durable installation obligation at height {} belongs to another transition",
                        decision.height.get()
                    ))),
                    Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
                        "pending installation at height {} is unreadable: {error}",
                        decision.height.get()
                    ))),
                }
            }
            Ok(None) => match store.cas(&key, None, &seal(&derived.encode())) {
                Ok(true) => {
                    if let Err(error) = store.flush() {
                        state.block_recovery(RecoveryReason::CorruptState(format!(
                            "the derived installation obligation could not be flushed: {error}"
                        )));
                    }
                    state.pending_installs.insert(decision.height, derived);
                }
                Ok(false) => state.block_recovery(RecoveryReason::CorruptState(format!(
                    "the derived installation obligation at height {} changed concurrently",
                    decision.height.get()
                ))),
                Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
                    "the derived installation obligation could not be written: {error}"
                ))),
            },
            Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
                "the installation obligation at height {} could not be read: {error}",
                decision.height.get()
            ))),
        }
    }

    if let Some(existing) = &report.state {
        state.persisted.locked = existing.locked;
        state.persisted.proof_of_lock = existing.proof_of_lock.clone();
        state.persisted.last_valid_certificate = existing.last_valid_certificate;
        state.persisted.highest_signed_round = existing.highest_signed_round;
        // AW-LOCK-5: a state that relied on a provisional unlock is not a state
        // this engine may sign from. The flag is read so the audit can refuse it.
        state.persisted.unlock_rule_provisional = existing.unlock_rule_provisional;

        // AW-LOCK-11: restore the lock **with** the proof that justifies it, and
        // re-verify that proof from its bytes — never trust the disk. A missing or
        // foreign proof costs the ability to propose the locked value; it never
        // weakens the lock and never blocks voting for it.
        if let Some(lock) = state.persisted.locked {
            // Only an **in-scope** lock has its proof checked: an inert record from
            // another height is kept integrally (`R-LOCK-2`), proof included.
            let proof_ok = if lock.height != height {
                true
            } else {
                state
                    .persisted
                    .proof_of_lock
                    .as_ref()
                    .map(|stored| {
                        PrevoteCertificate::from_bytes(&stored.encoded_qc, registry, network)
                            .map(|cert| {
                                cert.round() == lock.round
                                    && cert.checkpoint_id() == lock.checkpoint_id
                                    && cert.height() == lock.height
                                    && cert.generation() == registry.generation()
                                    && cert.set_root() == registry.set_root()
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            };
            if !proof_ok {
                state.persisted.proof_of_lock = None;
                state.lock_proof_absent = true;
            }
            // R-LOCK-1: a height restored below the lock's scope is a rollback.
            if height.get() < lock.height.get()
                && !matches!(state.persisted.status, RecoveryStatus::RecoveryRequired(_))
            {
                state.persisted.status = RecoveryStatus::RecoveryRequired(
                    crate::l2persist::RecoveryReason::CorruptState(format!(
                        "height {} restored below lock height {}",
                        height.get(),
                        lock.height.get()
                    )),
                );
            }
        }
    }

    // BX (R-BX-4): `highest_signed_round` is an audit summary, never a safety
    // input, and its authority is the slot records rather than the persisted
    // field: the value is re-derived from the signed votes at the restored
    // height, so a stale, zero or forged field can neither claim a round the
    // store does not prove nor block a legitimate restart. A field that *does*
    // claim a higher round than any signed slot at this height means a vote
    // record was deleted; that blocks, because it is evidence, not absence.
    if !matches!(state.persisted.status, RecoveryStatus::RecoveryRequired(_)) {
        match store.scan_slots() {
            Ok(records) => {
                let derived = records
                    .iter()
                    .filter(|record| matches!(record.state, crate::l2persist::SlotState::Signed))
                    .filter_map(|record| record.vote.as_ref())
                    .filter(|vote| vote.height == height)
                    .map(|vote| vote.round)
                    .max_by_key(|round| round.get());
                let stored = state.persisted.highest_signed_round;
                let proven = derived.map_or(0, |round| round.get());
                if stored.get() > proven {
                    state.block_recovery(RecoveryReason::IncompleteState(format!(
                        "the state records a signature in round {} but no signed slot at height {} proves it",
                        stored.get(),
                        height.get()
                    )));
                }
                state.persisted.highest_signed_round = derived.unwrap_or(Round(0));
            }
            Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
                "the signed-round summary could not be re-derived: {error}"
            ))),
        }
    }

    // BI: the stored round position must agree with the safety state. It is a
    // summary, never a proof: a disagreement blocks signing instead of choosing a
    // side. A record for another height is inert, exactly like an out-of-scope lock.
    match RoundPosition::load(store) {
        Ok(Some(position)) => {
            // N-4: the position is a second durable witness of a halt. A halt is
            // never cleared by a restart, so it wins over an absent `HALT_KEY`.
            if position.halted && !state.is_halted() {
                state.halt = Some(HaltReason::Persisted(format!(
                    "round position for height {} records a halt",
                    position.height.get()
                )));
            }
            match position.verify_against(&state.persisted, height, network) {
                Ok(PositionVerdict::Current) => {
                    if let RecoveryStatus::RecoveryRequired(reason) = &position.recovery {
                        state.block_recovery(reason.clone());
                    }
                    if position.round > state.round {
                        state.round = position.round;
                    }
                }
                Ok(PositionVerdict::Stale { .. }) => {}
                Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
                    "round position disagrees with the safety state: {error}"
                ))),
            }
        }
        Ok(None) => {}
        Err(error) => state.block_recovery(RecoveryReason::CorruptState(format!(
            "round position unreadable: {error}"
        ))),
    }

    // N-4: if the halt came from the position, re-establish the canonical record so
    // the two sources agree. A failure leaves the node halted and blocks signing:
    // an unpersisted stop is still a stop, but it must not look clean.
    if state.is_halted() && !durable_halt {
        if let Err(error) = state.persist_halt(store) {
            state.block_recovery(RecoveryReason::CorruptState(format!(
                "halt recovered from the round position could not be re-persisted: {error}"
            )));
        }
    }

    // AW-LOCK-11(c): the lock is a summary, the precommit slots are the evidence.

    state.audit_own_precommit_evidence(store, registry);

    let halt = state.halt.clone();
    RestoredEngine {
        state,
        report,
        decisions,
        halt,
    }
}
