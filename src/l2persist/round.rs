//! Persisted round position (mission BI, priority 4).
//!
//! # The gap this closes
//!
//! After BH, `BftState::round` lived only in memory. A restart always came back
//! at round 0 with a lock acquired at round 12 still in force: legal, but it
//! re-enters rounds the node has already voted in, and nothing on disk says what
//! round the node had reached. This module adds that record.
//!
//! # It is a *position*, not a proof
//!
//! > A stored round number is worth nothing on its own.
//!
//! The authoritative evidence for "what may I sign" stays where AU put it: the
//! flushed slot reservations, the lock and its re-verified proof. This record is a
//! summary that must **agree** with them; when it disagrees, the engine refuses to
//! sign rather than picking a side. [`RoundPosition::verify_against`] is that
//! check, and it is deliberately narrow: it compares the record with the safety
//! state — never the other way round.
//!
//! # What it stores
//!
//! | Field | Why |
//! |---|---|
//! | `network`, `generation`, `height` | the position it describes; a record for another height is inert, not merged |
//! | `round` | current round at that height, monotone |
//! | `max_signed_round` | highest round signed **at that height**; a record that lost it is corrupt |
//! | `lock` | a copy of the lock, so a silently vanished lock is detectable |
//! | `pol` | summary of the last proof of lock applied |
//! | `last_change` | last round change adopted, with its reconstituted weight |
//! | `halted` | whether the node was halted when the record was written |
//! | `recovery` | the AU verdict at that time; a blocked record keeps blocking |
//!
//! # What it cannot do
//!
//! - it does not fsync the device: `flush()` is an upper bound on what sled asks
//!   the OS to persist (same caveat as AU);
//! - it does not prove a round happened: a quorum's `RoundChange` messages are the
//!   evidence for that, and they are not stored here;
//! - it cannot repair a contradiction. Every disagreement is a reason not to
//!   sign, never a reason to rewrite the record.

use std::fmt;

use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, GenerationId, Round};
use crate::l2persist::slotlock::{open_sealed, seal, CasStore, SlotStoreError};
use crate::l2persist::state::{LockedValue, RecoveryReason, RecoveryStatus};

/// Version of the persisted round-position encoding.
///
/// Version 2 preserves the **class** of `RecoveryReason` (tag + payload) instead
/// of flattening it to `CorruptState(text)` (mission BK, N-8). Version 1 records
/// still decode: their single text field is read as `CorruptState`.
pub const ROUND_FORMAT_VERSION: u8 = 2;

/// The legacy encoding, read but never written.
pub const ROUND_FORMAT_VERSION_V1: u8 = 1;

/// Metadata key holding the single round-position record.
pub const ROUND_KEY: &str = "l2/v2/bft/round-position";

/// Summary of the last proof of lock the engine applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolSummary {
    /// Round of the certificate.
    pub round: Round,
    /// Certificate identifier.
    pub qc_id: [u8; 32],
    /// Value the certificate certifies.
    pub checkpoint_id: [u8; 32],
    /// Support weight reported by the certificate.
    pub support: u64,
    /// Total weight at that round.
    pub total: u64,
}

/// Summary of the round change that moved the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeSummary {
    /// Round left.
    pub from_round: Round,
    /// Round entered.
    pub target_round: Round,
    /// Weight that supported the adoption.
    pub support: u64,
    /// Total admissible weight.
    pub total: u64,
    /// Required threshold.
    pub quorum: u64,
    /// Number of distinct signers.
    pub signers: u32,
}

/// Why a round-position operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RoundError {
    /// The record cannot be decoded, or fails its seal.
    #[error("round position is unreadable: {0}")]
    Corrupt(String),

    /// A write was refused by the store.
    #[error("round position could not be written: {0}")]
    Store(String),

    /// The caller tried to move to an earlier round.
    #[error("round regression: stored {stored}, requested {requested}")]
    RoundRegression {
        /// Round already recorded.
        stored: u32,
        /// Round the caller asked for.
        requested: u32,
    },

    /// The lock would have been silently dropped.
    #[error("lock present on disk but absent from the update")]
    LockLost,

    /// Two records name different values for the same lock position.
    #[error("contradictory lock at height {height}: recorded {recorded}, state {state}")]
    ContradictoryLock {
        /// Height of the lock.
        height: u64,
        /// Identifier recorded in the position.
        recorded: String,
        /// Identifier held by the safety state.
        state: String,
    },

    /// The record describes a height the caller has already left behind.
    #[error("position is for height {recorded}, caller is at {requested}: a rollback")]
    Rollback {
        /// Height in the record.
        recorded: u64,
        /// Height supplied by the caller.
        requested: u64,
    },

    /// The record and the safety state disagree on the network.
    #[error("position belongs to network {recorded}, expected {expected}")]
    ForeignNetwork {
        /// Network in the record.
        recorded: u64,
        /// Network expected.
        expected: u64,
    },

    /// The record is for another generation at the same height.
    #[error("position names generation {recorded} at height {height}, state names {state}")]
    ForeignGeneration {
        /// Generation in the record.
        recorded: String,
        /// Generation in the state.
        state: String,
        /// Height both claim.
        height: u64,
    },
}

/// What a stored position means for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositionVerdict {
    /// The record describes the position being restored and agrees with the state.
    Current,
    /// The record is for an older height (or another generation): it is kept, but
    /// it says nothing about the position being restored.
    Stale {
        /// Why it was treated as inert.
        reason: String,
    },
}

/// The persisted round position of one validator at one height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundPosition {
    /// Encoding version.
    pub version: u8,
    /// Network.
    pub network: u64,
    /// Generation in force when written.
    pub generation: GenerationId,
    /// Height this position describes.
    pub height: CheckpointHeight,
    /// Current round.
    pub round: Round,
    /// Highest round signed at this height.
    pub max_signed_round: Round,
    /// Lock held, as recorded by the safety state.
    pub lock: Option<LockedValue>,
    /// Last proof of lock applied.
    pub pol: Option<PolSummary>,
    /// Last round change adopted.
    pub last_change: Option<ChangeSummary>,
    /// Whether the node was halted when this was written.
    pub halted: bool,
    /// AU verdict at the time.
    pub recovery: RecoveryStatus,
}

impl RoundPosition {
    /// A fresh position for `height`, at round 0, with a clean verdict.
    pub fn fresh(network: u64, generation: GenerationId, height: CheckpointHeight) -> Self {
        Self {
            version: ROUND_FORMAT_VERSION,
            network,
            generation,
            height,
            round: Round(0),
            max_signed_round: Round(0),
            lock: None,
            pol: None,
            last_change: None,
            halted: false,
            recovery: RecoveryStatus::Clean,
        }
    }

    /// Whether this record can be trusted to sign from.
    pub fn may_sign(&self) -> bool {
        self.recovery.may_sign()
    }

    /// Canonical encoding: fixed layout, little-endian integers, one tag byte per
    /// optional field.
    pub fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(160);
        out.push(ROUND_FORMAT_VERSION);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.round.get().to_le_bytes());
        out.extend_from_slice(&self.max_signed_round.get().to_le_bytes());
        out.push(u8::from(self.halted));
        match &self.lock {
            None => out.push(0),
            Some(lock) => {
                out.push(1);
                out.extend_from_slice(&lock.checkpoint_id);
                out.extend_from_slice(&lock.height.get().to_le_bytes());
                out.extend_from_slice(&lock.round.get().to_le_bytes());
            }
        }
        match &self.pol {
            None => out.push(0),
            Some(pol) => {
                out.push(1);
                out.extend_from_slice(&pol.round.get().to_le_bytes());
                out.extend_from_slice(&pol.qc_id);
                out.extend_from_slice(&pol.checkpoint_id);
                out.extend_from_slice(&pol.support.to_le_bytes());
                out.extend_from_slice(&pol.total.to_le_bytes());
            }
        }
        match &self.last_change {
            None => out.push(0),
            Some(change) => {
                out.push(1);
                out.extend_from_slice(&change.from_round.get().to_le_bytes());
                out.extend_from_slice(&change.target_round.get().to_le_bytes());
                out.extend_from_slice(&change.support.to_le_bytes());
                out.extend_from_slice(&change.total.to_le_bytes());
                out.extend_from_slice(&change.quorum.to_le_bytes());
                out.extend_from_slice(&change.signers.to_le_bytes());
            }
        }
        match &self.recovery {
            RecoveryStatus::Clean => out.push(0),
            RecoveryStatus::RecoveryRequired(reason) => {
                out.push(1);
                encode_reason(&mut out, reason);
            }
        }
        out
    }

    /// Decode a canonical encoding, refusing anything that is not one.
    pub fn decode(bytes: &[u8]) -> Result<Self, RoundError> {
        let mut cursor = Cursor::new(bytes);
        let version = cursor.u8()?;
        if version != ROUND_FORMAT_VERSION && version != ROUND_FORMAT_VERSION_V1 {
            return Err(RoundError::Corrupt(format!(
                "unsupported round-position version {version}"
            )));
        }
        let network = cursor.u64()?;
        let generation = GenerationId(cursor.array32()?);
        let height = CheckpointHeight(cursor.u64()?);
        let round = Round(cursor.u32()?);
        let max_signed_round = Round(cursor.u32()?);
        let halted = cursor.u8()? != 0;
        let lock = match cursor.u8()? {
            0 => None,
            1 => Some(LockedValue {
                checkpoint_id: cursor.array32()?,
                height: CheckpointHeight(cursor.u64()?),
                round: Round(cursor.u32()?),
            }),
            tag => {
                return Err(RoundError::Corrupt(format!(
                    "bad lock tag {tag} in round position"
                )))
            }
        };
        let pol = match cursor.u8()? {
            0 => None,
            1 => Some(PolSummary {
                round: Round(cursor.u32()?),
                qc_id: cursor.array32()?,
                checkpoint_id: cursor.array32()?,
                support: cursor.u64()?,
                total: cursor.u64()?,
            }),
            tag => {
                return Err(RoundError::Corrupt(format!(
                    "bad proof tag {tag} in round position"
                )))
            }
        };
        let last_change = match cursor.u8()? {
            0 => None,
            1 => Some(ChangeSummary {
                from_round: Round(cursor.u32()?),
                target_round: Round(cursor.u32()?),
                support: cursor.u64()?,
                total: cursor.u64()?,
                quorum: cursor.u64()?,
                signers: cursor.u32()?,
            }),
            tag => {
                return Err(RoundError::Corrupt(format!(
                    "bad change tag {tag} in round position"
                )))
            }
        };
        let recovery = match cursor.u8()? {
            0 => RecoveryStatus::Clean,
            1 => {
                let reason = if version == ROUND_FORMAT_VERSION_V1 {
                    // Legacy: one length-prefixed UTF-8 string, class lost.
                    let text = read_text(&mut cursor)?;
                    RecoveryReason::CorruptState(text)
                } else {
                    decode_reason(&mut cursor)?
                };
                RecoveryStatus::RecoveryRequired(reason)
            }
            tag => {
                return Err(RoundError::Corrupt(format!(
                    "bad recovery tag {tag} in round position"
                )))
            }
        };
        if !cursor.at_end() {
            return Err(RoundError::Corrupt(
                "trailing bytes after round position".into(),
            ));
        }
        Ok(Self {
            version: ROUND_FORMAT_VERSION,
            network,
            generation,
            height,
            round,
            max_signed_round,
            lock,
            pol,
            last_change,
            halted,
            recovery,
        })
    }

    /// Read the stored position, if any.
    ///
    /// An unreadable record is an error, never "no record": that distinction is
    /// the whole point of failing closed.
    pub fn load(store: &dyn CasStore) -> Result<Option<Self>, RoundError> {
        match store.get(ROUND_KEY) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                let plain = open_sealed(&bytes).map_err(|e| RoundError::Corrupt(e.to_string()))?;
                Self::decode(plain).map(Some)
            }
            Err(e) => Err(RoundError::Store(e.to_string())),
        }
    }

    /// Write the position, replacing the previous one atomically.
    pub fn persist(&self, store: &dyn CasStore) -> Result<(), RoundError> {
        let sealed = seal(&self.encode());
        let current = store
            .get(ROUND_KEY)
            .map_err(|e| RoundError::Store(e.to_string()))?;
        let swapped = store
            .cas(ROUND_KEY, current.as_deref(), &sealed)
            .map_err(|e| RoundError::Store(e.to_string()))?;
        if !swapped {
            return Err(RoundError::Store(
                "round position changed concurrently".into(),
            ));
        }
        // N-9: a position is durable only once the store has flushed it. Callers
        // that sign immediately afterwards rely on this barrier.
        store
            .flush()
            .map_err(|e| RoundError::Store(e.to_string()))?;
        Ok(())
    }

    /// Declare the current round, refusing to move backwards.
    pub fn observe_round(&mut self, round: Round) -> Result<(), RoundError> {
        if round.get() < self.round.get() {
            return Err(RoundError::RoundRegression {
                stored: self.round.get(),
                requested: round.get(),
            });
        }
        self.round = round;
        if self.max_signed_round.get() < round.get() {
            // A round that is current but unsigned is still a position the node
            // occupies; `max_signed_round` only moves when a signature happens.
        }
        Ok(())
    }

    /// Record that a vote was signed in `round`.
    ///
    /// Monotone, and it also moves the current round forward: a signature in round
    /// `r` proves the node was at `r`, whatever the record said before.
    pub fn note_signature(&mut self, round: Round) -> Result<(), RoundError> {
        if round.get() < self.max_signed_round.get() {
            return Err(RoundError::RoundRegression {
                stored: self.max_signed_round.get(),
                requested: round.get(),
            });
        }
        self.max_signed_round = round;
        if round.get() > self.round.get() {
            self.round = round;
        }
        Ok(())
    }

    /// Apply an adopted round change.
    ///
    /// Refuses a target that does not advance the round, and refuses to drop or
    /// change a lock: the lock on disk is the one the safety state holds.
    pub fn adopt(
        &mut self,
        change: ChangeSummary,
        lock: Option<LockedValue>,
    ) -> Result<(), RoundError> {
        if change.target_round.get() <= self.round.get() {
            return Err(RoundError::RoundRegression {
                stored: self.round.get(),
                requested: change.target_round.get(),
            });
        }
        self.set_lock_opt(lock)?;
        self.round = change.target_round;
        self.last_change = Some(change);
        Ok(())
    }

    /// Set the lock, refusing a silent loss or a different value at the same
    /// height.
    pub fn set_lock(&mut self, lock: LockedValue) -> Result<(), RoundError> {
        self.set_lock_opt(Some(lock))
    }

    /// Record the lock **the safety state already holds** (mission BK, N-9).
    ///
    /// This is not a proposal: the caller is the authoritative state, which has
    /// validated `UPD-NEW`/`UPD-SAME` and flushed before calling. A record that
    /// names another value at the same height is therefore a **stale witness**, not
    /// a contradiction, and is overwritten so the two views agree. Keeping
    /// [`Self::set_lock`] strict for round-change adoption is what prevents a
    /// `RoundChange` from moving a lock.
    pub fn record_authoritative_lock(&mut self, lock: LockedValue) {
        self.lock = Some(lock);
    }

    fn set_lock_opt(&mut self, lock: Option<LockedValue>) -> Result<(), RoundError> {
        match (self.lock, lock) {
            (Some(_existing), None) => Err(RoundError::LockLost),
            (Some(existing), Some(incoming)) => {
                if existing.checkpoint_id != incoming.checkpoint_id
                    && existing.height == incoming.height
                {
                    return Err(RoundError::ContradictoryLock {
                        height: existing.height.get(),
                        recorded: hex::encode(existing.checkpoint_id),
                        state: hex::encode(incoming.checkpoint_id),
                    });
                }
                // A lock for a later height replaces an inert one: it describes a
                // different position, not a contradiction.
                self.lock = Some(incoming);
                Ok(())
            }
            (None, Some(incoming)) => {
                self.lock = Some(incoming);
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }

    /// Compare this record with the safety state that will be used to sign.
    ///
    /// The comparison is one-way on purpose: the safety state is authoritative,
    /// and the record only has to be *compatible* with it. Any incompatibility is
    /// an error the caller must turn into "do not sign".
    pub fn verify_against(
        &self,
        state: &crate::l2persist::state::PersistentConsensusState,
        height: CheckpointHeight,
        network: u64,
    ) -> Result<PositionVerdict, RoundError> {
        if self.network != network {
            return Err(RoundError::ForeignNetwork {
                recorded: self.network,
                expected: network,
            });
        }
        if self.height.get() > height.get() {
            return Err(RoundError::Rollback {
                recorded: self.height.get(),
                requested: height.get(),
            });
        }
        if self.height.get() < height.get() {
            return Ok(PositionVerdict::Stale {
                reason: format!(
                    "record is for height {}, restoring {}",
                    self.height.get(),
                    height.get()
                ),
            });
        }
        if self.generation != state.generation {
            return Err(RoundError::ForeignGeneration {
                recorded: hex::encode(self.generation.0),
                state: hex::encode(state.generation.0),
                height: self.height.get(),
            });
        }
        if self.max_signed_round.get() > self.round.get() {
            // A signature in a round this node has already left is impossible in a
            // coherent record: `note_signature` moves the current round with it.
            return Err(RoundError::Corrupt(format!(
                "highest signed round {} is ahead of the current round {}",
                self.max_signed_round.get(),
                self.round.get()
            )));
        }
        match (self.lock, state.locked) {
            (None, Some(_found)) => {
                return Err(RoundError::LockLost);
            }
            (Some(recorded), Some(found)) => {
                if recorded.checkpoint_id != found.checkpoint_id {
                    return Err(RoundError::ContradictoryLock {
                        height: recorded.height.get(),
                        recorded: hex::encode(recorded.checkpoint_id),
                        state: hex::encode(found.checkpoint_id),
                    });
                }
                if self.round.get() < recorded.round.get() {
                    return Err(RoundError::Corrupt(format!(
                        "current round {} is below the lock round {}",
                        self.round.get(),
                        recorded.round.get()
                    )));
                }
            }
            (Some(recorded), None) if recorded.height == height => {
                // The record claims a lock the safety state does not have. That is
                // the exact shape of a lost lock: refuse, and let the engine's own
                // slot audit decide which side is right.
                return Err(RoundError::ContradictoryLock {
                    height: recorded.height.get(),
                    recorded: hex::encode(recorded.checkpoint_id),
                    state: "none".to_string(),
                });
            }
            _ => {}
        }
        Ok(PositionVerdict::Current)
    }
}

/// Encode a `RecoveryReason` with its class (N-8), not as a flattened string.
///
/// Tags are part of the persisted format: `1` corrupt, `2` missing anchor,
/// `3` foreign anchor, `4` incoherent slot, `5` contradictory lock, `6`
/// incomplete state. A new variant needs a new tag and a format version bump.
fn encode_reason(out: &mut Vec<u8>, reason: &RecoveryReason) {
    match reason {
        RecoveryReason::CorruptState(text) => {
            out.push(1);
            push_text(out, text);
        }
        RecoveryReason::MissingAnchor => out.push(2),
        RecoveryReason::ForeignAnchor { expected, found } => {
            out.push(3);
            out.extend_from_slice(expected);
            out.extend_from_slice(found);
        }
        RecoveryReason::IncoherentSlot(text) => {
            out.push(4);
            push_text(out, text);
        }
        RecoveryReason::ContradictoryLock(text) => {
            out.push(5);
            push_text(out, text);
        }
        RecoveryReason::IncompleteState(text) => {
            out.push(6);
            push_text(out, text);
        }
    }
}

/// Length-prefixed UTF-8, truncated on a character boundary if it exceeds `u16`.
fn push_text(out: &mut Vec<u8>, text: &str) {
    let mut text = text;
    if text.len() > u16::MAX as usize {
        let mut cut = u16::MAX as usize;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text = &text[..cut];
    }
    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
}

fn read_text(cursor: &mut Cursor<'_>) -> Result<String, RoundError> {
    let len = cursor.u16()? as usize;
    let bytes = cursor.bytes(len)?;
    String::from_utf8(bytes.to_vec())
        .map_err(|_| RoundError::Corrupt("recovery reason is not UTF-8".into()))
}

fn decode_reason(cursor: &mut Cursor<'_>) -> Result<RecoveryReason, RoundError> {
    match cursor.u8()? {
        1 => Ok(RecoveryReason::CorruptState(read_text(cursor)?)),
        2 => Ok(RecoveryReason::MissingAnchor),
        3 => Ok(RecoveryReason::ForeignAnchor {
            expected: cursor.array32()?,
            found: cursor.array32()?,
        }),
        4 => Ok(RecoveryReason::IncoherentSlot(read_text(cursor)?)),
        5 => Ok(RecoveryReason::ContradictoryLock(read_text(cursor)?)),
        6 => Ok(RecoveryReason::IncompleteState(read_text(cursor)?)),
        tag => Err(RoundError::Corrupt(format!(
            "bad recovery reason tag {tag} in round position"
        ))),
    }
}

impl fmt::Display for PositionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::Stale { reason } => write!(f, "stale: {reason}"),
        }
    }
}

/// Bounded reader; every field access checks the length.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], RoundError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| RoundError::Corrupt("round position length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(RoundError::Corrupt("round position is truncated".into()));
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, RoundError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RoundError> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.bytes(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, RoundError> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.bytes(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, RoundError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    fn array32(&mut self) -> Result<[u8; 32], RoundError> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.bytes(32)?);
        Ok(out)
    }

    fn at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Convenience: a `SlotStoreError` is a store failure, not a corrupt record.
impl From<SlotStoreError> for RoundError {
    fn from(error: SlotStoreError) -> Self {
        RoundError::Store(error.to_string())
    }
}
