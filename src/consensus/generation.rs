//! L2 validator generations (A-06.6-AQ `N-GEN-*`, `N-CKPT-*`).
//!
//! A generation is a **frozen** `(members, weights)` set together with its
//! derived quorum. Weights are pinned at `epoch_pin` and never recomputed
//! while the generation is current (`N-GEN-2`), unlike the existing L1
//! per-vote derivation in `crate::stake`.
//!
//! # Scope of this module
//!
//! Types, invariants, lifecycle state machine and canonical encoding. It does
//! **not** decide transitions, verify votes, or produce certificates — those
//! are later lots.
//!
//! # No wall-clock input
//!
//! Nothing here reads the system clock. A generation is identified by an
//! explicit `epoch_pin` value supplied by the caller, and ordered by explicit
//! `number` / `CheckpointHeight` values. Two nodes replaying the same inputs
//! therefore agree bit for bit.

use std::fmt;

use thiserror::Error;

use crate::consensus::roots::{generation_id_from, validator_set_root};

/// Monotone generation counter.
pub type GenerationNumber = u64;

/// 32-byte identifier of a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatorId(pub [u8; 32]);

impl ValidatorId {
    /// All-zero id (never a valid member; used as a sentinel).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// True for the all-zero sentinel.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// 32-byte generation identifier (content-addressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenerationId(pub [u8; 32]);

impl GenerationId {
    /// All-zero sentinel.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// True for the all-zero sentinel.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for GenerationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Checkpoint height (a counter, never a timestamp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CheckpointHeight(pub u64);

impl CheckpointHeight {
    /// Genesis height.
    pub const GENESIS: Self = Self(0);

    /// Raw value.
    pub fn get(self) -> u64 {
        self.0
    }

    /// Next height (saturating: an overflowing chain is a bug, not a wrap).
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// `self - earlier`, saturating at 0. Used for freshness windows.
    pub fn since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// Intra-height consensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Round(pub u32);

impl Round {
    /// First round of a height.
    pub const ZERO: Self = Self(0);

    /// Raw value.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Next round (saturating).
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Voting weight (bonded amount pinned at `epoch_pin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ValidatorWeight(pub u64);

impl ValidatorWeight {
    /// Zero weight.
    pub const ZERO: Self = Self(0);

    /// Raw value.
    pub fn get(self) -> u64 {
        self.0
    }

    /// Saturating sum.
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Saturating difference.
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl fmt::Display for ValidatorWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generation lifecycle.
///
/// The first five states are **protocol-decidable** (they are established by
/// on-chain artefacts). The last three are **operational observations**: no
/// protocol artefact can prove `Live`, and `Degraded` / `Halted` are
/// indistinguishable from the protocol's point of view (A-06.6-AQ §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GenerationState {
    /// Proposed, below the READY quorum.
    Candidate,
    /// READY quorum reached (`w_READY >= q'`).
    Ready,
    /// The transition value has been decided.
    TransitionDecided,
    /// Applied locally by this node.
    Installed,
    /// First height of the new generation.
    Active,
    /// Operational observation: enough weight is online.
    Live,
    /// Operational observation: quorum weight is offline.
    Degraded,
    /// Operational observation: no return is possible.
    Halted,
}

impl GenerationState {
    /// Stable wire encoding.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Candidate => 0,
            Self::Ready => 1,
            Self::TransitionDecided => 2,
            Self::Installed => 3,
            Self::Active => 4,
            Self::Live => 5,
            Self::Degraded => 6,
            Self::Halted => 7,
        }
    }

    /// Strict inverse of [`Self::as_u8`]; unknown bytes are rejected.
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Candidate,
            1 => Self::Ready,
            2 => Self::TransitionDecided,
            3 => Self::Installed,
            4 => Self::Active,
            5 => Self::Live,
            6 => Self::Degraded,
            7 => Self::Halted,
            _ => return None,
        })
    }

    /// Whether this state is established by protocol artefacts alone.
    ///
    /// `Live`, `Degraded` and `Halted` are **not**: they depend on observed
    /// availability, which no on-chain artefact can certify.
    pub fn is_protocol_decidable(self) -> bool {
        matches!(
            self,
            Self::Candidate
                | Self::Ready
                | Self::TransitionDecided
                | Self::Installed
                | Self::Active
        )
    }

    /// Terminal states accept no further transition.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Halted)
    }

    /// Allowed transition table.
    ///
    /// Deliberately narrow:
    /// - `Candidate -> Ready -> TransitionDecided -> Installed -> Active`
    /// - `Active -> Live | Degraded`
    /// - `Live -> Degraded` (availability can be lost)
    /// - `Degraded -> Live` (availability can return)
    /// - `Degraded -> Halted` (one-way: `Halted` has no exit)
    ///
    /// `Candidate` cannot go directly to `Halted`: an abandoned candidate is
    /// simply abandoned, it was never a generation in force.
    pub fn can_transition_to(self, next: GenerationState) -> bool {
        use GenerationState::*;
        match (self, next) {
            (Candidate, Ready) => true,
            (Ready, TransitionDecided) => true,
            (TransitionDecided, Installed) => true,
            (Installed, Active) => true,
            (Active, Live) => true,
            (Active, Degraded) => true,
            (Live, Degraded) => true,
            (Degraded, Live) => true,
            (Degraded, Halted) => true,
            _ => false,
        }
    }
}

impl fmt::Display for GenerationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Candidate => "Candidate",
            Self::Ready => "Ready",
            Self::TransitionDecided => "TransitionDecided",
            Self::Installed => "Installed",
            Self::Active => "Active",
            Self::Live => "Live",
            Self::Degraded => "Degraded",
            Self::Halted => "Halted",
        };
        f.write_str(s)
    }
}

/// Encoding version of [`Generation`].
pub const GENERATION_ENCODING_VERSION: u8 = 1;

/// Fixed prefix length before the member list.
const GEN_HEADER_LEN: usize = 1 + 8 + 8 + 1 + 8 + 8 + 4;
/// Encoded size of one member: id (32) + weight (8).
const GEN_MEMBER_LEN: usize = 40;

/// Generation construction and decoding failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GenerationError {
    /// No validator in the set.
    #[error("validator set is empty")]
    EmptyValidatorSet,
    /// A member carries zero weight.
    #[error("validator {0} has zero weight")]
    ZeroWeight(ValidatorId),
    /// The same validator appears twice.
    #[error("duplicate validator {0}")]
    DuplicateValidator(ValidatorId),
    /// Sum of weights is zero.
    #[error("total weight is zero")]
    ZeroTotalWeight,
    /// Total weight overflowed `u64`.
    #[error("total weight overflow")]
    TotalWeightOverflow,
    /// Lifecycle transition not allowed by the table.
    #[error("invalid generation transition {from} -> {to}")]
    InvalidTransition {
        /// Current state.
        from: GenerationState,
        /// Requested state.
        to: GenerationState,
    },
    /// Encoded bytes are truncated or have trailing data.
    #[error("malformed generation encoding (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// Unknown encoding version.
    #[error("unsupported generation encoding version {0}")]
    UnsupportedVersion(u8),
    /// Unknown state byte.
    #[error("unknown generation state byte {0}")]
    UnknownState(u8),
    /// Members are not in canonical (strictly increasing id) order.
    #[error("members are not in canonical order")]
    NonCanonicalOrder,
    /// Total or quorum stored in the record disagrees with the recomputation.
    #[error("derived field mismatch (total/quorum)")]
    DerivedMismatch,
}

/// A frozen validator generation.
///
/// Invariants established by [`Generation::new`] and re-checked by
/// [`Generation::decode`]:
/// - non-empty member list;
/// - members sorted by id, strictly increasing (unique);
/// - every weight non-zero;
/// - `total_weight` = sum of weights, `quorum` = `⌈2·total/3⌉`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    number: GenerationNumber,
    epoch_pin: u64,
    members: Vec<(ValidatorId, ValidatorWeight)>,
    state: GenerationState,
    total_weight: ValidatorWeight,
    quorum: ValidatorWeight,
    set_root: [u8; 32],
    id: GenerationId,
}

impl Generation {
    /// Build a generation from `(id, weight)` pairs given in any order.
    ///
    /// The pairs are sorted canonically; duplicates and zero weights are
    /// rejected rather than silently normalised, so a caller cannot
    /// accidentally create two distinct generations from the same intent.
    pub fn new(
        number: GenerationNumber,
        epoch_pin: u64,
        members: &[(ValidatorId, ValidatorWeight)],
    ) -> Result<Self, GenerationError> {
        if members.is_empty() {
            return Err(GenerationError::EmptyValidatorSet);
        }
        let mut sorted: Vec<(ValidatorId, ValidatorWeight)> = members.to_vec();
        sorted.sort_by_key(|(id, _)| *id);
        for pair in sorted.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(GenerationError::DuplicateValidator(pair[0].0));
            }
        }
        for (id, weight) in &sorted {
            if weight.get() == 0 {
                return Err(GenerationError::ZeroWeight(*id));
            }
        }
        let mut total: u64 = 0;
        for (_, weight) in &sorted {
            total = total
                .checked_add(weight.get())
                .ok_or(GenerationError::TotalWeightOverflow)?;
        }
        if total == 0 {
            return Err(GenerationError::ZeroTotalWeight);
        }
        let total_weight = ValidatorWeight(total);
        let quorum = quorum_threshold(total_weight);
        let set_root = validator_set_root(&sorted);
        let id = generation_id_from(number, epoch_pin, set_root);
        Ok(Self {
            number,
            epoch_pin,
            members: sorted,
            state: GenerationState::Candidate,
            total_weight,
            quorum,
            set_root,
            id,
        })
    }

    /// Generation counter.
    pub fn number(&self) -> GenerationNumber {
        self.number
    }

    /// Epoch at which weights were pinned.
    pub fn epoch_pin(&self) -> u64 {
        self.epoch_pin
    }

    /// Canonical member list (sorted, unique).
    pub fn members(&self) -> &[(ValidatorId, ValidatorWeight)] {
        &self.members
    }

    /// Current lifecycle state.
    pub fn state(&self) -> GenerationState {
        self.state
    }

    /// Content-addressed identifier.
    pub fn id(&self) -> GenerationId {
        self.id
    }

    /// Sum of member weights.
    pub fn total_weight(&self) -> ValidatorWeight {
        self.total_weight
    }

    /// Quorum threshold `⌈2·total/3⌉`.
    pub fn quorum(&self) -> ValidatorWeight {
        self.quorum
    }

    /// Validator-set commitment.
    pub fn set_root(&self) -> [u8; 32] {
        self.set_root
    }

    /// Whether `id` is a member.
    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.members.binary_search_by_key(id, |(m, _)| *m).is_ok()
    }

    /// Pinned weight of `id`, if a member.
    pub fn weight_of(&self, id: &ValidatorId) -> Option<ValidatorWeight> {
        self.members
            .binary_search_by_key(id, |(m, _)| *m)
            .ok()
            .map(|i| self.members[i].1)
    }

    /// Advance the lifecycle, rejecting any transition outside the table.
    pub fn transition_to(&mut self, next: GenerationState) -> Result<(), GenerationError> {
        if !self.state.can_transition_to(next) {
            return Err(GenerationError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }

    /// Canonical encoding.
    ///
    /// Layout (little-endian, fixed width):
    /// `version(1) ‖ number(8) ‖ epoch_pin(8) ‖ state(1) ‖ total(8) ‖
    /// quorum(8) ‖ count(4) ‖ [id(32) ‖ weight(8)] × count`
    ///
    /// The identifier and the set root are **not** stored: they are derived,
    /// so they cannot disagree with the content.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GEN_HEADER_LEN + GEN_MEMBER_LEN * self.members.len());
        out.push(GENERATION_ENCODING_VERSION);
        out.extend_from_slice(&self.number.to_le_bytes());
        out.extend_from_slice(&self.epoch_pin.to_le_bytes());
        out.push(self.state.as_u8());
        out.extend_from_slice(&self.total_weight.get().to_le_bytes());
        out.extend_from_slice(&self.quorum.get().to_le_bytes());
        out.extend_from_slice(&(self.members.len() as u32).to_le_bytes());
        for (id, weight) in &self.members {
            out.extend_from_slice(&id.0);
            out.extend_from_slice(&weight.get().to_le_bytes());
        }
        out
    }

    /// Strict canonical decoding.
    ///
    /// Rejects: unknown version, unknown state byte, wrong length (truncated
    /// or trailing bytes), non-increasing member order, and derived fields
    /// that disagree with the recomputation.
    pub fn decode(bytes: &[u8]) -> Result<Self, GenerationError> {
        if bytes.len() < GEN_HEADER_LEN {
            return Err(GenerationError::MalformedEncoding {
                expected: GEN_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != GENERATION_ENCODING_VERSION {
            return Err(GenerationError::UnsupportedVersion(version));
        }
        let mut p = 1usize;
        let number = read_u64(bytes, &mut p);
        let epoch_pin = read_u64(bytes, &mut p);
        let state_byte = bytes[p];
        p += 1;
        let state = GenerationState::from_u8(state_byte)
            .ok_or(GenerationError::UnknownState(state_byte))?;
        let total_encoded = read_u64(bytes, &mut p);
        let quorum_encoded = read_u64(bytes, &mut p);
        let count = read_u32(bytes, &mut p) as usize;
        let expected = GEN_HEADER_LEN
            .checked_add(GEN_MEMBER_LEN.checked_mul(count).ok_or(
                GenerationError::MalformedEncoding {
                    expected: usize::MAX,
                    actual: bytes.len(),
                },
            )?)
            .ok_or(GenerationError::MalformedEncoding {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if bytes.len() != expected {
            return Err(GenerationError::MalformedEncoding {
                expected,
                actual: bytes.len(),
            });
        }
        let mut members: Vec<(ValidatorId, ValidatorWeight)> = Vec::with_capacity(count);
        for _ in 0..count {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes[p..p + 32]);
            p += 32;
            let weight = read_u64(bytes, &mut p);
            members.push((ValidatorId(id), ValidatorWeight(weight)));
        }
        for pair in members.windows(2) {
            if pair[0].0 >= pair[1].0 {
                return Err(GenerationError::NonCanonicalOrder);
            }
        }
        let mut decoded = Generation::new(number, epoch_pin, &members)?;
        if decoded.total_weight.get() != total_encoded || decoded.quorum.get() != quorum_encoded {
            return Err(GenerationError::DerivedMismatch);
        }
        decoded.state = state;
        Ok(decoded)
    }
}

fn read_u64(bytes: &[u8], p: &mut usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*p..*p + 8]);
    *p += 8;
    u64::from_le_bytes(buf)
}

fn read_u32(bytes: &[u8], p: &mut usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*p..*p + 4]);
    *p += 4;
    u32::from_le_bytes(buf)
}

/// Quorum threshold `⌈2·total/3⌉` computed exactly in `u128`.
pub fn quorum_threshold(total: ValidatorWeight) -> ValidatorWeight {
    let t = total.get() as u128;
    ValidatorWeight(((2 * t + 2) / 3) as u64)
}

/// Quorum predicate `3·support >= 2·total`.
///
/// Identical to `crate::stake::StakeRegistry::quorum_met`, so L2 and L1 agree
/// on what "quorate" means. `total == 0` never quorates.
pub fn quorum_met(support: ValidatorWeight, total: ValidatorWeight) -> bool {
    if total.get() == 0 {
        return false;
    }
    (support.get() as u128) * 3 >= (total.get() as u128) * 2
}

/// Liveness-margin parameters (`N-LIVE-3`, `N-GATE-7`).
///
/// `rho` is expressed as a fraction so no floating point enters consensus.
/// The **bound** `0 < rho < 1/3 − F/W` is normative; the **value** is an
/// operational setting, still undecided (A-06.6-AR `§1.2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarginParams {
    /// Numerator of `rho`.
    pub rho_num: u64,
    /// Denominator of `rho` (must be non-zero).
    pub rho_den: u64,
}

impl MarginParams {
    /// Build a margin configuration.
    pub const fn new(rho_num: u64, rho_den: u64) -> Self {
        Self { rho_num, rho_den }
    }

    /// A configuration usable only in tests and examples.
    ///
    /// **Not normative.** `rho = 1/6` is a working value, not a guarantee:
    /// the definitive value requires operational availability data that does
    /// not exist yet (A-06.6-AR `B-1` / `§1.2`).
    pub const fn non_normative_test_default() -> Self {
        Self {
            rho_num: 1,
            rho_den: 6,
        }
    }

    /// Whether the fraction is usable (`rho_den != 0`).
    pub fn is_valid(&self) -> bool {
        self.rho_den != 0
    }

    /// `sigma_min = max(1, ⌈rho·total⌉)`.
    ///
    /// The floor of 1 is normative (`N-LIVE-3`): a zero margin means a single
    /// honest absence can stall the generation. The floor removes that class
    /// of failure; it does **not** establish liveness.
    pub fn sigma_min(&self, total: ValidatorWeight) -> ValidatorWeight {
        if !self.is_valid() || total.get() == 0 {
            return ValidatorWeight(1);
        }
        let num = self.rho_num as u128 * total.get() as u128;
        let den = self.rho_den as u128;
        let ceil = ((num + den - 1) / den) as u64;
        ValidatorWeight(ceil.max(1))
    }

    /// `total − quorum`: the weight that may be offline before progress stops.
    pub fn liveness_budget(&self, total: ValidatorWeight) -> ValidatorWeight {
        total.saturating_sub(quorum_threshold(total))
    }

    /// `N-GATE-7`: `F + sigma_min <= total − quorum`.
    ///
    /// Returns `false` when the constraint cannot hold, which makes the
    /// candidate generation stillborn by construction rather than stalling
    /// later.
    pub fn admissibility_margin_ok(
        &self,
        total: ValidatorWeight,
        declared_byzantine: ValidatorWeight,
    ) -> bool {
        let budget = self.liveness_budget(total);
        let sigma = self.sigma_min(total);
        match declared_byzantine.get().checked_add(sigma.get()) {
            Some(need) => need <= budget.get(),
            None => false,
        }
    }
}
