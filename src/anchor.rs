//! PHASE 4P: V6 anchor verification (4O design implementation).
//!
//! ADDITIVE-ONLY module: no existing consensus path calls into it, and it
//! changes no rule (quorum, stake, slash, finality, era gating, wire).
//! A V6 anchor binds a finality (conflict key + winner + quorum votes) to
//! the epoch, the validator-set commitment, and the recomputed denominator
//! (4O sec.6-9). Verification is offline and pure: same inputs always give
//! the same verdict, independent of wall-clock, era, or arrival order.
//! V6 stays dormant: nothing in production invokes this module yet.

use crate::stake::{
    ConflictKey, StakeRegistry, ValidatorRecord, ValidatorState, BOND_MATURATION_EPOCHS,
    EPOCH_GRACE,
};
use crate::transaction::{Vote, VoteId};

/// Anchor format version (single byte prefix of every canonical encoding in
/// this module; unknown versions MUST be rejected, never reinterpreted).
pub const ANCHOR_FORMAT_VERSION: u8 = 1;

/// Genesis previous-anchor value (first anchor chains to release).
pub const ANCHOR_GENESIS_PREV: [u8; 32] = [0u8; 32];

/// Minimal V6 anchor (4O sec.6). `supporting` MUST equal the sorted ids of
/// `votes`; `claimed_total` MUST equal the recomputed eligible total;
/// `set_root` MUST equal the recomputed set commitment at `epoch`.
/// `state_root` is RESERVED (None until a ledger state-hash exists).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6Anchor {
    pub epoch: u64,
    pub key: ConflictKey,
    pub winner: [u8; 32],
    pub members: Vec<[u8; 32]>,
    pub votes: Vec<Vote>,
    pub supporting: Vec<VoteId>,
    pub claimed_total: u64,
    pub set_root: [u8; 32],
    pub prev: [u8; 32],
    pub state_root: Option<[u8; 32]>,
}

/// Verified-anchor summary (inputs for equivalence checks against the
/// consensus decision on the same dataset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSummary {
    pub support: u64,
    pub total: u64,
    pub winner: [u8; 32],
    pub vote_count: usize,
}

/// Anchor rejection reasons, one per binding (fail-closed: the first
/// failing check aborts verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorError {
    UnknownVersion(u8),
    StateRootPresent,
    AnchorIdMismatch,
    EmptyVotes,
    IdSetMismatch,
    BadSignature(usize),
    WrongKey(usize),
    OutsideClosure(usize),
    DuplicateValidator([u8; 32]),
    VoteEpochOutsideWindow { index: usize, vote_epoch: u64 },
    UnknownValidator([u8; 32]),
    IneligibleValidator([u8; 32]),
    StakeAmountMismatch { validator: [u8; 32], claimed: u64, committed: u64 },
    SetRootMismatch,
    DenominatorMismatch { claimed: u64, recomputed: u64 },
    QuorumNotReached { support: u64, total: u64 },
    WinnerNotMember,
}

/// Canonical per-validator record encoding (4O sec.7), fixed sizes:
/// address(32) || bonded_amount(le64) || state_tag(1) || release_or_zero(le64)
/// || bonded_epoch(le64) || slashed_tag(1) || slashed_epoch_or_zero(le64).
fn canonical_validator_record(rec: &ValidatorRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 8 + 1 + 8 + 8 + 1 + 8);
    out.extend_from_slice(&rec.address);
    out.extend_from_slice(&rec.bonded_amount.to_le_bytes());
    match rec.state {
        ValidatorState::Bonded => {
            out.push(0u8);
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        ValidatorState::Unbonding { release_epoch } => {
            out.push(1u8);
            out.extend_from_slice(&release_epoch.to_le_bytes());
        }
        ValidatorState::Unbonded => {
            out.push(2u8);
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        ValidatorState::Slashed => {
            out.push(3u8);
            out.extend_from_slice(&0u64.to_le_bytes());
        }
    }
    out.extend_from_slice(&rec.bonded_epoch.to_le_bytes());
    match rec.slashed_epoch {
        None => {
            out.push(0u8);
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        Some(e) => {
            out.push(1u8);
            out.extend_from_slice(&e.to_le_bytes());
        }
    }
    out
}

/// Canonical validator-set bytes at `epoch`: version(1) || epoch(le64) ||
/// per-record encodings sorted by address. Epoch is inside the commitment
/// (4O sec.9): the same set at another epoch commits differently.
pub fn canonical_set_bytes(records: &[ValidatorRecord], epoch: u64) -> Vec<u8> {
    let mut sorted: Vec<&ValidatorRecord> = records.iter().collect();
    sorted.sort_by(|a, b| a.address.cmp(&b.address));
    let mut out = Vec::with_capacity(1 + 8 + sorted.len() * 66);
    out.push(ANCHOR_FORMAT_VERSION);
    out.extend_from_slice(&epoch.to_le_bytes());
    for rec in sorted {
        out.extend_from_slice(&canonical_validator_record(rec));
    }
    out
}

/// Eligibility used by anchor verification. Normative rule is
/// StakeRegistry::is_eligible (Bonded matured); this mirrors it exactly so
/// verification needs no registry. A dedicated test asserts agreement on
/// every lifecycle state (drift would fail it loudly).
fn anchor_eligible(rec: &ValidatorRecord, at_epoch: u64) -> (bool, u64) {
    if rec.state != ValidatorState::Bonded {
        return (false, 0);
    }
    if rec.bonded_epoch.saturating_add(BOND_MATURATION_EPOCHS) > at_epoch {
        return (false, 0);
    }
    (true, rec.bonded_amount)
}

/// Set commitment + recomputed eligible total at `epoch` (4O sec.7-8).
/// Returns (set_root, eligible_total).
pub fn validator_set_root(records: &[ValidatorRecord], epoch: u64) -> ([u8; 32], u64) {
    let bytes = canonical_set_bytes(records, epoch);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes);
    let root: [u8; 32] = hasher.finalize().into();
    let mut total = 0u64;
    for rec in records {
        let (ok, w) = anchor_eligible(rec, epoch);
        if ok {
            total = total.saturating_add(w);
        }
    }
    (root, total)
}

/// Bundle integrity tag (4O sec.10): BLAKE3 over canonical fields. Covers
/// every bundle field (sorted members, sorted vote ids, totals, roots,
/// chain, state tag), so any modification invalidates the tag. Vote bytes
/// are covered via their content-addressed ids (id = hash of canonical
/// encoding including signature).
pub fn anchor_id(anchor: &V6Anchor) -> [u8; 32] {
    let mut members = anchor.members.clone();
    members.sort();
    let mut ids: Vec<VoteId> = anchor.votes.iter().map(|v| v.id()).collect();
    ids.sort();
    let mut preimage = Vec::new();
    preimage.push(ANCHOR_FORMAT_VERSION);
    preimage.extend_from_slice(&anchor.epoch.to_le_bytes());
    preimage.extend_from_slice(&anchor.key.0);
    preimage.extend_from_slice(&anchor.key.1.to_le_bytes());
    preimage.extend_from_slice(&anchor.winner);
    for m in &members {
        preimage.extend_from_slice(m);
    }
    for id in &ids {
        preimage.extend_from_slice(id);
    }
    preimage.extend_from_slice(&anchor.claimed_total.to_le_bytes());
    preimage.extend_from_slice(&anchor.set_root);
    preimage.extend_from_slice(&anchor.prev);
    match anchor.state_root {
        None => preimage.push(0u8),
        Some(h) => {
            preimage.push(1u8);
            preimage.extend_from_slice(&h);
        }
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&preimage);
    hasher.finalize().into()
}

/// Build an anchor over explicit inputs (used by tests and, later, by
/// checkpoint tooling; NOT called by any consensus path).
pub fn build_anchor(
    epoch: u64,
    key: ConflictKey,
    winner: [u8; 32],
    members: Vec<[u8; 32]>,
    votes: Vec<Vote>,
    set: &[ValidatorRecord],
    prev: [u8; 32],
) -> V6Anchor {
    let (set_root, total) = validator_set_root(set, epoch);
    let mut supporting: Vec<VoteId> = votes.iter().map(|v| v.id()).collect();
    supporting.sort();
    V6Anchor {
        epoch,
        key,
        winner,
        members,
        votes,
        supporting,
        claimed_total: total,
        set_root,
        prev,
        state_root: None,
    }
}

/// Verify an anchor against an explicitly provided validator set (4O
/// sec.7-9). Pure function: no clock, no registry, no network. Every
/// binding failure returns its specific error (fail-closed on first
/// failure); success returns the recomputed summary.
pub fn verify_anchor<F>(
    anchor: &V6Anchor,
    set: &[ValidatorRecord],
    expected_id: [u8; 32],
    is_strict_descendant: F,
) -> Result<AnchorSummary, AnchorError>
where
    F: Fn(&[u8; 32], &[u8; 32]) -> bool,
{
    // 0. Bundle integrity first: any tampering invalidates the tag.
    if anchor_id(anchor) != expected_id {
        return Err(AnchorError::AnchorIdMismatch);
    }
    // State root reserved: this version anchors decision + set only.
    if anchor.state_root.is_some() {
        return Err(AnchorError::StateRootPresent);
    }
    if anchor.votes.is_empty() {
        return Err(AnchorError::EmptyVotes);
    }
    // 1. Pinned id set must equal the carried votes (order normalized).
    let mut ids: Vec<VoteId> = anchor.votes.iter().map(|v| v.id()).collect();
    ids.sort();
    let mut pinned = anchor.supporting.clone();
    pinned.sort();
    if ids != pinned {
        return Err(AnchorError::IdSetMismatch);
    }
    // 2. Commit the provided set at the anchor epoch (epoch inside).
    let (root, total) = validator_set_root(set, anchor.epoch);
    if root != anchor.set_root {
        return Err(AnchorError::SetRootMismatch);
    }
    if total != anchor.claimed_total {
        return Err(AnchorError::DenominatorMismatch {
            claimed: anchor.claimed_total,
            recomputed: total,
        });
    }
    // 3. Winner must be a known member (members advisory context only).
    if !anchor.members.contains(&anchor.winner) {
        return Err(AnchorError::WinnerNotMember);
    }
    // 4. Per-vote checks against the committed set.
    let mut by_validator: Vec<([u8; 32], u64)> = Vec::with_capacity(anchor.votes.len());
    for (i, v) in anchor.votes.iter().enumerate() {
        if !v.verify_signature() {
            return Err(AnchorError::BadSignature(i));
        }
        if (v.conflict_sender, v.conflict_nonce) != anchor.key {
            return Err(AnchorError::WrongKey(i));
        }
        if v.side != anchor.winner && !is_strict_descendant(&anchor.winner, &v.side) {
            return Err(AnchorError::OutsideClosure(i));
        }
        // Epoch binding (4O sec.9): votes live in [E-GRACE, E].
        if v.epoch.saturating_add(EPOCH_GRACE) < anchor.epoch || v.epoch > anchor.epoch {
            return Err(AnchorError::VoteEpochOutsideWindow {
                index: i,
                vote_epoch: v.epoch,
            });
        }
        let rec = set
            .iter()
            .find(|r| r.address == v.validator)
            .ok_or(AnchorError::UnknownValidator(v.validator))?;
        let (eligible, committed) = anchor_eligible(rec, anchor.epoch);
        if !eligible {
            return Err(AnchorError::IneligibleValidator(v.validator));
        }
        // Asserted context becomes checked binding: claimed stake MUST
        // equal the committed amount.
        if v.stake_amount != committed {
            return Err(AnchorError::StakeAmountMismatch {
                validator: v.validator,
                claimed: v.stake_amount,
                committed,
            });
        }
        by_validator.push((v.validator, committed));
    }
    by_validator.sort();
    for w in by_validator.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(AnchorError::DuplicateValidator(w[0].0));
        }
    }
    let support: u64 = by_validator.iter().map(|(_, w)| *w).fold(0u64, |a, b| a.saturating_add(b));
    // 5. Quorum over the RECOMPUTED denominator (never the claim alone).
    if !StakeRegistry::quorum_met(support, total) {
        return Err(AnchorError::QuorumNotReached { support, total });
    }
    Ok(AnchorSummary {
        support,
        total,
        winner: anchor.winner,
        vote_count: anchor.votes.len(),
    })
}
