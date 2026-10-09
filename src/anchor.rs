//! PHASE 4P: V6 anchor verification (4O design implementation).
//!
//! ADDITIVE-ONLY module: no existing consensus path calls into it, and it
//! changes no rule (quorum, stake, slash, finality, era gating, wire).
//! A V6 anchor binds a finality (conflict key + winner + quorum votes) to
//! the epoch, the validator-set commitment, and the recomputed denominator
//! (4O sec.6-9). Verification is offline and pure: same inputs always give
//! the same verdict, independent of wall-clock, era, or arrival order.
//! V6 stays dormant: the only production caller is the boot trust-boundary
//! check (refuses boot on an incoherent operator-supplied anchor file,
//! no-op when absent); no consensus decision reads this module.

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
/// PHASE 4V: `network_id` binds the whole bundle to one network (checked
/// against the expected network AND against every vote's network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6Anchor {
    pub epoch: u64,
    /// PHASE 4V: network discriminator (covered by the bundle tag,
    /// checked against the expected network).
    pub network_id: u64,
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
    /// PHASE 4V: bundle or member vote bound to another network.
    WrongNetwork { expected: u64, found: u64 },
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
    preimage.extend_from_slice(&anchor.network_id.to_le_bytes());
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
    network_id: u64,
) -> V6Anchor {
    let (set_root, total) = validator_set_root(set, epoch);
    let mut supporting: Vec<VoteId> = votes.iter().map(|v| v.id()).collect();
    supporting.sort();
    V6Anchor {
        epoch,
        network_id,
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
    expected_network: u64,
    is_strict_descendant: F,
) -> Result<AnchorSummary, AnchorError>
where
    F: Fn(&[u8; 32], &[u8; 32]) -> bool,
{
    // 0. Bundle integrity first: any tampering invalidates the tag.
    if anchor_id(anchor) != expected_id {
        return Err(AnchorError::AnchorIdMismatch);
    }
    // PHASE 4V: network domain separation. The bundle's network must equal
    // the expected network (cross-network anchor replay), and every quorum
    // vote must carry the same network (mixed-network bundles).
    if anchor.network_id != expected_network {
        return Err(AnchorError::WrongNetwork {
            expected: expected_network,
            found: anchor.network_id,
        });
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
        // PHASE 4V: every quorum vote must carry the anchor's network
        // (mixed-network bundles fail here even when each vote verifies
        // under its own network elsewhere).
        if v.network_id != expected_network {
            return Err(AnchorError::WrongNetwork {
                expected: expected_network,
                found: v.network_id,
            });
        }
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

// =====================================================================
// PHASE 4Q: bootstrap integration layer (distribution bundle, boot trust
// boundary, synced-state cross-check, multi-source comparison).
//
// Design notes (4O sec.13-14): the FILE is transport only (operator-placed,
// same trust class as genesis.json/known_peers.json). The canonical
// commitment bytes (sec.7) are what is verified, never the JSON itself.
// Authenticity of the bytes rests on file provenance (the 4F sourcing
// discipline executed by the operator); this layer proves internal
// coherence + bindings, and refuses incoherent bundles fail-closed.
// =====================================================================

/// Operator-supplied anchor file name inside the node data directory.
/// Absent by default: nodes without V6-finalized history need no anchor
/// and boot exactly as before (sec.6 no-anchor behavior).
pub const V6_ANCHOR_FILE: &str = "v6_anchor.json";

/// PHASE 4V: storage network-marker file name inside the node data
/// directory. Holds the u64 LE network id that claimed the directory;
/// a different network refuses to boot on it (fail closed). Sidecar file
/// only: no storage tree, key, or manifest format is touched.
pub const NETWORK_MARKER_FILE: &str = "network.id";

/// Distribution bundle: the anchor plus the validator set it commits to.
/// The set MUST reproduce `anchor.set_root` at `anchor.epoch` or the
/// bundle is incoherent (SetRootMismatch), however it was delivered.
#[derive(Debug, Clone)]
pub struct AnchorBundle {
    pub anchor: V6Anchor,
    pub validator_set: Vec<ValidatorRecord>,
}

fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn hex_32(s: &str, field: &'static str) -> Result<[u8; 32], BundleError> {
    let v = hex::decode(s).map_err(|e| BundleError::Hex(format!("{}: {}", field, e)))?;
    v.try_into()
        .map_err(|_| BundleError::BadLength(field))
}

/// Deterministic bundle encoding (fixed key order, hex fields). Identical
/// logical bundles encode to identical bytes, which is what makes
/// multi-source byte comparison meaningful (sec.11 detection).
pub fn encode_anchor_bundle(bundle: &AnchorBundle) -> Result<Vec<u8>, BundleError> {
    use serde_json::{json, Map, Value};
    let mut root = Map::new();
    root.insert("format".to_string(), Value::from(ANCHOR_FORMAT_VERSION));
    root.insert("epoch".to_string(), Value::from(bundle.anchor.epoch));
    root.insert(
        "network_id".to_string(),
        Value::from(bundle.anchor.network_id),
    );
    root.insert(
        "key_sender".to_string(),
        Value::from(hex_of(&bundle.anchor.key.0)),
    );
    root.insert(
        "key_nonce".to_string(),
        Value::from(bundle.anchor.key.1),
    );
    root.insert(
        "winner".to_string(),
        Value::from(hex_of(&bundle.anchor.winner)),
    );
    root.insert(
        "members".to_string(),
        Value::from(
            bundle
                .anchor
                .members
                .iter()
                .map(|m| Value::from(hex_of(m)))
                .collect::<Vec<Value>>(),
        ),
    );
    root.insert(
        "votes".to_string(),
        Value::from(
            bundle
                .anchor
                .votes
                .iter()
                .map(|v| Value::from(hex_of(&v.encode())))
                .collect::<Vec<Value>>(),
        ),
    );
    root.insert(
        "supporting".to_string(),
        Value::from(
            bundle
                .anchor
                .supporting
                .iter()
                .map(|id| Value::from(hex_of(id)))
                .collect::<Vec<Value>>(),
        ),
    );
    root.insert(
        "claimed_total".to_string(),
        Value::from(bundle.anchor.claimed_total),
    );
    root.insert(
        "set_root".to_string(),
        Value::from(hex_of(&bundle.anchor.set_root)),
    );
    root.insert(
        "prev".to_string(),
        Value::from(hex_of(&bundle.anchor.prev)),
    );
    root.insert(
        "state_root".to_string(),
        match bundle.anchor.state_root {
            None => Value::Null,
            Some(h) => Value::from(hex_of(&h)),
        },
    );
    root.insert(
        "validator_set".to_string(),
        serde_json::to_value(&bundle.validator_set)
            .map_err(|e| BundleError::Json(format!("validator_set: {}", e)))?,
    );
    serde_json::to_vec_pretty(&json!(root)).map_err(|e| BundleError::Json(e.to_string()))
}

/// Bundle parse errors (fail-closed: any of these refuses the bundle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    UnknownVersion(u64),
    Json(String),
    Hex(String),
    BadLength(&'static str),
    VoteDecode(String),
}

/// Strict bundle parser: unknown format rejected, every hex/length/vote
/// checked. Returns the bundle; coherence is proven separately by
/// verification (parse success is NOT trust).
pub fn parse_anchor_bundle(bytes: &[u8]) -> Result<AnchorBundle, BundleError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| BundleError::Json(e.to_string()))?;
    let get = |k: &str| v.get(k).ok_or_else(|| BundleError::Json(format!("missing {}", k)));
    let format = get("format")?
        .as_u64()
        .ok_or_else(|| BundleError::Json("bad format".to_string()))?;
    if format != ANCHOR_FORMAT_VERSION as u64 {
        return Err(BundleError::UnknownVersion(format));
    }
    let epoch = get("epoch")?
        .as_u64()
        .ok_or_else(|| BundleError::Json("bad epoch".to_string()))?;
    let network_id = get("network_id")?
        .as_u64()
        .ok_or_else(|| BundleError::Json("bad network_id".to_string()))?;
    let key_sender = hex_32(
        get("key_sender")?
            .as_str()
            .ok_or_else(|| BundleError::Json("bad key_sender".to_string()))?,
        "key_sender",
    )?;
    let key_nonce = get("key_nonce")?
        .as_u64()
        .ok_or_else(|| BundleError::Json("bad key_nonce".to_string()))?;
    let winner = hex_32(
        get("winner")?
            .as_str()
            .ok_or_else(|| BundleError::Json("bad winner".to_string()))?,
        "winner",
    )?;
    let mut members = Vec::new();
    for m in get("members")?
        .as_array()
        .ok_or_else(|| BundleError::Json("bad members".to_string()))?
    {
        members.push(hex_32(
            m.as_str()
                .ok_or_else(|| BundleError::Json("bad member".to_string()))?,
            "member",
        )?);
    }
    let mut votes = Vec::new();
    for enc in get("votes")?
        .as_array()
        .ok_or_else(|| BundleError::Json("bad votes".to_string()))?
    {
        let raw = hex::decode(
            enc.as_str()
                .ok_or_else(|| BundleError::Json("bad vote hex".to_string()))?,
        )
        .map_err(|e| BundleError::Hex(format!("vote: {}", e)))?;
        votes.push(Vote::decode(&raw).map_err(BundleError::VoteDecode)?);
    }
    let mut supporting = Vec::new();
    for id in get("supporting")?
        .as_array()
        .ok_or_else(|| BundleError::Json("bad supporting".to_string()))?
    {
        supporting.push(hex_32(
            id.as_str()
                .ok_or_else(|| BundleError::Json("bad supporting id".to_string()))?,
            "supporting",
        )?);
    }
    let claimed_total = get("claimed_total")?
        .as_u64()
        .ok_or_else(|| BundleError::Json("bad claimed_total".to_string()))?;
    let set_root = hex_32(
        get("set_root")?
            .as_str()
            .ok_or_else(|| BundleError::Json("bad set_root".to_string()))?,
        "set_root",
    )?;
    let prev = hex_32(
        get("prev")?
            .as_str()
            .ok_or_else(|| BundleError::Json("bad prev".to_string()))?,
        "prev",
    )?;
    let state_root = match get("state_root")? {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(hex_32(s, "state_root")?),
        _ => return Err(BundleError::Json("bad state_root".to_string())),
    };
    let validator_set: Vec<ValidatorRecord> = serde_json::from_value(get("validator_set")?.clone())
        .map_err(|e| BundleError::Json(format!("validator_set: {}", e)))?;
    Ok(AnchorBundle {
        anchor: V6Anchor {
            epoch,
            network_id,
            key: (key_sender, key_nonce),
            winner,
            members,
            votes,
            supporting,
            claimed_total,
            set_root,
            prev,
            state_root,
        },
        validator_set,
    })
}

/// Multi-source comparison primitive (sec.11 detection only): byte-exact
/// equality of bundle encodings. Contradiction is DETECTED (caller halts);
/// selection between contradictory bundles is DEFERRED (no rule invented):
/// MULTI_SOURCE_SELECTION = DEFERRED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleComparison {
    Equal,
    Contradictory,
}

pub fn compare_anchor_bundles(a: &[u8], b: &[u8]) -> BundleComparison {
    if a == b {
        BundleComparison::Equal
    } else {
        BundleComparison::Contradictory
    }
}

/// Synced-state cross-check (joiner path): the bundle is already verified;
/// this proves the LOCAL registry is consistent with it. Monotonic-safe by
/// construction: votes are never deleted, and finalized winners are sticky,
/// so a registry that advanced past the anchor still passes while any
/// divergence (missing votes, different winner) refuses. Needs no closure,
/// no epoch, no network: pure state comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateAnchorError {
    VoteMissing(VoteId),
    WinnerMismatch { expected: [u8; 32], found: [u8; 32] },
}

pub fn check_state_against_anchor(
    registry: &StakeRegistry,
    anchor: &V6Anchor,
) -> Result<(), StateAnchorError> {
    // (a) Every anchor vote id must be present locally (by content id, so
    // re-encoding differences cannot hide a missing vote).
    let mut present: std::collections::HashSet<VoteId> = std::collections::HashSet::new();
    for bytes in registry.snapshot().votes {
        if let Ok(v) = Vote::decode(&bytes) {
            present.insert(v.id());
        }
    }
    for v in &anchor.votes {
        if !present.contains(&v.id()) {
            return Err(StateAnchorError::VoteMissing(v.id()));
        }
    }
    // (b) A locally finalized winner must equal the anchored winner
    // (stickiness: same votes decide identically). Absent local finality
    // (fresh/mid-sync node) is NOT a contradiction: proceed.
    if let Some(rec) = registry.finalized_record(&anchor.key) {
        if rec.winner != anchor.winner {
            return Err(StateAnchorError::WinnerMismatch {
                expected: anchor.winner,
                found: rec.winner,
            });
        }
    }
    Ok(())
}

/// Boot trust-boundary verdict (sec.5): NoAnchor preserves current boot
/// behavior exactly; Accepted records a verified boundary; any refusal
/// fails boot closed (caller returns Err like the manifest path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapVerdict {
    NoAnchor,
    Accepted { anchor_id: [u8; 32], summary: AnchorSummary },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    Io(String),
    Parse(BundleError),
    Verify(AnchorError),
    StateDiverged(StateAnchorError),
}

/// Verify the operator-supplied anchor file (if any) against the just-loaded
/// registry. Pure logic over (data_dir, registry); the node boot path calls
/// it once and refuses boot on Err. Steps mirror charter sec.5 (1-9):
/// load -> structure/parse -> epoch+set+total bindings -> votes -> quorum
/// -> chain -> local-state consistency -> accept.
pub fn verify_bootstrap_anchor(
    data_dir: &std::path::Path,
    registry: &StakeRegistry,
    expected_network: u64,
    is_strict_descendant: impl Fn(&[u8; 32], &[u8; 32]) -> bool,
) -> Result<BootstrapVerdict, BootstrapError> {
    let path = data_dir.join(V6_ANCHOR_FILE);
    if !path.exists() {
        return Ok(BootstrapVerdict::NoAnchor);
    }
    let bytes =
        std::fs::read(&path).map_err(|e| BootstrapError::Io(format!("{}: {}", path.display(), e)))?;
    let bundle = parse_anchor_bundle(&bytes).map_err(BootstrapError::Parse)?;
    let id = anchor_id(&bundle.anchor);
    let summary = verify_anchor(
        &bundle.anchor,
        &bundle.validator_set,
        id,
        expected_network,
        is_strict_descendant,
    )
    .map_err(BootstrapError::Verify)?;
    check_state_against_anchor(registry, &bundle.anchor).map_err(BootstrapError::StateDiverged)?;
    Ok(BootstrapVerdict::Accepted {
        anchor_id: id,
        summary,
    })
}
