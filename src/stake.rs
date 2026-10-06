//! PHASE 4G: stake-weighted finality machinery (v6, NO PoW anywhere here).
//!
//! Contents: economic constants (4F values, INTERIM-flagged where the charter
//! says so), epochs, validator lifecycle, stake registry, quorum arithmetic
//! (integer-only), equivocation evidence + slash application, finality
//! records. Deterministic, integer-only, order-independent. No floats, no
//! wall-clock reads inside consensus fns (timestamps/epochs passed
//! explicitly  -  same discipline as `difficulty_for_tx_at`).
//!
//! Design decisions (argued in IMPLEMENTATION.md, not re-litigated here):
//! - weight(vote) = bonded_amount FLAT (no ledger coupling -> no circularity;
//!  double-use residual documented).
//! - slash = 100% voting-weight removal + permanent flag + re-entry gated by
//!  bond maturation (no ledger surgery -> no rebuild-divergence class).
//! - bond maturation 2 epochs (principled minimum: 1 = same-epoch = no
//!  protection against flash entry).
//! - unbonding validators / slashed validators never vote (clean cutover).
//! - no memoized quorums/finality beyond stored records (recompute-pure).

use crate::transaction::Vote;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// PHASE 4F P1: minimum bonded stake for validator admission (base units).
/// INTERIM (governance-tunable pending distribution data): maximin over the
/// derived band [1e6 dust/state floor, 1e9 accessibility ceiling] = 3e7.
/// Purpose here: dust-identity state-DoS pricing (weight is proportional
/// regardless  -  1M dust identities weigh ~nothing either way). Changing this
/// value needs the distribution-data review named in the 4F doc, NOT a code
/// tweak in passing.
pub const MIN_STAKE: u64 = 30_000_000;

/// PHASE 4F P2: epoch duration in milliseconds (1h, BALANCED profile).
/// Epoch index = floor(unix_ms / EPOCH_DURATION_MS). Existing 1h policy grid
/// (MAX_PAST/FUTURE) already tolerates this skew class.
pub const EPOCH_DURATION_MS: u64 = 3_600_000;

/// PHASE 4F P3: unbonding delay in epochs (72h at 1h epochs). Covers
/// fraud-inclusion + multi-day partition heals + checkpoint cadence.
pub const UNBONDING_EPOCHS: u64 = 72;

/// Bond maturation in epochs (principled minimum: 1 epoch = same-epoch =
/// no flash-entry protection). New bonds vote starting 2 epochs after
/// bonding (also gates slashed-identity re-entry: same delay applies).
pub const BOND_MATURATION_EPOCHS: u64 = 2;

/// Epoch-edge grace for vote validity (4F design note): votes tagged
/// current_epoch +/- 1 count (skew tolerance); anything older/newer is stale
/// (dropped, never slashed  -  staleness is not equivocation).
pub const EPOCH_GRACE: u64 = 1;

/// Pure epoch index from a millisecond timestamp. Deterministic.
pub fn epoch_of(timestamp_ms: u64) -> u64 {
    timestamp_ms / EPOCH_DURATION_MS
}

/// Current epoch from wall clock. SYSTEM EDGE ONLY (RPC/node call sites);
/// consensus fns take explicit epochs (testability + determinism).
pub fn current_epoch() -> u64 {
    epoch_of(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64,
    )
}

/// Validator lifecycle states. Bonded implies active (immediate
/// effectiveness tempered by BOND_MATURATION_EPOCHS for voting); Unbonding
/// and beyond never vote (clean cutover); Slashed is permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidatorState {
    /// Bonded (funds committed). Votes once maturation reached.
    Bonded,
    /// Exit requested; release at `release_epoch`; never votes.
    Unbonding { release_epoch: u64 },
    /// Released (funds free); record retained for audit, weight zero.
    Unbonded,
    /// Proven equivocator: weight zero forever; re-bonding rejected.
    Slashed,
}

/// One validator's bonded position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub address: [u8; 32],
    pub bonded_amount: u64,
    pub state: ValidatorState,
    pub bonded_epoch: u64,
    pub slashed_epoch: Option<u64>,
}

/// A conflict key: (sender, nonce), same identity as DAG conflict tracking.
pub type ConflictKey = ([u8; 32], u64);

/// Finality record: an immutable decision (removable ONLY via
/// slash-triggered invalidation, which deletes the entry so later
/// re-resolution starts clean  -  never mutates in place).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedRecord {
    pub winner: [u8; 32],
    pub epoch: u64,
    pub supporting_weight: u64,
}

/// Equivocation evidence: two valid signatures by one validator, same
/// (epoch, conflict key), different sides. Deterministic id (hash).
/// Carries BOTH full vote encodings (not just ids): the proof must survive
/// restarts (slash state alone only enforces locally; gossiping the proof
/// needs the votes themselves).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub id: [u8; 32],
    pub accused: [u8; 32],
    pub epoch: u64,
    pub conflict_sender: [u8; 32],
    pub conflict_nonce: u64,
    pub vote_a: [u8; 32],
    pub vote_b: [u8; 32],
    pub vote_a_encoding: Vec<u8>,
    pub vote_b_encoding: Vec<u8>,
}

/// Stake registry: validators + votes + finality + evidence. All maps keyed
/// by explicit ids (no iteration-order dependence anywhere: counts are sums,
/// decisions sort explicitly at use sites).
#[derive(Debug, Default)]
pub struct StakeRegistry {
    validators: HashMap<[u8; 32], ValidatorRecord>,
    /// (validator, epoch, conflict-key) -> vote. Enforces vote-once scope;
    /// second side for the same triple is equivocation EVIDENCE (handled at
    /// insert, never silently overwritten).
    votes: HashMap<([u8; 32], u64, ConflictKey), Vote>,
    finalized: HashMap<ConflictKey, FinalizedRecord>,
    evidence: HashMap<[u8; 32], EquivocationEvidence>,
    /// Admitted bond ids (replay protection: re-submitting the same bond
    /// bytes is an idempotent no-op, never a second top-up  -  each top-up
    /// needs a FRESH signature, i.e. a new id).
    seen_bonds: HashSet<[u8; 32]>,
}

impl StakeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bond a validator (post-validation admission will have checked
    /// signature + MIN_STAKE + funds + non-slashed; see validate_bond).
    /// Maturation applies to voting eligibility, not to recording.
    /// Re-bonding a slashed address is rejected (permanent flag).
    /// Re-bonding an already-bonded address tops up (same lifecycle).
    pub fn apply_bond(
        &mut self,
        validator: [u8; 32],
        amount: u64,
        epoch: u64,
    ) -> Result<(), String> {
        match self.validators.get(&validator) {
            Some(rec) if rec.state == ValidatorState::Slashed => {
                return Err("slashed address may never re-bond".to_string())
            }
            Some(rec)
                if matches!(
                    rec.state,
                    ValidatorState::Bonded | ValidatorState::Unbonding { .. }
                ) =>
            {
                // Top-up / re-bond while exiting: reset to Bonded with the
                // new maturation horizon (documented: re-entry always pays
                // the maturation delay again  -  no instant return).
                let rec = self.validators.get_mut(&validator).expect("present");
                rec.bonded_amount = rec.bonded_amount.saturating_add(amount);
                rec.state = ValidatorState::Bonded;
                rec.bonded_epoch = epoch;
                return Ok(());
            }
            _ => {}
        }
        self.validators.insert(
            validator,
            ValidatorRecord {
                address: validator,
                bonded_amount: amount,
                state: ValidatorState::Bonded,
                bonded_epoch: epoch,
                slashed_epoch: None,
            },
        );
        Ok(())
    }

    /// Request unbond: Bonded -> Unbonding (release at now+delay).
    /// Voting eligibility ends at request (clean cutover). Idempotent-ish:
    /// already-unbonding re-request refreshes nothing (keeps earliest
    /// release); slashed/unbonded/unbonded-missing are errors/no-ops.
    pub fn apply_unbond(&mut self, validator: [u8; 32], now_epoch: u64) -> Result<(), String> {
        let rec = self
            .validators
            .get_mut(&validator)
            .ok_or_else(|| "unknown validator".to_string())?;
        match rec.state {
            ValidatorState::Bonded => {
                rec.state = ValidatorState::Unbonding {
                    release_epoch: now_epoch.saturating_add(UNBONDING_EPOCHS),
                };
                Ok(())
            }
            ValidatorState::Unbonding { .. } => Ok(()),
            ValidatorState::Unbonded => Err("already unbonded".to_string()),
            ValidatorState::Slashed => Err("slashed: cannot unbond".to_string()),
        }
    }

    /// Release matured unbondings as of `now_epoch` (Unbonding -> Unbonded).
    /// Deterministic sweep over explicit state (call after epoch advance,
    /// at boot, and in tests directly).
    pub fn release_matured(&mut self, now_epoch: u64) -> Vec<[u8; 32]> {
        let mut released = Vec::new();
        for (addr, rec) in self.validators.iter_mut() {
            if let ValidatorState::Unbonding { release_epoch } = rec.state {
                if now_epoch >= release_epoch {
                    rec.state = ValidatorState::Unbonded;
                    released.push(*addr);
                }
            }
        }
        released.sort();
        released
    }

    /// Voting eligibility at `at_epoch`: Bonded (matured) and never slashed.
    /// Maturation: bonded_epoch + BOND_MATURATION_EPOCHS <= at_epoch.
    pub fn is_eligible(&self, validator: &[u8; 32], at_epoch: u64) -> bool {
        match self.validators.get(validator) {
            Some(rec) => {
                matches!(rec.state, ValidatorState::Bonded)
                    && rec.bonded_epoch.saturating_add(BOND_MATURATION_EPOCHS) <= at_epoch
            }
            None => false,
        }
    }

    /// Bonded amount (voting weight basis), 0 unless currently eligible.
    /// Flat (no ledger coupling  -  see IMPLEMENTATION doc for the decided
    /// tradeoff; double-use residual documented, not hidden).
    pub fn voting_weight(&self, validator: &[u8; 32], at_epoch: u64) -> u64 {
        if !self.is_eligible(validator, at_epoch) {
            return 0;
        }
        self.validators
            .get(validator)
            .map(|r| r.bonded_amount)
            .unwrap_or(0)
    }

    /// Eligible stake total (quorum denominator): sum of eligible bonded
    /// amounts. Saturating (documented cap class, unreachable magnitudes).
    pub fn eligible_stake_total(&self, at_epoch: u64) -> u64 {
        let mut total = 0u64;
        let mut addrs: Vec<[u8; 32]> = self.validators.keys().copied().collect();
        addrs.sort();
        for addr in addrs {
            total = total.saturating_add(self.voting_weight(&addr, at_epoch));
        }
        total
    }

    /// Quorum predicate: 3S >= 2T in u128 (exact, no floats, no division, no
    /// overflow). Empty total or empty support never quorate (T=0 and S=0
    /// must not finalize anything  -  explicit guard, tested boundaries).
    pub fn quorum_met(support: u64, total: u64) -> bool {
        if total == 0 {
            return false;
        }
        (support as u128) * 3 >= (total as u128) * 2
    }

    /// Insert a vote. Returns the disposition:
    /// - Duplicate (same bytes seen): idempotent Ok, no state change.
    /// - Fresh: stored.
    /// - Equivocation (same validator+epoch+key, different side): stored as
    ///  EVIDENCE (both votes kept for proof), accused slashed IMMEDIATELY
    ///  (weight zero + permanent flag), evidence id returned. The slash is
    ///  registry-local (no ledger surgery  -  convergence-safe by
    ///  construction); fund-burn semantics deferred per charter (no
    ///  tokenomics invention).
    /// Assumes validate_vote passed (signature/epoch/window/bonded checks).
    pub fn insert_vote(&mut self, vote: Vote) -> VoteInsertOutcome {
        let key = (
            vote.validator,
            vote.epoch,
            (vote.conflict_sender, vote.conflict_nonce),
        );
        if let Some(existing) = self.votes.get(&key) {
            if existing.side == vote.side {
                return VoteInsertOutcome::Duplicate;
            }
            // Equivocation: same (validator, epoch, key), different side.
            // The FIRST vote keeps the map slot (deterministic); BOTH votes
            // are preserved inside the evidence for proof; the accused is
            // slashed immediately (weight zero + permanent flag).
            let evidence = EquivocationEvidence::new(
                vote.validator,
                vote.epoch,
                (vote.conflict_sender, vote.conflict_nonce),
                existing,
                &vote,
            );
            let eid = evidence.id;
            self.evidence.insert(eid, evidence);
            self.apply_slash(vote.validator, vote.epoch);
            return VoteInsertOutcome::Equivocated { evidence_id: eid };
        }
        self.votes.insert(key, vote);
        VoteInsertOutcome::Accepted
    }

    /// Apply slash: bonded -> 0, permanent Slashed flag (re-bond rejected).
    /// Idempotent (second slash is a no-op returning false).
    pub fn apply_slash(&mut self, validator: [u8; 32], epoch: u64) -> bool {
        match self.validators.get_mut(&validator) {
            Some(rec) => {
                if rec.state == ValidatorState::Slashed {
                    return false;
                }
                rec.bonded_amount = 0;
                rec.state = ValidatorState::Slashed;
                rec.slashed_epoch = Some(epoch);
                true
            }
            None => false,
        }
    }

    /// Supporting weight for `side` of `key`: sum over validators of
    /// (latest vote for this key pointing at `side` or strictly inside its
    /// descendant closure) x weight. Latest-per-validator rule: max by
    /// (epoch, vote-id)  -  pure function of the vote SET (deterministic across
    /// nodes/orders). Eligibility + weight read live (unbonded/slashed
    /// contribute zero automatically). `is_strict_descendant` tests strict
    /// DAG descent (txid descends from `side`, excluding `side` itself;
    /// equality is handled here) and is supplied by the caller (DAG
    /// membership lives outside the registry) to keep this module
    /// DAG-agnostic and unit-testable.
    pub fn support_for<F>(
        &self,
        key: ConflictKey,
        side: &[u8; 32],
        at_epoch: u64,
        is_strict_descendant: F,
    ) -> u64
    where
        F: Fn(&[u8; 32]) -> bool,
    {
        // Latest vote per validator for this key (max by (epoch, id)).
        let mut latest: HashMap<[u8; 32], &Vote> = HashMap::new();
        let mut validators: Vec<[u8; 32]> = self
            .votes
            .keys()
            .filter(|(_, _, k)| *k == key)
            .map(|(v, _, _)| *v)
            .collect();
        validators.sort();
        validators.dedup();
        for v in validators {
            let mut best: Option<&Vote> = None;
            for ((vv, epoch, k), vote) in self.votes.iter() {
                if *vv != v || *k != key {
                    continue;
                }
                let better = match best {
                    None => true,
                    Some(b) => (*epoch, vote.id()) > (b.epoch, b.id()),
                };
                if better {
                    best = Some(vote);
                }
            }
            if let Some(bv) = best {
                latest.insert(v, bv);
            }
        }
        let mut total = 0u64;
        let mut ordered: Vec<[u8; 32]> = latest.keys().copied().collect();
        ordered.sort();
        for v in ordered {
            let bv = latest[&v];
            if bv.side == *side || is_strict_descendant(&bv.side) {
                total = total.saturating_add(self.voting_weight(&v, at_epoch));
            }
        }
        total
    }

    /// Try to finalize `key` among `members`: winner = max support
    /// (min-id tiebreak); finalize iff quorum over eligible total AND no
    /// valid finalized entry exists. Returns the decision (new or existing).
    /// `is_strict_descendant(member, txid)`: strict DAG descent test supplied
    /// by the caller (same separation as support_for). `at_epoch`: quorum
    /// evaluation epoch (caller: vote epoch or current; deterministic input).
    pub fn try_finalize<F>(
        &mut self,
        key: ConflictKey,
        members: &[[u8; 32]],
        at_epoch: u64,
        is_strict_descendant: F,
    ) -> Option<FinalizedRecord>
    where
        F: Fn(&[u8; 32], &[u8; 32]) -> bool,
    {
        if let Some(existing) = self.finalized.get(&key) {
            return Some(*existing);
        }
        if members.is_empty() {
            return None;
        }
        // Score each member; deterministic order (sorted ids).
        let mut ordered: Vec<[u8; 32]> = members.to_vec();
        ordered.sort();
        let mut best: Option<([u8; 32], u64)> = None;
        for m in &ordered {
            // Strict descendant test for this member; equality with the
            // member itself is handled inside support_for.
            let s = self.support_for(key, m, at_epoch, |txid: &[u8; 32]| {
                is_strict_descendant(m, txid)
            });
            let better = match best {
                None => true,
                Some((_, bs)) => s > bs,
            };
            // NOTE: ties keep the FIRST (sorted => smallest id)  -  min-id
            // tiebreak without a second pass.
            if better {
                best = Some((*m, s));
            }
        }
        let (winner, support) = best?;
        let total = self.eligible_stake_total(at_epoch);
        if Self::quorum_met(support, total) {
            let rec = FinalizedRecord {
                winner,
                epoch: at_epoch,
                supporting_weight: support,
            };
            self.finalized.insert(key, rec);
            Some(rec)
        } else {
            None
        }
    }

    /// Invalidate finality after slash-triggered recomputation shows the
    /// finalized side lost quorum WITHOUT slashed weight. Deletes the entry
    /// (later re-resolution starts clean  -  never mutates in place).
    /// Returns true when an entry was removed.
    pub fn invalidate_finality(&mut self, key: &ConflictKey) -> bool {
        self.finalized.remove(key).is_some()
    }

    pub fn finalized_winner(&self, key: &ConflictKey) -> Option<[u8; 32]> {
        self.finalized.get(key).map(|r| r.winner)
    }

    /// Validator lifecycle state (None = unknown address). Validation-layer
    /// read path (slash checks, eligibility error detail).
    pub fn validator_state(&self, validator: &[u8; 32]) -> Option<ValidatorState> {
        self.validators.get(validator).map(|r| r.state)
    }

    /// Crash-durability snapshot: every map cloned into sorted vecs
    /// (deterministic byte-identical snapshots across nodes/restarts).
    /// Votes serialize as canonical encodings (strict-decoded on restore).
    /// Evidence carries both full votes, so proofs survive restarts.
    pub fn snapshot(&self) -> RegistrySnapshot {
        let mut validators: Vec<ValidatorRecord> = self.validators.values().cloned().collect();
        validators.sort_by(|a, b| a.address.cmp(&b.address));
        let mut votes: Vec<Vec<u8>> = self.votes.values().map(|v| v.encode()).collect();
        votes.sort();
        let mut finalized: Vec<(ConflictKey, FinalizedRecord)> =
            self.finalized.iter().map(|(k, r)| (*k, *r)).collect();
        finalized.sort_by(|a, b| a.0.cmp(&b.0));
        let mut evidence: Vec<EquivocationEvidence> = self.evidence.values().cloned().collect();
        evidence.sort_by(|a, b| a.id.cmp(&b.id));
        let mut seen_bonds: Vec<[u8; 32]> = self.seen_bonds.iter().copied().collect();
        seen_bonds.sort();
        RegistrySnapshot {
            validators,
            votes,
            finalized,
            evidence,
            seen_bonds,
        }
    }

    /// Restore from a snapshot (boot path). Fail-closed: any corrupt vote
    /// encoding aborts the restore (operator investigates; never silently
    /// drop stake state). Replays inserts through insert_vote (equivocation
    /// re-detection re-fires deterministically  -  the restored registry
    /// equals the saved one, slash flags included). Evidence votes replay
    /// AFTER map votes so first-seen slots match the saved registry.
    pub fn restore(snapshot: RegistrySnapshot) -> Result<Self, String> {
        let mut reg = Self::new();
        for rec in snapshot.validators {
            reg.validators.insert(rec.address, rec);
        }
        for (key, rec) in snapshot.finalized {
            reg.finalized.insert(key, rec);
        }
        for id in snapshot.seen_bonds {
            reg.seen_bonds.insert(id);
        }
        for bytes in &snapshot.votes {
            let vote =
                Vote::decode(bytes).map_err(|e| format!("corrupt vote in snapshot: {}", e))?;
            match reg.insert_vote(vote) {
                VoteInsertOutcome::Accepted | VoteInsertOutcome::Duplicate => {}
                VoteInsertOutcome::Equivocated { .. } => {
                    return Err("snapshot map votes equivocate: corrupt snapshot".to_string())
                }
            }
        }
        for ev in &snapshot.evidence {
            let (a, b) = ev.votes()?;
            // First insert is Accepted-or-Duplicate (first-seen already in
            // the map); the second re-fires the equivocation (re-slash is
            // idempotent; re-derived evidence id must match the saved one).
            for v in [a, b] {
                match reg.insert_vote(v) {
                    VoteInsertOutcome::Accepted | VoteInsertOutcome::Duplicate => {}
                    VoteInsertOutcome::Equivocated { evidence_id } => {
                        if evidence_id != ev.id {
                            return Err("evidence id mismatch on restore".to_string());
                        }
                    }
                }
            }
            // The re-derived entry must exist (insert_vote created it).
            if !reg.evidence.contains_key(&ev.id) {
                return Err("evidence lost on restore".to_string());
            }
        }
        Ok(reg)
    }

    /// Test/debug accessor: evidence by id.
    pub fn get_evidence(&self, id: &[u8; 32]) -> Option<&EquivocationEvidence> {
        self.evidence.get(id)
    }

    /// Record a bond id as admitted. Returns true when NEW (caller applies
    /// the bond); false means replay (caller treats as idempotent Ok and
    /// applies NOTHING  -  no double top-up).
    pub fn note_bond_seen(&mut self, id: [u8; 32]) -> bool {
        self.seen_bonds.insert(id)
    }

    /// All finalized conflict keys (sorted). Slash/unbond invalidation
    /// sweeps (a weight removal can void quorum on ANY key the removed
    /// validator voted on  -  the sweep set is the finalized set).
    pub fn finalized_keys(&self) -> Vec<ConflictKey> {
        let mut keys: Vec<ConflictKey> = self.finalized.keys().copied().collect();
        keys.sort();
        keys
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }
}

/// Crash-durability snapshot of a StakeRegistry (sorted vecs; bincode-able).
/// Validators/finalized/evidence serialize via serde; votes as canonical
/// encodings (Vote has no serde impl  -  fixed arrays beyond 32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    pub validators: Vec<ValidatorRecord>,
    pub votes: Vec<Vec<u8>>,
    pub finalized: Vec<(ConflictKey, FinalizedRecord)>,
    pub evidence: Vec<EquivocationEvidence>,
    pub seen_bonds: Vec<[u8; 32]>,
}

/// Vote insertion disposition (exhaustive, logged by callers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteInsertOutcome {
    Accepted,
    Duplicate,
    Equivocated { evidence_id: [u8; 32] },
}

impl EquivocationEvidence {
    /// Build evidence from the two conflicting votes (full encodings
    /// preserved for proof survival across restarts). Canonical order by
    /// vote id (evidence id independent of arrival order).
    pub fn new(
        accused: [u8; 32],
        epoch: u64,
        key: ConflictKey,
        vote_a: &Vote,
        vote_b: &Vote,
    ) -> Self {
        let (first, second) = if vote_a.id() <= vote_b.id() {
            (vote_a, vote_b)
        } else {
            (vote_b, vote_a)
        };
        let first_id = first.id();
        let second_id = second.id();
        let mut preimage = Vec::with_capacity(32 + 8 + 64 + 32 + 32);
        preimage.extend_from_slice(&accused);
        preimage.extend_from_slice(&epoch.to_le_bytes());
        preimage.extend_from_slice(&key.0);
        preimage.extend_from_slice(&key.1.to_le_bytes());
        preimage.extend_from_slice(&first_id);
        preimage.extend_from_slice(&second_id);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&preimage);
        let id: [u8; 32] = hasher.finalize().into();
        Self {
            id,
            accused,
            epoch,
            conflict_sender: key.0,
            conflict_nonce: key.1,
            vote_a: first_id,
            vote_b: second_id,
            vote_a_encoding: first.encode(),
            vote_b_encoding: second.encode(),
        }
    }

    /// Decode both preserved votes (fail-closed on corruption).
    pub fn votes(&self) -> Result<(Vote, Vote), String> {
        let a = Vote::decode(&self.vote_a_encoding)
            .map_err(|e| format!("corrupt vote_a in evidence: {}", e))?;
        let b = Vote::decode(&self.vote_b_encoding)
            .map_err(|e| format!("corrupt vote_b in evidence: {}", e))?;
        Ok((a, b))
    }
}
