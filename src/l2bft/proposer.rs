//! Deterministic proposer selection (mission BI, priority 3).
//!
//! # Why this file exists
//!
//! Mission BH's audit finding was blunt: `T-AA` needs an assumption `H2` (a
//! leader-election rule) that the corpus **does not specify**, so `BftState` had
//! no proposer rule at all and the simulator's driver chose the value. That is
//! fine for a safety test and useless for an operational engine: with no rule,
//! "who may propose at round `r`" is whatever the environment happens to do.
//!
//! This module supplies the missing **progress** rule and nothing else. It is not
//! a safety rule: no vote, lock, certificate or finality check consults it. A
//! wrong proposer costs rounds, never a decision, because a proposal still has to
//! collect a prevote quorum under the unchanged `AW-LOCK-*` rules.
//!
//! # The rule
//!
//! For a position `(generation, height, round)`:
//!
//! ```text
//! seed   = H(AETHER-L2-PROPOSER-v1 ‖ generation ‖ height ‖ round)     32 bytes
//! draw   = first 8 bytes of seed, big-endian                          u64
//! slot   = draw mod total_weight                                      u64
//! owner  = the member whose cumulative-weight interval contains `slot`
//! ```
//!
//! Members are taken in the registry's canonical order (sorted by identifier),
//! which is the same order every other root in this codebase uses. **Only
//! entries that may vote contribute to the walk**: the denominator is
//! `total_voting_weight()`, i.e. the sum over eligible entries, so the walk has
//! to add exactly the same entries (mission BM, E-1). Skipping ineligible
//! entries keeps the intervals a partition of `[0, total)` and makes an
//! ineligible member unselectable, independently of its position.
//!
//! The result is a pure function of public data: no clock, no local randomness,
//! no hidden state, reproducible on every node and in every test.
//!
//! # Why not `height mod n`
//!
//! A naive modulo over a small counter is not uniform over the *weights*: it
//! walks the member list in step, so a validator with weight `w` is picked `w/n`
//! of the time rather than `w/total`, and consecutive rounds favour adjacent
//! indices. Both are exploitable: a member can compute the next proposer cheaply
//! and time a denial of service, and a light validator gets the same share as a
//! heavy one.
//!
//! # The bias this rule does have
//!
//! `draw mod total_weight` is very slightly biased toward low slots. The absolute
//! deviation of any member's selection probability from `w/total` is at most
//! `total_weight / 2^64`; relative to a member's own probability `w/total` that is
//! `total_weight^2 / (2^64 · w)`. With `total_weight` around `10^9` and any member
//! above weight 1, that is below `10^-10` — far under the noise of a single test
//! run. Rejection sampling would remove even that, at the cost of a variable
//! number of hashes; it is deliberately not done here, and the residual is stated
//! rather than hidden.
//!
//! # What this rule cannot do
//!
//! - **It is predictable.** Every node computes the same list, so an adversary
//!   knows the next proposer. This is inherent to any deterministic rule; hiding
//!   it needs a VRF, which A-06.6 does not specify.
//! - **It is proportional, not fair.** A member with 40 % of the weight proposes
//!   40 % of the rounds in expectation. That is what stake weighting means; a
//!   round-robin over identities would silently reject the corpus's weighting.
//! - **It does not guarantee liveness.** If the elected proposer is offline, this
//!   module changes nothing: the round timer (`timer.rs`) has to fire and a
//!   quorum has to adopt the next round, where a new proposer is elected. `H2` is
//!   satisfied, `H1`/`H3`-`H7` are not this module's business.
//! - **It does not gate anything by itself.** [`BftState::propose_as_proposer`]
//!   is the only place that enforces it, and it is opt-in: [`BftState::propose`]
//!   keeps its old behaviour so that no existing caller changes meaning.
//!
//! # Generation changes
//!
//! The generation is part of the seed and every member comes from the registry of
//! that generation, so a transition changes both the set and the schedule. No
//! stale index can point into a new set: the registry supplied must be the one of
//! the generation in the seed, or the function returns `None`.

use crate::consensus::generation::{CheckpointHeight, GenerationId, Round, ValidatorId};
use crate::l2crypto::frame::{frame_hash, le32, le64};
use crate::l2crypto::registry::ValidatorRegistry;

/// Domain tag of the proposer schedule.
pub const DOMAIN_PROPOSER: &[u8] = b"AETHER-L2-PROPOSER-v1";

/// Which member is elected to propose at one position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposerChoice {
    /// Canonical index in the registry.
    pub index: usize,
    /// Identity of the elected member.
    pub validator: ValidatorId,
    /// The draw that selected it, for auditability.
    pub draw: u64,
    /// Weight of the elected member.
    pub weight: u64,
    /// Total voting weight of the set.
    pub total: u64,
}

/// The 32-byte seed of a position.
pub fn schedule_seed(generation: GenerationId, height: CheckpointHeight, round: Round) -> [u8; 32] {
    frame_hash(
        DOMAIN_PROPOSER,
        &[&generation.0, &le64(height.get()), &le32(round.get())],
    )
}

/// First eight bytes of the seed, big-endian.
fn draw_of(seed: &[u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed[..8]);
    u64::from_be_bytes(bytes)
}

/// Elect the proposer of `(generation, height, round)`.
///
/// Returns `None` only when the registry does not belong to `generation`: a
/// schedule computed over the wrong set is not a schedule for this position.
pub fn proposer_for(
    registry: &ValidatorRegistry,
    generation: GenerationId,
    height: CheckpointHeight,
    round: Round,
) -> Option<ProposerChoice> {
    if registry.generation() != generation {
        return None;
    }
    let total = registry.total_voting_weight().get();
    if total == 0 {
        return None;
    }
    let draw = draw_of(&schedule_seed(generation, height, round));
    // `slot` stays fixed and the cumulative total advances: the interval of a
    // member is `[cumulative - w, cumulative)`. Subtracting the weight as well
    // would narrow every interval after the first and hand the middle members a
    // much larger share than their weight — which is exactly the bias a weighted
    // draw is supposed to avoid.
    let slot = draw % total;
    let mut cumulative = 0u64;
    for (index, entry) in registry.entries().iter().enumerate() {
        // BM / E-1: the denominator is the eligible weight, so an ineligible
        // entry must not consume an interval. Counting it would shift every
        // following interval and could return the ineligible entry itself.
        if !entry.admissibility.may_vote() {
            continue;
        }
        cumulative = cumulative.saturating_add(entry.weight.get());
        if slot < cumulative {
            return Some(ProposerChoice {
                index,
                validator: entry.id,
                draw,
                weight: entry.weight.get(),
                total,
            });
        }
    }
    // Unreachable: `cumulative` reaches `total` by construction, so the last
    // iteration always matches. Returning `None` rather than panicking keeps this
    // a total function even if a future registry breaks that invariant.
    None
}

/// Whether `validator` may propose at this position.
pub fn is_proposer(
    registry: &ValidatorRegistry,
    generation: GenerationId,
    height: CheckpointHeight,
    round: Round,
    validator: ValidatorId,
) -> bool {
    proposer_for(registry, generation, height, round)
        .map(|choice| choice.validator == validator)
        .unwrap_or(false)
}

/// The next `count` proposers from `from_round`, for audits and dashboards.
///
/// Consecutive rounds are independent draws, not a rotation: two heavy members
/// can be elected back to back, which is correct under the rule above.
pub fn schedule(
    registry: &ValidatorRegistry,
    generation: GenerationId,
    height: CheckpointHeight,
    from_round: Round,
    count: u32,
) -> Vec<ValidatorId> {
    (0..count)
        .filter_map(|offset| {
            let round = Round(from_round.get().saturating_add(offset));
            proposer_for(registry, generation, height, round).map(|choice| choice.validator)
        })
        .collect()
}

/// How many rounds out of `rounds` each member proposes, for bias audits.
///
/// Depends only on public data, so a test can assert the shape of the
/// distribution without a clock or a random source.
pub fn distribution(
    registry: &ValidatorRegistry,
    generation: GenerationId,
    height: CheckpointHeight,
    rounds: u32,
) -> Vec<(ValidatorId, u64)> {
    let mut counts: Vec<(ValidatorId, u64)> =
        registry.entries().iter().map(|e| (e.id, 0)).collect();
    for round in 0..rounds {
        if let Some(choice) = proposer_for(registry, generation, height, Round(round)) {
            if let Some(slot) = counts.iter_mut().find(|(id, _)| *id == choice.validator) {
                slot.1 += 1;
            }
        }
    }
    counts
}
