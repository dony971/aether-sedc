//! Deterministic round timer (mission BH, priority 5).
//!
//! # Why a timer exists here, and why it is not a clock
//!
//! Mission BG proved that a `RoundChange` is *transported and verified*, and also
//! that nothing ever **emits** one: there is no timeout mechanism anywhere in
//! `l2bft` or `network`. The audit for BH found exactly that — no `Instant`, no
//! `Duration`, no tick, no deadline in either module. Round changes could only be
//! produced by a test driver.
//!
//! A wall clock cannot be the source of truth for a consensus position: two nodes
//! with slightly different clocks would start different rounds, and no test could
//! be reproduced. So this module counts **steps supplied by the caller** — the
//! environment (`crate::network::sim`, or a test) decides when a step happens.
//! The mapping from steps to milliseconds is a deployment parameter, not something
//! this file reads.
//!
//! # What it changes, and what it cannot change
//!
//! It changes **when** a node asks to leave a round. It changes nothing about
//! what that request means: the message is the same `RoundChange`
//! (`ROUND_CHANGE_VERSION = 1`, `DOMAIN_ROUND_CHANGE`), verified by the same
//! [`crate::l2bft::round::RoundChange::verify`], adopted by the same
//! `BftState::process_round_change`. No rule, threshold, domain or byte layout is
//! added here.
//!
//! A round change never touches a lock and never authorizes a value
//! (`AW-LOCK-6`, `R-LOCK-2`), so a timer that fires too early or too late costs
//! liveness, never safety.
//!
//! # Proposer selection
//!
//! There is none, and this module does not invent one: `T-AA` requires H2
//! (a leader-election assumption) which the corpus does not specify for this
//! implementation. `BftState` therefore has no proposer rule, and neither has
//! this file. A node signs a round change; who proposes in the new round is
//! decided by whatever drives the engines.

use ed25519_dalek::SigningKey;

use crate::consensus::generation::{CheckpointHeight, Round};
use crate::l2bft::engine::BftState;
use crate::l2bft::round::RoundChange;
use crate::l2crypto::registry::validator_id;
use crate::l2persist::state::LockedValue;

/// Default number of steps before round 0 is declared timed out.
pub const DEFAULT_BASE_STEPS: u64 = 8;

/// How many times the budget may double before it stops growing.
pub const MAX_BACKOFF_SHIFT: u32 = 6;

/// A deterministic timeout counter for one validator at one height.
///
/// The budget doubles with the round (bounded), which is the usual way to stop a
/// partition from producing an unbounded storm of round changes. The growth is
/// explicit and testable, not tuned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTimer {
    base_steps: u64,
    round: Round,
    elapsed: u64,
    fired: bool,
}

impl RoundTimer {
    /// A timer for round 0 with `base_steps` before the first timeout.
    pub fn new(base_steps: u64) -> Self {
        Self {
            base_steps: base_steps.max(1),
            round: Round(0),
            elapsed: 0,
            fired: false,
        }
    }

    /// Adopt `round` if it differs from the one being timed, resetting the count.
    ///
    /// Called once per step with the engine's current round: a node that adopted a
    /// round change through the normal path stops counting the old round
    /// immediately, without any extra bookkeeping at the call site.
    pub fn sync_round(&mut self, round: Round) {
        if round != self.round {
            self.round = round;
            self.elapsed = 0;
            self.fired = false;
        }
    }

    /// Steps this round has been waiting.
    pub fn elapsed(&self) -> u64 {
        self.elapsed
    }

    /// Round being timed.
    pub fn round(&self) -> Round {
        self.round
    }

    /// Steps that must elapse before this round is timed out.
    ///
    /// `base << min(round, MAX_BACKOFF_SHIFT)`, saturating: a node that has been
    /// alone for a long time polls rarely instead of hammering.
    pub fn budget(&self) -> u64 {
        let shift = self.round.get().min(MAX_BACKOFF_SHIFT);
        self.base_steps.saturating_mul(1u64 << shift)
    }

    /// Advance by `steps`; return the round to move to when the budget is spent.
    ///
    /// Returning `Some(target)` does not move anything: the caller builds and signs
    /// the round change (see [`round_change_for`]). One ask per round: once the
    /// budget is spent the timer reports it **once**, and stays quiet until the
    /// round actually changes (`sync_round`). Otherwise a node that cannot move
    /// would emit one round change per step, which is a self-inflicted flood.
    pub fn tick(&mut self, steps: u64) -> Option<Round> {
        self.elapsed = self.elapsed.saturating_add(steps);
        if self.elapsed >= self.budget() && !self.fired {
            self.fired = true;
            // N-7: no round wraps. At the last representable round the timer
            // reports nothing; the height must be resolved or an operator called.
            self.round.get().checked_add(1).map(Round)
        } else {
            None
        }
    }

    /// Reset to round 0 at a new height.
    pub fn at_height(&mut self, _height: CheckpointHeight) {
        self.round = Round(0);
        self.elapsed = 0;
        self.fired = false;
    }
}

/// Build the round change a node would send after its timer fired.
///
/// The signed bytes are exactly those of `RoundChange::signing_bytes`: this
/// function only fills in the node's own position, the round it wants to leave,
/// the round it wants to enter, and the lock it currently holds. The lock travels
/// as **evidence** and never unlocks anything.
pub fn round_change_for(state: &BftState, target: Round, key: &SigningKey) -> RoundChange {
    let locked: Option<LockedValue> = state.active_lock();
    let identity = validator_id(&key.verifying_key().to_bytes());
    RoundChange::unsigned(
        state.network,
        state.generation,
        state.height,
        state.round,
        target,
        identity,
        state.set_root,
        locked,
    )
    .sign_with(key)
}

/// Build and sign a round change, **after** making the current position durable.
///
/// N-9: a round change is a signature in the current round like any other. The
/// non-persisting [`round_change_for`] remains for tests and for callers that run
/// their own schedule; every operational driver should use this variant. A
/// position that cannot be written returns an error and no signature exists.
pub fn round_change_for_persisted(
    state: &mut BftState,
    target: Round,
    key: &SigningKey,
    store: &dyn crate::l2persist::AtomicSlotStore,
) -> Result<RoundChange, crate::l2bft::context::BftError> {
    state.persist_position(store)?;
    store.flush()?;
    Ok(round_change_for(state, target, key))
}
