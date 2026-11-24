//! BFT engine for L2 checkpoints (missions AV, then AW/AX).
//!
//! # What this is
//!
//! A **local** deterministic engine: it accepts votes, builds phase certificates,
//! keeps the normative lock, handles round changes, and decides finality — with no
//! networking and no wiring into `node.rs`.
//!
//! # The rule, now normative
//!
//! Mission AW retrieved the lock rule the corpus actually contains — `LOCK-UPD`
//! (`UPD-NEW` ∪ `UPD-SAME`), `A4'`, `LOCK-EXC`, `LOCK-DUR` (A-06.6-S §4.2), plus
//! the proposal rule `P2`/`P3` and `T-AA` (A-06.6-AA §5, §7). This module
//! implements it as `R-LOCK-1..5` and `AW-LOCK-1..14`:
//!
//! > **The lock is written by a non-Nil precommit, and by nothing else.**
//! > A prevote for another value is allowed only with a verified proof of lock
//! > whose round sits in `[lockR, r)` — the lower bound inclusive (the node with
//! > the highest `lockR` owns the proof that qualifies the others), the upper bound
//! > strict (a proof of the round being voted proves nothing).
//!
//! Consequences, stated plainly:
//!
//! - **Safety** is the theorem of S (`A0, A1, A2, A3-ord, A4', LOCK-UPD,
//!   LOCK-EXC, LOCK-DUR, A8a`), not a consequence of this code.
//! - **Liveness is conditional** — `T-AA` gives `≤ B+1` rounds under H1-H7. This
//!   module does not elect proposers (H2) and does not network, so it cannot
//!   provide progress on its own.
//! - **There is no unlock operation.** A valid proof of lock never changes `V`; it
//!   authorizes one prevote. Erasing `lockV` would destroy `lockR`, which `L4`
//!   needs, so the absence is a safety requirement (A-06.6-X `A9-5`).
//! - **No operator path.** No command, flag or clock can move a lock.
//!
//! # What is reused
//!
//! | Layer | Reused |
//! |---|---|
//! | AT | `ConsensusVote`, `QuorumCertificate` (7 recalculations), `ValidatorRegistry`, `frame` |
//! | AU | `AtomicSlotStore`, `sign_vote` (reserve → flush → sign → record), `PersistentConsensusState` |
//! | AS | `Generation`, `Checkpoint::validate`/`validate_link`, `quorum_met` |
//!
//! Mission BU **removed** `apply_provisional_unlock` and `apply_and_persist`:
//! `AW-LOCK-5` forbids unlocking, and this module never called them. Since BU,
//! `sign_vote` also requires a `l2persist::VoteAuthorization`, produced only by
//! `for_prevote` (`A4'`) or `for_precommit` (`N-PC-1` / `AW-LOCK-8`).
//!
//! # Not implemented
//!
//! Networking, node activation, generation transitions, slashing, liveness
//! guarantees.

pub mod cert;
pub mod context;
pub mod engine;
pub mod halt_proof;
pub mod proposer;
pub mod round;
pub mod round_wire;
pub mod sync;
pub mod timer;

pub use cert::{PrecommitCertificate, PrevoteCertificate, ProofOfLock};
pub use context::{BftContext, BftError, Precommit, Prevote, VoteOutcome};
pub use engine::{
    finality_key, pending_install_key, restore_engine, BftState, FinalityDecision, HaltReason,
    PendingInstall, RestoredEngine, RoundState, FINALITY_FORMAT_VERSION, FINALITY_PREFIX, HALT_KEY,
    NIL_VALUE, PENDING_INSTALL_FORMAT_VERSION, PENDING_INSTALL_PREFIX,
};
pub use halt_proof::{HaltProof, HaltProofError, HALT_PROOF_TAG, HALT_PROOF_VERSION};
pub use proposer::{
    distribution, is_proposer, proposer_for, schedule, schedule_seed, ProposerChoice,
    DOMAIN_PROPOSER,
};
pub use round::{
    RoundChange, RoundChangeEvidence, RoundChangeOutcome, RoundChangeSet, DOMAIN_ROUND_CHANGE,
    MAX_ROUND_JUMP, ROUND_CHANGE_VERSION,
};
pub use sync::{
    bundle_from, check_commitments, compare_histories, install_history, participation,
    verify_history, GenerationSpec, HistoryAgreement, Participation, SyncAnchor, SyncBundle,
    SyncError, SyncLink, VerifiedHistory, VerifiedLink, VerifiedRoots, SYNC_FORMAT_VERSION,
};
pub use timer::{
    round_change_for, round_change_for_persisted, RoundTimer, DEFAULT_BASE_STEPS, MAX_BACKOFF_SHIFT,
};
