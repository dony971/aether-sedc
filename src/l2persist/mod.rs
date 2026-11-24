//! L2 persistent safety state (mission AU).
//!
//! Mission AT shipped `l2crypto::slots::StorageLockStore`, whose own module
//! documentation already admitted the defect: it is **read-then-write**, so two
//! writers can both decide a slot is empty. This module replaces that pattern
//! with a real compare-and-swap and adds the BFT lock state plus restart
//! recovery.
//!
//! # Layering
//!
//! ```text
//! l2crypto   registry, vote, qc, ready   (pure cryptography, no I/O)
//! l2persist  slot reservation, locks, recovery   (I/O, durability, ordering)
//! ```
//!
//! Dependencies point one way. Nothing here is wired into `node.rs`, `p2p.rs`,
//! `ledger.rs` or `stake.rs`, and no existing file of `l2crypto/` or
//! `consensus/` was modified.
//!
//! # What is guaranteed
//!
//! | Property | Mechanism |
//! |---|---|
//! | one value per slot, even under threads | `sled::Tree::compare_and_swap` |
//! | one process per database, otherwise refuse | exclusive lock file, fail closed |
//! | a signature is never emitted before its reservation is flushed | fixed call order in [`state::sign_vote`] |
//! | an uncertain restoration blocks signing | [`state::RecoveryStatus`] gate |
//!
//! # What is NOT guaranteed
//!
//! - **Power-loss durability.** `flush()` asks the database to fsync; no claim
//!   is made about the storage device below that.
//! - **Atomicity across processes.** Cross-process safety comes from refusing the
//!   second process entirely, not from a distributed CAS.
//! - **Completeness of recovery.** A wiped database is indistinguishable from a
//!   database that never voted. That is why recovery takes an expected anchor
//!   and fails closed when it is absent.
//! - **BFT liveness or finality.** Locks are recorded; the prevote/precommit
//!   protocol is not implemented.

pub mod auth;
pub mod ready;
pub mod round;
pub mod slotlock;
pub mod state;

pub use auth::VoteAuthorization;
pub use ready::{
    load_ready_evidence, ready_key, record_ready, record_readys, recorded_candidates,
    ReadyEvidence, ReadyStoreError, READY_FORMAT_VERSION, READY_PREFIX,
};
pub use round::{
    ChangeSummary, PolSummary, PositionVerdict, RoundError, RoundPosition, ROUND_FORMAT_VERSION,
    ROUND_KEY,
};
pub use slotlock::{
    open_sealed, seal, AtomicSlotStore, CasStore, MemoryAtomicSlotStore, ReserveOutcome,
    SledAtomicSlotStore, SlotKey, SlotReservation, SlotState, SlotStoreError, SlotStoreGuard,
    CAS_ATTEMPTS, SLOT_FORMAT_VERSION, SLOT_PREFIX,
};
pub use state::{
    observe_and_persist, restore, sign_vote, EmitError, LastValidCertificate, LockAction,
    LockedValue, PersistentConsensusState, ProofOfLock, RecoveryReason, RecoveryReport,
    RecoveryStatus, Settlement, SignedOutcome, StateError, HALT_KEY, PROVISIONAL_UNLOCK_RULE,
    STATE_FORMAT_VERSION, STATE_KEY,
};
