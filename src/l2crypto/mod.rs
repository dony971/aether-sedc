//! L2 cryptographic layer: registries, votes, certificates, READY, slots.
//!
//! Mission AT. This module is **additive** and sits beside the AS foundations
//! (`crate::consensus`), whose files are untouched.
//!
//! # Why it lives at crate root rather than under `consensus/`
//!
//! Mission AT requires every file of `src/consensus/` to be preserved. Placing
//! the new tree under `consensus/` would have forced an edit of
//! `src/consensus/mod.rs`; keeping it at `src/l2crypto/` guarantees that no AS
//! file is touched. Dependencies run one way only: `l2crypto` reads
//! `consensus::{generation, roots}`, never the reverse.
//!
//! # The five distinctions this layer exists to make
//!
//! | Question | Answer source |
//! |---|---|
//! | Is this vote correctly signed? | [`vote::ConsensusVote::verify`] |
//! | Is the signer authorised? | [`registry::ValidatorRegistry`] lookup |
//! | Is the weight real? | registry only — a vote carries no weight |
//! | Did the certificate reach quorum? | [`qc::QuorumCertificate::verify`], fully recomputed |
//! | Is the certificate contradictory? | [`qc::QuorumCertificate::conflicts_with`] |
//!
//! # What this layer does not claim
//!
//! - a valid signature is **not** economic legitimacy;
//! - a verified QC is **not** liveness, and not a promise of future progress;
//! - an authenticated READY is **not** future availability;
//! - a distinct key is **not** an independent operator;
//! - the slot store is **not** atomic across processes (see [`slots`]).
//!
//! Nothing here is wired into `node.rs`, `p2p.rs`, `ledger.rs` or `stake.rs`.

pub mod frame;
pub mod qc;
pub mod ready;
pub mod registry;
pub mod slots;
pub mod vote;

pub use frame::{frame, frame_hash};
pub use qc::{QcError, QuorumCertificate, VerifiedQc, QC_FORMAT_VERSION, DOMAIN_QC};
pub use ready::{
    evaluate_signed, ReadyReject, SignedReady, SignedReadyError, SignedReadyExpectation,
    SignedReadinessOutcome, SIGNED_READY_VERSION,
};
pub use registry::{
    validator_id, Admissibility, RegistryEntry, RegistryError, ValidatorRegistry,
    DOMAIN_REGISTRY, DOMAIN_VALIDATOR_ID, REGISTRY_FORMAT_VERSION,
};
pub use slots::{
    commit_vote, commitment_id, LockError, MemoryLockStore, SlotOutcome, StorageLockStore,
    VoteCommitment, VoteLockStore,
};
pub use vote::{
    ConsensusVote, VerifiedVote, VoteError, VotePhase, VoteVerifyError, CONSENSUS_VOTE_VERSION,
    DOMAIN_VOTE, VOTE_LEN,
};
