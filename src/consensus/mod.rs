//! L2 consensus foundations (A-06.6-AQ `SPC-1`, A-06.6-AR `ARCH-1`).
//!
//! This module tree is **additive**: it introduces the L2 data model beside
//! the existing L1 stake-finality layer and does not modify it. Nothing here
//! is wired into the node: no votes, no QC production, no locks, no
//! transition execution, no L1 sunset, no network activation.
//!
//! # What is implemented (foundations only)
//!
//! | Module | Content |
//! |---|---|
//! | [`generation`] | types, lifecycle state machine, quorum maths, margin parameters, canonical encoding |
//! | [`checkpoint`] | canonical checkpoint format, strict decoding, identity |
//! | [`roots`] | domain-separated BLAKE3 commitments (`state_root`, `finalized_root`, `validator_set_root`) |
//! | [`readiness`] | READY attestations and quorum evaluation |
//! | [`l2_store`] | persistence and startup consistency checks |
//!
//! # What is deliberately absent
//!
//! - BFT voting (prevote / precommit) and QC production or verification;
//! - vote locks and inter-round safety;
//! - validator-set transitions and their admissibility clauses;
//! - L1/L2 migration, `H_conv`, `H_sunset`, `try_finalize` changes;
//! - any claim of liveness, recovery or safety at runtime.
//!
//! # What no function in this module claims
//!
//! A well-formed generation, a canonical checkpoint, a matching root or a
//! satisfied READY quorum proves **structural correctness only**. None of
//! them establishes that the network is live, that a stalled generation can
//! be recovered, or that a validator set is independent.

pub mod checkpoint;
pub mod generation;
pub mod l2_store;
pub mod readiness;
pub mod roots;
pub mod transitions;

pub use checkpoint::{Checkpoint, CheckpointError, CHECKPOINT_FORMAT_VERSION, DOMAIN_CHECKPOINT};
pub use generation::{
    quorum_met, quorum_threshold, CheckpointHeight, Generation, GenerationError, GenerationId,
    GenerationState, MarginParams, Round, ValidatorId, ValidatorWeight,
    GENERATION_ENCODING_VERSION,
};
pub use l2_store::{commit_key, L2Commit, L2Store, L2StoreError, L2_COMMIT_VERSION};
pub use readiness::{
    evaluate, ReadinessConfig, ReadinessOutcome, ReadyAttestation, ReadyError, ReadyExpectation,
    ReadyRejection, READY_VERSION,
};
pub use roots::{
    finalized_root, hash_parts, id_set_root, ids_root, merkle_root, state_root, validator_leaf,
    validator_set_root, FinalityEntry,
};
pub use transitions::{
    candidate_id, ready_root, transition_value_id, AdmittedSet, CandidateOperator,
    GenerationClosure, GenerationLedger, LedgerStatus, SetPolicy, TransitionError,
    TransitionProposal, VerifiedTransition, DOMAIN_CANDIDATE_ID, DOMAIN_TRANSITION_VALUE,
    LEDGER_FORMAT_VERSION, LEDGER_KEY,
};
