//! Validator generation transitions (`R1-AL-2`: `R-SET-1..7`, `R-TRANS-4..7`).
//!
//! # What this module decides, and what it refuses to decide
//!
//! It turns a **candidate set** into an **admitted set** by applying the seven
//! `R-SET` rules to declared operator data, and it verifies a `TRANSITION`
//! proposal against `R-TRANS-5'` (C1-C7). Every weight, quorum, identifier and
//! root is **derived** here — nothing a message declares is trusted.
//!
//! It does not vote, and it cannot make a transition happen: the decision is
//! still a `QC` of the existing BFT engine over the transition `value_id`. This
//! module only refuses proposals that must not be voted for.
//!
//! # What is verifiable, and what is only declared
//!
//! | Condition | Verifiable here? |
//! |---|---|
//! | `R-SET-1..4` eligibility, weight, cardinality, operator uniqueness | **yes** |
//! | `R-SET-5` churn | **yes** |
//! | `R-SET-6` composition | **yes** (given the declared `F_b_new`) |
//! | `R-SET-7` READY quorum | **yes** (signatures, weights from the candidate set) |
//! | independence of operators (`H-INDEP`) | **no** — a declaration |
//! | real `F_b_new` (`H-FB`) | **no** — a declaration |
//! | Sybil resistance at entity level | **no** — not a cryptographic property |
//!
//! Nothing in this module may be read as establishing the last three.
//!
//! # Determinism
//!
//! No clock, no randomness, no iteration order dependence: candidates are sorted
//! by operator id before anything is derived, and all roots come from sorted
//! inputs. Two nodes holding the same valid data compute the same active set.

use std::fmt;

use thiserror::Error;

use crate::consensus::generation::{
    quorum_met, quorum_threshold, CheckpointHeight, GenerationId, GenerationNumber, ValidatorId,
    ValidatorWeight,
};
use crate::consensus::roots::{generation_id_from, hash_parts, ids_root, validator_set_root};
use crate::l2crypto::ready::{
    evaluate_signed, SignedReadinessOutcome, SignedReady, SignedReadyExpectation,
};
use crate::l2crypto::registry::{validator_id, Admissibility, RegistryEntry, ValidatorRegistry};
use crate::l2persist::{open_sealed, seal, CasStore};

/// Domain tag of `candidate_id` (`R1-AL-2` §1).
pub const DOMAIN_CANDIDATE_ID: &[u8] = b"AETHER-L2-CANDIDATE-v1";

/// Domain tag of the transition value (`R1-AL-2` §1).
pub const DOMAIN_TRANSITION_VALUE: &[u8] = b"AETHER-L2-TRANSITION-v1";

/// Format version of the persisted generation ledger.
pub const LEDGER_FORMAT_VERSION: u8 = 1;

/// Storage key of the generation ledger.
pub const LEDGER_KEY: &str = "l2/v3/bft/generations";

/// Errors of the admissibility and transition layer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransitionError {
    /// `R-SET-3`: too few or too many members.
    #[error("R-SET-3: cardinality {count} outside [{min}, {max}]")]
    Cardinality {
        /// Declared member count.
        count: usize,
        /// Minimum.
        min: usize,
        /// Maximum.
        max: usize,
    },

    /// `R-SET-1`: an operator is not eligible.
    #[error("R-SET-1: operator {operator} is not eligible ({reason})")]
    NotEligible {
        /// Operator identifier, hex.
        operator: String,
        /// Why.
        reason: &'static str,
    },

    /// `R-SET-1`/`R-SET-2`: the deposit is out of range.
    #[error("R-SET-1: operator {0} deposit {1} is below the minimum {2}")]
    DepositTooLow(String, u64, u64),

    /// `R-SET-2`: a derived weight leaves the allowed window.
    #[error("R-SET-2: derived weight {weight} outside [{min}, {max}]")]
    WeightOutOfRange {
        /// Derived weight.
        weight: u64,
        /// Minimum.
        min: u64,
        /// Maximum.
        max: u64,
    },

    /// `SetPolicy` is internally inconsistent (configuration error).
    #[error("SetPolicy: {0}")]
    Policy(&'static str),

    /// `R-SET-2`: the total weight leaves the allowed window.
    #[error("R-SET-2: total weight {total} outside [1, {max}]")]
    TotalWeightOutOfRange {
        /// Derived total.
        total: u64,
        /// Maximum.
        max: u64,
    },

    /// `R-SET-4`: two candidates share a key or an operator id.
    #[error("R-SET-4: duplicate {what} ({value})")]
    Duplicate {
        /// `"public key"` or `"operator id"`.
        what: &'static str,
        /// Offending value, hex.
        value: String,
    },

    /// `R-SET-5`: too much weight changed in one transition.
    #[error("R-SET-5: retained weight {retained} below the churn floor {floor}")]
    Churn {
        /// Weight shared by the old and the new set.
        retained: u64,
        /// `W_old - churn_max_weight`.
        floor: u64,
    },

    /// `R-SET-6`: the declared faulty weight is not admissible.
    #[error("R-SET-6: declared F_b_new {declared} above the bound {bound}")]
    Composition {
        /// Declared `F_b_new`.
        declared: u64,
        /// `floor((W_new - 1) / 3)`, the integer form of `3·f < W_new`.
        bound: u64,
    },

    /// `R-SET-7` / `R-TRANS-5'` C7: the READY certificate is not quorate.
    #[error("R-SET-7: READY weight {support} below the candidate quorum {quorum}")]
    ReadyNotQuorate {
        /// Weight of the accepted READY.
        support: u64,
        /// `q_new`.
        quorum: u64,
    },

    /// `R-TRANS-5'` C1/C2: the parent is not the expected checkpoint.
    #[error("R-TRANS-5 C1/C2: {0}")]
    Parent(&'static str),

    /// `R-TRANS-5'` C2: the parent checkpoint is itself a transition.
    #[error("R-TRANS-5 C2: the parent checkpoint already carries a transition")]
    ParentIsTransition,

    /// `R-TRANS-5'` C3: another validator set is in force.
    #[error("R-TRANS-5 C3: old set root {found} is not the one in force ({expected})")]
    WrongOldSetRoot {
        /// Expected root.
        expected: String,
        /// Proposed root.
        found: String,
    },

    /// The proposal targets another generation or height.
    #[error("proposal context mismatch: {0}")]
    Context(&'static str),

    /// The ledger refuses: a generation is closed, or a replay was seen.
    #[error("generation ledger: {0}")]
    Ledger(String),

    /// Persistent state could not be read; signing must stop.
    #[error("generation ledger unreadable: {0}")]
    Persistence(String),
}

/// Policy parameters of a generation (`R-SET-1..6`).
///
/// These are **configuration**, not consensus values: two nodes with different
/// policies compute different admitted sets and must not share a network. They
/// are passed in explicitly rather than read from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetPolicy {
    /// `R-SET-1`: minimum deposit to be a member.
    pub min_deposit: u64,
    /// `R-SET-2`: deposit unit that maps to one weight point.
    pub deposit_unit: u64,
    /// `R-SET-1`: minimum maturity, in blocks.
    pub maturity_blocks: u64,
    /// `R-SET-2`: floor weight per member.
    pub min_weight: u64,
    /// `R-SET-2`: cap weight per member.
    pub max_weight: u64,
    /// `R-SET-2`: maximum total weight.
    pub w_max: u64,
    /// `R-SET-3`: minimum member count.
    pub n_min: usize,
    /// `R-SET-3`: maximum member count.
    pub n_max: usize,
    /// `R-SET-5`: maximum weight that may leave the set in one transition.
    pub churn_max_weight: u64,
    /// `R-SET-6`: **declared** faulty weight of the new set (`H-FB`).
    pub f_b_new: u64,
    /// Freshness window of a READY, in heights (`SignedReadyExpectation`).
    pub d_ready: u64,
}

/// Declared operator data of one candidate (`R-SET-1`).
///
/// Every field is **declared** input. Eligibility is decided here; authenticity
/// of the key is decided by the signature check in `R-SET-7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateOperator {
    /// Operator identity (economic entity). `R-SET-4` uniqueness applies to it.
    pub operator: [u8; 32],
    /// Ed25519 public key.
    pub public_key: [u8; 32],
    /// Bonded deposit.
    pub deposit: u64,
    /// Blocks since the deposit matured.
    pub maturity_blocks: u64,
    /// Withdrawal in progress.
    pub unbonding: bool,
    /// Jailed by the chain.
    pub jailed: bool,
}

impl SetPolicy {
    /// Validate the internal consistency of the policy.
    ///
    /// Called before any weight derivation or admission logic.
    pub fn validate(&self) -> Result<(), TransitionError> {
        if self.min_weight > self.max_weight {
            return Err(TransitionError::Policy("min_weight above max_weight"));
        }
        if self.max_weight == 0 || self.w_max == 0 {
            return Err(TransitionError::Policy("a weight bound is zero"));
        }
        if self.w_max < self.min_weight {
            return Err(TransitionError::Policy("w_max below min_weight"));
        }
        if self.deposit_unit == 0 {
            return Err(TransitionError::Policy("deposit_unit is zero"));
        }
        if self.n_min == 0 || self.n_min > self.n_max {
            return Err(TransitionError::Policy("member bounds are inverted"));
        }
        Ok(())
    }
}

impl CandidateOperator {
    /// Weight derived from the deposit (`R-SET-2`), never declared directly.
    pub fn derived_weight(&self, policy: &SetPolicy) -> ValidatorWeight {
        let unit = policy.deposit_unit.max(1);
        let scaled = self.deposit / unit;
        // Never panic: `min`/`max` cannot panic, unlike `clamp` when min > max.
        ValidatorWeight(scaled.min(policy.max_weight).max(policy.min_weight))
    }

    /// `R-SET-1` eligibility.
    pub fn ineligibility(&self, policy: &SetPolicy) -> Option<&'static str> {
        if self.jailed {
            return Some("jailed");
        }
        if self.unbonding {
            return Some("unbonding");
        }
        if self.deposit < policy.min_deposit {
            return Some("deposit below minimum");
        }
        if self.maturity_blocks < policy.maturity_blocks {
            return Some("immature deposit");
        }
        None
    }
}

/// A candidate set that passed `R-SET-1..6`.
///
/// The registry (weights, total, quorum, set root, generation id) is built here
/// from the derived weights; a caller cannot inject any of those values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedSet {
    registry: ValidatorRegistry,
    members: Vec<(ValidatorId, ValidatorWeight)>,
    total: ValidatorWeight,
    quorum: ValidatorWeight,
    set_root: [u8; 32],
}

impl AdmittedSet {
    /// Apply `R-SET-1..6` to declared candidates.
    ///
    /// `old` is the generation in force, used for `R-SET-5` (churn). Pass `None`
    /// for a genesis set, where no churn bound applies.
    pub fn admit(
        policy: &SetPolicy,
        candidates: &[CandidateOperator],
        generation_number: GenerationNumber,
        epoch_pin: u64,
        old: Option<&ValidatorRegistry>,
    ) -> Result<Self, TransitionError> {
        // Validate the policy before any derived computation.
        policy.validate()?;
        // R-SET-3 — cardinality over the *declared* list.
        if candidates.len() < policy.n_min || candidates.len() > policy.n_max {
            return Err(TransitionError::Cardinality {
                count: candidates.len(),
                min: policy.n_min,
                max: policy.n_max,
            });
        }

        // R-SET-1 — eligibility, checked before anything is derived.
        for candidate in candidates {
            if let Some(reason) = candidate.ineligibility(policy) {
                return Err(TransitionError::NotEligible {
                    operator: hex::encode(candidate.operator),
                    reason,
                });
            }
        }

        // R-SET-4 — operator uniqueness and key uniqueness.
        let mut operators: Vec<[u8; 32]> = Vec::with_capacity(candidates.len());
        let mut keys: Vec<[u8; 32]> = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if operators.contains(&candidate.operator) {
                return Err(TransitionError::Duplicate {
                    what: "operator id",
                    value: hex::encode(candidate.operator),
                });
            }
            if keys.contains(&candidate.public_key) {
                return Err(TransitionError::Duplicate {
                    what: "public key",
                    value: hex::encode(candidate.public_key),
                });
            }
            operators.push(candidate.operator);
            keys.push(candidate.public_key);
        }

        // R-SET-2 — weights are derived, then sorted by validator id.
        let mut members: Vec<(ValidatorId, ValidatorWeight)> = candidates
            .iter()
            .map(|candidate| {
                (
                    validator_id(&candidate.public_key),
                    candidate.derived_weight(policy),
                )
            })
            .collect();
        members.sort_by_key(|(id, _)| *id);
        let mut total: u64 = 0;
        for (_, weight) in &members {
            if weight.get() < policy.min_weight || weight.get() > policy.max_weight {
                return Err(TransitionError::WeightOutOfRange {
                    weight: weight.get(),
                    min: policy.min_weight,
                    max: policy.max_weight,
                });
            }
            total =
                total
                    .checked_add(weight.get())
                    .ok_or(TransitionError::TotalWeightOutOfRange {
                        total: u64::MAX,
                        max: policy.w_max,
                    })?;
        }
        if total == 0 || total > policy.w_max {
            return Err(TransitionError::TotalWeightOutOfRange {
                total,
                max: policy.w_max,
            });
        }
        let total = ValidatorWeight(total);
        let quorum = quorum_threshold(total);

        // R-SET-6 — composition bound, with the declared F_b_new (H-FB).
        //
        // Mission BM (N-2 / N-SET-3): the safety condition is **strict** —
        // `3·f < W`, not `3·f <= W`. With `Q = ceil(2·W/3)`, two quorums of
        // weight `Q` intersect in at least `2·Q - W`; for `3 | W` that is exactly
        // `W/3`, so a faulty weight of `W/3` can own the whole intersection.
        // `f <= (W-1)/3` is the integer form of `3·f < W` and needs no division
        // by three of a `u64` sum (`W >= 1` is already checked above).
        //
        // The old `min(n-1, W-Q)` bound was expressed partly in *validators* and
        // partly in weight, and at `3 | W` it admitted `f = W/3`. The bound is a
        // weight: a dominant validator above `W/3` is refused by this single
        // rule, and an equal-weight set of any size is measured by the same
        // fraction rather than by its cardinality.
        let bound = total.0.saturating_sub(1) / 3;
        if policy.f_b_new > bound {
            return Err(TransitionError::Composition {
                declared: policy.f_b_new,
                bound,
            });
        }

        // R-SET-5 — churn, only for a transition.
        if let Some(old) = old {
            let retained: u64 = members
                .iter()
                .filter(|(id, _)| old.get(id).is_some())
                .map(|(_, weight)| weight.get())
                .sum();
            let floor = old
                .total_voting_weight()
                .0
                .saturating_sub(policy.churn_max_weight);
            if retained < floor {
                return Err(TransitionError::Churn { retained, floor });
            }
        }

        let entries: Vec<RegistryEntry> = candidates
            .iter()
            .map(|candidate| {
                RegistryEntry::new(
                    candidate.public_key,
                    candidate.derived_weight(policy),
                    Admissibility::Eligible,
                )
            })
            .collect();
        let set_root = validator_set_root(&members);
        let generation = generation_id_from(generation_number, epoch_pin, set_root);
        let registry = ValidatorRegistry::new(generation, &entries).map_err(|e| {
            TransitionError::Ledger(format!("building the candidate registry failed: {e}"))
        })?;
        debug_assert_eq!(registry.set_root(), set_root);

        Ok(Self {
            registry,
            members,
            total,
            quorum,
            set_root,
        })
    }

    /// Registry of the candidate set, with derived weights.
    pub fn registry(&self) -> &ValidatorRegistry {
        &self.registry
    }

    /// Sorted `(validator, weight)` pairs.
    pub fn members(&self) -> &[(ValidatorId, ValidatorWeight)] {
        &self.members
    }

    /// Derived total weight `W_new`.
    pub fn total(&self) -> ValidatorWeight {
        self.total
    }

    /// Derived quorum `q_new = ceil(2·W_new/3)`.
    pub fn quorum(&self) -> ValidatorWeight {
        self.quorum
    }

    /// Derived set root.
    pub fn set_root(&self) -> [u8; 32] {
        self.set_root
    }

    /// Derived generation identifier of the candidate.
    pub fn generation(&self) -> GenerationId {
        self.registry.generation()
    }

    /// `candidate_id = H(g_source ‖ h_close ‖ new_set_root ‖ S_old_root)`.
    pub fn candidate_id(
        &self,
        g_source: GenerationId,
        h_close: CheckpointHeight,
        old_set_root: [u8; 32],
    ) -> [u8; 32] {
        candidate_id(g_source, h_close, self.set_root, old_set_root)
    }

    /// Registry of this candidate set for one transition position.
    ///
    /// BO-F1 (mission BP): the identifier of the generation a closure opens is
    /// **not a free label** -- it is the transition itself. The quorum signs the
    /// closing checkpoint, whose `transition_id` is
    /// `candidate_id(g_source, h_close, set_root, old_set_root)`, so a registry
    /// built here is bound to exactly the transition that authorised it. The same
    /// members under another label are a different generation, and a node cannot
    /// install one for the other.
    pub fn registry_for(
        &self,
        old: &ValidatorRegistry,
        h_close: CheckpointHeight,
    ) -> Result<ValidatorRegistry, TransitionError> {
        let id = self.candidate_id(old.generation(), h_close, old.set_root());
        let entries: Vec<RegistryEntry> = self
            .registry
            .entries()
            .iter()
            .map(|entry| RegistryEntry::new(entry.public_key, entry.weight, entry.admissibility))
            .collect();
        let registry = ValidatorRegistry::new(GenerationId(id), &entries).map_err(|e| {
            TransitionError::Ledger(format!("rebuilding the candidate registry failed: {e}"))
        })?;
        debug_assert_eq!(registry.set_root(), self.set_root);
        Ok(registry)
    }
}

/// `candidate_id = H(g_source ‖ h_close ‖ new_set_root ‖ S_old_root)` (`R1-AL-2` §1).
pub fn candidate_id(
    g_source: GenerationId,
    h_close: CheckpointHeight,
    new_set_root: [u8; 32],
    old_set_root: [u8; 32],
) -> [u8; 32] {
    hash_parts(
        DOMAIN_CANDIDATE_ID,
        &[
            &g_source.0,
            &h_close.get().to_le_bytes(),
            &new_set_root,
            &old_set_root,
        ],
    )
}

/// `value_id` of the transition decided by the existing BFT engine.
///
/// `ready_root` binds which READY signatures backed the decision: two proposals
/// with the same set but different READY are **different values**.
#[allow(clippy::too_many_arguments)]
pub fn transition_value_id(
    network: u64,
    height: CheckpointHeight,
    generation: GenerationId,
    parent_digest: [u8; 32],
    old_set_root: [u8; 32],
    new_set_root: [u8; 32],
    ready_root: [u8; 32],
) -> [u8; 32] {
    hash_parts(
        DOMAIN_TRANSITION_VALUE,
        &[
            &network.to_le_bytes(),
            &height.get().to_le_bytes(),
            &generation.0,
            &parent_digest,
            &old_set_root,
            &new_set_root,
            &ready_root,
        ],
    )
}

/// Root over the accepted READY signers. Deterministic in signer order.
pub fn ready_root(outcome: &SignedReadinessOutcome) -> [u8; 32] {
    let ids: Vec<[u8; 32]> = outcome.accepted.iter().map(|id| id.0).collect();
    ids_root(&ids)
}

/// A `TRANSITION` proposal as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionProposal {
    /// Network.
    pub network: u64,
    /// Height at which the transition is decided (`h_close`).
    pub height: CheckpointHeight,
    /// Generation in force (`g_source`).
    pub generation: GenerationId,
    /// Digest of the previous decision.
    pub parent_digest: [u8; 32],
    /// Set root of the generation in force.
    pub old_set_root: [u8; 32],
    /// Declared candidates.
    pub candidates: Vec<CandidateOperator>,
    /// Number of the generation being installed.
    pub next_number: GenerationNumber,
    /// `epoch_pin` of the generation being installed.
    pub next_epoch_pin: u64,
    /// READY attestations of the candidate set.
    pub readys: Vec<SignedReady>,
}

/// A proposal that satisfies `R-TRANS-5'` C1-C7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransition {
    /// Network.
    pub network: u64,
    /// Height of the decision.
    pub height: CheckpointHeight,
    /// Generation in force.
    pub generation: GenerationId,
    /// Digest of the previous decision.
    pub parent_digest: [u8; 32],
    /// Set root in force.
    pub old_set_root: [u8; 32],
    /// Candidate set, admitted and derived.
    pub new_set: AdmittedSet,
    /// `candidate_id`.
    pub candidate_id: [u8; 32],
    /// Root over the accepted READY signers.
    pub ready_root: [u8; 32],
    /// `value_id` the generation in force must decide.
    pub value_id: [u8; 32],
    /// Outcome of the READY evaluation.
    pub ready: SignedReadinessOutcome,
}

impl VerifiedTransition {
    /// `S_old` root, for the ledger closure record.
    pub fn new_set_root(&self) -> [u8; 32] {
        self.new_set.set_root()
    }
}

/// Verify a `TRANSITION` proposal against `R-TRANS-5'`.
///
/// `previous` is the decision at `height - 1` (C1/C2); `old` is the registry in
/// force (C3). The seven conditions are checked in the normative order and each
/// failure names its condition.
pub fn verify_transition(
    proposal: &TransitionProposal,
    policy: &SetPolicy,
    old: &ValidatorRegistry,
    expected_parent_digest: [u8; 32],
    previous_is_transition: bool,
) -> Result<VerifiedTransition, TransitionError> {
    // C1 — the parent digest is the previous decision.
    if proposal.parent_digest != expected_parent_digest {
        return Err(TransitionError::Parent(
            "parent digest is not the previous decision",
        ));
    }
    // C2 — the previous decision is not itself a transition.
    if previous_is_transition {
        return Err(TransitionError::ParentIsTransition);
    }
    // C3 — the set root in force is the one the proposal names.
    if proposal.old_set_root != old.set_root() {
        return Err(TransitionError::WrongOldSetRoot {
            expected: hex::encode(old.set_root()),
            found: hex::encode(proposal.old_set_root),
        });
    }
    if proposal.generation != old.generation() {
        return Err(TransitionError::Context(
            "proposal names another generation",
        ));
    }

    // C4/C5/C6 — R-SET-1..6, derived here from the declared candidates.
    let new_set = AdmittedSet::admit(
        policy,
        &proposal.candidates,
        proposal.next_number,
        proposal.next_epoch_pin,
        Some(old),
    )?;

    // C7 / R-SET-7 — READY quorum, weights taken from the **candidate** registry.
    let candidate_id = new_set.candidate_id(proposal.generation, proposal.height, old.set_root());
    let expectation = SignedReadyExpectation {
        network: proposal.network,
        generation: proposal.generation,
        candidate: candidate_id,
        new_set_root: new_set.set_root(),
        reference_checkpoint: proposal.parent_digest,
        h_close: proposal.height,
        d_ready: policy.d_ready,
    };
    let ready = evaluate_signed(&proposal.readys, &expectation, new_set.registry());
    if !quorum_met(ready.weight, new_set.total()) {
        return Err(TransitionError::ReadyNotQuorate {
            support: ready.weight.get(),
            quorum: new_set.quorum().get(),
        });
    }

    let ready_root = ready_root(&ready);
    let value_id = transition_value_id(
        proposal.network,
        proposal.height,
        proposal.generation,
        proposal.parent_digest,
        proposal.old_set_root,
        new_set.set_root(),
        ready_root,
    );

    Ok(VerifiedTransition {
        network: proposal.network,
        height: proposal.height,
        generation: proposal.generation,
        parent_digest: proposal.parent_digest,
        old_set_root: proposal.old_set_root,
        new_set,
        candidate_id,
        ready_root,
        value_id,
        ready,
    })
}

/// One decided transition, as recorded by the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationClosure {
    /// Height at which the transition was decided (`h_close`).
    pub height: CheckpointHeight,
    /// Generation that closes.
    pub generation: GenerationId,
    /// `value_id` of the decided transition.
    pub value_id: [u8; 32],
    /// `candidate_id`.
    pub candidate_id: [u8; 32],
    /// Set root of the generation that becomes active.
    pub new_set_root: [u8; 32],
}

/// Verdict of the generation ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerStatus {
    /// Consistent.
    Clean,
    /// Contradictory evidence was seen: no signature is allowed.
    Halted(String),
}

impl LedgerStatus {
    /// Whether signing is allowed.
    pub fn may_sign(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

/// The chain of generations as this node knows it (`R-TRANS-7`).
///
/// The ledger is the only place that answers "which generation may vote at
/// height `h`". It enforces `R-TRANS-7a` (exactly one active generation per
/// height) by construction: activation moves `first_height` to `h_close + 1`
/// and replaces `active` atomically with the closure that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationLedger {
    /// Network.
    pub network: u64,
    /// Generation currently in force.
    pub active: GenerationId,
    /// Its number.
    pub active_number: GenerationNumber,
    /// First height at which it may decide.
    pub first_height: CheckpointHeight,
    /// Decided closures, ordered by height.
    pub closures: Vec<GenerationClosure>,
    /// Verdict.
    pub status: LedgerStatus,
}

impl GenerationLedger {
    /// A ledger that starts at a genesis generation.
    pub fn new(network: u64, genesis: GenerationId) -> Self {
        Self {
            network,
            active: genesis,
            active_number: 0,
            first_height: CheckpointHeight::GENESIS,
            closures: Vec::new(),
            status: LedgerStatus::Clean,
        }
    }

    /// Whether `generation` may decide at `height` (`R-TRANS-4`, `R-TRANS-7a`).
    pub fn may_vote(
        &self,
        generation: GenerationId,
        height: CheckpointHeight,
    ) -> Result<(), TransitionError> {
        if let LedgerStatus::Halted(reason) = &self.status {
            return Err(TransitionError::Ledger(format!("halted: {reason}")));
        }
        if generation != self.active {
            return Err(TransitionError::Ledger(format!(
                "generation {} is closed; {} is in force",
                hex::encode(generation.0),
                hex::encode(self.active.0)
            )));
        }
        if height.get() < self.first_height.get() {
            return Err(TransitionError::Ledger(format!(
                "height {} precedes the activation of generation {} at {}",
                height.get(),
                hex::encode(self.active.0),
                self.first_height.get()
            )));
        }
        Ok(())
    }

    /// Record the decision of a transition and install the next generation.
    ///
    /// This is `R-TRANS-6` (`h_new = h + 1`, `g_new = g + 1`) and `R-TRANS-7b`
    /// (the closing set stops at `h_close`, the new one starts at `h_close + 1`).
    /// A closure that contradicts an existing one halts the ledger: neither side
    /// is ever chosen.
    pub fn apply_closure(
        &mut self,
        closure: GenerationClosure,
        next: GenerationId,
        next_number: GenerationNumber,
    ) -> Result<(), TransitionError> {
        if let LedgerStatus::Halted(reason) = &self.status {
            return Err(TransitionError::Ledger(format!("halted: {reason}")));
        }
        // A decision is identified by its height and its `value_id`. The same
        // decision seen twice is a no-op; two different decisions at one height
        // halt the ledger and no side is ever chosen.
        for existing in &self.closures {
            if existing.height != closure.height {
                continue;
            }
            if existing.value_id == closure.value_id {
                return Ok(());
            }
            let reason = format!(
                "two transitions decided at height {}: {} and {}",
                closure.height.get(),
                hex::encode(existing.value_id),
                hex::encode(closure.value_id)
            );
            self.status = LedgerStatus::Halted(reason.clone());
            return Err(TransitionError::Ledger(reason));
        }
        if closure.generation != self.active {
            return Err(TransitionError::Ledger(format!(
                "closure names generation {}, which is not in force",
                hex::encode(closure.generation.0)
            )));
        }
        if closure.height.get() < self.first_height.get() {
            // R-TRANS-7a: a closure below the first height of the active
            // generation would overlap the previous one. Refused, not repaired.
            return Err(TransitionError::Ledger(format!(
                "closure height {} precedes the activation of the active generation at {}",
                closure.height.get(),
                self.first_height.get()
            )));
        }
        if next_number != self.active_number.saturating_add(1) {
            return Err(TransitionError::Ledger(format!(
                "generation {} would be skipped (expected {})",
                next_number,
                self.active_number.saturating_add(1)
            )));
        }

        self.closures.push(closure);
        self.closures.sort_by_key(|c| c.height.get());
        self.active = next;
        self.active_number = next_number;
        self.first_height = closure.height.next();
        Ok(())
    }

    /// Number of generations that closed before `height` (`R-TRANS-7a`).
    pub fn generation_at(&self, height: CheckpointHeight) -> u64 {
        self.closures
            .iter()
            .filter(|closure| closure.height.get() < height.get())
            .count() as u64
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(LEDGER_FORMAT_VERSION);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.active.0);
        out.extend_from_slice(&self.active_number.to_le_bytes());
        out.extend_from_slice(&self.first_height.get().to_le_bytes());
        out.extend_from_slice(&(self.closures.len() as u32).to_le_bytes());
        for closure in &self.closures {
            out.extend_from_slice(&closure.height.get().to_le_bytes());
            out.extend_from_slice(&closure.generation.0);
            out.extend_from_slice(&closure.value_id);
            out.extend_from_slice(&closure.candidate_id);
            out.extend_from_slice(&closure.new_set_root);
        }
        match &self.status {
            LedgerStatus::Clean => out.push(0),
            LedgerStatus::Halted(reason) => {
                out.push(1);
                let bytes = reason.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
        }
        out
    }

    /// Strict canonical decoding.
    ///
    /// A ledger whose closures contain two different transitions at one height,
    /// or whose closures are not strictly increasing, is **unreadable**: the
    /// caller must refuse to sign rather than pick a side.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransitionError> {
        let mut cursor = 0usize;
        let take = |cursor: &mut usize, n: usize| -> Result<&[u8], TransitionError> {
            if bytes.len() < *cursor + n {
                return Err(TransitionError::Persistence("truncated ledger".to_string()));
            }
            let slice = &bytes[*cursor..*cursor + n];
            *cursor += n;
            Ok(slice)
        };
        if *take(&mut cursor, 1)? != [LEDGER_FORMAT_VERSION] {
            return Err(TransitionError::Persistence(
                "unknown ledger version".to_string(),
            ));
        }
        let mut word = [0u8; 8];
        word.copy_from_slice(take(&mut cursor, 8)?);
        let network = u64::from_le_bytes(word);
        let mut active = [0u8; 32];
        active.copy_from_slice(take(&mut cursor, 32)?);
        word.copy_from_slice(take(&mut cursor, 8)?);
        let active_number = u64::from_le_bytes(word);
        word.copy_from_slice(take(&mut cursor, 8)?);
        let first_height = CheckpointHeight(u64::from_le_bytes(word));
        let mut count = [0u8; 4];
        count.copy_from_slice(take(&mut cursor, 4)?);
        let closure_count = u32::from_le_bytes(count) as usize;
        let mut closures: Vec<GenerationClosure> = Vec::with_capacity(closure_count);
        for _ in 0..closure_count {
            word.copy_from_slice(take(&mut cursor, 8)?);
            let height = CheckpointHeight(u64::from_le_bytes(word));
            let mut generation = [0u8; 32];
            generation.copy_from_slice(take(&mut cursor, 32)?);
            let mut value_id = [0u8; 32];
            value_id.copy_from_slice(take(&mut cursor, 32)?);
            let mut candidate_id = [0u8; 32];
            candidate_id.copy_from_slice(take(&mut cursor, 32)?);
            let mut new_set_root = [0u8; 32];
            new_set_root.copy_from_slice(take(&mut cursor, 32)?);
            closures.push(GenerationClosure {
                height,
                generation: GenerationId(generation),
                value_id,
                candidate_id,
                new_set_root,
            });
        }
        let tag = take(&mut cursor, 1)?;
        let status = match tag[0] {
            0 => LedgerStatus::Clean,
            1 => {
                let mut len = [0u8; 4];
                len.copy_from_slice(take(&mut cursor, 4)?);
                let n = u32::from_le_bytes(len) as usize;
                let text = String::from_utf8_lossy(take(&mut cursor, n)?).to_string();
                LedgerStatus::Halted(text)
            }
            other => {
                return Err(TransitionError::Persistence(format!(
                    "unknown ledger status {other}"
                )))
            }
        };
        if cursor != bytes.len() {
            return Err(TransitionError::Persistence(
                "trailing ledger bytes".to_string(),
            ));
        }
        // N-5 / D15: a ledger that decodes but does not describe one chain is not a
        // state the node may act on. These invariants are exactly the ones the only
        // writer (`apply_closure`) maintains; an encoding that violates them was
        // produced by something else and is refused rather than repaired.
        let mut previous_height: Option<u64> = None;
        let mut generations: Vec<GenerationId> = Vec::with_capacity(closures.len());
        for closure in &closures {
            if closure.height.get() == u64::MAX {
                return Err(TransitionError::Persistence(
                    "ledger records a closure at u64::MAX, which has no successor".to_string(),
                ));
            }
            if let Some(previous) = previous_height {
                if closure.height.get() <= previous {
                    return Err(TransitionError::Persistence(
                        "ledger closures are not strictly increasing".to_string(),
                    ));
                }
            }
            if generations.contains(&closure.generation) {
                return Err(TransitionError::Persistence(
                    "ledger closes the same generation twice".to_string(),
                ));
            }
            if closure.generation == GenerationId(active) {
                return Err(TransitionError::Persistence(
                    "ledger lists the active generation as closed".to_string(),
                ));
            }
            generations.push(closure.generation);
            previous_height = Some(closure.height.get());
        }
        match previous_height {
            None => {
                if active_number != 0 || first_height != CheckpointHeight::GENESIS {
                    return Err(TransitionError::Persistence(
                        "a ledger with no closure must be the genesis generation at height 0"
                            .to_string(),
                    ));
                }
            }
            Some(last) => {
                if active_number != closures.len() as u64 {
                    return Err(TransitionError::Persistence(format!(
                        "ledger active number {active_number} does not match its {} closures",
                        closures.len()
                    )));
                }
                if first_height.get() != last + 1 {
                    return Err(TransitionError::Persistence(format!(
                        "ledger first height {} is not one past its last closure {}",
                        first_height.get(),
                        last
                    )));
                }
            }
        }
        Ok(Self {
            network,
            active: GenerationId(active),
            active_number,
            first_height,
            closures,
            status,
        })
    }

    /// Persist the ledger durably through the compare-and-swap store.
    pub fn persist(&self, store: &dyn CasStore) -> Result<(), TransitionError> {
        let sealed = seal(&self.encode());
        let current = store
            .get(LEDGER_KEY)
            .map_err(|e| TransitionError::Persistence(e.to_string()))?;
        let swapped = store
            .cas(LEDGER_KEY, current.as_deref(), &sealed)
            .map_err(|e| TransitionError::Persistence(e.to_string()))?;
        if !swapped {
            return Err(TransitionError::Persistence(
                "concurrent writer changed the generation ledger".to_string(),
            ));
        }
        store
            .flush()
            .map_err(|e| TransitionError::Persistence(e.to_string()))?;
        Ok(())
    }

    /// Restore the ledger, if one was persisted.
    ///
    /// An unreadable or ambiguous ledger is returned as an error: the caller must
    /// keep signing disabled.
    pub fn load(store: &dyn CasStore) -> Result<Option<Self>, TransitionError> {
        let raw = store
            .get(LEDGER_KEY)
            .map_err(|e| TransitionError::Persistence(e.to_string()))?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let payload =
                    open_sealed(&bytes).map_err(|e| TransitionError::Persistence(e.to_string()))?;
                Self::decode(payload).map(Some)
            }
        }
    }
}

impl fmt::Display for GenerationClosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "closure(h={}, g={}, value={})",
            self.height.get(),
            hex::encode(self.generation.0),
            hex::encode(self.value_id)
        )
    }
}
