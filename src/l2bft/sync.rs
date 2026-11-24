//! Verified synchronisation of an L2 history (mission BD).
//!
//! # What this module is, and what it deliberately is not
//!
//! It is the **verification** half of a sync protocol: given a bundle that a
//! remote peer produced, decide whether it can be believed, and what state it
//! implies. It is not a transport, it does not choose peers, and it never trusts
//! a value because it arrived from a known validator.
//!
//! # The four kinds of root, kept apart
//!
//! | Root | Here |
//! |---|---|
//! | recomputed from data this module holds (`validator_set_root`) | **checked** against the checkpoint |
//! | recomputed over the verified decision chain (`finality_chain_root`) | **produced**, never compared to a claim |
//! | transported only (`state_root`, `finality_root`) | stored, marked **not authenticated** in [`VerifiedRoots`] |
//! | authenticated (`checkpoint_id`, via the parent link and the anchor) | **checked** at every link |
//!
//! A `state_root` commits to L1 balances, nonces and applied-set roots that an L2
//! node does not hold. It cannot be recomputed from the chain, so claiming it is
//! verified would be false. [`VerifiedRoots::state_root_authenticated`] is
//! therefore always `false` and says so per history.
//!
//! # Fail-closed
//!
//! Every error leaves the caller with nothing to install. There is no partial
//! `VerifiedHistory`, and [`install_history`] refuses to overwrite any commitment
//! the local store already holds: a finalised snapshot is **not** evidence that
//! the node made no promises.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::{CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight};
use crate::consensus::roots::{ids_root, validator_set_root};
use crate::consensus::transitions::{candidate_id, GenerationClosure, GenerationLedger};
use crate::l2bft::cert::PrecommitCertificate;
use crate::l2bft::engine::{
    finality_key, pending_install_key, FinalityDecision, PendingInstall, FINALITY_FORMAT_VERSION,
    FINALITY_PREFIX, HALT_KEY, PENDING_INSTALL_FORMAT_VERSION,
};
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2persist::{
    open_sealed, seal, AtomicSlotStore, CasStore, SlotReservation, SlotState, SLOT_PREFIX,
};

/// Format version of a synchronisation bundle.
pub const SYNC_FORMAT_VERSION: u8 = 1;

/// Why a bundle cannot be believed.
///
/// Every variant names the check that failed, so an operator can tell a truncated
/// history from a forged one without reading code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncError {
    /// The bundle carries no link at all.
    #[error("empty bundle")]
    EmptyBundle,

    /// The first link is not the trusted anchor.
    #[error("bundle does not start at the anchor: {0}")]
    Unanchored(&'static str),

    /// Two consecutive links are not one height apart.
    #[error("height {found} does not follow {expected}")]
    HeightJump {
        /// Expected height.
        expected: u64,
        /// Found height.
        found: u64,
    },

    /// A link does not chain to its predecessor.
    #[error("checkpoint at height {0} does not chain to its parent")]
    ParentMismatch(u64),

    /// The checkpoint record is invalid on its own.
    #[error("checkpoint at height {0} is invalid: {1}")]
    CheckpointInvalid(u64, String),

    /// No generation of the bundle matches the checkpoint.
    #[error("checkpoint at height {0} names generation {1}, which the bundle does not describe")]
    UnknownGeneration(u64, String),

    /// The registry of that generation does not match the checkpoint.
    #[error("checkpoint at height {0} disagrees with its generation ({1})")]
    SetRootMismatch(u64, &'static str),

    /// The certificate does not verify with the registry of its generation.
    #[error("certificate at height {0} does not verify: {1}")]
    CertificateInvalid(u64, String),

    /// The certificate is valid but names another position.
    #[error("certificate at height {0} names another {1}")]
    CertificateForeign(u64, &'static str),

    /// The generation chain described by the bundle is inconsistent.
    #[error("generation chain: {0}")]
    GenerationChain(String),

    /// A checkpoint closes a transition the bundle does not describe.
    #[error("checkpoint at height {0} closes an unknown transition")]
    UnknownTransition(u64),

    /// The transition identifier does not match its candidate.
    #[error("checkpoint at height {0} carries a transition id that is not its candidate")]
    TransitionMismatch(u64),

    /// The history does not reach the requested height.
    #[error("history stops at {tip}, {requested} was required")]
    Truncated {
        /// Tip reached.
        tip: u64,
        /// Height requested.
        requested: u64,
    },

    /// Two histories describe the same height differently.
    #[error("contradictory histories at height {0}: {1} and {2}")]
    Contradictory(u64, String, String),

    /// The local store holds a commitment this history would erase.
    #[error("local commitment conflict: {0}")]
    Commitment(String),

    /// The store failed.
    #[error("store error: {0}")]
    Store(String),

    /// The identity is not a member of the active generation.
    #[error("not a member of the active generation: {0}")]
    NotMember(&'static str),
}

/// The trust anchor a synchronising node is given **out of band**.
///
/// This module does not create a new trust rule: the anchor must already be
/// trusted by whatever means the deployment chose (a compiled-in constant, an
/// operator file, the L1 anchor of `crate::anchor`). All this code does is refuse
/// a bundle that does not literally start there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncAnchor {
    /// Network.
    pub network: u64,
    /// Height of the anchor checkpoint.
    pub height: CheckpointHeight,
    /// Identifier of the anchor checkpoint.
    pub checkpoint_id: [u8; 32],
    /// Generation the anchor checkpoint belongs to.
    pub generation: GenerationId,
    /// Validator-set root in force at the anchor.
    pub set_root: [u8; 32],
}

/// One generation of the bundle, with the transition that installed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationSpec {
    /// Monotone generation number, starting at 0.
    pub number: u64,
    /// Validator registry of this generation, weights included.
    pub registry: ValidatorRegistry,
    /// The closure that installed this generation; `None` for the first one.
    pub closure: Option<GenerationClosure>,
}

/// One checkpoint and the certificate that decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncLink {
    /// The checkpoint, as transported.
    pub checkpoint: Checkpoint,
    /// Its precommit certificate, re-verified against the generation registry.
    pub certificate: PrecommitCertificate,
}

/// What a peer offers: a chain plus the generations it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBundle {
    /// Trusted anchor (supplied by the caller, not by the peer).
    pub anchor: SyncAnchor,
    /// Generations, ordered by number, the first one with `closure == None`.
    pub generations: Vec<GenerationSpec>,
    /// Checkpoints, ordered by height, the first one **being** the anchor.
    pub links: Vec<SyncLink>,
}

/// One verified link, with the decision recomputed from its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLink {
    /// Recomputed checkpoint identifier.
    pub checkpoint_id: [u8; 32],
    /// Height.
    pub height: CheckpointHeight,
    /// Generation that decided it.
    pub generation: GenerationId,
    /// Set root in force.
    pub set_root: [u8; 32],
    /// The decision, recomputed here — not read from the peer.
    pub decision: FinalityDecision,
}

/// Which roots were actually recomputed, and which were only carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRoots {
    /// Root over the identifiers of the verified decisions, **computed here**.
    pub finality_chain_root: [u8; 32],
    /// `state_root` of the tip, exactly as transported.
    pub tip_state_root: [u8; 32],
    /// `finality_root` of the tip, exactly as transported.
    pub tip_finality_root: [u8; 32],
    /// Always `false`: `state_root` commits to L1 data an L2 node does not hold.
    /// Reported explicitly so no caller can present it as verified.
    pub state_root_authenticated: bool,
    /// Number of links whose `validator_set_root` was recomputed from the
    /// registry members and matched.
    pub set_roots_recomputed: usize,
}

/// A history that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHistory {
    /// Network.
    pub network: u64,
    /// Anchor the history starts at.
    pub anchor: SyncAnchor,
    /// Verified links, ordered, contiguous.
    pub links: Vec<VerifiedLink>,
    /// Verified generations, ordered.
    pub generations: Vec<GenerationSpec>,
    /// Ledger rebuilt from the generations and their closures.
    pub ledger: GenerationLedger,
    /// Tip height reached.
    pub tip: CheckpointHeight,
    /// Roots: recomputed vs transported.
    pub roots: VerifiedRoots,
}

impl VerifiedHistory {
    /// Registry of the generation in force at the tip.
    pub fn active_registry(&self) -> &ValidatorRegistry {
        &self.generations[self.generations.len() - 1].registry
    }

    /// Generation in force at the tip.
    pub fn active_generation(&self) -> GenerationId {
        self.ledger.active
    }

    /// Decision for `height`, if the history reaches it.
    pub fn decision_at(&self, height: CheckpointHeight) -> Option<&VerifiedLink> {
        self.links.iter().find(|l| l.height == height)
    }

    /// Refuse a history that does not reach `height`.
    pub fn require_tip(&self, height: CheckpointHeight) -> Result<(), SyncError> {
        if self.tip.get() < height.get() {
            return Err(SyncError::Truncated {
                tip: self.tip.get(),
                requested: height.get(),
            });
        }
        Ok(())
    }
}

fn registry_of<'a>(
    generations: &'a [GenerationSpec],
    generation: GenerationId,
) -> Option<&'a ValidatorRegistry> {
    generations
        .iter()
        .map(|g| &g.registry)
        .find(|r| r.generation() == generation)
}

/// Verify a bundle against the caller's anchor.
///
/// Nothing here trusts the bundle's own claims: identifiers are recomputed from
/// the checkpoint fields, certificates are re-verified from their bytes against
/// the registry of **their** generation, set roots are recomputed from the
/// registry members, and the transition identifier of a closing checkpoint is
/// recomputed from the candidate formula.
pub fn verify_history(bundle: &SyncBundle) -> Result<VerifiedHistory, SyncError> {
    if bundle.links.is_empty() {
        return Err(SyncError::EmptyBundle);
    }
    if bundle.generations.is_empty() {
        return Err(SyncError::GenerationChain(
            "no generation was supplied".to_string(),
        ));
    }
    let anchor = bundle.anchor;

    // --- generations -------------------------------------------------------
    if bundle.generations[0].closure.is_some() {
        return Err(SyncError::GenerationChain(
            "the first generation must not carry a closure".to_string(),
        ));
    }
    // Validate the generation chain, and collect the installations in height
    // order. The ledger itself is built **while** the links are verified: a
    // closure applies only once the checkpoint that decided it has been seen.
    let mut installs: Vec<(u64, GenerationClosure, GenerationId, u64)> = Vec::new();
    let mut previous_generation = bundle.generations[0].registry.generation();
    for (index, spec) in bundle.generations.iter().enumerate() {
        if spec.number != index as u64 {
            return Err(SyncError::GenerationChain(format!(
                "generation {} is numbered {}",
                index, spec.number
            )));
        }
        let members: Vec<(ValidatorId, ValidatorWeight)> = spec
            .registry
            .entries()
            .iter()
            .map(|e| (e.id, e.weight))
            .collect();
        if validator_set_root(&members) != spec.registry.set_root() {
            return Err(SyncError::GenerationChain(format!(
                "generation {} has a set root that its members do not produce",
                spec.number
            )));
        }
        if index == 0 {
            continue;
        }
        let closure = spec.closure.ok_or_else(|| {
            SyncError::GenerationChain(format!("generation {} has no closure", spec.number))
        })?;
        if closure.new_set_root != spec.registry.set_root() {
            return Err(SyncError::GenerationChain(format!(
                "generation {} closure installs another set root",
                spec.number
            )));
        }
        if closure.generation != previous_generation {
            return Err(SyncError::GenerationChain(format!(
                "generation {} closure names a generation that is not in force",
                spec.number
            )));
        }
        installs.push((
            closure.height.get(),
            closure,
            spec.registry.generation(),
            spec.number,
        ));
        previous_generation = spec.registry.generation();
    }
    installs.sort_by_key(|(height, _, _, _)| *height);
    for pair in installs.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(SyncError::GenerationChain(
                "two generations were installed at the same height".to_string(),
            ));
        }
    }

    let mut ledger =
        GenerationLedger::new(anchor.network, bundle.generations[0].registry.generation());
    let mut applied = 0usize;

    // --- links -------------------------------------------------------------
    let first = &bundle.links[0];
    if first.checkpoint.id() != anchor.checkpoint_id {
        return Err(SyncError::Unanchored(
            "the first checkpoint identifier is not the anchor's",
        ));
    }
    if first.checkpoint.height != anchor.height {
        return Err(SyncError::Unanchored(
            "the first checkpoint is not at the anchor height",
        ));
    }
    if first.checkpoint.generation != anchor.generation
        || first.checkpoint.validator_set_root != anchor.set_root
    {
        return Err(SyncError::Unanchored(
            "the first checkpoint disagrees with the anchor's generation or set",
        ));
    }

    let mut verified: Vec<VerifiedLink> = Vec::with_capacity(bundle.links.len());
    let mut previous: Option<&SyncLink> = None;
    let mut recomputed_set_roots = 0usize;

    for (index, link) in bundle.links.iter().enumerate() {
        let cp = &link.checkpoint;
        cp.validate()
            .map_err(|e| SyncError::CheckpointInvalid(cp.height.get(), e.to_string()))?;

        // Position: the first link is the anchor, then exactly +1.
        if let Some(prev) = previous {
            if cp.height.get() != prev.checkpoint.height.get().saturating_add(1) {
                return Err(SyncError::HeightJump {
                    expected: prev.checkpoint.height.get().saturating_add(1),
                    found: cp.height.get(),
                });
            }
            if cp.parent != prev.checkpoint.id() {
                return Err(SyncError::ParentMismatch(cp.height.get()));
            }
        }
        // Replay of an earlier height cannot happen here: heights are strictly
        // increasing by one, and the identifier is recomputed from the fields.
        if verified.iter().any(|v| v.height == cp.height) {
            return Err(SyncError::Contradictory(
                cp.height.get(),
                "duplicate height".to_string(),
                hex::encode(cp.id()),
            ));
        }

        // Generation and set root, recomputed from the registry members.
        let registry = registry_of(&bundle.generations, cp.generation).ok_or_else(|| {
            SyncError::UnknownGeneration(cp.height.get(), hex::encode(cp.generation.0))
        })?;
        if registry.set_root() != cp.validator_set_root {
            return Err(SyncError::SetRootMismatch(
                cp.height.get(),
                "checkpoint carries a set root its generation does not produce",
            ));
        }
        let members: Vec<(ValidatorId, ValidatorWeight)> = registry
            .entries()
            .iter()
            .map(|e| (e.id, e.weight))
            .collect();
        if validator_set_root(&members) != cp.validator_set_root {
            return Err(SyncError::SetRootMismatch(
                cp.height.get(),
                "recomputed set root differs",
            ));
        }
        recomputed_set_roots += 1;

        // Install every generation whose closing checkpoint precedes this
        // height. A closure is applied only after its checkpoint was verified.
        while applied < installs.len() && installs[applied].0 < cp.height.get() {
            let (_, closure, generation, number) = installs[applied];
            ledger
                .apply_closure(closure, generation, number)
                .map_err(|e| SyncError::GenerationChain(e.to_string()))?;
            applied += 1;
        }

        // The generation that decides this height must be open there.
        ledger.may_vote(cp.generation, cp.height).map_err(|e| {
            SyncError::GenerationChain(format!(
                "checkpoint at {} is decided by a generation that is not open there: {e}",
                cp.height.get()
            ))
        })?;

        // Certificate: re-verified from bytes, with **this generation's** registry.
        let certificate =
            PrecommitCertificate::from_bytes(&link.certificate.encode(), registry, anchor.network)
                .map_err(|e| SyncError::CertificateInvalid(cp.height.get(), e.to_string()))?;
        if certificate.checkpoint_id() != cp.id() {
            return Err(SyncError::CertificateForeign(cp.height.get(), "value"));
        }
        if certificate.height() != cp.height {
            return Err(SyncError::CertificateForeign(cp.height.get(), "height"));
        }
        if certificate.generation() != cp.generation {
            return Err(SyncError::CertificateForeign(cp.height.get(), "generation"));
        }
        if certificate.set_root() != cp.validator_set_root {
            return Err(SyncError::CertificateForeign(cp.height.get(), "set root"));
        }
        if certificate.qc().network != anchor.network {
            return Err(SyncError::CertificateForeign(cp.height.get(), "network"));
        }

        // A closing checkpoint must name a transition the bundle describes, and
        // that transition id must be its candidate (R-SET-7 / AM §1).
        if let Some(transition) = cp.transition_id {
            let closure = bundle
                .generations
                .iter()
                .filter_map(|g| g.closure)
                .find(|c| c.height == cp.height && c.generation == cp.generation)
                .ok_or(SyncError::UnknownTransition(cp.height.get()))?;
            let recomputed = candidate_id(
                cp.generation,
                cp.height,
                closure.new_set_root,
                cp.validator_set_root,
            );
            if recomputed != transition {
                return Err(SyncError::TransitionMismatch(cp.height.get()));
            }
            // BO-F1 (mission BP): the generation this closure opens must be
            // labelled by the transition itself. A bundle that keeps the members
            // but relabels the generation would install an identity no quorum
            // signed, so it is refused instead.
            if let Some(spec) = bundle.generations.iter().find(|spec| {
                spec.closure
                    .map(|c| c.height == cp.height && c.generation == cp.generation)
                    .unwrap_or(false)
            }) {
                let certified = crate::consensus::generation::GenerationId(transition);
                let legacy = crate::consensus::roots::generation_id_from(
                    spec.number,
                    0,
                    closure.new_set_root,
                );
                let label = spec.registry.generation();
                if label != certified && label != legacy {
                    return Err(SyncError::GenerationChain(format!(
                        "the generation opened at height {} is not derived from its transition",
                        cp.height.get()
                    )));
                }
            }
        }

        let verified_qc = certificate.verified();
        let decision = FinalityDecision {
            version: FINALITY_FORMAT_VERSION,
            network: anchor.network,
            generation: cp.generation,
            height: cp.height,
            round: certificate.round(),
            checkpoint_id: cp.id(),
            parent: cp.parent,
            validator_set_root: cp.validator_set_root,
            registry_root: certificate.qc().registry_root,
            support: verified_qc.support.get(),
            total: verified_qc.total.get(),
            quorum: verified_qc.quorum.get(),
            certificate_id: certificate.id(),
            // Mission BN: a bundle carries the transition of a closing checkpoint,
            // so the receiving node can derive its installation obligation.
            transition_id: cp.transition_id,
        };
        if decision.support < decision.quorum {
            return Err(SyncError::CertificateInvalid(
                cp.height.get(),
                "support below quorum".to_string(),
            ));
        }
        verified.push(VerifiedLink {
            checkpoint_id: cp.id(),
            height: cp.height,
            generation: cp.generation,
            set_root: cp.validator_set_root,
            decision,
        });
        previous = Some(link);
        let _ = index;
    }

    let tip = verified
        .last()
        .map(|v| v.height)
        .expect("verified is not empty");

    // The tip may itself close a generation: that installation is part of what
    // the verified history establishes, and nothing above the tip is applied.
    while applied < installs.len() && installs[applied].0 <= tip.get() {
        let (_, closure, generation, number) = installs[applied];
        ledger
            .apply_closure(closure, generation, number)
            .map_err(|e| SyncError::GenerationChain(e.to_string()))?;
        applied += 1;
    }

    let chain_ids: Vec<[u8; 32]> = verified.iter().map(|v| v.checkpoint_id).collect();
    let tip_cp = &bundle.links[bundle.links.len() - 1].checkpoint;
    let roots = VerifiedRoots {
        finality_chain_root: ids_root(&chain_ids),
        tip_state_root: tip_cp.state_root,
        tip_finality_root: tip_cp.finality_root,
        // Honest: an L2 node cannot recompute the L1 component roots.
        state_root_authenticated: false,
        set_roots_recomputed: recomputed_set_roots,
    };

    Ok(VerifiedHistory {
        network: anchor.network,
        anchor,
        links: verified,
        generations: bundle.generations.clone(),
        ledger,
        tip,
        roots,
    })
}

/// Whether `identity` may participate, and where.
///
/// Derived **only** from the rebuilt active registry: no message, header or
/// caller-supplied field can make a node a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Participation {
    /// Member of the active generation.
    Member {
        /// Active generation.
        generation: GenerationId,
        /// Weight assigned by the registry.
        weight: ValidatorWeight,
        /// Height at which it may first vote.
        first_height: CheckpointHeight,
    },
    /// Not allowed, with the reason.
    Refused(&'static str),
}

/// Decide whether `identity` may vote at `height` under the rebuilt history.
pub fn participation(
    history: &VerifiedHistory,
    identity: &ValidatorId,
    height: CheckpointHeight,
) -> Participation {
    let registry = history.active_registry();
    let entry = match registry.get(identity) {
        Some(entry) => entry,
        None => return Participation::Refused("not in the active validator set"),
    };
    if !entry.admissibility.may_vote() {
        return Participation::Refused("member is not admissible");
    }
    if history
        .ledger
        .may_vote(history.ledger.active, height)
        .is_err()
    {
        return Participation::Refused("the active generation is not open at that height");
    }
    Participation::Member {
        generation: history.ledger.active,
        weight: entry.weight,
        first_height: history.ledger.first_height,
    }
}

/// Two independently produced histories: agree, or contradict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryAgreement {
    /// Identical links over the common range.
    Agree {
        /// Heights both histories cover.
        common: usize,
    },
    /// A height is decided differently.
    Contradiction {
        /// Height.
        height: u64,
        /// First history's identifier.
        first: String,
        /// Second history's identifier.
        second: String,
    },
}

/// Compare two verified histories over their common range.
pub fn compare_histories(a: &VerifiedHistory, b: &VerifiedHistory) -> HistoryAgreement {
    let mut common = 0usize;
    for (left, right) in a.links.iter().zip(b.links.iter()) {
        if left.height != right.height {
            break;
        }
        if left.checkpoint_id != right.checkpoint_id {
            return HistoryAgreement::Contradiction {
                height: left.height.get(),
                first: hex::encode(left.checkpoint_id),
                second: hex::encode(right.checkpoint_id),
            };
        }
        common += 1;
    }
    HistoryAgreement::Agree { common }
}

/// Refuse to install a history that would erase a local commitment.
///
/// A finalised snapshot is not proof that this node made no promises: vote slots,
/// a lock, a halt record or a finality decision that disagrees with the verified
/// chain are all blocking. Nothing is repaired, no lock is zeroed.
pub fn check_commitments(
    store: &dyn AtomicSlotStore,
    history: &VerifiedHistory,
) -> Result<(), SyncError> {
    let by_height: BTreeMap<u64, [u8; 32]> = history
        .links
        .iter()
        .map(|l| (l.height.get(), l.checkpoint_id))
        .collect();

    if store
        .get(HALT_KEY)
        .map_err(|e| SyncError::Store(e.to_string()))?
        .is_some()
    {
        return Err(SyncError::Commitment(
            "a halt record is present: synchronisation cannot clear it".to_string(),
        ));
    }

    for (key, bytes) in store
        .scan(SLOT_PREFIX)
        .map_err(|e| SyncError::Store(e.to_string()))?
    {
        let record = open_sealed(&bytes)
            .map_err(|e| SyncError::Store(format!("undecodable slot {key}: {e}")))
            .and_then(|payload| {
                SlotReservation::decode(payload)
                    .map_err(|e| SyncError::Store(format!("undecodable slot {key}: {e}")))
            })?;
        if !matches!(record.state, SlotState::Signed) {
            continue;
        }
        if record.checkpoint_id == [0u8; 32] {
            continue; // Nil commits to nothing.
        }
        if let Some(verified) = by_height.get(&record.slot.height.get()) {
            if *verified != record.checkpoint_id {
                return Err(SyncError::Commitment(format!(
                    "signed {} at height {} but the verified history says {}",
                    hex::encode(record.checkpoint_id),
                    record.slot.height.get(),
                    hex::encode(verified)
                )));
            }
        }
    }

    if let Some(stored) =
        GenerationLedger::load(store).map_err(|e| SyncError::Store(e.to_string()))?
    {
        if stored != history.ledger && !ledger_extends(&stored, &history.ledger) {
            return Err(SyncError::Commitment(
                "the local generation ledger disagrees with the verified history".to_string(),
            ));
        }
    }

    if let Some(state) = crate::l2persist::restore(store, None, history.network).state {
        if let Some(lock) = state.locked {
            if let Some(verified) = by_height.get(&lock.height.get()) {
                if *verified != lock.checkpoint_id {
                    return Err(SyncError::Commitment(format!(
                        "locked on {} at height {} but the verified history says {}",
                        hex::encode(lock.checkpoint_id),
                        lock.height.get(),
                        hex::encode(verified)
                    )));
                }
            }
        }
    }

    for (_, bytes) in store
        .scan(FINALITY_PREFIX)
        .map_err(|e| SyncError::Store(e.to_string()))?
    {
        let payload = open_sealed(&bytes).map_err(|e| SyncError::Store(e.to_string()))?;
        let decision =
            FinalityDecision::decode(payload).map_err(|e| SyncError::Store(e.to_string()))?;
        if let Some(verified) = by_height.get(&decision.height.get()) {
            if *verified != decision.checkpoint_id {
                return Err(SyncError::Commitment(format!(
                    "a durable decision at height {} names {}, the verified history names {}",
                    decision.height.get(),
                    hex::encode(decision.checkpoint_id),
                    hex::encode(verified)
                )));
            }
        }
    }
    Ok(())
}

/// Whether `new` only **adds** closed generations to `old` (mission BH, priority 6).
///
/// A partial synchronisation asks for a window of links, and a window that stops
/// before a closure rebuilds a ledger shorter than the chain's. With successive
/// requests the stored ledger grows window by window; this predicate allows exactly
/// that and nothing else. Another network, fewer closures than already stored, or a
/// divergence at any shared position is refused.
///
/// It does not weaken [`check_commitments`]: erasing a closure is still refused.
pub fn ledger_extends(old: &GenerationLedger, new: &GenerationLedger) -> bool {
    old.network == new.network
        && new.closures.len() >= old.closures.len()
        && new.active_number >= old.active_number
        && old
            .closures
            .iter()
            .zip(new.closures.iter())
            .all(|(stored, offered)| stored == offered)
}

/// Install a verified history into a store, after the commitment check.
///
/// Writes the rebuilt ledger and one finality record per verified link. Never
/// deletes anything: a store that could not accept the history is refused by
/// [`check_commitments`] before a single byte is written.
pub fn install_history(
    store: &dyn AtomicSlotStore,
    history: &VerifiedHistory,
) -> Result<(), SyncError> {
    check_commitments(store, history)?;
    history
        .ledger
        .persist(store)
        .map_err(|e| SyncError::Store(e.to_string()))?;
    // Mission BQ: installing a history **is** the installation, so the durable
    // mark must exist afterwards. Without it a node that caught up from a peer
    // restored its ledger and then refused to sign, because the closure was on
    // disk but the installation was not marked. The record shape is unchanged;
    // this only writes the mark the closing node writes for itself.
    mark_installed(store, history)?;
    for link in &history.links {
        let key = finality_key(link.height);
        let sealed = seal(&link.decision.encode());
        match store
            .get(&key)
            .map_err(|e| SyncError::Store(e.to_string()))?
        {
            Some(existing) => {
                let payload =
                    open_sealed(&existing).map_err(|e| SyncError::Store(e.to_string()))?;
                let stored = FinalityDecision::decode(payload)
                    .map_err(|e| SyncError::Store(e.to_string()))?;
                if stored.checkpoint_id != link.checkpoint_id {
                    return Err(SyncError::Commitment(format!(
                        "a durable decision at height {} names another checkpoint",
                        link.height.get()
                    )));
                }
            }
            None => {
                if !store
                    .cas(&key, None, &sealed)
                    .map_err(|e| SyncError::Store(e.to_string()))?
                {
                    return Err(SyncError::Store(
                        "finality record changed concurrently".to_string(),
                    ));
                }
            }
        }
    }
    store.flush().map_err(|e| SyncError::Store(e.to_string()))?;
    Ok(())
}

/// Write the durable installation mark for the closure this history installs.
///
/// The closing node writes that mark itself (`mark_install_recorded`). A node
/// that installs the same closure from a bundle must leave the same evidence, or
/// a restart sees a ledger it cannot justify and refuses to sign. The record is
/// compare-and-swapped and never overwrites a different obligation: an
/// inconsistency is a refusal, not a repair.
fn mark_installed(store: &dyn AtomicSlotStore, history: &VerifiedHistory) -> Result<(), SyncError> {
    let Some(closure) = history.ledger.closures.last() else {
        return Ok(());
    };
    let installed = history.active_registry();
    let derived = PendingInstall {
        version: PENDING_INSTALL_FORMAT_VERSION,
        network: history.ledger.network,
        height: closure.height,
        generation: closure.generation,
        candidate_id: closure.candidate_id,
        value_id: closure.value_id,
        installed: true,
        installed_generation: installed.generation(),
        installed_set_root: installed.set_root(),
    };
    let key = pending_install_key(closure.height);
    match store
        .get(&key)
        .map_err(|e| SyncError::Store(e.to_string()))?
    {
        Some(bytes) => {
            let mut stored = PendingInstall::decode(
                open_sealed(&bytes).map_err(|e| SyncError::Store(e.to_string()))?,
            )
            .map_err(|e| SyncError::Store(e.to_string()))?;
            // The identity of the closure is its position, its generation and the
            // transition it carries. `value_id` is not compared: the ledger that
            // installed the generation is the certified authority for it, and a
            // record derived from a decision carries the decided value, which the
            // closure copies but which no rule makes the mark's business.
            if stored.height != closure.height
                || stored.generation != closure.generation
                || stored.candidate_id != closure.candidate_id
            {
                return Err(SyncError::Commitment(format!(
                    "the installation obligation at height {} belongs to another closure",
                    closure.height.get()
                )));
            }
            if stored.installed {
                if stored.installed_set_root != derived.installed_set_root
                    || (stored.installed_generation.0 != [0u8; 32]
                        && stored.installed_generation != derived.installed_generation)
                {
                    return Err(SyncError::Commitment(format!(
                        "the closure at height {} was installed as another generation",
                        closure.height.get()
                    )));
                }
                return Ok(());
            }
            stored.installed = true;
            stored.installed_generation = derived.installed_generation;
            stored.installed_set_root = derived.installed_set_root;
            if !store
                .cas(&key, Some(&bytes), &seal(&stored.encode()))
                .map_err(|e| SyncError::Store(e.to_string()))?
            {
                return Err(SyncError::Store(
                    "installation mark changed concurrently".to_string(),
                ));
            }
        }
        None => {
            if !store
                .cas(&key, None, &seal(&derived.encode()))
                .map_err(|e| SyncError::Store(e.to_string()))?
            {
                return Err(SyncError::Store(
                    "installation mark changed concurrently".to_string(),
                ));
            }
        }
    }
    store.flush().map_err(|e| SyncError::Store(e.to_string()))?;
    Ok(())
}

/// Build a bundle from data a serving node already holds.
///
/// Convenience for tests and for the serving half of a future transport: it does
/// not weaken verification, since the receiving side re-runs every check.
pub fn bundle_from(
    anchor: SyncAnchor,
    generations: Vec<GenerationSpec>,
    links: Vec<SyncLink>,
) -> SyncBundle {
    SyncBundle {
        anchor,
        generations,
        links,
    }
}
