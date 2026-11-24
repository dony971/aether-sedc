//! Mission BB — validator generation lifecycle (`R-SET-1..7`, `R-TRANS-4..7`).
//!
//! These tests exercise the **admissibility**, **READY**, **closure** and
//! **activation** rules through the public API only. Every validator set is
//! built from real Ed25519 keys, every weight is derived by the library, and
//! every store is an independent instance, so two runs on the same data must
//! agree.
//!
//! What these tests do **not** show: that a validator is online, that operators
//! are independent, or that a declared `F_b_new` is true. Those are hypotheses
//! (`H-FB`, `H-INDEP`), not properties of the code.

use std::collections::BTreeMap;

use aether_unified::consensus::generation::{
    quorum_threshold, CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    candidate_id, AdmittedSet, CandidateOperator, GenerationClosure, GenerationLedger,
    LedgerStatus, SetPolicy, TransitionError, TransitionProposal, LEDGER_KEY,
};
use aether_unified::l2crypto::ready::{SignedReady, SignedReadyExpectation};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::{seal, CasStore, MemoryAtomicSlotStore};
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const NET: u64 = 11;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

/// A policy that admits `deposit` as the weight directly (`deposit_unit = 1`).
fn policy(churn_max_weight: u64, f_b_new: u64) -> SetPolicy {
    SetPolicy {
        min_deposit: 1,
        deposit_unit: 1,
        maturity_blocks: 0,
        min_weight: 1,
        max_weight: 100,
        w_max: 10_000,
        n_min: 1,
        n_max: 64,
        churn_max_weight,
        f_b_new,
        d_ready: 1_000,
    }
}

fn operator(seed: u8, weight: u64) -> CandidateOperator {
    CandidateOperator {
        operator: [seed; 32],
        public_key: sk(seed).verifying_key().to_bytes(),
        deposit: weight,
        maturity_blocks: 0,
        unbonding: false,
        jailed: false,
    }
}

/// Seeds `1..=n` with equal weight.
fn members(n: usize, weight: u64) -> Vec<CandidateOperator> {
    (1..=n as u8).map(|seed| operator(seed, weight)).collect()
}

/// Registry of the generation in force, built from declared keys only.
fn genesis_registry(candidates: &[CandidateOperator]) -> ValidatorRegistry {
    let admitted = AdmittedSet::admit(&policy(0, 0), candidates, 0, 0, None).expect("genesis set");
    admitted.registry().clone()
}

fn sign_ready(
    seed: u8,
    network: u64,
    generation: GenerationId,
    candidate: [u8; 32],
    new_set_root: [u8; 32],
    reference: [u8; 32],
    h_ready: u64,
    sequence: u64,
) -> SignedReady {
    let ready = SignedReady::new(
        network,
        generation,
        candidate,
        new_set_root,
        reference,
        CheckpointHeight(h_ready),
        sequence,
        vid(seed),
    );
    let signature = sk(seed).sign(&ready.signing_bytes());
    ready.with_signature(signature.to_bytes())
}

/// Everything a proposer needs to build a well-formed `TRANSITION`.
struct Proposal {
    proposal: TransitionProposal,
    new_set: AdmittedSet,
    candidate: [u8; 32],
}

/// Build a proposal for `next` over `old`, signing READY with `signers`.
#[allow(clippy::too_many_arguments)]
fn build(
    old: &ValidatorRegistry,
    next: &[CandidateOperator],
    height: u64,
    parent: [u8; 32],
    signers: &[u8],
    sequence: u64,
    next_number: u64,
) -> Proposal {
    let new_set = AdmittedSet::admit(
        &policy(old.total_voting_weight().get(), 0),
        next,
        next_number,
        0,
        Some(old),
    )
    .expect("candidate set is admissible");
    let candidate =
        new_set.candidate_id(old.generation(), CheckpointHeight(height), old.set_root());
    let readys: Vec<SignedReady> = signers
        .iter()
        .map(|seed| {
            sign_ready(
                *seed,
                NET,
                old.generation(),
                candidate,
                new_set.set_root(),
                parent,
                height,
                sequence,
            )
        })
        .collect();
    Proposal {
        proposal: TransitionProposal {
            network: NET,
            height: CheckpointHeight(height),
            generation: old.generation(),
            parent_digest: parent,
            old_set_root: old.set_root(),
            candidates: next.to_vec(),
            next_number,
            next_epoch_pin: 0,
            readys,
        },
        new_set,
        candidate,
    }
}

const PARENT: [u8; 32] = [0x5A; 32];

fn verify(
    old: &ValidatorRegistry,
    p: &Proposal,
) -> Result<aether_unified::consensus::transitions::VerifiedTransition, TransitionError> {
    aether_unified::consensus::transitions::verify_transition(
        &p.proposal,
        &policy(old.total_voting_weight().get(), 0),
        old,
        PARENT,
        false,
    )
}

fn closure_of(v: &aether_unified::consensus::transitions::VerifiedTransition) -> GenerationClosure {
    GenerationClosure {
        height: v.height,
        generation: v.generation,
        value_id: v.value_id,
        candidate_id: v.candidate_id,
        new_set_root: v.new_set_root(),
    }
}

// ---------------------------------------------------------------------------
// 1. Normal transition g -> g+1
// ---------------------------------------------------------------------------

#[test]
fn normal_transition_closes_old_and_activates_new() {
    let old = genesis_registry(&members(4, 10));
    let p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1);
    let verified = verify(&old, &p).expect("transition is admissible");

    // Derived, never declared: W = 40, q = 27.
    assert_eq!(verified.new_set.total(), ValidatorWeight(40));
    assert_eq!(verified.new_set.quorum(), ValidatorWeight(27));
    assert_eq!(verified.ready.weight, ValidatorWeight(40));

    let mut ledger = GenerationLedger::new(NET, old.generation());
    // Before the decision, generation 0 decides.
    assert!(ledger
        .may_vote(old.generation(), CheckpointHeight(5))
        .is_ok());
    ledger
        .apply_closure(closure_of(&verified), verified.new_set.generation(), 1)
        .expect("closure applied");

    // R-TRANS-7b: S_new starts at h_close + 1.
    assert_eq!(ledger.first_height, CheckpointHeight(6));
    assert!(ledger
        .may_vote(verified.new_set.generation(), CheckpointHeight(6))
        .is_ok());
    // R-TRANS-4: S_old no longer decides anywhere.
    assert!(ledger
        .may_vote(old.generation(), CheckpointHeight(6))
        .is_err());
    assert_eq!(ledger.generation_at(CheckpointHeight(6)), 1);
    assert_eq!(ledger.generation_at(CheckpointHeight(5)), 0);
}

// ---------------------------------------------------------------------------
// 2-3. Membership changes
// ---------------------------------------------------------------------------

#[test]
fn new_member_absent_from_old_set_is_admitted_when_churn_allows() {
    let old = genesis_registry(&members(4, 10));
    // Seed 9 is new; seed 1 leaves. Retained = 30 of W_old = 40, churn = 40.
    let next = vec![
        operator(2, 10),
        operator(3, 10),
        operator(4, 10),
        operator(9, 10),
    ];
    let p = build(&old, &next, 5, PARENT, &[2, 3, 4, 9], 1, 1);
    let verified = verify(&old, &p).expect("one replacement is within churn");
    assert_ne!(verified.new_set.set_root(), old.set_root());
    assert!(verified.new_set.registry().get(&vid(9)).is_some());
    assert!(verified.new_set.registry().get(&vid(1)).is_none());
}

#[test]
fn leaving_member_outside_the_churn_bound_is_refused() {
    let old = genesis_registry(&members(4, 10));
    let next = vec![
        operator(2, 10),
        operator(3, 10),
        operator(4, 10),
        operator(9, 10),
    ];
    // churn_max_weight = 0: not one unit of weight may rotate.
    let p = build(&old, &next, 5, PARENT, &[2, 3, 4, 9], 1, 1);
    let err = aether_unified::consensus::transitions::verify_transition(
        &p.proposal,
        &policy(0, 0),
        &old,
        PARENT,
        false,
    )
    .expect_err("churn must be enforced");
    match err {
        TransitionError::Churn { retained, floor } => {
            assert_eq!(retained, 30);
            assert_eq!(floor, 40);
        }
        other => panic!("expected Churn, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 4-6. READY
// ---------------------------------------------------------------------------

#[test]
fn insufficient_ready_is_refused() {
    let old = genesis_registry(&members(4, 10));
    // 2 x 10 = 20 < q' = 27.
    let p = build(&old, &members(4, 10), 5, PARENT, &[1, 2], 1, 1);
    match verify(&old, &p) {
        Err(TransitionError::ReadyNotQuorate { support, quorum }) => {
            assert_eq!((support, quorum), (20, 27));
        }
        other => panic!("expected ReadyNotQuorate, got {other:?}"),
    }
}

#[test]
fn ready_quorum_at_exact_threshold_is_accepted() {
    let old = genesis_registry(&members(4, 10));
    // 3 x 10 = 30 >= 27, and 30 is the smallest passing subset.
    let p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3], 1, 1);
    let verified = verify(&old, &p).expect("exact-quorum READY passes");
    assert_eq!(verified.ready.weight, ValidatorWeight(30));
    // Weights come from the candidate registry, not from the message.
    let claimed = verified
        .ready
        .accepted
        .iter()
        .map(|id| verified.new_set.registry().voting_weight(id).unwrap().get())
        .sum::<u64>();
    assert_eq!(claimed, 30);
}

#[test]
fn forged_ready_signature_is_ignored() {
    let old = genesis_registry(&members(4, 10));
    let mut p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1);
    // Flip one signature: that signer's weight no longer counts.
    for ready in p.proposal.readys.iter_mut() {
        if ready.signer == vid(1) {
            ready.signature[0] ^= 0xFF;
        }
    }
    let verified = verify(&old, &p).expect("the honest three still form a quorum");
    assert_eq!(verified.ready.weight, ValidatorWeight(30));
    assert!(verified.ready.rejected.iter().any(|(id, _)| *id == vid(1)));
    assert!(!verified.ready.accepted.contains(&vid(1)));
}

#[test]
fn ready_for_another_candidate_or_generation_is_rejected() {
    let old = genesis_registry(&members(4, 10));
    let mut p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1);
    // Every READY is re-pointed at another candidate: nothing counts.
    for ready in p.proposal.readys.iter_mut() {
        let mut forged = *ready;
        forged.candidate = [0x11; 32];
        forged.signature = sk(1).sign(&forged.signing_bytes()).to_bytes();
        *ready = forged;
    }
    assert!(matches!(
        verify(&old, &p),
        Err(TransitionError::ReadyNotQuorate { .. })
    ));

    // Same for a READY signed under another generation.
    let mut p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 2, 1);
    p.proposal.readys = (1..=4u8)
        .map(|seed| {
            sign_ready(
                seed,
                NET,
                GenerationId([0xEE; 32]),
                p.candidate,
                p.new_set.set_root(),
                PARENT,
                5,
                3,
            )
        })
        .collect();
    assert!(matches!(
        verify(&old, &p),
        Err(TransitionError::ReadyNotQuorate { .. })
    ));
}

#[test]
fn ready_from_a_member_absent_from_the_new_set_is_rejected() {
    let old = genesis_registry(&members(4, 10));
    let next = vec![
        operator(5, 10),
        operator(6, 10),
        operator(7, 10),
        operator(8, 10),
    ];
    let mut p = build(&old, &next, 5, PARENT, &[5, 6, 7, 8], 1, 1);
    // A READY from an old member who is not in the candidate set.
    p.proposal.readys.push(sign_ready(
        1,
        NET,
        old.generation(),
        p.candidate,
        p.new_set.set_root(),
        PARENT,
        5,
        1,
    ));
    let verified = aether_unified::consensus::transitions::verify_transition(
        &p.proposal,
        &policy(40, 0),
        &old,
        PARENT,
        false,
    )
    .expect("the four candidates still form a quorum");
    assert_eq!(verified.ready.weight, ValidatorWeight(40));
    assert!(verified.ready.rejected.iter().any(|(id, _)| *id == vid(1)));
}

// ---------------------------------------------------------------------------
// 7. Wrong generation / stale proposal
// ---------------------------------------------------------------------------

#[test]
fn proposal_naming_another_generation_is_refused() {
    let old = genesis_registry(&members(4, 10));
    let mut p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1);
    p.proposal.generation = GenerationId([0xAA; 32]);
    assert!(matches!(verify(&old, &p), Err(TransitionError::Context(_))));

    // Wrong old set root is C3, not a silent re-derivation.
    let mut p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 2, 1);
    p.proposal.old_set_root = [0xBB; 32];
    assert!(matches!(
        verify(&old, &p),
        Err(TransitionError::WrongOldSetRoot { .. })
    ));

    // Wrong parent is C1.
    let mut p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 3, 1);
    p.proposal.parent_digest = [0xCC; 32];
    assert!(matches!(verify(&old, &p), Err(TransitionError::Parent(_))));

    // A checkpoint that already carries a transition cannot host another (C2).
    let p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 4, 1);
    assert!(matches!(
        aether_unified::consensus::transitions::verify_transition(
            &p.proposal,
            &policy(40, 0),
            &old,
            PARENT,
            true
        ),
        Err(TransitionError::ParentIsTransition)
    ));
}

// ---------------------------------------------------------------------------
// 8-10. Closure, contradiction, replay
// ---------------------------------------------------------------------------

#[test]
fn two_transitions_at_one_height_halt_the_ledger() {
    let old = genesis_registry(&members(4, 10));
    let a = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let next = vec![
        operator(5, 10),
        operator(6, 10),
        operator(7, 10),
        operator(8, 10),
    ];
    let b = aether_unified::consensus::transitions::verify_transition(
        &build(&old, &next, 5, PARENT, &[5, 6, 7, 8], 2, 1).proposal,
        &policy(40, 0),
        &old,
        PARENT,
        false,
    )
    .unwrap();
    assert_ne!(a.value_id, b.value_id);

    let mut ledger = GenerationLedger::new(NET, old.generation());
    ledger
        .apply_closure(closure_of(&a), a.new_set.generation(), 1)
        .expect("first closure");
    // The contradictory second closure is refused *and* the ledger halts: no side
    // is ever chosen.
    assert!(ledger
        .apply_closure(closure_of(&b), b.new_set.generation(), 1)
        .is_err());
    assert!(matches!(ledger.status, LedgerStatus::Halted(_)));
    assert!(!ledger.status.may_sign());
    assert!(ledger
        .may_vote(a.new_set.generation(), CheckpointHeight(6))
        .is_err());
}

#[test]
fn replaying_the_same_transition_is_idempotent_but_an_old_height_is_refused() {
    let old = genesis_registry(&members(4, 10));
    let v = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let mut ledger = GenerationLedger::new(NET, old.generation());
    ledger
        .apply_closure(closure_of(&v), v.new_set.generation(), 1)
        .unwrap();
    // Same decision, same height: idempotent, no second generation installed.
    ledger
        .apply_closure(closure_of(&v), v.new_set.generation(), 1)
        .expect("replay of the same decision is a no-op");
    assert_eq!(ledger.closures.len(), 1);
    assert_eq!(ledger.active_number, 1);

    // A closure below the first height of the active generation would overlap
    // the previous one: refused, and the ledger is not modified.
    let behind = GenerationClosure {
        height: CheckpointHeight(4),
        ..closure_of(&v)
    };
    assert!(ledger
        .apply_closure(behind, GenerationId([0x77; 32]), 2)
        .is_err());
    assert_eq!(ledger.active_number, 1);
    assert_eq!(ledger.first_height, CheckpointHeight(6));
}

#[test]
fn closed_generation_can_never_vote_again() {
    let old = genesis_registry(&members(4, 10));
    let v = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let mut ledger = GenerationLedger::new(NET, old.generation());
    ledger
        .apply_closure(closure_of(&v), v.new_set.generation(), 1)
        .unwrap();

    for height in [5u64, 6, 7, 100] {
        assert!(
            ledger
                .may_vote(old.generation(), CheckpointHeight(height))
                .is_err(),
            "closed generation must not decide at {height}"
        );
    }
    // The new generation cannot decide at the closing height either.
    assert!(ledger
        .may_vote(v.new_set.generation(), CheckpointHeight(5))
        .is_err());
    assert!(ledger
        .may_vote(v.new_set.generation(), CheckpointHeight(6))
        .is_ok());
}

#[test]
fn skipped_generation_number_is_refused() {
    let old = genesis_registry(&members(4, 10));
    let v = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let mut ledger = GenerationLedger::new(NET, old.generation());
    assert!(ledger
        .apply_closure(closure_of(&v), v.new_set.generation(), 2)
        .is_err());
    assert_eq!(ledger.closures.len(), 0);
    assert_eq!(ledger.active, old.generation());
}

// ---------------------------------------------------------------------------
// 13-14. Different set, impossible quorum
// ---------------------------------------------------------------------------

#[test]
fn different_sets_yield_different_identities() {
    let old = genesis_registry(&members(4, 10));
    let a = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let next = vec![
        operator(1, 10),
        operator(2, 10),
        operator(3, 10),
        operator(5, 10),
    ];
    let b = aether_unified::consensus::transitions::verify_transition(
        &build(&old, &next, 5, PARENT, &[1, 2, 3, 5], 1, 1).proposal,
        &policy(40, 0),
        &old,
        PARENT,
        false,
    )
    .unwrap();

    assert_ne!(a.new_set.set_root(), b.new_set.set_root());
    assert_ne!(a.new_set.generation(), b.new_set.generation());
    assert_ne!(a.candidate_id, b.candidate_id);
    assert_ne!(a.value_id, b.value_id);
    // Determinism: the same inputs give the same identity.
    let again = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    assert_eq!(a.value_id, again.value_id);
    assert_eq!(a.ready_root, again.ready_root);
}

#[test]
fn set_whose_quorum_is_unreachable_is_refused() {
    let old = genesis_registry(&members(4, 10));
    // One member holds 90 % of the weight: W = 43, q = 29, the three small
    // members together hold 3 < 29, so READY cannot be reached without the
    // dominant one.
    let next = vec![
        operator(1, 40),
        operator(2, 1),
        operator(3, 1),
        operator(4, 1),
    ];
    let p = build(&old, &next, 5, PARENT, &[2, 3, 4], 1, 1);
    match verify(&old, &p) {
        Err(TransitionError::ReadyNotQuorate { support, quorum }) => {
            assert_eq!((support, quorum), (3, 29));
        }
        other => panic!("expected ReadyNotQuorate, got {other:?}"),
    }
}

#[test]
fn composition_bound_is_enforced_from_declared_faulty_weight() {
    let old = genesis_registry(&members(4, 10));
    let next = members(4, 10);
    let set = AdmittedSet::admit(&policy(40, 0), &next, 1, 0, Some(&old)).unwrap();
    // W' = 40, so the strict safety bound is floor((40 - 1) / 3) = 13 (the old
    // `min(I' - 1, W' - q')` formula gave 3, which admitted f = W/3 = 13 at
    // 3 | W only by accident of the weight distribution, and was wrong in
    // general; mission BM N-2).
    let bound = (set.total().get() - 1) / 3;
    assert_eq!(bound, 13);
    // Declared 14 is refused; declared 13 is accepted.
    assert!(matches!(
        AdmittedSet::admit(&policy(40, 14), &next, 1, 0, Some(&old)),
        Err(TransitionError::Composition {
            declared: 14,
            bound: 13
        })
    ));
    assert!(AdmittedSet::admit(&policy(40, 13), &next, 1, 0, Some(&old)).is_ok());
}

#[test]
fn ineligible_duplicate_and_cardinality_violations_are_refused() {
    let old = genesis_registry(&members(4, 10));

    let mut jailed = members(4, 10);
    jailed[2].jailed = true;
    assert!(matches!(
        AdmittedSet::admit(&policy(40, 0), &jailed, 1, 0, Some(&old)),
        Err(TransitionError::NotEligible { .. })
    ));

    let mut duplicated = members(4, 10);
    duplicated[3].operator = duplicated[0].operator;
    assert!(matches!(
        AdmittedSet::admit(&policy(40, 0), &duplicated, 1, 0, Some(&old)),
        Err(TransitionError::Duplicate {
            what: "operator id",
            ..
        })
    ));

    let mut shared_key = members(4, 10);
    shared_key[3].public_key = shared_key[1].public_key;
    assert!(matches!(
        AdmittedSet::admit(&policy(40, 0), &shared_key, 1, 0, Some(&old)),
        Err(TransitionError::Duplicate {
            what: "public key",
            ..
        })
    ));

    let one = members(1, 10);
    let mut strict = policy(40, 0);
    strict.n_min = 4;
    assert!(matches!(
        AdmittedSet::admit(&strict, &one, 1, 0, Some(&old)),
        Err(TransitionError::Cardinality {
            count: 1,
            min: 4,
            ..
        })
    ));

    // Weights are derived from the deposit, so an under-funded member cannot
    // declare a large one.
    let mut underfunded = members(4, 10);
    underfunded[0].deposit = 2;
    let set = AdmittedSet::admit(&policy(40, 0), &underfunded, 1, 0, Some(&old)).unwrap();
    assert_eq!(
        set.registry().voting_weight(&vid(1)),
        Some(ValidatorWeight(2))
    );
}

// ---------------------------------------------------------------------------
// 11. Persistence and restore
// ---------------------------------------------------------------------------

#[test]
fn ledger_survives_persistence_and_restore() {
    let old = genesis_registry(&members(4, 10));
    let v = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let mut ledger = GenerationLedger::new(NET, old.generation());
    ledger
        .apply_closure(closure_of(&v), v.new_set.generation(), 1)
        .unwrap();

    let store = MemoryAtomicSlotStore::new();
    assert!(GenerationLedger::load(&store).unwrap().is_none());
    ledger.persist(&store).expect("ledger persisted");
    let restored = GenerationLedger::load(&store)
        .expect("ledger readable")
        .expect("ledger present");
    assert_eq!(restored.active, v.new_set.generation());
    assert_eq!(restored.first_height, CheckpointHeight(6));
    assert_eq!(restored.closures, ledger.closures);
    // After the restart the old generation is still closed.
    assert!(restored
        .may_vote(old.generation(), CheckpointHeight(6))
        .is_err());
    assert!(restored
        .may_vote(v.new_set.generation(), CheckpointHeight(6))
        .is_ok());
}

/// Splice a second closure into an encoded ledger: the payload a node would read
/// if two peers had reported two different transitions at one height.
fn ambiguous_ledger_bytes(ledger: &GenerationLedger) -> Vec<u8> {
    let bytes = ledger.encode();
    let header = 1 + 8 + 32 + 8 + 8 + 4; // version, net, active, number, height, count
    let record = 8 + 32 + 32 + 32 + 32;
    let mut out = bytes[..header].to_vec();
    out[57..61].copy_from_slice(&2u32.to_le_bytes());
    let first = bytes[header..header + record].to_vec();
    let mut second = first.clone();
    second[40] ^= 0xFF; // a different value_id
    out.extend_from_slice(&first);
    out.extend_from_slice(&second);
    out.push(0); // Clean
    out
}

#[test]
fn ambiguous_restore_refuses_to_load_and_therefore_to_sign() {
    let old = genesis_registry(&members(4, 10));
    let v = verify(
        &old,
        &build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1),
    )
    .unwrap();
    let mut ledger = GenerationLedger::new(NET, old.generation());
    ledger
        .apply_closure(closure_of(&v), v.new_set.generation(), 1)
        .unwrap();

    let payload = ambiguous_ledger_bytes(&ledger);
    assert!(matches!(
        GenerationLedger::decode(&payload),
        Err(TransitionError::Persistence(_))
    ));
    // The unmodified payload still decodes: the splice, not the format, is what
    // was rejected.
    assert!(GenerationLedger::decode(&ledger.encode()).is_ok());

    let store = MemoryAtomicSlotStore::new();
    let sealed = seal(&payload);
    assert!(store.cas(LEDGER_KEY, None, &sealed).unwrap());
    assert!(GenerationLedger::load(&store).is_err());

    // A tampered seal is unreadable too.
    let store = MemoryAtomicSlotStore::new();
    let mut corrupted = seal(&ledger.encode());
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(store.cas(LEDGER_KEY, None, &corrupted).unwrap());
    assert!(GenerationLedger::load(&store).is_err());
}

// ---------------------------------------------------------------------------
// Multi-validator arithmetic: 4, 5, 7, 21
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_holds_on_4_5_7_and_21_validators() {
    for (n, weight) in [(4usize, 10u64), (5, 10), (7, 10), (21, 1)] {
        let candidates = members(n, weight);
        let old = genesis_registry(&candidates);
        let total = old.total_voting_weight();
        assert_eq!(total, ValidatorWeight(n as u64 * weight));
        let quorum = quorum_threshold(total);
        assert_eq!(quorum, ValidatorWeight((2 * n as u64 * weight + 2) / 3));

        // Exactly the quorate prefix signs; the remainder does not.
        let mut support = 0u64;
        let mut signers: Vec<u8> = Vec::new();
        for seed in 1..=n as u8 {
            if support >= quorum.get() {
                break;
            }
            support += weight;
            signers.push(seed);
        }
        let p = build(&old, &candidates, 5, PARENT, &signers, 1, 1);
        let verified = verify(&old, &p).unwrap_or_else(|e| panic!("{n} validators: {e:?}"));
        assert_eq!(verified.new_set.quorum(), quorum);
        assert!(verified.ready.weight.get() >= quorum.get());

        let mut ledger = GenerationLedger::new(NET, old.generation());
        ledger
            .apply_closure(closure_of(&verified), verified.new_set.generation(), 1)
            .expect("closure");
        assert!(ledger
            .may_vote(old.generation(), CheckpointHeight(9))
            .is_err());
        assert!(ledger
            .may_vote(verified.new_set.generation(), CheckpointHeight(6))
            .is_ok());

        // One unit short is never a quorum.
        let short = &signers[..signers.len() - 1];
        let p = build(&old, &candidates, 5, PARENT, short, 2, 1);
        assert!(matches!(
            verify(&old, &p),
            Err(TransitionError::ReadyNotQuorate { .. })
        ));
    }
}

#[test]
fn byzantine_weight_cannot_forge_a_ready_quorum_on_21_validators() {
    let candidates = members(21, 1);
    let old = genesis_registry(&candidates);
    assert_eq!(old.total_voting_weight(), ValidatorWeight(21));
    // q' = 14, so 6 byzantine members (seeds 16..=21) are one short.
    let byzantine: Vec<u8> = (16..=21).collect();
    let p = build(&old, &candidates, 5, PARENT, &byzantine, 1, 1);
    match verify(&old, &p) {
        Err(TransitionError::ReadyNotQuorate { support, quorum }) => {
            assert_eq!((support, quorum), (6, 14));
        }
        other => panic!("expected ReadyNotQuorate, got {other:?}"),
    }
    // With 14 honest signers the same set is admissible.
    let honest: Vec<u8> = (1..=14).collect();
    let p = build(&old, &candidates, 5, PARENT, &honest, 2, 1);
    assert!(verify(&old, &p).is_ok());
}

#[test]
fn candidate_identity_binds_all_four_components() {
    let old = genesis_registry(&members(4, 10));
    let g = old.generation();
    let root = old.set_root();
    let base = candidate_id(g, CheckpointHeight(5), [1u8; 32], root);
    assert_ne!(base, candidate_id(g, CheckpointHeight(6), [1u8; 32], root));
    assert_ne!(base, candidate_id(g, CheckpointHeight(5), [2u8; 32], root));
    assert_ne!(
        base,
        candidate_id(g, CheckpointHeight(5), [1u8; 32], [3u8; 32])
    );
    assert_ne!(
        base,
        candidate_id(
            GenerationId([9u8; 32]),
            CheckpointHeight(5),
            [1u8; 32],
            root
        )
    );
    // Same inputs, same id.
    assert_eq!(base, candidate_id(g, CheckpointHeight(5), [1u8; 32], root));
}

#[test]
fn ready_expectation_matches_the_candidate_registry() {
    let old = genesis_registry(&members(4, 10));
    let p = build(&old, &members(4, 10), 5, PARENT, &[1, 2, 3, 4], 1, 1);
    let verified = verify(&old, &p).unwrap();
    // The weights used are the candidate registry's, and the accepted set is
    // exactly the four signers, sorted.
    let accepted: BTreeMap<ValidatorId, ValidatorWeight> = verified
        .ready
        .accepted
        .iter()
        .map(|id| (*id, verified.new_set.registry().voting_weight(id).unwrap()))
        .collect();
    assert_eq!(accepted.len(), 4);
    assert_eq!(accepted.values().map(|w| w.get()).sum::<u64>(), 40);
    let _: Option<&RegistryEntry> = verified.new_set.registry().get(&vid(1));
    assert_eq!(
        verified
            .new_set
            .registry()
            .get(&vid(1))
            .map(|e| e.admissibility),
        Some(Admissibility::Eligible)
    );
    let _: SignedReadyExpectation = SignedReadyExpectation {
        network: NET,
        generation: verified.generation,
        candidate: verified.candidate_id,
        new_set_root: verified.new_set.set_root(),
        reference_checkpoint: PARENT,
        h_close: verified.height,
        d_ready: 1_000,
    };
}
