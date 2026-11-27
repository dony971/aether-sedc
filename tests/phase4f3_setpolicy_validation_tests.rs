//! Mission M1 — F3: `SetPolicy` is validated before any derived computation.
//!
//! `AdmittedSet::admit` is the single public entry point that derives weights
//! from a policy, and `CandidateOperator::derived_weight` is public on its own.
//! A policy with `min_weight > max_weight` used to reach `Ord::clamp`, which
//! panics in the standard library; `deposit_unit = 0` was silently rewritten to
//! `1`, and inverted member bounds were reported as a cardinality problem.
//!
//! Every test below drives the public API and checks a typed, deterministic
//! `TransitionError::Policy`. No test hides a panic behind `catch_unwind`.

use aether_unified::consensus::transitions::{
    AdmittedSet, CandidateOperator, SetPolicy, TransitionError,
};

fn base_policy() -> SetPolicy {
    SetPolicy {
        min_deposit: 1,
        deposit_unit: 1,
        maturity_blocks: 0,
        min_weight: 1,
        max_weight: 1_000,
        w_max: 100_000,
        n_min: 1,
        n_max: 64,
        churn_max_weight: 100,
        f_b_new: 0,
        d_ready: 1_000,
    }
}

fn candidate(deposit: u64) -> CandidateOperator {
    CandidateOperator {
        operator: [1u8; 32],
        public_key: [2u8; 32],
        deposit,
        maturity_blocks: 0,
        unbonding: false,
        jailed: false,
    }
}

fn admit(policy: &SetPolicy) -> Result<AdmittedSet, TransitionError> {
    AdmittedSet::admit(policy, &[candidate(5)], 0, 0, None)
}

fn is_policy_error(error: &TransitionError) -> bool {
    matches!(error, TransitionError::Policy(_))
}

#[test]
fn f3_01_min_above_max_is_refused_before_derivation() {
    let mut p = base_policy();
    p.min_weight = 10;
    p.max_weight = 5;

    // Both public paths return the typed policy error; neither panics.
    let validated = p.validate();
    assert!(is_policy_error(validated.as_ref().unwrap_err()));
    let admitted = admit(&p);
    assert!(is_policy_error(admitted.as_ref().unwrap_err()));
    if let Err(TransitionError::Policy(reason)) = admitted {
        assert!(reason.contains("min_weight"), "{reason}");
    }

    // `derived_weight` is public and does not go through `admit`: it must stay
    // deterministic and panic-free for an inverted policy.
    let weight = candidate(5).derived_weight(&p);
    assert_eq!(weight.get(), 10, "documented fallback: the minimum bound");
}

#[test]
fn f3_02_deposit_unit_zero_is_refused_not_silently_rescaled() {
    let mut p = base_policy();
    p.deposit_unit = 0;

    let validated = p.validate();
    assert!(is_policy_error(validated.as_ref().unwrap_err()));
    let admitted = admit(&p);
    match admitted {
        Err(TransitionError::Policy(reason)) => {
            assert!(reason.contains("deposit_unit"), "{reason}")
        }
        other => panic!("deposit_unit = 0 must be refused, got {other:?}"),
    }

    // No derived value can be observed through `admit`: the error comes before
    // any weight is computed, so an empty candidate list is not the reason.
    let mut empty = base_policy();
    empty.deposit_unit = 0;
    assert!(matches!(
        AdmittedSet::admit(&empty, &[], 0, 0, None),
        Err(TransitionError::Policy(_))
    ));
}

#[test]
fn f3_03_inverted_member_bounds_name_the_policy() {
    let mut p = base_policy();
    p.n_min = 10;
    p.n_max = 5;

    let validated = p.validate();
    assert!(is_policy_error(validated.as_ref().unwrap_err()));
    match admit(&p) {
        // Not `Cardinality`: the policy is malformed, not the candidate list.
        Err(TransitionError::Policy(reason)) => {
            assert!(reason.contains("member bounds"), "{reason}")
        }
        other => panic!("inverted member bounds must be a policy error, got {other:?}"),
    }
}

#[test]
fn f3_04_a_valid_policy_is_accepted_unchanged() {
    let p = base_policy();
    assert!(p.validate().is_ok());

    let set = admit(&p).expect("a consistent policy admits");
    // deposit 5 / unit 1 = 5, inside [1, 1_000] — bit for bit the old `clamp`.
    assert_eq!(set.total().get(), 5);
    let entry = set
        .registry()
        .get(&aether_unified::l2crypto::registry::validator_id(&[2u8; 32]))
        .expect("the candidate is a member");
    assert_eq!(entry.weight.get(), 5);

    // The boundaries are inclusive and equal bounds are legal.
    let mut tight = base_policy();
    tight.min_weight = 5;
    tight.max_weight = 5;
    assert!(tight.validate().is_ok());
    assert_eq!(candidate(5).derived_weight(&tight).get(), 5);
    assert_eq!(candidate(50).derived_weight(&tight).get(), 5);
}

#[test]
fn f3_05_invalid_policies_never_panic() {
    let mut inverted = base_policy();
    inverted.min_weight = 10;
    inverted.max_weight = 5;

    let mut zero_unit = base_policy();
    zero_unit.deposit_unit = 0;

    let mut inverted_members = base_policy();
    inverted_members.n_min = 10;
    inverted_members.n_max = 5;

    let mut zero_bounds = base_policy();
    zero_bounds.max_weight = 0;
    zero_bounds.w_max = 0;

    let mut zero_members = base_policy();
    zero_members.n_min = 0;

    let cases = [
        inverted,
        zero_unit,
        inverted_members,
        zero_bounds,
        zero_members,
    ];

    for policy in cases {
        // `validate` is deterministic and typed.
        let first = policy.validate();
        let second = policy.validate();
        assert!(is_policy_error(first.as_ref().unwrap_err()));
        assert_eq!(
            format!("{:?}", first.unwrap_err()),
            format!("{:?}", second.unwrap_err()),
            "the rejection is deterministic"
        );

        // `admit` propagates the same error instead of panicking in `clamp`.
        let outcome = std::panic::catch_unwind(|| admit(&policy));
        match outcome {
            Ok(Err(TransitionError::Policy(_))) => {}
            Ok(other) => panic!("an invalid policy must be refused, got {other:?}"),
            Err(_) => panic!("an invalid policy must never panic"),
        }

        // The public derivation has no panic path either.
        let derived = std::panic::catch_unwind(|| candidate(5).derived_weight(&policy));
        assert!(derived.is_ok(), "derived_weight must not panic");
    }
}
