//! Mission BC — generation enforcement inside the BFT engine, and durable READY.
//!
//! These tests drive **real clusters**: one engine and one store per validator,
//! votes produced by each engine's own signing path, delivered as a transport
//! would deliver them. Two properties are under test:
//!
//! 1. a closed generation can no longer sign, propose, receive or decide
//!    (`R-TRANS-4`/`R-TRANS-7`), and the only way to change the active generation
//!    is the ledger-backed installation path;
//! 2. READY certificates are durable, re-verified on read, and their quorum is
//!    recomputed from the candidate registry after a restart.
//!
//! Deterministic: fixed seeds, fixed registry, no clock, no randomness.
//! What is **not** tested here: real crashes (each "crash" is a fresh
//! `restore_engine` over the same store), Linux, or any network transport.

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    quorum_threshold, CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::consensus::transitions::{
    candidate_id, AdmittedSet, CandidateOperator, GenerationClosure, GenerationLedger, SetPolicy,
    TransitionError, TransitionProposal,
};
use aether_unified::l2bft::{
    restore_engine, BftError, BftState, PrecommitCertificate, VoteOutcome,
};
use aether_unified::l2crypto::ready::{SignedReady, SignedReadyExpectation};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::{
    load_ready_evidence, record_ready, record_readys, seal, AtomicSlotStore, CasStore,
    MemoryAtomicSlotStore, ReadyStoreError, READY_PREFIX,
};
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const NET: u64 = 11;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const PARENT0: [u8; 32] = [0u8; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn registry_with(generation: [u8; 32], members: &[(u8, u64)]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = members
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(generation), &entries).expect("registry")
}

fn policy(churn: u64) -> SetPolicy {
    SetPolicy {
        min_deposit: 1,
        deposit_unit: 1,
        maturity_blocks: 0,
        min_weight: 1,
        max_weight: 1_000,
        w_max: 100_000,
        n_min: 1,
        n_max: 64,
        churn_max_weight: churn,
        f_b_new: 0,
        d_ready: 1_000,
    }
}

fn candidates(seeds: &[u8], weight: u64) -> Vec<CandidateOperator> {
    seeds
        .iter()
        .map(|seed| CandidateOperator {
            operator: [*seed; 32],
            public_key: sk(*seed).verifying_key().to_bytes(),
            deposit: weight,
            maturity_blocks: 0,
            unbonding: false,
            jailed: false,
        })
        .collect()
}

fn ready_for(
    seed: u8,
    generation: GenerationId,
    candidate: [u8; 32],
    new_set_root: [u8; 32],
    reference: [u8; 32],
    h_ready: u64,
    sequence: u64,
) -> SignedReady {
    let ready = SignedReady::new(
        NET,
        generation,
        candidate,
        new_set_root,
        reference,
        CheckpointHeight(h_ready),
        sequence,
        vid(seed),
    );
    ready.with_signature(sk(seed).sign(&ready.signing_bytes()).to_bytes())
}

/// A cluster of independent validators at one generation.
struct Cluster {
    seeds: Vec<u8>,
    engines: Vec<BftState>,
    stores: Vec<MemoryAtomicSlotStore>,
    registry: ValidatorRegistry,
    height: CheckpointHeight,
    /// Last checkpoint finalised, used as the parent of the next one.
    last: Option<Checkpoint>,
}

impl Cluster {
    fn new(generation: [u8; 32], seeds: &[u8], weight: u64) -> Self {
        let members: Vec<(u8, u64)> = seeds.iter().map(|s| (*s, weight)).collect();
        let registry = registry_with(generation, &members);
        Self {
            seeds: seeds.to_vec(),
            engines: seeds
                .iter()
                .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
                .collect(),
            stores: seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect(),
            registry,
            height: CheckpointHeight(0),
            last: None,
        }
    }

    fn len(&self) -> usize {
        self.engines.len()
    }

    fn prevote_all(&mut self, value: [u8; 32], absent: Option<usize>) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.len() {
            if Some(i) == absent {
                continue;
            }
            let vote = self.engines[i]
                .prevote(
                    value,
                    vid(self.seeds[i]),
                    &self.registry,
                    &self.stores[i],
                    sign_with(self.seeds[i]),
                )
                .expect("prevote");
            out.push(vote.vote().clone());
        }
        out
    }

    fn precommit_all(
        &mut self,
        certificate: &PrevoteCertificateOf,
        absent: Option<usize>,
    ) -> Vec<ConsensusVote> {
        let mut out = Vec::new();
        for i in 0..self.len() {
            if Some(i) == absent {
                continue;
            }
            let vote = self.engines[i]
                .precommit(
                    certificate,
                    vid(self.seeds[i]),
                    &self.registry,
                    &self.stores[i],
                    sign_with(self.seeds[i]),
                )
                .expect("precommit");
            out.push(vote.vote().clone());
        }
        out
    }

    fn deliver(&mut self, votes: &[ConsensusVote]) {
        for i in 0..self.len() {
            for vote in votes {
                let outcome = self.engines[i].accept_vote(vote, &self.registry);
                assert!(
                    !matches!(outcome, VoteOutcome::Rejected { .. }),
                    "validator {} rejected a genuine vote: {outcome:?}",
                    self.seeds[i]
                );
            }
        }
    }

    fn run_cycle(&mut self, value: [u8; 32]) -> PrecommitCertificate {
        let prevotes = self.prevote_all(value, None);
        self.deliver(&prevotes);
        let prevote_cert = self.engines[0]
            .certify_prevotes_for(value, &self.registry)
            .expect("prevote quorum");
        let precommits = self.precommit_all(&prevote_cert, None);
        self.deliver(&precommits);
        self.engines[0]
            .certify_precommits_for(value, &self.registry)
            .expect("precommit quorum")
    }

    fn finalize_all(&mut self, certificate: &PrecommitCertificate, cp: &Checkpoint) {
        let parent = self.last.clone();
        for i in 0..self.len() {
            self.engines[i]
                .finalize(
                    certificate,
                    cp,
                    parent.as_ref(),
                    &self.registry,
                    &self.stores[i],
                )
                .expect("finality");
        }
        self.last = Some(cp.clone());
    }

    /// Install `next` on every validator and move to `h_close + 1`.
    fn close_all(&mut self, closure: GenerationClosure, next: &ValidatorRegistry) {
        for i in 0..self.len() {
            self.engines[i]
                .close_generation(closure, next, &self.stores[i])
                .expect("closure");
        }
        self.registry = next.clone();
        self.height = closure.height.next();
        for i in 0..self.len() {
            self.engines[i]
                .advance_height(self.height, &self.stores[i])
                .expect("advance");
        }
    }

    fn checkpoint(&self, height: u64, transition: Option<[u8; 32]>) -> Checkpoint {
        let parent = if height == 0 {
            PARENT0
        } else {
            self.last.as_ref().expect("a parent checkpoint").id()
        };
        Checkpoint::new(
            self.registry.generation(),
            CheckpointHeight(height),
            parent,
            [0x22u8; 32],
            [0x33u8; 32],
            self.registry.set_root(),
            transition,
        )
        .expect("checkpoint")
    }
}

// Alias kept for readability of the signature above.
type PrevoteCertificateOf = aether_unified::l2bft::PrevoteCertificate;

/// Build the transition for `next` from `old`, ready quorum included.
fn transition(
    old: &ValidatorRegistry,
    next_seeds: &[u8],
    weight: u64,
    height: u64,
    signers: &[u8],
    sequence: u64,
) -> (AdmittedSet, [u8; 32], Vec<SignedReady>) {
    let candidates = candidates(next_seeds, weight);
    let set = AdmittedSet::admit(
        &policy(old.total_voting_weight().get()),
        &candidates,
        1,
        0,
        Some(old),
    )
    .expect("admissible set");
    let candidate = set.candidate_id(old.generation(), CheckpointHeight(height), old.set_root());
    let readys: Vec<SignedReady> = signers
        .iter()
        .map(|seed| {
            ready_for(
                *seed,
                old.generation(),
                candidate,
                set.set_root(),
                PARENT0,
                height,
                sequence,
            )
        })
        .collect();
    (set, candidate, readys)
}

fn expectation(
    old: &ValidatorRegistry,
    set: &AdmittedSet,
    candidate: [u8; 32],
    height: u64,
) -> SignedReadyExpectation {
    SignedReadyExpectation {
        network: NET,
        generation: old.generation(),
        candidate,
        new_set_root: set.set_root(),
        reference_checkpoint: PARENT0,
        h_close: CheckpointHeight(height),
        d_ready: 1_000,
    }
}

fn closure_of(
    height: u64,
    generation: GenerationId,
    candidate: [u8; 32],
    new_set_root: [u8; 32],
    value_id: [u8; 32],
) -> GenerationClosure {
    GenerationClosure {
        height: CheckpointHeight(height),
        generation,
        value_id,
        candidate_id: candidate,
        new_set_root,
    }
}

// ---------------------------------------------------------------------------
// BC-01 .. BC-04: the closure is enforced at every signing path
// ---------------------------------------------------------------------------

#[test]
fn bc_01_normal_transition_installs_the_next_generation() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);

    // READY is durable before anything is decided (R-BB-2).
    let exp = expectation(&old, &set, candidate, 0);
    let evidence =
        record_readys(&cluster.stores[0], set.registry(), &exp, &readys).expect("ready recorded");
    assert!(evidence.is_quorate(), "40 of 40 must be quorate");

    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    assert_eq!(
        cluster.engines[0].finality.map(|d| d.checkpoint_id),
        Some(cp.id())
    );

    cluster.close_all(
        closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
        set.registry(),
    );

    for engine in &cluster.engines {
        assert_eq!(engine.generation, set.generation());
        assert_eq!(engine.ledger.active, set.generation());
        assert_eq!(engine.ledger.first_height, CheckpointHeight(1));
        assert_eq!(engine.ledger.closures.len(), 1);
        assert_eq!(engine.height, CheckpointHeight(1));
    }
}

#[test]
fn bc_02_old_generation_may_vote_at_the_closing_checkpoint() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    // Before any closure the generation is open at its own height.
    assert!(cluster.engines[0].may_sign().is_ok());
    assert!(cluster.engines[0]
        .ledger
        .may_vote(old.generation(), CheckpointHeight(0))
        .is_ok());

    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    assert_eq!(
        cluster.engines[0].finality.map(|d| d.checkpoint_id),
        Some(cp.id())
    );
    let _ = set;
}

#[test]
fn bc_03_closed_generation_cannot_vote_any_more() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);

    // Validator 0 closes the generation and stands at `h_close` without
    // advancing: every signing path is closed, even with a valid registry.
    cluster.engines[0]
        .close_generation(
            closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
            set.registry(),
            &cluster.stores[0],
        )
        .expect("closure");
    let engine = &mut cluster.engines[0];
    assert!(matches!(
        engine.may_sign(),
        Err(BftError::GenerationClosed(_))
    ));
    assert!(matches!(
        engine.prevote(
            [0x99; 32],
            vid(1),
            set.registry(),
            &MemoryAtomicSlotStore::new(),
            sign_with(1)
        ),
        Err(BftError::GenerationClosed(_))
    ));
    assert!(matches!(
        engine.propose([0x99; 32]),
        Err(BftError::GenerationClosed(_))
    ));
    assert!(matches!(
        engine.begin_round(Round(1)),
        Err(BftError::GenerationClosed(_))
    ));
    // The closed generation may not act at any height, not just the closing one.
    for height in [0u64, 1, 5] {
        assert!(engine
            .ledger
            .may_vote(old.generation(), CheckpointHeight(height))
            .is_err());
    }
    assert!(engine
        .ledger
        .may_vote(set.generation(), CheckpointHeight(1))
        .is_ok());
}

#[test]
fn bc_04_new_generation_votes_only_after_activation() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    cluster.close_all(
        closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
        set.registry(),
    );

    // At (h_close, g+1) the new generation is not yet allowed: it starts at 1.
    for engine in &cluster.engines {
        assert!(engine
            .ledger
            .may_vote(set.generation(), CheckpointHeight(0))
            .is_err());
        assert!(engine
            .ledger
            .may_vote(set.generation(), CheckpointHeight(1))
            .is_ok());
    }
    // And it really can vote at height 1 under its own registry.
    let cp1 = cluster.checkpoint(1, None);
    let cert1 = cluster.run_cycle(cp1.id());
    assert_eq!(cert1.support().get(), 40);
    cluster.finalize_all(&cert1, &cp1);
    for engine in &cluster.engines {
        assert_eq!(engine.finality.map(|d| d.checkpoint_id), Some(cp1.id()));
    }
}

// ---------------------------------------------------------------------------
// BC-05 .. BC-07: bypass attempts and foreign QCs
// ---------------------------------------------------------------------------

#[test]
fn bc_05_direct_finalize_cannot_bypass_the_ledger() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    cluster.close_all(
        closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
        set.registry(),
    );

    // A second checkpoint for the closed generation at the closing height, with a
    // perfectly valid certificate, decides nothing.
    let stale = Checkpoint::new(
        old.generation(),
        CheckpointHeight(0),
        PARENT0,
        [0x44u8; 32],
        [0x55u8; 32],
        old.set_root(),
        None,
    )
    .expect("checkpoint");
    let err = cluster.engines[0]
        .finalize(&cert, &stale, None, &old, &cluster.stores[0])
        .expect_err("the ledger must refuse");
    assert!(
        matches!(
            err,
            BftError::GenerationClosed(_) | BftError::ContextMismatch { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn bc_06_certificate_from_a_closed_generation_is_refused() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);

    // Keep a genuine precommit certificate of generation `g` …
    let old_cert = cert;
    cluster.close_all(
        closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
        set.registry(),
    );

    // … and try to use it on the installed generation.
    let err = cluster.engines[0]
        .finalize(&old_cert, &cp, None, &cluster.registry, &cluster.stores[0])
        .expect_err("a closed generation's QC decides nothing");
    assert!(matches!(err, BftError::GenerationClosed(_)), "{err:?}");

    // A vote from the closed generation is foreign to the engine.
    let vote = ConsensusVote {
        version: aether_unified::l2crypto::vote::CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: old.generation(),
        height: CheckpointHeight(0),
        round: Round(0),
        phase: aether_unified::l2crypto::vote::VotePhase::Prevote,
        checkpoint_id: cp.id(),
        validator: vid(1),
        signature: [0u8; 64],
    };
    assert!(matches!(
        cluster.engines[0].accept_vote(&vote, &cluster.registry),
        VoteOutcome::ForeignContext {
            field: "generation",
            ..
        }
    ));
}

#[test]
fn bc_07_certificate_from_a_future_generation_is_refused() {
    let mut old_cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = old_cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);

    // A cluster already running generation g+1 at height 1.
    let mut new_cluster = Cluster::new(set.generation().0, &[1, 2, 3, 4], 10);
    new_cluster.height = CheckpointHeight(1);
    for i in 0..4 {
        new_cluster.engines[i]
            .advance_height(CheckpointHeight(1), &new_cluster.stores[i])
            .expect("advance");
    }
    // Built directly: this cluster has finalised nothing yet, so it has no parent
    // checkpoint to chain to. The engine only cares about the generation here.
    let future_cp = Checkpoint::new(
        set.generation(),
        CheckpointHeight(1),
        [0x11u8; 32],
        [0x22u8; 32],
        [0x33u8; 32],
        set.set_root(),
        None,
    )
    .expect("checkpoint");
    let future_cert = new_cluster.run_cycle(future_cp.id());
    assert_eq!(future_cert.generation(), set.generation());

    // The old cluster is at height 1 too, but under g: the certificate is foreign.
    old_cluster.height = CheckpointHeight(1);
    for i in 0..4 {
        old_cluster.engines[i]
            .advance_height(CheckpointHeight(1), &old_cluster.stores[i])
            .expect("advance");
    }
    let err = old_cluster.engines[0]
        .finalize(&future_cert, &future_cp, None, &old, &old_cluster.stores[0])
        .expect_err("a future generation's QC decides nothing here");
    assert!(
        matches!(
            err,
            BftError::ContextMismatch { .. } | BftError::GenerationClosed(_)
        ),
        "{err:?}"
    );
    let _ = candidate;
}

// ---------------------------------------------------------------------------
// BC-08 .. BC-12: durable READY
// ---------------------------------------------------------------------------

#[test]
fn bc_08_ready_is_persisted_before_the_closure() {
    let cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let exp = expectation(&old, &set, candidate, 0);

    for seed in [1u8, 2, 3] {
        let ready = readys
            .iter()
            .find(|r| r.signer == vid(seed))
            .expect("ready");
        record_ready(&cluster.stores[0], set.registry(), &exp, ready).expect("recorded");
    }
    let partial = load_ready_evidence(&cluster.stores[0], set.registry(), &exp).expect("read");
    assert_eq!(partial.support, ValidatorWeight(30));
    assert!(partial.is_quorate(), "30 of 40 is quorate");

    // The fourth READY completes the certificate, and re-recording is a no-op.
    let evidence =
        record_readys(&cluster.stores[0], set.registry(), &exp, &readys).expect("recorded all");
    assert_eq!(evidence.support, ValidatorWeight(40));
    assert_eq!(evidence.records, 4);
    record_readys(&cluster.stores[0], set.registry(), &exp, &readys).expect("idempotent");
    assert_eq!(cluster.stores[0].scan(READY_PREFIX).expect("scan").len(), 4);
}

#[test]
fn bc_09_restore_after_ready_collection_keeps_the_generation_open() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let exp = expectation(&old, &set, candidate, 0);
    record_readys(&cluster.stores[0], set.registry(), &exp, &readys).expect("ready");

    // Nothing was decided yet: the engine is still at generation `g`.
    let cp = cluster.checkpoint(0, None);
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);

    let restored = restore_engine(
        &cluster.stores[0],
        &old,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert_eq!(restored.state.generation, old.generation());
    assert_eq!(restored.state.ledger.closures.len(), 0);
    assert!(
        restored.state.may_sign().is_ok(),
        "{:?}",
        restored.state.persisted().status
    );
}

#[test]
fn bc_10_ready_quorum_is_reconstructed_after_restart() {
    let cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let exp = expectation(&old, &set, candidate, 0);
    record_readys(&cluster.stores[0], set.registry(), &exp, &readys).expect("ready");

    // A fresh registry instance (as a restarted process would build) recomputes
    // exactly the same quorum, from the same signatures.
    let rebuilt = registry_with(set.generation().0, &[(1, 10), (2, 10), (3, 10), (4, 10)]);
    assert_eq!(rebuilt.set_root(), set.registry().set_root());
    let evidence = load_ready_evidence(&cluster.stores[0], &rebuilt, &exp).expect("read");
    assert_eq!(evidence.support, ValidatorWeight(40));
    assert_eq!(evidence.quorum, quorum_threshold(ValidatorWeight(40)));
    assert_eq!(evidence.accepted.len(), 4);
    assert_eq!(evidence.candidate, candidate);
}

#[test]
fn bc_11_forged_ready_is_refused_at_write_and_ignored_when_read() {
    let cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let exp = expectation(&old, &set, candidate, 0);

    // Write-time refusal: validator 4's attestation with a broken signature.
    let mut forged = *readys
        .iter()
        .find(|r| r.signer == vid(4))
        .expect("ready of validator 4");
    forged.signature[0] ^= 0xFF;
    assert!(matches!(
        record_ready(&cluster.stores[0], set.registry(), &exp, &forged),
        Err(ReadyStoreError::Rejected { .. })
    ));
    assert!(cluster.stores[0]
        .scan(READY_PREFIX)
        .expect("scan")
        .is_empty());

    // Smuggle a forged record past the API, as a corrupted disk would.
    for ready in &readys {
        record_ready(&cluster.stores[0], set.registry(), &exp, ready).expect("recorded");
    }
    // Smuggle a forged record past the API, as a corrupted disk would: a fresh
    // store holding three honest READYs plus one forged record for signer 4,
    // sealed correctly so only the signature is wrong.
    let forged_store = MemoryAtomicSlotStore::new();
    for seed in [1u8, 2, 3] {
        let ready = readys
            .iter()
            .find(|r| r.signer == vid(seed))
            .expect("ready");
        record_ready(&forged_store, set.registry(), &exp, ready).expect("recorded");
    }
    let key = aether_unified::l2persist::ready_key(&candidate, &vid(4));
    assert!(forged_store
        .cas(&key, None, &seal(&forged.encode()))
        .expect("cas"));
    forged_store.flush().expect("flush");

    let evidence = load_ready_evidence(&forged_store, set.registry(), &exp).expect("read");
    // Validator 4's forged attestation no longer counts: 30 of 40 remains quorate,
    // but the signer is rejected, never trusted.
    assert_eq!(evidence.support, ValidatorWeight(30));
    assert!(evidence.rejected.iter().any(|(id, _)| *id == vid(4)));
    assert!(!evidence.accepted.contains(&vid(4)));
}

#[test]
fn bc_12_contradictory_ready_is_refused() {
    let cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let exp = expectation(&old, &set, candidate, 0);
    record_readys(&cluster.stores[0], set.registry(), &exp, &readys).expect("ready");

    // Same candidate, same signer, different sequence: a second, different intent.
    let other = ready_for(
        1,
        old.generation(),
        candidate,
        set.set_root(),
        PARENT0,
        0,
        2,
    );
    assert!(matches!(
        record_ready(&cluster.stores[0], set.registry(), &exp, &other),
        Err(ReadyStoreError::Contradictory { .. })
    ));

    // A READY for another candidate does not collide and stays as history.
    let elsewhere = candidate_id(
        old.generation(),
        CheckpointHeight(0),
        [0xEE; 32],
        old.set_root(),
    );
    let stray = ready_for(
        1,
        old.generation(),
        elsewhere,
        set.set_root(),
        PARENT0,
        0,
        1,
    );
    let stray_exp = SignedReadyExpectation {
        candidate: elsewhere,
        ..exp
    };
    record_ready(&cluster.stores[0], set.registry(), &stray_exp, &stray).expect("history kept");
    let evidence = load_ready_evidence(&cluster.stores[0], set.registry(), &exp).expect("read");
    assert_eq!(
        evidence.records, 4,
        "the other candidate's record is not mixed in"
    );
}

// ---------------------------------------------------------------------------
// BC-13 .. BC-16: incomplete transitions and crash windows
// ---------------------------------------------------------------------------

#[test]
fn bc_13_incomplete_transition_is_refused() {
    let cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, readys) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2], 1);
    let exp = expectation(&old, &set, candidate, 0);
    // Two READY of four: 20 < 27.
    let partial: Vec<SignedReady> = readys;
    record_readys(&cluster.stores[0], set.registry(), &exp, &partial).expect("recorded");
    let evidence = load_ready_evidence(&cluster.stores[0], set.registry(), &exp).expect("read");
    assert!(!evidence.is_quorate());

    // The proposal itself is refused by the normative check.
    let proposal = TransitionProposal {
        network: NET,
        height: CheckpointHeight(0),
        generation: old.generation(),
        parent_digest: PARENT0,
        old_set_root: old.set_root(),
        candidates: candidates(&[1, 2, 3, 4], 10),
        next_number: 1,
        next_epoch_pin: 0,
        readys: partial,
    };
    assert!(matches!(
        aether_unified::consensus::transitions::verify_transition(
            &proposal,
            &policy(40),
            &old,
            PARENT0,
            false
        ),
        Err(TransitionError::ReadyNotQuorate { .. })
    ));

    // And a closure at the wrong height is refused by the engine.
    let mut engine = BftState::new(NET, &old, CheckpointHeight(0), ANCHOR);
    let store = MemoryAtomicSlotStore::new();
    let err = engine
        .close_generation(
            closure_of(3, old.generation(), candidate, set.set_root(), [0u8; 32]),
            set.registry(),
            &store,
        )
        .expect_err("wrong height");
    assert!(matches!(err, BftError::ContextMismatch { field: "height" }));

    // A closure at the right height but with **no decision** at that height is
    // refused too: a proposal alone installs nothing.
    let mut engine = BftState::new(NET, &old, CheckpointHeight(0), ANCHOR);
    let err = engine
        .close_generation(
            closure_of(0, old.generation(), candidate, set.set_root(), [0u8; 32]),
            set.registry(),
            &store,
        )
        .expect_err("no decision to close on");
    assert!(matches!(err, BftError::Rejected(_)), "{err:?}");
    assert_eq!(engine.ledger.closures.len(), 0);
    assert_eq!(engine.generation, old.generation());
}

#[test]
fn bc_14_crash_between_closure_and_installation_blocks_signing() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);

    // Only validator 0 installs the ledger, then "crashes" before advancing.
    cluster.engines[0]
        .close_generation(
            closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
            set.registry(),
            &cluster.stores[0],
        )
        .expect("closure persisted");
    drop(cluster.engines);

    // Restart at the closing height with the **old** registry: the ledger says a
    // new generation is in force, so this node must not sign.
    let restored = restore_engine(
        &cluster.stores[0],
        &old,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert_eq!(restored.state.ledger.active, set.generation());
    assert!(restored.state.may_sign().is_err());
    assert!(!matches!(
        restored.state.persisted().status,
        aether_unified::l2persist::RecoveryStatus::Clean
    ));

    // Restart at the closing height with the new registry: still behind the
    // activation height of the generation in force, so still blocked.
    let restored = restore_engine(
        &cluster.stores[0],
        set.registry(),
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert_eq!(restored.state.generation, set.generation());
    assert!(restored.state.may_sign().is_err());

    // Restart at h_close + 1 with the new registry: the only consistent state.
    let restored = restore_engine(
        &cluster.stores[0],
        set.registry(),
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert_eq!(restored.state.generation, set.generation());
    assert_eq!(restored.state.ledger.first_height, CheckpointHeight(1));
    assert!(
        restored.state.may_sign().is_ok(),
        "{:?}",
        restored.state.persisted().status
    );
}

#[test]
fn bc_15_crash_after_installation_restores_the_new_generation() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);
    cluster.close_all(
        closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
        set.registry(),
    );

    let restored = restore_engine(
        &cluster.stores[2],
        set.registry(),
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert_eq!(restored.state.generation, set.generation());
    assert_eq!(restored.state.set_root, set.set_root());
    assert_eq!(restored.state.ledger.closures.len(), 1);
    assert_eq!(restored.state.ledger.closures[0].candidate_id, candidate);
    assert!(
        restored.state.may_sign().is_ok(),
        "{:?}",
        restored.state.persisted().status
    );

    // Restoring the same store with the old registry is refused, not silently
    // rolled back to the old generation.
    let stale = restore_engine(
        &cluster.stores[2],
        &old,
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    assert!(stale.state.may_sign().is_err());
}

#[test]
fn bc_16_concurrent_old_and_new_generation_cannot_both_be_restored() {
    let mut cluster = Cluster::new(GEN, &[1, 2, 3, 4], 10);
    let old = cluster.registry.clone();
    let (set, candidate, _) = transition(&old, &[1, 2, 3, 4], 10, 0, &[1, 2, 3, 4], 1);
    let cp = cluster.checkpoint(0, Some(candidate));
    let cert = cluster.run_cycle(cp.id());
    cluster.finalize_all(&cert, &cp);

    // Validator 0 closes and installs; validator 1 stops before the closure.
    cluster.engines[0]
        .close_generation(
            closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
            set.registry(),
            &cluster.stores[0],
        )
        .expect("closed");
    cluster.engines[0]
        .advance_height(CheckpointHeight(1), &cluster.stores[0])
        .expect("advanced");

    let installed = restore_engine(
        &cluster.stores[0],
        set.registry(),
        Some(ANCHOR),
        NET,
        CheckpointHeight(1),
    );
    let behind = restore_engine(
        &cluster.stores[1],
        &old,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    // The two nodes are in different generations; the stale one cannot act.
    assert!(installed.state.may_sign().is_ok());
    assert_eq!(behind.state.generation, old.generation());
    assert_eq!(behind.state.ledger.closures.len(), 0);
    // Supplying the new registry to the stale store is refused: its ledger never
    // recorded the activation, and its generation does not match.
    let mismatch = restore_engine(
        &cluster.stores[1],
        set.registry(),
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    // This store never recorded a closure: it has no ledger, but its safety state
    // knows generation `g`. Handing it the new registry is not "a fresh install",
    // it is a rollback with a stale witness, and it is refused.
    assert_eq!(mismatch.state.ledger.closures.len(), 0);
    assert!(mismatch.state.may_sign().is_err());
    assert_eq!(behind.state.ledger.closures.len(), 0);
    assert_eq!(behind.state.generation, old.generation());
    assert_ne!(behind.state.generation, set.generation());
}

// ---------------------------------------------------------------------------
// BC-17: the same enforcement on 4, 5, 7 and 21 validators
// ---------------------------------------------------------------------------

#[test]
fn bc_17_enforcement_holds_on_4_5_7_and_21_validators() {
    for (seeds, weight) in [
        (vec![1u8, 2, 3, 4], 10u64),
        (vec![1, 2, 3, 4, 5], 10),
        (vec![1, 2, 3, 4, 5, 6, 7], 10),
        ((1..=21u8).collect::<Vec<u8>>(), 1),
    ] {
        let mut cluster = Cluster::new(GEN, &seeds, weight);
        let old = cluster.registry.clone();
        assert_eq!(
            old.total_voting_weight(),
            ValidatorWeight(seeds.len() as u64 * weight)
        );
        let (set, candidate, readys) = transition(&old, &seeds, weight, 0, &seeds, 1);
        let exp = expectation(&old, &set, candidate, 0);
        let evidence = record_readys(&cluster.stores[0], set.registry(), &exp, &readys)
            .unwrap_or_else(|e| panic!("{} validators: {e:?}", seeds.len()));
        assert!(evidence.is_quorate(), "{} validators", seeds.len());
        assert_eq!(evidence.quorum, quorum_threshold(old.total_voting_weight()));

        let cp = cluster.checkpoint(0, Some(candidate));
        let cert = cluster.run_cycle(cp.id());
        cluster.finalize_all(&cert, &cp);
        cluster.close_all(
            closure_of(0, old.generation(), candidate, set.set_root(), cp.id()),
            set.registry(),
        );

        // Closed generation: nothing decides, at the closing height or the next.
        assert!(cluster.engines[0]
            .ledger
            .may_vote(old.generation(), CheckpointHeight(0))
            .is_err());
        assert!(cluster.engines[0]
            .ledger
            .may_vote(old.generation(), CheckpointHeight(1))
            .is_err());
        assert!(cluster.engines[0]
            .finalize(&cert, &cp, None, &cluster.registry, &cluster.stores[0])
            .is_err());
        // New generation: decides at h_close + 1.
        let cp1 = cluster.checkpoint(1, None);
        let cert1 = cluster.run_cycle(cp1.id());
        cluster.finalize_all(&cert1, &cp1);
        assert_eq!(
            cluster.engines[0].finality.map(|d| d.checkpoint_id),
            Some(cp1.id())
        );
        assert!(cluster.engines[0].may_sign().is_ok());

        // Restart keeps the closure and the active generation.
        let restored = restore_engine(
            &cluster.stores[0],
            &cluster.registry,
            Some(ANCHOR),
            NET,
            CheckpointHeight(1),
        );
        assert_eq!(restored.state.generation, set.generation());
        assert_eq!(restored.state.ledger.closures.len(), 1);
        assert!(restored.state.may_sign().is_ok());
        assert!(set.total().get() > 0);
        let _: GenerationLedger = restored.state.ledger.clone();
    }
}
