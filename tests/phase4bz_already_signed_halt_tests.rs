//! PHASE 4BZ — R-BZ-1 : un vote déjà signé ne doit pas être *libéré* après HALT.
//!
//! BX a fermé la libération d'une signature **fraîche** traversée par un HALT
//! (`SignedButHalted`, troisième lecture). Le chemin `AlreadySigned` — un vote
//! identique déjà enregistré lors d'un appel antérieur — retournait `Ok` sans
//! repasser cette barrière : un appelant recevait un vote prêt à diffuser alors
//! qu'un HALT était durable.
//!
//! Cette suite est déterministe : l'entrelacement est forcé par un magasin qui
//! écrit le HALT pendant la réservation, jamais par le temps.
//!
//! | Test | Ce qui est prouvé |
//! |---|---|
//! | `bz_01` | sans HALT, le second appel rend le même vote (`AlreadySigned`) |
//! | `bz_02` | HALT écrit entre deux appels : le second appel est refusé à l'entrée (`Halted`) |
//! | `bz_03` | HALT écrit *pendant* le second appel : la nouvelle barrière l'observe |
//!
//! Ce qui n'est pas — et ne peut pas être — prouvé ici : une signature Ed25519
//! déjà produite n'est pas révoquée. Le vote reste dans le magasin comme preuve ;
//! seule sa remise à l'appelant est refusée.

use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{BftError, BftState};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase, CONSENSUS_VOTE_VERSION};
use aether_unified::l2persist::{
    seal, sign_vote, AtomicSlotStore, CasStore, EmitError, MemoryAtomicSlotStore,
    PersistentConsensusState, ReserveOutcome, Settlement, SlotKey, SlotState, SlotStoreError,
    VoteAuthorization, HALT_KEY,
};

const NET: u64 = 43;
const ANCHOR: [u8; 32] = [0x5A; 32];
const A: [u8; 32] = [0xA1; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn gen() -> GenerationId {
    GenerationId([7u8; 32])
}

fn reg() -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = [(1u8, 10u64), (2, 10), (3, 10), (4, 10)]
        .iter()
        .map(|(seed, weight)| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(*weight),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(gen(), &entries).expect("registry")
}

fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    let key = sk(seed);
    move |msg: &[u8]| key.sign(msg).to_bytes()
}

fn unsigned(round: u32, value: [u8; 32]) -> ConsensusVote {
    ConsensusVote {
        version: CONSENSUS_VOTE_VERSION,
        network: NET,
        generation: gen(),
        height: CheckpointHeight(0),
        round: Round(round),
        phase: VotePhase::Prevote,
        checkpoint_id: value,
        validator: vid(1),
        signature: [0u8; 64],
    }
}

fn fresh_state() -> PersistentConsensusState {
    PersistentConsensusState::fresh(NET, gen(), ANCHOR)
}

fn halt(store: &dyn CasStore, text: &str) {
    assert!(
        store
            .cas(HALT_KEY, None, &seal(text.as_bytes()))
            .expect("write halt"),
        "halt written once"
    );
}

fn authorise(state: &PersistentConsensusState, vote: &ConsensusVote) -> VoteAuthorization {
    VoteAuthorization::for_prevote(state, vote, None, &reg()).expect("admissible")
}

fn slot_of() -> SlotKey {
    SlotKey {
        generation: gen().0,
        height: CheckpointHeight(0),
        round: Round(1),
        phase: VotePhase::Prevote,
        validator: vid(1),
    }
}

/// Without a HALT, a repeated call returns the vote that already exists; nothing
/// is re-signed. This is the behaviour `bz_02`/`bz_03` must not weaken for the
/// normal case.
#[test]
fn bz_01_an_already_signed_vote_is_returned_while_no_halt_exists() {
    let store = MemoryAtomicSlotStore::new();
    let state = fresh_state();
    let vote = unsigned(1, A);
    let auth = authorise(&state, &vote);

    let first = sign_vote(&state, &store, &reg(), &vote, &auth, sign_with(1)).expect("first call");
    assert_eq!(first.settlement, Settlement::FreshlySigned);

    let second =
        sign_vote(&state, &store, &reg(), &vote, &auth, sign_with(1)).expect("second call");
    assert_eq!(second.settlement, Settlement::AlreadySigned);
    assert_eq!(
        second.vote.signature, first.vote.signature,
        "the recorded vote is returned unchanged"
    );
    let record = store
        .load(&slot_of())
        .expect("load")
        .expect("the slot exists");
    assert_eq!(record.state, SlotState::Signed);
}

/// A HALT written between the two calls: the second call must refuse to release
/// the stored vote, and the slot must remain as evidence.
#[test]
fn bz_02_a_halt_written_between_calls_refuses_the_release() {
    let store = MemoryAtomicSlotStore::new();
    let state = fresh_state();
    let vote = unsigned(1, A);
    let auth = authorise(&state, &vote);

    sign_vote(&state, &store, &reg(), &vote, &auth, sign_with(1)).expect("first call");
    halt(&store, "operator halt between the two calls");

    // A HALT that predates the call is refused by the first gate (`Halted`);
    // the crossing case is `bz_03` (`SignedButHalted`). Both refuse the release.
    match sign_vote(&state, &store, &reg(), &vote, &auth, sign_with(1)) {
        Err(EmitError::Halted(reason)) => {
            assert!(reason.contains("between the two calls"), "{reason}")
        }
        other => panic!("expected Halted, got {other:?}"),
    }

    let record = store
        .load(&slot_of())
        .expect("load")
        .expect("the slot exists");
    assert_eq!(
        record.state,
        SlotState::Signed,
        "the signature is durable evidence, not a released vote"
    );
    assert!(
        record.vote.is_some(),
        "the recorded vote is never deleted by a HALT"
    );
}

/// Deterministic interleaving: the HALT is written by the store while the second
/// call is reserving. The entry gate cannot see it; the new gate must.
struct HaltOnReserve {
    inner: MemoryAtomicSlotStore,
    fired: AtomicBool,
}

impl CasStore for HaltOnReserve {
    fn backend(&self) -> &'static str {
        "halt-on-reserve"
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        self.inner.get(key)
    }
    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        self.inner.cas(key, expected, new)
    }
    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), SlotStoreError> {
        self.inner.flush()
    }
}

impl AtomicSlotStore for HaltOnReserve {
    fn reserve(
        &self,
        slot: &SlotKey,
        checkpoint_id: &[u8; 32],
    ) -> Result<ReserveOutcome, SlotStoreError> {
        if !self.fired.swap(true, Ordering::SeqCst) {
            halt(&self.inner, "halt while the second call was reserving");
        }
        self.inner.reserve(slot, checkpoint_id)
    }
}

/// A HALT that becomes durable after the entry gate but before the release is
/// observed: the caller is told not to broadcast, even though the vote predates
/// the HALT.
#[test]
fn bz_03_a_halt_appearing_during_the_second_call_is_observed() {
    let state = fresh_state();
    let vote = unsigned(1, A);
    let auth = authorise(&state, &vote);

    let inner = MemoryAtomicSlotStore::new();
    sign_vote(&state, &inner, &reg(), &vote, &auth, sign_with(1)).expect("first call");

    let store = HaltOnReserve {
        inner,
        fired: AtomicBool::new(false),
    };
    match sign_vote(&state, &store, &reg(), &vote, &auth, sign_with(1)) {
        Err(EmitError::SignedButHalted(reason)) => {
            assert!(reason.contains("while the second call"), "{reason}")
        }
        other => panic!("expected SignedButHalted, got {other:?}"),
    }
    assert!(
        store.fired.load(Ordering::SeqCst),
        "the interleaving really happened"
    );
}

/// Engine-level counterpart of `bz_03`, on the restart shape: after a restart
/// the in-memory round state is empty while the slot store still holds the
/// signed vote, so the engine actually reaches `AlreadySigned`. A HALT that
/// becomes durable while that call reserves must stop the vote being handed to
/// the caller — and therefore from being broadcast.
#[test]
fn bz_04_a_restarted_engine_does_not_release_an_already_signed_vote_across_a_halt() {
    let registry = reg();
    let inner = MemoryAtomicSlotStore::new();
    let mut first = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    first
        .prevote(A, vid(1), &registry, &inner, sign_with(1))
        .expect("first emission");
    assert_eq!(first.round_state.prevotes.len(), 1);

    // A second engine on the same durable directory: no vote in memory, the
    // signed slot still on disk. This is the post-restart shape.
    let mut restarted = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    assert!(restarted.round_state.prevotes.is_empty());

    let store = HaltOnReserve {
        inner,
        fired: AtomicBool::new(false),
    };
    match restarted.prevote(A, vid(1), &registry, &store, sign_with(1)) {
        Err(BftError::Emit(message)) => {
            assert!(
                message.contains("do not broadcast"),
                "the caller must be told not to broadcast: {message}"
            );
            assert!(
                message.contains("while the second call"),
                "the post-reservation gate observed the HALT: {message}"
            );
        }
        other => panic!("expected Emit(SignedButHalted), got {other:?}"),
    }
    assert!(
        restarted.round_state.prevotes.is_empty(),
        "no vote may be returned to the caller, so none can be broadcast"
    );
    let records = store.scan_slots().expect("scan the slots");
    assert_eq!(records.len(), 1, "one signed slot, no new reservation");
    assert_eq!(
        records[0].state,
        SlotState::Signed,
        "the pre-HALT signature stays as evidence; it is not revoked"
    );
    assert!(records[0].vote.is_some(), "the recorded vote is never deleted");
}
