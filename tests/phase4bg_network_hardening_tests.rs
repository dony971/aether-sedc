//! Mission BF — wire codecs, HALT proofs and injection.
//!
//! Three things are exercised here, each with real cryptography:
//!
//! 1. `SyncBundle` / `SyncRequest` encoding (R-BE-1): round trip, truncation,
//!    trailing bytes, tampered certificates, bounded counts.
//! 2. `RoundChange` byte codec (R-BE-2): round trip, and every field substitution
//!    refused by the existing `verify`.
//! 3. `HaltProof` (R-BE-3/R-BE-5): two quorum certificates over different values
//!    are a conflict; a tampered one is not; and a verified proof reaches the
//!    engine through `halt_with`, persists, and survives a restart.
//!
//! Everything is signed by real Ed25519 keys and certified by real quorum
//! arithmetic. No payload in this file is a placeholder.

use std::time::{Duration, Instant};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::halt_proof::HaltProof;
use aether_unified::l2bft::round::RoundChange;
use aether_unified::l2bft::sync::{
    install_history, verify_history, SyncAnchor, SyncBundle, SyncLink,
};
use aether_unified::l2bft::HALT_KEY;
use aether_unified::l2bft::{BftState, HaltReason, PrecommitCertificate, PrevoteCertificate};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::MemoryAtomicSlotStore;
use aether_unified::l2persist::{AtomicSlotStore, CasStore};
use aether_unified::network::dispatcher::{dispatch, dispatcher_admits, Dispatched, Incoming};
use aether_unified::network::protocol::{Envelope, MessageKind};
use aether_unified::network::wire_sync::{SyncRequest, MAX_SYNC_BYTES, SYNC_FORMAT_VERSION};
use aether_unified::network::PeerIdentity;
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const NET: u64 = 31;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];
const WEIGHT: u64 = 10;

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

fn registry_with(seeds: &[u8]) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = seeds
        .iter()
        .map(|seed| RegistryEntry {
            id: vid(*seed),
            public_key: sk(*seed).verifying_key().to_bytes(),
            weight: ValidatorWeight(WEIGHT),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

struct Cluster {
    seeds: Vec<u8>,
    engines: Vec<BftState>,
    stores: Vec<MemoryAtomicSlotStore>,
    registry: ValidatorRegistry,
    last: Option<Checkpoint>,
}

impl Cluster {
    fn new(seeds: &[u8]) -> Self {
        let registry = registry_with(seeds);
        Self {
            seeds: seeds.to_vec(),
            engines: seeds
                .iter()
                .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
                .collect(),
            stores: seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect(),
            registry,
            last: None,
        }
    }

    fn checkpoint(&self, height: u64, salt: u8) -> Checkpoint {
        let parent = match (&self.last, height) {
            (Some(cp), h) if h > 0 => cp.id(),
            _ => [0u8; 32],
        };
        Checkpoint::new(
            self.registry.generation(),
            CheckpointHeight(height),
            parent,
            [0x22u8 ^ salt; 32],
            [0x33u8 ^ salt; 32],
            self.registry.set_root(),
            None,
        )
        .expect("checkpoint")
    }

    /// Produce a QC for `value` from the live engines.
    fn certify(&mut self, value: [u8; 32]) -> PrecommitCertificate {
        let mut prevotes: Vec<ConsensusVote> = Vec::new();
        for i in 0..self.engines.len() {
            let vote = self.engines[i]
                .prevote(
                    value,
                    vid(self.seeds[i]),
                    &self.registry,
                    &self.stores[i],
                    sign_with(self.seeds[i]),
                )
                .expect("prevote")
                .vote()
                .clone();
            prevotes.push(vote);
        }
        for i in 0..self.engines.len() {
            for vote in &prevotes {
                self.engines[i].accept_vote(vote, &self.registry);
            }
        }
        let pol: PrevoteCertificate = self.engines[0]
            .certify_prevotes_for(value, &self.registry)
            .expect("prevote quorum");
        let mut precommits: Vec<ConsensusVote> = Vec::new();
        for i in 0..self.engines.len() {
            let vote = self.engines[i]
                .precommit(
                    &pol,
                    vid(self.seeds[i]),
                    &self.registry,
                    &self.stores[i],
                    sign_with(self.seeds[i]),
                )
                .expect("precommit")
                .vote()
                .clone();
            precommits.push(vote);
        }
        for i in 0..self.engines.len() {
            for vote in &precommits {
                self.engines[i].accept_vote(vote, &self.registry);
            }
        }
        self.engines[0]
            .certify_precommits_for(value, &self.registry)
            .expect("precommit quorum")
    }

    fn finalize_all(&mut self, certificate: &PrecommitCertificate, checkpoint: &Checkpoint) {
        let parent = self.last.clone();
        for i in 0..self.engines.len() {
            self.engines[i]
                .finalize(
                    certificate,
                    checkpoint,
                    parent.as_ref(),
                    &self.registry,
                    &self.stores[i],
                )
                .expect("finality");
            // A decided height is left behind; the next cycle starts above it.
            self.engines[i]
                .advance_height(checkpoint.height.next(), &self.stores[i])
                .expect("advance");
        }
        self.last = Some(checkpoint.clone());
    }
}

/// A two-link chain a synchronising node would receive.
fn bundle() -> (SyncBundle, Cluster) {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp0 = cluster.checkpoint(0, 0);
    let qc0 = cluster.certify(cp0.id());
    cluster.finalize_all(&qc0, &cp0);
    let cp1 = cluster.checkpoint(1, 0);
    let qc1 = cluster.certify(cp1.id());
    cluster.finalize_all(&qc1, &cp1);

    let anchor = SyncAnchor {
        network: NET,
        height: CheckpointHeight(0),
        checkpoint_id: cp0.id(),
        generation: cluster.registry.generation(),
        set_root: cluster.registry.set_root(),
    };
    let bundle = SyncBundle {
        anchor,
        generations: vec![aether_unified::l2bft::sync::GenerationSpec {
            number: 0,
            registry: cluster.registry.clone(),
            closure: None,
        }],
        links: vec![
            SyncLink {
                checkpoint: cp0,
                certificate: qc0,
            },
            SyncLink {
                checkpoint: cp1,
                certificate: qc1,
            },
        ],
    };
    (bundle, cluster)
}

// ---------------------------------------------------------------------------
// R-BE-1: sync bundle on the wire
// ---------------------------------------------------------------------------

#[test]
fn bg_01_bundle_round_trip_verifies_from_scratch() {
    let (bundle, _cluster) = bundle();
    let bytes = bundle.encode().expect("encode");
    let decoded = SyncBundle::decode(&bytes).expect("decode");
    assert_eq!(decoded, bundle, "the codec is lossless");

    // What the receiving node does next: verify the decoded bundle end to end.
    let history = verify_history(&decoded).expect("a decoded bundle verifies");
    assert_eq!(history.links.len(), 2);
    assert!(!history.roots.state_root_authenticated);

    // And it can be installed into a fresh store, which is the point of the codec.
    let store = MemoryAtomicSlotStore::new();
    install_history(&store, &history).expect("install");
    assert!(store.get(HALT_KEY).expect("get").is_none());
}

#[test]
fn bg_02_truncated_bundle_is_refused() {
    let (bundle, _cluster) = bundle();
    let bytes = bundle.encode().expect("encode");
    for cut in [1usize, 4, 40, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            SyncBundle::decode(&bytes[..cut]).is_err(),
            "a bundle truncated to {cut} bytes must not decode"
        );
    }
}

#[test]
fn bg_03_trailing_bytes_are_refused() {
    let (bundle, _cluster) = bundle();
    let mut bytes = bundle.encode().expect("encode");
    bytes.push(0);
    assert!(
        SyncBundle::decode(&bytes).is_err(),
        "no padding is accepted"
    );
}

#[test]
fn bg_04_tampered_certificate_is_refused_at_decode() {
    let (bundle, _cluster) = bundle();
    let mut bytes = bundle.encode().expect("encode");
    // Flip a byte near the end, inside the second certificate's signatures.
    let last = bytes.len() - 30;
    bytes[last] ^= 0x01;
    let error = SyncBundle::decode(&bytes).expect_err("a tampered certificate must not decode");
    let text = format!("{error}");
    assert!(
        text.contains("certificate") || text.contains("checkpoint"),
        "the refusal names the broken part, got: {text}"
    );
}

#[test]
fn bg_05_oversized_counts_and_bundles_are_refused_before_allocation() {
    // A version byte followed by an absurd generation count.
    let mut bytes = vec![SYNC_FORMAT_VERSION];
    bytes.extend_from_slice(&[0u8; 8 + 8 + 32 + 32 + 32]); // anchor
    bytes.extend_from_slice(&u16::MAX.to_le_bytes()); // generations
    assert!(
        SyncBundle::decode(&bytes).is_err(),
        "counts are bounded before looping"
    );

    // A buffer above the byte limit.
    let huge = vec![0u8; MAX_SYNC_BYTES + 1];
    assert!(
        SyncBundle::decode(&huge).is_err(),
        "the byte limit is checked first"
    );

    // A request that asks for more links than any bundle may hold.
    let mut request = SyncRequest {
        network: NET,
        from_height: CheckpointHeight(0),
        max_links: u32::MAX,
    }
    .encode();
    assert!(SyncRequest::decode(&request).is_err());
    request[0] = 0; // wrong version
    assert!(SyncRequest::decode(&request).is_err());
}

#[test]
fn bg_06_sync_request_round_trip() {
    let request = SyncRequest {
        network: NET,
        from_height: CheckpointHeight(3),
        max_links: 64,
    };
    let bytes = request.encode();
    assert_eq!(bytes.len(), 21);
    assert_eq!(SyncRequest::decode(&bytes).expect("decode"), request);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(
        SyncRequest::decode(&longer).is_err(),
        "trailing bytes refused"
    );
}

// ---------------------------------------------------------------------------
// R-BE-2: RoundChange bytes
// ---------------------------------------------------------------------------

fn round_change(locked: bool) -> RoundChange {
    let locked_value = if locked {
        Some(aether_unified::l2persist::state::LockedValue {
            checkpoint_id: [0x44; 32],
            height: CheckpointHeight(0),
            round: Round(0),
        })
    } else {
        None
    };
    RoundChange::unsigned(
        NET,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(0),
        Round(1),
        vid(1),
        registry_with(&[1, 2, 3, 4]).set_root(),
        locked_value,
    )
}

#[test]
fn bg_07_round_change_round_trip_with_and_without_lock() {
    let registry = registry_with(&[1, 2, 3, 4]);
    for locked in [false, true] {
        let message = round_change(locked).sign_with(&sk(1));
        let bytes = message.encode();
        assert_eq!(bytes.len(), if locked { 230 } else { 186 });
        let decoded = RoundChange::decode(&bytes, &registry, NET).expect("decode and verify");
        assert_eq!(decoded, message, "the codec is lossless");
        assert_eq!(
            decoded.id(),
            message.id(),
            "the content address is preserved"
        );
        assert_eq!(decoded.locked, message.locked);
    }
}

#[test]
fn bg_08_round_change_field_substitutions_are_refused() {
    let registry = registry_with(&[1, 2, 3, 4]);
    let signed = round_change(true).sign_with(&sk(1));

    // Network substitution: the signature covers the network.
    assert!(RoundChange::decode(&signed.encode(), &registry, NET + 1).is_err());

    // Generation substitution.
    let mut other = signed.clone();
    other.generation = GenerationId([9u8; 32]);
    assert!(RoundChange::decode(&other.encode(), &registry, NET).is_err());

    // Round substitution, both sides.
    let mut other = signed.clone();
    other.target_round = Round(2);
    assert!(RoundChange::decode(&other.encode(), &registry, NET).is_err());
    let mut other = signed.clone();
    other.from_round = Round(7);
    assert!(RoundChange::decode(&other.encode(), &registry, NET).is_err());

    // Lock alteration: a different checkpoint, a different height, a removed lock.
    let mut other = signed.clone();
    if let Some(locked) = other.locked.as_mut() {
        locked.checkpoint_id = [0x55; 32];
    }
    assert!(RoundChange::decode(&other.encode(), &registry, NET).is_err());
    let mut other = signed.clone();
    other.locked = None;
    assert!(RoundChange::decode(&other.encode(), &registry, NET).is_err());

    // A different sender cannot be forged: the signature is the sender's.
    let mut other = signed.clone();
    other.validator = vid(2);
    assert!(RoundChange::decode(&other.encode(), &registry, NET).is_err());
}

#[test]
fn bg_09_round_change_malformed_bytes_are_refused() {
    let registry = registry_with(&[1, 2, 3, 4]);
    let message = round_change(false).sign_with(&sk(1));
    let bytes = message.encode();

    // Truncation by one byte.
    assert!(RoundChange::decode(&bytes[..bytes.len() - 1], &registry, NET).is_err());
    // Trailing padding.
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(RoundChange::decode(&longer, &registry, NET).is_err());
    // Invalid lock tag.
    let mut bad_tag = bytes.clone();
    bad_tag[121] = 2;
    assert!(RoundChange::decode(&bad_tag, &registry, NET).is_err());
    // Wrong version.
    let mut bad_version = bytes.clone();
    bad_version[0] = 2;
    assert!(RoundChange::decode(&bad_version, &registry, NET).is_err());
    // Empty input.
    assert!(RoundChange::decode(&[], &registry, NET).is_err());
}

// ---------------------------------------------------------------------------
// R-BE-3 / R-BE-5: halt proofs
// ---------------------------------------------------------------------------

/// Two quorum certificates over different values at the same height.
fn conflicting_proof() -> (HaltProof, Cluster) {
    // Two independent clusters with the **same** keys: each produces one coherent
    // quorum certificate, and the two certificates contradict each other. That is
    // what a third party observing equivocation sees; no honest engine ever signs
    // both, so a single cluster cannot fake the evidence.
    let mut left = Cluster::new(&[1, 2, 3, 4]);
    let mut right = Cluster::new(&[1, 2, 3, 4]);
    let first = left.checkpoint(0, 0);
    let qc_first = left.certify(first.id());
    let second = right.checkpoint(0, 0x80); // different roots, same position
    let qc_second = right.certify(second.id());
    let cluster = left;
    assert_ne!(first.id(), second.id());
    let proof = HaltProof {
        network: NET,
        generation: cluster.registry.generation(),
        height: CheckpointHeight(0),
        first: (first, qc_first),
        second: (second, qc_second),
    };
    (proof, cluster)
}

#[test]
fn bg_10_two_conflicting_qcs_are_a_proven_halt() {
    let (proof, cluster) = conflicting_proof();
    let reason = proof.verify(&cluster.registry).expect("a real conflict");
    match reason {
        HaltReason::ConflictingFinality {
            height,
            first,
            second,
        } => {
            assert_eq!(height, CheckpointHeight(0));
            assert_ne!(first, second);
        }
        other => panic!("expected conflicting finality, got {other:?}"),
    }

    // The proof travels as bytes and is re-verified on the other side.
    let bytes = proof.encode();
    let decoded = HaltProof::decode(&bytes, &cluster.registry).expect("decode");
    assert_eq!(&decoded, &proof);
    assert!(decoded.verify(&cluster.registry).is_ok());
}

#[test]
fn bg_11_identical_values_are_not_a_conflict() {
    let mut cluster = Cluster::new(&[1, 2, 3, 4]);
    let cp = cluster.checkpoint(0, 0);
    let qc = cluster.certify(cp.id());
    let qc_again = cluster.certify(cp.id());
    let proof = HaltProof {
        network: NET,
        generation: cluster.registry.generation(),
        height: CheckpointHeight(0),
        first: (cp.clone(), qc),
        second: (cp, qc_again),
    };
    assert!(
        proof.verify(&cluster.registry).is_err(),
        "the same value twice proves nothing"
    );
}

#[test]
fn bg_12_invalid_proofs_are_refused() {
    let (proof, cluster) = conflicting_proof();

    // A forged signature on one half: the certificate does not re-verify at all,
    // so it cannot even be built into a proof.
    let mut bytes = proof.first.1.encode();
    let mid = bytes.len() - 20;
    bytes[mid] ^= 0xFF;
    assert!(
        PrecommitCertificate::from_bytes(&bytes, &cluster.registry, NET).is_err(),
        "a tampered signature must not decode"
    );

    // A certificate that does not certify its own checkpoint.
    let mut swapped = proof.clone();
    swapped.first.1 = proof.second.1.clone();
    assert!(
        swapped.verify(&cluster.registry).is_err(),
        "a certificate for another value is not evidence for this one"
    );

    // Wrong height / wrong generation in the proof envelope.
    let mut wrong_height = proof.clone();
    wrong_height.height = CheckpointHeight(1);
    assert!(wrong_height.verify(&cluster.registry).is_err());
    let mut wrong_generation = proof.clone();
    wrong_generation.generation = GenerationId([3u8; 32]);
    assert!(wrong_generation.verify(&cluster.registry).is_err());

    // A truncated or padded encoding.
    let bytes = proof.encode();
    assert!(HaltProof::decode(&bytes[..bytes.len() - 1], &cluster.registry).is_err());
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(HaltProof::decode(&padded, &cluster.registry).is_err());
    // An alert is not a proof.
    assert!(HaltProof::decode(&[0u8; 32], &cluster.registry).is_err());
}

// ---------------------------------------------------------------------------
// R-BE-3: alert vs proof vs engine state
// ---------------------------------------------------------------------------

fn peer_for(seed: u8) -> aether_unified::network::PeerState {
    let identity = PeerIdentity::derive(sk(seed).verifying_key().to_bytes(), 0);
    let mut table = aether_unified::network::PeerTable::new(Default::default());
    table.admit(identity, Instant::now()).expect("admit");
    table.get(&identity.id).expect("peer").clone()
}

fn envelope(kind: MessageKind, payload: Vec<u8>, seed: u8) -> Envelope {
    Envelope::new(NET, kind, vid(seed).0, GEN, 0, 0, payload).sign(&sk(seed))
}

#[test]
fn bg_13_alert_does_not_halt_but_proof_does() {
    let (proof, cluster) = conflicting_proof();
    let registry = cluster.registry.clone();
    let mut state = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let store = MemoryAtomicSlotStore::new();

    // (1) An alert: accepted, recorded by the caller, stops nothing.
    let mut peer = peer_for(2);
    let alert = envelope(MessageKind::HaltEvidence, vec![0x77; 32], 2);
    match dispatch(&mut peer, &alert, &mut state, &registry, false) {
        Incoming::Accepted(Dispatched::HaltAlert(evidence)) => {
            assert_eq!(evidence, [0x77; 32]);
        }
        other => panic!("an alert must be accepted as an alert, got {other:?}"),
    }
    assert!(!state.is_halted(), "an alert must not halt the engine");

    // (2) A proof: decoded with both certificates re-verified, then injected.
    let request = envelope(MessageKind::HaltEvidence, proof.encode(), 2);
    let verified = match dispatch(&mut peer, &request, &mut state, &registry, false) {
        Incoming::Accepted(Dispatched::HaltProof(proof)) => proof,
        other => panic!("a proof must decode as a proof, got {other:?}"),
    };
    let reason = verified.verify(&registry).expect("conflict");
    state.halt_with(reason, &store).expect("halt");
    assert!(state.is_halted());
    assert!(
        state
            .prevote(
                cluster_checkpoint_id(),
                vid(2),
                &registry,
                &store,
                sign_with(2)
            )
            .is_err(),
        "a halted engine signs nothing"
    );

    // (3) The record is durable: a sealed HALT record exists, so a restart
    // reloads it (BD's `bd_10` covers the reload path itself).
    let raw = store.get(HALT_KEY).expect("get").expect("record");
    assert!(
        raw.len() > 64,
        "the halt record was written and sealed, got {} bytes",
        raw.len()
    );
}

fn cluster_checkpoint_id() -> [u8; 32] {
    let cluster = Cluster::new(&[1, 2, 3, 4]);
    cluster.checkpoint(0, 0).id()
}

#[test]
fn bg_14_second_proof_never_replaces_the_first() {
    let (proof, cluster) = conflicting_proof();
    let registry = cluster.registry.clone();
    let mut state = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let store = MemoryAtomicSlotStore::new();

    state
        .halt_with(proof.verify(&registry).expect("conflict"), &store)
        .expect("first halt");
    let first = state.halt.clone();
    let mut other = proof.clone();
    other.height = CheckpointHeight(5);
    // Even a well-formed second reason cannot overwrite the record.
    state
        .halt_with(
            HaltReason::BrokenFinalityChain {
                height: CheckpointHeight(5),
            },
            &store,
        )
        .expect("second halt is a no-op");
    assert_eq!(state.halt, first, "the first evidence is preserved");

    // Re-injecting the same proof over the dispatcher changes nothing.
    let mut peer = peer_for(3);
    let request = envelope(MessageKind::HaltEvidence, proof.encode(), 3);
    let _ = dispatch(&mut peer, &request, &mut state, &registry, true);
    assert_eq!(state.halt, first);
}

#[test]
fn bg_15_malformed_halt_payloads_are_refused_without_halting() {
    let registry = registry_with(&[1, 2, 3, 4]);
    let mut state = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let mut peer = peer_for(2);

    for payload in [vec![0x01u8, 0x09], vec![0x01u8; 200], vec![0xAB; 33]] {
        let message = envelope(MessageKind::HaltEvidence, payload, 2);
        match dispatch(&mut peer, &message, &mut state, &registry, false) {
            Incoming::Refused(_) => {}
            other => panic!("a malformed halt payload must be refused, got {other:?}"),
        }
    }
    assert!(!state.is_halted(), "junk never stops a node");
}

#[test]
fn bg_16_dispatcher_admits_only_known_peers() {
    // A guard added for BF: the dispatcher refuses to account a message for a peer
    // it has not admitted, so per-peer quotas cannot be bypassed by identity.
    let registry = registry_with(&[1, 2, 3, 4]);
    let mut peer = peer_for(2);
    assert!(dispatcher_admits(
        &peer,
        &envelope(MessageKind::Ping, vec![0], 2)
    ));
    assert!(!dispatcher_admits(
        &peer,
        &envelope(MessageKind::Ping, vec![0], 3)
    ));
    // The peer is still the one admitted: nothing was replaced.
    assert_eq!(peer.identity.id, vid(2));
    assert!(Duration::from_secs(1) > Duration::from_millis(1));
}
