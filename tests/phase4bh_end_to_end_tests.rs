//! Mission BG — end-to-end P2P integration over real TCP sockets.
//!
//! Each test here builds a mesh of real `Node`s (real listeners, real sockets,
//! real Ed25519 handshakes) and exercises one end-to-end path:
//!
//! | Test | Path |
//! |---|---|
//! | `bh_01` | a round change crosses a socket and reaches the engine |
//! | `bh_02` | a round change with a broken signature/POL is refused |
//! | `bh_03` | wrong generation / height / round is refused |
//! | `bh_04` | a replayed round change is dropped |
//! | `bh_05` | three validators change round at once |
//! | `bh_06` | a blank node asks for a bundle, verifies it, installs it |
//! | `bh_07` | a tampered bundle installs nothing |
//! | `bh_08` | a HALT proof crosses sockets, halts and persists |
//! | `bh_09` | an invalid proof halts nobody |
//! | `bh_10` | an alert halts nobody |
//!
//! What is **not** here: real process restart (see `persistent-restart-tests.md`)
//! and the network simulator (see `network-simulator.md`).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::halt_proof::HaltProof;
use aether_unified::l2bft::round::RoundChange;
use aether_unified::l2bft::sync::{GenerationSpec, SyncAnchor, SyncBundle, SyncLink};
use aether_unified::l2bft::{BftState, PrecommitCertificate, PrevoteCertificate};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::MemoryAtomicSlotStore;
use aether_unified::network::protocol::MessageKind;
use aether_unified::network::wire_sync::SyncRequest;
use aether_unified::network::{Incoming, Node, PeerLimits};
use ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const NET: u64 = 41;
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

fn limits() -> PeerLimits {
    PeerLimits {
        read_timeout: Duration::from_millis(20),
        write_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(2),
        max_messages_per_second: 500,
        ..PeerLimits::default()
    }
}

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().expect("addr")
}

/// A mesh of real nodes, one per seed.
struct Mesh {
    seeds: Vec<u8>,
    nodes: Vec<Node>,
    registry: ValidatorRegistry,
}

impl Mesh {
    fn new(seeds: &[u8]) -> Self {
        let registry = registry_with(seeds);
        let mut nodes: Vec<Node> = seeds
            .iter()
            .map(|seed| {
                let mut node = Node::bind_with_limits(
                    ephemeral(),
                    NET,
                    sk(*seed),
                    BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR),
                    registry.clone(),
                    limits(),
                )
                .expect("bind");
                node.attach_store(Box::new(MemoryAtomicSlotStore::new()));
                node
            })
            .collect();
        let addrs: Vec<SocketAddr> = nodes.iter().map(|node| node.addr()).collect();
        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                nodes[i].dial(addrs[j]).expect("dial");
                nodes[j]
                    .accept_one(Duration::from_millis(500))
                    .expect("accept")
                    .expect("handshake");
            }
        }
        for node in &mut nodes {
            node.finish_dials();
        }
        Self {
            seeds: seeds.to_vec(),
            nodes,
            registry,
        }
    }

    fn drain(&mut self) {
        for _ in 0..60 {
            let mut quiet = true;
            for node in &mut self.nodes {
                let mut guard = 0;
                while let Some(_) = node.poll(Duration::from_millis(10)).expect("poll") {
                    quiet = false;
                    guard += 1;
                    if guard > 60 {
                        break;
                    }
                }
            }
            if quiet {
                return;
            }
        }
    }

    fn round_change(&self, seed: u8, target: u32, locked: Option<[u8; 32]>) -> RoundChange {
        let lock = locked.map(|id| aether_unified::l2persist::state::LockedValue {
            checkpoint_id: id,
            height: CheckpointHeight(0),
            round: Round(0),
        });
        RoundChange::unsigned(
            NET,
            self.registry.generation(),
            CheckpointHeight(0),
            Round(0),
            Round(target),
            vid(seed),
            self.registry.set_root(),
            lock,
        )
        .sign_with(&sk(seed))
    }
}

/// Produce a QC for `value` from a live set of engines.
fn certify_with(
    engines: &mut [BftState],
    stores: &[MemoryAtomicSlotStore],
    registry: &ValidatorRegistry,
    seeds: &[u8],
    value: [u8; 32],
) -> PrecommitCertificate {
    let mut prevotes: Vec<ConsensusVote> = Vec::new();
    for i in 0..seeds.len() {
        prevotes.push(
            engines[i]
                .prevote(
                    value,
                    vid(seeds[i]),
                    registry,
                    &stores[i],
                    sign_with(seeds[i]),
                )
                .expect("prevote")
                .vote()
                .clone(),
        );
    }
    for i in 0..seeds.len() {
        for vote in &prevotes {
            engines[i].accept_vote(vote, registry);
        }
    }
    let pol: PrevoteCertificate = engines[0]
        .certify_prevotes_for(value, registry)
        .expect("prevote quorum");
    let mut precommits: Vec<ConsensusVote> = Vec::new();
    for i in 0..seeds.len() {
        precommits.push(
            engines[i]
                .precommit(
                    &pol,
                    vid(seeds[i]),
                    registry,
                    &stores[i],
                    sign_with(seeds[i]),
                )
                .expect("precommit")
                .vote()
                .clone(),
        );
    }
    for i in 0..seeds.len() {
        for vote in &precommits {
            engines[i].accept_vote(vote, registry);
        }
    }
    engines[0]
        .certify_precommits_for(value, registry)
        .expect("precommit quorum")
}

/// A two-link chain plus the bundle that describes it.
struct Chain {
    bundle: SyncBundle,
}

fn build_chain() -> Chain {
    let seeds = [1u8, 2, 3, 4];
    let registry = registry_with(&seeds);
    let mut engines: Vec<BftState> = seeds
        .iter()
        .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
        .collect();
    let stores: Vec<MemoryAtomicSlotStore> =
        seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect();

    let cp0 = Checkpoint::new(
        registry.generation(),
        CheckpointHeight(0),
        [0u8; 32],
        [0x22; 32],
        [0x33; 32],
        registry.set_root(),
        None,
    )
    .expect("checkpoint");
    let qc0 = certify_with(&mut engines, &stores, &registry, &seeds, cp0.id());
    for i in 0..seeds.len() {
        engines[i]
            .finalize(&qc0, &cp0, None, &registry, &stores[i])
            .expect("finality");
        engines[i]
            .advance_height(CheckpointHeight(1), &stores[i])
            .expect("advance");
    }
    let cp1 = Checkpoint::new(
        registry.generation(),
        CheckpointHeight(1),
        cp0.id(),
        [0x23; 32],
        [0x34; 32],
        registry.set_root(),
        None,
    )
    .expect("checkpoint");
    let qc1 = certify_with(&mut engines, &stores, &registry, &seeds, cp1.id());

    let anchor = SyncAnchor {
        network: NET,
        height: CheckpointHeight(0),
        checkpoint_id: cp0.id(),
        generation: registry.generation(),
        set_root: registry.set_root(),
    };
    Chain {
        bundle: SyncBundle {
            anchor,
            generations: vec![GenerationSpec {
                number: 0,
                registry: registry.clone(),
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
        },
    }
}

/// Two quorum certificates over different values at the same height.
fn halt_proof() -> HaltProof {
    let seeds = [1u8, 2, 3, 4];
    let registry = registry_with(&seeds);
    let make = |salt: u8| -> (Checkpoint, PrecommitCertificate) {
        let mut engines: Vec<BftState> = seeds
            .iter()
            .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
            .collect();
        let stores: Vec<MemoryAtomicSlotStore> =
            seeds.iter().map(|_| MemoryAtomicSlotStore::new()).collect();
        let cp = Checkpoint::new(
            registry.generation(),
            CheckpointHeight(0),
            [0u8; 32],
            [0x22u8 ^ salt; 32],
            [0x33u8 ^ salt; 32],
            registry.set_root(),
            None,
        )
        .expect("checkpoint");
        let qc = certify_with(&mut engines, &stores, &registry, &seeds, cp.id());
        (cp, qc)
    };
    let first = make(0);
    let second = make(0x80);
    HaltProof {
        network: NET,
        generation: registry.generation(),
        height: CheckpointHeight(0),
        first,
        second,
    }
}

// ---------------------------------------------------------------------------
// Priority 1 — RoundChange on TCP
// ---------------------------------------------------------------------------

#[test]
fn bh_01_round_change_crosses_a_socket_and_reaches_the_engine() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    let change = mesh.round_change(1, 1, None);
    let sent = mesh.nodes[0].broadcast(MessageKind::RoundChange, change.encode());
    assert_eq!(sent, 3, "the change reached every connected peer");
    mesh.drain();

    for i in 1..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].round_changes, 1,
            "node {i} recorded exactly one round change"
        );
        assert_eq!(mesh.nodes[i].refusal_count(), 0, "nothing was refused");
    }
}

#[test]
fn bh_02_round_change_with_a_broken_proof_is_refused() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);

    // (a) A lock whose signature no longer matches the body.
    let mut tampered = mesh.round_change(1, 1, Some([0x44; 32])).encode();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    mesh.nodes[0].broadcast(MessageKind::RoundChange, tampered);
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert!(
            mesh.nodes[i].refusal_count() >= 1,
            "a bad signature is refused"
        );
        assert_eq!(mesh.nodes[i].round_changes, 0);
    }

    // (b) A lock claiming another height is refused by the engine.
    let mut wrong = mesh.round_change(1, 1, None);
    wrong.locked = Some(aether_unified::l2persist::state::LockedValue {
        checkpoint_id: [0x55; 32],
        height: CheckpointHeight(9),
        round: Round(0),
    });
    let wrong = wrong.sign_with(&sk(1));
    mesh.nodes[0].broadcast(MessageKind::RoundChange, wrong.encode());
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].round_changes, 0,
            "a lock for another height is not a valid round change"
        );
    }
}

#[test]
fn bh_03_wrong_generation_height_and_round_are_refused() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);

    let mut wrong_generation = mesh.round_change(1, 1, None);
    wrong_generation.generation = GenerationId([9u8; 32]);
    let wrong_generation = wrong_generation.sign_with(&sk(1));

    let mut wrong_height = mesh.round_change(1, 1, None);
    wrong_height.height = CheckpointHeight(3);
    let wrong_height = wrong_height.sign_with(&sk(1));

    let mut no_advance = mesh.round_change(1, 1, None);
    no_advance.target_round = Round(0); // does not advance
    let no_advance = no_advance.sign_with(&sk(1));

    for payload in [
        wrong_generation.encode(),
        wrong_height.encode(),
        no_advance.encode(),
    ] {
        mesh.nodes[0].broadcast(MessageKind::RoundChange, payload);
    }
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].round_changes, 0,
            "none of the three is acceptable"
        );
        assert!(mesh.nodes[i].refusal_count() >= 1);
    }
}

#[test]
fn bh_04_replayed_round_change_is_dropped() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    let bytes = mesh.round_change(1, 1, None).encode();
    mesh.nodes[0].broadcast(MessageKind::RoundChange, bytes.clone());
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert_eq!(mesh.nodes[i].round_changes, 1);
    }
    // The identical frame again: refused by the replay window, not counted twice.
    mesh.nodes[0].broadcast(MessageKind::RoundChange, bytes);
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].round_changes, 1,
            "a replayed change is not counted twice"
        );
    }
}

#[test]
fn bh_05_three_validators_change_round_at_once() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    for (index, seed) in [(0usize, 1u8), (1, 2), (2, 3)] {
        let bytes = mesh.round_change(seed, 1, None).encode();
        mesh.nodes[index].broadcast(MessageKind::RoundChange, bytes);
    }
    mesh.drain();
    // Node 4 receives from all three; each sender receives from the other two.
    assert_eq!(mesh.nodes[3].round_changes, 3, "node 4 collected all three");
    for i in 0..3 {
        assert_eq!(
            mesh.nodes[i].round_changes, 2,
            "node {i} collected the other two"
        );
    }
}

// ---------------------------------------------------------------------------
// Priority 2 — bootstrap over TCP
// ---------------------------------------------------------------------------

#[test]
fn bh_06_blank_node_requests_a_bundle_and_installs_it() {
    let chain = build_chain();
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    mesh.nodes[0].serve_history(chain.bundle.clone());

    // Node 1 asks for history from height 0 and receives the bundle.
    mesh.nodes[1].broadcast(
        MessageKind::SyncRequest,
        SyncRequest {
            network: NET,
            from_height: CheckpointHeight(0),
            max_links: 16,
        }
        .encode(),
    );
    mesh.drain();

    assert!(
        mesh.nodes[1].installed_links >= 2,
        "the blank node verified and installed the two links, got {}",
        mesh.nodes[1].installed_links
    );
    assert!(!mesh.nodes[0]
        .served
        .as_ref()
        .expect("served")
        .links
        .is_empty());
}

#[test]
fn bh_07_tampered_bundle_installs_nothing() {
    let chain = build_chain();
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    mesh.nodes[0].serve_history(chain.bundle.clone());

    let mut bytes = chain.bundle.encode().expect("encode");
    let last = bytes.len() - 5;
    bytes[last] ^= 0x40;
    mesh.nodes[0].broadcast(MessageKind::BootstrapResponse, bytes);
    mesh.drain();

    assert_eq!(
        mesh.nodes[1].installed_links, 0,
        "a bundle whose bytes were altered installs nothing"
    );
    assert!(
        mesh.nodes[1].refusal_count() >= 1,
        "the refusal is recorded"
    );
}

// ---------------------------------------------------------------------------
// Priority 3 — HALT over TCP
// ---------------------------------------------------------------------------

#[test]
fn bh_08_halt_proof_crosses_sockets_and_halts_every_peer() {
    let proof = halt_proof();
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    mesh.nodes[0].broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh.drain();

    for i in 1..mesh.nodes.len() {
        assert!(
            mesh.nodes[i].halt_proof().is_some(),
            "node {i} verified and accepted the proof"
        );
        assert!(
            mesh.nodes[i].engine().is_halted(),
            "node {i} entered the HALT state"
        );
        assert!(
            mesh.nodes[i].halt_persisted(),
            "node {i} persisted the record"
        );
        assert!(
            mesh.nodes[i]
                .prevote_with([0x11; 32], &MemoryAtomicSlotStore::new())
                .is_err(),
            "a halted node signs nothing"
        );
    }
}

#[test]
fn bh_09_invalid_halt_proof_halts_nobody() {
    let proof = halt_proof();
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);

    // Same value twice is not a conflict: swap one half for the other's value.
    let mut no_conflict = proof.clone();
    no_conflict.second = proof.first.clone();
    mesh.nodes[0].broadcast(MessageKind::HaltEvidence, no_conflict.encode());

    // A truncated proof and a tampered one.
    let bytes = proof.encode();
    mesh.nodes[0].broadcast(MessageKind::HaltEvidence, bytes[..bytes.len() - 3].to_vec());
    let mut tampered = bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    mesh.nodes[0].broadcast(MessageKind::HaltEvidence, tampered);
    mesh.drain();

    for i in 1..mesh.nodes.len() {
        assert!(
            !mesh.nodes[i].engine().is_halted(),
            "node {i} must not halt on invalid evidence"
        );
        assert!(
            mesh.nodes[i].refusal_count() >= 1,
            "the refusals are recorded"
        );
    }
}

#[test]
fn bh_10_alert_never_halts_a_node() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    mesh.nodes[0].broadcast(MessageKind::HaltEvidence, vec![0x77u8; 32]);
    mesh.drain();

    for i in 1..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].halt_evidence(),
            Some([0x77u8; 32]),
            "the alert is recorded by node {i}"
        );
        assert!(
            !mesh.nodes[i].engine().is_halted(),
            "an alert stops nothing"
        );
        assert!(
            mesh.nodes[i].status().may_sign,
            "node {i} still signs after an alert"
        );
        assert!(
            !mesh.nodes[i].halt_persisted(),
            "an alert writes no halt record"
        );
        assert!(mesh.nodes[i].round_changes == 0);
    }

    // BZ.5 (A1): the alert must not gate consensus ingress. Three members
    // prevote the same value; every node records all three prevotes, including
    // the nodes that saw the alert.
    let value = [0x42u8; 32];
    for i in 0..3 {
        let prevote = mesh.nodes[i]
            .prevote_value(value)
            .expect("a node that saw an alert still prevotes");
        mesh.nodes[i].broadcast(MessageKind::Prevote, prevote.vote().encode());
    }
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].status().prevotes,
            3,
            "prevotes are still accepted by node {i} after an alert"
        );
        assert!(mesh.nodes[i].status().may_sign);
    }

    // And precommit: node 1 builds the POL from the prevotes it recorded, and
    // the other nodes accept the precommit.
    let pol: PrevoteCertificate = mesh.nodes[1]
        .certify_prevotes(value)
        .expect("prevote quorum after an alert");
    let precommit = mesh.nodes[1]
        .precommit_value(&pol)
        .expect("precommit after an alert");
    mesh.nodes[1].broadcast(MessageKind::Precommit, precommit.vote().encode());
    mesh.drain();
    for i in 2..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].status().precommits,
            1,
            "precommits are still accepted by node {i} after an alert"
        );
    }

    // The rest of the network still works: a round change still goes through.
    let bytes = mesh.round_change(1, 1, None).encode();
    mesh.nodes[0].broadcast(MessageKind::RoundChange, bytes);
    mesh.drain();
    assert_eq!(
        mesh.nodes[1].round_changes, 1,
        "the network still works after an alert"
    );
    let _ = Instant::now();
    let _: Option<Incoming> = None;
}
