//! Shared fixture for the mission-BH integration tests.
//!
//! Included with `#[path = "support/bh_fixture.rs"] mod fixture;` from each test
//! file: a real 4-validator cluster produces a chain of decided checkpoints, and a
//! mesh of real `Node`s is built on loopback sockets.
//!
//! Nothing here is a shortcut around verification: the bundle produced by
//! [`Chain::bundle`] is only what a serving node would hold; every receiving side
//! runs `verify_history` again.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::sync::{GenerationSpec, SyncAnchor, SyncBundle, SyncLink};
use aether_unified::l2bft::{BftState, PrecommitCertificate};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::MemoryAtomicSlotStore;
use aether_unified::network::{Node, PeerLimits};

pub const NET: u64 = 41;
pub const ANCHOR: [u8; 32] = [0x5A; 32];
pub const GEN: [u8; 32] = [7u8; 32];
pub const WEIGHT: u64 = 10;
pub const SEEDS: [u8; 4] = [1, 2, 3, 4];

pub fn sk(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

pub fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

pub fn sign_with(seed: u8) -> impl FnOnce(&[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let key = sk(seed);
    move |message: &[u8]| key.sign(message).to_bytes()
}

pub fn registry_with(seeds: &[u8]) -> ValidatorRegistry {
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

pub fn limits() -> PeerLimits {
    PeerLimits {
        read_timeout: Duration::from_millis(20),
        write_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(2),
        max_messages_per_second: 500,
        ..PeerLimits::default()
    }
}

/// Produce a precommit certificate for `value` from four live engines.
pub fn certify_with(
    engines: &mut [BftState],
    stores: &[MemoryAtomicSlotStore],
    registry: &ValidatorRegistry,
    seeds: &[u8],
    value: [u8; 32],
) -> PrecommitCertificate {
    let mut prevotes: Vec<ConsensusVote> = Vec::new();
    for index in 0..seeds.len() {
        prevotes.push(
            engines[index]
                .prevote(
                    value,
                    vid(seeds[index]),
                    registry,
                    &stores[index],
                    sign_with(seeds[index]),
                )
                .expect("prevote")
                .vote()
                .clone(),
        );
    }
    for engine in engines.iter_mut() {
        for vote in &prevotes {
            engine.accept_vote(vote, registry);
        }
    }
    let pol = engines[0]
        .certify_prevotes_for(value, registry)
        .expect("prevote quorum");
    let mut precommits: Vec<ConsensusVote> = Vec::new();
    for index in 0..seeds.len() {
        precommits.push(
            engines[index]
                .precommit(
                    &pol,
                    vid(seeds[index]),
                    registry,
                    &stores[index],
                    sign_with(seeds[index]),
                )
                .expect("precommit")
                .vote()
                .clone(),
        );
    }
    for engine in engines.iter_mut() {
        for vote in &precommits {
            engine.accept_vote(vote, registry);
        }
    }
    engines[0]
        .certify_precommits_for(value, registry)
        .expect("precommit quorum")
}

/// A chain of `tip + 1` decided checkpoints, and the bundle that describes it.
pub struct Chain {
    pub registry: ValidatorRegistry,
    pub checkpoints: Vec<Checkpoint>,
    pub certificates: Vec<PrecommitCertificate>,
}

impl Chain {
    /// A bundle covering heights `from ..= to`, anchored on `from`.
    pub fn slice(&self, from: u64, to: u64) -> SyncBundle {
        let links: Vec<SyncLink> = (from..=to)
            .map(|height| SyncLink {
                checkpoint: self.checkpoints[height as usize],
                certificate: self.certificates[height as usize].clone(),
            })
            .collect();
        let first = &links[0].checkpoint;
        let anchor = SyncAnchor {
            network: NET,
            height: first.height,
            checkpoint_id: first.id(),
            generation: first.generation,
            set_root: first.validator_set_root,
        };
        SyncBundle {
            anchor,
            generations: vec![GenerationSpec {
                number: 0,
                registry: self.registry.clone(),
                closure: None,
            }],
            links,
        }
    }

    /// The whole history from height 0.
    pub fn bundle(&self) -> SyncBundle {
        self.slice(0, (self.checkpoints.len() - 1) as u64)
    }
}

/// Build `tip + 1` decided checkpoints with four validators.
pub fn build_chain(tip: u64) -> Chain {
    let registry = registry_with(&SEEDS);
    let mut engines: Vec<BftState> = SEEDS
        .iter()
        .map(|_| BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR))
        .collect();
    let stores: Vec<MemoryAtomicSlotStore> =
        SEEDS.iter().map(|_| MemoryAtomicSlotStore::new()).collect();
    let mut checkpoints = Vec::new();
    let mut certificates = Vec::new();
    let mut parent = [0u8; 32];

    for height in 0..=tip {
        let cp = Checkpoint::new(
            registry.generation(),
            CheckpointHeight(height),
            parent,
            [0x22u8.wrapping_add(height as u8); 32],
            [0x33u8.wrapping_add(height as u8); 32],
            registry.set_root(),
            None,
        )
        .expect("checkpoint");
        let certificate = certify_with(&mut engines, &stores, &registry, &SEEDS, cp.id());
        for index in 0..SEEDS.len() {
            let parent_checkpoint = checkpoints.last();
            engines[index]
                .finalize(
                    &certificate,
                    &cp,
                    parent_checkpoint,
                    &registry,
                    &stores[index],
                )
                .expect("finality");
        }
        parent = cp.id();
        checkpoints.push(cp);
        certificates.push(certificate);
        for index in 0..SEEDS.len() {
            engines[index]
                .advance_height(CheckpointHeight(height + 1), &stores[index])
                .expect("advance");
        }
    }
    Chain {
        registry,
        checkpoints,
        certificates,
    }
}

/// A fully connected mesh of real nodes on loopback.
pub struct Mesh {
    pub seeds: Vec<u8>,
    pub nodes: Vec<Node>,
    pub registry: ValidatorRegistry,
}

impl Mesh {
    pub fn new(seeds: &[u8]) -> Self {
        let registry = registry_with(seeds);
        let mut nodes: Vec<Node> = seeds
            .iter()
            .map(|seed| {
                let mut node = Node::bind_with_limits(
                    "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
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

    pub fn drain(&mut self) {
        for _ in 0..60 {
            let mut quiet = true;
            for node in &mut self.nodes {
                let mut guard = 0;
                while node
                    .poll(Duration::from_millis(10))
                    .expect("poll")
                    .is_some()
                {
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
}
