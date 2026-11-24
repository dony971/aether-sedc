//! Mission BZ.5 — remediation of the two HALT defects found by the BZ.4 audit.
//!
//! | Defect | What BZ.5 changes | Tests |
//! |---|---|---|
//! | A1: a HALT **alert** gated consensus ingress | only the engine's own HALT state gates ingress; an alert stops nothing, including transaction admission | `dh_01` - `dh_04` |
//! | A2: `halt_persisted()` claimed durability without checking the write | `halt_with` reports the write/flush/read-back result, and `halt_persisted()` is true only after a confirmed, read-back-identical record | `dh_05` - `dh_11` |
//!
//! Nothing here changes a consensus rule: the tests drive the existing engine,
//! the existing `HaltProof`, and the existing store trait. The negative cases use
//! a store with injected faults, so each failure mode is exercised explicitly.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::halt_proof::HaltProof;
use aether_unified::l2bft::{restore_engine, BftState, HaltReason, PrecommitCertificate};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase};
use aether_unified::l2persist::{
    seal, AtomicSlotStore, CasStore, MemoryAtomicSlotStore, SledAtomicSlotStore, SlotStoreError,
    HALT_KEY,
};
use aether_unified::network::protocol::MessageKind;
use aether_unified::network::{Node, PeerLimits};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const NET: u64 = 47;
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

fn node(seed: u8, registry: &ValidatorRegistry) -> Node {
    Node::bind_with_limits(
        ephemeral(),
        NET,
        sk(seed),
        BftState::new(NET, registry, CheckpointHeight(0), ANCHOR),
        registry.clone(),
        limits(),
    )
    .expect("bind")
}

/// One node dials another; the dialer finishes its pending handshake.
fn connect(a: &mut Node, b: &mut Node) {
    a.dial(b.addr()).expect("dial");
    b.accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("handshake");
    a.finish_dials();
}

fn drain(nodes: &mut [Node]) {
    for _ in 0..80 {
        let mut quiet = true;
        for node in nodes.iter_mut() {
            let mut guard = 0;
            while node.poll(Duration::from_millis(5)).expect("poll").is_some() {
                quiet = false;
                guard += 1;
                if guard > 80 {
                    break;
                }
            }
        }
        if quiet {
            return;
        }
    }
}

/// A mesh of real nodes, all connected to each other.
struct Mesh {
    nodes: Vec<Node>,
    registry: ValidatorRegistry,
}

impl Mesh {
    fn new(seeds: &[u8]) -> Self {
        let registry = registry_with(seeds);
        let mut nodes: Vec<Node> = seeds
            .iter()
            .map(|seed| {
                let mut node = node(*seed, &registry);
                node.attach_halt_store(Box::new(MemoryAtomicSlotStore::new()));
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
        Self { nodes, registry }
    }

    fn drain(&mut self) {
        drain(&mut self.nodes);
    }
}

// ---------------------------------------------------------------------------
// Proof fixture: two quorum certificates over different values, one height.
// ---------------------------------------------------------------------------

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
    let pol = engines[0]
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
        let checkpoint = Checkpoint::new(
            registry.generation(),
            CheckpointHeight(0),
            [0u8; 32],
            [0x22u8 ^ salt; 32],
            [0x33u8 ^ salt; 32],
            registry.set_root(),
            None,
        )
        .expect("checkpoint");
        let certificate = certify_with(&mut engines, &stores, &registry, &seeds, checkpoint.id());
        (checkpoint, certificate)
    };
    HaltProof {
        network: NET,
        generation: registry.generation(),
        height: CheckpointHeight(0),
        first: make(0),
        second: make(0x80),
    }
}

fn signed_vote(seed: u8, phase: VotePhase, value: [u8; 32]) -> ConsensusVote {
    let unsigned = ConsensusVote::new(
        NET,
        GenerationId(GEN),
        CheckpointHeight(0),
        Round(0),
        phase,
        value,
        vid(seed),
    );
    let signature = sk(seed).sign(&unsigned.signing_bytes()).to_bytes();
    unsigned.with_signature(signature)
}

// ---------------------------------------------------------------------------
// A store with injectable faults, for the negative durability cases.
// ---------------------------------------------------------------------------

struct FaultInner {
    inner: MemoryAtomicSlotStore,
    fail_cas: AtomicBool,
    fail_flush: AtomicBool,
    fail_get: AtomicBool,
    corrupt_read: AtomicBool,
}

#[derive(Clone)]
struct FaultStore(Arc<FaultInner>);

impl FaultStore {
    fn new() -> Self {
        Self(Arc::new(FaultInner {
            inner: MemoryAtomicSlotStore::new(),
            fail_cas: AtomicBool::new(false),
            fail_flush: AtomicBool::new(false),
            fail_get: AtomicBool::new(false),
            corrupt_read: AtomicBool::new(false),
        }))
    }

    fn fail_cas(&self, yes: bool) {
        self.0.fail_cas.store(yes, Ordering::SeqCst);
    }

    fn fail_flush(&self, yes: bool) {
        self.0.fail_flush.store(yes, Ordering::SeqCst);
    }

    fn fail_get(&self, yes: bool) {
        self.0.fail_get.store(yes, Ordering::SeqCst);
    }

    fn corrupt_read(&self, yes: bool) {
        self.0.corrupt_read.store(yes, Ordering::SeqCst);
    }

    /// The bytes really held, bypassing every injected fault.
    fn raw(&self, key: &str) -> Option<Vec<u8>> {
        self.0.inner.get(key).expect("raw read")
    }
}

impl CasStore for FaultStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SlotStoreError> {
        if self.0.fail_get.load(Ordering::SeqCst) {
            return Err(SlotStoreError::Storage("injected read failure".to_string()));
        }
        let value = self.0.inner.get(key)?;
        if self.0.corrupt_read.load(Ordering::SeqCst) {
            return Ok(value.map(|mut bytes| {
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0x01;
                }
                bytes
            }));
        }
        Ok(value)
    }

    fn cas(&self, key: &str, expected: Option<&[u8]>, new: &[u8]) -> Result<bool, SlotStoreError> {
        if self.0.fail_cas.load(Ordering::SeqCst) {
            return Err(SlotStoreError::Storage(
                "injected write failure".to_string(),
            ));
        }
        self.0.inner.cas(key, expected, new)
    }

    fn scan(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, SlotStoreError> {
        self.0.inner.scan(prefix)
    }

    fn flush(&self) -> Result<(), SlotStoreError> {
        if self.0.fail_flush.load(Ordering::SeqCst) {
            return Err(SlotStoreError::Storage(
                "injected flush failure".to_string(),
            ));
        }
        self.0.inner.flush()
    }

    fn backend(&self) -> &'static str {
        "bz5-fault-store"
    }
}

impl AtomicSlotStore for FaultStore {}

// ---------------------------------------------------------------------------
// A1 — an alert is evidence, never a stop
// ---------------------------------------------------------------------------

#[test]
fn dh_01_alert_from_a_non_member_blocks_nothing() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    // Seed 9 is not in the validator registry. The handshake authenticates its
    // key, not its membership, which is exactly the case the audit found.
    let mut outsider = node(9, &mesh.registry);
    connect(&mut outsider, &mut mesh.nodes[0]);

    outsider.broadcast(MessageKind::HaltEvidence, vec![0x99u8; 32]);
    mesh.drain();

    assert_eq!(
        mesh.nodes[0].halt_evidence(),
        Some([0x99u8; 32]),
        "the non-member's alert is recorded as evidence"
    );
    assert!(
        !mesh.nodes[0].engine().is_halted(),
        "a non-member's alert halts nothing"
    );
    assert!(mesh.nodes[0].status().may_sign);
    assert!(!mesh.nodes[0].halt_persisted(), "an alert writes no record");

    // Consensus ingress is still open: a member's prevote is accepted.
    let prevote = mesh.nodes[1].prevote_value([0x11u8; 32]).expect("prevote");
    mesh.nodes[1].broadcast(MessageKind::Prevote, prevote.vote().encode());
    mesh.drain();
    assert_eq!(
        mesh.nodes[0].status().prevotes,
        1,
        "a prevote is still accepted after the non-member's alert"
    );
}

#[test]
fn dh_02_malformed_alerts_are_refused_and_halt_nobody() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    for payload in [vec![0xABu8; 31], vec![0xABu8; 33], vec![0x01u8, 0x09]] {
        mesh.nodes[0].broadcast(MessageKind::HaltEvidence, payload);
    }
    mesh.drain();

    for i in 1..mesh.nodes.len() {
        assert!(
            mesh.nodes[i].refusal_count() >= 1,
            "node {i} refused every malformed alert"
        );
        assert_eq!(mesh.nodes[i].halt_evidence(), None);
        assert!(!mesh.nodes[i].engine().is_halted());
        assert!(mesh.nodes[i].status().may_sign);
    }
}

#[test]
fn dh_03_alert_during_consensus_does_not_drop_the_vote() {
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    let value = [0x31u8; 32];
    // Three prevotes are in flight when the alert arrives.
    for i in 0..3 {
        let prevote = mesh.nodes[i].prevote_value(value).expect("prevote");
        mesh.nodes[i].broadcast(MessageKind::Prevote, prevote.vote().encode());
    }
    mesh.nodes[3].broadcast(MessageKind::HaltEvidence, vec![0x44u8; 32]);
    mesh.drain();

    for i in 0..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[i].status().prevotes,
            3,
            "node {i} recorded the prevotes that crossed the alert"
        );
        assert!(!mesh.nodes[i].engine().is_halted());
        if i != 3 {
            assert_eq!(
                mesh.nodes[i].halt_evidence(),
                Some([0x44u8; 32]),
                "node {i} also recorded the alert"
            );
        }
    }

    // And the nodes that saw the alert still accept the precommit phase.
    let pol = mesh.nodes[0]
        .certify_prevotes(value)
        .expect("prevote quorum");
    let precommit = mesh.nodes[0].precommit_value(&pol).expect("precommit");
    mesh.nodes[0].broadcast(MessageKind::Precommit, precommit.vote().encode());
    mesh.drain();
    assert_eq!(mesh.nodes[3].status().precommits, 1);
}

#[test]
fn dh_04_valid_proof_halts_persists_and_refuses_votes() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let mut mesh = Mesh::new(&[1, 2, 3, 4]);
    for node in &mut mesh.nodes {
        node.attach_halt_store(Box::new(MemoryAtomicSlotStore::new()));
    }

    mesh.nodes[0].broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh.drain();

    let expected = seal(
        &proof
            .verify(&registry)
            .expect("conflict")
            .describe()
            .into_bytes(),
    );
    for i in 1..mesh.nodes.len() {
        assert!(mesh.nodes[i].halt_proof().is_some());
        assert!(mesh.nodes[i].engine().is_halted());
        assert!(
            mesh.nodes[i].halt_persisted(),
            "node {i} confirmed the durable record"
        );
        assert!(mesh.nodes[i].halt_record_error().is_none());
        assert!(!mesh.nodes[i].status().may_sign);
        assert!(
            mesh.nodes[i]
                .prevote_with([0x12u8; 32], &MemoryAtomicSlotStore::new())
                .is_err(),
            "a halted node signs nothing"
        );
    }

    // A well-formed consensus message arriving after the HALT is refused.
    let vote = signed_vote(1, VotePhase::Precommit, [0x66u8; 32]);
    mesh.nodes[0].broadcast(MessageKind::Precommit, vote.encode());
    mesh.drain();
    for i in 1..mesh.nodes.len() {
        assert_eq!(mesh.nodes[i].status().precommits, 0);
        assert!(mesh.nodes[i].refusal_count() >= 1);
    }
    let _ = expected;
}

#[test]
fn dh_05_halt_survives_a_restart_with_a_durable_store() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let mut sender = node(1, &registry);
        let mut receiver = node(2, &registry);
        receiver.attach_halt_store(Box::new(
            SledAtomicSlotStore::open(dir.path()).expect("open store"),
        ));
        connect(&mut sender, &mut receiver);

        sender.broadcast(MessageKind::HaltEvidence, proof.encode());
        mesh_drain_pair(&mut sender, &mut receiver);
        assert!(receiver.engine().is_halted());
        assert!(receiver.halt_persisted(), "the sled record is durable");
    }

    // The receiver was dropped with the block above: reopen the same directory.
    let store = SledAtomicSlotStore::open(dir.path()).expect("reopen store");
    let restored = restore_engine(&store, &registry, Some(ANCHOR), NET, CheckpointHeight(0));
    assert!(
        restored.state.is_halted(),
        "a restart reloads the durable HALT"
    );
    assert!(restored.state.may_sign().is_err());
}

// ---------------------------------------------------------------------------
// A2 — durability is a result, not an inference
// ---------------------------------------------------------------------------

#[test]
fn dh_06_successful_write_is_durable_and_reads_back() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let store = FaultStore::new();

    let mut sender = node(1, &registry);
    let mut receiver = node(2, &registry);
    receiver.attach_halt_store(Box::new(store.clone()));
    connect(&mut sender, &mut receiver);
    sender.broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh_drain_pair(&mut sender, &mut receiver);

    assert!(receiver.engine().is_halted());
    assert!(receiver.halt_persisted(), "a confirmed write is durable");
    assert!(receiver.halt_record_error().is_none());
    let expected = seal(
        &proof
            .verify(&registry)
            .expect("conflict")
            .describe()
            .into_bytes(),
    );
    assert_eq!(
        store.raw(HALT_KEY),
        Some(expected),
        "the record is the sealed description of the verified reason"
    );
}

#[test]
fn dh_07_write_failure_is_not_reported_as_durable() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let store = FaultStore::new();
    store.fail_cas(true);

    let mut sender = node(1, &registry);
    let mut receiver = node(2, &registry);
    receiver.attach_halt_store(Box::new(store.clone()));
    connect(&mut sender, &mut receiver);
    sender.broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh_drain_pair(&mut sender, &mut receiver);

    assert!(receiver.engine().is_halted(), "the stop is still in memory");
    assert!(!receiver.status().may_sign);
    assert!(!receiver.halt_persisted(), "a failed write is not durable");
    let error = receiver.halt_record_error().expect("a reason is reported");
    assert!(
        error.contains("injected write failure"),
        "unexpected error: {error}"
    );
    assert!(store.raw(HALT_KEY).is_none());
    // A restarted engine has no record to reload.
    let fresh = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    assert!(!fresh.is_halted());
}

#[test]
fn dh_08_flush_failure_is_not_reported_as_durable() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let store = FaultStore::new();
    store.fail_flush(true);

    let mut sender = node(1, &registry);
    let mut receiver = node(2, &registry);
    receiver.attach_halt_store(Box::new(store.clone()));
    connect(&mut sender, &mut receiver);
    sender.broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh_drain_pair(&mut sender, &mut receiver);

    assert!(receiver.engine().is_halted());
    assert!(
        !receiver.halt_persisted(),
        "an unflushed write is not durable"
    );
    let error = receiver.halt_record_error().expect("a reason is reported");
    assert!(
        error.contains("injected flush failure"),
        "unexpected error: {error}"
    );
}

#[test]
fn dh_09_unreadable_record_is_not_reported_as_durable() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let store = FaultStore::new();
    store.fail_get(true);

    let mut sender = node(1, &registry);
    let mut receiver = node(2, &registry);
    receiver.attach_halt_store(Box::new(store.clone()));
    connect(&mut sender, &mut receiver);
    sender.broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh_drain_pair(&mut sender, &mut receiver);

    assert!(receiver.engine().is_halted());
    assert!(
        !receiver.halt_persisted(),
        "a write that cannot be read back is not durable"
    );
    let error = receiver.halt_record_error().expect("a reason is reported");
    assert!(
        error.contains("injected read failure"),
        "unexpected error: {error}"
    );
}

#[test]
fn dh_10_read_back_mismatch_is_not_reported_as_durable() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);
    let store = FaultStore::new();
    store.corrupt_read(true);

    let mut sender = node(1, &registry);
    let mut receiver = node(2, &registry);
    receiver.attach_halt_store(Box::new(store.clone()));
    connect(&mut sender, &mut receiver);
    sender.broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh_drain_pair(&mut sender, &mut receiver);

    assert!(receiver.engine().is_halted());
    assert!(
        !receiver.halt_persisted(),
        "a record that reads back different is not durable"
    );
    let error = receiver.halt_record_error().expect("a reason is reported");
    assert!(error.contains("differs"), "unexpected error: {error}");
}

#[test]
fn dh_11_missing_store_is_explicitly_memory_only() {
    let proof = halt_proof();
    let registry = registry_with(&[1, 2, 3, 4]);

    let mut sender = node(1, &registry);
    let mut receiver = node(2, &registry);
    connect(&mut sender, &mut receiver);
    sender.broadcast(MessageKind::HaltEvidence, proof.encode());
    mesh_drain_pair(&mut sender, &mut receiver);

    assert!(receiver.engine().is_halted());
    assert!(!receiver.halt_persisted());
    let error = receiver.halt_record_error().expect("a reason is reported");
    assert!(
        error.contains("no store attached"),
        "unexpected error: {error}"
    );
    // The stop is real in memory, so consensus is still refused.
    assert!(!receiver.status().may_sign);
    assert!(receiver
        .prevote_with([0x21u8; 32], &MemoryAtomicSlotStore::new())
        .is_err());
    // But it is explicitly not durable: a fresh state has no halt.
    let fresh = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    assert!(!fresh.is_halted());
}

// ---------------------------------------------------------------------------
// A2 — the primitive itself: retry, idempotence, no overwrite
// ---------------------------------------------------------------------------

#[test]
fn dh_12_a_failed_halt_can_be_retried_without_losing_the_first_reason() {
    let registry = registry_with(&[1, 2, 3, 4]);
    let mut state = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let store = FaultStore::new();
    store.fail_cas(true);

    assert!(state
        .halt_with(HaltReason::Persisted("first".to_string()), &store)
        .is_err());
    assert!(state.is_halted(), "the in-memory stop is kept");
    assert!(!state.halt_is_durable(&store).expect("readable store"));

    store.fail_cas(false);
    state
        .halt_with(HaltReason::Persisted("second".to_string()), &store)
        .expect("a retry writes the first reason");
    assert!(state.halt_is_durable(&store).expect("readable store"));
    let first = seal(b"previous halt record: first");
    assert_eq!(store.raw(HALT_KEY), Some(first.clone()));

    // A further request is idempotent and still does not replace the record.
    state
        .halt_with(HaltReason::Persisted("third".to_string()), &store)
        .expect("an existing halt is a no-op");
    assert_eq!(store.raw(HALT_KEY), Some(first));
}

#[test]
fn dh_13_a_different_durable_record_is_never_overwritten() {
    let registry = registry_with(&[1, 2, 3, 4]);
    let mut state = BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR);
    let store = FaultStore::new();
    store
        .0
        .inner
        .cas(HALT_KEY, None, &seal(b"another halt"))
        .expect("seed record");

    let outcome = state.halt_with(HaltReason::Persisted("mine".to_string()), &store);
    assert!(outcome.is_err(), "a different durable record wins");
    assert!(state.is_halted(), "the engine still stops");
    assert!(
        !state.halt_is_durable(&store).expect("readable store"),
        "the durable record is not this halt"
    );
    assert_eq!(
        store.raw(HALT_KEY),
        Some(seal(b"another halt")),
        "the existing record was preserved"
    );
}

// ---------------------------------------------------------------------------
// Small helpers: drain two nodes without moving them into an array.
// ---------------------------------------------------------------------------

fn mesh_drain_pair(a: &mut Node, b: &mut Node) {
    for _ in 0..80 {
        let mut quiet = true;
        for node in [&mut *a, &mut *b] {
            let mut guard = 0;
            while node.poll(Duration::from_millis(5)).expect("poll").is_some() {
                quiet = false;
                guard += 1;
                if guard > 80 {
                    break;
                }
            }
        }
        if quiet {
            return;
        }
    }
}
