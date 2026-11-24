//! Mission BZ.3 — the six native interfaces, exercised through the `Node` API.
//!
//! Every test here drives consensus through `Node`, never by reaching into its
//! engine: the point of the mission is that a validator's BFT state is reachable
//! and pilotable **through an interface**, and these tests are the evidence that
//! the interface is sufficient for a real multi-process driver.
//!
//! What is not claimed anywhere in this file: that a BFT checkpoint finalises a
//! DAG transaction. The protocol defines no such relation, and §4 of the mission
//! forbids inventing one. Transactions are admitted and propagated; heights are
//! decided by votes.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};

use aether_unified::consensus::checkpoint::Checkpoint;
use aether_unified::consensus::generation::{
    CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use aether_unified::l2bft::{BftState, PrecommitCertificate};
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2crypto::vote::ConsensusVote;
use aether_unified::l2persist::state::PersistentConsensusState;
use aether_unified::l2persist::{
    seal, AtomicSlotStore, CasStore, MemoryAtomicSlotStore, SledAtomicSlotStore, STATE_KEY,
};
use aether_unified::network::{Dispatched, Incoming, MessageKind, Node, NodeError, PeerLimits};
use aether_unified::transaction::{Transaction, TransactionId};
use aether_unified::wallet::Wallet;

#[path = "support/bh_fixture.rs"]
mod fixture;

const NET: u64 = 71;
const GEN: [u8; 32] = [7u8; 32];
const ANCHOR: [u8; 32] = [0x5Au8; 32];
const WEIGHT: u64 = 10;
const SEEDS: [u8; 4] = [1, 2, 3, 4];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn vid(seed: u8) -> ValidatorId {
    validator_id(&sk(seed).verifying_key().to_bytes())
}

fn registry() -> ValidatorRegistry {
    registry_with(&SEEDS)
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

fn checkpoint() -> Checkpoint {
    let registry = registry();
    Checkpoint::new(
        registry.generation(),
        CheckpointHeight(0),
        [0u8; 32],
        [0x22; 32],
        [0x33; 32],
        registry.set_root(),
        None,
    )
    .expect("checkpoint")
}

/// Limits tuned for loopback: a short read timeout keeps a poll loop responsive
/// without turning an idle peer into a failure.
fn limits() -> PeerLimits {
    PeerLimits {
        read_timeout: Duration::from_millis(20),
        write_timeout: Duration::from_millis(500),
        idle_timeout: Duration::from_secs(5),
        max_messages_per_second: 500,
        ..PeerLimits::default()
    }
}

fn ephemeral() -> SocketAddr {
    "127.0.0.1:0".parse().expect("address")
}

fn node_with(seed: u8, registry: ValidatorRegistry) -> Node {
    Node::bind_with_limits(
        ephemeral(),
        NET,
        sk(seed),
        BftState::new(NET, &registry, CheckpointHeight(0), ANCHOR),
        registry,
        limits(),
    )
    .expect("bind")
}

fn node(seed: u8) -> Node {
    node_with(seed, registry())
}

/// Read every pending message until the node has been quiet for three polls.
fn drain(node: &mut Node) -> Vec<(ValidatorId, Incoming)> {
    let mut seen = Vec::new();
    let mut quiet = 0;
    while quiet < 3 {
        match node.poll(Duration::from_millis(10)).expect("poll") {
            Some((from, incoming)) => {
                quiet = 0;
                seen.push((from, incoming));
            }
            None => quiet += 1,
        }
    }
    seen
}

fn accepted_votes(seen: &[(ValidatorId, Incoming)]) -> Vec<&aether_unified::network::AcceptedVote> {
    seen.iter()
        .filter_map(|(_, incoming)| match incoming {
            Incoming::Accepted(Dispatched::Vote(vote)) => Some(vote),
            _ => None,
        })
        .collect()
}

fn connect(from: &mut Node, to: &mut Node) {
    let address = to.addr();
    from.dial(address).expect("dial");
    to.accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("a handshake arrived");
    from.finish_dials();
}

fn mesh(seeds: &[u8]) -> Vec<Node> {
    let registry = registry_with(seeds);
    let mut nodes: Vec<Node> = seeds
        .iter()
        .map(|seed| node_with(*seed, registry.clone()))
        .collect();
    for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            let address = nodes[j].addr();
            nodes[i].dial(address).expect("dial");
            nodes[j]
                .accept_one(Duration::from_millis(500))
                .expect("accept")
                .expect("a handshake arrived");
        }
    }
    for node in &mut nodes {
        node.finish_dials();
    }
    nodes
}

/// Run one full prevote → precommit → decide cycle entirely through `Node`.
fn cycle(
    nodes: &mut [Node],
    stores: &[MemoryAtomicSlotStore],
    cp: &Checkpoint,
) -> PrecommitCertificate {
    let value = cp.id();
    for node in nodes.iter_mut() {
        // Only the elected proposer succeeds; a refusal is a progress event and
        // does not stop the others from voting a value they were given.
        let _ = node.propose_value(value);
    }
    for (index, node) in nodes.iter_mut().enumerate() {
        let prevote = node
            .prevote_with(value, &stores[index])
            .expect("prevote through the node API");
        node.broadcast(MessageKind::Prevote, prevote.vote().encode());
    }
    for node in nodes.iter_mut() {
        drain(node);
    }
    let pol = nodes[0].certify_prevotes(value).expect("prevote quorum");
    for (index, node) in nodes.iter_mut().enumerate() {
        let precommit = node
            .precommit_with(&pol, &stores[index])
            .expect("precommit through the node API");
        node.broadcast(MessageKind::Precommit, precommit.vote().encode());
    }
    for node in nodes.iter_mut() {
        drain(node);
    }
    let qc = nodes[0]
        .certify_precommits(value)
        .expect("precommit quorum");
    for (index, node) in nodes.iter_mut().enumerate() {
        node.finalize_with(&qc, cp, None, &stores[index])
            .expect("finality through the node API");
    }
    qc
}

fn signed_transaction(wallet: &Wallet, parents: [TransactionId; 2], nonce: u64) -> Transaction {
    let mut transaction = Transaction::new(
        parents,
        wallet.address(),
        [0x42u8; 32],
        1,
        1,
        1_700_000_000_000,
        0,
        nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    transaction.signature = wallet.sign_transaction(&transaction).expect("sign");
    transaction.id = transaction.compute_hash();
    transaction
}

// ---------------------------------------------------------------------------
// §2 — the Node / BftState interface
// ---------------------------------------------------------------------------

#[test]
fn bz3_01_status_is_a_snapshot_of_the_engine() {
    let node = node(1);
    let status = node.status();

    assert_eq!(status.id, vid(1));
    assert_eq!(status.network, NET);
    assert_eq!(status.generation, GenerationId(GEN));
    assert_eq!(status.height, CheckpointHeight(0));
    assert_eq!(status.round, Round(0));
    assert!(status.may_sign, "a fresh engine may sign");
    assert!(status.recovery.is_none(), "a fresh engine has no verdict");
    assert!(!status.halted);
    assert_eq!(status.lock, None);
    assert_eq!(status.decided, None);
    assert_eq!(status.prevotes, 0);
    assert_eq!(status.precommits, 0);
    assert_eq!(status.transactions, 0);

    // The snapshot is derived from the engine, not cached: the same fields read
    // from the read-only accessor agree with it.
    assert_eq!(status.height, node.engine().height);
    assert_eq!(status.round, node.engine().round);
    assert_eq!(status.generation, node.engine().generation);
    assert_eq!(node.registry().set_root(), node.engine().set_root);
}

#[test]
fn bz3_02_the_node_signs_with_its_own_identity_or_refuses() {
    let mut node = node(1);
    let value = checkpoint().id();

    // No store: the node refuses rather than signing something it cannot persist.
    assert!(matches!(node.prevote_value(value), Err(NodeError::NoStore)));

    node.attach_store(Box::new(MemoryAtomicSlotStore::new()));
    let prevote = node.prevote_value(value).expect("prevote");
    assert_eq!(prevote.validator(), vid(1), "the node signs as itself");
    assert_eq!(prevote.checkpoint_id(), value);
    assert_eq!(prevote.context().generation, GenerationId(GEN));
    assert_eq!(prevote.context().height, CheckpointHeight(0));
    assert_eq!(prevote.context().round, Round(0));

    // A second, different value in the same round is refused by the engine: the
    // node does not get to choose, and the interface does not soften it.
    assert!(node.prevote_value([0x22u8; 32]).is_err());
    assert_eq!(node.status().prevotes, 1);
}

#[test]
fn bz3_03_a_restarted_validator_does_not_sign_a_second_value() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("store");
    let registry = registry();
    let value = checkpoint().id();

    {
        let store = SledAtomicSlotStore::open(&path).expect("open store");
        let init = PersistentConsensusState::fresh(NET, GenerationId(GEN), ANCHOR);
        store
            .cas(STATE_KEY, None, &seal(&init.encode()))
            .expect("bootstrap anchor");
        let restored = aether_unified::l2bft::restore_engine(
            &store,
            &registry,
            Some(ANCHOR),
            NET,
            CheckpointHeight(0),
        );
        let mut node = Node::bind_with_limits(
            ephemeral(),
            NET,
            sk(1),
            restored.state,
            registry.clone(),
            limits(),
        )
        .expect("bind");
        node.attach_store(Box::new(store));
        node.prevote_value(value).expect("sign in the first run");
    }

    let store = SledAtomicSlotStore::open(&path).expect("reopen store");
    let restored = aether_unified::l2bft::restore_engine(
        &store,
        &registry,
        Some(ANCHOR),
        NET,
        CheckpointHeight(0),
    );
    assert!(restored.decisions.is_empty());
    let mut node =
        Node::bind_with_limits(ephemeral(), NET, sk(1), restored.state, registry, limits())
            .expect("bind");
    node.attach_store(Box::new(store));

    // The durable slot is already spent: a different value in the same position is
    // refused, and no second signature exists.
    assert!(node.prevote_value([0x22u8; 32]).is_err());
    // The same value is returned, not re-signed: the engine's own idempotence.
    let again = node.prevote_value(value).expect("the stored vote");
    assert_eq!(again.checkpoint_id(), value);
    assert_eq!(node.status().prevotes, 1);
}

// ---------------------------------------------------------------------------
// §3 — vote transport
// ---------------------------------------------------------------------------

#[test]
fn bz3_04_an_accepted_vote_reaches_the_receiver_with_its_bytes() {
    let mut nodes = mesh(&[1, 3]);
    let value = checkpoint().id();
    let store = MemoryAtomicSlotStore::new();
    let prevote = nodes[0].prevote_with(value, &store).expect("prevote");
    nodes[0].broadcast(MessageKind::Prevote, prevote.vote().encode());

    let seen = drain(&mut nodes[1]);
    let votes = accepted_votes(&seen);
    assert_eq!(votes.len(), 1, "exactly one vote arrived");
    let accepted = votes[0];
    assert!(accepted.is_accepted(), "the engine accepted it");
    assert_eq!(
        accepted.vote().encode(),
        prevote.vote().encode(),
        "the bytes that arrived are the bytes that were signed"
    );
    assert_eq!(accepted.vote().validator, vid(1));
    assert_eq!(accepted.vote().checkpoint_id, value);
    assert!(matches!(
        accepted.outcome(),
        aether_unified::l2bft::VoteOutcome::Accepted { .. }
    ));
}

#[test]
fn bz3_05_an_accepted_vote_is_relayed_once_to_a_third_validator() {
    // A line, not a mesh: A and C are not connected, so C can only learn the vote
    // from B. This is what the old `Dispatched::Vote(VoteOutcome)` prevented.
    let mut a = node(1);
    let mut b = node(2);
    let mut c = node(3);
    connect(&mut a, &mut b);
    connect(&mut b, &mut c);
    assert_eq!(a.peers().len(), 1);
    assert_eq!(b.peers().len(), 2);
    assert_eq!(c.peers().len(), 1);

    let store = MemoryAtomicSlotStore::new();
    let prevote = a.prevote_with(checkpoint().id(), &store).expect("prevote");
    a.broadcast(MessageKind::Prevote, prevote.vote().encode());

    let at_b = drain(&mut b);
    assert_eq!(accepted_votes(&at_b).len(), 1, "B accepted the vote");
    assert_eq!(b.relayed_out, 1, "B relayed it once");

    let at_c = drain(&mut c);
    let relayed = accepted_votes(&at_c);
    assert_eq!(relayed.len(), 1, "C received the relayed vote");
    assert_eq!(relayed[0].vote().encode(), prevote.vote().encode());
}

#[test]
fn bz3_06_a_refused_vote_is_never_relayed() {
    let mut a = node(1);
    let mut b = node(2);
    let mut c = node(3);
    connect(&mut a, &mut b);
    connect(&mut b, &mut c);

    // A signs in round 1 while B is still in round 0: B's engine refuses it.
    a.begin_round(Round(1)).expect("advance the round");
    let store = MemoryAtomicSlotStore::new();
    let foreign = a.prevote_with(checkpoint().id(), &store).expect("prevote");
    a.broadcast(MessageKind::Prevote, foreign.vote().encode());

    let at_b = drain(&mut b);
    let votes = accepted_votes(&at_b);
    assert_eq!(votes.len(), 1, "the vote reached B's dispatcher");
    assert!(
        !votes[0].is_accepted(),
        "B's engine refused it as a foreign round"
    );
    assert_eq!(b.relayed_out, 0, "a refused vote is not relayed");
    assert!(drain(&mut c).is_empty(), "C heard nothing");
}

// ---------------------------------------------------------------------------
// §5 — connections
// ---------------------------------------------------------------------------

#[test]
fn bz3_07_a_second_connection_does_not_reset_the_peers_replay_window() {
    let mut a = node(1);
    let mut b = node(2);
    connect(&mut a, &mut b);

    // A second socket from the same key: one peer, and the old one is closed.
    let address = b.addr();
    a.dial(address).expect("second dial");
    b.accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("a handshake arrived");
    a.finish_dials();
    assert_eq!(b.peers().len(), 1, "one validator is one peer");
    assert_eq!(b.duplicate_connections_closed(), 1);
    assert_eq!(a.duplicate_connections_closed(), 1);

    // The surviving link works, and the replay window survived the duplicate: the
    // same envelope twice is one acceptance and one duplicate.
    let store = MemoryAtomicSlotStore::new();
    let prevote = a.prevote_with(checkpoint().id(), &store).expect("prevote");
    let bytes = prevote.vote().encode();
    a.broadcast(MessageKind::Prevote, bytes.clone());
    drain(&mut b);
    a.broadcast(MessageKind::Prevote, bytes);
    drain(&mut b);
    assert!(
        b.refusals.get("duplicate").copied().unwrap_or(0) >= 1,
        "the replay window was not erased by the second connection"
    );
}

#[test]
fn bz3_08_simultaneous_dials_converge_on_one_link() {
    let mut a = node(1);
    let mut b = node(2);
    let a_addr = a.addr();
    let b_addr = b.addr();
    // Both sides dial before either accepts: two sockets for one pair.
    a.dial(b_addr).expect("a dials b");
    b.dial(a_addr).expect("b dials a");
    a.finish_dials();
    b.finish_dials();
    for _ in 0..4 {
        let _ = a.accept_one(Duration::from_millis(100));
        let _ = b.accept_one(Duration::from_millis(100));
        a.finish_dials();
        b.finish_dials();
    }

    assert_eq!(a.peers(), vec![vid(2)], "one link survives at A");
    assert_eq!(b.peers(), vec![vid(1)], "one link survives at B");
    assert!(a.duplicate_connections_closed() >= 1);
    assert!(b.duplicate_connections_closed() >= 1);

    // And the survivor is usable in both directions.
    let store = MemoryAtomicSlotStore::new();
    let prevote = a.prevote_with(checkpoint().id(), &store).expect("prevote");
    assert_eq!(
        a.broadcast(MessageKind::Prevote, prevote.vote().encode()),
        1
    );
    assert_eq!(accepted_votes(&drain(&mut b)).len(), 1);
}

#[test]
fn bz3_09_disconnect_releases_the_address_slot_and_reconnect_restores_the_link() {
    let mut a = node(1);
    let mut b = node(2);
    connect(&mut a, &mut b);
    assert_eq!(a.address_book().total(), 1);

    assert!(a.disconnect(&vid(2)));
    assert!(a.peers().is_empty());
    assert_eq!(
        a.address_book().total(),
        0,
        "the address slot is released, not leaked"
    );

    let address = b.addr();
    assert!(a.reconnect(address).expect("reconnect"));
    // The peer side must accept the new socket: a reconnect is two ends.
    let _ = b.accept_one(Duration::from_millis(500));
    a.finish_dials();
    assert!(a.peers().contains(&vid(2)), "the peer is back");
    assert!(!a.reconnect(address).expect("idempotent"), "already known");
}

// ---------------------------------------------------------------------------
// §4 — DAG submission
// ---------------------------------------------------------------------------

#[test]
fn bz3_10_a_submitted_transaction_is_held_and_propagated() {
    let mut nodes = mesh(&[1, 2, 3]);
    let wallet = Wallet::new();
    let transaction = signed_transaction(&wallet, [[0u8; 32]; 2], 1);

    let submission = nodes[0].submit(transaction.clone()).expect("submission");
    assert_eq!(submission.id, transaction.id);
    assert_eq!(submission.peers_notified, 2, "both peers were told");
    assert!(nodes[0].holds_transaction(&transaction.id));
    assert_eq!(nodes[0].transactions(), 1);
    assert_eq!(nodes[0].status().transactions, 1);

    drain(&mut nodes[1]);
    drain(&mut nodes[2]);
    assert!(nodes[1].holds_transaction(&transaction.id));
    assert!(nodes[2].holds_transaction(&transaction.id));
    assert_eq!(
        nodes[1].transaction(&transaction.id).expect("held").id,
        transaction.id
    );
}

#[test]
fn bz3_11_submission_refuses_a_bad_signature_a_duplicate_and_an_unknown_parent() {
    let mut node = node(1);
    let wallet = Wallet::new();
    let transaction = signed_transaction(&wallet, [[0u8; 32]; 2], 1);

    let mut tampered = transaction.clone();
    tampered.amount = 2;
    assert_eq!(
        node.submit(tampered),
        Err(aether_unified::network::SubmitError::HashMismatch)
    );

    let mut forged = transaction.clone();
    forged.id = forged.compute_hash();
    forged.signature = vec![0u8; 64];
    forged.id = forged.compute_hash();
    assert_eq!(
        node.submit(forged),
        Err(aether_unified::network::SubmitError::BadSignature)
    );

    node.submit(transaction.clone()).expect("first submission");
    assert_eq!(
        node.submit(transaction.clone()),
        Err(aether_unified::network::SubmitError::Duplicate(
            transaction.id
        ))
    );

    // A parent this node does not hold: refused, not parked.
    let orphan = signed_transaction(&wallet, [[0x77u8; 32], [0u8; 32]], 2);
    assert_eq!(
        node.submit(orphan),
        Err(aether_unified::network::SubmitError::UnknownParent(
            [0x77u8; 32]
        ))
    );
    assert_eq!(node.transactions(), 1, "a refusal changes nothing");

    // A known parent is enough: the child is admitted.
    let child = signed_transaction(&wallet, [transaction.id, [0u8; 32]], 3);
    node.submit(child).expect("child admitted");
    assert_eq!(node.transactions(), 2);
}

#[test]
fn bz3_12_submission_without_peers_is_accepted_and_says_so() {
    let mut node = node(1);
    let wallet = Wallet::new();
    let transaction = signed_transaction(&wallet, [[0u8; 32]; 2], 1);
    let submission = node.submit(transaction).expect("accepted locally");
    assert_eq!(
        submission.peers_notified, 0,
        "nobody was told, and that is said"
    );
    assert_eq!(node.transactions(), 1);
}

#[test]
fn bz3_13_a_halted_node_accepts_no_new_transaction() {
    let mut nodes = mesh(&[1, 2]);
    // The alert is sent by a peer: a node does not warn itself.
    nodes[0].broadcast(MessageKind::HaltEvidence, vec![0x11u8; 32]);
    drain(&mut nodes[1]);
    assert_eq!(nodes[1].halt_evidence(), Some([0x11u8; 32]));

    let wallet = Wallet::new();
    let transaction = signed_transaction(&wallet, [[0u8; 32]; 2], 1);
    assert_eq!(
        nodes[1].submit(transaction),
        Err(aether_unified::network::SubmitError::Halted)
    );
    // The sender is not halted: an alert stops nobody by itself.
    let mut sender_transaction = signed_transaction(&wallet, [[0u8; 32]; 2], 2);
    sender_transaction.id = sender_transaction.compute_hash();
    assert!(nodes[0].submit(sender_transaction).is_ok());
}

// ---------------------------------------------------------------------------
// §6 — synchronisation
// ---------------------------------------------------------------------------

#[test]
fn bz3_14_a_fresh_validator_verifies_and_installs_a_real_bundle() {
    let chain = fixture::build_chain(2);
    let bundle = chain.bundle();
    assert_eq!(bundle.links.len(), 3);

    let mut fresh = node(1);
    fresh.attach_store(Box::new(MemoryAtomicSlotStore::new()));
    assert_eq!(fresh.status().decided, None);
    let installed = fresh.install_bundle(&bundle).expect("installed");
    assert_eq!(installed, 3);
    assert_eq!(fresh.history().len(), 0, "installing is not deciding");

    // Installing the same history again is idempotent: nothing is erased and the
    // commitments still agree.
    assert_eq!(fresh.install_bundle(&bundle).expect("idempotent"), 3);
}

#[test]
fn bz3_15_a_truncated_or_foreign_history_installs_nothing() {
    let chain = fixture::build_chain(2);
    let bundle = chain.bundle();

    // A hole in the middle: heights no longer follow.
    let mut holed = bundle.clone();
    holed.links.remove(1);
    let mut fresh = node(1);
    fresh.attach_store(Box::new(MemoryAtomicSlotStore::new()));
    assert!(fresh.install_bundle(&holed).is_err(), "a hole is refused");

    // A tampered certificate does not re-verify. This is the check the dispatcher
    // performs on the bytes that arrive, so it is where the refusal belongs: the
    // decoder never hands a bad certificate to the installer.
    let last = bundle.links.len() - 1;
    let mut bytes = bundle.links[last].certificate.encode();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    assert!(
        aether_unified::l2bft::PrecommitCertificate::from_bytes(
            &bytes,
            &bundle.generations[0].registry,
            bundle.anchor.network,
        )
        .is_err(),
        "an altered certificate does not re-verify"
    );

    // A bundle that contradicts itself: the checkpoint no longer matches the
    // certificate that decided it. Nothing is repaired and nothing is written.
    fresh.install_bundle(&bundle).expect("the first history");
    let mut contradictory = bundle.clone();
    contradictory.links[0].checkpoint.state_root = [0x99u8; 32];
    assert!(
        fresh.install_bundle(&contradictory).is_err(),
        "a bundle whose checkpoint contradicts its certificate is refused"
    );
}

// ---------------------------------------------------------------------------
// §7 — round changes
// ---------------------------------------------------------------------------

#[test]
fn bz3_16_a_round_change_adopts_at_quorum_and_keeps_the_lock() {
    let mut nodes = mesh(&SEEDS);
    let stores: Vec<MemoryAtomicSlotStore> =
        SEEDS.iter().map(|_| MemoryAtomicSlotStore::new()).collect();
    let cp = checkpoint();
    cycle(&mut nodes, &stores, &cp);

    let locks: Vec<_> = nodes
        .iter()
        .map(|node| node.engine().active_lock())
        .collect();
    assert!(
        locks.iter().all(|lock| lock.is_some()),
        "a precommit writes the lock, so every node holds one"
    );

    // Each node builds, signs, records and broadcasts its own round change.
    for (index, node) in nodes.iter_mut().enumerate() {
        let outcome = node
            .propose_round_change_with(Round(1), &stores[index])
            .expect("round change is legal");
        assert!(matches!(
            outcome,
            aether_unified::l2bft::RoundChangeOutcome::Recorded { .. }
                | aether_unified::l2bft::RoundChangeOutcome::Adopted { .. }
        ));
    }
    for node in nodes.iter_mut() {
        drain(node);
    }

    for (index, node) in nodes.iter_mut().enumerate() {
        let status = node.status();
        assert_eq!(status.round, Round(1), "node {index} adopted round 1");
        assert_eq!(
            status.lock, locks[index],
            "node {index} kept its lock: a round change unlocks nothing"
        );
        assert!(status.may_sign);
        assert_eq!(node.engine().round_state.prevotes.len(), 0);
    }

    // The new round is usable: the elected proposer proposes, everyone votes.
    let proposer = nodes.iter().position(|node| node.is_proposer());
    assert!(
        proposer.is_some(),
        "the schedule elects somebody in round 1"
    );
    let proposer = proposer.expect("proposer");
    nodes[proposer]
        .propose_value(cp.id())
        .expect("the elected proposer proposes");
    for node in nodes.iter_mut() {
        drain(node);
    }
    let store = MemoryAtomicSlotStore::new();
    let prevote = nodes[proposer]
        .prevote_with(cp.id(), &store)
        .expect("a locked node prevotes its own locked value");
    assert_eq!(prevote.checkpoint_id(), cp.id());
}

#[test]
fn bz3_17_a_round_change_cannot_jump_or_repeat() {
    let mut nodes = mesh(&SEEDS);
    let stores: Vec<MemoryAtomicSlotStore> =
        SEEDS.iter().map(|_| MemoryAtomicSlotStore::new()).collect();
    cycle(&mut nodes, &stores, &checkpoint());

    // Beyond `MAX_ROUND_JUMP`, which the engine refuses to adopt.
    let far = Round(aether_unified::l2bft::MAX_ROUND_JUMP + 2);
    let outcome = nodes[0]
        .propose_round_change_with(far, &stores[0])
        .expect("signed and recorded");
    assert!(
        matches!(
            outcome,
            aether_unified::l2bft::RoundChangeOutcome::Refused(_)
        ),
        "a jump larger than the bound is refused"
    );
    assert_eq!(nodes[0].status().round, Round(0));

    // A target that does not advance the round is refused outright: the codec's
    // own verification rejects it, so no signature is produced and no second
    // change can be recorded for the same round.
    match nodes[0].propose_round_change_with(Round(0), &stores[0]) {
        Err(NodeError::Engine(_)) => {}
        other => panic!("a round change must advance the round, got {other:?}"),
    }
    assert_eq!(nodes[0].status().round, Round(0));
}

// ---------------------------------------------------------------------------
// §9 — a decision survives being read back through the interface
// ---------------------------------------------------------------------------

#[test]
fn bz3_18_a_decided_height_is_visible_through_the_node_and_serves_a_bundle() {
    let mut nodes = mesh(&SEEDS);
    let stores: Vec<MemoryAtomicSlotStore> =
        SEEDS.iter().map(|_| MemoryAtomicSlotStore::new()).collect();
    let cp = checkpoint();
    let qc = cycle(&mut nodes, &stores, &cp);

    for node in &nodes {
        let status = node.status();
        assert_eq!(status.decided, Some(CheckpointHeight(0)));
        assert_eq!(node.decisions().len(), 1);
        assert_eq!(node.decisions()[0].checkpoint_id, cp.id());
        assert_eq!(node.history().len(), 1);
    }

    // The node can serve what it decided, and the bundle it builds is the one a
    // peer verifies: the certificate travels with the checkpoint.
    let bundle = nodes[0].build_history().expect("history to serve");
    assert_eq!(bundle.links.len(), 1);
    assert_eq!(
        bundle.links[0].certificate.checkpoint_id(),
        qc.checkpoint_id()
    );
    assert_eq!(bundle.anchor.checkpoint_id, cp.id());

    let mut blank = node(1);
    blank.attach_store(Box::new(MemoryAtomicSlotStore::new()));
    assert_eq!(blank.install_bundle(&bundle).expect("installed"), 1);
}

#[test]
fn bz3_19_a_vote_for_an_unknown_peer_is_not_invented() {
    // A node with no peer can still sign; nothing fabricates a peer to talk to.
    let mut node = node(1);
    node.attach_store(Box::new(MemoryAtomicSlotStore::new()));
    let prevote = node.prevote_value(checkpoint().id()).expect("prevote");
    assert_eq!(
        node.broadcast(MessageKind::Prevote, prevote.vote().encode()),
        0
    );
    assert!(node.peers().is_empty());
    assert_eq!(node.status().prevotes, 1);
}

#[test]
fn bz3_20_a_foreign_generation_vote_is_refused_and_counted() {
    // A vote genuinely signed in another generation never counts here, and the
    // refusal is attributable.
    let mut nodes = mesh(&[1, 3]);
    let foreign_registry = {
        let mut entries = Vec::new();
        for seed in SEEDS {
            entries.push(RegistryEntry {
                id: vid(seed),
                public_key: sk(seed).verifying_key().to_bytes(),
                weight: ValidatorWeight(WEIGHT),
                admissibility: Admissibility::Eligible,
            });
        }
        // Same members, another generation label: the position differs.
        ValidatorRegistry::new(GenerationId([9u8; 32]), &entries).expect("registry")
    };
    let mut foreign_state = BftState::new(NET, &foreign_registry, CheckpointHeight(0), ANCHOR);
    let store = MemoryAtomicSlotStore::new();
    let vote: ConsensusVote = foreign_state
        .prevote(checkpoint().id(), vid(1), &foreign_registry, &store, {
            let key = sk(1);
            move |message: &[u8]| key.sign(message).to_bytes()
        })
        .expect("signed in its own generation")
        .vote()
        .clone();

    let envelope = aether_unified::network::Envelope::new(
        NET,
        MessageKind::Prevote,
        vid(1).0,
        [9u8; 32],
        0,
        0,
        vote.encode(),
    )
    .sign(&sk(1));
    nodes[0]
        .send_raw(vid(3), &envelope)
        .expect("write to the peer");
    let seen = drain(&mut nodes[1]);
    let votes = accepted_votes(&seen);
    assert_eq!(votes.len(), 1);
    assert!(matches!(
        votes[0].outcome(),
        aether_unified::l2bft::VoteOutcome::ForeignContext {
            field: "generation",
            ..
        }
    ));
    assert_eq!(nodes[1].engine().round_state.prevotes.len(), 0);
}
