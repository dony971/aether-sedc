//! Mission BI — connection limits (priority 8).
//!
//! # What was missing after BH
//!
//! `PeerLimits::max_connections` bounded the whole node, but nothing bounded one
//! remote **address**, and slots were released only by removing the table entry.
//! `AddressBook` closes both gaps, and this file pins the behaviour:
//!
//! | Test | What it establishes |
//! |---|---|
//! | `br_01` | the book enforces both limits, counts refusals and releases slots |
//! | `br_02` | one address cannot hold more than its share of connections |
//! | `br_03` | the global connection budget still applies |
//! | `br_04` | a refused envelope releases the slot, so a long run cannot leak |
//! | `br_05` | several validators behind one address fit under a raised per-address limit |
//! | `br_06` | a refusal does not damage the connections that already work |
//!
//! # What this does **not** close
//!
//! A Sybil attacker with `n` addresses gets `n × per-address` connection slots,
//! and eclipse resistance is unchanged: an adversary that fills the peer table
//! first still decides who a node talks to. See `connection-limits.md`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use aether_unified::consensus::generation::CheckpointHeight;
use aether_unified::consensus::generation::GenerationId;
use aether_unified::l2bft::BftState;
use aether_unified::l2crypto::registry::{
    validator_id, Admissibility, RegistryEntry, ValidatorRegistry,
};
use aether_unified::l2persist::MemoryAtomicSlotStore;
use aether_unified::network::peer::{AddressBook, PeerError, PeerLimits};
use aether_unified::network::protocol::{Envelope, MessageKind};
use aether_unified::network::Node;
use ed25519_dalek::{Signer, SigningKey};

const NET: u64 = 41;
const ANCHOR: [u8; 32] = [0x5A; 32];
const GEN: [u8; 32] = [7u8; 32];

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn registry(n: usize) -> ValidatorRegistry {
    let entries: Vec<RegistryEntry> = (1..=n)
        .map(|seed| RegistryEntry {
            id: validator_id(&sk(seed as u8).verifying_key().to_bytes()),
            public_key: sk(seed as u8).verifying_key().to_bytes(),
            weight: aether_unified::consensus::generation::ValidatorWeight(10),
            admissibility: Admissibility::Eligible,
        })
        .collect();
    ValidatorRegistry::new(GenerationId(GEN), &entries).expect("registry")
}

fn limits(max: usize, per_address: usize) -> PeerLimits {
    PeerLimits {
        max_connections: max,
        max_connections_per_address: per_address,
        read_timeout: Duration::from_millis(50),
        write_timeout: Duration::from_millis(200),
        idle_timeout: Duration::from_secs(2),
        max_messages_per_second: 500,
        ..PeerLimits::default()
    }
}

fn node(seed: u8, registry: &ValidatorRegistry, limits: PeerLimits) -> Node {
    let mut node = Node::bind_with_limits(
        "127.0.0.1:0".parse::<SocketAddr>().expect("addr"),
        NET,
        sk(seed),
        BftState::new(NET, registry, CheckpointHeight(0), ANCHOR),
        registry.clone(),
        limits,
    )
    .expect("bind");
    node.attach_store(Box::new(MemoryAtomicSlotStore::new()));
    node
}

#[test]
fn br_01_the_address_book_enforces_both_limits() {
    let book_limits = limits(4, 2);
    let mut book = AddressBook::new();
    let a: SocketAddr = "10.0.0.1:1000".parse().expect("addr");
    let a2: SocketAddr = "10.0.0.1:1001".parse().expect("addr");
    let a3: SocketAddr = "10.0.0.1:1002".parse().expect("addr");
    let b: SocketAddr = "10.0.0.2:1000".parse().expect("addr");
    let c: SocketAddr = "10.0.0.3:1000".parse().expect("addr");

    book.try_open(a, &book_limits).expect("first");
    book.try_open(a2, &book_limits).expect("second");
    assert_eq!(book.count_for(a.ip()), 2);
    match book.try_open(a3, &book_limits) {
        Err(PeerError::AddressLimitReached { limit, .. }) => assert_eq!(limit, 2),
        other => panic!("the per-address limit must apply, got {other:?}"),
    }
    assert_eq!(book.refused(), 1);

    book.try_open(b, &book_limits).expect("another address");
    book.try_open(c, &book_limits).expect("the fourth slot");
    // The fifth connection hits the global budget, whatever its address.
    let d: SocketAddr = "10.0.0.4:1000".parse().expect("addr");
    match book.try_open(d, &book_limits) {
        Err(PeerError::TooManyConnections(limit)) => assert_eq!(limit, 4),
        other => panic!("the global limit must apply, got {other:?}"),
    }
    assert_eq!(book.total(), 4);
    assert_eq!(book.addresses(), 3);

    // Releasing one address frees exactly one slot, and frees the address with it.
    book.close(a);
    book.close(a2);
    assert_eq!(book.count_for(a.ip()), 0);
    assert_eq!(book.total(), 2, "b and c are still connected");
    assert_eq!(book.addresses(), 2);
    book.try_open(a3, &book_limits)
        .expect("and the slot is reusable");
    assert_eq!(book.total(), 3, "one slot came back, three are held");
}

#[test]
fn br_02_one_address_cannot_take_every_slot() {
    let registry = registry(4);
    let node_limits = limits(8, 1);
    let mut server = node(1, &registry, node_limits);
    let mut first = node(2, &registry, node_limits);
    let mut second = node(3, &registry, node_limits);

    first.dial(server.addr()).expect("dial");
    server
        .accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("handshake");
    first.finish_dials();
    assert_eq!(server.address_book().total(), 1);

    second.dial(server.addr()).expect("dial");
    match server.accept_one(Duration::from_millis(500)) {
        Err(aether_unified::network::NodeError::Peer(PeerError::AddressLimitReached {
            limit,
            ..
        })) => assert_eq!(limit, 1),
        other => panic!("a second connection from one address must be refused, got {other:?}"),
    }
    assert_eq!(
        server.address_book().total(),
        1,
        "the refusal released nothing"
    );
    assert_eq!(server.address_book().refused(), 1);
    assert_eq!(server.peers().len(), 1, "and the working peer is untouched");
}

#[test]
fn br_03_the_global_budget_still_applies() {
    let registry = registry(4);
    let node_limits = limits(1, 16);
    let mut server = node(1, &registry, node_limits);
    let mut first = node(2, &registry, node_limits);
    let mut second = node(3, &registry, node_limits);

    first.dial(server.addr()).expect("dial");
    server
        .accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("handshake");
    first.finish_dials();

    second.dial(server.addr()).expect("dial");
    match server.accept_one(Duration::from_millis(500)) {
        Err(aether_unified::network::NodeError::Peer(PeerError::TooManyConnections(limit))) => {
            assert_eq!(limit, 1)
        }
        other => panic!("the global limit must apply, got {other:?}"),
    }
    assert_eq!(server.peers().len(), 1);
}

#[test]
fn br_04_a_refused_envelope_releases_the_slot() {
    let registry = registry(4);
    let node_limits = limits(4, 4);
    let mut receiver = node(1, &registry, node_limits);
    let mut sender = node(2, &registry, node_limits);

    sender.dial(receiver.addr()).expect("dial");
    receiver
        .accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("handshake");
    sender.finish_dials();
    assert_eq!(receiver.address_book().total(), 1);

    // A message for another network is fatal for the connection, by design.
    let forged = Envelope::new(
        NET + 1,
        MessageKind::Prevote,
        sender.id().0,
        GEN,
        0,
        0,
        vec![0u8; 4],
    )
    .sign(&sk(2));
    let peer = sender.peers()[0];
    sender.send_raw(peer, &forged).expect("send");

    let _ = receiver.poll(Duration::from_millis(300));
    assert_eq!(
        receiver.address_book().total(),
        0,
        "the slot came back when the connection was closed"
    );
    assert_eq!(receiver.address_book().refused(), 0, "no limit was hit");
}

#[test]
fn br_05_a_raised_per_address_limit_fits_a_local_cluster() {
    let registry = registry(5);
    let node_limits = limits(8, 4);
    let mut server = node(1, &registry, node_limits);
    let mut clients: Vec<Node> = (2..=5)
        .map(|seed| node(seed, &registry, node_limits))
        .collect();

    for client in clients.iter_mut() {
        client.dial(server.addr()).expect("dial");
        server
            .accept_one(Duration::from_millis(500))
            .expect("accept")
            .expect("handshake");
    }
    for client in clients.iter_mut() {
        client.finish_dials();
    }
    assert_eq!(server.address_book().total(), 4);
    assert_eq!(
        server
            .address_book()
            .count_for(IpAddr::from([127, 0, 0, 1])),
        4
    );

    // One more than the per-address budget is refused.
    let mut extra = node(6, &registry, node_limits);
    extra.dial(server.addr()).expect("dial");
    assert!(matches!(
        server.accept_one(Duration::from_millis(500)),
        Err(aether_unified::network::NodeError::Peer(
            PeerError::AddressLimitReached { .. }
        ))
    ));
    assert_eq!(server.peers().len(), 4, "the four honest peers stay");
}

#[test]
fn br_06_a_refusal_does_not_break_working_peers() {
    let registry = registry(4);
    let node_limits = limits(4, 1);
    let mut server = node(1, &registry, node_limits);
    let mut honest = node(2, &registry, node_limits);
    let mut flooder = node(3, &registry, node_limits);

    honest.dial(server.addr()).expect("dial");
    server
        .accept_one(Duration::from_millis(500))
        .expect("accept")
        .expect("handshake");
    honest.finish_dials();

    // The flooder is refused at the address limit...
    flooder.dial(server.addr()).expect("dial");
    assert!(server.accept_one(Duration::from_millis(500)).is_err());
    // ...and the honest peer still gets its messages through.
    let sent = honest.broadcast(MessageKind::HaltEvidence, vec![0x11u8; 32]);
    assert_eq!(sent, 1, "the honest link still works");
    let received = server.poll(Duration::from_millis(300)).expect("poll");
    assert!(received.is_some(), "and the message arrives");
    assert_eq!(server.peers().len(), 1);
}
