//! Mission BH — global resource limits (priority 7).
//!
//! Per-peer limits already exist (`PeerLimits`: message rate, queue, frame size,
//! idle timeout) and were audited in BF. What BH adds is a **node-wide** budget for
//! history service, because "32 peers each ask once" and "one peer asks 32 times"
//! are different resource problems and only the second was bounded.
//!
//! | Test | What it shows |
//! |---|---|
//! | `bm_01` | the request budget is enforced and counted |
//! | `bm_02` | the byte budget is enforced and counted |
//! | `bm_03` | a burst of invalid messages is refused per peer, and the node keeps working |
//! | `bm_04` | eight peers are served within budget, then refused together |
//! | `bm_05` | concurrent duplicate requests cannot exceed the budget |
//!
//! What this is **not**: protection against a Sybil attack. Authenticating a peer
//! says who it is, not that it is one actor; see `eclipse-risk.md`.

#[path = "support/bh_fixture.rs"]
mod fixture;

use aether_unified::consensus::generation::CheckpointHeight;
use aether_unified::network::wire_sync::SyncRequest;
use aether_unified::network::{GlobalLimits, MessageKind};

use fixture::{build_chain, Mesh, NET};

fn request(from: u64, max: u32) -> SyncRequest {
    SyncRequest {
        network: NET,
        from_height: CheckpointHeight(from),
        max_links: max,
    }
}

fn mesh_with_history() -> (Mesh, fixture::Chain) {
    let chain = build_chain(6);
    let mut mesh = Mesh::new(&fixture::SEEDS);
    mesh.nodes[0].serve_history(chain.bundle());
    (mesh, chain)
}

#[test]
fn bm_01_the_request_budget_is_enforced() {
    let (mut mesh, _chain) = mesh_with_history();
    mesh.nodes[0].attach_global_limits(GlobalLimits {
        max_sync_requests: 2,
        max_served_bytes: 1024 * 1024,
    });

    // Three *distinct* requests: identical frames would be dropped by the replay
    // window before ever reaching the budget.
    for from in 0..3u64 {
        mesh.nodes[1].broadcast(MessageKind::SyncRequest, request(from, 1).encode());
        mesh.drain();
    }

    assert_eq!(
        mesh.nodes[0].sync_requests_served, 2,
        "exactly two requests were answered"
    );
    assert_eq!(mesh.nodes[0].sync_refused, 1, "the third was refused");
    assert_eq!(
        mesh.nodes[0].refusals.get("sync-budget").copied(),
        Some(1),
        "and the refusal is attributed to the budget"
    );
}

#[test]
fn bm_02_the_byte_budget_is_enforced() {
    let (mut mesh, _chain) = mesh_with_history();
    let bite = 64;
    mesh.nodes[0].attach_global_limits(GlobalLimits {
        max_sync_requests: 100,
        max_served_bytes: bite,
    });

    for _ in 0..4 {
        mesh.nodes[1].broadcast(MessageKind::SyncRequest, request(0, 8).encode());
        mesh.drain();
    }

    assert!(
        mesh.nodes[0].sync_bytes_served <= bite,
        "no answer may push the node past its byte budget: {} > {bite}",
        mesh.nodes[0].sync_bytes_served
    );
    assert!(
        mesh.nodes[0].sync_refused > 0,
        "the requests that could not fit were refused, not silently dropped"
    );
    assert!(
        mesh.nodes[0].refusal_count() > 0,
        "refusals are recorded on the node"
    );
}

#[test]
fn bm_03_a_burst_of_invalid_messages_is_absorbed() {
    let mut mesh = Mesh::new(&fixture::SEEDS);
    // 60 round changes with a broken signature, from one peer.
    let mut broken = vec![0xC7u8; 186];
    for _ in 0..60 {
        mesh.nodes[1].broadcast(MessageKind::RoundChange, std::mem::take(&mut broken));
        broken = vec![0xC7u8; 186];
    }
    mesh.drain();

    for index in 2..mesh.nodes.len() {
        assert_eq!(
            mesh.nodes[index].round_changes, 0,
            "node {index} accepted nothing"
        );
        assert!(
            mesh.nodes[index].refusal_count() > 0,
            "node {index} recorded the refusals"
        );
    }

    // The node is not wedged: a valid message still gets through afterwards.
    let (mut mesh2, _chain) = mesh_with_history();
    mesh2.nodes[1].broadcast(MessageKind::SyncRequest, request(0, 1).encode());
    mesh2.drain();
    assert_eq!(mesh2.nodes[1].installed_links, 1);
}

#[test]
fn bm_04_eight_peers_share_one_budget() {
    let (mut mesh, _chain) = mesh_with_history();
    mesh.nodes[0].attach_global_limits(GlobalLimits {
        max_sync_requests: 2,
        max_served_bytes: 1024 * 1024,
    });

    for index in 1..mesh.nodes.len() {
        mesh.nodes[index].broadcast(MessageKind::SyncRequest, request(0, 1).encode());
    }
    mesh.drain();

    assert_eq!(
        mesh.nodes[0].sync_requests_served, 2,
        "two peers were answered, the budget then ran out"
    );
    assert!(
        mesh.nodes[0].sync_refused >= 1,
        "and the rest were refused: served {} refused {}",
        mesh.nodes[0].sync_requests_served,
        mesh.nodes[0].sync_refused
    );
    let installed: usize = (1..mesh.nodes.len())
        .map(|index| mesh.nodes[index].installed_links)
        .sum();
    assert_eq!(installed, 2, "the same two peers installed a link each");
}

#[test]
fn bm_05_duplicate_requests_cannot_exceed_the_budget() {
    let (mut mesh, chain) = mesh_with_history();
    mesh.nodes[0].attach_global_limits(GlobalLimits {
        max_sync_requests: 1,
        max_served_bytes: 1024 * 1024,
    });

    // Two peers ask for the same window, at the same time.
    mesh.nodes[1].broadcast(MessageKind::SyncRequest, request(2, 2).encode());
    mesh.nodes[2].broadcast(MessageKind::SyncRequest, request(2, 2).encode());
    mesh.drain();

    assert_eq!(
        mesh.nodes[0].sync_requests_served, 1,
        "only one answer was paid for"
    );
    assert_eq!(mesh.nodes[0].sync_refused, 1);
    let encoded = chain.bundle().encode().expect("bundle encodes").len() as u64;
    assert!(
        mesh.nodes[0].sync_bytes_served < encoded,
        "and what was spent is one slice, not the whole history"
    );
}
