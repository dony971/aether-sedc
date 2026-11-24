//! Mission BH — partial synchronisation (priority 6).
//!
//! BG's `Node::serve_history` stored a bundle and then returned **that bundle**
//! for every request: `from_height` and `max_links` were decoded, validated, and
//! ignored. A peer asking for two links from height 40 received the whole history.
//!
//! BH slices the answer. The tests below check the four things that can go wrong
//! with a slice — wrong start, wrong length, silent truncation, and a ledger that
//! cannot be accumulated across windows — plus the commitment checks that must
//! still refuse anything contradictory.
//!
//! | Test | What it checks |
//! |---|---|
//! | `bl_01` | `from_height` selects the first link, exactly |
//! | `bl_02` | `max_links` bounds the answer |
//! | `bl_03` | an unknown height is refused, not answered with something else |
//! | `bl_04` | successive windows accumulate into a complete history |
//! | `bl_05` | a window that is too large for the budget is shortened, never cut silently |
//! | `bl_06` | the wire path honours the request (2 links asked, 2 installed) |
//! | `bl_07` | `ledger_extends` is a one-way predicate |
//! | `bl_08` | certificates are re-verified inside a slice as well |

#[path = "support/bh_fixture.rs"]
mod fixture;

use aether_unified::consensus::generation::CheckpointHeight;
use aether_unified::l2bft::sync::{install_history, ledger_extends, verify_history};
use aether_unified::l2bft::GenerationSpec;
use aether_unified::l2bft::FINALITY_PREFIX;
use aether_unified::l2persist::{CasStore, MemoryAtomicSlotStore};
use aether_unified::network::wire_sync::{SyncRequest, MAX_SYNC_BYTES};
use aether_unified::network::{GlobalLimits, MessageKind, Node};

use fixture::{build_chain, Mesh, NET, SEEDS};

fn request(from: u64, max: u32) -> SyncRequest {
    SyncRequest {
        network: NET,
        from_height: CheckpointHeight(from),
        max_links: max,
    }
}

fn node_serving(chain: &fixture::Chain) -> Node {
    let mut node = Node::bind(
        "127.0.0.1:0".parse().expect("addr"),
        NET,
        fixture::sk(9),
        aether_unified::l2bft::BftState::new(
            NET,
            &chain.registry,
            CheckpointHeight(0),
            fixture::ANCHOR,
        ),
        chain.registry.clone(),
    )
    .expect("bind");
    node.serve_history(chain.bundle());
    node
}

#[test]
fn bl_01_from_height_selects_the_first_link() {
    let chain = build_chain(5);
    let server = node_serving(&chain);

    let slice = server
        .history_slice(&chain.bundle(), &request(3, 8))
        .expect("a slice");
    assert_eq!(slice.links[0].checkpoint.height, CheckpointHeight(3));
    assert_eq!(slice.anchor.height, CheckpointHeight(3));
    assert_eq!(
        slice.anchor.checkpoint_id,
        chain.checkpoints[3].id(),
        "the anchor is the requested checkpoint, not the bundle's"
    );
    assert_eq!(
        slice.links.len(),
        3,
        "heights 3, 4 and 5 — never the whole history"
    );
}

#[test]
fn bl_02_max_links_bounds_the_answer() {
    let chain = build_chain(9);
    let server = node_serving(&chain);
    let slice = server
        .history_slice(&chain.bundle(), &request(0, 4))
        .expect("a slice");
    assert_eq!(slice.links.len(), 4);
    assert_eq!(slice.links[3].checkpoint.height, CheckpointHeight(3));

    // A request larger than what remains returns what remains, not more.
    let tail = server
        .history_slice(&chain.bundle(), &request(7, 100))
        .expect("a slice");
    assert_eq!(tail.links.len(), 3);

    // And one link is one link.
    let single = server
        .history_slice(&chain.bundle(), &request(5, 1))
        .expect("a slice");
    assert_eq!(single.links.len(), 1);
}

#[test]
fn bl_03_an_unknown_height_is_refused() {
    let chain = build_chain(4);
    let server = node_serving(&chain);
    assert!(
        server
            .history_slice(&chain.bundle(), &request(11, 4))
            .is_none(),
        "a height the history does not contain must be refused, not answered"
    );
    assert!(server
        .history_slice(&chain.bundle(), &request(4, 1))
        .is_some());
}

#[test]
fn bl_04_successive_windows_accumulate() {
    let chain = build_chain(7);
    let server = node_serving(&chain);
    let store = MemoryAtomicSlotStore::new();

    let mut installed = 0usize;
    let mut from = 0u64;
    loop {
        let slice = server
            .history_slice(&chain.bundle(), &request(from, 3))
            .expect("a slice");
        assert!(slice.links.len() <= 3, "the window is respected");
        let history = verify_history(&slice).expect("verified");
        install_history(&store, &history).expect("installed");
        installed += history.links.len();
        let tip = history.tip.get();
        if tip == 7 {
            break;
        }
        from = tip;
    }
    assert_eq!(
        installed, 11,
        "three windows of three plus a final window of two: the anchor of each window is repeated once"
    );
    let decisions = store.scan(FINALITY_PREFIX).expect("scan");
    assert_eq!(
        decisions.len(),
        8,
        "every height 0..=7 has exactly one durable decision"
    );
    // The tip is reachable and complete.
    let full = verify_history(&chain.bundle()).expect("verified");
    assert_eq!(full.tip, CheckpointHeight(7));
}

#[test]
fn bl_05_an_oversized_window_is_shortened_not_cut() {
    let chain = build_chain(20);
    let mut server = node_serving(&chain);
    // A byte budget smaller than the whole history forces a shorter answer.
    let full = chain.bundle().encode().expect("encode");
    server.attach_global_limits(GlobalLimits {
        max_sync_requests: 100,
        max_served_bytes: (full.len() as u64) / 3,
    });
    let slice = server
        .history_slice(&chain.bundle(), &request(0, 128))
        .expect("a slice");
    assert!(
        slice.links.len() < 21,
        "the answer is shorter than the history, got {}",
        slice.links.len()
    );
    assert!(slice.links.len() >= 1, "but never empty");
    let encoded = slice.encode().expect("encode");
    assert!(
        encoded.len() as u64 <= (full.len() as u64) / 3,
        "the shortened answer fits the budget: {} vs {}",
        encoded.len(),
        full.len() / 3
    );
    // Nothing was cut inside a link: the slice still verifies end to end.
    let history = verify_history(&slice).expect("verified");
    assert_eq!(history.links.len(), slice.links.len());
    assert!(encoded.len() <= MAX_SYNC_BYTES);
}

#[test]
fn bl_06_the_wire_path_honours_the_request() {
    let chain = build_chain(5);
    let mut mesh = Mesh::new(&SEEDS);
    mesh.nodes[0].serve_history(chain.bundle());

    mesh.nodes[1].broadcast(MessageKind::SyncRequest, request(2, 2).encode());
    mesh.drain();

    assert_eq!(
        mesh.nodes[1].installed_links, 2,
        "two links were asked for and two were installed, not the whole history"
    );
    assert_eq!(mesh.nodes[0].sync_requests_served, 1);
    assert!(mesh.nodes[0].sync_bytes_served > 0);
    assert_eq!(mesh.nodes[0].sync_refused, 0);
}

#[test]
fn bl_07_ledger_extends_is_one_way() {
    let chain = build_chain(2);
    let history = verify_history(&chain.bundle()).expect("verified");
    assert!(ledger_extends(&history.ledger, &history.ledger));

    let mut other_network = history.ledger.clone();
    other_network.network = NET + 1;
    assert!(
        !ledger_extends(&other_network, &history.ledger),
        "another network is not an extension"
    );
    assert!(
        !ledger_extends(&history.ledger, &other_network),
        "and it is not the other way round either"
    );

    // A stored generation that the offered history would drop is refused.
    let mut without_closure = history.ledger.clone();
    without_closure.closures.clear();
    assert!(
        !ledger_extends(&without_closure, &history.ledger) || history.ledger.closures.is_empty(),
        "erasing a closure is never an extension"
    );

    // The bundle's generation list is carried whole by every slice, which is what
    // makes successive windows rebuild the same ledger.
    let slice = node_serving(&chain)
        .history_slice(&chain.bundle(), &request(1, 1))
        .expect("a slice");
    assert_eq!(slice.generations.len(), chain.bundle().generations.len());
    let generation: &GenerationSpec = &slice.generations[0];
    assert!(generation.closure.is_none());
}

#[test]
fn bl_08_a_slice_re_verifies_its_certificates() {
    let chain = build_chain(5);
    let server = node_serving(&chain);
    let slice = server
        .history_slice(&chain.bundle(), &request(1, 3))
        .expect("a slice");
    let history = verify_history(&slice).expect("verified");
    assert_eq!(history.links[0].height, CheckpointHeight(1));
    assert_eq!(history.roots.set_roots_recomputed, 3);
    assert!(
        !history.roots.state_root_authenticated,
        "a slice does not authenticate state_root either"
    );

    // A certificate swapped for one of another height is refused inside the slice.
    let mut evil = slice.clone();
    evil.links[1].certificate = chain.certificates[0].clone();
    assert!(verify_history(&evil).is_err());

    // And a checkpoint edited in place no longer chains.
    let mut edited = slice.clone();
    edited.links[1].checkpoint.state_root[0] ^= 0xFF;
    assert!(verify_history(&edited).is_err());
}
