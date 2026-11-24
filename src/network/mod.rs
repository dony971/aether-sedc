//! Validator-to-validator network (mission BE).
//!
//! # Layers, kept apart on purpose
//!
//! | Layer | Module | Decides |
//! |---|---|---|
//! | framing and message format | [`protocol`] | nothing |
//! | sockets and timeouts | [`transport`] | nothing |
//! | who is on the other end | [`peer`] | identity only |
//! | may this message reach the engine | [`dispatcher`] | nothing authoritative |
//! | consensus | `l2bft` | **everything** |
//!
//! # The invariant
//!
//! A message from an authenticated peer is **not** thereby valid. Authentication
//! establishes a sender; `l2bft` establishes meaning. Nothing in this module can
//! sign on a validator's behalf, collect a quorum, or finalize: [`dispatcher`]
//! only forwards to engine methods that already enforce `may_sign_at`, generation
//! closure, POL, locks and HALT.
//!
//! # Scope
//!
//! There is **no** public discovery, no gossip, no anonymity layer, and no
//! production key material. Peers are configured locally ([`PeerLimits`], seed
//! addresses on [`node::NodeConfig`]), and the network is only instantiated by
//! tests and local experiments — never by the `aether` binary.

pub mod dispatcher;
pub mod node;
pub mod peer;
pub mod protocol;
pub mod sim;
pub mod transport;
pub mod wire_sync;

pub use dispatcher::{authenticate, dispatch, AcceptedVote, Dispatched, Incoming, Reject};
pub use node::{GlobalLimits, Node, NodeConfig, NodeError, NodeStatus, Submission, SubmitError};
pub use peer::{
    verify_hello, PeerError, PeerIdentity, PeerLimits, PeerState, PeerTable, RateLimiter,
    ReplayWindow,
};
pub use protocol::{
    Envelope, Hello, MessageKind, WireError, BODY_OVERHEAD, DOMAIN_WIRE, HEADER_LEN, MAX_FRAME,
    MAX_PAYLOAD, WIRE_VERSION,
};
pub use sim::{seeds, value_for_height, Body, Sim, SimConfig, SimMetrics, SimOutcome};
pub use transport::{accept_with_timeout, bind, FramedStream, TransportError};
pub use wire_sync::{SyncRequest, SyncWireError, MAX_SYNC_BYTES, SYNC_FORMAT_VERSION};
