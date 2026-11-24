//! A validator node's network face (mission BE).
//!
//! `Node` owns a listener, an outbound connection per peer, the verified peer
//! table, and the engine it feeds. It is a **transport driver**: it moves messages
//! and applies the dispatcher's verdicts; it never decides anything itself.
//!
//! Declared here, not in a binary, so it is only reachable when a test or a local
//! experiment constructs it. Nothing enables the network for the production
//! binary: `aether` never builds a [`Node`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::{CheckpointHeight, GenerationId, Round, ValidatorId};
use crate::l2bft::cert::{PrecommitCertificate, PrevoteCertificate};
use crate::l2bft::context::{BftError, Precommit, Prevote};
use crate::l2bft::engine::{BftState, FinalityDecision};
use crate::l2bft::halt_proof::HaltProof;
use crate::l2bft::round::RoundChangeOutcome;
use crate::l2bft::sync::{
    bundle_from, check_commitments, install_history, verify_history, GenerationSpec, SyncAnchor,
    SyncBundle, SyncError, SyncLink,
};
use crate::l2crypto::registry::{validator_id, ValidatorRegistry};
use crate::l2crypto::vote::VotePhase;
use crate::l2persist::state::{LockedValue, RecoveryStatus};
use crate::l2persist::AtomicSlotStore;
use crate::transaction::{Transaction, TransactionId};

use crate::network::dispatcher::{authenticate, dispatch, Dispatched, Incoming, Reject};
use crate::network::peer::{verify_hello, AddressBook, PeerError, PeerLimits, PeerTable};
use crate::network::protocol::{Envelope, Hello, MessageKind, WireError, WIRE_VERSION};
use crate::network::transport::{accept_with_timeout, bind, FramedStream, TransportError};
use crate::network::wire_sync::SyncRequest;

/// Why a connection attempt failed.
#[derive(Debug)]
pub enum NodeError {
    /// Socket failure.
    Io(std::io::Error),
    /// The peer was refused at the handshake.
    Peer(PeerError),
    /// The peer answered with something that is not a handshake.
    Protocol(WireError),
    /// The peer is already connected.
    AlreadyConnected(ValidatorId),
    /// The peer did not answer in time.
    Timeout,
    /// This operation needs a durable store and the node has none attached.
    NoStore,
    /// The engine refused the operation. The reason is the engine's own.
    Engine(BftError),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "socket: {error}"),
            Self::Peer(error) => write!(f, "peer: {error}"),
            Self::Protocol(error) => write!(f, "protocol: {error}"),
            Self::AlreadyConnected(id) => {
                write!(f, "already connected: {}", hex::encode(&id.0[..4]))
            }
            Self::Timeout => write!(f, "handshake timed out"),
            Self::NoStore => write!(f, "no durable store attached"),
            Self::Engine(error) => write!(f, "engine: {error}"),
        }
    }
}

impl From<BftError> for NodeError {
    fn from(error: BftError) -> Self {
        Self::Engine(error)
    }
}

impl std::error::Error for NodeError {}

impl From<std::io::Error> for NodeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PeerError> for NodeError {
    fn from(error: PeerError) -> Self {
        Self::Peer(error)
    }
}

impl From<TransportError> for NodeError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Io(error) => Self::Io(error),
            TransportError::Wire(error) => Self::Protocol(error),
            TransportError::Closed => Self::Timeout,
        }
    }
}

/// What a node needs beyond its engine.
#[derive(Debug)]
pub struct NodeConfig {
    /// Network discriminator.
    pub network: u64,
    /// This node's signing key.
    pub key: SigningKey,
    /// Limits.
    pub limits: PeerLimits,
    /// Addresses this node dials on start.
    pub seeds: Vec<SocketAddr>,
}

/// Node-wide budgets for serving history (mission BH, priority 7).
///
/// `PeerLimits` bounds one peer (rate, queue, frame). These bound the **node**:
/// 32 peers each asking for a full history is a different resource problem from
/// one peer asking too often. Both are counters, not timers; when either is spent
/// the node refuses and records `refusals["sync-budget"]`.
///
/// This is **not** Sybil protection: many identities still means many peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalLimits {
    /// Accepted history requests, over the node's lifetime.
    pub max_sync_requests: u64,
    /// Encoded bytes handed out, over the node's lifetime.
    pub max_served_bytes: u64,
}

impl Default for GlobalLimits {
    fn default() -> Self {
        Self {
            max_sync_requests: 4096,
            max_served_bytes: 64 * 1024 * 1024,
        }
    }
}

/// What a successful submission produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// Identifier of the accepted transaction.
    pub id: TransactionId,
    /// Peers the transaction was handed to. Zero is a valid answer: a node with
    /// no peer still accepts and holds the transaction, and says so rather than
    /// pretending it was propagated.
    pub peers_notified: usize,
}

/// Why a DAG transaction was not admitted.
///
/// These are admission refusals, not consensus verdicts. A transaction that is
/// admitted is **held**, not finalised: the protocol defines no relation between
/// a BFT checkpoint and a DAG transaction, and nothing here invents one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The identifier does not reproduce from the transaction's own fields.
    HashMismatch,
    /// The signature does not verify against the transaction's public key.
    BadSignature,
    /// A transaction with this identifier is already held.
    Duplicate(TransactionId),
    /// A parent is not held by this node (and is not the all-zero root).
    UnknownParent(TransactionId),
    /// The node is halted: it accepts no new work while it is stopped.
    Halted,
    /// The transaction could not be encoded for the wire.
    NotEncodable,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashMismatch => write!(f, "identifier does not reproduce from its fields"),
            Self::BadSignature => write!(f, "signature does not verify"),
            Self::Duplicate(id) => write!(f, "duplicate transaction {}", hex::encode(&id[..4])),
            Self::UnknownParent(id) => write!(f, "unknown parent {}", hex::encode(&id[..4])),
            Self::Halted => write!(f, "node is halted"),
            Self::NotEncodable => write!(f, "transaction could not be encoded"),
        }
    }
}

impl std::error::Error for SubmitError {}

/// A read-only snapshot of a node's BFT position.
///
/// Mission BZ.3 §2: the point of this type is that it is a **copy**. A caller can
/// read where the engine stands without holding, borrowing or mutating it, so no
/// caller can move a height, a round, a generation or a lock from the outside.
/// Everything here is derived from the engine on each call; nothing is cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    /// This node's identity.
    pub id: ValidatorId,
    /// Network discriminant.
    pub network: u64,
    /// Generation in force, as the engine holds it.
    pub generation: GenerationId,
    /// Height being decided.
    pub height: CheckpointHeight,
    /// Round being voted in.
    pub round: Round,
    /// Value adopted for this round, if any.
    pub proposal: Option<[u8; 32]>,
    /// Lock in force at this height, if any.
    pub lock: Option<LockedValue>,
    /// Votes recorded in this round.
    pub prevotes: usize,
    /// Precommits recorded in this round.
    pub precommits: usize,
    /// Round changes recorded for every target round.
    pub round_changes: usize,
    /// Whether the engine's own gate would allow a signature right now.
    pub may_sign: bool,
    /// Why the engine blocks signing, when it does.
    pub recovery: Option<String>,
    /// Whether the node is halted.
    pub halted: bool,
    /// Height decided at this position, if the round reached a decision.
    pub decided: Option<CheckpointHeight>,
    /// Connected peers.
    pub peers: usize,
    /// DAG transactions this node holds (admitted, not finalised).
    pub transactions: usize,
}

/// One validator, on the wire.
pub struct Node {
    listener: TcpListener,
    addr: SocketAddr,
    network: u64,
    key: SigningKey,
    id: ValidatorId,
    limits: PeerLimits,
    table: PeerTable,
    streams: BTreeMap<ValidatorId, FramedStream>,
    /// Connections opened but whose peer has not answered yet.
    pending: Vec<FramedStream>,
    /// Engine this node feeds. All decisions are its own.
    ///
    /// Private since BZ.3: no caller receives a mutable handle to it. Reads go
    /// through [`Node::engine`] / [`Node::status`], and every mutation goes through
    /// one of the node's own methods, which delegate to engine operations that
    /// already enforce generation closure, lock, POL and HALT.
    state: BftState,
    /// Registry of the generation in force, used by the engine for weight.
    registry: ValidatorRegistry,
    /// Halt **alert** received from the network, if any. Stops nothing.
    halt_evidence: Option<[u8; 32]>,
    /// Halt **proof** that was verified and injected into the engine.
    halt_proof: Option<Box<HaltProof>>,
    /// Whether the halt record was written, flushed and read back unchanged.
    ///
    /// BZ.5 (A2): set only from the result of the write and the read-back. The
    /// presence of a store or of a proof is never enough to claim durability.
    halt_durable: bool,
    /// Why durability was not confirmed, for the operator. `None` only when the
    /// halt is either absent or confirmed durable.
    halt_record_error: Option<String>,
    /// Content identifiers of votes this node has already relayed, so a relay
    /// ring terminates instead of echoing a vote forever.
    relayed: BTreeSet<[u8; 32]>,
    /// Which connection currently represents each peer: `true` when this node
    /// accepted it, `false` when this node opened it.
    directions: BTreeMap<ValidatorId, bool>,
    /// Second connections between one pair, closed because one peer is one peer.
    pub duplicates_closed: u64,
    /// Messages this node relayed to peers on behalf of somebody else.
    pub relayed_out: u64,
    /// Decisions this node took through its own engine, in order.
    decided: Vec<FinalityDecision>,
    /// Links this node decided itself, in height order, ready to be served.
    history: Vec<SyncLink>,
    /// Generations this node knows, the first one closed by nothing.
    generations: Vec<GenerationSpec>,
    /// DAG transactions this node admitted, by identifier.
    ///
    /// Held, not decided: admission checks the transaction's own integrity and
    /// that its parents are known here. No BFT operation reads this map, and
    /// nothing in this module claims that a checkpoint finalises a transaction.
    dag: BTreeMap<TransactionId, Transaction>,
    /// Store the halt record is written to. Without it, a verified proof stops the
    /// engine in memory but is not durable, which is reported honestly.
    halt_store: Option<Box<dyn AtomicSlotStore>>,
    /// History this node is willing to serve to a peer that asks.
    pub served: Option<SyncBundle>,
    /// Links installed from a peer's bundle.
    pub installed_links: usize,
    /// Round changes the engine accepted.
    pub round_changes: u64,
    /// Node-wide budgets for history service.
    pub globals: GlobalLimits,
    /// History requests accepted.
    pub sync_requests_served: u64,
    /// Encoded bytes handed out.
    pub sync_bytes_served: u64,
    /// Requests refused by the budget or by an impossible range.
    pub sync_refused: u64,
    /// Messages accepted from all peers.
    pub accepted: u64,
    /// Refusals, by reason.
    pub refusals: BTreeMap<&'static str, u64>,
    /// Connections held per remote address (mission BI, priority 6).
    addresses: AddressBook,
    /// Address each connected peer came from, so its slot can be released.
    addrs: BTreeMap<ValidatorId, SocketAddr>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("addr", &self.addr)
            .field("peers", &self.table.len())
            .field("accepted", &self.accepted)
            .finish()
    }
}

impl Node {
    /// Bind on `addr` (`127.0.0.1:0` for an ephemeral port).
    pub fn bind(
        address: SocketAddr,
        network: u64,
        key: SigningKey,
        state: BftState,
        registry: ValidatorRegistry,
    ) -> std::io::Result<Self> {
        Self::bind_with_limits(
            address,
            network,
            key,
            state,
            registry,
            PeerLimits::default(),
        )
    }

    /// Bind with explicit limits.
    pub fn bind_with_limits(
        address: SocketAddr,
        network: u64,
        key: SigningKey,
        state: BftState,
        registry: ValidatorRegistry,
        limits: PeerLimits,
    ) -> std::io::Result<Self> {
        let listener = bind(address)?;
        let addr = listener.local_addr()?;
        let id = validator_id(&key.verifying_key().to_bytes());
        // The first generation has no closure: it is the one this node started in.
        let generations = vec![GenerationSpec {
            number: 0,
            registry: registry.clone(),
            closure: None,
        }];
        Ok(Self {
            listener,
            addr,
            network,
            key,
            id,
            limits,
            table: PeerTable::new(limits),
            streams: BTreeMap::new(),
            pending: Vec::new(),
            state,
            registry,
            halt_evidence: None,
            halt_proof: None,
            halt_durable: false,
            halt_record_error: None,
            relayed: BTreeSet::new(),
            directions: BTreeMap::new(),
            duplicates_closed: 0,
            relayed_out: 0,
            decided: Vec::new(),
            history: Vec::new(),
            generations,
            dag: BTreeMap::new(),
            halt_store: None,
            served: None,
            installed_links: 0,
            round_changes: 0,
            globals: GlobalLimits::default(),
            sync_requests_served: 0,
            sync_bytes_served: 0,
            sync_refused: 0,
            accepted: 0,
            refusals: BTreeMap::new(),
            addresses: AddressBook::new(),
            addrs: BTreeMap::new(),
        })
    }

    /// This node's identity.
    pub fn id(&self) -> ValidatorId {
        self.id
    }

    /// Public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Connected peers.
    pub fn peers(&self) -> Vec<ValidatorId> {
        self.table.ids()
    }

    /// TCP links currently open, which is not the same number as peers: one peer
    /// is one entry in the table, and a duplicate socket is closed on arrival.
    pub fn links(&self) -> usize {
        self.streams.len()
    }

    /// Limits.
    pub fn limits(&self) -> PeerLimits {
        self.limits
    }

    /// Borrow the peer table, for limits and accounting in tests.
    pub fn table(&self) -> &PeerTable {
        &self.table
    }

    /// Total refusals recorded.
    pub fn refusal_count(&self) -> u64 {
        self.refusals.values().sum()
    }

    fn hello_envelope(&self) -> Envelope {
        let hello = Hello {
            version: WIRE_VERSION,
            network: self.network,
            public_key: self.public_key(),
            height: self.state.height.0,
        };
        Envelope::new(
            self.network,
            MessageKind::Hello,
            self.id.0,
            self.state.generation.0,
            self.state.height.0,
            self.state.round.0,
            hello.encode(),
        )
        .sign(&self.key)
    }

    /// Connection accounting per remote address.
    pub fn address_book(&self) -> &AddressBook {
        &self.addresses
    }

    /// Drop a peer and release every resource it held.
    ///
    /// One path for every removal, so the address book cannot drift: the stream,
    /// the table entry, the address record and the address slot go together.
    fn close_peer(&mut self, id: ValidatorId) {
        if let Some(mut stream) = self.streams.remove(&id) {
            stream.shutdown();
        }
        self.table.remove(&id);
        self.directions.remove(&id);
        if let Some(address) = self.addrs.remove(&id) {
            self.addresses.close(address);
        }
    }

    /// Dial a peer: open the connection and send our handshake, without waiting.
    ///
    /// Two-phase on purpose. A single-phase dial would deadlock against a peer
    /// that is not reading yet, so the caller interleaves [`Self::accept_one`] and
    /// [`Self::finish_dials`] — which is also what a real event loop does.
    pub fn dial(&mut self, address: SocketAddr) -> Result<(), NodeError> {
        self.addresses
            .try_open(address, &self.limits)
            .map_err(NodeError::Peer)?;
        let mut stream = match FramedStream::connect(address, self.limits) {
            Ok(stream) => stream,
            Err(error) => {
                self.addresses.close(address);
                return Err(error.into());
            }
        };
        if let Err(error) = stream.send(&self.hello_envelope()) {
            self.addresses.close(address);
            return Err(error.into());
        }
        self.pending.push(stream);
        Ok(())
    }

    /// Complete the handshake on every dialled connection that has answered.
    ///
    /// A peer that stays silent is dropped; the node keeps running.
    pub fn finish_dials(&mut self) -> usize {
        let mut done = 0;
        let mut remaining = Vec::new();
        for mut stream in std::mem::take(&mut self.pending) {
            let address = match stream.peer_addr() {
                Ok(address) => address,
                Err(_) => continue,
            };
            let answer = match stream.recv() {
                Ok(answer) => answer,
                Err(error) if error.is_timeout() => {
                    remaining.push(stream);
                    continue;
                }
                Err(_) => {
                    // BZ.3 §5: a connection that dies before its handshake releases
                    // its address slot. Before, every such failure leaked one slot
                    // for the life of the process.
                    self.addresses.close(address);
                    continue;
                }
            };
            if !matches!(answer.kind, MessageKind::Hello | MessageKind::HelloAck) {
                self.addresses.close(address);
                continue;
            }
            let hello = match Hello::decode(&answer.payload) {
                Ok(hello) => hello,
                Err(_) => {
                    self.addresses.close(address);
                    continue;
                }
            };
            let identity = match verify_hello(&hello, self.network) {
                Ok(identity) => identity,
                Err(_) => {
                    self.addresses.close(address);
                    continue;
                }
            };
            if answer.sender != identity.id.0 || !answer.verify_signature(&identity.public_key) {
                self.addresses.close(address);
                continue;
            }
            let id = identity.id;
            // BZ.3 §5: when both validators dial each other, two sockets exist for
            // one peer. Both ends keep the connection **opened by the lower
            // identity**, a rule each side can evaluate alone, so the two sides
            // always agree on which socket survives without exchanging anything.
            // BZ.3 §5: three cases, and each side can settle them alone.
            // No link yet: take it. An existing **inbound** link means the peer also
            // dialled us, so the two identities decide which socket lives: the one
            // opened by the lower identity. An existing **outbound** link is our own
            // earlier dial; dialling again means the old socket is being replaced,
            // and the peer resolves the same way on its side, so the new one wins.
            let keep = match self.directions.get(&id) {
                None => true,
                Some(true) => self.id < id,
                Some(false) => true,
            };
            if !keep {
                self.duplicates_closed += 1;
                self.addresses.close(address);
                stream.shutdown();
                continue;
            }
            if let Some(previous) = self.addrs.remove(&id) {
                self.addresses.close(previous);
            }
            if let Some(mut old) = self.streams.insert(id, stream) {
                old.shutdown();
                self.duplicates_closed += 1;
            }
            // The slot was reserved by `dial` for this very connection: reserving
            // again here would count one socket twice and, with a per-address limit
            // of one, refuse the node's own outbound link.
            if self.table.admit(identity, Instant::now()).is_err() {
                self.addresses.close(address);
                self.streams.remove(&id);
                continue;
            }
            self.addrs.insert(id, address);
            self.directions.insert(id, false);
            done += 1;
        }
        self.pending = remaining;
        done
    }

    /// Dial and finish in one step, for a peer that is already accepting.
    pub fn connect(&mut self, address: SocketAddr) -> Result<ValidatorId, NodeError> {
        self.dial(address)?;
        let before: Vec<ValidatorId> = self.streams.keys().copied().collect();
        self.finish_dials();
        let after: Vec<ValidatorId> = self.streams.keys().copied().collect();
        match after.iter().find(|id| !before.contains(id)) {
            Some(id) => Ok(*id),
            None => Err(NodeError::Timeout),
        }
    }

    /// Accept one inbound connection and complete the handshake.
    ///
    /// Returns `Ok(None)` when nothing arrived within `timeout`.
    pub fn accept_one(&mut self, timeout: Duration) -> Result<Option<ValidatorId>, NodeError> {
        let stream = match accept_with_timeout(&self.listener, timeout)? {
            Some(stream) => stream,
            None => return Ok(None),
        };
        let address = stream.peer_addr()?;
        // BI: reserve a slot **before** the handshake, so a flood never allocates
        // a framed stream for a connection that will be refused.
        self.addresses
            .try_open(address, &self.limits)
            .map_err(NodeError::Peer)?;
        let stream = match FramedStream::new(stream, self.limits) {
            Ok(stream) => stream,
            Err(error) => {
                self.addresses.close(address);
                return Err(error.into());
            }
        };
        let (id, mut stream) = match self.finish_handshake(stream) {
            Ok(pair) => pair,
            Err(error) => {
                self.addresses.close(address);
                return Err(error);
            }
        };
        if self.streams.contains_key(&id) {
            // BZ.3 §5: one peer is one peer. Both sides keep the connection opened
            // by the lower identity; the other socket is closed and its address
            // slot released. The peer's replay window and rate budget are left
            // alone — a reconnect must not erase a peer's own history.
            self.duplicates_closed += 1;
            let existing_inbound = *self.directions.get(&id).unwrap_or(&false);
            if !existing_inbound && self.id < id {
                // We are the lower identity, so the rule keeps the link **we**
                // opened and this inbound is the loser. The decision depends only
                // on the two identities, which both ends know, so the two sides
                // always agree on the surviving socket without exchanging
                // anything. (A probe was tried here and rejected: a socket the peer
                // has already closed still accepts one write, so "the write
                // succeeded" says nothing about liveness and would sometimes keep
                // a corpse. If this link is genuinely dead, the next write releases
                // it and the peer's retry finds no existing stream.)
                stream.shutdown();
                self.addresses.close(address);
                return Ok(Some(id));
            }
            // An existing **inbound** link is stale the moment a new inbound
            // arrives: a peer that reconnects abandons the socket it had, and
            // keeping the old one would refuse the reconnect for good. The new
            // connection replaces it, and the peer's replay window and rate budget
            // are left untouched.
            if let Some(mut old) = self.streams.remove(&id) {
                old.shutdown();
            }
            if let Some(previous) = self.addrs.remove(&id) {
                self.addresses.close(previous);
            }
            self.streams.insert(id, stream);
            self.addrs.insert(id, address);
            self.directions.insert(id, true);
            return Ok(Some(id));
        }
        // BZ.3 §5: a link that arrived on the listener is inbound. Recording it as
        // outbound made the duplicate rule read both sides as the dialler, so two
        // crossed dials each kept a different socket and the pair went silent.
        self.streams.insert(id, stream);
        self.addrs.insert(id, address);
        self.directions.insert(id, true);
        Ok(Some(id))
    }

    /// Verify the peer's answer and register it.
    fn finish_handshake(
        &mut self,
        mut stream: FramedStream,
    ) -> Result<(ValidatorId, FramedStream), NodeError> {
        let answer = stream.recv()?;
        if !matches!(answer.kind, MessageKind::Hello | MessageKind::HelloAck) {
            return Err(NodeError::Protocol(WireError::Malformed(
                "expected a handshake",
            )));
        }
        let hello = Hello::decode(&answer.payload).map_err(NodeError::Protocol)?;
        let identity = verify_hello(&hello, self.network)?;
        if answer.sender != identity.id.0 {
            return Err(NodeError::Peer(PeerError::IdentityMismatch));
        }
        if !answer.verify_signature(&identity.public_key) {
            return Err(NodeError::Peer(PeerError::IdentityMismatch));
        }
        // A peer that answered with `Hello` rather than `HelloAck` still gets a
        // reply, so two nodes dialling each other both learn each other's key.
        if answer.kind == MessageKind::Hello {
            stream.send(&self.hello_envelope())?;
        }
        self.table.admit(identity, Instant::now())?;
        Ok((identity.id, stream))
    }

    /// Broadcast a message to every connected peer. Returns how many accepted it.
    ///
    /// A peer whose write fails is dropped; the node keeps running.
    pub fn broadcast(&mut self, kind: MessageKind, payload: Vec<u8>) -> usize {
        let ids: Vec<ValidatorId> = self.streams.keys().copied().collect();
        let mut sent = 0;
        for id in ids {
            if self.send_to(id, kind, payload.clone()).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    /// Send one message to one peer.
    pub fn send_to(
        &mut self,
        peer: ValidatorId,
        kind: MessageKind,
        payload: Vec<u8>,
    ) -> Result<(), NodeError> {
        let envelope = Envelope::new(
            self.network,
            kind,
            self.id.0,
            self.state.generation.0,
            self.state.height.0,
            self.state.round.0,
            payload,
        )
        .sign(&self.key);
        let stream = match self.streams.get_mut(&peer) {
            Some(stream) => stream,
            None => return Err(NodeError::Peer(PeerError::Refused("not connected"))),
        };
        if let Err(error) = stream.send(&envelope) {
            self.close_peer(peer);
            return Err(error.into());
        }
        Ok(())
    }

    /// Send a pre-signed envelope to one peer (used to inject forged bytes).
    pub fn send_raw(&mut self, peer: ValidatorId, envelope: &Envelope) -> Result<(), NodeError> {
        let stream = match self.streams.get_mut(&peer) {
            Some(stream) => stream,
            None => return Err(NodeError::Peer(PeerError::Refused("not connected"))),
        };
        stream.send(envelope)?;
        Ok(())
    }

    /// Read one message from any peer and hand it to the dispatcher.
    ///
    /// `Ok(None)` means the read timed out: the node keeps running. Every other
    /// failure drops that connection and is returned as `Err`, still without
    /// touching the engine.
    pub fn poll(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<(ValidatorId, Incoming)>, NodeError> {
        let ids: Vec<ValidatorId> = self.streams.keys().copied().collect();
        let deadline = Instant::now() + timeout;
        loop {
            for id in &ids {
                let envelope = {
                    let stream = match self.streams.get_mut(id) {
                        Some(stream) => stream,
                        None => continue,
                    };
                    match stream.recv() {
                        Ok(envelope) => envelope,
                        Err(error) if error.is_timeout() => continue,
                        Err(_) => {
                            self.close_peer(*id);
                            continue;
                        }
                    }
                };
                let now = Instant::now();
                let outcome = {
                    let peer = match self.table.get_mut(&envelope.sender_id()) {
                        Some(peer) => peer,
                        None => continue,
                    };
                    match authenticate(peer, &envelope, self.network, now) {
                        Ok(()) => {
                            // BZ.5 (A1): only the engine's own HALT state gates
                            // consensus ingress. A HALT *alert* is evidence for an
                            // operator and must never stop a node, whoever sent it.
                            let halted = self.state.is_halted();
                            dispatch(peer, &envelope, &mut self.state, &self.registry, halted)
                        }
                        Err(reject) => Incoming::Refused(reject),
                    }
                };
                match &outcome {
                    Incoming::Accepted(dispatched) => {
                        self.accepted += 1;
                        match dispatched {
                            Dispatched::Vote(accepted) => {
                                // BZ.3 §3: only a vote this engine accepted is
                                // relayed, at most once per vote content, and
                                // never back to its sender. A refused vote dies
                                // here, so this node cannot launder it.
                                if accepted.is_accepted()
                                    && self.relayed.insert(accepted.vote().id())
                                {
                                    let kind = match accepted.vote().phase {
                                        VotePhase::Prevote => MessageKind::Prevote,
                                        VotePhase::Precommit => MessageKind::Precommit,
                                    };
                                    self.relay_except(
                                        envelope.sender_id(),
                                        kind,
                                        accepted.vote().encode(),
                                    );
                                }
                            }
                            Dispatched::Transaction(transaction) => {
                                // BZ.3 §4: a transaction arriving from a peer goes
                                // through exactly the same admission as a local
                                // submission — identifier, signature, duplicate,
                                // parents — minus the propagation, which is the
                                // sender's job.
                                if let Err(error) = self.admit_transaction((**transaction).clone())
                                {
                                    let key = match error {
                                        SubmitError::HashMismatch => "tx-hash",
                                        SubmitError::BadSignature => "tx-signature",
                                        SubmitError::Duplicate(_) => "tx-duplicate",
                                        SubmitError::UnknownParent(_) => "tx-parent",
                                        SubmitError::Halted => "tx-halted",
                                        SubmitError::NotEncodable => "tx-encoding",
                                    };
                                    *self.refusals.entry(key).or_insert(0) += 1;
                                }
                            }
                            Dispatched::HaltAlert(alert) => {
                                // An alert is recorded and nothing else: it cannot
                                // stop a node, and it is never a reason to sign.
                                self.halt_evidence = Some(*alert);
                            }
                            Dispatched::HaltProof(proof) => {
                                let proof = (**proof).clone();
                                // `verify` is the single authority on whether this is
                                // a conflict; `halt_with` is the single way to stop.
                                if self.halt_proof.is_none() {
                                    if let Ok(reason) = proof.verify(&self.registry) {
                                        self.halt_proof = Some(Box::new(proof));
                                        // BZ.5 (A2): the node reports durable only
                                        // after the write, the flush and a read-back
                                        // all succeeded. Every failure is recorded
                                        // rather than turned into a silent success.
                                        match self.halt_store.as_deref() {
                                            Some(store) => {
                                                let verified = match self
                                                    .state
                                                    .halt_with(reason, store)
                                                {
                                                    Ok(()) => match self
                                                        .state
                                                        .halt_is_durable(store)
                                                    {
                                                        Ok(true) => Ok(()),
                                                        Ok(false) => Err("the store holds no matching halt record".to_string()),
                                                        Err(error) => Err(error.to_string()),
                                                    },
                                                    Err(error) => Err(error.to_string()),
                                                };
                                                match verified {
                                                    Ok(()) => {
                                                        self.halt_durable = true;
                                                        self.halt_record_error = None;
                                                    }
                                                    Err(error) => {
                                                        self.halt_durable = false;
                                                        self.halt_record_error = Some(error);
                                                    }
                                                }
                                            }
                                            None => {
                                                // Explicit and honest: without a
                                                // store the engine still stops, but
                                                // only in memory; a restart does not
                                                // preserve it.
                                                self.state.halt_in_memory(reason);
                                                self.halt_durable = false;
                                                self.halt_record_error = Some(
                                                    "no store attached: the halt is in memory only"
                                                        .to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            Dispatched::RoundChange(change) => {
                                // The engine re-verifies signature, position,
                                // generation, height and target round, then records
                                // the change. The transport never decides.
                                //
                                // N-9: when a durable store is attached, adoption is
                                // written (and flushed) before the call returns, so
                                // no signature can follow an unpersisted round.
                                let outcome = match self.halt_store.as_deref() {
                                    Some(store) => self.state.process_round_change_persisted(
                                        (**change).clone(),
                                        &self.registry,
                                        self.network,
                                        store,
                                    ),
                                    None => self.state.process_round_change(
                                        (**change).clone(),
                                        &self.registry,
                                        self.network,
                                    ),
                                };
                                match outcome {
                                    Ok(_) => self.round_changes += 1,
                                    Err(_) => {
                                        *self.refusals.entry("round-change").or_insert(0) += 1;
                                    }
                                }
                            }
                            Dispatched::SyncRequested(request) => {
                                // BH priority 6: honour `from_height` and `max_links`,
                                // and bound the answer globally.
                                let remaining = self
                                    .globals
                                    .max_served_bytes
                                    .saturating_sub(self.sync_bytes_served);
                                let within_budget = self.sync_requests_served
                                    < self.globals.max_sync_requests
                                    && remaining > 0;
                                if !within_budget {
                                    self.sync_refused += 1;
                                    *self.refusals.entry("sync-budget").or_insert(0) += 1;
                                } else if let Some(bundle) = self.served.clone() {
                                    match self.history_slice(&bundle, request) {
                                        Some(slice) => match slice.encode() {
                                            Ok(bytes) => {
                                                let peer = envelope.sender_id();
                                                let _ = self.send_to(
                                                    peer,
                                                    MessageKind::BootstrapResponse,
                                                    bytes.clone(),
                                                );
                                                self.sync_requests_served += 1;
                                                self.sync_bytes_served += bytes.len() as u64;
                                            }
                                            Err(_) => {
                                                self.sync_refused += 1;
                                                *self.refusals.entry("sync-size").or_insert(0) += 1;
                                            }
                                        },
                                        None => {
                                            self.sync_refused += 1;
                                            *self.refusals.entry("sync-range").or_insert(0) += 1;
                                        }
                                    }
                                }
                            }
                            Dispatched::Bundle(bundle) => {
                                // BZ.3 §6: the network path and the API run the
                                // same three steps in the same order. Nothing is
                                // installed before verification and the commitment
                                // check have both succeeded.
                                if self.install_bundle(&bundle).is_err() {
                                    *self.refusals.entry("history").or_insert(0) += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    Incoming::Duplicate => {
                        *self.refusals.entry("duplicate").or_insert(0) += 1;
                    }
                    Incoming::Refused(reject) => {
                        let key = match reject {
                            Reject::Unauthenticated(_) => "unauthenticated",
                            Reject::SenderMismatch => "sender",
                            Reject::Malformed { .. } => "malformed",
                            Reject::RateLimited => "rate",
                            Reject::Halted => "halted",
                            Reject::Network(_) => "network",
                            Reject::Engine(_) => "engine",
                        };
                        *self.refusals.entry(key).or_insert(0) += 1;
                        if !crate::network::dispatcher::verdict_keeps_connection(reject) {
                            let sender = envelope.sender_id();
                            self.close_peer(sender);
                        }
                    }
                }
                return Ok(Some((envelope.sender_id(), outcome)));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // -----------------------------------------------------------------
    // Mission BZ.3 §2 — the node's BFT state, read and piloted
    // -----------------------------------------------------------------
    //
    // The engine is reachable through a shared reference and through these
    // methods only. None of them takes a signer, a key, a registry or a
    // generation: the node signs with its own identity, at its own position, and
    // the engine applies exactly the rules it applied when a test drove it
    // directly. Where a store is not taken as an argument, the attached store is
    // used, and its absence is an error rather than an in-memory vote.

    /// The engine, read-only.
    pub fn engine(&self) -> &BftState {
        &self.state
    }

    /// The validator registry the engine weighs votes with.
    pub fn registry(&self) -> &ValidatorRegistry {
        &self.registry
    }

    /// The halt **alert** last received. Evidence for an operator, never a stop.
    pub fn halt_evidence(&self) -> Option<[u8; 32]> {
        self.halt_evidence
    }

    /// The halt **proof** that was verified and injected, if any.
    pub fn halt_proof(&self) -> Option<&HaltProof> {
        self.halt_proof.as_deref()
    }

    /// Decisions this node took through its own engine, in the order taken.
    pub fn decisions(&self) -> &[FinalityDecision] {
        &self.decided
    }

    /// One coherent snapshot of the BFT position, copied out.
    pub fn status(&self) -> NodeStatus {
        let recovery = match &self.state.persisted().status {
            RecoveryStatus::Clean => None,
            RecoveryStatus::RecoveryRequired(reason) => Some(format!("{reason:?}")),
        };
        NodeStatus {
            id: self.id,
            network: self.network,
            generation: self.state.generation,
            height: self.state.height,
            round: self.state.round,
            proposal: self.state.round_state.proposal,
            lock: self.state.active_lock(),
            prevotes: self.state.round_state.prevotes.len(),
            precommits: self.state.round_state.precommits.len(),
            round_changes: self.state.round_state.round_changes.len(),
            may_sign: self.state.may_sign().is_ok(),
            recovery,
            halted: self.state.is_halted(),
            decided: self.state.finality.as_ref().map(|decision| decision.height),
            peers: self.table.len(),
            transactions: self.dag.len(),
        }
    }

    /// Prevote `value` with this node's own key, against the attached store.
    pub fn prevote_value(&mut self, value: [u8; 32]) -> Result<Prevote, NodeError> {
        let me = self.id;
        let Self {
            state,
            registry,
            halt_store,
            key,
            relayed,
            ..
        } = self;
        let store = halt_store.as_deref().ok_or(NodeError::NoStore)?;
        let prevote = state
            .prevote(value, me, registry, store, |message| {
                key.sign(message).to_bytes()
            })
            .map_err(NodeError::Engine)?;
        relayed.insert(prevote.vote().id());
        Ok(prevote)
    }

    /// Prevote `value` against a store the caller owns.
    ///
    /// The store is a durability parameter, not an authority: the signer, the
    /// registry and the position all still come from the node.
    pub fn prevote_with(
        &mut self,
        value: [u8; 32],
        store: &dyn AtomicSlotStore,
    ) -> Result<Prevote, NodeError> {
        let me = self.id;
        let Self {
            state,
            registry,
            key,
            relayed,
            ..
        } = self;
        let prevote = state
            .prevote(value, me, registry, store, |message| {
                key.sign(message).to_bytes()
            })
            .map_err(NodeError::Engine)?;
        relayed.insert(prevote.vote().id());
        Ok(prevote)
    }

    /// Precommit the value of `prevote_certificate`, against the attached store.
    pub fn precommit_value(
        &mut self,
        prevote_certificate: &PrevoteCertificate,
    ) -> Result<Precommit, NodeError> {
        let me = self.id;
        let Self {
            state,
            registry,
            halt_store,
            key,
            relayed,
            ..
        } = self;
        let store = halt_store.as_deref().ok_or(NodeError::NoStore)?;
        let precommit = state
            .precommit(prevote_certificate, me, registry, store, |message| {
                key.sign(message).to_bytes()
            })
            .map_err(NodeError::Engine)?;
        relayed.insert(precommit.vote().id());
        Ok(precommit)
    }

    /// Precommit against a store the caller owns.
    pub fn precommit_with(
        &mut self,
        prevote_certificate: &PrevoteCertificate,
        store: &dyn AtomicSlotStore,
    ) -> Result<Precommit, NodeError> {
        let me = self.id;
        let Self {
            state,
            registry,
            key,
            relayed,
            ..
        } = self;
        let precommit = state
            .precommit(prevote_certificate, me, registry, store, |message| {
                key.sign(message).to_bytes()
            })
            .map_err(NodeError::Engine)?;
        relayed.insert(precommit.vote().id());
        Ok(precommit)
    }

    /// Build a prevote certificate from the votes this node accepted this round.
    pub fn certify_prevotes(&self, value: [u8; 32]) -> Result<PrevoteCertificate, NodeError> {
        self.state
            .certify_prevotes_for(value, &self.registry)
            .map_err(NodeError::Engine)
    }

    /// Build a precommit certificate — a QC — from this round's precommits.
    pub fn certify_precommits(&self, value: [u8; 32]) -> Result<PrecommitCertificate, NodeError> {
        self.state
            .certify_precommits_for(value, &self.registry)
            .map_err(NodeError::Engine)
    }

    /// Decide `checkpoint` with `certificate`, using the attached store.
    pub fn finalize_height(
        &mut self,
        certificate: &PrecommitCertificate,
        checkpoint: &Checkpoint,
        parent: Option<&Checkpoint>,
    ) -> Result<FinalityDecision, NodeError> {
        let Self {
            state,
            registry,
            halt_store,
            decided,
            history,
            ..
        } = self;
        let store = halt_store.as_deref().ok_or(NodeError::NoStore)?;
        let decision = state
            .finalize(certificate, checkpoint, parent, registry, store)
            .map_err(NodeError::Engine)?;
        decided.push(decision.clone());
        // BZ.3 §6: what this node decided is what it can serve. The link keeps the
        // checkpoint and the certificate together, so a peer re-verifies both.
        history.push(SyncLink {
            checkpoint: *checkpoint,
            certificate: certificate.clone(),
        });
        Ok(decision)
    }

    /// Decide against a store the caller owns.
    pub fn finalize_with(
        &mut self,
        certificate: &PrecommitCertificate,
        checkpoint: &Checkpoint,
        parent: Option<&Checkpoint>,
        store: &dyn AtomicSlotStore,
    ) -> Result<FinalityDecision, NodeError> {
        let decision = {
            let Self {
                state, registry, ..
            } = self;
            state
                .finalize(certificate, checkpoint, parent, registry, store)
                .map_err(NodeError::Engine)?
        };
        self.decided.push(decision.clone());
        self.history.push(SyncLink {
            checkpoint: *checkpoint,
            certificate: certificate.clone(),
        });
        Ok(decision)
    }

    /// Propose `value` if this node is the elected proposer, and tell the peers.
    ///
    /// The election is not re-implemented here: `propose_as_proposer` applies the
    /// schedule and refuses a node that is not elected. A refusal is returned as
    /// an error and nothing is broadcast.
    pub fn propose_value(&mut self, value: [u8; 32]) -> Result<(), NodeError> {
        let me = self.id;
        self.state
            .propose_as_proposer(value, &self.registry, me)
            .map_err(NodeError::Engine)?;
        self.broadcast(MessageKind::Proposal, value.to_vec());
        Ok(())
    }

    /// Whether this node is the elected proposer of its current round.
    pub fn is_proposer(&self) -> bool {
        crate::l2bft::proposer::proposer_for(
            &self.registry,
            self.state.generation,
            self.state.height,
            self.state.round,
        )
        .map(|choice| choice.validator == self.id)
        .unwrap_or(false)
    }

    /// Move to `height`, using the attached store.
    pub fn advance_height(&mut self, height: CheckpointHeight) -> Result<(), NodeError> {
        let Self {
            state, halt_store, ..
        } = self;
        let store = halt_store.as_deref().ok_or(NodeError::NoStore)?;
        state
            .advance_height(height, store)
            .map_err(NodeError::Engine)
    }

    /// Move to `round` in the current height, keeping the lock.
    ///
    /// The engine refuses a round that does not advance, a closed generation and a
    /// halted node. A round change never clears the lock (`R-LOCK-2`).
    pub fn begin_round(&mut self, round: Round) -> Result<(), NodeError> {
        self.state.begin_round(round).map_err(NodeError::Engine)
    }

    /// Close the generation in force and install `next_registry`.
    pub fn close_generation(
        &mut self,
        closure: crate::consensus::transitions::GenerationClosure,
        next_registry: &ValidatorRegistry,
    ) -> Result<(), NodeError> {
        let Self {
            state, halt_store, ..
        } = self;
        let store = halt_store.as_deref().ok_or(NodeError::NoStore)?;
        state
            .close_generation(closure, next_registry, store)
            .map_err(NodeError::Engine)?;
        self.registry = next_registry.clone();
        Ok(())
    }

    /// Admit one DAG transaction into this node's pending set.
    ///
    /// The two-parent shape is structural: `Transaction::parents` is
    /// `[TransactionId; 2]`, so no admission path can accept a transaction with
    /// one parent, three parents or a block-like body. Nothing here rewrites the
    /// topology, adds a block, or changes the data model.
    ///
    /// The parent rule is the DAG's own: every non-zero parent must already be
    /// held by this node. A zero parent is the root the genesis allows, and it is
    /// the only value exempt from that check.
    fn admit_transaction(
        &mut self,
        transaction: Transaction,
    ) -> Result<TransactionId, SubmitError> {
        // BZ.5 (A1): a HALT alert stops nothing, transactions included. Only the
        // engine's own HALT state refuses work.
        if self.state.is_halted() {
            return Err(SubmitError::Halted);
        }
        if !transaction.verify_hash_compatible() {
            return Err(SubmitError::HashMismatch);
        }
        if !crate::wallet::Wallet::verify_transaction(&transaction) {
            return Err(SubmitError::BadSignature);
        }
        if self.dag.contains_key(&transaction.id) {
            return Err(SubmitError::Duplicate(transaction.id));
        }
        for parent in transaction.parents {
            let is_root = parent.iter().all(|byte| *byte == 0);
            if !is_root && !self.dag.contains_key(&parent) {
                return Err(SubmitError::UnknownParent(parent));
            }
        }
        let id = transaction.id;
        self.dag.insert(id, transaction);
        Ok(id)
    }

    /// Submit a DAG transaction from this node, then hand it to the active peers.
    ///
    /// A submission with no peer is **accepted** and reports
    /// `peers_notified == 0`: the transaction is held locally and the caller is
    /// told that nobody was told. A refused submission is never broadcast.
    pub fn submit(&mut self, transaction: Transaction) -> Result<Submission, SubmitError> {
        let id = self.admit_transaction(transaction.clone())?;
        let bytes = bincode::serialize(&transaction).map_err(|_| SubmitError::NotEncodable)?;
        let peers_notified = self.broadcast(MessageKind::Transaction, bytes);
        Ok(Submission { id, peers_notified })
    }

    /// DAG transactions held by this node.
    pub fn transactions(&self) -> usize {
        self.dag.len()
    }

    /// Whether this node holds `id`.
    pub fn holds_transaction(&self, id: &TransactionId) -> bool {
        self.dag.contains_key(id)
    }

    /// Read one held transaction.
    pub fn transaction(&self, id: &TransactionId) -> Option<&Transaction> {
        self.dag.get(id)
    }

    // -----------------------------------------------------------------
    // Mission BZ.3 §6 — synchronisation
    // -----------------------------------------------------------------
    //
    // Three separate steps, each one callable on its own, and one path that runs
    // them in order. Construction never weakens verification: a bundle built here
    // is only what a serving node holds, and every receiving node re-runs
    // `verify_history`, the commitment check and the installation itself.

    /// History this node decided, in height order.
    pub fn history(&self) -> &[SyncLink] {
        &self.history
    }

    /// Build the bundle this node would serve, from decisions it took itself.
    ///
    /// Returns `None` when this node has decided nothing: an empty bundle has no
    /// anchor, and inventing one would be a fabricated starting point.
    pub fn build_history(&self) -> Option<SyncBundle> {
        let first = self.history.first()?;
        let anchor = SyncAnchor {
            network: self.network,
            height: first.checkpoint.height,
            checkpoint_id: first.checkpoint.id(),
            generation: first.checkpoint.generation,
            set_root: first.checkpoint.validator_set_root,
        };
        Some(bundle_from(
            anchor,
            self.generations.clone(),
            self.history.clone(),
        ))
    }

    /// Verify a bundle, confront it with this node's own commitments, install it.
    ///
    /// The order is the guarantee: nothing is written before `verify_history` and
    /// `check_commitments` have both succeeded, and neither is weakened here.
    pub fn install_bundle(&mut self, bundle: &SyncBundle) -> Result<usize, SyncError> {
        let Self {
            halt_store,
            installed_links,
            ..
        } = self;
        let store = halt_store
            .as_deref()
            .ok_or_else(|| SyncError::Store("no durable store attached".to_string()))?;
        let history = verify_history(bundle)?;
        check_commitments(store, &history)?;
        install_history(store, &history)?;
        *installed_links = history.links.len();
        Ok(history.links.len())
    }

    /// Ask `peer` for its history from `from_height`, at most `max_links` links.
    pub fn request_history(
        &mut self,
        peer: ValidatorId,
        from_height: CheckpointHeight,
        max_links: u32,
    ) -> Result<(), NodeError> {
        let request = SyncRequest {
            network: self.network,
            from_height,
            max_links,
        };
        let bytes = request.encode();
        self.send_to(peer, MessageKind::SyncRequest, bytes)
    }

    // -----------------------------------------------------------------
    // Mission BZ.3 §7 — round changes
    // -----------------------------------------------------------------

    /// The round this node would move to if its timer fired now.
    pub fn next_round(&self) -> Round {
        Round(self.state.round.get().saturating_add(1))
    }

    /// Build, sign, record and broadcast a round change to `target`.
    ///
    /// Order, all enforced before the signature exists: the current position is
    /// made durable (`round_change_for_persisted`), the signed change carries this
    /// node's lock **as evidence**, and the engine's own `process_round_change`
    /// verifies the message, bounds the jump (`MAX_ROUND_JUMP`), refuses a
    /// duplicate, and adopts only at the round-change quorum. Adoption is a
    /// progress decision: it never touches the lock and never authorises a value.
    pub fn propose_round_change(&mut self, target: Round) -> Result<RoundChangeOutcome, NodeError> {
        // The store is moved out for the duration of the call so the engine can
        // borrow it while the rest of the node is mutably borrowed. It is put back
        // whatever the outcome.
        let store = self.halt_store.take().ok_or(NodeError::NoStore)?;
        let outcome = self.propose_round_change_with(target, store.as_ref());
        self.halt_store = Some(store);
        outcome
    }

    /// Build, sign, record and broadcast a round change against a store the
    /// caller owns, for drivers that already hold the node's durability.
    pub fn propose_round_change_with(
        &mut self,
        target: Round,
        store: &dyn AtomicSlotStore,
    ) -> Result<RoundChangeOutcome, NodeError> {
        let (outcome, bytes) = {
            let Self {
                state,
                registry,
                key,
                ..
            } = self;
            let network = state.network;
            let change = crate::l2bft::timer::round_change_for_persisted(state, target, key, store)
                .map_err(NodeError::Engine)?;
            let bytes = change.encode();
            let outcome = state
                .process_round_change_persisted(change, registry, network, store)
                .map_err(NodeError::Engine)?;
            (outcome, bytes)
        };
        self.broadcast(MessageKind::RoundChange, bytes);
        self.round_changes += 1;
        Ok(outcome)
    }

    /// Send one message to every connected peer except `except`.
    fn relay_except(&mut self, except: ValidatorId, kind: MessageKind, payload: Vec<u8>) {
        let ids: Vec<ValidatorId> = self.streams.keys().copied().collect();
        for id in ids {
            if id == except {
                continue;
            }
            if self.send_to(id, kind, payload.clone()).is_ok() {
                self.relayed_out += 1;
            }
        }
    }

    /// Give the node a store for its halt record.
    ///
    /// A verified proof handed to a node without a store stops the engine in memory
    /// and sets `halt_persisted == false`: the node is honest about the difference
    /// rather than pretending a restart would stay stopped. Attaching a store after
    /// the halt does not retroactively persist it; only a new `halt_with` request
    /// (a fresh verified proof, or an engine-level retry) can confirm durability.
    pub fn attach_halt_store(&mut self, store: Box<dyn AtomicSlotStore>) {
        self.halt_store = Some(store);
    }

    /// Same store, named for its second job: holding installed history.
    pub fn attach_store(&mut self, store: Box<dyn AtomicSlotStore>) {
        self.halt_store = Some(store);
    }

    /// Serve one request as a **slice** of the offered history (BH priority 6).
    ///
    /// `from_height` is the first link returned and `max_links` bounds what follows
    /// it; BG's server ignored both and always sent the whole bundle. Nothing is
    /// silently truncated: an unknown height is `None`, and the slice is shortened
    /// only until it fits the wire and the remaining byte budget, which the
    /// requester sees as a shorter answer and asks again from the new tip.
    /// `generations` travels whole: the ledger belongs to the chain, not to the
    /// window, so successive windows extend the stored one instead of replacing it.
    pub fn history_slice(&self, bundle: &SyncBundle, request: &SyncRequest) -> Option<SyncBundle> {
        let start = bundle
            .links
            .iter()
            .position(|link| link.checkpoint.height == request.from_height)?;
        let mut count = (bundle.links.len() - start).min(request.max_links as usize);
        while count > 0 {
            let links: Vec<SyncLink> = bundle.links[start..start + count].to_vec();
            let first = &links[0].checkpoint;
            let anchor = SyncAnchor {
                network: bundle.anchor.network,
                height: first.height,
                checkpoint_id: first.id(),
                generation: first.generation,
                set_root: first.validator_set_root,
            };
            let slice = SyncBundle {
                anchor,
                generations: bundle.generations.clone(),
                links,
            };
            let remaining = self
                .globals
                .max_served_bytes
                .saturating_sub(self.sync_bytes_served);
            match slice.encode() {
                Ok(bytes) if bytes.len() as u64 <= remaining => return Some(slice),
                _ => count -= 1,
            }
        }
        None
    }

    /// Set the node-wide budgets.
    pub fn attach_global_limits(&mut self, limits: GlobalLimits) {
        self.globals = limits;
    }

    /// Whether a durable store is attached.
    pub fn has_store(&self) -> bool {
        self.halt_store.is_some()
    }

    /// Offer a history to peers that ask for one.
    pub fn serve_history(&mut self, history: SyncBundle) {
        self.served = Some(history);
    }

    /// Whether the halt record reached durable storage **and was read back**.
    ///
    /// BZ.5 (A2): this is never inferred from the presence of a store or of a
    /// proof. It is true only after [`BftState::halt_with`] returned `Ok` and the
    /// stored record was read back identical.
    pub fn halt_persisted(&self) -> bool {
        self.halt_durable
    }

    /// Why the durable halt record was not confirmed, if it was not.
    ///
    /// `Some` also covers the deliberate case of a node with no store: the halt
    /// is real in memory, but it is not durable and the node says so.
    pub fn halt_record_error(&self) -> Option<&str> {
        self.halt_record_error.as_deref()
    }

    /// Drop one peer's connection (simulating a disconnect).
    ///
    /// BZ.3 §5: every removal goes through [`Self::close_peer`], which is the one
    /// place that releases the stream, the table entry, the direction record and
    /// the address slot together. The earlier version forgot the last two, so a
    /// disconnect leaked an address slot and a reconnect could be refused by the
    /// node's own accounting.
    pub fn disconnect(&mut self, peer: &ValidatorId) -> bool {
        let was_connected = self.streams.contains_key(peer) || self.table.get(peer).is_some();
        self.close_peer(*peer);
        was_connected
    }

    /// Dial `address` only if this node holds no link to it, and finish the
    /// handshake. `Ok(false)` means a live or pending connection already exists.
    pub fn reconnect(&mut self, address: SocketAddr) -> Result<bool, NodeError> {
        let known = self.addrs.values().any(|known| *known == address)
            || self
                .pending
                .iter()
                .filter_map(|stream| stream.peer_addr().ok())
                .any(|pending| pending == address);
        if known {
            return Ok(false);
        }
        self.dial(address)?;
        self.finish_dials();
        Ok(true)
    }

    /// How many duplicate connections this node closed, by peer.
    pub fn duplicate_connections_closed(&self) -> u64 {
        self.duplicates_closed
    }

    /// Drop every connection.
    pub fn disconnect_all(&mut self) {
        let ids: Vec<ValidatorId> = self.streams.keys().copied().collect();
        for id in ids {
            self.disconnect(&id);
        }
    }

    /// Peers that have gone silent beyond the idle timeout.
    pub fn expired_peers(&self) -> Vec<ValidatorId> {
        self.table.expired(Instant::now())
    }
}
