//! Peer identity, limits and replay window (mission BE).
//!
//! # Identity is derived, never claimed
//!
//! A peer sends its Ed25519 public key in the handshake; the identity used for
//! routing and for consensus roles is `validator_id(key)`, exactly the value the
//! registry uses. A peer cannot pick an identity, and an address says nothing
//! about who is behind it.
//!
//! # A connection is not a membership
//!
//! Being connected authenticates *who* is talking. It says nothing about whether
//! that party may vote: the registry decides, and the engine enforces it. This
//! module keeps the two apart on purpose.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::consensus::generation::ValidatorId;
use crate::l2crypto::registry::{validator_id, ValidatorRegistry};

/// Hard limits of one node's network surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    /// Maximum simultaneous connections.
    pub max_connections: usize,
    /// Maximum accepted messages per peer per second.
    pub max_messages_per_second: u32,
    /// Maximum payload accepted from a peer.
    pub max_payload: usize,
    /// Read timeout for one frame.
    pub read_timeout: Duration,
    /// Write timeout for one frame.
    pub write_timeout: Duration,
    /// Time after which an idle peer is considered dead.
    pub idle_timeout: Duration,
    /// Size of the replay window per peer.
    pub replay_window: usize,
    /// Maximum simultaneous connections from one remote address.
    ///
    /// The default is deliberately loose because every test in this repository
    /// runs on loopback, where an entire 21-validator network shares `127.0.0.1`.
    /// A deployment with one address per validator should lower it to 1 or 2.
    pub max_connections_per_address: usize,
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            max_connections: 32,
            max_messages_per_second: 200,
            max_payload: crate::network::protocol::MAX_PAYLOAD,
            read_timeout: Duration::from_millis(500),
            write_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(5),
            replay_window: 4096,
            max_connections_per_address: 16,
        }
    }
}

/// Why a peer was refused or dropped.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PeerError {
    /// The handshake carries another protocol version.
    #[error("handshake version {found} is not {expected}")]
    Version {
        /// Expected.
        expected: u8,
        /// Found.
        found: u8,
    },

    /// The handshake carries another network.
    #[error("handshake network {found} is not {expected}")]
    Network {
        /// Expected.
        expected: u64,
        /// Found.
        found: u64,
    },

    /// The claimed identity does not match the key.
    #[error("claimed identity does not derive from the presented key")]
    IdentityMismatch,

    /// The connection budget is exhausted.
    #[error("connection limit {0} reached")]
    TooManyConnections(usize),

    /// One remote address holds too many simultaneous connections.
    ///
    /// This is a **resource** limit, not an identity check: an attacker with many
    /// addresses is not slowed down by it, and that is exactly the Sybil gap this
    /// limit does not close (see `connection-limits.md`).
    #[error("address limit {limit} reached for {address}")]
    AddressLimitReached {
        /// Remote address, as text.
        address: String,
        /// Limit that applied.
        limit: usize,
    },

    /// The peer exceeds its message rate.
    #[error("rate limit exceeded for {0}")]
    RateLimited(String),

    /// The peer is not a member of the generation in force.
    #[error("peer is not a validator of the active generation")]
    NotAValidator,

    /// The peer sent something unacceptable.
    #[error("peer refused: {0}")]
    Refused(&'static str),
}

/// Identity established by a verified handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Derived identity.
    pub id: ValidatorId,
    /// Presented key.
    pub public_key: [u8; 32],
    /// Height the peer reported.
    pub height: u64,
}

impl PeerIdentity {
    /// Derive the identity from the key — the only way to obtain one.
    pub fn derive(public_key: [u8; 32], height: u64) -> Self {
        Self {
            id: validator_id(&public_key),
            public_key,
            height,
        }
    }

    /// Whether this peer is a validator of `registry`, and may therefore carry
    /// consensus messages.
    pub fn may_vote_in(&self, registry: &ValidatorRegistry) -> bool {
        registry
            .get(&self.id)
            .map(|entry| entry.admissibility.may_vote())
            .unwrap_or(false)
    }
}

/// Sliding window of recently accepted message identifiers.
///
/// Bounded on purpose: a peer cannot grow the node's memory by replaying forever.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    seen: std::collections::HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
    rejected: u64,
}

impl ReplayWindow {
    /// Empty window of `capacity` identifiers.
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            rejected: 0,
        }
    }

    /// Record `id`. Returns `false` when it was already seen.
    pub fn accept(&mut self, id: [u8; 32]) -> bool {
        if !self.seen.insert(id) {
            self.rejected += 1;
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }

    /// How many replays were refused.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// How many identifiers are currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

/// Token bucket, one per peer.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    per_second: u32,
    tokens: u32,
    last: Instant,
}

impl RateLimiter {
    /// A limiter allowing `per_second` messages, starting full.
    pub fn new(per_second: u32) -> Self {
        Self {
            per_second,
            tokens: per_second,
            last: Instant::now(),
        }
    }

    /// Take one token; `false` means the peer is over its budget.
    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last);
        if elapsed >= Duration::from_secs(1) {
            self.tokens = self.per_second;
            self.last = now;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// What this node knows about one connected peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Verified identity.
    pub identity: PeerIdentity,
    /// Whether the handshake completed.
    pub authenticated: bool,
    /// Last time anything was heard.
    pub last_seen: Instant,
    /// Replay window of this peer.
    pub replay: ReplayWindow,
    /// Rate limiter of this peer.
    pub limiter: RateLimiter,
    /// Messages accepted from this peer.
    pub accepted: u64,
    /// Messages refused from this peer.
    pub refused: u64,
}

/// The set of peers this node talks to.
///
/// Deduplicated by identity: two connections from the same key are the same peer,
/// and an address is never used as an identity.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: BTreeMap<ValidatorId, PeerState>,
    limits: PeerLimits,
}

impl PeerTable {
    /// Empty table with these limits.
    pub fn new(limits: PeerLimits) -> Self {
        Self {
            peers: BTreeMap::new(),
            limits,
        }
    }

    /// Limits in force.
    pub fn limits(&self) -> &PeerLimits {
        &self.limits
    }

    /// Insert or refresh a peer after a verified handshake.
    pub fn admit(&mut self, identity: PeerIdentity, now: Instant) -> Result<(), PeerError> {
        if !self.peers.contains_key(&identity.id) && self.peers.len() >= self.limits.max_connections
        {
            return Err(PeerError::TooManyConnections(self.limits.max_connections));
        }
        // BZ.3 §5: a second connection from the same key is the **same** peer, not
        // a new one. Admission therefore refreshes liveness and nothing else.
        // Replacing the state would reset the replay window and the rate budget,
        // which is exactly the hole a peer needs to replay a captured vote or to
        // spend its budget twice: reconnect, and its own history is gone.
        if let Some(existing) = self.peers.get_mut(&identity.id) {
            existing.identity = identity;
            existing.last_seen = now;
            return Ok(());
        }
        self.peers.insert(
            identity.id,
            PeerState {
                identity,
                authenticated: true,
                last_seen: now,
                replay: ReplayWindow::new(self.limits.replay_window),
                limiter: RateLimiter::new(self.limits.max_messages_per_second),
                accepted: 0,
                refused: 0,
            },
        );
        Ok(())
    }

    /// Look up a peer by identity.
    pub fn get(&self, id: &ValidatorId) -> Option<&PeerState> {
        self.peers.get(id)
    }

    /// Mutable access, for accounting.
    pub fn get_mut(&mut self, id: &ValidatorId) -> Option<&mut PeerState> {
        self.peers.get_mut(id)
    }

    /// Drop a peer (disconnection, timeout, misbehaviour).
    pub fn remove(&mut self, id: &ValidatorId) -> Option<PeerState> {
        self.peers.remove(id)
    }

    /// Identities currently connected.
    pub fn ids(&self) -> Vec<ValidatorId> {
        self.peers.keys().copied().collect()
    }

    /// Number of connected peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peer is connected.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Peers that have been silent for longer than the idle timeout.
    pub fn expired(&self, now: Instant) -> Vec<ValidatorId> {
        self.peers
            .iter()
            .filter(|(_, state)| now.duration_since(state.last_seen) > self.limits.idle_timeout)
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Connections currently held per remote address (mission BI, priority 6).
///
/// The peer table is keyed by **identity**, which is the right key for consensus
/// and the wrong one for resource accounting: one attacker can present a thousand
/// keys from one address, and one address can host a thousand keys. This book
/// counts sockets, not identities, and releases a slot on every disconnection.
///
/// It closes two gaps `PeerLimits::max_connections` left open:
///
/// | Gap | Before | Now |
/// |---|---|---|
/// | many sockets from one address | limited only globally | `max_connections_per_address` |
/// | slots released on disconnect | table removal only | `close` on every removal path |
///
/// It does **not** stop a Sybil attack: a peer with `n` addresses gets `n` times
/// the budget. No local counter can fix that; it needs an admission cost
/// (proof of work, stake, invitation), which this mission does not invent.
#[derive(Debug, Default)]
pub struct AddressBook {
    counts: std::collections::BTreeMap<std::net::IpAddr, usize>,
    total: usize,
    refused: u64,
}

impl AddressBook {
    /// Empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve one connection slot for `address`.
    ///
    /// Refuses when the global limit or the per-address limit is reached, and
    /// counts the refusal so an operator can see attempted floods.
    pub fn try_open(
        &mut self,
        address: std::net::SocketAddr,
        limits: &PeerLimits,
    ) -> Result<(), PeerError> {
        let ip = address.ip();
        let used = self.counts.get(&ip).copied().unwrap_or(0);
        if used >= limits.max_connections_per_address {
            self.refused += 1;
            return Err(PeerError::AddressLimitReached {
                address: ip.to_string(),
                limit: limits.max_connections_per_address,
            });
        }
        if self.total >= limits.max_connections {
            self.refused += 1;
            return Err(PeerError::TooManyConnections(limits.max_connections));
        }
        *self.counts.entry(ip).or_insert(0) += 1;
        self.total += 1;
        Ok(())
    }

    /// Release the slot held by `address`.
    ///
    /// Called on every removal path — read error, write error, refused envelope,
    /// deduplicated handshake — so a long run cannot drift upward and start
    /// refusing honest peers because of a leak.
    pub fn close(&mut self, address: std::net::SocketAddr) {
        let ip = address.ip();
        if let Some(count) = self.counts.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.counts.remove(&ip);
            }
            self.total = self.total.saturating_sub(1);
        }
    }

    /// Connections currently held from `ip`.
    pub fn count_for(&self, ip: std::net::IpAddr) -> usize {
        self.counts.get(&ip).copied().unwrap_or(0)
    }

    /// Distinct addresses with at least one connection.
    pub fn addresses(&self) -> usize {
        self.counts.len()
    }

    /// Total connections held.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Refusals due to a limit, since the node started.
    pub fn refused(&self) -> u64 {
        self.refused
    }
}

/// Verify a handshake and derive the peer's identity.
///
/// Checks version, network, and that the claimed key produces the identity the
/// caller will route by. It does **not** decide membership: that is the registry's
/// job, via [`PeerIdentity::may_vote_in`].
pub fn verify_hello(
    hello: &crate::network::protocol::Hello,
    expected_network: u64,
) -> Result<PeerIdentity, PeerError> {
    if hello.version != crate::network::protocol::WIRE_VERSION {
        return Err(PeerError::Version {
            expected: crate::network::protocol::WIRE_VERSION,
            found: hello.version,
        });
    }
    if hello.network != expected_network {
        return Err(PeerError::Network {
            expected: expected_network,
            found: hello.network,
        });
    }
    ed25519_dalek::VerifyingKey::from_bytes(&hello.public_key)
        .map_err(|_| PeerError::IdentityMismatch)?;
    Ok(PeerIdentity::derive(hello.public_key, hello.height))
}
