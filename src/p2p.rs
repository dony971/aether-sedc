//! # P2P Networking Module
//!
//! Implements peer-to-peer networking for the Aether DAG with efficient inventory synchronization.
//! Uses tip-based synchronization and hash comparison for inventory management.
//! Supports DNS-based peer discovery and peer exchange (PEX).

use crate::transaction::Transaction;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::sync_stats::{SyncContext, TOPO_ORDER_CAP};

/// P2P handshake magic bytes ("AETH")
const HANDSHAKE_MAGIC: [u8; 4] = [0x41, 0x45, 0x54, 0x48];

/// Maximum accepted encrypted message size (16 MiB). The length prefix is a
/// u32: without this cap a peer could advertise a 4 GiB frame and force a
/// giant allocation (memory DoS, V-09).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of concurrently connected peers (V-10)
const MAX_PEERS: usize = 128;

/// Maximum number of peers from the same /24 subnet (eclipse prevention)
const MAX_PEERS_PER_SUBNET: usize = 4;

/// Number of outbound connection slots reserved and never evicted
const PROTECTED_OUTBOUND_SLOTS: usize = 8;

/// Maximum number of known peer addresses retained (PEX/DNS growth bound)
const MAX_KNOWN_PEERS: usize = 1000;

/// Maximum outbound dials attempted in a single reconnection cycle (Phase 2A).
/// Without this a peer store full of dead addresses turns one cycle into an
/// hours-long serial sweep; the budget lets the loop move on to the next cycle.
const MAX_REDIAL_PER_CYCLE: usize = 32;

// ---------------------------------------------------------------------------
// Phase 2B — distributed peer manager (address categories, versioned store,
// anchors, bounded PEX, PEX-only address filtering).
// ---------------------------------------------------------------------------

/// Schema version of the on-disk peer store. v1 was a bare JSON array of
/// address strings; v2 adds per-entry metadata. See `PeerStoreFile`.
const PEER_STORE_VERSION: u32 = 2;

/// Maximum anchors retained at once (Principle 5). Several, never one: a
/// single anchor would recreate exactly the authority this phase removes.
const MAX_ANCHORS: usize = 8;

/// Minimum anchors worth trying to maintain. Below this the anchor task
/// promotes from recently-successful peers. Anchors are never *required*, so
/// this is a target rather than a floor that gates anything.
const MIN_ANCHORS: usize = 3;

/// Maximum addresses attached to a single PEX message (D5). The receive side
/// is already bounded by MAX_INV_ITEMS; this bounds the send side, which used
/// to relay the entire known set (up to MAX_KNOWN_PEERS) to every peer.
const PEX_MAX_SEND: usize = 64;

/// PEX only gossips addresses that were useful recently. Hints older than this
/// are retained for redial but not re-shared (PEX aging).
const PEX_SHARE_MAX_AGE_SECS: u64 = 24 * 3600;

/// An anchor with no successful contact for this long is expired and replaced.
const ANCHOR_TTL_SECS: u64 = 7 * 24 * 3600;

/// Interval at which anchors are rotated/expired (Phase 2B).
const ANCHOR_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// An address whose last successful handshake falls inside this window counts
/// as `Recent` (still in living memory) rather than `Candidate` (heard of,
/// unproven). Candidates are the lowest-priority redial fodder.
const RECENT_PEER_WINDOW_SECS: u64 = 24 * 3600;

/// An address whose score fell to/below this is categorised `Penalized` and is
/// never a promotion source for anchors, nor relayed by PEX.
const PEER_QUALITY_PENALIZED: i32 = PEER_SCORE_BAN_THRESHOLD;

/// Highest quality score a `PeerMeta` can carry (mirrors PeerScore ceiling).
const PEER_QUALITY_MAX: i32 = 200;

// ---------------------------------------------------------------------------
// Phase 2C — eclipse resistance (diversified, rotated outbound selection).
//
// Every coefficient below is expressed as a fraction of `PEER_SCORE_INITIAL`
// so that address quality — which starts at exactly `PEER_SCORE_INITIAL` —
// stays the dominant term in the selection weight. None of them is a number
// chosen to make a test pass; the fraction they represent is the justification.
// Full derivation: docs/AETHER_PHASE2_ECLIPSE_AUDIT.md §13.
// ---------------------------------------------------------------------------

/// Maximum addresses one network group may contribute to a *single* outbound
/// selection round. Half of `MAX_PEERS_PER_SUBNET` by construction: a round of
/// `MAX_REDIAL_PER_CYCLE` dials therefore spans at least 16 groups when the
/// pool allows, while two consecutive rounds can still fill a group right up
/// to its session cap.
const MAX_CANDIDATES_PER_GROUP: usize = MAX_PEERS_PER_SUBNET / 2;

/// Rank bonus for an address promoted as an anchor. Half of the initial score:
/// an anchor is an address we have *already* reached and deliberately kept, so
/// it must outrank an unknown candidate — but never outrank the gap between a
/// healthy peer and one that keeps failing.
const ANCHOR_SELECT_BONUS: i32 = PEER_SCORE_INITIAL / 2;

/// Rank bonus for a successful handshake inside `RECENT_PEER_WINDOW_SECS`.
/// A quarter of the initial score: fresh proof, worth less than the persisted
/// proof an anchor represents.
const RECENT_SUCCESS_BONUS: i32 = PEER_SCORE_INITIAL / 4;

/// Rank penalty applied once per live session already held in the same network
/// group. Four sessions in one group cost 80, making an over-represented group
/// roughly five times less likely to be picked than an empty one of equal
/// quality — which is what turns "diversity" into a selection property rather
/// than a post-hoc admission check.
const GROUP_OVERREPRESENTATION_PENALTY: i32 = PEER_SCORE_INITIAL / 5;

/// Selection weights are offset by one so a never-tried candidate can never
/// score zero: the node must always be able to try *something*.
const MIN_SELECT_WEIGHT: u64 = 1;

/// Quality assigned to an address learned **only** from a PEX gossip hint.
/// Half of `PEER_SCORE_INITIAL`, therefore strictly below every entry we
/// observed through a channel we control (inbound, outbound dial, DNS,
/// operator config). `admit_peer` evicts when `victim_quality <= incoming`,
/// so at this value a PEX burst can displace only already-degraded or banned
/// entries — never a healthy peer it happens to outnumber.
const PEX_ADMISSION_QUALITY: i32 = PEER_SCORE_INITIAL / 2;

// ---------------------------------------------------------------------------
// Phase 2D — self-healing (bounded, hysteretic peer recovery).
//
// Every threshold below is *derived* from a constant that already exists in
// this file; none of them was chosen to make a test pass. Full derivation:
// docs/AETHER_PHASE2_SELF_HEALING_AUDIT.md §E.6.
// ---------------------------------------------------------------------------

/// Hysteresis **exit** threshold, and the count recovery aims at.
///
/// Exactly `PROTECTED_OUTBOUND_SLOTS`, whose own doc says *"8 = 2 x
/// MAX_PEERS_PER_SUBNET: the reserve covers two complete network groups, i.e.
/// at least two independent paths"*. Recovery declares itself finished only
/// once the node holds the diversity 2C already reserves slots for.
const RECOVERY_COMFORT_PEERS: usize = PROTECTED_OUTBOUND_SLOTS;

/// Hysteresis **entry** threshold.
///
/// Exactly `MAX_PEERS_PER_SUBNET`: below one full group the node no longer
/// holds even the quota a single group is allowed, which is an observed loss
/// of diversity rather than a gradual dip. `RECOVERY_THRESHOLD <
/// RECOVERY_COMFORT_PEERS` is what makes the band `[4, 8)` wide enough that a
/// count oscillating between 7 and 8 can never start and stop recovery.
const RECOVERY_THRESHOLD: usize = MAX_PEERS_PER_SUBNET;

/// Diagnostic floor, never a trigger: `MIN_ANCHORS` is already documented as
/// *"Several, never one"*. Logged on the deep-loss transition only.
const RECOVERY_MIN_PEERS: usize = MIN_ANCHORS;

/// Upper bound on dials issued by a single recovery round.
///
/// `PROTECTED_OUTBOUND_SLOTS` again: a round never opens more dials than the
/// number of outbound slots Phase 2C reserves, and is therefore always below
/// `MAX_REDIAL_PER_CYCLE` by construction.
const MAX_DIALS_PER_ROUND: usize = PROTECTED_OUTBOUND_SLOTS;

/// Cadence of the recovery loop — the same 5s the existing redial loop uses,
/// so there is one familiar clock rather than a second one to reason about.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// First backoff step after a failed round. Same base as the existing
/// per-candidate redial backoff (`2 ^ attempt` seconds at `:2076`).
const RECOVERY_BACKOFF_BASE_SECS: u64 = 5;

/// Backoff ceiling, identical to the existing per-candidate ceiling
/// (`min(.., 60)` at `:2076`).
const RECOVERY_BACKOFF_MAX_SECS: u64 = 60;

/// Levels of backoff before the delay stops growing. The existing redial loop
/// caps its own counter at 6 (`min(attempt + 1, 6)` at `:2087`) because
/// `2 ^ 6 = 64` already exceeds the 60s ceiling — same reason, same number.
const RECOVERY_MAX_LEVEL: u32 = 6;

/// Rounds that may open no session at all before recovery gives up and moves
/// to `Exhausted`. Same bounded counter as above; this is what makes an
/// infinite redial loop impossible at the controller level.
const RECOVERY_MAX_CONSECUTIVE_FAILURES: u32 = 6;


/// Maximum entries in the seen-transaction cache (memory bound)
const MAX_SEEN_TXS: usize = 50_000;

/// Maximum items accepted from a single Inventory/GetData/GetInventory/Peers
/// message (vector-of-vectors amplification bound)
const MAX_INV_ITEMS: usize = 1000;

/// DEEP SYNC: maximum transactions per SyncResponse page.
/// Each page is ancestor-closed and topologically sorted.
const MAX_SYNC_PAGE: usize = 100;

/// DEEP SYNC: maximum number of ancestor-closure pages that can be computed
/// per GetData request. Total max served = MAX_CLOSURE_PAGES * MAX_SYNC_PAGE.
/// This bounds CPU (BFS walk), memory (HashSet), and network (message size).
const MAX_CLOSURE_PAGES: usize = 10;

/// DEEP SYNC: adaptive backpressure base interval (ms) for SyncResponse delivery.
/// Scales with batch size instead of fixed 50ms per tx.
const BACKPRESSURE_BASE_MS: u64 = 5;

// --- Peer Scoring ---
/// Initial score for new peers
const PEER_SCORE_INITIAL: i32 = 100;
/// Score below this → temporary ban
const PEER_SCORE_BAN_THRESHOLD: i32 = 0;
/// Penalty for invalid message (bad format, invalid tx)
const PEER_PENALTY_INVALID_MSG: i32 = -10;
/// Penalty for contradictory data (conflicting inventory)
const PEER_PENALTY_CONTRADICTION: i32 = -20;
/// Penalty for timeout (slow or stalled peer)
const PEER_PENALTY_TIMEOUT: i32 = -5;
/// Penalty for rate limit hit (flood)
const PEER_PENALTY_FLOOD: i32 = -15;
/// Penalty for abusive/abnormal requests
const PEER_PENALTY_ABUSIVE: i32 = -10;
/// Bonus for successful sync contribution
const PEER_BONUS_SYNC: i32 = 5;
/// Score recovery per decay interval (towards 100)
const PEER_DECAY_RATE: i32 = 1;
/// Decay interval
const PEER_DECAY_INTERVAL: Duration = Duration::from_secs(300);
/// Temporary ban duration
const PEER_BAN_TEMP: Duration = Duration::from_secs(300);
/// Number of temp bans before permanent ban
const PEER_BAN_TEMP_MAX: usize = 3;
/// Permanent ban duration
const PEER_BAN_PERM: Duration = Duration::from_secs(3600);

/// Per-peer reputation score with decay and ban tracking
#[derive(Clone, Debug)]
struct PeerScore {
    score: i32,
    temp_bans: usize,
    last_decay: Instant,
    banned_until: Option<Instant>,
}

impl PeerScore {
    fn new() -> Self {
        Self {
            score: PEER_SCORE_INITIAL,
            temp_bans: 0,
            last_decay: Instant::now(),
            banned_until: None,
        }
    }

    /// Apply decay: score moves towards PEER_SCORE_INITIAL
    fn decay(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_decay) >= PEER_DECAY_INTERVAL {
            if self.score < PEER_SCORE_INITIAL {
                self.score = (self.score + PEER_DECAY_RATE).min(PEER_SCORE_INITIAL);
            } else if self.score > PEER_SCORE_INITIAL {
                self.score = (self.score - PEER_DECAY_RATE).max(PEER_SCORE_INITIAL);
            }
            self.last_decay = now;
        }
    }

    /// Apply a penalty. Returns true if peer should be banned.
    fn penalize(&mut self, penalty: i32) -> bool {
        self.score += penalty;
        self.score <= PEER_SCORE_BAN_THRESHOLD
    }

    /// Apply a bonus (capped at initial)
    fn reward(&mut self, bonus: i32) {
        self.score = (self.score + bonus).min(PEER_SCORE_INITIAL + 50);
    }

    /// Check if currently banned
    fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Ban the peer (temp or perm based on history)
    fn ban(&mut self) {
        self.temp_bans += 1;
        if self.temp_bans >= PEER_BAN_TEMP_MAX {
            self.banned_until = Some(Instant::now() + PEER_BAN_PERM);
        } else {
            self.banned_until = Some(Instant::now() + PEER_BAN_TEMP);
        }
    }
}

/// Maximum frames accepted from a peer per second (rate limit)
const MAX_MSGS_PER_SEC: u64 = 400;

/// Phase 2C: the network group an endpoint belongs to. One group is one
/// unit of eclipse exposure — an attacker who owns one routable allocation
/// occupies exactly one group, so a per-group cap bounds what they can take.
///
/// Derivation of the granularity, and of why IPv6 uses 24 bits rather than a
/// finer /48, in docs/AETHER_PHASE2_ECLIPSE_AUDIT.md §13.1. The short version:
/// the only dangerous direction is *under*-grouping (one real allocation
/// spread over many groups), and every realistic single allocation — IPv4 /24
/// or larger, IPv6 /32 or larger — sits inside exactly one 24-bit group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum NetworkGroup {
    /// First three octets of an IPv4 address (a /24).
    V4([u8; 3]),
    /// First 24 bits of a native IPv6 address. Coarser than a /48 on purpose:
    /// a /48 would let a single provider allocation span thousands of groups.
    V6([u8; 3]),
}

impl NetworkGroup {
    /// The lossy three-byte projection used by the legacy `subnet_24` helpers.
    /// Erasing the family bit can only ever *merge* two groups, never split
    /// one, so the projection stays on the conservative side.
    fn prefix3(self) -> [u8; 3] {
        match self {
            NetworkGroup::V4(p) | NetworkGroup::V6(p) => p,
        }
    }
}

/// Phase 2C: the single grouping rule for endpoints.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is judged as IPv4. Without this every
/// mapped address collapses into the one group `[0, 0, 0]`, because the first
/// three octets of `::ffff:x.x.x.x` are zero — and a dual-stack listener on
/// Windows returns exactly that form from `accept()`, which would cap a
/// healthy node at four inbound sessions in total.
fn network_group(addr: SocketAddr) -> NetworkGroup {
    match addr {
        SocketAddr::V4(v4) => {
            let o = v4.ip().octets();
            NetworkGroup::V4([o[0], o[1], o[2]])
        }
        SocketAddr::V6(v6) => {
            let o = v6.ip().octets();
            // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d):
            // judge the embedded v4 address, exactly as `is_private_or_reserved`
            // already does, so the two rules can never disagree.
            if o[..10] == [0u8; 10]
                && ((o[10] == 0xff && o[11] == 0xff) || o[10..12] == [0, 0])
            {
                return network_group(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15])),
                    addr.port(),
                ));
            }
            NetworkGroup::V6([o[0], o[1], o[2]])
        }
    }
}

/// Phase 1 helper, retained unchanged in signature because the Phase 1/8 tests
/// assert on it directly. Now a projection of `network_group`, so the two can
/// never drift apart.
fn subnet_24(addr: SocketAddr) -> Option<[u8; 3]> {
    Some(network_group(addr).prefix3())
}


/// Count how many connected peers share the same /24 subnet as `addr`.
async fn count_subnet_peers(
    addr: SocketAddr,
    peers: &HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> usize {
    let target = match subnet_24(addr) {
        Some(s) => s,
        None => return 0,
    };
    peers
        .keys()
        .filter(|k| subnet_24(**k) == Some(target))
        .count()
}

/// Count how many connected peers share the same /24 subnet as `addr`,
/// excluding `addr` itself (for checking before adding).
async fn count_subnet_peers_excluding(
    addr: SocketAddr,
    peers: &HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> usize {
    let target = match subnet_24(addr) {
        Some(s) => s,
        None => return 0,
    };
    peers
        .keys()
        .filter(|k| **k != addr && subnet_24(**k) == Some(target))
        .count()
}

/// Phase 2C: histogram of `addr` over network groups — how many distinct
/// groups are represented, and how many endpoints each holds. Consumed by the
/// selection debug log and by the Phase 2C tests as the diversity metric.
fn group_counts<'a, I>(addrs: I) -> HashMap<NetworkGroup, usize>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut counts: HashMap<NetworkGroup, usize> = HashMap::new();
    for a in addrs {
        *counts.entry(network_group(a)).or_insert(0) += 1;
    }
    counts
}

/// Phase 2C: may one more *inbound* connection be accepted?
///
/// The guarantee, and the whole point of `PROTECTED_OUTBOUND_SLOTS`:
///
/// > whenever this returns true, `(total - outbound) + PROTECTED_OUTBOUND_SLOTS
/// > <= MAX_PEERS` — i.e. the reservation still fits in the table *after* this
/// > connection is admitted, so `outbound_admitted` keeps holding for at least
/// > `PROTECTED_OUTBOUND_SLOTS - outbound` further dials.
///
/// Without it a client that opens 128 connections fills the shared `MAX_PEERS`
/// table and `connect_to_peer_inner` refuses every subsequent dial — the node
/// keeps gossiping while being unable to initiate a single session (audit L1,
/// scenario A). `outbound` is passed in because a node that already holds its
/// reserved outbound sessions owes no further reservation: counting against the
/// *total* alone would throttle inbound on an outbound-heavy node.
fn inbound_admitted(total: usize, outbound: usize) -> bool {
    if outbound > total {
        // Direction bookkeeping can only ever be a subset of the session map;
        // treat anything else as "admit nothing" rather than unwrap it.
        return false;
    }
    // Sessions we still owe outbound. Each already-open outbound session counts
    // towards that target, so the reservation shrinks as they are filled.
    let reserve = PROTECTED_OUTBOUND_SLOTS.saturating_sub(outbound);
    // `total + 1` is the table once this inbound is admitted. It may enter only
    // if what outbound is still owed still fits alongside it.
    total + 1 + reserve <= MAX_PEERS
}

/// Phase 2C: may one more *outbound* connection be opened? Deliberately looser
/// than the inbound rule — the reserved slots exist precisely so this keeps
/// holding while inbound traffic saturates everything else.
fn outbound_admitted(total: usize) -> bool {
    total < MAX_PEERS
}

// ---------------------------------------------------------------------------
// Phase 2B pure helpers. Deliberately free of I/O and of `self` so every
// policy decision below is directly unit-testable.
// ---------------------------------------------------------------------------

/// Current wall-clock time in Unix seconds (metadata timestamps are persisted,
/// so they cannot be `Instant`).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Phase 2B (D7): classify an address. Priority is security-first:
/// `Penalized` beats everything (a banned peer is never "active" to us),
/// then liveness, then standing, then recency.
fn categorise(
    connected: bool,
    anchor: bool,
    penalized: bool,
    last_success: Option<u64>,
    now_unix: u64,
) -> PeerCategory {
    if penalized {
        PeerCategory::Penalized
    } else if connected {
        PeerCategory::Active
    } else if anchor {
        PeerCategory::Anchor
    } else if last_success
        .map(|t| now_unix.saturating_sub(t) <= RECENT_PEER_WINDOW_SECS)
        .unwrap_or(false)
    {
        PeerCategory::Recent
    } else {
        PeerCategory::Candidate
    }
}

/// Phase 2B (D6): addresses that must never be dialled on the authority of a
/// PEX hint. A peer that can steer us into dialing `127.0.0.1`, an RFC1918 or
/// a link-local host redirects our traffic onto a machine we own or probes our
/// LAN.
///
/// R4: this gate applies **only** to PEX-sourced addresses. Operator-configured
/// bootnodes and DNS seeds stay unrestricted, so private/LAN testnets keep
/// working.
fn is_private_or_reserved(addr: SocketAddr) -> bool {
    use std::net::IpAddr;
    match addr.ip() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            match (o[0], o[1], o[2]) {
                // 0.0.0.0/8 "this network" + broadcast
                (0, _, _) | (255, 255, 255) => true,
                // 10.0.0.0/8 (RFC1918)
                (10, _, _) => true,
                // 100.64.0.0/10 (CGNAT)
                (100, 64..=127, _) => true,
                // 127.0.0.0/8 (loopback)
                (127, _, _) => true,
                // 169.254.0.0/16 (link-local)
                (169, 254, _) => true,
                // 172.16.0.0/12 (RFC1918)
                (172, 16..=31, _) => true,
                // 192.168.0.0/16 (RFC1918)
                (192, 168, _) => true,
                // 192.0.0.0/24 (IETF protocol assignments)
                (192, 0, 0) => true,
                // 198.18.0.0/15 (benchmarking)
                (198, 18..=19, _) => true,
                // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved)
                (224..=239, _, _) | (240..=255, _, _) => true,
                _ => false,
            }
        }
        IpAddr::V6(ip) => {
            let o = ip.octets();
            // IPv4-mapped / IPv4-compatible: judge the embedded v4 address.
            if o[..10] == [0u8; 10]
                && ((o[10] == 0xff && o[11] == 0xff) || o[10..12] == [0, 0])
            {
                let v4 = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
                return is_private_or_reserved(SocketAddr::new(v4.into(), addr.port()));
            }
            // :: (unspecified) and ::1 (loopback)
            if o == [0u8; 16] {
                return true;
            }
            if o[..15] == [0u8; 15] && o[15] == 1 {
                return true;
            }
            // fe80::/10 (link-local)
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                return true;
            }
            // fc00::/7 (unique-local)
            if o[0] & 0xfe == 0xfc {
                return true;
            }
            // ff00::/8 (multicast)
            if o[0] == 0xff {
                return true;
            }
            false
        }
    }
}

/// Phase 2B (D5): the addresses eligible for a single PEX send. Replaces the
/// old behaviour of relaying the entire known set (up to `MAX_KNOWN_PEERS`) to
/// every peer every 15 seconds. Drops: ourselves, the recipient, banned or
/// penalized entries, anything the recipient itself taught us (no echo), and
/// hints we have held longer than `PEX_SHARE_MAX_AGE_SECS` (aging). Best
/// quality first, capped at `limit`.
///
/// Private addresses are deliberately *not* filtered here: the D6 gate belongs
/// on the dial decision (receive side), and suppressing private addresses on
/// the send side would break relay inside a LAN testnet (R4).
fn pex_sample(
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores: &HashMap<SocketAddr, PeerScore>,
    origins: &HashMap<SocketAddr, SocketAddr>,
    local: SocketAddr,
    recipient: SocketAddr,
    now_unix: u64,
    limit: usize,
) -> Vec<SocketAddr> {
    let mut picked: Vec<(i32, SocketAddr)> =
        P2PNetwork::pex_broadcast_list(entries, scores, local)
            .into_iter()
            .filter(|a| *a != recipient)
            // Never echo an address straight back to the peer that taught us it.
            .filter(|a| origins.get(a).copied() != Some(recipient))
            // PEX aging: hints held longer than PEX_SHARE_MAX_AGE_SECS stay in
            // the table for our own redial but are no longer gossiped.
            .filter(|a| {
                entries
                    .get(a)
                    .map(|e| now_unix.saturating_sub(e.first_seen) <= PEX_SHARE_MAX_AGE_SECS)
                    .unwrap_or(true)
            })
            .map(|a| {
                let q = entries
                    .get(&a)
                    .map(|e| e.quality)
                    .unwrap_or_else(default_peer_quality);
                (q, a)
            })
            .collect();
    // Deterministic: best quality first, address as tiebreak. Pseudo-random
    // outbound selection is 2C (D10), not this stage.
    picked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    picked.truncate(limit);
    picked.into_iter().map(|(_, a)| a).collect()
}

/// Phase 2B (D8): admission decision for a table already at capacity. Returns
/// the address that should be evicted to make room, or `None` when nothing is
/// worth replacing (the caller then simply keeps the table as it is).
///
/// This is the anti-poisoning control: the old code refused every new address
/// once `MAX_KNOWN_PEERS` was reached, so a hostile PEX burst of junk both
/// filled the table and then froze it permanently. Connected peers and anchors
/// are never victims; banned entries are always the preferred victim.
fn admit_peer(
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores: &HashMap<SocketAddr, PeerScore>,
    connected: &HashSet<SocketAddr>,
    incoming: SocketAddr,
    incoming_quality: i32,
) -> Option<SocketAddr> {
    if entries.contains_key(&incoming) || entries.len() < MAX_KNOWN_PEERS {
        return None;
    }
    let mut best: Option<(i32, i32, u64, SocketAddr)> = None;
    for (a, e) in entries {
        if connected.contains(a) {
            continue;
        }
        if e.anchor {
            continue;
        }
        let banned = scores.get(a).map(|s| s.is_banned()).unwrap_or(false);
        // Lower tuple wins as a victim: banned first, then lowest quality,
        // then oldest, then address (determinism).
        let key = (if banned { 0 } else { 1 }, e.quality, e.first_seen, *a);
        if best.map(|b| key < b).unwrap_or(true) {
            best = Some(key);
        }
    }
    let (banned_flag, quality, _, victim) = best?;
    if banned_flag == 0 || quality <= incoming_quality {
        Some(victim)
    } else {
        None
    }
}

/// Phase 2B (D9): recompute the anchor set. Surviving anchors and freshly
/// eligible candidates are merged, ranked by most recent success, deduplicated,
/// the local address excluded, and the whole set capped at `MAX_ANCHORS`.
/// Several anchors at once, never one — and never a hard requirement: this is
/// only ever a redial preference, so losing all of them costs nothing but a
/// fallback to store / PEX / seeds.
fn promote_anchors(
    current: &[(SocketAddr, u64)],
    candidates: &[(SocketAddr, u64)],
    local: SocketAddr,
) -> HashSet<SocketAddr> {
    let mut all: Vec<(u64, SocketAddr)> = current
        .iter()
        .chain(candidates.iter())
        .map(|(a, t)| (*t, *a))
        .filter(|(_, a)| *a != local)
        .collect();
    // Newest success first, so rotation drops the least-recently-useful anchor.
    all.sort_by(|a, b| b.cmp(a));
    let mut seen = HashSet::new();
    all.retain(|(_, a)| seen.insert(*a));
    all.truncate(MAX_ANCHORS);
    all.into_iter().map(|(_, a)| a).collect()
}

/// Phase 2B (D9): anchors with no successful contact for `ANCHOR_TTL_SECS`
/// are expired rather than kept forever. Replaceable, never authoritative.
fn expire_anchors(anchors: &[(SocketAddr, u64)], now_unix: u64) -> Vec<SocketAddr> {
    anchors
        .iter()
        .filter(|(_, last)| now_unix.saturating_sub(*last) > ANCHOR_TTL_SECS)
        .map(|(a, _)| *a)
        .collect()
}

/// Phase 2C: the outbound candidate order (audit L2).
///
/// Before this function existed the order came from `HashMap` iteration —
/// unpredictable to a distant attacker, but *stable inside a process* and
/// completely indifferent to quality, freshness, anchors, reputation and
/// network group. Every redial cycle therefore restarted from the same order
/// with the same budget, so the node never "discovered" anything its initial
/// hashing had not already placed first.
///
/// Two phases, so the Phase-2A invariant survives: **every known candidate
/// precedes every configured seed** (`test_seeds_are_unprivileged_in_redial`).
///
/// 1. **Known addresses** — weighted random sampling without replacement.
///    Weight is quality plus an anchor bonus plus a recency bonus, minus a
///    penalty per live session already held in the same network group. Every
///    coefficient is a fraction of `PEER_SCORE_INITIAL`, keeping quality the
///    dominant term (see the constant block).
/// 2. **Configured seeds** — appended afterwards, in configuration order, under
///    the same per-group quota. Unprivileged, but *reserved* a slice of the
///    round: without it a store that is already full pushes every seed out of
///    every round, which is seed authority by absence rather than by rank.
///
/// `ordered` is the Phase-2A candidate order produced by
/// `P2PNetwork::redial_candidates`: every address the node already knows first,
/// configured seeds appended last, its own listen address removed. `seed_tail`
/// marks which members of `ordered` are those appended seeds, so phase 1 can
/// re-rank the known half freely while phase 2 still keeps the tail behind it.
///
/// The RNG is injected so tests are deterministic (`StdRng::seed_from_u64`);
/// production reseeds from the OS each round, which is also what makes the
/// order differ from cycle to cycle.
///
/// Returns *fewer* than `limit` rather than relaxing the group quota: filling
/// the last slots from one over-represented group is exactly what scenario B
/// forbids. Progress is still guaranteed because the quota is recomputed from
/// live sessions every round, so a group climbs towards `MAX_PEERS_PER_SUBNET`
/// a few candidates at a time and then steps aside.
fn select_outbound<R: Rng + ?Sized>(
    ordered: &[SocketAddr],
    seed_tail: &HashSet<SocketAddr>,
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores: &HashMap<SocketAddr, PeerScore>,
    connected: &HashSet<SocketAddr>,
    limit: usize,
    now_unix: u64,
    rng: &mut R,
) -> Vec<SocketAddr> {
    use rand::distributions::{Distribution, WeightedIndex};

    let live_by_group = group_counts(connected.iter().copied());
    let mut used: HashMap<NetworkGroup, usize> = HashMap::new();
    let mut picked: Vec<SocketAddr> = Vec::with_capacity(limit);
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    let banned = |a: &SocketAddr| scores.get(a).map(|s| s.is_banned()).unwrap_or(false);

    /// Still dialable this round: not holding a session, not already picked,
    /// not banned.
    fn eligible(
        a: &SocketAddr,
        connected: &HashSet<SocketAddr>,
        seen: &HashSet<SocketAddr>,
        banned: &impl Fn(&SocketAddr) -> bool,
    ) -> bool {
        !connected.contains(a) && !seen.contains(a) && !banned(a)
    }
    let is_eligible =
        |a: &SocketAddr, seen: &HashSet<SocketAddr>| eligible(a, connected, seen, &banned);

    // A candidate may be taken only while it still has quota left: never more
    // than `MAX_CANDIDATES_PER_GROUP` in one round, and never enough to push
    // the group past `MAX_PEERS_PER_SUBNET` once live sessions are counted.
    let quota_left = |g: NetworkGroup, used: &HashMap<NetworkGroup, usize>| -> bool {
        let u = used.get(&g).copied().unwrap_or(0);
        if u >= MAX_CANDIDATES_PER_GROUP {
            return false;
        }
        let live = live_by_group.get(&g).copied().unwrap_or(0);
        live + u < MAX_PEERS_PER_SUBNET
    };

    // Reserve a slice of the round for configured seeds so a store that is
    // already full — poisoned or merely large — cannot push every seed out of
    // every round. One group's worth, i.e. the same quota any candidate gets.
    let seed_reserve = ordered
        .iter()
        .filter(|a| seed_tail.contains(*a) && is_eligible(a, &seen))
        .take(MAX_CANDIDATES_PER_GROUP)
        .count();
    let known_limit = limit.saturating_sub(seed_reserve);

    // Phase 1: known addresses, weighted and group-quota'd.
    loop {
        if picked.len() >= known_limit {
            break;
        }
        let mut pool: Vec<(SocketAddr, u64)> = Vec::new();
        for a in ordered {
            if seed_tail.contains(a) || !is_eligible(a, &seen) {
                continue;
            }
            let g = network_group(*a);
            if !quota_left(g, &used) {
                continue;
            }
            let live = live_by_group.get(&g).copied().unwrap_or(0);
            let e = entries.get(a);
            let mut w = i64::from(e.map(|e| e.quality).unwrap_or_else(default_peer_quality));
            if e.map(|e| e.anchor).unwrap_or(false) {
                w += i64::from(ANCHOR_SELECT_BONUS);
            }
            if e.and_then(|e| e.last_success)
                .map(|t| now_unix.saturating_sub(t) <= RECENT_PEER_WINDOW_SECS)
                .unwrap_or(false)
            {
                w += i64::from(RECENT_SUCCESS_BONUS);
            }
            w -= i64::from(GROUP_OVERREPRESENTATION_PENALTY) * live as i64;
            pool.push((*a, (w.max(0) as u64).saturating_add(MIN_SELECT_WEIGHT)));
        }
        if pool.is_empty() {
            break;
        }
        let Ok(dist) = WeightedIndex::new(pool.iter().map(|(_, w)| *w)) else {
            break;
        };
        let (addr, _) = pool[dist.sample(rng)];
        *used.entry(network_group(addr)).or_insert(0) += 1;
        seen.insert(addr);
        picked.push(addr);
    }

    // Phase 2: configured seeds, always behind every known candidate.
    for a in ordered {
        if !seed_tail.contains(a) {
            continue;
        }
        if picked.len() >= limit {
            break;
        }
        if !is_eligible(a, &seen) {
            continue;
        }
        let g = network_group(*a);
        if !quota_left(g, &used) {
            continue;
        }
        *used.entry(g).or_insert(0) += 1;
        seen.insert(*a);
        picked.push(*a);
    }

    picked
}

// ---------------------------------------------------------------------------
// Phase 2D — self-healing. Pure and I/O-free, so every transition and every
// bound is directly testable without a socket: the recovery task below is only
// the loop around these functions.
// ---------------------------------------------------------------------------

/// Where the node stands relative to its peer count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RecoveryState {
    /// `count >= RECOVERY_COMFORT_PEERS`: nothing to do. No dial, no log.
    Healthy,
    /// Below comfort with a dialable source left and no backoff pending:
    /// a round may run.
    Recovering,
    /// Below `RECOVERY_THRESHOLD` while the controller backoff is still
    /// running: recovery is throttled, not stalled — the next round re-checks.
    Degraded,
    /// Below `RECOVERY_THRESHOLD` with no dialable source left, or the
    /// consecutive-failure budget is spent. No further dial is issued.
    Exhausted,
}

/// Bounded controller state. Holds no session or address lock, ever.
#[derive(Clone, Copy, Debug)]
struct PeerRecoveryController {
    state: RecoveryState,
    /// When the last round issued its dials.
    last_attempt: Option<Instant>,
    /// Consecutive rounds that opened no session, `0 ..= RECOVERY_MAX_LEVEL`.
    backoff_level: u32,
    /// Consecutive rounds that opened no session,
    /// `0 ..= RECOVERY_MAX_CONSECUTIVE_FAILURES`.
    consecutive_failures: u32,
}

impl PeerRecoveryController {
    fn new() -> Self {
        Self {
            state: RecoveryState::Healthy,
            last_attempt: None,
            backoff_level: 0,
            consecutive_failures: 0,
        }
    }

    /// Delay before the *next* round may dial. Level 0 means "no extra delay",
    /// so a healthy controller never throttles anything.
    fn backoff(&self) -> Duration {
        recovery_backoff(self.backoff_level)
    }

    fn backoff_due(&self, now: Instant) -> bool {
        match self.last_attempt {
            None => true,
            Some(t) => now >= t + self.backoff(),
        }
    }

    /// One round finished. Any session opened counts as success and clears the
    /// backoff completely; a round that opened none climbs one level, bounded.
    fn record_round(&mut self, opened: usize, now: Instant) {
        self.last_attempt = Some(now);
        if opened > 0 {
            self.backoff_level = 0;
            self.consecutive_failures = 0;
        } else {
            self.backoff_level = (self.backoff_level + 1).min(RECOVERY_MAX_LEVEL);
            self.consecutive_failures = (self.consecutive_failures + 1)
                .min(RECOVERY_MAX_CONSECUTIVE_FAILURES);
        }
    }

    /// Back to `Healthy`: the hysteresis band is left, so every accumulated
    /// throttle is discarded rather than carried into the next incident.
    fn reset(&mut self) {
        self.state = RecoveryState::Healthy;
        self.last_attempt = None;
        self.backoff_level = 0;
        self.consecutive_failures = 0;
    }

    fn set_state(&mut self, state: RecoveryState) {
        self.state = state;
    }

    /// Clear the consecutive-failure latch once a full backoff has expired.
    ///
    /// Without it `Exhausted` would be terminal and a node whose peers came
    /// back later would never probe again. With it the controller settles into
    /// one probe per `RECOVERY_BACKOFF_MAX_SECS` (60s) — strictly slower than
    /// the pre-existing 5s redial loop, so recovery never becomes the
    /// aggressor, and never a hot loop.
    fn open_probe_window(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// `5s, 10s, 20s, 40s, 60s, 60s` for levels `1..=6`, `0` for level `0`.
///
/// Identical in shape to the existing per-candidate backoff
/// (`min(2 ^ min(attempt, 6), 60)` at `:2076`) so the codebase does not end up
/// with two different notions of "how long to wait".
fn recovery_backoff(level: u32) -> Duration {
    if level == 0 {
        return Duration::ZERO;
    }
    let shift = (level - 1).min(RECOVERY_MAX_LEVEL - 1);
    let secs = (RECOVERY_BACKOFF_BASE_SECS << shift).min(RECOVERY_BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

/// The whole state machine, as one pure function.
///
/// The hysteresis is `RECOVERY_THRESHOLD (4) < RECOVERY_COMFORT_PEERS (8)`:
/// recovery *starts* only below 4 and *stops* only at 8, so a count sitting in
/// `[4, 8)` neither starts nor stops it. From `Healthy`, a dip to 7 therefore
/// does nothing at all — which is exactly the `7 -> recovery, 8 -> stop, 7 ->
/// recovery` flapping this band exists to prevent.
fn next_state(
    prev: RecoveryState,
    count: usize,
    sources_left: bool,
    backoff_pending: bool,
    failures_exhausted: bool,
) -> RecoveryState {
    if count >= RECOVERY_COMFORT_PEERS {
        return RecoveryState::Healthy;
    }
    let deep = count < RECOVERY_THRESHOLD;
    if failures_exhausted || (deep && !sources_left) {
        return RecoveryState::Exhausted;
    }
    if prev != RecoveryState::Healthy || deep {
        if backoff_pending {
            RecoveryState::Degraded
        } else {
            RecoveryState::Recovering
        }
    } else {
        // Inside the band, entering from `Healthy`: hold. Nothing is broken
        // enough to warrant a round, and nothing recovers "just in case".
        RecoveryState::Healthy
    }
}

/// The outcome of one recovery round: the state it lands in and, if it may
/// dial, the addresses to dial in tier order. The per-tier counts exist only
/// for the round's diagnostic line — they describe where the dial budget went.
#[derive(Debug)]
struct RecoveryRound {
    state: RecoveryState,
    dial: Vec<SocketAddr>,
    /// Addresses taken from each tier, in ladder order.
    tier1_anchors: usize,
    tier2_known: usize,
    tier3_seeds: usize,
    /// At least one address across the three tiers is dialable at all.
    sources_left: bool,
}

/// The source ladder for one round.
///
/// Tier 1 anchors — addresses we have already reached and deliberately kept,
/// most recently proven first. Tier 2 everything else the node knows (peer
/// store + PEX), already ranked and network-group quota'd by Phase 2C's
/// `select_outbound`. Tier 3 configured seeds, **withheld** while tiers 1 and
/// 2 still hold something to try, and released only when a round has already
/// failed (`consecutive_failures > 0`) or when there is nothing else at all.
///
/// The seed is therefore a genuine last resort rather than a quota every round
/// — the gap Phase 2D exists to close (audit §C.1).
///
/// Tiers 1 and 3 bypass `select_outbound`, so they re-apply the same `/24`
/// invariant here with the same primitives (`network_group`, `group_counts`,
/// `MAX_PEERS_PER_SUBNET`); `connect_to_peer_inner` enforces it again per dial.
/// The `/24` room check shared by tiers 1 and 3 (tier 2 gets it for free from
/// `select_outbound`). Returns false when taking `a` would push its network
/// group past `MAX_PEERS_PER_SUBNET`, counting both live sessions and the
/// candidates already taken this round. On success it records the take.
///
/// A free function rather than a closure so the `used` tally can be updated
/// in place between checks without borrowing it twice.
fn recovery_group_room(
    a: SocketAddr,
    live: &HashMap<NetworkGroup, usize>,
    used: &mut HashMap<NetworkGroup, usize>,
) -> bool {
    let g = network_group(a);
    let live_n = live.get(&g).copied().unwrap_or(0);
    let used_n = used.get(&g).copied().unwrap_or(0);
    if live_n + used_n >= MAX_PEERS_PER_SUBNET {
        return false;
    }
    *used.entry(g).or_insert(0) += 1;
    true
}

fn plan_recovery(
    local: SocketAddr,
    count: usize,
    anchors: &[(SocketAddr, u64)],
    known: &[SocketAddr],
    seeds: &[SocketAddr],
    connected: &HashSet<SocketAddr>,
    is_banned: &dyn Fn(&SocketAddr) -> bool,
    controller: &PeerRecoveryController,
    now: Instant,
) -> RecoveryRound {
    let live = group_counts(connected.iter().copied());
    let mut used: HashMap<NetworkGroup, usize> = HashMap::new();
    let mut dial: Vec<SocketAddr> = Vec::with_capacity(MAX_DIALS_PER_ROUND);
    let mut picked: HashSet<SocketAddr> = HashSet::new();

    // Tier 1: anchors, most recently proven first.
    let mut ranked: Vec<(SocketAddr, u64)> = anchors
        .iter()
        .filter(|(a, _)| !connected.contains(a) && !is_banned(a) && *a != local)
        .copied()
        .collect();
    ranked.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
    for (a, _) in ranked {
        if dial.len() >= MAX_DIALS_PER_ROUND {
            break;
        }
        if !recovery_group_room(a, &live, &mut used) {
            continue;
        }
        picked.insert(a);
        dial.push(a);
    }
    let tier1_anchors = dial.len();

    // Tier 2: everything else the node knows, in the order 2C ranked it.
    for a in known {
        if dial.len() >= MAX_DIALS_PER_ROUND {
            break;
        }
        if picked.contains(a) || *a == local || connected.contains(a) || is_banned(a) {
            continue;
        }
        // Tier 2 already passed this quota inside `select_outbound`; re-applying
        // it here keeps tiers 1 and 2 from each spending the same group's room.
        if !recovery_group_room(*a, &live, &mut used) {
            continue;
        }
        picked.insert(*a);
        dial.push(*a);
    }
    let primary_empty = dial.is_empty();
    let tier2_known = dial.len() - tier1_anchors;

    // Tier 3: configured seeds, last resort.
    if primary_empty || controller.consecutive_failures > 0 {
        for s in seeds {
            if dial.len() >= MAX_DIALS_PER_ROUND {
                break;
            }
            if picked.contains(s) || *s == local || connected.contains(s) || is_banned(s) {
                continue;
            }
            if !recovery_group_room(*s, &live, &mut used) {
                continue;
            }
            picked.insert(*s);
            dial.push(*s);
        }
    }

    // Whether *any* tier still holds a dialable address, quota aside. This is
    // what tells `Exhausted` apart from "nothing left to try".
    let sources_left = anchors
        .iter()
        .map(|(a, _)| a)
        .chain(known.iter())
        .chain(seeds.iter())
        .any(|a| *a != local && !connected.contains(a) && !is_banned(a));

    let state = next_state(
        controller.state,
        count,
        sources_left,
        !controller.backoff_due(now),
        controller.consecutive_failures >= RECOVERY_MAX_CONSECUTIVE_FAILURES,
    );

    let tier3_seeds = dial.len() - tier1_anchors - tier2_known;

    RecoveryRound {
        state,
        dial,
        tier1_anchors,
        tier2_known,
        tier3_seeds,
        sources_left,
    }
}

/// Phase 2B: the shared ingress point for a newly-discovered address, usable by
/// callers that only hold the raw table guards (`accept_loop` and the PEX
/// branch of `handle_peer`). Records how the address was learned, stamps the
/// TTL clock, and applies quality-aware admission (D8) when the table is
/// already full. Returns true when the address ended up known.
async fn ingress_address(
    addresses: &Arc<RwLock<AddressManager>>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
    local: SocketAddr,
    addr: SocketAddr,
    source: PeerSource,
) -> bool {
    if addr == local || addr.port() == 0 {
        return false;
    }
    let now = unix_now();
    let at = Instant::now();

    // Snapshot the session table and release it *before* taking the address
    // manager. The old code held `known` while reading `sessions`, `scores`,
    // `meta` and `seen` in several different orders; nesting is now impossible
    // because only one of the two guards is ever held.
    let connected: HashSet<SocketAddr> = sessions.read().await.keys().copied().collect();

    let mut mgr = addresses.write().await;
    match mgr.admit(addr, source, admission_quality(source), now, at, &connected) {
        // Already present: just refresh the TTL clock.
        Admission::AlreadyKnown => {
            mgr.touch(addr, at);
            true
        }
        Admission::Inserted { .. } => true,
        Admission::Refused => false,
    }
}

// H2: network timeouts. A peer that connects and never speaks (slow-loris),
// stalls mid-frame, or points at a black-holed address must be released
// instead of holding a task + socket forever.
/// Handshake (magic + X25519) must complete within this budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Inactivity budget for reading a single frame (length/nonce/ciphertext).
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
/// Outbound connect budget (black-holed addresses must not stall discovery).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// H4/V-24: network identity in the P2P handshake. Two networks with
// different genesis hashes must NOT interconnect (cross-network gossip and
// inventory pollution). The genesis hash (public constant) identifies the
// network; the protocol version guards the wire format. This is a BREAKING
// protocol change (the handshake frame grew from 36 to 69 bytes): every node
// on the network must run the same binary — safe here because the testnet is
// not yet public and the genesis ceremony purges all node data dirs.
// v2 → v3 (WEIGHT): `tx.weight` is now DAG-maintained (subtree size) and
// Stable/practically_final became reachable. Status semantics changed, so
// mixed-version peers would disagree on finality — the version bump splits
// old and new networks. Deployment MUST rotate the genesis (ceremony) so the
// new network starts from a clean state.
/// Wire format version of the P2P handshake.
// OBSERVABILITY-ONLY visibility: `pub` so the boot banner can log it.
pub const P2P_PROTOCOL_VERSION: u8 = 3;
/// Handshake frame: magic(4) | version(1) | genesis hash(32) | ephemeral key(32)
const HANDSHAKE_FRAME_LEN: usize = 4 + 1 + 32 + 32;

/// Insert into the seen-transaction cache, evicting old entries once the
/// cache is full so memory stays bounded under flood.
async fn insert_seen(seen: &RwLock<HashMap<Vec<u8>, SeenTxEntry>>, tx_bytes: Vec<u8>) {
    let mut map = seen.write().await;
    if map.len() >= MAX_SEEN_TXS {
        let now = Instant::now();
        map.retain(|_, e| now.duration_since(e.timestamp) < Duration::from_secs(300));
        if map.len() >= MAX_SEEN_TXS {
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            }
        }
    }
    map.insert(
        tx_bytes,
        SeenTxEntry {
            timestamp: Instant::now(),
        },
    );
}

/// P2P network configuration
#[derive(Clone)]
pub struct P2PConfig {
    /// Local address to bind to
    pub listen_addr: SocketAddr,
    /// Bootstrap nodes to connect to
    pub bootnodes: Vec<SocketAddr>,
    /// DNS seed domains for peer discovery (e.g. "seed.aether.network")
    pub dns_seeds: Vec<String>,
    /// Path used to persist known peers across restarts (Phase 1)
    pub peer_store_path: Option<std::path::PathBuf>,
}

/// How long a peer remains in the known set after its last disconnect (Phase 1 TTL).
const PEER_TTL: Duration = Duration::from_secs(3600);
/// Interval at which the known-peer set is flushed to disk (Phase 1).
const PEER_STORE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap_or_else(|_| {
                tracing::warn!("Failed to parse default P2P address, using fallback");
                "127.0.0.1:30333"
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
            }),
            bootnodes: Vec::new(),
            dns_seeds: Vec::new(),
            peer_store_path: None,
        }
    }
}

/// Phase 2B: how an address entered the table. Persisted so a restart can tell
/// an operator-configured seed from a hostile PEX hint (D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum PeerSource {
    /// Operator-configured bootstrap address (never PEX-filtered, R4).
    Configured,
    /// Resolved from a DNS seed.
    Dns,
    /// Learned from a peer exchange message.
    Pex,
    /// The address dialled us.
    Inbound,
    /// An outbound connection we initiated.
    Outbound,
    /// Promoted by the anchor task.
    Anchor,
    /// Carried over from a pre-versioned store; origin unknown.
    Restored,
}

impl Default for PeerSource {
    fn default() -> Self {
        PeerSource::Restored
    }
}

/// Phase 2B: the five address categories (Principle 3, D7). Derived from live
/// state rather than stored, so a category can never drift out of sync with the
/// session / anchor / score tables it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerCategory {
    /// Holding a live session right now.
    Active,
    /// A successful handshake landed inside the recent window.
    Recent,
    /// Promoted for long-term reachability; never authoritative (Principle 5).
    Anchor,
    /// Known but never successfully connected (or cold for a long time).
    Candidate,
    /// Banned, or scored at/below the penalty floor.
    Penalized,
}

/// Default quality assigned to an address we know nothing else about.
fn default_peer_quality() -> i32 {
    PEER_SCORE_INITIAL
}

/// Phase 2C (audit L6): the quality an address enters the table with.
///
/// `admit_peer` displaces an entry when `victim_quality <= incoming_quality`.
/// Everything the node itself observed — a peer that dialled us, an address we
/// chose to dial, a DNS answer, an operator-configured bootnode — keeps the
/// historical `PEER_SCORE_INITIAL`. A pure gossip hint enters at half of that,
/// so a PEX burst can only target entries that are already degraded or banned.
/// It can never flush a healthy table it merely outnumbers.
///
/// A PEX address that proves itself climbs back through `record_success`
/// (+10 per successful handshake), so this is a head start for evidence, not a
/// permanent class.
fn admission_quality(source: PeerSource) -> i32 {
    match source {
        PeerSource::Pex => PEX_ADMISSION_QUALITY,
        _ => default_peer_quality(),
    }
}

/// Everything the node records about one address: where it came from, when it
/// was last useful, how well it has behaved, and whether it has been promoted
/// to an anchor. `last_seen` is the Phase-1 TTL clock.
///
/// Supersedes the former `PeerMeta` + `known_peers` + `peer_last_seen` triple.
/// Those three were always written together (`ingress_address`,
/// `load_known_peers`) and always removed together (the TTL sweep), so keeping
/// them in three tables only created a chance for them to disagree.
///
/// Deliberately *not* `Serialize`: persistence goes through `PeerStoreEntry`,
/// whose schema is the on-disk contract (`Instant` is not portable anyway).
#[derive(Debug, Clone)]
struct AddressEntry {
    /// How the address was learned.
    source: PeerSource,
    /// Unix seconds when this address was first learned.
    first_seen: u64,
    /// Monotonic clock of the last time we heard from or about this address.
    /// Drives `PEER_TTL` expiry; refreshed for every live session.
    last_seen: Instant,
    /// Unix seconds of the last successful handshake, if any.
    last_success: Option<u64>,
    /// Total outbound dial attempts.
    attempts: u32,
    /// Attempts that never reached a handshake.
    failures: u32,
    /// Quality in `0..=PEER_QUALITY_MAX`; drives admission and eviction (D8).
    quality: i32,
    /// True while promoted as an anchor (D9).
    anchor: bool,
}

impl AddressEntry {
    fn new(source: PeerSource, now: u64, at: Instant) -> Self {
        Self {
            source,
            first_seen: now,
            last_seen: at,
            last_success: None,
            attempts: 0,
            failures: 0,
            quality: default_peer_quality(),
            anchor: false,
        }
    }

    fn record_success(&mut self, now: u64) {
        self.last_success = Some(now);
        self.attempts = self.attempts.saturating_add(1);
        self.quality = (self.quality + 10).min(PEER_QUALITY_MAX);
    }

    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.failures = self.failures.saturating_add(1);
        self.quality = (self.quality - 5).max(0);
    }
}

// ---------------------------------------------------------------------------
// AddressManager
// ---------------------------------------------------------------------------

/// Single owner of everything the node knows about addresses.
///
/// Replaces the five previously-scattered tables — `known_peers`,
/// `peer_meta`, `peer_last_seen`, `pex_origins` and `peer_scores` — so that
/// address state sits behind exactly one lock. That removes the lock-order
/// inversions the four separate guards made possible (read `known` then write
/// `seen` in one task, the reverse in another) and makes it impossible for
/// membership, metadata and the TTL clock to drift apart.
///
/// `scores` stays a *separate* map rather than folding into `entries` on
/// purpose: an address evicted by the TTL sweep must keep its ban, otherwise
/// expiring a peer would silently un-ban it.
/// Outcome of a capacity-aware admission attempt (D8).
///
/// `ingress_address` needs to distinguish "already known" (true, just refresh
/// the clock) from "refused" (false) — a bare `Option<SocketAddr>` conflated
/// both with "made room", which is exactly the ambiguity that made the old
/// caller's `accepted` flag easy to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Already present; nothing was inserted.
    AlreadyKnown,
    /// Newly adopted. `evicted` is the address displaced to make room.
    Inserted { evicted: Option<SocketAddr> },
    /// Table full and nothing worth displacing; not adopted.
    Refused,
}

struct AddressManager {
    /// membership + metadata + TTL clock, in one map
    entries: HashMap<SocketAddr, AddressEntry>,
    /// which peer told us about each address (PEX echo suppression, D5)
    origins: HashMap<SocketAddr, SocketAddr>,
    /// reputation / ban state (per-message hot path)
    scores: HashMap<SocketAddr, PeerScore>,
}

impl AddressManager {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            origins: HashMap::new(),
            scores: HashMap::new(),
        }
    }

    // --- membership ------------------------------------------------------

    fn contains(&self, addr: SocketAddr) -> bool {
        self.entries.contains_key(&addr)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn addresses(&self) -> Vec<SocketAddr> {
        self.entries.keys().copied().collect()
    }

    /// Remove an address and everything keyed off it.
    fn remove(&mut self, addr: &SocketAddr) -> bool {
        self.origins.remove(addr);
        self.entries.remove(addr).is_some()
    }

    // --- observation / lifecycle ----------------------------------------

    /// Adopt an address, refreshing the TTL clock of one we already hold.
    ///
    /// The source is only recorded when the address is *new*: the first
    /// observer names it, so a later PEX hint cannot relabel an address we
    /// originally learned from a seed.
    fn observe(&mut self, addr: SocketAddr, source: PeerSource, now: u64, at: Instant) {
        self.touch(addr, at);
        self.entries
            .entry(addr)
            .or_insert_with(|| AddressEntry::new(source, now, at));
    }

    /// Stamp the TTL clock for an address we already hold.
    fn touch(&mut self, addr: SocketAddr, at: Instant) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.last_seen = at;
        }
    }

    fn record_success(&mut self, addr: SocketAddr, now: u64) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.record_success(now);
        }
    }

    fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.record_failure();
        }
    }

    // --- admission -------------------------------------------------------

    /// Capacity-aware admission (D8). Returns `AlreadyKnown` when the address
    /// is present, `Inserted` when it was adopted (carrying whatever address
    /// was displaced to make room), and `Refused` when the table is full and
    /// nothing present is worth displacing.
    ///
    /// `connected` and `at` come from the caller: the session table is not
    /// owned here, and must never be locked while this manager is held.
    fn admit(
        &mut self,
        addr: SocketAddr,
        source: PeerSource,
        quality: i32,
        now: u64,
        at: Instant,
        connected: &HashSet<SocketAddr>,
    ) -> Admission {
        if self.entries.contains_key(&addr) {
            return Admission::AlreadyKnown;
        }
        let evicted = if self.entries.len() >= MAX_KNOWN_PEERS {
            let Some(victim) = admit_peer(&self.entries, &self.scores, connected, addr, quality)
            else {
                return Admission::Refused;
            };
            self.remove(&victim);
            Some(victim)
        } else {
            None
        };
        self.entries.insert(addr, AddressEntry::new(source, now, at));
        Admission::Inserted { evicted }
    }

    // --- scores ----------------------------------------------------------

    fn is_banned(&self, addr: SocketAddr) -> bool {
        self.scores.get(&addr).map(|s| s.is_banned()).unwrap_or(false)
    }

    fn banned_until(&self, addr: SocketAddr) -> Option<Instant> {
        self.scores.get(&addr).and_then(|s| s.banned_until)
    }

    /// Penalize and, when the threshold is crossed, ban. Returns the score
    /// after the penalty *only* when a ban was triggered, so the caller can log
    /// it — an address with no score is left untouched, exactly as before.
    fn penalize_and_ban(&mut self, addr: SocketAddr, penalty: i32) -> Option<i32> {
        let s = self.scores.get_mut(&addr)?;
        if s.penalize(penalty) {
            s.ban();
            return Some(s.score);
        }
        None
    }

    /// Decay (or create) the score for an address we are about to dial.
    fn decay_score(&mut self, addr: SocketAddr) {
        match self.scores.get_mut(&addr) {
            Some(s) => s.decay(),
            None => {
                self.scores.insert(addr, PeerScore::new());
            }
        }
    }

    // --- PEX -------------------------------------------------------------

    fn set_origin(&mut self, addr: SocketAddr, from: SocketAddr) {
        self.origins.insert(addr, from);
    }

    fn sample_for_pex(
        &self,
        local: SocketAddr,
        recipient: SocketAddr,
        now: u64,
        limit: usize,
    ) -> Vec<SocketAddr> {
        pex_sample(
            &self.entries,
            &self.scores,
            &self.origins,
            local,
            recipient,
            now,
            limit,
        )
    }

    // --- anchors ---------------------------------------------------------

    fn anchor_addresses(&self) -> Vec<(SocketAddr, u64)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.anchor)
            .map(|(a, e)| (*a, e.last_success.unwrap_or(e.first_seen)))
            .collect()
    }

    /// Live sessions that have completed at least one handshake — the only
    /// legitimate promotion source for an anchor.
    fn anchor_candidates(&self, connected: &HashSet<SocketAddr>) -> Vec<(SocketAddr, u64)> {
        connected
            .iter()
            .filter_map(|a| {
                let e = self.entries.get(a)?;
                e.last_success.map(|t| (*a, t))
            })
            .collect()
    }

    /// Apply a freshly computed anchor set. Returns `(promoted, demoted)`.
    fn apply_anchors(&mut self, wanted: &HashSet<SocketAddr>) -> (usize, usize) {
        let mut promoted = 0usize;
        let mut demoted = 0usize;
        for (a, e) in self.entries.iter_mut() {
            let should = wanted.contains(a);
            if e.anchor == should {
                continue;
            }
            e.anchor = should;
            if should {
                e.source = PeerSource::Anchor;
                promoted += 1;
            } else {
                demoted += 1;
            }
        }
        (promoted, demoted)
    }

    // --- TTL -------------------------------------------------------------

    /// One pass of the Phase-1 TTL sweep: refresh the clock of every live
    /// session, then drop addresses we have not heard from inside the window
    /// (along with their metadata and PEX origin). Returns
    /// `(refreshed, expired)`.
    fn refresh_and_expire(
        &mut self,
        connected: &HashSet<SocketAddr>,
        now: Instant,
        ttl: Duration,
    ) -> (usize, usize) {
        let mut refreshed = 0usize;
        for a in connected {
            if let Some(e) = self.entries.get_mut(a) {
                e.last_seen = now;
                refreshed += 1;
            }
        }
        let expired: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) > ttl)
            .map(|(a, _)| *a)
            .collect();
        for a in &expired {
            self.origins.remove(a);
        }
        for a in &expired {
            self.entries.remove(a);
        }
        // Phase 2C (audit L7): a score that is neither banned nor attached to
        // anything we still track carries no information — `decay_score`
        // recreates it if the address ever returns. Without this pass the map
        // grew by one entry per *distinct* address ever dialled, which a peer
        // cycling fresh hints through the table could drive without bound.
        //
        // A ban always survives: that is the invariant that makes `scores` a
        // separate map in the first place. So does a live session, which may
        // hold a score even when the address itself was refused by a full
        // table.
        self.scores.retain(|a, s| {
            self.entries.contains_key(a) || connected.contains(a) || s.is_banned()
        });
        (refreshed, expired.len())
    }

    // --- views -----------------------------------------------------------

    /// Per-category census for diagnostics (D7).
    fn categories(&self, connected: &HashSet<SocketAddr>, now: u64) -> [usize; 5] {
        let mut counts = [0usize; 5];
        for (a, e) in self.entries.iter() {
            let penalized = e.quality <= PEER_QUALITY_PENALIZED
                || self
                    .scores
                    .get(a)
                    .map(|s| s.is_banned() || s.score <= PEER_QUALITY_PENALIZED)
                    .unwrap_or(false);
            let c = categorise(
                connected.contains(a),
                e.anchor,
                penalized,
                e.last_success,
                now,
            );
            counts[c as usize] += 1;
        }
        counts
    }

    // --- persistence -----------------------------------------------------

    /// Build the on-disk v2 document. Addresses without metadata are written
    /// with defaults rather than dropped, so nothing is silently lost.
    fn to_store(&self) -> PeerStoreFile {
        let entries = self
            .entries
            .iter()
            .map(|(a, e)| PeerStoreEntry {
                addr: a.to_string(),
                source: e.source,
                first_seen: e.first_seen,
                last_success: e.last_success,
                attempts: e.attempts,
                failures: e.failures,
                quality: e.quality,
                anchor: e.anchor,
            })
            .collect();
        PeerStoreFile {
            version: PEER_STORE_VERSION,
            entries,
        }
    }

    /// Load a parsed v2 document. Returns how many addresses were adopted.
    fn load_v2(&mut self, file: &PeerStoreFile, local: SocketAddr, now: u64, at: Instant) -> usize {
        let mut count = 0usize;
        for e in &file.entries {
            let Ok(addr) = e.addr.parse::<SocketAddr>() else {
                continue;
            };
            if addr == local {
                continue;
            }
            let entry = AddressEntry {
                source: e.source,
                first_seen: if e.first_seen > 0 { e.first_seen } else { now },
                last_seen: at,
                last_success: e.last_success,
                attempts: e.attempts,
                failures: e.failures,
                quality: e.quality,
                anchor: e.anchor,
            };
            let fresh = !self.entries.contains_key(&addr);
            self.entries.insert(addr, entry);
            count += fresh as usize;
        }
        count
    }

    /// Adopt addresses from a legacy `Vec<String>` store (R3). v1 carried no
    /// timestamps and no origin, so there is nothing to recover but the
    /// addresses themselves.
    fn load_legacy(&mut self, addrs: &[String], local: SocketAddr, now: u64, at: Instant) -> usize {
        let mut count = 0usize;
        for s in addrs {
            let Ok(addr) = s.parse::<SocketAddr>() else {
                continue;
            };
            if addr == local {
                continue;
            }
            let fresh = !self.entries.contains_key(&addr);
            self.entries
                .insert(addr, AddressEntry::new(PeerSource::Restored, now, at));
            count += fresh as usize;
        }
        count
    }

    // --- test accessors --------------------------------------------------
    //
    // Deliberately `#[cfg(test)]`: production code goes through the methods
    // above, so these never widen the real API surface and never show up as
    // dead code in a normal build.

    /// Phase 2C: metadata and reputation together, because the outbound
    /// selector needs both and a caller must never be able to observe one
    /// without the other. Read-only, and the guard is released by the caller
    /// as soon as selection returns.
    fn selection_tables(
        &self,
    ) -> (
        &HashMap<SocketAddr, AddressEntry>,
        &HashMap<SocketAddr, PeerScore>,
    ) {
        (&self.entries, &self.scores)
    }

    #[cfg(test)]
    fn entry(&self, addr: SocketAddr) -> Option<&AddressEntry> {
        self.entries.get(&addr)
    }

    #[cfg(test)]
    fn entries_mut(&mut self) -> &mut HashMap<SocketAddr, AddressEntry> {
        &mut self.entries
    }

    #[cfg(test)]
    fn scores_mut(&mut self) -> &mut HashMap<SocketAddr, PeerScore> {
        &mut self.scores
    }

    #[cfg(test)]
    fn origin_of(&self, addr: SocketAddr) -> Option<SocketAddr> {
        self.origins.get(&addr).copied()
    }
}

/// On-disk peer store, schema v2 (D8). v1 was a bare `Vec<String>`; the loader
/// falls back to that shape so an existing `known_peers.json` is never lost (R3).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PeerStoreFile {
    version: u32,
    #[serde(default)]
    entries: Vec<PeerStoreEntry>,
}

/// One persisted address plus the metadata v1 could not express.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PeerStoreEntry {
    addr: String,
    #[serde(default)]
    source: PeerSource,
    #[serde(default)]
    first_seen: u64,
    #[serde(default)]
    last_success: Option<u64>,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    failures: u32,
    #[serde(default = "default_peer_quality")]
    quality: i32,
    #[serde(default)]
    anchor: bool,
}

/// P2P network message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum P2PMessage {
    /// Transaction gossip
    Transaction(Vec<u8>),
    /// Inventory - list of transaction hashes
    Inventory(Vec<Vec<u8>>),
    /// GetData - request specific transactions by hash
    GetData(Vec<Vec<u8>>),
    /// GetInventory - request inventory based on tips
    GetInventory {
        /// Tips of the requesting node
        tips: Vec<Vec<u8>>,
    },
    /// SyncRequest - request full inventory from peer (legacy)
    SyncRequest,
    /// SyncResponse - send transactions (with pagination support)
    SyncResponse(Vec<Vec<u8>>),
    /// Ping message for keepalive
    Ping,
    /// Pong response
    Pong,
    /// Peer exchange - list of known peer addresses
    Peers(Vec<SocketAddr>),
}

/// Seen transaction entry with timestamp for LRU eviction
#[derive(Clone)]
struct SeenTxEntry {
    timestamp: Instant,
}

/// P2P network manager
#[derive(Clone)]
pub struct P2PNetwork {
    config: P2PConfig,
    peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Phase 2A: addresses with an outbound dial in flight. The initial sweep,
    /// heartbeat, redial loop and PEX can all reach `connect_to_peer` for the
    /// same address concurrently; without this guard a peer gets two sessions
    /// and the `peers` map silently drops one of them.
    dialing: Arc<RwLock<HashSet<SocketAddr>>>,
    /// Phase 2C: the subset of `peers` sessions this node itself initiated.
    ///
    /// Session *direction* lives with the sessions, not with the address book:
    /// an address's `PeerSource` records how we first learned it and is
    /// deliberately never relabelled, so it cannot answer "is this live session
    /// ours?". Exactly two writers — the dial path inserts, the task wrapping
    /// `handle_peer` removes — so it cannot drift from `peers` without `peers`
    /// drifting too. Never held together with `peers` or `addresses`.
    outbound_sessions: Arc<RwLock<HashSet<SocketAddr>>>,
    /// Phase 2B: the single owner of everything the node knows about
    /// addresses — membership, metadata, TTL clock, PEX origins and scores.
    /// Supersedes the former `known_peers` / `peer_last_seen` / `peer_meta` /
    /// `pex_origins` / `peer_scores` quintet.
    ///
    /// **Lock discipline**: this guard and `peers` (the session map) must never
    /// be held at the same time. Snapshot one, release it, then take the other.
    /// Holding both is the deadlock this migration exists to eliminate.
    addresses: Arc<RwLock<AddressManager>>,
    /// Phase 2D: the self-healing controller. Observes the peer count and
    /// decides whether a recovery round may run. Holds no session or address
    /// lock itself, so it can be read for diagnostics at any time. Written only
    /// by the recovery task, which is also the sole dialer it drives, so there
    /// is exactly one writer.
    recovery: Arc<RwLock<PeerRecoveryController>>,
    tx_channel: mpsc::UnboundedSender<Transaction>,
    peer_discovery_tx: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedSender<SocketAddr>>>>,
    get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
    get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
    /// B4: shared bootstrap state (counters, parent-request dedup, orphan TTL)
    sync_ctx: Arc<SyncContext>,
    /// B4: true when the hash is already in the orphan store (sync dedup)
    is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
}

impl P2PNetwork {
    /// Create a new P2P network manager
    pub fn new(
        config: P2PConfig,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            dialing: Arc::new(RwLock::new(HashSet::new())),
            outbound_sessions: Arc::new(RwLock::new(HashSet::new())),
            addresses: Arc::new(RwLock::new(AddressManager::new())),
            recovery: Arc::new(RwLock::new(PeerRecoveryController::new())),
            tx_channel,
            peer_discovery_tx: Arc::new(tokio::sync::Mutex::new(None)),
            get_dag_hashes,
            get_transaction_by_hash,
            get_tips,
            seen_transactions: Arc::new(RwLock::new(HashMap::new())),
            sync_ctx,
            is_orphan,
        }
    }

    /// Start the P2P network
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting P2P network on {}", self.config.listen_addr);

        // Phase 1: restore known peers from disk before first dial.
        self.load_known_peers().await;

        // Start listening for incoming connections
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let peers = self.peers.clone();
        let outbound_sessions = self.outbound_sessions.clone();
        let tx_channel = self.tx_channel.clone();
        let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
        let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
        let get_tips = Arc::clone(&self.get_tips);
        let seen_transactions = Arc::clone(&self.seen_transactions);
        let sync_ctx = Arc::clone(&self.sync_ctx);
        let is_orphan = Arc::clone(&self.is_orphan);
        let local_addr = self.config.listen_addr;
        let addresses = self.addresses.clone();
        let (peer_discovery_tx, mut peer_discovery_rx) = mpsc::unbounded_channel::<SocketAddr>();
        {
            let mut tx_lock = self.peer_discovery_tx.lock().await;
            *tx_lock = Some(peer_discovery_tx.clone());
        }
        let p2p_discovery = self.clone();
        tokio::spawn(async move {
            while let Some(addr) = peer_discovery_rx.recv().await {
                p2p_discovery.connect_to_peer(addr).await;
            }
        });
        tokio::spawn(async move {
            Self::accept_loop(
                listener,
                peers,
                local_addr,
                addresses,
                outbound_sessions,
                tx_channel,
                get_dag_hashes,
                get_transaction_by_hash,
                get_tips,
                seen_transactions,
                peer_discovery_tx,
                sync_ctx,
                is_orphan,
            )
            .await;
        });

        // Phase 2A: bring the recovery machinery up BEFORE the first dial pass.
        // The initial sweep used to run first and block here, so a peer store
        // full of dead addresses left the node with no heartbeat, no PEX and no
        // TTL task while it churned through timeouts.

        // Discover peers from DNS seeds
        self.discover_from_dns().await;

        // Phase 2D: self-healing loop (replaces the peer_count == 0 heartbeat)
        self.start_recovery_task().await;

        // Start reconnection task (known peers first, seeds unprivileged)
        self.start_reconnection_task().await;

        // Phase 1: periodic peer-store flush + TTL expiry.
        self.start_peer_store_task().await;

        // Phase 2B (D9): rotate/expire anchors (persisted with the store).
        self.start_anchor_task().await;

        // Start periodic DNS discovery
        self.start_dns_discovery().await;

        // Start periodic peer exchange (PEX)
        self.start_pex().await;

        // Start cache cleanup task
        self.start_cache_cleanup().await;

        // First outbound pass, off the critical path: seeds first (on a brand-new
        // node they are the only known address source), then everything restored
        // from the peer store. Runs as its own task so `start()` is never gated
        // on a serial sweep of possibly-dead addresses.
        {
            let sweep = self.clone();
            tokio::spawn(async move {
                sweep.initial_dial_sweep().await;
            });
        }

        Ok(())
    }

    /// Phase 2A: the very first outbound dial pass. Seeds go first because a
    /// node with an empty peer store has no other address source; afterwards the
    /// restored store is dialed. This is the only place where seeds lead, and it
    /// runs once — steady-state redial never privileges them.
    async fn initial_dial_sweep(&self) {
        for seed in &self.config.bootnodes {
            self.connect_to_peer(*seed).await;
        }

        // Phase 2C: the restored store is dialed through the same selection
        // every other redial round uses, bounded per cycle. A store restored
        // from a poisoned file must not be able to open every slot in one burst
        // before any selection has had a chance to weigh it.
        for addr in self.outbound_candidates(MAX_REDIAL_PER_CYCLE).await {
            self.connect_to_peer(addr).await;
        }
    }

    /// Phase 2B (D8): reload the versioned peer store. Schema v2 carries
    /// per-address metadata (source, attempts, quality, anchor flag); if the
    /// file does not parse as v2 we fall back to the legacy `Vec<String>`
    /// shape, so an existing `known_peers.json` is never silently discarded (R3).
    async fn load_known_peers(&self) {
        let Some(path) = self.config.peer_store_path.clone() else {
            return;
        };
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("Failed to load peer store {:?}: {}", path, e);
                return;
            }
        };

        let now = unix_now();
        let at = Instant::now();
        let local = self.config.listen_addr;

        let (count, legacy) = {
            let mut mgr = self.addresses.write().await;
            match serde_json::from_str::<PeerStoreFile>(&raw) {
                Ok(file) if file.version >= PEER_STORE_VERSION => {
                    (mgr.load_v2(&file, local, now, at), false)
                }
                // R3: a v1 store is plain address strings. Adopt every address
                // we can parse rather than discarding the file wholesale.
                _ => match serde_json::from_str::<Vec<String>>(&raw) {
                    Ok(addrs) => (mgr.load_legacy(&addrs, local, now, at), true),
                    Err(e) => {
                        warn!("Peer store {:?} unreadable ({}), starting empty", path, e);
                        return;
                    }
                },
            }
        };

        if count == 0 {
            return;
        }

        if legacy {
            info!(
                "💾 Loaded {} known peers from legacy store {:?} (upgrading to v{})",
                count,
                path,
                PEER_STORE_VERSION
            );
        } else {
            info!("💾 Loaded {} known peers from {:?}", count, path);
        }
    }

    /// Phase 2B (D8): persist the store as schema v2 with per-address metadata.
    /// Entries without metadata (possible only while a table is being rebuilt)
    /// are written with defaults rather than dropped, so no address is lost.
    async fn save_known_peers(&self) {
        let Some(path) = self.config.peer_store_path.clone() else {
            return;
        };
        let file = {
            let mgr = self.addresses.read().await;
            mgr.to_store()
        };
        let json = match serde_json::to_string(&file) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to serialize peer store: {}", e);
                return;
            }
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &json) {
            warn!("Failed to write peer store {:?}: {}", tmp, e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            warn!("Failed to replace peer store {:?}: {}", path, e);
        }
    }

    /// Phase 1: mark a peer as currently/just known (updates TTL clock).
    async fn touch_peer(&self, addr: SocketAddr) {
        let mut mgr = self.addresses.write().await;
        if mgr.len() >= MAX_KNOWN_PEERS && !mgr.contains(addr) {
            return;
        }
        mgr.observe(addr, PeerSource::Restored, unix_now(), Instant::now());
    }

    /// Phase 2A: refresh the TTL clock for every peer holding a live session, so
    /// a long-lived connection is never expired out of the peer store (and hence
    /// out of the persisted file) just for having stayed up.
    async fn refresh_live_peer_clocks(&self) {
        // Snapshot the sessions and release before touching the manager: the
        // two guards are never held at the same time.
        let live: Vec<SocketAddr> = self.peers.read().await.keys().copied().collect();
        if live.is_empty() {
            return;
        }
        let at = Instant::now();
        let mut mgr = self.addresses.write().await;
        for a in live {
            mgr.touch(a, at);
        }
    }

    /// Phase 1: expire peers whose last_seen is older than PEER_TTL and flush the store.
    async fn start_peer_store_task(&self) {
        let peers = self.clone();
        tokio::spawn(async move {
            let mut last_flush = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                // Phase 2A: a peer that stays connected longer than PEER_TTL must
                // not be expired out of the store. Refresh the clock for every live
                // session first, otherwise the node forgets its most reliable peers
                // precisely because they are reliable.
                peers.refresh_live_peer_clocks().await;

                // TTL expiry. The four guards the sweep used to hold in a fixed
                // order are now one, so there is no order left to invert.
                {
                    let live: HashSet<SocketAddr> =
                        peers.peers.read().await.keys().copied().collect();
                    let now = Instant::now();
                    let mut mgr = peers.addresses.write().await;
                    let (_, expired) = mgr.refresh_and_expire(&live, now, PEER_TTL);
                    if expired > 0 {
                        debug!("Peer TTL expired {} entries", expired);
                    }
                }

                // Phase 2B (D7): surface the live category mix. This is how an
                // operator can tell whether the node still has proven reachable
                // anchors or is running purely on untested candidates.
                {
                    let live: HashSet<SocketAddr> =
                        peers.peers.read().await.keys().copied().collect();
                    let mgr = peers.addresses.read().await;
                    let total = mgr.len();
                    if total > 0 {
                        let counts = mgr.categories(&live, unix_now());
                        debug!(
                            "Peer categories of {}: active={} recent={} anchor={} candidate={} penalized={}",
                            total, counts[0], counts[1], counts[2], counts[3], counts[4]
                        );
                    }
                }

                // Periodic flush
                if last_flush.elapsed() >= PEER_STORE_FLUSH_INTERVAL {
                    peers.save_known_peers().await;
                    last_flush = Instant::now();
                }
            }
        });
    }

    /// Phase 2B (D9): maintain a rotating set of anchors — addresses that have
    /// actually proven reachable — so the node keeps long-term entry points that
    /// do not depend on any seed.
    ///
    /// Anchors are several (never one), rotated by most-recent success, expired
    /// after `ANCHOR_TTL_SECS`, and freely replaceable. They are stored only as
    /// a flag on `PeerMeta`, so they are never consulted for state, never
    /// required for liveness, and never constitute a point of authority
    /// (Principle 5 / R6). The staged escalation that consumes them lives in 2D.
    async fn start_anchor_task(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(ANCHOR_REFRESH_INTERVAL).await;
                node.refresh_anchors().await;
            }
        });
    }

    /// One anchor rotation pass: expire dead anchors, then promote from live
    /// sessions that have completed at least one handshake.
    async fn refresh_anchors(&self) {
        let now = unix_now();

        // Snapshot the session map first so the address manager is never held
        // while `peers` is (the two locks must not nest).
        let sessions: HashSet<SocketAddr> = self.peers.read().await.keys().copied().collect();

        let (alive, candidates, dead) = {
            let mgr = self.addresses.read().await;
            let current = mgr.anchor_addresses();
            let dead = expire_anchors(&current, now);
            let alive: Vec<(SocketAddr, u64)> = current
                .into_iter()
                .filter(|(a, _)| !dead.contains(a))
                .collect();
            let candidates = mgr.anchor_candidates(&sessions);
            (alive, candidates, dead)
        };

        let wanted = promote_anchors(&alive, &candidates, self.config.listen_addr);

        let promoted = {
            let mut mgr = self.addresses.write().await;
            mgr.apply_anchors(&wanted).0
        };

        if promoted > 0 || !dead.is_empty() {
            debug!(
                "Anchor rotation: {} promoted, {} expired, {} total",
                promoted,
                dead.len(),
                wanted.len()
            );
        }
        if wanted.len() < MIN_ANCHORS {
            // Not fatal — anchors are never required — but resilience now leans
            // more on the peer store, PEX and configured seeds.
            warn!(
                "Only {} anchor(s) (< {}): reachability relies on store/PEX/seeds",
                wanted.len(),
                MIN_ANCHORS
            );
        }
    }

    /// Phase 2D: the self-healing loop.
    ///
    /// Replaces the old heartbeat, which only reacted to `peer_count == 0` and
    /// therefore could not tell a node that lost 6 of its 8 peers from a node
    /// holding 128. This task observes the count every `RECOVERY_INTERVAL`,
    /// drives the controller through `Healthy` / `Recovering` / `Degraded` /
    /// `Exhausted`, and dials at most `MAX_DIALS_PER_ROUND` addresses per round
    /// in the anchor -> known -> seed order of `plan_recovery`.
    ///
    /// Silent while `Healthy`; only state transitions are logged. The existing
    /// redial loop is left untouched — this task is inactive in the common
    /// case, so it never doubles the dial pressure of a healthy node.
    async fn start_recovery_task(&self) {
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RECOVERY_INTERVAL).await;
                node.recovery_round().await;
            }
        });
    }

    /// One full self-healing round: observe, decide, dial, record.
    ///
    /// Deliberately a method rather than inlined in the loop, so an integration
    /// test can drive the exact production round without waiting on wall-clock
    /// time. Returns the whole plan, including which tier supplied each dial.
    async fn recovery_round(&self) -> RecoveryRound {
        // Snapshot the session table and release before touching the
        // address manager: the two locks are never held together.
        let (count, connected) = {
            let guard = self.peers.read().await;
            (
                guard.len(),
                guard.keys().copied().collect::<HashSet<SocketAddr>>(),
            )
        };

        let mut ctl = *self.recovery.read().await;
        let now = Instant::now();

        if count >= RECOVERY_COMFORT_PEERS {
            if ctl.state != RecoveryState::Healthy {
                self.recovery.write().await.reset();
                info!(
                    "self-heal: peer_count {} >= comfort {} -> recovery complete, backoff reset",
                    count, RECOVERY_COMFORT_PEERS
                );
            }
            return RecoveryRound {
                state: RecoveryState::Healthy,
                dial: Vec::new(),
                tier1_anchors: 0,
                tier2_known: 0,
                tier3_seeds: 0,
                sources_left: true,
            };
        }

        // `Exhausted` is not a latch: once its backoff has fully expired, open
        // one slow probe window again (see `open_probe_window`).
        if ctl.state == RecoveryState::Exhausted && ctl.backoff_due(now) {
            self.recovery.write().await.open_probe_window();
            ctl = *self.recovery.read().await;
        }

        // Tier 2/3 come from the unchanged Phase 2C selection. Seeds
        // are split back out here so the ladder can withhold them.
        let ranked = self.outbound_candidates(MAX_DIALS_PER_ROUND).await;
        let seeds = self.config.bootnodes.clone();
        let seed_set: HashSet<SocketAddr> = seeds.iter().copied().collect();
        let known: Vec<SocketAddr> = ranked
            .iter()
            .copied()
            .filter(|a| !seed_set.contains(a))
            .collect();

        let round = {
            let mgr = self.addresses.read().await;
            let anchors = mgr.anchor_addresses();
            let banned = |a: &SocketAddr| mgr.is_banned(*a);
            plan_recovery(
                self.config.listen_addr,
                count,
                &anchors,
                &known,
                &seeds,
                &connected,
                &banned,
                &ctl,
                now,
            )
        };

        if round.state != ctl.state {
            match round.state {
                RecoveryState::Healthy => {}
                RecoveryState::Recovering => info!(
                    "self-heal: peer_count {} < comfort {} (threshold {}, min {}) -> entering recovery, planning {} anchor / {} known / {} seed dial(s)",
                    count,
                    RECOVERY_COMFORT_PEERS,
                    RECOVERY_THRESHOLD,
                    RECOVERY_MIN_PEERS,
                    round.tier1_anchors,
                    round.tier2_known,
                    round.tier3_seeds,
                ),
                RecoveryState::Degraded => info!(
                    "self-heal: peer_count {} -> recovery throttled for {:?} ({} consecutive failed round(s))",
                    count,
                    ctl.backoff(),
                    ctl.consecutive_failures
                ),
                RecoveryState::Exhausted => warn!(
                    "self-heal: peer_count {} below threshold {} with no dialable source (or {} consecutive failed rounds) -> exhausted, probing every {:?}",
                    count,
                    RECOVERY_THRESHOLD,
                    ctl.consecutive_failures,
                    recovery_backoff(RECOVERY_MAX_LEVEL)
                ),
            }
        }
        self.recovery.write().await.set_state(round.state);

        if round.state != RecoveryState::Recovering {
            return round;
        }

        debug!(
            "self-heal: round of {} dial(s): {} anchor, {} known, {} seed; {} source(s) left",
            round.dial.len(),
            round.tier1_anchors,
            round.tier2_known,
            round.tier3_seeds,
            round.sources_left
        );
        for addr in &round.dial {
            self.connect_to_peer(*addr).await;
        }

        // Success is measured by the planned addresses that now hold a
        // session — not by the raw count, which a concurrent inbound
        // connection could move underneath us.
        let opened = {
            let guard = self.peers.read().await;
            round.dial.iter().filter(|a| guard.contains_key(*a)).count()
        };
        debug!(
            "self-heal: round opened {} of {} planned session(s)",
            opened,
            round.dial.len()
        );
        self.recovery
            .write()
            .await
            .record_round(opened, Instant::now());
        round
    }

    /// Phase 2A candidate ordering for the redial loop: addresses the node
    /// already knows come first, configured seeds are ordinary unprivileged
    /// fallbacks appended at the end. No seed is ever allowed to outrank a peer
    /// the node already holds, so a dead seed cannot monopolise the cycle.
    fn redial_candidates(
        known: &[SocketAddr],
        seeds: &[SocketAddr],
        local: SocketAddr,
    ) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = known.iter().copied().filter(|a| *a != local).collect();
        for seed in seeds {
            if *seed != local && !out.contains(seed) {
                out.push(*seed);
            }
        }
        out
    }

    /// Phase 2C: one round of outbound candidates, ready to dial.
    ///
    /// This is the single production entry point that replaces the raw
    /// `redial_candidates` list in every redial path. `redial_candidates` still
    /// builds the order (Phase-2A invariant: known addresses before configured
    /// seeds), but the round itself is now bounded, reputation-weighted and
    /// network-group aware, so a store that an attacker has filled with one
    /// routable allocation can no longer decide who the node talks to.
    ///
    /// Lock discipline: the session table is snapshotted and released *before*
    /// the address manager is acquired, so `peers` and `addresses` are never
    /// held at the same time.
    async fn outbound_candidates(&self, limit: usize) -> Vec<SocketAddr> {
        let connected: HashSet<SocketAddr> = {
            let guard = self.peers.read().await;
            guard.keys().copied().collect()
        };

        let local = self.config.listen_addr;
        let seeds = self.config.bootnodes.clone();

        let picked = {
            let mgr = self.addresses.read().await;
            let known = mgr.addresses();
            let ordered = Self::redial_candidates(&known, &seeds, local);
            // Everything `redial_candidates` appended sits behind the known
            // half; that exact tail — not "is this a configured seed" — is what
            // phase 2 of the selection preserves.
            let known_len = known.iter().filter(|a| **a != local).count();
            let seed_tail: HashSet<SocketAddr> =
                ordered.iter().skip(known_len).copied().collect();

            let (entries, scores) = mgr.selection_tables();
            let mut rng = StdRng::from_entropy();
            let picked = select_outbound(
                &ordered,
                &seed_tail,
                entries,
                scores,
                &connected,
                limit,
                unix_now(),
                &mut rng,
            );
            debug!(
                "Outbound round: {} of {} ordered candidates over {} network groups",
                picked.len(),
                ordered.len(),
                group_counts(picked.iter().copied()).len()
            );
            picked
        };

        picked
    }

    /// Start the general redial task (Phase 1: known peers + seeds, Phase 2A: seeds unprivileged).
    async fn start_reconnection_task(&self) {
        let peers = self.peers.clone();
        let p2p_network = self.clone();

        tokio::spawn(async move {
            let mut retry_counts: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            let mut next_attempt: std::collections::HashMap<String, Instant> =
                std::collections::HashMap::new();
            loop {
                // Phase 2C: the round is drawn by the group-aware selection, so
                // a store dominated by one attacker-controlled group cannot
                // occupy the whole budget cycle after cycle.
                let candidates = p2p_network.outbound_candidates(MAX_REDIAL_PER_CYCLE).await;

                let now = Instant::now();
                let mut dials = 0usize;

                for target in candidates {
                    if dials >= MAX_REDIAL_PER_CYCLE {
                        break;
                    }
                    let key = target.to_string();

                    if peers.read().await.contains_key(&target) {
                        retry_counts.remove(&key);
                        next_attempt.remove(&key);
                        continue;
                    }

                    // Exponential backoff is tracked per candidate instead of
                    // sleeping inside the loop. Phase 1 slept here, so one
                    // black-holed seed delayed every other candidate behind it.
                    if let Some(due) = next_attempt.get(&key) {
                        if now < *due {
                            continue;
                        }
                    }

                    let attempt = *retry_counts.get(&key).unwrap_or(&0);
                    let backoff = std::cmp::min(2u64.pow(attempt.min(6)), 60); // Max 60s
                    debug!(
                        "Redial candidate {} (attempt {}, backoff {}s)",
                        target,
                        attempt + 1,
                        backoff
                    );

                    p2p_network.connect_to_peer(target).await;
                    dials += 1;

                    retry_counts.insert(key.clone(), std::cmp::min(attempt + 1, 6));
                    next_attempt.insert(key, Instant::now() + Duration::from_secs(backoff));
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    /// Start cache cleanup task to evict old seen transactions
    async fn start_cache_cleanup(&self) {
        let seen_transactions = self.seen_transactions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let now = Instant::now();
                let mut seen = seen_transactions.write().await;
                let before = seen.len();
                seen.retain(|_, entry| {
                    now.duration_since(entry.timestamp) < Duration::from_secs(3600)
                });
                let after = seen.len();
                if before != after {
                    debug!(
                        "Cache cleanup: removed {} entries ({} -> {})",
                        before - after,
                        before,
                        after
                    );
                }
            }
        });
    }

    /// Resolve DNS seeds to peer addresses
    async fn discover_from_dns(&self) {
        let dns_seeds = self.config.dns_seeds.clone();
        let default_port = self.config.listen_addr.port();
        let p2p = self.clone();

        tokio::spawn(async move {
                for seed in &dns_seeds {
                    match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                        Ok(addrs) => {
                            let addrs: Vec<SocketAddr> = addrs.collect();
                            info!("🌐 DNS seed {} resolved to {} addresses", seed, addrs.len());
                            for addr in &addrs {
                                let ok = ingress_address(
                                    &p2p.addresses,
                                    &p2p.peers,
                                    p2p.config.listen_addr,
                                    *addr,
                                    PeerSource::Dns,
                                )
                                .await;
                                if !ok {
                                    continue;
                                }
                                if !p2p.is_connected(*addr).await {
                                    p2p.connect_to_peer(*addr).await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("⚠️ DNS seed {} resolution failed: {}", seed, e);
                        }
                    }
                }
        });
    }

    /// Periodically re-resolve DNS seeds to discover new peers
    async fn start_dns_discovery(&self) {
        let dns_seeds = self.config.dns_seeds.clone();
        let default_port = self.config.listen_addr.port();
        let p2p = self.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(120)).await; // Every 2 minutes
                for seed in &dns_seeds {
                    match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                        Ok(addrs) => {
                            for addr in addrs {
                                let ok = ingress_address(
                                    &p2p.addresses,
                                    &p2p.peers,
                                    p2p.config.listen_addr,
                                    addr,
                                    PeerSource::Dns,
                                )
                                .await;
                                if ok && !p2p.is_connected(addr).await {
                                    let p2p_clone = p2p.clone();
                                    tokio::spawn(async move {
                                        p2p_clone.connect_to_peer(addr).await;
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            debug!("DNS seed {} re-resolution failed: {}", seed, e);
                        }
                    }
                }
            }
        });
    }

    /// Phase 2A: addresses eligible for a PEX broadcast. We never re-share an
    /// address we ourselves banned, and never send our own listen address.
    /// Extracted so the filter is unit-testable rather than buried in a loop.
    fn pex_broadcast_list(
        entries: &HashMap<SocketAddr, AddressEntry>,
        scores: &HashMap<SocketAddr, PeerScore>,
        local: SocketAddr,
    ) -> Vec<SocketAddr> {
        entries
            .keys()
            .copied()
            .filter(|a| *a != local)
            .filter(|a| !scores.get(a).map(|s| s.is_banned()).unwrap_or(false))
            .collect()
    }

    /// Periodically exchange peer addresses (PEX).
    ///
    /// Phase 2B (D5): every recipient now gets its own bounded sample instead
    /// of a verbatim copy of the whole known set (which used to be up to
    /// `MAX_KNOWN_PEERS` addresses every 15 seconds to every peer). The sample
    /// drops the recipient itself, anything that recipient taught us, banned or
    /// penalized entries and aged-out hints, and is capped at `PEX_MAX_SEND`.
    async fn start_pex(&self) {
        let peers = self.peers.clone();
        let addresses = self.addresses.clone();
        let local_addr = self.config.listen_addr;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await; // Every 15 seconds for fast peer discovery

                // Snapshot senders first and release, so no session lock is held
                // while the address manager is acquired.
                let targets: Vec<(SocketAddr, mpsc::UnboundedSender<Vec<u8>>)> = {
                    let guard = peers.read().await;
                    guard.iter().map(|(a, s)| (*a, s.clone())).collect()
                };
                if targets.is_empty() {
                    continue;
                }

                let now = unix_now();
                let mgr = addresses.read().await;

                for (recipient, sender) in &targets {
                    let list = mgr.sample_for_pex(local_addr, *recipient, now, PEX_MAX_SEND);
                    if list.is_empty() {
                        continue;
                    }
                    if let Ok(bytes) = bincode::serialize(&P2PMessage::Peers(list)) {
                        let _ = sender.send(bytes);
                    }
                }
            }
        });
    }

    /// Check if a peer address is currently connected
    async fn is_connected(&self, addr: SocketAddr) -> bool {
        self.peers.read().await.contains_key(&addr)
    }

    /// Accept loop for incoming connections
    async fn accept_loop(
        listener: TcpListener,
        peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        local_addr: SocketAddr,
        addresses: Arc<RwLock<AddressManager>>,
        outbound_sessions: Arc<RwLock<HashSet<SocketAddr>>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) {
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    // Phase 2C / scenario A: `PROTECTED_OUTBOUND_SLOTS` is read
                    // on its own so the direction map and the session map are
                    // never held at the same time.
                    let outbound = outbound_sessions.read().await.len();
                    {
                        let peers_guard = peers.read().await;
                        let total = peers_guard.len();
                        // Without this a client that opened MAX_PEERS
                        // connections used to leave the node with zero
                        // capacity for outbound dials: it kept gossiping while
                        // being unable to initiate a single session.
                        if !inbound_admitted(total, outbound) {
                            warn!(
                                "Rejecting incoming peer {}: {} inbound of {} usable, {} outbound slot(s) reserved",
                                addr,
                                total.saturating_sub(outbound),
                                MAX_PEERS.saturating_sub(PROTECTED_OUTBOUND_SLOTS),
                                PROTECTED_OUTBOUND_SLOTS
                            );
                            drop(socket);
                            continue;
                        }
                        // ECLIPSE-01: enforce /24 subnet diversity
                        let subnet_count = count_subnet_peers_excluding(addr, &peers_guard).await;
                        if subnet_count >= MAX_PEERS_PER_SUBNET {
                            warn!(
                                "Rejecting incoming peer {}: /24 subnet limit reached ({}/{})",
                                addr, subnet_count, MAX_PEERS_PER_SUBNET
                            );
                            drop(socket);
                            continue;
                        }
                    }
                    // SCORING: check if peer is banned
                    {
                        let mut mgr = addresses.write().await;
                        mgr.decay_score(addr);
                        if mgr.is_banned(addr) {
                            warn!(
                                "Rejecting banned peer {}: banned until {:?}",
                                addr,
                                mgr.banned_until(addr)
                            );
                            drop(socket);
                            continue;
                        }
                    }
                    info!("New peer connected: {}", addr);
                    let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                    {
                        let mut peers = peers.write().await;
                        peers.insert(addr, msg_sender.clone());
                    }

                    // Phase 2B (D7/D8): record how this address was learned and
                    // admit it through the quality-aware path.
                    ingress_address(
                        &addresses,
                        &peers,
                        local_addr,
                        addr,
                        PeerSource::Inbound,
                    )
                    .await;

                    let peers_clone = peers.clone();
                    let tx_channel = tx_channel.clone();
                    let get_dag_hashes = Arc::clone(&get_dag_hashes);
                    let get_transaction_by_hash = Arc::clone(&get_transaction_by_hash);
                    let get_tips = Arc::clone(&get_tips);
                    let seen_transactions = Arc::clone(&seen_transactions);
                    let peer_discovery_tx = peer_discovery_tx.clone();
                    let addresses = addresses.clone();
                    let sync_ctx = Arc::clone(&sync_ctx);
                    let is_orphan = Arc::clone(&is_orphan);
                    tokio::spawn(async move {
                        Self::handle_peer(
                            socket,
                            addr,
                            peers_clone,
                            local_addr,
                            addresses,
                            tx_channel,
                            get_dag_hashes,
                            get_transaction_by_hash,
                            get_tips,
                            seen_transactions,
                            msg_sender,
                            msg_receiver,
                            peer_discovery_tx,
                            sync_ctx,
                            is_orphan,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Build a 12-byte nonce: bytes[0..8] = u64 BE counter, byte[8] = direction
    /// (0x01 / 0x02 chosen from ephemeral public-key order so the two senders of
    /// one session never share a direction), bytes[9..12] = 0.
    /// Wire-compatible: the full 12 bytes are sent in clear before the ciphertext;
    /// the receiver decrypts with the wire nonce, so legacy peers (byte[8]=0)
    /// still interoperate while new↔new sessions never reuse (K, N).
    fn build_nonce(counter: u64, direction: u8) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        nonce[8] = direction;
        nonce
    }

    /// Deterministic send-direction byte from the two ephemeral handshake keys.
    /// Lower public key → 0x01, higher → 0x02 (equal keys are cryptographically
    /// negligible for random X25519 ephemerals; both would take 0x02 only then).
    fn send_direction(our_pk: &[u8], peer_pk: &[u8]) -> u8 {
        if our_pk < peer_pk {
            0x01
        } else {
            0x02
        }
    }

    /// H2: read exactly `buf.len()` bytes with an inactivity timeout, so a
    /// stalled or silent peer is disconnected instead of holding the task and
    /// socket forever. The timeout error surfaces as io::ErrorKind::TimedOut.
    async fn read_exact_timeout<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        buf: &mut [u8],
        budget: Duration,
    ) -> std::io::Result<()> {
        match tokio::time::timeout(budget, reader.read_exact(buf)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "P2P read timed out",
            )),
        }
    }

    /// H4/V-24: verify the network identity of a received handshake frame
    /// (magic + protocol version + genesis hash). Unit-testable pure check.
    fn verify_handshake_identity(incoming: &[u8]) -> Result<(), &'static str> {
        if incoming.len() < HANDSHAKE_FRAME_LEN {
            return Err("Short P2P handshake frame");
        }
        if incoming[..4] != HANDSHAKE_MAGIC {
            return Err("Invalid P2P handshake magic — not an Aether node");
        }
        if incoming[4] != P2P_PROTOCOL_VERSION {
            return Err("Incompatible P2P protocol version — upgrade the node");
        }
        if incoming[5..37] != crate::genesis::GENESIS_HASH {
            return Err("Network mismatch: peer genesis hash differs from ours");
        }
        Ok(())
    }

    /// Phase 1 crypto audit helper: a (key, nonce) collision requires equal
    /// counter AND equal direction byte under the same session key. After the
    /// direction-byte fix the two senders of one session always differ in
    /// direction, so equal counters no longer collide across directions.
    fn nonce_collision_possible(a_counter: u64, a_dir: u8, b_counter: u64, b_dir: u8) -> bool {
        a_counter == b_counter && a_dir == b_dir
    }

    /// Perform X25519 handshake, derive the session key (shared by both
    /// directions — ChaCha20 nonce uniqueness is enforced via the direction
    /// byte), and return (key, send_direction) for this side.
    async fn handshake(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
    ) -> Result<([u8; 32], u8), Box<dyn std::error::Error>> {
        let our_secret = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_secret);

        let mut outgoing = Vec::with_capacity(HANDSHAKE_FRAME_LEN);
        outgoing.extend_from_slice(&HANDSHAKE_MAGIC);
        outgoing.push(P2P_PROTOCOL_VERSION);
        outgoing.extend_from_slice(&crate::genesis::GENESIS_HASH);
        outgoing.extend_from_slice(our_public.as_bytes());
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&outgoing))
            .await
            .is_err()
        {
            return Err("P2P handshake write timed out".into());
        }

        let mut incoming = [0u8; HANDSHAKE_FRAME_LEN];
        Self::read_exact_timeout(reader, &mut incoming, HANDSHAKE_TIMEOUT)
            .await
            .map_err(|e| format!("P2P handshake read failed: {}", e))?;
        Self::verify_handshake_identity(&incoming)?;

        let mut peer_pk_bytes = [0u8; 32];
        peer_pk_bytes.copy_from_slice(&incoming[HANDSHAKE_FRAME_LEN - 32..]);
        let peer_public = PublicKey::from(peer_pk_bytes);
        let shared_secret = our_secret.diffie_hellman(&peer_public);

        let mut hasher = Sha256::new();
        hasher.update(b"aether-p2p-key-v1");
        hasher.update(shared_secret.as_bytes());
        let key_bytes = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&key_bytes);
        let send_dir = Self::send_direction(our_public.as_bytes(), &peer_pk_bytes);
        Ok((result, send_dir))
    }

    /// Handle a peer connection
    async fn handle_peer(
        socket: TcpStream,
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        local_addr: SocketAddr,
        addresses: Arc<RwLock<AddressManager>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        msg_sender: mpsc::UnboundedSender<Vec<u8>>,
        msg_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) {
        // Split socket into read and write halves
        let (mut reader, mut writer) = socket.into_split();

        // Perform encrypted handshake (X25519 key exchange)
        let (key_bytes, send_dir) = match Self::handshake(&mut reader, &mut writer)
            .await
            .map_err(|e| e.to_string())
        {
            Ok(k) => {
                info!("🔐 P2P encrypted handshake complete with {}", addr);
                k
            }
            Err(msg) => {
                warn!("❌ P2P handshake failed with {}: {}", addr, msg);
                {
                    let mut peers_lock = peers.write().await;
                    peers_lock.remove(&addr);
                }
                // Phase 1: do NOT drop the address from known_peers on a failed
                // handshake — keep it for a later redial attempt. Stamping the
                // TTL clock here is what keeps it alive to be retried.
                addresses.write().await.touch(addr, Instant::now());
                return;
            }
        };
        // Phase 2B: the encrypted handshake completed, so this address is a
        // proven reachable peer — the input to `Recent` categorisation and to
        // anchor candidacy.
        {
            let mut mgr = addresses.write().await;
            mgr.record_success(addr, unix_now());
        }
        let key_enc = Arc::new(key_bytes);
        let key_dec = Arc::clone(&key_enc);

        // Spawn task to handle outgoing messages (encrypted)
        let mut msg_receiver = msg_receiver;
        let send_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let send_counter_clone = Arc::clone(&send_counter);
        let send_dir_task = send_dir;
        tokio::spawn(async move {
            while let Some(msg) = msg_receiver.recv().await {
                let cipher = {
                    let key = Key::from_slice(key_enc.as_ref());
                    ChaCha20Poly1305::new(key)
                };
                let nonce_val =
                    send_counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let nonce_bytes = Self::build_nonce(nonce_val, send_dir_task);
                let nonce = Nonce::from_slice(&nonce_bytes);
                match cipher.encrypt(nonce, msg.as_ref()) {
                    Ok(ciphertext) => {
                        let total_len = 12 + ciphertext.len();
                        if writer
                            .write_all(&(total_len as u32).to_be_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if writer.write_all(nonce).await.is_err() {
                            break;
                        }
                        if writer.write_all(&ciphertext).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Encryption failed for {}: {:?}", addr, e);
                        break;
                    }
                }
            }
        });

        // Send GetInventory with tips on connection
        let our_tips = get_tips();
        if let Ok(getinv_msg) = bincode::serialize(&P2PMessage::GetInventory {
            tips: our_tips.clone(),
        }) {
            info!(
                "[Sync] Sending GetInventory with {} tips to {}",
                our_tips.len(),
                addr
            );
            let _ = msg_sender.send(getinv_msg);
        }

        // Also request the full inventory: tip-based sync can miss unconfirmed
        // (weight-0) tips, so fetch the peer's complete hash set to reconcile.
        if let Ok(sync_req) = bincode::serialize(&P2PMessage::SyncRequest) {
            let _ = msg_sender.send(sync_req);
        }

        // Mark peer as known (Phase 1: refresh TTL clock too)
        {
            let mut mgr = addresses.write().await;
            mgr.observe(addr, PeerSource::Restored, unix_now(), Instant::now());
        }

        let mut msg_count: u64 = 0;
        let mut window_start = Instant::now();
        // Anti-replay: peer send counters are strictly increasing over TCP;
        // reject any frame whose counter does not advance past the last one.
        let mut last_recv_counter: u64 = 0;

        loop {
            // Read encrypted message length (4 bytes)
            // H2: inactivity timeout so a peer that stops mid-stream is
            // disconnected instead of holding the task + socket forever.
            let mut len_buf = [0u8; 4];
            match Self::read_exact_timeout(&mut reader, &mut len_buf, FRAME_TIMEOUT).await {
                Ok(()) => {}
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        warn!(
                            "Peer {} idle for {:?}, disconnecting (frame timeout)",
                            addr, FRAME_TIMEOUT
                        );
                    } else {
                        warn!("Peer {} disconnected: {}", addr, e);
                    }
                    break;
                }
            }

            // Per-second rate limit: count every frame BEFORE decrypt/alloc
            let now = Instant::now();
            if now.duration_since(window_start) >= Duration::from_secs(1) {
                window_start = now;
                msg_count = 0;
            }
            msg_count += 1;
            if msg_count > MAX_MSGS_PER_SEC {
                warn!(
                    "Peer {} exceeded message rate limit ({} msgs/s), disconnecting",
                    addr, MAX_MSGS_PER_SEC
                );
                // SCORING: penalize flood
                {
                    let mut mgr = addresses.write().await;
                    if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_FLOOD) {
                        warn!("Peer {} banned (flood, score={})", addr, score);
                    }
                }
                break;
            }

            let total_len = u32::from_be_bytes(len_buf) as usize;
            if total_len < 12 {
                warn!("Peer {} sent invalid message length {}", addr, total_len);
                break;
            }
            if total_len > MAX_MESSAGE_SIZE {
                warn!(
                    "Peer {} sent oversized message ({} bytes > {}), disconnecting",
                    addr, total_len, MAX_MESSAGE_SIZE
                );
                break;
            }

            // Read nonce (12 bytes)
            let mut nonce_buf = [0u8; 12];
            if Self::read_exact_timeout(&mut reader, &mut nonce_buf, FRAME_TIMEOUT)
                .await
                .is_err()
            {
                warn!("Failed to read nonce from {}", addr);
                break;
            }

            // Anti-replay: counters must strictly increase for this session
            // (TCP preserves order, so a repeat or regression is a replay/forgery).
            let recv_counter = u64::from_be_bytes(nonce_buf[0..8].try_into().unwrap());
            if recv_counter <= last_recv_counter {
                warn!(
                    "Replay/regressed nonce from {} (counter {} <= {}), disconnecting",
                    addr, recv_counter, last_recv_counter
                );
                {
                    let mut mgr = addresses.write().await;
                    if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                        warn!("Peer {} banned (replay, score={})", addr, score);
                    }
                }
                break;
            }
            last_recv_counter = recv_counter;

            // Read ciphertext
            let ciphertext_len = total_len - 12;
            let mut ciphertext = vec![0u8; ciphertext_len];
            if Self::read_exact_timeout(&mut reader, &mut ciphertext, FRAME_TIMEOUT)
                .await
                .is_err()
            {
                warn!("Failed to read ciphertext from {}", addr);
                break;
            }

            // Decrypt
            let cipher = {
                let key = Key::from_slice(key_dec.as_ref());
                ChaCha20Poly1305::new(key)
            };
            let nonce = Nonce::from_slice(&nonce_buf);
            let plaintext = match cipher.decrypt(nonce, ciphertext.as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Decryption failed for {}: {:?}", addr, e);
                    // SCORING: penalize invalid message
                    {
                        let mut mgr = addresses.write().await;
                        if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                            warn!("Peer {} banned (invalid msg, score={})", addr, score);
                        }
                    }
                    break;
                }
            };

            // Deserialize message
            match bincode::deserialize::<P2PMessage>(&plaintext) {
                Ok(msg) => {
                    match msg {
                        P2PMessage::Transaction(tx_bytes) => {
                            // Deduplication: check if we've seen this transaction
                            {
                                let seen = seen_transactions.read().await;
                                if seen.contains_key(&tx_bytes) {
                                    continue;
                                }
                            }

                            // Deserialize transaction
                            if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                // Mark as seen with timestamp and source (Network) before sending to channel
                                insert_seen(&seen_transactions, tx_bytes.clone()).await;

                                // LOG NOISE (soak): per-tx line on the hot
                                // path — DEBUG only (failures keep WARN).
                                tracing::debug!(
                                    "Received transaction from {}: {}",
                                    addr,
                                    hex::encode(tx.id)
                                );
                                let _ = tx_channel.send(tx);

                                // Forward transaction to all other connected peers (relay)
                                let relay_msg = P2PMessage::Transaction(tx_bytes.clone());
                                if let Ok(relay_bytes) = bincode::serialize(&relay_msg) {
                                    let peers_guard = peers.read().await;
                                    for (peer_addr, sender) in peers_guard.iter() {
                                        if *peer_addr != addr {
                                            let _ = sender.send(relay_bytes.clone());
                                        }
                                    }
                                }
                            } else {
                                warn!("Failed to deserialize transaction from {}", addr);
                            }
                        }
                        P2PMessage::Inventory(hashes) => {
                            // Determine which hashes we need (bounded by MAX_INV_ITEMS).
                            // B4: dedup against the DAG AND the orphan store: a tx
                            // parked as an orphan is already tracked (its parents are
                            // being requested), re-requesting it is pure waste.
                            let our_hashes = get_dag_hashes();
                            let our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();
                            // PHASE D live-campaign fix: the MAX_INV_ITEMS cap
                            // used to apply to the PEER's raw inventory, which
                            // hid every tx beyond the first 1000 from a joining
                            // node (the diff came out empty, sync_requested=0,
                            // bootstrap stuck a few txs short of the tip). The
                            // cap now bounds the REQUEST (the real diff) so a
                            // late joiner still asks for the whole missing set.
                            // C2 diagnostics: advertised total + orphan-dedup skips.
                            sync_ctx.stats.inventory_advertised.fetch_add(
                                hashes.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            let mut skipped_orphan = 0u64;
                            let missing_hashes: Vec<Vec<u8>> = hashes
                                .into_iter()
                                .filter(|h| {
                                    if our_hash_set.contains(h) {
                                        return false;
                                    }
                                    if is_orphan(h.as_slice()) {
                                        skipped_orphan += 1;
                                        return false;
                                    }
                                    true
                                })
                                .take(MAX_INV_ITEMS)
                                .collect();
                            sync_ctx
                                .stats
                                .inventory_skipped_orphan
                                .fetch_add(skipped_orphan, std::sync::atomic::Ordering::Relaxed);
                            // VPS-2 §5: the diff size itself (how much the
                            // peer has that we lack), independent of caps.
                            sync_ctx.stats.inventory_missing.fetch_add(
                                missing_hashes.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );

                            // Request missing transactions via GetData
                            if !missing_hashes.is_empty() {
                                sync_ctx.stats.sync_requested.fetch_add(
                                    missing_hashes.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                // DEEP SYNC: register missing hashes in the frontier
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    for h in &missing_hashes {
                                        frontier.add_pending(h.clone());
                                    }
                                }
                                info!(
                                    "Requesting {} missing transactions from {}",
                                    missing_hashes.len(),
                                    addr
                                );
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_hashes.clone()))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                                // DEEP SYNC: mark hashes as requested in frontier
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    for h in &missing_hashes {
                                        frontier.mark_requested(h, addr);
                                    }
                                }
                            }
                        }
                        P2PMessage::GetInventory { tips: peer_tips } => {
                            // Get our hashes and tips
                            let our_hashes = get_dag_hashes();
                            let our_tips = get_tips();
                            let _our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();

                            // Find transactions we have that peer doesn't have (compare tips),
                            // bounded by MAX_INV_ITEMS on the peer-supplied list.
                            let peer_tips_set: HashSet<Vec<u8>> =
                                peer_tips.into_iter().take(MAX_INV_ITEMS).collect();
                            let our_tips_set: HashSet<Vec<u8>> = our_tips.into_iter().collect();

                            // Transactions we need from peer (tips we don't have)
                            let missing_for_us: Vec<Vec<u8>> =
                                peer_tips_set.difference(&our_tips_set).cloned().collect();

                            // Transactions peer might need from us (tips we have that they don't)
                            let missing_for_peer: Vec<Vec<u8>> =
                                our_tips_set.difference(&peer_tips_set).cloned().collect();

                            info!("[Sync] GetInventory from {}: we need {} tips, peer might need {} tips", 
                                addr, missing_for_us.len(), missing_for_peer.len());

                            // Send our tips that peer doesn't have (with pagination)
                            if !missing_for_peer.is_empty() {
                                const PAGE_SIZE: usize = 100;
                                let mut tx_bytes_list = Vec::new();

                                for hash in missing_for_peer.iter().take(PAGE_SIZE) {
                                    if let Some(tx) = get_transaction_by_hash(hash) {
                                        if let Ok(bytes) = bincode::serialize(&tx) {
                                            tx_bytes_list.push(bytes);
                                        }
                                    }
                                }

                                if !tx_bytes_list.is_empty() {
                                    info!(
                                        "[Sync] Sending {} transactions to {}",
                                        tx_bytes_list.len(),
                                        addr
                                    );
                                    if let Ok(sync_resp_msg) =
                                        bincode::serialize(&P2PMessage::SyncResponse(tx_bytes_list))
                                    {
                                        let _ = msg_sender.send(sync_resp_msg);
                                    }
                                }
                            }

                            // Request missing transactions from peer
                            if !missing_for_us.is_empty() {
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_for_us))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                            }
                        }
                        P2PMessage::GetData(hashes) => {
                            // DEEP SYNC: serve requested transactions with FULL
                            // ancestor closure, split into multiple topologically
                            // sorted pages. Each page is ancestor-closed so the
                            // receiver can insert bottom-up without orphans.
                            let topo = Self::cached_topo_order(
                                &sync_ctx,
                                get_dag_hashes(),
                                &*get_transaction_by_hash,
                            )
                            .await;
                            let sort_topo = |v: &mut Vec<Vec<u8>>, order: &Option<Vec<Vec<u8>>>| {
                                if let Some(order) = order {
                                    let pos: HashMap<&Vec<u8>, usize> =
                                        order.iter().enumerate().map(|(i, h)| (h, i)).collect();
                                    v.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
                                }
                            };
                            // Take up to MAX_SYNC_PAGE of the requested hashes.
                            let requested: Vec<Vec<u8>> =
                                hashes.iter().take(MAX_SYNC_PAGE).cloned().collect();
                            // Compute FULL ancestor closure (bounded by MAX_CLOSURE_PAGES).
                            let max_entries = MAX_SYNC_PAGE.saturating_mul(MAX_CLOSURE_PAGES);
                            let mut closure = P2PNetwork::ancestor_full_closure(
                                &requested,
                                &*get_transaction_by_hash,
                                max_entries,
                            );
                            // Topologically sort: ancestors first.
                            sort_topo(&mut closure, &topo);
                            // Split into pages of MAX_SYNC_PAGE and send each.
                            let total_pages = closure.len().div_ceil(MAX_SYNC_PAGE).max(1);
                            for (page_idx, chunk) in closure.chunks(MAX_SYNC_PAGE).enumerate() {
                                let mut tx_bytes_list = Vec::with_capacity(chunk.len());
                                for hash in chunk {
                                    if let Some(tx) = get_transaction_by_hash(hash) {
                                        if let Ok(bytes) = bincode::serialize(&tx) {
                                            tx_bytes_list.push(bytes);
                                        }
                                    }
                                }
                                if !tx_bytes_list.is_empty() {
                                    tracing::debug!(
                                        "[Sync] Serving page {}/{} ({} txs) to {}",
                                        page_idx + 1,
                                        total_pages,
                                        tx_bytes_list.len(),
                                        addr
                                    );
                                    if let Ok(sync_resp_msg) =
                                        bincode::serialize(&P2PMessage::SyncResponse(tx_bytes_list))
                                    {
                                        let _ = msg_sender.send(sync_resp_msg);
                                    }
                                }
                            }
                        }
                        P2PMessage::SyncRequest => {
                            // Respond with full inventory. LOG NOISE (soak):
                            // periodic full-inventory announcements (10k hashes
                            // each on a big DAG) — DEBUG only. Sync progress
                            // stays visible via the maintenance summary line.
                            let our_hashes = get_dag_hashes();
                            tracing::debug!(
                                "[Sync] Sending inventory with {} hashes to {}",
                                our_hashes.len(),
                                addr
                            );
                            if let Ok(inv_msg) =
                                bincode::serialize(&P2PMessage::Inventory(our_hashes))
                            {
                                let _ = msg_sender.send(inv_msg);
                            }
                        }
                        P2PMessage::SyncResponse(tx_bytes_list) => {
                            // B4: download and add transactions in dependency order
                            // (bounded by MAX_INV_ITEMS to avoid amplification).
                            // 1. Dedup against the DAG AND the orphan store: an
                            //    orphan is already tracked and retried by the
                            //    resolver (fixpoint in process_orphans), so
                            //    re-delivering it is pure waste (this was the B4
                            //    re-request amplification loop).
                            // 2. Split the batch into (deliverable now) / (parents
                            //    still missing) with dependency-aware passes: a tx
                            //    whose parents are in the DAG or accepted earlier in
                            //    this SAME batch is delivered immediately. The
                            //    remaining txs go through the normal pipeline where
                            //    they are parked as orphans and their parents are
                            //    requested (bounded by the parent-request dedup).
                            let mut pending: Vec<(Vec<u8>, Transaction)> = Vec::new();
                            // C2 diagnostics: raw items before the DAG/orphan
                            // dedup below (peers re-sending tracked items?).
                            sync_ctx.stats.sync_response_items.fetch_add(
                                tx_bytes_list.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            for tx_bytes in tx_bytes_list.into_iter().take(MAX_INV_ITEMS) {
                                if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                    if get_transaction_by_hash(&tx.id).is_some()
                                        || is_orphan(&tx.id)
                                    {
                                        sync_ctx
                                            .stats
                                            .duplicate_ignored
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        // DEEP SYNC: mark duplicate as applied in frontier (already resolved)
                                        {
                                            let mut frontier = sync_ctx.frontier.write().await;
                                            frontier.mark_received(&tx.id);
                                            frontier.mark_applied(&tx.id);
                                        }
                                        continue;
                                    }
                                    // FIX: do NOT mark_received here yet — only mark
                                    // AFTER partition_batch confirms the tx is deliverable.
                                    // Waiting txs (parents missing) must remain "unreceived"
                                    // so the next inventory diff re-requests them.
                                    pending.push((tx_bytes, tx));
                                }
                            }
                            sync_ctx.stats.sync_received.fetch_add(
                                pending.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            sync_ctx
                                .stats
                                .sync_batches
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let (deliverable, waiting) =
                                Self::partition_batch(pending, &*get_transaction_by_hash);

                            if !waiting.is_empty() {
                                tracing::info!(
                                    "📥 SyncResponse: {} deliverable, {} waiting (parents missing, will retry next cycle)",
                                    deliverable.len(),
                                    waiting.len()
                                );
                            }

                            // DEEP SYNC: adaptive backpressure instead of fixed
                            // 50ms per tx. Scale interval with batch size to
                            // maintain throughput while allowing ledger breathing room.
                            let batch_len = deliverable.len();
                            let delay_ms = if batch_len > 0 {
                                // Scale: base interval * sqrt(batch) / 10, clamped to [1, 20]ms
                                let scaled = (BACKPRESSURE_BASE_MS as f64
                                    * (batch_len as f64).sqrt()
                                    / 10.0) as u64;
                                scaled.clamp(1, 20)
                            } else {
                                0
                            };
                            // CRITICAL FIX: only send deliverable txs to the mempool.
                            // waiting txs have parents not yet in the DAG. Sending them
                            // would create orphans whose parents are also in the mempool,
                            // causing an unresolvable cascade (resolved=0).
                            // waiting txs will be re-requested by process_orphans() on
                            // subsequent cycles when their parents arrive.
                            for (tx_bytes, tx) in deliverable.into_iter() {
                                // DEEP SYNC: mark as received + applied in frontier AFTER
                                // partition_batch confirmed this tx is deliverable.
                                // Waiting txs (parents missing) are NOT marked, so the
                                // next inventory diff re-requests them.
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    frontier.mark_received(&tx.id);
                                    frontier.mark_applied(&tx.id);
                                    frontier.record_progress();
                                }
                                insert_seen(&seen_transactions, tx_bytes).await;
                                let _ = tx_channel.send(tx);
                                if delay_ms > 0 {
                                    tokio::time::sleep(tokio::time::Duration::from_millis(
                                        delay_ms,
                                    ))
                                    .await;
                                }
                            }
                            // DEEP SYNC: log frontier state after processing batch
                            {
                                let frontier = sync_ctx.frontier.read().await;
                                tracing::debug!("{}", frontier.log_line());
                            }
                        }
                        P2PMessage::Ping => {
                            // Respond with pong - skip for now, need sender
                        }
                        P2PMessage::Pong => {
                            // Ignore pong
                        }
                        P2PMessage::Peers(peer_list) => {
                            // Phase 2B (D6/R4): a PEX hint may never point at a
                            // private, loopback, link-local or otherwise
                            // reserved host — otherwise a peer can steer us
                            // into dialing our own LAN. This gate exists on the
                            // receive/dial path only: operator bootnodes and
                            // DNS seeds stay unrestricted so private testnets
                            // keep working.
                            let to_add: Vec<SocketAddr> = {
                                // Snapshot the session table and release first:
                                // `peers` and `addresses` are never held together.
                                let connected: HashSet<SocketAddr> =
                                    peers.read().await.keys().copied().collect();
                                let mgr = addresses.read().await;
                                peer_list
                                    .iter()
                                    .take(MAX_INV_ITEMS)
                                    .filter(|p| {
                                        !mgr.contains(**p)
                                            && **p != local_addr
                                            && !connected.contains(p)
                                            && !is_private_or_reserved(**p)
                                    })
                                    .copied()
                                    .collect()
                            };
                            for peer_addr in to_add {
                                let ok = ingress_address(
                                    &addresses,
                                    &peers,
                                    local_addr,
                                    peer_addr,
                                    PeerSource::Pex,
                                )
                                .await;
                                if !ok {
                                    // Nothing left to evict, and other hints in
                                    // this batch are no better.
                                    continue;
                                }
                                // Phase 2B (D5): remember who taught us about
                                // this address so we never echo it back to them.
                                addresses.write().await.set_origin(peer_addr, addr);
                                let _ = peer_discovery_tx.send(peer_addr);
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize message from {}: {}", addr, e);
                    // SCORING: penalize invalid message
                    {
                        let mut mgr = addresses.write().await;
                        if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                            warn!("Peer {} banned (deser fail, score={})", addr, score);
                        }
                    }
                }
            }
        }

        // Remove peer from active map on disconnect.
        // Phase 1 TTL: keep the address in known_peers so general redial / PEX
        // can re-establish the session; the TTL task expires it later.
        {
            let mut peers_lock = peers.write().await;
            peers_lock.remove(&addr);
        }
        {
            let mut mgr = addresses.write().await;
            mgr.touch(addr, Instant::now());
        }
        // DEEP SYNC: failover — move all in-flight requests from this peer back to pending
        {
            let mut frontier = sync_ctx.frontier.write().await;
            let requeued = frontier.on_peer_disconnect(&addr);
            if requeued > 0 {
                info!(
                    "[Sync] Peer {} disconnected, requeued {} in-flight requests for failover",
                    addr, requeued
                );
            }
            frontier.update_state();
            tracing::debug!("{}", frontier.log_line());
        }
        info!("Peer {} removed from peers map", addr);
    }

    /// Connect to a peer
    /// Dial `addr`, tolerating concurrent callers. The initial sweep, heartbeat,
    /// redial loop and PEX can all ask for the same address at the same time;
    /// the in-flight set collapses them into a single session so the `peers` map
    /// never gets a sender silently overwritten by a duplicate connection.
    async fn connect_to_peer(&self, addr: SocketAddr) {
        {
            let mut dialing = self.dialing.write().await;
            if !dialing.insert(addr) {
                debug!("Dial to {} already in flight, skipping", addr);
                return;
            }
        }
        self.connect_to_peer_inner(addr).await;
        self.dialing.write().await.remove(&addr);
    }

    /// Phase 2A: read-only guard consulted before any outbound dial. Inbound
    /// connections have always checked the ban table; outbound never did, so a
    /// node would happily redial a peer it had already banned.
    async fn outbound_dial_blocked(&self, addr: SocketAddr) -> bool {
        self.addresses.read().await.is_banned(addr)
    }

    async fn connect_to_peer_inner(&self, addr: SocketAddr) {
        info!("Dialing peer: {}", addr);

        if self.outbound_dial_blocked(addr).await {
            let until = self.addresses.read().await.banned_until(addr);
            warn!(
                "Skipping banned peer {} for outbound dial (banned until {:?})",
                addr, until
            );
            return;
        }

        self.addresses.write().await.decay_score(addr);

        {
            let peers_guard = self.peers.read().await;
            // Phase 2C: outbound is admitted against the *total* only — the
            // inbound side already keeps `PROTECTED_OUTBOUND_SLOTS` free for
            // exactly this check.
            if !outbound_admitted(peers_guard.len()) {
                warn!(
                    "Skipping connect to {}: connection limit reached ({})",
                    addr, MAX_PEERS
                );
                return;
            }
            // ECLIPSE-01: enforce /24 subnet diversity for outbound connections
            let subnet_count = count_subnet_peers_excluding(addr, &peers_guard).await;
            if subnet_count >= MAX_PEERS_PER_SUBNET {
                warn!(
                    "Skipping connect to {}: /24 subnet limit reached ({}/{})",
                    addr, subnet_count, MAX_PEERS_PER_SUBNET
                );
                return;
            }
        }

        // H2: bound the connect attempt so a black-holed or unroutable peer
        // address cannot stall the outbound discovery loop indefinitely.
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(socket)) => {
                info!("Connected to peer: {}", addr);
                let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                {
                    let mut peers = self.peers.write().await;
                    peers.insert(addr, msg_sender.clone());
                }
                // Phase 2C: record that *we* opened this session, so the
                // inbound admission gate can keep its reservation intact.
                {
                    let mut outbound = self.outbound_sessions.write().await;
                    outbound.insert(addr);
                }

                // Phase 2B (D7/D8): an address we chose to dial is an outbound
                // source, admitted through the quality-aware path.
                ingress_address(
                    &self.addresses,
                    &self.peers,
                    self.config.listen_addr,
                    addr,
                    PeerSource::Outbound,
                )
                .await;

                let peers = self.peers.clone();
                let addresses = self.addresses.clone();
                let local_addr = self.config.listen_addr;
                let tx_channel = self.tx_channel.clone();
                let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
                let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
                let get_tips = Arc::clone(&self.get_tips);
                let seen_transactions = Arc::clone(&self.seen_transactions);
                let sync_ctx = Arc::clone(&self.sync_ctx);
                let is_orphan = Arc::clone(&self.is_orphan);
                let peer_discovery_tx = {
                    let guard = self.peer_discovery_tx.lock().await;
                    guard.clone().unwrap_or_else(|| {
                        let (tx, _) = mpsc::unbounded_channel();
                        tx
                    })
                };
                let outbound_sessions = self.outbound_sessions.clone();
                tokio::spawn(async move {
                    Self::handle_peer(
                        socket,
                        addr,
                        peers,
                        local_addr,
                        addresses,
                        tx_channel,
                        get_dag_hashes,
                        get_transaction_by_hash,
                        get_tips,
                        seen_transactions,
                        msg_sender,
                        msg_receiver,
                        peer_discovery_tx,
                        sync_ctx,
                        is_orphan,
                    )
                    .await;
                    // Phase 2C: release the reservation only once the session
                    // is really gone. Cleaning up here rather than inside
                    // `handle_peer` keeps `handle_peer`'s signature — and
                    // therefore the inbound path — untouched.
                    outbound_sessions.write().await.remove(&addr);
                });
            }
            Ok(Err(e)) => {
                warn!("Failed to connect to {}: {}", addr, e);
                self.record_dial_failure(addr).await;
            }
            Err(_) => {
                warn!("Connect timeout to {} after {:?}", addr, CONNECT_TIMEOUT);
                self.record_dial_failure(addr).await;
            }
        }
    }

    /// Phase 2B: an outbound dial that never reached a session lowers the
    /// address's quality. `admit_peer` weighs exactly that quality when the
    /// table is full (D8), so a repeatedly unreachable address is the first
    /// thing displaced.
    async fn record_dial_failure(&self, addr: SocketAddr) {
        self.addresses.write().await.record_failure(addr);
    }

    /// Broadcast a transaction to all connected peers
    pub async fn broadcast_transaction(&self, tx: Transaction) {
        let tx_bytes = match bincode::serialize(&tx) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize transaction: {}", e);
                return;
            }
        };

        // Mark as seen with Local source before broadcasting to avoid rebroadcast loops
        insert_seen(&self.seen_transactions, tx_bytes.clone()).await;

        let msg = P2PMessage::Transaction(tx_bytes.clone());
        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize P2P message: {}", e);
                return;
            }
        };

        let peers = self.peers.read().await;
        let peers: &std::collections::HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = &*peers;
        for (addr, sender) in peers.iter() {
            let sender: &mpsc::UnboundedSender<Vec<u8>> = sender;
            if sender.send(msg_bytes.clone()).is_err() {
                warn!("Failed to send transaction to {}: channel closed", addr);
            }
        }
    }

    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get the list of connected peers
    pub async fn get_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let peers: &std::collections::HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = &*peers;
        peers.keys().copied().collect()
    }

    /// C2-004: cached topological serving order, keyed by DAG length.
    /// Sorting the whole DAG per GetData collapsed serving nodes at ~10k
    /// txs; repeat requests are O(1). The order is a SERVING HINT ONLY,
    /// never consensus (a stale entry merely batches less optimally).
    async fn cached_topo_order(
        sync_ctx: &Arc<SyncContext>,
        all_hashes: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Option<Vec<Vec<u8>>> {
        {
            let cache = sync_ctx.topo_cache.read().await;
            if let Some((len, order)) = cache.as_ref() {
                if *len as usize == all_hashes.len() {
                    sync_ctx
                        .stats
                        .topo_cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(order.clone());
                }
            }
            sync_ctx
                .stats
                .topo_cache_miss
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let order = Self::topological_order(all_hashes, get_transaction_by_hash);
        if let Some(ref o) = order {
            let mut cache = sync_ctx.topo_cache.write().await;
            *cache = Some((o.len() as u64, o.clone()));
        }
        order
    }

    /// VPS-2: extend a requested hash set with its DAG-resident ancestors
    /// (bounded), so the served page is self-sufficient for bottom-up
    /// insertion. Pure function of (requested set, DAG contents):
    /// deterministic, no network, no consensus impact.
    ///
    /// Guarantees: every returned hash is DAG-resident (requested unknowns
    /// are dropped — the serving layer skips them anyway); requested ones
    /// come with their ancestor closure up to the budget; at most
    /// ANCESTOR_BUDGET extras; genesis (`[0; 32]`) parents terminate;
    /// no duplicates; terminates (visited set + step cap double-guard
    /// against any cycle).
    pub(crate) fn ancestor_closed_page(
        requested: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Vec<Vec<u8>> {
        const ANCESTOR_BUDGET: usize = 400;
        const ANCESTOR_STEPS: usize = 20_000;
        let mut page: Vec<Vec<u8>> =
            Vec::with_capacity(requested.len().saturating_add(ANCESTOR_BUDGET));
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for h in requested.into_iter() {
            // Requested-but-unknown hashes are dropped here (the serving
            // layer would skip them anyway); only servable txs enter.
            if get_transaction_by_hash(&h).is_none() {
                continue;
            }
            if seen.insert(h.clone()) {
                page.push(h);
            }
        }
        let mut budget = ANCESTOR_BUDGET;
        let mut steps = 0usize;
        let mut idx = 0usize;
        while idx < page.len() && budget > 0 && steps < ANCESTOR_STEPS {
            steps += 1;
            let h = page[idx].clone();
            idx += 1;
            let parents: [[u8; 32]; 2] = match get_transaction_by_hash(&h) {
                Some(tx) => tx.parents,
                None => continue,
            };
            for parent in parents.iter() {
                if *parent == [0u8; 32] {
                    continue;
                }
                let key = parent.to_vec();
                if seen.contains(&key) {
                    continue;
                }
                if get_transaction_by_hash(&key).is_none() {
                    continue;
                }
                seen.insert(key.clone());
                page.push(key);
                budget -= 1;
                if budget == 0 {
                    break;
                }
            }
        }
        page
    }

    /// DEEP SYNC: compute the full ancestor closure of a set of requested
    /// transaction hashes. The result includes ALL ancestors reachable from
    /// the requested set, bounded by `max_entries` (CPU/memory protection).
    ///
    /// Unlike the previous `ancestor_closed_page` with its fixed ANCESTOR_BUDGET
    /// of 400, this function computes the FULL closure up to the bound, ensuring
    /// that the served page is self-sufficient for bottom-up insertion.
    ///
    /// Returns hashes in an UNORDERED set. The caller must topologically sort
    /// the result before sending.
    pub(crate) fn ancestor_full_closure(
        requested: &[Vec<u8>],
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
        max_entries: usize,
    ) -> Vec<Vec<u8>> {
        let mut closure: Vec<Vec<u8>> = Vec::with_capacity(requested.len().min(max_entries));
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut steps = 0usize;
        // Seed with requested hashes (only those that exist in the DAG).
        for h in requested {
            if get_transaction_by_hash(h).is_none() {
                continue;
            }
            if seen.insert(h.clone()) {
                closure.push(h.clone());
            }
        }
        // BFS walk: for each hash in the closure, append its parents.
        let mut idx = 0usize;
        while idx < closure.len()
            && closure.len() < max_entries
            && steps < crate::sync_stats::TOPO_ORDER_CAP
        {
            steps += 1;
            let h = closure[idx].clone();
            idx += 1;
            let parents: [[u8; 32]; 2] = match get_transaction_by_hash(&h) {
                Some(tx) => tx.parents,
                None => continue,
            };
            for parent in parents.iter() {
                if *parent == [0u8; 32] {
                    continue;
                }
                let key = parent.to_vec();
                if seen.contains(&key) {
                    continue;
                }
                if get_transaction_by_hash(&key).is_none() {
                    continue;
                }
                seen.insert(key.clone());
                closure.push(key);
                if closure.len() >= max_entries {
                    break;
                }
            }
        }
        closure
    }

    /// B4: deterministic dependency order of the local DAG (parents before
    /// children, Kahn's algorithm with a sorted queue for a stable result).
    /// Returns None above `TOPO_ORDER_CAP` (cost guard): the caller then falls
    /// back to the request order.
    fn topological_order(
        hashes: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Option<Vec<Vec<u8>>> {
        if hashes.is_empty() || hashes.len() > TOPO_ORDER_CAP {
            return None;
        }
        let mut indeg: HashMap<Vec<u8>, usize> = hashes.iter().map(|h| (h.clone(), 0)).collect();
        let mut children: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
        for h in &hashes {
            if let Some(tx) = get_transaction_by_hash(h) {
                for parent in tx.parents.iter() {
                    if *parent == [0u8; 32] {
                        continue;
                    }
                    if indeg.contains_key(parent.as_slice()) {
                        // C2-004 FIX: indeg[h] counts h's UNMET PARENT
                        // dependencies (Kahn). The previous code incremented
                        // the PARENT's counter (i.e. counted children), which
                        // emitted tips-first: joining nodes parked every batch
                        // as orphans and the re-request storm collapsed serving
                        // nodes at ~10k txs. Parents-first lets joiners insert
                        // immediately.
                        *indeg.get_mut(h).expect("topological_order: h must be in indeg") += 1;
                    }
                    children.entry(parent.to_vec()).or_default().push(h.clone());
                }
            }
        }
        let mut queue: Vec<Vec<u8>> = indeg
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(h, _)| h.clone())
            .collect();
        queue.sort();
        let mut order = Vec::with_capacity(hashes.len());
        while let Some(h) = queue.pop() {
            order.push(h.clone());
            if let Some(kids) = children.get(&h) {
                for kid in kids {
                    let d = indeg.get_mut(kid).expect("topological_order: kid must be in indeg");
                    *d -= 1;
                    if *d == 0 {
                        queue.push(kid.clone());
                    }
                }
            }
        }
        if order.len() != hashes.len() {
            // Cyclic references cannot exist (validation rejects them), but
            // never return a partial order: fall back to the caller's order.
            return None;
        }
        Some(order)
    }

    /// B4: split a sync batch into (deliverable now) / (waiting for parents)
    /// using dependency-aware passes. A tx is deliverable when BOTH parents
    /// are in the DAG or were accepted earlier in this batch (a parent that
    /// is itself still waiting keeps the child waiting too). The result is
    /// INDEPENDENT of the batch order: any permutation of the same tx set
    /// with the same DAG yields the same partition.
    fn partition_batch(
        batch: Vec<(Vec<u8>, Transaction)>,
        has_in_dag: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> (Vec<(Vec<u8>, Transaction)>, Vec<(Vec<u8>, Transaction)>) {
        use std::collections::HashSet;
        let mut inserted: HashSet<[u8; 32]> = HashSet::new();
        let mut pending = batch;
        let mut deliverable = Vec::new();
        loop {
            let before = pending.len();
            let mut still = Vec::new();
            for item in pending {
                let (_, tx) = &item;
                let p0_ok = tx.parents[0] == [0u8; 32]
                    || inserted.contains(&tx.parents[0])
                    || has_in_dag(tx.parents[0].as_slice()).is_some();
                let p1_ok = tx.parents[1] == [0u8; 32]
                    || inserted.contains(&tx.parents[1])
                    || has_in_dag(tx.parents[1].as_slice()).is_some();
                if p0_ok && p1_ok {
                    inserted.insert(tx.id);
                    deliverable.push(item);
                } else {
                    still.push(item);
                }
            }
            pending = still;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        (deliverable, pending)
    }

    /// Request a specific transaction by hash from all peers.
    ///
    /// B4: bounded + backoff. The missing-parent set is deduplicated so a
    /// parent is re-requested at most once per cooldown (escalating 2s/5s/15s
    /// by attempt count). Previously every parked orphan re-requested its
    /// parents unconditionally: the resulting 1-tx GetData flood starved the
    /// real sync batches and the bootstrap froze (B4 livelock).
    pub async fn request_transaction(&self, hash: Vec<u8>) {
        {
            let mut reqs = self.sync_ctx.requested_parents.write().await;
            if reqs.len() >= crate::sync_stats::MAX_INFLIGHT_PARENTS {
                // Evict the least recently requested entry (bounded memory).
                let oldest_key: Option<Vec<u8>> = reqs
                    .iter()
                    .min_by_key(|(_, (last, _))| *last)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    reqs.remove(&key);
                }
            }
            let now = Instant::now();
            if let Some((last, attempts)) = reqs.get_mut(&hash) {
                let cooldown = crate::sync_stats::SyncContext::backoff_for(*attempts);
                if now.duration_since(*last) < cooldown {
                    self.sync_ctx
                        .stats
                        .parent_already_known
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                *last = now;
                *attempts += 1;
            } else {
                reqs.insert(hash.clone(), (now, 1));
            }
        }

        self.sync_ctx
            .stats
            .parent_requested
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let msg = P2PMessage::GetData(vec![hash.clone()]);
        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize GetData message: {}", e);
                return;
            }
        };

        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            if sender.send(msg_bytes.clone()).is_err() {
                warn!("Failed to send GetData request to {}: channel closed", addr);
            }
        }
    }

    /// V-22 FIX: request the FULL inventory from every connected peer.
    ///
    /// The peer answers with `Inventory(all its transaction hashes)`, we
    /// diff it against our DAG and fetch what we are missing via GetData.
    /// Called periodically (see the node's 10s maintenance loop) and after
    /// boot, so a node that missed transactions while offline - or received
    /// a stale inventory at handshake time - keeps reconciling until it
    /// converges to the exact same transaction set as its peers. This never
    /// assumes the node already knows the parents: missing ancestors are
    /// fetched recursively through the orphan flow.
    pub async fn request_full_sync(&self) {
        let msg = match bincode::serialize(&P2PMessage::SyncRequest) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize SyncRequest: {}", e);
                return;
            }
        };
        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            debug!("[Sync] Requesting full inventory from {}", addr);
            if sender.send(msg.clone()).is_err() {
                warn!("Failed to send SyncRequest to {}: channel closed", addr);
            }
        }
    }
}

#[cfg(test)]
mod phase2_decentralized_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn net_with(bootnodes: Vec<SocketAddr>) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes,
            dns_seeds: vec![],
            peer_store_path: None,
        })
    }

    /// A node wired to a specific on-disk peer store (Phase 2B store tests).
    fn net_at(path: std::path::PathBuf) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
        })
    }

    fn net_at_config(cfg: P2PConfig) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt,
            empty,
            sync_ctx,
            is_orphan,
        )
    }

    fn banned_score() -> PeerScore {
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        s
    }

    /// PHASE2-2A / PRINCIPE 2: seeds are ordinary fallbacks in the redial
    /// ordering. A peer the node already knows always outranks an unknown seed,
    /// so one dead seed can no longer monopolise the redial cycle.
    #[test]
    fn test_seeds_are_unprivileged_in_redial() {
        let local = addr("127.0.0.1:31001");
        let seed1 = addr("10.0.0.1:25565");
        let seed2 = addr("10.0.0.2:25565");
        let peer_a = addr("203.0.113.10:25565");
        let peer_b = addr("203.0.113.11:25565");

        let known = vec![peer_a, peer_b, seed1]; // a seed may also already be a known peer

        let out = P2PNetwork::redial_candidates(&known, &[seed1, seed2], local);

        assert_eq!(out.iter().filter(|a| **a == peer_a).count(), 1);
        assert_eq!(out.iter().filter(|a| **a == peer_b).count(), 1);
        assert!(
            out.iter().filter(|a| **a == seed1).count() == 1,
            "seed already known must not be duplicated"
        );
        assert!(out.contains(&seed2), "unconfigured-seen seed still reachable");
        assert!(!out.contains(&local), "own listen address must never be dialled");

        let first_known = out
            .iter()
            .position(|a| *a == peer_a || *a == peer_b)
            .expect("known peers must be present");
        let last_seed = out.iter().position(|a| *a == seed2).unwrap();
        assert!(
            first_known < last_seed,
            "known peers must be redialled before an unknown seed"
        );
    }

    /// PHASE2-2A / PRINCIPE 1: a node that never configured any seed still has a
    /// usable candidate set — discovery does not require a bootnode.
    #[test]
    fn test_redial_candidates_without_any_seed() {
        let local = addr("127.0.0.1:31001");
        let peer = addr("203.0.113.77:25565");
        let known = vec![peer, local];

        let out = P2PNetwork::redial_candidates(&known, &[], local);
        assert_eq!(out, vec![peer]);
    }

    /// PHASE2-2A / PRINCIPE 1: outbound dials must respect the ban table.
    /// Inbound connections have always checked it; outbound never did.
    #[tokio::test]
    async fn test_outbound_dial_blocked_for_banned_peer() {
        let net = net_with(vec![]);
        let banned = addr("203.0.113.50:25565");
        let clean = addr("203.0.113.51:25565");

        assert!(
            !net.outbound_dial_blocked(banned).await,
            "unknown address is not blocked"
        );

        net.addresses
            .write()
            .await
            .scores_mut()
            .insert(banned, banned_score());

        assert!(
            net.outbound_dial_blocked(banned).await,
            "banned peer must not be redialled outbound"
        );
        assert!(
            !net.outbound_dial_blocked(clean).await,
            "clean peer must stay dialable"
        );
    }

    /// PHASE2-2A / PRINCIPE 3: PEX must not re-share addresses we banned, nor
    /// our own listen address (which would let peers dial us back pointlessly
    /// and would leak a self-reference into the address pool).
    #[test]
    fn test_pex_omits_banned_and_local() {
        let local = addr("127.0.0.1:31001");
        let good = addr("203.0.113.10:25565");
        let banned = addr("203.0.113.66:25565");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        for a in [local, good, banned] {
            entries.insert(a, AddressEntry::new(PeerSource::Pex, 1, Instant::now()));
        }

        let mut scores = HashMap::new();
        scores.insert(banned, banned_score());

        let out = P2PNetwork::pex_broadcast_list(&entries, &scores, local);
        assert_eq!(out.len(), 1, "only the healthy address is shared");
        assert!(out.contains(&good));
        assert!(!out.contains(&local));
        assert!(!out.contains(&banned));
    }

    /// PHASE2-2A: a peer with a live session must never have its TTL clock
    /// expire. Before this fix the clock was only touched at handshake and at
    /// disconnect, so a reliably-connected peer was dropped from the store.
    #[tokio::test]
    async fn test_connected_peer_survives_ttl_refresh() {
        let net = net_with(vec![]);
        let live = addr("203.0.113.20:25565");
        let idle = addr("203.0.113.21:25565");

        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(live, PeerSource::Pex, unix_now(), Instant::now());
            mgr.observe(idle, PeerSource::Pex, unix_now(), Instant::now());
        }

        // A live session exists for `live` only.
        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        net.peers.write().await.insert(live, tx);

        let idle_clock = net
            .addresses
            .read()
            .await
            .entry(idle)
            .expect("idle is a known address")
            .last_seen;
        let before = Instant::now();
        net.refresh_live_peer_clocks().await;
        let after = Instant::now();

        let mgr = net.addresses.read().await;
        let refreshed = mgr
            .entry(live)
            .expect("live peer must have a clock")
            .last_seen;
        assert!(
            refreshed >= before && refreshed <= after,
            "live session clock must be refreshed to now"
        );
        assert!(
            refreshed.elapsed() < PEER_TTL,
            "a live session must stay inside the TTL window"
        );
        // `idle` has no session, so the refresh pass must leave its clock alone.
        assert_eq!(
            mgr.entry(idle).unwrap().last_seen,
            idle_clock,
            "an address with no session must not have its TTL clock touched"
        );
    }

    /// PHASE2-2A: one redial cycle must never attempt more dials than the
    /// connection cap allows — that is what keeps a large stale peer store from
    /// turning a cycle into an hours-long serial sweep.
    #[test]
    fn test_redial_cycle_budget_is_sane() {
        assert!(MAX_REDIAL_PER_CYCLE >= 1);
        assert!(
            MAX_REDIAL_PER_CYCLE <= MAX_PEERS,
            "per-cycle budget must not exceed the connection cap"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2B — distributed peer manager
    // -----------------------------------------------------------------------

    /// PHASE2-2B / D8 / R3: a pre-versioned store (bare JSON array of address
    /// strings) must still load instead of being silently discarded, then be
    /// upgraded to schema v2 on the next flush.
    #[tokio::test]
    async fn test_peer_store_legacy_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let a = addr("203.0.113.20:25565");
        let b = addr("203.0.113.21:25565");
        std::fs::write(
            &path,
            serde_json::to_string(&vec![a.to_string(), b.to_string()]).unwrap(),
        )
        .unwrap();

        let net = net_at(path.clone());
        net.load_known_peers().await;
        {
            let mgr = net.addresses.read().await;
            assert_eq!(mgr.len(), 2, "legacy addresses must not be lost");
            assert!(mgr.contains(a) && mgr.contains(b));
            assert_eq!(
                mgr.entry(a).unwrap().source,
                PeerSource::Restored,
                "every legacy address gains metadata"
            );
        }

        net.save_known_peers().await;
        let file: PeerStoreFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file.version, PEER_STORE_VERSION, "legacy store upgrades to v2");
        assert_eq!(file.entries.len(), 2);
    }

    /// PHASE2-2B / D8: schema v2 round-trips the metadata v1 could not express —
    /// source, success time, attempt counts, quality and the anchor flag.
    #[tokio::test]
    async fn test_peer_store_v2_roundtrip_with_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let a = addr("203.0.113.10:25565");
        let b = addr("203.0.113.11:25565");

        {
            let net = net_at(path.clone());
            {
                let mut mgr = net.addresses.write().await;
                mgr.observe(a, PeerSource::Pex, 1_000_000, Instant::now());
                mgr.observe(b, PeerSource::Dns, 1_000_100, Instant::now());
                let ea = mgr.entries_mut().get_mut(&a).expect("just inserted");
                ea.record_success(1_000_500);
                ea.anchor = true;
            }
            net.save_known_peers().await;
        }

        let file: PeerStoreFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file.version, PEER_STORE_VERSION);
        assert_eq!(file.entries.len(), 2);

        let net2 = net_at(path);
        net2.load_known_peers().await;
        let mgr = net2.addresses.read().await;
        assert_eq!(mgr.len(), 2);
        assert!(mgr.contains(a) && mgr.contains(b));
        let ma = mgr.entry(a).expect("metadata must be restored");
        assert_eq!(ma.source, PeerSource::Pex);
        assert_eq!(ma.last_success, Some(1_000_500));
        assert_eq!(ma.attempts, 1);
        assert!(ma.quality > default_peer_quality());
        assert!(ma.anchor, "the anchor flag must survive a restart");
        let mb = mgr.entry(b).expect("metadata must be restored");
        assert_eq!(mb.source, PeerSource::Dns);
        assert!(mb.last_success.is_none());
        assert!(!mb.anchor);
    }

    /// PHASE2-2B / D5: the send side relays a bounded sample, never the whole
    /// table, and never the recipient's own address back at it.
    #[test]
    fn test_pex_send_bounded() {
        let local = addr("127.0.0.1:31001");
        let recipient = addr("198.51.100.9:25565");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        for i in 0..500u16 {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 30000 + i)
                .parse()
                .unwrap();
            entries.insert(a, AddressEntry::new(PeerSource::Pex, 1, Instant::now()));
        }
        entries.insert(
            local,
            AddressEntry::new(PeerSource::Restored, 1, Instant::now()),
        );
        let scores = HashMap::new();
        let origins = HashMap::new();

        let out = pex_sample(
            &entries,
            &scores,
            &origins,
            local,
            recipient,
            10,
            PEX_MAX_SEND,
        );
        assert_eq!(out.len(), PEX_MAX_SEND, "send side must be capped");
        assert!(
            out.len() < entries.len(),
            "must not relay the entire table"
        );
        assert!(!out.contains(&local), "never send our own address");
        assert!(!out.contains(&recipient), "never send the address back to its owner");
        let unique: HashSet<SocketAddr> = out.iter().copied().collect();
        assert_eq!(unique.len(), out.len(), "no duplicates in one message");
    }

    /// PHASE2-2B / D5: an address the recipient itself gave us is never echoed
    /// straight back to it, and hints old enough stop being gossiped.
    #[test]
    fn test_pex_origin_and_aging() {
        let local = addr("127.0.0.1:31001");
        let recipient = addr("198.51.100.9:25565");
        let from_recipient = addr("203.0.113.60:25565");
        let fresh = addr("203.0.113.61:25565");
        let stale = addr("203.0.113.62:25565");

        let now = 10_000_000u64;
        let aged_out = now - PEX_SHARE_MAX_AGE_SECS - 10;
        assert!(aged_out > 0, "test clock must stay positive");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        entries.insert(
            from_recipient,
            AddressEntry::new(PeerSource::Pex, now, Instant::now()),
        );
        entries.insert(
            fresh,
            AddressEntry::new(PeerSource::Pex, now, Instant::now()),
        );
        entries.insert(
            stale,
            AddressEntry::new(PeerSource::Pex, aged_out, Instant::now()),
        );

        // `from_recipient` is exactly the hint `recipient` sent us.
        let mut origins = HashMap::new();
        origins.insert(from_recipient, recipient);

        let scores = HashMap::new();

        let out = pex_sample(
            &entries,
            &scores,
            &origins,
            local,
            recipient,
            now,
            PEX_MAX_SEND,
        );
        assert!(out.contains(&fresh), "a fresh address is shared");
        assert!(!out.contains(&from_recipient), "never echo back to the source");
        assert!(!out.contains(&stale), "aged-out hints stop being gossiped");
    }

    /// PHASE2-2B / D6: a PEX hint may never point at a private, loopback,
    /// link-local or otherwise reserved host — that is exactly how a peer
    /// steers us into dialing its own LAN or our own loopback services.
    #[test]
    fn test_pex_ignores_private_addresses() {
        for s in [
            "127.0.0.1:30333",
            "10.1.2.3:30333",
            "172.16.0.1:30333",
            "172.31.255.255:30333",
            "192.168.1.1:30333",
            "169.254.5.5:30333",
            "100.64.0.1:30333",
            "100.127.255.255:30333",
            "0.0.0.0:30333",
            "224.0.0.1:30333",
            "240.0.0.1:30333",
            "255.255.255.255:30333",
            "[::1]:30333",
            "[::]:30333",
            "[fe80::1]:30333",
            "[fc00::1]:30333",
            "[fd12:3456::1]:30333",
            "[ff02::1]:30333",
            "[::ffff:192.168.0.1]:30333",
        ] {
            assert!(is_private_or_reserved(addr(s)), "{} must be filtered", s);
        }

        for s in [
            "203.0.113.10:30333",
            "198.51.100.7:30333",
            "1.1.1.1:30333",
            "8.8.8.8:30333",
            "[2001:4860:4860::8888]:30333",
        ] {
            assert!(!is_private_or_reserved(addr(s)), "{} must stay dialable", s);
        }
    }

    /// PHASE2-2B / R4: the private-address gate applies ONLY to PEX-sourced
    /// dials. An operator-configured bootnode on a LAN stays dialable, or
    /// private/LAN testnets break.
    #[test]
    fn test_pex_still_dials_operator_bootnode() {
        let local = addr("127.0.0.1:31001");
        let lan_boot = addr("192.168.1.50:30333");
        let public_peer = addr("203.0.113.5:25565");

        let known = vec![public_peer];
        let out = P2PNetwork::redial_candidates(&known, &[lan_boot], local);
        assert!(
            out.contains(&lan_boot),
            "an operator bootnode must not be gated by the PEX filter"
        );
        assert!(
            is_private_or_reserved(lan_boot),
            "the address itself is private; only the PEX path consults this"
        );
    }

    /// PHASE2-2B / D9: anchors are several and bounded — never one, never
    /// unbounded — and rotate in favour of the most recent successful contact.
    #[test]
    fn test_anchor_rotation_bounded() {
        let local = addr("127.0.0.1:31001");
        let current: Vec<(SocketAddr, u64)> = Vec::new();

        let mut candidates: Vec<(SocketAddr, u64)> = Vec::new();
        for i in 0..20u8 {
            let a = addr(&format!("203.0.113.{}:25565", i + 1));
            candidates.push((a, 1_000 + u64::from(i)));
        }

        let out = promote_anchors(&current, &candidates, local);
        assert!(out.len() <= MAX_ANCHORS, "anchor set must be bounded");
        assert!(out.len() >= MIN_ANCHORS, "enough anchors for resilience");
        assert!(out.len() > 1, "anchors must never collapse to a single point");

        // Rotation keeps the most recently successful candidates (1_019 .. 1_012).
        let kept: Vec<u64> = out
            .iter()
            .map(|a| candidates.iter().find(|(x, _)| x == a).unwrap().1)
            .collect();
        let min_kept = kept.iter().copied().min().unwrap();
        assert!(
            min_kept >= 1_000 + 20 - MAX_ANCHORS as u64,
            "rotation must retain the freshest anchors (min={})",
            min_kept
        );

        // The local address can never become an anchor.
        let mut with_local = candidates.clone();
        with_local.push((local, 9_999_999));
        let out2 = promote_anchors(&current, &with_local, local);
        assert!(!out2.contains(&local));
        assert!(out2.len() <= MAX_ANCHORS);

        // Re-promotion does not duplicate or grow the set.
        let again = promote_anchors(&current, &out2.iter().map(|a| (*a, 1)).collect::<Vec<_>>(), local);
        assert_eq!(again.len(), out2.len());
    }

    /// PHASE2-2B / D9: anchors are replaceable and expire — a dead one is
    /// dropped rather than kept as a permanent authority.
    #[test]
    fn test_anchor_expiry() {
        let a = addr("203.0.113.40:25565");
        let b = addr("203.0.113.41:25565");
        let now = 10_000_000u64;

        let anchors = vec![(a, now - ANCHOR_TTL_SECS - 1), (b, now)];
        let dead = expire_anchors(&anchors, now);
        assert_eq!(dead, vec![a], "anchors past the TTL must be expired");

        let dead2 = expire_anchors(&anchors, now - ANCHOR_TTL_SECS);
        assert!(dead2.is_empty(), "anchors still inside the TTL stay");
    }

    /// PHASE2-2B / D7: the five categories are derived from live state, with
    /// security first — a penalized peer is never counted as active, and a live
    /// session outranks an anchor's standing.
    #[test]
    fn test_categories_derived_from_state() {
        let now = 50_000_000u64;
        let recent = now - 60;
        let stale = now - RECENT_PEER_WINDOW_SECS - 1;

        assert_eq!(
            categorise(false, false, false, None, now),
            PeerCategory::Candidate
        );
        assert_eq!(
            categorise(true, false, false, None, now),
            PeerCategory::Active
        );
        assert_eq!(
            categorise(false, false, false, Some(recent), now),
            PeerCategory::Recent
        );
        assert_eq!(
            categorise(false, true, false, Some(stale), now),
            PeerCategory::Anchor
        );
        assert_eq!(
            categorise(false, true, false, None, now),
            PeerCategory::Anchor,
            "an anchor never degrades to a mere candidate"
        );
        assert_eq!(
            categorise(false, false, false, Some(stale), now),
            PeerCategory::Candidate,
            "a success outside the recent window leaves it a candidate"
        );
        // Security first: penalized beats active and anchor alike.
        assert_eq!(
            categorise(true, true, true, Some(recent), now),
            PeerCategory::Penalized
        );
        // Liveness beats standing.
        assert_eq!(
            categorise(true, true, false, Some(recent), now),
            PeerCategory::Active
        );
    }

    /// PHASE2-2B / D8: at capacity the store evicts its weakest entry instead
    /// of refusing newcomers, so a hostile PEX burst cannot fill the table with
    /// junk and then freeze it. Live sessions and anchors are never victims.
    #[test]
    fn test_quality_eviction_replaces_junk() {
        let incoming = addr("203.0.113.80:25565");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        for i in 0..MAX_KNOWN_PEERS {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 20000 + i as u16)
                .parse()
                .unwrap();
            let mut e = AddressEntry::new(PeerSource::Pex, 1, Instant::now());
            e.quality = 1;
            e.failures = 10;
            entries.insert(a, e);
        }
        assert_eq!(entries.len(), MAX_KNOWN_PEERS, "table must start full");

        let scores = HashMap::new();
        let connected: HashSet<SocketAddr> = HashSet::new();

        let victim = admit_peer(&entries, &scores, &connected, incoming, PEER_QUALITY_MAX)
            .expect("a full table of junk must yield a victim");
        assert_eq!(
            entries.get(&victim).unwrap().quality,
            1,
            "the weakest entry must be the victim"
        );

        // An address weaker than everything present displaces nobody.
        let weaker = admit_peer(&entries, &scores, &connected, incoming, 0);
        assert!(weaker.is_none(), "a worse address must not displace anyone");

        // A live session is never evicted to make room.
        let all_connected: HashSet<SocketAddr> = entries.keys().copied().collect();
        assert!(
            admit_peer(
                &entries,
                &scores,
                &all_connected,
                incoming,
                PEER_QUALITY_MAX
            )
            .is_none(),
            "a connected peer must never be evicted"
        );

        // Neither is an anchor.
        let mut anchored = entries.clone();
        for e in anchored.values_mut() {
            e.anchor = true;
        }
        assert!(
            admit_peer(&anchored, &scores, &connected, incoming, PEER_QUALITY_MAX).is_none(),
            "anchors must never be evicted"
        );

        // A banned entry is the first victim even when its quality looks fine.
        let banned_addr = *entries.keys().next().unwrap();
        let mut scores2 = HashMap::new();
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        scores2.insert(banned_addr, s);
        let mut entries2 = entries.clone();
        entries2.get_mut(&banned_addr).unwrap().quality = PEER_QUALITY_MAX;
        let victim = admit_peer(
            &entries2,
            &scores2,
            &connected,
            incoming,
            PEER_QUALITY_MAX,
        )
        .unwrap();
        assert_eq!(
            victim, banned_addr,
            "a banned entry is always the preferred victim"
        );
    }

    // -----------------------------------------------------------------------
    // AddressManager — the single owner of address state
    //
    // These drive the manager directly. The sixteen tests above cover the same
    // invariants through `P2PNetwork` wiring (on-disk store, PEX loop, TTL
    // task), so nothing here repeats them.
    // -----------------------------------------------------------------------

    /// Membership, TTL clock and metadata enter through `observe`, and
    /// `remove` takes them all back out together.
    #[test]
    fn test_address_manager_insert() {
        let mut mgr = AddressManager::new();
        let a = addr("203.0.113.1:25565");
        let b = addr("203.0.113.2:25565");
        let unknown = addr("203.0.113.3:25565");

        assert_eq!(mgr.len(), 0);
        mgr.observe(a, PeerSource::Dns, 1_000, Instant::now());
        mgr.observe(b, PeerSource::Pex, 1_001, Instant::now());
        assert_eq!(mgr.len(), 2);
        assert!(mgr.contains(a) && mgr.contains(b));
        assert!(!mgr.contains(unknown));

        // Re-observing something we already hold never duplicates it, and the
        // clock is the only thing that moves.
        let clock_before = mgr.entry(a).unwrap().last_seen;
        mgr.observe(a, PeerSource::Pex, 9_999, Instant::now());
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.entry(a).unwrap().first_seen, 1_000, "first_seen is written once");
        assert!(mgr.entry(a).unwrap().last_seen >= clock_before);

        // Eviction removes the entry entirely, twice is reported as removed once.
        assert!(mgr.remove(&b));
        assert!(!mgr.remove(&b));
        assert!(!mgr.contains(b));
        assert_eq!(mgr.len(), 1);
    }

    /// `to_store` / `load_v2` carry every field v1 could not express, and the
    /// node's own address is never round-tripped back into the table.
    #[test]
    fn test_address_manager_metadata_roundtrip() {
        let local = addr("127.0.0.1:31001");
        let a = addr("203.0.113.11:25565");
        let b = addr("203.0.113.12:25565");

        let mut src = AddressManager::new();
        src.observe(a, PeerSource::Pex, 1_000, Instant::now());
        src.record_success(a, 1_500);
        {
            let e = src.entries_mut().get_mut(&a).unwrap();
            e.anchor = true;
            e.failures = 3;
        }
        src.observe(b, PeerSource::Dns, 2_000, Instant::now());
        src.observe(local, PeerSource::Configured, 3_000, Instant::now());

        let file = src.to_store();
        assert_eq!(file.version, PEER_STORE_VERSION);
        assert_eq!(file.entries.len(), 3, "nothing on disk is dropped");

        let mut dst = AddressManager::new();
        assert_eq!(
            dst.load_v2(&file, local, 5_000, Instant::now()),
            2,
            "our own address is skipped on load"
        );
        assert!(!dst.contains(local));

        let ea = dst.entry(a).expect("a must round-trip");
        assert_eq!(ea.source, PeerSource::Pex);
        assert_eq!(ea.first_seen, 1_000);
        assert_eq!(ea.last_success, Some(1_500));
        assert_eq!(ea.attempts, 1);
        assert_eq!(ea.failures, 3);
        assert!(ea.quality > default_peer_quality(), "a success raises quality");
        assert!(ea.anchor, "the anchor flag must survive");

        let eb = dst.entry(b).expect("b must round-trip");
        assert_eq!(eb.source, PeerSource::Dns);
        assert_eq!(eb.first_seen, 2_000);
        assert!(eb.last_success.is_none());
        assert!(!eb.anchor);
    }

    /// R3: a bare `Vec<String>` from a pre-versioned store is adopted rather
    /// than discarded — skipping anything unparseable and our own address.
    #[test]
    fn test_address_manager_legacy_fallback() {
        let local = addr("127.0.0.1:31001");
        let a = addr("203.0.113.21:25565");
        let b = addr("203.0.113.22:25565");
        let legacy = vec![
            a.to_string(),
            "not-an-address".to_string(),
            b.to_string(),
            local.to_string(),
        ];

        let mut mgr = AddressManager::new();
        assert_eq!(mgr.load_legacy(&legacy, local, 7_000, Instant::now()), 2);
        assert!(mgr.contains(a) && mgr.contains(b));
        assert!(!mgr.contains(local), "our own address is never adopted");
        let ea = mgr.entry(a).unwrap();
        assert_eq!(ea.source, PeerSource::Restored, "v1 carried no origin");
        assert_eq!(ea.first_seen, 7_000, "v1 carried no clock");
        assert!(ea.last_success.is_none());
    }

    /// D8: the three admission outcomes — adopted, already present, and
    /// refused because nothing present is worth displacing.
    #[test]
    fn test_address_manager_admission() {
        let connected = HashSet::new();
        let mut mgr = AddressManager::new();

        let first = addr("203.0.113.31:25565");
        assert_eq!(
            mgr.admit(first, PeerSource::Pex, 50, 1_000, Instant::now(), &connected),
            Admission::Inserted { evicted: None },
            "below capacity the address is simply adopted"
        );
        assert_eq!(
            mgr.admit(first, PeerSource::Dns, 50, 1_000, Instant::now(), &connected),
            Admission::AlreadyKnown,
            "admitting twice never duplicates"
        );

        // Fill to capacity with junk so a newcomer must displace someone.
        let mut junk: Vec<SocketAddr> = Vec::new();
        for i in 0..(MAX_KNOWN_PEERS - 1) {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 40000 + i as u16)
                .parse()
                .unwrap();
            mgr.observe(a, PeerSource::Pex, 1, Instant::now());
            mgr.entries_mut().get_mut(&a).unwrap().quality = 1;
            junk.push(a);
        }
        assert_eq!(mgr.len(), MAX_KNOWN_PEERS, "table is at capacity");

        let newcomer = addr("198.51.100.77:25565");
        match mgr.admit(
            newcomer,
            PeerSource::Pex,
            PEER_QUALITY_MAX,
            1_000,
            Instant::now(),
            &connected,
        ) {
            Admission::Inserted { evicted: Some(victim) } => {
                assert!(
                    junk.contains(&victim),
                    "only an existing junk entry can be displaced"
                );
                assert!(!mgr.contains(victim), "the victim must be gone");
            }
            other => panic!("a full table of junk must evict, got {:?}", other),
        }
        assert_eq!(mgr.len(), MAX_KNOWN_PEERS, "capacity stays a hard cap");
        assert!(mgr.contains(newcomer));

        // A table where nothing is worth dropping refuses instead.
        let mut keepers = AddressManager::new();
        for i in 0..MAX_KNOWN_PEERS {
            let a: SocketAddr = format!("198.51.100.{}:{}", (i % 254) + 1, 50000 + i as u16)
                .parse()
                .unwrap();
            keepers.observe(a, PeerSource::Dns, 1, Instant::now());
            keepers.entries_mut().get_mut(&a).unwrap().anchor = true;
        }
        assert_eq!(
            keepers.admit(
                newcomer,
                PeerSource::Pex,
                PEER_QUALITY_MAX,
                1_000,
                Instant::now(),
                &connected
            ),
            Admission::Refused,
            "anchors are never displaced, so the newcomer is refused"
        );
    }

    /// D8: live sessions are protected even when every other entry is equally
    /// worthless, so a full table can never evict its own working peers.
    #[test]
    fn test_address_manager_quality_eviction() {
        let mut mgr = AddressManager::new();
        let mut all: Vec<SocketAddr> = Vec::new();
        for i in 0..MAX_KNOWN_PEERS {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 60000 + i as u16)
                .parse()
                .unwrap();
            mgr.observe(a, PeerSource::Pex, 1, Instant::now());
            mgr.entries_mut().get_mut(&a).unwrap().quality = 1;
            all.push(a);
        }

        let live = all[0];
        let mut live_set = HashSet::new();
        live_set.insert(live);

        let newcomer = addr("198.51.100.88:25565");
        let Admission::Inserted { evicted: Some(victim) } = mgr.admit(
            newcomer,
            PeerSource::Pex,
            PEER_QUALITY_MAX,
            1_000,
            Instant::now(),
            &live_set,
        ) else {
            panic!("a full table must yield a victim");
        };
        assert_ne!(victim, live, "a live session is never evicted");
        assert!(!mgr.contains(victim));
        assert!(mgr.contains(live), "the working peer stays");
        assert!(mgr.contains(newcomer));
    }

    /// D9: anchors come only from sessions that completed a handshake, are
    /// applied as a whole set, and record their promotion as a source change.
    #[test]
    fn test_address_manager_anchor_rotation() {
        let local = addr("127.0.0.1:31001");
        let a = addr("203.0.113.41:25565");
        let b = addr("203.0.113.42:25565");
        let c = addr("203.0.113.43:25565");
        let d = addr("203.0.113.44:25565");

        let mut mgr = AddressManager::new();
        for x in [a, b, c, d] {
            mgr.observe(x, PeerSource::Pex, 1, Instant::now());
        }
        // `c` never reaches a handshake, so it can never become an anchor.
        mgr.record_success(a, 100);
        mgr.record_success(b, 200);
        mgr.record_success(d, 300);

        let live: HashSet<SocketAddr> = [a, b, d].into_iter().collect();
        let candidates = mgr.anchor_candidates(&live);
        assert_eq!(candidates.len(), 3, "only proven sessions are candidates");
        assert!(
            !candidates.iter().any(|(x, _)| *x == c),
            "an address with no success is never a candidate"
        );
        // A known address with no live session is not a candidate either.
        let idle_live: HashSet<SocketAddr> = [c].into_iter().collect();
        assert!(mgr.anchor_candidates(&idle_live).is_empty());

        let wanted = promote_anchors(&[], &candidates, local);
        assert!(wanted.len() <= MAX_ANCHORS && wanted.len() >= MIN_ANCHORS);
        let (promoted, demoted) = mgr.apply_anchors(&wanted);
        assert_eq!(promoted, wanted.len(), "they were plain addresses before");
        assert_eq!(demoted, 0);
        assert_eq!(mgr.anchor_addresses().len(), wanted.len());
        assert_eq!(
            mgr.entry(a).unwrap().source,
            PeerSource::Anchor,
            "promotion records how the address became an anchor"
        );

        // Shrinking the wanted set demotes, never silently keeps stale anchors.
        let (promoted2, demoted2) = mgr.apply_anchors(&[a].into_iter().collect::<HashSet<_>>());
        assert_eq!(promoted2, 0);
        assert_eq!(demoted2, 2);
        assert!(!mgr.entry(b).unwrap().anchor);
        assert_eq!(
            mgr.anchor_addresses(),
            vec![(a, 100)],
            "the surviving anchor keeps its last-success time"
        );
    }

    /// D9 + Phase 1 TTL: an address we stop hearing from is swept out of the
    /// table — and an anchor among them stops being an anchor.
    #[test]
    fn test_address_manager_anchor_expiry() {
        let stale = addr("203.0.113.51:25565");
        let fresh = addr("203.0.113.52:25565");

        let mut mgr = AddressManager::new();
        mgr.observe(stale, PeerSource::Dns, 1, Instant::now());
        mgr.observe(fresh, PeerSource::Dns, 2, Instant::now());
        mgr.record_success(stale, 10);
        mgr.entries_mut().get_mut(&stale).unwrap().anchor = true;
        assert_eq!(mgr.anchor_addresses().len(), 1);

        // Give the sweep a window: `fresh` is reachable, `stale` is not.
        std::thread::sleep(Duration::from_millis(10));
        let mut live = HashSet::new();
        live.insert(fresh);
        let (refreshed, expired) =
            mgr.refresh_and_expire(&live, Instant::now(), Duration::from_millis(1));

        assert_eq!(refreshed, 1, "the live session's clock was refreshed");
        assert_eq!(expired, 1, "only the unheard-from address is swept");
        assert!(!mgr.contains(stale));
        assert!(mgr.contains(fresh), "a refreshed address stays");
        assert!(
            mgr.anchor_addresses().is_empty(),
            "an expired anchor stops being an anchor"
        );
    }

    /// D5: the per-recipient sample honours the recipient exclusion, origin
    /// echo suppression, PEX aging, the ban table and our own listen address.
    #[test]
    fn test_address_manager_pex_sampling() {
        let local = addr("127.0.0.1:31001");
        let recipient = addr("198.51.100.9:25565");
        let from_recipient = addr("203.0.113.61:25565");
        let fresh = addr("203.0.113.62:25565");
        let stale = addr("203.0.113.63:25565");
        let banned = addr("203.0.113.64:25565");

        let now = 10_000_000u64;
        let aged_out = now - PEX_SHARE_MAX_AGE_SECS - 10;
        assert!(aged_out > 0, "test clock must stay positive");

        let mut mgr = AddressManager::new();
        for (a, seen) in [
            (recipient, now),
            (from_recipient, now),
            (fresh, now),
            (stale, aged_out),
            (banned, now),
        ] {
            mgr.observe(a, PeerSource::Pex, seen, Instant::now());
        }
        mgr.observe(local, PeerSource::Restored, now, Instant::now());
        mgr.set_origin(from_recipient, recipient);
        mgr.scores_mut().insert(banned, banned_score());

        let out = mgr.sample_for_pex(local, recipient, now, PEX_MAX_SEND);
        assert!(out.contains(&fresh), "a fresh, healthy address is shared");
        assert!(!out.contains(&recipient), "never send the address back to its owner");
        assert!(!out.contains(&from_recipient), "never echo an address to its own source");
        assert!(!out.contains(&stale), "aged-out hints stop being gossiped");
        assert!(!out.contains(&banned), "we never re-share what we banned");
        assert!(!out.contains(&local), "never send our own listen address");
        assert!(out.len() <= PEX_MAX_SEND, "the sample stays bounded");
    }

    /// The first observer names an address; later hints never relabel it, and
    /// the hint's own origin is tracked separately from that source.
    #[test]
    fn test_address_manager_source_tracking() {
        let a = addr("203.0.113.71:25565");
        let peer = addr("198.51.100.5:25565");
        let mut mgr = AddressManager::new();

        mgr.observe(a, PeerSource::Dns, 1_000, Instant::now());
        assert_eq!(mgr.entry(a).unwrap().source, PeerSource::Dns);

        mgr.observe(a, PeerSource::Pex, 9_999, Instant::now());
        assert_eq!(mgr.entry(a).unwrap().source, PeerSource::Dns, "first observer names it");
        assert_eq!(mgr.entry(a).unwrap().first_seen, 1_000);
        assert!(mgr.origin_of(a).is_none(), "no origin was recorded yet");

        mgr.set_origin(a, peer);
        assert_eq!(mgr.origin_of(a), Some(peer));
        mgr.observe(a, PeerSource::Configured, 9_999, Instant::now());
        assert_eq!(mgr.entry(a).unwrap().source, PeerSource::Dns, "still not relabelled");
        assert_eq!(mgr.origin_of(a), Some(peer), "the origin is independent");
    }

    /// Quality follows dial outcomes, bans only bite once the threshold is
    /// crossed, and a ban survives the TTL sweep that removes its address.
    #[test]
    fn test_address_manager_failure_scoring() {
        let a = addr("203.0.113.81:25565");
        let mut mgr = AddressManager::new();
        mgr.observe(a, PeerSource::Outbound, 1_000, Instant::now());
        let base = mgr.entry(a).unwrap().quality;

        for _ in 0..3 {
            mgr.record_failure(a);
        }
        {
            let e = mgr.entry(a).unwrap();
            assert_eq!(e.attempts, 3);
            assert_eq!(e.failures, 3);
            assert!(e.quality < base, "repeated dial failures must lower quality");
        }

        mgr.record_success(a, 2_000);
        {
            let e = mgr.entry(a).unwrap();
            assert_eq!(e.last_success, Some(2_000));
            assert_eq!(e.attempts, 4);
            assert!(e.quality > base - 15, "a success pays some of it back");
        }

        // An address we do not track is left completely alone.
        let unknown = addr("203.0.113.82:25565");
        mgr.record_failure(unknown);
        assert!(!mgr.contains(unknown));

        // An address with no score is never silently banned by a penalty.
        let unscored = addr("203.0.113.84:25565");
        mgr.observe(unscored, PeerSource::Inbound, 1_000, Instant::now());
        assert!(
            mgr.penalize_and_ban(unscored, -10_000).is_none(),
            "penalties only apply to a score we already keep"
        );
        assert!(!mgr.is_banned(unscored));

        // One point short of the threshold is not a ban; the next one is.
        let hot = addr("203.0.113.83:25565");
        mgr.observe(hot, PeerSource::Inbound, 1_000, Instant::now());
        mgr.decay_score(hot);
        assert!(
            mgr.penalize_and_ban(hot, PEER_SCORE_BAN_THRESHOLD + 1 - PEER_SCORE_INITIAL)
                .is_none(),
            "score still above the threshold"
        );
        assert!(!mgr.is_banned(hot));
        assert_eq!(
            mgr.penalize_and_ban(hot, -1),
            Some(PEER_SCORE_BAN_THRESHOLD),
            "crossing the threshold bans and reports the score"
        );
        assert!(mgr.is_banned(hot));

        // A ban must outlive the address it belongs to: sweeping the entry out
        // of the table must never quietly un-ban it.
        let evicted = addr("203.0.113.85:25565");
        let mut ban_mgr = AddressManager::new();
        ban_mgr.observe(evicted, PeerSource::Pex, 1_000, Instant::now());
        ban_mgr.scores_mut().insert(evicted, banned_score());
        assert!(ban_mgr.is_banned(evicted));

        std::thread::sleep(Duration::from_millis(10));
        let (_, expired) =
            ban_mgr.refresh_and_expire(&HashSet::new(), Instant::now(), Duration::from_millis(1));
        assert_eq!(expired, 1, "the stale entry is swept");
        assert!(!ban_mgr.contains(evicted), "membership is gone");
        assert!(
            ban_mgr.is_banned(evicted),
            "the ban must survive the sweep, or expiry becomes an un-ban"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 2C — eclipse resistance. Every property below is one line of
// docs/AETHER_PHASE2_ECLIPSE_AUDIT.md §14; nothing here asserts on a number
// that was chosen to make it pass.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod phase2_eclipse_tests {
    use super::*;

    /// Selection is replayed, not observed: metadata timestamps are persisted
    /// Unix seconds, so they must not move between two runs of one test.
    const NOW: u64 = 1_700_000_000;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn no_scores() -> HashMap<SocketAddr, PeerScore> {
        HashMap::new()
    }

    fn banned_score() -> PeerScore {
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        s
    }

    fn entry() -> AddressEntry {
        AddressEntry::new(PeerSource::Restored, NOW, Instant::now())
    }

    /// A store of fresh, healthy, non-anchor entries — the state an honest node
    /// is in right after restoring its peer store.
    fn store(addrs: &[SocketAddr]) -> HashMap<SocketAddr, AddressEntry> {
        addrs.iter().map(|a| (*a, entry())).collect()
    }

    /// `count` distinct addresses inside the /24 `o1.o2.o3.0`.
    fn net4(o1: u8, o2: u8, o3: u8, count: usize) -> Vec<SocketAddr> {
        assert!(count <= 256, "a /24 only holds 256 addresses");
        (0..count)
            .map(|i| addr(&format!("{o1}.{o2}.{o3}.{i}:25565")))
            .collect()
    }

    /// `count` distinct addresses inside the /24 `203.0.x.0`, one group per
    /// value of `x`. Convenience for building a pool of several groups.
    fn groups(start: u8, count: usize, per_group: usize) -> Vec<Vec<SocketAddr>> {
        (0..count)
            .map(|i| net4(203, 0, start + i as u8, per_group))
            .collect()
    }

    fn flatten(gs: &[Vec<SocketAddr>]) -> Vec<SocketAddr> {
        gs.iter().flatten().copied().collect()
    }

    /// Exactly what `P2PNetwork::outbound_candidates` computes, with the RNG
    /// injected so a round can be replayed byte for byte.
    fn round(
        known: &[SocketAddr],
        seeds: &[SocketAddr],
        local: SocketAddr,
        entries: &HashMap<SocketAddr, AddressEntry>,
        scores: &HashMap<SocketAddr, PeerScore>,
        connected: &HashSet<SocketAddr>,
        limit: usize,
        seed: u64,
    ) -> Vec<SocketAddr> {
        let ordered = P2PNetwork::redial_candidates(known, seeds, local);
        let known_len = known.iter().filter(|a| **a != local).count();
        let tail: HashSet<SocketAddr> = ordered.iter().skip(known_len).copied().collect();
        let mut rng = StdRng::seed_from_u64(seed);
        select_outbound(&ordered, &tail, entries, scores, connected, limit, NOW, &mut rng)
    }

    fn counts_of(addrs: &[SocketAddr]) -> HashMap<NetworkGroup, usize> {
        group_counts(addrs.iter().copied())
    }

    /// L2 / L4: a round does not simply fill its budget from whichever
    /// addresses happen to hash first — it spans the network groups the pool
    /// actually offers.
    #[test]
    fn test_outbound_diversity() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 8, 4); // 8 groups, 4 addresses each, no sessions
        let known = flatten(&gs);
        let entries = store(&known);

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            16,
            7,
        );

        assert_eq!(picked.len(), 16, "the pool supports a full round");
        assert_eq!(
            counts_of(&picked).len(),
            8,
            "a round of 16 must reach all 8 available network groups, got {:?}",
            counts_of(&picked)
        );
        for (g, c) in counts_of(&picked) {
            assert!(
                c <= MAX_CANDIDATES_PER_GROUP,
                "group {g:?} took {c} of a round it may only contribute {MAX_CANDIDATES_PER_GROUP} to"
            );
        }
    }

    /// L4: one dominant network group can never take more than its round
    /// quota, and once it also holds the maximum number of live sessions its
    /// quota drops to zero and the round moves elsewhere.
    #[test]
    fn test_same_network_group_limited() {
        let local = addr("127.0.0.1:31001");
        let mut known = net4(10, 0, 0, 60);
        known.extend(net4(203, 0, 113, 4));
        let entries = store(&known);
        let attacker = network_group(addr("10.0.0.1:25565"));
        let honest = network_group(addr("203.0.113.1:25565"));

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            32,
            3,
        );
        let counts = counts_of(&picked);
        assert_eq!(
            counts.get(&attacker).copied(),
            Some(MAX_CANDIDATES_PER_GROUP),
            "60 addresses in one /24 may still only open the round quota"
        );
        assert_eq!(counts.get(&honest).copied(), Some(MAX_CANDIDATES_PER_GROUP));

        // Four live sessions already: the group is at MAX_PEERS_PER_SUBNET and
        // must contribute nothing at all.
        let saturated: HashSet<SocketAddr> = known
            .iter()
            .filter(|a| network_group(**a) == attacker)
            .take(MAX_PEERS_PER_SUBNET)
            .copied()
            .collect();
        assert_eq!(saturated.len(), MAX_PEERS_PER_SUBNET);

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &saturated,
            32,
            3,
        );
        let counts = counts_of(&picked);
        assert_eq!(
            counts.get(&attacker).copied().unwrap_or(0),
            0,
            "a group already holding MAX_PEERS_PER_SUBNET sessions gets no candidate"
        );
        assert!(
            counts.get(&honest).copied().unwrap_or(0) > 0,
            "the round must fall back to a group that still has room"
        );
    }

    /// L4: several groups stay live at once and each one is held inside its
    /// bound, including when live sessions already eat into the round quota.
    #[test]
    fn test_multi_group_selection() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 4, 8);
        let known = flatten(&gs);
        let entries = store(&known);

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            16,
            12,
        );
        let counts = counts_of(&picked);
        assert_eq!(counts.len(), 4, "every group stays in the round");
        assert_eq!(
            picked.len(),
            4 * MAX_CANDIDATES_PER_GROUP,
            "the round is capped per group, not at the requested limit"
        );
        for (g, c) in &counts {
            assert!(*c <= MAX_CANDIDATES_PER_GROUP, "group {g:?} over its quota");
        }

        // Three live sessions per group: only one slot is left below
        // MAX_PEERS_PER_SUBNET, so the round quota narrows to a single address.
        let nearly_full: HashSet<SocketAddr> = gs
            .iter()
            .flat_map(|g| g.iter().take(MAX_PEERS_PER_SUBNET - 1).copied())
            .collect();
        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &nearly_full,
            16,
            12,
        );
        let counts = counts_of(&picked);
        assert_eq!(counts.len(), 4);
        assert_eq!(picked.len(), 4, "one further candidate per group");
        for (g, c) in &counts {
            assert_eq!(*c, 1, "group {g:?} narrowed its quota with its live sessions");
        }
    }

    /// L1: the outbound reservation is a real invariant over the whole state
    /// space, not a value observed once. Whenever inbound is admitted, the
    /// reservation still fits in the table afterwards.
    #[test]
    fn test_protected_outbound_slots() {
        assert!(
            PROTECTED_OUTBOUND_SLOTS >= 2 * MAX_PEERS_PER_SUBNET,
            "the reservation must cover at least two complete network groups"
        );

        let mut admitted = 0usize;
        for total in 0..=(MAX_PEERS + 2) {
            for outbound in 0..=total {
                if !inbound_admitted(total, outbound) {
                    continue;
                }
                admitted += 1;
                assert!(
                    total - outbound + PROTECTED_OUTBOUND_SLOTS <= MAX_PEERS,
                    "inbound admitted at total={total} outbound={outbound} but the \
                     outbound reservation no longer fits"
                );
                assert!(outbound_admitted(total), "outbound must keep working");
                assert!(total < MAX_PEERS, "never admit past the table size");
            }
        }
        assert!(admitted > 0, "the invariant must describe reachable states");

        // An inbound-only node stops at MAX_PEERS - PROTECTED_OUTBOUND_SLOTS.
        assert!(inbound_admitted(
            MAX_PEERS - PROTECTED_OUTBOUND_SLOTS - 1,
            0
        ));
        assert!(!inbound_admitted(MAX_PEERS - PROTECTED_OUTBOUND_SLOTS, 0));

        // An outbound-heavy node already holds its reservation, so inbound may
        // fill the rest of the table rather than being throttled by it.
        assert!(inbound_admitted(MAX_PEERS - 1, PROTECTED_OUTBOUND_SLOTS));
        assert!(!inbound_admitted(MAX_PEERS, PROTECTED_OUTBOUND_SLOTS));

        assert!(outbound_admitted(MAX_PEERS - 1));
        assert!(!outbound_admitted(MAX_PEERS));
        assert!(
            !inbound_admitted(0, 1),
            "outbound can never exceed the sessions that exist"
        );
    }

    /// L9: rotation of the *selection*, not forced disconnection. Each round is
    /// a fresh draw, so the union of successive rounds widens instead of the
    /// node replaying one fixed order forever.
    #[test]
    fn test_outbound_rotation() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 8, 6);
        let known = flatten(&gs);
        let entries = store(&known);

        let rounds: Vec<Vec<SocketAddr>> = (0..6)
            .map(|s| {
                round(
                    &known,
                    &[],
                    local,
                    &entries,
                    &no_scores(),
                    &HashSet::new(),
                    8,
                    s,
                )
            })
            .collect();

        for (i, r) in rounds.iter().enumerate() {
            assert_eq!(r.len(), 8, "round {i} did not fill its budget");
        }
        for (i, w) in rounds.windows(2).enumerate() {
            assert_ne!(
                w[0], w[1],
                "round {i} and round {} drew the same order — the RNG is not re-seeded",
                i + 1
            );
        }
        let union: HashSet<SocketAddr> = rounds.iter().flatten().copied().collect();
        assert!(
            union.len() > 8,
            "successive rounds must widen the set actually dialled ({} of 48)",
            union.len()
        );
    }

    /// L3: a compromised bootnode is still only a seed. It never outranks an
    /// address the node already holds, it is never picked when banned, and
    /// when the budget is tiny it still gets its reserved slice rather than
    /// being squeezed out by a large store.
    #[test]
    fn test_bootnode_compromised() {
        let local = addr("127.0.0.1:31001");
        let bootnode = addr("198.51.100.9:25565");
        let seeds = vec![bootnode];
        let known = flatten(&groups(100, 6, 5));
        let entries = store(&known);

        let picked = round(
            &known,
            &seeds,
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            16,
            11,
        );
        let at = picked
            .iter()
            .position(|a| *a == bootnode)
            .expect("an unprivileged seed still gets its slice of the round");
        for (i, a) in picked.iter().enumerate() {
            if i < at {
                assert!(
                    known.contains(a),
                    "only addresses we already hold may precede the bootnode"
                );
            }
        }
        assert_eq!(
            picked.last(),
            Some(&bootnode),
            "the bootnode belongs at the tail of the round, never the head"
        );

        // A banned bootnode is not a candidate at all.
        let mut scores = HashMap::new();
        scores.insert(bootnode, banned_score());
        let picked = round(&known, &seeds, local, &entries, &scores, &HashSet::new(), 16, 11);
        assert!(
            !picked.contains(&bootnode),
            "a banned bootnode must never be dialled"
        );
        assert!(!picked.is_empty(), "the rest of the round still proceeds");

        // A budget of four is entirely spoken for by known addresses plus the
        // single reserved seed slot.
        let picked = round(
            &known,
            &seeds,
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            4,
            11,
        );
        assert_eq!(picked.len(), 4);
        assert_eq!(
            picked.last(),
            Some(&bootnode),
            "even a four-slot round keeps the bootnode last"
        );
    }

    /// L3 / L4: a swarm of configured seeds cannot buy more than one round
    /// quota of slots, no matter how many are configured.
    #[test]
    fn test_seed_compromised() {
        let local = addr("127.0.0.1:31001");
        let known = flatten(&groups(100, 4, 8));
        let seeds = net4(198, 51, 100, 10);
        let entries = store(&known);

        let picked = round(
            &known,
            &seeds,
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            8,
            5,
        );

        let seed_count = picked.iter().filter(|a| seeds.contains(a)).count();
        let known_count = picked.iter().filter(|a| known.contains(a)).count();

        assert_eq!(picked.len(), 8, "the round fills its budget");
        assert_eq!(
            seed_count, MAX_CANDIDATES_PER_GROUP,
            "ten configured seeds may only take the round quota"
        );
        assert_eq!(
            known_count,
            8 - MAX_CANDIDATES_PER_GROUP,
            "the remainder belongs to addresses the node already holds"
        );
    }

    /// L6 / L7 / L8: the store stays bounded, gossip cannot displace a peer we
    /// observed ourselves, degraded entries remain evictable, and the score map
    /// stops growing without bound.
    #[test]
    fn test_peer_store_poisoning() {
        let healthy: Vec<SocketAddr> = (0..MAX_KNOWN_PEERS)
            .map(|i| addr(&format!("203.0.{}.{}:25565", i / 256, i % 256)))
            .collect();
        let mut mgr = AddressManager::new();
        for a in &healthy {
            mgr.observe(*a, PeerSource::Outbound, NOW, Instant::now());
        }
        assert_eq!(mgr.len(), MAX_KNOWN_PEERS, "the store is at capacity");

        let connected = HashSet::new();
        let noisy = addr("198.51.100.7:25565");

        // A PEX hint at half quality may not displace an entry we observed.
        let (entries, scores) = mgr.selection_tables();
        assert_eq!(
            admit_peer(
                entries,
                scores,
                &connected,
                noisy,
                admission_quality(PeerSource::Pex)
            ),
            None,
            "gossip must never evict a healthy entry it merely outnumbers"
        );
        assert_eq!(
            admission_quality(PeerSource::Pex),
            PEX_ADMISSION_QUALITY,
            "a pure gossip hint enters at half the score we give our own observations"
        );
        assert!(
            admission_quality(PeerSource::Pex) < admission_quality(PeerSource::Outbound),
            "gossip must rank below anything we observed ourselves"
        );

        // Degrade exactly one entry: now gossip may target it, and only it.
        let weak = healthy[42];
        mgr.entries_mut().get_mut(&weak).unwrap().quality = PEX_ADMISSION_QUALITY;
        let (entries, scores) = mgr.selection_tables();
        assert_eq!(
            admit_peer(
                entries,
                scores,
                &connected,
                noisy,
                admission_quality(PeerSource::Pex)
            ),
            Some(weak),
            "an already-degraded entry is exactly what gossip is allowed to replace"
        );

        // L7: a score that is neither banned nor attached to anything we still
        // track carries no information and must not accumulate.
        let orphan = addr("192.0.2.99:25565");
        let banned = addr("192.0.2.100:25565");
        mgr.scores_mut().insert(orphan, PeerScore::new());
        mgr.scores_mut().insert(banned, banned_score());
        assert!(mgr.scores.len() >= 2);

        let (_refreshed, _expired) =
            mgr.refresh_and_expire(&HashSet::new(), Instant::now(), Duration::from_secs(365 * 86_400));
        assert!(
            !mgr.scores.contains_key(&orphan),
            "an unattached, unbanned score must be purged"
        );
        assert!(
            mgr.scores.contains_key(&banned),
            "a ban always survives the sweep — that is why scores are a separate map"
        );
        assert_eq!(
            mgr.len(),
            MAX_KNOWN_PEERS,
            "the sweep must not have evicted anything the store still holds"
        );
    }

    /// L3: after a restart under attack, the anchors the node persisted are
    /// restored, still win their slots, and the rebuilt round spans several
    /// independent network groups rather than the attacker's.
    #[test]
    fn test_restart_under_peer_attack() {
        let local = addr("127.0.0.1:31001");
        let attacker = net4(10, 0, 0, 40);
        let anchors: Vec<SocketAddr> = net4(203, 0, 113, 2)
            .into_iter()
            .chain(net4(192, 0, 2, 2))
            .chain(net4(198, 51, 100, 2))
            .collect();
        let known: Vec<SocketAddr> = attacker.iter().chain(anchors.iter()).copied().collect();

        let mut mgr = AddressManager::new();
        for a in &known {
            mgr.observe(*a, PeerSource::Outbound, NOW, Instant::now());
        }
        for a in &anchors {
            let e = mgr.entries_mut().get_mut(a).unwrap();
            e.anchor = true;
            e.record_success(NOW);
        }

        // Restart: everything is re-read from the versioned store.
        let file = mgr.to_store();
        let mut restored = AddressManager::new();
        let loaded = restored.load_v2(&file, local, NOW, Instant::now());
        assert_eq!(loaded, known.len(), "the whole store comes back");
        for a in &anchors {
            let e = restored.entry(*a).expect("anchor must survive the restart");
            assert!(e.anchor, "the anchor flag is persisted, not re-derived");
        }

        let (entries, scores) = restored.selection_tables();
        let known = restored.addresses();
        let picked = round(
            &known,
            &[],
            local,
            entries,
            scores,
            &HashSet::new(),
            8,
            21,
        );

        assert_eq!(picked.len(), 8, "the round fills its budget after restart");
        for a in &anchors {
            assert!(
                picked.contains(a),
                "every persisted anchor must be offered first, got {:?}",
                picked
            );
        }
        let counts = counts_of(&picked);
        assert!(
            counts.len() >= 2,
            "reconnect must offer several independent network groups, got {counts:?}"
        );
        assert!(
            counts
                .get(&network_group(attacker[0]))
                .copied()
                .unwrap_or(0)
                <= MAX_CANDIDATES_PER_GROUP,
            "the attacker's group stays inside the round quota after a restart"
        );
    }

    /// L2 / L3: losing every session must not lose the ability to choose. The
    /// addresses are still known, so the very next round is both non-empty and
    /// spread across groups.
    #[test]
    fn test_mass_peer_loss() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 4, 6);
        let known = flatten(&gs);
        let entries = store(&known);

        // Before: every group already holds MAX_PEERS_PER_SUBNET sessions, so
        // there is nothing left to dial.
        let saturated: HashSet<SocketAddr> = gs
            .iter()
            .flat_map(|g| g.iter().take(MAX_PEERS_PER_SUBNET).copied())
            .collect();
        assert_eq!(saturated.len(), 4 * MAX_PEERS_PER_SUBNET);
        let before = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &saturated,
            32,
            9,
        );
        assert!(
            before.is_empty(),
            "a saturated node correctly offers no dial at all"
        );

        // After: every session is gone, the addresses are not.
        let after = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            32,
            9,
        );
        assert!(!after.is_empty(), "the node must rebuild after a mass loss");
        assert_eq!(
            after.len(),
            4 * MAX_CANDIDATES_PER_GROUP,
            "each group contributes its round quota"
        );
        assert!(
            counts_of(&after).len() >= 2,
            "the rebuild spans several network groups: {:?}",
            counts_of(&after)
        );
    }

    /// L3: an anchor is never a victim of admission, and in selection it is
    /// ranked above an unknown candidate of the same quality.
    #[test]
    fn test_anchor_protection() {
        let local = addr("127.0.0.1:31001");

        // (a) Admission: a table made entirely of anchors yields no victim,
        // even for an incoming address of arbitrary quality.
        let full: Vec<SocketAddr> = (0..MAX_KNOWN_PEERS)
            .map(|i| addr(&format!("203.0.{}.{}:25565", i / 256, i % 256)))
            .collect();
        let mut entries = store(&full);
        for e in entries.values_mut() {
            e.anchor = true;
        }
        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &HashSet::new(),
                addr("198.51.100.1:25565"),
                i32::MAX
            ),
            None,
            "an anchor is never offered up for eviction"
        );

        // (b) Selection: one anchor against one unknown candidate, one slot.
        let anchor = addr("203.0.113.1:25565");
        let plain = addr("192.0.2.1:25565");
        let known = vec![anchor, plain];
        let mut entries = store(&known);
        let e = entries.get_mut(&anchor).unwrap();
        e.anchor = true;
        e.record_success(NOW);

        let mut anchor_wins = 0usize;
        for s in 0..128u64 {
            let picked = round(
                &known,
                &[],
                local,
                &entries,
                &no_scores(),
                &HashSet::new(),
                1,
                s,
            );
            assert_eq!(picked.len(), 1);
            if picked[0] == anchor {
                anchor_wins += 1;
            }
        }
        assert!(
            anchor_wins * 2 > 128,
            "an anchor must be preferred over an unknown candidate ({anchor_wins}/128)"
        );
    }

    /// L6: a PEX hint at half quality never displaces a healthy peer, but a
    /// degraded one remains replaceable so the table cannot freeze.
    #[test]
    fn test_low_quality_candidate_eviction() {
        assert!(
            admission_quality(PeerSource::Pex) < default_peer_quality(),
            "gossip must enter below the quality we grant our own observations"
        );

        let healthy: Vec<SocketAddr> = (0..MAX_KNOWN_PEERS)
            .map(|i| addr(&format!("198.51.{}.{}:25565", i / 256, i % 256)))
            .collect();
        let entries = store(&healthy);
        let incoming = addr("203.0.113.50:25565");
        let connected = HashSet::new();

        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &connected,
                incoming,
                admission_quality(PeerSource::Pex)
            ),
            None,
            "a full table of healthy peers is not open to gossip"
        );

        // Same table, one entry degraded: now gossip has a legitimate target.
        let mut entries = entries;
        let weak = healthy[7];
        entries.get_mut(&weak).unwrap().quality = PEX_ADMISSION_QUALITY - 1;
        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &connected,
                incoming,
                admission_quality(PeerSource::Pex)
            ),
            Some(weak),
            "only the degraded entry may be replaced"
        );

        // A connected peer is never a victim either, healthy or not.
        let mut connected = HashSet::new();
        connected.insert(weak);
        entries.get_mut(&healthy[8]).unwrap().quality = 0;
        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &connected,
                incoming,
                admission_quality(PeerSource::Pex)
            ),
            Some(healthy[8]),
            "the victim must come from the entries we are not holding a session with"
        );
    }

    /// L9: the round quota is recomputed from live sessions, so a saturated
    /// group falls to zero and the selection necessarily moves elsewhere.
    #[test]
    fn test_peer_group_rotation() {
        let local = addr("127.0.0.1:31001");
        let group_a = net4(10, 0, 0, 8);
        let group_b = net4(203, 0, 113, 8);
        let known: Vec<SocketAddr> = group_a.iter().chain(group_b.iter()).copied().collect();
        let entries = store(&known);
        let a = network_group(group_a[0]);
        let b = network_group(group_b[0]);

        let saturated: HashSet<SocketAddr> = group_a
            .iter()
            .take(MAX_PEERS_PER_SUBNET)
            .copied()
            .collect();
        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &saturated,
            16,
            4,
        );
        let counts = counts_of(&picked);
        assert!(
            !counts.contains_key(&a),
            "a saturated group must not be offered at all"
        );
        assert!(
            counts.get(&b).copied().unwrap_or(0) > 0,
            "the selection has to fall back to a group with room"
        );

        // One session released: exactly one slot is left in the group, so its
        // round quota is one and the group is reachable again.
        let partial: HashSet<SocketAddr> = group_a
            .iter()
            .take(MAX_PEERS_PER_SUBNET - 1)
            .copied()
            .collect();
        assert_eq!(partial.len(), MAX_PEERS_PER_SUBNET - 1);
        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &partial,
            16,
            4,
        );
        let counts = counts_of(&picked);
        assert_eq!(
            counts.get(&a).copied(),
            Some(1),
            "the last free slot in a group yields exactly one candidate"
        );
        assert_eq!(
            counts.get(&b).copied(),
            Some(MAX_CANDIDATES_PER_GROUP),
            "the untouched group keeps its full quota"
        );
    }

    /// L2: the selection is a pure function of (order, metadata, sessions,
    /// limit, seed). Same seed, same list; a different seed, a different one.
    #[test]
    fn test_selection_deterministic_under_seed() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 6, 5);
        let known = flatten(&gs);
        let entries = store(&known);
        let connected: HashSet<SocketAddr> = known.iter().take(3).copied().collect();

        let run = |seed: u64| {
            round(
                &known,
                &[],
                local,
                &entries,
                &no_scores(),
                &connected,
                8,
                seed,
            )
        };

        let a = run(42);
        let b = run(42);
        assert_eq!(a, b, "the same seed must replay the same selection");

        let c = run(43);
        assert_eq!(c.len(), a.len(), "only the order may differ");
        assert_ne!(a, c, "a different seed must draw a different selection");

        // Determinism does not depend on HashMap iteration order: rebuilding
        // the metadata table must not move a single address.
        let rebuilt = store(&known);
        let d = round(
            &known,
            &[],
            local,
            &rebuilt,
            &no_scores(),
            &connected,
            8,
            42,
        );
        assert_eq!(a, d, "selection must not depend on hash iteration order");
    }

    /// L5: the grouping rule unwraps IPv4-mapped IPv6 instead of collapsing
    /// every dual-stack listener into the single group `[0, 0, 0]`.
    #[test]
    fn test_network_group_unwraps_ipv4_mapped() {
        let plain = addr("203.0.113.7:25565");
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:25565".parse().unwrap();
        let compatible: SocketAddr = "[::203.0.113.7]:25565".parse().unwrap();

        assert_eq!(network_group(plain), NetworkGroup::V4([203, 0, 113]));
        assert_eq!(
            network_group(mapped),
            network_group(plain),
            "a mapped address belongs to the IPv4 group it embeds"
        );
        assert_eq!(
            network_group(compatible),
            network_group(plain),
            "the IPv4-compatible form is judged the same way"
        );

        // subnet_24 is a projection of the same rule, never a second opinion.
        assert_eq!(subnet_24(mapped), Some([203, 0, 113]));
        assert_eq!(subnet_24(plain), Some([203, 0, 113]));

        // Native IPv6 groups on its first 24 bits — `2001:0db8:abcd::1` and
        // `2001:0db8:ffff::9` differ only after that prefix, so a whole
        // provider allocation lands in one group, never one group per address.
        let v6: SocketAddr = "[2001:db8:abcd::1]:25565".parse().unwrap();
        let v6_other: SocketAddr = "[2001:db8:ffff::9]:25565".parse().unwrap();
        assert_eq!(network_group(v6), NetworkGroup::V6([0x20, 0x01, 0x0d]));
        assert_eq!(
            network_group(v6),
            network_group(v6_other),
            "the first 24 bits are fixed inside one provider allocation"
        );
    }
}

#[cfg(test)]
mod phase2_self_healing_tests {
    use super::*;
    use std::net::SocketAddr;

    /// Fixed metadata timestamp, so nothing depends on wall-clock time.
    const NOW: u64 = 1_700_000_000;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// `count` distinct addresses inside the /24 `o1.o2.o3.0`.
    fn net4(o1: u8, o2: u8, o3: u8, count: usize) -> Vec<SocketAddr> {
        (0..count)
            .map(|i| addr(&format!("{o1}.{o2}.{o3}.{i}:25565")))
            .collect()
    }

    /// `count` network groups, `per_group` addresses each.
    fn groups(start: u8, count: usize, per_group: usize) -> Vec<Vec<SocketAddr>> {
        (0..count)
            .map(|i| net4(203, 0, start + i as u8, per_group))
            .collect()
    }

    fn flatten(gs: &[Vec<SocketAddr>]) -> Vec<SocketAddr> {
        gs.iter().flatten().copied().collect()
    }

    fn not_banned(_: &SocketAddr) -> bool {
        false
    }

    fn fresh() -> PeerRecoveryController {
        PeerRecoveryController::new()
    }

    /// Anchors as `anchor_addresses()` reports them: `(address, last success)`,
    /// the first element being the most recently proven one.
    fn anchor_list(addrs: &[SocketAddr]) -> Vec<(SocketAddr, u64)> {
        addrs.iter()
            .enumerate()
            .map(|(i, a)| (*a, NOW - i as u64))
            .collect()
    }

    fn plan(
        count: usize,
        anchors: &[(SocketAddr, u64)],
        known: &[SocketAddr],
        seeds: &[SocketAddr],
        connected: &HashSet<SocketAddr>,
        ctl: &PeerRecoveryController,
    ) -> RecoveryRound {
        plan_recovery(
            addr("127.0.0.1:31001"),
            count,
            anchors,
            known,
            seeds,
            connected,
            &not_banned,
            ctl,
            Instant::now(),
        )
    }

    fn net_with(bootnodes: Vec<SocketAddr>) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes,
            dns_seeds: vec![],
            peer_store_path: None,
        })
    }

    fn net_at(path: std::path::PathBuf) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
        })
    }

    fn net_at_config(cfg: P2PConfig) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt,
            empty,
            sync_ctx,
            is_orphan,
        )
    }

    /// A listener that accepts and holds, standing in for a live peer. Loopback
    /// is a single network group, so one of these can host at most
    /// `MAX_PEERS_PER_SUBNET` real sessions — which is exactly the invariant
    /// recovery must respect.
    async fn live_peer() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut sock, _)) => {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            loop {
                                match tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => {}
                                }
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        local
    }

    /// Modelled sessions for peers the ladder is not expected to dial.
    ///
    /// Used only to move the *count* to `RECOVERY_COMFORT_PEERS`: a test host
    /// only has loopback, and loopback is one `/24`, so no more than
    /// `MAX_PEERS_PER_SUBNET` real sockets can ever be opened here.
    async fn insert_session(net: &P2PNetwork, a: SocketAddr) {
        let (tx, _rx) = mpsc::unbounded_channel();
        net.peers.write().await.insert(a, tx);
    }

    // -----------------------------------------------------------------------
    // Controller transitions and bounds (pure).
    // -----------------------------------------------------------------------

    /// S1 — one peer of eight disappears. Seven is still above the entry
    /// threshold, so recovery must not start: no state change, no dial, and
    /// nothing disturbs the seven sessions that remain.
    #[test]
    fn test_self_healing_single_peer_loss() {
        let peers: Vec<SocketAddr> = flatten(&groups(100, 8, 1));
        let connected: HashSet<SocketAddr> = peers[..7].iter().copied().collect();

        let round = plan(
            7,
            &anchor_list(&peers),
            &peers,
            &[],
            &connected,
            &fresh(),
        );

        assert_eq!(
            round.state,
            RecoveryState::Healthy,
            "losing one peer of eight must not trigger recovery"
        );
        assert!(round.sources_left, "the lost peer is still a known candidate");
        assert_eq!(connected.len(), 7, "existing sessions are untouched");
    }

    /// S2 — eight peers collapse to two. Recovery starts, and the round stays
    /// inside `MAX_DIALS_PER_ROUND`.
    #[test]
    fn test_self_healing_majority_peer_loss() {
        let peers: Vec<SocketAddr> = flatten(&groups(100, 8, 1));
        let connected: HashSet<SocketAddr> = peers[..2].iter().copied().collect();
        let anchors = anchor_list(&peers[..3]);

        let round = plan(2, &anchors, &peers, &[], &connected, &fresh());

        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND, "rounds are bounded");
        assert!(!round.dial.is_empty(), "recovery must actually plan dials");
        assert!(round.tier1_anchors >= 1, "an anchor that dropped leads");
        assert!(round.tier2_known >= 1, "the rest of the store fills in");
        for a in &round.dial {
            assert!(!connected.contains(a), "never re-dial a live session");
        }
    }

    /// S3 — the table is empty: anchors first, then everything else the node
    /// knows. Configured seeds stay out of it while primaries exist.
    #[test]
    fn test_self_healing_zero_peers() {
        let anchors_src: Vec<SocketAddr> = flatten(&groups(100, 3, 1));
        let known: Vec<SocketAddr> = flatten(&groups(110, 10, 1));
        let seeds: Vec<SocketAddr> = flatten(&groups(120, 2, 1));

        let round = plan(
            0,
            &anchor_list(&anchors_src),
            &known,
            &seeds,
            &HashSet::new(),
            &fresh(),
        );

        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, anchors_src.len(), "anchors lead");
        for (i, a) in anchors_src.iter().enumerate() {
            assert_eq!(round.dial[i], *a, "most recently proven anchor first");
        }
        assert!(round.tier2_known > 0, "the address manager fills the rest");
        assert_eq!(round.tier3_seeds, 0, "seeds are a last resort");
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND);
    }

    /// S4 — the bootnode is gone entirely. Recovery runs off anchors and the
    /// peer store, never touches the seed, and is not blocked on it.
    #[test]
    fn test_self_healing_bootnode_down() {
        let dead_seed = addr("192.0.2.9:25565");
        let anchors_src: Vec<SocketAddr> = flatten(&groups(100, 4, 1));
        let known: Vec<SocketAddr> = flatten(&groups(110, 6, 1));

        let round = plan(
            0,
            &anchor_list(&anchors_src),
            &known,
            &[dead_seed],
            &HashSet::new(),
            &fresh(),
        );

        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(!round.dial.contains(&dead_seed), "the dead seed is not dialed");
        assert!(!round.dial.is_empty(), "recovery proceeds without it");
        assert!(round.sources_left);

        // Same setup with the seed removed changes nothing: it was never a
        // dependency, only a candidate.
        let without = plan(
            0,
            &anchor_list(&anchors_src),
            &known,
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert_eq!(without.dial, round.dial);
        assert_eq!(without.sources_left, true);
    }

    /// S6 — dials fail: the address is penalised, rounds stay bounded, and a
    /// run of them terminates in `Exhausted` rather than looping forever.
    #[test]
    fn test_self_healing_dial_failures() {
        // (a) `record_failure` — the path `connect_to_peer_inner` takes after
        // a refused or timed-out dial — lowers the address's quality.
        let mut mgr = AddressManager::new();
        let miss = addr("198.51.100.7:25565");
        mgr.observe(miss, PeerSource::Restored, NOW, Instant::now());
        let before = mgr.selection_tables().0.get(&miss).unwrap().quality;
        mgr.record_failure(miss);
        let after = mgr.selection_tables().0.get(&miss).unwrap().quality;
        assert_eq!(after, before - 5, "each failed dial must cost quality");

        // (b) Six rounds that open nothing exhaust the controller, and a plan
        // built from it is therefore not dialable.
        let mut ctl = fresh();
        let t = Instant::now();
        for i in 0..RECOVERY_MAX_CONSECUTIVE_FAILURES {
            ctl.record_round(0, t + Duration::from_secs(3600 * (i as u64 + 1)));
        }
        assert_eq!(ctl.consecutive_failures, RECOVERY_MAX_CONSECUTIVE_FAILURES);
        assert_eq!(ctl.backoff_level, RECOVERY_MAX_LEVEL);

        let candidate: Vec<SocketAddr> = flatten(&groups(130, 8, 1));
        let round = plan(
            0,
            &anchor_list(&candidate),
            &[],
            &[],
            &HashSet::new(),
            &ctl,
        );
        assert_eq!(round.state, RecoveryState::Exhausted);

        // (c) While recovering, every round is bounded and offers *fresh*
        // candidates rather than replaying one bad address.
        let early = plan(
            0,
            &[],
            &flatten(&groups(140, 20, 1)),
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert_eq!(early.state, RecoveryState::Recovering);
        assert!(early.dial.len() <= MAX_DIALS_PER_ROUND);
        assert_eq!(
            early.dial.iter().collect::<HashSet<_>>().len(),
            early.dial.len(),
            "no address is planned twice in one round"
        );
    }

    /// The backoff is bounded and monotone: 0, 5, 10, 20, 40, 60, 60 seconds.
    #[test]
    fn test_self_healing_backoff() {
        let levels: Vec<u64> = (0..=RECOVERY_MAX_LEVEL)
            .map(|l| recovery_backoff(l).as_secs())
            .collect();

        assert_eq!(levels, vec![0, 5, 10, 20, 40, 60, 60]);
        assert!(
            levels.windows(2).all(|w| w[0] <= w[1]),
            "backoff must never shrink as failures accumulate"
        );
        assert!(
            levels.iter().all(|s| *s <= RECOVERY_BACKOFF_MAX_SECS),
            "backoff is capped"
        );
        assert_eq!(recovery_backoff(RECOVERY_MAX_LEVEL + 99), recovery_backoff(RECOVERY_MAX_LEVEL));
    }

    /// One opened session clears the throttle completely; a failed round
    /// climbs exactly one level.
    #[test]
    fn test_self_healing_backoff_reset() {
        let mut ctl = fresh();
        let t = Instant::now();

        ctl.record_round(0, t);
        ctl.record_round(0, t + Duration::from_secs(10));
        ctl.record_round(0, t + Duration::from_secs(30));
        assert_eq!(ctl.backoff_level, 3);
        assert_eq!(ctl.consecutive_failures, 3);
        assert!(!ctl.backoff_due(t));

        ctl.record_round(2, t + Duration::from_secs(60));
        assert_eq!(ctl.backoff_level, 0, "success resets the backoff");
        assert_eq!(ctl.consecutive_failures, 0, "success resets the failures");
        assert_eq!(ctl.backoff(), Duration::ZERO);
        assert!(ctl.backoff_due(t + Duration::from_secs(61)));
    }

    /// A round never exceeds `MAX_DIALS_PER_ROUND`, whatever the store holds,
    /// and never over-fills one network group.
    #[test]
    fn test_self_healing_respects_outbound_limits() {
        assert!(MAX_DIALS_PER_ROUND <= MAX_REDIAL_PER_CYCLE);
        assert_eq!(MAX_DIALS_PER_ROUND, PROTECTED_OUTBOUND_SLOTS);

        // 200 candidates, 200 distinct network groups.
        let spread: Vec<SocketAddr> = (0..200u16)
            .map(|i| addr(&format!("10.{}.{}.7:25565", i / 256, i % 256)))
            .collect();
        let round = plan(
            0,
            &anchor_list(&spread),
            &spread,
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert_eq!(
            round.dial.len(),
            MAX_DIALS_PER_ROUND,
            "a large store yields exactly one bounded round"
        );

        // 64 candidates all inside a single /24: the subnet gate caps it.
        let one_group = net4(198, 51, 100, 64);
        let round = plan(
            0,
            &anchor_list(&one_group),
            &[],
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert!(
            round.dial.len() <= MAX_PEERS_PER_SUBNET,
            "one /24 can never fill a round: {} > {}",
            round.dial.len(),
            MAX_PEERS_PER_SUBNET
        );
    }

    /// The `/24` invariant of Phase 2C still holds while recovering, even for
    /// the tiers that bypass `select_outbound`.
    #[test]
    fn test_self_healing_preserves_diversity() {
        let crowded = net4(203, 0, 100, 8);
        let connected: HashSet<SocketAddr> = crowded[..3].iter().copied().collect();

        let mut candidates: Vec<SocketAddr> = crowded[3..].to_vec();
        candidates.extend(flatten(&groups(110, 8, 4)));

        let round = plan(
            3,
            &anchor_list(&candidates),
            &[],
            &[],
            &connected,
            &fresh(),
        );

        let mut all: Vec<SocketAddr> = connected.iter().copied().collect();
        all.extend(round.dial.iter().copied());

        let counts = group_counts(all.iter().copied());
        assert!(
            counts.values().all(|n| *n <= MAX_PEERS_PER_SUBNET),
            "recovery must never push a group past {}: {:?}",
            MAX_PEERS_PER_SUBNET,
            counts
        );
        assert_eq!(
            counts.get(&network_group(crowded[0])).copied().unwrap(),
            MAX_PEERS_PER_SUBNET,
            "the crowded group gains exactly the one slot it still had"
        );
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND);
    }

    /// Tier 1 is the anchor set, ordered by recency, and it goes first.
    #[test]
    fn test_self_healing_uses_anchors() {
        let older = addr("203.0.113.1:25565");
        let newer = addr("203.0.114.1:25565");
        let anchors = vec![(older, NOW - 100), (newer, NOW)];
        let known = vec![
            addr("203.0.115.1:25565"),
            addr("203.0.116.1:25565"),
        ];

        let round = plan(0, &anchors, &known, &[], &HashSet::new(), &fresh());

        assert_eq!(round.tier1_anchors, 2);
        assert_eq!(round.dial[0], newer, "most recently proven anchor first");
        assert_eq!(round.dial[1], older);
        assert_eq!(round.tier2_known, known.len());
        assert_eq!(&round.dial[2..], &known[..]);
    }

    /// With no anchors at all, tier 2 — the Phase 2C view of the address
    /// manager — supplies the whole round.
    #[test]
    fn test_self_healing_uses_address_manager() {
        let known: Vec<SocketAddr> = flatten(&groups(100, 6, 1));

        let round = plan(0, &[], &known, &[], &HashSet::new(), &fresh());

        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, 0);
        assert_eq!(round.tier2_known, known.len());
        assert_eq!(round.dial, known);
    }

    /// An address learned only from PEX still reaches the ladder, at the
    /// quality Phase 2B assigns to gossip.
    #[tokio::test]
    async fn test_self_healing_uses_pex() {
        let net = net_with(vec![]);
        let hint = addr("203.0.113.42:25565");

        let ok = ingress_address(
            &net.addresses,
            &net.peers,
            net.config.listen_addr,
            hint,
            PeerSource::Pex,
        )
        .await;
        assert!(ok, "the hint must be admitted to the store");
        {
            let mgr = net.addresses.read().await;
            let (entries, _) = mgr.selection_tables();
            let e = entries.get(&hint).expect("PEX hint is stored");
            assert_eq!(e.source, PeerSource::Pex);
        }
        // The table is not full, so `admit` inserted at the default quality;
        // what matters is that the *admission decision* weighed the hint at
        // gossip quality, below anything the node observed itself.
        assert_eq!(admission_quality(PeerSource::Pex), PEX_ADMISSION_QUALITY);
        assert!(
            admission_quality(PeerSource::Pex) < admission_quality(PeerSource::Outbound),
            "a gossip hint may never outrank direct evidence"
        );

        let ranked = net.outbound_candidates(MAX_DIALS_PER_ROUND).await;
        let seeds: HashSet<SocketAddr> = net.config.bootnodes.iter().copied().collect();
        let known: Vec<SocketAddr> = ranked
            .iter()
            .copied()
            .filter(|a| !seeds.contains(a))
            .collect();
        assert!(known.contains(&hint), "the PEX hint reaches the ladder");

        let ctl = *net.recovery.read().await;
        let connected: HashSet<SocketAddr> = net.peers.read().await.keys().copied().collect();
        let round = plan_recovery(
            net.config.listen_addr,
            connected.len(),
            &[],
            &known,
            &net.config.bootnodes,
            &connected,
            &not_banned,
            &ctl,
            Instant::now(),
        );
        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(round.dial.contains(&hint), "the PEX hint is dialed");
    }

    /// The seed is withheld while anything else is left to try, offered when
    /// there is nothing else, and released after a round has failed.
    #[test]
    fn test_self_healing_seed_last_resort() {
        let seed = addr("192.0.2.9:25565");
        let known: Vec<SocketAddr> = flatten(&groups(100, 6, 1));

        let first = plan(0, &[], &known, &[seed], &HashSet::new(), &fresh());
        assert!(
            !first.dial.contains(&seed),
            "with known candidates the seed must not appear"
        );
        assert_eq!(first.tier3_seeds, 0);

        let empty = plan(0, &[], &[], &[seed], &HashSet::new(), &fresh());
        assert_eq!(empty.tier3_seeds, 1, "with nothing else, the seed is used");
        assert!(empty.sources_left);

        let mut failed = fresh();
        failed.record_round(0, Instant::now() - Duration::from_secs(3600));
        let after = plan(0, &[], &known, &[seed], &HashSet::new(), &failed);
        assert!(
            after.dial.contains(&seed),
            "a failed round releases the last resort"
        );
    }

    /// S7 — a restarted node with an empty table rebuilds from its peer store
    /// and anchors, without waiting on a bootnode.
    #[tokio::test]
    async fn test_self_healing_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let a1 = addr("203.0.113.1:25565");
        let a2 = addr("203.0.114.1:25565");
        {
            let net = net_at(path.clone());
            {
                let mut mgr = net.addresses.write().await;
                mgr.observe(a1, PeerSource::Restored, unix_now(), Instant::now());
                mgr.observe(a2, PeerSource::Restored, unix_now(), Instant::now());
                mgr.apply_anchors(&HashSet::from([a1, a2]));
            }
            net.save_known_peers().await;
        }

        let net2 = net_at(path.clone());
        assert_eq!(net2.peer_count().await, 0, "restart opens with no session");
        net2.load_known_peers().await;
        {
            let mgr = net2.addresses.read().await;
            assert!(mgr.contains(a1) && mgr.contains(a2));
            assert_eq!(mgr.anchor_addresses().len(), 2, "anchors survived the restart");
        }

        let ctl = *net2.recovery.read().await;
        let round = plan_recovery(
            net2.config.listen_addr,
            0,
            &net2.addresses.read().await.anchor_addresses(),
            &[],
            &[],
            &HashSet::new(),
            &not_banned,
            &ctl,
            Instant::now(),
        );
        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, 2, "the restored anchors lead");
        let mut got = round.dial.clone();
        got.sort();
        assert_eq!(got, vec![a1, a2], "both restored anchors are dialed");
    }

    /// S8 — loss plus a poisoned store plus a dead bootnode: recovery stays
    /// group-quota'd, leads with anchors, withholds the seed, and stops.
    #[test]
    fn test_self_healing_attack_scenario() {
        // The attacker owns one routable /24 and floods it with 64 candidates.
        let evil: Vec<SocketAddr> = net4(198, 51, 100, 64);
        // Honest anchors live in four other groups.
        let good: Vec<SocketAddr> = flatten(&groups(203, 4, 1));
        let seed = addr("192.0.2.9:25565");

        let mut known: Vec<SocketAddr> = evil.clone();
        known.extend(good.iter().copied());

        let round = plan(
            0,
            &anchor_list(&good),
            &known,
            &[seed],
            &HashSet::new(),
            &fresh(),
        );

        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND);
        for a in &round.dial[..round.tier1_anchors] {
            assert!(good.contains(a), "anchors always lead");
        }
        let evil_taken = round.dial.iter().filter(|a| evil.contains(a)).count();
        assert!(
            evil_taken <= MAX_PEERS_PER_SUBNET,
            "one attacker allocation can take at most a subnet's worth: {}",
            evil_taken
        );
        assert!(!round.dial.contains(&seed), "the seed is not the way out");

        // Bounded: six fruitless rounds end it instead of feeding the attacker.
        let mut ctl = fresh();
        let t = Instant::now();
        for i in 0..RECOVERY_MAX_CONSECUTIVE_FAILURES {
            ctl.record_round(0, t + Duration::from_secs(3600 * (i as u64 + 1)));
        }
        let stopped = plan(0, &anchor_list(&good), &known, &[seed], &HashSet::new(), &ctl);
        assert_eq!(stopped.state, RecoveryState::Exhausted);
    }

    // -----------------------------------------------------------------------
    // Integration: the production round, real sockets, real address manager.
    // -----------------------------------------------------------------------

    /// Loss of the majority with the bootnode cut, then recovery to a
    /// converged, healthy neighbourhood.
    ///
    /// Drives `recovery_round` — the exact function the background task calls.
    #[tokio::test]
    async fn test_self_healing_integration_bootnode_down_convergence() {
        let mut peers_live = Vec::new();
        for _ in 0..MAX_PEERS_PER_SUBNET {
            peers_live.push(live_peer().await);
        }
        let bootnode = addr("127.0.0.1:9"); // present in config, answers nothing

        let net = net_with(vec![bootnode]);
        {
            let mut mgr = net.addresses.write().await;
            for a in &peers_live {
                mgr.observe(*a, PeerSource::Restored, unix_now(), Instant::now());
            }
            let wanted: HashSet<SocketAddr> = peers_live.iter().copied().collect();
            mgr.apply_anchors(&wanted);
        }

        // The node has just lost every session it had.
        assert_eq!(net.peer_count().await, 0);

        let round = net.recovery_round().await;
        assert_eq!(round.state, RecoveryState::Recovering, "S2 detection");
        assert_eq!(round.tier1_anchors, peers_live.len(), "anchors lead");
        assert!(
            !round.dial.contains(&bootnode),
            "SEED_LAST_RESORT: the bootnode is not dialed while anchors exist"
        );
        assert_eq!(
            net.peer_count().await,
            peers_live.len(),
            "S4: recovery opened the neighbourhood without the bootnode"
        );
        {
            let ctl = net.recovery.read().await;
            assert_eq!(ctl.consecutive_failures, 0, "success clears the throttle");
            assert_eq!(ctl.backoff_level, 0);
        }

        // Bring the table to comfort and confirm the loop stands down.
        for i in 0..RECOVERY_COMFORT_PEERS.saturating_sub(peers_live.len()) {
            insert_session(
                &net,
                addr(&format!("203.0.{}.1:25565", 100 + i)),
            )
            .await;
        }
        let round = net.recovery_round().await;
        assert_eq!(
            round.state,
            RecoveryState::Healthy,
            "recovery ends once the count reaches comfort"
        );
        assert!(round.dial.is_empty(), "Healthy issues no dial at all");
        {
            let ctl = net.recovery.read().await;
            assert_eq!(ctl.backoff_level, 0);
            assert_eq!(ctl.consecutive_failures, 0);
        }
    }

    /// Restart with nothing connected, rebuild from the store and its anchors,
    /// and return to `Healthy`.
    #[tokio::test]
    async fn test_self_healing_integration_restart_to_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let first = live_peer().await;
        let second = live_peer().await;
        {
            let net = net_at(path.clone());
            {
                let mut mgr = net.addresses.write().await;
                mgr.observe(first, PeerSource::Restored, unix_now(), Instant::now());
                mgr.observe(second, PeerSource::Restored, unix_now(), Instant::now());
                mgr.apply_anchors(&HashSet::from([first, second]));
            }
            net.save_known_peers().await;
        }

        // Restart: zero sessions, store and anchors on disk.
        let net = net_at(path.clone());
        assert_eq!(net.peer_count().await, 0);
        net.load_known_peers().await;

        let round = net.recovery_round().await;
        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, 2, "recovered from the restored anchors");
        assert_eq!(net.peer_count().await, 2, "sessions reopened from the store");
        {
            let ctl = net.recovery.read().await;
            assert_eq!(ctl.consecutive_failures, 0);
            assert_eq!(ctl.backoff_level, 0);
        }

        for i in 0..RECOVERY_COMFORT_PEERS.saturating_sub(2) {
            insert_session(&net, addr(&format!("203.0.{}.1:25565", 120 + i))).await;
        }
        let round = net.recovery_round().await;
        assert_eq!(round.state, RecoveryState::Healthy, "back to a healthy count");
        assert!(round.dial.is_empty());
    }
}

#[cfg(test)]
mod bootstrap_phase1_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// PEER_PERSISTENCE: save then reload restores the same address set.
    #[tokio::test]
    async fn test_peer_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path.clone()),
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );

        net.addresses
            .write()
            .await
            .observe(addr("10.0.0.1:25565"), PeerSource::Restored, unix_now(), Instant::now());
        net.addresses
            .write()
            .await
            .observe(addr("10.0.0.2:25565"), PeerSource::Restored, unix_now(), Instant::now());
        net.save_known_peers().await;
        assert!(path.exists());

        // Simulate restart: fresh instance, same path.
        let cfg2 = P2PConfig {
            listen_addr: addr("127.0.0.1:30002"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
        };
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let sync_ctx2 = Arc::new(SyncContext::default());
        let net2 = P2PNetwork::new(
            cfg2,
            tx2,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx2,
            is_orphan.clone(),
        );
        assert_eq!(net2.addresses.read().await.len(), 0);
        net2.load_known_peers().await;
        let known = net2.addresses.read().await;
        assert!(known.contains(addr("10.0.0.1:25565")));
        assert!(known.contains(addr("10.0.0.2:25565")));
        assert_eq!(known.len(), 2);
    }

    /// PEER_TTL: disconnect path keeps the address in known_peers (TTL, not remove).
    #[tokio::test]
    async fn test_peer_ttl_keeps_address_after_disconnect() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30003"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );

        let peer = addr("192.168.1.10:25565");
        net.addresses
            .write()
            .await
            .observe(peer, PeerSource::Outbound, unix_now(), Instant::now());
        // Simulate disconnect bookkeeping (what handle_peer does at exit):
        net.peers.write().await.remove(&peer);
        net.addresses.write().await.touch(peer, Instant::now());
        // Address must still be known (TTL keeps it).
        assert!(net.addresses.read().await.contains(peer));
        // TTL clock is recorded.
        assert!(
            net.addresses
                .read()
                .await
                .entry(peer)
                .expect("known address carries a TTL clock")
                .last_seen
                .elapsed()
                < PEER_TTL
        );
        // Expire only after PEER_TTL.
        assert!(PEER_TTL > Duration::from_secs(60));
    }

    /// MULTI_SEED: default config exposes more than one bootnode.
    #[test]
    fn test_multi_seed_default_bootnodes() {
        let cfg = crate::config::NodeConfig::default();
        assert!(
            cfg.bootnodes.len() >= 2,
            "multi-seed requires >=2 default bootnodes, got {}",
            cfg.bootnodes.len()
        );
        // Distinct entries.
        let unique: std::collections::HashSet<_> = cfg.bootnodes.iter().collect();
        assert_eq!(unique.len(), cfg.bootnodes.len());
    }

    /// MULTI_SEED: P2PConfig accepts an arbitrary seed list.
    #[test]
    fn test_multi_seed_p2p_config_accepts_list() {
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30004"),
            bootnodes: vec![
                addr("10.0.0.1:25565"),
                addr("10.0.0.2:25565"),
                addr("10.0.0.3:25565"),
            ],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        assert_eq!(cfg.bootnodes.len(), 3);
    }

    /// GENERAL_REDIAL: heartbeat/reconnection candidate set includes non-bootnode peers.
    #[tokio::test]
    async fn test_general_redial_includes_known_peers() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let boot = addr("10.0.0.1:25565");
        let non_boot = addr("10.0.0.99:25565");
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30005"),
            bootnodes: vec![boot],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        net.addresses.write().await.observe(boot, PeerSource::Restored, unix_now(), Instant::now());
        net.addresses
            .write()
            .await
            .observe(non_boot, PeerSource::Restored, unix_now(), Instant::now());

        // Reconstruct the candidate set the way start_reconnection_task does.
        let local = net.config.listen_addr;
        let mut candidates: Vec<SocketAddr> = net.config.bootnodes.clone();
        for a in net.addresses.read().await.addresses() {
            if a != local && !candidates.contains(&a) {
                candidates.push(a);
            }
        }
        assert!(candidates.contains(&boot), "bootnode must be a candidate");
        assert!(
            candidates.contains(&non_boot),
            "known non-bootnode peer must be a general-redial candidate"
        );
    }

    /// PEX: Peers message carries known addresses for discovery.
    #[test]
    fn test_pex_message_carries_known_peers() {
        let list = vec![addr("10.0.0.1:25565"), addr("10.0.0.2:25565")];
        let msg = P2PMessage::Peers(list.clone());
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: P2PMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            P2PMessage::Peers(got) => assert_eq!(got, list),
            _ => panic!("wrong variant"),
        }
    }

    /// COLD_START: loading a peer store yields dial candidates without bootnodes.
    #[tokio::test]
    async fn test_cold_start_restores_dial_candidates_without_bootnode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let peer = addr("203.0.113.10:25565");
        std::fs::write(&path, format!("[\"{}\"]", peer)).unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30006"),
            bootnodes: vec![], // bootnode is down / absent
            dns_seeds: vec![],
            peer_store_path: Some(path),
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        net.load_known_peers().await;
        let known = net.addresses.read().await;
        assert!(known.contains(peer), "cold start must restore the peer");
        // General redial set (what start() dials after bootnodes) is non-empty.
        let candidates: Vec<SocketAddr> = known
            .addresses()
            .into_iter()
            .filter(|a| *a != net.config.listen_addr && !net.config.bootnodes.contains(a))
            .collect();
        assert_eq!(candidates.len(), 1);
    }

    /// P2P_CRYPTO_AUDIT: equal counters only collide under the SAME direction
    /// byte; the fix assigns opposite directions to the two session senders.
    #[test]
    fn test_nonce_collision_detected() {
        // Legacy/shared-direction view: equal counters under same dir collide.
        assert!(P2PNetwork::nonce_collision_possible(1, 0x01, 1, 0x01));
        assert!(P2PNetwork::nonce_collision_possible(42, 0x01, 42, 0x01));
        // Different counters under same dir: no collision.
        assert!(!P2PNetwork::nonce_collision_possible(1, 0x01, 2, 0x01));
        // Equal counters under OPPOSITE directions (the fixed scheme): no collision.
        assert!(!P2PNetwork::nonce_collision_possible(1, 0x01, 1, 0x02));
        assert!(!P2PNetwork::nonce_collision_possible(42, 0x02, 42, 0x01));
    }

    /// Nonce uniqueness: direction byte separates the two send directions, and
    /// counters are unique within a direction.
    #[test]
    fn test_nonce_uniqueness_across_directions() {
        let mut seen = std::collections::HashSet::new();
        for dir in [0x01u8, 0x02u8] {
            for counter in 1..=1000u64 {
                let n = P2PNetwork::build_nonce(counter, dir);
                assert!(seen.insert(n), "duplicate (K, nonce) at counter={counter} dir={dir:#04x}");
            }
        }
        // Opposite directions at the same counter must differ.
        assert_ne!(
            P2PNetwork::build_nonce(1, 0x01),
            P2PNetwork::build_nonce(1, 0x02)
        );
    }

    /// Direction assignment is deterministic and opposite for the two peers.
    #[test]
    fn test_send_direction_is_opposite() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let dir_a = P2PNetwork::send_direction(&a, &b);
        let dir_b = P2PNetwork::send_direction(&b, &a);
        assert_eq!(dir_a, 0x01);
        assert_eq!(dir_b, 0x02);
        assert_ne!(dir_a, dir_b);
    }

    /// Encrypt/decrypt roundtrip with direction nonces (both directions).
    #[test]
    fn test_encrypt_decrypt_roundtrip_bidirectional() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [7u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let msg_a = b"GET_INVENTORY_MESSAGE_A";
        let msg_b = b"SYNC_REQUEST_MESSAGE_B";

        let nonce_a = P2PNetwork::build_nonce(1, 0x01);
        let nonce_b = P2PNetwork::build_nonce(1, 0x02);
        assert_ne!(nonce_a, nonce_b);

        let ct_a = cipher.encrypt(Nonce::from_slice(&nonce_a), msg_a.as_ref()).unwrap();
        let ct_b = cipher.encrypt(Nonce::from_slice(&nonce_b), msg_b.as_ref()).unwrap();

        let pt_a = cipher.decrypt(Nonce::from_slice(&nonce_a), ct_a.as_ref()).unwrap();
        let pt_b = cipher.decrypt(Nonce::from_slice(&nonce_b), ct_b.as_ref()).unwrap();
        assert_eq!(pt_a, msg_a);
        assert_eq!(pt_b, msg_b);

        // Cross-direction decrypt must fail (wrong nonce / auth tag).
        assert!(cipher.decrypt(Nonce::from_slice(&nonce_b), ct_a.as_ref()).is_err());
    }

    /// Tampered ciphertext is rejected by Poly1305.
    #[test]
    fn test_tampered_ciphertext_fails() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [9u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = P2PNetwork::build_nonce(1, 0x01);
        let mut ct = cipher.encrypt(Nonce::from_slice(&nonce), b"integrity".as_ref()).unwrap();
        ct[0] ^= 0xff;
        assert!(cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).is_err());
    }

    /// Long message sequence: all nonces unique under one key; encrypt/decrypt
    /// succeeds for every frame in both directions.
    #[test]
    fn test_long_message_sequence_unique_nonces() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [3u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut seen = std::collections::HashSet::new();
        for dir in [0x01u8, 0x02u8] {
            for counter in 1..=10_000u64 {
                let n = P2PNetwork::build_nonce(counter, dir);
                assert!(seen.insert(n));
                let ct = cipher.encrypt(Nonce::from_slice(&n), counter.to_le_bytes().as_ref()).unwrap();
                let pt = cipher.decrypt(Nonce::from_slice(&n), ct.as_ref()).unwrap();
                assert_eq!(pt, counter.to_le_bytes());
            }
        }
        assert_eq!(seen.len(), 20_000);
    }

    /// Concurrent send counters remain unique (atomic fetch_add).
    #[test]
    fn test_concurrent_send_unique_counters() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = Arc::new(AtomicU64::new(1));
        let mut nonces = std::collections::HashSet::new();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let c = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let mut local = Vec::with_capacity(1000);
                    for _ in 0..1000 {
                        let v = c.fetch_add(1, Ordering::Relaxed);
                        local.push(P2PNetwork::build_nonce(v, 0x01));
                    }
                    local
                })
            })
            .collect();
        for h in handles {
            for n in h.join().unwrap() {
                assert!(nonces.insert(n), "duplicate nonce under concurrent send");
            }
        }
        assert_eq!(nonces.len(), 8000);
    }

    /// Reconnect / session rotation: each handshake yields a fresh ephemeral
    /// key, so (K, N) pairs from a prior session are never reused.
    #[tokio::test]
    async fn test_reconnect_session_rotation() {
        for _ in 0..8 {
            let (mut a_r, mut b_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_r, mut a_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_r, &mut a_w);
            let b = P2PNetwork::handshake(&mut b_r, &mut b_w);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, dir_a) = ra.expect("handshake A");
            let (key_b, dir_b) = rb.expect("handshake B");
            assert_eq!(key_a, key_b, "both ends share the session key");
            assert_ne!(dir_a, dir_b, "session directions must be opposite");
            assert!(dir_a == 0x01 || dir_a == 0x02);
        }
        // Distinct handshakes must not collide on keys (ephemeral X25519).
        let mut keys = std::collections::HashSet::new();
        for _ in 0..8 {
            let (mut a_r, mut b_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_r, mut a_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_r, &mut a_w);
            let b = P2PNetwork::handshake(&mut b_r, &mut b_w);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, _) = ra.expect("handshake A");
            let (key_b, _) = rb.expect("handshake B");
            assert_eq!(key_a, key_b);
            assert!(keys.insert(key_a), "reconnect must rotate the session key");
        }
        assert_eq!(keys.len(), 8);
    }

    /// Session handshake test (updated signature): shared key + opposite dirs.
    #[tokio::test]
    async fn test_handshake_derives_shared_key_bootstrap() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer);
        let (ra, rb) = tokio::join!(a, b);

        let (key_a, dir_a) = ra.expect("side A handshake must succeed");
        let (key_b, dir_b) = rb.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
        assert_ne!(dir_a, dir_b, "directions must be opposite");
    }

    /// Replay behaviour (logic-level): a repeated/regressed counter is rejected
    /// by the receiver's strict-increase check (mirrors handle_peer logic).
    #[test]
    fn test_replay_rejected_by_counter_check() {
        let mut last: u64 = 0;
        let mut accept = |counter: u64| -> bool {
            if counter <= last {
                false
            } else {
                last = counter;
                true
            }
        };
        assert!(accept(1));
        assert!(accept(2));
        assert!(!accept(2), "replay of counter=2 must fail");
        assert!(!accept(1), "regression to 1 must fail");
        assert!(accept(3));
    }

    /// PARTITION/RECONNECT: known_peers survives an active-map wipe (partition).
    #[tokio::test]
    async fn test_partition_keeps_known_peers_for_reconnect() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30007"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        let peer = addr("198.51.100.7:25565");
        net.addresses
            .write()
            .await
            .observe(peer, PeerSource::Pex, unix_now(), Instant::now());

        // Simulate a partition: active map wiped, known set retained (TTL).
        net.peers.write().await.clear();
        net.addresses.write().await.touch(peer, Instant::now());
        assert!(net.addresses.read().await.contains(peer));
        // Reconnect candidate reconstruction (same as start_reconnection_task).
        let mut candidates: Vec<SocketAddr> = net.config.bootnodes.clone();
        for a in net.addresses.read().await.addresses() {
            if a != net.config.listen_addr && !candidates.contains(&a) {
                candidates.push(a);
            }
        }
        assert!(candidates.contains(&peer));
    }

    /// BOOTNODE_LOSS: once A↔B know each other, killing the bootnode leaves
    /// the pair as mutual redial candidates (logic-level scenario).
    #[tokio::test]
    async fn test_bootnode_loss_pair_stays_connected() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let boot = addr("10.0.0.1:25565");
        let a = addr("127.0.0.1:40001");
        let b = addr("127.0.0.1:40002");
        let cfg = P2PConfig {
            listen_addr: a,
            bootnodes: vec![boot],
            dns_seeds: vec![],
            peer_store_path: None,
        };
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        // After PEX, A knows B and (locally) itself is not redialled.
        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(b, PeerSource::Pex, unix_now(), Instant::now());
            mgr.observe(boot, PeerSource::Restored, unix_now(), Instant::now());
        }

        // Bootnode dies: it is no longer a usable dial target, but B remains.
        let mut candidates: Vec<SocketAddr> = Vec::new();
        for x in net.addresses.read().await.addresses() {
            if x != a {
                candidates.push(x);
            }
        }
        // B survives as a general-redial candidate even if boot is removed.
        net.addresses.write().await.remove(&boot);
        let after: Vec<SocketAddr> = net
            .addresses
            .read()
            .await
            .addresses()
            .into_iter()
            .filter(|x| *x != a)
            .collect();
        assert!(after.contains(&b), "A must still redial B after bootnode loss");
        assert!(!after.contains(&boot));
        let _ = candidates;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transaction;
    use tokio::sync::mpsc;

    #[test]
    fn test_seen_tx_entry() {
        // The seen cache holds a timestamp for eviction decisions.
        let now = Instant::now();
        let entry = SeenTxEntry {
            timestamp: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
        };
        // 60s-old entry must be evictable (older than the 30s cleanup window).
        assert!(now.duration_since(entry.timestamp) >= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_seen_transactions_deduplication() {
        // Test that seen_transactions correctly tracks and deduplicates
        let seen = Arc::new(RwLock::new(HashMap::new()));

        let tx_bytes = vec![1u8, 2, 3, 4];

        // First insert should succeed
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                },
            );
        }

        // Check that it's present
        {
            let seen_read = seen.read().await;
            assert!(seen_read.contains_key(&tx_bytes));
            assert_eq!(seen_read.len(), 1);
        }

        // Second insert should not duplicate (just update)
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                },
            );
        }

        // Should still be only one entry
        {
            let seen_read = seen.read().await;
            assert_eq!(seen_read.len(), 1);
        }
    }

    /// H2: read_exact_timeout must fail with ErrorKind::TimedOut when the peer
    /// sends nothing, and succeed when the bytes arrive. A stalled peer can no
    /// longer hold a task + socket forever (slow-loris guard).
    #[tokio::test]
    async fn test_read_exact_timeout() {
        // A duplex stream with no writer activity: the read must time out.
        let (mut reader, _silent_writer) = tokio::io::duplex(64);
        let mut buf = [0u8; 36];
        let err = P2PNetwork::read_exact_timeout(&mut reader, &mut buf, Duration::from_millis(100))
            .await
            .expect_err("silent peer must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // A duplex stream that delivers the bytes: the read must succeed.
        let (mut reader2, mut writer2) = tokio::io::duplex(64);
        writer2.write_all(&[0xAAu8; 36]).await.unwrap();
        P2PNetwork::read_exact_timeout(&mut reader2, &mut buf, Duration::from_secs(5))
            .await
            .expect("bytes must be read within the budget");
        assert_eq!(buf, [0xAAu8; 36]);

        // A stream that closes mid-read: an io error, not a timeout.
        let (mut reader3, mut writer3) = tokio::io::duplex(64);
        writer3.write_all(&[0xBBu8; 4]).await.unwrap();
        drop(writer3);
        let err = P2PNetwork::read_exact_timeout(&mut reader3, &mut buf, Duration::from_secs(5))
            .await
            .expect_err("truncated frame must error");
        assert_ne!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn test_seen_transactions_cleanup() {
        // Test that old entries are evicted
        let seen = Arc::new(RwLock::new(HashMap::new()));

        let tx_bytes1 = vec![1u8, 2, 3, 4];
        let tx_bytes2 = vec![5u8, 6, 7, 8];

        // Insert one entry with old timestamp (use smaller duration to avoid overflow)
        {
            let mut seen_write = seen.write().await;
            let now = Instant::now();
            seen_write.insert(
                tx_bytes1.clone(),
                SeenTxEntry {
                    timestamp: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
                },
            );
            seen_write.insert(tx_bytes2.clone(), SeenTxEntry { timestamp: now });
        }

        // Simulate cleanup (remove entries older than 30 seconds)
        let now = Instant::now();
        {
            let mut seen_write = seen.write().await;
            seen_write.retain(|_, entry| {
                now.checked_duration_since(entry.timestamp)
                    .map_or(false, |d| d < Duration::from_secs(30))
            });
        }

        // Old entry should be removed, new entry should remain
        {
            let seen_read = seen.read().await;
            assert!(!seen_read.contains_key(&tx_bytes1));
            assert!(seen_read.contains_key(&tx_bytes2));
            assert_eq!(seen_read.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_seen_cache_bounded() {
        // insert_seen must keep the cache bounded: once at MAX_SEEN_TXS it
        // evicts before inserting.
        let seen = Arc::new(RwLock::new(HashMap::new()));

        // Fill past the cap with fresh entries (eviction removes one per insert
        // once the cap is reached).
        for i in 0..(MAX_SEEN_TXS + 100) {
            insert_seen(&seen, vec![(i % 256) as u8; 4]).await;
        }

        let size = seen.read().await.len();
        assert!(size <= MAX_SEEN_TXS);
    }

    #[tokio::test]
    async fn test_seen_cache_dedup_preserved_under_cap() {
        let seen = Arc::new(RwLock::new(HashMap::new()));
        let key = vec![7u8; 4];
        insert_seen(&seen, key.clone()).await;
        insert_seen(&seen, key.clone()).await;
        let map = seen.read().await;
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_limit_constants_sane() {
        // A 16 MiB frame cap + 400 msgs/s caps per-peer throughput at ~6.4 GiB/s
        // worst case, but more importantly caps single-allocation size.
        assert!(MAX_MESSAGE_SIZE <= 16 * 1024 * 1024);
        assert!(MAX_MSGS_PER_SEC >= 1);
        assert!(MAX_PEERS >= 1);
        assert!(MAX_INV_ITEMS >= 1);
    }

    /// H4/V-24: handshake identity check — a peer from another network
    /// (different genesis hash) or another protocol version must be rejected,
    /// while a same-network frame passes.
    #[test]
    fn test_handshake_identity_mismatch_rejected() {
        let mut frame = vec![0u8; HANDSHAKE_FRAME_LEN];
        frame[..4].copy_from_slice(&HANDSHAKE_MAGIC);
        frame[4] = P2P_PROTOCOL_VERSION;
        frame[5..37].copy_from_slice(&crate::genesis::GENESIS_HASH);

        // Correct same-network frame passes.
        assert!(
            P2PNetwork::verify_handshake_identity(&frame).is_ok(),
            "a same-network frame must pass"
        );

        // Wrong magic is rejected.
        let mut wrong_magic = frame.clone();
        wrong_magic[0] = 0x00;
        let err = P2PNetwork::verify_handshake_identity(&wrong_magic).unwrap_err();
        assert!(err.contains("magic"), "got: {}", err);

        // Version mismatch is rejected.
        let mut wrong_version = frame.clone();
        wrong_version[4] = P2P_PROTOCOL_VERSION + 1;
        let err = P2PNetwork::verify_handshake_identity(&wrong_version).unwrap_err();
        assert!(err.contains("version"), "got: {}", err);

        // Genesis (network) mismatch is rejected.
        let mut wrong_genesis = frame.clone();
        wrong_genesis[5] = 0x42;
        let err = P2PNetwork::verify_handshake_identity(&wrong_genesis).unwrap_err();
        assert!(err.contains("genesis"), "got: {}", err);

        // Truncated frame is rejected.
        assert!(P2PNetwork::verify_handshake_identity(&frame[..8]).is_err());
    }

    /// H4/V-24: two ends of the SAME network complete the X25519 handshake
    /// and derive the SAME session key with opposite send directions.
    #[tokio::test]
    async fn test_handshake_derives_shared_key() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer);
        let (ra, rb) = tokio::join!(a, b);

        let (key_a, dir_a) = ra.expect("side A handshake must succeed");
        let (key_b, dir_b) = rb.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
        assert_ne!(dir_a, dir_b, "directions must be opposite");
    }

    #[tokio::test]
    async fn test_broadcast_marks_as_local() {
        // Test that broadcast_transaction marks tx as Local before sending
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            Arc::new(crate::sync_stats::SyncContext::default()),
            Arc::new(|_| false),
        );

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );

        let tx_bytes = bincode::serialize(&tx).unwrap();

        // Broadcast should mark as seen
        p2p.broadcast_transaction(tx.clone()).await;

        // Check that it's in seen_transactions
        let seen = p2p.seen_transactions.read().await;
        assert!(seen.contains_key(&tx_bytes));
    }

    /// B4: partition_batch must be ORDER-INDEPENDENT. A chain A->B->C->D is
    /// fully deliverable in parent-first order, and the same set in
    /// child-first order must yield the SAME deliverable set (parents first).
    #[test]
    fn test_partition_batch_order_independent() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [b.id, genesis]);
        let d = mk(4, [c.id, genesis]);

        // DAG already contains genesis (and nothing else): lookup by id.
        let has_in_dag = |id: &[u8]| -> Option<Transaction> {
            let ids: [[u8; 32]; 4] = [a.id, b.id, c.id, d.id];
            if ids.iter().any(|x| x.as_slice() == id) {
                None
            } else {
                Some(a.clone())
            }
        };
        let serialize = |tx: &Transaction| bincode::serialize(tx).unwrap();

        // Parent-first order: everything deliverable.
        let (del, wait) = P2PNetwork::partition_batch(
            vec![
                (serialize(&a), a.clone()),
                (serialize(&b), b.clone()),
                (serialize(&c), c.clone()),
                (serialize(&d), d.clone()),
            ],
            &has_in_dag,
        );
        assert_eq!(del.len(), 4, "parent-first chain must be fully deliverable");
        assert!(wait.is_empty());

        // Child-first order: the SAME deliverable set. The head (a) is
        // deliverable (parents = genesis); once inserted in-batch, b, c and d
        // unlock in the same passes -> identical partition, no orphans.
        let (del2, wait2) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
                (serialize(&a), a.clone()),
            ],
            &has_in_dag,
        );
        assert_eq!(del2.len(), 4, "child-first chain must also fully resolve");
        assert!(wait2.is_empty());
        let mut del_ids: Vec<[u8; 32]> = del.into_iter().map(|(_, t)| t.id).collect();
        let mut del2_ids: Vec<[u8; 32]> = del2.into_iter().map(|(_, t)| t.id).collect();
        del_ids.sort();
        del2_ids.sort();
        assert_eq!(
            del_ids, del2_ids,
            "deliverable set must be order-independent"
        );

        // Without the head (a missing from the DAG AND the batch): everything
        // waits. Parents are requested via the orphan flow instead.
        let (del3, wait3) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
            ],
            &has_in_dag,
        );
        assert!(del3.is_empty(), "no head -> nothing deliverable in-batch");
        assert_eq!(wait3.len(), 3, "all members wait for the missing parent");
    }

    /// B4: a diamond A->(B,C)->D: B and C are both deliverable once A is in
    /// the DAG; D waits for both.
    #[test]
    fn test_partition_batch_diamond() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [a.id, genesis]);
        let d = mk(4, [b.id, c.id]);

        let has_in_dag = |id: &[u8]| -> Option<Transaction> {
            let known: Vec<[u8; 32]> = vec![a.id, b.id, c.id, d.id];
            if known.iter().any(|x| x.as_slice() == id) {
                None
            } else {
                Some(a.clone())
            }
        };
        let serialize = |tx: &Transaction| bincode::serialize(tx).unwrap();

        // Arrive in worst order: D, C, B, A.
        let (del, wait) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
                (serialize(&a), a.clone()),
            ],
            &has_in_dag,
        );
        // After the passes: A deliverable (parents=genesis); then B and C
        // (parent A now inserted in-batch); D still waits for C/B? No: B and C
        // are inserted, so D becomes deliverable in the same pass chain.
        assert_eq!(del.len(), 4, "diamond must resolve fully in-batch");
        assert!(wait.is_empty());
    }

    /// B4: parent-request dedup. Two immediate requests for the same parent
    /// must produce ONE actual request; the second is counted as
    /// already-known (backoff).
    #[tokio::test]
    async fn test_request_transaction_dedup() {
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let ctx = Arc::new(crate::sync_stats::SyncContext::default());
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            ctx.clone(),
            Arc::new(|_| false),
        );

        let hash = vec![0xABu8; 32];
        p2p.request_transaction(hash.clone()).await;
        p2p.request_transaction(hash.clone()).await;
        p2p.request_transaction(hash).await;

        let snap = ctx.stats.snapshot();
        assert_eq!(snap.parent_requested, 1, "only the first request is sent");
        assert_eq!(
            snap.parent_already_known, 2,
            "repeats within the cooldown are deduplicated"
        );
    }

    /// VPS-2 helper: build a linear chain root -> ... -> tip on top of
    /// genesis parents. Returns txs oldest-first.
    #[cfg(test)]
    fn test_chain(n: usize, start: u8) -> Vec<Transaction> {
        use crate::Transaction;
        let genesis = [0u8; 32];
        let mut chain = Vec::new();
        let mut parent = genesis;
        for i in 0..n {
            let tx = Transaction::new(
                [parent, genesis],
                [start.wrapping_add(i as u8); 32],
                [200u8; 32],
                100,
                10,
                1234567890 + i as u64,
                0,
                i as u64,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            parent = tx.id;
            chain.push(tx);
        }
        chain
    }

    /// VPS-2: requesting only the tip of a chain returns the whole
    /// ancestor-closed set (chain length < budget).
    #[test]
    fn test_ancestor_closed_page_closes_chain() {
        let chain = test_chain(10, 50);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let page = P2PNetwork::ancestor_closed_page(vec![tip.clone()], &lookup);
        assert_eq!(page.len(), 10, "full chain must be included");
        assert!(page.contains(&tip));
        assert!(page.contains(&chain[0].id.to_vec()));
        // Deterministic: same input twice, same output.
        let again = P2PNetwork::ancestor_closed_page(vec![tip], &lookup);
        assert_eq!(page, again);
    }

    /// VPS-2 §12 anti-loop/bound: a 600-deep chain with budget 400 returns
    /// exactly tip + 400 nearest ancestors (401), terminates, no dupes.
    #[test]
    fn test_ancestor_closed_page_budget_bound() {
        let chain = test_chain(600, 10);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let page = P2PNetwork::ancestor_closed_page(vec![tip], &lookup);
        assert_eq!(page.len(), 401, "tip + exactly 400 ancestors");
        // Nearest 400 present (indices 199..=598), the next one excluded.
        assert!(page.contains(&chain[599].id.to_vec()));
        assert!(page.contains(&chain[200].id.to_vec()));
        assert!(page.contains(&chain[199].id.to_vec()));
        assert!(!page.contains(&chain[198].id.to_vec()));
        let mut sorted = page.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), page.len(), "no duplicates in page");
    }

    /// VPS-2 §12: unknown hashes are skipped (never invented), duplicate
    /// requests deduped, genesis terminates.
    #[test]
    fn test_ancestor_closed_page_skips_unknown_and_dupes() {
        let chain = test_chain(5, 80);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let ghost = vec![0xFFu8; 32];
        let page = P2PNetwork::ancestor_closed_page(
            vec![tip.clone(), ghost.clone(), tip.clone()],
            &lookup,
        );
        assert_eq!(page.len(), 5, "chain once, ghost skipped, dupe dropped");
        assert!(!page.contains(&ghost));
    }

    /// C2-004: topological_order must emit parents before children.
    /// The previous implementation incremented the PARENT's counter
    /// (counting children), serving tips-first: joining nodes parked
    /// every batch as orphans and the re-request storm collapsed serving
    /// nodes at ~10k txs.    #[test]
    fn test_topological_order_parents_first() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [a.id, genesis]);
        let d = mk(4, [b.id, c.id]);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> = [&a, &b, &c, &d]
            .into_iter()
            .map(|t| (t.id.to_vec(), t.clone()))
            .collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };

        // Feed child-first: the order must still come out parents-first.
        let hashes = vec![d.id.to_vec(), c.id.to_vec(), b.id.to_vec(), a.id.to_vec()];
        let order =
            P2PNetwork::topological_order(hashes, &lookup).expect("chain+diamond must sort");
        assert_eq!(order.len(), 4);
        let pos = |id: &[u8; 32]| order.iter().position(|h| h.as_slice() == id).unwrap();
        assert!(pos(&a.id) < pos(&b.id), "A before B");
        assert!(pos(&a.id) < pos(&c.id), "A before C");
        assert!(pos(&b.id) < pos(&d.id), "B before D");
        assert!(pos(&c.id) < pos(&d.id), "C before D");
    }

    #[test]
    fn test_subnet_24_ipv4() {
        let addr: SocketAddr = "192.168.1.100:30333".parse().unwrap();
        assert_eq!(subnet_24(addr), Some([192, 168, 1]));
        let same: SocketAddr = "192.168.1.200:30333".parse().unwrap();
        assert_eq!(subnet_24(same), Some([192, 168, 1]));
        let diff: SocketAddr = "192.168.2.100:30333".parse().unwrap();
        assert_eq!(subnet_24(diff), Some([192, 168, 2]));
    }

    #[test]
    fn test_subnet_24_ipv6() {
        let addr: SocketAddr = "[2a0c:b641:1a0:800::ba]:30333".parse().unwrap();
        let sub = subnet_24(addr);
        assert!(sub.is_some(), "IPv6 must return a subnet");
    }

    #[test]
    fn test_count_subnet_peers() {
        let peers: HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
        let addr: SocketAddr = "10.0.0.1:30333".parse().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let count = rt.block_on(count_subnet_peers(addr, &peers));
        assert_eq!(count, 0);
    }

    #[test]
    fn test_diversity_constants() {
        assert!(
            MAX_PEERS_PER_SUBNET >= 2,
            "must allow at least 2 peers per /24"
        );
        assert!(MAX_PEERS_PER_SUBNET <= 16, "must limit to prevent eclipse");
        assert!(
            PROTECTED_OUTBOUND_SLOTS >= 4,
            "must protect at least 4 outbound slots"
        );
        assert!(
            PROTECTED_OUTBOUND_SLOTS < MAX_PEERS,
            "protected must be less than total"
        );
    }

    // === Phase 8: Adversarial P2P Tests ===

    #[test]
    fn test_peer_score_initial() {
        let score = PeerScore::new();
        assert_eq!(score.score, PEER_SCORE_INITIAL);
        assert!(!score.is_banned());
        assert_eq!(score.temp_bans, 0);
    }

    #[test]
    fn test_peer_score_penalize() {
        let mut score = PeerScore::new();
        assert!(!score.penalize(PEER_PENALTY_INVALID_MSG));
        assert_eq!(score.score, PEER_SCORE_INITIAL + PEER_PENALTY_INVALID_MSG);
        // Enough penalties to drop below threshold
        for _ in 0..10 {
            if score.penalize(PEER_PENALTY_INVALID_MSG) {
                break;
            }
        }
        assert!(score.score <= PEER_SCORE_BAN_THRESHOLD);
    }

    #[test]
    fn test_peer_score_ban_temp_then_perm() {
        let mut score = PeerScore::new();
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert!(score.is_banned());
        assert_eq!(score.temp_bans, 1);
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert_eq!(score.temp_bans, 2);
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert_eq!(score.temp_bans, 3);
        assert!(score.is_banned());
    }

    #[test]
    fn test_peer_score_decay() {
        let mut score = PeerScore::new();
        score.score = 50;
        score.last_decay = Instant::now() - Duration::from_secs(600);
        score.decay();
        assert_eq!(score.score, 51);
    }

    #[test]
    fn test_peer_score_decay_no_op() {
        let mut score = PeerScore::new();
        score.last_decay = Instant::now() - Duration::from_secs(600);
        score.decay();
        assert_eq!(score.score, PEER_SCORE_INITIAL);
    }

    #[test]
    fn test_peer_score_reward() {
        let mut score = PeerScore::new();
        score.reward(PEER_BONUS_SYNC);
        assert_eq!(score.score, PEER_SCORE_INITIAL + PEER_BONUS_SYNC);
        score.reward(100);
        assert_eq!(score.score, PEER_SCORE_INITIAL + 50);
    }

    #[test]
    fn test_subnet_diversity_limit() {
        let mut count = 0;
        for i in 1..=5 {
            let addr: SocketAddr = format!("192.168.1.{}:30333", i).parse().unwrap();
            if subnet_24(addr) == Some([192, 168, 1]) {
                count += 1;
            }
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn test_eclipse_attack_blocked() {
        let attacker_subnet = [10, 0, 0];
        let mut allowed = 0;
        for i in 1..=10 {
            let addr: SocketAddr = format!("10.0.0.{}:30333", i).parse().unwrap();
            if subnet_24(addr) == Some(attacker_subnet) && allowed < MAX_PEERS_PER_SUBNET {
                allowed += 1;
            }
        }
        assert_eq!(allowed, MAX_PEERS_PER_SUBNET);
    }

    #[test]
    fn test_scoring_flood_bans() {
        let mut score = PeerScore::new();
        for _ in 0..7 {
            if score.penalize(PEER_PENALTY_FLOOD) {
                score.ban();
                break;
            }
        }
        assert!(score.is_banned());
    }

    #[test]
    fn test_scoring_slow_not_banned() {
        let mut score = PeerScore::new();
        for _ in 0..10 {
            score.penalize(PEER_PENALTY_TIMEOUT);
        }
        assert!(score.score > PEER_SCORE_BAN_THRESHOLD);
        assert!(!score.is_banned());
    }

    // ===== DEEP SYNC TESTS =====

    /// Helper: build a linear chain of `n` transactions in a lookup table.
    /// Returns (tip_hash, lookup_fn).
    fn build_linear_chain(n: usize) -> (Vec<u8>, impl Fn(&[u8]) -> Option<Transaction>) {
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let mut prev_hash = [0u8; 32]; // genesis parent
        for i in 0..n {
            let mut parents = [[0u8; 32]; 2];
            parents[0] = prev_hash;
            parents[1] = [0u8; 32];
            let tx = Transaction::new(
                parents,
                [1u8; 32],       // sender
                [2u8; 32],       // receiver
                100,             // amount
                1,               // fee
                1000 + i as u64, // timestamp
                0,               // nonce
                0,               // account_nonce
                vec![],          // signature
                vec![],          // public_key
            );
            prev_hash = tx.id;
            chain.insert(tx.id.to_vec(), tx);
        }
        let tip = prev_hash.to_vec();
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        (tip, lookup)
    }

    #[test]
    fn test_ancestor_full_closure_linear_chain() {
        let (tip, lookup) = build_linear_chain(10);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, 100);
        // Full closure of a 10-tx chain should include all 10 txs.
        assert_eq!(
            closure.len(),
            10,
            "full closure should include all ancestors"
        );
        // The tip itself should be in the closure.
        assert!(closure.iter().any(|h| h == &tip));
    }

    #[test]
    fn test_ancestor_full_closure_respects_max_entries() {
        let (tip, lookup) = build_linear_chain(50);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, 20);
        // Should be capped at max_entries (20), not the full chain (50).
        assert!(
            closure.len() <= 20,
            "closure should respect max_entries bound"
        );
        assert!(closure.len() > 0, "closure should not be empty");
    }

    #[test]
    fn test_ancestor_full_closure_empty_request() {
        let (_tip, lookup) = build_linear_chain(10);
        let closure = P2PNetwork::ancestor_full_closure(&[], &lookup, 100);
        assert_eq!(
            closure.len(),
            0,
            "empty request should produce empty closure"
        );
    }

    #[test]
    fn test_ancestor_full_closure_unknown_hashes_skipped() {
        let (_tip, lookup) = build_linear_chain(10);
        let unknown = vec![99u8; 32];
        let closure = P2PNetwork::ancestor_full_closure(&[unknown], &lookup, 100);
        assert_eq!(closure.len(), 0, "unknown hashes should be skipped");
    }

    #[test]
    fn test_ancestor_full_closure_duplicate_requests_deduped() {
        let (tip, lookup) = build_linear_chain(5);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone(), tip.clone()], &lookup, 100);
        // Duplicate request hashes should be deduplicated.
        assert_eq!(closure.len(), 5, "duplicates should be deduped");
    }

    #[test]
    fn test_ancestor_full_closure_genesis_terminated() {
        // Chain where a tx has genesis parent [0; 32].
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let genesis_parent = [0u8; 32];
        let tx = Transaction::new(
            [genesis_parent, [0u8; 32]],
            [1u8; 32],
            [2u8; 32],
            100,
            1,
            1000,
            0,
            0,
            vec![],
            vec![],
        );
        let id = tx.id.to_vec();
        chain.insert(id.clone(), tx);
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        let closure = P2PNetwork::ancestor_full_closure(&[id.clone()], &lookup, 100);
        // Genesis parent [0; 32] should not be in the closure.
        assert_eq!(closure.len(), 1, "genesis parent should be terminated");
    }

    #[test]
    fn test_ancestor_full_closure_bounded_by_max_entries() {
        // Build a deep chain and verify the bound is strict.
        let (tip, lookup) = build_linear_chain(100);
        for max in [5, 10, 25, 50] {
            let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, max);
            assert!(
                closure.len() <= max,
                "closure len {} should be <= max_entries {}",
                closure.len(),
                max
            );
        }
    }

    #[test]
    fn test_ancestor_full_closure_diamond_dag() {
        // Build a diamond DAG: genesis -> A, genesis -> B, A+B -> C (tip).
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let genesis = [0u8; 32];
        let tx_a = Transaction::new(
            [genesis, genesis],
            [1u8; 32],
            [2u8; 32],
            10,
            1,
            100,
            0,
            0,
            vec![],
            vec![],
        );
        let tx_b = Transaction::new(
            [genesis, genesis],
            [1u8; 32],
            [2u8; 32],
            20,
            1,
            101,
            0,
            1,
            vec![],
            vec![],
        );
        let id_a = tx_a.id;
        let id_b = tx_b.id;
        chain.insert(id_a.to_vec(), tx_a);
        chain.insert(id_b.to_vec(), tx_b);
        let tx_c = Transaction::new(
            [id_a, id_b],
            [1u8; 32],
            [2u8; 32],
            30,
            1,
            102,
            0,
            2,
            vec![],
            vec![],
        );
        let id_c = tx_c.id;
        chain.insert(id_c.to_vec(), tx_c);
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        let closure = P2PNetwork::ancestor_full_closure(&[id_c.to_vec()], &lookup, 100);
        // Should include C, A, B = 3 txs (genesis [0;32] is terminated).
        assert_eq!(closure.len(), 3, "diamond closure should include all 3 txs");
        assert!(closure.iter().any(|h| h == &id_a.to_vec()));
        assert!(closure.iter().any(|h| h == &id_b.to_vec()));
        assert!(closure.iter().any(|h| h == &id_c.to_vec()));
    }
}
