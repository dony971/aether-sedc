//! Sybil scale simulation: measures P2P resistance to mass fake peers.
//!
//! Simulates the peer management logic (subnet limits, scoring, banning)
//! without requiring actual network connections.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

// Mirror P2P constants from p2p.rs
const MAX_PEERS: usize = 128;
const MAX_PEERS_PER_SUBNET: usize = 4;
const PEER_SCORE_INITIAL: i32 = 100;
const PEER_SCORE_BAN_THRESHOLD: i32 = 0;
const PEER_PENALTY_FLOOD: i32 = -15;
const PEER_PENALTY_INVALID_MSG: i32 = -10;
const PEER_PENALTY_CONTRADICTION: i32 = -20;
const PEER_DECAY_RATE: i32 = 1;
const PEER_DECAY_INTERVAL: Duration = Duration::from_secs(300);
const PEER_BAN_TEMP: Duration = Duration::from_secs(300);
const PEER_BAN_TEMP_MAX: usize = 3;
const PEER_BAN_PERM: Duration = Duration::from_secs(3600);

/// Simplified PeerScore for testing
#[derive(Clone, Debug)]
struct SimPeerScore {
    score: i32,
    temp_bans: usize,
    last_decay: Instant,
    banned_until: Option<Instant>,
}

impl SimPeerScore {
    fn new() -> Self {
        Self {
            score: PEER_SCORE_INITIAL,
            temp_bans: 0,
            last_decay: Instant::now(),
            banned_until: None,
        }
    }

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

    fn penalize(&mut self, penalty: i32) -> bool {
        self.score += penalty;
        self.score <= PEER_SCORE_BAN_THRESHOLD
    }

    fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }

    fn ban(&mut self) {
        self.temp_bans += 1;
        if self.temp_bans >= PEER_BAN_TEMP_MAX {
            self.banned_until = Some(Instant::now() + PEER_BAN_PERM);
        } else {
            self.banned_until = Some(Instant::now() + PEER_BAN_TEMP);
        }
    }
}

/// Extract /24 subnet from IPv4
fn subnet_24(addr: SocketAddr) -> Option<[u8; 3]> {
    match addr {
        SocketAddr::V4(v4) => {
            let o = v4.ip().octets();
            Some([o[0], o[1], o[2]])
        }
        _ => None,
    }
}

/// Create SocketAddr from (a, b, c, d, port)
fn make_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

/// Simulated P2P node with peer management
struct SimNode {
    peers: HashMap<SocketAddr, ()>,
    scores: HashMap<SocketAddr, SimPeerScore>,
    rejected_subnets: Vec<(SocketAddr, String)>,
    rejected_global_limit: Vec<SocketAddr>,
    rejected_banned: Vec<SocketAddr>,
}

impl SimNode {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            scores: HashMap::new(),
            rejected_subnets: Vec::new(),
            rejected_global_limit: Vec::new(),
            rejected_banned: Vec::new(),
        }
    }

    /// Try to accept a peer connection (mirrors accept_loop logic)
    fn try_accept(&mut self, addr: SocketAddr) -> bool {
        // Global limit
        if self.peers.len() >= MAX_PEERS {
            self.rejected_global_limit.push(addr);
            return false;
        }

        // Ban check
        if let Some(score) = self.scores.get(&addr) {
            if score.is_banned() {
                self.rejected_banned.push(addr);
                return false;
            }
        }

        // Subnet limit
        let subnet = match subnet_24(addr) {
            Some(s) => s,
            None => return false,
        };
        let subnet_count = self
            .peers
            .keys()
            .filter(|k| subnet_24(**k) == Some(subnet) && **k != addr)
            .count();
        if subnet_count >= MAX_PEERS_PER_SUBNET {
            self.rejected_subnets
                .push((addr, format!("{}/{}", subnet_count, MAX_PEERS_PER_SUBNET)));
            return false;
        }

        // Accept
        self.peers.insert(addr, ());
        self.scores.entry(addr).or_insert_with(SimPeerScore::new);
        true
    }

    /// Count connected peers from a specific subnet
    fn count_subnet(&self, subnet: [u8; 3]) -> usize {
        self.peers
            .keys()
            .filter(|k| subnet_24(**k) == Some(subnet))
            .count()
    }

    /// Simulate peer flood penalty
    fn penalize_flood(&mut self, addr: SocketAddr) -> bool {
        if let Some(score) = self.scores.get_mut(&addr) {
            let should_ban = score.penalize(PEER_PENALTY_FLOOD);
            if should_ban {
                score.ban();
                return true;
            }
        }
        false
    }

    /// Simulate invalid message penalty
    fn penalize_invalid(&mut self, addr: SocketAddr) -> bool {
        if let Some(score) = self.scores.get_mut(&addr) {
            let should_ban = score.penalize(PEER_PENALTY_INVALID_MSG);
            if should_ban {
                score.ban();
                return true;
            }
        }
        false
    }

    /// Simulate contradiction penalty
    fn penalize_contradiction(&mut self, addr: SocketAddr) -> bool {
        if let Some(score) = self.scores.get_mut(&addr) {
            let should_ban = score.penalize(PEER_PENALTY_CONTRADICTION);
            if should_ban {
                score.ban();
                return true;
            }
        }
        false
    }

    /// Decay all peer scores
    fn decay_all(&mut self) {
        for score in self.scores.values_mut() {
            score.decay();
        }
    }

    /// Remove a peer (e.g., disconnected)
    fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
        self.scores.remove(addr);
    }
}

// ============================================================================
// TEST A: All attackers on one subnet
// ============================================================================

#[test]
fn test_sybil_all_same_subnet() {
    let mut node = SimNode::new();

    // 100 attackers from 10.0.0.x/24
    let mut accepted = 0;
    let mut rejected = 0;
    for i in 1..=100 {
        let addr = make_addr(10, 0, 0, i, 25565);
        if node.try_accept(addr) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }

    // Only MAX_PEERS_PER_SUBNET (4) from same /24 accepted
    assert_eq!(accepted, MAX_PEERS_PER_SUBNET);
    assert_eq!(rejected, 100 - MAX_PEERS_PER_SUBNET);
    assert_eq!(node.count_subnet([10, 0, 0]), MAX_PEERS_PER_SUBNET);
    assert_eq!(node.rejected_subnets.len(), 100 - MAX_PEERS_PER_SUBNET);

    println!(
        "Sybil A (same subnet): {}/100 accepted, {}/100 rejected",
        accepted, rejected
    );
}

// ============================================================================
// TEST B: Attackers across multiple subnets
// ============================================================================

#[test]
fn test_sybil_multiple_subnets() {
    let mut node = SimNode::new();

    // 100 attackers across 25 different /24 subnets (4 per subnet = 100)
    let mut accepted = 0;
    let mut rejected = 0;
    let mut subnet_count = 0;
    for subnet in 0..25u8 {
        for host in 1..=4u8 {
            let addr = make_addr(10, subnet, 0, host, 25565);
            if node.try_accept(addr) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
        subnet_count += 1;
    }

    // 4 per subnet × 25 subnets = 100 accepted (all within limit)
    assert_eq!(accepted, 100);
    assert_eq!(rejected, 0);

    // Now add 101st attacker on a new subnet
    let overflow = make_addr(10, 25, 0, 1, 25565);
    let ok = node.try_accept(overflow);
    assert!(ok, "new subnet should accept");
    accepted += 1;

    println!(
        "Sybil B (multi-subnet): {}/101 accepted across {} subnets, {} rejected",
        accepted, subnet_count, rejected
    );
}

// ============================================================================
// TEST C: Multiple ASN simulation (different /16 prefixes)
// ============================================================================

#[test]
fn test_sybil_multiple_asn() {
    let mut node = SimNode::new();

    // Simulate 3 ASNs: AS1=10.0.x.x, AS2=172.16.x.x, AS3=192.168.x.x
    // Each ASN has 10 subnets, 4 hosts per subnet
    let mut accepted = 0;
    let mut rejected = 0;

    // AS1: 10.0.{0-9}.x
    for sub in 0..10 {
        for host in 1..=4 {
            let addr = make_addr(10, 0, sub, host, 25565);
            if node.try_accept(addr) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    // AS2: 172.16.{0-9}.x
    for sub in 0..10 {
        for host in 1..=4 {
            let addr = make_addr(172, 16, sub, host, 25565);
            if node.try_accept(addr) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    // AS3: 192.168.{0-9}.x
    for sub in 0..10 {
        for host in 1..=4 {
            let addr = make_addr(192, 168, sub, host, 25565);
            if node.try_accept(addr) {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }

    // 120 peers across 30 subnets — all within limits
    assert_eq!(accepted, 120);
    assert_eq!(rejected, 0);

    // Fill to MAX_PEERS (128)
    for host in 1..=8 {
        let addr = make_addr(10, 1, 10, host, 25565);
        if node.try_accept(addr) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    // 120 + up to 8 = 128 (at limit)
    assert!(node.peers.len() <= MAX_PEERS);

    println!(
        "Sybil C (multi-ASN): {}/{} accepted, {} rejected, {} total",
        accepted,
        120 + 8,
        rejected,
        node.peers.len()
    );
}

// ============================================================================
// TEST D: Mass inbound connections
// ============================================================================

#[test]
fn test_sybil_mass_inbound() {
    let mut node = SimNode::new();

    // 500 attackers from 500 different /24 subnets
    let mut accepted = 0;
    let mut rejected_subnet = 0;
    let mut rejected_global = 0;

    for i in 0..500u16 {
        // Each peer gets a unique /24 subnet
        let a = 10;
        let b = (i / 256) as u8;
        let c = (i % 256) as u8;
        let addr = make_addr(a, b, c, 1, 25565);
        if node.try_accept(addr) {
            accepted += 1;
        } else {
            // Determine rejection reason
            if node.peers.len() >= MAX_PEERS {
                rejected_global += 1;
            } else {
                rejected_subnet += 1;
            }
        }
    }

    // Capped at MAX_PEERS (128)
    assert_eq!(accepted, MAX_PEERS);
    assert_eq!(node.peers.len(), MAX_PEERS);
    assert_eq!(rejected_global, 500 - MAX_PEERS);

    println!(
        "Sybil D (mass inbound): {}/500 accepted, {} global-rejected, {} subnet-rejected",
        accepted, rejected_global, rejected_subnet
    );
}

// ============================================================================
// TEST E: Peer rotation (churn)
// ============================================================================

#[test]
fn test_sybil_rotation() {
    let mut node = SimNode::new();

    // Phase 1: Fill with 128 honest peers from different subnets
    for i in 0..128 {
        let addr = make_addr(10, (i / 256) as u8, (i % 256) as u8, 1, 25565);
        node.try_accept(addr);
    }
    assert_eq!(node.peers.len(), MAX_PEERS);

    // Phase 2: Attackers try to rotate — remove 10 honest, add 10 attackers
    let honest_addrs: Vec<SocketAddr> = node.peers.keys().copied().take(10).collect();
    for addr in &honest_addrs {
        node.remove_peer(addr);
    }
    assert_eq!(node.peers.len(), MAX_PEERS - 10);

    // 10 attackers from a new subnet
    let mut attackers_accepted = 0;
    for i in 1..=10 {
        let addr = make_addr(10, 50, 0, i, 25565);
        if node.try_accept(addr) {
            attackers_accepted += 1;
        }
    }

    // At most 4 from 10.50.0.x/24
    let sybil_subnet = node.count_subnet([10, 50, 0]);
    assert!(sybil_subnet <= MAX_PEERS_PER_SUBNET);
    assert_eq!(attackers_accepted, sybil_subnet);

    // Overall count
    assert!(node.peers.len() <= MAX_PEERS);

    println!(
        "Sybil E (rotation): removed {} honest, {}/10 attackers accepted (subnet limit {}/4)",
        honest_addrs.len(),
        attackers_accepted,
        sybil_subnet
    );
}

// ============================================================================
// TEST F: Scoring under attack
// ============================================================================

#[test]
fn test_sybil_scoring() {
    let mut node = SimNode::new();

    // Add 128 peers (mix of honest and attacker)
    for i in 0..128 {
        let addr = make_addr(10, (i / 256) as u8, 0, (i % 256).max(1) as u8, 25565);
        node.try_accept(addr);
    }

    // 50 peers flood repeatedly
    let flooders: Vec<SocketAddr> = node.peers.keys().copied().take(50).collect();
    let mut bans = 0;
    for addr in &flooders {
        // Each flood = -15, needs 7 floods to reach 0 (100/15 = 6.67)
        for _ in 0..10 {
            if node.penalize_flood(*addr) {
                bans += 1;
                break;
            }
        }
    }

    // After 10 flood penalties each: score = 100 - 150 = -50 → banned
    let banned_count = flooders
        .iter()
        .filter(|a| node.scores.get(a).map_or(false, |s| s.is_banned()))
        .count();

    assert!(banned_count > 0, "at least some flooders should be banned");

    println!(
        "Sybil F (scoring): {}/50 flooders banned after repeated floods",
        banned_count
    );
}

// ============================================================================
// TEST G: False positive rate
// ============================================================================

#[test]
fn test_sybil_false_positives() {
    let mut node = SimNode::new();

    // Add 100 honest peers from 100 different subnets
    for i in 0..100 {
        let addr = make_addr(10, 0, i as u8, 1, 25565);
        node.try_accept(addr);
    }
    assert_eq!(node.peers.len(), 100);

    // Apply decay to all (honest peers should stay at 100)
    node.decay_all();
    for score in node.scores.values() {
        assert_eq!(score.score, PEER_SCORE_INITIAL);
    }

    // No honest peers should be banned
    let honest_banned = node.scores.values().filter(|s| s.is_banned()).count();
    assert_eq!(honest_banned, 0, "no honest peer should be banned");

    // A single invalid message from an honest peer: -10, score = 90
    let honest: Vec<SocketAddr> = node.peers.keys().copied().take(1).collect();
    node.penalize_invalid(honest[0]);
    assert_eq!(node.scores[&honest[0]].score, 90);
    assert!(!node.scores[&honest[0]].is_banned());

    println!("Sybil F (false positives): 0/100 honest peers banned");
}

// ============================================================================
// TEST H: Ban recovery
// ============================================================================

#[test]
fn test_sybil_ban_recovery() {
    let mut node = SimNode::new();
    let addr = make_addr(10, 0, 0, 1, 25565);
    node.try_accept(addr);

    // Flood until banned
    for _ in 0..10 {
        node.penalize_flood(addr);
    }
    assert!(node.scores[&addr].is_banned(), "peer should be banned");

    // Simulate time passing (ban expires after 300s)
    // In real code, Instant::now() advances. Here we force-override.
    node.scores.get_mut(&addr).unwrap().banned_until =
        Some(Instant::now() - Duration::from_secs(1));

    assert!(
        !node.scores[&addr].is_banned(),
        "peer should be unbanned after expiry"
    );

    // Score is still low (-50) — needs decay to recover
    assert_eq!(node.scores[&addr].score, -50);

    println!(
        "Sybil H (ban recovery): peer unbanned after temp ban expiry, score={}",
        node.scores[&addr].score
    );
}

// ============================================================================
// TEST I: Eclipse resistance — honest peer retention
// ============================================================================

#[test]
fn test_sybil_honest_retention() {
    let mut node = SimNode::new();

    // 10 honest peers from diverse subnets
    let honest: Vec<SocketAddr> = (0..10)
        .map(|i| make_addr(10, 0, i as u8, 1, 25565))
        .collect();
    for addr in &honest {
        node.try_accept(*addr);
    }

    // 500 attackers from diverse subnets
    let mut attacker_accepted = 0;
    for i in 0..500u16 {
        let addr = make_addr(10, ((i / 4) + 100) as u8, 0, (i % 256).max(1) as u8, 25565);
        if node.try_accept(addr) {
            attacker_accepted += 1;
        }
    }

    // All 10 honest peers still connected
    for addr in &honest {
        assert!(
            node.peers.contains_key(addr),
            "honest peer {} must be retained",
            addr
        );
    }

    // Attackers limited by MAX_PEERS
    let total = node.peers.len();
    assert!(total <= MAX_PEERS);

    // Honest % in connected peers
    let honest_pct = honest.len() as f64 / total as f64 * 100.0;

    println!(
        "Sybil I (honest retention): {}/{} honest ({:.1}%), {} attackers accepted, {} total",
        honest.len(),
        total,
        honest_pct,
        attacker_accepted,
        total
    );
}

// ============================================================================
// TEST J: Full-scale 500 peer simulation
// ============================================================================

#[test]
fn test_sybil_500_scale() {
    let mut node = SimNode::new();

    // 500 attackers across 500 subnets (maximally diverse)
    let mut accepted = 0;
    for i in 0..500u16 {
        let a = (i / 256) as u8;
        let b = (i % 256) as u8;
        let addr = make_addr(10, a, b, 1, 25565);
        if node.try_accept(addr) {
            accepted += 1;
        }
    }

    assert_eq!(accepted, MAX_PEERS, "capped at MAX_PEERS");

    // Measure subnet diversity of accepted peers
    let mut subnets: HashMap<[u8; 3], usize> = HashMap::new();
    for addr in node.peers.keys() {
        if let Some(s) = subnet_24(*addr) {
            *subnets.entry(s).or_insert(0) += 1;
        }
    }

    let max_per_subnet = subnets.values().max().unwrap_or(&0);
    let unique_subnets = subnets.len();

    assert!(*max_per_subnet <= MAX_PEERS_PER_SUBNET);

    println!(
        "Sybil J (500 scale): {}/500 accepted, {} unique subnets, max {}/subnet, {} rejected",
        accepted,
        unique_subnets,
        max_per_subnet,
        500 - accepted
    );
}
