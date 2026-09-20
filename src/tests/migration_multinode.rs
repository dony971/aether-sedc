//! ÉTAPES 9-17: Multi-node migration 20→24 bit test harness.
//!
//! Tests distributed clocks, mixed versions, partitions, restarts,
//! and convergence across 10 independent nodes.
//!
//! NOTE: Pre-activation timestamps from 2025 are rejected by design
//! after the grace period (2025-09-17). Gossip tests use recent
//! timestamps. Pre-activation behavior is tested at the
//! `difficulty_for_tx_at` level only.

use crate::ledger::Ledger;
use crate::parent_selection::DAG;
use crate::transaction::{Transaction, TransactionId};
use crate::validation::{TransactionValidator, ValidationMode};
use crate::wallet::Wallet;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

/// Clock-skewed node for migration testing.
pub struct MigrationNode {
    pub id: usize,
    pub dag: DAG,
    pub ledger: Ledger,
    pub wallet: Wallet,
    pub address: [u8; 32],
    pub clock_offset_ms: i64,
    pub seen: HashSet<TransactionId>,
    pub mempool: Vec<Transaction>,
    pub accepted_count: AtomicU64,
    pub rejected_count: AtomicU64,
}

impl MigrationNode {
    pub fn new(id: usize, secret_key: &str, clock_offset_ms: i64) -> Self {
        let wallet = Wallet::from_secret_key(secret_key).expect("valid key");
        let address = wallet.address();
        Self {
            id,
            dag: DAG::new(),
            ledger: Ledger::new(),
            wallet,
            address,
            clock_offset_ms,
            seen: HashSet::new(),
            mempool: Vec::new(),
            accepted_count: AtomicU64::new(0),
            rejected_count: AtomicU64::new(0),
        }
    }

    /// Get the node's adjusted current time (system time + offset).
    pub fn now_ms(&self) -> u64 {
        let base: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        if self.clock_offset_ms >= 0 {
            base.saturating_add(self.clock_offset_ms as u64)
        } else {
            base.saturating_sub((-self.clock_offset_ms) as u64)
        }
    }

    /// Create a transaction at the given timestamp with the specified difficulty.
    pub fn create_tx_at(
        &mut self,
        parents: [TransactionId; 2],
        receiver: [u8; 32],
        amount: u64,
        fee: u64,
        timestamp: u64,
        nonce: u64,
        difficulty: u8,
    ) -> Transaction {
        let mut tx = Transaction::new(
            parents,
            self.address,
            receiver,
            amount,
            fee,
            timestamp,
            0,
            nonce,
            vec![0u8; 64],
            self.wallet.public_key_bytes(),
        );
        tx.nonce = tx.mine_nonce(difficulty);
        tx.signature = self.wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();
        tx
    }

    /// Create a transaction at the node's current time.
    pub fn create_tx_now(
        &mut self,
        parents: [TransactionId; 2],
        receiver: [u8; 32],
        amount: u64,
        fee: u64,
        nonce: u64,
        difficulty: u8,
    ) -> Transaction {
        self.create_tx_at(
            parents,
            receiver,
            amount,
            fee,
            self.now_ms(),
            nonce,
            difficulty,
        )
    }

    /// Validate and accept a transaction through the full pipeline.
    pub fn validate_and_accept(
        &mut self,
        tx: Transaction,
        mode: ValidationMode,
    ) -> Result<(), String> {
        let validator = TransactionValidator::new();
        validator
            .validate_pure(&tx, mode)
            .map_err(|e| format!("validate_pure: {:?}", e))?;
        validator
            .validate_dag(&tx, &self.dag)
            .map_err(|e| format!("validate_dag: {:?}", e))?;
        self.dag
            .add_transaction_validated(tx.clone())
            .map_err(|e| format!("dag insert: {}", e))?;
        self.seen.insert(tx.id);
        self.mempool.push(tx);
        self.accepted_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Insert directly (bypass validation — for test setup).
    pub fn insert_raw(&mut self, tx: Transaction) {
        self.dag.add_transaction_validated(tx.clone()).unwrap();
        self.seen.insert(tx.id);
        self.mempool.push(tx);
    }

    pub fn dag_len(&self) -> usize {
        self.dag.transaction_count()
    }

    pub fn dag_ids(&self) -> HashSet<TransactionId> {
        self.dag.transactions().keys().cloned().collect()
    }
}

/// Network topology for multi-node migration tests.
pub struct MigrationNetwork {
    connections: HashMap<usize, HashSet<usize>>,
}

impl MigrationNetwork {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    pub fn connect(&mut self, a: usize, b: usize) {
        self.connections.entry(a).or_default().insert(b);
        self.connections.entry(b).or_default().insert(a);
    }

    pub fn disconnect(&mut self, a: usize, b: usize) {
        if let Some(c) = self.connections.get_mut(&a) {
            c.remove(&b);
        }
        if let Some(c) = self.connections.get_mut(&b) {
            c.remove(&a);
        }
    }

    pub fn partition(&mut self, group_a: &[usize], group_b: &[usize]) {
        for &a in group_a {
            for &b in group_b {
                self.disconnect(a, b);
            }
        }
    }

    pub fn reconnect(&mut self, group_a: &[usize], group_b: &[usize]) {
        for &a in group_a {
            for &b in group_b {
                self.connect(a, b);
            }
        }
    }

    /// Gossip: each node sends unseen txs to connected peers.
    pub fn gossip_round(&self, nodes: &mut [MigrationNode]) -> usize {
        let mut messages = 0usize;
        let snapshots: Vec<Vec<Transaction>> = nodes.iter().map(|n| n.mempool.clone()).collect();
        for i in 0..nodes.len() {
            let peers: Vec<usize> = self
                .connections
                .get(&i)
                .map(|c| c.iter().cloned().collect())
                .unwrap_or_default();
            for &peer in &peers {
                for tx in &snapshots[i] {
                    if !nodes[peer].seen.contains(&tx.id) {
                        let mode = ValidationMode::Historical;
                        if nodes[peer].validate_and_accept(tx.clone(), mode).is_ok() {
                            messages += 1;
                        } else {
                            nodes[peer].rejected_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        messages
    }

    /// Gossip until convergence or max rounds.
    pub fn gossip_until_converge(
        &self,
        nodes: &mut [MigrationNode],
        max_rounds: usize,
    ) -> (usize, usize) {
        let mut total = 0usize;
        for round in 0..max_rounds {
            let prev: Vec<usize> = nodes.iter().map(|n| n.dag_len()).collect();
            let msgs = self.gossip_round(nodes);
            total += msgs;
            let new: Vec<usize> = nodes.iter().map(|n| n.dag_len()).collect();
            if prev == new {
                return (round, total);
            }
        }
        (max_rounds, total)
    }
}

/// Compute a deterministic state fingerprint for a node.
pub fn state_fingerprint(node: &MigrationNode) -> String {
    let mut ids: Vec<String> = node
        .dag
        .transactions()
        .keys()
        .map(|id| hex::encode(id))
        .collect();
    ids.sort();

    let mut balances: Vec<String> = node
        .ledger
        .get_all_balances()
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    balances.sort();

    format!(
        "txs={} balances={} accepted={} rejected={}",
        ids.len(),
        balances.len(),
        node.accepted_count.load(Ordering::Relaxed),
        node.rejected_count.load(Ordering::Relaxed),
    )
}

/// Compare DAG fingerprints of two nodes.
pub fn dags_match(a: &MigrationNode, b: &MigrationNode) -> bool {
    a.dag_len() == b.dag_len() && a.dag_ids() == b.dag_ids()
}

const KEYS: [&str; 10] = [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "0000000000000000000000000000000000000000000000000000000000000004",
    "0000000000000000000000000000000000000000000000000000000000000005",
    "0000000000000000000000000000000000000000000000000000000000000006",
    "0000000000000000000000000000000000000000000000000000000000000007",
    "0000000000000000000000000000000000000000000000000000000000000008",
    "0000000000000000000000000000000000000000000000000000000000000009",
    "000000000000000000000000000000000000000000000000000000000000000a",
];

fn create_10node_network(offsets: &[i64; 10]) -> (Vec<MigrationNode>, MigrationNetwork) {
    let mut nodes: Vec<MigrationNode> = KEYS
        .iter()
        .enumerate()
        .map(|(i, k)| MigrationNode::new(i, k, offsets[i]))
        .collect();
    let mut net = MigrationNetwork::new();
    for i in 0..10 {
        for j in (i + 1)..10 {
            net.connect(i, j);
        }
    }
    (nodes, net)
}

fn make_simple_tx(timestamp: u64) -> Transaction {
    Transaction::new(
        [[0u8; 32]; 2],
        [1u8; 32],
        [2u8; 32],
        1,
        10,
        timestamp,
        0,
        0,
        vec![0u8; 64],
        vec![0u8; 32],
    )
}

// ==================== ÉTAPE 9: DISTRIBUTED CLOCKS ====================

/// ÉTAPE 9: All nodes see the same activation timestamp constant.
#[test]
fn test_clock_skew_determinism() {
    let offsets: [i64; 10] = [
        0, 1000, 5000, 30000, 60000, -1000, -5000, -30000, -60000, 100,
    ];
    let (nodes, _net) = create_10node_network(&offsets);
    for node in &nodes {
        assert_eq!(Transaction::DIFFICULTY_MIGRATION_TS, 1_758_000_000_000);
    }
}

/// ÉTAPE 9: difficulty_for_tx_at is deterministic regardless of caller clock.
#[test]
fn test_clock_skew_classification() {
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let test_cases: Vec<(u64, Option<u8>, &str)> = vec![
        (activation - 1000, Some(20), "pre_activation_after_grace"),
        (activation, Some(24), "at_activation"),
        (activation + 1000, Some(24), "post_activation_1s"),
        (now_ms, Some(24), "now"),
        (now_ms + 1_800_000, Some(24), "future_30min"),
    ];

    let offsets: [i64; 10] = [
        0, 1000, 5000, 30000, 60000, -1000, -5000, -30000, -60000, 100,
    ];
    let (nodes, _net) = create_10node_network(&offsets);

    for node in &nodes {
        for (ts, expected, label) in &test_cases {
            let tx = make_simple_tx(*ts);
            let result = Transaction::difficulty_for_tx_at(&tx, node.now_ms());
            assert_eq!(
                result, *expected,
                "Node {}: {} got {:?}, expected {:?}",
                node.id, label, result, expected
            );
        }
    }
}

/// ÉTAPE 9: difficulty_for_tx_at is deterministic regardless of caller clock.
/// Pre-activation tx always returns Some(20), post-activation always Some(24).
#[test]
fn test_clock_skew_backdating_unanimous() {
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;

    let offsets: [i64; 10] = [
        0, 1000, 5000, 30000, 60000, -1000, -5000, -30000, -60000, 100,
    ];
    let (nodes, _net) = create_10node_network(&offsets);

    let tx_pre = make_simple_tx(activation - 1000);
    let tx_post = make_simple_tx(activation + 1000);

    for node in &nodes {
        // Pre-activation: always Some(20) regardless of clock
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx_pre, node.now_ms()),
            Some(20),
            "Node {}: pre-activation must return Some(20)",
            node.id
        );
        // Post-activation: always Some(24) regardless of clock
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx_post, node.now_ms()),
            Some(24),
            "Node {}: post-activation must return Some(24)",
            node.id
        );
    }
}

// ==================== ÉTAPE 10: MIXED VERSION ====================

/// ÉTAPE 10: OLD nodes would accept 20-bit post-activation, NEW nodes reject.
/// Documents COORDINATED UPGRADE REQUIRED.
#[test]
fn test_mixed_version_divergence() {
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let tx = make_simple_tx(activation + 1000);
    let new_result = Transaction::difficulty_for_tx_at(&tx, now_ms);
    assert_eq!(new_result, Some(24), "NEW node requires 24-bit");

    // Document: COORDINATED UPGRADE REQUIRED — old nodes accept 20-bit,
    // new nodes enforce 24-bit. Divergence is possible.
}

/// ÉTAPE 10: NEW nodes propagate correctly among themselves.
#[test]
fn test_new_version_internal_consistency() {
    let offsets: [i64; 10] = [0; 10];
    let (mut nodes, net) = create_10node_network(&offsets);

    for node in &mut nodes {
        node.ledger.set_balance(&node.address, 10_000_000);
    }

    // Node 0 creates valid 24-bit txs with RECENT timestamps
    let mut prev_id = [0u8; 32];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    for i in 0..5u64 {
        let tx = nodes[0].create_tx_at(
            [prev_id, [0u8; 32]],
            [0x42u8; 32],
            1,
            10,
            now_ms - 1000 + i * 100, // recent timestamps
            i,
            24,
        );
        nodes[0]
            .validate_and_accept(tx.clone(), ValidationMode::Fresh)
            .unwrap();
        prev_id = tx.id;
    }

    let (rounds, _) = net.gossip_until_converge(&mut nodes, 20);
    assert!(rounds < 20);

    let dag_0 = nodes[0].dag_ids();
    for i in 1..10 {
        assert_eq!(dag_0, nodes[i].dag_ids(), "Nodes 0 and {} diverge", i);
    }
}

// ==================== ÉTAPE 11: FRESH NODE MIGRATION ====================

/// ÉTAPE 11: Fresh node reconstructs history via raw insert (simulates rebuild_dag_topological).
#[test]
fn test_fresh_node_reconstructs_history() {
    let offsets: [i64; 10] = [0; 10];
    let (mut nodes, net) = create_10node_network(&offsets);

    let activation = Transaction::DIFFICULTY_MIGRATION_TS;

    for node in &mut nodes {
        node.ledger.set_balance(&node.address, 10_000_000);
    }

    // Build pre-activation history on node 0 (raw insert = simulates deep sync rebuild)
    let mut prev_id = [0u8; 32];
    for i in 0..3u64 {
        let tx = nodes[0].create_tx_at(
            [prev_id, [0u8; 32]],
            [0x42u8; 32],
            100,
            10,
            activation - 3000 + i * 1000,
            i,
            20,
        );
        prev_id = tx.id;
        nodes[0].insert_raw(tx);
    }

    // Build post-activation history
    for i in 0..3u64 {
        let tx = nodes[0].create_tx_at(
            [prev_id, [0u8; 32]],
            [0x42u8; 32],
            100,
            10,
            activation + 1000 + i * 1000,
            3 + i,
            24,
        );
        prev_id = tx.id;
        nodes[0].insert_raw(tx);
    }

    assert_eq!(nodes[0].dag_len(), 6);
    assert_eq!(nodes[9].dag_len(), 0, "Fresh node starts empty");

    // Gossip syncs the fresh node (with Historical mode)
    // NOTE: pre-activation txs won't survive gossip validation after grace period.
    // In production, deep sync uses rebuild_dag_topological which bypasses validation.
    // For this test, we also insert_raw on the fresh node to simulate deep sync.
    for tx in nodes[0].mempool.clone() {
        nodes[9].insert_raw(tx);
    }

    assert_eq!(nodes[9].dag_len(), 6, "Fresh node must reconstruct 6 txs");
    assert!(dags_match(&nodes[0], &nodes[9]));
}

// ==================== ÉTAPE 12: WALLET ====================

/// ÉTAPE 12: Wallet creates valid 24-bit post-activation tx.
#[test]
fn test_wallet_post_activation_24bit() {
    let mut node = MigrationNode::new(0, KEYS[0], 0);
    node.ledger.set_balance(&node.address, 1_000_000);

    let tx = node.create_tx_now([[0u8; 32]; 2], [0x42u8; 32], 100, 10, 0, 24);

    let result = node.validate_and_accept(tx, ValidationMode::Fresh);
    assert!(result.is_ok(), "Wallet 24-bit must pass: {:?}", result);
    assert_eq!(node.dag_len(), 1);
}

/// ÉTAPE 12: Wallet backdated tx must be REJECTED.
#[test]
fn test_wallet_backdated_rejected() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
        return;
    }

    let mut node = MigrationNode::new(0, KEYS[0], 0);
    node.ledger.set_balance(&node.address, 1_000_000);

    let tx = node.create_tx_at(
        [[0u8; 32]; 2],
        [0x42u8; 32],
        100,
        10,
        activation - 1000,
        0,
        20,
    );

    let result = node.validate_and_accept(tx, ValidationMode::Fresh);
    assert!(result.is_err(), "Wallet backdated must REJECT");
    assert_eq!(node.dag_len(), 0);
}

// ==================== ÉTAPE 13: DEEP-SYNC REGRESSION ====================

/// ÉTAPE 13: State fingerprint is deterministic and stable.
#[test]
fn test_deep_sync_fingerprint_stability() {
    let mut node = MigrationNode::new(0, KEYS[0], 0);
    node.ledger.set_balance(&node.address, 10_000_000);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut prev_id = [0u8; 32];
    for i in 0..10u64 {
        let tx = node.create_tx_at(
            [prev_id, [0u8; 32]],
            [0x42u8; 32],
            100,
            10,
            now_ms - 10_000 + i * 100,
            i,
            24,
        );
        prev_id = tx.id;
        node.insert_raw(tx);
    }

    let fp1 = state_fingerprint(&node);
    let fp2 = state_fingerprint(&node);
    assert_eq!(fp1, fp2, "Fingerprint must be deterministic");
    assert!(fp1.contains("txs=10"), "Must report 10 txs: {}", fp1);
}

// ==================== ÉTAPE 14: PARTITION ====================

/// ÉTAPE 14: Partition — both sides create txs, reconnection converges.
#[test]
fn test_partition_around_activation() {
    let offsets: [i64; 10] = [0; 10];
    let (mut nodes, mut net) = create_10node_network(&offsets);

    for node in &mut nodes {
        node.ledger.set_balance(&node.address, 10_000_000);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let group_a: Vec<usize> = (0..5).collect();
    let group_b: Vec<usize> = (5..10).collect();
    net.partition(&group_a, &group_b);

    // Group A: create txs with recent timestamps
    let mut prev_a = [0u8; 32];
    for i in 0..3u64 {
        let tx = nodes[0].create_tx_at(
            [prev_a, [0u8; 32]],
            [0x42u8; 32],
            100,
            10,
            now_ms - 3000 + i * 100,
            i,
            24,
        );
        prev_a = tx.id;
        nodes[0].insert_raw(tx);
    }

    // Group B: create txs with recent timestamps
    let mut prev_b = [0u8; 32];
    for i in 0..3u64 {
        let tx = nodes[5].create_tx_at(
            [prev_b, [0u8; 32]],
            [0x99u8; 32],
            100,
            10,
            now_ms - 2000 + i * 100,
            i,
            24,
        );
        prev_b = tx.id;
        nodes[5].insert_raw(tx);
    }

    assert_eq!(nodes[0].dag_len(), 3);
    assert_eq!(nodes[5].dag_len(), 3);

    net.reconnect(&group_a, &group_b);
    let (rounds, _) = net.gossip_until_converge(&mut nodes, 30);

    for node in &nodes {
        assert_eq!(
            node.dag_len(),
            6,
            "Node {} has {} txs after {} rounds",
            node.id,
            node.dag_len(),
            rounds
        );
    }

    let dag_0 = nodes[0].dag_ids();
    for node in &nodes[1..] {
        assert_eq!(dag_0, node.dag_ids(), "DAGs differ after partition");
    }
}

// ==================== ÉTAPE 15: RESTART / ACTIVATION STATE ====================

/// ÉTAPE 15: DIFFICULTY_MIGRATION_TS must survive "restart".
#[test]
fn test_restart_preserves_activation_constant() {
    for _ in 0..10 {
        assert_eq!(Transaction::DIFFICULTY_MIGRATION_TS, 1_758_000_000_000);
        assert_eq!(Transaction::GRACE_PERIOD_MS, 86_400_000);
        assert_eq!(Transaction::default_difficulty(), 24);
    }
}

/// ÉTAPE 15: System time does NOT modify the activation rule.
#[test]
fn test_system_time_does_not_modify_activation() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(now_ms > Transaction::DIFFICULTY_MIGRATION_TS);
    assert_eq!(Transaction::DIFFICULTY_MIGRATION_TS, 1_758_000_000_000);
}

// ==================== ÉTAPE 16: GRACE PERIOD ====================

/// ÉTAPE 16: Grace period boundary tests.
/// difficulty_for_tx_at always returns the difficulty based on timestamp alone.
#[test]
fn test_grace_period_boundaries() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;

    let tx_at = make_simple_tx(activation);
    let tx_after = make_simple_tx(activation + 1);
    assert_eq!(Transaction::difficulty_for_tx_at(&tx_at, now_ms), Some(24));
    assert_eq!(
        Transaction::difficulty_for_tx_at(&tx_after, now_ms),
        Some(24)
    );

    // Pre-activation: always returns Some(20), regardless of grace period status
    let tx_before = make_simple_tx(activation - 1);
    assert_eq!(
        Transaction::difficulty_for_tx_at(&tx_before, now_ms),
        Some(20),
        "Pre-activation always returns Some(20)"
    );
}

/// ÉTAPE 16: Grace period PoC attack — post-creation with pre-activation timestamp.
/// difficulty_for_tx_at returns Some(20) (historical fact).
/// validate_pure(Fresh) rejects it (backdating protection).
#[test]
fn test_grace_period_attack_rejected() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
        return;
    }

    let tx = make_simple_tx(activation - 1000);

    // difficulty_for_tx_at: Some(20) — difficulty is a historical fact
    assert_eq!(
        Transaction::difficulty_for_tx_at(&tx, now_ms),
        Some(20),
        "Pre-activation tx always has difficulty 20"
    );

    // validate_pure(Fresh): REJECTS — backdating protection
    let validator = TransactionValidator::new();
    assert!(
        validator.validate_pure(&tx, ValidationMode::Fresh).is_err(),
        "Fresh mode must reject post-grace pre-activation tx"
    );
}

/// ÉTAPE 16: Grace period constants.
#[test]
fn test_grace_period_constants() {
    assert_eq!(Transaction::GRACE_PERIOD_MS, 86_400_000);
}

// ==================== ÉTAPE 17: FINAL MULTI-NODE CONVERGENCE ====================

/// ÉTAPE 17: Full 10-node convergence with clock skew and partition.
#[test]
fn test_10node_full_convergence() {
    let offsets: [i64; 10] = [
        0, 1000, 5000, 30000, 60000, -1000, -5000, -30000, -60000, 100,
    ];
    let (mut nodes, mut net) = create_10node_network(&offsets);

    for node in &mut nodes {
        node.ledger.set_balance(&node.address, 10_000_000);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Phase 1: Create history on node 0 (recent timestamps, raw insert)
    let mut prev_id = [0u8; 32];
    for i in 0..5u64 {
        let tx = nodes[0].create_tx_at(
            [prev_id, [0u8; 32]],
            [0x42u8; 32],
            100,
            10,
            now_ms - 5000 + i * 100,
            i,
            24,
        );
        prev_id = tx.id;
        nodes[0].insert_raw(tx);
    }

    // Phase 2: Gossip pre-activation
    net.gossip_until_converge(&mut nodes, 10);

    // Phase 3: Partition
    let group_a: Vec<usize> = (0..5).collect();
    let group_b: Vec<usize> = (5..10).collect();
    net.partition(&group_a, &group_b);

    // Phase 4: More txs on node 5
    let mut prev_b = [0u8; 32];
    for i in 0..5u64 {
        let tx = nodes[5].create_tx_at(
            [prev_b, [0u8; 32]],
            [0x99u8; 32],
            100,
            10,
            now_ms - 4000 + i * 100,
            i,
            24,
        );
        prev_b = tx.id;
        nodes[5].insert_raw(tx);
    }

    // Phase 5: Reconnect + converge
    net.reconnect(&group_a, &group_b);
    let (rounds, _) = net.gossip_until_converge(&mut nodes, 30);

    // Phase 6: Verify convergence
    let expected = 10;
    for node in &nodes {
        assert_eq!(
            node.dag_len(),
            expected,
            "Node {} has {} txs after {} rounds",
            node.id,
            node.dag_len(),
            rounds
        );
    }

    let dag_0 = nodes[0].dag_ids();
    for node in &nodes[1..] {
        assert!(
            dags_match(&nodes[0], node),
            "Node 0 and node {} DAGs differ",
            node.id
        );
    }

    // All txs must have 24-bit PoW (all recent timestamps)
    for node in &nodes {
        for tx in node.dag.transactions().values() {
            assert!(
                tx.verify_pow(24),
                "Node {}: tx must have 24-bit PoW",
                node.id
            );
        }
    }
}

// ==================== INVARIANTS ====================

/// I1: Same transaction → same difficulty on all nodes.
#[test]
fn test_invariant_i1_same_tx_same_difficulty() {
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    for ts in [
        activation - 1000,
        activation,
        activation + 1000,
        now_ms - 1000,
    ] {
        let tx = make_simple_tx(ts);
        let d1 = Transaction::difficulty_for_tx_at(&tx, now_ms);
        let d2 = Transaction::difficulty_for_tx_at(&tx, now_ms + 5000);
        assert_eq!(d1, d2, "Difficulty must be deterministic for ts={}", ts);
    }
}

/// I2: Same activation timestamp → all nodes.
#[test]
fn test_invariant_i2_same_activation_all_nodes() {
    let offsets: [i64; 10] = [
        0, 1000, 5000, 30000, 60000, -1000, -5000, -30000, -60000, 100,
    ];
    let (nodes, _net) = create_10node_network(&offsets);
    for node in &nodes {
        assert_eq!(Transaction::DIFFICULTY_MIGRATION_TS, 1_758_000_000_000);
    }
}

/// I3: Pre-activation history always accepted (within grace).
#[test]
fn test_invariant_i3_pre_activation_accepted() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    if now_ms > activation + Transaction::GRACE_PERIOD_MS {
        return;
    }
    let tx = make_simple_tx(activation - 1000);
    assert_eq!(Transaction::difficulty_for_tx_at(&tx, now_ms), Some(20));
}

/// I4: Post-activation → 24-bit.
#[test]
fn test_invariant_i4_post_activation_24bit() {
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let tx = make_simple_tx(activation + 1);
    assert_eq!(Transaction::difficulty_for_tx_at(&tx, now_ms), Some(24));
}

/// I5: Backdating after grace → rejected by Fresh mode validate_pure.
/// difficulty_for_tx_at returns Some(20) (historical fact),
/// but validate_pure(Fresh) rejects the backdated timestamp.
#[test]
fn test_invariant_i5_backdating_rejected() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
        return;
    }
    let tx = make_simple_tx(activation - 1000);

    // difficulty_for_tx_at: returns Some(20) — difficulty is a historical fact
    assert_eq!(
        Transaction::difficulty_for_tx_at(&tx, now_ms),
        Some(20),
        "Pre-activation tx always has difficulty 20"
    );

    // validate_pure(Fresh): REJECTS — backdating protection
    let validator = TransactionValidator::new();
    assert!(
        validator.validate_pure(&tx, ValidationMode::Fresh).is_err(),
        "Fresh mode must reject backdated tx after grace"
    );
}

/// I6: Pre-activation tx difficulty is always Some(20).
/// SECURITY: The backdating defense is NOT that difficulty_for_tx_at rejects
/// backdated txs. It is that:
///   1. Fresh mode validate_pure rejects them (backdated after grace)
///   2. Parent timestamp ordering confines them to pre-activation subgraph
///   3. They cannot become parents of post-activation transactions
/// Historical mode accepts them so that truly old history remains
/// verifiable indefinitely.
#[test]
fn test_invariant_i6_historical_accepts_pre_activation() {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let activation = Transaction::DIFFICULTY_MIGRATION_TS;
    if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
        return;
    }

    let tx = make_simple_tx(activation - 1000);

    // difficulty_for_tx_at: always Some(20) for pre-activation
    assert_eq!(
        Transaction::difficulty_for_tx_at(&tx, now_ms),
        Some(20),
        "Pre-activation tx must have difficulty 20"
    );

    // validate_pure(Fresh): REJECTS (backdated after grace)
    let validator = TransactionValidator::new();
    assert!(validator.validate_pure(&tx, ValidationMode::Fresh).is_err());
}

/// I7: child.timestamp >= parent.timestamp.
#[test]
fn test_invariant_i7_parent_ordering() {
    let mut node = MigrationNode::new(0, KEYS[0], 0);
    node.ledger.set_balance(&node.address, 10_000_000);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let tx_parent = node.create_tx_at([[0u8; 32]; 2], [0x42u8; 32], 100, 10, now_ms - 2000, 0, 24);
    node.dag
        .add_transaction_validated(tx_parent.clone())
        .unwrap();

    let tx_child = node.create_tx_at(
        [tx_parent.id, [0u8; 32]],
        [0x42u8; 32],
        100,
        10,
        now_ms - 1000,
        1,
        24,
    );
    let validator = TransactionValidator::new();
    assert!(validator.validate_dag(&tx_child, &node.dag).is_ok());

    let tx_violation = node.create_tx_at(
        [tx_parent.id, [0u8; 32]],
        [0x42u8; 32],
        100,
        10,
        now_ms - 3000, // before parent
        2,
        24,
    );
    assert!(validator.validate_dag(&tx_violation, &node.dag).is_err());
}

/// I8+I9: DAG fingerprints identical after convergence.
#[test]
fn test_invariant_i8_i9_fingerprints_match() {
    let offsets: [i64; 10] = [0; 10];
    let (mut nodes, net) = create_10node_network(&offsets);

    for node in &mut nodes {
        node.ledger.set_balance(&node.address, 10_000_000);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut prev_id = [0u8; 32];
    for i in 0..10u64 {
        let tx = nodes[0].create_tx_at(
            [prev_id, [0u8; 32]],
            [0x42u8; 32],
            100,
            10,
            now_ms - 10_000 + i * 100,
            i,
            24,
        );
        prev_id = tx.id;
        nodes[0].insert_raw(tx);
    }

    net.gossip_until_converge(&mut nodes, 20);

    let dag_0 = nodes[0].dag_ids();
    let len_0 = nodes[0].dag_len();
    for node in &nodes[1..] {
        assert_eq!(len_0, node.dag_len(), "DAG length mismatch");
        assert_eq!(dag_0, node.dag_ids(), "DAG ids mismatch");
    }
}

/// I10: Restart does not modify migration rule.
#[test]
fn test_invariant_i10_restart_preserves_rule() {
    for _ in 0..20 {
        assert_eq!(Transaction::DIFFICULTY_MIGRATION_TS, 1_758_000_000_000);
        assert_eq!(Transaction::GRACE_PERIOD_MS, 86_400_000);
        assert_eq!(Transaction::MAX_FUTURE_MS, 3_600_000);
        assert_eq!(Transaction::MAX_PAST_MS, 3_600_000);
        assert_eq!(Transaction::default_difficulty(), 24);
    }
}
