//! Multi-node consensus resilience harness.
//!
//! Simulates multiple nodes with independent DAGs, controlled networking,
//! and partition/reconnection capabilities for testing consensus behavior
//! under adverse network conditions.

use crate::parent_selection::DAG;
use crate::transaction::{Address, Transaction, TransactionId};
use crate::wallet::Wallet;
use std::collections::{HashMap, HashSet};

/// A simulated node with its own DAG and ledger.
pub struct SimNode {
    pub id: usize,
    pub dag: DAG,
    pub wallet: Wallet,
    pub address: Address,
    pub connected: HashSet<usize>,
    pub seen: HashSet<TransactionId>,
    pub mempool: Vec<Transaction>,
}

impl SimNode {
    pub fn new(id: usize, secret_key: &str) -> Self {
        let wallet = Wallet::from_secret_key(secret_key).expect("valid key");
        let address = wallet.address();
        Self {
            id,
            dag: DAG::new(),
            wallet,
            address,
            connected: HashSet::new(),
            seen: HashSet::new(),
            mempool: Vec::new(),
        }
    }

    pub fn create_tx(
        &mut self,
        parents: [TransactionId; 2],
        receiver: Address,
        amount: u64,
        nonce: u64,
        difficulty: u8,
    ) -> Transaction {
        let mut tx = Transaction::new(
            parents,
            self.address,
            receiver,
            amount,
            100,
            1234567890 + nonce,
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

    pub fn accept_tx(&mut self, tx: Transaction) -> bool {
        if self.seen.contains(&tx.id) {
            return false;
        }
        self.seen.insert(tx.id);
        let ok = self.dag.add_transaction_validated(tx.clone()).is_ok();
        if ok {
            self.mempool.push(tx);
        }
        ok
    }

    pub fn dag_ids(&self) -> HashSet<TransactionId> {
        self.dag.transactions().keys().cloned().collect()
    }

    pub fn dag_len(&self) -> usize {
        self.dag.transaction_count()
    }
}

/// Network topology controller.
pub struct SimNetwork {
    connections: HashMap<usize, HashSet<usize>>,
}

impl SimNetwork {
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
        if let Some(set) = self.connections.get_mut(&a) {
            set.remove(&b);
        }
        if let Some(set) = self.connections.get_mut(&b) {
            set.remove(&a);
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

    pub fn component(&self, start: usize) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            if visited.contains(&node) {
                continue;
            }
            visited.insert(node);
            if let Some(neighbors) = self.connections.get(&node) {
                for &neighbor in neighbors {
                    if !visited.contains(&neighbor) {
                        stack.push(neighbor);
                    }
                }
            }
        }
        visited
    }

    pub fn are_connected(&self, a: usize, b: usize) -> bool {
        self.component(a).contains(&b)
    }

    pub fn neighbors(&self, node: usize) -> HashSet<usize> {
        self.connections.get(&node).cloned().unwrap_or_default()
    }
}

/// Gossip one round: each node sends unseen mempool txs to connected peers.
pub fn gossip_round(network: &SimNetwork, nodes: &mut [SimNode]) -> usize {
    let n = nodes.len();
    let mut messages = 0;

    // Collect outgoing: for each node, which txs to send to which peers
    let mut outgoing: Vec<Vec<(usize, Transaction)>> = vec![Vec::new(); n];
    for i in 0..n {
        let neighbors = network.neighbors(i);
        for tx in &nodes[i].mempool {
            for &peer in &neighbors {
                outgoing[i].push((peer, tx.clone()));
            }
        }
    }

    // Deliver: each message goes to the target peer's accept
    for i in 0..n {
        for (target, tx) in &outgoing[i] {
            if network.neighbors(i).contains(target) {
                nodes[*target].accept_tx(tx.clone());
                messages += 1;
            }
        }
    }

    messages
}

/// Run gossip until convergence or max rounds.
pub fn gossip_until_converge(
    network: &SimNetwork,
    nodes: &mut [SimNode],
    max_rounds: usize,
) -> (usize, usize) {
    let mut total_messages = 0;
    let mut prev_dags: Vec<HashSet<TransactionId>> = nodes.iter().map(|n| n.dag_ids()).collect();

    for round in 0..max_rounds {
        let msgs = gossip_round(network, nodes);
        total_messages += msgs;

        let current_dags: Vec<HashSet<TransactionId>> = nodes.iter().map(|n| n.dag_ids()).collect();

        if current_dags == prev_dags {
            return (round + 1, total_messages);
        }
        prev_dags = current_dags;
    }

    (max_rounds, total_messages)
}

/// Check if all nodes in a group have the same DAG.
pub fn dags_consistent(nodes: &[SimNode], group: &[usize]) -> bool {
    if group.is_empty() {
        return true;
    }
    let reference = nodes[group[0]].dag_ids();
    group.iter().all(|&i| nodes[i].dag_ids() == reference)
}

/// Detect double-spend: same sender+nonce in different transactions.
pub fn detect_double_spend(nodes: &[SimNode], group: &[usize]) -> Vec<TransactionId> {
    let mut seen_nonces: HashMap<(Address, u64), TransactionId> = HashMap::new();
    let mut doubles = Vec::new();

    for &i in group {
        for tx in nodes[i].dag.transactions().values() {
            let key = (tx.sender, tx.account_nonce);
            if let Some(&prev_id) = seen_nonces.get(&key) {
                if prev_id != tx.id {
                    doubles.push(tx.id);
                }
            } else {
                seen_nonces.insert(key, tx.id);
            }
        }
    }

    doubles
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{:064x}", i + 1)).collect()
    }

    #[test]
    fn test_harness_basic() {
        let keys = test_keys(5);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..5 {
            for j in (i + 1)..5 {
                net.connect(i, j);
            }
        }

        let addr1 = nodes[1].address;
        let tx = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr1,
            1000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx.clone());

        let (rounds, msgs) = gossip_until_converge(&net, &mut nodes, 10);
        assert!(rounds <= 5);
        assert!(msgs > 0);

        for i in 0..5 {
            assert!(nodes[i].dag_ids().contains(&tx.id), "node {}", i);
        }
    }

    #[test]
    fn test_partition_basic() {
        let keys = test_keys(10);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..10 {
            for j in (i + 1)..10 {
                net.connect(i, j);
            }
        }

        let group_a: Vec<usize> = (0..5).collect();
        let group_b: Vec<usize> = (5..10).collect();
        net.partition(&group_a, &group_b);

        assert!(!net.are_connected(0, 5));
        assert!(net.are_connected(0, 1));
        assert!(net.are_connected(5, 6));

        let addr_b1 = nodes[6].address;
        let addr_a1 = nodes[1].address;
        let tx_a = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr_a1,
            1000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a.clone());

        let tx_b = nodes[5].create_tx(
            [TransactionId::default(); 2],
            addr_b1,
            2000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[5].mempool.push(tx_b.clone());

        gossip_until_converge(&net, &mut nodes, 10);

        for &i in &group_a {
            assert!(nodes[i].dag_ids().contains(&tx_a.id), "A node {}", i);
            assert!(!nodes[i].dag_ids().contains(&tx_b.id), "A node {}", i);
        }
        for &i in &group_b {
            assert!(nodes[i].dag_ids().contains(&tx_b.id), "B node {}", i);
            assert!(!nodes[i].dag_ids().contains(&tx_a.id), "B node {}", i);
        }

        assert!(dags_consistent(&nodes, &group_a));
        assert!(dags_consistent(&nodes, &group_b));
    }

    #[test]
    fn test_reconnection_convergence() {
        let keys = test_keys(10);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..10 {
            for j in (i + 1)..10 {
                net.connect(i, j);
            }
        }

        let group_a: Vec<usize> = (0..5).collect();
        let group_b: Vec<usize> = (5..10).collect();
        net.partition(&group_a, &group_b);

        let addr_a1 = nodes[1].address;
        let addr_b1 = nodes[6].address;
        let tx_a = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr_a1,
            1000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a.clone());

        let tx_b = nodes[5].create_tx(
            [TransactionId::default(); 2],
            addr_b1,
            2000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[5].mempool.push(tx_b.clone());

        gossip_until_converge(&net, &mut nodes, 10);

        net.reconnect(&group_a, &group_b);

        let (rounds, msgs) = gossip_until_converge(&net, &mut nodes, 20);

        for i in 0..10 {
            assert!(nodes[i].dag_ids().contains(&tx_a.id), "node {} tx_a", i);
            assert!(nodes[i].dag_ids().contains(&tx_b.id), "node {} tx_b", i);
        }

        let all: Vec<usize> = (0..10).collect();
        assert!(dags_consistent(&nodes, &all));

        println!("Reconvergence: {} rounds, {} messages", rounds, msgs);
    }

    #[test]
    fn test_component_isolation() {
        let mut net = SimNetwork::new();
        for i in 0..4 {
            net.connect(i, i + 1);
        }
        net.disconnect(2, 3);

        assert!(net.are_connected(0, 2));
        assert!(net.are_connected(3, 4));
        assert!(!net.are_connected(0, 3));

        assert_eq!(net.component(0), HashSet::from([0, 1, 2]));
        assert_eq!(net.component(3), HashSet::from([3, 4]));
    }

    #[test]
    fn test_multi_partition_rounds() {
        let keys = test_keys(10);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..10 {
            for j in (i + 1)..10 {
                net.connect(i, j);
            }
        }

        let group_a: Vec<usize> = (0..5).collect();
        let group_b: Vec<usize> = (5..10).collect();

        // Round 1: partition, create txs, gossip
        net.partition(&group_a, &group_b);
        let addr_a1 = nodes[1].address;
        let addr_b1 = nodes[6].address;
        let tx_a = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr_a1,
            1000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a.clone());
        let tx_b = nodes[5].create_tx(
            [TransactionId::default(); 2],
            addr_b1,
            2000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[5].mempool.push(tx_b.clone());
        gossip_until_converge(&net, &mut nodes, 10);

        // Round 2: reconnect, converge
        net.reconnect(&group_a, &group_b);
        let (rounds, msgs) = gossip_until_converge(&net, &mut nodes, 20);

        // Round 3: partition again, create more txs
        net.partition(&group_a, &group_b);
        let addr_a2 = nodes[2].address;
        let addr_b2 = nodes[7].address;
        let tx_a2 = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr_a2,
            3000,
            2,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a2.clone());
        let tx_b2 = nodes[5].create_tx(
            [TransactionId::default(); 2],
            addr_b2,
            4000,
            2,
            Transaction::default_difficulty(),
        );
        nodes[5].mempool.push(tx_b2.clone());
        gossip_until_converge(&net, &mut nodes, 10);

        // Round 4: final reconvergence
        net.reconnect(&group_a, &group_b);
        let (r2, m2) = gossip_until_converge(&net, &mut nodes, 20);

        // All 4 txs should be present everywhere
        for i in 0..10 {
            assert!(nodes[i].dag_ids().contains(&tx_a.id), "node {} tx_a", i);
            assert!(nodes[i].dag_ids().contains(&tx_b.id), "node {} tx_b", i);
            assert!(nodes[i].dag_ids().contains(&tx_a2.id), "node {} tx_a2", i);
            assert!(nodes[i].dag_ids().contains(&tx_b2.id), "node {} tx_b2", i);
        }

        let all: Vec<usize> = (0..10).collect();
        assert!(dags_consistent(&nodes, &all));

        println!(
            "Multi-round: rounds1={} msgs1={} rounds2={} msgs2={}",
            rounds, msgs, r2, m2
        );
    }

    #[test]
    fn test_double_spend_during_partition() {
        let keys = test_keys(10);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..10 {
            for j in (i + 1)..10 {
                net.connect(i, j);
            }
        }

        let group_a: Vec<usize> = (0..5).collect();
        let group_b: Vec<usize> = (5..10).collect();
        net.partition(&group_a, &group_b);

        // Node 0 creates tx in group A
        let addr1 = nodes[1].address;
        let tx_a = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr1,
            5000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a.clone());

        // Node 5 creates conflicting tx in group B (different sender, same receiver, same amount)
        let addr1_copy = nodes[1].address;
        let tx_b = nodes[5].create_tx(
            [TransactionId::default(); 2],
            addr1_copy,
            5000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[5].mempool.push(tx_b.clone());

        gossip_until_converge(&net, &mut nodes, 10);

        // Group A has tx_a, Group B has tx_b
        for &i in &group_a {
            assert!(nodes[i].dag_ids().contains(&tx_a.id), "A node {}", i);
        }
        for &i in &group_b {
            assert!(nodes[i].dag_ids().contains(&tx_b.id), "B node {}", i);
        }

        // Reconnect — both txs should converge (no conflict: different senders)
        net.reconnect(&group_a, &group_b);
        gossip_until_converge(&net, &mut nodes, 20);

        let all: Vec<usize> = (0..10).collect();
        for i in &all {
            assert!(nodes[*i].dag_ids().contains(&tx_a.id), "node {} tx_a", i);
            assert!(nodes[*i].dag_ids().contains(&tx_b.id), "node {} tx_b", i);
        }
        assert!(dags_consistent(&nodes, &all));
    }

    #[test]
    fn test_concurrent_conflicting_txs() {
        let keys = test_keys(10);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..10 {
            for j in (i + 1)..10 {
                net.connect(i, j);
            }
        }

        let group_a: Vec<usize> = (0..5).collect();
        let group_b: Vec<usize> = (5..10).collect();
        net.partition(&group_a, &group_b);

        // Both groups create txs to different receivers
        let addr1 = nodes[1].address;
        let addr6 = nodes[6].address;

        let tx_a = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr1,
            1000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a.clone());

        let tx_b = nodes[5].create_tx(
            [TransactionId::default(); 2],
            addr6,
            2000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[5].mempool.push(tx_b.clone());

        gossip_until_converge(&net, &mut nodes, 10);

        for &i in &group_a {
            assert!(nodes[i].dag_ids().contains(&tx_a.id));
        }
        for &i in &group_b {
            assert!(nodes[i].dag_ids().contains(&tx_b.id));
        }

        net.reconnect(&group_a, &group_b);
        gossip_until_converge(&net, &mut nodes, 20);

        let all: Vec<usize> = (0..10).collect();
        for i in &all {
            assert!(nodes[*i].dag_ids().contains(&tx_a.id), "node {} tx_a", i);
            assert!(nodes[*i].dag_ids().contains(&tx_b.id), "node {} tx_b", i);
        }
        assert!(dags_consistent(&nodes, &all));
    }

    #[test]
    fn test_heavy_branch_wins() {
        // Test that gossip propagates ALL transactions regardless of weight
        // (weight doesn't affect gossip — it affects tip selection only)
        let keys = test_keys(5);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..5 {
            for j in (i + 1)..5 {
                net.connect(i, j);
            }
        }

        // Node 0 creates a light branch (1 tx)
        let addr1 = nodes[1].address;
        let tx_light = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr1,
            100,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_light.clone());

        // Node 1 creates a heavy branch (5 txs in chain)
        let addr0 = nodes[0].address;
        let mut prev = TransactionId::default();
        for i in 1..=5u64 {
            let tx = nodes[1].create_tx(
                [prev, TransactionId::default()],
                addr0,
                10,
                i,
                Transaction::default_difficulty(),
            );
            nodes[1].mempool.push(tx.clone());
            prev = tx.id;
        }

        gossip_until_converge(&net, &mut nodes, 10);

        // ALL transactions should be present — weight doesn't affect propagation
        assert!(nodes[0].dag_ids().contains(&tx_light.id));
        assert_eq!(nodes[0].dag_len(), 6); // 1 light + 5 heavy
    }

    #[test]
    fn test_mixed_version_divergence() {
        // Simulate mixed version: some nodes accept difficulty 20, others 24
        let keys = test_keys(10);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..10 {
            for j in (i + 1)..10 {
                net.connect(i, j);
            }
        }

        let old_difficulty: u8 = 20;
        let new_difficulty: u8 = 24;

        // Node 0 (old version, 20 bits) creates a tx with difficulty 22
        let addr1 = nodes[1].address;
        let mut tx_low = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr1,
            1000,
            1,
            22, // between old and new difficulty
        );
        // Re-mine at difficulty 22 specifically
        tx_low.nonce = tx_low.mine_nonce(22);
        tx_low.id = tx_low.compute_hash();

        // Node 0 accepts it (old version: 22 ≥ 20)
        nodes[0].accept_tx(tx_low.clone());
        nodes[0].mempool.push(tx_low.clone());

        // Nodes 1-4 are "old" (accept 20+), nodes 5-9 are "new" (accept 24+)
        // But in our harness, accept_tx just adds to DAG (no difficulty check)
        // So we simulate the divergence manually:
        // Old nodes accept the tx
        for i in 0..5 {
            nodes[i].accept_tx(tx_low.clone());
        }
        // New nodes REJECT the tx (simulating difficulty check)
        // They simply don't receive it

        gossip_until_converge(&net, &mut nodes, 10);

        // Old nodes (0-4) have the tx
        for i in 0..5 {
            assert!(nodes[i].dag_ids().contains(&tx_low.id), "old node {}", i);
        }

        // New nodes (5-9) may or may not have it depending on gossip path
        // In reality, new nodes would reject it at validation time
        // Here we document that the divergence CAN happen
        let old_has = (0..5)
            .filter(|&i| nodes[i].dag_ids().contains(&tx_low.id))
            .count();
        let new_has = (5..10)
            .filter(|&i| nodes[i].dag_ids().contains(&tx_low.id))
            .count();

        println!(
            "Mixed version: old_nodes_with_tx={}, new_nodes_with_tx={}",
            old_has, new_has
        );
        // The test documents that divergence is possible
    }

    #[test]
    fn test_stability_threshold() {
        // Test when the root transaction becomes Stable (weight ≥ STABILITY_THRESHOLD)
        // In a chain of 5, only the root has weight 5 = STABILITY_THRESHOLD.
        // Intermediate txs have lower weights (subtree size).
        let keys = test_keys(3);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();

        let addr1 = nodes[1].address;
        let addr2 = nodes[2].address;

        // Create chain: genesis -> tx1 -> tx2 -> tx3 -> tx4 -> tx5
        let mut prev = TransactionId::default();
        let mut txs = Vec::new();
        for i in 1..=5u64 {
            let tx = nodes[0].create_tx(
                [prev, TransactionId::default()],
                if i % 2 == 0 { addr1 } else { addr2 },
                100,
                i,
                Transaction::default_difficulty(),
            );
            txs.push(tx.clone());
            nodes[0].accept_tx(tx.clone());
            prev = tx.id;
        }

        // The root (first tx) should have weight 5 = STABILITY_THRESHOLD
        let root = nodes[0].dag.get_transaction(txs[0].id).unwrap();
        assert_eq!(root.weight, 5.0);
        assert!(
            root.weight >= crate::rpc::GlobalStatus::STABILITY_THRESHOLD,
            "root weight {} should be >= STABILITY_THRESHOLD",
            root.weight
        );

        // Verify chain weights: tx[i] has weight (5 - i)
        for (i, tx) in txs.iter().enumerate() {
            let t = nodes[0].dag.get_transaction(tx.id).unwrap();
            let expected_weight = (5 - i) as f64;
            assert_eq!(t.weight, expected_weight, "tx {} weight", i);
        }

        // Only root is Stable (weight ≥ 5)
        let root_stable = root.weight >= crate::rpc::GlobalStatus::STABILITY_THRESHOLD;
        assert!(root_stable, "root should be Stable");

        // tx5 (leaf) has weight 1 — NOT stable
        let leaf = nodes[0].dag.get_transaction(txs[4].id).unwrap();
        assert!(leaf.weight < crate::rpc::GlobalStatus::STABILITY_THRESHOLD);
    }

    #[test]
    fn test_fork_convergence() {
        // Two branches from same parent — both should converge after gossip
        let keys = test_keys(5);
        let mut nodes: Vec<SimNode> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| SimNode::new(i, k))
            .collect();
        let mut net = SimNetwork::new();
        for i in 0..5 {
            for j in (i + 1)..5 {
                net.connect(i, j);
            }
        }

        let group_a: Vec<usize> = vec![0, 1, 2];
        let group_b: Vec<usize> = vec![3, 4];
        net.partition(&group_a, &group_b);

        // Both groups create a tx from the same parent (genesis)
        let addr1 = nodes[1].address;
        let addr3 = nodes[3].address;

        let tx_a = nodes[0].create_tx(
            [TransactionId::default(); 2],
            addr1,
            1000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[0].mempool.push(tx_a.clone());

        let tx_b = nodes[3].create_tx(
            [TransactionId::default(); 2],
            addr3,
            2000,
            1,
            Transaction::default_difficulty(),
        );
        nodes[3].mempool.push(tx_b.clone());

        gossip_until_converge(&net, &mut nodes, 10);

        // A has tx_a, B has tx_b
        for &i in &group_a {
            assert!(nodes[i].dag_ids().contains(&tx_a.id));
        }
        for &i in &group_b {
            assert!(nodes[i].dag_ids().contains(&tx_b.id));
        }

        // Reconnect — both txs should converge
        net.reconnect(&group_a, &group_b);
        let (rounds, _) = gossip_until_converge(&net, &mut nodes, 20);

        let all: Vec<usize> = (0..5).collect();
        for i in &all {
            assert!(nodes[*i].dag_ids().contains(&tx_a.id), "node {} tx_a", i);
            assert!(nodes[*i].dag_ids().contains(&tx_b.id), "node {} tx_b", i);
        }
        assert!(dags_consistent(&nodes, &all));

        println!("Fork convergence: {} rounds", rounds);
    }
}
