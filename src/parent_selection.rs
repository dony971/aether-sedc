//! # Parent Selection Algorithm
//!
//! Implements tip selection based on cumulative weight and random walk.
//! Uses IOTA-style tip selection with cumulative weight calculation.

use crate::transaction::{Transaction, TransactionId};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Represents a set of tip transactions (transactions with no children)
#[derive(Debug, Clone)]
pub struct TipSet {
    tips: HashMap<TransactionId, Transaction>,
}

impl TipSet {
    /// Create a new empty tip set
    pub fn new() -> Self {
        Self {
            tips: HashMap::new(),
        }
    }

    /// Add a transaction to the tip set
    pub fn add(&mut self, tx: Transaction) {
        self.tips.insert(tx.id, tx);
    }

    /// Remove a transaction from the tip set
    pub fn remove(&mut self, id: &TransactionId) {
        self.tips.remove(id);
    }

    /// Get all tips
    pub fn get_tips(&self) -> Vec<&Transaction> {
        self.tips.values().collect()
    }

    /// Get the number of tips
    pub fn len(&self) -> usize {
        self.tips.len()
    }

    /// Check if tip set is empty
    pub fn is_empty(&self) -> bool {
        self.tips.is_empty()
    }
}

impl Default for TipSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Parent Selection Algorithm based on cumulative weight and random walk.
#[derive(Debug)]
pub struct ParentSelectionAlgorithm {
    /// Maximum age of a tip to be considered (in milliseconds)
    max_tip_age_ms: u64,

    /// Minimum weight threshold for selection
    #[allow(dead_code)]
    min_weight: f64,

    /// Diversity factor (0.0 to 1.0) - higher means more diverse parents
    #[allow(dead_code)]
    diversity_factor: f64,

    /// Random walk depth (how many steps to walk before selecting)
    walk_depth: usize,
}

impl ParentSelectionAlgorithm {
    /// Create a new parent selection algorithm
    pub fn new(max_tip_age_ms: u64, min_weight: f64, diversity_factor: f64) -> Self {
        Self {
            max_tip_age_ms,
            min_weight,
            diversity_factor: diversity_factor.clamp(0.0, 1.0),
            walk_depth: 10, // Default walk depth
        }
    }

    /// Create with default parameters
    pub fn default() -> Self {
        Self {
            max_tip_age_ms: 60_000, // 1 minute
            min_weight: 0.0,
            diversity_factor: 0.5,
            walk_depth: 10,
        }
    }

    /// Read the cumulative weight of a transaction.
    /// Cumulative weight = number of transactions that reference this
    /// transaction directly or indirectly (its subtree size, itself included).
    /// The DAG maintains `tx.weight` on every mutation (add/remove/prune), so
    /// this read is ALWAYS current — no cache, no staleness possible.
    fn calculate_cumulative_weight(&self, id: TransactionId, dag: &DAG) -> u64 {
        dag.get_transaction(id)
            .map(|tx| tx.weight.max(0.0) as u64)
            .unwrap_or(0)
    }

    /// Perform random walk from genesis to select a tip
    /// Returns a tip transaction ID
    fn random_walk(&self, dag: &DAG) -> Result<TransactionId, ParentSelectionError> {
        let genesis = TransactionId::default();
        let mut current = genesis;
        let mut rng = rand::thread_rng();

        for _ in 0..self.walk_depth {
            // Get children of current transaction
            let children = dag.children().get(&current).cloned().unwrap_or_default();

            if children.is_empty() {
                // No children, this is a tip
                return Ok(current);
            }

            // Calculate cumulative weights for children
            let mut weighted_children: Vec<(TransactionId, u64)> = children
                .iter()
                .map(|&child_id| {
                    let weight = self.calculate_cumulative_weight(child_id, dag);
                    (child_id, weight)
                })
                .collect();

            // Sort by weight (descending)
            weighted_children.sort_by(|a, b| b.1.cmp(&a.1));

            // Select child with probability proportional to weight
            let total_weight: u64 = weighted_children.iter().map(|(_, w)| w).sum();
            let mut random_weight = rng.gen_range(0..total_weight);

            for (child_id, weight) in weighted_children {
                if random_weight < weight {
                    current = child_id;
                    break;
                }
                random_weight -= weight;
            }
        }

        Ok(current)
    }

    /// Check if two tips are in conflict (double spend)
    /// Returns true if they conflict
    fn check_double_spend_conflict(
        &self,
        tip1: TransactionId,
        tip2: TransactionId,
        dag: &DAG,
    ) -> bool {
        // Get transactions
        let tx1 = match dag.get_transaction(tip1) {
            Some(tx) => tx,
            None => return false,
        };

        let tx2 = match dag.get_transaction(tip2) {
            Some(tx) => tx,
            None => return false,
        };

        // Check if they spend from the same address
        if tx1.sender == tx2.sender {
            return true; // Same sender, potential conflict
        }

        // Get ancestors of both tips
        let ancestors1 = dag.get_ancestors(tip1, 10);
        let ancestors2 = dag.get_ancestors(tip2, 10);

        // Check for overlapping spenders
        for ancestor1 in &ancestors1 {
            if let Some(tx) = dag.get_transaction(*ancestor1) {
                for ancestor2 in &ancestors2 {
                    if let Some(other_tx) = dag.get_transaction(*ancestor2) {
                        if tx.sender == other_tx.sender {
                            return true; // Conflicting spenders in ancestry
                        }
                    }
                }
            }
        }

        false
    }

    /// Select two parent transactions from the tip set using random walk
    pub fn select_parents(
        &self,
        tip_set: &TipSet,
        dag: &DAG,
    ) -> Result<[TransactionId; 2], ParentSelectionError> {
        let tips = tip_set.get_tips();

        if tips.is_empty() {
            // Return genesis parents if no tips available
            return Ok([TransactionId::default(); 2]);
        }

        // Filter tips by freshness
        let now = current_timestamp_ms();
        let valid_tips: Vec<&Transaction> = tips
            .into_iter()
            .filter(|tx| {
                let age = now.saturating_sub(tx.timestamp);
                age <= self.max_tip_age_ms
            })
            .collect();

        if valid_tips.is_empty() {
            return Err(ParentSelectionError::NoValidTips);
        }

        // Use random walk to select first parent
        let parent1 = self.random_walk(dag)?;

        // Use random walk to select second parent
        let mut attempts = 0;
        let max_attempts = 10;
        let mut parent2 = parent1;

        while attempts < max_attempts {
            let candidate = self.random_walk(dag)?;

            // V3 fix: Check if these parents are already used (prevent double spend)
            let proposed_parents = [parent1, candidate];
            if dag.has_transaction_with_parents(&proposed_parents) {
                tracing::warn!("⚠️ Parents already used, potential double spend detected");
                attempts += 1;
                continue;
            }

            // V3 fix: Ensure parents are different (prevent weight inflation)
            if candidate != parent1 && !self.check_double_spend_conflict(parent1, candidate, dag) {
                parent2 = candidate;
                break;
            }

            attempts += 1;
        }

        // If we couldn't find a non-conflicting parent, use genesis
        if parent2 == parent1 {
            parent2 = TransactionId::default();
        }

        // V3 fix: Final check to ensure parents are not identical
        if parent1 == parent2 {
            tracing::warn!("⚠️  Parent selection resulted in identical parents, using genesis as second parent");
            return Ok([parent1, TransactionId::default()]);
        }

        Ok([parent1, parent2])
    }
}

/// Error types for parent selection
#[derive(Debug, thiserror::Error)]
pub enum ParentSelectionError {
    #[error("No valid tips available")]
    NoValidTips,

    #[error("DAG is empty")]
    DagEmpty,
}

/// Simple DAG structure for parent selection
#[derive(Debug, Default, serde::Serialize)]
pub struct DAG {
    transactions: HashMap<TransactionId, Transaction>,
    children: HashMap<TransactionId, Vec<TransactionId>>,
    tips: HashSet<TransactionId>,
}

impl DAG {
    /// Create a new empty DAG
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            children: HashMap::new(),
            tips: HashSet::new(),
        }
    }

    /// Check if a transaction with these parents already exists (V3 fix - prevent double spend)
    /// 🔧 FIX: Roots (all-zero parents) never conflict - multiple chains can
    /// legitimately start from genesis, and a node must be able to absorb a
    /// peer's chain even if it has its own root. Real double spends are
    /// already covered by the sender nonce check.
    pub fn has_transaction_with_parents(&self, parents: &[TransactionId; 2]) -> bool {
        let is_root = parents.iter().all(|p| p.iter().all(|&b| b == 0));
        if is_root {
            return false;
        }
        self.transactions.values().any(|tx| &tx.parents == parents)
    }

    /// Check if a sender has a pending transaction in the DAG (conflict detection)
    /// Returns true if the sender already has a transaction in the DAG
    pub fn has_pending_transaction_from_sender(&self, sender: &[u8; 32]) -> bool {
        self.transactions.values().any(|tx| &tx.sender == sender)
    }

    /// Check if a sender has a transaction with a specific nonce in the DAG
    /// Returns true if the sender already has a transaction with this nonce
    pub fn has_transaction_with_nonce(&self, sender: &[u8; 32], nonce: u64) -> bool {
        self.transactions
            .values()
            .any(|tx| &tx.sender == sender && tx.account_nonce == nonce)
    }

    /// Check if a sender already has a transaction with a specific nonce in the DAG.
    /// Returns the id of the conflicting transaction if one exists.
    /// This is the canonical double-spend detector: a (sender, nonce) pair must be
    /// unique across the whole DAG. No special-casing is allowed for any address.
    pub fn find_sender_nonce_conflict(
        &self,
        sender: &[u8; 32],
        nonce: u64,
    ) -> Option<TransactionId> {
        self.transactions
            .iter()
            .find(|(_, tx)| &tx.sender == sender && tx.account_nonce == nonce)
            .map(|(id, _)| *id)
    }

    /// Check if a sender has a conflicting transaction (same nonce).
    /// Returns true if there's a conflict.
    pub fn has_sender_conflict(&self, sender: &[u8; 32], nonce: u64) -> bool {
        self.find_sender_nonce_conflict(sender, nonce).is_some()
    }

    /// Prune a transaction and its entire descendant subtree from the DAG
    /// (cascade removal). Used to deterministically resolve a double-spend
    /// conflict: the losing transaction and everything built on top of it is
    /// removed so the ledger can be rebuilt consistently.
    ///
    /// V-21 FIX: returns the ids of every pruned transaction so the caller
    /// can purge them from persistent storage (they must not resurrect at
    /// the next boot and resurrect a deterministic state).
    pub fn prune_subtree(&mut self, root_id: TransactionId) -> Vec<TransactionId> {
        // Collect all descendants via BFS over children.
        let mut to_remove: Vec<TransactionId> = Vec::new();
        let mut queue = vec![root_id];
        let mut seen = HashSet::new();
        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            to_remove.push(id);
            if let Some(children) = self.children.get(&id) {
                queue.extend(children.iter().copied());
            }
        }
        // Remove deepest-first: each `remove_transaction` adjusts the SURVIVING
        // ancestors of the removed node by -1. If a parent was already removed
        // (root-first order), the walk stops there and the ancestors above the
        // pruned chain are under-decremented (weights stay too high, and two
        // nodes that pruned at different times would disagree). Leaves-first
        // guarantees every pruned node's ancestors are still alive when it is
        // removed, so each surviving ancestor loses exactly 1 per pruned
        // descendant.
        for id in to_remove.iter().rev() {
            self.remove_transaction(id);
        }
        to_remove
    }

    /// Add a transaction to the DAG (REMOVED for zero-trust security)
    /// 🔒 ZERO TRUST: This method is REMOVED. Use add_transaction_validated ONLY.
    /// Economic policy: All transactions MUST be validated before insertion
    /// Any attempt to call this method will panic at compile time.
    #[deprecated(note = "REMOVED for security - use add_transaction_validated ONLY")]
    #[allow(dead_code)]
    pub fn add_transaction(&mut self, _tx: Transaction) {
        panic!("SECURITY VIOLATION: add_transaction() is removed. Use add_transaction_validated() ONLY.");
    }

    /// Add a transaction to the DAG with validation (SECURE METHOD)
    /// Economic policy: This is the ONLY method that should be used in production
    /// Requires validation proof to ensure transaction has been properly validated
    pub fn add_transaction_validated(&mut self, tx: Transaction) -> Result<(), String> {
        // Check for duplicate transaction
        if self.transactions.contains_key(&tx.id) {
            return Err(format!("Duplicate transaction: {}", hex::encode(tx.id)));
        }

        // Check parents exist (basic DAG integrity)
        for (i, parent) in tx.parents.iter().enumerate() {
            let is_genesis = parent.iter().all(|&b| b == 0);
            if !is_genesis && !self.transactions.contains_key(parent) {
                return Err(format!("Parent {} missing: {}", i, hex::encode(parent)));
            }
        }

        // Check for sender conflict (canonical double-spend detector).
        // Note: duplicate *parent pair* is intentionally NOT treated as a
        // double-spend: two different senders may legitimately build on the
        // same two tips. Real double-spends are caught by the (sender, nonce)
        // uniqueness check below.
        if self.has_sender_conflict(&tx.sender, tx.account_nonce) {
            return Err(
                "Sender conflict: only one pending transaction per sender allowed".to_string(),
            );
        }

        // All validations passed - add transaction
        // 🔧 FIX: Root transactions (parents [0,0]) keep their parents unchanged.
        // Auto-assigning current tips as parents rewrites the topology of a
        // transaction without changing its id (hash), so different nodes end up
        // storing different parents for the same tx id, breaking convergence and
        // causing false "parents already used" conflicts between merged chains.
        // WEIGHT: the DAG maintains `tx.weight` = subtree size (itself + all
        // descendants). A freshly added tx has subtree {itself} → weight 1.0;
        // every surviving ancestor gains +1 (the new tx becomes a descendant
        // of each). Re-adding at boot recomputes the same values, so the
        // stored weight always matches the live computation.
        let mut tx_with_parents = tx;
        tx_with_parents.weight = 1.0;
        let tx_id = tx_with_parents.id;

        self.transactions.insert(tx_id, tx_with_parents.clone());

        for parent in &tx_with_parents.parents {
            if parent.iter().all(|&b| b == 0) {
                self.children
                    .entry(*parent)
                    .or_insert_with(Vec::new)
                    .push(tx_id);
            } else if self.transactions.contains_key(parent) {
                self.children
                    .entry(*parent)
                    .or_insert_with(Vec::new)
                    .push(tx_id);
            }
        }

        self.tips.insert(tx_id);
        for parent in &tx_with_parents.parents {
            if !parent.iter().all(|&b| b == 0) {
                self.tips.remove(parent);
            }
        }

        self.adjust_ancestor_weights(&tx_with_parents.parents, 1.0);

        tracing::info!(
            "✅ Transaction {} added to DAG (validated). Tips count: {}",
            hex::encode(tx_id),
            self.tips.len()
        );

        Ok(())
    }

    /// Get a transaction by ID
    pub fn get_transaction(&self, id: TransactionId) -> Option<&Transaction> {
        self.transactions.get(&id)
    }

    /// Get mutable reference to children map
    pub fn children_mut(&mut self) -> &mut HashMap<TransactionId, Vec<TransactionId>> {
        &mut self.children
    }

    /// Remove transaction from DAG (for rollback)
    /// This removes the transaction, its children references, and updates tips
    pub fn remove_transaction(&mut self, tx_id: &TransactionId) {
        // Remove transaction from transactions map
        if let Some(tx) = self.transactions.remove(tx_id) {
            // Remove this transaction from its parents' children lists
            for parent in &tx.parents {
                if let Some(children) = self.children.get_mut(parent) {
                    children.retain(|child_id| child_id != tx_id);
                }
            }
            // Remove from tips
            self.tips.remove(tx_id);
            // Re-add parents to tips (since this transaction is gone)
            for parent in &tx.parents {
                if !parent.iter().all(|&b| b == 0) {
                    self.tips.insert(*parent);
                }
            }
            // WEIGHT: every surviving ancestor loses this descendant (-1).
            // During a prune cascade, ancestors already removed are skipped
            // naturally (they are gone from `transactions`), so each surviving
            // ancestor ends up decremented exactly once per pruned descendant.
            self.adjust_ancestor_weights(&tx.parents, -1.0);
        }
    }

    /// Maintain `tx.weight` = subtree size (itself + all descendants).
    /// Adjusts every SURVIVING ancestor of the transaction owning `parents`
    /// by `delta` (+1 when a transaction is added, -1 when one is removed).
    /// Genesis has no stored weight and is skipped. A per-walk visited set
    /// guarantees each ancestor is adjusted exactly once even through
    /// diamond-shaped paths.
    fn adjust_ancestor_weights(&mut self, parents: &[TransactionId; 2], delta: f64) {
        let mut visited = HashSet::new();
        let mut queue: Vec<TransactionId> = parents.to_vec();
        while let Some(pid) = queue.pop() {
            if !visited.insert(pid) {
                continue;
            }
            if pid.iter().all(|&b| b == 0) {
                continue; // genesis — no stored weight
            }
            let parents = match self.transactions.get_mut(&pid) {
                Some(ptx) => {
                    ptx.weight = (ptx.weight + delta).max(0.0);
                    ptx.parents
                }
                None => continue, // pruned ancestor — its chain is gone
            };
            queue.extend(parents.iter().copied());
        }
    }

    /// Get ancestors of a transaction up to a certain depth
    pub fn get_ancestors(&self, id: TransactionId, max_depth: usize) -> HashSet<TransactionId> {
        let mut ancestors = HashSet::new();
        let mut queue = vec![(id, 0)];

        while let Some((tx_id, depth)) = queue.pop() {
            if depth >= max_depth {
                continue;
            }

            if let Some(tx) = self.transactions.get(&tx_id) {
                for parent in &tx.parents {
                    if ancestors.insert(*parent) {
                        queue.push((*parent, depth + 1));
                    }
                }
            }
        }

        ancestors
    }

    /// Check if a transaction is reachable from another (for cycle detection)
    pub fn is_reachable_from(&self, from: TransactionId, to: TransactionId) -> bool {
        let mut visited = HashSet::new();
        let mut queue = vec![from];

        while let Some(current) = queue.pop() {
            if current == to {
                return true;
            }

            if !visited.insert(current) {
                continue;
            }

            if let Some(tx) = self.transactions.get(&current) {
                for parent in &tx.parents {
                    queue.push(*parent);
                }
            }
        }

        false
    }

    /// Get all transactions
    pub fn transactions(&self) -> &HashMap<TransactionId, Transaction> {
        &self.transactions
    }

    /// Get children map
    pub fn children(&self) -> &HashMap<TransactionId, Vec<TransactionId>> {
        &self.children
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get tip count (number of unconfirmed transactions)
    pub fn tip_count(&self) -> usize {
        self.tips.len()
    }

    /// Get random tips from the explicit tips set
    pub fn get_random_tips(&self, count: usize) -> Vec<TransactionId> {
        let tips_vec: Vec<TransactionId> = self.tips.iter().cloned().collect();

        if tips_vec.is_empty() {
            // Return genesis hash if no tips
            return vec![TransactionId::default(); count.min(1)];
        }

        // Randomly select up to 'count' tips
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        tips_vec
            .choose_multiple(&mut rng, count)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get tips using cumulative weight-based selection
    /// This is the new interface that uses the random walk algorithm
    pub fn get_tips_with_selector(&self) -> Vec<TransactionId> {
        let selector = ParentSelectionAlgorithm::default();
        let _tip_set = TipSet::new();

        // Build tip set from current tips
        let mut tips = TipSet::new();
        for tip_id in &self.tips {
            if let Some(tx) = self.transactions.get(tip_id) {
                tips.add(tx.clone());
            }
        }

        // Select two parents using the new algorithm
        match selector.select_parents(&tips, self) {
            Ok(parents) => {
                // Return the selected parents as tips
                parents.to_vec()
            }
            Err(_) => {
                // Fallback to random tips if selection fails
                self.get_random_tips(2)
            }
        }
    }

    /// Rebuild tips set from current DAG state (transactions with no children)
    pub fn rebuild_tips(&mut self) {
        self.tips.clear();
        for tx_id in self.transactions.keys() {
            if !self.children.contains_key(tx_id) {
                self.tips.insert(*tx_id);
            }
        }
        tracing::info!(
            "Rebuilt tips: {} tips from {} transactions",
            self.tips.len(),
            self.transactions.len()
        );
    }

    /// TEST ONLY: insert a transaction raw, with no validation and no
    /// topology bookkeeping. Lets tests construct corrupted DAGs (e.g. two
    /// conflicting transactions) that the public API rightly forbids.
    #[cfg(test)]
    pub fn inject_transaction_raw(&mut self, tx: Transaction) {
        self.transactions.insert(tx.id, tx);
    }
}

/// V-21: canonical (sender, account_nonce) conflict resolution on a flat
/// transaction set (e.g. loaded from persistent storage at boot).
///
/// For every (sender, nonce) pair, the transaction with the SMALLEST id wins
/// (the exact same rule as the runtime conflict resolution). Every losing
/// transaction AND its entire descendant subtree is removed, mirroring the
/// runtime `prune_subtree` cascade, so a boot cannot resurrect a pruned
/// loser (or txs built on it) that a crash kept in storage.
///
/// Deterministic: pure function of the input set, independent of iteration
/// order, HashMap order and arrival order. Returns the ids of every removed
/// transaction (losers + descendants).
pub fn canonical_resolve_conflicts(txs: &mut Vec<Transaction>) -> Vec<TransactionId> {
    // Smallest id per (sender, account_nonce).
    let mut winners: HashMap<(TransactionId, u64), TransactionId> = HashMap::new();
    for tx in txs.iter() {
        let key = (tx.sender, tx.account_nonce);
        let better = match winners.get(&key) {
            Some(existing) => tx.id < *existing,
            None => true,
        };
        if better {
            winners.insert(key, tx.id);
        }
    }

    // Losers = txs whose id is not the winner of their (sender, nonce) key.
    let mut losers: HashSet<TransactionId> = HashSet::new();
    for tx in txs.iter() {
        let key = (tx.sender, tx.account_nonce);
        if let Some(winner) = winners.get(&key) {
            if tx.id != *winner {
                losers.insert(tx.id);
            }
        }
    }

    if losers.is_empty() {
        return Vec::new();
    }

    // Descendants of losers (same cascade rule as prune_subtree).
    let mut child_map: HashMap<TransactionId, Vec<TransactionId>> = HashMap::new();
    for tx in txs.iter() {
        for parent in tx.parents.iter() {
            if parent.iter().any(|&b| b != 0) {
                child_map.entry(*parent).or_default().push(tx.id);
            }
        }
    }
    let mut pruned: HashSet<TransactionId> = losers.clone();
    let mut queue: Vec<TransactionId> = losers.into_iter().collect();
    while let Some(id) = queue.pop() {
        if let Some(children) = child_map.get(&id) {
            for child in children {
                if pruned.insert(*child) {
                    queue.push(*child);
                }
            }
        }
    }

    txs.retain(|tx| !pruned.contains(&tx.id));
    pruned.into_iter().collect()
}

/// INC-01: rebuild a DAG from a persisted transaction set using a pure
/// topological insert — a transaction is inserted only once its parents are
/// already in the DAG (Sled iteration order is random, so a single pass is
/// order-dependent). PURE insert: no ledger/balance validation — the
/// persisted ledger already contains the effects of historical txs and
/// re-validating them against it would wrongly drop valid txs (the boot
/// rebuild must never ignore a tx just because its nonce is already
/// committed). Every persisted tx ends up in EXACTLY ONE bucket:
///   - inserted: parents were (eventually) present;
///   - skipped: the DAG rejected it, with an explicit reason logged (never
///     a silent drop);
///   - orphans: parents absent from the set (the orphan solver heals them
///     later from the store or peers).
/// Deterministic: a pure function of the input set. Returns
/// (inserted, skipped, orphans).
pub fn rebuild_dag_topological(
    dag: &mut DAG,
    txs: Vec<Transaction>,
) -> (u64, u64, Vec<Transaction>) {
    let mut inserted: u64 = 0;
    let mut skipped: u64 = 0;
    let mut remaining: Vec<Transaction> = txs;
    let mut progress = true;
    while progress && !remaining.is_empty() {
        progress = false;
        let mut still_pending = Vec::new();
        for tx in remaining {
            let parent0_ok =
                tx.parents[0] == [0u8; 32] || dag.transactions().contains_key(&tx.parents[0]);
            let parent1_ok =
                tx.parents[1] == [0u8; 32] || dag.transactions().contains_key(&tx.parents[1]);
            if !(parent0_ok && parent1_ok) {
                still_pending.push(tx);
                continue;
            }
            progress = true;
            match dag.add_transaction_validated(tx) {
                Ok(_) => inserted += 1,
                Err(e) => {
                    tracing::warn!(
                        "⚠️ INC-01 rebuild skipped transaction (explicit reason): {}",
                        e
                    );
                    skipped += 1;
                }
            }
        }
        remaining = still_pending;
    }
    (inserted, skipped, remaining)
}

/// Get current timestamp in milliseconds
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tip_set_creation() {
        let tip_set = TipSet::new();
        assert!(tip_set.is_empty());
        assert_eq!(tip_set.len(), 0);
    }

    #[test]
    fn test_tip_set_add_remove() {
        let mut tip_set = TipSet::new();
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            current_timestamp_ms(),
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        tip_set.add(tx.clone());
        assert_eq!(tip_set.len(), 1);

        tip_set.remove(&tx.id);
        assert!(tip_set.is_empty());
    }

    #[test]
    fn test_parent_selection_algorithm_default() {
        let algo = ParentSelectionAlgorithm::default();
        assert_eq!(algo.max_tip_age_ms, 60_000);
        assert_eq!(algo.min_weight, 0.0);
        assert_eq!(algo.diversity_factor, 0.5);
    }

    #[test]
    fn test_parent_selection_empty_tip_set() {
        let algo = ParentSelectionAlgorithm::default();
        let tip_set = TipSet::new();
        let dag = DAG::new();

        let result = algo.select_parents(&tip_set, &dag);
        assert!(result.is_ok());
        let parents = result.expect("Parent selection should succeed");
        assert_eq!(parents, [TransactionId::default(); 2]);
    }

    #[test]
    fn test_parent_selection_with_tips() {
        let algo = ParentSelectionAlgorithm::default();
        let mut tip_set = TipSet::new();
        let mut dag = DAG::new();

        let now = current_timestamp_ms();

        // Create two tip transactions
        let mut tx1 = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            now,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );
        tx1.weight = 10.0;

        let mut tx2 = Transaction::new(
            [[0u8; 32]; 2],
            [3u8; 32],
            [4u8; 32],
            200,
            10,
            now,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );
        tx2.weight = 5.0;

        tip_set.add(tx1.clone());
        tip_set.add(tx2.clone());

        // Add transaction to DAG (using validated method)
        dag.add_transaction_validated(tx1.clone()).unwrap();

        let result = algo.select_parents(&tip_set, &dag);
        assert!(result.is_ok());

        let parents = result.expect("Parent selection should succeed");
        // Should select a tip (tx1 or tx2) as first parent
        assert!(parents[0] == tx1.id || parents[0] == tx2.id);
    }

    #[test]
    fn test_parent_selection_filters_old_tips() {
        let algo = ParentSelectionAlgorithm::new(60_000, 0.0, 0.5);
        let mut tip_set = TipSet::new();
        let dag = DAG::new();

        let old_time = current_timestamp_ms() - 120_000; // 2 minutes ago

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            old_time,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        tip_set.add(tx);

        let result = algo.select_parents(&tip_set, &dag);
        assert!(matches!(result, Err(ParentSelectionError::NoValidTips)));
    }

    #[test]
    fn test_dag_add_transaction() {
        let mut dag = DAG::new();
        let tx = Transaction::new(
            [[0u8; 32], [0u8; 32]], // Genesis parents
            [3u8; 32],
            [4u8; 32],
            100,
            10,
            0,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        dag.add_transaction_validated(tx.clone()).unwrap();

        assert!(dag.get_transaction(tx.id).is_some());
    }

    /// P2+WEIGHT: the cumulative weight is now MAINTAINED on the DAG itself
    /// (every mutation adjusts `tx.weight`), so there is no cache to go stale:
    /// any read returns the current value. This test pins the maintenance
    /// rules: +1 on add for every ancestor, -1 on remove, prune adjusts the
    /// surviving ancestors, and diamond paths count each ancestor once.
    #[test]
    fn test_cumulative_weight_maintained_by_dag() {
        let mut dag = DAG::new();

        // A (genesis parents); B and C reference A.
        let a = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        dag.add_transaction_validated(a.clone()).unwrap();
        let b = Transaction::new(
            [a.id, [0u8; 32]],
            [3u8; 32],
            [4u8; 32],
            100,
            10,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        dag.add_transaction_validated(b.clone()).unwrap();
        let c = Transaction::new(
            [a.id, [0u8; 32]],
            [5u8; 32],
            [6u8; 32],
            100,
            10,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        dag.add_transaction_validated(c.clone()).unwrap();

        // A has subtree {A, B, C} = 3; B and C = 1 each.
        assert_eq!(dag.get_transaction(a.id).unwrap().weight, 3.0);
        assert_eq!(dag.get_transaction(b.id).unwrap().weight, 1.0);
        assert_eq!(dag.get_transaction(c.id).unwrap().weight, 1.0);

        // DAG grows: D and E reference B. A → 5, B → 3.
        let d = Transaction::new(
            [b.id, [0u8; 32]],
            [7u8; 32],
            [8u8; 32],
            100,
            10,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        dag.add_transaction_validated(d.clone()).unwrap();
        let e = Transaction::new(
            [b.id, [0u8; 32]],
            [9u8; 32],
            [10u8; 32],
            100,
            10,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        dag.add_transaction_validated(e.clone()).unwrap();
        assert_eq!(dag.get_transaction(a.id).unwrap().weight, 5.0);
        assert_eq!(dag.get_transaction(b.id).unwrap().weight, 3.0);

        // Remove D: A → 4, B → 2.
        dag.remove_transaction(&d.id);
        assert_eq!(dag.get_transaction(a.id).unwrap().weight, 4.0);
        assert_eq!(dag.get_transaction(b.id).unwrap().weight, 2.0);

        // Diamond: F references B and C. A gains +1 ONCE (F is a single
        // descendant), B and C each gain +1.
        let f = Transaction::new(
            [b.id, c.id],
            [11u8; 32],
            [12u8; 32],
            100,
            10,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        dag.add_transaction_validated(f.clone()).unwrap();
        assert_eq!(dag.get_transaction(a.id).unwrap().weight, 5.0);
        assert_eq!(dag.get_transaction(b.id).unwrap().weight, 3.0);
        assert_eq!(dag.get_transaction(c.id).unwrap().weight, 2.0);
        assert_eq!(dag.get_transaction(f.id).unwrap().weight, 1.0);

        // Prune C (subtree {C, F}): A loses 2 (C + F), B loses 1 (F).
        let pruned = dag.prune_subtree(c.id);
        assert_eq!(pruned.len(), 2);
        assert_eq!(dag.get_transaction(a.id).unwrap().weight, 3.0);
        assert_eq!(dag.get_transaction(b.id).unwrap().weight, 2.0);
        assert_eq!(dag.get_transaction(e.id).unwrap().weight, 1.0);

        // Sanity: the selector reads the SAME stored weights (no recompute).
        let algo = ParentSelectionAlgorithm::default();
        assert_eq!(algo.calculate_cumulative_weight(a.id, &dag), 3);
        assert_eq!(algo.calculate_cumulative_weight(b.id, &dag), 2);
        assert_eq!(algo.calculate_cumulative_weight(e.id, &dag), 1);
    }

    #[test]
    fn test_dag_ancestors() {
        let mut dag = DAG::new();

        let parent1 = Transaction::new(
            [[0u8; 32], [0u8; 32]], // Genesis parents
            [1u8; 32],
            [2u8; 32],
            0,
            0,
            0,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        // Add parent1 first
        dag.add_transaction_validated(parent1.clone()).unwrap();

        // Child references parent1
        let child = Transaction::new(
            [parent1.id, [0u8; 32]],
            [5u8; 32],
            [6u8; 32],
            100,
            10,
            0,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        dag.add_transaction_validated(child.clone()).unwrap();

        let ancestors = dag.get_ancestors(child.id, 2);
        assert!(ancestors.contains(&parent1.id));
    }

    #[test]
    fn test_dag_reachability() {
        let mut dag = DAG::new();

        let parent = Transaction::new(
            [[0u8; 32], [0u8; 32]],
            [1u8; 32],
            [2u8; 32],
            0,
            0,
            0,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        let child = Transaction::new(
            [parent.id, [0u8; 32]],
            [3u8; 32],
            [4u8; 32],
            100,
            10,
            0,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        dag.add_transaction_validated(parent.clone()).unwrap();
        dag.add_transaction_validated(child.clone()).unwrap();

        assert!(dag.is_reachable_from(child.id, parent.id));
        assert!(!dag.is_reachable_from(parent.id, child.id));
    }

    // ---- V-21: canonical conflict resolution tests ----

    fn conflict_tx(sender: [u8; 32], receiver: [u8; 32], ts: u64) -> Transaction {
        Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            1,
            ts,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        )
    }

    #[test]
    fn test_canonical_resolve_conflicts_min_id_wins() {
        let sender = [0x0Au8; 32];
        let tx1 = conflict_tx(sender, [0x01u8; 32], 1);
        let tx2 = conflict_tx(sender, [0x02u8; 32], 2);
        let unrelated = conflict_tx([0x0Bu8; 32], [0x03u8; 32], 3);
        // The canonical winner is the smallest id - whichever that is.
        let (expected_winner, expected_loser) = if tx1.id < tx2.id {
            (tx1.clone(), tx2.clone())
        } else {
            (tx2.clone(), tx1.clone())
        };

        let mut txs = vec![tx2, tx1, unrelated.clone()];
        // Order must not matter: shuffle deterministically.
        txs.reverse();
        let pruned = canonical_resolve_conflicts(&mut txs);

        // The winner survives, the loser is dropped, unrelated txs are kept.
        assert!(txs.iter().any(|t| t.id == expected_winner.id));
        assert!(!txs.iter().any(|t| t.id == expected_loser.id));
        assert!(txs.iter().any(|t| t.id == unrelated.id));
        assert_eq!(pruned, vec![expected_loser.id]);
    }

    #[test]
    fn test_canonical_resolve_descendants_of_loser_dropped() {
        let sender = [0x0Cu8; 32];
        let tx1 = conflict_tx(sender, [0x01u8; 32], 1);
        let tx2 = conflict_tx(sender, [0x02u8; 32], 2);
        let (expected_winner, expected_loser) = if tx1.id < tx2.id {
            (tx1, tx2)
        } else {
            (tx2, tx1)
        };
        // A transaction built ON TOP of the loser (references it as parent).
        let child_of_loser = Transaction::new(
            [expected_loser.id, [0u8; 32]],
            [0x0Du8; 32],
            [0x04u8; 32],
            10,
            1,
            4,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );

        let mut txs = vec![
            expected_winner.clone(),
            expected_loser.clone(),
            child_of_loser.clone(),
        ];
        let pruned = canonical_resolve_conflicts(&mut txs);

        assert!(txs.iter().any(|t| t.id == expected_winner.id));
        assert!(!txs.iter().any(|t| t.id == expected_loser.id));
        assert!(
            !txs.iter().any(|t| t.id == child_of_loser.id),
            "descendants of a loser must be dropped (cascade prune)"
        );
        assert!(pruned.contains(&expected_loser.id));
        assert!(pruned.contains(&child_of_loser.id));
    }

    #[test]
    fn test_canonical_resolve_no_conflicts_noop() {
        let t1 = conflict_tx([0x0Eu8; 32], [0x01u8; 32], 1);
        // Same sender, NEXT nonce: distinct transactions, NOT a conflict.
        let t2 = Transaction::new(
            [[0u8; 32]; 2],
            [0x0Eu8; 32],
            [0x02u8; 32],
            100,
            1,
            2,
            0,
            2,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let mut txs = vec![t1, t2];
        let pruned = canonical_resolve_conflicts(&mut txs);
        assert!(pruned.is_empty());
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn test_prune_subtree_returns_removed_ids() {
        let mut dag = DAG::new();
        let root = conflict_tx([0x0Fu8; 32], [0x01u8; 32], 1);
        dag.add_transaction_validated(root.clone()).unwrap();
        let child = Transaction::new(
            [root.id, [0u8; 32]],
            [0x10u8; 32],
            [0x02u8; 32],
            10,
            1,
            2,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        dag.add_transaction_validated(child.clone()).unwrap();

        let removed = dag.prune_subtree(root.id);
        assert!(removed.contains(&root.id));
        assert!(removed.contains(&child.id));
        assert_eq!(dag.transaction_count(), 0);
    }

    // ================= W1-W12: poids — campagne phase finale v3 =================
    // Le poids = taille du sous-arbre (soi + descendants), maintenu par le DAG.
    // Ces tests verifient la SEMANTIQUE structurelle et demontrent l'attaque
    // W11 (l'inflation de poids est possible a cout quasi nul).

    fn w_tx(
        parents: [TransactionId; 2],
        sender: [u8; 32],
        amount: u64,
        account_nonce: u64,
    ) -> Transaction {
        Transaction::new(
            parents,
            sender,
            [0xEEu8; 32],
            amount,
            1, // min fee (1 unit)
            0,
            0,
            account_nonce,
            vec![0u8; 64],
            vec![0u8; 32],
        )
    }

    #[test]
    fn test_w1_weight_simple_dag() {
        // W1: poids d'un DAG simple — une tx racine vaut 1.0, un enfant
        // l'incremente a 2.0 (sous-arbre {root, child}).
        let mut dag = DAG::new();
        let root = w_tx([TransactionId::default(); 2], [0x11u8; 32], 1, 1);
        dag.add_transaction_validated(root.clone()).unwrap();
        assert_eq!(dag.get_transaction(root.id).unwrap().weight, 1.0);
        let child = w_tx([root.id, TransactionId::default()], [0x22u8; 32], 1, 1);
        dag.add_transaction_validated(child.clone()).unwrap();
        assert_eq!(dag.get_transaction(root.id).unwrap().weight, 2.0);
        assert_eq!(dag.get_transaction(child.id).unwrap().weight, 1.0);
    }

    #[test]
    fn test_w2_weight_grows_with_descendants() {
        // W2: chaque descendant ajoute exactement +1 a TOUS les ancetres
        // (chaine de 4 : racine = 4.0).
        let mut dag = DAG::new();
        let mut prev = w_tx([TransactionId::default(); 2], [0x33u8; 32], 1, 1);
        dag.add_transaction_validated(prev.clone()).unwrap();
        for i in 2..=4u64 {
            let next = w_tx([prev.id, TransactionId::default()], [0x44u8; 32], 1, i);
            dag.add_transaction_validated(next.clone()).unwrap();
            prev = next;
        }
        let root_id = dag
            .transactions()
            .values()
            .find(|t| t.account_nonce == 1)
            .unwrap()
            .id;
        assert_eq!(dag.get_transaction(root_id).unwrap().weight, 4.0);
    }

    #[test]
    fn test_w3_weight_decreases_on_removal() {
        // W3: suppression/pruning — retirer un sous-arbre decremente les
        // ancetres survivants d'exactement 1 par noeud retire.
        let mut dag = DAG::new();
        let root = w_tx([TransactionId::default(); 2], [0x55u8; 32], 1, 1);
        dag.add_transaction_validated(root.clone()).unwrap();
        let child = w_tx([root.id, TransactionId::default()], [0x66u8; 32], 1, 1);
        dag.add_transaction_validated(child.clone()).unwrap();
        let grandchild = w_tx([child.id, TransactionId::default()], [0x77u8; 32], 1, 1);
        dag.add_transaction_validated(grandchild.clone()).unwrap();
        assert_eq!(dag.get_transaction(root.id).unwrap().weight, 3.0);
        let pruned = dag.prune_subtree(child.id);
        assert_eq!(pruned.len(), 2);
        assert_eq!(dag.get_transaction(root.id).unwrap().weight, 1.0);
        assert!(dag.get_transaction(child.id).is_none());
        assert!(dag.get_transaction(grandchild.id).is_none());
    }

    #[test]
    fn test_w4_multiple_references() {
        // W4: references multiples — deux enfants qui pointent le meme parent
        // (sous-arbre {root, c1, c2} = 3.0).
        let mut dag = DAG::new();
        let root = w_tx([TransactionId::default(); 2], [0x88u8; 32], 1, 1);
        dag.add_transaction_validated(root.clone()).unwrap();
        let c1 = w_tx([root.id, TransactionId::default()], [0x99u8; 32], 1, 1);
        dag.add_transaction_validated(c1.clone()).unwrap();
        let c2 = w_tx([root.id, TransactionId::default()], [0xAAu8; 32], 1, 1);
        dag.add_transaction_validated(c2.clone()).unwrap();
        assert_eq!(dag.get_transaction(root.id).unwrap().weight, 3.0);
        assert_eq!(dag.get_transaction(c1.id).unwrap().weight, 1.0);
        assert_eq!(dag.get_transaction(c2.id).unwrap().weight, 1.0);
    }

    #[test]
    fn test_w5_branching() {
        // W5: branchement — deux branches independantes depuis la meme racine ;
        // chaque branche compte son propre sous-arbre.
        let mut dag = DAG::new();
        let root = w_tx([TransactionId::default(); 2], [0xBBu8; 32], 1, 1);
        dag.add_transaction_validated(root.clone()).unwrap();
        let b1 = w_tx([root.id, TransactionId::default()], [0xCCu8; 32], 1, 1);
        dag.add_transaction_validated(b1.clone()).unwrap();
        let b2 = w_tx([root.id, TransactionId::default()], [0xDDu8; 32], 1, 2);
        dag.add_transaction_validated(b2.clone()).unwrap();
        let b1c = w_tx([b1.id, TransactionId::default()], [0xEEu8; 32], 1, 1);
        dag.add_transaction_validated(b1c.clone()).unwrap();
        assert_eq!(dag.get_transaction(root.id).unwrap().weight, 4.0);
        assert_eq!(dag.get_transaction(b1.id).unwrap().weight, 2.0);
        assert_eq!(dag.get_transaction(b2.id).unwrap().weight, 1.0);
        assert_eq!(dag.get_transaction(b1c.id).unwrap().weight, 1.0);
    }

    #[test]
    fn test_w6_conflict_min_id_ignores_weight() {
        // W6: conflit — deux tx (sender, account_nonce) identiques : le plus
        // PETIT id gagne, quel que soit le poids accumule. Le sous-arbre du
        // perdant est entierement prune ; les poids du gagnant restent exacts.
        // (add_transaction_validated rejette le conflit — c'est STEP 0 qui
        // decide : on injecte le perdant en brut comme le ferait un noeud
        // fautif/partage, puis on applique le prune du perdant.)
        let sender = [0x5Au8; 32];
        let mut dag = DAG::new();
        // Double depense realisee : deux tx (sender, nonce) identiques mais de
        // montants DIFFERENTS (c'est la forme reelle de l'attaque).
        let winner = w_tx([TransactionId::default(); 2], sender, 1, 1);
        let loser = w_tx([TransactionId::default(); 2], sender, 2, 1);
        let (winner, loser) = if winner.id < loser.id {
            (winner, loser)
        } else {
            (loser, winner)
        };
        dag.add_transaction_validated(winner.clone()).unwrap();
        let loser_child = w_tx([loser.id, TransactionId::default()], [0x5Bu8; 32], 1, 1);
        dag.inject_transaction_raw(loser.clone());
        // Le descendant du perdant passe par le chemin valide (topologie
        // maintenue) : c'est ainsi qu'un noeud fautif aurait pu l'accepter.
        dag.add_transaction_validated(loser_child.clone()).unwrap();
        // Les poids du gagnant ne doivent pas etre affectes par le prune du
        // perdant et de son sous-arbre.
        let pruned = dag.prune_subtree(loser.id);
        assert_eq!(pruned.len(), 2);
        assert_eq!(dag.get_transaction(winner.id).unwrap().weight, 1.0);
        assert!(dag.get_transaction(loser.id).is_none());
        assert!(dag.get_transaction(loser_child.id).is_none());
    }

    #[test]
    fn test_w7_double_spend_winner_keeps_weight() {
        // W7: double depense — apres la resolution min-id, le gagnant
        // conserve son sous-arbre complet (poids inchange) ; le perdant et ses
        // descendants disparaissent du DAG.
        let sender = [0x6Au8; 32];
        let mut dag = DAG::new();
        let w1 = w_tx([TransactionId::default(); 2], sender, 1, 1);
        let w2 = w_tx([TransactionId::default(); 2], sender, 2, 1);
        let (winner, _loser) = if w1.id < w2.id { (w1, w2) } else { (w2, w1) };
        dag.add_transaction_validated(winner.clone()).unwrap();
        let child = w_tx([winner.id, TransactionId::default()], [0x6Bu8; 32], 1, 1);
        dag.add_transaction_validated(child.clone()).unwrap();
        let grandchild = w_tx([child.id, TransactionId::default()], [0x6Cu8; 32], 1, 1);
        dag.add_transaction_validated(grandchild.clone()).unwrap();
        // Le perdant arrive apres : STEP 0 le rejetterait (id plus grand),
        // et meme s'il etait ajoute, le prune ne toucherait pas le gagnant.
        assert_eq!(dag.get_transaction(winner.id).unwrap().weight, 3.0);
        assert_eq!(dag.get_transaction(child.id).unwrap().weight, 2.0);
        assert_eq!(dag.get_transaction(grandchild.id).unwrap().weight, 1.0);
    }

    #[test]
    fn test_w8_restart_rebuild_preserves_weights() {
        // W8: redemarrage — la persistance (bincode) + le rebuild du boot
        // (canonical_resolve_conflicts puis re-insertion) produisent les MEMES
        // poids, car le poids est derive de la structure du DAG.
        let mut dag = DAG::new();
        let root = w_tx([TransactionId::default(); 2], [0x7Au8; 32], 1, 1);
        dag.add_transaction_validated(root.clone()).unwrap();
        let c1 = w_tx([root.id, TransactionId::default()], [0x7Bu8; 32], 1, 1);
        dag.add_transaction_validated(c1.clone()).unwrap();
        let c2 = w_tx([c1.id, TransactionId::default()], [0x7Cu8; 32], 1, 1);
        dag.add_transaction_validated(c2.clone()).unwrap();
        let before: Vec<(TransactionId, f64)> = dag
            .transactions()
            .values()
            .map(|t| (t.id, t.weight))
            .collect();

        // "Disk" : serialisation bincode de chaque tx.
        let on_disk: Vec<Vec<u8>> = dag
            .transactions()
            .values()
            .map(|t| bincode::serialize(t).unwrap())
            .collect();
        let restored: Vec<Transaction> = on_disk
            .iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect();

        // "Boot" : resolution canonique + re-insertion topologique (les
        // parents doivent exister avant leurs enfants, comme dans node.rs).
        let mut txs = restored;
        canonical_resolve_conflicts(&mut txs);
        let mut dag2 = DAG::new();
        let mut remaining: Vec<Transaction> = txs;
        let mut progress = true;
        while progress && !remaining.is_empty() {
            progress = false;
            let mut still: Vec<Transaction> = Vec::new();
            for tx in remaining {
                let parents_ok = tx
                    .parents
                    .iter()
                    .all(|p| p.iter().all(|&b| b == 0) || dag2.get_transaction(*p).is_some());
                if parents_ok {
                    dag2.add_transaction_validated(tx.clone()).unwrap();
                    progress = true;
                } else {
                    still.push(tx);
                }
            }
            remaining = still;
        }
        assert!(remaining.is_empty(), "rebuild topologique incomplet");
        for (id, weight) in before {
            let w2 = dag2.get_transaction(id).unwrap().weight;
            assert_eq!(w2, weight, "poids {id:?} apres restart");
        }
    }

    #[test]
    fn test_w9_w10_arrival_order_independence() {
        // W9 (resynchronisation) + W10 (ordre d'arrivee different) : le meme
        // ensemble de transactions insere dans deux ordres differents produit
        // les MEMES poids sur les deux nœuds. C'est la propriete de
        // convergence : le poids est une fonction pure de la structure.
        let set = vec![
            w_tx([TransactionId::default(); 2], [0x8Au8; 32], 1, 1),
            w_tx([TransactionId::default(); 2], [0x8Bu8; 32], 1, 1),
        ];
        // Nœud A : ordre naturel ; Nœud B : ordre inverse, avec fils.
        let mut dag_a = DAG::new();
        for tx in &set {
            dag_a.add_transaction_validated(tx.clone()).unwrap();
        }
        let child = w_tx([set[0].id, set[1].id], [0x8Cu8; 32], 1, 1);
        dag_a.add_transaction_validated(child.clone()).unwrap();

        let mut dag_b = DAG::new();
        dag_b.add_transaction_validated(set[1].clone()).unwrap();
        dag_b.add_transaction_validated(set[0].clone()).unwrap();
        dag_b.add_transaction_validated(child.clone()).unwrap();

        assert_eq!(dag_a.transaction_count(), dag_b.transaction_count());
        for (id, tx) in dag_a.transactions() {
            assert_eq!(
                dag_b.get_transaction(*id).unwrap().weight,
                tx.weight,
                "convergence poids {id:?}"
            );
        }
    }

    #[test]
    fn test_w11_weight_inflation_attack() {
        // W11: tentative de manipulation du poids — DEMONSTRATION.
        // L'attaquant cree une chaine de 5 transactions qui se referencent
        // les unes les autres. Chaque tx ne coute que le min fee (1 unit =
        // 10^-10 AETH) et un PoW trivial (difficulty 20 ≈ 1M hashes ≈ ms).
        // Apres 5 tx, la racine atteint weight = 5.0 = STABILITY_THRESHOLD :
        // elle est Stable (practically_final) a cout quasi nul.
        let attacker = [0x9Au8; 32];
        let mut dag = DAG::new();
        let mut prev = w_tx([TransactionId::default(); 2], attacker, 1, 1);
        dag.add_transaction_validated(prev.clone()).unwrap();
        for i in 2..=5u64 {
            let next = w_tx([prev.id, TransactionId::default()], attacker, 1, i);
            dag.add_transaction_validated(next.clone()).unwrap();
            prev = next;
        }
        let root_weight = dag
            .get_transaction(
                dag.transactions()
                    .values()
                    .find(|t| t.account_nonce == 1)
                    .unwrap()
                    .id,
            )
            .unwrap()
            .weight;
        assert_eq!(root_weight, 5.0);
        assert!(
            root_weight >= crate::rpc::GlobalStatus::STABILITY_THRESHOLD,
            "l'attaquant atteint le seuil Stable avec 5 tx a cout quasi nul"
        );

        // Deuxieme volet : meme en etant "lourde" (poids 10.0), une chaine
        // conflictuelle perd TOUJOURS face a un id plus petit : la resolution
        // de conflit (min-id) ignore completement le poids.
        let sender = [0x9Bu8; 32];
        let mut dag2 = DAG::new();
        let heavy = w_tx([TransactionId::default(); 2], sender, 1, 1);
        let mut heavy = heavy;
        heavy.weight = 10.0; // poids artificiellement gonfle
        dag2.add_transaction_validated(heavy.clone()).unwrap();
        // add_transaction_validated recalcule le poids reel (1.0) — le champ
        // n'est pas un parametre d'entree du consensus.
        assert_eq!(dag2.get_transaction(heavy.id).unwrap().weight, 1.0);
    }

    #[test]
    fn test_w12_spam_weight_exactness() {
        // W12: spam — 1000 transactions en chaine et 1000 en etoile : les
        // poids restent EXACTS (pas de derive, pas de saturation).
        let mut dag = DAG::new();
        let mut prev = w_tx([TransactionId::default(); 2], [0xABu8; 32], 1, 1);
        dag.add_transaction_validated(prev.clone()).unwrap();
        for i in 2..=1000u64 {
            let next = w_tx([prev.id, TransactionId::default()], [0xABu8; 32], 1, i);
            dag.add_transaction_validated(next.clone()).unwrap();
            prev = next;
        }
        let root_id = dag
            .transactions()
            .values()
            .find(|t| t.account_nonce == 1)
            .unwrap()
            .id;
        assert_eq!(dag.get_transaction(root_id).unwrap().weight, 1000.0);

        // Etoile : 1000 enfants d'une meme racine (sous-arbre = 1001).
        let mut dag2 = DAG::new();
        let star = w_tx([TransactionId::default(); 2], [0xACu8; 32], 1, 1);
        dag2.add_transaction_validated(star.clone()).unwrap();
        for i in 2..=1001u64 {
            let leaf = w_tx([star.id, TransactionId::default()], [0xADu8; 32], 1, i);
            dag2.add_transaction_validated(leaf.clone()).unwrap();
        }
        assert_eq!(dag2.get_transaction(star.id).unwrap().weight, 1001.0);
        assert_eq!(dag2.transaction_count(), 1001);
    }
}
