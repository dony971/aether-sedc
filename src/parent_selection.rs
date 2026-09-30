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
///
/// PHASE 3E (M4) honesty note: parent choice shapes DAG TOPOLOGY only (which
/// tips get referenced sooner). It is NOT consensus: the ledger applies every
/// valid tx regardless of its parents, and conflict resolution ignores parent
/// choice entirely (min-id rule). Two parameters below are RESERVED (accepted,
/// never read); the freshness filter gates availability, not selection (see
/// select_parents).
#[derive(Debug)]
pub struct ParentSelectionAlgorithm {
    /// Maximum age of a tip to be considered (in milliseconds)
    max_tip_age_ms: u64,

    /// Minimum weight threshold for selection.
    /// PHASE 3E (M4): RESERVED — accepted by constructors, never read.
    /// Changing it has no effect (kept for a future weighted filter).
    #[allow(dead_code)]
    min_weight: f64,

    /// Diversity factor (0.0 to 1.0) - higher means more diverse parents.
    /// PHASE 3E (M4): RESERVED — accepted by constructors, never read.
    /// Changing it has no effect (kept for a future diversity heuristic).
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
            // PHASE 3E (M2): explicit zero-weight guard. Unreachable given
            // current weight invariants (children entries reference present
            // txs, each maintained at weight >= 1.0; the clamp forbids
            // negatives) — but a single invariant slip (future refactor,
            // corrupted state) must degrade to early termination, never to a
            // `gen_range(0..0)` panic (node crash = remote DoS primitive).
            // Returning `current` is always safe: it is genesis or a DAG tx,
            // both valid parent choices (roots are legal).
            if total_weight == 0 {
                return Ok(current);
            }
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
    /// Returns true if they conflict.
    ///
    /// PHASE 3E (M4): deliberately CONSERVATIVE parent-diversity heuristic —
    /// NOT the consensus double-spend rule. Flags same-sender (ANY nonce, so
    /// mostly non-conflicting) pairs and pairs sharing ANY sender within
    /// depth-10 ancestry. A `true` here only steers select_parents toward a
    /// genesis fallback parent; it never rejects, prunes, or reorders ledger
    /// state. The real double-spend rule is strictly (sender, account_nonce)
    /// uniqueness, enforced in validate_dag / add_transaction_validated /
    /// STEP 0. Do not cite this function as conflict evidence.
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

    /// Select two parent transactions from the tip set using random walk.
    ///
    /// PHASE 3E (M4): read this contract literally. The freshness filter
    /// below is a LIVENESS pre-check only: if NO tip is fresh, selection
    /// aborts with NoValidTips. When fresh tips exist, the actual parents
    /// come from weight-proportional random walks from genesis — the
    /// filtered list is NOT the selection pool (a misleading name otherwise).
    /// Fallbacks (genesis second parent) keep selection total: any returned
    /// pair is always DAG-valid, never consensus-relevant.
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
    /// PHASE 3C (H3): (sender, account_nonce) -> tx ids index. O(1) conflict
    /// lookup with identical answers to the former full scan.
    /// Skipped from serialization (rebuilt implicitly: every mutation below
    /// maintains it).
    /// PHASE 4B: multi-member — conflicting pairs COEXIST (loser retention),
    /// so one key maps to a LIST. Invariant: no duplicate ids in a list
    /// (duplicate tx ids are rejected before insert).
    #[serde(skip_serializing)]
    sender_nonce_index: HashMap<([u8; 32], u64), Vec<TransactionId>>,
}

impl DAG {
    /// Create a new empty DAG
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            children: HashMap::new(),
            tips: HashSet::new(),
            sender_nonce_index: HashMap::new(),
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

    /// Check if a sender already has transactions with a specific nonce.
    /// Returns ALL resident ids sharing the (sender, nonce) key (insertion
    /// order). Empty = no conflict. Length >= 2 = live conflict set.
    ///
    /// PHASE 4B: multi-member (loser retention) — replaces the unique-id
    /// lookup. Callers needing the conflict DECISION use
    /// resolve_conflict_key (CDW + tiebreak, grandfather-aware), never raw
    /// order or length alone.
    pub fn find_sender_nonce_conflicts(
        &self,
        sender: &[u8; 32],
        nonce: u64,
    ) -> Vec<TransactionId> {
        self.sender_nonce_index
            .get(&(*sender, nonce))
            .cloned()
            .unwrap_or_default()
    }

    /// PHASE 4B: resolve a conflict key to its winner id. Grandfathering: if
    /// ALL members predate CDW_ACTIVATION_TS, min-id wins (frozen legacy
    /// rule — pre-activation settled outcomes never change). Otherwise the
    /// max-subtree-work member wins, min-id tiebreak (deterministic total
    /// order). Returns None when fewer than 2 members (no conflict).
    /// Pure function of the DAG set (deterministic across nodes, orders,
    /// restarts, syncs). Missing members (index/store skew, should not
    /// happen) count as pre-activation (safe min-id fallback, never panic).
    pub fn resolve_conflict_key(
        &self,
        sender: &[u8; 32],
        nonce: u64,
    ) -> Option<TransactionId> {
        let members = self.find_sender_nonce_conflicts(sender, nonce);
        if members.len() < 2 {
            return None;
        }
        let pre_activation = members.iter().all(|id| {
            self.transactions
                .get(id)
                .map(|t| t.timestamp < Transaction::CDW_ACTIVATION_TS)
                .unwrap_or(true)
        });
        if pre_activation {
            return members.into_iter().min();
        }
        // CDW: highest subtree work wins; min-id breaks exact ties.
        // Sort is explicit (never rely on index/insertion/HashMap order).
        let mut scored: Vec<(u64, TransactionId)> = members
            .iter()
            .map(|id| (self.subtree_work(*id), *id))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        scored.into_iter().next().map(|(_, id)| id)
    }

    /// PHASE 4B: conflict keys (>= 2 members) in the ancestry of `parents`
    /// (genesis roots skipped). A new tx can only shift scores of conflicts
    /// it descends from (work flows upward), so re-resolution triggers walk
    /// ancestors, never the whole DAG. Sorted/deduped for determinism.
    /// Cost O(ancestors); single-member keys excluded (their winner is
    /// trivially themselves — nothing to flip).
    pub fn affected_conflict_keys(
        &self,
        parents: &[TransactionId; 2],
    ) -> Vec<([u8; 32], u64)> {
        let mut out = Vec::new();
        let mut seen_ids = HashSet::new();
        let mut seen_keys = HashSet::new();
        let mut queue: Vec<TransactionId> = parents.to_vec();
        while let Some(id) = queue.pop() {
            if !seen_ids.insert(id) {
                continue;
            }
            if id.iter().all(|&b| b == 0) {
                continue;
            }
            if let Some(tx) = self.transactions.get(&id) {
                let key = (tx.sender, tx.account_nonce);
                if seen_keys.insert(key)
                    && self
                        .sender_nonce_index
                        .get(&key)
                        .map(|v| v.len())
                        .unwrap_or(0)
                        >= 2
                {
                    out.push(key);
                }
                queue.extend(tx.parents.iter().copied());
            }
        }
        out.sort();
        out
    }

    /// PHASE 4B: subtree work = sum of work credits over the UNIQUE
    /// descendant closure (self included). Saturating u64 addition
    /// (u64::MAX cap, documented; unreachable magnitudes). Deterministic:
    /// addition commutes and the visited set makes traversal order
    /// irrelevant. Stale ids contribute 0 (absent tx) but traversal
    /// continues through live children entries.
    pub fn subtree_work(&self, root: TransactionId) -> u64 {
        let mut total = 0u64;
        let mut seen = HashSet::new();
        let mut queue = vec![root];
        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(tx) = self.transactions.get(&id) {
                total = total.saturating_add(tx.work_credit());
            }
            if let Some(children) = self.children.get(&id) {
                queue.extend(children.iter().copied());
            }
        }
        total
    }

    /// PHASE 4B: REMOVED `has_sender_conflict` (single-id unique-pair check).
    /// Conflicting pairs now COEXIST (loser retention); the conflict DECISION
    /// lives in resolve_conflict_key (CDW + tiebreak, grandfather-aware),
    /// enforced at ledger-application time (rebuild winners), not at DAG
    /// admission. Uniqueness callers migrated: STEP 0 (CDW resolve),
    /// validate_dag (check dropped), add_transaction_validated (check dropped).

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

        // PHASE 4B: NO sender-conflict rejection (loser retention). Same-key
        // pairs COEXIST in the DAG (both validated, both stored, both
        // gossiped); the conflict DECISION (CDW winner, min-id tiebreak,
        // grandfathered for all-pre-activation keys) is enforced at
        // ledger-application time by rebuild winners + STEP 0. Duplicate
        // *parent pair* remains allowed as before (independent rule).
        //
        // Convergence note: retention is symmetric (losing newcomers are
        // INSERTED, never dropped), so arrival order cannot split nodes —
        // sets converge via gossip and winners are pure functions of sets.

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
        // PHASE 3C (H3) index, PHASE 4B multi-member: append (duplicate tx
        // ids are rejected above, so no id appears twice in one list).
        self.sender_nonce_index
            .entry((tx_with_parents.sender, tx_with_parents.account_nonce))
            .or_default()
            .push(tx_id);

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
            // PHASE 4B multi-member: retain all OTHER ids for this key;
            // drop the key when its list empties.
            let key = (tx.sender, tx.account_nonce);
            if let Some(ids) = self.sender_nonce_index.get_mut(&key) {
                ids.retain(|id| id != tx_id);
                if ids.is_empty() {
                    self.sender_nonce_index.remove(&key);
                }
            }
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
    ///
    /// PHASE 3C (H3): also records the (sender, nonce) index.
    /// PHASE 4B: multi-member append (test harnesses inject conflicting
    /// pairs; order within a key list is insertion order and must never be
    /// read as a decision — resolve_conflict_key sorts explicitly).
    #[cfg(test)]
    pub fn inject_transaction_raw(&mut self, tx: Transaction) {
        self.sender_nonce_index
            .entry((tx.sender, tx.account_nonce))
            .or_default()
            .push(tx.id);
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

    #[test]
    fn test_w11_cost_measurement() {
        use std::time::Instant;
        let difficulty = Transaction::default_difficulty();
        let min_fee: u64 = 100;
        let chain_lengths = [5, 10, 50];
        println!("\n=== W11 COST MEASUREMENT (difficulty={}) ===", difficulty);
        println!(
            "{:<8} {:>10} {:>15} {:>15} {:>10} {:>10}",
            "LEN", "TIME_MS", "POW_TOTAL", "FEE_TOTAL", "WEIGHT", "STABLE?"
        );
        println!("{}", "-".repeat(75));
        for &len in &chain_lengths {
            let attacker = [0x9Au8; 32];
            let mut dag = DAG::new();
            let start = Instant::now();
            let mut prev = w_tx([TransactionId::default(); 2], attacker, 1, 1);
            dag.add_transaction_validated(prev.clone()).unwrap();
            for i in 2..=len {
                let mut tx = w_tx([prev.id, TransactionId::default()], attacker, 1, i);
                tx.nonce = tx.mine_nonce(difficulty);
                dag.add_transaction_validated(tx.clone()).unwrap();
                prev = tx;
            }
            let elapsed = start.elapsed().as_millis();
            let root = dag
                .transactions()
                .values()
                .find(|t| t.account_nonce == 1)
                .unwrap();
            let stable = root.weight >= crate::rpc::GlobalStatus::STABILITY_THRESHOLD;
            let pow_total: u64 = dag.transactions().values().map(|t| t.nonce).sum();
            let fee_total: u64 = len as u64 * min_fee;
            println!(
                "{:<8} {:>10} {:>15} {:>15} {:>10.1} {:>10}",
                len,
                elapsed,
                pow_total,
                fee_total,
                root.weight,
                if stable { "YES" } else { "NO" }
            );
        }
        println!("=== END W11 COST ===\n");
    }

    // ===== PHASE 3C (H2): min-id grinding model =====
    //
    // These tests measure the ORDER mechanism only (compute_hash over shaped
    // fixtures — no PoW, no signatures). Cost per grinding attempt in
    // production = one full PoW (difficulty from timestamp: 24-bit
    // post-activation, 20-bit pre-activation) + one Ed25519 sign. Ed25519
    // (ed25519-dalek) signs DETERMINISTICALLY, so re-signing identical
    // content yields the identical id: every attempt needs fresh content and
    // therefore a fresh PoW. No invented numbers: attempts are measured,
    // expectation follows from the uniformity premise proven below.

    /// Shape a tx with fully controlled fields (no mining, no signing —
    /// id is what matters here, not validity).
    fn shaped_tx(
        sender: [u8; 32],
        receiver: [u8; 32],
        amount: u64,
        fee: u64,
        timestamp: u64,
        pow_nonce: u64,
        account_nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            amount,
            fee,
            timestamp,
            pow_nonce,
            account_nonce,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        tx.id = tx.compute_hash();
        tx
    }

    /// H2 premise: min-id inputs are uniform over the id space. 1024 txs with
    /// systematically varied ATTACKER-CONTROLLED fields (receiver, amount,
    /// fee, timestamp, pow_nonce) and a FIXED conflict key (sender, nonce):
    /// all ids distinct; first-nibble buckets within ±6σ of uniform
    /// ([16,112] for E=64 — P(false alarm) ≈ 0); minimum below 2^250
    /// (P(fail) = (255/256)^1024 ≈ 0).
    #[test]
    fn test_min_id_distribution() {
        use std::collections::HashSet;
        let sender = [0x11u8; 32];
        let mut ids = Vec::with_capacity(1024);
        for i in 0..1024u64 {
            let mut receiver = [0u8; 32];
            receiver[..8].copy_from_slice(&i.to_le_bytes());
            let tx = shaped_tx(
                sender,
                receiver,
                100 + i,
                (i % 100) + 1,
                1_700_000_000_000 + i,
                i,
                7,
            );
            ids.push(tx.id);
        }
        let distinct: HashSet<_> = ids.iter().collect();
        assert_eq!(distinct.len(), 1024, "ids must all be distinct");
        let mut buckets = [0u32; 16];
        for id in &ids {
            buckets[(id[0] >> 4) as usize] += 1;
        }
        for (b, c) in buckets.iter().enumerate() {
            assert!(
                (16..=112).contains(c),
                "nibble bucket {} = {} (E=64, ±6σ)",
                b,
                c
            );
        }
        let min = ids.iter().min().unwrap();
        assert!(min[0] < 64, "minimum id unexpectedly large");
        println!(
            "H2 distribution: 1024 ids distinct, buckets {:?}, min {:02x}..",
            buckets, min[0]
        );
    }

    /// H2 bound: attempts to grind below a FIXED rival id. Attacker varies
    /// timestamp (+1 ms) and receiver bytes; each variant is a fresh uniform
    /// id (premise above), so attempts-to-win is geometric with
    /// p = R/2^256 for rival id R.
    ///
    /// AUTHORING NOTE (kept deliberately): the first version drew 5
    /// UNCONDITIONED rivals and observed mean 14.2 — one rival drew a small
    /// id, dominating the mean. That is not a product defect; it IS the
    /// scaling law (expected attempts = 2^256/R). The test therefore
    /// conditions rivals to the TYPICAL band (first byte in [64,192]) and
    /// asserts the typical case, with a second probe documenting the scaling
    /// against a small rival explicitly. Bounds are a priori from the model
    /// (per-trial cap 128; mean ≤ 8 = 2× the worst in-band expectation),
    /// never fitted to observations.
    #[test]
    fn test_min_id_grinding_bound() {
        let sender = [0x11u8; 32];
        // Typical-band rivals: first qualifying seeds (deterministic).
        let mut rivals = Vec::new();
        for r in 0..1024u64 {
            if rivals.len() >= 5 {
                break;
            }
            let mut r_receiver = [0u8; 32];
            r_receiver[..8].copy_from_slice(&(0xBEEF_0000 + r).to_le_bytes());
            let rival =
                shaped_tx(sender, r_receiver, 5000, 10, 1_700_000_000_000, 0, 1);
            if (64..=192).contains(&rival.id[0]) {
                rivals.push(rival);
            }
        }
        assert_eq!(rivals.len(), 5, "band must yield 5 rivals");
        let mut counts = Vec::new();
        for (k, rival) in rivals.iter().enumerate() {
            let mut attempts = 0u32;
            loop {
                attempts += 1;
                let mut receiver = [0u8; 32];
                receiver[..8]
                    .copy_from_slice(&(0xC123_0000u64.wrapping_add(attempts as u64)).to_le_bytes());
                let variant = shaped_tx(
                    sender,
                    receiver,
                    5000,
                    10,
                    1_700_000_000_000 + attempts as u64,
                    0,
                    1,
                );
                if variant.id < rival.id {
                    break;
                }
                assert!(
                    attempts <= 128,
                    "rival {} not beaten within 128 attempts",
                    k
                );
            }
            counts.push(attempts);
        }
        let mean = counts.iter().sum::<u32>() as f64 / counts.len() as f64;
        assert!(mean <= 8.0, "mean attempts {} (E≈2 typical)", mean);
        println!("H2 grinding: attempts per rival {:?}, mean {:.2}", counts, mean);

        // Scaling probe: grinding vs a SMALL rival id costs proportionally
        // more (expected attempts = 2^256/R). One rival with first byte < 16
        // (bounded seed scan, deterministic); must complete within 4096
        // attempts (E ≈ 16 for R ≈ 2^252). Reported: documents the
        // defender's luck factor, not a bound.
        let mut small = None;
        for r in 0..1024u64 {
            let mut r_receiver = [0u8; 32];
            r_receiver[..8].copy_from_slice(&(0xF00D_0000 + r).to_le_bytes());
            let cand =
                shaped_tx(sender, r_receiver, 5000, 10, 1_700_000_000_000, 0, 1);
            if cand.id[0] < 16 {
                small = Some(cand);
                break;
            }
        }
        let small_rival = small.expect("seed scan must find a small rival");
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let mut receiver = [0u8; 32];
            receiver[..8].copy_from_slice(
                &(0xD00D_0000u64.wrapping_add(attempts as u64)).to_le_bytes(),
            );
            let variant = shaped_tx(
                sender,
                receiver,
                5000,
                10,
                1_700_000_000_000 + attempts as u64,
                0,
                1,
            );
            if variant.id < small_rival.id {
                break;
            }
            assert!(attempts <= 4096, "small-rival grind runaway");
        }
        println!(
            "H2 scaling probe: small rival (leading {:02x}) beaten in {} attempts",
            small_rival.id[0], attempts
        );
    }

    /// H2 influence: grinding DECIDES the consensus outcome. txA fixed; grind
    /// txB variants (timestamp steps, no PoW — order mechanism only) until
    /// txB.id < txA.id (bounded 64); canonical_resolve_conflicts on {A, B}
    /// must then drop A and keep B. Control: an unground B' (id > A) loses.
    /// Same (sender, nonce) throughout (else no conflict exists to decide).
    #[test]
    fn test_min_id_selection_influence() {
        let sender = [0x11u8; 32];
        let tx_a = shaped_tx(sender, [0xAAu8; 32], 5000, 10, 1_700_000_000_000, 0, 1);
        // Grind B below A.
        let mut tx_b = shaped_tx(sender, [0xBBu8; 32], 100, 10, 1_700_000_000_000, 0, 1);
        let mut attempts = 0u32;
        while tx_b.id >= tx_a.id {
            attempts += 1;
            assert!(attempts <= 64, "grind did not flip within 64 attempts");
            tx_b = shaped_tx(
                sender,
                [0xBBu8; 32],
                100,
                10,
                1_700_000_000_000 + attempts as u64,
                0,
                1,
            );
        }
        let mut set = vec![tx_a.clone(), tx_b.clone()];
        let pruned = canonical_resolve_conflicts(&mut set);
        assert_eq!(pruned.len(), 1, "exactly the loser drops");
        assert!(pruned.contains(&tx_a.id), "A must lose once B is smaller");
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].id, tx_b.id, "B must survive");
        // Control: ground-in-reverse (B' id > A id) → A wins.
        let mut tx_b2 = shaped_tx(sender, [0xCCu8; 32], 100, 10, 1_700_000_000_000, 0, 1);
        let mut attempts2 = 0u32;
        while tx_b2.id <= tx_a.id {
            attempts2 += 1;
            assert!(attempts2 <= 64);
            tx_b2 = shaped_tx(
                sender,
                [0xCCu8; 32],
                100,
                10,
                1_700_000_000_000 + 1_000_000 + attempts2 as u64,
                0,
                1,
            );
        }
        let mut set2 = vec![tx_a.clone(), tx_b2.clone()];
        let pruned2 = canonical_resolve_conflicts(&mut set2);
        assert_eq!(pruned2.len(), 1);
        assert!(pruned2.contains(&tx_b2.id), "larger id must lose");
        assert_eq!(set2[0].id, tx_a.id, "A must survive");
        println!(
            "H2 influence: flip took {} attempts; control took {}",
            attempts, attempts2
        );
    }

    // ===== PHASE 3C (H3): conflict CPU cost =====
    //
    // No PoW anywhere below (add_transaction_validated checks
    // duplicate/parents/sender-conflict only — validation is the processor's
    // job). This measures the ALGORITHMIC cost that STEP 0 pays per conflict
    // (lookup, prune traversal, full ledger rebuild), i.e. the amplification
    // core. Per-tx crypto (one hash + one signature per validate_pure) is O(1)
    // by code inspection and needs no timing.

    /// Build a DAG of N distinct-sender root txs (validated inserts, no
    /// mining). Sender bytes derive from the counter (unique by construction).
    fn distinct_root_dag(n: usize) -> DAG {
        let mut dag = DAG::new();
        for i in 0..n {
            let mut sender = [0u8; 32];
            sender[..8].copy_from_slice(&(i as u64).to_le_bytes());
            sender[8..16].copy_from_slice(&(i as u64).to_be_bytes());
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                [9u8; 32],
                1,
                1,
                1234567890,
                0,
                0,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            dag.add_transaction_validated(tx).expect("distinct insert");
        }
        dag
    }

    /// H3 lookup scaling: 1k/2k/4k/8k DAGs, 20000 mixed hit/miss lookups each.
    /// Absolute bound (< 1 s) pins O(1) indexed lookup (a full scan would take
    /// seconds); ratio bound (< 32 for 8× growth) pins the shape. Reported
    /// times are the É11 record.
    #[test]
    fn test_conflict_lookup_scales() {
        use std::time::Instant;
        let mut times = Vec::new();
        for &n in &[1000usize, 2000, 4000, 8000] {
            let dag = distinct_root_dag(n);
            let start = Instant::now();
            let mut hits = 0u32;
            for j in 0..20000u32 {
                // Even = hit (exact reconstruction of an inserted sender,
                // tail zeros included); odd = miss (byte 16 set — inserted
                // senders are zero there by construction).
                let mut sender = [0u8; 32];
                if j % 2 == 0 {
                    let i = (j as usize / 2) % n;
                    sender[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    sender[8..16].copy_from_slice(&(i as u64).to_be_bytes());
                } else {
                    sender[0] = 0xFF;
                    sender[16] = 1;
                    sender[17] = (j % 251) as u8;
                }
                if !dag.find_sender_nonce_conflicts(&sender, 0).is_empty() {
                    hits += 1;
                }
            }
            let elapsed = start.elapsed();
            println!(
                "H3 lookup: N={} 20000 lookups in {:?} (hits {})",
                n, elapsed, hits
            );
            assert_eq!(hits, 10000, "every even lookup must hit");
            assert!(
                elapsed.as_secs_f64() < 1.0,
                "20k lookups on {} txs took {:?} (index regression?)",
                n,
                elapsed
            );
            times.push(elapsed);
        }
        let ratio = times[3].as_secs_f64() / times[0].as_secs_f64().max(1e-9);
        println!("H3 lookup scaling T(8k)/T(1k) = {:.2}", ratio);
        assert!(ratio < 32.0, "lookup scaling ratio {}", ratio);
    }

    /// H3 index equivalence: brute-force scan agrees with the index after
    /// every mutation. Deterministic op sequence (LCG): validated adds
    /// (fresh keys), rejected conflicting adds, removes, subtree prunes.
    /// After each op, every tracked key (+ never-keys) must match the scan
    /// EXACTLY (Some(id) with the same id — production holds ≤1 tx per key).
    #[test]
    fn test_conflict_index_matches_scan() {
        let mut rng_state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (rng_state >> 33) as usize
        };
        let mut dag = DAG::new();
        let mut keys: Vec<([u8; 32], u64)> = Vec::new();
        let mut key_serial: u64 = 0;
        let mut fresh_key = || {
            key_serial += 1;
            let mut sender = [0u8; 32];
            sender[..8].copy_from_slice(&key_serial.to_le_bytes());
            sender[8] = 0xA5;
            (sender, key_serial % 5)
        };
        let brute = |dag: &DAG, key: ([u8; 32], u64)| {
            // PHASE 4B: plural comparison (sorted both sides: scan order is
            // HashMap-random, index order is insertion order — neither is
            // contractual; SET equality is).
            let mut found: Vec<TransactionId> = dag
                .transactions()
                .iter()
                .filter(|(_, tx)| (tx.sender, tx.account_nonce) == key)
                .map(|(id, _)| *id)
                .collect();
            found.sort();
            found
        };
        for step in 0..150 {
            match next() % 4 {
                0 => {
                    // Fresh validated add (must succeed).
                    let (sender, nonce) = fresh_key();
                    let mut tx = Transaction::new(
                        [[0u8; 32]; 2],
                        sender,
                        [9u8; 32],
                        1,
                        1,
                        1234567890,
                        0,
                        nonce,
                        vec![0u8; 64],
                        vec![0u8; 32],
                    );
                    tx.id = tx.compute_hash();
                    dag.add_transaction_validated(tx).expect("fresh key inserts");
                    keys.push((sender, nonce));
                }
                1 => {
                    // Conflicting add (PHASE 4B: RETAINED, not rejected —
                    // loser retention; the key simply gains a member).
                    if keys.is_empty() {
                        continue;
                    }
                    let (sender, nonce) = keys[next() % keys.len()];
                    let mut tx = Transaction::new(
                        [[0u8; 32]; 2],
                        sender,
                        [7u8; 32],
                        // Unique per step (else a repeat pick would be an
                        // exact-id duplicate, rejected for the wrong reason).
                        2 + step as u64,
                        1,
                        1234567890,
                        0,
                        nonce,
                        vec![0u8; 64],
                        vec![0u8; 32],
                    );
                    tx.id = tx.compute_hash();
                    dag.add_transaction_validated(tx)
                        .expect("conflict pair coexists");
                }
                2 => {
                    // Remove (possibly absent → no-op).
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&(next() as u64).to_le_bytes());
                    dag.remove_transaction(&id);
                }
                _ => {
                    // Prune (possibly absent root → harmless singleton).
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&(next() as u64).to_le_bytes());
                    dag.prune_subtree(id);
                }
            }
            // Verify every tracked key plus never-keys.
            for key in keys.iter().copied() {
                let mut indexed = dag.find_sender_nonce_conflicts(&key.0, key.1);
                indexed.sort();
                assert_eq!(
                    indexed,
                    brute(&dag, key),
                    "index/scan mismatch for key after mutation"
                );
            }
            for k in 0..4u8 {
                let never = ([0xEEu8; 32], 1000 + k as u64);
                assert!(dag
                    .find_sender_nonce_conflicts(&never.0, never.1)
                    .is_empty());
                assert!(brute(&dag, never).is_empty());
            }
        }
        println!(
            "H3 index equivalence: 150 mixed ops, {} keys, all match",
            keys.len()
        );
    }

    /// H3 per-conflict cost: fixed 2000-tx DAG; K = 1,2,4,8,16 independent
    /// conflict pairs (distinct senders per pair, childless roots). Per pair:
    /// prune_subtree(loser) + full rebuild_from_dag. Each conflict pays a
    /// full rebuild BY CONSTRUCTION — the test reports the base cost and the
    /// scaling factor, and asserts no superlinear blowup (T(16)/T(1) < 64:
    /// linear allows 16×, 4× noise margin).
    #[test]
    fn test_conflict_cpu_cost() {
        use crate::ledger::Ledger;
        use std::time::Instant;
        let mut totals = Vec::new();
        for &k in &[1usize, 2, 4, 8, 16] {
            let mut dag = distinct_root_dag(2000);
            let mut ledger = Ledger::new();
            // K pairs: same (sender, nonce), distinct receivers; roles by id.
            let mut losers = Vec::new();
            for p in 0..k {
                let mut sender = [0u8; 32];
                sender[0] = 0xC0;
                sender[1] = p as u8;
                let mk = |receiver: [u8; 32]| {
                    let mut tx = Transaction::new(
                        [[0u8; 32]; 2],
                        sender,
                        receiver,
                        100,
                        10,
                        1234567890,
                        0,
                        77,
                        vec![0u8; 64],
                        vec![0u8; 32],
                    );
                    tx.id = tx.compute_hash();
                    tx
                };
                let t1 = mk([0x11u8; 32]);
                let t2 = mk([0x22u8; 32]);
                let loser_id = if t1.id < t2.id { t2.id } else { t1.id };
                dag.inject_transaction_raw(t1);
                dag.inject_transaction_raw(t2);
                losers.push(loser_id);
            }
            let start = Instant::now();
            for loser in &losers {
                dag.prune_subtree(*loser);
                ledger.rebuild_from_dag(&dag);
            }
            let elapsed = start.elapsed();
            // Each pair loses exactly its loser (childless roots).
            assert_eq!(
                dag.transaction_count(),
                2000 + k,
                "one removal per conflict"
            );
            println!("H3 conflict cost: K={} in {:?}", k, elapsed);
            totals.push(elapsed);
        }
        let factor =
            totals[4].as_secs_f64() / totals[0].as_secs_f64().max(1e-9);
        println!(
            "H3 conflict scaling T(16)/T(1) = {:.2} (linear = 16)",
            factor
        );
        assert!(factor < 64.0, "superlinear conflict blowup: {}", factor);
    }

    /// H3 deep-prune shape: chains L = 100/200/400/800 (same sender,
    /// sequential nonces — validated inserts allow distinct nonces), prune
    /// root + full rebuild. Loose bound (< 1000× for 8× growth: catches
    /// cubic-or-worse only); the REPORTED curve feeds the weight-maintenance
    /// decision (incremental O(L²) adjustment vs single-pass recompute).
    #[test]
    fn test_conflict_prune_chain_scaling() {
        use crate::ledger::Ledger;
        use std::time::Instant;
        let mut times = Vec::new();
        for &len in &[100usize, 200, 400, 800] {
            let mut dag = DAG::new();
            let mut ledger = Ledger::new();
            let sender = [0xBu8; 32];
            let mut prev = [0u8; 32];
            let mut first = [0u8; 32];
            for i in 0..len as u64 {
                let mut tx = Transaction::new(
                    [prev, [0u8; 32]],
                    sender,
                    [9u8; 32],
                    1,
                    1,
                    1234567890,
                    0,
                    i,
                    vec![0u8; 64],
                    vec![0u8; 32],
                );
                tx.id = tx.compute_hash();
                if i == 0 {
                    first = tx.id;
                }
                prev = tx.id;
                dag.add_transaction_validated(tx).expect("chain links");
            }
            assert_eq!(dag.transaction_count(), len);
            let start = Instant::now();
            let removed = dag.prune_subtree(first);
            ledger.rebuild_from_dag(&dag);
            let elapsed = start.elapsed();
            assert_eq!(removed.len(), len, "whole chain must go");
            assert_eq!(dag.transaction_count(), 0);
            println!("H3 chain prune: L={} in {:?}", len, elapsed);
            times.push(elapsed);
        }
        let ratio = times[3].as_secs_f64() / times[0].as_secs_f64().max(1e-9);
        println!("H3 chain scaling T(800)/T(100) = {:.2}", ratio);
        assert!(ratio < 1000.0, "pathological prune blowup: {}", ratio);
    }

    // ===== PHASE 3C (H4): innocent-descendant precision =====
    //
    // No PoW anywhere below (validated inserts need none; the single raw node
    // is always a ROOT, so no topology link is ever missing). Hash-bound
    // parents make in-DAG survival of a loser's descendants impossible by
    // construction — what must hold instead: (a) prune removes EXACTLY the
    // loser subtree, nothing else; (b) no funds are created, destroyed, or
    // stranded (expectation loss is re-issuable; fund loss is not); (c) the
    // boot-restart path converges to the identical state as live prune.

    /// Fund `receivers` through the DAG itself (faucet→receiver, fee 100,
    /// sequential faucet nonces from `nonce0`). REQUIRED because
    /// rebuild_from_dag reseeds balances from genesis (a manual set_balance
    /// is wiped): test funding must flow through real DAG transactions,
    /// exactly like production.
    fn fund_dag(dag: &mut DAG, receivers: &[([u8; 32], u64)], nonce0: u64) {
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .expect("faucet hex")
            .try_into()
            .expect("faucet len");
        for (i, (receiver, amount)) in receivers.iter().enumerate() {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                faucet,
                *receiver,
                *amount,
                100,
                1234567890,
                0,
                nonce0 + i as u64,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            dag.add_transaction_validated(tx).expect("funding inserts");
        }
    }

    /// Build the H4 fixture DAG. Shape:
    ///   P root; A→B→C innocent chain on P; W/L same-key roots (roles by id:
    ///   winner = min); D innocent child of [L, A] (diamond); E innocent
    ///   child of W (winner's branch must survive).
    /// W validates in first (no conflict yet); L is raw-injected as a ROOT
    /// (no missing links: roots reference nothing); D, E validate after.
    /// Returns (dag, ids of P,A,B,C,W,L,D,E with canonical roles).
    fn h4_fixture() -> (
        DAG,
        TransactionId,
        TransactionId,
        TransactionId,
        TransactionId,
        TransactionId,
        TransactionId,
        TransactionId,
        TransactionId,
    ) {
        let mut dag = DAG::new();
        let mk = |parents: [TransactionId; 2],
                  sender: [u8; 32],
                  receiver: [u8; 32],
                  amount: u64,
                  fee: u64,
                  nonce: u64| {
            let mut tx = Transaction::new(
                parents,
                sender,
                receiver,
                amount,
                fee,
                1234567890,
                0,
                nonce,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            tx
        };
        let zero = [0u8; 32];
        // P with concrete bytes (kept explicit for readability).
        let p = mk([zero, zero], [0x10u8; 32], [0x11u8; 32], 1, 1, 0);
        dag.add_transaction_validated(p.clone()).unwrap();
        let a = mk([p.id, zero], [0x12u8; 32], [0x13u8; 32], 1, 1, 0);
        dag.add_transaction_validated(a.clone()).unwrap();
        let b = mk([a.id, zero], [0x14u8; 32], [0x15u8; 32], 1, 1, 0);
        dag.add_transaction_validated(b.clone()).unwrap();
        let c = mk([b.id, zero], [0x16u8; 32], [0x17u8; 32], 1, 1, 0);
        dag.add_transaction_validated(c.clone()).unwrap();
        // Conflict pair: same sender+nonce; roles assigned post-hoc by id.
        let t1 = mk([zero, zero], [0x20u8; 32], [0x21u8; 32], 100, 10, 9);
        let t2 = mk([zero, zero], [0x20u8; 32], [0x22u8; 32], 100, 10, 9);
        assert_ne!(t1.id, t2.id);
        let (w, l) = if t1.id < t2.id {
            (t1.clone(), t2.clone())
        } else {
            (t2.clone(), t1.clone())
        };
        dag.add_transaction_validated(w.clone()).unwrap();
        dag.inject_transaction_raw(l.clone());
        // Diamond innocent: child of loser AND of A.
        let d = mk([l.id, a.id], [0x30u8; 32], [0x31u8; 32], 50, 5, 0);
        dag.add_transaction_validated(d.clone()).unwrap();
        // Winner's innocent child (must survive).
        let e = mk([w.id, zero], [0x40u8; 32], [0x41u8; 32], 30, 5, 0);
        dag.add_transaction_validated(e.clone()).unwrap();
        (dag, p.id, a.id, b.id, c.id, w.id, l.id, d.id, e.id)
    }

    /// H4 precision: prune(L) removes EXACTLY {L, D} — the loser plus its
    /// diamond descendant — and nothing else. Survivors {P,A,B,C,W,E}; tips
    /// {C, E}; weights A=3, P=4, W=2, B=2, C=E=1 (subtree sizes post-prune).
    #[test]
    fn test_conflict_prunes_only_invalid_branch() {
        let (mut dag, p, a, b, c, w, l, d, e) = h4_fixture();
        assert_eq!(dag.transaction_count(), 8);
        let mut removed = dag.prune_subtree(l);
        removed.sort();
        let mut expected = vec![l, d];
        expected.sort();
        assert_eq!(removed, expected, "prune must remove exactly the loser subtree");
        assert_eq!(dag.transaction_count(), 6);
        for gone in [l, d] {
            assert!(
                dag.get_transaction(gone).is_none(),
                "loser branch must be gone"
            );
        }
        for kept in [p, a, b, c, w, e] {
            assert!(
                dag.get_transaction(kept).is_some(),
                "innocent tx must survive"
            );
        }
        // Tips = childless survivors.
        let mut tips: Vec<[u8; 32]> = Vec::new();
        for id in dag.transactions().keys() {
            let has_live_child = dag
                .children()
                .get(id)
                .map(|kids| {
                    kids.iter()
                        .any(|k| dag.transactions().contains_key(k))
                })
                .unwrap_or(false);
            if !has_live_child {
                tips.push(*id);
            }
        }
        tips.sort();
        let mut expected_tips = vec![c, e];
        expected_tips.sort();
        assert_eq!(tips, expected_tips, "tips must be exactly {{C, E}}");
        // Weight exactness through the prune (subtree sizes).
        let weight = |id| dag.get_transaction(id).map(|t| t.weight).unwrap_or(-1.0);
        assert_eq!(weight(a), 3.0, "A subtree {{A,B,C}}");
        assert_eq!(weight(p), 4.0, "P subtree {{P,A,B,C}}");
        assert_eq!(weight(w), 2.0, "W subtree {{W,E}}");
        assert_eq!(weight(b), 2.0);
        assert_eq!(weight(c), 1.0);
        assert_eq!(weight(e), 1.0);
        // No stale children entries pointing at removed txs.
        for kids in dag.children().values() {
            for k in kids {
                assert!(
                    dag.transactions().contains_key(k),
                    "children map must not reference pruned txs"
                );
            }
        }
    }

    /// H4 funds: innocent balances survive, revocation is exact. Two-phase
    /// shape mirroring a partition merge (both sides present, then resolve):
    /// Phase 1 — DAG {L, D} only: L applies, D (funded solely via L) applies.
    /// Phase 2 — W arrives (same key, smaller id): prune L (takes D), rebuild.
    /// Phase 3 — E (winner's child) joins and applies.
    /// Asserts the REVOCATION precisely (M2: 45→0, M3: 50→0), the winner
    /// installation (M1: 0→100), preservation (M1→65, M4=30), S untouched
    /// across phases (9890), and conservation (9985 = funded − burned fees).
    /// Expectation loss (D's effects revoked) is by design (hash-bound
    /// parents); FUND loss must be zero. H4_INNOCENT_DESCENDANT_LOSS = NO.
    #[test]
    fn test_conflict_preserves_innocent_descendant() {
        use crate::ledger::Ledger;
        let sender = [0x20u8; 32];
        let m1 = [0x21u8; 32];
        let m2 = [0x22u8; 32];
        let m3 = [0x31u8; 32];
        let m4 = [0x41u8; 32];
        let zero = [0u8; 32];
        let mk = |parents: [TransactionId; 2],
                  s: [u8; 32],
                  r: [u8; 32],
                  amount: u64,
                  fee: u64,
                  nonce: u64| {
            let mut tx = Transaction::new(
                parents, s, r, amount, fee, 1234567890, 0, nonce,
                vec![0u8; 64], vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            tx
        };
        let t1 = mk([zero, zero], sender, m1, 100, 10, 5);
        let t2 = mk([zero, zero], sender, m2, 100, 10, 5);
        assert_ne!(t1.id, t2.id);
        // Canonical roles: winner = min id (its receiver gets funded).
        let (w, l, w_recv) = if t1.id < t2.id {
            (t1, t2, m1)
        } else {
            (t2, t1, m2)
        };
        let l_recv = if w_recv == m1 { m2 } else { m1 };
        // D spends the LOSER's output; E spends the WINNER's output.
        // Built after roles are known (receivers depend on them).
        let d = mk([l.id, zero], l_recv, m3, 50, 5, 0);
        let e = mk([w.id, zero], w_recv, m4, 30, 5, 0);

        let mut dag = DAG::new();
        let mut ledger = Ledger::new();
        // Fund S through the DAG (rebuild reseeds from genesis — manual
        // set_balance would be wiped).
        fund_dag(&mut dag, &[(sender, 100_000)], 0);

        // Phase 1: loser world (W unknown yet) — L and innocent D apply.
        dag.inject_transaction_raw(l.clone());
        dag.add_transaction_validated(d.clone()).unwrap();
        ledger.rebuild_from_dag(&dag);
        assert_eq!(ledger.get_balance(&sender), 100_000 - 100 - 10);
        assert_eq!(ledger.get_balance(&l_recv), 100 - 50 - 5);
        assert_eq!(ledger.get_balance(&m3), 50);
        assert!(ledger.is_applied(&l.id));
        assert!(ledger.is_applied(&d.id));

        // Phase 2: winner arrives (partition-merge shape) — prune L (takes
        // D), rebuild. Innocent effects revoked EXACTLY, winner installed.
        dag.inject_transaction_raw(w.clone());
        let removed = dag.prune_subtree(l.id);
        assert_eq!(removed.len(), 2, "loser + its innocent child");
        ledger.rebuild_from_dag(&dag);
        assert_eq!(ledger.get_balance(&l_recv), 0, "M2: 45→0 revoked");
        assert_eq!(ledger.get_balance(&m3), 0, "M3: 50→0 revoked");
        assert_eq!(ledger.get_balance(&w_recv), 100, "M1: 0→100 installed");
        assert_eq!(ledger.get_balance(&sender), 100_000 - 100 - 10);
        assert!(!ledger.is_applied(&l.id), "loser mark must not survive");
        assert!(!ledger.is_applied(&d.id), "revoked mark must not survive");
        assert!(dag.get_transaction(l.id).is_none());
        assert!(dag.get_transaction(d.id).is_none());

        // Phase 3: winner's innocent child joins and applies; conservation.
        dag.add_transaction_validated(e.clone()).unwrap();
        ledger.rebuild_from_dag(&dag);
        assert_eq!(ledger.get_balance(&w_recv), 100 - 30 - 5);
        assert_eq!(ledger.get_balance(&m4), 30);
        let total = ledger.get_balance(&sender)
            + ledger.get_balance(&w_recv)
            + ledger.get_balance(&m4);
        assert_eq!(total, 100_000 - 15, "supply conserved minus burned fees");
        assert!(dag.get_transaction(w.id).is_some());
        assert!(dag.get_transaction(e.id).is_some());
    }

    /// H4 restart equivalence: live-prune == boot-restart. The persisted set
    /// (ALL txs incl. loser+descendants) through boot order
    /// (canonical_resolve_conflicts → rebuild_dag_topological →
    /// rebuild_from_dag) vs live order (inject all → prune canonical loser →
    /// rebuild_from_dag): DAG id-sets equal + ledger fingerprints equal
    /// (balances, supply, nonces). AFTER_RESTART == AFTER_CONFLICT.
    #[test]
    fn test_conflict_rebuild_preserves_valid_state() {
        use crate::ledger::Ledger;
        let (mut live_dag, p, a, b, c, w, l, d, e) = h4_fixture();
        // Fund every spender THROUGH the DAG (rebuild reseeds from genesis).
        // Identical funding on both paths (deterministic ids) so the
        // fingerprints compare funded, non-vacuous states.
        let spenders = [
            [0x10u8; 32],
            [0x12u8; 32],
            [0x14u8; 32],
            [0x16u8; 32],
            [0x20u8; 32],
            [0x30u8; 32],
            [0x40u8; 32],
        ];
        let funded: Vec<([u8; 32], u64)> =
            spenders.iter().map(|s| (*s, 1_000_000)).collect();
        fund_dag(&mut live_dag, &funded, 0);
        // LIVE order: prune canonical loser (max id), rebuild.
        live_dag.prune_subtree(l);
        let mut live_ledger = Ledger::new();
        live_ledger.rebuild_from_dag(&live_dag);

        // BOOT order: flat persisted set (loser + descendants included).
        let (mut boot_src, _, _, _, _, _, _, _, _) = h4_fixture();
        fund_dag(&mut boot_src, &funded, 0);
        let mut persisted: Vec<Transaction> =
            boot_src.transactions().values().cloned().collect();
        assert_eq!(persisted.len(), 15, "persisted set holds the loser too");
        let boot_pruned = canonical_resolve_conflicts(&mut persisted);
        assert_eq!(boot_pruned.len(), 2, "canonical drop = loser + descendant");
        let mut boot_dag = DAG::new();
        let (inserted, skipped, orphans) =
            rebuild_dag_topological(&mut boot_dag, persisted);
        assert_eq!(skipped, 0, "no valid tx may be skipped");
        assert!(orphans.is_empty(), "no orphans expected");
        assert_eq!(inserted, 13);
        let mut boot_ledger = Ledger::new();
        boot_ledger.rebuild_from_dag(&boot_dag);

        // Fingerprints must match.
        let mut live_ids: Vec<[u8; 32]> =
            live_dag.transactions().keys().copied().collect();
        live_ids.sort();
        let mut boot_ids: Vec<[u8; 32]> =
            boot_dag.transactions().keys().copied().collect();
        boot_ids.sort();
        assert_eq!(live_ids, boot_ids, "DAG sets must match");
        assert_eq!(live_ids.len(), 13, "8 fixture + 7 funding minus L and D");
        for id in [p, a, b, c, w, e] {
            assert!(live_ids.contains(&id) && boot_ids.contains(&id));
        }
        for id in [l, d] {
            assert!(!live_ids.contains(&id) && !boot_ids.contains(&id));
        }
        assert_eq!(
            live_ledger.total_supply(),
            boot_ledger.total_supply(),
            "supply must match"
        );
        for addr in [
            [0x10u8; 32],
            [0x12u8; 32],
            [0x14u8; 32],
            [0x16u8; 32],
            [0x20u8; 32],
            [0x30u8; 32],
            [0x40u8; 32],
            [0x11u8; 32],
            [0x13u8; 32],
            [0x15u8; 32],
            [0x17u8; 32],
            [0x21u8; 32],
            [0x22u8; 32],
            [0x31u8; 32],
            [0x41u8; 32],
        ] {
            assert_eq!(
                live_ledger.get_balance(&addr),
                boot_ledger.get_balance(&addr),
                "balance mismatch for {:?}",
                &addr[..2]
            );
            assert_eq!(
                live_ledger.get_nonce(&addr),
                boot_ledger.get_nonce(&addr),
                "nonce mismatch for {:?}",
                &addr[..2]
            );
        }
    }

    // ===== PHASE 3E (M2): zero-weight walk guard =====
    //
    // The guard in random_walk (total_weight == 0 → return current) is
    // unreachable given current weight invariants (children entries reference
    // present txs maintained at weight >= 1.0; negatives clamped) — these
    // tests CONSTRUCT the broken states directly (private field access from
    // the child test module) to prove termination instead of panic. Analysis
    // of reachability classes (production / malformed / pruned-history /
    // empty-branch): impossible today in all four (add/remove/prune maintain
    // the map; inject_raw writes no children entries at all); the guard is
    // defense-in-depth against future invariant slips, with zero behavior
    // change on the normal path (existing walk tests stay green).

    /// M2: all-zero children weights terminate at genesis (no gen_range
    /// panic). Genesis is a legal parent choice (roots exist by design).
    #[test]
    fn test_zero_weight_walk() {
        let algo = ParentSelectionAlgorithm::default();
        let mut dag = DAG::new();
        let mut r = Transaction::new(
            [[0u8; 32]; 2],
            [0x60u8; 32],
            [0x61u8; 32],
            1,
            1,
            1234567890,
            0,
            0,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        r.id = r.compute_hash();
        dag.add_transaction_validated(r.clone()).unwrap();
        // Simulate the invariant break: zero the maintained weight.
        dag.transactions.get_mut(&r.id).unwrap().weight = 0.0;
        let got = algo.random_walk(&dag).expect("must terminate, not panic");
        assert_eq!(got, TransactionId::default(), "stay at genesis");
    }

    /// M2: terminates under repetition, and NEVER selects a zero-weight
    /// child while a positive one exists (weighted choice degenerates to a
    /// deterministic pick: sorted-desc first entry always wins when the
    /// random draw is below its weight — always, since total == its weight).
    #[test]
    fn test_zero_weight_walk_terminates() {
        let algo = ParentSelectionAlgorithm::default();
        let mut dag = DAG::new();
        let mk_root = |sender: [u8; 32]| {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                [0x61u8; 32],
                1,
                1,
                1234567890,
                0,
                0,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            tx
        };
        let z = mk_root([0x62u8; 32]);
        let p = mk_root([0x63u8; 32]);
        dag.add_transaction_validated(z.clone()).unwrap();
        dag.add_transaction_validated(p.clone()).unwrap();
        dag.transactions.get_mut(&z.id).unwrap().weight = 0.0;
        for _ in 0..200 {
            let got = algo.random_walk(&dag).expect("must terminate");
            assert_eq!(got, p.id, "positive child always wins over zero");
        }
        // Pure-zero set: every walk stays at genesis.
        dag.transactions.get_mut(&p.id).unwrap().weight = 0.0;
        for _ in 0..200 {
            let got = algo.random_walk(&dag).expect("must terminate");
            assert_eq!(got, TransactionId::default());
        }
    }

    /// M2: malformed children entries (stale id of an absent tx → weight 0
    /// via the unwrap_or fallback) combined with a zeroed real tx also
    /// terminate at genesis; the public selector surfaces its freshness
    /// error (ancient fixture timestamps) instead of panicking.
    #[test]
    fn test_zero_weight_walk_malformed_state() {
        let algo = ParentSelectionAlgorithm::default();
        let mut dag = DAG::new();
        let mut r = Transaction::new(
            [[0u8; 32]; 2],
            [0x64u8; 32],
            [0x65u8; 32],
            1,
            1,
            1234567890,
            0,
            0,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        r.id = r.compute_hash();
        dag.add_transaction_validated(r.clone()).unwrap();
        dag.transactions.get_mut(&r.id).unwrap().weight = 0.0;
        // Stale entry: present in children, absent from transactions.
        let stale = [0xDEu8; 32];
        dag.children
            .insert(TransactionId::default(), vec![stale, r.id]);
        let got = algo.random_walk(&dag).expect("must terminate");
        assert_eq!(got, TransactionId::default());
        // Public entry point: no panic either (freshness gate rejects the
        // ancient fixture → deterministic NoValidTips, not a walk crash).
        let mut tips = TipSet::new();
        tips.add(r.clone());
        assert!(algo.select_parents(&tips, &dag).is_err());
    }

    // ===== PHASE 3E (M3): pruned-list order independence =====
    //
    // Consumer audit (no functional order reader exists): STEP-0 pruned ids
    // feed an order-insensitive batch purge + a cosmetic log sample;
    // node.rs boot uses only pruned.len() + per-id deletes (set semantics);
    // all in-repo assertions compare lengths or sorted sets. Pruned ORDER
    // itself varies (BFS pop order over insertion-ordered children Vecs;
    // HashSet order in canonical_resolve_conflicts; random Sled iteration
    // order at boot) — and must not matter. This test proves two nodes with
    // different arrival orders decide IDENTICALLY. No sorting is imposed: an
    // arbitrary canonical order would be unjustified churn.

    /// M3: same logical tx set in three input orders (sorted / reversed /
    /// rotated — modeling random Sled iteration at boot) yields identical
    /// survivor SETS, identical pruned SETS, and identical rebuild
    /// fingerprints (balances, supply, nonces). Set = funding + winner +
    /// loser (same key) + loser-child.
    #[test]
    fn test_pruned_list_order_independence() {
        use crate::ledger::Ledger;
        let sender = [0x70u8; 32];
        let m1 = [0x71u8; 32];
        let m2 = [0x72u8; 32];
        let m3 = [0x73u8; 32];
        let zero = [0u8; 32];
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap();
        let mk = |parents: [TransactionId; 2],
                  s: [u8; 32],
                  r: [u8; 32],
                  amount: u64,
                  fee: u64,
                  nonce: u64| {
            let mut tx = Transaction::new(
                parents, s, r, amount, fee, 1234567890, 0, nonce,
                vec![0u8; 64], vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            tx
        };
        let f = mk([zero, zero], faucet, sender, 100_000, 100, 0);
        let t1 = mk([zero, zero], sender, m1, 100, 10, 5);
        let t2 = mk([zero, zero], sender, m2, 100, 10, 5);
        assert_ne!(t1.id, t2.id);
        let (w, l) = if t1.id < t2.id {
            (t1.clone(), t2.clone())
        } else {
            (t2.clone(), t1.clone())
        };
        let d = mk([l.id, zero], m2, m3, 50, 5, 0);
        // NOTE: D's sender is hardcoded m2; if L pays m1 instead (roles
        // flipped), D is funded only when L applies — but L never applies
        // (canonical loser in every order), so D never applies either way.
        // The fingerprint comparison below is order-vs-order (identical
        // inputs), hence exact regardless of roles.
        let base = vec![f.clone(), w.clone(), l.clone(), d.clone()];
        let mut orders: Vec<Vec<Transaction>> = Vec::new();
        let mut sorted = base.clone();
        sorted.sort_by_key(|t| t.id);
        orders.push(sorted);
        let mut reversed = base.clone();
        reversed.reverse();
        orders.push(reversed);
        let mut rotated = base.clone();
        rotated.rotate_left(2);
        orders.push(rotated);

        let mut fingerprints = Vec::new();
        for input in &orders {
            let mut set = input.clone();
            let mut pruned = canonical_resolve_conflicts(&mut set);
            pruned.sort();
            let mut survivors: Vec<TransactionId> =
                set.iter().map(|t| t.id).collect();
            survivors.sort();
            // Survivor set: funding + winner (loser + child dropped).
            assert_eq!(survivors, {
                let mut exp = vec![f.id, w.id];
                exp.sort();
                exp
            });
            assert_eq!(pruned.len(), 2, "loser + descendant drop in every order");
            // Fingerprint via validated DAG + funded rebuild.
            let mut dag = DAG::new();
            for tx in &set {
                dag.add_transaction_validated(tx.clone())
                    .expect("survivors insert");
            }
            let mut ledger = Ledger::new();
            ledger.rebuild_from_dag(&dag);
            let mut bals: Vec<(String, u64)> = ledger
                .get_all_balances()
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            bals.sort();
            fingerprints.push((
                survivors,
                pruned,
                bals,
                ledger.total_supply(),
                ledger.get_nonce(&sender),
            ));
        }
        assert_eq!(fingerprints[0], fingerprints[1]);
        assert_eq!(fingerprints[1], fingerprints[2]);

        // prune_subtree return order: the SAME two child txs inserted in
        // different orders (children Vec order differs) must yield identical
        // removed SETS. (An earlier draft varied sender bytes per position,
        // which builds DIFFERENT txs — correctly different prunes. The test
        // must vary ORDER, not identity.)
        let mk_child = |sender: [u8; 32], nonce: u64, root: TransactionId| {
            let mut tx = Transaction::new(
                [root, [0u8; 32]],
                sender,
                m3,
                10,
                1,
                1234567890,
                0,
                nonce,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            tx.id = tx.compute_hash();
            tx
        };
        let build_two = |swap: bool| {
            let mut dag = DAG::new();
            let root = mk([zero, zero], sender, m1, 100, 10, 5);
            dag.add_transaction_validated(root.clone()).unwrap();
            let c1 = mk_child([0x81u8; 32], 0, root.id);
            let c2 = mk_child([0x82u8; 32], 1, root.id);
            // Identical txs, different insertion orders.
            let (first, second) = if swap { (c2, c1) } else { (c1, c2) };
            dag.add_transaction_validated(first).unwrap();
            dag.add_transaction_validated(second).unwrap();
            (dag, root.id)
        };
        let (mut da, ra) = build_two(false);
        let (mut db, rb) = build_two(true);
        let mut pa = da.prune_subtree(ra);
        let mut pb = db.prune_subtree(rb);
        pa.sort();
        pb.sort();
        assert_eq!(pa.len(), 3, "root + two children");
        assert_eq!(pa, pb, "removed sets must match across insertion orders");
    }

    // ===== PHASE 3E (M7): floating-point determinism =====
    //
    // Triage (repo-wide f32/f64 audit): NO float reaches fork choice (min-id
    // over integer ids), the ledger (u64 balances/nonces/fees), finality
    // (no mechanism), or peer scoring (i32). Floats live in exactly three
    // consensus-adjacent places, all deterministic IEEE-754 for identical
    // inputs: (1) tx.weight f64 = subtree size, maintained by +1.0/-1.0 with
    // a 0.0 clamp — integer-valued at all times, no division, no NaN source;
    // consumed via exact `as u64` cast (tip walk) and a `>= 5.0` compare
    // (Stable indicator, advisory); (2) fee-oracle/estimator f64 internals
    // with u64 outputs (accept-time gates only; cross-node differences come
    // from different local inputs, not from float nondeterminism); (3)
    // timing/display/bench values (no consensus effect). Verdict below:
    // NOT_RELEVANT for consensus safety; this test pins the exactness
    // foundation the verdict rests on (integral, finite, bounded weights).

    /// M7: weights stay integral, finite, non-negative and bounded by the DAG
    /// size across random add/remove/prune sequences (deterministic LCG).
    /// Any fractional/NaN/negative/overflowing weight would break the
    /// exactness the tip-walk cast and the Stable threshold rely on.
    #[test]
    fn test_weight_finiteness_and_bounds() {
        let mut rng_state: u64 = 0xF0E1_D2C3_B4A5_96A7;
        let mut next = || {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (rng_state >> 33) as usize
        };
        let mut dag = DAG::new();
        let mut serial: u64 = 0;
        // Genesis-parented roots keep topology trivial; the exercise is the
        // weight bookkeeping across interleaved mutations.
        for _step in 0..200 {
            match next() % 3 {
                0 => {
                    serial += 1;
                    let mut sender = [0u8; 32];
                    sender[..8].copy_from_slice(&serial.to_le_bytes());
                    sender[8] = 0xB7;
                    let mut tx = Transaction::new(
                        [[0u8; 32]; 2],
                        sender,
                        [9u8; 32],
                        1,
                        1,
                        1234567890,
                        0,
                        0,
                        vec![0u8; 64],
                        vec![0u8; 32],
                    );
                    tx.id = tx.compute_hash();
                    dag.add_transaction_validated(tx).expect("fresh root");
                }
                1 => {
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&(next() as u64).to_le_bytes());
                    dag.remove_transaction(&id);
                }
                _ => {
                    let mut id = [0u8; 32];
                    id[..8].copy_from_slice(&(next() as u64).to_le_bytes());
                    dag.prune_subtree(id);
                }
            }
            let count = dag.transaction_count() as f64;
            for tx in dag.transactions().values() {
                let w = tx.weight;
                assert!(w.is_finite(), "weight must never be NaN/infinite");
                assert!(w >= 0.0, "weights are clamped at zero");
                assert_eq!(w.fract(), 0.0, "weights stay integral (+/-1.0 only)");
                assert!(
                    w <= count,
                    "subtree size {} cannot exceed DAG size {}",
                    w,
                    count
                );
            }
        }
    }
}
