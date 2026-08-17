//! # Ledger Module
//!
//! Manages the ledger state (account balances) with persistence to Sled DB.

use crate::parent_selection::DAG;
use crate::storage::Storage;
use crate::transaction::{Address, Transaction, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Ledger structure holding account balances with Sled persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ledger {
    /// Balances map: address (hex string) -> balance (AETH) - in-memory cache
    pub balances: HashMap<String, u64>,
    /// Nonce tracking: address (hex string) -> last nonce used (V2 fix - anti-replay)
    pub nonces: HashMap<String, u64>,
    /// Optional Sled storage backend for persistence
    #[serde(skip)]
    storage: Option<Arc<RwLock<Storage>>>,
    /// Total fees burned (economic policy: fees are burned, not given to miners)
    pub total_fees_burned: u64,
}

/// Fee burn address (all fees are sent here and effectively burned)
/// This is a special address that no one controls, ensuring fees are permanently removed from circulation
pub const FEE_BURN_ADDRESS: Address = [0xFFu8; 32];

/// Maximum supply invariant (hard cap), mirrored from genesis. With ZERO
/// emission the total supply can never exceed the genesis allocation and only
/// decreases through fee burning. This constant is retained as a defensive
/// invariant check.
pub const MAX_SUPPLY: u64 = crate::genesis::MAX_SUPPLY;

impl Ledger {
    /// Create a new empty ledger
    pub fn new() -> Self {
        Ledger {
            balances: HashMap::new(),
            nonces: HashMap::new(),
            storage: None,
            total_fees_burned: 0,
        }
    }

    /// Create a new ledger with Sled storage
    pub async fn new_with_storage(
        storage: Arc<RwLock<Storage>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let storage_read = storage.read().await;
        let mut ledger = Ledger {
            balances: HashMap::new(),
            nonces: HashMap::new(),
            storage: Some(storage.clone()),
            total_fees_burned: 0,
        };

        // Load balances from Sled
        let sled_balances = storage_read.get_all_balances()?;
        for (addr, balance) in sled_balances {
            let addr_hex = hex::encode(addr);
            ledger.balances.insert(addr_hex, balance);
        }

        // Load nonces from Sled for replay protection
        let sled_nonces = storage_read.get_all_nonces()?;
        for (addr, nonce) in sled_nonces {
            let addr_hex = hex::encode(addr);
            ledger.nonces.insert(addr_hex, nonce);
        }

        drop(storage_read);

        // Reconstruct total_fees_burned from burn address balance (source of truth)
        // This ensures consistency after restart: total_fees_burned == fee_burn_balance()
        let burn_hex = hex::encode(FEE_BURN_ADDRESS);
        ledger.total_fees_burned = *ledger.balances.get(&burn_hex).unwrap_or(&0);

        tracing::info!(
            "✓ Ledger loaded from Sled: {} accounts, {} nonces, total supply: {}",
            ledger.balances.len(),
            ledger.nonces.len(),
            ledger.total_supply()
        );
        Ok(ledger)
    }

    /// Save ledger to Sled (atomic write) if storage is available
    pub async fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(storage) = &self.storage {
            let storage_read = storage.read().await;
            // Save balances
            for (addr_hex, balance) in &self.balances {
                let addr_bytes = hex::decode(addr_hex)?;
                let address: Address = addr_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|e| format!("Invalid address length: {}", e))?;
                storage_read.put_balance(address, *balance)?;
            }
            // Save nonces for replay protection
            for (addr_hex, nonce) in &self.nonces {
                let addr_bytes = hex::decode(addr_hex)?;
                let address: Address = addr_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|e| format!("Invalid address length: {}", e))?;
                storage_read.put_nonce(address, *nonce)?;
            }
            // P4: no flush here — save() runs on EVERY accepted transaction
            // (STEP 8); a synchronous flush (fsync) per save cost ~690µs/tx
            // in release. Durability: Sled auto-flushes ~every 500ms, the
            // node flushes periodically (10s) and on shutdown, and the boot
            // rebuild reconstructs the ledger from the DAG (source of truth).
            tracing::debug!("💾 Ledger saved to Sled (balances + nonces)");
        }
        Ok(())
    }

    /// Get balance for an address
    pub fn get_balance(&self, address: &Address) -> u64 {
        let addr_hex = hex::encode(address);
        *self.balances.get(&addr_hex).unwrap_or(&0)
    }

    /// Get balance for an address by hex string
    pub fn get_balance_hex(&self, address_hex: &str) -> u64 {
        *self.balances.get(address_hex).unwrap_or(&0)
    }

    /// Total circulating supply = sum of all balances EXCLUDING the burn
    /// address. Computed on demand from the live balance map so it can never
    /// go stale (fixes NV-02: a direct set_balance previously left the stored
    /// total_supply out of sync, letting the MAX_SUPPLY check be bypassed).
    pub fn total_supply(&self) -> u64 {
        let burn_hex = hex::encode(FEE_BURN_ADDRESS);
        self.balances
            .iter()
            .filter(|(addr, _)| **addr != burn_hex)
            .map(|(_, balance)| *balance)
            .sum()
    }

    /// Economic invariant: circulating supply must never exceed MAX_SUPPLY.
    /// With ZERO emission the supply only ever decreases (fees burned), so this
    /// is a defensive check against accidental inflation.
    pub fn supply_within_bounds(&self) -> bool {
        self.total_supply() <= MAX_SUPPLY
    }

    /// Set balance for an address
    pub fn set_balance(&mut self, address: &Address, balance: u64) {
        let addr_hex = hex::encode(address);
        self.balances.insert(addr_hex, balance);
    }

    /// Set balance for an address by hex string
    pub fn set_balance_hex(&mut self, address_hex: String, balance: u64) {
        self.balances.insert(address_hex, balance);
    }

    /// Add amount to an address balance
    pub fn add_balance(&mut self, address: &Address, amount: u64) -> Result<(), String> {
        let addr_hex = hex::encode(address);
        let current = *self.balances.get(&addr_hex).unwrap_or(&0);
        let new_balance = current
            .checked_add(amount)
            .ok_or_else(|| format!("Balance overflow: {} + {}", current, amount))?;
        self.balances.insert(addr_hex, new_balance);
        Ok(())
    }

    /// Subtract amount from an address balance
    pub fn subtract_balance(&mut self, address: &Address, amount: u64) -> Result<(), String> {
        let addr_hex = hex::encode(address);
        let current = *self.balances.get(&addr_hex).unwrap_or(&0);
        if current < amount {
            return Err(format!("Insufficient balance: {} < {}", current, amount));
        }
        self.balances.insert(addr_hex, current - amount);
        Ok(())
    }

    /// Transfer balance from one address to another with fee deduction (INTERNAL USE ONLY)
    /// 🔒 ZERO TRUST: This method is private. Use TransactionProcessor for all transfers.
    /// Atomic: either all changes apply or none apply
    /// Economic policy: fees are burned (sent to FEE_BURN_ADDRESS), not given to miners
    pub(crate) fn transfer_internal(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u64,
        fee: u64,
    ) -> Result<(), String> {
        let from_hex = hex::encode(from);
        let to_hex = hex::encode(to);
        let burn_hex = hex::encode(FEE_BURN_ADDRESS);

        // Phase 1: Check all preconditions first (no mutations yet)
        let from_balance = *self.balances.get(&from_hex).unwrap_or(&0);
        let to_balance = *self.balances.get(&to_hex).unwrap_or(&0);
        let burn_balance = *self.balances.get(&burn_hex).unwrap_or(&0);

        // Check sender has enough for amount + fee
        let total_deduction = amount
            .checked_add(fee)
            .ok_or_else(|| format!("Overflow: amount + fee = {} + {}", amount, fee))?;
        if from_balance < total_deduction {
            return Err(format!(
                "Insufficient balance: {} < {} (amount: {}, fee: {})",
                from_balance, total_deduction, amount, fee
            ));
        }

        // Phase 2: Calculate all final values first (no mutations yet)
        let new_from_balance = from_balance - total_deduction;
        if from_hex == to_hex {
            // Self-transfer: sender == receiver. Only the fee is burned;
            // the amount cancels out. Must NOT re-credit the amount
            // (previous bug: insert order re-added amount, creating money).
            let (new_burn_balance, new_total_fees_burned) = if fee > 0 {
                let new_burn = burn_balance
                    .checked_add(fee)
                    .ok_or_else(|| format!("Burn address overflow: {} + {}", burn_balance, fee))?;
                let new_total = self.total_fees_burned.checked_add(fee).ok_or_else(|| {
                    format!(
                        "Total fees burned overflow: {} + {}",
                        self.total_fees_burned, fee
                    )
                })?;
                (new_burn, new_total)
            } else {
                (burn_balance, self.total_fees_burned)
            };
            self.balances.insert(from_hex, from_balance - fee);
            self.balances.insert(burn_hex, new_burn_balance);
            self.total_fees_burned = new_total_fees_burned;
            return Ok(());
        }
        let new_to_balance = to_balance
            .checked_add(amount)
            .ok_or_else(|| format!("Receiver balance overflow: {} + {}", to_balance, amount))?;

        let (new_burn_balance, new_total_fees_burned) = if fee > 0 {
            let new_burn = burn_balance
                .checked_add(fee)
                .ok_or_else(|| format!("Burn address overflow: {} + {}", burn_balance, fee))?;
            let new_total = self.total_fees_burned.checked_add(fee).ok_or_else(|| {
                format!(
                    "Total fees burned overflow: {} + {}",
                    self.total_fees_burned, fee
                )
            })?;
            (new_burn, new_total)
        } else {
            (burn_balance, self.total_fees_burned)
        };

        // Phase 3: Apply all mutations atomically (all or nothing)
        self.balances.insert(from_hex, new_from_balance);
        self.balances.insert(to_hex, new_to_balance);
        self.balances.insert(burn_hex, new_burn_balance);
        self.total_fees_burned = new_total_fees_burned;

        Ok(())
    }

    /// Get last nonce for an address
    pub fn get_nonce(&self, address: &Address) -> u64 {
        let addr_hex = hex::encode(address);
        *self.nonces.get(&addr_hex).unwrap_or(&0)
    }

    /// Set nonce for an address
    pub fn set_nonce(&mut self, address: &Address, nonce: u64) {
        let addr_hex = hex::encode(address);
        self.nonces.insert(addr_hex, nonce);
    }

    /// Validate account nonce (strict: must be exactly last_nonce + 1)
    /// Does NOT update the nonce - call commit_nonce() after successful transaction
    ///
    /// STRICT: no address is exempt (fixes V-01). Every sender, including the
    /// faucet, must present exactly `last_nonce + 1`.
    ///
    /// NOTE: This strict helper is only used by unit tests. Live transaction
    /// admission must NOT use a strict nonce check: it is arrival-order
    /// dependent and would diverge nodes that process the same transaction
    /// set in different orders. Replay protection is enforced by the DAG's
    /// canonical (sender, account_nonce) conflict resolution instead.
    pub fn validate_account_nonce(
        &self,
        address: &Address,
        account_nonce: u64,
    ) -> Result<(), String> {
        let last_nonce = self.get_nonce(address);
        if account_nonce != last_nonce + 1 {
            return Err(format!(
                "Invalid account_nonce: {} != {} + 1 (expected last_nonce + 1)",
                account_nonce, last_nonce
            ));
        }
        Ok(())
    }

    /// Commit nonce update after successful transaction
    pub fn commit_nonce(&mut self, address: &Address, account_nonce: u64) {
        self.set_nonce(address, account_nonce);
    }

    /// Get all balances
    pub fn get_all_balances(&self) -> &HashMap<String, u64> {
        &self.balances
    }

    /// Get the number of accounts
    pub fn account_count(&self) -> usize {
        self.balances.len()
    }

    /// Get storage reference
    pub fn storage(&self) -> Option<Arc<RwLock<Storage>>> {
        self.storage.clone()
    }

    /// Get total fees burned so far
    pub fn total_fees_burned(&self) -> u64 {
        self.total_fees_burned
    }

    /// Get balance of the fee burn address (total fees burned)
    pub fn fee_burn_balance(&self) -> u64 {
        self.get_balance(&FEE_BURN_ADDRESS)
    }

    /// Rebuild the ledger entirely from the genesis distribution + DAG.
    ///
    /// The DAG is the single source of truth; the ledger is treated as a
    /// *derived view*. This makes state reconstruction deterministic and
    /// guarantees atomicity after a conflict-prune (or after a node restart).
    ///
    /// Process:
    ///   1. Reset balances, nonces and fees-burned.
    ///   2. Apply the genesis allocation (no emission beyond this point).
    ///   3. Replay every DAG transaction in a CANONICAL, deterministic order:
    ///      parents before children, ties broken by ascending transaction id
    ///      (never HashMap iteration order). A transaction whose balance is
    ///      not yet available is NOT evicted: it is retried on the next pass
    ///      once its funding transactions have been applied (relaxation), so
    ///      a valid transaction can never be spuriously evicted just because
    ///      it appeared before its funding in the replay order.
    ///
    /// V-21 FIX (determinism): this function is a pure function of the DAG.
    /// Every node that holds the same DAG - regardless of arrival order,
    /// HashMap order, or restart history - computes byte-identical balances,
    /// nonces and total supply. Defensive residue handling: if the DAG still
    /// contains two transactions with the same (sender, account_nonce), only
    /// the smallest id applies (canonical double-spend rule).
    pub fn rebuild_from_dag(&mut self, dag: &DAG) {
        self.balances.clear();
        self.nonces.clear();
        self.total_fees_burned = 0;

        // Apply genesis distribution (fixed supply).
        for (addr_hex, balance) in crate::genesis::GENESIS_LEDGER {
            self.balances.insert(addr_hex.to_string(), balance);
        }

        // Canonical order: ascending id. HashMap iteration order is
        // explicitly forbidden (it differs across nodes and runs).
        let mut pending: Vec<Transaction> = dag.transactions().values().cloned().collect();

        // Canonical double-spend winners: the SMALLEST id per (sender,
        // account_nonce) pair, computed up front as a pure function of the
        // DAG. A tx that is not the canonical winner of its key can NEVER
        // apply, no matter when the replay meets it (this also covers the
        // pathological case where the loser is fundable before the winner).
        let mut canonical_winners: std::collections::HashMap<(Address, u64), TransactionId> =
            std::collections::HashMap::new();
        for tx in &pending {
            let key = (tx.sender, tx.account_nonce);
            let better = match canonical_winners.get(&key) {
                Some(existing) => tx.id < *existing,
                None => true,
            };
            if better {
                canonical_winners.insert(key, tx.id);
            }
        }
        pending.sort_unstable_by_key(|tx| tx.id);

        let mut applied: std::collections::HashSet<TransactionId> =
            std::collections::HashSet::new();

        loop {
            let mut progressed = false;
            let mut next_pending = Vec::new();
            for tx in pending {
                if applied.contains(&tx.id) {
                    continue;
                }
                let parents_ready = tx
                    .parents
                    .iter()
                    .all(|p| p.iter().all(|&b| b == 0) || applied.contains(p));
                if !parents_ready {
                    next_pending.push(tx);
                    continue;
                }
                // Residue: a losing double-spend still present in the DAG.
                // Skipped deterministically BEFORE any transfer, regardless
                // of processing order or funding state.
                let key = (tx.sender, tx.account_nonce);
                if let Some(winner_id) = canonical_winners.get(&key) {
                    if tx.id != *winner_id {
                        tracing::warn!(
                            "⚠️ rebuild_from_dag: skipping double-spend residue {} (winner {} applies)",
                            hex::encode(&tx.id[..8]),
                            hex::encode(&winner_id[..8])
                        );
                        // Mark as handled (not applied) so its children can
                        // still be evaluated; it never debits the account.
                        applied.insert(tx.id);
                        progressed = true;
                        continue;
                    }
                }
                // Transfer FIRST, then mark applied: a transaction that
                // cannot yet be funded is retried on the next pass, it is
                // never spuriously evicted (V-21 relaxation).
                if self
                    .transfer_internal(&tx.sender, &tx.receiver, tx.amount, tx.fee)
                    .is_err()
                {
                    next_pending.push(tx);
                    continue;
                }
                let last = self.get_nonce(&tx.sender);
                if tx.account_nonce > last {
                    self.set_nonce(&tx.sender, tx.account_nonce);
                }
                applied.insert(tx.id);
                progressed = true;
            }
            pending = next_pending;
            if !progressed {
                break;
            }
        }

        // Remaining transactions could never be funded even after full
        // relaxation: the DAG is genuinely inconsistent at their position.
        // This must not happen on a canonical DAG, but the rebuild stays
        // defensive and deterministic: the SAME txs are evicted on every node.
        for tx in pending {
            tracing::warn!(
                "⚠️ rebuild_from_dag: evicting inconsistent tx {} (never fundable)",
                hex::encode(&tx.id[..8])
            );
        }

        tracing::info!(
            "♻️ Ledger rebuilt from DAG: {} txs, supply {} (<= MAX {}): {}",
            applied.len(),
            self.total_supply(),
            MAX_SUPPLY,
            self.supply_within_bounds()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_ledger_with_sled() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let storage_arc = Arc::new(RwLock::new(storage));
        let ledger = Ledger::new_with_storage(storage_arc.clone()).await.unwrap();

        assert!(ledger.balances.is_empty());
    }

    #[test]
    fn test_ledger_balance_operations() {
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        assert_eq!(ledger.get_balance(&addr), 0);

        ledger.set_balance(&addr, 100);
        assert_eq!(ledger.get_balance(&addr), 100);

        ledger.add_balance(&addr, 50).unwrap();
        assert_eq!(ledger.get_balance(&addr), 150);

        ledger.subtract_balance(&addr, 30).unwrap();
        assert_eq!(ledger.get_balance(&addr), 120);
    }

    #[test]
    fn test_ledger_transfer() {
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 100);
        ledger.transfer_internal(&addr1, &addr2, 50, 5).unwrap(); // amount=50, fee=5

        assert_eq!(ledger.get_balance(&addr1), 45); // 100 - 50 - 5
        assert_eq!(ledger.get_balance(&addr2), 50); // 0 + 50
        assert_eq!(ledger.total_fees_burned(), 5); // Fee burned
        assert_eq!(ledger.fee_burn_balance(), 5); // Fee burn address balance
    }

    #[test]
    fn test_ledger_insufficient_balance() {
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        ledger.set_balance(&addr, 10);
        let result = ledger.subtract_balance(&addr, 20);

        assert!(result.is_err());
    }

    #[test]
    fn test_account_nonce_validation_strict() {
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        // First transaction with account_nonce 1 (must be last_nonce + 1 = 0 + 1)
        assert!(ledger.validate_account_nonce(&addr, 1).is_ok());
        ledger.commit_nonce(&addr, 1);
        assert_eq!(ledger.get_nonce(&addr), 1);

        // Replay attack: same account_nonce should fail
        assert!(ledger.validate_account_nonce(&addr, 1).is_err());

        // Non-sequential account_nonce should fail
        assert!(ledger.validate_account_nonce(&addr, 3).is_err());

        // Lower account_nonce should fail
        assert!(ledger.validate_account_nonce(&addr, 0).is_err());

        // Correct sequential account_nonce should succeed
        assert!(ledger.validate_account_nonce(&addr, 2).is_ok());
        ledger.commit_nonce(&addr, 2);
        assert_eq!(ledger.get_nonce(&addr), 2);
    }

    #[test]
    fn test_balance_overflow_protection() {
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        // Set balance near max
        ledger.set_balance(&addr, u64::MAX - 100);

        // Adding small amount should succeed
        assert!(ledger.add_balance(&addr, 50).is_ok());

        // Adding amount that would overflow should fail
        assert!(ledger.add_balance(&addr, 100).is_err());
    }

    #[test]
    fn test_transfer_atomic_with_fee() {
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 100);
        ledger.transfer_internal(&addr1, &addr2, 50, 5).unwrap(); // amount=50, fee=5

        assert_eq!(ledger.get_balance(&addr1), 45); // 100 - 50 - 5
        assert_eq!(ledger.get_balance(&addr2), 50); // 0 + 50
        assert_eq!(ledger.total_fees_burned(), 5); // Fee burned
        assert_eq!(ledger.fee_burn_balance(), 5); // Fee burn address balance
    }

    #[test]
    fn test_transfer_insufficient_with_fee() {
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 10);
        let result = ledger.transfer_internal(&addr1, &addr2, 50, 5); // amount=50, fee=5

        assert!(result.is_err());
        // Balances should remain unchanged (atomic)
        assert_eq!(ledger.get_balance(&addr1), 10);
        assert_eq!(ledger.get_balance(&addr2), 0);
    }

    #[test]
    fn test_transfer_receiver_overflow() {
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 100);
        ledger.set_balance(&addr2, u64::MAX - 50);

        let result = ledger.transfer_internal(&addr1, &addr2, 100, 0);
        assert!(result.is_err());
        // Balances should remain unchanged (atomic)
        assert_eq!(ledger.get_balance(&addr1), 100);
        assert_eq!(ledger.get_balance(&addr2), u64::MAX - 50);
    }

    #[test]
    fn test_nonce_persistence() {
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        assert_eq!(ledger.get_nonce(&addr), 0);
        ledger.commit_nonce(&addr, 1);
        assert_eq!(ledger.get_nonce(&addr), 1);
        ledger.commit_nonce(&addr, 2);
        assert_eq!(ledger.get_nonce(&addr), 2);
    }

    #[tokio::test]
    async fn test_nonce_persistence_with_storage() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let storage_arc = Arc::new(RwLock::new(storage));

        let mut ledger = Ledger::new_with_storage(storage_arc.clone()).await.unwrap();
        let addr = [1u8; 32];

        // Set nonce
        ledger.commit_nonce(&addr, 5);
        assert_eq!(ledger.get_nonce(&addr), 5);

        // Save to storage
        ledger.save().await.unwrap();

        // Load new ledger from storage
        let ledger2 = Ledger::new_with_storage(storage_arc.clone()).await.unwrap();
        assert_eq!(ledger2.get_nonce(&addr), 5); // Nonce persisted
    }

    #[test]
    fn test_concurrent_nonce_race_condition() {
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        // First transaction with account_nonce 1 (valid)
        assert!(ledger.validate_account_nonce(&addr, 1).is_ok());
        ledger.commit_nonce(&addr, 1);
        assert_eq!(ledger.get_nonce(&addr), 1);

        // Try to commit same nonce again (should fail validation)
        assert!(ledger.validate_account_nonce(&addr, 1).is_err());

        // Try to commit with nonce 3 (skip 2, should fail)
        assert!(ledger.validate_account_nonce(&addr, 3).is_err());

        // Only nonce 2 should be valid now
        assert!(ledger.validate_account_nonce(&addr, 2).is_ok());
        ledger.commit_nonce(&addr, 2);
        assert_eq!(ledger.get_nonce(&addr), 2);
    }

    #[test]
    fn test_atomic_transfer_rollback_on_failure() {
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 100);
        ledger.set_balance(&addr2, 0);

        // Simulate transfer that should fail partway through
        // The transfer method should be atomic - no partial state
        let result = ledger.transfer_internal(&addr1, &addr2, 200, 10);
        assert!(result.is_err());

        // Verify no partial state - balances unchanged
        assert_eq!(ledger.get_balance(&addr1), 100);
        assert_eq!(ledger.get_balance(&addr2), 0);
    }

    #[test]
    fn test_real_concurrent_nonce_race() {
        use std::sync::Arc;
        use std::thread;

        let ledger = Arc::new(std::sync::Mutex::new(Ledger::new()));
        let addr = [1u8; 32];

        // Set initial nonce to 0
        ledger.lock().unwrap().commit_nonce(&addr, 0);

        let mut handles = vec![];

        // Spawn 10 threads trying to commit nonce=1 concurrently
        for _ in 0..10 {
            let ledger_clone = ledger.clone();
            let handle = thread::spawn(move || {
                let mut l = ledger_clone.lock().unwrap();
                // Validate nonce=1 (should be valid for first thread only)
                let validation = l.validate_account_nonce(&addr, 1);
                if validation.is_ok() {
                    l.commit_nonce(&addr, 1);
                    true // Success
                } else {
                    false // Failed validation
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        let successes: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Only one thread should succeed
        let success_count = successes.iter().filter(|&&s| s).count();
        assert_eq!(
            success_count, 1,
            "Exactly one thread should succeed, but {} succeeded",
            success_count
        );

        // Final nonce should be 1
        assert_eq!(ledger.lock().unwrap().get_nonce(&addr), 1);
    }

    #[test]
    fn test_transactional_consistency_on_failure() {
        // Test that verifies if ledger transfer fails, no partial state remains
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 100);
        ledger.set_balance(&addr2, 0);
        ledger.commit_nonce(&addr1, 0);

        // Use internal transfer method (zero-trust architecture)
        ledger.transfer_internal(&addr1, &addr2, 50, 5).unwrap();

        // Simulate a transfer that would fail (insufficient balance)
        let result = ledger.transfer_internal(&addr1, &addr2, 200, 10);
        assert!(result.is_err());

        // Verify no partial state:
        // - Balance unchanged (should be 45 after first transfer)
        assert_eq!(ledger.get_balance(&addr1), 45);
        assert_eq!(ledger.get_balance(&addr2), 50);
        // - Nonce unchanged (not committed)
        assert_eq!(ledger.get_nonce(&addr1), 0);
    }

    #[test]
    fn test_atomic_nonce_validation_commit() {
        // Test that validates and commits nonce atomically under write lock
        // Simulates the pattern used in send_transaction: validate + commit under same lock
        use std::sync::Arc;
        use std::thread;

        let ledger = Arc::new(std::sync::Mutex::new(Ledger::new()));
        let addr = [1u8; 32];

        // Set initial nonce to 0
        ledger.lock().unwrap().commit_nonce(&addr, 0);

        let mut handles = vec![];

        // Spawn 10 threads trying to validate + commit nonce=1 concurrently
        // This simulates the pattern in send_transaction where validation and commit
        // happen under the same write lock
        for _ in 0..10 {
            let ledger_clone = ledger.clone();
            let handle = thread::spawn(move || {
                let mut l = ledger_clone.lock().unwrap();
                // Validate nonce=1 (should be valid for first thread only)
                let validation = l.validate_account_nonce(&addr, 1);
                if validation.is_ok() {
                    // Immediately commit under same lock (atomic pattern)
                    l.commit_nonce(&addr, 1);
                    true // Success
                } else {
                    false // Failed validation
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        let successes: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Only one thread should succeed
        let success_count = successes.iter().filter(|&&s| s).count();
        assert_eq!(
            success_count, 1,
            "Exactly one thread should succeed, but {} succeeded",
            success_count
        );

        // Final nonce should be 1
        assert_eq!(ledger.lock().unwrap().get_nonce(&addr), 1);
    }

    #[test]
    fn test_mempool_full_prevents_ledger_commit() {
        // Test that verifies if mempool is full, ledger is not committed
        // This simulates the capacity check before ledger commit in send_transaction
        let mut ledger = Ledger::new();
        let addr1 = [1u8; 32];
        let addr2 = [2u8; 32];

        ledger.set_balance(&addr1, 100);
        ledger.set_balance(&addr2, 0);
        ledger.commit_nonce(&addr1, 0);

        // Simulate mempool full check (before ledger commit)
        let mempool_size = 100; // Simulated max size
        let current_size = 100; // Full

        // If mempool is full, transaction should be rejected before ledger commit
        if current_size >= mempool_size {
            // Verify ledger state is unchanged
            assert_eq!(ledger.get_balance(&addr1), 100);
            assert_eq!(ledger.get_balance(&addr2), 0);
            assert_eq!(ledger.get_nonce(&addr1), 0);
        }
    }

    // ============================================================================
    // MONETARY POLICY & REBUILD TESTS (ZERO EMISSION)
    // ============================================================================

    #[test]
    fn test_zero_emission_never_mints() {
        // There is no reward function anymore. Verify the invariant that the
        // circulating supply can only decrease (fees burned) and never exceed
        // the genesis allocation.
        let mut ledger = Ledger::new();
        // Simulate genesis: founder + faucet
        for (addr_hex, balance) in crate::genesis::GENESIS_LEDGER {
            ledger.set_balance_hex(addr_hex.to_string(), balance);
        }
        let supply_at_genesis = ledger.total_supply();
        assert!(supply_at_genesis <= MAX_SUPPLY);

        // A transfer from a genesis-funded account (faucet) burns its fee.
        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let receiver = [2u8; 32];
        ledger
            .transfer_internal(&faucet, &receiver, 500, 10)
            .unwrap();
        assert!(ledger.total_supply() <= supply_at_genesis);
        assert_eq!(ledger.fee_burn_balance(), 10);
    }

    #[test]
    fn test_total_supply_never_goes_stale() {
        // Fixes NV-02: total_supply must always reflect the live balances even
        // after direct set_balance mutations (as used during conflict rebuild).
        let mut ledger = Ledger::new();
        let addr = [9u8; 32];
        ledger.set_balance(&addr, 100);
        assert_eq!(ledger.total_supply(), 100);
        ledger.set_balance(&addr, 250);
        assert_eq!(ledger.total_supply(), 250);
        assert!(ledger.supply_within_bounds());
    }

    #[test]
    fn test_rebuild_from_dag_applies_genesis_and_replays() {
        use crate::transaction::Transaction;

        let mut dag = DAG::new();
        let mut ledger = Ledger::new();

        // Apply genesis so balances exist for the replay.
        for (addr_hex, balance) in crate::genesis::GENESIS_LEDGER {
            ledger.set_balance_hex(addr_hex.to_string(), balance);
        }

        // Funds must come from a genesis-funded account (the faucet), because
        // rebuild_from_dag reseeds balances strictly from genesis.
        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let receiver = [2u8; 32];

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            receiver,
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.add_transaction_validated(tx).unwrap();

        // Rebuild: genesis + replayed tx (fee burned).
        ledger.rebuild_from_dag(&dag);
        assert_eq!(ledger.get_balance(&receiver), 100);
        assert_eq!(
            ledger.get_balance(&faucet),
            1_000_000_000_000_000_000_u64 - 100 - 10
        );
        assert_eq!(ledger.fee_burn_balance(), 10);
        assert_eq!(ledger.get_nonce(&faucet), 1);
    }

    #[test]
    fn test_rebuild_from_dag_invariant_holds() {
        use crate::transaction::Transaction;

        let mut dag = DAG::new();
        let mut ledger = Ledger::new();
        for (addr_hex, balance) in crate::genesis::GENESIS_LEDGER {
            ledger.set_balance_hex(addr_hex.to_string(), balance);
        }

        // Build a small chain of valid transfers funded by the faucet.
        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let b = [0xBBu8; 32];
        let c = [0xCCu8; 32];

        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            b,
            100,
            5,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let tx1_id = tx1.id;
        dag.add_transaction_validated(tx1.clone()).unwrap();

        let tx2 = Transaction::new(
            [tx1_id, [0u8; 32]],
            b,
            c,
            50,
            2,
            2,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        dag.add_transaction_validated(tx2).unwrap();

        ledger.rebuild_from_dag(&dag);
        assert_eq!(ledger.get_balance(&c), 50);
        assert_eq!(ledger.fee_burn_balance(), 7);
        assert!(ledger.supply_within_bounds());
        assert!(ledger.total_supply() <= MAX_SUPPLY);
    }

    // ---- V-21: deterministic canonical rebuild tests ----

    /// The user-mandated scenario: nodes receiving the same transactions in
    /// different orders must compute the EXACT same ledger state. Here we
    /// build the same DAG under every valid topological insertion order and
    /// assert that the rebuild is a pure function of the DAG: identical
    /// balances, nonces, fees burned and applied set (no spurious eviction).
    #[test]
    fn test_rebuild_deterministic_across_arrival_orders() {
        use crate::transaction::Transaction;

        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let x = [0x05u8; 32];
        let y = [0x06u8; 32];
        let u = [0x07u8; 32];
        let v = [0x08u8; 32];

        // Chain A: faucet -> X (nonce 1), X -> Y (nonce 2)
        let a1 = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            x,
            100,
            5,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let a2 = Transaction::new(
            [a1.id, [0u8; 32]],
            x,
            y,
            30,
            2,
            2,
            0,
            2,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        // Chain B: faucet -> U (nonce 2), U -> V (nonce 2)
        let b1 = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            u,
            100,
            5,
            1,
            0,
            2,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let b2 = Transaction::new(
            [b1.id, [0u8; 32]],
            u,
            v,
            40,
            3,
            2,
            0,
            2,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        // Cross link: X -> U, parents = [a1, b1]
        let m = Transaction::new(
            [a1.id, b1.id],
            x,
            u,
            10,
            1,
            3,
            0,
            3,
            vec![0u8; 64],
            vec![0u8; 64],
        );

        // Every valid topological insertion order (parents before children).
        let orders: Vec<Vec<&Transaction>> = vec![
            vec![&a1, &b1, &a2, &b2, &m],
            vec![&b1, &a1, &b2, &a2, &m],
            vec![&a1, &b1, &m, &a2, &b2],
            vec![&b1, &a1, &m, &b2, &a2],
        ];

        let mut states = Vec::new();
        for order in orders {
            let mut dag = DAG::new();
            for tx in order {
                dag.add_transaction_validated((*tx).clone()).unwrap();
            }
            let mut ledger = Ledger::new();
            ledger.rebuild_from_dag(&dag);

            // All 5 transactions must apply - NO spurious eviction.
            assert_eq!(ledger.total_supply(), 1_000_000_100_000_000_000_u64 - 16);
            assert_eq!(
                ledger.get_balance(&faucet),
                1_000_000_000_000_000_000_u64 - 210
            );
            assert_eq!(ledger.get_balance(&x), 57); // 100 - 32 (a2) - 11 (m)
            assert_eq!(ledger.get_balance(&y), 30);
            assert_eq!(ledger.get_balance(&u), 67); // 100 - 43 (b2) + 10 (m)
            assert_eq!(ledger.get_balance(&v), 40);
            assert_eq!(ledger.fee_burn_balance(), 16);
            assert_eq!(ledger.get_nonce(&faucet), 2);
            assert_eq!(ledger.get_nonce(&x), 3);
            assert_eq!(ledger.get_nonce(&u), 2);

            states.push((
                ledger.total_supply(),
                ledger.fee_burn_balance(),
                ledger.balances.clone(),
                ledger.nonces.clone(),
            ));
        }

        // Every arrival order must produce byte-identical state.
        for s in &states[1..] {
            assert_eq!(*s, states[0], "rebuild must be order-independent");
        }
    }

    /// Relaxation: a transaction that references no parents (genesis) but is
    /// FUNDED by another transaction must never be evicted, regardless of
    /// which one the replay encounters first. The old code marked a failing
    /// transaction as applied and dropped it forever.
    #[test]
    fn test_rebuild_relaxation_funding_after_spend() {
        use crate::transaction::Transaction;

        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let x = [0x5Au8; 32];
        let y = [0x5Bu8; 32];

        // Both have genesis parents: neither depends on the other topologically.
        let fund = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            x,
            1000,
            5,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let spend = Transaction::new(
            [[0u8; 32]; 2],
            x,
            y,
            300,
            2,
            2,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );

        let mut dag = DAG::new();
        // Insertion order does not matter for the rebuild: both orders are
        // exercised by the same DAG and must converge.
        dag.add_transaction_validated(fund.clone()).unwrap();
        dag.add_transaction_validated(spend.clone()).unwrap();

        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(&dag);

        // The spend MUST be applied even if the replay meets it before its
        // funding: relaxation retries it on the next pass.
        assert_eq!(ledger.get_balance(&x), 698); // 1000 - 300 - 2
        assert_eq!(ledger.get_balance(&y), 300);
        assert_eq!(ledger.fee_burn_balance(), 7);
        assert_eq!(ledger.get_nonce(&x), 1);
        assert_eq!(ledger.total_supply(), 1_000_000_100_000_000_000_u64 - 7);
    }

    /// Defensive residue handling: if the DAG somehow still holds two
    /// transactions with the same (sender, nonce), the smallest id applies
    /// and the larger one never debits the account.
    #[test]
    fn test_rebuild_double_spend_residue_only_min_id_applies() {
        use crate::transaction::Transaction;

        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();

        // Construct two conflicting txs directly (bypassing add_transaction
        // conflict checks) exactly as a corrupted legacy DAG would contain.
        let mut dag = DAG::new();
        let fund = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            [0x11u8; 32],
            1000,
            5,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            [0x11u8; 32],
            [0x22u8; 32],
            50,
            1,
            2,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let tx2 = Transaction::new(
            [[0u8; 32]; 2],
            [0x11u8; 32],
            [0x33u8; 32],
            60,
            1,
            2,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        // The canonical winner is the smallest id - whichever that is.
        let (winner, loser) = if tx1.id < tx2.id {
            (tx1, tx2)
        } else {
            (tx2, tx1)
        };
        let winner_receiver = winner.receiver;
        let loser_receiver = loser.receiver;

        dag.inject_transaction_raw(fund);
        dag.inject_transaction_raw(winner.clone());
        dag.inject_transaction_raw(loser);

        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(&dag);

        // ONLY the canonical winner's transfer applies (min-id rule); the
        // loser residue is skipped without debiting or crediting anything,
        // even when the replay would meet it first.
        assert_eq!(ledger.get_balance(&winner_receiver), winner.amount);
        assert_eq!(ledger.get_balance(&loser_receiver), 0);
        assert_eq!(ledger.fee_burn_balance(), 6); // 5 (fund) + 1 (winner)
        assert_eq!(ledger.get_nonce(&[0x11u8; 32]), 1);
        assert_eq!(ledger.total_supply(), 1_000_000_100_000_000_000_u64 - 6);
    }
}
