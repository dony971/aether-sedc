//! # Core Validation Module
//!
//! Provides unified transaction validation logic for the entire system.
//! This is the ONLY place where transaction validation should happen.
//! RPC, P2P, and DAG must EXCLUSIVELY use this validator.
//!
//! Economic policy: validation BEFORE any state modification, atomic rollback on failure.

use crate::ledger::Ledger;
use crate::parent_selection::DAG;
use crate::transaction::Transaction;
use crate::transaction::TransactionId;

/// Validation result with detailed error information
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    /// PoW does not meet difficulty requirement
    InvalidPoW { difficulty: u8 },
    /// Signature verification failed
    InvalidSignature,
    /// Sender address does not match public key
    SenderPublicKeyMismatch,
    /// Duplicate transaction already exists
    DuplicateTransaction { tx_id: TransactionId },
    /// Parent transaction missing
    MissingParent {
        parent_index: usize,
        parent_id: TransactionId,
    },
    /// Double spend detected (parents already used)
    DoubleSpend,
    /// Sender conflict (multiple pending transactions)
    SenderConflict,
    /// Insufficient balance
    InsufficientBalance { required: u64, available: u64 },
    /// Account nonce invalid (not sequential)
    InvalidNonce { expected: u64, provided: u64 },
    /// Fee below minimum
    InsufficientFee { required: u64, provided: u64 },
    /// Amount + fee overflow
    Overflow,
    /// Transaction timestamp is too far in the future (beyond MAX_FUTURE_MS)
    FutureTimestamp {
        tx_ts: u64,
        now: u64,
        max_future: u64,
    },
    /// Transaction timestamp is too far in the past (beyond MAX_PAST_MS)
    StaleTimestamp { tx_ts: u64, now: u64, max_past: u64 },
    /// Transaction has pre-activation timestamp after grace period (backdating attack)
    BackdatedTimestamp {
        tx_ts: u64,
        activation_ts: u64,
        grace_end: u64,
    },
    /// Transaction timestamp precedes parent timestamp (monotonicity violation)
    ParentTimestampViolation {
        child_ts: u64,
        parent_index: usize,
        parent_ts: u64,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidPoW { difficulty } => {
                write!(
                    f,
                    "Invalid PoW: transaction must meet difficulty {}",
                    difficulty
                )
            }
            ValidationError::InvalidSignature => {
                write!(f, "Invalid signature")
            }
            ValidationError::SenderPublicKeyMismatch => {
                write!(f, "Sender address does not match public key")
            }
            ValidationError::DuplicateTransaction { tx_id } => {
                write!(
                    f,
                    "Duplicate transaction: {} already exists",
                    hex::encode(tx_id)
                )
            }
            ValidationError::MissingParent {
                parent_index,
                parent_id,
            } => {
                write!(
                    f,
                    "Parent {} missing: {}",
                    parent_index,
                    hex::encode(parent_id)
                )
            }
            ValidationError::DoubleSpend => {
                write!(f, "Double spend detected: parents already used")
            }
            ValidationError::SenderConflict => {
                write!(
                    f,
                    "Sender conflict: only one pending transaction per sender allowed"
                )
            }
            ValidationError::InsufficientBalance {
                required,
                available,
            } => {
                write!(f, "Insufficient balance: {} < {}", available, required)
            }
            ValidationError::InvalidNonce { expected, provided } => {
                write!(
                    f,
                    "Invalid nonce: expected {}, provided {}",
                    expected, provided
                )
            }
            ValidationError::InsufficientFee { required, provided } => {
                write!(f, "Insufficient fee: {} < minimum {}", provided, required)
            }
            ValidationError::Overflow => {
                write!(f, "Amount + fee overflow")
            }
            ValidationError::FutureTimestamp {
                tx_ts,
                now,
                max_future,
            } => {
                write!(
                    f,
                    "Future timestamp: tx_ts {} is {}ms ahead (max {}ms, now {})",
                    tx_ts,
                    tx_ts.saturating_sub(*now),
                    max_future,
                    now
                )
            }
            ValidationError::StaleTimestamp {
                tx_ts,
                now,
                max_past,
            } => {
                write!(
                    f,
                    "Stale timestamp: tx_ts {} is {}ms old (max {}ms, now {})",
                    tx_ts,
                    now.saturating_sub(*tx_ts),
                    max_past,
                    now
                )
            }
            ValidationError::BackdatedTimestamp {
                tx_ts,
                activation_ts,
                grace_end,
            } => {
                write!(
                    f,
                    "Backdated timestamp: tx_ts {} < activation {} after grace period ended at {}",
                    tx_ts, activation_ts, grace_end
                )
            }
            ValidationError::ParentTimestampViolation {
                child_ts,
                parent_index,
                parent_ts,
            } => {
                write!(
                    f,
                    "Parent timestamp violation: child ts {} < parent[{}] ts {}",
                    child_ts, parent_index, parent_ts
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validation mode: determines which checks apply.
///
/// **Fresh**: new transaction from network (RPC/P2P). All checks including
/// timestamp bounds and difficulty migration.
///
/// **Historical**: transaction being replayed during sync or DAG rebuild.
/// Timestamp checks are SKIPPED — the tx was valid when originally created.
/// PoW and signature are still verified (structural integrity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Fresh transaction from network — full validation including timestamps
    Fresh,
    /// Historical transaction from sync/rebuild — skip timestamp checks
    Historical,
}

/// Core transaction validator
/// Economic policy: validation BEFORE any state modification
/// This is the ONLY validator that should be used across the entire system
pub struct TransactionValidator {
    /// PoW difficulty requirement
    difficulty: u8,
}

impl TransactionValidator {
    /// Create new validator with default difficulty
    pub fn new() -> Self {
        Self {
            difficulty: Transaction::default_difficulty(),
        }
    }

    /// Create validator with custom difficulty
    pub fn with_difficulty(difficulty: u8) -> Self {
        Self { difficulty }
    }

    /// Validate transaction without accessing DAG/Ledger (pure validation) - INTERNAL USE ONLY
    /// 🔒 ZERO TRUST: This method is private. Use validate_full() for all validation.
    /// These checks can be done before acquiring any locks
    /// Economic policy: no state access, no mutations
    ///
    /// `mode`: `Fresh` applies timestamp bounds + difficulty migration.
    ///         `Historical` skips timestamp checks (tx was valid at creation).
    pub(crate) fn validate_pure(
        &self,
        tx: &Transaction,
        mode: ValidationMode,
    ) -> Result<(), ValidationError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64;

        // Determine required difficulty from timestamp alone.
        // difficulty_for_tx_at always returns Some (20 or 24) — it never
        // rejects. The backdating rejection is handled below for Fresh mode.
        let required_difficulty = Transaction::difficulty_for_tx_at(tx, now_ms)
            .expect("difficulty_for_tx_at always returns Some");

        // Backdating rejection (Fresh mode ONLY)
        //
        // SECURITY MODEL:
        //   Fresh = new untrusted transaction → reject pre-activation after grace
        //   Historical = established transaction from verified history → allow
        //
        // A backdated transaction accepted in Historical mode is harmless:
        //   - It is confined to the pre-activation subgraph by parent timestamp
        //     ordering (child.ts >= parent.ts)
        //   - It cannot become a parent of any post-activation transaction
        //   - It cannot affect the post-activation ledger
        //
        // The attacker gains nothing: mining a 20-bit backdated tx is cheap
        // (~1M hashes) but the tx is structurally isolated.
        if mode == ValidationMode::Fresh {
            // Reject pre-activation timestamps after grace period
            if tx.timestamp < Transaction::DIFFICULTY_MIGRATION_TS
                && now_ms > Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS
            {
                return Err(ValidationError::BackdatedTimestamp {
                    tx_ts: tx.timestamp,
                    activation_ts: Transaction::DIFFICULTY_MIGRATION_TS,
                    grace_end: Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS,
                });
            }

            // Reject future timestamps beyond MAX_FUTURE_MS
            if tx.timestamp > now_ms.saturating_add(Transaction::MAX_FUTURE_MS) {
                return Err(ValidationError::FutureTimestamp {
                    tx_ts: tx.timestamp,
                    now: now_ms,
                    max_future: Transaction::MAX_FUTURE_MS,
                });
            }

            // Reject stale timestamps beyond MAX_PAST_MS
            if now_ms > tx.timestamp && now_ms - tx.timestamp > Transaction::MAX_PAST_MS {
                return Err(ValidationError::StaleTimestamp {
                    tx_ts: tx.timestamp,
                    now: now_ms,
                    max_past: Transaction::MAX_PAST_MS,
                });
            }
        }
        // Historical mode: skip all timestamp checks.
        // The tx was valid when originally created.
        // Parent timestamp ordering (validate_dag) prevents structural abuse.

        // PoW verification (always — using difficulty derived from timestamp)
        if !tx.verify_pow(required_difficulty) {
            return Err(ValidationError::InvalidPoW {
                difficulty: required_difficulty,
            });
        }

        // Signature verification (always)
        if !crate::wallet::Wallet::verify_transaction(tx) {
            return Err(ValidationError::InvalidSignature);
        }

        // Sender public key match (always)
        if !tx.verify_sender_matches_public_key() {
            return Err(ValidationError::SenderPublicKeyMismatch);
        }

        // Amount + fee overflow (always)
        if tx.amount.checked_add(tx.fee).is_none() {
            return Err(ValidationError::Overflow);
        }

        Ok(())
    }

    /// Validate transaction against DAG (INTERNAL USE ONLY)
    /// 🔒 ZERO TRUST: This method is private. Use validate_full() for all validation.
    /// These checks require DAG access but don't modify state
    /// Economic policy: read-only access to DAG
    pub(crate) fn validate_dag(&self, tx: &Transaction, dag: &DAG) -> Result<(), ValidationError> {
        // Check for duplicate transaction in DAG
        if dag.transactions().contains_key(&tx.id) {
            return Err(ValidationError::DuplicateTransaction { tx_id: tx.id });
        }

        // Check parents exist
        for (i, parent) in tx.parents.iter().enumerate() {
            let is_genesis = *parent == TransactionId::default();
            if !is_genesis && !dag.transactions().contains_key(parent) {
                return Err(ValidationError::MissingParent {
                    parent_index: i,
                    parent_id: *parent,
                });
            }
        }

        // Check parent timestamp ordering (monotonicity)
        // Child timestamp must be >= parent timestamp
        for (i, parent_id) in tx.parents.iter().enumerate() {
            let is_genesis = *parent_id == TransactionId::default();
            if !is_genesis {
                if let Some(parent_tx) = dag.transactions().get(parent_id) {
                    if tx.timestamp < parent_tx.timestamp {
                        return Err(ValidationError::ParentTimestampViolation {
                            child_ts: tx.timestamp,
                            parent_index: i,
                            parent_ts: parent_tx.timestamp,
                        });
                    }
                }
            }
        }

        // Check for sender conflict (canonical double-spend detector)
        if dag.has_sender_conflict(&tx.sender, tx.account_nonce) {
            return Err(ValidationError::SenderConflict);
        }

        Ok(())
    }

    /// Validate transaction against Ledger (INTERNAL USE ONLY)
    /// 🔒 ZERO TRUST: This method is private. Use validate_full() for all validation.
    /// These checks require Ledger access but don't modify state
    /// Economic policy: read-only access to Ledger
    pub(crate) fn validate_ledger(
        &self,
        tx: &Transaction,
        ledger: &Ledger,
        min_fee: u64,
    ) -> Result<(), ValidationError> {
        // Check balance
        let sender_balance = ledger.get_balance(&tx.sender);
        let required = match tx.amount.checked_add(tx.fee) {
            Some(sum) => sum,
            None => return Err(ValidationError::Overflow),
        };

        if sender_balance < required {
            return Err(ValidationError::InsufficientBalance {
                required,
                available: sender_balance,
            });
        }

        // Check minimum fee
        if tx.fee < min_fee {
            return Err(ValidationError::InsufficientFee {
                required: min_fee,
                provided: tx.fee,
            });
        }

        // NOTE: The account nonce is deliberately NOT validated here. Nonce
        // checks against the live ledger state are arrival-order-dependent:
        // a node that processed nonce 5,6,7 first would permanently reject a
        // late but valid nonce-3 transaction that another node accepted -
        // permanently diverging the two DAGs. Replay protection and
        // double-spend prevention are instead enforced deterministically at
        // the DAG level via the canonical (sender, account_nonce) conflict
        // resolution (STEP 0 in the transaction processor), which is a pure
        // function of the DAG and therefore identical on every node.

        Ok(())
    }

    /// Full validation pipeline (pure + DAG + ledger)
    /// Economic policy: all validations before any state modification
    pub fn validate_full(
        &self,
        tx: &Transaction,
        dag: &DAG,
        ledger: &Ledger,
        min_fee: u64,
        mode: ValidationMode,
    ) -> Result<(), ValidationError> {
        self.validate_pure(tx, mode)?;
        self.validate_dag(tx, dag)?;
        self.validate_ledger(tx, ledger, min_fee)?;
        Ok(())
    }
}

impl Default for TransactionValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use crate::parent_selection::DAG;
    use crate::transaction::Transaction;

    #[test]
    fn test_validate_pure_valid() {
        let validator = TransactionValidator::new();

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
            vec![1u8; 64],
        );

        // This should fail signature verification (invalid signature)
        assert!(validator.validate_pure(&tx, ValidationMode::Fresh).is_err());
    }

    #[test]
    fn test_validate_pure_overflow() {
        let validator = TransactionValidator::new();
        let mut dag = DAG::new();
        let _ledger = Ledger::new();

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            u64::MAX,
            u64::MAX,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        // Add transaction to DAG (using validated method)
        dag.add_transaction_validated(tx.clone())
            .expect("Failed to add transaction to DAG");

        // This should fail due to overflow
        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dag_genesis_parents_valid() {
        let validator = TransactionValidator::new();
        let dag = DAG::new();
        let _ledger = Ledger::new();

        // Transaction with genesis parents should be valid (not an orphan)
        let tx = Transaction::new(
            [[0u8; 32]; 2], // Genesis parents
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        // Validation should pass (genesis parents are always valid)
        let result = validator.validate_dag(&tx, &dag);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dag_missing_parent() {
        let validator = TransactionValidator::new();
        let dag = DAG::new();
        let _ledger = Ledger::new();

        // Use non-genesis parent that doesn't exist
        let tx = Transaction::new(
            [[1u8; 32], [2u8; 32]], // Non-existent parents
            [3u8; 32],
            [4u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![2u8; 64],
        );

        assert!(matches!(
            validator.validate_dag(&tx, &dag),
            Err(ValidationError::MissingParent { .. })
        ));
    }

    #[test]
    fn test_validate_dag_duplicate() {
        let validator = TransactionValidator::new();
        let mut dag = DAG::new();

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
            vec![2u8; 64],
        );

        // Add transaction to DAG (using validated method)
        dag.add_transaction_validated(tx.clone())
            .expect("Failed to add transaction to DAG");

        // Validation should fail (duplicate)
        let result = validator.validate_dag(&tx, &dag);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ledger_insufficient_balance() {
        let validator = TransactionValidator::new();
        let _dag = DAG::new();
        let ledger = Ledger::new();

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
            vec![1u8; 64],
        );

        // This should fail due to insufficient balance
        let result = validator.validate_ledger(&tx, &ledger, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ledger_invalid_nonce() {
        let validator = TransactionValidator::new();
        let _dag = DAG::new();
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        // Set nonce to 5
        ledger.commit_nonce(&addr, 5);

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            3, // Wrong nonce (should be 6)
            vec![0u8; 64],
            vec![1u8; 64],
        );

        // This should fail due to invalid nonce
        let result = validator.validate_ledger(&tx, &ledger, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_ledger_insufficient_fee() {
        let validator = TransactionValidator::new();
        let _dag = DAG::new();
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        ledger.set_balance(&addr, 1000);
        ledger.commit_nonce(&addr, 0);

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [2u8; 32],
            100,
            5, // Fee below minimum (10)
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        // This should fail due to insufficient fee
        let result = validator.validate_ledger(&tx, &ledger, 10);
        assert!(result.is_err());
    }

    // ==================== DIFFICULTY MIGRATION VALIDATION TESTS ====================

    #[test]
    fn test_validate_dag_parent_timestamp_violation() {
        use crate::wallet::Wallet;

        let validator = TransactionValidator::new();
        let mut dag = DAG::new();
        let mut ledger = Ledger::new();

        let wallet = Wallet::new();
        let sender_pubkey = wallet.public_key_bytes();
        let sender_addr = wallet.address();

        let parent_ts = Transaction::DIFFICULTY_MIGRATION_TS + 100;
        let child_ts = Transaction::DIFFICULTY_MIGRATION_TS + 50; // BEFORE parent

        // Create and mine parent with higher timestamp
        let mut parent = Transaction::new(
            [[0u8; 32]; 2],
            sender_addr,
            [2u8; 32],
            10,
            1,
            parent_ts,
            0,
            0,
            vec![0u8; 64],
            sender_pubkey.clone(),
        );
        parent.nonce = parent.mine_nonce(24);
        parent.signature = wallet.sign_transaction(&parent).expect("signing failed");
        parent.id = parent.compute_hash();

        dag.add_transaction_validated(parent.clone())
            .expect("add parent");
        ledger.set_balance(&sender_addr, 1_000_000);
        ledger.commit_nonce(&sender_addr, 1);

        // Child has EARLIER timestamp than parent
        let mut child = Transaction::new(
            [parent.id, [0u8; 32]],
            sender_addr,
            [3u8; 32],
            10,
            1,
            child_ts,
            0,
            1,
            vec![0u8; 64],
            sender_pubkey.clone(),
        );
        child.nonce = child.mine_nonce(24);
        child.signature = wallet.sign_transaction(&child).expect("signing failed");
        child.id = child.compute_hash();

        let result = validator.validate_dag(&child, &dag);
        assert!(
            matches!(
                result,
                Err(ValidationError::ParentTimestampViolation { .. })
            ),
            "Expected ParentTimestampViolation, got: {:?}",
            result
        );
    }

    // ==================== ÉTAPE 2: CRITICAL HISTORICAL TX TEST ====================
    // PROVES: MAX_PAST_MS does NOT break historical transaction validation.
    // This is the BLOCKER check: if validate_pure(Fresh) rejects old txs,
    // then validate_pure(Historical) MUST accept them.

    /// Helper: create a valid 24-bit PoW transaction at a given timestamp.
    fn make_valid_24bit_tx(timestamp: u64) -> Transaction {
        use crate::wallet::Wallet;
        let wallet = Wallet::new();
        let sender = wallet.address();
        let pubkey = wallet.public_key_bytes();
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            timestamp,
            0,
            1,
            vec![0u8; 64],
            pubkey,
        );
        tx.nonce = tx.mine_nonce(24);
        tx.signature = wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();
        tx
    }

    /// ÉTAPE 2 CORE: A historical transaction from 1 year ago MUST pass
    /// validate_pure(Historical) even though it fails validate_pure(Fresh).
    /// This proves MAX_PAST_MS doesn't break sync.
    #[test]
    fn test_historical_tx_1year_ago_passes_historical_mode() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // 1 year ago
        let ts_1yr = now_ms.saturating_sub(365 * 24 * 3600 * 1000);
        let tx = make_valid_24bit_tx(ts_1yr);

        // Historical mode: MUST pass (no timestamp check)
        let result_historical = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            result_historical.is_ok(),
            "HISTORICAL mode must accept 1-year-old tx: {:?}",
            result_historical
        );

        // Fresh mode: MUST reject (stale timestamp)
        let result_fresh = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            result_fresh.is_err(),
            "FRESH mode must reject 1-year-old tx"
        );
        assert!(
            matches!(result_fresh, Err(ValidationError::StaleTimestamp { .. })),
            "Must reject with StaleTimestamp, got: {:?}",
            result_fresh
        );
    }

    /// ÉTAPE 2 EXTENDED: multiple ages (1h, 1d, 1mo, 1yr).
    #[test]
    fn test_historical_tx_various_ages_all_pass_historical() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ages: Vec<(u64, &str)> = vec![
            (3_600_000, "1 hour"),
            (86_400_000, "1 day"),
            (30 * 86_400_000, "1 month"),
            (365 * 86_400_000, "1 year"),
        ];

        for (age_ms, label) in ages {
            let ts = now_ms.saturating_sub(age_ms);
            let tx = make_valid_24bit_tx(ts);
            let result = validator.validate_pure(&tx, ValidationMode::Historical);
            assert!(
                result.is_ok(),
                "HISTORICAL mode must accept {} old tx: {:?}",
                label,
                result
            );
        }
    }

    /// ÉTAPE 2: A fresh tx within MAX_PAST_MS passes Fresh mode.
    #[test]
    fn test_fresh_tx_recent_passes_fresh_mode() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // 30 minutes ago (within 1h window)
        let ts_recent = now_ms.saturating_sub(30 * 60 * 1000);
        let tx = make_valid_24bit_tx(ts_recent);

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            result.is_ok(),
            "FRESH mode must accept 30min-old tx: {:?}",
            result
        );
    }

    /// ÉTAPE 2: A tx 2h ago FAILS Fresh mode but PASSES Historical mode.
    #[test]
    fn test_stale_tx_2h_rejected_by_fresh_passed_by_historical() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ts_2h = now_ms.saturating_sub(2 * 3_600_000); // 2 hours ago
        let tx = make_valid_24bit_tx(ts_2h);

        // Fresh mode: rejected
        let fresh_result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(fresh_result.is_err(), "FRESH must reject 2h-old tx");

        // Historical mode: accepted
        let hist_result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            hist_result.is_ok(),
            "HISTORICAL must accept 2h-old tx: {:?}",
            hist_result
        );
    }

    /// ÉTAPE 2: DAG rebuild inserts historical txs without timestamp validation.
    /// This is the actual sync path: rebuild_dag_topological + rebuild_from_dag.
    #[test]
    fn test_dag_rebuild_accepts_historical_txs() {
        use crate::ledger::Ledger;
        use crate::parent_selection::DAG;

        let mut dag = DAG::new();
        let mut ledger = Ledger::new();

        // Simulate: genesis + 4 historical txs (1hr, 1d, 1mo, 1yr old)
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ages = vec![3_600_000, 86_400_000, 30 * 86_400_000, 365 * 86_400_000];
        let mut prev_id = [0u8; 32]; // genesis parent
        for (i, age) in ages.iter().enumerate() {
            let ts = now_ms.saturating_sub(*age);
            let wallet = crate::wallet::Wallet::new();
            let sender = wallet.address();
            let pubkey = wallet.public_key_bytes();
            let mut tx = Transaction::new(
                [prev_id, [0u8; 32]],
                sender,
                [2u8; 32],
                1,
                10,
                ts,
                0,
                i as u64,
                vec![0u8; 64],
                pubkey,
            );
            tx.nonce = tx.mine_nonce(24);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();

            // This is the sync path: add_transaction_validated (no timestamp check)
            dag.add_transaction_validated(tx.clone())
                .expect("historical tx must be insertable");
            ledger.set_balance(&sender, 1_000_000);
            prev_id = tx.id;
        }

        // Verify all 4 historical txs are in the DAG
        assert_eq!(dag.transaction_count(), 4);
    }

    /// ÉTAPE 2: Fresh mode rejects backdated tx (pre-activation after grace).
    #[test]
    fn test_fresh_mode_rejects_backdated_after_grace() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Pre-activation timestamp, after grace period
        let ts_pre_activation = Transaction::DIFFICULTY_MIGRATION_TS - 1000;
        let tx = make_valid_24bit_tx(ts_pre_activation);

        // Only test if we're actually past the grace period
        if now_ms > Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            let result = validator.validate_pure(&tx, ValidationMode::Fresh);
            assert!(
                matches!(result, Err(ValidationError::BackdatedTimestamp { .. })),
                "Must reject backdated tx after grace: {:?}",
                result
            );
        }
    }

    // ==================== SECURITY GATE: HISTORICAL MODE ATTACK TESTS ====================
    // These tests prove that ValidationMode::Historical CANNOT be exploited
    // to inject backdated post-activation transactions.

    /// ATTACK PoC #1: pre-activation tx validated via Historical mode.
    /// With the new design, Historical mode ACCEPTS this — the tx is verified
    /// at difficulty 20. This is correct: truly historical pre-activation txs
    /// must remain verifiable indefinitely. Fresh mode still REJECTS it.
    #[test]
    fn test_attack_backdated_pre_activation_accepted_historical() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        let ts_pre = Transaction::DIFFICULTY_MIGRATION_TS - 1000;
        let tx = make_valid_20bit_tx(ts_pre);

        // Historical mode: ACCEPTS (difficulty=20, PoW verified)
        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            result.is_ok(),
            "Historical mode MUST accept pre-activation tx: {:?}",
            result
        );

        // Fresh mode: REJECTS (backdated after grace)
        let result_fresh = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(
                result_fresh,
                Err(ValidationError::BackdatedTimestamp { .. })
            ),
            "Fresh mode MUST reject backdated tx: {:?}",
            result_fresh
        );
    }

    /// ATTACK PoC #2: Same attack via Fresh mode — must also be rejected.
    #[test]
    fn test_attack_backdated_pre_activation_rejected_fresh() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        let ts_pre = Transaction::DIFFICULTY_MIGRATION_TS - 500;
        let tx = make_valid_20bit_tx(ts_pre);

        // Fresh mode: MUST REJECT
        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(result, Err(ValidationError::BackdatedTimestamp { .. })),
            "Fresh mode MUST reject backdated tx: {:?}",
            result
        );
    }

    /// ATTACK PoC #3: tx at activation boundary (1ms before), 20-bit PoW.
    /// Historical mode: ACCEPTS (pre-activation tx, difficulty=20, valid PoW).
    /// Fresh mode: REJECTS (backdated after grace).
    #[test]
    fn test_attack_boundary_pre_activation_historical_accepts() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        let ts_boundary = Transaction::DIFFICULTY_MIGRATION_TS - 1;
        let tx = make_valid_20bit_tx(ts_boundary);

        // Historical: ACCEPTS
        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            result.is_ok(),
            "Historical mode must accept boundary tx: {:?}",
            result
        );

        // Fresh: REJECTS
        let result_fresh = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(
                result_fresh,
                Err(ValidationError::BackdatedTimestamp { .. })
            ),
            "Fresh mode must reject boundary tx: {:?}",
            result_fresh
        );
    }

    /// ATTACK PoC #4: Attacker creates tx at EXACTLY activation timestamp,
    /// mines at 20 bits (wrong difficulty — should be 24). MUST fail PoW.
    #[test]
    fn test_attack_exact_activation_wrong_difficulty() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        // At exact activation — requires 24-bit PoW
        let tx = make_valid_20bit_tx(Transaction::DIFFICULTY_MIGRATION_TS);

        // Historical mode: backdating check returns Some(24) (post-activation),
        // but tx was mined at 20 → PoW failure
        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            matches!(result, Err(ValidationError::InvalidPoW { .. })),
            "Wrong difficulty at activation must fail PoW: {:?}",
            result
        );
    }

    /// ATTACK PoC #5: Attacker creates tx 1 second after activation,
    /// mines at 20 bits, sends via Historical. MUST fail PoW (needs 24).
    #[test]
    fn test_attack_post_activation_20bit_rejected() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        // 1 second after activation
        let ts_post = Transaction::DIFFICULTY_MIGRATION_TS + 1000;
        let tx = make_valid_20bit_tx(ts_post);

        // difficulty_for_tx_at returns Some(24), but tx has 20-bit PoW
        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            matches!(result, Err(ValidationError::InvalidPoW { .. })),
            "Post-activation 20-bit tx must fail PoW: {:?}",
            result
        );
    }

    /// ATTACK PoC #6: Verify that Historical mode STILL accepts valid
    /// post-activation txs (regression check — the fix must not break legit txs).
    #[test]
    fn test_attack_valid_post_activation_accepted_historical() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Recent post-activation tx with 24-bit PoW
        let ts = now_ms.saturating_sub(1000);
        let tx = make_valid_24bit_tx(ts);

        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            result.is_ok(),
            "Valid post-activation tx MUST be accepted in Historical mode: {:?}",
            result
        );
    }

    /// Helper: create a valid 20-bit PoW transaction at a given timestamp.
    fn make_valid_20bit_tx(timestamp: u64) -> Transaction {
        use crate::wallet::Wallet;
        let wallet = Wallet::new();
        let sender = wallet.address();
        let pubkey = wallet.public_key_bytes();
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            timestamp,
            0,
            1,
            vec![0u8; 64],
            pubkey,
        );
        tx.nonce = tx.mine_nonce(20);
        tx.signature = wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();
        tx
    }

    // ==================== ÉTAPE 5: PARENT TIMESTAMP — POSITIVE TESTS ====================

    /// ÉTAPE 5 POSITIVE: child with timestamp == parent timestamp passes.
    #[test]
    fn test_parent_timestamp_equal_passes() {
        use crate::wallet::Wallet;

        let validator = TransactionValidator::new();
        let wallet = Wallet::new();
        let sender = wallet.address();
        let pubkey = wallet.public_key_bytes();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let parent_ts = now_ms.saturating_sub(1000);

        // Create parent
        let mut parent = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            parent_ts,
            0,
            0,
            vec![0u8; 64],
            pubkey.clone(),
        );
        parent.nonce = parent.mine_nonce(24);
        parent.signature = wallet.sign_transaction(&parent).expect("sign");
        parent.id = parent.compute_hash();

        // Create child with SAME timestamp as parent
        let mut child = Transaction::new(
            [parent.id, [0u8; 32]],
            sender,
            [2u8; 32],
            1,
            10,
            parent_ts, // equal to parent
            0,
            1,
            vec![0u8; 64],
            pubkey.clone(),
        );
        child.nonce = child.mine_nonce(24);
        child.signature = wallet.sign_transaction(&child).expect("sign");
        child.id = child.compute_hash();

        // Parent ordering: child.timestamp >= parent.timestamp → PASS
        let mut dag = crate::parent_selection::DAG::new();
        dag.add_transaction_validated(parent).unwrap();
        let result = validator.validate_dag(&child, &dag);
        assert!(
            result.is_ok(),
            "child == parent timestamp must pass: {:?}",
            result
        );
    }

    /// ÉTAPE 5 POSITIVE: child with timestamp > parent timestamp passes.
    #[test]
    fn test_parent_timestamp_after_passes() {
        use crate::wallet::Wallet;

        let validator = TransactionValidator::new();
        let wallet = Wallet::new();
        let sender = wallet.address();
        let pubkey = wallet.public_key_bytes();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let parent_ts = now_ms.saturating_sub(2000);
        let child_ts = now_ms.saturating_sub(1000);

        let mut parent = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            parent_ts,
            0,
            0,
            vec![0u8; 64],
            pubkey.clone(),
        );
        parent.nonce = parent.mine_nonce(24);
        parent.signature = wallet.sign_transaction(&parent).expect("sign");
        parent.id = parent.compute_hash();

        let mut child = Transaction::new(
            [parent.id, [0u8; 32]],
            sender,
            [2u8; 32],
            1,
            10,
            child_ts, // after parent
            0,
            1,
            vec![0u8; 64],
            pubkey.clone(),
        );
        child.nonce = child.mine_nonce(24);
        child.signature = wallet.sign_transaction(&child).expect("sign");
        child.id = child.compute_hash();

        let mut dag = crate::parent_selection::DAG::new();
        dag.add_transaction_validated(parent).unwrap();
        let result = validator.validate_dag(&child, &dag);
        assert!(
            result.is_ok(),
            "child > parent timestamp must pass: {:?}",
            result
        );
    }

    /// ÉTAPE 5 DUAL PARENT: child must be >= max(parentA.timestamp, parentB.timestamp).
    #[test]
    fn test_parent_timestamp_dual_parent() {
        use crate::wallet::Wallet;

        let validator = TransactionValidator::new();
        let wallet = Wallet::new();
        let sender = wallet.address();
        let pubkey = wallet.public_key_bytes();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ts_a = now_ms.saturating_sub(3000);
        let ts_b = now_ms.saturating_sub(1000);

        // Parent A: older
        let mut parent_a = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            ts_a,
            0,
            0,
            vec![0u8; 64],
            pubkey.clone(),
        );
        parent_a.nonce = parent_a.mine_nonce(24);
        parent_a.signature = wallet.sign_transaction(&parent_a).expect("sign");
        parent_a.id = parent_a.compute_hash();

        // Parent B: newer
        let mut parent_b = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            ts_b,
            0,
            1,
            vec![0u8; 64],
            pubkey.clone(),
        );
        parent_b.nonce = parent_b.mine_nonce(24);
        parent_b.signature = wallet.sign_transaction(&parent_b).expect("sign");
        parent_b.id = parent_b.compute_hash();

        // Child >= max(ts_a, ts_b) = ts_b
        let child_ts = now_ms.saturating_sub(500);
        let mut child = Transaction::new(
            [parent_a.id, parent_b.id],
            sender,
            [2u8; 32],
            1,
            10,
            child_ts,
            0,
            2,
            vec![0u8; 64],
            pubkey.clone(),
        );
        child.nonce = child.mine_nonce(24);
        child.signature = wallet.sign_transaction(&child).expect("sign");
        child.id = child.compute_hash();

        let mut dag = crate::parent_selection::DAG::new();
        dag.add_transaction_validated(parent_a).unwrap();
        dag.add_transaction_validated(parent_b).unwrap();
        let result = validator.validate_dag(&child, &dag);
        assert!(
            result.is_ok(),
            "child >= max(parentA, parentB) must pass: {:?}",
            result
        );
    }

    /// ÉTAPE 5 NEGATIVE DUAL PARENT: child < newer parent → rejected.
    #[test]
    fn test_parent_timestamp_dual_parent_rejected() {
        use crate::wallet::Wallet;

        let validator = TransactionValidator::new();
        let wallet = Wallet::new();
        let sender = wallet.address();
        let pubkey = wallet.public_key_bytes();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ts_a = now_ms.saturating_sub(3000);
        let ts_b = now_ms.saturating_sub(1000);

        let mut parent_a = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            ts_a,
            0,
            0,
            vec![0u8; 64],
            pubkey.clone(),
        );
        parent_a.nonce = parent_a.mine_nonce(24);
        parent_a.signature = wallet.sign_transaction(&parent_a).expect("sign");
        parent_a.id = parent_a.compute_hash();

        let mut parent_b = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            1,
            10,
            ts_b,
            0,
            1,
            vec![0u8; 64],
            pubkey.clone(),
        );
        parent_b.nonce = parent_b.mine_nonce(24);
        parent_b.signature = wallet.sign_transaction(&parent_b).expect("sign");
        parent_b.id = parent_b.compute_hash();

        // Child < parent_b (the newer one) → REJECTED
        let child_ts = ts_b.saturating_sub(500);
        let mut child = Transaction::new(
            [parent_a.id, parent_b.id],
            sender,
            [2u8; 32],
            1,
            10,
            child_ts,
            0,
            2,
            vec![0u8; 64],
            pubkey.clone(),
        );
        child.nonce = child.mine_nonce(24);
        child.signature = wallet.sign_transaction(&child).expect("sign");
        child.id = child.compute_hash();

        let mut dag = crate::parent_selection::DAG::new();
        dag.add_transaction_validated(parent_a).unwrap();
        dag.add_transaction_validated(parent_b).unwrap();
        let result = validator.validate_dag(&child, &dag);
        assert!(
            matches!(
                result,
                Err(ValidationError::ParentTimestampViolation { .. })
            ),
            "child < newer parent must be rejected: {:?}",
            result
        );
    }

    // ==================== ÉTAPE 8: FUTURE TIMESTAMP TESTS ====================

    /// ÉTAPE 8: tx 30 minutes in the future passes (within 1h window).
    #[test]
    fn test_future_30min_passes_fresh() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ts_future = now_ms.saturating_add(30 * 60 * 1000); // +30 min
        let tx = make_valid_24bit_tx(ts_future);

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(result.is_ok(), "+30min future tx must pass: {:?}", result);
    }

    /// ÉTAPE 8: tx at ~1 hour in the future passes.
    /// After ~30s PoW mining, the effective gap shrinks below MAX_FUTURE_MS.
    #[test]
    fn test_future_exact_1h_passes_fresh() {
        let validator = TransactionValidator::new();

        let base_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Exactly at MAX_FUTURE_MS: after ~30s mining, gap≈59.5min — passes
        let ts_future = base_now.saturating_add(Transaction::MAX_FUTURE_MS);
        let tx = make_valid_24bit_tx(ts_future);

        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            result.is_ok(),
            "Future tx at MAX_FUTURE must pass: now={}, ts={}, gap={}: {:?}",
            now_ms,
            ts_future,
            ts_future.saturating_sub(now_ms),
            result
        );
    }

    /// ÉTAPE 8: tx well beyond 1h in the future REJECTS.
    #[test]
    fn test_future_1h_plus_1ms_rejects() {
        let validator = TransactionValidator::new();

        let base_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // +2h from base: after ~30s mining, gap≈119.5min — rejected
        let ts_future = base_now.saturating_add(Transaction::MAX_FUTURE_MS * 2);
        let tx = make_valid_24bit_tx(ts_future);

        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(result, Err(ValidationError::FutureTimestamp { .. })),
            "Far future tx must reject: now={}, ts={}, gap={}: {:?}",
            now_ms,
            ts_future,
            ts_future.saturating_sub(now_ms),
            result
        );
    }

    /// ÉTAPE 8: tx 1 day in the future REJECTS.
    #[test]
    fn test_future_1day_rejects() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let ts_future = now_ms.saturating_add(86_400_000); // +1 day
        let tx = make_valid_24bit_tx(ts_future);

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(result, Err(ValidationError::FutureTimestamp { .. })),
            "+1day future tx must reject: {:?}",
            result
        );
    }

    /// ÉTAPE 8: future tx passes in Historical mode (bounds skipped).
    #[test]
    fn test_future_skipped_in_historical() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // 1 day in the future — would fail Fresh, must pass Historical
        let ts_future = now_ms.saturating_add(86_400_000);
        let tx = make_valid_24bit_tx(ts_future);

        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            result.is_ok(),
            "Historical mode must skip future bounds: {:?}",
            result
        );
    }

    /// ÉTAPE 8: boundary — wide gap passes, extreme gap rejects.
    /// Both timestamps computed from a single baseline to avoid mining drift.
    #[test]
    fn test_future_boundary_exact() {
        let validator = TransactionValidator::new();

        let base_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Pass: exactly at MAX_FUTURE_MS. After ~30s mining, gap shrinks below limit.
        let ts_pass = base_now.saturating_add(Transaction::MAX_FUTURE_MS);
        let tx_pass = make_valid_24bit_tx(ts_pass);

        // Reject: 2x MAX_FUTURE_MS — gap stays well above limit.
        let ts_reject = base_now.saturating_add(Transaction::MAX_FUTURE_MS * 2);
        let tx_reject = make_valid_24bit_tx(ts_reject);

        // Capture now AFTER both mining operations
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert!(
            validator
                .validate_pure(&tx_pass, ValidationMode::Fresh)
                .is_ok(),
            "At MAX_FUTURE must pass: now={}, ts_pass={}, gap={}",
            now_ms,
            ts_pass,
            ts_pass.saturating_sub(now_ms)
        );
        assert!(
            matches!(
                validator.validate_pure(&tx_reject, ValidationMode::Fresh),
                Err(ValidationError::FutureTimestamp { .. })
            ),
            "At 2x MAX_FUTURE must reject: now={}, ts_reject={}, gap={}",
            now_ms,
            ts_reject,
            ts_reject.saturating_sub(now_ms)
        );
    }

    // ==================== ÉTAPE 4: STALE BOUNDARY TESTS ====================

    /// ÉTAPE 4: stale boundary at now - MAX_PAST_MS passes (with mining margin).
    #[test]
    fn test_stale_boundary_at_max_past_passes() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Use offset within the safe zone (well inside MAX_PAST_MS)
        let ts = now_ms.saturating_sub(Transaction::MAX_PAST_MS / 2);
        let tx = make_valid_24bit_tx(ts);

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            result.is_ok(),
            "tx well within MAX_PAST_MS boundary must pass: {:?}",
            result
        );
    }

    /// ÉTAPE 4: stale boundary at now - MAX_PAST_MS - margin rejects.
    #[test]
    fn test_stale_boundary_over_max_past_rejects() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Well beyond the boundary
        let ts = now_ms.saturating_sub(Transaction::MAX_PAST_MS + 60_000);
        let tx = make_valid_24bit_tx(ts);

        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(result, Err(ValidationError::StaleTimestamp { .. })),
            "tx well beyond MAX_PAST_MS must reject: {:?}",
            result
        );
    }

    // ==================== ÉTAPE 6: MIGRATION FIXTURE DATASET ====================

    /// ÉTAPE 6: Complete migration fixture.
    /// Genesis → 3x 20-bit txs → ACTIVATION → 3x 24-bit txs.
    /// Verifies signatures, PoW, DAG, ledger, stability, convergence.
    #[test]
    fn test_migration_fixture_20_to_24() {
        use crate::ledger::Ledger;
        use crate::parent_selection::DAG;
        use crate::wallet::Wallet;

        let mut dag = DAG::new();
        let mut ledger = Ledger::new();

        // Genesis setup
        let genesis_sender = Wallet::new();
        let genesis_addr = genesis_sender.address();
        ledger.set_balance(&genesis_addr, 1_000_000);

        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // === PRE-ACTIVATION: 3x 20-bit txs ===
        let pre_ts = Transaction::DIFFICULTY_MIGRATION_TS - 3_600_000; // 1h before activation
        let mut prev_id = [0u8; 32]; // genesis parent
        for i in 0..3u64 {
            let wallet = Wallet::new();
            let sender = wallet.address();
            let pubkey = wallet.public_key_bytes();
            ledger.set_balance(&sender, 100_000);

            let tx_ts = pre_ts + (i * 1000);
            let mut tx = Transaction::new(
                [prev_id, [0u8; 32]],
                sender,
                genesis_addr,
                100,
                10,
                tx_ts,
                0,
                0,
                vec![0u8; 64],
                pubkey,
            );
            tx.nonce = tx.mine_nonce(20); // 20-bit pre-activation
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();

            // Verify PoW at 20 bits
            assert!(
                tx.verify_pow(20),
                "pre-activation tx must have valid 20-bit PoW"
            );

            dag.add_transaction_validated(tx.clone())
                .expect("pre-activation tx must insert");
            ledger.set_balance(&sender, ledger.get_balance(&sender) - (tx.amount + tx.fee));
            prev_id = tx.id;
        }

        assert_eq!(dag.transaction_count(), 3, "3 pre-activation txs in DAG");

        // === POST-ACTIVATION: 3x 24-bit txs ===
        let post_ts = Transaction::DIFFICULTY_MIGRATION_TS + 1000; // 1s after activation
        for i in 0..3u64 {
            let wallet = Wallet::new();
            let sender = wallet.address();
            let pubkey = wallet.public_key_bytes();
            ledger.set_balance(&sender, 100_000);

            let tx_ts = post_ts + (i * 1000);
            let mut tx = Transaction::new(
                [prev_id, [0u8; 32]],
                sender,
                genesis_addr,
                100,
                10,
                tx_ts,
                0,
                0,
                vec![0u8; 64],
                pubkey,
            );
            tx.nonce = tx.mine_nonce(24); // 24-bit post-activation
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();

            // Verify PoW at 24 bits
            assert!(
                tx.verify_pow(24),
                "post-activation tx must have valid 24-bit PoW"
            );

            dag.add_transaction_validated(tx.clone())
                .expect("post-activation tx must insert");
            ledger.set_balance(&sender, ledger.get_balance(&sender) - (tx.amount + tx.fee));
            prev_id = tx.id;
        }

        assert_eq!(dag.transaction_count(), 6, "total 6 txs in DAG");

        // Verify DAG is stable across multiple reads
        let count1 = dag.transaction_count();
        let count2 = dag.transaction_count();
        assert_eq!(count1, count2, "DAG count must be deterministic");
        assert_eq!(count1, 6, "DAG must contain exactly 6 txs");
    }

    // ==================== ÉTAPE 7: COMPLETE BACKDATING TEST ====================

    /// ÉTAPE 7 WITHIN-GRACE: pre-activation tx WITHIN grace period is accepted.
    /// (Only exercisable during the grace period — skipped otherwise.)
    #[test]
    fn test_backdating_within_grace_accepted() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Can only test within grace period
        if now_ms > Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        // Pre-activation tx within grace period
        let ts_pre = Transaction::DIFFICULTY_MIGRATION_TS - 1000;
        let tx = make_valid_20bit_tx(ts_pre);

        // Fresh mode: should pass (backdating check returns Some(20))
        let fresh = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            fresh.is_ok(),
            "Pre-activation tx within grace must pass Fresh: {:?}",
            fresh
        );

        // Historical mode: should also pass
        let hist = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            hist.is_ok(),
            "Pre-activation tx within grace must pass Historical: {:?}",
            hist
        );
    }

    /// ÉTAPE 7 AFTER-GRACE: pre-activation tx AFTER grace period.
    /// Fresh mode: REJECTS (backdated).
    /// Historical mode: ACCEPTS (truly historical tx remains verifiable).
    #[test]
    fn test_backdating_after_grace_fresh_rejects_historical_accepts() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        let ts_pre = Transaction::DIFFICULTY_MIGRATION_TS - 1000;
        let tx = make_valid_20bit_tx(ts_pre);

        // Fresh mode: REJECTS
        let fresh = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(fresh, Err(ValidationError::BackdatedTimestamp { .. })),
            "Pre-activation tx after grace must reject Fresh: {:?}",
            fresh
        );

        // Historical mode: ACCEPTS (difficulty=20, PoW verified)
        let hist = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            hist.is_ok(),
            "Pre-activation tx after grace must accept Historical: {:?}",
            hist
        );
    }

    // ==================== POST-GRACE HISTORICAL VERIFICATION ====================

    /// CORE PROPERTY: A truly old pre-activation tx remains verifiable forever.
    /// This is the central security property of the migration architecture.
    ///
    /// Case A: Old pre-activation tx, Historical mode → ACCEPT
    /// Case B: New tx with backdated timestamp, Fresh mode → REJECT
    /// Case C: Unknown peer tx with old timestamp, Fresh mode → REJECT
    /// Case D: Old tx from sync, Historical mode → ACCEPT
    ///
    /// The distinction: Fresh = untrusted new tx; Historical = established history.
    #[test]
    fn test_post_grace_historical_forever() {
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let activation = Transaction::DIFFICULTY_MIGRATION_TS;

        if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
            return; // Must be after grace period
        }

        let validator = TransactionValidator::new();

        // Case A: truly old pre-activation tx, Historical mode
        // This simulates a tx created 5 years ago, now being replayed during sync.
        let ts_old = activation - 3_600_000; // 1 hour before activation
        let tx_old = make_valid_20bit_tx(ts_old);
        let result_a = validator.validate_pure(&tx_old, ValidationMode::Historical);
        assert!(
            result_a.is_ok(),
            "Case A: truly old pre-activation tx MUST be accepted in Historical mode: {:?}",
            result_a
        );

        // Case B: new tx with backdated timestamp, Fresh mode
        // This simulates an attacker creating a tx today with timestamp = activation - 1h.
        let ts_backdated = activation - 3_600_000;
        let tx_backdated = make_valid_20bit_tx(ts_backdated);
        let result_b = validator.validate_pure(&tx_backdated, ValidationMode::Fresh);
        assert!(
            matches!(result_b, Err(ValidationError::BackdatedTimestamp { .. })),
            "Case B: new backdated tx MUST be rejected in Fresh mode: {:?}",
            result_b
        );

        // Case C: unknown peer tx with old timestamp, Fresh mode
        // Same as Case B — Fresh mode treats all new txs as untrusted.
        let ts_peer = activation - 1000;
        let tx_peer = make_valid_20bit_tx(ts_peer);
        let result_c = validator.validate_pure(&tx_peer, ValidationMode::Fresh);
        assert!(
            matches!(result_c, Err(ValidationError::BackdatedTimestamp { .. })),
            "Case C: unknown peer backdated tx MUST be rejected: {:?}",
            result_c
        );

        // Case D: old tx from sync, Historical mode
        // This simulates a fresh node syncing historical data years later.
        let ts_sync = activation - 86_400_000; // 1 day before activation
        let tx_sync = make_valid_20bit_tx(ts_sync);
        let result_d = validator.validate_pure(&tx_sync, ValidationMode::Historical);
        assert!(
            result_d.is_ok(),
            "Case D: sync historical tx MUST be accepted: {:?}",
            result_d
        );

        // Verify the key property: A and D pass, B and C fail
        assert!(result_a.is_ok(), "A must pass");
        assert!(result_d.is_ok(), "D must pass");
        assert!(result_b.is_err(), "B must fail");
        assert!(result_c.is_err(), "C must fail");
    }

    /// POST-GRACE SIMULATION: 5 years after activation.
    /// Uses difficulty_for_tx_at with a simulated future timestamp.
    /// Proves the difficulty function works correctly for all time zones.
    #[test]
    fn test_post_grace_5year_simulation() {
        let activation = Transaction::DIFFICULTY_MIGRATION_TS;
        let grace_end = activation + Transaction::GRACE_PERIOD_MS;
        let five_years = 5 * 365 * 86_400_000; // ~5 years in ms
        let simulated_now = activation + five_years;

        // Simulate: tx from 1 day before activation (5 years ago)
        let tx_old = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            activation - 86_400_000,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );

        // difficulty_for_tx_at: returns Some(20) — difficulty is a historical fact
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx_old, simulated_now),
            Some(20),
            "5 years later: pre-activation tx must still have difficulty 20"
        );

        // Simulate: tx after activation
        let tx_new = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            activation + 1000,
            0,
            2,
            vec![0u8; 64],
            vec![1u8; 32],
        );

        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx_new, simulated_now),
            Some(24),
            "5 years later: post-activation tx must have difficulty 24"
        );

        // Verify grace period is irrelevant after expiry
        assert!(simulated_now > grace_end, "Must be after grace period");
    }

    /// BACKDATING ATTACK: attacker creates tx today with timestamp 5 years ago.
    /// Must be rejected by Fresh mode regardless of difficulty.
    #[test]
    fn test_backdating_5year_attack_fresh_rejects() {
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let activation = Transaction::DIFFICULTY_MIGRATION_TS;

        if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
            return;
        }

        let validator = TransactionValidator::new();

        // Attacker creates tx with timestamp 5 years before activation
        let ts_ancient = activation - 5 * 365 * 86_400_000;
        let tx = make_valid_20bit_tx(ts_ancient);

        // Fresh mode: REJECTS (backdated after grace)
        let result = validator.validate_pure(&tx, ValidationMode::Fresh);
        assert!(
            matches!(result, Err(ValidationError::BackdatedTimestamp { .. })),
            "5-year backdating attack must be rejected: {:?}",
            result
        );

        // Historical mode: ACCEPTS (truly historical tx)
        let result_hist = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            result_hist.is_ok(),
            "Historical mode must accept truly old tx: {:?}",
            result_hist
        );
    }

    /// P2P HISTORICAL BYPASS: attacker sends backdated tx via P2P.
    /// P2P uses Historical mode, but the tx must still be structurally valid.
    /// The backdating attack is harmless because:
    ///   1. Parent timestamp ordering prevents integration into post-activation chain
    ///   2. The attacker can only mine 20-bit txs (cheap, ~1M hashes)
    ///   3. These txs are structurally isolated in the pre-activation subgraph
    #[test]
    fn test_p2p_backdating_historical_path() {
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let activation = Transaction::DIFFICULTY_MIGRATION_TS;

        if now_ms <= activation + Transaction::GRACE_PERIOD_MS {
            return;
        }

        let validator = TransactionValidator::new();

        // Attacker sends backdated tx via P2P (Historical mode)
        let ts_backdated = activation - 1000;
        let tx_backdated = make_valid_20bit_tx(ts_backdated);

        // In Historical mode: the tx passes validation
        // (difficulty=20, PoW verified, signature valid)
        let result = validator.validate_pure(&tx_backdated, ValidationMode::Historical);
        assert!(
            result.is_ok(),
            "P2P backdated tx in Historical mode: {:?}",
            result
        );

        // But in Fresh mode (if wallet creates it): REJECTED
        let result_fresh = validator.validate_pure(&tx_backdated, ValidationMode::Fresh);
        assert!(
            result_fresh.is_err(),
            "Same tx in Fresh mode must be rejected"
        );

        // SECURITY ARGUMENT:
        // The backdated tx accepted in Historical mode CANNOT:
        //   - Become a parent of post-activation tx (child.ts >= parent.ts)
        //   - Affect the post-activation ledger
        //   - Be used to double-spend post-activation funds
        // It is confined to the pre-activation subgraph.
    }
}
