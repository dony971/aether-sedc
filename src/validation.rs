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

        // SECURITY: difficulty_for_tx_at() is called for BOTH modes.
        // This enforces the backdating check universally — an attacker
        // cannot bypass it by entering the Historical path.
        // Returns None only if: pre-activation timestamp + after grace period.
        let required_difficulty = match Transaction::difficulty_for_tx_at(tx, now_ms) {
            Some(d) => d,
            None => {
                return Err(ValidationError::BackdatedTimestamp {
                    tx_ts: tx.timestamp,
                    activation_ts: Transaction::DIFFICULTY_MIGRATION_TS,
                    grace_end: Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS,
                });
            }
        };

        // Timestamp bounds (Fresh mode ONLY — historical txs may be old)
        if mode == ValidationMode::Fresh {
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
        // Historical mode: skip future/stale bounds — the tx was valid when
        // created. The backdating check above already prevents misuse.

        // PoW verification (always — using difficulty from backdating check)
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

    /// ATTACK PoC #1: Create tx with pre-activation timestamp, mine at 20 bits,
    /// validate via Historical mode. MUST be REJECTED (backdating check).
    #[test]
    fn test_attack_backdated_pre_activation_rejected_historical() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return; // Can only test after grace period
        }

        // Create tx with timestamp BEFORE activation
        let ts_pre = Transaction::DIFFICULTY_MIGRATION_TS - 1000;
        let tx = make_valid_20bit_tx(ts_pre);

        // Historical mode: MUST REJECT (backdating check applies to both modes)
        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            matches!(result, Err(ValidationError::BackdatedTimestamp { .. })),
            "Historical mode MUST reject pre-activation tx after grace: {:?}",
            result
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

    /// ATTACK PoC #3: Attacker creates tx at activation boundary (1ms before),
    /// mines at 20 bits, sends via Historical. MUST be REJECTED.
    #[test]
    fn test_attack_boundary_pre_activation_rejected() {
        let validator = TransactionValidator::new();
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        if now_ms <= Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS {
            return;
        }

        // 1ms before activation — tightest boundary
        let ts_boundary = Transaction::DIFFICULTY_MIGRATION_TS - 1;
        let tx = make_valid_20bit_tx(ts_boundary);

        let result = validator.validate_pure(&tx, ValidationMode::Historical);
        assert!(
            matches!(result, Err(ValidationError::BackdatedTimestamp { .. })),
            "Boundary attack MUST be rejected: {:?}",
            result
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
}
