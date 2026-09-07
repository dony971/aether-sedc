//! # Transaction Processor - Zero-Trust Single Entry Point
//!
//! This is the ONLY module that can modify system state.
//! All transaction processing MUST go through this module.
//!
//! 🔒 ZERO TRUST ARCHITECTURE:
//! - No direct access to Ledger, DAG, or Mempool mutation methods
//! - All mutations must pass through validate_full() first
//! - Atomic pipeline with rollback on failure
//! - Single entry point for RPC, P2P, and tests
//!
//! 🔒 CONSENSUS-LINKED MONETARY POLICY:
//! - Block rewards ONLY use consensus state (single source of truth)
//! - No external block_height injection possible
//! - Rewards tracked per height to prevent double-reward attacks
//!
//! Economic policy: validation → lock → snapshot → mutation → commit → persistence

use crate::ledger::Ledger;
use crate::parent_selection::DAG;
use crate::rpc::Mempool;
use crate::transaction::Transaction;
use crate::validation::{TransactionValidator, ValidationError};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Processing error with detailed information
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessingError {
    /// Validation failed
    ValidationFailed(ValidationError),
    /// Transaction passed the pure gate (PoW + signature) but its parents are
    /// not yet in the DAG: the caller may persist it as an orphan and request
    /// the missing parents over P2P. Carries the missing parent hashes.
    Orphan(Vec<[u8; 32]>),
    /// Lock acquisition failed
    LockError(String),
    /// Ledger operation failed
    LedgerError(String),
    /// DAG operation failed
    DagError(String),
    /// Mempool operation failed
    MempoolError(String),
    /// Persistence failed
    PersistenceError(String),
}

impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessingError::ValidationFailed(e) => write!(f, "Validation failed: {}", e),
            ProcessingError::Orphan(missing) => write!(
                f,
                "Transaction has {} missing parent(s) (orphan)",
                missing.len()
            ),
            ProcessingError::LockError(e) => write!(f, "Lock error: {}", e),
            ProcessingError::LedgerError(e) => write!(f, "Ledger error: {}", e),
            ProcessingError::DagError(e) => write!(f, "DAG error: {}", e),
            ProcessingError::MempoolError(e) => write!(f, "Mempool error: {}", e),
            ProcessingError::PersistenceError(e) => write!(f, "Persistence error: {}", e),
        }
    }
}

impl std::error::Error for ProcessingError {}

impl From<ValidationError> for ProcessingError {
    fn from(e: ValidationError) -> Self {
        ProcessingError::ValidationFailed(e)
    }
}

/// Transaction Processor - Single Entry Point for All State Mutations
///
/// 🔒 ZERO TRUST: This is the ONLY way to modify system state
/// All RPC, P2P, and test code MUST use this processor
pub struct TransactionProcessor {
    validator: TransactionValidator,
}

impl TransactionProcessor {
    /// Create new transaction processor
    pub fn new() -> Self {
        Self {
            validator: TransactionValidator::new(),
        }
    }

    /// Create processor with custom PoW difficulty
    pub fn with_difficulty(difficulty: u8) -> Self {
        Self {
            validator: TransactionValidator::with_difficulty(difficulty),
        }
    }

    /// PHASE D: expose the pure gate (PoW + signature) to the mempool ACCEPT
    /// path, so unvalidated junk never occupies a queue slot (parity with the
    /// H1 orphan rule: entering any store costs one valid PoW + signature).
    pub fn validate_pure(&self, tx: &Transaction) -> Result<(), ValidationError> {
        self.validator.validate_pure(tx)
    }

    /// Process a transaction through the secure pipeline
    ///
    /// 🔒 ZERO TRUST PIPELINE:
    /// 0. Deterministic double-spend resolution (min-id wins, cascade prune + ledger rebuild)
    /// 1. validate_pure() (PoW + signature gate) then orphan gate (missing
    ///    parents => ProcessingError::Orphan) then validate_dag() + validate_ledger()
    /// 2. Acquire write locks
    /// 3. Snapshot state for rollback
    /// 4. Apply ledger transfer
    /// 5. Commit nonce atomically
    /// 6. Add to DAG (validated) - THE CONSENSUS CONFIRMATION EVENT
    /// 7. Add to mempool
    /// 8. Persist state
    /// 9. Rollback on any error
    ///
    /// 🪙 MONETARY POLICY: ZERO EMISSION. No rewards are ever minted here.
    /// The token supply is fixed at genesis and can only decrease via fees
    /// being burned. There is nothing a caller can supply (no miner address,
    /// no height, no block id) that would create new tokens.
    ///
    /// This is the ONLY public method that can modify system state
    pub async fn process(
        &self,
        tx: Transaction,
        dag: &Arc<RwLock<DAG>>,
        ledger: &Arc<RwLock<Ledger>>,
        mempool: &Arc<RwLock<Mempool>>,
        min_fee: u64,
    ) -> Result<(), ProcessingError> {
        tracing::info!("🔍 Processing transaction: {}", hex::encode(tx.id));

        // STEP 0: DETERMINISTIC DOUBLE-SPEND RESOLUTION (NV-09)
        // If another transaction exists for the same (sender, nonce), the one
        // with the lexicographically SMALLEST id wins (this is the same rule on
        // every node, so all nodes converge). If we win, we prune the losing
        // subtree and rebuild the ledger from the remaining DAG. If we lose,
        // we reject deterministically. No special-casing for any address.
        {
            let dag_read = dag.read().await;
            if let Some(existing_id) =
                dag_read.find_sender_nonce_conflict(&tx.sender, tx.account_nonce)
            {
                if existing_id <= tx.id {
                    tracing::warn!(
                        "⚠️ Sender conflict rejected (existing id {} <= new id {}): {}",
                        hex::encode(&existing_id[..4]),
                        hex::encode(&tx.id[..4]),
                        hex::encode(tx.sender)
                    );
                    return Err(ProcessingError::ValidationFailed(
                        ValidationError::SenderConflict,
                    ));
                }
                drop(dag_read);
                // V-21 FIX: never destroy a valid transaction for an INVALID
                // winner. The incoming tx must at least pass pure validation
                // (PoW, signature, sender-key match) BEFORE we prune anything,
                // otherwise a malformed tx could knock a valid tx out of the
                // local DAG and diverge the node from the network.
                self.validator.validate_pure(&tx)?;
                tracing::warn!(
                    "🔄 Resolving sender conflict in favor of {} (pruning {})",
                    hex::encode(&tx.id[..4]),
                    hex::encode(&existing_id[..4])
                );
                let mut dag_w = match dag.try_write() {
                    Ok(l) => l,
                    Err(e) => return Err(ProcessingError::LockError(format!("DAG lock: {}", e))),
                };
                let mut ledger_w = match ledger.try_write() {
                    Ok(l) => l,
                    Err(e) => {
                        return Err(ProcessingError::LockError(format!("Ledger lock: {}", e)))
                    }
                };
                let pruned = dag_w.prune_subtree(existing_id);
                // V-21 FIX: purge the pruned transactions from persistent
                // storage so they cannot resurrect at the next boot (the boot
                // rebuild would otherwise become nondeterministic: whichever
                // of the loser/winner it hits first would win).
                if let Some(storage) = ledger_w.storage() {
                    let storage_read = storage.read().await;
                    for pruned_id in &pruned {
                        let _ = storage_read.delete_transaction(*pruned_id);
                    }
                }
                ledger_w.rebuild_from_dag(&dag_w);
            }
        }

        // STEP 1: PURE VALIDATION — the PoW + signature gate. NO state access,
        // no locks. This gate MUST pass before anything is parked in the
        // orphan store (H1): parking unvalidated transactions let anyone fill
        // disk and memory with garbage and trigger unbounded P2P re-requests.
        self.validator.validate_pure(&tx)?;

        // STEP 1b: ORPHAN GATE — a transaction whose parents are not yet in
        // the DAG is not inherently invalid: the parents may simply not have
        // arrived yet. Return Orphan so the caller (RPC/P2P path) persists it
        // and re-requests the parents. Only reached after the pure gate above,
        // so every orphan entry costs the submitter one valid PoW + signature.
        {
            let dag_read = dag.read().await;
            let missing_parents: Vec<[u8; 32]> = tx
                .parents
                .iter()
                .filter(|p| **p != [0u8; 32] && !dag_read.transactions().contains_key(*p))
                .copied()
                .collect();
            if !missing_parents.is_empty() {
                drop(dag_read);
                return Err(ProcessingError::Orphan(missing_parents));
            }
        }

        // STEP 1c: FULL DAG + LEDGER VALIDATION (read-only, no locks held for
        // mutation). Same checks as the former validate_full(), minus the
        // pure checks already performed above.
        let dag_read = dag.read().await;
        let ledger_read = ledger.read().await;
        self.validator.validate_dag(&tx, &dag_read)?;
        // INC-01 crash recovery, made PRECISE by C2 P3 applied-tracking:
        // the DAG-level checks passed, but the ledger may already contain
        // this tx's effects — a crash can truncate the transaction tree
        // while the ledger snapshot survives, leaving the ledger AHEAD of
        // the DAG. Such a tx must heal the DAG WITHOUT a ledger replay:
        // the balance gate would reject it (already debited) or the
        // transfer would double-apply.
        //
        // C2 P3: route on POSITIVE evidence, never on the nonce slot
        // alone. A committed slot does NOT prove this transfer ran:
        // the max-rule nonce can commit via a HIGHER-nonce tx while a
        // lower-nonce transfer never applied (out-of-order arrival on
        // catch-up nodes fossilized whole ledgers durably, INC-C2-003).
        //   1. account_nonce above the committed max ⟹ never applied
        //      (application would have committed >= it): normal path,
        //      no store I/O (fast path).
        //   2. id ∈ applied set ⟹ effects present ⟹ DAG-only heal.
        //   3. id persisted in store ⟹ was accepted (transfer ran;
        //      covers pre-tracking upgrades with empty applied sets,
        //      no backfill needed) ⟹ DAG-only heal.
        //   4. otherwise ⟹ transfer never ran here ⟹ NORMAL processing
        //      (the balance gate + DAG-duplicate reject + snapshot
        //      rollback bound every corner: DAG-present dups were already
        //      rejected by validate_dag above; conflicts by STEP 0;
        //      unfundable by validate_ledger with zero mutation; a DAG-add
        //      failure after transfer rolls everything back).
        {
            let ledger_nonce = ledger_read.get_nonce(&tx.sender);
            if tx.account_nonce <= ledger_nonce {
                let mut effects_present = ledger_read.is_applied(&tx.id);
                if !effects_present {
                    if let Some(storage) = ledger_read.storage() {
                        if let Ok(in_store) = storage.read().await.transaction_exists(tx.id) {
                            effects_present = in_store;
                        }
                    }
                }
                if effects_present {
                    drop(dag_read);
                    drop(ledger_read);
                    return self.process_recovery_insert(tx, dag, ledger).await;
                }
            }
        }
        self.validator.validate_ledger(&tx, &ledger_read, min_fee)?;
        drop(dag_read);
        drop(ledger_read);

        // STEP 2: ACQUIRE WRITE LOCKS
        let mut dag = match dag.try_write() {
            Ok(l) => l,
            Err(e) => return Err(ProcessingError::LockError(format!("DAG lock: {}", e))),
        };
        let mut ledger = match ledger.try_write() {
            Ok(l) => l,
            Err(e) => {
                drop(dag);
                return Err(ProcessingError::LockError(format!("Ledger lock: {}", e)));
            }
        };
        let mut mempool = match mempool.try_write() {
            Ok(l) => l,
            Err(e) => {
                drop(ledger);
                drop(dag);
                return Err(ProcessingError::LockError(format!("Mempool lock: {}", e)));
            }
        };

        // STEP 3: SNAPSHOT STATE FOR ROLLBACK
        let ledger_snapshot = ledger.clone();

        // STEP 4: APPLY LEDGER TRANSFER (burns the fee)
        if let Err(e) = ledger.transfer_internal(&tx.sender, &tx.receiver, tx.amount, tx.fee) {
            tracing::error!("❌ Ledger transfer failed: {}", e);
            *ledger = ledger_snapshot;
            drop(ledger);
            drop(dag);
            drop(mempool);
            return Err(ProcessingError::LedgerError(format!(
                "Transfer failed: {}",
                e
            )));
        }
        // C2 P3: effects applied — record positive evidence BEFORE the
        // nonce commit. Any later failure rolls back to the snapshot
        // (which excludes this mark), so the mark can never outlive the
        // transfer it attests.
        ledger.mark_applied(&tx.id);

        // STEP 5: COMMIT NONCE (deterministic max, not strict +1)
        // The strict `last_nonce + 1` rule is arrival-order-dependent: a node
        // that already processed nonces 4,5,6 would reject a late nonce-3
        // transaction that another node accepted, permanently diverging the
        // two DAGs. The ledger nonce is a pure function of the DAG (the boot
        // rebuild takes the max nonce per sender), so the live ledger must
        // apply the exact same rule to stay consistent with it.
        {
            let current = ledger.get_nonce(&tx.sender);
            if tx.account_nonce > current {
                ledger.set_nonce(&tx.sender, tx.account_nonce);
            }
        }

        // STEP 6: ADD TO DAG - THE CONSENSUS CONFIRMATION EVENT
        // The DAG is the single source of truth. Finality is immediate once a
        // transaction is accepted into the DAG.
        if let Err(e) = dag.add_transaction_validated(tx.clone()) {
            tracing::error!("❌ DAG add failed: {}", e);
            *ledger = ledger_snapshot;
            drop(ledger);
            drop(dag);
            drop(mempool);
            return Err(ProcessingError::DagError(format!("DAG add failed: {}", e)));
        }

        // STEP 7: REMOVE FROM MEMPOOL (PHASE D — the mempool is a PENDING
        // queue, not a dead-end window). The drainer SELECTed this tx; once it
        // reaches the DAG it leaves the queue. Previously this step ADDED the
        // tx to a never-drained window and ROLLED BACK the DAG add when the
        // window was full — that is exactly how the network deadlocked at 1000
        // transactions (Phase C root cause): DAG growth stopped, bootstrap got
        // blocked, the faucet was pinned. The queue can now never reject a
        // DAG-valid tx: inclusion is the terminal disposition. Idempotent (the
        // drainer may already have disposed of it).
        mempool.remove_transaction(&tx.id);

        // STEP 8: PERSIST STATE (transaction FIRST, then ledger — INC-01 commit
        // order). A crash can never leave the ledger snapshot AHEAD of the
        // transaction tree: if the ledger was saved for tx N, tx N is already
        // in the Sled transactions tree. The boot guard then knows the
        // persisted ledger never references history the DAG cannot rebuild.
        if let Some(storage) = ledger.storage() {
            let storage_read = storage.read().await;
            if let Err(e) = storage_read.put_transaction(&tx) {
                tracing::error!("❌ Failed to persist transaction to Sled: {}", e);
                return Err(ProcessingError::PersistenceError(format!(
                    "Transaction persist failed: {}",
                    e
                )));
            }
            // P4: NO per-transaction flush. A synchronous Sled flush (fsync)
            // per accepted tx cost ~690µs/tx in release (78.6ms vs 9.8ms per
            // 100 txs). Durability is covered by Sled's internal auto-flush
            // (~500ms), the INC-01 per-batch flush in the drainer, the
            // node's periodic flush (10s) and the shutdown flush; on a hard
            // kill the boot guard keeps the persisted ledger and the orphan
            // solver + full sync heal the DAG from peers.
        }
        if let Err(e) = ledger.save().await {
            tracing::error!("❌ Persistence failed: {}", e);
            return Err(ProcessingError::PersistenceError(format!(
                "Save failed: {}",
                e
            )));
        }

        tracing::info!(
            "✅ Transaction processed successfully: {}",
            hex::encode(tx.id)
        );
        Ok(())
    }

    /// INC-01 crash recovery: DAG-only insertion of a transaction whose
    /// ledger effects are already applied (the ledger is ahead of the DAG
    /// after a crash truncated the transaction tree). The DAG is the source
    /// of truth: heal it WITHOUT replaying the ledger — the ledger already
    /// reflects the tx, a replay would double-apply the transfer or be
    /// rejected by the balance gate. Idempotent: a tx already in the DAG is
    /// a no-op.
    async fn process_recovery_insert(
        &self,
        tx: Transaction,
        dag: &Arc<RwLock<DAG>>,
        ledger: &Arc<RwLock<Ledger>>,
    ) -> Result<(), ProcessingError> {
        {
            let mut dag = match dag.try_write() {
                Ok(l) => l,
                Err(e) => return Err(ProcessingError::LockError(format!("DAG lock: {}", e))),
            };
            if dag.transactions().contains_key(&tx.id) {
                return Ok(());
            }
            if let Err(e) = dag.add_transaction_validated(tx.clone()) {
                return Err(ProcessingError::DagError(format!("DAG add failed: {}", e)));
            }
        }
        if let Some(storage) = ledger.read().await.storage() {
            let storage_read = storage.read().await;
            if let Err(e) = storage_read.put_transaction(&tx) {
                tracing::error!("❌ INC-01: failed to persist recovery tx to Sled: {}", e);
            }
        }
        tracing::info!(
            "🔁 INC-01 recovery insert (ledger ahead of DAG): {}",
            hex::encode(&tx.id[..8])
        );
        Ok(())
    }
}

impl Default for TransactionProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_processor_valid_transaction() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        let sender = [1u8; 32];
        ledger.write().await.set_balance(&sender, 1000);
        ledger.write().await.commit_nonce(&sender, 0);

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
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
        let result = processor.process(tx, &dag, &ledger, &mempool, 10).await;
        assert!(result.is_err());
        // The error should be validation failed (insufficient balance or signature)
        // We just check that it failed, not the specific error type
    }

    #[tokio::test]
    async fn test_processor_insufficient_balance() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        let sender = [1u8; 32];
        ledger.write().await.set_balance(&sender, 50); // Insufficient balance
        ledger.write().await.commit_nonce(&sender, 0);

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            100, // More than balance
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        let result = processor.process(tx, &dag, &ledger, &mempool, 10).await;
        assert!(result.is_err());
        // The error should be validation failed (insufficient balance or signature)
        // We just check that it failed, not the specific error type
    }

    /// H1: an orphan requires the pure gate (PoW + signature) BEFORE being
    /// parked. A garbage transaction with missing parents must be rejected as
    /// a validation failure, never reported as an orphan — otherwise anyone
    /// could fill the orphan store (disk + memory) without any work.
    #[tokio::test]
    async fn test_orphan_gated_by_pure_validation() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        // Missing parents + NO PoW (nonce 0) + NO valid signature.
        let tx = Transaction::new(
            [[0xAAu8; 32], [0xBBu8; 32]],
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

        let result = processor.process(tx, &dag, &ledger, &mempool, 10).await;
        assert!(
            matches!(result, Err(ProcessingError::ValidationFailed(_))),
            "garbage orphan must fail pure validation, got {:?}",
            result
        );
        assert!(
            !matches!(result, Err(ProcessingError::Orphan(_))),
            "garbage orphan must never be reported as an orphan"
        );
    }

    /// H1: a transaction that PASSES the pure gate (valid PoW + signature)
    /// but references missing parents is returned as Orphan carrying the
    /// missing parent hashes, so the caller can persist and re-request them.
    #[tokio::test]
    async fn test_valid_orphan_returns_missing_parents() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        let tx = crate::tests::signed_mined_orphan_tx();

        let result = processor
            .process(tx.clone(), &dag, &ledger, &mempool, 1000)
            .await;
        match result {
            Err(ProcessingError::Orphan(missing_parents)) => {
                assert!(
                    missing_parents.contains(&tx.parents[0]),
                    "orphan must report the missing parent, got {:?}",
                    missing_parents
                );
            }
            other => panic!("expected ProcessingError::Orphan, got {:?}", other),
        }
    }

    /// S11: double-spend resolution is ORDER-INVARIANT. Two conflicting txs
    /// (same sender + account_nonce, different receivers), mined + signed,
    /// processed in EITHER arrival order, must leave the node in the same
    /// state: the lexicographically smallest id wins, the loser is rejected,
    /// and the ledger ends identical (prune + rebuild is a pure function of
    /// the DAG).
    #[tokio::test]
    async fn test_double_spend_order_invariance() {
        use crate::wallet::Wallet;
        let processor = TransactionProcessor::with_difficulty(1); // trivial PoW
        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();

        let build_conflict = |receiver: [u8; 32]| {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                receiver,
                100,
                10,
                1234567890,
                0, // nonce placeholder — mined below
                1, // same account_nonce for both → double spend
                vec![0u8; 64],
                pk.clone(),
            );
            tx.nonce = tx.mine_nonce(1);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            assert!(tx.verify_pow(1));
            assert!(Wallet::verify_transaction(&tx));
            tx
        };

        let tx_a = build_conflict([0xAAu8; 32]);
        let tx_b = build_conflict([0xBBu8; 32]);
        assert_ne!(tx_a.id, tx_b.id);
        let (winner, loser) = if tx_a.id <= tx_b.id {
            (tx_a.clone(), tx_b.clone())
        } else {
            (tx_b.clone(), tx_a.clone())
        };

        // Run the same pair in both arrival orders on fresh state. The sender
        // is funded THROUGH the DAG (faucet -> sender) so that the prune +
        // rebuild path (which reseeds strictly from genesis + DAG) keeps the
        // funding — mirroring production.
        // Borrow the processor once: the closure + async blocks capture this
        // shared reference (Copy), keeping the closure Fn for both runs.
        let processor_ref = &processor;
        let run = |first: Transaction, second: Transaction, second_is_loser: bool| {
            let expect_second_ok = !second_is_loser;
            async move {
                let dag = Arc::new(RwLock::new(DAG::new()));
                let ledger = Arc::new(RwLock::new(Ledger::new()));
                let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

                let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
                let faucet: [u8; 32] = faucet.try_into().unwrap();
                let funding = Transaction::new(
                    [[0u8; 32]; 2],
                    faucet,
                    sender,
                    1000,
                    5,
                    1234567890,
                    0,
                    1,
                    vec![0u8; 64],
                    vec![1u8; 64],
                );
                dag.write()
                    .await
                    .add_transaction_validated(funding)
                    .unwrap();
                let dag_read = dag.read().await;
                ledger.write().await.rebuild_from_dag(&dag_read);
                drop(dag_read);
                assert_eq!(ledger.read().await.get_balance(&sender), 1000);

                processor_ref
                    .process(first, &dag, &ledger, &mempool, 10)
                    .await
                    .expect("first arrival is accepted");
                let second_result = processor_ref
                    .process(second, &dag, &ledger, &mempool, 10)
                    .await;
                if expect_second_ok {
                    assert!(
                        second_result.is_ok(),
                        "the winning transaction must be accepted, got {:?}",
                        second_result
                    );
                } else {
                    assert!(
                        second_result.is_err(),
                        "the losing transaction must be rejected, got {:?}",
                        second_result
                    );
                }
                (dag, ledger)
            }
        };

        let (dag_wl, ledger_wl) = run(winner.clone(), loser.clone(), true).await;
        let (dag_lw, ledger_lw) = run(loser.clone(), winner.clone(), false).await;

        // Identical DAG outcome: funding + exactly the winner, in both orders.
        {
            let dag_wl_guard = dag_wl.read().await;
            let dag_lw_guard = dag_lw.read().await;
            assert_eq!(
                dag_wl_guard.transaction_count(),
                2,
                "order 1: funding + winner"
            );
            assert_eq!(
                dag_lw_guard.transaction_count(),
                2,
                "order 2: funding + winner"
            );
            assert!(dag_wl_guard.transactions().contains_key(&winner.id));
            assert!(dag_lw_guard.transactions().contains_key(&winner.id));
            assert!(!dag_wl_guard.transactions().contains_key(&loser.id));
            assert!(!dag_lw_guard.transactions().contains_key(&loser.id));
            // WEIGHT: identical in both orders too — the DAG maintains it the
            // same way whichever transaction arrives first. Both roots (winner
            // and funding have genesis parents) → each subtree = {itself} = 1.
            assert_eq!(dag_wl_guard.get_transaction(winner.id).unwrap().weight, 1.0);
            assert_eq!(dag_lw_guard.get_transaction(winner.id).unwrap().weight, 1.0);
            for (label, guard) in [("order 1", &dag_wl_guard), ("order 2", &dag_lw_guard)] {
                let funding_weight = guard
                    .transactions()
                    .values()
                    .find(|tx| tx.sender == funding_sender())
                    .map(|tx| tx.weight)
                    .unwrap_or(0.0);
                assert_eq!(funding_weight, 1.0, "{label}: funding weight");
            }
        }

        // Identical ledger outcome in both orders.
        let ledger_wl = ledger_wl.read().await;
        let ledger_lw = ledger_lw.read().await;
        assert_eq!(
            ledger_wl.get_balance(&sender),
            ledger_lw.get_balance(&sender),
            "sender balance must be order-invariant"
        );
        assert_eq!(
            ledger_wl.get_balance(&winner.receiver),
            ledger_lw.get_balance(&winner.receiver),
            "winner receiver balance must be order-invariant"
        );
        assert_eq!(ledger_wl.get_balance(&sender), 1000 - 110);
        assert_eq!(ledger_wl.get_balance(&winner.receiver), 100);
        assert_eq!(ledger_wl.get_balance(&loser.receiver), 0);
    }

    fn funding_sender() -> [u8; 32] {
        hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// S11 reinforcement (restart/resync dimension): a crash that leaves BOTH
    /// double-spend candidates — plus a descendant built on the loser — in
    /// persistent storage must still converge to the same canonical winner at
    /// boot. The boot path (node.rs) runs `canonical_resolve_conflicts` BEFORE
    /// the topological rebuild (V-21), then rebuilds the ledger from the
    /// surviving DAG. This test replays exactly that sequence on a simulated
    /// crash residue and asserts the outcome is identical to the live
    /// resolution (winner only, same balances).
    #[tokio::test]
    async fn test_boot_rebuild_converges_after_crash_residue() {
        use crate::parent_selection::canonical_resolve_conflicts;
        use crate::wallet::Wallet;

        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();

        let build_conflict = |receiver: [u8; 32]| {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                receiver,
                100,
                10,
                1234567890,
                0,
                1, // same account_nonce for both = double spend
                vec![0u8; 64],
                pk.clone(),
            );
            tx.nonce = tx.mine_nonce(1);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            tx
        };

        let tx_a = build_conflict([0xAAu8; 32]);
        let tx_b = build_conflict([0xBBu8; 32]);
        let (winner, loser) = if tx_a.id <= tx_b.id {
            (tx_a.clone(), tx_b.clone())
        } else {
            (tx_b.clone(), tx_a.clone())
        };

        // Crash residue: a descendant built on the loser before the prune.
        let mut loser_child = Transaction::new(
            [loser.id, [0u8; 32]],
            [0xADu8; 32],
            [0xACu8; 32],
            5,
            5,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        loser_child.nonce = loser_child.mine_nonce(1);
        loser_child.id = loser_child.compute_hash();

        // Funding tx (faucet -> sender) — present in the residue like S11.
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap();
        let funding = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            sender,
            1000,
            5,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        let mut residue = vec![
            funding.clone(),
            winner.clone(),
            loser.clone(),
            loser_child.clone(),
        ];

        // Boot step 1: canonical resolution (V-21) — pure function of the set.
        let pruned = canonical_resolve_conflicts(&mut residue);
        assert!(pruned.contains(&loser.id), "the loser must be pruned");
        assert!(
            pruned.contains(&loser_child.id),
            "the descendant of the loser must be pruned"
        );
        assert!(!pruned.contains(&winner.id), "the winner must survive");
        assert_eq!(residue.len(), 2, "only funding + winner remain");

        // Boot step 2: topological insert + tips rebuild.
        let mut dag = DAG::new();
        for tx in &residue {
            dag.add_transaction_validated(tx.clone()).unwrap();
        }
        dag.rebuild_tips();

        // Boot step 3: the ledger is a DERIVED VIEW of the DAG.
        let mut ledger = Ledger::new();
        ledger.rebuild_from_dag(&dag);

        assert_eq!(dag.transaction_count(), 2, "funding + winner only");
        assert!(dag.transactions().contains_key(&winner.id));
        assert!(!dag.transactions().contains_key(&loser.id));
        assert!(!dag.transactions().contains_key(&loser_child.id));
        assert_eq!(
            ledger.get_balance(&sender),
            1000 - 110,
            "same sender balance as the live S11 resolution"
        );
        assert_eq!(ledger.get_balance(&winner.receiver), 100);
        assert_eq!(ledger.get_balance(&loser.receiver), 0);
        assert_eq!(ledger.get_balance(&loser_child.receiver), 0);

        // WEIGHT: boot rebuild maintains tx.weight exactly like the live path.
        // The winner and funding are both roots (genesis parents) — each
        // subtree = {itself} = 1. The pruned loser and its descendant are
        // gone with their weights — nothing survives the prune.
        assert_eq!(dag.get_transaction(winner.id).unwrap().weight, 1.0);
        assert_eq!(dag.get_transaction(funding.id).unwrap().weight, 1.0);
    }

    /// P4 benchmark harness (run with `cargo test -- --ignored bench_`):
    /// measures the cost of the STEP 8 persistence path per accepted
    /// transaction. Before the P4 fix, each accepted tx performed TWO full
    /// Sled flushes (fsync) plus a full-state ledger rewrite (save writes
    /// every balance + nonce). The numbers printed are the reference and the
    /// post-fix regression check.
    #[ignore]
    #[tokio::test]
    async fn bench_sled_persistence_per_transaction() {
        use crate::storage::Storage;
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(RwLock::new(Storage::open(dir.path().join("sled")).unwrap()));
        let ledger = Arc::new(RwLock::new(
            Ledger::new_with_storage(storage.clone()).await.unwrap(),
        ));
        let dag = Arc::new(RwLock::new(DAG::new()));
        // Large mempool: the bench measures the STORAGE path, not the
        // 1000-entry mempool eviction policy.
        let mempool = Arc::new(RwLock::new(Mempool::new(100_000, 10)));
        let processor = TransactionProcessor::with_difficulty(1);

        // Fund one sender through the real DAG -> ledger path.
        let wallet = crate::wallet::Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap();
        let funding = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            sender,
            100_000_000,
            5,
            0,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.write()
            .await
            .add_transaction_validated(funding.clone())
            .unwrap();
        let dag_read = dag.read().await;
        ledger.write().await.rebuild_from_dag(&dag_read);
        drop(dag_read);

        let build_tx = |account_nonce: u64| {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                [0x77u8; 32],
                100,
                10,
                0,
                0,
                account_nonce,
                vec![0u8; 64],
                pk.clone(),
            );
            tx.nonce = tx.mine_nonce(1);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            tx
        };

        let mut nonce_counter: u64 = 0;
        // Isolate phase costs on a fresh state with the first 100 txs.
        let probe_txs: Vec<Transaction> = (0..100)
            .map(|_| {
                nonce_counter += 1;
                build_tx(nonce_counter)
            })
            .collect();
        let mut t = Instant::now();
        for tx in &probe_txs {
            assert!(tx.verify_pow(1));
        }
        println!("P4 micro: verify_pow x100 -> {:?}", t.elapsed());
        t = Instant::now();
        for tx in &probe_txs {
            assert!(crate::wallet::Wallet::verify_transaction(tx));
        }
        println!("P4 micro: verify_transaction x100 -> {:?}", t.elapsed());
        t = Instant::now();
        for tx in &probe_txs {
            processor.validator.validate_pure(tx).unwrap();
        }
        println!("P4 micro: validate_pure x100 -> {:?}", t.elapsed());
        t = Instant::now();
        for tx in &probe_txs {
            let d = dag.read().await;
            let l = ledger.read().await;
            processor.validator.validate_dag(tx, &d).unwrap();
            processor.validator.validate_ledger(tx, &l, 10).unwrap();
        }
        println!("P4 micro: validate_dag+ledger x100 -> {:?}", t.elapsed());
        t = Instant::now();
        for tx in &probe_txs {
            if let Err(e) = processor
                .process(tx.clone(), &dag, &ledger, &mempool, 10)
                .await
            {
                panic!("tx rejected: {}", e);
            }
        }
        println!("P4 micro: full process x100 -> {:?}", t.elapsed());
        for &n in &[1000usize, 10000] {
            // Build all txs up front so mining/signing cost is measured apart.
            let t_build = Instant::now();
            let txs: Vec<Transaction> = (0..n)
                .map(|_| {
                    nonce_counter += 1;
                    build_tx(nonce_counter)
                })
                .collect();
            let build_elapsed = t_build.elapsed();
            let t0 = Instant::now();
            for tx in &txs {
                if let Err(e) = processor
                    .process(tx.clone(), &dag, &ledger, &mempool, 10)
                    .await
                {
                    panic!("tx rejected: {}", e);
                }
            }
            let elapsed = t0.elapsed();
            println!(
                "P4 bench: {n} txs -> process {elapsed:?} ({:.0} tps), build {build_elapsed:?}",
                n as f64 / elapsed.as_secs_f64()
            );
        }
    }

    /// C2 P3 (INC-C2-003): a committed nonce slot is NOT proof the transfer
    /// ran. Simulate out-of-order arrival on a catch-up node: the slot is
    /// committed to 10 with NO transfer, then a nonce-3 tx arrives. The old
    /// nonce-only rule sent it to recovery-insert (DAG-only, transfer
    /// fossilized); the precise rule must FULLY apply it.
    #[tokio::test]
    async fn test_phantom_nonce_heals_transfer() {
        use crate::wallet::Wallet;
        let processor = TransactionProcessor::with_difficulty(1);
        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();
        let receiver = [9u8; 32];

        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        ledger.write().await.set_balance(&sender, 10000);
        // Phantom commit: slot to 10 with zero transfers.
        ledger.write().await.set_nonce(&sender, 10);

        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            1234567890,
            0,
            3,
            vec![0u8; 64],
            pk,
        );
        tx.nonce = tx.mine_nonce(1);
        tx.signature = wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();

        processor
            .process(tx.clone(), &dag, &ledger, &mempool, 10)
            .await
            .expect("phantom nonce must heal with full apply");
        // Transfer applied (not skipped): sender debited amount+fee.
        assert_eq!(ledger.read().await.get_balance(&sender), 10000 - 110);
        assert_eq!(ledger.read().await.get_balance(&receiver), 100);
        assert!(ledger.read().await.is_applied(&tx.id));
        // Max-rule nonce keeps the higher committed slot.
        assert_eq!(ledger.read().await.get_nonce(&sender), 10);
        assert!(dag.read().await.transactions().contains_key(&tx.id));
    }

    /// C2 P3: a tx whose effects ARE present (applied mark set, balances
    /// reflect the transfer — crash-ahead shape) heals the DAG WITHOUT
    /// replaying: no double debit, DAG gains the tx.
    #[tokio::test]
    async fn test_applied_true_duplicate_skips_replay() {
        use crate::wallet::Wallet;
        let processor = TransactionProcessor::with_difficulty(1);
        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();
        let receiver = [9u8; 32];

        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        ledger.write().await.set_balance(&sender, 10000);

        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            pk,
        );
        tx.nonce = tx.mine_nonce(1);
        tx.signature = wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();

        // Simulate crash-ahead: effects present, DAG lacks the tx.
        {
            let mut l = ledger.write().await;
            l.transfer_internal(&sender, &receiver, 100, 10).unwrap();
            l.set_nonce(&sender, 1);
            l.mark_applied(&tx.id);
        }
        assert_eq!(ledger.read().await.get_balance(&sender), 10000 - 110);

        processor
            .process(tx.clone(), &dag, &ledger, &mempool, 10)
            .await
            .expect("recovery must heal the DAG");
        // No double debit, DAG healed.
        assert_eq!(ledger.read().await.get_balance(&sender), 10000 - 110);
        assert_eq!(ledger.read().await.get_balance(&receiver), 100);
        assert!(dag.read().await.transactions().contains_key(&tx.id));
    }
}
