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
use crate::stake::{current_epoch, StakeRegistry, VoteInsertOutcome};
use crate::transaction::{Bond, Transaction, TransactionId, Unbond, Vote};
use crate::validation::{TransactionValidator, ValidationError, ValidationMode};
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
  /// PHASE 4G: live stake-finality registry (None = pre-v6 wiring:
  /// every path behaves EXACTLY as before  -  legacy CDW/min-id
  /// everywhere). Set by the node after boot-loading the registry from
  /// storage. When present, conflict winners are era-routed (v6 for
  /// post-activation keys) and vote/bond/unbond admission is enabled.
  stake_registry: Option<Arc<RwLock<StakeRegistry>>>,
}

impl TransactionProcessor {
    /// Create new transaction processor
    pub fn new() -> Self {
        Self {
            validator: TransactionValidator::new(),
  stake_registry: None,
        }
    }

    /// Create processor with custom PoW difficulty
    pub fn with_difficulty(difficulty: u8) -> Self {
        Self {
            validator: TransactionValidator::with_difficulty(difficulty),
  stake_registry: None,
        }
    }

  /// PHASE 4G: attach the live stake registry (node boot path, after
  /// storage load). Idempotent (re-attaching replaces the handle).
  pub fn set_stake_registry(&mut self, registry: Arc<RwLock<StakeRegistry>>) {
  self.stake_registry = Some(registry);
    }

    /// PHASE D: expose the pure gate (PoW + signature) to the mempool ACCEPT
    /// path, so unvalidated junk never occupies a queue slot (parity with the
    /// H1 orphan rule: entering any store costs one valid PoW + signature).
    pub fn validate_pure(
        &self,
        tx: &Transaction,
        mode: ValidationMode,
    ) -> Result<(), ValidationError> {
        self.validator.validate_pure(tx, mode)
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
        mode: ValidationMode,
    ) -> Result<(), ProcessingError> {
        // LOG NOISE (soak): per-tx line on the hot path (thousands/hour
        // during sync/load) — DEBUG only. Rejections/failures keep their
        // own WARN/ERROR lines at their sites.
        tracing::debug!("🔍 Processing transaction: {}", hex::encode(tx.id));

        // STEP 0: CONFLICT DETECTION (PHASE 4B: CDW + loser retention).
        // If resident txs share the newcomer's (sender, nonce), the newcomer
        // joins them as a retained conflict member — winner or loser — via
        // the conflict path below. It is NEVER pruned and NEVER rejected for
        // conflicting (loser retention: both sides must coexist everywhere so
        // arrival order cannot split nodes). Winner selection (CDW +
        // min-id tiebreak, grandfathered for all-pre-activation keys),
        // ledger application, and re-resolution triggers live there.
        // Fast path (no residents): fall through to the normal pipeline,
        // which carries its own re-resolution trigger for conflict-descendant
        // insertions (see STEP 1c + STEP 6b).
        {
            let has_conflict = !dag
                .read()
                .await
                .find_sender_nonce_conflicts(&tx.sender, tx.account_nonce)
                .is_empty();
            if has_conflict {
                return self
                    .process_conflict(tx, dag, ledger, mempool, mode)
                    .await;
            }
        }

        // STEP 1: PURE VALIDATION — the PoW + signature gate. NO state access,
        // no locks. This gate MUST pass before anything is parked in the
        // orphan store (H1): parking unvalidated transactions let anyone fill
        // disk and memory with garbage and trigger unbounded P2P re-requests.
        self.validator.validate_pure(&tx, mode)?;

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
        // PHASE 4B: re-resolution trigger bookkeeping. The newcomer may
        // descend from tracked conflicts (its work accrues to their
        // subtrees): record affected keys + their pre-insert winners now
        // (read locks held); STEP 6b recomputes post-insert and rebuilds
        // iff any winner flipped. Read-only, no state touched.
        let trigger_keys = dag_read.affected_conflict_keys(&tx.parents);
  let trigger_pre = self.conflict_winners_for(&dag_read, &trigger_keys);
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

        // STEP 6b: RE-RESOLUTION TRIGGER (PHASE 4B). The newcomer's work
        // accrues to its ancestors' subtrees: if any tracked conflict key was
        // affected (trigger_keys from STEP 1c), recompute and rebuild iff a
        // winner flipped. With no flip the STEP-4 live state stands (it is
        // rebuild-equivalent by the same live≈rebuild trust as the base
        // protocol — winners unchanged, newcomer applied). With a flip the
        // full replay re-derives the flipped world (the newcomer's STEP-4
        // transfer included or correctly dropped by the replay).
        if !trigger_keys.is_empty() {
  let trigger_post = self.conflict_winners_for(&dag, &trigger_keys);
            if trigger_post != trigger_pre {
                tracing::info!(
                    "🔄 Descendant arrival flipped conflict winner(s); rebuilding"
                );
  self.rebuild_for_era(&dag, &mut ledger);
            }
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
        //
        // PHASE 3E (M1): either persist call can fail (disk full, I/O error,
        // Sled transaction conflict). STEPS 4–7 already mutated memory, so a
        // bare Err would leave memory AHEAD of disk while reporting failure.
        // Roll back to the pre-apply snapshot (symmetric with the STEP 4/6
        // failure paths) so Err means "nothing applied": the drainer's
        // transient requeue then replays cleanly (the dup-gate precedes any
        // mutation, so the retry can never double-apply), and a crash lands
        // on consistent-older state in both windows (put-failed: tx absent
        // everywhere; save-failed: tx row present, ledger rebuilt from it).
        if let Some(storage) = ledger.storage() {
            let storage_read = storage.read().await;
            if let Err(e) = storage_read.put_transaction(&tx) {
                tracing::error!("❌ Failed to persist transaction to Sled: {}", e);
                Self::rollback_apply(&mut dag, &mut ledger, &ledger_snapshot, &tx.id);
                drop(ledger);
                drop(dag);
                drop(mempool);
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
        // P4-incremental: persist only the accounts modified by this tx
        // (sender + receiver + burn address = O(3) writes vs O(N) full sweep).
        if let Err(e) = ledger.save_dirty().await {
            tracing::error!("❌ Persistence failed: {}", e);
            // PHASE 3E (M1): same rollback as above (see comment at STEP 8).
            Self::rollback_apply(&mut dag, &mut ledger, &ledger_snapshot, &tx.id);
            drop(ledger);
            drop(dag);
            drop(mempool);
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

    /// PHASE 4B: conflict-path acceptance (CDW + loser retention).
    ///
    /// Entry: STEP 0 detected resident txs sharing the newcomer's
    /// (sender, nonce). The newcomer is validated (pure + DAG, orphan gate
    /// included) and INSERTED — winner or loser, never pruned, never rejected
    /// for conflicting. Ledger effects apply ONLY via rebuild, and only when
    /// some tracked winner flipped (newcomer effects included); otherwise the
    /// ledger stands (newcomer sits unapplied as residue).
    ///
    /// Deliberate deviations from the normal path, all argued:
    /// - NO validate_ledger gate: a would-be winner is routinely unfundable
    ///   in the incumbent loser's world; funding is evaluated at rebuild time
    ///   in winner-world (where the winner IS fundable if legitimately funded
    ///   at all). Gating here would veto valid winners (the exact bug this
    ///   redesign removes).
    /// - NO live transfer (no STEP-4 equivalent): effects flow exclusively
    ///   through rebuild_from_dag, so a flip can never half-apply.
    /// - Fee policy unchanged: the accept funnel fee-gates before the mempool;
    ///   min_fee is therefore not re-checked here.
    /// V-21 preserved: pure validation precedes ANY mutation, in the caller
    /// mode (3B consistency).
    async fn process_conflict(
        &self,
        tx: Transaction,
        dag: &Arc<RwLock<DAG>>,
        ledger: &Arc<RwLock<Ledger>>,
        mempool: &Arc<RwLock<Mempool>>,
        mode: ValidationMode,
    ) -> Result<(), ProcessingError> {
        self.validator.validate_pure(&tx, mode)?;
        // Orphan gate (same shape as STEP 1b): missing parents park, they
        // must never be inserted without their ancestry.
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
            // Full DAG checks (duplicate id, parents present, parent-ts
            // monotonicity). No sender-conflict rejection (retention).
            self.validator.validate_dag(&tx, &dag_read)?;
        }
        // Write locks (same order/discipline as the normal path).
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
        // Snapshot for M1 rollback.
        let ledger_snapshot = ledger.clone();
        // Pre-insert winners: own key (trivial if sole resident) + ancestor
        // keys the newcomer descends from (its work accrues to their subtrees).
        let mut keys = dag.affected_conflict_keys(&tx.parents);
        keys.push((tx.sender, tx.account_nonce));
        keys.sort();
        keys.dedup();
  let pre = self.conflict_winners_for(&dag, &keys);
        // Insert (retained win or lose — never pruned, never rejected).
        if let Err(e) = dag.add_transaction_validated(tx.clone()) {
            tracing::error!("❌ Conflict DAG add failed: {}", e);
            *ledger = ledger_snapshot;
            drop(ledger);
            drop(dag);
            drop(mempool);
            return Err(ProcessingError::DagError(format!("DAG add failed: {}", e)));
        }
        // Re-resolve; rebuild iff any winner flipped (newcomer effects apply
        // ONLY through the rebuild — never live-transferred on this path).
  let post = self.conflict_winners_for(&dag, &keys);
        if post != pre {
            tracing::info!(
  "🔄 Conflict re-resolved (flip): {:?} -> {:?}",
                pre.iter()
                    .map(|(_, id)| hex::encode(&id[..4]))
                    .collect::<Vec<_>>(),
                post.iter()
                    .map(|(_, id)| hex::encode(&id[..4]))
                    .collect::<Vec<_>>(),
            );
  self.rebuild_for_era(&dag, &mut ledger);
        }
        // Terminal disposition (DAG-held, winner or retained loser alike).
        mempool.remove_transaction(&tx.id);
        // Persistence (mirror STEP 8, M1 rollback on either failure).
        if let Some(storage) = ledger.storage() {
            let storage_read = storage.read().await;
            if let Err(e) = storage_read.put_transaction(&tx) {
                tracing::error!("❌ Failed to persist conflict tx to Sled: {}", e);
                Self::rollback_apply(&mut dag, &mut ledger, &ledger_snapshot, &tx.id);
                drop(ledger);
                drop(dag);
                drop(mempool);
                return Err(ProcessingError::PersistenceError(format!(
                    "Transaction persist failed: {}",
                    e
                )));
            }
        }
        if let Err(e) = ledger.save_dirty().await {
            tracing::error!("❌ Conflict persistence failed: {}", e);
            Self::rollback_apply(&mut dag, &mut ledger, &ledger_snapshot, &tx.id);
            drop(ledger);
            drop(dag);
            drop(mempool);
            return Err(ProcessingError::PersistenceError(format!(
                "Save failed: {}",
                e
            )));
        }
        tracing::info!(
            "✅ Conflict tx processed (retained): {}",
            hex::encode(tx.id)
        );
        Ok(())
    }

  // ====================================================================
  // PHASE 4G: stake admission entries (vote / bond / unbond). Shared by
  // RPC, P2P and node vote tasks  -  the ONLY way stake objects enter the
  // registry (same single-entry discipline as process() for txs).
  //
  // LOCK ORDER (global): dag -> registry -> ledger -> mempool, with
  // standalone single-lock phases allowed anywhere. Concretely: no path
  // ever holds the ledger while acquiring registry, and no path ever
  // holds the registry while acquiring dag (vote phases take dag first,
  // or take the registry alone); the tx conflict paths take the
  // registry LAST via try_read (fail-fast, never waits). try_* failures
  // map to LockError (transient requeue, same discipline as dag/ledger).
  // sweep_matured is phase-separated (one guard at a time) and therefore
  // order-exempt by construction.
  //
  // PERSISTENCE: every mutation persists via storage.save_registry
  // (authoritative rewrite + manifest; a crash before the manifest write
  // fails closed at next boot). INTERIM cost: O(registry) per event  - 
  // votes/bonds are validator-scale (not tx-scale); batched checkpointing
  // is a perf TODO, not a correctness gap. Votes lost to a crash before
  // persist are re-gossipable (producers re-emit per epoch).
  // ====================================================================

  /// PHASE 4G: admit a finality vote. Returns the insert disposition:
  /// Accepted (new weight), Duplicate (idempotent replay, no-op),
  /// Equivocated (slash applied + evidence; triggers full re-resolution).
  /// Re-resolution: the vote's key is re-decided (finalize attempt +
  /// quorum-loss invalidation check); the ledger rebuilds iff a decision
  /// is created/voided or the winner may have flipped toward the new
  /// vote (post-winner == vote side). Equivocation ALWAYS rebuilds (a
  /// slash zeroes weight on every key the slasher voted on) after a
  /// finalized-key quorum sweep on the vote's key.
  pub async fn process_vote(
        &self,
  vote: Vote,
        dag: &Arc<RwLock<DAG>>,
        ledger: &Arc<RwLock<Ledger>>,
  ) -> Result<VoteInsertOutcome, ProcessingError> {
  let registry = match &self.stake_registry {
  None => {
  return Err(ProcessingError::DagError(
  "stake registry not attached".to_string(),
  ))
                }
  Some(r) => r.clone(),
            };
  // Storage handle first (standalone phase  -  no locks held).
  let storage_opt = ledger.read().await.storage();
  let at_epoch = current_epoch();
  let key = (vote.conflict_sender, vote.conflict_nonce);
  let vote_side = vote.side;
  // F-L1: release matured exits first (frees funds validation may need;
  // deterministic, epoch-pure; see sweep_matured).
  Self::sweep_matured(&registry, ledger).await?;

  // Phase A: validate + insert (registry alone).
  let outcome = {
  let mut reg = registry.write().await;
  if let Err(e) = self.validator.validate_vote(&vote, &reg, at_epoch) {
  return Err(ProcessingError::ValidationFailed(e));
        }
  let outcome = reg.insert_vote(vote);
  if matches!(
  outcome,
  VoteInsertOutcome::Accepted | VoteInsertOutcome::Equivocated { .. }
    ) {
  Self::persist_registry(&reg, &storage_opt).await?;
    }
  outcome
            };
  if outcome == VoteInsertOutcome::Duplicate {
  return Ok(outcome);
    }

  // Phase B/C: re-resolve the vote's key (dag read, then registry
  // write  -  dag -> registry order) with finalize + invalidation.
  let mut need_rebuild = matches!(outcome, VoteInsertOutcome::Equivocated { .. });
        {
                let dag_guard = dag.read().await;
  let mut reg = registry.write().await;
  let members = dag_guard.find_sender_nonce_conflicts(&key.0, key.1);
  // F-V1 era gate: the finality machinery below (finalize attempt,
  // quorum-loss invalidation, plurality trigger) runs ONLY for
  // post-V6 keys (newest member decides, same predicate as fork
  // choice). Votes for pre-V6 keys stay ADMITTED (Phase A idempotent
  // insert keeps vote sets convergent across nodes) but can never
  // create, void, or trigger on a decision there: pre-V6 conflicts
  // resolve by the frozen legacy rule, which reads no registry state.
  // (Deliberately not a rejection: admitting keeps gossip sets
  // convergent; finalizing would create dead records.)
  let post_v6 = members.iter().any(|id| {
  dag_guard
  .get_transaction(*id)
  .map(|t| Transaction::is_v6_active_at(t.timestamp))
  .unwrap_or(false)
  });
  if members.len() >= 2 && post_v6 {
  // Finalize attempt (sticky: existing decisions returned as-is).
  let finalized_before = reg.finalized_winner(&key);
  let finalized_now = reg.try_finalize(key, &members, at_epoch, |m, txid| {
  dag_guard.is_strict_descendant(m, txid)
  });
  if finalized_now.is_some() && finalized_before.is_none() {
  need_rebuild = true;
            }
  // Quorum-loss invalidation: a valid finality whose support
  // fell below quorum (slash/unbond since finalizing) is
  // DELETED so later re-resolution starts clean.
  if let Some(winner) = reg.finalized_winner(&key) {
  let support = reg.support_for(key, &winner, at_epoch, |txid| {
  dag_guard.is_strict_descendant(&winner, txid)
  });
  let total = reg.eligible_stake_total(at_epoch);
  if !StakeRegistry::quorum_met(support, total) {
  reg.invalidate_finality(&key);
  need_rebuild = true;
            }
        }
  // Plurality flip toward the new vote (Accepted only;
  // Equivocated already forces a rebuild above).
  if !need_rebuild {
  if let Some(winner) =
  dag_guard.resolve_conflict_key_v6(&key.0, key.1, &reg, at_epoch)
        {
  if winner == vote_side {
  need_rebuild = true;
            }
        }
    }
}
  if need_rebuild {
  // Persist decision changes before replaying them.
  Self::persist_registry(&reg, &storage_opt).await?;
    }
  drop(reg);
                drop(dag_guard);
}

  // Phase D: global replay under v6 winners + ledger persist.
  if need_rebuild {
  let dag_guard = dag.read().await;
  let reg = registry.read().await;
  let mut ledger_guard = ledger.write().await;
  ledger_guard.rebuild_from_dag_v6(&dag_guard, &reg, at_epoch);
  if let Err(e) = ledger_guard.save_dirty().await {
  return Err(ProcessingError::PersistenceError(format!(
  "Save failed: {}",
  e
  )));
    }
    }
  Ok(outcome)
    }

  /// PHASE 4G: admit a bond intent (lock funds into voting weight).
  /// Maturation is measured from the SIGNED creation epoch (deterministic
  /// across nodes  -  arrival times differ; validation windows it to
  /// near-current so backdating cannot grant instant maturity). New bonds
  /// are immature for BOND_MATURATION_EPOCHS, hence ineligible
  /// immediately  -  no winner can flip, no rebuild. (Top-ups likewise
  /// reset maturation; see StakeRegistry::apply_bond.) Replays of the
  /// same bond id are idempotent Ok (no double top-up  -  each top-up
  /// needs a FRESH signature, i.e. a new id).
  pub async fn process_bond(
  &self,
  bond: Bond,
  ledger: &Arc<RwLock<Ledger>>,
    ) -> Result<(), ProcessingError> {
  let registry = match &self.stake_registry {
  None => {
  return Err(ProcessingError::DagError(
  "stake registry not attached".to_string(),
  ))
            }
  Some(r) => r.clone(),
        };
  let at_epoch = current_epoch();
  // F-L1: sweep matured exits (frees funds the bond check may need)
  // before validation, then reconcile orphaned locks (crash window
  // between fund-lock save and registry persist, sec. sweep_matured).
  Self::sweep_matured(&registry, ledger).await?;
  // Ledger read standalone (funds check needs no other lock).
                let ledger_guard = ledger.read().await;
  let storage_opt = ledger_guard.storage();
  let validation = {
  let reg = registry.read().await;
  self.validator
  .validate_bond(&bond, &ledger_guard, &reg, at_epoch)
        };
                drop(ledger_guard);
  if let Err(e) = validation {
  return Err(ProcessingError::ValidationFailed(e));
        }
  let mut reg = registry.write().await;
  if !reg.note_bond_seen(bond.id()) {
                return Ok(());
    }
  reg.apply_bond(bond.validator, bond.amount, bond.epoch)
  .map_err(ProcessingError::DagError)?;
  Self::persist_registry(&reg, &storage_opt).await?;
  drop(reg);
  // F-L1: lock the bonded funds AFTER the registry record exists
  // (lock-without-record orphans self-heal in sweep_matured; record-
  // without-lock cannot persist because any failure below is Err).
  // Re-checked under the write guard: spendable may have moved since
  // the validation read (single-node interleaving).
  {
  let mut ledger_guard = ledger.write().await;
  if ledger_guard.spendable(&bond.validator) < bond.amount {
  return Err(ProcessingError::ValidationFailed(
  ValidationError::InsufficientBalance {
  required: bond.amount,
  available: ledger_guard.spendable(&bond.validator),
  },
  ));
        }
  ledger_guard
  .bond_lock(&bond.validator, bond.amount)
  .map_err(ProcessingError::LedgerError)?;
  if let Err(e) = ledger_guard.save_dirty().await {
  return Err(ProcessingError::PersistenceError(format!(
  "Save failed: {}",
  e
  )));
        }
  }
        Ok(())
            }

  /// PHASE 4G: admit an unbond intent (begin exit; voting ends at
  /// acceptance  -  clean cutover). Release is measured from the SIGNED
  /// epoch (deterministic across nodes; validation windows it to
  /// near-current so backdating cannot grant early exits). Support drops
  /// immediately, so winners may flip on any key the validator backed:
  /// unconditional global rebuild + finalized-key quorum sweep (same
  /// invalidation rule as votes), then persist.
  pub async fn process_unbond(
  &self,
  unbond: Unbond,
  dag: &Arc<RwLock<DAG>>,
  ledger: &Arc<RwLock<Ledger>>,
  ) -> Result<(), ProcessingError> {
  let registry = match &self.stake_registry {
  None => {
  return Err(ProcessingError::DagError(
  "stake registry not attached".to_string(),
  ))
            }
  Some(r) => r.clone(),
        };
  let storage_opt = ledger.read().await.storage();
  let at_epoch = current_epoch();
  // F-L1: sweep matured exits before validation (same rationale as
  // process_vote/process_bond).
  Self::sweep_matured(&registry, ledger).await?;
            {
  let mut reg = registry.write().await;
  if let Err(e) = self.validator.validate_unbond(&unbond, &reg, at_epoch) {
  return Err(ProcessingError::ValidationFailed(e));
        }
  reg.apply_unbond(unbond.validator, unbond.epoch)
  .map_err(ProcessingError::DagError)?;
  Self::persist_registry(&reg, &storage_opt).await?;
    }
  // Quorum sweep over finalized keys (dag read, then registry write).
                {
  let dag_guard = dag.read().await;
  let mut reg = registry.write().await;
  let mut voided = false;
  for fkey in reg.finalized_keys() {
  if let Some(winner) = reg.finalized_winner(&fkey) {
  let support = reg.support_for(fkey, &winner, at_epoch, |txid| {
  dag_guard.is_strict_descendant(&winner, txid)
  });
  let total = reg.eligible_stake_total(at_epoch);
  if !StakeRegistry::quorum_met(support, total) {
  reg.invalidate_finality(&fkey);
  voided = true;
    }
        }
    }
  if voided {
  Self::persist_registry(&reg, &storage_opt).await?;
        }
  drop(reg);
  drop(dag_guard);
        }
  // Unconditional replay (support dropped on live keys too).
        {
  let dag_guard = dag.read().await;
  let reg = registry.read().await;
  let mut ledger_guard = ledger.write().await;
  ledger_guard.rebuild_from_dag_v6(&dag_guard, &reg, at_epoch);
  if let Err(e) = ledger_guard.save_dirty().await {
  return Err(ProcessingError::PersistenceError(format!(
  "Save failed: {}",
  e
  )));
        }
        }
  Ok(())
            }

    /// PHASE 4I (F-L1): release matured unbondings (registry state +
    /// ledger funds), called at the head of every stake admission and by
    /// the node periodic task. Epoch-pure and idempotent: releasable iff
    /// now_epoch >= release_epoch (monotone: once releasable, always
    /// releasable). Late-releasing nodes stay CONSERVATIVE (more locked =
    /// reject spends others accept; drainer requeues transiently, rebuild
    /// holds pending) and converge without intervention. Slashed funds
    /// are NEVER released (release_matured only transitions Unbonding;
    /// slash is permanent economic loss with zero supply invention).
    /// Also reconciles orphaned locks (locked funds with NO registry
    /// record: only producible by a crash between fund-lock save and
    /// registry persist): released back to spendable, since no position
    /// backs them.
    /// LOCKING: deliberately phase-separated (never two guards at once),
    /// so no lock-ordering hazard exists by construction. Returns the
    /// released addresses (empty = no-op).
    pub async fn sweep_matured(
        registry: &Arc<RwLock<StakeRegistry>>,
        ledger: &Arc<RwLock<Ledger>>,
    ) -> Result<Vec<[u8; 32]>, ProcessingError> {
        let at_epoch = current_epoch();
        // Storage handle first (standalone phase - no locks held).
        let storage_opt = ledger.read().await.storage();
        // Phase 1: registry state transitions (alone).
        let released: Vec<([u8; 32], u64)> = {
            let mut reg = registry.write().await;
            let addrs = reg.release_matured(at_epoch);
            if addrs.is_empty() {
                Vec::new()
            } else {
                let amounts = addrs
                    .iter()
                    .map(|a| (*a, reg.bonded_amount(a)))
                    .collect::<Vec<_>>();
                Self::persist_registry(&reg, &storage_opt).await?;
                amounts
            }
        };
        // Phase 2: ledger fund releases (alone).
        let mut out: Vec<[u8; 32]> = Vec::with_capacity(released.len());
        if !released.is_empty() {
            let mut ledger_guard = ledger.write().await;
            for (addr, amount) in &released {
                ledger_guard.bond_release(addr, *amount);
                out.push(*addr);
            }
            if let Err(e) = ledger_guard.save_dirty().await {
                return Err(ProcessingError::PersistenceError(format!(
                    "Save failed: {}",
                    e
                )));
            }
        }
        // Phase 3: orphan reconciliation (each guard alone, sequentially).
        // Candidates snapshot first; registry membership next; releases
        // last. A lock with no backing record is crash debris by
        // construction (locks are only ever created alongside a bond
        // admission whose registry record precedes them in code order).
        let candidates: Vec<([u8; 32], u64)> = {
            let ledger_guard = ledger.read().await;
            let mut found = Vec::new();
            for (addr_hex, locked) in ledger_guard.locked_entries() {
                if locked == 0 {
                    continue;
                }
                if let Ok(bytes) = hex::decode(&addr_hex) {
                    if let Ok(addr) = <[u8; 32]>::try_from(bytes) {
                        found.push((addr, locked));
                    }
                }
            }
            found
        };
        if !candidates.is_empty() {
            let reg = registry.read().await;
            let orphans: Vec<([u8; 32], u64)> = candidates
                .into_iter()
                .filter(|(addr, _)| reg.validator_state(addr).is_none())
                .collect();
            drop(reg);
            if !orphans.is_empty() {
                let mut ledger_guard = ledger.write().await;
                for (addr, locked) in &orphans {
                    ledger_guard.bond_release(addr, *locked);
                    out.push(*addr);
                }
                if let Err(e) = ledger_guard.save_dirty().await {
                    return Err(ProcessingError::PersistenceError(format!(
                        "Save failed: {}",
                        e
                    )));
                }
            }
        }
        Ok(out)
    }

    /// PHASE 4G: persist helper - authoritative registry rewrite (no-op
  /// without storage, e.g. pure in-memory tests). save_registry fails
  /// closed on I/O (Err => caller reports PersistenceError, memory state
  /// stands  -  the next event re-saves; boot never reads partial state
  /// thanks to the manifest).
  async fn persist_registry(
  reg: &StakeRegistry,
  storage_opt: &Option<Arc<RwLock<crate::storage::Storage>>>,
  ) -> Result<(), ProcessingError> {
  if let Some(storage) = storage_opt {
  let storage_guard = storage.read().await;
  if let Err(e) = storage_guard.save_registry(reg) {
  return Err(ProcessingError::PersistenceError(format!(
  "Stake persist failed: {}",
  e
  )));
        }
                }
  Ok(())
            }

  /// PHASE 4B winners for `keys` against `dag`, in input order, with
  /// PHASE 4G era routing when a registry is attached: single-member keys
  /// resolve trivially to their sole member (no score needed); multi-member
  /// keys via resolve_conflict_key_v6 (finalized-first, then stake
  /// plurality, min-id tiebreak; pre-V6 keys delegate to the frozen legacy
  /// resolve_conflict_key). WITHOUT a registry: exact legacy behavior
  /// (resolve_conflict_key everywhere). Empty member lists are skipped
  /// (cannot happen in production  -  maintained index  -  but never panic on
  /// skew). Pure, deterministic; the flip detector compares pre/post
  /// vectors.
    ///
  /// LOCK DISCIPLINE: takes the registry as try_read (fail-fast LockError
  /// discipline like the dag/ledger/mempool guards here  -  a contended
  /// registry means a vote/bond mutation is in flight RIGHT NOW, and that
  /// mutation's own trigger re-resolves the same keys after committing, so
  /// a transient legacy answer here can never stick). Global order is
  /// dag -> registry -> ledger -> mempool (registry always AFTER dag,
  /// never before, never held while acquiring dag).
    fn conflict_winners_for(
  &self,
        dag: &DAG,
        keys: &[([u8; 32], u64)],
    ) -> Vec<(([u8; 32], u64), TransactionId)> {
  // Registry view (fail-fast): None/absent => pure legacy path.
  let reg_guard = match &self.stake_registry {
  None => None,
  Some(reg) => match reg.try_read() {
  Ok(g) => Some(g),
  Err(_) => None,
  },
        };
  let at_epoch = current_epoch();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let members = dag.find_sender_nonce_conflicts(&key.0, key.1);
            if members.is_empty() {
                continue;
            }
            let winner = if members.len() == 1 {
                members[0]
            } else {
  let resolved = match &reg_guard {
  Some(reg) => dag.resolve_conflict_key_v6(&key.0, key.1, reg, at_epoch),
  None => dag.resolve_conflict_key(&key.0, key.1),
        };
  match resolved {
                    Some(id) => id,
                    None => continue,
                }
            };
            out.push((*key, winner));
        }
        out
        }

  /// PHASE 4G: era-branched ledger replay for the conflict paths. With an
  /// attached registry the replay consumes v6 winners (finalized-first);
  /// without, the frozen legacy replay. Callers hold dag+ledger already
  /// (write) and pass the registry view implicitly via self (try_read  - 
  /// same transient-legacy discipline as conflict_winners_for).
  fn rebuild_for_era(&self, dag: &DAG, ledger: &mut Ledger) {
  match &self.stake_registry {
  None => ledger.rebuild_from_dag(dag),
  Some(reg) => match reg.try_read() {
  Ok(view) => {
  let at_epoch = current_epoch();
  ledger.rebuild_from_dag_v6(dag, &view, at_epoch);
    }
  Err(_) => ledger.rebuild_from_dag(dag),
  },
            }
    }

    /// PHASE 3E (M1): undo STEPS 4–7 after a STEP-8 persistence failure so an
    /// Err means "nothing applied" (symmetric with the STEP 4/6 failure
    /// paths, which restore the same snapshot). The ledger is restored from
    /// the pre-apply snapshot (balances, nonces, applied marks, burned fees —
    /// `Ledger: Clone` captures all of it); the DAG entry added at STEP 6 is
    /// removed (`remove_transaction` maintains tips/weights/index, and is a
    /// safe no-op if a concurrent prune already took it). The mempool slot is
    /// deliberately left to the caller: the drainer requeues on transient
    /// errors (its retry then replays from a clean state — the dup-gate
    /// precedes any mutation, so no double-apply), and a crash lands on
    /// consistent-older state either way (see STEP 8 comment).
    fn rollback_apply(
        dag: &mut DAG,
        ledger: &mut Ledger,
        snapshot: &Ledger,
        tx_id: &TransactionId,
    ) {
        dag.remove_transaction(tx_id);
        *ledger = snapshot.clone();
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
        let result = processor
            .process(tx, &dag, &ledger, &mempool, 10, ValidationMode::Fresh)
            .await;
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

        let result = processor
            .process(tx, &dag, &ledger, &mempool, 10, ValidationMode::Fresh)
            .await;
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

        let result = processor
            .process(tx, &dag, &ledger, &mempool, 10, ValidationMode::Fresh)
            .await;
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
            .process(
                tx.clone(),
                &dag,
                &ledger,
                &mempool,
                1000,
                ValidationMode::Fresh,
            )
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
        // PHASE 3B (C2): the validator `difficulty` knob is NOT read by
        // validate_pure (timestamp-derived difficulty rules); mine at the
        // policy-required 20 bits for these pre-activation fixtures so the
        // test exercises conflict logic, not PoW rejection. Default processor
        // = production configuration.
        let processor = TransactionProcessor::new();
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
            tx.nonce = tx.mine_nonce(20);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            assert!(tx.verify_pow(20));
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
        // PHASE 4B: both arrivals accepted (loser retention) — the run
        // closure no longer takes a loser flag and expects Ok twice. The
        // ORDER-INVARIANCE property under test is unchanged (identical DAG
        // sets, identical ledgers, identical fingerprints in both orders);
        // only the expected SET grew (loser retained, decided at ledger via
        // CDW/min-id — grandfathered min-id here, same winner as before).
        let run = |first: Transaction, second: Transaction| {
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

                // PHASE 3B (C2): Historical = the production DAG-entry mode
                // (the drainer evaluates every tx timelessly; Fresh is an
                // edge-submission policy enforced at RPC accept, and the 1970
                // fixtures predate the migration timestamp policy). This test
                // proves timeless DAG/ledger properties (order invariance),
                // so it runs in the production configuration. Assertions
                // below are unchanged.
                processor_ref
                    .process(
                        first,
                        &dag,
                        &ledger,
                        &mempool,
                        10,
                        ValidationMode::Historical,
                    )
                    .await
                    .expect("first arrival is accepted");
                processor_ref
                    .process(
                        second,
                        &dag,
                        &ledger,
                        &mempool,
                        10,
                        ValidationMode::Historical,
                    )
                    .await
                    .expect("second arrival is retained (PHASE 4B)");
                (dag, ledger)
            }
        };

        let (dag_wl, ledger_wl) = run(winner.clone(), loser.clone()).await;
        let (dag_lw, ledger_lw) = run(loser.clone(), winner.clone()).await;

        // Identical DAG outcome: funding + winner + retained loser, both orders.
        {
            let dag_wl_guard = dag_wl.read().await;
            let dag_lw_guard = dag_lw.read().await;
            assert_eq!(
                dag_wl_guard.transaction_count(),
                3,
                "order 1: funding + winner + retained loser"
            );
            assert_eq!(
                dag_lw_guard.transaction_count(),
                3,
                "order 2: funding + winner + retained loser"
            );
            assert!(dag_wl_guard.transactions().contains_key(&winner.id));
            assert!(dag_lw_guard.transactions().contains_key(&winner.id));
            assert!(dag_wl_guard.transactions().contains_key(&loser.id));
            assert!(dag_lw_guard.transactions().contains_key(&loser.id));
            // WEIGHT: identical in both orders too — the DAG maintains it the
            // same way whichever transaction arrives first. All three roots
            // (winner, retained loser, funding — genesis parents each) →
            // each subtree = {itself} = 1.
            assert_eq!(dag_wl_guard.get_transaction(winner.id).unwrap().weight, 1.0);
            assert_eq!(dag_lw_guard.get_transaction(winner.id).unwrap().weight, 1.0);
            assert_eq!(dag_wl_guard.get_transaction(loser.id).unwrap().weight, 1.0);
            assert_eq!(dag_lw_guard.get_transaction(loser.id).unwrap().weight, 1.0);
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

    /// S11 reinforcement (restart/resync dimension), PHASE 4B note: this test
    /// replays the LEGACY boot sequence explicitly (canonical_resolve prunes
    /// losers, then topological rebuild) on a simulated crash residue and
    /// asserts winner-only convergence with identical balances. The live node
    /// boot path (node.rs) no longer prunes (loser retention — both sides are
    /// legitimate DAG residents, decided at ledger via CDW/min-id); the
    /// canonical helper itself is unchanged (pure min-id, still correct for
    /// pre-activation data), so this test pins the legacy helper, not current
    /// boot behavior. See test_conflict_rebuild_preserves_valid_state for the
    /// retention-era boot equivalence proof.
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
            processor
                .validator
                .validate_pure(tx, ValidationMode::Fresh)
                .unwrap();
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
                .process(
                    tx.clone(),
                    &dag,
                    &ledger,
                    &mempool,
                    10,
                    ValidationMode::Fresh,
                )
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
                    .process(
                        tx.clone(),
                        &dag,
                        &ledger,
                        &mempool,
                        10,
                        ValidationMode::Fresh,
                    )
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
        // PHASE 3B (C2): see note on test_double_spend_order_invariance —
        // timestamp-derived difficulty rules (validator knob unread); mine
        // the policy-required 20 bits for this pre-activation fixture.
        // Default processor = production configuration.
        let processor = TransactionProcessor::new();
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
        tx.nonce = tx.mine_nonce(20);
        tx.signature = wallet.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();

        // PHASE 3B (C2): Historical = the production DAG-entry mode (see
        // note on test_double_spend_order_invariance). Phantom-nonce healing
        // is a timeless recovery property; assertions below are unchanged.
        processor
            .process(
                tx.clone(),
                &dag,
                &ledger,
                &mempool,
                10,
                ValidationMode::Historical,
            )
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
        // PHASE 3B (C2): see note on test_double_spend_order_invariance —
        // timestamp-derived difficulty rules (validator knob unread); mine
        // the policy-required 20 bits for this pre-activation fixture.
        // Default processor = production configuration.
        let processor = TransactionProcessor::new();
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
        tx.nonce = tx.mine_nonce(20);
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

        // PHASE 3B (C2): Historical = the production DAG-entry mode (see
        // note on test_double_spend_order_invariance). DAG healing without
        // replay is a timeless recovery property; assertions below unchanged.
        processor
            .process(
                tx.clone(),
                &dag,
                &ledger,
                &mempool,
                10,
                ValidationMode::Historical,
            )
            .await
            .expect("recovery must heal the DAG");
        // No double debit, DAG healed.
        assert_eq!(ledger.read().await.get_balance(&sender), 10000 - 110);
        assert_eq!(ledger.read().await.get_balance(&receiver), 100);
        assert!(dag.read().await.transactions().contains_key(&tx.id));
    }

    /// PHASE 3B (C1) + PHASE 4B (retention): STEP-0 / STEP-1 validation-mode
    /// consistency under loser retention.
    ///
    /// Regression shape: a conflict winner whose timestamp is stale under
    /// live policy (pre-activation here → BackdatedTimestamp in Fresh) must
    /// be treated IDENTICALLY no matter which conflicting tx arrived first.
    /// Post-fix both steps use the caller mode:
    /// - Historical: the winner installs AND the loser is retained in BOTH
    ///   orders (healing works; no Fresh veto in the winner branch);
    /// - Fresh: neither installs in BOTH orders (consistent rejection at the
    ///   pure gate — still no split; only funding remains in both DAGs).
    /// Cross-mode outcomes legitimately differ (policy, not inconsistency);
    /// WITHIN one mode, arrival order must not matter. Compares DAG id sets,
    /// balances and supply (fingerprint) across A-then-B vs B-then-A.
    #[tokio::test]
    async fn test_step0_validation_mode_consistency() {
        use crate::wallet::Wallet;
        let processor = TransactionProcessor::new();
        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();

        // Pre-activation timestamps → 20-bit PoW required. Mined once and
        // reused across all four runs: policy-valid under Historical
        // (genuine-history shape), policy-rejected under Fresh — exactly the
        // C1 divergence shape. Default processor = production configuration
        // (timestamp-derived difficulty; the validator knob is unread).
        let pre_ts =
            crate::transaction::Transaction::DIFFICULTY_MIGRATION_TS - 3_600_000;
        let build = |receiver: [u8; 32], ts_off: u64| {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                receiver,
                100,
                10,
                pre_ts + ts_off,
                0,
                1,
                vec![0u8; 64],
                pk.clone(),
            );
            tx.nonce = tx.mine_nonce(20);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            assert!(tx.verify_pow(20));
            tx
        };
        let tx_a = build([0xAAu8; 32], 0);
        let tx_b = build([0xBBu8; 32], 1000);
        assert_ne!(tx_a.id, tx_b.id);
        let (winner, loser) = if tx_a.id <= tx_b.id {
            (tx_a.clone(), tx_b.clone())
        } else {
            (tx_b.clone(), tx_a.clone())
        };

        let processor_ref = &processor;
        let run = |first: Transaction,
                   second: Transaction,
                   mode: ValidationMode| {
            let winner = winner.clone();
            let loser = loser.clone();
            async move {
                let dag = Arc::new(RwLock::new(DAG::new()));
                let ledger = Arc::new(RwLock::new(Ledger::new()));
                let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

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
                    pre_ts,
                    0,
                    1,
                    vec![0u8; 64],
                    vec![1u8; 64],
                );
                dag.write()
                    .await
                    .add_transaction_validated(funding)
                    .expect("funding inserts");
                let dag_read = dag.read().await;
                ledger.write().await.rebuild_from_dag(&dag_read);
                drop(dag_read);

                let _ = processor_ref
                    .process(first, &dag, &ledger, &mempool, 10, mode)
                    .await;
                let _ = processor_ref
                    .process(second, &dag, &ledger, &mempool, 10, mode)
                    .await;

                // Fingerprint: DAG id set + balances + supply.
                let dag_guard = dag.read().await;
                let mut ids: Vec<[u8; 32]> =
                    dag_guard.transactions().keys().copied().collect();
                ids.sort();
                let winner_in = dag_guard.transactions().contains_key(&winner.id);
                let loser_in = dag_guard.transactions().contains_key(&loser.id);
                drop(dag_guard);
                let ledger_guard = ledger.read().await;
                let fp = (
                    ids,
                    ledger_guard.get_balance(&sender),
                    ledger_guard.get_balance(&winner.receiver),
                    ledger_guard.get_balance(&loser.receiver),
                    ledger_guard.total_supply(),
                );
                drop(ledger_guard);
                (fp, winner_in, loser_in)
            }
        };

        // PHASE 4B: retention — Historical installs the winner AND retains
        // the loser in BOTH orders (no prune anywhere on this path). The
        // C1 property under test is unchanged (same treatment regardless of
        // arrival order); only the expected SET grew (loser retained,
        // decided at ledger via CDW/min-id — grandfathered min-id here).
        let (fp_hw, w_hw, l_hw) = run(
            winner.clone(),
            loser.clone(),
            ValidationMode::Historical,
        )
        .await;
        let (fp_hl, w_hl, l_hl) = run(
            loser.clone(),
            winner.clone(),
            ValidationMode::Historical,
        )
        .await;
        assert!(w_hw && w_hl, "Historical: winner must install in both orders");
        assert!(l_hw && l_hl, "Historical: loser must be retained in both orders");
        assert_eq!(
            fp_hw, fp_hl,
            "Historical: fingerprint must be order-invariant"
        );

        // Fresh: winner rejected in BOTH orders (consistent rejection —
        // still no split; only funding remains in both DAGs).
        let (fp_fw, w_fw, l_fw) =
            run(winner.clone(), loser.clone(), ValidationMode::Fresh).await;
        let (fp_fl, w_fl, l_fl) =
            run(loser.clone(), winner.clone(), ValidationMode::Fresh).await;
        assert!(
            !w_fw && !w_fl && !l_fw && !l_fl,
            "Fresh: stale winner AND stale loser must both be rejected"
        );
        assert_eq!(
            fp_fw, fp_fl,
            "Fresh: fingerprint must be order-invariant"
        );
    }

    /// PHASE 4B (retention): STEP-0 loser retention end-to-end. A conflict
    /// resolved live through process() with a storage-backed ledger must
    /// leave BOTH sides persisted (winner installs, loser retained — no
    /// prune, no purge). Guards the batch_write call site (still exercised
    /// for other paths) and pins the retention invariant where the old
    /// prune+purge behavior lived: the store must hold the loser (future
    /// re-resolution needs it), the ledger must apply only the winner.
    /// (Pre-4B this test pinned prune+purge; the divergence is the specified
    /// CONSENSUS_BREAK — retention replaces deletion. MEDIUM: two 20-bit
    /// mines, policy-valid pre-activation fixtures, grandfathered min-id.)
    #[tokio::test]
    async fn test_step0_retains_loser_everywhere() {
        use crate::ledger::Ledger;
        use crate::storage::Storage;
        use crate::wallet::Wallet;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("open");
        let storage_arc = Arc::new(RwLock::new(storage));
        let processor = TransactionProcessor::new();
        let wallet = Wallet::from_secret_key(
            "6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef",
        )
        .expect("fixed test key");
        let sender = wallet.address();
        let pk = wallet.public_key_bytes();

        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(
            Ledger::new_with_storage(storage_arc.clone())
                .await
                .expect("ledger with storage"),
        ));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        // Fund the sender through the DAG (faucet -> sender).
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
        dag.write()
            .await
            .add_transaction_validated(funding)
            .expect("funding inserts");
        {
            let dag_read = dag.read().await;
            ledger.write().await.rebuild_from_dag(&dag_read);
        }

        // Conflicting pair (pre-activation ts → 20-bit PoW required).
        let pre_ts = crate::transaction::Transaction::DIFFICULTY_MIGRATION_TS
            - 3_600_000;
        let build = |receiver: [u8; 32]| {
            let mut tx = Transaction::new(
                [[0u8; 32]; 2],
                sender,
                receiver,
                100,
                10,
                pre_ts,
                0,
                1,
                vec![0u8; 64],
                pk.clone(),
            );
            tx.nonce = tx.mine_nonce(20);
            tx.signature = wallet.sign_transaction(&tx).expect("sign");
            tx.id = tx.compute_hash();
            assert!(tx.verify_pow(20));
            tx
        };
        let tx_a = build([0xAAu8; 32]);
        let tx_b = build([0xBBu8; 32]);
        assert_ne!(tx_a.id, tx_b.id);
        let (winner, loser) = if tx_a.id <= tx_b.id {
            (tx_a.clone(), tx_b.clone())
        } else {
            (tx_b.clone(), tx_a.clone())
        };

        // Loser first (accepted + persisted), then winner (retained pair).
        processor
            .process(
                loser.clone(),
                &dag,
                &ledger,
                &mempool,
                10,
                ValidationMode::Historical,
            )
            .await
            .expect("loser arrives first, no conflict yet");
        {
            let store = storage_arc.read().await;
            assert!(
                store.transaction_exists(loser.id).unwrap(),
                "loser persisted at accept"
            );
        }
        processor
            .process(
                winner.clone(),
                &dag,
                &ledger,
                &mempool,
                10,
                ValidationMode::Historical,
            )
            .await
            .expect("winner joins the retained pair");
        // DAG + ledger: winner installed, loser RETAINED (not pruned).
        assert!(dag.read().await.transactions().contains_key(&winner.id));
        assert!(dag.read().await.transactions().contains_key(&loser.id));
        assert_eq!(
            ledger.read().await.get_balance(&winner.receiver),
            100
        );
        assert_eq!(ledger.read().await.get_balance(&loser.receiver), 0);
        // Store: BOTH present (retention — re-resolution needs the loser).
        {
            let store = storage_arc.read().await;
            assert!(
                store.transaction_exists(winner.id).unwrap(),
                "winner persisted"
            );
            assert!(
                store.transaction_exists(loser.id).unwrap(),
                "retained loser must stay in storage"
            );
        }
    }

    /// PHASE 3E (M1): persist-failure rollback restores the pre-apply state.
    /// White-box: dirty the DAG+ledger exactly as STEPS 4–7 do (transfer +
    /// applied mark + nonce + DAG add), invoke rollback_apply, assert FULL
    /// restoration (balances, nonce, applied marks, supply, DAG membership,
    /// tips). Then prove clean replay: re-apply the same sequence (what the
    /// drainer retry does) and assert the funded outcome. No fault injection
    /// (Sled is reliable in-test): the trigger (persist Err → rollback at
    /// both STEP-8 sites) is pinned by inspection, and retry convergence
    /// rests on dup-gate-before-mutation (duplicate tests green). Sync, FAST.
    #[test]
    fn test_persist_error_after_apply() {
        let sender = [0x51u8; 32];
        let receiver = [0x52u8; 32];
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
            vec![0u8; 32],
        );
        tx.id = tx.compute_hash();
        let mut dag = DAG::new();
        let mut ledger = Ledger::new();
        ledger.set_balance(&sender, 10_000);
        let snapshot = ledger.clone();
        // STEPS 4–7 shape.
        ledger
            .transfer_internal(&sender, &receiver, 100, 10)
            .unwrap();
        ledger.mark_applied(&tx.id);
        ledger.set_nonce(&sender, 1);
        dag.add_transaction_validated(tx.clone()).unwrap();
        // Sanity: dirty.
        assert_eq!(ledger.get_balance(&sender), 9890);
        assert!(ledger.is_applied(&tx.id));
        assert!(dag.transactions().contains_key(&tx.id));
        // Rollback (what both STEP-8 failure paths now call).
        TransactionProcessor::rollback_apply(&mut dag, &mut ledger, &snapshot, &tx.id);
        // Restored.
        assert_eq!(ledger.get_balance(&sender), 10_000);
        assert_eq!(ledger.get_balance(&receiver), 0);
        assert_eq!(ledger.get_nonce(&sender), 0);
        assert!(!ledger.is_applied(&tx.id));
        assert_eq!(ledger.total_supply(), snapshot.total_supply());
        assert!(!dag.transactions().contains_key(&tx.id));
        assert_eq!(dag.transaction_count(), 0);
        assert_eq!(dag.tip_count(), 0);
        // Clean replay converges (the drainer-retry shape).
        ledger
            .transfer_internal(&sender, &receiver, 100, 10)
            .unwrap();
        ledger.mark_applied(&tx.id);
        ledger.set_nonce(&sender, 1);
        dag.add_transaction_validated(tx.clone()).unwrap();
        assert_eq!(ledger.get_balance(&sender), 9890);
        assert_eq!(ledger.get_balance(&receiver), 100);
        assert!(ledger.is_applied(&tx.id));
        assert!(dag.transactions().contains_key(&tx.id));
    }

    /// PHASE 3E (M1): restart converges after either persist-failure window.
    /// Funding flows through DAG txs (rebuild reseeds from genesis — manual
    /// set_balance would be wiped, same lesson as 3C H4). Window A
    /// (put-transaction failed: tx row absent): boot set = pre-apply →
    /// rebuild equals the snapshot world. Window B (save-dirty failed: tx
    /// row present, ledger stale): boot set includes tx → rebuild applies it
    /// (heals FORWARD). Both consistent, never half-applied. Fingerprints:
    /// balance maps, nonces, supply. Sync, FAST.
    #[test]
    fn test_restart_after_persist_failure() {
        let sender = [0x53u8; 32];
        let receiver = [0x54u8; 32];
        let faucet: [u8; 32] = hex::decode(crate::genesis::FAUCET_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap();
        let mut funding = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            sender,
            100_000,
            100,
            1234567890,
            0,
            0,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        funding.id = funding.compute_hash();
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
            vec![0u8; 32],
        );
        tx.id = tx.compute_hash();
        // Snapshot world: DAG {F}, ledger rebuilt (faucet is genesis-funded).
        let mut snap_dag = DAG::new();
        snap_dag
            .add_transaction_validated(funding.clone())
            .unwrap();
        let mut snapshot = Ledger::new();
        snapshot.rebuild_from_dag(&snap_dag);
        assert_eq!(snapshot.get_balance(&sender), 100_000);

        // Window A (put failed): persisted = {F} → rebuild == snapshot.
        let mut dag_a = DAG::new();
        dag_a
            .add_transaction_validated(funding.clone())
            .unwrap();
        let mut ledger_a = Ledger::new();
        ledger_a.rebuild_from_dag(&dag_a);
        assert_eq!(ledger_a.get_all_balances(), snapshot.get_all_balances());
        assert_eq!(ledger_a.total_supply(), snapshot.total_supply());
        assert_eq!(ledger_a.get_nonce(&sender), snapshot.get_nonce(&sender));
        assert!(!ledger_a.is_applied(&tx.id));

        // Window B (save failed after put): persisted = {F, T} → rebuild
        // applies T (heals forward, exactly once).
        let mut dag_b = DAG::new();
        dag_b
            .add_transaction_validated(funding.clone())
            .unwrap();
        dag_b.add_transaction_validated(tx.clone()).unwrap();
        let mut ledger_b = Ledger::new();
        ledger_b.rebuild_from_dag(&dag_b);
        assert_eq!(ledger_b.get_balance(&sender), 100_000 - 100 - 10);
        assert_eq!(ledger_b.get_balance(&receiver), 100);
        assert!(ledger_b.is_applied(&tx.id));
        // Re-rebuild is idempotent (second boot after the same crash image).
        let mut ledger_b2 = Ledger::new();
        ledger_b2.rebuild_from_dag(&dag_b);
        assert_eq!(
            ledger_b2.get_all_balances(),
            ledger_b.get_all_balances()
        );
    }
}
