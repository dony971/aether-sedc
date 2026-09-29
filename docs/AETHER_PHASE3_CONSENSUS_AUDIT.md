# AETHER PHASE 3A â€” CONSENSUS / DAG / PoW AUDIT

- **Scope**: audit, READ-ONLY. No code changes, no new tests, no commit/push/merge/tag/deploy.
- **Branch**: `dev/phase2-decentralized-network` @ `7af3e27` (`phase2: abstract network transport`).
- **Release**: `v1.4.0-testnet` = `ad08e30`, IMMUTABLE, untouched.
- **Method**: static code inspection (exact `file:line` citations below) + targeted FAST test executions only
  + previously recorded module runs. No HEAVY battery was re-run.
- **Structural fact**: there is NO `src/consensus.rs`, NO `src/dag.rs`, NO `src/pow.rs`.
  Consensus lives in `src/parent_selection.rs` (DAG + tip selection + conflict resolution),
  `src/transaction_processor.rs` (single acceptance pipeline), `src/ledger.rs` (state),
  `src/validation.rs` (PoW + rules), `src/rpc.rs` (status reporting + drainer),
  `src/node.rs` (ingress wiring), `src/p2p.rs` (propagation + sync).

No claim is made that Aether equals or exceeds Bitcoin. Maturity is assessed in Â§16.

---

## Â§1 â€” CONSENSUS_FLOW

```
INPUT â†’ VALIDATION â†’ DAG â†’ CONFLICT â†’ FORK CHOICE â†’ LEDGER â†’ PERSISTENCE â†’ FINALITY / RECOVERY
```

### INPUT (five ingress paths, three validation modes in play)

| Path | Entry point | Mode passed at accept |
|---|---|---|
| Local RPC submit | `src/rpc.rs:1059` â†’ `process_transaction(tx, "RPC", ValidationMode::Fresh)` | Fresh |
| Faucet issuance | `src/rpc.rs:2229,3451,3463` (`"Faucet"`, Fresh) | Fresh |
| P2P gossip / deep-sync ingress | `src/node.rs:620-667`, `process_transaction(tx, "P2P", ValidationMode::Historical)` (`:634`) | **Historical** |
| Orphan solver re-accept | `src/rpc.rs:1559` (`"Orphan"`, Historical), `:1722` (`"SolverStore"`, Historical) | **Historical** |
| Mempool drainer â†’ DAG (the ONLY path that mutates DAG+ledger) | `src/rpc.rs:1213-1250`, `processor.process(..., ValidationMode::Historical)` (`:1240`) | **Historical, always** |

Accept path (`src/rpc.rs:1066-1202`): pure gate FIRST (`validate_pure` in the caller-supplied mode, `:1128`)
â†’ DAG dedup (`:1141-1152`) â†’ fee-oracle gate (`:1160-1173`) â†’ mempool enqueue (`:1175`)
â†’ persist pending tx (`:1181-1183`) â†’ **broadcast to peers (`:1185`) BEFORE DAG inclusion**.
A tx is therefore relayed network-wide after PoW+signature+fee checks only; full
ledger/DAG validation happens later, asynchronously, in the drainer (~150 ms tick, `src/node.rs:725`,
batch `MEMPOOL_DRAIN_BATCH = 100`, `src/rpc.rs:60`).

### VALIDATION (`src/validation.rs`, `src/transaction_processor.rs:129-397`)

1. `validate_pure` (`validation.rs:226-313`): PoW (difficulty derived from `tx.timestamp` alone, `:239-240`),
   signature (`:298`), sender/key match (`:303`), amount+fee overflow (`:307`).
   Timestamp bounds (backdating `:256-266`, future `:268-275`, stale `:277-284`) apply **only in Fresh mode**.
   Historical mode skips ALL timestamp checks (`:286-288`).
2. Orphan gate (`transaction_processor.rs:208-225`): missing parents â†’ `ProcessingError::Orphan`
   (retryable, NOT invalid). Reached only AFTER the pure gate, so every parked orphan cost one valid PoW+sig.
3. `validate_dag` (`validation.rs:319-359`): duplicate id, parents exist, parent-timestamp
   monotonicity (child â‰¥ parent), `(sender, account_nonce)` conflict.
4. `validate_ledger` (`validation.rs:365+`): balance, fee, overflow. Strict `last_nonce+1`
   exists ONLY as a unit-test helper (`src/ledger.rs:395-416`, documented as must-NOT-use-live).

### DAG (`src/parent_selection.rs:277-281`, `:390-462`)

`add_transaction_validated` is the ONLY production insertion method (the old `add_transaction`
is a poisoned panic stub, `:383-385`). Checks: duplicate id (`:392`), parents exist (`:397-402`),
sender conflict (`:409-413`). Effects: `weight = 1.0` (`:427`), children index (`:432-444`),
tips update (`:446-451`), ancestor weights +1 (`:453`).
`DAG { transactions: HashMap, children: HashMap, tips: HashSet }` (`:277-281`).

### CONFLICT

Identity of a spend: `(sender, account_nonce)` (`find_sender_nonce_conflict` `:324`,
`has_sender_conflict` `:337`). Live resolution = STEP 0 of `process()`
(`transaction_processor.rs:143-200`): if an existing tx has `existing_id <= tx.id` â†’ reject
(`SenderConflict`); else the newcomer must pass `validate_pure(Fresh)` (`:171`, HARDCODED â€”
see CRITICAL-1), then `prune_subtree(existing)` (`:187`), purge pruned ids from storage
(`:192-197`, V-21 anti-resurrection), `rebuild_from_dag` (`:198`). Boot-time equivalent:
`canonical_resolve_conflicts` (`parent_selection.rs:676-728`, pure, min-id + descendant cascade)
called at `src/node.rs:265` before `rebuild_dag_topological` (`node.rs:296`,
`parent_selection.rs:745-779`).

### FORK CHOICE

See Â§2. There is no chain and no heaviest-work rule.

### LEDGER (`src/ledger.rs`, `transaction_processor.rs:302-347`)

Snapshot (`ledger.clone()`, `:303`) â†’ `transfer_internal` (fee burned, `:306`)
â†’ `mark_applied(tx.id)` (`:321`, positive-effects evidence BEFORE nonce commit)
â†’ nonce max-rule (`:330-335`: `if tx.account_nonce > current`, deliberate, arrival-order-safe)
â†’ DAG add (`:340`) â†’ mempool remove (`:358`, terminal disposition)
â†’ persist (`:365-390`) â†’ rollback to snapshot on error (`:308,:342`, and STEP-0/4 paths).
Zero emission: no minting path exists (tests `test_zero_emission_never_mints`,
`test_processing_does_not_mint`, `test_supply_never_exceeds_genesis`).

### PERSISTENCE

INC-01 commit order: transaction row FIRST (`put_transaction`, `:367`), ledger state second
(`save_dirty`, `:384`), so the persisted ledger can never reference history the DAG cannot
rebuild (`:360-364`). No per-tx fsync (P4: Sled auto-flush ~500 ms + per-batch flush in drainer
+ 10 s periodic + shutdown flush, `:374-381`). Mempool pending txs persisted (`rpc.rs:1181`);
orphans persisted/loaded (`security_tests.rs:464,493`).

### FINALITY / RECOVERY

No explicit finality mechanism (see Â§4). Recovery: `rebuild_from_dag` (canonical id-ordered
replay with precomputed min-id winners + funding relaxation loop, `ledger.rs:494-618`),
`process_recovery_insert` for ledger-ahead-of-DAG (`transaction_processor.rs:399-435`),
boot chain `canonical_resolve_conflicts â†’ rebuild_dag_topological â†’ rebuild_from_dag`
(`node.rs:265,296,385`), orphan solver + full sync from peers (`node.rs:835`,
`rpc.rs:1532+`), multiprocess crash harnesses.

---

## Â§2 â€” FORK CHOICE

```
FORK_CHOICE_RULE = NO CHAIN FORK-CHOICE.
                   Append-only DAG; every valid non-conflicting tx is accepted.
                   Conflicting txs (same sender + same account_nonce):
                   SMALLEST tx.id WINS, deterministically, on every node.
                   Loser subtree is pruned (cascade) and purged from storage.
```

- **INPUTS**: the set of txs sharing `(sender, account_nonce)`; their ids (`compute_hash`,
  `src/transaction.rs:133-150`, BLAKE3 over all fields incl. signature+pubkey).
- **DECISION**: `existing_id <= tx.id â†’ reject newcomer` (live, `transaction_processor.rs:154`);
  `canonical_resolve_conflicts` keeps min-id per key + drops loser descendants
  (`parent_selection.rs:676-728`); `rebuild_from_dag` precomputes min-id winners and skips
  residues before any transfer (`ledger.rs:516-565`).
- **DETERMINISM**: pure function of the tx set â€” PROVIDED every node applies the same validation
  to the winner. That proviso is currently VIOLATED on the live path (CRITICAL-1).
  Weight is EXPLICITLY ignored for conflicts (`test_w6_conflict_min_id_ignores_weight`).
- **ATTACK_SURFACE**:
  - ID GRINDING: an attacker owning the sender key can vary timestamp/parents/receiver and
    re-mine PoW to shop for a smaller id. Cost â‰ˆ one PoW per attempt (24-bit post-activation,
    20-bit if backdated â€” see HIGH-1). No test quantifies grinding cost vs min-id advantage.
  - LOSER-DESCENDANT DESTRUCTION: children built on the loser are dropped even if honestly
    constructed (`crash_harness.rs:209-237` shows the loser's child applying 0). After a
    partition, honest users building on the eventual loser lose their txs (must re-issue).
  - No reorg concept exists: there is nothing TO reorg; conflicts resolve by deletion, not
    by chain switching.
- **LIMITATIONS**: no cumulative-work rule, no GHOST, no weight-based choice, no voting
  (a `Finalized` enum variant exists but is unreachable â€” `rpc.rs:1823`; "VQV consensus votes"
  referenced only as future work, `:1824`). Partition sides each accept locally; the merge
  deletes one side's txs. See Â§7 for the staleness caveat that can make the merge DIVERGE.

---

## Â§3 â€” DOUBLE-SPEND (TX A vs TX B, same `(sender, account_nonce)`)

- **Detection**: `find_sender_nonce_conflict` / `has_sender_conflict`
  (`parent_selection.rs:324,337`); enforced at DAG entry (`validate_dag` â†’ `SenderConflict`,
  `validation.rs:353-356`; `add_transaction_validated`, `parent_selection.rs:409-413`).
- **Order (steady state)**: whoever arrives second loses, UNLESS its id is smaller â€” then STEP 0
  prunes the first and rebuilds (`transaction_processor.rs:143-200`).
- **Conflict rule / winner / loser**: min-id wins; winner applies (or stays applied); loser +
  its descendant subtree pruned from DAG, purged from storage, ledger rebuilt without them.
- **After partition**: each side accepts its own version (no cross-partition detection possible).
  `docs/THREAT_MODEL.md:83,131` already admits "partition can temporarily allow conflicting txs".
- **After reconnection**: gossip delivers both versions; the loser is pruned via STEP 0 â€”
  EXCEPT when the canonical winner is timestamp-stale at delivery time (CRITICAL-1):
  STEP 0 re-validates the winner with HARDCODED `ValidationMode::Fresh`
  (`transaction_processor.rs:171`) while the steady-state path (STEP 1, `:206`) and the drainer
  (`src/rpc.rs:1240`) use Historical. A winner older than `MAX_PAST_MS` (1 h), newer than
  `MAX_FUTURE_MS` (1 h), or backdated pre-activation is REJECTED at the node holding the loser,
  while the loser is rejected at the node holding the winner. Both nodes keep different
  winners: a PERMANENT ledger split with no self-healing (re-delivery hits the same STEP-0
  rejection; restart does not reconcile either â€” see below).
- **After restart**: boot applies `canonical_resolve_conflicts` (`node.rs:265`) + topological
  rebuild + `rebuild_from_dag`, i.e. pure min-id outcome over the PERSISTED set â€” deterministic,
  but it only reconciles txs the node actually stores. A node that reject-cached the winner
  (STEP-0 Fresh rejection) never persisted it, so restart preserves the split. Restart heals
  crash-ordering artifacts, NOT policy-divergent winners.
- **Test reality vs claims**: `consensus_harness.rs:498` `test_double_spend_during_partition` and
  `:561` `test_concurrent_conflicting_txs` use DIFFERENT senders (see `:517-536` "different
  sender, same receiver" and `:579-599`) â€” they prove gossip convergence of NON-conflicting txs,
  not double-spend resolution. True same-key conflicts are proven only OFFLINE
  (`crash_harness.rs:90,129,179,209` merge raw DAGs + `rebuild_from_dag`) and in unit tests
  (`test_canonical_resolve_conflicts_min_id_wins`, `test_sender_nonce_conflict_rejected`,
  `spec_check.rs:169`). The ONE live-pipeline order-invariance test,
  `transaction_processor.rs:593` `test_double_spend_order_invariance`, currently FAILS (Â§14, C2).

---

## Â§4 â€” FINALITY

```
FINALITY_TYPE = NOT EXPLICITLY DEFINED.
```

- No BFT, no checkpoints, no sog voting, no confirmation-depth rule in consensus code
  (`src/sync_stats.rs:19` confirms "finality â€¦ untouched" by Phase 2).
- `process()` comment claims "Finality is immediate once a transaction is accepted into the
  DAG" (`transaction_processor.rs:337-339`): de-facto 0-confirmation acceptance-finality,
  reversible ONLY by conflict-prune (STEP 0) â€” there is no depth after which a tx is immune.
- RPC REPORTING heuristics only (`src/rpc.rs:1811-1844`): `Confirmed` if child-reference count
  â‰¥ `MIN_CONFIRMATIONS = 3` (`rpc.rs:168,283`); `Stable` if `tx.weight â‰¥ STABILITY_THRESHOLD
  = 5.0` (`rpc.rs:171,286,1827`). Both are local observations, not consensus commitments.
- The `Finalized` status variant exists but is UNREACHABLE:
  "For now, we don't have a finalized mechanism, so we skip this" (`rpc.rs:1822-1824`).
- Consequence: nothing in the protocol marks a tx irreversible; conflict-prune can remove a
  long-accepted tx if a smaller-id same-key tx appears later (availability of such a tx is
  bounded only by key ownership + PoW, Â§11). Applications must treat `Stable` as an indicator,
  not a guarantee. Any "deterministic resolution" claim in docs (THREAT_MODEL `:148`) refers
  to conflict RULE determinism, not to finality.

---

## Â§5 â€” DAG_INVARIANT_MATRIX

| # | INVARIANT | SOURCE | TEST | STATUS | SECURITY_IMPACT |
|---|---|---|---|---|---|
| I1 | No duplicate tx ids | `parent_selection.rs:392`, `validation.rs:321` | `test_validate_dag_duplicate` | ENFORCED | Replay of identical bytes is inert |
| I2 | Parents exist or are genesis; missing â†’ Orphan (retryable) | `validation.rs:325-334`, `transaction_processor.rs:208-225` | `test_validate_dag_missing_parent`, `test_valid_orphan_returns_missing_parents`, `test_orphan_gated_by_pure_validation` | ENFORCED | No dangling edges; orphans cost attacker one PoW each |
| I3 | Parent-ts monotonicity (child â‰¥ parent) | `validation.rs:336-351` | `test_parent_timestamp_{equal,after,dual_parent*}` (5 tests) | ENFORCED | Ordering hint only; NO freshness (see I11) |
| I4 | One tx per (sender, account_nonce) | `parent_selection.rs:324,337,409`, `validation.rs:353`, STEP 0 | `test_sender_nonce_conflict_rejected`, `test_find_sender_nonce_conflict`, `test_canonical_resolve_*` (3), `crash_harness` double-spend (4), `spec_check:169` | ENFORCED WITH CRITICAL CAVEAT | See CRITICAL-1: live-path mode inconsistency |
| I5 | `weight` = subtree size, maintained on add/remove/prune | `parent_selection.rs:421-453,476-526` | `test_cumulative_weight_maintained_by_dag`, `test_w1..w12` (12), `test_w8_restart_rebuild_preserves_weights` | ENFORCED | Weight feeds tip selection + Stable heuristic, NOT conflicts |
| I6 | Supply conservation (â‰¤ genesis; fees burned; zero emission) | `transfer_internal`, `ledger.rs:494+` | `test_supply_never_exceeds_genesis`, `test_zero_emission_never_mints`, `test_processing_does_not_mint`, `test_total_supply_never_goes_stale`, `test_balance_conservation_*` (3), `test_no_balance_creation/destruction` | ENFORCED | No mint primitive exists in `process()` |
| I7 | No double-apply (applied set; idempotent recovery insert) | `ledger.rs:423-444`, `transaction_processor.rs:321,399-435` | `test_no_duplicate_application`, `test_applied_persistence_roundtrip`, `test_inc01_recovery_insert_ledger_ahead` | ENFORCED | Crash-replay cannot debit twice |
| I8 | Ledger is a pure function of the DAG set | `ledger.rs:507-528` (id-sort, winners up front) | `test_rebuild_deterministic_across_arrival_orders`, `test_rebuild_from_dag_invariant_holds`, fingerprint tests (`migration_multinode:1027`, `deep_sync:1143,1161`, `inc01:140`) | PARTIAL â€” RED ON LIVE PATH | Rebuild-level: proven. Live `process()`-level: `test_double_spend_order_invariance` FAILS at HEAD |
| I9 | Signature covers every economic/consensus field | `compute_signing_hash`, `transaction.rs:152+` | `test_signature_covers_amount/receiver/nonce_and_timestamp`, `test_sender_public_key_*` (4) | ENFORCED | No unsigned-field malleability |
| I10 | PoW binds exactly the signed content | preimage `transaction.rs:354-368` == signing coverage minus sig/pubkey | INDIRECT (mining/verify exercised everywhere; `test_pow_curve`, `test_pow_verification_cost`) | ENFORCED BY CONSTRUCTION | PoW cannot be transplanted across different economic content |
| I11 | Timestamp freshness (stale/future/backdate rejection) | `validation.rs:256-285` (Fresh ONLY) | ~20 Fresh/Historical/grace/boundary tests in `validation.rs` | NOT ENFORCED AT CONSENSUS ENTRY | Drainer (`rpc.rs:1240`) + P2P (`node.rs:634`) always Historical â†’ HIGH-1 |
| I12 | Orphan store bounded; pure-gate before parking | orphan cap, `transaction_processor.rs:202-206` | `test_orphan_cap_rejects_beyond_limit`, `test_orphan_gated_by_pure_validation`, `test_orphan_persistence/load_on_startup` | ENFORCED | Unvalidated junk cannot fill disk via orphan path |
| I13 | Mempool bounded; deterministic select (fee DESC / id ASC); drain-to-DAG | `rpc.rs:1204-1250`, `node.rs:686-727` | `test_m1_lifecycle_under_capacity`, `test_faucet_low_fee_revives_after_drain`, `test_mempool_full_prevents_ledger_commit` | ENFORCED | Queue cannot deadlock DAG growth (Phase C fix) |
| I14 | Min-id rule ignores weight (design choice, pinned) | conflict path | `test_w6_conflict_min_id_ignores_weight`, `test_w7_double_spend_winner_keeps_weight` | ENFORCED (as specified) | Grinding surface is id-space, not weight-space |

---

## Â§6 â€” DETERMINISM_AUDIT

| Source | Location | Effect on consensus state | Test evidence |
|---|---|---|---|
| `rand::thread_rng` in `random_walk` | `parent_selection.rs:112` | NON-DETERMINISTIC parent choice for locally created gossip tips. Does NOT alter ledger outcomes (all valid txs apply regardless of parents). Topology varies across nodes. | MISSING (no test asserts cross-node parent-selection equality; convergence asserted on tx-id sets: `dag_ids`, `consensus_harness.rs:76`, `dags_consistent`, `:209`) |
| `rand::thread_rng` in `get_random_tips` (+ fallback `:635`) | `parent_selection.rs:605` | Same as above; also feeds `get_tips` closure served to P2P (`node.rs:502-513`) | MISSING |
| `SystemTime::now` in `validate_pure` | `validation.rs:231` | Boundary divergence: tx near Â±1 h edges or grace edge accepted on one node, rejected on another | PARTIAL (`test_clock_skew_*`, grace-boundary tests pin classification, not live cross-node acceptance) |
| `current_timestamp_ms` freshness filter in `select_parents` | `parent_selection.rs:209` | `valid_tips` computed but NEVER USED for selection (only gates `NoValidTips`); actual parents come from RNG walk. Dead filter â€” behavior is deterministic-ish but NOT what the code advertises | MISSING (roadmap M4) |
| Arrival/network order | gossip, sync batches | Order-invariant BY DESIGN (min-id + id-sorted rebuild) â€” EXCEPT CRITICAL-1 mode split | MISSING ON LIVE PATH (C2: the proving test is red); PRESENT at rebuild level |
| `HashMap` iteration | `transactions`, `children` | Neutralized in `rebuild_from_dag` (explicit id sort `:528`); `canonical_resolve_conflicts` content-deterministic BUT return order is `HashSet` order (`:727`) â€” cosmetic (log/purge order only) | PARTIAL (rebuild determinism tested; pruned-list order not pinned â€” roadmap M3) |
| Async scheduling / lock contention (`try_write`) | `transaction_processor.rs:177-186,282-300` | `LockError` â†’ drainer retries with backoff (`rpc.rs:1229-1250`); no state effect, liveness preserved | Present by code path (retry loop); no dedicated contention test cited |
| Float `weight` (`f64`, threshold `5.0`) | `parent_selection.rs:101-104`, `rpc.rs:286` | +1/-1/clamp arithmetic exact for realistic sizes; `as u64` cast in walk; same-ops IEEE determinism | CODE_PROPERTY claimed; TEST_EVIDENCE = MISSING (roadmap M7) |
| `children` Vec arrival order | push order `:432-444` | Only lengths/BFS-set traversals observed (`reference_count` len `:1816-1820`, prune BFS, walk clone-then-weight); no index-based decision found | CODE_PROPERTY by inspection; TEST_EVIDENCE = MISSING |
| Dead-code consensus params (`min_weight`, `diversity_factor` `#[allow(dead_code)]`) | `parent_selection.rs:63-69` | No effect (unused); risk is documentary (operators believe weight/diversity filter exists) | MISSING (roadmap M4) |

---

## Â§7 â€” PARTITION (split â†’ concurrent txs â†’ reconnect â†’ sync â†’ conflict â†’ convergence)

**Covered (evidence, not re-run)**:
- Gossip convergence of NON-conflicting txs across split/reconnect: `test_double_spend_during_partition`,
  `test_concurrent_conflicting_txs`, `test_reconnection_convergence`, `test_multi_partition_rounds`,
  `test_fork_convergence` (`consensus_harness.rs`). NOTE: despite names, the first two use
  DIFFERENT senders â€” they do not exercise same-key conflict resolution (roadmap L2).
- True-conflict merge, offline: `test_double_spend_partition_reconnect`, `test_double_spend_fork`,
  `test_double_spend_two_wallets`, `test_double_spend_same_utxo` (`crash_harness.rs:90-237`) â€”
  merge + `rebuild_from_dag` yields min-id winner + conservation.
- Crash-during-partition, 500-cycle multiprocess, fuzz 100/1000: `multiprocess_crash.rs:377,435`,
  `crash_harness.rs:349,379,413`.
- Partition around difficulty activation + 10-node convergence + fingerprint stability:
  `migration_multinode.rs:601,766,567,1027`.
- Deep-sync interrupt/malicious/restart at 100â€“10k scale + 12 sync invariants:
  `deep_sync_harness.rs` (`test_interrupt_*`, `test_malicious_*`, `test_invariant_i1..i12`,
  `test_combined_10k_*`, `test_benchmark_10k_*`).

**NOT covered**:
- N1 (CRITICAL): live same-key conflict across a partition where the canonical winner arrives
  STALE/future/backdated â†’ STEP-0 Fresh rejection â†’ permanent split (CRITICAL-1). No test drives
  real `process()` on both sides with aged winners.
- N2: innocent-descendant loss at merge (honest children of the loser dropped; re-issuance burden
  unquantified) â€” shown in miniature (`crash_harness.rs:209`), never at partition scale.
- N3: mixed-version partition is documented as DIVERGENT (`test_mixed_version_divergence`,
  `consensus_harness.rs:672`; `p2p.rs:1501` version-split comment) â€” correct behavior, but it
  contradicts any reading of "partition = PROVEN safe".
- **Doc-vs-code gap**: `docs/THREAT_MODEL.md:121-148` marks Network Partition "PROVEN" with
  "Proof: Partition tests pass (consensus_harness, crash_harness)" and "Deterministic
  resolution". Given N1 + the red order-invariance test + the different-sender harness tests,
  that PROVEN label is overstated for TRUE conflicts on the LIVE path. Recommend downgrade to
  PARTIAL with the N1 caveat (roadmap P0).

---

## Â§8 â€” CRASH / PERSISTENCE (`DAG != LEDGER` analysis)

Write order per accepted tx: DAG+ledger in memory (steps 4â€“7) â†’ `put_transaction` to Sled
(`:367`) â†’ `save_dirty` ledger (`:384`) â†’ (async flushes). Boot: canonical-resolve persisted set
(`node.rs:265`) â†’ topological DAG rebuild (`:296`) â†’ `rebuild_from_dag` (`:385`).

| Crash window | In-memory state | On-disk state | Outcome at boot |
|---|---|---|---|
| Before STEP 6 (transfer done, DAG add failed) | rolled back to snapshot (`:342`) | unchanged | Consistent (tx absent) |
| After STEP 6, before STEP 8 persist | DAG+ledger have tx | old ledger + tx tree without tx | Consistent-older: tx lost everywhere; orphan solver + full sync re-heal from peers |
| After `put_transaction`, before `save_dirty` | applied | tx present, ledger stale | HEALED: rebuild re-derives ledger incl. tx (INC-01 design) |
| Ledger ahead of DAG (truncated tx tree, surviving ledger) | â€” | ledger has effects, DAG lacks tx | HEALED via `process_recovery_insert` (`:399-435`, routed `:270-274` on applied-set/store evidence, never on nonce slot alone â€” INC-C2-003 lesson) |
| During STEP-0 prune+rebuild, before persist | pruned+rebuilt | loser rows still stored | HEALED: boot `canonical_resolve_conflicts` re-derives the same prune (V-21 purge `:192-197` prevents resurrection races) |
| STEP-8 persist FAILURE (no crash) | tx APPLIED, `Err(PersistenceError)` returned (`:369-390`, NO rollback) | partial | NO divergence (rebuild converges), but caller sees failure for an applied tx â†’ resubmit â†’ duplicate-reject. MEDIUM correctness wart (M1) |
| During boot recovery itself | partial | unchanged inputs | Boot inputs are the persisted set; re-running boot is idempotent (topological insert + canonical resolve are pure over the set) |

Evidence: `test_inc01_rebuild_10000_restores_exact_state`, `test_inc01_rebuild_truncated_*` (2),
`test_rebuild_truncated_no_orphans_derives_higher_supply` (documents supply-direction safety),
`test_save_dirty_*` (9, incl. `test_save_dirty_crash_recovery_simulation`),
`test_atomic_*` / `test_transactional_consistency_on_failure` (ledger), `test_no_duplicate_application`,
`test_no_balance_creation/destruction` (multiprocess), crash fuzz 100/1000 cycles.

---

## Â§9 â€” REPLAY

- **Transaction replay** (same bytes): id covers signature+pubkey (`transaction.rs:133-150`) â†’
  duplicate rejected at DAG (`:392`, `validation.rs:321`), mempool, and P2P `seen` dedup
  (`p2p.rs:1495,4297`); applied-set blocks re-execution (`ledger.rs:434`).
  Test: `security_tests.rs:140` `test_replay_attack_prevention`. ENFORCED.
- **Same (sender, nonce), different content**: treated as CONFLICT, not replay (min-id rule, Â§3).
  Test: `test_out_of_order_nonce_accepted` (`:193`, max-rule pinned),
  `test_sender_nonce_conflict_rejected` (`:230`). ENFORCED as specified.
- **P2P session replay**: per-connection strictly-increasing 8-byte frame counter inside the
  12-byte nonce; repeat/regression â†’ warn + disconnect + score-ban (`p2p.rs:3797-3889`).
  Frames are encrypted with padding gates (`:3846-3864`). ENFORCED at session level.
- **Cross-version replay**: `P2P_PROTOCOL_VERSION = 4` bump splits the network
  (`p2p.rs:1501`); old-difficulty txs are a consensus fork, not a replay
  (`test_mixed_version_divergence`). Documented-divergent by design.
- **Historical replay (sync of old txs)**: accepted by design in Historical mode; idempotent
  (I1/I7). Benign.
- **UNVERIFIED**: cross-SESSION frame replay (new connection, counter restarts at 0) relies on
  per-session encryption-key separation, which this audit did NOT trace to the handshake key
  schedule. Marked as gap M6 (proposed handshake/key-separation test), not as a finding.

---

## Â§10 â€” TIMESTAMPS

Constants (`src/transaction.rs`): `DIFFICULTY_MIGRATION_TS = 1_758_000_000_000` (`:458`,
2025-09-16T00:00:00Z), `GRACE_PERIOD_MS = 86_400_000` (`:464`), `MAX_PAST_MS = 3_600_000`
(`:470`), `MAX_FUTURE_MS = 3_600_000` (`:475`). Stale doc comment: `:483-484` claims
pre-activation-after-grace returns `None` (REJECT); BOTH implementations
(`difficulty_for_tx` `:491-497`, `difficulty_for_tx_at` `:514-520`) ALWAYS return `Some`
(20 or 24) â€” rejection lives ONLY in Fresh-mode `validate_pure` (roadmap L1).

- **Difficulty is self-declared**: required PoW = pure function of `tx.timestamp`
  (`difficulty_for_tx_at`). The timestamp is attacker-chosen and covered by signature but
  NOT constrained at consensus entry (drainer + P2P = Historical). Hence HIGH-1: any peer can
  inject pre-activation-timestamped txs paying 20-bit PoW (~1/16th of 24-bit work) that are
  applied to the ledger and can parent post-activation txs (ordering allows oldâ†’new;
  the "structural isolation" claim in `validation.rs:250-252` is FALSE â€” no rule forbids a
  pre-activation tx from parenting a post-activation child; only `child.ts >= parent.ts` is
  checked, `validation.rs:336-351`).
- **Fresh-mode policy** (RPC/faucet accept only): backdate/future/stale rejection intact and
  heavily tested (~20 tests). It is a PERIMETER gate, not a consensus rule.
- **Clock skew**: `now_ms` from system clock (`validation.rs:231`); skew tests
  (`migration_multinode:319-400`, grace tests `:701-758`) pin classification; cross-node
  acceptance divergence at Â±1 h boundaries has no live test (determinism table).
- **Effect on consensus**: timestamps influence NOTHING in ledger/DAG outcomes except via (a)
  difficulty derivation, (b) the Fresh/Historical branch (CRITICAL-1), (c) tip-freshness filter
  that is computed-but-unused (Â§6). No median-time-past, no timestamp-based ordering of state.

---

## Â§11 â€” PoW

```
POW_SECURITY_MODEL
- Per-transaction BLAKE3 PoW (no blocks, no chain work).
- Preimage: parents | sender | receiver | amount | fee | timestamp | pow_nonce |
  account_nonce (transaction.rs:354-368). Excludes signature/pubkey â€” EXACTLY the signed
  content (compute_signing_hash). A PoW cannot move across different economic content;
  re-signing identical content yields a different id but identical state effect, which the
  (sender,nonce) rule collapses to one winner.
- Difficulty: 24 bits fixed (~16.7M hashes average), 20 bits pre-activation timestamp.
  No retargeting, no hashrate feedback, no difficulty schedule â€” static forever.
- Verification: single hash + leading-zero-prefix check (transaction.rs:373-397); overflow
  safe (checked_add, validation.rs:307).
- Measured cost baseline (project docs, not this audit): THREAT_MODEL.md:15-19 records
  ~5.3 s/tx CPU measured, ~3.25 ms/tx GPU ESTIMATED ONLY, ~308 tx/s vs 0.19 tx/s, status
  PARTIAL (GPU resistance unmeasured). pow_economics.rs:148 states the design position:
  "DAG weight + finality + peer reputation are the real defenses" (i.e. PoW is anti-spam,
  not Sybil-weight).
- PoW is NOT an input to fork resolution, weight, or status (weight = subtree size;
  test_w6 pins min-id-ignores-weight).

POW_LIMITATIONS
- L-a (HIGH, = HIGH-1): effective difficulty is attacker-selected via timestamp on every
  Historical path (P2P ingress, drainer, orphan solver). The 24-bit anti-spam cost is
  enforceable ONLY against RPC/faucet submitters.
- L-b: static difficulty â‡’ static attacker budget; hardware improvements silently cheapen
  spam over time; no feedback loop exists by design (and none is proposed here â€” roadmap).
- L-c: min-id conflict rule + grindable ids â‡’ conflict outcomes are purchasable at
  ~PoW-per-attempt (unquantified â€” gap H2). PoW does not RATE-LIMIT conflict creation
  beyond per-attempt cost, and STEP-0 prune+rebuild makes each conflict expensive to
  DEFENDERS (gap H3, CPU amplification).
- L-d: relay-before-full-validation (Â§1, rpc.rs:1185): a valid-PoW-but-unfunded tx is
  gossiped network-wide, then rejected at every drainer. Per-spam-tx network cost â‰«
  attacker cost (MEDIUM, relay amplification).
- L-e: GPU economics unmeasured (THREAT_MODEL PARTIAL); any "PoW = secure" reading is
  unsupported â€” PoW here buys per-tx spam delay, nothing more.
```

No difficulty change is proposed or made in this audit.

---

## Â§12 â€” SYBIL

```
P2P_ECLIPSE_RESISTANCE (network identity/peer layer â€” Phase 2C + AddressManager):
- Peer scoring + ban (flood, invalid-msg incl. replay), per-second rate limits, frame
  timeouts, subnet-aware admission, Sybil-scale harness sims (sybil_scale.rs), eclipse
  test battery (phase2_eclipse: 15 tests). Residual risk is DOCUMENTED, not closed:
  THREAT_MODEL.md:35,49,51 â€” eclipse needs 32 VPS in distinct /24 (~$544/mo) and
  "attacker with 32 VPS CAN eclipse a single node". Compiler warnings show partially
  wired scoring (unused PEER_PENALTY_CONTRADICTION, penalize_contradiction â€” roadmap L3).

CONSENSUS_SYBIL_RESISTANCE (state layer):
- There is NO validator set, NO stake, NO identity registry, NO vote, and PoW confers NO
  weight. Influence on state = ability to produce an ACCEPTED tx = (valid PoW + valid sig
  + funding for amount+fee + passing DAG rules).
- Creating more identities costs nothing beyond funding them (fixed supply â†’ faucet policy
  is the real identity throttle) plus one PoW + fee per tx.
- Safety properties (no double-apply, conservation, min-id resolution) are SYBIL-AGNOSTIC:
  they hold regardless of how many identities the attacker controls, because they are
  deterministic functions of the tx SET, not of who sent what.
- What Sybil DOES buy: (a) more parallel conflict injections (each costs PoW+fee, triggers
  defender-side prune+rebuild â€” H3); (b) more gossip volume (bounded by fanout/rate-limits);
  (c) id-grinding parallelism (H2). None of these can forge acceptance (PoW+sig+balance still
  required) or rewrite min-id outcomes for txs honest nodes already hold â€” EXCEPT via the
  CRITICAL-1 timing channel.
- Answer to the key question: PoW is used as a PER-TX ADMISSION COST, nowhere as a WEIGHT.
  Consensus influence per unit of attacker spend is therefore linear in tx count and capped
  by funding + fees â€” with the HIGH-1 asterisk that the PoW leg of that cost is 16Ã— cheaper
  via backdating on network paths.
```

---

## Â§13 â€” INTERACTION WITH PHASE 2 (can network properties steer consensus?)

Phase 2 mechanisms (bounded fanout `MAX_PROPAGATION_FANOUT = 4`, jitter 20â€“250 ms
`p2p.rs:345-352`, `insert_seen` dedup `:1495,4297`, upstream-source recording 2E-D `:4291-4296`,
rate-limit+ban `:3823-3843`, AddressManager/eclipse 2B-2C, self-healing 2D, TCP transport
abstraction 2E-B `src/transport.rs`) change TIMING and REACHABILITY of tx delivery. They do
not change any acceptance predicate.

- **Fork/conflict choice**: predicates are local and (modulo CRITICAL-1) order-invariant, so
  fanout/jitter/transport cannot alter outcomes â€” they only alter WHEN a node learns a tx.
  WHEN matters exclusively through the CRITICAL-1 Fresh/Historical branch: network timing
  decides arrival order, arrival order decides which STEP-0 branch runs, the branch decides the
  validation mode, the mode can decide acceptance. AFTER a P0 mode-unification fix, network
  influence on consensus outcomes reduces to liveness (what you see and when), never safety.
- **Eclipse**: an eclipsed node sees a subset of txs; it cannot be fed an INVALID tx (PoW+sig
  still verified) nor a LOSING conflict as a winner for keys whose true min-id tx it already
  holds. Eclipse degrades freshness/availability and can delay conflict discovery â€” it cannot
  forge state. (Partition analysis Â§7 applies symmetrically.)
- **Validation-before-relay**: accept-time pure gate (PoW+sig+fee) precedes broadcast
  (`rpc.rs:1128â†’1185`), so pure junk does not propagate; but FULL validation postdates relay,
  giving the L-d amplification. Jitter/fanout bound its rate, not its existence.
- **Self-healing/sync**: `partition_batch` order-independence (`p2p.rs:4893-4931` + test
  `test_partition_batch_order_independent`), Kahn-sorted topo order (`:4833-4891`, capped by
  `TOPO_ORDER_CAP` with request-order fallback), bounded parent re-request with backoff
  (`:4933+`), monotone frontier â€” all liveness/DoS properties; none feeds consensus predicates
  except by delivering txs to the (Historical) ingress.
- **Transport abstraction**: byte pipe; consensus-neutral by construction.

---

## Â§14 â€” PHASE3_TEST_GAPS

### CRITICAL

- **C1 â€” Live same-key partition conflict with aged winner (unproven merge safety).**
  PROPERTY: post-reconnect convergence when the canonical winner is stale/future/backdated.
  CURRENT: offline-merge tests only; harness partition tests use different senders.
  MISSING: two-sided live `process()` run with winner age > MAX_PAST_MS / backdated, asserting
  identical DAG+ledger on both nodes.
  RISK: permanent ledger split (CRITICAL-1 mechanism). PROPOSED TEST: partition sim driving
  the real pipeline in both arrival orders with time-shifted winner fixtures.
- **C2 â€” Live double-spend order-invariance is RED at HEAD.**
  PROPERTY: both arrival orders â†’ identical DAG+ledger via `process()`.
  CURRENT: `transaction_processor.rs:593` FAILS (`BackdatedTimestamp`, fixture `tx_ts=1234567890`).
  MISSING: a passing live order-invariance proof, incl. a FreshÃ—Historical mode matrix.
  RISK: the flagship consensus property is currently unproven; regressions invisible.
  PROPOSED TEST: repair fixture mode/timestamps (no prod-code change in audit scope) + add
  mode-matrix variant. (Test repair is roadmap work, NOT done here.)

### HIGH

- **H1 â€” Production validation-mode wiring unasserted.**
  PROPERTY: effective timestamp policy at DAG entry for P2P/orphan/drainer paths.
  CURRENT: unit tests pin mode BEHAVIOR (`validation.rs` ~20 tests) but nothing pins that the
  drainer/P2P ALWAYS use Historical. MISSING: wiring test (P2P-sourced backdated tx reaches
  DAG). RISK: HIGH-1 policy bypass persists silently. PROPOSED TEST: ingress-mode assertion
  test per path (RPC=Fresh at accept / drainer=Historical documented-or-fixed).
- **H2 â€” Min-id grinding economics unquantified.**
  PROPERTY: cost to bias a conflict outcome by id shopping. CURRENT: none.
  MISSING: measurement in the style of `test_w11_cost_measurement`. RISK: unknown price of
  stealing a conflict win. PROPOSED TEST: grinding-cost benchmark (MEDIUM/HEAVY, release-run
  per Â§15 protocol if pursued).
- **H3 â€” Conflict-flood CPU amplification unbounded.**
  PROPERTY: defender cost per injected conflict (prune_subtree + storage purge + full
  `rebuild_from_dag` + dirty-mark-all `:606-609`). CURRENT: scalability measures HONEST rebuild
  curve only. MISSING: adversarial conflict-flood benchmark + bound. RISK: cheap PoW (esp.
  20-bit backdated) â†’ expensive defender rebuilds, repeatable per conflict.
  PROPOSED TEST: conflict-injection benchmark; roadmap P1 bound.
- **H4 â€” Innocent-descendant loss at merge unquantified.**
  PROPERTY: honest txs built on the eventual loser are destroyed (must re-issue).
  CURRENT: miniature proof (`crash_harness.rs:209`). MISSING: partition-scale measurement +
  policy decision (warn/re-issue UX). RISK: silent user-fund limbo perception.

### MEDIUM

- **M1 â€” Persist-failure post-apply returns Err without rollback** (`transaction_processor.rs:365-390`).
  PROPOSED: storage fault-injection test asserting caller-visible vs actual state; then define
  rollback-or-commit semantics (roadmap P2).
- **M2 â€” `random_walk` zero-total-weight panic guard** (`parent_selection.rs:136-137`,
  `gen_range(0..total_weight)`). Reachability unproven (children cleanup suggests unreachable,
  weight-clamp `:519` suggests defensiveness). PROPOSED: hostile-state unit test + guard.
- **M3 â€” `canonical_resolve_conflicts` return order nondeterminism** (`:727` HashSetâ†’Vec).
  PROPOSED: content-only assertion test (order-agnostic) to pin the guarantee that matters.
- **M4 â€” Tip-selection inputs not as advertised** (`valid_tips` unused; `min_weight`/
  `diversity_factor` dead). PROPOSED: behavior-pinning test documenting ACTUAL selection
  inputs, then fix-or-document (roadmap P2).
- **M5 â€” Future-timestamped txs via P2P** (Historical skips MAX_FUTURE). Partially covered by
  H1 wiring test; explicit future-ts P2P case proposed.
- **M6 â€” Cross-session frame replay key separation** (Â§9 UNVERIFIED). PROPOSED:
  handshake/key-schedule test proving new-session keys reject old-session frames.
- **M7 â€” Float-weight cross-platform determinism.** PROPOSED: fixed-vector weight test
  (add/prune/rebuild sequence asserting exact weights).

### LOW

- **L1** â€” Stale doc comment (`transaction.rs:483-484`, "REJECT/None" vs always-`Some`).
- **L2** â€” Misleading harness test names (different-sender "double_spend"/"conflicting" tests).
- **L3** â€” Dead-code warnings in scoring path (`PEER_PENALTY_CONTRADICTION`,
  `penalize_contradiction`; 43 warnings in test profile â€” pre-existing baseline).
- **L4** â€” `#[ignore]`d benches (6) are the only perf coverage of hot paths; release perf
  unmeasured in CI-equivalent runs.

---

## Â§15 â€” TARGETED TEST RECORD (Ã‰TAPE 15)

Executed (FAST only, exact-match, `--nocapture`):
- `validation::tests::test_validate_pure_valid` â†’ ok, 0.00 s.
- `validation::tests::test_post_grace_5year_simulation` â†’ ok, 0.00 s.
Previously recorded (pre-Phase-3A turns, same tree, no code changes):
- `transaction_processor::tests::test_double_spend_order_invariance` â†’ FAILED
  (`BackdatedTimestamp { tx_ts: 1234567890, ... }` at `transaction_processor.rs:673`).
- Module `transaction_processor::` â†’ 5 passed, 3 failed
  (`test_double_spend_order_invariance`,
  `test_phantom_nonce_heals_transfer` (`:1095`, same BackdatedTimestamp signature, confirmed),
  `test_applied_true_duplicate_skips_replay` (`:1161`, same signature, confirmed)), 1 ignored.
- Module `validation::` full run â†’ exceeded shell timeout twice (>20 min, 8 threads); cause
  established by inventory: 34Ã— 24-bit + 15Ã— 20-bit REAL PoW mining in unoptimized debug
  profile with geometric-variance tails (40/10/8/22 FAST/MEDIUM/HEAVY/0). NOT re-run per orders.
- Total lib tests: 555.
HEAVY tests were NOT executed and NO `--release` run was performed: not indispensable â€” audit
conclusions rest on code inspection + FAST executions + the recorded live-path failures.
`mine_nonce`/`verify_pow` are pure functions of tx content, hence DEBUG/RELEASE semantically
identical by inspection (only wall-time differs); documented here instead of re-proven.
No test was modified.

---

## Â§16 â€” BITCOIN COMPARISON (descriptive only; no "better")

| PROPERTY | AETHER_CURRENT | BITCOIN_MODEL | EVIDENCE | MATURITY | LIMITATION |
|---|---|---|---|---|---|
| PoW | Per-tx, fixed 24-bit (20 pre-activation), BLAKE3, no retarget | Per-block, retargeted (~2016 blocks), chain-work | `transaction.rs:373-448`; THREAT_MODEL `:15-21` (CPU measured, GPU estimated) | Prototype static | Attacker budget fixed forever; GPU economics unmeasured |
| Fork choice | None (append-only DAG + min-id conflict deletion) | Heaviest accumulated work chain | Â§2; `test_w6` | Audit-phase | No work-based convergence; merge = deletion |
| Double-spend | Deterministic min-id per (sender,nonce); balance gate | First confirmation in winning chain wins | Â§3; STEP 0 | Audit-phase, live proof RED (C2) | Cross-partition loss of loser side; grinding (H2) |
| Finality | NOT EXPLICITLY DEFINED; insertion-acceptance + RPC heuristics (3 refs / weight 5.0) | Probabilistic depth convention (â‰ˆ6 conf) | `rpc.rs:1811-1844,1823` | Absent as mechanism | Nothing is ever irreversible by rule |
| Reorg | No such concept (prune instead of switch) | Reorgs to heavier chain | DAG structure | N/A | Loser-descendant destruction (H4) |
| Sybil | No stake/vote/weight; per-tx PoW+fee cost + fixed supply | PoW-weighted leader election per block | Â§12; `pow_economics.rs:148` | Design position stated, partially measured | 20-bit bypass cheapens the cost leg (HIGH-1) |
| Partition | Merge-by-min-id (offline-proven; live caveat CRITICAL-1) | Work-based reconvergence | Â§7; harnesses | Partial | Permanent-split scenario open (C1) |
| Persistence | Sled + canonical rebuild-from-DAG determinism | Block files + UTXO set + assume-valid | Â§8; INC-01 tests | Well-tested (10k rebuild, fuzz, multiprocess) | STEP-8 Err-post-apply wart (M1) |
| Consensus maturity | Single-node-tested pipelines + sim harnesses; 3 live-path tests red; policy bypasses open | 15+ years adversarial production | Â§14â€“15 | PROTOTYPE â€” not deployable as money | Must close P0 before any adversarial exposure |

---

## VERDICT

The DAG/ledger core is carefully engineered (canonical rebuilds, applied-evidence tracking,
commit ordering, extensive offline/harness coverage) but it is NOT currently a serious
crypto consensus core: (1) the live conflict path can permanently split nodes (CRITICAL-1);
(2) the flagship live order-invariance proof fails at HEAD (C2, +2 sibling failures same
signature); (3) the timestamp/PoW-cost policy is unenforced at every consensus entry
(HIGH-1); (4) finality does not exist as a mechanism; (5) partition-safety is claimed
PROVEN on tests that never inject a true live conflict. The good news: all five are
bounded, well-located, and fixable without architectural upheaval (see companion roadmap).
No "Aether = Bitcoin" or "Aether > Bitcoin" conclusion is supported by any evidence in
this audit.
