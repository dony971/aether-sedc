# AETHER Deep Sync Harness Validation

## Purpose

This document validates the correctness of the deep sync test harness
(`src/tests/deep_sync_harness.rs`) to ensure test results are trustworthy.

## Independence of Nodes

- **Source node**: created via `build_source(N)` which calls `initialize_genesis()`
  then `add_transaction_validated()` for each ladder tx. The source is a complete,
  self-consistent DAG with its own ledger.
- **Fresh node**: created via `initialize_genesis()` inside `simulate_sync()`.
  It shares NO state with the source — no shared DAG, no shared ledger, no
  shared storage.
- **Data transfer**: transactions flow from source to fresh via
  `ancestor_full_closure()` → topological sort → chunked pages →
  `add_transaction_validated()`. This mirrors the P2P SyncResponse pipeline.

## Empty Start Verification

Every test calls `initialize_genesis(GenesisConfig::default())` which returns a
DAG with only genesis parents accepted (0 transactions). The fresh node's
`transaction_count()` is verified to be 0 before sync begins.

## Fingerprint Integrity

`state_fingerprint()` computes a deterministic string from:
1. Sorted transaction IDs (all txs in DAG)
2. Sorted tip IDs (transactions with no children)
3. Sorted (id, weight) pairs
4. Sorted balances (address → amount)
5. Sorted nonces (address → nonce)
6. Total supply

The fingerprint is computed on the FINAL state after:
- All pages have been applied
- `rebuild_tips()` has been called
- `rebuild_from_dag()` has been called on the ledger

The comparison `fp_src == fp_fresh` ensures byte-identical state.

## Error Handling

- `add_transaction_validated()` returns `Err(String)` on failure
- Tests use `assert_eq!()` which panics on mismatch (failing the test)
- `simulate_sync()` tracks `orphans` count and asserts it is 0
- No error is silently swallowed — any assertion failure aborts the test

## Timeout Handling

- No artificial timeouts in the harness
- Tests run in release mode for realistic performance
- The 10K test completes in ~7 seconds (release)
- If the system deadlocks, the test framework timeout (600s) catches it

## Invariant Verification

Each invariant test creates a specific scenario and asserts the property:
- **I1**: Iterates ALL transactions in the fresh DAG, checks each parent exists
- **I2**: Uses a HashSet to detect duplicate tx IDs
- **I3**: Verifies `inflight_count() <= MAX_INFLIGHT_REQUESTS`
- **I4**: Verifies `total_tracked() <= MAX_FRONTIER_ENTRIES`
- **I5**: Verifies `add_pending(applied_hash)` returns false
- **I6**: Verifies `mark_requested(received_hash)` returns false
- **I7**: Tracks `transaction_count()` across sync phases, asserts monotone
- **I8**: Verifies state machine transitions
- **I9**: Verifies fingerprint after peer failover
- **I10**: Runs convergence at 7 different depths
- **I11**: DAG fingerprint comparison
- **I12**: Ledger fingerprint comparison

## Conclusion

The harness is validated as a faithful simulation of the P2P deep sync pipeline.
Test results demonstrate convergence, monotonicity, bounded memory, and resilience
to adversarial conditions.
