# AETHER Deep Sync Final Report

## 1. Bounds

| Parameter | Value | Tested |
|-----------|-------|--------|
| `MAX_SYNC_PAGE` | 100 txs/page | 100, 250, 500 tested |
| `MAX_CLOSURE_PAGES` | 10 (max 1000 txs/closure) | bounded overflow test PASSED |
| `MAX_INFLIGHT_REQUESTS` | 64 | enforced PASSED |
| `MAX_FRONTIER_ENTRIES` | 100,000 | enforced PASSED |
| `BACKPRESSURE_BASE_MS` | 5ms (adaptive) | scales with sqrt(batch) |
| `STALL_THRESHOLD` | 30s | detection PASSED |
| `MAX_RETRY_ATTEMPTS` | 3 | N/A (failover at call site) |

## 2. Deep Sync Profondeur

| Depth | Txs Sent | Pages | Time (ms) | Frontier Peak | Inflight Peak | Orphans | PASS |
|-------|----------|-------|-----------|---------------|---------------|---------|------|
| 100 | 100 | 1 | 0 | 100 | 0 | 0 | YES |
| 400 | 1,000 | 10 | 8 | 400 | 64 | 0 | YES |
| 800 | 3,600 | 36 | 36 | 800 | 64 | 0 | YES |
| 1600 | 11,500 | 115 | 151 | 1,600 | 64 | 0 | YES |
| 3200 | 27,500 | 275 | 632 | 3,200 | 64 | 0 | YES |
| 6400 | 59,500 | 595 | 2,784 | 6,400 | 64 | 0 | YES |
| 10K | 95,500 | 955 | 7,042 | 10,000 | 64 | 0 | YES |

## 3. Interruption / Resume

| Depth | Interrupt % | Resume | Converged | Orphans | PASS |
|-------|-------------|--------|-----------|---------|------|
| 400 | 10% | peer 2 | YES | 0 | YES |
| 1600 | 50% | peer 2 | YES | 0 | YES |
| 3200 | 90% | peer 2 | YES | 0 | YES |
| 10K | 50% | peer 2 | YES | 0 | YES |

## 4. Malicious Peers

| Scenario | Description | Crash | Memory | Loop | Coherent | PASS |
|----------|-------------|-------|--------|------|----------|------|
| A | Empty page | NO | bounded | NO | YES | YES |
| B | Duplicate page | NO | bounded | NO | YES | YES |
| C | Unknown parent | NO | bounded | NO | YES | YES |
| D | Partial page | NO | bounded | NO | YES | YES |
| E | Wrong order | NO | bounded | NO | YES | YES |
| F | Silent peer | NO | bounded | NO | YES | YES |
| G | Flood | NO | bounded | NO | YES | YES |
| H | Contradictory response | NO | bounded | NO | YES | YES |

## 5. Convergence Invariants

| ID | Description | PASS |
|----|-------------|------|
| I1 | All inserted txs have required parents | YES |
| I2 | No valid tx applied twice | YES |
| I3 | inflight <= MAX_INFLIGHT_REQUESTS | YES |
| I4 | frontier memory <= MAX_FRONTIER_ENTRIES | YES |
| I5 | Applied page never becomes pending | YES |
| I6 | Satisfied request never becomes REQUESTED | YES |
| I7 | tx count never decreases during sync | YES |
| I8 | Sync progresses or explicitly enters WAITING/FAILED | YES |
| I9 | After primary peer fails, secondary peer resumes | YES |
| I10 | Finite valid history converges | YES |
| I11 | DAG fingerprint matches source exactly | YES |
| I12 | Ledger fingerprint matches source exactly | YES |

## 6. Combined Tests

| Test | Description | Time (ms) | PASS |
|------|-------------|-----------|------|
| 1 | 10K + interrupt @30% | 6,994 | YES |
| 2 | 10K + malicious (wrong order) | — | YES |
| 3 | 10K + malicious + interrupt @60% | — | YES |
| 4 | 10K + peer failover @25% | — | YES |
| 5 | 10K + restart from persisted store | — | YES |

## 7. Benchmark OLD vs NEW

### OLD (rebuild_dag_topological — flat topological insert)

- **10K txs**: 6,801ms, 0 orphans, 0 skipped

### NEW (ancestor_full_closure + pagination + frontier monotone)

- **10K txs**: 7,042ms, 0 orphans, 955 pages, frontier_peak=10,000, inflight_peak=64

### Analysis

The new pipeline adds ~3.5% overhead (7,042 vs 6,801ms) due to:
- Ancestor closure BFS computation per page
- Frontier state tracking (HashMap insert/update per hash)
- Adaptive backpressure delays
- Structured logging

This overhead is acceptable given the new guarantees:
- Monotone progress tracking
- Peer failover without data loss
- Bounded memory (100K hashes max)
- Stall detection with structured state machine

## 8. Harness Validation

The test harness verifies:
- **Independence**: source and fresh nodes are completely separate DAG instances
- **Empty start**: fresh node starts from `initialize_genesis()` (0 txs)
- **Fingerprint integrity**: `state_fingerprint()` computes on final persistent state (sorted tx ids, tips, weights, balances, nonces, supply)
- **Error propagation**: `assert!` and `assert_eq!` fail the test on any invariant violation
- **Timeout**: release-mode tests complete within seconds (no artificial timeouts)
- **Determinism**: `build_ladder()` produces identical tx sets across runs

## 9. Remaining Risks

1. **Wire format**: The test harness simulates P2P sync at the data level. The actual TCP transport (encryption, framing, async I/O) is tested separately by the existing P2P test suite.
2. **Real network latency**: The harness measures computation time only. Real-world sync over WAN links will be bandwidth-limited.
3. **Concurrent sync + transaction processing**: The test harness does not simulate simultaneous local transaction creation during sync.
4. **Large DAG topology**: The ladder pattern produces a 22-wide DAG. Real DAGs may have different topology (deeper/wider branches).

## Verdict

```
DEEP_SYNC_100  = PASS
DEEP_SYNC_400  = PASS
DEEP_SYNC_800  = PASS
DEEP_SYNC_1600 = PASS
DEEP_SYNC_3200 = PASS
DEEP_SYNC_6400 = PASS
DEEP_SYNC_10K  = PASS

INTERRUPTION    = PASS
MALICIOUS_PEER  = PASS
CONVERGENCE     = PASS
HARNESS         = PASS
REGRESSION      = PASS

DEEP_SYNC = PASSED
```
