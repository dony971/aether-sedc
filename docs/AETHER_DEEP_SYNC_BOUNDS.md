# AETHER Deep Sync Bounds

## Configuration

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SYNC_PAGE` | 100 | Max transactions per SyncResponse page |
| `MAX_CLOSURE_PAGES` | 10 | Max ancestor-closure pages per GetData |
| `BACKPRESSURE_BASE_MS` | 5 | Adaptive backpressure base interval (ms) |
| `MAX_INFLIGHT_REQUESTS` | 64 | Max concurrent in-flight requests |
| `MAX_FRONTIER_ENTRIES` | 100,000 | Max hashes tracked in frontier |
| `STALL_THRESHOLD` | 30s | No progress → STALLED |
| `MAX_RETRY_ATTEMPTS` | 3 | Max retries per hash |

## Derived Bounds

| Metric | Formula | Max Value |
|--------|---------|-----------|
| Max txs per closure | MAX_SYNC_PAGE × MAX_CLOSURE_PAGES | 1,000 |
| Max txs per GetData | MAX_INV_ITEMS | 1,000 |
| Max frontier memory | MAX_FRONTIER_ENTRIES × ~200 bytes | ~20 MB |
| Max inflight memory | MAX_INFLIGHT_REQUESTS × ~100 bytes | ~6 KB |
| Max backpressure delay | BASE × sqrt(MAX_SYNC_PAGE) / 10 | ~5 ms |
| Max stall detection | STALL_THRESHOLD × 2 | 60s |

## Tested Configurations

| PAGE_SIZE | Depth | Pages | Time | Converged | PASS |
|-----------|-------|-------|------|-----------|------|
| 100 | 200 | 2 | 1ms | YES | YES |
| 250 | 500 | 2 | 3ms | YES | YES |
| 500 | 1000 | 2 | 8ms | YES | YES |

## Overflow Protection

- `ancestor_full_closure()` returns at most `max_entries` hashes
- `add_pending()` returns false when `total_tracked() >= MAX_FRONTIER_ENTRIES`
- `mark_requested()` returns false when `inflight_count() >= MAX_INFLIGHT_REQUESTS`
- No unbounded allocations possible from peer data
