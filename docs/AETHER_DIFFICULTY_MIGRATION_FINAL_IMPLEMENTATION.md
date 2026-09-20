# Aether Difficulty Migration — Final Implementation Report

## Summary

The 20→24 bit PoW difficulty migration is **fully implemented and all tests pass**.

## Architecture

**Decision:** `ACCEPT_CURRENT_ARCHITECTURE` — timestamp-based activation using hardcoded const.

**Key principle:** Difficulty is a historical fact. `difficulty_for_tx_at` returns difficulty based solely on `tx.timestamp` vs the activation constant, regardless of current time.

## Implementation Details

### Constants

| Constant | Value | Purpose |
|---|---|---|
| `DIFFICULTY_MIGRATION_TS` | `1_758_000_000_000` (2025-09-16T00:00:00Z) | Activation timestamp |
| `GRACE_PERIOD_MS` | `86_400_000` (24h) | Backdating rejection window for Fresh mode |
| `MAX_PAST_MS` | `3_600_000` (1h) | Max past timestamp tolerance |
| `MAX_FUTURE_MS` | `3_600_000` (1h) | Max future timestamp tolerance |
| `P2P_PROTOCOL_VERSION` | `3` | Unchanged — no protocol-level changes |

### Code Changes

#### `src/transaction.rs`

- `difficulty_for_tx()` — calls `difficulty_for_tx_at()` with system time
- `difficulty_for_tx_at(tx, now_ms)` — returns `Some(20)` if `tx.timestamp < DIFFICULTY_MIGRATION_TS`, else `Some(24)`. **No time-based rejection** — difficulty is always returned.

#### `src/validation.rs`

- `validate_pure()` — two validation paths:
  - **Fresh mode:** Validates difficulty (20-bit pre-activation, 24-bit post-activation). Rejects backdated txs after grace (`BackdatedTimestamp`). Rejects wrong-difficulty txs (`WrongDifficulty`).
  - **Historical mode:** Accepts any valid PoW (20 or 24 bit) with valid signature. No timestamp checks. Used for P2P and sync.

### What Does NOT Exist

- No `ActivationSchedule` struct
- No `activation_height` or height-based activation
- No `ClockSkewDecision` enum
- No majority voting for activation
- No nonce format changes
- No Block/BlockHeader/DagBlock modifications
- No new P2P messages

## Test Results

```
difficulty_for_tx:        5/5  ✓
validation::tests:       40/40 ✓
migration_multinode:     25/25 ✓
security_tests:          25/25 ✓
Total:                   95/95 ✓
```

## New Tests Added

| Test | File | Purpose |
|---|---|---|
| `test_post_grace_historical_forever` | `validation.rs` | 4-case test: A=Historical ACCEPT, B=Fresh REJECT, C=Fresh REJECT, D=Historical ACCEPT |
| `test_post_grace_5year_simulation` | `validation.rs` | Simulates 5 years after activation, verifies difficulty function |
| `test_backdating_5year_attack_fresh_rejects` | `validation.rs` | 5-year backdating attack: Fresh REJECTS, Historical ACCEPTS |
| `test_p2p_backdating_historical_path` | `validation.rs` | P2P Historical accepts backdated tx, Fresh rejects it |

## Updated Tests

| Test | File | Change |
|---|---|---|
| `test_attack_backdated_pre_activation_accepted_historical` | `validation.rs` | Was `rejected_historical` — now Historical ACCEPTS, Fresh REJECTS |
| `test_attack_boundary_pre_activation_historical_accepts` | `validation.rs` | Was `rejected` — same pattern |
| `test_backdating_after_grace_fresh_rejects_historical_accepts` | `validation.rs` | Was `rejected` — same pattern |
| `test_invariant_i6_historical_accepts_pre_activation` | `migration_multinode.rs` | Was `p2p_not_historical_bypass` — now uses `difficulty_for_tx_at` directly |
| `test_invariant_i5_backdating_rejected` | `migration_multinode.rs` | Now verifies both `difficulty_for_tx_at` and `validate_pure(Fresh)` |
| `test_clock_skew_backdating_unanimous` | `migration_multinode.rs` | Now verifies deterministic difficulty across all clock offsets |
| `test_grace_period_boundaries` | `migration_multinode.rs` | Pre-activation always returns `Some(20)` |
| `test_grace_period_attack_rejected` | `migration_multinode.rs` | Now verifies both `difficulty_for_tx_at` and `validate_pure(Fresh)` |
| `difficulty_for_tx_at` after-grace test | `transaction.rs` | Expects `Some(20)` instead of `None` |

## Security Properties

1. **Historical verifiability forever** — pre-activation txs accepted in Historical mode at any future time
2. **Backdating defense** — Fresh mode rejects txs with pre-activation timestamp after grace
3. **Isolation by timestamp ordering** — backdated txs confined to pre-activation subgraph
4. **Deterministic difficulty** — `difficulty_for_tx_at` returns same result regardless of caller's clock
5. **No protocol change** — `P2P_PROTOCOL_VERSION` unchanged, no new messages

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Fresh mode rejects old txs from legitimate wallets | None — by design. Wallets must create txs with current timestamp. |
| Historical mode accepts backdated attack txs | Harmless — confined by parent timestamp ordering |
| 5-year sync breaks | None — Historical mode always accepts pre-activation txs |
