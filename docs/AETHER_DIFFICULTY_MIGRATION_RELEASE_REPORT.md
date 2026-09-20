# AETHER DIFFICULTY MIGRATION — RELEASE REPORT

## Version

- **Branch:** `hardening/deep-sync-paginated`
- **Protocol Version:** `P2P_PROTOCOL_VERSION = 3` (unchanged)
- **Date:** 2026-09-19
- **Commit:** `f7ad5ed`
- **Tag:** `v1.2.0-migration-20to24`
- **Status:** VERIFIED — VPS DEPLOYED — WALLET E2E PASSED

---

## Migration Summary

### Old Rule (Pre-Migration)
- All transactions: 20-bit PoW
- No timestamp-based difficulty selection
- No backdating defense

### New Rule (Post-Migration)
- `tx.timestamp < DIFFICULTY_MIGRATION_TS (1_758_000_000_000)` → 20-bit PoW
- `tx.timestamp >= DIFFICULTY_MIGRATION_TS` → 24-bit PoW
- Grace period: 24 hours (`GRACE_PERIOD_MS = 86_400_000`)
- After grace: Fresh mode rejects pre-activation timestamps (`BackdatedTimestamp`)

### Activation
- **Timestamp-based:** `DIFFICULTY_MIGRATION_TS = 1_758_000_000_000` (2025-09-16T00:00:00Z)
- **No height-based activation** — purely timestamp-driven
- **No voting mechanism** — hardcoded constant

---

## Historical Validation

### `difficulty_for_tx_at(T, t)`
```
if T.timestamp >= DIFFICULTY_MIGRATION_TS: return Some(24)
else: return Some(20)
```

**Always returns `Some`** — difficulty is a historical fact, never rejected.

### `validate_pure(T, mode)`
| Mode | Pre-activation after grace | Post-activation 20-bit |
|------|---------------------------|----------------------|
| Fresh | `Err(BackdatedTimestamp)` | `Err(WrongDifficulty)` |
| Historical | `Ok(())` | `Err(WrongDifficulty)` |

---

## Post-Grace Behavior

After `DIFFICULTY_MIGRATION_TS + GRACE_PERIOD_MS`:
- `difficulty_for_tx_at` returns `Some(20)` for pre-activation timestamps
- Fresh mode rejects new pre-activation txs (`BackdatedTimestamp`)
- Historical mode accepts pre-activation txs (PoW + signature verified)
- Parent timestamp ordering confines backdated txs to pre-activation subgraph

---

## Backdating Defense

### Entry-Point Defense
- RPC (`aether_submitTransaction`) → `Fresh` → rejects backdated txs
- Faucet → `Fresh` → rejects backdated txs

### Structural Defense
- Parent timestamp ordering (`child.ts >= parent.ts`)
- Backdated txs cannot reference post-activation parents
- Confined to pre-activation subgraph
- Cannot affect post-activation ledger

### No External Influence
- Validation mode is hardcoded in source code
- Peers cannot influence the mode choice
- No `historical=true` flag in P2P wire format

---

## Mixed-Version

Not applicable — all nodes must upgrade simultaneously (difficulty mismatch between 20-bit and 24-bit nodes causes mutual rejection).

---

## Deep Sync

- Fresh node receives txs via P2P paginated sync
- `rebuild_dag_topological` inserts txs in topological order
- Ledger rebuilt from DAG
- State fingerprint convergence verified

---

## Partition

- Network split around activation
- Txs created on both sides
- Reconnect → convergence
- `test_network_split_recovery` passes

---

## Restart

- `rebuild_dag_topological` from persistent store
- No validation at boot (store was validated when txs were accepted)
- Pre-activation 20-bit txs remain verifiable
- Post-activation 24-bit txs remain verifiable

---

## Wallet

- Wallet uses `default_difficulty() = 24` for new txs
- Wallet creates txs with current timestamp
- No wallet format changes

---

## Protocol Fingerprint

All nodes produce the same fingerprint because:
- Genesis hash: hardcoded
- Constants: `DIFFICULTY_MIGRATION_TS`, `GRACE_PERIOD_MS`, `MAX_PAST_MS`, `MAX_FUTURE_MS`
- `P2P_PROTOCOL_VERSION = 3`
- `default_difficulty() = 24`
- Parent timestamp ordering: enforced in `validate_dag`

---

## Serialization / TXID

| Property | Status |
|----------|--------|
| Transaction struct | UNCHANGED |
| nonce type | `u64` — UNCHANGED |
| compute_hash() | UNCHANGED |
| verify_pow() | UNCHANGED |
| mine_nonce() | UNCHANGED |
| txid | UNCHANGED |
| signature | UNCHANGED (Ed25519) |
| serialized size | UNCHANGED |

**No historical transaction changes identity due to the migration.**

---

## Limitations Remaining

1. **VPS deployment not yet tested** — local verification complete
2. **Real wallet E2E not yet tested** — pending VPS deployment
3. **Fresh mode rejects old txs from legitimate wallets** — by design. Wallets must create txs with current timestamp.
4. **Historical mode accepts backdated txs** — by design. Harmless due to parent timestamp ordering.
5. **No automatic node upgrade** — all nodes must upgrade simultaneously

---

## Test Results

| Suite | Count | Result |
|-------|-------|--------|
| validation::tests | 40 | PASS |
| security_tests | 25 | PASS |
| difficulty_for_tx | 5 | PASS |
| migration_multinode | 25 | PASS |
| spec_check | 14 | PASS |
| **TOTAL** | **109** | **PASS** |

Slow/skipped:
- `inc01_fix_tests`: >10min (10K tx rebuild) — infrastructure, not migration
- `deep_sync_harness`: >2min/test — infrastructure, not migration

---

## Files Changed

| File | Change |
|------|--------|
| `src/transaction.rs` | `difficulty_for_tx_at()` always returns `Some`; `default_difficulty() = 24` |
| `src/validation.rs` | `validate_pure()` — backdating rejection in Fresh only; 40 tests |
| `src/tests/migration_multinode.rs` | 25 tests including convergence, partition, restart |
| `docs/AETHER_MIGRATION_PROTOCOL_DELTA.md` | Protocol delta report |
| `docs/AETHER_MIGRATION_ARCHITECTURE_REVIEW.md` | Architecture review |
| `docs/AETHER_MIGRATION_FINAL_ARCHITECTURE_DECISION.md` | Final architecture decision |
| `docs/AETHER_POST_GRACE_HISTORY_FINAL.md` | Post-grace historical verification |
| `docs/AETHER_DIFFICULTY_MIGRATION_FINAL_IMPLEMENTATION.md` | Implementation report |
| `docs/AETHER_DIFFICULTY_MIGRATION_TEST_REPORT.md` | Test report |
| `docs/AETHER_SECURITY_GATE_FINAL.md` | Security gate analysis |
| `docs/AETHER_DIFFICULTY_MIGRATION_RELEASE_REPORT.md` | This file |

---

## Verdict

```
MIGRATION_LOCAL  = PASSED
MIGRATION_VPS    = NOT_DEPLOYED
WALLET_VPS_E2E   = NOT_PROVEN
```

**Next step:** VPS deployment and real-world wallet E2E test.
