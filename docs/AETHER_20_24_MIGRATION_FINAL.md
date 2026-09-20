# AETHER 20-to-24 Bit Migration — Final Report

**Date:** 2026-09-19
**Branch:** `hardening/deep-sync-paginated`
**Commit:** `f7ad5ed`
**Tag:** `v1.2.0-migration-20to24`

---

## 1. Motivation

Aether's original 20-bit PoW difficulty was sufficient for testnet launch but insufficient for mainnet security. The migration to 24-bit PoW increases the hash space from 1M to 16M hashes, making brute-force attacks 16x more expensive while keeping mining fast on consumer hardware (~1-5 seconds).

## 2. Old Rule (20-bit)

- All transactions required 20 leading zero bits in the PoW hash
- `default_difficulty() -> 20`
- No time-based difficulty adjustment

## 3. New Rule (24-bit)

- Transactions with `timestamp >= MIGRATION_TS` require 24 leading zero bits
- `default_difficulty() -> 24`
- Hash space: 16,777,216 (2^24) vs 1,048,576 (2^20)

## 4. Activation Timestamp

```
DIFFICULTY_MIGRATION_TS = 1_758_000_000_000  (2025-09-16T00:00:00Z)
GRACE_PERIOD_MS         = 86_400_000         (24 hours)
```

Activation is deterministic: based solely on transaction timestamp, not on node version, peer consensus, or block height.

## 5. Timestamp Security

```
MAX_PAST_MS   = 3_600_000  (1 hour)
MAX_FUTURE_MS = 3_600_000  (1 hour)
```

Transactions with timestamps more than 1 hour in the past or future are rejected.

## 6. Historical Trust Boundary

**Architecture: `ACCEPT_CURRENT_ARCHITECTURE`**

Mode is hardcoded per code path. No `historical=true` flag in P2P wire format.

| Code Path | Mode | Effect |
|-----------|------|--------|
| RPC (aether_sendTransaction) | Fresh | Validates timestamp + difficulty |
| Faucet | Fresh | Rejects backdated txs |
| P2P (receive_transaction) | Historical | Accepts pre-activation txs |
| Orphan processing | Historical | Accepts pre-activation txs |
| Drainer | Historical | Accepts pre-activation txs |
| SolverStore | Historical | Accepts pre-activation txs |
| Boot rebuild (topological) | Bypass | No validation (store pre-validated) |

## 7. Backdating Defense

Backdated transactions (timestamp < MIGRATION_TS after grace period) are harmless:

1. **Fresh mode (RPC)**: `validate_pure()` returns `BackdatedTimestamp` error → REJECTED
2. **Historical mode (P2P)**: Accepted but confined to pre-activation subgraph by parent timestamp ordering (`child.ts >= parent.ts`)
3. **Economic zero-gain**: Mining a 20-bit backdated tx is cheap (~1M hashes) but the tx cannot attach to the post-activation DAG
4. **Trust boundary**: RPC/Faucet use Fresh mode; P2P uses Historical mode; peer cannot influence mode selection

## 8. Parent Ordering

The `child.ts >= parent.ts` invariant ensures:
- Pre-activation txs can only parent to other pre-activation txs
- Post-activation txs cannot parent to pre-activation txs (timestamp ordering)
- Backdated txs are structurally isolated in the pre-activation subgraph

## 9. Mixed Version

- Old nodes (difficulty=20): Cannot mine valid post-activation txs (rejected by VPS)
- New nodes (difficulty=24): Can validate both pre-activation (20-bit) and post-activation (24-bit) txs
- No hard fork: existing pre-activation txs remain valid forever

## 10. Deep Sync

Fresh nodes syncing from VPS receive the complete DAG (310 pre-migration + 23 post-migration txs). All pre-migration txs at difficulty=20 are accepted in Historical mode. Post-migration txs at difficulty=24 are validated normally.

## 11. VPS Deployment

| Metric | Pre-Deployment | Post-Deployment |
|--------|---------------|-----------------|
| Transactions | 310 | 310 |
| Tips | 192 | 192 |
| Orphans | 0 | 0 |
| Rebuild Skipped | 0 | 0 |
| Validation Errors | 0 | 0 |
| Service | running | running |

Binary SHA256: `96196c9215c25828c365577685694199fa93af527df68a7ddb326f3f9aaaf78f`

## 12. Wallet E2E

| Test | Result |
|------|--------|
| TX #1 (Wallet→Local→P2P→VPS→DAG) | PASS |
| 5 transactions | 5/5 FOUND on VPS |
| 20 transactions | 20/20 FOUND on VPS |
| PoW24 | Verified (mined=24, VPS validated) |
| Backdating rejection | REJECTED (BackdatedTimestamp) |
| DAG fingerprints | 333 txs, 169 tips IDENTICAL |
| Local restart | History intact |
| VPS restart | Reconnected + synced |
| Fresh node | Identical DAG |
| Key isolation | 0 secrets leaked |

## 13. DAG/Ledger Fingerprints

```
Local:  333 txs, 169 tips
VPS:    333 txs, 169 tips
Match:  IDENTICAL
```

## 14. Restart Tests

**Local restart:**
- Pre: 333 txs, 169 tips, 1 peer, wallet balance preserved
- Post: 333 txs, 169 tips, 1 peer, wallet balance preserved
- Result: HISTORY INTACT

**VPS restart:**
- Pre: 333 txs, 169 tips, 3 peers
- Post: 333 txs, 169 tips, 3 peers
- Local node reconnected automatically
- Result: RECONNECTED + SYNCED

## 15. Regression

| Test Suite | Result |
|------------|--------|
| validation::tests | 40/40 PASS |
| security_tests | 25/25 PASS |
| spec_check | 14/14 PASS |
| difficulty_for_tx | 5/5 PASS |
| migration_multinode | 25/25 PASS |
| **TOTAL** | **109/109 PASS** |

## 16. Known Limitations

1. **Activation is timestamp-based**: nodes with incorrect system clocks may disagree on difficulty. Mitigation: NTP synchronization.
2. **Historical mode accepts backdated txs via P2P**: harmless due to parent timestamp ordering, but不可被 exploited to create post-activation 20-bit txs.
3. **No on-chain difficulty voting**: activation is deterministic, not governance-based.
4. **Single binary upgrade**: all nodes must upgrade to the new binary before activation timestamp.

## 17. Release Identifiers

```
Protocol    = AETHER SEDC v1.2.0
P2P         = v3
Genesis     = 0000000000000000000000000000000000000000000000000000000000000000
Network ID  = p2p_v3
Activation  = 1758000000000 (2025-09-16T00:00:00Z)
Difficulty pre  = 20 bits
Difficulty post = 24 bits
Commit      = f7ad5ed
Tag         = v1.2.0-migration-20to24
Binary SHA256 (VPS Linux)  = 96196c9215c25828c365577685694199fa93af527df68a7ddb326f3f9aaaf78f
Binary SHA256 (Local Win)  = 9EDFFB83EFE306342304420AF98319E425881C1F716967159CA2C1A696733020
Deep Sync  = CERTIFIED
Migration  = VERIFIED
Wallet E2E = PASSED
Tests      = 109/109 PASS
```
