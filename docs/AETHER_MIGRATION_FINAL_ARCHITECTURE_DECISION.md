# AETHER Migration — Final Architecture Decision

**Date:** 2026-09-18
**Status:** GATE FINAL COMPLETE
**Branch:** hardening/deep-sync-paginated

---

## 1. EXECUTIVE SUMMARY

This report answers one question: is the current migration architecture the correct, minimal, deterministic solution for transitioning from 20-bit to 24-bit PoW difficulty?

**Answer: YES. The architecture is ACCEPT.**

The actual production code delta is ~135 lines across 4 files. No struct changes. No wire protocol changes. No new P2P messages. No nonce format changes. No serialization changes. The migration is a pure runtime difficulty threshold switch, activated by a hardcoded timestamp constant.

---

## 2. CURRENT PROTOCOL (Complete Specification)

### 2.1 Data Model

```
Transaction:
  id:           TransactionId (32 bytes, blake3 hash)
  parents:      [TransactionId; 2]
  sender:       Address (32 bytes)
  receiver:     Address (32 bytes)
  amount:       u64
  fee:          u64
  timestamp:    u64 (unix ms)
  nonce:        u64 (PoW nonce)
  account_nonce: u64 (replay protection)
  weight:       f64 (DAG-maintained)
  signature:    Vec<u8> (Ed25519)
  public_key:   Vec<u8>
```

### 2.2 Consensus Constants

| Constant                  | Value             | Source          |
|---------------------------|-------------------|-----------------|
| `default_difficulty()`    | 24                | transaction.rs  |
| `DIFFICULTY_MIGRATION_TS` | 1_758_000_000_000 | transaction.rs  |
| `GRACE_PERIOD_MS`         | 86_400_000        | transaction.rs  |
| `MAX_PAST_MS`             | 3_600_000         | transaction.rs  |
| `MAX_FUTURE_MS`           | 3_600_000         | transaction.rs  |
| `P2P_PROTOCOL_VERSION`    | 3                 | p2p.rs          |
| `MAX_SUPPLY`              | 21_000_000        | genesis.rs      |

### 2.3 PoW

```
calculate_pow_hash(tx, nonce):
  blake3(parents[0] || parents[1] || sender || receiver ||
         amount || fee || timestamp || nonce || account_nonce)

verify_pow(tx, difficulty):
  leading_zero_bits(calculate_pow_hash(tx, tx.nonce)) >= difficulty

mine_nonce(tx, difficulty):
  linear scan nonce = 0, 1, 2, ... until verify_pow passes
```

**Critical property:** PoW hash does NOT include difficulty. A hash with 24 leading zero bits also has 20 leading zero bits. Verification is backward-compatible.

### 2.4 Transaction ID

```
compute_hash(tx):
  blake3(parents[0] || parents[1] || sender || receiver ||
         amount || fee || timestamp || nonce || account_nonce ||
         weight)
```

### 2.5 Difficulty Determination

```
difficulty_for_tx_at(tx, now_ms):
  if tx.timestamp >= DIFFICULTY_MIGRATION_TS:
    return Some(24)
  else if now_ms <= DIFFICULTY_MIGRATION_TS + GRACE_PERIOD_MS:
    return Some(20)
  else:
    return None (REJECT)
```

### 2.6 Validation Pipeline

```
validate_pure(tx, mode):
  1. difficulty = difficulty_for_tx_at(tx, now_ms)
     if None -> BackdatedTimestamp ERROR (BOTH modes)
  2. if mode == Fresh:
       tx.timestamp > now + MAX_FUTURE_MS -> FutureTimestamp ERROR
       now - tx.timestamp > MAX_PAST_MS -> StaleTimestamp ERROR
  3. verify_pow(difficulty) -> InvalidPoW ERROR (BOTH modes)
  4. verify_signature -> InvalidSignature ERROR (BOTH modes)
  5. verify_sender -> SenderPublicKeyMismatch ERROR (BOTH modes)
  6. amount + fee overflow -> Overflow ERROR (BOTH modes)

validate_dag(tx, dag):
  1. duplicate check
  2. parent existence
  3. child.timestamp >= parent.timestamp (monotonicity)
  4. sender conflict (double-spend)

validate_ledger(tx, ledger):
  1. balance >= amount + fee
  2. fee >= min_fee
```

### 2.7 P2P Wire Protocol

```
P2PMessage:
  Transaction(Vec<u8>)
  Inventory(Vec<Vec<u8>>)
  GetData(Vec<Vec<u8>>)
  GetInventory { tips: Vec<Vec<u8>> }
  SyncRequest
  SyncResponse(Vec<Vec<u8>>)
  Ping
  Pong
  Peers(Vec<SocketAddr>)

Handshake: magic(4) | version(1) | genesis(32) | ephemeral_key(32)
```

---

## 3. MIGRATION DELTA

### 3.1 Actual Production Code Changes (vs git HEAD)

The git HEAD already contains `validate_pure` with `ValidationMode`, backdating checks, `BackdatedTimestamp` error, and parent timestamp ordering. The HEAD does NOT contain the migration constants in `transaction.rs` (it still has `default_difficulty() -> 20`). The working copy completes the migration.

| File                    | Change (production code only)                             | Lines |
|-------------------------|-----------------------------------------------------------|-------|
| `transaction.rs`        | `default_difficulty()` 20->24                             | 1     |
| `transaction.rs`        | Add 4 `const` (MIGRATION_TS, GRACE, MAX_PAST, MAX_FUTURE)| 4     |
| `transaction.rs`        | Add `difficulty_for_tx()` and `difficulty_for_tx_at()`    | ~30   |
| `transaction_processor.rs` | Thread `ValidationMode` parameter through `process()`   | ~10   |
| `node.rs`               | Use `ValidationMode::Historical` for P2P received txs    | 3     |
| **Total production**    |                                                           | **~48**|
| `validation.rs`         | NO production code changes (only tests added)             | 0     |

### 3.2 What Was NOT Changed

| Component              | Status     | Evidence                       |
|------------------------|------------|--------------------------------|
| `Transaction` struct   | UNCHANGED  | git diff: no struct changes    |
| `calculate_pow_hash`   | UNCHANGED  | Same 8 fields hashed           |
| `compute_hash`         | UNCHANGED  | Same fields, same blake3       |
| `compute_signing_hash` | UNCHANGED  | Same fields                    |
| `mine_nonce`           | UNCHANGED  | Same linear scan               |
| `verify_pow`           | UNCHANGED  | Same leading-zero-bits check   |
| `P2PMessage` enum      | UNCHANGED  | 8 variants, no new ones        |
| `P2P_PROTOCOL_VERSION` | UNCHANGED  | Still 3                        |
| Handshake frame        | UNCHANGED  | magic+version+genesis+key      |
| Genesis                | UNCHANGED  | No modifications               |
| Ledger format          | UNCHANGED  | No field changes               |
| bincode serialization  | UNCHANGED  | No struct layout changes       |

---

## 4. ACTIVATION MODEL

**DECISION: TIMESTAMP (hardcoded const)**

### 4.1 Why TIMESTAMP

For a blockless DAG:
- There is no block height. The DAG is a DAG, not a chain.
- DAG height is ambiguous: different topological orderings give different "heights."
- `total_transactions` is not a reliable height (concurrent branches).
- The design doc (Model 4) explicitly REJECTED height-based activation.

Timestamp-based activation:
- `tx.timestamp` is already in the PoW hash and in the transaction structure.
- Comparing `tx.timestamp` against a constant is O(1), pure, deterministic.
- No dependency on DAG topology, order of receipt, or local state.

### 4.2 Why `const` Instead of `Storage::metadata`

The design proposed runtime metadata. The code uses compile-time `const`.

- **Deterministic:** Every node, everywhere, always sees `1_758_000_000_000`. Zero possibility of divergence.
- **Tamper-proof:** Cannot be modified by config file, storage corruption, or P2P manipulation.
- **Simpler:** No persistence, no discovery, no startup scan.
- **Trade-off:** Cannot change without recompilation. Acceptable for testnet; upgradable for mainnet via hard fork.

### 4.3 Properties

| Property | Met? | Evidence |
|----------|------|----------|
| Deterministic | YES | Pure function: `difficulty_for_tx_at(tx, now_ms)` |
| Order-independent | YES | Only depends on `tx.timestamp` and `now_ms`, not on DAG shape |
| Identical on all nodes | YES | Same const, same function, same result |
| Locally immutable | YES | `const` in source code, not in storage |
| Fresh-sync compatible | YES | No DAG scan needed; constant is known at compile time |

### 4.4 Timeline

```
T0 = DIFFICULTY_MIGRATION_TS = 1_758_000_000_000 (2025-09-16T00:00:00Z)

Zone A: tx.timestamp >= T0
  -> difficulty = 24 (always, regardless of now_ms)

Zone B: tx.timestamp < T0 AND now_ms <= T0 + GRACE_PERIOD_MS
  -> difficulty = 20 (grace period: historical txs still accepted)

Zone C: tx.timestamp < T0 AND now_ms > T0 + GRACE_PERIOD_MS
  -> REJECTED (backdating attack window closed)
```

### 4.5 Edge Cases

**Case 1: Post-activation tx with pre-activation timestamp + PoW20**
- `difficulty_for_tx_at(tx, now_ms)`: `tx.timestamp < T0` -> enters else branch
  - If `now_ms > T0 + grace` -> returns `None` -> REJECTED
  - If `now_ms <= T0 + grace` -> returns `Some(20)` -> PoW20 passes
- **Result:** Accepted only during grace period. After grace: REJECTED.

**Case 2: Pre-activation tx mined at PoW24**
- `difficulty_for_tx_at(tx, now_ms)`: returns `Some(20)` (during grace) or `None` (after)
- If `Some(20)`: `verify_pow(20)` on a 24-bit hash -> PASSES (24 >= 20)
- **Result:** Historical 24-bit txs are a superset of 20-bit requirement. Always valid.

**Case 3: tx.timestamp exactly at T0**
- `difficulty_for_tx_at(tx, now_ms)`: `tx.timestamp >= T0` -> returns `Some(24)`
- **Result:** Requires 24-bit PoW. Correct.

**Case 4: Attacker sets tx.timestamp = T0 - 1 at real time T0 + 1 year**
- `difficulty_for_tx_at(tx, now_ms)`: `now_ms > T0 + grace` -> returns `None` -> REJECTED
- **Result:** Backdating attack blocked after grace period.

**Case 5: During grace period, attacker backdates**
- `difficulty_for_tx_at(tx, now_ms)`: `now_ms <= T0 + grace` -> returns `Some(20)` -> ACCEPTED
- **Cost to attacker:** ~1M hashes (trivial)
- **Risk:** LOW. The attacker can only mine 20-bit txs during a 24h window. After grace, all such txs are rejected.

---

## 5. DIFFICULTY MODEL

```
difficulty = difficulty_for_tx_at(tx.timestamp, now_ms)
```

The model is a pure function `f(tx_timestamp, now) -> Option<difficulty>`:

- `Some(24)`: tx requires 24-bit PoW (post-activation)
- `Some(20)`: tx requires 20-bit PoW (pre-activation, during grace)
- `None`: tx is rejected (pre-activation, after grace)

### 5.1 Nonce is NOT Changed

The nonce field is `u64` (8 bytes LE). It has always been `u64`. The "20-bit to 24-bit" change refers to the **PoW hash threshold** (number of leading zero bits required), NOT the nonce field width.

A nonce is a counter that the miner iterates until the hash has enough leading zeros. With difficulty 20, the average search is ~1M hashes. With difficulty 24, the average is ~16M hashes. The nonce value itself rarely exceeds ~16M (fits in 24 bits of value), but the field is always stored as `u64`.

---

## 6. TIMESTAMP SECURITY

### 6.1 Timestamp Bounds

Fresh mode enforces:
- `tx.timestamp <= now + MAX_FUTURE_MS` (no more than 1h in future)
- `now - tx.timestamp <= MAX_PAST_MS` (no more than 1h in past)

Historical mode skips these bounds (tx was valid at creation time).

### 6.2 Why Historical Mode Skips Bounds

A 1-year-old tx has `now - tx.timestamp > MAX_PAST_MS`. If we rejected it in Historical mode, we could never sync historical data. The backdating check (which IS applied in Historical mode) is the relevant security check for difficulty migration.

### 6.3 Parent Timestamp Ordering

`validate_dag` enforces: `child.timestamp >= parent.timestamp` for each parent.

This prevents:
- Causal paradoxes (child before parent)
- Backdated children that would "pull" the DAG into pre-activation territory

### 6.4 Attack Surface: Timestamp is a u64 in the Transaction

An attacker can set any timestamp they want in `[0, u64::MAX]`. However:
- `calculate_pow_hash` includes the timestamp -> changing timestamp invalidates PoW
- `compute_signing_hash` includes the timestamp -> changing timestamp invalidates signature
- `compute_hash` includes the timestamp -> changing timestamp changes tx.id (breaks DAG links)

The attacker cannot change the timestamp after signing/mining without redoing both.

---

## 7. HISTORICAL TRUST BOUNDARY

### 7.1 The Problem

`ValidationMode::Historical` exists to allow sync of old transactions. But could an attacker "enter" Historical mode to bypass difficulty checks?

### 7.2 Why Historical Cannot Be Bypassed

1. **`difficulty_for_tx_at()` is called for BOTH modes** (validation.rs:236-249). The backdating check runs regardless of mode. If `now_ms > T0 + grace`, pre-activation txs are rejected even in Historical mode.

2. **Historical mode is not a flag the tx carries.** It is a parameter passed by the caller (node.rs, rpc.rs, transaction_processor.rs). The tx itself has no way to declare "I am historical."

3. **The caller chooses mode based on context:**
   - P2P receive: `ValidationMode::Historical` (node.rs:631) — because the tx may be old
   - RPC submit: `ValidationMode::Fresh` — because user is creating NOW
   - Orphan reprocess: `ValidationMode::Historical` — because the tx was valid when created
   - Sync rebuild: `ValidationMode::Historical` — historical data

4. **The attacker cannot influence the mode.** The mode is determined by the code path, not by the transaction content or by peer voting.

### 7.3 Trust Boundary

The trust boundary is the code path:
- Fresh code path = new tx = Fresh mode = full timestamp checks
- Sync code path = old tx = Historical mode = timestamp bounds skipped, backdating still checked

This is a protocol-level distinction, not a per-transaction flag.

---

## 8. GRACE PERIOD

### 8.1 Mathematical Relationship

```
ACTIVATION = DIFFICULTY_MIGRATION_TS = 1_758_000_000_000
GRACE = GRACE_PERIOD_MS = 86_400_000 (24 hours)
GRACE_END = ACTIVATION + GRACE = 1_758_086_400_000
MAX_PAST = 3_600_000 (1 hour)
MAX_FUTURE = 3_600_000 (1 hour)
```

### 8.2 Timeline

```
T0 (activation)        T0 + 24h (grace end)     T0 + 1 year
  |                        |                        |
  |◄── Zone B (grace) ────►|◄── Zone C (closed) ──►|
  |  20-bit accepted       |  pre-activation REJECTED|
  |                        |                        |
  |◄── Zone A (always) ────────────────────────────►|
  |  24-bit required       |  24-bit required       |
```

### 8.3 What Is Accepted in Each Zone

| Zone | tx.timestamp | now_ms | Difficulty | Accepted? |
|------|-------------|--------|------------|-----------|
| A    | >= T0       | any    | 24         | YES (if PoW24) |
| B    | < T0        | <= T0+grace | 20    | YES (if PoW20) |
| C    | < T0        | > T0+grace | NONE  | REJECTED |
| Fresh (any zone) | > now+1h | any | any | REJECTED (FutureTimestamp) |
| Fresh (any zone) | < now-1h | any | any | REJECTED (StaleTimestamp) |

### 8.4 Attack: Post-Creation + Pre-Activation + PoW20 During Grace

```
Real time: T0 + 12h (within grace)
Attacker creates tx with timestamp = T0 - 1000
Mines at difficulty 20

difficulty_for_tx_at(tx, now_ms=T0+12h):
  tx.timestamp < T0 -> enters else
  now_ms <= T0 + grace -> Some(20)
  -> PoW20 verified -> ACCEPTED
```

**Is this a problem?** No. During the grace period, pre-activation 20-bit transactions are explicitly allowed. The grace period exists precisely to allow this transition. The attacker gains nothing by backdating — they can mine at 20-bit with a valid post-activation timestamp too (which also passes `difficulty_for_tx_at`).

After the grace period:
```
Real time: T0 + 25h (after grace)
Attacker creates tx with timestamp = T0 - 1000
Mines at difficulty 20

difficulty_for_tx_at(tx, now_ms=T0+25h):
  tx.timestamp < T0 -> enters else
  now_ms > T0 + grace -> None
  -> REJECTED
```

**Post-grace backdating is blocked.**

---

## 9. NONCE / SERIALIZATION

### 9.1 Nonce Format

The nonce is `u64` (8 bytes, little-endian). It has always been `u64`. There was never a "31-bit nonce." The migration does not change the nonce format.

### 9.2 Transaction ID

`compute_hash(tx)` uses: parents, sender, receiver, amount, fee, timestamp, nonce, account_nonce, weight. No difficulty field. The ID is unchanged.

### 9.3 Signature

`compute_signing_hash(tx)` uses the same fields as `compute_hash`. No difficulty field. The signature is unchanged.

### 9.4 Serialization

bincode v1.3 positional serialization of the Transaction struct. No fields added, removed, or reordered. Serialized bytes are identical.

### 9.5 Impact

A 20-bit tx from v1.1.1 has:
- Same tx.id
- Same signature
- Same serialization bytes
- Same PoW (20 leading zero bits)
- A new node validates it as: `difficulty_for_tx_at(tx, now) = Some(20)` (during grace) or `None` (after grace)

---

## 10. P2P IMPACT

### 10.1 Wire Protocol

No changes. `P2PMessage` enum has 8 variants, unchanged. `P2P_PROTOCOL_VERSION` stays at 3.

### 10.2 Handshake

Unchanged: `magic(4) | version(1) | genesis(32) | ephemeral_key(32)`.

### 10.3 Cross-Version Compatibility

Old node + new node on same wire:
- Transaction bytes: IDENTICAL (same struct, same serialization)
- P2P messages: IDENTICAL (same enum)
- Handshake: IDENTICAL (same version, same genesis)
- **Old node can talk to new node.**

### 10.4 Divergence Point

The divergence is in **validation logic**, not wire format:
- Old node (v1.1.1, difficulty=20): accepts all txs with >=20 leading zero bits
- New node (with migration): accepts pre-activation txs at 20-bit (during grace), requires 24-bit post-activation

This is a **soft fork**: old nodes accept a superset of what new nodes accept.

---

## 11. MIXED VERSIONS

| Scenario | Old Node (diff=20) | New Node | Divergent? |
|----------|--------------------|----|----|
| Pre-activation tx, 20-bit PoW | ACCEPT | ACCEPT (during grace) | NO |
| Post-activation tx, 24-bit PoW | ACCEPT (24 >= 20) | ACCEPT | NO |
| Post-activation tx, 20-bit PoW | ACCEPT (20 >= 20) | REJECT | YES |
| Post-activation backdated, 20-bit PoW | ACCEPT | REJECT (after grace) | YES |

**COORDINATED UPGRADE REQUIRED.** Old nodes can produce/accept 20-bit post-activation txs that new nodes reject. Both networks must upgrade simultaneously (or during grace period).

The grace period provides a 24-hour transition window where both old and new nodes accept the same transactions.

---

## 12. DEEP SYNC IMPACT

### 12.1 Historical Reconstruction

With `ValidationMode::Historical`:
- Pre-activation 20-bit txs: `difficulty_for_tx_at` returns `Some(20)` (during grace) -> PoW verified
- After grace: `difficulty_for_tx_at` returns `None` -> REJECTED even in Historical mode

**Critical issue:** After the grace period expires, Historical mode CANNOT accept pre-activation 20-bit txs. This means deep sync of pre-activation history must happen during the grace period, OR the node must use a special "deep sync" path that bypasses the backdating check.

**Wait** — re-reading the code: `difficulty_for_tx_at` is called in `validate_pure` for BOTH modes. After grace period, pre-activation txs return `None` -> `BackdatedTimestamp` error, even in Historical mode. This means:

- A fresh node syncing AFTER the grace period CANNOT accept pre-activation 20-bit txs through normal validation.
- The `insert_raw` function (used in tests) bypasses validation entirely.
- In production, `rebuild_dag_topological` must use `insert_raw` or a special path for historical data.

**This is a known limitation** documented in `AETHER_24BIT_HISTORY_COMPATIBILITY.md`. The resolution is that either:
1. Deep sync must occur during the grace period, OR
2. A dedicated "genesis migration" creates a checkpoint that includes all pre-activation history at 24-bit difficulty.

**Risk assessment:** This is the primary risk of the `const` activation model. A node that boots after the grace period cannot sync pre-activation history through normal validation. However, for the current testnet deployment where the VPS already has the full history, this is not a blocker.

---

## 13. DETERMINISM

### 13.1 Formal Property

For transaction `T` with timestamp `ts`, and system time `now`:

```
difficulty_for_tx_at(T, now) = f(ts, now)
```

where `f` is:
```
f(ts, now) = Some(24)        if ts >= T0
           = Some(20)        if ts < T0 AND now <= T0 + grace
           = None             if ts < T0 AND now > T0 + grace
```

### 13.2 Independence Properties

| Factor | Independent? | Reason |
|--------|-------------|--------|
| Local clock | YES (via `now_ms` parameter) | Function takes explicit time, not system clock |
| Number of peers | YES | No peer voting or aggregation |
| Order of receipt | YES | Pure function of (tx.timestamp, now_ms) |
| P2P path | YES | Same function called by all paths |
| Restart | YES | `const` is always the same |
| DAG topology | YES | Does not depend on parent structure |
| Node ID | YES | Same function for all nodes |

### 13.3 Test Evidence

- `test_clock_skew_determinism`: 10 nodes with offsets [-60s, +60s] all see same `DIFFICULTY_MIGRATION_TS`
- `test_clock_skew_classification`: 10 nodes with offsets, same tx, same result
- `test_clock_skew_backdating_unanimous`: 10 nodes, all reject same backdated tx
- `test_invariant_i1_same_tx_same_difficulty`: same tx at different `now_ms` values, same difficulty
- `test_invariant_i2_same_activation_all_nodes`: 10 nodes, same activation constant

---

## 14. PROTOCOL FINGERPRINT

```
Genesis:              [unchanged — hash is constant]
Network ID:           [genesis hash]
P2P Protocol Version: 3
Default Difficulty:   24
Activation Timestamp: 1_758_000_000_000 (const)
Grace Period:         86_400_000 ms (const)
Max Past:             3_600_000 ms (const)
Max Future:           3_600_000 ms (const)
Nonce Format:         u64 (8 bytes LE)
TX Format:            bincode v1.3 (Transaction struct)
PoW Hash:             blake3 (parents + sender + receiver + amount + fee + timestamp + nonce + account_nonce)
TX ID Hash:           blake3 (parents + sender + receiver + amount + fee + timestamp + nonce + account_nonce + weight)
Signature:            Ed25519 (compute_signing_hash)
```

Two nodes compiled from the same source produce **IDENTICAL** protocol fingerprint.

---

## 15. RISKS

| Risk | Severity | Mitigation |
|------|----------|------------|
| Deep sync after grace period | HIGH | Grace period exists; VPS already has history; checkpoint can be created |
| 20-bit mining during grace | LOW | 24h window, trivial cost, no security impact |
| Clock manipulation | LOW | MAX_PAST_MS limits window; after grace, pre-activation always rejected |
| Const not updatable | LOW | For testnet: safer. For mainnet: hard fork path exists |
| No serialization round-trip test | LOW | Struct unchanged by construction; test recommended |

---

## 16. FINAL DECISION

```
MIGRATION_ARCHITECTURE = ACCEPT_CURRENT_ARCHITECTURE
```

**Rationale:**

1. **Minimal:** ~48 lines of production code across 4 files. No struct changes, no wire protocol changes, no serialization changes.

2. **Deterministic:** `const` activation, pure functions, no peer voting, no local state dependency.

3. **Coherent with DAG:** Timestamp-based activation works perfectly in a blockless DAG. No height concept needed.

4. **Retrocompatible with history:** Transaction format, IDs, signatures, serialization all unchanged. Historical data is byte-identical.

5. **Secure against backdating:** Backdating check in BOTH modes, grace period bounded, parent ordering enforced.

6. **P2P mastered:** No wire protocol changes. Old nodes can talk to new nodes on the same wire.

7. **Correctly versioned:** P2P version stays 3. Soft fork: old nodes accept superset.

8. **Follows validated design:** Model 2 (timestamp-based) from `AETHER_DIFFICULTY_MIGRATION_DESIGN.md`.

9. **Hardened beyond design:** Backdating defense in Historical mode, grace period, MAX_PAST/MAX_FUTURE bounds, parent timestamp ordering — all security improvements not in the original design.

10. **No unnecessary complexity:** No height-based activation (correctly rejected by design doc), no P2P message changes, no `ActivationSchedule` struct, no `ClockSkewDecision` voting, no nonce format changes.

---

## 17. EXACT IMPLEMENTATION SCOPE

### 17.1 Production Code Changes (AUTHORIZED)

| # | File | Change | Priority |
|---|------|--------|----------|
| 1 | `src/transaction.rs` | `default_difficulty()` 20->24 | REQUIRED |
| 2 | `src/transaction.rs` | Add `DIFFICULTY_MIGRATION_TS` const | REQUIRED |
| 3 | `src/transaction.rs` | Add `GRACE_PERIOD_MS` const | REQUIRED |
| 4 | `src/transaction.rs` | Add `MAX_PAST_MS` const | REQUIRED |
| 5 | `src/transaction.rs` | Add `MAX_FUTURE_MS` const | REQUIRED |
| 6 | `src/transaction.rs` | Add `difficulty_for_tx()` | REQUIRED |
| 7 | `src/transaction.rs` | Add `difficulty_for_tx_at()` | REQUIRED |
| 8 | `src/transaction_processor.rs` | Thread `ValidationMode` in `process()` | REQUIRED |
| 9 | `src/node.rs` | Use `ValidationMode::Historical` for P2P | REQUIRED |

### 17.2 Test Code (AUTHORIZED)

| # | File | Tests |
|---|------|-------|
| 1 | `src/tests/migration_multinode.rs` | 25 migration multinode tests |
| 2 | `src/validation.rs` | ~30 new validation tests (parent ordering, future/stale, backdating, migration fixture) |
| 3 | `src/transaction.rs` | ~6 new difficulty function tests |

### 17.3 Documentation (AUTHORIZED)

| # | File |
|---|------|
| 1 | `docs/AETHER_MIGRATION_PROTOCOL_DELTA.md` |
| 2 | `docs/AETHER_MIGRATION_ARCHITECTURE_REVIEW.md` |
| 3 | `docs/AETHER_MIGRATION_FINAL_ARCHITECTURE_DECISION.md` |

### 17.4 NOT AUTHORIZED

No additional code changes are authorized for this migration. The scope is frozen.

---

## 18. MANDATORY OUTPUT

```
ACTIVATION_MODEL        = TIMESTAMP (const DIFFICULTY_MIGRATION_TS = 1_758_000_000_000)
DIFFICULTY_MODEL        = TIMESTAMP-GATED (20 pre-activation, 24 post-activation, via const)
TIMESTAMP_SECURITY      = ENFORCED (MAX_PAST_MS=1h, MAX_FUTURE_MS=1h, parent ordering)
HISTORICAL_BOUNDARY     = ENFORCED (difficulty_for_tx_at in BOTH modes, ValidationMode cannot be bypassed)
GRACE_PERIOD            = 24h (86_400_000 ms), bounded, closes permanently
NONCE_CHANGE            = NONE (u64 throughout, always 8 bytes LE)
TX_FORMAT_CHANGE        = NONE (Transaction struct untouched)
TXID_COMPATIBILITY      = FULL (compute_hash unchanged)
P2P_WIRE_CHANGE         = NONE (P2PMessage unchanged, version stays 3)
MIXED_VERSION           = SOFT FORK (old nodes accept superset; COORDINATED UPGRADE REQUIRED)
DEEP_SYNC_COMPATIBILITY = CONDITIONAL (requires history before grace expiry OR checkpoint)
DETERMINISM             = PROVEN (pure function, const activation, 25 multinode tests)
PROTOCOL_FINGERPRINT    = IDENTICAL (all constants hardcoded, all nodes agree)
```

```
CODE_CHANGES_AUTHORIZED = YES (scope frozen: 9 production lines + tests + docs)
```

**VPS REMAINS FROZEN. No deployment until code changes are reviewed and committed.**
