# Aether Post-Grace Historical Verification — Final Architecture

## Core Property

After the 24-hour grace period expires, **pre-activation transactions remain verifiable forever** in Historical mode. This is the central security property of the migration architecture.

## How It Works

### `difficulty_for_tx_at(tx, now_ms)` — Timestamp-Based Difficulty Selection

| Condition | Returns |
|---|---|
| `tx.timestamp < DIFFICULTY_MIGRATION_TS` | `Some(20)` — pre-activation |
| `tx.timestamp >= DIFFICULTY_MIGRATION_TS` | `Some(24)` — post-activation |

**Critical fix:** Pre-activation timestamps always return `Some(20)`, regardless of current time or grace period status. The difficulty of a transaction is a **historical fact** determined solely by its timestamp, not by when it is validated.

### `validate_pure(tx, mode)` — Validation Behavior by Mode

| Mode | Pre-activation after grace | Post-activation 20-bit |
|---|---|---|
| **Fresh** | `Err(BackdatedTimestamp)` — rejected | `Err(WrongDifficulty)` — rejected |
| **Historical** | `Ok(())` — accepted | `Err(WrongDifficulty)` — rejected |

### Why This Is Secure

1. **Fresh mode rejects backdated txs** — wallet/node creating a new tx today with timestamp = activation - 1h gets `BackdatedTimestamp`
2. **Historical mode accepts them** — a node syncing old history years later can verify all pre-activation txs
3. **Parent timestamp ordering** (`child.ts >= parent.ts`) confines backdated txs to the pre-activation subgraph
4. **They cannot become parents of post-activation transactions** — isolation by timestamp ordering

## Security Model

```
Attacker creates tx today with timestamp = activation - 1h
  → Fresh mode: REJECTED (BackdatedTimestamp)
  → Cannot enter the network as a new tx

Historical sync sends the same tx 5 years later
  → Historical mode: ACCEPTS (difficulty=20, PoW verified)
  → Confined to pre-activation subgraph by parent ordering
  → Cannot affect post-activation ledger
```

## Test Coverage

| Test | What It Verifies |
|---|---|
| `test_post_grace_historical_forever` | 4 cases (A,B,C,D): old tx Historical=ACCEPT, backdated Fresh=REJECT, peer Fresh=REJECT, sync Historical=ACCEPT |
| `test_post_grace_5year_simulation` | difficulty_for_tx_at works at simulated 5-year future timestamp |
| `test_backdating_5year_attack_fresh_rejects` | 5-year backdating attack rejected by Fresh, accepted by Historical |
| `test_p2p_backdating_historical_path` | P2P Historical path accepts backdated tx, Fresh rejects it |
| `test_invariant_i6_historical_accepts_pre_activation` | Pre-activation tx always has difficulty 20 |
| `test_invariant_i5_backdating_rejected` | Backdated tx rejected by Fresh mode after grace |
