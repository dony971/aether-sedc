# AETHER Migration Protocol Delta Report

**Date:** 2026-09-18
**Status:** AUDIT COMPLETE
**Scope:** Compare validated design vs actual code implementation

---

## 1. CORRECTION: Previous Session Summary Was Inaccurate

The summary produced during the implementation session contained **major factual errors** about what was implemented. This report corrects them.

| Claim in Session Summary | Actual Code Reality |
|---|---|
| `ActivationSchedule` struct | **DOES NOT EXIST** — never implemented |
| `activation_height` concept | **DOES NOT EXIST** — no height anywhere |
| `is_post_migration()` method | **DOES NOT EXIST** — inline comparison only |
| Modifications to `Block`, `BlockHeader`, `DagBlock` | **IMPOSSIBLE** — these structs do not exist (blockless DAG) |
| New P2P messages (SyncAck, InventoryRequest/Response/Ack, MempoolRequest/Response/Ack, FullBlockRequest/Response/Ack) | **DO NOT EXIST** — `P2PMessage` has 8 variants, unchanged |
| `ClockSkewDecision` enum | **DOES NOT EXIST** |
| `classify_clock_skew()` function | **DOES NOT EXIST** |
| "unanimous vs majority timestamp backdating classification" | **DOES NOT EXIST** — no voting, no majority, no consensus-from-peers |
| Nonce format change 31-bit → 24-bit | **NONCE IS u64 (64-bit)** — always has been; the change is PoW difficulty threshold, not nonce field |

---

## 2. DESIGN VALIDÉ vs CODE ACTUEL — COMPLETE DELTA

### 2.1 Activation Model

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| Mécanisme | `activation_timestamp` in `Storage::metadata` | `Transaction::DIFFICULTY_MIGRATION_TS: u64 = 1_758_000_000_000` (hardcoded `const`) | **MINOR** — design used runtime metadata, code uses compile-time constant |
| Stockage | `Storage::metadata` (persisted KV) | `const` on `Transaction` impl block | **CHANGED** — constant is simpler, no persistence needed |
| Découverte | Scan DAG → find first 24-bit tx → store timestamp | N/A — constant is always known | **SIMPLIFIED** — no discovery needed |
| Rollback | Change metadata value | Impossible — recompile required | **LESS FLEXIBLE but MORE SECURE** — cannot be accidentally modified |
| Actif partout | Oui (const hardcoded) | Oui (const hardcoded) | IDENTIQUE |

**Écart: ACCEPTABLE.** La design utilisait `Storage::metadata` comme conteneur; le code utilise un `const`. Le const est **plus sûr** car impossible à modifier par erreur, accident de config, ou attaque. Le behavior est identique: tous les nœuds voient la même valeur.

### 2.2 Difficulty Rules

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| Pré-activation | 20 bits | 20 bits | IDENTIQUE |
| Post-activation | 24 bits | 24 bits | IDENTIQUE |
| `difficulty_for_tx(tx)` | Proposed (uses system clock) | `Transaction::difficulty_for_tx(tx)` — EXISTS, uses system clock | IDENTIQUE |
| `difficulty_for_tx_at(tx, time)` | Not explicitly in design | `Transaction::difficulty_for_tx_at(tx, current_time_ms)` — EXISTS, deterministic | **ADDITION** — deterministic variant for testability |
| Activation boundary | `tx.timestamp >= activation_ts → 24` | `tx.timestamp >= DIFFICULTY_MIGRATION_TS → Some(24)` | IDENTIQUE |

**Écart: IDENTIQUE.** Les règles de difficulté sont exactement celles du design.

### 2.3 Nonce Format

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| Nonce field type | `u64` (unchanged) | `u64` (unchanged) | IDENTIQUE |
| PoW difficulty constraint | 20 bits → 24 bits (hash leading zeros) | 20 bits → 24 bits (hash leading zeros) | IDENTIQUE |
| `calculate_pow_hash` inputs | parents, sender, receiver, amount, fee, timestamp, nonce, account_nonce | Same 8 fields (transaction.rs:348-368) | IDENTIQUE |
| `mine_nonce(difficulty)` | Linear scan, increment nonce | Linear scan, increment nonce (transaction.rs:399-435) | IDENTIQUE |
| Serialization | `u64` LE = 8 bytes | `u64` LE = 8 bytes | IDENTIQUE |
| Transaction ID | `compute_hash()` — no difficulty field | `compute_hash()` — no difficulty field | IDENTIQUE |

**Écart: IDENTIQUE.** Le nonce n'a JAMAIS changé de format. La migration concerne la difficulté du PoW (nombre de zéros en tête du hash), pas la taille du champ nonce.

### 2.4 Transaction Struct

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `Transaction` fields | NO CHANGES | NO CHANGES — struct unchanged | IDENTIQUE |
| `calculate_pow_hash` | NO CHANGES | NO CHANGES | IDENTIQUE |
| `compute_hash` | NO CHANGES | NO CHANGES | IDENTIQUE |
| bincode serialization | NO CHANGES | NO CHANGES | IDENTIQUE |
| Signature verification | NO CHANGES | NO CHANGES | IDENTIQUE |

**Écart: IDENTIQUE.** Le design imposait `NE PAS CHANGER Transaction struct` et c'est respecté.

### 2.5 Block / BlockHeader / DagBlock

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `Block` struct | N/A — blockless DAG | **N'EXISTE PAS** | N/A |
| `BlockHeader` struct | N/A | **N'EXISTE PAS** | N/A |
| `DagBlock` struct | N/A | **N'EXISTE PAS** | N/A |

**Note:** Ces structures n'existent pas dans le codebase. Le DAG est composé uniquement de transactions. Aucune modification n'a été faute parce qu'il n'y a rien à modifier.

### 2.6 ValidationMode (Nouveau)

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `ValidationMode` | Not explicitly in design doc | `ValidationMode { Fresh, Historical }` | **ADDITION** — non dans le design initial |
| Fresh mode | Implicit (validate_pure always checks) | Timestamp bounds (MAX_FUTURE, MAX_PAST) + backdating + PoW + signature | **EXTENSION** — ajoute MAX_PAST/MAX_FUTURE |
| Historical mode | Implicit (sync uses process_transaction) | Skips timestamp bounds, still checks backdating + PoW + signature | **EXTENSION** — sépare explicitement les deux modes |
| Backdating in Historical | Not addressed in design | `difficulty_for_tx_at()` called for BOTH modes (validation.rs:236-249) | **SECURITY FIX** — addresses the attack vector from security review |

**Écart: EXTENSION SÛRE.** Le design n'explicitait pas `ValidationMode` mais le comportement result (sync = pas de timestamp check, fresh = full check) est identique. L'ajout de `ValidationMode` rend le code EXPLICITE au lieu d'IMPLICITE. Le security fix (backdating check dans les deux modes) corrige la vulnérabilité identifiée dans `AETHER_DIFFICULTY_MIGRATION_SECURITY_REVIEW.md`.

### 2.7 TransactionValidator (Nouveau)

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `TransactionValidator` | Not in design | `struct TransactionValidator { difficulty: u8 }` | **ADDITION** — encapsulation |
| `validate_pure()` | 3-line change proposed | Full pipeline: backdating → timestamp bounds → PoW → signature → sender → overflow | **EXTENSION** — much more complete |
| `validate_dag()` | Not in design | Parent ordering, duplicate detection, sender conflict | **ADDITION** — previously scattered |
| `validate_ledger()` | Not in design | Balance, fee checks | **ADDITION** — previously scattered |
| `validate_full()` | Not in design | Pure + DAG + Ledger | **ADDITION** — composable validation |

**Écart: EXTENSION.** Le design proposait 3 lignes de modification; le code a une couche de validation complète. C'est plus de code mais plus SÛR: toute la validation est centralisée, testable, et documentée.

### 2.8 Error Types

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `InvalidPoW { difficulty }` | In design | EXISTS (validation.rs:18) | IDENTIQUE |
| `BackdatedTimestamp` | Not in design | `BackdatedTimestamp { tx_ts, activation_ts, grace_end }` (validation.rs:51-55) | **ADDITION** |
| `FutureTimestamp` | Not in design | `FutureTimestamp { tx_ts, now, max_future }` (validation.rs:43-47) | **ADDITION** |
| `StaleTimestamp` | Not in design | `StaleTimestamp { tx_ts, now, max_past }` (validation.rs:49) | **ADDITION** |
| `ParentTimestampViolation` | Not in design | `ParentTimestampViolation { child_ts, parent_index, parent_ts }` (validation.rs:57-61) | **ADDITION** |

**Écart: EXTENSIONS.** Les nouveaux error types ne changent pas le wire protocol — ce sont des erreurs internes de validation, pas des messages P2P.

### 2.9 P2P Messages

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `P2PMessage` enum | Not modified | 8 variants, unchanged | IDENTIQUE |
| `SyncRequest/Response` | Mentioned in design (metadata exchange) | `SyncRequest`, `SyncResponse(Vec<Vec<u8>>)` — ALREADY EXISTED | IDENTIQUE |
| `SyncAck` | Not in design | **DOES NOT EXIST** | N/A |
| `InventoryRequest/Response/Ack` | Not in design | **DO NOT EXIST** — Inventory uses `Inventory(Vec<Vec<u8>>)` and `GetInventory { tips }` | N/A |
| `MempoolRequest/Response/Ack` | Not in design | **DO NOT EXIST** | N/A |
| `FullBlockRequest/Response/Ack` | Not in design | **DO NOT EXIST** | N/A |
| `NetworkMessage` enum | Not in design | **DOES NOT EXIST** — `P2PMessage` is the wire protocol | N/A |
| P2P_PROTOCOL_VERSION | 3 | 3 (unchanged) | IDENTIQUE |
| Handshake | Not modified | `magic(4) | version(1) | genesis(32) | key(32)` — unchanged | IDENTIQUE |

**Écart: AUCUN.** Aucun message P2P n'a été ajouté ni modifié. Le wire protocol est inchangé.

### 2.10 Clock Skew / Majority

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `ClockSkewDecision` | Not in design | **DOES NOT EXIST** | N/A |
| `classify_clock_skew()` | Not in design | **DOES NOT EXIST** | N/A |
| Unanimous/majority voting | Not in design | **DOES NOT EXIST** — no voting mechanism | N/A |
| Clock determinism | Design: timestamps are consensus constants | Code: `difficulty_for_tx_at(tx, now_ms)` — deterministic pure function | IDENTIQUE |

**Écart: AUCUN.** Il n'y a JAMAIS eu de mécanisme de vote majoritaire. La détermination est purement fonctionnelle: même tx + même now → même résultat. Les 10 nœuds avec offsets d'horloge différents voient la même constante `DIFFICULTY_MIGRATION_TS` et arrivent au même résultat.

### 2.11 Grace Period (Nouveau — pas dans le design initial)

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| Grace period concept | Not in design | `GRACE_PERIOD_MS = 86_400_000` (24 hours) | **ADDITION** |
| Behavior during grace | Not addressed | Pre-activation txs with `now <= activation + grace` → difficulty 20 accepted | **ADDITION** |
| Behavior after grace | Not addressed | Pre-activation txs → `None` → REJECTED | **ADDITION** |
| Security purpose | N/A | Prevents indefinite 20-bit mining after activation | **SECURITY IMPROVEMENT** |

**Écart: EXTENSION SÛRE.** Le design n'avait pas de grace period. Sans grace period, après activation, les transactions pré-activation seraient immédiatement rejetées — ce qui briserait les nœuds en transition. La grace period donne 24h pour migrer. C'est une amélioration de sécurité.

### 2.12 Timestamp Bounds (Nouveau — pas dans le design initial)

| Élément | Design Validé | Code Actuel | Changement Protocolaire ? |
|---|---|---|---|
| `MAX_FUTURE_MS` | Not in design | `3_600_000` (1 hour) — transaction.rs:475 | **ADDITION** |
| `MAX_PAST_MS` | Not in design | `3_600_000` (1 hour) — transaction.rs:470 | **ADDITION** |
| Future rejection | Not in design | Fresh mode rejects `tx.timestamp > now + MAX_FUTURE_MS` | **ADDITION** |
| Stale rejection | Not in design | Fresh mode rejects `now - tx.timestamp > MAX_PAST_MS` | **ADDITION** |
| Parent ordering | Not in design | DAG validation: child_ts >= parent_ts | **ADDITION** |

**Écart: EXTENSIONS SÛRES.** Ces bornes de timestamp ne existaient pas dans le design mais sont des protections essentielles contre les attaques par manipulation de timestamp. Elles ne changent pas le wire protocol.

---

## 3. CONSOLIDATED DELTA TABLE

| Élément | Design | Code | Protocol Change? | Risk |
|---|---|---|---|---|
| Activation | timestamp in metadata | hardcoded const | Minor (safer) | LOW |
| Difficulty 20/24 | timestamp-based | timestamp-based | NONE | NONE |
| Nonce format | u64 | u64 | NONE | NONE |
| Transaction struct | unchanged | unchanged | NONE | NONE |
| Serialization | unchanged | unchanged | NONE | NONE |
| Block/Header/DagBlock | N/A (blockless) | N/A | NONE | NONE |
| P2P messages | unchanged | unchanged | NONE | NONE |
| P2P version | 3 | 3 | NONE | NONE |
| Wire protocol | unchanged | unchanged | NONE | NONE |
| ValidationMode | implicit | explicit enum | NONE (internal) | NONE |
| TransactionValidator | 3-line change | full validation layer | NONE (internal) | LOW |
| Grace period | not designed | 24h window | NONE (internal) | LOW |
| Timestamp bounds | not designed | ±1h | NONE (internal) | LOW |
| Parent ordering | not designed | enforced | NONE (internal) | LOW |
| Error types | minimal | detailed variants | NONE (internal) | NONE |
| ClockSkewDecision | N/A | DOES NOT EXIST | NONE | NONE |
| Majority voting | N/A | DOES NOT EXIST | NONE | NONE |
| Height-based activation | REJECTED in design | NOT IMPLEMENTED | NONE | NONE |

---

## 4. ITEMS NOT IMPLEMENTED (from session summary claims)

These items were claimed in the session summary but DO NOT EXIST in the code:

1. **`ActivationSchedule` struct** — never created
2. **`activation_height`** — never implemented (design explicitly REJECTED height-based activation)
3. **`is_post_migration()`** — never created (inline comparison used instead)
4. **`Block` modifications** — struct doesn't exist
5. **`BlockHeader` modifications** — struct doesn't exist
6. **`DagBlock` modifications** — struct doesn't exist
7. **`SyncAck`** — never created
8. **`InventoryRequest/Response/Ack`** — never created
9. **`MempoolRequest/Response/Ack`** — never created
10. **`FullBlockRequest/Response/Ack`** — never created
11. **`ClockSkewDecision`** — never created
12. **`classify_clock_skew()`** — never created
13. **Majority/unanimous voting** — never implemented
14. **Nonce format change 31→24** — never happened (nonce is always u64)

---

## 5. PROTOCOL FINGERPRINT

```
Genesis:        [consensus constant — unchanged]
Network ID:     [genesis hash — unchanged]
P2P version:    3
Difficulty:     24-bit (default_difficulty = 24)
Activation:     DIFFICULTY_MIGRATION_TS = 1_758_000_000_000 (hardcoded const)
Nonce format:   u64 (8 bytes LE)
TX format:      [unchanged — bincode v1.3]
Consensus:      MAX_FUTURE_MS = 3_600_000, MAX_PAST_MS = 3_600_000
```

Two nodes compiled from the same source produce **IDENTICAL** protocol fingerprint.
