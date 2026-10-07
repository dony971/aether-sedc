# Aether Protocol Specification

**Version:** 3.0 (V3 testnet release candidate)
**Date:** 2026-09-16
**Status:** Current protocol — matches code exactly

---

## 1. Network Identity

| Parameter | Value |
|---|---|
| Protocol version | `3` |
| Handshake magic | `0x41455448` ("AETH") |
| Genesis hash | `[0u8; 32]` (32 zero bytes) |
| Network separation | Genesis hash comparison during handshake |
| Encryption | ChaCha20-Poly1305 (X25519 key exchange) |

Nodes on different networks (different genesis hashes) reject each other during handshake. No explicit NETWORK_ID constant exists; the genesis hash serves as the network identifier.

## 2. Genesis

**Genesis hash:** `[0u8; 32]`

**Genesis message:** `"17/Aug/2026 - Aether: Trust is computed, not granted. V3 testnet release candidate: canonical genesis for P2P protocol v3 (structural weight, zero emission). Operator ceremony."`

**Genesis ledger:**

| Address | Balance (base units) | AETH |
|---|---|---|
| Founder (`2ffab7...60d4`) | 100,000,000,000 | 10 |
| Faucet (`a19ee0...aabfb`) | 1,000,000,000,000,000,000 | 100,000,000 |
| **Total** | **1,000,010,000,000,000,000** | **100,000,010** |

**MAX_SUPPLY:** `2,000,000,000,000,000,000` (200,000,000 AETH)
**UNITS_PER_AETH:** `10,000,000,000` (10^10)
**Emission:** ZERO after genesis. Total supply can only decrease through fee burning.

**Parents of genesis transactions:** `[0u8; 32]; 2]` (all zeros). Any transaction with parents `[0,0]` is a root transaction.

## 3. Transaction Format

```
Transaction {
    id:           [u8; 32],    // BLAKE3 hash (computed)
    parents:      [[u8; 32]; 2], // Exactly 2 parents
    sender:       [u8; 32],    // Ed25519 public key (first 32 bytes)
    receiver:     [u8; 32],    // Destination address
    amount:       u64,         // Transfer amount (base units)
    fee:          u64,         // Fee burned (base units)
    timestamp:    u64,         // Unix milliseconds
    nonce:        u64,         // PoW nonce (mined)
    account_nonce: u64,        // Sequential per sender (replay protection)
    weight:       f64,         // Subtree size (computed, not serialized)
    signature:    Vec<u8>,     // Ed25519 signature (64 bytes)
    public_key:   Vec<u8>,     // Ed25519 public key (32 bytes)
}
```

**Minimum binary size:** 208 bytes (5×32 + 6×8).

**Hash function:** BLAKE3.

**Hash input order:** `parents[0] || parents[1] || sender || receiver || amount || fee || timestamp || nonce || account_nonce || signature || public_key`

**Signing hash input order:** `parents[0] || parents[1] || sender || receiver || amount || fee || timestamp || nonce || account_nonce` (excludes signature and public_key)

## 4. Transaction Validation

Three-phase validation pipeline:

### Phase 1: Pure validation (`validate_pure`)
1. **PoW verification:** Hash must meet difficulty threshold
2. **Signature verification:** Ed25519 signature must be valid
3. **Sender-publickey match:** `sender == public_key[..32]`

### Phase 2: DAG validation (`validate_dag`)
1. **Duplicate check:** Transaction ID must not already exist in DAG
2. **Parent existence:** Both parents must exist in DAG (or be genesis `[0,0]`)
3. **Sender conflict:** No other transaction with same `(sender, account_nonce)` pair

### Phase 3: Ledger validation (`validate_ledger`)
1. **Balance check:** Sender balance ≥ amount + fee
2. **Fee check:** fee ≥ min_fee (currently 1 base unit)

**Full validation** = `validate_pure` + `validate_dag` + `validate_ledger`

## 5. Signature Validation

- **Scheme:** Ed25519 (`ed25519-dalek`)
- **Key size:** 32 bytes
- **Signature size:** 64 bytes
- **Address derivation:** First 32 bytes of Ed25519 public key
- **Verification:** Standard Ed25519 verify over signing hash

## 6. Proof-of-Work

**Algorithm:** Micro-PoW (hash-based, linear nonce scan).

**Mining:** For nonce = 0, 1, 2, ..., compute `BLAKE3(tx_hash || nonce)`. Accept if leading zero bits ≥ difficulty.

**Current difficulty:** 24 bits (default_difficulty() = 24).

**Verification:** Single BLAKE3 hash + bit check. Cost: ~330 ns.

**Mining cost (CPU):** ~5,288 ms per transaction at 24 bits.

## 7. Difficulty

**Current:** 24 bits (changed from 20 bits in V3 upgrade).

**Adaptive difficulty:** Available but NOT active in current deployment. Parameters:
- Min: 8 bits
- Max: 24 bits
- Window: 10,000 ms (10 seconds)
- Target TPS: 10

**Genesis initial difficulty:** 1000 (stored in genesis config, not enforced in mining).

## 8. Parent Selection

Each transaction has exactly 2 parents.

**Parent selection algorithm:**
1. Start from genesis
2. Random walk weighted by cumulative subtree weight
3. `walk_depth`: 10 steps
4. `diversity_factor`: 0.5
5. `min_weight`: 0.0
6. `max_tip_age_ms`: 60,000 (1 minute)

**Second parent:** Same random walk with up to 10 attempts to find non-conflicting parent. Fallback: genesis `[0u8; 32]`.

**Identical parents prevention:** If parent1 == parent2, second parent forced to genesis.

## 9. DAG Insertion

**Method:** `add_transaction_validated(tx)`

**Validation before insertion:**
1. No duplicate transaction ID
2. Both parents exist in DAG (or are genesis)
3. No sender conflict: `(sender, account_nonce)` must be unique

**Weight initialization:** New transaction weight = 1.0

**Weight adjustment:** All surviving ancestors gain +1.0 (the new transaction becomes a descendant).

**Root transactions:** Parents `[0,0]` keep their parents unchanged. Never auto-reassigned.

## 10. Weight

**Definition:** Subtree size = itself + all descendants (recursive count).

**Stored as:** `tx.weight: f64`

**Initial value:** 1.0 (on insertion)

**Adjustment on add:** `adjust_ancestor_weights()`: +1.0 per surviving ancestor

**Adjustment on prune:** -1.0 per surviving ancestor (leaves-first order)

**Purpose:** Determines DAG weight for parent selection and stability.

## 11. Stability

**Stable status threshold:** `STABILITY_THRESHOLD = 5.0` cumulative weight.

**Confirmed status threshold:** `MIN_CONFIRMATIONS = 3` (number of children/references).

A transaction is "stable" if its cumulative weight ≥ 5.0. It is "confirmed" if it has ≥ 3 children.

## 12. Conflict Resolution

**Canonical rule:** Per `(sender, account_nonce)` pair, the transaction with the **lexicographically smallest ID** wins.

**Implementation:**
1. `rebuild_from_dag()` computes `canonical_winners` map up front
2. For each `(sender, nonce)` pair, the smallest id is selected
3. All non-winning transactions are marked as "residue" (skipped, not applied)

**Prune cascade:** When a conflict is detected at runtime, the loser + entire descendant subtree is pruned (leaves-first order for weight correctness).

## 13. Double Spend

**Detection:** `has_sender_conflict()` checks if another transaction exists with same `(sender, account_nonce)`.

**Prevention:** `add_transaction_validated()` rejects conflicting transactions at insertion time.

**Resolution:** If two conflicting transactions exist in the DAG (e.g., from partition merge), `rebuild_from_dag()` applies only the canonical winner (smallest id).

**Loser treatment:** Loser's transfer is never applied. Loser's descendants may still be applied if they have different senders and sufficient balance.

## 14. Ledger Derivation

**Method:** `rebuild_from_dag(dag)`

**Process:**
1. Reset all balances, nonces, fees-burned
2. Apply genesis distribution
3. Sort all transactions by ascending ID (canonical order)
4. Relaxation loop:
   - For each tx in sorted order:
     - Skip if already applied
     - Check parents ready (all parents applied or genesis)
     - Skip if non-canonical winner (residue)
     - Attempt `transfer_internal()`
     - If insufficient balance → defer to next pass
     - If success → mark applied, update nonce
5. Loop until no progress
6. Remaining txs evicted as "never fundable"

**Key property:** This is a **pure function of the DAG**. Same DAG → byte-identical ledger state regardless of arrival order, restart history, or crash timing.

## 15. Mempool

**Capacity:** `MAX_ORPHANS = 50,000` transactions

**TTL:** `MEMPOOL_TTL = 15 minutes`

**Reject cache:** `MEMPOOL_REJECT_CACHE = 1,000`

**Drain batch:** `MEMPOOL_DRAIN_BATCH = 100` per cycle (~150ms tick)

**Selection order:** Fee descending, then transaction ID ascending (canonical)

**Min fee:** 1 base unit (default)

**Fee oracle:** Dynamic adjustment based on occupancy:
- >80% capacity: 2× base fee
- >50% capacity: 1.5× base fee
- <20% capacity: 0.5× base fee
- Adjustment interval: 10 seconds

## 16. Orphans

**Definition:** Transactions whose parents are not yet in the DAG.

**Handling:** Stored in orphan pool. Re-evaluated when parents arrive.

**TTL:** 15 minutes. Orphans not resolved within TTL are evicted.

**Fixpoint passes:** `ORPHAN_FIXPOINT_MAX_PASSES = 64` maximum resolution attempts per cycle.

## 17. Sync

**Bootstrap:** Connect to bootnode, request DAG hashes, compare, fetch missing transactions.

**Page size:** 100 transactions per GetData response.

**Ancestor budget:** 400 extra ancestors per page (for deep chains).

**Missing parent re-request:** Up to 128 per cycle, with exponential backoff (2s, 5s, 15s).

**SyncResponse throttle:** 50ms between each transaction delivery.

**Topological ordering cap:** `TOPO_ORDER_CAP = 50,000`. Above this, falls back to timestamp order.

## 18. P2P Protocol

See `P2P_SPECIFICATION.md` for full details.

**Handshake frame:** 69 bytes
- Magic: 4 bytes (`0x41455448`)
- Version: 1 byte (`3`)
- Genesis hash: 32 bytes
- Ephemeral public key: 32 bytes

**Encryption:** ChaCha20-Poly1305 after X25519 key exchange.

**Key derivation:** `SHA-256(shared_secret || "aether-p2p-key-v1")`

## 19. Peer Management

| Parameter | Value |
|---|---|
| MAX_PEERS | 128 |
| MAX_PEERS_PER_SUBNET | 4 (/24) |
| PROTECTED_OUTBOUND_SLOTS | 8 |
| MAX_KNOWN_PEERS | 1,000 |

## 20. Peer Scoring

| Parameter | Value |
|---|---|
| Initial score | 100 |
| Ban threshold | ≤ 0 |
| Invalid message penalty | -10 |
| Contradiction penalty | -20 |
| Timeout penalty | -5 |
| Flood penalty | -15 |
| Abusive penalty | -10 |
| Sync bonus | +5 |
| Decay rate | +1 per interval |
| Decay interval | 300 seconds |
| Reward cap | 150 |
| Temp ban duration | 300 seconds |
| Temp bans before perm | 3 |
| Permanent ban duration | 3,600 seconds |

## 21. Rate Limits

| Scope | Limit |
|---|---|
| Global P2P messages | 400 per second |
| RPC global | 200 per 10-second window |
| RPC per IP | 40 per 10-second window |
| Max message size | 16 MiB |
| Max INV items | 1,000 |
| Max seen txs cache | 50,000 |

## 22. Persistence

**Backend:** Sled (embedded key-value store)

**Data stored:**
- DAG transactions (by ID)
- Ledger balances (by address hex)
- Ledger nonces (by address hex)
- Applied transaction set
- Known peers
- Peer scores

**Durability:** Sled auto-flushes ~every 500ms. Node flushes periodically (10s) and on shutdown.

## 23. Crash Recovery

**Method:** `rebuild_from_dag()` — pure function of the DAG.

**Guarantee:** Same DAG → identical ledger state regardless of crash timing.

**Verified:** 1,062+ crash/restart cycles, 0 invariant violations.

## 24. Wallet

**Key derivation:** Ed25519

**Address format:** `AETH` + 20-byte-pubkey-hex + 4-byte-checksum

**Encryption:** Argon2id + AES-256-GCM

**Mnemonic:** BIP39 (optional, new wallets)

**Legacy:** Raw Ed25519 keypair (existing wallets)

## 25. RPC

**Default bind:** `127.0.0.1:9933` (loopback only)

**CORS:** Restricted to localhost origins by default

**Default P2P port:** 25565

**Faucet cooldown:** 60 seconds per address

**Faucet amount:** 10 AETH (100,000,000,000 base units)

## 26. Error Handling

**Validation errors:** InvalidPoW, InvalidSignature, SenderPublicKeyMismatch, DuplicateTransaction, MissingParent, DoubleSpend, SenderConflict, InsufficientBalance, InvalidNonce, InsufficientFee, Overflow

**Processing:** Failed transactions are rejected with specific error messages. No partial application.

## 27. Protocol Versioning

**Current version:** 3

**Version check:** During handshake, `incoming[4] != P2P_PROTOCOL_VERSION` → reject.

**Upgrade mechanism:** Hard fork. All nodes must upgrade simultaneously. No backward compatibility.

## 28. 24-Bit Upgrade

**Change:** `default_difficulty()` changed from 20 to 24 bits.

**Type:** Soft fork. Old nodes (20-bit) accept a superset of what new nodes (24-bit) accept.

**Activation:** Coordinated node upgrade. All nodes must run v3 software.

**Migration:** No data migration needed. DAG and ledger are unaffected.

**Rollback:** Downgrade to v2 software restores 20-bit difficulty.

**See:** `PROTOCOL_UPGRADE_24BIT.md` for full details.
