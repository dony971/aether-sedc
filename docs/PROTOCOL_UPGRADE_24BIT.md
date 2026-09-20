# Aether Protocol Upgrade: 20-bit → 24-bit PoW

**Date:** 2026-09-16
**Status:** Deployed (V3 testnet)

---

## Overview

The PoW difficulty was increased from 20 bits to 24 bits in the V3 testnet release. This is a **soft fork** — old nodes accept a superset of what new nodes accept.

## Old Rule (V2)

```
default_difficulty() → 20
```

- Mining: ~1,048,576 hashes average (~464 ms CPU)
- Anti-spam: Moderate (botnet feasible)

## New Rule (V3)

```
default_difficulty() → 24
```

- Mining: ~16,777,216 hashes average (~5,288 ms CPU)
- Anti-spam: Strong (CPU expensive, GPU trivial)

## Compatibility

| Scenario | Result |
|---|---|
| V3 node → V3 network | ✅ Compatible |
| V2 node → V3 network | ⚠️ V2 accepts V3 txs (superset) |
| V3 node → V2 network | ❌ V3 rejects V2 txs (subset) |
| V2 + V3 mixed | ⚠️ Works but V2 nodes are weaker |

**Soft fork property:** V2 nodes accept transactions that V3 nodes also accept (20-bit is easier than 24-bit). V3 nodes reject transactions that V2 nodes accept (24-bit is harder than 20-bit). This means V2 nodes on a V3 network are not harmful — they just accept more transactions.

## Activation

**Mechanism:** Coordinated node upgrade. All nodes must run V3 software.

**No on-chain activation signal:** The difficulty change is hardcoded in `default_difficulty()`.

**Rollback:** Downgrade to V2 software restores 20-bit difficulty.

## Migration Procedure

1. Back up V2 data directory
2. Stop V2 node
3. Install V3 binary
4. Start V3 node (same data directory)
5. DAG and ledger are unaffected (difficulty is only a mining parameter)

## Data Impact

- **DAG:** No change. Existing transactions are valid at both difficulties.
- **Ledger:** No change. Balances, nonces, fees unaffected.
- **P2P:** Version bump from 2 to 3. V2 and V3 nodes reject each other during handshake.
- **Wallet:** No change. Keys, addresses, signatures unaffected.

## Risks

1. **V2 nodes on V3 network:** Accept weaker PoW. Can be exploited by spammers targeting V2 nodes.
2. **No automatic upgrade:** Nodes must be manually upgraded.
3. **No activation signal:** Cannot coordinate upgrade via blockchain.

## Recommendations

1. Upgrade all nodes simultaneously
2. Monitor for V2 nodes on network (reject via version check)
3. Consider on-chain activation signal for future upgrades
