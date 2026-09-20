# AETHER Release Baseline

**Tag:** `v1.2.0-migration-20to24`
**Date:** 2026-09-19
**Status:** FROZEN — do not modify without new protocol proposal

---

```text
Protocol        = AETHER SEDC v1.2.0
P2P             = v3
Genesis         = 0000000000000000000000000000000000000000000000000000000000000000
Network ID      = p2p_v3
Activation      = 1758000000000 (2025-09-16T00:00:00Z)
Difficulty pre  = 20 bits
Difficulty post = 24 bits
Commit          = f7ad5ed
Tag             = v1.2.0-migration-20to24
Binary SHA256   = 96196c9215c25828c365577685694199fa93af527df68a7ddb326f3f9aaaf78f (Linux VPS)
Binary SHA256   = 9EDFFB83EFE306342304420AF98319E425881C1F716967159CA2C1A696733020 (Windows local)
Deep Sync       = CERTIFIED
Migration       = VERIFIED
Wallet E2E      = PASSED
Test count      = 109/109 PASS
VPS status      = running, 333 txs, 0 orphans, 0 validation errors
```

## Frozen Protocol Rules

The following MUST NOT be modified without a new protocol proposal:

- Activation rule (DIFFICULTY_MIGRATION_TS)
- Difficulty rule (20-bit pre, 24-bit post)
- Historical validation mode
- Transaction format (bincode serialization)
- Txid computation (blake3)
- Genesis hash
- P2P v3 protocol
- DAG consensus (parent timestamp ordering)

## Post-Release Campaigns

This baseline is the reference for:

1. Soak test (24h+ continuous operation)
2. Load test (high TPS sustained)
3. External security audit
4. Performance benchmarking
5. Scalability testing
6. Independent audit

## Change Control

Any protocol evolution must follow:

```
DESIGN → REVIEW → TEST → RELEASE
```

Never modify the reference build directly.
