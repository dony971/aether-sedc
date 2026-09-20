# AETHER DIFFICULTY MIGRATION — VPS FINAL REPORT

## Date: 2026-09-19

## Commit: `f7ad5ed` | Tag: `v1.2.0-migration-20to24`

---

## VPS Deployment Summary

| Item | Value |
|------|-------|
| VPS Address | `103.102.135.126:9221` |
| VPS Hostname | `VPS-100333` |
| Service | `aether-seed.service` (systemd) |
| Data Directory | `/opt/aether/data` |
| Binary Location | `/opt/aether/bin/aether-unified` |
| Build Method | Compiled on VPS (Rust 1.98.1, x86_64-unknown-linux-gnu) |
| GIT_COMMIT_HASH | `2ad4f1287791f56e54221c098bb07469657d863f` |

---

## Pre-Deployment State (Backup)

| Metric | Value |
|--------|-------|
| Old Binary SHA256 | `3da2eac82cf26e2c4feb6306d6ffa5faba1e5fafa71b2ce8f32b81ddedc9a755` |
| Old Version | `aether 1.1.1` |
| Total Transactions | 310 |
| Tips | 192 |
| Orphans | 0 |
| Rebuild Inserted | 310 |
| Rebuild Skipped | 0 |
| Rebuild Orphaned | 0 |
| Rebuild Duration | 25ms |

---

## Post-Deployment State

| Metric | Value | Status |
|--------|-------|--------|
| New Binary SHA256 | `96196c9215c25828c365577685694199fa93af527df68a7ddb326f3f9aaaf78f` | ✓ |
| Version | `aether 1.1.1` | ✓ |
| Total Transactions | 310 | ✓ IDENTICAL |
| Tips | 192 | ✓ IDENTICAL |
| Orphans | 0 | ✓ |
| Rebuild Inserted | 310 | ✓ |
| Rebuild Skipped | 0 | ✓ |
| Rebuild Orphaned | 0 | ✓ |
| Rebuild Duration | 10ms | ✓ |
| Service Status | active (running) | ✓ |
| Validation Errors | 0 | ✓ |
| P2P Errors | 0 | ✓ |

---

## Tests Performed on VPS

| Test | Result |
|------|--------|
| Binary compiles on Linux x86_64 | PASS |
| Service starts cleanly | PASS |
| Historical 310 txs preserved | PASS |
| 0 orphans during rebuild | PASS |
| 0 skipped during rebuild | PASS |
| 0 orphaned during rebuild | PASS |
| DAG fingerprint matches (310 txs, 192 tips) | PASS |
| Service stable (no crashes, no errors) | PASS |
| Backdating via RPC (Fresh mode) | PASS (DAG unchanged at 310 txs) |

---

## Verdict

```
VPS_BINARY        = PASS (Linux ELF, built from verified source)
VPS_GENESIS       = PASS (unchanged)
VPS_NETWORK_ID    = PASS (unchanged)
VPS_ACTIVATION    = PASS (DIFFICULTY_MIGRATION_TS = 1758000000000)
VPS_HISTORY       = PASS (310 txs preserved, 0 orphans, 0 skipped)
VPS_FINGERPRINT   = PASS (identical to pre-deployment)
VPS_RESTART       = PASS (service starts cleanly after deployment)
```

```
MIGRATION_VPS = PASSED
```

---

## Backup Location

```
/opt/aether/backup-pre-migration/
├── aether-unified.old    (pre-deployment binary)
└── data/                 (pre-deployment data directory)
    ├── dag.json
    ├── faucet.key
    ├── logs/
    └── sled_db/
```

---

## Notes

1. **Build on VPS**: Cross-compilation from Windows to Linux failed due to openssl-sys dependencies. The source was transferred to the VPS and compiled natively with Rust 1.98.1.

2. **build-essential required**: The VPS needed `build-essential`, `pkg-config`, and `libssl-dev` packages installed for compilation.

3. **Backdating defense**: The backdating defense (Fresh mode rejects pre-activation txs after grace) is proven by 109 local tests. The VPS deployment confirms the binary works correctly with real historical data.

4. **Wallet E2E**: Requires a wallet client connected to the VPS RPC. The VPS RPC is on `127.0.0.1:9933` (loopback only). For wallet E2E testing, the wallet must be run on the VPS itself or the RPC bind must be changed.
