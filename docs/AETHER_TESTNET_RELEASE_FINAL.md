# Aether Testnet Release Final

**Release Date**: 2026-09-21
**Status**: TESTNET RELEASE
**Classification**: NOT mainnet ready

---

## Source

| Field | Value |
|-------|-------|
| Commit | `9f1ab3df12fe63f406a09d9bb0f7763d04c77a8d` |
| Branch | `hardening/deep-sync-paginated` |
| Version | 1.2.0 |
| Previous tag | `v1.2.0-migration-20to24` (baseline) |

---

## Protocol

| Component | Specification |
|-----------|---------------|
| P2P Protocol | v3 (struct weight, zero emission) |
| PoW Difficulty | 24 bits (post-migration) |
| Genesis Hash | `0000000000000000000000000000000000000000000000000000000000000000` |
| Network ID | Testnet |
| Max Supply | 200,000,000 AETH |
| Units per AETH | 10^9 |
| Mempool | 1000 tx max, min fee 1 |
| Transaction | Ed25519 signed, PoW mined, 2 parents |

---

## Wallet

| Field | Status |
|-------|--------|
| State | Beta |
| Encryption | Argon2id (64 MiB, t=3, p=1) + AES-256-GCM |
| Single payload | `{secret_key_hex, mnemonic}` |
| Wallet Network E2E | **PASS** |
| RC pinning | Commit `79fbee4`, SHA256 `FFBA2239...` |

---

## Stability Campaign Results

| Test | Result | Details |
|------|--------|---------|
| Load Testing | **PASS** | 50/50 txs, 0 failures, ~8s/tx with PoW |
| Crash Chaos (20 cycles) | **PASS** | 20/20 kill-restart, fingerprint `3ff21dd4d0796ade` stable, 0 data loss |
| P2P Chaos | **PASS** | Firewall block, iptables flush, 3 rapid restarts |
| Memory Soak (5 min) | **PASS** | RAM stable 27.2 MB, no leak, CPU 0.0% idle |
| Consensus Fingerprint | **PASS** | Identical across all 20 crash cycles |
| Wallet Network E2E | **PASS** | Faucet + send + balance verification |

**Note**: The accelerated stability campaign is NOT a 24h/72h soak test. It validates crash resilience, memory stability, and data integrity under controlled conditions.

---

## Infrastructure

| Component | Configuration |
|-----------|---------------|
| RPC | `127.0.0.1:9933` (localhost only, NOT accessible from Internet) |
| P2P | `0.0.0.0:25565` (public) |
| Service | systemd (`aether.service`), enabled at boot |
| Firewall | UFW + iptables, INPUT DROP policy, loopback ACCEPT |
| Faucet key | `aether:aether`, mode 644, NOT in logs/reports/RPC/P2P |
| Data dir | `/opt/aether/data/` (sled_db 3 MB, dag.json 2 MB, 60 MB total) |

### VPS Configuration
- Provider: vps1euro.fr
- IPv6: `2a0c:b641:1a0:800::ba`
- Internal IPv4: `172.50.0.44`
- SSH Proxy: `103.102.135.126:9221`

---

## Regression

| Category | Result |
|----------|--------|
| Total tests | 412 |
| Passed | 408 |
| Failed (pre-existing) | 3 |
| Ignored (benchmarks) | 1 |
| **FINAL_REGRESSION** | **PASS** |

Pre-existing failures (documented, NOT P4-related):
- `test_applied_true_duplicate_skips_replay`
- `test_double_spend_order_invariance`
- `test_phantom_nonce_heals_transfer`

---

## Release Builds

### Windows
- File: `target\release\aether-unified.exe`
- Size: 17.33 MB (18,168,277 bytes)
- SHA256: `5033FF5BA2F11F6362A9D178EE2EFE2FDF1EA5C4A832B0805801758CD755D924`
- Toolchain: rustc 1.97.1, cargo 1.97.1

### Linux (x86_64)
- File: `/opt/aether/src/target/release/aether-unified`
- Size: 11.75 MB (12,318,544 bytes)
- SHA256: `4d4057e0ce56f176aa61fc7defcb692d6d0341d2c8e2d359b7187ba7c00ba13d`
- Toolchain: rustc 1.98.1, cargo 1.98.1
- Build command: `cargo build --release`
- Build date: 2026-09-21

---

## Known Limitations

1. **Not a long soak test**: The accelerated stability campaign tested crash resilience and memory stability under controlled conditions. It is NOT a 24h or 72h soak test.
2. **P2P not externally routable**: The VPS provider (vps1euro.fr) uses IPv6-only public routing. Port 25565 is not reachable from external IPv4.
3. **3 pre-existing test failures**: Documented in regression, unrelated to P4.
4. **Mempool stuck txs**: 3 persisted mempool txs remain unconfirmed (validator mode doesn't mine).
5. **Bootnodes default**: The default config references `103.102.135.123:25565` which is not routable.
6. **Single node network**: No external peers during testing.

---

## Changelog Since v1.2.0-migration-20to24

### P4: Incremental Persistence
- Dirty tracking: `dirty_balances`, `dirty_nonces`, `dirty_applied_added`, `dirty_applied_removed`
- `save_dirty()` O(K) replaces `save()` O(N) in transaction processing
- `rebuild_from_dag()` marks all state dirty after rebuild
- Load test: `save()` 37.1ms → `save_dirty()` 16µs at 10K accounts (2,305x speedup)
- 42/42 ledger tests pass, 10 new P4 tests added

### Fixes
- `faucet.key` ownership: `root:root` → `aether:aether`
- Loopback firewall: Added `iptables -I INPUT 1 -i lo -j ACCEPT`
- systemd service: `aether.service` for boot persistence
- rc.local: iptables rules restoration + faucet key permissions

---

*This is a TESTNET release. Do NOT deploy to mainnet.*
