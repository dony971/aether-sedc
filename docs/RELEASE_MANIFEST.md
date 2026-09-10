# RELEASE MANIFEST — Wallet Hardening Release (HOLD, not deployed)

**Status:** package PREPARED and VERIFIED, **NOT rotated** (soak `AA9F`
untouched by explicit operator order).
**Rule:** never ship a wallet whose backend, pins and gate SHA come from
different commits. All three below resolve to the same tree.

---

## 1. Commits (branch `canary-c2-fixes`, wallet `main`)

| Component | Repo | Commit | Content vs RC `77f01ee` |
|---|---|---|---|
| Protocol+node | aether-fix/aether-main | `09cec4e` | P1 purge-on-prune, P2 diagnostics, P3 applied-tracking, topo parents-first+cache, faucet serial, file logging, rpc-bind loopback, to_file atomic. NO consensus/DAG/ledger-rule/economic/genesis change |
| Wallet app | aether-wallet | `005e987` | Argon2id v2, atomic writes, locks, no-overwrite, QProcess fix, history fixes, canary guard, env overrides |

## 2. Versions

| Item | Value |
|---|---|
| Wallet app | 1.2.0 |
| Protocol crate | 1.2.0 (`Cargo.toml`) |
| Binary `--version` string | `aether 1.1.1` (STALE cosmetic string, known debt — identity is by SHA, not by this string) |
| Wallet format | v2 (Argon2id m=65536 t=3 p=1 + AES-GCM, single payload) |
| P2P wire version | 3 (`P2P_PROTOCOL_VERSION`) |
| network_id | **NONE — not implemented** (tracked limitation: same-genesis networks would merge on peering; segregation is by bootnodes only) |
| Build date (this package) | 2026-09-09 |

## 3. SHA256

| Artifact | SHA256 |
|---|---|
| `target-rel/release/aether-unified.exe` (validation build) | `8CF1B9375A018259C8ACF8372B902D0A89B80F0E316B58BD5A0DE9F6F86A3C61` |
| `target/release/aether-unified.exe` (DEPLOYED canary 2026-09-10, +emoji fix) | `CB8B93E7D1979AED44013D7D6540E25E0EA542A93120B6F4B833323ED27EC8AF` |
| Running canary/soak image (HELD, do not touch) | `AA9F74445186BDE5FA011A547EA333CA5AE72D02A70D4C5F384FD9DA2EBE5B90` |
| Previous RC build (superseded) | `770D5AF8FEBB5CACC37646FF5EFFD306827FC14863B2A0565829970ADDD89C6F` |

## 4. Genesis (identical on all builds — verified byte-equal constants)

- difficulty 1000, supply 1000000100000000000, MAX_SUPPLY 2000000000000000000
- faucet `a19ee04c…507aabfb` = 1000000000000000000
- message `17/Aug/2026 - Aether: Trust is computed, not granted…`

## 5. CLI surface (this release, verified `--help`)

`keygen`, `wallet create/restore`, `send`, `balance`, `--rpc-bind`
(default `127.0.0.1`), NO `--daemon`, NO `--stop`, NO keygen
`--import-file`. Any deviation at deploy time = wrong binary, STOP.

## 6. Compatibility

- Wallet files v2 readable both directions (Python↔Rust, tested).
- Sled schema backward compatible (new `applied_tx` tree auto-created;
  old data boots; STEP-1c store backstop covers empty applied sets).
- TOML configs without `rpc_bind` parse as loopback (tested).
- No protocol rule change → old and new binaries reach identical
  ledger states from identical DAGs (regression suites green both sides).

## 7. Rotation precondition checklist (for the maintenance window)

- [ ] cargo clean/fmt/clippy/audit/test green on this exact commit
- [ ] wallet 66/66 + E2E green
- [ ] secrets scan clean, legacy binary quarantined (not in package)
- [ ] SHA above re-verified after copy
- [ ] pins updated together (rc.py, canary_gate.ps1, backend copy)
- [ ] STOP → SWAP → VERIFY → START → SYNC → CONVERGE → E2E → WATCHDOG
- [ ] old binary kept out of PATH until new build validated live
