# AETHER — PHASE 1 BOOTSTRAP IMPLEMENTATION

**Status:** IMPLEMENTED + TESTED  
**Date:** 2026-09-23  
**Branch:** `dev/phase1-bootstrap`  
**Base:** `fix/sync-frontier-delivery` (includes `cb47977`)  
**Release frozen:** `v1.4.0-testnet` (`ad08e30`) — **IMMUTABLE**  
**Deploy:** NONE (local/dev only; `SAFE_TO_DEPLOY_FIX = NO` remains for infra)

---

## 1. Scope

Phase 1 quick wins from `docs/AETHER_DECENTRALIZED_BOOTSTRAP_ARCHITECTURE.md` §9:

| # | Item | Files |
|---|---|---|
| 1 | Peer persistence | `src/p2p.rs`, `src/node.rs` |
| 2 | Peer TTL (no remove-on-disconnect) | `src/p2p.rs` |
| 3 | Multi-seed defaults | `src/config.rs` |
| 4 | General redial (bootnodes + known peers) | `src/p2p.rs` |
| 5 | PEX robustness (touch + keep for redial) | `src/p2p.rs` |
| 6 | Bootnode-loss + cold-start tests | `src/p2p.rs` tests |
| 7 | P2P crypto nonce audit + minimal fix | `src/p2p.rs`, this doc |

**Not modified:** consensus, PoW 24, genesis, network ID, Transaction, TXID, P2P wire protocol v3 framing/handshake format (direction byte lives inside the existing 12-byte nonce; framing/version unchanged).

---

## 2. Implementation detail

### 2.1 PEER_PERSISTENCE

- `P2PConfig.peer_store_path: Option<PathBuf>` — where the JSON peer store lives.
- `node.rs:584` sets `peer_store_path: Some(data_dir.join("known_peers.json"))`.
- `load_known_peers()` — called at the top of `start()` before bind/dial; parses `["ip:port",...]`, inserts into `known_peers`, stamps `peer_last_seen = now`.
- `save_known_peers()` — serializes `known_peers` to string list; atomic write via `.json.tmp` + rename.
- `start_peer_store_task()` — 30s loop: TTL expiry + flush every `PEER_STORE_FLUSH_INTERVAL` (60s).
- Test: `test_peer_persistence_roundtrip` — save two peers, reload on a fresh instance, assert set equality.

### 2.2 PEER_TTL

- Const `PEER_TTL = 3600s` (1 hour).
- Field `peer_last_seen: Arc<RwLock<HashMap<SocketAddr, Instant>>>`.
- Disconnect path (`handle_peer` exit) **does not** `known_peers.remove`; it only removes from the active `peers` map and refreshes `peer_last_seen`.
- Handshake-failure path likewise keeps the address for a later redial.
- TTL task expires entries older than `PEER_TTL` from both maps.
- Test: `test_peer_ttl_keeps_address_after_disconnect` — address remains in `known_peers` after simulated disconnect; TTL constant > 60s.

### 2.3 MULTI_SEED

- `config.rs` default `bootnodes` now three entries:
  - `103.102.135.123:25565` (existing VPS)
  - `103.102.135.124:25565`
  - `103.102.135.125:25565`
- Operator override still via `--bootnodes` / TOML.
- Note: `.124`/`.125` may not be provisioned yet — they are config-level seeds (dial attempts fail soft; heartbeat retries).
- Tests: `test_multi_seed_default_bootnodes` (≥2 distinct defaults), `test_multi_seed_p2p_config_accepts_list` (3-seed P2PConfig).

### 2.4 GENERAL_REDIAL

- `start()` dials **all** bootnodes, then **all** restored `known_peers` (minus local listen addr).
- `start_heartbeat` (peer_count == 0): redials every bootnode **and** every known non-bootnode peer.
- `start_reconnection_task`: candidate set = bootnodes ∪ known_peers (local excluded, dedup); exp backoff cap 60s, 6 retries preserved.
- Test: `test_general_redial_includes_known_peers` — non-bootnode peer appears in the reconnection candidate set.

### 2.5 PEX

- `P2PMessage::Peers(Vec<SocketAddr>)` unchanged on the wire (bincode variant already present).
- Receive path: insert new addresses into `known_peers` (bounded by `MAX_KNOWN_PEERS = 1000`) **and** stamp `peer_last_seen` (so PEX-learned peers participate in TTL/redial).
- Send path (`start_pex`, 15s): broadcasts current `known_peers` to all connected peers.
- Disconnect/handshake-fail **keep** addresses → PEX + redial can re-establish.
- Tests: `test_pex_message_carries_known_peers` (roundtrip), `test_partition_keeps_known_peers_for_reconnect`.

### 2.6 BOOTNODE_LOSS

- Scenario: A↔B already know each other; bootnode dies.
- Because disconnect no longer drops `known_peers`, A still has B as a redial candidate after removing the dead bootnode.
- Test: `test_bootnode_loss_pair_stays_connected` — after removing boot from the known set, B remains in the general-redial candidate list.

### 2.7 COLD_START

- On `start()`: `load_known_peers()` runs before any dial; restored addresses are dialed even if `bootnodes` is empty.
- Test: `test_cold_start_restores_dial_candidates_without_bootnode` — pre-written store + empty bootnodes → peer restored, non-boot candidate count == 1.
- Companion: `test_partition_keeps_known_peers_for_reconnect`.

---

## 3. P2P_CRYPTO_AUDIT + MINIMAL FIX

**`P2P_CRYPTO_ISSUE = CONFIRMED` (pre-fix)**  
**`P2P_CRYPTO_FIX = PASS` (direction-byte nonce, wire-compatible)**

### Cause (pre-fix)

Both directions of a session shared **one** X25519-derived key:

1. Handshake derives `shared_secret` via ephemeral X25519 (`p2p.rs` handshake).
2. Key = `SHA-256(b"aether-p2p-key-v1" || shared_secret)` — no HKDF, no direction/salt separation.
3. Each side’s send path initialised `send_counter = 1`.
4. Nonce = `build_nonce(counter)` = 8-byte BE counter in bytes `[0..8]`, rest zero.
5. Receiver trusted the **wire-supplied nonce** verbatim (no independent direction byte).

Therefore the first frame A→B and the first frame B→A both encrypted under:

```
(K, N) where K = shared session key, N = BE_u64(counter) || 00 00 00
```

Equal counters under the same key ⇒ ChaCha20-Poly1305 (key, nonce) reuse.

### Synthetic exploit scenario (test vector only — no real keys)

```
KEY = 0303030303030303030303030303030303030303030303030303030303030303   (synthetic test key)
NONCE = 0000000000000001 00000000                                       (counter=1, direction=0 pre-fix)
MESSAGE A = GetInventory { tips: [...] }                                 (first frame A→B)
MESSAGE B = SyncRequest                                                  (first frame B→A)
REUSE CONDITION = same session key K + both senders' counters equal (both start at 1) + no direction byte
```

Passive observer XORs the two ciphertexts ⇒ XOR of the two structured plaintexts; crib-dragging recovers session-open messages. Impact is concentrated on equal-counter frames (first frame each way under pre-fix counters).

### Impact values (pre-fix)

```
NONCE_REUSE_SCOPE = Per-session equal-counter frames (first frame each direction under shared key + no direction byte)
EXPLOITABILITY = Confidentiality degradation (XOR/crib-drag) for an observer of both ciphertext streams; requires passive MITM or traffic capture of the session
AFFECTES = P2P session confidentiality on affected links; integrity/auth unchanged (no peer auth existed); availability and consensus unaffected
```

### Minimal fix (applied, wire v3 preserved)

| Change | Location | Guarantee |
|---|---|---|
| `build_nonce(counter, direction)` — byte[8] = direction | `src/p2p.rs` | Nonce unique across directions for equal counters |
| `send_direction(our_pk, peer_pk)` — lower key → 0x01, higher → 0x02 | handshake return | Two session senders always get opposite direction bytes |
| Send path uses session `send_dir` | `handle_peer` send task | Same K never sees same N from both directions |
| Receive-side strict counter increase | `handle_peer` recv loop | Replay/regressed nonce rejected (TCP-ordered counters) |
| `nonce_collision_possible(a_c, a_d, b_c, b_d)` | helper | Collision iff equal counter **and** equal direction |

**Wire compatibility:** framing still `[u32 len][12-byte nonce][ciphertext]`, `P2P_PROTOCOL_VERSION = 3` unchanged. Direction is carried inside the nonce (bytes 9–12 were always zero in v3 peers). Legacy peers send `byte[8]=0` and still interoperate; new↔new sessions never reuse (K, N).

**Handshake** now returns `(session_key, send_dir)`; both ends still derive the **same** session key (X25519 DH + same KDF label).

### Crypto tests added (all PASS)

| Test | Covers |
|---|---|
| `test_nonce_uniqueness_across_directions` | Nonce uniqueness across dirs + counters |
| `test_send_direction_is_opposite` | Opposite direction assignment |
| `test_encrypt_decrypt_roundtrip_bidirectional` | Encrypt/decrypt both directions |
| `test_tampered_ciphertext_fails` | Tampered ciphertext rejection |
| `test_long_message_sequence_unique_nonces` | 20k nonces unique + roundtrip |
| `test_concurrent_send_unique_counters` | Concurrent send uniqueness |
| `test_reconnect_session_rotation` | Reconnect ⇒ new key + opposite dirs |
| `test_replay_rejected_by_counter_check` | Replay/regression rejected |
| `test_nonce_collision_detected` | Updated: collision needs equal counter **and** dir |
| `test_handshake_derives_shared_key` / `_bootstrap` | Shared key + opposite dirs |

Regression: full `p2p::` suite (57/57), bootstrap_phase1 (19/19).

---

## 4. Test results

PATH prepended with MSYS2 dlltool (`C:\msys64\mingw64\bin` + rust self-contained).

```
cargo test --lib bootstrap_phase1
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 419 filtered out
```

```
cargo test --lib p2p::
test result: ok. 57 passed; 0 failed; 0 ignored; 0 measured; 381 filtered out
```

`cargo check --lib` — **EXIT_CODE=0** (warnings only; pre-existing dead_code / unused imports).

Full `cargo test --lib` (438 tests) was interrupted — **old run log lost**, `RESUME_POINT = UNKNOWN`. Accounting is split; results from different runs are never summed into one number.

**Old (interrupted) run — captured fragment:**

```
OLD_RUN_PASS = 249
OLD_RUN_FAIL = 0
OLD_RUN_IGNORED = 3
```

**Migration_multinode targeted re-run (21 tests, resumed this session)** — `mig_results.txt`:

```
test_grace_period_attack_rejected            | 2.14s    | PASS
test_grace_period_boundaries                 | 1.76s    | PASS
test_grace_period_constants                  | 1.77s    | PASS
test_invariant_i10_restart_preserves_rule    | 2s       | PASS
test_invariant_i1_same_tx_same_difficulty    | 1.79s    | PASS
test_invariant_i2_same_activation_all_nodes  | 1.76s    | PASS
test_invariant_i3_pre_activation_accepted    | 1.75s    | PASS
test_invariant_i4_post_activation_24bit      | 1.81s    | PASS
test_invariant_i5_backdating_rejected        | 1.8s     | PASS
test_invariant_i6_historical_accepts_pre_activation | 1.94s | PASS
test_invariant_i7_parent_ordering            | 567s     | PASS
test_invariant_i8_i9_fingerprints_match      | 3296.04s | PASS
test_mixed_version_divergence                | 19.18s   | PASS
test_restart_preserves_activation_constant   | 2.34s    | PASS
test_system_time_does_not_modify_activation  | 1.88s    | PASS
test_wallet_backdated_rejected               | 87.32s   | PASS
test_wallet_post_activation_24bit            | 156s     | PASS
test_new_version_internal_consistency        | 1729.64s | PASS
test_partition_around_activation             | 3236.93s | PASS
test_10node_full_convergence                 | 5681.06s | PASS
test_fresh_node_reconstructs_history         | 3264.08s | PASS
```

4 tests previously only confirmed from the old (lost) run log have since been **re-executed** and now carry their own result lines (`RELEASE`):

```
test_clock_skew_determinism                 | 2.04s    | PASS | RELEASE
test_clock_skew_classification              | 1.85s    | PASS | RELEASE
test_clock_skew_backdating_unanimous        | 1.88s    | PASS | RELEASE
test_deep_sync_fingerprint_stability        | 59.9s    | PASS | RELEASE
```

```
MIGRATION_MULTINODE = PASS   (25/25, every test has a result line in mig_results.txt)
FAILURES = none
```

**Group `tests::multiprocess_crash` (10 tests, sequential)**:

```
test_harness_integrity                     | 2.07s  | PASS
test_no_balance_destruction                | 1.91s  | PASS
test_no_balance_creation                   | 2.09s  | PASS
test_no_duplicate_application              | 1.98s  | PASS
test_multiprocess_crash_during_tx          | 9.51s  | PASS
test_multiprocess_crash_during_dag_insert  | 3.01s  | PASS
test_multiprocess_crash_during_ledger_persist | 4.16s | PASS
test_multiprocess_crash_during_sync        | 1.91s  | PASS
test_multiprocess_crash_during_partition   | 2.02s  | PASS
test_multiprocess_500_cycles               | 75.48s | PASS
```

```
MULTIPROCESS_CRASH = PASS   (10/10)
NEXT_GROUP = deep_sync_harness
```

**Group `tests::deep_sync_harness` (44 tests, sequential)** — all lines in `mig_results.txt` (mode not recorded on those earlier lines; no `debug_assertions` present in `src/`):

```
DEEP_SYNC_HARNESS = PASS   (44/44)
FAILURES = 0   INCOMPLETE = 0
```

**Group `tests::pow_economics` (4 tests, sequential)**:

```
test_pow_benchmark_24bit | 8091.69s   | PASS | DEBUG
test_pow_cost_model      | 10814.51s  | PASS | DEBUG
test_pow_curve           | 3246.08s   | PASS | RELEASE
test_pow_verification_cost | 115.43s  | PASS | RELEASE
```

```
POW_ECONOMICS = PASS   (4/4)
FAILURES = 0   INCOMPLETE = 0
```

Mode rationale: `test_pow_benchmark_24bit` asserts `median > 500ms` → DEBUG (speed-sensitive). `test_pow_curve` (no assertion) and `test_pow_verification_cost` (ratio > 100, ratio invariant) → RELEASE.

**Group `tests::scalability` (7 tests, sequential, RELEASE)** — `22:15:13 → 23:05:04`:

```
test_rebuild_curve        | 1008.88s | PASS | RELEASE
test_rebuild_degradation  | 941.7s   | PASS | RELEASE
test_scalability_100k_chain | 796.52s | PASS | RELEASE
test_scalability_10k_chain  | 8.34s   | PASS | RELEASE
test_scalability_25k_chain  | 44.71s  | PASS | RELEASE
test_scalability_50k_chain  | 188.04s | PASS | RELEASE
test_scalability_50k_tree   | 2.48s   | PASS | RELEASE
```

```
SCALABILITY = PASS   (7/7)
FAILURES = 0   INCOMPLETE = 0
```

Mode rationale: no PoW (`inject_transaction_raw`), sole assertion `assert_eq!(tx_count, n+1)` → RELEASE.

**Group `tests::security_tests` (25 tests, sequential, DEBUG)** — `23:06:39 → 23:07:30`:

```
SECURITY_TESTS = PASS   (25/25)
FAILURES = 0   INCOMPLETE = 0
```

Mode rationale: pure assertions, no PoW / no benchmark / no `Instant` elapsed assertion → DEBUG.

**Group `tests::spec_check` (14 tests, sequential, DEBUG)** — `23:27:49 → 23:28:16`:

```
SPEC_CHECK = PASS   (14/14)
FAILURES = 0   INCOMPLETE = 0
```

Mode rationale: constant/spec assertions only → DEBUG.

**Group `tests::sybil_scale` (10 tests, sequential, RELEASE)** — `23:29:30 → 23:29:48`:

```
SYBIL_SCALE = PASS   (10/10)
FAILURES = 0   INCOMPLETE = 0
```

Mode rationale: no `debug_assertions`, no `elapsed` assertion, ban-recovery uses a forced deterministic offset → RELEASE.

---

## 5. Final verdict values

```
PEER_PERSISTENCE = PASS
PEER_TTL = PASS
MULTI_SEED = PASS
GENERAL_REDIAL = PASS
PEX = PASS
BOOTNODE_LOSS = PASS
COLD_START = PASS
P2P_CRYPTO_AUDIT = PASS
P2P_CRYPTO_ISSUE = CONFIRMED
P2P_CRYPTO_FIX = PASS
PHASE1_REGRESSION = PASS   (p2p:: + bootstrap_phase1 green)
MIGRATION_MULTINODE = PASS  (25/25)
MULTIPROCESS_CRASH = PASS   (10/10)
DEEP_SYNC_HARNESS = PASS    (44/44)
POW_ECONOMICS = PASS        (4/4)
SCALABILITY = PASS          (7/7, RELEASE)
SECURITY_TESTS = PASS       (25/25, DEBUG)
SPEC_CHECK = PASS           (14/14, DEBUG)
SYBIL_SCALE = PASS          (10/10, RELEASE)
V1.4.0_IMMUTABLE = PASS    (ad08e30 untouched, no deploy)
DEPLOYMENT = NONE
```

**`PHASE1_VALIDATION_FINAL` (accounting kept separate — never summed):**

```
OLD_RUN_PASS = 249      (old interrupted run, log lost, RESUME_POINT = UNKNOWN)
OLD_RUN_FAIL = 0
OLD_RUN_IGNORED = 3

MIGRATION_MULTINODE = 25/25
MULTIPROCESS_CRASH  = 10/10
DEEP_SYNC_HARNESS   = 44/44
POW_ECONOMICS       =  4/4
SCALABILITY         =  7/7
SECURITY_TESTS      = 25/25
SPEC_CHECK          = 14/14
SYBIL_SCALE         = 10/10
                    ---------
TARGETED_GROUPS     = 139/139   PASS, 0 FAIL, 0 INCOMPLETE

TOTAL_NEW_VALIDATED = 139
FAILURES = 0
INCOMPLETE = 0
V1.4.0_IMMUTABLE = PASS
DEPLOYMENT = NONE
```

**Tests not executed in this validation pass** (documented, not presented as passing): the `cargo test --lib` suite contains **438** tests; the 8 targeted groups cover **139**. The remaining **299** were not part of this pass and are **not** claimed as validated here:

```
tests (non-grouped modules) = 254
bootstrap_phase1_tests      =  19   (covered separately by PHASE1_REGRESSION, 19/19)
consensus_harness           =  11
crash_harness               =  10
inc01_fix_tests             =   5
```

Note on `mig_results.txt`: one stale line `test_pow_curve | 3350.81s | INCOMPLETE` remains from an interrupted attempt; it is superseded by `test_pow_curve | 3246.08s | PASS | RELEASE`. The authoritative count is **139 PASS / 0 FAIL** across the 8 groups.

- `P2P_CRYPTO_AUDIT = PASS` — audit completed to required depth (cause / exploit / impact / fix / tests).
- `P2P_CRYPTO_ISSUE = CONFIRMED` — the pre-fix nonce-reuse defect was real (equal counters, shared key, no direction byte).
- `P2P_CRYPTO_FIX = PASS` — direction-byte nonces + strict receive counter; wire v3 preserved; mandatory crypto tests green.

---

## 6. Constraints respected

- `v1.4.0-testnet` / `ad08e30` untouched: `git rev-list -n1 v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` (annotated tag object `c230cde` peels to `ad08e30`); no commit created this session (`reflog`: branch created from HEAD, zero new commits); 4 commits ahead of `ad08e30` all pre-existing.
- No consensus / PoW / genesis / network ID / Transaction / TXID change.
- No deploy; VPS remains bootnode-only under separate infra escalation.
- Crypto fix: minimal direction-byte approach — **no** full protocol redesign, **no** version bump required for interop.
- Work confined to `dev/phase1-bootstrap`: `src/p2p.rs`, `src/config.rs`, `src/node.rs`, `src/rpc.rs` (test config field), this document.
