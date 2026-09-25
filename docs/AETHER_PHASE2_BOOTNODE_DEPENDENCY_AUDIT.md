# AETHER — PHASE 2 — BOOTNODE_DEPENDENCY_AUDIT

**Status:** AUDIT ONLY — no code change in this document
**Date:** 2026-09-26
**Branch:** `dev/phase2-decentralized-network`
**Base:** `dcc33c9` (Phase 1 checkpoint)
**Release frozen:** `v1.4.0-testnet` (`ad08e30`) — **IMMUTABLE**

Method: static reading of `src/p2p.rs` (3584 lines), `src/node.rs`, `src/config.rs`,
`src/main.rs`, `src/gui.rs`, plus `cargo test --lib -- --list` and `cargo check --lib`
(EXIT=0, baseline clean). Every claim below carries a file:line reference that was read,
not inferred.

---

## 1. BOOTNODE_DEPENDENCY_AUDIT

### 1.1 CRITICAL DEPENDENCIES

| # | Dependency | Where | Critical? |
|---|---|---|---|
| C1 | `start()` dials **every** bootnode first, awaited, before anything else | `p2p.rs:422-425` | YES — but non-fatal if the list is empty |
| C2 | **Cold start with an empty peer store dials only bootnodes + DNS.** With `bootnodes=[]` and `dns_seeds=[]` there is **zero** outbound discovery path. | `p2p.rs:422-438`, `config.rs:67` (`dns_seeds: Vec::new()`) | **YES — the real SPOF** |
| C3 | `start()` serial-dials the whole restored peer store **before starting any background task** (heartbeat, PEX, reconnection, TTL). | `p2p.rs:427-457` | **YES — gates all recovery** |
| C4 | Heartbeat (`peer_count == 0`) dials bootnodes first, then known peers. | `p2p.rs:586-603` | Medium — falls back to `known` |
| C5 | Reconnection task candidate list is built as `bootnodes ++ known`, bootnodes always first, and `sleep(delay)` runs **inside** the per-candidate loop. A black-holed bootnode stalls the whole cycle before any real peer is tried. | `p2p.rs:623-658` | **YES — seed privilege (Principle 2 violation)** |
| C6 | `connect_to_peer` logs every dial as `Tentative de connexion au bootnode` — every peer is treated as a bootnode in code path semantics/log surface. | `p2p.rs:1699` | Low (cosmetic, but reveals the mental model) |

### 1.2 NON-CRITICAL DEPENDENCIES

| # | Dependency | Where | Why non-critical |
|---|---|---|---|
| N1 | Config parse/validate of bootnode strings | `node.rs:69-72`, `main.rs:302-309`, `gui.rs:794-797` | Fails soft; empty list parses fine, node starts |
| N2 | Bootnode banner logging | `node.rs:93` | Informational |
| N3 | CLI/TOML override of the seed list | `main.rs:49-51`, `config.rs:44`, `config.rs:62-65` | Operator choice, not a runtime dependency |
| N4 | DNS seed re-resolution loop (120s) | `p2p.rs:722-754` | Independent path, no-op when `dns_seeds` empty |
| N5 | PEX broadcast (15s) | `p2p.rs:757-780` | Runs unconditionally, never consults bootnodes |
| N6 | PEX receive → dial | `p2p.rs:1620-1653` | Never consults bootnodes |

### 1.3 FALLBACK PATHS (already present after Phase 1)

1. **Peer store restore** — `load_known_peers()` `p2p.rs:461-487`, path from `node.rs:584`.
2. **General redial** — heartbeat candidate set includes non-bootnode peers `p2p.rs:593-603`.
3. **Reconnection task** — `bootnodes ++ known` `p2p.rs:623-629`.
4. **PEX** — broadcast `p2p.rs:757-780`, receive `p2p.rs:1620-1653`.
5. **DNS seeds** — `p2p.rs:690-719`, `p2p.rs:722-754` (empty by default).
6. **Inbound accept** — `accept_loop` `p2p.rs:788+` (works with zero bootnodes).

**Absent fallbacks:** anchors, outbound-slot reservation, feelers, address aging/quality,
peer categories, self-healing escalation, address-source tracking, private-range filtering.

### 1.4 CONCERNED FILES

```
src/p2p.rs        3584 lines   the whole discovery / redial / PEX / store surface
src/node.rs        943 lines   :69-72 parse, :93 log, :577-585 P2PConfig, :601-606 start()
src/config.rs      111 lines   :44 bootnodes field, :56-71 multi-seed default, :67 dns_seeds empty
src/main.rs        668 lines   :49-51 CLI, :302-309 apply, :345-351 banner
src/gui.rs         830 lines   :34, :794-797, :815 CLI override
docs/AETHER_PHASE1_BOOTSTRAP_IMPLEMENTATION.md   Phase 1 baseline
```

### 1.5 CONCERNED FUNCTIONS

```
p2p.rs  P2PNetwork::start()                    371-459   order of bootstrap steps
p2p.rs  load_known_peers()                     461-487   store restore
p2p.rs  save_known_peers()                     489-519   atomic write
p2p.rs  touch_peer()                           521-531   DEAD CODE — defined, never called
p2p.rs  start_peer_store_task()                533-567   TTL expiry + flush
p2p.rs  start_heartbeat()                      569-609   peer_count==0 redial
p2p.rs  start_reconnection_task()              611-662   candidate loop, bootnode-first
p2p.rs  discover_from_dns()                    690-719
p2p.rs  start_dns_discovery()                  721-754
p2p.rs  start_pex()                            756-780   unbounded full-set broadcast
p2p.rs  accept_loop()                          787+      inbound: MAX_PEERS / subnet / ban
p2p.rs  handle_peer()                          ~1010-1680 inbound session, PEX receive, disconnect
p2p.rs  connect_to_peer()                      1698-1790 outbound: no ban check, no addr filter
p2p.rs  subnet_24 / count_subnet_peers(_excluding) 160-205  /24 diversity
node.rs parse_bootnode_address()               27-60
node.rs run_node()                             62+       config → P2PConfig → start()
```

---

## 2. CURRENT STATE OF THE FOUR OBJECTIVES

| Objective | Current | Evidence |
|---|---|---|
| `BOOTNODE_REQUIRED_FOR_EXISTING_SESSIONS` | **NO** | `handle_peer` never reads `config.bootnodes`; sessions are independent once established |
| `BOOTNODE_REQUIRED_FOR_STEADY_STATE` | **PARTIAL → NO in principle, NO in practice only if `known_peers` is non-empty** | heartbeat `p2p.rs:586-603` and reconnection `p2p.rs:623-629` both include non-bootnode peers; but bootnodes are always tried first and stall the cycle (C5) |
| `BOOTNODE_REQUIRED_FOR_PEER_DISCOVERY` | **NO** (PEX + DNS are bootnode-independent) | `p2p.rs:756-780`, `p2p.rs:1620-1653` never consult bootnodes |
| `BOOTNODE_REQUIRED_FOR_COLD_START` | **YES for a fresh node** | C2: empty store + empty `dns_seeds` ⇒ the only outbound path is the bootnode list. C3: a large/dead store delays recovery even further |

**Therefore today:** `BOOTNODE_SINGLE_POINT_OF_FAILURE = YES` (cold start only).

---

## 3. CURRENT ARCHITECTURE (as implemented)

```
                       ┌──────────────────────────────┐
                       │  VPS bootnode (single seed)  │  ← default in config.rs:62-65
                       └──────────────┬───────────────┘
                                      │  (1) start() dials bootnodes FIRST, awaited
                                      ▼
   start() ──► dial all bootnodes ──► dial ALL restored known_peers (serial, awaited)
                 (p2p.rs:422)           (p2p.rs:427-435)          ▲
                                       │                           │
                                       │  only AFTER these finish: │
                                       ▼                           │
                       start_heartbeat / start_reconnection_task    │
                       start_peer_store_task / start_dns_discovery  │
                       start_pex / start_cache_cleanup (p2p.rs:441-456)

   known_peers : HashSet<SocketAddr>          (flat, no categories, no metadata)
   peer_last_seen : HashMap<Addr, Instant>    (refreshed ONLY on handshake :1121
                                                and on disconnect :1679)
   store on disk : ["ip:port", ...]           (p2p.rs:489-519, atomic rename)
   TTL           : 3600s, sweep every 30s     (p2p.rs:39, :533-567)
   PEX           : every 15s, FULL set, to ALL peers (p2p.rs:757-780)
   PEX receive   : take(1000) → insert → DIAL IMMEDIATELY (p2p.rs:1620-1653)
```

## 4. TARGET ARCHITECTURE (Phase 2)

```
                    ┌─────────┐
                    │ Node A  │
                    └──┬───┬──┘
           ┌───────────┘   └───────────┐
       ┌───▼───┐                   ┌───▼───┐
       │Node B │◄──────────────────►│Node C │
       └───┬───┘                   └───┬───┘
           │        ┌───────────┐      │
           └───────►│  Node E   │◄─────┘
                    └─────┬─────┘
                          │
   seed1 ─┐              │              ┌─ seed3
           ├─► any node ─┴─► any node ◄─┤
   seed2 ─┘        (seeds are ordinary, unprivileged entry points)

   After bootstrap, the graph is self-sustaining:
       A↔B  A↔C  B↔D  C↔E ...
   Loss of every seed ⇒ steady state unchanged.
```

Bootnode = one *initial entry point among many*, never an authority, never privileged
in the redial ordering, never required once `known_peers`/anchors hold live addresses.

---

## 5. DEFECTS FOUND (mapped to the 16 principles)

| ID | Principle | Defect | Evidence |
|---|---|---|---|
| D1 | P4 / P8 | **`peer_last_seen` is refreshed only at handshake and disconnect.** A peer that stays connected > `PEER_TTL` (3600s) is expired out of `known_peers` and therefore **dropped from the persisted store** — the node forgets its best long-lived peer precisely because it is reliable. | set at `p2p.rs:1121` and `:1679`; expiry `:545-555` |
| D2 | P2 | **Seed privilege in redial ordering.** Candidate list is `bootnodes ++ known` and `sleep(delay)` + `connect_to_peer` run inside the per-candidate loop, so one dead seed serially delays every real peer redial. | `p2p.rs:623-658` |
| D3 | P1 / P10 | **Cold start has no non-seed path.** `dns_seeds` defaults to empty (`config.rs:67`); with an empty store the only dial target is the bootnode list. | `p2p.rs:422-438` |
| D4 | P4 / P10 | **Recovery tasks are gated behind a serial dial sweep.** With a store full of dead addresses, `start()` spends up to `N × CONNECT_TIMEOUT` before PEX/heartbeat/TTL exist at all. Worst case for `MAX_KNOWN_PEERS=1000` at `CONNECT_TIMEOUT=5s` ≈ **83 minutes**. | order `p2p.rs:422-457`; timeouts `:213`, `:39` |
| D5 | P3 | **PEX floods.** Full `known_peers` set (≤1000) is broadcast to **every** peer every 15s, with no send-side cap, no randomization, no rate limit, no origin dedup. | `p2p.rs:756-780` |
| D6 | P3 | **PEX receive dials unconditionally and immediately**, with no rate limit and **no private/reserved address filtering** — a peer can steer the node into dialing `127.0.0.1`, RFC1918, link-local or internal addresses. | `p2p.rs:1620-1653`, `connect_to_peer` `:1698` |
| D7 | P3 / P4 | **`known_peers` is a flat `HashSet`** — no categories (active / recent / anchor / candidate / penalized), no source, no attempt count, no last-success, no quality. Not a real "peer address manager". | `p2p.rs:315`, `:329` |
| D8 | P3 / P4 | **Peer store has no metadata** — a JSON array of strings. No truncation by quality, no per-entry TTL persisted, no poisoning defence (a hostile PEX burst of 1000 junk addrs permanently displaces good ones, up to `MAX_KNOWN_PEERS`). | `p2p.rs:461-519`, insert `:1645` |
| D9 | P5 | **No anchors at all.** | absent |
| D10 | P6 | **`PROTECTED_OUTBOUND_SLOTS = 8` is declared but never used in logic** — only referenced by assertions. No inbound/outbound slot split, no feelers, no periodic outbound replacement, no pseudo-random selection. | `p2p.rs:39`, `:3283`, `:3287` only |
| D11 | P6 / P7 | **Outbound dial does not check `is_banned`** while inbound does — a node will redial a peer it has already banned. Banned addresses also remain in `known_peers` and are re-shared over PEX to other nodes. | inbound check `p2p.rs:828-844`; outbound `:1698-1719` absent |
| D12 | P7 | **Diversity is /24-only and IPv6 is synthetic.** `subnet_24` maps IPv6 to its first 3 bytes, which is not a routing prefix — no ASN / /48 awareness. Single-network-lockout is only partially mitigated. | `p2p.rs:160-172` |
| D13 | P15 | **No self-healing escalation.** No `MIN_PEERS` constant exists anywhere in `src/`; there is no staged recovery (anchors → store → PEX → seeds → new candidates) and no de-escalation once healthy. | grep `MIN_PEERS` ⇒ 0 hits |
| D14 | P1 / P14 | **`connect_to_peer` hard-codes bootnode wording**, encoding the assumption that dialing == dialing a bootnode. | `p2p.rs:1699` |
| D15 | P4 | **`touch_peer()` is dead code** — defined at `p2p.rs:521-531`, never called. The Phase 1 "refresh TTL clock" helper is not wired in. | grep `touch_peer` ⇒ 1 hit (the definition) |
| D16 | P12 | **Crypto is healthy and must not be touched.** `build_nonce` / `send_direction` / `nonce_collision_possible` / `last_recv_counter` are present and Phase-1-validated. CHIFFREMENT ≠ ANONYMAT: nothing in this codebase provides anonymity. | `p2p.rs:891-1000`, `:1128`, `:1195+` |

### Positive findings (already correct — do not regress)

- Node starts with `bootnodes = []` without error (`node.rs:69-72`, no validation failure).
- Steady state never consults bootnodes when peers are connected (`p2p.rs:586,604`).
- PEX/DNS paths are bootnode-independent.
- Peer store write is atomic (`tmp` + `rename`, `p2p.rs:511-518`).
- Inbound limits exist: `MAX_PEERS=128`, `MAX_PEERS_PER_SUBNET=4`, ban check.
- `MAX_INV_ITEMS=1000` bounds incoming PEX lists.
- Wire v3 + direction-byte nonces + counter anti-replay intact.

---

## 6. RISKS

| # | Risk | Impact | Mitigation in Phase 2 |
|---|---|---|---|
| R1 | Making seeds unprivileged accidentally breaks the only working cold-start path | New nodes cannot join at all | Keep seeds as *one* candidate class; every stage keeps seeds as a fallback, never removes them |
| R2 | Reordering `start()` (D4) changes dial semantics and could break Phase 1 tests `test_cold_start_restores_dial_candidates_without_bootnode`, `test_bootnode_loss_pair_stays_connected` | Regressions | Run `p2p::` + `bootstrap_phase1` after every stage |
| R3 | Peer-store schema change (D8) breaks existing `known_peers.json` | Silent loss of stored peers | Version the JSON, fall back to legacy `Vec<String>` on parse failure |
| R4 | Address filtering (D6) blocks legitimate private/LAN test deployments | Testnets on LAN break | Filter only for **PEX-sourced** dials; keep operator-configured bootnodes unrestricted |
| R5 | PEX send-side capping (D5) slows discovery | Slower peer growth | Bound by sample, not by removal; keep `MAX_INV_ITEMS` receive bound |
| R6 | Anchors become a de-facto authority (Principle 5) | Reintroduces the SPOF we are removing | Multiple anchors, rotation, expiry, never required, never trusted for state |
| R7 | Eclipse resistance overstated | False safety claim | Document limits explicitly; never claim perfect resistance |
| R8 | Over-engineering (DHT, Tor) before measuring | Wasted complexity, new bugs | DHT is **study-only** (Principle 11); Tor/I2P **study-only** (Principle 13) |
| R9 | Touching crypto "while we are here" | Invalidates Phase 1 crypto validation | P12: no crypto change without a dedicated audit first |
| R10 | Relaunching the 139 Phase 1 tests / 438 suite repeatedly | Hours of wasted compute | Only targeted tests per stage |

---

## 7. TESTS TO ADD

Minimum set (Principle 16), each mapping to a success criterion:

| Test | Principle | Verifies | Criterion |
|---|---|---|---|
| `test_bootnode_optional_after_bootstrap` | P1 | established sessions do not need bootnodes | `BOOTNODE_REQUIRED_FOR_EXISTING_SESSIONS = NO` |
| `test_bootnode_loss_steady_state` | P8 | tx propagation + PEX + redial + convergence with all seeds down | `NETWORK_CONTINUES_AFTER_BOOTNODE_LOSS = PASS` |
| `test_multihop_bootstrap_without_seed` | P9 | A→seed, A discovers B, B→C, C→D, D works with no seed; then seed dies | `MULTIHOP_BOOTSTRAP = PASS` |
| `test_multi_seed_failure` | P2 | seed1/2 down + seed3 up ⇒ join succeeds; no seed privilege | `MULTI_SEED_BOOTSTRAP = PASS` |
| `test_peer_store_recovery` | P4 | restart with seeds down rebuilds neighbourhood from store | `PEER_PERSISTENCE = PASS` |
| `test_anchor_recovery` | P5 | anchors reconnect, dead anchors rotate, anchors never required | `ANCHOR_RECOVERY = PASS` |
| `test_pex_without_bootnode` | P3 | PEX discovers + dials with `bootnodes = []` | `PEX_WITHOUT_BOOTNODE = PASS` |
| `test_redial_without_bootnode` | P1/P15 | heartbeat + reconnection recover with `bootnodes = []` | `REDIAL_WITHOUT_BOOTNODE = PASS` |
| `test_cold_start_without_single_seed` | P10 | 3 seed permutations incl. all-down + anchors-up | `COLD_START_DISTRIBUTED = PASS` |
| `test_peer_diversity` | P6 | /24 + slot limits hold under a single-network flood | `BASIC_ECLIPSE_RESISTANCE = PASS` |
| `test_eclipse_resistance_basic` | P7 | scenarios A–G (see §8) | `BASIC_ECLIPSE_RESISTANCE = PASS` |
| `test_peer_store_poisoning` | P4/P7 | junk burst cannot displace good addresses | `BASIC_ECLIPSE_RESISTANCE = PASS` |
| `test_bootstrap_self_healing` | P15 | `peer_count < MIN_PEERS` escalates, then de-escalates | `SELF_HEALING = PASS` |

Supporting regression tests for defects found here:

```
test_connected_peer_survives_ttl            (D1)
test_dead_seed_does_not_delay_real_peer     (D2)
test_start_does_not_gate_tasks_on_dialing   (D4)
test_pex_send_bounded                       (D5)
test_pex_ignores_private_addresses          (D6)
test_outbound_respects_ban                  (D11)
```

---

## 8. ECLIPSE SCENARIOS TO TEST (Principle 7)

| # | Scenario | Handling |
|---|---|---|
| A | attacker controls every peer offered to a node | diversity slots + anchors from before the attack + PEX sampling |
| B | attacker offers only one network's IPs | `/24` limit (exists) + outbound slot reservation (missing, D10) |
| C | bootnode compromised | seeds are unprivileged; poisoned seed cannot become sole source |
| D | seed compromised | same as C; multiple independent seeds |
| E | peer store poisoned | quality-aware store, per-source caps (missing, D8) |
| F | hostile restart | anchors + store + PEX before seeds (missing, D9/D3) |
| G | simultaneous loss of several peers | self-healing escalation (missing, D13) |

**Limitation to document, never to hide:** resistance is probabilistic. With ≤128 slots
and /24-only grouping, a well-provisioned attacker on many networks can still eclipse a
targeted node. Phase 2 reduces the attack cost required — it does not eliminate it.

---

## 9. PLAN PHASE 2A → 2E

### PHASE 2A — Audit + remove unnecessary bootnode runtime dependency
- Delete the seed privilege: shuffle/deprioritize candidates, move `sleep` out of the
  per-candidate loop so one dead seed cannot stall real peers (D2).
- Reorder `start()`: start heartbeat/reconnection/TTL/PEX **before** the dial sweep (D4).
- Refresh `peer_last_seen` for peers that remain connected, wired through the dead
  `touch_peer()` (D1, D15).
- Fix outbound ban check + exclude banned addresses from PEX sends (D11).
- Neutralise bootnode-specific wording in `connect_to_peer` (D14).
- Gate: `cargo check --lib` + `p2p::` + `bootstrap_phase1`.
- Commit: `phase2: remove bootnode runtime dependency`

### PHASE 2B — Distributed peer manager (anchors + peer store + redial + PEX)
- Real peer address manager with the 5 categories (Principle 3): active / recent /
  anchors / candidates / penalized (D7).
- Versioned store with metadata (source, attempts, last-success, quality), legacy
  fallback (D8, R3).
- Anchors: several, rotated, expired, replaceable, never authoritative (Principle 5, D9).
- PEX: send-side sample + cap, aging, dedup, origin tracking (D5).
- Private/reserved address filtering for PEX-sourced dials only (D6, R4).
- Gate: `cargo check --lib` + targeted tests.
- Commit: `phase2: add distributed peer manager`

### PHASE 2C — Eclipse resistance (diversity + rotation + selection)
- Wire `PROTECTED_OUTBOUND_SLOTS`, inbound/outbound slot split, feelers, periodic
  outbound replacement, pseudo-random selection (D10, Principle 6).
- Scenarios A–G tests (§8).
- Document remaining limits (R7).
- Commit: `phase2: harden peer diversity`

### PHASE 2D — Self-healing + distributed cold start
- `MIN_PEERS` staged recovery: anchors → store → PEX-known → seeds → new candidates,
  with de-escalation once healthy (D13, Principle 15).
- Cold start permutations: seeds down/up combinations, anchors-up, multi-peer config
  (Principle 10).
- Tests: `test_bootstrap_self_healing`, `test_cold_start_without_single_seed`,
  `test_multihop_bootstrap_without_seed`, `test_bootnode_loss_steady_state`.
- Commit: `phase2: add self-healing bootstrap`

### PHASE 2E — Privacy / anonymity audit
- Study only: Tor, I2P, pluggable transports, network-identity/IP separation,
  metadata reduction (Principle 13).
- Produce `docs/AETHER_NETWORK_PRIVACY_ROADMAP.md`.
- **No Tor/I2P integration in this phase.**
- Explicit statement: **CHIFFREMENT ≠ ANONYMAT**; the network is not anonymous.
- Commit: `phase2: document privacy roadmap`

### Cross-cutting, all stages
- Never `git add .` — explicit per-file staging, pre-existing dirty files stay unstaged.
- No push, no merge, no tag, no deploy. `v1.4.0-testnet` / `ad08e30` untouched.
- No change to `build_nonce`, `send_direction`, `nonce_collision_possible`,
  `last_recv_counter`, handshake, difficulty, assertions or protocol.
- Never relaunch the 139 Phase 1 tests or the 438-test suite without cause.

---

## 10. DEFERRED (explicitly out of scope for Phase 2)

- **DHT** — Principle 11: study only, into `docs/AETHER_PHASE2_DISCOVERY_DESIGN.md`,
  comparing (A) seeds+PEX+persistence, (B) +anchors, (C) full DHT. No implementation
  before `DHT_REQUIRED / BENEFIT / RISK / COMPLEXITY` are answered.
- **Tor / I2P / pluggable transports** — Principle 13, `docs/AETHER_NETWORK_PRIVACY_ROADMAP.md`.
- **Consensus / PoW / genesis / transaction format** — untouched.
