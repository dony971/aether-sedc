# CANARY INCIDENTS — Phases C1 + C2 (RC-aligned)

## INC-C1-001: Ledger Divergence node1 vs nodes 2-8

**Timestamp:** 2026-08-28 04:24 UTC
**Node:** node1 (seed, RPC 42101) vs all other 7 nodes
**Type:** LEDGER / CONSENSUS
**Severity:** MEDIUM
**RC:** `77f01ee` (unchanged)

### Symptoms

- 5 wallet addresses have 11 more AETH-units on node1 than on nodes 2-8
- Total supply divergence: 55 units
- Affected addresses: `eee2fc33`, `a8dfcc54`, `8ddf5ce4`, `2c7ebf0c`, `6a4f940c`
- All non-seed nodes (2-8) have IDENTICAL ledgers
- node1 is the only outlier

### Key Facts

- DAG total: 1478 on ALL nodes (match)
- Tips: 1170 on ALL nodes (match)
- Nonces: identical on ALL nodes for ALL addresses
- Faucet balance: identical on ALL nodes
- Static divergence: same 55 delta observed at all check times
- Not growing over time

### Hypothesis

gen_optimized submitted 171 transactions to node1's RPC endpoint in parallel (12 workers). The RPC submit path on node1 may apply the fee differently than the P2P receive path on nodes 2-8. Specifically, node1 may credit the fee back to the sender or fail to deduct it fully, giving senders 11 more per transaction.

### Impact

- LOW: All non-seed nodes are consistent (8/9 agree, only seed differs)
- The divergence is STATIC (not growing)
- Nonces are identical (same tx count)
- Bootstrap, restart, crash tests all PASS

### Classification

- Not a critical protocol bug (non-seed nodes agree)
- Likely a gen_optimized RPC submission artifact
- Does not affect network operation
- Documented for protocol review

### Growth Test (2026-08-28 04:26)

- Pre-gen divergence: 55 units
- Generated 60 tx (50 requested + 10 extra)
- Post-gen divergence: 55 units
- **Growth: 0**
- New transactions processed consistently across all nodes

### Status

**RESOLVED — ROOT CAUSE PROVEN (2026-08-28 ~05:30 UTC)**

**Restart test (Step 6): full network restart → divergence 55 → 0.**
All 5 addresses identical on all nodes after restart. DAG total unchanged
(1540). Proves the sled-persisted ledger + DAG were identical everywhere;
the 55 lived only in node1's in-memory live ledger.

**Dynamic test (Step 5): 108 new tx via gen_optimized → divergence stays 0.**
The 55 did NOT reappear under the same parallel-submit load. One-time
transient, not systematically reproducible.

**Classification: STATE DIVERGENCE (live-ledger vs rebuild) — NOT a
CONSENSUS/PROTOCOL bug.**
- DAG consensus identical on all nodes at all times (total/tips match).
- Boot rebuild from DAG heals the ledger deterministically.
- No code modified (RC `77f01ee` frozen throughout).

## INC-C1-002: Faucet-tx ledger divergence (1 × 10 AETH)

**Timestamp:** 2026-08-28 ~05:00 UTC
**Nodes:** node2/node5/node8 (RPC 43101/46101/49101) vs other 5 nodes
**Type:** LEDGER / STATE
**Severity:** MEDIUM
**RC:** `77f01ee` (unchanged)

### Symptoms

- Wallet `f499fa06` (NOT the genesis faucet — operator correction during
  investigation; real faucet is `a19ee04c`): 599999998383 on node2/5/8 vs
  699999998383 on the other 5 nodes. Delta = exactly 100,000,000,000 =
  **one faucet distribution** (faucet amount = 100e9 = 10 AETH, fee = 1,
  `src/rpc.rs:2125-2126`).
- Real faucet `a19e…`: higher by exactly 100e9+1 (amount+fee) on the same
  3 nodes → they did NOT apply one faucet→f499 transfer.
- Faucet nonce = 28 identical on all 8 nodes.
- DAG total = 1650 identical on all 8 nodes.

### Interpretation

Exactly ONE faucet transaction exists in the DAG on every node but its
ledger effect is applied on 5 nodes and missing on 3. Consistent with a
live-application race under burst load (gen_optimized auto-fund fires up
to 15 faucet RPC calls per low wallet; concurrent faucet txs share
`account_nonce = ledger.get_nonce+1`, creating same-nonce sender
conflicts resolved by smallest-id-wins — a node that prunes/applies in a
different order can end with the nonce committed but one transfer's
balance effect missing in memory).

### Restart test (Step 6) — HEALED

- node2 restart → f499 599999998383 → 699999998383, faucet converges.
- node5, node8 restart → same healing.
- Final: **8/8 nodes identical** on 7 addresses × 7 nodes = 0 divergences.
  DAG total 1650, tips 1306, rebuild_total=1540 (boot rebuild ran), wal=0.

### Classification

**STATE DIVERGENCE (live-ledger vs rebuild) — same class as INC-C1-001.**
- DAG consensus identical everywhere; rebuild from DAG heals every node.
- Static (no growth without new load); healed deterministically by restart.
- No code modified (RC `77f01ee` frozen throughout).

### Status

**RESOLVED (healed by restart, root-cause class identified).**
Follow-up for protocol review (NOT canary): audit live ledger
application vs rebuild path under concurrent same-sender (incl. faucet)
bursts; consider serializing faucet nonce assignment. No RC change
during canary.

## Final diagnostic after toolchain alignment (2026-08-28)

Full report: `docs/TOOLCHAIN_RC_ALIGNMENT.md`.

The Python wallet tooling had **real incompatibilities** with the RC, all
fixed and verified (RC backend SHA `770D5AF8…`, no `--daemon`, Argon2id v2
format both directions, stdin passwords, Python-side import, `--password`
send flow, dead RPCs removed, local-only seed): wallet suite **36/36**,
E2E 3 wallets on live canary PASS, node_manager start→sync→stop PASS.

Honest note: the observed 55 (INC-C1-001) transited through the **RC CLI
itself** (gen_optimized → node1 RPC), not through the Python wallet, so
the Python fixes are not proven to be its cause. With aligned tooling the
55 does **not** reproduce (parallel bursts + E2E + sequential faucet all
clean; final check DAG 0 + ledger 0 divergences at total=1659).

**Final classification (both incidents): STATE BUG (live ledger vs
rebuild) — NOT a PROTOCOL BUG.** DAG consensus never diverged; boot
rebuild from DAG heals deterministically; divergences static, restart-healed.

## INC-C2-001: Post-load ledger divergence (majority vs 3 nodes)

**Timestamp:** 2026-08-28 (C2 campaign, DAG total=1004)
**Nodes:** node5 (+309), node6/node7 (+78) vs 6-node majority
**Type:** LEDGER / STATE
**Severity:** MEDIUM
**RC:** `77f01ee` (unchanged, toolchain aligned)

### Symptoms

After a 672-tx parallel burst (gen_optimized, 8 workers, RC TEST TOOL):
- DAG total identical 1004 on all 9 nodes; mempools drained (size=0);
  tips converged (729 everywhere) after settle.
- 10-address supply: majority `...989158`, node5 `...989467` (+309),
  node6/node7 `...989236` (+78).
- Higher supply = fewer fees burned = missed live ledger applications.

### Restart tests — ALL HEALED

- node5 restart -> supply `...989467` -> `...989158` (majority). HEALED.
- node6, node7 restart -> same healing.
- Post-heal: **0 divergences (10 addrs x 8 nodes)** at total=1004.

### Classification

**STATE BUG (live ledger vs rebuild) — 3rd occurrence of the same class
(INC-C1-001, INC-C1-002, INC-C2-001).**
- DAG consensus never diverged; rebuild from DAG heals deterministically.
- Appears under parallel-submit burst load; static afterwards.
- Protocol-review follow-up (NOT canary): audit live application path vs
  rebuild under burst load. No RC change during canary.

### Status

**RESOLVED (healed by restart).** Campaign continues to 5000/10000.

## INC-C2-002: Syncing node died during 5000-load burst

**Timestamp:** 2026-08-28 (C2, during 1004->5006 generation)
**Node:** node10 (fresh bootstrap at 1000-level, was at 1002/1004 syncing)
**Type:** INFRASTRUCTURE / STABILITY (cause undetermined)
**Severity:** MEDIUM
**RC:** `77f01ee` (unchanged, toolchain aligned)

### Symptoms

- node10 (RPC 49110) unreachable after the 4000-tx burst; process gone.
- No logs captured (headless console process, no log file configured).
- Data dir intact (dag.json + sled_db present).

### Recovery

- Relaunch with same args -> node UP, `wal=1` (WAL recovery engaged),
  `rebuild=1003`, syncing 1492->5006. Recovery path works as designed.

### Notes

- The 9 stable nodes show 0 divergence at 5006 (DAG + tips + 10-addr
  supply all identical) — the burst itself was clean.
- Possible causes: OOM during catch-up+burst, Windows process kill,
  transient crash. Without node logs, not classifiable as protocol bug.
- Follow-up: run future nodes with stderr redirected to a log file so a
  crash leaves evidence (tooling improvement, NOT protocol).

### Status

**OPEN (cause undetermined) — node recovered, campaign continues.**

## INC-C2-003: Durable ledger divergence on catch-up node (restart does NOT heal)

**Timestamp:** 2026-08-28 (C2, DAG total ~10024-10034)
**Node:** node10 (RPC 49110) vs 9-node converged majority
**Type:** LEDGER / RECOVERY
**Severity:** HIGH
**RC:** `77f01ee` (unchanged, toolchain aligned)

### History

- node10 bootstrapped fresh at 1000-level (synced 1002/1004).
- Died during the 4000-tx burst (INC-C2-002, cause undetermined).
- Relaunched: WAL recovery engaged (wal=1), synced to 9998, stuck with
  578 parked orphans (548 resolved, ~30 unresolvable, mempool draining).
- Restart: orphans purged, total frozen at 9998 (-10 vs network).
- New txs propagate fine (9998->10024) but the -10 historical gap never
  backfills. Second restart: still diverged. DURABLE.

### Ledger evidence (9 tracked addresses)

- Faucet: majority `...599976` (24 sends applied) vs node10 `...399984`
  (16 sends) — delta = 8 x (100e9+1). Faucet **nonce identical 25/25**:
  nonce slots committed WITHOUT their transfers on node10.
- Wallet `77f07ce2`: -400e9 (4 faucet receives missing) on node10.
- Other wallets: +/- thousands (hundreds of missed send applications).
- node10 supply HIGHER (burns never applied).

### Majority status

9 nodes (seed + node2-9): **0 divergences** (DAG + 10-addr supply) at
total=10034. The network is healthy; node10 alone is poisoned.

### Hypothesis (protocol-review, NOT canary)

The INC-01 crash-recovery guard (STEP 1c: sender nonce already committed
=> heal DAG WITHOUT ledger replay) fossilizes entries whose nonce was
persisted without their transfer: every rebuild trusts the nonce and
skips the transfer forever. A node that persists nonce-commits ahead of
transfers during catch-up races can never self-heal by restart.

### Next step

Wipe node10 data dir -> fresh bootstrap -> check convergence. Distinguishes
poisoned-state (heals) from systematic sync bug (diverges again).

### Status

**OPEN — HIGH. Load paused. No RC change during canary.**

## INC-C2-004: Fresh nodes cannot join (orphan resolution fully stalled)

**Timestamp:** 2026-08-28 (C2, DAG total ~10044)
**Nodes:** node10 (wiped), node11 (fresh) vs 9-node healthy majority
**Type:** SYNC / ORPHAN-RESOLUTION
**Severity:** CRITICAL (testnet blocker: no new node can join)
**RC:** `77f01ee` (unchanged, toolchain aligned)

### Symptoms

- Fresh/wiped nodes connect (1-2 peers), receive sync batches
  (sync_requested=5000, batches=3535, received=1125) but insert ZERO:
  total stays 0.
- Essentially every received tx becomes an orphan (1165 parked);
  **orphan_resolved=0** (local=0, remote=0) despite parent_requested=8864.
- New live txs do not arrive either (total stays 0 after stim).
- Restart + different bootnode (seed and node2): identical stall.
- Earlier in the same campaign, node9 joined fine at 209 and node10 at
  1004; node10 catch-up resolved 548 orphans mid-campaign. The stall
  appeared at ~10k DAG scale (or after some network event — TBD).

### Contrast with INC-C2-003

- C2-003: catch-up node with poisoned live ledger (recovery-guard
  hypothesis), DAG nearly complete, restart does not heal ledger.
- C2-004: fresh nodes with EMPTY DAG cannot ingest anything; all
  received history orphans with zero resolution.

### Status

**OPEN — CRITICAL. Load paused. Code reading of sync/orphan path next.
No RC change during canary.**

### Root cause (code reading, 2026-08-28)

**Sync congestion collapse at ~10k DAG.** Measured over 60 s while two
fresh nodes tried to join:
- seed served +34,382,489 getdata units, node2 +32,621,374
  (`get_transaction_by_hash` calls = per-hash DAG/store lookups).
- fresh nodes received ~7 txs in the same minute; orphans only grow.

Mechanism (`src/p2p.rs`):
1. `GetData` handler (l.942) recomputes `topological_order` over the
   ENTIRE local DAG for EVERY GetData message — O(10k) per request —
   before serving at most PAGE_SIZE=100 hashes.
2. A behind node parks everything as orphans and re-requests up to 128
   missing parents per 10 s cycle (`process_orphans`, rpc.rs:1628),
   each as its own GetData broadcast (`request_transaction`).
3. Peers drown in full-DAG topo sorts; real responses starve; orphans
   never resolve; re-requests escalate. Positive feedback = livelock.
4. The B4 `is_orphan` inventory dedup (p2p.rs:861) additionally hides
   parked txs from re-fetch, so the stall is stable, not transient.

Why the majority is unaffected: they synced incrementally and never
need bulk catch-up. Any node that falls far behind (fresh join,
long-offline return like node10) triggers the storm.

Fix direction (protocol-review, NOT canary): cache the topological
order / serve GetData without per-message full sort; bound or batch
parent re-requests; cap inventory-driven storms. No RC change here.

## C3 validation of C2-004 fix (2026-09-05, branch canary-c2-fixes)

**Result: SYNC COLLAPSE FIXED, LEDGER DIVERGENCE PERSISTS (refined).**

- Fresh node11 @10k DAG: 0 -> 10043/10053 in ~20 min. Orphan resolution
  works (3510 resolved). Serving is O(1): seed **28784 topo hits / 1 miss**
  (was 1147 miss / 0 hits pre-fix). No request storm.
- BUT node11 ledger diverges durably (restart does NOT heal):
  faucet nonce **28 vs 25** on the majority; faucet balance reflects ~16
  sends vs 24; wallets +/- hundreds of billions.
- Totals: 10043 vs 10053 (-10); the gap never backfills.

### Refined mechanism (supplements INC-C2-003)

node11 holds faucet conflict-LOSERS (nonces 26-28) the 9-node majority
pruned, while missing ~13 winners. Coherent story:
1. C2 faucet bursts (pre-serialization) minted same-nonce siblings;
   smallest-id-wins pruned losers on nodes that saw both.
2. Store-backed GetData can serve a loser still present in some peer s
   sled (prune/purge lag), so a syncing node ingests losers.
3. The corresponding winners never arrive (same -10 tail pattern as
   node10: suspected is_orphan/seen interaction), so node11 never
   re-resolves; nonce slots advance past phantom transfers.
4. Restart cannot heal: DAG lacks winners, ledger trusts nonce slots.

### Next-branch work (NOT this canary)

1. Synchronous purge-on-prune: store must never serve pruned losers.
2. Diagnose why fetched-missing winners stall (is_orphan dedup vs
   requested_parents vs seen-cache on the -10 tail).
3. STEP-1c redesign: applied-tx tracking instead of nonce-only guard.

## INFRA-20260910: Defender false positive kills canary (Bearfoos.A!ml)

**Date:** 2026-09-10 (discovered at canary restart)
**Type:** INFRASTRUCTURE (antivirus) — NOT protocol, NOT wallet
**Severity:** HIGH (kills running nodes + deletes binary)

### Facts

- Windows Defender flagged `target/release/aether-unified.exe` as
  `Trojan:Win32/Bearfoos.A!ml` (ML heuristic) and REMOVED the file +
  killed 3 running node processes (pids logged in Defender history).
- Rust+P2P+crypto+PoW loops are classic Bearfoos.ml triggers; the
  verdict is a false positive by construction (our own source, built
  locally, SHA-pinned).
- Explains prior silent mass deaths (no logs, no trace — the killer
  was outside the processes).

### Resolution

- Operator added Defender exclusions (workspace dirs + process names).
- Rebuilt from clean tree, relaunched 9/9, gate ALL PASS.
- No code change required. Lesson recorded: any future "silent mass
  death" checks Defender history FIRST (before protocol hypotheses).

### Status

**RESOLVED (environment).** Revisit if re-detected after exclusion.

## OBS-20260910: node_logging tail slice panicked on emoji (exit 101)

**Date:** 2026-09-10 (found during canary restart with logging build)
**Type:** OBSERVABILITY BUG (own code, `node_logging.rs`) — NOT protocol
**Severity:** HIGH (bricked every restart once logs exceeded 8 KB)

### Facts

- `previous_shutdown_clean` sliced `content[len-8192..]` on a BYTE
  index; node logs are full of multi-byte emoji -> slice landed
  mid-glyph -> Rust panic (`not a char boundary`) -> exit 101 BEFORE
  any log line. Production proof stronger than any unit test.
- Observed: 4 nodes dead on relaunch, zero log output, exit code 101
  captured via foreground run.

### Fix

- Floor both slice indices to char boundaries (`is_char_boundary`
  loop) + regression test `test_previous_shutdown_emoji_boundary`
  (misaligned multi-byte filler, live + rotated + marked cases).
- Rebuilt, relaunched 9/9 @10081, restarts clean, toolchain + E2E green.

### Status

**RESOLVED (verified live).**
