# VPS SYNC ARCHITECTURE — Ancestor-Closed Fetching

**Scope:** sync/fetching strategy ONLY. No consensus, DAG semantics,
weight, min-id, pruning, ledger rules, finality, genesis, emission or
economy change. All validation/acceptance paths untouched.

---

## 1. Problem (measured)

Deep-history bootstrap over real links: **~8 txs / 40 min** for a 10k
DAG (VPS over WebGate/WAN). Same binary over loopback: ~1000 txs /
5 min. Transport exonerated; strategy indicted.

Mechanism: the requester asked for RANDOM 1000-subsets (inventory
order = HashMap iteration), the server returned topo-sorted sub-pages
whose ancestors lived outside the page. Every page parked as orphans;
orphans resolve only against DAG-resident parents; DAG parents arrive
only by chance (genesis-rooted chains complete by luck). Fixpoint +
parent re-requests (128/cycle, backoff) crawled level by level:
110k requests for 6 resolutions. Positive feedback into a request
storm (179k requested, 117k duplicates ignored).

## 2. Sync frontier (explicit)

Per node, maintained live:

```text
KNOWN (DAG ∪ store ∪ parked orphans)
  → REQUESTED (GetData sent, backoff-tracked)
  → RECEIVED (SyncResponse, partitioned deliverable/waiting)
  → PARENTS COMPLETE (fixpoint: all parents in DAG)
  → APPLICABLE (full validation pipeline)
  → INTEGRATED (DAG insert + ledger apply)
```

Monotone metric (§6): `sync_frontier` = max DAG total observed on the
P2P path (max-update, monotone BY CONSTRUCTION), plus existing
`sync_progress` (P2P successes) and DAG `total_transactions` (state).
A flat frontier with pending orphans/requests = stall evidence
(watchdog rule).

## 3. Ancestor-closed fetching (the fix)

**Server side** (`P2PMessage::GetData` handler, `p2p.rs`): for each
requested hash (≤ PAGE_SIZE=100), walk up its ancestor chain through
the LOCAL DAG and append missing ancestors, bounded scoreboard:

- `ANCESTOR_BUDGET = 400` extra txs max per response (~250 KB worst case)
- `ANCESTOR_STEPS = 20_000` defensive walk cap (+ visited set: cycle-proof)
- DAG-resident only (unknown parents stay the requester's next frontier)
- genesis `[0;32]` parents terminate
- result re-sorted parents-first via the CACHED topo order (C2-004)

Every served page is then SELF-SUFFICIENT: the receiver's existing
`partition_batch` in-batch chaining inserts the whole page bottom-up.

Unchanged: message types, validation gates, accept pipeline, conflict
resolution, prune rules, ledger application, fee handling. A receiver
on old code still converges (slower) — wire-compatible.

## 4. Inventory → diff → GetData → validate → integrate → frontier

Unchanged flow, new guarantees per step:

- INVENTORY: full hash list (unchanged).
- Diff local: DAG ∪ orphans ∪ seen (unchanged, B4 dedup kept).
- GETDATA: ≤1000 requested (unchanged cap).
- Serving: requested + ≤400 ancestors, parents-first (NEW).
- Validation: pure gate → orphan gate → STEP-1c precise rule → ledger
  gate (all unchanged).
- Integration: DAG insert + applied-mark (P3, unchanged).
- Frontier: `sync_frontier` max-update on P2P success (NEW counter).

## 5. Orphan handling (unchanged, now effective)

Parked orphans + fixpoint (64 passes) + TTL purge + escalating-backoff
re-requests (128/cycle) all unchanged. What changed is their INPUT:
with self-sufficient pages, the fixpoint resolves instead of spinning,
and re-request volume decays as the DAG fills (observed locally:
1549 created / 1549 resolved during a 10k join).

## 6. Store-first (unchanged, INC-01)

`get_transaction_by_hash`: DAG memory → sled store → None. Ancestor
walks use the same lookup (store-backed ancestors included when the
serving node holds them persisted but not in memory).

## 7. Progression guarantee

Each served page inserts ≥1 new DAG tx whenever the requester lacks
anything the server has within budget (the page always contains at
least the requested-resident txs AND their closure is attempted first).
DAG total is non-decreasing across pages except canonical conflict
prunes (logged, deterministic, convergent). No infinite loop: every
loop in the path is bounded (PAGE_SIZE, ANCESTOR_BUDGET/STEPS,
fixpoint passes, backoff, TTL, seen-dedup).

## 8. Retry / backoff (unchanged)

Parent re-requests: dedup + 2/5/15 s escalating backoff + 4096
inflight cap + 128/cycle. Proven sufficient once pages are
self-sufficient (no storm observed post-fix locally).

## 9. Resume after interruption

All sync state is reconstructible: DAG+store persist inserted txs;
orphans persist (sled orphan tree); requested_parents backoff is
in-memory only (rebuilt on demand — a restart re-requests, bounded by
the same caps). A join interrupted at 50% resumes, never restarts
(except prune-driven rebuilds, which are deterministic).
