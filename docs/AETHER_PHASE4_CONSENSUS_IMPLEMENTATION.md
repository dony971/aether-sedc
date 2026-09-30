# AETHER PHASE 4B — CONSENSUS IMPLEMENTATION (CDW, as built)

- **Status**: implemented on `dev/phase2-decentralized-network`, unreleased.
  Design authority: `AETHER_PHASE4_CONSENSUS_WEIGHT_DESIGN.md` (PRIMARY =
  Cumulative Descendant Work + min-id tiebreak + loser retention with
  re-resolution). This document records WHAT WAS BUILT, including deliberate
  deviations from the sketch (each justified).
- **Rule change summary**: conflict winner selection changed from min-id to
  CDW + min-id tiebreak (grandfathered); conflicting pairs coexist (loser
  retention); ledgers apply winners only; re-resolution fires on member
  arrival and on conflict-descendant arrival. Nothing else in consensus
  changed (validation except the conflict admission, mempool, fees, orphans,
  sync, P2P framing all intact).

## 1. New rule (exact)

For a conflict key K = (sender, account_nonce) with resident members M (|M| >= 2):
- If EVERY member has timestamp < CDW_ACTIVATION_TS (1_758_000_000_000,
  `Transaction::CDW_ACTIVATION_TS`, shared era with the difficulty migration,
  separate policy): winner = min id (frozen legacy rule).
- Else: winner = argmax subtree_work (ties -> min id).
- |M| < 2: no conflict (sole member wins trivially).

subtree_work(X) = sum of work_credit over the UNIQUE descendant closure of X
(self included), saturating u64 addition. work_credit(t) =
2^(leading zero bits of t's PoW hash), saturating at u64::MAX (n >= 64).
All integer-only, deterministic, recomputable from stored fields.

## 2. Formula (exact code references)

- `Transaction::leading_zero_bits(&hash) -> u32` (`transaction.rs`): byte
  walk + `u8::leading_zeros`, pure.
- `Transaction::credit_for_bits(n: u32) -> u64`: `1u64.checked_shl(n)`
  saturating to `u64::MAX`. Vectors pinned: 0->1, 20->2^20, 24->2^24,
  63->2^63, 64/65/255->MAX (never wraps).
- `Transaction::work_credit(&self) -> u64`: composes the two over
  `calculate_pow_hash(self.nonce)`. Never touches validation.
- `DAG::subtree_work(root) -> u64` (`parent_selection.rs`): BFS with visited
  set (diamond-safe uniqueness), saturating sum. Traversal order irrelevant
  (addition commutes).
- `DAG::resolve_conflict_key(sender, nonce) -> Option<id>`: grandfather
  check, then explicit sort by (work DESC, id ASC). Never reads index,
  insertion, HashMap, or arrival order for the decision.
- `DAG::affected_conflict_keys(parents) -> sorted Vec<key>`: ancestor walk
  collecting keys with >= 2 members (single-member keys cannot flip).
- `TransactionProcessor::conflict_winners_for(dag, keys)`: per-key winners
  (trivial singletons included), used for pre/post flip comparison.

## 3. Actual-bits credits

Per §2. Chosen over difficulty-class units (design §14 open question, closed
here): exact expected-cost pricing, rewards over-mining, no oracle, no new
constants, always recomputable (no store migration). Denomination-free: a
20-bit and a 24-bit proof price exactly their expected hashes (the H1xH2
compound priced — sim table in design §13: paths converge with depth).

## 4. Cumulative descendant work

Per §2. Descendant coverage rule (design §8): a member's score counts UNIQUE
descendant work only; count alone scores nothing (volume without work is
free — the inflation answer, tested). Shared descendants counted once
(visited set; diamond test pins exact sums).

## 5. Tie-break

min-id among max-work members, explicit sort (never positional). Exact ties
are common (childless same-difficulty pairs) — the tiebreak decides them
deterministically. Pinned by `test_min_id_only_tie_break` (forced tie via
credit search) and by grandfathered pairs (min-id path).

## 6. Loser retention + RETENTION_RULE + PRUNING_RULE

- RETENTION_RULE: every validated conflict member is a permanent DAG
  resident (inserted win or lose, stored, gossiped, synced). No conflict
  member is ever pruned, purged, or rejected for conflicting. Uniqueness
  invariant dropped at admission; enforced at ledger-application instead.
- PRUNING_RULE: `prune_subtree` is NEVER called for conflicts anymore
  (kept as a tested primitive for explicit use + unit tests). Nothing new is
  deleted anywhere: the only deletions in the tree remain the pre-existing
  non-conflict paths (none in production). Retention growth is the same cost
  class as baseline DAG spam (each retained tx cost its author a valid
  PoW+signature+fee) — no new unbounded-growth class introduced.
- Rationale (design §9 trap, restated): destructive + view-dependent
  decisions diverge permanently on arrival order (worked example); destructive
  + static (old min-id) converged; dynamic + retentive converges via set
  convergence. Retention is load-bearing, not optional.

## 7. Re-resolution

Triggers (all deterministic; timing affects WHEN local ledgers flip, never
ultimate convergence — same transient class as partitions):
- T1 member arrival (STEP 0 conflict path): recompute own key + ancestor
  keys pre/post insert; rebuild iff any winner flipped.
- T2 conflict-descendant arrival (normal path STEP 6b): ancestor walk +
  pre/post compare (pre computed at STEP 1c under read locks); rebuild iff
  flipped. No-flip path keeps STEP-4 live state (rebuild-equivalent by the
  base live~=rebuild trust).
- T3 boot / deep-sync completion: full rebuild recomputes ALL keys (no
  memoized winners anywhere — recompute-pure by design, zero staleness
  vectors). No periodic task (insert-cover is complete; no production
  removals exist to miss).
- Rebuilds are full `rebuild_from_dag` (correctness first; O(DAG) per flip,
  measured ~32 ms at 2k DAG debug). Flip frequency is economically bounded
  (each flip needs fresh descendant work — attacker pays per flip-fuel).

## 8. Activation + grandfathering

- `CDW_ACTIVATION_TS = 1_758_000_000_000` (code constant, documented).
  Predicate per conflict: newest member ts >= activation -> CDW;
  all members strictly below -> min-id (frozen). Boundary (== activation)
  counts post-activation (tested).
- Effect: all 1970-era fixtures resolve exactly as before (all green suites
  pass unmodified on winner selection); all live-network traffic (2026 wall
  clock) resolves CDW. Grandfathering preserved every old test that does not
  assert rejection/absence.
- P2P_PROTOCOL_VERSION 4 -> 5 (rule negotiation; existing handshake gate
  splits mixed networks loudly). Same bytes on the wire; no store migration
  (scores recomputable); genesis untouched.

## 9. Tests (module phase4_consensus_weight_tests + migrated)

New (18): work_credit vectors/composition; cumulative exact sums (+stale 0);
monotonicity; no_free_weight (garbage < 2^20 + real 20-bit mine >= 2^20);
min-id-only tiebreak (forced tie); weight-beats-min-id (larger id wins);
live order invariance (2x24-bit mines, both orders, DAG+winner+ledger equal);
loser retention; loser re-resolution (staged flips + ledger follows);
partition reconvergence (both merge orders); restart weights/scores/ledger;
deep-sync reconstruction; grandfathering (heavy descendants, min-id wins);
post-activation rule (work wins); activation boundary (== vs -1);
overflow (u64 edges + 1000-tx exact sum); old-vs-new divergence (same DAG,
different winners by rule — the specified break, proven intended).
Migrated (intended divergences, each rationale in situ): security
conflict-retained + replay-split (exact replay still rejected), malicious
contradictory (retained + grandfathered winner), order_invariance (retention
sets), step0 mode-consistency (retention sets), purge->retains-everywhere
(rename, honest), index-matches-scan (retention semantics).
Untouched-and-green: canonical (frozen helper), crash merge (pre-activation
fixtures), H3/H4 precision, validation timestamp sets, sims, harnesses.

## 10. Performance (measured, debug unless noted)

- Score compute: O(subtree) HashMap scale (phase4 suite: 17 tests green —
  16 debug FAST/MEDIUM in ~35 s total incl. one 20-bit mine, plus the live
  order-invariance test ~75 s debug for 2x24-bit mines / ~10 s release).
- Trigger walks: O(ancestors) per insert (same class as existing weight
  walks; no measurable regression — full suites wall-stable vs baselines).
- Trigger: O(ancestors) per insert (same class as existing weight walks).
- Rebuild-on-flip: H3 base ~32 ms at 2k DAG (unchanged code path).
- Retention memory: conflict rows only (same order as DAG growth; no tombstones).
- Restart/deep-sync: unchanged shapes + resolve calls (measured via inc01/migration greens).
- Live order-invariance: ~75 s debug (2x24-bit mines) / ~10 s release.
- Incremental-computation note: no memoized winners/scores by design (purity
  over caching); batch-suppression during sync identified as future work (not
  implemented — correctness first).

## 11. Limitations (honest)

- d=0 conflicts: CDW not stronger than min-id (granularity favors small
  units) — moat materializes with confirmations (stated plainly).
- Threshold-free: no finality gadget (same as before, now priced).
- Retention growth under sustained conflicting load: same class as spam;
  work-margin deletion policy deferred (documented trigger).
- Fee markets, GPU translation, light clients: out of scope (unchanged).
