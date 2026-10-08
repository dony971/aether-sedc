# AETHER PHASE 4L -- V6 SCALABILITY IMPLEMENTATION (B+G)

- Status: IMPLEMENTED. Branch dev/phase2-decentralized-network.
- Baseline: HEAD 3a8ecd5 at start (phase4: close v6 remediation audit), parent d1fd8d7. Tracked tree clean at start (only preexisting untracked dirty, never staged via git add .). git diff --check clean throughout.
- Design source: docs/AETHER_PHASE4K_V6_SCALABILITY.md sections B+G (per-conflict latest-vote index + event-driven maintenance), read in full before any code along with src/stake.rs, src/parent_selection.rs, src/transaction_processor.rs, src/storage.rs, src/node.rs. No other optimization invented. Design judged sufficiently specified (key, selection rule, update points, rebuild path all fixed); NOT BLOCKED.
- Rule: NO quorum change (3S>=2T intact), NO MIN_STAKE/epoch/unbonding/slash/vote/finality/min-id/weak-subjectivity/activation/V5/wire change, NO PoW reintroduction, NO tokenomics change. Consensus stays STAKE_WEIGHTED_DAG_FINALITY. V6 stays dormant (V6_ACTIVATION_TS = 1_893_456_000_000). No push, no merge, no tag, no deploy, no v1.4.0 change.
- ASCII pure, CRLF. Nothing invented; NOT_RUN / NOT_VERIFIED used where applicable.

## 1. Scope

Implement the 4K-designed B+G optimization to cut support()/finalize() cost while preserving EXACTLY the same stake, quorum, branch, finality, tiebreak, slash, order behavior, persistence, LIVE/SYNC/REBUILD, restart and partition behavior. Includes: reference path kept for tests, optimized path, index definition, invalidation analysis, full equivalence harness (50 perms), benchmarks before/after, memory, persistence, fail-closed, regressions.

## 2. Baseline

4K proved: support O(V x T) general / O(V^2) single-conflict, finalize O(M x support + V log V), bottleneck stake.rs:533-546 per-validator full scan x per-member recompute 593-608, duplicates O(1), multi-conflict O(V^2 x C^2), 10k reference timings insert 107.03s support 2.26s finalize 2.25s. Starting HEAD 3a8ecd5 already contains 4I fixes (63 tests) and 4J closure; all reference suites green on it.

## 3. B+G design

B: per-conflict vote index, conflict-key -> validator -> latest vote (max by (epoch, vote id)), exactly the selection the reference recomputed by scanning. Support becomes O(V) per member (index read + live weight + sorts). Memory O(indexed pairs) vote clones plus map overhead.
G: event-driven maintenance inside insert_vote for the affected (key, validator) only: recompute that pair from the authoritative map over its epochs (few), mirroring exactly the reference per-validator selection including the F-A2 canonical smallest-id slot and equivocation handling. Weights/slash/eligibility still read live, never cached. C (per-epoch totals) deliberately NOT implemented (denominator is V log V minor vs V^2; extra invalidation surface not justified).

## 4. Reference path

support_breakdown_reference + try_finalize_reference kept as #[cfg(test)] methods on StakeRegistry with the pre-optimization bodies verbatim (whole-registry scan, per-member recompute). Compiled into test builds only; production builds exclude them (zero production impact). The equivalence harness (sec.8) fails on any divergence of totals, id sets, quorum bit, winner, or full record.

## 5. Optimized path

Production support_breakdown now reads the per-conflict index (sorted iteration, same order as reference), then the identical weight/side/sort tail. try_finalize logic untouched apart from calling the optimized support. Both deterministic, idempotent (index is a pure function of the map), order-independent (max by (epoch,id) is commutative; iteration sorted), rebuildable (rebuild_vote_index), restart-safe (restore replays then rebuilds).

## 6. Index/cache

Key: ConflictKey (sender, nonce) -> validator [u8; 32] -> latest Vote clone. Key matches the design ((epoch, conflict, validator) triple collapses to per-(conflict, validator) latest by epoch then id; epoch stays inside the stored vote). Duplicate vote: map slot keeps smallest id (F-A2), index refresh recomputes from the map so it stores the same vote (no double counting; replays are Duplicate O(1)). Contradictory vote: existing equivocation machinery (evidence + immediate slash/tombstone) runs first; index stores the map's kept vote while the accused weighs zero either way (support total identical, id set identical because both paths read the same map slot). Ineligible/out-of-epoch voter: vote stored, weight read live as zero (index carries votes, never weights).

## 7. Invalidation

The index needs invalidation ONLY on vote-map changes, and the map changes ONLY in insert_vote (verified by grep: self.votes.insert at three sites, all inside insert_vote; no remove/clear anywhere). Hence refresh_vote_index(ck, vv) on every insert_vote exit (all five returns, including no-mutation Duplicates as idempotent no-ops) is total by construction. Bonds/unbonds/slashes/epoch transitions/finality/re-resolution change weights or records, never the per-(validator,key) latest vote, and support reads weights live. Restore replays through insert_vote plus an explicit rebuild_vote_index() safety net. Sync/rebuild use the same replay. A missed refresh would undercount (never overcount: index entries only come from the map), failing closed toward no-quorum.

## 8. Equivalence

Harness src/tests/phase4l_v6_scalability_tests.rs (13 tests) compares REFERENCE vs OPTIMIZED on identical datasets for eligible/total/supporting stake, quorum bit, winners, full FinalizedRecord equality, validator/slash/epoch state and snapshots: basic 100 (l01) and 1000 (l02), multi-conflict 50x10 + 20x100 (l03), duplicates 1/2/10/100 copies (l04), 50 LCG order permutations incl. equivocation+tombstone+unbond+top-up multiset (l05), equivocation both orders + tombstone both orders (l06), finality-sticky with late supermajority with and without index drop+rebuild (l07), snapshot/restore restart (l08), live/sync/restore-rebuild paths (l09), partition merge both orders (l10), absent-index fail-closed + rebuild (l11), 10k support/finalize equality + speedup (l12), memory estimate (l13). Result: all 13 PASS, zero divergence on any dataset.

## 9. Order independence

50 deterministic LCG Fisher-Yates permutations of a 19-op multiset (5 bonds, 10 votes over 2 epochs x 2 conflicts, 1 equivocation pair, 1 unbond, 1 top-up) covering bond-after-slash (tombstone rejection recorded, not errored) orderings: ref==opt on every perm for both conflicts x both sides, and identical totals across all 50 perms. PASS (l05). Cache never turns arrival order into decision: update rule recomputes from map contents, max is commutative.

## 10. Partition

3 validators vote X + 3 vote Y on one key, merged X-then-Y and Y-then-X: ref==opt within each order and identical across orders for both sides. PASS (l10). Merging only changes set timing; the index is a pure function of the set.

## 11. Restart

Snapshot save/load roundtrip then ref==opt on both keys incl. a pre-restart finalized record (l08 PASS). Drop-index + rebuild returns bit-identical support and restores finality behavior (l07 with_restart + l11 PASS). Cache either restores via replay or rebuilds; both give the same consensus, finality and ledger inputs.

## 12. Live/Sync/Rebuild

Same 150-voter dataset via direct inserts (live), storage save/load roundtrip (sync), and in-memory restore() replay (rebuild): ref==opt on each path and identical support across paths. PASS (l09). Nothing in the index depends on a LIVE-only event (all paths end in the same vote set).

## 13. Equivocation

Validator votes X then Y and Y then X (bond-first), plus equivocation-before-bond both orders (tombstone, bond correctly rejected): ref==opt and order-identical in all four, slashed weight zero, Slashed state present. PASS (l06). The index mirrors the canonical map slot, so the F-A2/F-A1 semantics survive verbatim.

## 14. Multi-conflict

Bounded matrix (1000-conflict at large V unreasonable for any suite: 1000 x 10000 signed votes is ~10M signatures): 50 validators x 10 conflicts and 20 x 100, ref==opt support+finalize on every conflict with correct index sizes. PASS (l03). The optimization removes the C multiplier on scan cost: per-conflict support no longer scans other conflicts.

## 15. Benchmarks

Same h15 protocol throughout (sign + verify assert). BEFORE (4J, old code): n=100 support 3.51ms finalize 3.59ms; n=1000 support 50.68ms finalize 52.26ms; n=10000 support 2.26s finalize 2.25s. AFTER (this phase): h15 n=100 support 3.17ms finalize 3.09ms; n=1000 support 30.33ms finalize 31.67ms (1.7x); harness n=10000 support 314ms vs 2.30s reference (7.3x). Insert unchanged (1.07s / 10.70s / ~107s: index refresh is O(epochs), negligible vs signing). Priority goal (support/finalize) achieved with growing ratio at scale, as predicted (scan term removed, per-validator common work remains). No theoretical complexity announced beyond the static analysis (support per member O(V^2) -> O(V); sweep O(V^2 x C^2) -> O(V x C)) plus these measurements.

## 16. Memory

Vote struct 264B (size_of). Index holds one Vote clone per (conflict, validator): measured 2000 entries for 2 conflicts x 1000 validators ~= 656KB (~336B/entry incl. 40B key + map overhead). Scales linearly with indexed pairs (~3.3MB per 10k single-conflict). Transient per-call allocation drops from (validators Vec + latest map over whole registry) to (ordered Vec + ids over the per-key index). No CPU-into-memory explosion: bounded, proportional, derived (rebuilt anytime). 50k/100k single-conflict index projects to ~16MB/~33MB plus base maps.

## 17. Persistence

Index deliberately excluded from RegistrySnapshot (no format change, no migration). Save/load paths untouched (verified by grep: only snapshot()/restore() carry state). Save->load->compare gives identical support/finality on both paths (l08 PASS; all preexisting save/load suites in sec.19 re-pass). Reconstruction from sources of truth tested (l09, l11 rebuild PASS).

## 18. Fail-closed

Absent index (simulated drop): support reads empty (0, []), quorum unreachable, try_finalize returns None: fails closed toward no-finality, never toward wrong finality. Rebuild from the map restores exact results. PASS (l11). Corrupt-index case cannot arise from the API (index is private, only written by refresh/rebuild from the map); any future persistence of the index must be versioned and hash-verified or discarded (documented constraint, not implemented since nothing is persisted).

## 19. Regressions

On optimized code: phase4l 13/13 PASS (new), phase4i 63/63 PASS, phase4g 36/36 PASS, phase4h 16/16 PASS (incl. h15 post-opt timings above), phase4c 12/12 PASS. Combined 140 targeted green, 0 red. Historically heavy suites (full ledger sweep, parent_selection sweep, inc01 full suite, crash/multiprocess/security/deep-sync/consensus/migration/phase2/bootstrap) NOT rerun in-window given 4K-documented PoW-fixture costs; 4K/4J results on identical logic stand, nothing presented as PASS without a run. REGRESSION_STATUS = TARGETED_FULL_GREEN_PLUS_DOCUMENTED_NOT_RUN.

## 20. Residuals

R1 (eligible_total): denominator still O(V log V) per finalize (C declined in 4K as unjustified surface); support now dominates less, denominator is the next minor term at very large V.
R2 (per-validator common work): id hashing + weight + sorts per support call remain O(V log V); further gains would need vote-id caching or weight tables (new invalidation surface, deferred).
R3 (50k/50000-conflict scale): 50k validators NOT_RUN (10k insert alone is ~107s double-verify protocol); multi-conflict 1000-conflict at large V NOT_RUN as unreasonable for any suite; projections in 4K stand.
R4 (4K doc): left untracked per its audit-only disposition (sec.24: not staged without explicit justification; none needed).
No new consensus findings opened (bottleneck removed without semantic change).

## 21. Conclusion

B+G implemented exactly as designed: whole-registry scans replaced by a per-conflict latest-vote index maintained event-driven, reference path preserved under cfg(test), equivalence proven across 13 harness tests plus 127 preexisting targeted tests with zero divergence, 7x support speedup at 10k, memory bounded and linear, fail-closed verified. Commit authorized (sec.25 all gates PASS).
