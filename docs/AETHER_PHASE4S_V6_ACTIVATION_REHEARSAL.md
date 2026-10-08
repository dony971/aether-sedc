# AETHER PHASE 4S -- V6 ACTIVATION REHEARSAL

- Status: REHEARSAL ONLY. Simulated boundary SIM_TS = 1_700_000_000_000 used in temp tests; real V6_ACTIVATION_TS = 1_893_456_000_000 UNCHANGED (verified: zero diff on transaction.rs and every consensus file). No activation executed, no values chosen, no release published, no network launched. Temp scenarios (11) run green then deleted; mod.rs restored.
- Baseline: HEAD a4e21a7. Preexisting untracked preserved (never git add .).
- ASCII pure, CRLF.

## 1. Objective

Rehearse V6 activation end to end: parameters plannable, nodes preparable, anchors preparable, transition deterministic, no premature activation, operational rollback defined, runbooks complete -- all without activating anything.

## 2. Current State

4R granted bounded readiness-to-schedule (YES): 145+ targeted green then, anchor enforced at boot (4Q), WS bounded residual, release dossier defined. Since then: no production change except none (4R committed nothing). Rehearsal inputs: SIM_TS label only (code always consulted the real const).

## 3. Activation Inputs

Placeholders, owners, no values: ACTIVATION_TS (governance, 4F constraints), V6_RELEASE tag (release management), INITIAL_ANCHOR bundle (checkpoint tooling + quorum operators), INITIAL_VALIDATOR_SET (staking governance), INITIAL_STAKE_STATE (derived by replay, not declared), release hash/bundle procedure (release management), bootstrap runbook (this phase). Nothing invented.

## 4. Simulation

Temp harness s01-s11 (deleted after green, 11/11 in 0.20s): boundary matrix on the REAL const (T-2..T+2 classification + era-admission with explicit now, no wall clock), transition determinism (pre-key legacy delegation + post-key finalized resolution, evaluated twice), two-group same-binary behavior, simulated anchor build/verify, fake-anchor matrix, multisource pair, network joiner, partition-at-activation, restart-at-boundary (3 pairs + save/load), clock matrix, rollback dry-run. SIM_TS appears only as a label distinguishing rehearsal narrative from the real const (asserted unequal).

## 5. Transition

BEFORE (all ts < const): V5 everywhere on both groups. AT BORDER (== const): deterministic flip by timestamp (predicate >=). AFTER: V6 rules for post data. T-2/T-1/T/T+1/T+2 legs green for tx/vote/bond admission shapes (era predicate + admission matrix), finality on post keys, sync/restart/rebuild determinism inherited from rerun suites (4i inside 4g-run window below). No premature activation observed: pre-ts objects classify legacy even when evaluated after wall-clock passes (predicate reads DATA timestamps, s10).

## 6. Anchor

Simulated INITIAL_ANCHOR built via the real build_anchor over test sets: canonical encoding deterministic, signatures verified, epoch/set/denominator/tag checks green (s04); tamper matrix refused (s05: epoch/root/total/signature arms). New node -> anchor -> sync -> validation -> same finality (s07: winner + weight identical, restart+rebuild preserve). Fake anchors never pass (s05/s06).

## 7. Validator Set

Set of 4-6 bonded validators per scenario; root recomputed and compared at anchor epoch; mismatched sets refuse (s05/s06 patterns). Set-change leg: old anchor still verifies as history after unbonds (s09 scenario 7 in 4R temp, inherited). No auto-compat invented for pre-4G binaries (documented loud-split behavior, h11 standalone proof cited).

## 8. Partition

Split just before simulated activation: both sides V5 (predicate on pre data). Post data split X|Y with disjoint voters, reconnect both orders: identical (3000,3000) support, no premature activation (classification timestamp-driven, unaffected by topology), no double finality (single key, single quorum evaluation), convergence by merge determinism, same set/epoch throughout (s08). Real-partition machinery (P2P heal, backfill) covered by h06/p1 inherited.

## 9. Restart

Shutdown at T-1/boot at T, T/T+1, T+1/T+2: boundary table exact (false,true,true,true), registry save/load byte-identical across each pair (s09), same deterministic rule after reboot (resolve re-evaluated identically). No rule flip-flop across restarts.

## 10. Clock

Local-clock users mapped: validation.rs Fresh-mode staleness bounds (3 call sites + tests, all explicit-now in tests), stake::current_epoch() SYSTEM-EDGE-ONLY (node/RPC pass explicit epochs into consensus fns). Risks: wrong local clock shifts Fresh admission bounds (documented existing behavior, unchanged); CANNOT reclassify data timestamps (predicate reads tx timestamps, s10 asserts), CANNOT move activation (const), CANNOT disturb Historical era-gate (pure function of (tx_ts, now) pair, matrix green). Drift/old/future timestamps behave per existing validation rules (cited suites). No rule changed in this phase. CLOCK = PASS with the documented Fresh-bound proviso (RESIDUAL only in the sense that operator NTP hygiene stays required; recorded in runbook sec.1).

## 11. Rollback

Theoretical runbook (runbook doc sec.13): unwanted/ anomalous activation -> SOFTWARE rollback (previous binary; V5 history intact), DEPLOYMENT rollback (halt pre-timestamp = nothing happened, proven trivially by s11 frozen pre-activation outcomes), CONSENSUS rollback of finalized history DECLARED IMPOSSIBLE (never un-finalize; forward resolution only). Drill executed as s11 (pre-activation frozen across evaluations). ROLLBACK_RUNBOOK = COMPLETE (theoretical, never executed live).

## 12. Monitoring

Metrics defined (runbook sec.11: epoch, V6 flag, counts/stakes, quorum, finality latency, conflicts, anchor failures, sync/orphan health, equivocation/slash, propagation, restart/rebuild failures, supply bounds). No new monitoring system implemented (existing logs + sync_stats + RPC cover all; sole new watch item = anchor boot-boundary log line). MONITORING = COMPLETE as definition.

## 13. Blocking Alerts

Complete list (runbook + verdict): invalid anchor, incoherent set/denominator/quorum, finality divergence, LIVE/SYNC/REBUILD divergence, V5/V6 mismatch, premature V6 activity, PoW in V6 paths, ledger divergence, slash-state divergence, restart/rebuild failures, sync stall. Each maps to an existing or 4P/4Q-testable check; none fired during rehearsal (11/11 + rerun suites green).

## 14. Testnet

Binaries: tagged V6 build (to be cut, not cut here). Version: single binary for both groups (data decides behavior; pre-4G nodes out of scope with documented loud split). Network/nodes/keys: testnet governance (placeholders). Anchor/set/snapshot: generated at flag-day per runbook sec.3-5. Rollback: sec.11/13 here. No network launched (rehearsal only).

## 15. Performance

Reused measured costs (no heavy re-run needed for integration questions): 100/1000/10000 support+finalize from 4L/4P (7x at 10k post-B+G), anchor verify 41ms/4 and 1.02s/100 (4P), bootstrap hook ~64ms/6 votes (4Q), file-absent path trivial. Activation adds no per-object cost (predicate O(1) timestamp compare); anchor verification is per-checkpoint (amortized). No new bottleneck introduced by rehearsal (zero production change).

## 16. Release Artifacts

To be produced at real release (NOT produced here): binary + hashes, docs (this set), activation configuration (ACTIVATION_TS), anchor bundle + validator set + checksums, runbook filled with values, release notes. COMPLETE as a list with owners; INCOMPLETE as artifacts by design (no real release).

## 17. Runbook

docs/AETHER_V6_TESTNET_ACTIVATION_RUNBOOK.md created with all 14 charter items (prereqs, pre-checks, distribution, anchor/set/stake/node verification, pre/at/post-activation, monitoring, incident response, operational rollback, final validation). Values are placeholders with owners; no live values invented.

## 18. Risks

Rehearsal-scope risks: (1) simulated boundary is narrative-only (real const behavior proven separately by s01 on the const itself); (2) single-binary groups (pre-4G incompatibility cited, not executed); (3) clock hygiene stays operator duty; (4) heavy suites PARTIAL (unchanged labels); (5) activation values still governance-open (by design). No new risk discovered; no finding opened.

## 19. Governance Inputs

Required decisions before any real flag-day: ACTIVATION_TS date (+announcement+grace per 4F), initial validator set + stake schedule, anchor generation ceremony (who runs tooling, who cross-checks bytes), release hash/bundle channel decision, testnet node/key roster, monitoring ownership, incident commander. All listed with constraints; none preempted here.

## 20. Final Readiness

Rehearsal confirms the 4R YES: parameters plannable (sec.3 placeholders+owners), nodes preparable (runbook), anchors preparable (proven built+verified), transition deterministic (sec.5/8/9), no premature activation (predicate + s10), rollback defined (sec.11, theoretical), runbooks complete (sec.17). V6_DORMANT stays PASS (const and behavior verified unchanged at close). Activation remains a future governed act, explicitly not executed.
