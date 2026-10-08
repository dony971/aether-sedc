# AETHER PHASE 4Q -- V6 ANCHOR INTEGRATION (bootstrap/sync/new node)

- Status: IMPLEMENTED as dormant infrastructure. No consensus rule moved: zero diff on stake/validation/processor/p2p/rpc/node-consensus/ledger/storage/transaction/genesis (verified via git status on each file). Additive code only: anchor bundle + bootstrap hook + state cross-check + bundle comparison (src/anchor.rs), one boot call site (src/node.rs), one mod line, new tests. V6 dormant, V5 unchanged, no push/merge/tag/deploy/activation.
- Baseline: HEAD 72aacb9 at start; preexisting untracked left alone (never git add .).
- Design sources: 4O (anchor fields/bindings), 4P (verifier semantics), 4N (sourcing rule, EXPECTED_FAIL), 4M (joiner expectations), 4G (gossip/receiver paths), 4F (sourcing discipline). Nothing invented beyond explicit format choices documented in sec.3/14.
- ASCII pure, CRLF.

## 1. Scope

Give the 4P pure verifier a real production role without waking V6: an operator-supplied anchor file verified at node boot (fail-closed), plus a synced-state cross-check for joiners, plus byte-exact multi-source comparison (detection only). Covers new-node with/without/fake anchor, cross-epoch/set, denominator, multi-source contradiction, sync/rebuild/restart/persistence legs, dormant + no-PoW proofs, and an end-to-end joiner test. State binding stays RESERVED (no new primitive, per 4O/4P).

## 2. Production paths

Real paths mapped in src/node.rs run_node (1055-line boot, single entry):
A. new-node start: data_dir ensure -> Sled open -> ledger load -> DAG rebuild from Sled (+JSON legacy) -> stake registry load (fail-closed on manifest mismatch) -> era-aware ledger rebuild -> receivers/P2P/RPC spawn. CURRENT: no anchor role. DESIRED: verify operator bundle if present. SAFE POINT: right after registry load (registry available, nothing decided yet, refusal aborts before networking).
B. bootstrap: same as A (no separate bootstrap routine exists; boot IS bootstrap). SAFE POINT: same hook.
C. peer discovery: bootnodes/DNS seeds -> P2PNetwork::start (continuous). No anchor role (anchors travel as files, sec.10/13); untouched.
D. initial sync: continuous P2P receivers (tx_receiver -> process_transaction; stake_receiver -> process_vote/bond/unbond) + GetData vote fallback. No discrete completion hook exists; anchor verification of synced state happens via check_state_against_anchor after quiescence (tooling/procedure) and at every reboot via the hook. No per-message change.
E. deep sync: vote backfill + DAG replay (4I d3/ds1). Unchanged; anchor cross-checks its output.
F. rebuild: rebuild_dag_topological + rebuild_from_dag_v6 + registry restore (replays + index rebuild). Unchanged; anchor context survives because votes/finality are never deleted.
G. restart: save/load roundtrips (storage + JSON). Unchanged; hook re-runs and re-verifies.
H. state restore: StakeRegistry::restore (replay + rebuild). Unchanged; verified stable (q11).
No path was modified before this mapping existed.

## 3. Bootstrap integration

Implemented in run_node after registry load: verify_bootstrap_anchor(data_dir, registry) -> NoAnchor (log, proceed EXACTLY as before) | Accepted (log id+support/total, proceed) | Err (refuse boot, same fail-closed pattern as the manifest path). The hook reads no clock, applies no era rule, and decides nothing about conflicts: it gates STARTUP on the coherence of operator bytes only. Consensus decisions downstream are untouched (hook output is not an input to any resolver).

## 4. New node

With anchor: empty node verifies the bundle (9 charter steps all inside verify_bootstrap_anchor: load file -> parse structure -> epoch/set/total bindings -> votes -> quorum -> chain tag -> state consistency -> accept), syncs votes (existing backfill), then check_state_against_anchor converges and try_finalize matches the active node (q10: same winner, same weight, hook accepts). WITHOUT inventing history: every check is recomputation, and the node still syncs the underlying data. Deterministic (q14 double-run identical).

## 5. No anchor

Preserved EXPECTED behavior: NoAnchor -> boot proceeds exactly as today (q03 on populated AND empty registries; q16 absent-path trivial cost). No invented mode: the node does not refuse V6 startup, does not enter a special mode, does not wait: with no V6-finalized history present there is nothing to anchor, and sync proceeds on existing machinery. A node fed alternate history without any anchor still converges on whatever it was fed (4N n11 stands, unchanged).

## 6. Fake anchor

Through the INTEGRATED functions (file + hook, not just the pure verifier): bad epoch/root/total, dropped vote, bad signature, truncated/garbage bytes all refuse (q04: 5 Verify + 2 Parse arms). Each tamper class maps to its binding error; garbage never reaches verification (parse gate). Nothing accepted that 4P would reject: the hook calls the same verify_anchor.

## 7. Cross epoch

anchor(E1)+state(E2) refused through bundle+hook (q05) and through the pure verifier (p09 inherited same-HEAD). Restart/sync/rebuild legs: anchor bytes are epoch-pinned, so a restarted/rebuilt node re-verifies the same verdict (q11/q12); sync output evaluated at a shifted epoch fails root+window (documented behavior, not re-run as a separate leg: same code path as q05).

## 8. Cross validator set

anchor(R1)+state(R2) refused (q06), combined 2x2 matrix green through the hook (q08: only (E1,R1) accepts). Same keys/same stake/near epoch still fail when the committed root differs (p10 inherited; q06 tampers one amount). Restart/sync/rebuild legs identical by code-path identity (bundle bytes immutable across restarts, q13).

## 9. Denominator

certificate(S,T1) against registry/set giving T2 refuses unless T2 == recomputed T (q07: claimed-1 fails). The hook never trusts the claim: verify_anchor recomputes from the bundled set every call. Registry-side totals steadily come from existing eligible_stake_total (unchanged); the anchor's T is independently recomputed, and check_state compares winners rather than re-litigating live totals (live state legitimately advances past the anchor: new bonds/slashes change totals without invalidating history).

## 10. Multi-source

Detection implemented, selection DEFERRED per charter (no invented source-quorum): compare_anchor_bundles is byte-exact over deterministic encodings (q01 determinism pin). A=B=C proceeds (each verifies); A!=B detected as Contradictory (q09, including same-decision/different-chain case); valid-vs-invalid pair: invalid refuses on its own (q04), so a node checking both never silently follows the bad one; no source: NoAnchor path (q03). MULTI_SOURCE_SELECTION = DEFERRED (operator halts on contradiction, 4O/4F procedural rule, no code invented).

## 11. Sync

Joiner with anchor: verify bundle -> sync DAG + votes (existing P2P/backfill) -> rebuild registry -> check_state passes -> same finality/support as the active node (q10 full leg). Join before finality: no local record yet -> presence check passes vacuously for synced votes, winner check skipped (absent finality is not contradiction); after finality arrives locally it must match (stickiness). Join during resolution, restart-during-sync, interrupted-sync-resume: covered by existing backfill machinery (4I d3_restart_during_backfill, ds1) whose output the anchor cross-checks; no new sync protocol added. SYNC = PASS.

## 12. Rebuild

Source -> shutdown -> wipe derived caches (index rebuild via restore path) -> rebuild: anchor context identical before/after (q11: byte-identical anchor ids, snapshots equal, hook accepts). Epoch/set/stake/votes/finality/ledger-inputs compared via snapshot equality + re-verification. REBUILD = PASS.

## 13. Persistence

Decision: anchor NOT persisted by the node (no new tree/keys/manifest: none justified, none added). It is operator-SUPPLIED at bootstrap and re-derived after every restart (deterministic build from registry+votes gives identical bytes, q13). Restart behavior identical with or without the file present (file present: re-verify same verdict; absent: NoAnchor path). Save/load roundtrips keep the anchor verifiable (q12/q13). No versioning/migration surface created.

## 14. State binding reserved

Unchanged RESERVED: no state_root binding implemented or invented (4O/4P). Integration works on actually available proofs: winner + quorum + set + epoch + chain. State still comes from ledger replay of the anchored branch (existing rebuild path). Explicitly NOT claimed otherwise.

## 15. Dormant gate

Post-integration proof: V6_ACTIVATION_TS and all five gate sites byte-identical (zero diff); new code paths (bundle parse/verify, hook, state check, comparison) read no clock and branch on no timestamp; activation suites inside rerun 4g/4h/4i green (g16/g23/g24/h01/h02/d2/v1); hook determinism proven (q14); pre-activation registries (no V6 finality) traverse the hook as NoAnchor-or-vacuous without any V6 rule firing (no votes/keys to bind). Timestamp <, =, > activation behave as before; the anchor causes no stake consensus, no V6 finality, no V6 fork choice anywhere (no production caller besides the boot gate). V6_DORMANT = PASS, V5_UNCHANGED = PASS.

## 16. No-PoW

Bootstrap/sync/anchor-verify/joiner paths read no difficulty/nonce/work/bits/hashrate/mining: grep over the 4Q additions shows zero such reads (sole nonce-substring hit is conflict_nonce, an account nonce). Signatures are Ed25519 verifications (authentication, not work). ANCHOR_BOOTSTRAP_POW = NONE. NO_POW = PASS.

## 17. Security

fake anchor: REFUSED (q04 matrix). replay: cross-context replays REFUSED (q05-q08); same-context redelivery harmless (idempotent inserts, existing dedup). old anchor: verifies as its own epoch only (epoch-pinned; stale anchors cannot authorize new state). future anchor: fails root/window against current sets. wrong epoch/set/denominator: REFUSED. malformed/truncated: Parse-stage REFUSED. source contradiction: DETECTED (q09), no silent pick. storage corruption (anchor file): Parse/Verify REFUSED. restart: same verdicts (q11/q12). sync interruption: partial state fails presence check until converged (q10 first leg), never false-accepts. All EXPECTED==ACTUAL: PASS.

## 18. Joiner test

q10 (kept, fast): A coherent (6/6 finalized) -> bundle file -> B empty verifies bundle, reports missing votes (no false accept), replays quorum votes + bonds, state check passes, B finalizes identically (winner + weight), hook accepts B. Then with bad anchor B refuses before syncing anything. END_TO_END_JOINER = PASS (registry/validator-set/stake/finality equality; ledger-inputs identical by deterministic rebuild, d1 standing).

## 19. Performance

Hook (6 votes + file): ~64ms total (signature verifies dominate, ~40ms/4 votes debug; file IO negligible; absent path trivially <100ms asserted). Verify scales linearly in quorum size (4P: 41ms/4, 1.02s/100). Bootstrap with anchor ~= existing boot + one verify pass; without anchor ~= existing boot exactly. Joiner reconstruction cost = existing backfill + one verify. 10k not re-run (4L numbers stand, code paths additive). No optimization in this phase (nothing critical found). PERFORMANCE = PASS.

## 20. Regressions

On final code: 4q 16/16, 4p 18/18, 4g 36/36, 4h 16/16, 4i 63/63, 4n 12/12, 4l 13/13 (incl. 10k) = 174 targeted green, 0 red; 4c 12/12 same-HEAD inherited (consensus files untouched by 4Q). Heavy suites (ledger sweep, parent_selection sweep, inc01 full, crash/multiprocess/security/deep-sync/consensus/migration/phase2/bootstrap) NOT rerun (4K/4J labels carried; node.rs hook uncalled by unit tests). Nothing presented as PASS without its run. REGRESSION_COVERAGE = PARTIAL.

## 21. Residuals

R1 multi-source selection stays procedural (detection implemented, choice deferred). R2 state-root primitive still reserved. R3 release dossier (set procedure, calendar, bundle operation) still open. R4 4J file + d1fd8d7 message carried. R5 50k scale unmeasured. No new findings opened (performance/behavior as designed; hook adds ~64ms at 6 votes, linear).

## 22. Final verdict

The anchor moved from pure verifier to enforced bootstrap boundary with joiner convergence proven, changing no consensus decision and waking nothing.
