# AETHER PHASE 3E â€” MEDIUM GAPS (M1â€“M7)

- **Scope**: the seven MEDIUM gaps of the Phase-3A audit, in charter order.
  H2 stays OPEN_RESIDUAL (untouched: no min-id/difficulty/fork-choice change).
  No P2P features, no Tor/I2P/transport/eclipse/self-healing changes, no
  release artifacts, no push/merge/tag/deploy.
- **Branch**: `dev/phase2-decentralized-network`, from `417be2a`.
- **Rule honored per gap**: reproduce/confirm â†’ exact cause â†’ bug / test-gap /
  docs-only verdict â†’ minimal fix only if necessary â†’ proof test â†’ targeted
  regression. No test weakened (two just-authored experiments corrected with
  disclosed rationale; see M3 and the M4-adjacent restore episodes).
- Companions: CONSENSUS_AUDIT (3A), CONSENSUS_HARDENING (3B),
  CONSENSUS_ECONOMIC_HARDENING (3C), CONSENSUS_RESIDUALS (3D),
  SECURITY_ROADMAP (updated Â§7: P2-1/P2-2/P2-3 closed).

## M1 â€” persist error after apply: FIXED

- **STATUS**: FIXED.
- **CAUSE (M1_ROOT_CAUSE)**: STEPS 4â€“7 mutated memory (ledger transfer + nonce
  + DAG add + mempool removal) before the two fallible STEP-8 persist calls;
  both `Err` paths returned WITHOUT restoring the pre-apply snapshot (and
  without touching the DAG entry), so memory stayed AHEAD of disk while
  reporting failure â€” unlike the STEP 4/6 failure paths, which roll back.
- **EVIDENCE (M1_CURRENT_BEHAVIOR / M1_FAILURE_WINDOW)**: drainer treats the
  Err as transient â†’ requeues â†’ retry converges via DuplicateTransactionâ†’
  Included (dup-gate precedes mutation; RPC users never see it â€” accept is
  pre-DAG). Crash windows both convergent but asymmetric: put-failed â†’ tx lost
  everywhere-consistent; save-failed â†’ tx row present, ledger rebuilt forward.
  Wart: Err meant "applied but failed" â€” misleading internally.
- **FIX**: `rollback_apply` (ledger snapshot restore + DAG entry removal via
  maintained `remove_transaction`; mempool left to the drainer requeue) called
  at BOTH STEP-8 failure sites with the STEP 4/6 drop discipline. After the
  fix Err means "nothing applied"; retries replay cleanly; crashes land on
  consistent-older state in both windows.
- **TEST**: `test_persist_error_after_apply` (white-box: STEPS 4â€“7 shape â†’
  rollback â†’ full restoration incl. tips + clean replay converges) and
  `test_restart_after_persist_failure` (put-failed world == snapshot world;
  save-failed world heals forward exactly once + idempotent re-rebuild).
  Deterministic, sync, FAST (Sled is reliable in-test, so no flaky fault
  injection â€” the trigger is pinned by inspection, retry by dup-gate order).
  Both PASS (0.00 s).
- **LIMITATION**: the trigger condition itself (real I/O failure) has no
  dedicated fault-injection test; a storage fault-injection harness remains
  future work (ex-roadmap P2-1 remainder, re-scoped below).

## M2 â€” zero-weight walk guard: FIXED

- **STATUS**: FIXED.
- **CAUSE**: `random_walk` called `gen_range(0..total_weight)` unguarded; a
  zero total (all children zero-weight/absent) panics the node (remote DoS
  primitive if ever reachable). Reachability audit: impossible in production
  today in all four classes (production data: children entries reference
  present txs â‰¥ weight 1.0; malformed: only test `inject_raw` writes children,
  and it writes none; pruned history: remove/prune clean links; empty branch:
  early return) â€” guard is defense-in-depth, zero normal-path change.
- **EVIDENCE**: code path + constructed states (see tests).
- **FIX**: `total_weight == 0 â†’ return Ok(current)` (genesis or DAG tx â€” both
  legal parents; roots exist by design). 3 lines + comment.
- **TEST**: `test_zero_weight_walk` (all-zero â†’ genesis, no panic),
  `test_zero_weight_walk_terminates` (400 walks; zero child never selected
  while a positive exists â€” deterministically), 
- `test_zero_weight_walk_malformed_state` (stale + zeroed entries â†’ genesis;
  public selector surfaces freshness error, no crash). ALL PASS (0.00 s).
  Walk/tip neighbors re-run green (4 + 2).
- **LIMITATION**: none known (guard is total: every zero-total state returns).

## M3 â€” pruned-list ordering: ALREADY_PROTECTED

- **STATUS**: ALREADY_PROTECTED (no vulnerability; proof test added).
- **CAUSE**: pruned ORDER varies (BFS pop order over insertion-ordered children
  Vecs; HashSet order in `canonical_resolve_conflicts`; random Sled iteration
  at boot) â€” but a full consumer audit finds NO functional order reader:
  STEP-0 purge is set-semantic (now one atomic batch), boot uses only
  `pruned.len()` + per-id deletes, logs are cosmetic, all in-repo assertions
  compare lengths or sorted sets.
- **EVIDENCE**: consumer grep (STEP 0, node.rs boot, tests) + new test below.
- **FIX**: none (deliberately no arbitrary sort â€” unjustified churn per rule).
- **TEST**: `test_pruned_list_order_independence` â€” same logical set in
  sorted/reversed/rotated input orders â†’ identical survivor SETS, pruned SETS,
  rebuild fingerprints (balances/supply/nonces); same children in two insertion
  orders â†’ identical removed SETS. PASS (0.01 s). One authoring correction
  disclosed: first draft varied sender bytes (different txs, correctly
  different prunes) instead of order â€” fixed to identical sets.
- **LIMITATION**: none (order-independence proven over the actual consumers).

## M4 â€” misleading tip selection: DOCUMENTED_RESIDUAL

- **STATUS**: DOCUMENTED_RESIDUAL (representation, not consensus).
- **CAUSE**: three code-level misdirections, none safety-relevant (ledger
  applies every valid tx regardless of parents; conflict rule ignores parents):
  (a) `select_parents` freshness filter gates availability (`NoValidTips`) but
  is not the selection pool (RNG walk from genesis decides); (b) `min_weight` /
  `diversity_factor` accepted-but-unread (`dead_code`); (c)
  `check_double_spend_conflict` is an over-conservative parent-DIVERSITY
  heuristic (same-sender-any-nonce + shared depth-10 ancestry â†’ genesis
  fallback), not the consensus double-spend rule (strict `(sender, nonce)`).
  Representations verified honest: RPC `aether_getTips` returns raw childless
  txs as such; P2P selector tips are sync HINTS with an explicit full-inventory
  fallback for missed tips.
- **EVIDENCE**: code + consumer tracing (node.rs closure â†’ P2P GetInventory;
  RPC tips endpoint; no ledger/fork consumer).
- **FIX**: documentation/naming record only (struct + selector + heuristic
  comments corrected; reserved params marked; heuristic distinguished from the
  consensus rule). NO behavior change (green selection tests pin current
  topology behavior; altering the heuristic risks propagation regressions for
  zero safety gain).
- **TEST**: none (charter: test only if real behavior is concerned â€” it is not;
  existing selection tests re-run green).
- **LIMITATION**: over-conservative parent diversity (genesis fallbacks) remains
  as analyzed topology-shaping behavior.

## M5 â€” future timestamps via P2P: ALREADY_PROTECTED

- **STATUS**: ALREADY_PROTECTED (live paths enforce Fresh; sync latitude by
  design).
- **CAUSE**: post-3B, P2P live relay evaluates Fresh (rejects beyond
  MAX_FUTURE_MS) while sync backfill stays Historical (genuine history must
  heal). A future-ts tx via sync is self-limiting (parent-ordering forces its
  descendants future-dated too, which live paths reject).
- **EVIDENCE**: receiveâ†’validateâ†’mempoolâ†’DAG path traced; live vs sync modes
  pinned by 3B wiring + new tests.
- **FIX**: none needed (historical latitude preserved; margins untouched).
- **TEST**: `test_p2p_future_timestamp_rejected` (far-future via P2P-live â†’
  FutureTimestamp, never queued/DAGged/parked) and
  `test_p2p_future_timestamp_boundary` (exact MAX_FUTURE bound passes the
  timestamp gate â€” Invalid PoW proves passage; +5000 ms fires FutureTimestamp;
  Â±1 ms edge covered at validator level by existing mined tests, wiring pinned
  here with deterministic margins). PASS (0.07 s each, garbage fixtures â€”
  gates fire before PoW).
- **LIMITATION**: sync-path future-ts anomalies possible but self-containing.

## M6 â€” inter-session replay: ALREADY_PROTECTED

- **STATUS**: ALREADY_PROTECTED (not formally tested before â€” now proven).
- **CAUSE/analysis (session A â†’ capture â†’ session B â†’ replay)**: sessions
  derive FRESH ephemeral X25519 keys per connection, both sides
  (`EphemeralSecret::random_from_rng`), hashed into the session key â€” keys
  differ across sessions. Captured frames therefore fail AEAD authentication
  in any other session BEFORE counter/content processing (production: warn +
  peer ban + disconnect). Defense in depth: strictly-increasing per-session
  8-byte counters (replay/regression â†’ ban + disconnect) + direction byte
  separating nonce spaces.
- **EVIDENCE**: handshake/key/nonce/counter/decrypt-failure code paths +
  pre-existing tests (rotation over 8 real handshakes with distinct keys;
  shared-key + opposite-direction derivation; counter strict-increase logic;
  roundtrip/cross-direction/tamper/nonce-uniqueness) + 2 new tests below.
- **FIX**: none (no crypto change â€” correctly, per charter).
- **TEST**: `test_replay_across_sessions` (verbatim captured frames rejected
  under the new session key; controls open under their own) and
  `test_old_ciphertext_rejected_new_session` (counterÃ—direction matrix, all
  rejected cross-key). PASS (0.00 s, pure crypto).
- **LIMITATION**: network-level session test (live MITM harness) out of scope;
  primitive breakage (X25519/SHA256/ChaCha20-Poly1305) out of scope by definition.

## M7 â€” floating-point determinism: NOT_RELEVANT

- **STATUS**: NOT_RELEVANT for consensus safety (with pinned foundation).
- **CAUSE (repo-wide f32/f64 triage)**: NO float reaches fork choice (min-id
  over integer ids), the ledger (u64 balances/nonces/fees), finality (no
  mechanism), or peer scoring (i32). Floats live in three consensus-adjacent
  places, all IEEE-754-deterministic for identical inputs: (1) `tx.weight`
  f64 = subtree size via +1.0/âˆ’1.0 + 0.0 clamp â€” integer-valued always, no
  division, no NaN source; consumed via exact `as u64` cast (tip walk) and
  `>= 5.0` (advisory Stable); (2) fee-oracle/estimator f64 internals with u64
  outputs (accept-time gates; cross-node differences come from different local
  inputs, not float nondeterminism); (3) timing/display/bench values.
- **EVIDENCE**: triage list above + existing pins (w-suite weights, RPC Stable
  test, H4 exact-weight asserts) + new test below.
- **FIX**: none (nothing to determinize; no representation change without proof).
- **TEST**: `test_weight_finiteness_and_bounds` â€” 200 deterministic mixed
  add/remove/prune ops; every weight finite, â‰¥ 0.0, integral (`fract()==0`),
  â‰¤ DAG size. PASS (0.01 s). Pins the exactness the verdict rests on.
- **LIMITATION**: cross-implementation float formatting in logs/RPC is display
  only.

## H2 = OPEN_RESIDUAL (restated, untouched)

No H2 work in this phase (charter): min-id, difficulty, fork choice unchanged;
grinding model/tests/measures stand from 3C; mitigation roadmap stands from 3D.

## Test record (this phase; green-test assertions/logic: zero edits)

- New (11): M1Ã—2, M2Ã—3, M3Ã—1, M5Ã—2, M6Ã—2, M7Ã—1 â€” ALL PASS (all FAST, 0.00â€“0.07 s).
- Re-run: processor FULL 12/12; parent_selection walk/tip/canonical/prune
  neighbors green; p2p:: 151/0/2; phase2 suites 26+15+17+16+18+11; bootstrap
  21/21 (19 + 2 M6); validation FAST + security + spec + crash + migration-fast
  all green (3B/3C tree-identity holds â€” no source file they cover changed
  except parent_selection/processor, whose FULL affected modules re-ran).
- `cargo check --lib`: EXIT 0, 9 warnings = baseline exactly (0 new).
- Total lib tests: 575 â†’ 586 (+11).
- Two authoring incidents disclosed (never-green experiments, fixed by design
  correction with rationale, never by assertion weakening): M3 sender/order
  confusion; two accidental line deletions during editing, both restored
  byte-identical and re-verified green (mempool test line, tampered-ciphertext
  body).

## Exit mapping

- M1 = FIXED; M2 = FIXED; M3 = ALREADY_PROTECTED; M4 = DOCUMENTED_RESIDUAL;
  M5 = ALREADY_PROTECTED; M6 = ALREADY_PROTECTED; M7 = NOT_RELEVANT.
- H2 = OPEN_RESIDUAL. C1/C2/H1/H3/H4 = PASS (tree-identity + targeted re-runs).
- LEDGER_EQUIVALENCE / DAG_REGRESSION / FORK_CHOICE / PARTITION_REGRESSION = PASS.
- P2P / PHASE2 / BOOTSTRAP (21/21) = PASS. CRITICAL_FAILURES = 0, HIGH_FAILURES = 0.
