# AETHER PHASE 3A â€” SECURITY ROADMAP (future work, no code in this audit)

> PHASE 3B STATUS (commit `8ec482d`): P0-1, P0-2, P0-doc CLOSED — see
> `docs/AETHER_PHASE3_CONSENSUS_HARDENING.md` (C1/C2/H1 = PASS).
> PHASE 3C STATUS (this phase): P1-1 (H3), P1-2 (H2), P2-4 (H4) CLOSED — see
> `docs/AETHER_PHASE3_CONSENSUS_ECONOMIC_HARDENING.md` (gates PASS with stated
> residuals). REMAINS OPEN: P1-3, P1-4, P2-1, P2-2, P2-3, P3, backlog items
> 3–10 below.

Companion to `docs/AETHER_PHASE3_CONSENSUS_AUDIT.md`. Nothing here is implemented, committed,
or scheduled by this document â€” it is a prioritized backlog for explicit follow-up phases.
Scope guardrails inherited from the audit: no consensus-constant change without a migration
plan; no commit/push from audit turns; `v1.4.0-testnet` stays immutable.

Finding IDs reference the audit: CRITICAL-1 (Â§3), C1/C2 (Â§14), HIGH-1 (Â§10â€“11), H1â€“H4, M1â€“M7, L1â€“L4.

---

## P0 â€” CONSENSUS-SAFETY BLOCKERS (must close before any adversarial exposure)

### P0-1 â€” Unify validation mode on the conflict path (CRITICAL-1, C1, C2)
- **3B CLOSURE**: fixed (STEP 0 uses caller mode; provenance threading) + tests green — see CONSENSUS_HARDENING section 1.
- **Problem**: STEP 0 re-validates the conflict winner with hardcoded `ValidationMode::Fresh`
  (`src/transaction_processor.rs:171`) while entry (STEP 1, `:206`) and the drainer
  (`src/rpc.rs:1240`) use the caller mode (Historical in production). Same tx, same content,
  different verdict depending on arrival order â†’ permanent split risk.
- **Direction (no code here)**: make STEP 0 use the caller-supplied `mode`; if the intent was
  "never prune for an invalid winner", enforce it with the SAME mode plus explicit
  PoW/signature/key checks (already covered by `validate_pure` in any mode), not a stricter
  timestamp regime. Alternatively: evaluate the winner in BOTH modes and define precedence.
- **Tests to add**: C1 partition sim (both arrival orders Ã— aged winner); C2 mode-matrix
  order-invariance (Fresh/Historical Ã— winner-first/loser-first); repair the three red
  live-path tests with mode-correct fixtures (their current fixtures predate the policy â€”
  fixing the TESTS is safe; changing the POLICY is not, without migration).
- **Acceptance**: C1 + C2 green; THREAT_MODEL partition row re-evaluated (downgrade to PARTIAL
  until then â€” documentation task, P0-doc below).

### P0-2 â€” Enforce timestamp/PoW-cost policy at DAG entry (HIGH-1, H1)
- **3B CLOSURE**: fixed (provenance: live=Fresh, sync=Historical, drainer honors recorded mode) + 4 H1 tests green — see CONSENSUS_HARDENING section 3.
- **Problem**: drainer + P2P + orphan paths always Historical â†’ backdated 20-bit PoW accepted,
  stale/future timestamps accepted at consensus entry; Fresh policy is perimeter-only.
- **Direction**: separate RELAY data (untrusted, Fresh) from SYNC data (provenance-known
  historical ranges, Historical with explicit bounds, e.g. only below a sync horizon).
  Candidates: Fresh-at-drainer with an allowlist for backfill batches; or epoch-scoped
  difficulty (consensus-explicit, not timestamp-implied) â€” the latter is a CONSENSUS CHANGE
  and needs a migration design + mixed-version plan first.
- **Tests to add**: H1 wiring tests pinning effective mode per ingress path; M5 future-ts P2P
  case; backdated-relay rejection test on the P2P path.
- **Acceptance**: H1 green; documented policy ("what it costs to enter the DAG from each
  path") matches code on all five ingress paths (Â§1 table).

### P0-doc â€” Correct the Â« PROVEN Â» partition claim
- `docs/THREAT_MODEL.md:121-148`: downgrade Network Partition to PARTIAL, citing C1/C2/HIGH-1,
  until P0-1/P0-2 acceptance. Docs-only, safe to do first.

---

## P1 â€” ECONOMIC / DoS HARDENING

### P1-1 â€” Conflict-flood CPU amplification bound (H3)
- Each injected conflict forces defenders through prune + storage purge + full
  `rebuild_from_dag` + full dirty-marking (`ledger.rs:606-609`). Attacker cost â‰ˆ one PoW
  (possibly 20-bit backdated); defender cost = O(DAG).
- Direction: per-sender conflict rate limit; incremental (non-full) rebuild after prune;
  cap + prioritize; measure first (H3 benchmark), then bound.
- **3C CLOSURE**: measured + shipped (sender-nonce index, atomic batch purge, pruned logging) + 5 tests green — see ECONOMIC_HARDENING H3. Quadratic chain-prune + per-conflict rebuild documented with triggers.
- Tests: H3 adversarial benchmark; regression bound test.

### P1-2 â€” Min-id grinding quantification (H2)
- **3C CLOSURE**: quantified (1 PoW/attempt, mean ~2 vs typical rival, TOTAL influence proven) + 3 tests green + receiver guidance — see ECONOMIC_HARDENING H2. No compatible consensus fix exists; capability retained by design (stated residual).
- Measure cost-per-id-improvement at 24-bit (and 20-bit) in the style of
  `test_w11_cost_measurement`; decide whether min-id needs a cost anchor (e.g. fee-weighted
  tiebreak is a CONSENSUS CHANGE â€” design only, not in audit scope).
- Tests: H2 benchmark (release-run per Â§15 protocol if pursued).

### P1-3 â€” Relay-before-full-validation amplification (L-d)
- Broadcast at accept (`rpc.rs:1185`) precedes drainer validation; unfunded-but-PoW-valid
  txs traverse the network then die at every drainer.
- Direction: consider ledger-prefilter hints at relay (balance Bloom / fee escrow signal) â€”
  design work; must not break partition healing (waiting-tx re-request logic).
- Tests: spam-relay amplification measurement (network harness, not unit).

### P1-4 â€” Difficulty-schedule decision (L-b, L-e)
- Static 24-bit forever; GPU economics unmeasured (THREAT_MODEL PARTIAL).
- Direction: measure GPU cost properly; decide retarget-vs-static as an explicit design
  record (ADR). Any change = hard fork + migration plan. No action proposed beyond
  measurement + decision record.

---

## P2 â€” CORRECTNESS / ROBUSTNESS

### P2-1 â€” STEP-8 persist-failure semantics (M1)
- **3E CLOSURE (M1)**: rollback symmetry shipped + 2 deterministic tests green — see MEDIUM_GAPS M1. Fault-injection harness remains future work (narrowed scope).
- Define: rollback in-memory apply on persist failure (symmetric with STEPS 4/6) OR
  commit-and-report-applied. Current mixed state (applied + Err) must go.
- Tests: storage fault-injection (M1).

### P2-2 â€” Defensive guards + determinism pins (M2, M3, M4, M7)
- `random_walk` zero-weight guard (M2) + hostile-state test.
- Pin `canonical_resolve_conflicts` CONTENT (order-agnostic test, M3); optionally sort the
  returned list for log determinism (behavior-preserving).
- Tip selection honesty (M4): either wire `valid_tips`/`min_weight`/`diversity_factor` into
  selection or remove/document them as reserved; add behavior-pinning test FIRST so the
  change is observable.
- Fixed-vector float-weight test (M7).
- **3E CLOSURE (M2/M3/M4/M7)**: zero-weight guard + 3 tests; pruned-order independence proven (no consumer — no sort imposed); tip-selection record corrected (docs only, no behavior change); weight finiteness/integrality pinned — see MEDIUM_GAPS. Canonical-content and tip-behavior pins covered by existing + new tests; M4 heuristic itself intentionally unchanged.

### P2-3 â€” Replay key separation proof (M6)
- Trace handshake â†’ per-session AEAD key schedule; add test proving cross-session frame
  rejection. If the binding is missing, file it as HIGH (key-schedule fix = P1).
- **3E CLOSURE (M6)**: binding PRESENT (ephemeral per-session keys + AEAD + counter + ban) + 2 proof tests green — see MEDIUM_GAPS M6. No crypto change.

### P2-4 â€” Innocent-descendant policy (H4)
- Measure merge-time loss at partition scale; define user-facing semantics (re-issue flow,
  mempool retention of pruned-but-valid txs for re-broadcast?). Design + tests.
- **3C CLOSURE**: proven (exact {L,D} removal, funds intact, live==boot) + pruned logging shipped + 3 tests green — see ECONOMIC_HARDENING H4. H4_INNOCENT_DESCENDANT_LOSS = NO (funds).

---

## P3 â€” HYGIENE (docs, names, warnings)

- **L1**: fix `transaction.rs:483-484` doc (always-`Some` reality).
- **L2**: rename misleading harness tests (`test_double_spend_during_partition`,
  `test_concurrent_conflicting_txs`) to convergence names, or upgrade them to true conflicts
  (then they become C1 material â€” prefer upgrading ONE and renaming the other).
- **L3**: clear the 43-warning test-profile baseline drift: wire-or-remove
  `penalize_contradiction`/`PEER_PENALTY_CONTRADICTION`, then re-baseline the count.
- **L4**: decide release-perf coverage for hot paths (currently 6 `#[ignore]`d benches only).

---

## TEST EXECUTION BACKLOG (ordered; none executed here)

1. Repair + extend live order-invariance (C2) â€” FAST once fixtures fixed.
2. Ingress-mode wiring tests (H1, M5) â€” FAST (no mining; use pre-mined or low-difficulty fixtures... note: fixtures must satisfy the CURRENT policy â€” build them Fresh-valid).
3. Content-order test for canonical resolve (M3) â€” FAST.
4. Fault-injection persist test (M1) â€” MEDIUM (needs storage harness).
5. Zero-weight walk test (M2), float-weight vectors (M7) â€” FAST.
6. Tip-selection behavior pins (M4) â€” FAST.
7. Handshake key-separation test (M6) â€” MEDIUM (needs P2P harness).
8. Partition sim C1 (both orders, aged winner) â€” MEDIUM/HEAVY (sim harness, small DAGs; keep
   PoW trivial via test-only difficulty like existing harnesses â€” check harness precedent
   before assuming).
9. Benchmarks H2/H3/P1-3 â€” HEAVY, release-only per Â§15 protocol
   (`cargo test --release --lib <test> --exact --nocapture`), with DEBUG/RELEASE semantic
   note (pure functions â‡’ identical verdicts, wall-time differs).
10. Full `validation::` battery â€” only after a faster strategy exists (release profile or
    pre-mined fixture cache); the 34Ã—24+15Ã—20 debug-mining load is a known wall-clock sink.

---

## NON-GOALS (explicitly out of scope for any Phase-3 follow-up unless re-chartered)

- Changing `default_difficulty`, migration timestamp, grace, or time bounds without a
  designed, versioned migration (consensus fork risk).
- Adding staking, voting, checkpoints, or finality gadgets (would be Phase 4+ architecture).
- Touching `v1.4.0-testnet`, the VPS, or any release artifact.
- "Beating Bitcoin" narratives: the comparison table (Â§16 of the audit) stays descriptive.
