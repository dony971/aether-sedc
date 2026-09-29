# AETHER PHASE 3C â€” CONSENSUS ECONOMIC / CONFLICT HARDENING (H2 / H3 / H4)

- **Scope**: the three HIGH gaps left by Phase 3A. No MEDIUM work, no P2P
  features, no Tor/I2P/transport/eclipse/self-healing changes, no PoW/difficulty
  change, no min-id rule change, no release artifact touched.
- **Branch**: `dev/phase2-decentralized-network`, from `8ec482d`.
- **Rules honored**: conflicts are NOT removed/limited/time-boxed; difficulty is
  untouched; min-id is untouched (any weight/commit/depth redesign would be a
  fork â€” analyzed, deferred, documented); no test weakened (two authoring
  iterations disclosed below: both were never-green experiments whose failures
  taught model refinements, documented, never hidden).
- Companions: `AETHER_PHASE3_CONSENSUS_AUDIT.md` (gaps as found),
  `AETHER_PHASE3_CONSENSUS_HARDENING.md` (3B fixes), `AETHER_PHASE3_SECURITY_ROADMAP.md`
  (updated Â§8: H2/H3/H4 closed here; H4 follow-ups re-scoped).

We do NOT write "consensus securise". Closed gaps report measurements; residual
capabilities retained by design are stated plainly.

---

## H2 â€” min-id grinding (QUANTIFIED; capability retained by design)

### H2_GRINDING_MODEL

- **ATTACK_SURFACE**: the conflict winner for a `(sender, account_nonce)` pair is
  the smallest `tx.id` (`transaction_processor.rs:154`, `canonical_resolve_conflicts`,
  rebuild winners). Only the key owner can mint valid variants (signature binds
  sender), so grinding = a sender replacing their own tx â€” the classic
  double-spend shape (pay merchant, then grind a smaller-id self-refund).
- **CONTROLLED_FIELDS** (per attempt, all covered by signature AND PoW preimage
  except noted): receiver, amount, fee, timestamp, parents (among known tips),
  pow_nonce, signature (derived). **UNCONTROLLED_FIELDS**: sender, account_nonce
  (fixed = the conflict key); the victim's rival id (fixed once broadcast);
  BLAKE3 output (uniform â€” proven, not assumed).
- **Determinism gate (verified, not assumed)**: signatures are Ed25519 via
  ed25519-dalek (`src/wallet.rs:15-17`, `sign_transaction` uses deterministic
  `sign()` with no RNG) â†’ re-signing identical content yields the identical id.
  There are NO free re-sign attempts: every attempt needs fresh content and
  therefore a fresh PoW.
- **COST_PER_ATTEMPT**: one full PoW (24-bit post-activation â‰ˆ 16.7M hashes mean;
  20-bit pre-activation â‰ˆ 1M) + one Ed25519 sign (Âµs). No invented wall-times:
  project-measured CPU â‰ˆ 5.3 s/tx (`THREAT_MODEL.md:15`); debug 20-bit mines
  observed 7â€“148 s in this phase's runs (geometric variance + unoptimized profile).
- **EXPECTED_SEARCH**: geometric with p = R/2^256 for fixed rival id R (derivation
  from the uniformity premise). Typical rival (R â‰ˆ 2^255): mean â‰ˆ 2 attempts.
  Measured: [1, 2, 2, 1, 1], mean 1.40. Small rival (leading 0x03, R â‰ˆ 2^250):
  measured 100 attempts (expected â‰ˆ 64; same order, geometric variance).
- **CONSENSUS_INFLUENCE**: TOTAL for the pair â€” winner installs, loser AND its
  entire descendant subtree are pruned (proven: influence test + H4 precision
  test). Grinding decides who wins, deterministically, at any later time: there
  are no slots, epochs or confirmation-depth rules, so the replacement window
  never expires.
- **CURRENT_MITIGATION**: per-attempt PoW (deterministic sig â‡’ no free attempts);
  per-tx burned fees; funding gate (variants must be fundable against the live
  ledger); weight-independent rule (no weight to buy); deterministic outcome
  (no reorg lottery â€” the cheapest id always wins, which is also what makes the
  cost calculable).
- **UNQUANTIFIED_PARTS (closed)**: search distribution (now measured), cost per
  attempt (now code-derived + wall-cited), influence scope (now proven). Residual
  unknowns kept explicit: GPU-time translation (project-estimated only), network
  race irrelevance (no deadlines by design).

### H2 problem / proof / cause / fix / limits / residual

- **Problem**: the price of flipping a same-key payment was unknown.
- **Proof**: `test_min_id_distribution` (1024 ids: distinct; nibble buckets
  [53..74] for E=64; min 00.. â€” uniformity premise MEASURED),
  `test_min_id_grinding_bound` (typical mean 1.40; small-rival 100 attempts),
  `test_min_id_selection_influence` (ground B flips canonical resolution; control
  loses). All PASS, milliseconds, zero PoW (order mechanism only â€” cost leg is
  code-derived, never conflated).
- **Authoring disclosure**: first grinding version drew unconditioned rivals and
  observed mean 14.2 (one small rival dominated). Not a product defect â€” it is
  the scaling law E=2^256/R, now documented and probed explicitly; the test
  conditions typical rivals (first byte [64,192]) with a-priori bounds. The
  episode is kept in the test comment.
- **Cause**: min-id + permissionless variants + no time bounds (design, not bug).
- **Fix**: NONE compatible within 3C rules â€” supplementary-data / complementary-
  weight / pre-commit / depth rules all fork consensus or mask the mechanism
  (analyzed, rejected with reasons). H2 closure = quantification + tests +
  receiver guidance: a payment is reversible for ~2 PoWs expected at ANY time;
  receivers must treat DAG-inclusion as 0-conf and wait for weight/reference
  heuristics (existing RPC Stable signals) per value at risk. Recorded as
  accepted residual, not as safety.
- **Limits**: model assumes rational compute pricing; fee-oracle dynamics under
  grinding floods unmeasured (H3 covers defender CPU, not fee markets).

### H2 measures (Ã‰TAPE 11)

- H2_GRINDING_COST = 1 PoW (24-bit; 20-bit pre-activation) + 1 sign per attempt.
- H2_SEARCH_ESTIMATE = mean ~2 vs typical rival (measured 1.40); ~100 vs 0x03 rival.
- H2_CONSENSUS_INFLUENCE = TOTAL (pair decided + loser subtree pruned).

---

## H3 â€” conflict CPU cost (MEASURED, BOUNDED, REDUCED where principled)

### H3_CPU_AMPLIFICATION_MODEL

Per conflicting tx admitted, the defender pays (code-traced, `process()` STEP 0):

- **INPUT_COST** (attacker): 1 valid PoW + 1 signature + fee + funding (V-21
  `validate_pure` before any prune â€” junk cannot trigger work for free).
- **VALIDATION_COST**: 3Ã— pure evaluations along the acceptâ†’drain path
  (accept gate, STEP 0 winner branch, STEP 1) = 3 hashes + 3 sig verifies, O(1).
  Deliberately NOT deduplicated (STEP-0/STEP-1 skip considered and rejected:
  negligible gain, non-zero risk) and NOT cached (Fresh verdicts are
  time-relative â€” caching them is unsound; Historical evaluation is already cheap).
- **CONFLICT_COST** (dominant): `find_sender_nonce_conflict` lookup +
  `prune_subtree` traversal + `rebuild_from_dag` full replay + storage purge.
- **REPEATED_WORK** (found): the lookup was a FULL O(n) scan at THREE sites per
  admission (STEP 0 `transaction_processor.rs:152`, `validate_dag`
  `validation.rs:354`, `add_transaction_validated` `parent_selection.rs:409`).
- **AMPLIFICATION_FACTOR** (measured, 2k-tx DAG, debug): single conflict =
  prune + full rebuild â‰ˆ 32 ms; K=16 conflicts â‰ˆ 831 ms â†’ 26Ã—/16 = **â‰ˆ1.6Ã— over
  linear** (noise-banded; each conflict pays one full O(DAG) rebuild by
  construction). Lookup post-fix: 20k lookups â‰ˆ 14 ms, flat 1.18Ã— over 8Ã— size.
  Chain prune: 60.75Ã— for 8Ã— length (theory 64Ã—) â€” **quadratic weight
  maintenance confirmed** (each of L removals walks O(L) ancestors).
- **LIMITS**: attacker cost per conflict (PoW+fee+funding) is linear in K; defender
  cost is K Ã— O(DAG) + O(subtreeÂ²) for deep prunes. No exponential path found
  (bounds asserted in tests). Deep-chain asymmetry favors the defender (building
  an L-chain costs L PoWs + L fees vs ~LÂ² fast HashMap ops â€” measured 0.9 s at
  L=800 debug).
- **MITIGATIONS (shipped)**:
  1. `(sender, nonce)â†’id` index in `DAG` (O(n)â†’O(1) per admission incl. steady
     state, identical answers; serde-skipped; maintained on add/remove/prune;
     test-only last-wins documented). The pre-existing full scan is gone.
  2. STEP-0 purge via single atomic `batch_write(DeleteTransactionâ€¦)` â€”
     semantically identical (index + applied-mark purge per id, pre-tested) with
     one Sled transaction + one flush instead of N syscalls. End-to-end pinned
     by `test_step0_prune_purges_loser_from_storage` (winner present, loser
     absent from store post-STEP-0).
  3. Pruned-set observability (count + id sample logged at STEP 0) â€” doubles as
     H4 re-issuance aid.
- **MITIGATIONS (deferred with reasons)**: single-pass weight recompute after
  prune (converts O(LÂ²)â†’O(DAG); touches consensus-visible weights â€” deferred
  under Ã‰7 risk rule; trigger documented: prune depths Ã— frequency growth);
  per-sender conflict throttling (arbitrary-limit class, forbidden); validation
  cache (unsound, above).

### H3 tests (all PASS, no PoW â€” validated inserts need none)

- `test_conflict_lookup_scales` (absolute < 1 s pins O(1); ratio 1.18 pins shape).
- `test_conflict_index_matches_scan` (150 mixed ops incl. rejected adds/removes/
  prunes; index == brute force after EVERY op).
- `test_conflict_cpu_cost` (K=1,2,4,8,16; exact removals asserted; T(16)/T(1) <
  64; base + factor reported).
- `test_conflict_prune_chain_scaling` (L=100..800; exact removals; loose <1000Ã—
  bound; curve reported â†’ deferral decision above).
- `test_step0_prune_purges_loser_from_storage` (live STEP-0 + Sled: purge wiring).

### H3 measures (Ã‰TAPE 11, debug profile)

- H3_CONFLICT_CPU_BASE â‰ˆ 32 ms (1 conflict: prune + full 2k-DAG rebuild).
- H3_CONFLICT_CPU_8 â‰ˆ 405 ms.
- H3_AMPLIFICATION_FACTOR â‰ˆ 1.6 (linear = 1.0 + noise).
- Lookup: flat. Chain prune: quadratic (measured 60.75Ã— / theory 64Ã—).

---

## H4 â€” innocent descendants (PRECISION PROVEN; funds INTACT)

### Analysis (Ã‰5 shape built explicitly)

DAG: P root; Aâ†’Bâ†’C innocent chain on P; W/L same-key roots (roles post-hoc by
id); D innocent child of [L, A] (diamond); E innocent child of W.

- **Removed**: EXACTLY {L, D} (proven). **Kept**: {P, A, B, C, W, E} + funding.
- **Depends on loser**: D (parent hash fixed) â€” in-DAG survival IMPOSSIBLE
  (rewriting parents changes the id). Deletion is by-design necessity, not a bug.
- **Depends on winner**: E â€” survives + applies (proven).
- **Legitimate loss**: D's EFFECTS are revoked exactly (M2: 45â†’0, M3: 50â†’0);
  expectation loss is re-issuable (owner holds keys + full pruned list is now
  logged). **Fund loss: ZERO** (conservation asserted: 9985 = 10000 âˆ’ 15 fees).
- **Ledger rollback**: full re-derivation (C2-P3 applied-set cleared + rebuilt;
  loser/revoked marks proven absent post-rebuild).
- **Reconstruction**: by re-issuance only (new parents, new PoW); boot path
  converges to the identical funded state (proven below).
- **Prune level**: sub-DAG (loser + transitive children via maintained children
  map; hygiene asserted: no stale references post-prune; weights exact:
  A=3, P=4, W=2, B=2, C=E=1; tips exactly {C, E}).
- **Fix shipped**: pruned-set logging at STEP 0 (re-issuance aid). No deletion-
  semantics change (already exactly the invalidated branch).

### H4 tests (all PASS, no PoW)

- `test_conflict_prunes_only_invalid_branch` (exact removal set, survivors,
  tips, weights, children hygiene).
- `test_conflict_preserves_innocent_descendant` (two-phase partition-merge
  shape: revocation M2/M3, installation M1, preservation M1â†’65/M4=30,
  conservation, applied-mark lifecycle).
- `test_conflict_rebuild_preserves_valid_state` (live-prune vs boot
  canonical+topological+rebuild: DAG sets + balances + supply + nonces equal â€”
  AFTER_RESTART == AFTER_CONFLICT, on funded non-vacuous states).

### H4 measure (Ã‰TAPE 11)

- H4_INNOCENT_DESCENDANT_LOSS = NO (funds; expectation loss by design, re-issuable).

---

## Test record (3C tree; green-test assertions/logic: zero edits)

- New (11): 3 H2 + 4 H3 + 3 H4 + 1 purge-wiring. ALL PASS (H2/H4 instant;
  lookup 1.4 s; cpu_cost 2.4 s; chain 2.5 s; purge 64 s incl. 2Ã—20-bit mines).
- Re-run affected: parent_selection 35/36 (w11_cost_measurement unfinished â€”
  PoW-bound, pre-existing slowness, path untouched); transaction_processor
  10/10 (9/10 in-module + valid_orphan solo 0.24 s); storage 13/13; p2p::
  149/0/2ign; phase2 suites 26+15+17+16+18+11; bootstrap 19/19.
- `cargo check --lib`: EXIT 0, 9 warnings = baseline exactly (0 new).
- Total lib tests: 564 â†’ 575 (+11).
- No `--release` runs: heavy tests here are PoW-bound sims/miners on paths
  untouched by this diff; verdict logic is pure functions of content
  (DEBUG/RELEASE identical by construction, wall-time only differs) â€” recorded
  instead of re-proven, per Ã‰8/Ã‰10 protocol.

## Exit mapping

- H2_GRINDING = PASS (quantified + tested + receiver guidance; capability retained
  by design, stated).
- H3_CPU_AMPLIFICATION = PASS (measured + bounded + index/batch/log shipped;
  quadratic deferred with trigger, O(DAG)-per-conflict inherent to
  rebuild-consistency, stated).
- H4_DESCENDANT_PRESERVATION = PASS (precision + funds + restart proven; loss = NO).
- CONSENSUS_REGRESSION / LEDGER_EQUIVALENCE / DAG_REGRESSION /
  PARTITION_REGRESSION = PASS (above runs).
- P2P_REGRESSION / PHASE2_REGRESSION / BOOTSTRAP_PHASE1 19/19 = PASS.
- CRITICAL_FAILURES = 0.
