# AETHER PHASE 3D â€” CONSENSUS RESIDUALS (H2 / W11 / INC01)

- **Scope**: close the residuals left open after Phase 3C. No P2P features, no
  Tor/I2P/transport/eclipse/self-healing changes, no M1â€“M7 work, no release
  artifacts touched, no push/merge/tag/deploy.
- **Branch**: `dev/phase2-decentralized-network`, from `417be2a`.
- **Outcome**: H2 = OPEN_RESIDUAL (no compatible fix exists â€” proven by option
  analysis below, not by lack of trying); W11 = PASS (release run); INC01 = PASS
  (5/5). NO source file was modified in this phase (read-only audit + test
  executions), so per the phase charter: CODE_CHANGES = NONE, COMMIT = NONE.
  This document is the deliverable; it remains uncommitted in the tree.
- Companions: `AETHER_PHASE3_CONSENSUS_AUDIT.md` (3A findings),
  `AETHER_PHASE3_CONSENSUS_HARDENING.md` (3B), `AETHER_PHASE3_CONSENSUS_ECONOMIC_HARDENING.md`
  (3C), `AETHER_PHASE3_SECURITY_ROADMAP.md` (backlog).

We do NOT write CONSENSUS_SECURE = YES. We do NOT write BITCOIN_EQUIVALENT = YES.

---

## 1. H2 â€” min-id grinding: root cause (Ã‰TAPE 1)

### H2_ROOT_CAUSE

The conflict winner is `min(tx.id)` over same-`(sender, account_nonce)` txs,
consumed by bare comparison at three sites: STEP 0 live
(`transaction_processor.rs:154`), `canonical_resolve_conflicts` (boot),
rebuild winners (`ledger.rs`). `tx.id = BLAKE3(parents|sender|receiver|amount|
fee|timestamp|pow_nonce|account_nonce|signature|pubkey)` (`transaction.rs`).
Of these inputs the key owner controls EVERYTHING except the conflict key
itself (sender, account_nonce â€” fixed by definition of a conflict). Signatures
are deterministic Ed25519 (no free re-sign variants â€” verified), so each new
id attempt requires fresh content and therefore a fresh PoW. Uniformity of ids
is measured, not assumed (`test_min_id_distribution`: 1024 distinct, buckets
[53..74] for E=64).

Why influence is TOTAL: min-id is the ONLY decision input (weight explicitly
ignored â€” `test_w6` pins this), there are no slots/epochs/depths, and
replacement never expires. The min-id is CHOSEN offline, pre-broadcast, at any
time (before, during, or arbitrarily long after the victim's confirmation);
consensus CONSUMES it deterministically at delivery (STEP 0), at boot
(canonical resolve) and at every rebuild. Choosing â‰  consuming, and nothing
bounds the former.

Field-by-field: parents (attacker-chosen among known tips; exotic parents risk
orphaning at consumers â€” slight natural brake); timestamp (free, self-declared;
drives difficulty + Fresh policy on live paths); pow_nonce (mined);
amount/fee/receiver (free, funding-constrained: variants must be fundable or the
ledger gate rejects them); signature (deterministic function of content â€” zero
freedom); sender/account_nonce (fixed). Fork-choice interaction: min-id IS the
conflict fork-choice; no work/weight/stake input exists anywhere in the path.

### H2_ATTACK_MODEL

S pays merchant M (tx1 enters DAGs; M delivers goods off-chain) â†’ S grinds tx2
(same nonce, self-refund, id < tx1.id; ~2 PoWs expected, unbounded time, fully
offline) â†’ S broadcasts tx2 â†’ every node prunes tx1 AND its descendant subtree
â†’ M unpaid, with no protocol recourse (no depth rule, no slashing, no appeal).
Cost â‰ˆ 2Ã— 24-bit PoW + fees (â‰ˆ10 s CPU class per project-measured ~5.3 s/tx).
The ONLY current defense is receiver-side: treat DAG-inclusion as 0-conf and
wait for weight/reference heuristics per value at risk.

### H2_CURRENT_LIMITATION

Per-attempt PoW + burned fees + funding gate are all real but linear and small;
the replacement window is infinite; the rule ignores everything but id order.

### H2_DESIGN_OPTIONS (each scored, none adopted lightly)

**A. Attacker-independent min-id (VRF / commit-reveal / beacon).**
SECURITY_BENEFIT: kills offline grinding. CONSENSUS_IMPACT: different winners
possible â†’ chain split between rule versions. WIRE_IMPACT: none (same bytes).
BACKWARD_COMPATIBILITY: NO. IMPLEMENTATION_COST: medium + migration design.
NEW_ATTACK_SURFACE: beacon/VRF-seed grinding (recursion), liveness dependence
on beacon availability. VERDICT: breaking change â€” out of scope, recorded below.

**B. Decision weight linked to PoW done (lower PoW hash wins / higher difficulty
wins).** BENEFIT: ~nil â€” both ids and PoW hashes are uniform; difficulty is
self-declared via timestamp (attacker picks post-activation ts). IMPACT: forks
outcomes. BACKWARD_COMPAT: NO. COST: low. NEW_SURFACE: timestamp gaming for
difficulty class. VERDICT: rejected (no benefit).

**C. Committed / non-directly-controllable data (DAG-entropy salt in
resolution).** BENEFIT: partial (cannot fully pre-grind). IMPACT: resolution
becomes context-dependent â€” nodes/partitions see different entropy â†’ DIVERGENCE
RISK against the core determinism property; attacker partially influences
entropy via parent choice anyway. BACKWARD_COMPAT: NO. COST: medium.
NEW_SURFACE: entropy-view manipulation. VERDICT: rejected (weakens determinism
for little gain).

**D. Secondary tie-breaker.** Ids never tie (256-bit) â†’ meaningless as specified.
Fee-weighted variant: plutocratic (richest sender wins conflicts), enables
fee-bullying, still a fork. VERDICT: rejected.

**E. Other, compatible-with-current-protocol.**
(i) Receiver confirmation policy (advisory depth/weight waits): COMPATIBLE, no
code, economically effective â€” ADOPTED as guidance (below). (ii) RBF-style
fee-bump replacement rule (replacement must carry strictly higher fee):
changes conflict outcomes â†’ needs versioned migration; replaces id-grinding
with fee-grinding (plutocratic residue) â€” POTENTIAL BREAKING CONSENSUS CHANGE,
recorded, not implemented. (iii) Per-sender conflict throttling:
arbitrary-limit class, doesn't stop grinding â€” rejected.

### H2 verdict (Ã‰TAPE 6)

**H2_STATUS = OPEN_RESIDUAL.** No option is both compatible with the current
consensus rules and effective; every effective option forks conflict outcomes.

### H2_MITIGATION_ROADMAP

1. NOW (no code): receiver guidance â€” DAG-inclusion is 0-conf; require
   weight/reference confirmations scaled to value (existing RPC
   Confirmed â‰¥3 refs / Stable â‰¥5.0 signals); document the ~2-PoW reversal price
   in operator docs (THREAT_MODEL partition/payment rows).
2. FUTURE, **POTENTIAL BREAKING CONSENSUS CHANGE** (not designed here, not
   implemented): (a) versioned confirmation-depth rule for conflict replacement
   (shared-clock problem must be solved first: DAG has no height; timestamps
   skew); (b) RBF-style fee-bump replacement precondition; (c) VRF-based
   conflict randomness with migration-gated activation. Any of these needs a
   fork design + mixed-version plan + testnet reset discussion. Explicitly NOT
   started in this phase.

---

## 2. W11 â€” PASS (release run, semantics identical)

- **Identification**: `parent_selection.rs:1653 test_w11_cost_measurement` â€”
  a MEASUREMENT test (prints a cost table; asserts nothing), mining 62Ã— 24-bit
  PoW in debug (chains 5/10/50) â†’ PoW-bound, unfinished in debug wall-clock.
  Test-vs-code question settled: test-side cost, code is fine (all w1â€“w12
  siblings green in debug).
- **Release compatibility**: behavior identical by construction (same DAG
  ops/weights/fees; only wall-time and mined nonce values differ; no fixed
  expectations). No difficulty/iteration/assertion changed (untouched).
- **Run**: `cargo test --release --lib
  parent_selection::tests::test_w11_cost_measurement -- --exact --nocapture` â†’
  **ok, 472 s**, difficulty=24:
  LEN=5: 13.6 s, PoW 32.4M, weight 5.0 STABLE YES;
  LEN=10: 63.9 s, PoW 139.6M, weight 10.0 YES;
  LEN=50: 395 s, PoW 844.5M, weight 50.0 YES.
  Per-tx release mining â‰ˆ 5â€“8 s â€” consistent with project-measured ~5.3 s CPU.
- **W11_STATUS = PASS.**

## 3. INC01 â€” PASS (5/5)

- **Missing result identified**: `tests::inc01_fix_tests::test_inc01_getdata_store_only`
  (the other 4 green in debug). File `src/tests/inc01_fix_tests.rs` is dirty
  pre-existing: NOT MODIFIED (read-only inspection + execution).
- **Why slow**: calls `signed_mined_orphan_tx()` (mines 24-bit) **100Ã—** â†’
  hours in debug. Not a hang, not a bug â€” pure test cost. No timing assertions
  in the test (store presence/absence/counts only) â†’ release-compatible.
- **Run**: `cargo test --release --lib
  tests::inc01_fix_tests::test_inc01_getdata_store_only -- --exact` â†’ **ok,
  600 s**, `store_hits=100` (100 Ã— ~6 s mines, consistent with W11 rates).
- **INC01_STATUS = PASS (5/5).**

---

## 4. Tests effectuÃ©s / encore manquants (this phase)

Done: W11 release (PASS + table above); INC01 solo release (PASS, hits=100);
heavy_branch_wins release (PASS, 61 s â€” closes the last consensus-sim gap,
11/11 sims effectively green); Ã‰5 re-verification by tree-identity (no source
file modified in 3D, so all 3B/3C runs stand: C1/C2/H1, H3/H4, processor 10/10,
storage 13/13, p2p 149/0/2, phase2 suites, bootstrap 19/19, validation FAST,
security/spec/crash/migration-fast, consensus sims, inc01 4/5 debug).
Missing: none required â€” every Ã‰5 area has green evidence on the current tree
(HEAD `417be2a`, zero source diffs this phase). Full-suite re-runs were
deliberately NOT repeated (no code changed; wall-clock cost with zero
information gain).

## 5. Risques rÃ©siduels (restated, not softened)

- H2 replacement window stays infinite; reversal price stays ~2 PoWs; receivers
  without confirmation policy accept double-spend risk knowingly or not.
- H3 per-conflict full rebuild + quadratic deep-prune stand (measured, bounded,
  trigger-documented); conflict floods remain the cheapest defender-taxing
  primitive (â‰ˆ1 PoW in, O(DAG) out).
- H4 expectation loss (re-issuance burden) stands by hash-bound necessity.
- M1â€“M7, L-series, P1-3, P1-4: untouched, still open per SECURITY_ROADMAP.
- No full `validation::` debug battery was ever completed wall-clock; release
  runs covered the indispensable PoW-bound cases only.

## 6. Breaking changes futurs Ã©ventuels (explicitement NON commencÃ©s)

Confirmation-depth replacement rule; RBF-style fee-bump; VRF conflict
randomness; any difficulty-schedule change. Each needs fork design +
mixed-version plan + testnet governance. Listed here so a future charter can
adopt them â€” nothing here authorizes or starts that work.
