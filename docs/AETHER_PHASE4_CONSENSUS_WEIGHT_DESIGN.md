# AETHER PHASE 4A -- CONSENSUS WEIGHT / FORK-CHOICE REDESIGN (DESIGN ONLY)

- **Nature**: DESIGN STUDY. No production code, no consensus change, no
  fork-choice change, no difficulty/PoW change, no commit/push/merge/tag/deploy,
  release untouched. Zero `.rs` diffs this phase (verified at the end).
- **Branch**: `dev/phase2-decentralized-network`, from `13b004b`.
- **Standing result**: H2 = REQUIRES_PROTOCOL_CHANGE (3F decision, argued from
  measurement: ~2 PoWs expected per flip, infinite window, TOTAL influence, no
  compatible+effective fix among options A-F).
- **Scope discipline**: max 2 candidate architectures + rejected-others summary
  (no variant sprawl). Bitcoin appears as principle comparison only.
- Companions: CONSENSUS_AUDIT (3A), ECONOMIC_HARDENING sec. H2 (3C measures),
  RESIDUALS sec. H2 + H2_MITIGATION_ROADMAP (3D), H2_GRINDING_ANALYSIS (3F study).

## 1. H2 problem (recap, 1 paragraph)

For any `(sender, account_nonce)` pair with two valid txs, the network keeps
`min(tx.id)` and deletes the other plus its descendant subtree. Ids are hashes
over mostly attacker-shaped content (deterministic Ed25519: no free re-signs),
so the sender pre-computes offline, at any time, a smaller-id variant for ~2
PoWs expected, and evicts the incumbent network-wide on broadcast. Flat price,
infinite window, total influence. Measured, not assumed (3C tests + 3F study).

## 2. Current min-id (formal)

CURRENT: winner(S) = argmin_{t in S} id(t), where S = txs sharing the conflict
key present in the local DAG. Detection: `(sender, nonce)` index/scan. Loser
handling: destructive prune of the loser subtree + storage purge + ledger
rebuild. Consumers: STEP 0 live, canonical resolve at boot, rebuild winners.
Tie frequency: exact ties impossible in practice (256-bit); the rule is total.

## 3. Threat model (for the redesign)

Attacker: key owner (only party able to mint same-key variants), arbitrary
offline compute (1x..Nx honest), full network access (gossip, sync backfill,
partition timing), deterministic-signature constraint (each variant costs a
fresh PoW). Attacker CANNOT: forge others' signatures, rewrite victims'
timestamps, break BLAKE3/Ed25519/X25519/AEAD. Honest nodes: follow the rule,
gossip completely (eventual set convergence assumed -- same assumption as today).

## 4. Required mathematical properties (defined BEFORE architecture)

- MONOTONICITY: adding valid work must never decrease a branch's standing.
- DETERMINISM: same logical DAG set -> same decision, on every node, every run.
- LOCAL_VERIFIABILITY: score recomputable from stored tx fields alone (no
  oracle, no trust, no extra round trips).
- ANTI_GRINDING: generating more ids must not, by itself, displace
  already-committed work (price must scale with what is being replaced).
- PARTITION_CONVERGENCE: honest nodes with converging sets converge decisions;
  NO order-dependent destructive step (see sec. 9: the destructive+view-dependent
  trap).
- NO_FREE_WEIGHT: no consensus weight without the corresponding computational
  cost (volume alone scores nothing).
- DAG_CONSISTENCY: scores respect causality (a tx never outscores its own
  causal past in a way that inverts ancestry; descendants add, never subtract).

## 5. Options A-F (4A lettering)

**OPTION A -- Cumulative PoW (naive global form).** Branch weight = sum of work
of "relevant" txs, scope undefined. VERDICT: underspecified -- without an
ancestry rule it collapses to global-DAG sum (same for all conflicts: decides
nothing) or to per-subtree sums (which IS option C). Kept as baseline row only.

**OPTION B -- Weighted DAG (per-tx PoW credit propagated through sub-DAG).**
Each tx carries work credit; descendants add their credit upward (visited-set
uniqueness on diamonds). VERDICT: viable mechanics -- converges, in fact, to
option C's numbers with different bookkeeping. Retained as C's implementation
twin, not a separate contender (no variant sprawl).

**OPTION C -- Cumulative Work + DAG ancestry (CDW).** Score(X) = WORK(X) +
sum of WORK over the UNIQUE descendant closure of X, where WORK(t) =
2^(actual leading-zero bits of t's PoW hash) = expected hashes priced exactly,
rewards over-mining, no oracle, always recomputable. Conflict winner = highest
score; ties (common: childless same-difficulty pairs) -> min-id tiebreak
(deterministic total order preserved). Loser handling: RETAINED UNAPPLIED with
deterministic re-resolution (see sec. 9 why retention is load-bearing, not optional).
VERDICT: PRIMARY candidate (sec. 10).

**OPTION D -- Virtual/deterministic work score (work + structural extras:
depth penalties, diversity bonuses, age terms).** VERDICT: rejected -- every
extra term is a new gameable knob with no security proof; age/depth views
differ across nodes (determinism risk); complexity without demonstrated gain
over C.

**OPTION E -- Hybrid work + deterministic tie-breaker.** In the bucketed form
(work CLASSES + min-id within a bucket): bucket boundaries create
cliff games (1 unit of work flips classes); coarse-graining buys nothing over
C's exact comparison + min-id tiebreak (which E collapses to). As a
standalone family: rejected in favor of C. (A *gated* variant -- work-threshold
finality keeping min-id inside the window -- survives as BACKUP, sec. 10.)

**OPTION F -- New architecture (BFT/stake/vote/leader).** Out of track: discards
the permissionless-PoW DAG premise (different system, different threat model,
multi-year redesign). Recorded, not pursued.

## 6. Comparison matrix (per option; scale: strong/partial/weak/absent)

Columns: (1) anti-grinding, (2) double-spend resistance, (3) Sybil resistance,
(4) determinism, (5) DAG convergence, (6) honest compute cost, (7) attacker
compute cost, (8) memory, (9) sync cost, (10) implementation complexity,
(11) ledger compat, (12) persistence compat, (13) crash/restart compat,
(14) deep-sync compat, (15) P2P compat, (16) incremental computation,
(17) local verifiability, (18) simulatability, (19) wire change,
(20) genesis change, (21) migration, (22) new attack surface.

- A (min-id): (1) absent (~2 PoWs) (2) weak (0-conf reversible) (3) n/a
  (permissionless) (4) total (5) total (6) O(1) (7) flat ~2 PoWs (8) O(1)
  (9) O(1) (10) shipped (11-15) native (16) n/a (17) total (18) done (19-20)
  none (21) none (22) grinding (documented).
- B (=C mechanics): same row as C below.
- C (CDW+retention): (1) strong (price scales with incumbent subtree work)
  (2) strong with confirmations (weak at d=0 -- honest, see sec. 9 numbers)
  (3) unchanged-permissionless (work-priced, no identity game) (4) total
  (pure set function) (5) total VIA retention (sets converge -> winners
  converge; destructive variant would diverge -- sec. 9 proof) (6) O(subtree)
  per decision, cacheable/incremental (mirror of current weight walks)
  (7) scales with victim confirmations (8) O(conflicts retained) -- bounded by
  retention policy (Phase-4B design item) (9) serve full sets incl. unapplied
  losers (minor inventory growth) (10) high (score + retention lifecycle +
  re-resolution) (11) compatible (ledger applies winner chain only)
  (12) compatible (same rows + optional work-cache column, recomputable)
  (13) compatible (recompute from persisted set, deterministic) (14) compatible
  (ancestor-closed pages already the unit) (15) compatible + version bump
  (rule negotiation) (16) yes (incremental mirror of adjust_ancestor_weights)
  (17) total (recompute from fields) (18) yes (see sec. 13 numbers)
  (19) NO (same bytes) (20) NO (21) YES -- consensus break (versioned
  activation, mixed split, testnet reset discussion) (22) work-inflation
  attempts (priced out -- volume without work scores nothing), majority-work
  (inherent to work systems, stated), retention-exhaustion (bounded by policy).
- D: (1) partial (2) partial (3) unchanged (4) AT RISK (view-dependent terms)
  rest comparable-to-C cost with higher (10)(22). Rejected.
- E-bucketed: (1) partial (cliff games) (4) total (5) total (22) boundary
  gaming. Rejected in favor of C's exact comparison.
- E-gated aka BACKUP (min-id + work-threshold finality): (1) partial (flat
  rate inside window; window now finite) (2) partial (young payments still
  reversible) (4) total except threshold-boundary view splits (RESIDUAL --
  partition aligned with threshold crossing splits permanently; rare but real)
  (10) low-medium (one gate + threshold constant) (21) YES but SMALLER blast
  radius than C (only late replacements behave differently) (22) threshold
  calibration burden + boundary splits. Backup, eyes open.
- F-BFT: out of track (row omitted deliberately).

## 7. Security argument (primary)

CDW satisfies sec. 4: MONOTONIC (scores sum non-negative work over supersets),
DETERMINISTIC (pure set function; min-id tiebreak totalizes), LOCALLY
VERIFIABLE (recompute from stored fields), ANTI_GRINDING (id order affects
only exact ties; displacing work W costs > W fresh hashes -- the 3F gap
closed by construction), PARTITION_CONVERGENT (retention keeps decisions
revisable; set convergence implies winner convergence -- with the destructive
variant PROVEN divergent, hence retention is part of the design, not an
add-on), NO_FREE_WEIGHT (credit = expected hashes, denomination-free:
20-bit and 24-bit paths price identically per hash), DAG_CONSISTENT
(descendants add via unique closure; parents never outscored by own past
alone... plus min-id stability for ties).

## 8. Attacker model A-M vs recommended designs

- A-D (1x/2x/4x/8x honest compute): min-id flip price flat ~2 PoWs at ANY
  multiple (excess compute buys nothing today). CDW: flipping a payment with
  honest subtree work W costs > W fresh hashes -- 8x compute flips <=8x-confirmed
  payments only; d=20 needs ~21 PoWs (measured curve sec. 13) vs 2 today.
- E (grinding): CDW-immune except exact ties (bounded influence, stated).
- F (Sybil identities): no identity game in any option (work-priced, same as
  min-id); volume without work scores nothing (inflation answer).
- G (partial eclipse): deterministic given held set in all options; delays
  discovery only.
- H (partition): merge re-evaluates over union; convergent under CDW+retention
  (proven shape), divergent under destructive-dynamic rules (proven trap).
- I (withheld branch): must exceed accumulated work at release under CDW
  (expensive) vs free under min-id (no timing constraint -- strictly worse
  than slot systems today).
- J (double-spend): needs sustained work > confirmation threshold (C) vs ~2
  PoWs any time (today).
- K (mass conflicts): per-pair independent in all options; each priced.
- L (spam): spam without work scores nothing under CDW (the ETAPE-9 answer:
  weight = SUM OF WORK UNITS, denomination-free -- 100x 20-bit txs = 100M
  hashes of weight, exactly priced, no bonus).
- M (private fork): must out-work the public union to matter at merge (C);
  free under min-id.

## 9. DAG example + the descendant-coverage rule + double-spend walkthrough

Shape: A with children B, C; B with D, E; C with F. Let unit = 2^24 (24-bit
txs; a 20-bit tx credits 2^20 = 1/16th -- same scale, no special case).
work(B) = 1 + D + E = 3 units; work(C) = 1 + F = 2 units. B wins ties-vs-C
*although locally identical*, purely on descendant work. RULE (ETAPE 8
answer): more descendants win ONLY insofar as they carry verified work --
count alone scores nothing (D,E,F each contribute their own credits; empty
or unfunded descendants contribute zero). B-with-less-local-but-more-
descendants is therefore CORRECT, not an anomaly: descendants are sunk honest
work referencing B.

Double-spend under PRIMARY: TX_A / TX_B same key detected as today (index);
scores computed over the current union (unique closures); winner applies,
ledger replays winner chain; loser RETAINED UNAPPLIED (new lifecycle) with
re-resolution on every descendant-closure mutation; descendants of the loser
stay unapplied while their inputs are unapplied (effects follow applied
ancestors -- edge cases with cross-funded descendants are Phase-4B design
items); restart rebuilds scores+winners from the persisted set
(deterministic); sync serves full sets.

The destructive+dynamic trap (WHY retention is load-bearing): deciding B-vs-A
on partial subtrees then DELETING splits nodes on arrival order (Order 1:
{B+5} vs Order 2: {A+3}, both final -- permanent split; worked example in
analysis notes). Destructive + view-dependent NEVER converges; destructive +
static (min-id) converges; dynamic + retentive converges. Hence: dynamic
scores REQUIRE retention. The 3C sketch ("swap the comparison only") is
hereby SUPERSEDED -- recorded explicitly so no future reader reverts to it.

## 10. Decision (max 2, justified)

- PRIMARY_DESIGN = Cumulative Descendant Work (actual-bits work credits) +
  min-id tiebreak + loser retention with deterministic re-resolution. Closes
  the vulnerability class (convergence argued above); preserves determinism,
  local verifiability, and the entire prune/rebuild/storage/sync machinery
  shape (only winner selection + loser lifecycle change).
- BACKUP_DESIGN = work-gated min-id replacement window (min-id decides while
  the incumbent subtree work is below threshold W; at/above W the incumbent
  is final). Minimal delta, closes the INFINITE window, keeps min-id
  machinery; residual: threshold-boundary view splits + in-window flat-rate
  grinding + threshold calibration burden. Deployable faster, weaker guarantees.
- Justification: primary is the only option that is effective, convergent,
  and determinism-preserving; backup is the honest minimal fallback. All
  others rejected with reasons in sec. 5 (no 10-variant sprawl).

## 11. Migration implications (detail in MIGRATION_PLAN.md)

CONSENSUS_BREAK = YES (different winners on contested keys). Grandfathering
recommended: conflicts settled before activation stay settled (avoids
re-resolving ancient history + bounds sync cost). P2P version bump YES;
wire NO; store NO (+optional recomputable work cache); genesis NO; network
YES (coordinated upgrade / testnet reset discussion). Never smuggled: HEAD
implements OPTION A only.

## 12. Test plan (FAST/MEDIUM/HEAVY/RELEASE-ONLY; no debug marathons)

- FAST (unit, ms): work-credit vectors (leading-zero counts incl. boundary
  difficulties 20/24/over-mined); score arithmetic on fixed DAGs (diamond
  double-count exclusion, empty closures, tie=min-id); determinism matrix
  (same set, shuffled insertion orders -> identical scores/winners);
  retention lifecycle (unapplied states, re-resolution triggers).
- MEDIUM (sim harnesses, small DAGs, pre-mined or difficulty-1-equivalent
  fixtures where policy allows... note: fixtures must satisfy CURRENT policy
  at authoring time -- lesson from 3B): partition-merge under CDW (both
  arrival orders -> identical winners); withheld-branch cost bounds;
  orphan interplay with retained losers.
- HEAVY (bounded): grind-vs-work bounds with REAL PoW (attacker multiples
  1/2/4/8 vs depths, asserting measured price >= model); massive-conflict
  soak (retention bounds under flood).
- RELEASE-ONLY: all PoW-mining tests (semantic identity: pure functions;
  wall-time differs) + the full validation battery strategy from 3B
  (pre-mined fixture cache or release profile).
- Malformed DAG (cycles impossible by construction -- parent-existence gate;
  pin it), Sybil-volume (weight==work proof), restart equivalence,
  ledger equivalence, deep-sync under work rule, work-inflation attempts.

## 13. Simulation (bounded, off-repo, uncommitted -- TEMP script, this phase)

Deterministic seeds; min-id attempts (Monte-Carlo over 64 fixed rivals) vs
CDW closed-form (attacker needs strictly more work units than the honest
subtree; cheapest denomination wins ties toward the attacker -- worst case).

d | min-id hashes (E) | CDW hashes, 24-bit path | CDW hashes, 20-bit path | ratio
0 | 33,554,432 | 33,554,432 | 17,825,792 | 1.0
1 | 33,554,432 | 50,331,648 | 34,603,008 | 1.5
5 | 33,554,432 | 117,440,512 | 101,711,872 | 3.5
20 | 33,554,432 | 369,098,752 | 353,370,112 | 11.0

min-id attempts over 64 rivals: mean 3.75 (E=2; tail from small rivals --
the documented scaling law). Reading: min-id price FLAT (~2 PoWs) at every
depth; CDW price SCALES with confirmations (11x at d=20); 20-bit vs 24-bit
paths converge with depth (denomination-free pricing -- the inflation answer).
At d=0 CDW is NOT stronger (granularity favors small units) -- stated plainly:
the moat materializes with confirmations, which is exactly the
receiver-confirmation story. No billions of hashes burned (us-class script).

## 14. Unresolved questions (for Phase-4B design, NOT this study)

Retention bound exact rule (work-margin deletion vs TTL+re-fetch vs archive
tier); re-resolution trigger granularity (per-mutation vs batched);
work-function final form (actual-bits recommended vs class units);
tie-break chain beyond min-id (settled: min-id); threshold constants (backup
only); fee interaction (kept out of consensus by default -- confirm);
cross-funded descendant edge semantics; work-cache schema (optional).

## 15. Comparaison Bitcoin (descriptive; no "better")

- AETHER_CURRENT_MIN_ID: flat-rate replacement (~2 PoWs expected), infinite
  window, total influence, deterministic, convergent.
- AETHER_PROPOSED_WEIGHT (CDW+retention): depth-scaled replacement price,
  deterministic, convergent via retention, same wire/store shapes.
- BITCOIN_STYLE_WORK_WEIGHT: work-weighted fork choice (heaviest chain);
  reorg price scales with confirmations; probabilistic finality by depth.
- Difference: Aether has no work weight today; proposed adds DAG-native work
  weight without blocks/leaders. Potential advantage: grinding priced out
  with confirmations. Cost: retention lifecycle + migration break + threshold
  calibrations (backup). Maturity: design-stage (this document) vs 15+ years
  adversarial production -- no equivalence claimed.

## 16. AS-BUILT (Phase 4B implementation record)

Implemented as specified with the following pinned-down decisions (all open
questions from sec. 14 now closed except stated deferrals):

- Work function: ACTUAL-BITS confirmed (`2^(leading zero bits)`, saturating
  u64). Class-units alternative dropped (timestamp-gameable at class edges;
  actual-bits prices exactly what was paid).
- Retention lifecycle: FULL retention, no deletion, no tombstones, no
  expiry. Rationale: any deletion reintroduces view-divergence (proven trap);
  retention growth is the same cost class as baseline DAG spam (every retained
  tx cost a valid PoW+signature+fee). Work-margin deletion stays a documented
  future trigger, not implemented.
- Re-resolution: T1 member arrival + T2 conflict-descendant arrival (ancestor
  walk, O(depth)) + T3 boot/deep-sync full recompute. NO memoized winners or
  scores anywhere (purity over caching -- zero staleness vectors). NO periodic
  task (insert-cover is complete; no production removals exist to miss).
  Conditional rebuild (only on flips) in both STEP 0 and normal paths.
- Grandfather predicate (exact): conflict uses min-id iff ALL members have
  timestamp strictly below CDW_ACTIVATION_TS (1_758_000_000_000); otherwise
  CDW + min-id tiebreak. Boundary (==) counts post-activation (tested).
- Activation: constant shipped, rule live immediately (all live traffic
  post-dates it; all historical fixtures pre-date it -- every old test keeps
  its winner selection). P2P_PROTOCOL_VERSION 4 -> 5 shipped (handshake gate
  splits mixed networks loudly).
- Insertion: uniform retention (no era check in the hot path); era-gating
  lives ONLY in winner selection. validate_ledger SKIPPED on the conflict
  path (winners unfundable in loser-world); funding evaluated at rebuild in
  winner-world. No live transfer on conflict path (effects via rebuild only).
- 3C sketch correction stands: "swap the comparison only" was PROVEN
  insufficient (destructive+dynamic diverges); retention is load-bearing.
- Deviations from sketch: none substantive (conditional-rebuild instead of
  always-rebuild is a strict optimization with identical outcomes; periodic
  recompute dropped as redundant, argued above).
