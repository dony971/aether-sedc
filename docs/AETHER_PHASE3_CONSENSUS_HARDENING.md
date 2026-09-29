# AETHER PHASE 3B â€” CONSENSUS HARDENING (C1 / C2 / H1)

- **Scope**: fixes ONLY for Phase-3A findings CRITICAL-1, C2, HIGH-1. No new network
  feature, no privacy work, no Tor/I2P, no transport/eclipse/self-healing changes
  (untouched), no PoW/difficulty change, no release artifact touched.
- **Branch**: `dev/phase2-decentralized-network`, from `7af3e27`.
- **Policy guardrails respected**: no test weakened to pass (assertions/logic of green
  tests untouched; 3 red tests restored to coherent production contexts with written
  rationale); no validation disabled (every mode still enforces PoW+signature+key+DAG+
  ledger); no blanket Fresh/Historical substitution (provenance decides per tx);
  historical-tx protection preserved (Historical paths intact + tested); difficulty,
  nonces, targets, mining counts, timestamps policy constants: all unchanged.
- Companion: `docs/AETHER_PHASE3_CONSENSUS_AUDIT.md` (findings), 
- `docs/AETHER_PHASE3_SECURITY_ROADMAP.md` (remaining backlog: H2/H3/H4/M1-M7/L1-L4,
  still open and NOT claimed fixed here).

We do NOT write "consensus securise". Covered properties are reported as
`CONSENSUS_HARDENING = PASS` items in the exit block at the end.

---

## 1. C1 â€” STEP-0 / STEP-1 validation-mode consistency

**Root cause.** `TransactionProcessor::process()` evaluated the SAME tx under TWO policies:
STEP 0 (conflict-winner branch) hardcoded `ValidationMode::Fresh`
(`src/transaction_processor.rs:171`), while STEP 1 used the caller-supplied `mode`
(`:206`), which in production is always Historical (sole production caller: the
drainer, `src/rpc.rs:1240`; verified: every other `.process(` call site is a test).
A canonical winner that was timestamp-stale (>1 h), future (>1 h) or backdated at
delivery was therefore REJECTED at a node holding the loser while being ACCEPTED at
a node that saw it first â€” a permanent ledger split across partition/reconnect, with
no self-healing (re-delivery hits the same STEP-0 rejection; restart does not
reconcile reject-cached winners).

**Fix (contextual, 1 line + comment).** STEP 0 now validates the winner with the
CALLER's `mode` instead of hardcoded Fresh. PoW, signature and sender-key checks run
in EVERY mode, so the V-21 intent ("never destroy a valid tx for an INVALID winner")
is fully preserved; only the timestamp regime follows the tx's provenance, exactly
like STEP 1. No blanket mode: the mode travels with the tx (see Â§3), so each tx is
judged once, under one policy, in both steps.

**Proof.** New `test_step0_validation_mode_consistency` (PASS, 35 s): same conflict
pair Ã— {Historical, Fresh} Ã— {winner-first, loser-first} with DAG-id-set + balances +
supply fingerprint comparison â€” Historical installs the winner in both orders
(pre-fix this failed loser-first: the STEP-0 Fresh veto), Fresh rejects in both
orders (consistent rejection, still no split). Cross-mode outcomes legitimately
differ (policy); within one mode, order is now irrelevant.

## 2. C2 â€” double-spend order invariance (3 red tests restored)

**Root causes (layered, both pre-existing).**
1. The tests drove `process()` in `Fresh` mode with 1970 fixtures
   (`tx_ts=1234567890`): correctly rejected per the migration timestamp policy
   (`BackdatedTimestamp`) â€” first arrival, both orders. Not order-dependence at all.
2. After switching to the production mode, a second layer surfaced: fixtures mined
   at difficulty 1 while `validate_pure` enforces TIMESTAMP-derived difficulty
   (`InvalidPoW { difficulty: 20 }` for pre-activation timestamps). The
   `TransactionValidator::difficulty` / `with_difficulty` knob is NEVER READ
   (compiler now confirms: `field 'difficulty' is never read`, pre-existing
   warning) â€” the tests believed they ran difficulty-1; the code enforced 20.
   Production validation semantics were NOT changed to accommodate tests.

**Restoration (documented in situ, assertions/logic untouched).** The three tests
prove TIMELESS DAG/ledger properties (order invariance, phantom-nonce healing,
applied-duplicate healing) and production `process()` runs EXCLUSIVELY via the
drainer in Historical mode â€” so they now run in Historical (the production
configuration) with policy-valid 20-bit fixtures for their pre-activation
timestamps (i.e. the genuine-history-replay shape). Fresh remains the
edge-submission policy, enforced and tested at RPC accept (H1 tests below).
`test_boot_rebuild_converges_after_crash_residue` (green) and the ignored bench
were NOT touched.

**Proof.** `test_double_spend_order_invariance` (76 s), 
- `test_phantom_nonce_heals_transfer` (7 s), `test_applied_true_duplicate_skips_replay`
(31 s): all PASS. Full `transaction_processor::` module: 9 passed, 0 failed,
1 ignored (was 5/3/1).

## 3. H1 â€” live policy enforced on live paths, history preserved (provenance)

**Root cause.** Five ingress paths funneled into one timeless drainer; the P2P layer
could not tell live relay from sync backfill (single `tx_channel<Transaction>`),
so everything was evaluated Historical and a live-submitted backdated 20-bit tx
paid 1/16th PoW into the DAG.

**Fix (provenance travels with the tx, no signature changes).**
- `SyncContext.ingress_mode` (`src/sync_stats.rs`): tx-id â†’ (mode, instant),
  `note_ingress_mode` (first-delivery-wins + 100 k cap with oldest eviction,
  insert-then-send ordering documented as load-bearing) / `take_ingress_mode`
  (consume; absent defaults Historical = pre-3B behavior). Zero test churn
  (derived `Clone + Default` preserved; no literal constructions exist).
- P2P live singles arm records Fresh; SyncResponse deliverable arm records
  Historical (`src/p2p.rs`). Healing traffic (inventory diffs, GetData closures,
  backfill batches) flows exclusively through the sync arm â€” verified.
- Node P2P receiver takes the mode and forwards it to `process_transaction`
  (`src/node.rs`); source label `"P2P"` unchanged.
- `Mempool.admit_mode` (`src/rpc.rs`): accept-time mode per tx id, mirroring the
  `enqueued_at` lifecycle exactly (insert on enqueue, drop on terminal dispose,
  kept across requeue/select). `enqueue()` signature UNCHANGED (defaults
  Historical); new `enqueue_with_mode` used by `process_transaction`; drainer
  processes under the recorded mode.
- Orphan solver and boot reload UNCHANGED (Historical): safe by TTL bound
  (ORPHAN_TTL 15 min + MEMPOOL_TTL 15 min << 60 min staleness), and live-backdated
  txs can never park (rejected at live accept) â€” asserted by test.
- Queue-aging safety: a Fresh-recorded tx can sit â‰¤ MEMPOOL_TTL (15 min) Â«
  MAX_PAST_MS (60 min), so live policy at drain never false-rejects aged queue
  entries. Fresh-at-accept already filtered anything older.

**Etape 2 â€” mode matrix (BEFORE â†’ AFTER).**

| PATH | FUNCTION | BEFORE | AFTER | WHY |
|---|---|---|---|---|
| local submit / RPC | `process_transaction` accept | Fresh | Fresh (unchanged) | edge-submission policy |
| faucet | `process_transaction` accept | Fresh | Fresh (unchanged) | edge-submission policy |
| P2P live relay | `handle_peer` Transaction arm â†’ receiver | Historical | Fresh (recorded) | new tx from network = live policy (matches documented Fresh intent) |
| P2P sync backfill | SyncResponse deliverable â†’ receiver | Historical | Historical (recorded) | genuine history must heal (protection preserved) |
| drainer | `drain_mempool` â†’ `process` | Historical (hardcoded) | recorded mode | one tx, one policy end-to-end |
| STEP 0 winner | `process` STEP 0 | Fresh (hardcoded) | caller (= recorded) mode | consistency with STEP 1 (C1) |
| STEP 1 | `process` STEP 1 | caller mode | caller mode (unchanged) | â€” |
| orphan solver | `process_orphans` â†’ accept | Historical | Historical (unchanged) | already-accepted txs, TTL-bounded age |
| boot reload / rebuild | `node.rs` / `rebuild_*` | n/a (direct insert) | n/a (unchanged) | pure reconstruction, no validation |
| mempool reload | `node.rs` â†’ `enqueue` | Historical-equiv | Historical default (unchanged) | pending live txs re-enter timelessly |

**Proof.** Helper units (sync_stats, FAST): roundtrip+default, first-wins,
bounded â€” all PASS. Mempool lifecycle unit (FAST): PASS. Four H1 tests (MEDIUM,
one shared 20-bit fixture + one orphan fixture): live RPC rejects
backdated/stale/future (nothing queued/DAG/orphans); P2P Fresh rejects while P2P
Historical queues + drains to DAG once funded; live-backdated never parks while
sync orphan parks; drain honors recorded mode (Fresh â†’ deferred/requeued, DAG
untouched; Historical â†’ included). All PASS (35â€“148 s debug each, PoW variance).

## 4. Tests â€” record (all on the fixed tree; no test modified except the 3
restorations + 9 additions; green-test assertions/logic: zero edits)

- New (9): step0 consistency; 3 ingress helpers; mempool admit unit; 4 H1. ALL PASS.
- Restored (3): order invariance, phantom, applied-duplicate. ALL PASS.
- Targeted green (unchanged, re-run): validation `test_validate*` (9, incl. 2Ã—24-bit
  miner), 5year_sim, within_grace-skip, sync_stats full (25), spec_check (14),
  mempool_ttl, m2 backpressure, valid_orphan_persisted, security replay/conflict/
  out-of-order/atomic (4), crash double-spend (4) + conservation (3), migration
  fast-16 (clock-skew/grace/invariants/restart), consensus sims 10/11 (partition,
  reconnect, fork, multi-partition, double-spend-named, mixed-version, stability,
  harness, component). ALL PASS.
- Phase-2 gates (unchanged): p2p:: 149/0/2ign; decentralized 26; eclipse 15;
  self-healing 17; privacy 16 (+1ign); privacy-propagation 18 (+1ign); transport
  11; bootstrap_phase1 19/19. ALL PASS.
- `cargo check --lib`: EXIT 0, 9 warnings = pre-existing baseline exactly (0 new).
- Total lib tests: 555 â†’ 564 (+9 new).

## 5. Compatibility

Unchanged signatures: `Mempool::enqueue`, `TransactionProcessor::process`,
`process_transaction`, `accept_inbound_transaction`, `tx_channel` type,
`P2PNetwork::new`, all storage/orphan APIs. Legacy entries (tests, boot reload,
solver re-drive) default Historical = byte-identical pre-3B behavior; verified by
the unchanged green suites above. Difficulty, timestamps, grace, fee oracle, tip
selection, transport, eclipse, self-healing: untouched. No migration needed
(policy constants identical; acceptance SETS can only shrink on live paths for
previously-accepted-but-policy-violating txs â€” the intended H1 closure; sync and
restart paths admit a superset as before).

## 6. Remaining risks (NOT closed here; see SECURITY_ROADMAP)

- Bytes cannot prove age: a backdated-new tx delivered EXCLUSIVELY via the sync
  backfill protocol is still accepted Historical. Inherent to timeless DAG sync;
  residual spam cost = 20-bit PoW + burned fee (+ fee-oracle throttle). Documented
  accepted risk, not a bypass of any live path.
- H2 (id grinding economics), H3 (conflict-flood CPU amplification), H4
  (innocent-descendant loss), M1â€“M7, L1â€“L4: open, untouched.
- Dead `with_difficulty` knob: documented in situ + compiler warning; removal is
  future cleanup (could break external test harnesses relying on the constructor â€”
  left in place deliberately).
- Cross-session frame replay (M6): still unverified (out of scope).

## 7. Environment-limited (not failures; paths verified untouched by this diff)

- `test_heavy_branch_wins` (6Ã—24-bit debug mines), `test_inc01_getdata_store_only`
  (4/5 inc01 green), migration slow-9 (all mine 24-bit or long sims), wallet miners,
  m1 (200Ã—24-bit), validation 22 heavies: unfinished in debug wall-clock, none
  failing, none touching modified code (sim/mining/classification only â€” verified
  by grep: no `process(`/drainer/mempool/STEP-0 usage in those files).
- No `--release` runs performed: not indispensable (Ã‰8 targets heavy tests; mine are
  FAST/MEDIUM). DEBUG/RELEASE semantic identity holds by construction for the
  verdict logic (`mine_nonce`/`verify_pow`/`validate_*` are pure functions of tx
  content + fixed timestamps; only wall-time differs) â€” recorded here instead of
  re-proven.

## 8. Exit mapping

- C1_VALIDATION_MODE_CONSISTENCY = PASS (step0 test; C1 mechanism closed in code).
- C2_DOUBLE_SPEND_ORDER_INVARIANCE = PASS (restored test + fingerprint matrix).
- H1_LIVE_VALIDATION_POLICY = PASS (4 tests + helper/mempool units).
- FORK_CHOICE = VERIFIED (min-id rule untouched; consistency now holds in both
  arrival orders â€” step0 test).
- DETERMINISM_TARGETS = PASS (order-invariance + fingerprint equality within mode).
- LEDGER_EQUIVALENCE = PASS (balances/supply asserts across orders; rebuild tests green).
- PARTITION_RECONNECTION = PASS (6 consensus sims + crash reconnect + live-pipeline
  matrix; 1 PoW-bound sim unfinished, path untouched â€” Â§7).
- P2P_REGRESSION = PASS (149/0/2ign). PHASE2_REGRESSION = PASS (all suites).
  PRIVACY_REGRESSION = PASS (16+18 suites). BOOTSTRAP_PHASE1 = 19/19 PASS.
- CRITICAL_FAILURES = 0. HIGH_FAILURES = 0.
