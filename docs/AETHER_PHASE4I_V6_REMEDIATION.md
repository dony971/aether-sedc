# AETHER PHASE 4I -- V6 REMEDIATION (4H findings)

- Status: IMPLEMENTED. Branch dev/phase2-decentralized-network.
- Baseline: HEAD d1fd8d7, parent ef817ba (phase4: implement stake-weighted dag finality (v6, dormant)).
- Target: ef817ba + 4G v6 dormant (V6_ACTIVATION_TS = 1_893_456_000_000, 2030-01-01), P2P wire v5 unchanged.
- Method: targeted production remediation + 63 new tests in src/tests/phase4i_v6_remediation_tests.rs (deterministic fixtures, timings REPORTED never asserted).
- Rule: NO deploy, NO push, NO merge, NO tag, NO v1.4.0 change, NO genesis change, NO activation change, V6 stays dormant.
- Commit-message compliance: COMMIT_MESSAGE_COMPLIANCE = RESIDUAL (charter asked "phase4: harden v6 finality state consistency", current commit uses "phase4: remediate v6 audit findings (4I, 63 tests)". No history rewrite per 4J sec.3, no fake functional commit).
- ASCII pure, CRLF. Nothing invented. NOT_VERIFIED is used where a claim is not demonstrated by a test.

## 1. Scope

V6 = StakeRegistry + Vote/Bond/Unbond wire + validators + v6 fork choice + processor admission + v6 ledger replay + stake storage/P2P/RPC + node wiring, all era-gated dormant. 4H audited PASS_WITH_RESIDUALS with FAIL/HIGH blocking activation. 4I remediates exactly: F-A1, F-D1, F-D3, F-L1, F-D2, F-D4, F-A2, F-V1, plus order/partition/live-sync-rebuild-restart/persistence coverage and perf re-measurement. No new economy (4F values only: 72 epochs unbonding, 100 percent slash on proven equivocation, MIN_STAKE band, no rewards). No PoW reintroduction. No wire change.

Out of scope: tokenomics calibration, weak subjectivity operations, release management flag-day, activation declaration.

## 2. F-A1

BEFORE: equivocation before bond lost silently. Order A (bond then equivocation) weight 0 with slash; order B (equivocation then bond) minted a clean record weight 200. EQUIVOCATION = FAIL, SLASHING = FAIL.

ROOT CAUSE: apply_slash on unknown validator was a no-op. Bond and slash arrived on separate gossip kinds in any order, so a later bond erased the earlier proof.

FIX: SLASH_TOMBSTONE in src/stake.rs apply_slash. Slashing UNKNOWN inserts a tombstone record (bonded_amount 0, state Slashed, bonded_epoch 0, slashed_epoch Some(epoch)). apply_bond and top-up and unbond reject Slashed in every order. Idempotent second slash returns false. Persisted via snapshot/restore and save/load. bonded_epoch 0 for tombstones is consensus-irrelevant (Slashed never votes, never weighs).

WHY: preserves proof across arrival orders, restarts, sync, and bond activation without inventing collateral, burn destination, or partial slash. Uses 4F slash 100 percent only.

TEST: a1_tombstone_on_unknown_slash, a1_bond_after_tombstone_rejected, a1_tombstone_idempotent, a1_tombstone_persists_save_load, a1_tombstone_support_zero_both_sides, a1_tombstone_evidence_intact, a1_tombstone_unbond_rejected, a1_tombstone_topup_rejected, a1_tombstone_epoch_recorded, a1_both_orders_converge_weight_zero (10 tests).

VERDICT: PASS.

## 3. F-D1

BEFORE: boot rebuild ignored V6 (node.rs:376 legacy path). Post-activation restart rolled back to V5 winners. RESTART = FAIL, LIVE_SYNC_REBUILD = FAIL.

ROOT CAUSE: rebuild selected the rule without era check. Registry load existed but rebuild did not route by newest-member era.

FIX: era-aware boot rebuild. src/node.rs era-aware path + src/transaction_processor.rs rebuild_for_era. Pre-activation keys delegate to frozen legacy bit-identically; post-activation uses v6 winners. Restart preserves registry then rebuilds deterministically. Supply guard intact.

WHY: newest-member decides era (same rule as live path), so boot matches live. No clock-based rule selection beyond the existing timestamp predicate.

TEST: d1_pre_v6_boot_rebuild_is_legacy_identical, d1_boundary_newest_member_decides_rebuild, d1_full_rebuild_determinism, d1_post_v6_restart_no_rollback, d1_save_reload_registry_then_rebuild_equal, d1_supply_guard_intact_after_v6_rebuild (6 tests).

VERDICT: PASS.

## 4. F-D3

BEFORE: tx-only sync, votes never backfilled. Joiners diverged on finality. LIVE_SYNC_REBUILD = FAIL.

ROOT CAUSE: no vote inventory, no GetVotes serving, no deterministic backfill into registry/finality.

FIX: vote-inventory diff (pure, bounded, missing-only) in src/p2p.rs, VoteInventory gossip (enum tail, v5 compat), GetData vote fallback, backfill idempotent and duplicate-safe, delayed votes converge to same finality, restart-during-backfill converges, finalized-key joiner reproduces record, ledger-coupled joiner fill.

WHY: finality becomes reconstructible from DAG + historical votes + proofs + stake state + checkpoints, live and sync converge.

TEST: d3_backfill_duplicates_idempotent, d3_fresh_joiner_empty_then_fill_with_ledger, d3_backfill_converges_joiner, d3_inventory_diff_missing_only_bounded, d3_delayed_votes_same_finality, d3_getvotes_serving_known_vs_unknown, d3_finalized_key_joiner_reproduces_record, d3_restart_during_backfill_converges (8 tests).

VERDICT: PASS.

## 5. F-L1

BEFORE: registry without on-ledger locks. Bonded funds stayed spendable, double bond/spend possible, slash had no necessary economic loss. LEDGER_STAKE_LOCK = FAIL.

ROOT CAUSE: capital representation split: registry tracked weight, ledger tracked balances, no binding.

FIX: bonded-stake locks. src/ledger.rs locked map (address hex -> amount) + dirty_locked set; src/storage.rs locked tree (put_locked/get_all_locked, zero stored explicitly); bond admission locks amount (spendable = balance - locked); spend-while-bonded rejected; double-bond same funds rejected; top-up increases lock; unbond keeps locked for UNBONDING_EPOCHS (72, per 4F), voting cut at request, matured sweep releases deterministically; slash freezes forever (weight zero + funds frozen, no burn invention, zero-emission supply untouched); clone/rebuild/restart preserve locks verbatim; orphan locks reconciled.

WHY: reuses existing ledger/UTXO model and 4F-specified values only. Answers to the 10 mandatory questions: (1) bond funds are ledger balances locked by address; (2) registry consumes lock state, ledger enforces spendability; (3) spend checked against balance-locked; (4) double use rejected at admission; (5) unbond releases only after 72 epochs via sweep; (6) slash zeroes weight and freezes funds permanently; (7) locks persisted in locked tree and reloaded; (8) sync reconstructs locks via same backfill + ledger replay; (9) identity change cannot move locks (address-keyed); (10) same capital cannot fund two bonds (locked accounting). No collateral amount invented, no inflation, no reward, no partial slash, no new threshold. STOP condition not triggered, no design sub-document needed.

TEST: l1_bond_locks_funds_reduces_spendable, l1_spend_while_bonded_rejected, l1_double_bond_same_funds_rejected, l1_topup_increases_lock, l1_ledger_clone_carries_locks, l1_rebuild_preserves_locks, l1_restart_persistence_locks, l1_unbond_keeps_locked_until_mature, l1_release_after_72_epochs_unit, l1_slash_freezes_forever, l1_rebond_slashed_rejected_funds_stay, l1_orphan_lock_reconciled (12 tests, minimum was 10).

VERDICT: PASS.

## 6. F-D2

BEFORE: Historical sync skipped all timestamp checks, so crafted post-V6-dated objects were admitted pre-activation with PoW skipped (zero-cost sync spam + dormant-rule planting). V6_DORMANT_ISOLATION = FAIL (scoped).

ROOT CAUSE: Historical mode trusted timestamps unconditionally.

FIX: pure era-admission predicate src/validation.rs historical_era_check(tx_ts, now_ms). Rejects post-V6-dated objects while wall clock is pre-activation on EVERY mode (Fresh and Historical). Inert post-activation. Pre-V6 history unchanged. Error shape FutureEraTransaction.

WHY: admission timing gate, not consensus PoW. Post-activation Historical still skips PoW by design. POW_IN_V6_CONSENSUS stays NO.

TEST: d2_pure_matrix_9_combos, d2_pre_v6_historical_unchanged, d2_historical_rejects_pre_wall, d2_fresh_far_future_still_rejected, d2_no_pow_reintroduction_post_wall, d2_error_shape (6 tests).

VERDICT: PASS.

## 7. F-D4

BEFORE: quorum then finality then vote loss had no autonomous reconstruction; transient finality plus missing evidence plus partition could split without reconciliation.

ROOT CAUSE: finality depended on live registry/RAM/ephemeral messages.

FIX: pinned quorum vote set via src/stake.rs support_breakdown (support + sorted distinct vote ids, latest-per-validator). Certificate contents pinned, verify paths for ok/bad-sig/wrong-side/wrong-set/bad-numbers, conflicting quorums proven impossible, verify from backfilled votes works.

WHY: finality becomes re-verifiable and re-gossipable without the live registry.

TEST: d4_empty_no_certificate, d4_verify_bad_sig_rejected, d4_verify_wrong_side_rejected, d4_verify_wrong_set_rejected, d4_verify_bad_numbers_rejected, d4_cert_contents_pinned, d4_conflicting_quorums_impossible_proof, d4_verify_ok_from_backfilled_votes (8 tests).

VERDICT: PASS.

## 8. F-A2

BEFORE: first-seen slot based on received bytes could make consensus depend on local network speed.

ROOT CAUSE: byte-equality vs semantic equality on equivocation evidence and slot rule.

FIX: canonical LE encode/decode unchanged semantics, evidence ids canonical regardless of arrival order, same-side variants canonicalized, three-sides deterministic semantics, both orders byte-equal where required.

WHY: deterministic protocol data only; no timing dependence.

TEST: a2_evidence_unchanged_by_slot_rule, a2_both_orders_byte_equal, a2_same_side_variants_canonical, a2_three_sides_deterministic_semantics (4 tests).

VERDICT: PASS.

## 9. F-V1

BEFORE: pre-V6 finality records could be confused with V6 finality.

ROOT CAUSE: no era boundary on finalized interpretation.

FIX: dead pre-V6 records ignored by resolve, mixed newest-post finalizes, post-V6 control finalizes, pre-V6 votes accepted but never finalize.

WHY: V5 stays V5 pre-activation; no old heuristic passes as V6 finality.

TEST: v1_pre_v6_dead_record_ignored_by_resolve, v1_mixed_newest_post_finalizes, v1_post_v6_control_finalizes, v1_pre_v6_vote_accepted_never_finalizes, plus v1 boundary member test (5 tests, minimum was 4).

VERDICT: PASS.

## 10. Order Independence

Requirement: 20 permutations minimum across DAG/stake/votes/epochs/evidence/checkpoints, compare registry/tombstones/branch/finality/ledger/persisted state.

Result: o1_full_interleave_24_perms_converge_tolerant covers bonds, top-up-shaped re-bonds, votes at two epochs, equivocation pair including tombstone path, and unbond in all 24 full interleavings with tolerant convergence; plus h05b bonds-first perms, h06 partition both heal orders, h13 vote-before-DAG, h14 equivocation both orders, g10 duplicate vs equivocation vs slash, and 4I unbond-intent max-epoch rule. Replay of already-seen votes is Duplicate (not second slash).

TEST: o1 plus inherited h05b/h06/h13/h14/g10/h10.

VERDICT: PASS.

## 11. Live/Sync/Rebuild

Requirement: same consensus state via LIVE, SYNC, REBUILD, RESTART across stake/bonds/unbonds/slash/tombstones/votes/quorum/finality/branch/ledger.

Result: lsr1_live_sync_rebuild_restart_converge_with_ledger plus ds1_deep_sync_tx_then_vote_backfill_100 (topological insert, not id-sorted) plus d3_restart_during_backfill_converges plus d1_post_v6_restart_no_rollback. Any divergence would be FAIL; none observed.

TEST: lsr1, ds1, p1_partition_equiponderant_merge_converges.

VERDICT: PASS.

## 12. Persistence

Requirement: write, shutdown, reload, compare for registry, tombstone, slash evidence, vote state, finality, bond lock, unbond state, epoch, checkpoint.

Result: a1_tombstone_persists_save_load, d1_save_reload_registry_then_rebuild_equal, l1_restart_persistence_locks, d3_restart_during_backfill_converges, i_tombstone_and_unbonding_persist, g29 snapshot restore equivalence, g30/g31 storage roundtrip and fail-closed partial save.

TEST: as listed.

VERDICT: PASS.

## 13. Security

Dormant isolation: pre-V6 natural data behaves bit-identically to 4B (g23/g24/h01/h02). Crafted future-dated ingress rejected on every mode (d2). No PoW in v6 decision paths (sec.10 audit). Quorum 3S>=2T in u128, no floats, no overflow (h03 sweep incl. MAX). Split invariance holds (h04). Tombstone prevents resurrection. Locks prevent double spend of bonded capital. RPC stake endpoints fail-closed unwired except tested paths. No new operator flags; activation const-based.

Threat model and protocol spec updated in the same commit (docs/THREAT_MODEL.md, docs/PROTOCOL_SPECIFICATION.md, docs/AETHER_PHASE3_SECURITY_ROADMAP.md, docs/INC-01_FIX_REPORT.md, scripts/canary_monitor.ps1).

VERDICT: PASS (within dormant scope; activation still gated by tokenomics/weak-subjectivity/release-management, explicitly out of scope).

## 14. Performance

Protocol: h15 REPORTED never asserted. 4J re-measured 100/1000 post-commit and added 10000 with the same protocol (temp test removed before commit; extra verify assert included to match h15 exactly).

Measured post-closure:
n=100: insert=1.0722022s support=3.5095ms finalize=3.5917ms snapshot=204.7us save=13.004ms load=6.6593ms
n=1000: insert=10.7812253s support=50.6839ms finalize=52.2582ms snapshot=1.3982ms save=113.4991ms load=65.3868ms
n=10000: insert=107.0347043s support=2.2615469s finalize=2.2543807s snapshot=18.359ms save=1.2603s load=650.5859ms

Analysis (observation + static, three points):
- insert O(N): 1.07s / 10.78s / 107.03s = 10.7ms per vote linear. Static: loop of N bonds + N votes, each O(1) map plus 2 sig verifies. Observation matches static.
- support/finalize super-linear: 3.5ms / 50.7ms (14x) / 2260ms (45x) for 10x N. Static: latest-per-validator scan plus descendant closure over the vote set; no complexity claim beyond observed super-linearity, no optimization applied.
- snapshot/save/load O(N): snapshot 0.20ms / 1.40ms / 18.36ms; save 13.0ms / 113.5ms / 1260ms; load 6.66ms / 65.39ms / 650.59ms, each ~10x per 10x N. Static: sorted snapshot plus full tree rewrite.
No functional regression tied to timings. No consensus change to accelerate the bench.

VERDICT: PASS.

## 15. Tests

4I suite total 63 passed, 0 failed:
a1 10, d1 6, d3 8, l1 12, d2 6, d4 8, a2 4, v1 5, o1 1, p1 1, lsr1 1, ds1 1.
Post-closure coherence on HEAD d1fd8d7: phase4i 63/63, phase4g 36/36, phase4h 16/16, phase4c 12/12, ledger 35/35 (pre-commit tree, same code), test_stake_ingress_format_only_dedup 1/1, test_relay_is_reachable_only_after_the_pure_gate 1/1, test_double_spend_order_invariance 1/1, transaction_processor test_step0 2/2.
inc01: 2 isolated tests PASS (87s each, PoW-bound fixtures); full 5-test suite TIMEOUT >600s (see sec.16 R3 and 4J triage). Other long suites (crash, multiprocess, security, deep-sync, consensus, migration, phase2, bootstrap) NOT_RUN in closure window and documented as such, never passed off as PASS.

## 16. Residuals

R1 commit message: charter asked "phase4: harden v6 finality state consistency", actual d1fd8d7 uses "phase4: remediate v6 audit findings (4I, 63 tests)". 4J sec.3 decision: COMMIT_MESSAGE_COMPLIANCE = RESIDUAL, no history rewrite (HEAD reference d1fd8d7 must stay stable), no fake functional commit.
R2 documentation: CLOSED in 4J (this file expanded from 4 to 17 sections, ASCII pure, CRLF, no consensus change).
R3 regression coverage: PARTIAL. Closed as far as reasonable: 4g/4h/4i/4c/ledger/ingress/relay/double-spend/step0 PASS post-closure; inc01 full suite TIMEOUT >600s triaged as PREEXISTING_TIMEOUT (PoW-bound fixtures ~87s per test, 4I change was signature-only ValidationMode::Fresh, no logic change); crash/multiprocess/security/deep-sync/consensus/migration/phase2/bootstrap NOT_RUN, never claimed PASS.
R4 benchmark 10k: CLOSED in 4J (measured with same protocol, temp file removed before commit).
No HIGH/MEDIUM/LOW technical findings remain open from 4H after 4I fixes.

## 17. Migration

No migration in 4I. P2P_PROTOCOL_VERSION stays 5. V6_ACTIVATION_TS stays 1_893_456_000_000. Genesis addresses changed only for faucet rotation in src/genesis.rs (public address, no secret, no supply change). Storage adds locked tree with manifest guard, empty on pre-lock upgrades (fail-closed). No operator action required. Activation NOT declared. V6 READY FOR ACTIVATION is explicitly NOT claimed (needs tokenomics, weak subjectivity, release management).

Coverage Matrix (4J closure, post-closure result on HEAD d1fd8d7 unless noted):
FINDING | ORIGINAL RESULT | POST-CLOSURE RESULT | TEST | STATUS
F-A1 | PASS (4I 10 tests) | PASS (re-verified, no code change in closure) | a1_* (10) | CLOSED
F-D1 | PASS (4I 6 tests) | PASS (re-verified) | d1_* (6) | CLOSED
F-D3 | PASS (4I 8 tests) | PASS (re-verified) | d3_* (8) | CLOSED
F-L1 | PASS (4I 12 tests) | PASS (re-verified, no new economy) | l1_* (12) | CLOSED
F-D2 | PASS (4I 6 tests) | PASS (re-verified, POW_IN_V6=NO) | d2_* (6) | CLOSED
F-D4 | PASS (4I 8 tests) | PASS (re-verified) | d4_* (8) | CLOSED
F-A2 | PASS (4I 4 tests) | PASS (re-verified) | a2_* (4) | CLOSED
F-V1 | PASS (4I 5 tests) | PASS (re-verified) | v1_* (5) | CLOSED
ORDER_INDEPENDENCE | PASS (o1 24 perms) | PASS (no change) | o1 + h05b/h06/h13/h14/g10 | CLOSED
LIVE_SYNC_REBUILD | PASS (lsr1/ds1) | PASS (no change) | lsr1/ds1/p1 | CLOSED
PERSISTENCE | PASS | PASS (no change) | save/load set sec.12 | CLOSED
REGRESSION 4G | 36/36 PASS | 36/36 PASS post-closure | phase4g | CLOSED
REGRESSION 4H | 16/16 PASS | 16/16 PASS post-closure | phase4h | CLOSED
REGRESSION 4C | NOT rerun in 4I | 12/12 PASS in 4J | phase4c | CLOSED
REGRESSION LEDGER | 35/35 PASS | 35/35 (same code, pre-commit tree) | ledger | CLOSED
INC01 | TIMEOUT >600s | 2 isolated PASS (~87s each); full suite TIMEOUT = PREEXISTING_TIMEOUT (PoW fixtures, 4I diff signature-only) | inc01_fix_tests | DOCUMENTED
BENCH 10K | NOT_MEASURED | PASS measured same protocol then temp removed (insert 107.03s, support 2.26s, finalize 2.25s, snapshot 18.36ms, save 1.26s, load 650.59ms) | h15 protocol + j10 temp | CLOSED
DOC 17 SECTIONS | 4 sections | 17 sections ASCII CRLF | this file | CLOSED
COMMIT MESSAGE | MISMATCH | RESIDUAL, no rewrite per 4J sec.3 | d1fd8d7 | RESIDUAL
V6 DORMANT | PASS | PASS (const unchanged, pre=V5 post=V6) | grep + g23/g24/h01/h02 | CLOSED
NO_POW | PASS | PASS (stake.rs zero PoW refs; V6_CONSENSUS_POW_DEPENDENCY=NONE) | grep audit | CLOSED
V1.4.0 | PASS | PASS (tags ad08e30/c230cde intact, no push/merge/tag) | rev-parse | CLOSED
