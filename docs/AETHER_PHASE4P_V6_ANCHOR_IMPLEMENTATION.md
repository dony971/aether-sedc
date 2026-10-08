# AETHER PHASE 4P -- V6 ANCHOR IMPLEMENTATION (epoch + set bindings)

- Status: IMPLEMENTED exactly per docs/AETHER_PHASE4O_V6_ANCHOR_DESIGN.md. No invented mechanism: every field, rule, and constant below traces to a 4O section (mapping in sec.2). The single deliberate reading is documented in sec.9 (signature context enforced by verification, since 4O specifies no signature change).
- Baseline: HEAD b20259e at start and during all test runs. No prior dirty tracked files; preexisting untracked left alone (never git add .).
- Additive only: new file src/anchor.rs + one mod line in src/lib.rs + new test file. Verified zero modifications to stake/validation/processor/p2p/rpc/node/ledger/storage/transaction/genesis (git status clean on all of them). No quorum/stake/epoch/slash/finality/wire/economics/V5 rule touched. V6 dormant (nothing in production calls the anchor module; activation constant untouched). No push, merge, tag, deploy.
- ASCII pure, CRLF.

## 1. Scope

Implement the 4O minimal anchor so cross-epoch and cross-set replays (4O FAILs) become rejections, while every valid V6 decision keeps verifying with identical outcomes (sec.24 equivalence). Includes epoch/set/denominator bindings, canonical encoding, bundle integrity tag, 18-test harness, persistence/P2P/storage treatment, dormant + no-PoW proofs, and this document.

## 2. 4O Design Mapping

4O sec.6 anchor fields -> V6Anchor struct verbatim (epoch/key/winner/members/votes/supporting/claimed_total/set_root/prev/state_root Option reserved). 4O sec.7 record layout + sort + BLAKE3 + saturating eligible sum -> canonical_validator_record/canonical_set_bytes/validator_set_root. 4O sec.8 recompute-T rule -> DenominatorMismatch arm. 4O sec.9 window [E-GRACE,E] with existing EPOCH_GRACE + E inside set preimage -> window check + canonical_set_bytes epoch prefix. 4O sec.10 anchor_id formula extended to cover every bundle field (sorted members/ids, state tag) -> anchor_id(); state replay rule -> sec.7 state omission documented (reserved). 4O sec.11-15 models -> harness long-range/new-node/fake/multi-source behavior (behavioral, no new protocol). No 4O detail was missing; no STOP needed.

## 3. Anchor Structure

V6Anchor { epoch, key, winner, members, votes, supporting, claimed_total, set_root, prev, state_root: Option }. supporting MUST equal sorted ids(votes) (derived-check, stronger than carrying); claimed_total MUST equal recomputed eligible sum; set_root MUST equal recomputed commitment at epoch; prev chains ([0;32] genesis); state_root MUST be None in this version (StateRootPresent rejection reserves the field). build_anchor() constructs valid bundles for tests/tooling; it is NOT called by any consensus path.

## 4. Epoch Binding

Three teeth: (i) anchor_id covers epoch (tamper -> AnchorIdMismatch, p02a/p13); (ii) set root covers epoch (same records at E+1000 commit differently -> SetRootMismatch, p02c); (iii) each vote must satisfy vote.epoch in [E-EPOCH_GRACE, E] (outside -> VoteEpochOutsideWindow, p02b). vote(E)->verify(E) PASS (p01/p07); vote(E)->E+1/E-1 tag shifts FAIL (p02a); far shifts FAIL (p02c); same votes re-anchored +1000 FAIL (p09). Grace neighbors (E-1) legitimately pass: skew tolerance, not a hole (documented in-test).

## 5. Validator Set Binding

Canonical record (fixed sizes): address(32) || amount(le64) || state_tag(1) || release_or_zero(le64) || bonded_epoch(le64) || slashed_tag(1) || slashed_epoch_or_zero(le64); sorted by address; version(1) || epoch(le64) prefix; BLAKE3 = set_root. vote(R1)->verify(R1) PASS; vote(R1)->verify(R2) FAIL with R2 = any record change (amount+1, member swap) -> SetRootMismatch (p03/p10); unknown validator -> UnknownValidator (p03); ineligible (immature/unbonding/slashed) -> IneligibleValidator (p15 mixed-state registry); claimed stake != committed -> StakeAmountMismatch with valid signature (p04: asserted context becomes checked binding). Same key, same stake, near epoch, valid crypto still FAILs under R2: proven.

## 6. Denominator Binding

T recomputed from the committed set at E every verification; claimed_total MUST match (DenominatorMismatch, p05 both directions: shrink-to-fake-unanimity and weight-cut). No vote-cert + later-arbitrary-denominator pairing is possible: the pairing is re-derived, never trusted (n08 becomes MUST-REJECT, proven). No per-category split beyond the existing eligible/zero rule (unbonding/slashed/unbonded weigh 0 by existing code, cited not redefined).

## 7. State/Chain Binding

Chain: prev carried, covered by anchor_id; tamper vs original tag -> AnchorIdMismatch (p06/p13); re-tagged bundle is a different anchor whose prev must resolve elsewhere (no anchor store exists yet: resolution procedural, stated). Members/winner/votes/ids/totals/roots all covered by the tag; reordered-but-identical bundles verify identically (canonical property, p07: logically identical representations share one commitment per 4O sec.8). State: reserved (STATE_BINDING = RESERVED verdict): no ledger hash primitive exists and none was invented; state still comes from ledger replay of the anchored branch (existing path). state_root: Some(..) rejected.

## 8. Canonical Encoding

Fixed-size fields, version-first, epoch-prefixed set bytes, address-sorted records, sorted members/ids in the tag preimage, content-addressed vote ids (hash of canonical encoding including signature). Determinism proven: p07 builds the same logical anchor from reversed vote order -> identical anchor_id. Distinct states -> distinct commitments (any record/epoch/field change flips root or tag; covered by p03/p11/p13 matrix).

## 9. Signature Context

4O specifies NO signature change: checked first. Therefore no re-signing, no new domain separator invented (inventing one would change the wire and break V5 compat). Context binding is enforced by VERIFICATION (epoch window, set membership, amount equality, key/closure checks) over the existing signing_bytes. Type/version contexts rely on existing machinery (Vote.format_version rejection paths, g04) cited, not duplicated. The same bytes/signature cannot validate in another (epoch, set) context (p09-p11 matrix); message-type confusion is precluded by existing distinct encodings.

## 10. Cross-Epoch Replay

4O FAIL corrected on the anchor path (legacy support stays epoch-agnostic by design; admission grace stays validation-layer). Matrix: A vote(E)@E PASS; B vote(E)@E+1-tag FAIL; C vote(E)@E-1-tag FAIL; D cert(E)@E+1000 FAIL; E cert(E+1000)@E+1000 with E-votes FAIL (window+root); F restart (drop+rebuild index, save/load) same verdicts (p12); G P2P (relay paths carry votes unchanged; verification at receipt uses anchor epoch; malformed rejected p08); H sync (restore path, p12); I RPC N/A (no anchor RPC in this phase; existing RPC abuse suites unchanged). Only the correct context verifies.

## 11. Cross-Validator-Set Replay

4O FAIL corrected on the anchor path. R1->R1 PASS; R1->R2 FAIL (root); R2->R1 FAIL (root); plus restart/sync/rebuild/relay legs (p12 legs + p10/p11) identical verdicts. No reuse across sets regardless of key/stake/epoch/signature validity (p03/p10/p11). Combined matrix (p11): (E1,R1) PASS only; (E1,R2), (E2,R1), (E2,R2) FAIL, each arm a distinct error (root/tag).

## 12. New Node

Empty registry + 4O bundle -> verifies epoch/root/total/votes/quorum/chain and concludes finality deterministically (p01/p07/p16 patterns; pure function, no clock/net). WITHOUT anchor: halt preserved (no code path invents history; EXPECTED_FAIL unchanged, 4N n11 stands). Fake anchor: every field class rejected (p13 + p02-p06/p08). Multi-anchor contradiction: no selection rule (halt, stated).

## 13. Fake Anchor

Epoch/root/total/vote/signature/order/chain/state-field tamperings each rejected (p13 matrix + p02-p06/p08): integrity tag catches epoch/prev/order-adjacent changes; binding rules catch semantic changes even when re-tagged (root/denominator/amount/window/closure). No accepted forgery class remains except the two explicitly reserved items (state binding primitive, distribution operation).

## 14. Long-Range

4N scenario replayed under anchor rules (p14): real anchor verifies with real set; alternate same-keys history also self-verifies (honestly asserted Ok: with identical validator sets cryptography cannot pick a history -- the sourcing rule picks, never oversold); cross bundles fail on id-set mismatch (4N n12 pattern); disjoint-set forgery fails on unknown validators. Anchor removes ambiguity of epoch/set/denominator/finality FOR the anchored history; it does not (and per 4O must not claim to) replace the sourcing rule.

## 15. Multi-Source

Unchanged RESIDUAL per charter (no new protocol): byte-exact comparison detects contradiction (p07 determinism makes comparison meaningful); no arbitration invented. Tested: identical sources verify identically (p07/p12 id stability); contradictory sources have no selection rule (halt, stated). 4F >=3-source guidance stays procedural.

## 16. Persistence

No new persistent state (no storage tree per sec.20 absence-of-justification rule): anchors re-derive deterministically from registry+votes (p12: pre-save, post-load, post-restore anchor ids byte-identical, all verify). create/save/shutdown/reload/verify + sync/restart/rebuild legs green (p12). Nothing to version, corrupt, or migrate.

## 17. P2P

No new gossip kinds (p2p.rs untouched): votes propagate on existing paths (relay/ingress suites stand); anchor bytes need no wire in this phase (verification is local). Rejected at verification (unit-mapped to propagation): duplicates (existing dedup + p04-suite semantics), replays across contexts (p09-p11), bad epoch/set-root/signature (p02-p06), truncated bundles (p08 IdSetMismatch/EmptyVotes), order variants (canonicalized identically, p07 -- same logical anchor, correctly accepted). Nothing invalid influences consensus (verifier is read-only; consensus paths do not call it).

## 18. Storage

No new trees/keys/manifest entries (deliberate per 4O and charter sec.20). Hence fail-closed/versioning/corruption/rebuild for anchor data are vacuous; registry storage behavior proven unchanged by rerun persistence suites (inside 4g/4i). Documented as compliant-by-absence, not as tested-new-code.

## 19. Dormant Gate

V6_ACTIVATION_TS and all five gate sites untouched (zero diff on transaction/parent_selection/processor/validation paths; anchor.rs references no era predicate, no clock, no V5 state). Pre-activation behavior == old (activation suites inside rerun 4g/4h/4i green: g16/g23/g24/h01/h02/d2/v1). Post-activation == new-plus-anchor-available (anchor callable on any registry regardless of era; it constrains nothing by itself). p17 proves era-independent determinism (same logic at distant epochs, cross-epoch bundles never confused). V5_UNCHANGED = PASS.

## 20. No-PoW

Grep over src/anchor.rs for difficulty/nonce/cumulative/work/mining/subtree/hashrate/bits/mine/verify_pow: sole hit is conflict_nonce (account nonce, not proof-of-work). Anchor reads votes, records, hashes (BLAKE3 content addressing, not mining), and quorum arithmetic only. ANCHOR_POW_DEPENDENCY = NONE. Result: NO_POW = PASS.

## 21. Tests

18/18 PASS in 2.26s: p01 valid, p02 epoch (3 teeth), p03 set (+unknown), p04 stake-claim, p05 denominator, p06 chain/state-reserved, p07 canonical matrix, p08 malformed (4 arms), p09 cross-epoch flip, p10 cross-set flip, p11 combined 2x2, p12 restart/sync/rebuild stability, p13 fake-field matrix, p14 long-range, p15 eligibility agreement (mixed states), p16 consensus equivalence (winners+weights+totals), p17 era independence, p18 100-vote timing. Legacy reference behavior pinned by rerun suites, not duplicated here.

## 22. Performance

Anchor build (100 votes) 3.7ms; verify 4 votes 41ms (~10ms/vote: Ed25519 debug); verify 100 votes 1.02s (linear in quorum size, signature-dominated). New-node-with-anchor bootstrap = restore cost (existing numbers) + one verify pass; reload identical (p12). Deep-sync proxy: verify-after-backfill costs one pass over quorum votes. No optimization applied; no target invented. Bottleneck remains vote ingestion signatures (preexisting, unchanged).

## 23. Regressions

On final code: 4p 18/18, 4g 36/36, 4h 16/16, 4i 63/63, 4n 12/12, 4l 13/13 (incl. 10k) = 158 targeted green, 0 red. Heavy suites (ledger sweep, parent_selection sweep, inc01 full, crash/multiprocess/security/deep-sync/consensus/migration/phase2/bootstrap) NOT rerun in-window; 4K/4J labels carried (stake.rs untouched by 4P except... verified: zero diff on all consensus files, so prior runs stand undisturbed). Nothing summed artificially. REGRESSION_STATUS = TARGETED_FULL_GREEN_PLUS_DOCUMENTED_NOT_RUN.

## 24. Residuals

R1 state binding primitive (ledger hash) deferred by design; R2 distribution operation + runbooks (4O R3); R3 4J file + d1fd8d7 message (carried, untouched); R4 50k scale unmeasured; R5 release dossier (set procedure, calendar, bundle). No new findings opened.

## 25. Final Verdict

Bindings implemented and proven without moving any consensus rule; replays closed on the anchor path with equivalence preserved everywhere else.
