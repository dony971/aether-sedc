# AETHER PHASE 4N -- WEAK SUBJECTIVITY AND READINESS

- Status: AUDIT + TARGETED TESTS, no production change. Branch dev/phase2-decentralized-network, HEAD eff1f82 throughout (verified at close: no tracked modifications except the two intended new files).
- V6 stays dormant: V6_ACTIVATION_TS = 1_893_456_000_000 (2030-01-01), untouched. No genesis/quorum/stake/epoch/slash/unbonding/finality/fork-choice/wire change, no PoW reintroduction, no v1.4.0 change. No push, no merge, no tag, no deploy, no activation date chosen.
- Documents read before code: 4D, 4F, 4G, 4H, 4I (incl. 4J closure sections), 4K, 4L (4M read as prior verdict). NOTE: docs/AETHER_PHASE4J_V6_REMEDIATION.md does not exist as a file (4J closed inside the 4I document); carried residual, not a technical gap.
- Key code fact framing everything below: the codebase has NO checkpoint type, store, verify, or sync-from-checkpoint path (grep: only two comments mention checkpoints). The falsifiable trust object is the F-D4 finality certificate (FinalizedRecord + quorum votes via verify_certificate). Nothing in this phase invents a format the code/design does not have.
- ASCII pure, CRLF.

## 1. Scope

Close the 4M residual WEAK_SUBJECTIVITY = RESIDUAL: define exactly what remains (model, checkpoint mapping to real code, long-range mechanics, new-node cases, distribution, fake rejection, cert/finality link, release dossier), fill reasonable test gaps with 12 new fast tests, measure certificate verification cost, and decide activation readiness honestly.

## 2. Current residual

4M left exactly one security residual (0 findings): weak subjectivity has a design (4F sec.10: horizon 72+margin, cert-list payloads, combo distribution, multi-source rule) but no distribution/verification-of-anchor implementation, and full-history sync is the only coded join path. Everything else is PASS. This phase determines whether that residual can be closed by audit + tests alone.

## 3. Weak-subjectivity model

Why needed: signatures do not expire. A node syncing from genesis cannot distinguish canonical history from an attacker-forged alternative built with old unbonded keys; forgery is free, only making it canonical under live quorum is expensive (4F sec.10; demonstrated in sec.5/n11).
Protects against: long-range history forgery fooling new or long-offline nodes (sec.5).
Trust period: UNBONDING_EPOCHS + margin (72+margin epochs, 4F). A checkpoint younger than the horizon is safe because the keys that could contradict it are still slashable; older epochs are checkpoint-locked (rule stated, enforcement of the lock is the residual).
New node must know: one anchored finality (winner + quorum votes + epoch + validator set of that epoch) obtained under the 4F sourcing rule.
Authentication: quorum signatures over the certificate payload, verified against the anchored set (n01 PASS, ~40ms/4 votes debug), plus source agreement (rule only, sec.7).
Valid vs fake: valid = exact pinned vote set, all signatures good, key/closure match, distinct validators, quorum arithmetic holds (n02-n06 reject all tamperings). Fake fails cryptographically except denominator/epoch claims (n07/n08 residuals).
Multiple sources: cross-check identical anchoring payloads; disagreement = halt and investigate (rule only, no code).
Attacker history: free to build, verifiable as internally consistent, but its certificate does not match the anchor's vote set (n12).
No checkpoint: full-history sync converges only if the history is the real one; nothing in code marks it as such (sec.6 case B).
Old checkpoint: safe iff within horizon AND re-anchored forward; months-offline nodes must re-anchor (4F UX residual, no code).
Contradictory checkpoints: halt, never pick by majority-of-servers alone (rule only).
Compromised source: bounded by the multi-source rule (rule only); single-source sync is forgeable by its publisher.

## 4. Checkpoint model

4F format Checkpoint{epoch, state_hash, quorum_sigs list} maps to code as follows: epoch -> FinalizedRecord.epoch (ADVISORY, unverified, n07); state_hash -> NO counterpart (certs bind no state; n09 pins verify_certificate takes no state parameter); quorum_sigs list -> supporting_votes + per-vote Ed25519 signatures (verified, n01). Minimum verifiable anchor in real code: (conflict key, members, FinalizedRecord, exact quorum vote vec). Missing vs 4F: state-hash binding, epoch binding, denominator proof, distribution/sourcing, horizon enforcement. All flagged, none invented.

## 5. Long-range attack

Scenario (built and run, n11): 5 validators finalize F1 (X); all unbond and release; new set B bonds; attacker replays the old keys with alternate votes Y (no equivocation inside the alternate history). N1 replaying real history finalizes F1; N2 fed only the alternate history finalizes F1-prime; both internally consistent and both verify against their own votes. Protections, honestly separated: cryptography does NOT stop it (all signatures valid); historical stake does NOT stop it (old keys still sign); unbonding (72 epochs) stops key reuse only while slashable AND only if the new node knows the exit happened (it cannot tell from key material alone); the checkpoint/anchor DOES stop it (n12: cross-anchor verification fails both ways); weak subjectivity (recent anchor under the sourcing rule) is therefore necessary, not merely harder. No mechanism is oversold.

## 6. New-node behavior

Case A (valid anchor + quorum votes): verifies (n01), syncs backfill from it, converges (d3/lsr1). SECURE, PASS.
Case B (no anchor): converges on WHATEVER history it is fed (n11 N1 vs N2 both finalize). INSECURE-BY-DESIGN without anchor; actual code behavior confirmed, not assumed.
Case C (old anchor): within horizon + re-anchor forward = secure by rule; code has no horizon check (residual); months-offline must re-anchor (UX residual).
Case D (falsified anchor): rejected cryptographically (n02-n06) EXCEPT denominator/epoch claims (n07/n08) and state binding (n09): a same-key forged cert with adjusted claims needs the sourcing rule to catch it. PARTIAL.
Case E (contradictory anchors): no code path picks; rule is halt-and-investigate. RESIDUAL (procedure, not code).
Case F (multiple sources): agreement check is procedural (no quorum-of-sources in code; none invented). RESIDUAL.

## 7. Community checkpoints

Same payload from sources A/B/C is compared by exact equality of (key, record, vote set); any byte difference = investigate, never vote. How many agreements suffice: 4F rule (>=3 independent sources, or bundle+1) is procedural; no code enforces a count and none is invented here. A single source CAN fool a node that trusts it alone (n11 proves the forged history is self-consistent). A majority of cooperating sources is NOT cryptographic safety, only publisher-compromise bounding. No source-quorum invented.

## 8. Fake checkpoints

Mapped to certificate fields and tested in src/tests/phase4n_checkpoint_tests.rs (12/12 PASS): bad epoch -> VERIFIES (advisory, n07 residual); bad root -> NO FIELD (n09 residual); bad proof (truncated/padded set) -> REJECTED (n04); bad signature -> REJECTED (n06); nonexistent finality -> None, no record (n10); insufficient quorum (weight cut or denominator inflation) -> REJECTED (n03); incompatible set (wrong key/closure/members) -> REJECTED (n05, n02). Duplicate-validator padding -> REJECTED (n04). Every invalid CHECKABLE claim is rejected; the three non-checkable claims are pinned as residuals, not passed off.

## 9. Checkpoint/finality relation

A checkpoint is NOT external advice in this codebase: the anchorable object IS a V6 finality (FinalizedRecord + quorum votes), verifiable by verify_certificate. Relation: certificate == checkpoint payload minus (state_hash, epoch binding, distribution). A node verifies the anchor is a REALLY PROVEN finality for everything except the pinned numbers (n01 proves the proven part; n08 proves the claim part). CHECKPOINT_FINALITY_LINK = PASS with the two stated claim-residuals.

## 10. Release management

Dossier prepared, no date chosen: activation mechanism (timestamp flag-day + P2P gate, 4F sec.11) fully specified; V6 launch would additionally need (a) initial validator set/distribution procedure (out of scope: tokenomics), (b) checkpoint sourcing procedure per the 4F rule (residual sec.7), (c) activation calendar decision with announcement+grace (governance, NOT set here), (d) release hash/bundle procedure if bundle sourcing is used (residual). Nothing here selects values.

## 11. Global coverage matrix

SUITE | RUN (HEAD eff1f82 unless noted) | RESULT | V6 RELEVANCE | STATUS
phase4g stake/finality 36 | 4N window re-run | 36/36 PASS | direct | PASS
phase4i remediation 63 | 4N window re-run | 63/63 PASS | direct | PASS
phase4n checkpoint/long-range 12 | 4N window NEW | 12/12 PASS | direct | PASS
phase4h audit 16 | 4L window, same HEAD | 16/16 PASS | direct | INHERITED_PASS
phase4c adversarial 12 | 4L/4K windows, same HEAD | 12/12 PASS | direct | INHERITED_PASS
phase4l B+G equivalence 13 | 4L window, same HEAD | 13/13 PASS | direct | INHERITED_PASS
m01-m03 integration stitch | 4M window, same HEAD, deleted after | 3/3 PASS | direct | INHERITED_PASS
ingress/relay/double-spend/step0 | 4J window, same code paths | PASS | direct | INHERITED_PASS
ledger 35 | pre-4L tree (stake untouched by ledger paths) | 35/35 PASS | supporting | INHERITED_PASS
h12 RPC abuse | 4L window, same HEAD | PASS | supporting | INHERITED_PASS
validation unit (grace/stale) | tree (untouched files) | PASS | supporting | INHERITED_PASS
inc01 full suite | 4J/4K windows | TIMEOUT (2 isolated PASS) | supporting | PREEXISTING_TIMEOUT
parent_selection sweep | 4K window | TIMEOUT (PoW fixtures) | supporting | TIMEOUT
crash/multiprocess/security/deep-sync/consensus/migration/phase2/bootstrap | any window | not executed | indirect | NOT_RUN
Categories A-Q: A consensus PASS (4c/4g/o1/lsr1), B stake PASS, C finality PASS, D equivocation PASS, E slash PASS, F persistence PASS, G restart PASS, H sync PASS, I deep-sync PASS (ds1), J p2p PASS, K rpc PASS, L ledger INHERITED, M processor INHERITED/partial (g33/g34 re-ran), N bootstrap NOT_RUN, O security PARTIAL (abuse suites green, heavy NOT_RUN), P phase4-historical PASS, Q validation PASS. No cross-run sums presented as one execution.

## 12. Missing critical tests

After adding the 12 checkpoint/long-range tests, implementable-test gaps remaining: NONE for consensus/finality/slash/lock/long-range-behavior/checkpoint-negatives/deep-sync/restart/partition/order (all covered). Blocked-by-design gaps (not test gaps): checkpoint distribution/multi-source agreement tests (no distribution impl), 50k scale (unreasonable suite cost), horizon-enforcement tests (no horizon code). CRITICAL_TEST_GAPS = 0.

## 13. Long-range test harness

Kept permanently in src/tests/phase4n_checkpoint_tests.rs (test-only file, no production touch): real-vs-alternate indistinguishable histories (n11), anchor-decides cross-verification (n12), all negative/positive certificate cases (n01-n10). Deterministic (fixed keys, no mining, no clock), fast (12 tests in 0.29s), fails on any divergence or any newly-accepted forgery class except the three pinned residuals.

## 14. Performance

Certificate verification (4 votes, debug): ~40ms total, ~10ms per Ed25519 verify; scales linearly in quorum size. New-node bootstrap cost = full replay (insert-dominated, 4L numbers: ~10.7ms/vote double-verify protocol) + backfill + one restore pass. Deep sync WITH anchor: anchor verify (ms) + backfilled-vote verification (same per-vote cost, bounded by backfill size) + rebuild; WITHOUT anchor: unbounded full-history verification with no authenticity (the WS residual, not a speed issue). No optimization applied; no target invented. Cert check is never the bottleneck (ms vs seconds of vote ingestion).

## 15. Regression results

In-phase: 4g 36/36, 4i 63/63, 4n 12/12 PASS. Same-HEAD inherited: 4h/4c/4l/m01-m03/ingress/relay/double-spend/step0/h12 PASS. Carried labels: ledger INHERITED_PASS (stake change does not touch ledger paths), inc01 PREEXISTING_TIMEOUT, parent_selection TIMEOUT, heavy suites NOT_RUN. No failure, no flake observed; two 4M-harness mistakes were test bugs fixed in-harness (documented in 4M), none here.

## 16. Remaining risks

R1 checkpoint distribution: no sourcing/agreement/horizon code; single-source sync forgeable (proven n11); multi-source rule procedural only.
R2 pinned claims: denominator/epoch/state unbound in lone certs (pinned n07-n09); mitigated only by anchored-set cross-check (needs the set = the anchor problem R1).
R3 long-offline nodes: must re-anchor; no UX/code path exists yet.
R4 scale terms: eligible_total O(V log V), per-validator id/weight O(V) per support call remain (4L R1/R2); 50k NOT measured.
R5 release dossier items (sec.10 a-d) undecided by design at this phase.
No HIGH/CRITICAL technical findings; risks are scope boundaries.

## 17. Activation readiness

Exit criteria (charter sec.20): WS sufficiently defined? NO (model yes, distribution/horizon-enforcement no). HIGH/CRITICAL open? none. Long-range understood? YES (demonstrated). Checkpoint verifiable? PARTIALLY (payload yes, claims/distribution no). Critical tests covered? YES (gaps 0). No LIVE/SYNC/REBUILD/restart divergence? YES stable. No consensus regression? YES. NO_POW? YES. Dormant? YES. Conclusion: V6_READY_FOR_ACTIVATION = NO, for exactly R1/R2-distribution + sec.10 dossier reasons. Integration itself is green; readiness is gated on out-of-scope release decisions, which this audit refuses to preempt.

## 18. Final decision

Record WEAK_SUBJECTIVITY = RESIDUAL (model + falsifiable payload closed; distribution + horizon enforcement open), LONG_RANGE = RESIDUAL (mechanics demonstrated and anchored path proven; anchor acquisition procedural), CHECKPOINT_MODEL = RESIDUAL (payload mapped, three claim-gaps pinned), readiness NO. Keep the 12 tests (they guard the payload forever). Default COMMIT = NONE; a documentation-only commit of this file + the test file is permitted by the charter and recommended (no consensus touch). No activation, no date, no deployment.
