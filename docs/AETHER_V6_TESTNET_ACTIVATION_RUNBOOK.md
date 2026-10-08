# AETHER V6 TESTNET ACTIVATION RUNBOOK (theoretical, no live values)

- Status: THEORETICAL PROCEDURE. No real timestamp, no real validator set, no real anchor, no live network action. All values below are PLACEHOLDERS with decision owners; inventing finals here is forbidden.
- V6 stays dormant until a governed flag-day executes this runbook for real.
- ASCII pure, CRLF.

## 1. Pre-requis

- Binary built from a tagged V6 commit with phase4g-4R suites green (same gates as 4Q: 174+ targeted, heavy suites labeled).
- Operator holds: the decided ACTIVATION_TS, the INITIAL_ANCHOR bundle file, the INITIAL_VALIDATOR_SET listing, the release checksums.
- Each node: data_dir backup completed and verified restorable, clock NTP-synced (Fresh-mode bounds and epoch math assume sane clocks; consensus timestamps come from data, but operators must not run skewed clocks).
- At least the quorum operators reachable for coordinated verification.

## 2. Verifications pre-activation

- git: expected tag hash matches release notes on every node.
- V6_ACTIVATION_TS in the binary equals the governed value (single const, transaction.rs); any mismatch halts.
- Anchor file parses (structure gate) on every node.
- No node reports anchor verification failure (boot log boundary line).
- Sync state healthy: no unresolved orphan storms, no INC-01 truncated-store flags.

## 3. Distribution artefacts

- From release: binary + hashes + this runbook + release notes + activation configuration (ACTIVATION_TS).
- From checkpoint tooling: INITIAL_ANCHOR bundle file (anchor + validator set records).
- Channels (any combination; verification, not channel, is the root): release bundle, docs page, bootstrap peers, snapshots.
- Every operator fetches from >=2 independent channels where possible and byte-compares (compare_anchor_bundles semantics: Equal proceeds, Contradictory halts).

## 4. Verification ancre

- Recompute anchor_id from the file fields; mismatch with the published id -> halt, investigate (tamper or corruption).
- Run full verification (epoch/set/denominator/votes/quorum/chain): any binding failure -> halt.
- Confirm winner/members/key match the announced activation scope.

## 5. Verification validator set

- Recompute set_root from the operator-held set listing at the anchor epoch; mismatch with anchor.set_root -> halt.
- Confirm each validator's address, bonded amount, state, and epochs against staking records; confirm claimed_total equals the recomputed eligible sum.

## 6. Verification stake

- Confirm denominator recomputation matches claimed_total (no trusted claims).
- Confirm no ineligible voter inside the quorum set (immature/unbonding/slashed would fail verification: such a bundle is incoherent, halt).

## 7. Verification noeuds

- Every node boots with the anchor file present and logs the accepted boundary (support/total/votes line).
- Any node logging refusal stops before networking: fix its files, never bypass with an empty dir to "make it start" (that would drop the boundary silently; empty dir is only legitimate for nodes with genuinely no V6 history).
- Node without V6 history and without anchor file: expected NoAnchor path (syncs first; anchor check applies once state exists).

## 8. Pre-activation

- Freeze window: no validator set changes (bonds/unbonds) after the anchor epoch; changes invalidate the anchor's set binding and require a fresh anchor.
- Publish the anchor + set through the decided channels; collect byte-equality confirmations from operators.
- Set monitoring dashboards (sec.11) and alert thresholds (blocking list below) BEFORE the timestamp passes.

## 9. Activation

- No command flips consensus: activation is data-driven (object timestamps >= ACTIVATION_TS route to V6 rules deterministically). Operators only ensure binaries, files, and clocks are correct BEFORE the timestamp.
- At the timestamp: watch era classification (pre objects legacy, post objects V6, mixed keys newest-member) on every node.
- Block on ANY divergence: halt rollout (stop distributing post-activation data), keep serving V5 history, investigate. Never "vote through" a divergence.

## 10. Post-activation

- Confirm quorum formation and first V6 finalities on all nodes with identical winners/weights.
- Confirm joiners with the anchor converge (verify-then-sync-then-check pattern).
- Re-anchor cadence starts: fresh anchors per checkpoint epoch for late/long-offline joiners.

## 11. Monitoring

- current epoch, V6 active/inactive per node, validator count, bonded/active stake, quorum reachability, finality latency, pending conflicts, anchor verification failures at boot, sync failures/orphan rates, equivocation/slash events, P2P vote propagation counts, restart/rebuild failures, ledger supply bounds. No new monitoring system is mandated: existing node logs + sync_stats counters + RPC status cover these; add anchor-failure log alerting (the boot boundary line) as the single new watch item.

## 12. Incident response

- Anchor failure at boot: node refuses; operator fixes files (re-fetch, byte-compare), never deletes the file to bypass.
- Contradictory anchors across sources: halt affected joins, escalate to release governance; no majority-pick.
- Finality divergence: freeze (stop new post-activation flow), preserve data dirs untouched for forensics, escalate; never rewind finalized history to "fix" it.
- Equivocation wave: expected path (evidence + slash + tombstone) handles it; watch stake health.

## 13. Rollback operationnel

- SOFTWARE rollback: redeploy previous binary (V5 behavior resumes for pre-activation data; post-activation V6 data stays interpretable only by V6 builds: keep archives).
- DEPLOYMENT rollback: halt rollout before the timestamp (nothing happened: all nodes still V5 trivially, proven by rehearsal s11 pattern).
- CONSENSUS rollback: DECLARED IMPOSSIBLE for finalized history (never silently un-finalize). Only forward resolution (re-resolve under V6 rules with full data) is legitimate.
- Post-timestamp deployment failure does NOT roll back consensus: nodes keep serving decided history; fix forward.

## 14. Validation finale

- All nodes same era classification, same validator set root at anchor epoch, same first finalities, joiners converged, no blocking alert firing, logs archived. Only then is the testnet declared V6-live by governance (separate act, not this runbook's execution).
