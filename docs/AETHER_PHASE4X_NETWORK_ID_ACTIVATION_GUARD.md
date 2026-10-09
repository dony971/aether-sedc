# AETHER PHASE 4X -- EXPLICIT NETWORK IDENTITY ENFORCEMENT FOR V6

- Status: IMPLEMENTED as configuration/startup/storage/restore guards. No consensus rule moved (quorum/stake/epoch/slash/finality/fork-choice/tokenomics untouched; resolve/try_finalize/support/insert/evidence paths byte-identical). No economics invented. V6 dormant, V5 behavior preserved, v1.4.0-testnet/ad08e30 intact. No push, merge, tag, deploy.
- Baseline: HEAD 48908d9 at start; preexisting untracked preserved (never git add .); 4h harness left untracked per standing practice.
- Design record (charter sec.4, decided BEFORE code): gating consensus-math functions was REJECTED (all V6 fixtures are post-activation-epoch with network 0 and must keep finalizing as math tests; data-driven gating would rewrite history and contradict sec.8 V5-compat). The gate keys on NODE CONFIGURATION (Option: UNSET vs explicit) at trust boundaries (boot-with-V6-state, restore, sync adoption via admission, anchor), while unit-test math stays era+rule pure. No silent V5 fallback added anywhere (resolve era routing untouched); violations fail closed with explicit errors. Composition argument: configured networks are deaf/mute to foreign data (handshake+admission+marker+hook), so V6 cannot accumulate on unconfigured nodes except via deliberate operator file surgery, which restore/marker gates refuse.
- ASCII pure, CRLF.

## 1. Scope

Close F4W-1 (no technical bar on unconfigured V6) and F4W-2 (restore network-blindness) with: Option-based config explicitness, one central gate validator, boot gating on V6 engagement, network-checked restore/load, and an 18-item harness -- without moving any consensus rule and without choosing any governed value.

## 2. F4W-1

Was: V6 paths runnable with never-configured network (4W w05/w08 proved boot+activation need no id). Fixed at three layers: (a) config distinguishes UNSET (None) from explicit (Some, incl. Some(0) = explicitly legacy); (b) central validate_v6_network_configuration() refuses None/LegacyZero/mismatches with named errors; (c) node boot refuses when V6-finalized state is present but the gate fails. Live gossip accumulation on unconfigured nodes is additionally impossible against configured peers (deaf/mute: 4V admission+handshake), leaving only all-default shadow operation -- the pre-4V status quo, now runbook-gated for activation.

## 3. F4W-2

Was: restore() replayed any snapshot bytes without network checks (4W w09 first half). Fixed: restore_on_network() pre-checks map votes AND evidence-embedded votes BEFORE any insert (no partial state), and storage.load_registry_on_network() applies it on the boot load path; plain restore()/load_registry() keep legacy behavior byte-identical (pinned suites). Second half of w09 (admission still gates) stands unchanged.

## 4. Configuration Model

NodeConfig.network_id: u64 -> Option<u64>; Default None; TOML absent -> None (serde default); CLI --network-id is Option (absent preserves file value, explicit 0 recorded as Some(0)). Effective id = unwrap_or(DEFAULT_NETWORK_ID=0) at every existing use site (handshake/admission/marker/hook/processor/RPC): legacy behavior bit-identical, single mapping point per site, no second source of truth (the Option IS the source; u64s downstream are derived views).

## 5. V5 Compatibility

Default and explicit-0 nodes traverse every pre-activation path exactly as before: admission (default validators accept net-0 objects), handshake (0==0), marker (adopts/pins 0), hook (NoAnchor/coherent-0 bundles), resolve era routing (untouched), finality math (untouched). Proven by rerun suites with zero expectation changes (4g/4h/4i/4n/4p/4q/4l/4c/p2p/config green) plus explicit legacy asserts (harness x01). No v1.4.0 impact (tag verified intact at close).

## 6. V6 Gate

Central validate_v6_network_configuration(node, storage, anchor): None->NotConfigured; Some(0)->LegacyZero; storage mismatch->StorageMismatch; anchor mismatch->AnchorMismatch; else Ok(n). Enforced at: node startup IFF loaded registry holds V6-finalized records (fresh/pre-finality boots skip: V5 untouched); anchor adoption path keeps its hook (bundle coherence) with gate semantics documented (sec.11); sync adoption inherits admission (4V) + restore (sec.7) gates -- no separate sync gate invented. Gate failures refuse boot with explicit errors naming the requirement (never silent legacy fallback after the boundary).

## 7. Startup

Boot sequence unchanged except two insertions: (1) registry load path switched to the guarded variant (same-network snapshots behave identically; foreign snapshots refuse before adoption); (2) post-load V6 gate (fires only on finalized state). Fresh dirs, empty registries, pre-finality states, and explicit nonzero configurations all boot exactly as before (matrix green). Marker/hook behavior otherwise identical to 4Q/4V.

## 8. Activation Boundary

Predicate and era routing untouched (no timestamp games: T-1/T/T+1 table re-pinned green). Restart across the boundary preserves gate verdicts (save/load roundtrip test: refusal under absent config, acceptance under explicit, byte-identical state). Activation still timestamp-driven; the gate adds a configuration precondition at engagement, independent of wall-clock (no clock reads added anywhere).

## 9. Storage Marker

Unchanged logic, extracted to testable verify_data_dir_network() (identical semantics: adopt-once/pin/mismatch-refuse/corrupt-refuse). The 4X addition is the restore layer beneath it (sec.7/10): marker guards the directory, restore guards the content, gate guards the engagement -- three depths, one model.

## 10. Restore

restore_on_network() (map + evidence pre-check, then legacy restore) and load_registry_on_network() (load, check, discard-on-error before caller use). Foreign snapshots refuse in both layers (harness x11/x14, both vote classes). Same-network roundtrips byte-identical (x10). seen_bonds ids carry no bytes to check (replay-protection only, fail-closed direction by construction: unknown ids simply occupy slots). No storage schema change (sidecar discipline kept).

## 11. Anchor

Hook signature unchanged (effective u64); node passes effective id derived from Option config. Valid-7-under-7 accepts, valid-7-under-9 refuses (integrated test), bundle coherence rules otherwise identical (4p/4q green untouched). Anchor adoption additionally sits behind the boot gate when V6 state exists (sec.6). STATE_BINDING stays RESERVED (no new primitive, per 4O/4P).

## 12. Sync

No new sync code was needed (audit conclusion, not omission): production vote insertion has exactly ONE site (process_vote, post-validation), so backfill/sync/gossip all traverse the 4V network check -- verified by exhaustive caller grep (node/p2p/processor/rpc). Sync-resume under legacy mapping rejects foreign votes (harness x16 with default processor). Restart/sync/rebuild legs for the new guards: marker + restore + gate matrices green.

## 13. RPC

No new authentication (forbidden to invent): submit paths inherit the processor's effective network (wired in 4V, remapped through Option in 4X with identical defaults). Default RpcImpl + foreign vote refuses; same-network accepts (harness x17, real submitVote path). No RPC behavior change for configured networks.

## 14. Failure Behavior

Every guard fails closed with a named error before state adoption or boot completion: NotConfigured / LegacyZero / StorageMismatch / AnchorMismatch (gate), WrongNetwork (admission/anchor/cert), marker/parse/database errors (storage/hook). No path downgrades silently, relabels data, or retries with weaker checks. Operator remediation is explicit in each message (configure id / separate dirs / replace bundle / resync).

## 15. Tests

18/18 green (<1s): legacy intact, gate refusals (None/0), full nonzero flow, config absent/explicit forms, T-1/T/T+1 table, restart stability, storage A+A/A+B/no-marker/corrupt, foreign snapshot (map+evidence), integrated anchor mismatch, sync-resume, RPC default, gate decision matrix (10 rows). Handshake legs live in p2p.rs (rerun green); vote/cert/anchor legs in 4V/4P suites (rerun green).

## 16. Regressions

On final code: 4x 18, 4v 14, 4p 18, 4q 16, 4g 36, 4h 16, 4i 63, 4n 12, 4c 12, config 1, p2p 153, 4l 13 (incl. 10k) = 356+ targeted green, 0 red. stake.rs gained only additive fns (B+G paths identical); storage.rs added one method (legacy path identical); ledger/processor/validation-math untouched (INHERITED standing for heavy PoW suites: validation full, inc01 full, parent_selection sweep TIMEOUT/NOT_RUN per standing labels). Nothing summed artificially.

## 17. Governance Package

4U NETWORK_ID fiche appended (this phase): Option model (UNSET vs explicit incl. explicit 0), central gate semantics, storage/restore/anchor legs, pre-launch verification procedure (configure -> marker -> bundle -> gate matrix -> boundary table). All seven inputs remain UNSET (verified on the sheet; no default substituted). Governed value still NOT chosen here.

## 18. Residuals

R1 live gossip accumulation in all-default worlds behaves as legacy (documented sec.2 composition; runbook-gated for activation, not code-forced). R2 full-sweep PARTIAL/TIMEOUT carried (PoW-fixture-bound; covered paths green targeted). R3 state primitive still reserved. R4 distribution operation + 4J-file + d1fd8d7-message carried. R5 50k scale unmeasured. No new findings opened (two candidate failures during work were both harness bugs, fixed in-harness with no production touch).

## 19. Final Verdict

Explicit configuration now gates V6 engagement at every trust boundary that can create it, with legacy behavior preserved bit-for-bit and zero consensus movement.
