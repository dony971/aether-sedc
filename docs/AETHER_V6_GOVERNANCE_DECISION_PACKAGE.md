# AETHER V6 GOVERNANCE DECISION PACKAGE

- Status: DECISION DOSSIER. No value chosen below: every decision field reads UNSET until governance supplies it. Choosing any of them here is explicitly forbidden.
- Baseline: HEAD 9529d24. V6 dormant (V6_ACTIVATION_TS = 1_893_456_000_000, verified unchanged). v1.4.0-testnet/ad08e30 immutable. No code change in this phase (document only).
- Sources actually used: 4D (design), 4F (parameters + activation constraints + sourcing rule), 4G (implementation: P2P v5 unchanged, endpoints), 4N (WS residual + 12 tests), 4O (anchor fields/bindings), 4P (verifier semantics), 4Q (boot hook + file bundle), 4R (readiness bounds), 4S (rehearsal + runbook), 4T (blocked gate), migration plan (4B-era precedent only, NOT the V6 plan: it bumped wire v4->v5 for CDW; V6 ships no wire bump per 4G).
- ASCII pure, CRLF.

## 1. Purpose

Let governance take 7 explicit decisions (sec.3-9) with full knowledge of format, impact, verification, and ownership -- without this phase choosing anything. Activation stays blocked until the sheet in sec.14 is filled AND verified (sec.11-13).

## 2. Current State

Code default (NOT a decision): CURRENT_CODE_DEFAULT V6_ACTIVATION_TS = 1_893_456_000_000 (2030-01-01 placeholder from implementation phases). All seven governance slots UNSET. Technical gates green within stated bounds (4Q/4R/4S). Nothing deployed, nothing activated.

## 3. Activation Timestamp

PARAMETER: ACTIVATION_TS. PURPOSE: flag-day instant splitting V5/V6 rule application per object timestamp (>= activates V6 path). CURRENT_VALUE: UNSET (code default 1_893_456_000_000 is NOT governed). ALLOWED_FORMAT: u64 unix milliseconds, MUST postdate all V5-settled history intended frozen AND allow announcement+grace+soak per 4F sec.11. SECURITY_IMPACT: too close => operators unprepared, anchors undistributed, split risk; too far => planning drift, history growth under V5 semantics, anchor epoch far from decided set. NETWORK_IMPACT: single instant for all nodes; clocks must be sane (Fresh bounds assume it). MIGRATION_IMPACT: none on stored data (rules are per-object by timestamp; 4B-era migration precedent cited only for process). WHAT_MUST_BE_VERIFIED: const in binary equals decided value on every node; boundary matrix T-1/T/T+1 re-run green (s01/s09 pattern). WHO_MUST_DECIDE: governance/release-management (calendar + announcement). STATUS: UNSET.

## 4. Initial Validator Set

PARAMETER: INITIAL_VALIDATOR_SET. PURPOSE: the staking identities whose quorum activates the chain (anchor set + first voters). CURRENT_VALUE: UNSET. ALLOWED_FORMAT: list of VALIDATOR_ID (32B address hex) + PUBLIC_KEY (Ed25519, address-derivable per Vote convention) + STAKE (u64 base units, >= MIN_STAKE 30_000_000 per 4F P1 band) + STATUS at anchor epoch (Bonded expected; bonded_epoch <= E-2 for immediate eligibility) + bonded_epoch. SECURITY_IMPACT: wrong set => wrong quorum, anchor binds the wrong trust root; unknown keys => UnknownValidator failures at verification. NETWORK_IMPACT: every node must hold the identical list (byte-exact for root recomputation). MIGRATION_IMPACT: none (fresh testnet state). WHAT_MUST_BE_VERIFIED: EXPECTED_SET_ROOT == recomputed canonical root (sorted records + epoch prefix + BLAKE3, 4O sec.7) on every node; each quorum vote's stake_amount equals its committed amount. WHO_MUST_DECIDE: staking/testnet governance (who stakes what). STATUS: UNSET.

## 5. Initial Stake State

PARAMETER: INITIAL_STAKE_STATE. PURPOSE: totals and positions backing the first denominator (no invented money: must reconcile ledger, registry, set, quorum). CURRENT_VALUE: UNSET. ALLOWED_FORMAT: total stake, eligible stake at anchor epoch, per-validator (balance, locked, bonded_amount, state, epochs). SECURITY_IMPACT: mismatch => denominator disputes, false quorum impressions. NETWORK_IMPACT: identical on all nodes (derived by replay, d1 determinism). MIGRATION_IMPACT: ledger rebuilt from DAG must show supply within bounds (INC-01 guards). WHAT_MUST_BE_VERIFIED checklist: ledger balances/locks vs registry bonded_amounts (per validator) vs set listing (same amounts) vs quorum denominator (recomputed eligible sum, 3S>=2T in u128). WHO_MUST_DECIDE: staking governance for amounts; arithmetic verified by tooling on all nodes. STATUS: UNSET.

## 6. Initial Anchor

PARAMETER: INITIAL_ANCHOR. PURPOSE: the trust bundle new nodes verify (epoch, set root, denominator, votes, chain). CURRENT_VALUE: UNSET. ALLOWED_FORMAT: v6_anchor.json bundle (anchor fields + validator_set records, deterministic encoding per 4Q) with anchor_id published alongside for the out-of-band check. SECURITY_IMPACT: incoherent anchor refuses everywhere (fail-closed); coherent-but-wrong-history anchor is only caught by the sourcing rule (4O/4N boundary, honestly restated). NETWORK_IMPACT: distributed via decided channels, byte-compared across sources, halt on contradiction. MIGRATION_IMPACT: none (new file, no store change). WHAT_MUST_BE_VERIFIED: valid anchor verifies (all 9 boot steps); fake/wrong-epoch/wrong-set/wrong-denominator variants refuse (4P/4Q matrices re-run on the REAL bundle before acceptance). STATE_BINDING stays RESERVED (no state_root value to decide). WHO_MUST_DECIDE: checkpoint tooling output + quorum-operator cross-check (bytes), release for distribution. STATUS: UNSET.

## 7. Release Version

PARAMETER: RELEASE_VERSION. PURPOSE: human identifier binding binary+docs+network scope. CURRENT_VALUE: UNSET. ALLOWED_FORMAT: semver-like tag distinct from every v1.x line, e.g. form v<major>.<minor>.<patch>-v6testnet<N> (form only, number NOT chosen). SECURITY_IMPACT: confusion with v1.4.0-testnet risks wrong-binary operation. NETWORK_IMPACT: displayed at boot, logged, referenced by runbook. MIGRATION_IMPACT: none. WHAT_MUST_BE_VERIFIED: tag string distinct from v1.4.0-testnet; tag object points to the decided RELEASE_COMMIT; nodes log it at startup. WHO_MUST_DECIDE: release management. STATUS: UNSET.

## 8. Release Commit

PARAMETER: RELEASE_COMMIT. PURPOSE: exact source the binaries and checksums derive from. CURRENT_VALUE: UNSET (HEAD 9529d24 is the latest AUDITED commit, not a decided release). ALLOWED_FORMAT: full 40-hex git hash on the V6 line with a clean tree except documented audit docs. SECURITY_IMPACT: any deviation invalidates all prior verification evidence. NETWORK_IMPACT: all nodes build/run the same hash. MIGRATION_IMPACT: none. WHAT_MUST_BE_VERIFIED: rev-parse match on every build machine; test-suite gates re-run green on that exact hash before tagging; checksums recorded. WHO_MUST_DECIDE: release management (after verification). STATUS: UNSET.

## 9. Network ID

PARAMETER: NETWORK_ID / TESTNET_ID. PURPOSE: isolate the new testnet (no V5/V6 data mixing, no cross-network peering confusion). CURRENT_VALUE: UNSET. CONSTRAINTS (honest code reading): NO network_id/chain_id field exists in config.rs or the P2P handshake today (verified by grep; only P2P_PROTOCOL_VERSION = 5 and bootnode/port separation exist). Therefore verifiable-by-nodes isolation has TWO honest options: (a) procedural separation (distinct ports, bootnodes, data dirs, genesis context, docs) enforced operationally, or (b) a tiny additive network-magic check introduced in a future implementation phase (NOT designed here, NOT decided here). Uniqueness, unambiguity, and difference from v1.4.0-testnet are REQUIRED under either option; cross-network protection "if provided" is currently procedural-only -- stated, not oversold. SECURITY_IMPACT: reuse/confusion risks cross-network peering and anchor misapplication. NETWORK_IMPACT: every node configured identically. MIGRATION_IMPACT: none (new network). WHAT_MUST_BE_VERIFIED: uniqueness + documented separation mechanism + node-side check (config grep or new-code review once chosen). WHO_MUST_DECIDE: release/network governance (identifier + mechanism choice). STATUS: UNSET. UPDATE 4W (implementation reality, Phase 4V commit 48908d9): NETWORK_ID is now a u64 config value (default 0 = legacy neutral; old TOML files parse unchanged; CLI --network-id opt-in), carried in the P2P handshake frame (69 -> 77 bytes, exact-match gate, genesis check retained), signed+encoded+validated in vote/bond/unbond bytes (wire v2, format versions 1 -> 2, old bytes explicitly rejected), checked in anchor verification (bundle field + per-vote check) and certificate verification (per-vote check), and pinned per data directory by a network.id marker file (mismatch/corrupt refuses boot fail-closed). STATUS stays UNSET: the code default 0 is neutral legacy behavior, proven indistinguishable from an explicit 0 and from an absent field (4W), so no default may stand in for this decision; activation with everyone default remains technically possible and is tracked as a MEDIUM finding (no technical gate forces an explicit choice; governance sheet + runbook are the only gates). UPDATE 4X (explicit gate, Phase 4X): NodeConfig.network_id is now Option<u64> (None = absent/unconfigured, Some(0) = explicitly legacy, Some(n) = V6-eligible): UNSET is distinguishable from explicit 0 at config level; effective id stays unwrap_or(0) everywhere else (legacy behavior bit-identical). Central validate_v6_network_configuration() refuses None/zero/mismatches with named errors; node boot refuses when V6-finalized state is present but the gate fails (fresh/pre-finality boots unaffected); restore/load paths refuse foreign snapshots before adoption (no partial state); sync adoption inherits admission gates (single production insert site, validated). STATUS stays UNSET: no governed value chosen here.

## 10. Cross-Parameter Consistency

validator set -> set_root -> anchor.set_root -> anchor_id (recompute chain must close; sec.4 vs sec.6). stake state -> eligible sum -> claimed_total -> quorum 3S>=2T (sec.5 vs sec.6). release commit -> tree -> artifact hashes -> release version (sec.8 vs sec.7). network ID -> config/handshake/docs isolation (sec.9). ACTIVATION_TS vs anchor epoch vs set bonded_epochs: anchor epoch must satisfy maturation (bonded+2<=E) for quorum members, else the anchor cannot verify (mechanical check). ACTIVATION_TS vs history: must postdate frozen V5 history (4F). Any mismatch in this graph BLOCKS (verification commands fail closed; no override procedure exists).

## 11. Governance Gate

GOVERNANCE_READY = YES iff ALL hold: 7 inputs present with valid formats; cross-consistency graph (sec.10) closes mechanically on every checker node; anchor verifies (all 9 steps); set root recomputed equal; stake reconciled (4-way checklist); release hash matches built artifacts; network ID unique with a documented separation mechanism; boundary matrix re-run green. Else GOVERNANCE_READY = NO (current state).

## 12. Technical Gate

TECHNICAL_READY = YES iff the standing evidence holds (cited, not recounted): V6 readiness PASS-with-bounds (4R), runbook + rehearsal PASS (4S), anchor verification + integration PASS (4P/4Q suites green on the release-candidate tree), joiner/sync/rebuild/restart PASS, no-PoW PASS, V5 isolation PASS. Re-verified on the exact RELEASE_COMMIT before tagging (sec.8 gate). Current standing on HEAD 9529d24: YES.

## 13. Activation Gate

ACTIVATION_ALLOWED = GOVERNANCE_READY AND TECHNICAL_READY. Currently NO (governance side empty). No activation act in this phase under any circumstance.

## 14. Decision Sheet

V6 GOVERNANCE DECISION SHEET (fill ONLY with real governed values):

ACTIVATION_TS = UNSET
INITIAL_VALIDATOR_SET = UNSET
INITIAL_STAKE_STATE = UNSET
INITIAL_ANCHOR = UNSET
RELEASE_VERSION = UNSET
RELEASE_COMMIT = UNSET
NETWORK_ID = UNSET

GOVERNANCE_READY = NO

(TECHNICAL_READY = YES stands as phase evidence, cited above.)

## 15. Final Checklist

- [ ] 7 inputs present, formats valid, consistency graph closes
- [ ] Anchor + set + stake re-verified on N checker nodes with identical results
- [ ] Boundary matrix + targeted suites re-run green on RELEASE_COMMIT
- [ ] Runbook filled with values, monitoring + alerts armed, rollback rehearsed
- [ ] Activation executed only as the governed act (separate phase), never here
