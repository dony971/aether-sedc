# AETHER PHASE 4G  -  STAKE FINALITY IMPLEMENTATION (v6)

- **Status**: IMPLEMENTED per `AETHER_PHASE4D_NO_POW_CONSENSUS_DESIGN.md`
  with parameters from `AETHER_PHASE4F_STAKE_FINALITY_PARAMETERS.md`.
  Branch `dev/phase2-decentralized-network`. No push/merge/tag/deploy.
- **Absolute rule held**: after V6 activation, NO PoW/mining/nonce/difficulty/
  difficulty_bits/hash-rate/actual_bits/cumulative-work/hash-competition in
  vote, weight, fork choice, finality, quorum, admission, or stake.
  Historical PoW fields kept, parsed, explicitly ignored (no brutal deletion).
- **Activation**: `V6_ACTIVATION_TS = 1_893_456_000_000` (2030-01-01,
  dormant placeholder pending release-management flag-day). All v6 paths
  fully exercised with post-activation fixtures regardless of wall-clock.
- **P2P wire**: `P2P_PROTOCOL_VERSION = 5` UNCHANGED (charter rule+wire flip
  together at activation; until then v6 traffic is test/RPC-local gossip
  between wired nodes, old peers error-disconnect on unknown kinds per
  existing discipline).

## 0. Cartography V5 CDW -> V6 STAKE FINALITY (built as mapped)

FICHIER | FONCTION | ANCIEN (v5) | NOUVEAU (v6)
`src/stake.rs` (NEW) | registry/lifecycle/epoch/quorum/slash/finality | n/a (did not exist) | StakeRegistry + ValidatorState + snapshot/restore + 3S>=2T u128 + evidence + slash application + finalized map + seen_bonds
`src/transaction.rs` | consts + Vote/Bond structs | CDW_ACTIVATION_TS, PoW fns | + V6_ACTIVATION_TS (dormant); + Vote/Bond/Unbond + canonical LE encode/decode + id + verify
`src/validation.rs` | validate_pure / validate_dag | PoW gate always | PoW gate SKIPPED post-V6-activation timestamps (fee-only admission); + validate_vote/validate_bond/validate_unbond + 8 stake error variants
`src/parent_selection.rs` | resolve_conflict_key | CDW+tiebreak / grandfathered min-id | + resolve_conflict_key_v6 (finalized -> stake-support -> min-id) + is_strict_descendant; legacy frozen
`src/transaction_processor.rs` | STEP 0 / process_conflict | CDW resolve + rebuild | + era-routed winners + rebuild_for_era; + process_vote/process_bond/process_unbond; global lock order dag->registry->ledger->mempool
`src/ledger.rs` | rebuild_from_dag | CDW winners | + rebuild_from_dag_v6 (same pipeline, v6 winners); legacy refactored without behavior change
`src/rpc.rs` | status + drainer | Finalized unreachable | drainer processor registry-wired; + submitVote/submitBond/submitUnbond + getFinality/getValidators; drainer unchanged otherwise
`src/p2p.rs` | messages + relay | v5 Transaction gossip | + Vote/Bond/Unbond kinds (enum tail) + accept_inbound_stake + broadcast_stake + GetData vote fallback + StakeHooks setters; version const UNCHANGED (5)
`src/node.rs` | boot + receivers | DAG rebuild only | + registry load (fail-closed boot) + stake receiver task + vote lookup + set_stake_registry on all RpcImpl sites + RPC server wiring
`src/storage.rs` | trees | tx/balance/mempool/applied trees | + Validators/Votes/Finalized/Evidence trees + manifest save/load_registry
`src/config.rs` |  -  | untouched | untouched (no new operator flags; activation const-based like prior migrations)
`src/sync_stats.rs`, mempool, fee oracle, orphans |  -  | untouched | untouched
Tests | suites | 4B greens | 36 phase4g tests (g01-g36) + 1 p2p ingress test; all pre-existing suites untouched and green

## 1. Scope

Implements the v6 `STAKE_WEIGHTED_DAG_FINALITY` consensus (4D design, 4F
parameters) as DORMANT-BY-DEFAULT code: every v6 rule is era-gated by
`is_v6_active_at` (timestamp predicate, never peer versions or local
flags), pre-activation data flows through the frozen legacy rules
bit-identically, and post-activation fixtures exercise the full v6
pipeline (admit -> vote -> finalize -> rebuild -> persist -> gossip ->
reload). No tokenomics invented (slash is weight removal + flag; fund
burn deferred per charter). No auto vote production (operator-driven
submission; key custody design is an explicit non-goal  -  sec.15).

## 2. V5 to V6 behavior delta

- Conflict decision: CDW (subtree work) -> stake plurality, finalized
  first, min-id tiebreak only. Pre-V6 keys: legacy EXACT (delegation
  inside resolve_conflict_key_v6 + canonical_winners_v6 routing).
- Admission: PoW gate skipped for post-V6 timestamps (fee-only);
  pre-V6 timestamps keep the exact legacy gate (g23 proves both).
- Weight: work credits -> bonded stake (flat, live-read, no ledger
  coupling  -  double-use residual documented in 4F, not hidden).
- Finality: none (v5) -> quorum 3S>=2T finalized records, sticky,
  slash-voidable with clean re-resolution (delete-only invalidation).
- Liveness inputs: votes/bonds/unbonds as first-class gossip + RPC.
- Durability: stake state in Sled (manifest-guarded) + boot reload
  (fail-closed); pre-4G trees untouched.

## 3. Consensus core (src/stake.rs)

- Constants (4F exact): MIN_STAKE=30M (INTERIM), EPOCH_DURATION_MS=3.6M,
  UNBONDING_EPOCHS=72, BOND_MATURATION_EPOCHS=2, EPOCH_GRACE=1.
- Lifecycle: Bonded (votes iff matured) -> Unbonding (never votes,
  release at +72) -> Unbonded (record kept, weight 0) / Slashed
  (permanent, re-bond rejected). Top-up resets maturation (no instant
  return). Unbonding refresh keeps earliest release.
- Quorum: `3S >= 2T` in u128, exact, no floats/division/overflow;
  T=0 and S=0 never quorate (tested boundaries incl. u64::MAX).
- Votes: latest-per-validator (max (epoch,id)), support = weight sum
  over votes pointing at side-or-strict-descendant; eligibility +
  weight read live (unbonded/slashed contribute zero automatically).
- Equivocation: same (validator,epoch,key) + different side ->
  evidence (BOTH full votes preserved, canonical id) + IMMEDIATE slash
  (weight 0 + permanent flag). First vote keeps the map slot.
- Finality: try_finalize (max support, min-id tiebreak, quorum-gated,
  sticky) + invalidate_finality (delete-only, slash-triggered).
- Replay: seen_bonds set (same bytes = idempotent Ok, no double
  top-up); votes dedup by triple+side; unbonds idempotent by state
  machine.
- Snapshots: sorted vecs (byte-identical across nodes), votes as
  canonical encodings, restore replays through insert_vote
  (re-detection deterministic; evidence ids re-derived and checked).

## 4. Wire formats (src/transaction.rs)

- Vote 257B: ver u8 | validator 32 | epoch u64 | conflict_sender 32 |
  conflict_nonce u64 | side 32 | stake_epoch u64 | stake_amount u64 |
  parents 2x32 | sig 64. VOTE_FORMAT_VERSION=1.
- Bond 113B: ver | validator 32 | amount u64 | epoch u64 | sig 64.
  BOND_FORMAT_VERSION=1. Unbond 105B: ver | validator 32 | epoch u64 |
  sig 64. All integers LE, fixed arrays only, strict decode (exact
  length + version, fail closed). Ids = BLAKE3 over full encoding
  (incl. signature). Validator address IS the ed25519 key (same
  convention as tx senders  -  no pubkey field).
- stake_amount/stake_epoch/parents are ASSERTED/AUDIT context, never
  validity conditions (partitions must not veto votes; weight reads
  live from the registry).

## 5. Validation (src/validation.rs)

- validate_pure: PoW skipped iff is_v6_active_at(tx.timestamp)
  (one-line gate; everything else identical, incl. backdating,
  future/stale, signature, sender-key, overflow).
- 8 new error variants (additive; rpc.rs match has wildcard arm  - 
  no breakage): InvalidVoteSignature, InvalidBondSignature,
  UnknownValidator, SlashedValidator, IneligibleValidator,
  InsufficientStake, EpochOutOfWindow, InvalidStakeVersion.
- validate_vote: version -> sig -> epoch in at+/-1 -> known ->
  not-slashed -> Bonded -> matured. NO duplicate/equivocation
  rejection (second side is EVIDENCE; rejecting it would let the
  first-seen vote censor proof of its own author's equivocation).
- validate_bond: version -> sig -> amount>=MIN_STAKE -> not-slashed
  -> ledger funds (LEDGER read  -  no circularity) -> epoch in
  at+/-1 (CLOSES the maturation bypass: maturation is measured from
  the SIGNED epoch for cross-node determinism, so unbounded past
  would grant instant maturity; delayed gossip re-signs).
- validate_unbond: version -> sig -> known -> slashed? -> Bonded
  -> epoch in at+/-1 (release measured from signed epoch).

## 6. Fork choice (src/parent_selection.rs)

- resolve_conflict_key FROZEN (legacy callers + tests untouched).
- resolve_conflict_key_v6(sender, nonce, registry, at_epoch):
  <2 members -> None; newest member pre-V6 -> legacy delegate;
  else finalized_winner (if resident) -> stake plurality ->
  min-id tiebreak (sorted single pass). NO quorum for preference
  (quorum is a FINALITY property); NO PoW anywhere.
- is_strict_descendant(ancestor, txid): parent-walk with visited set
  (terminates regardless; genesis never; self excluded).

## 7. Processor admission (src/transaction_processor.rs)

- Optional handle (None = exact legacy behavior): set_stake_registry.
- conflict_winners_for is now a method: registry try_read ->
  era-routed winners; try_read miss -> legacy for THIS computation
  (transient only  -  the in-flight mutation's own trigger re-resolves
  after committing, so a legacy answer never sticks).
- rebuild_for_era: v6 replay when wired, legacy otherwise (drainer,
  STEP 0, STEP 6b all routed through it; recovery paths stay legacy).
- process_vote: validate+insert (registry alone) -> persist ->
  re-resolve key (finalize attempt + quorum-loss invalidation +
  plurality-toward-vote check) -> conditional global v6 replay +
  ledger persist. Duplicate = early Ok. Equivocated = ALWAYS replay
  (slash hits every key the slasher backed).
- process_bond: validate (ledger funds standalone) -> dedup ->
  apply at SIGNED epoch -> persist. No rebuild (immature by
  construction).
- process_unbond: validate -> apply at SIGNED epoch -> persist ->
  finalized-key quorum sweep -> UNCONDITIONAL v6 replay + persist.
- Lock order dag->registry->ledger->mempool (registry never held
  while acquiring dag; tx paths take registry LAST via try_read).

## 8. Ledger replay (src/ledger.rs)

- rebuild_from_dag refactored into prelude + canonical_winners_legacy
  + apply_rebuild (no behavior change  -  35 ledger tests green).
- rebuild_from_dag_v6: same pipeline, canonical_winners_v6
  (finalized-first). Slash needs NO separate replay step: slashing
  zeroes weight at READ time and rebuilds consume live weights.
- Fund-burn on slash: NOT implemented (charter deferral  -  no
  tokenomics invented; no ledger surgery, hence no divergence class).

## 9. Storage and durability (src/storage.rs)

- Trees (additive): stake_validators (addr->bincode record),
  stake_votes (vote-id->257B canonical), stake_finalized
  (sender++nonceLE->bincode record), stake_evidence (id->bincode,
  both votes inside). Records never deleted except authoritative
  save + remove_finalized (invalidation path only).
- save_registry: clear 4 trees, write snapshot parts, manifest LAST
  (counts + blake3 + seen_bonds, Metadata tree).
- load_registry: None when no manifest (fresh node); else counts +
  hash verify, strict-decode every vote/evidence, restore through
  insert_vote replay. ANY mismatch = Err (fail closed  -  boot refuses,
  see sec.12). O(registry) per event is INTERIM (validator-scale;
  batching is a perf TODO).

## 10. P2P (src/p2p.rs)

- Kinds Vote/Bond/Unbond(Vec<u8>) appended at ENUM TAIL (indices
  9/10/11  -  pre-4G indices 0..=8 frozen; old peers error-disconnect
  per existing discipline). P2P_PROTOCOL_VERSION stays 5.
- accept_inbound_stake: format-only (strict decode + dedup + upstream
  record + channel), mirroring tx ingress (signatures are admission's
  job  -  proven by test with bogus sig accepted at ingress).
- broadcast_stake: validation-before-send (re-encode + version + sig),
  same scheduling-dedup/fanout/jitter discipline as transactions.
  "Sends gated pre-activation": the gate on WHAT is produced lives
  at vote production (post-V6 keys only); relay stays
  content-agnostic by 2E-D design (documented interpretation).
- GetData vote fallback: unknown hash + wired lookup -> Vote message
  (bounded; id-collision argument: disjoint BLAKE3 preimages).
- StakeHooks (set-once, P2PNetwork::new signature UNCHANGED  - 
  15 call sites untouched): stake_channel + vote lookup, resolved
  per message.

## 11. RPC (src/rpc.rs)

- stake_registry field (None default  -  5 new() call sites + tests
  untouched) + setter; start_rpc_server takes trailing
  Option<handle> (1 caller updated).
- aether_submitVote/submitBond/submitUnbond (hex canonical params;
  TransactionResponse reuse with vote/bond ids; gossip post-accept,
  duplicates not re-relayed) + aether_getFinality(sender, nonce)
  + aether_getValidators (bounded 500, sorted). Rate limiting
  automatic (per-method). Drainer processor registry-wired
  (prevents drainer/vote-path winner divergence).

## 12. Node boot and wiring (src/node.rs)

- Registry load after mempool init: manifest-verified restore,
  fresh-start empty, MISMATCH = boot refusal (fail closed  -  never
  run consensus on partial stake state).
- Stake channel + P2P hooks (storage-backed vote lookup via
  try_read) + stake receiver task (admit via processor, relay
  post-accept, Duplicates not re-relayed).
- set_stake_registry on all three RpcImpl sites + RPC server.
- No auto vote-production task (explicit non-goal this phase:
  operator-driven submission via RPC/P2P; validator key custody
  needs its own design; V6 dormant so production would idle).

## 13. Lock discipline (global)

dag -> registry -> ledger -> mempool. Registry never held while
acquiring dag (vote phases take dag first or registry alone; tx
conflict paths take registry LAST via try_read, fail-fast to
LockError/transient-legacy). Storage locks are leaves (sync ops,
never nest outward). No new lock primitives introduced.

## 14. No-PoW audit (this implementation)

- Searched: vote weight (bonded_amount only), support sums (no
  work_credit call in stake.rs/validation.rs vote paths),
  resolve_conflict_key_v6 (support_for + min-id only),
  try_finalize/quorum (u128 stake arithmetic),
  validate_vote/bond/unbond (sig/epoch/stake/ledger-funds only),
  process_vote/bond/unbond (no nonce/difficulty/mining refs),
  rebuild_from_dag_v6 (winners only  -  work_credit unreachable:
  canonical_winners_v6 never calls subtree_work).
- PoW functions (verify_pow/work_credit/credit_for_bits/mine_nonce)
  still called ONLY by: validate_pure pre-V6 branch, CDW legacy
  path, existing tests/benchmarks. Post-V6 timestamps skip the only
  consensus gate (g23 proves skip + frozen pre-V6 enforcement).
- POW_IN_CONSENSUS = NO after activation: HELD (dormant until
  V6_ACTIVATION_TS; pre-activation behavior bit-identical).

## 15. Operator and autonomy notes

- V6 dormant until 2030-01-01 flag-day (release management flips
  const + wire version together per charter). Until then registries
  warm via RPC/P2P submission; fork choice pre-V6 ignores votes
  (era-routed)  -  warming is safe and free of consensus effect.
- Weak subjectivity: boot from manifest + checkpoint discipline per
  4F (unchanged by this implementation); fresh nodes start empty
  and learn via gossip.
- No validator auto-voting: production needs operator key custody
  (non-goal, documented residual alongside per-event O(registry)
  persist cost and vote-orphan TTL mirroring).
- Boot refusal on manifest mismatch: operator restores data dir or
  resyncs (never auto-deletes  -  deletion would hide corruption).

## 16. Test map (36 phase4g + 1 p2p)

- Registry: g01 constants, g02 epochs, g06 maturation, g07 unbond
  cutover/release, g08 slash permanent, g09 quorum boundaries,
  g10 insert/dup/equivocation+slash, g11 evidence canonical,
  g12 latest-per-validator + closure, g13 finalize/sticky,
  g14 tie-at-quorum min-id, g15 invalidate delete-only, g17 top-up
  maturation, g18 state space.
- Wire: g03/g04 vote codec, g05 bond/unbond codec, g16 activation
  predicate, g35 P2P wire tail compat.
- Validation: g19 vote, g20 second-side admissibility, g21 bond
  (+backdate close), g22 unbond (+backdate close), g23 PoW skip.
- Fork choice: g24 era delegation, g25 no-votes min-id, g26 stake
  over work, g27 finalized absolute, g28 descendant predicate.
- Durability: g29 snapshot/restore (+corrupt fails closed),
  g30 save/load roundtrip + fresh None + resave idempotent,
  g31 partial-save fails closed.
- Integration: g32 v6 rebuild applies stake winner, g33 vote
  end-to-end (accept/dup/no-registry-reject), g34 bond/unbond
  lifecycle (+replay idempotent), g36 RPC endpoints end-to-end.
- P2P ingress: test_stake_ingress_format_only_dedup (in p2p.rs).
- Pre-existing suites: untouched files' tests green (ledger 35/35,
  phase4/4C suites, validation completed subset; full-suite only
  known-flaky timing test test_conflict_cpu_cost fails under
  parallel load, passes solo  -  pre-existing, unrelated: it
  exercises prune+rebuild, never touched).

## 17. Residuals (honest, all documented in code)

- O(registry) authoritative save per stake event (INTERIM;
  validator-scale; batching TODO, not correctness).
- No auto vote production (operator-driven; key custody design
  pending; V6 dormant so nothing to vote on yet).
- Vote-orphan TTL mirrors tx orphans (no separate vote mempool;
  DAG-membership-independent votes never orphan by design).
- Fee gates on stake gossip: validation-before-relay + existing
  fan-out/rate caps (no separate stake fee  -  4F minimum-viable).
- Fund locking on bond / release on unbond-expiry: NOT in ledger
  yet (bonds checked against balances; locking is the tokenomics
  follow-up; release_epoch recorded but unenforced on-ledger).
- GetData vote fallback serves single votes (no vote-inventory
  pagination  -  validator-scale makes it unnecessary).

## 18. V5/V6 comparative (built-in fixtures)

- g24: pre-CDW key  -  v6 output == legacy output (min-id), frozen.
- g24: CDW-era key  -  v6 == legacy (subtree-work winner); same DAG
  with post-V6 timestamps + votes  -  v6 follows stake (g26) while
  legacy stays on work (asserted both sides in-test).
- g32: v6 rebuild applies stake winner; legacy rebuild recorded
  without equality assertion (frozen rule, may agree or diverge  - 
  divergence is the intended protocol change, era-gated).
- V5 regressions: zero (legacy paths byte-identical; new code is
  additive + era-gated; suites green).

## 19. Performance notes

- support_for: O(votes-on-key) per member + sort; try_finalize:
  members x support; rebuild: unchanged complexity class + winner
  map (same scan as legacy, different resolver).
- is_strict_descendant: parent-walk bounded by DAG size, memoized
  nowhere (called per (member, vote-side); vote-sides per key are
  validator-bounded  -  same cost class as CDW subtree walks).
- No benchmarks invented (4F sims were TEMP deterministic; live
  perf follows the soak campaign, not this phase).

## 20. Activation and flag-day

- Dormant const (2030-01-01) + P2P v5: nodes run v5/v6-capable
  binaries with v6 rules unreachable (predicate false)  -  the 4B
  migration precedent (CDW_ACTIVATION_TS pattern).
- Flag-day flips V6_ACTIVATION_TS (release management) + wire
  version together; NO code change needed at activation (rules
  already live behind the predicate). Rollback = const revert
  (pre-activation history untouched by construction).

## 21. Files changed (this phase only)

- NEW: src/stake.rs (~700 lines + docs), docs/ this file.
- EXTENDED (additive, legacy frozen): src/transaction.rs
  (Vote/Bond/Unbond + V6 const, +~370), src/validation.rs
  (PoW skip + 3 validators + 8 errors, +~200),
  src/parent_selection.rs (v6 resolve + descendant, +~110),
  src/transaction_processor.rs (winners era-route + 3 entries,
  +~330), src/ledger.rs (v6 rebuild via shared helpers, +~120/-40),
  src/storage.rs (4 trees + manifest, +~330),
  src/p2p.rs (3 kinds + ingress/relay/GetData + hooks, +~330),
  src/rpc.rs (3 submits + 2 queries + drainer wire, +~330),
  src/node.rs (load + receiver + 4 wirings, +~200),
  src/lib.rs (+1 mod, +3 exports), src/tests/mod.rs (+1 mod).
- TOUCHED NOTHING ELSE. Pre-existing dirty/untracked files
  (canary scripts, audit docs, target-*/build artifacts) predate
  this phase and are NOT staged.

## 22. Charter compliance

- Params: all 8 from 4F used EXACTLY (3e7/1h/72/2/1/100%-slash/
  no-reward/minimum-viable-fee-posture/combo-weak-subjectivity)  - 
  nothing invented, INTERIM flags preserved.
- Rule: V6_ACTIVATION_TS dormant + P2P v5 + no-PoW audit (sec.14) +
  grandfathering (newest-member era route; pre-V6 bit-identical).
- Proofs: 36 green + ingress green; lib warnings == baseline (9);
  test-profile warnings == baseline (44, all pre-existing).
- Stops at scoped commit (no push/merge/tag/deploy; release tag
  untouched; dirty files outside this phase unstaged).
