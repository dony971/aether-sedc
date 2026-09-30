# AETHER PHASE 4 -- MIGRATION PLAN (weight-based fork choice)

- **Status**: PLAN ONLY. Nothing here is scheduled, activated, or implemented.
  Any line below becomes real work only under an explicit Phase-4B charter.
- **Subject**: activating the PRIMARY design from
  `AETHER_PHASE4_CONSENSUS_WEIGHT_DESIGN.md` (Cumulative Descendant Work +
  min-id tiebreak + loser retention with re-resolution). The BACKUP design
  (work-gated min-id window) would need a lighter variant of the same plan
  (flagged per-section where it differs).
- **Cardinal rule (from 4A sec. 11)**: never smuggle the rule change into the
  current version. Mixed-version nodes MUST split loudly and quickly rather
  than disagree silently, so the bump, the gate, and the grandfathering are
  load-bearing -- not decoration.

## 1. Break inventory (answers to Etape 11)

- CONSENSUS_BREAK = YES. Contested keys with confirmations resolve differently
  under CDW than under min-id. Uncontested history is unaffected (no conflicts
  to re-decide), which bounds the blast radius enormously.
- P2P_PROTOCOL_BUMP = YES. Current P2P_PROTOCOL_VERSION = 4. The rule change
  ships as version 5; handshake version check (existing machinery) splits the
  network into rule-homogeneous partitions instead of letting mixed nodes
  diverge state silently. No new handshake fields required (rule is local
  computation over shared bytes).
- GENESIS_CHANGE = NO. Same genesis hash, same initial distribution, same
  timestamp constants. Work credits derive from stored tx fields.
- DATABASE_MIGRATION = NO for correctness (same rows; scores recomputable).
  OPTIONAL additive work-cache column/tree for performance (recomputable from
  fields -- droppable without loss). If added: additive-only migration, no
  backfill required (lazy compute on first touch).
- REPLAY_PROTECTION_CHANGE = NO (tx ids, signatures, nonces untouched).
- PEER_VERSIONING = via the protocol bump (existing version gate; mixed peers
  rejected at handshake with a clear error, same as the v3->v4 split).
- ACTIVATION_HEIGHT/TIME = decision required in 4B: flag-day timestamp (simple,
  clock-skew tolerant windows needed) vs DAG-size trigger (no height exists;
  e.g. activate when own DAG reaches N txs -- nondeterministic across nodes,
  NOT recommended) vs version-gated deterministic switch (recommended:
  rule active iff peer version >= 5 AND local activation flag past -- still
  needs a shared temporal anchor: use flag-day + grace window, documented).
- MIXED_NETWORK_PERIOD = YES, unavoidable and DANGEROUS: v4 nodes keep
  min-id-resolving while v5 nodes CDW-resolve the same conflicts -> state
  split across versions BY DESIGN during coexistence. Mitigations: short
  advertised window, bios-style "upgrade or halt sync" messaging, bootnodes
  upgraded first, partition monitoring (conflict-rate telemetry), and a
  documented end-of-life for v4 peering.
- OLD_TX_COMPATIBILITY = full for bytes (no re-signing, no re-mining, no
  re-gossip required); PARTIAL for conflict outcomes (see grandfathering).

## 2. Grandfathering (the load-bearing simplification)

Conflicts settled BEFORE activation stay settled under EITHER rule for all
future decisions: nodes record (or recompute-and-freeze) pre-activation
outcomes and never re-resolve them. Effects:
- No re-resolution of ancient history (bounds sync/rebuild cost; avoids
  resurrecting long-dead losers whose rows were purged under min-id).
- Boot rebuild applies the new rule ONLY to conflicts with at least one
  post-activation tx (or post-activation descendant activity -- exact predicate
  is a 4B design item; recommended: any conflict whose newest member
  post-dates activation).
- Loser rows purged pre-activation are NOT recoverable (by design -- same as
  today); sync of pre-activation history serves winners only (already the case).

## 3. Activation sequence ( strawman for 4B to refine, not to execute)

1. Ship v5 code with the rule BEHIND the activation gate, default OFF;
   gate tests (both rules computable side-by-side on test DAGs, asserted equal
   on uncontested sets).
2. Canary: single-node + partitioned-network soak with conflicting traffic,
   comparing v4/v5 decisions on IDENTICAL feeds (divergence expected ONLY on
   contested keys past activation -- asserted).
3. Flag-day announced (timestamp + grace window); bootnodes + faucet upgraded.
4. Activation: v5 rule live; v4 peering deprecated with logged warnings, then
   refused after the window.
5. Post-activation monitoring: conflict rate, re-resolution counts, retention
   growth vs bound, decision latency percentiles.
6. v4 end-of-life: removal in a later version (separate charter).

## 4. Coexistence behavior (must be specified, not emergent)

- v4 <-> v5 peering: refused at handshake post-window (loud split > silent split).
- During the window: cross-version gossip still flows (same bytes); each side
  resolves by its own rule; operators MUST expect state divergence on
  contested keys and MUST NOT serve merchants across versions during the window
  (operational rule, documented).
- No auto-negotiation of rules per-tx (would fork per-tx -- forbidden shape).

## 5. Replay rules (historical conflicts under the new rule)

- Pre-activation settled conflicts: frozen (grandfathering sec. 2), never replayed.
- Post-activation conflicts: full CDW + retention + re-resolution semantics.
- Cross-boundary conflicts (one member on each side): resolved under the NEW
  rule at/after activation (deterministic given the union set).
- Boot rebuild replays in dependency order under the active rule set; the
  grandfather predicate is evaluated per conflict, not per DAG.

## 6. Genesis implications

None (same hash, same distribution). IF the work function ever needs new
genesis-anchored constants (it should not -- actual-bits needs none), they ship
as new constants with their own activation, never by editing genesis.

## 7. Test plan delta (extends WEIGHT_DESIGN sec. 12 for migration specifically)

- Mixed-version harness: v4-sim vs v5-sim on identical conflict feeds;
  assert divergence EXACTLY on contested post-activation keys and nowhere else.
- Activation-boundary tests: conflicts straddling the flag (grandfathered vs
  re-resolved, per the predicate).
- Rollback drill: deactivate flag -> min-id resumes on NEW conflicts;
  pre-existing CDW decisions stay (no un-pruning of retained losers without
  re-resolution -- specify in 4B).
- Long-soak: retention growth under sustained conflicting load vs bound;
  decision latency vs subtree size (validates the incremental-computation
  design).

## 8. Rollback strategy

- Pre-activation: flip the gate back (one constant + version tag); new
  conflicts resume min-id; CDW-computed states from the active window REMAIN
  (no history rewrite -- rollback is forward-only by construction).
- Post-activation steady state: rollback = coordinated downgrade (same
  machinery as activation, reversed) + grandfather everything decided under
  CDW. No silent auto-rollback (would re-split the network unpredictably).
- Data safety: nothing in this plan deletes rows the current version would
  keep; the only new deletions are loser-retention expiries under the new
  rule, themselves gated and logged (mirror of today's purge discipline).

## 9. What this plan deliberately does NOT cover

Fee-market redesign, difficulty schedule, finality gadgets, staking/voting,
incentive redesign, light-client protocol, archive-node economics. Each is a
separate charter or explicitly out of scope.

## 10. AS-BUILT (Phase 4B implementation record)

- Activation constant shipped: `Transaction::CDW_ACTIVATION_TS =
  1_758_000_000_000` (shared era with the difficulty migration, separate
  policy). Grandfather predicate as specified (newest-member rule).
- P2P_PROTOCOL_VERSION 4 -> 5 shipped in code (unreleased); handshake gate
  splits mixed versions loudly (existing machinery); version-bump test
  updated (4 -> 5 with the consensus-break rationale).
- Boot no longer prunes/purges (retention); topological insert of ALL
  persisted txs + rebuild resolves (grandfathered where applicable).
- No store migration performed (confirmed unnecessary: scores recomputable;
  no work-cache column added — deferred as optional performance work).
- Genesis untouched. Wire format untouched (same bytes). Replay protection
  untouched. Rollback drill + canary soak + v4 EOL remain operational
  (non-code) follow-ups, NOT executed here.
