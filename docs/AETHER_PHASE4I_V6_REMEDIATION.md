# AETHER PHASE 4I — V6 REMEDIATION (4H findings)

- **Status**: IMPLEMENTED. Branch `dev/phase2-decentralized-network`. No push / merge / tag / deploy.
- **Target**: `ef817ba` + 4G v6 dormant (`V6_ACTIVATION_TS = 1_893_456_000_000`, 2030-01-01), P2P wire v5 inchangé.
- **Method**: remediation production ciblée + 63 tests neufs `phase4i_v6_remediation_tests.rs` (fixtures déterministes, timings REPORTED jamais assertés). Régressions voisines re-mesurées sur le code final.
- **Précédent point d'arrêt**: 63/63 acquis, `Regressions voisines (4g,4h)` in_progress, `Perfs + doc + décision commit` pending. Reprise exacte ici.

## 1. Findings 4H -> Fixes 4I

| Finding | Sévérité 4H | Fix 4I (production) | Preuve |
|---|---|---|---|
| F-A1 equivocation avant bond: divergence de poids | HIGH | slash-tombstone: equivocation pré-bond laisse tombstone, bond/top-up/unbond post-tombstone rejetés, support à zéro des deux côtés, persistance save/load | a1_* (10 tests) |
| F-A2 byte-equality vs sémantique | LOW | canon byte-égal des deux ordres, variants same-side canonicalisés, 3-sides déterministe | a2_* (4 tests) |
| F-D1 boot rebuild legacy post-activation | BLOCKING | rebuild era-aware: newest-member décide, post-V6 restart sans rollback, déterminisme full rebuild, supply-guard intact, legacy pré-V6 bit-identique | d1_* (6 tests) |
| F-D3 vote sync absent (tx-only) | BLOCKING | vote-inventory diff (bounded, missing-only), backfill idempotent, GetVotes known-vs-unknown, joiner vide->fill+ledger, restart-during-backfill converge | d3_* (8 tests) |
| F-L1 double-usage stake (vote weight + spendable) | HIGH | bonded-stake locks: bond lock, spend-while-bonded rejeté, double-bond rejeté, top-up augmente lock, clone/rebuild/restart préservent locks, unbond garde lock jusqu'à maturité (72 epochs), release mature + orphan reconcile + slash freeze forever | l1_* (10+ tests) |
| F-D2 admission economics post-V6 sur ingress historique | MED | prédicat era-admission pur (9 combos), fresh far-future rejeté, pas de réintro PoW post-wall, shape d'erreur | d2_* (6 tests) |
| F-D4 certificats | — | contenus pinnés, verify ok/bad-sig/wrong-side/wrong-set/bad-numbers, conflicting-quorums impossibles, verify depuis votes backfillés | d4_* (8 tests) |
| F-V1 finalité morte pré-V6 | LOW | dead record ignoré par resolve, mixed newest-post finalise, post-V6 control finalise, pré-V6 vote accepté mais ne finalise jamais | v1_* (4 tests) |
| Ordre O1 | — | 24 perms full-interleave (bonds, re-bonds top-up-shaped, votes 2 époques) convergent tolérant; intents d'unbond indépendants de l'ordre (max-epoch); replay vote déjà-vu = Duplicate | o1 + g10/h10 adaptés |
| Partition P1 | — | merge équipondérant converge | p1 |
| Live/Sync/Rebuild/Restart LSR1 | — | rebuild+restart convergent avec ledger | lsr1 |
| Deep-sync DS1 | — | tx-then-vote-backfill 100, insertion ordre topologique (pas tri id) | ds1 |

Fichiers prod touchés (4I): `src/genesis.rs`, `src/ledger.rs` (locks), `src/node.rs` (D1 rebuild, D3 inventory, L1 backstop), `src/p2p.rs` (D3 diff/backfill), `src/stake.rs` (intents, tombstone, ordre), `src/storage.rs` (locks trees), `src/transaction_processor.rs` (L1 release), `src/validation.rs` (D2), `src/rpc.rs`, `src/node_logging.rs` + docs/roadmap/spec/threat/canary.

## 2. Vérification reprise (2026-10-07)

- `cargo test --lib phase4i_v6_remediation_tests`: **63 passed, 0 failed**.
- `cargo test --lib phase4g_stake_finality_tests`: **36 passed, 0 failed**.
- `cargo test --lib phase4h_v6_adversarial_audit_tests`: **16 passed, 0 failed** (dont h15 timings, ~12s).
- `cargo test --lib ledger::`: **35 passed**.
- `test_stake_ingress_format_only_dedup`: **1 passed**.
- `test_relay_is_reachable_only_after_the_pure_gate`: **1 passed**.
- `test_double_spend_order_invariance`: **1 passed** (~53s).
- `transaction_processor::tests::test_step0` (2 tests): **2 passed** (~48s).
- Total ciblé: 63+36+16+35+1+1+1+2 = 155 verts, 0 rouge sur l'arbre final sale (mêmes modifications que l'arrêt).

## 3. Perfs post-fix (h15, REPORTED)

```
4H PERF n=100:  insert=1.0652054s support=3.4633ms finalize=3.4325ms snapshot=208.8µs save=12.4176ms load=6.6941ms
4H PERF n=1000: insert=10.6843993s support=51.6763ms finalize=52.3208ms snapshot=1.3877ms save=114.7364ms load=66.2891ms
```

Insert linéaire (~10.6ms/vote), support/finalize ~50ms à 1000 votes, snapshot/save/load sous 115ms. Pas d'assertion, base de comparaison pré-commit. Pas de régression fonctionnelle associée.

## 4. Décision commit

- **READY TO COMMIT (local uniquement)**: 4I 63/63 + voisines 4G/4H vertes + ledger/ingress/relay/double-spend/step0 verts sur le même arbre.
- Ne pas push / merge / tag / deploy (même discipline que 4G/4H). Laisser `git status` sale tel quel pour revue; le commit doit inclure prod + `phase4i_v6_remediation_tests.rs` + `mod.rs` + ce doc + spec/roadmap/threat mis à jour.
- Risque résiduel: arbre non committé (18 modifiés + docs untracked listés en `git status`); refaire `cargo test --lib phase4i_v6_remediation_tests` après tout rebase.
- Prochaine étape après commit: gate d'activation V6 (flag-day) hors scope 4I.
