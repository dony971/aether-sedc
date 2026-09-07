# CANARY RC-ALIGNED REPORT — Campaign C2

**RC :** `77f01ee31cde8a0a900d75934fc8af8afa6efc97` — **protocole jamais modifié**
**SHA256 :** `770D5AF8FEBB5CACC37646FF5EFFD306827FC14863B2A0565829970ADDD89C6F`
**Genesis :** difficulty=1000, supply=1000000100000000000 (faucet vérifié 1e18)
**Toolchain :** alignée (voir `docs/TOOLCHAIN_RC_ALIGNMENT.md`), gate `scripts/canary_gate.ps1` ALL PASS
**Réseau :** local `127.0.0.1`, seed 42001, 8 nœuds + node9/node10/node11, VPS exclu
**Dates :** 2026-08-28
**Auteur :** Muse Spark (opencode)

---

## 1. Campagne

| Étape | Résultat |
|---|---|
| Purge + fresh dirs C2 + faucet.key | ✅ |
| Toolchain gate (SHA, CLI, RPC mortes, bootnode local) | ✅ ALL PASS |
| Launch 8 nœuds depuis genesis | ✅ total=0, faucet=1e18 |
| INC-C1-001 repro (200 tx parallèles, 8 wallets × 7 nœuds) | ✅ **0 divergence** |
| Test 1 bootstrap node9 | ✅ 209/209, 21.8 s, rebuild=0 |
| Test 2 restart non-seed ×3 | ✅ 3/3 |
| Test 3 crash dur ×3 | ✅ 3/3 |
| Test 4a disconnect/reconnect | ✅ 267/267 |
| Test 4b multi-peer offline | ✅ 9/9 à 325 |
| Test 5 wallet/faucet/send (Python E2E) | ✅ 12/12 |
| Charge 1000 (672 tx, 2.2 tps, 0 rejet) | ✅ + INC-C2-001 (heal) |
| Fresh node10 + restart seed + crash @1000 | ✅ |
| Charge 5000 (4000 tx, 2.1 tps, 0 rejet) | ✅ 0 divergence (9 nœuds) |
| Crash + restart @5000 | ✅ |
| Charge 10000 (5000 tx, 2.1 tps, 0 rejet) | ✅ 0 divergence majorité (9 nœuds @10008→10044) |
| Wallet E2E Python (3 wallets, faucet→send→restart→send) | ✅ PASS |
| Tests tooling wallet | ✅ 36/36 |

Débit stable ~2.1-2.5 tps, 0 rejet sur ~10 000 tx. Majorité 9 nœuds :
DAG + tips + supply(10 adresses) identiques à tous les niveaux.

## 2. W11 / T1 (toujours SÉVÈRE)

- Ratio tips/total stable ~0.73-0.74 (DAG très large : 7475 tips pour 10008 tx).
- Aucune branche artificielle, weight stable, pas de coût anormal observé.
- Surveillance continue, aucun changement consensus (interdit en canary).

## 3. Ressources (stables)

| Niveau | Disk total | RAM totale |
|---|---|---|
| ~1500 tx | 44.5 MB | ~400 MB (10 procs) |
| 10000 tx | (croissance linéaire, pas d'anomalie) | stable, pas de fuite |

Mempools drainés (size=0) après chaque charge, 0 rejet, 0 expired.

## 4. Incidents C2

| ID | Sévérité | Statut |
|---|---|---|
| INC-C2-001 : divergence ledger post-charge 1000 (6 vs 3) | MEDIUM | **RESOLVED** (heal par restart ×3) |
| INC-C2-002 : node10 tombé pendant charge 5000 (cause indéterminée, pas de logs) | MEDIUM | **OPEN** (nœud récupéré, WAL recovery OK) — suivi : stderr vers fichiers log |
| INC-C2-003 : divergence ledger DURABLE node10 (restart ne guérit pas) | **HIGH** | **OPEN** — nonce commis sans transferts ; hypothèse : garde recovery INC-01 (STEP 1c) fossilise les manques |
| INC-C2-004 : fresh nodes ne peuvent plus joindre (résolution orphans = 0) | **CRITICAL** | **OPEN** — cause racine prouvée : collapse de congestion sync (tri topo complet du DAG 10k à chaque GetData + tempête de re-requêtes parents) |

Détails : `docs/CANARY_INCIDENTS.md`.

## 5. Cause racine INC-C2-004 (mesurée, pas supposée)

- 60 s d'observation : seed +34.4M getdata-serves, node2 +32.6M ; frais
  entrants +7 tx/min. Réponses affamées, orphans monotones, 0 résolu.
- `p2p.rs` GetData : `topological_order` sur tout le DAG à chaque message.
- `rpc.rs` `process_orphans` : jusqu'à 128 parents re-demandés par cycle.
- Boucle à rétroaction positive = livelock dès ~10k tx pour tout nœud
  en rattrapage (join frais, retour après absence).
- La majorité incrémentale n'est pas affectée (pas de rattrapage massif).

## 6. Critères de sortie (§13)

- tooling aligné ✅ | INC-C1-001 non reproductible ✅
- charge stable ✅ | wallet E2E stable ✅
- **bootstrap stable ❌** (INC-C2-004 : joins frais impossibles à 10k)
- **aucun problème critique ❌** (INC-C2-003 HIGH + INC-C2-004 CRITICAL)
- restart stable ✅ (sauf ledger empoisonné C2-003) | crash stable ✅

## Verdict

```
🔴 STOP
```

La campagne C2 a prouvé exactement ce qu'un canary doit prouver : le
réseau sain à 9 nœuds et 10k tx (0 divergence majorité, 0 rejet), mais
**deux défauts bloquants pour tout testnet public** :
1. un nœud en rattrapage peut se retrouver avec un ledger durablement
   divergent et inguérissable par restart (INC-C2-003) ;
2. passé ~10k tx, plus aucun nouveau nœud ne peut joindre le réseau
   (INC-C2-004, cause mesurée).

**Prochaines étapes (protocol-review, nouvelle branche, pas en canary) :**
- GetData sans tri topo complet par message (ordre topo en cache / batch) ;
- borner/fusionner les re-requêtes parents ; revoir la dédup `is_orphan` ;
- auditer application live vs rebuild (garde STEP 1c, nonces sans transferts) ;
- logs stderr systématiques sur tous les nœuds de test ;
- sérialiser l'assignation des nonces faucet.

**Rappels :** pas d'audit externe crypto ; W11/T1 reste SÉVÈRE ;
VPS hors périmètre ; aucun binaire publié sans décision opérateur.

---

## 7. C3 — validation des fixes (branche `canary-c2-fixes`, 2026-09-05)

Commits : `2fd46e9` (cache topo + faucet serial), `064b788` (compteurs),
`07f7d46` (parents-first + test). SHA binaire : `8ADA9726…`.

| Fix | Résultat |
|---|---|
| Cache ordre topo (serve O(1)) | ✅ 28784 hits / 1 miss (était 1147 miss / 0 hit) |
| Ordre parents-first (root cause : indeg comptait les enfants) | ✅ + test `test_topological_order_parents_first` |
| Join frais à 10k DAG | ✅ 0 → 10043/10053 en ~20 min, 3510 orphans résolus, pas de tempête |
| Faucet sérialisé | ✅ en place (effet : plus de siblings même-nonce) |
| Tests Rust | ✅ 167/167 + 14/14 p2p (nouveau test inclus) |

**MAIS — divergence ledger persistante (classe C2-003, mécanisme affiné) :**
node11 DAG quasi complet mais ledger divergent (faucet nonce 28 vs 25 :
losers de conflits smallest-id-wins ingérés depuis les stores pairs,
winners correspondants jamais récupérés, queue -10 figée, restart
ingérissable). Voir `CANARY_INCIDENTS.md` (section C3).

### Verdict confirmé

```
🔴 STOP (inchangé)
```

Le collapse sync est réparé, mais un nœud en rattrapage peut toujours
atterrir sur un état ledger durablement divergent. Prochaine branche :
purge-on-prune synchrone, diagnostic winners manquants, redesign STEP-1c.

---

## 8. Branche `canary-c2-fixes` — correctifs P1→P3 (au-delà de `f8a435f`)

Protocole `77f01ee` intouché ; tout le travail est sur `canary-c2-fixes`.
Aucune règle consensus/DAG/ledger/économique modifiée (que de la
précision d'application, du serving et de l'observabilité).

| Priorité | Contenu | Commit | Tests |
|---|---|---|---|
| P1 purge-on-prune | `delete_transaction` + `batch_write` effacent aussi les clés `AddressIndex` (sender+receiver) et le mark applied ; un loser élagué ne laisse aucune trace servable | `4ff6446` | `test_delete_purges_address_index`, `test_batch_delete_purges_address_index` (contrôle négatif : échouent sur l'ancien code) |
| P2 diagnostic winners | compteurs `inventory_advertised`, `inventory_skipped_orphan`, `sync_response_items` exposés via `aether_getSyncStats` | `bab1b80` | `test_p2_diagnostic_counters` |
| P3 applied-tracking | arbre Sled `AppliedTx` + set `Ledger.applied` persisté ; STEP-1c routé sur preuve positive (appliqué/store) au lieu du seul nonce ; cross-check boot loggé | `99c06f5` | `test_applied_persistence_roundtrip`, `test_phantom_nonce_heals_transfer`, `test_applied_true_duplicate_skips_replay` ; setup du test INC-01 `recovery_insert_ledger_ahead` rendu fidèle (transfert réellement appliqué — l'ancien setup testait le cas fantôme) |
| P4 régression | suite complète | — | **174/174 PASS**, fmt, clippy, 0 erreur |

Mécanisme C2-003 affiné par cette analyse : l'out-of-order massif du
rattrapage + nonce max-rule + garde nonce-only = transferts sautés
fossilisés (aucun crash requis). P3 corrige exactement ce cas : un
winner tardif s'applique (au lieu d'être sauté), un vrai dupliqué ne
rejoue pas (rollback snapshot + rejet dupliqué DAG en garde-fous).
