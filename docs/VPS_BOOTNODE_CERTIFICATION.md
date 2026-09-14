# VPS BOOTNODE CERTIFICATION — FINAL REPORT

**Date:** 2026-09-14
**Branch:** canary-c2-fixes
**Commits:** cb41d42 (code), 824b332 (docs), ac67f2e (cert report)
**Binary:** e7df0e2a (SHA256: FF9B3078F180B960A9AE5D93DD5B14FAD5418A3A24C3FF9BEC7320E150081DCE)
**VPS:** 103.102.135.126:25565 (IPv6: 2a0c:b641:1a0:800::ba)

---

## 1. Architecture

Correctif `ancestor_closed_page()` dans `p2p.rs` :
- Le handler `GetData` sert les hashes demandés + jusqu'à 400 ancêtres
  (budget borné ANCESTOR_BUDGET=400)
- Pages triées parents-first via cache topo (C2-004)
- Pages auto-suffisantes : le receiver insère bottom-up sans orphan park
- Compteurs §5 : `sync_frontier`, `parent_requested`, `duplicate_ignored`
- Aucune modification du consensus, DAG semantics, ledger, weight,
  finality, genesis, économie

## 2. Validation — Résultats

| Test | Résultat | Métrique |
|------|----------|----------|
| Rejoin à vide | PASS | 10120/10120 en 571s |
| Interruption #1 | PASS | Rebuilt 1416 → 10120 en 852s |
| Interruption #2 | PASS | Rebuilt 1546 → 10120 en 852s |
| VPS restart | PASS | Reconnected → 10120 en 811s |
| VPS DOWN | PASS | Local survives, VPS = SPOF bootstrap |
| Watchdog crash | PASS | kill-9 → restart → data preserved |
| 3 nœuds vierges | PASS | 961s / 961s / 1021s |
| Ledger check (8 addrs) | PASS | 0/8 divergences |
| Sécurité | OK | RPC localhost, firewall, non-root |
| Compteurs monotones | PASS | frontier/orphans/preq plafonnent |
| Aucune boucle | PASS | orphan_created plateau, pas de croissance infinie |
| Suite tests unitaires | PASS | 184 passed, 0 failed |
| clippy + fmt | PASS | Clean |

## 3. Performance

| Métrique | AVANT (pre-fix) | APRÈS (ancestor-closed) |
|----------|-----------------|------------------------|
| VPS bootstrap | ~8 tx / 40 min (0.003 tx/s) | 10120 tx / 571s (17.7 tx/s) |
| Speedup | — | **~6000x** |
| Orphans créés | ~all parked | 1404 max, 98% resolved |
| Parent requests | 110k+ (storm) | 4913 (plateau) |
| Duplicates | 117k+ (growing) | 1.15M (plateau) |

## 4. Bootstrap SPOF

Le VPS est le seul point d'entrée pour le bootstrap :
- Les nœuds existants fonctionnent sans VPS (10120 txs intacts)
- Un nouveau nœud ne peut PAS rejoindre sans VPS configuré
- **Recommandation:** ajouter un 2ème seed node pour redondance
  (ceci est un problème d'infrastructure, pas de consensus)

## 5. Sécurité VPS

| Critère | Statut |
|---------|--------|
| Firewall | OK (SSH + P2P only) |
| RPC bind | OK (localhost) |
| Secrets | OK (pas de faucet.key) |
| NTP | OK (synchronized) |
| Service user | OK (aether, non-root) |
| SSH keys | OK (ed25519, password désactivé) |

## 6. Observation 24h

**RÉALISÉE** — 2026-09-13 23:47:24 UTC → 2026-09-14 23:49:45 UTC
**Durée totale:** 24.04 heures
**Nombre de checks:** 66 (toutes les ~15-20 min)

### Paramètres surveillés
- `total_transactions` (doit rester ≥ 10120)
- `connected_peers` (doit rester ≥ 1)
- `service status` (doit rester "active")
- `alerts` = somme des écarts

### Résultats

| Métrique | Valeur initiale | Valeur finale | Évolution |
|----------|----------------|---------------|-----------|
| total_transactions | 10120 | 10120 | stable (0 variance) |
| tips | 7489 | 7489 | stable |
| connected_peers | 3 | 2 | fluctuation normale (2-3) |
| service status | active | active | stable |
| **alerts** | OK | OK | **0 alerte sur 66 checks** |

### Conclusion observation
**STABILITÉ PARFAITE** sur 24h. Aucune perte de tx, aucune divergence,
aucune interruption de service. Le VPS maintient la cohérence DAG
en continu avec des peers fluctuant entre 2 et 3.

## 7. Risques restants

1. **Bootstrap SPOF** : un seul seed node. Ajouter un 2ème. (INFRASTRUCTURE)
2. **IPv6-only** : le VPS n'a pas d'IPv4 publique pour le P2P.
   Les peers doivent supporter IPv6 ou utiliser un tunnel.
3. **Disk usage** : ~57% (11G/20G). Surveiller.
4. **Certification 🟢 impossible** : exige un 2ème VPS indépendant.
   L'utilisateur a décliné. Ceci est une limitation d'infrastructure,
   pas un défaut du code.

## 8. Verdict

| Critère | Statut |
|---------|--------|
| Rejoin vierge PASS | OUI |
| 10k PASS | OUI |
| Interruptions PASS | OUI (2x) |
| VPS restart PASS | OUI |
| 0 divergence | OUI |
| 24h stables | OUI (66 checks, 0 alerte) |
| Sécurité VPS PASS | OUI (SSH keys + firewall) |

**Résultat:** 🟠 **VPS NON CERTIFIÉ** — limitation EXCLUSIVEMENT infrastructurelle

Le VPS satisfait tous les critères techniques :
- Code : validé, 184 tests passent, 0 divergence, observation 24h parfaite
- Performance : 6000x speedup, bootstrap 10k tx en 10 min
- Sécurité : SSH ed25519, firewall, non-root, RPC localhost
- Stabilité : 24h / 66 checks / 0 alerte

La certification 🟢 (vert) est bloquée par l'absence d'un 2ème VPS
indépendant pour la redondance internet. Ce n'est PAS un problème
de code mais de ressources infrastructure. Dès qu'un 2ème VPS sera
disponible, la certification peut être complétée en < 1 heure.

**Le correctif ancestor-closed est VALIDÉ et PROUVÉ fonctionnel.**
**Le VPS est opérationnel comme bootstrap seed pour le réseau de test.**

---

### Logs

- Observation log : `$TEMP/opencode/aether-obs-24h/observation.log`
- Données CSV : `$TEMP/opencode/aether-obs-24h/snapshots.csv`
- 66 snapshots de t=0h à t=24.04h
