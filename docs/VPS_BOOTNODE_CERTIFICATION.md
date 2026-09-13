# VPS BOOTNODE CERTIFICATION — FINAL REPORT

**Date:** 2026-09-13
**Branch:** canary-c2-fixes
**Commits:** cb41d42 (code), 824b332 (docs)
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
| SSH keys | MANQUE (password auth only) |

## 6. Observation 24h

**NON EFFECTUÉE** — les tests de la session ont été interrompus.
L'observation 24h est recommandée avant certification finale.

## 7. Risques restants

1. **Bootstrap SPOF** : un seul seed node. Ajouter un 2ème.
2. **SSH keys** : password auth uniquement. Ajouter des clés.
3. **Observation 24h** : non effectuée. Recommandée.
4. **IPv6-only** : le VPS n'a pas d'IPv4 publique.
   Les peers doivent supporter IPv6 ou utiliser un tunnel.
5. **Disk usage** : 57% (11G/20G). Surveiller.

## 8. Verdict

| Critère | Statut |
|---------|--------|
| Rejoin vierge PASS | OUI |
| 10k PASS | OUI |
| Interruptions PASS | OUI (2x) |
| VPS restart PASS | OUI |
| 0 divergence | OUI |
| 24h/48h stables | NON TESTÉ |
| Sécurité VPS PASS | PARTIEL (manque SSH keys) |

**Résultat:** 🟠 **VPS NON CERTIFIÉ** — conditionnel à :
1. Observation 24h (recommandée)
2. Ajout SSH keys (recommandé)
3. Ajout 2ème seed node (recommandé)

Le correctif ancestor-closed est VALIDÉ et PROUVÉ fonctionnel.
Le VPS est opérationnel comme bootstrap seed pour le réseau de test.
