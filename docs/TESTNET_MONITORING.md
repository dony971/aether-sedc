# AETHER V3 — Surveillance du testnet (TESTNET_MONITORING.md)

Version: 1.2.0 · Réseau: TESTNET PUBLIC (canary) · P2P_PROTOCOL_VERSION: 3
Date: 2026-08-17

Ce document décrit les métriques et les seuils d'alerte à surveiller sur chaque
nœud du testnet AETHER V3. Il ne contient **aucun secret** (aucune clé, aucun
seed, aucun mot de passe).

---

## 1. Métriques RPC disponibles

Chaque nœud expose une API JSON-RPC locale (défaut `http://127.0.0.1:42101`).
Les méthodes utiles au monitoring :

| Méthode | Données retournées |
|---|---|
| `aether_getDagStats` | hauteur, nombre de transactions, poids, orphans, supply |
| `aether_getDagGraph` | DAG complet (nœuds + poids) |
| `aether_getDagSnapshot` | vue compacte du DAG |
| `aether_getTips` | tips courants (points d'entrée du DAG) |
| `aether_getRecentTransactions` | transactions récentes |
| `aether_getTransactionStatus` | statut d'une transaction (confirmée, Stable, final) |
| `aether_getMiningStatus` | état du minage |
| `aether_getBalance` / `aether_getAccountNonce` | solde / nonce d'un compte |
| `aether_getTransactionHistory` | historique d'un compte |
| `aether_sendTransaction` | envoi de transaction (faucet/tests uniquement) |

Métriques système : à relever via l'outil du système d'exploitation (Task
Manager, `top`, `ps`), pas via l'API.

## 2. Tableau des métriques et seuils

| Métrique | Source | Seuil normal | Alerte | Critique |
|---|---|---|---|---|
| Nœuds connectés (peers) | `aether_getDagStats` / logs `p2p` | ≥ 2 par nœud (hub ≥ 4) | < 2 pendant 5 min | 0 peer pendant 5 min |
| Utilisation CPU | système | < 50 % | > 80 % > 10 min | 100 % continu |
| RAM | système | < 2 Go | > 4 Go | > 8 Go |
| Disque | système | < 50 % | > 80 % | > 90 % |
| Taille du DAG | `aether_getDagStats` (tx count) | croît régulièrement | stagnation > 10 min | décroissance |
| Taille du mempool | txs envoyées − txs confirmées | < 1 000 | > 10 000 | > 50 000 |
| Orphans | logs `Loaded N orphans` / stats | < 100 | > 5 000 | > 20 000 (MAX_ORPHANS 50k) |
| TPS | txs récentes / fenêtre | < 10 | > 50 | > 200 (limite par nœud) |
| Latence RPC | temps de réponse | < 50 ms | > 500 ms | > 2 s |
| Synchronisation | écarts de hauteur entre nœuds | 0 | > 3 | > 10 (divergeance) |
| Consensus | hash txset/DAG/tips/ledger | identiques sur tous les nœuds | 1 nœud diffère | ≥ 2 nœuds diffèrent |
| Erreurs logs | logs `ERROR` / `WARN` | 0 | > 10/h | crash (processus absent) |
| Limites RPC | réponses `Rate limited` | 0 | > 100/h | > 1 000/h |

## 3. Procédure de relevé

1. Interroger chaque nœud : `aether_getDagStats`, `aether_getTips`,
   `aether_getRecentTransactions`.
2. Comparer les empreintes de convergence entre nœuds :
   - txset (ensemble des transactions),
   - hash du DAG (structure + poids),
   - tips,
   - hash du ledger (balances + nonces),
   - supply totale.
3. Relever CPU/RAM/disque du processus `aether-unified` sur chaque machine.
4. Compter les `WARN`/`ERROR` dans `node*.err.log`.
5. Archiver les relevés datés (sans secrets) dans un journal d'exploitation.

## 4. Alerte et escalade

- **Alerte** (seuil dépassé) : noter l'heure, le nœud, la métrique ; vérifier
  sur un second relevé.
- **Critique** (convergence perdue, divergence de ledger/DAG, crash massif,
  hash différent sur 2+ nœuds) : suivre la procédure
  `docs/INCIDENT_RESPONSE.md` — STOP DU RÉSEAU, préservation des journaux,
  identification du commit, reproduction, correctif, retest, nouvelle release.
- Toute anomalie de consensus impose **l'arrêt immédiat** du testnet et
  l'ouverture d'un rapport d'incident.

## 5. Limites RPC (rappel)

- 200 requêtes / 10 s / méthode (toutes IP),
- 40 requêtes / 10 s / (IP, méthode),
- corps de requête ≤ 1 MiB.
- Faucet : 10 AETH / 60 s / adresse (cooldown par adresse).

## 6. Ce qui ne doit JAMAIS apparaître dans les relevés

Clés privées, seeds, `faucet.key`, fichiers de wallet, adresses de clé
fondateur (sauf le compte public), logs d'erreur contenant des secrets.
Les relevés sont publiables dans leur intégralité.
