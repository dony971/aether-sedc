# AETHER V3 — Rapport de campagne Canary (CANARY_REPORT.md)

Version: 1.2.0 · Commit gelé: `b1b8376d6adbbf3607e57b7ab1ab198c12e3902f` (IMMUTABLE)
Network ID V3: `59a4fc920c91f4583aa427b860b6c04b337f263ab421be05264346c2076baa69`
Date de la campagne: 2026-08-17

---

## PHASE A — 3 SEED NODES

### Déploiement

| Élément | Valeur |
|---|---|
| Date | 2026-08-17 16:35 (UTC+2) |
| Durée d'observation | 40 minutes instrumentées (16:56:39 → 17:36:44) |
| Nombre de nœuds | 3 (seed-1, seed-2, seed-3) + 1 nœud temporaire (test « nouveau peer ») |
| Versions | software 1.2.0 · commit b1b8376 · P2P_PROTOCOL_VERSION 3 |
| Genesis hash (sha256 genesis.json) | `4f3e693ee56a224dec556f1c05a7c2f4383b2ba8334368ae5d25ba48991d9f8f` |
| network_id | `59a4fc920c91f4583aa427b860b6c04b337f263ab421be05264346c2076baa69` (recalculé, identique) |
| Data directory | neuf (purgé avant déploiement, 0 fichier résiduel) |
| Anciennes données | aucune |
| Clés de cérémonie | absentes des data dirs et des logs (scan à 0) |
| Faucet | désactivé au déploiement (aucun `faucet.key`), activé APRÈS stabilisation |
| Horloge | locale lisible ; service w32time arrêté sur la machine opérateur (à corriger sur les seeds publics) |
| Firewall | 3 profils actifs ; règles « RPC loopback-only » à créer par un admin (accès refusé dans la session) ; RPC se lie sur 0.0.0.0 (node.rs:565) → RÈGLE OBLIGATOIRE avant exposition publique |

### Identité des seeds (manifest)

| node_id | adresse (P2P) | pid | uptime | peers |
|---|---|---|---|---|
| seed-1 (hub) | 127.0.0.1:42001 | 3352 | running (campagne entière) | 4 (max 5) |
| seed-2 | 127.0.0.1:43001 | 1460 | running (1 redémarrage contrôlé) | 1 |
| seed-3 | 127.0.0.1:44001 | 10768 | running (1 récupération hors-ligne) | 1 |

Adresses « publiques » = loopback dans cet environnement de campagne ; l'opérateur
redéploie les seeds sur des hôtes publics avec le MÊME commit, la MÊME genèse et
les MÊMES SHA256 (aucune clé privée impliquée).

### OBSERVATION A — données (40 snapshots, 1/min)

| Métrique | Résultat |
|---|---|
| Divergence (empreintes txset/tips) | **0/40** snapshots (fp1=fp2=fp3 à chaque instant) |
| Erreurs RPC/P2P (WARN/ERROR dans les logs) | **0** tout au long |
| Crashes | **0** |
| Redémarrages | 3, tous contrôlés par les tests (activation faucet, restart node2, recovery node3) |
| Sync (écart de hauteur/état entre nœuds) | **0** en permanence |
| Orphelins | **0** (métrique `Loaded N orphans` = 0 à chaque cycle) |
| TPS (mesuré par les nœuds) | ≤ 1 stable ; pics de charge > 30 tx/min pendant les tests |
| CPU (cumulé) | n1 ≈ 7s, n2 ≈ 1.7s, n3 ≈ 1.6s sur 40 min (très faible) |
| RAM | 12-34 MB par nœud |
| Disque libre | 37.6-37.7 GB (stable) |
| Taille du DAG | 0 → 61 transactions, identique sur les 3 nœuds |
| Mempool | vidé après chaque cycle (aucune accumulation) |
| État consensus | identique sur les 3 nœuds (empreintes égales, supply identique) |
| T1 / W11 (divergence documentée SÉVÈRE) | **AUCUNE occurrence observée** dans les scénarios exécutés ; risque documenté, non corrigé dynamiquement |

### Tests canary (batterie complète) — RÉSULTAT : PASS (0 échec)

| Test | Résultat |
|---|---|
| Faucet désactivé avant stabilisation (3 nœuds) | PASS |
| Gate de stabilité (30 s, aucun changement) | PASS |
| Activation faucet (key sur nœud 1 uniquement, redémarrage) | PASS |
| Faucet : 1ère requête OK (10 AETH = 1e11) | PASS |
| Faucet : 2e requête même adresse → cooldown 60 s | PASS |
| Faucet : désactivé sur les nœuds sans clé (2, 3) | PASS |
| Faucet : burst 8 adresses → 0 rejet inattendu | PASS |
| Transactions normales (5 self + 5 cross, PoW 20) | PASS (10/10) |
| Transactions concurrentes (8) | PASS (8/8) |
| Double dépense (1 acceptée + 1 rejetée, ledger: balance=90, nonce+1) | PASS — déterministe |
| Redémarrage nœud 2 (même data dir) | PASS — resync + convergence |
| Nœud 3 hors-ligne + 20 tx + récupération | PASS — resync + convergence |
| Nouveau peer (nœud 4) joint + quitte | PASS — sync + convergence avant/après |
| Spam raisonnable (30 tx) | PASS (30/30) |
| Rate limit RPC (250 appels rapides) | PASS (210/250 « Rate limited ») |
| Orphans | 0 observés (couverture unitaire existante) |
| Convergence post-charge / post-restart / post-resync / post-spam | PASS à chaque étape |
| Aucun secret dans les logs (scan du seed faucet) | PASS (0 occurrence) |

### Faucet — état après campagne

| Contrôle | Valeur |
|---|---|
| Actif sur | seed-1 uniquement (clé hors dépôt, fichier `faucet.key` local) |
| Cooldown | 10 AETH / 60 s / adresse (testé) |
| Rate limit | RPC 200/10 s/méthode + 40/10 s/IP+méthode (testé) |
| Plafond par demande | 10 AETH (1e11 unités) — vérifié au ledger |
| Adresse faucet | `a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb` (publique) |
| Solde restant | 999 998 799 999 999 988 (≈ 12-13 distributions de 10 AETH, cohérent) |
| Logs | aucun secret (scan du seed = 0) |
| Distributions anormales | aucune (seuls les wallets de test ont reçu) |

### Incidents / problèmes rencontrés / résolution

| Problème | Cause | Résolution |
|---|---|---|
| Échec initial de déploiement | `--node-type full` invalide (types: miner/validator/observer) | réglé sur `validator` (scripts campagne, code gelé non modifié) |
| Gate « fresh data dirs » | `manifest.txt` résiduel verrouillé | purge racine avec retries dans le script de déploiement |
| 1er run de tests stoppé au double-spend | `ErrorActionPreference=Stop` + sortie stderr du CLI | passage en `Continue` (assertions explicites conservées) |
| Double-spend « aucun accepté » (1er run) | montant = solde total → pas de marge pour les frais (10) | montant = solde − 100 ; vérification au ledger (balance=90, nonce+1) |
| Manifest adresses erronées (cosmétique) | formule 42000+i*1000+1 | corrigée (42001/43001/44001) |
| Nœud 4 temporaire non arrêté | son dossier n'existait pas → pid file non écrit | arrêt manuel + purge du dossier |

Aucun incident de réseau, aucune divergence, aucun crash, aucune fuite.

---

## CANARY STATUS

```
A — PASS   (3 seed nodes, observation 40 min, batterie complète, 0 divergence)
B — EN ATTENTE DE DÉCISION OPÉRATEUR (phase suivante non lancée)
C — EN ATTENTE DE DÉCISION OPÉRATEUR
```

---

## CRITÈRES D'ARRÊT — vérification

Aucun critère d'arrêt déclenché : pas de divergence DAG/ledger/supply, consensus
cohérent, double dépense déterministe, pas de corruption DB, pas de fuite de
clé, pas de crash reproductible, synchronisation parfaite, genèse conforme,
aucune vulnérabilité critique observée.

## Passages de phase

Conformément au mandat, la campagne s'ARRÊTE ici : le passage en Phase B (5-10
nœuds contrôlés) requiert une décision humaine explicite de l'opérateur.
Le commit `b1b8376d6adbbf3607e57b7ab1ab198c12e3902f` reste immuable.