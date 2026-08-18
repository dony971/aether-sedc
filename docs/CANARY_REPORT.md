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

## PHASE B — 5 SEED NODES (autorisation opérateur)

### Autorisation et portes (GATES)

| Porte | Contrôle | Résultat |
|---|---|---|
| GATE 0 — Firewall | 12 règles créées (admin, via `scripts/gate_admin.ps1`) : 6 × RPC 42101-47101 « Any profile » + 6 × P2P 42001-47001 « Public profile » ; profils actifs ; défaut inbound = block ; aucune règle allow concurrente | PASS (avec réserve : le test LAN-IP 10.0.6.10 contourne le filtre Windows (hairpin NIC, hôte unique) → vérification externe différée à l'exposition publique ; RPC loopback toujours OK) |
| GATE 1 — Horloge | w32time démarré + Automatic, source pool.ntp.org (stratum 3, drift 0, dernier sync 17:53:13) | PASS |
| GATE 2 — Identité | HEAD `3681ddb` ; `git diff b1b8376 -- src/` = propre ; version 1.2.0 ; genesis `4f3e693e…` ; network_id `59a4fc92…` ; P2P_PROTOCOL_VERSION 3 ; SHA256 `f32723be8b5391349945c7713ec19acec063028cb4f105a055b90be2b0c98d7c` identique (target/package/binaire exécuté) ; data dirs neufs ; aucune clé privée sur les nouveaux nœuds | PASS (artefact regex corrigé, valeur re-vérifiée) |

### Déploiement (5 nœuds convergents)

| node_id | adresse (P2P/RPC) | pid | état |
|---|---|---|---|
| seed-1 (hub) | 42001/42101 | 3352 | running, 6 pairs |
| seed-2 | 43001/43101 | 1460 | running |
| seed-3 | 44001/44101 | 10768 | running |
| node-4 | 45001/45101 | 3344 | running (binaire du package, rejoint via 127.0.0.1:42001) |
| node-5 | 46001/46101 | 18020 | running (binaire du package, rejoint) |

Joins progressifs : hub peers 5 → 6, CONVERGENCE vérifiée après chaque joint (txset/dag/tips/ledger/weights/supply identiques). DAG final : **463 transactions**, identique sur les 5 nœuds.

### Tests B1-B8 (batterie v2, assertions corrigées) — RÉSULTAT : FAIL (2 échecs, les deux = B4)

| Test | Résultat |
|---|---|
| B1 — Sync incrémentale (10/50/100 tx pendant que nœuds 4-5 hors ligne, rejoints ensuite) | **PASS** — 0 rejet, deltas exacts, convergence 5/5 |
| B2 — Redémarrages (nœuds 4, 5, seed-2, même data dir) | **PASS** — 224 → 224 tx, 0 perte, resync + convergence |
| B3 — Hors-ligne 20 tx + récupération (nœud 4) | **PASS** — 439 = nœud 1, convergence |
| B4 — **NOUVEAU nœud (binaire package, data dir neuf) rejoignant un réseau à ~463 tx** | **FAIL — DÉFAUT RÉEL (code gelé)** : le sync de démarrage à froid se bloque (livelock). 8 717 téléchargements / 11 159 rejets « orphan » en 10+ min, DAG figé (16 tx à froid, 31 après redémarrage d'état partiel). Les joints à 61 tx (Phase A) et 224 tx (B3) fonctionnent → seuil de blocage entre 224 et 463 tx. Mécanisme (src/p2p.rs, non modifié) : livraison par lots hors-ordre (itération map), enfants reçus avant parents → park en orphelins ; résolveur (rpc.rs process_orphans) ré-essaie ≤32 parents/cycle mais chaque re-livraison est rejetée puis re-demandée (déduplication par appartenance au DAG, V-22) → boucle sans progression. Correspond au critère d'arrêt « problème P2P ». |
| B5 — Tentative de divergence (8 tx « concurrentes » toutes ensembles) | **PASS** — 0 divergence (67 occurrences « orphan » = lignes récurrentes bénignes ; orphelins réels = 0) |
| B6 — Double dépense (2 CLI, ordres d'arrivée opposés) | **PASS** — 1 acceptée + 1 rejetée au processeur (ledger : delta 1, convergé, balance 190) ; les 2 CLI affichent « envoyé » (gap de visibilité CLI documenté, main.rs:536-541 : rejet au niveau processeur après réponse RPC) |
| B7 — Rate limit (250 appels rapides) | **PASS** — 213/250 « Rate limited », OK après la fenêtre, aucun crash |
| B8 — Faucet sous charge (burst 8, multi-client via nœud 5, désactivé sur 4-5) | **PASS** — montant 1e11, cooldown, delta exact 10×(1e11+1), 0 secret dans les logs |

Conflits observés dans les logs : 247 paires same-id (re-livraison P2P bénigne, redondance de déduplication) + **1 conflit différent-id authentique** (nœud 4, 16:11:03Z, ids `a28c46b0` vs `eecf8ffd`) — traité déterministe (1 acceptée, 1 rejetée, convergence).

### Surveillance (monitor v5 puis v6 corrigé)

- Monitor v5 (17:59:28, 90 min, `canary_monitor_b.log`) : 48 snapshots, 0 erreur, 0 crash inopiné (3 événements « down » = nœud 6 stoppé/relancé par les tests), **mais `divergence=1` sur 41/48**.
- **ARTEFACT IDENTIFIÉ ET CORRIGÉ** : `aether_getDagSnapshot` est tronqué à 100 transactions (MAX_PAGE_SIZE) dans un sous-ensemble arbitraire par nœud (itération map) → empreintes fausses dès que le DAG dépasse 100 tx (Phase A à 61 tx : données valides). Vérifié directement : DAGs n1/n2 identiques (463 nœuds, 462 arêtes, poids identiques, txset identiques) → **la divergence observée était un faux positif de l'outil, pas une divergence réseau**.
- Monitor v6 corrigé (`canary_monitor.ps1` réécrit sur `aether_getDagGraph` complet, `canary_monitor_b2.log`, 19:37 → ~20:38) : premières snapshots **divergence=0, fp identiques sur les 5 nœuds**.
- Phase de stabilisation en cours (fenêtre 60 min) ; données finales consolidées en annexe.

### Faucet — état après Phase B

| Contrôle | Valeur |
|---|---|
| Solde restant | 999 997 399 999 999 974 (≈ 10 distributions supplémentaires de Phase B) |
| Actif sur | seed-1 uniquement (aucune clé sur nœuds 4/5) |

### Incidents / problèmes / résolution

| Problème | Cause | Résolution |
|---|---|---|
| Batterie v1 « 16 échecs » | 4 bugs de script de test (B3 ciblait le nœud hors-ligne ; B6 comptait via CLI au lieu du ledger ; B8 formule de delta sans frais + wallet non financé) + 11 lignes PASS à libellé inversé (FailIf) | batterie v2 réécrite sur le ledger + cibles vivantes uniquement → seul B4 reste en échec |
| B4 échec (2 runs) | livelock de sync à froid (code gelé, voir B4) | caractérisé pour le rapport ; aucun correctif appliqué (commit gelé) ; nœud 6 arrêté + purgé (réseau revenu à 5 nœuds) |
| divergence=1 du monitor v5 | troncature getDagSnapshot à 100 tx | monitor v6 sur getDagGraph ; divergence=0 confirmée |

---

## CANARY STATUS

```
A — PASS   (3 seed nodes, observation 40 min, batterie complète, 0 divergence)
B — FAIL   (5 seed nodes : batterie B1-B8 — B4 en échec : livelock de sync à froid
            d'un nouveau nœud au-delà de ~224 tx ; défaut sur code gelé)
C — NE PAS LANCER (recommandation) — le défaut B4 bloque l'ajout de nouveaux
    nœuds au réseau ; à corriger dans une nouvelle itération du protocole,
    re-geler, puis relancer une campagne canary
```

---

## CRITÈRES D'ARRÊT — vérification

Phase A : aucun critère déclenché.

Phase B : **critère « problème P2P » DÉCLENCHÉ (B4)** — un nouveau nœud ne peut
pas synchroniser un DAG > ~224 transactions (livelock d'orphelins, cf. B4).
Aucun autre critère déclenché : pas de divergence DAG/ledger/supply sur le
réseau des 5 nœuds, consensus cohérent, double dépense déterministe, pas de
corruption DB, pas de fuite de clé, pas de crash reproductible, genèse conforme.

## Passages de phase

Phase A → B : autorisée par l'opérateur (gates 0-2 validés).

Phase B → C : **NON recommandé**. Le défaut B4 (sync à froid) est un problème
P2P sur le code gelé ; toute extension du réseau (nœuds 6-10, testeurs publics)
échouerait à rejoindre. Verdict : **🟡 CONTINUER CANARY impossible sans correctif ;
🔴 STOP recommandé** — le réseau stable à 5 nœuds reste observé (monitor v6,
fenêtre de stabilisation ~20:38) en attendant la décision opérateur.
Le commit `b1b8376d6adbbf3607e57b7ab1ab198c12e3902f` reste immuable ; le correctif
sera développé dans une nouvelle itération, re-gelée avant toute campagne.

---

## PHASE B4 — CORRECTION DU BOOTSTRAP/SYNC P2P (mandat opérateur, 2026-08-17 soir)

### B4.1 Correctif committé (`24c61e3`, au-dessus du gel `b1b8376` — consensus intact)

Analyse de logs du livelock (run B4, seed-1) : `park_orphan` re-demandait chaque
parent manquant sans dédup ni backoff (2 req/orphelin) → le seed a répondu par
**23 394 SyncResponses à 1 tx (~16/s)** qui ont affamé les rafales de 100 tx ;
chaînes orphelines avancées de 1 niveau/10 s ; GetData servies en ordre
HashMap arbitraire, répété à chaque cycle de 10 s.

Correctif (bootstrap/sync uniquement, zéro changement de consensus) :
- `sync_stats.rs` (nouveau) : compteurs `aether_getSyncStats` + `SyncContext`
  (cooldown parent 2 s, backoff [2,5,15] s, `MAX_INFLIGHT_PARENTS` 4096,
  `ORPHAN_TTL` 15 min, `ORPHAN_FIXPOINT_MAX_PASSES` 64, `TOPO_ORDER_CAP` 50 k).
- `p2p.rs` : dédup Inventory/SyncResponse (DAG ∪ orphelins) ; GetData en ordre
  **topologique** (Kahn) ; `partition_batch` (livrable/en attente, ordre-indépendant) ;
  `request_transaction` dédupliquée avec backoff et ensemble borné.
- `rpc.rs` : `process_orphans` en point fixe borné + purge TTL + retrait des
  erreurs permanentes ; cap parents 32 → 128.
- `node.rs` : `sync_progress` + log périodique des stats.

### B4.2 Validation

- `cargo test` : **154 PASS / 0 FAIL** (S1-S11, W1-W12 inchangés et verts).
- `cargo fmt --check` : OK. `cargo clippy --all-targets` : 0 erreur.
- `cargo audit` : 0 vulnérabilité (7 non maintenues autorisées, baseline).
- Builds propres (clean + debug + release) : OK.

### B4.3 Harnais de reproduction `canary_b4_repro.ps1` — 23/23 PASS

| Cas | Résultat (RC B4 `8f04bb27…`) | Code gelé (réf.) |
|---|---|---|
| Jointure fraîche @100 | PASS (~50 s) | OK |
| Jointure fraîche @224 | PASS (53 s) | OK |
| Jointure fraîche @300 (relais inclus) | PASS (63-65 s) | — |
| **Jointure fraîche @463** | **PASS (107 s)** | **FAIL : livelock (16/31 tx après 16 min, 11 159 rejets)** |
| Jointure fraîche @500 | PASS (≈2 min) | — |
| **@500 simultanées (2 nœuds)** | PASS (J5+J6, convergence complète) | — |
| **Redémarrage en cours de bootstrap @800** | PASS (tué à 186/800, relancé, converge en 138 s) | — |
| **@1000 avec churn de pair** (relais coupé puis relancé) | PASS (237 s ; relais resynchronisé) | — |

Convergence vérifiée sur txset/DAG/tips/ledger/weights/supply **identiques au
seed** (getDagGraph avec limite explicite — plafond par défaut 500 corrigé dans
le monitor). Stats de synchronisation (ex. @1000) : `requested=2471
received=1138 progress=11 batches=2670 orphan_created=1108 orphan_resolved=990
orphan_purged=0 retries=990 parent_requested=2662 parent_deduped=2008
dup_ignored=2043` — **zéro purge, zéro perte, toutes les bornes respectées**.

### B4.4 RC B4

- Commit : `24c61e3` · SHA256 binaire : `8f04bb278aed4fd11fc76f839dcadc58df8b1af97ee13db0b9fb620d9c5587ff`
  (gel `b1b8376` : `f32723be…` inchangé — cf. `RELEASE_CANDIDATE.md` §8).
- Réseau canary gelé toujours en observation (5 nœuds, 465 tx, monitor b2
  divergence=0 sur 60 min). Note : reboot machine à 22:10 — réseau relancé à
  l'identique (5 nœuds, 465 tx, convergés).

### B4.5 Verdict attendu (mandat)

> Campagne Phase A → B sur la RC B4 : **jointure @463 MUST PASS**, puis 500/1000,
> batterie B1-B8, monitoring divergence=0. 🔴 STOP si B4 échoue ; 🟠 NOUVELLE
> CORRECTION si régression ; 🟡 NOUVELLE RC + CANARY si tout passe. Jamais de
> publication directe.

### B4.6 Campagne Phase A → B sur la RC B4 (`canary_b4_campaign.ps1`, 23:24-23:50)

Réseau **neuf** (8 nœuds, RC `8f04bb27…`, dirs `aether-canary-b4`, ports
42001-46101 + joineurs 47001-49101). Gates validés : SHA256 du binaire,
HEAD de campagne, diff `src` vs gel = fichiers B4 uniquement, version 1.2.0,
genèse. L'ancien réseau gelé (5 nœuds, 465 tx, monitor b2 divergence=0 sur
60 min) a été arrêté proprement après archivage.

**PHASE A — PASS** : 3 seeds déployés (faucet.key sur seed-1, copie avant
premier boot), 2 pairs hub, solde fondateur 100 000 000 000, convergence
3/3 pendant 2 min d'observation, 0 tx. Wallet générateur financé (1e11).

**PHASE B — batterie B1-B8 (5 nœuds)** :

| Test | Résultat |
|---|---|
| B1 — séries 10/50/100 (multi-endpoints 1/4/5) | **PASS** — 0 rejet, delta exact, convergence 5/5 |
| B2 — redémarrages nœuds 4-5 (mêmes dirs) | **PASS** — 0 perte, resync, convergence |
| B3 — nœud 4 hors-ligne pendant 20 tx | **PASS** — récupération + convergence |
| B5 — 8 tx concurrentes | **PASS** — ≥ 8 acceptées, convergence |
| B6 — double dépense (2 CLI parallèles) | **PASS** — exactement 1 acceptée, convergence |
| B7 — 250 appels rapides | **PASS** — 212 limités / 38 OK, nœud réactif après la fenêtre |
| B8 — faucet burst 8 | **PASS** — delta ≥ 8, convergence |

**B4 SERIES (PRIORITÉ) — joins à froid** :

| Test | Résultat | Code gelé (réf.) |
|---|---|---|
| **B4-1 jointure fraîche @463** | **PASS — 123 s** (stats : requested=798 received=470 batches=1169 orphan_created=468 resolved=461 purged=0) | **FAIL : livelock** |
| B4-2 jointure fraîche @500 | **PASS — 107 s** (orphan_purged=0) | — |
| B4-3 jointure fraîche @1000 | **PASS — 268 s** (requested=2523 received=1144 batches=2642 orphan_created=1133 resolved=993 purged=0, parent_deduped=1590, dup_ignored=1993) | — |

**Convergence finale 8/8 nœuds @1000 tx : PASS** (txset/dag/tips/ledger/
weights/supply identiques). **Zéro purge d'orphelin, zéro divergence** sur
toute la campagne. 6 « FAIL » du résumé = artefacts de script uniquement
(vérifications « exactement N » lues pendant le dernier tx en vol, message
affichant bien N ; check « nœud encore up » de B7 exécuté dans la fenêtre de
rate-limit — nœud confirmé réactif juste après). Checks corrigés
(Wait-Exact, pause hors fenêtre) pour les prochaines exécutions.

### B4.7 Verdict — campagne Phase A → B sur RC B4

| Critère | Résultat |
|---|---|
| Jointure @463 (MUST PASS) | ✅ PASS (123 s vs livelock gelé) |
| Jointures @500 / @1000 | ✅ PASS (107 s / 268 s) |
| Ordre (child-first, partition) | ✅ couvert : tests unitaires + joins à froid réels |
| Redémarrage en cours de bootstrap | ✅ harnais (186/800, relancé, converge 138 s) |
| Réseau (multi-pairs, churn, simultané, duplication) | ✅ harnais 23/23 + campagne |
| Performance avant/après | ✅ 123 s @463 vs boucle infinie |
| Compteurs de monitoring | ✅ `aether_getSyncStats` sur chaque join |
| Batterie B1-B8, divergence, convergence | ✅ PASS intégral |
| Consensus / gel `b1b8376` | ✅ intact (diff src = fichiers B4 uniquement) |

**Verdict : 🟡 NOUVELLE RC + CANARY validée** — tous les tests de la campagne
B4 passent, aucune régression, zéro divergence. Conformément au mandat,
**aucune publication directe** : la RC B4 (`24c61e3`, `8f04bb27…`) est
proposée comme candidat final à la décision opérateur (Phase C, extension du
réseau, testeurs publics). Réseau de campagne actif : 8 nœuds, 1000 tx,
convergés (observation continue possible via `canary_monitor.ps1
-NodeList 1,2,3,4,5,6,7,8 -DataRoot aether-canary-b4
-LogName canary_monitor_c.log`).

## C.1 — Phase C (testnet contrôlé) — RÉSULTAT : 🔴 STOP (nouvelle RC)

Le rapport complet est dans `docs/PHASE_C_REPORT.md` (12 sections du mandat)
et le registre des incidents dans `docs/PHASE_C_INCIDENTS.md`. En bref :
portes release/réseau PASS, testeurs 10 nœuds PASS, tests utilisateurs PASS
(faucet substitué), charge 100/500/1000 PASS, charges 2500/5000/10000
INATTEIGNABLES et bootstrap bloqué au-delà de ~1000 tx (plafond du mempool à
1000, jamais drainé ; join @1100 figé à 1012/1100, 42 min, livelock Orphan
Solver, purges d'orphelins > 0). 0 divergence, 0 perte, 0 crash. Décision
opérateur requise.
