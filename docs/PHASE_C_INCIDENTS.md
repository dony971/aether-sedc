# PHASE C — Registre des incidents (PHASE_C_INCIDENTS.md)

Phase C · Canary testnet contrôlé Aether V3 · RC B4 (`24c61e3`, SHA256
`8F04BB27…`, version 1.2.0) · genèse : hash fichier `4F3E693E…`, hash de
poignée de main `[0;32]` (src/genesis.rs), `network_id`
`59a4fc92…` (RELEASE_CANDIDATE.md §1).

Règle : aucune preuve n'est supprimée. Les logs cités sont conservés dans
`%TEMP%\opencode\aether-canary-b4\` (dossiers `node1`…`node14`,
`canary_phase_c.log`, `phase_c_escalation.log`).

---

## INC-01 — Redémarrage machine 00:25 — nœuds canary tués

| Champ | Valeur |
|---|---|
| Horodatage | 2026-08-18 00:25:35 (événements 1074/6006) ; redémarrages antérieurs : 09:55, 16:05, 22:10 (08-17) |
| Nœud | Tous (les 8 nœuds du réseau campagne) |
| Commit | `1262475` (exécutable RC B4 `8F04BB27…`) |
| Genèse | Inchangée |
| Reproduction | Redémarrage périodique de la machine (cause externe, non liée au logiciel) |
| Logs | Journaux d'événements Windows (System, sources Kernel-Power/User32) |
| Impact | Arrêt des 8 nœuds ; **aucune perte de transaction** : redémarrage sur les mêmes dossiers → total préservé (1000 tx) |
| Statut | **Résolu** (watchdog + redémarrage manuel 05:35-05:41, re-vérification 05:47) |

## INC-02 — Faucet bloqué à l'échelle (≥ ~1000 tx)

| Champ | Valeur |
|---|---|
| Horodatage | 2026-08-18 05:03 → 06:00 (phases 1-3 du script Phase C) |
| Nœud | nœud 1 (faucet), tous nœuds (oracle) |
| Commit | `1262475` (RC B4) |
| Genèse | Inchangée |
| Reproduction | 3 exécutions : `faucet` → `Insufficient fee: 1 < minimum 100` (et `minimum 64` en décroissance) ; cooldown 60 s/adresse appliqué même aux rejets |
| Logs | `canary_phase_c.log` ; rpc.rs:594-624 (FeeOracle), rpc.rs:407-436 (add_internal), src/node.rs:369 (`Mempool::new(1000, 10)`) |
| Impact | Faucet inutilisable au-delà de ~1000 tx (hystérésis de l'oracle : occupation ≥ 0,2 permanente sous le churn V-22 → frais min plafonnés à 100 > 1) |
| Statut | **Documenté — limitation de la RC** (aucune modification de la RC) ; contournement : portefeuilles préfinancés (12 wallets campagne, ~1e11 brut chacun) utilisés pour les tests utilisateurs |

## INC-03 — Mempool saturée (plafond 1000) — arrêt de l'entrée des transactions

| Champ | Valeur |
|---|---|
| Horodatage | 2026-08-18 05:48 → 06:05 (vagues de charge) |
| Nœud | Tous (nœud 1 mesuré) |
| Commit | `1262475` (RC B4) |
| Genèse | Inchangée |
| Reproduction | `Mempool error: Mempool add failed: Mempool full (consider higher fee for priority)` pour toute tx à frais 100 quand le pool est plein de tx à frais 100 ; 2 min après inactivité, la saturation persiste (le pool ne se vide jamais : aucun pop/drain en production — nœud miner/validator ne font que logger/dormir, node.rs:660-699) ; une tx à frais 200 est acceptée (éviction du min du pool, rpc.rs:419-425) |
| Logs | `canary_phase_c.log` ; probes 06:38 : fee 100 → REJECTED, fee 300 → ACCEPTED ; `phase_c_escalation.log` |
| Impact | **Le réseau ne peut pas dépasser ~1000 tx avec des frais uniformes** ; la croissance n'est possible qu'avec des frais croissants (enchère d'éviction : 100 → 200 → 300 → 500 observées) ; l'objectif de charge 2500/5000/10000 du mandat est **inatteignable** sur cette RC |
| Statut | **Documenté — limitation de la RC** (comportement déterministe, reproduit 3×) |

## INC-04 — Bootstrap bloqué au-delà de ~1000 tx (CRITIQUE — critère d'arrêt)

| Champ | Valeur |
|---|---|
| Horodatage | 2026-08-18 06:40 → 07:18 (test interrompu après 42 min) |
| Nœud | nœud 14 (joiner frais, ports 55001/55101), réseau 1-10 @1100 |
| Commit | `1262475` (RC B4) |
| Genèse | Inchangée |
| Reproduction | Join d'un nœud frais sur un réseau à 1100 tx : la convergence atteint **1012/1100 puis s'arrête définitivement**. Livelock Orphan Solver : re-requêtes P2P en boucle (`Orphan Solver - Re-requesting missing parent via P2P`), chaque tx reçue rejetée par le processeur → `Mempool add failed: Mempool full` → `P2P transaction rejected` ; 35+ min à 1012 sans aucun progrès |
| Logs | `%TEMP%\opencode\aether-canary-b4\node14\node.log` (32 797 lignes ; rejets en fin de fichier) ; stats sync finales : `requested=2827 received=1566 progress=9 batches=9716 | orphans created=1379 resolved=1003 purged=173 retries=1069 | parents requested=9593 deduped=8669 | dup_ignored=8797` — **purges d'orphelins > 0** (les joins de la campagne B4 avaient purged=0) |
| Impact | **Critère d'arrêt §10 du mandat déclenché : « bootstrap bloqué ».** Le join à 1000 tx (B4-3, 268 s, purged=0) fonctionne ; le join à 1100 tx échoue : la limite est le plafond du mempool (1000) |
| Statut | **Reproduit, documenté — STOP (nouvelle RC requise)** |

## INC-05 — Discordance d'empreinte transitoire du nœud 1

| Champ | Valeur |
|---|---|
| Horodatage | 2026-08-18 05:5x (pendant le redémarrage nœud 1) |
| Nœud | nœud 1 |
| Commit | `1262475` (RC B4) |
| Genèse | Inchangée |
| Reproduction | Empreinte session affichée `d1ce…` puis `0872…` ; après stabilisation : identique sur tous les nœuds échantillonnés (`df2c017ccf98`) ; nonce faucet 13 (cohérent) |
| Logs | logs nœud 1 |
| Impact | Aucun (transitoire, auto-réparée) |
| Statut | **Résolu (transitoire)** |

## INC-06 — Contact externe sur le port P2P (scanner)

| Champ | Valeur |
|---|---|
| Horodatage | 2026-08-17 → 08-18 (répété) |
| Nœud | nœud 1 (port 42001, IP publique de la machine) |
| Commit | `1262475` (RC B4) |
| Genèse | Inchangée |
| Reproduction | Scanner `103.102.135.123:25565` → rejeté : `Incompatible P2P protocol version` (poignée de main magic `AETH` + P2P v3, refus des non-v3) |
| Logs | logs nœud 1 (`node4.log`) |
| Impact | Aucun — le contrôle de version de protocole fonctionne (porte réseau fermée aux protocoles incompatibles) |
| Statut | **Bénin, surveillé** |