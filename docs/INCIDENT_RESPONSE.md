# AETHER V3 — Réponse aux incidents (INCIDENT_RESPONSE.md)

Version: 1.2.0 · Réseau: TESTNET PUBLIC (canary) · Date: 2026-08-17

Ce document définit la marche à suivre en cas d'incident sur le testnet.
Aucun secret ne doit apparaître dans les rapports d'incident.

## Procédure générale

1. **STOP DU RÉSEAU** : arrêter les nœuds (ou le nœud concerné), geler le
   faucet (retirer `faucet.key`).
2. **COLLECTE DES JOURNAUX** : archiver l'ensemble des logs et métriques
   datés (heure UTC), sans secrets.
3. **PRÉSERVATION DES PREUVES** : copier données, DAG, ledger, configs,
   binaire et empreintes SHA256 sur support hors ligne avant tout correctif.
4. **IDENTIFICATION DU COMMIT** : relever la version et le hash du commit
   exact qui tournait.
5. **REPRODUCTION** : reproduire l'incident en local (mêmes paramètres,
   même genèse) avant toute modification.
6. **CORRECTIF** : patcher le code ; le code est gELÉ pour la durée du
   testnet — toute modification passe par une nouvelle release.
7. **RETEST** : rejouer la campagne complète (tests unitaires, harnais
   S1-S10 ×3, smoke 5 nœuds) sur la branche corrigée.
8. **NOUVELLE RELEASE** : nouvelle version, nouveau `SHA256SUMS.txt`,
   mise à jour de `RELEASE_NOTES` et de l'avis public.

## Scénarios connus

### S1. Divergence de ledger ou de DAG entre nœuds
- Critères : empreintes txset/DAG/tips/ledger/supply différentes sur 2+
  nœuds, ou hash identique mais ordre différent.
- Action : STOP immédiat ; préserver tous les logs ; reporter le scénario
  exact (charge, redémarrages, partitions) ; ouvrir un rapport détaillé.
- Référence : `docs/THREAT_MODEL.md` (W11 SÉVÈRE, T1).

### S2. Clé compromise (faucet ou fondateur)
- Critères : dépenses non autorisées, faucet vidé, demandes anormales.
- Action : retirer `faucet.key` immédiatement, révoquer l'adresse faucet
  (nouvelle genèse ou comptes de contrôle), préserver les preuves, publier
  un avis. La clé fondateur n'est pas dans le dépôt : si elle est exposée,
  le compte fondateur doit être considéré comme perdu.

### S3. Nœud seed compromis
- Critères : comportement anormal, connexions entrantes inhabituelles.
- Action : isoler le nœud, archiver ses logs, vérifier l'intégrité des
  binaires (SHA256SUMS), analyser les connexions. Les nœuds seed ne
  détiennent aucune clé : un compromis affecte la disponibilité, pas les
  fonds.

### S4. Crash massif des nœuds
- Critères : arrêts simultanés ou en cascade.
- Action : STOP, collecte des logs et des fichiers de données, vérification
  des ressources (CPU/RAM/disque), reproduction, correctif, nouvelle
  release.

### S5. Corruption de base de données (DAG/ledger)
- Critères : erreurs de lecture, empreintes incohérentes au démarrage,
  transactions manquantes après redémarrage.
- Action : geler le réseau, préserver les données corrompues (preuves),
  diagnostiquer (version, arrêt propre ?), réparer ou reconstruire,
  documenter la perte éventuelle de données.

### S6. Bug de consensus
- Critères : deux nœuds acceptent des blocs/transactions incompatibles,
  validité différente, poids incohérents.
- Action : STOP immédiat, préservation complète, reproduction hors ligne,
  correctif, retest complet, nouvelle release. C'est l'incident le plus
  grave : aucun correctif chaud n'est autorisé.

### S7. Vulnérabilité RPC
- Critères : charge anormale, réponses inattendues, contournement des
  limites.
- Action : restreindre l'accès RPC (firewall), collecter les requêtes
  reçues (sans secrets), auditer les méthodes exposées, patcher, nouvelle
  release.

### S8. Attaque de spam (faucet ou transactions)
- Critères : dépassement des limites RPC, mempool saturé, orphelins proches
  de 50 000.
- Action : ralentir/désactiver le faucet, surveiller, documenter. Les
  limites RPC (200/10 s/méthode, 40/10 s/IP) amortissent le spam.

### S9. Fork inattendu
- Critères : deux DAG divergents avec même genèse.
- Action : STOP immédiat, identifier le point de fork, préserver, comparer
  les empreintes, analyser la cause (version ? partition ? bug ?),
  correction, nouvelle release.

## Journal des incidents

Chaque incident est consigné dans `docs/INCIDENT_LOG.md` (créé au premier
incident) avec : date/heure UTC, scénario, nœuds concernés, version+commit,
cause racine, actions, correctif, retour d'expérience. Aucun secret.
