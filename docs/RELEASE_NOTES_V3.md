# AETHER — Notes de version V3 (RELEASE_NOTES_V3.md)

Version: 1.2.0 · Réseau: TESTNET PUBLIC (canary) · Date: 2026-08-17

## 1. Changements depuis V2

- **Nouvelle genèse** : comptes fondateur et faucet régénérés selon la
  cérémonie documentée (`docs/V3_TESTNET_CEREMONY_PLAN.md`), `network_id`
  dérivé de la genèse (`59a4fc92…`). Aucune continuité avec les réseaux
  précédents.
- **Nouveau protocole P2P (v3)** : version de protocole incrémentée,
  découverte par bootnodes, cycle de synchronisation 10 s, limites
  d'inventaire et de messages.
- **Consensus révisé** : confirmation à ≥ 3 références, statut `Stable` à
  poids ≥ 5,0, `practically_final`, convergence vérifiée par empreintes
  (txset / DAG / tips / ledger / supply).
- **Économie** : pas d'émission (minage par preuve de travail, zéro
  récompense), frais minimum 1 AETH **brûlés** (adresse `0xFF…FF`), offre
  initiale 1 000 000 000 000 000 000 + 100 000 000 000 (faucet + fondateur),
  plafond d'offre 2 000 000 000 000 000 000. Aucun mécanisme de staking ni
  d'énergie : tout ce qui existe est le modèle décrit dans le protocole.
- **Poids et h_weights** : fonction de poids consolidée et vérifiée par le
  harnais de tests (`h_weights` identique sur tous les nœuds).
- **Façade RPC** : limites de débit (200/10 s/méthode, 40/10 s/IP+méthode,
  1 MiB), faucet avec cooldown 10 AETH/60 s/adresse, désactivé sans clé.
- **Hygiène des clés** : le faucet nécessite `faucet.key` hors dépôt, jamais
  committé ; scan de secrets dans le CI/les scripts de vérification.
- **Modules supprimés** : vestiges de staking/énergie (`staking.rs`,
  `energy.rs`, VQV), `pow.rs`, `reputation.rs`, `explorer_api.rs`,
  `consensus.rs`, `economics.rs`, `security_audit.rs` — remplacés par
  l'architecture unifiée `aether-unified`.

## 2. Tests effectués

- **Tests unitaires** : 149 exécutés, 0 échec, 1 ignoré (S11), couvrant
  W1-W12 (wallet, transactions, frais, PoW, parents, DAG, confirmations,
  Stable, practically_final, synchronisation, redémarrage, faucet) et les
  scénarios de sécurité S1-S11.
- **Harnais multi-nœuds** : 3 exécutions complètes × 28 assertions
  (S1-S10) sur la genèse V3 : **84/84 PASS**, 0 FAIL, 0 dégradé, 0 divergence.
- **Smoke 5 nœuds** : réseau neuf, 5 nœuds, faucet sur un seul nœud, 10
  transactions (PoW 20), redémarrage d'un nœud, nœud hors ligne + resynchronisation :
  **PASS**, convergence txset/DAG/tips/ledger/weights/supply sur les 5 nœuds
  à chaque étape.
- **Vérification de la genèse** : `verify_genesis.ps1` et `verify_genesis.sh`
  : **EXIT 0** (0 échec) — clés historiques absentes, artefacts absents,
  `network_id` reproductible, offre conforme.

## 3. Sécurité

- `cargo audit` : **0 vulnérabilité**. 7 dépendances marquées « non
  maintenues » acceptées et documentées. `RUSTSEC-2026-0257` (webbrowser,
  Unix uniquement) ignoré par configuration, justifié dans le dépôt.
- Scan de secrets : aucun fichier contenant une clé privée, un seed ou un
  `faucet.key` dans le dépôt ni dans les artefacts de release.
- Les clés de la cérémonie (fondateur/faucet) sont stockées hors dépôt dans
  un dossier ACL-restreint ; elles ne sont **jamais** publiées.

## 4. Limites et risques connus

- **W11 (risque de divergence)** : classé SÉVÈRE et documenté
  (`docs/THREAT_MODEL.md` T1/W11). Le protocole ne prétend pas résoudre
  certaines classes de divergence ; le harnais vérifie qu'aucune ne se
  produit dans les scénarios testés.
- Pas d'audit de sécurité externe de la cryptographie (Ed25519 via
  dépendances standard, non audité indépendamment).
- Les clés de la cérémonie ont été générées sur une machine non isolée :
  recommandation de régénération hors ligne par l'opérateur avant tout
  déploiement durable.
- Le faucet autorise 10 AETH / 60 s / adresse : des abus de spam sont
  possibles, limités par les taux RPC.
- Orphelins plafonnés à 50 000 : un dépassement entraîne l'éviction des plus
  anciens.

## 5. Incompatibilités et migration

- **Migration impossible** : la genèse V3 a un `network_id` distinct ; un
  nœud V3 refuse toute autre genèse. Les wallets V2 peuvent être réimportés
  (même format de fichier) mais les comptes/soldes du réseau précédent
  n'existent pas sur le testnet V3.
- P2P v3 : les nœuds V2 et V3 ne peuvent pas se connecter (version de
  protocole incompatible).

## 6. Références

- `docs/WHITEPAPER_V2.md` — description du protocole (seule source de
  vérité).
- `docs/PROTOCOL_SPECIFICATION.md` — spécification technique.
- `docs/THREAT_MODEL.md` — menaces (T1-T6) et W1-W12.
- `docs/PUBLIC_TESTNET_NOTICE.md` — avis public de lancement (communication
  encadrée).
- `docs/RELEASE_CANDIDATE.md` — état du candidat de release et verdict.
