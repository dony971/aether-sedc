# AETHER V3 — Candidat de release (RELEASE_CANDIDATE.md)

Version: 1.2.0 · Date: 2026-08-17 · Statut : CANDIDAT DE RELEASE (RC)

> **MAJ 2026-08-17 (soir) — RC B4 (`24c61e3`)** : correctif canary de
> phase B4 (bootstrap/sync P2P déterministe) committé au-dessus du gel.
> Le gel `b1b8376` reste immuable ; la RC B4 en conserve l'intégralité du
> consensus (aucun changement de weight, VQV, min-id, pruning, ledger,
> finalité, règle de parents, genèse ni paramètres économiques — vérifié
> par diff et par la batterie S1-S11/W1-W12). Voir §8.

## 1. Identité du candidat

| Élément | Valeur |
|---|---|
| Version | 1.2.0 (Cargo.toml) |
| Commit de gel (immutable) | `b1b8376d6adbbf3607e57b7ab1ab198c12e3902f` |
| Commit RC B4 (correctif canary) | `24c61e3` (9 fichiers, +1035/−111) |
| Branche | `main` (dépôt local, non poussé) |
| `P2P_PROTOCOL_VERSION` | 3 |
| `network_id` | `59a4fc920c91f4583aa427b860b6c04b337f263ab421be05264346c2076baa69` |
| Outil | rustc/cargo 1.97.1 |
| `Cargo.lock` | verrouillé, committé au commit de gel |
| Paramètres | difficulty 20 · frais min 1 · Confirmed ≥ 3 refs · Stable ≥ 5,0 · MAX_ORPHANS 50 000 · RPC 1 MiB · 200 req/10 s/méthode · 40 req/10 s/IP · faucet 10 AETH/60 s/adresse · supply 1e18+1e11 · MAX_SUPPLY 2e18 · FEE_BURN `[0xFF;32]` · zéro émission |

Le candidat est **immutable** : aucun changement de consensus, ledger, DAG
ou règle économique après ce commit. Tout correctif = nouvelle version.

## 2. Résultats de validation

- `verify_genesis.ps1` : EXIT 0 (PASS) — log `verify_genesis_v3_ps1_final.log`.
- `verify_genesis.sh` : EXIT 0 (PASS) — log `verify_genesis_v3_sh_final.log`.
- `cargo clean` + build release : OK (binaires sans débogage, `target/` purgé).
- `cargo test --lib` : 149 PASS / 0 FAIL / 1 ignoré (S11, documenté).
- `cargo fmt --check` : OK. `cargo clippy` : 43 avertissements (baseline).
- `cargo audit` : 0 vulnérabilité (7 non maintenues autorisées ; RUSTSEC-2026-0257 ignoré, justifié).
- Harnais S1-S10 : 3 × 28 = **84/84 PASS** sur genèse V3 (logs conservés).
- Smoke 5 nœuds : **PASS** (faucet, 10 tx PoW 20, redémarrage, hors-ligne+resync, convergence ×3).
- Scan de secrets : dépôt et artefacts exempts de clés privées / seeds / `faucet.key`.

## 3. Empreintes des binaires de release

| Fichier | SHA256 |
|---|---|
| `aether-unified.exe` | `f32723be8b5391349945c7713ec19acec063028cb4f105a055b90be2b0c98d7c` |
| `aether.exe` | `93bd414be6c771ab2b85f9cdb90397ad4ee5c82808ab63fcc4de1437ddea262e` |

(Tableau complet : `aether-v3-testnet-release/SHA256SUMS.txt`.)

## 4. Composition du dossier de release

`aether-v3-testnet-release/` (9 fichiers) :
`aether-unified.exe`, `aether.exe`, `genesis.json`, `SHA256SUMS.txt`,
`WHITEPAPER_V2.md`, `PROTOCOL_SPECIFICATION.md`, `THREAT_MODEL.md`,
`PUBLIC_TESTNET_NOTICE.md`, `RELEASE_NOTES.md`.

Jamais inclus : clés fondateur/faucet, seeds, `faucet.key`, wallets, logs
avec secrets, dossiers de données, genèses anciennes.

## 5. Plan canary (phases)

- **A** : 3 nœuds seed (monitoring actif, convergence vérifiée).
- **B** : 5-10 nœuds contrôlés par l'opérateur.
- **C** : testeurs restreints (faucet sollicité).
- **D** : public (avis public uniquement via `PUBLIC_TESTNET_NOTICE.md`).

Règle d'arrêt : toute divergence de txset/DAG/tips/ledger/supply, tout crash
ou incident de sécurité = arrêt du réseau + procédure `INCIDENT_RESPONSE.md`.

## 6. Verdict

> Verdict final (émis par l'opérateur après revue de ce dossier) :
>
> **🟡 CANARY TESTNET — PRÊT POUR LA PHASE A → B CONTROLLÉE**
>
> Le candidat satisfait toutes les conditions techniques de validation
> (genèse vérifiée, tests 84/84 + 5 nœuds, audit 0 vulnérabilité, aucun
> secret, monitoring défini). Le passage au testnet public (🟢) est
> subordonné à : audit externe de la cryptographie, régénération des clés
> de cérémonie sur machine hors ligne par l'opérateur, et observation
> stable des phases canary A→C. Aucune publication n'est automatique.

## 7. Artéfacts prêts à publier (si verdict 🟢/🟡 confirmé)

1. `aether-v3-testnet-release/` (dossier complet, 9 fichiers).
2. Commit `b1b8376d6adbbf3607e57b7ab1ab198c12e3902f` (source, gelé).
3. Logs de validation conservés hors dépôt : `verify_genesis_v3_ps1_final.log`,
   `verify_genesis_v3_sh_final.log`, `resilience_v3_run1/2/3.log`,
   `testnet5_v3.log` (publiables, sans secrets).
4. Dossier de cérémonie (secrets) : **jamais publié** — conservation par
   l'opérateur, hors dépôt (`%TEMP%\opencode\aether-v3-ceremony\`).

## 8. RC B4 — correctif canary (bootstrap/sync), 2026-08-17

### 8.1 Motivation

Le canary phase B (campagne 5 nœuds, commit `57aabd9`) a échoué sur
**B4 : livelock du bootstrap à froid** (jointure d'un nœud vierge sur un
DAG de 463 tx : 16/31 tx acceptées après 16 min, 11 159 rejets orphelins).
Analyse de logs : `park_orphan` re-demandait chaque parent manquant **sans
dédup ni backoff** (2 requêtes/orphelin) → le seed a répondu par
**23 394 SyncResponses à 1 tx** (~16/s), affamant les vraies rafales de
100 tx ; les chaînes orphelines n'avançaient que de 1 niveau/10 s ; le seed
servait les GetData dans un ordre arbitraire (HashMap), répété à chaque
cycle de 10 s.

### 8.2 Correctif (commit `24c61e3`) — bootstrap/sync uniquement

- `src/sync_stats.rs` (nouveau) : compteurs atomiques
  (`sync_requested/received/progress/batches`, `orphan_created/resolved/purged`,
  `parent_requested/parent_already_known`, `duplicate_ignored`, `retry_count`) ;
  `SyncContext` (parents demandés avec cooldown 2 s + backoff `[2,5,15]` s,
  naissances d'orphelins pour TTL) ; bornes : `MAX_INFLIGHT_PARENTS` 4096
  (éviction du plus ancien), `ORPHAN_TTL` 15 min, `ORPHAN_FIXPOINT_MAX_PASSES`
  64, `TOPO_ORDER_CAP` 50 000.
- `src/p2p.rs` : dédup des Inventory/SyncResponse contre DAG ∪ orphelins ;
  GetData servies **en ordre topologique** (Kahn, parents d'abord) ;
  `partition_batch` découpe chaque rafale en (livrable, en attente) par
  passes indépendantes de l'ordre ; `request_transaction` dédupliquée avec
  backoff croissant et ensemble borné.
- `src/rpc.rs` : `process_orphans` réécrit en **point fixe borné** avec purge
  TTL, ensemble des tentés, suppression des erreurs permanentes ; re-demande
  de parents plafonnée à 128 (au lieu de 32) ; nouvelle RPC
  `aether_getSyncStats`.
- `src/node.rs` : compteur `sync_progress`, log périodique des statistiques.
- Aucun changement de consensus (S1-S11, W1-W12 inchangés et verts).

### 8.3 Validation

- `cargo fmt --check` : OK. `cargo clippy --all-targets` : 0 erreur.
- `cargo test` : **154 PASS / 0 FAIL** / 1 ignoré (S11 documenté).
- `cargo audit` : 0 vulnérabilité (7 non maintenues autorisées, baseline).
- Builds propres (cargo clean + debug + release) : OK.
- **Harnais B4 `canary_b4_repro.ps1` : 23/23 PASS** — jointures à froid à
  100 (≈50 s), 224 (53 s), 300 (65 s), **463 (107 s)**, 500 simultanées,
  800 avec **redémarrage en cours de bootstrap** (tué à 186/800, converge en
  138 s après relance), **1000 avec churn de pair** (relais coupé puis
  relancé, converge en 237 s). Convergence vérifiée sur
  txset/DAG/tips/ledger/weights/supply identiques au seed. Zéro purge
  d'orphelin, zéro perte (stats `aether_getSyncStats`).

### 8.4 Empreinte du binaire RC B4

| Fichier | SHA256 |
|---|---|
| `aether-unified.exe` (RC B4, commit `24c61e3`) | `8f04bb278aed4fd11fc76f839dcadc58df8b1af97ee13db0b9fb620d9c5587ff` |
| `aether-unified.exe` (gel `b1b8376`, inchangé) | `f32723be8b5391349945c7713ec19acec063028cb4f105a055b90be2b0c98d7c` |

### 8.5 Verdict canary B4

> La campagne canary (phase A→B) sur la **RC B4** doit confirmer sur le
> réseau : jointure à 463 (MUST PASS), puis 500 et 1000, batterie B1-B8,
> monitoring divergence=0. Verdict final : 🔴 STOP si B4 échoue, 🟠
> NOUVELLE CORRECTION si régression, 🟡 NOUVELLE RC + CANARY si tout
> passe. Jamais de publication directe.
