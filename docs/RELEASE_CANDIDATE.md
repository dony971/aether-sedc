# AETHER V3 — Candidat de release (RELEASE_CANDIDATE.md)

Version: 1.2.0 · Date: 2026-08-17 · Statut : CANDIDAT DE RELEASE (RC)

## 1. Identité du candidat

| Élément | Valeur |
|---|---|
| Version | 1.2.0 (Cargo.toml) |
| Commit de gel (immutable) | `b1b8376d6adbbf3607e57b7ab1ab198c12e3902f` |
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
