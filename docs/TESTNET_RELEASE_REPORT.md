# AETHER V3 — Rapport de release testnet (TESTNET_RELEASE_REPORT.md)

Version: 1.2.0 · Date: 2026-08-17 · Statut : CANDIDAT DE RELEASE

## 1. CODE

- Version `Cargo.toml` : **1.2.0**.
- Rust : 1.97.1 · `cargo` 1.97.1.
- `P2P_PROTOCOL_VERSION` : **3**.
- Code gELÉ : aucune modification consensus/ledger/DAG/économique après le
  gel ; tout correctif = nouvelle release (voir `INCIDENT_RESPONSE.md`).
- Compilation release propre après `cargo clean` (dossier `target/` purgé).

## 2. GENESIS

- Cérémonie : `docs/V3_TESTNET_CEREMONY_PLAN.md` +
  `docs/CEREMONIE_GENESIS.md` + `docs/RAPPORT_CEREMONIE_GENESIS.md`.
- `network_id` : `59a4fc920c91f4583aa427b860b6c04b337f263ab421be05264346c2076baa69`
  (reproductible : sha256 de `msg|fondateur|faucet|offres`).
- Comptes : fondateur `2ffab797…60d4` (100 000 000 000 AETH) ; faucet
  `a19ee04c…abfb` (1 000 000 000 000 000 000 AETH).
- Offre initiale : 1 000 000 000 000 000 000 + 100 000 000 000 ; plafond
  2 000 000 000 000 000 000 ; pas d'émission ; frais brûlés.
- Vérification : `verify_genesis.ps1` et `verify_genesis.sh` → **EXIT 0
  (PASS, 0 échec)** — logs : `verify_genesis_v3_ps1_final.log`,
  `verify_genesis_v3_sh_final.log` (conservés hors dépôt).

## 3. TESTS

- Unitaires : **149 exécutés, 0 échec, 1 ignoré** (S11, documenté).
- Harnais multi-nœuds (S1-S10, 28 assertions) : **3×28 = 84/84 PASS** sur
  genèse V3 (logs `resilience_v3_run1/2/3.log` conservés).
- Smoke 5 nœuds : **PASS** — faucet (OK / cooldown / désactivé sans clé),
  10 transactions PoW 20, redémarrage nœud, hors-ligne + resync, convergence
  txset/DAG/tips/ledger/weights/supply ×3 (log `testnet5_v3.log` conservé).
- Couverture : W1-W12 + S1-S11 (frais, PoW, parents, DAG, confirmations,
  Stable, practically_final, synchronisation, redémarrage, faucet, sécurité).
- 0 FAIL, 0 dégradé, 0 divergence constatés.

## 4. SECURITE

- `cargo audit` : **0 vulnérabilité** ; 7 dépendances non maintenues
  acceptées (config `.cargo/audit.toml`) ; `RUSTSEC-2026-0257` (webbrowser,
  Unix) ignoré avec justification.
- Scan de secrets : dépôt et artefacts exempts de clés privées/seeds ;
  `faucet.key` uniquement hors dépôt (dossier ACL-restreint).
- Clés de cérémonie : générées sur machine non isolée — recommande
  régénération hors ligne par l'opérateur avant déploiement durable
  (limitation assumée, pas un blocage du testnet canary).
- Menaces documentées : `docs/THREAT_MODEL.md` (T1-T6, W11 SÉVÈRE).
- Aucun audit externe de la cryptographie.

## 5. DEPENDANCES

- `cargo tree` verrouillé dans `Cargo.lock` (commit de gel).
- Nouvelles dépendances de release : aucune ajoutée depuis le gel.
- Non maintenues acceptées : listées dans `.cargo/audit.toml` (justification
  par version et usage).

## 6. RELEASE

- Dossier : `aether-v3-testnet-release/` (9 fichiers : binaires,
  `genesis.json`, `SHA256SUMS.txt`, `WHITEPAPER_V2.md`,
  `PROTOCOL_SPECIFICATION.md`, `THREAT_MODEL.md`, `PUBLIC_TESTNET_NOTICE.md`,
  `RELEASE_NOTES.md`).
- Empreintes :
  - `aether-unified.exe` : `f32723be8b5391349945c7713ec19acec063028cb4f105a055b90be2b0c98d7c`
  - `aether.exe` : `93bd414be6c771ab2b85f9cdb90397ad4ee5c82808ab63fcc4de1437ddea262e`
- Jamais inclus : clés, seeds, wallets, logs avec secrets, dossiers de
  données, genèses anciennes.

## 7. MONITORING

- `docs/TESTNET_MONITORING.md` : métriques RPC et système, seuils, alerte,
  escalade (divergence = STOP).
- Phases canary : A (3 seed) → B (5-10 contrôlés) → C (testeurs restreints)
  → D (public). Monitoring à chaque phase ; divergence = arrêt.

## 8. FAUCET

- Clé : hors dépôt, permissions minimales, un seul nœud faucet.
- Règles : 10 AETH / 60 s / adresse ; désactivé sans clé ; limites RPC
  (200/10 s/méthode, 40/10 s/IP) contre le spam ; logs sans secrets.
- Tests : requête normale OK, répétition → cooldown 60 s, nœud sans clé →
  désactivé, (over-limit et IP abusive couverts par les limites RPC et les
  tests unitaires de rate limiting).

## 9. LIMITATIONS

- W11/T1 SÉVÈRE documenté (divergence possible non résolue).
- Pas d'audit crypto externe ; clés non offline ; faucet spammable dans les
  limites ; orphelins plafonnés à 50 000 ; pas de staking ni d'énergie
  (futur documenté `FUTURE_STAKE_ENERGY_PROPOSAL.md`, NON NORMATIF).
- Communication publique limitée à `docs/PUBLIC_TESTNET_NOTICE.md`.

## 10. VERDICT

Voir `docs/RELEASE_CANDIDATE.md` — le verdict final (🔴 / 🟠 / 🟡 / 🟢)
est émis par l'opérateur après revue de ce rapport ; aucune publication
n'est automatique.
