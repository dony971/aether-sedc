# Compte-rendu de la Cérémonie Genesis — 2026-08-16

**Résultat global : 🟡 TESTNET PUBLIC POSSIBLE — cérémonie exécutée, toutes les vérifications PASS.**

## 1. Résultat de la purge

| Élément | Quantité purgée | Vérification post-purge |
|---|---|---|
| `faucet.key` (ancien seed) | 52 fichiers (data-dirs de test) | 0 restant |
| `faucet.json` (secret_key_hex en clair) | 1 | 0 restant |
| Wallets JSON de test (ancien réseau) | ~328 (A.json…, probe wallets) | 0 restant |
| Runs réseau (aether-net, aether-net2 : DAG Sled, ledger, txs) | 19 + 8 runs antérieurs | supprimés |
| Binaires compilés contenant la clé (GUI + wallet_stage) | 5 (`guia\a111.exe`, `guia\a112.exe`, `wallet_stage\**\aether.exe` ×3) | supprimés |
| Scripts avec seed en dur (`multi_node.ps1`, `focus_test.ps1`, `key_exposure.py`, `key_exposure2.py`) | 4 supprimés, 1 modifié (`resilience.ps1` → env vars) | 0 occurrence |
| Logs de runs (aether-smoke*.out.log, run dirs) | supprimés | 0 restant |
| Dossiers divers (probe1-3, testnode1-7, itest, ci-test, gh_logs, mingw, monpetit, faucetkey, aether-sedc, runners CI) | supprimés | 0 restant |

**Scan final** : `fa5979dd7273d55c6b5f2028ab166dc3163f90ac9f68da28b79a1fe0f06c45b8`
présente uniquement dans les 3 fichiers whitelist de la cérémonie
(`docs/CEREMONIE_GENESIS.md`, `scripts/verify_genesis.ps1`, `scripts/verify_genesis.sh`).
Le dépôt source (`src/`) et les binaires publiés : 0 occurrence. ✓

## 2. Résultat de la rotation

| Contrôle | Résultat |
|---|---|
| Ancien faucet.key placé dans un nœud du nouveau réseau | **REJETÉ** : `faucet.key does not match genesis FAUCET_ADDRESS (derived 5579ae…, expected e880b7…)` — faucet désactivé |
| Solde des anciennes adresses (founder `3d17ac…`, faucet `5579ae…`) | **0** sur le nouveau réseau |
| Solde des nouvelles adresses | founder = `100000000000` (10 AETH), faucet = `1000000000000000000` (100M AETH) ✓ |
| Réseau neuf | `total_transactions = 0` — aucun état de l'ancien réseau importé ✓ |

## 3. Nouveau Genesis

| Paramètre | Valeur |
|---|---|
| `GENESIS_MESSAGE` | `16/Aug/2026 - Aether: Trust is computed, not granted. Genesis rotation: legacy faucet key revoked, new canonical ledger. Le Monde 16/08/2026.` |
| `FOUNDER_ADDRESS` | `32252d108b9079fc049347697cf4ebe48723ad682e3f03e1d257fb9db7fc298b` |
| `FAUCET_ADDRESS` / `FAUCET_PUBLIC_KEY` | `e880b7f984acd825eace21d38fa85a2cebf33d6bfcb5e7f521369c339fdb1518` |
| `FEE_BURN_ADDRESS` | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |
| Supply initiale | `1000000100000000000` (1e18 + 1e11) |
| MAX_SUPPLY | `2000000000000000000` (200M AETH) |
| `GENESIS_HASH` (block genesis) | `0000000000000000000000000000000000000000000000000000000000000000` |
| **`network_id`** (SHA256 message\|founder\|faucet\|supply\|max) | **`714c2a89e66adcb9aea304666084e6eede5db7977cc45f888a08a88cf181de2c`** |

Calculé **identiquement** par `verify_genesis.ps1` et `verify_genesis.sh` ✓ (référence : `docs/genesis.json`).

## 4. Résultat des deux verify_genesis

| Script | Avant cérémonie | Après purge+rotation | Après runs S1-S10 + purge finale |
|---|---|---|---|
| `scripts/verify_genesis.ps1` | FAIL (7 échecs, gate actif) | **PASS, exit 0** | **PASS, exit 0** |
| `scripts/verify_genesis.sh` | FAIL (5-4 échecs, gate actif) | **PASS, exit 0** | **PASS, exit 0** |

> Note : le `.sh` a été corrigé (extraction des adresses robuste sans PCRE multi-lignes) —
> le gate était volontairement rouge avant la cérémonie, vert après.

## 5. Contrôle des dépendances (RUSTSEC-2026-0221)

- **Crate** : `event-listener` — **version vulnérable** : `5.4.1` — **patched** : `>= 5.4.2`.
- **Chaîne de dépendances** (GUI uniquement) :
  `aether-unified 1.1.1 → eframe 0.27.2 → egui-winit → accesskit_winit →
  accesskit_unix → zbus 3.15.2 → async-process 1.8.1 / async-lock 3.4.2 /
  event-listener-strategy 0.5.4 → event-listener 5.4.1`.
- **Impact réel sur Aether** : très faible — (a) chemin exclusivement lié au GUI et à
  l'accessibilité (AT-SPI/D-Bus, actif sur Linux, pas dans le graphe de build Windows) ;
  (b) l'advisory (unsound `Send`/`Sync` sur `StackSlot` avec `Event::with_tag`) requiert
  un usage de tags `!Send` non utilisé par ces crates. **Non exploitable tel quel**,
  mais corrigé par précaution.
- **Résolution** : `cargo update -p event-listener` → **5.4.2** (aucune suppression
  d'advisory ; `audit.toml` inchangé pour 0221 — seul RUSTSEC-2026-0257 reste ignoré,
  avec justification documentée).
- **Cargo audit final** : `Scanning Cargo.lock (567 crates)` — **0 vulnérabilité**,
  7 warnings « unmaintained » (bincode, derivative, fxhash, instant, paste,
  rustls-pemfile, ttf-parser — toutes transitives, non exploitées).

## 6. S1–S10 sur le nouveau Genesis

Harnais : `resilience.ps1` (seed/adresses via env vars, jamais en dur), binaire
`target\release\aether-unified.exe` rebuild propre (`cargo clean` + `cargo build --release`,
5 m 44 s, puis `cargo test --lib` : **122/122 PASS**).

**3 runs complets S1–S10 : 84 assertions, 84/84 PASS, 0 FAIL, 0 WARN.**
Preuves : `genesis_run3.txt`, `genesis-run-proof\` (logs du run final, secrets retirés).

| Scénario | Tx attendues | Résultat ×3 runs |
|---|---|---|
| S1 (2 nœuds, 20 txs) | 20 | PASS (supply exacte) |
| S2 (3 nœuds, kill+restart node3, 30 txs) | 30 | PASS |
| S3 (3 nœuds, kill node2 early, 30 txs) | 30 | PASS |
| S4 (4 nœuds, disconnect+reconnect node4, 50 txs) | 50 | PASS |
| S5 (5 nœuds, kill node5, 100 txs) | 100 | PASS |
| S6 (3 nœuds, reboot total, 30 txs) | 30 | PASS |
| S7 (4 nœuds, 30 txs simultanées) | 30 | PASS |
| S8 (double dépense, send impossible) | 3 | PASS (rejeté, 1 survivant) |
| S9 (collision même nonce) | 3 | PASS (0 doublon (sender,nonce)) |
| S10 (4 nœuds, 200 txs) | 200 | PASS |

Dans **chaque** assertion : `supply=1000000100000000000` exact ; `h_txset`, `h_dag`,
`h_tips`, `h_ledger` SHA-256 identiques sur tous les nœuds ; les 3 « SEND FAILED »
sont les rejets attendus de S8(a) (send impossible), un par run.

## 7. Artefacts publiables (testnet)

Dossier `aether-release-714c2a89\` :

| Fichier | SHA-256 | Taille |
|---|---|---|
| `aether-unified.exe` (CLI+RPC+P2P) | `f0b6ac44381189e35ed98bc0afe128a588a50ce410a513890674e4bad3b82691` | 17 452 379 |
| `aether.exe` (GUI) | `5871128473b15d88cb92d8c380beb34bcd86f1a93682a1ea95ded75ab69ea952` | 25 746 120 |
| `genesis.json` (référence) | `cb4255588f96b6bbb581fb1423bc8c6a11e3429d8a7687603cf1597bca1d7704` | 1 019 |
| `SHA256SUMS.txt` | manifest | — |

Binaires scannés : 0 occurrence de la clé historique, 0 occurrence des anciennes
adresses. Build : commit `be4df38` + rotation (genesis.rs), rustc 1.97.1, target GNU.

## 8. Secrets qui doivent rester HORS publication

| Secret | Statut |
|---|---|
| Seed faucet historique `fa5979…` | **COMPROMIS** — n'existe plus que dans la whitelist cérémonie (documentation de détection) |
| **Nouveau seed faucet** `24a3ee…` (faucet.key) | DOIT rester hors dépôt — fourni par env var aux opérateurs, jamais commité |
| **Nouveau seed founder** `c44b38…` | DOIT rester hors dépôt (PEM dans `genesis-ceremony\`, à transférer dans un coffre) |
| Wallets de test (pwtest123) | temporaires, purgés après chaque run |
| `resilience.ps1` (env vars) | ne contient plus de secret en dur |

## 9. Verdict final

**🟡 TESTNET PUBLIC POSSIBLE** — cérémonie genesis exécutée, purge complète vérifiée,
rotation prouvée, 2/2 gates `verify_genesis` verts (exit 0) avant et après tests,
0 vulnérabilité de dépendance (RUSTSEC-2026-0221 corrigée), S1–S10 ×3 PASS sur le
nouveau genesis (84 assertions, supply exacte). **Pas 🟢** : pas d'audit crypto
externe, 7 dépendances unmaintained, traçabilité V-02…V-19 non documentée,
V-20/V-21/V-22/V-23 et NV-02/NV-09 corrigées mais non auditées par un tiers.
**Publication du testnet autorisée** selon la checklist opérateur (Étape 7 de
`CEREMONIE_GENESIS.md`) : ≥3 seed nodes, monitoring Prometheus, alertes divergence
d'état/sync, faucet.key du nouveau seed déployé UNIQUEMENT sur les nœuds faucet désignés.