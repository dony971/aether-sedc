# Cérémonie Genesis — AETHER SEDC

**Objet** : purge totale de l'ancien genesis (clé faucet `fa5979…` compromise) et
création d'un nouveau réseau, reproductible et vérifiable par une personne externe.
**Règle d'or** : *ne jamais supposer qu'un ancien secret est supprimé — prouver son
absence.* Toute occurrence de l'ancien faucet est une compromission potentielle.

---

## Étape 0 — Prérequis

- Machine **hors ligne** pour la génération des clés (jamais de réseau pendant
  l'Étape 2).
- Environnement de build reproductible : Rust `1.97.1`, toolchain GNU MSYS2
  (`C:\msys64\ucrt64\bin`), réseau isolé.
- Rôles séparés : `OPERATOR` (exécute), `WITNESS` (vérifie indépendamment),
  `REVIEWER` (contresigne le rapport).

---

## Étape 1 — Inventaire (résultats RÉELS de la campagne)

Scan complet exécuté le 2026-08-16 (résultats réels) :

### 1.1 Ancienne clé privée `fa5979dd7273d55c6b5f2028ab166dc3163f90ac9f68da28b79a1fe0f06c45b8`

| FICHIER | TYPE | ACTION | STATUT |
|---|---|---|---|
| `src/genesis.rs` (dépôt `aether-main`) | Source | AUCUNE occurrence | CONSERVÉ (vérifié : 0 occurrence) |
| `src/rpc.rs`, `src/wallet.rs`, `src/transaction.rs`… | Source | AUCUNE occurrence | CONSERVÉ (vérifié) |
| `Cargo.lock`, `Cargo.toml`, `config.toml`, `*.yml`, `*.toml`, `*.json` du dépôt | Config | AUCUNE occurrence | CONSERVÉ (vérifié) |
| `C:\Users\Shadow\AppData\Local\Temp\opencode\faucet.json` | Wallet (secret_key_hex = fa5979…) | **SUPPRIMÉ** | À supprimer |
| `C:\Users\Shadow\AppData\Local\Temp\opencode\resilience.ps1` | Harnais (`$FAUCET_SEED`) | **MODIFIÉ** (seed retiré, remplacé par paramètre) | À modifier |
| `C:\Users\Shadow\AppData\Local\Temp\opencode\multi_node.ps1` | Harnais (seed) | **SUPPRIMÉ ou MODIFIÉ** | À traiter |
| `C:\Users\Shadow\AppData\Local\Temp\opencode\focus_test.ps1` | Harnais (seed) | **SUPPRIMÉ ou MODIFIÉ** | À traiter |
| 52 × `faucet.key` dans les data-dirs de test (`aether-net2\*\node1\faucet.key`, probes, smoke…) | Clé faucet | **SUPPRIMÉ** (tous) | À supprimer |
| ~328 × `*.json` wallets de test (`A.json`, `B.json`… + `probe*/w.json`) | Wallets | **SUPPRIMÉ** (tous) | À supprimer |
| Logs de runs (123 fichiers contenant « faucet »/seed) | Logs | **SUPPRIMÉ** | À supprimer |
| 19 dossiers de runs `aether-net2\2026*` (DAG Sled, ledger, txs) | Données réseau | **SUPPRIMÉ** | À supprimer |
| `aether-net`, `aether-focus`, `aether-smoke*`, `aether-tipcheck`, `testnode*`, `itest*`, `wallet_stage`, `ci-test`, `gh_logs`, `setup114`, `mingw*`… | Artefacts de test | **SUPPRIMÉ** (après extraction des preuves) | À supprimer |
| Variables d'environnement (aucune `FAUCET_SEED` détectée) | Env | AUCUNE occurrence | CONSERVÉ (vérifié) |
| Git history du dépôt | VCS | **VÉRIFIER** (aucun commit ne doit contenir la clé ; sinon purge d'historique ou nouveau dépôt) | À vérifier |
| `README.md`, `CHANGELOG.md`, `SECURITY.md`, whitepaper | Doc | AUCUNE occurrence de seed | CONSERVÉ (vérifié) |

### 1.2 Commandes de vérification d'absence (à rejouer après purge)

```powershell
# Source et configs (doit retourner 0 ligne)
rg -i "fa5979dd7273d55c6b5f2028ab166dc3163f90ac9f68da28b79a1fe0f06c45b8" `
  C:\Users\Shadow\Documents\aether-fix\aether-main -g "!target" -g "!*.git*"

# Clés fa5979 courtes (fragment de 8 hex minimum)
rg -i "fa5979" C:\Users\Shadow\Documents\aether-fix\aether-main -g "!target"

# Anciens artefacts (doit retourner 0)
Get-ChildItem "$env:TEMP\opencode" -Recurse -Filter "faucet.key" | Measure-Object
Get-ChildItem "$env:TEMP\opencode" -Recurse -Filter "faucet.json" | Measure-Object
```

> **Résultat attendu** : le dépôt source est propre (0 occurrence) ; tout le reste
> (harnais, wallets, data-dirs, logs) contient la clé et doit être purgé.
> Le script `scripts/verify_genesis.ps1` automatise ces contrôles.
>
> **Whitelist cérémonie** : la clé historique reste VOLONTAIREMENT présente dans
> 3 fichiers du dépôt (documentation + outils de détection) :
> `docs/CEREMONIE_GENESIS.md`, `scripts/verify_genesis.ps1`, `scripts/verify_genesis.sh`.
> Le script vérifie qu'elle n'existe **nulle part ailleurs** (aucun `src/`, aucun
> `*.json`, aucun `.yml`, aucun `Cargo.*`). Si un 4e fichier venait à contenir la
> clé, `verify_genesis.ps1` échoue (« Whitelist inattendue »).

---

## Étape 2 — Génération du nouveau genesis (hors ligne)

### 2.1 Génération des clés

Outils : `openssl` (hors ligne) ou la commande wallet du binaire (compilé à partir du
dépôt propre). Les clés sont générées sur la machine isolée, **jamais transmises par
réseau**.

```bash
# Founder (allocateur initial)
openssl genpkey -algorithm ed25519 -out founder.pem
openssl pkey -in founder.pem -pubout -out founder_pub.pem
openssl pkey -in founder.pem -text -noout   # récupérer la clé privée hex

# Faucet (fonds de test)
openssl genpkey -algorithm ed25519 -out faucet.pem
openssl pkey -in faucet.pem -pubout -out faucet_pub.pem
openssl pkey -in faucet.pem -text -noout    # récupérer la clé privée hex
```

Ou via le wallet du binaire :

```powershell
"<mot-de-passe-robuste>`n" | aether-unified.exe wallet create founder.json
"<mot-de-passe-robuste>`n" | aether-unified.exe wallet create faucet.json
aether-unified.exe balance founder.json --rpc-url http://127.0.0.1:1 --password "<mdp>"
```

L'adresse Aether = les 32 premiers octets de la clé publique Ed25519 (hex, 64
caractères) — c'est ce que lit `wallet.address()` (cf. `main.rs:355`).

### 2.2 Allocation initiale

| Adresse | Allocation | Commentaire |
|---|---|---|
| `FOUNDER_ADDRESS` (nouvelle) | `100_000_000_000` (= 10 AETH) | Allocation fondatrice |
| `FAUCET_ADDRESS` (nouvelle) | `1_000_000_000_000_000_000` (= 100 000 000 AETH) | Fonds faucet |
| `FEE_BURN_ADDRESS` | inchangé `[0xFF;32]` | Burn des fees |

Supply initiale = **1000000100000000000** (invariant vérifié à chaque assertion).

### 2.3 Paramètres économiques et réseau

| Paramètre | Valeur | Fichier |
|---|---|---|
| `UNITS_PER_AETH` | 10^10 | `genesis.rs` |
| `MAX_SUPPLY` | 2 × 10^18 (200M AETH) | `genesis.rs` |
| `initial_difficulty` | 1000 | `GenesisConfig` |
| `GENESIS_MESSAGE` | **NOUVEAU** (date de cérémonie + preuve d'ancrage) | `genesis.rs` |
| Fee par défaut | 10 unités (CLI), 1 (faucet) | `main.rs` / `rpc.rs` |
| Faucet rate limit | 60 s par adresse | `rpc.rs` |
| Ports RPC/P2P par défaut | 42001-50100 / 42101-50101 (test) | harnais |
| Quorum VQV | 0.67 (2/3) | `rpc.rs` |

### 2.4 Rotation des constantes dans le code

Modifier `src/genesis.rs` :
- `FOUNDER_ADDRESS` → nouvelle adresse founder ;
- `FAUCET_ADDRESS` / `FAUCET_PUBLIC_KEY` → nouvelle adresse faucet ;
- `GENESIS_LEDGER` → conserver les montants, remplacer les adresses ;
- `GENESIS_MESSAGE` → nouveau message incluant la date de cérémonie et le
  fingerprint attendu (preuve anti-rejeu).

⚠️ Vérifier ensuite que **toute référence** à l'ancienne adresse a disparu :
`rg -i "5579ae9096f1ae55bfd6fd88155fad09c59ab8ccb61c8a297b5d1027ea4ca916|3d17ace653283dbd9aeba6e0d4684795a800e9da952cb682bb67cd970cbe1b3e" src`

---

## Étape 3 — Construction du Genesis

### 3.1 Fichier `genesis.json` (référence, généré par le script)

Le protocole lit le genesis depuis `genesis.rs` (constantes compilées). Le script
`scripts/genesis_verify.ps1` génère un `genesis.json` de RÉFÉRENCE (documentation et
vérification externe) contenant : `network_id`, `genesis_message`, adresses,
allocations, supply initiale, `MAX_SUPPLY`, `initial_difficulty`, hash.

### 3.2 Hash du genesis / identifiant réseau

Définition reproductible (implémentée dans le script de vérification) :

```
network_id = SHA256( GENESIS_MESSAGE || FOUNDER_ADDRESS || FAUCET_ADDRESS ||
                     supply_hex || MAX_SUPPLY_hex )
```

Tous les nœuds doivent afficher le même `network_id` au démarrage. Le hash du
**premier état** du réseau (ledger genesis) est vérifiable en démarrant un nœud sur
data-dir vide : `aether_getDagStats` doit donner `total_transactions=0`,
`supply=1000000100000000000`, tips=`[0000…00]` (GENESIS_HASH).

### 3.3 Fingerprint

Fingerprint d'état = SHA-256 des ensembles triés (`txset`, `edges`, `tips`,
`ledger`) + supply — identique sur tous les nœuds (même mécanique que
`Assert-Invariant` du harnais). Fingerprint du genesis (réseau vide) = valeur
calculée par le script et affichée comme « genesis fingerprint ».

---

## Étape 4 — Vérification (scripts automatiques)

Scripts fournis (dépôt) :
- `scripts/verify_genesis.ps1` — contrôle de l'absence de la clé historique,
  absence d'artefacts, cohérence du `genesis.rs`, calcul du `network_id`, du
  fingerprint genesis et de la supply.
- `scripts/verify_genesis.sh` — équivalent Linux (CI).

Ce que vérifie `verify_genesis.ps1` (extrait) :
```powershell
# 1. Absence de l'ancienne clé dans le dépôt source
$leaks = rg -i "fa5979" $repo -g "!target" 2>$null
if ($leaks) { throw "ANCIENNE CLÉ TROUVÉE: $leaks" }

# 2. Absence d'anciens artefacts
if ((Get-ChildItem $temp -Recurse -Filter "faucet.key" -EA SilentlyContinue | Measure-Object).Count -gt 0) { throw "faucet.key résiduel" }

# 3. Coherence du genesis (parsing de src/genesis.rs)
$founder = [regex]::Match($genesis, 'FOUNDER_ADDRESS:\s*&str\s*=\s*"([0-9a-f]{64})"').Groups[1].Value
$faucet  = [regex]::Match($genesis, 'FAUCET_ADDRESS:\s*&str\s*=\s*"([0-9a-f]{64})"').Groups[1].Value
if ($founder -eq $script:OLD_FOUNDER -or $faucet -eq $script:OLD_FAUCET) { throw "Anciennes adresses encore présentes" }
if ($founder -notmatch '^[0-9a-f]{64}$' -or $faucet -notmatch '^[0-9a-f]{64}$') { throw "Adresses invalides" }

# 4. Supply et réseau
$supply = 100000000000 + 1000000000000000000   # 1e11 + 1e18
$networkId = Sha256Hex ("$message|$founder|$faucet|$supply|2000000000000000000")
Write-Output "network_id=$networkId"
Write-Output "supply=$supply"

# 5. Cohérence wallets (optionnel : recharge chaque wallet et vérifie le format)
```

**Vérifications manuelles après build** (démarrer 3 nœuds sur data-dir vide) :
1. `aether_getDagStats` → `total_transactions=0`, même `connected_peers`, epoch 0 ;
2. `aether_getTips` → `[00000000…]` identique partout ;
3. `aether_getBalance(FOUNDER)` = 1e11, `aether_getBalance(FAUCET)` = 1e18 ;
4. supply = 1000000100000000000 sur chaque nœud ;
5. faucet.key absent → `aether_faucet` renvoie « Faucet disabled ».

---

## Étape 5 — Rotation complète (preuves)

| Contrôle | Méthode | Résultat attendu |
|---|---|---|
| Ancien wallet ne fonctionne pas | `aether balance` avec un ancien `A.json` → solde 0 ; tenter un send → rejet « Insufficient balance » (l'adresse n'a aucune allocation) | REJET |
| Ancien faucet ne fonctionne pas | Ancien `faucet.key` placé dans `data_dir` → `load_faucet_key` rejette (« does not match genesis FAUCET_ADDRESS ») ; `aether_faucet` désactivé | DÉSACTIVÉ |
| Ancien secret ne fonctionne pas | Signer une tx avec l'ancienne clé → rejet (adresse inconnue du genesis) | REJET |
| Ancien nœud ne rejoint pas | Démarrer un nœud avec un ancien data-dir (DAG de l'ancien réseau) → les txs référencent des adresses/constantes absentes du nouveau genesis ; `rebuild_from_dag` produit un état différent ; comparaison d'état échoue | EXCLU / non reconnu |

> Ces contrôles sont automatisables via le harnais : `Assert-Invariant` sur un
> réseau neuf (supply + hash) + tentative de send avec une clé étrangère.

---

## Étape 6 — Build propre

```powershell
# Nettoyage total
cargo clean
# Build release (toolchain GNU)
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;" + $env:PATH
cargo build --release
# Tests
cargo test --lib
# Audit dépendances (doit être vert ou dérogations documentées)
cargo audit   # ou: cargo install cargo-audit && cargo audit

# Checksums
Get-FileHash target\release\aether-unified.exe -Algorithm SHA256 | Select Hash
```

Documentation requise (à joindre au rapport) :
- Version : `1.2.0-genesis-<network_id-8>` (bump dans `Cargo.toml`) ;
- Commit Git : `git rev-parse HEAD` + tag signé `genesis-<network_id-8>` ;
- Rust : `rustc --version` (attendu `1.97.1`) ;
- Dépendances : `cargo tree -e normal` (joindre la liste) ;
- Checksums SHA-256 du/des binaires (Windows + Linux) ;
- Signature des artefacts par la clé de release (si disponible).

---

## Étape 7 — Publication testnet

| Élément | Valeur recommandée |
|---|---|
| Seed nodes | **3** (géographiquement répartis), `--node-type observer` |
| Bootstrap | `--bootnodes <ip1>:<p2p-port>,<ip2>:<p2p-port>,<ip3>:<p2p-port>` (explicite, jamais de DNS public) |
| Faucet | `faucet.key` du NOUVEAU faucet déployé UNIQUEMENT sur 1-2 seed nodes désignés |
| Monitoring | Prometheus `/metrics` sur chaque nœud (transactions, peers, mempool, uptime) |
| Logs | `tracing` en fichier + rotation ; collecte centralisée (Loki/ELK) |
| Alertes | divergence d'état (`h_ledger`/supply ≠ ref), sync stuck, peers < 2, faucet down |
| Observabilité | endpoint RPC `aether_getDagStats` + `aether_getTips` vérifiés toutes les 30 s |
| Sécurité | ports RPC accessibles en local seulement (reverse proxy authentifié si besoin) |

---

## Checklist opérateur (avant ouverture)

- [ ] Étape 1 : scan d'absence de `fa5979…` dans le dépôt = 0 résultat (prouvé, log joint)
- [ ] Étape 1 : suppression des 52 `faucet.key`, ~328 wallets de test, 19 runs réseau,
      `faucet.json`, harnais contenant la seed (preuve : re-scan = 0 résultat)
- [ ] Étape 2 : clés founder/faucet générées HORS LIGNE, seeds stockés hors du dépôt
      (gestionnaire de secrets / coffre), jamais commités
- [ ] Étape 2/3 : `genesis.rs` modifié ; `rg` anciennes adresses = 0 résultat
- [ ] Étape 3 : `genesis.json` généré ; `network_id` publié ; fingerprint genesis publié
- [ ] Étape 4 : `verify_genesis.ps1` PASS (toutes les vérifications) ; 3 nœuds neufs
      identiques (stats, tips, supply)
- [ ] Étape 5 : rotation prouvée (ancien wallet/faucet/secret/nœud rejetés)
- [ ] Étape 6 : build propre + tests 122/122 + cargo audit vert (ou dérogations
      documentées) + checksums + commit/tag
- [ ] Étape 7 : 3 seed nodes up, monitoring actif, alertes configurées
- [ ] Compte-rendu public : hash genesis, network_id, fingerprint, checksums,
      procédure reproductible (ce document)

---

## Commandes exactes (récapitulatif)

```bash
# 1. Inventaire / purge
rg -i "fa5979" <repo> -g "!target"                    # doit être vide
Remove-Item "$env:TEMP\opencode\faucet.json" -Force
Get-ChildItem "$env:TEMP\opencode" -Recurse -Filter "faucet.key" | Remove-Item -Force
Get-ChildItem "$env:TEMP\opencode\aether-net2" -Directory | Remove-Item -Recurse -Force

# 2. Clés (machine hors ligne)
openssl genpkey -algorithm ed25519 -out founder.pem
openssl genpkey -algorithm ed25519 -out faucet.pem

# 3. Modifier src/genesis.rs (adresses + message) puis :
cargo clean; cargo build --release; cargo test --lib

# 4. Vérification
powershell -ExecutionPolicy Bypass -File scripts\verify_genesis.ps1 -Repo C:\...\aether-main
#   -> imprime network_id, supply, fingerprint genesis

# 5. Rotation : ancien faucet.key dans un nœud neuf -> faucet désactivé (log)

# 6. Checksums
Get-FileHash target\release\aether-unified.exe -Algorithm SHA256

# 7. Lancement seed node
aether-unified.exe --node-type observer --data-dir ./data1 --p2p-port 42001 --rpc-port 42101 `
  --bootnodes 127.0.0.1:1   # (réseau neuf : aucun autre bootnode)
```

---

## Preuves archivées (à conserver dans un dossier `genesis-ceremony/` signé)

1. Logs des scans d'absence (Étape 1 et post-purge).
2. `genesis.json` + `network_id` + fingerprint genesis (Étape 3/4).
3. Sortie `verify_genesis.ps1` complète.
4. Logs de rotation (Étape 5) : rejets ancien wallet/faucet/nœud.
5. Checksums SHA-256 + commit + tag + `cargo tree` (Étape 6).
6. Ce document signé par OPERATOR, WITNESS, REVIEWER.