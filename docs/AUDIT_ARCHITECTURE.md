# AETHER SEDC — Audit Architecture & Sécurité (Phase 1)

**Mission 2 — Phase 1 : audit complet, AUCUNE modification de code**
**Version évaluée** : `aether-unified 1.1.1` (Cargo.toml, édition 2021)
**Date** : 2026-08-16
**Méthode** : lecture intégrale des 19 modules `src/` (~13 300 lignes), des 3 workflows GitHub Actions, de `Cargo.toml`/`Cargo.lock`, et confrontation avec `docs/RAPPORT_FINAL_TECHNIQUE.md` (mission 1).
**Statut** : AUDIT TERMINÉ — 1 finding 🟠 HIGH, 3 🟡 MEDIUM, 8 🔵 LOW, 3 ⚪ INFO. Aucun défaut de consensus/déterminisme identifié. Voir §H et le verdict §M.

---

## A. Architecture générale

### A.1 Composants

| Composant | Fichier | Rôle |
|---|---|---|
| Binaire daemon/CLI `aether-unified` | `src/main.rs` (586 L) | CLI (clap) : `daemon`, `wallet`, `send`, `balance`, `faucet`, `pow`, `keygen`, `reset`, `repair-ledger` |
| Binaire GUI `aether` | `src/gui.rs` (790 L) | eframe/egui ; wallet intégré (création, mnémonique affichée, jamais persistée) ; CLI partiel dupliqué (send/balance) |
| Bibliothèque | `src/lib.rs` | 19 modules exportés, `SyncEvent` |
| Orchestration | `src/node.rs` (600 L) | Démarrage, tâches périodiques (reconcil 10 s, full sync, orphan solver, faucet), `rebuild_from_dag` au boot |
| Entrée unique « zéro-trust » | `src/transaction_processor.rs` (339 L) | STEP 0..9 : conflit → pure → sig → PoW → DAG → ledger → mempool → persistance |
| DAG | `src/parent_selection.rs` (972 L) | `DAG`, tips, sélection de parents (random walk), résolution canonique des conflits |
| Ledger | `src/ledger.rs` (1008 L) | Soldes/nonces in-memory, `rebuild_from_dag` déterministe, burn des fees |
| Validation | `src/validation.rs` (420 L) | Pipeline pure / DAG / ledger |
| Transaction | `src/transaction.rs` (765 L) | Ids canoniques hex (V-20), PoW, sérialisation, `tips_to_parents` strict |
| P2P | `src/p2p.rs` (1171 L) | TCP chiffré (X25519 + ChaCha20-Poly1305), inventory/GetData, sync complet |
| RPC | `src/rpc.rs` (2529 L) | JSON-RPC axum (~30 méthodes), faucet, status, explorer HTML, `/metrics` |
| Stockage | `src/storage.rs` (685 L) | Sled (Transactions/Balances/Metadata/AddressIndex/Nonces/Orphans/Mempool) |
| Stockage JSON legacy | `src/json_storage.rs` (98 L) | `dag.json` écrit périodiquement, relu au boot (backup de secours) |
| Wallet | `src/wallet.rs` (579 L) | Ed25519 + BIP39, Argon2id + AES-256-GCM, migration v1→v2 |
| Genesis | `src/genesis.rs` (105 L) | Allocations, `UNITS_PER_AETH`, `MAX_SUPPLY`, message d'ancrage |
| Config | `src/config.rs` (64 L) | `NodeConfig`, bootnode par défaut `103.102.135.123:25565` |
| Explorer API | `src/explorer_api.rs` (213 L) | **CODE MORT** (voir §J) |

### A.2 Modèle d'exécution

- **Binaire unique**, pas de séparation client/serveur : chaque nœud est daemon, mineur potentiel et client.
- **État en mémoire** : `DAG` (HashMap txs + HashMap enfants) et `Ledger` (HashMap soldes + nonces) derrière `Arc<RwLock<>>` (tokio, contention → `try_read`/`try_write` + retry 20×25 ms, V-22).
- **Persistance** : Sled (source de vérité) + `dag.json` périodique (secours) + wallets chiffrés au repos.
- **Entrée transactionnelle unique** : `TransactionProcessor::process` (`transaction_processor.rs`), appelé par RPC et P2P — l'acceptation d'une tx passe TOUJOURS par le même chemin de validation.
- **V-20/V-21/V-22/V-23** : ids hex canoniques, rebuild déterministe (min-id, nonces=max), sync complet + retry locks, suppression du nonce strict ordre-dépendant. **Confirmés présents et cohérents dans le code.**

### A.3 Réseau

- P2P : TCP `25565` (défaut), handshake X25519 → clé de session, chiffrement par message ChaCha20-Poly1305 ; magic `"AETH"` ; bornes : message ≤ 16 MiB, 128 peers max, 1000 peers connus, 50 000 txs vues, 1000 items par inventory, 400 msg/s par peer.
- RPC : axum, `0.0.0.0:9933` (défaut), **non authentifié** (aucun auth token) ; rate limiter par nom de méthode ; explorer HTML sur `/` et `/explorer` ; `/metrics` Prometheus (compteurs de base).

---

## B. Flux des transactions

```
CLI/GUI ──mine PoW (difficulté 20, nonce u64)── signe (ed25519)
   │  payload bincode + hex
   ▼
RPC aether_sendTransaction (rpc.rs)
   │  décodage hex → bincode ; taille ≤ 1 MiB (MAX_RPC_TX_SIZE)
   │  [⚠️ H1] STEP 1 : parents manquants → ORPHELIN persisté SANS validation
   ▼
TransactionProcessor::process (entrée unique)
   STEP 0  conflit (sender, nonce) → min-id gagne, prune du perdant (canonical)
   STEP 1  validate_pure : id hex, montants, signature, PoW, fee
   STEP 2/3 signature / PoW
   STEP 4  validate_dag : parents présents, pas de replay, pas de conflit
   STEP 5  validate_ledger : solde ≥ amount+fee, nonce max, pas de mint
   STEP 6  mempool (max 50 000, min_fee de l'oracle)
   STEP 7  DAG.add (tips parents, hash d'état)
   STEP 8  persistance Sled (batch) + flush
   STEP 9  broadcast P2P relay_all
   ▼
Pairs : même chemin de validation → même verdict (règles pures)
```

**Points vérifiés** : l'ordre d'arrivée n'influence aucun verdict ; le nonce ledger = max par sender (V-23) ; le fee est brûlé vers `FEE_BURN_ADDRESS = [0xFF; 32]` ; aucune frappe (`MAX_SUPPLY` = 2e18, supply vivante = 1e18 + 1e11 exactement).

---

## C. Flux de synchronisation

```
Nouvelle connexion : handshake (magic, X25519, clé session)
  → GetInventory → Inventory (liste d'ids, ≤ 1000)
  → GetData (ids manquants dans le DAG local)
  → SyncResponse (100 txs/page, triées par timestamp, throttle 50 ms)
Périodique (node.rs) :
  - réconciliation complète toutes les 10 s : request_full_sync
  - orphan solver : re-demande des parents manquants via P2P (10 s)
  - process_orphans : ré-essai des orphelins dont les parents sont arrivés
Boot : Sled (+ JSON) → rebuild_from_dag canonique → sync complet → converge
```

**Dédup par appartenance au DAG** (V-22), pas par `seen_transactions` — une tx absente du DAG est toujours re-demandée. **Vérifié.**

---

## D. Flux de consensus

- **Le DAG est le consensus** : une tx est acceptée si elle satisfait les règles déterministes — aucun vote réseau requis.
- Ordre canonique de tout ensemble : tri lexicographique des ids hex (V-20).
- Conflits (sender, nonce) : `canonical_winners` — min-id gagne, identique partout (V-21) ; les perdants sont purgés de Sled.
- Statuts observés (`determine_transaction_status`) : `in_mempool` / `in_local_dag` / `orphan` / `unknown` + consensus `unconfirmed`/`confirmed`/`stable`. **Note** : `Stable` dépend de `tx.weight`, qui n'est **jamais calculé** (toujours 0.0) → `Stable` inaccessible ; `Confirmed` = ≥ 3 enfants. Vestiges VQV (voir §I).

---

## E. Reconstruction du ledger

`rebuild_from_dag` (`ledger.rs`) : fonction pure du DAG — allocation genesis + replay des txs en ordre canonique (id hex), conflits par min-id, nonces = max, fees brûlés, `total_supply` dérivée des soldes vivants. **Même DAG ⇒ même ledger, mêmes hash** (V-21, prouvé S6).

---

## F. Gestion des clés & wallet

- Entropie : `OsRng` ; BIP39 mnémonique ; clé secrète Ed25519 (64 octets).
- Chiffrement au repos : Argon2id (64 MiB, t=3, p=1) → clé AES-256-GCM ; payload unique `{secret_key_hex, mnemonic}` avec nonce frais (pas de réutilisation de nonce).
- Refus d'enregistrer un wallet non chiffré ; migration v1 (PBKDF2) en lecture seule.
- Faucet : clé depuis `data_dir/faucet.key` (64 hex) ; absence ou non-concordance avec `FAUCET_ADDRESS` ⇒ faucet désactivé.
- ⚠️ `Wallet::new_with_mnemonic` : fallback `Mnemonic::from_entropy(&[0u8; 16])` si `OsRng` échoue → **mnémonique déterministe identique pour tous** en cas de panne RNG (chemin quasi-impossible, mais à corriger : erreur, pas fallback).

---

## G. Gestion du genesis

- `GENESIS_HASH = [0u8; 32]` ; message d'ancrage `GENESIS_MESSAGE` (roté 2026-08-16) ; `UNITS_PER_AETH = 1e10` ; founder 1e11, faucet 1e18 ; `MAX_SUPPLY = 2e18`.
- Clé faucet historique `fa5979…` **considérée compromise** (rapport mission 1) — cérémonie genesis obligatoire avant tout testnet public.
- ⚠️ **Aucune vérification d'identité de réseau dans le handshake P2P** (pas de hash de genesis/network_id) → un nœud d'un autre réseau peut s'interconnecter (voir H4).

---

## H. Surface d'attaque — findings

### 🟠 H1 — HIGH : orphelins persistés SANS validation (aucun gate PoW)

- **Où** : `src/rpc.rs:1030-1110` (STEP 1 de `process_transaction`, avant `validate_pure`), `src/storage.rs:471` (`put_orphan`), `src/node.rs` (orphan solver re-demande les parents de tous les orphelins).
- **Fait** : une tx dont un parent est absent est **persistée en Sled + en mémoire sans aucune validation** (ni PoW, ni signature, ni montants). L'id est arbitraire (hash de champs quelconques).
- **Impact** : remplissage illimité du disque (1 MiB/tx max par le cap RPC, ~500 B typique) et de la mémoire (`orphans` HashMap sans éviction), + amplification P2P (le nœud re-demande les parents fantômes à tous ses pairs à chaque cycle). Le rate-limit RPC (200 req/10 s) ralentit mais n'arrête pas : ~1,2 GB/min soutenable.
- **Contre-mesures actuelles** : cap 1 MiB, rate limit — insuffisants pour un testnet public.
- **Correctif (Phase 2, P0)** : déplacer la vérification d'orphelin APRÈS `validate_pure` (PoW + signature) — les orphelins légitimes passent le PoW ; + éviction/TTL des orphelins ; + borne du nombre d'orphelins.

### 🟡 H2 — MEDIUM : aucun timeout réseau P2P

- **Où** : `src/p2p.rs:436` (`accept`), `:511` (handshake `read_exact`), `:639-685` (frames), `:976` (`TcpStream::connect`). Aucun `tokio::time::timeout` dans tout le module.
- **Impact** : un pair qui connecte et ne parle jamais occupe une tâche + un socket indéfiniment (jusqu'à 128 entrées) ; un `connect` vers une IP black-holée peut bloquer une tâche d'outbound indéfiniment. DoS de ressources (modéré, borné) + tâches zombies.
- **Correctif (P1)** : timeout handshake (ex. 10 s), timeout de lecture par frame (ex. 30 s), timeout de connect (ex. 5 s).

### 🟡 H3 — MEDIUM : RPC — rate limit par méthode (pas par IP) et scans O(DAG) sans pagination

- **Où** : `src/rpc.rs` (rate limiter clé = nom de méthode), `get_dag_graph` (`:1548`, construit TOUS les nœuds+edges à chaque appel), `get_transaction_history` (`:1491`, retourne TOUTES les txs de l'adresse, sans pagination), `get_recent_transactions` (`:1461`).
- **Impact** : (a) un client peut épuiser le budget partagé d'une méthode (DoS des autres clients) ; (b) sur un DAG de taille N, chaque appel `getDagGraph` = O(N) CPU+mémoire, répétable à volonté → amplification ; (c) l'API n'est pas scalable au-delà de quelques dizaines de milliers de txs.
- **Correctif (P1)** : rate limit par IP (+ budget global par méthode conservé), pagination/bornes sur `get_transaction_history`, cache ou limite sur `get_dag_graph`.

### 🟡 H4 — MEDIUM : pas d'identité de réseau dans le handshake P2P

- **Où** : `src/p2p.rs` (handshake = magic + X25519 uniquement).
- **Impact** : deux réseaux (genesis différents) peuvent s'interconnecter ; pollution d'inventaires, confusion opérateurs, et aucun détecteur de fork/mismatch. Le testnet public (nouveau genesis après cérémonie) devra distinguer les réseaux.
- **Correctif (P2)** : inclure le hash du genesis (ou network_id) dans le handshake, rejeter les mismatch. **Changement de protocole** → numéro V, tests de compat, à faire AVANT l'ouverture publique.

### 🔵 H5 — LOW : faucet cooldowns sans éviction

- `faucet_cooldowns` (HashMap adresse→Instant) : les entrées ne sont jamais purgées → croissance mémoire continue (faible en pratique, bornée par le taux de demandes).

### 🔵 H6 — LOW : CLI — fallback silencieux vers parents genesis sur erreur de transport RPC

- **Où** : `src/main.rs:429-431` : `Err(_) => [[0u8; 32]; 2]` sur erreur HTTP/JSON de `aether_getTips` (le V-20 strict ne couvre que le payload malformé mais parsable).
- **Impact** : en cas de panne RPC transitoire, le CLI envoie une tx racine (parents genesis) → DAG en étoile possible, alors que le GUI refuse. Contredit le principe V-20. Pas de rupture de consensus (la tx reste valide), mais divergence topologique.
- **Correctif (P1)** : erreur stricte (option `--force-genesis` explicite).

### 🔵 H7 — LOW : amplification des logs

- `src/rpc.rs:996-1028` : 8 lignes `info!` par tx (payload complet, parents, nonce…) + logs du payload hex brut à l'entrée RPC ; `RAW RPC PARAMS` en `error!`. Un attaquant envoyant des txs invalides à la chaîne génère des volumes de logs importants (et les payloads en clair dans les logs — confidentialité).
- **Correctif (P1)** : passer ces logs en `debug!`, ne loguer que les ids.

### 🔵 H8 — LOW : wallet — clé privée en ligne de commande, commentaire base58 erroné, fallback RNG

- `keygen --import <hex>` expose la clé dans la ligne de commande (historique shell, `ps`) — préférer stdin/`--import-file` (déjà disponible pour le fichier).
- `src/wallet.rs:27` commente « base58 » mais le code produit `AETH` + **hex** (20 octets de clé + 4 octets checksum SHA-256²) — commentaire obsolète, pas d'impact sécurité.
- Fallback mnémonique zéro-entropie (voir §F) : à remplacer par une erreur.

### ⚪ H9 — INFO : deux formats d'adresse

- Ledger/RPC : adresse = clé publique Ed25519 brute (32 octets, hex). Affichage wallet : `AETH` + hex(20+4). Les deux coexistent sans conversion automatisée → risque de confusion utilisateur (envoi vers une « adresse AETH » non reconnue par le CLI qui attend 64 hex). À documenter clairement pour les utilisateurs du testnet.

### ⚪ H10 — INFO : `/metrics` — version et type de nœud codés en dur

- `src/rpc.rs:2382` : `node_type="miner"`, `version="1.0.0"` (le paquet est en 1.1.1) → métadonnées de monitoring inexactes.

### ⚪ H11 — INFO : explorer HTML

- L'explorer injecte les valeurs dans le HTML via `format!` ; les champs sont des nombres ou des hex (charset sûr) → pas de XSS identifié. La recherche d'adresse passe par POST JSON (pas d'injection). OK.

---

## I. Dette technique

1. **Vestiges VQV** : `GlobalStatus`, `ConsensusStatus::Finalized`, `reconcile_quorum`, `NodeStatusReport`/`TransactionFinality` (P2P), staking (`StakingResponse`/`StakingInfoResponse`), `mining_rewards: 0`, `start_mining`/`stop_mining` (le booléen est lu mais ignoré : `let _should_mine`), `get_network_hashrate` (placeholder), `block_height: Some(0)`.
2. **Poids jamais calculé** : `tx.weight` reste 0.0 → `determine_transaction_status` ne peut jamais produire `Stable` ; les statuts consensus observés sont partiellement cosmétiques. À clarifier (calculer le poids ou supprimer les statuts morts).
3. **Persistance double** : Sled (source de vérité) + `dag.json` périodique (backup) + chemins legacy `ledger.json` (`load_or_create`/`save_to_file`/`save_blocking` inutilisés au boot).
4. **Client CLI dupliqué** : `main.rs` et `gui.rs` implémentent chacun send/balance/faucet/mining → divergence déjà observée (H6). Factoriser.
5. **Logs mixtes** français/anglais, commentaires obsolètes (base58, VQV, « finality »).
6. **`get_recent_transactions`** : itération HashMap (ordre non déterministe — cosmétique, hors hash d'état).

---

## J. Code mort

| Élément | Localisation | Sort |
|---|---|---|
| `ExplorerApi`, `DagGraph`, `DagNode`, `DagEdge`, `DagStatistics` | `src/explorer_api.rs` (module entier) | non utilisé par `node.rs`/`rpc.rs` (seul son propre test + exports `lib.rs`) → **supprimer ou connecter** |
| `GlobalStatus`, `reconcile_quorum`, `NodeStatusReport`, `TransactionFinality` | `rpc.rs` / `p2p.rs` | vestiges VQV |
| Staking (`StakingResponse`, `StakingInfoResponse`, méthode RPC associée) | `rpc.rs` | vestiges |
| `start_mining`/`stop_mining`, `mining_rewards`, `get_network_hashrate` placeholder | `rpc.rs` | placeholders |
| `Ledger::load_or_create`, `save_to_file`, `save_blocking` | `ledger.rs` | legacy fichier (inutilisés au boot) |
| `AdaptiveDifficulty` (oracle de frais alternatif) | — | à confirmer usage ; l'oracle actif est `FeeOracle` dans `rpc.rs` |

---

## K. Dépendances

- **`cargo audit` (état mission 1, inchangé)** : 1 vulnérabilité active — `RUSTSEC-2026-0221` (`event-listener 5.4.1`, unsound, transitive) ; 8 warnings « unmaintained » : `bincode` 1.3, `derivative`, `fxhash`, `instant`, `paste`, `rustls-pemfile`, `ttf-parser` ; `RUSTSEC-2026-0257` (`webbrowser`) ignoré avec justification dans `.cargo/audit.toml` (cible GUI Windows, URLs internes).
- **Directes** : serde/serde_json/toml, bincode 1.3, tokio, sha2, blake3, ed25519-dalek 2.1, x25519-dalek 2.0, rand 0.8, hex, bip39, bs58, aes-gcm 0.9, chacha20poly1305 0.9, pbkdf2 0.12, argon2 0.5.3, clap 4.4, reqwest 0.11, sled 0.34, axum 0.7, tower-http 0.5, tracing(+subscriber), colored, eframe/egui 0.27, tempfile (dev).
- **Points d'attention** : `bincode` 1.3 est le **format fil** (P2P + RPC) et de stockage — une migration vers bincode 2 = **changement de protocole** (numéro V, compat, tests). `sled` 0.34 est en maintenance mode (pas de v1 stable) — alternative `redb`/`rocksdb` à étudier, non prioritaire. `eframe/egui` tire une grosse arborescence (winit, ttf-parser…) — acceptable pour un binaire GUI séparé.
- **CI** : `.github/workflows/ci.yml` (build+test Ubuntu/Windows, clippy, fmt, test d'intégration 3 nœuds), `security.yml` (cargo audit hebdo + workflow_dispatch), `release.yml`, `dependabot.yml`. **Aucun CI local reproduit dans le harnais `resilience.ps1`** (à améliorer).

---

## L. Performance & scalabilité

1. **Sélection de parents** (`parent_selection.rs`) : `random_walk` fait un BFS descendant par pas ; `CumulativeWeightCache` n'est **jamais invalidée** → poids périmés (sous-estimés, monotonie croissante) après croissance du DAG. O(n) par tirage sans cache → coût quadratique sur gros DAG.
2. **RPC O(DAG) par appel** : `get_dag_graph`, `get_transaction_history`, `get_recent_transactions` scannent tout le DAG à chaque appel (H3).
3. **Sync** : 100 txs/page, 50 ms de throttle → 100 000 txs ≈ 50 s par pair ; full sync toutes les 10 s ; relay de chaque tx à tous les pairs (O(n·p)).
4. **Persistance** : flush Sled à chaque tx acceptée (STEP 8) → fsync par tx (bottleneck TPS).
5. **Orphelins** : ré-essais + re-demandes P2P périodiques pour TOUS les orphelins (y compris les morts-vivants, H1/H10).
6. **PoW** : mining client mono-thread (CPU-bound) — acceptable pour testnet, à paralléliser si besoin.

---

## M. Verdict Phase 1

> **Aucun défaut de consensus ou de déterminisme identifié.** Les conclusions de la mission 1 (🟡 TESTNET PUBLIC POSSIBLE après cérémonie genesis) restent valides, avec **une réserve nouvelle de priorité absolue** : H1 (orphelins non validés → DoS stockage/mémoire/P2P) doit être corrigé et testé **avant** toute ouverture publique.

**Priorités Phase 2** (ordre suggéré) :

| Priorité | Items |
|---|---|
| P0 | H1 : gate PoW/signature avant persistation des orphelins + éviction + borne ; tests associés |
| P1 | H2 (timeouts P2P), H3 (rate limit IP + pagination RPC), H6 (CLI strict), H7 (logs debug) |
| P2 | H4 (network_id au handshake, changement de protocole numéroté), H5 (éviction faucet), purge du code mort (§J), corrections wallet H8, metrics H10 |
| P3 | Déterminisme renforcé (tests S11–S15 + preuves), perf (§L), fuzzing, couverture, migration bincode 2 (optionnel, planifié) |

**Contraintes respectées** : aucune modification de code en Phase 1 ; les règles économiques et le genesis actuel sont inchangés ; le rapport sera archivé dans le dépôt.

---

## N. Rapport d'exécution Phase 2 (mission 2)

Toutes les corrections P0–P2 du tableau ci-dessus ont été **implémentées, testées et vérifiées** (133 tests lib, 0 échec ; build lib + binaires OK ; clippy lib : 43 warnings, tous pré-existants — aucun warning nouveau introduit).

| Finding | Statut | Détail |
|---|---|---|
| **H1 (P0)** | ✅ Corrigé | Gate PoW+signature (`validate_pure`) **avant** tout parkage orphelin dans `TransactionProcessor::process` (STEP 1 → 1b). Nouveau `ProcessingError::Orphan(Vec<[u8;32]>)` portant les parents manquants. Cap `MAX_ORPHANS = 50_000` dans `rpc.rs` (rejet au-delà, rien persisté). Tests : 2 (processor) + 3 (rpc) + fixture déterministe `signed_mined_orphan_tx()` dans `src/tests/mod.rs` (nonce 161041 + signature précalculés, difficulty 20 — le mining stochastique est trop lent pour la CI). |
| **H2 (P1)** | ✅ Corrigé | `HANDSHAKE_TIMEOUT` (10 s), `FRAME_TIMEOUT` (30 s), `CONNECT_TIMEOUT` (5 s) + helper `read_exact_timeout` appliqué au handshake, aux 3 lectures de frame (len/nonce/ciphertext) et au connect outbound. Test `test_read_exact_timeout`. |
| **H3 (P1)** | ✅ Corrigé | Rate limit **par IP** (`ConnectInfo(remote_addr)` + `rate_limiter_per_ip`, clé `IP|method`, 40 req/10 s) avant le check global. Pagination : `get_transaction_history(address, limit)` (default 100, max 1000, `total_count` exact par count séparé) et `get_dag_graph(limit)` (default 500, max 5000, edges filtrés sur les nœuds inclus) ; les deux dispatches RPC transmettent le paramètre. Tests : isolation par IP, bornes dag_graph, bornes history. |
| **H4 (P2)** | ✅ Corrigé | **V-24, changement de protocole** : handshake 36 → 69 octets `magic(4) \| version(1) \| genesis_hash(32) \| clé éphémère(32)`, avec `P2P_PROTOCOL_VERSION = 2` et `verify_handshake_identity` (magic + version + genesis). Compatibilité : tous les nœuds doivent tourner le même binaire — acceptable car le testnet n'est pas public et la cérémonie genesis purge les datadirs. Tests : mismatch (magic/version/genesis/truncation) + clé de session partagée (X25519) via duplex. |
| **H5 (P2)** | ✅ Corrigé | `check_and_evict_cooldowns` : éviction des entrées > 60 s à chaque check → la map est bornée par le nombre d'adresses distinctes actives dans la fenêtre. Test unitaire. *(Erreur de lecture initiale : le faucet EXISTE bien dans `rpc.rs` — vérifié par re-grep fiable.)* |
| **H6 (P1)** | ✅ Corrigé | `main.rs` : suppression des deux fallbacks silencieux `[[0u8;32];2]` (erreur transport ET erreur de parsing JSON de `aether_getTips` → erreur stricte avec message, refus d'envoyer avec parents genesis). |
| **H7 (P1)** | ✅ Corrigé | `rpc.rs` : les 8 lignes `info!` par tx (`🔍 Processing transaction…`) + `Raw hex` passées en `debug!` ; `RAW RPC PARAMS RECEIVED` passe de `error!` à `debug!` (anti-amplification + confidentialité des payloads). |
| **H8 (P2)** | ✅ Partiel | Commentaire « base58 » → hex (correct) ; fallback mnémonique zéro-entropie `[0u8;16]` supprimé → `expect` (erreur dure, un keypair prévisible ne doit jamais exister). La partie « `--import <hex>` en ligne de commande » est **n/a** : aucune commande d'import hex n'existe dans ce codebase (seuls `Create` et `Restore` mnémonique). |
| **H10 (P2)** | ✅ Corrigé | `/metrics` : `node_type="full"`, `version={env!("CARGO_PKG_VERSION")}` (1.1.1) au lieu de « miner »/« 1.0.0 » codés en dur. |
| **H9, H11** | ⚪ INFO | Aucune action requise (documentées). |
| **§J (P2)** | ✅ Purge | Supprimé (vérifié sans appelant nulle part, y compris tests/harness/explorer/GUI) : module `explorer_api.rs` entier (+ exports `lib.rs`) ; `NodeStatusReport` + `GlobalStatusResolver`/`reconcile_quorum` (vestiges VQV — `reconcile_single` conservé et déplacé dans `impl GlobalStatus`) ; `StakingResponse`/`StakingInfoResponse` ; `TransactionFinality` ; `HashrateResponse` + `get_network_hashrate` + `aether_getNetworkHashrate` ; `start_mining`/`stop_mining` + `aether_startMining`/`aether_stopMining` (placeholders, aucune méthode n'appelle ces RPC) ; champ `mining_rewards` (toujours 0, zéro émission) ; `Ledger::load_or_create`/`save_to_file`/`save_blocking` (legacy fichier inutilisé). Conservés : `get_mining_status`/`aether_getMiningStatus` (non flaggé par l'audit, état réel lu). |
| **S11 (P3, anticipé)** | ✅ Ajouté | `test_double_spend_order_invariance` : double-dépense (même sender+nonce, receivers différents) traitée dans **les deux ordres d'arrivée** → même gagnant (min-id, prune + rebuild) et état du ledger identique. Met en évidence que la règle min-id est câblée dans STEP 0 du processor (`existing_id <= tx.id` → rejet ; sinon prune du sous-arbre du perdant + rebuild du ledger) et que `rebuild_from_dag` reseed strictement depuis le genesis. |

### Erreurs de l'audit corrigées pendant l'exécution

1. **Le faucet existe** (`rpc.rs` : `aether_faucet`, `faucet_cooldowns`, `faucet.key` serveur-only, V-01) — H5 était réel et non « code absent ». L'outil de recherche initial était défaillant ; tous les usages ont été re-vérifiés.
2. **H8‑import** : la commande `keygen --import <hex>` décrite dans l'audit n'existe pas dans ce codebase.
3. **Le poids n'est jamais calculé** (`tx.weight = 0.0`) : `determine_transaction_status` ne peut donc jamais produire `Stable` (statut conservé par l'API). Défaut **déjà connu** (§I.2) — non corrigé en Phase 2 (hors périmètre P0–P2, nécessite une décision produit : calculer le poids ou retirer les statuts morts).

### Risques restants (honnêteté)

- **§L.1** : `CumulativeWeightCache` jamais invalidée → poids périmés ; RPC `get_dag_graph`/`get_transaction_history`/`get_recent_transactions` restent O(DAG) même bornés (H3 atténue, pas élimine).
- **§L.4** : flush Sled par tx acceptée (STEP 8) — bottleneck TPS.
- **H1/H10 orphelins** : les ré-essais + re-demandes P2P périodiques pour TOUS les orphelins restent une feature manquante (les orphelins sont persistés mais ne sont pas re-soumis automatiquement ; un nœud re-connecté à un pair plus riche converge via la sync périodique).
- **Migration bincode 2** : changera le format fil — planifiée, non exécutée (changement de protocole numéroté).
- **`mining_enabled`** : lu par `get_mining_status` mais jamais écrit depuis la suppression des placeholders (le mining est client-side) — cosmétique.

### Verdict Phase 2

> **Toutes les failles P0–P2 de l'audit sont corrigées avec tests.** Les 133 tests passent (122 → 133 : +11), zéro warning clippy nouveau, build complet OK. Les conclusions restent : **TESTNET PUBLIC POSSIBLE après cérémonie genesis** (rotation genesis + purge des datadirs, seule procédure de compat pour V-24 et le genesis actuel) — sous réserve des risques restants ci-dessus et des recommandations de la Phase 3 (perf §L, déterminisme étendu, fuzzing).
## O. Rapport d'execution Phase 4 (mission 2) — les 5 risques restants

Date : 2026-08-16. Base : 138 tests unitaires (1 ignore = bench), 0 echec.
Mise a jour 2026-08-17 : decision produit O.1 = implémenter un vrai poids (v3) ; harnais S1-S10 reconstruit et re-certifie (84/84).

### O.1 WEIGHT / Stable — verdict : CORRIGE (decision produit executee, v3)

Analyse initiale (tests ajoutes : `test_consensus_path_real_status_ladder`) :
- L'acceptation = gate pure (PoW 20 + signature) → gate orphelin → validate_dag/validate_ledger → `add_transaction_validated` + resolution de conflit deterministe min-id (STEP 0, `existing_id <= tx.id` → rejet ; sinon prune + rebuild). La finalite est immediate une fois dans le DAG (commentaire STEP 6 : "The DAG is the single source of truth").
- A l'epoque : `tx.weight` n'etait JAMAIS ecrit en production (0.0 partout ; seul `get_dag_snapshot` calculait a la volee un poids cumule descendant — jamais stocke). `determine_transaction_status` : `Stable` exige `weight >= 5.0` → **structuralement inatteignable** ; `Finalized` saute explicitement ("we don't have a finalized mechanism"). `practically_final` ne valait donc jamais vrai.
- Le whitepaper decrit un consensus "Heavy Subgraph" (poids stake/energie, reputation, seuils dynamiques) qui n'existe pas dans le code : l'implementation est un DAG-append simplifie. L'ecart documentation ↔ code etait REEL.

**Decision produit (2026-08-17) : option (b) — implementer un vrai poids.** Changement de protocole :
- `tx.weight` est desormais MAINTENU par le DAG : `add_transaction_validated` pose `weight = 1.0` puis `adjust_ancestor_weights(parents, +1.0)` (marche ascendante, anti-doublon par `visited`, genesis et noeuds prunes ignores) ; `remove_transaction` fait `adjust_ancestor_weights(parents, -1.0)` — la cascade de prune decremente correctement chaque ancetre survivant d'exactement 1 par descendant prune. Le poids = taille du sous-arbre (soi + descendants).
- `compute_hash()` exclut le poids → les identifiants de transactions sont INCHANGES ; aucun impact sur le consensus, les conflits, le stockage ni la resolution de boot.
- `CumulativeWeightCache` (cf. O.2) SUPPRIME ; `calculate_cumulative_weight` lit `tx.weight` stocke.
- Echelle de statut organiquement atteignable : `Unconfirmed` (0 refs) → `Confirmed` (>= 3 refs) → `Stable` (weight >= 5.0) → `practically_final`. Verifie par test (`test_consensus_path_real_status_ladder` reecrit : 1 → 4 → 5 → 6, Stable + practically_final atteints, propagation petit-enfant).
- Test ajoute : `test_cumulative_weight_maintained_by_dag` (ajout/retrait/prune/diamant : prune de C → A 5→3, B 3→2).
- **Deploiement : `P2P_PROTOCOL_VERSION` 2 → 3** (p2p.rs) → ancien et nouveau reseaux incompatibles ; **rotation genesis obligatoire** (nouvelle ceremonie, les anciens smokes genese ne se connectent pas). Aucune genese fabriquee : la ceremonie est manuelle (cf. docs/CEREMONIE_GENESIS.md).
- **Correction decouverte par la campagne W (2026-08-17, phase finale) :** `prune_subtree` supprimait la racine d'abord → la marche ascendante d'un descendant s'arretait sur un parent deja retire → ancetres survivants SOUS-decrementes (poids trop eleves, differents selon l'historique : risque de divergence). Corrige : retrait en **ordre feuilles→racine** (`to_remove.iter().rev()`), les parents des survivants sont toujours presents lors de leur marche. Decouvert par `test_w3_weight_decreases_on_removal` (W1-W12 : 149 PASS). Verifie en regression par l'empreinte `h_weights` du harnais (identique sur tous les nœuds).

### O.2 CACHE — verdict : CORRIGE (cache supprime)

- A l'origine : `CumulativeWeightCache` vivait uniquement dans `ParentSelectionAlgorithm`, cree FRAIS a chaque appel de `get_tips_with_selector` (parent_selection.rs:643), seule utilisation production (node.rs:395, inventaire tips P2P) ; `invalidate`/`clear` = API morte (zero appelant) — risque latente documentee.
- 2026-08-17 : la decision O.1 rendant le poids STOCKE, le cache est devenu inutile et a ete **entièrement supprime** (plus d'API morte, plus de risque latente). Les tests `test_cumulative_weight_cache_per_call_scope` (ancienne instance = 3, instance fraiche = 5) sont remplaces par `test_cumulative_weight_maintained_by_dag` (O.1).

### O.3 ORPHANS — verdict : OK (mechanisme present et prouve)

- La resoumission automatique EXISTE : `process_orphans` (rpc.rs:1053) tourne apres chaque tx P2P acceptee (node.rs:477) et toutes les 10s (node.rs:542) ; recharge les orphelins du disque au boot ; re-traite via le gate complet ; re-demande les parents P2P a chaque cycle ; retire en cas de succes ou d'erreur permanente (duplicate/double-spend/sender conflict) ; plafonne a MAX_ORPHANS=50 000 (H1).
- Test ajoute : `test_orphan_auto_resubmission_cycle` — orphelin mine+signe (diff 20) parke (memoire+Sled) → parent ajoute → `process_orphans` le resout (DAG + ledger 3900, retrait memoire+Sled). Precedence de statut verifiee : orphans → mempool → DAG (`InMempool` quand la tx est dans les deux, comportement reel).
- Le boot rebuild (node.rs:128-141) re-ajoute les orphelins residuels au DAG seulement si leurs parents existent (add_transaction_validated verifie les parents) ; sinon ils restent orphelins et sont re-resolus par process_orphans.

### O.4 SLED — verdict : OK, FIX applique (bench avant/après)

- Avant : **2 fsyncs par tx acceptee** — `ledger.save()` (flush dans save, ledger.rs:112) + `flush()` explicite apres put_transaction (STEP 8, transaction_processor.rs:317) ; save() reecrit aussi tout l'etat balances+nonces a chaque tx.
- Bench (harness `bench_sled_persistence_per_transaction`, ignore par defaut) :
  - Debug : avant 73/74/68 tps (100/1000/10000) ; apres identique (~80 tps) — le goulot debug est `Wallet::verify_transaction` (12 ms/tx, ed25519 non optimise — artefact du profil test, PAS production).
  - Release (binaries de production) : avant **1226 / 1101 tps** ; apres **8480 / 4870 tps** (1000/10000). Le per-tx flush coutait ~690 µs/tx (78.6 ms vs 9.8 ms par 100 txs).
- Fix : suppression du flush dans STEP 8 et dans `ledger.save()` ; **flush periodique ajoute au cycle 10s du node** (node.rs) + auto-flush Sled (~500 ms) + flush d'arret (main.rs) → fenetre de perte sur kill brutal bornee a un cycle ; le boot rebuild reconstruit le ledger depuis le DAG (source de verite) de toute facon.
- Decouverte secondaire (documentee, non corrigee) : `find_sender_nonce_conflict` est un scan O(n) du DAG entier, execute 2× par tx (STEP 0 + validate_dag) → O(n²) global (explique la baisse 8480→4870 entre 1000 et 10000). Correct mais a indexer pour une future optimisation (aucun impact consensus).

### O.5 BINCODE — verdict : OK (aucun risque bincode 2)

- `bincode = "1.3"` pince dans Cargo.toml — semver interdit une migration silencieuse vers bincode 2 (format different). L'ecosysteme RustSec signale bincode 1.3 "unmaintained" (RUSTSEC-2025-0141) : risque de maintenance, pas de securite.
- Test ajoute : `test_bincode_persistence_round_trip_across_reopen` — ecriture → reopen Sled → lecture byte-identique (transactions + orphelins + mempool) ; verrou Sled Windows gere (drop avant reopen). Le format sur disque depend de l'ORDRE des champs de `Transaction` : toute modification de schema doit etre un changement delibere (version reseau + migration), jamais silencieux.

### O.6 S11 renforce

- `test_boot_rebuild_converges_after_crash_residue` : residue de crash contenant les DEUX candidats + un descendant du perdant dans le stockage → `canonical_resolve_conflicts` (V-21, boot) → insert topologique → rebuild_tips → `rebuild_from_dag` → meme gagnant que la resolution live (funding+winner, sender 890, receiver gagnant 100, perdant 0). 6 tests double-spend au total, 3 passes consecutifs sans flakiness.

### O.7 Verification finale (post cargo clean, toolchain stable-x86_64-pc-windows-gnu)

- `cargo fmt --check` : propre. `cargo test --lib` : **138/138 + 1 ignore** (bench). `cargo clippy --lib` : 43 warnings (tous pre-existants, 0 nouveau). `cargo audit` : **0 vulnerabilite** sur 567 dependances, 7 warnings "unmaintained" (dont bincode, derivative, fxhash, instant, paste, rustls-pemfile, ttf-parser). Builds debug + release OK.
- Multi-node (test-multi-node.ps1, corrige : `peer_count` → `connected_peers` renomme au purge §J ; etape faucet tolerante car `faucet.key` supprime par la ceremonie genesis — etat attendu) : **3/3 PASS** (3 nœuds, connexions P2P, sante).
- Toolchain GNU : apres `cargo clean`, `dlltool` (mingw) doit etre sur PATH (`C:\msys64\ucrt64\bin`) pour la compilation — a documenter pour CI.

### O.7bis Harnais resilience S1-S10 reconstruit et re-certifie (2026-08-17)

- `resilience.ps1` restaure (copie d'archive temp, seed `fa5979` supprime, pilote par env : `AETHER_FOUNDER`, `AETHER_FAUCET`, `AETHER_FAUCET_SEED` — cles ceremonie). Exe : `target\release\aether-unified.exe` ; racine : `%TEMP%\opencode\aether-net2` ; 10 scenarios (kill/restart V-22, reconnect V-18, boot rebuild V-21, double-spend, charge 200 txs) ; assertions = empreintes SHA-256 par nœud (txset/edges/tips/ledger/supply) comparees entre nœuds.
- Adaptation au durcissement RPC existant : le limiteur de debit est **40 req / 10s par (IP, methode)** (rpc.rs) — les rafales du harnais (assertions multi-nœuds + envois CLI partagent 127.0.0.1) declenchaient des rejets transitoires ; le CLI `send` echouait alors sur `Failed to extract next_nonce from RPC response` (main.rs). Correction COTE HARNASSIER UNIQUEMENT (aucun code consensus touche) : retry des envois (backoff traversant la fenetre 10s), retry des lectures balance/nonce (sleep 12s ≥ fenetre), et **flag "degraded"** : une lecture echouee definitivement rend l'assertion FAIL explicite au lieu d'un PASS silencieux (valeurs null). Aucun assouplissement de securite.
- Resultat : **3 runs complets S1-S10, 28 assertions chacune = 84/84 PASS** (2026-08-17). Le "SEND FAILED A->B" de S8 est le rejet ATTENDU du double-spend (fond insuffisant). Les mises a jour de statut ne sont pas re-verifiees ici : cf. O.1 (echelle Stable/practically_final desormais atteignable).
- **Phase finale (2026-08-17) :** `Get-FullState` calcule desormais `h_weights` (SHA-256 des paires triees `id:weight` extraites de `aether_getDagGraph`) et l'ajoute a l'objet d'etat + empreinte → la convergence des POIDS entre nœuds est comparee a chaque assertion. Run final avec cette empreinte active : **28/28 PASS** (log `%TEMP%\opencode\resilience_run_weights.log`). Couverture totale : txset, edges, tips, ledger, supply, poids.

### O.8 Verdicts Phase 4 (mis a jour 2026-08-17)

| Risque | Verdict | Justification |
|---|---|---|
| WEIGHT / Stable | **CORRIGE (decision v3)** | Vrai poids implante (taille de sous-arbre maintenue par le DAG) ; Stable + practically_final organiquement atteignables ; `P2P_PROTOCOL_VERSION` 3 ; rotation genesis au deploiement |
| CACHE | **CORRIGE** | Cache ephemere supprime avec la decision O.1 ; plus d'API morte ni de risque latente |
| ORPHANS | **OK** | Auto-resoumission prouvee (cycle complet teste) ; aucun changement necessaire |
| SLED | **OK (corrige)** | Flush par tx supprime ; bench release 1226→8480 tps (1000 txs) ; durabilite bornee 10s + rebuild au boot |
| BINCODE | **OK** | bincode 1.3 pince ; format stable ; round-trip reopen teste ; migration bincode 2 = decision explicite |
| PRUNE (poids) | **CORRIGE (phase finale)** | Ordre feuilles→racine dans `prune_subtree` (W3) ; W1-W12 : 149 PASS ; `h_weights` converge (harnais 28/28) |

**Phase finale (2026-08-17) — alignement whitepaper ↔ code :** voir
`RAPPORT_FINAL_TECHNIQUE.md` §7 (comparaison formelle, question critique,
analyse Sybil W11, decision OPTION A, verdicts A-E) et
`docs/PROTOCOL_SPECIFICATION.md` (spec normative v3), `docs/THREAT_MODEL.md`
(menaces T1-T6), `docs/V3_TESTNET_CEREMONY_PLAN.md` (preparation ceremonie V3,
non executee).
| Harnais S1-S10 | **OK (reconstruit)** | `resilience.ps1` restaure et adapte au limiteur RPC ; 84/84 assertions (3 runs) le 2026-08-17 |

**Verdict global Phase 4 : 🟢 TESTNET PUBLIC — reserves O.1 (poids) et O.7 (harnais) LEVEES le 2026-08-17. Le code n'a PAS de defaut de consensus actif ; l'echelle de statut est desormais organiquement atteignable. Le modele economique complet du whitepaper (Heavy Subgraph stake/energie, finalite probabiliste) reste une simplification DAG-append : a acter explicitement avant toute communication publique (documentation, pas code).**
