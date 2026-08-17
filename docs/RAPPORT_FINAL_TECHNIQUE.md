# AETHER SEDC — Rapport Final Technique

**Version évaluée** : `aether-unified 1.1.1` (Cargo.toml) — workspace unique
**Commit de référence** : `be4df38` (HEAD, après corrections V-20..V-23)
**Rust toolchain** : `rustc 1.97.1 (8bab26f4f 2026-07-14)`
**Date du rapport** : 2026-08-16
**Statut global** : 🟡 TESTNET PUBLIC POSSIBLE (après cérémonie genesis — voir §6)

---

## 1. État du projet

### 1.1 Architecture générale

AETHER SEDC est un protocole **DAG blockless** : il n'y a pas de blocs. Chaque transaction
est un nœud du graphe ; elle référence des transactions antérieures (parents) et est
référencée par des transactions ultérieures (enfants). L'implémentation est un binaire
unique `aether-unified` avec un CLI (`aether`) et un GUI (`aether-gui`), construit en Rust
(édition 2021, dépendances dans `Cargo.toml` : tokio, sled, ed25519-dalek, x25519-dalek,
chacha20poly1305, sha2, blake3, axum, eframe/egui, argon2, bip39…).

Modules (`src/lib.rs`) :

| Module | Rôle |
|---|---|
| `transaction.rs` | Transaction, ids canoniques hex (V-20), sérialisation, PoW |
| `parent_selection.rs` | DAG, tips, sélection de parents, résolution canonique des conflits (V-21) |
| `validation.rs` | Pipeline de validation pure / DAG / ledger |
| `transaction_processor.rs` | STEP 0..9 : entrée unique « zéro-trust » de toute transaction |
| `ledger.rs` | Soldes, nonces, supply, `rebuild_from_dag` déterministe (V-21) |
| `p2p.rs` | Transport chiffré, inventory/GetData, sync complet (V-22) |
| `rpc.rs` | API JSON-RPC, faucet, status consensus (VQV), retry locks (V-22) |
| `node.rs` | Orchestration nœud, tâches de sync, réconciliation périodique (V-22) |
| `wallet.rs` | Wallet Ed25519 + BIP39, chiffré au repos Argon2id + AES-256-GCM |
| `storage.rs` | Persistance Sled (DAG, ledger, mempool, orphelins) |
| `genesis.rs` | Allocation initiale, constantes monétaires, adresses publiques |
| `explorer_api.rs` / `gui.rs` / `config.rs` / `json_storage.rs` | Explorer, GUI, config, stockage JSON |

### 1.2 DAG

- Genesis : `GENESIS_HASH = [0u8; 32]`, message d'ancrage `GENESIS_MESSAGE`
  (preuve de date de lancement).
- Chaque transaction acceptée est ajoutée au DAG ; les parents sont choisis parmi les
  tips (extrémités du graphe).
- L'ordre canonique de tout ensemble de transactions est défini par tri lexicographique
  des ids hex (V-20) : **tous les nœuds trient le même ensemble de la même façon**.
- Micro-PoW par transaction (difficulté initiale 1000, ajustée par l'oracle de frais).

### 1.3 Consensus

- **Heavy Subgraph Consensus** : finalité probabilistique, sans leader.
- Quorum pondéré (VQV) : `quorum_threshold = 0.67` (2/3), fallback majorité
  (`rpc.rs` : `GlobalStatus`/`reconcile_quorum`) ; statuts `in_mempool`,
  `confirmed`, `stable`, `final`.
- **Le DAG est le consensus** : une transaction est « acceptée » quand elle satisfait
  les règles de validation déterministes ; aucun vote réseau n'est requis pour
  l'acceptation — les votes VQV ne servent qu'au statut de finalité observé.

### 1.4 Règle canonique

- Tips sérialisés en hex canonique (V-20) : `aether_getTips` renvoie des chaînes hex,
  jamais des tableaux d'octets.
- `rebuild_from_dag` (ledger) : fonction pure du DAG — même DAG ⇒ même ledger,
  même hash, mêmes nonces (V-21).
- `canonical_winners` (parent_selection) : parmi les transactions en conflit
  (sender, nonce), le **minimum d'id lexicographique gagne**, déterministe et
  indépendant de l'ordre d'arrivée.

### 1.5 Résolution des conflits

- `has_sender_conflict` dans `validate_dag` : deux transactions du même sender avec le
  même nonce sont en conflit ⇒ le perdant est rejeté/pruné (STEP 0 du processeur).
- Un conflit est résolu **avant** toute mutation d'état (STEP 0), puis les transactions
  prunées sont purgées de la persistance (V-21) et leurs nonces n'affectent pas le ledger.
- V-23 : la validation de nonce STRICTE (`nonce == last+1`, dépendante de l'ordre
  d'arrivée) a été **supprimée** ; le nonce ledger est désormais le **max** par sender
  (STEP 5), identique au résultat de `rebuild_from_dag`.

### 1.6 Double dépense

- Impossible au niveau DAG : unicité (sender, account_nonce) vérifiée canoniquement.
- Deux txs concurrentes même (sender, nonce) : une seule survit (min id), de façon
  identique sur tous les nœuds (prouvé par S8/S9).
- Protection anti-replay : même id de transaction rejoué ⇒ rejet par `validate_dag`.

### 1.7 P2P

- Transport chiffré : handshake X25519, chiffrement ChaCha20-Poly1305 / AES-256-GCM,
  Perfect Forward Secrecy.
- Limites anti-DoS : message max 16 MiB (V-09), nombre max de peers (V-10),
  rate limit par frame.
- **V-22** : sync complet — `request_full_sync` demande l'inventaire complet de chaque
  pair ; les transactions reçues sont dédupliquées par **appartenance au DAG** (et non
  par `seen_transactions`) ; retry des verrous en contention (RPC et processeur).

### 1.8 Wallet

- Ed25519 (signatures), BIP39 (mnémotechnique), fichiers chiffrés au repos :
  Argon2id (KDF mot de passe) + AES-256-GCM ; mnémonique et clé partagent un nonce frais.
- CLI `aether wallet create/balance/send` + GUI intégré.

### 1.9 Économie

- Allocation genesis (`GENESIS_LEDGER`) :
  - Founder : 10 AETH (`100_000_000_000` unités de base)
  - Faucet : 100 000 000 AETH (`1_000_000_000_000_000_000`)
- **Émission ZÉRO** après genesis ; `MAX_SUPPLY = 200 000 000 AETH` (garde défensive).
- Chaque transaction brûle son fee vers `FEE_BURN_ADDRESS = [0xFF;32]`.
- Supply totale vérifiée à chaque assertion réseau : **1000000100000000000**
  (= 1e18 faucet + 1e11 founder) — exactement, dans tous les scénarios, sans inflation.

### 1.10 Persistance

- Sled : DAG, ledger, mempool (persistant), orphelins, stockage batch
  (`storage.rs`), sauvegarde à chaque transaction acceptée (STEP 8).
- Wallet : fichiers JSON chiffrés au repos.

### 1.11 Synchronisation

- Flux P2P : inventaires, GetData, broadcast, demande de txs manquantes (10 s).
- **V-22** : réconciliation périodique complète (`node.rs` — periodic full
  reconciliation) + `request_full_sync` + retry sur LockError (RPC `process_transaction`).
- Un nœud redémarré demande l'inventaire complet de ses pairs et re-télécharge tout.

### 1.12 Reconstruction après redémarrage

- Au boot : chargement Sled, puis `rebuild_from_dag` canonique (V-21) : le ledger
  (soldes, nonces, supply) est **recalculé à partir du DAG** — ordre de traitement
  canonique, conflits résolus par min-id, nonces = max.
- Puis sync P2P (V-22) pour rattraper les transactions manquantes. Validé par
  S2, S3, S5, S6 (restarts) et S4 (reconnexion).

### 1.13 Convergence multi-nœuds — explication précise

> Comment plusieurs nœuds recevant les mêmes transactions dans des ordres différents
> convergent vers le même état final ?

1. **Validation sans état mutable** (`validate_pure`) : signature, id, PoW, montants —
   déterministe par le contenu seul ; l'ordre d'arrivée ne peut pas changer le résultat.
2. **Validation DAG** (`validate_dag`) : parents présents, pas de conflit
   (sender, nonce) canonique, pas de replay (id unique) — propriétés de l'ENSEMBLE
   des transactions, pas de leur ordre.
3. **Validation ledger** (`validate_ledger`) : solde suffisant, fee, **nonce max** —
   le ledger étant une fonction pure du DAG, l'ordre d'arrivée n'influence plus rien
   (V-23).
4. **Résolution canonique** : en cas de collision (sender, nonce), le même gagnant
   (min id) est choisi partout ; les perdants sont prunés partout de la même façon
   (V-21).
5. **Mêmes règles ⇒ mêmes verdicts** : une transaction acceptée par un nœud l'est par
   tous les autres (mêmes règles pures) ; une transaction rejetée l'est partout.
6. **Propagation complète** : chaque nœud finit par posséder le même ensemble de
   transactions (broadcast + inventory/GetData + full sync V-22), donc le même DAG.
7. **Hash d'état identique** : `h_txset`, `h_dag`, `h_tips`, `h_ledger`, supply
   (SHA-256 d'ensembles triés) — comparés par le harnais : 84/84 identiques.
8. **Redémarrage** : `rebuild_from_dag` donne le même ledger depuis le même DAG ;
   un nœud mort puis ressuscité rattrape via full sync et converge.

---

## 2. Historique des corrections

La traçabilité en dépôt est partielle : les commentaires de code référencent
V-01, V-09, V-10, V-20, V-21, V-22, V-23 et NV-02, NV-09. Les numéros intermédiaires
(V-02..V-08, V-11..V-19) ne sont **pas documentés dans le dépôt** — ils sont marqués
`NON CONFIRMÉ` (aucune trace de la description, de la correction ou des tests).

### V-01 — Clé privée du faucet présente dans le source
- **Description** : le seed du faucet figurait en dur dans le code source.
- **Impact** : toute personne ayant accès au dépôt pouvait signer des transactions
  faucet (contrôle de 100M AETH).
- **Fichier** : `src/rpc.rs` (ancien), `src/genesis.rs` (adresses publiques).
- **Correction** : la clé a été retirée du source ; le faucet charge la clé depuis un
  fichier serveur `data_dir/faucet.key` (64 hex, 32 octets) ; sans fichier, le faucet
  est désactivé ; clé non concordante avec `FAUCET_ADDRESS` ⇒ faucet désactivé
  (`rpc.rs` `load_faucet_key`).
- **Tests** : `faucet_key_tests` (missing/invalid/wrong length/mismatch) dans
  `security_tests.rs`.
- **Statut** : CORRIGÉ. **Note : la clé historique `fa5979…` est néanmoins CONSIDÉRÉE
  COMPROMISE** (elle a circulé dans des scripts de test, harnais, wallets, data-dirs) —
  cérémonie genesis obligatoire (livrable 2).

### V-09 — Allocation mémoire illimitée sur message P2P
- **Description** : pas de borne sur la taille d'un message reçu → OOM possible.
- **Impact** : DoS mémoire d'un nœud.
- **Fichier** : `src/p2p.rs` (max 16 MiB).
- **Correction** : taille maximale de message accepté (16 MiB) + préfixe de longueur.
- **Tests** : contrainte vérifiée par les tests P2P et les tests de dépassement RPC
  (`test_oversized_tx_rejected_by_rpc`).
- **Statut** : CORRIGÉ.

### V-10 — Connexions P2P illimitées
- **Description** : nombre de peers concurrents non borné.
- **Impact** : DoS par épuisement des connexions.
- **Fichier** : `src/p2p.rs`.
- **Correction** : maximum de peers connectés.
- **Tests** : intégrés aux tests P2P.
- **Statut** : CORRIGÉ.

### V-02 … V-08, V-11 … V-19
- **Statut** : NON CONFIRMÉ — aucune description, correction ou test associé n'existe
  dans le dépôt. Ces numéros proviennent d'un registre d'audit antérieur non archivé.
  Une re-documentation (ou un re-audit) est requise avant toute publication — voir §5.

### NV-02 — `total_supply` périmée lors de set_balance direct
- **Description** : un `set_balance` direct pouvait rendre `total_supply` incohérent.
- **Fichier** : `src/ledger.rs` (`total_supply` recalculée depuis les soldes vivants).
- **Correction** : `total_supply` toujours dérivée des soldes réels.
- **Statut** : CORRIGÉ.

### NV-09 — Résolution de double dépense non déterministe
- **Description** : le traitement d'une collision (sender, nonce) dépendait de l'ordre
  de traitement.
- **Fichier** : `src/transaction_processor.rs` (STEP 0).
- **Correction** : STEP 0 déterministe avant toute mutation : `find_sender_nonce_conflict`
  + min-id canonique ; les perdants sont purgés de la persistance.
- **Tests** : `test_find_sender_nonce_conflict`, `test_sender_nonce_conflict_rejected`,
  `test_distinct_nonces_are_not_conflict`, `test_shared_parents_are_not_conflict`,
  S8/S9.
- **Statut** : CORRIGÉ (précurseur de V-21/V-23).

### V-20 — Tips sérialisés en tableaux d'octets (non canoniques)
- **Description** : `aether_getTips` et les limites de sérialisation pouvaient
  renvoyer des tableaux numériques → hash d'état différent d'un client à l'autre.
- **Impact** : divergence d'observation entre nœuds/CLI/GUI ; rupture d'invariant.
- **Fichier** : `src/transaction.rs` (`encode_id`), `src/rpc.rs` (get_tips),
  `src/main.rs` (parsing strict), `src/gui.rs`.
- **Correction** : sérialisation canonique hex partout (RPC, CLI, GUI, P2P, stockage) ;
  parsing strict : un payload malformé est une ERREUR, jamais un silence.
- **Tests** : `transaction.rs` (§V-20 canonical hex id serialization),
  `rpc.rs` (`aether_getTips` canonical hex), compat inter-nœuds.
- **Statut** : CORRIGÉ.

### V-21 — `rebuild_from_dag` non déterministe
- **Description** : la reconstruction du ledger au boot pouvait dépendre de l'ordre
  d'itération du DAG → états divergents après redémarrage.
- **Impact** : divergence post-redémarrage (défaut majeur de consensus).
- **Fichier** : `src/ledger.rs`, `src/parent_selection.rs` (`canonical_winners`),
  `src/node.rs`, `src/transaction_processor.rs`.
- **Correction** : traitement canonique (tri lexicographique), résolution canonique
  des conflits (min id), nonces = max, tips canoniques ; relaxation : ne jamais
  détruire une tx valide pour une tx invalide ; purge des prunés de Sled.
- **Tests** : `ledger.rs` (§V-21 deterministic canonical rebuild),
  `parent_selection.rs` (§V-21 canonical conflict resolution), S6 (reboot complet).
- **Statut** : CORRIGÉ.

### V-22 — Synchronisation P2P incomplète / txs perdues
- **Description** : (a) dédup par `seen_transactions` pouvait laisser une tx absente
  du DAG sans re-demande ; (b) contention de verrous (LockError) faisait échouer
  définitivement le processing d'une tx ; (c) pas de sync complète périodique.
- **Impact** : transactions perdues, états divergents, resync infinie.
- **Fichier** : `src/p2p.rs` (handler SyncResponse, `request_full_sync`),
  `src/node.rs` (réconciliation périodique), `src/rpc.rs` (retry LockError).
- **Correction** : dédup par appartenance au DAG ; retry des verrous (20 tentatives,
  backoff 25 ms×n) ; réconciliation complète périodique ; full sync à la demande.
- **Tests** : tests P2P + scénarios S2 (restart node3), S4 (reconnexion),
  S5 (kill node5 + resync), S6 (reboot total).
- **Statut** : CORRIGÉ.

### V-23 — Validation de nonce dépendante de l'ordre d'arrivée
- **Description** : `validate_ledger` exigeait `nonce == last_nonce + 1`. Une tx
  valide (nonce 3) arrivant après les nonces 4,5,6 était rejetée en boucle sur un
  nœud (« Invalid nonce: expected 6, provided 3 ») mais acceptée sur un autre →
  divergence PERMANENTE + boucle de resync infinie (le pair la redemande chaque cycle).
- **Impact** : rupture de convergence observée sur 5 nœuds (S5 run 1 échoué :
  node1=44, node2=47, node3=45, node4=47, node5=43 ; 2 orphelins coincés).
- **Fichier** : `src/validation.rs` (check strict supprimé), `src/transaction_processor.rs`
  (STEP 5 : commit MAX), `src/ledger.rs` (`validate_and_commit_nonce_internal` supprimée,
  `validate_account_nonce` conservée pour tests), `src/rpc.rs` (retry lock).
- **Correction** : la protection anti-replay/double-dépense vit au niveau DAG
  (unicité (sender, nonce) canonique, déterministe) ; le nonce ledger = **max par
  sender**, identique au rebuild. Ordre d'arrivée sans effet.
- **Tests** : `test_replay_attack_prevention` réécrit (niveau DAG),
  `test_out_of_order_nonce_rejected` → **renommé** `test_out_of_order_nonce_accepted`
  (le nonce hors-ordre est ACCEPTÉ, conformément à la nouvelle règle). 122/122.
  ⚠️ **Déviation assumée** : 2 tests ont été adaptés car ils asserçaient l'ancien
  comportement ordre-dépendant qui cassait la convergence — preuve S5.
- **Statut** : CORRIGÉ.

---

## 3. Résultats des tests

### 3.1 Tests unitaires

- **Nombre** : 122 (listing `cargo test --lib -- --list`).
- **Résultats** : `122 passed; 0 failed; 0 ignored` (12,15 s).
- **Répartition réelle par module** (listing exact) :

| Module | Tests |
|---|---|
| tests (mod, security_tests) | 25 |
| ledger | 24 |
| transaction | 20 |
| parent_selection | 13 |
| storage | 10 |
| wallet | 9 |
| validation | 8 |
| p2p | 7 |
| explorer_api | 2 |
| rpc | 2 |
| transaction_processor | 2 |
| **Total** | **122** |

Couverture de code : non instrumentée (pas de tarpaulin/grcov configuré) — voir §5.

### 3.2 Tests multi-nœuds (S1–S10, harnais `resilience.ps1`)

Protocole d'assertion (`Assert-Invariant`) : pour chaque scénario, l'état complet de
chaque nœud est capturé (txset trié, edges triés, tips triés, ledger = soldes+nonces
de toutes les adresses connues, supply) et haché SHA-256 ; tous les nœuds doivent
produire **exactement** `h_txset`, `h_dag`, `h_tips`, `h_ledger` et `supply` identiques,
avec le nombre de transactions exact attendu. **Résultat : 3 runs complets
S1–S10, 84 assertions, 84/84 PASS, 0 FAIL, 0 WARN.**

| Scénario | Nœuds | Txs | Événements | Convergence | Résultat ×3 |
|---|---|---|---|---|---|
| S1 | 2 | 20 | — | tx=20, tips=1 | PASS |
| S2 | 3 | 30 | kill node3 mi-charge + restart + resync | 30/30 | PASS |
| S3 | 3 | 30 | kill node2 tôt + restart mi-flux | 30/30 | PASS |
| S4 | 4 | 50 | déconnexion/reconnexion node4 | 50/50 | PASS |
| S5 | 5 | 100 | kill node5 mi-charge + restart + full resync | 100/100 | PASS |
| S6 | 3 | 30 | kill TOUS les nœuds + reboot (rebuild V-21) | 30/30 | PASS |
| S7 | 4 | 30 | txs simultanées (sends séquentiels) | 30/30 | PASS |
| S8 | 3 | 3 | double dépense fonds insuffisants + send impossible rejeté | 3/3 (1 survivant) | PASS |
| S9 | 3 | 3 | double dépense concurrente MÊME nonce | 3/3, 0 doublon (sender,nonce) | PASS |
| S10 | 4 | 200 | charge 200 txs | 200/200 | PASS |

Détails clés des runs :
- **S5 run 1 (avant V-23)** : ÉCHEC — divergence 44/47/45/47/43, boucles
  « Invalid nonce: expected 6, provided 3 », 2 orphelins coincés. **Après V-23 :
  PASS** (run `aether-net2\20260815-203930`).
- **S8** : le send impossible (99999999999999 >> solde) est rejeté par le nœud
  (« Insufficient balance: 100000000000 < 100000000000009 »), count resté 2 ; un
  faux WARN initial était un bug du HARNAS (Write-Output fuyant dans la valeur de
  retour PowerShell) — corrigé (`Write-Host`), pas un bug réseau.
- **S9** : résolution canonique vérifiée : aucun doublon (sender, nonce) dans le DAG
  final (« canonical resolution verified »).
- **Supply dans CHAQUE assertion** : `1000000100000000000` — exact, invariant absolu.
- **S10** : 200 txs exactes sur 4 nœuds, 1 tip final, supply exacte.
- Bugs de harnais corrigés en cours de route : purge des data dirs entre runs
  (sinon accumulation 25=5+20, 150=50+100…), `knownAddrs` reset par run.

Preuves : logs `aether-net2\20260816-061643` (run ×3 complet, 84 assertions PASS),
`aether-net2\20260815-203930` (S5 post-fix), etc.

---

## 4. Invariants du protocole

| Invariant | Définition | Vérification |
|---|---|---|
| Supply maximale | `≤ MAX_SUPPLY (2e18)` ; supply vivante = `1e18 + 1e11` | Assertion supply dans chaque scénario + `test_supply_never_exceeds_genesis` + `test_processing_does_not_mint` |
| Burn des fees | fee débité du sender + brûlé vers `FEE_BURN_ADDRESS` ; émission zéro | Invariant supply exact sous charge ; tests ledger |
| Nonces | nonce ledger = **max** (sender, nonce) dans le DAG ; jamais strict +1 | `h_ledger` identique partout ; `test_rebuild_from_dag_preserves_invariant` ; V-23 |
| Unicité des transactions | (sender, account_nonce) unique dans le DAG ; id unique | `validate_dag`/`has_sender_conflict` ; S8/S9 (0 doublon) ; tests conflict |
| Cohérence DAG | même ensemble de txs, mêmes edges, mêmes tips (canoniques) | `h_txset`, `h_dag`, `h_tips` SHA-256 identiques sur tous les nœuds |
| Cohérence ledger | mêmes soldes+nonces sur toutes les adresses connues | `h_ledger` SHA-256 identique ; comparaison entrée par entrée en cas de mismatch |
| Synchronisation | nombre total de txs identique sur tous les nœuds ; resync après restart | `total_transactions` comparé ; S2-S6 |
| Déterminisme | l'état est une fonction pure du DAG (ordre d'arrivée sans effet) | S5 ×3, S6 (rebuild), 84/84 hash identiques |

---

## 5. Limites actuelles

### 🔴 Bloquants
1. **Clé faucet historique compromise** (`fa5979…`) : elle a circulé dans des scripts,
   harnais, wallets, data-dirs et logs de test. Toute publication nécessite la
   **cérémonie genesis** (livrable 2) — aucune clé ni wallet lié à l'ancien genesis
   ne doit survivre.
2. **Aucun audit cryptographique externe** : les primitives (Ed25519, X25519,
   ChaCha20-Poly1305, AES-256-GCM, Argon2id, PoW) et le protocole de consensus
   n'ont pas été audités par un tiers indépendant.
3. **Traçabilité V-02…V-19 absente** : numéros non documentés dans le dépôt ;
   impossible de prouver leur traitement. Re-audit nécessaire.

### 🟠 À surveiller
1. **`cargo audit` : 1 vulnérabilité active** — `RUSTSEC-2026-0221` (`event-listener
   5.4.1`, unsound, dépendance transitive) ; 8 warnings « unmaintained » (bincode,
   derivative, fxhash, instant, paste, rustls-pemfile, ttf-parser) ;
   `RUSTSEC-2026-0257` (webbrowser) ignoré avec justification documentée
   (`.cargo/audit.toml`) — cible GUI Windows, URLs internes.
2. **Pas de fuzzing long terme** (aucun fuzzer configuré sur transaction/P2P/RPC).
3. **Charge testée limitée** : 200 txs/scénario, 10 nœuds max ; pas de test
   réseau public multi-dizaines de nœuds.
4. **Peers comptés** : `connected_peers` affiche des valeurs supérieures au nombre
   réel de connexions (cosmétique, hors fingerprint, non bloquant).
5. **Faucet** : rate-limit 60 s **par adresse** (pas global) — acceptable pour
   testnet, à revoir pour mainnet.
6. **CI sécurité** : pipeline GitHub Actions présent (ci, release, security) mais
   audit déclenché manuellement ; pas de CI locale reproduite dans le harnais.

### 🟡 Améliorations futures
- Couverture de code (tarpaulin/grcov) + gate de qualité en CI.
- Fuzzing (cargo-fuzz / proptest) sur sérialisation, P2P, RPC, DAG.
- Benchmarks de charge (TPS, latence, mémoire) et réseau étendu.
- Monitoring/alerting renforcé (Prometheus `/metrics` existe ; ajouter alertes
  divergence d'état, sync stuck).
- Hardware wallet, support multisig, réputation dynamique plus granulaire.
- Documenter V-02…V-19 (ou re-audit) et archiver le registre des vulnérabilités.

---

## 6. Verdict

> **🟡 TESTNET PUBLIC POSSIBLE**

Justification :
- Les défauts de convergence (V-20, V-21, V-22, V-23) sont **corrigés et prouvés** :
  3 runs complets S1–S10, 84 assertions identiques sur tous les nœuds, restarts,
  partitions, doubles dépenses et charge 200 txs OK ; 122 tests unitaires PASS.
- Aucun bloquant de CONSENSUS identifié à ce stade (aucun 🟠/🔴 ne touche la
  convergence après les corrections).
- MAIS : (1) la clé faucet historique est compromise → le testnet ne peut ouvrir
  qu'**après la cérémonie genesis** (livrable 2) ; (2) pas d'audit crypto externe ;
  (3) traçabilité V-02…V-19 incomplète ; (4) une vulnérabilité de dépendance active
  (RUSTSEC-2026-0221). Ces points interdisent le 🟢 (validation définitive) et
  recommandent de considérer ce statut comme « testnet public de première étape »
  avec purge/rotation complète, monitoring actif et re-audit avant tout actif réel.
- Pas de 🔴 : aucun défaut de consensus ou d'intégrité bloquant n'a été démontré
  lors de cette campagne ; les artefacts de test seront supprimés par la cérémonie.

**Conditions d'ouverture du testnet public** (checklist opérateur dans le livrable 2) :
1. Cérémonie genesis exécutée et vérifiée (scripts fournis).
2. `cargo audit` vert (ou dérogations documentées pour chaque RUSTSEC).
3. Build reproductible documenté (commit, Rust, checksums).
4. Monitoring + alertes actives ; seed nodes ≥ 3.
5. Compte-rendu public de la cérémonie (hash genesis, fingerprint, preuves).

---

## 7. Phase finale — Alignement whitepaper ↔ code (2026-08-17)

### 7.1 Comparaison formelle (extraits vérifiés dans le code)

| Affirmation whitepaper v1 | Réalité du code (v3) | Écart |
|---|---|---|
| « Heavy Subgraph Consensus » : le sous-graphe le plus lourd gagne | Conflits résolus par **min-id** (STEP 0, transaction_processor.rs:136-172 ; `canonical_resolve_conflicts`, parent_selection.rs:668) ; le poids ne décide JAMAIS un conflit | **FONDAMENTAL** |
| Poids = f(stake, énergie, réputation) | Poids = **taille structurelle du sous-arbre** (1 + descendants), champs stake/energy inexistants dans `Transaction` | **FONDAMENTAL** |
| Sécurité Sybil par le stake | Aucun stake ; identité gratuite ; **W11 prouve** `Stable` en 5 txs (fee 5×10⁻¹⁰ AETH + ~5 M hachages) | **FONDAMENTAL** |
| Finalité probabiliste | Statuts fixes Confirmed ≥3 refs / Stable ≥5.0 ; `Finalized` **inatteignable** (pas de VQV) | MAJEUR |
| 2 à 8 parents | **Exactement 2** parents (`[TransactionId; 2]`) | MINEUR |
| Résolution de conflits par score/détection | Détection = `(sender, account_nonce)` ; résolution = min-id | MAJEUR |
| Difficulté adaptative / frais dynamiques | `AdaptiveDifficulty` et `calculate_recommended_fee` **définis mais jamais appelés** (code mort) ; difficulté fixe 20, `min_fee = 1` | MAJEUR |
| Supply 21 M, halving, récompenses | **Émission zéro** ; 100 000 010 AETH au genesis ; fees brûlés ; pas de mining reward | FONDAMENTAL |

### 7.2 Question critique : le consensus dépend-il du stake/énergie ?

**NON.** Le consensus v3 est purement structurel : acceptation = PoW 20 +
signature + parents présents + solvabilité + unicité `(sender, account_nonce)` ;
convergence = règle déterministe min-id + poids dérivé du DAG. Aucune étape
(validation, conflit, finalité, sélection) ne lit un stake ou une énergie. Les
preuves : campagne W1-W12 (149 tests PASS, dont W11 inflation et W12
exactitude 1000 txs), empreinte `h_weights` identique sur tous les nœuds
(harnais 28/28 PASS avec comparaison des poids actifs).

### 7.3 Analyse de sécurité (Sybil / manipulation du poids)

Démonstration par tests (voir THREAT_MODEL.md, menaces T1-T4) :
- **W11** : 5 txs chaînées → racine poids 5.0 = `Stable` = `practically_final`,
  à coût quasi nul. Le champ `weight` émis est écrasé (non contrôlable) — mais
  la structure elle-même suffit.
- **W6/W7** : un perdant de conflit est pruné même avec poids 3.0 → le poids ne
  protège pas d'un min-id plus petit.
- **W12** : exactitude du calcul (chaîne 1000 → 1000.0 ; étoile 1000 → 1001.0).

Conclusion sécurité : le mécanisme est déterministe et convergent, mais la
**finalité Stable n'a aucune garantie économique** ; « stake-secured »,
« energy-weighted » ou « Heavy Subgraph stake consensus » sont des formulations
**interdites** tant que cela n'est pas traité.

### 7.4 Décision de spécification — OPTION A RATIFIÉE (2026-08-17)

Le code (P2P v3) est **la** spécification normative ; le whitepaper v1 contient
des affirmations non implémentées. Décision ratifiée officiellement :
1. **OPTION A** : le code actuel est la référence du protocole Aether v3 ;
   le whitepaper est réécrit honnêtement dans `docs/WHITEPAPER_V2.md`
   (statut : document de référence, spec normative = `PROTOCOL_SPECIFICATION.md`).
2. **Pas de stake/énergie dans cette phase** — proposition non normative
   séparée : `docs/FUTURE_STAKE_ENERGY_PROPOSAL.md`.
3. Aucune modification du consensus, du genesis préparé, ni minimisation des
   résultats W11.
4. Documents normatifs v3 : `PROTOCOL_SPECIFICATION.md`, `WHITEPAPER_V2.md`,
   `THREAT_MODEL.md`, ce rapport §7, `AUDIT_ARCHITECTURE.md` O ;
   communication publique : `docs/PUBLIC_TESTNET_NOTICE.md`.

### 7.5 Campagne de tests après v3

- Unitaires : **149 PASS / 0 FAIL / 1 ignoré** (dont W1-W12).
- Harnais S1-S10 : **28/28 PASS** (3 runs 84/84) puis run final avec empreinte
  `h_weights` active → **28/28 PASS** (`%TEMP%\opencode\resilience_run_weights.log`).
- `cargo fmt` propre ; clippy = 43 warnings pré-existants (aucun nouveau).
- Découverte et correction réelles : **ordre de prune inversé (feuilles→racine)**
  dans `prune_subtree` (divergence de poids possible), trouvée par W3 ; le
  maintien de l'empreinte `h_weights` dans le harnais en est la régression.

### 7.6 Verdicts

| Item | Verdict |
|---|---|
| A. Code ↔ whitepaper alignés | **A : NON ALIGNÉ — écart FONDAMENTAL sur consensus pondéré, finalité, émission** |
| B. Consensus sûr / démontré | **B : À RISQUE — déterministe et convergent, mais finalité Stable manipulable (W11)** |
| C. Sécurité Sybil démontrée | **C : NON DÉMONTRÉE — identité gratuite, poids structurel** |
| D. Prêt pour cérémonie V3 (code) | **D : PRÊT — tests, harnais, spec, menaces et whitepaper v2 documentés ; cérémonie planifiée, non exécutée (V3_TESTNET_CEREMONY_PLAN.md)** |
| E. Décision de spécification | **E : OPTION A RATIFIÉE (2026-08-17)** — code = protocole, whitepaper v2 rédigé |

Verdict global : **🟡 TESTNET TECHNiquement PRÊT, COMMUNICATION ENCADRÉE** — le
code peut ouvrir un testnet V3 (cérémonie planifiée, non exécutée — voir
`V3_TESTNET_CEREMONY_PLAN.md`), et la communication est désormais cadrée par
`docs/PUBLIC_TESTNET_NOTICE.md` (aucune annonce « consensus pondéré/stake/
énergie » ; limitations W11 publiques). Ce statut n'est **pas** un 🟢 : il
restera conditionné par (a) l'exécution de la cérémonie, (b) l'audit crypto
externe, (c) le traitement de RUSTSEC-2026-0221.