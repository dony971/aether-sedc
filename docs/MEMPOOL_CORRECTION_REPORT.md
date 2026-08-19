# MEMPOOL CORRECTION REPORT — PHASE D

## Contexte

- **Verdict Phase C :** 🔴 STOP — croissance du réseau bloquée à ~1000 transactions,
  bootstrap bloqué (join@1100 stallé à 1012/1100 pendant 42 min, livelock, purges
  d'orphelins 173), faucet mort à l'échelle (oracle plafonné à 100).
- **Mandat Phase D :** corriger le mempool (leçon tirée : `pop_front` /
  `remove_transaction` jamais appelés → fenêtre pleine qui ne se vide JAMAIS),
  sans modifier le consensus (VQV, min-id, poids, pruning, ledger, finalité,
  genesis, règles de parents, émission, frais minimum). Preuve : reproduction
  avant modification = incidents INC-03/INC-04 de Phase C (voir PHASE_C_INCIDENTS.md).

## Cause racine (pré-correction)

1. Le mempool était une **fenêtre morte** : les transactions acceptées y étaient
   AJOUTÉES (`add_internal`, STEP 7 du processeur) après leur inclusion dans le
   DAG, mais JAMAIS retirées — `pop_front` et `remove_transaction` n'étaient
   appelés nulle part, le sémaphore n'était jamais acquis.
2. À 1000 transactions acceptées, la fenêtre était pleine ; toute nouvelle
   transaction valide faisait échouer STEP 7 → **rollback de l'ajout DAG**
   (`dag.remove_transaction`) → croissance arrêtée net.
3. Conséquences en cascade : bootstrap >1000 impossible, faucet pinné (oracle
   d'occupation à 100), et l'éviction fee-only (pseudo-économie) ne pouvait pas
   débloquer un flux saturé de frais ≥.

## Architecture après correction (ACCEPT → QUEUE → SELECT → PROCESS → INCLUDE → REMOVE)

### Accept (entonnoir `process_transaction`, rpc.rs)
1. **Gate pure** (PoW + signature, `TransactionProcessor::validate_pure`) — les
   ordures n'occupent jamais de slot de file (parité H1).
2. **Dédoublonnage DAG** (id déjà dans le DAG = doublon idempotent, compté).
3. **Gate économique** : oracle de frais ajusté par l'occupation de la file →
   `enqueue(tx, min_fee)`.
4. Persistance du tx en attente (Sled, arbre `Mempool`) + broadcast P2P.
5. Réponse `in_mempool` (compatible CLI/GUI).

### Queue (Mempool, rpc.rs)
- `enqueue` : frais → cache de rejets permanents (LRU borné 1000) → dedup file →
  capacité (backpressure TRANSIENTE — la file se vide au cycle suivant).
- TTL `MEMPOOL_TTL` = 15 min : un tx coincé (échec transitoire répété) expire et
  est compté (`mempool_expired`). Les nouvelles tentatives sont bornées.
- Sélection **déterministe** (`select_batch`) : frais DESC puis id ASC — deux
  nœuds dans le même état sélectionnent exactement le même lot. Parents manquants
  ≠ blocage de la file : le tx est sélectionné, process() signale l'orphelin, il
  est garé HORS de la file (résolu ensuite par le solveur d'orphelins).

### Process (drainer, node.rs + `drain_mempool`)
- Tâche dédiée sur **tous** les types de nœud (mineur, validateur, observateur),
  tick 150 ms, lot ≤ 100 (`MEMPOOL_DRAIN_BATCH`), `process()` avec `min_fee = 0`
  (le frais a déjà été payé à l'accept — le drainer ne peut pas s'auto-plafonner,
  les frais ne sont pas contournés : la gate d'accept refuse toujours les frais
  < minimum oracle).
- **STEP 7 du processeur réécrit** : `add_internal` + rollback DAG →
  `remove_transaction` (idempotent). **Une file pleine ne peut plus jamais
  annuler une inclusion DAG.**
- Dispositions par cycle, une seule par transaction :
  - `Ok` → inclus, retiré (`mempool_included`, `mempool_removed`) ;
  - `Orphan`/`MissingParent` → garé (`mempool_orphan_parked`), parents
    re-demandés P2P ; le solveur ré-accepte via l'entonnoir
    (`mempool_orphan_resolved`) ;
  - `DuplicateTransaction` → déjà dans le DAG = état terminal INCLUS ;
  - `SenderConflict`/`InvalidPoW`/`InvalidSignature`/`SenderPublicKeyMismatch`/
    `DoubleSpend`/`Overflow`/`InsufficientFee`/`InvalidNonce` → rejet permanent
    UNE fois + cache LRU borné (pas de boucle infinie) ;
  - `InsufficientBalance`/`Ledger`/`Dag`/`Persistence`/`Lock` → ré-inscription
    (re-tentatives bornées par le TTL).

### Inclusions et invariants (mandat §2-§5)
1. Même état → même lot candidat (frais DESC, id ASC).
2. Un tx à parents manquants ne bloque jamais la file (garé, hors file).
3. Retrait correct : après inclusion DAG, après résolution d'orphelin, après
   expiration ; les re-tentatives ne croissent jamais (TTL + cache + file bornée).
4. `MAX_MEMPOOL = 1000` **inchangé** — c'est désormais une borne de backpressure
   transitoire, plus jamais une impasse (le mandat interdit de l'augmenter).
5. Bootstrap : le chargement au démarrage ignore les tx déjà présentes dans le
   DAG et purge leurs copies périmées (auto-guérison des anciens répertoires de
   données — le pool "plein" persistant de l'ancienne version ne bloque plus rien).

## Observabilité (mandat §5/§13)

- Compteurs atomiques : `mempool_added / removed / included / rejected / expired /
  duplicate / orphan_parked / orphan_resolved` + `size / max_size / min_fee`.
- Nouvelle RPC `aether_getMempoolStats` (queue + compteurs).
- Log nœud toutes les 5 s : `🔻 Mempool | size=… added=… removed=… included=…
  rejected=… expired=… duplicate=… orphan=… resolved=… | drain_rate=…/s`.
- `/metrics` Prometheus : `aether_mempool_{size,added_total,removed_total,
  included_total,rejected_total,expired_total,duplicate_total,orphan_parked_total,
  orphan_resolved_total}`.

## Tests (mandat §7)

Unitaires (suite debug complète — 160 tests, 0 échec ; les M-tests lourds en
release — 3 tests, 0 échec) :

| Test | Charge | Garantie |
|---|---|---|
| M1 `test_m1_lifecycle_under_capacity` | 200 tx (< 1000) | cycle complet, compteurs cohérents (added == included == removed), file → 0 |
| M2 `test_m2_full_queue_transient_backpressure` | 1000 pleine | 1001ᵉ rejetée (backpressure), drain vide la file, nouvelles tx acceptées ; dedup file |
| M3 `test_m3_drain_1100_transactions` (release) | 1100 | non-régression obligatoire : le scénario exact qui a stallé la Phase C converge |
| M4 `test_m4_drain_2500_transactions` (release) | 2500 | pas de livelock, pas de croissance infinie, convergence complète |
| M5 `test_m5_drain_5000_transactions` (release) | 5000 | plafond de l'enveloppe : drain complet sous file de 1000 |
| `test_mempool_deterministic_selection` | — | même état → même lot (frais DESC, id ASC) |
| `test_mempool_ttl_expiry` | — | expiration TTL bornée + comptée |
| `test_mempool_reject_cache_bounded` | 1100 rejets | cache LRU ≤ 1000, id ancien réinscriptible, récent dédoublonné |
| `test_faucet_low_fee_revives_after_drain` | — | régression INC-05 : faucet rejeté file pleine (gate anti-spam) puis ACCEPTÉ après drain (oracle relâché) |
| Tests orphelins H1 adaptés | — | gate pure inchangée ; parking désormais effectué par le drainer (mémoire + Sled), cap respecté, résolution via entonnoir + drain |

Exécution : `cargo test --lib` (debug) + `cargo test --release --lib -- --ignored
drain_` (M3/M4/M5).

## Régressions (mandat §11)

- 160/160 tests debug (dont S1-S11, B4-1/2/3, batterie B1-B8, tests consensus) — 0 échec.
- M-tests lourds release — 0 échec.
- Aucun test modifié pour passer : les 3 tests orphelins adaptés reflètent le
  nouveau cycle CONTRACTUEL (parking par le drainer, statut honnête `InLocalDag`
  après inclusion — un tx inclus quitte la file par conception).
- `cargo fmt --check` ✓, `cargo clippy --lib` sans nouvelle alerte.

## Campagne réseau (mandat §15)

Rejouée à partir du binaire release de cette correction (commits `d5051ed` +
fixes de campagne, SHA256 final `153394F86EA613A5A57FF8D791D6C1DE2C03E99A4F4E95C423B3D5DCAFA6BFE2`).

### Fixes de campagne découverts pendant la Phase D

1. **Tempête de requêtes parents (`src/rpc.rs`, park_orphan)** : le drainer
   re-demandait les DEUX parents pour CHAQUE orphelin garé, immédiatement —
   tempête de GetData (une réponse par requête), affamant les vrais lots de
   sync : un joineur recevait seulement les ~500 premières tx, les racines
   n'arrivaient jamais, bootstrap livelocké à 0 tx. **Fix** : park_orphan ne
   requête plus rien ; le solveur d'orphelins possède les requêtes.
2. **Solveur d'orphelins (`src/rpc.rs`, process_orphans)** : ne collecte plus
   que les parents DUE (cooldown via `SyncContext::backoff_for`), en priorisant
   les jamais-demandés → rotation complète du set de parents (128/cycle) au lieu
   des mêmes 128 ; suppression du sleep 20 ms/requête (stallait le cycle drain).
3. **Cap d'inventaire (`src/p2p.rs`)** : `take(MAX_INV_ITEMS)` s'appliquait à
   l'inventaire BRUT du pair → toute tx au-delà de la 1000ᵉ invisible pour le
   joineur (diff vide, `sync_requested=0`, bootstrap bloqué à quelques tx du
   tip). **Fix** : le cap borne la REQUÊTE (le vrai diff) — un joineur tardif
   demande tout son manquant.

### Leçon opérationnelle (ports)

Les ports d'écoute des joineurs (50001-54001) tombent dans la plage éphémère
OS (49152-65535) : un socket SORTANT d'un pair peut s'y lier (collision
observée : éphémère de node5 sur 50001) et le bind du listener échoue
(10048/10013) — le nœud tourne alors SANS couche P2P (RPC + drainer vivants,
sync = 0, silencieux). Les joineurs Phase D utilisent donc 49002-49006
(p2p) / 49102-49106 (rpc), sous la plage éphémère.

### Résultats

- **Stage A — rampe 1100 (non-régression Phase C) : PASS (15/15).**
  Ramp 1100 atteinte (~3,5 tx/s, 8 générateurs parallèles), convergence 8/8,
  mempool after1100 : `size=0/1000 min_fee=1 added=1104 removed=1100
  included=1100 rejected=0 expired=0 dup=32 orphan=0 resolved=0`.
- **Stage B — join frais @1100 (node9) : PASS.** Empreintes identiques
  (h_txset/h_dag/h_tips/h_ledger/h_weights/supply). Mempool du joineur :
  `added=2184 removed=2184 included=1068 orphan=1116 resolved=1055` — cascade
  de résolution d'orphelins fonctionnelle (avant fix : livelock à 0).
- **Stage C — rampe 2500 + join frais @2500 (node10) : PASS.** Sync 0 → 2500
  en ~140 s (orphan_created=1641, resolved=1578) ; empreintes identiques ;
  drain : `added=1400 included=1400 removed=1400 size=0`.
- **Stage D — rampe 5000 + join frais @5000 (node11) : PASS — bootstrap 5000
  critique réussi.** Sync 0 → 5007 en ~340 s (orphan_created=2765,
  resolved=2751) ; empreintes identiques ; drain : `added=3908 included=3907
  size=0 rejected=0 expired=0`.
- **Stage E — faucet sous charge @5000+ : PASS.** Tx faucet acceptée et
  créditée (+100000000000 raw) ; convergence finale 11/11 empreintes
  identiques ; mempool final `size=0` ; **invariant zéro-émission delta=0**
  (somme des 16 adresses surveillées == genesis `1000000100000000000`, frais
  dirigés vers l'adresse de burn `ffff…`).
- Redémarrages §10 : boot-load 1069 tx persistées rejouées + ledger reconstruit
  (supply cohérent) ; les nodes 1-8 ont repris à 1100 exactement.

### Verdict campagne

Tous les seuils critiques du mandat §15 sont passés (drain correct, bootstrap
5000, joins @1100/2500/5000, faucet sous charge, invariants) → **🟡 CANARY À
REPRENDRE** (nouvelle RC, même mandat).

## Limites restantes

- `MAX_MEMPOOL = 1000` inchangé (backpressure) : au-delà, l'accept rejette
  transitoirement (le drainer libère au cycle suivant).
- L'oracle de frais reste un garde-fou d'accept (anti-spam) : en charge soutenue,
  les frais < oracle sont refusés à l'accept (pas de contournement des frais).
- Faucet : cooldown 60 s/adresse inchangé ; sous charge, le rejet d'accept est
  transitoire (retry client).
- Le drainer sélectionne 100 tx/cycle : à 5000 tx soutenues, la file oscille
  sous 1000 (backpressure) mais le débit d'inclusion suit le processeur
  (mesuré en campagne).
- W11/T1 (révélation de clé privée par marquage temporel) : toujours SÉVÈRE,
  non couvert par cette correction. Audit crypto externe toujours requis.