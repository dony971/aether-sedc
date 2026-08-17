# AETHER SEDC — Protocol Specification (v3)

Version du protocole : **P2P 3** (WEIGHT, 2026-08-17) — consensus DAG-append.
Ce document est la **référence normative** : une équipe indépendante doit pouvoir
implémenter un nœud interopérable SANS lire le code source ni deviner les règles.
Toute divergence entre ce document et le code est un bug à corriger.

---

## 1. Modèle général

- Registre **sans blocs, sans leaders** : les transactions sont des nœuds d'un
  DAG. Pas de récompenses de bloc, **émission zéro** après le genesis ; l'offre
  ne peut que décroître (fees brûlés).
- Le **DAG est la source de vérité** : le ledger (soldes + nonces) est dérivé du
  DAG et reconstruit depuis lui au démarrage.
- Unité : `1 AETH = 10^10 unités` (`UNITS_PER_AETH`). Supply genesis vivante :
  `10 AETH (founder) + 100 000 000 AETH (faucet)`. `MAX_SUPPLY = 2 × 10^18`
  (invariant défensif, jamais atteint).

## 2. Transaction

```
Transaction {
  id:           32 octets  (BLAKE3, voir §3)
  parents:      [32B; 2]   (deux parents ; [0;32]² = genesis virtuel)
  sender:       32 octets  (= les 32 premiers octets de la clé publique Ed25519)
  receiver:     32 octets
  amount:       u64
  fee:          u64        (>= 1 unité, brûlée vers FEE_BURN_ADDRESS = [0xFF;32])
  timestamp:    u64        (ms Unix)
  nonce:        u64        (Micro-PoW, voir §4)
  account_nonce:u64        (séquentiel par sender, anti-rejeu, voir §6)
  weight:       f64        (CALCULÉ par le nœud, jamais accepté en entrée ; exclu du hash)
  signature:    64 octets  (Ed25519 du hash de signature)
  public_key:   32 octets  (clé publique du sender)
}
```

Taille sérialisée minimum : 208 octets + variables. Sérialisation binaire
personnalisée (ordre des champs ci-dessus, longueurs préfixées) ; sur disque
(Sled) : **bincode 1.3** — le format sur disque dépend de l'ordre des champs de
la structure.

## 3. Hachages

- `id = BLAKE3(parents0 ‖ parents1 ‖ sender ‖ receiver ‖ amount_le ‖ fee_le ‖
  timestamp_le ‖ nonce_le ‖ account_nonce_le ‖ signature ‖ public_key)`.
  **`id` et `weight` exclus** : le poids n'a AUCUN effet sur l'identité d'une tx.
- Hash de signature : identique sans signature/public_key. `nonce` inclus → le
  minage précède la signature.
- Hash PoW (`calculate_pow_hash(nonce)`) : parents, sender, receiver, amount,
  fee, timestamp, nonce, account_nonce (sans signature ni clé).

## 4. Micro-PoW (anti-spam)

- **Difficulté fixe : 20 bits** (`default_difficulty`), vérifiée par le gate pur.
  N bits de poids fort nuls dans `BLAKE3(pow_hash fields)` — ~2^20 hachages en
  moyenne. Le module `AdaptiveDifficulty` (difficulté dynamique 8-24 bits)
  existe dans le code mais **n'est PAS utilisé en production** : il ne fait pas
  partie du protocole v3.

## 5. Genesis

- Un genesis **virtuel** `[0;32]` : aucune transaction genesis n'est stockée ;
  les transactions racines référencent `[0;32]²`. `GENESIS_HASH = [0;32]`.
- Ledger initial (adresses dérivées de clés publiques) :
  - founder `32252d…298b` → `10^11` unités (10 AETH)
  - faucet  `e880…1518` → `10^18` unités (100 000 000 AETH)
- `GENESIS_MESSAGE` : texte horodaté publié dans la binaire (preuve de date de
  lancement), modifié à chaque rotation.
- Le faucet n'est actif que si l'opérateur fournit `data_dir/faucet.key`
  (seed hex 64 caractères de la clé Ed25519 du faucet) ; sans ce fichier,
  `aether_faucet` renvoie une erreur.

## 6. Validation et acceptation

Pipeline de `process_transaction` (seule entrée mutante) :

1. **STEP 0 — résolution de conflit déterministe** : pour toute tx existante avec
   le même `(sender, account_nonce)`, le **plus petit `id` gagne** (comparaison
   lexicographique d'octets). Si le gagnant est la nouvelle tx : prune en
   cascade du sous-arbre perdant (ordre feuilles→racine, chaque ancêtre
   survivant perd exactement 1 par descendant retiré), purge du stockage
   persistant, rebuild du ledger depuis le DAG. Si la nouvelle tx perd :
   rejet `SenderConflict`. Le poids n'intervient JAMAIS dans cette décision.
2. **Gate pur** (sans état) : PoW 20 ✓, signature Ed25519 du hash de signature ✓,
   sender = clé publique ✓, `amount + fee` sans overflow ✓.
3. **Gate orphelin** : si un parent (non-genesis) est absent du DAG → la tx est
   **parquée** (memoire + Sled, plafond `MAX_ORPHANS = 50 000`) et les parents
   sont re-demandés en P2P. Re-tentée à chaque tx P2P acceptée et toutes les 10 s.
4. **Validation DAG** : id unique, parents présents, pas de conflit
   `(sender, account_nonce)`.
5. **Validation ledger** (min_fee = 1) : `balance(sender) ≥ amount + fee` ;
   `fee ≥ min_fee`. **`account_nonce` n'est PAS vérifié contre le ledger** (les
   nonces sont résolus de façon déterministe au niveau DAG — cf. §6 STEP 0) ;
   c'est volontaire pour éviter la divergence liée à l'ordre d'arrivée.
6. Application : ledger (débit sender, crédit receiver, fee → brûlé), nonce
   ledger = max(nonce, nonces du DAG), insertion DAG `add_transaction_validated`
   (poids = 1.0 + +1 pour chaque ancêtre), mempool, persistance. Rollback total
   sur erreur.

Nonce ledger lu via RPC = `max(account_nonce du sender dans le DAG) + 1`
(`get_account_nonce`).

## 7. Poids et statuts

- **Poids = taille du sous-arbre** : `weight(tx) = 1 + |descendants(tx)|`.
  Maintenu incrémentalement par le DAG : +1 à chaque ajout pour tous les
  ancêtres (marche ascendante anti-doublon, genesis exclu), −1 à chaque retrait,
  −1 par descendant pruné pour chaque ancêtre survivant (ordre de prune
  feuilles→racine).
- Le poids est **dérivé de la structure** : deux nœuds ayant le même ensemble de
  txs et les mêmes edges ont les mêmes poids (indépendant de l'ordre d'arrivée).
- Statuts (`determine_transaction_status`, par nœud) :
  - `Unconfirmed` : dans le DAG, < 3 références et poids < 5.0
  - `Confirmed` : ≥ 3 références directes
  - `Stable` : poids ≥ 5.0 — `practically_final`
  - `Finalized` : **inatteignable** (nécessiterait un mécanisme de votes VQV
    non implémenté) — à ne pas annoncer
  - `Orphan`/`InMempool`/`Unknown` : statuts locaux hors DAG.
- Aucun reorg ni finalité probabiliste : le DAG local est accepté tel quel ; les
  conflits sont résolus par min-id (déterministe, identique sur tous les nœuds).

## 8. Sélection des parents

- `aether_getTips` renvoie les txs sans enfants. Le client CLI prend les **deux
  premiers** de la réponse (parsing strict ; réponse malformée = erreur, jamais
  de repli silencieux vers genesis — sauf réponse vide : parents `[0;32]²`).
- Côté nœud (`ParentSelectionAlgorithm`) : marche aléatoire depuis le genesis,
  ~10 pas, transition vers un enfant avec probabilité ∝ son poids ; tips de
  moins de 60 s. Deux parents distincts, refus si la paire est déjà utilisée.
  (Cette sélection sert l'inventaire tips P2P ; le CLI n'utilise pas la marche
  aléatoire mais l'ordre de `getTips`.)

## 9. P2P

- Version de protocole **3** dans l'en-tête de chaque frame (`frame[4]`) : les
  nœuds v2/v3 ne se connectent pas entre eux → la rotation genesis est
  obligatoire au passage v2→v3.
- Pas d'identifiant réseau séparé (`network_id`) : l'identité du réseau est
  (version P2P + hachages du genesis + `GENESIS_MESSAGE`).
- Sync : inventaire de hachages → demandes par lots → insertion validée ;
  re-demande des parents manquants ; cycle 10 s ; rebuild complet au boot
  (résolution canonique min-id sur le résidu disque, insertion topologique,
  rebuild tips, rebuild ledger).
- Bootnode facultatif (`--bootnode`), reconnect avec backoff ; aucun timeout de
  connexion côté pair (durcissement H2 documenté).

## 10. Stockage

- Sled ; transactions, orphelins, mempool persistés en bincode 1.3.
- Pas de flush par transaction (P4) : flush périodique (cycle 10 s du nœud +
  auto-flush Sled + flush d'arrêt) → une perte sur kill brutal est bornée à un
  cycle ; le boot reconstruit de toute façon le ledger depuis le DAG.
- Pas de pruning temporel : les txs ne sont retirées que par la résolution de
  conflit (perdant + descendants).

## 11. RPC (JSON-RPC 2.0, HTTP)

Méthodes : `aether_sendTransaction`, `aether_getBalance`, `aether_getAccountNonce`,
`aether_getTips`, `aether_getDagStats`, `aether_getDagGraph` (limite 500-5000),
`aether_getTransactionStatus`, `aether_getRecentTransactions` (≤ 50),
`aether_getTransactionHistory`, `aether_faucet`, `aether_getTransactionSnapshot`.

- Limiteur : **200 requêtes / 10 s par méthode** (global) + **40 requêtes / 10 s
  par (IP, méthode)**. Taille max de tx sérialisée : 1 MiB.
- Faucet : 10 AETH par requête, fee 1, **1 requête / 60 s / adresse**.
- Formats canoniques : ids/adresses en hex minuscule 64 caractères (jamais de
  tableaux numériques).

## 12. Paramètres (tous fixes en v3)

| Paramètre | Valeur |
|---|---|
| P2P_PROTOCOL_VERSION | 3 |
| Difficulté PoW | 20 bits (fixe) |
| min_fee | 1 unité |
| MAX_ORPHANS | 50 000 |
| MAX_RPC_TX_SIZE | 1 MiB |
| Rate limit méthode | 200 / 10 s |
| Rate limit (IP, méthode) | 40 / 10 s |
| Faucet | 10 AETH / 60 s / adresse |
| Seuil Confirmed | ≥ 3 références |
| Seuil Stable | poids ≥ 5.0 |
| Tips fraîcheur | ≤ 60 s |
| RPC getDagGraph limit | 500 (max 5000) |
| RPC getRecentTransactions | 50 max |

## 13. Propriétés garanties

- **Déterminisme** : l'état (DAG + ledger + poids) est une fonction pure de
  l'ensemble des txs acceptées, indépendante de l'ordre d'arrivée (min-id,
  rebuild canonique, poids structurel).
- **Double-dépense** : au plus une tx par `(sender, account_nonce)` ; le perdant
  et ses descendants sont prunés partout (règle identique au live et au boot).
- **Convergence** : vérifiée par le harnais S1-S10 (empreintes SHA-256
  txset/edges/tips/ledger/poids identiques sur tous les nœuds).
- **Invariants économiques** : supply ≤ genesis, fees brûlés, pas de mint.

## 14. Limites protocolaires (ne PAS annoncer au-delà)

- Le poids est **purement structurel** : inflatable à coût quasi nul (5 txs à
  fee minimale atteignent `Stable`, cf. test W11 et THREAT_MODEL.md).
- Pas de stake, pas d'énergie, pas de réputation, pas de finalité probabiliste
  ni de seuil dynamique : ces concepts du whitepaper v1 **ne sont pas** le
  protocole implémenté (voir RAPPORT_FINAL_TECHNIQUE.md §7).
- `Finalized` inatteignable ; `Stable` ne garantit pas l'irréversibilité : un
  conflit min-id plus petit peut encore pruner un sous-arbre.