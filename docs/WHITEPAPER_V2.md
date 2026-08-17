# Aether — Whitepaper v2 (2026-08-17)

**Statut : document de référence du protocole v3 actuellement implémenté.**
La référence normative est `docs/PROTOCOL_SPECIFICATION.md` ; en cas de
contradiction, la spécification et le code priment sur ce document.
La version v1 (`AETHER_SEDC_Whitepaper.md`) est **obsolète** : elle contient des
concepts NON IMPLEMENTÉS (voir §17 et §18). Ce document décrit uniquement ce qui
existe dans le code, afin que le comportement du nœud soit prévisible à la
lecture.

Réseau : testnet expérimental — **aucune valeur économique garantie**.

---

## 1. Vue d'ensemble

Aether est un registre distribué **sans blocs** : les transactions sont les
nœuds d'un **DAG** (graphe acyclique dirigé). Il n'y a ni mineurs, ni validateurs
désignés, ni leaders : chaque nœud valide localement et diffuse. Le consensus
n'est pas probabiliste : il est une **règle déterministe de convergence** — deux
nœuds ayant accepté les mêmes transactions arrivent au même état.

Éléments clés :

- **Émission zéro** : l'offre est fixée au genesis et ne peut que décroître
  (frais brûlés).
- **Micro-PoW** : difficulté fixe, anti-spam quantitatif (pas de sécurité
  économique).
- **Poids structurel** : le poids d'une transaction = taille de son sous-arbre.
  Il participe à l'affichage des statuts, **pas** au choix des conflits.
- **Min-id** : règle de convergence pour les double-dépenses.
- **Faucet** : distribution de test (10 AETH / 60 s / adresse).

## 2. Le DAG

- Chaque transaction référence **exactement 2 parents** (`[0;32]²` pour les
  racines). C'est l'arête du DAG.
- Le genesis est **virtuel** : `[0;32]`, aucune transaction stockée.
- Une transaction sans enfant est un **tip** (sélectionnée par le RPC et par la
  marche aléatoire).
- Il n'existe ni blocks, ni slots, ni finalisation par tour de voix.

## 3. Transactions

Champ par champ (sérialisation binaire, ~208 octets minimum) :

| Champ | Taille | Rôle |
|---|---|---|
| `id` | 32 B | BLAKE3 du contenu (§3.1) — **exclut `weight`** |
| `parents` | 2 × 32 B | 2 parents dans le DAG (ou genesis) |
| `sender` | 32 B | 32 premiers octets de la clé publique Ed25519 |
| `receiver` | 32 B | destinataire |
| `amount` | u64 | montant en unités |
| `fee` | u64 | ≥ 1 unité, **brûlée** |
| `timestamp` | u64 | ms Unix |
| `nonce` | u64 | nonce Micro-PoW |
| `account_nonce` | u64 | séquentiel par sender (anti-rejeu) |
| `weight` | f64 | **calculé par le nœud** — toute valeur émise est écrasée |
| `signature` | 64 B | Ed25519 |
| `public_key` | 32 B | clé du sender |

Unités : `1 AETH = 10^10 unités`.

### 3.1 Identité

`id = BLAKE3(parents0 ‖ parents1 ‖ sender ‖ receiver ‖ amount ‖ fee ‖ timestamp
‖ nonce ‖ account_nonce ‖ signature ‖ public_key)`. Le hash de signature exclut
signature et clé publique ; le hash PoW exclut signature, clé publique et
poids. Le poids **n'a aucun effet sur l'identité** : il est dérivé, jamais
signé.

## 4. Micro-PoW

- **Difficulté fixe : 20 bits de zéro de tête** sur BLAKE3 du hash PoW (~2²⁰
  hachages en moyenne par transaction).
- Rôle : rendre le spam coûteux en CPU et quantifier la charge. Ce n'est **pas**
  une sécurité économique : le coût est un calcul, pas un actif.
- La difficulté **adaptative** (`AdaptiveDifficulty`, 8-24 bits) existe comme
  module **non appelé** : **NON ACTIVE** (voir §17).

## 5. Sélection des parents

- Côté client : `aether_getTips` → 2 premiers tips (parents genesis si liste
  vide ; réponse malformée = erreur, jamais de repli silencieux).
- Côté nœud (sélection P2P/tips) : **marche aléatoire** depuis le genesis,
  ~10 pas, transition vers un enfant avec probabilité ∝ son **poids** ; tips
  frais (< 60 s). Deux parents distincts.

## 6. Validation et consensus

Pipeline d'acceptation (une seule entrée mutante) :

1. **STEP 0 — résolution de conflit déterministe** : pour chaque tx existante
   partageant le même `(sender, account_nonce)`, le **plus petit `id`
   (lexicographique) gagne**. Le perdant et tout son sous-arbre sont **prunés**
   (voir §9), le ledger reconstruit. **Le poids ne joue aucun rôle ici.**
2. **Gate pur** : PoW 20 ✓, signature Ed25519 ✓, sender = clé publique ✓,
   pas d'overflow ✓.
3. **Gate orphelin** : parent absent → tx **parquée** (plafond 50 000),
   re-tentée périodiquement.
4. **Gate DAG** : id unique, parents présents, pas de conflit
   `(sender, account_nonce)`.
5. **Gate ledger** : `balance ≥ amount + fee`, `fee ≥ 1`. L'`account_nonce`
   **n'est pas** vérifié contre le ledger (règle volontaire, anti-divergence ;
   cf. spécification §6).
6. Application : ledger (débit, crédit, burn), poids (voir §7), persistance.
   Rollback total sur erreur.

Consensus = convergence déterministe (mêmes txs → même DAG → même ledger →
mêmes poids). Pas de fork réversible, pas de finalité par probabilité.

## 7. Poids (weight)

**Définition : `weight(tx) = 1 + nombre de descendants(tx)`** — la taille de son
sous-arbre. C'est une propriété **purement structurelle** du DAG.

- Maintenu incrémentalement : +1 aux ancêtres à l'ajout, −1 aux ancêtres à la
  suppression, −1 par descendant pruné aux ancêtres survivants (prune en ordre
  feuilles→racine).
- Indépendant de l'ordre d'arrivée : deux nœuds avec le même DAG ont les mêmes
  poids.
- **Le poids n'est PAS un stake, PAS de l'énergie, PAS une réputation** : il ne
  peut pas être acheté, brûlé ou accumulé hors du DAG. Il ne détermine pas les
  conflits.
- Le champ `weight` émis par un client est **écrasé** par le nœud.

## 8. Confirmation et finalité

Statuts locaux (`determine_transaction_status`) :

| Statut | Condition | Lecture |
|---|---|---|
| `Unconfirmed` | dans le DAG, < 3 références, poids < 5.0 | reçu |
| `Confirmed` | ≥ 3 références directes | visible par le réseau |
| `Stable` | poids ≥ 5.0 | `practically_final` |
| `Finalized` | **inatteignable** | nécessiterait des votes VQV non implémentés |

`practically_final = Stable | Finalized`. **Aucun statut n'est irréversible en
toute rigueur** : un conflit min-id plus petit peut encore pruner un sous-arbre.
Voir les limites de sécurité §16 (W11).

## 9. Pruning

- Une transaction n'est retirée que si elle (ou un ancêtre) **perd un conflit**
  min-id : prune en cascade du sous-arbre perdant, purge du stockage, rebuild
  du ledger.
- Ordre de retrait : **feuilles → racine** (chaque ancêtre survivant perd
  exactement 1 par descendant retiré).
- Pas de pruning temporel ; rien n'expire.

## 10. Ledger

- Dérivé du DAG (source de vérité), **reconstruit au boot**.
- Soldes : debit du sender, crédit du receiver, fee → `FEE_BURN_ADDRESS`
  (`[0xFF;32]`), émission zéro.
- Nonces : le nonce ledger d'un sender = `max(account_nonce du sender dans le
  DAG) + 1` (RPC `getAccountNonce`).

## 11. P2P et synchronisation

- Version de protocole **3** dans chaque frame : un nœud v2 ne peut pas se
  connecter à un nœud v3 (séparation des réseaux ; pas de `network_id` séparé —
  l'identité du réseau = version P2P + genesis).
- Synchronisation : inventaire de hachages → lots → validation → insertion ;
  parents manquants re-demandés ; cycle 10 s ; reconnect avec backoff.
- Boot : résolution canonique min-id du résidu disque, insertion topologique,
  rebuild tips + ledger.

## 12. Wallet

- Ed25519 ; adresse = 32 premiers octets de la clé publique (hex minuscule
  64 caractères).
- `wallet.key` : seed hex 64 caractères (clé privée). La seed peut aussi être
  passée par argument de ligne de commande (usage à éviter sur machine partagée).
- Pas de multisig, pas de hardware wallet (recherches futures).

## 13. Émissions et frais

- **Émission zéro** : aucune récompense, aucun mint, aucun halving. L'offre
  totale est fixée au genesis : `10 + 100 000 000 = 100 000 010 AETH`.
- Frais : **minimum 1 unité**, **brûlés** (jamais versés à des mineurs —
  il n'y en a pas).
- Offre décroissante sous charge (burn).

## 14. Genesis

- Virtuel `[0;32]` ; balances initiales : founder `10^11` unités, faucet
  `10^18` unités. `MAX_SUPPLY = 2 × 10^18` (invariant défensif).
- `GENESIS_MESSAGE` : texte horodaté compilé dans la binaire (preuve de date).
- Faucet actif **seulement si** `data_dir/faucet.key` existe (seed de la clé
  faucet) ; sinon erreur. Limite : 10 AETH / 60 s / adresse.

## 15. Interface

- JSON-RPC 2.0 HTTP : envoi, balance, nonce, tips, stats, graph (500-5000),
  statut, historique, faucet.
- Rate limits : 200 req / 10 s par méthode + 40 req / 10 s par (IP, méthode).
- Taille max : 1 MiB.

## 16. Security limitations (à lire avant toute utilisation)

1. **Le poids n'est pas une sécurité économique — W11 (démontré par test).**
   `Stable` est atteignable avec **~5 transactions auto-référencées** : coût
   mesuré = 5 × (fee minimale `10⁻¹⁰` AETH + ~2²⁰ hachages BLAKE3), soit
   ~5 unités et quelques millions de hachages (~1-2 s CPU sur un poste
   moderne). La finalité apparente n'engage **aucun actif** de l'attaquant.
2. **Pas de résistance Sybil démontrée** : les identités sont gratuites ; le
   Micro-PoW 20 + fee minimale ralentissent le spam sans le rendre coûteux.
3. **Pas de sécurité par stake ou énergie** : ces mécanismes n'existent pas
   dans v3 et ne doivent pas être présentés comme actifs (voir §17).
4. **Min-id** : règle de convergence, pas de sécurité ; un attaquant peut
   chercher un nonce donnant un id plus petit que la tx concurrente (avantage
   a priori sur les conflits d'arrivée).
5. **Aucun audit cryptographique externe** n'a été réalisé (Ed25519, BLAKE3,
   PoW, échange P2P chiffré).
6. **Finalité relative** : `Stable` n'est pas irréversible (un min-id plus
   petit peut pruner).
7. Risques transport documentés séparément : `docs/THREAT_MODEL.md` (T1 SÉVÈRE
   = inflation de poids, T2-T6) et `docs/AUDIT_ARCHITECTURE.md` (H1-H11).

## 17. Future protocol research (NON ACTIF en v3)

Concepts du whitepaper v1 **non implémentés**, listés pour la transparence —
ils ne sont **pas** des garanties du protocole actuel :

- **Supply 21 M + halving + récompenses** : inexistants ; l'offre v3 est
  fixe au genesis et décroît par burn. Proposition séparée :
  `docs/FUTURE_STAKE_ENERGY_PROPOSAL.md`.
- **Consensus pondéré par stake/énergie/réputation** : inexistant en v3 ; la
  proposition (non normative) détaille les changements de consensus, risques et
  tests nécessaires avant toute adoption.
- **Difficulté adaptative** : module présent mais **jamais appelé** ; réactiver
  demanderait une nouvelle version de protocole et une cérémonie.
- **Finalité probabiliste / VQV** : non implémentée ; `Finalized` est
  inatteignable.

## 18. Classification documentaire

Aucune ambiguïté — chaque affirmation du corpus documentaire est classée :

| Concept | Statut | Où |
|---|---|---|
| DAG blockless, 2 parents | **ACTIVE** | §§2-5 |
| Micro-PoW 20 bits | **ACTIVE** | §4 |
| Difficulté adaptative | **NON IMPLEMENTED** | §17 |
| Poids = taille du sous-arbre | **ACTIVE** | §7 |
| Poids = stake/énergie | **REMOVED** | §16.3, §17 |
| Résolution de conflit min-id | **ACTIVE** | §6 |
| Résolution par poids/score (« Heavy Subgraph ») | **REMOVED** | §6, §16 |
| Confirmed (≥ 3) / Stable (≥ 5.0) | **ACTIVE** | §8 |
| Finalité probabiliste / `Finalized` | **NON IMPLEMENTED** | §8, §17 |
| Pruning feuilles→racine | **ACTIVE** | §9 |
| Ledger dérivé du DAG, rebuild boot | **ACTIVE** | §10 |
| P2P v3, sync inventaire 10 s | **ACTIVE** | §11 |
| Wallet Ed25519 | **ACTIVE** | §12 |
| Émission zéro, burn, pas de 21M | **ACTIVE** | §13 |
| 21M / halving / récompenses | **FUTURE** | §17 |
| Genesis virtuel, founder + faucet | **ACTIVE** | §14 |
| Faucet 10 AETH / 60 s | **ACTIVE** | §14 |
| RPC + rate limits | **ACTIVE** | §15 |
| Résistance Sybil | **NON IMPLEMENTED** (non démontrée) | §16.2 |
| Stake-secured / energy-secured | **REMOVED** | §16.3, §17 |

## 19. Conformité

Ce document est fidèle au code v3 (P2P 3) et à `PROTOCOL_SPECIFICATION.md`.
Une implémentation basée sur ce document et la spécification produit le même
comportement que le code : mêmes règles d'acceptation, mêmes statuts, mêmes
poids, mêmes empreintes d'état. Toute divergence constatée doit être signalée
comme bug documentaire.