# AETHER SEDC — Modèle de Menaces (v3, 2026-08-17)

Analyse des menaces sur le protocole **réellement implémenté** (P2P v3, DAG +
poids structurel, min-id). Ce document remplace les hypothèses du whitepaper v1
(stake/énergie) par l'analyse du code. Priorités : les menaces qui touchent le
consensus et la finalité.

---

## T1 — Inflation du poids / fausse « finalité Stable »  [SÉVÈRE, DÉMONTRÉE]

**Description.** Le poids = taille du sous-arbre. Un attaquant contrôle `n`
adresses (aucun coût d'identité, pas de stake). En 5 txs auto-référencées
(chaîne : chaque tx pointe la précédente, dont la racine 2× genesis), chaque
transaction atteint le seuil `Stable` (poids ≥ 5.0) → `practically_final`.

**Coût réel de l'attaque (mesuré par le test `test_w11_weight_inflation_attack`) :**

| Élément | Coût |
|---|---|
| 5 paires de clés Ed25519 | ~0 (µs) |
| Fee minimale × 5 | 5 unités = 5 × 10⁻¹⁰ AETH |
| Micro-PoW 20 bits × 5 | ~5 × 2²⁰ ≈ 5,2 M hachages BLAKE3 (~1-2 s CPU) |

**Impact.**
- `Stable` n'a **aucune valeur de garantie** : il ne certifie ni rareté
  d'attaque, ni engagement économique, ni quorum.
- Le poids ne participe **pas** au choix du vainqueur de conflit (min-id
  uniquement) : la victoire ne s'achète pas avec du poids.
- Un poids gonflé peut orienter la sélection des parents (marche ∝ poids) et
  les stats affichées (`aether_getDagStats`).
- T1 s'applique aussi à l'accent mis sur « Heavy Subgraph » : l'implémentation
  n'a pas de sous-graphe « lourd » ni de consensus pondéré.

**Mitigations actuelles.**
- Le champ `weight` n'est **pas** contrôlable par l'émetteur : écrasé par
  `add_transaction_validated` (vérifié par W11 partie 2).
- Le PoW (20 bits) + fee minimale rendent le spam *bruyant*, sans le rendre
  coûteux.
- `Finalized` est inatteignable ; personne ne doit annoncer une finalité
  cryptographique.
- Limitation **assumée publiquement** : `WHITEPAPER_V2.md` §16.1 et
  `PUBLIC_TESTNET_NOTICE.md` point 5. **La sévérité SÉVÈRE est conservée** :
  le fait que le testnet fonctionne ne réduit pas la criticité de T1.

**Recommandations (hors périmètre v3, à valider produit).** Voir §7 — options
pondération par stake, énergie, ou abandon de la notion de poids stable.

---

## T2 — Manipulation de la résolution de conflit (min-id)  [MODÉRÉ]

**Description.** Le vainqueur d'un double-spend `(sender, account_nonce)` est le
plus petit `id` = BLAKE3(contenu + nonce PoW). Un attaquant ne peut pas choisir
librement son id sans casser PoW/signature, mais peut **brute-forcer le nonce
au-delà de la difficulté** : trouver un nonce donnant un id avec k bits de poids
fort nuls au lieu de 20 (coût 2^k) — puisqu'il peut soumettre SA tx avant la
tx victime (concurrence d'arrivée) et gagner de façon déterministe.

**Impact.** Attaquant a priori (`nonce` choisi en connaissance du contenu) sur
les conflits concurrents ; pas d'impact sur les txs non conflictuelles.

**Mitigations.** Conflits rares en pratique (nonce = max+1, usage normal) ;
aucune mitigation protocolaire au-delà du PoW 20. Documenter que min-id est une
règle de convergence, pas une sécurité.

---

## T3 — Faible coût d'identité (Sybil généralisé)  [MODÉRÉ]

**Description.** Pas de barrière d'entrée : un attaquant crée autant de clés
qu'il veut. Conséquences protocolaires : (a) multi-comptes pour faucet farming
(60 s/adresse contournable), (b) amplification du spam au-dessus du PoW nominal
— le gate PoW est global, pas par identité, (c) un seul nœud peut saturer le
mempool/les files P2P d'un pair.

**Mitigations.** PoW 20, fee minimale, orphelins plafonnés (50 000), rate limits
RPC par IP, faucet par adresse.

---

## T4 — Confusion/erreurs de finalité côté client  [MODÉRÉ]

**Description.** `Stable` (poids ≥ 5.0) est affiché comme « final » par le client
et l'explorer alors qu'un conflit min-id plus petit peut pruner le sous-arbre.
`Finalized` n'est jamais produit. Les messages « Heavy Subgraph Consensus » /
« stake-secured » du whitepaper v1 peuvent laisser croire à des garanties
inexistantes.

**Mitigations.** Ce document + RAPPORT_FINAL_TECHNIQUE.md §7 ; interdiction de
communication marketing sur stake/énergie ; le CLI ne doit pas libeller
`Stable` = irréversible.

---

## T5 — Divergence de poids entre nœuds  [RÉGRESSÉ, CORRIGÉ]

**Description.** `prune_subtree` supprimait racine d'abord : la marche ascendante
d'un descendant s'arrêtait sur un parent déjà retiré → ancêtres survivants
sous-décrémentés → poids trop élevés, différents selon l'historique de chaque
nœud (découvert par `test_w3_weight_decreases_on_removal`).

**Statut : CORRIGÉ** — retrait en ordre feuilles→racine (parents des survivants
toujours présents au moment de leur marche). Vérifié par la campagne W1-W12 et
l'empreinte `h_weights` du harnais (identique sur tous les nœuds, 28/28 PASS).

---

## T6 — Réseau / transport  [documentés AUDIT H2-H7]

- H2 : aucun timeout P2P par pair (MEDIUM) — un pair muet gèle la file.
- H3 : scans RPC O(DAG) sans pagination — bornés par rate limit (MEDIUM).
- H4 : pas de `network_id` séparé (MEDIUM) — l'identité réseau = version P2P +
  genesis ; un clone du genesis + version = même réseau.
- H5 : cooldowns faucet sans éviction mémoire (LOW).
- H6 : repli CLI silencieux vers parents genesis sur réponse vide (LOW).
- H1 (orphelins sans gate PoW) : CORRIGÉ en v2 (validation complète à
  l'insertion orpheline).

---

## Grille de criticité (résumé)

| # | Menace | Séverité | Statut | Preuve |
|---|---|---|---|---|
| T1 | Inflation de poids → Stable factice | SÉVÈRE | **Non mitigeable en v3** | W11 |
| T2 | Avantage a priori min-id (nonce) | MODÉRÉ | Documenté | W6/W7 |
| T3 | Sybil / faucet farming / spam | MODÉRÉ | Partiel (PoW+fee) | W11, W12 |
| T4 | Fausse finalité communiquée | MODÉRÉ | Doc + interdiction | — |
| T5 | Divergence poids au prune | RÉGRESSÉ | **CORRIGÉ** | W3, harnais |
| T6 | Transport / RPC / orphelins | LOW-MED | V2/V3 + docs | AUDIT H1-H7 |

**Conclusion.** Le protocole est **déterministe, convergent et résistant aux
double-dépenses** (min-id), mais sa notion de finalité (`Stable` via poids) est
**purement structurelle et manipulable à coût quasi nul**. Aucune publication
publique ne doit revendiquer une sécurité par stake/énergie/reputation tant que
T1 n'est pas traité (proposition §7 de RAPPORT_FINAL_TECHNIQUE.md) ou que le
whitepaper n'est pas réécrit fidèlement.