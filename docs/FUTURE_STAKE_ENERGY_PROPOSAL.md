# Proposition stake/énergie — FUTUR, NON NORMATIF (2026-08-17)

**Statut : DOCUMENT DE RECHERCHE. AUCUN caractère normatif. AUCUN code modifié
pour cette proposition. Le protocole v3 (P2P 3, `PROTOCOL_SPECIFICATION.md`)
reste inchangé et n'utilise ni stake ni énergie.**

---

## 1. Pourquoi le whitepaper historique parlait de stake/énergie

La version v1 (`AETHER_SEDC_Whitepaper.md`) décrivait un « Heavy Subgraph
Consensus » avec un poids = f(stake, énergie, réputation), une finalité
probabiliste, des seuils dynamiques et une sécurité Sybil par le stake. Ces
descriptions provenaient de la **conception cible**, jamais d'une
implémentation : le code a toujours été un DAG-append simple sans champs
stake/energy dans `Transaction`. Le whitepaper v2 (§17-18) classe ces concepts
**NON IMPLEMENTED / FUTURE**.

## 2. Pourquoi ce mécanisme n'existe pas dans v3

- `Transaction` n'a aucun champ stake/énergie ; `compute_hash()` ne les connaît
  pas — les ajouter changerait l'identité des transactions et casserait le
  protocole (nouvelle version P2P, nouvelle cérémonie).
- La résolution de conflit est **min-id déterministe** (STEP 0) ; le poids est
  structurel (taille de sous-arbre) et n'intervient jamais dans un conflit.
- L'émission est zéro : il n'existe aucun mécanisme d'acquisition/consommation
  d'énergie comme preuve de travail économique.
- Le réseau v3 est un testnet expérimental : ajouter une économie du stake sans
  analyse créerait une fausse sécurité.

## 3. Quel problème chercherait à résoudre un stake/énergie

La menace principale est **T1** (THREAT_MODEL.md) : `Stable` (poids ≥ 5.0) est
atteignable avec ~5 transactions à coût quasi nul (test W11 :
`test_w11_weight_inflation_attack`). Un mécanisme à engagement économique
viserait à :

1. Rendre l'inflation de poids coûteuse (chaque unité de poids « achetée »).
2. Donner à `Stable` une interprétation de sécurité (coût de réversion).
3. Ralentir le spam au-delà du PoW 20 (coût marginal par identité).

## 4. Modifications de consensus nécessaires (si un jour envisagées)

- Nouveau champ (ou dérivation) de poids : stake verrouillé / énergie prouvée ;
  exclusion du hash inchangée ou nouvelle version.
- Règle de conflit : min-id remplacé ou complété par un critère pondéré →
  nécessite de démontrer la convergence **avant** tout déploiement (le min-id
  garantit aujourd'hui une convergence pure ; tout critère pondéré doit être
  une fonction pure du DAG, identique sur tous les nœuds, indépendante de
  l'ordre d'arrivée).
- Émission/récompenses éventuelles : contradictoires avec l'émission zéro et
  l'invariant `MAX_SUPPLY` → décision économique séparée.
- Nouvelle version P2P (v4+) + rotation genesis : toute modification du poids
  change les statuts et la signification des données stockées.

## 5. Nouveaux risques introduits (non exhaustif)

- **Concentration** : le stake favorise les gros porteurs → centralisation de
  la résolution de conflit.
- **Coût de verrouillage / liquidité** : lockups, slashing, gouvernance.
- **Double-spend par le poids** : si le poids gagne les conflits, un attaquant
  suffisamment riche peut reverter (nouvelle forme de T1, plus coûteuse mais
  potentiellement catastrophique).
- **Complexité de convergence** : toute règle non pure (dépendante du temps,
  de l'historique de verrouillage) peut réintroduire des divergences du type
  de celles corrigées en V-20…V-23.
- **Attaque sur l'énergie** : sans mécanisme de difficulté renouvelable,
  l'« énergie » devient un simple coût CPU pré-payé (équivalent au PoW actuel).

## 6. Tests nécessaires avant toute adoption

- Extension de W1-W12 : inflation pondérée, convergence sur conflits pondérés,
  independence de l'ordre d'arrivée, rebuild de boot avec stake, divergence
  impossible (déjà couverte par `h_weights` — à adapter).
- S1-S11 sur le nouveau mécanisme ; benchmark de charge ; fuzzing.
- Preuve de convergence formelle (ou au minimum modèle de simulation multi-
  nœuds avec partitions, comme V-22).

## 7. Pourquoi ne pas l'ajouter maintenant

1. Le testnet v3 doit d'abord être observé : T1 est quantifié, documenté,
   **assumé** (WHITEPAPER_V2 §16) — pas de faux sentiment de sécurité.
2. L'ajout imposerait une **rupture de protocole** (nouvelle version P2P,
   nouvelle cérémonie) : coût élevé pour un bénéfice non démontré.
3. Aucun besoin produit identifié à ce stade (testnet, pas de valeur).
4. Le min-id + PoW + fee couvrent déjà la convergence et le spam quantitatif
   pour un usage de test.

**Décision attendue :** cette proposition reste ouverte ; elle ne sera activée
que par une décision produit explicite, accompagnée de l'analyse §4-§6, dans
une phase ultérieure. Rien ne doit être ajouté « en passant ».