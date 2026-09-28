# AETHER — Roadmap confidentialité réseau (Phase 2E et au-delà)

**Statut : `2E_ROADMAP = COMPLETE` (la roadmap est rédigée) ·
`2E-A = IMPLEMENTED` · `2E-B … 2E-E = PROPOSED`**

> **Ce document reste un document de planification. Seule l'étape 2E-A a été
> livrée, par un commit dédié (`phase2: harden network metadata privacy`).**
>
> Les étapes 2E-B à 2E-E restent des **propositions**. Aucune n'est engagée,
> aucune n'a commencé, et le passage d'une étape à l'autre exige une décision
> explicite — il ne se fait pas automatiquement.
>
> Détail et preuves de ce qui a réellement été codé (et de ce qui ne l'a pas
> été) : `docs/AETHER_PHASE2_METADATA_HARDENING.md`.

Branche : `dev/phase2-decentralized-network` · HEAD précédent `c9c44d0 phase2: add peer self-healing`
RELEASE `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` (inchangée)
`2E_CODE_CHANGES = 2E-A ONLY` · `2E_COMMIT = phase2: harden network metadata privacy` · `DEPLOYMENT = NONE`

Entrées de cette roadmap :

* `docs/AETHER_PHASE2_PRIVACY_THREAT_MODEL.md` — étapes 1-8 et 15 de l'audit.
* `docs/AETHER_TRANSPORT_COMPARISON.md` — étapes 9-12.

---

## 1. Séquence proposée, et pourquoi elle diffère de l'exemple

L'exemple de séquence était `2E-A → 2E-B → 2E-C → 2E-D → 2E-E`. L'audit
conduit à **un ordre différent** :

```
2E-A  metadata hardening      ─┐
                               ├─ indépendantes l'une de l'autre
2E-D  privacy-aware propagation ┘
        │
        ▼
2E-B  transport abstraction   ── prérequis obligatoire de 2E-C
        │
        ▼
2E-C  optional Tor transport
        │
        ▼
2E-E  advanced anonymity      ── NON PLANIFIÉE (voir §2.E)
```

### Justification du réordonnancement

| Étape | Priorité retenue | Raison tirée de l'audit |
|---|---|---|
| **2E-A** | **1** | C'est la seule qui réduit `METADATA_PRIVACY_CURRENT` (actuellement `LOW`) à coût faible, **et** elle contient une sous-partie sans changement de wire déployable immédiatement. Elle réduit aussi les perturbations de mesure pour tout ce qui suit. |
| **2E-D** | **2** | `TRANSACTION_CORRELATION_RISK = HIGH` est la **notation la plus grave** de tout le critère de sortie, et 2E-D est la **seule** étape qui l'adresse. Repousser D derrière B laisserait le risque maximal non traité pendant toute la durée de B, qui n'apporte aucun bénéfice utilisateur. |
| **2E-B** | **3** | Aucun bénéfice de sécurité en soi (comparaison §5 : « Nul en soi »). Son coût est réel, son bénéfice est **conditionnel** à 2E-C. On ne paie donc son prix que lorsqu'on s'apprête à en tirer parti. |
| **2E-C** | **4** | Dépend de B. Dépend aussi d'un réseau suffisamment peuplé : Tor ne masque l'IP que si une part notable des nœuds l'utilise, sinon il crée deux populations identifiables (comparaison §4, `OPERATIONAL_RISK`). |
| **2E-E** | **non planifiée** | Aucune conception n'existe, aucun besoin n'est démontré avant A+D. Voir §2.E. |

**Variante assumée.** Si l'équipe préfère stabiliser l'architecture de
transport avant de toucher à la propagation, **B et D peuvent être
intervertis**. Le coût de cette variante est explicite : `TRANSACTION_
CORRELATION_RISK = HIGH` reste non traité pendant toute la durée de 2E-B. Ce
document recommande l'ordre A → D, mais c'est une recommandation, pas une
obligation.

**Ce qui est exclu de toute séquence :** Tor et I2P ne sont **jamais** des
prérequis de quoi que ce soit d'autre ; le chiffrement de session actuel
n'est **jamais** à « remplacer » ; et aucune étape ne doit être engagée sans
que les tests de régression `p2p::`, `phase2_decentralized`, `phase2_eclipse`,
`phase2_self_healing` et `bootstrap_phase1` restent verts.

---

## 2. Étapes détaillées

### 2E-A — Metadata hardening

**STATUT — IMPLÉMENTÉ** (étape 16, commit `phase2: harden network metadata
privacy`). Livré : A.1.a (0600), A.1.b (masquage de `logs/node.log`),
A.1.c (revue `/metrics`+RPC → **CLEAN, aucun changement**), A.2.i
(`SyncRequest` borné + rotatif), A.2.ii/iii (jitter borné), A.3.a (paliers
256 o), A.3.b (magie obfusquée), A.3.c (version **3 → 4**,
`PROTOCOL_COMPATIBILITY = BREAKING`). Détail, limites et coût mesuré dans
`AETHER_PHASE2_METADATA_HARDENING.md`.
**Hors périmètre et non fait ici** : chiffrement du peer store, chiffrement du
handshake, compteur de frames (`DEFERRED`), tout ce qui est 2E-B/C/D/E.

**OBJECTIVE**
Réduire `METADATA_PRIVACY_CURRENT` (actuellement `LOW`) en supprimant les
fuites locales gratuites et en bornant les fuites réseau sans changer de
sémantique.

**CHANGE** — trois sous-étapes, indépendamment déployables :

| Sous-partie | Changement | Wire ? |
|---|---|---|
| **A.1 — local** | permissions restrictives du peer store (0600) ou chiffrement au repos ; anonymisation des adresses dans `logs/node.log` (masquage en sortie, pas en mémoire) ; revue de tout ce que `/metrics` et le RPC exposent | **non** |
| **A.2 — réseau, sans changement de wire** | (i) borner la réponse à `SyncRequest` (`p2p.rs:3461`), qui est aujourd'hui l'intégralité du DAG — s'appuyer sur l'`MAX_INV_ITEMS` déjà utilisé ailleurs ; (ii) aléa de fréquence PEX autour des 15 s ; (iii) aléa sur `RECOVERY_INTERVAL` et sur le redial | **non** |
| **A.3 — wire, avec bump de version** | agrégation / paliers de padding sur `total_len` ; masquage ou suppression du compteur en clair ; obfuscation de la magie `AETH` | **oui** — exige un bump de `P2P_PROTOCOL_VERSION` (actuellement **3**, `p2p.rs:1211`) et une fenêtre de compatibilité, `verify_handshake_identity` (`:2915`) rejetant toute version différente |

**SECURITY BENEFIT**
A.1 : divulgation locale d'adresses (risque `PEER_STORE_PRIVACY_RISK`,
`LOCAL_METADATA_EXPOSURE`).
A.2 : (i) suppression de la fuite « taille du DAG » pour **tout** observateur
passif — c'est la ligne 5/10 de la matrice ; (ii)(iii) réduction de
l'empreinte de reconnaissance (battement 15 s, cadence 5 s).
A.3 : les lignes 5 et 6 de la matrice passent de « en clair » à « palier » —
**c'est le bénéfice le plus large de toute la roadmap**, car il s'applique à
un observateur passif qui n'est pas un pair.

**COST**
A.1 : faible. A.2 : faible à modéré (A.2(i) touche au comportement de
synchronisation → à valider contre les tests de sync). A.3 : **élevé** —
c'est un changement de wire, avec version, compatibilité et mesure du coût
de bande.

**NEW ATTACK SURFACE**
A.1 : une clé d'encryption au repos devient elle-même un secret à protéger.
A.2(i) : risque de ralentissement du bootstrap si la borne est trop stricte ;
A.2(ii)(iii) : la mesure de « temps de propagation » devient bruitée — c'est
voulu, mais cela rend les diagnostics de latence plus difficiles.
A.3 : tout bug de padding = rejet de trames entre versions ; un palier mal
choisi ne masque rien et consomme de la bande pour rien.

**TEST REQUIREMENTS — 7/8 écrits** (16 tests au total dans
`p2p::phase2_privacy_tests`, plus 12 dans `log_privacy::tests`) :

| §3 | Écrit comme |
|---|---|
| 1 `test_no_plaintext_peer_metadata` | identique |
| 2 `test_handshake_metadata_exposure` | identique |
| 3 `test_inventory_size_not_leaked` | identique |
| 4 `test_frame_length_padding` | renommé `test_frame_size_buckets` (+ `test_padding_bounds`, `test_max_padding`, `test_padding_determinism`, `test_old_frame_rejected`, `test_frame_metadata_hardening`, `test_padding_is_authenticated`) |
| 5 `test_pex_rate_is_randomized` | renommé `test_pex_rate_limit` (+ `test_pex_privacy_bounds`) |
| 6 `test_peer_store_privacy` | identique |
| 7 `test_peer_store_no_addresses_in_logs` | identique |
| 8 `test_no_ip_in_metrics` | **non écrit** — A.1.c revu propre, aucun point-quadruplet exposé (`METRICS_REVIEW = CLEAN`) ; un test ici testerait du code que le commit ne change pas |
| + | `test_protocol_version_bump`, `test_handshake_magic_is_obfuscated` (ajouts non prévus au §3) |

**DEPENDENCIES**
Aucune. A.3 exige uniquement une décision explicite de bump de version —
prise ici : **3 → 4, BREAKING, sans fenêtre de compatibilité**.

**CONDITION DE SORTIE — SATISFAITE**
`cargo check --lib` = 9 warnings, 0 nouveau ; régressions **131/26/15/17/19**
vertes (115 + 16 nouveaux tests P2P) ; `METRICS_REVIEW = CLEAN`.
`METADATA_PRIVACY_CURRENT` re-noté → voir §6.

---

### 2E-B — Transport abstraction

**OBJECTIVE**
Séparer « qui je veux parler » (peer manager) de « comment j'arrive jusqu'à
lui » (transport), pour rendre 2E-C possible sans réécrire la Phase 2.

**CHANGE**
Introduction de `AetherTransport` (dial/accept/supports_inbound), d'un
`PeerAddr` enum `Ip(SocketAddr) | Onion(String) | I2p(String)`, et d'un
**groupement de repli** pour les variantes sans IP ; extraction des points de
couplage listés en §5 du document de comparaison : `connect_to_peer`,
`accept_loop`, `handle_peer`, `peers: HashMap<SocketAddr, …>`,
`NetworkGroup` / `subnet_24`, `PeerStoreEntry.addr`.

**SECURITY BENEFIT**
**Aucun directement.** Bénéfice purement conditionnel : c'est le prix d'entrée
de 2E-C et de tout travail de transport ultérieur.

**COST**
Modéré à élevé. Le poste le plus risqué n'est pas le trait, c'est
**`NetworkGroup` / `subnet_24`** : ce sont des défenses de sécurité de la
Phase 2C, pas des utilitaires. Toute réécriture doit re-passer les 15 tests
`phase2_eclipse_tests` **et** les 17 `phase2_self_healing_tests` sans
modification d'un seul test existant.

**NEW ATTACK SURFACE**
Un groupement de repli mal défini rend les quotas 2C/2D **silencieusement
no-ops** : le pire des cas est un quota qui croit s'appliquer alors qu'il ne
s'applique plus. C'est le risque structurel principal de toute cette roadmap.

**TEST REQUIREMENTS**
`test_transport_pluggability`, `test_transport_identity_separation`,
`test_network_group_fallback_bounds` (nouveau : un `PeerAddr` non-IP tombe
dans un groupe défini et reste borné), plus la régression complète.

**DEPENDENCIES**
Aucune pour B lui-même. **B est le prérequis obligatoire de 2E-C.**

**CONDITION DE SORTIE**
`phase2_eclipse_tests` 15/15 et `phase2_self_healing_tests` 17/17 **inchangés**
(donc : aucun test existant modifié), `p2p::` 115/115.

---

### 2E-C — Optional Tor transport

**OBJECTIVE**
Offrir, **en option et jamais par défaut**, un mode dans lequel l'IP du nœud
n'est pas exposée à ses pairs.

**CHANGE**
Deux sous-étapes, dans cet ordre :

| Sous-partie | Changement | Condition |
|---|---|---|
| **C.1 — SOCKS sortant** | `dial()` passe par un client SOCKS5 (arti ou crate `socks`) ; `supports_inbound() = false` | requiert **2E-B** |
| **C.2 — service onion bilatéral** | adresse `.onion` persistante, `accept()` sur service onion, `supports_inbound() = true` | requiert **C.1 + 2E-B + une refonte du groupement** |

**SECURITY BENEFIT**
C.1 : le pair et le réseau IP voient un nœud de sortie Tor, pas l'IP réelle.
`IP_PRIVACY_CURRENT` passerait de `NONE` à `PARTIAL (outbound only)`.
C.2 : les **deux** extrémités masquées — la seule variante Tor qui rend le
pair-à-pair symétrique.

**COST**
C.1 : modéré. C.2 : **élevé** — dépendance à un daemon externe, gestion
d'une adresse de long terme, et **remise en cause de `SocketAddr`**.

**NEW ATTACK SURFACE**
C.1 : (a) dépendance à `127.0.0.1:9050` — un Tor absent casse tout le
sortant ; (b) si peu de nœuds l'utilisent, une population minoritaire devient
**immédiatement identifiable** ; (c) la magie `AETH` traverse Tor sans
gêne : un opérateur de nœud de sortie sait qu'il porte du trafic Aether ;
(d) le `Inventory` non borné sur circuit à faible débit — **d'où la
dépendance à 2E-A.2(i)**.
C.2 : (a) une fuite d'IP par un autre canal (RPC exposé, DNS seed, seed TCP)
annule **tout** le bénéfice ; (b) **les défenses 2C/2D perdent leur sens**
sur un `.onion` : `NetworkGroup`, `subnet_24`, `MAX_PEERS_PER_SUBNET` sont
des concepts IP. C'est un chantier de sécurité, pas un plugin ; (c) l'adresse
`.onion` devient un nouveau **pseudonyme de long terme** dont le peer store
devient le support.

**TEST REQUIREMENTS**
`test_tor_transport` (dial via SOCKS simulé, `supports_inbound() == false`),
`test_transport_identity_separation`, `test_no_ip_in_metrics`,
`test_bootstrap_metadata_exposure` (le seed en mode C.1 ne voit qu'une IP de
sortie), plus un test de dégradation propre quand Tor est absent.

**DEPENDENCIES**
**2E-B obligatoire.** C.1 recommande **2E-A.2(i)** (inventaire borné).
C.2 recommande **2E-A** au complet et une décision explicite sur le
groupement. **C.2 ne doit pas être engagée avant que 2E-A et 2E-D soient
stabilisés**, sinon on cumule trois sources de changement sur le même chemin
de validation.

**CONDITION DE SORTIE**
`IP_PRIVACY_CURRENT` re-noté ; les 5 régressions vertes ; mesure documentée
de la latence et de la fiabilité sur circuit réel (**aucune mesure n'est
revendiquée aujourd'hui**).

---

### 2E-D — Privacy-aware propagation

**OBJECTIVE**
Réduire `TRANSACTION_CORRELATION_RISK` (actuellement `HIGH`) en rendant
l'inférence de premier-vu et la corrélation de timing moins fiables.

**CHANGE** — candidates, par ordre de coût croissant :

| Option | Changement | Bénéfice attendu |
|---|---|---|
| **D.1 — aléa de relais** | delay + jitter avant le relais de `P2PMessage::Transaction` (`p2p.rs:3249-3258`) et avant `broadcast_transaction` (`:3831`) | casse la synchronisation de rafale ; réduit le timing correlation |
| **D.2 — fanout partiel** | relayer à un **sous-ensemble** aléatoire de voisins plutôt qu'à tous | réduit le nombre de points d'observation simultanés |
| **D.3 — annonce par inventaire** | annoncer un hash (`Inventory`) puis servir en `GetData`, au lieu du push complet | masque la taille exacte de la transaction au premier saut |
| **D.4 — stem / flare** | un seul relais discret (« stem ») puis diffusion large (« flare ») | l'approche Dandelion/Dandelion++, conçue exactement pour l'inférence de premier-vu |

**SECURITY BENEFIT**
D.1 et D.2 attaquent directement les trois risques listés en §4.3 du modèle
de menaces (first-seen, timing, ingress). D.3 attaque le propagation
fingerprinting. D.4 est la seule qui attaque **structurellement** l'origine —
et aussi la seule qui coûte cher.

**COST**
D.1 : faible en code, **élevé en validation** — un délai de relais se
retrouve dans la latence de confirmation, qui est une grandeur observable
par tous. D.2 : modéré — réduit la couverture par nœud, donc la vitesse de
propagation. D.3 : modéré — double aller-retour par transaction. D.4 :
**élevé** — deux phases de propagation distinctes à valider contre la
convergence du DAG.

**NEW ATTACK SURFACE**
Toute latence ajoutée est aussi une **fenêtre de double-vision** dans un DAG
sans bloc : deux nœuds peuvent observer des états différents plus
longtemps. D.2 réduit la redondance de propagation, donc la tolérance aux
pairs défaillants. D.4 introduit un nœud « stem » identifiable par défaut,
qui devient une cible. **Aucune de ces options n'est neutraliste : elles
déplacent des compromis, elles n'en suppriment pas.**

**TEST REQUIREMENTS**
`test_transaction_propagation_timing` (distribution des délais de relais),
`test_transaction_propagation_first_seen` (un adversaire tenant k pairs
doit-il encore résoudre l'origine ?), `test_transaction_propagation_coverage`
(le fanout partiel couvre-t-il toujours tout le graphe en temps borné ?),
`test_propagation_convergence` (convergence du DAG inchangée sous latence
ajoutée). **Porte d'entrée obligatoire : les régressions de consensus et de
DAG doivent rester vertes.**

**DEPENDENCIES**
Indépendante de A et de B sur le plan du code. **Dépend de la validation de
convergence du DAG** — c'est la raison pour laquelle c'est une étape entière
et non une puce dans 2E-A. D.3 tire profit de 2E-A.3 (padding).

**CONDITION DE SORTIE**
`TRANSACTION_CORRELATION_RISK` re-noté **avec la mesure qui justifie la
nouvelle note** ; convergence du DAG démontrée sous latence/fanout modifié ;
les 5 régressions vertes. **Si la mesure ne montre pas d'amélioration,
le risque n'est pas re-noté** — on ne descend pas une note sans preuve.

---

### 2E-E — Advanced anonymity

**OBJECTIVE** — *non définie.*

**CHANGE** — aucun.

**SECURITY BENEFIT** — non évalué.

**COST** — non évalué.

**NEW ATTACK SURFACE** — non évalué.

**TEST REQUIREMENTS** — non définis.

**DEPENDENCIES** — 2E-A, 2E-B, 2E-D stabilisés ; et d'abord une **étude de
menaces spécifique**, sur le modèle de la présente phase, avant toute
esquisse de design.

**STATUT : NON PLANIFIÉE.** Mixnets, réputations d'anonymat, routing
multiples, pools de signatures : aucune de ces pistes n'a été étudiée pour
Aether, et **aucune ne doit être annoncée comme « envisagée »** tant qu'une
étude équivalente à celle-ci n'existe pas. C'est la seule étape de cette
roadmap dont on affirme explicitement qu'on ne sait pas ce qu'elle contient.

---

## 3. Tests à prévoir (étape 14) — **7 des 8 tests 2E-A écrits ; les 10 autres non**

| # | Test | Étape | Ce qu'il vérifierait |
|---|---|---|---|
| 1 | `test_no_plaintext_peer_metadata` | 2E-A | après handshake, aucun octet hors des 4+12 d'encadrement ne contient d'adresse IP ni de clé de pair |
| 2 | `test_handshake_metadata_exposure` | 2E-A | le handshake fait exactement 69 o et ne contient que {magie, version, genesis, clé éphémère} — **aucune IP, aucun node-id** |
| 3 | `test_inventory_size_not_leaked` | 2E-A.2 | la réponse à `SyncRequest` est bornée → `total_len` ne révèle plus qu'un palier |
| 4 | `test_frame_length_padding` | 2E-A.3 | toutes les longueurs de frames tombent dans les paliers déclarés |
| 5 | `test_pex_rate_is_randomized` | 2E-A.2 | distribution des intervalles PEX dans [a, b], pas un 15 s fixe |
| 6 | `test_peer_store_privacy` | 2E-A.1 | permissions 0600 et/ou payload chiffré ; le JSON en clair n'existe plus |
| 7 | `test_peer_store_no_addresses_in_logs` | 2E-A.1 | sortie de tracing capturée : **aucune adresse IP** à partir du niveau INFO |
| 8 | `test_no_ip_in_metrics` | 2E-A.1 | `/metrics` et réponses RPC : **aucun point-quadruplet** |
| 9 | `test_transaction_propagation_timing` | 2E-D | distribution des délais de relais, avec la borne attendue |
| 10 | `test_transaction_propagation_first_seen` | 2E-D | un adversaire contrôlant *k* pairs résout-il encore l'origine ? |
| 11 | `test_transaction_propagation_coverage` | 2E-D | le fanout partiel couvre tout le graphe en temps borné |
| 12 | `test_propagation_convergence` | 2E-D | convergence du DAG inchangée sous latence ajoutée |
| 13 | `test_bootstrap_metadata_exposure` | 2E-C | ce que reçoit réellement un seed au premier contact, dans chaque mode |
| 14 | `test_transport_identity_separation` | 2E-B | l'identité d'un pair est indépendante du transport |
| 15 | `test_transport_pluggability` | 2E-B | un transport en mémoire implémente le trait ; le peer manager se comporte **à l'identique** |
| 16 | `test_network_group_fallback_bounds` | 2E-B | un `PeerAddr` non-IP tombe dans un groupe défini et reste borné — **garde-fou contre les quotas devenus no-ops** |
| 17 | `test_tor_transport` | 2E-C | dial via SOCKS simulé ; `supports_inbound() == false` ; dégradation propre si Tor absent |
| 18 | `test_i2p_transport` | 2E-C+ | même forme, avec un mock I2P ; tunnels unidirectionnels |

**Statut après 2E-A (étape 16) :**

* n° **1, 2, 3, 6, 7** : écrits **à l'identique**, dans `p2p::phase2_privacy_tests` ;
* n° **4** : écrit sous le nom `test_frame_size_buckets`, complété par
  `test_padding_bounds`, `test_max_padding`, `test_padding_determinism`,
  `test_old_frame_rejected`, `test_frame_metadata_hardening`,
  `test_padding_is_authenticated` ;
* n° **5** : écrit sous le nom `test_pex_rate_limit`, complété par
  `test_pex_privacy_bounds` ;
* n° **8** : **non écrit** — revue A.1.c propre (`METRICS_REVIEW = CLEAN`),
  aucun point-quadruplet exposé ; ce test porterait sur du code que le commit
  ne change pas ;
* hors tableau : `test_protocol_version_bump`, `test_handshake_magic_is_obfuscated`
  (ajouts non prévus) ;
* n° **9 à 18** : **toujours non écrits** (2E-B, 2E-C, 2E-D).

**Gates de régression obligatoires pour chacun de ces tests, sans exception :**

```
cargo test --lib p2p::                    # 131/131  (115 + 16)
cargo test --lib phase2_decentralized_tests  # 26/26
cargo test --lib phase2_eclipse_tests        # 15/15
cargo test --lib phase2_self_healing_tests   # 17/17
cargo test --lib bootstrap_phase1            # 19/19
cargo test --lib p2p::phase2_privacy_tests   # 16/16
cargo test --lib log_privacy                 # 12/12
cargo check --lib                            # 9 warnings, 0 nouveau
```

**7 tests sur 18 sont codés (tous 2E-A, dont 2 renommés et 9 ajoutés hors
tableau), 1 est écarté dûment justifié (n° 8), et les n° 9 à 18 restent
spécifiés, pas codés.**

---

## 4. Ce qui ne sera pas promis

Les formulations interdites de l'étape 15 du modèle de menaces
(`AETHER_PHASE2_PRIVACY_THREAT_MODEL.md` §9) s'appliquent **à chaque étape de
cette roadmap**, y compris après livraison :

* 2E-A ne rend pas « le trafic opaque » — il réduit des fuites identifiées,
  chacune bornée, chacune listée.
* 2E-B ne protège rien.
* 2E-C ne produit **pas** « un nœud anonyme » : il produit un nœud dont
  l'IP n'est pas exposée à ses pairs **tant que** Tor fonctionne, **tant
  qu'aucune fuite d'un autre canal n'existe**, et **tant qu'il est
  suffisamment peuplé**.
* 2E-D ne rend pas « les transactions intraçables » : il réduit la fiabilité
  d'attaque donnée, à mesurer.
* 2E-E n'existe pas.

Chaque étape ne devra communiquer que : *protection contre tel observateur*,
*réduction de telle fuite*, *limite de telle corrélation*, *hypothèses*,
*limites*.

---

## 5. Risques restants (après toute la roadmap, y compris si elle réussit)

1. **Le registre reste public.** Aucune étape ne masque clé publique, adresse,
   montant ou `timestamp` au registre. Ce n'est pas un problème de transport.
2. **Un pair reste un observateur de premier rang.** Tant qu'un nœud accepte
   des pairs, il leur transmet transactions et voisinage. La seule parade est
   de réduire ce qu'on leur transmet (2E-D) — pas de l'empêcher.
3. **L'authentification du handshake n'existe toujours pas** (modèle de
   menaces §6.1). Ni A, ni B, ni C, ni D n'y touchent. Un MITM actif reste
   possible ; c'est un sujet de sécurité, distinct de la confidentialité, et
   il n'est **pas** dans cette roadmap.
4. **Le groupement `/24` est un présupposé de transport.** C'est le risque
   structurel le plus important : toute migration vers un transport sans IP
   peut annuler silencieusement les défenses 2C/2D.
5. **Toute mesure reste à faire.** Rien, dans cette phase, n'a été mesuré sur
   réseau réel : ni la latence de Tor, ni la taille réelle du voisinage
   divulgué par PEX, ni l'efficacité réelle de l'inférence de premier-vu
   contre Aether. Les notes `HIGH` / `MEDIUM` / `LOW` de cette roadmap sont
   **déduites du code**, pas mesurées.
6. **L'effet de seuil.** Tor ou I2P ne protège réellement qu'au-dessus d'un
   seuil de peuplement ; en deçà, ils créent une population identifiable.
   Ce seuil est inconnu pour Aether — personne ne l'a mesuré.

---

## 6. Critère de sortie

```
2E_ROADMAP                  = DOC COMPLETE, 1 ÉTAPE LIVRÉE SUR 5

2E-A  METADATA HARDENING    = IMPLEMENTED  (A.1.a/b/c, A.2.i/ii/iii, A.3.a/b/c)
                              wire : P2P_PROTOCOL_VERSION 3 → 4
                              PROTOCOL_COMPATIBILITY = BREAKING (aucune fenêtre)
                              METRICS_REVIEW = CLEAN (A.1.c : aucun changement)
2E-B  TRANSPORT ABSTRACTION = PROPOSED  (prérequis obligatoire de 2E-C)
2E-C  OPTIONAL TOR          = PROPOSED  (C.1 SOCKS sortant, C.2 onion bilatéral)
2E-D  PRIVACY PROPAGATION   = PROPOSED  (D.1..D.4, ordre de coût croissant)
2E-E  ADVANCED ANONYMITY    = NOT SCHEDULED (aucune conception, aucune étude)
SEQUENCE RECOMMANDÉE        = ~~2E-A~~ → 2E-D → 2E-B → 2E-C → 2E-E(non planifiée)
                             (variante assumée : B et D interchangeables, au coût
                              de TRANSACTION_CORRELATION_RISK = HIGH non traité)

METADATA_PRIVACY_CURRENT    = LOW → MEDIUM (borne, PAS suppression — cf.
                              AETHER_PHASE2_METADATA_HARDENING.md §4 et §5)
IP_PRIVACY_CURRENT          = NONE (inchangé — hors périmètre de 2E-A)
ANONYMITY_CURRENT           = NONE (inchangé — aucun mécanisme implémenté)
TRANSACTION_CORRELATION_RISK= HIGH (inchangé — 2E-D)

2E_TESTS_SPECIFIED          = 18 · 7 IMPLEMENTED (2E-A) · 1 ÉCARTÉ JUSTIFIÉ (n° 8)
                              · 10 RESTENT SPÉCIFIÉS, PAS CODÉS (n° 9..18)
2E_TESTS_NEW                = 28 (p2p::phase2_privacy_tests 16 · log_privacy 12)
2E_TEST_GATES               = p2p:: 131 · phase2_decentralized 26 · phase2_eclipse 15
                              · phase2_self_healing 17 · bootstrap_phase1 19
                              · phase2_privacy_tests 16 · log_privacy 12
                              · cargo check --lib 9 warnings / 0 nouveau

METADATA_OVERHEAD           = mean 129.5 o · worst 257 o (sweep 4097 tailles)
                              Peers(8) +113.33 % · Inventory(1000) +0.38 %
LATENCY_IMPACT              = pad+unpad ≈ 0.14 µs/trame · encrypt +1.69 % (40 Ko)
THROUGHPUT_IMPACT           = ≈ −1 % (717.8 → 708.6 MB/s, best-of-6)
                              reproductible : cargo test --release --lib
                              p2p::phase2_privacy_tests::bench_2e_a_costs -- --ignored

2E_CODE_CHANGES             = 2E-A ONLY
2E_COMMIT                   = phase2: harden network metadata privacy
TRANSPORT_IMPLEMENTED       = NONE
DEPLOYMENT                  = NONE
V1.4.0_IMMUTABLE            = PASS   (ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316)
```
