# AETHER — Roadmap confidentialité réseau (Phase 2E et au-delà)

**Statut : `2E_ROADMAP = COMPLETE` (la roadmap est rédigée) ·
`2E-A = IMPLEMENTED` · `2E-D = IMPLEMENTED` · `2E-B = IMPLEMENTED` ·
`2E-C = PROPOSED` · `2E-E = NOT SCHEDULED`**

> **Ce document reste un document de planification. Trois étapes ont été
> livrées, chacune par un commit dédié : 2E-A
> (`phase2: harden network metadata privacy`), 2E-D
> (`phase2: harden transaction propagation privacy`) et 2E-B
> (`phase2: abstract network transport`).**
>
> **2E-B n'implémente qu'un transport TCP.** `TCP = IMPLEMENTED` ·
> `TOR = NOT IMPLEMENTED` · `I2P = NOT IMPLEMENTED` · `ANONYMITY = NONE`.
> La présence d'un `trait Transport` ne signifie **pas** qu'un transport
> anonymisant existe, et 2E-B ne protège rien.
>
> L'étape 2E-C reste une **proposition**. Aucune n'est engagée, aucune n'a
> commencé, et le passage d'une étape à l'autre exige une décision explicite
> — il ne se fait pas automatiquement.
>
> Détail et preuves de ce qui a réellement été codé (et de ce qui ne l'a pas
> été) : `docs/AETHER_PHASE2_METADATA_HARDENING.md` (2E-A),
> `docs/AETHER_PHASE2_PRIVACY_PROPAGATION.md` (2E-D) et
> `docs/AETHER_PHASE2_TRANSPORT_ABSTRACTION.md` (2E-B).

Branche : `dev/phase2-decentralized-network` · HEAD précédent `028cca9 phase2: harden transaction propagation privacy`
RELEASE `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` (inchangée)
`2E_CODE_CHANGES = 2E-A · 2E-D · 2E-B` · `2E_COMMITS = phase2: harden network metadata privacy (2E-A) · phase2: harden transaction propagation privacy (2E-D) · phase2: abstract network transport (2E-B)` · `DEPLOYMENT = NONE`

Entrées de cette roadmap :

* `docs/AETHER_PHASE2_PRIVACY_THREAT_MODEL.md` — étapes 1-8 et 15 de l'audit.
* `docs/AETHER_TRANSPORT_COMPARISON.md` — étapes 9-12.
* `docs/AETHER_PHASE2_TRANSPORT_ABSTRACTION.md` — preuves du 2E-B livré.

---

## 1. Séquence proposée, et pourquoi elle diffère de l'exemple

L'exemple de séquence était `2E-A → 2E-B → 2E-C → 2E-D → 2E-E`. L'audit
conduit à **un ordre différent** :

```
2E-A  metadata hardening      ─┐ LIVRÉ (commit dédié)
                               ├─ indépendantes l'une de l'autre
2E-D  privacy-aware propagation ┘ LIVRÉ (commit dédié)
        │
        ▼
2E-B  transport abstraction   ── LIVRÉ (commit dédié) — TCP SEUL   [LIVRÉ]
        │                        TOR / I2P = NOT IMPLEMENTED
        ▼
2E-C  optional Tor transport                                     [PROPOSED]
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

**STATUT — IMPLÉMENTÉ** (commit `phase2: abstract network transport`).
**Portée réelle : `TCP = IMPLEMENTED`, et TCP seul.**
`TOR = NOT IMPLEMENTED` · `I2P = NOT IMPLEMENTED` · `ANONYMITY = NONE`.
Preuves et diff : `docs/AETHER_PHASE2_TRANSPORT_ABSTRACTION.md`.

**OBJECTIVE**
Séparer « qui je veux parler » (peer manager) de « comment j'arrive jusqu'à
lui » (transport), pour rendre 2E-C possible sans réécrire la Phase 2.

**CHANGE — ce qui a été codé**

* `src/transport.rs` (nouveau) : `PeerAddr` avec la **seule** variante `Ip`,
  `TransportError`, `trait Transport` (`dial` + `bind` uniquement,
  dyn-compatible, boxed futures natives, **sans `async_trait`**),
  `TransportStream` / `TransportListener` en enums, `TcpTransport`.
* Les **3 seuls points de couplage** de l'audit sont détournés :
  `TcpStream::connect` → `transport.dial(&PeerAddr::Ip(..))`,
  `TcpListener::bind` → `transport.bind(..)`,
  `listener.accept()` → `TransportListener::accept()`.
* `handle_peer` reçoit un `TransportStream` ; `into_split()` rend des halves
  **possédées**, `Send`, `'static` — obligatoire puisque le write half part
  dans `tokio::spawn`.
* `TransportGroupKey { Ip(NetworkGroup), NoNetworkGroup }`, projection
  **directe** de `network_group()` : une seule source de vérité.
* `NetworkGroup` : privé → `pub`. **Visibilité seule**, aucun comportement.

**CHANGE — ce qui n'a PAS été codé (décision explicite)**

* `PeerAddr` ne remplace **pas** `SocketAddr` comme clé. Sessions,
  `AddressManager`, `sync_stats`, wire PEX et peer store restent
  `SocketAddr` / `String`. Conversion au boundary, 2 sites. Contrainte dure :
  `src/sync_stats.rs` (intouchable) expose `peer: SocketAddr`.
* **Aucune variante `Onion` / `I2p`** : ajoutée « pour faire joli », elle
  serait du code mort présentant comme une fonctionnalité.
* `peers: HashMap<SocketAddr, …>`, `NetworkGroup` / `subnet_24`,
  `PeerStoreEntry.addr` : **inchangés** — conformément à l'interdiction de
  réécrire les défenses de Phase 2C.
* Pas de bump de store (`PEER_STORE_VERSION` reste **2**), pas de bump de
  protocole (`P2P_PROTOCOL_VERSION = 4`, `PROTOCOL_CHANGE = NONE`).

**SECURITY BENEFIT**
**Aucun directement.** Bénéfice purement conditionnel : c'est le prix d'entrée
de 2E-C et de tout travail de transport ultérieur. 2E-B ne protège rien.

**COST**
Réalisé à **faible coût** : 3 points de couplage, `NetworkGroup` non touchée
(visibilité seule), 0 test existant modifié. Le scénario redouté — devoir
convertir les 277 occurrences de `SocketAddr` — **ne s'est pas produit** :
`TRANSPORT_ABSTRACTION_BOUNDARY = OK`.

**NEW ATTACK SURFACE**
Un groupement de repli mal défini rend les quotas 2C/2D **silencieusement
no-ops** : le pire des cas est un quota qui croit s'appliquer alors qu'il ne
s'applique plus. C'est le risque structurel principal de toute cette roadmap.
Atténué ici : `NoNetworkGroup` existe et est testé, mais **n'est rempli par
personne** — TCP passe toujours par `network_group()`, et aucun /24 n'est
inventé pour un endpoint non-IP.

**TEST REQUIREMENTS — état réel**
Module `transport::phase2_transport_tests`, **11 tests** :
`test_peer_addr_ip_roundtrip`, `test_peer_addr_invalid_conversion`,
`test_tcp_transport_dial`, `test_tcp_transport_accept`,
`test_tcp_transport_bind_reports_endpoint`, `test_tcp_transport_roundtrip`,
`test_transport_stream_split_owned` (les 2 halves dans `tokio::spawn`),
`test_transport_listener_returns_peer_addr`, `test_transport_group_ip`,
`test_transport_group_no_network_group` (← couvre le n° 16 du tableau §3),
`test_legacy_peer_store_transport_boundary`.
Les n° 14 et 15 du tableau **restent non écrits** — voir §3.

**DEPENDENCIES**
Aucune pour B lui-même. **B est le prérequis obligatoire de 2E-C**, qu'elle
reste **PROPOSED** : rien n'est engagé.

**CONDITION DE SORTIE — remplie**
`phase2_eclipse_tests` 15/15 et `phase2_self_healing_tests` 17/17 **inchangés**
(donc : aucun test existant modifié), `p2p::` **149/149**,
`bootstrap_phase1` 19/19, `transport::` 11/11,
`cargo check --lib` 9 warnings / 0 nouveau.

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

> **STATUT : D.1 + D.2 LIVRÉS**, ainsi que les deux changements non
> optionnels qui les accompagnaient — suppression du relay **pré-validation**
> et dédup de **planification** avant tout scheduling. Commit dédié
> `phase2: harden transaction propagation privacy`. **D.3 et D.4 restent
> PROPOSED.**
>
> `TRANSACTION_CORRELATION_RISK = HIGH → REDUCED`, justifié par la mesure
> (`AETHER_PHASE2_PRIVACY_PROPAGATION.md` §9) : coût de trafic ×0,0625,
> duplication 2,00 → 0,125 copies/lien, spread de relais 0 ms → 92,5-234,5 ms.
> Le reste de cette section est le dossier de conception d'origine, conservé
> pour D.3/D.4.

**CHANGE** — candidates, par ordre de coût croissant :

| Option | Changement | Bénéfice attendu |
|---|---|---|
| **D.1 — aléa de relais** | delay + jitter par peer avant chaque envoi — `propagation_delay` (`p2p.rs:619`), appelé dans `broadcast_transaction` (`p2p.rs:4530`) | casse la synchronisation de rafale ; réduit le timing correlation |
| **D.2 — fanout partiel** | relayer à un **sous-ensemble** aléatoire de voisins plutôt qu'à tous — `propagation_targets` (`p2p.rs:646`), `MAX_PROPAGATION_FANOUT = 4` | réduit le nombre de points d'observation simultanés |
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

## 3. Tests à prévoir (étape 14) — **n° 1-7 écrits ; n° 9, 11, 12 couverts ; n° 16 couvert par 2E-B ; n° 8, 10 écartés ; n° 14, 15 non écrits ; n° 13, 17, 18 restent 2E-C**

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
* n° **13 à 18** : **toujours non écrits** (2E-B, 2E-C).

**Statut après 2E-D (étape 17) — module `p2p::phase2_privacy_propagation_tests`,
19 tests dont 18 exécutés :**

* n° **9** (`timing`) : **écrit** — `test_relay_delay_bounds_and_spread`
  (bornes incluses, `MIN > 0`) et `test_relay_delay_depends_only_on_the_rng`
  (pur dans le RNG, pas de décalage fixe) ;
* n° **10** (`first_seen`) : **non écrit, écarté dûment justifié** — 2E-D ne
  prétend pas résoudre le premier-vu : c'est la limite §12.2 de
  `AETHER_PHASE2_PRIVACY_PROPAGATION.md`, à couvrir par **D.3/D.4**, hors
  périmètre. Écrire ce test maintenant reviendrait à tester une garantie que
  l'étape ne donne pas ;
* n° **11** (`coverage`) : **écrit partiellement** —
  `test_topology_cannot_shrink_the_fanout` (le fan-out ne se réduit jamais
  pour cause de topologie) et `test_no_privileged_relay_address`
  (aucune adresse privilégiée). La couverture du **graphe entier** n'est pas
  simulée ici : elle est assurée par l'`Inventory` sync de 10 s, déjà couverte
  par les tests de sync ;
* n° **12** (`convergence`) : **écrit** —
  `test_multihop_convergence_stays_within_the_existing_bounds` (8 hops ≤ 2 s
  < backstop 10 s / 4 et < `FRAME_TIMEOUT` / 4) ;
* hors tableau (14 tests + 1 bench) : `test_fanout_is_bounded`,
  `test_upstream_peer_is_excluded_without_shrinking_the_wave`,
  `test_fanout_spans_network_groups`, `test_fanout_selection_varies_by_seed`,
  `test_receive_stage_schedules_no_relay`,
  `test_a_payload_schedules_exactly_one_wave`,
  `test_upstream_peer_is_first_observation`,
  `test_local_payload_still_propagates`,
  `test_each_peer_receives_at_most_one_copy`,
  `test_upstream_peer_never_receives_the_relay`,
  `test_inflight_relays_drain_to_zero`,
  `test_relay_is_reachable_only_after_the_pure_gate`,
  `test_invalid_transaction_is_never_scheduled_for_relay`, + le n° 11 ci-dessus ;
  `#[ignore] bench_transaction_propagation` (release).

**Statut après 2E-B — module `transport::phase2_transport_tests`, 11 tests :**

* n° **14** (`transport_identity_separation`) : **non écrit** — le concept
  suppose que l'identité d'un pair est détachable du transport. Or, dans ce
  commit, la clé de session **reste `SocketAddr`** par choix de frontière
  (`sync_stats.rs` intouchable) : il n'y a donc pas deux identités à séparer.
  Écrire ce test maintenant testerait une propriété que l'étape ne donne pas ;
* n° **15** (`transport_pluggability`) : **non écrit** — il exigeait un
  transport en mémoire (`MockTransport`) exerçant le trait à côté de TCP.
  Aucun `MockTransport` n'a été construit : le trait n'a qu'une seule
  implémentation réelle, et un mock n'aurait rien vérifié de plus que les 6
  tests TCP déjà écrits. **`supports_inbound()` n'existe pas** dans le trait
  livré — l'API est `dial` + `bind` ;
* n° **16** (`network_group_fallback_bounds`) : **écrit** —
  `test_transport_group_no_network_group` (un `TransportGroupKey` non-IP n'est
  **jamais** assimilé à un groupe IP, donc aucun quota ne devient no-op),
  complété par `test_transport_group_ip` (v4 → `/24`, v6 → 24 bits) ;
* hors tableau (10 tests) : `test_peer_addr_ip_roundtrip`,
  `test_peer_addr_invalid_conversion`, `test_tcp_transport_dial`,
  `test_tcp_transport_accept`, `test_tcp_transport_bind_reports_endpoint`,
  `test_tcp_transport_roundtrip`, `test_transport_stream_split_owned`,
  `test_transport_listener_returns_peer_addr`,
  `test_legacy_peer_store_transport_boundary`.

**Gates de régression obligatoires pour chacun de ces tests, sans exception :**

```
cargo test --lib p2p::                    # 149/149  (131 + 18)
cargo test --lib phase2_                  # 92/92    (74 + 18)
cargo test --lib phase2_decentralized_tests  # 26/26
cargo test --lib phase2_eclipse_tests        # 15/15
cargo test --lib phase2_self_healing_tests   # 17/17
cargo test --lib bootstrap_phase1            # 19/19
cargo test --lib p2p::phase2_privacy_tests   # 16/16
cargo test --lib p2p::phase2_privacy_propagation_tests  # 18/18 + 1 ignored
cargo test --lib transport::phase2_transport_tests      # 11/11   (2E-B)
cargo test --lib log_privacy                 # 12/12
cargo check --lib                            # 9 warnings, 0 nouveau
cargo test --release --lib bench_transaction_propagation -- --ignored  # PASS
```

**13 tests sur 18 du tableau sont codés (7 pour 2E-A dont 2 renommés et 10
ajoutés hors tableau ; 2 pour 2E-D au sens strict, 1 partiellement ; 1 pour
2E-B), 3 sont écartés dûment justifiés (n° 8, 10 et 14), 1 n'a pas été jugé
utile (n° 15), et les n° 13, 17, 18 restent spécifiés, pas codés (2E-C).**
S'y ajoutent 15 tests 2E-D hors tableau (dont le bench) et 10 tests 2E-B
hors tableau.

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
  d'attaque donnée. Mesuré en 2E-D (`AETHER_PHASE2_PRIVACY_PROPAGATION.md` §9)
  : le coût de trafic passe à 0,0625 de l'ancien et la duplication de 2,00 à
  0,125 copies par lien, mais un observateur voyant les deux extrémités reste
  capable d'apparier les flux. Le seul résultat revendiqué est
  `TRANSACTION_CORRELATION_RISK = REDUCED`.
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
2E_ROADMAP                  = DOC COMPLETE, 3 ÉTAPES LIVRÉES SUR 5

2E-A  METADATA HARDENING    = IMPLEMENTED  (A.1.a/b/c, A.2.i/ii/iii, A.3.a/b/c)
                              wire : P2P_PROTOCOL_VERSION 3 → 4
                              PROTOCOL_COMPATIBILITY = BREAKING (aucune fenêtre)
                              METRICS_REVIEW = CLEAN (A.1.c : aucun changement)
2E-B  TRANSPORT ABSTRACTION = IMPLEMENTED  (src/transport.rs : PeerAddr + trait
                              Transport{dial,bind} + TransportStream/Listener
                              + TcpTransport + TransportGroupKey ; 3 points de
                              couplage détournés ; 11 tests transport)
                              TCP = IMPLEMENTED · TOR = NOT IMPLEMENTED
                              I2P = NOT IMPLEMENTED · ANONYMITY = NONE
                              wire : aucun changement · PROTOCOL_CHANGE = NONE
                              P2P_PROTOCOL_VERSION = 4 (inchangé)
                              PEER_STORE_VERSION = 2 (inchangé)
2E-C  OPTIONAL TOR          = PROPOSED  (C.1 SOCKS sortant, C.2 onion bilatéral)
                              non engagé malgré 2E-B livré — décision requise
2E-D  PRIVACY PROPAGATION   = IMPLEMENTED  (D.1 jitter + D.2 fanout borné/diversifié
                              + dédup de planification + relay pré-validation supprimé
                              + exclusion source)
                              wire : aucun changement · PROTOCOL_CHANGE = NONE
                              P2P_PROTOCOL_VERSION = 4 (inchangé depuis 2E-A)
2E-E  ADVANCED ANONYMITY    = NOT SCHEDULED (aucune conception, aucune étude)
SEQUENCE RECOMMANDÉE        = ~~2E-A~~ → ~~2E-D~~ → ~~2E-B~~ → 2E-C → 2E-E(non planifiée)

METADATA_PRIVACY_CURRENT    = LOW → MEDIUM (borne, PAS suppression — cf.
                              AETHER_PHASE2_METADATA_HARDENING.md §4 et §5)
IP_PRIVACY_CURRENT          = NONE (inchangé — hors périmètre de 2E-A, 2E-D et 2E-B)
ANONYMITY_CURRENT           = NONE (inchangé — aucun mécanisme implémenté, y
                              compris avec le trait Transport livré en 2E-B)
TRANSACTION_CORRELATION_RISK= HIGH → REDUCED (2E-D — borne, PAS suppression — cf.
                              AETHER_PHASE2_PRIVACY_PROPAGATION.md §12)

2E_TESTS_SPECIFIED          = 18 · 10 IMPLEMENTED (7 pour 2E-A, 2 pour 2E-D,
                              1 pour 2E-B) · 1 PARTIEL (n° 11)
                              · 3 ÉCARTÉS JUSTIFIÉS (n° 8, 10, 14)
                              · 1 NON UTILE (n° 15 — pas de MockTransport)
                              · 3 RESTENT SPÉCIFIÉS, PAS CODÉS (n° 13, 17, 18)
2E_TESTS_NEW                = 58 (p2p::phase2_privacy_tests 16 · log_privacy 12
                              · p2p::phase2_privacy_propagation_tests 18 + 1 bench
                              · transport::phase2_transport_tests 11)
2E_TEST_GATES               = p2p:: 149 · phase2_ 92 · bootstrap_phase1 19
                              · phase2_decentralized 26 · phase2_eclipse 15
                              · phase2_self_healing 17 · phase2_privacy_tests 16
                              · phase2_privacy_propagation_tests 18 (+1 ignored)
                              · transport::phase2_transport_tests 11
                              · log_privacy 12
                              · cargo check --lib 9 warnings / 0 nouveau

METADATA_OVERHEAD           = mean 129.5 o · worst 257 o (sweep 4097 tailles)
                              Peers(8) +113.33 % · Inventory(1000) +0.38 %
LATENCY_IMPACT              = pad+unpad ≈ 0.14 µs/trame · encrypt +1.69 % (40 Ko)
THROUGHPUT_IMPACT           = ≈ −1 % (717.8 → 708.6 MB/s, best-of-6)
                              reproductible : cargo test --release --lib
                              p2p::phase2_privacy_tests::bench_2e_a_costs -- --ignored

TRANSACTION_PROPAGATION_OVERHEAD = 64 000 → 4 000 frames = 0,0625 de l'ancien
                              (−93,75 %)
TRANSACTION_DUPLICATION_RATE= 2,00 → 0,125 copies par lien
TRANSACTION_PROPAGATION_LATENCY  = 0 ms → first 38,6..129,4 ms · last 189,0..275,9 ms
                              · spread 92,5..234,5 ms (6 exécutions)
                              reproductible : cargo test --release --lib
                              p2p::phase2_privacy_propagation_tests::bench_transaction_propagation
                              -- --ignored --nocapture

2E_CODE_CHANGES             = 2E-A · 2E-D · 2E-B
2E_COMMITS                  = phase2: harden network metadata privacy (2E-A)
                              · phase2: harden transaction propagation privacy (2E-D)
                              · phase2: abstract network transport (2E-B)
TRANSPORT_PERFORMANCE_IMPACT= LOW (NEGLIGIBLE) — analyse statique du chemin
                              P2P → Arc<dyn Transport> → TcpTransport →
                              TcpStream ; aucune mesure chiffrée n'est revendiquée
TRANSPORT_IMPLEMENTED       = TCP ONLY
                              src/transport.rs — un seul impl Transport
TOR                         = NOT IMPLEMENTED
I2P                         = NOT IMPLEMENTED
ANONYMITY                   = NONE
                            (la présence d'un `trait Transport` ne signifie PAS
                            qu'un transport anonymisant existe)
DEPLOYMENT                  = NONE
V1.4.0_IMMUTABLE            = PASS   (ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316)
```
