# AETHER — Phase 2C : résistance à l'eclipse

**Statut : `BASIC_ECLIPSE_RESISTANCE = PASS`**

> Ce document est le rapport d'implémentation de la Phase 2C. Le raisonnement
> qui a produit la conception se trouve dans
> `docs/AETHER_PHASE2_ECLIPSE_AUDIT.md` (écrit **avant** toute modification de
> code) ; ce document décrit ce qui a réellement été livré, vérifié et ce qui
> reste ouvert.
>
> **Ce document ne revendique jamais `ECLIPSE_PROOF = YES`.** Une attaque
> d'eclipse n'est pas « prouvée impossible » : elle est rendue plus chère, plus
> dépendante de l'adversaire, et bornée par des quotas vérifiables.

Branche : `dev/phase2-decentralized-network`
Base : `7195144 phase2: migrate peer metadata to address manager`
Fichier modifié : `src/p2p.rs` (seul fichier de code de la Phase 2C)
RELEASE figée : `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316`
Déploiement : **aucun** (`DEPLOYMENT = NONE`)

---

## 1. La menace

Un nœud AETHER est « éclipsé » quand un adversaire parvient à remplir **toutes**
ses sessions sortantes **et** toutes ses sessions entrantes avec des paires
qu'il contrôle. Ainsi coupé du réseau honnête, le nœud :

* ne voit plus que la portion de chaîne que l'attaquant lui présente ;
* ne relaie plus ses transactions vers le réseau honnête ;
* peut être amené à accepter un état de consensus que le reste du réseau
  rejette, puis à le rejeter une fois réintégré — un problème de *consistency*,
  pas seulement de disponibilité.

L'éclipse ne demande aucune rupture cryptographique : pas de clé volée, pas de
signature falsifiée. Elle demande seulement de **présélectionner les
voisinages** du nœud. C'est pourquoi elle se joue entièrement dans trois
endroits du code :

1. l'ordre et le nombre de connexions **sortantes** ouvertes (`select_outbound`) ;
2. le nombre de connexions **entrantes** acceptées et leur répartition par
   réseau (`inbound_admitted`, `count_subnet_peers_excluding`) ;
3. le contenu du **peer store**, qui est la mémoire de tout le reste
   (`AddressManager`).

---

## 2. Modèle d'attaquant

| Capacité | Hypothèse retenue |
|---|---|
| Argent | Illimité pour acheter des adresses, mais **pas** illimité pour en annoncer des milliers : chaque /24 IPv4 acheté est une ressource réelle, chaque allocation IPv6 /32 ou /48 l'est aussi. |
| Réseau | L'attaquant peut atteindre le nœud (il n'est pas derrière un NAT bloquant) et peut ouvrir autant de connexions entrantes que le protocole l'autorise. |
| Peer store | L'attaquant peut injecter des adresses par PEX, par réponse DNS s'il compromise un seed, et par un bootnode compromis. |
| Défenses visées | Les **quatre** points suivants, qui sont exactement ceux que la Phase 2C touche. |
| Hors portée | Compromission du handshake, de la PoW, des clés, ou d'un nœud déjà connecté de longue date avec lequel le chiffrement est établi. |

Trois niveaux d'adversaire sont distingués dans les tests :

* **A — faible** : un seul /24, aucun seed compromis. Contenu par le quota de
  groupe.
* **B — soutenu** : bootnode ou seeds compromis, peer store empli d'adresses
  hostiles. Contenu par l'ordre « connues avant seeds », la réservation de
  slot sortant et la qualité d'admission PEX.
* **C — sévère** : adversaire possédant plusieurs /24 **et** ayant provoqué une
  perte massive de sessions **et** une redémarrage du nœud. Contenu par la
  recomputation du quota à chaque round et par la persistance des anchors.

Le niveau **C n'est pas éliminé** : il est documenté en §9 (risques résiduels).

---

## 3. Cartographie A → G

| Scénario | Défense livrée | Lacune traitée | Test |
|---|---|---|---|
| **A — OUTBOUND STARVATION** : un client remplit les 128 slots, le nœud ne peut plus ouvrir *aucune* connexion sortante. | Réserve directionnelle `PROTECTED_OUTBOUND_SLOTS` activée par `inbound_admitted(total, outbound)` / `outbound_admitted(total)`, avec suivi de direction via `outbound_sessions`. | L1 | `test_protected_outbound_slots` |
| **B — SAME-NETWORK CONCENTRATION** : un seul /24 (ou une seule allocation IPv6) occupe toutes les sessions. | `NetworkGroup` (IPv4 /24, IPv6 24 bits, IPv4-mapped dé-embalqué) + quota par round `MAX_CANDIDATES_PER_GROUP` + quota de session `MAX_PEERS_PER_SUBNET` réévalué à chaque round. | L2, L4, L5 | `test_outbound_diversity`, `test_same_network_group_limited`, `test_multi_group_selection`, `test_network_group_unwraps_ipv4_mapped` |
| **C — BOOTNODE COMPROMIS** : le bootnode décide de qui le nœud contacte. | `redial_candidates` (Phase 2A) reste le substrat : toute adresse connue précède toute seed ; `select_outbound` ne fait que **réordonner** la moitié connue ; le bootnode n'est jamais prioritaire, jamais dialé s'il est banni. | L3 | `test_bootnode_compromised` |
| **D — SEED COMPROMIS** : un grand nombre de seeds configurées achète des slots. | Réservation `seed_reserve ≤ MAX_CANDIDATES_PER_GROUP` par round : dix seeds ne prennent que le quota d'un round. | L3, L4 | `test_seed_compromised` |
| **E — PEER STORE POISONING** : le store se remplit de bruit, la carte `scores` croît sans borne, un pair sain est délogé. | Qualité d'admission PEX `PEX_ADMISSION_QUALITY = PEER_SCORE_INITIAL / 2`, purge de `scores` dans `refresh_and_expire`, table bornée par `admit_peer`. | L6, L7, L8 | `test_peer_store_poisoning`, `test_low_quality_candidate_eviction` |
| **F — RESTART UNDER ATTACK** : au redémarrage, le store restauré est hostile et les anchors ont disparu. | Schema v2 persiste `anchor`, `source`, `quality`, `last_success` ; `select_outbound` donne un bonus `ANCHOR_SELECT_BONUS` aux anchors restaurés. | L3 | `test_restart_under_peer_attack` |
| **G — MASS PEER LOSS** : toutes les sessions tombent ; le nœud doit pouvoir se reconstruire sans recourir à un bootnode. | Le quota est **réévalué** depuis les sessions vivantes : elles disparaissent, le quota remonte, le round suivant est non-empty et diversifié. | L2, L3 | `test_mass_peer_loss` |

---

## 4. Défenses implémentées

### 4.1 `NetworkGroup` — une seule règle de groupement (§13.1)

```rust
enum NetworkGroup { V4([u8; 3]), V6([u8; 3]) }
fn network_group(addr: SocketAddr) -> NetworkGroup
```

* **IPv4 → /24.** Un /24 est la plus petite préfixe qu'un opérateur
  indépendant obtient réellement. Un adversaire qui achète un /24 gagne
  `MAX_PEERS_PER_SUBNET` sessions, pas plus.
* **IPv6 → 24 premiers bits.** Une allocation de fin d'utilisateur est un /32
  ou un /48 : les 24 premiers bits y sont fixes, donc toute l'allocation d'un
  adversaire tombe dans **un seul** groupe. Un /48 *affinerait* la granularité
  et laisserait un /32 se répartir sur 65 536 groupes — c'est la direction
  dangereuse. Le /24 IPv6 sur-grouppe, ce qui est **conservateur**.
* **IPv4-mapped (`::ffff:a.b.c.d`) et IPv4-compatible (`::a.b.c.d`) → traités
  en IPv4.** Corrige L5 : sans cela, toutes les adresses renvoyées par un
  listener dual-stack (Windows, et toute la pile accept()) tombaient dans le
  groupe `[0, 0, 0]` et le nœud était capé à quatre sessions entrantes **en
  total**.
* `subnet_24()` subsiste en tant que **projection** `network_group(addr).prefix3()`.
  La projection efface la famille, ce qui ne peut que *fusionner* deux groupes,
  jamais les scinder — direction conservatrice. Les 5 tests Phase 1 qui
  appellent `subnet_24` restent verts parce que la projection est identique à
  l'ancien résultat pour les adresses qu'ils utilisent.

`group_counts()` fournit l'histogramme `NetworkGroup → usize` consommé par le
`debug!` du round de sélection et par les tests : aucune métrique globale, aucune
dépendance ajoutée.

### 4.2 Réserve de slot sortant (§13.2)

```rust
fn inbound_admitted(total: usize, outbound: usize) -> bool
fn outbound_admitted(total: usize) -> bool
```

Garantie, énoncée et testée par boucle exhaustive sur tout l'espace
`(total, outbound)` :

> pour tout état où `inbound_admitted(total, outbound)` est vrai,
> `(total - outbound) + PROTECTED_OUTBOUND_SLOTS <= MAX_PEERS`.

Le corps retenu est `total + 1 + reserve <= MAX_PEERS` avec
`reserve = PROTECTED_OUTBOUND_SLOTS.saturating_sub(outbound)` :

* `total + 1` est la table **une fois** cette entrée admise ;
* `reserve` décroît à mesure que le nœud tient ses propres sessions
  sortantes : un nœud déjà outbound-heavy n'est pas throttlé par une réserve
  qu'il a déjà dépensée, mais un nœud 100 % inbound s'arrête à
  `MAX_PEERS - PROTECTED_OUTBOUND_SLOTS = 120`.

`PROTECTED_OUTBOUND_SLOTS = 8` est une **constante existante** (`:40`), déjà
couverte par `test_diversity_constants`. Elle n'a pas été modifiée. Sa
justification : `8 = 2 × MAX_PEERS_PER_SUBNET`, donc la réserve couvre **deux
groupes réseau complets** — au moins deux chemins indépendants même quand
l'entrée est saturée à 4 par groupe — soit 6,25 % de la table.

Le suivi directionnel vit dans `P2PNetwork::outbound_sessions`
(`Arc<RwLock<HashSet<SocketAddr>>>`), avec exactement deux writers : insertion
dans `connect_to_peer_inner`, retrait par le `spawn` qui enrobe `handle_peer`.
Aucun paramètre nouveau de `handle_peer`, aucune table d'adresse parallèle, et
la carte n'est jamais tenue en même temps que `peers` ni que `addresses`.

### 4.3 Sélection sortante (§13.3)

```rust
fn select_outbound<R: Rng + ?Sized>(
    ordered: &[SocketAddr],        // ordre Phase 2A, connues puis seeds
    seed_tail: &HashSet<SocketAddr>,// lesquelles de `ordered` sont ces seeds
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores:  &HashMap<SocketAddr, PeerScore>,
    connected: &HashSet<SocketAddr>,
    limit: usize,
    now_unix: u64,
    rng: &mut R,
) -> Vec<SocketAddr>
```

**Écart par rapport à §13.3 de l'audit** (document écrit avant le code) : la
signature reçoit `ordered` + `seed_tail` plutôt que `(entries, …, local, seeds)`.
Le motif est que `redial_candidates` devait **rester en production** : le le
remplacer entièrement aurait laissé une fonction de prod non appelée, donc un
avertissement `dead code` nouveau, ce que les consignes interdisent. Le résultat
est identique — `redial_candidates` construit l'ordre, `select_outbound` le
réordonne — mais l'invariant « connues avant seeds » est préservé par
construction et non par re-calcul.

Deux phases :

1. **Phase connues** — tirage **pondéré sans remplacement**
   (`rand::distributions::WeightedIndex`) sur le RNG injecté.

   ```
   w = quality
     + ANCHOR_SELECT_BONUS          si anchor
     + RECENT_SUCCESS_BONUS         si last_success dans RECENT_PEER_WINDOW_SECS
     - GROUP_OVERREPRESENTATION_PENALTY × (connectés dans le même groupe)
   poids = max(w, 0) + MIN_SELECT_WEIGHT
   ```

   Quota par round, réévalué à chaque tirage :
   `min(MAX_CANDIDATES_PER_GROUP, MAX_PEERS_PER_SUBNET − connectés_dans_le_groupe)`.
   Quota à 0 ⇒ le groupe est écarté du round.

2. **Phase seeds** — les seeds appposées par `redial_candidates`, dans leur
   ordre de configuration, **après** toutes les candidats connues, sous le même
   quota de groupe. Jamais prioritaires, jamais exclues du round : c'est
   « sans privilège », pas « ignoré ».

**Pas de seconde passe de relaxation** : si le quota empêche d'atteindre
`limit`, la sélection retourne *moins* d'adresses. C'est le but même du
scénario B — préférer manquer des slots à les remplir depuis un seul groupe. Le
progrès est assuré car le quota se réévalue chaque round à partir des sessions
réellement ouvertes (cf. `test_mass_peer_loss`).

Le RNG est ré-ensablé à chaque round en production (`StdRng::from_entropy()`),
ce qui fait à la fois varier l'ordre d'un cycle à l'autre et rendre l'ordre
imprévisible pour un adversaire distant. En test, `StdRng::seed_from_u64` le rend
rejouer à l'identique.

### 4.4 Rotation (§13.4) — sélection, pas déconnexion forcée

Décision explicite : **aucune déconnexion forcée.** Trois motifs :

1. `P2PNetwork` ne possède **aucune primitive de déconnexion** : `P2PMessage`
   n'a pas de variante « bye/disconnect », et la boucle `handle_peer` détient
   elle-même un clone du `UnboundedSender`. L'ajouter aurait signé un nouveau
   verrou d'état de session et un nouveau paramètre de `handle_peer` pour un
   bénéfice non prouvé.
2. L'instruction de travail est explicite : ne pas déconnecter brutalement,
   rotation progressive uniquement.
3. La rotation est obtenue par trois mécanismes progressifs :
   * le quota de round est **réévalué** depuis les sessions ouvertes : dès qu'un
     groupe atteint ses 4 sessions, son quota tombe et la sélection se déplace
     nécessairement ;
   * le RNG est ré-ensablé à chaque round : deux rounds ne proposent pas les
     mêmes adresses à l'intérieur d'un même groupe ;
   * `MAX_REDIAL_PER_CYCLE`, le backoff par candidat et `PEER_TTL` font tourner
     les candidats sur la durée.

Les sessions déjà ouvertes ne sont jamais fermées pour cause de rotation : elles
sont simplement **comptées**, et c'est leur nombre qui réduit le quota du
groupe. C'est exactement ce que vérifient `test_outbound_rotation` et
`test_peer_group_rotation`.

### 4.5 Qualité d'admission PEX (§13.5)

```rust
fn admission_quality(source: PeerSource) -> i32 {
    PeerSource::Pex => PEX_ADMISSION_QUALITY,   // PEER_SCORE_INITIAL / 2 = 50
    _                => default_peer_quality(), // PEER_SCORE_INITIAL   = 100
}
```

`admit_peer` évince quand `victim_quality <= incoming_quality`. À
`incoming = 100`, une salve PEX délogeait **toute** entrée saine de qualité 100
— c'était la lacune L6. À `incoming = 50`, elle ne vise que les entrées déjà
dégradées (≤ 50) ou bannies, tandis que les adresses que le nœud a observées
lui-même (inbound, dial sortant, DNS, config opérateur) restent à 100.

La valeur 50 est la **moitié** de `PEER_SCORE_INITIAL` : assez haute pour qu'une
adresse PEX honnête reste concurrentielle une fois le tableau plein de déchets,
assez basse pour ne jamais déloger un pair que nous avons nous-mêmes observé.
Un pair PEX qui prouve sa valeur remonte ensuite par `record_success`
(+10 par succès) : c'est une avance sur les preuves, pas une classe permanente.

### 4.6 Purge des `scores` (§13.6)

Dans `AddressManager::refresh_and_expire` :

```rust
self.scores.retain(|a, s| self.entries.contains_key(a) || connected.contains(a) || s.is_banned());
```

* un score **banni** survit toujours — c'est l'invariant qui justifie
  l'existence de `scores` comme carte séparée de `entries` ;
* un score non banni, dont l'adresse a disparu de `entries` et qui ne tient
  aucune session, est vidé : il ne porte plus d'information ;
* `decay_score` le recrée si l'adresse revient.

Sans cette passe, la carte grandissait d'une entrée par **adresse distincte
jamais dialée**, ce qu'un pair faisant défiler des indices frais à travers la
table pouvait faire croître sans borne (lacune L7, violation E).

### 4.7 Ce qui n'a pas été changé

Aucune constante de production existante n'a été modifiée :
`PEER_TTL`, `MAX_ANCHORS`, `MIN_ANCHORS`, `PEX_MAX_SEND`, `MAX_KNOWN_PEERS`,
`MAX_PEERS`, `MAX_PEERS_PER_SUBNET`, `PROTECTED_OUTBOUND_SLOTS`,
`MAX_REDIAL_PER_CYCLE`, `PEER_SCORE_INITIAL` sont tous identiques à `7195144`.
Aucun changement de handshake, de bruit de nonce, de direction, de PoW ni de
wire format. Aucun DHT, aucun Tor/I2P, aucun self-healing.

---

## 5. Limites et hors périmètre

Ce qui a été **explicitement décidé** de ne pas faire, avec la raison :

| Exclu | Raison |
|---|---|
| Déconnexion forcée des sessions existantes | Aucune primitive dans la codebase ; instruction explicite « ne pas déconnecter brutalement ». Reporté en risque résiduel (§9). |
| Plafond par **source** d'injection (L11) | Un tel plafond exigerait de distinguer une source honnête d'une source hostile, ce que le protocole ne permet pas. Une constante arbitraire ici serait une fausse assurance. |
| DHT / Kademlia, Tor, I2P | Nouveaux protocoles, nouveau threat model. Hors Phase 2C. |
| Self-healing (Phase 2D) | Prévu, non commencé. |
| Confidentialité des adresses (Phase 2E) | Étude seule, non commencée. |
| `ECLIPSE_PROOF = YES` | Jamais déclarable : voir l'en-tête. |

---

## 6. Tests

Module `phase2_eclipse_tests` (`use super::*;`), **15 tests** — les 14 imposés
par l'audit §14 plus un test justifié par la lacune L5.

| # | Test | Propriété vérifiée | Lacune |
|---|---|---|---|
| 1 | `test_outbound_diversity` | 16 candidats sur 8 groupes → 8 groupes distincts, aucun au-delà de son quota | L2, L4 |
| 2 | `test_same_network_group_limited` | 60 adresses dans un /24 → exactement `MAX_CANDIDATES_PER_GROUP` par round ; saturé à 4 sessions → 0 | L4 |
| 3 | `test_multi_group_selection` | 4 groupes → chacun dans ses bornes ; 3 sessions vivantes → quota ramené à 1 | L4 |
| 4 | `test_protected_outbound_slots` | invariant vérifié par **boucle exhaustive** sur `(total, outbound)` ; borne inbound à 120 ; nœud outbound-heavy non throttlé | L1 |
| 5 | `test_outbound_rotation` | 6 rounds → 6 listes différentes, union > taille d'un round | L9 |
| 6 | `test_bootnode_compromised` | le bootnode est toujours **dernier** ; banni ⇒ jamais dialé ; budget de 4 ⇒ il garde sa tranche | L3 |
| 7 | `test_seed_compromised` | 10 seeds configurées → exactement `MAX_CANDIDATES_PER_GROUP` slots, le reste aux adresses connues | L3, L4 |
| 8 | `test_peer_store_poisoning` | table à `MAX_KNOWN_PEERS`, PEX ne déloge aucun pair sain, entrée dégradée remplaçable, `scores` purgée, **la bannissement survit** | L6, L7, L8 |
| 9 | `test_restart_under_peer_attack` | aller/retour `to_store` → `load_v2` : les 6 anchors restaurés sont **tous** offerts, groupe attaquant sous quota, ≥ 2 groupes | L3 |
| 10 | `test_mass_peer_loss` | saturé → round vide (correct) ; perte totale → round non-empty, 4 groupes, 2 candidats chacun | L2, L3 |
| 11 | `test_anchor_protection` | `admit_peer` ne renvoie **jamais** un anchor ; sur 128 rounds semi-aleatoires, l'anchor l'emporte largement sur un candidat inconnu | L3 |
| 12 | `test_low_quality_candidate_eviction` | table saine pleine → `None` ; une entrée dégradée → c'est elle ; une paire **connectée** n'est jamais victime | L6 |
| 13 | `test_peer_group_rotation` | groupe saturé → absent du round ; un slot libéré → exactement 1 candidat, l'autre groupe garde ses 2 | L9 |
| 14 | `test_selection_deterministic_under_seed` | même graine → même liste ; graine différente → liste différente ; **reconstruction de la table → même liste** (pas de dépendance à l'ordre des `HashMap`) | L2 |
| 15 | `test_network_group_unwraps_ipv4_mapped` | `::ffff:x.x.x.x` et `::x.x.x.x` → groupe IPv4 embarqué ; `subnet_24` = projection de la même règle ; IPv6 natif groupé sur 24 bits | L5 |

**Aucun test existant n'a été modifié.** Les 5 tests legacy qui appellent
`subnet_24` (`test_subnet_24_ipv4`, `test_subnet_24_ipv6`,
`test_subnet_diversity_limit`, `test_eclipse_attack_blocked`,
`test_count_subnet_peers`) sont restés verts sans modification.

Les assertions portent sur des **propriétés** (quotas, invariants, cardinalités,
appartenance à un groupe), jamais sur une liste d'adresses choisie pour faire
passer un test. Les seuls nombres littéraux sont `8`, `4`, `2`, `16`, `128` —
tous des constantes de production déjà justifiées.

---

## 7. Constantes

**Aucune constante de production existante n'a été modifiée.** Celles-ci sont
nouvelles et chacune est une fraction de `PEER_SCORE_INITIAL = 100`, de sorte que
la qualité — qui démarre exactement à `PEER_SCORE_INITIAL` — reste le terme
dominant :

| Constante | Valeur | Justification |
|---|---|---|
| `MAX_CANDIDATES_PER_GROUP` | `MAX_PEERS_PER_SUBNET / 2` = **2** | La moitié du plafond de sessions par groupe : un round de 32 dials couvre donc ≥ 16 groupes quand le pool le permet, et **deux** rounds consécutifs peuvent encore compléter un groupe jusqu'à son plafond de 4. |
| `ANCHOR_SELECT_BONUS` | `PEER_SCORE_INITIAL / 2` = **50** | Un anchor est une adresse que nous avons **déjà** atteinte et volontairement retenue ; il doit l'emporter sur un candidat inconnu, sans l'emporter sur l'écart sain/échouant. |
| `RECENT_SUCCESS_BONUS` | `PEER_SCORE_INITIAL / 4` = **25** | Un succès < 24 h est une preuve fraîche ; moitié moindre que l'anchor, qui est une preuve *persistée*. |
| `GROUP_OVERREPRESENTATION_PENALTY` | `PEER_SCORE_INITIAL / 5` = **20** | 4 pairs déjà connectés dans le groupe = −80, soit environ cinq fois moins de chance qu'un candidat de qualité égale dans un groupe vide : c'est ce qui transforme la diversité en **propriété de sélection** plutôt qu'en contrôle d'admission a posteriori. |
| `MIN_SELECT_WEIGHT` | **1** | Un candidat jamais essayé ne doit jamais avoir un poids nul : on doit *toujours* pouvoir essayer quelque chose. |
| `PEX_ADMISSION_QUALITY` | `PEER_SCORE_INITIAL / 2` = **50** | La moitié du score initial : `admit_peer` n'évince que les entrées déjà dégradées ou bannies. |

**Constantes inchangées** (vérifié identique à `7195144`) : `PEER_TTL`,
`MAX_ANCHORS`, `MIN_ANCHORS`, `PEX_MAX_SEND`, `MAX_KNOWN_PEERS`, `MAX_PEERS`,
`MAX_PEERS_PER_SUBNET`, `PROTECTED_OUTBOUND_SLOTS`, `MAX_REDIAL_PER_CYCLE`,
`PEER_SCORE_INITIAL`.

---

## 8. Résultats

| Contrôle | Résultat |
|---|---|
| `ECLIPSE_AUDIT` | **PASS** — `docs/AETHER_PHASE2_ECLIPSE_AUDIT.md` écrit avant toute modification de code (sections 0 à 15, cartographie A→G, lacunes L1–L11). |
| `ECLIPSE_TESTS` | **15/15 PASS** |
| `P2P_REGRESSION` (`cargo test --lib p2p::`) | **98/98 PASS** |
| `PHASE2_REGRESSION` (`cargo test --lib phase2_decentralized_tests`) | **26/26 PASS** |
| `BOOTSTRAP_PHASE1` (`cargo test --lib bootstrap_phase1`) | **19/19 PASS** |
| `cargo check --lib` | **EXIT 0**, **9 warnings**, **0 nouveau** |
| `git diff --check -- src/p2p.rs` | **EXIT 0** |
| `OUTBOUND_DIVERSITY` | PASS |
| `NETWORK_GROUP_LIMIT` | PASS |
| `PROTECTED_OUTBOUND` | PASS |
| `ROTATION` | PASS |
| `BOOTNODE_COMPROMISED` | PASS |
| `SEED_COMPROMISED` | PASS |
| `PEER_STORE_POISONING` | PASS |
| `RESTART_ATTACK` | PASS |
| `MASS_PEER_LOSS` | PASS |
| `BASIC_ECLIPSE_RESISTANCE` | **PASS** |
| `ECLIPSE_PROOF` | **non déclaré — jamais `YES`** |
| `DEPLOYMENT` | **NONE** |
| `V1.4.0_IMMUTABLE` | **PASS** — `git rev-list -n1 v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316`, inchangé ; aucun tag ajouté. |

### Détail des warnings

Baseline Phase 2B : **10 warnings préexistants**. Phase 2C en laisse **9** :

| # | Warning | Statut |
|---|---|---|
| 1 | `unused import: tower_http::cors::CorsLayer` (rpc.rs) | préexistant |
| 2 | `constant PROTECTED_OUTBOUND_SLOTS is never used` | **résolu** — maintenant lu par `inbound_admitted` |
| 3 | `constant PEER_PENALTY_CONTRADICTION is never used` | préexistant |
| 4 | `constant PEER_PENALTY_TIMEOUT is never used` | préexistant |
| 5 | `constant PEER_PENALTY_ABUSIVE is never used` | préexistant |
| 6 | `constant PEER_BONUS_SYNC is never used` | préexistant |
| 7 | `method PeerScore::reward is never used` | préexistant |
| 8 | `function count_subnet_peers is never used` | préexistant |
| 9 | `touch_peer` / `nonce_collision_possible` / `ancestor_closed_page` jamais utilisés | préexistant |
| 10 | `field difficulty is never read` (validation.rs) | préexistant |

**0 warning nouveau introduit.** En particulier `redial_candidates`,
`subnet_24`, `network_group`, `group_counts`, `select_outbound`,
`MAX_CANDIDATES_PER_GROUP` et les autres constantes 2C sont tous effectivement
appelés par la production — c'est la raison pour laquelle
`redial_candidates` est resté le substrat de `select_outbound` plutôt que
d'être remplacé.

---

## 9. Risques résiduels

Ce qui reste vrai **après** la Phase 2C, et qui n'est pas résolu :

1. **Aucune déconnexion forcée.** Une session ouverte par un adversaire avant
   la Phase 2C reste ouverte. Le quota empêche d'en *ajouter* au-delà de la
   limite, mais ne réduit pas l'existant. Seuls `PEER_TTL`, la détection
   d'erreur et un redémarrage la ferment. *Atténuation :* Phase 2D (self-healing).
2. **Pas de plafond par source d'injection.** Un adversaire qui parvient à
   injecter des adresses par plusieurs voix (PEX + DNS + bootnode) n'est pas
   distingué d'un pair honnête multi-homed. Le plafond est par **groupe réseau**,
   ce qui borne l'effet réel tant que l'adversaire ne possède pas plusieurs
   allocations indépendantes.
3. **`seed_reserve` bornée à `MAX_CANDIDATES_PER_GROUP`.** Un store déjà plein
   d'adresses saines ne peut pas étouffer les seeds, mais un store *vide* ne
   donne aux seeds qu'une part fixe : si toutes les adresses connues sont
   mortes, les seeds ne reçoivent que 2 slots par round. Le round suivant, 5 s
   plus tard, leur en donne à nouveau 2 — la convergence est en minutes, pas en
   secondes.
4. **Le quota est par round, pas par session cumulée.** Deux rounds
   consécutifs peuvent porter un groupe à 4 sessions (2 + 2). C'est voulu —
   c'est ce qui garantit le progrès — mais cela signifie que le plafond réel
   d'un groupe est `MAX_PEERS_PER_SUBNET`, atteint en deux rounds, pas
   instantanément.
5. **IPv6 /24 sur-grouppe.** Deux fournisseurs distincts tombant dans le même
   /24 IPv6 sont traités comme un seul groupe : le nœud peut refuser un pair
   honnête. C'est la direction *sûre* (disponibilité sacrifiée au profit de la
   résistance), mais elle réduit la connectivité réelle.
6. **Adversaire multi-allocation (niveau C).** Un adversaire possédant
   plusieurs /24 IPv4 indépendants peut remplir plusieurs groupes à la fois.
   Le quota borne chaque groupe individuellement mais ne borne pas le **nombre
   de groupes** qu'il peut remplir. Avec `MAX_PEERS / MAX_PEERS_PER_SUBNET = 32`
   groupes au total, il lui faudrait 32 allocations pour un eclipse complet —
   c'est l'ordre de grandeur de la garantie, pas une preuve.
7. **`scores` purgée mais non bornée par écriture.** La purge se déclenche à
   chaque `refresh_and_expire` (cadencé par la tâche d'anchors). Entre deux
   passes, un pair qui fait défiler des indices peut encore faire croître la
   carte ; la borne est `MAX_KNOWN_PEERS` + le nombre de sessions, pas zéro.
8. **Rotation de la sélection ≠ rotation des sessions.** Le nœud peut rester
   connecté longtemps au même pair honnête (ou hostile) tant qu'il n'échoue
   pas. C'est un choix explicite (§4.4), pas un oubli.

---

## 10. Reproductibilité

```powershell
$env:PATH = "C:\msys64\mingw64\bin;C:\Users\Shadow\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained;" + $env:PATH
cargo check --lib
cargo test --lib p2p::
cargo test --lib phase2_decentralized_tests
cargo test --lib phase2_eclipse_tests
cargo test --lib bootstrap_phase1
git diff --check -- src/p2p.rs
```

Prochaine étape : **Phase 2D — self-healing** (réparation du voisinage après
une perte ou une éclipse partielle), puis **Phase 2E — confidentialité**
(étude seule).
