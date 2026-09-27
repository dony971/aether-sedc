# AETHER — Phase 2C : audit de résistance à l'eclipse

**Branche :** `dev/phase2-decentralized-network`
**Point de départ :** `7195144 phase2: migrate peer metadata to address manager`
**Release gelée :** `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316`
**Statut de ce document :** cartographie faite *avant* toute modification de code.

---

## 0. Périmètre et honnêteté du résultat attendu

L'objectif de la Phase 2C n'est **pas** de produire `ECLIPSE_PROOF = YES`.
Un attaquant qui contrôle suffisamment d'adresses *et* suffisamment de groupes
réseau *et* la totalité des sources indépendantes (seeds, DNS, PEX, inbound)
gagne toujours — c'est le théorème de base du problème : sans un canal de
découverte honnête, aucun nœud ne peut distinguer un pair honnête d'un pair
compromis qui se comporte correctement au niveau du protocole.

Ce que la Phase 2C peut honnêtement obtenir et tester :

```
ECLIPSE_RESISTANCE_BASIC = PASS
```

c'est-à-dire : **diversification, rotation, limites et conservation de chemins
de connexion indépendants**, chacun vérifié par un test qui échouerait sans la
défense.

Le code audité est celui du commit `7195144`. Toutes les lignes citées sont
celles de ce commit.

---

## 1. Comment les pairs *sortants* (outbound) sont sélectionnés

Il n'existe **aucune fonction de sélection**. Il existe quatre chemins qui
appellent `connect_to_peer()` (src/p2p.rs:2769) :

| Chemin | Code | Cadence | Budget |
|---|---|---|---|
| Balayage initial | `initial_dial_sweep` :1323 | une fois, au démarrage | aucun — dials **tous** les seeds, puis **toutes** les adresses restaurées |
| Boucle de reconnexion | `start_reconnection_task` :1622 | toutes les 5 s | `MAX_REDIAL_PER_CYCLE` = 32 dials par cycle |
| Battement de cœur | `start_heartbeat` :1568 | toutes les 10 s, **uniquement si `peer_count == 0`** | 32 |
| Résolution DNS | `discover_from_dns` :1712 / `start_dns_discovery` :1749 | au démarrage + périodique | toutes les adresses résolues |
| Réception PEX | `peer_discovery_rx` :1254 → `connect_to_peer` | à chaque message `Peers` | une par hint, sérialisée dans une seule tâche |

L'« ordre » vient exclusivement de `redial_candidates()` (src/p2p.rs:1607) :

```rust
let mut out = known.iter().copied().filter(|a| *a != local).collect();
for seed in seeds { ... out.push(*seed); }
```

`known` est `AddressManager::addresses()` (src/p2p.rs:776) =
`entries.keys().copied().collect()`, c'est-à-dire **l'ordre d'itération d'une
`HashMap`**.

### Constat 1 — sélection non pilotée

* La qualité (`AddressEntry::quality`), la fraîcheur (`last_seen`), le
  `last_success`, le statut d'anchor, le score de réputation et le groupe réseau
  **n'entrent dans aucune décision d'ordre**. Ces données existent, sont
  persistées, et ne servent qu'à l'admission/éviction (`admit_peer` :421) et au
  diagnostic (`categories` :989).
* L'ordre d'une `HashMap` Rust est pseudo-aléatoire (graine `RandomState` par
  processus) donc *imprévisible* par un attaquant distant — mais il est
  **stable dans un processus** tant que la table n'est pas modifiée. Ce n'est
  pas de la sélection : c'est l'absence de sélection.
* **`anchor` n'influence aucun dial.** Relevé exhaustif des consommateurs de
  `AddressEntry::anchor` : `admit_peer` :436 (protection à l'éviction),
  `apply_anchors` :938, `categories` :1000, `to_store`/`load_v2` (persistance),
  `anchor_addresses`/`anchor_candidates` (tâche d'ancrage). **Aucun dial.** Le
  drapeau anchor de la 2B est donc une protection d'admission, pas un chemin de
  récupération.

### Constat 2 — les seeds ne sont *pas* toutes désavantagées

`redial_candidates` place bien les seeds à la fin (testé par
`test_seeds_are_unprivileged_in_redial` :3345). En revanche
`initial_dial_sweep` :1324 diale **tous les seeds en premier**, avant toute
adresse restaurée. C'est voulu et documenté (un nœud neuf n'a que ça), mais
c'est exactement la fenêtre des scénarios C, D et F.

### Constat 3 — le budget n'est pas un budget

`MAX_REDIAL_PER_CYCLE = 32` borne les *dials* par cycle de 5 s, soit
32 × 12 = **384 dials par minute**, pas le nombre de sessions. Rien ne borne le
nombre de sessions *sortantes* en elles-mêmes.

---

## 2. Comment les pairs *entrants* (inbound) sont acceptés

`accept_loop` :1850 applique exactement trois filtres, dans cet ordre :

1. `peers.len() >= MAX_PEERS` (128) → refus (`:1869`)
2. `count_subnet_peers_excluding(addr) >= MAX_PEERS_PER_SUBNET` (4) → refus (`:1878`)
3. `addresses.is_banned(addr)` → refus (`:1892`)

Puis `ingress_address` (:495) et `handle_peer`.

### Constat 4 — aucun plafond directionnel (scénario A)

`MAX_PEERS = 128` est **commun** aux deux directions. Or
`connect_to_peer_inner` :2804 fait :

```rust
if peers_guard.len() >= MAX_PEERS { ... return; }
```

**Conséquence : 128 connexions entrantes suppriment totalement la capacité
sortante.** Le nœud accepte encore des pairs, échange, gossippe — et ne peut
plus jamais en initié un seul. C'est la définition d'une starvation sortante :
il n'y a aucun « slot sortant protégé ».

`PROTECTED_OUTBOUND_SLOTS = 8` **existe déjà** (src/p2p.rs:39) et figure dans
`test_diversity_constants` :5502, mais est **mort** — c'est l'un des 10 warnings
préexistants (`constant PROTECTED_OUTBOUND_SLOTS is never used`). La
constante a été écrite lors de la Phase 8 sans jamais être câblée.

---

## 3. Combien de connexions un même réseau peut occuper

`subnet_24()` :210 extrait les **3 premiers octets**, pour IPv4 **et** IPv6.

```rust
SocketAddr::V4(v4) => Some([o[0], o[1], o[2]]),
SocketAddr::V6(v6) => Some([o[0], o[1], o[2]]),   // « synthetic /24-equivalent »
```

### Constat 5 — bogue IPv4-mapped

Une adresse `::ffff:192.168.1.100` a pour octets
`00 00 00 00 00 00 00 00 00 00 ff ff c0 a8 01 64`, donc
`subnet_24(...) == Some([0, 0, 0])`.

**Toutes les adresses IPv4-mapped tombent dans un unique groupe `[0,0,0]`.**

C'est une direction *conservative* (sur-groupement ⇒ plafond plus dur ⇒ sûr
contre l'eclipse) mais c'est une **disponibilité cassée** : sur Windows, un
socket double-famille qui écoute sur `::` renvoie des `accept()` en
`::ffff:x.x.x.x`. Un nœud dual-stack n'accepterait alors que
`MAX_PEERS_PER_SUBNET = 4` connexions entrantes **au total**, toutes familles
confondues.

`is_private_or_reserved()` :332 dé-emballe déjà correctement l'IPv4-mapped.
`subnet_24()` non. Les deux jugements du même octet divergent.

### Constat 6 — le plafond par groupe est réel… et contourné

`count_subnet_peers_excluding` :241 est bien appelé dans les **deux** sens
(`accept_loop` :1878 et `connect_to_peer_inner` :2812), à 4 par groupe. C'est
la défense la plus solide du fichier.

Mais elle borne le **groupe**, pas le **nombre de groupes**. Un attaquant qui
possède 32 plages /24 distinctes prend 32 × 4 = 128 sessions, c'est-à-dire la
totalité de `MAX_PEERS`. Aucune constante du fichier ne limite le nombre de
groupes distincts présents dans la table de sessions.

### Constat 7 — IPv6 groupé au /24, jamais audité

Le commentaire dit « synthetic /24-equivalent » sans justification. Une
allocation de fin d'utilisateur IPv6 chez un fournisseur est typiquement un
/32 ou un /48 ; les 24 premiers bits sont fixes dans les deux cas, donc un
attaquant doté d'une allocation unique reste dans **un seul** groupe /24. La
granularité choisie est donc *sûre* (elle sur-grouppe) — mais elle n'est
documentée nulle part, et le dé-emballement IPv4-mapped lui fait défaut.

---

## 4. Comment les pairs sont choisis depuis `AddressManager`

Ils ne le sont pas. `AddressManager` expose :

* `addresses()` :776 — clés brutes, ordre de `HashMap`
* `sample_for_pex()` :892 — pour le **gossip**, trié qualité décroissante, déterministe (commenté : *« Pseudo-random outbound selection is 2C (D10), not this stage »* :407)
* `anchor_candidates()` :922 — pour la tâche d'ancrage uniquement
* `categories()` :989 — diagnostic uniquement

Aucune vue n'est utilisée par un dial.

---

## 5. Comment anchors et candidats interagissent

```
refresh_anchors (60 s) : sessions → anchor_candidates → promote_anchors → apply_anchors
```

* `anchor_candidates` = sessions vivantes **avec au moins un `last_success`** (:922-930) — règle correcte : seul un handshake complété peut promouvoir.
* `promote_anchors` :461 fusionne survivants + candidats, plus récent d'abord, cap `MAX_ANCHORS = 8`, exclut l'adresse locale, jamais en dessous de `MIN_ANCHORS = 3` sans alerte.
* `expire_anchors` :482 → `ANCHOR_TTL_SECS = 7 j`.

### Constat 8 — l'anchor est non exclusif… et non utilisateur

Le dossier 2B dit « redial preference ». Le code ne l'utilise jamais pour
dialer. L'anchor est **exclusivement** une protection d'admission/éviction et
un bit persisté. Un nœud redémarre, restaure 1000 adresses, et les dialle dans
un ordre qui ignore totalement lesquelles il avait soigneusement retenues.

---

## 6. Comment PEX influence la sélection

Réception (`handle_peer` :2684-2720) :

1. filtre `!contains`, `!= local`, `!connected`, `!is_private_or_reserved` (**D6, uniquement à la réception**)
2. `ingress_address(..., PeerSource::Pex)`
3. `set_origin(peer_addr, addr)` (anti-écho, D5)
4. `peer_discovery_tx.send(peer_addr)` → **dial immédiat**, un par un, dans une tâche consommatrice unique (:1254)

Envoi (`start_pex` :1809, toutes les 15 s) : `sample_for_pex` borné à
`PEX_MAX_SEND = 64`, exclusion du destinataire, anti-écho, aging
`PEX_SHARE_MAX_AGE_SECS = 24 h`, exclusion des bannis, qualité décroissante.

### Constat 9 — PEX est le seul chemin qui contourne la sélection

Les hints PEX sont dialés **immédiatement**, sans passer par aucun ordre de
sélection, sans quota de groupe par round. Le seul garde-fou est le plafond de
sessions par groupe de `connect_to_peer_inner` (4), donc un envoi PEX de 64
adresses dans 64 groupes différents produit 64 sessions sortantes en une
réception.

Par ailleurs la tâche consommatrice est **sérialisée** : `connect_to_peer` est
`await`é l'un après l'autre avec `CONNECT_TIMEOUT = 5 s`. Une salve de 64 hints
morts bloque toute découverte PEX pendant jusqu'à 320 s.

### Constat 10 — l'ingestion PEX utilise la même qualité que tout le monde

`ingress_address` :515 insère **toujours** avec
`default_peer_quality()` = `PEER_SCORE_INITIAL` = 100, quelle que soit la
source. Or `admit_peer` :448 évicte si `quality <= incoming_quality`. Avec
`incoming = 100`, une salve PEX de 1000 adresses médiocres déplace **chaque**
entrée saine non connectée et non-anchor de qualité 100 (`100 <= 100`).

Les protections actuelles de l'adresse saine sont donc seulement :
être **connectée**, être **anchor**, ou avoir une qualité **> 100** (obtenue
par succès). Tout ce qui est connu, inactif et jamais réussi est évictable par
du bruit PEX.

---

## 7. Comment les pairs récents peuvent monopoliser les slots

* `categorise` :272 produit `Recent` pour un `last_success` < 24 h, mais cette
  catégorie n'est consommée que par `categories()` (diagnostic). Elle ne donne
  **aucun** privilège de sélection — donc aucun monopole *par cette voie*.
* En revanche `refresh_and_expire` :958 rafraîchit `last_seen` de **toute**
  session vivante, toutes les 60 s (`start_peer_store_task`). Une adresse
  connectée **n'expire jamais**.
* `handle_peer` ne se termine que sur erreur de socket/fermeture du pair.
  `P2PMessage` (src/p2p.rs:1140) ne contient **aucune variante de
  déconnexion** : il n'existe dans le fichier **aucun primitive de
  déconnexion forcée**. La carte `peers` ne retient qu'un
  `mpsc::UnboundedSender` ; retirer la clé ne termine pas la boucle de
  `handle_peer`, qui détient elle-même un clone du sender.

### Constat 11 — les sessions d'un attaquant sont immortelles

Une fois connecté, un pair n'est retiré que s'il se déconnecte, s'il est banni
(score ≤ 0), ou si le processus s'arrête. Il n'y a **aucune rotation de
slot sortant**. `PROTECTED_OUTBOUND_SLOTS` est morte ; aucun feeler n'existe.

C'est la raison exacte pour laquelle la contrainte « rotation progressive, ne
pas déconnecter brutalement tous les peers » est difficile : la rotation de
*session* demanderait une primitive de déconnexion qui n'existe pas.

---

## 8. Comment un attaquant pourrait remplir le peer store

`MAX_KNOWN_PEERS = 1000`, `MAX_PEERS = 128`, `MAX_INV_ITEMS = 1000` borne la
taille d'un message PEX. Le mécanisme d'admission (2B/D8) :

* table non pleine → insertion libre
* table pleine → `admit_peer` choisit une victime : jamais connectée, jamais
  anchor, bannie d'abord, puis qualité la plus basse, puis plus ancienne
* la victime n'est remplacée que si `banned || victim_quality <= incoming_quality`

### Constat 12 — pas de plafond par source

Aucun compteur ne limite combien d'adresses **une seule source** (un seul
pair, un seul seed) peut injecter. Un unique pair PEX peut pousser jusqu'à
`MAX_INV_ITEMS = 1000` adresses par message, et le faire toutes les 15 s.

### Constat 13 — le rafraîchissement du TTL perpétue l'empoisonnement

`ingress_address` :519 fait `mgr.touch(addr, at)` sur une adresse déjà connue.
Un attaquant qui **re-annonce** périodiquement ses 1000 adresses via PEX
rafraâchit leur `last_seen` indéfiniment : la fenêtre `PEER_TTL = 1 h` ne les
jette jamais. Le bruit n'a pas besoin d'être dialé pour survivre, il suffit
qu'il soit répété.

### Constat 14 — `scores` croît sans borne (violation E)

`refresh_and_expire` :971-982 ne retire que `origins` et `entries`.
`scores` **n'est jamais nettoyée**. Or `decay_score` :877 **insère** une
entrée si elle n'existe pas, et `connect_to_peer_inner` :2800 l'appelle pour
chaque dial. Le retirer de `entries` (TTL) laisse le score en place —
volontairement, pour qu'un bannissement survive à l'expiration (invariant 2B).

Mais un score **non banni**, dont l'adresse n'est plus dans `entries` ni
connectée, ne porte plus aucune information : il n'est consulté que si
l'adresse revient. Au fil des cycles d'empoisonnement, `scores` accumule une
entrée par adresse *distincte* jamais vue auparavant. C'est une croissance non
bornée en mémoire, exactement ce que le scénario E interdit.

---

## 9. Si un même /24 (ou équivalent) peut monopoliser les connexions

**Non, dans la limite de 4.** Vérifié dans les deux sens, test
`test_eclipse_attack_blocked` :5597.

**Oui, si l'attaquant possède plusieurs groupes.** 32 groupes × 4 = 128 = la
totalité. Aucune constante ne borne le nombre de groupes distincts d'une table
de sessions. Voir Constat 6.

---

## 10. Si un groupe de pairs peut verrouiller durablement un nœud

**Oui.** Trois verrous réunis :

1. **Verrou de capacité** — 128 entrées bloquent tout dial sortant (Constat 4).
2. **Verrou de pérennité** — aucune rotation, sessions immortelles, TTL neutralisé
   pour les sessions vivantes (Constat 11).
3. **Verrou d'ordre** — l'ordre de `HashMap` étant stable dans un processus,
   chaque cycle de 5 s repart exactement du même ordre, avec le même budget de
   32 dials. Le nœud ne « découvre » jamais autre chose que ce que son propre
   hasard d'initialisation lui a donné une fois.

---

# Cartographie A → G

Chaque ligne : attaque · défense actuelle · lacune · modification proposée · test.

---

## A — OUTBOUND STARVATION

**Attaquant.** Ouvre 128 connexions entrantes (128 adresses, ou moins si
`MAX_PEERS_PER_SUBNET` se déclenche — 32 groupes suffisent). Le nœud cesse
immédiatement de pouvoir initier la moindre connexion sortante.

**Défense actuelle.** `MAX_PEERS_PER_SUBNET = 4` ralentit l'entrée ; le ban
table écarte les pairs déjà sanctionnés. **Aucune réserve sortante.**

**Lacune.** `PROTECTED_OUTBOUND_SLOTS` est morte ; `connect_to_peer_inner`
refuse dès `len == MAX_PEERS`, indépendamment de la direction.

**Modification.** Câbler `PROTECTED_OUTBOUND_SLOTS` : une connexion entrante
n'est admise que si, après elle, **au moins `PROTECTED_OUTBOUND_SLOTS`
emplacements restent mobilisables en sortant**. Nécessite de connaître le
compte sortant → suivi directionnel des sessions (section « Conception »).

**Test.** `test_protected_outbound_slots`.

---

## B — SAME-NETWORK CONCENTRATION

**Attaquant.** Fournit 500 adresses dans un seul /24, ou 500 adresses réparties
dans 125 /24 qu'il possède.

**Défense actuelle.** 4 sessions par groupe, dans les deux sens. La
concentration dans *un* /24 est bloquée à 4.

**Lacune.** (i) Le *round de sélection* n'a aucun quota de groupe : les 32 dials
d'un cycle peuvent tous viser le même groupe (gâchis de budget, découverte des
autres groupes retardée). (ii) Multi-groupe : 125 × 4 = 500 > 128, aucune borne.
(iii) Le plafond de session est aveugle à la famille (Constat 5).

**Modification.**
* `NetworkGroup` : abstraction unique de groupement, IPv4 /24, IPv6 /24
  documenté, **IPv4-mapped dé-embalqué** (corrige Constat 5).
* Quota **par round** : `MAX_CANDIDATES_PER_GROUP` par groupe et par
  sélection, borné en plus par `MAX_PEERS_PER_SUBNET - connectés_dans_le_groupe`.
* La diversité devient une **propriété de la sélection** et pas seulement de
  l'acceptation.

**Test.** `test_same_network_group_limited`, `test_outbound_diversity`,
`test_multi_group_selection`.

---

## C — BOOTNODE COMPROMISED

**Attaquant.** Le bootnode configuré ne renvoie que des paires qu'il contrôle.

**Défense actuelle.** `redial_candidates` met les seeds **derniers** (testé).
PEX apporte d'autres candidats. Les anchors persistent sur disque.
`is_private_or_reserved` bloque les adresses LAN à la réception PEX.

**Lacune.** `initial_dial_sweep` dial les seeds **en premier** puis le store
dans un ordre qui **ignore les anchors** : le nœud restauré reconstruit
exactement le même ordre à chaque redémarrage. PEX est le seul apport réel, et
il passe par un dial immédiat sans quota (Constat 9).

**Modification.** La sélection sortante ordonne : anchors d'abord (avantage de
rang, pas de place réservée — « anchors non exclusifs »), puis qualité/fraîcheur
pondérés, puis diversité de groupe ; les seeds restent **après** les adresses
connues. `initial_dial_sweep` utilise la même sélection après les seeds.

**Test.** `test_bootnode_compromised`.

---

## D — SEED COMPROMISED

**Attaquant.** Un seed (ou plusieurs) ne renvoie que du matériel hostile.

**Défense actuelle.** Phase 2A : les seeds sont des candidats sans privilège,
jamais prioritaires sur une adresse déjà connue (`test_seeds_are_unprivileged_in_redial`,
`test_redial_candidates_without_any_seed`).

**Lacune.** « Sans privilège » ne veut pas dire « sans influence » : si le store
est vide ou déjà empoisonné, les seeds sont les seuls candidats et deviennent de
fait une autorité. Aucune limite ne dit « un seul seed ne peut pas fournir tous
les slots sortants ».

**Modification.** Le quota de groupe s'applique **aussi aux seeds** (un seed et
ses successeurs ne peuvent pas monopoliser un round), et ils restent en queue
de sélection. Aucun seed n'entre dans les anchors : `anchor_candidates`
(:922) n'accepte que des sessions ayant complété un handshake — propriété déjà
correcte, à documenter comme garantie D.

**Test.** `test_seed_compromised`.

---

## E — PEER STORE POISONING

**Attaquant.** Injecte un volume massif d'adresses médiocres via PEX, et les
re-annonce indéfiniment.

**Défense actuelle.** `MAX_KNOWN_PEERS = 1000` (borne stricte) ;
`admit_peer` ne sacrifie jamais une session vivante ni un anchor ; victime de
préférence bannie puis de qualité la plus basse ; aging PEX 24 h ; TTL 1 h ;
`MAX_INV_ITEMS = 1000`.

**Lacunes.**
* **Constat 10** : qualité d'entrée identique pour PEX et pour le reste ⇒ le
  bruit PEX peut déloger toute entrée saine inactif de qualité 100.
* **Constat 13** : re-annonce périodique ⇒ rafraîchissement du TTL ⇒ le bruit
  ne meurt jamais.
* **Constat 14** : `scores` croît sans borne.
* **Constat 12** : aucun plafond par source.

**Modification.**
* `admission_quality(source)` : une adresse apprise **uniquement** par gossip
  entre avec une qualité strictement inférieure à `PEER_SCORE_INITIAL`, si bien
  qu'elle ne peut **jamais** déloger une entrée que nous avons observée par un
  canal que nous contrôlons (ingress, DNS, dial, inbound). Elle ne peut viser
  que les entrées déjà dégradées ou bannies.
* `refresh_and_expire` : purge des scores **non bannis** dont l'adresse n'est
  plus dans `entries` et n'est pas connectée. Le bannissement survit toujours
  (invariant 2B préservé).
* Pas de plafond par source : refusé comme arbitraire et non justifiable ;
  reporté en risque résiduel.

**Test.** `test_peer_store_poisoning`, `test_low_quality_candidate_eviction`.

---

## F — RESTART UNDER ATTACK

**Attaquant.** Au redémarrage, les seules adresses disponibles (store + seeds)
sont majoritairement les siennes.

**Défense actuelle.** Persistance v2 avec anchors ; seeds d'abord au premier
balayage ; DNS ; PEX dès la première session ; anchors persistés.

**Lacunes.** L'ordre du store restauré ignore les anchors (Constat 8) ; aucune
diversité de groupe au balayage ; l'ordre est le même à chaque redémarrage.

**Modification.** `initial_dial_sweep` : seeds (inchangé, seule source d'un nœud
neuf) puis **sélection sortante** ancrée sur les anchors restaurés et diversifiée
par groupe. Chemins de récupération indépendants : seeds opérateur, DNS, anchors,
store, PEX, inbound.

**Test.** `test_restart_under_peer_attack`.

---

## G — MASS PEER LOSS

**Attaquant.** Fait disparaître une grande partie des pairs simultanément
(blocage réseau, purge).

**Défense actuelle.** `start_heartbeat` (0 pair → redial), `start_reconnection_task`
(5 s, backoff exponentiel par candidat, cap 60 s), TTL qui libère les adresses
mortes, `MAX_ANCHORS` conservés sur disque.

**Lacune.** Le remplacement est exactement aussi divers que la sélection — qui
n'en a pas. Et une perte totale combinée à un store empoisonné ne retrouve que
l'attaquant (recouvre avec F).

**Modification.** La sélection sortante (C/B) fournit diversité, anchors et
rotation ; les mécanismes de remplacement 2A/2B restent inchangés.

**Test.** `test_mass_peer_loss`.

---

# 11. Défenses actuelles — inventaire confirmé

| Défense | Statut | Réf. |
|---|---|---|
| 4 sessions max par /24, inbound **et** outbound | **actif** | `:1878`, `:2812` |
| Plafond total 128 | actif | `:1869`, `:2804` |
| Ban table consultée à l'entrée **et** au dial sortant | actif (2A) | `:1892`, `:2784` |
| Anti-écho PEX + aging 24 h + `PEX_MAX_SEND` 64 | actif (2B/D5) | `:892` |
| Blocage des adresses privées/réservées à la **réception** PEX | actif (2B/D6) | `:2697` |
| Table bornée à 1000, victime = bannie puis plus mauvaise qualité | actif (2B/D8) | `:421` |
| Sessions vivantes et anchors **jamais** évictées | actif (2B/D8) | `:433-437` |
| Anchors : promotion uniquement depuis un handshake réussi, cap 8, TTL 7 j | actif (2B/D9) | `:461`, `:922` |
| Seeds sans privilège dans la reconnexion | actif (2A) | `:1607` |
| Anti-deadlock `peers`/`addresses` | actif (2B) | `:508` |
| PEX ingéré avec la même qualité que tout le reste | **défaut** | `:515` |
| `scores` purgée | **défaut** | `:971` |
| Réserve sortante | **défaut** (`PROTECTED_OUTBOUND_SLOTS` morte) | `:39` |
| Quota de groupe à la sélection | **défaut** | — |
| Ordre de sélection piloté par qualité/anchor/diversité | **défaut** | `:1612` |
| Rotation de slot sortant | **défaut** (aucune primitive de déconnexion) | — |
| Dé-emballement IPv4-mapped dans le groupement | **défaut** | `:216` |

---

# 12. Lacunes — synthèse

| # | Lacune | Scénario | Sévérité |
|---|---|---|---|
| L1 | Aucune réserve de slot sortant | A | **haute** |
| L2 | Aucune sélection sortante (ordre de `HashMap`) | A, B, C, D, F, G | **haute** |
| L3 | `anchor` n'influence aucun dial | C, F | moyenne |
| L4 | Quota de groupe absent de la sélection | B | moyenne |
| L5 | IPv4-mapped → unique groupe `[0,0,0]` | B (disponibilité) | moyenne |
| L6 | Qualité PEX = qualité de tout le monde | E | moyenne |
| L7 | `scores` non purgée (croissance non bornée) | E | moyenne |
| L8 | TTL rafraîchi par re-annonce → bruit éternel | E | faible/moyenne |
| L9 | Aucune rotation de slot sortant | A, G | faible (contrainte explicite) |
| L10 | PEX dialé immédiatement, hors sélection | A, B | faible |
| L11 | Aucun plafond par source d'injection | E | faible (reportée) |

---

# 13. Conception retenue (à implémenter)

## 13.1 `NetworkGroup`

```rust
enum NetworkGroup { V4([u8; 3]), V6([u8; 3]) }
fn network_group(addr: SocketAddr) -> NetworkGroup
```

* **IPv4 → /24.** Un /24 est la plus petite préfixe que des opérateurs
  indépendants obtiennent réellement pour annoncer un routeur ; en dessous, on
  est dans l'espace d'autrui. Une attaquant qui achète un /24 gagne
  `MAX_PEERS_PER_SUBNET` slots, pas plus.
* **IPv6 → 24 premiers bits.** Une allocation de fin d'utilisateur chez un
  fournisseur est un /32 ou un /48 : les 24 premiers bits y sont fixes, donc
  **toute** l'allocation d'un attaquant tombe dans un seul groupe. Adopter un
  /48 *affinerait* la granularité et laisserait un /32 se répartir sur 65 536
  groupes — c'est la direction dangereuse. Le /24 IPv6 sur-grouppe (il peut
  fusionner des fournisseurs distincts), ce qui est **conservateur** : plus dur
  contre l'eclipse, au prix d'une connectivité réduite.
* **IPv4-mapped (`::ffff:a.b.c.d`) → traité en IPv4.** Corrige L5.
* `subnet_24()` devient une projection `prefix3()` de `network_group()` : une
  seule source de vérité. La projection efface la famille, ce qui ne peut que
  **fusionner** deux groupes (jamais les scinder) — direction conservatrice.

Justification de la granularité : la seule direction dangereuse est le
*sous-groupement* (un attaquant tient plusieurs groupes réels en un seul). Le
choix retenu ne sous-grouppe jamais.

## 13.2 Réserve de slot sortant

```rust
fn inbound_admitted(total: usize, outbound: usize) -> bool
fn outbound_admitted(total: usize) -> bool
```

Invariant garanti et testé :

> Pour tout état où `inbound_admitted` est vrai,
> `(total - outbound) + PROTECTED_OUTBOUND_SLOTS <= MAX_PEERS`.

*Note de livraison : le corps retenu est
`total + 1 + PROTECTED_OUTBOUND_SLOTS.saturating_sub(outbound) <= MAX_PEERS`,
où `total + 1` est la table **une fois** cette entrée admise. Un corps de la
forme `(total - outbound) + reserve < MAX_PEERS` ne satisfait pas l'invariant
ci-dessus (contre-exemple : `total = 123, outbound = 2` est accepté alors que
`(121) + 8 = 129 > 128`). Vérifié par boucle exhaustive sur tout l'espace
`(total, outbound)` dans `test_protected_outbound_slots`.*

`PROTECTED_OUTBOUND_SLOTS = 8` (constante **existante**, `:39`, déjà couverte
par `test_diversity_constants`). Justification :

* `8 = 2 × MAX_PEERS_PER_SUBNET` : la réserve couvre **deux groupes réseau
  complets**, donc au moins deux chemins indépendants même quand l'entrée est
  saturée à 4 par groupe.
* `8 / 128 = 6,25 %` de la table réservée : le coût en capacité entrante est
  négligeable.
* Elle est **inférieure** à `MAX_PEERS / 8` et **supérieure** à
  `MAX_PEERS_PER_SUBNET`, déjà exigé par `test_diversity_constants`.

Suivi directionnel : `outbound_sessions: Arc<RwLock<HashSet<SocketAddr>>>`.
Écrit à deux endroits seulement — insertion dans `connect_to_peer_inner`,
retrait par le `spawn` qui enrobe `handle_peer`. Aucun paramètre nouveau de
`handle_peer`, aucune table d'adresse parallèle (l'état de *session* vit avec
les sessions).

## 13.3 Sélection sortante

```rust
fn select_outbound<R: Rng + ?Sized>(
    ordered: &[SocketAddr],          // ordre Phase 2A : connues, puis seeds
    seed_tail: &HashSet<SocketAddr>, // lesquelles de `ordered` sont ces seeds
    entries, scores, connected, limit, now_unix, rng
) -> Vec<SocketAddr>
```

*Note de livraison : la signature reçoit `ordered` + `seed_tail` plutôt que
`(…, local, seeds)`. `P2PNetwork::redial_candidates` doit rester en
production — le remplacer entièrement aurait laissé une fonction de prod non
appelée, donc un warning `dead code` nouveau. `redial_candidates` construit
l'ordre, `select_outbound` le réordonne ; l'invariant « connues avant seeds »
est préservé par construction. Voir `AETHER_PHASE2_ECLIPSE_RESISTANCE.md` §4.3.*

Deux phases, afin de préserver l'invariant 2A « connues avant seeds » :

1. **Phase connues** — candidats = `entries` hors local, hors déjà connectés,
   hors bannis. Poids :

   ```
   w = clamp(quality
           + ANCHOR_SELECT_BONUS        si anchor
           + RECENT_SUCCESS_BONUS       si last_success dans RECENT_PEER_WINDOW_SECS
           - GROUP_OVERREPRESENTATION_PENALTY × (connectés dans le même groupe)
           + MIN_SELECT_WEIGHT, 0, ..)
   ```

   Tous les coefficients sont des **fractions de `PEER_SCORE_INITIAL`** (100),
   de sorte que la qualité — qui démarre exactement à `PEER_SCORE_INITIAL` —
   reste le terme dominant et qu'aucune constante ne soit arbitraire :

   | constante | valeur | justification |
   |---|---|---|
   | `ANCHOR_SELECT_BONUS` | `PEER_SCORE_INITIAL / 2` = 50 | un anchor est une adresse que nous avons **déjà** atteinte et volontairement retenue ; il doit l'emporter sur un candidat inconnu, sans l'emporter sur l'écart sain/échouant |
   | `RECENT_SUCCESS_BONUS` | `PEER_SCORE_INITIAL / 4` = 25 | un succès < 24 h est une preuve fraîche ; moitié moindre que l'anchor, qui est une preuve *persistée* |
   | `GROUP_OVERREPRESENTATION_PENALTY` | `PEER_SCORE_INITIAL / 5` = 20 | 4 pairs déjà connectés dans le groupe = −80, soit ×5 de moins de chance qu'un candidat de qualité égale dans un groupe vide |
   | `MIN_SELECT_WEIGHT` | 1 | un candidat jamais essayé ne doit jamais avoir un poids nul : on doit **toujours** pouvoir essayer quelque chose |
   | `MAX_CANDIDATES_PER_GROUP` | 2 | **la moitié** de `MAX_PEERS_PER_SUBNET` (4). Un round de 32 dials couvre donc ≥ 16 groupes quand le pool le permet, et deux rounds consécutifs peuvent encore compléter un groupe jusqu'à son plafond de sessions |

   Tirage **pondéré sans remplacement** via `rand::distributions::WeightedIndex`
   sur un RNG injecté. En production : `StdRng::from_entropy()`. En test :
   `StdRng::seed_from_u64(n)` → reproductible.
   Quota par round : `min(MAX_CANDIDATES_PER_GROUP, MAX_PEERS_PER_SUBNET −
   connectés_dans_le_groupe)`. Quota à 0 ⇒ le groupe est écarté du round.

2. **Phase seeds** — les seeds non déjà retenus, dans leur ordre de
   configuration, **après** toutes les candidats connues, soumis au même quota
   de groupe. Jamais prioritaires, jamais exclus du round : c'est
   « sans privilège », pas « ignoré ».

**Pas de second passe de relaxation** : si le quota empêche d'atteindre
`limit`, la sélection retourne moins d'adresses. C'est le but même du
scénario B — préférer manquer des slots à les remplir avec un seul groupe. Le
progrès est assuré car le quota se réévalue chaque round à partir des sessions
déjà ouvertes.

## 13.4 Rotation

**Décision : rotation de la *sélection*, pas de la session forcée.**

Motifs, tous explicités dans le dossier :

1. `P2PMessage` (`:1140`) ne contient aucune variante de déconnexion, et la
   boucle `handle_peer` détient elle-même un clone du `UnboundedSender` :
   **la codebase ne possède aucune primitive de déconnexion forcée.** L'ajouter
   signerait un nouveau verrou d'état de session et un nouveau paramètre de
   `handle_peer` pour un bénéfice non prouvé.
2. L'instruction est explicite : « Ne pas déconnecter brutalement tous les
   peers. Rotation progressive uniquement. »
3. La rotation est obtenue par trois mécanismes déjà progressifs :
   * le quota de round est **réévalué** à partir des sessions ouvertes : dès
     qu'un groupe atteint ses 4 sessions, son quota tombe à 0 et la sélection
     se déplace nécessairement ailleurs ;
   * le RNG est **re-saupoudré** à chaque round : deux rounds ne proposent pas
     les mêmes adresses au sein d'un même groupe ;
   * `MAX_REDIAL_PER_CYCLE`, le backoff et le TTL font tourner les candidats
     sur la durée.

**Test.** `test_outbound_rotation` (rounds successifs → listes différentes,
union croissante), `test_peer_group_rotation` (groupe saturé → quota 0 → la
sélection bascule).

## 13.5 Qualité d'admission PEX

```rust
fn admission_quality(source: PeerSource) -> i32 {
    PeerSource::Pex => PEX_ADMISSION_QUALITY,   // PEER_SCORE_INITIAL / 2 = 50
    _                => default_peer_quality(), // 100
}
```

Justification : `admit_peer` évicte quand `victim_quality <= incoming_quality`.
À `incoming = 100`, le bruit PEX déloge toute entrée de qualité 100. À
`incoming = 50`, il ne vise que les entrées déjà dégradées (≤ 50) ou bannies.
La valeur 50 est la **moitié** de `PEER_SCORE_INITIAL`, assez haute pour que
les adresses PEX honnêtes restent concurrentielles une fois le tableau plein
de déchets, assez basse pour qu'elles ne délogent jamais un pair que nous avons
nous-mêmes observé. Un pair PEX qui prouve sa valeur remonte par
`record_success` (+10 par succès).

**Aucune constante de production existante n'est modifiée.**

## 13.6 Purge des `scores`

Dans `refresh_and_expire` :

```rust
self.scores.retain(|a, s| self.entries.contains_key(a) || s.is_banned());
```

* Un score **banni** survit toujours ⇒ invariant 2B préservé.
* Un score non banni, dont l'adresse a disparu de `entries` et n'est pas
  connectée, est vidé : il n'a plus d'information.
* `decay_score` le recrée si l'adresse revient.

## 13.7 Métriques

Fonctions pures, sans dépendance de production nouvelle : `group_counts()` →
histogramme `NetworkGroup → usize`, consommé par un `debug!` déjà présent dans
la boucle de sélection (aucun crate ajouté, aucun compteur global).

---

# 14. Tests prévus

Module `phase2_eclipse_tests` (`use super::*;`), 14 tests imposés :

| Test | Propriété vérifiée | Lacune couverte |
|---|---|---|
| `test_outbound_diversity` | N candidats → ≥ K groupes distincts | L2, L4 |
| `test_same_network_group_limited` | un groupe dominant ne dépasse pas son quota de round | L4 |
| `test_multi_group_selection` | sélection multi-groupes vivante, chaque groupe dans ses bornes | L4 |
| `test_protected_outbound_slots` | invariant de réserve sortante + compteurs directionnels | L1 |
| `test_outbound_rotation` | rounds successifs ≠ ; union croissante | L9 |
| `test_bootnode_compromised` | store/anchors/dns l'emportent sur le bootnode ; seeds en queue | L3 |
| `test_seed_compromised` | un seed ne prend aucun slot au-delà de son quota | L3, L4 |
| `test_peer_store_poisoning` | table bornée, sains intacts, bruit évictable, `scores` purgée | L6, L7, L8 |
| `test_restart_under_peer_attack` | anchors restaurés prioritaire + diversité + chemins multiples | L3 |
| `test_mass_peer_loss` | après perte, sélection non vide et diverse | L2, L3 |
| `test_anchor_protection` | anchor jamais victime d'admission, jamais en queue de sélection | L3 |
| `test_low_quality_candidate_eviction` | le PEX de basse qualité ne déloge jamais un pair sain | L6 |
| `test_peer_group_rotation` | groupe saturé → quota 0 → bascule | L9 |
| `test_selection_deterministic_under_seed` | même RNG ⇒ même liste ; RNG différent ⇒ liste différente | L2 |

Aucun test existant n'est modifié. Les 5 tests legacy qui appellent
`subnet_24` (`test_subnet_24_ipv4`, `test_subnet_24_ipv6`,
`test_subnet_diversity_limit`, `test_eclipse_attack_blocked`,
`test_count_subnet_peers`) restent verts : `subnet_24` subsiste en tant que
projection de `network_group`.

---

# 15. Hors périmètre (décisions explicites)

* **Aucune primitive de déconnexion forcée** — voir 13.4.
* **Aucun plafond par source d'injection (L11)** — un tel plafond exigerait de
  distinguer une source honnête d'une source hostile, ce que le protocole ne
  permet pas. Reporté en risque résiduel plutôt qu'implémenté sous une
  constante arbitraire.
* **Aucune modification du handshake, de la bruit de nonce, de la direction,
  de la PoW ni du wire format.**
* **Aucun DHT, aucun slot « protégé » par confiance, aucun self-healing,
  aucun Tor/I2P.**
* **Aucun changement de `PEER_TTL`, `MAX_ANCHORS`, `MIN_ANCHORS`,
  `PEX_MAX_SEND`, `MAX_KNOWN_PEERS`, `MAX_PEERS`, `MAX_PEERS_PER_SUBNET`,
  `PROTECTED_OUTBOUND_SLOTS`, `MAX_REDIAL_PER_CYCLE`.**
