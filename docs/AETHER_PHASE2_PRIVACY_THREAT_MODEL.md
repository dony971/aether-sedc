# AETHER — Phase 2E : modèle de menaces confidentialité réseau

**Statut : `PRIVACY_AUDIT = COMPLETE`**

> **Ce document est une étude. Aucune ligne de code n'a été modifiée, aucune
> fonctionnalité n'a été ajoutée, aucun commit n'a été créé *par ce document*.**
>
> **Mise à jour post-2E-A :** l'étape 2E-A a été livrée **ensuite**, par un
> commit distinct — `phase2: harden network metadata privacy`
> (`2E_CODE_CHANGES = 2E-A ONLY`, `2E_COMMIT = phase2: harden network metadata
> privacy`). Le corps de cette étude (dont les tableaux d'état §6) décrit
> l'état **à la fin de l'audit, avant** ce commit : `2E_CODE_CHANGES = NONE` et
> `2E_COMMIT = NONE` qui s'y trouvent sont des valeurs **historiques**, pas
> l'état actuel. Preuves, limites et coût mesuré de 2E-A :
> `docs/AETHER_PHASE2_METADATA_HARDENING.md`.
>
> **Ce document ne conclut jamais « Aether est anonyme ».** Le terme
> **ANONYMAT** y est réservé à un mécanisme réellement étudié, implémenté et
> testé — ce qui n'est le cas d'aucun mécanisme aujourd'hui
> (`ANONYMITY_CURRENT = NONE`). 2E-A n'y change rien.

Branche : `dev/phase2-decentralized-network`
HEAD au moment de l'étude : `c9c44d0 phase2: add peer self-healing`
RELEASE figée : `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316`
Déploiement : **aucun** (`DEPLOYMENT = NONE`)
`2E_CODE_CHANGES = NONE` — `2E_COMMIT = NONE` *(valeurs de l'audit, voir ci-dessus)*

Documents voisins :

* `docs/AETHER_NETWORK_PRIVACY_ROADMAP.md` — séquence proposée et tests futurs (étapes 13-14).
* `docs/AETHER_TRANSPORT_COMPARISON.md` — TCP / Tor / I2P / abstraction (étapes 9-12).
* `docs/AETHER_PHASE2_SELF_HEALING_AUDIT.md`, `docs/AETHER_PHASE2_ECLIPSE_AUDIT.md` — phases 2D et 2C.

---

# 1. Inventaire actuel (étape 1)

Audit du code réseau existant : `src/p2p.rs`, `src/config.rs`, `src/node.rs`,
`src/rpc.rs`, plus les tests Phase 2 (`phase2_decentralized_tests`,
`phase2_eclipse_tests`, `phase2_self_healing_tests`, `bootstrap_phase1`).

## 1.1 Le handshake — 69 octets en clair

`handshake()` (`src/p2p.rs:2942`) émet **dans cet ordre, en clair**, avant
toute dérivation de clé :

| Offset | Taille | Champ | Source |
|---|---|---|---|
| 0 | 4 | `HANDSHAKE_MAGIC` = `0x41 0x45 0x54 0x48` (`"AETH"`) | `:26`, `:2950` |
| 4 | 1 | `P2P_PROTOCOL_VERSION` = **3** | `:1211`, `:2951` |
| 5 | 32 | `GENESIS_HASH` du réseau | `:2952` |
| 37 | 32 | clé publique **éphémère** X25519 | `:2953` |

`HANDSHAKE_FRAME_LEN = 4 + 1 + 32 + 32 = 69` (`:1213`).

**Conséquences directes, toutes vérifiables dans le code :**

1. Le réseau est **identifiable sur le fil** par n'importe quel observateur :
   la séquence `AETH` + version + hash de genesis est une signature de
   protocole non obfusquée. Aucun domaine-frontière, aucun padding.
2. `verify_handshake_identity` (`:2915`) ne contrôle que magie / version /
   genesis. **Aucune signature, aucun identifiant de long terme, aucun
   transcript signé.** L'échange X25519 est donc **non authentifié** : un
   attaquant actif sur le chemin peut terminer un handshake de chaque côté et
   détenir deux clés de session (voir §2.A et §6).
3. La clé publique éphémère est **neuve à chaque session** et le secret
   associé est consommé par `diffie_hellman` (`:2970`) : deux sessions ne
   partagent aucun matériau dérivable.

## 1.2 Le frame — longueur et nonce en clair

Après handshake, chaque message suit ce format (`:3053-3066` en émission,
`:3111-3199` en réception) :

| Offset | Taille | Champ | En clair ? |
|---|---|---|---|
| 0 | 4 | `total_len` = `12 + ciphertext.len()`, u32 BE | **OUI** |
| 4 | 8 | compteur d'anti-replay, u64 BE, strictement croissant | **OUI** |
| 12 | 1 | octet de direction (`0x01`/`0x02`, dérivé de l'ordre des clés éphémères) | **OUI** |
| 13 | 3 | zéros réservés | **OUI** |
| 16 | `total_len − 12` | ChaCha20-Poly1305 (AAD vide) | non |

**Il n'y a ni padding, ni chaff, ni couverture de trafic, ni jitter.** Le
format de frame est intégralement déterministe.

Ce qui reste donc visible **après** chiffrement, y compris pour un simple
observateur passif qui n'est pas un pair :

* les bornes exactes de chaque message et donc leur **taille** ;
* l'**ordre**, le **nombre** et la **cadence** des messages par direction ;
* le compteur par direction, donc toute perte/réordonnancement ;
* la direction « clé basse / clé haute » de chaque extrémité.

## 1.3 Les messages chiffrés

`enum P2PMessage` (`:1846`) — les 9 variantes sont **toutes** chiffrées après
handshake : `Transaction`, `Inventory`, `GetData`, `GetInventory { tips }`,
`SyncRequest`, `SyncResponse`, `Ping`, `Pong`, `Peers(Vec<SocketAddr>)`.

Aucune de ces charges utiles n'est lisible par un observateur passif.

## 1.4 Tâches périodiques (empreinte temporelle)

| Période | Tâche | Réseau ? | Référence |
|---|---|---|---|
| 15 s | **PEX** : jusqu'à `PEX_MAX_SEND = 64` adresses à **chaque** pair connecté | **oui** | `:71`, `:2717` |
| 30 s | maintenance du peer store (horloge TTL + sweep) | non (local) | `:2180` |
| 120 s | re-résolution des DNS seeds | **oui**, seulement si `dns_seeds` non vide (par défaut vide) | `:2657` |
| 300 s | purge du cache `seen_transactions` | non (local) | `:2592` |
| 60 s | flush du peer store sur disque (`PEER_STORE_FLUSH_INTERVAL`) | non (local) | `:1252` |
| à chaque handshake | `GetInventory { tips }` **puis** `SyncRequest` | **oui** | `:3078`, `:3091` |
| à chaque `SyncRequest` reçu | réponse = **l'intégralité** des hashs du DAG | **oui** | `:3461-3470` |

Points remarquables :

* **La cadence PEX de 15 s est uniforme, sans aléa.** Elle agit de fait comme
  keepalive : `Ping` n'est **jamais** émis (seul un récepteur existe, `:3584`),
  et `FRAME_TIMEOUT = 30 s` (`:1193`) déconnecte un pair silencieux. Un
  observateur peut donc reconnaître un nœud Aether à son battement de 15 s.
* **`SyncRequest` → inventaire complet du DAG, non borné.** Le préfixe de
  longueur en clair vaut approximativement `32 × (nombre de transactions) +
  surcoût bincode`. Un observateur (passif **ou** pair) mesure ainsi la
  **taille du DAG** du nœud sans déchiffrer quoi que ce soit. Le commentaire
  `:3458` le dit explicitement : « 10k hashes each on a big DAG ».

## 1.5 Persistances (disque)

| Artefact | Chemin | Format | Contenu réseau | Chiffré ? |
|---|---|---|---|---|
| Peer store | `<data_dir>/known_peers.json` | JSON, `version = PEER_STORE_VERSION` | `addr` (IP:port), `source`, `first_seen`, `last_success`, `attempts`, `failures`, `quality`, `anchor` | **non** |
| Journal | `<data_dir>/logs/node.log` (+ `.1`…`.5`) | texte, rotation 10 MiB × 5 | bannières de démarrage (version/commit/genesis/ports) + **25 énoncés réseau** contenant `addr` | **non** |
| Base Sled | `<data_dir>/sled_db` | bincode | transactions (clé publique, montants, timestamps), balances | non (données publiques par conception) |
| Wallet | `<data_dir>/*.json` | chiffré Argon2id | clés privées | **oui**, et la sauvegarde sans mot de passe est **refusée** (`wallet.rs:414`) |

Écriture atomique du peer store : `.json.tmp` puis `rename` (`:2145-2153`).
Aucun `chmod` restrictif n'est posé : les permissions sont celles du `umask`.

## 1.6 RPC / métriques / logs

* **RPC = HTTP clair** (axum, `start_rpc_server` `:2271`). **Aucun TLS**
  (recherche `TlsAcceptor`/`rustls`/`https` : aucun résultat).
* Bind par défaut `127.0.0.1` (`config.rs:58`) ; tout bind non-loopback
  déclenche un `warn!` explicite (`node.rs:86`).
* `aether_getDagStats` expose `connected_peers: u32` — **un compteur, jamais
  d'adresse** (`rpc.rs:1765`, `:1778`).
* `/metrics` expose `aether_peers_connected` — compteur (`rpc.rs:2871`).
* L'adresse du client RPC (`ConnectInfo<SocketAddr>`) sert **uniquement** de
  clé de rate-limiteur en mémoire (`rpc.rs:2394`) : ni loggée, ni retournée.
* Aucun endpoint RPC ne renvoie une liste d'adresses de pairs.

## 1.7 Table DATA / SOURCE / DESTINATION / VISIBLE_TO / PERSISTED / ENCRYPTED / CORRELATABLE / RISK

| # | DATA | SOURCE | DESTINATION | VISIBLE_TO | PERSISTED? | ENCRYPTED? | CORRELATABLE? | RISK |
|---|---|---|---|---|---|---|---|---|
| 1 | IP publique + port d'émission (TCP) | socket OS | pair | pair, **et tout observateur sur le chemin** | non | non (couches IP/TCP) | **oui** — c'est la clé d'identité du nœud | **CRITIQUE** |
| 2 | Port d'écoute fixe (`0.0.0.0:25565`, `node.rs:578`) | config | pairs entrants | pairs entrants | config | non | oui — distingue « nœud » de « client » | **ÉLEVÉ** |
| 3 | Magie `AETH` + version 3 + genesis (69 o) | `p2p.rs:2950-2953` | pair | pair **+ observateur passif** | non | **non** | oui — identifie Aether et la version | **ÉLEVÉ** |
| 4 | Clé X25519 éphémère (32 o) | `p2p.rs:2953` | pair | pair + observateur | non | non | **non** — neuve par session | faible |
| 5 | `total_len` (4 o, u32 BE) | `p2p.rs:3055` | pair + réseau | pair **+ observateur passif** | non | **non** | **oui** — taille = type de message ≈ taille de DAG / de tx | **ÉLEVÉ** |
| 6 | Compteur + direction (12 o) | `p2p.rs:3061`, `:3049` | pair + réseau | pair + observateur | non | **non** | **oui** — nombre/ordre de messages | **MOYEN** |
| 7 | Contenu des 9 `P2PMessage` | `p2p.rs:1846` | tous les pairs | **tous les pairs connectés** (ils déchiffrent aussi) | non | **oui** ChaCha20-Poly1305 | oui **entre pairs** | voir §4 |
| 8 | **Liste d'adresses de pairs** (PEX, 64 / 15 s) | `p2p.rs:2733-2739` | **chaque pair connecté** | pair destinataire | indirect (peer store du pair) | en transit oui | **oui** — divulgation du voisinage | **CRITIQUE** |
| 9 | Adresse IP du pair lui-même | TCP | pair | le pair | indirect | non | oui | **CRITIQUE** (inévitable en TCP) |
| 10 | Ensemble des hashs du DAG (taille ≈ 32·N) | `p2p.rs:3461` | pair demandeur | pair + observateur (via `total_len`) | non | en transit oui, **taille non** | **oui** — taille/vétusté du DAG | **MOYEN** |
| 11 | Tips courants (`GetInventory`) | `p2p.rs:3078` | pair | pair | non | oui | oui — position dans le DAG | **MOYEN** |
| 12 | Transaction : `sender` = 32 o de clé publique, `receiver`, `amount`, `fee`, `timestamp` **ms**, `account_nonce`, `parents`, `signature` | `transaction.rs` | pair, puis **le registre public** | **tout le monde, définitivement** | **oui** (Sled + registre) | au transport oui, **au registre non** | **oui**, par conception du registre | **ÉLEVÉ** (registre) |
| 13 | IP:port des pairs connus + métadonnées | `to_store()` `:1707` | disque local | accès local au disque | **oui**, JSON clair | **non** | oui | **ÉLEVÉ local** |
| 14 | IP de pairs dans les journaux | 25 énoncés `p2p.rs` | `logs/node.log` | accès local | **oui**, texte clair | **non** | oui | **MOYEN local** |
| 15 | `connected_peers` (compteur) | `rpc.rs:1765` | client RPC / scrapeur | client RPC (loopback par défaut) | non | HTTP clair | faible | **FAIBLE** |
| 16 | IP du client RPC | axum `ConnectInfo` | clé de rate-limiteur | mémoire vive seulement | non | non | faible | **FAIBLE** |
| 17 | Liste des bootnodes (config + log) | `config.rs:62-66`, `node.rs:93` | local | local | **oui** (TOML clair) | non | oui | **FAIBLE** |
| 18 | Demande DNS de seed | `p2p.rs:2620` | résolveur + NS autoritaire | résolveur, NS, observateur | non | non (UDP/DNS) | **oui** — révèle « je démarre Aether » | **MOYEN** (si configuré) |
| 19 | Clés de wallet | wallet | disque | local | oui | **oui** Argon2id | — | hors périmètre réseau |

---

# 2. Modèle de menaces (étape 2)

Six adversaires, du moins au plus puissant. Chaque affirmation est reliée à
une ligne de code ou à une propriété du protocole ; là où aucune preuve n'est
possible, c'est dit explicitement.

## A — Observateur réseau passif (PASSIVE NETWORK OBSERVER)

**Capacité** : écoute sur un lien, un FAI, un point d'échange, ou un nœud en
amont d'une session. **Ne modifie rien.**

**Ce qu'il voit, preuve à l'appui :**

| Observation | Preuve |
|---|---|
| IP source et destination, ports, durée de session, sens d'ouverture | TCP/IP, hors du périmètre du chiffrement |
| Que le trafic est Aether, et quelle version, et quel réseau | 69 o en clair contenant `AETH` + `3` + `GENESIS_HASH` (`:2950-2953`) |
| Chaque message : début, fin, taille, ordre, cadence | préfixe `u32` + 12 o de nonce en clair (`:3055`, `:3061`) |
| Le battement PEX de 15 s et son nombre de destinataires | `:2717`, non chiffré (bornes visibles) |
| La taille du DAG du nœud à chaque handshake | `SyncRequest` → inventaire complet, longueur en clair (`:3461`) |
| Les reconnexions, le redial, le bootstrap | idem |
| Le nombre de pairs du nœud (par dénombrement de sessions) | table des connexions |

**Ce qu'il ne voit PAS** : le contenu des 9 `P2PMessage` (ChaCha20-Poly1305),
et donc les transactions, les listes PEX, les tips.

**Conclusion A** : l'observateur passif obtient une **cartographie complète du
comportement** (qui parle à qui, quand, combien, quelle taille) et une
**identification certaine du protocole**, mais pas le contenu. C'est la
distinction centrale entre `ENCRYPTION_CURRENT` et `METADATA_PRIVACY_CURRENT`.

## B — Observateur pair unique (SINGLE PEER OBSERVER)

**Capacité** : contrôle un pair connecté à la victime. Il déchiffre tout ce
que la victime lui envoie.

**Ce qu'il apprend, preuve à l'appui :**

1. **L'IP publique de la victime** — le socket TCP lui-même.
2. **L'intégralité des transactions** relayées : `sender` (32 o de clé
   publique), `receiver`, `amount`, `timestamp` **à la milliseconde**,
   `account_nonce`, `signature` (`transaction.rs:91-95`).
3. **Jusqu'à 64 adresses du voisinage de la victime toutes les 15 s**
   (`:71` + `:2733`), assaisonnées de `first_seen` implicite par l'âge.
4. **L'ensemble des hashs du DAG** de la victime, et donc sa taille
   (`:3461`).
5. **Ses tips**, donc sa position dans le DAG (`:3078`).
6. **Les instants exacts** où elle émet, reçoit, se reconnecte.

**Ce qu'il n'apprend pas** : ce que la victime envoie aux *autres* pairs (les
sessions sont indépendantes), ni les métadonnées des sessions qu'il ne tient
pas.

**Limite de preuve** : on ne peut pas affirmer depuis le code seul combien de
voisinage un pair obtient *en pratique* (cela dépend du chevauchement des
échantillons PEX). On peut affirmer la **borne** : 64 par envoi, 4 envois par
minute, par pair.

## C — Plusieurs pairs (MULTIPLE PEERS)

**Capacité** : contrôle *k* pairs, éventuellement choisis.

**Corrélations possibles — chacune justifiée :**

| Canaux | Mécanisme | Preuve |
|---|---|---|
| **IP** | chaque session révèle l'IP de la victime ; *k* sessions → confirmation, et si la victime change d'IP, les *k* pairs la voient | TCP |
| **Timing** | relay immédiat sans jitter (`:3249-3258`) : l'écart entre l'arrivée chez le pair 1 et le pair 2 est la latence inter-sauts, de l'ordre du milliseconde | code |
| **Propagation** | chaque nœud re-relaie **à tous** ses pairs sauf l'émetteur, puis **encore à tous** après validation (`rpc.rs:1185`) : la transaction traverse le graphe en rafale | code |
| **Messages** | `total_len` en clair → taille de la transaction identique à chaque saut ; l'observateur peut apparier les rafales entre ses *k* sessions | `:3055` |
| **Connexions** | le PEX de la victime contient les adresses des pairs 2…*k* : intersection des listes → le graphe se révèle | `:584-619` |

**Attaque d'intersection PEX** : si les *k* pairs reçoivent chacun un échantillon
de 64 adresses tirés du même `entries`, l'intersection de leurs listes échantillonne
le voisinage réel ; plus *k* est grand, plus l'échantillon approche le voisinage
complet. **Borne de preuve** : le code garantit `limit ≤ 64` par envoi
(`pex_sample`, `:584`), et que le destinataire lui-même, les adresses qu'il nous a
apprises et les entrées âgées de plus de 24 h sont retirées (`:596-606`). Il ne
garantit **pas** que les *k* échantillons sont disjoints — donc l'intersection
n'est pas bornée par le code.

**Inference de premier-vu (ingress inference)** : voir §4, c'est le risque le
plus sérieux de cette catégorie.

## D — Bootstrap malveillant (MALICIOUS BOOTSTRAP)

Phase 2D a rendu le bootnode **non essentiel** (il est en dernier recours,
`plan_recovery`), et Phase 2A a supprimé la dépendance au démarrage. Cela ne
supprime pas ce qu'un seed apprend **au premier contact**.

`initial_dial_sweep` (`:2048`) :

```rust
for seed in &self.config.bootnodes { self.connect_to_peer(*seed).await; }   // d'abord
for addr in self.outbound_candidates(MAX_REDIAL_PER_CYCLE).await { ... }    // ensuite
```

**Un nœud dont le store est vide dial TOUTES les bootnodes AVANT ses pairs
restaurés.** Avec la configuration par défaut, ce sont les trois adresses
`103.102.135.123/124/125` — **le même /24** (`config.rs:62-66`).

Ce que le seed apprend, dans l'ordre :

1. l'IP publique et le port d'émission du nouveau nœud ;
2. que c'est Aether, version 3, réseau genesis donné (69 o en clair) ;
3. que c'est un **nouveau** nœud (il se présente avec `GetInventory` + `SyncRequest`
   avant d'avoir reçu PEX) ;
4. la taille de son DAG ;
5. **15 s plus tard, jusqu'à 64 de ses adresses** — mais un nœud neuf n'en a
   pas encore, donc à froid le seed apprend surtout 1-4 ;
6. toutes les transactions que le nœud relaye sur cette session, pendant
   toute la durée de la session.

**Corrélation bootstrap → trafic ultérieur** : oui, tant que la session dure.
Le seed voit tout ce qui transite sur *sa* session. Il ne voit pas les autres
sessions du nœud. Après rétablissement d'un store (et donc en régime
permanent), le seed n'est plus dialé qu'en dernier recours — mais reste
dialé s'il est le seul dans le tier 3 et que tier 1+2 sont vides.

## E — Eclipse + analyse de trafic (ECLIPSE + TRAFFIC ANALYSIS)

Phase 2C borne les sessions par groupe réseau (`MAX_PEERS_PER_SUBNET = 4`),
par sélection (`select_outbound`) et par qualité ; Phase 2D ajoute la
reconstruction. Ce que cette **combinaison** permet :

* Un adversaire qui occupe déjà les quotas de groupe observé voit **tout** le
  trafic de la victime vers ces sessions : c'est le pair B, généralisé.
* L'eclipse n'a pas besoin de lire le chiffrement pour être utile : elle donne
  un **point d'observation garanti** sur le voisinage choisi par la victime.
* Inversement, la diversité 2C **réduit** le nombre de points d'observation
  qu'un adversaire peut acquérir : c'est un bénéfice de sécurité *et* de
  confidentialité, même s'il n'a jamais été facturé comme tel.

**Limite de preuve** : la 2C documente les quotas ; elle ne documente pas et
ne mesure pas la confidentialité. On ne peut pas affirmer depuis le code
qu'un adversaire « peut » ou « ne peut pas » reconstituer le graphe — il faut
une mesure sur réseau réel, qui n'existe pas (voir §14 de la roadmap).

## F — Observateur global (GLOBAL OBSERVER)

**Capacité** : observe une grande partie des liens TCP du réseau Aether.

**Ce qui reste corrélable, avec preuve :**

* **Le graphe de connexions en entier.** Chaque session est un flux TCP nu,
  sans chaff (`:3053-3066`) : degrés, clusters, révélations d'IP sont lisibles
  directement.
* **La synchronisation des rafales.** Le relay est immédiat et non aléatoire
  (`:3249-3258`) ; une même transaction produit des rafales de taille quasi
  identique chez tous les voisins presque simultanément. L'observateur global
  qui peut *aussi* voir le registre public (il est public) dispose d'une
  signature de taille en millisecondes.
* **Les nouveaux nœuds**, à la signature `AETH` + `GetInventory` + requête
  d'inventaire complet.

**Ce qui reste protégé** : le contenu des messages (ChachaCha20-Poly1305) et
donc les adresses de pairs *transportées par PEX*, les montants, les
destinataires.

**Ce qu'on n'affirme PAS** : on n'affirme **pas** qu'un observateur global
peut ou ne peut pas résoudre l'origine d'une transaction. Cela dépend du
nombre de ses points d'observation et de la topologie réelle du réseau,
grandeurs qui ne sont mesurables que par expérience. La littérature
technique établit que la propagation « flood sans délai » est vulnérable à
l'inférence de premier-vu (Biryukov, Khushrush, Zimmermann, CCS 2014 ;
travaux Dandelion/Dandelion++ sur la propagation en deux phases ; Erlay sur
le fanout limité). **Ce document reprend ce résultat général sans prétendre
quantifier son application à Aether.**

---

# 3. METADATA_LEAKAGE_MATRIX (étape 3)

| METADATA | EXPOSED_NOW | PROTECTION | ATTACK | MITIGATION | LIMITATION |
|---|---|---|---|---|---|
| IP source / destination | **oui**, intégralement | aucune (hors du périmètre du transport actuel) | identification, suivi, géolocalisation, appariement au registre | Tor / I2P / proxy (§9-11 de `AETHER_TRANSPORT_COMPARISON.md`) | tout transport « direct » révèle l'IP ; seule une couche d'anonymat change cela |
| Port d'écoute fixe (25565) | **oui** | aucun | distinguer les nœuds des clients ; balayage ciblé (cf. Trawling, Kappos et al., USENIX 2018) | port aléatoire configurable ; Tor/I2P | un port configurable ne change pas l'IP |
| Identification du protocole (`AETH`+version+genesis) | **oui**, 69 o | aucun | ciblage/isolement du trafic Aether, discrimination au FAI | obfuscation de magie ; padding ; version | nécessite un changement de wire format (bump `P2P_PROTOCOL_VERSION`) |
| Taille de chaque message (`u32`) | **oui** | aucun | inférence du type de message, de la taille du DAG, de la taille d'une transaction | agrégation de messages, padding par paliers, messages multiples par frame | le padding coûte de la bande ; un palier trop fin ne masque rien |
| Compteur + direction (12 o) | **oui** | aucun | dénombrement exact de messages, ordre, perte | compteur opaque ou supprimé en faveur d'un compteur TCP | l'anti-replay actuel *exige* un compteur (`last_recv_counter`, `:3175`) |
| Timing / cadence | **oui** | aucun | analyse de propagation, reconnaissance du battement PEX 15 s | jitter, bruit de fond, fréquence PEX aléatoire | le bruit de fond consomme de la bande ; `FRAME_TIMEOUT` impose un minimum de trafic |
| Nombre de pairs | **oui** (dénombrement) | aucun | estimation de la centralité | non applicable directement | — |
| Durée des sessions / patterns de reconnexion | **oui** | aucun | corrélation d'identité à travers redémarrages | jitter de redial, aléa de `RECOVERY_INTERVAL` | la Phase 2D a déjà une cadence fixe de 5 s |
| Voisinage (adresses PEX) | **oui, auprès de chaque pair** | chiffré au transport, **mais remis en clair au destinataire** | divulgation de voisinage, intersection de graphe | PEX différentiel chiffré par pair (échantillons disjoints) ; réduire `PEX_MAX_SEND` et la fréquence | borne : 64 / 15 s actuelle |
| Ensemble des hashs du DAG | contenu oui, **taille en clair** | chiffré au transport | mesure de la taille/vétusté du DAG par tout observateur | inventaire paginé/borné | `MAX_INV_ITEMS = 1000` borne déjà la *réponse*, pas l'annonce |
| Bootstrap (quelle seed, quand) | **oui** | aucun | identification des nouveaux nœuds ; seed voit tout premier contact | store déjà peuplé (Phase 2B/2D) ; DNS seeds multiples ; Tor | un nœud **à froid** n'a pas d'alternative |
| Requêtes DNS de seed | oui si configuré | aucun (UDP) | « l'opérateur X démarre Aether » | résolveur local / DoH ; IP directes en config | par défaut `dns_seeds` est vide → pas de requête |
| IP:port + métadonnées sur disque | **oui**, JSON clair | aucun | accès local au disque, sauvegarde, support volé | chiffrement du peer store ; permissions 0600 | le chiffrement au repos demande une clé d'opérateur |
| IP dans les journaux | **oui**, texte clair | aucun | même | anonymisation des adresses dans les logs ; niveau de log | les logs servent au diagnostic |
| Compteur `connected_peers` en RPC/métrique | **oui** | bind loopback par défaut | divulgation de l'activité si le RPC est exposé | rester en loopback (déjà le défaut) | — |
| IP du client RPC | mémoire seulement, jamais loggée | bind loopback | — | — | — |
| Transaction : clé publique → adresse | **oui**, registre permanent | signée Ed25519, pas de secret | lien entre transactions d'un même émetteur, **par conception du registre** | voir §2E-D/E de la roadmap | hors périmètre du transport |
| `timestamp` ms + `account_nonce` | **oui**, registre permanent | aucun | appariement horodatage réseau ↔ registre | horodatage flouté ou arrondi | changer le champ touche au consensus |

---

# 4. Propagation des transactions (étape 4)

## 4.1 Chemin exact

**Origine locale (RPC / CLI / GUI)**

1. `process_transaction` valide (porte pure : PoW + signature), place en
   mempool, **puis** `broadcast_transaction(tx)` — `rpc.rs:1185`.
2. `broadcast_transaction` (`p2p.rs:3831`) marque `seen` **puis envoie
   `P2PMessage::Transaction` à TOUS les pairs, sans délai, sans sélection,
   sans sous-ensemble.**

**Réception d'un pair**

1. `bincode::deserialize` (`:3236`) ;
2. `insert_seen` (`:3238`) — marque vu **avant** tout le reste ;
3. `tx_channel.send(tx)` (`:3247`) — vers le pipeline de validation ;
4. **relais immédiat** `P2PMessage::Transaction` à **tous les pairs sauf
   l'émetteur** (`:3249-3258`).

**Puis**, en aval, le consommateur de `tx_channel` (`node.rs:634`) appelle
`process_transaction(..., "P2P", ValidationMode::Historical)` qui, si la
transaction passe les portes, rappelle `broadcast_transaction`
(`rpc.rs:1185`) — **cette fois vers TOUS les pairs, y compris l'émetteur**.

## 4.2 Réponses aux questions de l'étape 4

| Question | Réponse, avec preuve |
|---|---|
| À qui la transmet-il ? | **à tous ses pairs connectés**, sauf l'émetteur au premier passage (`:3253-3256`), puis à **tous** au second (`rpc.rs:1185`) |
| Avec quel délai ? | **aucun** — pas de `sleep`, pas de timer, pas de jitter entre `insert_seen` et l'envoi (`:3238-3258`) |
| Selon quelle sélection ? | **aucune** — itération complète de la table `peers` |
| Immédiatement ou après temporisation ? | **immédiatement**, et **sans attendre le résultat de la validation** (le relais dépend uniquement d'une désérialisation réussie) |
| Comportement corrélable ? | **oui fortement** : rafale unique, sans bruit, taille ≈ taille de la transaction, à chaque saut |
| Le premier peer à propager peut-il être identifié ? | **oui en principe** : c'est le seul nœud dont les pairs reçoivent la transaction *directement de lui* ; chaque nœud retransmet une seule fois (déduplication `seen_transactions`, `:3227-3233`), donc le graphe de première-vue pointe vers l'origine |

## 4.3 Les quatre risques demandés

**First-seen inference.** Le dédup `seen_transactions` fait que chaque nœud
relaie **exactement une fois**. Un adversaire tenant un sous-ensemble *S* des
pairs observe, pour chaque candidat *v*, l'instant auquel *S* reçoit la
transaction depuis *v*. L'origine est le nœud minimisant l'instant d'arrivée
chez tous les membres de *S*. C'est exactement le schéma établi dans la
littérature (Biryukov et al., CCS 2014) et la raison d'être de
Dandelion/Dandelion++ (phase « stem » discrète puis « flare »). **Le code
Aether comporte aucune contre-mesure.**

**Timing correlation.** Aucun jitter : l'écart de signature entre deux voisins
est la latence de bout en bout. Un adversaire avec *k* paires de mesures
dispose de *k* contraintes horaires. Aucune contre-mesure dans le code.

**Ingress inference.** L'émetteur local est identifié de deux manières
indépendantes : (i) c'est le nœud dont les pairs le reçoivent en premier ;
(ii) côté pair, le contenu de la transaction contient `timestamp` en
**millisecondes** posé à la création (`main.rs:518-525`, `rpc.rs:2195`) — un
pair qui reçoit la transaction *t* ms après son horodatage a une mesure directe
de sa proximité avec l'origine. **Réserve importante** : le chemin P2P valide
en `ValidationMode::Historical`, qui **ne contrôle pas la fenêtre de
timestamp** (`validation.rs:194`), donc `timestamp` n'est pas un oracle
fiable pour un émetteur malveillant ; pour un émetteur honnête, il reste
exact.

**Propagation fingerprinting.** La forme de propagation est une rafale
uniforme : même taille, même absence de délai, même fanout complet. Il n'y a
ni trickle (envoi progressif), ni palier aléatoire, ni sous-ensemble de
voisins, ni messages de couverture. La signature est donc stable et
reproductible.

## 4.4 Ce qui n'a **pas** été fait

Aucune modification de la propagation n'a été effectuée. Les observations
ci-dessus alimentent la étape **2E-D** de la roadmap, qui reste **non
implémentée**.

---

# 5. Pseudonymity (étape 5)

## 5.1 Ce qui constitue aujourd'hui l'identité d'un pair

| Candidat | Présent dans le protocole ? | Preuve |
|---|---|---|
| `SocketAddr` (IP + port) | **oui — c'est la seule identité de session** | clé de la table `peers: HashMap<SocketAddr, …>` (`:1880`) |
| IP publique | oui, côté TCP | inévitable |
| Port d'écoute fixe 25565 | oui, côté entrant | `node.rs:578` |
| Node ID / peer ID dérivé d'une clé | **non** | aucun dans `P2PMessage` ni dans le handshake |
| Clé publique de long terme du nœud | **non** | `handshake()` ne contient que la clé éphémère X25519 (`:2953`) |
| Clé de session | oui, mais **jetable** | `EphemeralSecret::random_from_rng(OsRng)` (`:2946`), consommée par `diffie_hellman` (`:2970`), jamais persistée |
| Identifiant persistant (`known_peers.json`) | oui, mais **local** | `:1711-1720` |
| Identité au registre (clé Ed25519 → adresse) | oui, **côté transaction** | `transaction.rs:91-95`, `sender = 32 premiers octets de la clé publique` (`main.rs:419`) |

## 5.2 Réponse

```
PSEUDONYMITY_CURRENT = ADDRESS-LEVEL ONLY
```

**Justification :** il n'existe **aucune identité de nœud au niveau
protocole**. Une session est identifiée par son `SocketAddr`. La seule
pseudonymie durable est au niveau **ledger** : la clé publique Ed25519 d'un
émetteur, dérivée en adresse, qui lie toutes ses transactions. Ces deux
pseudonymes **ne sont pas reliés par le protocole** (aucun message ne contient
la clé publique du nœud), mais ils **le sont par la topologie et le timing** :
un pair qui reçoit d'un nœud l'adresse d'émission et, dans la même session,
les transactions signées par une clé publique, tient les deux bouts.

```
CAN_TWO_SESSIONS_BE_LINKED = YES (réseau) / NO (cryptographie)
```

**Justification `NO` côté cryptographie :**

1. clé éphémère X25519 **neuve par session** (`:2946`) ;
2. aucune reprise de session, aucun ticket, aucun identifiant de nœud ;
3. le secret est consommé et jeté → pas de matériau réutilisable ;
4. conséquence : deux sessions successives **ne partagent aucun octet
   dérivable l'une de l'autre** au niveau de la couche de session.

**Justification `YES` côté réseau :**

1. même IP publique source (sauf changement/NAT) ;
2. fingerprint TCP identique (TTL, options, fenêtre) — propriété du système
   d'exploitation, hors du code Aether ;
3. port d'écoute fixe pour les sessions entrantes (`node.rs:578`) ;
4. voisinage partagé : le même ensemble d'adresses apparaît dans les PEX
   (`:584-619`) ;
5. signature temporelle identique : battement PEX de 15 s (`:2717`),
   `SyncRequest` à chaque handshake (`:3091`), redial de 5 s en Phase 2D ;
6. volume et taille de messages identiques (pas de padding, `:3055`).

**Conclusion : la liaison est possible sans rupture cryptographique, par
moyens purement observationnels.** C'est la distinction qu'aucun document ne
doit oublier : le chiffrement de session est solide, l'identité réseau ne
l'est pas.

---

# 6. Chiffrement (étape 6)

Le correctif Phase 1/2 — `build_nonce()` (`:2878`), `send_direction()`
(`:2888`), `nonce_collision_possible()` (`:2935`), `last_recv_counter`
(`:3105`) — **est intact et n'a pas été touché.**

## 6.1 Ce qui est chiffré / ce qui ne l'est pas

| | |
|---|---|
| **Avant handshake** | tout est en clair : magie, version, genesis, clé éphémère (69 o) |
| **Pendant** | le handshake lui-même n'a pas de couche « après » : il n'y a qu'une seule trame en clair, puis tout est chiffré |
| **Après handshake** | les 9 variantes de `P2PMessage` sont intégralement chiffrées ; **restent en clair** `total_len`, le compteur et l'octet de direction |
| **Authentification du pair** | **aucune** — pas de signature, pas de clé de long terme (`:2915` ne vérifie que magie/version/genesis) |
| **Confidentialité** | ChaCha20-Poly1305, clé dérivée `SHA256("aether-p2p-key-v1" ‖ X25519_shared)` (`:2972-2975`) |
| **Intégrité** | tag Poly1305 : toute altération du ciphertext échoue au déchiffrement (`:3207-3219`) et déclenche un `penalize_and_ban` |
| **Forward secrecy** | **oui contre un enregistreur passif** : DH éphémère-éphémère, secret consommé (`:2970`), aucune clé de long terme à compromettre. **Non contre un MITM actif**, qui possède les deux clés pendant la session |
| **Anti-replay** | compteur strictement croissant par session (`:3175-3188`), séparation de direction (`send_direction`, `:2888`) |
| **Possibilité de corrélation au niveau session** | voir §5.2 — possible, sans lien cryptographique |
| **Informations de session exposées** | le compteur et l'octet de direction, en clair |

## 6.2 `WHAT_ENCRYPTION_PROTECTS`

1. **Confidentialité du contenu des messages** contre un observateur passif
   qui n'est pas un pair : transactions, listes PEX, tips, inventaires,
   synchronisation — tous illisibles.
2. **Intégrité des trames** : Poly1305 détecte toute modification, et la
   modification déclenche un bannissement (`:3211-3217`).
3. **Anti-replay** : un enregistrement rejoué est rejeté (compteur non
   croissant → déconnexion + bannissement, `:3175-3186`).
4. **Forward secrecy contre l'enregistrement passif** : DH éphémère, secret
   détruit à la fin du handshake.
5. **Séparation des directions** : `send_direction` garantit que les deux
   émetteurs d'une session n'utilisent jamais le même octet de direction, donc
   jamais le couple (clé, nonce) deux fois (`:2888-2894`, `nonce_collision_possible`
   `:2935`).
6. **Non-liabilité entre sessions au niveau cryptographique** (clé éphémère
   neuve) — mais voir §5.2 : cela ne suffit pas à empêcher la liaison.

## 6.3 `WHAT_ENCRYPTION_DOES_NOT_PROTECT`

1. **Les adresses IP et ports** — en amont du transport.
2. **L'identification du protocole** — magie `AETH`, version 3 et hash de
   genesis en clair, 69 octets (`:2950-2953`).
3. **Les tailles, l'ordre, le nombre et la cadence des messages** — préfixe
   `u32` et nonce en clair (`:3055`, `:3061`), sans padding.
4. **Le voisinage d'un nœud** — le PEX est chiffré *en transit*, mais le
   destinataire le reçoit **en clair dans sa propre session** et le stocke en
   JSON sur son disque.
5. **La liaison de session** — voir `CAN_TWO_SESSIONS_BE_LINKED`.
6. **L'origine d'une transaction** — le relay immédiat et sans jitter est
   entièrement observable (§4).
7. **Le registre public** — clé publique, adresse, montant, `timestamp` ms
   sont publics par conception.
8. **Un attaquant actif sur le chemin (MITM)** — l'échange X25519 n'est pas
   authentifié (`:2942-2981`) : un attaquant qui intercepte termine un
   handshake de chaque côté et lit le flux. Les transactions restent
   protégées en *intégrité* par leur signature Ed25519 et leur PoW, mais la
   *confidentialité* et la *disponibilité* (censure, éclipse) lui échappent.
9. **Les artefacts locaux** — `known_peers.json` et `logs/node.log` sont en
   clair.
10. **Le RPC** — HTTP sans TLS (`start_rpc_server`, `:2271`), protégé par le
    bind loopback par défaut, pas par le chiffrement.

> **Ne jamais confondre : `ENCRYPTION_CURRENT = ChaCha20-Poly1305 (fort, avec
> les réserves de §6.3.8)` et `ANONYMITY_CURRENT = NONE`.** Le chiffrement
> empêche de *lire* ; il n'empêche pas de *voir qui parle à qui*.

---

# 7. Bootstrap privacy (étape 7)

## 7.1 Quelle IP est révélée, à quel seed, combien de temps

| Question | Réponse | Preuve |
|---|---|---|
| Quelle IP ? | l'IP publique d'émission du nœud + port éphémère | TCP |
| À quel seed ? | **toutes** les bootnodes configurées, dans l'ordre de la config, **avant** les pairs restaurés | `initial_dial_sweep` `:2048` |
| Combien de temps ? | toute la durée de la session ; une session reste ouverte jusqu'à `FRAME_TIMEOUT` d'inactivité (30 s) ou la fermeture explicite | `:1193` |
| Par défaut ? | 3 adresses **dans le même /24** : `103.102.135.123/124/125` | `config.rs:62-66` |
| Via DNS ? | jamais par défaut (`dns_seeds = Vec::new()`) ; si configuré, une requête tous les 120 s | `config.rs:67`, `:2657` |

## 7.2 Ce que le seed peut apprendre

1. IP + port d'émission, et que le contact est un **nouveau** nœud (la séquence
   `GetInventory` puis `SyncRequest` avant réception de PEX est un marqueur).
2. Version du protocole et réseau (69 o en clair).
3. Taille du DAG (réponse d'inventaire non bornée, longueur en clair, `:3461`).
4. Jusqu'à **64 adresses** de son voisinage 15 s plus tard — nul si le nœud
   est neuf.
5. Tout le contenu des sessions qu'il porte.

## 7.3 Peut-il corréler bootstrap et trafic ultérieur ?

**Oui, sur sa propre session** : il voit tout ce qui y transite, avec les
horodatages. **Non sur les autres sessions** du nœud, qu'il ne porte pas.

**Atténuations déjà en place (phases 2A/2B/2D) :**

* store persisté → au redémarrage, les pairs restaurés sont dialés via
  `outbound_candidates(MAX_REDIAL_PER_CYCLE)` après les seeds seulement si le
  store est vide ;
* Phase 2D : les seeds sont le **tier 3**, retenues tant que tier 1+2
  fournissent des candidats (`plan_recovery`) ;
* PEX vieillit à 24 h (`PEX_SHARE_MAX_AGE_SECS`, `:75`) → les adresses d'un
  seed ne sont pas éternelles ;
* `MAX_PEERS_PER_SUBNET = 4` borne le nombre de sessions qu'un même /24 de
  seeds peut obtenir.

**Non atténué :** à froid, un nœud sans store n'a **aucune** alternative aux
seeds ; et les trois seeds par défaut étant dans le même /24, **un seul
observateur de ce préfixe voit tous les nouveaux nœuds utilisant la
configuration par défaut.**

```
BOOTSTRAP_PRIVACY_RISK = MEDIUM
```

**Justification `MEDIUM` et non `HIGH`** : la divulgation est bornée dans le
temps (premier contact seulement), bornée en volume (64 adresses / 15 s, et
seulement si le nœud en a), et Phase 2D fait des seeds un dernier recours en
régime permanent. **Justification `MEDIUM` et non `LOW`** : à froid la
divulgation est totale (IP + version + taille de DAG), les trois seeds
partagent un /24, et aucun mécanisme de confidentialité de bootstrap
(aléa de sélection, connexion différée, seed multiple par préfixe distinct)
n'existe aujourd'hui.

```
BOOTNODE_METADATA_VALUE = HIGH for a first-contact observer, DECAYING thereafter
```

**Justification** : au premier contact, le seed obtient l'intégralité des
métadonnées d'identification du nouveau nœud — c'est le renseignement le plus
riche du protocole. En régime permanent, la valeur chute : le seed n'est plus
dialé qu'en dernier recours, et ne reçoit plus que le trafic que le nœud lui
confie. **La valeur n'est pas nulle** : tant qu'un nœud conserve des périodes
à store vide (installation, `--reset`, perte du disque), le seed redevient
l'interlocuteur principal.

---

# 8. Persistence privacy (étape 8)

## 8.1 Ce qui reste sur disque

`to_store()` (`:1707-1726`) écrit, pour **chaque** adresse connue :

| Champ | Signification | Sensibilité |
|---|---|---|
| `addr` | IP:port du pair | **élevée** — voisinage complet |
| `source` | `Dns / Bootnode / Restored / Pex / Anchor` | moyenne — révèle comment le nœud s'est connecté |
| `first_seen` | horodatage Unix de première découverte | moyenne — historique de vie |
| `last_success` | horodatage Unix du dernier handshake réussi | moyenne — activité récente |
| `attempts` / `failures` | compteurs | faible |
| `quality` | score 0..100 | faible |
| `anchor` | appartenance au set d'ancres | faible |

Plus, en clair dans `logs/node.log` : 25 énoncés réseau contenant l'adresse,
et les bannières de démarrage (version, commit, genesis, ports).

Plus, dans `sled_db` : l'intégralité des transactions (clés publiques,
montants, timestamps) — **données publiques par conception du registre**.

Seul artefact chiffré : le wallet (Argon2id ; la sauvegarde sans mot de passe
est refusée, `wallet.rs:414`).

```
LOCAL_METADATA_EXPOSURE = HIGH (peer IPs + timestamps + scores + logs, tous en clair ; seul le wallet est chiffré)
```

## 8.2 Risque du peer store

```
PEER_STORE_PRIVACY_RISK = MEDIUM
```

**Justification :**

* **Côté local : élevé en volume** — le fichier est le voisinage complet du
  nœud, en JSON non chiffré, avec horodatages. Tout accès au disque (malware,
  sauvegarde, support volé, autre utilisateur de la machine, réquisition) le
  restitue en clair.
* **Côté local : borné en pratique** — un peer store n'a que
  `MAX_KNOWN_PEERS = 1000` entrées, il ne contient **jamais** le montant ni la
  clé publique d'une transaction, et il est écrit atomiquement (`.tmp` +
  `rename`, `:2145-2153`) donc pas de brouillon résiduel.
* **Côté distant : faible** — le peer store n'est jamais transmis. Ce qui est
  transmis, c'est l'échantillon PEX de 64 adresses toutes les 15 s, dont la
  divulgation est couverte par `BOOTSTRAP_PRIVACY_RISK` et la matrice §3.
* **Côté accidentel : faible** — aucun endpoint RPC ne l'expose (vérifié §1.6).

**Ce qui ferait passer ce risque à `LOW`** : chiffrement du peer store au repos
ou permissions `0600` + anonymisation des adresses dans les journaux. Ces
pistes sont classées **2E-A** dans la roadmap.

---

# 9. Ce qui n'est PAS à promettre (étape 15)

Ce document **ne contient pas**, et les documents dérivés ne devront jamais
contenir, les affirmations suivantes :

| Formulation interdite | Pourquoi elle serait fausse ici |
|---|---|
| « réseau anonyme » | `ANONYMITY_CURRENT = NONE` : aucun mécanisme d'anonymat n'est implémenté ni testé |
| « IP invisible » | l'IP est en clair à chaque session ; c'est la donnée la plus exposée |
| « impossible à tracer » | le pair unique voit tout le voisinage (PEX 64/15 s) et tout le flux |
| « résistant à tout adversaire » | un observateur global voit le graphe complet : aucun chaff, aucun padding |
| « Tor résout tout » | Tor couvre l'IP de transport ; il ne couvre ni le timing, ni le registre, ni la corrélation multi-pair (voir `AETHER_TRANSPORT_COMPARISON.md` §4) |
| « le chiffrement protège l'anonymat » | il protège le **contenu**, pas la **topologie** |
| « les bootnodes ne savent plus rien » | à froid, le seed obtient IP + version + taille de DAG (`BOOTNODE_METADATA_VALUE = HIGH` au premier contact) |
| « le peer store est privé » | JSON en clair, `LOCAL_METADATA_EXPOSURE = HIGH` |
| « les transactions sont traçables/ine traçables » | le registre est public par conception ; la question du lien IP↔transaction relève de mesures non réalisées |

**Formulations à utiliser à la place** (celles que ce document applique déjà) :

* « protection contre **tel** observateur, identifié par sa capacité » ;
* « **réduction de telle fuite**, bornée par telle constante » ;
* « **limite de telle corrélation**, sous telle hypothèse » ;
* « **hypothèse** : … , **limite** : … » ;
* « mesuré », « déduit du code », ou « non mesuré — nécessite une expérience ».

---

# 10. Critère de sortie

```
PRIVACY_AUDIT               = COMPLETE

IP_PRIVACY_CURRENT          = NONE — l'IP source/destination est en clair à chaque session TCP ; aucun mécanisme de masquage n'existe dans le code (recherche SOCKS/Tor/I2P : aucun résultat)
PSEUDONYMITY_CURRENT        = ADDRESS-LEVEL ONLY — aucune identité de nœud au niveau protocole ; clé de session éphémère par session ; pseudonyme durable = clé publique Ed25519 → adresse au registre
METADATA_PRIVACY_CURRENT    = LOW — longueur, compteur, direction, timing, cadence PEX 15 s, magie `AETH`+version+genesis tous en clair ; ni padding, ni chaff, ni jitter
TRANSACTION_CORRELATION_RISK= HIGH — relay immédiat sans jitter, sans sous-ensemble de voisins, relais non gated sur la validation (`p2p.rs:3249-3258`), plus double envoi post-validation (`rpc.rs:1185`) ; inférence de premier-vu sans contre-mesure
BOOTSTRAP_PRIVACY_RISK      = MEDIUM — divulgation totale à froid (IP + version + taille de DAG, les 3 seeds par défaut dans un même /24), bornée au premier contact et atténuée par 2A/2B/2D
PEER_STORE_PRIVACY_RISK     = MEDIUM — JSON en clair avec IP + timestamps + scores ; jamais transmis, jamais exposé en RPC, borné à 1000 entrées
ENCRYPTION_CURRENT          = ChaCha20-Poly1305 avec nonce de 12 o (compteur BE ‖ direction ‖ zéros), clé X25519 éphémère SHA256("aether-p2p-key-v1"‖secret) — confidentialité + intégrité + anti-replay + FS contre enregistreur passif ; SANS authentification de pair (MITM actif possible)
ANONYMITY_CURRENT           = NONE — aucun mécanisme d'anonymat implémenté, aucun test d'anonymat existant, aucun document ne revendique l'anonymat

TRANSPORT_TCP               = ANALYZED
TRANSPORT_TOR               = ANALYZED
TRANSPORT_I2P               = ANALYZED
TRANSPORT_ABSTRACTION       = ANALYZED

2E_ROADMAP                  = COMPLETE
2E_CODE_CHANGES             = NONE
2E_COMMIT                   = NONE
DEPLOYMENT                  = NONE
V1.4.0_IMMUTABLE            = PASS   (git rev-list -n1 v1.4.0-testnet = ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316)
```

### Preuves de non-modification

| Contrôle | Résultat |
|---|---|
| Fichiers sources modifiés | **aucun** |
| Fichiers créés | 3 documents Markdown dans `docs/` |
| Commit créé | **aucun** (`2E_COMMIT = NONE`) |
| Tests lancés | **aucun** (audit de lecture uniquement) |
| Push / merge / tag / deploy | **aucun** |
| `git rev-list -n1 v1.4.0-testnet` | `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` — inchangé |
| HEAD | `c9c44d0 phase2: add peer self-healing` — inchangé |
