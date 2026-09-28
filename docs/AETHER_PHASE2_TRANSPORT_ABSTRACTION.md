# AETHER — Phase 2E-B : abstraction du transport réseau

**Statut : `TRANSPORT_ABSTRACTION = PASS` — TCP = `IMPLEMENTED` ·
`TOR = NOT IMPLEMENTED` · `I2P = NOT IMPLEMENTED` · `ANONYMITY = NONE`**

> **Aucun transport anonymisant n'est implémenté.** L'existence d'un
> `trait Transport` ne signifie **pas** qu'un canal Tor ou I2P existe, et ne
> change **rien** à `IP_PRIVACY_CURRENT = NONE` ni à `ANONYMITY_CURRENT =
> NONE`. C'est une réécriture de frontière technique, pas une protection.
> 2E-B ne protège rien.

Branche : `dev/phase2-decentralized-network` · HEAD précédent `028cca9 phase2: harden transaction propagation privacy`
RELEASE `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` (inchangée)
Commit : `phase2: abstract network transport` · `DEPLOYMENT = NONE`

Entrées :

* `docs/AETHER_NETWORK_PRIVACY_ROADMAP.md` — §2E-B (objectif, coût, conditions).
* `docs/AETHER_TRANSPORT_COMPARISON.md` — étapes 9-12 de l'audit.
* `docs/AETHER_PHASE2_ECLIPSE_AUDIT.md` — §13.1 (règle de groupement /24).

---

## 1. Objectif

Séparer « qui je veux parler » (peer manager) de « comment j'arrive jusqu'à
lui » (transport), **sans** réécrire le réseau et **sans** modifier un seul
octet de wire.

Objectifs explicites de l'étape :

| # | Objectif | Résultat |
|---|---|---|
| 1 | Le code P2P ne crée plus `TcpStream` / `TcpListener` lui-même | 3 points détournés vers le transport |
| 2 | L'API de transport reste minimale | `dial` + `bind`, rien d'autre |
| 3 | `PeerAddr` devient la représentation d'endpoint extensible | 1 variante fonctionnelle, `Ip` |
| 4 | Le groupement non-IP est défini explicitement | `TransportGroupKey::NoNetworkGroup` |
| 5 | Aucun changement de comportement observable | `p2p::` 149/149, 0 test existant modifié |
| 6 | Aucun changement de wire | `P2P_PROTOCOL_VERSION = 4`, `PROTOCOL_CHANGE = NONE` |
| 7 | Tor / I2P **jamais** implémentés ici | `TOR = NOT IMPLEMENTED`, `I2P = NOT IMPLEMENTED` |

Ce que l'étape **ne** fait pas : anonymiser quoi que ce soit, ajouter une
variante `Onion` / `I2p` à `PeerAddr` « pour faire joli », ou convertir les
277 occurrences de `SocketAddr` du fichier.

---

## 2. Audit du couplage TCP

Réalisé **avant toute ligne de code**. Bilan : `TcpStream` / `TcpListener`
n'apparaissent qu'à quatre endroits en production ; le couplage réel est
`SocketAddr` comme identité de pair (277 occurrences).

| Cat | Emplacement | Dépendance TCP | Abstrait ? | Raison |
|---|---|---|---|---|
| A dial | `p2p.rs:4471` `connect_to_peer_inner` | `TcpStream::connect(addr)` | **OUI** | point d'appel unique du dial sortant |
| A dial | `p2p.rs:1490` `CONNECT_TIMEOUT` | const 5 s | NON | politique p2p, pas mécanisme |
| B accept | `p2p.rs:2445` `start` | `TcpListener::bind` | **OUI** | → `transport.bind(&PeerAddr::Ip(..))` |
| B accept | `p2p.rs:3269` `accept_loop` | `listener: TcpListener`, `.accept()` | **OUI** | 1 seul call site |
| C état | `p2p.rs:3649` `handle_peer` | `socket: TcpStream` | **stream OUI / addr NON** | clé de session reste `SocketAddr` |
| C état | `p2p.rs:3668` | `socket.into_split()` | **OUI** | halves déplacées dans `tokio::spawn` à `:3709` → doivent être `'static` |
| C état | `p2p.rs:2339..` `P2PNetwork` | `HashMap<SocketAddr, …>` | NON | `sync_stats.rs` (dirty) impose `SocketAddr` |
| D persistance | `p2p.rs:116, 2224-2251` | `PeerStoreEntry.addr: String` | NON | **déjà agnostique** ; pas de bump v3 |
| E log | ~150 sites | `SocketAddr: Display` | NON | masqué par `log_privacy.rs` (2E-A) |
| F groupement | `p2p.rs:504` `NetworkGroup`, `:530 network_group` | règle /24 Phase 2C | **ajout seul** | `TransportGroupKey` projeté, règle intacte |
| G PEX | `p2p.rs:2276` `Peers(Vec<SocketAddr>)` | **bincode wire** | NON | un `enum` ajouterait un tag u32 → bump v5 |
| H AddressManager | `p2p.rs:1837-1843` | `HashMap<SocketAddr, _>` | NON | interdiction de side-table |
| I anchors | 238 refs | promotion `PeerSource::Anchor` | NON | logique de découverte |
| J self-healing | `p2p.rs:1173` `PeerRecoveryController` | `dial: Vec<SocketAddr>` | NON | interdit ; le dial effectif passe par A |
| K relay | `p2p.rs:4583` `broadcast_transaction` | `mpsc` in-process | NON | aucune socket |
| L handshake | `p2p.rs:3609, 3433` | `impl AsyncReadExt/AsyncWriteExt` | NON | **déjà abstrait** |
| — | `rpc.rs:2365` | `TcpListener` HTTP axum | NON | hors P2P |
| — | `sync_stats.rs:276, 375, 498, 603` | `peer: SocketAddr` | NON | fichier intouchable |

**Verdict** : 3 sites à détourner, aucun risque de réécriture massive → pas
de `TRANSPORT_ABSTRACTION_SCOPE_RISK`.

---

## 3. Architecture avant

```
P2PNetwork
  ├─ start()        ─► TcpListener::bind(config.listen_addr)
  ├─ accept_loop(TcpListener)
  │                    └─ listener.accept()  ─► (TcpStream, SocketAddr)
  ├─ connect_to_peer_inner(addr)
  │                    └─ timeout(5s, TcpStream::connect(addr))
  └─ handle_peer(socket: TcpStream, addr: SocketAddr, …)
                       └─ socket.into_split() ─► (OwnedReadHalf, OwnedWriteHalf)
                                                  │
                                                  ├─ handshake<R, W>   (générique)
                                                  └─ writer ─► tokio::spawn  (… + 'static)
```

Le transport est **éparpillé** : création du socket, écoute, split et
timeout sont mélangés à la logique de pair.

---

## 4. Architecture après

```
P2PNetwork
  ├─ transport: Arc<dyn Transport>          (= TcpTransport)
  ├─ start()        ─► transport.bind(&PeerAddr::Ip(listen_addr))
  ├─ accept_loop(TransportListener)
  │                    └─ listener.accept() ─► (TransportStream, PeerAddr)
  │                          └─ BOUNDARY: endpoint.as_socket_addr() ─► SocketAddr
  ├─ connect_to_peer_inner(addr)
  │                    └─ timeout(5s, transport.dial(&PeerAddr::Ip(addr)))
  │                                    └► TransportStream
  └─ handle_peer(stream: TransportStream, addr: SocketAddr, …)
                       └─ stream.into_split() ─► (TransportReadHalf, TransportWriteHalf)
                                                  │  (owned, Send, 'static)
                                                  ├─ handshake<R, W>   (inchangé)
                                                  └─ writer ─► tokio::spawn (inchangé)
```

Le transport expose **deux opérations** ; tout ce qui décide *quand*, *si* et
*avec qui* connecter reste au-dessus.

---

## 5. PeerAddr

```rust
pub enum PeerAddr {
    Ip(SocketAddr),
}
```

* **Une seule variante.** Aucune variante `Onion` / `I2p` n'est ajoutée : elle
  serait du code mort présentant comme une fonctionnalité.
* Conversions : `From<SocketAddr>`, `TryFrom<PeerAddr, Error = TransportError>`,
  `as_socket_addr() -> Option<SocketAddr>`, `Display`, `FromStr`.
* **Aucune panique.** `FromStr` renvoie `TransportError::InvalidAddr` ;
  `as_socket_addr()` renvoie `None` plutôt que de fabriquer une adresse.
* **Aucune sérialisation dérivée** — ni `Serialize` ni `Deserialize`. C'est
  volontaire : un dérivé sur un `enum` changerait la forme binaire et
  JSON, donc le wire et le store.
* Ajouter une variante force un bras d'`match` supplémentaire **au moment de
  la compilation** dans `dial`, `bind`, `accept`, `Display`, `FromStr`,
  `TransportGroupKey::from_peer_addr`. C'est le mode de défaillance voulu.

---

## 6. Transport

```rust
pub trait Transport: Send + Sync + 'static {
    fn dial (&self, &PeerAddr) -> BoxFuture<'_, Result<TransportStream,  TransportError>>;
    fn bind(&self, &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>>;
}
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

* **Deux méthodes.** Pas de `supports_inbound`, pas de `close`, pas de
  `metrics`, pas de 40 méthodes « au cas où ».
* **Dyn-compatible** : `Arc<dyn Transport>`, donc `P2PNetwork` n'est pas
  générique sur le transport et les ~40 constructeurs de tests restent
  identiques.
* **Pas de `async_trait`** : boxed futures natives, aucun proc-macro ajouté.
* **Pas de politique** : ni timeout, ni retry, ni ban, ni quota. Le timeout de
  dial reste `CONNECT_TIMEOUT = 5 s` dans `p2p.rs:1490`, enveloppant l'appel
  au transport à `p2p.rs:4471`.

---

## 7. TransportStream

```rust
pub enum TransportStream { Tcp(TcpStream) }
    into_split(self) -> (TransportReadHalf, TransportWriteHalf)

pub enum TransportReadHalf  { Tcp(OwnedReadHalf) }   // impl AsyncRead
pub enum TransportWriteHalf { Tcp(OwnedWriteHalf) }  // impl AsyncWrite
```

Contrainte structurante : `handle_peer` **déplace** le half d'écriture dans un
`tokio::spawn` (`p2p.rs:3709`). La division doit donc rendre des halves
**possédées**, `Send` et `'static` — `tokio::io::split(&stream)` ne peut pas
fonctionner ici (elle emprunte). Chaque variante se divise elle-même, comme
`TcpStream::into_split`.

`handle_peer` reçoit `TransportStream` et divise **à l'intérieur** (1 ligne),
plutôt que de dupliquer le split sur ses 2 call sites.

---

## 8. TransportListener

```rust
pub enum TransportListener { Tcp(TcpListener) }
    accept(&self)      -> Result<(TransportStream, PeerAddr), TransportError>
    local_addr(&self)  -> Option<PeerAddr>
```

`accept` retourne l'endpoint distant en `PeerAddr`. `local_addr` sert à
remonter le port réellement bindé après un bind sur `:0` ; il n'est **pas**
dans le `trait Transport` (l'API reste `dial` + `bind`).

---

## 9. TcpTransport

```rust
pub struct TcpTransport;   // impl Transport
    dial:  PeerAddr::Ip(addr) → TcpStream::connect(addr) → TransportStream::Tcp
    bind:  PeerAddr::Ip(addr) → TcpListener::bind(addr)   → TransportListener::Tcp
```

Mécanique **uniquement**. Chaque variante non-IP devra être ajoutée
explicitement ; le chemin actuel ne contient ni `panic!`, ni `unwrap`, ni
`unreachable!`.

---

## 10. Frontière PeerAddr / SocketAddr

`PeerAddr` est un type **couche transport**. Il s'arrête à deux points :

| Passage | Où | Sens |
|---|---|---|
| dial sortant | `p2p.rs:4471` | `SocketAddr` → `PeerAddr::Ip(..)` |
| accept entrant | `p2p.rs:3286` | `PeerAddr` → `endpoint.as_socket_addr()` |

À l'acceptation, un endpoint non exprimable produit `error!` + `continue`
(connexion écartée) — **jamais** une adresse fabriquée.

Reste en `SocketAddr`, volontairement :

* clé de session `peers`, `dialing`, `outbound_sessions`, `peer_discovery_tx` ;
* `AddressManager` (entries / origins / scores) ;
* `sync_stats` (`SyncContext`) ;
* wire PEX `P2PMessage::Peers(Vec<SocketAddr>)` ;
* persistance `PeerStoreEntry.addr: String` ;
* logging.

**Contrainte dure** : `src/sync_stats.rs` expose `peer: SocketAddr`
(`:276, :375, :498, :603`) et ce fichier n'est pas modifiable. Convertir la
clé de session aurait imposé de le modifier. Le rendu : `PeerAddr` ne se
propage nulle part — **`TRANSPORT_ABSTRACTION_BOUNDARY = OK`**, pas de
`TOO_LEAKY`.

---

## 11. AddressManager inchangé

Aucune ligne de `AddressManager` n'a changé.

* `entries: HashMap<SocketAddr, AddressEntry>` — inchangé ;
* `origins`, `scores` — inchangés ;
* `PeerSource`, `AddressEntry`, admission, TTL, qualité — inchangés ;
* **aucune side-table** n'a été créée : `AddressManager` reste l'unique
  propriétaire des métadonnées de pair.

Le dial sortant part du `SocketAddr` de l'`AddressManager`, est converti en
`PeerAddr::Ip(..)` à l'appel, et revient. `ADDRESS_MANAGER_UNCHANGED = PASS`.

---

## 12. sync_stats inchangé

`src/sync_stats.rs` : **0 ligne modifiée.** Le `SyncContext` continue de
recevoir `addr: SocketAddr` dans `handle_peer`, exactement comme avant.
C'est cette contrainte qui a fixé la frontière décrite en §10.

---

## 13. PEX inchangé

```rust
pub enum P2PMessage { …, Peers(Vec<SocketAddr>), … }   // p2p.rs:2276 — inchangé
```

* **Wire identique.** Remplacer `Vec<SocketAddr>` par `Vec<PeerAddr>` ferait
  écrire un tag d'`enum` u32 par adresse → changement bincode → bump de
  version → **`PROTOCOL_CHANGE ≠ NONE`**. Non fait.
* Encodage `p2p.rs:3254`, décodage `p2p.rs:4318` : inchangés, y compris le
  filtre `is_private_or_reserved`.
* `PEX_ADDRESSABILITY = TCP_ONLY` : seul un endpoint IP peut être encodé. Un
  futur endpoint non-IP n'est **jamais** mis sur le fil, et le chemin de
  décodage ne panique pas — il continue d'ignorer ce qu'il ne sait pas
  représenter.

---

## 14. NetworkGroup inchangé

* `network_group()` (`p2p.rs:530`) : **0 ligne modifiée**.
* `subnet_24()` (`p2p.rs:557`) : inchangé.
* `count_subnet_peers`, `group_counts`, `select_outbound`, sélection pondérée,
  `PROTECTED_OUTBOUND_SLOTS`, `MAX_PEERS_PER_SUBNET` : **inchangés**.
* Seul ajout : `enum NetworkGroup` est passé de privé à `pub`, parce que le
  champ `Ip(NetworkGroup)` du `pub enum TransportGroupKey` l'exige (sinon lint
  `private_interfaces`). **Changement de visibilité uniquement**, zéro
  comportement.

```rust
pub enum TransportGroupKey {
    Ip(NetworkGroup),      // projection directe de network_group(), pas une 2e règle
    NoNetworkGroup,        // transport sans notion de sous-réseau
}
impl TransportGroupKey { pub fn from_peer_addr(&PeerAddr) -> Self }
```

`from_peer_addr(PeerAddr::Ip(a))` appelle `network_group(a)` : **une seule
source de vérité**, la propriété /24 de la Phase 2C ne peut pas dériver.

`NoNetworkGroup` existe pour qu'un futur endpoint non-IP ait son propre
seau. Il n'est **jamais** rempli par un /24 inventé — c'est exactement le
« quota silencieusement devenu no-op » que la roadmap §2E-B désigne comme le
risque structurel principal. Il n'est consommé par aucun chemin de production
aujourd'hui : TCP passe toujours par `network_group()`.

---

## 15. Self-healing inchangé

`PeerRecoveryController`, `RecoveryState`, `RecoveryRound`, les tournées de
dial, l'ancrage : **0 ligne modifiée.** Le contrôle automatique de reconnexion
demeure tel quel. Le seul chemin concerné est `connect_to_peer` →
`connect_to_peer_inner`, dont le corps interne a changé d'une expression
(`TcpStream::connect` → `transport.dial`) sans toucher à `record_dial_failure`,
au backoff, aux paliers de bannissement ni au comportement de redial.
`SELF_HEALING_UNCHANGED = PASS`.

---

## 16. Eclipse resistance inchangée

Les défenses de la Phase 2C passent les régressions **sans modification
d'un seul test existant** :

| Défense | Référence | Résultat |
|---|---|---|
| Diversité /24 à l'entrée | `accept_loop`, ECLIPSE-01 | 15/15 `phase2_eclipse_tests` |
| Slots sortants protégés | `inbound_admitted`, `PROTECTED_OUTBOUND_SLOTS` | inchangé |
| `select_outbound` pondéré | `p2p.rs:887` | inchangé |
| Limites de sous-réseau | `MAX_PEERS_PER_SUBNET` | inchangé |
| Contrôle de régénération | 17 `phase2_self_healing_tests` | 17/17 |
| Adresses privées / réservées au PEX | `is_private_or_reserved` | inchangé |

`PHASE2C_SELECT_OUTBOUND_UNCHANGED = PASS`.

---

## 17. Tests

Module **`transport::phase2_transport_tests`**, 11 tests, tous verts :

| # | Test | Ce qu'il vérifie |
|---|---|---|
| 1 | `test_peer_addr_ip_roundtrip` | `SocketAddr ⇄ PeerAddr` identique, `Display`, `FromStr` |
| 2 | `test_peer_addr_invalid_conversion` | 4 entrées invalides → `Err`, **zéro panic** |
| 3 | `test_tcp_transport_dial` | dial vers un listener réel → `TransportStream::Tcp` |
| 4 | `test_tcp_transport_accept` | `bind` + `accept` sur loopback |
| 5 | `test_tcp_transport_bind_reports_endpoint` | `bind :0` → `local_addr()` reflète le port OS |
| 6 | `test_tcp_transport_roundtrip` | ping/pong dans les deux sens après `into_split` |
| 7 | `test_transport_stream_split_owned` | **les 2 halves déplacées dans `tokio::spawn`** et échangent des octets (preuve `'static` + `Send`) |
| 8 | `test_transport_listener_returns_peer_addr` | `accept` rend `PeerAddr::Ip`, IP + port valides |
| 9 | `test_transport_group_ip` | v4 → `Ip(V4([203,0,113]))`, v6 → `Ip(V6([0x20,0x01,0x0d]))` |
| 10 | `test_transport_group_no_network_group` | `NoNetworkGroup` ≠ aucun groupe IP (pas de /24 inventé) |
| 11 | `test_legacy_peer_store_transport_boundary` | adresses `String` v1/v2 inchangées par `PeerAddr` → pas de bump de store |

Gates de régression (exécutées, toutes vertes) :

```
cargo check --lib                              # 9 warnings / 0 erreur (= baseline)
cargo test --lib p2p::                         # 149 passed / 0 failed / 2 ignored
cargo test --lib phase2_decentralized_tests    # PASS
cargo test --lib phase2_eclipse_tests          # PASS
cargo test --lib phase2_self_healing_tests     # PASS
cargo test --lib phase2_privacy_tests          # PASS
cargo test --lib phase2_privacy_propagation_tests  # PASS
cargo test --lib transport::phase2_transport_tests # 11/11
cargo test --lib bootstrap_phase1              # 19/19
git diff --check -- src/p2p.rs src/lib.rs      # 0 erreur
```

Aucun test existant n'a été modifié ; aucun des 9 fichiers dirty
préexistants n'a été touché.

---

## 18. Performances

Analyse statique du chemin, **sans benchmark** (aucune mesure chiffrée n'est
revendiquée) :

```
P2P → Arc<dyn Transport> → TcpTransport → TcpStream
```

| Poste | Avant | Après | Coût |
|---|---|---|---|
| dial | `TcpStream::connect` (1 futur interne) | 1 appel vtable + 1 `Box::pin` (~32-64 o) + `connect` | **1 allocation par tentative de dial** |
| bind | `TcpListener::bind` | idem + 1 `Box::pin` | **1 allocation, une fois au démarrage** |
| accept | `listener.accept()` | match enum + `accept()` + constr. 2 enums | **0 allocation** |
| split | `into_split()` | match enum + move | **0 allocation, 0 copie** |
| read/write | délégué à la socket | 1 match enum + appel direct (inliné) | **négligeable** |
| timeout | enveloppe le dial | enveloppe **le même dial** | inchangé |
| handshake | générique `AsyncReadExt/WriteExt` | identique, mêmes types | **0** |
| framing | `read_exact_timeout`, padding, nonce, compteurs | identique | **0** |

Fréquence : le dial est borné par l'ensemble `dialing` (un seul dial en vol
par adresse) et par les backoffs — quelques tentatives par seconde au pire.
Le bind a lieu une fois. L'accept est un événement rare.

```
TRANSPORT_PERFORMANCE_IMPACT = LOW (NEGLIGIBLE)
```

Valeur **déduite du code**, pas mesurée. Aucun chiffre n'est inventé.

---

## 19. Limites

1. **Aucune protection ajoutée.** `IP_PRIVACY_CURRENT = NONE`,
   `ANONYMITY_CURRENT = NONE` — inchangés. 2E-B ne protège rien.
2. **Une seule implémentation.** `TcpTransport` est le seul transport ; le
   `trait` n'a jamais été exercé par une seconde implémentation.
3. **`PeerAddr` n'a qu'une variante.** Sa capacité d'évolution est démontrée
   par la compilation (match exhaustif), pas par une réelle seconde variante.
4. **`TransportGroupKey` n'a pas de chemin de production.** Testé, `pub`,
   mais consommé par personne : TCP passe par `network_group()`.
5. **La clé de session reste `SocketAddr`.** Tant que `sync_stats.rs`
   l'expose, aucun endpoint non-IP ne peut devenir une session.
6. **Le wire reste IP-only.** `P2PMessage::Peers(Vec<SocketAddr>)` : un
   pair non-IP ne pourrait pas être échangé par PEX sans bump de version.
7. **`local_addr()` n'est pas dans le trait.** Les tests le construisent sur
   la variante concrète.
8. **Pas de mesure de performance.** L'analyse §18 est statique ; aucun
   benchmark n'a été lancé.

---

## 20. Évolutivité future

Ce que 2E-B rend **possible sans réécriture** (et seulement cela) :

| Ajout | Où | Ce qui ne bouge pas |
|---|---|---|
| Nouveau transport | nouvelle variante d'enum + `impl Transport` | `P2PNetwork`, `AddressManager`, `PeerRecoveryController` |
| Variante `PeerAddr` non-IP | bras d'`match` additionnel (erreur propre) | session, store, wire, groupement existants |
| Regroupement non-IP | `TransportGroupKey::NoNetworkGroup` déjà défini | règle /24 Phase 2C |
| Fuite de socket vers un transport SOCKS | `TcpTransport` remplacé par un transport tunnel | tout le reste du chemin |

Ce que 2E-B **ne** rend pas possible sans travail supplémentaire :

* un pair non-IP comme clé de session (`sync_stats.rs`) ;
* l'échange d'adresse non-IP par PEX (wire bincode) ;
* une session non-IP dans l'`AddressManager` (clé `SocketAddr`) ;
* tout bénéfice de confidentialité — voir §19.1.

**Ordre d'exécution des étapes suivantes** (décision explicite requise,
jamais automatique) : 2E-C (`optional Tor transport`) **décide** si elle est
engagée ; 2E-B ne l'a pas déclenchée.

---

## Critères de sortie

```
TRANSPORT_ABSTRACTION               = PASS
TCP_TRANSPORT                       = PASS   TCP = IMPLEMENTED
TCP_DIAL                            = PASS
TCP_ACCEPT                          = PASS
TRANSPORT_STREAM_SPLIT              = PASS   halves owned, 'static, testé dans tokio::spawn
PEER_ADDR                           = PASS   1 variante, conversions sans panic
NETWORK_GROUP_BOUNDARY              = PASS   TransportGroupKey::Ip / NoNetworkGroup

ADDRESS_MANAGER_UNCHANGED           = PASS   0 ligne modifiée, pas de side-table
PEX_WIRE_UNCHANGED                  = PASS   P2PMessage::Peers(Vec<SocketAddr>) inchangé
PHASE2C_SELECT_OUTBOUND_UNCHANGED   = PASS   select_outbound, /24, slots intacts
SELF_HEALING_UNCHANGED              = PASS   PeerRecoveryController 0 ligne
SYNC_STATS_UNCHANGED                = PASS   0 ligne
HANDSHAKE_UNCHANGED                 = PASS   X25519, ChaCha20-Poly1305, nonce, framing
PERSISTENCE_UNCHANGED               = PASS   PEER_STORE_VERSION = 2, legacy v1 intact

P2P_REGRESSION                      = PASS   p2p:: 149/149
PHASE2_REGRESSION                   = PASS   phase2_ 92/92
PRIVACY_REGRESSION                  = PASS   privacy 16/16 · propagation 18/18
TRANSPORT_TESTS                     = 11/11 PASS
BOOTSTRAP_PHASE1                    = 19/19 PASS
RUSTC                               = 9 warnings / 0 erreur (= baseline, 0 nouveau)

P2P_PROTOCOL_VERSION                = 4
PROTOCOL_CHANGE                     = NONE
PEER_STORE_VERSION                  = 2
TRANSPORT_PERFORMANCE_IMPACT        = LOW (NEGLIGIBLE) — statique, non mesuré

TRANSPORT_IMPLEMENTED               = TCP ONLY
TOR                                 = NOT IMPLEMENTED
I2P                                 = NOT IMPLEMENTED
ANONYMITY                           = NONE
IP_PRIVACY_CURRENT                  = NONE (inchangé)
ANONYMITY_CURRENT                   = NONE (inchangé)

COMMIT                              = phase2: abstract network transport
DEPLOYMENT                          = NONE
PUSH                                = NONE
MERGE                               = NONE
TAG                                 = NONE
V1.4.0_IMMUTABLE                    = PASS   ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316
```
