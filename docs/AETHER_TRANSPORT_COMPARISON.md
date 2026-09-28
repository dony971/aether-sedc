# AETHER — Comparaison des transports réseau

**Statut : `TRANSPORT_TCP = ANALYZED` · `TRANSPORT_TOR = ANALYZED` ·
`TRANSPORT_I2P = ANALYZED` · `TRANSPORT_ABSTRACTION = ANALYZED`**

> **Étude uniquement. Aucune ligne de code n'a été modifiée, aucun transport
> n'a été implémenté, aucun commit n'a été créé *par ce document*.**
>
> **Mise à jour post-2E-A :** l'étape 2E-A a été livrée **ensuite**, par un
> commit distinct (`phase2: harden network metadata privacy`,
> `2E_CODE_CHANGES = 2E-A ONLY`). Aucun transport (2E-B / 2E-C) n'a été
> implémenté : `TRANSPORT_IMPLEMENTED = NONE` reste exact. Les valeurs
> `2E_CODE_CHANGES = NONE` / `2E_COMMIT = NONE` ci-dessous sont celles de
> l'audit, avant ce commit. Voir `docs/AETHER_PHASE2_METADATA_HARDENING.md`.
>
> Ce document **ne fait aucun classement global**. Chaque axe est présenté
> séparément, avec ses compromis. Une solution « gagnante sur tout » n'existe
> pas et n'est pas recherchée.

Branche : `dev/phase2-decentralized-network` · HEAD au moment de l'étude `c9c44d0`
RELEASE `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` (inchangée)
`2E_CODE_CHANGES = NONE` · `2E_COMMIT = NONE` · `DEPLOYMENT = NONE` *(valeurs de l'audit, voir ci-dessus)*

Contexte : `docs/AETHER_PHASE2_PRIVACY_THREAT_MODEL.md` (constats de code),
`docs/AETHER_NETWORK_PRIVACY_ROADMAP.md` (séquence proposée).

---

## 0. Constat de départ, commun à tous les transports

Le code Aether ne contient **aucun** des éléments suivants (recherche exacte
`SOCKS5?`, `I2P`, `Tor`, `.onion`, `Arti`, `Socks5Config` dans `src/*.rs` :
**aucun résultat**) :

* aucun proxy, aucun SOCKS, aucun paramètre de transport ;
* aucune abstraction : `connect_to_peer` ouvre un `TcpStream` directement, et
* `TcpListener::bind` sur `0.0.0.0` (`node.rs:578`, `p2p.rs:1959`) ;
* IPv4 uniquement dans la configuration (`0.0.0.0`, aucun bind `::`).

Les comparaisons qui suivent sont donc des **évaluations de ce qu'il
faudrait faire**, pas des mesures d'implémentations existantes.

**Constantes qui conditionnent tout transport alternatif :**

| Constante | Valeur | Conséquence sur un transport lent |
|---|---|---|
| `HANDSHAKE_TIMEOUT` | 10 s | doit tenir dans un circuit établi |
| `FRAME_TIMEOUT` | **30 s** | **contraignante** : tout transport dont l'idle dépasse 30 s est déconnecté |
| `MAX_MSGS_PER_SEC` | 400 | borne le débit par session, pas le débit réseau |
| `MAX_MESSAGE_SIZE` | 16 MiB | un `Inventory` complet peut approcher cette borne ; sur un circuit lent c'est un blocage long |
| PEX | 15 s, 64 adresses | sur Tor/I2P, coût récurrent × nombre de pairs |
| `SyncRequest` à chaque handshake | inventaire **non borné** | le plus gros transfert du protocole, mal adapté à un circuit à faible débit |

---

## 1. TCP direct (état actuel)

| Axe | Évaluation |
|---|---|
| **PRIVACY** | **Faible.** IP source et destination en clair, protocole identifié par la magie `AETH` + version + genesis en clair, tailles/cadence visibles. Le chiffrement de session protège le contenu mais pas la topologie. C'est la référence « sans protection » de cet audit. |
| **LATENCY** | **Meilleure possible** — RTT nu, pas d'intermédiaire. |
| **RELIABILITY** | **Élevée** — TCP fournit ordre et retransmission ; Aether ne gère qu'une inactivité de 30 s (`FRAME_TIMEOUT`). |
| **COMPLEXITY** | **Nulle par rapport au reste** — c'est l'implémentation actuelle. |
| **RESOURCE_COST** | **Minimal** — un `TcpStream` par pair, aucune couche supplémentaire. |
| **BOOTSTRAP_IMPACT** | Un seed voit directement l'IP du nouveau nœud (§7 du modèle de menaces). Trois seeds par défaut dans un même /24. |
| **P2P_COMPATIBILITY** | **Totale** — le modèle pair-à-pair entrant/sortant, le PEX, les anchors et la Phase 2D fonctionnent tels quels. |
| **OPERATIONAL_RISK** | **Faible** — pas de dépendance externe, pas de tiers à faire tourner. |

**Avantages** : simplicité, débit, compatibilité immédiate avec 2A→2D.
**Inconvénients** : c'est le point de départ de toutes les fuites de la
matrice §3 du modèle de menaces.

---

## 2. Tor — Aether → SOCKS5 (sortant seulement)

| Axe | Évaluation |
|---|---|
| **PRIVACY** | **Le pair voit un nœud de sortie Tor, pas l'IP du client.** Le contenu reste chiffré par Aether en plus. Restent visibles pour le nœud de sortie : le battement PEX 15 s, les tailles de messages, le `SyncRequest` d'inventaire — tout ce que la matrice §3 liste comme « non protégé par le chiffrement ». Tor ne change rien à ces lignes. |
| **LATENCY** | **Dégradée de manière significative et variable** — 3 sauts, circuit réétabli périodiquement, distributions à longue traîne. À confirmer par mesure ; non mesuré ici. |
| **RELIABILITY** | **Dégradée** — un circuit coupé casse une session TCP. Le code déconnecte au-delà de `FRAME_TIMEOUT = 30 s` sans reconnexion transparente : les deux sont compatibles, mais une coupure de circuit = re-handshake complet. |
| **COMPLEXITY** | **Moyenne à élevée** — client SOCKS optionnel (arti ou `socks` crate), gestion d'erreur, file d'attente de connexion, et surtout **impossibilité d'accepter entrant** (voir ci-dessous). |
| **RESOURCE_COST** | **Modéré côté Aether** (un socket par pair) ; **élevé côté réseau Tor** (bande passante du réseau donationnée). L'inventaire non borné de `SyncRequest` est un coût anormal à imposer à un nœud de sortie. |
| **BOOTSTRAP_IMPACT** | **Fortement amélioré** : les seeds reçoivent l'adresse d'un nœud de sortie, pas la vraie IP. Mais le DNS seed, s'il est configuré, **fuit toujours** en clair (UDP) — il faudrait le résoudre via Tor lui-même ou n'utiliser que des IP. |
| **P2P_COMPATIBILITY** | **Partielle et asymétrique.** Sortant : oui, un `connect` SOCKS remplace le `connect` TCP. Entrant : **non** — un nœud derrière Tor ne peut pas recevoir de connexion TCP directe sans révéler son IP. Résultat : les nœuds Tor ne peuvent être que **clients**, jamais **hôtes** de sessions entrantes. |
| **OPERATIONAL_RISK** | **Moyen.** (a) Dépendance à un tiers (`127.0.0.1:9050`) — un Tor absent casse tout le sortant. (b) **Dépendance centralisée en pratique** : si la majorité des nœuds utilisent Tor et que les seeds restent en TCP, un petit nombre de nœuds de sortie voit tout le trafic sortant. (c) Fingerprinting de protocole : `AETH` en clair traverse Tor sans gêne, donc un opérateur de nœud de sortie sait qu'il porte du trafic Aether. (d) Attaques connues du réseau Tor contre ce type d'usage (corrélations de moment/taille à grande échelle) : à documenter, pas mesuré ici. |

**Ce que Tor résout** : l'IP du client vis-à-vis du pair et vis-à-vis du
réseau IP.
**Ce que Tor ne résout pas** : le timing, les tailles, le voisinage révélé par
PEX, l'origine des transactions, le registre public, l'absence
d'authentification du handshake (un nœud de sortie malveillant reste en amont
du chiffrement Aether s'il est *lui-même* le pair — mais il ne peut pas
décoder Aether sans faire le MITM, cf. §6.3.8 du modèle de menaces).

---

## 3. Tor — Aether → service onion (entrée ET sortie)

| Axe | Évaluation |
|---|---|
| **PRIVACY** | **Meilleur que SOCKS seul** : les deux extrémités sont des services onion, donc aucune des deux ne voit l'IP de l'autre. Le pair ne voit qu'un `.onion`. C'est la seule variante Tor qui permet un pair-à-pair **symétrique**. |
| **LATENCY** | **Plus dégradée que SOCKS** — rendezvous point en plus (introduction + rendez-vous), établissement de service plus long. À mesurer. |
| **RELIABILITY** | **Dégradée** comme ci-dessus, avec en plus l'expiration des points d'introduction. |
| **COMPLEXITY** | **Élevée** — gestion de service onion (adresse `.onion` à générer, stocker, restituer), publication, re-publication, et découplage entre « adresse de service » et « adresse IP d'écoute ». |
| **RESOURCE_COST** | Élevé (double circuit) + inventaire non borné sur un circuit à faible débit. |
| **BOOTSTRAP_IMPACT** | **Le meilleur du Tor** : le bootstrap lui-même peut se faire vers des `.onion`, ce qui cache l'IP du nouveau nœud **y compris au seed**. Nécessite que les seeds aient aussi un `.onion` — les trois IP fixes actuelles n'en ont pas. |
| **P2P_COMPATIBILITY** | **Structurante pour Aether.** L'adresse d'un pair cesserait d'être `ip:port` pour devenir un identifiant de service. Or **toute la Phase 2 repose sur `SocketAddr`** : `peers: HashMap<SocketAddr, …>`, `AddressManager`, `select_outbound`, `NetworkGroup`, `subnet_24`, `MAX_PEERS_PER_SUBNET`, `plan_recovery`, le peer store JSON… Le groupement par `/24` n'a **aucun sens** sur un `.onion` : les garanties anti-eclipse de la 2C et le quota de la 2D seraient **neutralisés**, pas améliorés. |
| **OPERATIONAL_RISK** | **Élevé.** (a) Une fuite d'IP par un autre canal (RPC exposé, DNS seed, seed TCP) anule tout le bénéfice. (b) Si tous les nœuds deviennent onion, **les défenses 2C/2D doivent être redéfinies** — c'est un chantier consensus-adjacent, pas un plugin. (c) Adresse `.onion` persistante = nouveau **pseudonyme de long terme** à protéger (le peer store deviendrait encore plus sensible). |

---

## 4. I2P

| Axe | Évaluation |
|---|---|
| **PRIVACY** | **Comparable à Tor onion en intention**, avec un modèle différent : tunnels unidirectionnels et *garlic routing* ; I2P est conçu pour du pair-à-pair interne au réseau, là où Tor est conçu pour client → web. Les deux cachent les IP aux extrémités. |
| **LATENCY** | **Dégradée**, souvent jugée meilleure que Tor en débit interne, mais **non mesurée ici** — aucune mesure n'est revendiquée. |
| **RELIABILITY** | **Dégradée**, avec en plus une dépendance à la *netDB* I2P (réseau de tunnels, peer holes) qui doit elle-même être atteinte au démarrage. |
| **COMPLEXITY** | **La plus élevée des options** — daemon I2P (Java ou `i2p_rs`), gestion d'adresse base32/base64, tunnels entrants et sortants, réinitialisation. |
| **RESOURCE_COST** | **Élevé** — plusieurs tunnels par pair, maintenance de la netDB, surcoût mémoire notable. |
| **BOOTSTRAP_IMPACT** | **Le plus délicat.** I2P a besoin d'un *bootstrap* lui-même : les premiers pairs I2P doivent être atteints par des *floodfills* ou une adresse donnée. On remplace la dépendance bootnode par une dépendance **netDB**, ce qui est structurellement la même classe de problème. |
| **P2P_COMPATIBILITY** | **Même problème structurel que Tor onion** : plus de `SocketAddr`, donc remise en cause de `NetworkGroup` / `subnet_24` / quotas 2C / quota 2D. En outre, les pair-à-pair I2P sont **unidirectionnels** (un tunnel par sens) : le modèle « une session TCP bidirectionnelle » du code ne correspond pas directement. |
| **OPERATIONAL_RISK** | **Le plus élevé.** Écosystème plus petit que Tor, moins audité, dépendance logicielle lourde, et surtout un **effet de seuil** : I2P n'apporte de la confidentialité que s'il est suffisamment peuplé. Un déploiement partiel crée exactement la situation décrite en §2 du modèle : deux populations identifiables. |

---

## 5. Transport abstrait pluggable

**Question 1 — peut-on séparer transport et peer manager ?**

Oui, en principe. Les deux responsabilités sont aujourd'hui **mélangées dans
`src/p2p.rs`** :

| Couche | Endroit actuel |
|---|---|
| Découverte / sélection / scoring / quotas (peer manager) | `select_outbound`, `AddressManager`, `plan_recovery`, `inbound_admitted`, `pex_sample` |
| Établissement de session (transport) | `connect_to_peer` → `TcpStream::connect`, `accept_loop` → `TcpListener::bind` |
| Session applicative (ni l'un ni l'autre) | `handshake()`, boucle de frame (`:3107`), tâche d'émission (`:3041`) |

Le **point de couplage réel** est plus fin qu'il n'y paraît :

1. **`SocketAddr` est le type universel.** Il est la clé de `peers`, la valeur
   de `AddressManager`, le paramètre de `plan_recovery`, le champ `addr` du
   peer store, et le contenu du message `P2PMessage::Peers`. Un transport qui
   ne produit pas de `SocketAddr` ne peut pas entrer dans le système.
2. **`handle_peer(socket: TcpStream, addr: SocketAddr, …)`** (`:2984`) — la
   fonction centrale reçoit un `TcpStream` concret et un `SocketAddr`.
3. **`accept_loop(listener: TcpListener, …)`** (`:2751`) — idem côté entrant.
4. **Le groupement réseau** (`NetworkGroup`, `subnet_24`) interprète des octets
   IP : c'est à la fois une défense de sécurité et un présupposé de transport.

**Question 2 — quelles APIs seraient nécessaires ?**

Nécessaire et suffisant pour couvrir les cinq transports envisagés :

```
trait AetherTransport {
    /// Établir une session sortante vers une adresse de pair.
    async fn dial(&self, target: PeerAddr) -> Result<Box<dyn FramedStream>>;

    /// Accepter une session entrante (non implémentable en SOCKS simple).
    async fn accept(&self) -> Result<(Box<dyn FramedStream>, PeerAddr)>;

    /// Est-ce que ce transport peut porter de l'entrée ?
    fn supports_inbound(&self) -> bool;
}

/// Doit pouvoir représenter à la fois "1.2.3.4:25565" et "abcd…onion:0"
/// et "base32.i2p".
enum PeerAddr { Ip(SocketAddr), Onion(String), I2p(String) }

trait FramedStream: AsyncRead + AsyncWrite + Send + 'static {}
```

Plus, en aval mais indispensable : `NetworkGroup` et `subnet_24` doivent
accepter `PeerAddr` et définir un **groupement de repli** pour les variantes
qui n'ont pas d'IP (sinon les quotas 2C/2D deviennent des non-opérations
silencieuses — le pire des cas).

**Question 3 — où se trouve le couplage actuel ?**

| Fichier | Symbole | Nature du couplage |
|---|---|---|
| `src/p2p.rs` | `connect_to_peer` / `connect_to_peer_inner` | `TcpStream::connect` en dur |
| `src/p2p.rs` | `accept_loop` | `TcpListener::bind` en dur |
| `src/p2p.rs` | `handle_peer` | signature fixée sur `TcpStream` |
| `src/p2p.rs` | `peers: HashMap<SocketAddr, …>` | type d'adresse en dur |
| `src/p2p.rs` | `NetworkGroup` / `subnet_24` / `count_subnet_peers` | interprétation IP en dur |
| `src/p2p.rs` | `PeerStoreEntry.addr: String` | format `ip:port` en dur |
| `src/node.rs:578` | `listen_addr = "0.0.0.0:{port}"` | IPv4 en dur |

**Question 4 — quel coût architectural ?**

| Poste | Estimation qualitative |
|---|---|
| Extraction du trait + enum d'adresse | **modéré** — toucherait `p2p.rs` à ~8 points d'entrée |
| Groupement réseau générique | **modéré à élevé** — c'est une défense de sécurité (Phase 2C), pas un simple utilitaire : toute réécriture doit **repasser la batterie `phase2_eclipse_tests` (15/15) et `phase2_self_healing_tests` (17/17)** |
| Peer store : format d'adresse | **faible** — `addr` est déjà un `String` |
| Handshake / frame | **nul** — ils ne connaissent pas le transport, seulement un `AsyncRead + AsyncWrite` |
| Tests | **élevé** — chaque combinaison transport × direction × groupement a ses cas |

**Question 5 — quel bénéfice réel ?**

**Aucun en soi.** L'abstraction ne protège personne : tant qu'aucun transport
alternatif n'est branché, le comportement réseau est strictement identique.
Son bénéfice est **conditionnel** : c'est le prix d'entrée de 2E-C (Tor) et de
tout travail I2P, et il réduit le coût de toute évolution future de transport.

C'est précisément pour cette raison que la roadmap recommande de ne **pas**
la placer en tête : elle coûte de l'ingénierie et ne rapporte rien à
l'utilisateur tant qu'aucun transport n'est branché (voir
`AETHER_NETWORK_PRIVACY_ROADMAP.md` §1).

---

## 6. Tableau croisé (sans classement global)

| Axe | TCP direct | Tor SOCKS (sortant) | Tor onion (bilatéral) | I2P | Abstraction seule |
|---|---|---|---|---|---|
| **PRIVACY** | faible (référence) | IP du pair masquée ; timing, tailles et voisinage PEX inchangés | IP des deux extrémités masquées | idem intention | nulle |
| **LATENCY** | optimale | dégradée, variable | plus dégradée (rendez-vous) | dégradée, non mesurée | inchangée |
| **RELIABILITY** | élevée | coupures de circuit vs `FRAME_TIMEOUT` 30 s | idem + expiration d'intro | idem + netDB | inchangée |
| **COMPLEXITY** | nulle | moyenne-élevée | élevée | très élevée | modérée-élevée |
| **RESOURCE_COST** | minimal | modéré (hors coût réseau Tor) | élevé | élevé | nul tant que non branchée |
| **BOOTSTRAP_IMPACT** | seed voit l'IP | seed voit un nœud de sortie ; DNS seed reste un fuit | meilleur : seed onion possible | remplace le bootnode par la netDB | inchangé |
| **P2P_COMPATIBILITY** | totale | asymétrique (sortant seul) | **remet `SocketAddr` en cause** | **idem + tunnels unidirectionnels** | — |
| **OPERATIONAL_RISK** | faible | dépendance + dépendance de sortie + fingerprint | fuite annulant tout + refonte des quotas 2C/2D | écosystème + seuil de peuplement | coût sans bénéfice immédiat |

---

## 7. Constats transversaux

1. **Aucune option ne protège le registre public.** Clé publique, adresse,
   montant et `timestamp` ms sont visibles par tous, quel que soit le
   transport. C'est une propriété du protocole de consensus, pas du transport.
2. **Aucune option ne protège l'origine d'une transaction contre un pair.**
   Le relay immédiat sans jitter (`p2p.rs:3249-3258`) est observé par les
   pairs, pas par le transport. Seule la étape **2E-D** y touche.
3. **Le `Inventory` non borné est un problème transverse** : sur TCP c'est une
   fuite de taille de DAG, sur Tor/I2P c'est un coût de circuit. Il est
   corrigible indépendamment du transport et appartiendrait à **2E-A**.
4. **`FRAME_TIMEOUT = 30 s` est le paramètre le plus contraignant** pour tout
   transport alternatif ; il n'a pas été conçu pour des circuits à latence
   variable.
5. **Le groupement `/24` est la défense 2C ET le présupposé de transport.**
   C'est le principal risque structurel de toute migration : on ne peut pas
   ajouter un transport sans redéfinir ce qu'est un « groupe ».

---

## 8. Sortie

```
TRANSPORT_TCP           = ANALYZED
TRANSPORT_TOR           = ANALYZED   (SOCKS sortant et service onion bilatéral, séparément)
TRANSPORT_I2P           = ANALYZED
TRANSPORT_ABSTRACTION   = ANALYZED   (API proposée, couplage cartographié, coût et bénéfice évalués)

TRANSPORT_IMPLEMENTED   = NONE
TRANSPORT_CODE_CHANGES  = NONE
2E_CODE_CHANGES         = NONE
2E_COMMIT               = NONE
DEPLOYMENT              = NONE
V1.4.0_IMMUTABLE        = PASS
```

**Aucun de ces transports n'est implémenté. Aucun n'est recommandé « tout de
suite »** : la séquence, les conditions de sortie et les tests requis figurent
dans `docs/AETHER_NETWORK_PRIVACY_ROADMAP.md`.
