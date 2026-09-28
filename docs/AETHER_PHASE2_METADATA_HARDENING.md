# AETHER — Phase 2E-A : hardening des métadonnées réseau

**Étape :** 2E-A (périmètre strictement A.1 + A.2 + A.3)
**Branche :** `dev/phase2-decentralized-network`
**Commit :** `phase2: harden network metadata privacy`
**Companion :** `AETHER_NETWORK_PRIVACY_ROADMAP.md` (§2 « 2E-A »),
`AETHER_PHASE2_PRIVACY_THREAT_MODEL.md` (matrice de fuites)

> Ce document décrit **uniquement** ce qui a été codé dans ce commit. Tout ce
> qui figure dans la roadmap et qui n'est pas ici n'est pas implémenté.

---

## 0. Portée

### Inclus (IN_SCOPE)

| Sous-partie | Changement | Wire ? |
|---|---|---|
| **A.1.a** | peer store écrit avec permissions **0600** | non |
| **A.1.b** | masquage des adresses dans `logs/node.log` | non |
| **A.1.c** | revue de ce que `/metrics` et le RPC exposent | non — **revue propre, aucun changement** |
| **A.2.i** | réponse à `SyncRequest` bornée à `MAX_INV_ITEMS`, fenêtre **rotative** | non |
| **A.2.ii** | aléa de cadence PEX ~15 s | non |
| **A.2.iii** | aléa sur `RECOVERY_INTERVAL` et sur le redial | non |
| **A.3.a** | padding de `total_len` par paliers de **256** o | **oui** |
| **A.3.b** | obfuscation de la magie `AETH` | **oui** |
| **A.3.c** | `P2P_PROTOCOL_VERSION` **3 → 4** | **oui** |

### Exclus (OUT_OF_SCOPE)

- **Propagation des transactions (2E-D)** — `TRANSACTION_PROPAGATION = OUT_OF_SCOPE_FOR_2E_A`.
- **Métadonnées du handshake** (chiffrer/authentifier le handshake, masquer la
  clé éphémère) — hors périmètre de 2E-A. Ce que 2E-A garantit ici tient en
  une **borne de taille**, pas en un secret.
- **Compteur en clair** (`FRAME_COUNTER_METADATA = DEFERRED`) — masque XOR à
  nonce dérivé du compteur : le masque est constant sur une séquence, donc non
  sonore sur un compteur monotone. Interdit de toucher `build_nonce`,
  `send_direction`, `nonce_collision_possible`, `last_recv_counter`.
- **Chiffrement au repos du peer store** — `PEER_STORE_ENCRYPTION = NOT_REQUESTED` :
  0600 a été choisi à la place, sans secret supplémentaire à protéger.
- Tor, I2P, abstraction de transport, mixnets, DHT privacy, consensus privacy,
  paiement privé, anonymat.

---

## 1. Menace ciblée

Un **observateur passif qui n'est pas un pair** — sur le même LAN, au niveau
d'une IA, d'un FAI, ou un pair compromise mais passive — qui ne fait que
compter et mesurer les octets du flux TCP entre deux nœuds AETHER. Cet
observateur n'a **pas** la clé AEAD : il ne lit aucun contenu. Il ne lui reste
que :

1. la **longueur** de chaque trame,
2. le **moment** où elle part,
3. le **fichier de pairs** laissé sur disque par le nœud, et le **log** qu'il
   peut lire si le disque n'est pas chiffré.

C'est la menace qui produit, dans la matrice de fuites, les lignes
`DAG size`, `frame length` (avant : « en clair ») et
`LOCAL_METADATA_EXPOSURE = HIGH`.

**Ce que la menace ne couvre pas** : un adversaire global qui corrèle la
timelines de tous les flux, ou qui lit la sortie du nœud. Rien de ce qui suit
ne répond à ça — voir §5.

---

## 2. Fuite avant

| Fuite | Où | État avant |
|---|---|---|
| Peer store en clair, permissions larges | `P2PNetwork::save_known_peers` | `PEER_STORE_PRIVACY_RISK = MEDIUM` |
| Adresse IP en clair dans `logs/node.log` | `init_node_logging` (`main.rs:340`) | `LOCAL_METADATA_EXPOSURE = HIGH` |
| Réponse à `SyncRequest` = **tout le DAG** | arm `SyncRequest` | `total_len` ≈ taille du DAG → oracle direct |
| Cadence PEX fixe à 15 s, recovery/redial à 5 s | `start_pex` / `start_recovery_task` / `start_reconnection_task` | empreinte de reconnaissance stable |
| `total_len` = taille exacte du message | boucle d'émission | longueur en clair, 1 octet de résolution |
| Magie ASCII `AETH` en tête de handshake | `handshake` / `verify_handshake_identity` | signature de protocole détectable à la volée |

---

## 3. Mécanisme

### A.1 — local

**a. Peer store 0600.** `save_known_peers` écrit via `write_private_file`
(`src/p2p.rs`), qui ouvre le fichier avec `OpenOptions::mode(0o600)` sous Unix,
écrit, puis **ré-applique** `set_permissions(0o600)` : `OpenOptions::mode()`
ne s'applique qu'à la création, donc un `.tmp` hérité avec des permissions
larges (crash antérieur) ne serait jamais resserré sans cette seconde passe.
Le `.tmp` est ensuite renommé atomiquement. Sur Windows il n'y a pas de bits
POSIX : la fonction écrit quand même (testé), et la propriété 0600 est un
garant Unix uniquement — cf. §5.

**b. Masquage des logs.** Nouveau module `src/log_privacy.rs`, branché par
`init_masked_node_logging` au lieu de `init_node_logging` dans `src/main.rs`.
Le fichier `src/node_logging.rs` n'est **pas** modifié (il est dirty depuis une
autre session et hors périmètre) : `log_privacy` réutilise `NodeLineFormat`,
`RollingFileWriter` et `RollingGuard` tels quels, et wrappe la couche de
sortie avec `MaskingGuard`, qui **bufferise par ligne** et applique
`mask_socket_addrs_with_salt`.

Le masque est `p2p.` + 6 caractères hex dérivés de `fnv1a(addr) ⊕ sel`, le sel
étant un `u64` tiré au chargement du module et stocké en `OnceLock` — donc
**stables pour la vie du processus, différentes entre deux processus**. Un
adversaire qui lit deux logs de deux nœuds ne peut donc pas joindre les tags
entre eux. Le masquage ne touche ni les horodatages, ni les cibles
`aether_unified::…`, ni les hashes de transaction, ni les glyphe multi-octets.
Un test vérifie explicitement que la détection IPv6 ne mord **pas** sur
`aether_unified::…` (le `ed::` du chemin).

**c. Revue `/metrics` + RPC.** Les trois routes (`/`, `/explorer`,
`/metrics`, `rpc.rs:2313/2318/2324` + `handle_metrics :2841`) n'exposent
**aucun champ d'adresse** : `connected_peers` est un compteur, `remote_addr`
sert uniquement de clé de rate-limiting. → `METRICS_REVIEW = CLEAN`,
**aucun code changé**.

### A.2 — réseau, sans changement de wire

**(i) `SyncRequest` borné et rotatif.** `inventory_window(hashes, cursor)`
renvoie au plus `MAX_INV_ITEMS` (1000) entrées, en partant d'un offset lu et
incrémenté dans un `static SYNC_WINDOW_CURSOR: AtomicU64`. Un simple
`take(MAX_INV_ITEMS)` aurait été **faux** : `get_dag_hashes()` (`node.rs:516`)
vient d'un `HashMap`, dont l'ordre est fixe → la même tranche serait toujours
envoyée et le reste du DAG ne serait jamais annoncé. La rotation fait couvrir
l'ensemble entier en `ceil(n / MAX_INV_ITEMS)` tours, ce qui préserve le
comportement de sync tout en bornant `total_len`.

**(ii)(iii) Aléa de cadence.** `jittered_interval(base, max_jitter, r)`
ajoute `r % (span+1)` millisecondes : **borné unilatéralement**, jamais en
deçà de la baseline (donc aucun surcoût de trafic, aucun surcroît de pression
de dial), jamais au-delà de la borne déclarée.

| Boucle | Baseline | Jitter |
|---|---|---|
| PEX | 15 s | +0 … +4 s |
| recovery | 5 s | +0 … +2 s |
| redial | 5 s | +0 … +3 s |

### A.3 — wire, bump de version

**a. Padding par paliers.** Nouveau format de trame (`src/p2p.rs:57`) :

```
u32 total_len   // multiple de 256, ≥ 256, ≤ MAX_MESSAGE_SIZE ; n'inclut pas ses propres 4 octets
nonce 12
ciphertext = AEAD(payload || u16 LE pad_len || pad[0..pad_len])   // pad_len ∈ [0, 255]
tag 16
```

- `FRAME_PAD_BUCKET = 256`, `MAX_FRAME_PADDING = 255`, `FRAME_PAD_TAIL = 2`,
  `FRAME_FIXED_OVERHEAD = 12 + 16 + 2 = 30`.
- `pad_message` / `unpad_message` : le padding vit **dans** l'AEAD, donc
  modifier la longueur du pad casse Poly1305 (test
  `test_padding_is_authenticated`).
- `padded_total_len(msg_len)` = `round_up(30 + msg_len, 256)`, `None` si
  `30 + msg_len > FRAME_MAX_EMIT` (`MAX_MESSAGE_SIZE - 256`).
- `pad` est une **fonction pure** de la longueur : aucun RNG sur le chemin
  d'émission → aucune divergence entre pairs, tests déterministes.
- **Deuxième couche** : le récepteur rejette tout `total_len` non multiple de
  256 **avant toute allocation** (`valid_frame_len`), ce qui repousse aussi
  une trame v3 même si elle avait passé le contrôle de version.

**b. Magie obfuscée.** `handshake_wire_magic() = HANDSHAKE_MAGIC ⊕ HANDSHAKE_MAGIC_MASK`
= `7E 34 F1 54` au lieu de `41 45 54 48` (`AETH`). `handshake()` l'écrit,
`verify_handshake_identity()` la compare.

**c. Version.** `P2P_PROTOCOL_VERSION` **3 → 4**. `PROTOCOL_COMPATIBILITY =
BREAKING`. `verify_handshake_identity` rejette d'abord la magie (un pair v3
envoie l'ancienne → `magic`), puis la version (`version`).

---

## 4. Fuite après

Ce qui reste, et ce qui a été **réduit** :

| | Avant | Après |
|---|---|---|
| Taille du DAG via `SyncRequest` | en clair, 1 octet | bornée à 1000 entrées, tournante |
| Longueur de trame | exacte | palier de 256 o — deux messages d'une même plage sont **bit-à-bit identiques en longueur** |
| Cadence PEX / recovery / redial | 15 s / 5 s / 5 s | bandes bornées [15,19] / [5,7] / [5,8] s |
| Signature `AETH` | détectable à la volée | absente du flux (obfuscation) |
| Peer store sur disque | permissions larges | 0600 (Unix) |
| IP dans `logs/node.log` | en clair | tag `p2p.xxxxxx` |

**Ce qui reste volontairement en clair** : les 4 octets de `total_len` (mais
résolus à 256 o), les 12 octets de nonce, le nombre et le rythme des trames,
la destination IP:port de chaque connexion TCP, le handshake de 69 o, et tout
le contenu trafic ↔ flux. Le peer store reste en JSON **lisible** par le
propriétaire ; seule la permission change.

---

## 5. Limites — ce que ce commit ne prouve PAS

Interdits rappelés par la roadmap §4 :

- **`IP_PRIVACY_CURRENT` reste `NONE`** — 2E-A ne touche pas à l'IP de
  transport. Les adresses IP voyagent dans chaque paquet TCP et dans chaque
  handshake. Il faut 2E-B/2E-C pour ça.
- **`ANONYMITY_CURRENT` reste `NONE`.** Aucun mécanisme d'anonymat n'est
  implémenté ici, et ce document ne prétend pas le contraire.
- **`TRANSACTION_CORRELATION_RISK` reste `HIGH`** — la propagation des
  transactions est hors périmètre (2E-D).
- **Le padding n'est pas un secret.** L'observateur voit toujours la taille de
  connexion, le nombre de trames et leur cadence ; il ne peut plus distinguer
  *deux tailles de message situées dans le même palier*, ce qui est beaucoup
  plus faible que « il ne voit rien ». Aucune phrase du type « l'adversaire ne
  peut pas relier… » n'est soutenue par ce commit.
- **L'obfuscation de la magie n'est pas du chiffrement.** XOR avec une constante
  publique est involutif ; le test le dit explicitement. Son seul effet est de
  retirer une signature ASCII de 4 lettres à un DPI de bas niveau.
- **Le masquage de log ne protège que contre qui lit les fichiers** — pas contre
  qui lit la sortie du processus, et pas contre un disque non chiffré si le
  peer store (0600, mais en clair) est lue par root.
- **0600 est Unix.** Sous Windows la propriété n'existe pas ; seul le chemin
  d'écriture est testé.
- **Compatibilité : c'est une rupture.** Un v3 et un v4 ne parlent pas
  ensemble. Aucune fenêtre de compatibilité, aucun fallback — c'est le choix
  assumé de 2E-A (`PROTOCOL_COMPATIBILITY = BREAKING`).

---

## 6. Compatibilité

| | |
|---|---|
| `PROTOCOL_VERSION_NEW` | **4** |
| `PROTOCOL_VERSION_OLD` | **3** |
| `PROTOCOL_COMPATIBILITY` | **BREAKING** |
| Rejet côté handshake | magie d'abord, puis version |
| Rejet côté trame | `total_len` non multiple de 256 → `PEER_PENALTY_INVALID_MSG` |
| `v1.4.0-testnet` | **inchangé** (`ad08e308…`), jamais touché |

Aucun déploiement : `DEPLOYMENT = NONE`.

---

## 7. Tests

### Nouveaux : `p2p::phase2_privacy_tests` — **16/16**

| Test | Couvre |
|---|---|
| `test_protocol_version_bump` | A.3.c — bump unique, rejet v3 (magie puis version) |
| `test_handshake_magic_is_obfuscated` | A.3.b — magie ≠ `AETH`, XOR réversible documenté |
| `test_handshake_metadata_exposure` | A.3 — 69 o, décomposition octet par octet, aucun champ supplémentaire |
| `test_frame_size_buckets` | A.3.a — 18 tailles alignées sur 256 ; 100 B et 200 B → même `total_len` |
| `test_padding_bounds` | A.3.a — padding borné, roundtrip exact |
| `test_max_padding` | A.3.a — `MAX_FRAME_PADDING` atteint (227 o) + balayage 0..2000 |
| `test_padding_determinism` | A.3.a — fonction pure, pas de RNG d'émission |
| `test_old_frame_rejected` | A.3.a — toute longueur non alignée refusée |
| `test_frame_metadata_hardening` | A.3 — trame réelle : longueur bornée, adresse hors ciphertext, roundtrip |
| `test_no_plaintext_peer_metadata` | A.3 — `Peers` (IPv4 + IPv6) et `Inventory` : aucun octet d'identifiant sur le fil |
| `test_padding_is_authenticated` | A.3.a — bit de padding retourné → Poly1305 échoue |
| `test_inventory_size_not_leaked` | A.2.i — borné à 1000, indépendant de la taille du DAG, rotation sans chevauchement |
| `test_pex_privacy_bounds` | A.2.ii — 10 000 tirages dans [15 s, 19 s] |
| `test_pex_rate_limit` | A.2.ii/iii — jitter réel (pas une constante), baseline atteignable, 3 boucles bornées |
| `test_peer_store_privacy` | A.1.a — 0600 à la création **et** re-tightening d'un `.tmp` élargi |
| `test_peer_store_no_addresses_in_logs` | A.1.b — ligne INFO avec IP → tag, horodatage/cible intacts |

### Nouveaux : `log_privacy::tests` — **12/12**

`masks_ipv4_with_port`, `masks_ipv4_without_port`, `masks_ipv6_bracketed_and_bare`,
`leaves_module_paths_alone`, `leaves_timestamps_and_versions_alone`,
`leaves_transaction_hashes_alone`, `masking_is_idempotent`,
`different_salt_changes_the_tag`, `different_addresses_get_different_tags`,
`same_input_same_salt_is_stable`, `multi_byte_glyphs_survive`,
`guard_masks_across_split_writes`.

### Non écrit, et pourquoi

`test_no_ip_in_metrics` (§3 n° 8) n'a **pas** été écrit : la revue A.1.c a
établi que `/metrics` et les réponses RPC n'exposent aucun point-quadruplet.
Ajouter un test eût été un test de non-régression sur du code que ce commit ne
change pas → `METRICS_REVIEW = CLEAN`, test non requis. Les tests §3 n° 9–18
appartiennent à 2E-B/C/D et ne sont **pas** écrits ici.

### Régressions (gates)

```
cargo check --lib                            # 9 warnings, 0 nouveau
cargo test --lib p2p::                       # 131/131   (115 + 16)
cargo test --lib phase2_decentralized_tests  # 26/26
cargo test --lib phase2_eclipse_tests        # 15/15
cargo test --lib phase2_self_healing_tests   # 17/17
cargo test --lib bootstrap_phase1            # 19/19
cargo test --lib p2p::phase2_privacy_tests   # 16/16
cargo test --lib log_privacy                 # 12/12
```

---

## 8. Coût mesuré

Benchmark reproductible :
`cargo test --release --lib p2p::phase2_privacy_tests::bench_2e_a_costs -- --ignored --nocapture`
(rustc 1.97.1, `release`, best-of-6).

### `METADATA_OVERHEAD`

Balayage exhaustif de **4 097** tailles de payload (0 … 4096 o), en clair :

| Métrique | Valeur |
|---|---|
| surcoût moyen | **129,5 o** par trame (= `(2 + 255) / 2`, comme attendu pour un arrondi uniforme) |
| surcoût pire cas | **257 o** (= `2 + 255`, atteint — borne serrée, pas décorative) |
| garantie | `0 ≤ extra ≤ 257` pour **toutes** les tailles |

Messages réels :

| Message | payload | `total_len` v3 | `total_len` v4 | extra | % |
|---|---|---|---|---|---|
| `Peers(8)` | 92 o | 120 | 256 | +136 o | **+113,33 %** |
| `Inventory(100)` | 4 012 o | 4 040 | 4 096 | +56 o | +1,39 % |
| `Inventory(1000)` | 40 012 o | 40 040 | 40 192 | +152 o | +0,38 % |

Le coût est donc **concentré sur les petites trames** (les messages de
signalisation PEX/ping) et **négligeable sur les grosses** (sync). C'est le
prix attendu de tout arrondi à 256 o, et c'est la raison pour laquelle le
palier n'est pas plus fin : à 64 o on diviserait le masquage par 4 pour
gagner ~96 o sur une trame de signalisation.

### `LATENCY_IMPACT`

| Mesure | Valeur |
|---|---|
| `pad + unpad`, petite trame (92 o) | **144,3 ns**/trame |
| `pad + unpad`, grosse trame (40 012 o) | 3 883,5 ns/trame |
| …dont part « copie du payload » (grosse − petite) | 3 739,2 ns |
| **coût attribuable au padding lui-même** | **≈ 0,14 µs/trame** |
| chiffrement v3 vs v4 (trame 40 Ko) | 55 742 ns → 56 681 ns, **+939 ns (+1,69 %)** |

Le surcoût mesuré suit la bande ajoutée : `+152 o` à ~718 MB/s ≈ +0,9 µs.
Cohérent des deux côtés, ce qui est la vérification utile — le padding
n'ajoute aucune surcharge algorithmique, seulement des octets.

### `THROUGHPUT_IMPACT`

| | |
|---|---|
| v3 (sans padding) | 717,8 MB/s |
| v4 (avec padding) | 708,6 MB/s |
| **impact** | **−1,28 %** |

Variation de ±1,5 points entre deux exécutions (best-of-6, charge machine) :
à rapporter comme « de l'ordre de −1 % », pas comme une mesure à deux
décimales.

---

## 9. Reste non résolu (ouvert pour les étapes suivantes)

| Question | Étape |
|---|---|
| IP de transport visible par tout observateur (`IP_PRIVACY_CURRENT = NONE`) | 2E-B, 2E-C |
| Corrélation de transaction (`TRANSACTION_CORRELATION_RISK = HIGH`) | 2E-D |
| Handshake non authentifié (pas d'authenticité de pair, seulement du réseau) | hors roadmap actuelle |
| Compteur de frames en clair (`FRAME_COUNTER_METADATA = DEFERRED`) | à réévaluer |
| Peer store lisible (0600, pas chiffré) | `PEER_STORE_ENCRYPTION = NOT_REQUESTED` |
| Métadonnées de bootstrap : ce que reçoit réellement un seed | 2E-C |
| Existence/annulation des nœuds (timing global, corrélation multi-nœuds) | 2E-E, **sans conception à ce jour** |

Aucune de ces questions n'est améliorée, ne serait-ce qu'un peu, par ce
commit ; aucune n'est réglée non plus. Elles sont listées pour que la
séquence ne soit pas relue comme si 2E-A suffisait.
