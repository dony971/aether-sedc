# AETHER — Phase 2E-D : propagation de transaction aware de la confidentialité

**Étape :** 2E-D (`PRIVACY-AWARE TRANSACTION PROPAGATION`)
**Branche :** `dev/phase2-decentralized-network`
**HEAD au départ :** `b3f9839 phase2: harden network metadata privacy`
**Commit visé :** `phase2: harden transaction propagation privacy`
**Entrées :** `AETHER_PHASE2_PRIVACY_THREAT_MODEL.md` (§4.3),
`AETHER_NETWORK_PRIVACY_ROADMAP.md` (§2 « 2E-D »),
`AETHER_TRANSPORT_COMPARISON.md`

> **Ce document commence par un audit, rédigé AVANT toute modification de
> code.** La section §2 (audit) décrit l'état du code tel qu'il était au
> `HEAD` ci-dessus. Les sections suivantes décrivent ce qui a été codé.
>
> **Ce document ne conclut jamais « Aether est anonyme ».** Le résultat
> visé — et le seul — est
> `TRANSACTION_CORRELATION_RISK = REDUCED`.
> `ANONYMITY_CURRENT = NONE` et `IP_PRIVACY_CURRENT = NONE` **restent inchangés**.

---

## 1. Périmètre

### Inclus (IN_SCOPE)

| | Changement | Wire ? |
|---|---|---|
| **D.1** | délai + jitter de relais, **par peer**, avant chaque envoi | non |
| **D.2** | fanout borné et diversifié au lieu de « tous les peers » | non |
| **—** | suppression du relay **pré-validation** (relay n° 1) | non |
| **—** | dédup de *planification* avant tout scheduling | non |
| **—** | exclusion systématique du peer source | non |

### Exclus (OUT_OF_SCOPE)

Tor, I2P, mixnet, onion routing, **Dandelion complet** (D.4), identité
anonyme, abstraction de transport (2E-B), chiffrement de transport
supplémentaire, **D.3** (annonce par inventaire → `Inventory` puis `GetData`),
contenu/cryptographie de la transaction, consensus, PoW, difficulté.

> **PROTOCOL_CHANGE = NONE** — aucun octet ne change de sens sur le fil :
> ni format de message, ni ordre, ni taille. `P2P_PROTOCOL_VERSION` reste
> **4**. Aucun bump.

---

## 2. TRANSACTION_PROPAGATION_AUDIT *(rédigé avant code)*

### 2.1 `BEFORE_FLOW`

**Origine distante — `P2PMessage::Transaction` (le chemin « push ») :**

| # | Étape | Endroit |
|---|---|---|
| 1 | réception du payload | `p2p.rs:3572` (bras de réception) |
| 2 | **dédup** vs `seen_transactions` (clé = octets bruts, TTL 300 s, cap 50 000) → stop si déjà vu | `p2p.rs:3575` |
| 3 | `bincode::deserialize::<Transaction>` | `p2p.rs:3582` |
| 4 | `insert_seen` (horodatage 1ʳᵉ observation) | `p2p.rs:3584` |
| 5 | `tx_channel.send(tx)` → récepteur `node.rs` | `p2p.rs:3593` |
| 6 | **RELAY n° 1 — immédiat, vers TOUS les peers sauf la source, AVANT toute validation** | **`p2p.rs:3596-3604`** |
| 7 | `process_transaction(tx, "P2P", Historical)` | `node.rs:634` |
| 8 | `validate_pure` (PoW + signature) → `Err` si invalide | `rpc.rs:1128` |
| 9 | dédup DAG → `Err("Duplicate transaction")` | `rpc.rs:1142` |
| 10 | gate de fee + `mempool.enqueue` | `rpc.rs:1160-1179` |
| 11 | **RELAY n° 2 — `broadcast_transaction`, vers TOUS les peers, source comprise** | **`rpc.rs:1185` → `p2p.rs:4183`** |
| 12 | plus tard : drainer → commit DAG | `node.rs` |

**Conséquence mesurée :** une transaction acceptée est transmise **deux fois**
sur chaque lien sortant ; une transaction **rejetée** (PoW ou signature
invalides) est quand même transmise **une fois** (étape 6).

**Origine locale — RPC `send_transaction`** : un seul relay (étape 11), mais
**après** `validate_pure` ✓.

**Origine `GetData` (sync, `p2p.rs:3910-3922`)** : `insert_seen` puis
`tx_channel.send` → étapes 7-11 → un seul relay, après validation, mais
**sans exclusion de la source**.

### 2.2 `DUPLICATE_RELAY_PATHS`

| Path | Déclencheur | Cible | Moment |
|---|---|---|---|
| **A** | bras `P2PMessage::Transaction` | tous les peers **sauf la source** | **avant validation** |
| **B** | `process_transaction` → `broadcast_transaction` | **tous** les peers, source comprise | après accept |
| **C** | `Inventory` → `GetData` → réponse | pas un push : la réponse ré-entre par `tx_channel` et **rejoue le path B** | après accept |

Paths A **et** B pour tout ce qui arrive en push → double relay. Le path A
part même pour des payloads invalides.

### 2.3 `TIMING_LEAKS`

1. **`receive_t ≈ relay_t`** pour le path A : aucune attente entre la
   réception et l'envoi, dans la même tâche. Un voisin qui observe le
   retransmetteur voit les deux instants se succéder sans décalage.
2. **Deux envois par lien à ~le même instant** (A puis B, séparés seulement
   par la latence de validation) — signature de tracé propre à ce nœud.
3. `tracing::debug!("Received transaction from {addr}: {hash}")`
   (`p2p.rs:3588`) : peer source + hash. Niveau DEBUG.
4. `insert_seen.timestamp` : interne (évacuation uniquement), jamais exposé.
5. `/metrics` et RPC : **aucun** horodatage de propagation (revu propre en
   2E-A, `METRICS_REVIEW = CLEAN`).
6. Depuis 2E-A, `total_len` est par paliers de 256 o → la taille du payload
   n'est plus un signal complémentaire.

### 2.4 `TOPOLOGY_LEAKS`

1. **Fanout = toute la table de pairs**, la même sur les deux paths → tous
   les voisins apprennent la transaction à peu près au même instant ; aucune
   dé-synchronisation, donc pas de dilution de l'empreinte.
2. Source exclue sur le path A mais **incluse** sur le path B → la source
   reçoit immédiatement son propre écho : elle peut constater qu'elle était
   en amont d'un nœud qui vient de relayer.
3. L'ordre d'envoi est celui d'une itération `HashMap` : pseudo-hasard de
   hachage, **identique pour les deux paths d'un même payload** — pas
   d'aléa délibéré.

### 2.5 `CURRENT_FANOUT`

`|peers connectés|` — **non borné**, de 0 à `MAX_PEERS = 128`.

### 2.6 `CURRENT_PEER_SELECTION`

Aucune sélection : itération complète de `peers: HashMap<SocketAddr,
UnboundedSender<Vec<u8>>>`. Ni diversité réseau, ni score, ni exclusion de
la source (path B), ni aléa.

### 2.7 `CURRENT_DEDUP`

| Couche | Mécanisme | Où |
|---|---|---|
| réception | `seen_transactions` (octets bruts), TTL 300 s, cap 50 000 | `p2p.rs:3575` |
| consensus | appartenance au DAG | `rpc.rs:1142` |
| sync | frontier / orphelins | `p2p.rs:3614-3642`, `3910-3922` |
| **scheduling** | **aucun** — `broadcast_transaction` ne consulte rien avant d'envoyer, il ne fait qu'**insérer** dans `seen_transactions` | `p2p.rs:4193` |

### 2.8 `TARGET_FLOW`

```
RECEIVE
   ↓
DEDUPE            (seen_transactions — AVANT tout scheduling)
   ↓
VALIDATE / ACCEPT (validate_pure: PoW + signature → dédup DAG → fee → mempool)
   ↓
STORE             (mempool ; commit DAG plus tard par le drainer)
   ↓
SCHEDULE          (UNE seule vague de relais, marquée dans PropagationState)
   ↓
PER-PEER RANDOMIZED DELAY   (jitter borné, RNG injecté)
   ↓
BOUNDED FANOUT    (≤ MAX_PROPAGATION_FANOUT, diversifié, source exclue)
   ↓
FORWARD
   ↓
OTHER PEERS
```

### 2.9 Raison technique du relay pré-validation — **aucune trouvée**

Le point 6 du `BEFORE_FLOW` est-il nécessaire à quelque chose ? Vérification
faite, **non** :

* les transactions orphelines (parents absents) ne dépendent **pas** du
  path A : `process_transaction` ne teste pas les parents, donc un orphelin
  est bel et bien relayé à l'étape 11 — leur propagation est préservée ;
* la dédup ne dépend pas du path A : elle est faite étape 2, en amont ;
* aucun test existant n'exerce le relay du bras de réception
  (`P2PMessage::Transaction` n'apparaît dans aucun test) ;
* aucun code en aval ne consomme le fait que « ça a déjà été envoyé ».

Ce que le path A apporte réellement : relayer des payloads **invalides**, et
transmettre deux fois chaque payload accepté. **Il est supprimé.**

**Conséquences assumées** (à surveiller, et couvertes par le backstop de
sync) :

| Cas | Avant | Après |
|---|---|---|
| PoW/signature invalides | relaies une fois | **jamais relaies** |
| déjà dans le DAG | relaies une fois (path B) | jamais relaies |
| fee < min_fee local | relaies (2×) | **pas relaies par ce nœud** |
| mempool plein | relaies (2×) | **pas relaies par ce nœud** |
| orphelin (parents absents) | relaies (2×) | relaies **une fois** ✓ |
| acceptée | relaies **2×** | relaies **une fois** ✓ |

Les deux dernières lignes défavorables (fee/mempool) sont couvertes par
**l'`Inventory` sync de rattrapage, toutes les 10 s**
(`node.rs:766` → `request_full_sync`), qui reste inchangé : c'est le
mécanisme qui garantit la convergence indépendamment du fanout.

---

## 3. Décisions d'architecture

### 3.1 Constantes (`src/p2p.rs:345-352`)

| Constante | Valeur | Rôle |
|---|---|---|
| `PROPAGATION_JITTER_MIN` | **20 ms** | plancher du délai de relais |
| `PROPAGATION_JITTER_MAX` | **250 ms** | plafond du délai de relais |
| `MAX_PROPAGATION_FANOUT` | **4** | nombre max de peers destinataires d'une vague |

**Dérivation (et non choix arbitraire) :**

* **MIN = 20 ms.** Ce qui compte, c'est seulement que `relay_t != receive_t`
  sur *chaque* lien. 20 ms est au-dessus du bruit de traitement local / RTT
  LAN (quelques ms) — le décalage est donc réel, pas un arrondi — et deux
  ordres de grandeur sous toute cadence de consensus ou de confirmation : il
  ne peut pas être lu comme un événement de protocole. `MIN > 0` est
  asserté : `relay_t == receive_t` n'est pas constructible.
* **MAX = 250 ms.** Il doit rester très en dessous des deux horloges qui bornent
  déjà la convergence : l'`Inventory` sync de rattrapage tourne **toutes les
  10 s** (`node.rs:766` → `request_full_sync`), et `FRAME_TIMEOUT = 30 s`.
  250 ms = **2,5 %** du backstop. Une chaîne A→B→C→D→E complète coûte donc
  **≤ 1 s** au pire cas (≤ 0,5 s attendu, uniforme), tout en éparpillant le
  fan-out d'un nœud sur une fenêtre de 230 ms — quatre ordres de grandeur
  au-dessus des 0 ms d'aujourd'hui.
* **FANOUT = 4.** Le gossip aléatoire avec fan-out ≥ 3-5 est le point de
  fonctionnement standard ; 4^h couvre une table de 128 peers
  (`MAX_PEERS`) en 4 hops. Surtout : **le fan-out n'est PAS la garantie de
  convergence** — c'est `request_full_sync` toutes les 10 s, inchangé.
  Descendre le fan-out sous le degré typique reviendrait à troquer une
  couverture réelle contre un gain de confidentialité que cette étape ne peut
  pas promettre ; il reste donc volontairement conservateur.

**Aucune `PROPAGATION_MAX_ROUNDS`.** Cette architecture n'a pas de tours :
chaque nœud relaie **une fois**, à la première acceptation ; les retards sont
couverts par l'`Inventory` sync existant, pas par une deuxième vague. Ajouter
une constante de tours documenterait un mécanisme qui n'existe pas.

### 3.2 État de planification : `PropagationState`, séparé de `seen_transactions`

```rust
struct PropagationEntry {
    timestamp: Instant,             // règle de rétention commune
    source: Option<SocketAddr>,     // peer d'amont, à exclure (None = local)
    scheduled: bool,                // la vague de relais est déjà prise
}
type PropagationState = HashMap<Vec<u8>, PropagationEntry>;
```

**Pourquoi une map séparée et non deux champs de plus sur `SeenTxEntry` :**

1. `SeenTxEntry` est construit **littéralement** par plusieurs tests
   existants qui n'exercent que la réception (`p2p.rs:8484, 8503, 8521,
   8579, 8583`). Y ajouter un champ forcerait à réécrire ces tests pour
   décrire un mécanisme qu'ils ne testent pas — exactement ce qu'il ne faut
   pas faire.
2. Les deux questions sont réellement différentes : `seen` répond « *je l'ai
   déjà reçu ?* », `PropagationState` répond « *ai-je déjà planifié une vague
   pour cet octet, et de quel peer vient-il ?* ».

Dédup centralisée : **une seule** clé (les octets bruts du payload, comme
`seen_transactions`), **un seul** mécanisme, réutilisé par les deux chemins
d'entrée. Aucun deuxième système de dédup n'est inventé.

**Rétention** : règle commune `PAYLOAD_CACHE_TTL = 300 s` + cap
`MAX_SEEN_TXS = 50 000`, appliquée par `bound_payload_cache`
(`p2p.rs:2295`) aux **deux** maps — y compris `insert_seen`, dont la logique
d'évacuation est extraite plutôt que dupliquée. Mémoire = O(50 000) sous
flood, pour les deux.

### 3.3 Plomberie

Le `PropagationState` doit être accessible là où `source` est connu (le bras
de réception) et là où la vague est planifiée (`broadcast_transaction`), qui
sont deux fonctions différentes. Il est donc passé explicitement :

* champ `propagation_state: Arc<RwLock<PropagationState>>` sur `P2PNetwork`
  (`p2p.rs:2311`), initialisé dans `new()` ;
* paramètre de `accept_loop` et de `handle_peer` (`p2p.rs:3599`), avec les 2
  sites d'appel (`accept_loop`, `connect_to_peer`) ;
* `propagation_rng: Arc<Mutex<StdRng>>` — le **seul** RNG de l'étape,
  semé `from_entropy` (politique du reste du nœud) ; mutex **jamais** tenu
  à travers un `.await`, pour qu'un test puisse le re-semer et rejouer une
  vague ;
* `propagation_inflight: AtomicUsize` + accesseur `propagation_inflight()`.

### 3.4 Flux après (=AFTER_FLOW, section 2.8 du §2)

```
P2P : bras Transaction (p2p.rs:3895)
  → accept_inbound_transaction (p2p.rs:1582)
      dedup → deserialize → insert_seen → record_propagation_source
      → tx_channel.send          [AUCUN RELAY]
  → node.rs:634 process_transaction
      → rpc.rs:1128 validate_pure        ← gate de validation
      → rpc.rs:1142 dédup DAG
      → rpc.rs:1160-1179 fee + mempool.enqueue
      → rpc.rs:1185 broadcast_transaction ← SEUL site de relay du code
          → p2p.rs:4543 take_propagation_slot   (dédup de planification)
          → propagation_targets  (≤ 4, diversifié, source exclue)
          → tokio::spawn + sleep(propagation_delay) par peer
```

`SyncResponse` (deep sync, `p2p.rs:4135`) enregistre lui aussi la source
(`p2p.rs:4231`) : sans cela, un payload arrivé par la sync serait re-renvoyé
à celui qui l'a envoyé.

### 3.5 Suppression du relay pré-validation

Le relay n° 1 (`p2p.rs:3596-3604` avant la modification) a été **supprimé**,
pas déplacé. La justification complète est au §2.9 : aucun besoin technique
ne le réclame, et il relaie des payloads invalides. Le bras de réception ne
contient plus aucun accès à la table de pairs — vérifié par test
(`test_relay_is_reachable_only_after_the_pure_gate`).

### 3.6 Pas de `PROPAGATION_MAX_ROUNDS`, pas de nouveau message

`PROTOCOL_CHANGE = NONE`. Aucun message ni champ n'est ajouté ; le jitter est
**local** : seul l'émetteur le connaît, le destinataire ne voit qu'un envoi
normal. `P2P_PROTOCOL_VERSION` reste **4** (le bump de 2E-A).

---

## 4. Jitter (`D.1`)

`propagation_delay` (`p2p.rs:619`) : uniforme sur `[20 ms, 250 ms]`, bornes
incluses, fonction **pure** du RNG injecté — pas d'horloge, pas d'état partagé,
et surtout **aucune dépendance au contenu**. Une dépendance au payload
remplacerait le signal de minutage fixe par une empreinte de contenu, ce qui
est strictement pire.

Le jitter est dessiné **par peer**, dans la même section critique que la
sélection des cibles : deux voisins n'observent donc jamais le même instant
de relais.

**Ce que le jitter n'est pas** (et 2E-D ne le prétend pas) : ce n'est pas une
défense contre un observateur qui voit les **deux** extrémités. C'est un
**plancher sous l'observation**, pas une garantie d'anonymat.

---

## 5. Fan-out borné et diversifié (`D.2`)

`propagation_targets` (`p2p.rs:646`), en quatre étapes :

1. **source retirée** — le peer d'amont possède déjà le payload ; le lui
   renvoyer gaspille une frame et signale que c'était nous ;
2. **mélange Fisher-Yates** avec le RNG injecté — jamais l'ordre d'itération
   du `HashMap`, différent par payload et par seed ;
3. **quota de diversité** : `ceil(limit / groupes_distincts)` par
   `network_group` — la primitive Phase 2C, **réutilisée** ;
4. **assouplissement** si la topologie offre moins de groupes que `limit`.

L'étape 4 est essentielle : la diversité est une préférence, la **taille du
fan-out est l'exigence**. Un nœud dans un seul /24 ne doit pas relayer vers
un peer au lieu de quatre — c'est testé
(`test_topology_cannot_shrink_the_fanout`).

Résultat : ≤ `MAX_PROPAGATION_FANOUT = 4`, sans doublon, source exclue, et
retour **strictement inférieur** à `limit` uniquement quand moins de peers
sont connectés.

---

## 6. Dédup de planification (`§2.7`, ligne « scheduling = aucun »)

`take_propagation_slot` (`p2p.rs:1542`) est appelé **en tout premier** dans
`broadcast_transaction`, avant `insert_seen`, avant toute sérialisation,
avant qu'une seule frame ne parte :

* `Some(Some(peer))` → cette appel possède la vague, à exclure `peer` ;
* `Some(None)` → origine locale (RPC/faucet/mineur), pas de peer à exclure ;
* `None` → déjà planifié : **retour immédiat**, rien n'est envoyé.

C'est la ligne qui fait passer le nombre de transmissions par lien de
**2 → 1**. Testé de bout en bout par
`test_a_payload_schedules_exactly_one_wave` et
`test_each_peer_receives_at_most_one_copy` (le second broadcast, identique,
délivre **0** message).

L'observation gagnante est la première : `record_propagation_source`
(`p2p.rs:1514`) préserve la source existante et ne dé-schedule jamais.

---

## 7. Validation avant relay

Aucun code nouveau ici — il s'agit de **ne pas court-circuiter** ce qui
existe. `broadcast_transaction` n'est appelé qu'à `rpc.rs:1185`, strictement
après `validate_pure` (`rpc.rs:1128`), la dédup DAG (`rpc.rs:1142`), le gate
de fee et `mempool.enqueue` (`rpc.rs:1175`).

Deux gardes-fous structurels, testés :

* `test_relay_is_reachable_only_after_the_pure_gate` : lit les sources
  (`include_str!`) et impose (a) `validate_pure` **avant** le relay dans
  `rpc.rs`, (b) **un seul** site d'appel, (c) le bras de réception sans
  `peers.read()` ni construction de message de relais ;
* `test_invalid_transaction_is_never_scheduled_for_relay` : un payload qui
  échoue à `validate_pure` n'a jamais `scheduled = true`.

---

## 8. Sélection des peers et primitives réutilisées

| Existant | Réutilisé pour 2E-D ? | Raison |
|---|---|---|
| `network_group` (`p2p.rs:530`) | **oui** | règle unique de groupement Phase 2C |
| `group_counts` (`p2p.rs:596`) | **oui** | quota par groupe, `ceil(limit/distinct)` |
| RNG injecté (`StdRng`, idiome Phase 2E-A) | **oui** | rejouable en test |
| `select_outbound` (`p2p.rs:859`) | **non** | sélection de **dial** : exclut les peers déjà connectés (`!connected.contains(a)`); alimenté de la table de sessions, il renverrait **toujours** un vecteur vide |
| `AddressManager` / `PeerRecoveryController` | **non** | concernent la **découverte** d'adresses (bannissement, ré-dial, ancres) ; les cibles de relais sont des pairs *connectés*, jamais des candidats à composer |
| `jittered_interval` (2E-A, `p2p.rs:3113`) | **non** | bornes de **cadence** avec rejet du tirage hors borne ; ici on veut au contraire un tirage uniforme *dans* l'intervalle |

Un éventuel prochain palier (ex. score de pairs dans la sélection) devrait
réutiliser `PeerScore`, pas en inventer un.

---

## 9. Performance et convergence

### 9.1 Mesures (release, `bench_transaction_propagation`, 6 exécutions)

| Métrique | Avant (2E-D) | Après |
|---|---|---|
| **`TRANSACTION_PROPAGATION_OVERHEAD`** | 64 000 frames / 1 000 payloads / 32 peers | **4 000 frames = 0,0625** de l'ancien coût (−93,75 %) |
| **`TRANSACTION_DUPLICATION_RATE`** | **2,00** copies par lien | **0,125** copies par lien |
| **`TRANSACTION_PROPAGATION_LATENCY`** | **0 ms** (émission dans la même tâche que la réception) | `first` 38,6–129,4 ms · `last` 189,0–275,9 ms · **spread 92,5–234,5 ms** (6 exécutions) |

* 64 000 = 1 000 payloads × 32 peers × **2** relays (les deux paths A et B) ;
* 4 000 = 1 000 payloads × 4 (fan-out borné, une seule fois) ;
* le spread mesure exactement ce que l'étape introduit : les voisins ne
  voient plus l'événement ensemble. Avant, il était 0 ms *par construction*.

### 9.2 Convergence (`test_multihop_convergence_stays_within_the_existing_bounds`)

| | Pire cas (8 hops) | Référence | Marge |
|---|---|---|---|
| chaîne de relais | 8 × 250 ms = **2,0 s** | sync backstop 10 s | < 10 s / 4 |
| chaîne de relais | **2,0 s** | `FRAME_TIMEOUT` 30 s | < 30 s / 4 |
| coût attendu (uniforme) | 8 × 135 ms = **1,08 s** | sync backstop 10 s | ≪ |

Un tableau de 128 peers couvert par un fan-out de 4 converge en **4 hops**
(≤ 1 s au pire) ; 8 hops est une marge ×2. Aucun des deux horloges
contrôleuses n'est modifié.

### 9.3 Coût d'exécution

* par relais : 1 verrou d'état + 1 tirage de RNG + `≤ 4` `tokio::spawn`, puis
  chaque tâche dort seule puis écrit ; **aucun blocage** du chemin appelant ;
* aucun lock n'est tenu à travers un `.await` (le bloc de sélection referme
  `peers.read()` et le mutex RNG avant tout `spawn`) ;
* `propagation_inflight` = `acceptances en vol × 4`, et **retombe à 0**
  (asserté par `test_inflight_relays_drain_to_zero`) : pas de file qui
  s'accumule ;
* mémoire d'état bornée par `bound_payload_cache` (50 000 entrées × 2 maps).

---

## 10. Révision des logs (§11)

| Avant | Après | Raison |
|---|---|---|
| `tracing::debug!("Received transaction from {addr}: {hash}")` | **`tracing::trace!`** dans `accept_inbound_transaction` (`p2p.rs:1607`) | triplet **(hash, source, horodatage)** lisible dans `node.log` : exactement ce qu'un lecteur local ne doit pas obtenir gratuitement. TRACE reste disponible pour une investigation ciblée, n'est pas écrit au niveau par défaut. |
| `warn!("Failed to send transaction to {addr}: channel closed")` | **`tracing::trace!("relay peer channel closed")`** (`p2p.rs:4591`) | ni adresse, ni hash, ni horodatage de relais : la sortie d'un pair n'est pas un événement de corrélation |

Aucun log ajouté. Aucun horodatage de propagation, aucune adresse de relais,
aucun compteur de fan-out exposé — `/metrics` reste tel que révisé en 2E-A
(`METRICS_REVIEW = CLEAN`).

**Anonymat** : le seul résultat revendiqué est
`TRANSACTION_CORRELATION_RISK = REDUCED`. `IP_PRIVACY_CURRENT = NONE` et
`ANONYMITY_CURRENT = NONE` sont **inchangés** ; un observateur global qui voit
les deux extrémités reste en mesure d'apparier les flux (voir §12).

---

## 11. Tests

Module : **`p2p::phase2_privacy_propagation_tests`** (`p2p.rs:9773`),
**18 exécutés + 1 ignoré (bench)**, tous verts.

| # | Test | Mécanisme vérifié |
|---|---|---|
| 1 | `test_relay_delay_bounds_and_spread` | JITTER — bornes, deux extrémites atteintes, `MIN > 0` |
| 2 | `test_relay_delay_depends_only_on_the_rng` | JITTER — fonction pure du RNG, pas de décalage fixe |
| 3 | `test_fanout_is_bounded` | BOUNDED FANOUT — ≤ 4, sans doublon, non vide |
| 4 | `test_upstream_peer_is_excluded_without_shrinking_the_wave` | exclusion source + taille préservée |
| 5 | `test_fanout_spans_network_groups` | NETWORK DIVERSITY — 4 groupes sur 4 cibles |
| 6 | `test_topology_cannot_shrink_the_fanout` | assouplissement du quota (2 groupes → 4 peers) |
| 7 | `test_fanout_selection_varies_by_seed` | sélection aléatoire, pas l'ordre `HashMap` |
| 8 | `test_no_privileged_relay_address` | **BOOTNODE INDEPENDENCE** — aucun adresse exclue ni dominante |
| 9 | `test_receive_stage_schedules_no_relay` | réception = file d'attente, `scheduled == false` |
| 10 | `test_a_payload_schedules_exactly_one_wave` | DEDUPLICATION de planification |
| 11 | `test_upstream_peer_is_first_observation` | première observation gagnante |
| 12 | `test_local_payload_still_propagates` | origine locale `source = None` toujours relaie |
| 13 | `test_each_peer_receives_at_most_one_copy` | **DUPLICATION** : ≤ 1 copie/peer, 2ᵉ broadcast = 0 |
| 14 | `test_upstream_peer_never_receives_the_relay` | E2E : source à 0 message, vague complète (4) |
| 15 | `test_inflight_relays_drain_to_zero` | pas de file illimitée |
| 16 | `test_relay_is_reachable_only_after_the_pure_gate` | VALIDATION_BEFORE_RELAY (lecture de source) |
| 17 | `test_invalid_transaction_is_never_scheduled_for_relay` | payload invalide jamais schedule |
| 18 | `test_multihop_convergence_stays_within_the_existing_bounds` | **MULTIHOP CONVERGENCE** |
| — | `bench_transaction_propagation` (`#[ignore]`) | les 3 métriques de §9.1 |

**Régression** : les huit suites de portée existante restent vertes —
`p2p::` **149/149** (131 avant + 18 nouveaux), `phase2_` **92/92**
(74 avant + 18), `bootstrap_phase1` **19/19**.

**Note de mesure** : `rpc::tests::test_m1..m5` (drains de 1 100 à 5 000
transactions) et `test_orphan_*` / `test_faucet_*` sont très lents en
debug. **Vérifié par comparaison A/B** : `test_m1_lifecycle_under_capacity`
dépasse 25 minutes **sur le `HEAD` pré-2E-D aussi** — la lenteur est
antérieure à cette étape (backoff de verrou du drainer, `rpc.rs:1247`), et
n'a pas été introduite ici. Les suites `rpc::` rapides
(mempool, get, per_ip, consensus) sont vertes.

---

## 12. Limites — ce que 2E-D **ne** résout pas

1. **Observateur global.** Lier `receive_t` et `relay_t` sur les deux
   extrémités reste possible si l'on voit les deux. Le jitter élève le coût
   de l'observation, il ne la supprime pas.
2. **Premier nœud observé.** Un adversaire connecté à un nœud qui observe
   le flux entrant et sortant sur *ses propres* liens voit toujours le
   nœud en amont : c'est le risque de « first-seen » identifié au §4.3 du
   modèle de menaces. 2E-D ne le couvre pas — cela demande **D.3**
   (annonce par inventaire) et/ou **D.4** (Dandelion complet), hors périmètre.
3. **Divergence de fee/mempool.** Un nœud dont le gate de fee ou la
   mémoire tampon rejette un payload ne le relaie pas ; la convergence est
   déléguée à l'`Inventory` sync de 10 s. Compensé, pas supprimé (§2.9).
4. **Dilution bornée.** Le fan-out est 4 sur une table de 128 : la
   transaction est vue par un sous-ensemble par vague. C'est volontaire
   (couverture réelle > gain théorique) et c'est le backstop qui garantit
   l'atteinte de tous.
5. **Pas de protection de couche adresse.** L'adresse IP reste visible par
   les pairs : `IP_PRIVACY_CURRENT = NONE`. L'étape ne touche ni au
   transport (2E-B), ni à Tor/I2P, ni à la découverte de pairs.

---

## 13. Livraison

| | |
|---|---|
| **Fichiers** | `src/p2p.rs`, `docs/AETHER_PHASE2_PRIVACY_PROPAGATION.md`, `docs/AETHER_NETWORK_PRIVACY_ROADMAP.md` |
| **PROTOCOL_CHANGE** | `NONE` — `P2P_PROTOCOL_VERSION = 4` inchangé |
| **`TRANSACTION_CORRELATION_RISK`** | `HIGH` → **`REDUCED`** |
| **`IP_PRIVACY_CURRENT`** | `NONE` (inchangé) |
| **`ANONYMITY_CURRENT`** | `NONE` (inchangé) |
| **V1.4.0** | `IMMUTABLE = PASS` (release gelée, aucun commit hors `dev/phase2-decentralized-network`) |
| **DÉPLOIEMENT** | `NONE` |
| **Commit** | `phase2: harden transaction propagation privacy` |

### Mesures de gates (à actualiser au moment du commit)

| Gate | Résultat |
|---|---|
| `cargo check --lib` | **9 warnings / 0 erreur** (9 warnings préexistants, 0 nouveau) |
| `cargo test --lib p2p::` | **149 passed / 0 failed** |
| `cargo test --lib phase2_` | **92 passed / 0 failed** |
| `cargo test --lib bootstrap_phase1` | **19 passed / 0 failed** |
| `cargo test --lib phase2_privacy_propagation_tests` | **18 passed / 0 failed / 1 ignored** |
| bench `--release --ignored` | **PASS** (3 métriques, §9.1) |
| `git diff --check` | à vérifier à l'ajout |
| dirty files préexistants | 9, **non modifiés / non stagés** |
