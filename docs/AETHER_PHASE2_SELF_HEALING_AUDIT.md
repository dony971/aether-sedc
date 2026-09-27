# AETHER — PHASE 2D : SELF-HEALING NETWORK — AUDIT AVANT CODE

| | |
|---|---|
| Branche | `dev/phase2-decentralized-network` |
| HEAD audité | `161d43e` — `phase2: harden eclipse resistance` |
| Base | Phase 2A (bootnode), 2B (AddressManager), 2C (eclipse resistance) |
| Release gelée | `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316` |
| Objet | Reconstruction automatique du voisinage P2P après perte partielle ou massive |
| Statut | **Écrit avant toute modification de code** |

Toutes les références de ligne ci-dessous sont valables à `161d43e`. Ce document
décrit l'état **tel qu'il est**, pas tel que la Phase 2D le fera.

---

## A. État actuel

### A.1 Où les connexions sont créées

Un seul point d'entrée pour l'initiative sortante :

```
connect_to_peer(addr)              :3192   // dédup via `dialing` (in-flight set)
  └─ connect_to_peer_inner(addr)   :3211
```

`connect_to_peer` pose l'adresse dans `dialing` (write) ; si elle y était déjà,
il retourne immédiatement — c'est ce qui empêche que l'initial sweep, le
heartbeat, la boucle de redial et PEX n'ouvrent deux sessions pour la même
adresse. `dialing` est libéré en sortie de `connect_to_peer` (`:3201`).

`connect_to_peer_inner` applique, **dans cet ordre** :

| # | Garde | Ligne | Effet en cas d'échec |
|---|---|---|---|
| 1 | `outbound_dial_blocked` (table de ban) | `:3214` | retour silencieux + `warn!` |
| 2 | `decay_score(addr)` | `:3223` | **toujours exécuté** (soigne `PeerScore` vers `PEER_SCORE_INITIAL`) |
| 3 | `outbound_admitted(total)` = `total < MAX_PEERS` | `:3230` | retour + `warn!` |
| 4 | quota `/24` (`MAX_PEERS_PER_SUBNET`) | `:3238` | retour + `warn!` |
| 5 | `timeout(CONNECT_TIMEOUT=5s, TcpStream::connect)` | `:3250` | `record_dial_failure` |

Répertoire des appelants sortants :

| Appelant | Ligne | Cadence | Portée |
|---|---|---|---|
| consumer PEX / discovery | `:1616` | à chaque hint PEX | **immédiat, non borné par round** |
| `initial_dial_sweep` | `:1687` | une fois, au démarrage | seeds d'abord |
| `initial_dial_sweep` | `:1695` | une fois, au démarrage | `outbound_candidates(32)` |
| `start_heartbeat` | `:1952` | 10 s | **uniquement si `peer_count == 0`** |
| `start_reconnection_task` | `:2084` | 5 s | **inconditionnel**, ≤ 32 dials |
| `discover_from_dns` | `:2146` | à la résolution | toutes les adresses résolues |
| `start_dns_discovery` | `:2182` | 120 s | toutes les adresses résolues, en `spawn` concurrent |

Côté entrant, `accept_loop` (`:2260`) appelle `handle_peer` directement : aucune
`connect_to_peer`, donc aucune des gardes sortantes.

### A.2 Où les connexions sont supprimées

Il n'existe que **deux** suppressions en production, toutes deux dans
`handle_peer` :

1. `:2526` — échec du handshake : `peers_lock.remove(&addr)` puis
   `addresses.touch(addr)` **pour que l'adresse reste re-dialectable**.
2. `:3163-3170` — fin de session (lecture en erreur, frame timeout, rate limit,
   nonce régressé) : `peers_lock.remove(&addr)` puis `mgr.touch(addr, ...)`.

À aucun moment l'adresse n'est retirée du `AddressManager` lors d'une
déconnexion : la Phase 1 TTL (`refresh_and_expire`, `:1282`) est seule à
expirer une adresse après `PEER_TTL`. **Conséquence pour 2D : une perte de
peers ne laisse aucune trace explicite** — elle n'est observable que comme une
diminution de `peers.len()`.

Il n'existe **aucune déconnexion forcée** en production. Les seules suppressions
restantes (`:3896`, `:5821`) sont des helpers de test.

### A.3 Comment le nombre de peers actifs est connu

- `pub async fn peer_count(&self) -> usize` = `peers.read().await.len()` (`:3372`).
- Lecture directe en ligne dans le heartbeat (`:1939-1942`).
- La direction est tracée séparément par `outbound_sessions: HashSet<SocketAddr>`
  (insert `:3262`, retrait `:3317`), alimentant `outbound_admitted`/`inbound_admitted`.

Il n'existe **aucun compteur lissé, aucun historique, aucune moyenne** : seul un
instantané de la table de sessions est disponible. Un graphe « peer_count »
n'existe pas.

### A.4 Comment les erreurs de dial sont enregistrées

Deux branches dans `connect_to_peer_inner` :

- `Ok(Err(e))` (`:3320`) — refus/erreur OS → `warn!` + `record_dial_failure`.
- `Err(_)` (`:3324`) — `CONNECT_TIMEOUT` écoulé → `warn!` + `record_dial_failure`.

```rust
async fn record_dial_failure(&self, addr: SocketAddr) {   // :3335
    self.addresses.write().await.record_failure(addr);
}
```

`AddressManager::record_failure` (`:1137`) → `AddressEntry::record_failure`
(`:1033`) : `attempts += 1`, `failures += 1`,
**`quality = max(quality - 5, 0)`** (plancher à 0), **sans horodatage**.

Point important : le signal « ce dial a échoué » n'est porté que par la
**qualité de l'adresse**. Il n'y a pas d'horodatage, pas de notion d'échec
*consécutif* (le champ `failures` d'`AddressEntry` est **cumulatif**, pas une
rafale), et pas de distinguo entre « injoignable » et « table pleine » (ce
dernier retourne avant le `timeout` et **n'atteint jamais** `record_dial_failure`).

### A.5 Comment `record_success()` / `record_failure()` fonctionnent

| Fonction | Définition | Appelé depuis | Effet |
|---|---|---|---|
| `AddressEntry::record_success(now)` | `:1027` | `handle_peer:2540` (handshake OK) | `last_success = now`, `attempts += 1`, `quality = min(q+10, PEER_QUALITY_MAX=200)` |
| `AddressEntry::record_failure()` | `:1033` | `record_dial_failure:3336` | `attempts += 1`, `failures += 1`, `quality = max(q-5, 0)` |
| `AddressManager::decay_score(addr)` | `:1201` | `connect_to_peer_inner:3223`, chemin entrant `:2314` | `PeerScore::decay()` |
| `PeerScore::decay()` | `:210` | via `decay_score` | **soigne** `score` vers `PEER_SCORE_INITIAL` (ce n'est *pas* une pénalité) |
| `PeerScore::reward(bonus)` | `:229` | **jamais en production** (warning baseline) | — |

Deux métriques **distinctes et non couplées** :

- `AddressEntry.quality` (dans `entries`) → pondère `select_outbound` (Phase 2C).
- `PeerScore.score` (dans `scores`) → sert uniquement à la **bannissement**.

`record_success` ne touche **pas** `PeerScore`, et `record_failure` non plus.
Aucun des deux n'implémente un backoff temporel : ce sont des scalaires de
classement (et un compteur cumulatif), pas des horloges. `failures` n'est
jamais remis à zéro et n'est **jamais lu** par la sélection.

### A.6 Comment `AddressManager` expose les candidats

| Accès | Ligne | Signature | Usage |
|---|---|---|---|
| `addresses()` | `:1100` | `-> Vec<SocketAddr>` | moitié « connues » de `redial_candidates` |
| `selection_tables()` | `:1429` | `-> (&entries, &scores)` | entrée de `select_outbound` |
| `anchor_addresses()` | `:1236` | `-> Vec<(SocketAddr,u64)>` | rotation d'ancres |
| `anchor_candidates(&connected)` | `:1246` | `-> Vec<(SocketAddr,u64)>` | promotion d'ancres |
| `is_banned(a)` / `banned_until(a)` | `:1180` | | garde sortante |
| `categories(&connected, now)` | `:1326` | `-> [usize;5]` | diagnostic |

Le **seul** consommateur de production de la sélection est
`P2PNetwork::outbound_candidates(limit)` (`:1991`) :

```
snapshot peers → release → addresses.read()
  → known = mgr.addresses()
  → ordered = redial_candidates(known, bootnodes, local)   // connues, puis seeds
  → seed_tail = ordered[known_len..]
  → select_outbound(ordered, seed_tail, entries, scores, connected, limit, now, rng)
```

Il n'existe **aucune vue « par priorité de récupération »**. Les ancres
n'apparaissent que comme un **bonus de poids** (`ANCHOR_SELECT_BONUS = +50`,
`:748-750`) à l'intérieur d'un tirage pondéré stochastique — elles ne sont
jamais garanties en tête de file.

### A.7 Comment les ancres sont récupérées

- `start_anchor_task` (`:1873`) : boucle, `ANCHOR_REFRESH_INTERVAL = 60 s`.
- `refresh_anchors` (`:1885`) :
  1. snapshot `peers` → release (discipline de verrous respectée) ;
  2. `anchor_addresses()` → `expire_anchors` (TTL `ANCHOR_TTL_SECS = 7 j`) ;
  3. `anchor_candidates(&sessions)` = sessions vivantes ayant **au moins un
     handshake réussi** (`last_success.is_some()`) ;
  4. `promote_anchors(alive, candidates, local)` → `apply_anchors(wanted)`.
- `MIN_ANCHORS = 3` est une **cible**, pas un plafond qui gate quoi que ce soit :
  en dessous, un simple `warn!` (`:1919`).

**Les ancres ne sont jamais consommées explicitement pour la récupération.**
Elles survivent au redémarrage via le peer store v2 (`PeerStoreEntry.anchor`),
ce qui est exactement ce dont 2D a besoin — mais rien ne les *priorise*.

### A.8 Comment PEX ajoute de nouveaux candidats

Émission — `start_pex` (`:2219`), toutes les 15 s : snapshot des expéditeurs,
release, puis `sample_for_pex(..., PEX_MAX_SEND = 64)` par destinataire.

Réception — `handle_peer`, `P2PMessage::Peers` (`:3099`) :

```
filtre : !mgr.contains(p) && p != local && !connected(p) && !is_private_or_reserved(p)
      → ingress_address(..., PeerSource::Pex)     // qualité PEX_ADMISSION_QUALITY = 50
      → set_origin(p, from)
      → peer_discovery_tx.send(p)
```

Consommateur — `:1614-1618` : **`connect_to_peer(addr)` immédiatement**, un par
hint, en série dans une task dédiée.

C'est la **seule** source qui déclenche un dial sans passer par une sélection
bornée par round. Les gardes restantes sont : `dialing`, les 5 gardes de
`connect_to_peer_inner`, et `is_private_or_reserved` à la réception.

### A.9 Comment le redial fonctionne

`start_reconnection_task` (`:2036`) — **c'est déjà une boucle de récupération,
mais sans état** :

```
boucle {
  candidates = outbound_candidates(MAX_REDIAL_PER_CYCLE = 32)   // :2049
  now = Instant::now(); dials = 0
  for target in candidates {
      if dials >= 32 { break }
      if peers.contains(target) { retry_counts.remove; next_attempt.remove; continue }
      if next_attempt[key] > now { continue }                   // backoff par candidat
      attempt = retry_counts[key] (défaut 0)
      backoff = min(2^min(attempt,6), 60)                       // :2076
      connect_to_peer(target); dials += 1
      retry_counts[key] = min(attempt+1, 6)                     // :2087
      next_attempt[key] = now + backoff
  }
  sleep(5s)                                                     // :2091
}
```

Propriétés constatées :

- **Cadence** : 5 s, **inconditionnelle** — elle tourne aussi à 128 peers.
- **Backoff par candidat**, borné à 60 s, compteur borné à 6 ; il est **réinitialisé
  quand le candidat apparaît connecté** (`:2060-2064`) — c'est le seul « succès → reset ».
- **Aucun backoff au niveau du contrôleur** : si les 32 candidats échouent, la
  boucle recommence dans 5 s, quoi qu'il arrive.
- **Aucune distinction de source** : ancres, peers récents, candidats et seeds
  sont traités par une seule sélection pondérée.
- `retry_counts` / `next_attempt` sont des `HashMap<String, _>` qui ne sont
  purgées que lorsqu'un candidat est retrouvé connecté — les clés de candidats
  définitivement abandonnés restent (voir F.3).

### A.10 Comment le bootnode est actuellement utilisé

| Site | Ligne | Comportement |
|---|---|---|
| `initial_dial_sweep` | `:1686` | seeds d'abord, **une seule fois** au démarrage |
| `outbound_candidates` | `:1998` | `seeds = config.bootnodes.clone()` → queue de `redial_candidates` |
| `discover_from_dns` | `:2123` | `dns_seeds` (fournies par config, distinctes de `bootnodes`) |
| `start_dns_discovery` | `:2160` | idem, toutes les 120 s |
| garde de réception PEX | `:3104` | note explicite : `is_private_or_reserved` **ne s'applique pas** aux bootnodes/DNS |

Ordre garanti par `redial_candidates` (`:1965`) : connues d'abord, seeds
toujours **derrière**. Puis `select_outbound` (`:677`) :

```rust
let seed_reserve = ordered.iter()
    .filter(|a| seed_tail.contains(a) && is_eligible(a, &seen))
    .take(MAX_CANDIDATES_PER_GROUP)      // = 2
    .count();                            // :724
let known_limit = limit.saturating_sub(seed_reserve);
// phase 1 : connues, jusqu'à known_limit
// phase 2 : seeds, jusqu'à limit                        // :772
```

**Conséquence exacte (C.1) :** dès qu'au moins un seed est éligible (non
connecté, non banni), le round réserve **jusqu'à `MAX_CANDIDATES_PER_GROUP = 2`
slots sur 32 pour les seeds**, indépendamment du nombre de candidats connus
disponibles. Le seed est *classé* dernier dans le round mais *garanti* d'en
faire partie.

Ce n'est **pas** une boucle agressive : le backoff par candidat de la
boucle de redial s'applique aussi aux seeds, donc un bootnode mort est retenté
au plus une fois par ~60 s, pas 2 fois par 5 s.

### A.11 Existe-t-il déjà une logique périodique de reconnexion ?

**Oui, deux, non coordonnées :**

1. `start_heartbeat` (`:1931`) — 10 s, **agit uniquement si `peer_count == 0`**
   (`:1944`). Sous ce seuil, il appelle `outbound_candidates(32)` et dialle
   **sans backoff propre** (il ne fait que déléguer à `connect_to_peer`).
2. `start_reconnection_task` (`:2036`) — 5 s, **inconditionnel**, avec backoff
   par candidat.

Plus les deux chemins à déclenchement événementiel (PEX immédiat, DNS 120 s).

**Il n'existe aucune machine à états, aucun seuil intermédiaire, aucun concept
de « dégradé ».** Le heartbeat ne connaît que `== 0` et `!= 0`. Un nœud à
2 peers est, à ses yeux, identique à un nœud à 128.

### A.12 Existe-t-il une protection contre les boucles de redial agressives ?

| Protection | Emport | Limite |
|---|---|---|
| `dialing` in-flight set | oui (`:3194`) | ne déduplique que les dials **concurrents**, pas séquentiels |
| `CONNECT_TIMEOUT = 5 s` | oui (`:3250`) | borne la durée, pas le nombre |
| `outbound_dial_blocked` (ban) | oui (`:3214`) | — |
| `outbound_admitted` = `total < 128` | oui (`:3230`) | borne le total, pas le débit |
| quota `/24` = 4 | oui (`:3238`) | borne la diversité, pas le débit |
| backoff par candidat ≤ 60 s | oui (`:2076`) | **uniquement** dans la boucle de redial |
| `MAX_REDIAL_PER_CYCLE = 32` | oui (`:2055`) | par round, pas global |
| quotas `MAX_CANDIDATES_PER_GROUP` | oui (`:712`) | par round |
| **backoff / limite au niveau contrôleur** | **non** | — |
| **limite de dials par unité de temps** | **non** | — |
| **limite sur le chemin PEX** | **non** | un dial par hint |

**Trou (A.12.1) — saturation silencieuse.** Sur un nœud à 128 peers,
`outbound_candidates(32)` rend 32 candidats non connectés ; chacun traverse
`connect_to_peer_inner` jusqu'à `outbound_admitted` (`total < 128` → `false`) et
retourne après un `warn!`. Résultat : **32 avertissements toutes les 5 s,
indéfiniment**, sur un nœud parfaitement sain. Le débit réseau reste nul
(le `connect` n'est jamais lancé) mais le journal est saturé. Ce trou est
**préexistant** et hors du périmètre de 2D (voir F.1).

---

## B. Mécanismes de récupération existants

Quatre mécanismes sont déjà en place. La Phase 2D **ne les remplace pas** :

| # | Mécanisme | Déclencheur | Borné ? | Priorise les sources ? | A un état ? |
|---|---|---|---|---|---|
| B.1 | heartbeat | 10 s, `peer_count == 0` | oui (32) | non (même sélection) | non |
| B.2 | boucle de redial | 5 s, inconditionnel | oui (32/round, backoff ≤ 60 s/candidat) | non (seeds réservés à 2 slots) | non |
| B.3 | PEX → dial immédiat | à la réception d'un hint | **non** par round | n/a | non |
| B.4 | DNS seeds | 120 s | **non** par résolution | n/a | non |

Ce qui **manque** réellement (et définit la portée de 2D) :

| Lacune | Conséquence observable |
|---|---|
| **L-1** Pas de machine à états | Impossible de savoir si le nœud est sain, dégradé ou en récupération ; aucun log d'entrée/sortie de récupération |
| **L-2** Seuil unique `== 0` | Une perte 8 → 2 n'est pas traitée différemment d'une perte 128 → 127 ; aucune accélération, aucun arrêt |
| **L-3** Pas d'hystéresis | Aucun seuil haut/bas distinct : dès qu'un seuil sera introduit, il faudra une bande pour éviter le va-et-vient 7 ↔ 8 |
| **L-4** Pas de priorité de sources | Les ancres ne sont qu'un bonus de poids ; aucun ordre garanti ancres → connus → seeds |
| **L-5** Les seeds reçoivent une quota garantie chaque round | Le bootnode n'est jamais totalement mis de côté, même avec des centaines de candidats connus (C.1) |
| **L-6** Pas de backoff de contrôleur | Si toutes les sources échouent, la boucle reprend à 5 s égales ; `Exhausted` n'existe pas |
| **L-7** Pas de limite d'échecs consécutifs | Rien n'arrête jamais la récupération « proprement » |
| **L-8** Le chemin PEX n'a pas de limite par round | Un pair peut pousser des hints qui déclenchent autant de dials qu'il envoie de messages (borné seulement par `dialing` + admission) |
| **L-9** `record_failure` n'a ni horodatage ni compteur de rafale | `failures` est cumulatif et jamais lu : impossible de distinguer « injoignable » de « rate-limited », ni de calculer un backoff à partir de l'historique |
| **L-10** Aucune vue « peer_count dans le temps »** | Un test d'intégration ne peut observer la convergence que par sondage de `peer_count()` |

---

## C. Dépendance bootnode restante

### C.1 Quota garanti par round (constaté, A.10)

`select_outbound` réserve jusqu'à `MAX_CANDIDATES_PER_GROUP = 2` slots de chaque
round pour le `seed_tail`, **dès qu'un seul seed est éligible**. Sur la boucle de
redial (5 s), un bootnode **en vie** est donc retenté en permanence alors même
que des centaines de candidats connus sont disponibles ; un bootnode **mort**
est borné par son backoff personnel à ~1 dial / 60 s.

Le classement « connues avant seeds » (Phase 2A) est respecté, mais le
**quota** n'est pas un « dernier recours » : c'est une *réserve*.

### C.2 Ce qui reste correct

- `initial_dial_sweep` ne mène que **une fois** — le démarrage est le seul
  endroit où le seed est légitimement premier, et 2D le conserve.
- Le bootnode n'apparaît **dans aucune autre logique** : ni ancre, ni PEX
  (un bootnode ne peut pas se auto-ancrer, `anchor_candidates` exige un
  handshake réussi sur une session vivante), ni TTL.
- Sans `bootnodes`, `redial_candidates` retourne simplement la liste connue —
  le nœud fonctionne. **Il n'y a pas de dépendance runtime au bootnode**
  (c'est l'objet de la Phase 2A, `3750940`).

### C.3 Le cas vide (le seul vrai risque)

`outbound_candidates` = connues **puis** seeds. Si les deux sont vides :

| État | Source restante |
|---|---|
| store vide + `bootnodes` vide + `dns_seeds` vides | **aucune** — le nœud reste à 0 peer indéfiniment |
| store vide + `bootnodes` vides + `dns_seeds` remplies | DNS toutes les 120 s (B.4) |
| store rempli + bootnode mort | connues + ancres + PEX — **cas nominal visé par 2D** |

C'est précisément la propriété à démontrer :

> un nœud ayant **déjà participé** au réseau (donc avec store + ancres remplis)
> peut perdre son bootnode **et** l'essentiel de ses connexions sans perdre sa
> capacité à reconstruire son voisinage.

**2D n'ajoute aucune nouvelle source.** Il ajoute l'**ordonnancement**,
l'**état** et les **bornes** autour des sources qui existent déjà.

---

## D. Scénarios de perte

| ID | Scénario | État du code aujourd'hui | Atteint aujourd'hui ? |
|---|---|---|---|
| **S1** | perte d'un peer (8 → 7) | la boucle de redial (5 s) redessine 32 candidats dont 7 non connectés ; backoff par candidat | **partiellement** — aucune garantie de remplacement ordonné, pas de log, risque de diales inutiles |
| **S2** | perte de la majorité (8 → 2) | idem ; le heartbeat (`== 0`) ne se déclenche pas | **partiellement** — aucun seuil intermédiaire, aucune accélération, aucun état |
| **S3** | tous les peers (→ 0) | heartbeat **et** boucle de redial tous deux actifs | **oui**, mais sans ordre de sources garanti et sans backoff de contrôleur |
| **S4** | bootnode down | seed classé dernier, backoff ≤ 60 s, quota 2 slots/round | **oui** — mais le quota C.1 le re-tente indéfiniment ; pas de notion de « dernier recours » |
| **S5** | peers intermittents | backoff **par candidat** (≤ 60 s, attempt ≤ 6) ; pas de backoff de contrôleur | **partiellement** — le va-et-vient 7 ↔ 8 n'est pas amorti (L-3) |
| **S6** | échecs de dial multiples | `record_failure` (quality −5), backoff par candidat, quotas groupe | **partiellement** — aucune borne d'échecs **consécutifs** (L-7), aucune transition `Exhausted` |
| **S7** | restart (0 connexion, store + ancres présents) | `load_known_peers` (v2) → `initial_dial_sweep` → seeds puis `outbound_candidates(32)` | **oui** — c'est le cas le mieux couvert aujourd'hui |
| **S8** | attack + self-heal (perte + candidats de mauvaise qualité + bootnode down) | `select_outbound` pondère la qualité, quota par groupe, ban ; ancres bonus +50 | **partiellement** — le tirage pondéré peut servir des candidats médiocres tant qu'il en reste ; aucun état `Degraded`/`Exhausted` |

**Ce que 2D doit changer, scénario par scénario :**

- **S1, S2** → seuil `RECOVERY_THRESHOLD`, hystéresis, log d'entrée/sortie.
- **S3, S7** → échelle de sources explicite ancres → connues → seeds.
- **S4** → les seeds ne sont proposées **que** si les sources primaires sont
  épuisées (supprime C.1 pour la tâche de récupération ; la boucle de redial
  existante n'est pas modifiée).
- **S5, S6** → backoff de contrôleur borné + `MAX_CONSECUTIVE_FAILURES` → `Exhausted`.
- **S8** → la récupération passe **obligatoirement** par
  `AddressManager + select_outbound + NetworkGroup + protected slots`
  (aucune seconde logique de sélection) et dégrade proprement en `Exhausted`
  plutôt que de tourner.

---

## E. Stratégie proposée

### E.1 Principe

**Aucune réécriture.** La Phase 2D ajoute un **contrôleur fin** au-dessus de la
sélection qui existe déjà :

```
NORMAL ──perte──> [observation peer_count]
                     │ count < RECOVERY_THRESHOLD (4)
                     ▼
              SELF-HEAL ──> échelle de sources
                     │         1. ancres (ankhor_addresses, dialables)
                     │         2. outbound_candidates(...) SANS les seeds
                     │         3. seeds/bootnodes (dernier recours)
                     ▼
              select_outbound + NetworkGroup + protected slots   (2C, inchangé)
                     │
                     ▼
              nouvelles connexions ──> diversification
                     │ count >= COMFORT_PEERS (8)
                     ▼
              NORMAL  (backoff remis à zéro)
```

### E.2 Composant : `PeerRecoveryController`

Petit, déterministe, **sans I/O** — les transitions sont des fonctions pures et
donc testables sans réseau.

```rust
enum RecoveryState {
    /// count >= COMFORT_PEERS : rien à faire.
    Healthy,
    /// Sous le seuil de confort, des sources sont dialables.
    Recovering,
    /// Sous RECOVERY_THRESHOLD et un backoff est en cours : on est freiné.
    Degraded,
    /// count < RECOVERY_THRESHOLD et plus aucune source n'est dialable.
    Exhausted,
}

struct PeerRecoveryController {
    state: RecoveryState,
    last_attempt: Option<Instant>,
    backoff_level: u32,             // 0 ..= RECOVERY_MAX_LEVEL
    consecutive_failures: u32,      // 0 ..= RECOVERY_MAX_CONSECUTIVE_FAILURES
}
```

Transitions (fonction pure, testée telle quelle) :

```rust
fn next_state(count, sources_left, backoff_pending, now) -> RecoveryState
```

| Entrée | Sortie |
|---|---|
| `count >= COMFORT_PEERS` | `Healthy` (reset `backoff_level`, `consecutive_failures`) |
| `count < RECOVERY_THRESHOLD` et `!sources_left` | `Exhausted` |
| `count < RECOVERY_THRESHOLD` et `backoff_pending` | `Degraded` |
| sinon | `Recovering` |

**Toutes les sorties sont bornées** : `backoff_level ≤ RECOVERY_MAX_LEVEL`,
`consecutive_failures ≤ RECOVERY_MAX_CONSECUTIVE_FAILURES`, et un round ne
dialle jamais plus de `MAX_DIALS_PER_ROUND`.

Le contrôleur **ne détient aucun verrou de session** : il est observé via
`Arc<RwLock<PeerRecoveryController>>` et mis à jour par la task de
récupération seule.

### E.3 Échelle de sources (priorité)

Ordre imposé, **sans nouvelle logique de sélection** :

| Tier | Source | Fonction existante | Condition d'usage |
|---|---|---|---|
| 1 | ancres dialables | `AddressManager::anchor_addresses()` (`:1236`) | filtrées : non connectées, non bannis, ≠ local |
| 2 | candidats connus (PEX inclus) | `outbound_candidates(n)` **sans les seeds** | toujours si tier 1 insuffisant |
| 3 | seeds / bootnodes | `config.bootnodes` | **uniquement** si tiers 1 + 2 n'ont pas rempli le round |

Le filtrage des seeds du tier 2 est fait en aval de `outbound_candidates` en
soustrayant `config.bootnodes` — **`select_outbound` et
`outbound_candidates` ne sont pas modifiés**, donc la Phase 2C reste intacte et
les tests 2C ne changent pas.

Chaque tier est borné à `MAX_DIALS_PER_ROUND` au total, pas par tier.

### E.4 Interaction avec `select_outbound` / 2C

La récupération **ne sélectionne rien elle-même** : elle construit une
`Vec<SocketAddr>` ordonnée par tier, puis appelle `connect_to_peer` (donc
`connect_to_peer_inner`), qui applique déjà :

- ban table, `outbound_admitted`, quota `/24` (`:3214`, `:3230`, `:3238`) ;
- `dialing` pour la dédup (`:3194`) ;
- `decay_score` + `record_dial_failure`.

Les adresses des tiers 1 et 2 passent **aussi** par `outbound_candidates`
(tier 2) où `select_outbound` applique quotas de groupe et pondération par
qualité. Le tier 1 (ancres) contourne `select_outbound` mais reste borné par
les gardes 1/3/4/5 de `connect_to_peer_inner` et par `MAX_DIALS_PER_ROUND`.

> **Choix assumé :** les ancres ne passent pas par `select_outbound` car c'est
> le seul moyen de *garantir* qu'elles sont essayées en premier. Les gardes de
> `connect_to_peer_inner` conservent la diversité `/24` et le plafond `MAX_PEERS`.
> `test_self_healing_preserves_diversity` vérifie que le quota `/24` tient
> pendant un round de récupération.

### E.5 Tâche et cadence

```rust
async fn start_recovery_task(&self)   // branchée dans start(), comme les autres
```

- Cadence : `RECOVERY_INTERVAL = 5 s` (même cadence que la boucle de redial
  existante `:2091` — une seule horloge familiale, pas une de plus à régler).
- **Silence total en `Healthy`** : aucune écriture de log, aucun dial. C'est
  la garantie « pas de burst » de S1.
- En `Recovering` : au plus `MAX_DIALS_PER_ROUND` dials par round, puis
  `backoff_level += 1` en cas d'échec complet, `= 0` dès qu'un dial réussit.
- En `Degraded` : le round n'est lancé que lorsque `backoff` est expiré.
- En `Exhausted` : plus aucun dial, `warn!` **une seule fois** à la transition,
  puis ré-évaluation silencieuse à chaque round (les sources peuvent revenir :
  un peer peut réapparaître, un seed peut revenir).

La boucle de redial existante (B.2) **n'est pas modifiée**. Les deux coexistent :
la tâche de récupération est inactive en régime sain et ne fait qu'ajouter de
la priorité quand le nœud est dégradé. La dédup `dialing` empêche tout double
dial.

### E.6 Seuils — tous dérivés du code existant

Aucune valeur n'est choisie pour faire passer un test.

| Constante | Valeur | Dérivation |
|---|---|---|
| `TARGET_PEERS` | **8** | `PROTECTED_OUTBOUND_SLOTS` (`:40`). Sa doc dit déjà : *« 8 = 2 × MAX_PEERS_PER_SUBNET : la réserve couvre deux groupes réseau complets, donc au moins deux chemins indépendants »*. C'est l'invariant de diversité que 2C garantit déjà. |
| `COMFORT_PEERS` | **8** | `TARGET_PEERS`. Seuil de **sortie** de la bande d'hystéresis : on ne déclare la récupération terminée qu'au niveau que 2C réserve. |
| `RECOVERY_THRESHOLD` | **4** | `MAX_PEERS_PER_SUBNET` (`:37`). Sous une adresse plein groupe, le nœud ne détient même plus le quota qu'un seul groupe autorise — c'est la perte de diversité avérée. |
| `MIN_PEERS` | **3** | `MIN_ANCHORS` (`:66`), dont la doc dit *« Several, never one »*. Marqueur de « encore plusieurs chemins ». N'est **pas** un seuil de déclenchement. |
| `MAX_DIALS_PER_ROUND` | **8** | `PROTECTED_OUTBOUND_SLOTS`. Un round de récupération ne dépasse jamais le nombre de slots sortants que 2C réserve ; et `≤ MAX_REDIAL_PER_CYCLE = 32` par construction. |
| `RECOVERY_INTERVAL` | **5 s** | cadence existante de la boucle de redial (`:2091`). |
| `RECOVERY_BACKOFF_BASE` | **5 s** | base du backoff existant `2^min(attempt,6)` (`:2076`) et de l'intervalle (`:2091`). |
| `RECOVERY_BACKOFF_MAX` | **60 s** | plafond existant du backoff par candidat (`:2076`, `min(..., 60)`). |
| `RECOVERY_MAX_LEVEL` | **6** | `min(attempt + 1, 6)` existant (`:2087`) — `2^6 = 64 → 60 s`, le plafond est atteint exactement ici. |
| `RECOVERY_MAX_CONSECUTIVE_FAILURES` | **6** | même compteur borné (`:2087`). Au-delà : `Exhausted`. |

Bande d'hystéresis résultante, **calculée** :

```
enter : count < RECOVERY_THRESHOLD = 4
exit  : count >= COMFORT_PEERS     = 8
bande : [4, 8)  →  4 peers de large
```

à 7 peers on **ne déclenche rien** (Healthy) ; si on était déjà en
`Recovering`, on y reste jusqu'à 8. **Pas de va-et-vient 7 ↔ 8.**
Les constantes portent les justifications ci-dessus en doc-comment — c'est le
même style que la constante 2C.

### E.7 Backoff borné

```
succès                     → backoff_level = 0, consecutive_failures = 0
1 échec   →  5 s  (2^0 * 5)
2 échecs  → 10 s  (2^1 * 5)
3 échecs  → 20 s  (2^2 * 5)
4+ échecs → 40 s, puis 60 s plafonné  (2^3, 2^4… min(..., 60))
6 échecs consécutifs      →  Extinguished/Exhausted, arrêt des dials
```

Formule : `min(RECOVERY_BACKOFF_BASE << min(level, RECOVERY_MAX_LEVEL), RECOVERY_BACKOFF_MAX)`,
c'est **exactement** la formule existante `:2076`, réutilisée pour ne pas
introduire une deuxième politique de backoff.

Aucun `sleep()` n'est placé dans une boucle de décision : la task dort une fois
par round (`RECOVERY_INTERVAL`), et l'attente entre rounds est portée par
`last_attempt` + `backoff_level` (testable sans horloge réelle).

### E.8 Rate limit — synthèse

| Borne | Valeur | Où |
|---|---|---|
| dials par round | `MAX_DIALS_PER_ROUND = 8` | tier ladder |
| rounds par seconde | `1 / RECOVERY_INTERVAL = 0,2` | task |
| échecs consécutifs avant arrêt | `RECOVERY_MAX_CONSECUTIVE_FAILURES = 6` | contrôleur |
| tentatives par round et par endpoint | 1 (déjà garanti par `dialing` + `seen`) | `connect_to_peer` |
| backoff maximal | 60 s | contrôleur |
| **boucle infinie** | **impossible** : `Exhausted` n'émet aucun dial | transition |

### E.9 Observabilité

Volume minimal, aucun spam :

| Événement | Niveau | Quota |
|---|---|---|
| entrée en récupération (transition → `Recovering`/`Degraded`) | `info!` | **une fois par transition** |
| cause (compte, seuil, sources disponibles) | dans le même `info!` | idem |
| source utilisée (tier + nombre de candidats) | `debug!` | par round |
| tentatives / succès d'un round | `debug!` | par round |
| `Exhausted` | `warn!` | **une fois par transition**, pas par round |
| sortie de récupération (→ `Healthy`) | `info!` | **une fois par transition** |
| régime sain | **aucun log** | — |

---

## F. Risques

| # | Risque | Sévérité | Atténuation |
|---|---|---|---|
| **F.1** | La boucle de redial existante (5 s, inconditionnelle) tourne **déjà** : ajouter une task de récupération peut **doubler** la pression de dialement | moyenne | `dialing` déduplique les dials concurrents ; `outbound_admitted` + quota `/24` bornent le total ; la tâche 2D est **inactive** en `Healthy`, donc en régime sain il n'y a aucun dial supplémentaire. **Vérifié par `test_self_healing_respects_outbound_limits`.** |
| **F.2** | Le tier 1 (ancres) **contourne** `select_outbound` → pourrait briser la garantie de diversité 2C | **haute** | Les gardes `/24` (`:3238`) et `MAX_PEERS` (`:3230`) restent dans `connect_to_peer_inner`, exécutées **avant** tout `connect`. **Vérifié par `test_self_healing_preserves_diversity`.** |
| **F.3** | `retry_counts` / `next_attempt` (`:2041`) croissent sans borne (purge seulement au succès) | faible | **Hors périmètre 2D** : non modifié. Documenté comme limitation (§I.3). Un `retain` serait un changement dans la boucle de redial existante, explicitement à ne pas toucher. |
| **F.4** | Surchauffe des verrous : la task tient-elle `peers` et `addresses` ensemble ? | **haute** | Non — la tâche suit la discipline établie : snapshot `peers` → release → `addresses.read()`. Jamais imbriquées. Vérifié à la lecture du code et par les tests. |
| **F.5** | Log spam en `Healthy` | moyenne | Aucun log n'est émis en `Healthy`. Seules les **transitions** produisent un `info!`. |
| **F.6** | Dépendance à `Instant` → tests non déterministes | moyenne | Toutes les transitions passent une horloge injectée (`now: Instant`) ; les tests contrôlent `now` explicitement (même pattern que `refresh_and_expire`). |
| **F.7** | Un adversaire provoque un va-et-vient `Recovering` ↔ `Healthy` pour forcer des dials | moyenne | Hystéresis de 4 peers (E.6) + `MAX_DIALS_PER_ROUND` + backoff borné. |
| **F.8** | Changer `outbound_candidates` casserait l'helper `round(...)` des tests 2C | **haute** | **`outbound_candidates` et `select_outbound` ne sont pas modifiés.** Aucun test 2C à réécrire. |
| **F.9** | Le trap A.12.1 (32 `warn!`/5 s sur nœud saturé) pourrait être confondu avec un spam 2D | faible | 2D n'émets **rien** en `Healthy`. Si ce spam est observé, il est **préexistant** (A.12.1) et hors périmètre. |

### F.10 Hors périmètre — confirmé

Aucun des éléments suivants n'est modifié :

`handshake` · `build_nonce` · `send_direction` · `nonce_collision_possible` ·
`last_recv_counter` · PoW · difficulté · consensus · ledger · `handle_peer`
(signature **et** corps) · `accept_loop` · `select_outbound` ·
`outbound_candidates` · `redial_candidates` · `inbound_admitted` ·
`outbound_admitted` · `network_group` · `MAX_PEERS` · `PROTECTED_OUTBOUND_SLOTS` ·
aucun test existant · aucune constante de production existante.
Pas de DHT, pas de Tor/I2P, pas de 2E privacy, pas de nouvelle source de peers.

---

## G. Tests

Module : `phase2_self_healing_tests` (avant `bootstrap_phase1_tests`,
même emplacement que `phase2_eclipse_tests`).

Helpers réutilisés : `addr`, `net_with`, `net_at`, `net_at_config` (de
`phase2_decentralized_tests` — redéfinis localement dans le module, comme 2C),
plus `PeerRecoveryController` en pur.

### G.1 Tests unitaires du contrôleur (transitions pures)

| Test | Vérifie | Critère |
|---|---|---|
| `test_self_healing_single_peer_loss` | S1 : 8 → 7 ne **déclenche** rien (≥ `RECOVERY_THRESHOLD`), pas de dial, pas de log | SINGLE_PEER_LOSS |
| `test_self_healing_majority_peer_loss` | S2 : 8 → 2 → état `Recovering`, round borné à `MAX_DIALS_PER_ROUND` | MAJORITY_LOSS |
| `test_self_healing_zero_peers` | S3 : 0 → ancres d'abord, puis connues, puis seeds | ZERO_PEERS |
| `test_self_healing_backoff` | backoff 5 → 10 → 20 → 40 → 60 borné, monotone | BACKOFF |
| `test_self_healing_backoff_reset` | un succès remet `backoff_level` et `consecutive_failures` à 0 | BACKOFF |
| `test_self_healing_hysteresis` | 7 (Healthy, rien) ; entrée < 4 ; sortie ≥ 8 ; pas de 7 ↔ 8 | *(additif)* |

### G.2 Tests d'échelle de sources

| Test | Vérifie | Critère |
|---|---|---|
| `test_self_healing_uses_anchors` | tier 1 vide → ancres en tête du round | ANCHOR_RECOVERY |
| `test_self_healing_uses_address_manager` | tier 1 insuffisant → `outbound_candidates` fournit le reste | *(additif)* |
| `test_self_healing_uses_pex` | adresses apprises par PEX (qualité 50) sont dialables en récupération | PEX_RECOVERY |
| `test_self_healing_seed_last_resort` | avec des candidats connus, **aucun** seed dans le round ; sans aucun candidat → seeds présentes | SEED_LAST_RESORT |
| `test_self_healing_bootnode_down` | S4 : bootnode mort, store + ancres → récupération sans lui, aucun blocage | BOOTNODE_DOWN |

### G.3 Tests de bornes et de diversité

| Test | Vérifie | Critère |
|---|---|---|
| `test_self_healing_respects_outbound_limits` | round ≤ `MAX_DIALS_PER_ROUND` ; n'ouvre jamais au-delà de `MAX_PEERS` | — |
| `test_self_healing_preserves_diversity` | pendant un round de récupération, aucun groupe `/24` ne dépasse `MAX_PEERS_PER_SUBNET` | DIVERSITY |
| `test_self_healing_dial_failures` | S6 : `record_failure` appelé, pénalisation visible, aucun nombre infini de dials | DIAL_FAILURES |

### G.4 Tests de cycle de vie

| Test | Vérifie | Critère |
|---|---|---|
| `test_self_healing_restart` | S7 : store v2 + ancres, 0 connexion → reconstruction | RESTART_RECOVERY |
| `test_self_healing_attack_scenario` | S8 : candidats de mauvaise qualité + perte + bootnode mort → `Degraded`/`Exhausted`, **pas** « tous les premiers candidats » | ATTACK_SCENARIO |

### G.5 Tests d'intégration (deux, exigés)

**I-1 — perte massive avec bootnode coupé, convergence :**

```
A : peer store rempli (hétérogène), ancres, bootnode configuré
  → plusieurs peers établis
  → perte de la majorité (retrait du half du store)
  → bootnode rendu injoignable
  → détection (count < RECOVERY_THRESHOLD)
  → round de récupération (tier 1 → tier 2, seeds écartées)
  → nouveaux peers
  → count >= COMFORT_PEERS → Healthy
  → diversité /24 vérifiée à l'arrivée
```

**I-2 — restart puis reconstruction :**

```
B : peer store v2 persisté + ancres, aucune session
  → initial_dial_sweep (seeds puis store)
  → récupération depuis store/ancres
  → count >= COMFORT_PEERS → Healthy
```

Ces deux scénarios sondent `peer_count()` **réellement** (pas une fonction
isolée) et vérifient l'état du contrôleur en sortie.

### G.6 Régie

- **DEBUG** pour tous les tests 2D (ils sont légers : aucune boucle réseau
  réelle, aucun `sleep` long — l'horloge est injectée).
- `cargo test --lib p2p::` / `phase2_decentralized_tests` /
  `phase2_eclipse_tests` / `bootstrap_phase1` doivent rester **intacts**.
- **Ne pas** lancer les 438 tests.
- FAILURE POLICY : un échec → STOP, pas de commit, diagnostic écrit.

---

## H. Observabilité — journal attendu

Exemple de trace en régime nominal (S2) :

```
INFO  self-heal: peer_count 2 < threshold 4 -> entering recovery (sources: 3 anchors, 41 known, 2 seeds)
DEBUG self-heal: round 1: tier=anchors 3 dialable, tier=known 5 of 41, tier=seeds withheld (0 used)
DEBUG self-heal: round 1: 8 dials, 0 sessions opened, backoff -> 5s
DEBUG self-heal: round 2: tier=anchors 1 dialable (2 connected), tier=known 7 of 41
INFO  self-heal: peer_count 8 >= comfort 8 -> recovery complete, backoff reset
```

En régime sain : **aucune ligne.**

---

## I. Limites connues (ne seront pas résolues par 2D)

1. **Aucune source nouvelle.** 2D ordonne et borne les sources existantes ;
   un nœud dont le store est vide, sans DNS et sans bootnode n'a toujours
   aucune chose à reconstruire (C.3).
2. **`record_failure` reste sans horloge** (L-9) : `failures` est cumulatif,
   jamais remis à zéro et jamais lu. La récupération s'appuie sur son propre
   backoff de contrôleur, pas sur l'historique d'`AddressEntry`.
3. **`retry_counts` / `next_attempt` ne sont pas purgés** (F.3) : leurs clés
   s'accumulent avec les candidats abandonnés. Hors périmètre.
4. **Le chemin PEX n'a pas de limite par round** (L-8). 2D ne le touche pas ;
   il reste borné par `dialing` + les 5 gardes de `connect_to_peer_inner`.
5. **Le trap A.12.1 (32 `warn!`/5 s sur nœud saturé) est préexistant.**
6. **`ECLIPSE_PROOF` n'est jamais déclaré `YES`**, comme en 2C. Le statut de
   cette phase est `SELF_HEALING = PASS` sur les scénarios testés.

---

## J. Critères de sortie visés

```
SELF_HEALING_AUDIT  = PASS          (ce document)
SELF_HEALING_TESTS  = X/X PASS
P2P_REGRESSION      = 98/98 PASS
PHASE2_REGRESSION   = 26/26 PASS
ECLIPSE_REGRESSION  = 15/15 PASS
BOOTSTRAP_PHASE1    = 19/19 PASS
SINGLE_PEER_LOSS    = PASS    MAJORITY_LOSS    = PASS    ZERO_PEERS       = PASS
BOOTNODE_DOWN       = PASS    DIAL_FAILURES    = PASS    BACKOFF          = PASS
DIVERSITY           = PASS    ANCHOR_RECOVERY  = PASS    PEX_RECOVERY     = PASS
SEED_LAST_RESORT    = PASS    RESTART_RECOVERY = PASS    ATTACK_SCENARIO  = PASS
COMMIT              = <hash>  DEPLOYMENT       = NONE    V1.4.0_IMMUTABLE = PASS
```

**Propriété fondamentale à démontrer :**

> Un nœud Aether ayant déjà participé au réseau peut perdre son bootnode **et**
> une grande partie de ses connexions sans perdre sa capacité à reconstruire
> automatiquement son voisinage P2P.

`SELF_HEALING = PASS` uniquement si les scénarios ci-dessus sont réellement
couverts. **Jamais** « self-healing parfait ».
