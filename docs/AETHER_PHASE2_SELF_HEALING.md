# AETHER — Phase 2D : self-healing réseau

**Statut : `SELF_HEALING = PASS`** (sur les scénarios de §9, réellement testés)

> Ce document est le rapport d'implémentation de la Phase 2D. Le raisonnement
> qui a produit la conception se trouve dans
> `docs/AETHER_PHASE2_SELF_HEALING_AUDIT.md` (écrit **avant** toute
> modification de code) ; ce document décrit ce qui a réellement été livré,
> vérifié, et ce qui reste ouvert.
>
> **Ce document ne revendique jamais « self-healing parfait ».** Un nœud dont
> le peer store est vide, sans DNS et sans bootnode n'a toujours **aucune**
> source vers laquelle se reconstruire (audit §I.1, §C.3). Le statut revendiqué
> est uniquement : *un nœud qui a **déjà** participé au réseau reconstruit
> automatiquement son voisinage, y compris si son bootnode est tombé.*

Branche : `dev/phase2-decentralized-network`
Base : `161d43e phase2: harden eclipse resistance`
Fichier modifié : `src/p2p.rs` (seul fichier de code de la Phase 2D)
RELEASE figée : `v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316`
Déploiement : **aucun** (`DEPLOYMENT = NONE`)

---

## 1. Objectif

Après la Phase 2A (plus de bootnode obligatoire au démarrage), la 2B
(`AddressManager`) et la 2C (résistance à l'eclipse), il restait une question
non traitée : **que se passe-t-il quand les connexions tombent ?**

Les trois mécanismes existants ne répondaient pas :

* `initial_dial_sweep` ne tourne **qu'une fois**, au démarrage (audit §A.11) ;
* `start_reconnection_task` ne redialle **que** des adresses déjà connues, à un
  intervalle fixe, sans regarder le **nombre** de sessions vivantes ;
* `outbound_candidates` borne et classe les candidats, mais **n'observe** pas
  l'état de santé du nœud.

Résultat : un nœud pouvait perdre progressivement ses sessions (pire cas : un
adversaire qui les ferme une à une) et rester silencieusement seul, sans jamais
rouvrir un slot. La Phase 2D ajoute **l'observation périodique du nombre de
sessions** et **une décision de reconnexion bornée**, en réutilisant
intégralement le ladder de sélection de la 2C.

**Ce que la Phase 2D n'est pas :** ce n'est pas une source de pairs nouvelle
(mécanisme 2E ou DHT hors périmètre), pas une réécriture de `src/p2p.rs`, pas
une protection anti-eclipse supplémentaire. `ECLIPSE_PROOF` reste **non déclaré**.

---

## 2. Architecture

```
start()
  └── start_recovery_task()            ← tâche, remplace start_heartbeat()
        └── toutes les RECOVERY_INTERVAL (5 s)
              └── recovery_round()     ← appelable par les tests d'intégration
                    ├── peers.read() → (count, connected)   [snapshot puis release]
                    ├── count >= RECOVERY_COMFORT_PEERS ? → Healthy, reset, retour
                    ├── ctl = recovery.read()
                    ├── ranked = outbound_candidates(MAX_DIALS_PER_ROUND)
                    │        └── known = ranked \ seeds        ← les seeds sont
                    │                                          scindées ici pour
                    │                                          pouvoir être retenues
                    ├── plan_recovery(...)  ← pure, testable sans réseau
                    │        ├── tier 1 : anchors   (AddressManager)
                    │        ├── tier 2 : known     (Phase 2C select_outbound)
                    │        └── tier 3 : seeds     (en dernier recours seulement)
                    ├── log si changement d'état
                    ├── for addr in round.dial → connect_to_peer(addr)
                    └── recovery.write().record_round(opened, now)
```

Trois pièces, toutes nouvelles, toutes séparées du reste :

| Pièce | Rôle | Testable sans réseau |
|---|---|---|
| `PeerRecoveryController` | état + backoff + échec consécutif | oui (transitions pures) |
| `plan_recovery()` | fonction **pure** : compte + sources → `RecoveryRound` | oui |
| `recovery_round()` | tâche : observer, décider, dialer, enregistrer | oui (appel direct) |

**Discipline de verrous respectée** : `peers` est lu, **copié**, puis relâché
*avant* l'acquisition de `addresses` (`recovery_round`, lignes `:2323-2329` puis
`:2370-2385`). `peers` et `addresses` ne sont **jamais** détenus simultanément,
comme en 2C.

---

## 3. États

```rust
enum RecoveryState { Healthy, Recovering, Degraded, Exhausted }
```

| État | Signification | Dial ? |
|---|---|---|
| `Healthy` | `count >= RECOVERY_COMFORT_PEERS` (8) | non |
| `Recovering` | sous le seuil, source disponible, backoff expiré | **oui** |
| `Degraded` | sous le seuil, backoff en cours (échecs consécutifs) | non |
| `Exhausted` | aucune source dialable **ou** `consecutive_failures >= 6` | non (sonde lente) |

**Hystéresis** (audit §E.6) : on *entre* en récupération dès `count < 4`, on en
*sort* seulement à `count >= 8`. La bande `[4, 8)` est large exprès : un nœud à
6 pairs ne oscille pas entre deux états, il reste simplement silencieux et n'a
rien à faire — il n'est pas encore « malade », mais il ne sera pas non plus
considéré comme sain si la perte continue.

`Exhausted` n'est **pas un loquet** : dès que son backoff est entièrement
expiré, `open_probe_window()` rouvre une fenêtre de sonde (`:2354-2357`), de
sortie que le nœud ne reste jamais définitivement figé.

---

## 4. Seuils — tous dérivés du code existant

**Aucune constante de production existante n'a été modifiée.** Les cinq
constantes 2D sont des alias ou des fractions de constantes déjà justifiées
en Phase 1 / 2C :

| Constante 2D | Valeur | Égal | Justification |
|---|---|---|---|
| `RECOVERY_COMFORT_PEERS` | **8** | `PROTECTED_OUTBOUND_SLOTS` | « confort » = le nombre de slots sortants qu'un nœud est censé tenir. Atteindre 8, c'est tenir exactement le contingent sortant protégé : rien à réparer. |
| `RECOVERY_THRESHOLD` | **4** | `MAX_PEERS_PER_SUBNET` | Le *plafond* par /24 devient le *plancher* de santé : sous ce nombre, le nœud ne dispose même plus de l'équivalent d'un seul subnet sain. Coïncidence assumée et documentée. |
| `RECOVERY_MIN_PEERS` | **3** | `MIN_ANCHORS` | En dessous, le nœud est même en dessous de la diversité d'ancres minimale : état d'alerte affiché dans le log. |
| `MAX_DIALS_PER_ROUND` | **8** | = `RECOVERY_COMFORT_PEERS` | Un round ne peut pas, à lui seul, réparer plus que la distance maximale au confort. Borne stricte sur la pression de dial. |
| `RECOVERY_INTERVAL` | **5 s** | — | Une observation toutes les 5 s : assez rapide pour qu'un nœud isolé reconstitue 8 sessions en ≤ 4 rounds, assez lente pour ne pas peser sur le scheduler. |

`RECOVERY_THRESHOLD < RECOVERY_COMFORT_PEERS` est ce qui rend la bande
`[4, 8)` large : 4 et 8 ne sont pas deux visions d'un même chiffre, ce sont
deux seuils distincts avec un espace mort volontaire entre eux.

---

## 5. Backoff

```rust
fn recovery_backoff(level: u32) -> Duration {
    if level == 0 { return Duration::ZERO; }
    let shift = (level - 1).min(RECOVERY_MAX_LEVEL - 1);      // 5
    let secs = (RECOVERY_BACKOFF_BASE_SECS << shift).min(RECOVERY_BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}
```

| `backoff_level` | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
|---|---|---|---|---|---|---|---|
| délai | 0 s | 5 s | 10 s | 20 s | 40 s | **60 s** | **60 s** |

* **Borné** à `RECOVERY_BACKOFF_MAX_SECS = 60` : le nœud se sonde au pire une
  fois par minute, jamais moins. `recovery_backoff(RECOVERY_MAX_LEVEL + 99) ==
  recovery_backoff(RECOVERY_MAX_LEVEL)` est vérifié par test.
* **Identique en forme** à l'existant `min(2 ^ min(attempt, 6), 60)` du
  backoff par candidat : le codebase ne se retrouve pas avec deux notions
  différentes de « combien de temps attendre ».
* **Incrémenté** à chaque round qui n'ouvre **aucune** session
  (`record_round(0, …)` → `backoff_level += 1`, plafonné à 6),
  `consecutive_failures` compté en parallèle, plafonné à
  `RECOVERY_MAX_CONSECUTIVE_FAILURES = 6`.
* **Remis à zéro** dès que `count >= RECOVERY_COMFORT_PEERS` (`reset()`),
  c'est-à-dire dès que le problème est résolu — pas seulement quand un seul
  dial réussit.

C'est le backoff du **contrôleur**, pas celui des adresses : l'audit §I.2
rappelle que `record_failure` d'`AddressEntry` reste sans horloge (`failures`
cumulatif, jamais lu) et n'a pas été touché.

---

## 6. Ordre des sources (échelle)

`plan_recovery` construit la liste à dialer dans cet ordre strict, en s'arrêtant
dès que `MAX_DIALS_PER_ROUND` est atteint :

1. **Tier 1 — anchors** (`mgr.anchor_addresses()`, tri récence décroissante).
   Ce sont des adresses que le nœud a **lui-même** atteintes et retenues :
   preuve directe, priorité absolue.
2. **Tier 2 — connues** (`outbound_candidates`, c'est-à-dire le ladder 2C
   inchangé : qualité, récence, bonus anchor, pénalité de groupe).
3. **Tier 3 — seeds** (`config.bootnodes`) : **retenues**, sauf si
   (a) tier 1 + tier 2 sont vides, ou (b) `consecutive_failures > 0`.

La condition (b) est le cœur de l'audit §C : un nœud dont les tentatives
échouent n'a **pas** le droit de remonter au bootnode en boucle — c'est
exactement le scénario « bootnode compromis qui noie le nœud » que la 2A
cherchait à rendre inoffensif. Le bootnode ne devient une option que quand il
n'y a **rien** d'autre.

Chaque dial passe par `recovery_group_room` : le /24 courant est recompté à
chaque candidat, donc un round ne peut pas mettre plus de
`MAX_PEERS_PER_SUBNET = 4` sessions dans un même groupe.

---

## 7. AddressManager

Aucun nouveau champ dans `AddressManager`. La 2D **consomme** trois API
existantes :

| API | Usage en 2D |
|---|---|
| `anchor_addresses()` | tier 1 du ladder |
| `is_banned(addr)` | filtre appliqué à **chacun** des trois tiers |
| `observe` / `admit` / `record_success` / `record_failure` | inchangés |

Les anchors proviennent de la persistance `to_store` → `load_v2` déjà livrée en
2C/2B : c'est ce qui rend `test_self_healing_restart` possible — un redémarrage
ne perd pas la capacité de se reconstruire.

`outbound_candidates` est appelé **tel quel**, avec `limit = MAX_DIALS_PER_ROUND`.
La 2D n'introduit aucun second chemin de sélection : la 2C reste l'unique
producteur de candidats, la 2D ne fait qu'ajouter une **observation** et une
**échelle** au-dessus.

---

## 8. Interaction avec Eclipse Resistance (Phase 2C)

| Invariant 2C | Statut après 2D |
|---|---|
| `select_outbound` : quota par groupe, bonus anchor, pénalité de sur-représentation | **inchangé** — appelé par `outbound_candidates` comme avant |
| Réserve de slots sortants (`PROTECTED_OUTBOUND_SLOTS`) | **inchangé** — `RECOVERY_COMFORT_PEERS` est un *alias*, pas une redéfinition |
| `inbound_admitted` | **non touché** |
| Qualité d'admission PEX (50) | **inchangé** — vérifié par `test_self_healing_uses_pex` |
| Purge des `scores` | **inchangé** |
| Bannissement `is_banned` | **appliqué en plus** dans les trois tiers |

La 2D **ne peut pas** ouvrir plus de 4 sessions par /24 ni plus de 8 dials par
round : elle hérite des bornes 2C par construction (`recovery_group_room`,
`MAX_DIALS_PER_ROUND`). C'est ce qui autorise à affirmer que la 2D ne
dilate pas la surface d'eclipse.

Ce qui **n'a pas** été déclaré : `ECLIPSE_PROOF = YES`. Rien n'a changé là-dessus.

---

## 9. Scénarios

Les douze critères de sortie de l'audit §J :

| Scénario | Couvert par | Ce qui est vérifié |
|---|---|---|
| `SINGLE_PEER_LOSS` | `test_self_healing_single_peer_loss` | 8 sessions → 7 : état reste `Healthy`, aucun dial, aucun log |
| `MAJORITY_PEER_LOSS` | `test_self_healing_majority_peer_loss` | 8 → 2 : `Recovering`, tier1 ≥ 1, tier2 ≥ 1, ≥ 6 dials planifiés |
| `ZERO_PEERS` | `test_self_healing_zero_peers` | 0 session : 3 anchors + 5 connues, **0 seed** (tier 1+2 non vides) |
| `BOOTNODE_DOWN` | `test_self_healing_bootnode_down` | plan **identique** avec et sans seed configurée : le bootnode n'est pas une dépendance |
| `DIAL_FAILURES` | `test_self_healing_dial_failures` | qualité −5 par échec (`max(q−5, 0)`), `backoff_level` et `consecutive_failures` incrémentés, plafonnés |
| `BACKOFF` | `test_self_healing_backoff`, `…_backoff_reset` | strictement croissant, monotone, **plafonné à 60 s**, niveau 0 = 0 s, reset au retour à `Healthy` |
| `DIVERSITY` | `test_self_healing_respects_outbound_limits`, `…_preserves_diversity` | ≤ `MAX_DIALS_PER_ROUND` par round ; sessions résultantes ≤ 4 par /24, plusieurs groupes |
| `ANCHOR_RECOVERY` | `test_self_healing_uses_anchors`, `…_uses_address_manager` | anchors en tête, triées par récence, connues ensuite ; viennent bien de l'`AddressManager` |
| `PEX_RECOVERY` | `test_self_healing_uses_pex` | un hint PEX est admis, marqué `PeerSource::Pex`, pesé à `PEX_ADMISSION_QUALITY = 50` < qualité observée, **et** atteint le ladder |
| `SEED_LAST_RESORT` | `test_self_healing_seed_last_resort` | seed dialée **uniquement** après échecs consécutifs ou tier 1+2 vides |
| `RESTART_RECOVERY` | `test_self_healing_restart` | restauration `load_v2` → `Recovering`, les 2 anchors restaurées sont **toutes** dialées |
| `ATTACK_SCENARIO` | `test_self_healing_attack_scenario` | /24 adverse saturé (64 candidats) → **≤ `MAX_PEERS_PER_SUBNET`** dials dans ce groupe, anchors honnêtes en tête, seed **jamais** dialée ; 6 rounds sans succès → `Exhausted` |

Deux tests d'**intégration** (sockets TCP réelles, boucle locale) :

| Test | Ce qu'il prouve |
|---|---|
| `test_self_healing_integration_bootnode_down_convergence` | bootnode configuré mais **mort**, **0 session** et 4 anchors loopback → `recovery_round()` ouvre **4 sessions TCP réelles** (tier 1 uniquement, le bootnode n'est jamais dialé), `consecutive_failures = 0`, `backoff_level = 0` ; puis 4 sessions modélisées portent le total à 8 → `Healthy`, round **vide**, backoff remis à zéro |
| `test_self_healing_integration_restart_to_healthy` | aller/retour disque (`to_store` → `load_v2`) : redémarrage à **0 session** → `Recovering`, 2 anchors restaurées, **2 sessions TCP réelles** rouvertes depuis le store, backoff à 0 ; puis 6 sessions modélisées → `Healthy` et round **vide** : le nœud à l'aise ne dial rien |

---

## 10. Tests

Module `phase2_self_healing_tests` (`use super::*;`), **17 tests** — les 15
imposés par l'audit §G (G.1→G.4) plus les 2 tests d'intégration exigés par
§G.5.

| # | Test | Type |
|---|---|---|
| 1 | `test_self_healing_single_peer_loss` | transition (G.1) |
| 2 | `test_self_healing_majority_peer_loss` | échelle de sources (G.2) |
| 3 | `test_self_healing_zero_peers` | échelle de sources (G.2) |
| 4 | `test_self_healing_bootnode_down` | dépendance bootnode (§C) |
| 5 | `test_self_healing_dial_failures` | contrôleur (G.1) |
| 6 | `test_self_healing_backoff` | bornes (G.3) |
| 7 | `test_self_healing_backoff_reset` | cycle de vie (G.4) |
| 8 | `test_self_healing_respects_outbound_limits` | bornes (G.3) |
| 9 | `test_self_healing_preserves_diversity` | diversité (G.3) |
| 10 | `test_self_healing_uses_anchors` | échelle (G.2) |
| 11 | `test_self_healing_uses_address_manager` | échelle (G.2) |
| 12 | `test_self_healing_uses_pex` | PEX (async) |
| 13 | `test_self_healing_seed_last_resort` | échelle (G.2) |
| 14 | `test_self_healing_restart` | cycle de vie (G.4, async) |
| 15 | `test_self_healing_attack_scenario` | scénario d'attaque |
| 16 | `test_self_healing_integration_bootnode_down_convergence` | **intégration** (G.5, async, TCP réel) |
| 17 | `test_self_healing_integration_restart_to_healthy` | **intégration** (G.5, async, TCP réel) |

**Aucun test existant n'a été modifié.** Les 98 tests `p2p::`, les 26
`phase2_decentralized_tests`, les 15 `phase2_eclipse_tests` et les 19
`bootstrap_phase1` sont restés verts sans modification d'une seule ligne.

Note de réggie : les sessions « modélisées » (`insert_session`) servent
uniquement à déplacer le **compteur** jusqu'à `RECOVERY_COMFORT_PEERS`. Un hôte
de test ne dispose que de la boucle locale, et la boucle locale est **un seul**
`/24` — donc au plus `MAX_PEERS_PER_SUBNET = 4` sockets réelles y sont
jamais ouvrables. C'est la raison pour laquelle le test d'intégration 16 s'arrête
à 8 sessions avec 4 réelles et 4 modélisées, et non pas 8 sockets réelles.

Les assertions portent sur des **propriétés** (états, bornes, cardinalités,
appartenance à un groupe, ordre relatif des tiers), jamais sur une liste
d'adresses choisie pour faire passer un test. Les seuls nombres littéraux sont
`8`, `4`, `3`, `2`, `6`, `60` — tous des constantes de production déjà
justifiées.

---

## 11. Limites (audit §I — **non résolues par 2D**)

1. **Aucune source nouvelle.** 2D ordonne et borne les sources existantes ;
   un nœud dont le store est vide, sans DNS et sans bootnode n'a toujours
   **aucune chose** à reconstruire. C'est la limite exacte du statut revendiqué.
2. **`record_failure` reste sans horloge** (L-9) : `failures` est cumulatif,
   jamais remis à zéro, jamais lu. La récupération s'appuie sur son propre
   backoff de contrôleur.
3. **`retry_counts` / `next_attempt` ne sont pas purgés** (F.3) : leurs clés
   s'accumulent avec les candidats abandonnés. Hors périmètre.
4. **Le chemin PEX n'a pas de limite par round** (L-8) : la 2D ne le touche
   pas ; il reste borné par `dialing` + les 5 gardes de `connect_to_peer_inner`.
5. **Le trap A.12.1** (jusqu'à 32 `warn!` par 5 s sur un nœud saturé) est
   préexistant et n'a pas été modifié.
6. **`ECLIPSE_PROOF` n'est jamais déclaré `YES`**, comme en 2C.
7. **Le contrôleur est un `RwLock` mono-instance**, pas un état persisté :
   un redémarrage repart à `Healthy` / niveau 0. C'est volontaire — l'état de
   santé n'a pas de sens entre deux process — mais cela signifie qu'un nœud
   en `Exhausted` qui redémarre repart de zéro.
8. **`Degraded` et `Exhausted` n'ont pas d'alerte externe** (webhook, RPC) :
   ils sont journalisés en `warn!` uniquement (audit §H).

---

## 12. Résultats

| Contrôle | Résultat |
|---|---|
| `SELF_HEALING_AUDIT` | **PASS** — `docs/AETHER_PHASE2_SELF_HEALING_AUDIT.md` écrit **avant** toute modification de code (sections A→J, lacunes L-1…L-10, 12 scénarios) |
| `SELF_HEALING_TESTS` | **17/17 PASS** |
| `P2P_REGRESSION` (`cargo test --lib p2p::`) | **115/115 PASS** (98 base + 17 nouveaux) |
| `PHASE2_REGRESSION` (`cargo test --lib phase2_decentralized_tests`) | **26/26 PASS** |
| `ECLIPSE_REGRESSION` (`cargo test --lib phase2_eclipse_tests`) | **15/15 PASS** |
| `BOOTSTRAP_PHASE1` (`cargo test --lib bootstrap_phase1`) | **19/19 PASS** |
| `cargo check --lib` | **EXIT 0**, **9 warnings**, **0 nouveau** |
| `git diff --check -- src/p2p.rs` | **EXIT 0** |
| `SINGLE_PEER_LOSS` | PASS |
| `MAJORITY_LOSS` | PASS |
| `ZERO_PEERS` | PASS |
| `BOOTNODE_DOWN` | PASS |
| `DIAL_FAILURES` | PASS |
| `BACKOFF` | PASS |
| `DIVERSITY` | PASS |
| `ANCHOR_RECOVERY` | PASS |
| `PEX_RECOVERY` | PASS |
| `SEED_LAST_RESORT` | PASS |
| `RESTART_RECOVERY` | PASS |
| `ATTACK_SCENARIO` | PASS |
| `SELF_HEALING` | **PASS — sur les scénarios de §9, réellement testés. Jamais « self-healing parfait ».** |
| `ECLIPSE_PROOF` | **non déclaré — jamais `YES`** |
| `COMMIT` | `phase2: add peer self-healing` |
| `DEPLOYMENT` | **NONE** |
| `V1.4.0_IMMUTABLE` | **PASS** — `git rev-list -n1 v1.4.0-testnet` = `ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316`, inchangé ; aucun tag ajouté |

### Détail des warnings

Baseline Phase 2C : **9 warnings préexistants**. Phase 2D en laisse **9**, la
liste est **identique** :

| # | Warning | Statut |
|---|---|---|
| 1 | `unused import: tower_http::cors::CorsLayer` (rpc.rs) | préexistant |
| 2 | `constant PEER_PENALTY_CONTRADICTION is never used` | préexistant |
| 3 | `constant PEER_PENALTY_TIMEOUT is never used` | préexistant |
| 4 | `constant PEER_PENALTY_ABUSIVE is never used` | préexistant |
| 5 | `constant PEER_BONUS_SYNC is never used` | préexistant |
| 6 | `method PeerScore::reward is never used` | préexistant |
| 7 | `function count_subnet_peers is never used` | préexistant |
| 8 | `touch_peer` / `nonce_collision_possible` / `ancestor_closed_page` jamais utilisés | préexistant |
| 9 | `field difficulty is never read` (validation.rs) | préexistant |

**0 warning nouveau introduit.** En particulier `plan_recovery`,
`recovery_backoff`, `next_state`, `recovery_group_room`, `PeerRecoveryController`
et les cinq constantes 2D sont tous effectivement appelés par la production —
c'est la raison pour laquelle `start_heartbeat` a été **remplacé** par
`start_recovery_task` plutôt qu'à côté de lui : laisser l'ancienne boucle de
10 s en place aurait donné deux cadences concurrentes.

---

## Reproductibilité

```powershell
$env:PATH = "C:\msys64\mingw64\bin;C:\Users\Shadow\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained;" + $env:PATH
cargo check --lib
cargo test --lib phase2_self_healing_tests   # 17/17
cargo test --lib p2p::                       # 115/115
cargo test --lib phase2_decentralized_tests  # 26/26
cargo test --lib phase2_eclipse_tests        # 15/15
cargo test --lib bootstrap_phase1            # 19/19
git diff --check -- src/p2p.rs
git rev-list -n1 v1.4.0-testnet              # ad08e308ffbb96152f1ed6d4d7a2ea8e9ed54316
```

Aucun push, aucun merge, aucun tag, aucun déploiement.
