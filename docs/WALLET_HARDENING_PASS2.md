# WALLET HARDENING PASS 2 — Persistance, concurrence, recovery, transactions

**Protocole :** GELÉ (aucune règle consensus/DAG/ledger/économie/Genesis
touchée ; `wallet.rs:to_file` = file-IO wallet uniquement).
**Canary/soak :** non perturbés (environnement de dev séparé, binaires
en mémoire intouchés). Binaire canary : image `AA9F` conservée.

---

## 1. Persistance atomique (P1)

Constat : 3 écritures Python directes (`create`/`restore`/`import`) +
`to_file` Rust en un seul `write` → crash mid-write = wallet tronqué
irrécupérable (sans mnémonique : fonds perdus sans backup).
Correctif : `utils/atomic.py` (temp même dir + flush + fsync + rename)
appliqué aux 3 flows + `encrypt_file` ; `to_file` Rust : temp PID-unique
+ flush + sync_all + rename.
Tests : contenu exact, zéro `.tmp` résiduel, JSON toujours parsable.

## 2. Concurrence (P2)

`FileLock` coopératif (fichier `.lock` + PID, reap des morts, timeout
borné). **Bug trouvé PAR les nouveaux tests** : v1 fuyait le fd (fichier
inéffaçable sous Windows) + branche `continue` sans check deadline →
boucle infinie en contention. Corrigé (close immédiat, deadline à
chaque tour, release limitée à ses propres locks) : suite 9/9 en 2,5 s.
Lecteurs sans verrou (rename atomique = lecture ancien-ou-nouveau complet).

## 3. Recovery (P3)

- `create`/`restore`/`import` **refusent d'écraser** un wallet existant
  (avant : destruction silencieuse → perte potentielle). Message explicite.
- Fichier tronqué/vide/JSON invalide/v2 incomplet : erreur `load_error`
  forte, jamais de chargement silencieux, jamais d'écrasement.
- Permission refusée : échec propre OU succès avec fichier valide —
  jamais de partiel (testé).
- PIN/chiffrement via chemin atomique.

## 4. Transactions (P4)

- Double-submit mesuré : 2 tx distinctes (delta exact 120) — UX ISSUE
  confirmée (pas d'idempotence), dialogue + bouton désactivé en place.
- **Bug trouvé : use-after-free QProcess** — le wrapper pouvait être
  collecté mid-flight → slot sur objet C++ mort → page send bloquée
  à jamais. Fix : refs dures `self._procs` + retrait à complétion.
- Single-flight testé (désactivé pendant drain, réactivé à la fin).
- Crash A–E mappés (analyse §12 rapport stabilité) : aucun cas ne crée
  deux débits pour un paiement (le retry crée une SECONDE tx voulue ou
  non — cf. double-submit).

## 5. RPC wallet (P5)

Zéro référence `0.0.0.0` côté wallet ; `RpcClient` et `send.py` en
`127.0.0.1` explicite ; redondance avec le gate canary. Tests existants
(E2E loopback) verts.

## 6. Tests et gates

- Wallet : **66/66** (dont 9 hardening + single-flight).
- Rust : `wallet::` 11/11 ; suite complète 180/180 conservée (aucune
  régression) ; fmt/clippy/audit : propres (1 faille connue acceptée).
- Contrôles négatifs exécutés (échec sur ancien code prouvé quand
  applicable : index purge, history rendering).
- Soak : 138 min, RAM 99→56 Mo, sync 10121 convergée, 0 erreur.

## 7. Recommandation GO / HOLD — rotation vers `75806F49` ou successeur

**HOLD sur la rotation binaire**, GO sur le reste :
- Le wallet durci (Python) est indépendant du binaire embarqué : ses
  correctifs sont validés et committés, déployables via rebuild.
- La rotation `AA9F` → `75806F49` (+ futurs builds avec `to_file`
  atomique Rust) doit suivre la procédure : stop planifié → swap →
  boot rebuild → convergence → watchdog, PAS en cours de soak.
- Prochain build release à produire depuis `canary-c2-fixes` quand la
  fenêtre s'ouvrira ; pins/gate à mettre à jour ensemble (rc.py,
  canary_gate.ps1, backend wallet).
