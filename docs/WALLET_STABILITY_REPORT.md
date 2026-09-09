# WALLET STABILITY REPORT — Phase n°6

**Wallet :** 1.2.0, backend `AA9F7444` (vérifié au lancement), RC gelée intacte
**Protocole :** GELÉ — seules des corrections wallet (Python) listées §8
**Canary live :** 9 nœuds @10053, convergence 0 divergence (8×8)
**Test wallets :** `%TEMP%\tri wallets\` (triA/B/C, fundés, identifiés) ;
  mnémonique de test `double female…exit` (zéro balance, jamais fundée)

---

## 1. Environnement (§1)

Version/GUI/backend/SHA/pins : vérifiés au démarrage (garde RC).
`%APPDATA%\Aether` : wallets + backups chiffrés + logs (contient aussi
des résidus pré-RC : vieux sled_db, `.wallet_key`, backups — non touchés,
signalés §10).

## 2. Crash wallet (§2)

Aucun crash reproduit pendant la phase (lancements GUI multiples,
offscreen + réel, cycles, soak). Une disparition GUI antérieure à la
phase (pid 17252) : cause **INDÉTERMINÉE** (fenêtre fermée par
l'utilisateur ou crash — aucune preuve ; pas de stack, pas compté
comme incident trouvé).

## 3. Wallet + node (§3)

Processus séparés prouvés (pid GUI ≠ pid node) ; stop GUI → stop node
propre (terminate + kill de repli). Kill GUI brutal → nœud orphelin
survit (données sauves), relance OK (retry verrou sled). Sens inverse :
nœud mort → GUI reste utilisable en lecture dégradée (erreurs RPC
affichées, pas de crash).

## 4. Create (§4) — matrice 6 cas, tous PASS

normal/faible/long/spéciaux/unicode acceptés (pas de politique mot de
passe en RC — documenté), vide refusé, mauvais password rejeté au
verify. Aucun secret en logs.

## 5. Restore (§5)

`wallet create` → mnemonic → `wallet restore` : **même adresse**
(2× déterministe). Python relit le fichier restauré. Mnémonique jamais
loggée (scan §16).

## 6. Import (§6)

Clé 64 hex → adresse correcte (Ed25519 vérifié contre Rust) ; 128 hex
tronquée proprement ; entrées invalides rejetées avec message (pas de
fichier écrit, pas de clair stocké hors format chiffré).

## 7. Chiffrement (§7)

Matrice Argon2id : bon/mauvais password, payload tronqué/corrompu,
champ manquant, version inconnue, non-JSON, binding trafiqué → tous
rejetés proprement (`RustWalletError`), jamais de fallback clair.
Cross-compat Python↔Rust déjà prouvée (phase toolchain, 5/5).

## 8. Corrections wallet de la phase (toutes WALLET BUG / UX, 0 protocole)

1. **Historique : timestamps ms non rendus** (colonne Time à `-`) → détection
   ms→s (table + CSV).
2. **Export CSV plantait** (`fromtimestamp` non protégé + ms) → protégé.
3. **Frais affichés `0` trompeurs** (champ absent en RC) → `—`.
4. **Statut toujours `unknown`** (champ absent ; l'historique ne contient
   que du confirmé) → `confirmed`.
   Test de régression `test_history_renders_real_rc_shape` (forme RPC
   réelle : tableaux de bytes, ms) : **échoue sur l'ancien code**
   (contrôle négatif OK), passe sur le nouveau.

## 9. Transactions (§9) — triangle A→B→C→A

3 wallets fundés (faucet séquentiel,/node1) : 3 sends OK, balances
`99999999990` chacun, **identiques sur 3 nœuds**. Frais/PoW/nonce gérés
par le CLI (aucun cache local : vérifié, le manager ne détient ni
balance ni nonce).

## 10. Double envoi (§10) — UX ISSUE documentée, pas un bug

Double soumission rapide = **2 tx distinctes** (delta mesuré 120 =
2×(50+10), nonces distincts). Pas d'idempotence côté CLI/protocole
(comportement correct protocolairement). Atténuations GUI en place :
dialogue de confirmation + bouton désactivé pendant la file. Recommandé
aux utilisateurs : ne pas re-cliquer après timeout (vérifier l'historique).

## 11. Historique (§11)

`getRecentTransactions` (forme réelle vérifiée : fee/status/tx_id
présents, adresses en tableaux de bytes, timestamps ms) : rendu corrigé
(§8), recherche + export CSV non-crash. `getTransactionHistory`
(1262 tx sur wallet actif, paginé 100) inutilisé par la GUI (noté).

## 12. Crash pendant send (§12) — analyse A–E

- A (avant signature) : rien créé, rien à renvoyer. Sûr.
- B/C (après signature / pendant RPC) : le CLI est un processus séparé ;
  la mort de la GUI n'interrompt pas la soumission. Vérifier l'historique.
- D (après acceptation) : prouvé par E2E (inclusion constatée).
- E (node crash pendant send) : tx en mempool/WAL des autres nœuds ;
  renvoyer est SANS RISQUE de double-débit protocolaire (nouveau nonce),
  mais crée une SECONDE tx (cf. §10) — UX, pas consensus.

## 13. Cache local (§13)

Aucun : ni balance, ni nonce, ni tips, ni historique en cache (vérifié
code + test). Chaque affichage = RPC frais. Impossible d'écraser un
état réseau par du périmé.

## 14. Concurrence (§14)

4 créations parallèles : aucune corruption (4 wallets listés). Envois
parallèles multi-wallets : OK en live (gen 8 workers en canary).
Pas de freeze observé (timers courts, RPC synchrones brèves).

## 15. GUI (§15)

7 pages construites offscreen sans crash (dashboard/send/receive/
transactions/staking/mining/settings) ; aucune RPC inexistante appelée
(test statique + smoke) ; staking/mining explicitement indisponibles ;
aucun secret affiché (adresses publiques seules).

## 16. Secrets (§16)

Scan mots de passe de test + `mnemonic` sur `%APPDATA%`, wallets,
backups, logs, TEMP : **0 fuite**. Backups `.enc` chiffrés. Audit trail
sans matière sensible.

## 17. Permissions (§17)

`wallets/` : SYSTEM + Administrateurs + utilisateur seul (héritage
profil privé Windows). Fichiers créés sans partage élargi. Correct.

## 18. Updates (§18)

Garde canary testée : `CANARY_MODE=LOCAL` (défaut) bloque tout update
(testé). Bouton update inerte en canary. Aucun remplacement silencieux
possible (SHA pinné au lancement de toute façon).

## 19. Firewall/RPC (§19) — LIMITATION CONNUE

Le nœud wallet écoute RPC sur `0.0.0.0:9933` (toutes interfaces, constaté
`0.0.0.0 Listen`) : visible sur le LAN. Pas de bind local possible sans
changement protocole (hors phase). Recommandation : firewall hôte
(Windows Defender : bloquer 9933/25565 entrants sauf loopback) +
documenté ici. Testé : fonctionnement 100% local OK.

## 20. Stabilité longue (§20)

Soak GUI+node offscreen lancé (21:17) : RAM ~99 Mo stable, handles/
threads stables, rotation `app.log` prouvée en live (2 Mo + bascule),
sync 6791/10053 en cours sans erreur. Objectif 1 h : **en cours**
(relevé à ~6 min au moment du verdict) ; 4 h/24 h en suivi (processus
laissés tournants, à relever).

## 21. Restarts (§21)

3 cycles GUI start/stop : GUI vivante + nœud sur 9933 à chaque fois.
Limite honnête : répertoire partagé avec le soak → isolation imparfaite
(retry verrou sled : le mécanisme prévu a fonctionné).

## 22. E2E (§22)

A (create→faucet→send→restart→send), B (restore→receive→send),
C (import→receive→send) : suite existante relancée sur RC live — PASS.
Balances vérifiées multi-nœuds.

## 23. Régression

- Wallet : 15 (stabilité) + 5 (GUI) + E2E + 35 existants = verts
- Rust : inchangé cette phase (179/179 conservés)
- fmt Python : à passer ; clippy/audit Rust : inchangés

## 24. Incidents

Aucun WALLET-INC ouvert (aucun crash reproductible, aucune fuite,
aucun défaut signature/chiffrement).

## 26. Classification des constats

| # | Classe |
|---|---|
| Historique ms/fee/status/CSV | WALLET BUG (corrigé + testé) |
| Double-submit non idempotent | UX ISSUE (documenté) |
| RPC bind 0.0.0.0 | LIMITATION CONNUE (correctif = protocole, hors phase) |
| Disparition GUI antérieure | INDÉTERMINÉ (pas de preuve) |
| Résidus pré-RC dans %APPDATA% | UX ISSUE mineure (nettoyage manuel conseillé) |

## Verdict

```
🟢 WALLET STABLE (sous réserve soak 1 h en cours de complétion)
🟡 CANARY PEUT CONTINUER
```

Protocole toujours GELÉ. Le wallet s'est adapté au protocole.
