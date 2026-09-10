# WALLET ROTATION AA9F → CB8B93E7 — Procédure (NE PAS EXÉCUTER pendant le soak)

## 1. État actuel AA9F

- Binaire : `target/release/aether-unified.exe` = image mémoire des 9
  nœuds canary (fichier depuis remplacé sur disque — voir §2).
- Wallet embarqué (`aether-wallet/aether.exe`) : AA9F, pin rc.py conforme.
- Gate SHA : CB8B93E7 (binaire disque actuel).

## 2. Cible CB8B93E7

- Commit `canary-c2-fixes` incluant : P1/P2/P3, topo parents-first+cache,
  faucet serial, file logging + fix char-boundary, rpc-bind loopback.
- SHA256 : `CB8B93E7D1979AED44013D7D6540E25E0EA542A93120B6F4B833323ED27EC8AF`
- Formats compatibles : wallet v2 inchangé, Sled compatible (nouvel
  arbre `applied_tx` auto-créé, backstop store testé), TOML compatibles.

## 3-4. Versions / commits / SHA : voir `docs/RELEASE_MANIFEST.md`.

## 5. Compatibilité format : testée §6 (wallets + DAG + ledger).

## 6. Rollback

- Conserver `aether-unified.AA9F.bak` hors PATH avant tout swap.
- Rollback = stop → restaurer le .bak → start → convergence → E2E.
- Ne jamais supprimer l'ancien binaire avant validation live du nouveau.

## 7-16. Fenêtre de maintenance (ordre strict)

1. STOP : arrêter proprement les 9 nœuds (un par un, 30 s d'intervalle).
2. LOGS : copier `node*/logs/` vers archive horodatée (ne jamais perdre
   les preuves). BACKUP : snapshot des data dirs (au moins sled_db).
3. SWAP : remplacer le binaire (garder `.AA9F.bak`).
4. SHA VERIFY : `Get-FileHash` == CB8B93E7… (gate).
5. START : seed d'abord, puis les autres (30 s d'intervalle).
6. VERSION VERIFY : banner `BOOT` (version/commit/genesis/pid) par nœud.
7. SYNC : attendre total identique partout + mempools vides.
8. WALLET E2E : suite wallet (faucet/balance/send sur 127.0.0.1).
9. WATCHDOG : sweep propre (0 DOWN/CRITICAL).
10. CONVERGENCE : fingerprints totaux (DAG+tips+supply 10 adresses).
11. RESUME SOAK : nouveau T0, monitoring 1 h minimum.
