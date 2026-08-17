# AETHER V3 — Guide de démarrage du testnet (GETTING_STARTED_TESTNET.md)

Version: 1.2.0 · Réseau: TESTNET PUBLIC (canary) · Date: 2026-08-17

Ce guide explique comment rejoindre le testnet AETHER V3, envoyer des
transactions et utiliser le faucet. Aucune clé ni seed n'apparaît ici.

---

## 1. Télécharger les binaires

Depuis le dossier de release `aether-v3-testnet-release/` :

- `aether-unified.exe` (nœud complet + CLI, Windows x64),
- `aether.exe` (interface graphique, Windows x64),
- `genesis.json` (genèse officielle du testnet),
- `SHA256SUMS.txt` (empreintes des fichiers à vérifier).

Vérifier l'intégrité :

```
Get-FileHash aether-unified.exe -Algorithm SHA256   # comparer à SHA256SUMS.txt
```

## 2. Vérifier les empreintes

Comparer chaque fichier téléchargé à `SHA256SUMS.txt` avant toute exécution.
En cas de différence : ne pas lancer le nœud, signaler l'incident
(`docs/INCIDENT_RESPONSE.md`).

## 3. Créer un compte (wallet)

```
aether-unified.exe wallet create mon_wallet.json
```

Un mot de passe est demandé. Le fichier `mon_wallet.json` est privé : ne jamais
le partager, ne jamais le publier.

## 4. Obtenir la genèse

Le fichier `genesis.json` doit être présent à côté du binaire. Le réseau V3
n'accepte **que** cette genèse (`network_id` imprimé au démarrage). Ne pas
utiliser une genèse d'une autre version : la migration est impossible.

## 5. Lancer un nœud

```
aether-unified.exe --node-type full --data-dir ./data --p2p-port 42001 --rpc-port 42101 --bootnodes <ADRESSE_PUBLIQUE_D_UN_NOEUD>
```

- `--bootnodes` : au moins un nœud connu du réseau (adresse IP publique : port P2P).
- Le port RPC (`42101`) doit rester local (firewall : ne pas l'exposer à Internet).

## 6. Vérifier la synchronisation

Le nœud affiche dans ses logs la hauteur et le nombre de transactions.
Lancer ensuite le fichier `aether_getDagStats` via RPC pour confirmer que la
hauteur correspond à celle des autres nœuds.

## 7. Consulter le solde

```
aether-unified.exe balance mon_wallet.json --rpc-url http://127.0.0.1:42101 --password <MDP>
```

## 8. Recevoir des AETH du faucet

Envoyer une requête RPC au nœud faucet :

```
{"jsonrpc":"2.0","id":1,"method":"aether_faucet","params":["<ADRESSE_64_HEX>"]}
```

Règles : 10 AETH / 60 s / adresse. Les demandes excessives sont rejetées
(`Rate limited`). Le faucet est un outil de test : il ne dispense pas des
règles économiques du réseau (frais minimum de 1 AETH, burn des frais).

## 9. Envoyer une transaction

```
aether-unified.exe send mon_wallet.json --to <ADRESSE_64_HEX> --amount 100 --rpc-url http://127.0.0.1:42101 --password <MDP>
```

Le réseau exige : solde suffisant (montant + frais ≥ 1), nonce correct,
preuve de travail (difficulté 20). La confirmation requiert ≥ 3 références
directes ; le statut `Stable` requiert un poids ≥ 5,0.

## 10. Suivre une transaction

```
aether-unified.exe status <HASH_64_HEX> --rpc-url http://127.0.0.1:42101
```

Statuts possibles : `confirmed` (≥ 3 références), `Stable` (poids ≥ 5,0),
`practically_final`, `orphan` (à re-miner ou perdre).

## 11. Limites et règles du testnet

- Difficulté de minage : 20 (réglée pour du matériel de test, pas pour une
  production).
- Frais minimum : 1 AETH. Les frais sont **brûlés** (adresse `0xFF...FF`),
  aucune émission : l'offre totale ne peut que diminuer.
- RPC : 200 requêtes / 10 s / méthode, 40 requêtes / 10 s / (IP, méthode),
  1 MiB par requête.
- Orphelins : file plafonnée à 50 000 entrées.

## 12. Signaler un problème

Toute anomalie (divergence, crash, comportement inattendu) doit être signalée
avec : version du binaire, hash `SHA256SUMS`, extraits de logs **sans
secrets**, heure, et description. Les procédures d'urgence sont dans
`docs/INCIDENT_RESPONSE.md`.

---

## Avertissement

AETHER V3 est un testnet de validation technique : pas de valeur monétaire,
pas de garantie de disponibilité, données réinitialisables, et un rapport
complet des limites dans `docs/PUBLIC_TESTNET_NOTICE.md`.
