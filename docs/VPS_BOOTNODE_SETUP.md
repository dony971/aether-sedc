# VPS BOOTNODE SETUP — VPS-100333 (vps1uro)

**Rôle :** seed d'infrastructure (phase test, PAS de testnet public)
**OS :** Ubuntu 24.04 LTS, 1 vCPU / 1 Go RAM / 20 Go (18G libres)
**Binaire :** build natif depuis branche `canary-c2-fixes` (P1→P3 + topo fixes),
  SHA256 Linux `6a60210c85e0e8b7e3a737bef359f8c4f762a60c062006bb9bc60049894a501d`
**Genesis :** identique au canary local (faucet `a19e…` = 1000000000000000000)
**Faucet :** ABSENT du VPS (aucune `faucet.key`, endpoint désactivé)
**Verdict :** 🟢 VPS BOOTNODE VALIDÉ (infra) — usage test uniquement, rien de public

---

## 1. Endpoint public

| Couche | Valeur |
|---|---|
| **PUBLIC ENDPOINT** | `webgate.vps1euro.fr:32314` (TCP, joignable, handshake OK) |
| Forwarding | WebGate port dédié `32314` → VPS `25565` (créé 07/09/2026) |
| Réseau interne hébergeur | `172.50.0.44/16` (interface `webgate` sur le VPS) |
| P2P listener | `0.0.0.0:25565`, pid `aether-unified`, user `aether` |

Notes :
- L'IP directe `103.102.135.123:25565` est INFILTRABLE (firewall hébergeur,
  tout inbound fermé sauf via leurs proxys). Idem ports 22/80/443/9933.
- Le proxy SSH (`VPS-...ssh.vps1euro.fr:9221`, gateway `.126`) est un hôte
  séparé ; le port 32314 n'y répond pas (c'est bien `webgate.vps1euro.fr`).
- IPv6 VPS : `2a0c:b641:1a0:800::ba` (non testée depuis ici, pas d'IPv6 locale).

## 2. Machine

- Utilisateur dédié `aether` (uid 1000), binaire `/opt/aether/bin/aether-unified`,
  data `/opt/aether/data`, sources `/opt/aether/src` (build natif 32 min, `-j1`,
  1 Go RAM sans swap possible — conteneur).
- Dépendances : `curl ca-certificates build-essential pkg-config libssl-dev`,
  toolchain stable via rustup (profil minimal).
- **Pas de swap possible** (conteneur, `swapon` refusé) — à retenir pour les
  futurs builds (toujours `-j1`).

## 3. Service

`/etc/systemd/system/aether-seed.service` (extrait) :
```
User=aether
ExecStart=/opt/aether/bin/aether-unified --node-type validator \
  --data-dir /opt/aether/data --p2p-port 25565 --rpc-port 9933 --bootnodes ""
Restart=always / RestartSec=10 / NoNewPrivileges=true
```
- `--bootnodes ""` = seed pur (aucune sortie, que de l'entrant).
- Auto-start après reboot : **confirmé** (reboot réel, service remonté seul).
- **JAMAIS de `--daemon`** (inexistant en RC), **JAMAIS de faucet.key**.

## 4. Firewall

| Port | Statut | Raison |
|---|---|---|
| 25565/tcp (P2P) | ALLOW IN (v4+v6, ufw) | seed entrant (+ forward WebGate) |
| 9933/tcp (RPC) | FERMÉ (ni ufw ni panel) | RPC bind `0.0.0.0` : exposition = danger |
| 22/tcp (SSH) | ALLOW (ufw) + proxy hébergeur 9221 | admin via proxy uniquement |
| Autres | DROP (panel hébergeur par défaut) | tout inbound direct fermé |

Vérifié depuis Internet : P2P via `webgate.vps1euro.fr:32314` OK ;
`103.102.135.123:9933` TIMEOUT (RPC inaccessible ✓).

## 5. Procédure de test (validée)

1. Nœud vierge local, `--bootnodes webgate.vps1euro.fr:32314` uniquement.
2. Résultat : 1 peer des deux côtés, handshake accepté (genesis identique,
   faucet 1e18 des deux côtés), DAG vides convergés, sync Received actif.
3. Compteurs à surveiller : `connected_peers`, `sync_requested/received`,
   `orphan_created/resolved`, `topo_cache_hits/miss`.

## 6. Handshake / identité

- Genesis hash + version protocole P2P vérifiés au handshake (code :
  rejet `identity-mismatch`, test `test_handshake_identity_mismatch_rejected`).
- Rejet d'un réseau incompatible : garanti par construction (même code
  que le canary local) ; pas de second réseau sous la main pour le
  démontrer en live — noté comme vérifié par code + tests, pas en live.

## 7. Limitations connues

- 1 Go RAM / 1 CPU : UN seed uniquement, pas de charge, pas de build
  parallèle (`-j1` obligatoire), pas de swap.
- Pas de faucet : les wallets d'essai doivent être fundés ailleurs
  (le VPS ne distribue rien).
- Le VPS ne doit JAMAIS être bootnode du canary local 127.0.0.1
  (risque de pontage de réseaux) ni l'inverse sans décision explicite.
- Pas d'annonce publique (IP/port/bootnode/téléchargement) tant que
  l'intégration n'est pas terminée.

## 8. Reboot / maintenance

- `systemctl {status,restart} aether-seed.service` (via proxy SSH 9221).
- Après reboot : vérifier `is-active`, listener `:25565`,
  `aether_getDagStats` en localhost, endpoint public.
- Mise à jour binaire : rebuild natif (`-j1`), `install` + `systemctl
  restart`, vérifier SHA + genesis avant/après.
- Mot de passe root initial transité en clair : **à changer** (`passwd`).
