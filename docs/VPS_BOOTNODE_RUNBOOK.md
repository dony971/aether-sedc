# VPS BOOTNODE RUNBOOK — VPS-100333 (vps1uro, Ubuntu 24.04)

## Accès

- SSH via proxy hébergeur : `ssh -p 9221 root@VPS-100333.ssh.vps1euro.fr`
  (direct 22/80/443 fermés côté hébergeur ; seul le proxy passe).
- IPv4 : 103.102.135.123 (injoignable directement sauf via WebGate).
- IPv6 : `2a0c:b641:1a0:800::ba` (non testée, pas d'IPv6 locale).
- Auth : mot de passe root INITIAL TRANSMIS EN CLAIR — **à changer**
  (`passwd`) avant toute autre chose. Envisager clé SSH ensuite.

## Installation (reproductible)

1. `useradd -m -s /bin/bash aether`
2. `apt-get install curl ca-certificates build-essential pkg-config libssl-dev`
3. rustup stable profil minimal (user aether) ; **pas de swap possible**
   (conteneur) → toujours `cargo build --release -j1`.
4. Sources : archive git de la branche validée → `/opt/aether/srcN`.
5. `install -o aether -m 0755 target/release/aether-unified /opt/aether/bin/`
6. Vérifier SHA256 avant mise en service (pins : manifest + gate).

## Service

`/etc/systemd/system/aether-seed.service` : user `aether`,
`--node-type validator --data-dir /opt/aether/data --p2p-port 25565
--rpc-port 9933 --bootnodes ""`, `Restart=always`, `RestartSec=10`,
`KillSignal=SIGINT` (shutdown CLEAN loggé), `NoNewPrivileges=true`.
`systemctl {status,restart,stop} aether-seed.service`.
**JAMAIS de `faucet.key`** sur le VPS (seed uniquement).

## Firewall

- ufw actif : ALLOW IN 22/tcp + 25565/tcp (v4+v6), reste fermé.
- Hébergeur : tout inbound direct fermé ; exposition via **WebGate port
  dédié TCP → 25565** (actuel : externe `32314`).
- RPC (`9933`, bind `0.0.0.0` côté binaire) : NON exposé (ni ufw ni
  WebGate) — vérifié TIMEOUT depuis Internet.

## Endpoint public

`webgate.vps1euro.fr:<port-dédié>` → forward → `172.50.0.44:25565`
(réseau interne `webgate` du VPS). Port actuel : **32314**.
Ne jamais supposer `32314 = port Aether` : c'est le port EXTERNE
WebGate, attribué par l'hébergeur.

## Monitoring

- `scripts/watchdog_vps.ps1` (auth via `SSH_ASKPASS` d'environnement,
  jamais embarquée) : service, RPC localhost, peers, RAM/disk/load,
  logs (UNCLEAN/panic), progression sync. Exécution : Task Scheduler
  côté opérateur (non démontrable depuis un shell restreint — validé
  par revue + exécution des étapes une par une).
- Seuils : DOWN/CRITICAL immédiats, circuit breaker conservé (pas de
  restart aveugle ; systemd `Restart=always` suffit au seed).

## Logs

`/opt/aether/data/logs/node.log` (+ rotations `.1..`), format unifié,
flush immédiat. Vérifiés : banner BOOT, UNCLEAN après kill -9,
rotation active.

## Reboot / recovery

- Reboot OS : service remonté seul (validé 2×).
- Kill -9 : systemd relance <30 s, WAL recovery engagée, DAG repris.
- `systemctl stop` : SIGINT → shutdown CLEAN loggé.

## Incident response

1. `watchdog_vps` / `systemctl status` / `journalctl -u aether-seed`.
2. `ss -ltn` (listeners), `curl localhost:9933` (état DAG).
3. Logs `node.log` (UNCLEAN ? panic ?).
4. Ne JAMAIS copier `faucet.key` sur le VPS pour "tester le faucet".
5. Rollback binaire : `/opt/aether/bin/aether-unified.prev` conservé.

## Limites dures (1 vCPU / 1 Go RAM / pas de swap)

- UN seed uniquement ; builds `-j1` (~30 min) ; pas de charge dessus.
- Sync complète 10k txs : ~1,5 tx/s effectifs (bottleneck stratégie
  sync, pas machine — voir certification).
- Disque : toolchains+targets ~3 Go (one-shot) ; data ~73 Mo/8k txs.
