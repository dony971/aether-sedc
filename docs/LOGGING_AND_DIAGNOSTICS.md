# LOGGING AND DIAGNOSTICS — Milestone n°4

**Statut :** `OBSERVABILITY-ONLY` — aucun consensus / DAG / ledger /
règles économiques / Genesis modifié. Seul un second sink `tracing` +
un module neuf, un `build.rs`, des logs de boot et des tests.
**Branche :** `canary-c2-fixes` (au-delà de `f8a435f`).

---

## 1. Emplacement

| Composant | Fichier | Rotation |
|---|---|---|
| Nœud Rust | `<data_dir>/logs/node.log` (+ `node.log.1..5`) | 10 MiB, 5 fichiers |
| Wallet Python | `%APPDATA%/Aether/app.log` (+ `.1..3`) | 2 MiB, 3 fichiers |
| Audit wallet | `%APPDATA%/Aether/audit.log` | propre rotation existante |

Le fichier survit au redémarrage (append) ; le répertoire est créé au boot.

## 2. Format (unique, §10)

```text
2026-09-09T11:45:15Z | node1 | INFO | aether_unified::node | message…
2026-09-09T12:27:28Z | wallet | INFO | core.rc | message…
```

`timestamp UTC | node | level | component | event…` — timestamp ISO8601
Zulu sans dépendance (algo civil maison, testé), node = nom du data-dir
(`node1`…) ou `wallet` / `cli`, component = cible `tracing` / logger
Python. Même système partout ; seul le legacy `aether` (binaire GUI
historique, non distribué) reste stdout-only (documenté).

## 3. Niveaux

INFO global (stdout + fichier), identique au comportement précédent
(`with_max_level(INFO)` conservé des deux côtés). Pas de DEBUG en
production (volume).

## 4. Rotation et persistance (§4–§5)

- Seuil 10 MiB nœud / 2 MiB wallet ; renommage atomique
  (`node.log` → `.1` → … → `.5`, le plus vieux supprimé).
- **Flush immédiat par ligne** (pas de buffer utilisateur) : un
  `Kill-Hard` ne perd rien d'écrit ; seul un crash machine peut rogner
  la queue (énoncé honnêtement).
- Événements critiques couverts : boot/banner, config, rebuild, WAL
  recovery, orphans (created/resolved/purged), mempool, accept/reject,
  sync progress, peers connect/disconnect, handshake, erreurs RPC/P2P,
  shutdown marker (chemin Ctrl+C).

## 5. Banner de boot (§2, §6)

```text
BOOT aether v1.2.0 commit=<short>[-dirty] genesis_hash=… p2p_v3
  max_supply=… pid=… data_dir=…
🆕 first boot | 🧹 previous shutdown was CLEAN | ⚠️ previous shutdown UNCLEAN
```

- `commit` injecté par `build.rs` (`git rev-parse --short HEAD` + suffixe
  `-dirty` si l'arbre diffère — jamais de fausse attribution).
- Honnêteté crash (exigée) : un processus mort ne loggue pas sa mort.
  Convention : boot N+1 **sans** marqueur après boot N = arrêt inattendu
  (kill/crash/coupure). La cause OS exacte n'est **pas** prétendue.
  Sur Windows, `Stop-Process`/terminate ne délivre jamais Ctrl+C :
  UNCLEAN y est **par design** (documenté, pas un bug).
- Amélioration VPS : `KillSignal=SIGINT` dans l'unité systemd pour que
  `systemctl stop` produise un marqueur CLEAN.

## 6. Sécurité (§3)

- Aucun call site ne formate password/mnémonique/clé/PIN/clé faucet
  (audité par grep : seules des invites « Password required » sans valeur).
- Mentions du NOM de fichier `faucet.key` dans 2 lignes opérationnelles
  (`key loaded from <path>`, `disabled: no faucet.key at <path>`) :
  bénignes (chemin, jamais le contenu), revues une par une.
- Le mnémonique affiché par `wallet create` reste une sortie CLI
  intentionnelle, jamais redirigée vers un fichier de log.
- `scan_for_secrets()` (`src/node_logging.rs`) : motifs `password=`/`mnemonic:`/
  `secret_key`/`private_key`/`faucet.key`/`pin=`… ; testé (vrai positifs
  synthétiques + vrais négatifs), appliqué aux 24 fichiers de logs des
  tests opérationnels : **0 fuite de matière, 64 mentions bénignes revues**.

## 7. Diagnostic crash (§6)

Ce qu'un log permet d'affirmer après Kill-Hard + restart (LOG-CRASH-01) :
quel nœud (tag), quand (timestamps), verdict UNCLEAN, rebuild visible,
second banner avec nouveau PID, convergence RPC. Ce qui reste
impossible : la cause OS exacte (assumée, pas devinée).

## 8. Monitoring (§11, préparation n°5)

Les événements nécessaires au futur watchdog sont tous présents et
 requêtables : processus absent (pas de lignes récentes), sync bloquée
(`sync_requested` sans `sync_received`), peers anormaux
(`connected_peers`, lignes disconnect), crash (banner sans marqueur),
RPC indisponible (sonde HTTP existante). Rien d'autre développé.

## 9. Preuves d'exécution

| Test | Résultat |
|---|---|
| unitaires `node_logging` (format, rotation, scanner, heuristique) | 5/5 |
| LOG-CRASH-01 (3 nœuds, kill-hard node2, diagnostic par logs) | ALL PASS |
| LOG-SYNC-03 + LOG-P2P-04 (bootstrap, handshake, kill/reconnect seed) | ALL PASS |
| LOG-MINI9 (9 nœuds + 64 tx + restart + crash + resync, 8 questions) | ALL PASS, 9/9 convergés |
| secrets scan 24 fichiers réels | 0 fuite |
| wallet `app.log` nouveau format | vérifié (prochain run GUI) |

Exemple réel (`log-mini9/node3`, après kill) :
```text
... | node3 | WARN | aether_unified | previous shutdown UNCLEAN (no shutdown marker) — possible crash/kill
... | node3 | INFO | aether_unified | BOOT aether v1.2.0 commit=… p2p_v3 …
```

## 10. Conservation

Nœud : 60 MiB max (6×10). Wallet : 6 MiB (3×2). Pas de rotation
temporelle (les incidents se relisent par sections BOOT→…→shutdown).
Au-delà : écrasement du plus vieux, jamais du live.
