# WATCHDOG AND ALERTING — Phase n°5

**Classification :** `OBSERVABILITY-ONLY` + `INFRASTRUCTURE-ONLY`
(zéro touche consensus/DAG/ledger/économie/Genesis/transactions).
**Implémentation :** `scripts/watchdog.ps1` + `scripts/watchdog_c2.json`
(aucun code Rust modifié dans cette phase).

Rôle strict : **DÉTECTER → CAPTURER → ALERTER → DOCUMENTER**.
Jamais : réparer le consensus, toucher aux balances, décider.

---

## 1. Architecture

Un passage = un sweep : pour chaque nœud configuré, dans l'ordre
process → RPC → heartbeat/stall → peers/rôle → ressources → logs,
puis convergence inter-nœuds et note réseau. État persistant
(`heartbeat.json`) pour les deltas inter-passages.

## 2. Heartbeat et états

Suivi par nœud : PID, uptime (via date de création), dernière RPC,
dernier progrès (total DAG + `sync_received`), requêtes, orphans/mempool.

| État | Signification |
|---|---|
| HEALTHY | process + RPC + pairs/ressources/logs nominaux |
| DEGRADED | RPC OK mais anomalie (peers, stall, RAM, patterns log) |
| UNRESPONSIVE | process vivant, RPC muette (hors grâce) |
| DOWN | process absent |

Seuils configurables (`thresholds` du JSON) : `rpcTimeoutSec`,
`graceSec` (boot), `stallWindowSec`, `ramWarnMB/ramCritMB`,
`diskWarnPct/diskCritPct`, `mempoolWarn`, `orphanWarn`,
`maxRestartsPerHour`, `restartCooldownSec`.

## 3. Restart policy

Défaut : **MONITOR ONLY** (constaté : aucun restart sans `-AutoRestart`).
Opt-in `-AutoRestart` : redémarre avec les args du nœud configuré,
max/heure + cooldown + **circuit breaker** (seuil atteint → plus aucun
restart, CRITICAL opérateur). Pas de boucle possible par construction.

## 4. Rôles (anti-faux-positifs)

SEED/FULL exigent des peers après grâce ; BOOTSTRAP tolère 0 peer en
sync ; ISOLATED tolère toujours 0. Nœud jeune (< grâce) : mansuétude
peers/RPC (un nœud de 25 s silencieux est indistinguable d'un boot —
vérifié manuellement, pas deviné).

## 5. Sync stall

Règle anti-faux-positif (une version naïve alertait sur nœuds sains
au repos — corrigée pendant les tests) : STALL ssi **pas de progrès
depuis le dernier passage** ET (**requêtes en croissance** OU
**orphans/mempool en attente**). Nœud synchronisé au repos : compteurs
figés, files vides → jamais alerté.

## 6. Convergence

Compare `total_transactions` (+ `tip_count`, balance faucet en
tripwires) entre nœuds. Divergence de totaux → CRITICAL, **sans aucune
tentative de réparation**. Distingue nœud en sync (progresse → pas
d'alerte) — la preuve par compteurs, pas par présomption.

## 7. Logs

Exploite `logs/node.log` (phase n°4) : `UNCLEAN` (contextualisé :
historique connu ≠ critique frais), `PANIC`/`fatal runtime` (toujours
remontés), erreurs P2P/handshake. Panne silencieuse type bind `10048`
(nœud sourd, RPC OK, 0 peers) : détectée via peers + pattern.

## 8. Alertes

Console + `watchdog-incidents.jsonl` (ID `INC-YYYYMMDD-HHMMSS-NODE`,
timestamp UTC, sévérité, nœud, événement, détail, version, genesis,
snapshot process/RPC/sync/ressources — **jamais** de secrets).
Webhook extensible via `$env:AETHER_ALERT_WEBHOOK` (Discord/Telegram
compatibles ; URL en variable d'environnement, jamais en git).
Snapshot CRITICAL : PID, uptime, peers, sync, DAG, mempool, orphans,
RAM, disque, derniers logs. Lecture seule : le snapshot ne modifie
jamais le réseau.

## 9. Sécurité

Aucun secret lu/écrit/transmis (ni clés, ni mots de passe, ni tokens ;
le webhook vit hors dépôt). Le watchdog ne se connecte qu'en localhost
+ lecture fichiers locaux.

## 10. Limites honnêtes

- Ne distingue pas un nœud gelé récent d'un boot (fenêtre de grâce).
- La divergence ledger fine (soldes) n'est couverte que via le tripwire
  faucet, pas par fingerprint complet (coût RPC).
- Pas de redémarrage distant (Windows) ni d'action P2P : que du local.
- `Get-CimInstance` peut renvoyer des fantômes : croiser avec RPC.

## 11. Troubleshooting

- `WATCHDOG CONFIG ERROR` → JSON invalide/chemin faux (exit 2).
- Exit 1 = au moins un DOWN/CRITICAL (exploitable en scheduler).
- Faux PEER_LOSS persistant + `10048` dans les logs → port squatté
  (ex. ShadowStreamer NVIDIA sur 49705 vu en test) : changer de ports.
- État incohérent après runs avortés → `heartbeat.json` périmé :
  effacer `watchdog-state/` et relancer.
