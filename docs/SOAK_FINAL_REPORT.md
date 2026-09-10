# SOAK FINAL REPORT — 1h (canary C2, binaire CB8B93E7)

**Fenêtre :** T0 18:25 → 19:16 (~51 min) + période pré-T0 stable depuis
reboot 18:09 => ~1 h d'observation continue. 4 h/24 h : réseau laissé
tournant, à relever.
**Réseau :** 9/9 nœuds, total 10086 figé (aucune tx générée — soak
passif après incident reboot OS ; activité : sync/entretien P2P).

## Snapshots

| # | Heure | Total | Tips | Peers | Div | RAM | Disk | Procs |
|---|---|---|---|---|---|---|---|---|
| 1 | 18:25 | 10086 | 7467 | 10 | 0 | 520 MB | 439 MB | 9 |
| 2 | 18:40 | 10086 | 7467 | 10 | 0 | 348 MB | — | 9 |
| 3 | 18:55 | 10086 | 7467 | 10 | 0 (+supply 10×8) | 345 MB | — | 9 |
| 4 | 19:16 | 10086 | 7467 | 10 | 0 | 399 MB | 477 MB | 9 |

rebuild=0, wal_recovery=0 partout, mempools vides, 0 crash, 0 restart
requis, 0 alerte watchdog bloquante.

## Convergence

- DAG + tips identiques 9/9 à chaque snapshot.
- Supply 10 adresses × 8 nœuds : 0 divergence.
- Reboot OS complet + restart 9/9 AVANT le soak : 0 divergence
  post-reboot (résilience prouvée).

## Ressources

- RAM : 520 → 348 → 345 → 399 Mo (tassement, pas de fuite).
- Disque : 439 → 477 Mo en ~1 h **dont 250 Mo de logs** (vs 102 Mo
  sled). Le volume INFO (~28 Mo/nœud/h) est excessif pour du 24/7 :
  top contributeurs = `Signature verified` (6450×), `Loaded 0 orphans`
  (2437×, loggé même à zéro), `Processing transaction` répétés,
  inventaires 10k répétés, `Faucet key loaded` périodique.
  Recommandation (hors phase) : passer le bruit en DEBUG/conditionnel.
- Rotation 10 MiB ×6 borne le risque (constaté en service).

## Incidents pendant la fenêtre

Aucun. (Le reboot OS 13:26 et le bug emoji-exit-101 sont antérieurs,
documentés dans CANARY_INCIDENTS.md.)

## Verdict soak 1h

```
🟢 SOAK 1H PASS — continuer 4 h puis 24 h
```
