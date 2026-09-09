# WATCHDOG REPORT — Phase n°5

**Verdict :** 🟢 WATCHDOG = PASS → 🟡 CANARY OPÉRATIONNELLEMENT RENFORCÉ
**Classification :** OBSERVABILITY-ONLY / INFRASTRUCTURE-ONLY (0 Rust modifié).

---

## 1. Architecture livrée

`scripts/watchdog.ps1` (~300 lignes) + `scripts/watchdog_c2.json` :
sweep process→RPC→heartbeat/stall→peers/rôle→ressources→logs→convergence→note
réseau ; incidents JSONL avec ID ; snapshots lecture seule ; webhook
optionnel par env ; exit 0/1/2 pour schedulers.

## 2. Tests WATCH-01 à WATCH-10

| Test | Résultat |
|---|---|
| WATCH-01 crash process (DOWN, incident, pas de restart en monitor) | PASS |
| WATCH-02 RPC muette, process vivant (suspend NtSuspendProcess) | PASS (après correction du test : grâce boot respectée) |
| WATCH-03 sync stall (joiner orphelin, 2 passages) | PASS (après correction règle + test : requêtes croissantes ou files en attente exigées) |
| WATCH-04 perte peers (kill seed → PEER_LOSS → recovery) | PASS |
| WATCH-05/06 seuils disque/RAM (seuils synthétiques bas) | PASS |
| WATCH-07 divergence (2 groupes isolés, DAG + faucet) | PASS, mention "no auto-repair" présente |
| WATCH-08 restart loop → circuit breaker (2/h puis stop) | PASS (preuve au journal : 1/2, 2/2, BREAKER) |
| WATCH-09 clean shutdown | PARTIEL : chemin Ctrl+C/SIGINT non déclenchable headless Windows ; heuristique couverte par tests unitaires n°4 + `KillSignal=SIGINT` côté VPS. Marqueur vérifié en lecture (banner suivant) |
| WATCH-10 unclean shutdown | PASS (UNCLEAN remonté + diagnostic complet par logs) |
| Négatifs (frais, isolé, vide, calme) | PASS, 0 faux positif |
| §16 auto-restart (crash→restart→recovery→convergence) | PASS (73 vs 73) |
| §17 9 nœuds (1 crash isolé vs double kill = NETWORK EVENT) | PASS, 9/9 reconvergés |
| §18 perf | sweep ~2 s, RAM négligeable (vs ~35 Mo/nœud) |

## 3. Faux positifs trouvés ET corrigés pendant les tests

1. **Règle stall naïve** alertait sur nœuds sains au repos (compteurs
   cumulés > 0) → redéfinie sur deltas + files d'attente.
2. **Grâce boot trop longue vs rythme des tests** masquait WATCH-02 →
   config de test à 15 s + garde documentée (comportement watchdog correct).
3. **Strays inter-runs** (ports partagés) → pre-flight ports + kill avec
   attente + dirs conservées en cas d'échec.

## 4. Découvertes réelles (non masquées)

1. **Port 49705 squatté par ShadowStreamer (NVIDIA)** : nœuds sourds
   (bind 10048, RPC OK, 0 peers) — diagnostiqué précisément grâce aux
   logs n°4 + watchdog. Piste produit : fail-fast au bind au lieu de
   servir sourd (hors phase, noté).
2. **`ConvertFrom-Json -AsHashtable` n'existe PAS sous PS 5.1** : l'état
   (stall, breaker) ne persistait jamais (catch silencieux). Corrigé par
   projection manuelle. Sans ce fix, WATCH-03/08 échouaient à raison.
3. **Stop-Process est fire-and-forget** : tout kill de test doit attendre
   la mort (sinon bindrace). Idem pour un futur auto-restart robuste.
4. `$pid` est en lecture seule en PowerShell (piège répété, corrigé
   partout + à retenir pour les futurs scripts).

## 5. Ressources / sécurité / limites

- Sweep ~2 s, un seul processus PowerShell éphémère, 0 démon résident.
- Incidents : `watchdog-incidents.jsonl` (IDs `INC-…`, snapshots, 0 secret).
- Limites : §10 du doc (grâce, tripwire faucet, local-only, CIM fantômes).

## 6. Régression (§20)

- `cargo fmt --check` PASS, `cargo clippy` PASS (0 Rust modifié : inchangé),
  `cargo audit` : 1 faille connue acceptée, 0 nouvelle.
- `cargo test --lib` : 179/179 (inchangé, relancé : voir ci-dessous).
- Wallet 35/35 (helpers format log), tests watchdog P1+P2+P3 verts,
  mini-canary 9 nœuds vert (déjà couvert phase n°4, non régressé).
