# VPS BOOTNODE CERTIFICATION — VPS-100333

**Verdict :** 🟠 VPS NON CERTIFIÉ (bloqué par UN point : bootstrap
d'historique profonde trop lent — voir VPS-03). Le reste valide.
**Protocole :** GELÉ, aucune modification pour cette campagne.

## 1. Infrastructure

Ubuntu 24.04 x86_64, 1 vCPU/1 Go/20 Go (9,4G libres), horloge skew 0 s,
uptime suivi. Service systemd user `aether`, auto-start validé (2
reboots), `KillSignal=SIGINT`, `Restart=always`.

## 2. Version (règle §20 — exacte)

- Binaire : build natif du commit `canary-c2-fixes` courant (P1→P3 +
  topo/cache + faucet serial + logging + rpc-bind), SHA
  `61fc7551857c9dfc2cae50d0c252e699995bb01fa14502d8add3f0bb73a18621`,
  ancien conservé en `.prev`. `--version` affiche `1.1.1` (chaîne
  cosmétique périmée — identité par SHA, documenté).
- Genesis : faucet 1e18 identique au canary. P2P v3. network_id :
  INEXISTANT (limitation connue, ségrégation par bootnodes).

## 3. Endpoint / sécurité

- Public : `webgate.vps1euro.fr:32314` → `172.50.0.44:25565` (prouvé :
  peering + handshake + sync à travers).
- Direct `.123:25565` : fermé (hébergeur). RPC `:9933` : TIMEOUT Internet.
- ufw : 22+25565 seuls. Pas de faucet.key, pas de clé cérémonie/founder,
  pas de secret wallet sur la machine (noms vérifiés, contenus jamais).

## 4. Tests VPS-01..10

| ID | Test | Résultat |
|---|---|---|
| VPS-01 | connectivité TCP externe | PASS (`webgate:32314` joignable) |
| VPS-02 | handshake+genesis (nœud vierge, bootnode=VPS) | PASS (1 peer bilatéral, faucet 1e18 des deux côtés) |
| VPS-03 | bootstrap historique 10k via VPS | **FAIL** : 8 tx/40 min (serveur sain, clients affamés — voir §6) |
| VPS-04 | restart (service) | PASS (actif, listener, peers de retour) |
| VPS-05 | crash dur (kill -9) | PASS (systemd <30 s, WAL recovery, UNCLEAN loggé) |
| VPS-06 | VPS indisponible | PASS (canary 8/8 @10120 autonome ; join local OK ; **SPOF bootstrap prouvé** : nœud VPS-only = 0/0) |
| VPS-07 | nœud externe via VPS | PASS (mécanisme : handshake/sync démarrent ; rejoint l'état VPS) |
| VPS-08 | store/GetData | PARTIEL : compteurs P2 inédits utilisés (advertised/skipped/items) — pas de divergence ; re-requêtes bornées (backoff) |
| VPS-09 | watchdog | PASS par construction revue + étapes unitaires (exécution schedulée impossible à démontrer depuis shell restreint — honnête) |
| VPS-10 | logging | PASS (persistants, rotation `.1..4`, UNCLEAN après kill, 0 secret) |

Répétitions : restart ×2, crash ×1, bootstrap ×3 (ext-node, vpsoff-node,
recovery) — scénarios critiques couverts ≥3 démarrages au total.

## 5. Bootstrap réaliste (§10)

Latence WAN réelle, 10-12 peers, reconnexions, restart client :
peering <2 min, handshake OK, premières tx OK, puis débit ~1,5 tx/s
effectifs sur historique profonde. Mesures : requested 179k,
received 19k, orphans 9,4k/6 résolus, re-requêtes 110k, dup 117k.

## 6. Cause racine VPS-03 (mesurée, pas supposée)

Requêtes en sous-ensembles aléatoires (1000/inventaire) + résolution
uniquement par DAG-parents-déjà-insérés = marche aléatoire sans
amorçage topologique : seules les chaînes genesis-ancrées complètes
arrivées par chance s'insèrent (~8/40 min ici). Contrôle : même
binaire en loopback local synchronise ~1000/5 min. Le transport
(WebGate) est EXONÉRÉ (peering/handshake/petits-syncs OK) ; la
stratégie de requêtes est en cause. Correctif = fetching
ancestor-closed (branche suivante, design à valider, jamais de contournement).

## 7. Performance / limites (§14)

1 CPU saturé en sync (normal), ~200 Mo/1 Go, data 73 Mo/8k txs,
bootstrap ~1,5 tx/s effectifs WAN (insuffisant testnet), LAN ~40× plus
vite (contrôle). Ne pas compenser par protocole : corriger la stratégie.

## 8. Résilience (§15)

A reboot PASS, B crash PASS, C peer-loss PASS, D reconnect PASS,
E nouveau node PASS (mécanisme), F node pendant VPS OFF PASS (0/0
documenté = SPOF), G recovery PASS (1 peer + reprise).

## 9. SPOF

VPS = SPOF **de bootstrap uniquement** pour nœuds qui ne le connaissent
que lui (prouvé 0/0). PAS un SPOF consensus (réseau autonome 8/8 sans
lui). Mitigation prévue : multi-bootnodes (§17 : VPS + seed opérateur
+ futur opérateur — configuration supportée, nœuds non créés).

## 10. Risques restants

1. Bootstrap profonde inutilisable en l'état (bloquant testnet).
2. Pas de `network_id` (fusion accidentelle possible entre réseaux
   même-genesis — discipline bootnodes en attendant).
3. Mot de passe root initial transmis en clair : **à changer d'urgence**.
4. Chaîne `--version` cosmétique fausse (`1.1.1`).
5. Cachet PEX : adresses loopback apprises via PEX ont connecté un
   nœud de test au canary local (observation : à durcir un jour —
   filtrage d'annonces non routables).
