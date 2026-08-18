# PHASE C — RAPPORT FINAL — Canary testnet contrôlé Aether V3 (RC B4)

Date : 2026-08-18 · Durée de la phase active : ~06:00 → 07:20 (tests de
charge et bootstrap) ; observation continue depuis la campagne B4 (réseau
8 nœuds actif depuis 08-17 22:20).

RC : `24c61e3` (SHA256 `8F04BB27AED4FD11FC76F839DCADC58DF8B1AF97EE13DB0B9FB620D9C5587FF`) ·
version 1.2.0 · gel `b1b8376` (historique) · **RC non modifiée durant la phase** ·
réseau : 10 nœuds convergés à 1100 tx · preuves conservées dans
`%TEMP%\opencode\aether-canary-b4\`.

## Verdict

| Phase | Résultat |
|---|---|
| PHASE A (AUTHENTICITÉ + GENÈSE) | **PASS** |
| PHASE B (CANARY CŒUR) | **PASS** |
| PHASE C (TESTNET CONTRÔLÉ) | **FAIL** — capacité limitée par le plafond du mempool (1000) |

**VERDICT : 🔴 STOP — nouvelle RC requise.**

Motif : critère d'arrêt §10 déclenché (**bootstrap bloqué** au-delà de
~1000 tx, reproduit) et objectifs de charge §5 (2500/5000/10000) et joins
critiques §6 inatteignables. Le réseau lui-même est sain (0 divergence,
0 perte, 0 crash) jusqu'à sa limite de capacité. Aucune publication
automatique ; la décision opérateur est requise.

---

## 1. Porte de release — PASS

- `cargo test --lib` : **154 PASS / 0 FAIL / 1 ignoré** (S11 documenté).
- `cargo fmt --check` : EXIT 0. `cargo audit` : 0 vulnérabilité (7
  avertissements autorisés, baseline — ex. `ttf-parser` non maintenue).
- SHA256 binaire `aether-unified.exe` : `8F04BB27…` (vérifié, conforme RC).
- Genèse : hash fichier `4F3E693EE56A224DEC556F1C05A7C2F4383B2BA8334368AE5D25BA48991D9F8F`
  (vérifié) ; hash de poignée de main `[0;32]` (src/genesis.rs) ; `network_id`
  `59a4fc92…` (RELEASE_CANDIDATE.md §1) ; identité P2P : magic `AETH`, version 3.
- HEAD pendant les tests : `1262475` (docs Phase C) ; exécutable RC B4 immuable.
- Paquetage : artefacts Rust standard dans `target-b4\release`
  (`aether-unified.exe` 17 660 638 octets, etc.).
- **Scan de secrets : PASS** — aucune clé privée, aucun seed, aucun
  `canary-pass-2026` dans le dépôt ni dans les logs de campagne ; les seules
  occurrences sont des adresses publiques (`a19ee0…`, `2ffab7…`) dans
  docs/scripts/genesis.json. Faucet : `faucet.key` jamais distribué.

## 2. Porte réseau — PASS (avec constat)

- Pare-feu : profils Domain/Private/Public **actifs** ; NTP : stratum 3,
  `pool.ntp.org`, dernière sync 04:44:34 — **PASS**.
- Ports documentés : P2P `42001…55001` (nœuds 1-14), RPC `42101…55101` ;
  RPC non exposé inutilement ? **CONSTAT** : le RPC se lie sur `0.0.0.0`
  (src/node.rs:622) — exposition documentée, atténuation recommandée (règle
  de pare-feu entrante ; shell non élevé, règle non ajoutée). Aucun secret
  dans les logs de nœuds.
- Test machine externe : le scanner `103.102.135.123:25565` a été rejeté
  (`Incompatible P2P protocol version`) — la porte P2P v3 fonctionne.

## 3. Testeurs (ajout progressif) — PASS

10 nœuds : 8 nœuds campagne (ports 42001-49001) + testeurs nœuds 9-10
(50001/51001). Vérification par nœud : SHA binaire RC (`8F04BB27…`),
version 1.2.0, genèse/identité (magic AETH + P2P v3 + hash genèse),
dossiers de données frais, empreinte de session cohérente
(`df2c017ccf98` après stabilisation), pairs (jusqu'à 11 sur le nœud 1),
convergence (tous à 1100 tx au 2026-08-18 07:19). **Aucune clé privée
distribuée** — les wallets de test restent locaux à la machine.

## 4. Tests utilisateurs — PASS (avec substitution documentée)

Wallet, réception d'AETH, envoi, PoW 20, balance, DAG, redémarrage,
resynchronisation (1,8 s), multi-clients (CLI + RPC simultanés) : **PASS**
(05:48-05:54). Le test faucet est **substitué** : faucet bloqué au-delà de
~1000 tx (INC-02) → envois depuis 12 portefeuilles préfinancés (balance
récepteur vérifiée : `99999994183` brut). Le faucet fonctionne au démarrage
à froid (testé 05:03).

## 5. Charge progressive — 100/500/1000 PASS · 2500/5000/10000 **BLOQUÉ**

| Palier | Résultat |
|---|---|
| 100 / 500 / 1000 | **PASS** (campagne B4 : batteries B1-B8, deltas exacts 10/50/100, 0 rejet) |
| 1100 (preuve) | Ramp 86 tx / 63 s à frais 300, 11 vagues, 8 générateurs parallèles — **PASS** (réseau 10 nœuds convergés) |
| 2500 / 5000 / 10000 | **INATTEIGNABLE** — le plafond du mempool (1000, jamais drainé) bloque l'entrée des transactions à frais uniformes ; la croissance n'est possible que par enchère de frais (100→200→300→500 observée, INC-03). Mesures de charge au palier atteint : 1100 tx, volume ~1,1e5 brut de frais brûlés, ramp ~1,4 tx/s (PoW 20 ~0,18 s, latence RPC < 50 ms, CPU/RAM stables — 10 nœuds locaux). |

## 6. Nouveau nœud (test critique) — 500/1000 PASS · **>1000 FAIL**

| Join | Résultat |
|---|---|
| @463 (B4-1) | PASS en 123 s — must-pass |
| @500 (B4-2) | PASS en 107 s — purged=0 |
| @1000 (B4-3) | PASS en 268 s — purged=0 (cas limite = plafond) |
| @1100 (Phase C) | **FAIL — bootstrap bloqué** à 1012/1100 (INC-04) : livelock Orphan Solver, `Mempool full` en boucle, purges d'orphelins (173), 42 min sans convergence, stats : `requested=2827 received=1566 progress=9 batches=9716 | orphans 1379/1003/173 | dup_ignored=8797`. Les hachages finaux (h_txset/h_dag/h_tips/h_ledger/h_weights) ne peuvent pas être atteints. |

## 7. Longue durée — observation en cours, 0 divergence

Réseau 8 nœuds actif depuis 08-17 22:20, campagnes B4 et Phase C incluses.
Surveillance : divergence = 0, aucune perte (y compris après le
redémarrage machine INC-01), pas de fuite mémoire/disque anormale, pas de
crash, faucet/monitoring stables, sync propre (purged=0 sur tous les joins
≤1000). Rapports périodiques : CANARY_REPORT.md B4.4-B4.7, présent document.

## 8. W11/T1 — **SÉVÈRE, non résolu** (par conception, conforme au mandat)

Aucune revendication de résolution. La manipulation de poids reste
théoriquement explorable (surface : DAG weights, arbre de finalité) ; VQV a
été retiré (nœuds = full nodes) et aucune attaque de poids n'a été tentée
ou observée pendant la phase. L'audit cryptographique externe reste requis
(critère de sortie §11).

## 9. Incidents — voir `docs/PHASE_C_INCIDENTS.md`

INC-01 redémarrage machine (résolu, 0 perte) · INC-02 faucet bloqué à
l'échelle (documenté) · INC-03 mempool saturée, plafond 1000 (documenté,
reproduit) · INC-04 **bootstrap bloqué >1000** (reproduit — STOP) ·
INC-05 empreinte transitoire (résolu) · INC-06 scanner externe (bénin).
Aucune preuve supprimée ; logs conservés.

## 10. Critères d'arrêt — **DÉCLENCHÉ**

- **Bootstrap bloqué** : INC-04 (join @1100, 42 min, livelock) ✔
- Non déclenchés : divergence, perte de tx, incohérence ledger/offre,
  double-dépense non déterministe, corruption, fuite de secret, crash
  critique, vulnérabilité critique, ressources anormales (tous vérifiés :
  rien).

## 11. Critères de sortie — NON SATISFAITS

PASS : A (authenticité/genèse), B (canary cœur), stabilité du réseau,
convergence, monitoring, pare-feu, NTP, absence de secrets, docs
(RELEASE_CANDIDATE.md, CANARY_REPORT.md, présent rapport, registre
d'incidents). ÉCHEC : charge 2500+, joins à 2500+, faucet à l'échelle.
Audit cryptographique externe : toujours requis (non réalisé).

## 12. Synthèse des données de la phase

| Mesure | Valeur |
|---|---|
| Durée phase active | 06:00 → 07:20 (tests) ; réseau actif depuis 08-17 22:20 |
| Nœuds | 10 actifs (8 + 2 testeurs), 3 joiners de test (11/12/13 lancés, 14 bloqué) |
| Transactions | 1100 (dont ramp 86) ; volume : frais brûlés ~1,1e5 brut |
| Performance | ramp ~1,4 tx/s ; PoW 20 ~0,18 s ; bootstrap ≤1000 : 107-268 s ; resync 1,8 s |
| Bootstrap | ≤1000 : PASS (purged=0) · >1000 : **BLOQUÉ** |
| Incidents / divergences | 6 incidents (1 critique) · 0 divergence |
| W11/T1 | SÉVÈRE (non résolu) |
| Ressources | CPU/RAM/Disque stables (10 nœuds locaux, 0 fuite observée) |
| Faucet | OK à froid, bloqué ≥ ~1000 tx (INC-02) |
| Monitoring / réseau | 0 divergence, pare-feu actif, NTP OK, RPC `0.0.0.0` (constat) |

---

## Recommandation

Nouvelle RC : drain/rotation du mempool (relay window avec expiration, ou
éviction du plus ancien indépendamment des frais) — à concevoir sans
changer le consensus (le mempool n'est pas un état de consensus ; la DAG
reste la seule source de vérité). Après correction : rejouer §5/§6
(charges 2500/5000/10000 et joins critiques), puis re-évaluer
🟡/🟢. Décision opérateur requise avant toute publication.