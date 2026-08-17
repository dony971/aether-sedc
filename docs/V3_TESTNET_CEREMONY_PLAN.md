# Plan de Cérémonie — Testnet V3 (préparation, NON EXÉCUTÉE)

Statut : **DOCUMENT DE PRÉPARATION** — aucune commande de cérémonie ne doit
être exécutée sans validation produit de la décision de spécification
(`RAPPORT_FINAL_TECHNIQUE.md` §7.4 — OPTION A recommandée) et validation
opérateur. L'exécution réelle du v2 a eu lieu le 2026-08-16
(`CEREMONIE_GENESIS.md`, `RAPPORT_CEREMONIE_GENESIS.md`) ; ce plan adapte le
même protocole au passage **P2P v2 → v3**.

---

## 1. Pourquoi une nouvelle cérémonie

1. `P2P_PROTOCOL_VERSION` 2 → 3 (implémentation du poids, décision O.1) :
   les nœuds v2 et v3 ne se connectent pas (check `frame[4]`, p2p.rs).
2. **Il n'existe AUCUN `network_id` dans le code** : l'identité du réseau est
   (version P2P + hachages genesis + `GENESIS_MESSAGE`). La séparation des
   réseaux se fait donc par la version + un nouveau genesis.
3. Le faucet v2 est inutilisable (faucet.key supprimé, seed connu des anciens
   artefacts — clé `fa5979…` compromise).
4. Le format de stockage (bincode, dépend de l'ordre des champs de
   `Transaction`) est inchangé en v3 (aucun nouveau champ dans `Transaction`) —
   mais la purge totale reste obligatoire : les data-dirs v2 portent des txs
   sans poids correctement maintenu (prune v2) et un genesis différent.

## 2. Prérequis (bloquants avant exécution)

- [ ] Décision produit : OPTION A ratifiée (whitepaper v2 honnête) ou autre
      voie arbitrée — voir §7.4 du rapport final.
- [ ] Audit externe des primitives cryptographiques (Ed25519, BLAKE3, PoW) et
      de la résolution de conflit min-id — recommandé avant ouverture publique.
- [ ] Traitement documenté de `RUSTSEC-2026-0221` (event-listener 5.4.1,
      transitif) : mise à jour ou dérogation écrite.
- [ ] Candidats des 3 paires de clés (founder, faucet, faucet_seed) générés
      SUR MACHINE HORS LIGNE, jamais dans le dépôt.
- [ ] Env vars harnais à jour : `AETHER_FOUNDER`, `AETHER_FAUCET`,
      `AETHER_FAUCET_SEED`.

## 3. Checklist d'exécution (à exécuter seulement après validation)

1. **Purge** : supprimer les anciennes clés (`fa5979…`), wallets, data-dirs,
   smokes, logs, artefacts v2 — vérifier `0 ligne` sur les greps de la §1.1 de
   `CEREMONIE_GENESIS.md` (adaptés : `fa5979`, `32252d`, `e880`).
2. **Génération hors ligne** des clés (mêmes commandes que `CEREMONIE_GENESIS.md`
   §2.1).
3. **Rotation du code** : `src/genesis.rs` — nouvelles adresses founder/faucet,
   nouveau `GENESIS_MESSAGE` horodaté (atteste la date du lancement v3) ;
   supprimer toute trace de l'ancien message.
4. **Params v3 inchangés** (aucun ajustement en v3) : difficulté 20, min_fee 1,
   seuils Confirmed ≥ 3 / Stable ≥ 5.0, MAX_ORPHANS 50 000, faucet 10 AETH/60 s.
   Si la décision produit ajoute du stake/énergie : c'est un CHANGEMENT DE
   PROTOCOLE → nouvelle version P2P et nouvelle cérémonie, PAS une retouche
   de cette liste.
5. **Construction** : `cargo clean` (toolchain GNU — `C:\msys64\ucrt64\bin`
   sur PATH), build release, `cargo test --lib` (attendu : 149 PASS / 0 FAIL /
   1 ignoré), `cargo fmt --check`, clippy = 43 warnings pré-existants,
   `cargo audit` vert (ou dérogations).
6. **Vérifications automatiques** : scripts `verify_genesis` de
   `CEREMONIE_GENESIS.md` §4 (network_id/supply/fingerprint) — attendu :
   supply `1e18 + 1e11`, `P2P_PROTOCOL_VERSION = 3`, fingerprint nouveau.
7. **Hash attendus** : documenter le hash du nouveau genesis et le fingerprint
   réseau (sha256 des artefacts) dans le compte-rendu public — générés pendant
   la cérémonie, PAS anticipés ici.
8. **Checksums** : archives des binaires + sources, signées.
9. **Lancement seed nodes** (≥ 3), puis **harnais S1-S10 complet** sur le
   nouveau genesis : 28 assertions × N runs, 100 % PASS, empreintes (dont
   `h_weights`) identiques.
10. **Rotation faucet** : placer le nouveau `faucet.key` dans les data-dirs des
    nœuds à faucet ; vérifier qu'un nœud avec l'ANCIENNE clé (ou sans clé)
    désactive le faucet en log.

## 4. Vérifications post-ouverture

- `aether_getDagStats` / statuts : Confirmed ≥ 3 refs, Stable ≥ 5.0 atteints
  organiquement (échelle v3).
- Convergence `h_weights` sur tous les nœuds (harnais).
- Absence de toute référence « Heavy Subgraph », « stake-secured »,
  « energy-weighted » dans la communication publique (décision §7.4).

## 5. Artefacts à produire le jour J

- `genesis-ceremony-v3/` signé : clés (HORS DÉPÔT, coffre), genesis.json,
  fingerprint, checksums, compte-rendu (`RAPPORT_CEREMONIE_V3.md` à créer),
  logs harnais.

## 6. Non-périmètre de ce plan

- La réécriture du whitepaper v2 (suit la décision §7.4).
- L'implémentation du stake/énergie (proposition séparée si demandée).
- L'audit crypto externe (bloquant pré-ouverture, hors cérémonie).