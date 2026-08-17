# Avis Public — Testnet Aether v3

**À lire avant toute utilisation ou communication.** Version : protocole P2P 3,
2026-08-17. Ce réseau est un **testnet expérimental**.

---

## Déclaration publique

1. **Aether v3 est expérimental.** Il est fourni pour l'étude et le test, sans
   aucune garantie de disponibilité, de continuité ou d'intégrité.

2. **Le protocole est exactement le consensus actuellement implémenté.** La
   référence normative est `docs/PROTOCOL_SPECIFICATION.md` ; le whitepaper
   (`docs/WHITEPAPER_V2.md`) la reflète. Aucun document antérieur ne décrit le
   réseau actuel.

3. **Le poids est structurel.** Le poids d'une transaction = taille de son
   sous-arbre dans le DAG. Il est dérivé de la structure, maintenu par le
   nœud, et n'engage aucun actif.

4. **Aucun consensus par stake ou énergie n'est utilisé.** Le protocole v3 ne
   comporte ni stake, ni énergie, ni réputation comme input du consensus. La
   résolution des conflits est la règle déterministe min-id. Les documents
   évoquant un consensus pondéré par stake/énergie sont des recherches futures,
   pas une description du réseau.

5. **Certaines propriétés de sécurité restent à démontrer.** En particulier,
   la résistance aux attaques Sybil et la robustesse économique ne sont pas
   établies. Limitation connue (W11, démontrée par test) : un poids `Stable`
   (seuil 5.0) peut être atteint avec environ cinq transactions, pour un coût
   de quelques unités et quelques millions de hachages. Le statut `Stable`
   n'implique donc aucune sécurité économique.

6. **Le testnet n'a aucune valeur économique garantie.** L'émission est nulle
   après le genesis ; les fonds du faucet sont des jetons de test. Rien sur ce
   réseau ne doit être traité comme un actif de valeur.

7. **Aucun audit externe n'a encore été effectué** sur les primitives
   cryptographiques, le P2P ou le protocole de consensus.

## Ce que les opérateurs et utilisateurs doivent savoir

- La finalité (`Stable`) est **relative** : un conflit min-id plus petit peut
  pruner un sous-arbre même `Stable`.
- Le réseau peut être **purge/réinitialisé** à tout moment par une cérémonie
  genesis (aucun engagement de pérennité).
- Les données, wallets et clés de ce testnet sont jetables ; ne pas y déposer
  d'information sensible ou de valeur.

## Interdits de communication

- « stake-secured », « energy-weighted », « Heavy Subgraph stake consensus »,
  « Sybil-resistant », « finalité cryptographique » — toute formulation
  laissant entendre une sécurité supérieure aux preuves disponibles.

## Références

- Spécification normative : `docs/PROTOCOL_SPECIFICATION.md`
- Whitepaper v2 : `docs/WHITEPAPER_V2.md`
- Menaces : `docs/THREAT_MODEL.md` (T1 SÉVÈRE : inflation de poids)
- Proposition stake/énergie (NON NORMATIF) : `docs/FUTURE_STAKE_ENERGY_PROPOSAL.md`
- Rapport technique et verdicts : `docs/RAPPORT_FINAL_TECHNIQUE.md`