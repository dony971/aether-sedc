# WALLET ROTATION REPORT — AA9F → CB8B93E7 (PRÉPARATION, NON EXÉCUTÉE)

**Statut :** HOLD maintenu. Rien n'a été remplacé ; le soak tourne
toujours sur l'image `AA9F` en mémoire. Ce document + la procédure
`docs/WALLET_ROTATION_AA9F_CB8B93E7.md` permettent la rotation en
fenêtre contrôlée.

## Compatibilité vérifiée (sur COPIES, jamais le wallet opérateur)

| Sens | Moyen | Résultat |
|---|---|---|
| Fichier AA9F → binaire CB | `balance --password` + RPC | adresse + balance OK |
| Fichier CB → binaire AA9F | `balance --password` + RPC | adresse + balance 0 OK |
| Fichier CB → Python | `decrypt_v2` | pubkey + mnemonic OK |
| Fichier AA9F → Python | (couvert phase toolchain 5/5) | OK |
| Nonce/historique/signature | mêmes formats, mêmes chemins de code | OK (E2E) |

Aucune migration de format requise (v2 inchangé des deux côtés).

## Rollback

Ancien binaire conservé hors PATH jusqu'à validation live du nouveau
(`aether-legacy-*.bak` + copies) ; procédure §6 du doc de rotation :
stop → restaurer → start → convergence → E2E ; jamais de suppression
avant validation.

## Risques restants

- `to_file` atomique Rust non encore exercé en production (couvert par
  tests 11/11 + roundtrips ; premier usage réel à la rotation).
- Logs node 28 Mo/h/nœud : dimensionner le disque avant 24 h
  (rotation borne à 60 Mo/nœud — suffisant).
- Réseau sans `network_id` : la rotation ne change rien à ce point
  (limitation connue, pas une régression).

## Verdict

```
🟡 ROTATION HOLD — package prêt, fenêtre à planifier
```
