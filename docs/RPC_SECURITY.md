# RPC SECURITY — Phase n°7 (INFRASTRUCTURE / SECURITY HARDENING)

**Classification :** pas un changement protocole (consensus/DAG/ledger/
économie/Genesis intouchés). Seuls le bind du serveur RPC, un flag CLI,
un champ config et des logs changent.

---

## 1. Bind par défaut : loopback

- `NodeConfig.rpc_bind` défaut = `127.0.0.1` ; flag `--rpc-bind` idem.
- Anciens fichiers TOML sans le champ : parsés via `serde(default)` →
  loopback (testé).
- Auncun fallback silencieux vers `0.0.0.0` : seule une valeur explicite
  non-loopback expose (CLI ou TOML).

## 2. Exposition volontaire

`--rpc-bind 0.0.0.0` (ou TOML) + log systématique :

```text
WARNING RPC exposed on non-loopback address 0.0.0.0 — anyone who can
reach it can query balances, request faucet funds (if enabled) and
submit transactions. Bind 127.0.0.1 unless you operate a firewall.
```

Vérifié en live : la ligne apparaît, l'IP LAN sert.

## 3. Firewall

| Cas | Recommandation |
|---|---|
| RPC local (défaut) | rien à faire (loopback non routable) |
| RPC LAN (explicite) | firewall hôte : n'autoriser que les IP connues |
| RPC Internet | INTERDIT par défaut ; si vraiment requis : firewall strict + pas de faucet.key sur le nœud + audit |

Le nœud wallet écoute RPC+ P2P : en LAN non filtré, `9933` répondait à
tout le segment (constaté pré-correctif). Après correctif : loopback.

## 4. Sécurité

Le RPC n'a pas d'authentification : quiconque l'atteint peut lire les
soldes, miner du PoW via `send` (coût CPU à la charge du client),
appeler le faucet (rate-limit 60 s/adresse, clé requise côté serveur).
D'où : loopback par défaut, exposition = décision explicite + firewall.

## 5. Compatibilité (RPC-04/05/06)

Wallet (create/restore/balance/faucet/send/history/restart),
`node_manager`, watchdog, CLI : 100% `127.0.0.1` — E2E + toolchain
verts après changement. Rien ne dépendait du LAN.

## 6. Tests

- `config::test_rpc_bind_defaults_loopback` (défaut + vieux TOML).
- `scripts/test_rpc_bind.ps1` : RPC-02 (loopback OK, IP LAN refusée),
  RPC-03 (warning + IP LAN servie si explicite).
- Leçons de harness (à retenir) : `$host` est réservé en PowerShell
  (comme `$pid`) ; attendre la readiness RPC (jamais de check à durée
  fixe seule) ; les checks négatifs doivent prouver le positif d'abord
  (sinon ils passent dans le vide).
