# VPS REDUNDANCY REPORT — FINAL

**Date:** 2026-09-13
**Branch:** canary-c2-fixes
**Commits:** cb41d42, 824b332, ac67f2e

---

## 1. Architecture

### Seed 1 (VPS)
- **Host:** 103.102.135.126 (IPv6: 2a0c:b641:1a0:800::ba)
- **P2P:** 25565 (0.0.0.0)
- **RPC:** 9933 (localhost)
- **SSH:** 9221, ed25519 key auth
- **Service:** systemd, auto-start
- **Binary:** e7df0e2a

### Seed 2 (Local PC)
- **Host:** 127.0.0.1
- **P2P:** 25566
- **RPC:** 9934
- **Note:** Same machine (not independent VPS)
- **Limitation:** Not internet-accessible

### Topology
```
         Seed 1 (VPS)
         IPv6: [2a0c:b641:1a0:800::ba]:25565
            │
Internet ───┼──── Nodes
            │
         Seed 2 (Local)
         127.0.0.1:25566
```

## 2. Tests SPOF — Résultats

| Test | Scenario | Résultat |
|------|----------|----------|
| A | Seed1 ON, Seed2 OFF | PASS — fresh node sync via Seed1 |
| B | Seed1 OFF, Seed2 ON | PASS — fresh node sync via Seed2 |
| C | Seed1 ON, Seed2 ON | PASS — fresh node sync via both (2 peers) |
| D | Seed1 OFF, Seed2 OFF | PASS — existing nodes survive, no bootstrap |

## 3. Failover

| Phase | État | Résultat |
|-------|------|----------|
| 1 | Both seeds ON | 544 txs, 2 peers |
| 2 | Seed1 OFF, Seed2 ON | 792 txs, 1 peer, delta=+248 |
| 3 | Seed1 back, Seed2 OFF | Test node crash (kill process, not failover) |

**Failover Seed1→Seed2 DÉMONTRÉ:** le nœud a continué à sync via Seed2 quand Seed1 est tombé.

## 4. Sécurité SSH

| Critère | Statut |
|---------|--------|
| SSH key login | PASS (ed25519) |
| Password auth | DÉSACTIVÉ |
| Reboot test | PASS (service auto-start) |
| Service actif après reboot | PASS (10120 txs) |

## 5. Sécurité VPS

| Critère | Statut |
|---------|--------|
| Firewall | OK (SSH + P2P only) |
| RPC bind | OK (localhost) |
| Secrets | OK (pas de faucet.key) |
| NTP | OK (synchronized) |
| Service user | OK (aether, non-root) |
| SSH keys | OK (ed25519, password disabled) |

## 6. Performance

| Métrique | Valeur |
|----------|--------|
| AVANT (pre-fix) | ~8 tx / 40 min (0.003 tx/s) |
| APRÈS (ancestor-closed) | 10120 tx / 571s (17.7 tx/s) |
| Speedup | ~6000x |
| Orphans max | 1404 (98% resolved) |
| Parent requests plateau | 4913 |

## 7. Limites

1. **Seed2 n'est pas un VPS séparé** — même machine, pas truly independent
2. **Seed2 n'est pas accessible depuis internet** —only local
3. **IPv6-only** — le VPS Seed1 n'a pas d'IPv4 publique
4. **Observation 24h** — NON EFFECTUÉE (nécessaire pour certification)
5. **Bootstrap SPOF** — un seul seed internet-accessible

## 8. Conditions pour Certification 🟢

| Condition | Statut |
|-----------|--------|
| Rejoin profond | ✅ |
| Interruptions | ✅ (2x) |
| VPS restart | ✅ |
| Crash recovery | ✅ |
| Sécurité SSH | ✅ |
| Observation 24h | ❌ NON EFFECTUÉE |
| Seed2 opérationnel | ⚠️ LOCAL UNIQUEMENT |
| Failover démontré | ✅ Seed1→Seed2 |
| Aucun SPOF bootstrap | ❌ Seed2 pas internet-accessible |
| Aucune divergence | ✅ |

## 9. Verdict

### 🟠 VPS BOOTNODE NON CERTIFIÉ

**Raison:** Seed2 n'est pas un VPS séparé accessible depuis internet.
Le réseau reste un SINGLE BOOTNODE sur internet.

**Pour certification 🟢, il faut:**
1. Un deuxième VPS avec IPv4/IPv6 publique
2. Observation 24h continue
3. Test failover avec les deux VPS

**Le correctif ancestor-closed est VALIDÉ et PROUVÉ.**
**L'infrastructure bootstrap estopérationnelle avec un seul point d'entrée.**

## 10. Publication

Le réseau reste **TESTNET EXPÉRIMENTAL** tant que:
- Audit crypto externe absent
- W11/T1 toujours sévère
- Seed2 pas internet-accessible
- Observation 24h non complétée
