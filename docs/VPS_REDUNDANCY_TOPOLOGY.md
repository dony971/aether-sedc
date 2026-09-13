# VPS REDUNDANCY — Topology & Bootstrap Architecture

**Date:** 2026-09-13
**Status:** IN PROGRESS (waiting for Seed2 VPS)

---

## Current State

### Seed 1 (OPERATIONAL)
- **Host:** 103.102.135.126 (IPv6: 2a0c:b641:1a0:800::ba)
- **P2P:** port 25565 (0.0.0.0)
- **RPC:** port 9933 (127.0.0.1 — localhost only)
- **SSH:** port 9221, key-based auth (ed25519)
- **Service:** aether-seed.service (systemd, auto-start)
- **Data:** /opt/aether/data (10120 txs)
- **Binary:** /opt/aether/bin/aether-unified

### Target Topology

```
           Seed 1 (existing)
           IPv4: 103.102.135.126:25565
           IPv6: [2a0c:b641:1a0:800::ba]:25565
              │
Internet ─────┼────── Nodes (canary, fresh, etc.)
              │
           Seed 2 (NEW — required)
           [TBD]
```

### Bootstrap Discovery

New nodes discover the network via bootnodes parameter:
```
--bootnodes "SEED1:25565"           # Seed1 only
--bootnodes "SEED1:25565,SEED2:25565"  # Both seeds (redundant)
```

### Requirements for Seed 2

- Independent machine/VPS (not same host)
- Same binary version (e7df0e2a or later)
- Same genesis, network_id, P2P version
- No wallet/faucet keys needed
- Separate SSH credentials
- Firewall: P2P 25565 open, RPC 9933 localhost only
- Non-root service user
- NTP enabled
- systemd auto-start

### SPOF Matrix

| Scenario | Bootstrap works? | Existing nodes survive? |
|----------|-----------------|------------------------|
| Seed1 ON, Seed2 OFF | YES (via Seed1) | YES |
| Seed1 OFF, Seed2 ON | YES (via Seed2) | YES |
| Seed1 ON, Seed2 ON | YES (redundant) | YES |
| Seed1 OFF, Seed2 OFF | NO (SPOF) | YES |

### Failover Behavior

When Seed1 goes down during a new node's bootstrap:
1. Node detects peer loss (connection timeout)
2. Node retries with backoff
3. If Seed2 is configured, node connects to Seed2
4. Sync resumes from where it left off (store-first)
5. No data loss, no full restart needed

### IPv4 Situation

Seed1 has only IPv6 public address. Options:
1. **Current:** IPv6 direct (works for IPv6-capable peers)
2. **SSH tunnel:** Works for testing, not production
3. **IPv4 port forward:** If VPS provider supports it (OPTIONAL)
4. **WebGate/relay:** If available

Decision: Keep current setup. IPv4 is OPTIONAL per plan.
