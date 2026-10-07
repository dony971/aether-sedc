# Aether Threat Model

**Date:** 2026-09-16

---

## Attacker Types

### 1. Spammer

**Capacity:** Generate transactions at will (CPU/GPU limited)

**Objective:** Flood the network with transactions, exhaust resources

**Current defense:** PoW 24-bit (~5.3s/tx CPU, ~3.25ms/tx GPU estimated)

**Proof:** CPU benchmark measured, GPU estimated only

**Known limit:** GPU attacker generates ~308 tx/s vs CPU 0.19 tx/s

**Status:** PARTIAL (GPU resistance unmeasured)

---

### 2. Sybil Attacker

**Capacity:** Create unlimited fake peer identities

**Objective:** Control peer connections, isolate honest nodes

**Current defense:** /24 subnet limit (4 peers per subnet), global limit (128 peers)

**Proof:** 10/10 Sybil simulation tests pass

**Known limit:** Eclipse requires ≥32 VPS in distinct /24 subnets (~$544/month)

**Status:** PROVEN

---

### 3. Eclipse Attacker

**Capacity:** Control all connections to a target node

**Objective:** Isolate node from honest network, feed false data

**Current defense:** Subnet diversity (4/subnet), peer scoring, ban system

**Proof:** Sybil simulation shows 32 VPS minimum for eclipse

**Known limit:** Attacker with 32 VPS can eclipse a single node

**Status:** PROVEN

---

### 4. Malicious Peer

**Capacity:** Send invalid/contradictory messages

**Objective:** Crash nodes, corrupt state, waste resources

**Current defense:** Peer scoring (penalties), ban system, message validation

**Proof:** Peer scoring tests pass, message validation in validation.rs

**Known limit:** Unknown attack surface in message parsing

**Status:** PARTIAL

---

### 5. Double Spender

**Capacity:** Create conflicting transactions (same sender, same nonce)

**Objective:** Spend the same tokens twice

**Current defense:** Canonical rule (smallest ID wins), DAG-level conflict detection

**Proof:** 4/4 double-spend tests pass, 1,000 fuzz cycles

**Known limit:** Partition can temporarily allow conflicting txs (resolved on merge)

**Status:** PROVEN

---

### 6. DAG Manipulator

**Capacity:** Insert transactions with specific parent structures

**Objective:** Skew weight calculations, favor own transactions

**Current defense:** Weight = subtree size (structural), random walk parent selection

**Proof:** Weight tests pass, parent selection is randomized

**Known limit:** No formal proof of weight manipulation resistance

**Status:** PARTIAL

---

### 7. Resource Exhaustion Attacker

**Capacity:** Send large messages, many connections, slow reads

**Objective:** Exhaust memory, CPU, bandwidth

**Current defense:** Rate limits (400 msg/s), message size cap (16 MiB), connection limit (128), timeouts

**Proof:** Constants defined and enforced in accept_loop/handle_peer

**Known limit:** Not tested under real load

**Status:** PARTIAL

---

### 8. Network Partition Attacker

**Capacity:** Isolate subsets of nodes

**Objective:** Cause divergent state, double-spend during partition

**Current defense:** Canonical conflict resolution, rebuild_from_dag determinism

**Proof:** Partition tests pass (consensus_harness, crash_harness)

**Known limit:** Partition can temporarily allow conflicting txs

**Status:** PROVEN

---

## Summary

| Attacker | Status | Confidence |
|---|---|---|
| Spammer | PARTIAL | GPU unmeasured |
| Sybil | PROVEN | 32 VPS for eclipse |
| Eclipse | PROVEN | Subnet limit enforced |
| Malicious Peer | PARTIAL | Unknown attack surface |
| Double Spender | PROVEN | Canonical rule enforced |
| DAG Manipulator | PARTIAL | No formal proof |
| Resource Exhaustion | PARTIAL | Not load-tested |
| Network Partition | PROVEN | Deterministic resolution |
