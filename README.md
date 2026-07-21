# AETHER SEDC - Self-Evolving DAG Consensus

**Version**: 1.0.0  
**Statut**: Unifié et Prêt pour Compilation

---

## 🚀 AETHER SEDC - Protocole Blockchain Révolutionnaire

AETHER SEDC est un protocole de consensus DAG révolutionnaire qui élimine les blocs séquentiels et le consensus basé sur des leaders.

### 🌟 Innovations Uniques

1. **Architecture Blockless** - Pas de blocs, seulement des transactions comme nœuds DAG
2. **Consensus Sans Leader** - Heavy Subgraph Consensus (pas de mining, pas de validators élus)
3. **Finalité Adaptative** - Finalité probabilistique qui s'adapte aux conditions réseau
4. **Économie Liée au Consensus** - Récompenses SEULEMENT pour transactions finalisées
5. **Réputation Dynamique** - Système de réputation qui évolue selon le comportement

### 📊 Comparaison avec Bitcoin

| Caractéristique | Bitcoin | AETHER SEDC |
|---|---|---|
| Architecture | Blocs séquentiels | DAG blockless |
| Consensus | Proof-of-Work | Heavy Subgraph Consensus |
| Leaders | Miners | Aucun (leaderless) |
| Finalité | 6 confirmations fixes | Adaptative probabilistique |
| Économie | Indépendante de finalité | Strictement liée au consensus |
| Débit | ~7 TPS | Illimité (théoriquement) |

---

## 🏗️ Architecture du Projet Unifié

Le projet `aether-unified` fusionne:
- **Infrastructure complète** de `dag-network` (storage, RPC, P2P, wallet, etc.)
- **Algorithmes de consensus avancés** de `sedc-core` (Heavy Subgraph Scoring, Reputation System)

### Modules Principaux

```
src/
├── transaction.rs          # Structure de transaction et signature
├── parent_selection.rs     # DAG storage et tip selection
├── consensus.rs            # Consensus State + Heavy Subgraph Scoring
├── reputation.rs           # Système de réputation dynamique
├── ledger.rs               # Gestion des soldes et politique monétaire
├── validation.rs           # Pipeline de validation (3 étapes)
├── transaction_processor.rs # Zero-trust single entry point
├── storage.rs              # Persistance Sled DB
├── p2p.rs                  # Réseau P2P chiffré (X25519 + ChaCha20-Poly1305)
├── rpc.rs                  # API JSON-RPC + rate-limiting + métriques Prometheus
├── config.rs               # Configuration TOML
├── wallet.rs               # Gestion de wallet
├── economics.rs            # Module économique
├── pow.rs                  # Micro-PoW anti-spam
├── genesis.rs              # Initialisation genesis
└── main.rs                 # Point d'entrée du noeud
```

---

## 🔒 Sécurité Renforcée

### Pipeline de Validation Strict
```
1. validate_pure(tx)      - Validation structurelle (pas d'accès état)
2. validate_dag(tx, dag)  - Validation parents, double-spend (lecture seule)
3. validate_ledger(tx)    - Validation solde, nonce, fee (lecture seule)
4. Exécution atomique     - Write locks + rollback sur erreur
```

### Invariants de Sécurité
- ❌ Pas de mutation avant validation complète
- ❌ Pas de bypass des validation layers
- ❌ Pas de block_height manuel dans RPC
- ✅ Single source of truth: ConsensusState
- ✅ Atomicité avec rollback
- ✅ Fork-safe rewards via BlockId tracking

### Système de Réputation
- Réputation initiale: 0.5
- +0.01 pour transaction validée correctement
- -0.5 pour double-spend confirmé
- -0.1 pour transaction invalide
- Décroissance temporelle: 0.001 par heure
- Seuil minimum: 0.1 pour validation
- Discount sur frais si réputation ≥ 0.7

---

## 💰 Politique Monétaire

- **MAX_SUPPLY**: 21,000,000 AETH
- **Unités**: 10 décimales (1 AETH = 10^10 unités)
- **Récompense initiale**: 10 AETH
- **Halving**: Tous les 210,000 blocs
- **FEE_BURN_ADDRESS**: [0xFFu8; 32]

### Récompenses Liées au Consensus
```
reward_issued(tx) = true iff state(tx) = Finalized
```

---

## 🛠️ Compilation & Utilisation

### Prérequis
- Rust 1.70 ou supérieur
- Windows 10/11, Linux, ou macOS

### Instructions

```bash
# Compiler
cargo build --release

# Exécuter les tests (160+ tests)
cargo test --lib

# Lancer un noeud mineur (port par défaut)
cargo run --release

# Lancer avec configuration personnalisée
cargo run --release -- --config config.toml

# Lancer un noeud observateur
cargo run --release -- --node-type observer --data-dir ./data-observer

# Lancer avec DNS seeds + bootnodes
cargo run --release -- \
  --bootnodes 192.168.1.100:25565 \
  --dns-seeds seed1.aether.network,seed2.aether.network

# Lancer le wallet (CLI)
cargo run --release -- wallet create
cargo run --release -- wallet restore "mnemonic phrase here..."
```

### Configuration (TOML)

```toml
# config.toml — voir config.example.toml
node_type = "miner"
data_dir = "./data"
p2p_port = 25565
rpc_port = 9933
reset = false
bootnodes = ["192.168.1.100:25565", "node1.aether.network:25565"]
dns_seeds = ["seed1.aether.network", "seed2.aether.network"]
# miner_address = "abcd1234..."
```

Les flags CLI écrasent les valeurs du fichier de configuration.

## 🌐 Déploiement Multi-Noeud

### Script automatisé (Windows PowerShell)
```powershell
.\test-multi-node.ps1
```

Démarre 3 noeuds (bootnode + 2 miners), vérifie :
- Connexion P2P (peer count ≥ 1)
- Propagation de transaction via faucet
- Santé de chaque noeud

### Déploiement manuel
```bash
# Terminal 1: Bootnode
./target/release/aether --node-type miner --data-dir ./data-bootnode --p2p-port 25565 --rpc-port 9933

# Terminal 2: Miner 1
./target/release/aether --node-type miner --data-dir ./data-miner-1 --p2p-port 25566 --rpc-port 9934 --bootnodes 127.0.0.1:25565

# Terminal 3: Miner 2
./target/release/aether --node-type miner --data-dir ./data-miner-2 --p2p-port 25567 --rpc-port 9935 --bootnodes 127.0.0.1:25565
```

### Docker
```bash
docker compose up --build
```

## 🔒 Sécurité Production

### P2P Chiffré
- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Chiffrement**: ChaCha20-Poly1305 (AEAD, constant-time)
- **Perfect Forward Secrecy**: Nouvelle clé éphémère par connexion

### Rate-Limiting RPC
- Algorithme: Token bucket (sliding window)
- Limite: 200 requêtes par 10 secondes par méthode
- Retourne erreur `-32000` avec `retry_after` quand limité

### Arrêt Gracieux (Graceful Shutdown)
- Sauvegarde automatique du DAG (JSON)
- Flush de la base Sled
- Ctrl+C géré proprement

### DNS Peer Discovery
- Résolution DNS des seeds au démarrage
- Re-résolution périodique (10 min)
- Échange de pairs (PEX) toutes les 2 minutes

### Résoudre les problèmes de compilation

Si vous rencontrez des erreurs de fichiers verrouillés:
```bash
# Fermer tous les processus Rust
taskkill /F /IM rustc.exe /T
taskkill /F /IM cargo.exe /T

# Nettoyer le dossier target
Remove-Item -Recurse -Force target

# Recompiler
cargo build --release
```

---

## 🧪 Tests

Le projet inclut 159 tests de sécurité couvrant:
- ✅ Replay attack prevention
- ✅ Double spend prevention
- ✅ Fork safety
- ✅ Atomic execution rollback
- ✅ Orphan recovery
- ✅ Monetary policy enforcement
- ✅ Consensus state invariants

```bash
# Exécuter tous les tests
cargo test --lib

# Exécuter uniquement les tests de sécurité
cargo test --lib security_tests
```

---

## 📝 API RPC & Monitoring

Le noeud expose une API JSON-RPC sur le port 9933 (par défaut).
Le endpoint `/metrics` (Prometheus) est disponible sur le même port.

### Métriques Prometheus (`GET /metrics`)
| Métrique | Type | Description |
|---|---|---|
| `aether_transactions_total` | counter | Transactions totales dans le DAG |
| `aether_tips_current` | gauge | Nombre de tips actuels |
| `aether_peers_connected` | gauge | Pairs P2P connectés |
| `aether_mempool_size` | gauge | Transactions en attente dans le mempool |
| `aether_uptime_seconds` | counter | Temps depuis le démarrage |
| `aether_node_info` | gauge | Métadonnées du noeud (type, version) |

### Exemple Prometheus scrape config
```yaml
scrape_configs:
  - job_name: 'aether'
    static_configs:
      - targets: ['localhost:9933']
```

### Méthodes JSON-RPC

```json
// Soumettre une transaction
{
  "jsonrpc": "2.0",
  "method": "aether_submitTransaction",
  "params": [{ "transaction": "..." }],
  "id": 1
}

// Obtenir le solde
{
  "jsonrpc": "2.0",
  "method": "aether_getBalance",
  "params": ["0x..."],
  "id": 1
}

// Faucet (testnet)
{
  "jsonrpc": "2.0",
  "method": "aether_faucet",
  "params": ["127.0.0.1:9934"],
  "id": 1
}

// Stats du DAG
{
  "jsonrpc": "2.0",
  "method": "aether_getDagStats",
  "params": [],
  "id": 1
}
```

---

## 🔬 Fonctionnalités Avancées

### Heavy Subgraph Scoring
```rust
score(S) = Σ (weight(tx) × reputation(validator) × depth_factor)
depth_factor = 1.0 + (depth(tx) / max_depth) × 0.5
```

### Finalité Adaptative
```rust
P_finality(tx) = 1 - exp(-λ × confirmations / volatility)
```

### Frais Dynamiques
```rust
fee = max(base_fee, adaptive_fee)
adaptive_fee = base_fee × (1 + density_multiplier) × (1 - reputation_discount)
```

---

## 📈 Feuille de Route

### ✅ Complété
- [x] Infrastructure DAG complète
- [x] Système de validation strict
- [x] Transaction processor atomique
- [x] Système de réputation dynamique
- [x] Heavy Subgraph Scoring
- [x] Finalité adaptative
- [x] Orphan recovery persistant
- [x] Tests de sécurité (160 tests)
- [x] Chiffrement P2P (X25519 + ChaCha20-Poly1305)
- [x] Rate-limiting RPC
- [x] Mempool persistant (Sled)
- [x] DNS peer discovery + PEX
- [x] Configuration TOML
- [x] Métriques Prometheus (/metrics)
- [x] CI/CD (GitHub Actions)
- [x] Graceful shutdown
- [x] Déploiement multi-noeud (scripts + Docker)

### 🚧 En Cours / À Faire
- [ ] Wallet UI (egui)
- [ ] Explorer API avancé
- [ ] Audit de sécurité externe
- [ ] Déploiement testnet public
- [ ] Documentation API complète

---

## 🤝 Contribution

Pour contribuer:
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commit vos changements
4. Push vers la branche
5. Ouvrir une Pull Request

---

## 📄 Licence

MIT License - Voir le fichier LICENSE pour les détails

---

## 📞 Contact

- **Projet**: AETHER SEDC
- **Version**: 1.0.0
- **Date**: 26 Avril 2026

---

## 🎯 Objectif

Créer un système blockchain véritablement décentralisé, sans leaders, avec une finalité adaptative et une économie strictement liée au consensus pour une sécurité zero-trust.

**"Le futur de la blockchain n'a pas de blocs."**
