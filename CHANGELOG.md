# Changelog

## v1.0.0 (2026-07-21)

### 🚀 AETHER SEDC — Premier lancement public

#### ✨ Nouvelles fonctionnalités
- **Architecture DAG Blockless** — Transactions comme nœuds DAG, pas de blocs
- **Heavy Subgraph Consensus** — Consensus leaderless avec finalité probabilistique adaptative
- **Chiffrement P2P** — X25519 + ChaCha20-Poly1305 avec Perfect Forward Secrecy
- **Micro-PoW anti-spam** — Preuve de travail légère par transaction
- **Système de réputation dynamique** — Score de confiance par adresse
- **Mempool persistant** — Transactions en attente sauvegardées dans Sled
- **DNS Peer Discovery** — Résolution DNS + Peer Exchange (PEX) automatique
- **Rate-limiting RPC** — 200 requêtes/10s par méthode
- **Métriques Prometheus** — Endpoint `/metrics` avec transactions, peers, mempool, uptime

#### 🖥️ Interface Graphique (GUI)
- Wallet intégré (création, import, signature)
- Envoi de transactions
- Faucet testnet
- Stats DAG en temps réel
- Connexion au noeud local

#### ⚙️ Opérations
- Configuration TOML (`--config config.toml`)
- Arrêt gracieux (Ctrl+C → sauvegarde DAG + flush Sled)
- Script de déploiement multi-noeud (`test-multi-node.ps1`)
- Docker Compose prêt
- CI/CD (GitHub Actions — build + test + lint + audit sécurité)

#### 🔒 Sécurité
- Pipeline de validation en 4 étapes
- Atomicité avec rollback
- Aucune fuite de clé privée dans l'API RPC
- Récompenses strictement liées à la finalité
- Fee burn address intégré

#### 📦 Binaries
- `aether.exe` — Noeud CLI (miner, validator, observer)
- `aether-gui.exe` — Interface graphique desktop
