use crate::{
    config::NodeConfig,
    consensus::VQVConsensus,
    genesis::{initialize_genesis, GenesisConfig, GENESIS_MESSAGE},
    json_storage::{ensure_data_dir, load_dag_from_json},
    ledger::Ledger,
    parent_selection::DAG,
    p2p::{P2PConfig, P2PNetwork},
    pow::{DifficultyAdjuster, MicroPoW},
    rpc::{start_rpc_server, AetherRpcImpl, Mempool},
    storage::Storage,
    transaction::{Address, Transaction},
    SyncEvent,
};
use colored::Colorize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub struct NodeHandles {
    pub dag: Arc<RwLock<DAG>>,
    pub storage: Arc<RwLock<Storage>>,
    pub dag_store_path: PathBuf,
}

async fn sync_save_ledger(ledger: Arc<RwLock<Ledger>>, ledger_path: PathBuf) {
    let ledger_clone = ledger.clone();
    tokio::task::spawn_blocking(move || {
        let ledger_lock = ledger_clone.blocking_read();
        ledger_lock.save_blocking(&ledger_path).ok();
    })
    .await
    .ok();
}

fn parse_bootnode_address(addr_str: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if addr_str.contains(':') && !addr_str.starts_with('/') {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() == 2 {
            let domain = parts[0];
            let port = parts[1].parse::<u16>()?;
            if let Ok(mut ips) =
                std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", domain, port))
            {
                if let Some(addr) = ips.next() {
                    return Ok(addr);
                }
            }
        }
    }
    if addr_str.starts_with("/ip4/") || addr_str.starts_with("/ip6/") {
        let parts: Vec<&str> = addr_str.split('/').collect();
        if parts.len() >= 5 {
            let ip = parts[2];
            let port = parts[4].parse::<u16>()?;
            return format!("{}:{}", ip, port)
                .parse::<SocketAddr>()
                .map_err(|e| e.into());
        }
    }
    Err(format!(
        "Invalid bootnode address format: {}. Use IP:PORT, DOMAIN:PORT, or /ip4/IP/tcp/PORT",
        addr_str
    )
    .into())
}

pub async fn run_node(cfg: NodeConfig) -> Result<NodeHandles, Box<dyn std::error::Error>> {
    let node_type = cfg.node_type;
    let mut data_dir = cfg.data_dir;
    let p2p_port = cfg.p2p_port;
    let rpc_port = cfg.rpc_port;

    let mut bootnodes: Vec<SocketAddr> = Vec::new();
    for addr_str in &cfg.bootnodes {
        bootnodes.push(parse_bootnode_address(addr_str.trim())?);
    }
    let mut miner_address: Option<Address> = None;
    if let Some(addr_hex) = &cfg.miner_address {
        let addr: Address = hex::decode(addr_hex)?
            .try_into()
            .map_err(|_| "Invalid miner address hex")?;
        miner_address = Some(addr);
    }

    tracing::info!("🚀 Aether Node v1.0.0 - The Satoshi Protocol");
    tracing::info!("========================================");
    tracing::info!("Node Type: {}", node_type);
    tracing::info!("Data Directory: {:?}", data_dir);
    tracing::info!("P2P Port: {}", p2p_port);
    tracing::info!("RPC Port: {}", rpc_port);
    tracing::info!("Bootnodes: {:?}", bootnodes);
    if !cfg.dns_seeds.is_empty() {
        tracing::info!("DNS Seeds: {:?}", cfg.dns_seeds);
    }

    if cfg.reset && data_dir.exists() {
        tracing::warn!("🗑️  --reset: Cleaning up data directory...");
        std::fs::remove_dir_all(&data_dir)
            .map_err(|e| format!("Failed to delete data directory: {}", e))?;
        tracing::info!("  ✅ Data directory deleted");
    }

    ensure_data_dir(&data_dir).await?;
    let db_path = data_dir.join("sled_db");
    let dag_store_path = data_dir.join("dag.json");
    let ledger_path = data_dir.join("ledger.json");

    tracing::info!("🗄️  Initializing Sled database at {:?}", db_path);
    let storage = Arc::new(RwLock::new(
        Storage::open(&db_path).map_err(|e| format!("Failed to open Sled database: {}", e))?,
    ));

    {
        let storage_read = storage.read().await;
        if storage_read.needs_migration(&data_dir) {
            tracing::info!("🔄 Migration from JSON to Sled needed");
            drop(storage_read);
            let mut storage_write = storage.write().await;
            storage_write
                .migrate_from_json(&data_dir)
                .map_err(|e| format!("Failed to migrate from JSON: {}", e))?;
        }
    }

    let mut ledger = Ledger::new_with_storage(storage.clone(), &ledger_path)
        .await
        .map_err(|e| format!("Failed to load ledger from Sled: {}", e))?;

    let genesis_config = GenesisConfig::default();
    let mut initialized_count = 0;
    for (addr, balance) in &genesis_config.initial_balances {
        let addr_hex = hex::encode(addr);
        let current_balance = ledger.get_balance_hex(&addr_hex);
        tracing::info!("🔍 Genesis check: {} -> current balance: {}", addr_hex, current_balance);
        tracing::info!("🔍 Genesis config balance for {}: {} (raw)", addr_hex, balance);
        if current_balance == 0 {
            ledger.set_balance(addr, *balance);
            initialized_count += 1;
            tracing::info!("🌱 Genesis balance set for {}: {} AETH", addr_hex, *balance / 10_000_000_000);
        }
    }
    if initialized_count > 0 {
        tracing::info!("{}", format!("🌱 Genesis initialized: {} addresses with message: {}", initialized_count, GENESIS_MESSAGE).cyan());
        let storage_read = storage.read().await;
        for (addr_hex, balance) in &ledger.balances {
            let addr_bytes = hex::decode(addr_hex)?;
            let address: Address = addr_bytes.as_slice().try_into()
                .map_err(|e| format!("Invalid address length: {}", e))?;
            storage_read.put_balance(address, *balance)?;
        }
        storage_read.flush()?;
        drop(storage_read);
        tracing::info!("💾 Genesis balances saved to Sled");
    } else {
        tracing::info!("✅ Genesis balances already initialized");
    }

    let (save_tx, mut save_rx) = mpsc::channel::<SyncEvent>(100);

    let (dag, consensus, balances, orphans, missing_parent_hashes) =
        if dag_store_path.exists() {
            tracing::info!("📂 Loading DAG state from JSON...");
            let store = load_dag_from_json(&dag_store_path).await?;
            tracing::info!("  Loaded {} transactions from storage", store.transactions.len());
            tracing::info!("  Loaded {} child relationships from storage", store.children.len());

            let mut dag = DAG::new();
            let mut consensus = VQVConsensus::new(100, 0.7, 5, 50);
            let mut orphans: HashMap<[u8; 32], Transaction> = HashMap::new();

            let mut skipped_count = 0;
            for stored_tx in store.transactions {
                let signature = if let Some(sig) = stored_tx.signature {
                    hex::decode(&sig).unwrap_or_else(|_| {
                        tracing::warn!("Failed to decode signature for transaction, skipping");
                        vec![0u8; 64]
                    })
                } else {
                    vec![0u8; 64]
                };
                let public_key = if let Some(pk) = stored_tx.public_key {
                    hex::decode(&pk).unwrap_or_else(|_| {
                        tracing::warn!("Failed to decode public key for transaction, skipping");
                        vec![0u8; 32]
                    })
                } else {
                    vec![0u8; 32]
                };

                let parent0_bytes = hex::decode(&stored_tx.parents[0]).unwrap_or_else(|_| {
                    tracing::warn!("Failed to decode parent0 for transaction, skipping");
                    vec![0u8; 32]
                });
                let parent1_bytes = hex::decode(&stored_tx.parents[1]).unwrap_or_else(|_| {
                    tracing::warn!("Failed to decode parent1 for transaction, skipping");
                    vec![0u8; 32]
                });
                let sender_bytes = hex::decode(&stored_tx.sender).unwrap_or_else(|_| {
                    tracing::warn!("Failed to decode sender for transaction, skipping");
                    vec![0u8; 32]
                });
                let receiver_bytes = hex::decode(&stored_tx.receiver).unwrap_or_else(|_| {
                    tracing::warn!("Failed to decode receiver for transaction, skipping");
                    vec![0u8; 32]
                });

                let parent0: [u8; 32] = parent0_bytes.clone().try_into().unwrap_or_else(|_| {
                    tracing::warn!("Failed to convert parent0 to TransactionId, skipping transaction");
                    [0u8; 32]
                });
                let parent1: [u8; 32] = parent1_bytes.clone().try_into().unwrap_or_else(|_| {
                    tracing::warn!("Failed to convert parent1 to TransactionId, skipping transaction");
                    [0u8; 32]
                });

                let sender: Address = sender_bytes.clone().try_into().unwrap_or_else(|_| {
                    tracing::warn!("Failed to convert sender to Address, skipping transaction");
                    [0u8; 32]
                });
                let receiver: Address = receiver_bytes.clone().try_into().unwrap_or_else(|_| {
                    tracing::warn!("Failed to convert receiver to Address, skipping transaction");
                    [0u8; 32]
                });

                if parent0_bytes.iter().all(|&b| b == 0)
                    && parent1_bytes.iter().all(|&b| b == 0)
                    && sender_bytes.iter().all(|&b| b == 0)
                    && receiver_bytes.iter().all(|&b| b == 0)
                {
                    tracing::warn!("Skipping transaction with all-zero critical fields");
                    skipped_count += 1;
                    continue;
                }

                let parent0_missing =
                    parent0 != [0u8; 32] && !dag.transactions().contains_key(&parent0);
                let parent1_missing =
                    parent1 != [0u8; 32] && !dag.transactions().contains_key(&parent1);

                if parent0_missing || parent1_missing {
                    tracing::warn!(
                        "⚠️ Orphan transaction detected: missing parent(s) - tx_id: {}, parent0: {}, parent1: {}",
                        hex::encode(&parent0_bytes[..8]),
                        if parent0_missing { "MISSING" } else { "OK" },
                        if parent1_missing { "MISSING" } else { "OK" }
                    );
                    let orphan_tx = Transaction::new(
                        [parent0, parent1],
                        sender,
                        receiver,
                        stored_tx.amount,
                        stored_tx.fee,
                        stored_tx.timestamp,
                        stored_tx.nonce,
                        stored_tx.account_nonce,
                        signature,
                        public_key,
                    );
                    orphans.insert(orphan_tx.id, orphan_tx);
                    continue;
                }

                let tx = Transaction::new(
                    [parent0, parent1],
                    sender_bytes.try_into().unwrap_or_else(|_| [0u8; 32]),
                    receiver_bytes.try_into().unwrap_or_else(|_| [0u8; 32]),
                    stored_tx.amount,
                    stored_tx.fee,
                    stored_tx.timestamp,
                    stored_tx.nonce,
                    stored_tx.account_nonce,
                    signature,
                    public_key,
                );
                if let Err(e) = dag.add_transaction_validated(tx.clone()) {
                    tracing::warn!("⚠️ Failed to load transaction from storage: {}", e);
                    continue;
                }
            }

            let mut missing_parent_hashes: Vec<Vec<u8>> = Vec::new();
            if skipped_count > 0 {
                tracing::warn!("⚠️ Skipped {} invalid transactions during DAG loading", skipped_count);
            }
            if !orphans.is_empty() {
                tracing::warn!("⚠️ {} orphan transactions detected - requesting missing parents via P2P", orphans.len());
                for (_tx_id, orphan) in &orphans {
                    for parent in orphan.parents.iter() {
                        if *parent != [0u8; 32] && !dag.transactions().contains_key(parent) {
                            missing_parent_hashes.push(parent.to_vec());
                            tracing::info!("📡 Orphan Solver - Requesting missing parent: {}", hex::encode(parent));
                        }
                    }
                }
            }

            for stored_child in store.children {
                let parent_bytes = hex::decode(&stored_child.parent).unwrap_or_else(|_| vec![0u8; 32]);
                let child_bytes = hex::decode(&stored_child.child).unwrap_or_else(|_| vec![0u8; 32]);
                let parent: [u8; 32] = parent_bytes.try_into().unwrap_or_else(|_| [0u8; 32]);
                let child: [u8; 32] = child_bytes.try_into().unwrap_or_else(|_| [0u8; 32]);

                if let Some(children_vec) = dag.children_mut().get_mut(&parent) {
                    let mut temp_vec: Vec<[u8; 32]> = children_vec.clone();
                    temp_vec.push(child);
                    dag.children_mut().insert(parent, temp_vec);
                } else {
                    dag.children_mut().insert(parent, vec![child]);
                }
            }

            tracing::info!("  DAG reconstruction complete");
            tracing::info!("  Ledger (balances+nonces) loaded from Sled as source of truth");

            let ledger_balances = ledger.get_all_balances();
            tracing::info!("  Ledger has {} accounts with balances", ledger_balances.len());
            tracing::info!("  Ledger has {} accounts with nonces", ledger.nonces.len());

            (
                dag,
                consensus,
                ledger.balances.clone(),
                orphans,
                missing_parent_hashes,
            )
        } else {
            tracing::info!("🌱 No existing DAG state found, initializing genesis...");
            let genesis_config = GenesisConfig::default();
            let (dag, consensus, balances, orphans, missing_parent_hashes) =
                initialize_genesis(genesis_config);

            for (addr_hex, balance) in &balances {
                let addr_bytes = hex::decode(addr_hex)?;
                let address: Address = addr_bytes.as_slice().try_into()
                    .map_err(|e| format!("Invalid address length: {}", e))?;
                ledger.set_balance(&address, *balance);
            }
            ledger.save().await?;

            (
                dag,
                consensus,
                ledger.balances.clone(),
                orphans,
                missing_parent_hashes,
            )
        };

    let orphans: Arc<RwLock<HashMap<[u8; 32], Transaction>>> =
        Arc::new(RwLock::new(orphans));
    let missing_parent_hashes: Vec<Vec<u8>> = missing_parent_hashes;

    let dag: Arc<RwLock<DAG>> = Arc::new(RwLock::new(dag));
    let consensus: Arc<RwLock<VQVConsensus>> = Arc::new(RwLock::new(consensus));
    let _balances: Arc<RwLock<HashMap<String, u64>>> = Arc::new(RwLock::new(balances));

    let ledger: Arc<RwLock<Ledger>> = Arc::new(RwLock::new(ledger));

    let ledger_for_save = ledger.clone();
    tokio::spawn(async move {
        while let Some(event) = save_rx.recv().await {
            match event {
                SyncEvent::SaveRequested => {
                    let ledger = ledger_for_save.read().await;
                    if let Err(e) = ledger.save().await {
                        tracing::error!("Failed to save ledger: {}", e);
                    } else {
                        tracing::debug!("💾 Ledger saved to Sled");
                    }
                    drop(ledger);
                }
            }
        }
    });

    tracing::info!("💾 DAG loaded from JSON");
    tracing::info!("🔄 Rebuilding tips...");
    {
        let mut dag_write = dag.write().await;
        dag_write.rebuild_tips();
        tracing::info!("  TIP COUNT: {}", dag_write.transaction_count());
    }
    tracing::info!("✅ Tips rebuilt");

    tracing::info!("⚙️  Initializing Micro-PoW...");
    let difficulty_adjuster = DifficultyAdjuster::default();
    let pow = MicroPoW::default();
    tracing::info!("✓ Micro-PoW initialized");
    tracing::info!("  Initial Difficulty: {}", pow.difficulty().value());
    tracing::info!("  Target TPS: {}", difficulty_adjuster.target_tps());

    let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
    {
        let storage_read = storage.read().await;
        if let Ok(persisted_txs) = storage_read.load_mempool_txs() {
            let mut mempool_write = mempool.write().await;
            for tx in persisted_txs {
                if mempool_write.size() < mempool_write.max_size() {
                    let _ = mempool_write.add_internal(tx).await;
                }
            }
            tracing::info!("💾 Loaded {} persisted mempool transactions", mempool_write.size());
        }
    }
    tracing::info!("✓ Mempool initialized");

    tracing::info!("📡 Creating P2P channel...");
    let (tx_channel, mut tx_receiver) = tokio::sync::mpsc::unbounded_channel::<Transaction>();
    tracing::info!("✓ P2P channel created");

    let p2p_dag_for_tips = dag.clone();
    let get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        if let Ok(dag_lock) = p2p_dag_for_tips.try_read() {
            dag_lock
                .get_tips_with_selector()
                .iter()
                .map(|id| id.to_vec())
                .collect()
        } else {
            Vec::new()
        }
    });

    let p2p_dag_for_hashes = dag.clone();
    let get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        if let Ok(dag_lock) = p2p_dag_for_hashes.try_read() {
            dag_lock.transactions().keys().map(|k| k.to_vec()).collect()
        } else {
            Vec::new()
        }
    });

    let p2p_dag_for_tx = dag.clone();
    let get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
        Arc::new(move |hash| {
            if let Ok(dag_lock) = p2p_dag_for_tx.try_read() {
                let tx_id: [u8; 32] = hash.try_into().ok()?;
                dag_lock.transactions().get(&tx_id).cloned()
            } else {
                None
            }
        });

    let p2p_config = P2PConfig {
        listen_addr: format!("0.0.0.0:{}", p2p_port)
            .parse()
            .map_err(|e| format!("Failed to parse P2P listen address: {}", e))?,
        bootnodes,
        dns_seeds: cfg.dns_seeds.clone(),
    };

    let p2p_ledger = ledger.clone();
    let get_balance: Arc<dyn Fn(&[u8; 32]) -> u64 + Send + Sync> = Arc::new(move |addr| {
        if let Ok(ledger_lock) = p2p_ledger.try_read() {
            ledger_lock.get_balance(addr)
        } else {
            0
        }
    });

    let _p2p_dag = dag.clone();
    let _p2p_dag_store_path = dag_store_path.clone();
    let save_dag = Arc::new(move || {});

    let process_orphans_dag = dag.clone();
    let process_orphans_ledger = ledger.clone();
    let process_orphans_orphans = orphans.clone();
    let process_orphans = Arc::new(move || {
        let dag = process_orphans_dag.clone();
        let ledger = process_orphans_ledger.clone();
        let orphans = process_orphans_orphans.clone();
        tokio::spawn(async move {
            let mut orphans_to_remove = Vec::new();
            {
                let orphans_lock = orphans.read().await;
                let dag_lock = dag.read().await;

                for (tx_id, orphan) in orphans_lock.iter() {
                    let parent0_ok = orphan.parents[0] == [0u8; 32]
                        || dag_lock.transactions().contains_key(&orphan.parents[0]);
                    let parent1_ok = orphan.parents[1] == [0u8; 32]
                        || dag_lock.transactions().contains_key(&orphan.parents[1]);

                    if parent0_ok && parent1_ok {
                        tracing::info!(
                            "🔗 [Sync] Transaction {} resolved - parents now available via P2P sync",
                            hex::encode(&tx_id[..8])
                        );
                        orphans_to_remove.push(*tx_id);
                    }
                }
            }

            if !orphans_to_remove.is_empty() {
                let mut orphans_lock = orphans.write().await;
                let mut dag_lock = dag.write().await;
                let mut ledger_lock = ledger.write().await;

                for tx_id in orphans_to_remove {
                    if let Some(orphan) = orphans_lock.remove(&tx_id) {
                        if let Err(e) = dag_lock.add_transaction_validated(orphan.clone()) {
                            tracing::warn!("⚠️ Failed to add orphan to DAG: {}", e);
                            continue;
                        }

                        let sender_hex = hex::encode(orphan.sender);
                        let receiver_hex = hex::encode(orphan.receiver);
                        let amount = orphan.amount;

                        if let Some(balance) = ledger_lock.balances.get_mut(&sender_hex) {
                            *balance = balance.saturating_sub(amount);
                        }
                        if let Some(balance) = ledger_lock.balances.get_mut(&receiver_hex) {
                            *balance = balance.saturating_add(amount);
                        }
                    }
                }

                dag_lock.rebuild_tips();
                tracing::info!("✅ Orphans resolved, tips rebuilt");
            }
        });
    });

    tracing::info!("🌐 Initializing P2P network...");
    let p2p_network = Arc::new(P2PNetwork::new(
        p2p_config,
        tx_channel,
        get_dag_hashes,
        get_transaction_by_hash,
        get_balance,
        save_dag,
        process_orphans,
        get_tips,
    ));
    tracing::info!("✅ P2P network initialized");

    let p2p_network_clone = p2p_network.clone();
    tracing::info!("🔄 Spawning P2P Network task...");
    tokio::spawn(async move {
        tracing::info!("✅ P2P Network task spawned");
        if let Err(e) = p2p_network_clone.start().await {
            tracing::error!("P2P network error: {}", e);
        }
    });

    tracing::info!("🔄 Spawning P2P transaction receiver...");
    let dag_for_p2p = dag.clone();
    let mempool_for_p2p = mempool.clone();
    let ledger_for_p2p = ledger.clone();
    let consensus_for_p2p = consensus.clone();
    let p2p_network_for_p2p = p2p_network.clone();
    let save_tx_for_p2p = save_tx.clone();
    let miner_addr_for_p2p = miner_address.clone();
    let ledger_path_for_p2p = ledger_path.clone();
    let storage_for_p2p = storage.clone();
    let orphans_for_p2p = orphans.clone();

    tokio::spawn(async move {
        tracing::info!("✅ P2P transaction receiver task spawned");
        while let Some(tx) = tx_receiver.recv().await {
            let rpc_impl = AetherRpcImpl::new(
                consensus_for_p2p.clone(),
                dag_for_p2p.clone(),
                ledger_for_p2p.clone(),
                storage_for_p2p.clone(),
                ledger_path_for_p2p.clone(),
                mempool_for_p2p.clone(),
                p2p_network_for_p2p.clone(),
                save_tx_for_p2p.clone(),
                Arc::new(RwLock::new(true)),
                miner_addr_for_p2p.clone(),
                orphans_for_p2p.clone(),
            );

            match rpc_impl.process_transaction(tx, "P2P").await {
                Ok(_) => {
                    tracing::info!("✅ P2P transaction accepted and processed");
                    rpc_impl.process_orphans().await;
                }
                Err(e) => {
                    tracing::warn!("❌ P2P transaction rejected: {}", e);
                }
            }
        }
    });

    tracing::info!("✓ P2P Network initialized");
    tracing::info!("  Listening on port {}", p2p_port);

    if !missing_parent_hashes.is_empty() {
        let p2p_for_orphans = p2p_network.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            for parent_hash in missing_parent_hashes {
                tracing::info!(
                    "📡 Orphan Solver - Requesting missing parent via P2P: {}",
                    hex::encode(&parent_hash)
                );
                p2p_for_orphans.request_transaction(parent_hash).await;
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });
    }

    let mining_enabled = Arc::new(RwLock::new(true));

    let orphans_periodic = orphans.clone();
    let dag_periodic = dag.clone();
    let ledger_periodic = ledger.clone();
    let storage_periodic = storage.clone();
    let ledger_path_periodic = ledger_path.clone();
    let mempool_periodic = mempool.clone();
    let consensus_periodic = consensus.clone();
    let p2p_periodic = p2p_network.clone();
    let save_tx_periodic = save_tx.clone();
    let mining_enabled_periodic = mining_enabled.clone();
    let miner_addr_periodic = miner_address.clone();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            let rpc_impl = AetherRpcImpl::new(
                consensus_periodic.clone(),
                dag_periodic.clone(),
                ledger_periodic.clone(),
                storage_periodic.clone(),
                ledger_path_periodic.clone(),
                mempool_periodic.clone(),
                p2p_periodic.clone(),
                save_tx_periodic.clone(),
                mining_enabled_periodic.clone(),
                miner_addr_periodic.clone(),
                orphans_periodic.clone(),
            );

            rpc_impl.process_orphans().await;
        }
    });

    tracing::info!("📡 About to start RPC server...");

    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", rpc_port).parse()?;
    let rpc_dag = dag.clone();
    let rpc_consensus = consensus.clone();
    let rpc_ledger = ledger.clone();
    let rpc_ledger_path = ledger_path.clone();
    let rpc_mempool = mempool.clone();
    let rpc_p2p = p2p_network.clone();
    let rpc_save_tx = save_tx.clone();
    let rpc_storage = storage.clone();
    let mining_enabled_rpc = mining_enabled.clone();
    let rpc_orphans = orphans.clone();

    tracing::info!("🔄 Spawning RPC Server task...");
    tokio::spawn(async move {
        tracing::info!("✅ RPC Server task spawned");
        if let Err(e) = start_rpc_server(
            rpc_addr,
            rpc_consensus,
            rpc_dag,
            rpc_ledger,
            rpc_storage,
            rpc_ledger_path,
            rpc_mempool,
            rpc_p2p,
            rpc_save_tx,
            mining_enabled_rpc,
            miner_address,
            rpc_orphans,
        )
        .await
        {
            tracing::error!("RPC server error: {}", e);
        }
    });
    tracing::info!("✓ RPC Server initialized");

    tracing::info!("✅ Aether Node Ready");

    match node_type.as_str() {
        "miner" => {
            tracing::info!("⛏️  Starting Mining Mode...");
            tracing::info!("  Node will actively mine transactions to secure the DAG");

            let mining_mempool = mempool.clone();
            let _dag_store_path_clone = dag_store_path.clone();
            let _data_dir_clone = data_dir.clone();
            let mining_enabled_clone = mining_enabled.clone();
            let mining_storage = storage.clone();

            tracing::info!("🔄 Spawning Mining task...");
            let mining_dag = dag.clone();
            tokio::spawn(async move {
                tracing::info!("✅ Mining task spawned");
                let mut iteration = 0u64;
                let _save_tx_clone = save_tx.clone();
                let mut last_status_time = std::time::Instant::now();

                let mut transactions_processed = 0u64;
                let start_time = std::time::Instant::now();

                loop {
                    let should_mine = *mining_enabled_clone.read().await;
                    if !should_mine {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    if let Some(tx) = {
                        let mut mempool_lock = mining_mempool.write().await;
                        let t = mempool_lock.pop_front();
                        if let Some(ref removed_tx) = t {
                            if let Ok(storage_guard) = mining_storage.try_read() {
                                let _ = storage_guard.remove_mempool_tx(removed_tx.id);
                            }
                        }
                        t
                    } {
                        tracing::info!("📦 Transaction found in mempool! Mining...");
                        {
                            let mut dag_write = mining_dag.write().await;
                            if let Err(e) = dag_write.add_transaction_validated(tx) {
                                tracing::warn!("⚠️ Failed to add mempool transaction to DAG: {}", e);
                                continue;
                            }
                        }
                        transactions_processed += 1;
                        let elapsed_secs = start_time.elapsed().as_secs_f64();
                        let real_tps = if elapsed_secs > 0.0 {
                            transactions_processed as f64 / elapsed_secs
                        } else {
                            0.0
                        };
                        let dag_read = mining_dag.read().await;
                        tracing::info!(
                            "🔄 Mining iteration {} | TPS: {:.2} | Transactions: {}",
                            iteration,
                            real_tps,
                            dag_read.transaction_count()
                        );
                        iteration += 1;
                    } else {
                        if last_status_time.elapsed() >= std::time::Duration::from_secs(5) {
                            let mempool_size = mining_mempool.read().await.size();
                            let dag_read = mining_dag.read().await;
                            let elapsed_secs = start_time.elapsed().as_secs_f64();
                            let real_tps = if elapsed_secs > 0.0 {
                                transactions_processed as f64 / elapsed_secs
                            } else {
                                0.0
                            };
                            tracing::info!(
                                "⛏️  Mining Active | Mempool: {} tx | DAG: {} tx | TPS: {:.2} | Connected to RPC",
                                mempool_size,
                                dag_read.transaction_count(),
                                real_tps
                            );
                            last_status_time = std::time::Instant::now();
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    }
                }
            });
            tracing::info!("✓ Mining task initialized");
        }
        "validator" => {
            tracing::info!("🔒 Starting Validator Mode...");
            tracing::info!("  Node will participate in VQV consensus");

            tracing::info!("🔄 Spawning Validator task...");
            tokio::spawn(async move {
                tracing::info!("✅ Validator task spawned");
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            });
            tracing::info!("✓ Validator task initialized");
        }
        "observer" => {
            tracing::info!("👁️  Starting Observer Mode...");
            tracing::info!("  Node will monitor the network without participating in consensus");

            tracing::info!("🔄 Spawning Observer task...");
            tokio::spawn(async move {
                tracing::info!("✅ Observer task spawned");
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            });
            tracing::info!("✓ Observer task initialized");
        }
        _ => {
            tracing::error!("❌ Unknown node type: {}", node_type);
            tracing::error!("Valid types: miner, validator, observer");
            std::process::exit(1);
        }
    }

    Ok(NodeHandles {
        dag,
        storage,
        dag_store_path,
    })
}
