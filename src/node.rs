use crate::{
    config::NodeConfig,
    genesis::{initialize_genesis, GenesisConfig},
    json_storage::{ensure_data_dir, load_dag_from_json, save_dag_to_json},
    ledger::Ledger,
    p2p::{P2PConfig, P2PNetwork},
    parent_selection::{canonical_resolve_conflicts, rebuild_dag_topological, DAG},
    rpc::{start_rpc_server, AetherRpcImpl, Mempool},
    storage::Storage,
    transaction::{Address, Transaction},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

pub struct NodeHandles {
    pub dag: Arc<RwLock<DAG>>,
    pub storage: Arc<RwLock<Storage>>,
    pub dag_store_path: PathBuf,
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
    let data_dir = cfg.data_dir;
    let p2p_port = cfg.p2p_port;
    let rpc_port = cfg.rpc_port;
    let rpc_bind = cfg.rpc_bind;

    let mut bootnodes: Vec<SocketAddr> = Vec::new();
    for addr_str in &cfg.bootnodes {
        bootnodes.push(parse_bootnode_address(addr_str.trim())?);
    }

    tracing::info!("🚀 Aether Node v1.0.0 - The Satoshi Protocol");
    tracing::info!("========================================");
    tracing::info!("Node Type: {}", node_type);
    tracing::info!("Data Directory: {:?}", data_dir);
    tracing::info!("P2P Port: {}", p2p_port);
    tracing::info!("RPC Port: {}", rpc_port);
    // INFRASTRUCTURE (n°7): loud warning on any non-loopback RPC bind.
    // Loopback covers 127.0.0.1, ::1 and localhost spellings.
    {
        let b = rpc_bind.trim().to_lowercase();
        let loopback = b == "127.0.0.1" || b == "::1" || b == "localhost";
        tracing::info!("RPC Bind: {}", rpc_bind);
        if !loopback {
            tracing::warn!(
                "⚠️ WARNING RPC exposed on non-loopback address {} — anyone who can reach it can query balances, request faucet funds (if enabled) and submit transactions. Bind 127.0.0.1 unless you operate a firewall.",
                rpc_bind
            );
        }
    }
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
            let storage_write = storage.write().await;
            storage_write
                .migrate_from_json(&data_dir)
                .await
                .map_err(|e| format!("Failed to migrate from JSON: {}", e))?;
        }
    }

    // INC-01: shared bootstrap state created BEFORE the boot rebuild so the
    // rebuild itself is observable (counters, orphan TTL, parent dedup).
    let sync_ctx = Arc::new(crate::sync_stats::SyncContext::default());

    let mut ledger = Ledger::new_with_storage(storage.clone())
        .await
        .map_err(|e| format!("Failed to load ledger from Sled: {}", e))?;

    let (dag, balances, orphans, missing_parent_hashes, rebuild_skipped) = {
        let genesis_config = GenesisConfig::default();
        let (mut dag, _balances, mut orphans_rebuilt, mut missing_parent_hashes) =
            initialize_genesis(genesis_config);

        // 🔧 FIX (unified): Sled is the single source of truth for the DAG.
        // Every accepted transaction is persisted to Sled (STEP 9b), so on
        // restart we rebuild the DAG from Sled transactions + orphans.
        // dag.json is only a legacy fallback when Sled has no transactions
        // (pre-fix data, first migration). Loading from dag.json alone used
        // to silently drop transactions (non-topological order, no
        // rebuild_tips, and it ignored Sled entirely) -> wallet showed fewer
        // transactions than the network after a hard kill.
        let mut all_txs: Vec<Transaction> = Vec::new();
        {
            let storage_read = storage.read().await;
            if let Ok(persisted_txs) = storage_read.get_all_transactions() {
                all_txs.extend(persisted_txs);
            }
            if let Ok(persisted_orphans) = storage_read.get_all_orphans() {
                for orphan in persisted_orphans {
                    if !all_txs.iter().any(|tx| tx.id == orphan.id) {
                        all_txs.push(orphan);
                    }
                }
            }
        }

        // Legacy fallback: if Sled is empty but dag.json exists (data written
        // by an old build without Sled persistence), load from dag.json.
        if all_txs.is_empty() && dag_store_path.exists() {
            tracing::info!("📂 Sled empty, loading DAG state from JSON (legacy)...");
            let store = load_dag_from_json(&dag_store_path).await?;
            tracing::info!(
                "  Loaded {} transactions from dag.json",
                store.transactions.len()
            );
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
                    tracing::warn!(
                        "Failed to convert parent0 to TransactionId, skipping transaction"
                    );
                    [0u8; 32]
                });
                let parent1: [u8; 32] = parent1_bytes.clone().try_into().unwrap_or_else(|_| {
                    tracing::warn!(
                        "Failed to convert parent1 to TransactionId, skipping transaction"
                    );
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
                    continue;
                }

                let tx = Transaction::new(
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
                if !all_txs.iter().any(|existing| existing.id == tx.id) {
                    all_txs.push(tx);
                }
            }
        }

        // V-21 FIX: canonical double-spend resolution BEFORE rebuilding the
        // DAG. Persistent storage may contain a pruned loser (and the txs
        // built on it) - e.g. a crash between the runtime prune and its Sled
        // purge. Without this, the boot rebuild would be nondeterministic:
        // whichever of the loser/winner Sled iterates first would win. The
        // smallest id per (sender, nonce) always wins, losers + descendants
        // are dropped and purged from Sled (same rule as the runtime prune).
        {
            let pruned = canonical_resolve_conflicts(&mut all_txs);
            if !pruned.is_empty() {
                tracing::warn!(
                    "⚠️ Boot canonicalization: dropping {} conflicting/descendant transaction(s) (min-id wins)",
                    pruned.len()
                );
                let storage_read = storage.read().await;
                for pruned_id in &pruned {
                    let _ = storage_read.delete_transaction(*pruned_id);
                }
            }
        }

        let mut rebuild_skipped = 0u64;
        if !all_txs.is_empty() {
            tracing::info!(
                "📂 Rebuilding DAG from {} persisted transactions + orphans (Sled/JSON)",
                all_txs.len()
            );
            // INC-01: pure topological insert via rebuild_dag_topological —
            // every persisted tx lands in exactly one bucket (inserted /
            // skipped with an explicit reason / orphaned), nothing is ever
            // dropped silently. NO ledger/balance validation here: the
            // persisted ledger already contains the effects of historical
            // txs, re-validating them would wrongly drop valid txs.
            sync_ctx
                .stats
                .rebuild_total
                .fetch_add(all_txs.len() as u64, Ordering::Relaxed);
            let rebuild_started = Instant::now();
            let (rebuild_inserted, rebuild_skipped_count, rebuild_orphans) =
                rebuild_dag_topological(&mut dag, all_txs);
            rebuild_skipped = rebuild_skipped_count;
            for tx in rebuild_orphans {
                tracing::warn!(
                    "⚠️ Orphan transaction detected during rebuild: tx_id: {}",
                    hex::encode(&tx.id[..8])
                );
                orphans_rebuilt.insert(tx.id, tx);
            }
            sync_ctx
                .stats
                .rebuild_inserted
                .fetch_add(rebuild_inserted, Ordering::Relaxed);
            sync_ctx
                .stats
                .rebuild_skipped
                .fetch_add(rebuild_skipped, Ordering::Relaxed);
            sync_ctx
                .stats
                .rebuild_orphaned
                .fetch_add(orphans_rebuilt.len() as u64, Ordering::Relaxed);
            sync_ctx.stats.rebuild_duration_ms.fetch_add(
                rebuild_started.elapsed().as_millis() as u64,
                Ordering::Relaxed,
            );
            dag.rebuild_tips();
            tracing::info!(
                "  DAG rebuilt: {} transactions, {} tips",
                dag.transaction_count(),
                dag.tip_count()
            );
        }

        if cfg.repair_ledger {
            // The ledger is now always derived from the DAG (see below), so
            // --repair-ledger is a no-op kept for CLI compatibility.
            tracing::warn!("🔧 --repair-ledger: ledger is rebuilt from the DAG on every boot");
        } else {
            tracing::info!(
                "✓ Ledger balances loaded from Sled ({} accounts, {} nonces)",
                ledger.balances.len(),
                ledger.nonces.len()
            );
        }
        ledger.save().await?;

        for orphan in orphans_rebuilt.values() {
            for parent in orphan.parents.iter() {
                if *parent != [0u8; 32] && !dag.transactions().contains_key(parent) {
                    missing_parent_hashes.push(parent.to_vec());
                }
            }
        }

        (
            dag,
            ledger.balances.clone(),
            orphans_rebuilt,
            missing_parent_hashes,
            rebuild_skipped,
        )
    };

    let orphans: Arc<RwLock<HashMap<[u8; 32], Transaction>>> = Arc::new(RwLock::new(orphans));
    let missing_parent_hashes: Vec<Vec<u8>> = missing_parent_hashes;

    let dag: Arc<RwLock<DAG>> = Arc::new(RwLock::new(dag));
    let _balances: Arc<RwLock<HashMap<String, u64>>> = Arc::new(RwLock::new(balances));

    // INC-01 GUARD: the DAG is the source of truth ONLY when the local store
    // is complete. A crash can truncate the transaction tree (observed in the
    // incident: 10004 -> 20 persisted txs). Deriving the ledger from a partial
    // DAG and SAVING it permanently destroys the persisted ledger (observed:
    // supply 1000000099999000986 -> 1000000099999999188). Rules:
    //   - rebuild complete (no orphans, no skips) AND derived supply <=
    //     persisted supply -> the DAG covers at least all persisted history
    //     (a truncated tree with no orphans derives a HIGHER supply, because
    //     fewer fees were burned) -> rebuild ledger from DAG and save.
    //   - otherwise -> KEEP the persisted ledger untouched, flag a
    //     crash-recovery event and let the orphan solver + full sync heal the
    //     DAG; every tx accepted through the runtime path updates the ledger
    //     (its nonce guard prevents double application).
    {
        let dag_read = dag.read().await;
        let orphans_read = orphans.read().await;
        let store_complete = orphans_read.is_empty() && rebuild_skipped == 0;
        drop(orphans_read);
        if store_complete {
            let mut derived = ledger.clone();
            derived.rebuild_from_dag(&dag_read);
            let derived_supply = derived.total_supply();
            let persisted_supply = ledger.total_supply();
            // Fresh node: persisted ledger is empty (0) because Sled has no
            // balances yet — derived == genesis supply is the correct state.
            // The "truncated store looks complete but derives HIGHER supply"
            // guard only applies when the persisted ledger already holds
            // genesis funds.
            let is_fresh = persisted_supply == 0;
            if is_fresh || derived_supply <= persisted_supply {
                ledger = derived;
                drop(dag_read);
                let _ = ledger.save().await;
                tracing::info!(
                    "♻️ Ledger rebuilt from DAG on boot: supply {} (bounds: {})",
                    ledger.total_supply(),
                    ledger.supply_within_bounds()
                );
            } else {
                drop(dag_read);
                tracing::error!(
                    "⛔ INC-01: store looks complete but derived supply {} > persisted {} — the persisted ledger has MORE applied history (truncated store with no orphans); KEEPING persisted ledger, recovery required",
                    derived_supply,
                    persisted_supply
                );
                sync_ctx.stats.wal_recovery.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            drop(dag_read);
            tracing::error!(
                "⛔ INC-01: local store INCOMPLETE ({} orphans, {} skipped) — KEEPING persisted ledger (supply {}), NOT overwriting; recovery via orphan solver + sync required",
                orphans.read().await.len(),
                rebuild_skipped,
                ledger.total_supply()
            );
            sync_ctx.stats.wal_recovery.fetch_add(1, Ordering::Relaxed);
        }
    }

    let ledger: Arc<RwLock<Ledger>> = Arc::new(RwLock::new(ledger));

    // C2 P3: applied-set cross-check (observability for the next canary).
    // dag_not_applied > 0 after a complete-store rebuild means transfers
    // were skipped live and only healed at boot; applied_not_in_dag > 0
    // means marks survived their tx (should only happen transiently
    // around prunes — save() rewrites authoritatively).
    {
        let dag_read = dag.read().await;
        let ledger_read = ledger.read().await;
        let mut dag_not_applied = 0u64;
        for key in dag_read.transactions().keys() {
            if let Ok(id) = <[u8; 32]>::try_from(key.as_slice()) {
                if !ledger_read.is_applied(&id) {
                    dag_not_applied += 1;
                }
            }
        }
        let mut applied_not_in_dag = 0u64;
        for id in ledger_read.applied.iter() {
            if !dag_read.transactions().contains_key(id.as_slice()) {
                applied_not_in_dag += 1;
            }
        }
        if dag_not_applied > 0 || applied_not_in_dag > 0 {
            tracing::warn!(
                "🔍 C2 P3 applied cross-check: {} DAG txs without applied mark, {} applied marks without DAG tx",
                dag_not_applied,
                applied_not_in_dag
            );
        }
    }

    tracing::info!("💾 DAG loaded from JSON");
    tracing::info!("🔄 Rebuilding tips...");
    {
        let mut dag_write = dag.write().await;
        dag_write.rebuild_tips();
        tracing::info!("  TIP COUNT: {}", dag_write.transaction_count());
    }
    tracing::info!("✅ Tips rebuilt");

    let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
    {
        let storage_read = storage.read().await;
        if let Ok(persisted_txs) = storage_read.load_mempool_txs() {
            let dag_read = dag.read().await;
            let mut mempool_write = mempool.write().await;
            let mut skipped = 0usize;
            for tx in persisted_txs {
                // PHASE D: skip txs already in the DAG (legacy persisted copies
                // of accepted txs — the old build persisted the last-1000
                // accepted txs into the "Mempool" tree) and drop their stale
                // copies: only genuinely pending txs re-enter the queue. This
                // self-heals old data dirs: a fresh boot never starts with a
                // full queue that blocks everything (the Phase C dead-end).
                if dag_read.transactions().contains_key(&tx.id) {
                    let _ = storage_read.remove_mempool_tx(tx.id);
                    skipped += 1;
                    continue;
                }
                if mempool_write.size() < mempool_write.max_size() {
                    let _ = mempool_write.enqueue(tx, 0);
                }
            }
            tracing::info!(
                "💾 Loaded {} persisted mempool transactions ({} skipped: already in DAG)",
                mempool_write.size(),
                skipped
            );
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
    let storage_for_getdata = storage.clone();
    let sync_ctx_for_getdata = sync_ctx.clone();
    let get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
        Arc::new(move |hash| {
            let tx_id: [u8; 32] = match hash.try_into() {
                Ok(id) => id,
                Err(_) => return None,
            };
            // Memory first: the DAG is the live source of truth.
            if let Ok(dag_lock) = p2p_dag_for_tx.try_read() {
                if let Some(tx) = dag_lock.transactions().get(&tx_id) {
                    sync_ctx_for_getdata
                        .stats
                        .getdata_remote
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(tx.clone());
                }
            }
            // INC-01: store-backed fallback — serve persisted transactions
            // from disk when they are not in memory (after a reboot with a
            // partial DAG, or historical txs beyond the mempool). Without
            // this, peers that own a tx on disk but not in memory could
            // never serve it, and a node with a truncated DAG could never
            // heal from a peer that only has it persisted.
            if let Ok(storage_lock) = storage_for_getdata.try_read() {
                if let Ok(tx) = storage_lock.get_transaction(tx_id) {
                    sync_ctx_for_getdata
                        .stats
                        .getdata_local
                        .fetch_add(1, Ordering::Relaxed);
                    return Some(tx);
                }
            }
            None
        });

    // B4: shared bootstrap state (counters, parent-request dedup, orphan TTL).
    // (created before the boot rebuild — see above)

    // B4: sync dedup must also treat already-parked orphans as known (they are
    // retried by the fixpoint resolver; re-delivering them was the request
    // amplification loop of the B4 livelock).
    let orphans_for_p2p = orphans.clone();
    let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(move |hash: &[u8]| {
        if let Ok(orphan_lock) = orphans_for_p2p.try_read() {
            if let Ok(tx_id) = <[u8; 32]>::try_from(hash) {
                return orphan_lock.contains_key(&tx_id);
            }
        }
        false
    });

    let p2p_config = P2PConfig {
        listen_addr: format!("0.0.0.0:{}", p2p_port)
            .parse()
            .map_err(|e| format!("Failed to parse P2P listen address: {}", e))?,
        bootnodes,
        dns_seeds: cfg.dns_seeds.clone(),
    };

    tracing::info!("🌐 Initializing P2P network...");
    let p2p_network = Arc::new(P2PNetwork::new(
        p2p_config,
        tx_channel,
        get_dag_hashes,
        get_transaction_by_hash,
        get_tips,
        sync_ctx.clone(),
        is_orphan,
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

    let p2p_network_for_p2p = p2p_network.clone();
    let ledger_path_for_p2p = ledger_path.clone();
    let storage_for_p2p = storage.clone();
    let orphans_for_p2p = orphans.clone();
    let sync_ctx_for_p2p = sync_ctx.clone();

    tokio::spawn(async move {
        tracing::info!("✅ P2P transaction receiver task spawned");
        while let Some(tx) = tx_receiver.recv().await {
            let rpc_impl = AetherRpcImpl::new(
                dag_for_p2p.clone(),
                ledger_for_p2p.clone(),
                storage_for_p2p.clone(),
                ledger_path_for_p2p.clone(),
                mempool_for_p2p.clone(),
                p2p_network_for_p2p.clone(),
                Arc::new(RwLock::new(true)),
                orphans_for_p2p.clone(),
                sync_ctx_for_p2p.clone(),
            );

            match rpc_impl.process_transaction(tx, "P2P").await {
                Ok(_) => {
                    tracing::info!("✅ P2P transaction accepted and processed");
                    // B4: count DAG growth through the sync path and resolve
                    // newly applicable orphans in the same cycle (fixpoint).
                    sync_ctx_for_p2p
                        .stats
                        .sync_progress
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // VPS-2 §6: monotone frontier = max DAG total observed
                    // on P2P success. progress(t+1) >= progress(t) BY
                    // CONSTRUCTION (max-update); a flat frontier alongside
                    // pending orphans/requests is stall evidence.
                    let total_now = dag_for_p2p.read().await.transaction_count() as u64;
                    let prev = sync_ctx_for_p2p
                        .stats
                        .sync_frontier
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if total_now > prev {
                        sync_ctx_for_p2p
                            .stats
                            .sync_frontier
                            .fetch_max(total_now, std::sync::atomic::Ordering::Relaxed);
                    }
                    rpc_impl.process_orphans().await;
                }
                Err(e) => {
                    tracing::warn!("❌ P2P transaction rejected: {}", e);
                }
            }
        }
    });

    // PHASE D: MEMPOOL DRAINER — the mempool lifecycle loop
    // (ACCEPT → QUEUE → SELECT → PROCESS → INCLUDE → REMOVE). Spawned
    // unconditionally so it runs on every node type (miner, validator,
    // observer): a node that accepts transactions into its queue must also
    // drain them into its DAG, or the queue becomes the Phase C dead-end
    // again. Observability (mandate §13): the lifecycle counters + drain
    // rate are logged every 5 s (aether_getMempoolStats + /metrics expose
    // them on demand).
    let dag_for_drain = dag.clone();
    let mempool_for_drain = mempool.clone();
    let ledger_for_drain = ledger.clone();
    let storage_for_drain = storage.clone();
    let ledger_path_for_drain = ledger_path.clone();
    let p2p_for_drain = p2p_network.clone();
    let orphans_for_drain = orphans.clone();
    let sync_ctx_for_drain = sync_ctx.clone();

    tokio::spawn(async move {
        tracing::info!("✅ Mempool drainer task spawned");
        let rpc_impl = AetherRpcImpl::new(
            dag_for_drain,
            ledger_for_drain,
            storage_for_drain,
            ledger_path_for_drain,
            mempool_for_drain,
            p2p_for_drain,
            Arc::new(RwLock::new(true)),
            orphans_for_drain,
            sync_ctx_for_drain,
        );
        let mut last_log = std::time::Instant::now();
        let mut last_removed: u64 = 0;
        loop {
            rpc_impl.drain_mempool().await;
            if last_log.elapsed() >= std::time::Duration::from_secs(5) {
                let s = rpc_impl.mempool_stats().await;
                let removed_delta = s.removed.saturating_sub(last_removed);
                let drain_rate = removed_delta as f64 / 5.0;
                tracing::info!(
                    "🔻 Mempool | size={} max={} min_fee={} | added={} removed={} included={} rejected={} expired={} duplicate={} orphan={} resolved={} | drain_rate={:.1}/s",
                    s.size,
                    s.max_size,
                    s.min_fee,
                    s.added,
                    s.removed,
                    s.included,
                    s.rejected,
                    s.expired,
                    s.duplicate,
                    s.orphan_parked,
                    s.orphan_resolved,
                    drain_rate
                );
                last_removed = s.removed;
                last_log = std::time::Instant::now();
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
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

    let mining_enabled = Arc::new(RwLock::new(false));

    let orphans_periodic = orphans.clone();
    let dag_periodic = dag.clone();
    let ledger_periodic = ledger.clone();
    let storage_periodic = storage.clone();
    let ledger_path_periodic = ledger_path.clone();
    let mempool_periodic = mempool.clone();
    let p2p_periodic = p2p_network.clone();
    let mining_enabled_periodic = mining_enabled.clone();
    let dag_save_periodic = dag.clone();
    let dag_store_path_save_periodic = dag_store_path.clone();
    let sync_ctx_periodic = sync_ctx.clone();
    let last_stats_snapshot = Arc::new(std::sync::Mutex::new(
        crate::sync_stats::SyncStatsSnapshot::default(),
    ));

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            // 🔧 FIX: Persist the DAG periodically so a hard kill cannot leave
            // the node with an advanced ledger but an empty DAG.
            {
                let dag_lock = dag_save_periodic.read().await;
                if let Err(e) = save_dag_to_json(&dag_lock, &dag_store_path_save_periodic).await {
                    tracing::warn!("⚠️ Periodic DAG save failed: {}", e);
                }
                drop(dag_lock);
            }
            // P4: periodic Sled flush bounds hard-kill data loss to one cycle
            // (~10s). Per-transaction flushes were removed from the acceptance
            // path (STEP 8) because they capped throughput at ~70 tps; Sled's
            // internal ~500ms auto-flush plus this periodic flush keep
            // durability bounded, and the boot rebuild reconstructs the ledger
            // from the DAG (the source of truth).
            if let Ok(storage_lock) = storage_periodic.try_read() {
                let _ = storage_lock.flush();
            }

            let rpc_impl = AetherRpcImpl::new(
                dag_periodic.clone(),
                ledger_periodic.clone(),
                storage_periodic.clone(),
                ledger_path_periodic.clone(),
                mempool_periodic.clone(),
                p2p_periodic.clone(),
                mining_enabled_periodic.clone(),
                orphans_periodic.clone(),
                sync_ctx_periodic.clone(),
            );

            rpc_impl.process_orphans().await;

            // B4: log the sync counters when they changed (bootstrap/join
            // observability; the RPC endpoint exposes them on demand).
            {
                let snap = sync_ctx_periodic.stats.snapshot();
                let mut last = last_stats_snapshot
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if *last != snap {
                    tracing::info!(
                        "📊 sync requested={} received={} progress={} batches={} | orphans created={} resolved={} purged={} retries={} | parents requested={} deduped={} | dup_ignored={}",
                        snap.sync_requested,
                        snap.sync_received,
                        snap.sync_progress,
                        snap.sync_batches,
                        snap.orphan_created,
                        snap.orphan_resolved,
                        snap.orphan_purged,
                        snap.retry_count,
                        snap.parent_requested,
                        snap.parent_already_known,
                        snap.duplicate_ignored
                    );
                    *last = snap;
                }
            }

            // V-22 FIX: periodic full reconciliation. The tip-based sync only
            // runs once at connection time; a node that missed transactions
            // (offline, or a stale inventory at handshake) would otherwise
            // never recover them. Every cycle we request the full inventory
            // of every connected peer, diff it against our DAG and fetch what
            // is missing, until all nodes converge on the same transaction set.
            p2p_periodic.request_full_sync().await;
        }
    });

    tracing::info!("📡 About to start RPC server...");

    let rpc_addr: SocketAddr = format!("{}:{}", rpc_bind, rpc_port).parse()?;
    let rpc_dag = dag.clone();
    let rpc_ledger = ledger.clone();
    let rpc_ledger_path = ledger_path.clone();
    let rpc_mempool = mempool.clone();
    let rpc_p2p = p2p_network.clone();
    let rpc_storage = storage.clone();
    let mining_enabled_rpc = mining_enabled.clone();
    let rpc_orphans = orphans.clone();
    let sync_ctx_rpc = sync_ctx.clone();

    tracing::info!("🔄 Spawning RPC Server task...");
    tokio::spawn(async move {
        tracing::info!("✅ RPC Server task spawned");
        if let Err(e) = start_rpc_server(
            rpc_addr,
            rpc_dag,
            rpc_ledger,
            rpc_storage,
            rpc_ledger_path,
            rpc_mempool,
            rpc_p2p,
            mining_enabled_rpc,
            rpc_orphans,
            sync_ctx_rpc,
        )
        .await
        {
            tracing::error!("RPC server error: {}", e);
        }
    });
    tracing::info!("✓ RPC Server initialized");

    tracing::info!("✅ Aether Node Ready");

    // With ZERO emission there is no block to mine and no validator reward.
    // "miner", "validator" and "observer" node types all run as full nodes that
    // relay, validate and process transactions through the secure pipeline.
    match node_type.as_str() {
        "miner" => {
            tracing::info!("⛏️  Starting Node Mode (mining/relay)...");
            tracing::info!("  PoW nonce mining is done client-side; no block reward exists.");

            let mining_mempool = mempool.clone();
            let mining_dag = dag.clone();
            let mining_enabled_clone = mining_enabled.clone();

            tokio::spawn(async move {
                tracing::info!("✅ Node task spawned");
                let mut last_status_time = std::time::Instant::now();
                loop {
                    let _should_mine = *mining_enabled_clone.read().await;
                    if last_status_time.elapsed() >= std::time::Duration::from_secs(5) {
                        let mempool_size = mining_mempool.read().await.size();
                        let dag_read = mining_dag.read().await;
                        tracing::info!(
                            "⛏️  Node Active | Mempool: {} tx | DAG: {} tx",
                            mempool_size,
                            dag_read.transaction_count()
                        );
                        last_status_time = std::time::Instant::now();
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                }
            });
            tracing::info!("✓ Node task initialized");
        }
        "validator" => {
            tracing::info!("🔒 Starting Validator Mode...");
            tracing::info!("  VQV has been removed; this node runs as a full node.");

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
