//! # Aether Node Main Entry Point
//!
//! Main entry point for the Aether blockchain node.
//! Defaults to mining mode if no command is specified.

use aether_unified::{
    config::NodeConfig,
    json_storage::save_dag_to_json,
    transaction::{Address, Transaction},
    wallet::Wallet,
};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::env;
use std::path::PathBuf;

/// AETHER SEDC — Self-Evolving DAG Consensus Node
#[derive(Parser)]
#[command(name = "aether", version = "1.1.1", about = "AETHER SEDC")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to TOML config file (CLI args override file values)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Node type: miner, validator, or observer
    #[arg(long, default_value = "miner")]
    node_type: String,

    /// Data directory for storage
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// P2P listening port
    #[arg(long, default_value_t = 25565)]
    p2p_port: u16,

    /// RPC listening port
    #[arg(long, default_value_t = 9933)]
    rpc_port: u16,

    /// Bootnode addresses (comma-separated IP:PORT or domain:PORT)
    #[arg(long)]
    bootnodes: Option<String>,

    /// DNS seed domains for peer discovery (comma-separated, e.g. seed1.aether.network,seed2.aether.network)
    #[arg(long)]
    dns_seeds: Option<String>,

    /// Miner address (hex)
    #[arg(long)]
    miner_address: Option<String>,

    /// Reset storage data on startup
    #[arg(long)]
    reset: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a legacy keypair wallet
    Keygen {
        /// Output wallet path
        #[arg(default_value = "wallet.json")]
        path: String,
    },
    /// Create a new wallet with BIP39 mnemonic
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// Send a transaction
    Send {
        /// Receiver address (hex)
        receiver: String,
        /// Amount
        amount: u64,
        /// Fee (optional, default: 10)
        #[arg(default_value_t = 10)]
        fee: u64,
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:9933")]
        rpc_url: String,
        /// Wallet path
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        /// Wallet password
        #[arg(long)]
        password: Option<String>,
    },
    /// Check balance
    Balance {
        /// Address or wallet path
        address_or_wallet: String,
        /// RPC URL
        #[arg(long, default_value = "http://127.0.0.1:9933")]
        rpc_url: String,
        /// Wallet password
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum WalletAction {
    /// Create a new wallet with mnemonic phrase
    Create {
        /// Output path
        #[arg(default_value = "wallet.json")]
        path: String,
    },
    /// Restore a wallet from mnemonic phrase
    Restore {
        /// Output path
        #[arg(default_value = "wallet.json")]
        path: String,
        /// Mnemonic phrase
        mnemonic: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse_from(env::args_os());

    // Handle subcommands (non-node commands)
    match &cli.command {
        Some(Commands::Keygen { path }) => {
            let wallet = Wallet::new();
            wallet.to_file(path, None).await?;
            println!("{}", "✓ Wallet generated and saved to".green());
            println!("  Path: {}", path.cyan());
            println!("  Address: {}", hex::encode(wallet.address()).cyan());
            return Ok(());
        }
        Some(Commands::Wallet { action }) => match action {
            WalletAction::Create { path } => {
                let wallet = Wallet::new_with_mnemonic();
                print!("Enter password to encrypt wallet: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                let password = password.trim();
                if password.is_empty() {
                    eprintln!("{}", "Password cannot be empty".red());
                    std::process::exit(1);
                }
                wallet.to_file(path, Some(password)).await?;
                println!("{}", "✓ Wallet generated and saved".green());
                println!("  Path: {}", path.cyan());
                println!("  Address: {}", wallet.address_string().cyan());
                println!();
                println!(
                    "{}",
                    "⚠️  IMPORTANT: Write down your mnemonic phrase below.".yellow()
                );
                println!("   This is the ONLY way to recover your wallet if you lose the file.");
                println!();
                println!(
                    "   Mnemonic: {}",
                    wallet.mnemonic.as_deref().unwrap_or("<unavailable>").cyan()
                );
                println!();
                println!(
                    "{}",
                    "   Store this phrase in a secure location. Never share it with anyone."
                        .yellow()
                );
                return Ok(());
            }
            WalletAction::Restore { path, mnemonic } => {
                let wallet = Wallet::from_mnemonic(mnemonic)?;
                wallet.to_file(path, None).await?;
                println!("{}", "✓ Wallet restored from mnemonic".green());
                println!("  Path: {}", path.cyan());
                println!("  Address: {}", wallet.address_string().cyan());
                return Ok(());
            }
        },
        Some(Commands::Send {
            receiver,
            amount,
            fee,
            rpc_url,
            wallet,
            password,
        }) => {
            if !std::path::Path::new(&wallet).exists() {
                eprintln!("{}", "⚠️  Wallet file not found".yellow());
                eprintln!("  Path: {}", wallet);
                eprintln!("  Create one with: aether wallet create");
                std::process::exit(1);
            }
            send_transaction_client(
                &wallet,
                &receiver,
                *amount,
                *fee,
                rpc_url,
                password.as_deref(),
            )
            .await?;
            return Ok(());
        }
        Some(Commands::Balance {
            address_or_wallet,
            rpc_url,
            password,
        }) => {
            let address_hex = if address_or_wallet.ends_with(".json")
                || std::path::Path::new(&address_or_wallet).exists()
            {
                let w = Wallet::from_file(address_or_wallet, password.as_deref()).await?;
                let addr = hex::encode(w.address());
                println!("📍 Address: {}", addr);
                addr
            } else {
                address_or_wallet.clone()
            };
            match balance_client(&address_hex, rpc_url).await {
                Ok(_) => {}
                Err(_) => {
                    println!("⚠️  Could not connect to RPC server at {}", rpc_url);
                    println!("   Make sure the node is running to check balance");
                }
            }
            return Ok(());
        }
        None => {} // Continue to node startup
    }

    // Load config from file (if provided), CLI overrides
    let mut cfg = if let Some(ref config_path) = cli.config {
        match NodeConfig::load(config_path) {
            Ok(c) => {
                tracing::info!("📋 Loaded config from: {:?}", config_path);
                c
            }
            Err(e) => {
                tracing::warn!("⚠️  Failed to load config file {:?}: {}", config_path, e);
                NodeConfig::default()
            }
        }
    } else {
        NodeConfig::default()
    };

    // CLI overrides config file
    if cli.node_type != "miner" {
        cfg.node_type = cli.node_type.clone();
    }
    if cli.data_dir != PathBuf::from("./data") {
        cfg.data_dir = cli.data_dir.clone();
    }
    if cli.p2p_port != 25565 {
        cfg.p2p_port = cli.p2p_port;
    }
    if cli.rpc_port != 9933 {
        cfg.rpc_port = cli.rpc_port;
    }
    if let Some(ref bn) = cli.bootnodes {
        cfg.bootnodes = bn
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(ref ds) = cli.dns_seeds {
        cfg.dns_seeds = ds
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if cli.miner_address.is_some() {
        cfg.miner_address = cli.miner_address.clone();
    }
    if cli.reset {
        cfg.reset = true;
    }

    let handles = aether_unified::node::run_node(cfg).await?;

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("Failed to listen for Ctrl+C: {}", e))?;
    tracing::info!("🛑 Shutting down gracefully...");

    tracing::info!("💾 Saving DAG...");
    {
        let dag_guard = handles.dag.read().await;
        if let Err(e) = save_dag_to_json(&dag_guard, &handles.dag_store_path).await {
            tracing::error!("❌ Failed to save DAG: {}", e);
        }
    }

    tracing::info!("💾 Flushing storage...");
    let storage_guard = handles.storage.read().await;
    let _ = storage_guard.flush();

    tracing::info!("👋 Aether Node stopped. Goodbye!");

    Ok(())
}

/// Lightweight transaction client for sending transactions via RPC
async fn send_transaction_client(
    wallet_path: &str,
    receiver_hex: &str,
    amount: u64,
    fee: u64,
    rpc_url: &str,
    password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load wallet (with password if provided)
    let wallet: aether_unified::wallet::Wallet =
        match Wallet::from_file(wallet_path, password).await {
            Ok(w) => w,
            Err(e) if e.to_string().contains("Password required") => {
                eprintln!("⚠️  Warning: Wallet is encrypted but no password provided");
                eprintln!("  Use --password option to unlock the wallet");
                return Err(e);
            }
            Err(e) => return Err(e),
        };
    let sender_address = wallet.address(); // Already returns first 32 bytes of public_key

    // Decode receiver address
    let receiver_address: Address = hex::decode(receiver_hex)?
        .try_into()
        .map_err(|_| "Invalid receiver address hex")?;

    // Fetch account_nonce from RPC
    let client = reqwest::Client::new();
    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "aether_getAccountNonce",
        "params": [hex::encode(sender_address)],
        "id": 1
    });

    let account_nonce = match client.post(rpc_url).json(&rpc_payload).send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(json) => json
                .get("result")
                .and_then(|r| r.get("next_nonce"))
                .and_then(|n| n.as_u64())
                .ok_or_else(|| "Failed to extract next_nonce from RPC response")?,
            Err(e) => {
                return Err(format!("Failed to parse account_nonce response: {}", e).into());
            }
        },
        Err(e) => {
            return Err(format!("Failed to fetch account_nonce from RPC: {}", e).into());
        }
    };

    // Fetch tips from RPC for proper parent selection
    let tips_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "aether_getTips",
        "params": [],
        "id": 2
    });

    let parents = match client.post(rpc_url).json(&tips_payload).send().await {
        Ok(response) => {
            match response.json::<serde_json::Value>().await {
                Ok(json) => {
                    if let Some(result) = json.get("result") {
                        if let Some(tips_data) = result.get("tips") {
                            if let Some(tips_array) = tips_data.as_array() {
                                let mut parent_ids = [[0u8; 32]; 2];
                                for (i, tip) in tips_array.iter().take(2).enumerate() {
                                    if let Some(tip_str) = tip.as_str() {
                                        if let Ok(tip_bytes) = hex::decode(tip_str) {
                                            if tip_bytes.len() == 32 {
                                                parent_ids[i].copy_from_slice(&tip_bytes);
                                            }
                                        }
                                    }
                                }
                                parent_ids
                            } else {
                                [[0u8; 32]; 2] // Fallback to genesis
                            }
                        } else {
                            [[0u8; 32]; 2] // Fallback to genesis
                        }
                    } else {
                        [[0u8; 32]; 2] // Fallback to genesis
                    }
                }
                Err(_) => [[0u8; 32]; 2], // Fallback to genesis on parse error
            }
        }
        Err(_) => [[0u8; 32]; 2], // Fallback to genesis on RPC error
    };

    // Create transaction with proper parents from DAG tips
    // Sender is already the first 32 bytes of public_key (matches GUI logic)
    let tx = Transaction::new(
        parents,
        sender_address,
        receiver_address,
        amount,
        fee,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64,
        0,             // Initial PoW nonce (will be mined)
        account_nonce, // Fetched from RPC
        vec![0u8; 64], // Will be signed
        wallet.public_key_bytes(),
    );

    // Mine nonce locally first
    let difficulty = Transaction::default_difficulty();
    println!("{}", "⛏️  Mining transaction...".yellow());
    let start = std::time::Instant::now();
    let nonce = tx.mine_nonce(difficulty);
    let elapsed = start.elapsed();
    println!(
        "{} Nonce: {} (took {:.2}s)",
        "✓ Mined".green(),
        nonce,
        elapsed.as_secs_f64()
    );

    // Update transaction with mined nonce
    let mut signed_tx = tx.clone();
    signed_tx.nonce = nonce;

    // Re-compute hash with mined nonce (this will be the final tx.id)
    signed_tx.id = signed_tx.compute_hash();

    // Sign transaction with the signing hash (excludes signature and public_key)
    let _signing_hash = signed_tx.compute_signing_hash();
    let signature = wallet.sign_transaction(&signed_tx)?;
    signed_tx.signature = signature.clone();

    // Prepare RPC request
    let client = reqwest::Client::new();
    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "aether_sendTransaction",
        "params": [hex::encode(bincode::serialize(&signed_tx)?)],
        "id": 1
    });

    // Send to RPC server
    let response = match client.post(rpc_url).json(&rpc_payload).send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("{}", "⚠️  Failed to connect to RPC server".yellow());
            eprintln!("  URL: {}", rpc_url.cyan());
            eprintln!("  Error: {}", e);
            eprintln!("  Make sure the node is running with RPC enabled");
            std::process::exit(1);
        }
    };

    // Parse RPC response (errors are returned as HTTP 200 with a JSON "error" field)
    let body = response.text().await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;
    if let Some(err) = json.get("error") {
        eprintln!(
            "{}",
            format!(
                "✗ Transaction REJECTED by node: {}",
                err.get("message").and_then(|m| m.as_str()).unwrap_or(&body)
            )
            .red()
        );
        std::process::exit(1);
    }
    if let Some(result) = json.get("result") {
        if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
            if status != "accepted" && status != "in_mempool" {
                eprintln!(
                    "{}",
                    format!("✗ Transaction not accepted: {} ({})", status, result)
                        .red()
                );
                std::process::exit(1);
            }
        }
    }

    println!("{}", "✓ Transaction sent & signed!".green());
    println!("  Sender: {}", wallet.address_string().cyan());
    println!("  Receiver: {}", receiver_hex.cyan());
    println!("  Amount: {}", amount.to_string().cyan());
    println!("  Fee: {}", fee.to_string().cyan());
    println!("  Nonce: {}", nonce.to_string().cyan());
    println!("  Signature: {}", hex::encode(&signature).cyan());

    Ok(())
}

/// Balance client for querying balance via RPC
async fn balance_client(
    address_hex: &str,
    rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prepare RPC request
    let client = reqwest::Client::new();
    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "aether_getBalance",
        "params": [address_hex],
        "id": 1
    });

    // Send to RPC server
    let response = match client.post(rpc_url).json(&rpc_payload).send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("{}", "⚠️  Failed to connect to RPC server".yellow());
            eprintln!("  URL: {}", rpc_url.cyan());
            eprintln!("  Error: {}", e);
            eprintln!("  Make sure the node is running with RPC enabled");
            std::process::exit(1);
        }
    };

    if response.status().is_success() {
        let response_text = response.text().await?;
        let response_json: serde_json::Value = serde_json::from_str(&response_text)?;

        if let Some(result) = response_json.get("result") {
            let balance = result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("{}", "✓ Balance retrieved".green());
            println!("  Address: {}", address_hex.cyan());
            println!(
                "  Balance: {} AETH",
                (balance / 10_000_000_000).to_string().cyan()
            );
        } else if let Some(error) = response_json.get("error") {
            eprintln!("{}", format!("✗ RPC error: {}", error).red());
            std::process::exit(1);
        }
    } else {
        let error_text = response.text().await?;
        eprintln!(
            "{}",
            format!("✗ Failed to get balance: {}", error_text).red()
        );
        std::process::exit(1);
    }

    Ok(())
}
