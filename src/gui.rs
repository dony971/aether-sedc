use clap::Parser;
use eframe::egui;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use aether_unified::config::NodeConfig;
use aether_unified::wallet::Wallet;

#[derive(Parser)]
#[command(name = "aether-gui", version = "1.2.0", about = "AETHER SEDC GUI")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "miner")]
    node_type: String,
    #[arg(long, default_value = "./data-gui")]
    data_dir: PathBuf,
    #[arg(long, default_value_t = 25565)]
    p2p_port: u16,
    #[arg(long, default_value_t = 9933)]
    rpc_port: u16,
    #[arg(long)]
    bootnodes: Option<String>,
    #[arg(long)]
    dns_seeds: Option<String>,
    #[arg(long)]
    miner_address: Option<String>,
    #[arg(long)]
    reset: bool,
}

#[derive(Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u32,
}

#[derive(Serialize, Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let client = Client::builder().timeout(std::time::Duration::from_secs(5)).build().map_err(|e| e.to_string())?;
    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params,
        id: 1,
    };
    let response = client.post(url).json(&request).send().map_err(|e| format!("Connection failed: {}", e))?;
    let rpc_response: RpcResponse = response.json().map_err(|e| format!("Parse error: {}", e))?;
    if let Some(error) = rpc_response.error {
        return Err(format!("RPC Error: {}", error));
    }
    rpc_response.result.ok_or_else(|| "No result".to_string())
}

#[derive(Default)]
struct AetherGui {
    rpc_url: String,
    wallet: Option<Wallet>,
    address: String,
    status: String,
    status_color: egui::Color32,
    balance: String,
    peers: String,
    transactions: String,
    recipient: String,
    amount: String,
    send_result: String,
    auto_refresh: bool,
    dag_stats: String,
}

impl eframe::App for AetherGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.auto_refresh {
            ctx.request_repaint_after(std::time::Duration::from_secs(3));
            self.refresh_status();
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🚀 AETHER SEDC");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(&self.status);
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                // Dashboard cards
                egui::Grid::new("stats").min_col_width(100.0).show(ui, |ui| {
                    ui.label("💰 Balance:");
                    ui.label(&self.balance);
                    ui.end_row();

                    ui.label("👥 Peers:");
                    ui.label(&self.peers);
                    ui.end_row();

                    ui.label("📦 Transactions:");
                    ui.label(&self.transactions);
                    ui.end_row();
                });

                ui.separator();

                // Wallet section
                ui.heading("🔑 Wallet");
                ui.horizontal(|ui| {
                    if ui.button("Create Wallet").clicked() {
                        let w = Wallet::new_with_mnemonic();
                        self.address = w.address_string();
                        self.wallet = Some(w);
                        self.status = "✅ Wallet created".to_string();
                        self.status_color = egui::Color32::GREEN;
                    }
                    if ui.button("Show Key").clicked() {
                        if let Some(ref w) = self.wallet {
                            self.status = format!("🔑 Key: {}", w.secret_key_hex);
                        }
                    }
                    if ui.button("Use Faucet").clicked() {
                        if !self.address.is_empty() {
                            match rpc_call(&self.rpc_url, "aether_faucet", serde_json::json!([self.address])) {
                                Ok(r) => self.send_result = format!("✅ Faucet: {}", r),
                                Err(e) => self.send_result = format!("❌ {}", e),
                            }
                        }
                    }
                });
                if !self.address.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label("Address:");
                        ui.monospace(&self.address);
                    });
                }

                ui.separator();

                // Send section
                ui.heading("📤 Send");
                ui.horizontal(|ui| {
                    ui.label("To:");
                    ui.text_edit_singleline(&mut self.recipient);
                });
                ui.horizontal(|ui| {
                    ui.label("Amount:");
                    ui.text_edit_singleline(&mut self.amount);
                });
                if ui.button("Send").clicked() {
                    if let Some(ref wallet) = self.wallet {
                        let addr = self.recipient.clone();
                        let amt: u64 = self.amount.parse().unwrap_or(0);
                        let amount = amt;
                        if addr.len() == 64 && amount > 0 {
                            match rpc_call(&self.rpc_url, "aether_sendTransaction", serde_json::json!([addr, amount])) {
                                Ok(r) => self.send_result = format!("✅ Sent: {}", r),
                                Err(e) => self.send_result = format!("❌ {}", e),
                            }
                        } else {
                            self.send_result = "❌ Invalid address or amount".to_string();
                        }
                    } else {
                        self.send_result = "❌ Create a wallet first".to_string();
                    }
                }
                if !self.send_result.is_empty() {
                    ui.label(&self.send_result);
                }

                ui.separator();

                // Network section
                ui.heading("📊 Network");
                ui.horizontal(|ui| {
                    if ui.button("Refresh Stats").clicked() {
                        self.refresh_status();
                    }
                    ui.checkbox(&mut self.auto_refresh, "Auto-refresh");
                });
                if !self.dag_stats.is_empty() {
                    ui.monospace(&self.dag_stats);
                }
            });
        });
    }
}

impl AetherGui {
    fn refresh_status(&mut self) {
        // Check connection
        match rpc_call(&self.rpc_url, "aether_getMiningStatus", serde_json::json!([])) {
            Ok(_) => {
                self.status = "🟢 Connected".to_string();
                self.status_color = egui::Color32::GREEN;
            }
            Err(_) => {
                self.status = "🔴 Disconnected".to_string();
                self.status_color = egui::Color32::RED;
                return;
            }
        }

        // Get stats
        if let Ok(stats) = rpc_call(&self.rpc_url, "aether_getDagStats", serde_json::json!([])) {
            if let Some(tx_count) = stats.get("transaction_count").and_then(|v| v.as_u64()) {
                self.transactions = tx_count.to_string();
            }
            if let Some(peer_count) = stats.get("peer_count").and_then(|v| v.as_u64()) {
                self.peers = peer_count.to_string();
            }
            self.dag_stats = serde_json::to_string_pretty(&stats).unwrap_or_default();
        }

        // Get balance
        if !self.address.is_empty() {
            if let Ok(bal) = rpc_call(&self.rpc_url, "aether_getBalance", serde_json::json!([self.address.clone()])) {
                self.balance = format!("{} AETH", bal);
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse_from(std::env::args_os());

    // Build config
    let mut cfg = if let Some(ref config_path) = cli.config {
        NodeConfig::load(config_path).unwrap_or_default()
    } else {
        NodeConfig::default()
    };
    if cli.node_type != "miner" { cfg.node_type = cli.node_type; }
    if cli.data_dir != PathBuf::from("./data-gui") { cfg.data_dir = cli.data_dir; }
    if cli.p2p_port != 25565 { cfg.p2p_port = cli.p2p_port; }
    if cli.rpc_port != 9933 { cfg.rpc_port = cli.rpc_port; }
    if let Some(ref bn) = cli.bootnodes { cfg.bootnodes = bn.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(); }
    if let Some(ref ds) = cli.dns_seeds { cfg.dns_seeds = ds.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(); }
    if cli.miner_address.is_some() { cfg.miner_address = cli.miner_address; }
    if cli.reset { cfg.reset = true; }

    let rpc_port = cfg.rpc_port;
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

    // Spawn node in background
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");
        rt.block_on(async {
            if let Err(e) = aether_unified::node::run_node(cfg).await {
                tracing::error!("Node error: {}", e);
            }
        });
    });

    // Wait a moment for node to start, then launch GUI
    std::thread::sleep(std::time::Duration::from_secs(2));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_title("AETHER SEDC"),
        ..Default::default()
    };

    let mut gui = AetherGui::default();
    gui.rpc_url = rpc_url;
    gui.auto_refresh = true;

    eframe::run_native("AETHER SEDC", options, Box::new(|_cc| Box::new(gui)))
}
