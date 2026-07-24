use clap::Parser;
use eframe::egui;
use eframe::egui::{Color32, Vec2, IconData};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use aether_unified::config::NodeConfig;
use aether_unified::wallet::Wallet;

#[derive(Parser)]
#[command(name = "aether-gui", version = "1.3.0", about = "AETHER SEDC")]
struct Cli {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    node_type: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    p2p_port: Option<u16>,
    #[arg(long)]
    rpc_port: Option<u16>,
    #[arg(long)]
    bootnodes: Option<String>,
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
    let client = Client::builder().timeout(std::time::Duration::from_secs(3)).build().map_err(|e| e.to_string())?;
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

#[derive(Clone)]
struct GuiState {
    status: String,
    status_color: Color32,
    balance: String,
    peers: String,
    transactions: String,
    send_result: String,
    dag_stats: String,
    address: String,
    wallet: bool,
    mnemonic: String,
    secret_key: String,
}

impl Default for GuiState {
    fn default() -> Self {
        Self {
            status: "Starting...".to_string(),
            status_color: Color32::YELLOW,
            balance: "0 AETH".to_string(),
            peers: "0".to_string(),
            transactions: "0".to_string(),
            send_result: String::new(),
            dag_stats: String::new(),
            address: String::new(),
            wallet: false,
            mnemonic: String::new(),
            secret_key: String::new(),
        }
    }
}

struct AetherGui {
    rpc_url: String,
    state: Arc<Mutex<GuiState>>,
    recipient: String,
    amount: String,
    last_refresh: Instant,
}

impl eframe::App for AetherGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed().as_secs() >= 2 {
            let state = self.state.clone();
            let url = self.rpc_url.clone();
            ctx.request_repaint();
            std::thread::spawn(move || {
                Self::refresh_background(&url, state);
            });
            self.last_refresh = Instant::now();
        }

        let state = self.state.lock().unwrap().clone();
        let status_color = state.status_color;
        let connected = state.status == "Connected";

        egui::TopBottomPanel::top("header").min_height(36.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label("\u{2B22}");
                ui.heading("AETHER");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    ui.colored_label(status_color, &state.status);
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            egui::Grid::new("stats").min_col_width(80.0).max_col_width(120.0).show(ui, |ui| {
                ui.label("Balance:");
                ui.heading(&state.balance);
                ui.end_row();
                ui.label("Peers:");
                ui.label(&state.peers);
                ui.end_row();
                ui.label("Transactions:");
                ui.label(&state.transactions);
                ui.end_row();
            });

            ui.separator();

            ui.heading("Wallet");
            ui.horizontal(|ui| {
                if ui.button("Create Wallet").clicked() {
                    let w = Wallet::new_with_mnemonic();
                    let addr = w.address_string();
                    let sk = w.secret_key_hex.clone();
                    let mn = w.mnemonic.clone().unwrap_or_default();
                    let mut s = self.state.lock().unwrap();
                    s.address = addr;
                    s.wallet = true;
                    s.secret_key = sk;
                    s.mnemonic = mn;
                    s.status = "Wallet created".to_string();
                    s.status_color = Color32::GREEN;
                }
                if state.wallet && connected {
                    if ui.button("Faucet").clicked() {
                        let addr = state.address.clone();
                        let url = self.rpc_url.clone();
                        let state = self.state.clone();
                        std::thread::spawn(move || {
                            match rpc_call(&url, "aether_faucet", serde_json::json!([addr])) {
                                Ok(r) => { let mut s = state.lock().unwrap(); s.send_result = format!("Faucet: {}", r); }
                                Err(e) => { let mut s = state.lock().unwrap(); s.send_result = format!("Error: {}", e); }
                            }
                        });
                    }
                }
            });
            if !state.address.is_empty() {
                ui.label("Address:");
                ui.monospace(&state.address);
                if !state.mnemonic.is_empty() {
                    ui.label("Recovery phrase:");
                    ui.monospace(&state.mnemonic);
                }
            }
            if !state.send_result.is_empty() {
                ui.separator();
                ui.label(&state.send_result);
            }

            ui.separator();

            if state.wallet {
                ui.heading("Send");
                ui.horizontal(|ui| {
                    ui.label("To:");
                    ui.text_edit_singleline(&mut self.recipient);
                });
                ui.horizontal(|ui| {
                    ui.label("Amount:");
                    ui.text_edit_singleline(&mut self.amount);
                });
                if ui.button("Send").clicked() && connected {
                    let addr = self.recipient.clone();
                    let amt: u64 = self.amount.parse().unwrap_or(0);
                    let url = self.rpc_url.clone();
                    let state = self.state.clone();
                    std::thread::spawn(move || {
                        if addr.len() == 64 && amt > 0 {
                            match rpc_call(&url, "aether_sendTransaction", serde_json::json!([addr, amt])) {
                                Ok(r) => { let mut s = state.lock().unwrap(); s.send_result = format!("Sent: {}", r); }
                                Err(e) => { let mut s = state.lock().unwrap(); s.send_result = format!("Error: {}", e); }
                            }
                        } else {
                            let mut s = state.lock().unwrap();
                            s.send_result = "Invalid address or amount".to_string();
                        }
                    });
                }
            }

            if !state.dag_stats.is_empty() {
                ui.separator();
                ui.heading("Network");
                ui.monospace(&state.dag_stats);
            }
        });
    }
}

impl AetherGui {
    fn refresh_background(url: &str, state: Arc<Mutex<GuiState>>) {
        match rpc_call(url, "aether_getMiningStatus", serde_json::json!([])) {
            Ok(_) => {
                let mut s = state.lock().unwrap();
                s.status = "Connected".to_string();
                s.status_color = Color32::GREEN;
            }
            Err(_) => {
                let mut s = state.lock().unwrap();
                s.status = "Disconnected".to_string();
                s.status_color = Color32::RED;
                return;
            }
        }

        if let Ok(stats) = rpc_call(url, "aether_getDagStats", serde_json::json!([])) {
            let mut s = state.lock().unwrap();
            if let Some(tx_count) = stats.get("transaction_count").and_then(|v| v.as_u64()) {
                s.transactions = tx_count.to_string();
            }
            if let Some(peer_count) = stats.get("peer_count").and_then(|v| v.as_u64()) {
                s.peers = peer_count.to_string();
            }
            s.dag_stats = serde_json::to_string_pretty(&stats).unwrap_or_default();
        }

        let addr = { state.lock().unwrap().address.clone() };
        if !addr.is_empty() {
            if let Ok(bal) = rpc_call(url, "aether_getBalance", serde_json::json!([addr])) {
                let mut s = state.lock().unwrap();
                s.balance = format!("{} AETH", bal);
            }
        }
    }
}

fn load_icon() -> IconData {
    let w = 32;
    let h = 32;
    let mut rgba = vec![0u8; w * h * 4];
    for y in 0..h {
        for x in 0..w {
            let i = (y * w + x) * 4;
            let cx = x as f64;
            let cy = y as f64;
            let left = 16.0 - (cy - 3.0) * 0.4;
            let right = 16.0 + (cy - 3.0) * 0.4;
            let in_a = cx >= left && cx <= right && cy >= 3.0 && cy <= 28.0;
            let crossbar = cy >= 16.0 && cy <= 19.0 && cx >= 11.0 && cx <= 21.0;
            let inner = cx >= left + 2.0 && cx <= right - 2.0 && cy >= 7.0 && cy <= 28.0 && !crossbar;
            if (in_a || crossbar) && !inner {
                rgba[i] = 0; rgba[i + 1] = 212; rgba[i + 2] = 255; rgba[i + 3] = 255;
            } else {
                rgba[i] = 26; rgba[i + 1] = 26; rgba[i + 2] = 46; rgba[i + 3] = 255;
            }
        }
    }
    IconData { rgba, width: w as u32, height: h as u32 }
}

fn main() -> eframe::Result<()> {
    let cli = Cli::parse_from(std::env::args_os());

    let mut cfg = if let Some(ref config_path) = cli.config {
        NodeConfig::load(config_path).unwrap_or_default()
    } else {
        NodeConfig::default()
    };
    if let Some(ref nt) = cli.node_type { cfg.node_type = nt.clone(); }
    if let Some(ref dd) = cli.data_dir { cfg.data_dir = dd.clone(); }
    if let Some(pp) = cli.p2p_port { cfg.p2p_port = pp; }
    if let Some(rp) = cli.rpc_port { cfg.rpc_port = rp; }
    if let Some(ref bn) = cli.bootnodes { cfg.bootnodes = bn.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(); }
    if cli.reset { cfg.reset = true; }

    let rpc_port = cfg.rpc_port;
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

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

    std::thread::sleep(std::time::Duration::from_secs(2));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(520.0, 440.0))
            .with_min_inner_size(Vec2::new(400.0, 350.0))
            .with_icon(Arc::new(load_icon()))
            .with_title("AETHER SEDC"),
        ..Default::default()
    };

    let gui = AetherGui {
        rpc_url,
        state: Arc::new(Mutex::new(GuiState::default())),
        recipient: String::new(),
        amount: String::new(),
        last_refresh: Instant::now(),
    };

    eframe::run_native("AETHER SEDC", options, Box::new(|_cc| Box::new(gui)))
}
