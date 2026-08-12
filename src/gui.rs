#![windows_subsystem = "windows"]

use clap::{Parser, Subcommand};
use eframe::egui;
use eframe::egui::{Color32, Frame, IconData, Margin, Rounding, Vec2};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use aether_unified::config::NodeConfig;
use aether_unified::json_storage::save_dag_to_json;
use aether_unified::transaction::Transaction;
use aether_unified::wallet::Wallet;

#[derive(Parser)]
#[command(name = "aether", version = "1.1.1", about = "AETHER SEDC")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

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
    miner_address: Option<String>,
    #[arg(long)]
    reset: bool,
    /// Run in daemon (headless) mode instead of GUI
    #[arg(long)]
    daemon: bool,
    /// Rebuild the ledger (balances) from genesis + DAG replay on startup
    #[arg(long)]
    repair_ledger: bool,
}

#[derive(Subcommand)]
enum Commands {
    Keygen {
        #[arg(default_value = "wallet.json")]
        path: String,
        /// Import wallet from private key hex string
        #[arg(long)]
        import: Option<String>,
        /// Import wallet from file containing private key hex
        #[arg(long)]
        import_file: Option<String>,
    },
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    Send {
        receiver: String,
        amount: u64,
        #[arg(default_value_t = 10)]
        fee: u64,
        #[arg(long, default_value = "http://127.0.0.1:9933")]
        rpc_url: String,
        #[arg(long, default_value = "wallet.json")]
        wallet: String,
        #[arg(long)]
        password: Option<String>,
    },
    Balance {
        address_or_wallet: String,
        #[arg(long, default_value = "http://127.0.0.1:9933")]
        rpc_url: String,
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum WalletAction {
    Create {
        #[arg(default_value = "wallet.json")]
        path: String,
    },
    Restore {
        #[arg(default_value = "wallet.json")]
        path: String,
        mnemonic: String,
    },
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

fn rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params,
        id: 1,
    };
    let response = client
        .post(url)
        .json(&request)
        .send()
        .map_err(|e| format!("Connection failed: {}", e))?;
    let rpc_response: RpcResponse = response.json().map_err(|e| format!("Parse error: {}", e))?;
    if let Some(error) = rpc_response.error {
        return Err(format!("RPC Error: {}", error));
    }
    rpc_response.result.ok_or_else(|| "No result".to_string())
}

#[derive(Clone, PartialEq)]
enum Tab {
    Overview,
    Send,
    Receive,
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
    active_tab: Tab,
}

const CARD_BG: Color32 = Color32::from_rgb(26, 26, 46);
const ACCENT: Color32 = Color32::from_rgb(0, 180, 255);
const TEXT_SECONDARY: Color32 = Color32::from_rgb(140, 140, 160);

fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    Frame::none()
        .fill(CARD_BG)
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::symmetric(12.0, 8.0))
        .show(ui, add_contents);
}

impl eframe::App for AetherGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed().as_secs() >= 2 {
            let state = self.state.clone();
            let url = self.rpc_url.clone();
            ctx.request_repaint();
            std::thread::spawn(move || Self::refresh_bg(&url, state));
            self.last_refresh = Instant::now();
        }

        let state = self.state.lock().unwrap().clone();
        let connected = state.status == "Connected";

        egui::TopBottomPanel::top("header")
            .min_height(44.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("\u{2B22}").size(20.0).color(ACCENT));
                    ui.label(
                        egui::RichText::new("AETHER")
                            .size(18.0)
                            .strong()
                            .color(Color32::WHITE),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(12.0);
                        ui.colored_label(state.status_color, &state.status);
                    });
                });
                ui.add_space(4.0);
            });

        egui::TopBottomPanel::bottom("footer")
            .min_height(28.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new(format!("Peers: {}", state.peers))
                            .size(11.0)
                            .color(TEXT_SECONDARY),
                    );
                    ui.label(
                        egui::RichText::new(format!("TX: {}", state.transactions))
                            .size(11.0)
                            .color(TEXT_SECONDARY),
                    );
                    if state.wallet {
                        ui.label(
                            egui::RichText::new("Wallet: active")
                                .size(11.0)
                                .color(Color32::GREEN),
                        );
                    }
                });
            });

        egui::SidePanel::left("tabs")
            .resizable(false)
            .exact_width(120.0)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                let tabs = [Tab::Overview, Tab::Send, Tab::Receive];
                let names = ["Overview", "Send", "Receive"];
                for (tab, name) in tabs.iter().zip(names.iter()) {
                    let sel = self.active_tab == *tab;
                    let btn = egui::Button::new(egui::RichText::new(*name).size(14.0))
                        .min_size(Vec2::new(96.0, 36.0))
                        .fill(if sel { ACCENT } else { Color32::TRANSPARENT })
                        .rounding(Rounding::same(6.0));
                    if ui.add(btn).clicked() {
                        self.active_tab = tab.clone();
                    }
                    ui.add_space(4.0);
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            match self.active_tab {
                Tab::Overview => self.show_overview(ui, &state, connected),
                Tab::Send => self.show_send(ui, &state, connected),
                Tab::Receive => self.show_receive(ui, &state),
            }
        });
    }
}

impl AetherGui {
    fn show_overview(&mut self, ui: &mut egui::Ui, state: &GuiState, connected: bool) {
        ui.heading("Overview");
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(egui::RichText::new("Balance").color(TEXT_SECONDARY));
            ui.heading(egui::RichText::new(&state.balance).size(28.0).color(ACCENT));
        });
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(egui::RichText::new("Network").color(TEXT_SECONDARY));
            ui.horizontal(|ui| {
                ui.label(format!("Peers: {}", state.peers));
                ui.add_space(16.0);
                ui.label(format!("Transactions: {}", state.transactions));
            });
        });
        if !state.address.is_empty() {
            ui.add_space(8.0);
            card(ui, |ui| {
                ui.label(egui::RichText::new("Address").color(TEXT_SECONDARY));
                ui.monospace(&state.address);
            });
        }
        if state.wallet && connected {
            ui.add_space(8.0);
            if ui
                .button(egui::RichText::new("Request Faucet").size(14.0))
                .clicked()
            {
                let addr = state.address.clone();
                let url = self.rpc_url.clone();
                let state = self.state.clone();
                std::thread::spawn(move || {
                    match rpc_call(&url, "aether_faucet", serde_json::json!([addr])) {
                        Ok(r) => {
                            let mut s = state.lock().unwrap();
                            s.send_result = format!("Faucet: {}", r);
                        }
                        Err(e) => {
                            let mut s = state.lock().unwrap();
                            s.send_result = format!("Error: {}", e);
                        }
                    }
                });
            }
        }
        if !state.send_result.is_empty() {
            ui.add_space(8.0);
            ui.label(&state.send_result);
        }
        if !state.dag_stats.is_empty() {
            ui.add_space(8.0);
            ui.separator();
            ui.label(
                egui::RichText::new("Node Info")
                    .color(TEXT_SECONDARY)
                    .size(11.0),
            );
            ui.monospace(&state.dag_stats);
        }
    }

    fn show_send(&mut self, ui: &mut egui::Ui, state: &GuiState, connected: bool) {
        ui.heading("Send");
        if !state.wallet {
            card(ui, |ui| {
                ui.label("Create a wallet first in the Receive tab.");
            });
            return;
        }
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(egui::RichText::new("Recipient Address").color(TEXT_SECONDARY));
            ui.text_edit_singleline(&mut self.recipient);
            ui.add_space(8.0);
            ui.label(egui::RichText::new("Amount (AETH)").color(TEXT_SECONDARY));
            ui.text_edit_singleline(&mut self.amount);
        });
        ui.add_space(8.0);
        if ui
            .button(egui::RichText::new("Send Transaction").size(14.0))
            .clicked()
            && connected
        {
            let addr = self.recipient.clone();
            let amt: u64 = self.amount.parse().unwrap_or(0);
            let url = self.rpc_url.clone();
            let state = self.state.clone();
            std::thread::spawn(move || {
                if addr.len() == 64 && amt > 0 {
                    match rpc_call(
                        &url,
                        "aether_sendTransaction",
                        serde_json::json!([addr, amt]),
                    ) {
                        Ok(r) => {
                            let mut s = state.lock().unwrap();
                            s.send_result = format!("Sent: {}", r);
                        }
                        Err(e) => {
                            let mut s = state.lock().unwrap();
                            s.send_result = format!("Error: {}", e);
                        }
                    }
                } else {
                    let mut s = state.lock().unwrap();
                    s.send_result = "Invalid address or amount".to_string();
                }
            });
        }
        if !state.send_result.is_empty() {
            ui.add_space(8.0);
            ui.label(&state.send_result);
        }
    }

    fn show_receive(&mut self, ui: &mut egui::Ui, state: &GuiState) {
        ui.heading("Receive");
        if !state.wallet {
            card(ui, |ui| {
                ui.label("Create a wallet to receive AETH.");
                ui.add_space(8.0);
                if ui.button("Create Wallet").clicked() {
                    let w = Wallet::new_with_mnemonic();
                    let mut s = self.state.lock().unwrap();
                    s.address = w.address_string();
                    s.wallet = true;
                    s.secret_key = w.secret_key_hex.clone();
                    s.mnemonic = w.mnemonic.unwrap_or_default();
                    s.status = "Wallet created".to_string();
                    s.status_color = Color32::GREEN;
                }
            });
            return;
        }
        card(ui, |ui| {
            ui.label(egui::RichText::new("Your Address").color(TEXT_SECONDARY));
            ui.add_space(4.0);
            ui.monospace(&state.address);
        });
        if !state.mnemonic.is_empty() {
            ui.add_space(8.0);
            card(ui, |ui| {
                ui.colored_label(Color32::YELLOW, "Recovery Phrase (SAVE THIS)");
                ui.add_space(4.0);
                ui.monospace(&state.mnemonic);
            });
        }
    }

    fn refresh_bg(url: &str, state: Arc<Mutex<GuiState>>) {
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
            if let Some(tx) = stats.get("transaction_count").and_then(|v| v.as_u64()) {
                s.transactions = tx.to_string();
            }
            if let Some(pc) = stats.get("peer_count").and_then(|v| v.as_u64()) {
                s.peers = pc.to_string();
            }
            s.dag_stats = serde_json::to_string_pretty(&stats).unwrap_or_default();
        }
        let addr = { state.lock().unwrap().address.clone() };
        if !addr.is_empty() {
            if let Ok(bal) = rpc_call(url, "aether_getBalance", serde_json::json!([addr])) {
                state.lock().unwrap().balance = format!("{} AETH", bal);
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
            let inner =
                cx >= left + 2.0 && cx <= right - 2.0 && cy >= 7.0 && cy <= 28.0 && !crossbar;
            if (in_a || crossbar) && !inner {
                rgba[i] = 0;
                rgba[i + 1] = 180;
                rgba[i + 2] = 255;
                rgba[i + 3] = 255;
            } else {
                rgba[i] = 18;
                rgba[i + 1] = 18;
                rgba[i + 2] = 28;
                rgba[i + 3] = 255;
            }
        }
    }
    IconData {
        rgba,
        width: w as u32,
        height: h as u32,
    }
}

async fn send_transaction_client(
    wallet_path: &str,
    receiver_hex: &str,
    amount: u64,
    fee: u64,
    rpc_url: &str,
    password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = Wallet::from_file(wallet_path, password)
        .await
        .map_err(|e| {
            if e.to_string().contains("Password required") {
                eprintln!("Password required. Use --password");
            }
            e
        })?;
    let sender_address = wallet.address();
    let receiver_address: [u8; 32] = hex::decode(receiver_hex)?
        .try_into()
        .map_err(|_| "Invalid receiver hex")?;
    let client = reqwest::Client::new();
    let nonce_resp = client.post(rpc_url).json(&serde_json::json!({"jsonrpc":"2.0","method":"aether_getAccountNonce","params":[hex::encode(sender_address)],"id":1})).send().await?;
    let nonce_json: serde_json::Value = nonce_resp.json().await?;
    let account_nonce = nonce_json["result"]["next_nonce"]
        .as_u64()
        .ok_or("No nonce")?;
    let tips_resp = client
        .post(rpc_url)
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"aether_getTips","params":[],"id":2}))
        .send()
        .await?;
    let tips_json: serde_json::Value = tips_resp.json().await?;
    let mut parents = [[0u8; 32]; 2];
    if let Some(tips) = tips_json["result"]["tips"].as_array() {
        for (i, tip) in tips.iter().take(2).enumerate() {
            if let Some(ts) = tip.as_str() {
                if let Ok(tb) = hex::decode(ts) {
                    if tb.len() == 32 {
                        parents[i].copy_from_slice(&tb);
                    }
                }
            }
        }
    }
    let tx = Transaction::new(
        parents,
        sender_address,
        receiver_address,
        amount,
        fee,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    let difficulty = Transaction::default_difficulty();
    println!("Mining transaction...");
    let start = std::time::Instant::now();
    let nonce = tx.mine_nonce(difficulty);
    println!(
        "Mined nonce: {} ({:.2}s)",
        nonce,
        start.elapsed().as_secs_f64()
    );
    let mut signed_tx = tx.clone();
    signed_tx.nonce = nonce;
    signed_tx.id = signed_tx.compute_hash();
    let signature = wallet.sign_transaction(&signed_tx)?;
    signed_tx.signature = signature.clone();
    let send_resp = client.post(rpc_url).json(&serde_json::json!({"jsonrpc":"2.0","method":"aether_sendTransaction","params":[hex::encode(bincode::serialize(&signed_tx)?)],"id":1})).send().await?;
    if let Ok(body) = send_resp.text().await {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(err) = json.get("error") {
                eprintln!(
                    "REJECTED by node: {}",
                    err.get("message").and_then(|m| m.as_str()).unwrap_or(&body)
                );
                std::process::exit(1);
            }
            if let Some(result) = json.get("result") {
                if let Some(status) = result.get("status").and_then(|s| s.as_str()) {
                    if status != "accepted" && status != "in_mempool" {
                        eprintln!("Not accepted: {} ({})", status, result);
                        std::process::exit(1);
                    }
                }
            }
            println!("Transaction sent! Amount: {} to {}", amount, receiver_hex);
            return Ok(());
        }
        eprintln!("Failed: {}", body);
    } else {
        eprintln!("Failed: no response body");
    }
    std::process::exit(1);
    #[allow(unreachable_code)]
    Ok(())
}

async fn balance_client(
    address_hex: &str,
    rpc_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let resp = client.post(rpc_url).json(&serde_json::json!({"jsonrpc":"2.0","method":"aether_getBalance","params":[address_hex],"id":1})).send().await?;
    if resp.status().is_success() {
        let json: serde_json::Value = resp.json().await?;
        if let Some(result) = json.get("result") {
            let balance = result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("Balance: {} AETH", balance / 10_000_000_000);
        }
    } else {
        eprintln!("RPC error");
        std::process::exit(1);
    }
    Ok(())
}

fn run_gui(cfg: NodeConfig) -> eframe::Result<()> {
    let rpc_port = cfg.rpc_port;
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            if let Err(e) = aether_unified::node::run_node(cfg).await {
                tracing::error!("Node error: {}", e);
            }
        });
    });

    std::thread::sleep(std::time::Duration::from_secs(2));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(Vec2::new(640.0, 480.0))
            .with_min_inner_size(Vec2::new(480.0, 360.0))
            .with_icon(Arc::new(load_icon()))
            .with_title("AETHER SEDC"),
        ..Default::default()
    };

    eframe::run_native(
        "AETHER SEDC",
        options,
        Box::new(|_cc| {
            Box::new(AetherGui {
                rpc_url,
                state: Arc::new(Mutex::new(GuiState::default())),
                recipient: String::new(),
                amount: String::new(),
                last_refresh: Instant::now(),
                active_tab: Tab::Overview,
            })
        }),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse_from(std::env::args_os());

    match &cli.command {
        Some(Commands::Keygen {
            path,
            import,
            import_file,
        }) => {
            let wallet: Wallet = if let Some(sk) = import {
                Wallet::from_secret_key(sk)?
            } else if let Some(file_path) = import_file {
                let content = tokio::fs::read_to_string(file_path).await?;
                let sk = content.trim();
                Wallet::from_secret_key(sk)?
            } else {
                Wallet::new()
            };
            wallet.to_file(path, None).await?;
            println!("Wallet saved to {}", path);
            println!("Address: {}", hex::encode(wallet.address()));
            return Ok(());
        }
        Some(Commands::Wallet { action }) => match action {
            WalletAction::Create { path } => {
                let wallet = Wallet::new_with_mnemonic();
                print!("Encrypt wallet password: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut pw = String::new();
                std::io::stdin().read_line(&mut pw)?;
                let pw = pw.trim();
                if pw.is_empty() {
                    eprintln!("Password required");
                    std::process::exit(1);
                }
                wallet.to_file(path, Some(pw)).await?;
                println!("Wallet created at {}", path);
                println!("Address: {}", wallet.address_string());
                println!(
                    "Mnemonic: {}",
                    wallet.mnemonic.as_deref().unwrap_or("<none>")
                );
                return Ok(());
            }
            WalletAction::Restore { path, mnemonic } => {
                let wallet = Wallet::from_mnemonic(mnemonic)?;
                wallet.to_file(path, None).await?;
                println!("Wallet restored at {}", path);
                println!("Address: {}", wallet.address_string());
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
            send_transaction_client(
                wallet,
                receiver,
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
                println!("Address: {}", hex::encode(w.address()));
                hex::encode(w.address())
            } else {
                address_or_wallet.clone()
            };
            balance_client(&address_hex, rpc_url).await?;
            return Ok(());
        }
        None => {}
    }

    let mut cfg = if let Some(ref config_path) = cli.config {
        NodeConfig::load(config_path).unwrap_or_default()
    } else {
        NodeConfig::default()
    };

    if let Some(ref nt) = cli.node_type {
        cfg.node_type = nt.clone();
    }
    if let Some(ref dd) = cli.data_dir {
        cfg.data_dir = dd.clone();
    }
    if let Some(pp) = cli.p2p_port {
        cfg.p2p_port = pp;
    }
    if let Some(rp) = cli.rpc_port {
        cfg.rpc_port = rp;
    }
    if let Some(ref bn) = cli.bootnodes {
        cfg.bootnodes = bn
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if cli.reset {
        cfg.reset = true;
    }
    if cli.repair_ledger {
        cfg.repair_ledger = true;
    }

    if cli.daemon
        || cli.node_type.is_some()
        || cli.p2p_port.is_some()
        || cli.rpc_port.is_some()
        || cli.bootnodes.is_some()
    {
        let handles = aether_unified::node::run_node(cfg).await?;
        tokio::signal::ctrl_c().await?;
        tracing::info!("Shutting down...");
        if let Ok(dag) = handles.dag.try_read() {
            let _ = save_dag_to_json(&dag, &handles.dag_store_path).await;
        };
        if let Ok(storage) = handles.storage.try_read() {
            let _ = storage.flush();
        };
    } else {
        run_gui(cfg)?;
    }
    Ok(())
}
