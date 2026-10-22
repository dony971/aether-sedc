// Phase 4CP-BO baseline tests

use aether_unified::genesis::{initialize_genesis, GenesisConfig};
use aether_unified::ledger::Ledger;
use aether_unified::p2p::{IngressTx, P2PConfig, P2PNetwork, P2PProtocolMode, TX_INGRESS_CAPACITY_MSGS};
use aether_unified::parent_selection::DAG;
use aether_unified::stake::{current_epoch, StakeRegistry};
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone)]
struct BenchResult {
    scenario: String,
    sha: String,
    profile: String,
    os: String,
    arch: String,
    nodes: usize,
    transactions_submitted: usize,
    transactions_applied: usize,
    duration_total_ms: u64,
    duration_generation_ms: u64,
    duration_propagation_ms: u64,
    tps_applied: f64,
    latency_median_ms: Option<u64>,
    latency_p95_ms: Option<u64>,
    latency_p99_ms: Option<u64>,
    duplicates_rejected: u64,
    memory_rss_kb: Option<u64>,
}

fn get_sha() -> String {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        let sha = sha.trim();
        if !sha.is_empty() { return sha.to_string(); }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| if out.status.success() { String::from_utf8(out.stdout).ok() } else { None })
        .map(|sha| sha.trim().to_string())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
fn get_profile() -> String { if cfg!(debug_assertions) { "debug".to_string() } else { "release".to_string() } }
fn get_os() -> String { std::env::consts::OS.to_string() }
fn get_arch() -> String { std::env::consts::ARCH.to_string() }

fn get_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/proc/self/status") {
            for line in contents.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<u64>() { return Some(kb); }
                    }
                }
            }
        }
    }
    None
}

fn log_jsonl(result: &BenchResult) {
    println!("BENCH_JSONL:{{\"scenario\":\"{}\",\"sha\":\"{}\",\"profile\":\"{}\",\"os\":\"{}\",\"arch\":\"{}\",\"nodes\":{},\"transactions_submitted\":{},\"transactions_applied\":{},\"duration_total_ms\":{},\"duration_generation_ms\":{},\"duration_propagation_ms\":{},\"tps_applied\":{},\"latency_median_ms\":{},\"latency_p95_ms\":{},\"latency_p99_ms\":{},\"duplicates_rejected\":{},\"memory_rss_kb\":{}}}",
        result.scenario, result.sha, result.profile, result.os, result.arch,
        result.nodes, result.transactions_submitted, result.transactions_applied,
        result.duration_total_ms, result.duration_generation_ms, result.duration_propagation_ms,
        result.tps_applied,
        result.latency_median_ms.map(|v| v.to_string()).unwrap_or("null".to_string()),
        result.latency_p95_ms.map(|v| v.to_string()).unwrap_or("null".to_string()),
        result.latency_p99_ms.map(|v| v.to_string()).unwrap_or("null".to_string()),
        result.duplicates_rejected,
        result.memory_rss_kb.map(|v| v.to_string()).unwrap_or("null".to_string())
    );
}

const PORT_A_BO: u16 = 55731;
const PORT_B_BO: u16 = 55732;

fn unique_dir_bo(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aether-4bo-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

async fn wait_for_bo<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where F: FnMut() -> Fut, Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(timeout, async {
        loop { if cond().await { return; } tokio::time::sleep(Duration::from_millis(50)).await; }
    })
    .await
    .unwrap_or_else(|_| panic!("TIMEOUT waiting for: {}", what));
}

fn wallet_bo(n: u64) -> Wallet { Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key") }

fn make_valid_tx_bo(wallet: &Wallet, parents: [[u8; 32]; 2], account_nonce: u64, timestamp: u64) -> Transaction {
    let mut tx = Transaction::new(parents, wallet.address(), [0xBBu8; 32], 1000, 1, timestamp, 0, account_nonce, vec![0u8; 64], wallet.public_key_bytes());
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    TransactionProcessor::new().validate_pure(&tx, ValidationMode::Historical).expect("freshly mined+signed tx must pass");
    tx
}

fn record_tx_bo(dag: &mut DAG, store: &Storage, processor: &TransactionProcessor, tx: &Transaction) -> Result<(), String> {
    processor.validate_pure(tx, ValidationMode::Historical).map_err(|e| format!("pure gate: {:?}", e))?;
    dag.add_transaction_validated(tx.clone()).map_err(|e| format!("dag insert: {}", e))?;
    store.put_transaction(tx).map_err(|e| format!("persist: {}", e))?;
    store.mark_applied(tx.id).map_err(|e| format!("applied mark: {}", e))?;
    Ok(())
}

struct TestNodeBo {
    _dir_guard: tempfile::TempDir,
    storage: Arc<RwLock<Storage>>,
    dag: Arc<RwLock<DAG>>,
    p2p: Arc<P2PNetwork>,
    rx: mpsc::Receiver<IngressTx>,
}

async fn boot_node_bo(dir: tempfile::TempDir, port: u16, bootnodes: Vec<std::net::SocketAddr>) -> TestNodeBo {
    let storage = Arc::new(RwLock::new(Storage::open(dir.path()).expect("open store")));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let (tx_sender, rx) = mpsc::channel::<IngressTx>(TX_INGRESS_CAPACITY_MSGS);
    let dag_c = dag.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on_bo(async { dag_c.read().await.transactions().keys().map(|id| id.to_vec()).collect() })
    });
    let dag_c = dag.clone();
    let storage_c2 = storage.clone();
    let get_tx: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(move |hash| {
        __test_only_block_on_bo(async {
            if let Ok(id) = <[u8; 32]>::try_from(hash) {
                if let Ok(g) = dag_c.try_read() { if let Some(tx) = g.transactions().get(&id) { return Some(tx.clone()); } }
                if let Ok(s) = storage_c2.try_read() { if let Ok(tx) = s.get_transaction(id) { return Some(tx); } }
            }
            None
        })
    });
    let dag_c = dag.clone();
    let get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on_bo(async {
            let g = dag_c.read().await;
            g.transactions().keys().filter(|id| !g.children().contains_key(*id)).map(|id| id.to_vec()).collect()
        })
    });
    let p2p = Arc::new(P2PNetwork::new(
        P2PConfig { listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(), bootnodes, dns_seeds: vec![], peer_store_path: None, network_id: DEFAULT_NETWORK_ID },
        tx_sender, get_hashes, get_tx, get_tips,
        Arc::new(aether_unified::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    p2p.set_protocol_mode(P2PProtocolMode::LegacyV5);
    p2p.start().await.expect("p2p start");
    TestNodeBo { _dir_guard: dir, storage, dag, p2p, rx }
}

fn __test_only_block_on_bo<F, T>(fut: F) -> T where F: std::future::Future<Output = T> + Send, T: Send {
    std::thread::scope(|s| s.spawn(|| tokio::runtime::Builder::new_current_thread().build().expect("rt").block_on(fut)).join().expect("join"))
}

#[tokio::test]
async fn bo01_scenario_a_throughput_baseline() {
    let total_start = Instant::now();
    let rss_start = get_rss_kb();
    
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PORT_A_BO).parse().unwrap();

    let node_a = boot_node_bo(dir_a, PORT_A_BO, vec![]).await;
    let mut node_b = boot_node_bo(dir_b, PORT_B_BO, vec![pa]).await;

    wait_for_bo("peering", Duration::from_secs(20), || async { node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1 }).await;

    let wallet = wallet_bo(777777);
    let processor = TransactionProcessor::new();
    let ts0: u64 = 1_750_000_100_000;
    let n_tx = if cfg!(debug_assertions) { 10usize } else { 25usize };
    
    let gen_start = Instant::now();
    let mut prev = [0u8; 32];
    let mut sent: Vec<Transaction> = Vec::new();
    for i in 0..n_tx {
        let tx = make_valid_tx_bo(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
        prev = tx.id;
        { let mut dag = node_a.dag.write().await; let store = node_a.storage.read().await; record_tx_bo(&mut dag, &store, &processor, &tx).expect("A records"); }
        sent.push(tx);
    }
    let gen_time = gen_start.elapsed();
    
    let prop_start = Instant::now();
    for tx in &sent { node_a.p2p.broadcast_transaction(tx.clone()).await; tokio::time::sleep(Duration::from_millis(50)).await; }
    
    let mut received: Vec<Transaction> = Vec::new();
    for _ in 0..n_tx {
        if let Ok(Some(ingress)) = tokio::time::timeout(Duration::from_secs(60), node_b.rx.recv()).await {
            received.push(ingress.into_tx());
        } else { break; }
    }
    let prop_time = prop_start.elapsed();
    received.sort_by_key(|tx| tx.account_nonce);
    
    let mut applied_b = 0;
    let mut latencies_ms = Vec::new();
    for tx in &received {
        let rec_start = Instant::now();
        let mut done = false;
        for _ in 0..30 {
            let r = { let mut dag = node_b.dag.write().await; let store = node_b.storage.read().await; record_tx_bo(&mut dag, &store, &processor, tx) };
            if r.is_ok() { done = true; break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        if done { applied_b += 1; latencies_ms.push(rec_start.elapsed().as_millis() as u64); }
    }
    
    latencies_ms.sort_unstable_by(|a,b| a.cmp(b));
    let median = if !latencies_ms.is_empty() { Some(latencies_ms[latencies_ms.len()/2]) } else { None };
    let p95 = if !latencies_ms.is_empty() { Some(latencies_ms[(latencies_ms.len()*95)/100]) } else { None };
    let p99 = if !latencies_ms.is_empty() { Some(latencies_ms[(latencies_ms.len()*99)/100]) } else { None };
    
    let total_time = total_start.elapsed();
    let tps = if total_time.as_secs_f64() > 0.0 { applied_b as f64 / total_time.as_secs_f64() } else { 0.0 };
    let rss_end = get_rss_kb();
    
    let result = BenchResult {
        scenario: "bo01_scenario_a_throughput".to_string(), sha: get_sha(), profile: get_profile(), os: get_os(), arch: get_arch(),
        nodes: 2, transactions_submitted: sent.len(), transactions_applied: applied_b,
        duration_total_ms: total_time.as_millis() as u64, duration_generation_ms: gen_time.as_millis() as u64, duration_propagation_ms: prop_time.as_millis() as u64,
        tps_applied: tps, latency_median_ms: median, latency_p95_ms: p95, latency_p99_ms: p99,
        duplicates_rejected: 0, memory_rss_kb: rss_end.or(rss_start),
    };
    log_jsonl(&result);
    assert_eq!(applied_b, received.len());
    assert!(applied_b > 0);
    drop(node_a); drop(node_b); tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn bo02_scenario_d_memory_budget() {
    let total_start = Instant::now();
    let rss_start = get_rss_kb();
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: std::net::SocketAddr = format!("127.0.0.1:{}", PORT_A_BO + 100).parse().unwrap();
    let node_a = boot_node_bo(dir_a, PORT_A_BO + 100, vec![]).await;
    let node_b = boot_node_bo(dir_b, PORT_B_BO + 100, vec![pa]).await;
    wait_for_bo("peering", Duration::from_secs(20), || async { node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1 }).await;
    let _peer_count = node_a.p2p.peer_count().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let rss_end = get_rss_kb();
    let total_time = total_start.elapsed();
    let result = BenchResult {
        scenario: "bo02_scenario_d_memory".to_string(), sha: get_sha(), profile: get_profile(), os: get_os(), arch: get_arch(),
        nodes: 2, transactions_submitted: 0, transactions_applied: 0,
        duration_total_ms: total_time.as_millis() as u64, duration_generation_ms: 0, duration_propagation_ms: 0,
        tps_applied: 0.0, latency_median_ms: None, latency_p95_ms: None, latency_p99_ms: None,
        duplicates_rejected: 0, memory_rss_kb: rss_end.or(rss_start),
    };
    log_jsonl(&result);
    assert!(_peer_count >= 1);
    drop(node_a); drop(node_b); tokio::time::sleep(Duration::from_millis(500)).await;
}
