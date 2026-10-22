// Phase 4CP-BO/BS/BT baseline tests (BO JSONL schema v2, BS/BT schema v4)

use aether_unified::p2p::{IngressTx, P2PConfig, P2PNetwork, P2PProtocolMode, TX_INGRESS_CAPACITY_MSGS};
use aether_unified::parent_selection::DAG;
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

const SCENARIO_A: &str = "bo01_scenario_a_throughput";
const SCENARIO_A_AGGREGATE: &str = "bo01_scenario_a_throughput_aggregate";
const SCENARIO_BS: &str = "bs01_sustained_load";
const SCENARIO_BS_AGGREGATE: &str = "bs01_sustained_load_aggregate";
const SCENARIO_BT: &str = "bt01_load_curve";
const SCENARIO_BT_LEVEL_AGGREGATE: &str = "bt01_load_curve_level_aggregate";
const SCENARIO_BT_AGGREGATE: &str = "bt01_load_curve_aggregate";
const POW_DIFFICULTY: u8 = 20;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 100;
const REPETITIONS: usize = 3;
const SUBMISSION_INTERVAL_MS: u64 = 5;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);
const BS_TXS_PER_REPETITION: usize = 300;
const BS_REPETITIONS: usize = 3;
const BS_SUBMISSION_INTERVAL_US: u64 = 1_000;
const BS_PORT_BASE: u16 = 56100;
const BT_TXS_PER_REPETITION: usize = 300;
const BT_REPETITIONS_PER_LEVEL: usize = 3;
const BT_LEVELS: [u64; 5] = [250, 400, 550, 700, 1_000];
const BT_PORT_BASE: u16 = 56200;
const BS_RECOVERY_TIMEOUT: Duration = Duration::from_secs(60);
const BS_SAMPLE_INTERVAL: Duration = Duration::from_millis(10);

const RATE_UNIT: &str = "transactions_per_second";
const FORMULA_OFFERED: &str = "submitted / ((last_submission_us - first_submission_us) / 1_000_000)";
const FORMULA_RECEIVED: &str = "received / ((last_receipt_us - first_receipt_us) / 1_000_000)";
const FORMULA_APPLIED: &str = "applied / ((last_apply_us - first_apply_us) / 1_000_000)";
const FORMULA_COMPLETION: &str = "applied / ((last_apply_us - first_submission_us) / 1_000_000)";

#[derive(Debug, Serialize)]
struct RateMetric {
    numerator: u64,
    window_start_us: u64,
    window_end_us: u64,
    duration_us: u64,
    unit: &'static str,
    formula: &'static str,
    value: Option<f64>,
}

fn rate_value(numerator: u64, duration_us: u64) -> Option<f64> {
    if duration_us == 0 {
        None
    } else {
        Some(numerator as f64 / (duration_us as f64 / 1_000_000.0))
    }
}

fn make_rate_metric(numerator: u64, window_start_us: u64, window_end_us: u64, formula: &'static str) -> RateMetric {
    let duration_us = window_end_us.saturating_sub(window_start_us);
    RateMetric {
        numerator,
        window_start_us,
        window_end_us,
        duration_us,
        unit: RATE_UNIT,
        formula,
        value: rate_value(numerator, duration_us),
    }
}

#[test]
fn formula_rate_uses_exact_window_and_units() {
    let metric = make_rate_metric(300, 100_000, 600_000, FORMULA_APPLIED);
    assert_eq!(metric.duration_us, 500_000);
    assert_eq!(metric.window_start_us, 100_000);
    assert_eq!(metric.window_end_us, 600_000);
    assert!((metric.value.expect("rate") - 600.0).abs() < 1e-9);
}

#[test]
fn formula_zero_duration_is_null_not_zero() {
    let metric = make_rate_metric(300, 500_000, 500_000, FORMULA_COMPLETION);
    assert_eq!(metric.duration_us, 0);
    assert_eq!(metric.value, None);
}

#[test]
fn formula_completion_and_application_windows_are_distinct() {
    let completion = make_rate_metric(300, 0, 500_000, FORMULA_COMPLETION);
    let application = make_rate_metric(300, 100_000, 500_000, FORMULA_APPLIED);
    assert!((completion.value.expect("completion") - 600.0).abs() < 1e-9);
    assert!((application.value.expect("application") - 750.0).abs() < 1e-9);
}

#[test]
fn formula_reproduces_bs_v3_and_bo_v2_rates() {
    let bs = make_rate_metric(900, 0, 1_589_209, FORMULA_COMPLETION);
    let bo = make_rate_metric(300, 0, 2_531_866, FORMULA_COMPLETION);
    assert!((bs.value.expect("bs") - 566.3194708814259).abs() < 1e-6);
    assert!((bo.value.expect("bo") - 118.4896831032922).abs() < 1e-6);
}

#[derive(Debug, Serialize)]
struct BenchRecord {
    schema_version: u32,
    record_type: String,
    scenario: String,
    sha: String,
    profile: String,
    os: String,
    arch: String,
    nodes: usize,
    nodes_in_same_process: bool,
    repetition: Option<usize>,
    repetitions_total: usize,
    transactions_per_repetition: usize,
    pow_difficulty: u8,
    tx_value: u64,
    tx_fee: u64,
    submission_interval_ms: u64,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_applied: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    latency_samples: usize,
    generation_span_ms: u64,
    propagation_span_ms: u64,
    application_span_ms: u64,
    end_to_end_span_ms: u64,
    generation_tps: f64,
    reception_tps: f64,
    application_tps: f64,
    end_to_end_tps: f64,
    generation_latency_p50_us: Option<u64>,
    generation_latency_p95_us: Option<u64>,
    generation_latency_p99_us: Option<u64>,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    application_latency_p50_us: Option<u64>,
    application_latency_p95_us: Option<u64>,
    application_latency_p99_us: Option<u64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    rss_process_start_kb: Option<u64>,
    rss_idle_two_nodes_kb: Option<u64>,
    rss_after_repetition_kb: Option<u64>,
    rss_peak_kb: Option<u64>,
    rss_scope: String,
    rss_note: String,
    throughput_note: String,
}

#[derive(Debug, Default)]
struct CoreMetrics {
    submitted: u64,
    received: u64,
    applied: u64,
    rejected: u64,
    duplicates: u64,
    generation_us: Vec<u64>,
    propagation_us: Vec<u64>,
    application_us: Vec<u64>,
    end_to_end_us: Vec<u64>,
    generation_span: Duration,
    propagation_span: Duration,
    application_span: Duration,
    end_to_end_span: Duration,
}

struct RoundResult {
    core: CoreMetrics,
    rss_idle: Option<u64>,
    rss_after: Option<u64>,
    rss_peak: Option<u64>,
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

#[cfg(target_os = "linux")]
fn read_vm_kb(field: &str) -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in contents.lines() {
        if line.starts_with(field) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse::<u64>().ok();
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_vm_kb(_field: &str) -> Option<u64> { None }

fn get_rss_kb() -> Option<u64> { read_vm_kb("VmRSS:") }
fn get_peak_rss_kb() -> Option<u64> { read_vm_kb("VmHWM:") }

fn stats_us(values: &[u64]) -> (Option<u64>, Option<u64>, Option<u64>) {
    if values.is_empty() {
        return (None, None, None);
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let at = |p: usize| {
        let rank = (p * sorted.len() + 99) / 100;
        Some(sorted[rank.saturating_sub(1).min(sorted.len() - 1)])
    };
    (at(50), at(95), at(99))
}

fn tps(count: u64, span: Duration) -> f64 {
    if span.as_nanos() > 0 { count as f64 / span.as_secs_f64() } else { 0.0 }
}

fn build_record(
    record_type: &str,
    scenario: &str,
    repetition: Option<usize>,
    m: &CoreMetrics,
    rss_process_start: Option<u64>,
    rss_idle_two_nodes: Option<u64>,
    rss_after_repetition: Option<u64>,
    rss_peak: Option<u64>,
) -> BenchRecord {
    let (g50, g95, g99) = stats_us(&m.generation_us);
    let (p50, p95, p99) = stats_us(&m.propagation_us);
    let (a50, a95, a99) = stats_us(&m.application_us);
    let (e50, e95, e99) = stats_us(&m.end_to_end_us);
    BenchRecord {
        schema_version: 2,
        record_type: record_type.to_string(),
        scenario: scenario.to_string(),
        sha: get_sha(),
        profile: get_profile(),
        os: get_os(),
        arch: get_arch(),
        nodes: 2,
        nodes_in_same_process: true,
        repetition,
        repetitions_total: REPETITIONS,
        transactions_per_repetition: TXS_PER_REPETITION,
        pow_difficulty: POW_DIFFICULTY,
        tx_value: TX_VALUE,
        tx_fee: TX_FEE,
        submission_interval_ms: SUBMISSION_INTERVAL_MS,
        transactions_submitted: m.submitted,
        transactions_received: m.received,
        transactions_applied: m.applied,
        transactions_rejected: m.rejected,
        duplicates_received: m.duplicates,
        latency_samples: m.application_us.len(),
        generation_span_ms: m.generation_span.as_millis() as u64,
        propagation_span_ms: m.propagation_span.as_millis() as u64,
        application_span_ms: m.application_span.as_millis() as u64,
        end_to_end_span_ms: m.end_to_end_span.as_millis() as u64,
        generation_tps: tps(m.submitted, m.generation_span),
        reception_tps: tps(m.received, m.propagation_span),
        application_tps: tps(m.applied, m.application_span),
        end_to_end_tps: tps(m.applied, m.end_to_end_span),
        generation_latency_p50_us: g50,
        generation_latency_p95_us: g95,
        generation_latency_p99_us: g99,
        propagation_latency_p50_us: p50,
        propagation_latency_p95_us: p95,
        propagation_latency_p99_us: p99,
        application_latency_p50_us: a50,
        application_latency_p95_us: a95,
        application_latency_p99_us: a99,
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        rss_process_start_kb: rss_process_start,
        rss_idle_two_nodes_kb: rss_idle_two_nodes,
        rss_after_repetition_kb: rss_after_repetition,
        rss_peak_kb: rss_peak,
        rss_scope: "test_process (both P2P nodes and the harness run in one process)".to_string(),
        rss_note: "Linux only, whole test process including both nodes and the harness. rss_idle_two_nodes_kb is VmRSS before load; rss_after_repetition_kb is VmRSS immediately after load; rss_peak_kb is process-lifetime VmHWM, so it includes all earlier phases and is not a per-repetition peak. null when /proc is unavailable.".to_string(),
        throughput_note: "generation: first mine start to last mine end (PoW included); reception: first submission to last first receipt; application: batch application window after all receipts to last apply end; end_to_end: first submission to last apply end. Generation is excluded from reception, application and end_to_end. Application latency starts at receipt and therefore includes the wait for the batch application window; application throughput covers only that batch window. Aggregate spans are sums of non-overlapping repetition spans.".to_string(),
    }
}

fn log_record(record: &BenchRecord) {
    println!("BENCH_JSONL:{}", serde_json::to_string(record).expect("serialize BENCH_JSONL"));
}

const PORT_BASE_BO: u16 = 56010;

fn round_ports(round: usize) -> (u16, u16) {
    let base = PORT_BASE_BO + (round as u16) * 4;
    (base, base + 1)
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
    let mut tx = Transaction::new(parents, wallet.address(), [0xBBu8; 32], TX_VALUE, TX_FEE, timestamp, 0, account_nonce, vec![0u8; 64], wallet.public_key_bytes());
    tx.nonce = tx.mine_nonce(POW_DIFFICULTY);
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

async fn run_round(round: usize) -> RoundResult {
    let (port_a, port_b) = round_ports(round);
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: SocketAddr = format!("127.0.0.1:{}", port_a).parse().unwrap();

    let node_a = boot_node_bo(dir_a, port_a, vec![]).await;
    let node_b = boot_node_bo(dir_b, port_b, vec![pa]).await;
    wait_for_bo("peering", Duration::from_secs(20), || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    }).await;

    let rss_idle = get_rss_kb();

    let wallet = wallet_bo(777777);
    let ts0: u64 = 1_750_000_100_000 + (round as u64) * 1_000_000;
    let mut prev = [0u8; 32];
    let mut sent: Vec<Transaction> = Vec::with_capacity(TXS_PER_REPETITION);
    let mut generation_us: Vec<u64> = Vec::with_capacity(TXS_PER_REPETITION);

    let generation_start = Instant::now();
    for i in 0..TXS_PER_REPETITION {
        let mine_start = Instant::now();
        let tx = make_valid_tx_bo(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
        generation_us.push(mine_start.elapsed().as_micros() as u64);
        prev = tx.id;
        sent.push(tx);
    }
    let generation_span = generation_start.elapsed();

    let TestNodeBo { _dir_guard: dir_b_guard, storage: storage_b, dag: dag_b, p2p: p2p_b, rx: mut rx } = node_b;
    let expected = sent.len();
    let rx_task = tokio::spawn(async move {
        let mut seen: HashMap<[u8; 32], (Instant, Transaction)> = HashMap::with_capacity(expected);
        let mut duplicates = 0u64;
        while let Some(ingress) = rx.recv().await {
            let received_at = Instant::now();
            let tx = ingress.into_tx();
            if seen.contains_key(&tx.id) {
                duplicates += 1;
                continue;
            }
            seen.insert(tx.id, (received_at, tx));
            if seen.len() >= expected { break; }
        }
        (seen, duplicates)
    });

    let mut submitted_at: HashMap<[u8; 32], Instant> = HashMap::with_capacity(expected);
    let first_submission = Instant::now();
    for tx in sent {
        let tx_id = tx.id;
        submitted_at.insert(tx_id, Instant::now());
        node_a.p2p.broadcast_transaction(tx).await;
        tokio::time::sleep(Duration::from_millis(SUBMISSION_INTERVAL_MS)).await;
    }

    let mut rx_task = rx_task;
    let (seen, duplicates) = match tokio::time::timeout(RECEIVE_TIMEOUT, &mut rx_task).await {
        Ok(Ok(collected)) => collected,
        Ok(Err(join_error)) => panic!("receiver task failed: {}", join_error),
        Err(_) => {
            rx_task.abort();
            panic!("TIMEOUT waiting for {} transactions", expected);
        }
    };
    assert_eq!(seen.len(), expected, "received {} of {} transactions", seen.len(), expected);

    let last_receipt = seen.values().map(|(at, _)| *at).max().expect("receipts");
    let propagation_span = last_receipt.duration_since(first_submission);
    let mut propagation_us: Vec<u64> = Vec::with_capacity(expected);
    for (tx_id, (received_at, _)) in &seen {
        let submitted = submitted_at.get(tx_id).expect("submission timestamp");
        propagation_us.push(received_at.duration_since(*submitted).as_micros() as u64);
    }

    let mut received: Vec<(Instant, Transaction)> = seen.into_values().collect();
    received.sort_by_key(|(_, tx)| tx.account_nonce);

    let processor = TransactionProcessor::new();
    let mut application_us: Vec<u64> = Vec::with_capacity(expected);
    let mut end_to_end_us: Vec<u64> = Vec::with_capacity(expected);
    let application_phase_start = Instant::now();
    let mut last_application_end = application_phase_start;
    let mut applied = 0u64;
    let mut rejected = 0u64;

    for (received_at, tx) in received {
        let submitted = *submitted_at.get(&tx.id).expect("submission timestamp");
        let result = {
            let mut dag = dag_b.write().await;
            let store = storage_b.read().await;
            record_tx_bo(&mut dag, &store, &processor, &tx)
        };
        match result {
            Ok(()) => {
                let applied_at = Instant::now();
                application_us.push(applied_at.duration_since(received_at).as_micros() as u64);
                end_to_end_us.push(applied_at.duration_since(submitted).as_micros() as u64);
                last_application_end = applied_at;
                applied += 1;
            }
            Err(error) => {
                rejected += 1;
                eprintln!("application rejected tx {}: {}", hex::encode(tx.id), error);
            }
        }
    }

    let application_span = last_application_end.duration_since(application_phase_start);
    let end_to_end_span = last_application_end.duration_since(first_submission);
    let rss_after = get_rss_kb();
    let rss_peak = get_peak_rss_kb();

    drop(node_a);
    drop(p2p_b);
    drop(dag_b);
    drop(storage_b);
    drop(dir_b_guard);
    tokio::time::sleep(Duration::from_millis(500)).await;

    RoundResult {
        core: CoreMetrics {
            submitted: expected as u64,
            received: expected as u64,
            applied,
            rejected,
            duplicates,
            generation_us,
            propagation_us,
            application_us,
            end_to_end_us,
            generation_span,
            propagation_span,
            application_span,
            end_to_end_span,
        },
        rss_idle,
        rss_after,
        rss_peak,
    }
}

fn aggregate_rounds(rounds: &[RoundResult], rss_process_start: Option<u64>) -> BenchRecord {
    let mut core = CoreMetrics::default();
    for round in rounds {
        core.submitted += round.core.submitted;
        core.received += round.core.received;
        core.applied += round.core.applied;
        core.rejected += round.core.rejected;
        core.duplicates += round.core.duplicates;
        core.generation_us.extend_from_slice(&round.core.generation_us);
        core.propagation_us.extend_from_slice(&round.core.propagation_us);
        core.application_us.extend_from_slice(&round.core.application_us);
        core.end_to_end_us.extend_from_slice(&round.core.end_to_end_us);
        core.generation_span += round.core.generation_span;
        core.propagation_span += round.core.propagation_span;
        core.application_span += round.core.application_span;
        core.end_to_end_span += round.core.end_to_end_span;
    }
    let rss_idle = rounds.first().and_then(|round| round.rss_idle);
    let rss_after = rounds.last().and_then(|round| round.rss_after);
    let rss_peak = rounds.iter().filter_map(|round| round.rss_peak).max();
    build_record(
        "aggregate",
        SCENARIO_A_AGGREGATE,
        None,
        &core,
        rss_process_start,
        rss_idle,
        rss_after,
        rss_peak,
    )
}

#[derive(Debug, Serialize)]
struct SustainedRecord {
    schema_version: u32,
    record_type: String,
    scenario: String,
    aggregate_scope: Option<String>,
    sha: String,
    profile: String,
    os: String,
    arch: String,
    nodes: usize,
    nodes_in_same_process: bool,
    repetition: Option<usize>,
    repetitions_total: usize,
    levels_total: usize,
    load_level_index: Option<usize>,
    level_repetition: Option<usize>,
    transactions_per_repetition: usize,
    pow_difficulty: u8,
    tx_value: u64,
    tx_fee: u64,
    load_model: String,
    target_offered_tps: Option<f64>,
    target_submission_interval_us: Option<u64>,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_applied: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    latency_samples: usize,
    generation_scope: String,
    generation_span_ms: Option<u64>,
    generation_included_in_rates: bool,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    application_rate: RateMetric,
    completion_rate: RateMetric,
    submission_start_us: Option<u64>,
    submission_end_us: Option<u64>,
    first_receipt_us: Option<u64>,
    last_receipt_us: Option<u64>,
    first_apply_us: Option<u64>,
    last_apply_us: Option<u64>,
    recovery_ms: Option<u64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    backlog_sample_count: usize,
    backlog_series_ms: Vec<u64>,
    backlog_series_submitted: Vec<u64>,
    backlog_series_received: Vec<u64>,
    backlog_series_applied: Vec<u64>,
    backlog_series_pending: Vec<u64>,
    backlog_series_rss_kb: Vec<Option<u64>>,
    rss_process_start_kb: Option<u64>,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_cleanup_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
    rss_scope: String,
    rss_peak_scope: String,
    rss_note: String,
    window_basis: String,
    formula_note: String,
    throughput_note: String,
}

struct SustainedRound {
    submitted: u64,
    received: u64,
    applied: u64,
    rejected: u64,
    duplicates: u64,
    generation_span: Duration,
    generation_shared: bool,
    submission_span: Duration,
    reception_span: Duration,
    application_span: Duration,
    completion_span: Duration,
    drain_span: Duration,
    timestamps_measured: bool,
    last_submission_us: Option<u64>,
    first_receipt_us: Option<u64>,
    last_receipt_us: Option<u64>,
    first_apply_us: Option<u64>,
    last_apply_us: Option<u64>,
    end_to_end_us: Vec<u64>,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    series: Vec<(u64, u64, u64, u64, Option<u64>)>,
    rss_before_load: Option<u64>,
    rss_after_submissions: Option<u64>,
    rss_under_load_peak: Option<u64>,
    rss_after_cleanup: Option<u64>,
    rss_process_peak: Option<u64>,
}

struct SustainedConsumerResult {
    received: u64,
    applied: u64,
    rejected: u64,
    duplicates: u64,
    end_to_end_us: Vec<u64>,
    first_receipt: Option<Instant>,
    last_receipt: Option<Instant>,
    first_apply: Option<Instant>,
    last_apply: Option<Instant>,
}

#[derive(Clone, Copy)]
struct SustainedMeta<'a> {
    record_type: &'a str,
    scenario: &'a str,
    aggregate_scope: Option<&'a str>,
    repetition: Option<usize>,
    repetitions_total: usize,
    levels_total: usize,
    transactions_per_repetition: usize,
    load_level_index: Option<usize>,
    level_repetition: Option<usize>,
    target_offered_tps: Option<f64>,
    target_submission_interval_us: Option<u64>,
    generation_scope: &'a str,
    window_basis: &'a str,
}

fn rate_window(start: Option<u64>, end: Option<u64>, span: Duration) -> (u64, u64) {
    match (start, end) {
        (Some(start), Some(end)) => (start, end),
        _ => (0, span.as_micros() as u64),
    }
}

fn build_sustained_record(meta: SustainedMeta<'_>, r: &SustainedRound, rss_process_start: Option<u64>) -> SustainedRecord {
    let (e50, e95, e99) = stats_us(&r.end_to_end_us);
    let (series_ms, series_submitted, series_received, series_applied, series_pending, series_rss) = {
        let mut ms = Vec::with_capacity(r.series.len());
        let mut submitted = Vec::with_capacity(r.series.len());
        let mut received = Vec::with_capacity(r.series.len());
        let mut applied = Vec::with_capacity(r.series.len());
        let mut pending = Vec::with_capacity(r.series.len());
        let mut rss = Vec::with_capacity(r.series.len());
        for (t, s, recv, a, mem) in &r.series {
            ms.push(*t);
            submitted.push(*s);
            received.push(*recv);
            applied.push(*a);
            pending.push(s.saturating_sub(*a));
            rss.push(*mem);
        }
        (ms, submitted, received, applied, pending, rss)
    };
    let (recv_start, recv_end) = rate_window(r.first_receipt_us, r.last_receipt_us, r.reception_span);
    let (apply_start, apply_end) = rate_window(r.first_apply_us, r.last_apply_us, r.application_span);
    let completion_end = r.last_apply_us.unwrap_or(r.completion_span.as_micros() as u64);
    let offered = make_rate_metric(r.submitted, 0, r.submission_span.as_micros() as u64, FORMULA_OFFERED);
    let reception = make_rate_metric(r.received, recv_start, recv_end, FORMULA_RECEIVED);
    let application = make_rate_metric(r.applied, apply_start, apply_end, FORMULA_APPLIED);
    let completion = make_rate_metric(r.applied, 0, completion_end, FORMULA_COMPLETION);
    SustainedRecord {
        schema_version: 4,
        record_type: meta.record_type.to_string(),
        scenario: meta.scenario.to_string(),
        aggregate_scope: meta.aggregate_scope.map(str::to_string),
        sha: get_sha(),
        profile: get_profile(),
        os: get_os(),
        arch: get_arch(),
        nodes: 2,
        nodes_in_same_process: true,
        repetition: meta.repetition,
        repetitions_total: meta.repetitions_total,
        levels_total: meta.levels_total,
        load_level_index: meta.load_level_index,
        level_repetition: meta.level_repetition,
        transactions_per_repetition: meta.transactions_per_repetition,
        pow_difficulty: POW_DIFFICULTY,
        tx_value: TX_VALUE,
        tx_fee: TX_FEE,
        load_model: "steady_submission_with_concurrent_application".to_string(),
        target_offered_tps: meta.target_offered_tps,
        target_submission_interval_us: meta.target_submission_interval_us,
        transactions_submitted: r.submitted,
        transactions_received: r.received,
        transactions_applied: r.applied,
        transactions_rejected: r.rejected,
        duplicates_received: r.duplicates,
        latency_samples: r.end_to_end_us.len(),
        generation_scope: meta.generation_scope.to_string(),
        generation_span_ms: (!r.generation_span.is_zero()).then_some(r.generation_span.as_millis() as u64),
        generation_included_in_rates: false,
        offered_rate: offered,
        reception_rate: reception,
        application_rate: application,
        completion_rate: completion,
        submission_start_us: r.timestamps_measured.then_some(0),
        submission_end_us: r.timestamps_measured.then_some(r.last_submission_us.unwrap_or(0)),
        first_receipt_us: r.first_receipt_us,
        last_receipt_us: r.last_receipt_us,
        first_apply_us: r.first_apply_us,
        last_apply_us: r.last_apply_us,
        recovery_ms: (r.applied > 0).then_some(r.drain_span.as_millis() as u64),
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        backlog_peak: r.backlog_peak,
        backlog_peak_at_ms: r.backlog_peak_at_ms,
        backlog_sample_count: r.series.len(),
        backlog_series_ms: series_ms,
        backlog_series_submitted: series_submitted,
        backlog_series_received: series_received,
        backlog_series_applied: series_applied,
        backlog_series_pending: series_pending,
        backlog_series_rss_kb: series_rss,
        rss_process_start_kb: rss_process_start,
        rss_before_load_kb: r.rss_before_load,
        rss_after_submissions_kb: r.rss_after_submissions,
        rss_under_load_peak_kb: r.rss_under_load_peak,
        rss_after_cleanup_kb: r.rss_after_cleanup,
        rss_process_peak_kb: r.rss_process_peak,
        rss_scope: "whole test process: both P2P nodes and the benchmark harness".to_string(),
        rss_peak_scope: "rss_process_peak_kb is VmHWM from process start; it is not a per-repetition peak. rss_under_load_peak_kb is sampled current VmRSS within this repetition window (10 ms interval).".to_string(),
        rss_note: "Linux only. Whole process includes both P2P nodes, the harness, and allocator retention. rss_before_load_kb is VmRSS before submission; rss_after_submissions_kb is VmRSS immediately after the last submission; rss_under_load_peak_kb is the maximum current VmRSS sampled during submission+drain; rss_after_cleanup_kb is VmRSS after both nodes are dropped plus 500 ms; rss_process_peak_kb is lifetime VmHWM read after cleanup. null when /proc is unavailable.".to_string(),
        window_basis: meta.window_basis.to_string(),
        formula_note: "Rate metrics are numerator / (duration_us / 1_000_000). Per-repetition windows start at that repetition's first successful submission (0 us). Aggregate windows are sums of non-overlapping repetition window durations and are not wall-clock intervals; their raw timestamps are null.".to_string(),
        throughput_note: "offered: submitted/(last_submission-first_submission); reception: received/(last_receipt-first_receipt); application: applied/(last_apply-first_apply); completion: applied/(last_apply-first_submission); recovery: last_apply-last_submission. PoW generation is excluded from all rates. Backlog pending is submitted minus applied (network in-flight plus receive/apply queue).".to_string(),
    }
}

fn log_record_sustained(record: &SustainedRecord) {
    println!("BENCH_JSONL:{}", serde_json::to_string(record).expect("serialize sustained BENCH_JSONL"));
}

fn aggregate_sustained(meta: SustainedMeta<'_>, rounds: &[SustainedRound], rss_process_start: Option<u64>) -> SustainedRecord {
    let shared_generation = rounds.first().map(|r| r.generation_shared).unwrap_or(false);
    let generation_span = if shared_generation {
        rounds.first().map(|r| r.generation_span).unwrap_or(Duration::ZERO)
    } else {
        rounds.iter().map(|r| r.generation_span).sum()
    };
    let mut aggregate = SustainedRound {
        submitted: 0,
        received: 0,
        applied: 0,
        rejected: 0,
        duplicates: 0,
        generation_span,
        generation_shared: shared_generation,
        submission_span: Duration::ZERO,
        reception_span: Duration::ZERO,
        application_span: Duration::ZERO,
        completion_span: Duration::ZERO,
        drain_span: Duration::ZERO,
        timestamps_measured: false,
        last_submission_us: None,
        first_receipt_us: None,
        last_receipt_us: None,
        first_apply_us: None,
        last_apply_us: None,
        end_to_end_us: Vec::new(),
        backlog_peak: 0,
        backlog_peak_at_ms: None,
        series: Vec::new(),
        rss_before_load: rounds.first().and_then(|r| r.rss_before_load),
        rss_after_submissions: rounds.last().and_then(|r| r.rss_after_submissions),
        rss_under_load_peak: rounds.iter().filter_map(|r| r.rss_under_load_peak).max(),
        rss_after_cleanup: rounds.last().and_then(|r| r.rss_after_cleanup),
        rss_process_peak: rounds.iter().filter_map(|r| r.rss_process_peak).max(),
    };
    for round in rounds {
        aggregate.submitted += round.submitted;
        aggregate.received += round.received;
        aggregate.applied += round.applied;
        aggregate.rejected += round.rejected;
        aggregate.duplicates += round.duplicates;
        aggregate.submission_span += round.submission_span;
        aggregate.reception_span += round.reception_span;
        aggregate.application_span += round.application_span;
        aggregate.completion_span += round.completion_span;
        aggregate.drain_span = aggregate.drain_span.max(round.drain_span);
        aggregate.end_to_end_us.extend_from_slice(&round.end_to_end_us);
        aggregate.backlog_peak = aggregate.backlog_peak.max(round.backlog_peak);
    }
    build_sustained_record(meta, &aggregate, rss_process_start)
}

async fn run_sustained_round(
    port_a: u16,
    sent: Vec<Transaction>,
    generation_span: Duration,
    generation_shared: bool,
    target_submission_interval_us: u64,
) -> SustainedRound {
    let port_b = port_a + 1;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: SocketAddr = format!("127.0.0.1:{}", port_a).parse().unwrap();

    let node_a = boot_node_bo(dir_a, port_a, vec![]).await;
    let node_b = boot_node_bo(dir_b, port_b, vec![pa]).await;

    wait_for_bo("sustained peering", Duration::from_secs(20), || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let rss_before_load = get_rss_kb();
    let TestNodeBo { _dir_guard: dir_b_guard, storage: storage_b, dag: dag_b, p2p: p2p_b, rx: mut rx } = node_b;
    let expected = sent.len();
    assert!(expected > 0, "sustained load requires transactions");

    let submitted_count = Arc::new(AtomicU64::new(0));
    let received_count = Arc::new(AtomicU64::new(0));
    let applied_count = Arc::new(AtomicU64::new(0));
    let submitted_at: Arc<StdMutex<HashMap<[u8; 32], Instant>>> =
        Arc::new(StdMutex::new(HashMap::with_capacity(expected)));

    let load_start = Instant::now();
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let sampler_peak_rss = Arc::new(AtomicU64::new(0));
    let series: Arc<StdMutex<Vec<(u64, u64, u64, u64, Option<u64>)>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let sampler = {
        let stop = stop_sampler.clone();
        let peak = sampler_peak_rss.clone();
        let series = series.clone();
        let submitted = submitted_count.clone();
        let received = received_count.clone();
        let applied = applied_count.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let rss = get_rss_kb();
                if let Some(value) = rss {
                    peak.fetch_max(value, Ordering::Relaxed);
                }
                series.lock().expect("series lock").push((
                    load_start.elapsed().as_millis() as u64,
                    submitted.load(Ordering::Relaxed),
                    received.load(Ordering::Relaxed),
                    applied.load(Ordering::Relaxed),
                    rss,
                ));
                std::thread::sleep(BS_SAMPLE_INTERVAL);
            }
        })
    };

    let submitted_at_consumer = submitted_at.clone();
    let received_atomic = received_count.clone();
    let applied_atomic = applied_count.clone();
    let dag_consumer = dag_b.clone();
    let storage_consumer = storage_b.clone();
    let consumer = tokio::spawn(async move {
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::with_capacity(expected);
        let mut pending: HashMap<u64, (Instant, Transaction)> = HashMap::new();
        let mut next_nonce = 1u64;
        let mut result = SustainedConsumerResult {
            received: 0,
            applied: 0,
            rejected: 0,
            duplicates: 0,
            end_to_end_us: Vec::with_capacity(expected),
            first_receipt: None,
            last_receipt: None,
            first_apply: None,
            last_apply: None,
        };
        let processor = TransactionProcessor::new();

        while let Some(ingress) = rx.recv().await {
            let received_at = Instant::now();
            let tx = ingress.into_tx();
            if !seen.insert(tx.id) {
                result.duplicates += 1;
                continue;
            }
            if result.first_receipt.is_none() {
                result.first_receipt = Some(received_at);
            }
            result.last_receipt = Some(received_at);
            result.received += 1;
            received_atomic.fetch_add(1, Ordering::Relaxed);
            pending.insert(tx.account_nonce, (received_at, tx));

            while let Some((_, tx)) = pending.remove(&next_nonce) {
                let submitted = submitted_at_consumer
                    .lock()
                    .expect("submitted timestamps")
                    .get(&tx.id)
                    .copied();
                let outcome = {
                    let mut dag = dag_consumer.write().await;
                    let store = storage_consumer.read().await;
                    record_tx_bo(&mut dag, &store, &processor, &tx)
                };
                match outcome {
                    Ok(()) => {
                        let applied_at = Instant::now();
                        if result.first_apply.is_none() {
                            result.first_apply = Some(applied_at);
                        }
                        result.last_apply = Some(applied_at);
                        result.applied += 1;
                        applied_atomic.fetch_add(1, Ordering::Relaxed);
                        if let Some(submitted) = submitted {
                            result
                                .end_to_end_us
                                .push(applied_at.duration_since(submitted).as_micros() as u64);
                        }
                        next_nonce += 1;
                    }
                    Err(error) => {
                        result.rejected += 1;
                        eprintln!("sustained application rejected tx {}: {}", hex::encode(tx.id), error);
                        break;
                    }
                }
                if result.applied as usize >= expected {
                    break;
                }
            }
            if result.applied as usize >= expected {
                break;
            }
        }
        result
    });

    let mut first_submission = None;
    let mut last_submission = None;
    for (index, tx) in sent.iter().enumerate() {
        let target = load_start + Duration::from_micros(target_submission_interval_us * index as u64);
        if let Some(wait) = target.checked_duration_since(Instant::now()) {
            tokio::time::sleep(wait).await;
        }
        let submitted = Instant::now();
        if first_submission.is_none() {
            first_submission = Some(submitted);
        }
        submitted_at
            .lock()
            .expect("submitted timestamps")
            .insert(tx.id, submitted);
        submitted_count.fetch_add(1, Ordering::Relaxed);
        node_a.p2p.broadcast_transaction(tx.clone()).await;
        last_submission = Some(Instant::now());
    }
    let first_submission = first_submission.expect("first submission");
    let last_submission = last_submission.expect("last submission");
    let rss_after_submissions = get_rss_kb();

    let result = match tokio::time::timeout(BS_RECOVERY_TIMEOUT, consumer).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_error)) => panic!("sustained consumer task failed: {}", join_error),
        Err(_) => panic!("TIMEOUT waiting for sustained backlog recovery"),
    };

    stop_sampler.store(true, Ordering::Relaxed);
    sampler.join().expect("sampler join");

    let first_receipt = result.first_receipt.expect("first receipt");
    let last_receipt = result.last_receipt.expect("last receipt");
    let first_apply = result.first_apply.expect("first apply");
    let last_apply = result.last_apply.expect("last apply");
    let final_at = last_apply.duration_since(load_start).as_millis() as u64;
    let final_rss = get_rss_kb();
    let mut points = series.lock().expect("series lock").clone();
    points.push((
        final_at,
        submitted_count.load(Ordering::Relaxed),
        received_count.load(Ordering::Relaxed),
        applied_count.load(Ordering::Relaxed),
        final_rss,
    ));
    points.sort_by_key(|point| point.0);
    points.dedup_by_key(|point| point.0);

    let mut backlog_peak = 0u64;
    let mut backlog_peak_at_ms = None;
    for (at_ms, submitted, _, applied, _) in &points {
        let pending = submitted.saturating_sub(*applied);
        if pending > backlog_peak {
            backlog_peak = pending;
            backlog_peak_at_ms = Some(*at_ms);
        }
    }

    let mut rss_under_load_peak = sampler_peak_rss.load(Ordering::Relaxed);
    if let Some(value) = final_rss {
        rss_under_load_peak = rss_under_load_peak.max(value);
    }
    let rss_under_load_peak = (rss_under_load_peak > 0).then_some(rss_under_load_peak);

    assert_eq!(result.received as usize, expected, "received {} of {} sustained transactions", result.received, expected);
    assert_eq!(result.applied as usize, expected, "applied {} of {} sustained transactions", result.applied, expected);
    assert_eq!(result.rejected, 0, "rejected sustained transactions");
    assert_eq!(result.end_to_end_us.len(), expected, "end-to-end latency samples");

    drop(node_a);
    drop(p2p_b);
    drop(dag_b);
    drop(storage_b);
    drop(dir_b_guard);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rss_after_cleanup = get_rss_kb();
    let rss_process_peak = get_peak_rss_kb();

    let submission_span = last_submission.saturating_duration_since(first_submission);
    let reception_span = last_receipt.saturating_duration_since(first_receipt);
    let application_span = last_apply.saturating_duration_since(first_apply);
    let completion_span = last_apply.saturating_duration_since(first_submission);
    let drain_span = last_apply.saturating_duration_since(last_submission);

    SustainedRound {
        submitted: expected as u64,
        received: result.received,
        applied: result.applied,
        rejected: result.rejected,
        duplicates: result.duplicates,
        generation_span,
        generation_shared,
        submission_span,
        reception_span,
        application_span,
        completion_span,
        drain_span,
        timestamps_measured: true,
        last_submission_us: Some(last_submission.duration_since(first_submission).as_micros() as u64),
        first_receipt_us: Some(first_receipt.duration_since(first_submission).as_micros() as u64),
        last_receipt_us: Some(last_receipt.duration_since(first_submission).as_micros() as u64),
        first_apply_us: Some(first_apply.duration_since(first_submission).as_micros() as u64),
        last_apply_us: Some(last_apply.duration_since(first_submission).as_micros() as u64),
        end_to_end_us: result.end_to_end_us,
        backlog_peak,
        backlog_peak_at_ms,
        series: points,
        rss_before_load,
        rss_after_submissions,
        rss_under_load_peak,
        rss_after_cleanup,
        rss_process_peak,
    }
}

#[tokio::test]
async fn bo01_scenario_a_throughput_baseline() {
    let rss_process_start = get_rss_kb();
    let mut rounds: Vec<RoundResult> = Vec::with_capacity(REPETITIONS);

    for round in 0..REPETITIONS {
        let result = run_round(round).await;

        assert_eq!(result.core.submitted, TXS_PER_REPETITION as u64, "submitted count");
        assert_eq!(result.core.received, TXS_PER_REPETITION as u64, "received count");
        assert_eq!(result.core.applied, TXS_PER_REPETITION as u64, "applied count");
        assert_eq!(result.core.rejected, 0, "rejected count");
        assert_eq!(result.core.application_us.len(), TXS_PER_REPETITION, "application samples");
        assert_eq!(result.core.end_to_end_us.len(), TXS_PER_REPETITION, "end-to-end samples");

        let record = build_record(
            "repetition",
            SCENARIO_A,
            Some(round + 1),
            &result.core,
            None,
            result.rss_idle,
            result.rss_after,
            result.rss_peak,
        );
        log_record(&record);
        rounds.push(result);
    }

    let aggregate = aggregate_rounds(&rounds, rss_process_start);
    assert_eq!(aggregate.latency_samples, REPETITIONS * TXS_PER_REPETITION, "aggregate samples");
    log_record(&aggregate);
}


fn assert_rate_arithmetic(metric: &RateMetric, numerator: u64) {
    assert_eq!(metric.numerator, numerator, "rate numerator");
    assert_eq!(
        metric.duration_us,
        metric.window_end_us.saturating_sub(metric.window_start_us),
        "rate duration"
    );
    if metric.duration_us == 0 {
        assert!(metric.value.is_none(), "zero-duration rate must be null");
    } else {
        let expected = numerator as f64 / (metric.duration_us as f64 / 1_000_000.0);
        let value = metric.value.expect("non-zero-duration rate");
        assert!((value - expected).abs() < 1e-6, "rate value {} != {}", value, expected);
    }
}

#[tokio::test]
async fn bs01_sustained_load() {
    let rss_process_start = get_rss_kb();
    let mut rounds: Vec<SustainedRound> = Vec::with_capacity(BS_REPETITIONS);

    for round in 0..BS_REPETITIONS {
        let wallet = wallet_bo(888888);
        let ts0: u64 = 1_750_000_100_000 + (round as u64) * 1_000_000;
        let mut prev = [0u8; 32];
        let mut sent: Vec<Transaction> = Vec::with_capacity(BS_TXS_PER_REPETITION);
        let generation_start = Instant::now();
        for i in 0..BS_TXS_PER_REPETITION {
            let tx = make_valid_tx_bo(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
            prev = tx.id;
            sent.push(tx);
        }
        let generation_span = generation_start.elapsed();

        let port = BS_PORT_BASE + (round as u16) * 4;
        let result = run_sustained_round(port, sent, generation_span, false, BS_SUBMISSION_INTERVAL_US).await;
        assert_eq!(result.submitted, BS_TXS_PER_REPETITION as u64, "sustained submitted count");
        assert_eq!(result.received, BS_TXS_PER_REPETITION as u64, "sustained received count");
        assert_eq!(result.applied, BS_TXS_PER_REPETITION as u64, "sustained applied count");
        assert_eq!(result.rejected, 0, "sustained rejected count");
        assert_eq!(result.end_to_end_us.len(), BS_TXS_PER_REPETITION, "sustained end-to-end samples");
        assert!(!result.series.is_empty(), "sustained backlog samples");
        assert!(result.submission_span.as_nanos() > 0, "sustained submission span");
        assert!(result.completion_span.as_nanos() > 0, "sustained completion span");
        let (p50, p95, p99) = stats_us(&result.end_to_end_us);
        assert!(p50.is_some() && p95.is_some() && p99.is_some(), "sustained latency percentiles");

        let meta = SustainedMeta {
            record_type: "repetition",
            scenario: SCENARIO_BS,
            aggregate_scope: None,
            repetition: Some(round + 1),
            repetitions_total: BS_REPETITIONS,
            levels_total: 1,
            transactions_per_repetition: BS_TXS_PER_REPETITION,
            load_level_index: None,
            level_repetition: None,
            target_offered_tps: Some(1_000.0),
            target_submission_interval_us: Some(BS_SUBMISSION_INTERVAL_US),
            generation_scope: "per_repetition_pow_before_node_boot",
            window_basis: "continuous_repetition_window_from_first_submission",
        };
        let record = build_sustained_record(meta, &result, rss_process_start);
        assert_rate_arithmetic(&record.offered_rate, BS_TXS_PER_REPETITION as u64);
        assert_rate_arithmetic(&record.reception_rate, BS_TXS_PER_REPETITION as u64);
        assert_rate_arithmetic(&record.application_rate, BS_TXS_PER_REPETITION as u64);
        assert_rate_arithmetic(&record.completion_rate, BS_TXS_PER_REPETITION as u64);
        assert_eq!(record.submission_start_us, Some(0));
        assert_eq!(record.offered_rate.window_end_us, record.submission_end_us.expect("submission end"));
        assert_eq!(record.completion_rate.window_end_us, record.last_apply_us.expect("last apply"));
        log_record_sustained(&record);
        rounds.push(result);
    }

    let aggregate_meta = SustainedMeta {
        record_type: "aggregate",
        scenario: SCENARIO_BS_AGGREGATE,
        aggregate_scope: Some("overall"),
        repetition: None,
        repetitions_total: BS_REPETITIONS,
        levels_total: 1,
        transactions_per_repetition: BS_TXS_PER_REPETITION,
        load_level_index: None,
        level_repetition: None,
        target_offered_tps: Some(1_000.0),
        target_submission_interval_us: Some(BS_SUBMISSION_INTERVAL_US),
        generation_scope: "sum_of_per_repetition_pow_spans",
        window_basis: "sum_of_non_overlapping_repetition_windows",
    };
    let aggregate = aggregate_sustained(aggregate_meta, &rounds, rss_process_start);
    assert_eq!(aggregate.transactions_submitted, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64, "aggregate submitted");
    assert_eq!(aggregate.transactions_received, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64, "aggregate received");
    assert_eq!(aggregate.transactions_applied, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64, "aggregate applied");
    assert_eq!(aggregate.transactions_rejected, 0, "aggregate rejected");
    assert_eq!(aggregate.latency_samples, BS_TXS_PER_REPETITION * BS_REPETITIONS, "aggregate latency samples");
    assert_rate_arithmetic(&aggregate.offered_rate, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64);
    assert_rate_arithmetic(&aggregate.reception_rate, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64);
    assert_rate_arithmetic(&aggregate.application_rate, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64);
    assert_rate_arithmetic(&aggregate.completion_rate, (BS_TXS_PER_REPETITION * BS_REPETITIONS) as u64);
    log_record_sustained(&aggregate);
}

#[tokio::test]
async fn bt01_load_curve() {
    let wallet = wallet_bo(999999);
    let ts0: u64 = 1_750_200_000_000;
    let mut prev = [0u8; 32];
    let mut sent: Vec<Transaction> = Vec::with_capacity(BT_TXS_PER_REPETITION);
    let generation_start = Instant::now();
    for i in 0..BT_TXS_PER_REPETITION {
        let tx = make_valid_tx_bo(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
        prev = tx.id;
        sent.push(tx);
    }
    let shared_generation_span = generation_start.elapsed();

    let rss_process_start = get_rss_kb();
    let mut all_rounds: Vec<SustainedRound> =
        Vec::with_capacity(BT_LEVELS.len() * BT_REPETITIONS_PER_LEVEL);

    for (level_index, target_tps) in BT_LEVELS.iter().copied().enumerate() {
        let interval_us = 1_000_000 / target_tps;
        let mut level_rounds: Vec<SustainedRound> = Vec::with_capacity(BT_REPETITIONS_PER_LEVEL);

        for repetition in 0..BT_REPETITIONS_PER_LEVEL {
            let global_repetition = level_index * BT_REPETITIONS_PER_LEVEL + repetition + 1;
            let port = BT_PORT_BASE + ((global_repetition - 1) as u16) * 4;
            let result = run_sustained_round(
                port,
                sent.clone(),
                shared_generation_span,
                true,
                interval_us,
            )
            .await;

            assert_eq!(result.submitted, BT_TXS_PER_REPETITION as u64, "load curve submitted");
            assert_eq!(result.received, BT_TXS_PER_REPETITION as u64, "load curve received");
            assert_eq!(result.applied, BT_TXS_PER_REPETITION as u64, "load curve applied");
            assert_eq!(result.rejected, 0, "load curve rejected");
            assert_eq!(result.end_to_end_us.len(), BT_TXS_PER_REPETITION, "load curve latency samples");
            assert!(!result.series.is_empty(), "load curve backlog samples");
            assert!(result.submission_span.as_nanos() > 0, "load curve submission span");
            assert!(result.completion_span.as_nanos() > 0, "load curve completion span");

            let meta = SustainedMeta {
                record_type: "repetition",
                scenario: SCENARIO_BT,
                aggregate_scope: None,
                repetition: Some(global_repetition),
                repetitions_total: BT_REPETITIONS_PER_LEVEL,
                levels_total: BT_LEVELS.len(),
                transactions_per_repetition: BT_TXS_PER_REPETITION,
                load_level_index: Some(level_index),
                level_repetition: Some(repetition + 1),
                target_offered_tps: Some(target_tps as f64),
                target_submission_interval_us: Some(interval_us),
                generation_scope: "one_time_shared_pow_before_all_repetitions",
                window_basis: "continuous_repetition_window_from_first_submission",
            };
            let record = build_sustained_record(meta, &result, rss_process_start);
            assert_rate_arithmetic(&record.offered_rate, BT_TXS_PER_REPETITION as u64);
            assert_rate_arithmetic(&record.reception_rate, BT_TXS_PER_REPETITION as u64);
            assert_rate_arithmetic(&record.application_rate, BT_TXS_PER_REPETITION as u64);
            assert_rate_arithmetic(&record.completion_rate, BT_TXS_PER_REPETITION as u64);
            assert_eq!(record.submission_start_us, Some(0));
            assert_eq!(record.offered_rate.window_end_us, record.submission_end_us.expect("submission end"));
            assert_eq!(record.completion_rate.window_end_us, record.last_apply_us.expect("last apply"));
            log_record_sustained(&record);
            level_rounds.push(result);
        }

        let level_meta = SustainedMeta {
            record_type: "level_aggregate",
            scenario: SCENARIO_BT_LEVEL_AGGREGATE,
            aggregate_scope: Some("level"),
            repetition: None,
            repetitions_total: BT_REPETITIONS_PER_LEVEL,
            levels_total: BT_LEVELS.len(),
            transactions_per_repetition: BT_TXS_PER_REPETITION,
            load_level_index: Some(level_index),
            level_repetition: None,
            target_offered_tps: Some(target_tps as f64),
            target_submission_interval_us: Some(interval_us),
            generation_scope: "one_time_shared_pow_before_all_repetitions",
            window_basis: "sum_of_non_overlapping_repetition_windows",
        };
        let level_aggregate = aggregate_sustained(level_meta, &level_rounds, rss_process_start);
        assert_eq!(
            level_aggregate.transactions_applied,
            (BT_TXS_PER_REPETITION * BT_REPETITIONS_PER_LEVEL) as u64,
            "level aggregate applied"
        );
        assert_eq!(
            level_aggregate.latency_samples,
            BT_TXS_PER_REPETITION * BT_REPETITIONS_PER_LEVEL,
            "level aggregate samples"
        );
        assert_rate_arithmetic(
            &level_aggregate.offered_rate,
            (BT_TXS_PER_REPETITION * BT_REPETITIONS_PER_LEVEL) as u64,
        );
        assert_rate_arithmetic(
            &level_aggregate.completion_rate,
            (BT_TXS_PER_REPETITION * BT_REPETITIONS_PER_LEVEL) as u64,
        );
        log_record_sustained(&level_aggregate);
        all_rounds.extend(level_rounds);
    }

    let aggregate_meta = SustainedMeta {
        record_type: "aggregate",
        scenario: SCENARIO_BT_AGGREGATE,
        aggregate_scope: Some("overall"),
        repetition: None,
        repetitions_total: BT_LEVELS.len() * BT_REPETITIONS_PER_LEVEL,
        levels_total: BT_LEVELS.len(),
        transactions_per_repetition: BT_TXS_PER_REPETITION,
        load_level_index: None,
        level_repetition: None,
        target_offered_tps: None,
        target_submission_interval_us: None,
        generation_scope: "one_time_shared_pow_before_all_repetitions",
        window_basis: "sum_of_non_overlapping_repetition_windows",
    };
    let aggregate = aggregate_sustained(aggregate_meta, &all_rounds, rss_process_start);
    assert_eq!(
        aggregate.transactions_applied,
        (BT_TXS_PER_REPETITION * BT_LEVELS.len() * BT_REPETITIONS_PER_LEVEL) as u64,
        "overall aggregate applied"
    );
    assert_eq!(
        aggregate.latency_samples,
        BT_TXS_PER_REPETITION * BT_LEVELS.len() * BT_REPETITIONS_PER_LEVEL,
        "overall aggregate samples"
    );
    log_record_sustained(&aggregate);
}
