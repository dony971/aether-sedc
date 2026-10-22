// Phase 4CP-BO/BQ baseline tests (JSONL schema v2)

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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

const SCENARIO_A: &str = "bo01_scenario_a_throughput";
const SCENARIO_A_AGGREGATE: &str = "bo01_scenario_a_throughput_aggregate";
const POW_DIFFICULTY: u8 = 20;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 100;
const REPETITIONS: usize = 3;
const SUBMISSION_INTERVAL_MS: u64 = 5;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(120);

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
        rss_note: "Linux VmRSS (current) and VmHWM (peak) for the whole test process; null when /proc is unavailable".to_string(),
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
