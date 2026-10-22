// Phase 4CP-BW: propagation-jitter compromise benchmark (schema v6).
//
// The jitter override is compiled only with the `test-jitter-control` feature.
// Production builds keep the fixed 2E-D window and OS entropy.

#![cfg(feature = "test-jitter-control")]

use aether_unified::p2p::{
    clear_test_propagation_jitter, set_test_propagation_jitter, IngressTx, P2PConfig, P2PNetwork,
    P2PProtocolMode, TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::parent_selection::DAG;
use aether_unified::storage::Storage;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

const SCENARIO_REPETITION: &str = "bw01_jitter_compromise";
const SCENARIO_CELL_AGGREGATE: &str = "bw01_jitter_compromise_cell_aggregate";
const SCENARIO_OVERALL_AGGREGATE: &str = "bw01_jitter_compromise_aggregate";
const SCHEMA_VERSION: u32 = 6;
const POW_DIFFICULTY: u8 = 20;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 300;
const REPETITIONS_PER_CELL: usize = 3;
const PORT_BASE: u16 = 56300;
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(120);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);

const RATE_UNIT: &str = "transactions_per_second";
const FORMULA_OFFERED: &str =
    "submitted / ((last_submission_us - first_submission_us) / 1_000_000)";
const FORMULA_RECEIVED: &str = "received / ((last_receipt_us - first_receipt_us) / 1_000_000)";
const FORMULA_APPLIED: &str = "applied / ((last_apply_us - first_apply_us) / 1_000_000)";
const FORMULA_COMPLETION: &str = "applied / ((last_apply_us - first_submission_us) / 1_000_000)";

#[derive(Clone, Copy)]
struct JitterProfile {
    id: &'static str,
    min_ms: u64,
    max_ms: u64,
}

const PROFILES: [JitterProfile; 4] = [
    JitterProfile {
        id: "none_0_0",
        min_ms: 0,
        max_ms: 0,
    },
    JitterProfile {
        id: "20_50",
        min_ms: 20,
        max_ms: 50,
    },
    JitterProfile {
        id: "20_100",
        min_ms: 20,
        max_ms: 100,
    },
    JitterProfile {
        id: "20_250",
        min_ms: 20,
        max_ms: 250,
    },
];

const TARGET_RATES: [u64; 2] = [550, 1_000];

struct JitterReset;

impl Drop for JitterReset {
    fn drop(&mut self) {
        clear_test_propagation_jitter();
    }
}

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

fn make_rate_metric(
    numerator: u64,
    window_start_us: u64,
    window_end_us: u64,
    formula: &'static str,
) -> RateMetric {
    let duration_us = window_end_us.saturating_sub(window_start_us);
    RateMetric {
        numerator,
        window_start_us,
        window_end_us,
        duration_us,
        unit: RATE_UNIT,
        formula,
        value: if duration_us == 0 {
            None
        } else {
            Some(numerator as f64 / (duration_us as f64 / 1_000_000.0))
        },
    }
}

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

fn mean_us(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<u64>() as f64 / values.len() as f64)
    }
}

fn max_us(values: &[u64]) -> Option<u64> {
    values.iter().copied().max()
}

fn get_sha() -> String {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        let sha = sha.trim();
        if !sha.is_empty() {
            return sha.to_string();
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                String::from_utf8(out.stdout).ok()
            } else {
                None
            }
        })
        .map(|sha| sha.trim().to_string())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_profile() -> String {
    if cfg!(debug_assertions) {
        "debug".to_string()
    } else {
        "release".to_string()
    }
}

fn get_os() -> String {
    std::env::consts::OS.to_string()
}

fn get_arch() -> String {
    std::env::consts::ARCH.to_string()
}

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
fn read_vm_kb(_field: &str) -> Option<u64> {
    None
}

fn get_rss_kb() -> Option<u64> {
    read_vm_kb("VmRSS:")
}

fn get_peak_rss_kb() -> Option<u64> {
    read_vm_kb("VmHWM:")
}

fn wallet_bw(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn make_valid_tx_bw(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    account_nonce: u64,
    timestamp: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        [0xCCu8; 32],
        TX_VALUE,
        TX_FEE,
        timestamp,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(POW_DIFFICULTY);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Historical)
        .expect("freshly mined+signed tx must pass");
    tx
}

fn record_tx_bw(
    dag: &mut DAG,
    store: &Storage,
    processor: &TransactionProcessor,
    tx: &Transaction,
) -> Result<(), String> {
    processor
        .validate_pure(tx, ValidationMode::Historical)
        .map_err(|e| format!("pure gate: {:?}", e))?;
    dag.add_transaction_validated(tx.clone())
        .map_err(|e| format!("dag insert: {}", e))?;
    store
        .put_transaction(tx)
        .map_err(|e| format!("persist: {}", e))?;
    store
        .mark_applied(tx.id)
        .map_err(|e| format!("applied mark: {}", e))?;
    Ok(())
}

struct TestNodeBw {
    _dir_guard: tempfile::TempDir,
    storage: Arc<RwLock<Storage>>,
    dag: Arc<RwLock<DAG>>,
    p2p: Arc<P2PNetwork>,
    rx: mpsc::Receiver<IngressTx>,
}

async fn boot_node_bw(dir: tempfile::TempDir, port: u16, bootnodes: Vec<SocketAddr>) -> TestNodeBw {
    let storage = Arc::new(RwLock::new(Storage::open(dir.path()).expect("open store")));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let (tx_sender, rx) = mpsc::channel::<IngressTx>(TX_INGRESS_CAPACITY_MSGS);
    let dag_c = dag.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on_bw(async {
            dag_c
                .read()
                .await
                .transactions()
                .keys()
                .map(|id| id.to_vec())
                .collect()
        })
    });
    let dag_c = dag.clone();
    let storage_c2 = storage.clone();
    let get_tx: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(move |hash| {
        __test_only_block_on_bw(async {
            if let Ok(id) = <[u8; 32]>::try_from(hash) {
                if let Ok(g) = dag_c.try_read() {
                    if let Some(tx) = g.transactions().get(&id) {
                        return Some(tx.clone());
                    }
                }
                if let Ok(s) = storage_c2.try_read() {
                    if let Ok(tx) = s.get_transaction(id) {
                        return Some(tx);
                    }
                }
            }
            None
        })
    });
    let dag_c = dag.clone();
    let get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on_bw(async {
            let g = dag_c.read().await;
            g.transactions()
                .keys()
                .filter(|id| !g.children().contains_key(*id))
                .map(|id| id.to_vec())
                .collect()
        })
    });
    let p2p = Arc::new(P2PNetwork::new(
        P2PConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            bootnodes,
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: DEFAULT_NETWORK_ID,
        },
        tx_sender,
        get_hashes,
        get_tx,
        get_tips,
        Arc::new(aether_unified::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    p2p.set_protocol_mode(P2PProtocolMode::LegacyV5);
    p2p.start().await.expect("p2p start");
    TestNodeBw {
        _dir_guard: dir,
        storage,
        dag,
        p2p,
        rx,
    }
}

fn __test_only_block_on_bw<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("rt")
                .block_on(fut)
        })
        .join()
        .expect("join")
    })
}

async fn wait_for_bw<F, Fut>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("TIMEOUT waiting for: {}", what);
}

struct BwRound {
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    submitted: u64,
    received: u64,
    applied: u64,
    rejected: u64,
    duplicates: u64,
    first_submission_us: u64,
    last_submission_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_apply_us: u64,
    last_apply_us: u64,
    drain_us: u64,
    propagation_us: Vec<u64>,
    application_us: Vec<u64>,
    end_to_end_us: Vec<u64>,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    series: Vec<(u64, u64, u64, u64, Option<u64>)>,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_cleanup_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
}

struct ConsumerResult {
    received: u64,
    applied: u64,
    rejected: u64,
    duplicates: u64,
    propagation_us: Vec<u64>,
    application_us: Vec<u64>,
    end_to_end_us: Vec<u64>,
    first_receipt: Option<Instant>,
    last_receipt: Option<Instant>,
    first_apply: Option<Instant>,
    last_apply: Option<Instant>,
}

async fn run_round_bw(
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    sent: Vec<Transaction>,
    port_a: u16,
) -> BwRound {
    set_test_propagation_jitter(
        Duration::from_millis(profile.min_ms),
        Duration::from_millis(profile.max_ms),
        seed,
    );

    let port_b = port_a + 1;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: SocketAddr = format!("127.0.0.1:{}", port_a).parse().unwrap();

    let node_a = boot_node_bw(dir_a, port_a, vec![]).await;
    let node_b = boot_node_bw(dir_b, port_b, vec![pa]).await;

    wait_for_bw("jitter peering", Duration::from_secs(20), || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let rss_before_load = get_rss_kb();
    let TestNodeBw {
        _dir_guard: dir_b_guard,
        storage: storage_b,
        dag: dag_b,
        p2p: p2p_b,
        mut rx,
    } = node_b;
    let expected = sent.len();
    assert!(expected > 0, "jitter load requires transactions");

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
                std::thread::sleep(SAMPLE_INTERVAL);
            }
        })
    };

    let submitted_at_consumer = submitted_at.clone();
    let received_atomic = received_count.clone();
    let applied_atomic = applied_count.clone();
    let dag_consumer = dag_b.clone();
    let storage_consumer = storage_b.clone();
    let consumer = tokio::spawn(async move {
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(expected);
        let mut pending: HashMap<u64, (Instant, Transaction)> = HashMap::new();
        let mut next_nonce = 1u64;
        let mut result = ConsumerResult {
            received: 0,
            applied: 0,
            rejected: 0,
            duplicates: 0,
            propagation_us: Vec::with_capacity(expected),
            application_us: Vec::with_capacity(expected),
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

            while let Some((ingress_at, tx)) = pending.remove(&next_nonce) {
                let submitted = submitted_at_consumer
                    .lock()
                    .expect("submitted timestamps")
                    .get(&tx.id)
                    .copied();
                let outcome = {
                    let mut dag = dag_consumer.write().await;
                    let store = storage_consumer.read().await;
                    record_tx_bw(&mut dag, &store, &processor, &tx)
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
                                .propagation_us
                                .push(ingress_at.duration_since(submitted).as_micros() as u64);
                            result
                                .application_us
                                .push(applied_at.duration_since(ingress_at).as_micros() as u64);
                            result
                                .end_to_end_us
                                .push(applied_at.duration_since(submitted).as_micros() as u64);
                        }
                        next_nonce += 1;
                    }
                    Err(error) => {
                        result.rejected += 1;
                        eprintln!(
                            "jitter application rejected tx {}: {}",
                            hex::encode(tx.id),
                            error
                        );
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
        let target = load_start + Duration::from_micros(submission_interval_us * index as u64);
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

    let result = match tokio::time::timeout(RECOVERY_TIMEOUT, consumer).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_error)) => panic!("jitter consumer task failed: {}", join_error),
        Err(_) => panic!("TIMEOUT waiting for jitter backlog recovery"),
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

    assert_eq!(
        result.received as usize, expected,
        "received {} of {} jitter transactions",
        result.received, expected
    );
    assert_eq!(
        result.applied as usize, expected,
        "applied {} of {} jitter transactions",
        result.applied, expected
    );
    assert_eq!(result.rejected, 0, "rejected jitter transactions");
    assert_eq!(
        result.propagation_us.len(),
        expected,
        "propagation latency samples"
    );
    assert_eq!(
        result.application_us.len(),
        expected,
        "application latency samples"
    );
    assert_eq!(
        result.end_to_end_us.len(),
        expected,
        "end-to-end latency samples"
    );

    drop(node_a);
    drop(p2p_b);
    drop(dag_b);
    drop(storage_b);
    drop(dir_b_guard);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rss_after_cleanup = get_rss_kb();
    let rss_process_peak = get_peak_rss_kb();

    BwRound {
        profile,
        seed,
        target_tps,
        submission_interval_us,
        submitted: expected as u64,
        received: result.received,
        applied: result.applied,
        rejected: result.rejected,
        duplicates: result.duplicates,
        first_submission_us: first_submission.duration_since(load_start).as_micros() as u64,
        last_submission_us: last_submission.duration_since(load_start).as_micros() as u64,
        first_receipt_us: first_receipt.duration_since(load_start).as_micros() as u64,
        last_receipt_us: last_receipt.duration_since(load_start).as_micros() as u64,
        first_apply_us: first_apply.duration_since(load_start).as_micros() as u64,
        last_apply_us: last_apply.duration_since(load_start).as_micros() as u64,
        drain_us: last_apply.duration_since(last_submission).as_micros() as u64,
        propagation_us: result.propagation_us,
        application_us: result.application_us,
        end_to_end_us: result.end_to_end_us,
        backlog_peak,
        backlog_peak_at_ms,
        series: points,
        rss_before_load_kb: rss_before_load,
        rss_after_submissions_kb: rss_after_submissions,
        rss_under_load_peak_kb: rss_under_load_peak,
        rss_after_cleanup_kb: rss_after_cleanup,
        rss_process_peak_kb: rss_process_peak,
    }
}

#[derive(Debug, Serialize)]
struct RepetitionRecord {
    schema_version: u32,
    record_type: &'static str,
    scenario: &'static str,
    sha: String,
    profile: String,
    os: String,
    arch: String,
    nodes: usize,
    nodes_in_same_process: bool,
    profile_id: &'static str,
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    jitter_seed: u64,
    target_offered_tps: u64,
    target_submission_interval_us: u64,
    repetition: usize,
    cell_repetition: usize,
    repetitions_total: usize,
    transactions_per_repetition: usize,
    transaction_set: &'static str,
    pow_difficulty: u8,
    generation_included_in_rates: bool,
    generation_scope: &'static str,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_applied: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    latency_samples: usize,
    submission_start_us: u64,
    submission_end_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_apply_us: u64,
    last_apply_us: u64,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    application_rate: RateMetric,
    completion_rate: RateMetric,
    propagation_latency_mean_us: Option<f64>,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    propagation_latency_max_us: Option<u64>,
    application_latency_mean_us: Option<f64>,
    application_latency_p50_us: Option<u64>,
    application_latency_p95_us: Option<u64>,
    application_latency_p99_us: Option<u64>,
    application_latency_max_us: Option<u64>,
    end_to_end_latency_mean_us: Option<f64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    end_to_end_latency_max_us: Option<u64>,
    drain_ms: u64,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    backlog_sample_count: usize,
    backlog_series_ms: Vec<u64>,
    backlog_series_submitted: Vec<u64>,
    backlog_series_received: Vec<u64>,
    backlog_series_applied: Vec<u64>,
    backlog_series_pending: Vec<u64>,
    backlog_series_rss_kb: Vec<Option<u64>>,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_cleanup_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
    rss_scope: &'static str,
    window_basis: &'static str,
    throughput_note: &'static str,
}

fn build_repetition_record(
    round: &BwRound,
    repetition: usize,
    global_repetition: usize,
) -> RepetitionRecord {
    let (p50, p95, p99) = stats_us(&round.propagation_us);
    let (a50, a95, a99) = stats_us(&round.application_us);
    let (e50, e95, e99) = stats_us(&round.end_to_end_us);
    let mut series_ms = Vec::with_capacity(round.series.len());
    let mut series_submitted = Vec::with_capacity(round.series.len());
    let mut series_received = Vec::with_capacity(round.series.len());
    let mut series_applied = Vec::with_capacity(round.series.len());
    let mut series_pending = Vec::with_capacity(round.series.len());
    let mut series_rss = Vec::with_capacity(round.series.len());
    for (at_ms, submitted, received, applied, rss) in &round.series {
        series_ms.push(*at_ms);
        series_submitted.push(*submitted);
        series_received.push(*received);
        series_applied.push(*applied);
        series_pending.push(submitted.saturating_sub(*applied));
        series_rss.push(*rss);
    }

    RepetitionRecord {
        schema_version: SCHEMA_VERSION,
        record_type: "repetition",
        scenario: SCENARIO_REPETITION,
        sha: get_sha(),
        profile: get_profile(),
        os: get_os(),
        arch: get_arch(),
        nodes: 2,
        nodes_in_same_process: true,
        profile_id: round.profile.id,
        jitter_min_ms: round.profile.min_ms,
        jitter_max_ms: round.profile.max_ms,
        jitter_seed: round.seed,
        target_offered_tps: round.target_tps,
        target_submission_interval_us: round.submission_interval_us,
        repetition: global_repetition,
        cell_repetition: repetition,
        repetitions_total: REPETITIONS_PER_CELL,
        transactions_per_repetition: TXS_PER_REPETITION,
        transaction_set: "one_shared_pre_generated_valid_set",
        pow_difficulty: POW_DIFFICULTY,
        generation_included_in_rates: false,
        generation_scope: "one_time_shared_pow_before_all_repetitions",
        transactions_submitted: round.submitted,
        transactions_received: round.received,
        transactions_applied: round.applied,
        transactions_rejected: round.rejected,
        duplicates_received: round.duplicates,
        latency_samples: round.end_to_end_us.len(),
        submission_start_us: round.first_submission_us,
        submission_end_us: round.last_submission_us,
        first_receipt_us: round.first_receipt_us,
        last_receipt_us: round.last_receipt_us,
        first_apply_us: round.first_apply_us,
        last_apply_us: round.last_apply_us,
        offered_rate: make_rate_metric(
            round.submitted,
            round.first_submission_us,
            round.last_submission_us,
            FORMULA_OFFERED,
        ),
        reception_rate: make_rate_metric(
            round.received,
            round.first_receipt_us,
            round.last_receipt_us,
            FORMULA_RECEIVED,
        ),
        application_rate: make_rate_metric(
            round.applied,
            round.first_apply_us,
            round.last_apply_us,
            FORMULA_APPLIED,
        ),
        completion_rate: make_rate_metric(
            round.applied,
            round.first_submission_us,
            round.last_apply_us,
            FORMULA_COMPLETION,
        ),
        propagation_latency_mean_us: mean_us(&round.propagation_us),
        propagation_latency_p50_us: p50,
        propagation_latency_p95_us: p95,
        propagation_latency_p99_us: p99,
        propagation_latency_max_us: max_us(&round.propagation_us),
        application_latency_mean_us: mean_us(&round.application_us),
        application_latency_p50_us: a50,
        application_latency_p95_us: a95,
        application_latency_p99_us: a99,
        application_latency_max_us: max_us(&round.application_us),
        end_to_end_latency_mean_us: mean_us(&round.end_to_end_us),
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        end_to_end_latency_max_us: max_us(&round.end_to_end_us),
        drain_ms: round.drain_us / 1_000,
        backlog_peak: round.backlog_peak,
        backlog_peak_at_ms: round.backlog_peak_at_ms,
        backlog_sample_count: series_ms.len(),
        backlog_series_ms: series_ms,
        backlog_series_submitted: series_submitted,
        backlog_series_received: series_received,
        backlog_series_applied: series_applied,
        backlog_series_pending: series_pending,
        backlog_series_rss_kb: series_rss,
        rss_before_load_kb: round.rss_before_load_kb,
        rss_after_submissions_kb: round.rss_after_submissions_kb,
        rss_under_load_peak_kb: round.rss_under_load_peak_kb,
        rss_after_cleanup_kb: round.rss_after_cleanup_kb,
        rss_process_peak_kb: round.rss_process_peak_kb,
        rss_scope: "process_wide_two_nodes_same_process",
        window_basis: "per_repetition_from_first_submission",
        throughput_note: "Network path includes production broadcast relay and the requested test-only jitter window; PoW generation is excluded. The no-jitter profile is a laboratory control, not a production recommendation.",
    }
}

#[derive(Debug, Serialize)]
struct AggregateRecord {
    schema_version: u32,
    record_type: &'static str,
    scenario: &'static str,
    aggregate_scope: String,
    sha: String,
    profile: String,
    os: String,
    arch: String,
    nodes: usize,
    nodes_in_same_process: bool,
    profile_id: String,
    jitter_min_ms: Option<u64>,
    jitter_max_ms: Option<u64>,
    target_offered_tps: Option<u64>,
    repetitions: usize,
    transactions_per_repetition: usize,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_applied: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    latency_samples: usize,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    application_rate: RateMetric,
    completion_rate: RateMetric,
    propagation_latency_mean_us: Option<f64>,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    propagation_latency_max_us: Option<u64>,
    application_latency_mean_us: Option<f64>,
    application_latency_p50_us: Option<u64>,
    application_latency_p95_us: Option<u64>,
    application_latency_p99_us: Option<u64>,
    application_latency_max_us: Option<u64>,
    end_to_end_latency_mean_us: Option<f64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    end_to_end_latency_max_us: Option<u64>,
    drain_ms_mean: Option<f64>,
    drain_ms_max: Option<u64>,
    backlog_peak_max: u64,
    recovery_ms_mean: Option<f64>,
    recovery_ms_max: Option<u64>,
    rss_before_load_mean_kb: Option<f64>,
    rss_under_load_peak_max_kb: Option<u64>,
    rss_process_peak_max_kb: Option<u64>,
    rss_scope: &'static str,
    window_basis: &'static str,
    throughput_note: &'static str,
}

fn aggregate_rounds(
    scope: String,
    profile_id: String,
    jitter: Option<(u64, u64)>,
    target: Option<u64>,
    rounds: &[&BwRound],
) -> AggregateRecord {
    let mut propagation = Vec::new();
    let mut application = Vec::new();
    let mut end_to_end = Vec::new();
    let mut offered_duration_us = 0u64;
    let mut reception_duration_us = 0u64;
    let mut application_duration_us = 0u64;
    let mut completion_duration_us = 0u64;
    let mut submitted = 0u64;
    let mut received = 0u64;
    let mut applied = 0u64;
    let mut rejected = 0u64;
    let mut duplicates = 0u64;
    let mut drain_ms = Vec::new();
    let mut backlog_peak_max = 0u64;
    let mut rss_before = Vec::new();
    let mut rss_peak = 0u64;
    let mut rss_process_peak = 0u64;

    for round in rounds {
        submitted += round.submitted;
        received += round.received;
        applied += round.applied;
        rejected += round.rejected;
        duplicates += round.duplicates;
        offered_duration_us += round
            .last_submission_us
            .saturating_sub(round.first_submission_us);
        reception_duration_us += round.last_receipt_us.saturating_sub(round.first_receipt_us);
        application_duration_us += round.last_apply_us.saturating_sub(round.first_apply_us);
        completion_duration_us += round
            .last_apply_us
            .saturating_sub(round.first_submission_us);
        propagation.extend_from_slice(&round.propagation_us);
        application.extend_from_slice(&round.application_us);
        end_to_end.extend_from_slice(&round.end_to_end_us);
        drain_ms.push(round.drain_us / 1_000);
        backlog_peak_max = backlog_peak_max.max(round.backlog_peak);
        if let Some(value) = round.rss_before_load_kb {
            rss_before.push(value);
        }
        if let Some(value) = round.rss_under_load_peak_kb {
            rss_peak = rss_peak.max(value);
        }
        if let Some(value) = round.rss_process_peak_kb {
            rss_process_peak = rss_process_peak.max(value);
        }
    }

    let (p50, p95, p99) = stats_us(&propagation);
    let (a50, a95, a99) = stats_us(&application);
    let (e50, e95, e99) = stats_us(&end_to_end);

    AggregateRecord {
        schema_version: SCHEMA_VERSION,
        record_type: if target.is_some() { "cell_aggregate" } else { "overall_aggregate" },
        scenario: if target.is_some() { SCENARIO_CELL_AGGREGATE } else { SCENARIO_OVERALL_AGGREGATE },
        aggregate_scope: scope,
        sha: get_sha(),
        profile: get_profile(),
        os: get_os(),
        arch: get_arch(),
        nodes: 2,
        nodes_in_same_process: true,
        profile_id,
        jitter_min_ms: jitter.map(|value| value.0),
        jitter_max_ms: jitter.map(|value| value.1),
        target_offered_tps: target,
        repetitions: rounds.len(),
        transactions_per_repetition: TXS_PER_REPETITION,
        transactions_submitted: submitted,
        transactions_received: received,
        transactions_applied: applied,
        transactions_rejected: rejected,
        duplicates_received: duplicates,
        latency_samples: end_to_end.len(),
        offered_rate: make_rate_metric(submitted, 0, offered_duration_us, FORMULA_OFFERED),
        reception_rate: make_rate_metric(received, 0, reception_duration_us, FORMULA_RECEIVED),
        application_rate: make_rate_metric(applied, 0, application_duration_us, FORMULA_APPLIED),
        completion_rate: make_rate_metric(applied, 0, completion_duration_us, FORMULA_COMPLETION),
        propagation_latency_mean_us: mean_us(&propagation),
        propagation_latency_p50_us: p50,
        propagation_latency_p95_us: p95,
        propagation_latency_p99_us: p99,
        propagation_latency_max_us: max_us(&propagation),
        application_latency_mean_us: mean_us(&application),
        application_latency_p50_us: a50,
        application_latency_p95_us: a95,
        application_latency_p99_us: a99,
        application_latency_max_us: max_us(&application),
        end_to_end_latency_mean_us: mean_us(&end_to_end),
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        end_to_end_latency_max_us: max_us(&end_to_end),
        drain_ms_mean: if drain_ms.is_empty() {
            None
        } else {
            Some(drain_ms.iter().sum::<u64>() as f64 / drain_ms.len() as f64)
        },
        drain_ms_max: drain_ms.iter().copied().max(),
        backlog_peak_max,
        recovery_ms_mean: if drain_ms.is_empty() {
            None
        } else {
            Some(drain_ms.iter().sum::<u64>() as f64 / drain_ms.len() as f64)
        },
        recovery_ms_max: drain_ms.iter().copied().max(),
        rss_before_load_mean_kb: if rss_before.is_empty() {
            None
        } else {
            Some(rss_before.iter().sum::<u64>() as f64 / rss_before.len() as f64)
        },
        rss_under_load_peak_max_kb: (rss_peak > 0).then_some(rss_peak),
        rss_process_peak_max_kb: (rss_process_peak > 0).then_some(rss_process_peak),
        rss_scope: "process_wide_two_nodes_same_process",
        window_basis: "sum_of_non_overlapping_repetition_windows",
        throughput_note: "Network path includes production broadcast relay and the requested test-only jitter window; PoW generation is excluded. The no-jitter profile is a laboratory control, not a production recommendation.",
    }
}

fn log_jsonl<T: Serialize>(record: &T) {
    println!(
        "BENCH_JSONL:{}",
        serde_json::to_string(record).expect("serialize record")
    );
}

#[tokio::test]
async fn bw01_jitter_compromise() {
    let _reset = JitterReset;
    let wallet = wallet_bw(777777);
    let ts0: u64 = 1_750_300_000_000;
    let mut prev = [0u8; 32];
    let mut sent: Vec<Transaction> = Vec::with_capacity(TXS_PER_REPETITION);
    let generation_start = Instant::now();
    for i in 0..TXS_PER_REPETITION {
        let tx = make_valid_tx_bw(&wallet, [prev, [0u8; 32]], 1 + i as u64, ts0 + i as u64);
        prev = tx.id;
        sent.push(tx);
    }
    let _generation_span = generation_start.elapsed();

    let mut all_rounds: Vec<BwRound> =
        Vec::with_capacity(PROFILES.len() * TARGET_RATES.len() * REPETITIONS_PER_CELL);
    let mut cell_round_indices: HashMap<(&'static str, u64), Vec<usize>> = HashMap::new();
    let mut global_repetition = 0usize;

    for (profile_index, profile) in PROFILES.iter().copied().enumerate() {
        for (rate_index, target_tps) in TARGET_RATES.iter().copied().enumerate() {
            let submission_interval_us = 1_000_000 / target_tps;
            for repetition in 1..=REPETITIONS_PER_CELL {
                global_repetition += 1;
                let seed = 0xB3_0000
                    + (profile_index as u64) * 1_000
                    + (rate_index as u64) * 100
                    + repetition as u64;
                let port = PORT_BASE + ((global_repetition - 1) as u16) * 4;
                let round = run_round_bw(
                    profile,
                    seed,
                    target_tps,
                    submission_interval_us,
                    sent.clone(),
                    port,
                )
                .await;

                assert_eq!(
                    round.submitted, TXS_PER_REPETITION as u64,
                    "submitted count"
                );
                assert_eq!(round.received, TXS_PER_REPETITION as u64, "received count");
                assert_eq!(round.applied, TXS_PER_REPETITION as u64, "applied count");
                assert_eq!(round.rejected, 0, "rejected count");
                assert_eq!(
                    round.propagation_us.len(),
                    TXS_PER_REPETITION,
                    "propagation samples"
                );
                assert_eq!(
                    round.application_us.len(),
                    TXS_PER_REPETITION,
                    "application samples"
                );
                assert_eq!(
                    round.end_to_end_us.len(),
                    TXS_PER_REPETITION,
                    "end-to-end samples"
                );
                assert!(!round.series.is_empty(), "backlog samples");
                assert!(
                    round.last_submission_us > round.first_submission_us,
                    "submission span"
                );
                assert!(
                    round.last_apply_us >= round.last_submission_us,
                    "completion order"
                );

                let record = build_repetition_record(&round, repetition, global_repetition);
                log_jsonl(&record);
                println!(
                    "BW_REP profile={} target={} rep={} completion_tps={:.1} p50_us={} p95_us={} p99_us={} backlog_peak={} drain_ms={}",
                    profile.id,
                    target_tps,
                    repetition,
                    record.completion_rate.value.unwrap_or(0.0),
                    record.end_to_end_latency_p50_us.unwrap_or(0),
                    record.end_to_end_latency_p95_us.unwrap_or(0),
                    record.end_to_end_latency_p99_us.unwrap_or(0),
                    round.backlog_peak,
                    round.drain_us / 1_000,
                );
                cell_round_indices
                    .entry((profile.id, target_tps))
                    .or_default()
                    .push(all_rounds.len());
                all_rounds.push(round);
            }
        }
    }

    for profile in PROFILES.iter().copied() {
        for target_tps in TARGET_RATES.iter().copied() {
            let indices = cell_round_indices
                .get(&(profile.id, target_tps))
                .expect("cell repetitions");
            assert_eq!(indices.len(), REPETITIONS_PER_CELL, "cell repetition count");
            let rounds: Vec<&BwRound> = indices.iter().map(|index| &all_rounds[*index]).collect();
            let aggregate = aggregate_rounds(
                format!("profile={},target_tps={}", profile.id, target_tps),
                profile.id.to_string(),
                Some((profile.min_ms, profile.max_ms)),
                Some(target_tps),
                &rounds,
            );
            assert_eq!(
                aggregate.transactions_applied,
                (TXS_PER_REPETITION * REPETITIONS_PER_CELL) as u64,
                "cell applied total"
            );
            log_jsonl(&aggregate);
            println!(
                "BW_CELL profile={} target={} completion_tps={:.1} e2e_p50_us={} e2e_p95_us={} backlog_max={} drain_mean_ms={:.1}",
                profile.id,
                target_tps,
                aggregate.completion_rate.value.unwrap_or(0.0),
                aggregate.end_to_end_latency_p50_us.unwrap_or(0),
                aggregate.end_to_end_latency_p95_us.unwrap_or(0),
                aggregate.backlog_peak_max,
                aggregate.drain_ms_mean.unwrap_or(0.0),
            );
        }
    }

    let all_refs: Vec<&BwRound> = all_rounds.iter().collect();
    let overall = aggregate_rounds(
        "overall".to_string(),
        "all".to_string(),
        None,
        None,
        &all_refs,
    );
    assert_eq!(
        overall.transactions_applied,
        (TXS_PER_REPETITION * PROFILES.len() * TARGET_RATES.len() * REPETITIONS_PER_CELL) as u64,
        "overall applied total"
    );
    log_jsonl(&overall);
    println!(
        "BW_OVERALL completion_tps={:.1} e2e_p50_us={} e2e_p95_us={} e2e_p99_us={} backlog_max={} drain_mean_ms={:.1}",
        overall.completion_rate.value.unwrap_or(0.0),
        overall.end_to_end_latency_p50_us.unwrap_or(0),
        overall.end_to_end_latency_p95_us.unwrap_or(0),
        overall.end_to_end_latency_p99_us.unwrap_or(0),
        overall.backlog_peak_max,
        overall.drain_ms_mean.unwrap_or(0.0),
    );
}
