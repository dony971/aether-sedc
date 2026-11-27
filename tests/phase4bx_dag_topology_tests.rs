#![cfg(feature = "test-jitter-control")]

use aether_unified::p2p::{
    clear_test_propagation_jitter, set_test_propagation_jitter, IngressTx, P2PConfig, P2PNetwork,
    P2PProtocolMode,
};
use aether_unified::parent_selection::DAG;
use aether_unified::storage::Storage;
use aether_unified::sync_stats::SyncContext;
use aether_unified::transaction::{Transaction, TransactionId, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

const SCENARIO_REPETITION: &str = "bx01_dag_topology";
const SCENARIO_CELL_AGGREGATE: &str = "bx01_dag_topology_cell_aggregate";
const SCENARIO_OVERALL_AGGREGATE: &str = "bx01_dag_topology_aggregate";
const SCHEMA_VERSION: u32 = 7;
const POW_DIFFICULTY: u8 = 20;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 300;
const MULTI_LANE_COUNT: usize = 10;
const MULTI_LANE_TX_COUNT: usize = 30;
const REPETITIONS_PER_CELL: usize = 3;
const PORT_BASE: u16 = 26200;
const BX_INGRESS_CAPACITY_MSGS: usize = 512;
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(120);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);
const SUBMISSION_ORDER: &str = "pre_generated_vector_index_order";
const TRANSACTION_SET: &str = "one_shared_pre_generated_valid_set_per_topology";
const GENERATION_SCOPE: &str = "one_time_shared_pow_per_topology_before_all_repetitions";
const TIMING_SCOPE: &str = "submission_to_receipt_and_receipt_to_dag_persisted_acceptance";
const THROUGHPUT_NOTE: &str = "Timed path is pure validation, DAG insertion, Sled transaction row write, and applied-state mark. It is NOT full ledger application through TransactionProcessor::process. PoW generation is excluded. The no-jitter profile is a laboratory control, not a production recommendation.";

const RATE_UNIT: &str = "transactions_per_second";
const FORMULA_OFFERED: &str =
    "submitted / ((last_submission_us - first_submission_us) / 1_000_000)";
const FORMULA_RECEIVED: &str = "received / ((last_receipt_us - first_receipt_us) / 1_000_000)";
const FORMULA_ACCEPTED: &str =
    "accepted / ((last_acceptance_us - first_acceptance_us) / 1_000_000)";
const FORMULA_PERSISTED_ACCEPTANCE: &str =
    "persisted / ((last_persisted_us - first_persisted_us) / 1_000_000)";
const FORMULA_COMPLETION: &str =
    "persisted / ((last_persisted_us - first_submission_us) / 1_000_000)";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Topology {
    Chain,
    MultiLane,
}

impl Topology {
    fn id(self) -> &'static str {
        match self {
            Topology::Chain => "chain",
            Topology::MultiLane => "multi_lane",
        }
    }

    fn lanes(self) -> usize {
        match self {
            Topology::Chain => 1,
            Topology::MultiLane => MULTI_LANE_COUNT,
        }
    }

    fn transactions_per_lane(self) -> usize {
        match self {
            Topology::Chain => TXS_PER_REPETITION,
            Topology::MultiLane => MULTI_LANE_TX_COUNT,
        }
    }

    fn layout(self) -> &'static str {
        match self {
            Topology::Chain => "single_wallet_single_parent_chain",
            Topology::MultiLane => "ten_independent_single_parent_lane_chains",
        }
    }

    fn transaction_set_id(self) -> &'static str {
        match self {
            Topology::Chain => "chain_1x300_v1",
            Topology::MultiLane => "multi_lane_10x30_v1",
        }
    }
}

const TOPOLOGIES: [Topology; 2] = [Topology::Chain, Topology::MultiLane];

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

fn wallet_bx(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn make_valid_tx_bx(
    wallet: &Wallet,
    parents: [TransactionId; 2],
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

fn build_transaction_set(topology: Topology, ts0: u64) -> Vec<Transaction> {
    let mut sent = Vec::with_capacity(TXS_PER_REPETITION);
    match topology {
        Topology::Chain => {
            let wallet = wallet_bx(880_001);
            let mut previous = [0u8; 32];
            for index in 0..TXS_PER_REPETITION {
                let tx = make_valid_tx_bx(
                    &wallet,
                    [previous, [0u8; 32]],
                    1 + index as u64,
                    ts0 + index as u64,
                );
                previous = tx.id;
                sent.push(tx);
            }
        }
        Topology::MultiLane => {
            let wallets: Vec<Wallet> = (0..MULTI_LANE_COUNT)
                .map(|lane| wallet_bx(881_000 + lane as u64))
                .collect();
            let mut previous = [[0u8; 32]; MULTI_LANE_COUNT];
            for step in 0..MULTI_LANE_TX_COUNT {
                for (lane, wallet) in wallets.iter().enumerate() {
                    let tx = make_valid_tx_bx(
                        wallet,
                        [previous[lane], [0u8; 32]],
                        1 + step as u64,
                        ts0 + (step * MULTI_LANE_COUNT + lane) as u64,
                    );
                    previous[lane] = tx.id;
                    sent.push(tx);
                }
            }
        }
    }
    sent
}

struct RecordOutcome {
    stored: bool,
    accepted_at: Instant,
    persisted_at: Option<Instant>,
    storage_error: Option<String>,
}

fn record_tx_bx(
    dag: &mut DAG,
    store: &Storage,
    processor: &TransactionProcessor,
    tx: &Transaction,
) -> Result<RecordOutcome, String> {
    processor
        .validate_pure(tx, ValidationMode::Historical)
        .map_err(|e| format!("pure gate: {:?}", e))?;
    dag.add_transaction_validated(tx.clone())
        .map_err(|e| format!("dag insert: {}", e))?;
    let accepted_at = Instant::now();

    if let Err(error) = store.put_transaction(tx) {
        return Ok(RecordOutcome {
            stored: false,
            accepted_at,
            persisted_at: None,
            storage_error: Some(format!("transaction row write: {}", error)),
        });
    }

    if let Err(error) = store.mark_applied(tx.id) {
        return Ok(RecordOutcome {
            stored: true,
            accepted_at,
            persisted_at: None,
            storage_error: Some(format!("applied-state mark: {}", error)),
        });
    }

    Ok(RecordOutcome {
        stored: true,
        accepted_at,
        persisted_at: Some(Instant::now()),
        storage_error: None,
    })
}

struct TestNodeBx {
    _dir_guard: tempfile::TempDir,
    storage: Arc<RwLock<Storage>>,
    dag: Arc<RwLock<DAG>>,
    p2p: Arc<P2PNetwork>,
    /// 4CP-BX v2.1 (M3): the node's own SyncContext. Production's drainer takes
    /// the ingress provenance at dequeue (`node.rs`), so the test consumer must
    /// do the same; without it `ingress_mode` is never purged in this harness
    /// and the in-flight window would look permanently open — the test would
    /// then pass on a state production never reaches.
    sync_ctx: Arc<SyncContext>,
    rx: mpsc::Receiver<IngressTx>,
}

async fn boot_node_bx(dir: tempfile::TempDir, port: u16, bootnodes: Vec<SocketAddr>) -> TestNodeBx {
    let storage = Arc::new(RwLock::new(Storage::open(dir.path()).expect("open store")));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let (tx_sender, rx) = mpsc::channel::<IngressTx>(BX_INGRESS_CAPACITY_MSGS);
    let dag_c = dag.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on_bx(async {
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
        __test_only_block_on_bx(async {
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
        __test_only_block_on_bx(async {
            let g = dag_c.read().await;
            g.transactions()
                .keys()
                .filter(|id| !g.children().contains_key(*id))
                .map(|id| id.to_vec())
                .collect()
        })
    });
    let sync_ctx = Arc::new(SyncContext::default());
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
        sync_ctx.clone(),
        Arc::new(|_| false),
    ));
    p2p.set_protocol_mode(P2PProtocolMode::LegacyV5);
    p2p.start().await.expect("p2p start");
    TestNodeBx {
        _dir_guard: dir,
        storage,
        dag,
        p2p,
        sync_ctx,
        rx,
    }
}

fn __test_only_block_on_bx<F, T>(fut: F) -> T
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

async fn wait_for_bx<F, Fut>(what: &str, timeout: Duration, mut check: F)
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

struct BxRound {
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    submitted: u64,
    received: u64,
    accepted: u64,
    stored: u64,
    persisted: u64,
    rejected: u64,
    duplicates: u64,
    storage_errors: u64,
    unresolved_dependencies: u64,
    first_submission_us: u64,
    last_submission_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_acceptance_us: u64,
    last_acceptance_us: u64,
    first_persisted_us: u64,
    last_persisted_us: u64,
    drain_us: u64,
    propagation_us: Vec<u64>,
    acceptance_us: Vec<u64>,
    persisted_acceptance_us: Vec<u64>,
    submission_to_acceptance_us: Vec<u64>,
    submission_to_persisted_acceptance_us: Vec<u64>,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    series: Vec<(u64, u64, u64, u64, u64, Option<u64>)>,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    parent_missing_count: usize,
    ingress_drops: u64,
    session_drops: u64,
    outbound_budget_drops: u64,
    ingress_queue_capacity_msgs: usize,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_cleanup_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
}

struct ConsumerResult {
    received: u64,
    accepted: u64,
    stored: u64,
    persisted: u64,
    rejected: u64,
    duplicates: u64,
    storage_errors: u64,
    unresolved_dependencies: u64,
    propagation_us: Vec<u64>,
    acceptance_us: Vec<u64>,
    persisted_acceptance_us: Vec<u64>,
    submission_to_acceptance_us: Vec<u64>,
    submission_to_persisted_acceptance_us: Vec<u64>,
    first_receipt: Option<Instant>,
    last_receipt: Option<Instant>,
    first_acceptance: Option<Instant>,
    last_acceptance: Option<Instant>,
    first_persisted: Option<Instant>,
    last_persisted: Option<Instant>,
}
async fn run_round_bx(
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    sent: Vec<Transaction>,
    port_a: u16,
) -> BxRound {
    set_test_propagation_jitter(
        Duration::from_millis(profile.min_ms),
        Duration::from_millis(profile.max_ms),
        seed,
    );

    let port_b = port_a + 1;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let pa: SocketAddr = format!("127.0.0.1:{}", port_a).parse().unwrap();

    let node_a = boot_node_bx(dir_a, port_a, vec![]).await;
    let node_b = boot_node_bx(dir_b, port_b, vec![pa]).await;

    wait_for_bx("jitter peering", Duration::from_secs(20), || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let rss_before_load = get_rss_kb();
    let TestNodeBx {
        _dir_guard: dir_b_guard,
        storage: storage_b,
        dag: dag_b,
        p2p: p2p_b,
        sync_ctx: sync_ctx_b,
        mut rx,
    } = node_b;
    let expected = sent.len();
    assert!(expected > 0, "jitter load requires transactions");

    let submitted_count = Arc::new(AtomicU64::new(0));
    let received_count = Arc::new(AtomicU64::new(0));
    let accepted_count = Arc::new(AtomicU64::new(0));
    let persisted_count = Arc::new(AtomicU64::new(0));
    let submitted_at: Arc<StdMutex<HashMap<[u8; 32], Instant>>> =
        Arc::new(StdMutex::new(HashMap::with_capacity(expected)));

    let load_start = Instant::now();
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let sampler_peak_rss = Arc::new(AtomicU64::new(0));
    let series: Arc<StdMutex<Vec<(u64, u64, u64, u64, u64, Option<u64>)>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let sampler = {
        let stop = stop_sampler.clone();
        let peak = sampler_peak_rss.clone();
        let series = series.clone();
        let submitted = submitted_count.clone();
        let received = received_count.clone();
        let accepted = accepted_count.clone();
        let persisted = persisted_count.clone();
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
                    accepted.load(Ordering::Relaxed),
                    persisted.load(Ordering::Relaxed),
                    rss,
                ));
                std::thread::sleep(SAMPLE_INTERVAL);
            }
        })
    };

    let submitted_at_consumer = submitted_at.clone();
    let received_atomic = received_count.clone();
    let accepted_atomic = accepted_count.clone();
    let persisted_atomic = persisted_count.clone();
    // 4CP-BX v2.2 (R1): the harness's consumer IS this node's funnel — it holds
    // the transactions it received until it applies them. Publishing that set to
    // the node is what production does with `Mempool::held_ids`, so the Inventory
    // diff sees the same window it sees in a real node instead of a window that
    // only exists because the harness never reported its queue.
    let pipeline_held: Arc<StdMutex<HashSet<[u8; 32]>>> =
        Arc::new(StdMutex::new(HashSet::with_capacity(expected)));
    {
        let held = pipeline_held.clone();
        sync_ctx_b
            .set_pipeline_holds(Arc::new(move || {
                let snapshot: Vec<[u8; 32]> = held
                    .lock()
                    .expect("pipeline lock")
                    .iter()
                    .copied()
                    .collect();
                Box::pin(async move { snapshot })
                    as std::pin::Pin<Box<dyn std::future::Future<Output = Vec<[u8; 32]>> + Send>>
            }))
            .await;
    }

    let dag_consumer = dag_b.clone();
    let storage_consumer = storage_b.clone();
    let sync_ctx_consumer = sync_ctx_b.clone();
    let pipeline_consumer = pipeline_held.clone();
    let consumer = tokio::spawn(async move {
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(expected);
        let mut pending: HashMap<[u8; 32], BTreeMap<u64, (Instant, Transaction)>> = HashMap::new();
        let mut next_nonce: HashMap<[u8; 32], u64> = HashMap::new();
        let mut accepted_ids: HashSet<[u8; 32]> = HashSet::with_capacity(expected);
        let mut result = ConsumerResult {
            received: 0,
            accepted: 0,
            stored: 0,
            persisted: 0,
            rejected: 0,
            duplicates: 0,
            storage_errors: 0,
            unresolved_dependencies: 0,
            propagation_us: Vec::with_capacity(expected),
            acceptance_us: Vec::with_capacity(expected),
            persisted_acceptance_us: Vec::with_capacity(expected),
            submission_to_acceptance_us: Vec::with_capacity(expected),
            submission_to_persisted_acceptance_us: Vec::with_capacity(expected),
            first_receipt: None,
            last_receipt: None,
            first_acceptance: None,
            last_acceptance: None,
            first_persisted: None,
            last_persisted: None,
        };
        let processor = TransactionProcessor::new();

        while let Some(ingress) = rx.recv().await {
            let received_at = Instant::now();
            let tx = ingress.into_tx();
            // 4CP-BX v2.3: the same three steps, in the same order, as
            // `node.rs` — open the handoff (the id stays visible), let the
            // funnel take ownership (here: publish it in the pipeline set),
            // then close the handoff. Nothing is inserted before the dequeue
            // and nothing is published after the handoff ends, so the harness
            // reproduces the production visibility chain instead of masking a
            // hole in it.
            let tx_id = tx.id;
            let (_ingress_mode, handoff) = sync_ctx_consumer.begin_ingress_handoff(tx_id).await;
            pipeline_consumer
                .lock()
                .expect("pipeline lock")
                .insert(tx_id);
            sync_ctx_consumer.end_ingress_handoff(tx_id, handoff).await;
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

            let submitted = submitted_at_consumer
                .lock()
                .expect("submitted timestamps")
                .get(&tx.id)
                .copied();
            if let Some(submitted) = submitted {
                result
                    .propagation_us
                    .push(received_at.duration_since(submitted).as_micros() as u64);
            }

            pending
                .entry(tx.sender)
                .or_default()
                .insert(tx.account_nonce, (received_at, tx));

            let mut fatal = false;
            loop {
                let mut progress = false;
                let senders: Vec<[u8; 32]> = pending.keys().copied().collect();
                for sender in senders {
                    let expected_nonce = *next_nonce.get(&sender).unwrap_or(&1);
                    let entry = pending
                        .get(&sender)
                        .and_then(|by_nonce| by_nonce.get(&expected_nonce))
                        .map(|(received, tx)| (*received, tx.clone()));
                    let Some((ingress_at, tx)) = entry else {
                        continue;
                    };
                    let parents_ready = tx.parents.iter().all(|parent| {
                        parent.iter().all(|byte| *byte == 0) || accepted_ids.contains(parent)
                    });
                    if !parents_ready {
                        continue;
                    }
                    if let Some(by_nonce) = pending.get_mut(&sender) {
                        by_nonce.remove(&expected_nonce);
                    }

                    let outcome = {
                        let mut dag = dag_consumer.write().await;
                        let store = storage_consumer.read().await;
                        record_tx_bx(&mut dag, &store, &processor, &tx)
                    };
                    match outcome {
                        Ok(outcome) => {
                            accepted_ids.insert(tx.id);
                            result.accepted += 1;
                            accepted_atomic.fetch_add(1, Ordering::Relaxed);
                            if result.first_acceptance.is_none() {
                                result.first_acceptance = Some(outcome.accepted_at);
                            }
                            result.last_acceptance = Some(outcome.accepted_at);

                            if let Some(submitted) = submitted {
                                result.acceptance_us.push(
                                    outcome.accepted_at.duration_since(ingress_at).as_micros()
                                        as u64,
                                );
                                result.submission_to_acceptance_us.push(
                                    outcome.accepted_at.duration_since(submitted).as_micros()
                                        as u64,
                                );
                            }

                            if outcome.stored {
                                result.stored += 1;
                            }
                            match outcome.persisted_at {
                                Some(persisted_at) => {
                                    result.persisted += 1;
                                    persisted_atomic.fetch_add(1, Ordering::Relaxed);
                                    if result.first_persisted.is_none() {
                                        result.first_persisted = Some(persisted_at);
                                    }
                                    result.last_persisted = Some(persisted_at);
                                    if let Some(submitted) = submitted {
                                        result.persisted_acceptance_us.push(
                                            persisted_at.duration_since(ingress_at).as_micros()
                                                as u64,
                                        );
                                        result.submission_to_persisted_acceptance_us.push(
                                            persisted_at.duration_since(submitted).as_micros()
                                                as u64,
                                        );
                                    }
                                }
                                None => {
                                    result.storage_errors += 1;
                                    eprintln!(
                                        "topology storage failure tx {}: {}",
                                        hex::encode(tx.id),
                                        outcome.storage_error.unwrap_or_default()
                                    );
                                    fatal = true;
                                }
                            }

                            next_nonce.insert(sender, expected_nonce + 1);
                            progress = true;
                        }
                        Err(error) => {
                            result.rejected += 1;
                            eprintln!(
                                "topology acceptance rejected tx {}: {}",
                                hex::encode(tx.id),
                                error
                            );
                            fatal = true;
                        }
                    }
                    if result.persisted as usize >= expected || fatal {
                        break;
                    }
                }
                if !progress || fatal || result.persisted as usize >= expected {
                    break;
                }
            }
            if fatal || result.persisted as usize >= expected {
                break;
            }
        }

        result.unresolved_dependencies =
            pending.values().map(|by_nonce| by_nonce.len() as u64).sum();
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
        Ok(Err(join_error)) => panic!("topology consumer task failed: {}", join_error),
        Err(_) => panic!(
            "TIMEOUT waiting for topology backlog recovery: received={} accepted={} persisted={} ingress_drops={} session_drops={} outbound_budget_drops={} profile={} target={}",
            received_count.load(Ordering::Relaxed),
            accepted_count.load(Ordering::Relaxed),
            persisted_count.load(Ordering::Relaxed),
            p2p_b.ingress_drops(),
            node_a.p2p.session_drops() + p2p_b.session_drops(),
            node_a.p2p.outbound_budget_drops() + p2p_b.outbound_budget_drops(),
            profile.id,
            target_tps
        ),
    };

    stop_sampler.store(true, Ordering::Relaxed);
    sampler.join().expect("sampler join");

    let first_receipt = result.first_receipt.expect("first receipt");
    let last_receipt = result.last_receipt.expect("last receipt");
    let first_acceptance = result.first_acceptance.expect("first acceptance");
    let last_acceptance = result.last_acceptance.expect("last acceptance");
    let first_persisted = result.first_persisted.expect("first persisted acceptance");
    let last_persisted = result.last_persisted.expect("last persisted acceptance");
    let final_at = last_persisted.duration_since(load_start).as_millis() as u64;
    let final_rss = get_rss_kb();
    let mut points = series.lock().expect("series lock").clone();
    points.push((
        final_at,
        submitted_count.load(Ordering::Relaxed),
        received_count.load(Ordering::Relaxed),
        accepted_count.load(Ordering::Relaxed),
        persisted_count.load(Ordering::Relaxed),
        final_rss,
    ));
    points.sort_by_key(|point| point.0);

    let mut backlog_peak = 0u64;
    let mut backlog_peak_at_ms = None;
    for (at_ms, submitted, _, _, persisted, _) in &points {
        let pending = submitted.saturating_sub(*persisted);
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

    let (dag_transaction_count, parent_missing_count) = {
        let dag = dag_b.read().await;
        let transactions = dag.transactions();
        let parent_missing_count = transactions
            .values()
            .filter(|tx| {
                tx.parents.iter().any(|parent| {
                    parent.iter().any(|byte| *byte != 0) && !transactions.contains_key(parent)
                })
            })
            .count();
        (transactions.len(), parent_missing_count)
    };
    let storage_transaction_count = storage_b
        .read()
        .await
        .transaction_count()
        .expect("storage transaction count");
    let applied_mark_count = storage_b
        .read()
        .await
        .get_all_applied()
        .expect("applied marks")
        .len();

    assert_eq!(
        result.received as usize, expected,
        "received {} of {} topology transactions",
        result.received, expected
    );
    assert_eq!(
        result.accepted as usize, expected,
        "accepted {} of {} topology transactions",
        result.accepted, expected
    );
    assert_eq!(
        result.stored as usize, expected,
        "stored {} of {} topology transactions",
        result.stored, expected
    );
    assert_eq!(
        result.persisted as usize, expected,
        "persisted {} of {} topology transactions",
        result.persisted, expected
    );
    assert_eq!(result.rejected, 0, "rejected topology transactions");
    assert_eq!(result.duplicates, 0, "duplicate topology transactions");
    assert_eq!(result.storage_errors, 0, "storage errors");
    assert_eq!(
        result.unresolved_dependencies, 0,
        "unresolved dependency transactions"
    );
    assert_eq!(
        result.propagation_us.len(),
        expected,
        "propagation latency samples"
    );
    assert_eq!(
        result.acceptance_us.len(),
        expected,
        "acceptance latency samples"
    );
    assert_eq!(
        result.persisted_acceptance_us.len(),
        expected,
        "persisted acceptance latency samples"
    );
    assert_eq!(
        result.submission_to_acceptance_us.len(),
        expected,
        "submission-to-acceptance latency samples"
    );
    assert_eq!(
        result.submission_to_persisted_acceptance_us.len(),
        expected,
        "submission-to-persisted-acceptance latency samples"
    );
    assert_eq!(dag_transaction_count, expected, "DAG transaction count");
    assert_eq!(
        storage_transaction_count, expected,
        "storage transaction count"
    );
    assert_eq!(applied_mark_count, expected, "applied mark count");
    assert_eq!(parent_missing_count, 0, "missing parent count");
    assert_eq!(p2p_b.ingress_drops(), 0, "ingress drops");
    let ingress_drops = p2p_b.ingress_drops();
    let session_drops = node_a.p2p.session_drops() + p2p_b.session_drops();
    let outbound_budget_drops = node_a.p2p.outbound_budget_drops() + p2p_b.outbound_budget_drops();
    assert_eq!(session_drops, 0, "session drops");
    assert_eq!(outbound_budget_drops, 0, "outbound budget drops");

    drop(node_a);
    drop(p2p_b);
    drop(dag_b);
    drop(storage_b);
    drop(dir_b_guard);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let rss_after_cleanup = get_rss_kb();
    let rss_process_peak = get_peak_rss_kb();

    BxRound {
        topology,
        profile,
        seed,
        target_tps,
        submission_interval_us,
        generation_span_ms,
        submitted: expected as u64,
        received: result.received,
        accepted: result.accepted,
        stored: result.stored,
        persisted: result.persisted,
        rejected: result.rejected,
        duplicates: result.duplicates,
        storage_errors: result.storage_errors,
        unresolved_dependencies: result.unresolved_dependencies,
        first_submission_us: first_submission.duration_since(load_start).as_micros() as u64,
        last_submission_us: last_submission.duration_since(load_start).as_micros() as u64,
        first_receipt_us: first_receipt.duration_since(load_start).as_micros() as u64,
        last_receipt_us: last_receipt.duration_since(load_start).as_micros() as u64,
        first_acceptance_us: first_acceptance.duration_since(load_start).as_micros() as u64,
        last_acceptance_us: last_acceptance.duration_since(load_start).as_micros() as u64,
        first_persisted_us: first_persisted.duration_since(load_start).as_micros() as u64,
        last_persisted_us: last_persisted.duration_since(load_start).as_micros() as u64,
        drain_us: last_persisted.duration_since(last_submission).as_micros() as u64,
        propagation_us: result.propagation_us,
        acceptance_us: result.acceptance_us,
        persisted_acceptance_us: result.persisted_acceptance_us,
        submission_to_acceptance_us: result.submission_to_acceptance_us,
        submission_to_persisted_acceptance_us: result.submission_to_persisted_acceptance_us,
        backlog_peak,
        backlog_peak_at_ms,
        series: points,
        dag_transaction_count,
        storage_transaction_count,
        applied_mark_count,
        parent_missing_count,
        ingress_drops,
        session_drops,
        outbound_budget_drops,
        ingress_queue_capacity_msgs: BX_INGRESS_CAPACITY_MSGS,
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
    topology: &'static str,
    topology_layout: &'static str,
    lanes: usize,
    transactions_per_lane: usize,
    transaction_set: &'static str,
    transaction_set_id: &'static str,
    generation_scope: &'static str,
    generation_span_ms: u64,
    generation_included_in_rates: bool,
    profile_id: &'static str,
    jitter_min_ms: u64,
    jitter_max_ms: u64,
    jitter_seed: u64,
    target_offered_tps: u64,
    target_submission_interval_us: u64,
    repetition: usize,
    topology_repetition: usize,
    repetitions_total: usize,
    transactions_per_repetition: usize,
    pow_difficulty: u8,
    submission_order: &'static str,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_accepted: u64,
    transactions_stored: u64,
    transactions_persisted: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    storage_errors: u64,
    unresolved_dependency_transactions: u64,
    latency_samples: usize,
    propagation_samples: usize,
    acceptance_samples: usize,
    persisted_acceptance_samples: usize,
    submission_to_acceptance_samples: usize,
    submission_to_persisted_acceptance_samples: usize,
    submission_start_us: u64,
    submission_end_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_acceptance_us: u64,
    last_acceptance_us: u64,
    first_persisted_us: u64,
    last_persisted_us: u64,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    acceptance_rate: RateMetric,
    persisted_acceptance_rate: RateMetric,
    completion_rate: RateMetric,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    acceptance_latency_p50_us: Option<u64>,
    acceptance_latency_p95_us: Option<u64>,
    acceptance_latency_p99_us: Option<u64>,
    persisted_acceptance_latency_p50_us: Option<u64>,
    persisted_acceptance_latency_p95_us: Option<u64>,
    persisted_acceptance_latency_p99_us: Option<u64>,
    submission_to_acceptance_latency_p50_us: Option<u64>,
    submission_to_acceptance_latency_p95_us: Option<u64>,
    submission_to_acceptance_latency_p99_us: Option<u64>,
    submission_to_persisted_acceptance_latency_p50_us: Option<u64>,
    submission_to_persisted_acceptance_latency_p95_us: Option<u64>,
    submission_to_persisted_acceptance_latency_p99_us: Option<u64>,
    drain_ms: u64,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    backlog_sample_count: usize,
    backlog_series_ms: Vec<u64>,
    backlog_series_submitted: Vec<u64>,
    backlog_series_received: Vec<u64>,
    backlog_series_accepted: Vec<u64>,
    backlog_series_persisted: Vec<u64>,
    backlog_series_pending: Vec<u64>,
    backlog_series_rss_kb: Vec<Option<u64>>,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    parent_missing_count: usize,
    ingress_drops: u64,
    session_drops: u64,
    outbound_budget_drops: u64,
    ingress_queue_capacity_msgs: usize,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_cleanup_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
    rss_scope: &'static str,
    window_basis: &'static str,
    timing_scope: &'static str,
    throughput_note: &'static str,
}

fn build_repetition_record(
    round: &BxRound,
    repetition: usize,
    topology_repetition: usize,
) -> RepetitionRecord {
    let (p50, p95, p99) = stats_us(&round.propagation_us);
    let (a50, a95, a99) = stats_us(&round.acceptance_us);
    let (pa50, pa95, pa99) = stats_us(&round.persisted_acceptance_us);
    let (sa50, sa95, sa99) = stats_us(&round.submission_to_acceptance_us);
    let (sp50, sp95, sp99) = stats_us(&round.submission_to_persisted_acceptance_us);
    let mut series_ms = Vec::with_capacity(round.series.len());
    let mut series_submitted = Vec::with_capacity(round.series.len());
    let mut series_received = Vec::with_capacity(round.series.len());
    let mut series_accepted = Vec::with_capacity(round.series.len());
    let mut series_persisted = Vec::with_capacity(round.series.len());
    let mut series_pending = Vec::with_capacity(round.series.len());
    let mut series_rss = Vec::with_capacity(round.series.len());
    for (at_ms, submitted, received, accepted, persisted, rss) in &round.series {
        series_ms.push(*at_ms);
        series_submitted.push(*submitted);
        series_received.push(*received);
        series_accepted.push(*accepted);
        series_persisted.push(*persisted);
        series_pending.push(submitted.saturating_sub(*persisted));
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
        topology: round.topology.id(),
        topology_layout: round.topology.layout(),
        lanes: round.topology.lanes(),
        transactions_per_lane: round.topology.transactions_per_lane(),
        transaction_set: TRANSACTION_SET,
        transaction_set_id: round.topology.transaction_set_id(),
        generation_scope: GENERATION_SCOPE,
        generation_span_ms: round.generation_span_ms,
        generation_included_in_rates: false,
        profile_id: round.profile.id,
        jitter_min_ms: round.profile.min_ms,
        jitter_max_ms: round.profile.max_ms,
        jitter_seed: round.seed,
        target_offered_tps: round.target_tps,
        target_submission_interval_us: round.submission_interval_us,
        repetition,
        topology_repetition,
        repetitions_total: REPETITIONS_PER_CELL,
        transactions_per_repetition: TXS_PER_REPETITION,
        pow_difficulty: POW_DIFFICULTY,
        submission_order: SUBMISSION_ORDER,
        transactions_submitted: round.submitted,
        transactions_received: round.received,
        transactions_accepted: round.accepted,
        transactions_stored: round.stored,
        transactions_persisted: round.persisted,
        transactions_rejected: round.rejected,
        duplicates_received: round.duplicates,
        storage_errors: round.storage_errors,
        unresolved_dependency_transactions: round.unresolved_dependencies,
        latency_samples: round.submission_to_persisted_acceptance_us.len(),
        propagation_samples: round.propagation_us.len(),
        acceptance_samples: round.acceptance_us.len(),
        persisted_acceptance_samples: round.persisted_acceptance_us.len(),
        submission_to_acceptance_samples: round.submission_to_acceptance_us.len(),
        submission_to_persisted_acceptance_samples: round
            .submission_to_persisted_acceptance_us
            .len(),
        submission_start_us: round.first_submission_us,
        submission_end_us: round.last_submission_us,
        first_receipt_us: round.first_receipt_us,
        last_receipt_us: round.last_receipt_us,
        first_acceptance_us: round.first_acceptance_us,
        last_acceptance_us: round.last_acceptance_us,
        first_persisted_us: round.first_persisted_us,
        last_persisted_us: round.last_persisted_us,
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
        acceptance_rate: make_rate_metric(
            round.accepted,
            round.first_acceptance_us,
            round.last_acceptance_us,
            FORMULA_ACCEPTED,
        ),
        persisted_acceptance_rate: make_rate_metric(
            round.persisted,
            round.first_persisted_us,
            round.last_persisted_us,
            FORMULA_PERSISTED_ACCEPTANCE,
        ),
        completion_rate: make_rate_metric(
            round.persisted,
            round.first_submission_us,
            round.last_persisted_us,
            FORMULA_COMPLETION,
        ),
        propagation_latency_p50_us: p50,
        propagation_latency_p95_us: p95,
        propagation_latency_p99_us: p99,
        acceptance_latency_p50_us: a50,
        acceptance_latency_p95_us: a95,
        acceptance_latency_p99_us: a99,
        persisted_acceptance_latency_p50_us: pa50,
        persisted_acceptance_latency_p95_us: pa95,
        persisted_acceptance_latency_p99_us: pa99,
        submission_to_acceptance_latency_p50_us: sa50,
        submission_to_acceptance_latency_p95_us: sa95,
        submission_to_acceptance_latency_p99_us: sa99,
        submission_to_persisted_acceptance_latency_p50_us: sp50,
        submission_to_persisted_acceptance_latency_p95_us: sp95,
        submission_to_persisted_acceptance_latency_p99_us: sp99,
        drain_ms: round.drain_us / 1_000,
        backlog_peak: round.backlog_peak,
        backlog_peak_at_ms: round.backlog_peak_at_ms,
        backlog_sample_count: series_ms.len(),
        backlog_series_ms: series_ms,
        backlog_series_submitted: series_submitted,
        backlog_series_received: series_received,
        backlog_series_accepted: series_accepted,
        backlog_series_persisted: series_persisted,
        backlog_series_pending: series_pending,
        backlog_series_rss_kb: series_rss,
        dag_transaction_count: round.dag_transaction_count,
        storage_transaction_count: round.storage_transaction_count,
        applied_mark_count: round.applied_mark_count,
        parent_missing_count: round.parent_missing_count,
        ingress_drops: round.ingress_drops,
        session_drops: round.session_drops,
        outbound_budget_drops: round.outbound_budget_drops,
        ingress_queue_capacity_msgs: round.ingress_queue_capacity_msgs,
        rss_before_load_kb: round.rss_before_load_kb,
        rss_after_submissions_kb: round.rss_after_submissions_kb,
        rss_under_load_peak_kb: round.rss_under_load_peak_kb,
        rss_after_cleanup_kb: round.rss_after_cleanup_kb,
        rss_process_peak_kb: round.rss_process_peak_kb,
        rss_scope: "process_wide_two_nodes_same_process",
        window_basis: "per_repetition_from_first_submission",
        timing_scope: TIMING_SCOPE,
        throughput_note: THROUGHPUT_NOTE,
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
    topology: String,
    topology_layout: String,
    lanes: Option<usize>,
    transactions_per_lane: Option<usize>,
    profile_id: String,
    jitter_min_ms: Option<u64>,
    jitter_max_ms: Option<u64>,
    target_offered_tps: Option<u64>,
    repetitions: usize,
    transactions_per_repetition: usize,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_accepted: u64,
    transactions_stored: u64,
    transactions_persisted: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    storage_errors: u64,
    unresolved_dependency_transactions: u64,
    latency_samples: usize,
    propagation_samples: usize,
    acceptance_samples: usize,
    persisted_acceptance_samples: usize,
    submission_to_acceptance_samples: usize,
    submission_to_persisted_acceptance_samples: usize,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    acceptance_rate: RateMetric,
    persisted_acceptance_rate: RateMetric,
    completion_rate: RateMetric,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    acceptance_latency_p50_us: Option<u64>,
    acceptance_latency_p95_us: Option<u64>,
    acceptance_latency_p99_us: Option<u64>,
    persisted_acceptance_latency_p50_us: Option<u64>,
    persisted_acceptance_latency_p95_us: Option<u64>,
    persisted_acceptance_latency_p99_us: Option<u64>,
    submission_to_acceptance_latency_p50_us: Option<u64>,
    submission_to_acceptance_latency_p95_us: Option<u64>,
    submission_to_acceptance_latency_p99_us: Option<u64>,
    submission_to_persisted_acceptance_latency_p50_us: Option<u64>,
    submission_to_persisted_acceptance_latency_p95_us: Option<u64>,
    submission_to_persisted_acceptance_latency_p99_us: Option<u64>,
    drain_ms_mean: Option<f64>,
    drain_ms_max: Option<u64>,
    backlog_peak_max: u64,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    parent_missing_count: usize,
    rss_before_load_mean_kb: Option<f64>,
    rss_under_load_peak_max_kb: Option<u64>,
    rss_process_peak_max_kb: Option<u64>,
    rss_scope: &'static str,
    window_basis: &'static str,
    timing_scope: &'static str,
    throughput_note: &'static str,
}

fn aggregate_rounds(
    scope: String,
    topology: Option<Topology>,
    profile_id: String,
    jitter: Option<(u64, u64)>,
    target: Option<u64>,
    rounds: &[&BxRound],
) -> AggregateRecord {
    let mut propagation = Vec::new();
    let mut acceptance = Vec::new();
    let mut persisted_acceptance = Vec::new();
    let mut submission_to_acceptance = Vec::new();
    let mut submission_to_persisted_acceptance = Vec::new();
    let mut offered_duration_us = 0u64;
    let mut reception_duration_us = 0u64;
    let mut acceptance_duration_us = 0u64;
    let mut persisted_acceptance_duration_us = 0u64;
    let mut completion_duration_us = 0u64;
    let mut submitted = 0u64;
    let mut received = 0u64;
    let mut accepted = 0u64;
    let mut stored = 0u64;
    let mut persisted = 0u64;
    let mut rejected = 0u64;
    let mut duplicates = 0u64;
    let mut storage_errors = 0u64;
    let mut unresolved_dependencies = 0u64;
    let mut drain_ms = Vec::new();
    let mut backlog_peak_max = 0u64;
    let mut dag_transaction_count = 0usize;
    let mut storage_transaction_count = 0usize;
    let mut applied_mark_count = 0usize;
    let mut parent_missing_count = 0usize;
    let mut rss_before = Vec::new();
    let mut rss_peak = 0u64;
    let mut rss_process_peak = 0u64;

    for round in rounds {
        submitted += round.submitted;
        received += round.received;
        accepted += round.accepted;
        stored += round.stored;
        persisted += round.persisted;
        rejected += round.rejected;
        duplicates += round.duplicates;
        storage_errors += round.storage_errors;
        unresolved_dependencies += round.unresolved_dependencies;
        offered_duration_us += round
            .last_submission_us
            .saturating_sub(round.first_submission_us);
        reception_duration_us += round.last_receipt_us.saturating_sub(round.first_receipt_us);
        acceptance_duration_us += round
            .last_acceptance_us
            .saturating_sub(round.first_acceptance_us);
        persisted_acceptance_duration_us += round
            .last_persisted_us
            .saturating_sub(round.first_persisted_us);
        completion_duration_us += round
            .last_persisted_us
            .saturating_sub(round.first_submission_us);
        propagation.extend_from_slice(&round.propagation_us);
        acceptance.extend_from_slice(&round.acceptance_us);
        persisted_acceptance.extend_from_slice(&round.persisted_acceptance_us);
        submission_to_acceptance.extend_from_slice(&round.submission_to_acceptance_us);
        submission_to_persisted_acceptance
            .extend_from_slice(&round.submission_to_persisted_acceptance_us);
        drain_ms.push(round.drain_us / 1_000);
        backlog_peak_max = backlog_peak_max.max(round.backlog_peak);
        dag_transaction_count += round.dag_transaction_count;
        storage_transaction_count += round.storage_transaction_count;
        applied_mark_count += round.applied_mark_count;
        parent_missing_count += round.parent_missing_count;
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
    let (a50, a95, a99) = stats_us(&acceptance);
    let (pa50, pa95, pa99) = stats_us(&persisted_acceptance);
    let (sa50, sa95, sa99) = stats_us(&submission_to_acceptance);
    let (sp50, sp95, sp99) = stats_us(&submission_to_persisted_acceptance);

    AggregateRecord {
        schema_version: SCHEMA_VERSION,
        record_type: if target.is_some() {
            "cell_aggregate"
        } else {
            "overall_aggregate"
        },
        scenario: if target.is_some() {
            SCENARIO_CELL_AGGREGATE
        } else {
            SCENARIO_OVERALL_AGGREGATE
        },
        aggregate_scope: scope,
        sha: get_sha(),
        profile: get_profile(),
        os: get_os(),
        arch: get_arch(),
        nodes: 2,
        nodes_in_same_process: true,
        topology: topology
            .map(|value| value.id())
            .unwrap_or("all")
            .to_string(),
        topology_layout: topology
            .map(|value| value.layout())
            .unwrap_or("all_topologies")
            .to_string(),
        lanes: topology.map(|value| value.lanes()),
        transactions_per_lane: topology.map(|value| value.transactions_per_lane()),
        profile_id,
        jitter_min_ms: jitter.map(|value| value.0),
        jitter_max_ms: jitter.map(|value| value.1),
        target_offered_tps: target,
        repetitions: rounds.len(),
        transactions_per_repetition: TXS_PER_REPETITION,
        transactions_submitted: submitted,
        transactions_received: received,
        transactions_accepted: accepted,
        transactions_stored: stored,
        transactions_persisted: persisted,
        transactions_rejected: rejected,
        duplicates_received: duplicates,
        storage_errors,
        unresolved_dependency_transactions: unresolved_dependencies,
        latency_samples: submission_to_persisted_acceptance.len(),
        propagation_samples: propagation.len(),
        acceptance_samples: acceptance.len(),
        persisted_acceptance_samples: persisted_acceptance.len(),
        submission_to_acceptance_samples: submission_to_acceptance.len(),
        submission_to_persisted_acceptance_samples: submission_to_persisted_acceptance.len(),
        offered_rate: make_rate_metric(submitted, 0, offered_duration_us, FORMULA_OFFERED),
        reception_rate: make_rate_metric(received, 0, reception_duration_us, FORMULA_RECEIVED),
        acceptance_rate: make_rate_metric(accepted, 0, acceptance_duration_us, FORMULA_ACCEPTED),
        persisted_acceptance_rate: make_rate_metric(
            persisted,
            0,
            persisted_acceptance_duration_us,
            FORMULA_PERSISTED_ACCEPTANCE,
        ),
        completion_rate: make_rate_metric(persisted, 0, completion_duration_us, FORMULA_COMPLETION),
        propagation_latency_p50_us: p50,
        propagation_latency_p95_us: p95,
        propagation_latency_p99_us: p99,
        acceptance_latency_p50_us: a50,
        acceptance_latency_p95_us: a95,
        acceptance_latency_p99_us: a99,
        persisted_acceptance_latency_p50_us: pa50,
        persisted_acceptance_latency_p95_us: pa95,
        persisted_acceptance_latency_p99_us: pa99,
        submission_to_acceptance_latency_p50_us: sa50,
        submission_to_acceptance_latency_p95_us: sa95,
        submission_to_acceptance_latency_p99_us: sa99,
        submission_to_persisted_acceptance_latency_p50_us: sp50,
        submission_to_persisted_acceptance_latency_p95_us: sp95,
        submission_to_persisted_acceptance_latency_p99_us: sp99,
        drain_ms_mean: if drain_ms.is_empty() {
            None
        } else {
            Some(drain_ms.iter().sum::<u64>() as f64 / drain_ms.len() as f64)
        },
        drain_ms_max: drain_ms.iter().copied().max(),
        backlog_peak_max,
        dag_transaction_count,
        storage_transaction_count,
        applied_mark_count,
        parent_missing_count,
        rss_before_load_mean_kb: if rss_before.is_empty() {
            None
        } else {
            Some(rss_before.iter().sum::<u64>() as f64 / rss_before.len() as f64)
        },
        rss_under_load_peak_max_kb: (rss_peak > 0).then_some(rss_peak),
        rss_process_peak_max_kb: (rss_process_peak > 0).then_some(rss_process_peak),
        rss_scope: "process_wide_two_nodes_same_process",
        window_basis: "sum_of_non_overlapping_repetition_windows",
        timing_scope: TIMING_SCOPE,
        throughput_note: THROUGHPUT_NOTE,
    }
}

fn log_jsonl<T: Serialize>(record: &T) {
    println!(
        "BENCH_JSONL:{}",
        serde_json::to_string(record).expect("serialize record")
    );
}
fn bx_only_filter() -> Option<Vec<(String, String, u64)>> {
    let raw = std::env::var("BX_ONLY").ok()?;
    let mut parsed = Vec::new();
    for item in raw.split(';').filter(|item| !item.trim().is_empty()) {
        let mut parts = item.split(':');
        let topology = parts.next()?.trim().to_string();
        let profile = parts.next()?.trim().to_string();
        let target = parts.next()?.trim().parse::<u64>().ok()?;
        parsed.push((topology, profile, target));
    }
    (!parsed.is_empty()).then_some(parsed)
}

fn bx_selected(
    filter: Option<&Vec<(String, String, u64)>>,
    topology: Topology,
    profile: JitterProfile,
    target_tps: u64,
) -> bool {
    filter.map_or(true, |entries| {
        entries
            .iter()
            .any(|(entry_topology, entry_profile, entry_target)| {
                entry_topology == topology.id()
                    && entry_profile == profile.id
                    && *entry_target == target_tps
            })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bx01_dag_topology() {
    let _reset = JitterReset;
    let only = bx_only_filter();
    let ts0: u64 = 1_750_300_000_000;

    let chain_generation_start = Instant::now();
    let chain_set = build_transaction_set(Topology::Chain, ts0);
    let chain_generation_ms = chain_generation_start.elapsed().as_millis() as u64;

    let multi_generation_start = Instant::now();
    let multi_set = build_transaction_set(Topology::MultiLane, ts0);
    let multi_generation_ms = multi_generation_start.elapsed().as_millis() as u64;

    assert_eq!(chain_set.len(), TXS_PER_REPETITION, "chain set size");
    assert_eq!(
        multi_set.len(),
        MULTI_LANE_COUNT * MULTI_LANE_TX_COUNT,
        "multi-lane set size"
    );
    println!(
        "BX_GEN chain_txs={} chain_span_ms={} multi_lane_txs={} multi_span_ms={}",
        chain_set.len(),
        chain_generation_ms,
        multi_set.len(),
        multi_generation_ms
    );

    let mut all_rounds: Vec<BxRound> = Vec::with_capacity(
        TOPOLOGIES.len() * PROFILES.len() * TARGET_RATES.len() * REPETITIONS_PER_CELL,
    );
    let mut cell_round_indices: HashMap<(Topology, &'static str, u64), Vec<usize>> = HashMap::new();
    let mut global_repetition = 0usize;

    for topology in TOPOLOGIES {
        let sent = match topology {
            Topology::Chain => &chain_set,
            Topology::MultiLane => &multi_set,
        };
        let generation_span_ms = match topology {
            Topology::Chain => chain_generation_ms,
            Topology::MultiLane => multi_generation_ms,
        };
        for (profile_index, profile) in PROFILES.iter().copied().enumerate() {
            for (rate_index, target_tps) in TARGET_RATES.iter().copied().enumerate() {
                if !bx_selected(only.as_ref(), topology, profile, target_tps) {
                    continue;
                }
                let submission_interval_us = 1_000_000 / target_tps;
                for topology_repetition in 1..=REPETITIONS_PER_CELL {
                    global_repetition += 1;
                    let seed = 0xB4_0000
                        + (profile_index as u64) * 1_000
                        + (rate_index as u64) * 100
                        + topology_repetition as u64;
                    let port = PORT_BASE + ((global_repetition - 1) as u16) * 4;
                    let round = run_round_bx(
                        topology,
                        profile,
                        seed,
                        target_tps,
                        submission_interval_us,
                        generation_span_ms,
                        sent.clone(),
                        port,
                    )
                    .await;

                    let record =
                        build_repetition_record(&round, global_repetition, topology_repetition);
                    assert_eq!(
                        record.transactions_persisted, TXS_PER_REPETITION as u64,
                        "persisted count"
                    );
                    assert_eq!(
                        record.transactions_accepted, TXS_PER_REPETITION as u64,
                        "accepted count"
                    );
                    assert_eq!(
                        record.submission_to_persisted_acceptance_samples, TXS_PER_REPETITION,
                        "submission-to-persisted-acceptance samples"
                    );
                    assert!(!round.series.is_empty(), "backlog samples");
                    assert!(
                        round.last_submission_us > round.first_submission_us,
                        "submission span"
                    );
                    assert!(
                        round.last_persisted_us >= round.last_submission_us,
                        "completion order"
                    );

                    log_jsonl(&record);
                    println!(
                        "BX_REP topology={} profile={} target={} rep={} completion_tps={:.1} persisted_tps={:.1} sub_to_persist_p50_us={} sub_to_persist_p95_us={} sub_to_persist_p99_us={} prop_p50_us={} backlog_peak={} drain_ms={}",
                        topology.id(),
                        profile.id,
                        target_tps,
                        topology_repetition,
                        record.completion_rate.value.unwrap_or(0.0),
                        record.persisted_acceptance_rate.value.unwrap_or(0.0),
                        record
                            .submission_to_persisted_acceptance_latency_p50_us
                            .unwrap_or(0),
                        record
                            .submission_to_persisted_acceptance_latency_p95_us
                            .unwrap_or(0),
                        record
                            .submission_to_persisted_acceptance_latency_p99_us
                            .unwrap_or(0),
                        record.propagation_latency_p50_us.unwrap_or(0),
                        round.backlog_peak,
                        round.drain_us / 1_000,
                    );
                    cell_round_indices
                        .entry((topology, profile.id, target_tps))
                        .or_default()
                        .push(all_rounds.len());
                    all_rounds.push(round);
                }
            }
        }
    }

    let mut cell_aggregates: HashMap<(Topology, &'static str, u64), AggregateRecord> =
        HashMap::new();
    for topology in TOPOLOGIES {
        for profile in PROFILES.iter().copied() {
            for target_tps in TARGET_RATES.iter().copied() {
                if !bx_selected(only.as_ref(), topology, profile, target_tps) {
                    continue;
                }
                let indices = cell_round_indices
                    .get(&(topology, profile.id, target_tps))
                    .expect("cell repetitions");
                assert_eq!(indices.len(), REPETITIONS_PER_CELL, "cell repetition count");
                let rounds: Vec<&BxRound> =
                    indices.iter().map(|index| &all_rounds[*index]).collect();
                let aggregate = aggregate_rounds(
                    format!(
                        "topology={},profile={},target_tps={}",
                        topology.id(),
                        profile.id,
                        target_tps
                    ),
                    Some(topology),
                    profile.id.to_string(),
                    Some((profile.min_ms, profile.max_ms)),
                    Some(target_tps),
                    &rounds,
                );
                assert_eq!(
                    aggregate.transactions_persisted,
                    (TXS_PER_REPETITION * REPETITIONS_PER_CELL) as u64,
                    "cell persisted total"
                );
                assert_eq!(
                    aggregate.dag_transaction_count,
                    TXS_PER_REPETITION * REPETITIONS_PER_CELL,
                    "cell DAG total"
                );
                log_jsonl(&aggregate);
                println!(
                    "BX_CELL topology={} profile={} target={} completion_tps={:.1} persisted_tps={:.1} sub_to_persist_p50_us={} sub_to_persist_p95_us={} sub_to_persist_p99_us={} backlog_max={} drain_mean_ms={:.1}",
                    topology.id(),
                    profile.id,
                    target_tps,
                    aggregate.completion_rate.value.unwrap_or(0.0),
                    aggregate.persisted_acceptance_rate.value.unwrap_or(0.0),
                    aggregate
                        .submission_to_persisted_acceptance_latency_p50_us
                        .unwrap_or(0),
                    aggregate
                        .submission_to_persisted_acceptance_latency_p95_us
                        .unwrap_or(0),
                    aggregate
                        .submission_to_persisted_acceptance_latency_p99_us
                        .unwrap_or(0),
                    aggregate.backlog_peak_max,
                    aggregate.drain_ms_mean.unwrap_or(0.0),
                );
                cell_aggregates.insert((topology, profile.id, target_tps), aggregate);
            }
        }
    }

    for profile in PROFILES.iter().copied() {
        for target_tps in TARGET_RATES.iter().copied() {
            let (Some(chain), Some(multi)) = (
                cell_aggregates.get(&(Topology::Chain, profile.id, target_tps)),
                cell_aggregates.get(&(Topology::MultiLane, profile.id, target_tps)),
            ) else {
                continue;
            };
            let chain_tps = chain.completion_rate.value.unwrap_or(0.0);
            let multi_tps = multi.completion_rate.value.unwrap_or(0.0);
            let delta = multi_tps - chain_tps;
            let relative = if chain_tps == 0.0 {
                f64::NAN
            } else {
                delta / chain_tps * 100.0
            };
            println!(
                "BX_COMPARE profile={} target={} chain_completion_tps={:.1} multi_completion_tps={:.1} delta_tps={:.1} delta_pct={:.1}",
                profile.id,
                target_tps,
                chain_tps,
                multi_tps,
                delta,
                relative
            );
        }
    }

    let all_refs: Vec<&BxRound> = all_rounds.iter().collect();
    let overall = aggregate_rounds(
        "overall".to_string(),
        None,
        "all".to_string(),
        None,
        None,
        &all_refs,
    );
    let expected_rounds =
        TOPOLOGIES.len() * PROFILES.len() * TARGET_RATES.len() * REPETITIONS_PER_CELL;
    if only.is_none() {
        assert_eq!(all_rounds.len(), expected_rounds, "executed round count");
    }
    assert_eq!(
        overall.transactions_persisted,
        (TXS_PER_REPETITION * all_rounds.len()) as u64,
        "overall persisted total"
    );
    assert_eq!(
        overall.submission_to_persisted_acceptance_samples,
        TXS_PER_REPETITION * all_rounds.len(),
        "overall latency sample total"
    );
    log_jsonl(&overall);
    println!(
        "BX_OVERALL completion_tps={:.1} persisted_tps={:.1} sub_to_persist_p50_us={} sub_to_persist_p95_us={} sub_to_persist_p99_us={} backlog_max={} drain_mean_ms={:.1}",
        overall.completion_rate.value.unwrap_or(0.0),
        overall.persisted_acceptance_rate.value.unwrap_or(0.0),
        overall
            .submission_to_persisted_acceptance_latency_p50_us
            .unwrap_or(0),
        overall
            .submission_to_persisted_acceptance_latency_p95_us
            .unwrap_or(0),
        overall
            .submission_to_persisted_acceptance_latency_p99_us
            .unwrap_or(0),
        overall.backlog_peak_max,
        overall.drain_ms_mean.unwrap_or(0.0),
    );
}
