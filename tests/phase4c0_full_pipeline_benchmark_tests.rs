#![cfg(all(
    feature = "test-pipeline-trace",
    feature = "test-jitter-control"
))]

use aether_unified::{
    config::NodeConfig,
    ledger::Ledger,
    node::{run_node, NodeHandles},
    p2p::{
        clear_test_propagation_jitter, set_test_propagation_jitter, P2PProtocolMode,
    },
    pipeline_trace::{self, PipelineEventKind, PipelineRecorder},
    storage::Storage,
    sync_stats::SyncStatsSnapshot,
    transaction::{Address, Transaction, TransactionId, DEFAULT_NETWORK_ID},
    transaction_processor::TransactionProcessor,
    validation::ValidationMode,
    wallet::Wallet,
};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

const SCENARIO_REPETITION: &str = "c0_full_pipeline";
const SCHEMA_VERSION: u32 = 9;
const POW_DIFFICULTY: u8 = 24;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 300;
const MULTI_LANE_COUNT: usize = 10;
const MULTI_LANE_TX_COUNT: usize = 30;
const REPETITIONS_PER_CELL: usize = 1;
const PORT_BASE: u16 = 27000;
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(20);
const INITIAL_SENDER_BALANCE: u64 = 1_000_000;
const SUBMISSION_WORKERS: usize = 4;
const SUBMISSION_ORDER: &str = "pre_generated_vector_index_order_parallel_workers";
const TRANSACTION_SET: &str = "one_shared_pre_generated_valid_set_per_topology";
const GENERATION_SCOPE: &str = "one_time_shared_pow_per_topology_before_all_repetitions";
const VALIDATION_MODE: &str = "fresh_live_rpc_and_p2p_ingress";
const RATE_UNIT: &str = "transactions_per_second";
const FORMULA_OFFERED: &str =
    "submitted / ((last_submission_us - first_submission_us) / 1_000_000)";
const FORMULA_ADMITTED: &str =
    "admitted / ((last_admission_us - first_admission_us) / 1_000_000)";
const FORMULA_RECEIVED: &str =
    "received / ((last_receipt_us - first_receipt_us) / 1_000_000)";
const FORMULA_APPLIED: &str =
    "applied / ((last_applied_us - first_applied_us) / 1_000_000)";
const FORMULA_COMPLETION: &str =
    "persisted / ((last_persisted_us - first_submission_us) / 1_000_000)";
const TIMING_SCOPE: &str = concat!(
    "offered=client call start; admitted=production send_transaction return; ",
    "receipt=production receiver ingress dequeue; admitted_rx=production queue enqueue; ",
    "drain_start=production drainer SELECT; applied=processor return after persistence; ",
    "end_to_end=client call start to applied; persisted=post-drain storage row+applied verification"
);
const THROUGHPUT_NOTE: &str = concat!(
    "Two real node instances on loopback in one process. Submissions call the production ",
    "AetherRpcImpl::send_transaction handler directly; HTTP framing and per-IP rate limiting ",
    "are excluded from the load, while the node's HTTP server is smoke-tested separately. ",
    "P2P relay, receiver ingestion, mempool admission, production drainer and ",
    "TransactionProcessor are exercised without a test consumer."
);
const PERSISTENCE_NOTE: &str = concat!(
    "Processor return includes STEP 8 storage row + incremental ledger save. Post-drain ",
    "audit verifies DAG, ledger, Sled row, applied mark, then reopen verifies durability."
);

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
            Topology::Chain => "chain_1x300_c0_full_pipeline",
            Topology::MultiLane => "multi_lane_10x30_c0_full_pipeline",
        }
    }

    fn receiver_for(self, lane: usize) -> Address {
        match self {
            Topology::Chain => [0xCC; 32],
            Topology::MultiLane => [0xC0 + lane as u8; 32],
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

const PROFILES: [JitterProfile; 2] = [
    JitterProfile {
        id: "none_0_0",
        min_ms: 0,
        max_ms: 0,
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
        pipeline_trace::clear();
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

fn wallet_c0(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn mine_nonce_parallel(tx: &Transaction, difficulty: u8) -> u64 {
    let threads = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4)
        .min(16) as u64;
    let found = AtomicBool::new(false);
    let nonce = AtomicU64::new(u64::MAX);
    std::thread::scope(|scope| {
        for lane in 0..threads {
            let found = &found;
            let nonce = &nonce;
            scope.spawn(move || {
                let mut candidate = tx.clone();
                let mut value = lane;
                while !found.load(Ordering::Relaxed) {
                    candidate.nonce = value;
                    if candidate.verify_pow(difficulty) {
                        if !found.swap(true, Ordering::Relaxed) {
                            nonce.store(value, Ordering::Relaxed);
                        }
                        break;
                    }
                    value = value.wrapping_add(threads);
                }
            });
        }
    });
    let value = nonce.load(Ordering::Relaxed);
    assert_ne!(value, u64::MAX, "parallel PoW search found no nonce");
    value
}

fn make_valid_tx_c0(
    wallet: &Wallet,
    receiver: Address,
    parents: [TransactionId; 2],
    account_nonce: u64,
    timestamp: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        receiver,
        TX_VALUE,
        TX_FEE,
        timestamp,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = mine_nonce_parallel(&tx, POW_DIFFICULTY);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Fresh)
        .expect("freshly mined+signed tx must pass");
    tx
}

fn build_transaction_set(topology: Topology, ts0: u64) -> Vec<Transaction> {
    let mut sent = Vec::with_capacity(TXS_PER_REPETITION);
    match topology {
        Topology::Chain => {
            let wallet = wallet_c0(980_001);
            let mut previous = [0u8; 32];
            for index in 0..TXS_PER_REPETITION {
                let tx = make_valid_tx_c0(
                    &wallet,
                    topology.receiver_for(0),
                    [previous, [0u8; 32]],
                    1 + index as u64,
                    ts0 + index as u64,
                );
                previous = tx.id;
                sent.push(tx);
                if (index + 1) % 25 == 0 {
                    eprintln!("[c0] chain generation {}/{}", index + 1, TXS_PER_REPETITION);
                }
            }
        }
        Topology::MultiLane => {
            let wallets: Vec<Wallet> = (0..MULTI_LANE_COUNT)
                .map(|lane| wallet_c0(981_000 + lane as u64))
                .collect();
            let mut previous = [[0u8; 32]; MULTI_LANE_COUNT];
            for step in 0..MULTI_LANE_TX_COUNT {
                for (lane, wallet) in wallets.iter().enumerate() {
                    let tx = make_valid_tx_c0(
                        wallet,
                        topology.receiver_for(lane),
                        [previous[lane], [0u8; 32]],
                        1 + step as u64,
                        ts0 + (step * MULTI_LANE_COUNT + lane) as u64,
                    );
                    previous[lane] = tx.id;
                    sent.push(tx);
                }
                if (step + 1) % 5 == 0 {
                    eprintln!(
                        "[c0] multi-lane generation {}/{}",
                        (step + 1) * MULTI_LANE_COUNT,
                        TXS_PER_REPETITION
                    );
                }
            }
        }
    }
    sent
}

fn sender_expectations(sent: &[Transaction]) -> HashMap<Address, u64> {
    let mut counts = HashMap::new();
    for tx in sent {
        *counts.entry(tx.sender).or_insert(0) += 1;
    }
    counts
}

fn receiver_expectations(sent: &[Transaction]) -> HashMap<Address, u64> {
    let mut totals = HashMap::new();
    for tx in sent {
        *totals.entry(tx.receiver).or_insert(0) += tx.amount;
    }
    totals
}

#[derive(Default, Clone, Copy)]
struct TxTrace {
    ingress: Option<Instant>,
    accepted: Option<Instant>,
    drain_start: Option<Instant>,
    applied: Option<Instant>,
    ingress_events: u64,
    accepted_events: u64,
}

fn trace_by_id(events: &[pipeline_trace::PipelineEvent], label: &str) -> HashMap<TransactionId, TxTrace> {
    let mut traces: HashMap<TransactionId, TxTrace> = HashMap::new();
    for event in events.iter().filter(|event| event.label == label) {
        let entry = traces.entry(event.tx_id).or_default();
        match event.kind {
            PipelineEventKind::ReceiverIngress => {
                entry.ingress_events += 1;
                entry.ingress.get_or_insert(event.at);
            }
            PipelineEventKind::Accepted => {
                entry.accepted_events += 1;
                entry.accepted = Some(event.at);
            }
            PipelineEventKind::DrainStart => entry.drain_start = Some(event.at),
            PipelineEventKind::Applied => entry.applied = Some(event.at),
        }
    }
    traces
}

struct LedgerAudit {
    initial_supply: u64,
    final_supply: u64,
    expected_final_supply: u64,
    fees_burned: u64,
    expected_fees_burned: u64,
    sender_nonce_mismatches: u64,
    sender_balance_mismatches: u64,
    receiver_balance_mismatches: u64,
    fee_burn_mismatches: u64,
    supply_mismatches: u64,
    storage_balance_mismatches: u64,
    storage_nonce_mismatches: u64,
    storage_applied_mismatches: u64,
    storage_row_mismatches: u64,
    storage_weight_mismatches: u64,
    persisted: u64,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    dag_missing_count: usize,
    parent_missing_count: usize,
}

fn audit_ledger(
    ledger: &Ledger,
    storage: &Storage,
    dag_transactions: &HashSet<TransactionId>,
    sent: &[Transaction],
    ledger_initial_supply: u64,
) -> LedgerAudit {
    let senders = sender_expectations(sent);
    let receivers = receiver_expectations(sent);
    let initial_supply = ledger_initial_supply;
    let expected_fees_burned = sent.len() as u64 * TX_FEE;
    let expected_final_supply = initial_supply.saturating_sub(expected_fees_burned);
    let mut audit = LedgerAudit {
        initial_supply,
        final_supply: ledger.total_supply(),
        expected_final_supply,
        fees_burned: ledger.total_fees_burned(),
        expected_fees_burned,
        sender_nonce_mismatches: 0,
        sender_balance_mismatches: 0,
        receiver_balance_mismatches: 0,
        fee_burn_mismatches: 0,
        supply_mismatches: 0,
        storage_balance_mismatches: 0,
        storage_nonce_mismatches: 0,
        storage_applied_mismatches: 0,
        storage_row_mismatches: 0,
        storage_weight_mismatches: 0,
        persisted: 0,
        dag_transaction_count: dag_transactions.len(),
        storage_transaction_count: storage.transaction_count().unwrap_or(0),
        applied_mark_count: ledger.applied.len(),
        dag_missing_count: 0,
        parent_missing_count: 0,
    };

    if ledger.total_fees_burned() != expected_fees_burned
        || ledger.fee_burn_balance() != expected_fees_burned
    {
        audit.fee_burn_mismatches += 1;
    }
    if ledger.total_supply() != expected_final_supply {
        audit.supply_mismatches += 1;
    }

    for (sender, count) in &senders {
        let expected_balance = INITIAL_SENDER_BALANCE.saturating_sub(*count * (TX_VALUE + TX_FEE));
        if ledger.get_nonce(sender) != *count {
            audit.sender_nonce_mismatches += 1;
        }
        if ledger.get_balance(sender) != expected_balance {
            audit.sender_balance_mismatches += 1;
        }
        if storage.get_nonce(*sender).ok() != Some(*count) {
            audit.storage_nonce_mismatches += 1;
        }
        if storage.get_balance(*sender).ok() != Some(expected_balance) {
            audit.storage_balance_mismatches += 1;
        }
    }

    for (receiver, expected_balance) in &receivers {
        if ledger.get_balance(receiver) != *expected_balance {
            audit.receiver_balance_mismatches += 1;
        }
        if storage.get_balance(*receiver).ok() != Some(*expected_balance) {
            audit.storage_balance_mismatches += 1;
        }
    }

    let applied_count = storage.get_all_applied().map(|items| items.len()).unwrap_or(0);
    if applied_count != sent.len() {
        audit.storage_applied_mismatches += 1;
    }
    for tx in sent {
        if !dag_transactions.contains(&tx.id) {
            audit.dag_missing_count += 1;
        }
        for parent in tx.parents.iter().filter(|parent| **parent != [0u8; 32]) {
            if !dag_transactions.contains(parent) {
                audit.parent_missing_count += 1;
            }
        }
        if !ledger.is_applied(&tx.id) || storage.is_applied(tx.id).ok() != Some(true) {
            audit.storage_applied_mismatches += 1;
        }
        match storage.get_transaction(tx.id) {
            Ok(row) if transaction_payload_matches(&row, tx) => {
                audit.persisted += 1;
                if row.weight != tx.weight {
                    audit.storage_weight_mismatches += 1;
                }
            }
            _ => audit.storage_row_mismatches += 1,
        }
    }
    audit
}

fn transaction_payload_matches(stored: &Transaction, sent: &Transaction) -> bool {
    stored.id == sent.id
        && stored.parents == sent.parents
        && stored.sender == sent.sender
        && stored.receiver == sent.receiver
        && stored.amount == sent.amount
        && stored.fee == sent.fee
        && stored.timestamp == sent.timestamp
        && stored.nonce == sent.nonce
        && stored.account_nonce == sent.account_nonce
        && stored.signature == sent.signature
        && stored.public_key == sent.public_key
}

#[derive(Serialize)]
struct P2PDiagnostics {
    ingress_drops: u64,
    session_drops: u64,
    outbound_budget_drops: u64,
    ingress_reserved_bytes: usize,
    propagation_inflight: usize,
}

struct PersistentAudit {
    reload_ok: bool,
    balance_mismatches: u64,
    nonce_mismatches: u64,
    applied_mismatches: u64,
    supply_mismatches: u64,
    fee_mismatches: u64,
    transaction_count_mismatches: u64,
}

async fn audit_persistent(
    dir: &Path,
    sent: &[Transaction],
    ledger_initial_supply: u64,
) -> PersistentAudit {
    let senders = sender_expectations(sent);
    let receivers = receiver_expectations(sent);
    let expected_fees_burned = sent.len() as u64 * TX_FEE;
    let expected_final_supply = ledger_initial_supply.saturating_sub(expected_fees_burned);

    let storage = {
        let mut attempt = 0;
        loop {
            match Storage::open(dir) {
                Ok(storage) => break Arc::new(RwLock::new(storage)),
                Err(error) if attempt < 60 => {
                    attempt += 1;
                    let message = error.to_string();
                    if !message.contains("could not acquire lock")
                        && !message.contains("Resource temporarily unavailable")
                    {
                        panic!("reopen persistent store: {}", message);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => panic!("reopen persistent store: {}", error),
            }
        }
    };
    let ledger = Ledger::new_with_storage(storage.clone())
        .await
        .expect("reload persistent ledger");
    let mut audit = PersistentAudit {
        reload_ok: false,
        balance_mismatches: 0,
        nonce_mismatches: 0,
        applied_mismatches: 0,
        supply_mismatches: 0,
        fee_mismatches: 0,
        transaction_count_mismatches: 0,
    };

    for (sender, count) in &senders {
        let expected_balance = INITIAL_SENDER_BALANCE.saturating_sub(*count * (TX_VALUE + TX_FEE));
        if ledger.get_balance(sender) != expected_balance {
            audit.balance_mismatches += 1;
        }
        if ledger.get_nonce(sender) != *count {
            audit.nonce_mismatches += 1;
        }
    }
    for (receiver, expected_balance) in &receivers {
        if ledger.get_balance(receiver) != *expected_balance {
            audit.balance_mismatches += 1;
        }
    }
    for tx in sent {
        if !ledger.is_applied(&tx.id) {
            audit.applied_mismatches += 1;
        }
    }
    if ledger.total_supply() != expected_final_supply {
        audit.supply_mismatches += 1;
    }
    if ledger.total_fees_burned() != expected_fees_burned {
        audit.fee_mismatches += 1;
    }
    let storage_guard = storage.read().await;
    let count = storage_guard.transaction_count().unwrap_or(0);
    if count != sent.len() {
        audit.transaction_count_mismatches += 1;
    }
    let applied_count = storage_guard
        .get_all_applied()
        .map(|applied| applied.len())
        .unwrap_or(0);
    if applied_count != sent.len() {
        audit.applied_mismatches += 1;
    }
    drop(storage_guard);

    audit.reload_ok = audit.balance_mismatches == 0
        && audit.nonce_mismatches == 0
        && audit.applied_mismatches == 0
        && audit.supply_mismatches == 0
        && audit.fee_mismatches == 0
        && audit.transaction_count_mismatches == 0;
    audit
}

async fn boot_node_c0(
    dir: &Path,
    p2p_port: u16,
    rpc_port: u16,
    bootnodes: Vec<String>,
    trace_label: &str,
) -> NodeHandles {
    let mut cfg = NodeConfig::default();
    cfg.node_type = "observer".to_string();
    cfg.data_dir = dir.to_path_buf();
    cfg.p2p_port = p2p_port;
    cfg.rpc_port = rpc_port;
    cfg.rpc_bind = "127.0.0.1".to_string();
    cfg.bootnodes = bootnodes;
    cfg.dns_seeds = Vec::new();
    cfg.network_id = Some(DEFAULT_NETWORK_ID);
    cfg.p2p_protocol = Some(P2PProtocolMode::LegacyV5);
    cfg.trace_label = Some(trace_label.to_string());
    run_node(cfg).await.expect("run_node")
}

async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut check: F)
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

async fn fund(node: &NodeHandles, senders: &HashMap<Address, u64>) {
    {
        let mut ledger = node.ledger.write().await;
        for address in senders.keys() {
            ledger.set_balance(address, INITIAL_SENDER_BALANCE);
        }
        ledger.save().await.expect("persist funding");
    }
    node.storage.read().await.flush().expect("flush funding");
}

async fn http_smoke(port: u16) -> u64 {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/", port);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        let response = client
            .post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "aether_getMempoolStats",
                "params": [],
                "id": 1
            }))
            .send()
            .await;
        if let Ok(response) = response {
            if response.status().is_success() {
                if let Ok(body) = response.json::<serde_json::Value>().await {
                    if body.get("error").is_none() {
                        return start.elapsed().as_millis() as u64;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("RPC HTTP smoke failed on port {}", port);
}

#[derive(Clone)]
struct SubmitMark {
    submit: Instant,
    admitted: Option<Instant>,
}

struct RoundRaw {
    submitted: u64,
    admitted: u64,
    rpc_refusals: u64,
    received: u64,
    duplicate_ingress: u64,
    receiver_admission_events: u64,
    receiver_admitted: u64,
    applied: u64,
    persisted: u64,
    duplicate_apply: u64,
    unresolved: u64,
    first_submission_us: u64,
    last_submission_us: u64,
    first_admission_us: u64,
    last_admission_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_drain_us: u64,
    last_drain_us: u64,
    first_applied_us: u64,
    last_applied_us: u64,
    first_persisted_us: u64,
    last_persisted_us: u64,
    persistence_confirmation_us: u64,
    admission_us: Vec<u64>,
    relay_us: Vec<u64>,
    receiver_admission_us: Vec<u64>,
    queue_wait_us: Vec<u64>,
    apply_us: Vec<u64>,
    end_to_end_us: Vec<u64>,
    backlog_peak: u64,
    receiver_queue_peak: u64,
    http_smoke_ms: u64,
    sync_stats: SyncStatsSnapshot,
    p2p: P2PDiagnostics,
    p2p_sender: P2PDiagnostics,
    ledger_initial_supply: u64,
    audit: LedgerAudit,
    persistent: PersistentAudit,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_drain_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
}

#[derive(Serialize)]
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
    runtime_path: &'static str,
    rpc_admission_entrypoint: &'static str,
    rpc_http_transport_measured: bool,
    rpc_http_smoke_ok: bool,
    http_smoke_ms: u64,
    sync_stats: SyncStatsSnapshot,
    p2p: P2PDiagnostics,
    p2p_sender: P2PDiagnostics,
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
    submission_workers: usize,
    validation_mode: &'static str,
    processing_path: &'static str,
    min_fee_at_process: u64,
    transactions_submitted: u64,
    transactions_admitted: u64,
    rpc_refusals: u64,
    transactions_received: u64,
    duplicate_ingress: u64,
    receiver_admission_events: u64,
    transactions_receiver_admitted: u64,
    transactions_applied: u64,
    transactions_persisted: u64,
    transactions_rejected: u64,
    duplicate_applies: u64,
    persistence_failures: u64,
    transaction_effect_mismatches: u64,
    unresolved_dependency_transactions: u64,
    latency_samples: usize,
    admission_samples: usize,
    relay_samples: usize,
    receiver_admission_samples: usize,
    queue_wait_samples: usize,
    apply_samples: usize,
    end_to_end_samples: usize,
    submission_start_us: u64,
    submission_end_us: u64,
    first_admission_us: u64,
    last_admission_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_drain_start_us: u64,
    last_drain_start_us: u64,
    first_applied_us: u64,
    last_applied_us: u64,
    first_persisted_us: u64,
    last_persisted_us: u64,
    persistence_confirmation_us: u64,
    offered_rate: RateMetric,
    admission_rate: RateMetric,
    reception_rate: RateMetric,
    ledger_application_rate: RateMetric,
    completion_rate: RateMetric,
    admission_latency_p50_us: Option<u64>,
    admission_latency_p95_us: Option<u64>,
    admission_latency_p99_us: Option<u64>,
    relay_latency_p50_us: Option<u64>,
    relay_latency_p95_us: Option<u64>,
    relay_latency_p99_us: Option<u64>,
    receiver_admission_latency_p50_us: Option<u64>,
    receiver_admission_latency_p95_us: Option<u64>,
    receiver_admission_latency_p99_us: Option<u64>,
    queue_wait_latency_p50_us: Option<u64>,
    queue_wait_latency_p95_us: Option<u64>,
    queue_wait_latency_p99_us: Option<u64>,
    apply_latency_p50_us: Option<u64>,
    apply_latency_p95_us: Option<u64>,
    apply_latency_p99_us: Option<u64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    backlog_peak: u64,
    receiver_queue_peak: u64,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    dag_missing_count: usize,
    parent_missing_count: usize,
    storage_weight_mismatches: u64,
    ledger_initial_supply: u64,
    ledger_final_supply: u64,
    ledger_expected_final_supply: u64,
    fees_burned: u64,
    expected_fees_burned: u64,
    sender_nonce_mismatches: u64,
    sender_balance_mismatches: u64,
    receiver_balance_mismatches: u64,
    fee_burn_mismatches: u64,
    supply_mismatches: u64,
    storage_balance_mismatches: u64,
    storage_nonce_mismatches: u64,
    storage_applied_mismatches: u64,
    storage_row_mismatches: u64,
    persistent_reload_verified: bool,
    persistent_balance_mismatches: u64,
    persistent_nonce_mismatches: u64,
    persistent_applied_mismatches: u64,
    persistent_supply_mismatches: u64,
    persistent_fee_mismatches: u64,
    persistent_transaction_count_mismatches: u64,
    rss_before_load_kb: Option<u64>,
    rss_after_submissions_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_drain_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
    rss_scope: &'static str,
    window_basis: &'static str,
    timing_scope: &'static str,
    throughput_note: &'static str,
    persistence_note: &'static str,
}

async fn run_round_async(
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    sent: &[Transaction],
    dir_a: &Path,
    dir_b: &Path,
    port_a: u16,
    recorder: Arc<PipelineRecorder>,
) -> RoundRaw {
    let port_b = port_a + 2;
    let rpc_a = port_a + 1;
    let rpc_b = port_b + 1;
    set_test_propagation_jitter(
        Duration::from_millis(profile.min_ms),
        Duration::from_millis(profile.max_ms),
        seed,
    );
    pipeline_trace::install(recorder.clone());

    let node_a = boot_node_c0(dir_a, port_a, rpc_a, Vec::new(), "tx").await;
    let node_b = boot_node_c0(
        dir_b,
        port_b,
        rpc_b,
        vec![format!("127.0.0.1:{}", port_a)],
        "rx",
    )
    .await;

    wait_for("C0 peering", Duration::from_secs(30), || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let senders = sender_expectations(sent);
    fund(&node_a, &senders).await;
    fund(&node_b, &senders).await;
    let ledger_initial_supply = node_b.ledger.read().await.total_supply();

    let http_smoke_ms = http_smoke(rpc_a).await;
    let rss_before_load_kb = get_rss_kb();

    let expected = sent.len();
    let hexes: Arc<Vec<(TransactionId, String)>> = Arc::new(
        sent.iter()
            .map(|tx| {
                (
                    tx.id,
                    hex::encode(bincode::serialize(tx).expect("serialize tx")),
                )
            })
            .collect(),
    );
    let marks: Arc<StdMutex<HashMap<TransactionId, SubmitMark>>> =
        Arc::new(StdMutex::new(HashMap::with_capacity(expected)));
    let admitted = Arc::new(AtomicU64::new(0));
    let refusals = Arc::new(AtomicU64::new(0));
    let next = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();

    let mut workers = Vec::with_capacity(SUBMISSION_WORKERS);
    for _ in 0..SUBMISSION_WORKERS {
        let rpc = node_a.rpc.clone();
        let hexes = hexes.clone();
        let marks = marks.clone();
        let admitted = admitted.clone();
        let refusals = refusals.clone();
        let next = next.clone();
        workers.push(tokio::spawn(async move {
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= hexes.len() {
                    break;
                }
                let due = start + Duration::from_micros(index as u64 * submission_interval_us);
                tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
                let (tx_id, encoded) = &hexes[index];
                let submit = Instant::now();
                marks.lock().unwrap_or_else(|error| error.into_inner()).insert(
                    *tx_id,
                    SubmitMark {
                        submit,
                        admitted: None,
                    },
                );
                match rpc
                    .send_transaction(serde_json::json!([encoded.clone()]))
                    .await
                {
                    Ok(_) => {
                        let admitted_at = Instant::now();
                        if let Some(mark) = marks
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .get_mut(tx_id)
                        {
                            mark.admitted = Some(admitted_at);
                        }
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        eprintln!("C0 RPC refusal tx {}: {}", hex::encode(tx_id), error);
                        refusals.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for worker in workers {
        worker.await.expect("submission worker");
    }
    let submission_end = Instant::now();
    let rss_after_submissions_kb = get_rss_kb();

    let expected_ids: HashSet<TransactionId> = sent.iter().map(|tx| tx.id).collect();
    let mut receiver_queue_peak = node_b.mempool.read().await.size() as u64;
    let mut backlog_peak = admitted.load(Ordering::Relaxed);
    let wait_start = Instant::now();
    let mut final_traces = HashMap::new();
    let mut last_progress_log: Option<Instant> = None;
    while wait_start.elapsed() < RECOVERY_TIMEOUT {
        let traces = trace_by_id(&recorder.snapshot(), "rx");
        let applied_count = expected_ids
            .iter()
            .filter(|id| traces.get(*id).and_then(|trace| trace.applied).is_some())
            .count();
        let queue_size = node_b.mempool.read().await.size() as u64;
        receiver_queue_peak = receiver_queue_peak.max(queue_size);
        let submitted_now = marks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len() as u64;
        backlog_peak = backlog_peak.max(submitted_now.saturating_sub(applied_count as u64));
        final_traces = traces;
        if last_progress_log.map_or(true, |t: Instant| t.elapsed() >= Duration::from_secs(10)) {
            last_progress_log = Some(Instant::now());
            let a_dag = node_a.dag.read().await.transactions().len();
            let a_mp = node_a.mempool.read().await.size() as usize;
            let b_dag = node_b.dag.read().await.transactions().len();
            let b_mp = node_b.mempool.read().await.size() as usize;
            eprintln!(
                "C0_PROGRESS t={:?} applied={} a_dag={} a_mp={} b_dag={} b_mp={}",
                wait_start.elapsed(),
                applied_count,
                a_dag,
                a_mp,
                b_dag,
                b_mp
            );
        }
        if applied_count == expected && queue_size == 0 {
            break;
        }
        tokio::time::sleep(SAMPLE_INTERVAL).await;
    }
    let rss_under_load_peak_kb = get_peak_rss_kb();

    node_b.storage.read().await.flush().expect("flush receiver");
    let persistence_confirmation = Instant::now();
    let traces = if final_traces.is_empty() {
        trace_by_id(&recorder.snapshot(), "rx")
    } else {
        final_traces
    };

    let marks = marks
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let dag_guard = node_b.dag.read().await;
    let dag_transactions: HashSet<TransactionId> =
        dag_guard.transactions().keys().copied().collect();
    drop(dag_guard);
    {
        let a_dag = node_a.dag.read().await.transactions().len();
        let a_mempool = node_a.mempool.read().await.size() as usize;
        eprintln!("C0_ANODE dag={} mempool={}", a_dag, a_mempool);
    }
    let ledger_guard = node_b.ledger.read().await;
    let sync_stats = node_b.sync_ctx.stats.snapshot();
    let p2p = P2PDiagnostics {
        ingress_drops: node_b.p2p.ingress_drops(),
        session_drops: node_b.p2p.session_drops(),
        outbound_budget_drops: node_b.p2p.outbound_budget_drops(),
        ingress_reserved_bytes: node_b.p2p.ingress_reserved_bytes(),
        propagation_inflight: node_b.p2p.propagation_inflight(),
    };
    let p2p_sender = P2PDiagnostics {
        ingress_drops: node_a.p2p.ingress_drops(),
        session_drops: node_a.p2p.session_drops(),
        outbound_budget_drops: node_a.p2p.outbound_budget_drops(),
        ingress_reserved_bytes: node_a.p2p.ingress_reserved_bytes(),
        propagation_inflight: node_a.p2p.propagation_inflight(),
    };
    let storage_guard = node_b.storage.read().await;
    let audit = audit_ledger(
        &ledger_guard,
        &storage_guard,
        &dag_transactions,
        sent,
        ledger_initial_supply,
    );
    drop(storage_guard);
    drop(ledger_guard);

    let mut admission_us = Vec::with_capacity(expected);
    let mut relay_us = Vec::with_capacity(expected);
    let mut receiver_admission_us = Vec::with_capacity(expected);
    let mut queue_wait_us = Vec::with_capacity(expected);
    let mut apply_us = Vec::with_capacity(expected);
    let mut end_to_end_us = Vec::with_capacity(expected);
    let mut first_submission = None;
    let mut last_submission = None;
    let mut first_admission = None;
    let mut last_admission = None;
    let mut first_receipt = None;
    let mut last_receipt = None;
    let mut first_drain = None;
    let mut last_drain = None;
    let mut first_applied = None;
    let mut last_applied = None;
    let mut received_ids = HashSet::new();
    let mut duplicate_ingress = 0u64;
    let mut receiver_admission_events = 0u64;
    let mut receiver_admitted_ids = HashSet::new();
    let mut applied_ids = HashSet::new();
    let mut duplicate_apply = 0u64;

    for tx in sent {
        let Some(mark) = marks.get(&tx.id) else {
            continue;
        };
        let submit = mark.submit;
        first_submission = Some(first_submission.map_or(submit, |value: Instant| value.min(submit)));
        last_submission = Some(last_submission.map_or(submit, |value: Instant| value.max(submit)));
        if let Some(admitted_at) = mark.admitted {
            admission_us.push(admitted_at.duration_since(submit).as_micros() as u64);
            first_admission =
                Some(first_admission.map_or(admitted_at, |value: Instant| value.min(admitted_at)));
            last_admission =
                Some(last_admission.map_or(admitted_at, |value: Instant| value.max(admitted_at)));
            if let Some(trace) = traces.get(&tx.id) {
                if let Some(ingress) = trace.ingress {
                    relay_us.push(ingress.duration_since(admitted_at).as_micros() as u64);
                }
            }
        }
        if let Some(trace) = traces.get(&tx.id) {
            if trace.ingress_events > 0 {
                received_ids.insert(tx.id);
                duplicate_ingress += trace.ingress_events.saturating_sub(1);
            }
            receiver_admission_events += trace.accepted_events;
            if let Some(accepted) = trace.accepted {
                receiver_admitted_ids.insert(tx.id);
            }
            if let Some(accepted) = trace.accepted {
                if let Some(ingress) = trace.ingress {
                    receiver_admission_us
                        .push(accepted.duration_since(ingress).as_micros() as u64);
                }
                if let Some(drain) = trace.drain_start {
                    queue_wait_us.push(drain.duration_since(accepted).as_micros() as u64);
                }
            }
            if let Some(drain) = trace.drain_start {
                first_drain =
                    Some(first_drain.map_or(drain, |value: Instant| value.min(drain)));
                last_drain = Some(last_drain.map_or(drain, |value: Instant| value.max(drain)));
            }
            if let Some(applied) = trace.applied {
                if !applied_ids.insert(tx.id) {
                    duplicate_apply += 1;
                }
                if let Some(drain) = trace.drain_start {
                    apply_us.push(applied.duration_since(drain).as_micros() as u64);
                }
                end_to_end_us.push(applied.duration_since(submit).as_micros() as u64);
                first_applied =
                    Some(first_applied.map_or(applied, |value: Instant| value.min(applied)));
                last_applied =
                    Some(last_applied.map_or(applied, |value: Instant| value.max(applied)));
                if let Some(ingress) = trace.ingress {
                    first_receipt =
                        Some(first_receipt.map_or(ingress, |value: Instant| value.min(ingress)));
                    last_receipt =
                        Some(last_receipt.map_or(ingress, |value: Instant| value.max(ingress)));
                }
            }
        }
    }

    let applied = applied_ids.len() as u64;
    let persisted = audit.persisted;
    let unresolved = expected as u64 - applied;
    let first_submission = first_submission.unwrap_or(start);
    let last_submission = last_submission.unwrap_or(first_submission);
    let first_admission = first_admission.unwrap_or(first_submission);
    let last_admission = last_admission.unwrap_or(first_admission);
    let first_receipt = first_receipt.unwrap_or(first_submission);
    let last_receipt = last_receipt.unwrap_or(first_receipt);
    let first_drain = first_drain.unwrap_or(first_submission);
    let last_drain = last_drain.unwrap_or(first_drain);
    let first_applied = first_applied.unwrap_or(first_submission);
    let last_applied = last_applied.unwrap_or(first_applied);
    let first_persisted = first_applied;
    let last_persisted = last_applied;

    let rss_after_drain_kb = get_rss_kb();
    let rss_process_peak_kb = get_peak_rss_kb();
    let to_us = |at: Instant| at.duration_since(start).as_micros() as u64;
    RoundRaw {
        submitted: marks.len() as u64,
        admitted: admitted.load(Ordering::Relaxed),
        rpc_refusals: refusals.load(Ordering::Relaxed),
        received: received_ids.len() as u64,
        duplicate_ingress,
        receiver_admission_events,
        receiver_admitted: receiver_admitted_ids.len() as u64,
        applied,
        persisted,
        duplicate_apply,
        unresolved,
        first_submission_us: to_us(first_submission),
        last_submission_us: to_us(last_submission),
        first_admission_us: to_us(first_admission),
        last_admission_us: to_us(last_admission),
        first_receipt_us: to_us(first_receipt),
        last_receipt_us: to_us(last_receipt),
        first_drain_us: to_us(first_drain),
        last_drain_us: to_us(last_drain),
        first_applied_us: to_us(first_applied),
        last_applied_us: to_us(last_applied),
        first_persisted_us: to_us(first_persisted),
        last_persisted_us: to_us(last_persisted),
        persistence_confirmation_us: to_us(persistence_confirmation),
        admission_us,
        relay_us,
        receiver_admission_us,
        queue_wait_us,
        apply_us,
        end_to_end_us,
        backlog_peak,
        receiver_queue_peak,
        http_smoke_ms,
        sync_stats,
        p2p,
        p2p_sender,
        ledger_initial_supply,
        audit,
        persistent: PersistentAudit {
            reload_ok: false,
            balance_mismatches: 0,
            nonce_mismatches: 0,
            applied_mismatches: 0,
            supply_mismatches: 0,
            fee_mismatches: 0,
            transaction_count_mismatches: 0,
        },
        rss_before_load_kb,
        rss_after_submissions_kb,
        rss_under_load_peak_kb,
        rss_after_drain_kb,
        rss_process_peak_kb,
    }
}

fn build_record(
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    repetition: usize,
    topology_repetition: usize,
    round: RoundRaw,
    persistence_confirmation_us: u64,
) -> RepetitionRecord {
    let (a50, a95, a99) = stats_us(&round.admission_us);
    let (r50, r95, r99) = stats_us(&round.relay_us);
    let (ra50, ra95, ra99) = stats_us(&round.receiver_admission_us);
    let (q50, q95, q99) = stats_us(&round.queue_wait_us);
    let (p50, p95, p99) = stats_us(&round.apply_us);
    let (e50, e95, e99) = stats_us(&round.end_to_end_us);

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
        runtime_path: "run_node_two_instance_loopback_same_process",
        rpc_admission_entrypoint: "AetherRpcImpl::send_transaction",
        rpc_http_transport_measured: false,
        rpc_http_smoke_ok: round.http_smoke_ms < 15_000,
        http_smoke_ms: round.http_smoke_ms,
        sync_stats: round.sync_stats,
        p2p: round.p2p,
        p2p_sender: round.p2p_sender,
        topology: topology.id(),
        topology_layout: topology.layout(),
        lanes: topology.lanes(),
        transactions_per_lane: topology.transactions_per_lane(),
        transaction_set: TRANSACTION_SET,
        transaction_set_id: topology.transaction_set_id(),
        generation_scope: GENERATION_SCOPE,
        generation_span_ms,
        generation_included_in_rates: false,
        profile_id: profile.id,
        jitter_min_ms: profile.min_ms,
        jitter_max_ms: profile.max_ms,
        jitter_seed: seed,
        target_offered_tps: target_tps,
        target_submission_interval_us: submission_interval_us,
        repetition,
        topology_repetition,
        repetitions_total: REPETITIONS_PER_CELL,
        transactions_per_repetition: TXS_PER_REPETITION,
        pow_difficulty: POW_DIFFICULTY,
        submission_order: SUBMISSION_ORDER,
        submission_workers: SUBMISSION_WORKERS,
        validation_mode: VALIDATION_MODE,
        processing_path: "run_node_receiver_ingress_mempool_drainer_transaction_processor",
        min_fee_at_process: 0,
        transactions_submitted: round.submitted,
        transactions_admitted: round.admitted,
        rpc_refusals: round.rpc_refusals,
        transactions_received: round.received,
        duplicate_ingress: round.duplicate_ingress,
        receiver_admission_events: round.receiver_admission_events,
        transactions_receiver_admitted: round.receiver_admitted,
        transactions_applied: round.applied,
        transactions_persisted: round.persisted,
        transactions_rejected: round.rpc_refusals,
        duplicate_applies: round.duplicate_apply,
        persistence_failures: round.audit.storage_row_mismatches
            + round.audit.storage_applied_mismatches,
        transaction_effect_mismatches: round.audit.sender_nonce_mismatches
            + round.audit.sender_balance_mismatches
            + round.audit.receiver_balance_mismatches
            + round.audit.fee_burn_mismatches
            + round.audit.supply_mismatches
            + round.audit.storage_balance_mismatches
            + round.audit.storage_nonce_mismatches
            + round.audit.storage_applied_mismatches,
        unresolved_dependency_transactions: round.unresolved,
        latency_samples: round.end_to_end_us.len(),
        admission_samples: round.admission_us.len(),
        relay_samples: round.relay_us.len(),
        receiver_admission_samples: round.receiver_admission_us.len(),
        queue_wait_samples: round.queue_wait_us.len(),
        apply_samples: round.apply_us.len(),
        end_to_end_samples: round.end_to_end_us.len(),
        submission_start_us: round.first_submission_us,
        submission_end_us: round.last_submission_us,
        first_admission_us: round.first_admission_us,
        last_admission_us: round.last_admission_us,
        first_receipt_us: round.first_receipt_us,
        last_receipt_us: round.last_receipt_us,
        first_drain_start_us: round.first_drain_us,
        last_drain_start_us: round.last_drain_us,
        first_applied_us: round.first_applied_us,
        last_applied_us: round.last_applied_us,
        first_persisted_us: round.first_persisted_us,
        last_persisted_us: round.last_persisted_us,
        persistence_confirmation_us,
        offered_rate: make_rate_metric(
            round.submitted,
            round.first_submission_us,
            round.last_submission_us,
            FORMULA_OFFERED,
        ),
        admission_rate: make_rate_metric(
            round.admitted,
            round.first_admission_us,
            round.last_admission_us,
            FORMULA_ADMITTED,
        ),
        reception_rate: make_rate_metric(
            round.received,
            round.first_receipt_us,
            round.last_receipt_us,
            FORMULA_RECEIVED,
        ),
        ledger_application_rate: make_rate_metric(
            round.applied,
            round.first_applied_us,
            round.last_applied_us,
            FORMULA_APPLIED,
        ),
        completion_rate: make_rate_metric(
            round.persisted,
            round.first_submission_us,
            round.last_persisted_us,
            FORMULA_COMPLETION,
        ),
        admission_latency_p50_us: a50,
        admission_latency_p95_us: a95,
        admission_latency_p99_us: a99,
        relay_latency_p50_us: r50,
        relay_latency_p95_us: r95,
        relay_latency_p99_us: r99,
        receiver_admission_latency_p50_us: ra50,
        receiver_admission_latency_p95_us: ra95,
        receiver_admission_latency_p99_us: ra99,
        queue_wait_latency_p50_us: q50,
        queue_wait_latency_p95_us: q95,
        queue_wait_latency_p99_us: q99,
        apply_latency_p50_us: p50,
        apply_latency_p95_us: p95,
        apply_latency_p99_us: p99,
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        backlog_peak: round.backlog_peak,
        receiver_queue_peak: round.receiver_queue_peak,
        dag_transaction_count: round.audit.dag_transaction_count,
        storage_transaction_count: round.audit.storage_transaction_count,
        applied_mark_count: round.audit.applied_mark_count,
        dag_missing_count: round.audit.dag_missing_count,
        parent_missing_count: round.audit.parent_missing_count,
        storage_weight_mismatches: round.audit.storage_weight_mismatches,
        ledger_initial_supply: round.audit.initial_supply,
        ledger_final_supply: round.audit.final_supply,
        ledger_expected_final_supply: round.audit.expected_final_supply,
        fees_burned: round.audit.fees_burned,
        expected_fees_burned: round.audit.expected_fees_burned,
        sender_nonce_mismatches: round.audit.sender_nonce_mismatches,
        sender_balance_mismatches: round.audit.sender_balance_mismatches,
        receiver_balance_mismatches: round.audit.receiver_balance_mismatches,
        fee_burn_mismatches: round.audit.fee_burn_mismatches,
        supply_mismatches: round.audit.supply_mismatches,
        storage_balance_mismatches: round.audit.storage_balance_mismatches,
        storage_nonce_mismatches: round.audit.storage_nonce_mismatches,
        storage_applied_mismatches: round.audit.storage_applied_mismatches,
        storage_row_mismatches: round.audit.storage_row_mismatches,
        persistent_reload_verified: round.persistent.reload_ok,
        persistent_balance_mismatches: round.persistent.balance_mismatches,
        persistent_nonce_mismatches: round.persistent.nonce_mismatches,
        persistent_applied_mismatches: round.persistent.applied_mismatches,
        persistent_supply_mismatches: round.persistent.supply_mismatches,
        persistent_fee_mismatches: round.persistent.fee_mismatches,
        persistent_transaction_count_mismatches: round.persistent.transaction_count_mismatches,
        rss_before_load_kb: round.rss_before_load_kb,
        rss_after_submissions_kb: round.rss_after_submissions_kb,
        rss_under_load_peak_kb: round.rss_under_load_peak_kb,
        rss_after_drain_kb: round.rss_after_drain_kb,
        rss_process_peak_kb: round.rss_process_peak_kb,
        rss_scope: "process_wide_two_nodes_same_process",
        window_basis: "per_repetition_from_first_submission",
        timing_scope: TIMING_SCOPE,
        throughput_note: THROUGHPUT_NOTE,
        persistence_note: PERSISTENCE_NOTE,
    }
}

fn log_jsonl<T: Serialize>(record: &T) {
    println!(
        "BENCH_JSONL:{}",
        serde_json::to_string(record).expect("serialize record")
    );
}

fn c0_only_filter() -> Option<Vec<(String, String, u64)>> {
    let raw = std::env::var("C0_ONLY").ok()?;
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

fn c0_selected(
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

fn run_round(
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    sent: &[Transaction],
    repetition: usize,
    topology_repetition: usize,
) -> RepetitionRecord {
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let node_a_dir = dir_a.path().join("node");
    let node_b_dir = dir_b.path().join("node");
    let recorder = Arc::new(PipelineRecorder::default());
    let port = PORT_BASE + ((repetition - 1) as u16) * 4;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    let mut round = runtime.block_on(run_round_async(
        topology,
        profile,
        seed,
        target_tps,
        submission_interval_us,
        generation_span_ms,
        sent,
        &node_a_dir,
        &node_b_dir,
        port,
        recorder,
    ));
    let persistence_confirmation_us = round.persistence_confirmation_us;
    runtime.shutdown_timeout(Duration::from_secs(2));
    pipeline_trace::clear();

    let reopen_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("reopen runtime");
    round.persistent = reopen_runtime.block_on(audit_persistent(
        &node_b_dir.join("sled_db"),
        sent,
        round.ledger_initial_supply,
    ));
    reopen_runtime.shutdown_timeout(Duration::from_secs(1));
    dir_b.close().expect("close dirB");
    dir_a.close().expect("close dirA");

    build_record(
        topology,
        profile,
        seed,
        target_tps,
        submission_interval_us,
        generation_span_ms,
        repetition,
        topology_repetition,
        round,
        persistence_confirmation_us,
    )
}

#[test]
fn c0_full_pipeline() {
    let _reset = JitterReset;
    let only = c0_only_filter();
    let ts0: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
        - 300_000;

    eprintln!("[c0] generating chain fixture");
    let chain_generation_start = Instant::now();
    let chain_set = build_transaction_set(Topology::Chain, ts0);
    let chain_generation_ms = chain_generation_start.elapsed().as_millis() as u64;

    eprintln!("[c0] generating multi-lane fixture");
    let multi_generation_start = Instant::now();
    let multi_set = build_transaction_set(Topology::MultiLane, ts0);
    let multi_generation_ms = multi_generation_start.elapsed().as_millis() as u64;

    assert_eq!(chain_set.len(), TXS_PER_REPETITION);
    assert_eq!(
        multi_set.len(),
        MULTI_LANE_COUNT * MULTI_LANE_TX_COUNT
    );
    println!(
        "C0_GEN chain_txs={} chain_span_ms={} multi_lane_txs={} multi_span_ms={}",
        chain_set.len(),
        chain_generation_ms,
        multi_set.len(),
        multi_generation_ms
    );

    let mut executed = 0usize;
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
                if !c0_selected(only.as_ref(), topology, profile, target_tps) {
                    continue;
                }
                let submission_interval_us = 1_000_000 / target_tps;
                for topology_repetition in 1..=REPETITIONS_PER_CELL {
                    global_repetition += 1;
                    let seed = 0xC0_0000
                        + (profile_index as u64) * 1_000
                        + (rate_index as u64) * 100
                        + topology_repetition as u64;
                    eprintln!(
                        "[c0] start topology={} profile={} target={} rep={}",
                        topology.id(),
                        profile.id,
                        target_tps,
                        topology_repetition
                    );
                    let record = run_round(
                        topology,
                        profile,
                        seed,
                        target_tps,
                        submission_interval_us,
                        generation_span_ms,
                        sent,
                        global_repetition,
                        topology_repetition,
                    );

                    log_jsonl(&record);
                    println!(
                        "C0_REP topology={} profile={} target={} rep={} submitted={} admitted={} received={} applied={} persisted={} completion_tps={:.1} admission_p50_us={} relay_p50_us={} queue_p50_us={} apply_p50_us={} e2e_p50_us={} e2e_p99_us={} backlog_peak={} queue_peak={} http_smoke_ms={}",
                        topology.id(),
                        profile.id,
                        target_tps,
                        topology_repetition,
                        record.transactions_submitted,
                        record.transactions_admitted,
                        record.transactions_received,
                        record.transactions_applied,
                        record.transactions_persisted,
                        record.completion_rate.value.unwrap_or(0.0),
                        record.admission_latency_p50_us.unwrap_or(0),
                        record.relay_latency_p50_us.unwrap_or(0),
                        record.queue_wait_latency_p50_us.unwrap_or(0),
                        record.apply_latency_p50_us.unwrap_or(0),
                        record.end_to_end_latency_p50_us.unwrap_or(0),
                        record.end_to_end_latency_p99_us.unwrap_or(0),
                        record.backlog_peak,
                        record.receiver_queue_peak,
                        record.http_smoke_ms,
                    );
                    eprintln!(
                        "C0_SYNC topology={} profile={} target={} rep={} requested={} received={} progress={} batches={} orphans={} resolved={} parent_req={} parent_known={} inv_adv={} inv_skip_orphan={} inv_missing={} response_items={} dup_ignored={} rx_ingress_drops={} rx_session_drops={} rx_budget_drops={} tx_ingress_drops={} tx_session_drops={} tx_budget_drops={}",
                        record.topology,
                        record.profile_id,
                        record.target_offered_tps,
                        record.topology_repetition,
                        record.sync_stats.sync_requested,
                        record.sync_stats.sync_received,
                        record.sync_stats.sync_progress,
                        record.sync_stats.sync_batches,
                        record.sync_stats.orphan_created,
                        record.sync_stats.orphan_resolved,
                        record.sync_stats.parent_requested,
                        record.sync_stats.parent_already_known,
                        record.sync_stats.inventory_advertised,
                        record.sync_stats.inventory_skipped_orphan,
                        record.sync_stats.inventory_missing,
                        record.sync_stats.sync_response_items,
                        record.sync_stats.duplicate_ignored,
                        record.p2p.ingress_drops,
                        record.p2p.session_drops,
                        record.p2p.outbound_budget_drops,
                        record.p2p_sender.ingress_drops,
                        record.p2p_sender.session_drops,
                        record.p2p_sender.outbound_budget_drops,
                    );

                    assert_eq!(
                        record.transactions_submitted, TXS_PER_REPETITION as u64,
                        "submitted count"
                    );
                    assert_eq!(
                        record.transactions_admitted, TXS_PER_REPETITION as u64,
                        "admitted count"
                    );
                    assert_eq!(record.rpc_refusals, 0, "RPC refusals");
                    assert_eq!(
                        record.transactions_received, TXS_PER_REPETITION as u64,
                        "receiver ingress count"
                    );
                    assert_eq!(
                        record.transactions_applied, TXS_PER_REPETITION as u64,
                        "applied count"
                    );
                    assert_eq!(
                        record.transactions_persisted, TXS_PER_REPETITION as u64,
                        "persisted count"
                    );
                    assert_eq!(record.unresolved_dependency_transactions, 0);
                    assert_eq!(record.dag_missing_count, 0);
                    assert_eq!(record.transaction_effect_mismatches, 0);
                    assert_eq!(record.persistence_failures, 0);
                    assert!(record.persistent_reload_verified);
                    assert!(record.rpc_http_smoke_ok);
                    assert!(record.end_to_end_samples > 0);
                    assert!(record.admission_samples > 0);
                    assert!(record.relay_samples > 0);
                    assert!(record.apply_samples > 0);
                    executed += 1;
                }
            }
        }
    }

    if only.is_none() {
        assert_eq!(
            executed,
            TOPOLOGIES.len() * PROFILES.len() * TARGET_RATES.len() * REPETITIONS_PER_CELL
        );
    }
    println!(
        "C0_DONE repetitions={} transactions={}",
        executed,
        executed * TXS_PER_REPETITION
    );
}
