#![cfg(feature = "test-jitter-control")]

use aether_unified::ledger::Ledger;
use aether_unified::p2p::{
    clear_test_propagation_jitter, set_test_propagation_jitter, IngressTx, P2PConfig, P2PNetwork,
    P2PProtocolMode,
};
use aether_unified::parent_selection::DAG;
use aether_unified::rpc::Mempool;
use aether_unified::storage::Storage;
use aether_unified::transaction::{Address, Transaction, TransactionId, DEFAULT_NETWORK_ID};
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

const SCENARIO_REPETITION: &str = "by01_ledger_apply";
const SCENARIO_CELL_AGGREGATE: &str = "by01_ledger_apply_cell_aggregate";
const SCENARIO_OVERALL_AGGREGATE: &str = "by01_ledger_apply_aggregate";
const SCHEMA_VERSION: u32 = 8;
const POW_DIFFICULTY: u8 = 20;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 300;
const MULTI_LANE_COUNT: usize = 10;
const MULTI_LANE_TX_COUNT: usize = 30;
const REPETITIONS_PER_CELL: usize = 3;
const PORT_BASE: u16 = 26000;
const BY_INGRESS_CAPACITY_MSGS: usize = 512;
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(180);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);
const INITIAL_SENDER_BALANCE: u64 = 1_000_000;
const MIN_FEE_AT_PROCESS: u64 = 0;
const SUBMISSION_ORDER: &str = "pre_generated_vector_index_order";
const TRANSACTION_SET: &str = "one_shared_pre_generated_valid_set_per_topology";
const GENERATION_SCOPE: &str = "one_time_shared_pow_per_topology_before_all_repetitions";
const VALIDATION_MODE: &str = "historical_pre_activation_fixture";
const TIMING_SCOPE: &str =
    "submission_to_receipt_receipt_to_ready_process_call_and_submission_to_persisted_confirmation";
const THROUGHPUT_NOTE: &str = "Timed path invokes TransactionProcessor::process for every transaction and requires successful ledger transfer, nonce commit, DAG insertion, transaction-row persistence and applied-mark persistence before an apply is counted. PoW generation is excluded. The test consumer resolves parents and per-sender account nonces before processing; it does not run RPC admission, mempool fee selection, orphan re-request, or node background flush. The no-jitter profile is a laboratory control, not a production recommendation.";

const RATE_UNIT: &str = "transactions_per_second";
const FORMULA_OFFERED: &str =
    "submitted / ((last_submission_us - first_submission_us) / 1_000_000)";
const FORMULA_RECEIVED: &str = "received / ((last_receipt_us - first_receipt_us) / 1_000_000)";
const FORMULA_APPLIED: &str = "applied / ((last_applied_us - first_applied_us) / 1_000_000)";
const FORMULA_PERSISTED: &str =
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
            Topology::Chain => "chain_1x300_v2_ledger",
            Topology::MultiLane => "multi_lane_10x30_v2_ledger",
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

fn wallet_by(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn make_valid_tx_by(
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
            let wallet = wallet_by(880_001);
            let mut previous = [0u8; 32];
            for index in 0..TXS_PER_REPETITION {
                let tx = make_valid_tx_by(
                    &wallet,
                    topology.receiver_for(0),
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
                .map(|lane| wallet_by(881_000 + lane as u64))
                .collect();
            let mut previous = [[0u8; 32]; MULTI_LANE_COUNT];
            for step in 0..MULTI_LANE_TX_COUNT {
                for (lane, wallet) in wallets.iter().enumerate() {
                    let tx = make_valid_tx_by(
                        wallet,
                        topology.receiver_for(lane),
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
    applied: bool,
    applied_at: Instant,
    process_us: u64,
    persisted: bool,
    persisted_at: Option<Instant>,
    effect_mismatches: u64,
    storage_error: Option<String>,
}

async fn record_tx_by(
    dag: &Arc<RwLock<DAG>>,
    ledger: &Arc<RwLock<Ledger>>,
    mempool: &Arc<RwLock<Mempool>>,
    processor: &TransactionProcessor,
    tx: &Transaction,
) -> Result<RecordOutcome, (bool, String)> {
    let before = {
        let guard = ledger.read().await;
        (
            guard.get_balance(&tx.sender),
            guard.get_balance(&tx.receiver),
            guard.fee_burn_balance(),
            guard.total_supply(),
            guard.total_fees_burned(),
        )
    };

    let process_start = Instant::now();
    processor
        .process(
            tx.clone(),
            dag,
            ledger,
            mempool,
            MIN_FEE_AT_PROCESS,
            ValidationMode::Historical,
        )
        .await
        .map_err(|e| {
            (
                matches!(
                    e,
                    aether_unified::transaction_processor::ProcessingError::PersistenceError(_)
                ),
                e.to_string(),
            )
        })?;
    let process_us = process_start.elapsed().as_micros() as u64;
    let applied_at = Instant::now();

    let mut effect_mismatches = 0u64;
    {
        let guard = ledger.read().await;
        if !guard.is_applied(&tx.id) {
            effect_mismatches += 1;
        }
        let expected_sender = before.0.saturating_sub(tx.amount.saturating_add(tx.fee));
        if guard.get_balance(&tx.sender) != expected_sender {
            effect_mismatches += 1;
        }
        if guard.get_balance(&tx.receiver) != before.1.saturating_add(tx.amount) {
            effect_mismatches += 1;
        }
        if guard.fee_burn_balance() != before.2.saturating_add(tx.fee) {
            effect_mismatches += 1;
        }
        if guard.total_fees_burned() != before.4.saturating_add(tx.fee) {
            effect_mismatches += 1;
        }
        if guard.total_supply() != before.3.saturating_sub(tx.fee) {
            effect_mismatches += 1;
        }
        if guard.get_nonce(&tx.sender) != tx.account_nonce {
            effect_mismatches += 1;
        }
    }
    {
        let guard = dag.read().await;
        if !guard.transactions().contains_key(&tx.id) {
            effect_mismatches += 1;
        }
        for parent in tx.parents.iter().filter(|p| **p != [0u8; 32]) {
            if !guard.transactions().contains_key(parent) {
                effect_mismatches += 1;
            }
        }
    }

    let (persisted, storage_error) = {
        let guard = ledger.read().await;
        match guard.storage() {
            Some(storage) => {
                let store = storage.read().await;
                let exists = store.transaction_exists(tx.id).unwrap_or(false);
                let marked = store.is_applied(tx.id).unwrap_or(false);
                let row_matches = store
                    .get_transaction(tx.id)
                    .map(|stored| stored == *tx)
                    .unwrap_or(false);
                if exists && marked && row_matches {
                    (true, None)
                } else {
                    (
                        false,
                        Some(format!(
                            "row_exists={} applied_mark={} row_matches={}",
                            exists, marked, row_matches
                        )),
                    )
                }
            }
            None => (false, Some("ledger has no storage".to_string())),
        }
    };

    Ok(RecordOutcome {
        applied: effect_mismatches == 0,
        applied_at,
        process_us,
        persisted,
        persisted_at: persisted.then(Instant::now),
        effect_mismatches,
        storage_error,
    })
}

struct TestNodeBy {
    _dir_guard: tempfile::TempDir,
    storage: Arc<RwLock<Storage>>,
    ledger: Arc<RwLock<Ledger>>,
    dag: Arc<RwLock<DAG>>,
    p2p: Arc<P2PNetwork>,
    rx: mpsc::Receiver<IngressTx>,
}

async fn boot_node_by(
    dir: tempfile::TempDir,
    port: u16,
    bootnodes: Vec<SocketAddr>,
    funding: &[(Address, u64)],
) -> TestNodeBy {
    let storage = Arc::new(RwLock::new(Storage::open(dir.path()).expect("open store")));
    let ledger = Arc::new(RwLock::new(
        Ledger::new_with_storage(storage.clone())
            .await
            .expect("load ledger"),
    ));
    if !funding.is_empty() {
        {
            let mut guard = ledger.write().await;
            for (address, balance) in funding {
                guard.set_balance(address, *balance);
            }
            guard.save().await.expect("persist initial balances");
        }
        storage.read().await.flush().expect("flush funding");
    }
    let dag = Arc::new(RwLock::new(DAG::new()));
    let (tx_sender, rx) = mpsc::channel::<IngressTx>(BY_INGRESS_CAPACITY_MSGS);
    let dag_c = dag.clone();
    let get_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(move || {
        __test_only_block_on_by(async {
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
        __test_only_block_on_by(async {
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
        __test_only_block_on_by(async {
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
    TestNodeBy {
        _dir_guard: dir,
        storage,
        ledger,
        dag,
        p2p,
        rx,
    }
}

fn __test_only_block_on_by<F, T>(fut: F) -> T
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

async fn wait_for_by<F, Fut>(what: &str, timeout: Duration, mut check: F)
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

struct ByRound {
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    submitted: u64,
    received: u64,
    applied: u64,
    persisted: u64,
    rejected: u64,
    duplicates: u64,
    persistence_failures: u64,
    effect_mismatches: u64,
    unresolved_dependencies: u64,
    first_submission_us: u64,
    last_submission_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_applied_us: u64,
    last_applied_us: u64,
    first_persisted_us: u64,
    last_persisted_us: u64,
    drain_us: u64,
    persisted_drain_us: u64,
    propagation_us: Vec<u64>,
    dependency_wait_us: Vec<u64>,
    ledger_apply_us: Vec<u64>,
    end_to_end_us: Vec<u64>,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    dependency_pending_peak: u64,
    series: Vec<(u64, u64, u64, u64, u64, u64, Option<u64>)>,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    parent_missing_count: usize,
    audit: LedgerAudit,
    persistent: PersistentAudit,
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
    applied: u64,
    persisted: u64,
    rejected: u64,
    duplicates: u64,
    persistence_failures: u64,
    effect_mismatches: u64,
    unresolved_dependencies: u64,
    propagation_us: Vec<u64>,
    dependency_wait_us: Vec<u64>,
    ledger_apply_us: Vec<u64>,
    end_to_end_us: Vec<u64>,
    first_receipt: Option<Instant>,
    last_receipt: Option<Instant>,
    first_applied: Option<Instant>,
    last_applied: Option<Instant>,
    first_persisted: Option<Instant>,
    last_persisted: Option<Instant>,
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

fn audit_ledger(ledger: &Ledger, storage: &Storage, sent: &[Transaction]) -> LedgerAudit {
    let senders = sender_expectations(sent);
    let receivers = receiver_expectations(sent);
    let initial_supply = senders.len() as u64 * INITIAL_SENDER_BALANCE;
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

    let applied_count = match storage.get_all_applied() {
        Ok(applied) => applied.len(),
        Err(_) => 0,
    };
    if applied_count != sent.len() {
        audit.storage_applied_mismatches += 1;
    }
    for tx in sent {
        if !ledger.is_applied(&tx.id) || storage.is_applied(tx.id).ok() != Some(true) {
            audit.storage_applied_mismatches += 1;
        }
        match storage.get_transaction(tx.id) {
            Ok(row) if row == *tx => {}
            _ => audit.storage_row_mismatches += 1,
        }
    }
    audit
}

async fn audit_persistent(dir: &std::path::Path, sent: &[Transaction]) -> PersistentAudit {
    let senders = sender_expectations(sent);
    let receivers = receiver_expectations(sent);
    let expected_fees_burned = sent.len() as u64 * TX_FEE;
    let expected_final_supply =
        senders.len() as u64 * INITIAL_SENDER_BALANCE - expected_fees_burned;

    let storage = Arc::new(RwLock::new(
        Storage::open(dir).expect("reopen persistent store"),
    ));
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

async fn run_round_by(
    topology: Topology,
    profile: JitterProfile,
    seed: u64,
    target_tps: u64,
    submission_interval_us: u64,
    generation_span_ms: u64,
    sent: Vec<Transaction>,
    port_a: u16,
) -> ByRound {
    set_test_propagation_jitter(
        Duration::from_millis(profile.min_ms),
        Duration::from_millis(profile.max_ms),
        seed,
    );

    let port_b = port_a + 1;
    let dir_a = tempfile::tempdir().expect("dirA");
    let dir_b = tempfile::tempdir().expect("dirB");
    let dir_b_path = dir_b.path().to_path_buf();
    let pa: SocketAddr = format!("127.0.0.1:{}", port_a).parse().unwrap();

    let senders = sender_expectations(&sent);
    let funding: Vec<(Address, u64)> = senders
        .keys()
        .map(|address| (*address, INITIAL_SENDER_BALANCE))
        .collect();
    let node_a = boot_node_by(dir_a, port_a, vec![], &[]).await;
    let node_b = boot_node_by(dir_b, port_b, vec![pa], &funding).await;

    wait_for_by("jitter peering", Duration::from_secs(20), || async {
        node_a.p2p.peer_count().await >= 1 && node_b.p2p.peer_count().await >= 1
    })
    .await;

    let rss_before_load = get_rss_kb();
    let TestNodeBy {
        _dir_guard: dir_b_guard,
        storage: storage_b,
        ledger: ledger_b,
        dag: dag_b,
        p2p: p2p_b,
        mut rx,
    } = node_b;
    let expected = sent.len();
    assert!(expected > 0, "jitter load requires transactions");

    let submitted_count = Arc::new(AtomicU64::new(0));
    let received_count = Arc::new(AtomicU64::new(0));
    let applied_count = Arc::new(AtomicU64::new(0));
    let persisted_count = Arc::new(AtomicU64::new(0));
    let dependency_pending = Arc::new(AtomicU64::new(0));
    let submitted_at: Arc<StdMutex<HashMap<[u8; 32], Instant>>> =
        Arc::new(StdMutex::new(HashMap::with_capacity(expected)));

    let load_start = Instant::now();
    let stop_sampler = Arc::new(AtomicBool::new(false));
    let sampler_peak_rss = Arc::new(AtomicU64::new(0));
    let series: Arc<StdMutex<Vec<(u64, u64, u64, u64, u64, u64, Option<u64>)>>> =
        Arc::new(StdMutex::new(Vec::new()));
    let sampler = {
        let stop = stop_sampler.clone();
        let peak = sampler_peak_rss.clone();
        let series = series.clone();
        let submitted = submitted_count.clone();
        let received = received_count.clone();
        let applied = applied_count.clone();
        let persisted = persisted_count.clone();
        let dependency_pending = dependency_pending.clone();
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
                    persisted.load(Ordering::Relaxed),
                    dependency_pending.load(Ordering::Relaxed),
                    rss,
                ));
                std::thread::sleep(SAMPLE_INTERVAL);
            }
        })
    };

    let submitted_at_consumer = submitted_at.clone();
    let received_atomic = received_count.clone();
    let applied_atomic = applied_count.clone();
    let persisted_atomic = persisted_count.clone();
    let dependency_pending_consumer = dependency_pending.clone();
    let dag_consumer = dag_b.clone();
    let ledger_consumer = ledger_b.clone();
    let consumer = tokio::spawn(async move {
        let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(expected);
        let mut pending: HashMap<Address, BTreeMap<u64, (Instant, Transaction)>> = HashMap::new();
        let mut next_nonce: HashMap<Address, u64> = HashMap::new();
        let mut applied_ids: HashSet<[u8; 32]> = HashSet::with_capacity(expected);
        let mut result = ConsumerResult {
            received: 0,
            applied: 0,
            persisted: 0,
            rejected: 0,
            duplicates: 0,
            persistence_failures: 0,
            effect_mismatches: 0,
            unresolved_dependencies: 0,
            propagation_us: Vec::with_capacity(expected),
            dependency_wait_us: Vec::with_capacity(expected),
            ledger_apply_us: Vec::with_capacity(expected),
            end_to_end_us: Vec::with_capacity(expected),
            first_receipt: None,
            last_receipt: None,
            first_applied: None,
            last_applied: None,
            first_persisted: None,
            last_persisted: None,
        };
        let processor = TransactionProcessor::new();
        let mempool = Arc::new(RwLock::new(Mempool::new(1024, 8)));

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
                let senders: Vec<Address> = pending.keys().copied().collect();
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
                        parent.iter().all(|byte| *byte == 0) || applied_ids.contains(parent)
                    });
                    if !parents_ready {
                        continue;
                    }
                    if let Some(by_nonce) = pending.get_mut(&sender) {
                        by_nonce.remove(&expected_nonce);
                        if by_nonce.is_empty() {
                            pending.remove(&sender);
                        }
                    }

                    let submitted = submitted_at_consumer
                        .lock()
                        .expect("submitted timestamps")
                        .get(&tx.id)
                        .copied();
                    let process_start = Instant::now();
                    result
                        .dependency_wait_us
                        .push(process_start.duration_since(ingress_at).as_micros() as u64);
                    let outcome =
                        record_tx_by(&dag_consumer, &ledger_consumer, &mempool, &processor, &tx)
                            .await;
                    match outcome {
                        Ok(outcome) => {
                            if !outcome.applied {
                                result.effect_mismatches += outcome.effect_mismatches.max(1);
                                fatal = true;
                            }
                            applied_ids.insert(tx.id);
                            result.applied += 1;
                            applied_atomic.fetch_add(1, Ordering::Relaxed);
                            if result.first_applied.is_none() {
                                result.first_applied = Some(outcome.applied_at);
                            }
                            result.last_applied = Some(outcome.applied_at);
                            result.ledger_apply_us.push(outcome.process_us);

                            if outcome.persisted {
                                result.persisted += 1;
                                persisted_atomic.fetch_add(1, Ordering::Relaxed);
                                let persisted_at =
                                    outcome.persisted_at.expect("persisted timestamp");
                                if result.first_persisted.is_none() {
                                    result.first_persisted = Some(persisted_at);
                                }
                                result.last_persisted = Some(persisted_at);
                                if let Some(submitted) = submitted {
                                    result
                                        .end_to_end_us
                                        .push(persisted_at.duration_since(submitted).as_micros()
                                            as u64);
                                }
                            } else {
                                result.persistence_failures += 1;
                                eprintln!(
                                    "ledger persistence failure tx {}: {}",
                                    hex::encode(tx.id),
                                    outcome.storage_error.unwrap_or_default()
                                );
                                fatal = true;
                            }

                            next_nonce.insert(sender, expected_nonce + 1);
                            progress = true;
                        }
                        Err((is_persistence_failure, error)) => {
                            result.rejected += 1;
                            if is_persistence_failure {
                                result.persistence_failures += 1;
                            }
                            eprintln!("ledger apply rejected tx {}: {}", hex::encode(tx.id), error);
                            fatal = true;
                        }
                    }
                    if result.applied as usize >= expected || fatal {
                        break;
                    }
                }
                let pending_now: u64 = pending.values().map(|by_nonce| by_nonce.len() as u64).sum();
                dependency_pending_consumer.store(pending_now, Ordering::Relaxed);
                if !progress || fatal || result.applied as usize >= expected {
                    break;
                }
            }
            if fatal || result.applied as usize >= expected {
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
        Ok(Err(join_error)) => panic!("ledger consumer task failed: {}", join_error),
        Err(_) => panic!(
            "TIMEOUT waiting for ledger backlog recovery: received={} applied={} persisted={} ingress_drops={} session_drops={} outbound_budget_drops={} profile={} target={}",
            received_count.load(Ordering::Relaxed),
            applied_count.load(Ordering::Relaxed),
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
    let first_applied = result.first_applied.expect("first apply");
    let last_applied = result.last_applied.expect("last apply");
    let first_persisted = result.first_persisted.expect("first persisted");
    let last_persisted = result.last_persisted.expect("last persisted");
    let final_at = last_persisted.duration_since(load_start).as_millis() as u64;
    let final_rss = get_rss_kb();
    let mut points = series.lock().expect("series lock").clone();
    points.push((
        final_at,
        submitted_count.load(Ordering::Relaxed),
        received_count.load(Ordering::Relaxed),
        applied_count.load(Ordering::Relaxed),
        persisted_count.load(Ordering::Relaxed),
        dependency_pending.load(Ordering::Relaxed),
        final_rss,
    ));
    points.sort_by_key(|point| point.0);

    let mut backlog_peak = 0u64;
    let mut backlog_peak_at_ms = None;
    let mut dependency_pending_peak = 0u64;
    for (at_ms, submitted, _, applied, _, dependency, _) in &points {
        let backlog = submitted.saturating_sub(*applied);
        if backlog > backlog_peak {
            backlog_peak = backlog;
            backlog_peak_at_ms = Some(*at_ms);
        }
        dependency_pending_peak = dependency_pending_peak.max(*dependency);
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
    let audit = {
        let ledger = ledger_b.read().await;
        let storage = storage_b.read().await;
        audit_ledger(&ledger, &storage, &sent)
    };
    storage_b.read().await.flush().expect("flush ledger store");
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
        result.applied as usize, expected,
        "applied {} of {} topology transactions",
        result.applied, expected
    );
    assert_eq!(
        result.persisted as usize, expected,
        "persisted {} of {} topology transactions",
        result.persisted, expected
    );
    assert_eq!(result.rejected, 0, "rejected topology transactions");
    assert_eq!(result.duplicates, 0, "duplicate topology transactions");
    assert_eq!(result.persistence_failures, 0, "persistence failures");
    assert_eq!(result.effect_mismatches, 0, "ledger effect mismatches");
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
        result.dependency_wait_us.len(),
        expected,
        "dependency wait samples"
    );
    assert_eq!(
        result.ledger_apply_us.len(),
        expected,
        "ledger apply samples"
    );
    assert_eq!(
        result.end_to_end_us.len(),
        expected,
        "end-to-end latency samples"
    );
    assert_eq!(dag_transaction_count, expected, "DAG transaction count");
    assert_eq!(
        storage_transaction_count, expected,
        "storage transaction count"
    );
    assert_eq!(applied_mark_count, expected, "applied mark count");
    assert_eq!(parent_missing_count, 0, "missing parent count");
    assert_eq!(audit.sender_nonce_mismatches, 0, "sender nonce mismatches");
    assert_eq!(
        audit.sender_balance_mismatches, 0,
        "sender balance mismatches"
    );
    assert_eq!(
        audit.receiver_balance_mismatches, 0,
        "receiver balance mismatches"
    );
    assert_eq!(audit.fee_burn_mismatches, 0, "fee burn mismatches");
    assert_eq!(audit.supply_mismatches, 0, "supply mismatches");
    assert_eq!(
        audit.storage_balance_mismatches, 0,
        "storage balance mismatches"
    );
    assert_eq!(
        audit.storage_nonce_mismatches, 0,
        "storage nonce mismatches"
    );
    assert_eq!(
        audit.storage_applied_mismatches, 0,
        "storage applied mismatches"
    );
    assert_eq!(audit.storage_row_mismatches, 0, "storage row mismatches");
    assert_eq!(p2p_b.ingress_drops(), 0, "ingress drops");
    let ingress_drops = p2p_b.ingress_drops();
    let session_drops = node_a.p2p.session_drops() + p2p_b.session_drops();
    let outbound_budget_drops = node_a.p2p.outbound_budget_drops() + p2p_b.outbound_budget_drops();
    assert_eq!(session_drops, 0, "session drops");
    assert_eq!(outbound_budget_drops, 0, "outbound budget drops");

    node_a.p2p.shutdown().await.expect("shutdown node A p2p");
    p2p_b.shutdown().await.expect("shutdown node B p2p");
    drop(node_a);
    drop(p2p_b);
    drop(dag_b);
    drop(ledger_b);
    drop(storage_b);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let persistent = audit_persistent(&dir_b_path, &sent).await;
    assert!(persistent.reload_ok, "persistent ledger reload mismatch");
    drop(dir_b_guard);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let rss_after_cleanup = get_rss_kb();
    let rss_process_peak = get_peak_rss_kb();

    ByRound {
        topology,
        profile,
        seed,
        target_tps,
        submission_interval_us,
        generation_span_ms,
        submitted: expected as u64,
        received: result.received,
        applied: result.applied,
        persisted: result.persisted,
        rejected: result.rejected,
        duplicates: result.duplicates,
        persistence_failures: result.persistence_failures,
        effect_mismatches: result.effect_mismatches,
        unresolved_dependencies: result.unresolved_dependencies,
        first_submission_us: first_submission.duration_since(load_start).as_micros() as u64,
        last_submission_us: last_submission.duration_since(load_start).as_micros() as u64,
        first_receipt_us: first_receipt.duration_since(load_start).as_micros() as u64,
        last_receipt_us: last_receipt.duration_since(load_start).as_micros() as u64,
        first_applied_us: first_applied.duration_since(load_start).as_micros() as u64,
        last_applied_us: last_applied.duration_since(load_start).as_micros() as u64,
        first_persisted_us: first_persisted.duration_since(load_start).as_micros() as u64,
        last_persisted_us: last_persisted.duration_since(load_start).as_micros() as u64,
        drain_us: last_applied.duration_since(last_submission).as_micros() as u64,
        persisted_drain_us: last_persisted.duration_since(last_submission).as_micros() as u64,
        propagation_us: result.propagation_us,
        dependency_wait_us: result.dependency_wait_us,
        ledger_apply_us: result.ledger_apply_us,
        end_to_end_us: result.end_to_end_us,
        backlog_peak,
        backlog_peak_at_ms,
        dependency_pending_peak,
        series: points,
        dag_transaction_count,
        storage_transaction_count,
        applied_mark_count,
        parent_missing_count,
        audit,
        persistent,
        ingress_drops,
        session_drops,
        outbound_budget_drops,
        ingress_queue_capacity_msgs: BY_INGRESS_CAPACITY_MSGS,
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
    validation_mode: &'static str,
    processing_path: &'static str,
    min_fee_at_process: u64,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_applied: u64,
    transactions_persisted: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    persistence_failures: u64,
    transaction_effect_mismatches: u64,
    unresolved_dependency_transactions: u64,
    latency_samples: usize,
    propagation_samples: usize,
    dependency_wait_samples: usize,
    ledger_apply_samples: usize,
    end_to_end_samples: usize,
    submission_start_us: u64,
    submission_end_us: u64,
    first_receipt_us: u64,
    last_receipt_us: u64,
    first_applied_us: u64,
    last_applied_us: u64,
    first_persisted_us: u64,
    last_persisted_us: u64,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    ledger_application_rate: RateMetric,
    persistence_rate: RateMetric,
    completion_rate: RateMetric,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    dependency_wait_latency_p50_us: Option<u64>,
    dependency_wait_latency_p95_us: Option<u64>,
    dependency_wait_latency_p99_us: Option<u64>,
    ledger_apply_latency_p50_us: Option<u64>,
    ledger_apply_latency_p95_us: Option<u64>,
    ledger_apply_latency_p99_us: Option<u64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    drain_ms: u64,
    persisted_drain_ms: u64,
    backlog_peak: u64,
    backlog_peak_at_ms: Option<u64>,
    dependency_pending_peak: u64,
    backlog_sample_count: usize,
    backlog_series_ms: Vec<u64>,
    backlog_series_submitted: Vec<u64>,
    backlog_series_received: Vec<u64>,
    backlog_series_applied: Vec<u64>,
    backlog_series_persisted: Vec<u64>,
    backlog_series_dependency_pending: Vec<u64>,
    backlog_series_pending: Vec<u64>,
    backlog_series_rss_kb: Vec<Option<u64>>,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    parent_missing_count: usize,
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
    round: &ByRound,
    repetition: usize,
    topology_repetition: usize,
) -> RepetitionRecord {
    let (p50, p95, p99) = stats_us(&round.propagation_us);
    let (d50, d95, d99) = stats_us(&round.dependency_wait_us);
    let (l50, l95, l99) = stats_us(&round.ledger_apply_us);
    let (e50, e95, e99) = stats_us(&round.end_to_end_us);
    let mut series_ms = Vec::with_capacity(round.series.len());
    let mut series_submitted = Vec::with_capacity(round.series.len());
    let mut series_received = Vec::with_capacity(round.series.len());
    let mut series_applied = Vec::with_capacity(round.series.len());
    let mut series_persisted = Vec::with_capacity(round.series.len());
    let mut series_dependency_pending = Vec::with_capacity(round.series.len());
    let mut series_pending = Vec::with_capacity(round.series.len());
    let mut series_rss = Vec::with_capacity(round.series.len());
    for (at_ms, submitted, received, applied, persisted, dependency, rss) in &round.series {
        series_ms.push(*at_ms);
        series_submitted.push(*submitted);
        series_received.push(*received);
        series_applied.push(*applied);
        series_persisted.push(*persisted);
        series_dependency_pending.push(*dependency);
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
        validation_mode: VALIDATION_MODE,
        processing_path: "transaction_processor_process_full_ledger_apply",
        min_fee_at_process: MIN_FEE_AT_PROCESS,
        transactions_submitted: round.submitted,
        transactions_received: round.received,
        transactions_applied: round.applied,
        transactions_persisted: round.persisted,
        transactions_rejected: round.rejected,
        duplicates_received: round.duplicates,
        persistence_failures: round.persistence_failures,
        transaction_effect_mismatches: round.effect_mismatches,
        unresolved_dependency_transactions: round.unresolved_dependencies,
        latency_samples: round.end_to_end_us.len(),
        propagation_samples: round.propagation_us.len(),
        dependency_wait_samples: round.dependency_wait_us.len(),
        ledger_apply_samples: round.ledger_apply_us.len(),
        end_to_end_samples: round.end_to_end_us.len(),
        submission_start_us: round.first_submission_us,
        submission_end_us: round.last_submission_us,
        first_receipt_us: round.first_receipt_us,
        last_receipt_us: round.last_receipt_us,
        first_applied_us: round.first_applied_us,
        last_applied_us: round.last_applied_us,
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
        ledger_application_rate: make_rate_metric(
            round.applied,
            round.first_applied_us,
            round.last_applied_us,
            FORMULA_APPLIED,
        ),
        persistence_rate: make_rate_metric(
            round.persisted,
            round.first_persisted_us,
            round.last_persisted_us,
            FORMULA_PERSISTED,
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
        dependency_wait_latency_p50_us: d50,
        dependency_wait_latency_p95_us: d95,
        dependency_wait_latency_p99_us: d99,
        ledger_apply_latency_p50_us: l50,
        ledger_apply_latency_p95_us: l95,
        ledger_apply_latency_p99_us: l99,
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        drain_ms: round.drain_us / 1_000,
        persisted_drain_ms: round.persisted_drain_us / 1_000,
        backlog_peak: round.backlog_peak,
        backlog_peak_at_ms: round.backlog_peak_at_ms,
        dependency_pending_peak: round.dependency_pending_peak,
        backlog_sample_count: series_ms.len(),
        backlog_series_ms: series_ms,
        backlog_series_submitted: series_submitted,
        backlog_series_received: series_received,
        backlog_series_applied: series_applied,
        backlog_series_persisted: series_persisted,
        backlog_series_dependency_pending: series_dependency_pending,
        backlog_series_pending: series_pending,
        backlog_series_rss_kb: series_rss,
        dag_transaction_count: round.dag_transaction_count,
        storage_transaction_count: round.storage_transaction_count,
        applied_mark_count: round.applied_mark_count,
        parent_missing_count: round.parent_missing_count,
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
    validation_mode: &'static str,
    processing_path: &'static str,
    min_fee_at_process: u64,
    transactions_submitted: u64,
    transactions_received: u64,
    transactions_applied: u64,
    transactions_persisted: u64,
    transactions_rejected: u64,
    duplicates_received: u64,
    persistence_failures: u64,
    transaction_effect_mismatches: u64,
    unresolved_dependency_transactions: u64,
    latency_samples: usize,
    propagation_samples: usize,
    dependency_wait_samples: usize,
    ledger_apply_samples: usize,
    end_to_end_samples: usize,
    offered_rate: RateMetric,
    reception_rate: RateMetric,
    ledger_application_rate: RateMetric,
    persistence_rate: RateMetric,
    completion_rate: RateMetric,
    propagation_latency_p50_us: Option<u64>,
    propagation_latency_p95_us: Option<u64>,
    propagation_latency_p99_us: Option<u64>,
    dependency_wait_latency_p50_us: Option<u64>,
    dependency_wait_latency_p95_us: Option<u64>,
    dependency_wait_latency_p99_us: Option<u64>,
    ledger_apply_latency_p50_us: Option<u64>,
    ledger_apply_latency_p95_us: Option<u64>,
    ledger_apply_latency_p99_us: Option<u64>,
    end_to_end_latency_p50_us: Option<u64>,
    end_to_end_latency_p95_us: Option<u64>,
    end_to_end_latency_p99_us: Option<u64>,
    drain_ms_mean: Option<f64>,
    drain_ms_max: Option<u64>,
    persisted_drain_ms_mean: Option<f64>,
    persisted_drain_ms_max: Option<u64>,
    backlog_peak_max: u64,
    dependency_pending_peak_max: u64,
    dag_transaction_count: usize,
    storage_transaction_count: usize,
    applied_mark_count: usize,
    parent_missing_count: usize,
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
    rounds: &[&ByRound],
) -> AggregateRecord {
    let mut propagation = Vec::new();
    let mut dependency_wait = Vec::new();
    let mut ledger_apply = Vec::new();
    let mut end_to_end = Vec::new();
    let mut offered_duration_us = 0u64;
    let mut reception_duration_us = 0u64;
    let mut applied_duration_us = 0u64;
    let mut persisted_duration_us = 0u64;
    let mut completion_duration_us = 0u64;
    let mut submitted = 0u64;
    let mut received = 0u64;
    let mut applied = 0u64;
    let mut persisted = 0u64;
    let mut rejected = 0u64;
    let mut duplicates = 0u64;
    let mut persistence_failures = 0u64;
    let mut effect_mismatches = 0u64;
    let mut unresolved_dependencies = 0u64;
    let mut drain_ms = Vec::new();
    let mut persisted_drain_ms = Vec::new();
    let mut backlog_peak_max = 0u64;
    let mut dependency_pending_peak_max = 0u64;
    let mut dag_transaction_count = 0usize;
    let mut storage_transaction_count = 0usize;
    let mut applied_mark_count = 0usize;
    let mut parent_missing_count = 0usize;
    let mut ledger_initial_supply = 0u64;
    let mut ledger_final_supply = 0u64;
    let mut ledger_expected_final_supply = 0u64;
    let mut fees_burned = 0u64;
    let mut expected_fees_burned = 0u64;
    let mut sender_nonce_mismatches = 0u64;
    let mut sender_balance_mismatches = 0u64;
    let mut receiver_balance_mismatches = 0u64;
    let mut fee_burn_mismatches = 0u64;
    let mut supply_mismatches = 0u64;
    let mut storage_balance_mismatches = 0u64;
    let mut storage_nonce_mismatches = 0u64;
    let mut storage_applied_mismatches = 0u64;
    let mut storage_row_mismatches = 0u64;
    let mut persistent_reload_verified = true;
    let mut persistent_balance_mismatches = 0u64;
    let mut persistent_nonce_mismatches = 0u64;
    let mut persistent_applied_mismatches = 0u64;
    let mut persistent_supply_mismatches = 0u64;
    let mut persistent_fee_mismatches = 0u64;
    let mut persistent_transaction_count_mismatches = 0u64;
    let mut rss_before = Vec::new();
    let mut rss_peak = 0u64;
    let mut rss_process_peak = 0u64;

    for round in rounds {
        submitted += round.submitted;
        received += round.received;
        applied += round.applied;
        persisted += round.persisted;
        rejected += round.rejected;
        duplicates += round.duplicates;
        persistence_failures += round.persistence_failures;
        effect_mismatches += round.effect_mismatches;
        unresolved_dependencies += round.unresolved_dependencies;
        offered_duration_us += round
            .last_submission_us
            .saturating_sub(round.first_submission_us);
        reception_duration_us += round.last_receipt_us.saturating_sub(round.first_receipt_us);
        applied_duration_us += round.last_applied_us.saturating_sub(round.first_applied_us);
        persisted_duration_us += round
            .last_persisted_us
            .saturating_sub(round.first_persisted_us);
        completion_duration_us += round
            .last_persisted_us
            .saturating_sub(round.first_submission_us);
        propagation.extend_from_slice(&round.propagation_us);
        dependency_wait.extend_from_slice(&round.dependency_wait_us);
        ledger_apply.extend_from_slice(&round.ledger_apply_us);
        end_to_end.extend_from_slice(&round.end_to_end_us);
        drain_ms.push(round.drain_us / 1_000);
        persisted_drain_ms.push(round.persisted_drain_us / 1_000);
        backlog_peak_max = backlog_peak_max.max(round.backlog_peak);
        dependency_pending_peak_max =
            dependency_pending_peak_max.max(round.dependency_pending_peak);
        dag_transaction_count += round.dag_transaction_count;
        storage_transaction_count += round.storage_transaction_count;
        applied_mark_count += round.applied_mark_count;
        parent_missing_count += round.parent_missing_count;
        ledger_initial_supply += round.audit.initial_supply;
        ledger_final_supply += round.audit.final_supply;
        ledger_expected_final_supply += round.audit.expected_final_supply;
        fees_burned += round.audit.fees_burned;
        expected_fees_burned += round.audit.expected_fees_burned;
        sender_nonce_mismatches += round.audit.sender_nonce_mismatches;
        sender_balance_mismatches += round.audit.sender_balance_mismatches;
        receiver_balance_mismatches += round.audit.receiver_balance_mismatches;
        fee_burn_mismatches += round.audit.fee_burn_mismatches;
        supply_mismatches += round.audit.supply_mismatches;
        storage_balance_mismatches += round.audit.storage_balance_mismatches;
        storage_nonce_mismatches += round.audit.storage_nonce_mismatches;
        storage_applied_mismatches += round.audit.storage_applied_mismatches;
        storage_row_mismatches += round.audit.storage_row_mismatches;
        persistent_reload_verified &= round.persistent.reload_ok;
        persistent_balance_mismatches += round.persistent.balance_mismatches;
        persistent_nonce_mismatches += round.persistent.nonce_mismatches;
        persistent_applied_mismatches += round.persistent.applied_mismatches;
        persistent_supply_mismatches += round.persistent.supply_mismatches;
        persistent_fee_mismatches += round.persistent.fee_mismatches;
        persistent_transaction_count_mismatches += round.persistent.transaction_count_mismatches;
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
    let (d50, d95, d99) = stats_us(&dependency_wait);
    let (l50, l95, l99) = stats_us(&ledger_apply);
    let (e50, e95, e99) = stats_us(&end_to_end);

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
        validation_mode: VALIDATION_MODE,
        processing_path: "transaction_processor_process_full_ledger_apply",
        min_fee_at_process: MIN_FEE_AT_PROCESS,
        transactions_submitted: submitted,
        transactions_received: received,
        transactions_applied: applied,
        transactions_persisted: persisted,
        transactions_rejected: rejected,
        duplicates_received: duplicates,
        persistence_failures,
        transaction_effect_mismatches: effect_mismatches,
        unresolved_dependency_transactions: unresolved_dependencies,
        latency_samples: end_to_end.len(),
        propagation_samples: propagation.len(),
        dependency_wait_samples: dependency_wait.len(),
        ledger_apply_samples: ledger_apply.len(),
        end_to_end_samples: end_to_end.len(),
        offered_rate: make_rate_metric(submitted, 0, offered_duration_us, FORMULA_OFFERED),
        reception_rate: make_rate_metric(received, 0, reception_duration_us, FORMULA_RECEIVED),
        ledger_application_rate: make_rate_metric(applied, 0, applied_duration_us, FORMULA_APPLIED),
        persistence_rate: make_rate_metric(persisted, 0, persisted_duration_us, FORMULA_PERSISTED),
        completion_rate: make_rate_metric(persisted, 0, completion_duration_us, FORMULA_COMPLETION),
        propagation_latency_p50_us: p50,
        propagation_latency_p95_us: p95,
        propagation_latency_p99_us: p99,
        dependency_wait_latency_p50_us: d50,
        dependency_wait_latency_p95_us: d95,
        dependency_wait_latency_p99_us: d99,
        ledger_apply_latency_p50_us: l50,
        ledger_apply_latency_p95_us: l95,
        ledger_apply_latency_p99_us: l99,
        end_to_end_latency_p50_us: e50,
        end_to_end_latency_p95_us: e95,
        end_to_end_latency_p99_us: e99,
        drain_ms_mean: if drain_ms.is_empty() {
            None
        } else {
            Some(drain_ms.iter().sum::<u64>() as f64 / drain_ms.len() as f64)
        },
        drain_ms_max: drain_ms.iter().copied().max(),
        persisted_drain_ms_mean: if persisted_drain_ms.is_empty() {
            None
        } else {
            Some(persisted_drain_ms.iter().sum::<u64>() as f64 / persisted_drain_ms.len() as f64)
        },
        persisted_drain_ms_max: persisted_drain_ms.iter().copied().max(),
        backlog_peak_max,
        dependency_pending_peak_max,
        dag_transaction_count,
        storage_transaction_count,
        applied_mark_count,
        parent_missing_count,
        ledger_initial_supply,
        ledger_final_supply,
        ledger_expected_final_supply,
        fees_burned,
        expected_fees_burned,
        sender_nonce_mismatches,
        sender_balance_mismatches,
        receiver_balance_mismatches,
        fee_burn_mismatches,
        supply_mismatches,
        storage_balance_mismatches,
        storage_nonce_mismatches,
        storage_applied_mismatches,
        storage_row_mismatches,
        persistent_reload_verified,
        persistent_balance_mismatches,
        persistent_nonce_mismatches,
        persistent_applied_mismatches,
        persistent_supply_mismatches,
        persistent_fee_mismatches,
        persistent_transaction_count_mismatches,
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
fn by_only_filter() -> Option<Vec<(String, String, u64)>> {
    let raw = std::env::var("BY_ONLY").ok()?;
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

fn by_selected(
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
async fn by01_ledger_apply() {
    let _reset = JitterReset;
    let only = by_only_filter();
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
        "BY_GEN chain_txs={} chain_span_ms={} multi_lane_txs={} multi_span_ms={}",
        chain_set.len(),
        chain_generation_ms,
        multi_set.len(),
        multi_generation_ms
    );

    let mut all_rounds: Vec<ByRound> = Vec::with_capacity(
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
                if !by_selected(only.as_ref(), topology, profile, target_tps) {
                    continue;
                }
                let submission_interval_us = 1_000_000 / target_tps;
                for topology_repetition in 1..=REPETITIONS_PER_CELL {
                    global_repetition += 1;
                    let seed = 0xB7_0000
                        + (profile_index as u64) * 1_000
                        + (rate_index as u64) * 100
                        + topology_repetition as u64;
                    let port = PORT_BASE + ((global_repetition - 1) as u16) * 4;
                    let round = run_round_by(
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
                        record.transactions_applied, TXS_PER_REPETITION as u64,
                        "applied count"
                    );
                    assert_eq!(
                        record.end_to_end_samples, TXS_PER_REPETITION,
                        "end-to-end samples"
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
                        "BY_REP topology={} profile={} target={} rep={} completion_tps={:.1} persisted_tps={:.1} sub_to_persist_p50_us={} sub_to_persist_p95_us={} sub_to_persist_p99_us={} prop_p50_us={} backlog_peak={} drain_ms={}",
                        topology.id(),
                        profile.id,
                        target_tps,
                        topology_repetition,
                        record.completion_rate.value.unwrap_or(0.0),
                        record.persistence_rate.value.unwrap_or(0.0),
                        record
                            .end_to_end_latency_p50_us
                            .unwrap_or(0),
                        record
                            .end_to_end_latency_p95_us
                            .unwrap_or(0),
                        record
                            .end_to_end_latency_p99_us
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
                if !by_selected(only.as_ref(), topology, profile, target_tps) {
                    continue;
                }
                let indices = cell_round_indices
                    .get(&(topology, profile.id, target_tps))
                    .expect("cell repetitions");
                assert_eq!(indices.len(), REPETITIONS_PER_CELL, "cell repetition count");
                let rounds: Vec<&ByRound> =
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
                    "BY_CELL topology={} profile={} target={} completion_tps={:.1} persisted_tps={:.1} sub_to_persist_p50_us={} sub_to_persist_p95_us={} sub_to_persist_p99_us={} backlog_max={} drain_mean_ms={:.1}",
                    topology.id(),
                    profile.id,
                    target_tps,
                    aggregate.completion_rate.value.unwrap_or(0.0),
                    aggregate.persistence_rate.value.unwrap_or(0.0),
                    aggregate
                        .end_to_end_latency_p50_us
                        .unwrap_or(0),
                    aggregate
                        .end_to_end_latency_p95_us
                        .unwrap_or(0),
                    aggregate
                        .end_to_end_latency_p99_us
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
                "BY_COMPARE profile={} target={} chain_completion_tps={:.1} multi_completion_tps={:.1} delta_tps={:.1} delta_pct={:.1}",
                profile.id,
                target_tps,
                chain_tps,
                multi_tps,
                delta,
                relative
            );
        }
    }

    let all_refs: Vec<&ByRound> = all_rounds.iter().collect();
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
        overall.end_to_end_samples,
        TXS_PER_REPETITION * all_rounds.len(),
        "overall latency sample total"
    );
    log_jsonl(&overall);
    println!(
        "BY_OVERALL completion_tps={:.1} persisted_tps={:.1} sub_to_persist_p50_us={} sub_to_persist_p95_us={} sub_to_persist_p99_us={} backlog_max={} drain_mean_ms={:.1}",
        overall.completion_rate.value.unwrap_or(0.0),
        overall.persistence_rate.value.unwrap_or(0.0),
        overall
            .end_to_end_latency_p50_us
            .unwrap_or(0),
        overall
            .end_to_end_latency_p95_us
            .unwrap_or(0),
        overall
            .end_to_end_latency_p99_us
            .unwrap_or(0),
        overall.backlog_peak_max,
        overall.drain_ms_mean.unwrap_or(0.0),
    );
}
