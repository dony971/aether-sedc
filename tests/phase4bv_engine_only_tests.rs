// Phase 4CP-BV: engine-only processing capacity (JSONL schema v5).
//
// This benchmark measures the real TransactionProcessor::process path against
// a fresh Sled database and a fresh ledger for every repetition. It does not
// submit through P2P and therefore does not include propagation jitter. It is
// an engine-capacity measurement, not an Aether network throughput number.
//
// Included in the timed region:
//   - validate_pure: PoW verification + signature verification
//   - orphan gate, DAG validation, ledger validation
//   - conflict lookup, ledger transfer, nonce commit, DAG insertion
//   - mempool removal, transaction persistence, ledger delta persistence
//
// Excluded from the timed region:
//   - PoW generation/signing (measured once, shared across repetitions)
//   - storage/ledger setup and teardown
//   - transaction cloning into the processor call
//   - P2P transport, propagation jitter, receipt queue, end-to-end latency

use aether_unified::ledger::{Ledger, FEE_BURN_ADDRESS};
use aether_unified::parent_selection::DAG;
use aether_unified::rpc::Mempool;
use aether_unified::storage::Storage;
use aether_unified::transaction::Transaction;
use aether_unified::transaction_processor::{ProcessingError, TransactionProcessor};
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const SCENARIO: &str = "engine_only_processing";
const SCENARIO_AGGREGATE: &str = "engine_only_processing_aggregate";
const ENGINE_SCHEMA_VERSION: u32 = 5;
const POW_DIFFICULTY: u8 = 20;
const TX_VALUE: u64 = 1000;
const TX_FEE: u64 = 1;
const TXS_PER_REPETITION: usize = 300;
const REPETITIONS: usize = 5;
const MIN_FEE: u64 = TX_FEE;
const INITIAL_BALANCE: u64 = 1_000_000_000;
const RSS_SAMPLE_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug, Serialize)]
struct EngineRecord {
    schema_version: u32,
    record_type: String,
    scenario: String,
    aggregate_scope: Option<String>,
    sha: String,
    profile: String,
    os: String,
    arch: String,
    repetition: Option<usize>,
    repetitions_total: usize,
    transactions_per_repetition: usize,
    pow_difficulty: u8,
    tx_value: u64,
    tx_fee: u64,
    min_fee: u64,
    validation_mode: String,
    storage_backend: String,
    state_scope: String,
    generation_scope: String,
    generation_span_ms: u64,
    generation_included_in_rates: bool,
    timing_scope: String,
    includes_p2p: bool,
    includes_propagation_jitter: bool,
    includes_generation: bool,
    includes_setup: bool,
    includes_pow_validation: bool,
    includes_signature_validation: bool,
    includes_storage_persistence: bool,
    transactions_submitted: u64,
    transactions_applied: u64,
    transactions_rejected: u64,
    persistence_failures: u64,
    duplicates_skipped: u64,
    transactions_persisted: u64,
    latency_samples: usize,
    total_duration_us: u64,
    applied_tps: f64,
    mean_duration_us: f64,
    sample_duration_sum_us: u64,
    sample_mean_duration_us: f64,
    total_minus_sample_sum_us: u64,
    tps_mean_identity_error: f64,
    rate_formula: &'static str,
    mean_formula: &'static str,
    latency_min_us: Option<u64>,
    latency_p50_us: Option<u64>,
    latency_p95_us: Option<u64>,
    latency_p99_us: Option<u64>,
    latency_max_us: Option<u64>,
    sample_duration_us: Vec<u64>,
    ledger_nonce: Option<u64>,
    ledger_applied_count: Option<u64>,
    sender_balance_end: Option<u64>,
    receiver_balance_end: Option<u64>,
    fees_burned_end: Option<u64>,
    error_samples: Vec<String>,
    rss_before_kb: Option<u64>,
    rss_under_load_peak_kb: Option<u64>,
    rss_after_kb: Option<u64>,
    rss_after_cleanup_kb: Option<u64>,
    rss_process_peak_kb: Option<u64>,
    rss_scope: String,
    rss_peak_scope: String,
    rss_note: String,
}

#[derive(Debug)]
struct EngineRound {
    submitted: u64,
    applied: u64,
    rejected: u64,
    persistence_failures: u64,
    duplicates_skipped: u64,
    persisted: u64,
    total_duration: Duration,
    samples_us: Vec<u64>,
    ledger_nonce: u64,
    ledger_applied_count: u64,
    sender_balance_end: u64,
    receiver_balance_end: u64,
    fees_burned_end: u64,
    error_samples: Vec<String>,
    rss_before: Option<u64>,
    rss_under_load_peak: Option<u64>,
    rss_after: Option<u64>,
    rss_after_cleanup: Option<u64>,
    rss_process_peak: Option<u64>,
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

fn stats_us(values: &[u64]) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    if values.is_empty() {
        return (None, None, None, None, None);
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let at = |p: usize| {
        let rank = (p * sorted.len() + 99) / 100;
        sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
    };
    (
        Some(sorted[0]),
        Some(at(50)),
        Some(at(95)),
        Some(at(99)),
        Some(sorted[sorted.len() - 1]),
    )
}

fn wallet_bv() -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", 4_242_424u64)).expect("key")
}

fn make_valid_tx_bv(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    account_nonce: u64,
    timestamp: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        [0xBBu8; 32],
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

fn prepare_transactions(wallet: &Wallet) -> (Vec<Transaction>, Duration) {
    let ts0: u64 = 1_750_400_000_000;
    let mut prev = [0u8; 32];
    let mut txs = Vec::with_capacity(TXS_PER_REPETITION);
    let started = Instant::now();
    for i in 0..TXS_PER_REPETITION {
        let tx = make_valid_tx_bv(
            wallet,
            [prev, [0u8; 32]],
            1 + i as u64,
            ts0 + i as u64,
        );
        prev = tx.id;
        txs.push(tx);
    }
    (txs, started.elapsed())
}

struct RssSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RssSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let stop_thread = stop.clone();
        let peak_thread = peak.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                if let Some(rss) = get_rss_kb() {
                    peak_thread.fetch_max(rss, Ordering::Relaxed);
                }
                std::thread::sleep(RSS_SAMPLE_INTERVAL);
            }
        });
        Self {
            stop,
            peak,
            handle: Some(handle),
        }
    }

    fn stop(mut self) -> Option<u64> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("RSS sampler join");
        }
        let peak = self.peak.load(Ordering::Relaxed);
        (peak > 0).then_some(peak)
    }
}

async fn run_engine_round(txs: &[Transaction], wallet: &Wallet) -> EngineRound {
    let dir = tempfile::tempdir().expect("engine-only tempdir");
    let storage = Arc::new(RwLock::new(
        Storage::open(dir.path()).expect("open engine-only store"),
    ));

    let mut ledger = Ledger::new_with_storage(storage.clone())
        .await
        .expect("ledger with engine-only storage");
    ledger.set_balance(&wallet.address(), INITIAL_BALANCE);
    ledger
        .save_dirty()
        .await
        .expect("seed engine-only ledger balance");
    let ledger = Arc::new(RwLock::new(ledger));
    let dag = Arc::new(RwLock::new(DAG::new()));
    let mempool = Arc::new(RwLock::new(Mempool::new(10_000, 1)));
    let processor = TransactionProcessor::new();

    let rss_before = get_rss_kb();
    let sampler = RssSampler::start();
    let mut samples_us = Vec::with_capacity(txs.len());
    let mut applied = 0u64;
    let mut rejected = 0u64;
    let mut persistence_failures = 0u64;
    let mut error_samples = Vec::new();

    let total_started = Instant::now();
    for tx in txs.iter().cloned() {
        let started = Instant::now();
        let result = processor
            .process(
                tx,
                &dag,
                &ledger,
                &mempool,
                MIN_FEE,
                ValidationMode::Historical,
            )
            .await;
        samples_us.push(started.elapsed().as_micros() as u64);
        match result {
            Ok(()) => applied += 1,
            Err(ProcessingError::PersistenceError(error)) => {
                persistence_failures += 1;
                rejected += 1;
                if error_samples.len() < 5 {
                    error_samples.push(format!("persistence: {}", error));
                }
            }
            Err(error) => {
                rejected += 1;
                if error_samples.len() < 5 {
                    error_samples.push(format!("{:?}", error));
                }
            }
        }
    }
    let total_duration = total_started.elapsed();
    let rss_under_load_peak = sampler.stop();
    let rss_after = get_rss_kb();

    let (ledger_nonce, ledger_applied_count, sender_balance_end, receiver_balance_end, fees_burned_end) = {
        let ledger = ledger.read().await;
        (
            ledger.get_nonce(&wallet.address()),
            ledger.applied.len() as u64,
            ledger.get_balance(&wallet.address()),
            ledger.get_balance(&[0xBBu8; 32]),
            ledger.get_balance(&FEE_BURN_ADDRESS),
        )
    };

    let persisted = {
        let store = storage.read().await;
        txs.iter()
            .filter(|tx| store.transaction_exists(tx.id).unwrap_or(false))
            .count() as u64
    };

    drop(dag);
    drop(ledger);
    drop(storage);
    drop(dir);
    let rss_after_cleanup = get_rss_kb();
    let rss_process_peak = get_peak_rss_kb();

    let mut seen = std::collections::HashSet::with_capacity(txs.len());
    let duplicates_skipped = txs.iter().filter(|tx| !seen.insert(tx.id)).count() as u64;

    EngineRound {
        submitted: txs.len() as u64,
        applied,
        rejected,
        persistence_failures,
        duplicates_skipped,
        persisted,
        total_duration,
        samples_us,
        ledger_nonce,
        ledger_applied_count,
        sender_balance_end,
        receiver_balance_end,
        fees_burned_end,
        error_samples,
        rss_before,
        rss_under_load_peak,
        rss_after,
        rss_after_cleanup,
        rss_process_peak,
    }
}

fn build_record(
    record_type: &str,
    scenario: &str,
    aggregate_scope: Option<&str>,
    repetition: Option<usize>,
    repetitions_total: usize,
    generation_span: Duration,
    round: &EngineRound,
) -> EngineRecord {
    let total_us = round.total_duration.as_micros() as u64;
    let applied = round.applied;
    let applied_tps = if total_us > 0 {
        applied as f64 / (total_us as f64 / 1_000_000.0)
    } else {
        0.0
    };
    let mean_duration_us = if applied > 0 {
        total_us as f64 / applied as f64
    } else {
        0.0
    };
    let sample_sum_us: u64 = round.samples_us.iter().sum();
    let sample_mean_duration_us = if applied > 0 {
        sample_sum_us as f64 / applied as f64
    } else {
        0.0
    };
    let (min, p50, p95, p99, max) = stats_us(&round.samples_us);

    EngineRecord {
        schema_version: ENGINE_SCHEMA_VERSION,
        record_type: record_type.to_string(),
        scenario: scenario.to_string(),
        aggregate_scope: aggregate_scope.map(str::to_string),
        sha: get_sha(),
        profile: get_profile(),
        os: get_os(),
        arch: get_arch(),
        repetition,
        repetitions_total,
        transactions_per_repetition: TXS_PER_REPETITION,
        pow_difficulty: POW_DIFFICULTY,
        tx_value: TX_VALUE,
        tx_fee: TX_FEE,
        min_fee: MIN_FEE,
        validation_mode: "historical".to_string(),
        storage_backend: "sled".to_string(),
        state_scope: "fresh Sled database + fresh ledger + fresh DAG + fresh mempool per repetition".to_string(),
        generation_scope: "one_time_shared_pow_before_all_repetitions".to_string(),
        generation_span_ms: generation_span.as_millis() as u64,
        generation_included_in_rates: false,
        timing_scope: "wall-clock around each TransactionProcessor::process call; excludes generation, storage/ledger setup, teardown, and input cloning".to_string(),
        includes_p2p: false,
        includes_propagation_jitter: false,
        includes_generation: false,
        includes_setup: false,
        includes_pow_validation: true,
        includes_signature_validation: true,
        includes_storage_persistence: true,
        transactions_submitted: round.submitted,
        transactions_applied: applied,
        transactions_rejected: round.rejected,
        persistence_failures: round.persistence_failures,
        duplicates_skipped: round.duplicates_skipped,
        transactions_persisted: round.persisted,
        latency_samples: round.samples_us.len(),
        total_duration_us: total_us,
        applied_tps,
        mean_duration_us,
        sample_duration_sum_us: sample_sum_us,
        sample_mean_duration_us,
        total_minus_sample_sum_us: total_us.saturating_sub(sample_sum_us),
        tps_mean_identity_error: applied_tps * mean_duration_us - 1_000_000.0,
        rate_formula: "applied / (total_duration_us / 1_000_000)",
        mean_formula: "total_duration_us / applied",
        latency_min_us: min,
        latency_p50_us: p50,
        latency_p95_us: p95,
        latency_p99_us: p99,
        latency_max_us: max,
        sample_duration_us: round.samples_us.clone(),
        ledger_nonce: repetition.map(|_| round.ledger_nonce),
        ledger_applied_count: repetition.map(|_| round.ledger_applied_count),
        sender_balance_end: repetition.map(|_| round.sender_balance_end),
        receiver_balance_end: repetition.map(|_| round.receiver_balance_end),
        fees_burned_end: repetition.map(|_| round.fees_burned_end),
        error_samples: round.error_samples.clone(),
        rss_before_kb: round.rss_before,
        rss_under_load_peak_kb: round.rss_under_load_peak,
        rss_after_kb: round.rss_after,
        rss_after_cleanup_kb: round.rss_after_cleanup,
        rss_process_peak_kb: round.rss_process_peak,
        rss_scope: "whole test process: engine-only harness, shared transaction set, fresh Sled database and ledger".to_string(),
        rss_peak_scope: "rss_under_load_peak_kb is sampled current VmRSS at 1 ms during the measured loop; rss_process_peak_kb is lifetime VmHWM and includes earlier work in the same test process.".to_string(),
        rss_note: "Linux only. rss_before_kb is VmRSS before the measured loop; rss_after_kb is VmRSS immediately after it; rss_under_load_peak_kb is the maximum sampled current VmRSS during it; rss_after_cleanup_kb is VmRSS after dropping the fresh store/ledger/DAG; rss_process_peak_kb is lifetime VmHWM. null when /proc is unavailable.".to_string(),
    }
}

fn log_record(record: &EngineRecord) {
    println!(
        "BENCH_JSONL:{}",
        serde_json::to_string(record).expect("serialize engine-only BENCH_JSONL")
    );
}

fn aggregate_rounds(rounds: &[EngineRound]) -> EngineRound {
    let mut aggregate = EngineRound {
        submitted: 0,
        applied: 0,
        rejected: 0,
        persistence_failures: 0,
        duplicates_skipped: 0,
        persisted: 0,
        total_duration: Duration::ZERO,
        samples_us: Vec::with_capacity(TXS_PER_REPETITION * rounds.len()),
        ledger_nonce: 0,
        ledger_applied_count: 0,
        sender_balance_end: 0,
        receiver_balance_end: 0,
        fees_burned_end: 0,
        error_samples: Vec::new(),
        rss_before: rounds.first().and_then(|round| round.rss_before),
        rss_under_load_peak: rounds
            .iter()
            .filter_map(|round| round.rss_under_load_peak)
            .max(),
        rss_after: rounds.last().and_then(|round| round.rss_after),
        rss_after_cleanup: rounds.last().and_then(|round| round.rss_after_cleanup),
        rss_process_peak: rounds
            .iter()
            .filter_map(|round| round.rss_process_peak)
            .max(),
    };
    for round in rounds {
        aggregate.submitted += round.submitted;
        aggregate.applied += round.applied;
        aggregate.rejected += round.rejected;
        aggregate.persistence_failures += round.persistence_failures;
        aggregate.duplicates_skipped += round.duplicates_skipped;
        aggregate.persisted += round.persisted;
        aggregate.total_duration +=
            Duration::from_micros(round.total_duration.as_micros() as u64);
        aggregate.samples_us.extend_from_slice(&round.samples_us);
        aggregate.error_samples.extend(round.error_samples.iter().cloned());
    }
    aggregate
}

#[tokio::test(flavor = "current_thread")]
async fn engine_only_processing() {
    let wallet = wallet_bv();
    let (txs, generation_span) = prepare_transactions(&wallet);
    assert_eq!(txs.len(), TXS_PER_REPETITION);
    assert!(
        txs.iter().enumerate().all(|(i, tx)| tx.account_nonce == 1 + i as u64),
        "engine-only fixture must be a nonce-ordered chain"
    );
    assert!(
        txs.windows(2).all(|pair| pair[1].parents[0] == pair[0].id),
        "engine-only fixture parents must form the measured chain"
    );

    // Warm the code paths once. The warmup uses the same clean-state protocol
    // but is not published and is not part of the measured repetitions.
    let warmup = run_engine_round(&txs, &wallet).await;
    assert_eq!(warmup.applied, TXS_PER_REPETITION as u64, "warmup applied");
    assert_eq!(warmup.rejected, 0, "warmup rejected");
    assert_eq!(warmup.persistence_failures, 0, "warmup persistence failures");

    let mut rounds = Vec::with_capacity(REPETITIONS);
    for repetition in 0..REPETITIONS {
        let round = run_engine_round(&txs, &wallet).await;
        assert_eq!(round.submitted, TXS_PER_REPETITION as u64, "submitted count");
        assert_eq!(round.applied, TXS_PER_REPETITION as u64, "applied count");
        assert_eq!(round.rejected, 0, "rejected count");
        assert_eq!(round.persistence_failures, 0, "persistence failures");
        assert_eq!(round.persisted, TXS_PER_REPETITION as u64, "persisted count");
        assert_eq!(round.samples_us.len(), TXS_PER_REPETITION, "latency samples");
        assert_eq!(round.duplicates_skipped, 0, "duplicate fixtures");
        assert_eq!(round.ledger_nonce, TXS_PER_REPETITION as u64, "ledger nonce");
        assert_eq!(
            round.ledger_applied_count, TXS_PER_REPETITION as u64,
            "ledger applied count"
        );
        assert_eq!(round.fees_burned_end, TXS_PER_REPETITION as u64, "fees burned");
        assert_eq!(
            round.sender_balance_end,
            INITIAL_BALANCE - TXS_PER_REPETITION as u64 * (TX_VALUE + TX_FEE),
            "sender balance"
        );
        assert_eq!(
            round.receiver_balance_end,
            TXS_PER_REPETITION as u64 * TX_VALUE,
            "receiver balance"
        );
        assert!(round.total_duration.as_nanos() > 0, "total duration");
        assert!(
            round.samples_us.iter().all(|sample| *sample > 0),
            "per-transaction samples must be positive"
        );

        let record = build_record(
            "repetition",
            SCENARIO,
            None,
            Some(repetition + 1),
            REPETITIONS,
            generation_span,
            &round,
        );
        assert_eq!(record.latency_samples, TXS_PER_REPETITION);
        assert_eq!(record.sample_duration_us.len(), TXS_PER_REPETITION);
        assert!(record.total_duration_us > 0);
        assert!((record.applied_tps - TXS_PER_REPETITION as f64 / (record.total_duration_us as f64 / 1_000_000.0)).abs() < 1e-9);
        assert!((record.mean_duration_us - record.total_duration_us as f64 / TXS_PER_REPETITION as f64).abs() < 1e-9);
        assert!(record.tps_mean_identity_error.abs() < 1e-6);
        assert!(record.sample_duration_sum_us <= record.total_duration_us);
        assert!(record.latency_min_us.is_some());
        assert!(record.latency_p50_us.is_some());
        assert!(record.latency_p95_us.is_some());
        assert!(record.latency_p99_us.is_some());
        assert!(record.latency_max_us.is_some());
        log_record(&record);
        rounds.push(round);
    }

    let aggregate_round = aggregate_rounds(&rounds);
    let aggregate = build_record(
        "aggregate",
        SCENARIO_AGGREGATE,
        Some("overall"),
        None,
        REPETITIONS,
        generation_span,
        &aggregate_round,
    );
    assert_eq!(aggregate.transactions_submitted, (TXS_PER_REPETITION * REPETITIONS) as u64);
    assert_eq!(aggregate.transactions_applied, (TXS_PER_REPETITION * REPETITIONS) as u64);
    assert_eq!(aggregate.transactions_rejected, 0);
    assert_eq!(aggregate.persistence_failures, 0);
    assert_eq!(aggregate.transactions_persisted, (TXS_PER_REPETITION * REPETITIONS) as u64);
    assert_eq!(aggregate.latency_samples, TXS_PER_REPETITION * REPETITIONS);
    assert_eq!(aggregate.sample_duration_us.len(), TXS_PER_REPETITION * REPETITIONS);
    assert!(aggregate.total_duration_us > 0);
    assert!((aggregate.applied_tps - aggregate.transactions_applied as f64 / (aggregate.total_duration_us as f64 / 1_000_000.0)).abs() < 1e-9);
    assert!((aggregate.mean_duration_us - aggregate.total_duration_us as f64 / aggregate.transactions_applied as f64).abs() < 1e-9);
    assert!(aggregate.tps_mean_identity_error.abs() < 1e-6);
    assert!(aggregate.sample_duration_sum_us <= aggregate.total_duration_us);
    assert!(aggregate.ledger_nonce.is_none());
    assert!(aggregate.sender_balance_end.is_none());
    log_record(&aggregate);
}

