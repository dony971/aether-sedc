//! PHASE 4CP-AV — recovery after a stop, impossible compensation, and
//! storage coherence (follow-up to 4CP-AU's atomic ledger delta).
//!
//! What this module pins, through the REAL acceptance path
//! (`process_transaction` -> persisted mempool tree -> `drain_mempool` ->
//! `TransactionProcessor::process`) and the REAL boot recovery decision
//! block (mirrored from `node.rs`, see `boot_recovery_like_node`):
//!
//!   av1  atomic tx write     — `put_transaction` is ONE multi-tree Sled
//!                              transaction (tx row + both AddressIndex
//!                              keys): an injected fault at the write aborts
//!                              the WHOLE write (no row, no index residue)
//!                              and the retry applies exactly once.
//!   av2  double fault        — window B (row durable, ledger save failed)
//!                              with the compensating delete ALSO failing:
//!                              the accept must KEEP the applied state
//!                              (the surviving row is the durable recovery
//!                              source; boot applies it exactly once)
//!                              instead of rolling back into the pre-4CP-AV
//!                              misroute (rule #3 sees the row, the retry
//!                              DAG-only heals, effects never applied live).
//!   av3  simulated stop      — durable image between STEP-8's row write and
//!                              the ledger save: after a close+reopen the
//!                              boot mirrors heal it to consistent-applied
//!                              (derived <= persisted guard) and the boot
//!                              mempool reload drops the stale accepted
//!                              copy. Close+reopen, NOT a power-loss claim.
//!   av4  legacy row-only     — crafted pre-4CP-AV image (row, no index):
//!                              boots to consistent-applied; documented
//!                              degradation = address scans cannot find it;
//!                              re-arrival never double-applies.
//!   av5  legacy index-only   — crafted residue (index keys, no row): never
//!                              resurrects (scans skip missing rows), is
//!                              never auto-deleted, and a genuine re-arrival
//!                              applies exactly once through the normal
//!                              path (row absent => effects absent).
//!   av6  legacy row+1 index  — boots to consistent-applied; the present
//!                              side is scannable, the missing side is not.
//!   av7  migration           — `migrate_from_json` is ONE atomic
//!                              `batch_write`: a fault aborts the import
//!                              with NOTHING durable and `needs_migration`
//!                              still true; the re-run completes cleanly.
//!
//! Fixture model (why funding is a DAG tx): the boot guard only adopts the
//! derived ledger when `derived_supply <= persisted_supply`. A balance set
//! WITHOUT a DAG transaction would be invisible to the derivation and make
//! every healed assertion meaningless. Every fixture therefore persists the
//! full genesis distribution (like a real first boot) and funds the test
//! sender through a raw genesis-era funding tx (same pattern as
//! `src/tests/crash_harness.rs`), so memory, durable store and DAG-derived
//! world are supply-identical before the fault window opens.

use crate::genesis::{initialize_genesis, GenesisConfig, FAUCET_ADDRESS};
use crate::ledger::{Ledger, FEE_BURN_ADDRESS};
use crate::parent_selection::{rebuild_dag_topological, DAG};
use crate::rpc::{AetherRpcImpl, Mempool};
use crate::stake::{current_epoch, StakeRegistry};
use crate::storage::{Storage, StorageFault};
use crate::transaction::Transaction;
use crate::validation::ValidationMode;
use crate::wallet::Wallet;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;

const AV_RECEIVER: [u8; 32] = [0x42u8; 32];
const FUND_AMOUNT: u64 = 10_000;
const TX_AMOUNT: u64 = 100;
const TX_FEE: u64 = 10;

struct AvNode {
    rpc: AetherRpcImpl,
    storage: Arc<RwLock<Storage>>,
    ledger: Arc<RwLock<Ledger>>,
    dag: Arc<RwLock<DAG>>,
    mempool: Arc<RwLock<Mempool>>,
}

fn av_wallet() -> Wallet {
    Wallet::from_secret_key("6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef")
        .expect("fixed test key")
}

fn faucet_bytes() -> [u8; 32] {
    hex::decode(FAUCET_ADDRESS)
        .expect("faucet hex")
        .try_into()
        .expect("32B")
}

fn genesis_total() -> u64 {
    crate::genesis::GENESIS_LEDGER.iter().map(|(_, b)| *b).sum()
}

fn addr(prefix: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = prefix;
    a
}

/// Pre-migration timestamp -> 20-bit PoW (mined once per test, ~fast).
/// Historical mode matches the sync/reload/orphan ingress shape a real
/// re-arrival of an accepted-but-unpersisted tx takes in production.
fn build_tx(
    wallet: &Wallet,
    receiver: [u8; 32],
    amount: u64,
    fee: u64,
    account_nonce: u64,
) -> Transaction {
    let ts = Transaction::DIFFICULTY_MIGRATION_TS - 3_600_000;
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        wallet.address(),
        receiver,
        amount,
        fee,
        ts,
        0,
        account_nonce,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_pow(20));
    tx
}

/// Genesis-era funding tx: faucet -> `sender`, fee 0, raw (zero signature).
/// Mirrors `crash_harness::fund_tx`: injected into the DAG and persisted
/// directly like a genesis distribution; the ledger rebuild replays it
/// without crypto re-verification, so `sender`'s balance is DAG-backed and
/// survives every boot derivation byte-for-byte.
fn funding_tx(sender: [u8; 32]) -> Transaction {
    let ts = Transaction::DIFFICULTY_MIGRATION_TS - 7_200_000;
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        faucet_bytes(),
        sender,
        FUND_AMOUNT,
        0,
        ts,
        0,
        0,
        vec![0u8; 64],
        vec![0u8; 64],
    );
    tx.id = tx.compute_hash();
    tx
}

/// Open a sled store, tolerating sled's transient release of the exclusive
/// directory lock after a close (same bounded retry as the 4BZ harness:
/// only the recognized lock error is retried; anything else fails loudly).
fn open_store_with_retry(dir: &Path) -> Storage {
    const MAX_ATTEMPTS: u32 = 50;
    for attempt in 1..=MAX_ATTEMPTS {
        match Storage::open(dir) {
            Ok(s) => return s,
            Err(e) => {
                let msg = e.to_string();
                let lock_held = msg.contains("could not acquire lock")
                    || msg.contains("Resource temporarily unavailable");
                if lock_held && attempt < MAX_ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                panic!(
                    "could not open sled store at {} after {attempt} attempt(s): {e}",
                    dir.display()
                );
            }
        }
    }
    unreachable!("bounded open loop always returns or panics")
}

/// Faithful mirror of the `node.rs` boot recovery decision block, in order:
/// open store -> load ledger -> rebuild DAG topologically from persisted
/// txs + orphans -> tips -> `ledger.save()` (node.rs:387) -> INC-01 guard
/// (node.rs:543-601: derive only on a complete-looking store, adopt only
/// when `is_fresh || derived_supply <= persisted_supply`) -> mempool reload
/// with DAG-duplicate skip + removal (node.rs:645-674). p2p/sync/task
/// wiring is omitted (no consensus input); the v6 rebuild uses the loaded
/// registry, empty in these fixtures (bit-identical to legacy for all-pre-V6
/// DAGs). This is the same fidelity stance as `tests/phase4bz_*`'s
/// `boot_like_rebuild`.
async fn boot_recovery_like_node(dir: &Path) -> (DAG, Ledger, Arc<RwLock<Storage>>, Mempool) {
    let storage = Arc::new(RwLock::new(open_store_with_retry(&dir.join("sled"))));
    let mut ledger = Ledger::new_with_storage(storage.clone())
        .await
        .expect("ledger with storage");

    let (mut dag, _b, _o, _m) = initialize_genesis(GenesisConfig::default());
    let mut all = storage
        .read()
        .await
        .get_all_transactions()
        .expect("read txs");
    for orphan in storage
        .read()
        .await
        .get_all_orphans()
        .expect("read orphans")
    {
        if !all.iter().any(|t| t.id == orphan.id) {
            all.push(orphan);
        }
    }
    let (_inserted, rebuild_skipped, orphans) = rebuild_dag_topological(&mut dag, all);
    dag.rebuild_tips();

    ledger.save().await.expect("boot ledger save (node.rs:387)");

    if orphans.is_empty() && rebuild_skipped == 0 {
        let mut derived = ledger.clone();
        {
            let reg = StakeRegistry::new();
            derived.rebuild_from_dag_v6(&dag, &reg, current_epoch());
        }
        let derived_supply = derived.total_supply();
        let persisted_supply = ledger.total_supply();
        let is_fresh = persisted_supply == 0;
        if is_fresh || derived_supply <= persisted_supply {
            ledger = derived;
            ledger.save().await.expect("guard ledger save");
        }
    }

    let mut mempool = Mempool::new(1000, 10);
    {
        let s = storage.read().await;
        if let Ok(persisted_txs) = s.load_mempool_txs() {
            for tx in persisted_txs {
                if dag.transactions().contains_key(&tx.id) {
                    let _ = s.remove_mempool_tx(tx.id);
                    continue;
                }
                if mempool.size() < mempool.max_size() {
                    let _ = mempool.enqueue(tx, 0);
                }
            }
        }
    }

    (dag, ledger, storage, mempool)
}

/// Live node wired around the REAL recovery path (above) + RPC, so every
/// test starts from a state a real node would have after boot.
async fn boot_av_node(dir: &Path) -> AvNode {
    let (dag, ledger, storage, mempool) = boot_recovery_like_node(dir).await;
    let dag = Arc::new(RwLock::new(dag));
    let ledger = Arc::new(RwLock::new(ledger));
    let mempool = Arc::new(RwLock::new(mempool));
    let (tx_channel, _rx) = tokio::sync::mpsc::unbounded_channel::<Transaction>();
    let p2p = Arc::new(crate::P2PNetwork::new(
        crate::p2p::P2PConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: crate::transaction::DEFAULT_NETWORK_ID,
        },
        tx_channel,
        Arc::new(|| Vec::new()),
        Arc::new(|_| None),
        Arc::new(|| Vec::new()),
        Arc::new(crate::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    let rpc = AetherRpcImpl::new(
        dag.clone(),
        ledger.clone(),
        storage.clone(),
        dir.join("ledger.json"),
        mempool.clone(),
        p2p,
        Arc::new(RwLock::new(true)),
        Arc::new(RwLock::new(std::collections::HashMap::new())),
        Arc::new(crate::sync_stats::SyncContext::default()),
    );
    AvNode {
        rpc,
        storage,
        ledger,
        dag,
        mempool,
    }
}

/// Persist the funding tx durably, inject it into the live DAG and bring
/// the memory ledger to the same DAG-consistent world: faucet debited by
/// FUND_AMOUNT, sender credited by FUND_AMOUNT (supply conserved). After
/// this, `memory == durable == derived(DAG)` for the accounts in play, so
/// any later difference is evidence about the fault window only.
async fn fund_sender(node: &AvNode) -> ([u8; 32], Transaction) {
    let wallet = av_wallet();
    let sender = wallet.address();
    let fund = funding_tx(sender);

    let (faucet_hex, faucet_genesis) = crate::genesis::GENESIS_LEDGER
        .iter()
        .find(|(a, _)| *a == FAUCET_ADDRESS)
        .expect("faucet in genesis ledger");
    let faucet_addr: [u8; 32] = hex::decode(faucet_hex)
        .expect("faucet hex")
        .try_into()
        .expect("32B");

    {
        let storage = node.storage.read().await;
        storage.put_transaction(&fund).expect("persist funding tx");
        storage.flush().expect("flush funding tx");
    }
    node.dag.write().await.inject_transaction_raw(fund.clone());
    {
        let mut ledger = node.ledger.write().await;
        ledger.set_balance(&faucet_addr, faucet_genesis - FUND_AMOUNT);
        ledger.set_balance(&sender, FUND_AMOUNT);
        ledger.save_dirty().await.expect("persist funding state");
    }
    node.storage
        .read()
        .await
        .flush()
        .expect("flush funding state");

    assert_eq!(
        node.storage.read().await.get_balance(sender).unwrap(),
        FUND_AMOUNT,
        "funding balance must be durable before the fault window"
    );
    (sender, fund)
}

/// Full post-success fingerprint (memory + durable + queue + index).
async fn assert_applied_world(node: &AvNode, tx: &Transaction, sender: &[u8; 32]) {
    {
        let ledger = node.ledger.read().await;
        assert_eq!(
            ledger.get_balance(sender),
            FUND_AMOUNT - TX_AMOUNT - TX_FEE,
            "sender debited once"
        );
        assert_eq!(ledger.get_balance(&AV_RECEIVER), TX_AMOUNT);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), TX_FEE);
        assert!(ledger.is_applied(&tx.id));
    }
    assert!(node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 0, "queue drained");
    {
        let storage = node.storage.read().await;
        assert!(storage.transaction_exists(tx.id).unwrap());
        assert_eq!(
            storage.get_balance(*sender).unwrap(),
            FUND_AMOUNT - TX_AMOUNT - TX_FEE
        );
        assert_eq!(storage.get_balance(AV_RECEIVER).unwrap(), TX_AMOUNT);
        assert_eq!(storage.get_balance(FEE_BURN_ADDRESS).unwrap(), TX_FEE);
        assert!(storage.is_applied(tx.id).unwrap(), "durable applied mark");
        assert_eq!(
            storage.address_index_len_for(sender).unwrap(),
            2,
            "funding receiver-key + this tx's sender-key"
        );
        assert_eq!(
            storage.address_index_len_for(&AV_RECEIVER).unwrap(),
            1,
            "exactly one receiver index key"
        );
    }
}

/// Assert the durable balances of the fully-healed world (post-boot).
async fn assert_healed_durable_world(node: &AvNode, tx: &Transaction, sender: &[u8; 32]) {
    {
        let ledger = node.ledger.read().await;
        assert_eq!(ledger.get_balance(sender), FUND_AMOUNT - TX_AMOUNT - TX_FEE);
        assert_eq!(ledger.get_balance(&AV_RECEIVER), TX_AMOUNT);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), TX_FEE);
        assert!(ledger.is_applied(&tx.id));
        assert_eq!(
            ledger.get_nonce(sender),
            0,
            "account_nonce-0 tx: the rebuild's max rule (ledger.rs) leaves the nonce at 0, same as STEP 5"
        );
        assert_eq!(ledger.total_supply(), genesis_total() - TX_FEE);
    }
    assert!(node.dag.read().await.transactions().contains_key(&tx.id));
    {
        let storage = node.storage.read().await;
        assert!(storage.transaction_exists(tx.id).unwrap());
        assert_eq!(
            storage.get_balance(*sender).unwrap(),
            FUND_AMOUNT - TX_AMOUNT - TX_FEE
        );
        assert_eq!(storage.get_balance(AV_RECEIVER).unwrap(), TX_AMOUNT);
        assert_eq!(storage.get_balance(FEE_BURN_ADDRESS).unwrap(), TX_FEE);
        assert!(storage.is_applied(tx.id).unwrap());
        assert_eq!(
            storage.get_nonce(*sender).unwrap_or(0),
            0,
            "nonce 0 is never written (set_nonce is only called when account_nonce advances it)"
        );
        assert!(storage.load_mempool_txs().unwrap().is_empty());
    }
}

/// av1 — the tx write is ONE multi-tree Sled transaction. An injected fault
/// aborts it entirely (row AND both index keys) and the retried tx applies
/// exactly once through the normal path.
#[tokio::test]
async fn av1_put_transaction_atomic_under_fault_and_retry_applies_once() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let (sender, _fund) = fund_sender(&node).await;
    let wallet = av_wallet();
    let tx = build_tx(&wallet, AV_RECEIVER, TX_AMOUNT, TX_FEE, 0);

    node.rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await
        .expect("accept");
    assert_eq!(node.mempool.read().await.size(), 1);

    node.storage
        .write()
        .await
        .arm_fault(StorageFault::PutTransaction);
    node.rpc.drain_mempool().await;

    {
        let ledger = node.ledger.read().await;
        assert_eq!(
            ledger.get_balance(&sender),
            FUND_AMOUNT,
            "memory rolled back"
        );
        assert!(!ledger.is_applied(&tx.id));
    }
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(node.mempool.read().await.size(), 1, "requeued (transient)");
    {
        let storage = node.storage.read().await;
        assert!(!storage.transaction_exists(tx.id).unwrap(), "row absent");
        assert!(
            !storage.is_applied(tx.id).unwrap(),
            "no applied mark for an aborted write"
        );
        assert_eq!(
            storage.address_index_len_for(&sender).unwrap(),
            1,
            "only the funding tx's receiver-key indexes this address"
        );
        assert_eq!(
            storage.address_index_len_for(&AV_RECEIVER).unwrap(),
            0,
            "the aborted atomic write must leave NO receiver index key"
        );
        assert_eq!(storage.get_balance(sender).unwrap(), FUND_AMOUNT);
    }

    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;

    // Extra cycle: the queue is empty, nothing double-applies.
    node.rpc.drain_mempool().await;
    assert_eq!(
        node.ledger.read().await.get_balance(&sender),
        FUND_AMOUNT - TX_AMOUNT - TX_FEE
    );
}

/// av2 — M1 window B with the compensating delete ALSO failing (double
/// fault). The surviving row is the durable recovery source: the accept must
/// keep the applied state (coherent, terminates Ok, no requeue), and the
/// next boot must apply the row's effects exactly once. Rolling back here
/// (pre-4CP-AV) would strand the accept in the rule-#3 misroute: the retry
/// DAG-only heals and the effects are never applied live, while boot would
/// apply them anyway — a live/durable divergence presented as success.
#[tokio::test]
async fn av2_compensation_failure_keeps_applied_state_and_restart_heals_delta() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let (sender, fund) = fund_sender(&node).await;
    let wallet = av_wallet();
    let tx = build_tx(&wallet, AV_RECEIVER, TX_AMOUNT, TX_FEE, 0);

    node.rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await
        .expect("accept");

    // FIFO: the delta write fails first, then the compensating delete.
    {
        let mut s = node.storage.write().await;
        s.arm_fault(StorageFault::PutBalance);
        s.arm_fault(StorageFault::DeleteTransaction);
    }
    node.rpc.drain_mempool().await;

    // Two-outcome rule: cleanup failed => KEEP applied, terminate coherently.
    {
        let ledger = node.ledger.read().await;
        assert_eq!(
            ledger.get_balance(&sender),
            FUND_AMOUNT - TX_AMOUNT - TX_FEE,
            "ledger effects stay applied when the row survives (durable recovery source)"
        );
        assert_eq!(ledger.get_balance(&AV_RECEIVER), TX_AMOUNT);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), TX_FEE);
        assert!(ledger.is_applied(&tx.id));
        assert_eq!(
            ledger.get_nonce(&sender),
            0,
            "account_nonce-0 tx: the max rule (nonce = max(nonce, account_nonce)) leaves it at 0"
        );
    }
    assert!(node.dag.read().await.transactions().contains_key(&tx.id));
    assert_eq!(
        node.mempool.read().await.size(),
        0,
        "the accept terminated (no requeue): keeping applied + Err would requeue into the misroute"
    );
    assert_eq!(node.rpc.mempool_stats().await.included, 1);
    {
        let storage = node.storage.read().await;
        assert!(
            storage.transaction_exists(tx.id).unwrap(),
            "row survived (compensation failed) — durable recovery source"
        );
        assert_eq!(
            storage.get_balance(sender).unwrap(),
            FUND_AMOUNT,
            "the failed delta wrote nothing (4CP-AU atomicity)"
        );
        assert!(!storage.is_applied(tx.id).unwrap());
        assert!(
            storage.get_nonce(sender).is_err(),
            "nonce not durable either — the whole delta failed"
        );
        assert_eq!(storage.address_index_len_for(&sender).unwrap(), 2);
        assert_eq!(storage.address_index_len_for(&AV_RECEIVER).unwrap(), 1);
    }
    // Live coherence: memory ledger == derived-from-live-DAG.
    {
        let dag = node.dag.read().await;
        let mut derived = Ledger::new();
        derived.rebuild_from_dag(&dag);
        let ledger = node.ledger.read().await;
        assert_eq!(
            derived.total_supply(),
            ledger.total_supply(),
            "live memory must equal the DAG-derived world"
        );
        assert_eq!(derived.get_balance(&sender), ledger.get_balance(&sender));
        assert_eq!(
            derived.get_balance(&AV_RECEIVER),
            ledger.get_balance(&AV_RECEIVER)
        );
        assert_eq!(
            derived.get_balance(&FEE_BURN_ADDRESS),
            ledger.get_balance(&FEE_BURN_ADDRESS)
        );
    }

    drop(node);

    // REAL boot: close + reopen through the node.rs recovery mirror.
    let node = boot_av_node(dir.path()).await;
    assert!(node.dag.read().await.transactions().contains_key(&fund.id));
    assert_healed_durable_world(&node, &tx, &sender).await;

    // Re-arrival of the same id after the heal: no double apply, no double fee.
    let res = node
        .rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await;
    assert!(
        format!("{res:?}").contains("Duplicate transaction"),
        "re-arrival of an already-applied tx must be refused at the accept funnel (DAG dedup, rpc.rs): {res:?}"
    );
    node.rpc.drain_mempool().await;
    {
        let ledger = node.ledger.read().await;
        assert_eq!(
            ledger.get_balance(&sender),
            FUND_AMOUNT - TX_AMOUNT - TX_FEE
        );
        assert_eq!(ledger.get_balance(&AV_RECEIVER), TX_AMOUNT);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), TX_FEE);
    }
    assert_eq!(node.mempool.read().await.size(), 0);
}

/// av3 — simulated process stop BETWEEN STEP-8's row write and the ledger
/// save (the exact boundary of the window-B fault, without the failure
/// branch): row durable, no delta, no mark, accepted copy still in the
/// persisted mempool tree. After the close+reopen the boot mirror must heal
/// it to consistent-applied (derived <= persisted guard) and the boot
/// mempool reload must drop the stale accepted copy (tx already in the DAG).
/// This is a close+reopen simulation, NOT a power-loss claim.
#[tokio::test]
async fn av3_stop_between_row_write_and_ledger_save_heals_at_boot() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let (sender, _fund) = fund_sender(&node).await;
    let wallet = av_wallet();
    let tx = build_tx(&wallet, AV_RECEIVER, TX_AMOUNT, TX_FEE, 0);

    node.rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await
        .expect("accept");
    // Mirror STEP 8's first half, then stop: no drain, no ledger save.
    {
        let storage = node.storage.read().await;
        storage
            .put_transaction(&tx)
            .expect("row write (mirrors STEP 8)");
        storage.flush().expect("flush row");
    }
    drop(node);

    let node = boot_av_node(dir.path()).await;
    assert_healed_durable_world(&node, &tx, &sender).await;

    // Re-arrival: already in the DAG, no double apply.
    let res = node
        .rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await;
    assert!(
        format!("{res:?}").contains("Duplicate transaction"),
        "re-arrival of an already-applied tx must be refused at the accept funnel (DAG dedup, rpc.rs): {res:?}"
    );
    node.rpc.drain_mempool().await;
    assert_eq!(
        node.ledger.read().await.get_balance(&sender),
        FUND_AMOUNT - TX_AMOUNT - TX_FEE
    );
    assert_eq!(node.mempool.read().await.size(), 0);
}

/// av4 — crafted pre-4CP-AV image: tx row present, NO index keys (stop
/// between the old writer's first and second insert). Boot heals it to
/// consistent-applied; the documented degradation is that address scans
/// cannot find it (no index key) even though the DAG and ledger are exact.
#[tokio::test]
async fn av4_legacy_row_only_heals_forward_with_documented_scan_degradation() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let (sender, fund) = fund_sender(&node).await;
    let wallet = av_wallet();
    let tx = build_tx(&wallet, AV_RECEIVER, TX_AMOUNT, TX_FEE, 0);

    {
        let storage = node.storage.read().await;
        storage
            .craft_partial_tx_for_test(&tx, true, false, false)
            .expect("craft legacy row-only image");
        assert_eq!(
            storage.transaction_count().unwrap(),
            2,
            "funding + this row"
        );
    }
    drop(node);

    let node = boot_av_node(dir.path()).await;
    assert_healed_durable_world(&node, &tx, &sender).await;
    {
        let storage = node.storage.read().await;
        assert_eq!(
            storage.address_index_len_for(&sender).unwrap(),
            1,
            "only the funding tx's receiver-key exists (no auto-repair of legacy index)"
        );
        assert_eq!(storage.address_index_len_for(&AV_RECEIVER).unwrap(), 0);
        let by_sender = storage.get_transactions_by_address(&sender).unwrap();
        assert!(
            by_sender.iter().any(|t| t.id == fund.id),
            "funding tx scannable"
        );
        assert!(
            !by_sender.iter().any(|t| t.id == tx.id),
            "legacy row NOT address-scannable (documented degradation)"
        );
        assert!(storage
            .get_transactions_by_address(&AV_RECEIVER)
            .unwrap()
            .is_empty());
    }

    // Re-arrival: already in the DAG, no double apply.
    let res = node
        .rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await;
    assert!(
        format!("{res:?}").contains("Duplicate transaction"),
        "re-arrival of an already-applied tx must be refused at the accept funnel (DAG dedup, rpc.rs): {res:?}"
    );
    node.rpc.drain_mempool().await;
    assert_eq!(
        node.ledger.read().await.get_balance(&sender),
        FUND_AMOUNT - TX_AMOUNT - TX_FEE
    );
}

/// av5 — crafted pre-4CP-AV residue: BOTH index keys present, row absent
/// (stop after the index inserts, before the row commit). The residue is
/// never auto-deleted (preservation rule), never resurrects (scans resolve
/// the index to a row and skip missing rows), and a genuine re-arrival of
/// the same tx applies exactly once through the NORMAL path (row absent =>
/// effects absent), reusing the same index keys.
#[tokio::test]
async fn av5_legacy_index_residue_never_resurrects_and_rearrival_applies_once() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let (sender, fund) = fund_sender(&node).await;
    let wallet = av_wallet();
    let tx = build_tx(&wallet, AV_RECEIVER, TX_AMOUNT, TX_FEE, 0);

    {
        let storage = node.storage.read().await;
        storage
            .craft_partial_tx_for_test(&tx, false, true, true)
            .expect("craft legacy index-only residue");
        assert!(!storage.transaction_exists(tx.id).unwrap());
        assert_eq!(storage.address_index_len_for(&sender).unwrap(), 2);
        assert_eq!(storage.address_index_len_for(&AV_RECEIVER).unwrap(), 1);
    }
    drop(node);

    let node = boot_av_node(dir.path()).await;
    // No row => no DAG tx => no effects: the residue alone must not apply.
    assert!(!node.dag.read().await.transactions().contains_key(&tx.id));
    {
        let ledger = node.ledger.read().await;
        assert_eq!(
            ledger.get_balance(&sender),
            FUND_AMOUNT,
            "residue applies nothing"
        );
        assert_eq!(ledger.get_balance(&AV_RECEIVER), 0);
        assert_eq!(ledger.get_balance(&FEE_BURN_ADDRESS), 0);
    }
    {
        let storage = node.storage.read().await;
        assert_eq!(
            storage.address_index_len_for(&sender).unwrap(),
            2,
            "residue preserved verbatim (never auto-deleted)"
        );
        assert_eq!(storage.address_index_len_for(&AV_RECEIVER).unwrap(), 1);
        let by_sender = storage.get_transactions_by_address(&sender).unwrap();
        assert_eq!(by_sender.len(), 1, "scans skip missing rows");
        assert_eq!(by_sender[0].id, fund.id);
        assert!(storage
            .get_transactions_by_address(&AV_RECEIVER)
            .unwrap()
            .is_empty());
    }

    // Genuine re-arrival: row absent => effects absent => NORMAL path,
    // accepted by the funnel and applied exactly once (reusing the same
    // index keys — residue overwritten, never duplicated).
    node.rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await
        .expect("re-accept (row absent => not a duplicate)");
    node.rpc.drain_mempool().await;
    assert_applied_world(&node, &tx, &sender).await;
    assert_eq!(
        node.storage
            .read()
            .await
            .address_index_len_for(&sender)
            .unwrap(),
        2,
        "re-arrival overwrote the residue keys, never duplicated them"
    );
    assert_eq!(
        node.storage
            .read()
            .await
            .address_index_len_for(&AV_RECEIVER)
            .unwrap(),
        1
    );
}

/// av6 — crafted pre-4CP-AV image: row present + ONE index key (stop between
/// the two index inserts of the old writer). Boot heals to
/// consistent-applied; the present index side is scannable, the missing side
/// is not (documented, no auto-repair).
#[tokio::test]
async fn av6_legacy_row_with_single_index_heals_forward() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let (sender, fund) = fund_sender(&node).await;
    let wallet = av_wallet();
    let tx = build_tx(&wallet, AV_RECEIVER, TX_AMOUNT, TX_FEE, 0);

    {
        let storage = node.storage.read().await;
        storage
            .craft_partial_tx_for_test(&tx, true, true, false)
            .expect("craft legacy row + sender-index image");
    }
    drop(node);

    let node = boot_av_node(dir.path()).await;
    assert_healed_durable_world(&node, &tx, &sender).await;
    {
        let storage = node.storage.read().await;
        assert_eq!(storage.address_index_len_for(&sender).unwrap(), 2);
        assert_eq!(storage.address_index_len_for(&AV_RECEIVER).unwrap(), 0);
        let by_sender = storage.get_transactions_by_address(&sender).unwrap();
        assert!(by_sender.iter().any(|t| t.id == fund.id));
        assert!(
            by_sender.iter().any(|t| t.id == tx.id),
            "present index side is scannable"
        );
        assert!(
            storage
                .get_transactions_by_address(&AV_RECEIVER)
                .unwrap()
                .is_empty(),
            "missing index side is not scannable (documented degradation)"
        );
    }

    let res = node
        .rpc
        .process_transaction(tx.clone(), "AV-Test", ValidationMode::Historical)
        .await;
    assert!(
        format!("{res:?}").contains("Duplicate transaction"),
        "re-arrival of an already-applied tx must be refused at the accept funnel (DAG dedup, rpc.rs): {res:?}"
    );
    node.rpc.drain_mempool().await;
    assert_eq!(
        node.ledger.read().await.get_balance(&sender),
        FUND_AMOUNT - TX_AMOUNT - TX_FEE
    );
    assert_eq!(
        node.storage.read().await.get_balance(AV_RECEIVER).unwrap(),
        TX_AMOUNT
    );
}

/// av7 — `migrate_from_json` is ONE atomic `batch_write` (plus the
/// completion flag as a separate post-batch write). An injected fault at
/// the batch aborts the whole import with NOTHING durable and
/// `needs_migration` still true, so the next boot re-runs the import from
/// the intact JSON; the re-run then completes cleanly and idempotently.
#[tokio::test]
async fn av7_migration_is_all_or_nothing_and_reruns_cleanly() {
    let dir = tempdir().unwrap();
    let data = dir.path().join("legacy-json");
    std::fs::create_dir_all(&data).unwrap();

    // Small legacy JSON world: funding tx + two chained transfers.
    let sender = addr(0x11);
    let receiver = addr(0x22);
    let f = funding_tx(sender);
    let t1 = Transaction::new(
        [f.id, [0u8; 32]],
        sender,
        receiver,
        1_000,
        5,
        f.timestamp + 1,
        0,
        1,
        vec![0u8; 64],
        vec![0u8; 64],
    );
    let t2 = Transaction::new(
        [t1.id, [0u8; 32]],
        sender,
        receiver,
        500,
        5,
        f.timestamp + 2,
        0,
        2,
        vec![0u8; 64],
        vec![0u8; 64],
    );
    let mut dag = DAG::new();
    for t in [&f, &t1, &t2] {
        dag.inject_transaction_raw((*t).clone());
    }
    crate::json_storage::save_dag_to_json(&dag, &data.join("dag.json"))
        .await
        .expect("write legacy dag.json");
    let ledger_json = format!(
        "{{\"balances\": {{\"{}\": {}, \"{}\": {}}}}}",
        hex::encode(sender),
        8_000u64,
        hex::encode(receiver),
        2_000u64
    );
    std::fs::write(data.join("ledger.json"), ledger_json).unwrap();

    let sled_dir = dir.path().join("sled");
    let storage = open_store_with_retry(&sled_dir);
    assert!(
        storage.needs_migration(&data),
        "fresh DB + legacy JSON => migration needed"
    );

    storage.arm_fault(StorageFault::BatchWrite);
    let res = storage.migrate_from_json(&data).await;
    assert!(
        res.is_err(),
        "the atomic import must abort when its batch write fails"
    );
    assert_eq!(
        storage.transaction_count().unwrap(),
        0,
        "aborted import leaves NOTHING durable (all-or-nothing)"
    );
    assert!(storage.get_all_balances().unwrap().is_empty());
    assert!(storage.get_metadata("migration_complete").is_err());
    assert!(
        storage.needs_migration(&data),
        "still unmigrated => the next boot re-imports from the intact JSON"
    );
    drop(storage);

    // Re-run on a clean reopen: the import completes and is idempotent.
    let storage = open_store_with_retry(&sled_dir);
    storage
        .migrate_from_json(&data)
        .await
        .expect("re-run completes");
    assert_eq!(storage.transaction_count().unwrap(), 3);
    assert_eq!(storage.get_balance(sender).unwrap(), 8_000);
    assert_eq!(storage.get_balance(receiver).unwrap(), 2_000);
    assert!(storage.get_metadata("migration_complete").is_ok());
    assert!(
        !storage.needs_migration(&data),
        "DB non-empty => no further migration"
    );
}
