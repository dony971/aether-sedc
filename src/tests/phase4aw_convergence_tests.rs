//! PHASE 4CP-AW — DAG determinism, transaction conflicts and node
//! convergence, through the REAL acceptance path (`process_transaction` ->
//! persisted mempool tree -> `drain_mempool` -> `TransactionProcessor::
//! process/process_conflict`) and the REAL boot recovery mirror
//! (`boot_av_node`, see phase4av for its fidelity stance).
//!
//! What this module pins (all deterministic, no sleeps and no retries
//! beyond the drainer's own bounded requeue):
//!
//!   aw1  permutations        — the same set of independent txs delivered
//!                              incrementally in three different orders
//!                              converges to byte-equal DAG + ledger
//!                              fingerprints on all nodes, and each node
//!                              restarts from its own durable store to the
//!                              same fingerprint.
//!   aw2  orphan ordering     — child-before-parent parks as an orphan and
//!                              heals when the parent arrives (rescue loop),
//!                              converging to the exact state of a node that
//!                              received parent-first.
//!   aw3  duplicates          — a tx re-delivered from multiple sources and
//!                              after inclusion is refused at the funnel
//!                              (in-queue and DAG dedup) and applies exactly
//!                              once; restart keeps it applied once.
//!   aw4  conflict flip       — a conflicting pair delivered in opposite
//!                              orders: one node applies the incumbent and
//!                              retains the late loser, the other applies the
//!                              late arrival and the flip rebuilds to the
//!                              same canonical winner (min-id pre-activation,
//!                              resolve_conflict_key). Same DAG + ledger
//!                              fingerprints; boot heals the durable applied
//!                              marks (see the pre-restart asymmetry note).
//!   aw5  cumulative overspend— two non-conflicting txs whose sum exceeds the
//!                              balance: the canonical drain order (fee DESC,
//!                              id ASC) applies exactly one, deterministically
//!                              on both nodes regardless of submission order;
//!                              the other stays queued (TTL-bounded) and is
//!                              never inserted into the DAG or the store.
//!   aw6  loser descendants   — a child of a RETAINED conflict loser still
//!                              applies on the live path and after a boot
//!                              rebuild (retention handles parents without
//!                              granting the loser any economic effect).
//!
//! Consensus honesty: these prove order-independence of the CURRENT contract
//! (canonical conflict resolution + pure-function rebuild). They do NOT prove
//! BFT-style convergence for arbitrary delivery sets: the tested guarantee is
//! "same transaction set => same canonical state", plus restart stability.

use super::phase4av_recovery_tests::{boot_av_node, faucet_bytes, AvNode};
use crate::genesis::{FAUCET_ADDRESS, GENESIS_LEDGER};
use crate::ledger::Ledger;
use crate::parent_selection::DAG;
use crate::transaction::Transaction;
use crate::validation::ValidationMode;
use crate::wallet::Wallet;
use tempfile::tempdir;

const FUND_AMOUNT: u64 = 100_000;
const TX_FEE: u64 = 10;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("fixed test key")
}

fn addr(prefix: u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = prefix;
    a
}

fn pre_migration_ts(offset: u64) -> u64 {
    Transaction::DIFFICULTY_MIGRATION_TS - 3_600_000 + offset
}

fn genesis_total() -> u64 {
    GENESIS_LEDGER.iter().map(|(_, b)| *b).sum()
}

/// Genesis-era funding tx (raw, zero signature), identical to the av
/// pattern: the rebuild replays it without crypto checks, so the funded
/// balance is DAG-backed and byte-stable across boots on every node.
fn funding_tx_amount(sender: [u8; 32], amount: u64) -> Transaction {
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        faucet_bytes(),
        sender,
        amount,
        0,
        Transaction::DIFFICULTY_MIGRATION_TS - 7_200_000,
        0,
        0,
        vec![0u8; 64],
        vec![0u8; 64],
    );
    tx.id = tx.compute_hash();
    // Raw injection bypasses the DAG weight bookkeeping
    // (add_transaction_validated sets weight = 1.0 + ancestors); the boot
    // rebuild always recomputes 1.0 for it (no parents), so the live world
    // must carry the same value or live != rebuilt fingerprints (harness).
    tx.weight = 1.0;
    tx
}

/// DAG-backed funding, accumulating the faucet debit across calls so the
/// memory ledger, the durable store and the DAG-derived world stay equal
/// for any number of funded wallets.
async fn fund_sender_amount(node: &AvNode, sender: [u8; 32], amount: u64) -> Transaction {
    let fund_tx = funding_tx_amount(sender, amount);
    let (faucet_hex, _genesis) = GENESIS_LEDGER
        .iter()
        .find(|(a, _)| *a == FAUCET_ADDRESS)
        .expect("faucet in genesis ledger");
    let faucet_addr: [u8; 32] = hex::decode(faucet_hex)
        .expect("faucet hex")
        .try_into()
        .expect("32B");

    {
        let storage = node.storage.read().await;
        storage
            .put_transaction(&fund_tx)
            .expect("persist funding tx");
        storage.flush().expect("flush funding tx");
    }
    node.dag
        .write()
        .await
        .inject_transaction_raw(fund_tx.clone());
    {
        let mut ledger = node.ledger.write().await;
        let faucet_now = ledger.get_balance(&faucet_addr);
        ledger.set_balance(&faucet_addr, faucet_now - amount);
        ledger.set_balance(&sender, amount);
        // The funding transfer IS economically applied, and every
        // rebuild_from_dag (flip rebuild or boot derived ledger) re-marks it
        // applied with its transfer replayed; the live world must carry the
        // same positive evidence or live != rebuilt fingerprints (harness).
        ledger.mark_applied(&fund_tx.id);
        ledger.save_dirty().await.expect("persist funding state");
    }
    node.storage
        .read()
        .await
        .flush()
        .expect("flush funding state");
    fund_tx
}

/// Real tx: fixed pre-migration timestamp (Historical mode, the production
/// DAG-entry mode for sync/re-arrival), real 20-bit PoW, real signature.
/// Deterministic mining: `mine_nonce` scans from 0, so the same inputs
/// produce byte-identical txs on every node.
#[allow(clippy::too_many_arguments)]
fn build_tx(
    wallet: &Wallet,
    parents: [[u8; 32]; 2],
    receiver: [u8; 32],
    amount: u64,
    fee: u64,
    account_nonce: u64,
    ts_offset: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        wallet.address(),
        receiver,
        amount,
        fee,
        pre_migration_ts(ts_offset),
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

async fn accept_ok(node: &AvNode, tx: &Transaction) {
    node.rpc
        .process_transaction(tx.clone(), "AW-Test", ValidationMode::Historical)
        .await
        .expect("accept must succeed");
}

async fn accept_err(node: &AvNode, tx: &Transaction) -> String {
    let res = node
        .rpc
        .process_transaction(tx.clone(), "AW-Test", ValidationMode::Historical)
        .await;
    format!("{res:?}")
}

async fn drain_cycles(node: &AvNode, cycles: usize) {
    for _ in 0..cycles {
        node.rpc.drain_mempool().await;
    }
}

/// Semantic DAG fingerprint: id set + parent multiset + weights + frontier.
/// Weights are integer-valued f64 counters (subtree sizes), so `to_bits` is
/// exact; including them pins that the live incremental maintenance and the
/// boot rebuild agree.
fn dag_fingerprint(dag: &DAG) -> String {
    let mut items: Vec<String> = dag
        .transactions()
        .iter()
        .map(|(id, tx)| {
            let mut parents: Vec<String> =
                tx.parents.iter().map(|p| hex::encode(&p[..4])).collect();
            parents.sort();
            format!(
                "{}|{}|{}",
                hex::encode(&id[..8]),
                parents.join(","),
                tx.weight.to_bits()
            )
        })
        .collect();
    items.sort();
    let mut tips: Vec<String> = dag
        .transactions()
        .keys()
        .filter(|id| !dag.children().contains_key(*id))
        .map(|id| hex::encode(&id[..8]))
        .collect();
    tips.sort();
    format!(
        "n={} tips=[{}] {{{}}}",
        items.len(),
        tips.join(","),
        items.join("; ")
    )
}

/// Semantic ledger fingerprint: full balances + nonces + applied set +
/// supply + burned fees, all canonically sorted (no HashMap order).
fn ledger_fingerprint(ledger: &Ledger) -> String {
    let mut balances: Vec<(String, u64)> = ledger
        .balances
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    balances.sort();
    let mut nonces: Vec<(String, u64)> =
        ledger.nonces.iter().map(|(k, v)| (k.clone(), *v)).collect();
    nonces.sort();
    let mut applied: Vec<String> = ledger
        .applied
        .iter()
        .map(|id| hex::encode(&id[..8]))
        .collect();
    applied.sort();
    format!(
        "supply={} burned={} balances={:?} nonces={:?} applied=[{}]",
        ledger.total_supply(),
        ledger.total_fees_burned,
        balances,
        nonces,
        applied.join(",")
    )
}

fn hex_balances(map: &std::collections::HashMap<[u8; 32], u64>) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = map
        .iter()
        .map(|(a, b)| (hex::encode(&a[..4]), *b))
        .collect();
    v.sort();
    v
}

/// Durable-store fingerprint (rows, balances, nonces, applied marks).
async fn durable_fingerprint(node: &AvNode) -> String {
    let storage = node.storage.read().await;
    let mut txs: Vec<String> = storage
        .get_all_transactions()
        .expect("read txs")
        .iter()
        .map(|t| hex::encode(&t.id[..8]))
        .collect();
    txs.sort();
    let balances = hex_balances(&storage.get_all_balances().expect("balances"));
    let nonces = hex_balances(&storage.get_all_nonces().expect("nonces"));
    let mut applied: Vec<String> = storage
        .get_all_applied()
        .expect("applied set")
        .into_iter()
        .map(|id| hex::encode(&id[..8]))
        .collect();
    applied.sort();
    format!(
        "txs=[{}] balances={:?} nonces={:?} applied=[{}]",
        txs.join(","),
        balances,
        nonces,
        applied.join(",")
    )
}

async fn node_dag_fp(node: &AvNode) -> String {
    let dag = node.dag.read().await;
    dag_fingerprint(&dag)
}

async fn node_ledger_fp(node: &AvNode) -> String {
    let ledger = node.ledger.read().await;
    ledger_fingerprint(&ledger)
}

/// aw1 — same independent-tx set, three different incremental orders (one
/// submit + drain per step), three nodes: DAG, ledger and durable store must
/// converge to identical fingerprints, and each node's restart must
/// reproduce its own live fingerprint from persisted data alone.
#[tokio::test]
async fn aw1_arrival_order_permutations_converge_and_restart_stable() {
    let dirs: Vec<_> = (0..3).map(|_| tempdir().unwrap()).collect();
    let mut nodes = Vec::new();
    for d in &dirs {
        nodes.push(boot_av_node(d.path()).await);
    }
    let wallet = wallet_n(0xA1);
    for node in &nodes {
        fund_sender_amount(node, wallet.address(), FUND_AMOUNT).await;
    }

    // 4 independent txs: distinct nonces, receivers, amounts (all fundable).
    let txs: Vec<Transaction> = (0..4u64)
        .map(|i| {
            build_tx(
                &wallet,
                [[0u8; 32]; 2],
                addr(0x21 + i as u8),
                100 * (i + 1),
                TX_FEE,
                1 + i,
                1_000 * (i + 1),
            )
        })
        .collect();

    let orders: [&[usize]; 3] = [&[0, 1, 2, 3], &[3, 2, 1, 0], &[1, 3, 0, 2]];
    for (node, order) in nodes.iter().zip(orders.iter()) {
        for &i in *order {
            accept_ok(node, &txs[i]).await;
            drain_cycles(node, 2).await;
        }
    }

    // Semantic convergence across arrival orders.
    let dag_fps: Vec<String> = {
        let mut v = Vec::new();
        for node in &nodes {
            v.push(node_dag_fp(node).await);
        }
        v
    };
    let ledger_fps: Vec<String> = {
        let mut v = Vec::new();
        for node in &nodes {
            v.push(node_ledger_fp(node).await);
        }
        v
    };
    for i in 1..3 {
        assert_eq!(dag_fps[0], dag_fps[i], "aw1: DAG fingerprints diverge");
        assert_eq!(
            ledger_fps[0], ledger_fps[i],
            "aw1: ledger fingerprints diverge"
        );
    }
    assert!(dag_fps[0].starts_with("n=5 "), "funding + 4 txs");
    // Explicit economics: one debit per tx, fees burned, supply conserved.
    {
        let ledger = nodes[0].ledger.read().await;
        assert_eq!(
            ledger.get_balance(&wallet.address()),
            FUND_AMOUNT - (100 + 200 + 300 + 400) - 4 * TX_FEE
        );
        assert_eq!(ledger.get_balance(&addr(0x21)), 100);
        assert_eq!(ledger.get_balance(&addr(0x24)), 400);
        assert_eq!(ledger.total_fees_burned, 4 * TX_FEE);
        assert_eq!(ledger.total_supply(), genesis_total() - 4 * TX_FEE);
    }
    let durable_fps: Vec<String> = {
        let mut v = Vec::new();
        for node in &nodes {
            v.push(durable_fingerprint(node).await);
        }
        v
    };
    assert_eq!(durable_fps[0], durable_fps[1]);
    assert_eq!(durable_fps[0], durable_fps[2]);

    // Restart each node from its own store: live == rebuilt.
    drop(nodes);
    for (i, d) in dirs.iter().enumerate() {
        let node = boot_av_node(d.path()).await;
        assert_eq!(node_dag_fp(&node).await, dag_fps[i], "restart DAG fp");
        assert_eq!(
            node_ledger_fp(&node).await,
            ledger_fps[i],
            "restart ledger fp"
        );
        assert_eq!(
            durable_fingerprint(&node).await,
            durable_fps[i],
            "restart durable fp"
        );
    }
}

/// aw2 — dependency ordering: a child delivered BEFORE its parent parks as
/// an orphan (never inserted without ancestry), then heals when the parent
/// arrives; the final state is identical to a node that received
/// parent-first, including after both restart.
#[tokio::test]
async fn aw2_child_before_parent_orphan_path_converges_with_parent_first() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let n1 = boot_av_node(dir_a.path()).await;
    let n2 = boot_av_node(dir_b.path()).await;
    let wallet = wallet_n(0xA2);
    for node in [&n1, &n2] {
        fund_sender_amount(node, wallet.address(), FUND_AMOUNT).await;
    }

    let parent = build_tx(&wallet, [[0u8; 32]; 2], addr(0x31), 500, TX_FEE, 1, 1_000);
    let child = build_tx(
        &wallet,
        [parent.id, [0u8; 32]],
        addr(0x32),
        200,
        TX_FEE,
        2,
        2_000,
    );

    // n1: parent first, child second (plain normal path).
    accept_ok(&n1, &parent).await;
    drain_cycles(&n1, 2).await;
    accept_ok(&n1, &child).await;
    drain_cycles(&n1, 2).await;

    // n2: child first -> orphan parking (accepted, queued, no DAG insert).
    accept_ok(&n2, &child).await;
    drain_cycles(&n2, 2).await;
    assert_eq!(
        n2.mempool.read().await.size(),
        0,
        "the orphan left the queue (parked)"
    );
    assert!(
        !n2.dag.read().await.transactions().contains_key(&child.id),
        "an orphan must never be inserted without its ancestry"
    );
    {
        let storage = n2.storage.read().await;
        let orphans = storage.get_all_orphans().expect("read orphans");
        assert_eq!(orphans.len(), 1, "child persisted as orphan");
        assert_eq!(orphans[0].id, child.id);
    }

    // Parent arrives: applied; the drainer's rescue loop re-accepts the
    // parked child, which is then drained through the normal path.
    accept_ok(&n2, &parent).await;
    drain_cycles(&n2, 4).await;
    assert!(
        n2.dag.read().await.transactions().contains_key(&child.id),
        "rescued orphan must reach the DAG"
    );
    assert!(
        n2.storage
            .read()
            .await
            .get_all_orphans()
            .unwrap()
            .is_empty(),
        "resolved orphan removed from the orphan store"
    );

    // Convergence + explicit economics (500 + 200 out, 2 fees burned).
    let dag_fp = node_dag_fp(&n1).await;
    assert_eq!(dag_fp, node_dag_fp(&n2).await, "aw2 DAG convergence");
    let ledger_fp = node_ledger_fp(&n1).await;
    assert_eq!(
        ledger_fp,
        node_ledger_fp(&n2).await,
        "aw2 ledger convergence"
    );
    for node in [&n1, &n2] {
        let ledger = node.ledger.read().await;
        assert!(ledger.is_applied(&parent.id) && ledger.is_applied(&child.id));
        assert_eq!(
            ledger.get_balance(&wallet.address()),
            FUND_AMOUNT - 700 - 20
        );
        assert_eq!(ledger.get_balance(&addr(0x31)), 500);
        assert_eq!(ledger.get_balance(&addr(0x32)), 200);
        assert_eq!(ledger.total_supply(), genesis_total() - 20);
    }

    // Restart both: rebuilt state must equal the live state exactly.
    drop((n1, n2));
    for d in [&dir_a, &dir_b] {
        let node = boot_av_node(d.path()).await;
        assert_eq!(node_dag_fp(&node).await, dag_fp, "aw2 restart DAG fp");
        assert_eq!(
            node_ledger_fp(&node).await,
            ledger_fp,
            "aw2 restart ledger fp"
        );
    }
}

/// aw3 — duplicates: the same tx re-submitted while queued, after inclusion,
/// and "from a second peer" (same funnel, identical bytes) is refused every
/// time past the first; it applies exactly once and restart keeps it so.
#[tokio::test]
async fn aw3_duplicates_from_multiple_sources_apply_once() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let wallet = wallet_n(0xA3);
    fund_sender_amount(&node, wallet.address(), FUND_AMOUNT).await;
    let tx = build_tx(&wallet, [[0u8; 32]; 2], addr(0x41), 300, TX_FEE, 1, 1_000);

    accept_ok(&node, &tx).await;
    let dup_queued = accept_err(&node, &tx).await;
    assert!(
        dup_queued.contains("Duplicate transaction"),
        "re-delivery while queued must be refused at enqueue: {dup_queued}"
    );
    drain_cycles(&node, 2).await;

    let dup_dag = accept_err(&node, &tx).await;
    assert!(
        dup_dag.contains("Duplicate transaction"),
        "re-delivery after inclusion must be refused by DAG dedup: {dup_dag}"
    );
    let dup_peer = accept_err(&node, &tx).await; // second peer, identical bytes
    assert!(
        dup_peer.contains("Duplicate transaction"),
        "multi-peer re-delivery must be refused: {dup_peer}"
    );
    drain_cycles(&node, 3).await;

    {
        let ledger = node.ledger.read().await;
        assert!(ledger.is_applied(&tx.id));
        assert_eq!(
            ledger.get_balance(&wallet.address()),
            FUND_AMOUNT - 300 - TX_FEE
        );
        assert_eq!(ledger.get_balance(&addr(0x41)), 300);
        assert_eq!(ledger.total_fees_burned, TX_FEE, "one fee, not four");
    }
    assert_eq!(node.mempool.read().await.size(), 0, "queue empty");
    let stats = node.rpc.mempool_stats().await;
    assert_eq!(stats.included, 1, "exactly one inclusion");
    assert!(stats.duplicate >= 3, "three duplicates logged: {stats:?}");

    let live_ledger_fp = node_ledger_fp(&node).await;
    drop(node);
    let node = boot_av_node(dir.path()).await;
    assert_eq!(node_ledger_fp(&node).await, live_ledger_fp);
    {
        let ledger = node.ledger.read().await;
        assert_eq!(
            ledger.get_balance(&wallet.address()),
            FUND_AMOUNT - 300 - TX_FEE
        );
        assert_eq!(
            ledger.total_fees_burned, TX_FEE,
            "restart must not re-apply"
        );
    }
    let dup_after = accept_err(&node, &tx).await;
    assert!(dup_after.contains("Duplicate transaction"));
}

/// aw4 — conflicting pair, opposite delivery orders. Canonical resolution
/// (pre-activation: min-id, `resolve_conflict_key`) must crown the same
/// winner whether it was the incumbent (no flip) or the late arrival (flip
/// via rebuild). Losers are RETAINED in the DAG but never economical; boot
/// reproduces the same winner and heals the durable applied marks.
#[tokio::test]
async fn aw4_conflicting_pair_opposite_orders_converge_once_and_survive_restart() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let n1 = boot_av_node(dir_a.path()).await;
    let n2 = boot_av_node(dir_b.path()).await;
    let wallet = wallet_n(0xA4);
    for node in [&n1, &n2] {
        fund_sender_amount(node, wallet.address(), FUND_AMOUNT).await;
    }

    // Same sender, same account_nonce, different receiver/amount: a real
    // double-spend attempt under the (sender, account_nonce) uniqueness rule.
    let cand1 = build_tx(&wallet, [[0u8; 32]; 2], addr(0x51), 700, TX_FEE, 1, 1_000);
    let cand2 = build_tx(&wallet, [[0u8; 32]; 2], addr(0x52), 300, TX_FEE, 1, 1_000);
    let (low, high) = if cand1.id < cand2.id {
        (&cand1, &cand2)
    } else {
        (&cand2, &cand1)
    };

    // n1: incumbent winner first (low), late loser second (high, no flip).
    accept_ok(&n1, low).await;
    drain_cycles(&n1, 2).await;
    accept_ok(&n1, high).await;
    drain_cycles(&n1, 2).await;

    // n2: incumbent is the eventual loser (high), late arrival flips (low).
    accept_ok(&n2, high).await;
    drain_cycles(&n2, 2).await;
    assert!(
        n2.ledger.read().await.is_applied(&high.id),
        "precondition: the incumbent was really applied before the flip"
    );
    accept_ok(&n2, low).await;
    drain_cycles(&n2, 3).await;

    for (name, node) in [("n1", &n1), ("n2", &n2)] {
        let ledger = node.ledger.read().await;
        assert!(
            ledger.is_applied(&low.id),
            "{name}: canonical winner (min-id) must be applied"
        );
        assert!(
            !ledger.is_applied(&high.id),
            "{name}: the loser must never be applied"
        );
        assert_eq!(
            ledger.get_balance(&low.receiver),
            low.amount,
            "{name}: only the winner's receiver is credited"
        );
        assert_eq!(
            ledger.get_balance(&high.receiver),
            0,
            "{name}: the loser transfers nothing"
        );
        assert_eq!(
            ledger.get_balance(&wallet.address()),
            FUND_AMOUNT - low.amount - low.fee,
            "{name}: exactly one debit"
        );
        assert_eq!(ledger.total_fees_burned, low.fee, "{name}: exactly one fee");
        assert_eq!(
            ledger.get_nonce(&wallet.address()),
            1,
            "{name}: nonce max-committed once"
        );
        drop(ledger);
        let dag = node.dag.read().await;
        assert!(
            dag.transactions().contains_key(&low.id) && dag.transactions().contains_key(&high.id),
            "{name}: BOTH members are retained in the DAG"
        );
    }

    let dag_fp = node_dag_fp(&n1).await;
    assert_eq!(dag_fp, node_dag_fp(&n2).await, "aw4 DAG convergence");
    let live_ledger_fp = node_ledger_fp(&n1).await;
    assert_eq!(
        live_ledger_fp,
        node_ledger_fp(&n2).await,
        "aw4 live ledger convergence"
    );

    // Documented transient asymmetry: n2's flip rebuilt memory to the
    // winner-world, but the flipped-out incumbent's OLD durable applied mark
    // is not queued for removal (apply_rebuild rebuilds the added-set and
    // clears the removed-set), so it survives until the next authoritative
    // save. It is non-economic: rule #3 evidence for a rotated-out member is
    // row-based too, and the boot save() reconciles the marker set. n1 never
    // wrote a mark for its never-applied loser.
    {
        let s = n2.storage.read().await;
        assert!(s.is_applied(low.id).unwrap(), "n2: winner mark durable");
        assert!(
            s.is_applied(high.id).unwrap(),
            "n2: stale incumbent mark survives the flip until boot (documented)"
        );
    }
    {
        let s = n1.storage.read().await;
        assert!(s.is_applied(low.id).unwrap());
        assert!(
            !s.is_applied(high.id).unwrap(),
            "n1: no durable mark for a never-applied loser"
        );
    }

    // Boot: canonical winner reproduced, durable marker sets healed equal.
    drop((n1, n2));
    for d in [&dir_a, &dir_b] {
        let node = boot_av_node(d.path()).await;
        assert_eq!(node_dag_fp(&node).await, dag_fp, "aw4 restart DAG fp");
        assert_eq!(
            node_ledger_fp(&node).await,
            live_ledger_fp,
            "aw4 restart ledger fp"
        );
        let s = node.storage.read().await;
        assert!(s.is_applied(low.id).unwrap(), "boot keeps the winner mark");
        assert!(
            !s.is_applied(high.id).unwrap(),
            "boot removes the stale incumbent mark"
        );
        drop(s);
        // Re-arrival of BOTH members after restart: already in the DAG.
        let dup_low = accept_err(&node, low).await;
        let dup_high = accept_err(&node, high).await;
        assert!(dup_low.contains("Duplicate transaction"));
        assert!(dup_high.contains("Duplicate transaction"));
    }
}

/// aw5 — cumulative overspend without a conflict: two non-conflicting txs
/// (distinct account_nonces) whose sum exceeds the balance. The canonical
/// drain order (fee DESC, id ASC) makes the outcome deterministic: exactly
/// one applies, identically on both nodes and regardless of submission
/// order. The other stays queued (bounded transient requeue) and was never
/// mutated into the DAG or the store. Restart keeps both properties.
#[tokio::test]
async fn aw5_cumulative_overspend_is_deterministic_and_restart_stable() {
    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();
    let n1 = boot_av_node(dir_a.path()).await;
    let n2 = boot_av_node(dir_b.path()).await;
    let wallet = wallet_n(0xA5);
    for node in [&n1, &n2] {
        fund_sender_amount(node, wallet.address(), 10_000).await;
    }

    let a = build_tx(&wallet, [[0u8; 32]; 2], addr(0x61), 6_000, TX_FEE, 1, 1_000);
    let b = build_tx(&wallet, [[0u8; 32]; 2], addr(0x62), 6_000, TX_FEE, 2, 2_000);
    // Equal fees => drain order is id ASC: `first` is the deterministic one.
    let (first, second) = if a.id < b.id { (&a, &b) } else { (&b, &a) };

    // Opposite submission orders; the drainer's canonical select decides.
    accept_ok(&n1, &a).await;
    accept_ok(&n1, &b).await;
    drain_cycles(&n1, 3).await;
    accept_ok(&n2, &b).await;
    accept_ok(&n2, &a).await;
    drain_cycles(&n2, 3).await;

    for (name, node) in [("n1", &n1), ("n2", &n2)] {
        let ledger = node.ledger.read().await;
        assert!(
            ledger.is_applied(&first.id),
            "{name}: the canonical first (fee DESC, id ASC) must apply"
        );
        assert!(
            !ledger.is_applied(&second.id),
            "{name}: the unfundable second must not apply"
        );
        assert_eq!(
            ledger.get_balance(&wallet.address()),
            10_000 - first.amount - first.fee,
            "{name}: exactly one debit"
        );
        assert_eq!(ledger.get_balance(&first.receiver), first.amount);
        assert_eq!(ledger.get_balance(&second.receiver), 0);
        assert_eq!(ledger.total_fees_burned, first.fee);
        drop(ledger);
        assert_eq!(
            node.mempool.read().await.size(),
            1,
            "{name}: the unfundable tx stays queued (TTL-bounded requeue)"
        );
        assert!(
            !node
                .dag
                .read()
                .await
                .transactions()
                .contains_key(&second.id),
            "{name}: an insufficient-balance failure precedes any DAG insert"
        );
        assert!(
            !node
                .storage
                .read()
                .await
                .transaction_exists(second.id)
                .unwrap(),
            "{name}: no durable row for the never-admitted tx"
        );
    }

    let dag_fp = node_dag_fp(&n1).await;
    assert_eq!(dag_fp, node_dag_fp(&n2).await, "aw5 DAG convergence");
    let live_ledger_fp = node_ledger_fp(&n1).await;
    assert_eq!(
        live_ledger_fp,
        node_ledger_fp(&n2).await,
        "aw5 ledger convergence"
    );

    // Restart: the pending tx is reloaded from the persisted mempool tree;
    // the applied world is unchanged and draining again applies nothing new.
    drop((n1, n2));
    for d in [&dir_a, &dir_b] {
        let node = boot_av_node(d.path()).await;
        assert_eq!(node_dag_fp(&node).await, dag_fp, "aw5 restart DAG fp");
        assert_eq!(
            node_ledger_fp(&node).await,
            live_ledger_fp,
            "aw5 restart ledger fp"
        );
        assert_eq!(node.mempool.read().await.size(), 1, "pending tx reloaded");
        drain_cycles(&node, 2).await;
        assert_eq!(
            node_ledger_fp(&node).await,
            live_ledger_fp,
            "aw5: retry after restart must not apply anything new"
        );
    }
}

/// aw6 — a child of a RETAINED conflict loser: the loser never produces
/// economic effects, but it still counts as a satisfied parent for its
/// descendants. The child (funded from a different wallet) applies on the
/// live path, and the boot rebuild must reproduce that exactly (residue
/// skipping marks the loser "handled" without transferring).
#[tokio::test]
async fn aw6_children_of_retained_loser_still_apply_live_and_after_restart() {
    let dir = tempdir().unwrap();
    let node = boot_av_node(dir.path()).await;
    let attacker = wallet_n(0xA6);
    let spender = wallet_n(0xB6);
    fund_sender_amount(&node, attacker.address(), 10_000).await;
    fund_sender_amount(&node, spender.address(), 10_000).await;

    let cand1 = build_tx(&attacker, [[0u8; 32]; 2], addr(0x71), 400, TX_FEE, 1, 1_000);
    let cand2 = build_tx(&attacker, [[0u8; 32]; 2], addr(0x72), 600, TX_FEE, 1, 1_000);
    let (winner, loser) = if cand1.id < cand2.id {
        (&cand1, &cand2)
    } else {
        (&cand2, &cand1)
    };

    accept_ok(&node, winner).await;
    drain_cycles(&node, 2).await;
    accept_ok(&node, loser).await;
    drain_cycles(&node, 2).await;
    assert!(
        !node.ledger.read().await.is_applied(&loser.id),
        "precondition: the loser is residue, never applied"
    );

    // Child of the loser, signed and funded by a different wallet.
    let child = build_tx(
        &spender,
        [loser.id, [0u8; 32]],
        addr(0x73),
        150,
        TX_FEE,
        1,
        3_000,
    );
    accept_ok(&node, &child).await;
    drain_cycles(&node, 2).await;

    {
        let ledger = node.ledger.read().await;
        assert!(
            ledger.is_applied(&child.id),
            "the child of a retained loser applies through the normal path"
        );
        assert_eq!(ledger.get_balance(&addr(0x73)), 150);
        assert_eq!(
            ledger.get_balance(&spender.address()),
            10_000 - 150 - TX_FEE
        );
        assert_eq!(
            ledger.get_balance(&attacker.address()),
            10_000 - winner.amount - winner.fee,
            "the loser's own economics stay absent"
        );
        assert_eq!(ledger.get_balance(&loser.receiver), 0);
        assert_eq!(ledger.total_fees_burned, winner.fee + TX_FEE);
    }
    let live_dag_fp = node_dag_fp(&node).await;
    let live_ledger_fp = node_ledger_fp(&node).await;

    // Restart: the rebuild must treat the residue as handled (parents-ready)
    // without transferring its amount, and re-apply the child identically.
    drop(node);
    let node = boot_av_node(dir.path()).await;
    assert_eq!(node_dag_fp(&node).await, live_dag_fp, "aw6 restart DAG fp");
    assert_eq!(
        node_ledger_fp(&node).await,
        live_ledger_fp,
        "aw6 restart ledger fp"
    );
    {
        let ledger = node.ledger.read().await;
        assert!(ledger.is_applied(&child.id));
        assert!(!ledger.is_applied(&loser.id));
        assert_eq!(ledger.get_balance(&addr(0x73)), 150);
    }
}
