//! Crash recovery, double-spend protocol audit, and balance conservation tests.
//!
//! Uses `inject_transaction_raw` to bypass signature/nonce validation and test
//! the ledger's canonical double-spend resolution and balance invariant directly.

use crate::genesis::FAUCET_ADDRESS;
use crate::parent_selection::DAG;
use crate::transaction::{Address, Transaction, TransactionId};

/// Faucet address as bytes.
fn faucet() -> Address {
    let bytes = hex::decode(FAUCET_ADDRESS).unwrap();
    bytes.try_into().unwrap()
}

/// Genesis total supply.
fn genesis_total() -> u64 {
    crate::genesis::GENESIS_LEDGER
        .iter()
        .map(|(_, bal)| *bal)
        .sum()
}

/// Simple address from byte prefix.
fn addr(n: u8) -> Address {
    let mut a = [0u8; 32];
    a[0] = n;
    a
}

/// Genesis tx (parents [0,0]) funding `receiver` from faucet.
fn fund_tx(receiver: Address, amount: u64, fee: u64, nonce: u64) -> Transaction {
    Transaction::new(
        [[0u8; 32]; 2],
        faucet(),
        receiver,
        amount,
        fee,
        1000 + nonce,
        0,
        nonce,
        vec![0u8; 64],
        vec![0u8; 64],
    )
}

/// Transfer tx from `sender` to `receiver`.
fn transfer_tx(
    parents: [TransactionId; 2],
    sender: Address,
    receiver: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
) -> Transaction {
    Transaction::new(
        parents,
        sender,
        receiver,
        amount,
        fee,
        2000 + nonce,
        0,
        nonce,
        vec![0u8; 64],
        vec![0u8; 64],
    )
}

/// Rebuild ledger from DAG and verify supply invariant.
fn rebuild(dag: &DAG) -> crate::ledger::Ledger {
    let mut ledger = crate::ledger::Ledger::new();
    ledger.rebuild_from_dag(dag);
    assert!(
        ledger.total_supply() <= genesis_total(),
        "supply {} > genesis {}",
        ledger.total_supply(),
        genesis_total()
    );
    ledger
}

// ============================================================================
// DOUBLE-SPEND PROTOCOL AUDIT
// ============================================================================

/// Test A: Two txs spending the same UTXO (same sender, same nonce).
/// Canonical rule: smallest id wins.
#[test]
fn test_double_spend_same_utxo() {
    let mut dag = DAG::new();
    let w = addr(0x11);
    let r1 = addr(0x22);
    let r2 = addr(0x33);

    // Fund w from faucet
    let fund = fund_tx(w, 10_000, 0, 0);
    dag.inject_transaction_raw(fund.clone());

    // Two conflicting txs: w -> r1 and w -> r2, same nonce
    let tx1 = transfer_tx([fund.id, [0u8; 32]], w, r1, 5000, 1, 1);
    let tx2 = transfer_tx([fund.id, [0u8; 32]], w, r2, 5000, 1, 1);

    let (winner, loser) = if tx1.id < tx2.id {
        (&tx1, &tx2)
    } else {
        (&tx2, &tx1)
    };

    dag.inject_transaction_raw(tx1.clone());
    dag.inject_transaction_raw(tx2.clone());

    let ledger = rebuild(&dag);

    // Only the canonical winner (smallest id) applies
    assert_eq!(ledger.get_balance(&winner.receiver), winner.amount);
    assert_eq!(ledger.get_balance(&loser.receiver), 0);

    println!(
        "Double-spend UTXO: winner={}, loser={}, total_supply={}",
        hex::encode(&winner.id[..8]),
        hex::encode(&loser.id[..8]),
        ledger.total_supply()
    );
}

/// Test B: Two concurrent txs in two partitions, then reconnection.
#[test]
fn test_double_spend_partition_reconnect() {
    // Partition A
    let mut dag_a = DAG::new();
    let w = addr(0x11);
    let r1 = addr(0x22);
    let r2 = addr(0x33);

    let fund_a = fund_tx(w, 10_000, 0, 0);
    dag_a.inject_transaction_raw(fund_a.clone());
    let tx1 = transfer_tx([fund_a.id, [0u8; 32]], w, r1, 5000, 1, 1);
    dag_a.inject_transaction_raw(tx1.clone());

    // Partition B (same sender, same nonce, different receiver)
    let mut dag_b = DAG::new();
    let fund_b = fund_tx(w, 10_000, 0, 0);
    dag_b.inject_transaction_raw(fund_b.clone());
    let tx2 = transfer_tx([fund_b.id, [0u8; 32]], w, r2, 5000, 1, 1);
    dag_b.inject_transaction_raw(tx2.clone());

    // Reconnect: merge all txs into one DAG
    let mut merged = DAG::new();
    for tx in dag_a.transactions().values() {
        merged.inject_transaction_raw(tx.clone());
    }
    for tx in dag_b.transactions().values() {
        merged.inject_transaction_raw(tx.clone());
    }

    let ledger = rebuild(&merged);

    // Only the canonical winner applies
    let (winner, loser) = if tx1.id < tx2.id {
        (&tx1, &tx2)
    } else {
        (&tx2, &tx1)
    };
    assert_eq!(ledger.get_balance(&winner.receiver), winner.amount);
    assert_eq!(ledger.get_balance(&loser.receiver), 0);

    // Conservation: total <= genesis
    assert!(ledger.total_supply() <= genesis_total());
    println!(
        "Partition reconnect: winner={}, total={}",
        hex::encode(&winner.id[..8]),
        ledger.total_supply()
    );
}

/// Test C: Double spend with fork (two txs from same parent).
#[test]
fn test_double_spend_fork() {
    let mut dag = DAG::new();
    let w = addr(0x11);
    let r1 = addr(0x22);
    let r2 = addr(0x33);

    let fund = fund_tx(w, 10_000, 0, 0);
    dag.inject_transaction_raw(fund.clone());

    // Two txs from same parent, same sender, same nonce
    let tx1 = transfer_tx([fund.id, [0u8; 32]], w, r1, 3000, 1, 1);
    let tx2 = transfer_tx([fund.id, [0u8; 32]], w, r2, 3000, 1, 1);

    dag.inject_transaction_raw(tx1.clone());
    dag.inject_transaction_raw(tx2.clone());

    let ledger = rebuild(&dag);

    let (winner, loser) = if tx1.id < tx2.id {
        (&tx1, &tx2)
    } else {
        (&tx2, &tx1)
    };
    assert_eq!(ledger.get_balance(&winner.receiver), winner.amount);
    assert_eq!(ledger.get_balance(&loser.receiver), 0);
    assert!(ledger.total_supply() <= genesis_total());
}

/// Test D: Double spend with child chain — loser's subtree must be pruned from ledger effects.
#[test]
fn test_double_spend_two_wallets() {
    let mut dag = DAG::new();
    let w = addr(0x11);
    let r1 = addr(0x22);
    let r2 = addr(0x33);
    let r3 = addr(0x44); // child of loser

    let fund = fund_tx(w, 10_000, 0, 0);
    dag.inject_transaction_raw(fund.clone());

    let tx1 = transfer_tx([fund.id, [0u8; 32]], w, r1, 5000, 1, 1);
    let tx2 = transfer_tx([fund.id, [0u8; 32]], w, r2, 5000, 1, 1);

    dag.inject_transaction_raw(tx1.clone());
    dag.inject_transaction_raw(tx2.clone());

    // Child of loser
    let loser = if tx1.id < tx2.id { &tx2 } else { &tx1 };
    let child = transfer_tx([loser.id, [0u8; 32]], r2, r3, 100, 1, 0);
    dag.inject_transaction_raw(child.clone());

    let ledger = rebuild(&dag);

    let winner = if tx1.id < tx2.id { &tx1 } else { &tx2 };
    assert_eq!(ledger.get_balance(&winner.receiver), winner.amount);
    // Loser's child: r2 has 0 balance (loser didn't apply), so child also can't apply
    assert_eq!(ledger.get_balance(&r3), 0);
    assert!(ledger.total_supply() <= genesis_total());
}

// ============================================================================
// BALANCE CONSERVATION
// ============================================================================

/// Basic conservation: one transfer, fees burned.
#[test]
fn test_balance_conservation_basic() {
    let mut dag = DAG::new();
    let w = addr(0x11);
    let r = addr(0x22);

    let fund = fund_tx(w, 10_000, 0, 0);
    dag.inject_transaction_raw(fund.clone());

    let tx = transfer_tx([fund.id, [0u8; 32]], w, r, 1000, 100, 1);
    dag.inject_transaction_raw(tx);

    let ledger = rebuild(&dag);

    // Conservation: total supply = genesis_total - fees_burned
    let expected_total = genesis_total() - 100; // 100 fee burned
    assert_eq!(ledger.total_supply(), expected_total);
    assert_eq!(ledger.get_balance(&r), 1000);
    // w balance: 10000 (fund) - 1000 (amount) - 100 (fee) = 8900
    assert_eq!(ledger.get_balance(&w), 8900);

    println!(
        "Conservation basic: total={}, fees_burned={}",
        ledger.total_supply(),
        ledger.fee_burn_balance()
    );
}

/// Chain of transfers: conservation holds across many hops.
#[test]
fn test_balance_conservation_chain() {
    let mut dag = DAG::new();
    let wa = addr(0x11);
    let wb = addr(0x22);

    let fund = fund_tx(wa, 100_000, 0, 0);
    dag.inject_transaction_raw(fund.clone());

    let mut total_amount = 0u64;
    let mut total_fees = 0u64;
    let mut prev = fund.id;

    for i in 1..=10u64 {
        let amount = 100 * i;
        let fee = 50;
        let tx = transfer_tx([prev, [0u8; 32]], wa, wb, amount, fee, i);
        total_amount += amount;
        total_fees += fee;
        prev = tx.id;
        dag.inject_transaction_raw(tx);
    }

    let ledger = rebuild(&dag);

    // wb received total_amount
    assert_eq!(ledger.get_balance(&wb), total_amount);
    // wa: 100000 - total_amount - total_fees
    assert_eq!(ledger.get_balance(&wa), 100_000 - total_amount - total_fees);
    // Total supply = genesis - total_fees
    assert_eq!(ledger.total_supply(), genesis_total() - total_fees);

    println!(
        "Chain conservation: sent={}, fees={}, total={}",
        total_amount,
        total_fees,
        ledger.total_supply()
    );
}

/// Conservation holds after crash recovery.
#[test]
fn test_balance_conservation_after_crash() {
    let mut dag = DAG::new();
    let wa = addr(0x11);
    let wb = addr(0x22);

    let fund = fund_tx(wa, 50_000, 0, 0);
    dag.inject_transaction_raw(fund.clone());

    let mut prev = fund.id;
    for i in 1..=5u64 {
        let tx = transfer_tx([prev, [0u8; 32]], wa, wb, 1000, 100, i);
        prev = tx.id;
        dag.inject_transaction_raw(tx);
    }

    // Rebuild twice (simulating two crashes)
    let ledger1 = rebuild(&dag);
    let ledger2 = rebuild(&dag);

    // Deterministic: both rebuilds must produce identical state
    assert_eq!(ledger1.total_supply(), ledger2.total_supply());
    assert_eq!(ledger1.get_balance(&wb), ledger2.get_balance(&wb));

    // Conservation
    assert_eq!(ledger1.total_supply(), genesis_total() - 500);
    assert_eq!(ledger1.get_balance(&wb), 5000);
}

// ============================================================================
// CRASH FUZZING
// ============================================================================

/// Fuzz: 100 cycles of random tx additions, crash, rebuild. 0 violations.
#[test]
fn test_crash_fuzz_100_cycles() {
    let wa = addr(0x11);
    let wb = addr(0x22);

    let mut dag = DAG::new();
    let genesis = fund_tx(wa, 1_000_000, 0, 0);
    dag.inject_transaction_raw(genesis.clone());

    let mut nonce = 1u64;
    let mut prev = genesis.id;

    for cycle in 0..100 {
        let tx_count = (cycle % 5) + 1;
        for _ in 0..tx_count {
            let (sender, receiver) = if nonce % 2 == 0 { (wa, wb) } else { (wb, wa) };
            let tx = transfer_tx([prev, [0u8; 32]], sender, receiver, 10, 1, nonce);
            dag.inject_transaction_raw(tx.clone());
            prev = tx.id;
            nonce += 1;
        }

        let ledger = rebuild(&dag);
        assert!(ledger.total_supply() <= genesis_total());
    }

    println!("Crash fuzz 100: 0 violations");
}

/// Fuzz: 1000 cycles. 0 violations.
#[test]
fn test_crash_fuzz_1000_cycles() {
    let wa = addr(0x11);
    let wb = addr(0x22);

    let mut dag = DAG::new();
    let genesis = fund_tx(wa, 10_000_000, 0, 0);
    dag.inject_transaction_raw(genesis.clone());

    let mut nonce = 1u64;
    let mut prev = genesis.id;

    for cycle in 0..1000 {
        let tx_count = ((cycle * 7 + 3) % 10) + 1;
        for _ in 0..tx_count {
            let (sender, receiver) = if nonce % 2 == 0 { (wa, wb) } else { (wb, wa) };
            let tx = transfer_tx([prev, [0u8; 32]], sender, receiver, 10, 1, nonce);
            dag.inject_transaction_raw(tx.clone());
            prev = tx.id;
            nonce += 1;
        }

        let ledger = rebuild(&dag);
        assert!(ledger.total_supply() <= genesis_total());
    }

    println!("Crash fuzz 1000: 0 violations");
}

// ============================================================================
// CRASH + PARTITION
// ============================================================================

/// Crash during partition: A|B with conflicting nonces, both crash, merge DAGs.
#[test]
fn test_crash_during_partition() {
    let wa = addr(0x11);
    let wb = addr(0x22);

    // Partition A
    let mut dag_a = DAG::new();
    let fund_a = fund_tx(wa, 100_000, 0, 0);
    dag_a.inject_transaction_raw(fund_a.clone());

    let mut prev_a = fund_a.id;
    for i in 1..=5u64 {
        let tx = transfer_tx([prev_a, [0u8; 32]], wa, wb, 100, 10, i);
        prev_a = tx.id;
        dag_a.inject_transaction_raw(tx);
    }

    // Partition B: conflicting nonces (1,2,3)
    let mut dag_b = DAG::new();
    let fund_b = fund_tx(wa, 100_000, 0, 0);
    dag_b.inject_transaction_raw(fund_b.clone());

    let mut prev_b = fund_b.id;
    for i in 1..=3u64 {
        let tx = transfer_tx([prev_b, [0u8; 32]], wa, wb, 200, 10, i);
        prev_b = tx.id;
        dag_b.inject_transaction_raw(tx);
    }

    // Crash and recover each partition
    let ledger_a = rebuild(&dag_a);
    let ledger_b = rebuild(&dag_b);
    assert!(ledger_a.total_supply() <= genesis_total());
    assert!(ledger_b.total_supply() <= genesis_total());

    // Reconnect: merge DAGs
    let mut merged = DAG::new();
    for tx in dag_a.transactions().values() {
        merged.inject_transaction_raw(tx.clone());
    }
    for tx in dag_b.transactions().values() {
        merged.inject_transaction_raw(tx.clone());
    }

    let final_ledger = rebuild(&merged);
    assert!(final_ledger.total_supply() <= genesis_total());

    // Nonces 1,2,3 conflict: for each, the smallest id wins
    // Total: fund + (at most 5 successful transfers)
    println!(
        "Crash+partition: a_total={}, b_total={}, merged_total={}",
        ledger_a.total_supply(),
        ledger_b.total_supply(),
        final_ledger.total_supply()
    );
}
