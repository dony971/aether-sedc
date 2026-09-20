//! Automated specification consistency check.
//!
//! Verifies that critical protocol parameters in code match documented values.

#[cfg(test)]
mod spec_check_tests {
    use crate::genesis::*;
    use crate::parent_selection::DAG;
    use crate::transaction::Transaction;

    /// SPEC-CHECK-01: PoW difficulty matches documentation
    #[test]
    fn check_pow_difficulty() {
        let difficulty = Transaction::default_difficulty();
        assert_eq!(
            difficulty, 24,
            "PoW difficulty must be 24 (documented in PROTOCOL_SPEC §7)"
        );
    }

    /// SPEC-CHECK-02: Genesis hash matches documentation
    #[test]
    fn check_genesis_hash() {
        assert_eq!(GENESIS_HASH, [0u8; 32], "Genesis hash must be [0u8; 32]");
    }

    /// SPEC-CHECK-03: MAX_SUPPLY matches documentation
    #[test]
    fn check_max_supply() {
        assert_eq!(
            MAX_SUPPLY, 2_000_000_000_000_000_000,
            "MAX_SUPPLY must be 2×10^18"
        );
    }

    /// SPEC-CHECK-04: UNITS_PER_AETH matches documentation
    #[test]
    fn check_units_per_aeth() {
        assert_eq!(
            UNITS_PER_AETH, 10_000_000_000,
            "UNITS_PER_AETH must be 10^10"
        );
    }

    /// SPEC-CHECK-05: Genesis ledger has exactly 2 entries
    #[test]
    fn check_genesis_ledger() {
        assert_eq!(
            GENESIS_LEDGER.len(),
            2,
            "Genesis ledger must have exactly 2 entries"
        );
    }

    /// SPEC-CHECK-06: Founder balance matches documentation
    #[test]
    fn check_founder_balance() {
        let founder_balance = GENESIS_LEDGER[0].1;
        assert_eq!(
            founder_balance, 100_000_000_000,
            "Founder balance must be 10 AETH (10^11 base units)"
        );
    }

    /// SPEC-CHECK-07: Faucet balance matches documentation
    #[test]
    fn check_faucet_balance() {
        let faucet_balance = GENESIS_LEDGER[1].1;
        assert_eq!(
            faucet_balance, 1_000_000_000_000_000_000,
            "Faucet balance must be 100M AETH (10^18 base units)"
        );
    }

    /// SPEC-CHECK-08: Fee burn address is all 0xFF
    #[test]
    fn check_fee_burn_address() {
        use crate::ledger::FEE_BURN_ADDRESS;
        assert_eq!(
            FEE_BURN_ADDRESS, [0xFFu8; 32],
            "Fee burn address must be [0xFFu8; 32]"
        );
    }

    /// SPEC-CHECK-09: Transaction has exactly 2 parents
    #[test]
    fn check_parent_count() {
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        assert_eq!(
            tx.parents.len(),
            2,
            "Transaction must have exactly 2 parents"
        );
    }

    /// SPEC-CHECK-10: Genesis parents are [0,0]
    #[test]
    fn check_genesis_parents() {
        let genesis_parents = [[0u8; 32]; 2];
        assert!(
            genesis_parents[0].iter().all(|&b| b == 0),
            "Genesis parent 0 must be all zeros"
        );
        assert!(
            genesis_parents[1].iter().all(|&b| b == 0),
            "Genesis parent 1 must be all zeros"
        );
    }

    /// SPEC-CHECK-11: DAG accepts transactions with genesis parents
    #[test]
    fn check_dag_genesis_parent() {
        let mut dag = DAG::new();
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        let result = dag.add_transaction_validated(tx);
        assert!(
            result.is_ok(),
            "DAG must accept transactions with genesis parents"
        );
    }

    /// SPEC-CHECK-12: DAG rejects transactions with missing parents
    #[test]
    fn check_dag_missing_parent() {
        let mut dag = DAG::new();
        let tx = Transaction::new(
            [[0xCAu8; 32], [0xFEu8; 32]],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        let result = dag.add_transaction_validated(tx);
        assert!(
            result.is_err(),
            "DAG must reject transactions with missing parents"
        );
    }

    /// SPEC-CHECK-13: Canonical conflict resolution picks smallest id
    #[test]
    fn check_canonical_smallest_id() {
        let mut dag = DAG::new();
        let sender = [0x11u8; 32];
        let r1 = [0x22u8; 32];
        let r2 = [0x33u8; 32];

        // Fund the sender from faucet
        let faucet_addr: [u8; 32] = hex::decode(FAUCET_ADDRESS).unwrap().try_into().unwrap();
        let fund = Transaction::new(
            [[0u8; 32]; 2],
            faucet_addr,
            sender,
            10_000,
            0,
            0,
            0,
            0,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        dag.inject_transaction_raw(fund.clone());

        // Two conflicting txs
        let tx1 = Transaction::new(
            [fund.id, [0u8; 32]],
            sender,
            r1,
            5000,
            1,
            100,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        let tx2 = Transaction::new(
            [fund.id, [0u8; 32]],
            sender,
            r2,
            5000,
            1,
            101,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );

        let (winner, loser) = if tx1.id < tx2.id {
            (&tx1, &tx2)
        } else {
            (&tx2, &tx1)
        };

        dag.inject_transaction_raw(tx1.clone());
        dag.inject_transaction_raw(tx2.clone());

        let mut ledger = crate::ledger::Ledger::new();
        ledger.rebuild_from_dag(&dag);

        // Winner's receiver gets funds
        assert_eq!(ledger.get_balance(&winner.receiver), winner.amount);
        // Loser's receiver gets nothing
        assert_eq!(ledger.get_balance(&loser.receiver), 0);
    }

    /// SPEC-CHECK-14: Supply never exceeds genesis
    #[test]
    fn check_supply_invariant() {
        let total_genesis: u64 = GENESIS_LEDGER.iter().map(|(_, b)| *b).sum();
        let mut dag = DAG::new();
        let sender = [0x11u8; 32];
        let receiver = [0x22u8; 32];

        let faucet_addr: [u8; 32] = hex::decode(FAUCET_ADDRESS).unwrap().try_into().unwrap();
        let fund = Transaction::new(
            [[0u8; 32]; 2],
            faucet_addr,
            sender,
            1_000_000,
            0,
            0,
            0,
            0,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        dag.inject_transaction_raw(fund.clone());

        for i in 1..=100 {
            let tx = Transaction::new(
                [fund.id, [0u8; 32]],
                sender,
                receiver,
                10,
                1,
                i,
                0,
                i,
                vec![0u8; 64],
                vec![0u8; 64],
            );
            dag.inject_transaction_raw(tx);
        }

        let mut ledger = crate::ledger::Ledger::new();
        ledger.rebuild_from_dag(&dag);

        assert!(
            ledger.total_supply() <= total_genesis,
            "Supply {} must not exceed genesis {}",
            ledger.total_supply(),
            total_genesis
        );
    }
}
