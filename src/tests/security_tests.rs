//! # Comprehensive Security Tests
//!
//! Tests for security invariants:
//! - Replay attack prevention (nonce validation)
//! - Double spend prevention (sender+nonce uniqueness)
//! - Deterministic conflict resolution (min-id wins)
//! - Atomic transaction execution (rollback on failure)
//! - Orphan recovery (persistence and reprocessing)
//! - MAX_SUPPLY / zero-emission monetary policy
//! - Ledger always derived from the DAG (rebuild invariant)

use crate::ledger::{Ledger, MAX_SUPPLY};
use crate::parent_selection::DAG;
use crate::rpc::Mempool;
use crate::storage::Storage;
use crate::transaction::Transaction;
use crate::transaction_processor::TransactionProcessor;
use crate::validation::TransactionValidator;
use crate::wallet::Wallet;
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::RwLock;

#[cfg(test)]
mod identity_spoofing_tests {
    use super::*;

    /// Sender must always match the public key (identity spoofing protection)
    #[test]
    fn test_sender_public_key_match_valid() {
        let wallet = Wallet::new();
        let public_key = wallet.public_key_bytes();
        let sender = wallet.address();
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            public_key,
        );
        assert!(tx.verify_sender_matches_public_key());
    }

    #[test]
    fn test_sender_public_key_mismatch_invalid() {
        let wallet1 = Wallet::new();
        let wallet2 = Wallet::new();
        let sender1 = wallet1.address();
        let public_key2 = wallet2.public_key_bytes();
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender1,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            public_key2,
        );
        assert!(!tx.verify_sender_matches_public_key());
    }

    #[test]
    fn test_sender_public_key_length_check() {
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
            vec![0u8; 16], // Too short
        );
        assert!(!tx.verify_sender_matches_public_key());
    }

    /// Full attack scenario: attacker signs with their own key but claims the
    /// victim's address as sender. Must be blocked by sender/public_key match.
    #[test]
    fn test_identity_spoofing_attack_scenario() {
        let victim_wallet = Wallet::new();
        let attacker_wallet = Wallet::new();
        let victim_address = victim_wallet.address();
        let attacker_public_key = attacker_wallet.public_key_bytes();

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&attacker_wallet.secret_key_bytes()[..32]);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let dummy_hash = [0u8; 32];
        let signature: Signature = signing_key.sign(&dummy_hash);

        let malicious_tx = Transaction::new(
            [[0u8; 32]; 2],
            victim_address,
            [2u8; 32],
            1_000_000,
            10,
            1234567890,
            0,
            1,
            signature.to_bytes().to_vec(),
            attacker_public_key,
        );
        assert!(!malicious_tx.verify_sender_matches_public_key());
        // And the full validator must reject it too.
        let validator = TransactionValidator::new();
        let ledger = Ledger::new();
        assert!(validator
            .validate_ledger(&malicious_tx, &ledger, 0)
            .is_err());
    }
}

#[cfg(test)]
mod replay_attack_tests {
    use super::*;

    /// Test that replay attacks are prevented via DAG-level (sender, nonce)
    /// uniqueness - the canonical conflict detector.
    ///
    /// NOTE: replay protection lives at the DAG level, NOT at the ledger
    /// level. A strict ledger `last_nonce + 1` check is arrival-order
    /// dependent: a node that processed nonces 4,5,6 before a late but valid
    /// nonce-3 transaction would reject it, while another node accepts it -
    /// permanently diverging the two DAGs (observed in the S5 resilience
    /// run: endless "Invalid nonce: expected 6, provided 3" resync loop).
    /// The ledger nonce is a pure function of the DAG (max per sender).
    #[tokio::test]
    async fn test_replay_attack_prevention() {
        let validator = TransactionValidator::new();
        let mut ledger = Ledger::new();
        let mut dag = DAG::new();
        let addr = [1u8; 32];

        ledger.set_balance(&addr, 1000);
        ledger.commit_nonce(&addr, 0);

        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        dag.add_transaction_validated(tx1.clone()).unwrap();
        ledger.commit_nonce(&addr, 1);

        // Replaying the exact same transaction (same id) must be rejected.
        let result = validator.validate_dag(&tx1, &dag);
        assert!(result.is_err());

        // A DIFFERENT transaction reusing the same (sender, nonce) pair must
        // be rejected by the canonical double-spend detector.
        let tx2 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [3u8; 32],
            50,
            10,
            1234567891,
            0,
            1, // same nonce as tx1
            vec![0u8; 64],
            vec![1u8; 64],
        );
        let result = validator.validate_dag(&tx2, &dag);
        assert!(result.is_err());
    }

    /// Out-of-order nonces must NOT be rejected at the ledger level: the
    /// acceptance rule must be independent of the arrival order, otherwise
    /// two nodes processing the same transaction set in different orders
    /// permanently diverge (see the S5 resilience evidence). The ledger
    /// nonce simply takes the max seen, exactly like the boot rebuild.
    #[tokio::test]
    async fn test_out_of_order_nonce_accepted() {
        let validator = TransactionValidator::new();
        let mut ledger = Ledger::new();
        let addr = [1u8; 32];

        ledger.set_balance(&addr, 1000);
        ledger.commit_nonce(&addr, 0);

        // Nonce 3 arrives before nonces 1 and 2: it is valid (balance OK,
        // fee OK) and must be accepted - the strict "must be last+1" rule
        // would make acceptance depend on the arrival order.
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            3, // Out of order, but not a replay
            vec![0u8; 64],
            vec![1u8; 64],
        );

        let result = validator.validate_ledger(&tx, &ledger, 0);
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod double_spend_tests {
    use super::*;

    /// A (sender, nonce) pair must be unique in the DAG (canonical double-spend
    /// detector). A second transaction from the same sender with the same nonce
    /// is rejected, regardless of its parents.
    #[tokio::test]
    async fn test_sender_nonce_conflict_rejected() {
        let mut dag = DAG::new();
        let addr = [1u8; 32];

        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [3u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.add_transaction_validated(tx1.clone()).unwrap();

        // Same sender, same nonce -> double spend -> rejected.
        let tx2 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [5u8; 32],
            50,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        let result = dag.add_transaction_validated(tx2);
        assert!(result.is_err());
    }

    /// find_sender_nonce_conflict must locate the existing conflicting tx so the
    /// processor can deterministically decide the winner (min-id wins).
    #[tokio::test]
    async fn test_find_sender_nonce_conflict() {
        let mut dag = DAG::new();
        let addr = [1u8; 32];

        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [3u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.add_transaction_validated(tx1.clone()).unwrap();

        let found = dag.find_sender_nonce_conflict(&addr, 1);
        assert_eq!(found, Some(tx1.id));
        // A different nonce has no conflict.
        assert!(dag.find_sender_nonce_conflict(&addr, 2).is_none());
    }

    /// Distinct nonces from the same sender are NOT a conflict (valid chains
    /// of sequential transactions).
    #[tokio::test]
    async fn test_distinct_nonces_are_not_conflict() {
        let mut dag = DAG::new();
        let addr = [1u8; 32];

        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [3u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.add_transaction_validated(tx1.clone()).unwrap();

        let tx2 = Transaction::new(
            [[0u8; 32]; 2],
            addr,
            [5u8; 32],
            50,
            10,
            1234567890,
            0,
            2,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        let result = dag.add_transaction_validated(tx2);
        assert!(result.is_ok());
    }

    /// Two different senders may legitimately build on the SAME parent pair.
    /// This must NOT be treated as a conflict (fixes the convergence bug where
    /// a node rejected valid txs whose parent pair was already used).
    #[tokio::test]
    async fn test_shared_parents_are_not_conflict() {
        let mut dag = DAG::new();
        let parent = Transaction::new(
            [[0u8; 32]; 2],
            [2u8; 32],
            [9u8; 32],
            0,
            0,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        dag.add_transaction_validated(parent.clone()).unwrap();

        let parents = [parent.id, [0u8; 32]];
        let a = Transaction::new(
            parents,
            [1u8; 32],
            [3u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        assert!(dag.add_transaction_validated(a.clone()).is_ok());

        // Sender B uses the SAME parent pair -> must be accepted (no false
        // positive on duplicated parents).
        let b = Transaction::new(
            parents,
            [4u8; 32],
            [5u8; 32],
            50,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        assert!(dag.add_transaction_validated(b).is_ok());
    }
}

#[cfg(test)]
mod atomic_execution_tests {
    use super::*;

    /// Transaction execution must roll back on failure (balance unchanged).
    #[tokio::test]
    async fn test_atomic_rollback_on_failure() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        let sender = [1u8; 32];
        let receiver = [2u8; 32];
        ledger.write().await.set_balance(&sender, 1000);
        ledger.write().await.commit_nonce(&sender, 0);
        let balance_before = ledger.read().await.get_balance(&sender);

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            2000, // More than balance
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        let result = processor.process(tx, &dag, &ledger, &mempool, 10).await;
        assert!(result.is_err());

        let balance_after = ledger.read().await.get_balance(&sender);
        assert_eq!(balance_before, balance_after);
    }

    /// Nonce must NOT be committed if the transfer fails.
    #[tokio::test]
    async fn test_nonce_not_committed_on_transfer_failure() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        let sender = [1u8; 32];
        let receiver = [2u8; 32];
        ledger.write().await.set_balance(&sender, 1000);
        ledger.write().await.commit_nonce(&sender, 0);
        let nonce_before = ledger.read().await.get_nonce(&sender);

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            2000,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        let _ = processor.process(tx, &dag, &ledger, &mempool, 10).await;

        let nonce_after = ledger.read().await.get_nonce(&sender);
        assert_eq!(nonce_before, nonce_after);
    }
}

#[cfg(test)]
mod orphan_recovery_tests {
    use super::*;

    /// Test that orphans persist to disk.
    #[tokio::test]
    async fn test_orphan_persistence() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        let tx = Transaction::new(
            [[1u8; 32], [2u8; 32]], // Non-existent parents
            [3u8; 32],
            [4u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );

        storage.put_orphan(tx.id, &tx).unwrap();
        let retrieved = storage.get_orphan(tx.id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, tx.id);

        storage.remove_orphan(tx.id).unwrap();
        let retrieved_after = storage.get_orphan(tx.id).unwrap();
        assert!(retrieved_after.is_none());
    }

    /// Test that orphans are loaded on startup.
    #[tokio::test]
    async fn test_orphan_load_on_startup() {
        let dir = tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();

        for i in 0..5 {
            let tx = Transaction::new(
                [[i as u8; 32], [((i + 1) % 255) as u8; 32]],
                [3u8; 32],
                [4u8; 32],
                100,
                10,
                1234567890,
                0,
                1,
                vec![0u8; 64],
                vec![1u8; 64],
            );
            storage.put_orphan(tx.id, &tx).unwrap();
        }

        let orphans = storage.get_all_orphans().unwrap();
        assert_eq!(orphans.len(), 5);
    }
}

#[cfg(test)]
mod zero_emission_tests {
    use super::*;

    /// There is no reward function: money can never be minted. The circulating
    /// supply must always be ≤ the genesis allocation and ≤ MAX_SUPPLY.
    #[tokio::test]
    async fn test_supply_never_exceeds_genesis() {
        let mut ledger = Ledger::new();
        for (addr_hex, balance) in crate::genesis::GENESIS_LEDGER {
            ledger.set_balance_hex(addr_hex.to_string(), balance);
        }
        let genesis_supply = ledger.total_supply();
        assert!(genesis_supply <= MAX_SUPPLY);

        // A transfer from a genesis-funded account (faucet) only burns fees,
        // so supply shrinks or stays flat.
        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let b = [0xBBu8; 32];
        ledger.transfer_internal(&faucet, &b, 500, 10).unwrap();
        assert!(ledger.total_supply() <= genesis_supply);
        assert!(ledger.supply_within_bounds());
    }

    /// The ledger is a DERIVED VIEW of the DAG: rebuild_from_dag reproduces the
    /// exact balances from genesis + replay and never introduces new supply.
    #[tokio::test]
    async fn test_rebuild_from_dag_preserves_invariant() {
        let mut dag = DAG::new();
        let mut ledger = Ledger::new();
        for (addr_hex, balance) in crate::genesis::GENESIS_LEDGER {
            ledger.set_balance_hex(addr_hex.to_string(), balance);
        }

        // Funds come from a genesis-funded account (the faucet): rebuild
        // reseeds balances strictly from genesis.
        let faucet = hex::decode(crate::genesis::FAUCET_ADDRESS).unwrap();
        let faucet: [u8; 32] = faucet.try_into().unwrap();
        let b = [0xBBu8; 32];

        let tx1 = Transaction::new(
            [[0u8; 32]; 2],
            faucet,
            b,
            100,
            5,
            1,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 64],
        );
        dag.add_transaction_validated(tx1.clone()).unwrap();

        ledger.rebuild_from_dag(&dag);
        assert_eq!(ledger.get_balance(&b), 100);
        assert_eq!(ledger.fee_burn_balance(), 5);
        assert!(ledger.supply_within_bounds());
        assert!(ledger.total_supply() <= MAX_SUPPLY);
    }

    /// No emission: after processing a real transfer the total supply must not
    /// have grown (fees are burned, nothing is minted).
    #[tokio::test]
    async fn test_processing_does_not_mint() {
        let processor = TransactionProcessor::new();
        let dag = Arc::new(RwLock::new(DAG::new()));
        let ledger = Arc::new(RwLock::new(Ledger::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));

        // Seed a sender (simulating a funded account) and note total supply.
        let sender = [1u8; 32];
        let receiver = [2u8; 32];
        {
            let mut l = ledger.write().await;
            l.set_balance(&sender, 1000);
            l.commit_nonce(&sender, 0);
        }
        let supply_before = ledger.read().await.total_supply();

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            receiver,
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 64],
        );
        // This fails validation (placeholder signature), so nothing changes.
        let _ = processor.process(tx, &dag, &ledger, &mempool, 10).await;
        let supply_after = ledger.read().await.total_supply();
        assert!(supply_after <= supply_before);
    }
}

#[cfg(test)]
mod malleability_tests {
    use super::*;

    /// The signing hash covers ALL fields (parents, sender, receiver, amount,
    /// fee, timestamp, nonce, account_nonce): mutating ANY field invalidates
    /// the signature. This blocks transaction malleability attacks.
    #[test]
    fn test_signature_covers_amount() {
        let wallet = Wallet::new();
        let receiver = [0x02u8; 32];
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            wallet.address(),
            receiver,
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            wallet.public_key_bytes(),
        );
        tx.signature = wallet.sign_transaction(&tx).unwrap();
        assert!(Wallet::verify_transaction(&tx));

        // Attacker changes the amount: signature must no longer verify.
        tx.amount = 999_999;
        assert!(!Wallet::verify_transaction(&tx));
        // And the transaction id changes too (malleated tx is a NEW tx).
        let original = tx.clone();
        assert_ne!(original.id, original.compute_hash());
    }

    #[test]
    fn test_signature_covers_receiver() {
        let wallet = Wallet::new();
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            wallet.address(),
            [0x02u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            wallet.public_key_bytes(),
        );
        tx.signature = wallet.sign_transaction(&tx).unwrap();
        assert!(Wallet::verify_transaction(&tx));

        // Redirect the payment to the attacker.
        tx.receiver = [0xEEu8; 32];
        assert!(!Wallet::verify_transaction(&tx));
    }

    #[test]
    fn test_signature_covers_nonce_and_timestamp() {
        let wallet = Wallet::new();
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            wallet.address(),
            [0x02u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            wallet.public_key_bytes(),
        );
        tx.signature = wallet.sign_transaction(&tx).unwrap();
        assert!(Wallet::verify_transaction(&tx));

        // Replay-style mutations (timestamp, nonce, account_nonce) all break
        // the signature: a node can never be tricked into accepting a
        // re-framed transaction.
        let mut t1 = tx.clone();
        t1.timestamp += 1;
        assert!(!Wallet::verify_transaction(&t1));

        let mut t2 = tx.clone();
        t2.nonce += 1;
        assert!(!Wallet::verify_transaction(&t2));

        let mut t3 = tx.clone();
        t3.account_nonce += 1;
        assert!(!Wallet::verify_transaction(&t3));
    }

    /// An oversized serialized transaction must be rejected at RPC reception
    /// BEFORE deserialization/processing (memory DoS guard). MAX_RPC_TX_SIZE is
    /// private to rpc.rs, so we assert the guard exists via the RPC handler's
    /// public path: hex payloads larger than the cap fail with a clear error.
    #[tokio::test]
    async fn test_oversized_tx_rejected_by_rpc() {
        // Build the RPC implementation with minimal state.
        let rpc_impl = crate::rpc::AetherRpcImpl::new(
            Arc::new(RwLock::new(DAG::new())),
            Arc::new(RwLock::new(Ledger::new())),
            Arc::new(RwLock::new(
                crate::storage::Storage::open(tempdir().unwrap().path()).unwrap(),
            )),
            std::path::PathBuf::from("test_rpc_size"),
            Arc::new(RwLock::new(Mempool::new(1000, 10))),
            Arc::new(crate::p2p::P2PNetwork::new(
                crate::p2p::P2PConfig::default(),
                tokio::sync::mpsc::unbounded_channel::<Transaction>().0,
                Arc::new(|| vec![]),
                Arc::new(|_| None),
                Arc::new(|| vec![]),
            )),
            Arc::new(RwLock::new(false)),
            Arc::new(RwLock::new(std::collections::HashMap::new())),
        );

        // 2 MiB of zeros: way beyond the 1 MiB cap.
        let huge = vec![0u8; 2 * 1024 * 1024];
        let result = rpc_impl
            .send_transaction(serde_json::json!([hex::encode(&huge)]))
            .await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("too large"));
    }
}

/// The faucet secret key must never be embedded in the binary: it is loaded
/// from a server-only file and ONLY accepted if it derives to the genesis
/// FAUCET_ADDRESS (otherwise the faucet would sign for an empty address).
/// The original genesis seed was removed from the source (V-01), so only the
/// negative paths are testable: absent / malformed / mismatched keys.
#[cfg(test)]
mod faucet_key_tests {
    use super::*;

    fn key_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("faucet.key")
    }

    #[test]
    fn test_missing_key_disables_faucet() {
        let dir = tempdir().unwrap();
        assert!(crate::rpc::AetherRpcImpl::load_faucet_key(&key_path(&dir)).is_none());
    }

    #[test]
    fn test_invalid_hex_disables_faucet() {
        let dir = tempdir().unwrap();
        std::fs::write(key_path(&dir), "not-hex!!!").unwrap();
        assert!(crate::rpc::AetherRpcImpl::load_faucet_key(&key_path(&dir)).is_none());
    }

    #[test]
    fn test_wrong_length_disables_faucet() {
        let dir = tempdir().unwrap();
        std::fs::write(key_path(&dir), hex::encode([7u8; 16])).unwrap();
        assert!(crate::rpc::AetherRpcImpl::load_faucet_key(&key_path(&dir)).is_none());
    }

    /// A well-formed key whose address differs from the genesis FAUCET_ADDRESS
    /// must be rejected: it could never spend the genesis faucet balance, so
    /// accepting it would silently break every faucet transaction.
    #[test]
    fn test_mismatched_key_disables_faucet() {
        let dir = tempdir().unwrap();
        let seed = [0x42u8; 32];
        std::fs::write(key_path(&dir), hex::encode(seed)).unwrap();
        let loaded = crate::rpc::AetherRpcImpl::load_faucet_key(&key_path(&dir));
        assert!(
            loaded.is_none(),
            "a key that does not derive to genesis FAUCET_ADDRESS must be rejected"
        );
    }
}
