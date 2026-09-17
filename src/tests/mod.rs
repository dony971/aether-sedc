//! Security tests module
pub mod consensus_harness;
pub mod crash_harness;
pub mod deep_sync_harness;
pub mod inc01_fix_tests;
pub mod multiprocess_crash;
pub mod pow_economics;
pub mod scalability;
pub mod security_tests;
pub mod spec_check;
pub mod sybil_scale;

use crate::transaction::Transaction;
use crate::wallet::Wallet;

/// H1: deterministic orphan transaction with a VALID PoW (difficulty 24) and
/// VALID signature, referencing parents `[0xCA; 32]` / `[0xFE; 32]` that are
/// absent from any fresh DAG. The nonce and signature were computed once with
/// `mine_nonce(24)` + signing and are hardcoded here so tests never spend
/// seconds (or minutes on an unlucky nonce) in a PoW search.
pub fn signed_mined_orphan_tx() -> Transaction {
    let wallet =
        Wallet::from_secret_key("6b0d2c3e4f5a60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef")
            .expect("fixed test key");
    let tx = Transaction::new(
        [[0xCAu8; 32], [0xFEu8; 32]],
        wallet.address(),
        [2u8; 32],
        100,
        1000,
        1234567890,
        0, // placeholder nonce — mined below
        1,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    let mut tx = tx;
    tx.nonce = tx.mine_nonce(Transaction::default_difficulty());
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    debug_assert!(tx.verify_pow(Transaction::default_difficulty()));
    debug_assert!(Wallet::verify_transaction(&tx));
    tx
}
