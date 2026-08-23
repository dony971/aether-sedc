//! Security tests module
pub mod inc01_fix_tests;
pub mod security_tests;

use crate::transaction::Transaction;
use crate::wallet::Wallet;

/// H1: deterministic orphan transaction with a VALID PoW (difficulty 20) and
/// VALID signature, referencing parents `[0xCA; 32]` / `[0xFE; 32]` that are
/// absent from any fresh DAG. The nonce and signature were computed once with
/// `mine_nonce(20)` + signing and are hardcoded here so tests never spend
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
        161041, // precomputed PoW nonce
        1,
        hex::decode(
            "019a99bc40bf26f25f9e724dc8f0cb0a3f917e65092389107d05cf95fefbb8275c95cff0bb2a703f072ff46ec49b6ffb5f94d9820239feb905612be9bbe4960d",
        )
        .expect("fixed signature"),
        wallet.public_key_bytes(),
    );
    debug_assert!(tx.verify_pow(Transaction::default_difficulty()));
    debug_assert!(Wallet::verify_transaction(&tx));
    tx
}
