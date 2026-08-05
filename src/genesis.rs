use crate::consensus::{VQVConsensus, Validator};
use crate::parent_selection::DAG;
use crate::transaction::{Address, Transaction, TransactionId};
use hex;
use std::collections::HashMap;

/// Genesis block ID (hash of 64 zeros)
pub const GENESIS_HASH: TransactionId = [0u8; 32];

/// Genesis message containing a news headline to prove launch date
/// "23/Apr/2026 - Aether: Trust is computed, not granted. Le Monde 21/04/2026: L'Aether naît du chaos numérique."
pub const GENESIS_MESSAGE: &str = "23/Apr/2026 - Aether: Trust is computed, not granted. Le Monde 21/04/2026: L'Aether naît du chaos numérique.";

/// Aether Founder address (receives 1M AETH at genesis)
/// Derived from public key: 1de352e44cd333672593f2334a730e180aaf290de89aa16d480de594e34e2961
pub const FOUNDER_ADDRESS: &str =
    "3d17ace653283dbd9aeba6e0d4684795a800e9da952cb682bb67cd970cbe1b3e";

/// Faucet address (deterministic from sha256("aether-faucet-v1") via Ed25519)
pub const FAUCET_ADDRESS: &str = "5579ae9096f1ae55bfd6fd88155fad09c59ab8ccb61c8a297b5d1027ea4ca916";

/// Faucet secret key hex (deterministic, for testnet only)
pub const FAUCET_SECRET_KEY: &str =
    "fa5979dd7273d55c6b5f2028ab166dc3163f90ac9f68da28b79a1fe0f06c45b8";

/// Faucet public key hex
pub const FAUCET_PUBLIC_KEY: &str =
    "5579ae9096f1ae55bfd6fd88155fad09c59ab8ccb61c8a297b5d1027ea4ca916";

/// Genesis ledger with initial token distribution
/// 10 AETH = 100,000,000,000 units (10 decimals)
pub const GENESIS_LEDGER: [(&str, u64); 2] = [
    (FOUNDER_ADDRESS, 100_000_000_000_u64), // 10 AETH for founder
    (FAUCET_ADDRESS, 10_000_000_000_000_000_000_u64), // 1M AETH for faucet (10^18 units)
];

/// Genesis configuration
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Genesis timestamp
    pub timestamp: u64,

    /// Initial difficulty
    pub initial_difficulty: u64,

    /// Initial validators
    pub initial_validators: Vec<Address>,

    /// Initial token distribution (address -> balance)
    pub initial_balances: HashMap<Address, u64>,
}

impl Default for GenesisConfig {
    fn default() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        let mut initial_balances = HashMap::new();
        for (address_hex, balance) in GENESIS_LEDGER {
            let addr_bytes = hex::decode(address_hex).expect("Invalid genesis address hex");
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_bytes);
            tracing::info!(
                "🔍 GenesisConfig: Adding address {} with balance {} (raw)",
                address_hex,
                balance
            );
            initial_balances.insert(addr, balance);
        }

        let founder_addr = hex::decode(FOUNDER_ADDRESS).expect("Invalid founder address hex");
        let mut founder = [0u8; 32];
        founder.copy_from_slice(&founder_addr);
        let initial_validators = vec![founder];

        Self {
            timestamp,
            initial_difficulty: 1000,
            initial_validators,
            initial_balances,
        }
    }
}

/// Genesis block (first transaction in DAG)
#[derive(Debug, Clone)]
pub struct GenesisBlock {
    pub transaction: Transaction,
    pub timestamp: u64,
}

/// Genesis hash is the hash of the genesis transaction
pub fn genesis_hash() -> TransactionId {
    [0u8; 32]
}

/// Initialize the DAG with genesis
pub fn initialize_genesis(
    config: GenesisConfig,
) -> (
    DAG,
    VQVConsensus,
    HashMap<String, u64>,
    HashMap<[u8; 32], Transaction>,
    Vec<Vec<u8>>,
) {
    let mut dag = DAG::new();
    let mut orphans = HashMap::new();
    let missing_parent_hashes = Vec::new();

    let mut balances = HashMap::new();
    for (addr_hex, balance) in GENESIS_LEDGER {
        balances.insert(addr_hex.to_string(), balance);
    }

    let validators: Vec<Validator> = config
        .initial_validators
        .iter()
        .map(|addr| {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&addr[..32]);
            Validator::new(*addr, 100_000, pk.to_vec())
        })
        .collect();

    let consensus = VQVConsensus::default();

    (dag, consensus, balances, orphans, missing_parent_hashes)
}
