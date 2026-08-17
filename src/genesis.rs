use crate::parent_selection::DAG;
use crate::transaction::{Address, Transaction, TransactionId};
use std::collections::HashMap;

/// Genesis block ID (hash of 64 zeros)
pub const GENESIS_HASH: TransactionId = [0u8; 32];

/// Genesis message containing a news headline to prove launch date
/// "23/Apr/2026 - Aether: Trust is computed, not granted. Le Monde 21/04/2026: L'Aether naît du chaos numérique."
/// ROTATION 2026-08-16: the legacy faucet key was compromised; new canonical
/// genesis issued by the operator ceremony (see docs/CEREMONIE_GENESIS.md).
/// ROTATION 2026-08-17 (V3 RELEASE CANDIDATE): canonical genesis for P2P
/// protocol v3 (structural weight, zero emission). Ceremony keys generated
/// offline; secrets never stored in the repository.
pub const GENESIS_MESSAGE: &str = "17/Aug/2026 - Aether: Trust is computed, not granted. V3 testnet release candidate: canonical genesis for P2P protocol v3 (structural weight, zero emission). Operator ceremony.";

/// Monetary precision: 1 AETH = 10^10 base units.
pub const UNITS_PER_AETH: u64 = 10_000_000_000;

/// Aether Founder address (receives the initial founder allocation at genesis).
/// This is a PUBLIC address (derived from a public key). No secret is present
/// in the source code or distributed binary.
pub const FOUNDER_ADDRESS: &str =
    "2ffab7975e84a8b6feb5e47534c8a14af10d0b09f946014437f32723347e60d4";

/// Faucet address. This is a PUBLIC address only. The matching SECRET KEY is
/// NOT in the source or the distributed binary: it must be supplied at runtime
/// by the node operator in a server-only file (`data_dir/faucet.key`) so that
/// only operators who hold the key can serve testnet faucet funds. Nodes
/// without that file simply disable the faucet endpoint.
pub const FAUCET_ADDRESS: &str = "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb";

/// Faucet public key hex (public information, no secret).
pub const FAUCET_PUBLIC_KEY: &str =
    "a19ee04cfaeaee20d74e59d066a178f3f9d0e69f48ffa001f8314ead507aabfb";

/// Genesis ledger with the initial token distribution (FIXED SUPPLY).
/// Aether's monetary policy: emission is ZERO after genesis; the total supply
/// is the genesis allocation and can only decrease through fee burning.
///   - Founder: 10 AETH
///   - Faucet : 100,000,000 AETH (bounded testnet fund, spent via signed txs)
pub const GENESIS_LEDGER: [(&str, u64); 2] = [
    (FOUNDER_ADDRESS, 100_000_000_000_u64),          // 10 AETH
    (FAUCET_ADDRESS, 1_000_000_000_000_000_000_u64), // 100,000,000 AETH
];

/// Maximum supply invariant (hard bound). With zero emission the supply can
/// never exceed the genesis allocation; this constant is kept as a defensive
/// invariant check against any accidental supply inflation.
pub const MAX_SUPPLY: u64 = 2_000_000_000_000_000_000; // 200,000,000 AETH

/// Genesis configuration
#[derive(Debug, Clone)]
pub struct GenesisConfig {
    /// Genesis timestamp
    pub timestamp: u64,

    /// Initial difficulty
    pub initial_difficulty: u64,

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

        Self {
            timestamp,
            initial_difficulty: 1000,
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

/// Initialize the DAG with genesis balances.
/// Returns: (DAG, balances map keyed by hex address, orphan map, missing parents)
pub fn initialize_genesis(
    config: GenesisConfig,
) -> (
    DAG,
    HashMap<String, u64>,
    HashMap<[u8; 32], Transaction>,
    Vec<Vec<u8>>,
) {
    let dag = DAG::new();
    let orphans = HashMap::new();
    let missing_parent_hashes = Vec::new();

    let mut balances = HashMap::new();
    for (addr_hex, balance) in GENESIS_LEDGER {
        balances.insert(addr_hex.to_string(), balance);
    }

    let _ = config;
    (dag, balances, orphans, missing_parent_hashes)
}
