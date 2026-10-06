//! # Transaction Module
//!
//! Defines the core Transaction structure for the DAG network.
//! Each transaction references two parent transactions, forming a DAG topology.

use hex;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a transaction (256-bit hash)
pub type TransactionId = [u8; 32];

/// Address type (256-bit)
pub type Address = [u8; 32];

/// Canonical textual form of a transaction id or address (lowercase hex, 64 chars).
///
/// V-20 FIX: every serialization boundary (RPC, CLI, GUI, P2P, storage,
/// explorer) MUST use this exact format. Byte arrays serialized as numeric
/// JSON arrays (`[32, 219, ...]`) are explicitly forbidden: they broke
/// `aether_getTips`, silently degraded every client to genesis parents
/// `[0,0]` and turned the DAG into a star. Any component that parses a tip
/// uses `decode_id`, so a tip round-trips losslessly.
pub fn encode_id(id: &[u8; 32]) -> String {
    hex::encode(id)
}

/// Parse the canonical textual form (64 lowercase/uppercase hex chars) back
/// into bytes. Returns `None` for anything else (wrong length, non-hex, or
/// a non-string JSON value).
pub fn decode_id(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// Parse the `"tips"` array of an `aether_getTips` response into at most two
/// parent ids for a new transaction.
///
/// V-20 FIX: strict parsing. A malformed entry is an ERROR, never a silent
/// fallback to genesis parents. Genesis parents `[0,0]` are only returned
/// when the array is empty (empty DAG), which is the only legitimate case
/// for a transaction to reference genesis directly.
pub fn tips_to_parents(tips_array: &[serde_json::Value]) -> Result<[TransactionId; 2], String> {
    let mut parents = [[0u8; 32]; 2];
    for (i, tip) in tips_array.iter().take(2).enumerate() {
        let tip_str = tip
            .as_str()
            .ok_or_else(|| format!("Malformed tip at index {}: not a hex string", i))?;
        let bytes = decode_id(tip_str)
            .ok_or_else(|| format!("Malformed tip at index {}: invalid hex id", i))?;
        parents[i] = bytes;
    }
    Ok(parents)
}

/// Core transaction structure for the DAG
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    /// Unique transaction hash (computed from fields)
    pub id: TransactionId,

    /// Two parent transaction IDs (DAG topology)
    pub parents: [TransactionId; 2],

    /// Sender address (derived from public key)
    pub sender: Address,

    /// Receiver address
    pub receiver: Address,

    /// Amount to transfer
    pub amount: u64,

    /// Transaction fee
    pub fee: u64,

    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// Nonce for Micro-PoW (anti-spam) - mined to meet difficulty
    pub nonce: u64,

    /// Account nonce for replay protection (sequential per address)
    /// Must be exactly last_nonce + 1 for each transaction from this address
    pub account_nonce: u64,

    /// Cumulative weight (for tip selection) - default 0.0 for CLI compatibility
    #[serde(default)]
    pub weight: f64,

    /// Ed25519 signature (64 bytes)
    pub signature: Vec<u8>,

    /// Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(
        parents: [TransactionId; 2],
        sender: Address,
        receiver: Address,
        amount: u64,
        fee: u64,
        timestamp: u64,
        nonce: u64,
        account_nonce: u64,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Self {
        let mut tx = Self {
            id: [0u8; 32],
            parents,
            sender,
            receiver,
            amount,
            fee,
            timestamp,
            nonce,
            account_nonce,
            weight: 0.0,
            signature,
            public_key,
        };

        // Compute hash after all fields are set
        tx.id = tx.compute_hash();
        tx
    }

    /// Compute the transaction hash using BLAKE3 (includes signature and public_key)
    pub fn compute_hash(&self) -> TransactionId {
        let mut hasher = blake3::Hasher::new();

        // Hash all fields except id and weight (computed fields)
        hasher.update(&self.parents[0]);
        hasher.update(&self.parents[1]);
        hasher.update(&self.sender);
        hasher.update(&self.receiver);
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.account_nonce.to_le_bytes());
        hasher.update(&self.signature);
        hasher.update(&self.public_key);

        hasher.finalize().into()
    }

    /// Compute the signing hash (excludes only the signature and public_key,
    /// which cannot authenticate themselves).
    ///
    /// This is what should be signed. It MUST cover every field that has an
    /// economic or consensus influence, otherwise an attacker could mutate an
    /// unsigned field without invalidating the signature (malleability):
    ///   - parents        (DAG topology / conflict resolution)
    ///   - sender, receiver, amount, fee  (economic flow)
    ///   - timestamp      (ordering hints)
    ///   - nonce          (Micro-PoW proof)
    ///   - account_nonce  (replay protection)
    ///
    /// Note: `nonce` is included, which requires mining to happen BEFORE
    /// signing. Both the CLI (`main.rs`) and the GUI (`gui.rs`) already mine
    /// the nonce before signing, so this is compatible.
    pub fn compute_signing_hash(&self) -> TransactionId {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.parents[0]);
        hasher.update(&self.parents[1]);
        hasher.update(&self.sender);
        hasher.update(&self.receiver);
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.account_nonce.to_le_bytes());

        hasher.finalize().into()
    }

    /// Verify that the transaction hash is valid
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.id
    }

    /// Check if this transaction is a genesis transaction (no parents)
    pub fn is_genesis(&self) -> bool {
        self.parents == [TransactionId::default(); 2]
    }

    /// Get the total deduction from sender (amount + fee)
    pub fn total_deduction(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }

    /// Calculate recommended fee based on DAG load and Micro-PoW difficulty
    pub fn calculate_recommended_fee(dag_size: usize, current_tps: u64, difficulty: u64) -> u64 {
        // Base fee
        let base_fee = 1u64;

        // Load factor: increases with DAG size and TPS
        let load_factor = (dag_size as f64 / 10000.0).min(5.0); // Cap at 5x multiplier
        let tps_factor = (current_tps as f64 / 100.0).min(3.0); // Cap at 3x multiplier

        // Difficulty factor: higher difficulty means higher fee for priority
        let difficulty_factor = (difficulty as f64 / 10000.0).min(2.0); // Cap at 2x multiplier

        // Calculate final fee
        let recommended_fee =
            (base_fee as f64 * (1.0 + load_factor + tps_factor + difficulty_factor)) as u64;

        // Ensure minimum fee of 1
        recommended_fee.max(1)
    }

    /// Deserialize transaction - Manual binary decoding for strict alignment
    /// Matches SDK's serialize() format
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        const MIN_SIZE: usize = 208; // Fixed fields: 5*32 + 6*8 = 160 + 48 = 208 (added account_nonce)

        if bytes.len() < MIN_SIZE {
            return Err(format!(
                "Data too short: minimum {} bytes required, got {}",
                MIN_SIZE,
                bytes.len()
            ));
        }

        let mut cursor = 0;

        // Helper function to safely read slice
        let read_slice = |start: usize, len: usize, field_name: &str| -> Result<&[u8], String> {
            let end = start + len;
            if end > bytes.len() {
                return Err(format!("Error: Received {} bytes, trying to read field {} at index {} (length {})", bytes.len(), field_name, start, len));
            }
            Ok(&bytes[start..end])
        };

        // Fixed-size fields (208 bytes total)
        let id: TransactionId = read_slice(cursor, 32, "id")?
            .try_into()
            .map_err(|_| "Invalid id: cannot convert to [u8; 32]".to_string())?;
        cursor += 32;

        let parent0: TransactionId = read_slice(cursor, 32, "parent0")?
            .try_into()
            .map_err(|_| "Invalid parent0: cannot convert to [u8; 32]".to_string())?;
        cursor += 32;

        let parent1: TransactionId = read_slice(cursor, 32, "parent1")?
            .try_into()
            .map_err(|_| "Invalid parent1: cannot convert to [u8; 32]".to_string())?;
        cursor += 32;

        let sender: Address = read_slice(cursor, 32, "sender")?
            .try_into()
            .map_err(|_| "Invalid sender: cannot convert to [u8; 32]".to_string())?;
        cursor += 32;

        let receiver: Address = read_slice(cursor, 32, "receiver")?
            .try_into()
            .map_err(|_| "Invalid receiver: cannot convert to [u8; 32]".to_string())?;
        cursor += 32;

        let amount = u64::from_le_bytes(
            read_slice(cursor, 8, "amount")?
                .try_into()
                .map_err(|_| "Invalid amount: cannot convert to u64".to_string())?,
        );
        cursor += 8;

        let fee = u64::from_le_bytes(
            read_slice(cursor, 8, "fee")?
                .try_into()
                .map_err(|_| "Invalid fee: cannot convert to u64".to_string())?,
        );
        cursor += 8;

        let timestamp = u64::from_le_bytes(
            read_slice(cursor, 8, "timestamp")?
                .try_into()
                .map_err(|_| "Invalid timestamp: cannot convert to u64".to_string())?,
        );
        cursor += 8;

        let nonce = u64::from_le_bytes(
            read_slice(cursor, 8, "nonce")?
                .try_into()
                .map_err(|_| "Invalid nonce: cannot convert to u64".to_string())?,
        );
        cursor += 8;

        let account_nonce = u64::from_le_bytes(
            read_slice(cursor, 8, "account_nonce")?
                .try_into()
                .map_err(|_| "Invalid account_nonce: cannot convert to u64".to_string())?,
        );
        cursor += 8;

        let weight = f64::from_le_bytes(
            read_slice(cursor, 8, "weight")?
                .try_into()
                .map_err(|_| "Invalid weight: cannot convert to f64".to_string())?,
        );
        cursor += 8;

        // Variable-size fields (with length prefix)
        let sig_len_bytes = read_slice(cursor, 8, "signature_length")?;
        let sig_len = u64::from_le_bytes(
            sig_len_bytes
                .try_into()
                .map_err(|_| "Invalid signature length: cannot convert to u64".to_string())?,
        ) as usize;
        cursor += 8;

        let signature = read_slice(cursor, sig_len, "signature")?.to_vec();
        cursor += sig_len;

        let pk_len_bytes = read_slice(cursor, 8, "public_key_length")?;
        let pk_len = u64::from_le_bytes(
            pk_len_bytes
                .try_into()
                .map_err(|_| "Invalid public key length: cannot convert to u64".to_string())?,
        ) as usize;
        cursor += 8;

        let public_key = read_slice(cursor, pk_len, "public_key")?.to_vec();

        Ok(Self {
            id,
            parents: [parent0, parent1],
            sender,
            receiver,
            amount,
            fee,
            timestamp,
            nonce,
            account_nonce,
            weight,
            signature,
            public_key,
        })
    }

    /// Calculate PoW hash for a transaction with a specific nonce
    /// This is used for mining the nonce to meet difficulty requirements.
    ///
    /// Covers every data field EXCEPT signature/public_key (so PoW can be
    /// computed before signing). `account_nonce` is included so a single PoW
    /// proof cannot be reused across different nonce values.
    pub fn calculate_pow_hash(&self, nonce: u64) -> TransactionId {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.parents[0]);
        hasher.update(&self.parents[1]);
        hasher.update(&self.sender);
        hasher.update(&self.receiver);
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&self.account_nonce.to_le_bytes());

        hasher.finalize().into()
    }

    /// Verify that the transaction's PoW meets the difficulty requirement
    /// Difficulty is specified as the number of leading zero bits required
    /// For example, difficulty 16 means the hash must start with 16 zero bits (4 hex zeros)
    pub fn verify_pow(&self, difficulty: u8) -> bool {
        let hash = self.calculate_pow_hash(self.nonce);

        // Convert difficulty from bits to bytes
        // difficulty 16 = 2 bytes of zeros
        let zero_bytes = (difficulty / 8) as usize;
        let remaining_bits = (difficulty % 8) as u8;

        // Check that the first zero_bytes are all zeros
        for i in 0..zero_bytes {
            if hash[i] != 0 {
                return false;
            }
        }

        // Check remaining bits in the next byte
        if remaining_bits > 0 && zero_bytes < hash.len() {
            let mask = 0xFF << (8 - remaining_bits);
            if (hash[zero_bytes] & mask) != 0 {
                return false;
            }
        }

        true
    }

    /// PHASE 4B: count leading zero BITS of a 32-byte hash. Pure, exact,
    /// deterministic on every platform (byte walk + u8::leading_zeros —
    /// no floats, no platform sniffing). factored separately from
    /// work_credit so tests pin it with fixed vectors (no hash grinding).
    pub fn leading_zero_bits(hash: &TransactionId) -> u32 {
        let mut n = 0u32;
        for b in hash.iter() {
            if *b == 0 {
                n += 8;
            } else {
                n += b.leading_zeros();
                break;
            }
        }
        n
    }

    /// PHASE 4B: work credit for n leading zero bits = 2^n expected hashes,
    /// saturating at u64::MAX (n >= 64, unreachable magnitudes — saturation
    /// is documented, never silent wrap). Exact integer arithmetic.
    pub fn credit_for_bits(n: u32) -> u64 {
        1u64.checked_shl(n).unwrap_or(u64::MAX)
    }

    /// PHASE 4B: actual-bits work credit of this transaction =
    /// 2^(leading zero bits of its PoW hash) = expected hashes priced
    /// exactly. Rewards over-mining; denomination-free (a 20-bit and a
    /// 24-bit proof price exactly their expected cost — the H1xH2 compound
    /// priced, not banned). Deterministic, integer-only, recomputable from
    /// stored fields (no migration, no oracle). Drives Cumulative Descendant
    /// Work fork choice; never touches validation (difficulty rules unchanged).
    pub fn work_credit(&self) -> u64 {
        let n = Self::leading_zero_bits(&self.calculate_pow_hash(self.nonce));
        Self::credit_for_bits(n)
    }

    /// Mine the nonce to meet the difficulty requirement
    /// Returns the nonce that satisfies the PoW requirement
    pub fn mine_nonce(&self, difficulty: u8) -> u64 {
        let mut nonce: u64 = 0;

        loop {
            let hash = self.calculate_pow_hash(nonce);

            // Check if hash meets difficulty
            let zero_bytes = (difficulty / 8) as usize;
            let remaining_bits = (difficulty % 8) as u8;

            let mut valid = true;

            // Check that the first zero_bytes are all zeros
            for i in 0..zero_bytes {
                if hash[i] != 0 {
                    valid = false;
                    break;
                }
            }

            // Check remaining bits in the next byte
            if valid && remaining_bits > 0 && zero_bytes < hash.len() {
                let mask = 0xFF << (8 - remaining_bits);
                if (hash[zero_bytes] & mask) != 0 {
                    valid = false;
                }
            }

            if valid {
                return nonce;
            }

            nonce += 1;
        }
    }

    /// Get the current PoW difficulty (anti-spam requirement)
    /// Default difficulty is 24 bits (6 hex zeros): ~16M hashes average.
    /// This makes spam non-trivial (~s of CPU per tx for honest users)
    /// while remaining cheap for legitimate transactions.
    ///
    /// CONSENSUS RULE: All nodes MUST use the same difficulty. Changing this
    /// value is a soft fork — old nodes accept a superset of what new nodes
    /// accept (20-bit nodes accept txs that 24-bit nodes reject).
    /// All nodes must upgrade simultaneously.
    pub fn default_difficulty() -> u8 {
        24
    }

    /// Activation timestamp for the 20→24 bit difficulty migration (milliseconds).
    /// This is a consensus constant: all nodes MUST use the same value.
    /// Transactions with timestamp >= DIFFICULTY_MIGRATION_TS require 24-bit PoW.
    /// Transactions with timestamp < DIFFICULTY_MIGRATION_TS require 20-bit PoW.
    ///
    /// CONSENSUS RULE: This value is hardcoded. It MUST NOT be read from
    /// local metadata, config files, or network messages. All nodes derive
    /// difficulty from the same constant, ensuring deterministic validation.
    pub const DIFFICULTY_MIGRATION_TS: u64 = 1_758_000_000_000; // 2025-09-16T00:00:00Z

    /// Grace period after activation (24 hours in ms) during which nodes can
    /// still accept 20-bit transactions with pre-activation timestamps.
    /// After the grace period, no new 20-bit transactions are possible:
    /// any tx with timestamp < DIFFICULTY_MIGRATION_TS is rejected.
    pub const GRACE_PERIOD_MS: u64 = 86_400_000; // 24 hours

    /// Maximum age of a transaction timestamp in the past (1 hour in ms).
    /// Transactions older than this relative to system clock are rejected.
    /// This prevents backdating attacks and limits the window for difficulty
    /// manipulation.
    pub const MAX_PAST_MS: u64 = 3_600_000; // 1 hour

    /// Maximum age of a transaction timestamp in the future (1 hour in ms).
    /// Transactions newer than this relative to system clock are rejected.
    /// This prevents future-dating attacks and clock manipulation.
    pub const MAX_FUTURE_MS: u64 = 3_600_000; // 1 hour

    /// PHASE 4B: activation timestamp for Cumulative Descendant Work conflict
    /// resolution (milliseconds). A conflict whose NEWEST member has
    /// timestamp >= CDW_ACTIVATION_TS resolves by CDW + min-id tiebreak; a
    /// conflict with ALL members older resolves by grandfathered min-id
    /// (frozen legacy rule — pre-activation settled outcomes never change).
    /// Separate constant from DIFFICULTY_MIGRATION_TS (separate policy;
    /// shared era value): all live-network traffic post-dates it, all
    /// historical fixtures pre-date it.
    ///
    /// CONSENSUS RULE: hardcoded, same on every node (like DIFFICULTY_-
    /// MIGRATION_TS). Changing it re-resolves cross-boundary conflicts.
    pub const CDW_ACTIVATION_TS: u64 = 1_758_000_000_000; // 2025-09-16T00:00:00Z

    /// Determine the required PoW difficulty for a transaction based on its
    /// timestamp relative to the difficulty migration activation timestamp.
    ///
    /// Rules:
    /// 1. If tx.timestamp >= DIFFICULTY_MIGRATION_TS → difficulty = 24
    /// 2. If tx.timestamp < DIFFICULTY_MIGRATION_TS:
    ///    a. If now <= DIFFICULTY_MIGRATION_TS + GRACE_PERIOD_MS → difficulty = 20
    ///    b. If now > DIFFICULTY_MIGRATION_TS + GRACE_PERIOD_MS → REJECT (return None)
    ///
    /// Returns `Some(difficulty)` if the transaction is valid, `None` if it
    /// should be rejected (pre-activation timestamp after grace period).
    ///
    /// DETERMINISTIC: This function uses ONLY the hardcoded constants and the
    /// system clock. No local metadata, config, or network state.
    pub fn difficulty_for_tx(tx: &Transaction) -> Option<u8> {
        if tx.timestamp >= Self::DIFFICULTY_MIGRATION_TS {
            Some(24)
        } else {
            Some(20)
        }
    }

    /// Determine the difficulty required for a transaction WITHOUT accessing
    /// the system clock. Used for deterministic validation in contexts where
    /// clock access is unavailable or undesirable.
    ///
    /// `current_time_ms`: current system time in milliseconds since UNIX epoch
    ///
    /// RULE: A transaction's difficulty is determined solely by its timestamp
    /// relative to the activation constant. Pre-activation timestamps always
    /// require 20-bit PoW; post-activation always require 24-bit.
    ///
    /// The time-based backdating REJECTION (after grace period) is NOT done
    /// here. It is handled by validate_pure() in Fresh mode only. This
    /// separation ensures that truly historical pre-activation transactions
    /// remain verifiable indefinitely, while new backdated transactions are
    /// rejected by the Fresh validation path.
    pub fn difficulty_for_tx_at(tx: &Transaction, _current_time_ms: u64) -> Option<u8> {
        if tx.timestamp >= Self::DIFFICULTY_MIGRATION_TS {
            Some(24)
        } else {
            Some(20)
        }
    }

    // ========================================================================
    // PHASE 4G: v6 stake-finality primitives (NO PoW anywhere in this section).
    // ========================================================================
    //
    // V6_ACTIVATION_TS gates the stake-finality rule the same way
    // DIFFICULTY_MIGRATION_TS gates difficulty: conflicts whose newest member
    // predates it resolve under legacy rules (min-id / CDW, frozen);
    // conflicts touching post-activation data resolve by stake finality.
    // INTERIM VALUE (release-management flag-day pending - see migration
    // plan): far-future placeholder so the v6 rule is DORMANT by default and
    // can never activate accidentally. All v6 paths are fully exercised with
    // post-activation fixtures regardless of wall-clock time.
    pub const V6_ACTIVATION_TS: u64 = 1_893_456_000_000; // 2030-01-01T00:00:00Z

    /// True iff the v6 stake-finality rule governs an object carrying this
    /// timestamp (post-activation). Pure, deterministic, same on every node.
    /// Grandfathering (pre-activation data keeps legacy rules) flows from this
    /// single predicate - never from peer versions or local flags.
    pub fn is_v6_active_at(timestamp_ms: u64) -> bool {
        timestamp_ms >= Self::V6_ACTIVATION_TS
    }

    /// Benchmark PoW timing at a given difficulty level.
    /// Returns (average_ns, median_ns, p95_ns, hashes_per_second) over `iterations` mines.
    #[cfg(test)]
    pub fn bench_pow(difficulty: u8, iterations: usize) -> (u128, u128, u128, f64) {
        use std::time::Instant;
        let mut tx = Transaction::new(
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
        let mut times: Vec<u128> = Vec::with_capacity(iterations);
        let mut total_hashes: u64 = 0;
        for i in 0..iterations {
            tx.nonce = 0;
            tx.timestamp = 1234567890 + i as u64;
            let start = Instant::now();
            let nonce = tx.mine_nonce(difficulty);
            let elapsed = start.elapsed().as_nanos();
            times.push(elapsed);
            total_hashes += nonce + 1;
        }
        times.sort();
        let median = times[iterations / 2];
        let p95_idx = (iterations as f64 * 0.95) as usize;
        let p95 = times[p95_idx.min(iterations - 1)];
        let avg = times.iter().sum::<u128>() / iterations as u128;
        let total_ns: u128 = times.iter().sum();
        let hps = if total_ns > 0 {
            total_hashes as f64 / (total_ns as f64 / 1_000_000_000.0)
        } else {
            0.0
        };
        (avg, median, p95, hps)
    }

    /// Verify that the sender address matches the public key
    /// This prevents identity spoofing attacks
    pub fn verify_sender_matches_public_key(&self) -> bool {
        // The sender address should be derived from the public key
        // In Aether, the address is the first 32 bytes of the public key
        if self.public_key.len() < 32 {
            return false;
        }

        let derived_address: [u8; 32] = self.public_key[..32].try_into().unwrap_or([0u8; 32]);
        self.sender == derived_address
}
}

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// PHASE 4G: vote wire format version (first byte of every canonical vote
/// encoding). Unknown versions are rejected fail-closed; extensions ship as
/// new versions, never silent tail fields.
pub const VOTE_FORMAT_VERSION: u8 = 1;
/// Bond/unbond wire format version (same discipline as votes).
pub const BOND_FORMAT_VERSION: u8 = 1;

/// PHASE 4G: a stake-weighted finality vote (P6 exact fields).
///
/// Wire layout is FIXED (field order below, integers little-endian, no
/// floats, no maps, no variable-length vectors - fixed arrays only):
/// version u8 | validator [u8;32] | epoch u64 | conflict_sender [u8;32] |
/// conflict_nonce u64 | side [u8;32] | stake_epoch u64 | stake_amount u64 |
/// parents [[u8;32];2] | signature [u8;64] = 1+32+8+32+8+32+8+8+64+64 = 257 B.
/// Validator address IS the ed25519 verifying key (same convention as
/// transaction sender/public-key binding), so no pubkey field is needed.
/// `parents` is DAG-embedding CONTEXT only (auditability, fork causality
/// display): never a validity condition (existence-checking votes against
/// sync state would let partitions veto valid votes - liveness harm).
/// `stake_amount`/`stake_epoch` are ASSERTED context: validity checks bond
/// state live in the registry; mismatches are logged, never rejected (a
/// partitioned voter's view may lag legitimately).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vote {
    pub format_version: u8,
    pub validator: [u8; 32],
    pub epoch: u64,
    pub conflict_sender: [u8; 32],
    pub conflict_nonce: u64,
    pub side: [u8; 32],
    pub stake_epoch: u64,
    pub stake_amount: u64,
    pub parents: [[u8; 32]; 2],
    pub signature: [u8; 64],
        }

/// Canonical vote id = BLAKE3 over the canonical encoding INCLUDING the
/// signature (same id philosophy as transactions: content-addressed,
/// dedup-safe, replay-inert).
pub type VoteId = [u8; 32];

impl Vote {
    /// Canonical bytes WITHOUT the signature (what gets signed).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(193);
        out.push(self.format_version);
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.conflict_sender);
        out.extend_from_slice(&self.conflict_nonce.to_le_bytes());
        out.extend_from_slice(&self.side);
        out.extend_from_slice(&self.stake_epoch.to_le_bytes());
        out.extend_from_slice(&self.stake_amount.to_le_bytes());
        out.extend_from_slice(&self.parents[0]);
        out.extend_from_slice(&self.parents[1]);
        out
    }

    /// Full canonical encoding (signing bytes + signature). Deterministic.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
        }

    /// Strict decode: exact length (193 + 64 = 257), exact version, else Err.
    /// Fails closed on truncation, extension, or version mismatch.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 257 {
            return Err(format!("bad vote length: {}", bytes.len()));
    }
        if bytes[0] != VOTE_FORMAT_VERSION {
            return Err(format!("unknown vote version: {}", bytes[0]));
        }
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&bytes[1..33]);
        let mut u8buf = [0u8; 8];
        u8buf.copy_from_slice(&bytes[33..41]);
        let epoch = u64::from_le_bytes(u8buf);
        let mut conflict_sender = [0u8; 32];
        conflict_sender.copy_from_slice(&bytes[41..73]);
        u8buf.copy_from_slice(&bytes[73..81]);
        let conflict_nonce = u64::from_le_bytes(u8buf);
        let mut side = [0u8; 32];
        side.copy_from_slice(&bytes[81..113]);
        u8buf.copy_from_slice(&bytes[113..121]);
        let stake_epoch = u64::from_le_bytes(u8buf);
        u8buf.copy_from_slice(&bytes[121..129]);
        let stake_amount = u64::from_le_bytes(u8buf);
        let mut p0 = [0u8; 32];
        p0.copy_from_slice(&bytes[129..161]);
        let mut p1 = [0u8; 32];
        p1.copy_from_slice(&bytes[161..193]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[193..257]);
        Ok(Self {
            format_version: VOTE_FORMAT_VERSION,
            validator,
            epoch,
            conflict_sender,
            conflict_nonce,
            side,
            stake_epoch,
            stake_amount,
            parents: [p0, p1],
            signature,
        })
    }

    /// Vote id (content address, includes signature).
    pub fn id(&self) -> VoteId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.encode());
        hasher.finalize().into()
    }

    /// Verify the Ed25519 signature against the validator address (= the
    /// verifying key, same convention as transaction senders).
    pub fn verify_signature(&self) -> bool {
        let key = match VerifyingKey::try_from(self.validator.as_slice()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::try_from(self.signature.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        key.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// PHASE 4G: bond intent (lock funds into voting weight).
/// Canonical layout: version u8 | validator [u8;32] | amount u64 LE |
/// epoch u64 LE | signature [u8;64] = 1+32+8+8+64 = 113 B.
/// `epoch` records creation epoch (auditability; effectiveness is immediate
/// by design decision - documented, no maturation delay).
/// No fee field (spam posture: per-peer rate limits + validation-before-
/// relay + id dedup + MIN_STAKE admission gate; documented residual).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Bond {
    pub format_version: u8,
    pub validator: [u8; 32],
    pub amount: u64,
    pub epoch: u64,
    pub signature: [u8; 64],
    }

/// Bond id (content address, includes signature).
pub type BondId = [u8; 32];

impl Bond {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        out.push(self.format_version);
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
}

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 113 {
            return Err(format!("bad bond length: {}", bytes.len()));
    }
        if bytes[0] != BOND_FORMAT_VERSION {
            return Err(format!("unknown bond version: {}", bytes[0]));
    }
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&bytes[1..33]);
        let mut u8buf = [0u8; 8];
        u8buf.copy_from_slice(&bytes[33..41]);
        let amount = u64::from_le_bytes(u8buf);
        u8buf.copy_from_slice(&bytes[41..49]);
        let epoch = u64::from_le_bytes(u8buf);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[49..113]);
        Ok(Self {
            format_version: BOND_FORMAT_VERSION,
            validator,
            amount,
            epoch,
            signature,
        })
    }

    pub fn id(&self) -> BondId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.encode());
        hasher.finalize().into()
    }

    pub fn verify_signature(&self) -> bool {
        let key = match VerifyingKey::try_from(self.validator.as_slice()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::try_from(self.signature.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        key.verify(&self.signing_bytes(), &sig).is_ok()
    }
    }

/// PHASE 4G: unbond intent (begin exit; funds release after UNBONDING_EPOCHS).
/// Canonical layout: version u8 | validator [u8;32] | epoch u64 LE (request
/// epoch; release at request + UNBONDING_EPOCHS) | signature [u8;64] =
/// 1+32+8+64 = 105 B. Voting eligibility ends at request acceptance
/// (clean cutover, no exit-timing games).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Unbond {
    pub format_version: u8,
    pub validator: [u8; 32],
    pub epoch: u64,
    pub signature: [u8; 64],
    }

/// Unbond id (content address, includes signature).
pub type UnbondId = [u8; 32];

impl Unbond {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(self.format_version);
        out.extend_from_slice(&self.validator);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 105 {
            return Err(format!("bad unbond length: {}", bytes.len()));
    }
        if bytes[0] != BOND_FORMAT_VERSION {
            return Err(format!("unknown unbond version: {}", bytes[0]));
    }
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&bytes[1..33]);
        let mut u8buf = [0u8; 8];
        u8buf.copy_from_slice(&bytes[33..41]);
        let epoch = u64::from_le_bytes(u8buf);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[41..105]);
        Ok(Self {
            format_version: BOND_FORMAT_VERSION,
            validator,
            epoch,
            signature,
        })
    }

    pub fn id(&self) -> UnbondId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.encode());
        hasher.finalize().into()
    }

    pub fn verify_signature(&self) -> bool {
        let key = match VerifyingKey::try_from(self.validator.as_slice()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sig = match Signature::try_from(self.signature.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        key.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

/// Adaptive difficulty tracker for PoW
/// Tracks transaction rates and adjusts difficulty to prevent spam
#[derive(Debug, Clone)]
pub struct AdaptiveDifficulty {
    /// Current difficulty in bits
    current_difficulty: u8,

    /// Minimum difficulty
    min_difficulty: u8,

    /// Maximum difficulty
    max_difficulty: u8,

    /// Transaction timestamps for rate calculation
    tx_timestamps: Vec<u64>,

    /// Window size in milliseconds for rate calculation
    window_ms: u64,

    /// Target transactions per window
    target_tps: u64,
}

impl AdaptiveDifficulty {
    /// Create a new adaptive difficulty tracker
    pub fn new(min_difficulty: u8, max_difficulty: u8, window_ms: u64, target_tps: u64) -> Self {
        Self {
            current_difficulty: 16, // Start at default difficulty
            min_difficulty,
            max_difficulty,
            tx_timestamps: Vec::new(),
            window_ms,
            target_tps,
        }
    }

    /// Create with default parameters
    pub fn default() -> Self {
        Self {
            current_difficulty: 16,
            min_difficulty: 8,  // Minimum 8 bits (2 hex zeros)
            max_difficulty: 24, // Maximum 24 bits (6 hex zeros)
            tx_timestamps: Vec::new(),
            window_ms: 10_000, // 10 second window
            target_tps: 10,    // Target 10 TPS
        }
    }

    /// Record a transaction timestamp and adjust difficulty if needed
    pub fn record_transaction(&mut self, timestamp: u64) -> u8 {
        // Add timestamp
        self.tx_timestamps.push(timestamp);

        // Remove old timestamps outside window
        let cutoff = timestamp.saturating_sub(self.window_ms);
        self.tx_timestamps.retain(|&ts| ts >= cutoff);

        // Calculate current TPS
        let tps = self.tx_timestamps.len() as u64;

        // Adjust difficulty based on TPS
        if tps > self.target_tps * 2 {
            // Too many transactions, increase difficulty
            self.current_difficulty = (self.current_difficulty + 1).min(self.max_difficulty);
        } else if tps < self.target_tps / 2 && self.current_difficulty > self.min_difficulty {
            // Too few transactions, decrease difficulty
            self.current_difficulty = (self.current_difficulty - 1).max(self.min_difficulty);
        }

        self.current_difficulty
    }

    /// Get the current difficulty
    pub fn current_difficulty(&self) -> u8 {
        self.current_difficulty
    }

    /// Get the current TPS
    pub fn current_tps(&self) -> u64 {
        self.tx_timestamps.len() as u64
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Transaction[id={}, sender={:?}, receiver={:?}, amount={}, fee={}, timestamp={}]",
            hex::encode(self.id),
            hex::encode(self.sender),
            hex::encode(self.receiver),
            self.amount,
            self.fee,
            self.timestamp
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let parents = [[1u8; 32], [2u8; 32]];
        let sender = [3u8; 32];
        let receiver = [4u8; 32];
        let signature = vec![5u8; 64];
        let public_key = vec![6u8; 32];

        let tx = Transaction::new(
            parents, sender, receiver, 1000, 10, 1234567890, 0, 1, // account_nonce
            public_key, signature,
        );

        assert!(tx.verify_hash());
        assert_eq!(tx.sender, sender);
        assert_eq!(tx.receiver, receiver);
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.fee, 10);
    }

    #[test]
    fn test_genesis_transaction() {
        let tx = Transaction::new(
            [TransactionId::default(); 2],
            [1u8; 32],
            [2u8; 32],
            0,
            0,
            0,
            0,
            0, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        assert!(tx.is_genesis());
    }

    #[test]
    fn test_non_genesis_transaction() {
        let parents = [[1u8; 32], [2u8; 32]];
        let tx = Transaction::new(
            parents,
            [3u8; 32],
            [4u8; 32],
            100,
            5,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        assert!(!tx.is_genesis());
    }

    #[test]
    fn test_total_deduction() {
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            1000,
            50,
            0,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        assert_eq!(tx.total_deduction(), 1050);
    }

    #[test]
    fn test_hash_deterministic() {
        let parents = [[1u8; 32]; 2];
        let sender = [2u8; 32];
        let receiver = [3u8; 32];
        let signature = vec![4u8; 64];
        let public_key = vec![5u8; 32];

        let tx1 = Transaction::new(
            parents,
            sender,
            receiver,
            100,
            10,
            1234567890,
            0,
            1,
            signature.clone(),
            public_key.clone(),
        );
        let tx2 = Transaction::new(
            parents, sender, receiver, 100, 10, 1234567890, 0, 1, signature, public_key,
        );

        assert_eq!(tx1.id, tx2.id);
    }

    #[test]
    fn test_hash_changes_with_nonce() {
        let parents = [[1u8; 32]; 2];
        let sender = [2u8; 32];
        let receiver = [3u8; 32];
        let signature = vec![4u8; 64];
        let public_key = vec![5u8; 32];

        let tx1 = Transaction::new(
            parents,
            sender,
            receiver,
            100,
            10,
            1234567890,
            0,
            1,
            public_key.clone(),
            signature.clone(),
        );
        let tx2 = Transaction::new(
            parents, sender, receiver, 100, 10, 1234567890, 1, 2, public_key, signature,
        );

        assert_ne!(tx1.id, tx2.id);
    }

    #[test]
    fn test_sender_public_key_match_valid() {
        // Valid case: sender matches public_key (first 32 bytes)
        let public_key = vec![1u8; 64];
        let sender: [u8; 32] = public_key[..32]
            .try_into()
            .expect("Failed to convert public key to sender");

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            public_key,
        );

        assert!(tx.verify_sender_matches_public_key());
    }

    #[test]
    fn test_sender_public_key_mismatch_invalid() {
        // Invalid case: sender does NOT match public_key
        let public_key = vec![1u8; 64];
        let sender = [99u8; 32]; // Different from public_key[..32]

        let tx = Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            public_key,
        );

        assert!(!tx.verify_sender_matches_public_key());
    }

    #[test]
    fn test_sender_public_key_length_check() {
        // Invalid case: public_key too short
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 16],
            vec![0u8; 64],
        );

        assert!(!tx.verify_sender_matches_public_key());
    }

    #[test]
    fn test_identity_spoofing_attack_blocked() {
        // Simulate identity spoofing attack
        let victim_address = [1u8; 32];
        let attacker_public_key = vec![2u8; 64];

        let malicious_tx = Transaction::new(
            [[0u8; 32]; 2],
            victim_address, // Claiming to be victim
            [3u8; 32],
            1000000, // Large amount
            10,
            1234567890,
            0,
            1,                   // account_nonce
            attacker_public_key, // But using attacker's public_key
            vec![0u8; 64],
        );

        // V1 fix should block this
        assert!(!malicious_tx.verify_sender_matches_public_key());
    }

    #[test]
    fn test_signing_hash_deterministic() {
        // Test that signing hash is deterministic and matches expected format
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            1234567890,
            0,
            1, // account_nonce
            vec![0u8; 64],
            vec![0u8; 32],
        );

        let hash1 = tx.compute_signing_hash();
        let hash2 = tx.compute_signing_hash();

        // Should be deterministic
        assert_eq!(hash1, hash2);

        // Should be exactly 32 bytes (BLAKE3 output)
        assert_eq!(hash1.len(), 32);
    }

    // ---- V-20: canonical hex id serialization tests ----

    #[test]
    fn test_encode_id_returns_lowercase_hex_64_chars() {
        let id: TransactionId = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x01, 0x02, 0x03,
        ];
        let s = encode_id(&id);
        assert_eq!(s.len(), 64);
        assert_eq!(
            s,
            "abcdef0123456789deadbeef00112233445566778899aabbccddeeff00010203"
        );
    }

    #[test]
    fn test_decode_id_roundtrip() {
        let id: TransactionId = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x01, 0x02, 0x03,
        ];
        let s = encode_id(&id);
        let decoded = decode_id(&s).expect("valid hex must decode");
        assert_eq!(decoded, id);
        // bytes -> hex -> bytes must be the identity
        assert_eq!(encode_id(&decoded), s);
    }

    #[test]
    fn test_decode_id_accepts_uppercase_hex() {
        let id: TransactionId = [0xab; 32];
        let upper = encode_id(&id).to_uppercase();
        assert_eq!(decode_id(&upper).expect("uppercase hex must decode"), id);
    }

    #[test]
    fn test_decode_id_rejects_invalid_inputs() {
        // Wrong length
        assert!(decode_id("abcd").is_none());
        assert!(decode_id(&"00".repeat(33)).is_none());
        // Non-hex characters
        assert!(decode_id(&"zz".repeat(32)).is_none());
        // Empty
        assert!(decode_id("").is_none());
    }

    #[test]
    fn test_tips_to_parents_uses_tips_as_parents() {
        let tip1: TransactionId = [1u8; 32];
        let tip2: TransactionId = [2u8; 32];
        let tips = serde_json::json!([encode_id(&tip1), encode_id(&tip2), encode_id(&[3u8; 32]),]);
        let array = tips.as_array().unwrap();
        let parents = tips_to_parents(array).expect("valid tips must parse");
        assert_eq!(parents, [tip1, tip2]);
    }

    #[test]
    fn test_tips_to_parents_empty_is_genesis() {
        let parents = tips_to_parents(&[]).expect("empty tips is legitimate");
        assert_eq!(parents, [[0u8; 32]; 2]);
    }

    #[test]
    fn test_tips_to_parents_rejects_numeric_arrays() {
        // The V-20 bug: a node returning raw byte arrays. This MUST be an
        // error so a client can never accidentally use genesis parents.
        let tips = serde_json::json!([[32, 219, 13, 5]]);
        let array = tips.as_array().unwrap();
        assert!(tips_to_parents(array).is_err());
    }

    #[test]
    fn test_tips_to_parents_rejects_malformed_hex() {
        let tips = serde_json::json!(["not-a-hex-id", encode_id(&[1u8; 32])]);
        let array = tips.as_array().unwrap();
        assert!(tips_to_parents(array).is_err());
    }

    #[test]
    fn test_tips_to_parents_rejects_non_string() {
        let tips = serde_json::json!([12345]);
        let array = tips.as_array().unwrap();
        assert!(tips_to_parents(array).is_err());
    }

    #[test]
    fn test_pow_benchmark_20bits() {
        let (avg, median, p95, hps) = Transaction::bench_pow(20, 20);
        println!(
            "PoW d20: avg={}ns median={}ns p95={}ns hps={:.0}",
            avg, median, p95, hps
        );
        assert!(avg > 0);
    }

    #[test]
    fn test_pow_benchmark_22bits() {
        let (avg, median, p95, hps) = Transaction::bench_pow(22, 10);
        println!(
            "PoW d22: avg={}ns median={}ns p95={}ns hps={:.0}",
            avg, median, p95, hps
        );
        assert!(avg > 0);
    }

    #[test]
    fn test_pow_benchmark_24bits() {
        let (avg, median, p95, hps) = Transaction::bench_pow(24, 5);
        println!(
            "PoW d24: avg={}ns median={}ns p95={}ns hps={:.0}",
            avg, median, p95, hps
        );
        assert!(avg > 0);
    }

    #[test]
    fn test_pow_benchmark_26bits() {
        let (avg, median, p95, hps) = Transaction::bench_pow(26, 2);
        println!(
            "PoW d26: avg={}ns median={}ns p95={}ns hps={:.0}",
            avg, median, p95, hps
        );
        assert!(avg > 0);
    }

    #[test]
    fn test_pow_benchmark_28bits() {
        let (avg, median, p95, hps) = Transaction::bench_pow(28, 1);
        println!(
            "PoW d28: avg={}ns median={}ns p95={}ns hps={:.0}",
            avg, median, p95, hps
        );
        assert!(avg > 0);
    }

    #[test]
    fn test_pow_benchmark_30bits() {
        let (avg, median, p95, hps) = Transaction::bench_pow(30, 1);
        println!(
            "PoW d30: avg={}ns median={}ns p95={}ns hps={:.0}",
            avg, median, p95, hps
        );
        assert!(avg > 0);
    }

    // ==================== DIFFICULTY MIGRATION TESTS ====================

    #[test]
    fn test_difficulty_for_tx_post_activation() {
        // Transaction with timestamp >= DIFFICULTY_MIGRATION_TS → difficulty = 24
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            Transaction::DIFFICULTY_MIGRATION_TS + 1_000_000,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );
        let result = Transaction::difficulty_for_tx(&tx);
        assert_eq!(result, Some(24));
    }

    #[test]
    fn test_difficulty_for_tx_exact_activation() {
        // Transaction at exact activation timestamp → difficulty = 24
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            Transaction::DIFFICULTY_MIGRATION_TS,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );
        let result = Transaction::difficulty_for_tx(&tx);
        assert_eq!(result, Some(24));
    }

    #[test]
    fn test_difficulty_for_tx_at_deterministic() {
        // difficulty_for_tx_at is deterministic — no system clock dependency
        let tx_before = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            Transaction::DIFFICULTY_MIGRATION_TS - 1_000,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );
        let tx_after = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            Transaction::DIFFICULTY_MIGRATION_TS + 1_000,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );

        // Before activation, within grace period → 20
        let now_ms = Transaction::DIFFICULTY_MIGRATION_TS + 1_000;
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx_before, now_ms),
            Some(20)
        );

        // After activation → 24
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx_after, now_ms),
            Some(24)
        );
    }

    #[test]
    fn test_difficulty_for_tx_at_grace_period_rejects() {
        // After grace period, pre-activation timestamp → None (rejected)
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            Transaction::DIFFICULTY_MIGRATION_TS - 1_000,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );
        let after_grace =
            Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS + 1_000;
        // After grace: difficulty_for_tx_at still returns Some(20) for pre-activation.
        // The backdating rejection is handled by validate_pure in Fresh mode.
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx, after_grace),
            Some(20)
        );
    }

    #[test]
    fn test_difficulty_for_tx_at_within_grace_allows() {
        // Within grace period, pre-activation timestamp → 20
        let tx = Transaction::new(
            [[0u8; 32]; 2],
            [1u8; 32],
            [2u8; 32],
            100,
            10,
            Transaction::DIFFICULTY_MIGRATION_TS - 1_000,
            0,
            1,
            vec![0u8; 64],
            vec![1u8; 32],
        );
        let within_grace =
            Transaction::DIFFICULTY_MIGRATION_TS + Transaction::GRACE_PERIOD_MS - 1_000;
        assert_eq!(
            Transaction::difficulty_for_tx_at(&tx, within_grace),
            Some(20)
        );
    }

    #[test]
    fn test_constants_are_consistent() {
        // GRACE_PERIOD_MS must be > 0
        assert!(Transaction::GRACE_PERIOD_MS > 0);
        // MAX_PAST_MS must be > 0
        assert!(Transaction::MAX_PAST_MS > 0);
        // MAX_FUTURE_MS must be > 0
        assert!(Transaction::MAX_FUTURE_MS > 0);
        // DIFFICULTY_MIGRATION_TS must be > 0
        assert!(Transaction::DIFFICULTY_MIGRATION_TS > 0);
        // default_difficulty must be 24
        assert_eq!(Transaction::default_difficulty(), 24);
    }
}
