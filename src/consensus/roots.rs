//! L2 cryptographic commitments (A-06.6-AQ `N-CKPT-5`, A-06.6-AR `ARCH-1`).
//!
//! Domain-separated BLAKE3 hashing, matching the primitive already used
//! throughout the repository (`blake3::Hasher`, see `anchor.rs`,
//! `transaction.rs`, `stake.rs`).
//!
//! # What these functions guarantee
//!
//! - **Determinism**: identical logical content always yields identical
//!   bytes, independently of insertion order (inputs are sorted internally).
//! - **Type separation**: two objects of different kinds never share a hash
//!   preimage, because every hash is prefixed with a distinct domain tag.
//!
//! # What these functions do NOT guarantee
//!
//! A root hash is **not** a validity proof. It commits to bytes; it says
//! nothing about whether those bytes describe a legitimate ledger state, a
//! quorate validator set, or an authorised transition. Those properties come
//! from the rules in `checkpoint.rs` / `readiness.rs` and from the (future)
//! QC verification layer — never from the hash itself.
//!
//! A root also does not prove **availability**: a valid root can exist for
//! data that no node still stores.

use crate::consensus::generation::{GenerationId, ValidatorId, ValidatorWeight};

/// Domain tag for a merkle **leaf**.
pub const DOMAIN_LEAF: &[u8] = b"AETHER-L2-LEAF-v1";
/// Domain tag for a merkle **internal node**.
pub const DOMAIN_NODE: &[u8] = b"AETHER-L2-NODE-v1";
/// Domain tag for the validator-set root.
pub const DOMAIN_VALIDATOR_SET: &[u8] = b"AETHER-L2-VALSET-v1";
/// Domain tag for the commitment to L1 finality records (`finalized_root`).
pub const DOMAIN_FINALITY: &[u8] = b"AETHER-L2-FINAL-v1";
/// Domain tag for the checkpoint state root.
pub const DOMAIN_STATE: &[u8] = b"AETHER-L2-STATE-v1";
/// Domain tag for a checkpoint identifier.
pub const DOMAIN_CHECKPOINT: &[u8] = b"AETHER-L2-CKPT-v1";
/// Domain tag for a READY attestation digest.
pub const DOMAIN_READY: &[u8] = b"AETHER-L2-READY-v1";
/// Domain tag for a generation identifier.
pub const DOMAIN_GENERATION: &[u8] = b"AETHER-L2-GEN-v1";

/// Hash of `domain` followed by every part, each length-prefixed.
///
/// Length prefixing means `[b"ab", b"c"]` and `[b"a", b"bc"]` produce
/// different digests: concatenation ambiguity is removed by construction.
pub fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u32).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Canonical merkle root over `leaves`.
///
/// Leaves are **sorted** before combination, so the root is independent of
/// insertion order. Odd nodes are **promoted unchanged** to the next level
/// (never duplicated — duplication would let distinct trees share a root).
/// An empty set still has a defined root, so "no entries" cannot be confused
/// with "one entry whose hash is zero".
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return hash_parts(DOMAIN_NODE, &[&0u64.to_le_bytes()[..]]);
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    level.sort_unstable();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(hash_parts(DOMAIN_NODE, &[&level[i][..], &level[i + 1][..]]));
            } else {
                next.push(level[i]);
            }
            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Leaf commitment for one validator entry.
pub fn validator_leaf(id: &ValidatorId, weight: ValidatorWeight) -> [u8; 32] {
    hash_parts(DOMAIN_LEAF, &[&id.0[..], &weight.get().to_le_bytes()[..]])
}

/// `validator_set_root` over `(id, weight)` pairs.
///
/// Order-independent: leaves are sorted inside `merkle_root`.
pub fn validator_set_root(members: &[(ValidatorId, ValidatorWeight)]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = members
        .iter()
        .map(|(id, w)| validator_leaf(id, *w))
        .collect();
    hash_parts(DOMAIN_VALIDATOR_SET, &[&merkle_root(&leaves)[..]])
}

/// One committed L1 finality record.
///
/// Shape mirrors `crate::stake::FinalizedRecord` (`winner`, `epoch`,
/// `supporting_weight`, `supporting_votes`, `eligible_total`), keyed by the
/// conflict key `(sender, nonce)` and with the vote ids replaced by their
/// root so the commitment stays fixed-size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalityEntry {
    /// Conflict-key sender.
    pub sender: [u8; 32],
    /// Conflict-key nonce.
    pub nonce: u64,
    /// Committed winner.
    pub winner: [u8; 32],
    /// Epoch at decision time.
    pub epoch: u64,
    /// Supporting weight pinned at decision time.
    pub supporting_weight: u64,
    /// Eligible total pinned at decision time.
    pub eligible_total: u64,
    /// Root over the pinned supporting vote ids.
    pub votes_root: [u8; 32],
}

impl FinalityEntry {
    /// Canonical sort key: `(sender, nonce)` ascending.
    fn key(&self) -> ([u8; 32], u64) {
        (self.sender, self.nonce)
    }

    /// Leaf commitment for this record.
    pub fn leaf(&self) -> [u8; 32] {
        hash_parts(
            DOMAIN_LEAF,
            &[
                &self.sender[..],
                &self.nonce.to_le_bytes()[..],
                &self.winner[..],
                &self.epoch.to_le_bytes()[..],
                &self.supporting_weight.to_le_bytes()[..],
                &self.eligible_total.to_le_bytes()[..],
                &self.votes_root[..],
            ],
        )
    }
}

/// `finalized_root`: commitment over L1 finality records.
///
/// Sorted by `(sender, nonce)` so the same set always yields the same root.
/// This is the value a checkpoint engages to make an L1 finality
/// non-disappearable without detection (AR migration step 3).
pub fn finalized_root(entries: &[FinalityEntry]) -> [u8; 32] {
    let mut sorted: Vec<&FinalityEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.key());
    let leaves: Vec<[u8; 32]> = sorted.iter().map(|e| e.leaf()).collect();
    hash_parts(DOMAIN_FINALITY, &[&merkle_root(&leaves)[..]])
}

/// `state_root`: commits the five component roots.
///
/// Fixed arity and fixed order — no optional members, so a missing component
/// cannot be silently omitted.
pub fn state_root(
    balances_root: [u8; 32],
    nonces_root: [u8; 32],
    applied_root: [u8; 32],
    validators_root: [u8; 32],
    finality_root: [u8; 32],
) -> [u8; 32] {
    hash_parts(
        DOMAIN_STATE,
        &[
            &balances_root[..],
            &nonces_root[..],
            &applied_root[..],
            &validators_root[..],
            &finality_root[..],
        ],
    )
}

/// Root over an unordered set of validator ids.
pub fn id_set_root(ids: &[ValidatorId]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = ids
        .iter()
        .map(|id| hash_parts(DOMAIN_LEAF, &[&id.0[..]]))
        .collect();
    merkle_root(&leaves)
}

/// Root over an unordered list of opaque identifiers.
pub fn ids_root(ids: &[[u8; 32]]) -> [u8; 32] {
    merkle_root(ids)
}

/// Generation identifier from its immutable content.
///
/// Deliberately excludes `state`: a generation keeps its identity while its
/// lifecycle advances. Includes the set root, so any change of membership or
/// weight produces a different generation.
pub fn generation_id_from(number: u64, epoch_pin: u64, set_root: [u8; 32]) -> GenerationId {
    GenerationId(hash_parts(
        DOMAIN_GENERATION,
        &[
            &number.to_le_bytes()[..],
            &epoch_pin.to_le_bytes()[..],
            &set_root[..],
        ],
    ))
}
