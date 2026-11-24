//! L2 validator registry: the cryptographic set that decides voting rights.
//!
//! # What the registry is
//!
//! A registry is the per-generation set of validators, each with:
//! - a [`ValidatorId`] (derived, not chosen);
//! - an Ed25519 public key;
//! - a voting weight;
//! - an admissibility status.
//!
//! # What it commits
//!
//! Two distinct commitments, both needed:
//!
//! | Commitment | Content | Purpose |
//! |---|---|---|
//! | [`ValidatorRegistry::root`] | generation ‖ id ‖ public key ‖ weight ‖ admissibility | binds **everything** that can change voting rights |
//! | [`ValidatorRegistry::set_root`] | id ‖ weight | bridge to `consensus::generation` / `consensus::checkpoint` |
//!
//! The second exists because `consensus::checkpoint::Checkpoint::validator_set_root`
//! is defined by the (unmodified) AS layer over `(id, weight)` pairs. Keeping the
//! two values distinct lets the richer registry root bind key material and
//! admissibility **without** changing any AS file.
//!
//! # What a root does NOT prove
//!
//! A matching root proves the registry bytes were not altered. It proves nothing
//! about whether the validators are honest, independent, or reachable. **A
//! distinct Ed25519 key is not a distinct operator.** Operator independence is an
//! external assumption (`A-INDEP` in A-06.6-AQ §5); the protocol can only enforce
//! that a key appears once.

use std::fmt;

use thiserror::Error;

use crate::consensus::generation::{GenerationId, ValidatorId, ValidatorWeight};
use crate::consensus::roots::{merkle_root, validator_set_root};
use crate::l2crypto::frame::{frame_hash, le64};

/// Encoding version of [`ValidatorRegistry`].
pub const REGISTRY_FORMAT_VERSION: u8 = 1;

/// Domain tag for a validator identifier.
pub const DOMAIN_VALIDATOR_ID: &[u8] = b"AETHER-L2-VID-v1";
/// Domain tag for the registry root.
pub const DOMAIN_REGISTRY: &[u8] = b"AETHER-L2-REGISTRY-v1";
/// Domain tag for a registry leaf.
pub const DOMAIN_REGISTRY_LEAF: &[u8] = b"AETHER-L2-REGISTRY-LEAF-v1";

/// Fixed size of one encoded entry: id(32) + key(32) + weight(8) + status(1).
const ENTRY_LEN: usize = 73;

/// Derive a validator identifier from its public key.
///
/// The id is **not** the public key: keeping them separate means a public key
/// can appear under exactly one id (checked in [`ValidatorRegistry::new`]), and
/// leaves room for key rotation without changing the on-chain identity.
///
/// Note the deliberate divergence from L1, where `validator` **is** the
/// verifying key (`transaction.rs`). L2 ids are opaque; the binding is enforced
/// by this function plus the `IdKeyMismatch` check.
pub fn validator_id(public_key: &[u8; 32]) -> ValidatorId {
    ValidatorId(frame_hash(DOMAIN_VALIDATOR_ID, &[&public_key[..]]))
}

/// Whether a validator may cast votes in its generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Admissibility {
    /// Counted in the denominator and may vote.
    Eligible,
    /// Kept in the set for audit, counted in neither numerator nor denominator.
    Suspended,
    /// Permanently out; kept only so the root changes when it happens.
    Removed,
}

impl Admissibility {
    /// Stable wire encoding.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Eligible => 0,
            Self::Suspended => 1,
            Self::Removed => 2,
        }
    }

    /// Strict inverse of [`Self::as_u8`].
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Eligible,
            1 => Self::Suspended,
            2 => Self::Removed,
            _ => return None,
        })
    }

    /// Whether this status grants voting rights.
    pub fn may_vote(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

impl fmt::Display for Admissibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Eligible => "eligible",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        })
    }
}

/// One registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryEntry {
    /// Derived identifier.
    pub id: ValidatorId,
    /// Ed25519 public key.
    pub public_key: [u8; 32],
    /// Voting weight.
    pub weight: ValidatorWeight,
    /// Admissibility status.
    pub admissibility: Admissibility,
}

impl RegistryEntry {
    /// Build an entry, deriving the id from the key.
    pub fn new(public_key: [u8; 32], weight: ValidatorWeight, admissibility: Admissibility) -> Self {
        Self {
            id: validator_id(&public_key),
            public_key,
            weight,
            admissibility,
        }
    }

    /// Canonical leaf commitment.
    pub fn leaf(&self) -> [u8; 32] {
        frame_hash(
            DOMAIN_REGISTRY_LEAF,
            &[
                &self.id.0[..],
                &self.public_key[..],
                &le64(self.weight.get())[..],
                &[self.admissibility.as_u8()][..],
            ],
        )
    }
}

/// Registry construction and decoding failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// No entry.
    #[error("validator registry is empty")]
    EmptyRegistry,

    /// The same identifier appears twice.
    #[error("duplicate validator id {0}")]
    DuplicateValidatorId(ValidatorId),

    /// The same public key appears twice.
    #[error("duplicate public key {}", hex::encode(.0))]
    DuplicatePublicKey([u8; 32]),

    /// A validator with no weight could never contribute to a quorum.
    #[error("validator {0} has zero weight")]
    ZeroWeight(ValidatorId),

    /// The stored identifier is not the one derived from the key.
    #[error("validator id does not match its public key")]
    IdKeyMismatch {
        /// Identifier found in the record.
        id: ValidatorId,
        /// Identifier derived from the stored key.
        derived: ValidatorId,
    },

    /// Sum of weights does not fit in `u64`.
    #[error("registry weight overflow")]
    TotalWeightOverflow,

    /// Record bytes are truncated or have trailing data.
    #[error("malformed registry encoding (expected {expected} bytes, got {actual})")]
    MalformedEncoding {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Unknown encoding version.
    #[error("unsupported registry version {0}")]
    UnsupportedVersion(u8),

    /// Unknown admissibility byte.
    #[error("unknown admissibility byte {0}")]
    UnknownAdmissibility(u8),

    /// Entries are not sorted by identifier.
    #[error("registry entries are not in canonical order")]
    NonCanonicalOrder,

    /// A computed root does not match the expected one.
    #[error("registry root mismatch")]
    RootMismatch {
        /// Expected root.
        expected: [u8; 32],
        /// Recomputed root.
        actual: [u8; 32],
    },
}

/// The validator set of one generation, with keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRegistry {
    generation: GenerationId,
    entries: Vec<RegistryEntry>,
}

impl ValidatorRegistry {
    /// Build a registry from entries given in any order.
    ///
    /// Rejects: empty set, duplicate id, duplicate public key, zero weight, and
    /// an id that does not match its key. Nothing is silently normalised except
    /// the ordering.
    pub fn new(
        generation: GenerationId,
        entries: &[RegistryEntry],
    ) -> Result<Self, RegistryError> {
        if entries.is_empty() {
            return Err(RegistryError::EmptyRegistry);
        }
        let mut sorted: Vec<RegistryEntry> = entries.to_vec();
        sorted.sort_by_key(|e| e.id);

        for pair in sorted.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(RegistryError::DuplicateValidatorId(pair[0].id));
            }
        }

        let mut keys: Vec<[u8; 32]> = sorted.iter().map(|e| e.public_key).collect();
        keys.sort_unstable();
        for pair in keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(RegistryError::DuplicatePublicKey(pair[0]));
            }
        }

        for entry in &sorted {
            if entry.weight.get() == 0 {
                return Err(RegistryError::ZeroWeight(entry.id));
            }
            let derived = validator_id(&entry.public_key);
            if derived != entry.id {
                return Err(RegistryError::IdKeyMismatch {
                    id: entry.id,
                    derived,
                });
            }
        }

        let mut total: u128 = 0;
        for entry in &sorted {
            total += entry.weight.get() as u128;
        }
        if total > u64::MAX as u128 {
            return Err(RegistryError::TotalWeightOverflow);
        }

        Ok(Self {
            generation,
            entries: sorted,
        })
    }

    /// Generation this registry belongs to.
    pub fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Entries, sorted by id.
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry has no entry (never true after `new`).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lookup by identifier.
    pub fn get(&self, id: &ValidatorId) -> Option<&RegistryEntry> {
        self.entries
            .binary_search_by_key(id, |e| e.id)
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Weight of `id` **if it may vote**, else `None`.
    ///
    /// This is the only sanctioned source of voting weight. A vote that carries
    /// its own weight is simply ignored.
    pub fn voting_weight(&self, id: &ValidatorId) -> Option<ValidatorWeight> {
        self.get(id)
            .filter(|e| e.admissibility.may_vote())
            .map(|e| e.weight)
    }

    /// Sum of weights over admissible entries — the quorum denominator.
    pub fn total_voting_weight(&self) -> ValidatorWeight {
        let sum: u128 = self
            .entries
            .iter()
            .filter(|e| e.admissibility.may_vote())
            .map(|e| e.weight.get() as u128)
            .sum();
        ValidatorWeight(sum.min(u64::MAX as u128) as u64)
    }

    /// Registry root: binds generation, key, weight and admissibility.
    pub fn root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self.entries.iter().map(|e| e.leaf()).collect();
        frame_hash(
            DOMAIN_REGISTRY,
            &[&self.generation.0[..], &merkle_root(&leaves)[..]],
        )
    }

    /// Set root over `(id, weight)` only — the bridge to
    /// `consensus::generation::Generation::set_root()` and to a checkpoint's
    /// `validator_set_root`.
    pub fn set_root(&self) -> [u8; 32] {
        let pairs: Vec<(ValidatorId, ValidatorWeight)> =
            self.entries.iter().map(|e| (e.id, e.weight)).collect();
        validator_set_root(&pairs)
    }

    /// Check `root()` against an expected commitment.
    pub fn check_root(&self, expected: [u8; 32]) -> Result<(), RegistryError> {
        let actual = self.root();
        if actual != expected {
            return Err(RegistryError::RootMismatch { expected, actual });
        }
        Ok(())
    }

    /// Canonical encoding:
    /// `version(1) ‖ generation(32) ‖ count(u32) ‖ [id(32) ‖ key(32) ‖ weight(8) ‖ status(1)]×count`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 4 + ENTRY_LEN * self.entries.len());
        out.push(REGISTRY_FORMAT_VERSION);
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.id.0);
            out.extend_from_slice(&entry.public_key);
            out.extend_from_slice(&le64(entry.weight.get()));
            out.push(entry.admissibility.as_u8());
        }
        out
    }

    /// Strict canonical decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, RegistryError> {
        if bytes.len() < 1 + 32 + 4 {
            return Err(RegistryError::MalformedEncoding {
                expected: 1 + 32 + 4,
                actual: bytes.len(),
            });
        }
        if bytes[0] != REGISTRY_FORMAT_VERSION {
            return Err(RegistryError::UnsupportedVersion(bytes[0]));
        }
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&bytes[1..33]);
        let mut count_buf = [0u8; 4];
        count_buf.copy_from_slice(&bytes[33..37]);
        let count = u32::from_le_bytes(count_buf) as usize;
        let expected = 37usize
            .checked_add(ENTRY_LEN.checked_mul(count).ok_or(
                RegistryError::MalformedEncoding {
                    expected: usize::MAX,
                    actual: bytes.len(),
                },
            )?)
            .ok_or(RegistryError::MalformedEncoding {
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if bytes.len() != expected {
            return Err(RegistryError::MalformedEncoding {
                expected,
                actual: bytes.len(),
            });
        }
        let mut entries = Vec::with_capacity(count);
        let mut p = 37usize;
        for _ in 0..count {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes[p..p + 32]);
            p += 32;
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[p..p + 32]);
            p += 32;
            let mut w = [0u8; 8];
            w.copy_from_slice(&bytes[p..p + 8]);
            p += 8;
            let status = Admissibility::from_u8(bytes[p])
                .ok_or(RegistryError::UnknownAdmissibility(bytes[p]))?;
            p += 1;
            entries.push(RegistryEntry {
                id: ValidatorId(id),
                public_key: key,
                weight: ValidatorWeight(u64::from_le_bytes(w)),
                admissibility: status,
            });
        }
        for pair in entries.windows(2) {
            if pair[0].id >= pair[1].id {
                return Err(RegistryError::NonCanonicalOrder);
            }
        }
        ValidatorRegistry::new(GenerationId(generation), &entries)
    }
}

impl fmt::Display for ValidatorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "registry[gen={}, n={}, root={}]",
            self.generation,
            self.entries.len(),
            hex::encode(&self.root()[..6])
        )
    }
}
