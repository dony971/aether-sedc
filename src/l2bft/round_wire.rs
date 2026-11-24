//! Wire codec for `RoundChange` (mission BF, R-BE-2).
//!
//! # The finding that shapes this file
//!
//! `RoundChange` **already** has a canonical, domain-framed, versioned signed
//! format: [`RoundChange::signing_bytes`] in `round.rs`, with
//! `DOMAIN_ROUND_CHANGE = "AETHER-L2-ROUNDCHANGE-v1"`, a version byte, and
//! length-prefixed parts (`le64`/`le32`, `frame()`). BE's report said "no
//! canonical encoding", which was true only of the **byte codec**: there was no
//! way to turn a `RoundChange` into bytes and back.
//!
//! So this module adds a codec that reproduces the existing signed layout
//! **exactly**, field for field, and nothing else. It defines no new domain, adds
//! no field, changes no version, and cannot make a signature verify differently:
//! `decode` rebuilds the struct and then calls the existing `verify`.
//!
//! # Layout (`ROUND_CHANGE_WIRE_VERSION = 1`)
//!
//! ```text
//! bytes := version(1) ‖ network(8) ‖ generation(32) ‖ height(8)
//!          ‖ from_round(4) ‖ target_round(4) ‖ validator(32) ‖ set_root(32)
//!          ‖ locked ‖ signature(64)
//! locked := 0                                  (no lock)
//!         | 1 ‖ checkpoint_id(32) ‖ height(8) ‖ round(4)
//! ```
//!
//! Fixed size: `1+8+32+8+4+4+32+32+1+64 = 186` bytes without a lock, `231` with
//! one. Because the size depends only on the lock tag, decoding is unambiguous: a
//! strict length check runs **before** any field is read, and no two byte strings
//! can decode to the same message.
//!
//! # What the format prevents
//!
//! | Ambiguity | How |
//! |---|---|
//! | two encodings of one message | one fixed layout, one tag value per case |
//! | signature reused on another network | `network` is inside the signed bytes |
//! | generation substitution | `generation` is inside the signed bytes |
//! | round substitution | both rounds are inside the signed bytes |
//! | POL alteration | the lock is inside the signed bytes, tag-separated |
//! | replay | position (`network`/`generation`/`height`/`round`) is signed and `id()` is content addressed |
//! | truncation | exact length required |
//! | trailing padding | any extra byte is an error |

use thiserror::Error;

use crate::consensus::generation::{CheckpointHeight, GenerationId, Round, ValidatorId};
use crate::l2bft::round::RoundChange;
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2persist::state::LockedValue;

/// Version of the byte codec.
///
/// Equal to `round::ROUND_CHANGE_VERSION`: this module encodes the same message
/// the signature covers, so a codec change that alters layout would be a
/// different version of the *signed* format and must not be done here.
pub const ROUND_CHANGE_WIRE_VERSION: u8 = 1;

/// Size of a round change without a lock.
pub const RC_LEN_UNLOCKED: usize = 1 + 8 + 32 + 8 + 4 + 4 + 32 + 32 + 1 + 64;

/// Size of a round change with a lock.
pub const RC_LEN_LOCKED: usize = RC_LEN_UNLOCKED + 32 + 8 + 4;

/// Why a round change did not decode or verify.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RoundChangeWireError {
    /// The length is neither the unlocked nor the locked size.
    #[error("round change has {found} bytes, expected {RC_LEN_UNLOCKED} or {RC_LEN_LOCKED}")]
    Length {
        /// Bytes found.
        found: usize,
    },

    /// The version is not the one this codec speaks.
    #[error("unsupported round-change version {0}")]
    Version(u8),

    /// The lock tag is not 0 or 1.
    #[error("invalid lock tag {0}")]
    LockTag(u8),

    /// The frame was well formed but the message did not verify.
    #[error("round change refused: {0}")]
    Refused(String),
}

impl RoundChange {
    /// Encode exactly the bytes `signing_bytes` covers, followed by the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RC_LEN_LOCKED);
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.height.get().to_le_bytes());
        out.extend_from_slice(&self.from_round.get().to_le_bytes());
        out.extend_from_slice(&self.target_round.get().to_le_bytes());
        out.extend_from_slice(&self.validator.0);
        out.extend_from_slice(&self.validator_set_root);
        match &self.locked {
            None => out.push(0),
            Some(locked) => {
                out.push(1);
                out.extend_from_slice(&locked.checkpoint_id);
                out.extend_from_slice(&locked.height.get().to_le_bytes());
                out.extend_from_slice(&locked.round.get().to_le_bytes());
            }
        }
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode, then submit to [`RoundChange::verify`].
    ///
    /// The signature is checked against the registry of the **message's**
    /// generation, and the position (network, generation, height, set root,
    /// membership, admissibility) is checked by `verify` — this codec deliberately
    /// does not re-implement any of it.
    pub fn decode(
        bytes: &[u8],
        registry: &ValidatorRegistry,
        network: u64,
    ) -> Result<Self, RoundChangeWireError> {
        let version = *bytes
            .first()
            .ok_or(RoundChangeWireError::Length { found: 0 })?;
        if version != ROUND_CHANGE_WIRE_VERSION {
            return Err(RoundChangeWireError::Version(version));
        }
        // The lock tag decides the total length, so it is read before anything is
        // sliced: an inconsistent length cannot reach the field readers.
        let tag_at = 1 + 8 + 32 + 8 + 4 + 4 + 32 + 32;
        let tag = *bytes
            .get(tag_at)
            .ok_or(RoundChangeWireError::Length { found: bytes.len() })?;
        let expected = match tag {
            0 => RC_LEN_UNLOCKED,
            1 => RC_LEN_LOCKED,
            other => return Err(RoundChangeWireError::LockTag(other)),
        };
        if bytes.len() != expected {
            return Err(RoundChangeWireError::Length { found: bytes.len() });
        }

        // One field reader, used by both entry points: `decode_unverified` rebuilds
        // the exact bytes `signing_bytes` covers, so `verify` sees the original
        // message and not a re-interpretation of it.
        let message = Self::decode_unverified(bytes)?;
        if message.version != version {
            return Err(RoundChangeWireError::Version(message.version));
        }
        // `verify` is the only authority on validity; a codec that also decided
        // would be a second, divergent one.
        message
            .verify(registry, network)
            .map_err(|error| RoundChangeWireError::Refused(error.to_string()))?;
        Ok(message)
    }

    /// Whether the bytes decode to the same message, without a registry.
    ///
    /// Useful for a transport that only needs to route, but never a substitute for
    /// [`Self::decode`]: no signature is checked here.
    pub fn decode_unverified(bytes: &[u8]) -> Result<Self, RoundChangeWireError> {
        let version = *bytes
            .first()
            .ok_or(RoundChangeWireError::Length { found: 0 })?;
        let tag_at = 1 + 8 + 32 + 8 + 4 + 4 + 32 + 32;
        let tag = *bytes
            .get(tag_at)
            .ok_or(RoundChangeWireError::Length { found: bytes.len() })?;
        let expected = match tag {
            0 => RC_LEN_UNLOCKED,
            1 => RC_LEN_LOCKED,
            other => return Err(RoundChangeWireError::LockTag(other)),
        };
        if bytes.len() != expected {
            return Err(RoundChangeWireError::Length { found: bytes.len() });
        }
        if version != ROUND_CHANGE_WIRE_VERSION {
            return Err(RoundChangeWireError::Version(version));
        }
        let cursor = &bytes[1..expected - 64];
        let mut at = 0usize;
        let mut take = |n: usize| {
            let slice = &cursor[at..at + n];
            at += n;
            slice
        };
        let mut u64_at = |slice: &[u8]| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(slice);
            u64::from_le_bytes(raw)
        };
        let mut u32_at = |slice: &[u8]| {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(slice);
            u32::from_le_bytes(raw)
        };
        let mut id_at = |slice: &[u8]| {
            let mut out = [0u8; 32];
            out.copy_from_slice(slice);
            out
        };
        let network = u64_at(take(8));
        let generation = GenerationId(id_at(take(32)));
        let height = CheckpointHeight(u64_at(take(8)));
        let from_round = Round(u32_at(take(4)));
        let target_round = Round(u32_at(take(4)));
        let validator = ValidatorId(id_at(take(32)));
        let validator_set_root = id_at(take(32));
        // The lock tag sits between the set root and the lock body; it was read
        // above to decide the total length, and must be stepped over here.
        take(1);
        let locked = match tag {
            0 => None,
            _ => Some(LockedValue {
                checkpoint_id: id_at(take(32)),
                height: CheckpointHeight(u64_at(take(8))),
                round: Round(u32_at(take(4))),
            }),
        };
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[expected - 64..]);
        Ok(Self {
            version,
            network,
            generation,
            height,
            from_round,
            target_round,
            validator,
            validator_set_root,
            locked,
            signature,
        })
    }
}
