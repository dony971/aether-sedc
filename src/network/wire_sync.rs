//! Wire codec for the mission-BD synchronisation bundle (mission BF, R-BE-1).
//!
//! # What this adds
//!
//! BE declared `SyncRequest`/`BootstrapResponse` but had no bytes behind them.
//! This module supplies a **deterministic, versioned, bounded** encoding of
//! [`SyncBundle`], plus the request that asks for one. It does **not** decide
//! anything: [`crate::l2bft::sync::verify_history`] remains the only authority on
//! whether a bundle is acceptable, and it is called by the peer after decoding.
//!
//! # Layout (`SYNC_FORMAT_VERSION = 1`)
//!
//! ```text
//! bundle     := version(1) ‖ anchor ‖ generations ‖ links
//! anchor     := network(8) ‖ height(8) ‖ checkpoint_id(32) ‖ generation(32)
//!               ‖ set_root(32)
//! generations:= count(u16) ‖ generation*
//! generation := number(8) ‖ generation_id(32) ‖ entries(u16) ‖ entry* ‖ closed(1)
//!               [‖ closure]
//! entry      := id(32) ‖ public_key(32) ‖ weight(8) ‖ admissibility(1)
//! closure    := height(8) ‖ generation(32) ‖ value_id(32) ‖ candidate_id(32)
//!               ‖ new_set_root(32)
//! links      := count(u32) ‖ link*
//! link       := checkpoint_len(u32) ‖ checkpoint ‖ certificate_len(u32) ‖ cert
//! ```
//!
//! Every integer is little-endian, every count is bounded **before** it is used
//! to loop or allocate, and a bundle must consume exactly the bytes it declares:
//! trailing bytes are an error, so two different byte strings cannot decode to
//! the same bundle.
//!
//! # Certificates are verified while decoding
//!
//! `PrecommitCertificate::from_bytes` needs the registry of the certificate's
//! **own** generation, so the generations are decoded first and the certificate
//! is re-verified from its bytes during `decode`. A bundle whose certificates do
//! not verify never becomes a `SyncBundle` at all.
//!
//! # Roots
//!
//! `state_root` and `finality_root` travel inside the checkpoint and are **not**
//! authenticated here — a node L2 does not hold the L1 data that composes them.
//! `VerifiedRoots::state_root_authenticated` stays `false`; this module does not
//! weaken that, and nothing in it may be read as authenticating those two roots.

use thiserror::Error;

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::{CheckpointHeight, GenerationId, ValidatorId, ValidatorWeight};
use crate::consensus::transitions::GenerationClosure;
use crate::l2bft::cert::PrecommitCertificate;
use crate::l2bft::sync::{GenerationSpec, SyncAnchor, SyncBundle, SyncLink};
use crate::l2crypto::registry::{
    Admissibility, RegistryEntry, ValidatorRegistry, REGISTRY_FORMAT_VERSION,
};

/// Version of this container format.
pub const SYNC_FORMAT_VERSION: u8 = 1;

/// Largest accepted encoded bundle.
pub const MAX_SYNC_BYTES: usize = 256 * 1024;

/// Largest number of generations in one bundle.
pub const MAX_GENERATIONS: u16 = 64;

/// Largest number of links in one bundle.
pub const MAX_LINKS: u32 = 4096;

/// Largest number of registry entries in one generation.
pub const MAX_ENTRIES: u16 = 256;

/// Default number of links a peer will serve, and the largest it will ask for.
pub const DEFAULT_SYNC_LINKS: u32 = 128;

/// Why a bundle or request could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SyncWireError {
    /// The buffer ended before the field did.
    #[error("truncated bundle at offset {0}")]
    Truncated(usize),

    /// Bytes remain after the bundle ended.
    #[error("{0} trailing bytes after the bundle")]
    Trailing(usize),

    /// The version is not this one.
    #[error("unsupported sync version {0}")]
    Version(u8),

    /// A count exceeds its bound.
    #[error("{field} count {value} exceeds the limit {limit}")]
    Count {
        /// Field.
        field: &'static str,
        /// Declared count.
        value: usize,
        /// Limit.
        limit: usize,
    },

    /// An identifier or key is unusable.
    #[error("invalid {0}")]
    Field(&'static str),

    /// The embedded checkpoint did not decode.
    #[error("checkpoint: {0}")]
    Checkpoint(String),

    /// The embedded certificate did not verify.
    #[error("certificate: {0}")]
    Certificate(String),

    /// A generation referenced by a link is absent.
    #[error("link refers to an unknown generation")]
    UnknownGeneration,

    /// The registry rejected its own entries.
    #[error("registry: {0}")]
    Registry(String),

    /// A tag is not one of the allowed values.
    #[error("invalid tag {value} for {field}")]
    Tag {
        /// Field.
        field: &'static str,
        /// Value found.
        value: u8,
    },
}

// ---------------------------------------------------------------------------
// Bounded reader / writer
// ---------------------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], SyncWireError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(SyncWireError::Truncated(self.at))?;
        if end > self.bytes.len() {
            return Err(SyncWireError::Truncated(self.at));
        }
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, SyncWireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SyncWireError> {
        let mut raw = [0u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, SyncWireError> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, SyncWireError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn array32(&mut self) -> Result<[u8; 32], SyncWireError> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Anchor, generation, link
// ---------------------------------------------------------------------------

impl SyncAnchor {
    fn encode_into(&self, out: &mut Vec<u8>) {
        put_u64(out, self.network);
        put_u64(out, self.height.get());
        out.extend_from_slice(&self.checkpoint_id);
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.set_root);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, SyncWireError> {
        Ok(Self {
            network: reader.u64()?,
            height: CheckpointHeight(reader.u64()?),
            checkpoint_id: reader.array32()?,
            generation: GenerationId(reader.array32()?),
            set_root: reader.array32()?,
        })
    }
}

impl GenerationClosure {
    fn encode_into(&self, out: &mut Vec<u8>) {
        put_u64(out, self.height.get());
        out.extend_from_slice(&self.generation.0);
        out.extend_from_slice(&self.value_id);
        out.extend_from_slice(&self.candidate_id);
        out.extend_from_slice(&self.new_set_root);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, SyncWireError> {
        Ok(Self {
            height: CheckpointHeight(reader.u64()?),
            generation: GenerationId(reader.array32()?),
            value_id: reader.array32()?,
            candidate_id: reader.array32()?,
            new_set_root: reader.array32()?,
        })
    }
}

fn encode_registry(registry: &ValidatorRegistry, out: &mut Vec<u8>) {
    put_u16(out, registry.entries().len() as u16);
    for entry in registry.entries() {
        out.extend_from_slice(&entry.id.0);
        out.extend_from_slice(&entry.public_key);
        put_u64(out, entry.weight.get());
        out.push(entry.admissibility.as_u8());
    }
}

fn decode_registry(
    reader: &mut Reader<'_>,
    generation: GenerationId,
) -> Result<ValidatorRegistry, SyncWireError> {
    let count = reader.u16()?;
    if count > MAX_ENTRIES {
        return Err(SyncWireError::Count {
            field: "registry entry",
            value: count as usize,
            limit: MAX_ENTRIES as usize,
        });
    }
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let id = ValidatorId(reader.array32()?);
        let public_key = reader.array32()?;
        let weight = ValidatorWeight(reader.u64()?);
        let tag = reader.u8()?;
        let admissibility = Admissibility::from_u8(tag).ok_or(SyncWireError::Tag {
            field: "admissibility",
            value: tag,
        })?;
        entries.push(RegistryEntry {
            id,
            public_key,
            weight,
            admissibility,
        });
    }
    ValidatorRegistry::new(generation, &entries)
        .map_err(|error| SyncWireError::Registry(error.to_string()))
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

impl SyncBundle {
    /// Deterministic encoding, or a size error.
    pub fn encode(&self) -> Result<Vec<u8>, SyncWireError> {
        let mut out = Vec::with_capacity(512 * self.links.len().max(1));
        out.push(SYNC_FORMAT_VERSION);
        self.anchor.encode_into(&mut out);
        if self.generations.len() > MAX_GENERATIONS as usize {
            return Err(SyncWireError::Count {
                field: "generation",
                value: self.generations.len(),
                limit: MAX_GENERATIONS as usize,
            });
        }
        put_u16(&mut out, self.generations.len() as u16);
        for generation in &self.generations {
            put_u64(&mut out, generation.number);
            out.extend_from_slice(&generation.registry.generation().0);
            encode_registry(&generation.registry, &mut out);
            match &generation.closure {
                None => out.push(0),
                Some(closure) => {
                    out.push(1);
                    closure.encode_into(&mut out);
                }
            }
        }
        if self.links.len() as u32 > MAX_LINKS {
            return Err(SyncWireError::Count {
                field: "link",
                value: self.links.len(),
                limit: MAX_LINKS as usize,
            });
        }
        put_u32(&mut out, self.links.len() as u32);
        for link in &self.links {
            let checkpoint = link.checkpoint.encode();
            put_u32(&mut out, checkpoint.len() as u32);
            out.extend_from_slice(&checkpoint);
            let certificate = link.certificate.encode();
            put_u32(&mut out, certificate.len() as u32);
            out.extend_from_slice(&certificate);
        }
        if out.len() > MAX_SYNC_BYTES {
            return Err(SyncWireError::Count {
                field: "bundle byte",
                value: out.len(),
                limit: MAX_SYNC_BYTES,
            });
        }
        Ok(out)
    }

    /// Strict decoding: bounded counts, exact length, no trailing bytes, and
    /// every embedded certificate re-verified against the registry of its own
    /// generation.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncWireError> {
        if bytes.len() > MAX_SYNC_BYTES {
            return Err(SyncWireError::Count {
                field: "bundle byte",
                value: bytes.len(),
                limit: MAX_SYNC_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let version = reader.u8()?;
        if version != SYNC_FORMAT_VERSION {
            return Err(SyncWireError::Version(version));
        }
        let anchor = SyncAnchor::decode_from(&mut reader)?;

        let generation_count = reader.u16()?;
        if generation_count > MAX_GENERATIONS {
            return Err(SyncWireError::Count {
                field: "generation",
                value: generation_count as usize,
                limit: MAX_GENERATIONS as usize,
            });
        }
        let mut generations = Vec::with_capacity(generation_count as usize);
        for _ in 0..generation_count {
            let number = reader.u64()?;
            // The registry's generation identity travels with it: it is derived
            // from (number, epoch pin, set root) and cannot be recomputed here
            // without inventing that derivation, so it is carried, then checked
            // against every link that uses it.
            let generation_id = GenerationId(reader.array32()?);
            let registry = decode_registry(&mut reader, generation_id)?;
            let closure = match reader.u8()? {
                0 => None,
                1 => Some(GenerationClosure::decode_from(&mut reader)?),
                other => {
                    return Err(SyncWireError::Tag {
                        field: "closure",
                        value: other,
                    })
                }
            };
            generations.push(GenerationSpec {
                number,
                registry,
                closure,
            });
        }

        let link_count = reader.u32()?;
        if link_count > MAX_LINKS {
            return Err(SyncWireError::Count {
                field: "link",
                value: link_count as usize,
                limit: MAX_LINKS as usize,
            });
        }
        let mut links = Vec::with_capacity(link_count.min(1024) as usize);
        for _ in 0..link_count {
            let checkpoint_len = reader.u32()? as usize;
            if checkpoint_len > MAX_SYNC_BYTES {
                return Err(SyncWireError::Count {
                    field: "checkpoint byte",
                    value: checkpoint_len,
                    limit: MAX_SYNC_BYTES,
                });
            }
            let checkpoint = Checkpoint::decode(reader.take(checkpoint_len)?)
                .map_err(|error| SyncWireError::Checkpoint(error.to_string()))?;
            let certificate_len = reader.u32()? as usize;
            if certificate_len > MAX_SYNC_BYTES {
                return Err(SyncWireError::Count {
                    field: "certificate byte",
                    value: certificate_len,
                    limit: MAX_SYNC_BYTES,
                });
            }
            let certificate_bytes = reader.take(certificate_len)?;
            let spec = generations
                .iter()
                .find(|spec| spec.registry.generation() == checkpoint.generation)
                .ok_or(SyncWireError::UnknownGeneration)?;
            let certificate =
                PrecommitCertificate::from_bytes(certificate_bytes, &spec.registry, anchor.network)
                    .map_err(|error| SyncWireError::Certificate(error.to_string()))?;
            links.push(SyncLink {
                checkpoint,
                certificate,
            });
        }

        if reader.remaining() != 0 {
            return Err(SyncWireError::Trailing(reader.remaining()));
        }

        Ok(Self {
            anchor,
            generations,
            links,
        })
    }
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// A peer asking for history, starting after `from_height`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRequest {
    /// Network.
    pub network: u64,
    /// First height the requester wants. It must equal `anchor.height + 1` for a
    /// contiguous chain, or an older height to re-request from there.
    pub from_height: CheckpointHeight,
    /// Largest number of links the requester will accept.
    pub max_links: u32,
}

impl SyncRequest {
    /// Fixed 21-byte encoding: `version ‖ network(8) ‖ from_height(8) ‖ max(4)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21);
        out.push(SYNC_FORMAT_VERSION);
        put_u64(&mut out, self.network);
        put_u64(&mut out, self.from_height.get());
        put_u32(&mut out, self.max_links);
        out
    }

    /// Strict decoding of exactly 21 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncWireError> {
        if bytes.len() > MAX_SYNC_BYTES {
            return Err(SyncWireError::Count {
                field: "request byte",
                value: bytes.len(),
                limit: MAX_SYNC_BYTES,
            });
        }
        let mut reader = Reader::new(bytes);
        let version = reader.u8()?;
        if version != SYNC_FORMAT_VERSION {
            return Err(SyncWireError::Version(version));
        }
        let request = Self {
            network: reader.u64()?,
            from_height: CheckpointHeight(reader.u64()?),
            max_links: reader.u32()?,
        };
        if request.max_links == 0 || request.max_links > MAX_LINKS {
            return Err(SyncWireError::Count {
                field: "requested link",
                value: request.max_links as usize,
                limit: MAX_LINKS as usize,
            });
        }
        if reader.remaining() != 0 {
            return Err(SyncWireError::Trailing(reader.remaining()));
        }
        Ok(request)
    }
}

/// Version of the registry format this codec expects to carry.
///
/// Not on the wire: the registry's own encoding is the entries themselves, and
/// the root is recomputed by `verify_history`. Kept as a compile-time reminder
/// that a registry format change must be reviewed here too.
pub const CARRIED_REGISTRY_FORMAT: u8 = REGISTRY_FORMAT_VERSION;
