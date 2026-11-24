//! Canonical framing for L2 signed messages.
//!
//! Every L2 signature covers a **length-prefixed, domain-tagged** byte string.
//! This module is the single place that produces such strings, so a message can
//! never be assembled two different ways.
//!
//! # Why not reuse the L1 convention
//!
//! `crate::transaction::Vote::signing_bytes` concatenates raw fields with no
//! domain prefix: its only separator is a `format_version` byte produced by
//! `bincode`-free hand layout. That is adequate for a single message type, but
//! it gives no cross-type separation. An L2 message must never be verifiable as
//! an L1 vote, nor an L1 vote as an L2 vote, so L2 tags every message with an
//! explicit domain string and length-prefixes every field.
//!
//! # Framing
//!
//! ```text
//! [domain_len u32 LE][domain bytes][part0_len u64 LE][part0][part1_len u64 LE][part1]...
//! ```
//!
//! Consequences, each covered by a test:
//! - `[b"ab", b"c"]` and `[b"a", b"bc"]` differ (no concatenation ambiguity);
//! - a message of another domain differs even with identical parts;
//! - the encoding is a pure function of its inputs (no clock, no map order).

/// Length-prefixed framing of `domain` and every part.
pub fn frame(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + domain.len() + parts.len() * 8);
    out.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    out.extend_from_slice(domain);
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// BLAKE3 over the canonical frame of `domain` and `parts`.
pub fn frame_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    *blake3::hash(&frame(domain, parts)).as_bytes()
}

/// Little-endian helper kept local so call sites cannot pick an encoding by
/// accident.
pub fn le64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Little-endian helper for 32-bit round numbers.
pub fn le32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}
