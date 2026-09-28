//! Phase 2E-A (A.1) — address masking on the `node.log` SINK.
//!
//! Threat addressed: `<data_dir>/logs/node.log` (plus its 5 rotations, 10 MiB
//! each) is the local half of `LOCAL_METADATA_EXPOSURE`. It is written in
//! clear, lives on disk for the lifetime of the node, and every INFO line
//! carrying a peer (handshake success/failure, redial, PEX, ban, config
//! banner with `bootnodes=`) prints a raw `SocketAddr`. Anyone with read
//! access to the data dir therefore learns every IP this node has ever talked
//! to, and with it the exact topology of the network around it.
//!
//! Fix (roadmap 2E-A A.1: "anonymisation des adresses dans `logs/node.log`
//! (masquage en sortie, pas en mémoire)"): the mask is applied where the line
//! is written, never where the address is stored. `SocketAddr` values, the
//! `AddressManager`, `known_peers.json` and every log CALL SITE keep the real
//! address; only the bytes that reach the file change. Nothing is deleted, so
//! debuggability survives — an address becomes a short, per-process tag
//! (`p2p.4f2a91:40001`) that still distinguishes peers WITHIN one run.
//!
//! Design notes:
//! - Per-process random salt. The tag is `FNV-1a(ip || salt)` truncated to
//!   24 bits, so it cannot be dictionary-attacked back to an IPv4 address
//!   (2^32 candidates, salt unknown and never logged) and two runs of the
//!   same node cannot be aligned against each other. Cost: correlation does
//!   NOT survive a restart. That is deliberate — a stable tag would trade a
//!   machine-readable fingerprint for a debug convenience.
//! - Only `node.log` is masked. The stdout layer is left byte-for-byte as it
//!   was (the operator console is not an artefact at rest); the roadmap
//!   scopes A.1 to `logs/node.log`.
//! - Line granularity: the guard buffers until `\n` so an address split
//!   across two `write()` calls cannot slip through unmasked.
//!
//! Why this module exists instead of an edit inside `node_logging.rs`: that
//! file carries a pre-existing uncommitted change which must stay unstaged, so
//! the mask is installed from a separate module that reuses `NodeLineFormat`
//! and `RollingFileWriter` unchanged.

use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

use crate::node_logging as nl;
use tracing_subscriber::fmt::MakeWriter;

/// Per-process salt for the address tag. Never logged, never persisted.
static SALT: OnceLock<u64> = OnceLock::new();

fn salt() -> u64 {
    *SALT.get_or_init(|| rand::random::<u64>() | 1)
}

/// FNV-1a over `data` then `salt`, so the tag depends on both.
fn fnv1a(data: &[u8], salt: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for i in 0..8 {
        h ^= (salt >> (i * 8)) & 0xff;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `FNV-1a(ip || salt)` → 6 lowercase hex digits. 24 bits: enough that two
/// distinct peers almost never collide inside one run, few enough to stay
/// readable in a log line.
fn ip_tag(ip: &[u8], salt: u64) -> String {
    format!("{:06x}", fnv1a(ip, salt) & 0x00ff_ffff)
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Characters allowed inside a bare IPv6 literal.
fn is_v6_char(b: u8) -> bool {
    is_hex(b) || b == b':' || b == b'%'
}

/// Validate a maximal `[0-9a-f:%]` run as an IPv6 literal.
///
/// Deliberately strict — a false positive here eats a log line's meaning:
/// - `::` compressed form requires hex on BOTH sides unless the run itself
///   begins with `::` (which only happens when the literal is not glued to a
///   preceding word; `aether_unified::p2p` produces the run `ed::` and is
///   rejected precisely because nothing follows the `::`).
/// - the dotted form requires all 8 groups.
/// - length capped at 45, the longest legal textual IPv6.
fn looks_like_ipv6(run: &[u8]) -> bool {
    if run.is_empty() || run.len() > 45 {
        return false;
    }
    if !run.iter().all(|&b| is_v6_char(b)) {
        return false;
    }
    let groups: Vec<&[u8]> = run.split(|&b| b == b':').collect();
    if groups.iter().any(|g| g.len() > 4) {
        return false;
    }
    if let Some(pos) = run.windows(2).position(|w| w == &b"::"[..]) {
        if pos == 0 {
            // Run literally starts with "::" (only reachable when nothing
            // precedes it, so this is a real "::1", not "word::").
            return run[2..].iter().any(|&b| is_hex(b));
        }
        // Compressed form: hex must exist on BOTH sides. This is what
        // rejects the run `ed::` produced by `aether_unified::p2p`.
        return run[..pos].iter().any(|&b| is_hex(b))
            && run[pos + 2..].iter().any(|&b| is_hex(b));
    }
    // Full form: exactly 8 non-empty groups of 1..=4 hex digits.
    groups.len() == 8 && groups.iter().all(|g| !g.is_empty())
}

/// Parse a decimal octet of 1..=3 digits at `i`. Returns (value, next_index).
fn parse_octet(b: &[u8], i: usize) -> Option<(u8, usize)> {
    let mut j = i;
    let mut digits = 0usize;
    let mut val: u32 = 0;
    while j < b.len() && b[j].is_ascii_digit() && digits < 3 {
        val = val * 10 + u32::from(b[j] - b'0');
        digits += 1;
        j += 1;
    }
    // A 4th consecutive digit means this is not an octet ("2026-…").
    if digits == 0 || (j < b.len() && b[j].is_ascii_digit()) || val > 255 {
        return None;
    }
    Some((val as u8, j))
}

/// Attempt to match one address at `b[i]`. Returns the number of bytes the
/// match consumes and the replacement text.
fn match_at(b: &[u8], i: usize, salt: u64) -> Option<(usize, String)> {
    // --- bracketed IPv6: "[::1]:30001" (the SocketAddr Display form) ---
    if b[i] == b'[' {
        let close = b[i..].iter().position(|&c| c == b']')?;
        if close == 0 || close > 46 {
            return None;
        }
        let inner = &b[i + 1..i + close];
        if !looks_like_ipv6(inner) {
            return None;
        }
        let mut end = i + close + 1;
        let mut port = None;
        if end < b.len() && b[end] == b':' && end + 1 < b.len() && b[end + 1].is_ascii_digit() {
            let mut p = end + 1;
            let mut digits = 0;
            while p < b.len() && b[p].is_ascii_digit() && digits < 5 {
                p += 1;
                digits += 1;
            }
            port = Some(String::from_utf8_lossy(&b[end + 1..p]).into_owned());
            end = p;
        }
        let tag = format!(
            "p2p.{}{}",
            ip_tag(inner, salt),
            port.map(|p| format!(":{}", p)).unwrap_or_default()
        );
        return Some((end - i, tag));
    }

    // --- bare IPv6 starting at "::" (e.g. "::1" not wrapped in brackets) ---
    if b[i] == b':' && b.get(i + 1) == Some(&b':') && (i == 0 || !is_v6_char(b[i - 1])) {
        let mut j = i;
        while j < b.len() && is_v6_char(b[j]) {
            j += 1;
        }
        let run = &b[i..j];
        if looks_like_ipv6(run) {
            return Some((j - i, format!("p2p.{}", ip_tag(run, salt))));
        }
        return None;
    }

    // --- IPv4, optionally with ":port" ---
    if b[i].is_ascii_digit() && (i == 0 || (!b[i - 1].is_ascii_digit() && b[i - 1] != b'.')) {
        let mut j = i;
        let mut octets = [0u8; 4];
        let mut ok = true;
        for (n, octet) in octets.iter_mut().enumerate() {
            let (v, next) = match parse_octet(b, j) {
                Some(x) => x,
                None => {
                    ok = false;
                    break;
                }
            };
            *octet = v;
            j = next;
            if n < 3 {
                if j >= b.len() || b[j] != b'.' {
                    ok = false;
                    break;
                }
                j += 1;
            }
        }
        // Must not be a prefix of a longer dotted number.
        if ok && (j >= b.len() || !b[j].is_ascii_digit()) {
            let mut end = j;
            let mut port = None;
            if end < b.len() && b[end] == b':' && end + 1 < b.len() && b[end + 1].is_ascii_digit()
            {
                let mut p = end + 1;
                let mut digits = 0;
                while p < b.len() && b[p].is_ascii_digit() && digits < 5 {
                    p += 1;
                    digits += 1;
                }
                port = Some(String::from_utf8_lossy(&b[end + 1..p]).into_owned());
                end = p;
            }
            let tag = format!(
                "p2p.{}{}",
                ip_tag(&octets, salt),
                port.map(|p| format!(":{}", p)).unwrap_or_default()
            );
            return Some((end - i, tag));
        }
        return None;
    }

    // --- bare IPv6 starting at a hex digit (e.g. "fe80::1") ---
    if is_hex(b[i]) && (i == 0 || !is_v6_char(b[i - 1])) {
        let mut j = i;
        while j < b.len() && is_v6_char(b[j]) {
            j += 1;
        }
        let run = &b[i..j];
        if run.contains(&b':') && looks_like_ipv6(run) {
            return Some((j - i, format!("p2p.{}", ip_tag(run, salt))));
        }
    }

    None
}

/// Mask every socket address in `input`, using a fixed salt (unit-testable,
/// deterministic). Production goes through `mask_socket_addrs`.
pub fn mask_socket_addrs_with_salt(input: &str, salt: u64) -> String {
    let b = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if let Some((len, replacement)) = match_at(b, i, salt) {
            out.extend_from_slice(replacement.as_bytes());
            i += len;
            continue;
        }
        // Copy one whole character so multi-byte glyphs are never split.
        let width = if b[i] < 0x80 {
            1
        } else if b[i] & 0xe0 == 0xc0 {
            2
        } else if b[i] & 0xf0 == 0xe0 {
            3
        } else if b[i] & 0xf8 == 0xf0 {
            4
        } else {
            1
        };
        let end = (i + width).min(b.len());
        out.extend_from_slice(&b[i..end]);
        i = end;
    }
    // Input was UTF-8 and every replacement is ASCII, so this is lossless.
    String::from_utf8_lossy(&out).into_owned()
}

/// Mask every socket address in `input` with this process's salt.
pub fn mask_socket_addrs(input: &str) -> String {
    mask_socket_addrs_with_salt(input, salt())
}

/// Writer handed to the fmt layer: buffers a line, masks it, forwards it.
pub struct MaskingGuard<'a> {
    inner: nl::RollingGuard<'a>,
    pending: Vec<u8>,
}

impl Write for MaskingGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(pos) = self.pending.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            let masked = mask_socket_addrs(&String::from_utf8_lossy(&line));
            self.inner.write_all(masked.as_bytes())?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            let masked = mask_socket_addrs(&String::from_utf8_lossy(&self.pending));
            self.pending.clear();
            self.inner.write_all(masked.as_bytes())?;
        }
        self.inner.flush()
    }
}

/// File writer that produces masked guards.
pub struct MaskingFileWriter {
    inner: nl::RollingFileWriter,
}

impl MaskingFileWriter {
    pub fn new(inner: nl::RollingFileWriter) -> Self {
        Self { inner }
    }
}

impl<'a> MakeWriter<'a> for MaskingFileWriter {
    type Writer = MaskingGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        MaskingGuard {
            inner: MakeWriter::make_writer(&self.inner),
            pending: Vec::new(),
        }
    }
}

/// Install the global subscriber: identical to
/// `node_logging::init_node_logging` except that the FILE layer writes
/// through `MaskingFileWriter`. The stdout layer is byte-identical to the
/// original (2E-A scopes masking to `logs/node.log`).
///
/// Returns the writer (keep alive; dropping it only stops file output).
pub fn init_masked_node_logging(
    data_dir: &Path,
    node_tag: &str,
) -> std::io::Result<nl::RollingFileWriter> {
    use tracing_subscriber::{fmt, prelude::*};

    let log_dir = data_dir.join("logs");
    let writer = nl::RollingFileWriter::new(&log_dir, nl::LOG_FILE_NAME)?;
    let file_layer = fmt::layer()
        .event_format(nl::NodeLineFormat {
            node: node_tag.to_string(),
        })
        .with_writer(MaskingFileWriter::new(writer.clone()))
        .with_ansi(false)
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stdout)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        )
        .with(file_layer)
        .init();
    Ok(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 0x1234_5678_9abc_def0;

    #[test]
    fn masks_ipv4_with_port() {
        let out = mask_socket_addrs_with_salt("Peer 10.0.0.5:40001 disconnected", S);
        assert!(!out.contains("10.0.0.5"), "got: {out}");
        assert!(out.contains(":40001"), "port kept for debuggability: {out}");
        assert!(out.starts_with("Peer p2p."), "got: {out}");
    }

    #[test]
    fn masks_ipv4_without_port() {
        let out = mask_socket_addrs_with_salt("bootnodes=[192.168.1.7, 8.8.8.8]", S);
        assert!(!out.contains("192.168.1.7"), "got: {out}");
        assert!(!out.contains("8.8.8.8"), "got: {out}");
        assert!(out.contains('[') && out.contains(']'), "got: {out}");
    }

    #[test]
    fn masks_ipv6_bracketed_and_bare() {
        let out = mask_socket_addrs_with_salt("[::1]:30001 then fe80::1 end", S);
        assert!(!out.contains("::1"), "got: {out}");
        assert!(!out.contains("fe80::1"), "got: {out}");
        assert!(out.contains(":30001"), "got: {out}");
    }

    #[test]
    fn leaves_timestamps_and_versions_alone() {
        let line = "2026-01-01T00:00:00Z | n1 | INFO | aether_unified::p2p | v1.1.1 ratio 0.5";
        assert_eq!(mask_socket_addrs_with_salt(line, S), line);
    }

    #[test]
    fn leaves_module_paths_alone() {
        // `unified::` would produce the run `ed::`, which must NOT be masked.
        for line in [
            "aether_unified::p2p",
            "aether_unified::node",
            "aether_unified::node_logging",
            "aether_unified::sync_stats",
        ] {
            assert_eq!(
                mask_socket_addrs_with_salt(line, S),
                line,
                "module path mangled: {line}"
            );
        }
    }

    #[test]
    fn leaves_transaction_hashes_alone() {
        let hash = "3f786850e387550fdab836ed7e6dc881de23001b";
        let line = format!("tx {hash} accepted");
        assert_eq!(mask_socket_addrs_with_salt(&line, S), line);
    }

    #[test]
    fn same_input_same_salt_is_stable() {
        let line = "dial 203.0.113.9:1234 now";
        assert_eq!(
            mask_socket_addrs_with_salt(line, S),
            mask_socket_addrs_with_salt(line, S)
        );
    }

    #[test]
    fn different_salt_changes_the_tag() {
        let line = "dial 203.0.113.9:1234 now";
        assert_ne!(
            mask_socket_addrs_with_salt(line, S),
            mask_socket_addrs_with_salt(line, S.wrapping_add(1))
        );
    }

    #[test]
    fn different_addresses_get_different_tags() {
        let a = mask_socket_addrs_with_salt("10.0.0.1", S);
        let b = mask_socket_addrs_with_salt("10.0.0.2", S);
        assert_ne!(a, b, "distinct peers must stay distinguishable: {a} {b}");
    }

    #[test]
    fn masking_is_idempotent() {
        let once = mask_socket_addrs_with_salt("peer 10.1.2.3:4444 gone", S);
        let twice = mask_socket_addrs_with_salt(&once, S);
        assert_eq!(once, twice, "masking a masked line must be a no-op");
    }

    #[test]
    fn multi_byte_glyphs_survive() {
        let line = "🔐 P2P encrypted handshake complete with 10.0.0.1:30001";
        let out = mask_socket_addrs_with_salt(line, S);
        assert!(out.contains('🔐'), "emoji must not be split: {out}");
        assert!(!out.contains("10.0.0.1"), "got: {out}");
    }

    /// 2E-A: the guard must mask even when the fmt layer splits one line
    /// across several `write()` calls (it does — header, fields, newline).
    #[test]
    fn guard_masks_across_split_writes() {
        let dir = tempfile::tempdir().unwrap();
        let w = nl::RollingFileWriter::new(dir.path(), "node.log").unwrap();
        let mut guard = MaskingGuard {
            inner: MakeWriter::make_writer(&w),
            pending: Vec::new(),
        };
        guard.write_all(b"2026-01-01T00:00:00Z | n1 | INFO | x | dial 10.0.").unwrap();
        guard.write_all(b"0.1:30001").unwrap();
        guard.write_all(b"\n").unwrap();
        guard.flush().unwrap();
        let content = std::fs::read_to_string(dir.path().join("node.log")).unwrap();
        assert!(!content.contains("10.0.0.1"), "got: {content}");
        assert!(content.contains(":30001"), "got: {content}");
        assert!(content.contains("10.0.") || content.contains("p2p."), "got: {content}");
    }
}
