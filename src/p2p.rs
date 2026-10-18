//! # P2P Networking Module
//!
//! Implements peer-to-peer networking for the Aether DAG with efficient inventory synchronization.
//! Uses tip-based synchronization and hash comparison for inventory management.
//! Supports DNS-based peer discovery and peer exchange (PEX).

use crate::transaction::Transaction;
use crate::transaction::{Bond, Unbond, Vote};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::sync_stats::{SyncContext, TOPO_ORDER_CAP};
use crate::validation::ValidationMode;
use crate::transport::{PeerAddr, TcpTransport, Transport, TransportListener, TransportStream};

/// P2P handshake magic bytes ("AETH")  -  LOGICAL network identifier only.
///
/// 2E-A (A.3): the literal ASCII signature is never put on the wire. The
/// handshake transmits `handshake_wire_magic()` (this constant XOR
/// `HANDSHAKE_MAGIC_MASK`), so a passive packet inspection that greps for
/// `AETH` no longer classifies the flow. This is **obfuscation, not
/// anonymity**: the mask is a public constant and trivially reversible by
/// anyone who knows the format, and the version byte next to it is in clear
/// anyway. It removes a signature; it hides nothing else.
const HANDSHAKE_MAGIC: [u8; 4] = [0x41, 0x45, 0x54, 0x48];
/// Fixed, public XOR mask applied to `HANDSHAKE_MAGIC` before it is written
/// to (and after it is read from) the socket. No zero bytes, and byte 0 must
/// not cancel `HANDSHAKE_MAGIC[0]` (see `test_handshake_magic_is_obfuscated`).
const HANDSHAKE_MAGIC_MASK: [u8; 4] = [0x3F, 0x71, 0xA5, 0x1C];

/// Maximum accepted encrypted message size (16 MiB). The length prefix is a
/// u32: without this cap a peer could advertise a 4 GiB frame and force a
/// giant allocation (memory DoS, V-09).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Phase 2E-A (A.3)  -  frame length padding ("paliers de padding sur total_len").
//
// Threat addressed: the clear `u32 total_len` prefix tells any passive
// observer the EXACT size of every message, which sizes the DAG inventory
// (SyncRequest), fingerprints PEX vs transaction vs gossip frames, and gives
// an exact plaintext length to correlate. Padding collapses those lengths
// onto a bucket: an observer now learns "somewhere in [k*B, (k+1)*B)" instead
// of the exact value.
//
// Layout (v4):
//   u32 total_len (always a multiple of FRAME_PAD_BUCKET)
//   | 12-byte nonce (unchanged, still clear — see FRAME_COUNTER note in 2E-A)
//   | ChaCha20Poly1305( pad_message(msg) )
// where pad_message appends zeros and a u16-LE pad length INSIDE the AEAD, so
// the padding is authenticated: a frame whose padding is stripped, added to or
// truncated fails Poly1305 verification instead of silently parsing.
// ---------------------------------------------------------------------------

/// Every frame's `total_len` is padded up to a multiple of this bucket.
/// 256 B: worst-case overhead 255 B/frame (0.8 % on a 32 KiB inventory),
/// while collapsing the common message classes (a ~300 B transaction and a
/// ~450 B PEX list land in the SAME bucket 513..768, so length no longer
/// distinguishes them).
const FRAME_PAD_BUCKET: usize = 256;
/// Hard cap on padding added to one frame — `FRAME_PAD_BUCKET - 1`. Enforced
/// by construction and asserted by `test_padding_bounds`.
const MAX_FRAME_PADDING: usize = FRAME_PAD_BUCKET - 1;
/// Trailing `u16`-LE pad length carried inside the ciphertext.
const FRAME_PAD_TAIL: usize = 2;
/// Length of the clear nonce prefix of every frame.
const NONCE_LEN: usize = 12;
/// ChaCha20-Poly1305 authentication tag appended to every ciphertext.
const AEAD_TAG_LEN: usize = 16;
/// Everything the receiver's `total_len` covers besides the payload itself:
/// 12-byte nonce + 16-byte tag + 2-byte in-ciphertext pad length (= 30).
/// This is the offset the bucket alignment is computed against — getting it
/// wrong by the nonce or tag size silently mis-aligns every frame.
const FRAME_FIXED_OVERHEAD: usize = NONCE_LEN + AEAD_TAG_LEN + FRAME_PAD_TAIL;
/// Largest `total_len` we will ever emit. Padding must not push a legal
/// message past `MAX_MESSAGE_SIZE` (the receiver rejects on it), so the
/// effective payload ceiling is reduced by one bucket. Anything this large is
/// rejected before the padding is even considered — unreachable in practice
/// (the biggest message type, a 1000-hash inventory, is ~32 KiB).
const FRAME_MAX_EMIT: usize = MAX_MESSAGE_SIZE - FRAME_PAD_BUCKET;

/// Maximum number of concurrently connected peers (V-10)
const MAX_PEERS: usize = 128;

/// Maximum number of peers from the same /24 subnet (eclipse prevention)
const MAX_PEERS_PER_SUBNET: usize = 4;

/// Number of outbound connection slots reserved and never evicted
const PROTECTED_OUTBOUND_SLOTS: usize = 8;

/// Maximum number of known peer addresses retained (PEX/DNS growth bound)
const MAX_KNOWN_PEERS: usize = 1000;

/// Maximum outbound dials attempted in a single reconnection cycle (Phase 2A).
/// Without this a peer store full of dead addresses turns one cycle into an
/// hours-long serial sweep; the budget lets the loop move on to the next cycle.
const MAX_REDIAL_PER_CYCLE: usize = 32;

// ---------------------------------------------------------------------------
// Phase 2B — distributed peer manager (address categories, versioned store,
// anchors, bounded PEX, PEX-only address filtering).
// ---------------------------------------------------------------------------

/// Schema version of the on-disk peer store. v1 was a bare JSON array of
/// address strings; v2 adds per-entry metadata. See `PeerStoreFile`.
const PEER_STORE_VERSION: u32 = 2;

/// Maximum anchors retained at once (Principle 5). Several, never one: a
/// single anchor would recreate exactly the authority this phase removes.
const MAX_ANCHORS: usize = 8;

/// Minimum anchors worth trying to maintain. Below this the anchor task
/// promotes from recently-successful peers. Anchors are never *required*, so
/// this is a target rather than a floor that gates anything.
const MIN_ANCHORS: usize = 3;

/// Maximum addresses attached to a single PEX message (D5). The receive side
/// is already bounded by MAX_INV_ITEMS; this bounds the send side, which used
/// to relay the entire known set (up to MAX_KNOWN_PEERS) to every peer.
const PEX_MAX_SEND: usize = 64;

/// PEX only gossips addresses that were useful recently. Hints older than this
/// are retained for redial but not re-shared (PEX aging).
const PEX_SHARE_MAX_AGE_SECS: u64 = 24 * 3600;

/// An anchor with no successful contact for this long is expired and replaced.
const ANCHOR_TTL_SECS: u64 = 7 * 24 * 3600;

/// Interval at which anchors are rotated/expired (Phase 2B).
const ANCHOR_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// An address whose last successful handshake falls inside this window counts
/// as `Recent` (still in living memory) rather than `Candidate` (heard of,
/// unproven). Candidates are the lowest-priority redial fodder.
const RECENT_PEER_WINDOW_SECS: u64 = 24 * 3600;

/// An address whose score fell to/below this is categorised `Penalized` and is
/// never a promotion source for anchors, nor relayed by PEX.
const PEER_QUALITY_PENALIZED: i32 = PEER_SCORE_BAN_THRESHOLD;

/// Highest quality score a `PeerMeta` can carry (mirrors PeerScore ceiling).
const PEER_QUALITY_MAX: i32 = 200;

// ---------------------------------------------------------------------------
// Phase 2C — eclipse resistance (diversified, rotated outbound selection).
//
// Every coefficient below is expressed as a fraction of `PEER_SCORE_INITIAL`
// so that address quality — which starts at exactly `PEER_SCORE_INITIAL` —
// stays the dominant term in the selection weight. None of them is a number
// chosen to make a test pass; the fraction they represent is the justification.
// Full derivation: docs/AETHER_PHASE2_ECLIPSE_AUDIT.md §13.
// ---------------------------------------------------------------------------

/// Maximum addresses one network group may contribute to a *single* outbound
/// selection round. Half of `MAX_PEERS_PER_SUBNET` by construction: a round of
/// `MAX_REDIAL_PER_CYCLE` dials therefore spans at least 16 groups when the
/// pool allows, while two consecutive rounds can still fill a group right up
/// to its session cap.
const MAX_CANDIDATES_PER_GROUP: usize = MAX_PEERS_PER_SUBNET / 2;

/// Rank bonus for an address promoted as an anchor. Half of the initial score:
/// an anchor is an address we have *already* reached and deliberately kept, so
/// it must outrank an unknown candidate — but never outrank the gap between a
/// healthy peer and one that keeps failing.
const ANCHOR_SELECT_BONUS: i32 = PEER_SCORE_INITIAL / 2;

/// Rank bonus for a successful handshake inside `RECENT_PEER_WINDOW_SECS`.
/// A quarter of the initial score: fresh proof, worth less than the persisted
/// proof an anchor represents.
const RECENT_SUCCESS_BONUS: i32 = PEER_SCORE_INITIAL / 4;

/// Rank penalty applied once per live session already held in the same network
/// group. Four sessions in one group cost 80, making an over-represented group
/// roughly five times less likely to be picked than an empty one of equal
/// quality  -  which is what turns "diversity" into a selection property rather
/// than a post-hoc admission check.
const GROUP_OVERREPRESENTATION_PENALTY: i32 = PEER_SCORE_INITIAL / 5;

/// Selection weights are offset by one so a never-tried candidate can never
/// score zero: the node must always be able to try *something*.
const MIN_SELECT_WEIGHT: u64 = 1;

/// Quality assigned to an address learned **only** from a PEX gossip hint.
/// Half of `PEER_SCORE_INITIAL`, therefore strictly below every entry we
/// observed through a channel we control (inbound, outbound dial, DNS,
/// operator config). `admit_peer` evicts when `victim_quality <= incoming`,
/// so at this value a PEX burst can displace only already-degraded or banned
/// entries — never a healthy peer it happens to outnumber.
const PEX_ADMISSION_QUALITY: i32 = PEER_SCORE_INITIAL / 2;

// ---------------------------------------------------------------------------
// Phase 2D — self-healing (bounded, hysteretic peer recovery).
//
// Every threshold below is *derived* from a constant that already exists in
// this file; none of them was chosen to make a test pass. Full derivation:
// docs/AETHER_PHASE2_SELF_HEALING_AUDIT.md §E.6.
// ---------------------------------------------------------------------------

/// Hysteresis **exit** threshold, and the count recovery aims at.
///
/// Exactly `PROTECTED_OUTBOUND_SLOTS`, whose own doc says *"8 = 2 x
/// MAX_PEERS_PER_SUBNET: the reserve covers two complete network groups, i.e.
/// at least two independent paths"*. Recovery declares itself finished only
/// once the node holds the diversity 2C already reserves slots for.
const RECOVERY_COMFORT_PEERS: usize = PROTECTED_OUTBOUND_SLOTS;

/// Hysteresis **entry** threshold.
///
/// Exactly `MAX_PEERS_PER_SUBNET`: below one full group the node no longer
/// holds even the quota a single group is allowed, which is an observed loss
/// of diversity rather than a gradual dip. `RECOVERY_THRESHOLD <
/// RECOVERY_COMFORT_PEERS` is what makes the band `[4, 8)` wide enough that a
/// count oscillating between 7 and 8 can never start and stop recovery.
const RECOVERY_THRESHOLD: usize = MAX_PEERS_PER_SUBNET;

/// Diagnostic floor, never a trigger: `MIN_ANCHORS` is already documented as
/// *"Several, never one"*. Logged on the deep-loss transition only.
const RECOVERY_MIN_PEERS: usize = MIN_ANCHORS;

/// Upper bound on dials issued by a single recovery round.
///
/// `PROTECTED_OUTBOUND_SLOTS` again: a round never opens more dials than the
/// number of outbound slots Phase 2C reserves, and is therefore always below
/// `MAX_REDIAL_PER_CYCLE` by construction.
const MAX_DIALS_PER_ROUND: usize = PROTECTED_OUTBOUND_SLOTS;

/// Cadence of the recovery loop — the same 5s the existing redial loop uses,
/// so there is one familiar clock rather than a second one to reason about.
const RECOVERY_INTERVAL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Phase 2E-A (A.2 ii/iii) — bounded cadence jitter.
//
// Threat addressed: three of this node's maintenance tasks fire on a fixed
// period (PEX 15 s, recovery 5 s, redial 5 s). A passive observer sees a
// three-lane metronome and can fingerprint the client, phase-lock onto it and
// estimate session start/end from the beat alone. Adding a bounded, one-sided
// jitter removes the exact period without ever firing FASTER than baseline
// (no extra traffic, no extra dial pressure) and without ever blocking: the
// sleep is the only thing that changes, the tasks themselves are untouched.
//
// Deliberately scoped to exactly these three loops — relay jitter belongs to
// 2E-D and must NOT be smuggled in here.
// ---------------------------------------------------------------------------

/// Base PEX cadence (was the literal `Duration::from_secs(15)` inline).
const PEX_INTERVAL: Duration = Duration::from_secs(15);
/// Extra delay uniformly added to the PEX period: actual sleep is
/// `[PEX_INTERVAL, PEX_INTERVAL + PEX_INTERVAL_JITTER)`.
const PEX_INTERVAL_JITTER: Duration = Duration::from_secs(4);
/// Extra delay uniformly added to the recovery period (5s → [5s, 7s)).
const RECOVERY_INTERVAL_JITTER: Duration = Duration::from_secs(2);
/// Extra delay uniformly added to the redial period (5s → [5s, 8s)).
const REDIAL_INTERVAL_JITTER: Duration = Duration::from_secs(3);

/// First backoff step after a failed round. Same base as the existing
/// per-candidate redial backoff (`2 ^ attempt` seconds at `:2076`).
const RECOVERY_BACKOFF_BASE_SECS: u64 = 5;

/// Backoff ceiling, identical to the existing per-candidate ceiling
/// (`min(.., 60)` at `:2076`).
const RECOVERY_BACKOFF_MAX_SECS: u64 = 60;

/// Levels of backoff before the delay stops growing. The existing redial loop
/// caps its own counter at 6 (`min(attempt + 1, 6)` at `:2087`) because
/// `2 ^ 6 = 64` already exceeds the 60s ceiling — same reason, same number.
const RECOVERY_MAX_LEVEL: u32 = 6;

/// Rounds that may open no session at all before recovery gives up and moves
/// to `Exhausted`. Same bounded counter as above; this is what makes an
/// infinite redial loop impossible at the controller level.
const RECOVERY_MAX_CONSECUTIVE_FAILURES: u32 = 6;


/// Maximum entries in the seen-transaction cache (memory bound)
const MAX_SEEN_TXS: usize = 50_000;

/// Maximum items accepted from a single Inventory/GetData/GetInventory/Peers
/// message (vector-of-vectors amplification bound)
const MAX_INV_ITEMS: usize = 1000;

/// 2E-A (A.2 i): rotating read cursor for the bounded `SyncRequest`
/// advertisement (see `inventory_window`). Process-wide on purpose — it is
/// only an offset, and sharing it across peers widens the rotation rather
/// than narrowing it.
static SYNC_WINDOW_CURSOR: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Phase 2E-D — privacy-aware transaction propagation.
//
// Threat addressed (threat model §4.3, `TRANSACTION_CORRELATION_RISK = HIGH`):
// today a node forwards an inbound transaction in the SAME task that received
// it, to EVERY connected peer, twice (once before validation, once after). An
// observer of any single link therefore learns (a) the forward happens in the
// same instant as the receive, (b) every neighbour learns at the same instant,
// and (c) the receiving node relays even payloads it ends up rejecting. The
// three constants below are the whole of the timing/topology countermeasure:
//
// * relay_t = receive_t + jitter, drawn PER PEER, so no two neighbours see
//   the same forward instant;
// * at most `MAX_PROPAGATION_FANOUT` neighbours are told, chosen across
//   network groups (Phase 2C primitive), so the observing set shrinks;
// * the payload is scheduled exactly once, and only after `validate_pure`.
//
// Bound derivation (not chosen at random):
//
// * MIN = 20 ms. The point is only that `relay_t != receive_t` on every link;
//   20 ms sits above local processing / LAN RTT noise (a few ms) so the gap is
//   real rather than rounding, and is two orders of magnitude below any
//   consensus or confirmation cadence, so it cannot be read as a protocol
//   event.
// * MAX = 250 ms. It must stay far below the two clocks that already bound
//   convergence: the inventory sync backstop runs every 10 s
//   (`node.rs:766`) and `FRAME_TIMEOUT` is 30 s. 250 ms is 2.5 % of the
//   backstop, so even a full A→B→C→D→E chain costs ≤ 1 s worst case
//   (≤ 0.5 s expected, uniform) while still spreading a node's fan-out across
//   a 230 ms window — four orders of magnitude wider than the current 0 ms.
//   It is a *floor under the observation*, not an anonymity guarantee: a
//   global observer with both endpoints still sees the pair.
// * FANOUT = 4. Random gossip with fan-out ≥ 3-5 is the standard working
//   point; 4^h covers a 128-node table (`MAX_PEERS`) in 4 hops. Crucially it
//   is NOT the convergence guarantee — `request_full_sync` every 10 s is, and
//   it is untouched by this step. Lowering the fan-out below the typical
//   degree would trade real coverage for a privacy gain this step cannot
//   claim, so it stays deliberately conservative.
//
// NO `PROPAGATION_MAX_ROUNDS`: this architecture has no rounds. Each node
// relays once, on first acceptance; stragglers are covered by the existing
// inventory sync, not by a second relay wave. Adding a rounds constant here
// would document a mechanism that does not exist.
// ---------------------------------------------------------------------------

/// 2E-D: lower bound of the per-peer relay delay. Always > 0, so
/// `relay_t == receive_t` is impossible by construction.
const PROPAGATION_JITTER_MIN: Duration = Duration::from_millis(20);
/// 2E-D: upper bound of the per-peer relay delay (see the derivation above:
/// 2.5 % of the 10 s sync backstop, ≪ the 30 s `FRAME_TIMEOUT`).
const PROPAGATION_JITTER_MAX: Duration = Duration::from_millis(250);
/// 2E-D: maximum number of connected peers a single transaction is forwarded
/// to. Never raised above the degree: a node with fewer peers forwards to all
/// of them (minus the source).
const MAX_PROPAGATION_FANOUT: usize = 4;

/// 2E-A (A.1): write `contents` to `path` so the file is readable by its owner
/// only (0600) instead of inheriting a world-readable umask (0644); the mode is
/// re-asserted after the write, so a file left wide by a previous crash is
/// tightened. The file holds every IP this node has ever dialed, which is the
/// local half of `LOCAL_METADATA_EXPOSURE`.
///
/// Test-only since 4CP-AK / 4CP-AM: production now stages with
/// `write_private_file_new` (exclusive `create_new`, `0600`) and publishes with
/// `rename`, so it never truncates a file in place. This helper keeps the
/// historical create/truncate-and-re-tighten behaviour covered by
/// `test_peer_store_privacy`.
#[cfg(test)]
fn write_private_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.flush()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

// ---------------------------------------------------------------------------
// 4CP-AK (AB-1): coordination of peer-store saves.
//
// `try_save_known_peers` runs its file I/O on a `spawn_blocking` thread so the
// `shutdown()` deadline can bound the wait for it. Two consequences had to be
// handled:
//
//   * the previous code staged into a FIXED `known_peers.json.tmp`, so two
//     saves could truncate each other's staging file and publish a snapshot
//     neither writer ever produced;
//   * a `spawn_blocking` closure is never cancelled, so a save that outlives a
//     `shutdown()` timeout keeps running, and its unconditional `rename` could
//     replace a snapshot written by the *next* cycle.
//
// Both are fixed by coordinating writers **inside the blocking work itself**
// (per destination path), not in an async guard: cancelling the awaiting future
// cannot drop the coordination, because the coordination lives on the thread
// that actually performs the write. No async guard is ever held across an
// `.await`, and the async runtime is never blocked.
// ---------------------------------------------------------------------------

/// Process-wide, monotonic source of peer-store save generations. Taken while
/// the address read lock is held (see `try_save_known_peers`), so a higher
/// generation can never describe an older snapshot.
static PEER_STORE_GENERATION: AtomicU64 = AtomicU64::new(0);

/// One coordination slot per destination path, shared by every writer in the
/// process — including a fresh `P2PNetwork` started after a `shutdown()` that
/// timed out on an earlier save.
#[derive(Default)]
struct PeerStoreSlot {
    /// Held for the whole write+publish of a single save, **on the blocking
    /// thread**. Never acquired from async context.
    write_lock: std::sync::Mutex<()>,
    /// Highest generation whose snapshot has actually been published to this
    /// path. A save older than this is discarded instead of being allowed to
    /// replace the newer snapshot.
    published: AtomicU64,
}

static PEER_STORE_SLOTS: std::sync::OnceLock<
    std::sync::Mutex<HashMap<std::path::PathBuf, Arc<PeerStoreSlot>>>,
> = std::sync::OnceLock::new();

/// Return (creating if needed) the slot for `key`. `key` is a stable,
/// canonicalised form of the destination file, so two spellings of the same
/// path share one slot.
fn peer_store_slot(key: &std::path::Path) -> Arc<PeerStoreSlot> {
    let registry = PEER_STORE_SLOTS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut map = registry.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(key.to_path_buf())
        .or_insert_with(|| Arc::new(PeerStoreSlot::default()))
        .clone()
}

/// Per-save staging path: a hidden sibling of the destination, on the same
/// filesystem (so the final rename is atomic), uniquely named by pid, the save
/// generation and a process-wide counter. Never a fixed name, so two saves can
/// never share a staging file.
fn peer_store_staging_path(path: &std::path::Path, generation: u64) -> std::path::PathBuf {
    static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "known_peers.json".to_string());
    parent.join(format!(
        ".{}.{}.{}.{}.tmp",
        name,
        std::process::id(),
        generation,
        seq
    ))
}

/// Removes a staging file when it goes out of scope, on every exit path. On the
/// success path the file was renamed away first, so the removal then sees
/// `NotFound` and is a no-op.
struct StagingGuard {
    path: std::path::PathBuf,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    "could not remove peer-store staging file {:?}: {}",
                    self.path, e
                );
            }
        }
    }
}

/// Create `path` exclusively and write `contents` with owner-only permissions
/// on Unix. `create_new` makes a name collision a hard error rather than a
/// silent truncation of another writer's staging file.
///
/// `flush` + `sync_all` propagate write/durability errors from the file
/// contents. They do NOT claim that the rename's *directory entry* survives a
/// power loss on every platform — that stronger guarantee is deliberately not
/// promised here; the peer store is a best-effort cache rebuilt from discovery.
fn write_private_file_new(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    }
}

/// Write `json` to `path`, atomically and coordinated process-wide per path.
/// Runs on a blocking thread; every failure is a distinct `Err`.
///
/// Invariants (4CP-AK / AB-1):
///   * the write+publish is serialised per destination path, so two saves never
///     share a staging file;
///   * a save whose generation is older than the last published one is
///     discarded — an old survivor of a cancelled/timed-out save can never
///     replace a newer snapshot;
///   * the destination is replaced by an in-directory `rename` (atomic on Unix
///     and on Windows via `MOVEFILE_REPLACE_EXISTING`); it is never deleted
///     first, so a reader never observes a missing file;
///   * the staging file is removed on every exit path.
fn save_peer_store_blocking(
    path: &std::path::Path,
    json: &str,
    generation: u64,
) -> Result<(), String> {
    run_peer_store_test_hook(generation);

    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create peer store dir {:?}: {}", parent, e))?;

    // Canonicalise so two spellings of the same destination share one slot.
    let key = match std::fs::canonicalize(parent) {
        Ok(p) => p.join(path.file_name().unwrap_or_default()),
        Err(_) => path.to_path_buf(),
    };
    let slot = peer_store_slot(&key);

    // Serialise the whole write+publish for this path. Held only here, on the
    // blocking thread, and never across an `.await`.
    let _guard = slot.write_lock.lock().unwrap_or_else(|e| e.into_inner());

    // Freshness gate. A save that lost the race — or the survivor of a
    // cancelled/timed-out save — must not overwrite a newer snapshot that
    // already landed. A newer generation always wins, so new work can never be
    // displaced by the older work it waited behind.
    let published = slot.published.load(Ordering::SeqCst);
    if generation < published {
        debug!(
            "peer-store save gen {} discarded: gen {} already published",
            generation, published
        );
        return Ok(());
    }

    let tmp = peer_store_staging_path(path, generation);
    let _tmp_guard = StagingGuard { path: tmp.clone() };

    write_private_file_new(&tmp, json)
        .map_err(|e| format!("write peer store {:?}: {}", tmp, e))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("replace peer store {:?}: {}", path, e))?;

    slot.published.store(generation, Ordering::SeqCst);
    Ok(())
}

/// Test-only ordering hook (4CP-AK). It is compiled out of production builds, so
/// it cannot change the production path. Tests use it to hold one generation
/// inside the blocking thread and interleave a newer save.
#[cfg(test)]
static PEER_STORE_TEST_HOOK: std::sync::Mutex<Option<Arc<dyn Fn(u64) + Send + Sync>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn run_peer_store_test_hook(generation: u64) {
    let hook = PEER_STORE_TEST_HOOK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(h) = hook {
        h(generation);
    }
}

#[cfg(not(test))]
fn run_peer_store_test_hook(_generation: u64) {}

/// DEEP SYNC: maximum transactions per SyncResponse page.
/// Each page is ancestor-closed and topologically sorted.
const MAX_SYNC_PAGE: usize = 100;

/// DEEP SYNC: maximum number of ancestor-closure pages that can be computed
/// per GetData request. Total max served = MAX_CLOSURE_PAGES * MAX_SYNC_PAGE.
/// This bounds CPU (BFS walk), memory (HashSet), and network (message size).
const MAX_CLOSURE_PAGES: usize = 10;

/// DEEP SYNC: adaptive backpressure base interval (ms) for SyncResponse delivery.
/// Scales with batch size instead of fixed 50ms per tx.
const BACKPRESSURE_BASE_MS: u64 = 5;

// --- Peer Scoring ---
/// Initial score for new peers
const PEER_SCORE_INITIAL: i32 = 100;
/// Score below this → temporary ban
const PEER_SCORE_BAN_THRESHOLD: i32 = 0;
/// Penalty for invalid message (bad format, invalid tx)
const PEER_PENALTY_INVALID_MSG: i32 = -10;
/// Penalty for contradictory data (conflicting inventory)
const PEER_PENALTY_CONTRADICTION: i32 = -20;
/// Penalty for timeout (slow or stalled peer)
const PEER_PENALTY_TIMEOUT: i32 = -5;
/// Penalty for rate limit hit (flood)
const PEER_PENALTY_FLOOD: i32 = -15;
/// Penalty for abusive/abnormal requests
const PEER_PENALTY_ABUSIVE: i32 = -10;
/// Bonus for successful sync contribution
const PEER_BONUS_SYNC: i32 = 5;
/// Score recovery per decay interval (towards 100)
const PEER_DECAY_RATE: i32 = 1;
/// Decay interval
const PEER_DECAY_INTERVAL: Duration = Duration::from_secs(300);
/// Temporary ban duration
const PEER_BAN_TEMP: Duration = Duration::from_secs(300);
/// Number of temp bans before permanent ban
const PEER_BAN_TEMP_MAX: usize = 3;
/// Permanent ban duration
const PEER_BAN_PERM: Duration = Duration::from_secs(3600);

/// Per-peer reputation score with decay and ban tracking
#[derive(Clone, Debug)]
struct PeerScore {
    score: i32,
    temp_bans: usize,
    last_decay: Instant,
    banned_until: Option<Instant>,
}

impl PeerScore {
    fn new() -> Self {
        Self {
            score: PEER_SCORE_INITIAL,
            temp_bans: 0,
            last_decay: Instant::now(),
            banned_until: None,
        }
    }

    /// Apply decay: score moves towards PEER_SCORE_INITIAL
    fn decay(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_decay) >= PEER_DECAY_INTERVAL {
            if self.score < PEER_SCORE_INITIAL {
                self.score = (self.score + PEER_DECAY_RATE).min(PEER_SCORE_INITIAL);
            } else if self.score > PEER_SCORE_INITIAL {
                self.score = (self.score - PEER_DECAY_RATE).max(PEER_SCORE_INITIAL);
            }
            self.last_decay = now;
        }
    }

    /// Apply a penalty. Returns true if peer should be banned.
    fn penalize(&mut self, penalty: i32) -> bool {
        self.score += penalty;
        self.score <= PEER_SCORE_BAN_THRESHOLD
    }

    /// Apply a bonus (capped at initial)
    fn reward(&mut self, bonus: i32) {
        self.score = (self.score + bonus).min(PEER_SCORE_INITIAL + 50);
    }

    /// Check if currently banned
    fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Ban the peer (temp or perm based on history)
    fn ban(&mut self) {
        self.temp_bans += 1;
        if self.temp_bans >= PEER_BAN_TEMP_MAX {
            self.banned_until = Some(Instant::now() + PEER_BAN_PERM);
        } else {
            self.banned_until = Some(Instant::now() + PEER_BAN_TEMP);
        }
    }
}

/// Maximum frames accepted from a peer per second (rate limit)
const MAX_MSGS_PER_SEC: u64 = 400;

/// Phase 2C: the network group an endpoint belongs to. One group is one
/// unit of eclipse exposure — an attacker who owns one routable allocation
/// occupies exactly one group, so a per-group cap bounds what they can take.
///
/// Derivation of the granularity, and of why IPv6 uses 24 bits rather than a
/// finer /48, in docs/AETHER_PHASE2_ECLIPSE_AUDIT.md §13.1. The short version:
/// the only dangerous direction is *under*-grouping (one real allocation
/// spread over many groups), and every realistic single allocation — IPv4 /24
/// or larger, IPv6 /32 or larger — sits inside exactly one 24-bit group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetworkGroup {
    /// First three octets of an IPv4 address (a /24).
    V4([u8; 3]),
    /// First 24 bits of a native IPv6 address. Coarser than a /48 on purpose:
    /// a /48 would let a single provider allocation span thousands of groups.
    V6([u8; 3]),
}

impl NetworkGroup {
    /// The lossy three-byte projection used by the legacy `subnet_24` helpers.
    /// Erasing the family bit can only ever *merge* two groups, never split
    /// one, so the projection stays on the conservative side.
    fn prefix3(self) -> [u8; 3] {
        match self {
            NetworkGroup::V4(p) | NetworkGroup::V6(p) => p,
        }
    }
}

/// Phase 2C: the single grouping rule for endpoints.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is judged as IPv4. Without this every
/// mapped address collapses into the one group `[0, 0, 0]`, because the first
/// three octets of `::ffff:x.x.x.x` are zero — and a dual-stack listener on
/// Windows returns exactly that form from `accept()`, which would cap a
/// healthy node at four inbound sessions in total.
fn network_group(addr: SocketAddr) -> NetworkGroup {
    match addr {
        SocketAddr::V4(v4) => {
            let o = v4.ip().octets();
            NetworkGroup::V4([o[0], o[1], o[2]])
        }
        SocketAddr::V6(v6) => {
            let o = v6.ip().octets();
            // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d):
            // judge the embedded v4 address, exactly as `is_private_or_reserved`
            // already does, so the two rules can never disagree.
            if o[..10] == [0u8; 10]
                && ((o[10] == 0xff && o[11] == 0xff) || o[10..12] == [0, 0])
            {
                return network_group(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15])),
                    addr.port(),
                ));
            }
            NetworkGroup::V6([o[0], o[1], o[2]])
        }
    }
}

/// Phase 1 helper, retained unchanged in signature because the Phase 1/8 tests
/// assert on it directly. Now a projection of `network_group`, so the two can
/// never drift apart.
fn subnet_24(addr: SocketAddr) -> Option<[u8; 3]> {
    Some(network_group(addr).prefix3())
}

/// 2E-B: how a transport endpoint is bucketed for diversity accounting.
///
/// `Ip` carries the Phase 2C group unchanged — `from_peer_addr` is a thin
/// projection of `network_group`, never a second rule, so the /24 property
/// Phase 2C asserts cannot drift. A transport with no subnet notion maps to
/// `NoNetworkGroup` rather than to an invented group: inventing one would let
/// a non-IP endpoint claim subnet capacity it does not have.
///
/// No production path consumes this key yet — TCP addresses still flow
/// straight through `network_group`. It exists so that a second transport is
/// an addition rather than a rewrite of the peer manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportGroupKey {
    /// The endpoint is IP-addressable; the Phase 2C grouping rule applies.
    Ip(NetworkGroup),
    /// The endpoint belongs to a transport with no subnet notion.
    NoNetworkGroup,
}

impl TransportGroupKey {
    /// Bucket a transport endpoint, using the unchanged Phase 2C rule for IP.
    pub fn from_peer_addr(addr: &PeerAddr) -> Self {
        match addr {
            PeerAddr::Ip(addr) => TransportGroupKey::Ip(network_group(*addr)),
        }
    }
}


/// Count how many connected peers share the same /24 subnet as `addr`.
async fn count_subnet_peers(
    addr: SocketAddr,
    peers: &HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> usize {
    let target = match subnet_24(addr) {
        Some(s) => s,
        None => return 0,
    };
    peers
        .keys()
        .filter(|k| subnet_24(**k) == Some(target))
        .count()
}

/// Count how many connected peers share the same /24 subnet as `addr`,
/// excluding `addr` itself (for checking before adding).
async fn count_subnet_peers_excluding(
    addr: SocketAddr,
    peers: &HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>,
) -> usize {
    let target = match subnet_24(addr) {
        Some(s) => s,
        None => return 0,
    };
    peers
        .keys()
        .filter(|k| **k != addr && subnet_24(**k) == Some(target))
        .count()
}

/// Phase 2C: histogram of `addr` over network groups — how many distinct
/// groups are represented, and how many endpoints each holds. Consumed by the
/// selection debug log and by the Phase 2C tests as the diversity metric.
fn group_counts<'a, I>(addrs: I) -> HashMap<NetworkGroup, usize>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut counts: HashMap<NetworkGroup, usize> = HashMap::new();
    for a in addrs {
        *counts.entry(network_group(a)).or_insert(0) += 1;
    }
    counts
}

/// 2E-D: how long to hold one outbound copy of a relay, drawn for **this
/// peer only**.
///
/// Uniform over `[PROPAGATION_JITTER_MIN, PROPAGATION_JITTER_MAX]`, both ends
/// inclusive. Pure in the injected RNG — no clock, no shared state, and
/// deliberately **no dependence on the transaction**: a delay derived from
/// the payload would replace the fixed-timing signal with a content
/// fingerprint, which is strictly worse.
///
/// The point is that `relay_t - receive_t > 0` on every link and differs
/// between neighbours. It is *not* a defence against an observer that sees
/// both endpoints; 2E-D never claims one.
fn propagation_delay<R: Rng + ?Sized>(rng: &mut R) -> Duration {
    let span = (PROPAGATION_JITTER_MAX.as_millis() - PROPAGATION_JITTER_MIN.as_millis()) as u64;
    PROPAGATION_JITTER_MIN + Duration::from_millis(rng.gen_range(0..=span))
}

/// 2E-D: which connected peers receive one relay wave.
///
/// 1. the upstream peer (`source`) is removed — it already has the payload,
///    and telling it back is both waste and a first-hop signal;
/// 2. the remainder is shuffled with the injected RNG, so the choice is never
///    the `HashMap` iteration order and differs per payload and per seed;
/// 3. if more peers remain than `limit`, at most
///    `ceil(limit / distinct_groups)` are taken per network group — the Phase
///    2C `network_group` primitive, reused rather than reinvented;
/// 4. if topology leaves fewer groups than `limit`, the quota is relaxed so
///    the wave still reaches `limit` peers.
///
/// Step 4 matters: diversity is a preference, the fan-out size is the
/// requirement. A node sitting in one /24 must not silently forward to one
/// peer instead of four.
///
/// Returns **fewer** than `limit` only when fewer peers are connected (or the
/// source accounted for all of them) — never because a quota ran out.
///
/// `select_outbound` is NOT reused here, deliberately: it exists to *dial*
/// addresses the node is not connected to (`!connected.contains(a)`), so fed
/// the session table it would always return an empty vector.
fn propagation_targets<R: Rng + ?Sized>(
    connected: &[SocketAddr],
    source: Option<SocketAddr>,
    limit: usize,
    rng: &mut R,
) -> Vec<SocketAddr> {
    // 1. upstream peer out.
    let mut pool: Vec<SocketAddr> = connected
        .iter()
        .copied()
        .filter(|a| Some(*a) != source)
        .collect();
    if pool.len() <= limit {
        return pool;
    }

    // 2. uniform shuffle (Fisher-Yates over the injected RNG).
    for i in (1..pool.len()).rev() {
        let j = rng.gen_range(0..=i);
        pool.swap(i, j);
    }

    // 3. diversity quota: one group may not own the whole wave.
    let distinct = group_counts(pool.iter().copied()).len().max(1);
    let quota = limit.div_ceil(distinct);
    let mut used: HashMap<NetworkGroup, usize> = HashMap::new();
    let mut picked: Vec<SocketAddr> = Vec::with_capacity(limit);
    let mut overflow: Vec<SocketAddr> = Vec::new();
    for a in pool {
        let g = network_group(a);
        let n = used.get(&g).copied().unwrap_or(0);
        if picked.len() < limit && n < quota {
            *used.entry(g).or_insert(0) += 1;
            picked.push(a);
        } else {
            overflow.push(a);
        }
    }

    // 4. relax — fill up to `limit` whatever is left, in shuffled order.
    for a in overflow {
        if picked.len() >= limit {
            break;
        }
        picked.push(a);
    }
    picked
}

/// Phase 2C: may one more *inbound* connection be accepted?
///
/// The guarantee, and the whole point of `PROTECTED_OUTBOUND_SLOTS`:
///
/// > whenever this returns true, `(total - outbound) + PROTECTED_OUTBOUND_SLOTS
/// > <= MAX_PEERS` — i.e. the reservation still fits in the table *after* this
/// > connection is admitted, so `outbound_admitted` keeps holding for at least
/// > `PROTECTED_OUTBOUND_SLOTS - outbound` further dials.
///
/// Without it a client that opens 128 connections fills the shared `MAX_PEERS`
/// table and `connect_to_peer_inner` refuses every subsequent dial — the node
/// keeps gossiping while being unable to initiate a single session (audit L1,
/// scenario A). `outbound` is passed in because a node that already holds its
/// reserved outbound sessions owes no further reservation: counting against the
/// *total* alone would throttle inbound on an outbound-heavy node.
fn inbound_admitted(total: usize, outbound: usize) -> bool {
    if outbound > total {
        // Direction bookkeeping can only ever be a subset of the session map;
        // treat anything else as "admit nothing" rather than unwrap it.
        return false;
    }
    // Sessions we still owe outbound. Each already-open outbound session counts
    // towards that target, so the reservation shrinks as they are filled.
    let reserve = PROTECTED_OUTBOUND_SLOTS.saturating_sub(outbound);
    // `total + 1` is the table once this inbound is admitted. It may enter only
    // if what outbound is still owed still fits alongside it.
    total + 1 + reserve <= MAX_PEERS
}

/// Phase 2C: may one more *outbound* connection be opened? Deliberately looser
/// than the inbound rule — the reserved slots exist precisely so this keeps
/// holding while inbound traffic saturates everything else.
fn outbound_admitted(total: usize) -> bool {
    total < MAX_PEERS
}

// ---------------------------------------------------------------------------
// Phase 2B pure helpers. Deliberately free of I/O and of `self` so every
// policy decision below is directly unit-testable.
// ---------------------------------------------------------------------------

/// Current wall-clock time in Unix seconds (metadata timestamps are persisted,
/// so they cannot be `Instant`).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Phase 2B (D7): classify an address. Priority is security-first:
/// `Penalized` beats everything (a banned peer is never "active" to us),
/// then liveness, then standing, then recency.
fn categorise(
    connected: bool,
    anchor: bool,
    penalized: bool,
    last_success: Option<u64>,
    now_unix: u64,
) -> PeerCategory {
    if penalized {
        PeerCategory::Penalized
    } else if connected {
        PeerCategory::Active
    } else if anchor {
        PeerCategory::Anchor
    } else if last_success
        .map(|t| now_unix.saturating_sub(t) <= RECENT_PEER_WINDOW_SECS)
        .unwrap_or(false)
    {
        PeerCategory::Recent
    } else {
        PeerCategory::Candidate
    }
}

/// Phase 2B (D6): addresses that must never be dialled on the authority of a
/// PEX hint. A peer that can steer us into dialing `127.0.0.1`, an RFC1918 or
/// a link-local host redirects our traffic onto a machine we own or probes our
/// LAN.
///
/// R4: this gate applies **only** to PEX-sourced addresses. Operator-configured
/// bootnodes and DNS seeds stay unrestricted, so private/LAN testnets keep
/// working.
fn is_private_or_reserved(addr: SocketAddr) -> bool {
    use std::net::IpAddr;
    match addr.ip() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            match (o[0], o[1], o[2]) {
                // 0.0.0.0/8 "this network" + broadcast
                (0, _, _) | (255, 255, 255) => true,
                // 10.0.0.0/8 (RFC1918)
                (10, _, _) => true,
                // 100.64.0.0/10 (CGNAT)
                (100, 64..=127, _) => true,
                // 127.0.0.0/8 (loopback)
                (127, _, _) => true,
                // 169.254.0.0/16 (link-local)
                (169, 254, _) => true,
                // 172.16.0.0/12 (RFC1918)
                (172, 16..=31, _) => true,
                // 192.168.0.0/16 (RFC1918)
                (192, 168, _) => true,
                // 192.0.0.0/24 (IETF protocol assignments)
                (192, 0, 0) => true,
                // 198.18.0.0/15 (benchmarking)
                (198, 18..=19, _) => true,
                // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved)
                (224..=239, _, _) | (240..=255, _, _) => true,
                _ => false,
            }
        }
        IpAddr::V6(ip) => {
            let o = ip.octets();
            // IPv4-mapped / IPv4-compatible: judge the embedded v4 address.
            if o[..10] == [0u8; 10]
                && ((o[10] == 0xff && o[11] == 0xff) || o[10..12] == [0, 0])
            {
                let v4 = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
                return is_private_or_reserved(SocketAddr::new(v4.into(), addr.port()));
            }
            // :: (unspecified) and ::1 (loopback)
            if o == [0u8; 16] {
                return true;
            }
            if o[..15] == [0u8; 15] && o[15] == 1 {
                return true;
            }
            // fe80::/10 (link-local)
            if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
                return true;
            }
            // fc00::/7 (unique-local)
            if o[0] & 0xfe == 0xfc {
                return true;
            }
            // ff00::/8 (multicast)
            if o[0] == 0xff {
                return true;
            }
            false
        }
    }
}

/// Phase 2B (D5): the addresses eligible for a single PEX send. Replaces the
/// old behaviour of relaying the entire known set (up to `MAX_KNOWN_PEERS`) to
/// every peer every 15 seconds. Drops: ourselves, the recipient, banned or
/// penalized entries, anything the recipient itself taught us (no echo), and
/// hints we have held longer than `PEX_SHARE_MAX_AGE_SECS` (aging). Best
/// quality first, capped at `limit`.
///
/// Private addresses are deliberately *not* filtered here: the D6 gate belongs
/// on the dial decision (receive side), and suppressing private addresses on
/// the send side would break relay inside a LAN testnet (R4).
fn pex_sample(
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores: &HashMap<SocketAddr, PeerScore>,
    origins: &HashMap<SocketAddr, SocketAddr>,
    local: SocketAddr,
    recipient: SocketAddr,
    now_unix: u64,
    limit: usize,
) -> Vec<SocketAddr> {
    let mut picked: Vec<(i32, SocketAddr)> =
        P2PNetwork::pex_broadcast_list(entries, scores, local)
            .into_iter()
            .filter(|a| *a != recipient)
            // Never echo an address straight back to the peer that taught us it.
            .filter(|a| origins.get(a).copied() != Some(recipient))
            // PEX aging: hints held longer than PEX_SHARE_MAX_AGE_SECS stay in
            // the table for our own redial but are no longer gossiped.
            .filter(|a| {
                entries
                    .get(a)
                    .map(|e| now_unix.saturating_sub(e.first_seen) <= PEX_SHARE_MAX_AGE_SECS)
                    .unwrap_or(true)
            })
            .map(|a| {
                let q = entries
                    .get(&a)
                    .map(|e| e.quality)
                    .unwrap_or_else(default_peer_quality);
                (q, a)
            })
            .collect();
    // Deterministic: best quality first, address as tiebreak. Pseudo-random
    // outbound selection is 2C (D10), not this stage.
    picked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    picked.truncate(limit);
    picked.into_iter().map(|(_, a)| a).collect()
}

/// Phase 2B (D8): admission decision for a table already at capacity. Returns
/// the address that should be evicted to make room, or `None` when nothing is
/// worth replacing (the caller then simply keeps the table as it is).
///
/// This is the anti-poisoning control: the old code refused every new address
/// once `MAX_KNOWN_PEERS` was reached, so a hostile PEX burst of junk both
/// filled the table and then froze it permanently. Connected peers and anchors
/// are never victims; banned entries are always the preferred victim.
fn admit_peer(
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores: &HashMap<SocketAddr, PeerScore>,
    connected: &HashSet<SocketAddr>,
    incoming: SocketAddr,
    incoming_quality: i32,
) -> Option<SocketAddr> {
    if entries.contains_key(&incoming) || entries.len() < MAX_KNOWN_PEERS {
        return None;
    }
    let mut best: Option<(i32, i32, u64, SocketAddr)> = None;
    for (a, e) in entries {
        if connected.contains(a) {
            continue;
        }
        if e.anchor {
            continue;
        }
        let banned = scores.get(a).map(|s| s.is_banned()).unwrap_or(false);
        // Lower tuple wins as a victim: banned first, then lowest quality,
        // then oldest, then address (determinism).
        let key = (if banned { 0 } else { 1 }, e.quality, e.first_seen, *a);
        if best.map(|b| key < b).unwrap_or(true) {
            best = Some(key);
        }
    }
    let (banned_flag, quality, _, victim) = best?;
    if banned_flag == 0 || quality <= incoming_quality {
        Some(victim)
    } else {
        None
    }
}

/// Phase 2B (D9): recompute the anchor set. Surviving anchors and freshly
/// eligible candidates are merged, ranked by most recent success, deduplicated,
/// the local address excluded, and the whole set capped at `MAX_ANCHORS`.
/// Several anchors at once, never one — and never a hard requirement: this is
/// only ever a redial preference, so losing all of them costs nothing but a
/// fallback to store / PEX / seeds.
fn promote_anchors(
    current: &[(SocketAddr, u64)],
    candidates: &[(SocketAddr, u64)],
    local: SocketAddr,
) -> HashSet<SocketAddr> {
    let mut all: Vec<(u64, SocketAddr)> = current
        .iter()
        .chain(candidates.iter())
        .map(|(a, t)| (*t, *a))
        .filter(|(_, a)| *a != local)
        .collect();
    // Newest success first, so rotation drops the least-recently-useful anchor.
    all.sort_by(|a, b| b.cmp(a));
    let mut seen = HashSet::new();
    all.retain(|(_, a)| seen.insert(*a));
    all.truncate(MAX_ANCHORS);
    all.into_iter().map(|(_, a)| a).collect()
}

/// Phase 2B (D9): anchors with no successful contact for `ANCHOR_TTL_SECS`
/// are expired rather than kept forever. Replaceable, never authoritative.
fn expire_anchors(anchors: &[(SocketAddr, u64)], now_unix: u64) -> Vec<SocketAddr> {
    anchors
        .iter()
        .filter(|(_, last)| now_unix.saturating_sub(*last) > ANCHOR_TTL_SECS)
        .map(|(a, _)| *a)
        .collect()
}

/// Phase 2C: the outbound candidate order (audit L2).
///
/// Before this function existed the order came from `HashMap` iteration —
/// unpredictable to a distant attacker, but *stable inside a process* and
/// completely indifferent to quality, freshness, anchors, reputation and
/// network group. Every redial cycle therefore restarted from the same order
/// with the same budget, so the node never "discovered" anything its initial
/// hashing had not already placed first.
///
/// Two phases, so the Phase-2A invariant survives: **every known candidate
/// precedes every configured seed** (`test_seeds_are_unprivileged_in_redial`).
///
/// 1. **Known addresses** — weighted random sampling without replacement.
///    Weight is quality plus an anchor bonus plus a recency bonus, minus a
///    penalty per live session already held in the same network group. Every
///    coefficient is a fraction of `PEER_SCORE_INITIAL`, keeping quality the
///    dominant term (see the constant block).
/// 2. **Configured seeds** — appended afterwards, in configuration order, under
///    the same per-group quota. Unprivileged, but *reserved* a slice of the
///    round: without it a store that is already full pushes every seed out of
///    every round, which is seed authority by absence rather than by rank.
///
/// `ordered` is the Phase-2A candidate order produced by
/// `P2PNetwork::redial_candidates`: every address the node already knows first,
/// configured seeds appended last, its own listen address removed. `seed_tail`
/// marks which members of `ordered` are those appended seeds, so phase 1 can
/// re-rank the known half freely while phase 2 still keeps the tail behind it.
///
/// The RNG is injected so tests are deterministic (`StdRng::seed_from_u64`);
/// production reseeds from the OS each round, which is also what makes the
/// order differ from cycle to cycle.
///
/// Returns *fewer* than `limit` rather than relaxing the group quota: filling
/// the last slots from one over-represented group is exactly what scenario B
/// forbids. Progress is still guaranteed because the quota is recomputed from
/// live sessions every round, so a group climbs towards `MAX_PEERS_PER_SUBNET`
/// a few candidates at a time and then steps aside.
fn select_outbound<R: Rng + ?Sized>(
    ordered: &[SocketAddr],
    seed_tail: &HashSet<SocketAddr>,
    entries: &HashMap<SocketAddr, AddressEntry>,
    scores: &HashMap<SocketAddr, PeerScore>,
    connected: &HashSet<SocketAddr>,
    limit: usize,
    now_unix: u64,
    rng: &mut R,
) -> Vec<SocketAddr> {
    use rand::distributions::{Distribution, WeightedIndex};

    let live_by_group = group_counts(connected.iter().copied());
    let mut used: HashMap<NetworkGroup, usize> = HashMap::new();
    let mut picked: Vec<SocketAddr> = Vec::with_capacity(limit);
    let mut seen: HashSet<SocketAddr> = HashSet::new();

    let banned = |a: &SocketAddr| scores.get(a).map(|s| s.is_banned()).unwrap_or(false);

    /// Still dialable this round: not holding a session, not already picked,
    /// not banned.
    fn eligible(
        a: &SocketAddr,
        connected: &HashSet<SocketAddr>,
        seen: &HashSet<SocketAddr>,
        banned: &impl Fn(&SocketAddr) -> bool,
    ) -> bool {
        !connected.contains(a) && !seen.contains(a) && !banned(a)
    }
    let is_eligible =
        |a: &SocketAddr, seen: &HashSet<SocketAddr>| eligible(a, connected, seen, &banned);

    // A candidate may be taken only while it still has quota left: never more
    // than `MAX_CANDIDATES_PER_GROUP` in one round, and never enough to push
    // the group past `MAX_PEERS_PER_SUBNET` once live sessions are counted.
    let quota_left = |g: NetworkGroup, used: &HashMap<NetworkGroup, usize>| -> bool {
        let u = used.get(&g).copied().unwrap_or(0);
        if u >= MAX_CANDIDATES_PER_GROUP {
            return false;
        }
        let live = live_by_group.get(&g).copied().unwrap_or(0);
        live + u < MAX_PEERS_PER_SUBNET
    };

    // Reserve a slice of the round for configured seeds so a store that is
    // already full — poisoned or merely large — cannot push every seed out of
    // every round. One group's worth, i.e. the same quota any candidate gets.
    let seed_reserve = ordered
        .iter()
        .filter(|a| seed_tail.contains(*a) && is_eligible(a, &seen))
        .take(MAX_CANDIDATES_PER_GROUP)
        .count();
    let known_limit = limit.saturating_sub(seed_reserve);

    // Phase 1: known addresses, weighted and group-quota'd.
    loop {
        if picked.len() >= known_limit {
            break;
        }
        let mut pool: Vec<(SocketAddr, u64)> = Vec::new();
        for a in ordered {
            if seed_tail.contains(a) || !is_eligible(a, &seen) {
                continue;
            }
            let g = network_group(*a);
            if !quota_left(g, &used) {
                continue;
            }
            let live = live_by_group.get(&g).copied().unwrap_or(0);
            let e = entries.get(a);
            let mut w = i64::from(e.map(|e| e.quality).unwrap_or_else(default_peer_quality));
            if e.map(|e| e.anchor).unwrap_or(false) {
                w += i64::from(ANCHOR_SELECT_BONUS);
            }
            if e.and_then(|e| e.last_success)
                .map(|t| now_unix.saturating_sub(t) <= RECENT_PEER_WINDOW_SECS)
                .unwrap_or(false)
            {
                w += i64::from(RECENT_SUCCESS_BONUS);
            }
            w -= i64::from(GROUP_OVERREPRESENTATION_PENALTY) * live as i64;
            pool.push((*a, (w.max(0) as u64).saturating_add(MIN_SELECT_WEIGHT)));
        }
        if pool.is_empty() {
            break;
        }
        let Ok(dist) = WeightedIndex::new(pool.iter().map(|(_, w)| *w)) else {
            break;
        };
        let (addr, _) = pool[dist.sample(rng)];
        *used.entry(network_group(addr)).or_insert(0) += 1;
        seen.insert(addr);
        picked.push(addr);
    }

    // Phase 2: configured seeds, always behind every known candidate.
    for a in ordered {
        if !seed_tail.contains(a) {
            continue;
        }
        if picked.len() >= limit {
            break;
        }
        if !is_eligible(a, &seen) {
            continue;
        }
        let g = network_group(*a);
        if !quota_left(g, &used) {
            continue;
        }
        *used.entry(g).or_insert(0) += 1;
        seen.insert(*a);
        picked.push(*a);
    }

    picked
}

// ---------------------------------------------------------------------------
// Phase 2D — self-healing. Pure and I/O-free, so every transition and every
// bound is directly testable without a socket: the recovery task below is only
// the loop around these functions.
// ---------------------------------------------------------------------------

/// Where the node stands relative to its peer count.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RecoveryState {
    /// `count >= RECOVERY_COMFORT_PEERS`: nothing to do. No dial, no log.
    Healthy,
    /// Below comfort with a dialable source left and no backoff pending:
    /// a round may run.
    Recovering,
    /// Below `RECOVERY_THRESHOLD` while the controller backoff is still
    /// running: recovery is throttled, not stalled — the next round re-checks.
    Degraded,
    /// Below `RECOVERY_THRESHOLD` with no dialable source left, or the
    /// consecutive-failure budget is spent. No further dial is issued.
    Exhausted,
}

/// Bounded controller state. Holds no session or address lock, ever.
#[derive(Clone, Copy, Debug)]
struct PeerRecoveryController {
    state: RecoveryState,
    /// When the last round issued its dials.
    last_attempt: Option<Instant>,
    /// Consecutive rounds that opened no session, `0 ..= RECOVERY_MAX_LEVEL`.
    backoff_level: u32,
    /// Consecutive rounds that opened no session,
    /// `0 ..= RECOVERY_MAX_CONSECUTIVE_FAILURES`.
    consecutive_failures: u32,
}

impl PeerRecoveryController {
    fn new() -> Self {
        Self {
            state: RecoveryState::Healthy,
            last_attempt: None,
            backoff_level: 0,
            consecutive_failures: 0,
        }
    }

    /// Delay before the *next* round may dial. Level 0 means "no extra delay",
    /// so a healthy controller never throttles anything.
    fn backoff(&self) -> Duration {
        recovery_backoff(self.backoff_level)
    }

    fn backoff_due(&self, now: Instant) -> bool {
        match self.last_attempt {
            None => true,
            Some(t) => now >= t + self.backoff(),
        }
    }

    /// One round finished. Any session opened counts as success and clears the
    /// backoff completely; a round that opened none climbs one level, bounded.
    fn record_round(&mut self, opened: usize, now: Instant) {
        self.last_attempt = Some(now);
        if opened > 0 {
            self.backoff_level = 0;
            self.consecutive_failures = 0;
        } else {
            self.backoff_level = (self.backoff_level + 1).min(RECOVERY_MAX_LEVEL);
            self.consecutive_failures = (self.consecutive_failures + 1)
                .min(RECOVERY_MAX_CONSECUTIVE_FAILURES);
        }
    }

    /// Back to `Healthy`: the hysteresis band is left, so every accumulated
    /// throttle is discarded rather than carried into the next incident.
    fn reset(&mut self) {
        self.state = RecoveryState::Healthy;
        self.last_attempt = None;
        self.backoff_level = 0;
        self.consecutive_failures = 0;
    }

    fn set_state(&mut self, state: RecoveryState) {
        self.state = state;
    }

    /// Clear the consecutive-failure latch once a full backoff has expired.
    ///
    /// Without it `Exhausted` would be terminal and a node whose peers came
    /// back later would never probe again. With it the controller settles into
    /// one probe per `RECOVERY_BACKOFF_MAX_SECS` (60s) — strictly slower than
    /// the pre-existing 5s redial loop, so recovery never becomes the
    /// aggressor, and never a hot loop.
    fn open_probe_window(&mut self) {
        self.consecutive_failures = 0;
    }
}

/// `5s, 10s, 20s, 40s, 60s, 60s` for levels `1..=6`, `0` for level `0`.
///
/// Identical in shape to the existing per-candidate backoff
/// (`min(2 ^ min(attempt, 6), 60)` at `:2076`) so the codebase does not end up
/// with two different notions of "how long to wait".
fn recovery_backoff(level: u32) -> Duration {
    if level == 0 {
        return Duration::ZERO;
    }
    let shift = (level - 1).min(RECOVERY_MAX_LEVEL - 1);
    let secs = (RECOVERY_BACKOFF_BASE_SECS << shift).min(RECOVERY_BACKOFF_MAX_SECS);
    Duration::from_secs(secs)
}

/// The whole state machine, as one pure function.
///
/// The hysteresis is `RECOVERY_THRESHOLD (4) < RECOVERY_COMFORT_PEERS (8)`:
/// recovery *starts* only below 4 and *stops* only at 8, so a count sitting in
/// `[4, 8)` neither starts nor stops it. From `Healthy`, a dip to 7 therefore
/// does nothing at all — which is exactly the `7 -> recovery, 8 -> stop, 7 ->
/// recovery` flapping this band exists to prevent.
fn next_state(
    prev: RecoveryState,
    count: usize,
    sources_left: bool,
    backoff_pending: bool,
    failures_exhausted: bool,
) -> RecoveryState {
    if count >= RECOVERY_COMFORT_PEERS {
        return RecoveryState::Healthy;
    }
    let deep = count < RECOVERY_THRESHOLD;
    if failures_exhausted || (deep && !sources_left) {
        return RecoveryState::Exhausted;
    }
    if prev != RecoveryState::Healthy || deep {
        if backoff_pending {
            RecoveryState::Degraded
        } else {
            RecoveryState::Recovering
        }
    } else {
        // Inside the band, entering from `Healthy`: hold. Nothing is broken
        // enough to warrant a round, and nothing recovers "just in case".
        RecoveryState::Healthy
    }
}

/// The outcome of one recovery round: the state it lands in and, if it may
/// dial, the addresses to dial in tier order. The per-tier counts exist only
/// for the round's diagnostic line — they describe where the dial budget went.
#[derive(Debug)]
struct RecoveryRound {
    state: RecoveryState,
    dial: Vec<SocketAddr>,
    /// Addresses taken from each tier, in ladder order.
    tier1_anchors: usize,
    tier2_known: usize,
    tier3_seeds: usize,
    /// At least one address across the three tiers is dialable at all.
    sources_left: bool,
}

/// The source ladder for one round.
///
/// Tier 1 anchors — addresses we have already reached and deliberately kept,
/// most recently proven first. Tier 2 everything else the node knows (peer
/// store + PEX), already ranked and network-group quota'd by Phase 2C's
/// `select_outbound`. Tier 3 configured seeds, **withheld** while tiers 1 and
/// 2 still hold something to try, and released only when a round has already
/// failed (`consecutive_failures > 0`) or when there is nothing else at all.
///
/// The seed is therefore a genuine last resort rather than a quota every round
/// — the gap Phase 2D exists to close (audit §C.1).
///
/// Tiers 1 and 3 bypass `select_outbound`, so they re-apply the same `/24`
/// invariant here with the same primitives (`network_group`, `group_counts`,
/// `MAX_PEERS_PER_SUBNET`); `connect_to_peer_inner` enforces it again per dial.
/// The `/24` room check shared by tiers 1 and 3 (tier 2 gets it for free from
/// `select_outbound`). Returns false when taking `a` would push its network
/// group past `MAX_PEERS_PER_SUBNET`, counting both live sessions and the
/// candidates already taken this round. On success it records the take.
///
/// A free function rather than a closure so the `used` tally can be updated
/// in place between checks without borrowing it twice.
fn recovery_group_room(
    a: SocketAddr,
    live: &HashMap<NetworkGroup, usize>,
    used: &mut HashMap<NetworkGroup, usize>,
) -> bool {
    let g = network_group(a);
    let live_n = live.get(&g).copied().unwrap_or(0);
    let used_n = used.get(&g).copied().unwrap_or(0);
    if live_n + used_n >= MAX_PEERS_PER_SUBNET {
        return false;
    }
    *used.entry(g).or_insert(0) += 1;
    true
}

fn plan_recovery(
    local: SocketAddr,
    count: usize,
    anchors: &[(SocketAddr, u64)],
    known: &[SocketAddr],
    seeds: &[SocketAddr],
    connected: &HashSet<SocketAddr>,
    is_banned: &dyn Fn(&SocketAddr) -> bool,
    controller: &PeerRecoveryController,
    now: Instant,
) -> RecoveryRound {
    let live = group_counts(connected.iter().copied());
    let mut used: HashMap<NetworkGroup, usize> = HashMap::new();
    let mut dial: Vec<SocketAddr> = Vec::with_capacity(MAX_DIALS_PER_ROUND);
    let mut picked: HashSet<SocketAddr> = HashSet::new();

    // Tier 1: anchors, most recently proven first.
    let mut ranked: Vec<(SocketAddr, u64)> = anchors
        .iter()
        .filter(|(a, _)| !connected.contains(a) && !is_banned(a) && *a != local)
        .copied()
        .collect();
    ranked.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
    for (a, _) in ranked {
        if dial.len() >= MAX_DIALS_PER_ROUND {
            break;
        }
        if !recovery_group_room(a, &live, &mut used) {
            continue;
        }
        picked.insert(a);
        dial.push(a);
    }
    let tier1_anchors = dial.len();

    // Tier 2: everything else the node knows, in the order 2C ranked it.
    for a in known {
        if dial.len() >= MAX_DIALS_PER_ROUND {
            break;
        }
        if picked.contains(a) || *a == local || connected.contains(a) || is_banned(a) {
            continue;
        }
        // Tier 2 already passed this quota inside `select_outbound`; re-applying
        // it here keeps tiers 1 and 2 from each spending the same group's room.
        if !recovery_group_room(*a, &live, &mut used) {
            continue;
        }
        picked.insert(*a);
        dial.push(*a);
    }
    let primary_empty = dial.is_empty();
    let tier2_known = dial.len() - tier1_anchors;

    // Tier 3: configured seeds, last resort.
    if primary_empty || controller.consecutive_failures > 0 {
        for s in seeds {
            if dial.len() >= MAX_DIALS_PER_ROUND {
                break;
            }
            if picked.contains(s) || *s == local || connected.contains(s) || is_banned(s) {
                continue;
            }
            if !recovery_group_room(*s, &live, &mut used) {
                continue;
            }
            picked.insert(*s);
            dial.push(*s);
        }
    }

    // Whether *any* tier still holds a dialable address, quota aside. This is
    // what tells `Exhausted` apart from "nothing left to try".
    let sources_left = anchors
        .iter()
        .map(|(a, _)| a)
        .chain(known.iter())
        .chain(seeds.iter())
        .any(|a| *a != local && !connected.contains(a) && !is_banned(a));

    let state = next_state(
        controller.state,
        count,
        sources_left,
        !controller.backoff_due(now),
        controller.consecutive_failures >= RECOVERY_MAX_CONSECUTIVE_FAILURES,
    );

    let tier3_seeds = dial.len() - tier1_anchors - tier2_known;

    RecoveryRound {
        state,
        dial,
        tier1_anchors,
        tier2_known,
        tier3_seeds,
        sources_left,
    }
}

/// Phase 2B: the shared ingress point for a newly-discovered address, usable by
/// callers that only hold the raw table guards (`accept_loop` and the PEX
/// branch of `handle_peer`). Records how the address was learned, stamps the
/// TTL clock, and applies quality-aware admission (D8) when the table is
/// already full. Returns true when the address ended up known.
async fn ingress_address(
    addresses: &Arc<RwLock<AddressManager>>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
    local: SocketAddr,
    addr: SocketAddr,
    source: PeerSource,
) -> bool {
    if addr == local || addr.port() == 0 {
        return false;
    }
    let now = unix_now();
    let at = Instant::now();

    // Snapshot the session table and release it *before* taking the address
    // manager. The old code held `known` while reading `sessions`, `scores`,
    // `meta` and `seen` in several different orders; nesting is now impossible
    // because only one of the two guards is ever held.
    let connected: HashSet<SocketAddr> = sessions.read().await.keys().copied().collect();

    let mut mgr = addresses.write().await;
    match mgr.admit(addr, source, admission_quality(source), now, at, &connected) {
        // Already present: refresh the TTL clock — or, when the announce
        // source is PEX, halve the failure debt (see `pex_refresh`).
        // NOTE (4CH): the production `P2PMessage::Peers` arm now refreshes
        // every held address itself (one halving per announce, intra-message
        // duplicates collapsed) and no longer routes held addresses through
        // this function; this PEX branch only covers the membership race
        // where an address is inserted between the arm's snapshot and this
        // admission call. The network wake paths are: PEX refresh, a
        // completed handshake (record_success), and TTL expiry followed by
        // fresh admission.
        Admission::AlreadyKnown => {
            if source == PeerSource::Pex {
                mgr.pex_refresh(addr, at);
            } else {
                mgr.touch(addr, at);
            }
            true
        }
        Admission::Inserted { .. } => true,
        Admission::Refused => false,
    }
}

// H2: network timeouts. A peer that connects and never speaks (slow-loris),
// stalls mid-frame, or points at a black-holed address must be released
// instead of holding a task + socket forever.
/// Handshake (magic + X25519) must complete within this budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Inactivity budget for reading a single frame (length/nonce/ciphertext).
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
/// Outbound connect budget (black-holed addresses must not stall discovery).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 4CP-Y (X-2) / 4CP-AA: the single teardown deadline for `shutdown()`. It is
/// armed once, after the synchronous teardown steps, and the remaining time is
/// applied to *both* bounded waits that can plausibly block: aborting+awaiting
/// every tracked task and the final peer-store flush. A per-task 5 s allowance
/// (5 s × N) is deliberately not used. The deadline does NOT cover the handful
/// of synchronous lock acquisitions or the `session_auth` registry seal that
/// precede it — those are not awaited I/O — so the total wall time of
/// `shutdown()` is this budget plus that fixed, small prologue.
const SHUTDOWN_TASK_BUDGET: Duration = Duration::from_secs(30);
/// 4CP-Y (X-4): per-write budget for the per-session send task. A peer that
/// stops reading must not pin the task (and the task's socket) forever; on
/// timeout the session's writer is dropped and the task ends.
const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// 4CE hygiene: consecutive dial failures after which a never-successful,
/// non-configured entry sleeps out of redial (see `redial_sleep`). Five
/// failures span roughly the first minute of redial (backoffs 1,2,4,8,16s
/// inside the 5s cycle): a merely flaky peer (1-2 fails) is unaffected,
/// while an address that has never completed one handshake stops costing a
/// dial per backoff window until a handshake completes (either direction)
/// or the TTL expires and the address is admitted fresh. A PEX
/// re-announcement reaches held addresses since 4CH and halves their debt
/// once per announce (never a full reset), so it is a progressive — not
/// immediate — wake (see `pex_refresh`). Configured seeds are exempt
/// (operator intent outranks hygiene).
const MAX_DIAL_FAILURES_SLEEP: u32 = 5;

// H4/V-24: network identity in the P2P handshake. Two networks with
// different genesis hashes must NOT interconnect (cross-network gossip and
// inventory pollution). The genesis hash (public constant) identifies the
// network; the protocol version guards the wire format. This is a BREAKING
// protocol change (the handshake frame grew from 36 to 69 bytes, then to
// 77 with the 4V network id): every node
// on the network must run the same binary — safe here because the testnet is
// not yet public and the genesis ceremony purges all node data dirs.
// v2 → v3 (WEIGHT): `tx.weight` is now DAG-maintained (subtree size) and
// Stable/practically_final became reachable. Status semantics changed, so
// mixed-version peers would disagree on finality — the version bump splits
// old and new networks. Deployment MUST rotate the genesis (ceremony) so the
// new network starts from a clean state.
// v3 → v4 (2E-A METADATA HARDENING): the frame layout changed. Every frame's
// `total_len` is now padded up to a `FRAME_PAD_BUCKET` multiple, the
// ciphertext carries `pad_message()` (pad + u16-LE pad length, authenticated
// by Poly1305), and the handshake magic is the obfuscated
// `handshake_wire_magic()` instead of the ASCII "AETH". v3 peers send
// unpadded frames whose `total_len` is not bucket-aligned and an unobfuscated
// magic, so `verify_handshake_identity` and the frame-length check both reject
// them. THIS IS A BREAKING CHANGE: PROTOCOL_COMPATIBILITY = BREAKING. A v3
// peer is rejected at the handshake (magic first, then version), so a mixed
// network partitions cleanly along the version byte rather than desyncing
// later on a padded frame — the same strategy v2→v3 used.
/// Wire format version of the P2P handshake.
// OBSERVABILITY-ONLY visibility: `pub` so the boot banner can log it.
pub const P2P_PROTOCOL_VERSION: u8 = 5;
/// Handshake frame: magic(4) | version(1) | genesis hash(32) | network(8) | ephemeral key(32)
/// PHASE 4V: the trailing 8 bytes carry the node's V6 network id (u64 LE,
/// exact-match checked). Genesis check retained (defense in depth); the
/// network field is what separates testnets sharing one binary/genesis.
const HANDSHAKE_FRAME_LEN: usize = 4 + 1 + 32 + 8 + 32;

// ---------------------------------------------------------------------------
// PHASE 4CP: authenticated P2P v6 handshake.
//
// v5 remains byte-for-byte unchanged as an explicitly selected legacy mode.
// v6 adds a nonce and a persistent Ed25519 `NodeId` to the Hello and then
// exchanges an Ed25519 signature over a canonical transcript. There is NO
// capability negotiation and NO automatic v6 -> v5 fallback: a peer that does
// not speak v6 fails the handshake, always.
// ---------------------------------------------------------------------------
/// Wire format version of the authenticated P2P handshake.
pub const P2P_PROTOCOL_VERSION_V6: u8 = 6;
/// v6 Hello: magic(4) | version(1) | genesis(32) | network(8) |
/// ephemeral X25519 key(32) | fresh nonce(32) | node id(32).
const V6_HELLO_LEN: usize = 4 + 1 + 32 + 8 + 32 + 32 + 32;
/// Ed25519 signature carried after the Hello exchange (raw 64 bytes).
const V6_SIG_LEN: usize = 64;
/// Signature domain separator for the v6 session transcript.
const V6_AUTH_DOMAIN: &[u8] = b"aether-p2p-auth-v1";
/// Session-key domain separator; distinct from v5's `aether-p2p-key-v1` so a
/// v5 and a v6 session can never derive the same key material.
const V6_KEY_DOMAIN: &[u8] = b"aether-p2p-key-v2";
/// Role tags used in the transcript and in the signed message. The role byte
/// inside the signature is what defeats reflection of one side's signature
/// back to it (a reflected signature carries the wrong role).
const V6_ROLE_INITIATOR: u8 = 0x01;
const V6_ROLE_RESPONDER: u8 = 0x02;

/// PHASE 4CP: the three identity-bearing fields of a v6 Hello.
#[derive(Clone, Copy)]
struct V6Hello {
    eph: [u8; 32],
    nonce: [u8; 32],
    node_id: [u8; 32],
}

/// Insert into the seen-transaction cache, evicting old entries once the
/// cache is full so memory stays bounded under flood.
async fn insert_seen(seen: &RwLock<HashMap<Vec<u8>, SeenTxEntry>>, tx_bytes: Vec<u8>) {
    let mut map = seen.write().await;
    let now = Instant::now();
    bound_payload_cache(&mut map, |e| now.duration_since(e.timestamp));
    map.insert(
        tx_bytes,
        SeenTxEntry {
            timestamp: Instant::now(),
        },
    );
}

/// 2E-D: remember which peer an inbound payload arrived from, so the relay
/// that later runs in `broadcast_transaction` can leave that one peer out.
///
/// Called from the two ingress points (the `Transaction` arm and the
/// `GetData` answer), i.e. exactly where `source` is known. Preserves
/// whatever is already recorded: first observation wins, and an already
/// scheduled payload is never un-scheduled by a late duplicate.
async fn record_propagation_source(
    state: &RwLock<PropagationState>,
    tx_bytes: &[u8],
    source: SocketAddr,
) {
    let mut map = state.write().await;
    let now = Instant::now();
    bound_payload_cache(&mut map, |e| now.duration_since(e.timestamp));
    let entry = map.entry(tx_bytes.to_vec()).or_insert_with(|| PropagationEntry {
        timestamp: now,
        source: Some(source),
        scheduled: false,
    });
    if !entry.scheduled {
        entry.source.get_or_insert(source);
    }
}

/// 2E-D: claim the single relay wave for this payload.
///
/// Returns `Some(source)` the first time (the wave may start, and must skip
/// `source`), and `None` for every subsequent call — whether the payload came
/// from the network (`Some(peer)`) or was created locally (`None`). This is
/// the check that has to happen **before** scheduling; the old code had no
/// equivalent and transmitted every accepted payload twice per link.
///
/// A payload never recorded at ingress (local origin) is recorded here with
/// `source = None`.
async fn take_propagation_slot(
    state: &RwLock<PropagationState>,
    tx_bytes: &[u8],
) -> Option<Option<SocketAddr>> {
    let mut map = state.write().await;
    let now = Instant::now();
    bound_payload_cache(&mut map, |e| now.duration_since(e.timestamp));
    match map.get_mut(tx_bytes) {
        Some(entry) if entry.scheduled => None,
        Some(entry) => {
            entry.scheduled = true;
            entry.timestamp = now;
            Some(entry.source)
        }
        None => {
            map.insert(
                tx_bytes.to_vec(),
                PropagationEntry {
                    timestamp: now,
                    source: None,
                    scheduled: true,
                },
            );
            Some(None)
        }
    }
}

/// 2E-D: the entire receive stage for one inbound transaction payload.
///
/// Returns `true` when the payload was accepted for validation. It performs
/// **no relay of any kind** — see docs/AETHER_PHASE2_PRIVACY_PROPAGATION.md
/// §2.9. The old code forwarded from here, before `validate_pure` had run,
/// which is how (a) payloads the node ends up rejecting still reached the
/// wire and (b) every accepted payload was transmitted twice per link.
///
/// Order is deliberate and is part of the contract the tests assert:
/// dedup → parse → record receipt + upstream peer → queue. Nothing in here
/// schedules a relay; that happens exactly once, later, in
/// `broadcast_transaction`, reachable only after validation and acceptance.
async fn accept_inbound_transaction(
    tx_bytes: Vec<u8>,
    source: SocketAddr,
    seen: &RwLock<HashMap<Vec<u8>, SeenTxEntry>>,
    propagation_state: &RwLock<PropagationState>,
    tx_channel: &mpsc::UnboundedSender<Transaction>,
) -> bool {
    // DEDUPE, ahead of anything that could schedule a relay.
    if seen.read().await.contains_key(&tx_bytes) {
        return false;
    }

    let tx = match bincode::deserialize::<Transaction>(&tx_bytes) {
        Ok(tx) => tx,
        Err(_) => {
            warn!("Failed to deserialize transaction from {}", source);
            return false;
        }
    };

    insert_seen(seen, tx_bytes.clone()).await;
    // The upstream peer must be recorded at ingress, while `source` is still
    // in scope; the relay wave consults it later in `broadcast_transaction`.
    record_propagation_source(propagation_state, &tx_bytes, source).await;

    // LOG REVIEW (2E-D §11): this pairs a payload hash with a peer address
    // and a log timestamp — the (hash, source, time) triple a local reader of
    // `node.log` should not get for free. Dropped from DEBUG (where it sat)
    // to TRACE: still reachable for a targeted investigation, not written at
    // the default level.
    tracing::trace!("received transaction from {}: {}", source, hex::encode(tx.id));

    tx_channel.send(tx).is_ok()
}

/// PHASE 4I (F-D3): pure vote-inventory diff used by the VoteInventory
/// arm: advertised ids minus locally known ids, deduplicated, bounded.
/// Deterministic (order-preserving over the first-seen advertised order).
/// Cap bounds a single response; re-announcement converges the remainder.
pub fn vote_inventory_missing(
    advertised: &[Vec<u8>],
    is_known: &dyn Fn(&[u8]) -> bool,
    cap: usize,
) -> Vec<Vec<u8>> {
    use std::collections::HashSet;
    let mut seen: HashSet<&[u8]> = HashSet::new();
    let mut out = Vec::new();
    for id in advertised.iter().take(cap) {
        if out.len() >= cap {
            break;
        }
        if !seen.insert(id.as_slice()) {
            continue;
        }
        if !is_known(id) {
            out.push(id.clone());
        }
    }
    out
}
/// PHASE 4G: the receive stage for one inbound stake payload (vote / bond /
/// unbond gossip). Same contract as accept_inbound_transaction: dedup →
/// strict-decode → record receipt + upstream peer → queue, NO relay of any
/// kind (relay happens exactly once, later, in broadcast_stake, reachable
/// only after validation + admission). Signature verification is an
/// ADMISSION check (process_vote/validate_*), not a receive check  -  the
/// receive stage is format-only by design (same as transactions, where
/// validate_pure owns the signature gate).
/// Crate-visible for the phase4G integration tests (ingress contract).
async fn accept_inbound_stake(
  kind: &'static str,
  payload_bytes: Vec<u8>,
  source: SocketAddr,
  seen: &RwLock<HashMap<Vec<u8>, SeenTxEntry>>,
  propagation_state: &RwLock<PropagationState>,
  stake_channel: &mpsc::UnboundedSender<StakePayload>,
) -> bool {
  // DEDUPE, ahead of anything that could schedule a relay.
  if seen.read().await.contains_key(&payload_bytes) {
                                        return false;
}

  let payload = match kind {
  "vote" => match Vote::decode(&payload_bytes) {
  Ok(v) => StakePayload::Vote(v),
            Err(_) => {
  warn!("Failed to decode vote from {}", source);
                                        return false;
        }
    },
  "bond" => match Bond::decode(&payload_bytes) {
  Ok(b) => StakePayload::Bond(b),
  Err(_) => {
  warn!("Failed to decode bond from {}", source);
  return false;
    }
                },
  "unbond" => match Unbond::decode(&payload_bytes) {
  Ok(u) => StakePayload::Unbond(u),
  Err(_) => {
  warn!("Failed to decode unbond from {}", source);
  return false;
}
                },
  _ => return false,
            };

  insert_seen(seen, payload_bytes.clone()).await;
  record_propagation_source(propagation_state, &payload_bytes, source).await;
  tracing::trace!("received {} from {}", kind, source);
  stake_channel.send(payload).is_ok()
}

/// P2P network configuration
#[derive(Clone)]
pub struct P2PConfig {
    /// Local address to bind to
    pub listen_addr: SocketAddr,
    /// Bootstrap nodes to connect to
    pub bootnodes: Vec<SocketAddr>,
    /// DNS seed domains for peer discovery (e.g. "seed.aether.network")
    pub dns_seeds: Vec<String>,
    /// Path used to persist known peers across restarts (Phase 1)
    pub peer_store_path: Option<std::path::PathBuf>,
    /// PHASE 4V: V6 network identity checked in the handshake (0 = legacy
    /// default: behaves EXACTLY as before; governed nonzero values pending).
    pub network_id: u64,
}

/// How long a peer remains in the known set after its last disconnect (Phase 1 TTL).
const PEER_TTL: Duration = Duration::from_secs(3600);
/// Interval at which the known-peer set is flushed to disk (Phase 1).
const PEER_STORE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:30333".parse().unwrap_or_else(|_| {
                tracing::warn!("Failed to parse default P2P address, using fallback");
                "127.0.0.1:30333"
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
            }),
            bootnodes: Vec::new(),
            dns_seeds: Vec::new(),
            peer_store_path: None,
            network_id: crate::transaction::DEFAULT_NETWORK_ID,
        }
    }
}

/// PHASE 4CP: which handshake a node speaks.
///
/// This is the **P2P wire protocol** version only. It is unrelated to the V6
/// governance feature (`ACTIVATION_ALLOWED=NO`); the two must never be
/// conflated.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum P2PProtocolMode {
    /// Historical, encrypted-but-**unauthenticated** v5 handshake. Preserves
    /// the 77-byte frame and key derivation exactly. Opt-in only.
    #[default]
    LegacyV5,
    /// Authenticated v6 handshake: a persistent Ed25519 `NodeId` plus a
    /// signature over the session transcript. Requires a node identity.
    AuthenticatedV6,
}

impl std::str::FromStr for P2PProtocolMode {
    type Err = String;

    /// 4CP-U: the operator-facing spelling of the handshake choice, used by the
    /// `--p2p-protocol` CLI flag. Accepts the TOML snake_case names plus the
    /// short aliases operators type by hand. Rejects everything else so a typo
    /// is a hard error rather than a silent legacy fallback.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "legacy_v5" | "legacy" | "v5" => Ok(P2PProtocolMode::LegacyV5),
            "authenticated_v6" | "authenticated" | "v6" => Ok(P2PProtocolMode::AuthenticatedV6),
            other => Err(format!(
                "unknown P2P protocol '{}': expected 'legacy_v5' or 'authenticated_v6'",
                other
            )),
        }
    }
}

/// PHASE 4CP: the verified provenance of a live session.
///
/// A legacy session is **always** `EncryptedUnauthenticated`; it is never
/// presented as `Authenticated`. Future reputation / address-announcement work
/// must branch on this so an unauthenticated peer can never be treated as a
/// verified identity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum P2PSessionAuth {
    /// v5 session: confidentiality only, peer identity NOT proven.
    EncryptedUnauthenticated,
    /// v6 session: the peer proved possession of the private key naming it.
    Authenticated {
        node_id: crate::node_identity::NodeId,
    },
    /// A session that failed during establishment (no live session).
    Failed,
}

/// PHASE 4CP-S: one recorded session's provenance.
#[derive(Clone, Debug)]
struct SessionAuthEntry {
    /// The peer endpoint this session is talking to. Recorded for observability
    /// only — it is NOT the map key, because two live sessions can share an
    /// endpoint (see `SessionAuthRegistry`).
    addr: SocketAddr,
    state: P2PSessionAuth,
}

/// PHASE 4CP-S: verified provenance of the currently-live sessions.
///
/// Keyed by a node-local, monotonically increasing **session id** — never by
/// `SocketAddr`. An endpoint is not a session: a peer can dial us from a source
/// port we are also dialing, and a fast reconnect can reuse an endpoint while
/// the old task is still tearing down. Keying by address made a late teardown
/// able to erase (or a legacy insert able to overwrite) a *different* session's
/// state (4CP-R F1). With a unique id, each session's record/clear can only
/// ever touch its own entry; a closing session can never remove a newer one.
#[derive(Default)]
struct SessionAuthRegistry {
    entries: HashMap<u64, SessionAuthEntry>,
    /// 4CP-W: the network cycle this registry currently serves. Bumped by
    /// `begin_generation` on every `start()`; a registration/clear carrying an
    /// older generation is refused so a late handshake from a previous cycle
    /// can never write into a later one, even after a restart with the exact
    /// same configuration.
    generation: u64,
    /// 4CP-W: set by `close_and_clear` when a cycle is shut down. Once closed,
    /// every `record_if_active`/`clear_if_active` is refused, so a handshake
    /// that reaches the registration point after teardown records nothing.
    closed: bool,
}

impl SessionAuthRegistry {
    /// Record (or replace) the state for one exact session id.
    fn record(&mut self, session_id: u64, addr: SocketAddr, state: P2PSessionAuth) {
        self.entries
            .insert(session_id, SessionAuthEntry { addr, state });
    }

    /// 4CP-W: open a fresh cycle. Clears any state and makes the registry
    /// accept registrations tagged with `generation`. Called by `start()`
    /// under the registry write lock, so it races neither a registration nor a
    /// close.
    fn begin_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.closed = false;
        self.entries.clear();
    }

    /// 4CP-W: atomically close the registry and drop every entry. After this
    /// returns, no `record_if_active` for this registry can succeed, so a
    /// handshake that already passed its provenance check records nothing.
    /// This is the serialisation point between "record a session" and
    /// "tear the cycle down".
    fn close_and_clear(&mut self) {
        self.closed = true;
        self.entries.clear();
    }

    /// 4CP-W: register a session only if this registry still serves
    /// `generation` and the cycle is open. Returns whether the record was
    /// applied. The generation check and the write happen under the same lock,
    /// so a late handshake can never reintroduce an entry after teardown, and a
    /// previous cycle can never register into a newer one.
    fn record_if_active(
        &mut self,
        generation: u64,
        session_id: u64,
        addr: SocketAddr,
        state: P2PSessionAuth,
    ) -> bool {
        if self.closed || self.generation != generation {
            return false;
        }
        self.record(session_id, addr, state);
        true
    }

    /// 4CP-W: drop one session only if the caller still belongs to the live
    /// cycle. A teardown from an old generation can never touch the current
    /// cycle's map (session ids are also process-unique, so it could not alias
    /// another session even without this check).
    fn clear_if_active(&mut self, generation: u64, session_id: u64) -> bool {
        if self.closed || self.generation != generation {
            return false;
        }
        self.clear(session_id);
        true
    }

    /// Drop one session's state. Removing an unknown id is a no-op, and can
    /// never affect another session.
    fn clear(&mut self, session_id: u64) {
        self.entries.remove(&session_id);
    }

    fn get(&self, session_id: u64) -> Option<&SessionAuthEntry> {
        self.entries.get(&session_id)
    }

    /// All live sessions currently at `addr`, oldest session id first. There
    /// may legitimately be several; the caller must not assume one.
    fn for_addr(&self, addr: &SocketAddr) -> Vec<(u64, P2PSessionAuth)> {
        let mut v: Vec<(u64, P2PSessionAuth)> = self
            .entries
            .iter()
            .filter(|(_, e)| &e.addr == addr)
            .map(|(id, e)| (*id, e.state.clone()))
            .collect();
        v.sort_by_key(|(id, _)| *id);
        v
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Phase 2B: how an address entered the table. Persisted so a restart can tell
/// an operator-configured seed from a hostile PEX hint (D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum PeerSource {
    /// Operator-configured bootstrap address (never PEX-filtered, R4).
    Configured,
    /// Resolved from a DNS seed.
    Dns,
    /// Learned from a peer exchange message.
    Pex,
    /// The address dialled us.
    Inbound,
    /// An outbound connection we initiated.
    Outbound,
    /// Promoted by the anchor task.
    Anchor,
    /// Carried over from a pre-versioned store; origin unknown.
    Restored,
}

impl Default for PeerSource {
    fn default() -> Self {
        PeerSource::Restored
    }
}

/// Phase 2B: the five address categories (Principle 3, D7). Derived from live
/// state rather than stored, so a category can never drift out of sync with the
/// session / anchor / score tables it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerCategory {
    /// Holding a live session right now.
    Active,
    /// A successful handshake landed inside the recent window.
    Recent,
    /// Promoted for long-term reachability; never authoritative (Principle 5).
    Anchor,
    /// Known but never successfully connected (or cold for a long time).
    Candidate,
    /// Banned, or scored at/below the penalty floor.
    Penalized,
}

/// Default quality assigned to an address we know nothing else about.
fn default_peer_quality() -> i32 {
    PEER_SCORE_INITIAL
}

/// Phase 2C (audit L6): the quality an address enters the table with.
///
/// `admit_peer` displaces an entry when `victim_quality <= incoming_quality`.
/// Everything the node itself observed — a peer that dialled us, an address we
/// chose to dial, a DNS answer, an operator-configured bootnode — keeps the
/// historical `PEER_SCORE_INITIAL`. A pure gossip hint enters at half of that,
/// so a PEX burst can only target entries that are already degraded or banned.
/// It can never flush a healthy table it merely outnumbers.
///
/// A PEX address that proves itself climbs back through `record_success`
/// (+10 per successful handshake), so this is a head start for evidence, not a
/// permanent class.
fn admission_quality(source: PeerSource) -> i32 {
    match source {
        PeerSource::Pex => PEX_ADMISSION_QUALITY,
        _ => default_peer_quality(),
    }
}

/// Everything the node records about one address: where it came from, when it
/// was last useful, how well it has behaved, and whether it has been promoted
/// to an anchor. `last_seen` is the Phase-1 TTL clock.
///
/// Supersedes the former `PeerMeta` + `known_peers` + `peer_last_seen` triple.
/// Those three were always written together (`ingress_address`,
/// `load_known_peers`) and always removed together (the TTL sweep), so keeping
/// them in three tables only created a chance for them to disagree.
///
/// Deliberately *not* `Serialize`: persistence goes through `PeerStoreEntry`,
/// whose schema is the on-disk contract (`Instant` is not portable anyway).
#[derive(Debug, Clone)]
struct AddressEntry {
    /// How the address was learned.
    source: PeerSource,
    /// Unix seconds when this address was first learned.
    first_seen: u64,
    /// Monotonic clock of the last time we heard from or about this address.
    /// Drives `PEER_TTL` expiry; refreshed for every live session.
    last_seen: Instant,
    /// Unix seconds of the last successful handshake, if any.
    last_success: Option<u64>,
    /// Total outbound dial attempts.
    attempts: u32,
    /// Attempts that never reached a handshake.
    failures: u32,
    /// Quality in `0..=PEER_QUALITY_MAX`; drives admission and eviction (D8).
    quality: i32,
    /// True while promoted as an anchor (D9).
    anchor: bool,
}

impl AddressEntry {
    fn new(source: PeerSource, now: u64, at: Instant) -> Self {
        Self {
            source,
            first_seen: now,
            last_seen: at,
            last_success: None,
            attempts: 0,
            failures: 0,
            quality: default_peer_quality(),
            anchor: false,
        }
    }

    fn record_success(&mut self, now: u64) {
        self.last_success = Some(now);
        self.attempts = self.attempts.saturating_add(1);
        // 4CE hygiene: a completed handshake forgives failure debt. Sleep is
        // keyed on consecutive-unproven failure, so a peer that proves
        // itself once must not carry its old debt into the next outage.
        self.failures = 0;
        self.quality = (self.quality + 10).min(PEER_QUALITY_MAX);
    }

    fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.failures = self.failures.saturating_add(1);
        self.quality = (self.quality - 5).max(0);
    }
}

// ---------------------------------------------------------------------------
// AddressManager
// ---------------------------------------------------------------------------

/// Single owner of everything the node knows about addresses.
///
/// Replaces the five previously-scattered tables — `known_peers`,
/// `peer_meta`, `peer_last_seen`, `pex_origins` and `peer_scores` — so that
/// address state sits behind exactly one lock. That removes the lock-order
/// inversions the four separate guards made possible (read `known` then write
/// `seen` in one task, the reverse in another) and makes it impossible for
/// membership, metadata and the TTL clock to drift apart.
///
/// `scores` stays a *separate* map rather than folding into `entries` on
/// purpose: an address evicted by the TTL sweep must keep its ban, otherwise
/// expiring a peer would silently un-ban it.
/// Outcome of a capacity-aware admission attempt (D8).
///
/// `ingress_address` needs to distinguish "already known" (true, just refresh
/// the clock) from "refused" (false)  -  a bare `Option<SocketAddr>` conflated
/// both with "made room", which is exactly the ambiguity that made the old
/// caller's `accepted` flag easy to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Already present; nothing was inserted.
    AlreadyKnown,
    /// Newly adopted. `evicted` is the address displaced to make room.
    Inserted { evicted: Option<SocketAddr> },
    /// Table full and nothing worth displacing; not adopted.
    Refused,
}

struct AddressManager {
    /// membership + metadata + TTL clock, in one map
    entries: HashMap<SocketAddr, AddressEntry>,
    /// which peer told us about each address (PEX echo suppression, D5)
    origins: HashMap<SocketAddr, SocketAddr>,
    /// reputation / ban state (per-message hot path)
    scores: HashMap<SocketAddr, PeerScore>,
}

impl AddressManager {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            origins: HashMap::new(),
            scores: HashMap::new(),
        }
    }

    // --- membership ------------------------------------------------------

    fn contains(&self, addr: SocketAddr) -> bool {
        self.entries.contains_key(&addr)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn addresses(&self) -> Vec<SocketAddr> {
        self.entries.keys().copied().collect()
    }

    /// Remove an address and everything keyed off it.
    fn remove(&mut self, addr: &SocketAddr) -> bool {
        self.origins.remove(addr);
        self.entries.remove(addr).is_some()
    }

    // --- observation / lifecycle ----------------------------------------

    /// Adopt an address, refreshing the TTL clock of one we already hold.
    ///
    /// The source is only recorded when the address is *new*: the first
    /// observer names it, so a later PEX hint cannot relabel an address we
    /// originally learned from a seed.
    fn observe(&mut self, addr: SocketAddr, source: PeerSource, now: u64, at: Instant) {
        self.touch(addr, at);
        self.entries
            .entry(addr)
            .or_insert_with(|| AddressEntry::new(source, now, at));
    }

    /// Stamp the TTL clock for an address we already hold.
    fn touch(&mut self, addr: SocketAddr, at: Instant) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.last_seen = at;
        }
    }

    fn record_success(&mut self, addr: SocketAddr, now: u64) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.record_success(now);
        }
    }

    fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.record_failure();
        }
    }

    /// 4CE hygiene: true when this entry should sit out of redial selection.
    /// Sleeps only never-successful entries past the failure threshold.
    /// Anchors always carry `last_success`, connected sessions are skipped by
    /// the caller anyway, and configured seeds are exempted at the call site
    /// (config membership — a dialed seed carries source Outbound, so source
    /// alone cannot identify it). Unknown addresses report false: there is
    /// nothing to rest. Sleep never deletes: TTL expiry and the peer store
    /// still own the entry's lifetime, and inbound connections bypass
    /// redial entirely.
    fn redial_sleep(&self, addr: &SocketAddr) -> bool {
        match self.entries.get(addr) {
            Some(e) => e.failures >= MAX_DIAL_FAILURES_SLEEP && e.last_success.is_none(),
            None => false,
        }
    }

    /// 4CE hygiene, FUNCTION-level contract (4CG): refresh the TTL clock and
    /// halve the failure debt for an address announced again — never a full
    /// reset (one wave must not erase sustained failure; repeated waves keep
    /// halving toward zero). NOTE (4CH): the production `P2PMessage::Peers`
    /// arm calls this once per held address per announce (intra-message
    /// duplicates collapsed by the arm's `seen` set), after the same
    /// validity/loopback/private/reserved filters as admission, and without
    /// pushing the address to the discovery channel — a refresh never forces
    /// a dial; the bounded redial selection decides retries. The isolated
    /// behaviour stays pinned by `ce_pex_refresh_fn_isolated_halves_debt`;
    /// the wired network path is pinned by
    /// `phase4ch_pex_wiring_tests::ch_real_path_peers_frame_wires_refresh`.
    fn pex_refresh(&mut self, addr: SocketAddr, at: Instant) {
        if let Some(e) = self.entries.get_mut(&addr) {
            e.last_seen = at;
            e.failures /= 2;
        }
    }

    // --- admission -------------------------------------------------------

    /// Capacity-aware admission (D8). Returns `AlreadyKnown` when the address
    /// is present, `Inserted` when it was adopted (carrying whatever address
    /// was displaced to make room), and `Refused` when the table is full and
    /// nothing present is worth displacing.
    ///
    /// `connected` and `at` come from the caller: the session table is not
    /// owned here, and must never be locked while this manager is held.
    fn admit(
        &mut self,
        addr: SocketAddr,
        source: PeerSource,
        quality: i32,
        now: u64,
        at: Instant,
        connected: &HashSet<SocketAddr>,
    ) -> Admission {
        if self.entries.contains_key(&addr) {
            return Admission::AlreadyKnown;
        }
        let evicted = if self.entries.len() >= MAX_KNOWN_PEERS {
            let Some(victim) = admit_peer(&self.entries, &self.scores, connected, addr, quality)
            else {
                return Admission::Refused;
            };
            self.remove(&victim);
            Some(victim)
        } else {
            None
        };
        self.entries.insert(addr, AddressEntry::new(source, now, at));
        Admission::Inserted { evicted }
    }

    // --- scores ----------------------------------------------------------

    fn is_banned(&self, addr: SocketAddr) -> bool {
        self.scores.get(&addr).map(|s| s.is_banned()).unwrap_or(false)
    }

    fn banned_until(&self, addr: SocketAddr) -> Option<Instant> {
        self.scores.get(&addr).and_then(|s| s.banned_until)
    }

    /// Penalize and, when the threshold is crossed, ban. Returns the score
    /// after the penalty *only* when a ban was triggered, so the caller can log
    /// it — an address with no score is left untouched, exactly as before.
    fn penalize_and_ban(&mut self, addr: SocketAddr, penalty: i32) -> Option<i32> {
        let s = self.scores.get_mut(&addr)?;
        if s.penalize(penalty) {
            s.ban();
            return Some(s.score);
        }
        None
    }

    /// Decay (or create) the score for an address we are about to dial.
    fn decay_score(&mut self, addr: SocketAddr) {
        match self.scores.get_mut(&addr) {
            Some(s) => s.decay(),
            None => {
                self.scores.insert(addr, PeerScore::new());
            }
        }
    }

    // --- PEX -------------------------------------------------------------

    fn set_origin(&mut self, addr: SocketAddr, from: SocketAddr) {
        self.origins.insert(addr, from);
    }

    fn sample_for_pex(
        &self,
        local: SocketAddr,
        recipient: SocketAddr,
        now: u64,
        limit: usize,
    ) -> Vec<SocketAddr> {
        pex_sample(
            &self.entries,
            &self.scores,
            &self.origins,
            local,
            recipient,
            now,
            limit,
        )
    }

    // --- anchors ---------------------------------------------------------

    fn anchor_addresses(&self) -> Vec<(SocketAddr, u64)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.anchor)
            .map(|(a, e)| (*a, e.last_success.unwrap_or(e.first_seen)))
            .collect()
    }

    /// Live sessions that have completed at least one handshake — the only
    /// legitimate promotion source for an anchor.
    fn anchor_candidates(&self, connected: &HashSet<SocketAddr>) -> Vec<(SocketAddr, u64)> {
        connected
            .iter()
            .filter_map(|a| {
                let e = self.entries.get(a)?;
                e.last_success.map(|t| (*a, t))
            })
            .collect()
    }

    /// Apply a freshly computed anchor set. Returns `(promoted, demoted)`.
    fn apply_anchors(&mut self, wanted: &HashSet<SocketAddr>) -> (usize, usize) {
        let mut promoted = 0usize;
        let mut demoted = 0usize;
        for (a, e) in self.entries.iter_mut() {
            let should = wanted.contains(a);
            if e.anchor == should {
                continue;
            }
            e.anchor = should;
            if should {
                e.source = PeerSource::Anchor;
                promoted += 1;
            } else {
                demoted += 1;
            }
        }
        (promoted, demoted)
    }

    // --- TTL -------------------------------------------------------------

    /// One pass of the Phase-1 TTL sweep: refresh the clock of every live
    /// session, then drop addresses we have not heard from inside the window
    /// (along with their metadata and PEX origin). Returns
    /// `(refreshed, expired)`.
    fn refresh_and_expire(
        &mut self,
        connected: &HashSet<SocketAddr>,
        now: Instant,
        ttl: Duration,
    ) -> (usize, usize) {
        let mut refreshed = 0usize;
        for a in connected {
            if let Some(e) = self.entries.get_mut(a) {
                e.last_seen = now;
                refreshed += 1;
            }
        }
        let expired: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) > ttl)
            .map(|(a, _)| *a)
            .collect();
        for a in &expired {
            self.origins.remove(a);
        }
        for a in &expired {
            self.entries.remove(a);
        }
        // Phase 2C (audit L7): a score that is neither banned nor attached to
        // anything we still track carries no information — `decay_score`
        // recreates it if the address ever returns. Without this pass the map
        // grew by one entry per *distinct* address ever dialled, which a peer
        // cycling fresh hints through the table could drive without bound.
        //
        // A ban always survives: that is the invariant that makes `scores` a
        // separate map in the first place. So does a live session, which may
        // hold a score even when the address itself was refused by a full
        // table.
        self.scores.retain(|a, s| {
            self.entries.contains_key(a) || connected.contains(a) || s.is_banned()
        });
        (refreshed, expired.len())
    }

    // --- views -----------------------------------------------------------

    /// Per-category census for diagnostics (D7).
    fn categories(&self, connected: &HashSet<SocketAddr>, now: u64) -> [usize; 5] {
        let mut counts = [0usize; 5];
        for (a, e) in self.entries.iter() {
            let penalized = e.quality <= PEER_QUALITY_PENALIZED
                || self
                    .scores
                    .get(a)
                    .map(|s| s.is_banned() || s.score <= PEER_QUALITY_PENALIZED)
                    .unwrap_or(false);
            let c = categorise(
                connected.contains(a),
                e.anchor,
                penalized,
                e.last_success,
                now,
            );
            counts[c as usize] += 1;
        }
        counts
    }

    // --- persistence -----------------------------------------------------

    /// Build the on-disk v2 document. Addresses without metadata are written
    /// with defaults rather than dropped, so nothing is silently lost.
    fn to_store(&self) -> PeerStoreFile {
        let entries = self
            .entries
            .iter()
            .map(|(a, e)| PeerStoreEntry {
                addr: a.to_string(),
                source: e.source,
                first_seen: e.first_seen,
                last_success: e.last_success,
                attempts: e.attempts,
                failures: e.failures,
                quality: e.quality,
                anchor: e.anchor,
            })
            .collect();
        PeerStoreFile {
            version: PEER_STORE_VERSION,
            entries,
        }
    }

    /// Load a parsed v2 document. Returns how many addresses were adopted.
    fn load_v2(&mut self, file: &PeerStoreFile, local: SocketAddr, now: u64, at: Instant) -> usize {
        let mut count = 0usize;
        for e in &file.entries {
            let Ok(addr) = e.addr.parse::<SocketAddr>() else {
                continue;
            };
            if addr == local {
                continue;
            }
            let entry = AddressEntry {
                source: e.source,
                first_seen: if e.first_seen > 0 { e.first_seen } else { now },
                last_seen: at,
                last_success: e.last_success,
                attempts: e.attempts,
                failures: e.failures,
                quality: e.quality,
                anchor: e.anchor,
            };
            let fresh = !self.entries.contains_key(&addr);
            self.entries.insert(addr, entry);
            count += fresh as usize;
        }
        count
    }

    /// Adopt addresses from a legacy `Vec<String>` store (R3). v1 carried no
    /// timestamps and no origin, so there is nothing to recover but the
    /// addresses themselves.
    fn load_legacy(&mut self, addrs: &[String], local: SocketAddr, now: u64, at: Instant) -> usize {
        let mut count = 0usize;
        for s in addrs {
            let Ok(addr) = s.parse::<SocketAddr>() else {
                continue;
            };
            if addr == local {
                continue;
            }
            let fresh = !self.entries.contains_key(&addr);
            self.entries
                .insert(addr, AddressEntry::new(PeerSource::Restored, now, at));
            count += fresh as usize;
        }
        count
    }

    // --- test accessors --------------------------------------------------
    //
    // Deliberately `#[cfg(test)]`: production code goes through the methods
    // above, so these never widen the real API surface and never show up as
    // dead code in a normal build.

    /// Phase 2C: metadata and reputation together, because the outbound
    /// selector needs both and a caller must never be able to observe one
    /// without the other. Read-only, and the guard is released by the caller
    /// as soon as selection returns.
    fn selection_tables(
        &self,
    ) -> (
        &HashMap<SocketAddr, AddressEntry>,
        &HashMap<SocketAddr, PeerScore>,
    ) {
        (&self.entries, &self.scores)
    }

    #[cfg(test)]
    fn entry(&self, addr: SocketAddr) -> Option<&AddressEntry> {
        self.entries.get(&addr)
    }

    #[cfg(test)]
    fn entries_mut(&mut self) -> &mut HashMap<SocketAddr, AddressEntry> {
        &mut self.entries
    }

    #[cfg(test)]
    fn scores_mut(&mut self) -> &mut HashMap<SocketAddr, PeerScore> {
        &mut self.scores
    }

    #[cfg(test)]
    fn origin_of(&self, addr: SocketAddr) -> Option<SocketAddr> {
        self.origins.get(&addr).copied()
    }
}

/// On-disk peer store, schema v2 (D8). v1 was a bare `Vec<String>`; the loader
/// falls back to that shape so an existing `known_peers.json` is never lost (R3).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PeerStoreFile {
    version: u32,
    #[serde(default)]
    entries: Vec<PeerStoreEntry>,
}

/// One persisted address plus the metadata v1 could not express.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PeerStoreEntry {
    addr: String,
    #[serde(default)]
    source: PeerSource,
    #[serde(default)]
    first_seen: u64,
    #[serde(default)]
    last_success: Option<u64>,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    failures: u32,
    #[serde(default = "default_peer_quality")]
    quality: i32,
    #[serde(default)]
    anchor: bool,
}

/// P2P network message types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum P2PMessage {
    /// Transaction gossip
    Transaction(Vec<u8>),
    /// Inventory - list of transaction hashes
    Inventory(Vec<Vec<u8>>),
    /// GetData - request specific transactions by hash
    GetData(Vec<Vec<u8>>),
    /// GetInventory - request inventory based on tips
    GetInventory {
        /// Tips of the requesting node
        tips: Vec<Vec<u8>>,
    },
    /// SyncRequest - request full inventory from peer (legacy)
    SyncRequest,
    /// SyncResponse - send transactions (with pagination support)
    SyncResponse(Vec<Vec<u8>>),
    /// Ping message for keepalive
    Ping,
    /// Pong response
    Pong,
    /// Peer exchange - list of known peer addresses
    Peers(Vec<SocketAddr>),
  // -- PHASE 4G stake-finality gossip (additive ENUM TAIL: existing
  // variants keep their bincode indices, so old binaries decode every
  // pre-4G message identically; a pre-4G peer receiving these fails
  // deserialization and error-disconnects per existing discipline).
  // Payloads are the CANONICAL encodings (Vote 265B / Bond 121B /
  // Unbond 113B v2  -  strict-decoded on receipt, never trusted).
  /// Finality vote gossip (canonical vote encoding)
  Vote(Vec<u8>),
  /// Bond intent gossip (canonical bond encoding)
  Bond(Vec<u8>),
    /// Unbond intent gossip (canonical unbond encoding)
    Unbond(Vec<u8>),
    // -- PHASE 4I (F-D3) vote backfill (additive ENUM TAIL, same compat
    // rule as the 4G kinds: indices 12, 13; old peers error-disconnect).
    // Sync carries transactions only, so joining nodes rebuild EMPTY
    // registries and resolve post-V6 keys by min-id while live nodes use
    // stake/finality (permanent divergence for settled keys). These two
    // control messages close the gap: peers announce known vote ids,
    // joiners fetch the unknown encodings, admission stays idempotent
    // (process_vote Duplicate) so backfill can never fork state.
    /// Vote inventory announcement (vote ids known to the sender)
    VoteInventory(Vec<Vec<u8>>),
    /// Vote fetch request (vote ids wanted by the sender)
    GetVotes(Vec<Vec<u8>>),
}

/// PHASE 4G: decoded stake payload handed from the P2P receive stage to
/// the node (mirrors how Transaction objects cross tx_channel  -  the node
/// admits them via TransactionProcessor::process_vote/bond/unbond).
#[derive(Debug, Clone)]
pub enum StakePayload {
  Vote(Vote),
  Bond(Bond),
  Unbond(Unbond),
}

/// PHASE 4G: node-supplied stake hooks for the P2P layer. Both behind
/// set-once Arcs so P2PNetwork::new (15 call sites) keeps its signature:
/// the node wires these after construction via the setters below.
/// Unwired (None) = stake gossip is dropped at ingress and GetData serves
/// transactions only (pre-v6 behavior, no crash, no silent mis-handle).
#[derive(Clone, Default)]
pub struct StakeHooks {
  /// Admit decoded stake payloads (node vote/bond receiver task).
  pub stake_channel: std::sync::Arc<
  std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<StakePayload>>>,
  >,
  /// Serve vote encodings by vote id (GetData fallback; backed by the
  /// stake_votes storage tree). None = tx-only serving (as before).
  pub get_vote_by_id:
  std::sync::Arc<std::sync::Mutex<Option<StakeVoteLookup>>>,
}

/// PHASE 4G: vote serving lookup (id -> canonical encoding).
pub type StakeVoteLookup =
  std::sync::Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// Seen transaction entry with timestamp for LRU eviction
#[derive(Clone)]
struct SeenTxEntry {
    timestamp: Instant,
}

/// 2E-D: scheduling state for one transaction payload.
///
/// Deliberately a *separate* map from `seen_transactions`, not two extra
/// fields on it: that struct is receipt dedup, it is constructed literally by
/// several existing tests that assert receipt semantics only, and merging the
/// two would force those tests to change to describe a mechanism they do not
/// exercise. The two concerns are also genuinely different — `seen` answers
/// "have I received this?", this answers "have I already scheduled a relay
/// wave for this, and from whom did it come?".
///
/// Keyed by the same raw payload bytes as `seen_transactions`, bounded by the
/// same rule, and consulted strictly *before* any scheduling happens.
#[derive(Clone)]
struct PropagationEntry {
    /// When this payload was first recorded here (for the shared bound).
    timestamp: Instant,
    /// Peer the payload first arrived from, i.e. the one upstream node that
    /// must NOT be told about it again. `None` means locally created (RPC,
    /// faucet, miner) — there is no upstream peer to exclude.
    source: Option<SocketAddr>,
    /// Set in the same critical section that hands the payload to the
    /// scheduler. A second accept therefore schedules nothing: this is the
    /// dedup that stops the double relay.
    scheduled: bool,
}

/// Payload-keyed scheduling state: bytes → `PropagationEntry`.
type PropagationState = HashMap<Vec<u8>, PropagationEntry>;

/// Shared retention rule for the two payload-keyed caches
/// (`seen_transactions` and `PropagationState`): once the cap is reached,
/// drop everything older than the TTL, then — if still at the cap — drop one
/// arbitrary entry so the insert that follows keeps the map bounded. Memory
/// stays O(`MAX_SEEN_TXS`) under flood either way.
const PAYLOAD_CACHE_TTL: Duration = Duration::from_secs(300);

/// Apply `PAYLOAD_CACHE_TTL` + the hard cap to a payload-keyed map.
/// `age_of` returns how old an entry is; it is evaluated once per entry.
fn bound_payload_cache<T>(map: &mut HashMap<Vec<u8>, T>, age_of: impl Fn(&T) -> Duration) {
    if map.len() < MAX_SEEN_TXS {
        return;
    }
    map.retain(|_, v| age_of(v) < PAYLOAD_CACHE_TTL);
    if map.len() >= MAX_SEEN_TXS {
        if let Some(k) = map.keys().next().cloned() {
            map.remove(&k);
        }
    }
}

/// PHASE 4CP-U: conceptual lifecycle state of a [`P2PNetwork`].
///
/// This is the observable answer to "may this node still be configured, and is
/// it live?". It exists so that the set-once configuration (protocol mode +
/// node identity) and the start/shutdown transitions are decided under one
/// lock, never by a check-then-act across independent flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2PNetworkState {
    /// No protocol mode was chosen yet. `start()` refuses with an explicit
    /// error (4CP-W V-3): there is no implicit fallback to `LegacyV5`. Setters
    /// are accepted.
    Unconfigured,
    /// A protocol mode (and, for v6, an identity) was chosen explicitly via
    /// `set_protocol_mode` / the `p2p_protocol` setting / `--p2p-protocol`;
    /// not started yet. Setters are accepted.
    Configured,
    /// `start()` is in progress: the configuration is frozen and the network
    /// is not yet live. Setters are refused. A `shutdown()` may engage during
    /// this window; it wins, and `start()` must not return to `Started`.
    Starting,
    /// `start()` completed; the network is live. The configuration is frozen
    /// forever (see [`NetworkLifecycle`]). Setters are refused.
    Started,
    /// `shutdown()` is in progress: task admission is already closed and the
    /// cycle is being torn down. Setters and a new `start()` are refused until
    /// the teardown finishes and the state becomes `Stopped`.
    Stopping,
    /// The last `start()` failed (for example a bind error) and left no live
    /// session. Setters are accepted again so the operator can fix the choice
    /// and retry; `start()` may be called again.
    Failed,
    /// `shutdown()` completed on a live network. The configuration stays frozen
    /// (immutable once started); a restart reuses the exact same snapshot and
    /// still cannot be reconfigured.
    Stopped,
}

/// The exact, immutable configuration a network was started with. Both the
/// accept loop and the dial path read this snapshot, never the live setters, so
/// every session the node opens speaks one handshake decided at one instant.
struct StartedConfig {
    mode: P2PProtocolMode,
    identity: Option<Arc<crate::node_identity::NodeIdentity>>,
}

/// PHASE 4CP-U (4CPT-01): the single source of truth for a `P2PNetwork`'s
/// configuration and lifecycle.
///
/// One `std::sync::Mutex` protects the lifecycle state, the chosen mode, the
/// identity and the frozen start snapshot *together*. `set_protocol_mode`,
/// `set_node_identity` and `start()` therefore serialise against each other:
/// a setter can never interleave between `start()` reading the configuration
/// and the network becoming live, and the snapshot the accept loop and the dial
/// path use is always the one the same critical section froze. The lock is
/// never held across an `.await`.
struct NetworkLifecycle {
    state: P2PNetworkState,
    /// The chosen mode; `LegacyV5` until a setter runs.
    mode: P2PProtocolMode,
    /// The chosen identity, if any.
    identity: Option<Arc<crate::node_identity::NodeIdentity>>,
    /// The frozen snapshot, present from `start()` until a failed start or a
    /// shutdown clears it.
    active: Option<Arc<StartedConfig>>,
    /// 4CP-W: monotonic network-cycle id, bumped by every `start()`. Tasks and
    /// session registrations carry the generation they were created under, so
    /// a late result from a torn-down cycle is rejected even if a restart
    /// reuses the exact same configuration.
    generation: u64,
    /// 4CP-Y (X-6): true for the whole duration of a `shutdown()`, from the
    /// moment the stop is engaged until the teardown completes. It closes the
    /// window in which a `start()` racing a `shutdown()` on a *non-live* state
    /// (`Configured` / `Failed` / `Unconfigured`) could slip through: while a
    /// stop is in flight, `start()` refuses regardless of the recorded state.
    stopping: bool,
}

impl NetworkLifecycle {
    fn new() -> Self {
        Self {
            state: P2PNetworkState::Unconfigured,
            mode: P2PProtocolMode::LegacyV5,
            identity: None,
            active: None,
            generation: 0,
            stopping: false,
        }
    }

    /// True once the configuration has been frozen by a `start()` attempt
    /// (live, in progress, or cleanly stopped). Once frozen it can never be
    /// reconfigured, even across a restart.
    fn is_frozen(&self) -> bool {
        matches!(
            self.state,
            P2PNetworkState::Starting
                | P2PNetworkState::Started
                | P2PNetworkState::Stopping
                | P2PNetworkState::Stopped
        )
    }
}

/// 4CP-W: the atomic task-admission control for one network cycle.
///
/// One `std::sync::Mutex` guards the acceptance flag, the current generation
/// and the list of tracked handles *together*, so "may I register a task?" and
/// "close admission" are a single decision. This removes the previous race in
/// which a task was spawned after `shutdown()` had already drained the task
/// list (the flag check and the `push` were not atomic): a spawn either lands
/// before the close and is therefore included in the teardown, or the cycle is
/// already closed and the spawn is refused (its future is never created, so it
/// acquires no resources). The lock is never held across an `.await`.
struct TaskAdmission {
    /// True only while a cycle is live. 4CP-Y (X-3): closed by construction and
    /// opened only by `start()` (under the lifecycle lock), so a network that
    /// never started admits no session task — there is no pre-start window in
    /// which an operational dial could register a session. Test harnesses that
    /// need a dialable cycle without binding a socket open it explicitly through
    /// `open_cycle_for_test`.
    accepting: bool,
    /// The generation of the cycle currently accepting tasks.
    generation: u64,
    /// Handles of this cycle's long-lived tasks, drained+aborted by
    /// `shutdown()`.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TaskAdmission {
    fn new() -> Self {
        Self {
            accepting: false,
            generation: 0,
            tasks: Vec::new(),
        }
    }
}

/// 4CP-W (tests only): a rendezvous that lets a test interleave a `shutdown()`
/// deterministically in the middle of `start()`, or a real `handle_peer` in the
/// middle of its session registration. Production never installs one, so the
/// only cost on those paths is a single `None` check.
#[allow(dead_code)]
#[derive(Default)]
struct StartGate {
    /// Signalled by the gated function once it has reached the rendezvous.
    arrived: tokio::sync::Notify,
    /// Awaited by the gated function; the test fires it after it has shut the
    /// cycle down.
    release: tokio::sync::Notify,
}

/// 4CP-AA (X-2): why `shutdown()` did not report a clean teardown. The classes
/// are kept distinct so a caller can tell a task that refused to stop from a
/// task that panicked from a peer-store flush that could not finish in time.
/// The public signature stays `Result<(), String>`; these are rendered to
/// strings only at the boundary.
#[derive(Debug)]
enum ShutdownError {
    /// A tracked task did not terminate within the global teardown budget.
    TaskTimeout(usize),
    /// A tracked task panicked (a join error that is not a cancellation).
    TaskPanic(usize, String),
    /// The peer store could not be flushed within the global teardown budget.
    PeerStoreSave(String),
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownError::TaskTimeout(i) => write!(
                f,
                "task {} did not terminate within the {:?} shutdown budget",
                i, SHUTDOWN_TASK_BUDGET
            ),
            ShutdownError::TaskPanic(i, e) => write!(f, "task {} join error: {}", i, e),
            ShutdownError::PeerStoreSave(e) => write!(f, "peer-store save failed: {}", e),
        }
    }
}

/// P2P network manager
#[derive(Clone)]
pub struct P2PNetwork {
    config: P2PConfig,
    /// 2E-B: the wire this node opens and accepts sockets on.
    ///
    /// Held as `Arc<dyn Transport>` so the peer manager never names a socket
    /// type: dial and accept go through this, everything else (session keys,
    /// address book, PEX, sync) stays on `SocketAddr`.
    transport: Arc<dyn Transport>,
    peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Phase 2A: addresses with an outbound dial in flight. The initial sweep,
    /// heartbeat, redial loop and PEX can all reach `connect_to_peer` for the
    /// same address concurrently; without this guard a peer gets two sessions
    /// and the `peers` map silently drops one of them.
    dialing: Arc<RwLock<HashSet<SocketAddr>>>,
    /// Phase 2C: the subset of `peers` sessions this node itself initiated.
    ///
    /// Session *direction* lives with the sessions, not with the address book:
    /// an address's `PeerSource` records how we first learned it and is
    /// deliberately never relabelled, so it cannot answer "is this live session
  /// ours?". Exactly two writers  -  the dial path inserts, the task wrapping
    /// `handle_peer` removes — so it cannot drift from `peers` without `peers`
    /// drifting too. Never held together with `peers` or `addresses`.
    outbound_sessions: Arc<RwLock<HashSet<SocketAddr>>>,
    /// Phase 2B: the single owner of everything the node knows about
    /// addresses — membership, metadata, TTL clock, PEX origins and scores.
    /// Supersedes the former `known_peers` / `peer_last_seen` / `peer_meta` /
    /// `pex_origins` / `peer_scores` quintet.
    ///
    /// **Lock discipline**: this guard and `peers` (the session map) must never
    /// be held at the same time. Snapshot one, release it, then take the other.
    /// Holding both is the deadlock this migration exists to eliminate.
    addresses: Arc<RwLock<AddressManager>>,
    /// Phase 2D: the self-healing controller. Observes the peer count and
    /// decides whether a recovery round may run. Holds no session or address
    /// lock itself, so it can be read for diagnostics at any time. Written only
    /// by the recovery task, which is also the sole dialer it drives, so there
    /// is exactly one writer.
    recovery: Arc<RwLock<PeerRecoveryController>>,
    tx_channel: mpsc::UnboundedSender<Transaction>,
    peer_discovery_tx: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedSender<SocketAddr>>>>,
    get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
    get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
  // PHASE 4G stake hooks (set-once; see StakeHooks).
  stake_hooks: StakeHooks,
    seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
  /// 2E-D: scheduling state for relays  -  upstream peer + "already
    /// scheduled". Read strictly before a relay wave is started, so a
    /// payload can never be transmitted twice per link. Separate from
    /// `seen_transactions` (receipt dedup); see `PropagationEntry`.
    propagation_state: Arc<RwLock<PropagationState>>,
    /// 2E-D: relays currently waiting out their per-peer jitter. Bounded by
    /// construction (`in-flight accepts × MAX_PROPAGATION_FANOUT`) and
    /// returned to 0 once the wave has been written out — this is what the
    /// "no unbounded queue" test observes.
    propagation_inflight: Arc<AtomicUsize>,
    /// 2E-D: the one RNG that draws relay delays and fan-out selections.
    /// Mutex, never held across an `.await`, and short-lived: it exists so a
    /// test can reseed it and replay a wave byte for byte.
    propagation_rng: Arc<std::sync::Mutex<StdRng>>,
    /// B4: shared bootstrap state (counters, parent-request dedup, orphan TTL)
    sync_ctx: Arc<SyncContext>,
    /// B4: true when the hash is already in the orphan store (sync dedup)
    is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    /// 4CB: cooperative shutdown flag. Set by `shutdown()`; read by dial
    /// paths to refuse new sessions while teardown is in progress.
    /// Long-lived loops are stopped by aborting their tracked handles
    /// (see `admission`); the flag only gates NEW work, never fakes completion.
    shutdown: Arc<AtomicBool>,
    /// 4CB / 4CP-W: registry of long-lived background tasks (accept loop,
    /// discovery, recovery, redial, peer-store, anchor, DNS, PEX, cache,
    /// initial sweep) plus per-peer `handle_peer` tasks, combined with the
    /// atomic acceptance flag and the cycle generation (see [`TaskAdmission`]).
    /// Every handle is aborted AND awaited with a bounded timeout in
    /// `shutdown()`; a task that does not terminate is a reported error, never
    /// silently leaked. Registration is a synchronous call from any task
    /// context (the mutex is never held across an `.await`).
    admission: Arc<std::sync::Mutex<TaskAdmission>>,
    /// 4CP-W: serialises concurrent `shutdown()` calls so the second one waits
    /// for the first teardown instead of observing a half-torn-down cycle.
    shutdown_lock: Arc<tokio::sync::Mutex<()>>,
    /// 4CP-W: test-only start rendezvous (see [`StartGate`]). `None` in
    /// production.
    #[cfg(test)]
    start_gate: Arc<std::sync::Mutex<Option<Arc<StartGate>>>>,
    /// 4CP-AA (Y-5, tests): test-only outbound registration rendezvous (see
    /// [`StartGate`]). `None` in production; consumed once by the outbound
    /// session path so a test can interleave a `shutdown()` inside a real
    /// outbound `handle_peer`.
    #[cfg(test)]
    outbound_record_gate: Arc<std::sync::Mutex<Option<Arc<StartGate>>>>,
    /// PHASE 4CP-U (4CPT-01): the one place that owns the handshake choice, the
    /// persistent node identity, the start/shutdown lifecycle state and the
    /// frozen start snapshot. Replaces the former `protocol_mode` RwLock,
    /// `started` AtomicBool and `node_identity` RwLock, whose independent
    /// guards allowed a setter to race `start()`. See [`NetworkLifecycle`].
    lifecycle: Arc<std::sync::Mutex<NetworkLifecycle>>,
    /// PHASE 4CP-S: verified provenance of the live sessions, keyed by a
    /// node-local unique session id (NEVER by `SocketAddr` — see
    /// `SessionAuthRegistry`). Observability only in this phase: reputation and
    /// address announcements do NOT consume it yet.
    session_auth: Arc<RwLock<SessionAuthRegistry>>,
    /// PHASE 4CP-S: monotonic source of `session_auth` session ids. Each
    /// `handle_peer` invocation takes exactly one; ids are never reused within
    /// the process.
    session_seq: Arc<AtomicU64>,
}

impl P2PNetwork {
    /// Create a new P2P network manager
    pub fn new(
        config: P2PConfig,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            config,
            transport: Arc::new(TcpTransport::new()),
            peers: Arc::new(RwLock::new(HashMap::new())),
            dialing: Arc::new(RwLock::new(HashSet::new())),
            outbound_sessions: Arc::new(RwLock::new(HashSet::new())),
            addresses: Arc::new(RwLock::new(AddressManager::new())),
            recovery: Arc::new(RwLock::new(PeerRecoveryController::new())),
            tx_channel,
            peer_discovery_tx: Arc::new(tokio::sync::Mutex::new(None)),
            get_dag_hashes,
            get_transaction_by_hash,
            get_tips,
            seen_transactions: Arc::new(RwLock::new(HashMap::new())),
            propagation_state: Arc::new(RwLock::new(HashMap::new())),
            propagation_inflight: Arc::new(AtomicUsize::new(0)),
            // OS entropy, same policy as the rest of the node: the choice of
            // which neighbour hears first must not be predictable, and must
            // not be reproducible across restarts.
            propagation_rng: Arc::new(std::sync::Mutex::new(StdRng::from_entropy())),
            sync_ctx,
            is_orphan,
  stake_hooks: StakeHooks::default(),
            shutdown: Arc::new(AtomicBool::new(false)),
            admission: Arc::new(std::sync::Mutex::new(TaskAdmission::new())),
            shutdown_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(test)]
            start_gate: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            outbound_record_gate: Arc::new(std::sync::Mutex::new(None)),
            // PHASE 4CP-U: legacy by default; authenticated mode and the node
            // identity are wired explicitly (see `set_protocol_mode` /
            // `set_node_identity`) before the node starts. The lifecycle mutex
            // holds both plus the start/shutdown state.
            lifecycle: Arc::new(std::sync::Mutex::new(NetworkLifecycle::new())),
            session_auth: Arc::new(RwLock::new(SessionAuthRegistry::default())),
            session_seq: Arc::new(AtomicU64::new(1)),
        }
    }

    /// 4CP-U: lock the lifecycle, ignoring poisoning (a panic while holding it
    /// cannot leave the node with a half-configured state — the data is plain
    /// and every accessor tolerates the poison).
    fn lock_lifecycle(&self) -> std::sync::MutexGuard<'_, NetworkLifecycle> {
        match self.lifecycle.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        }
    }

    /// 4CP-W: lock the admission control, ignoring poisoning (plain data; the
    /// guard tolerates a poisoned mutex so a panic in one task cannot wedge
    /// teardown).
    fn lock_admission(&self) -> std::sync::MutexGuard<'_, TaskAdmission> {
        match self.admission.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        }
    }

    /// 4CP-W: the generation of the current network cycle (diagnostics / tests).
    pub fn generation(&self) -> u64 {
        self.lock_lifecycle().generation
    }

    /// PHASE 4CP: select the handshake protocol. Intended to be called once,
    /// before `start()`. Never triggers a fallback: the mode is authoritative.
    /// 4CP-U (4CPT-01): refused once the configuration is frozen (starting,
    /// live, or stopped), decided under the same lock `start()` uses.
    pub fn set_protocol_mode(&self, mode: P2PProtocolMode) {
        let mut lc = self.lock_lifecycle();
        if lc.is_frozen() {
            tracing::error!(
                "set_protocol_mode ignored: the P2P protocol mode is immutable after start()"
            );
            return;
        }
        lc.mode = mode;
        lc.state = P2PNetworkState::Configured;
    }

    /// PHASE 4CP: the currently selected handshake protocol.
    pub fn protocol_mode(&self) -> P2PProtocolMode {
        self.lock_lifecycle().mode
    }

    /// PHASE 4CP-U: the current lifecycle state (diagnostics / tests).
    pub fn lifecycle_state(&self) -> P2PNetworkState {
        self.lock_lifecycle().state
    }

    /// PHASE 4CP-U: the mode the *running* network was actually started with,
    /// taken from the frozen snapshot. `None` before any successful `start()`.
    /// Lets a test prove the dial path and the accept loop speak the snapshot,
    /// not whatever a racing setter wrote.
    pub fn started_protocol_mode(&self) -> Option<P2PProtocolMode> {
        self.lock_lifecycle().active.as_ref().map(|s| s.mode)
    }

    /// PHASE 4CP: install the persistent network identity used by v6.
    /// `AuthenticatedV6` mode fails closed without one. 4CP-U (4CPT-01): like
    /// the mode, refused once the configuration is frozen.
    pub fn set_node_identity(&self, identity: crate::node_identity::NodeIdentity) {
        let mut lc = self.lock_lifecycle();
        if lc.is_frozen() {
            tracing::error!(
                "set_node_identity ignored: the node identity is immutable after start()"
            );
            return;
        }
        lc.identity = Some(Arc::new(identity));
    }

    /// PHASE 4CP: this node's persistent network identity, if configured.
    pub fn node_identity(&self) -> Option<Arc<crate::node_identity::NodeIdentity>> {
        self.lock_lifecycle().identity.clone()
    }

    /// PHASE 4CP-U: the frozen `(mode, identity)` pair the running network uses.
    /// 4CP-Y (X-3): `None` when there is no live cycle. There is no fallback to
    /// the live setters: a dial must be able to observe "not operational" so it
    /// can refuse, instead of silently opening a session with an un-frozen mode.
    fn started_config(
        &self,
    ) -> Option<(
        P2PProtocolMode,
        Option<Arc<crate::node_identity::NodeIdentity>>,
    )> {
        let lc = self.lock_lifecycle();
        lc.active
            .as_ref()
            .map(|s| (s.mode, s.identity.clone()))
    }

    /// PHASE 4CP-S: take the next unique session id (process-monotonic).
    /// Test-only surface: `handle_peer` draws its id straight from the shared
    /// counter (it has no `&self`).
    #[cfg(test)]
    fn next_session_id(&self) -> u64 {
        self.session_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// PHASE 4CP-S: record a session's verified provenance under its exact id.
    /// Test-only surface mirroring `handle_peer`'s registry write.
    #[cfg(test)]
    async fn record_session_auth(&self, session_id: u64, addr: SocketAddr, state: P2PSessionAuth) {
        self.session_auth
            .write()
            .await
            .record(session_id, addr, state);
    }

    /// PHASE 4CP-S: drop exactly one session's state (teardown). Never affects
    /// any other session, even one sharing the same endpoint.
    /// Test-only surface mirroring `handle_peer`'s registry clear.
    #[cfg(test)]
    async fn clear_session_auth(&self, session_id: u64) {
        self.session_auth.write().await.clear(session_id);
    }

    /// 4CP-W: the exact registration `handle_peer` performs, exposed so a test
    /// can prove the cycle/generation guard on the real code path. Returns
    /// whether the session was recorded. 4CP-AA (X-5): test-only — it is not
    /// compiled into the production binary.
    #[cfg(test)]
    async fn record_session_auth_if_active(
        &self,
        generation: u64,
        session_id: u64,
        addr: SocketAddr,
        state: P2PSessionAuth,
    ) -> bool {
        self.session_auth
            .write()
            .await
            .record_if_active(generation, session_id, addr, state)
    }

    /// 4CP-W: the exact teardown clear `handle_peer` performs, exposed for the
    /// same reason. Returns whether an entry was removed (and it belonged to
    /// the live cycle). 4CP-AA (X-5): test-only — not compiled into production.
    #[cfg(test)]
    async fn clear_session_auth_if_active(&self, generation: u64, session_id: u64) -> bool {
        self.session_auth
            .write()
            .await
            .clear_if_active(generation, session_id)
    }

    /// 4CP-W (tests): install a one-shot `StartGate` so a test can interleave a
    /// `shutdown()` deterministically inside `start()`.
    #[cfg(test)]
    fn install_start_gate(&self) -> Arc<StartGate> {
        let gate = Arc::new(StartGate::default());
        *self.start_gate.lock().unwrap_or_else(|e| e.into_inner()) = Some(gate.clone());
        gate
    }

    /// 4CP-AA (Y-5, tests): install a one-shot outbound registration rendezvous,
    /// so a test can interleave a `shutdown()` inside a real *outbound*
    /// `handle_peer`, exactly as `install_start_gate` does for `start()`.
    #[cfg(test)]
    fn install_outbound_record_gate(&self) -> Arc<StartGate> {
        let gate = Arc::new(StartGate::default());
        *self
            .outbound_record_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(gate.clone());
        gate
    }

    /// 4CP-AA (Y-5): consume the outbound registration rendezvous. Always `None`
    /// in production, so the outbound path pays a single `Option` check.
    fn take_outbound_record_gate(&self) -> Option<Arc<StartGate>> {
        #[cfg(test)]
        {
            self.outbound_record_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
        }
        #[cfg(not(test))]
        {
            None
        }
    }

    /// 4CP-Y (X-3, tests): open one operational cycle WITHOUT binding a socket,
    /// so a harness that exercises the dialing paths (recovery, PEX) has the
    /// same frozen snapshot, open task admission, live lifecycle state and
    /// registry generation that a real `start()` would install. This isolates
    /// the "dialable before start" concession to tests; production can only
    /// reach these states through `start()`.
    #[cfg(test)]
    async fn open_cycle_for_test(&self, mode: P2PProtocolMode) {
        let generation = {
            let mut lc = self.lock_lifecycle();
            lc.generation = lc.generation.wrapping_add(1);
            let generation = lc.generation;
            lc.active = Some(Arc::new(StartedConfig {
                mode,
                identity: lc.identity.clone(),
            }));
            lc.state = P2PNetworkState::Started;
            lc.stopping = false;
            generation
        };
        {
            let mut adm = self.lock_admission();
            adm.accepting = true;
            adm.generation = generation;
        }
        self.shutdown.store(false, Ordering::Relaxed);
        self.session_auth.write().await.begin_generation(generation);
    }

    /// PHASE 4CP-S: how the session with this exact id was authenticated.
    pub async fn session_auth_by_id(&self, session_id: u64) -> Option<P2PSessionAuth> {
        self.session_auth
            .read()
            .await
            .get(session_id)
            .map(|e| e.state.clone())
    }

    /// PHASE 4CP-S: the states of every live session at `addr`. There can be
    /// more than one (same endpoint, distinct sessions); never assume one.
    pub async fn session_auth_for_addr(&self, addr: &SocketAddr) -> Vec<(u64, P2PSessionAuth)> {
        self.session_auth.read().await.for_addr(addr)
    }

    /// PHASE 4CP-S: number of live recorded sessions (diagnostics / tests).
    pub async fn session_auth_len(&self) -> usize {
        self.session_auth.read().await.len()
    }

    /// PHASE 4CP: classify a completed handshake into a session state. Pure,
    /// so the legacy/authenticated split is unit-testable and cannot drift
    /// from `handle_peer`.
    fn session_auth_for(peer: Option<crate::node_identity::NodeId>) -> P2PSessionAuth {
        match peer {
            Some(node_id) => P2PSessionAuth::Authenticated { node_id },
            None => P2PSessionAuth::EncryptedUnauthenticated,
        }
    }

    /// Phase 4CH: same construction as [`P2PNetwork::new`], but the wire
    /// transport is supplied by the caller. Production code builds through
    /// `new()` (always TCP); only tests install a substitute — typically a
    /// dial-refusing transport that records every outbound attempt and never
    /// opens a socket, so a synthetic public address can be exercised through
    /// the real receive path without any real connection leaving the machine.
    /// A test transport should still delegate `bind` to [`TcpTransport`] when
    /// the test needs real inbound sockets.
    pub fn new_with_transport(
        config: P2PConfig,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
        transport: Arc<dyn Transport>,
    ) -> Self {
        Self {
            transport,
            ..Self::new(
                config,
                tx_channel,
                get_dag_hashes,
                get_transaction_by_hash,
                get_tips,
                sync_ctx,
                is_orphan,
            )
        }
    }

    /// 4CB / 4CP-W: spawn a long-lived background task and register its handle
    /// so `shutdown()` can abort AND await it. 4CP-W: the acceptance check and
    /// the handle registration are one atomic step under the admission lock, so
    /// a task can never be spawned after `shutdown()` has drained the registry.
    /// Returns whether the task was admitted (callers may ignore this; a
    /// refused task is simply never created).
    fn spawn_tracked(&self, fut: impl Future<Output = ()> + Send + 'static) -> bool {
        Self::admit_task(&self.admission, |_generation| fut)
    }

    /// 4CP-W: the atomic admission primitive. The closure receives the
    /// generation of the cycle it is admitted into and returns the future to
    /// spawn; it is not called at all when the cycle is closed, so refusing a
    /// task creates nothing. Free-function form so `accept_loop` (which has no
    /// `&self`) shares the exact same mechanism.
    fn admit_task<F, Fut>(admission: &Arc<std::sync::Mutex<TaskAdmission>>, make: F) -> bool
    where
        F: FnOnce(u64) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut guard = match admission.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if !guard.accepting {
            return false;
        }
        // 4CP-AA (X-4): reap handles that already finished, so the tracked set
        // is bounded by the number of *live* tasks rather than by every task
        // ever admitted (long-lived nodes churn sessions). A completed handle
        // carries no teardown obligation; a panic has already been reported by
        // the task's own panic hook.
        guard.tasks.retain(|h| !h.is_finished());
        let handle = tokio::spawn(make(guard.generation));
        guard.tasks.push(handle);
        true
    }

    /// 4CB: explicit graceful shutdown.
    ///
    /// ## Contract (4CP-AA, X-2)
    ///
    /// `Ok(())` guarantees, at the instant it returns:
    /// 1. no new dials and no new sessions — the shutdown flag is set and task
    ///    admission is closed, so every later spawn is refused;
    /// 2. the session registry is sealed and cleared for this cycle, so a
    ///    handshake still in flight registers nothing;
    /// 3. the peer/dial/outbound maps are cleared;
    /// 4. every tracked task was aborted and *observed to terminate* within the
    ///    single [`SHUTDOWN_TASK_BUDGET`] deadline (a task that did not is
    ///    reported, never silently leaked);
    /// 5. the peer store was flushed within the same deadline;
    /// 6. the lifecycle is `Stopped` (or `Unconfigured` for a never-configured
    ///    network) with no live snapshot.
    ///
    /// `Err` reports *which* of (4)/(5) failed, classified as a task timeout, a
    /// task panic, or a peer-store save failure. A `shutdown()` that returns
    /// `Ok` performed every step; a partial teardown never masquerades as
    /// success. The few steps *before* the deadline is armed (the lifecycle
    /// transitions, the discovery-channel drop and the registry seal) are
    /// synchronous and are not awaited I/O, so they are outside the budget.
    ///
    /// ## Sequence
    ///
    /// (1) serialise concurrent callers (`shutdown_lock`); (2) under the
    /// lifecycle lock, move `Starting|Started` -> `Stopping`, and a never-live
    /// `Configured|Failed` -> `Stopped`; (3) under the admission lock, close
    /// task admission and detach every tracked handle atomically; (4) under the
    /// registry write lock, `close_and_clear` the session map; (5) abort+await
    /// the detached handles under one shared deadline; (6) flush the peer store
    /// under the same deadline; (7) finalise the state as `Stopped` with no live
    /// snapshot.
    ///
    /// No lock is held across the awaits in (5)/(6).
    pub async fn shutdown(&self) -> Result<(), String> {
        // Serialise concurrent shutdown() calls: the second waits until the
        // first teardown is fully done, then runs its (empty) pass.
        let _serial = self.shutdown_lock.lock().await;
        // (2) Engage the stop under the lifecycle lock.
        {
            let mut lc = self.lock_lifecycle();
            match lc.state {
                P2PNetworkState::Starting | P2PNetworkState::Started => {
                    lc.state = P2PNetworkState::Stopping;
                }
                // 4CP-Y (X-6): a stop on a never-live network still freezes it
                // as `Stopped`, so a concurrent start() can never observe a
                // stale `Configured`/`Failed` and slip through.
                P2PNetworkState::Configured | P2PNetworkState::Failed => {
                    lc.state = P2PNetworkState::Stopped;
                }
                P2PNetworkState::Stopping
                | P2PNetworkState::Stopped
                | P2PNetworkState::Unconfigured => {}
            }
            lc.stopping = true;
            lc.active = None;
        }
        self.shutdown.store(true, Ordering::Relaxed);
        {
            let mut tx_lock = self.peer_discovery_tx.lock().await;
            *tx_lock = None;
        }
        // (3) Close task admission and detach this cycle's handles atomically.
        let handles: Vec<tokio::task::JoinHandle<()>> = {
            let mut adm = self.lock_admission();
            adm.accepting = false;
            adm.tasks.drain(..).collect()
        };
        {
            let mut peers = self.peers.write().await;
            peers.clear();
        }
        self.dialing.write().await.clear();
        self.outbound_sessions.write().await.clear();
        // (4) Close+clear the session registry: no late registration survives.
        self.session_auth.write().await.close_and_clear();
        // (5) Arm ONE teardown deadline and abort+await every detached handle
        // under it. The same deadline then covers the peer-store flush in (6),
        // so the bounded part of the teardown is a single budget regardless of
        // how many tasks the cycle registered. No lock is held across these
        // awaits.
        let mut failures: Vec<ShutdownError> = Vec::new();
        let deadline = tokio::time::Instant::now() + SHUTDOWN_TASK_BUDGET;
        for (i, handle) in handles.into_iter().enumerate() {
            handle.abort();
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                failures.push(ShutdownError::TaskTimeout(i));
                continue;
            }
            match tokio::time::timeout(remaining, handle).await {
                // Cancellation is the expected outcome of `abort()`.
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_cancelled() => {}
                Ok(Err(e)) => failures.push(ShutdownError::TaskPanic(i, e.to_string())),
                Err(_) => failures.push(ShutdownError::TaskTimeout(i)),
            }
        }
        // A late accepted connection cannot have re-inserted itself: its spawn
        // was refused by the closed admission. Clear again defensively.
        {
            let mut peers = self.peers.write().await;
            peers.clear();
        }
        self.dialing.write().await.clear();
        self.outbound_sessions.write().await.clear();
        // (6) Flush the peer store under the SAME deadline. A flush that cannot
        // finish is a distinct teardown failure, not a silent best-effort miss.
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            failures.push(ShutdownError::PeerStoreSave(format!(
                "not attempted: shutdown budget of {:?} exhausted",
                SHUTDOWN_TASK_BUDGET
            )));
        } else {
            match tokio::time::timeout(remaining, self.try_save_known_peers()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => failures.push(ShutdownError::PeerStoreSave(e)),
                Err(_) => failures.push(ShutdownError::PeerStoreSave(format!(
                    "did not complete within the {:?} shutdown budget",
                    SHUTDOWN_TASK_BUDGET
                ))),
            }
        }
        // (7) 4CP-W: a live network that has shut down becomes `Stopped`. The
        // configuration stays frozen (immutable once started) and the snapshot
        // is released; a later restart re-reads the same mode/identity and gets
        // a fresh generation.
        {
            let mut lc = self.lock_lifecycle();
            if matches!(
                lc.state,
                P2PNetworkState::Stopping
                    | P2PNetworkState::Started
                    | P2PNetworkState::Starting
            ) {
                lc.state = P2PNetworkState::Stopped;
            }
            lc.stopping = false;
            lc.active = None;
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; "))
        }
    }

    /// 4CB: true once `shutdown()` has been called. Dial paths consult this
    /// to refuse new sessions during teardown.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

  /// PHASE 4G: wire the node stake receiver (called once at boot, before
  /// or after start  -  the hooks are resolved per message, never cached).
  pub fn set_stake_channel(&self, tx: mpsc::UnboundedSender<StakePayload>) {
  if let Ok(mut guard) = self.stake_hooks.stake_channel.lock() {
  *guard = Some(tx);
            }
                }

  /// PHASE 4G: wire vote-by-id serving for GetData fallback (node
  /// storage accessor). Unwired = transactions only (as before).
  pub fn set_vote_lookup(&self, lookup: StakeVoteLookup) {
  if let Ok(mut guard) = self.stake_hooks.get_vote_by_id.lock() {
  *guard = Some(lookup);
        }
    }

    /// Start the P2P network
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 4CP-W (4CPT-01/02/10): freeze the configuration, bump the cycle
        // generation, move to `Starting` and OPEN task admission — all under the
        // lifecycle lock, so no setter can interleave and no shutdown can be
        // half-observed. From this commit point an engaged `shutdown()` always
        // wins: it moves the state off `Starting`, and the final check below
        // refuses to move back to `Started`.
        let (snapshot, generation) = {
            let mut lc = self.lock_lifecycle();
            match lc.state {
                P2PNetworkState::Starting => {
                    return Err("P2P network is already starting".into());
                }
                P2PNetworkState::Started => {
                    return Err("P2P network is already started".into());
                }
                P2PNetworkState::Stopping => {
                    return Err("P2P network is shutting down".into());
                }
                // 4CP-W (V-3): no implicit v5. An unconfigured network must be
                // given an explicit mode first (set_protocol_mode / TOML /
                // --p2p-protocol); a silent legacy start is exactly the bug.
                P2PNetworkState::Unconfigured => {
                    return Err("P2P protocol mode not configured: call set_protocol_mode \
                                (or set `p2p_protocol`) before start()"
                        .into());
                }
                P2PNetworkState::Configured
                | P2PNetworkState::Failed
                | P2PNetworkState::Stopped => {}
            }
            // 4CP-Y (X-6): a stop that is in flight for a non-live state also
            // blocks a racing start, so the outcome never depends on which of
            // the two reached the lifecycle lock first.
            if lc.stopping {
                return Err("P2P network is shutting down".into());
            }
            // 4CPT-02: AuthenticatedV6 must never start without an identity —
            // fail closed here even if the caller forgot, leaving the lifecycle
            // un-frozen so the operator can fix it and retry.
            if lc.mode == P2PProtocolMode::AuthenticatedV6 && lc.identity.is_none() {
                return Err("AuthenticatedV6 requires a node identity before start()".into());
            }
            lc.generation = lc.generation.wrapping_add(1);
            let generation = lc.generation;
            let snap = Arc::new(StartedConfig {
                mode: lc.mode,
                identity: lc.identity.clone(),
            });
            lc.active = Some(snap.clone());
            lc.state = P2PNetworkState::Starting;
            // Open task admission for this cycle while still holding the
            // lifecycle lock (lock order: lifecycle -> admission, never the
            // reverse). A concurrent shutdown() cannot have run yet: it needs
            // the lifecycle lock we hold.
            {
                let mut adm = self.lock_admission();
                adm.accepting = true;
                adm.generation = generation;
            }
            self.shutdown.store(false, Ordering::Relaxed);
            (snap, generation)
        };
        // Open the session registry for this generation (clears any prior
        // cycle's state). This is serialised with a late handshake's
        // registration by the registry write lock.
        self.session_auth.write().await.begin_generation(generation);

        info!(
            "Starting P2P network on {} (cycle {})",
            self.config.listen_addr, generation
        );

        // 4CP-W (tests): a deterministic interleaving point. A test installs a
        // gate, then shuts the cycle down while `start()` is parked here.
        #[cfg(test)]
        {
            let gate = self
                .start_gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(gate) = gate {
                gate.arrived.notify_one();
                gate.release.notified().await;
            }
        }

        // If a shutdown() engaged while we were parked (or during the registry
        // setup), abandon the start before acquiring any resource.
        if !self.lock_admission().accepting {
            return Err("P2P start() was superseded by a concurrent shutdown()".into());
        }

        // Phase 1: restore known peers from disk before first dial.
        self.load_known_peers().await;

        // Start listening for incoming connections. 4CPT-10: a bind failure
        // must not leave the network looking started — move to `Failed`, clear
        // the snapshot and report the error.
        let listener = match self
            .transport
            .bind(&PeerAddr::Ip(self.config.listen_addr))
            .await
        {
            Ok(listener) => listener,
            Err(e) => {
                {
                    let mut adm = self.lock_admission();
                    adm.accepting = false;
                }
                {
                    let mut lc = self.lock_lifecycle();
                    lc.active = None;
                    // Only the start that actually owns `Starting` may record
                    // the failure; a racing shutdown keeps its Stopping/Stopped
                    // state.
                    if lc.state == P2PNetworkState::Starting {
                        lc.state = P2PNetworkState::Failed;
                    }
                }
                // 4CP-Y (X-7): a failed start leaves no live cycle, so seal the
                // session registry opened for this generation. No residual
                // session state survives, and no dial can proceed either (the
                // dial path refuses without a live snapshot).
                {
                    self.session_auth.write().await.close_and_clear();
                }
                tracing::error!("P2P bind on {} failed: {}", self.config.listen_addr, e);
                return Err(e.into());
            }
        };
        let peers = self.peers.clone();
        let outbound_sessions = self.outbound_sessions.clone();
        let tx_channel = self.tx_channel.clone();
        let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
        let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
        let get_tips = Arc::clone(&self.get_tips);
        let seen_transactions = Arc::clone(&self.seen_transactions);
        let propagation_state = Arc::clone(&self.propagation_state);
        let sync_ctx = Arc::clone(&self.sync_ctx);
        let is_orphan = Arc::clone(&self.is_orphan);
  let stake_hooks = self.stake_hooks.clone();
  let network_id = self.config.network_id;
        let local_addr = self.config.listen_addr;
        let addresses = self.addresses.clone();
        // PHASE 4CP: handshake selection + identity + session-auth registry,
        // read from the frozen snapshot so both loops agree.
        let protocol_mode = snapshot.mode;
        let node_identity = snapshot.identity.clone();
        let session_auth = self.session_auth.clone();
        let session_seq = self.session_seq.clone();
        let (peer_discovery_tx, mut peer_discovery_rx) = mpsc::unbounded_channel::<SocketAddr>();
        {
            let mut tx_lock = self.peer_discovery_tx.lock().await;
            *tx_lock = Some(peer_discovery_tx.clone());
        }
        let p2p_discovery = self.clone();
        // 4CB: tracked so shutdown() aborts AND awaits it (was detached).
        self.spawn_tracked(async move {
            while let Some(addr) = peer_discovery_rx.recv().await {
                p2p_discovery.connect_to_peer(addr).await;
            }
        });
        // 4CB / 4CP-W: the accept task owns the listener; awaiting it in
        // shutdown() proves the OS port is released. Per-peer sessions spawned
        // inside accept_loop are admitted through the same atomic admission
        // control, so none can escape teardown.
        let accept_admission = self.admission.clone();
        self.spawn_tracked(async move {
            Self::accept_loop(
                listener,
                peers,
                local_addr,
                addresses,
                outbound_sessions,
                tx_channel,
                get_dag_hashes,
                get_transaction_by_hash,
                get_tips,
                seen_transactions,
                propagation_state,
                peer_discovery_tx,
                sync_ctx,
                is_orphan,
  stake_hooks,
  network_id,
                protocol_mode,
                node_identity,
                session_auth,
                session_seq,
                accept_admission,
            )
            .await;
        });

        // Phase 2A: bring the recovery machinery up BEFORE the first dial pass.
        // The initial sweep used to run first and block here, so a peer store
        // full of dead addresses left the node with no heartbeat, no PEX and no
        // TTL task while it churned through timeouts.

        // Discover peers from DNS seeds
        self.discover_from_dns().await;

        // Phase 2D: self-healing loop (replaces the peer_count == 0 heartbeat)
        self.start_recovery_task().await;

        // Start reconnection task (known peers first, seeds unprivileged)
        self.start_reconnection_task().await;

        // Phase 1: periodic peer-store flush + TTL expiry.
        self.start_peer_store_task().await;

        // Phase 2B (D9): rotate/expire anchors (persisted with the store).
        self.start_anchor_task().await;

        // Start periodic DNS discovery
        self.start_dns_discovery().await;

        // Start periodic peer exchange (PEX)
        self.start_pex().await;

        // Start cache cleanup task
        self.start_cache_cleanup().await;

        // First outbound pass, off the critical path: seeds first (on a brand-new
        // node they are the only known address source), then everything restored
        // from the peer store. Runs as its own task so `start()` is never gated
        // on a serial sweep of possibly-dead addresses.
        {
            let sweep = self.clone();
            // 4CB: tracked (was detached); one-shot dial sweep.
            self.spawn_tracked(async move {
                sweep.initial_dial_sweep().await;
            });
        }

        // 4CP-W: every task is spawned and the listener is held — the network
        // is live. Freeze the lifecycle as `Started`, but ONLY if the cycle is
        // still the one we committed: if a `shutdown()` engaged in the meantime
        // it moved the state to `Stopping`/`Stopped` and closed admission, and
        // it must never be undone by this late start. In that case the failed
        // start reports the supersession and leaves the stop in force.
        {
            let mut lc = self.lock_lifecycle();
            if lc.state == P2PNetworkState::Starting {
                lc.state = P2PNetworkState::Started;
                return Ok(());
            }
        }
        Err("P2P start() was superseded by a concurrent shutdown()".into())
    }

    /// Phase 2A: the very first outbound dial pass. Seeds go first because a
    /// node with an empty peer store has no other address source; afterwards the
    /// restored store is dialed. This is the only place where seeds lead, and it
    /// runs once — steady-state redial never privileges them.
    async fn initial_dial_sweep(&self) {
        for seed in &self.config.bootnodes {
            self.connect_to_peer(*seed).await;
        }

        // Phase 2C: the restored store is dialed through the same selection
        // every other redial round uses, bounded per cycle. A store restored
        // from a poisoned file must not be able to open every slot in one burst
        // before any selection has had a chance to weigh it.
        for addr in self.outbound_candidates(MAX_REDIAL_PER_CYCLE).await {
            self.connect_to_peer(addr).await;
        }
    }

    /// Phase 2B (D8): reload the versioned peer store. Schema v2 carries
    /// per-address metadata (source, attempts, quality, anchor flag); if the
    /// file does not parse as v2 we fall back to the legacy `Vec<String>`
    /// shape, so an existing `known_peers.json` is never silently discarded (R3).
    async fn load_known_peers(&self) {
        let Some(path) = self.config.peer_store_path.clone() else {
            return;
        };
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("Failed to load peer store {:?}: {}", path, e);
                return;
            }
        };

        let now = unix_now();
        let at = Instant::now();
        let local = self.config.listen_addr;

        let (count, legacy) = {
            let mut mgr = self.addresses.write().await;
            match serde_json::from_str::<PeerStoreFile>(&raw) {
                Ok(file) if file.version >= PEER_STORE_VERSION => {
                    (mgr.load_v2(&file, local, now, at), false)
                }
                // R3: a v1 store is plain address strings. Adopt every address
                // we can parse rather than discarding the file wholesale.
                _ => match serde_json::from_str::<Vec<String>>(&raw) {
                    Ok(addrs) => (mgr.load_legacy(&addrs, local, now, at), true),
                    Err(e) => {
                        warn!("Peer store {:?} unreadable ({}), starting empty", path, e);
                        return;
                    }
                },
            }
        };

        if count == 0 {
            return;
        }

        if legacy {
            info!(
                "💾 Loaded {} known peers from legacy store {:?} (upgrading to v{})",
                count,
                path,
                PEER_STORE_VERSION
            );
        } else {
            info!("💾 Loaded {} known peers from {:?}", count, path);
        }
    }

    /// Phase 2B (D8): persist the store as schema v2 with per-address metadata.
    /// Entries without metadata (possible only while a table is being rebuilt)
    /// are written with defaults rather than dropped, so no address is lost.
    async fn save_known_peers(&self) {
        // 4CP-AA (X-2): best-effort wrapper for the periodic task and existing
        // callers; `shutdown()` uses `try_save_known_peers` so a flush that
        // cannot complete is reported as a distinct teardown error.
        if let Err(e) = self.try_save_known_peers().await {
            warn!("{}", e);
        }
    }

    /// 4CP-AA (X-2): the fallible form of the peer-store flush. Returns `Ok(())`
    /// when there is nothing to save (no configured path) or the atomic replace
    /// succeeded; every failure is a distinct `Err` so `shutdown()` can classify
    /// it apart from a task that did not stop. The blocking file I/O runs on a
    /// `spawn_blocking` thread, so the `shutdown()` deadline is a real bound on
    /// the wait (a synchronous write on the async thread could not be preempted
    /// by `tokio::time::timeout`).
    async fn try_save_known_peers(&self) -> Result<(), String> {
        let Some(path) = self.config.peer_store_path.clone() else {
            return Ok(());
        };
        // 4CP-AK (AB-1): the snapshot and its generation are taken together,
        // under the address read lock. Two concurrent readers holding it observe
        // the same frozen state, so a higher generation can never describe
        // older content. All write coordination then happens on the blocking
        // thread (see `save_peer_store_blocking`), so a cancelled await cannot
        // drop it.
        let (file, generation) = {
            let mgr = self.addresses.read().await;
            let generation = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
            (mgr.to_store(), generation)
        };
        let json = serde_json::to_string(&file)
            .map_err(|e| format!("serialize peer store: {}", e))?;
        tokio::task::spawn_blocking(move || save_peer_store_blocking(&path, &json, generation))
            .await
            .map_err(|e| format!("peer-store save task failed to join: {}", e))?
    }

    /// Phase 1: mark a peer as currently/just known (updates TTL clock).
    async fn touch_peer(&self, addr: SocketAddr) {
        let mut mgr = self.addresses.write().await;
        if mgr.len() >= MAX_KNOWN_PEERS && !mgr.contains(addr) {
            return;
        }
        mgr.observe(addr, PeerSource::Restored, unix_now(), Instant::now());
    }

    /// Phase 2A: refresh the TTL clock for every peer holding a live session, so
    /// a long-lived connection is never expired out of the peer store (and hence
    /// out of the persisted file) just for having stayed up.
    async fn refresh_live_peer_clocks(&self) {
        // Snapshot the sessions and release before touching the manager: the
        // two guards are never held at the same time.
        let live: Vec<SocketAddr> = self.peers.read().await.keys().copied().collect();
        if live.is_empty() {
            return;
        }
        let at = Instant::now();
        let mut mgr = self.addresses.write().await;
        for a in live {
            mgr.touch(a, at);
        }
    }

    /// Phase 1: expire peers whose last_seen is older than PEER_TTL and flush the store.
    async fn start_peer_store_task(&self) {
        let peers = self.clone();
        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            let mut last_flush = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                // Phase 2A: a peer that stays connected longer than PEER_TTL must
                // not be expired out of the store. Refresh the clock for every live
                // session first, otherwise the node forgets its most reliable peers
                // precisely because they are reliable.
                peers.refresh_live_peer_clocks().await;

                // TTL expiry. The four guards the sweep used to hold in a fixed
                // order are now one, so there is no order left to invert.
                {
                    let live: HashSet<SocketAddr> =
                        peers.peers.read().await.keys().copied().collect();
                    let now = Instant::now();
                    let mut mgr = peers.addresses.write().await;
                    let (_, expired) = mgr.refresh_and_expire(&live, now, PEER_TTL);
                    if expired > 0 {
                        debug!("Peer TTL expired {} entries", expired);
                    }
                }

                // Phase 2B (D7): surface the live category mix. This is how an
                // operator can tell whether the node still has proven reachable
                // anchors or is running purely on untested candidates.
                {
                    let live: HashSet<SocketAddr> =
                        peers.peers.read().await.keys().copied().collect();
                    let mgr = peers.addresses.read().await;
                    let total = mgr.len();
                    if total > 0 {
                        let counts = mgr.categories(&live, unix_now());
                        debug!(
                            "Peer categories of {}: active={} recent={} anchor={} candidate={} penalized={}",
                            total, counts[0], counts[1], counts[2], counts[3], counts[4]
                        );
                    }
                }

                // Periodic flush
                if last_flush.elapsed() >= PEER_STORE_FLUSH_INTERVAL {
                    peers.save_known_peers().await;
                    last_flush = Instant::now();
                }
            }
        });
    }

    /// Phase 2B (D9): maintain a rotating set of anchors — addresses that have
    /// actually proven reachable — so the node keeps long-term entry points that
    /// do not depend on any seed.
    ///
    /// Anchors are several (never one), rotated by most-recent success, expired
    /// after `ANCHOR_TTL_SECS`, and freely replaceable. They are stored only as
    /// a flag on `PeerMeta`, so they are never consulted for state, never
    /// required for liveness, and never constitute a point of authority
    /// (Principle 5 / R6). The staged escalation that consumes them lives in 2D.
    async fn start_anchor_task(&self) {
        let node = self.clone();
        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            loop {
                tokio::time::sleep(ANCHOR_REFRESH_INTERVAL).await;
                node.refresh_anchors().await;
            }
        });
    }

    /// One anchor rotation pass: expire dead anchors, then promote from live
    /// sessions that have completed at least one handshake.
    async fn refresh_anchors(&self) {
        let now = unix_now();

        // Snapshot the session map first so the address manager is never held
        // while `peers` is (the two locks must not nest).
        let sessions: HashSet<SocketAddr> = self.peers.read().await.keys().copied().collect();

        let (alive, candidates, dead) = {
            let mgr = self.addresses.read().await;
            let current = mgr.anchor_addresses();
            let dead = expire_anchors(&current, now);
            let alive: Vec<(SocketAddr, u64)> = current
                .into_iter()
                .filter(|(a, _)| !dead.contains(a))
                .collect();
            let candidates = mgr.anchor_candidates(&sessions);
            (alive, candidates, dead)
        };

        let wanted = promote_anchors(&alive, &candidates, self.config.listen_addr);

        let promoted = {
            let mut mgr = self.addresses.write().await;
            mgr.apply_anchors(&wanted).0
        };

        if promoted > 0 || !dead.is_empty() {
            debug!(
                "Anchor rotation: {} promoted, {} expired, {} total",
                promoted,
                dead.len(),
                wanted.len()
            );
        }
        if wanted.len() < MIN_ANCHORS {
            // Not fatal — anchors are never required — but resilience now leans
            // more on the peer store, PEX and configured seeds.
            warn!(
                "Only {} anchor(s) (< {}): reachability relies on store/PEX/seeds",
                wanted.len(),
                MIN_ANCHORS
            );
        }
    }

    /// Phase 2D: the self-healing loop.
    ///
    /// Replaces the old heartbeat, which only reacted to `peer_count == 0` and
    /// therefore could not tell a node that lost 6 of its 8 peers from a node
    /// holding 128. This task observes the count every `RECOVERY_INTERVAL`,
    /// drives the controller through `Healthy` / `Recovering` / `Degraded` /
    /// `Exhausted`, and dials at most `MAX_DIALS_PER_ROUND` addresses per round
    /// in the anchor -> known -> seed order of `plan_recovery`.
    ///
    /// Silent while `Healthy`; only state transitions are logged. The existing
    /// redial loop is left untouched — this task is inactive in the common
    /// case, so it never doubles the dial pressure of a healthy node.
    async fn start_recovery_task(&self) {
        let node = self.clone();
        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            loop {
                // 2E-A (A.2 iii): bounded jitter on the recovery cadence so
                // the 5s self-heal beat is not a fixed fingerprint. The
                // controller and `recovery_round()` are untouched — only the
                // sleep changes, and never below the 5s baseline.
                tokio::time::sleep(Self::jittered_interval(
                    RECOVERY_INTERVAL,
                    RECOVERY_INTERVAL_JITTER,
                    rand::random::<u64>(),
                ))
                .await;
                node.recovery_round().await;
            }
        });
    }

    /// One full self-healing round: observe, decide, dial, record.
    ///
    /// Deliberately a method rather than inlined in the loop, so an integration
    /// test can drive the exact production round without waiting on wall-clock
    /// time. Returns the whole plan, including which tier supplied each dial.
    async fn recovery_round(&self) -> RecoveryRound {
        // Snapshot the session table and release before touching the
        // address manager: the two locks are never held together.
        let (count, connected) = {
            let guard = self.peers.read().await;
            (
                guard.len(),
                guard.keys().copied().collect::<HashSet<SocketAddr>>(),
            )
        };

        let mut ctl = *self.recovery.read().await;
        let now = Instant::now();

        if count >= RECOVERY_COMFORT_PEERS {
            if ctl.state != RecoveryState::Healthy {
                self.recovery.write().await.reset();
                info!(
                    "self-heal: peer_count {} >= comfort {} -> recovery complete, backoff reset",
                    count, RECOVERY_COMFORT_PEERS
                );
            }
            return RecoveryRound {
                state: RecoveryState::Healthy,
                dial: Vec::new(),
                tier1_anchors: 0,
                tier2_known: 0,
                tier3_seeds: 0,
                sources_left: true,
            };
        }

        // `Exhausted` is not a latch: once its backoff has fully expired, open
        // one slow probe window again (see `open_probe_window`).
        if ctl.state == RecoveryState::Exhausted && ctl.backoff_due(now) {
            self.recovery.write().await.open_probe_window();
            ctl = *self.recovery.read().await;
        }

        // Tier 2/3 come from the unchanged Phase 2C selection. Seeds
        // are split back out here so the ladder can withhold them.
        let ranked = self.outbound_candidates(MAX_DIALS_PER_ROUND).await;
        let seeds = self.config.bootnodes.clone();
        let seed_set: HashSet<SocketAddr> = seeds.iter().copied().collect();
        let known: Vec<SocketAddr> = ranked
            .iter()
            .copied()
            .filter(|a| !seed_set.contains(a))
            .collect();

        let round = {
            let mgr = self.addresses.read().await;
            let anchors = mgr.anchor_addresses();
            let banned = |a: &SocketAddr| mgr.is_banned(*a);
            plan_recovery(
                self.config.listen_addr,
                count,
                &anchors,
                &known,
                &seeds,
                &connected,
                &banned,
                &ctl,
                now,
            )
        };

        if round.state != ctl.state {
            match round.state {
                RecoveryState::Healthy => {}
                RecoveryState::Recovering => info!(
                    "self-heal: peer_count {} < comfort {} (threshold {}, min {}) -> entering recovery, planning {} anchor / {} known / {} seed dial(s)",
                    count,
                    RECOVERY_COMFORT_PEERS,
                    RECOVERY_THRESHOLD,
                    RECOVERY_MIN_PEERS,
                    round.tier1_anchors,
                    round.tier2_known,
                    round.tier3_seeds,
                ),
                RecoveryState::Degraded => info!(
                    "self-heal: peer_count {} -> recovery throttled for {:?} ({} consecutive failed round(s))",
                    count,
                    ctl.backoff(),
                    ctl.consecutive_failures
                ),
                RecoveryState::Exhausted => warn!(
                    "self-heal: peer_count {} below threshold {} with no dialable source (or {} consecutive failed rounds) -> exhausted, probing every {:?}",
                    count,
                    RECOVERY_THRESHOLD,
                    ctl.consecutive_failures,
                    recovery_backoff(RECOVERY_MAX_LEVEL)
                ),
            }
        }
        self.recovery.write().await.set_state(round.state);

        if round.state != RecoveryState::Recovering {
            return round;
        }

        debug!(
            "self-heal: round of {} dial(s): {} anchor, {} known, {} seed; {} source(s) left",
            round.dial.len(),
            round.tier1_anchors,
            round.tier2_known,
            round.tier3_seeds,
            round.sources_left
        );
        for addr in &round.dial {
            self.connect_to_peer(*addr).await;
        }

        // Success is measured by the planned addresses that now hold a
        // session — not by the raw count, which a concurrent inbound
        // connection could move underneath us.
        let opened = {
            let guard = self.peers.read().await;
            round.dial.iter().filter(|a| guard.contains_key(*a)).count()
        };
        debug!(
            "self-heal: round opened {} of {} planned session(s)",
            opened,
            round.dial.len()
        );
        self.recovery
            .write()
            .await
            .record_round(opened, Instant::now());
        round
    }

    /// Phase 2A candidate ordering for the redial loop: addresses the node
    /// already knows come first, configured seeds are ordinary unprivileged
    /// fallbacks appended at the end. No seed is ever allowed to outrank a peer
    /// the node already holds, so a dead seed cannot monopolise the cycle.
    fn redial_candidates(
        known: &[SocketAddr],
        seeds: &[SocketAddr],
        local: SocketAddr,
    ) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = known.iter().copied().filter(|a| *a != local).collect();
        for seed in seeds {
            if *seed != local && !out.contains(seed) {
                out.push(*seed);
            }
        }
        out
    }

    /// Phase 2C: one round of outbound candidates, ready to dial.
    ///
    /// This is the single production entry point that replaces the raw
    /// `redial_candidates` list in every redial path. `redial_candidates` still
    /// builds the order (Phase-2A invariant: known addresses before configured
    /// seeds), but the round itself is now bounded, reputation-weighted and
    /// network-group aware, so a store that an attacker has filled with one
    /// routable allocation can no longer decide who the node talks to.
    ///
    /// Lock discipline: the session table is snapshotted and released *before*
    /// the address manager is acquired, so `peers` and `addresses` are never
    /// held at the same time.
    async fn outbound_candidates(&self, limit: usize) -> Vec<SocketAddr> {
        let connected: HashSet<SocketAddr> = {
            let guard = self.peers.read().await;
            guard.keys().copied().collect()
        };

        let local = self.config.listen_addr;
        let seeds = self.config.bootnodes.clone();

        let picked = {
            let mgr = self.addresses.read().await;
            // 4CE hygiene: never-successful entries past the failure threshold
            // sit out of redial (their dials have never completed). Configured
            // seeds are exempt by config membership (a seed dialed once carries
            // source Outbound, so source alone cannot exempt it); everything
            // else still flows to the unchanged group-aware selection below.
            let seed_set: HashSet<SocketAddr> = seeds.iter().copied().collect();
            let known: Vec<SocketAddr> = mgr
                .addresses()
                .into_iter()
                .filter(|a| seed_set.contains(a) || !mgr.redial_sleep(a))
                .collect();
            let ordered = Self::redial_candidates(&known, &seeds, local);
            // Everything `redial_candidates` appended sits behind the known
  // half; that exact tail  -  not "is this a configured seed"  -  is what
            // phase 2 of the selection preserves.
            let known_len = known.iter().filter(|a| **a != local).count();
            let seed_tail: HashSet<SocketAddr> =
                ordered.iter().skip(known_len).copied().collect();

            let (entries, scores) = mgr.selection_tables();
            let mut rng = StdRng::from_entropy();
            let picked = select_outbound(
                &ordered,
                &seed_tail,
                entries,
                scores,
                &connected,
                limit,
                unix_now(),
                &mut rng,
            );
            debug!(
                "Outbound round: {} of {} ordered candidates over {} network groups",
                picked.len(),
                ordered.len(),
                group_counts(picked.iter().copied()).len()
            );
            picked
        };

        picked
    }

    /// Start the general redial task (Phase 1: known peers + seeds, Phase 2A: seeds unprivileged).
    async fn start_reconnection_task(&self) {
        let peers = self.peers.clone();
        let p2p_network = self.clone();

        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            let mut retry_counts: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            let mut next_attempt: std::collections::HashMap<String, Instant> =
                std::collections::HashMap::new();
            loop {
                // Phase 2C: the round is drawn by the group-aware selection, so
                // a store dominated by one attacker-controlled group cannot
                // occupy the whole budget cycle after cycle.
                let candidates = p2p_network.outbound_candidates(MAX_REDIAL_PER_CYCLE).await;

                let now = Instant::now();
                let mut dials = 0usize;

                for target in candidates {
                    if dials >= MAX_REDIAL_PER_CYCLE {
                        break;
                    }
                    let key = target.to_string();

                    if peers.read().await.contains_key(&target) {
                        retry_counts.remove(&key);
                        next_attempt.remove(&key);
                        continue;
                    }

                    // Exponential backoff is tracked per candidate instead of
                    // sleeping inside the loop. Phase 1 slept here, so one
                    // black-holed seed delayed every other candidate behind it.
                    if let Some(due) = next_attempt.get(&key) {
                        if now < *due {
                            continue;
                        }
                    }

                    let attempt = *retry_counts.get(&key).unwrap_or(&0);
                    let backoff = std::cmp::min(2u64.pow(attempt.min(6)), 60); // Max 60s
                    debug!(
                        "Redial candidate {} (attempt {}, backoff {}s)",
                        target,
                        attempt + 1,
                        backoff
                    );

                    p2p_network.connect_to_peer(target).await;
                    dials += 1;

                    retry_counts.insert(key.clone(), std::cmp::min(attempt + 1, 6));
                    next_attempt.insert(key, Instant::now() + Duration::from_secs(backoff));
                }

                // 2E-A (A.2 iii): bounded jitter on the redial cycle. The
                // dial budget, backoff and candidate selection above are
                // untouched; only this sleep is randomised, never below 5s.
                tokio::time::sleep(Self::jittered_interval(
                    Duration::from_secs(5),
                    REDIAL_INTERVAL_JITTER,
                    rand::random::<u64>(),
                ))
                .await;
            }
        });
    }

    /// Start cache cleanup task to evict old seen transactions
    async fn start_cache_cleanup(&self) {
        let seen_transactions = self.seen_transactions.clone();
        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let now = Instant::now();
                let mut seen = seen_transactions.write().await;
                let before = seen.len();
                seen.retain(|_, entry| {
                    now.duration_since(entry.timestamp) < Duration::from_secs(3600)
                });
                let after = seen.len();
                if before != after {
                    debug!(
                        "Cache cleanup: removed {} entries ({} -> {})",
                        before - after,
                        before,
                        after
                    );
                }
            }
        });
    }

    /// Resolve DNS seeds to peer addresses
    async fn discover_from_dns(&self) {
        let dns_seeds = self.config.dns_seeds.clone();
        let default_port = self.config.listen_addr.port();
        let p2p = self.clone();

        // 4CB: tracked (was detached); one-shot resolve.
        self.spawn_tracked(async move {
                for seed in &dns_seeds {
                    match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                        Ok(addrs) => {
                            let addrs: Vec<SocketAddr> = addrs.collect();
                            info!("🌐 DNS seed {} resolved to {} addresses", seed, addrs.len());
                            for addr in &addrs {
                                let ok = ingress_address(
                                    &p2p.addresses,
                                    &p2p.peers,
                                    p2p.config.listen_addr,
                                    *addr,
                                    PeerSource::Dns,
                                )
                                .await;
                                if !ok {
                                    continue;
                                }
                                if !p2p.is_connected(*addr).await {
                                    p2p.connect_to_peer(*addr).await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("⚠️ DNS seed {} resolution failed: {}", seed, e);
                        }
                    }
                }
        });
    }

    /// Periodically re-resolve DNS seeds to discover new peers
    async fn start_dns_discovery(&self) {
        let dns_seeds = self.config.dns_seeds.clone();
        let default_port = self.config.listen_addr.port();
        let p2p = self.clone();

        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(120)).await; // Every 2 minutes
                for seed in &dns_seeds {
                    match tokio::net::lookup_host(format!("{}:{}", seed, default_port)).await {
                        Ok(addrs) => {
                            for addr in addrs {
                                let ok = ingress_address(
                                    &p2p.addresses,
                                    &p2p.peers,
                                    p2p.config.listen_addr,
                                    addr,
                                    PeerSource::Dns,
                                )
                                .await;
                                if ok && !p2p.is_connected(addr).await {
                                    // 4CP-AA (X-4): track the child dial so it is
                                    // aborted+awaited by `shutdown()` like the
                                    // discovery loop that spawns it, instead of
                                    // being detached. A closed cycle refuses the
                                    // spawn outright, so no dial outlives teardown.
                                    let dialer = p2p.clone();
                                    p2p.spawn_tracked(async move {
                                        dialer.connect_to_peer(addr).await;
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            debug!("DNS seed {} re-resolution failed: {}", seed, e);
                        }
                    }
                }
            }
        });
    }

    /// Phase 2A: addresses eligible for a PEX broadcast. We never re-share an
    /// address we ourselves banned, and never send our own listen address.
    /// Extracted so the filter is unit-testable rather than buried in a loop.
    fn pex_broadcast_list(
        entries: &HashMap<SocketAddr, AddressEntry>,
        scores: &HashMap<SocketAddr, PeerScore>,
        local: SocketAddr,
    ) -> Vec<SocketAddr> {
        entries
            .keys()
            .copied()
            .filter(|a| *a != local)
            .filter(|a| !scores.get(a).map(|s| s.is_banned()).unwrap_or(false))
            .collect()
    }

    /// Periodically exchange peer addresses (PEX).
    ///
    /// Phase 2B (D5): every recipient now gets its own bounded sample instead
    /// of a verbatim copy of the whole known set (which used to be up to
    /// `MAX_KNOWN_PEERS` addresses every 15 seconds to every peer). The sample
    /// drops the recipient itself, anything that recipient taught us, banned or
    /// penalized entries and aged-out hints, and is capped at `PEX_MAX_SEND`.
    async fn start_pex(&self) {
        let peers = self.peers.clone();
        let addresses = self.addresses.clone();
        let local_addr = self.config.listen_addr;

        // 4CB: tracked (was detached).
        self.spawn_tracked(async move {
            loop {
                // 2E-A (A.2 ii): bounded jitter around the 15s baseline. The
                // exact period used to be a clean metronome a passive
                // observer could phase-lock onto; the sleep is now drawn from
                // [15s, 19s) — never faster, so traffic never increases.
                tokio::time::sleep(Self::jittered_interval(
                    PEX_INTERVAL,
                    PEX_INTERVAL_JITTER,
                    rand::random::<u64>(),
                ))
                .await;

                // Snapshot senders first and release, so no session lock is held
                // while the address manager is acquired.
                let targets: Vec<(SocketAddr, mpsc::UnboundedSender<Vec<u8>>)> = {
                    let guard = peers.read().await;
                    guard.iter().map(|(a, s)| (*a, s.clone())).collect()
                };
                if targets.is_empty() {
                    continue;
                }

                let now = unix_now();
                let mgr = addresses.read().await;

                for (recipient, sender) in &targets {
                    let list = mgr.sample_for_pex(local_addr, *recipient, now, PEX_MAX_SEND);
                    if list.is_empty() {
                        continue;
                    }
                    if let Ok(bytes) = bincode::serialize(&P2PMessage::Peers(list)) {
                        let _ = sender.send(bytes);
                    }
                }
            }
        });
    }

    /// Check if a peer address is currently connected
    async fn is_connected(&self, addr: SocketAddr) -> bool {
        self.peers.read().await.contains_key(&addr)
    }

    /// Accept loop for incoming connections
    async fn accept_loop(
        listener: TransportListener,
        peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        local_addr: SocketAddr,
        addresses: Arc<RwLock<AddressManager>>,
        outbound_sessions: Arc<RwLock<HashSet<SocketAddr>>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        propagation_state: Arc<RwLock<PropagationState>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
  stake_hooks: StakeHooks,
  network_id: u64,
        // PHASE 4CP: handshake selection + identity + verified session state.
        protocol_mode: P2PProtocolMode,
        node_identity: Option<Arc<crate::node_identity::NodeIdentity>>,
        session_auth: Arc<RwLock<SessionAuthRegistry>>,
        session_seq: Arc<AtomicU64>,
        // 4CP-W: atomic task admission for per-peer session tasks. Replaces the
        // former separate `tasks` registry + `shutdown` flag, whose
        // check-then-push let a session task escape teardown.
        admission: Arc<std::sync::Mutex<TaskAdmission>>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, endpoint)) => {
                    // 2E-B BOUNDARY: the session table, the address book,
                    // `sync_stats` and the PEX wire all key on `SocketAddr`.
                    // `PeerAddr` stops here — an endpoint this build cannot
                    // express as an IP is dropped, never coerced into one.
                    let addr = match endpoint.as_socket_addr() {
                        Some(addr) => addr,
                        None => {
                            error!(
                                "Dropping inbound connection: endpoint {} is not IP-addressable",
                                endpoint
                            );
                            continue;
                        }
                    };
                    // Phase 2C / scenario A: `PROTECTED_OUTBOUND_SLOTS` is read
                    // on its own so the direction map and the session map are
                    // never held at the same time.
                    let outbound = outbound_sessions.read().await.len();
                    {
                        let peers_guard = peers.read().await;
                        let total = peers_guard.len();
                        // Without this a client that opened MAX_PEERS
                        // connections used to leave the node with zero
                        // capacity for outbound dials: it kept gossiping while
                        // being unable to initiate a single session.
                        if !inbound_admitted(total, outbound) {
                            warn!(
                                "Rejecting incoming peer {}: {} inbound of {} usable, {} outbound slot(s) reserved",
                                addr,
                                total.saturating_sub(outbound),
                                MAX_PEERS.saturating_sub(PROTECTED_OUTBOUND_SLOTS),
                                PROTECTED_OUTBOUND_SLOTS
                            );
                            drop(stream);
                            continue;
                        }
                        // ECLIPSE-01: enforce /24 subnet diversity
                        let subnet_count = count_subnet_peers_excluding(addr, &peers_guard).await;
                        if subnet_count >= MAX_PEERS_PER_SUBNET {
                            warn!(
                                "Rejecting incoming peer {}: /24 subnet limit reached ({}/{})",
                                addr, subnet_count, MAX_PEERS_PER_SUBNET
                            );
                            drop(stream);
                            continue;
                        }
                    }
                    // SCORING: check if peer is banned
                    {
                        let mut mgr = addresses.write().await;
                        mgr.decay_score(addr);
                        if mgr.is_banned(addr) {
                            warn!(
                                "Rejecting banned peer {}: banned until {:?}",
                                addr,
                                mgr.banned_until(addr)
                            );
                            drop(stream);
                            continue;
                        }
                    }
                    info!("New peer connected: {}", addr);
                    let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                    {
                        let mut peers = peers.write().await;
                        peers.insert(addr, msg_sender.clone());
                    }

                    // Phase 2B (D7/D8): record how this address was learned and
                    // admit it through the quality-aware path.
                    ingress_address(
                        &addresses,
                        &peers,
                        local_addr,
                        addr,
                        PeerSource::Inbound,
                    )
                    .await;

                    let peers_clone = peers.clone();
                    let tx_channel = tx_channel.clone();
                    let get_dag_hashes = Arc::clone(&get_dag_hashes);
                    let get_transaction_by_hash = Arc::clone(&get_transaction_by_hash);
                    let get_tips = Arc::clone(&get_tips);
                    let seen_transactions = Arc::clone(&seen_transactions);
                    let propagation_state = Arc::clone(&propagation_state);
                    let peer_discovery_tx = peer_discovery_tx.clone();
                    let addresses = addresses.clone();
                    let sync_ctx = Arc::clone(&sync_ctx);
                    let is_orphan = Arc::clone(&is_orphan);
  let stake_hooks = stake_hooks.clone();
                    // PHASE 4CP: inbound session -> this node is the responder.
                    let node_identity = node_identity.clone();
                    let session_auth = session_auth.clone();
                    let session_seq = session_seq.clone();
                    // 4CP-W: admit the session task and register its handle in
                    // ONE atomic step. If shutdown() has already closed the
                    // cycle, `admit_task` refuses (the future is never created,
                    // so the stream is dropped) and we unregister the peer we
                    // optimistically inserted. There is no separate
                    // check-then-spawn window any more.
                    let session_admission = admission.clone();
                    let admitted = Self::admit_task(&admission, |generation| async move {
                        Self::handle_peer(
                            stream,
                            addr,
                            peers_clone,
                            local_addr,
                            addresses,
                            tx_channel,
                            get_dag_hashes,
                            get_transaction_by_hash,
                            get_tips,
                            seen_transactions,
                            propagation_state,
                            msg_sender,
                            msg_receiver,
                            peer_discovery_tx,
                            sync_ctx,
                            is_orphan,
  stake_hooks,
  network_id,
                            protocol_mode,
                            node_identity,
                            false,
                            session_auth,
                            session_seq,
                            generation,
                            None,
                            session_admission,
                            HANDSHAKE_TIMEOUT,
                        )
                        .await;
                    });
                    if !admitted {
                        let mut peers_lock = peers.write().await;
                        peers_lock.remove(&addr);
                        continue;
                    }
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Build a 12-byte nonce: bytes[0..8] = u64 BE counter, byte[8] = direction
    /// (0x01 / 0x02 chosen from ephemeral public-key order so the two senders of
    /// one session never share a direction), bytes[9..12] = 0.
    /// Wire-compatible: the full 12 bytes are sent in clear before the ciphertext;
    /// the receiver decrypts with the wire nonce, so legacy peers (byte[8]=0)
    /// still interoperate while new↔new sessions never reuse (K, N).
    fn build_nonce(counter: u64, direction: u8) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        nonce[8] = direction;
        nonce
    }

    /// Deterministic send-direction byte from the two ephemeral handshake keys.
    /// Lower public key → 0x01, higher → 0x02 (equal keys are cryptographically
    /// negligible for random X25519 ephemerals; both would take 0x02 only then).
    fn send_direction(our_pk: &[u8], peer_pk: &[u8]) -> u8 {
        if our_pk < peer_pk {
            0x01
        } else {
            0x02
        }
    }

    /// H2: read exactly `buf.len()` bytes with an inactivity timeout, so a
    /// stalled or silent peer is disconnected instead of holding the task and
    /// socket forever. The timeout error surfaces as io::ErrorKind::TimedOut.
    async fn read_exact_timeout<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        buf: &mut [u8],
        budget: Duration,
    ) -> std::io::Result<()> {
        match tokio::time::timeout(budget, reader.read_exact(buf)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "P2P read timed out",
            )),
        }
    }

    /// 2E-A (A.3): the bytes actually written to / read from the socket for
    /// the handshake magic. Pure XOR with the public mask — an obfuscation of
    /// the ASCII signature, NOT an encryption and NOT anonymity.
    fn handshake_wire_magic() -> [u8; 4] {
        let mut m = [0u8; 4];
        for i in 0..4 {
            m[i] = HANDSHAKE_MAGIC[i] ^ HANDSHAKE_MAGIC_MASK[i];
        }
        m
    }

    /// H4/V-24: verify the network identity of a received handshake frame
    /// (magic + protocol version + genesis hash). Unit-testable pure check.
    ///
    /// 2E-A: compares against `handshake_wire_magic()`, so a v3 peer that
    /// still sends the literal "AETH" fails here with the magic error and is
    /// disconnected before it can send an unpadded frame.
    /// PHASE 4V: additionally checks the trailing network id against the
    /// node's expected network (exact match; 0 == 0 preserves legacy
    /// behavior). Different testnets on one binary share magic/version/
    /// genesis, so this field is the operative cross-network gate.
    fn verify_handshake_identity(
        incoming: &[u8],
        expected_network_id: u64,
    ) -> Result<(), &'static str> {
        if incoming.len() < HANDSHAKE_FRAME_LEN {
            return Err("Short P2P handshake frame");
        }
        if incoming[..4] != Self::handshake_wire_magic() {
  return Err("Invalid P2P handshake magic  -  not an Aether node");
        }
        if incoming[4] != P2P_PROTOCOL_VERSION {
  return Err("Incompatible P2P protocol version  -  upgrade the node");
        }
        if incoming[5..37] != crate::genesis::GENESIS_HASH {
            return Err("Network mismatch: peer genesis hash differs from ours");
        }
        let mut net = [0u8; 8];
        net.copy_from_slice(&incoming[37..45]);
        if u64::from_le_bytes(net) != expected_network_id {
            return Err("Network mismatch: peer network id differs from ours");
        }
        Ok(())
    }

    /// 2E-A (A.2 ii/iii): bounded, one-sided cadence jitter.
    ///
    /// `r` is any u64 (production passes `rand::random()`, tests pass a fixed
    /// value, so the function is deterministic and unit-testable). The result
    /// is always in `[base, base + max_jitter]` — never faster than the
    /// baseline, so jitter can never increase traffic or dial pressure, and
    /// never unbounded, so no sleep can grow without limit.
    fn jittered_interval(base: Duration, max_jitter: Duration, r: u64) -> Duration {
        let span = max_jitter.as_millis() as u64;
        if span == 0 {
            return base;
        }
        base + Duration::from_millis(r % (span + 1))
    }

    /// 2E-A (A.3): the only `total_len` values a v4 peer is allowed to send.
    /// A v3 frame's length is the raw message size and is virtually never a
    /// multiple of `FRAME_PAD_BUCKET`, so this is what rejects an unpadded
    /// (old) frame even if it somehow got past the handshake version check.
    fn valid_frame_len(total_len: usize) -> bool {
        total_len >= FRAME_PAD_BUCKET
            && total_len % FRAME_PAD_BUCKET == 0
            && total_len <= MAX_MESSAGE_SIZE
    }

    /// 2E-A (A.3): clear length this message will occupy on the wire once
    /// padded, or `None` when the message is too large to pad legally.
    /// Always a multiple of `FRAME_PAD_BUCKET`, always `>= FRAME_PAD_BUCKET`.
    fn padded_total_len(msg_len: usize) -> Option<usize> {
        // What the receiver's `total_len` covers without any padding:
        // nonce(12) + tag(16) + msg + pad-length tail(2).
        let unpadded = FRAME_FIXED_OVERHEAD.checked_add(msg_len)?;
        if unpadded > FRAME_MAX_EMIT {
            return None;
        }
        let padded = unpadded
            .checked_add(FRAME_PAD_BUCKET - 1)?
            .checked_div(FRAME_PAD_BUCKET)?
            .checked_mul(FRAME_PAD_BUCKET)?;
        // Rounding up can only cross FRAME_MAX_EMIT by < FRAME_PAD_BUCKET,
        // which the FRAME_MAX_EMIT headroom above already absorbed.
        if padded > MAX_MESSAGE_SIZE {
            return None;
        }
        Some(padded)
    }

    /// 2E-A (A.3): append zeros + a u16-LE pad length so the padded plaintext
    /// fills exactly one bucket. The tail lives INSIDE the AEAD plaintext, so
    /// the receiver learns the pad length only by decrypting first, and any
    /// third party that edits the padding breaks Poly1305 verification.
    ///
    /// Returns `None` for a message that cannot be padded under
    /// `MAX_MESSAGE_SIZE` (see `padded_total_len`).
    fn pad_message(msg: &[u8]) -> Option<Vec<u8>> {
        // Same base as padded_total_len: this is `total_len` before padding.
        let unpadded = FRAME_FIXED_OVERHEAD.checked_add(msg.len())?;
        if unpadded > FRAME_MAX_EMIT {
            return None;
        }
        let pad = (FRAME_PAD_BUCKET - (unpadded % FRAME_PAD_BUCKET)) % FRAME_PAD_BUCKET;
        debug_assert!(pad <= MAX_FRAME_PADDING);
        let mut out = Vec::with_capacity(unpadded + pad);
        out.extend_from_slice(msg);
        out.resize(msg.len() + pad, 0u8);
        out.extend_from_slice(&(pad as u16).to_le_bytes());
        Some(out)
    }

    /// Inverse of `pad_message`. Rejects a truncated, oversized or otherwise
    /// malformed tail instead of guessing.
    fn unpad_message(pt: &[u8]) -> Result<Vec<u8>, &'static str> {
        if pt.len() < FRAME_PAD_TAIL {
            return Err("Padded frame too short");
        }
        let tail = &pt[pt.len() - FRAME_PAD_TAIL..];
        let pad = u16::from_le_bytes([tail[0], tail[1]]) as usize;
        if pad > MAX_FRAME_PADDING {
            return Err("Frame padding exceeds bucket");
        }
        let body = pt.len() - FRAME_PAD_TAIL;
        if pad > body {
            return Err("Frame padding longer than body");
        }
        Ok(pt[..body - pad].to_vec())
    }

    /// 2E-A (A.2 i): bounded, rotating advertisement for a `SyncRequest`.
    ///
    /// The response used to be the ENTIRE DAG (`get_dag_hashes()` verbatim),
    /// so `total_len` alone told any passive observer the exact transaction
    /// count. It is now capped at `MAX_INV_ITEMS`.
    ///
    /// A plain `take(MAX_INV_ITEMS)` would be WRONG here: `get_dag_hashes()`
    /// iterates a `HashMap`, so its order is fixed for a given process — a
    /// fixed prefix would advertise the same 1000 hashes forever and a late
    /// joiner would never learn the rest (this exact failure shipped once in
    /// the Phase D live campaign, see the comment on the `Inventory` receive
    /// arm). The window therefore ROTATES: `cursor` advances by a full window
    /// per request, so consecutive windows are disjoint until they wrap and
    /// the whole set is advertised after `ceil(n / MAX_INV_ITEMS)` rounds.
    ///
    /// Convergence rate is unchanged: the receive side already caps its
    /// `GetData` at `MAX_INV_ITEMS` per round, so that cap — not this one —
    /// has always been the throughput limiter.
    fn inventory_window(all: &[Vec<u8>], cursor: &AtomicU64) -> Vec<Vec<u8>> {
        if all.len() <= MAX_INV_ITEMS {
            return all.to_vec();
        }
        let n = all.len();
        let start = (cursor.fetch_add(MAX_INV_ITEMS as u64, Ordering::Relaxed) as usize) % n;
        let mut out = Vec::with_capacity(MAX_INV_ITEMS);
        for i in 0..MAX_INV_ITEMS {
            out.push(all[(start + i) % n].clone());
        }
        out
    }

    /// Phase 1 crypto audit helper: a (key, nonce) collision requires equal
    /// counter AND equal direction byte under the same session key. After the
    /// direction-byte fix the two senders of one session always differ in
    /// direction, so equal counters no longer collide across directions.
    fn nonce_collision_possible(a_counter: u64, a_dir: u8, b_counter: u64, b_dir: u8) -> bool {
        a_counter == b_counter && a_dir == b_dir
    }

    /// Perform X25519 handshake, derive the session key (shared by both
    /// directions — ChaCha20 nonce uniqueness is enforced via the direction
    /// byte), and return (key, send_direction) for this side.
    /// PHASE 4V: advertises and checks `network_id` (exact match both ways;
    /// a legacy/foreign peer fails closed here, before any gossip).
    async fn handshake(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
        network_id: u64,
    ) -> Result<([u8; 32], u8), Box<dyn std::error::Error>> {
        let our_secret = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_secret);

        let mut outgoing = Vec::with_capacity(HANDSHAKE_FRAME_LEN);
        outgoing.extend_from_slice(&Self::handshake_wire_magic());
        outgoing.push(P2P_PROTOCOL_VERSION);
        outgoing.extend_from_slice(&crate::genesis::GENESIS_HASH);
        outgoing.extend_from_slice(&network_id.to_le_bytes());
        outgoing.extend_from_slice(our_public.as_bytes());
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&outgoing))
            .await
            .is_err()
        {
            return Err("P2P handshake write timed out".into());
        }

        let mut incoming = [0u8; HANDSHAKE_FRAME_LEN];
        Self::read_exact_timeout(reader, &mut incoming, HANDSHAKE_TIMEOUT)
            .await
            .map_err(|e| format!("P2P handshake read failed: {}", e))?;
        Self::verify_handshake_identity(&incoming, network_id)?;

        let mut peer_pk_bytes = [0u8; 32];
        peer_pk_bytes.copy_from_slice(&incoming[HANDSHAKE_FRAME_LEN - 32..]);
        let peer_public = PublicKey::from(peer_pk_bytes);
        let shared_secret = our_secret.diffie_hellman(&peer_public);
        // 4CP-S / F2: reject a non-contributory X25519 result (a low-order or
        // all-zero peer ephemeral forces the shared secret to a known value,
        // removing our contribution to the key). A conforming peer sends a
        // random ephemeral and is unaffected; only cryptographically invalid
        // exchanges are refused. Verified independently of any signature.
        if !shared_secret.was_contributory() {
            return Err("P2P handshake: non-contributory X25519 peer key rejected".into());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"aether-p2p-key-v1");
        hasher.update(shared_secret.as_bytes());
        let key_bytes = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&key_bytes);
        let send_dir = Self::send_direction(our_public.as_bytes(), &peer_pk_bytes);
        Ok((result, send_dir))
    }

    /// PHASE 4CP: build the canonical, role-ordered v6 transcript that both
    /// sides must agree on byte-for-byte.
    ///
    /// Layout:
    /// `domain | magic(4) | version(1) | genesis(32) | network(8 LE) |
    ///  init_tag(1) | init_eph(32) | init_nonce(32) | init_node(32) |
    ///  resp_tag(1) | resp_eph(32) | resp_nonce(32) | resp_node(32)`
    ///
    /// The initiator/responder split is fixed by the dial direction, so both
    /// ends compute the same bytes; a signature over it therefore covers the
    /// versions, magic, genesis, network id, BOTH ephemeral keys, BOTH nonces,
    /// BOTH identities and the roles.
    fn v6_transcript(network_id: u64, initiator: &V6Hello, responder: &V6Hello) -> Vec<u8> {
        let mut t = Vec::with_capacity(
            V6_AUTH_DOMAIN.len() + 4 + 1 + 32 + 8 + 1 + 32 + 32 + 32 + 1 + 32 + 32 + 32,
        );
        t.extend_from_slice(V6_AUTH_DOMAIN);
        t.extend_from_slice(&Self::handshake_wire_magic());
        t.push(P2P_PROTOCOL_VERSION_V6);
        t.extend_from_slice(&crate::genesis::GENESIS_HASH);
        t.extend_from_slice(&network_id.to_le_bytes());
        t.push(V6_ROLE_INITIATOR);
        t.extend_from_slice(&initiator.eph);
        t.extend_from_slice(&initiator.nonce);
        t.extend_from_slice(&initiator.node_id);
        t.push(V6_ROLE_RESPONDER);
        t.extend_from_slice(&responder.eph);
        t.extend_from_slice(&responder.nonce);
        t.extend_from_slice(&responder.node_id);
        t
    }

    /// PHASE 4CP: the exact bytes each side signs. Binding the signer's role
    /// (not just the symmetric transcript) is what makes a reflected signature
    /// useless: the peer would have to sign the OPPOSITE role's message.
    fn v6_signed_message(role: u8, transcript: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(V6_AUTH_DOMAIN.len() + 1 + transcript.len());
        m.extend_from_slice(V6_AUTH_DOMAIN);
        m.push(role);
        m.extend_from_slice(transcript);
        m
    }

    /// PHASE 4CP: authenticated v6 handshake.
    ///
    /// Symmetric two-step exchange: Hello (magic/version/genesis/network/
    /// ephemeral/nonce/node id) each way, then an Ed25519 signature over the
    /// role-bound transcript. The session key is domain-separated from v5 and
    /// bound to the transcript. Returns
    /// `(session_key, send_direction, peer_node_id)`.
    ///
    /// No fallback of any kind: any mismatch, malformed frame, truncated read,
    /// timeout or invalid signature is an error that ends the session.
    ///
    /// 4CP-AC (4CPT-07): the whole negotiation runs under ONE global budget
    /// (`HANDSHAKE_TIMEOUT` in production), enforced via
    /// `handshake_v6_with_budget`. A slow peer can no longer spend a fresh full
    /// timeout at each step.
    /// 4CP-AC: production reaches the handshake through
    /// `handshake_v6_with_budget` (from `handle_peer`, with `HANDSHAKE_TIMEOUT`);
    /// this convenience wrapper (always `HANDSHAKE_TIMEOUT`) is used by the
    /// contract tests that do not exercise a custom budget.
    #[cfg(test)]
    async fn handshake_v6(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
        network_id: u64,
        identity: &crate::node_identity::NodeIdentity,
        is_initiator: bool,
    ) -> Result<([u8; 32], u8, crate::node_identity::NodeId), Box<dyn std::error::Error>> {
        Self::handshake_v6_with_budget(
            reader,
            writer,
            network_id,
            identity,
            is_initiator,
            HANDSHAKE_TIMEOUT,
        )
        .await
    }

    /// 4CP-AC (4CPT-07): run one v6 handshake I/O step under the SINGLE global
    /// deadline captured at handshake entry. `remaining` is recomputed from the
    /// absolute deadline on every call, so progress on an earlier step (a
    /// completed write, a partial read) never resets or extends the budget: a
    /// slow peer cannot spend a fresh full per-step timeout at each stage.
    ///
    /// Distinguishes the two failure classes: an I/O error (peer disconnected
    /// or malformed stream) surfaces as `... failed: <io error>`, while expiry
    /// of the shared budget surfaces as `... timeout during <step>`.
    async fn handshake_io<F, T>(
        deadline: tokio::time::Instant,
        what: &str,
        op: F,
    ) -> Result<T, Box<dyn std::error::Error>>
    where
        F: std::future::Future<Output = std::io::Result<T>>,
    {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, op).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(format!("P2P v6 handshake {} failed: {}", what, e).into()),
            Err(_) => Err(format!("P2P v6 handshake timeout during {}", what).into()),
        }
    }

    /// 4CP-AC (4CPT-07): the v6 handshake with an explicit GLOBAL budget.
    ///
    /// Production calls it with `HANDSHAKE_TIMEOUT`; tests call it with a short
    /// budget to prove a slow peer cannot cumulate several per-step timeouts.
    /// The whole negotiation — Hello write/flush, 5-byte prefix read, Hello
    /// rest read, signature write/flush and signature read — shares ONE
    /// absolute deadline armed here, at entry, so a peer that dribbles data
    /// step by step is bounded by the total, not by the slowest single read.
    async fn handshake_v6_with_budget(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
        network_id: u64,
        identity: &crate::node_identity::NodeIdentity,
        is_initiator: bool,
        budget: Duration,
    ) -> Result<([u8; 32], u8, crate::node_identity::NodeId), Box<dyn std::error::Error>> {
        use crate::node_identity::{verify_message, NodeId};

        // The one and only deadline for this handshake.
        let deadline = tokio::time::Instant::now() + budget;

        let our_secret = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_secret);
        let mut our_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut our_nonce);
        let our_node_id = identity.node_id();
        let ours = V6Hello {
            eph: *our_public.as_bytes(),
            nonce: our_nonce,
            node_id: *our_node_id.as_bytes(),
        };

        // --- Step A: Hello ---
        let mut outgoing = Vec::with_capacity(V6_HELLO_LEN);
        outgoing.extend_from_slice(&Self::handshake_wire_magic());
        outgoing.push(P2P_PROTOCOL_VERSION_V6);
        outgoing.extend_from_slice(&crate::genesis::GENESIS_HASH);
        outgoing.extend_from_slice(&network_id.to_le_bytes());
        outgoing.extend_from_slice(&ours.eph);
        outgoing.extend_from_slice(&ours.nonce);
        outgoing.extend_from_slice(&ours.node_id);
        debug_assert_eq!(outgoing.len(), V6_HELLO_LEN);
        Self::handshake_io(deadline, "Hello write", writer.write_all(&outgoing)).await?;
        Self::handshake_io(deadline, "Hello flush", writer.flush()).await?;

        // 4CP-S / F7: read the fixed 5-byte prefix (magic + version) first, so
        // an incompatible peer is rejected immediately instead of waiting the
        // whole Hello budget for 136 bytes it will never send. Only the v6 read
        // path changes; the channel is still cleartext, so no encrypted byte is
        // consumed. Magic and version remain strictly checked.
        //
        // 4CP-AC: the prefix read and the rest read draw on the SAME deadline
        // armed above, so the fast-reject behaviour is preserved without giving
        // the peer a second full budget after the prefix.
        let mut incoming = [0u8; V6_HELLO_LEN];
        Self::handshake_io(
            deadline,
            "Hello prefix read",
            reader.read_exact(&mut incoming[..5]),
        )
        .await?;
        if incoming[..4] != Self::handshake_wire_magic() {
            return Err("P2P v6 handshake: invalid magic (not an Aether node)".into());
        }
        if incoming[4] != P2P_PROTOCOL_VERSION_V6 {
            return Err(format!(
                "P2P v6 handshake: peer protocol version {} is not v{}",
                incoming[4], P2P_PROTOCOL_VERSION_V6
            )
            .into());
        }
        Self::handshake_io(deadline, "Hello read", reader.read_exact(&mut incoming[5..])).await?;

        if incoming[5..37] != crate::genesis::GENESIS_HASH {
            return Err("P2P v6 handshake: peer genesis hash differs from ours".into());
        }
        let mut net = [0u8; 8];
        net.copy_from_slice(&incoming[37..45]);
        if u64::from_le_bytes(net) != network_id {
            return Err("P2P v6 handshake: peer network id differs from ours".into());
        }
        let mut peer = V6Hello {
            eph: [0u8; 32],
            nonce: [0u8; 32],
            node_id: [0u8; 32],
        };
        peer.eph.copy_from_slice(&incoming[45..77]);
        peer.nonce.copy_from_slice(&incoming[77..109]);
        peer.node_id.copy_from_slice(&incoming[109..141]);
        let peer_node_id = NodeId::from_bytes(peer.node_id);

        // --- Step B: transcript + signatures ---
        let (initiator, responder) = if is_initiator {
            (&ours, &peer)
        } else {
            (&peer, &ours)
        };
        let transcript = Self::v6_transcript(network_id, initiator, responder);
        let our_role = if is_initiator {
            V6_ROLE_INITIATOR
        } else {
            V6_ROLE_RESPONDER
        };
        let peer_role = if is_initiator {
            V6_ROLE_RESPONDER
        } else {
            V6_ROLE_INITIATOR
        };

        let our_sig = identity.sign_message(&Self::v6_signed_message(our_role, &transcript));
        Self::handshake_io(deadline, "signature write", writer.write_all(&our_sig)).await?;
        Self::handshake_io(deadline, "signature flush", writer.flush()).await?;

        let mut peer_sig = [0u8; V6_SIG_LEN];
        Self::handshake_io(
            deadline,
            "signature read",
            reader.read_exact(&mut peer_sig),
        )
        .await?;

        let peer_message = Self::v6_signed_message(peer_role, &transcript);
        if !verify_message(&peer_node_id, &peer_message, &peer_sig) {
            return Err(format!(
                "P2P v6 handshake: invalid Ed25519 signature for peer {}",
                peer_node_id
            )
            .into());
        }

        // --- Session key: domain-separated from v5 and bound to the transcript ---
        let peer_public = PublicKey::from(peer.eph);
        let shared_secret = our_secret.diffie_hellman(&peer_public);
        // 4CP-S / F2: reject a non-contributory X25519 result. This is checked
        // independently of the Ed25519 signature: a valid identity can still
        // sign a transcript carrying a low-order ephemeral, so the signature is
        // NOT a substitute for this check.
        if !shared_secret.was_contributory() {
            return Err("P2P v6 handshake: non-contributory X25519 peer key rejected".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(V6_KEY_DOMAIN);
        hasher.update(shared_secret.as_bytes());
        hasher.update(Sha256::digest(&transcript));
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        let send_dir = Self::send_direction(our_public.as_bytes(), &peer.eph);
        Ok((key, send_dir, peer_node_id))
    }

    /// Handle a peer connection
    async fn handle_peer(
        stream: TransportStream,
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
        local_addr: SocketAddr,
        addresses: Arc<RwLock<AddressManager>>,
        tx_channel: mpsc::UnboundedSender<Transaction>,
        get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        get_transaction_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync>,
        get_tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
        seen_transactions: Arc<RwLock<HashMap<Vec<u8>, SeenTxEntry>>>,
        propagation_state: Arc<RwLock<PropagationState>>,
        msg_sender: mpsc::UnboundedSender<Vec<u8>>,
        msg_receiver: mpsc::UnboundedReceiver<Vec<u8>>,
        peer_discovery_tx: mpsc::UnboundedSender<SocketAddr>,
        sync_ctx: Arc<SyncContext>,
        is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
  stake_hooks: StakeHooks,
  network_id: u64,
        // PHASE 4CP: handshake selection + identity + verified session state.
        protocol_mode: P2PProtocolMode,
        node_identity: Option<Arc<crate::node_identity::NodeIdentity>>,
        is_initiator: bool,
        session_auth: Arc<RwLock<SessionAuthRegistry>>,
        session_seq: Arc<AtomicU64>,
        // 4CP-W: the network cycle this session was admitted into. Every
        // record/clear below is refused if the registry has moved on (cycle
        // closed, or a newer generation started).
        generation: u64,
        // 4CP-Y (tests): a rendezvous installed only by a test that drives a
        // real `handle_peer` against a concurrent `shutdown()`. `None` on every
        // production path.
        record_gate: Option<Arc<StartGate>>,
        // 4CP-AA (X-4): the cycle's admission control, so the per-session send
        // task is registered in the SAME set `shutdown()` aborts+awaits rather
        // than being left detached. A refused admission (cycle already closed)
        // simply drops the send half without creating a task.
        admission: Arc<std::sync::Mutex<TaskAdmission>>,
        // 4CP-AC (4CPT-07): the GLOBAL budget for the v6 handshake this session
        // will run. Production passes `HANDSHAKE_TIMEOUT`; tests pass a short
        // one to prove the total (not per-step) bound and the teardown on
        // expiry. The v5 path ignores it (its historical timeouts are unchanged).
        handshake_budget: Duration,
    ) {
        let _ = &record_gate;
        // 4CP-S: this session's unique id. Every record/clear below is keyed by
        // it, never by `addr` — two live sessions can share one endpoint.
        let session_id = session_seq.fetch_add(1, Ordering::Relaxed);
        // Split stream into read and write halves (both owned, so the write
        // half can be moved into the send task below).
        let (mut reader, mut writer) = stream.into_split();

        // PHASE 4CP: perform the configured handshake. `AuthenticatedV6`
        // requires a node identity and NEVER falls back to v5; a legacy peer
        // (or any error) simply fails the session. The legacy path keeps the
        // historical 77-byte v5 handshake untouched.
        let handshake_result = match protocol_mode {
            P2PProtocolMode::LegacyV5 => Self::handshake(&mut reader, &mut writer, network_id)
                .await
                .map(|(k, d)| (k, d, None))
                .map_err(|e| e.to_string()),
            P2PProtocolMode::AuthenticatedV6 => match node_identity.as_ref() {
                Some(identity) => Self::handshake_v6_with_budget(
                    &mut reader,
                    &mut writer,
                    network_id,
                    identity,
                    is_initiator,
                    handshake_budget,
                )
                .await
                .map(|(k, d, nid)| (k, d, Some(nid)))
                .map_err(|e| e.to_string()),
                None => Err(
                    "P2P v6 mode requires a node identity; refusing to fall back to v5".to_string(),
                ),
            },
        };

        let (key_bytes, send_dir, peer_node_id) = match handshake_result {
            Ok(k) => {
                info!(
                    "🔐 P2P handshake complete with {} (mode={:?})",
                    addr, protocol_mode
                );
                k
            }
            Err(msg) => {
                warn!("❌ P2P handshake failed with {}: {}", addr, msg);
                {
                    let mut peers_lock = peers.write().await;
                    peers_lock.remove(&addr);
                }
                // 4CP-S: a failed handshake records NO session state at all —
                // there is nothing to clear later, and a later reconnect gets a
                // fresh id with no inherited provenance. The session id itself
                // is never reused, so no stale entry can alias this one.
                // Phase 1: do NOT drop the address from known_peers on a failed
                // handshake — keep it for a later redial attempt. Stamping the
                // TTL clock here is what keeps it alive to be retried.
                addresses.write().await.touch(addr, Instant::now());
                return;
            }
        };
        // 4CP-Y (tests): park a real session at the exact point just before its
        // registration, so a test can close the cycle and prove the late record
        // is refused on the production code path.
        #[cfg(test)]
        {
            if let Some(gate) = record_gate.as_ref() {
                gate.arrived.notify_one();
                gate.release.notified().await;
            }
        }
        // PHASE 4CP + 4CP-W: record the verified provenance of this session,
        // under its exact id — but ONLY if this cycle's registry is still open
        // and still ours. A legacy session is explicitly unauthenticated; only
        // a verified v6 signature yields `Authenticated`. A handshake that
        // reached this point after `shutdown()` closed the cycle (or after a
        // newer generation started) is refused and torn down here: no residual
        // session, no half-open peer.
        let recorded = session_auth.write().await.record_if_active(
            generation,
            session_id,
            addr,
            Self::session_auth_for(peer_node_id),
        );
        if !recorded {
            let mut peers_lock = peers.write().await;
            peers_lock.remove(&addr);
            return;
        }
        // Phase 2B: the encrypted handshake completed, so this address is a
        // proven reachable peer — the input to `Recent` categorisation and to
        // anchor candidacy.
        {
            let mut mgr = addresses.write().await;
            mgr.record_success(addr, unix_now());
        }
        let key_enc = Arc::new(key_bytes);
        let key_dec = Arc::clone(&key_enc);

        // Spawn task to handle outgoing messages (encrypted)
        let mut msg_receiver = msg_receiver;
        let send_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let send_counter_clone = Arc::clone(&send_counter);
        let send_dir_task = send_dir;
        // 4CP-AA (X-4): the send task owns the socket's write half, so it must
        // stop with the cycle. Register it through the SAME admission control
        // as every other tracked task, so `shutdown()` aborts AND awaits it
        // instead of leaving a detached writer behind. If the cycle is already
        // closed (shutdown won the race), `admit_task` refuses without calling
        // the closure, and the captured `writer`/`msg_receiver` are dropped —
        // the socket is released and no task is created.
        let send_admission = Arc::clone(&admission);
        let _ = Self::admit_task(&send_admission, move |_generation| async move {
            while let Some(msg) = msg_receiver.recv().await {
                let cipher = {
                    let key = Key::from_slice(key_enc.as_ref());
                    ChaCha20Poly1305::new(key)
                };
                // 2E-A (A.3): pad the plaintext up to a bucket BEFORE
                // encrypting, so the clear `total_len` reveals only the
                // bucket. The pad length travels inside the AEAD, so it is
                // authenticated and invisible until decryption.
                let padded = match Self::pad_message(msg.as_ref()) {
                    Some(p) => p,
                    None => {
                        // Unreachable for any realistic message: the ceiling
                        // is one bucket below the 16 MiB receiver bound.
                        warn!(
                            "Dropping message of {} bytes to {}: exceeds padded frame limit",
                            msg.len(),
                            addr
                        );
                        continue;
                    }
                };
                let nonce_val =
                    send_counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let nonce_bytes = Self::build_nonce(nonce_val, send_dir_task);
                let nonce = Nonce::from_slice(&nonce_bytes);
                match cipher.encrypt(nonce, padded.as_ref()) {
                    Ok(ciphertext) => {
                        let total_len = 12 + ciphertext.len();
                        debug_assert_eq!(
                            total_len % FRAME_PAD_BUCKET,
                            0,
                            "every emitted frame must land on a bucket"
                        );
                        debug_assert_eq!(
                            Some(total_len),
                            Self::padded_total_len(msg.len()),
                            "padded frame length must match the declared layout"
                        );
                        // 4CP-Y (X-4): bound every write. A peer that stops
                        // reading would otherwise pin this detached task (and
                        // its write half) forever; on timeout the task ends and
                        // the socket is released.
                        let write = tokio::time::timeout(SESSION_WRITE_TIMEOUT, async {
                            writer
                                .write_all(&(total_len as u32).to_be_bytes())
                                .await?;
                            writer.write_all(nonce).await?;
                            writer.write_all(&ciphertext).await
                        })
                        .await;
                        match write {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => break,
                            Err(_) => {
                                warn!(
                                    "Dropping session with {}: write timed out after {:?}",
                                    addr, SESSION_WRITE_TIMEOUT
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Encryption failed for {}: {:?}", addr, e);
                        break;
                    }
                }
            }
        });

        // Send GetInventory with tips on connection
        let our_tips = get_tips();
        if let Ok(getinv_msg) = bincode::serialize(&P2PMessage::GetInventory {
            tips: our_tips.clone(),
        }) {
            info!(
                "[Sync] Sending GetInventory with {} tips to {}",
                our_tips.len(),
                addr
            );
            let _ = msg_sender.send(getinv_msg);
        }

        // Also request the full inventory: tip-based sync can miss unconfirmed
        // (weight-0) tips, so fetch the peer's complete hash set to reconcile.
        if let Ok(sync_req) = bincode::serialize(&P2PMessage::SyncRequest) {
            let _ = msg_sender.send(sync_req);
        }

        // Mark peer as known (Phase 1: refresh TTL clock too)
        {
            let mut mgr = addresses.write().await;
            mgr.observe(addr, PeerSource::Restored, unix_now(), Instant::now());
        }

        let mut msg_count: u64 = 0;
        let mut window_start = Instant::now();
        // Anti-replay: peer send counters are strictly increasing over TCP;
        // reject any frame whose counter does not advance past the last one.
        let mut last_recv_counter: u64 = 0;

        loop {
            // Read encrypted message length (4 bytes)
            // H2: inactivity timeout so a peer that stops mid-stream is
            // disconnected instead of holding the task + socket forever.
            let mut len_buf = [0u8; 4];
            match Self::read_exact_timeout(&mut reader, &mut len_buf, FRAME_TIMEOUT).await {
                Ok(()) => {}
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        warn!(
                            "Peer {} idle for {:?}, disconnecting (frame timeout)",
                            addr, FRAME_TIMEOUT
                        );
                    } else {
                        warn!("Peer {} disconnected: {}", addr, e);
                    }
                    break;
                }
            }

            // Per-second rate limit: count every frame BEFORE decrypt/alloc
            let now = Instant::now();
            if now.duration_since(window_start) >= Duration::from_secs(1) {
                window_start = now;
                msg_count = 0;
            }
            msg_count += 1;
            if msg_count > MAX_MSGS_PER_SEC {
                warn!(
                    "Peer {} exceeded message rate limit ({} msgs/s), disconnecting",
                    addr, MAX_MSGS_PER_SEC
                );
                // SCORING: penalize flood
                {
                    let mut mgr = addresses.write().await;
                    if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_FLOOD) {
                        warn!("Peer {} banned (flood, score={})", addr, score);
                    }
                }
                break;
            }

            let total_len = u32::from_be_bytes(len_buf) as usize;
            if total_len > MAX_MESSAGE_SIZE {
                warn!(
                    "Peer {} sent oversized message ({} bytes > {}), disconnecting",
                    addr, total_len, MAX_MESSAGE_SIZE
                );
                break;
            }
            // 2E-A (A.3): every v4 frame is bucket-aligned and at least one
            // bucket long. A v3 peer (or a forger) sending a raw, unpadded
            // length is rejected here — second layer behind the handshake
            // version check, and the guarantee that `total_len` never leaks an
            // exact message size.
            if !Self::valid_frame_len(total_len) {
                warn!(
                    "Peer {} sent non-padded frame length {} (must be a multiple of {}), disconnecting",
                    addr, total_len, FRAME_PAD_BUCKET
                );
                break;
            }

            // Read nonce (12 bytes)
            let mut nonce_buf = [0u8; 12];
            if Self::read_exact_timeout(&mut reader, &mut nonce_buf, FRAME_TIMEOUT)
                .await
                .is_err()
            {
                warn!("Failed to read nonce from {}", addr);
                break;
            }

            // Anti-replay: counters must strictly increase for this session
            // (TCP preserves order, so a repeat or regression is a replay/forgery).
            let recv_counter = u64::from_be_bytes(nonce_buf[0..8].try_into().unwrap());
            if recv_counter <= last_recv_counter {
                warn!(
                    "Replay/regressed nonce from {} (counter {} <= {}), disconnecting",
                    addr, recv_counter, last_recv_counter
                );
                {
                    let mut mgr = addresses.write().await;
                    if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                        warn!("Peer {} banned (replay, score={})", addr, score);
                    }
                }
                break;
            }
            last_recv_counter = recv_counter;

            // Read ciphertext
            let ciphertext_len = total_len - 12;
            let mut ciphertext = vec![0u8; ciphertext_len];
            if Self::read_exact_timeout(&mut reader, &mut ciphertext, FRAME_TIMEOUT)
                .await
                .is_err()
            {
                warn!("Failed to read ciphertext from {}", addr);
                break;
            }

            // Decrypt
            let cipher = {
                let key = Key::from_slice(key_dec.as_ref());
                ChaCha20Poly1305::new(key)
            };
            let nonce = Nonce::from_slice(&nonce_buf);
            let plaintext = match cipher.decrypt(nonce, ciphertext.as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Decryption failed for {}: {:?}", addr, e);
                    // SCORING: penalize invalid message
                    {
                        let mut mgr = addresses.write().await;
                        if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                            warn!("Peer {} banned (invalid msg, score={})", addr, score);
                        }
                    }
                    break;
                }
            };

            // 2E-A (A.3): strip the authenticated padding. Done AFTER
            // decryption on purpose — the pad length only exists inside the
            // AEAD plaintext, and a malformed tail is a protocol violation
            // (penalised like any other invalid message), not a parse guess.
            let plaintext = match Self::unpad_message(&plaintext) {
                Ok(p) => p,
                Err(reason) => {
                    warn!("Peer {} sent malformed frame padding: {}", addr, reason);
                    {
                        let mut mgr = addresses.write().await;
                        if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                            warn!("Peer {} banned (bad padding, score={})", addr, score);
                        }
                    }
                    break;
                }
            };

            // Deserialize message
            match bincode::deserialize::<P2PMessage>(&plaintext) {
                Ok(msg) => {
                    match msg {
                        P2PMessage::Transaction(tx_bytes) => {
  // 2E-D (sec.2.9): this arm is now receive → dedup →
                            // record upstream peer → queue, and NOTHING else.
                            //
                            // The relay that used to live here ran *before*
                            // `validate_pure`, so it forwarded payloads the
                            // node would go on to reject, to every connected
                            // peer, in the same instant it received them —
                            // it was copy #1 of the per-link double relay.
                            // Aether relays from `broadcast_transaction`
                            // instead: after validation, once, to a bounded
                            // fan-out, behind a per-peer jitter.
                            //
                            // PHASE 3B (H1): this arm is the LIVE gossip path
                            // (single-tx relay of newly submitted txs). Record
                            // Fresh provenance BEFORE queueing so the node
                            // evaluates the tx under live policy end-to-end.
                            // Sync backfill (SyncResponse batches below)
                            // records Historical instead. First-delivery-wins:
                            // a duplicate arriving via the other path keeps
                            // the ORIGINAL mode. Insert-then-send ordering is
                            // load-bearing (see note_ingress_mode).
                            if let Ok(live_tx) =
                                bincode::deserialize::<Transaction>(&tx_bytes)
                            {
                                sync_ctx
                                    .note_ingress_mode(live_tx.id, ValidationMode::Fresh)
                                    .await;
                            }
                            if !accept_inbound_transaction(
                                tx_bytes,
                                addr,
                                &seen_transactions,
                                &propagation_state,
                                &tx_channel,
                            )
                            .await
                            {
                                continue;
                            }
                        }
                        P2PMessage::Inventory(hashes) => {
                            // Determine which hashes we need (bounded by MAX_INV_ITEMS).
                            // B4: dedup against the DAG AND the orphan store: a tx
                            // parked as an orphan is already tracked (its parents are
                            // being requested), re-requesting it is pure waste.
                            let our_hashes = get_dag_hashes();
                            let our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();
                            // PHASE D live-campaign fix: the MAX_INV_ITEMS cap
                            // used to apply to the PEER's raw inventory, which
                            // hid every tx beyond the first 1000 from a joining
                            // node (the diff came out empty, sync_requested=0,
                            // bootstrap stuck a few txs short of the tip). The
                            // cap now bounds the REQUEST (the real diff) so a
                            // late joiner still asks for the whole missing set.
                            // C2 diagnostics: advertised total + orphan-dedup skips.
                            sync_ctx.stats.inventory_advertised.fetch_add(
                                hashes.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            let mut skipped_orphan = 0u64;
                            let missing_hashes: Vec<Vec<u8>> = hashes
                                .into_iter()
                                .filter(|h| {
                                    if our_hash_set.contains(h) {
                                        return false;
                                    }
                                    if is_orphan(h.as_slice()) {
                                        skipped_orphan += 1;
                                        return false;
                                    }
                                    true
                                })
                                .take(MAX_INV_ITEMS)
                                .collect();
                            sync_ctx
                                .stats
                                .inventory_skipped_orphan
                                .fetch_add(skipped_orphan, std::sync::atomic::Ordering::Relaxed);
                            // VPS-2 §5: the diff size itself (how much the
                            // peer has that we lack), independent of caps.
                            sync_ctx.stats.inventory_missing.fetch_add(
                                missing_hashes.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );

                            // Request missing transactions via GetData
                            if !missing_hashes.is_empty() {
                                sync_ctx.stats.sync_requested.fetch_add(
                                    missing_hashes.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                // DEEP SYNC: register missing hashes in the frontier
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    for h in &missing_hashes {
                                        frontier.add_pending(h.clone());
                                    }
                                }
                                info!(
                                    "Requesting {} missing transactions from {}",
                                    missing_hashes.len(),
                                    addr
                                );
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_hashes.clone()))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                                // DEEP SYNC: mark hashes as requested in frontier
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    for h in &missing_hashes {
                                        frontier.mark_requested(h, addr);
                                    }
                                }
                            }
                        }
                        P2PMessage::GetInventory { tips: peer_tips } => {
                            // Get our hashes and tips
                            let our_hashes = get_dag_hashes();
                            let our_tips = get_tips();
                            let _our_hash_set: HashSet<Vec<u8>> = our_hashes.into_iter().collect();

                            // Find transactions we have that peer doesn't have (compare tips),
                            // bounded by MAX_INV_ITEMS on the peer-supplied list.
                            let peer_tips_set: HashSet<Vec<u8>> =
                                peer_tips.into_iter().take(MAX_INV_ITEMS).collect();
                            let our_tips_set: HashSet<Vec<u8>> = our_tips.into_iter().collect();

                            // Transactions we need from peer (tips we don't have)
                            let missing_for_us: Vec<Vec<u8>> =
                                peer_tips_set.difference(&our_tips_set).cloned().collect();

                            // Transactions peer might need from us (tips we have that they don't)
                            let missing_for_peer: Vec<Vec<u8>> =
                                our_tips_set.difference(&peer_tips_set).cloned().collect();

                            info!("[Sync] GetInventory from {}: we need {} tips, peer might need {} tips", 
                                addr, missing_for_us.len(), missing_for_peer.len());

                            // Send our tips that peer doesn't have (with pagination)
                            if !missing_for_peer.is_empty() {
                                const PAGE_SIZE: usize = 100;
                                let mut tx_bytes_list = Vec::new();

                                for hash in missing_for_peer.iter().take(PAGE_SIZE) {
                                    if let Some(tx) = get_transaction_by_hash(hash) {
                                        if let Ok(bytes) = bincode::serialize(&tx) {
                                            tx_bytes_list.push(bytes);
                                        }
                                    }
                                }

                                if !tx_bytes_list.is_empty() {
                                    info!(
                                        "[Sync] Sending {} transactions to {}",
                                        tx_bytes_list.len(),
                                        addr
                                    );
                                    if let Ok(sync_resp_msg) =
                                        bincode::serialize(&P2PMessage::SyncResponse(tx_bytes_list))
                                    {
                                        let _ = msg_sender.send(sync_resp_msg);
                                    }
                                }
                            }

                            // Request missing transactions from peer
                            if !missing_for_us.is_empty() {
                                if let Ok(getdata_msg) =
                                    bincode::serialize(&P2PMessage::GetData(missing_for_us))
                                {
                                    let _ = msg_sender.send(getdata_msg);
                                }
                            }
                        }
                        P2PMessage::GetData(hashes) => {
  // PHASE 4G: vote fallback. Vote ids and tx ids
  // share the 32-byte space but never collide in
  // practice (both are BLAKE3 content addresses
  // over disjoint encodings  -  grinding a tx id to
  // equal a vote id is a 2nd-preimage attack on
  // 256 bits). A requested hash with no transaction
  // is therefore served from the vote store when
  // present (one Vote message per hit, bounded like
  // tx pages); misses stay silent (peer retries via
  // gossip, same as unknown txs today).
  let vote_lookup = match stake_hooks.get_vote_by_id.lock() {
  Ok(guard) => guard.clone(),
  Err(_) => None,
                            };
  if let Some(lookup) = vote_lookup {
  for hash in hashes.iter().take(MAX_SYNC_PAGE) {
  if get_transaction_by_hash(hash).is_none() {
  if let Some(enc) = lookup(hash) {
  if let Ok(vote_msg) = bincode::serialize(
  &P2PMessage::Vote(enc),
        ) {
  let _ = msg_sender.send(vote_msg);
                                    }
                                }
                            }
                            }
                                }
                            // DEEP SYNC: serve requested transactions with FULL
                            // ancestor closure, split into multiple topologically
                            // sorted pages. Each page is ancestor-closed so the
                            // receiver can insert bottom-up without orphans.
                            let topo = Self::cached_topo_order(
                                &sync_ctx,
                                get_dag_hashes(),
                                &*get_transaction_by_hash,
                            )
                            .await;
                            let sort_topo = |v: &mut Vec<Vec<u8>>, order: &Option<Vec<Vec<u8>>>| {
                                if let Some(order) = order {
                                    let pos: HashMap<&Vec<u8>, usize> =
                                        order.iter().enumerate().map(|(i, h)| (h, i)).collect();
                                    v.sort_by_key(|h| pos.get(h).copied().unwrap_or(usize::MAX));
                                }
                            };
                            // Take up to MAX_SYNC_PAGE of the requested hashes.
                            let requested: Vec<Vec<u8>> =
                                hashes.iter().take(MAX_SYNC_PAGE).cloned().collect();
                            // Compute FULL ancestor closure (bounded by MAX_CLOSURE_PAGES).
                            let max_entries = MAX_SYNC_PAGE.saturating_mul(MAX_CLOSURE_PAGES);
                            let mut closure = P2PNetwork::ancestor_full_closure(
                                &requested,
                                &*get_transaction_by_hash,
                                max_entries,
                            );
                            // Topologically sort: ancestors first.
                            sort_topo(&mut closure, &topo);
                            // Split into pages of MAX_SYNC_PAGE and send each.
                            let total_pages = closure.len().div_ceil(MAX_SYNC_PAGE).max(1);
                            for (page_idx, chunk) in closure.chunks(MAX_SYNC_PAGE).enumerate() {
                                let mut tx_bytes_list = Vec::with_capacity(chunk.len());
                                for hash in chunk {
                                    if let Some(tx) = get_transaction_by_hash(hash) {
                                        if let Ok(bytes) = bincode::serialize(&tx) {
                                            tx_bytes_list.push(bytes);
                                        }
                                    }
                                }
                                if !tx_bytes_list.is_empty() {
                                    tracing::debug!(
                                        "[Sync] Serving page {}/{} ({} txs) to {}",
                                        page_idx + 1,
                                        total_pages,
                                        tx_bytes_list.len(),
                                        addr
                                    );
                                    if let Ok(sync_resp_msg) =
                                        bincode::serialize(&P2PMessage::SyncResponse(tx_bytes_list))
                                    {
                                        let _ = msg_sender.send(sync_resp_msg);
                                    }
                                }
                            }
                        }
                        P2PMessage::SyncRequest => {
                            // 2E-A (A.2 i): respond with a BOUNDED, ROTATING
                            // inventory window instead of the whole DAG. The
                            // old "full inventory" reply made `total_len` an
                            // exact DAG-size oracle for any passive observer
                            // and a free amplification lever. See
                            // `inventory_window` for why a plain `take()` was
                            // not an option (it stranded late joiners).
                            // LOG NOISE (soak): announcements are DEBUG only.
                            let all_hashes = get_dag_hashes();
                            let our_hashes = Self::inventory_window(&all_hashes, &SYNC_WINDOW_CURSOR);
                            tracing::debug!(
                                "[Sync] Sending inventory window of {} ({} total known) to {}",
                                our_hashes.len(),
                                all_hashes.len(),
                                addr
                            );
                            if let Ok(inv_msg) =
                                bincode::serialize(&P2PMessage::Inventory(our_hashes))
                            {
                                let _ = msg_sender.send(inv_msg);
                            }
                        }
                        P2PMessage::SyncResponse(tx_bytes_list) => {
                            // B4: download and add transactions in dependency order
                            // (bounded by MAX_INV_ITEMS to avoid amplification).
                            // 1. Dedup against the DAG AND the orphan store: an
                            //    orphan is already tracked and retried by the
                            //    resolver (fixpoint in process_orphans), so
                            //    re-delivering it is pure waste (this was the B4
                            //    re-request amplification loop).
                            // 2. Split the batch into (deliverable now) / (parents
                            //    still missing) with dependency-aware passes: a tx
                            //    whose parents are in the DAG or accepted earlier in
                            //    this SAME batch is delivered immediately. The
                            //    remaining txs go through the normal pipeline where
                            //    they are parked as orphans and their parents are
                            //    requested (bounded by the parent-request dedup).
                            let mut pending: Vec<(Vec<u8>, Transaction)> = Vec::new();
                            // C2 diagnostics: raw items before the DAG/orphan
                            // dedup below (peers re-sending tracked items?).
                            sync_ctx.stats.sync_response_items.fetch_add(
                                tx_bytes_list.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            for tx_bytes in tx_bytes_list.into_iter().take(MAX_INV_ITEMS) {
                                if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                                    if get_transaction_by_hash(&tx.id).is_some()
                                        || is_orphan(&tx.id)
                                    {
                                        sync_ctx
                                            .stats
                                            .duplicate_ignored
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        // DEEP SYNC: mark duplicate as applied in frontier (already resolved)
                                        {
                                            let mut frontier = sync_ctx.frontier.write().await;
                                            frontier.mark_received(&tx.id);
                                            frontier.mark_applied(&tx.id);
                                        }
                                        continue;
                                    }
                                    // FIX: do NOT mark_received here yet — only mark
                                    // AFTER partition_batch confirms the tx is deliverable.
                                    // Waiting txs (parents missing) must remain "unreceived"
                                    // so the next inventory diff re-requests them.
                                    pending.push((tx_bytes, tx));
                                }
                            }
                            sync_ctx.stats.sync_received.fetch_add(
                                pending.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            sync_ctx
                                .stats
                                .sync_batches
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            let (deliverable, waiting) =
                                Self::partition_batch(pending, &*get_transaction_by_hash);

                            if !waiting.is_empty() {
                                tracing::info!(
                                    "📥 SyncResponse: {} deliverable, {} waiting (parents missing, will retry next cycle)",
                                    deliverable.len(),
                                    waiting.len()
                                );
                            }

                            // DEEP SYNC: adaptive backpressure instead of fixed
                            // 50ms per tx. Scale interval with batch size to
                            // maintain throughput while allowing ledger breathing room.
                            let batch_len = deliverable.len();
                            let delay_ms = if batch_len > 0 {
                                // Scale: base interval * sqrt(batch) / 10, clamped to [1, 20]ms
                                let scaled = (BACKPRESSURE_BASE_MS as f64
                                    * (batch_len as f64).sqrt()
                                    / 10.0) as u64;
                                scaled.clamp(1, 20)
                            } else {
                                0
                            };
                            // CRITICAL FIX: only send deliverable txs to the mempool.
                            // waiting txs have parents not yet in the DAG. Sending them
                            // would create orphans whose parents are also in the mempool,
                            // causing an unresolvable cascade (resolved=0).
                            // waiting txs will be re-requested by process_orphans() on
                            // subsequent cycles when their parents arrive.
                            for (tx_bytes, tx) in deliverable.into_iter() {
                                // DEEP SYNC: mark as received + applied in frontier AFTER
                                // partition_batch confirmed this tx is deliverable.
                                // Waiting txs (parents missing) are NOT marked, so the
                                // next inventory diff re-requests them.
                                //
                                // PHASE 3B (H1): this is the SYNC backfill path
                                // (inventory diffs, GetData closures, healing).
                                // Record Historical provenance BEFORE queueing:
                                // backfill carries genuinely-old txs that live
                                // policy (Fresh) must not reject. Live gossip
                                // singles record Fresh at the Transaction arm
                                // above; first-delivery-wins on duplicates.
                                sync_ctx
                                    .note_ingress_mode(tx.id, ValidationMode::Historical)
                                    .await;
                                {
                                    let mut frontier = sync_ctx.frontier.write().await;
                                    frontier.mark_received(&tx.id);
                                    frontier.mark_applied(&tx.id);
                                    frontier.record_progress();
                                }
                                // 2E-D: the deep-sync ingress has to record its
                                // upstream peer too, otherwise a payload that
                                // arrives here is later re-sent to the very
                                // peer that sent it (its `PropagationEntry`
                                // would be created in `broadcast_transaction`
                                // with `source = None`). Recorded before the
                                // bytes are moved into `insert_seen`.
                                record_propagation_source(
                                    &propagation_state,
                                    &tx_bytes,
                                    addr,
                                )
                                .await;
                                insert_seen(&seen_transactions, tx_bytes).await;
                                let _ = tx_channel.send(tx);
                                if delay_ms > 0 {
                                    tokio::time::sleep(tokio::time::Duration::from_millis(
                                        delay_ms,
                                    ))
                                    .await;
                                }
                            }
                            // DEEP SYNC: log frontier state after processing batch
                            {
                                let frontier = sync_ctx.frontier.read().await;
                                tracing::debug!("{}", frontier.log_line());
                            }
                        }
                        P2PMessage::Ping => {
                            // Respond with pong - skip for now, need sender
                        }
                        P2PMessage::Pong => {
                            // Ignore pong
                        }
                        P2PMessage::Peers(peer_list) => {
                            // Phase 2B (D6/R4): a PEX hint may never point at a
                            // private, loopback, link-local or otherwise
                            // reserved host — otherwise a peer can steer us
                            // into dialing our own LAN. This gate exists on the
                            // receive/dial path only: operator bootnodes and
                            // DNS seeds stay unrestricted so private testnets
                            // keep working.
                            //
                            // Phase 4CH: every address in ONE announce is
                            // examined exactly once (`seen` collapses
                            // intra-message duplicates, so a doubled entry
                            // cannot halve an address's failure debt twice),
                            // then split: addresses the table already holds are
                            // refreshed in place; unknown ones keep the
                            // unchanged admission path below. A PEX announce is
                            // a limited-trust discovery hint — it is never
                            // treated as proof of identity or of ownership of
                            // the address it names.
                            let mut seen: HashSet<SocketAddr> = HashSet::new();
                            let (to_add, to_refresh): (Vec<SocketAddr>, Vec<SocketAddr>) = {
                                // Snapshot the session table and release first:
                                // `peers` and `addresses` are never held together.
                                let connected: HashSet<SocketAddr> =
                                    peers.read().await.keys().copied().collect();
                                let mgr = addresses.read().await;
                                peer_list
                                    .iter()
                                    .take(MAX_INV_ITEMS)
                                    .filter(|p| {
                                        **p != local_addr
                                            && !connected.contains(p)
                                            && !is_private_or_reserved(**p)
                                    })
                                    .filter(|p| seen.insert(**p))
                                    .copied()
                                    .partition(|p| !mgr.contains(*p))
                            };
                            // 4CH: refresh held addresses in place — the failure
                            // debt halves and the TTL clock advances — and
                            // deliberately do NOT push them to the discovery
                            // channel: a re-announce never forces a dial, the
                            // bounded redial selection decides if and when the
                            // address is retried. One write guard covers the
                            // whole (<= MAX_INV_ITEMS) batch.
                            if !to_refresh.is_empty() {
                                let at = Instant::now();
                                let mut mgr = addresses.write().await;
                                for peer_addr in &to_refresh {
                                    mgr.pex_refresh(*peer_addr, at);
                                }
                            }
                            for peer_addr in to_add {
                                let ok = ingress_address(
                                    &addresses,
                                    &peers,
                                    local_addr,
                                    peer_addr,
                                    PeerSource::Pex,
                                )
                                .await;
                                if !ok {
                                    // Nothing left to evict, and other hints in
                                    // this batch are no better.
                                    continue;
                                }
                                // Phase 2B (D5): remember who taught us about
                                // this address so we never echo it back to them.
                                addresses.write().await.set_origin(peer_addr, addr);
                                let _ = peer_discovery_tx.send(peer_addr);
                            }
                        }
  // -- PHASE 4G stake gossip arms (enum tail: these sit
  // AFTER Peers so the Transaction..Inventory source
  // span asserted by the relay-gate test is untouched).
  // Format-only receive (strict decode + dedup), then
  // queue for the node vote/bond tasks. No provenance
  // modes (Fresh/Historical is tx-sync-specific);
  // admission (signature/epoch/stake checks) owns
  // rejection downstream. Unwired stake channel =
  // drop at ingress (pre-v6 nodes).
  P2PMessage::Vote(payload_bytes) => {
  let stake_tx = match stake_hooks
  .stake_channel
  .lock()
                    {
  Ok(guard) => guard.clone(),
  Err(_) => None,
        };
  match stake_tx {
                None => continue,
  Some(tx) => {
  if !accept_inbound_stake(
  "vote",
  payload_bytes,
                    addr,
  &seen_transactions,
  &propagation_state,
  &tx,
                )
            .await
        {
                continue;
        }
            }
            }
        }
  P2PMessage::Bond(payload_bytes) => {
  let stake_tx = match stake_hooks
  .stake_channel
  .lock()
        {
  Ok(guard) => guard.clone(),
  Err(_) => None,
        };
  match stake_tx {
                None => continue,
  Some(tx) => {
  if !accept_inbound_stake(
  "bond",
  payload_bytes,
                        addr,
  &seen_transactions,
  &propagation_state,
  &tx,
                    )
            .await
        {
                    continue;
                }
                }
            }
            }
  P2PMessage::Unbond(payload_bytes) => {
  let stake_tx = match stake_hooks
  .stake_channel
  .lock()
        {
  Ok(guard) => guard.clone(),
  Err(_) => None,
        };
  match stake_tx {
  None => continue,
  Some(tx) => {
  if !accept_inbound_stake(
  "unbond",
  payload_bytes,
  addr,
  &seen_transactions,
  &propagation_state,
  &tx,
        )
            .await
        {
                    continue;
            }
        }
    }
    }
  // -- PHASE 4I (F-D3) vote-backfill arms (enum tail: after Unbond so
  // the Transaction..Inventory source span asserted by the relay-gate
  // test is untouched).
  P2PMessage::VoteInventory(ids) => {
  // Diff advertised ids against our vote store; fetch what we lack
  // (bounded, deduplicated pure helper). Unwired lookup (tx-only
  // node) = ignore.
  let lookup = match stake_hooks.get_vote_by_id.lock() {
  Ok(guard) => guard.clone(),
  Err(_) => None,
        };
  if let Some(lookup) = lookup {
  let missing =
  vote_inventory_missing(&ids, &|id| lookup(id).is_some(), MAX_INV_ITEMS);
  if !missing.is_empty() {
  // Re-cap to page size for the request itself.
  let page: Vec<Vec<u8>> = missing.into_iter().take(MAX_SYNC_PAGE).collect();
  if let Ok(req) = bincode::serialize(&P2PMessage::GetVotes(page)) {
  let _ = msg_sender.send(req);
                    }
                }
            }
        }
  P2PMessage::GetVotes(ids) => {
  // Serve known vote encodings (bounded). Unknown ids stay silent
  // (requester retries via gossip, same as unknown txs today).
  let lookup = match stake_hooks.get_vote_by_id.lock() {
  Ok(guard) => guard.clone(),
  Err(_) => None,
        };
  if let Some(lookup) = lookup {
  for id in ids.into_iter().take(MAX_SYNC_PAGE) {
  if let Some(enc) = lookup(&id) {
  if let Ok(vote_msg) = bincode::serialize(&P2PMessage::Vote(enc)) {
  let _ = msg_sender.send(vote_msg);
                            }
                        }
                    }
                }
            }
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize message from {}: {}", addr, e);
                    // SCORING: penalize invalid message
                    {
                        let mut mgr = addresses.write().await;
                        if let Some(score) = mgr.penalize_and_ban(addr, PEER_PENALTY_INVALID_MSG) {
                            warn!("Peer {} banned (deser fail, score={})", addr, score);
                        }
                    }
                }
            }
        }

        // Remove peer from active map on disconnect.
        // Phase 1 TTL: keep the address in known_peers so general redial / PEX
        // can re-establish the session; the TTL task expires it later.
        {
            let mut peers_lock = peers.write().await;
            peers_lock.remove(&addr);
        }
        // PHASE 4CP-S + 4CP-W: drop exactly THIS session's provenance, and only
        // if it still belongs to our cycle. Keyed by id (and guarded by the
        // generation), so a late teardown can never erase a newer session at
        // the same address nor touch a later cycle's registry.
        session_auth.write().await.clear_if_active(generation, session_id);
        {
            let mut mgr = addresses.write().await;
            mgr.touch(addr, Instant::now());
        }
        // DEEP SYNC: failover — move all in-flight requests from this peer back to pending
        {
            let mut frontier = sync_ctx.frontier.write().await;
            let requeued = frontier.on_peer_disconnect(&addr);
            if requeued > 0 {
                info!(
                    "[Sync] Peer {} disconnected, requeued {} in-flight requests for failover",
                    addr, requeued
                );
            }
            frontier.update_state();
            tracing::debug!("{}", frontier.log_line());
        }
        info!("Peer {} removed from peers map", addr);
    }

    /// Connect to a peer
    /// Dial `addr`, tolerating concurrent callers. The initial sweep, heartbeat,
    /// redial loop and PEX can all ask for the same address at the same time;
    /// the in-flight set collapses them into a single session so the `peers` map
    /// never gets a sender silently overwritten by a duplicate connection.
    async fn connect_to_peer(&self, addr: SocketAddr) {
        // 4CB: refuse new dials once shutdown has begun.
        if self.shutdown.load(Ordering::Relaxed) {
            return;
        }
        {
            let mut dialing = self.dialing.write().await;
            if !dialing.insert(addr) {
                debug!("Dial to {} already in flight, skipping", addr);
                return;
            }
        }
        self.connect_to_peer_inner(addr).await;
        self.dialing.write().await.remove(&addr);
    }

    /// Phase 2A: read-only guard consulted before any outbound dial. Inbound
    /// connections have always checked the ban table; outbound never did, so a
    /// node would happily redial a peer it had already banned.
    async fn outbound_dial_blocked(&self, addr: SocketAddr) -> bool {
        self.addresses.read().await.is_banned(addr)
    }

    async fn connect_to_peer_inner(&self, addr: SocketAddr) {
        info!("Dialing peer: {}", addr);

        // 4CP-Y (X-3): refuse to open a session unless a live cycle has frozen
        // the handshake choice. Before start() (or after a failed start / a
        // shutdown) there is no snapshot and no operational cycle, so a dial
        // must not proceed with an implicit mode.
        let (protocol_mode, node_identity) = match self.started_config() {
            Some(cfg) => cfg,
            None => {
                debug!("Refusing dial to {}: no live network cycle", addr);
                return;
            }
        };

        if self.outbound_dial_blocked(addr).await {
            let until = self.addresses.read().await.banned_until(addr);
            warn!(
                "Skipping banned peer {} for outbound dial (banned until {:?})",
                addr, until
            );
            return;
        }

        self.addresses.write().await.decay_score(addr);

        {
            let peers_guard = self.peers.read().await;
            // Phase 2C: outbound is admitted against the *total* only — the
            // inbound side already keeps `PROTECTED_OUTBOUND_SLOTS` free for
            // exactly this check.
            if !outbound_admitted(peers_guard.len()) {
                warn!(
                    "Skipping connect to {}: connection limit reached ({})",
                    addr, MAX_PEERS
                );
                return;
            }
            // ECLIPSE-01: enforce /24 subnet diversity for outbound connections
            let subnet_count = count_subnet_peers_excluding(addr, &peers_guard).await;
            if subnet_count >= MAX_PEERS_PER_SUBNET {
                warn!(
                    "Skipping connect to {}: /24 subnet limit reached ({}/{})",
                    addr, subnet_count, MAX_PEERS_PER_SUBNET
                );
                return;
            }
        }

        // H2: bound the connect attempt so a black-holed or unroutable peer
        // address cannot stall the outbound discovery loop indefinitely.
        // 2E-B: the socket itself comes from the transport; the timeout stays
        // here because when to give up is policy, not mechanism.
        match tokio::time::timeout(CONNECT_TIMEOUT, self.transport.dial(&PeerAddr::Ip(addr)))
            .await
        {
            Ok(Ok(stream)) => {
                info!("Connected to peer: {}", addr);
                let (msg_sender, msg_receiver) = mpsc::unbounded_channel::<Vec<u8>>();
                {
                    let mut peers = self.peers.write().await;
                    peers.insert(addr, msg_sender.clone());
                }
                // Phase 2C: record that *we* opened this session, so the
                // inbound admission gate can keep its reservation intact.
                {
                    let mut outbound = self.outbound_sessions.write().await;
                    outbound.insert(addr);
                }

                // Phase 2B (D7/D8): an address we chose to dial is an outbound
                // source, admitted through the quality-aware path.
                ingress_address(
                    &self.addresses,
                    &self.peers,
                    self.config.listen_addr,
                    addr,
                    PeerSource::Outbound,
                )
                .await;

                let peers = self.peers.clone();
                let addresses = self.addresses.clone();
                let local_addr = self.config.listen_addr;
                let tx_channel = self.tx_channel.clone();
                let get_dag_hashes = Arc::clone(&self.get_dag_hashes);
                let get_transaction_by_hash = Arc::clone(&self.get_transaction_by_hash);
                let get_tips = Arc::clone(&self.get_tips);
                let seen_transactions = Arc::clone(&self.seen_transactions);
                let propagation_state = Arc::clone(&self.propagation_state);
                let sync_ctx = Arc::clone(&self.sync_ctx);
                let is_orphan = Arc::clone(&self.is_orphan);
  let stake_hooks = self.stake_hooks.clone();
  let network_id = self.config.network_id;
                // PHASE 4CP-U: the handshake choice comes from the frozen
                // start snapshot captured at the top of this function, so the
                // outbound handshake matches the accept loop.
                let session_auth = self.session_auth.clone();
                let session_seq = self.session_seq.clone();
                let peer_discovery_tx = {
                    let guard = self.peer_discovery_tx.lock().await;
                    guard.clone().unwrap_or_else(|| {
                        let (tx, _) = mpsc::unbounded_channel();
                        tx
                    })
                };
                let outbound_sessions = self.outbound_sessions.clone();
                // 4CP-W: admit the session task and register its handle in ONE
                // atomic step (as on the inbound path). If shutdown() already
                // closed the cycle, `admit_task` refuses — the future is never
                // created and the peer we optimistically inserted is removed.
                let peers_for_session = peers.clone();
                // 4CP-AA (X-4/Y-5): capture this cycle's admission for the
                // per-session send task, and consume the test-only outbound
                // registration rendezvous (`None` in production).
                let session_admission = self.admission.clone();
                let outbound_record_gate = self.take_outbound_record_gate();
                let admitted = Self::admit_task(&self.admission, |generation| async move {
                    Self::handle_peer(
                        stream,
                        addr,
                        peers_for_session,
                        local_addr,
                        addresses,
                        tx_channel,
                        get_dag_hashes,
                        get_transaction_by_hash,
                        get_tips,
                        seen_transactions,
                        propagation_state,
                        msg_sender,
                        msg_receiver,
                        peer_discovery_tx,
                        sync_ctx,
                        is_orphan,
                        stake_hooks,
                        network_id,
                        protocol_mode,
                        node_identity,
                        true,
                        session_auth,
                        session_seq,
                        generation,
                        outbound_record_gate,
                        session_admission,
                        HANDSHAKE_TIMEOUT,
                    )
                    .await;
                    // Phase 2C: release the reservation only once the session
                    // is really gone. Cleaning up here rather than inside
                    // `handle_peer` keeps `handle_peer`'s signature — and
                    // therefore the inbound path — untouched.
                    outbound_sessions.write().await.remove(&addr);
                });
                if !admitted {
                    let mut peers_lock = peers.write().await;
                    peers_lock.remove(&addr);
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to connect to {}: {}", addr, e);
                self.record_dial_failure(addr).await;
            }
            Err(_) => {
                warn!("Connect timeout to {} after {:?}", addr, CONNECT_TIMEOUT);
                self.record_dial_failure(addr).await;
            }
        }
    }

    /// Phase 2B: an outbound dial that never reached a session lowers the
    /// address's quality. `admit_peer` weighs exactly that quality when the
    /// table is full (D8), so a repeatedly unreachable address is the first
    /// thing displaced.
    async fn record_dial_failure(&self, addr: SocketAddr) {
        self.addresses.write().await.record_failure(addr);
    }

    /// 2E-D: forward one accepted transaction to a bounded fan-out of peers,
    /// each behind its own jitter.
    ///
    /// This is the ONLY place a `P2PMessage::Transaction` is ever put on the
    /// wire, and it is reachable only after `process_transaction` has passed
    /// `validate_pure`, the DAG dedup, the fee gate and the mempool enqueue
    /// (rpc.rs:1185). The pre-validation relay that used to live in the
    /// receive arm is gone — see docs/AETHER_PHASE2_PRIVACY_PROPAGATION.md
    /// §2.9.
    ///
    /// Three properties, each asserted by a test:
    ///
    /// * **once** — `take_propagation_slot` claims the single wave for this
    ///   payload before anything is transmitted, so a second call (RPC and
    ///   P2P racing, or a duplicate arriving) schedules nothing. Net effect
    ///   per link: ONE transmission, down from two.
    /// * **not back to the sender** — the peer recorded at ingress is
    ///   excluded. The upstream node already has the payload; sending it back
    ///   wastes a frame and tells the observer it was us.
    /// * **bounded and spread** — at most `MAX_PROPAGATION_FANOUT` peers,
    ///   chosen across network groups, sent from `tokio::spawn`ed tasks after
    ///   `propagation_delay` each. Nothing blocks here: a slow or stalled
    ///   peer cannot delay the caller or the other targets.
    pub async fn broadcast_transaction(&self, tx: Transaction) {
        let tx_bytes = match bincode::serialize(&tx) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize transaction: {}", e);
                return;
            }
        };

        // 2E-D: scheduling dedup comes FIRST — before `insert_seen`, before
        // any serialization, before a single frame is handed to a socket.
        // `Some(source)` = this call owns the wave; `None` = an earlier call
        // already scheduled it and this one must not add a second.
        let source = match take_propagation_slot(&self.propagation_state, &tx_bytes).await {
            Some(source) => source,
            None => return,
        };

        // Keep the receipt-level mark too: it is what stops a copy of this
        // payload coming back from a peer from being re-processed at all.
        insert_seen(&self.seen_transactions, tx_bytes.clone()).await;

        let msg = P2PMessage::Transaction(tx_bytes.clone());
        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize P2P message: {}", e);
                return;
            }
        };

        // Select the targets and draw each peer's delay under ONE rng lock
        // (short, never held across an `.await`), then drop every guard before
        // spawning so no lock is live while tasks are created.
        let wave: Vec<(mpsc::UnboundedSender<Vec<u8>>, Duration)> = {
            let peers_guard = self.peers.read().await;
            let addrs: Vec<SocketAddr> = peers_guard.keys().copied().collect();
            let mut rng = self.propagation_rng.lock().unwrap_or_else(|e| e.into_inner());
            let targets = propagation_targets(&addrs, source, MAX_PROPAGATION_FANOUT, &mut *rng);
            targets
                .into_iter()
                .filter_map(|addr| {
                    let sender = peers_guard.get(&addr)?.clone();
                    let delay = propagation_delay(&mut *rng);
                    Some((sender, delay))
                })
                .collect()
        };

        let inflight = Arc::clone(&self.propagation_inflight);
        for (sender, delay) in wave {
            let task_inflight = Arc::clone(&inflight);
            let task_msg = msg_bytes.clone();
            task_inflight.fetch_add(1, Ordering::Relaxed);
            // 4CP-AA (X-4): deliberately DETACHED. A relay holds no socket, no
            // session and no registry entry — only a clone of one peer's
            // outbound channel plus a copy of the payload — and completes within
            // `PROPAGATION_JITTER_MAX` (250 ms) with a single non-blocking
            // `send`. It cannot open a connection, register a session or touch a
            // later cycle, and tracking one handle per fan-out per broadcast
            // would grow the teardown set without bound on a busy node.
            tokio::spawn(async move {
                // The jitter IS the countermeasure: `relay_t - receive_t` is
                // > 0 and differs per neighbour, so no two links show the same
                // instant. It is not — and 2E-D does not claim it is — a
                // defence against an observer holding both endpoints.
                tokio::time::sleep(delay).await;
                if sender.send(task_msg).is_err() {
                    // LOG REVIEW (2E-D §11): no address, no hash, no relay
                    // timestamp — a peer dropping out is not a correlation
                    // event worth a line at the default level.
                    tracing::trace!("relay peer channel closed");
                }
                task_inflight.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// 2E-D: relays currently waiting out their jitter. Returns to 0 once
    /// every scheduled wave has been written out.
    pub fn propagation_inflight(&self) -> usize {
        self.propagation_inflight.load(Ordering::Relaxed)
        }

  /// PHASE 4G: relay one admitted stake payload (vote / bond / unbond).
  /// Validation-before-send (canonical re-encode + version + signature  - 
  /// NOTHING the node rejected reaches the wire), scheduling dedup first
  /// (same take_propagation_slot discipline as transactions: one wave
  /// per payload, upstream peer excluded, bounded fan-out + jitter).
  /// Called by the node AFTER process_vote/bond/unbond accepts (and by
  /// RPC submission paths post-admission)  -  never by the receive stage.
  /// NOTE on "sends gated pre-activation": the gate on WHAT gets produced
  /// lives at the node vote task (it only votes post-V6 keys); the relay
  /// itself is content-agnostic by 2E-D design (it never interprets
  /// payloads)  -  its gates are validation + dedup + fan-out caps.
  pub async fn broadcast_stake(&self, payload: StakePayload) {
  let (payload_bytes, msg) = match &payload {
  StakePayload::Vote(v) => {
  if v.format_version != crate::transaction::VOTE_FORMAT_VERSION
  || !v.verify_signature()
            {
                    return;
                    }
  let bytes = v.encode();
  (bytes.clone(), P2PMessage::Vote(bytes))
                    }
  StakePayload::Bond(b) => {
  if b.format_version != crate::transaction::BOND_FORMAT_VERSION
  || !b.verify_signature()
        {
                return;
                }
  let bytes = b.encode();
  (bytes.clone(), P2PMessage::Bond(bytes))
            }
  StakePayload::Unbond(u) => {
  if u.format_version != crate::transaction::BOND_FORMAT_VERSION
  || !u.verify_signature()
        {
                return;
        }
  let bytes = u.encode();
  (bytes.clone(), P2PMessage::Unbond(bytes))
                    }
        };

  let source = match take_propagation_slot(&self.propagation_state, &payload_bytes).await {
  Some(source) => source,
  None => return,
        };
  insert_seen(&self.seen_transactions, payload_bytes.clone()).await;

        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
  error!("Failed to serialize P2P stake message: {}", e);
  return;
                }
        };

  let wave: Vec<(mpsc::UnboundedSender<Vec<u8>>, Duration)> = {
  let peers_guard = self.peers.read().await;
  let addrs: Vec<SocketAddr> = peers_guard.keys().copied().collect();
  let mut rng = self.propagation_rng.lock().unwrap_or_else(|e| e.into_inner());
  let targets = propagation_targets(&addrs, source, MAX_PROPAGATION_FANOUT, &mut *rng);
  targets
            .into_iter()
  .filter_map(|addr| {
  let sender = peers_guard.get(&addr)?.clone();
  let delay = propagation_delay(&mut *rng);
  Some((sender, delay))
        })
            .collect()
        };

  let inflight = Arc::clone(&self.propagation_inflight);
  for (sender, delay) in wave {
  let task_inflight = Arc::clone(&inflight);
  let task_msg = msg_bytes.clone();
  task_inflight.fetch_add(1, Ordering::Relaxed);
        // 4CP-AA (X-4): deliberately DETACHED — same reasoning as the
        // transaction relay above (no socket/session/registry, bounded by the
        // jitter, non-blocking send).
        tokio::spawn(async move {
  tokio::time::sleep(delay).await;
  if sender.send(task_msg).is_err() {
  tracing::trace!("relay peer channel closed");
            }
  task_inflight.fetch_sub(1, Ordering::Relaxed);
                        });
        }
    }

    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get the list of connected peers
    pub async fn get_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let peers: &std::collections::HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = &*peers;
        peers.keys().copied().collect()
    }

    /// C2-004: cached topological serving order, keyed by DAG length.
    /// Sorting the whole DAG per GetData collapsed serving nodes at ~10k
    /// txs; repeat requests are O(1). The order is a SERVING HINT ONLY,
    /// never consensus (a stale entry merely batches less optimally).
    async fn cached_topo_order(
        sync_ctx: &Arc<SyncContext>,
        all_hashes: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Option<Vec<Vec<u8>>> {
        {
            let cache = sync_ctx.topo_cache.read().await;
            if let Some((len, order)) = cache.as_ref() {
                if *len as usize == all_hashes.len() {
                    sync_ctx
                        .stats
                        .topo_cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Some(order.clone());
                }
            }
            sync_ctx
                .stats
                .topo_cache_miss
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let order = Self::topological_order(all_hashes, get_transaction_by_hash);
        if let Some(ref o) = order {
            let mut cache = sync_ctx.topo_cache.write().await;
            *cache = Some((o.len() as u64, o.clone()));
        }
        order
    }

    /// VPS-2: extend a requested hash set with its DAG-resident ancestors
    /// (bounded), so the served page is self-sufficient for bottom-up
    /// insertion. Pure function of (requested set, DAG contents):
    /// deterministic, no network, no consensus impact.
    ///
    /// Guarantees: every returned hash is DAG-resident (requested unknowns
    /// are dropped — the serving layer skips them anyway); requested ones
    /// come with their ancestor closure up to the budget; at most
    /// ANCESTOR_BUDGET extras; genesis (`[0; 32]`) parents terminate;
    /// no duplicates; terminates (visited set + step cap double-guard
    /// against any cycle).
    pub(crate) fn ancestor_closed_page(
        requested: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Vec<Vec<u8>> {
        const ANCESTOR_BUDGET: usize = 400;
        const ANCESTOR_STEPS: usize = 20_000;
        let mut page: Vec<Vec<u8>> =
            Vec::with_capacity(requested.len().saturating_add(ANCESTOR_BUDGET));
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for h in requested.into_iter() {
            // Requested-but-unknown hashes are dropped here (the serving
            // layer would skip them anyway); only servable txs enter.
            if get_transaction_by_hash(&h).is_none() {
                continue;
            }
            if seen.insert(h.clone()) {
                page.push(h);
            }
        }
        let mut budget = ANCESTOR_BUDGET;
        let mut steps = 0usize;
        let mut idx = 0usize;
        while idx < page.len() && budget > 0 && steps < ANCESTOR_STEPS {
            steps += 1;
            let h = page[idx].clone();
            idx += 1;
            let parents: [[u8; 32]; 2] = match get_transaction_by_hash(&h) {
                Some(tx) => tx.parents,
                None => continue,
            };
            for parent in parents.iter() {
                if *parent == [0u8; 32] {
                    continue;
                }
                let key = parent.to_vec();
                if seen.contains(&key) {
                    continue;
                }
                if get_transaction_by_hash(&key).is_none() {
                    continue;
                }
                seen.insert(key.clone());
                page.push(key);
                budget -= 1;
                if budget == 0 {
                    break;
                }
            }
        }
        page
    }

    /// DEEP SYNC: compute the full ancestor closure of a set of requested
    /// transaction hashes. The result includes ALL ancestors reachable from
    /// the requested set, bounded by `max_entries` (CPU/memory protection).
    ///
    /// Unlike the previous `ancestor_closed_page` with its fixed ANCESTOR_BUDGET
    /// of 400, this function computes the FULL closure up to the bound, ensuring
    /// that the served page is self-sufficient for bottom-up insertion.
    ///
    /// Returns hashes in an UNORDERED set. The caller must topologically sort
    /// the result before sending.
    pub(crate) fn ancestor_full_closure(
        requested: &[Vec<u8>],
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
        max_entries: usize,
    ) -> Vec<Vec<u8>> {
        let mut closure: Vec<Vec<u8>> = Vec::with_capacity(requested.len().min(max_entries));
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut steps = 0usize;
        // Seed with requested hashes (only those that exist in the DAG).
        for h in requested {
            if get_transaction_by_hash(h).is_none() {
                continue;
            }
            if seen.insert(h.clone()) {
                closure.push(h.clone());
            }
        }
        // BFS walk: for each hash in the closure, append its parents.
        let mut idx = 0usize;
        while idx < closure.len()
            && closure.len() < max_entries
            && steps < crate::sync_stats::TOPO_ORDER_CAP
        {
            steps += 1;
            let h = closure[idx].clone();
            idx += 1;
            let parents: [[u8; 32]; 2] = match get_transaction_by_hash(&h) {
                Some(tx) => tx.parents,
                None => continue,
            };
            for parent in parents.iter() {
                if *parent == [0u8; 32] {
                    continue;
                }
                let key = parent.to_vec();
                if seen.contains(&key) {
                    continue;
                }
                if get_transaction_by_hash(&key).is_none() {
                    continue;
                }
                seen.insert(key.clone());
                closure.push(key);
                if closure.len() >= max_entries {
                    break;
                }
            }
        }
        closure
    }

    /// B4: deterministic dependency order of the local DAG (parents before
    /// children, Kahn's algorithm with a sorted queue for a stable result).
    /// Returns None above `TOPO_ORDER_CAP` (cost guard): the caller then falls
    /// back to the request order.
    fn topological_order(
        hashes: Vec<Vec<u8>>,
        get_transaction_by_hash: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> Option<Vec<Vec<u8>>> {
        if hashes.is_empty() || hashes.len() > TOPO_ORDER_CAP {
            return None;
        }
        let mut indeg: HashMap<Vec<u8>, usize> = hashes.iter().map(|h| (h.clone(), 0)).collect();
        let mut children: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
        for h in &hashes {
            if let Some(tx) = get_transaction_by_hash(h) {
                for parent in tx.parents.iter() {
                    if *parent == [0u8; 32] {
                        continue;
                    }
                    if indeg.contains_key(parent.as_slice()) {
                        // C2-004 FIX: indeg[h] counts h's UNMET PARENT
                        // dependencies (Kahn). The previous code incremented
                        // the PARENT's counter (i.e. counted children), which
                        // emitted tips-first: joining nodes parked every batch
                        // as orphans and the re-request storm collapsed serving
                        // nodes at ~10k txs. Parents-first lets joiners insert
                        // immediately.
                        *indeg.get_mut(h).expect("topological_order: h must be in indeg") += 1;
                    }
                    children.entry(parent.to_vec()).or_default().push(h.clone());
                }
            }
        }
        let mut queue: Vec<Vec<u8>> = indeg
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(h, _)| h.clone())
            .collect();
        queue.sort();
        let mut order = Vec::with_capacity(hashes.len());
        while let Some(h) = queue.pop() {
            order.push(h.clone());
            if let Some(kids) = children.get(&h) {
                for kid in kids {
                    let d = indeg.get_mut(kid).expect("topological_order: kid must be in indeg");
                    *d -= 1;
                    if *d == 0 {
                        queue.push(kid.clone());
                    }
                }
            }
        }
        if order.len() != hashes.len() {
            // Cyclic references cannot exist (validation rejects them), but
            // never return a partial order: fall back to the caller's order.
            return None;
        }
        Some(order)
    }

    /// B4: split a sync batch into (deliverable now) / (waiting for parents)
    /// using dependency-aware passes. A tx is deliverable when BOTH parents
    /// are in the DAG or were accepted earlier in this batch (a parent that
    /// is itself still waiting keeps the child waiting too). The result is
    /// INDEPENDENT of the batch order: any permutation of the same tx set
    /// with the same DAG yields the same partition.
    fn partition_batch(
        batch: Vec<(Vec<u8>, Transaction)>,
        has_in_dag: &(dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync),
    ) -> (Vec<(Vec<u8>, Transaction)>, Vec<(Vec<u8>, Transaction)>) {
        use std::collections::HashSet;
        let mut inserted: HashSet<[u8; 32]> = HashSet::new();
        let mut pending = batch;
        let mut deliverable = Vec::new();
        loop {
            let before = pending.len();
            let mut still = Vec::new();
            for item in pending {
                let (_, tx) = &item;
                let p0_ok = tx.parents[0] == [0u8; 32]
                    || inserted.contains(&tx.parents[0])
                    || has_in_dag(tx.parents[0].as_slice()).is_some();
                let p1_ok = tx.parents[1] == [0u8; 32]
                    || inserted.contains(&tx.parents[1])
                    || has_in_dag(tx.parents[1].as_slice()).is_some();
                if p0_ok && p1_ok {
                    inserted.insert(tx.id);
                    deliverable.push(item);
                } else {
                    still.push(item);
                }
            }
            pending = still;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        (deliverable, pending)
    }

    /// Request a specific transaction by hash from all peers.
    ///
    /// B4: bounded + backoff. The missing-parent set is deduplicated so a
    /// parent is re-requested at most once per cooldown (escalating 2s/5s/15s
    /// by attempt count). Previously every parked orphan re-requested its
    /// parents unconditionally: the resulting 1-tx GetData flood starved the
    /// real sync batches and the bootstrap froze (B4 livelock).
    pub async fn request_transaction(&self, hash: Vec<u8>) {
        {
            let mut reqs = self.sync_ctx.requested_parents.write().await;
            if reqs.len() >= crate::sync_stats::MAX_INFLIGHT_PARENTS {
                // Evict the least recently requested entry (bounded memory).
                let oldest_key: Option<Vec<u8>> = reqs
                    .iter()
                    .min_by_key(|(_, (last, _))| *last)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    reqs.remove(&key);
                }
            }
            let now = Instant::now();
            if let Some((last, attempts)) = reqs.get_mut(&hash) {
                let cooldown = crate::sync_stats::SyncContext::backoff_for(*attempts);
                if now.duration_since(*last) < cooldown {
                    self.sync_ctx
                        .stats
                        .parent_already_known
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                *last = now;
                *attempts += 1;
            } else {
                reqs.insert(hash.clone(), (now, 1));
            }
        }

        self.sync_ctx
            .stats
            .parent_requested
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let msg = P2PMessage::GetData(vec![hash.clone()]);
        let msg_bytes = match bincode::serialize(&msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize GetData message: {}", e);
                return;
            }
        };

        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            if sender.send(msg_bytes.clone()).is_err() {
                warn!("Failed to send GetData request to {}: channel closed", addr);
            }
        }
    }

    /// V-22 FIX: request the inventory window from every connected peer.
    ///
    /// The peer answers with a bounded `Inventory` window (2E-A: capped at
    /// `MAX_INV_ITEMS` and rotated per request, so the frame length stops
    /// revealing the DAG size), we diff it against our DAG and fetch what we
    /// are missing via GetData. Called periodically (see the node's 10s
    /// maintenance loop) and after boot, so a node that missed transactions
    /// while offline - or received a stale inventory at handshake time -
    /// keeps reconciling until it converges to the exact same transaction set
    /// as its peers. The rotation means every window is a fresh slice, so the
    /// same convergence holds without ever sending the whole set in one
    /// frame. This never assumes the node already knows the parents: missing
    /// ancestors are fetched recursively through the orphan flow.
    pub async fn request_full_sync(&self) {
        let msg = match bincode::serialize(&P2PMessage::SyncRequest) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize SyncRequest: {}", e);
                return;
            }
        };
        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            debug!("[Sync] Requesting full inventory from {}", addr);
            if sender.send(msg.clone()).is_err() {
                warn!("Failed to send SyncRequest to {}: channel closed", addr);
            }
        }
    }

    /// PHASE 4I (F-D3): announce known vote ids to every connected peer
    /// (bounded at MAX_INV_ITEMS: validator-scale, no rotation needed -
    /// callers pass the full sorted set and it fits; oversized sets are
    /// truncated deterministically by sort order... callers sort first).
    /// Peers answer GetVotes for the ids they lack; admission is
    /// idempotent, so announcements are safe to repeat every sync cycle.
    pub async fn announce_vote_inventory(&self, mut vote_ids: Vec<Vec<u8>>) {
        vote_ids.sort();
        vote_ids.truncate(MAX_INV_ITEMS);
        let msg = match bincode::serialize(&P2PMessage::VoteInventory(vote_ids)) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to serialize VoteInventory: {}", e);
                return;
            }
        };
        let peers = self.peers.read().await;
        for (addr, sender) in peers.iter() {
            debug!("[Sync] Announcing vote inventory to {}", addr);
            if sender.send(msg.clone()).is_err() {
                warn!("Failed to send VoteInventory to {}: channel closed", addr);
            }
        }
    }
}

#[cfg(test)]
mod phase2_decentralized_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn net_with(bootnodes: Vec<SocketAddr>) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes,
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
})
    }

    /// A node wired to a specific on-disk peer store (Phase 2B store tests).
    fn net_at(path: std::path::PathBuf) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
})
    }

    fn net_at_config(cfg: P2PConfig) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt,
            empty,
            sync_ctx,
            is_orphan,
        )
    }

    fn banned_score() -> PeerScore {
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        s
    }

    /// PHASE2-2A / PRINCIPE 2: seeds are ordinary fallbacks in the redial
    /// ordering. A peer the node already knows always outranks an unknown seed,
    /// so one dead seed can no longer monopolise the redial cycle.
    #[test]
    fn test_seeds_are_unprivileged_in_redial() {
        let local = addr("127.0.0.1:31001");
        let seed1 = addr("10.0.0.1:25565");
        let seed2 = addr("10.0.0.2:25565");
        let peer_a = addr("203.0.113.10:25565");
        let peer_b = addr("203.0.113.11:25565");

        let known = vec![peer_a, peer_b, seed1]; // a seed may also already be a known peer

        let out = P2PNetwork::redial_candidates(&known, &[seed1, seed2], local);

        assert_eq!(out.iter().filter(|a| **a == peer_a).count(), 1);
        assert_eq!(out.iter().filter(|a| **a == peer_b).count(), 1);
        assert!(
            out.iter().filter(|a| **a == seed1).count() == 1,
            "seed already known must not be duplicated"
        );
        assert!(out.contains(&seed2), "unconfigured-seen seed still reachable");
        assert!(!out.contains(&local), "own listen address must never be dialled");

        let first_known = out
            .iter()
            .position(|a| *a == peer_a || *a == peer_b)
            .expect("known peers must be present");
        let last_seed = out.iter().position(|a| *a == seed2).unwrap();
        assert!(
            first_known < last_seed,
            "known peers must be redialled before an unknown seed"
        );
    }

    /// PHASE2-2A / PRINCIPE 1: a node that never configured any seed still has a
    /// usable candidate set — discovery does not require a bootnode.
    #[test]
    fn test_redial_candidates_without_any_seed() {
        let local = addr("127.0.0.1:31001");
        let peer = addr("203.0.113.77:25565");
        let known = vec![peer, local];

        let out = P2PNetwork::redial_candidates(&known, &[], local);
        assert_eq!(out, vec![peer]);
    }

    /// PHASE2-2A / PRINCIPE 1: outbound dials must respect the ban table.
    /// Inbound connections have always checked it; outbound never did.
    #[tokio::test]
    async fn test_outbound_dial_blocked_for_banned_peer() {
        let net = net_with(vec![]);
        let banned = addr("203.0.113.50:25565");
        let clean = addr("203.0.113.51:25565");

        assert!(
            !net.outbound_dial_blocked(banned).await,
            "unknown address is not blocked"
        );

        net.addresses
            .write()
            .await
            .scores_mut()
            .insert(banned, banned_score());

        assert!(
            net.outbound_dial_blocked(banned).await,
            "banned peer must not be redialled outbound"
        );
        assert!(
            !net.outbound_dial_blocked(clean).await,
            "clean peer must stay dialable"
        );
    }

    /// PHASE2-2A / PRINCIPE 3: PEX must not re-share addresses we banned, nor
    /// our own listen address (which would let peers dial us back pointlessly
    /// and would leak a self-reference into the address pool).
    #[test]
    fn test_pex_omits_banned_and_local() {
        let local = addr("127.0.0.1:31001");
        let good = addr("203.0.113.10:25565");
        let banned = addr("203.0.113.66:25565");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        for a in [local, good, banned] {
            entries.insert(a, AddressEntry::new(PeerSource::Pex, 1, Instant::now()));
        }

        let mut scores = HashMap::new();
        scores.insert(banned, banned_score());

        let out = P2PNetwork::pex_broadcast_list(&entries, &scores, local);
        assert_eq!(out.len(), 1, "only the healthy address is shared");
        assert!(out.contains(&good));
        assert!(!out.contains(&local));
        assert!(!out.contains(&banned));
    }

    /// PHASE2-2A: a peer with a live session must never have its TTL clock
    /// expire. Before this fix the clock was only touched at handshake and at
    /// disconnect, so a reliably-connected peer was dropped from the store.
    #[tokio::test]
    async fn test_connected_peer_survives_ttl_refresh() {
        let net = net_with(vec![]);
        let live = addr("203.0.113.20:25565");
        let idle = addr("203.0.113.21:25565");

        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(live, PeerSource::Pex, unix_now(), Instant::now());
            mgr.observe(idle, PeerSource::Pex, unix_now(), Instant::now());
        }

        // A live session exists for `live` only.
        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        net.peers.write().await.insert(live, tx);

        let idle_clock = net
            .addresses
            .read()
            .await
            .entry(idle)
            .expect("idle is a known address")
            .last_seen;
        let before = Instant::now();
        net.refresh_live_peer_clocks().await;
        let after = Instant::now();

        let mgr = net.addresses.read().await;
        let refreshed = mgr
            .entry(live)
            .expect("live peer must have a clock")
            .last_seen;
        assert!(
            refreshed >= before && refreshed <= after,
            "live session clock must be refreshed to now"
        );
        assert!(
            refreshed.elapsed() < PEER_TTL,
            "a live session must stay inside the TTL window"
        );
        // `idle` has no session, so the refresh pass must leave its clock alone.
        assert_eq!(
            mgr.entry(idle).unwrap().last_seen,
            idle_clock,
            "an address with no session must not have its TTL clock touched"
        );
    }

    /// PHASE2-2A: one redial cycle must never attempt more dials than the
    /// connection cap allows — that is what keeps a large stale peer store from
    /// turning a cycle into an hours-long serial sweep.
    #[test]
    fn test_redial_cycle_budget_is_sane() {
        assert!(MAX_REDIAL_PER_CYCLE >= 1);
        assert!(
            MAX_REDIAL_PER_CYCLE <= MAX_PEERS,
            "per-cycle budget must not exceed the connection cap"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 2B — distributed peer manager
    // -----------------------------------------------------------------------

    /// PHASE2-2B / D8 / R3: a pre-versioned store (bare JSON array of address
    /// strings) must still load instead of being silently discarded, then be
    /// upgraded to schema v2 on the next flush.
    #[tokio::test]
    async fn test_peer_store_legacy_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let a = addr("203.0.113.20:25565");
        let b = addr("203.0.113.21:25565");
        std::fs::write(
            &path,
            serde_json::to_string(&vec![a.to_string(), b.to_string()]).unwrap(),
        )
        .unwrap();

        let net = net_at(path.clone());
        net.load_known_peers().await;
        {
            let mgr = net.addresses.read().await;
            assert_eq!(mgr.len(), 2, "legacy addresses must not be lost");
            assert!(mgr.contains(a) && mgr.contains(b));
            assert_eq!(
                mgr.entry(a).unwrap().source,
                PeerSource::Restored,
                "every legacy address gains metadata"
            );
        }

        net.save_known_peers().await;
        let file: PeerStoreFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file.version, PEER_STORE_VERSION, "legacy store upgrades to v2");
        assert_eq!(file.entries.len(), 2);
    }

    /// PHASE2-2B / D8: schema v2 round-trips the metadata v1 could not express —
    /// source, success time, attempt counts, quality and the anchor flag.
    #[tokio::test]
    async fn test_peer_store_v2_roundtrip_with_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let a = addr("203.0.113.10:25565");
        let b = addr("203.0.113.11:25565");

        {
            let net = net_at(path.clone());
            {
                let mut mgr = net.addresses.write().await;
                mgr.observe(a, PeerSource::Pex, 1_000_000, Instant::now());
                mgr.observe(b, PeerSource::Dns, 1_000_100, Instant::now());
                let ea = mgr.entries_mut().get_mut(&a).expect("just inserted");
                ea.record_success(1_000_500);
                ea.anchor = true;
            }
            net.save_known_peers().await;
        }

        let file: PeerStoreFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(file.version, PEER_STORE_VERSION);
        assert_eq!(file.entries.len(), 2);

        let net2 = net_at(path);
        net2.load_known_peers().await;
        let mgr = net2.addresses.read().await;
        assert_eq!(mgr.len(), 2);
        assert!(mgr.contains(a) && mgr.contains(b));
        let ma = mgr.entry(a).expect("metadata must be restored");
        assert_eq!(ma.source, PeerSource::Pex);
        assert_eq!(ma.last_success, Some(1_000_500));
        assert_eq!(ma.attempts, 1);
        assert!(ma.quality > default_peer_quality());
        assert!(ma.anchor, "the anchor flag must survive a restart");
        let mb = mgr.entry(b).expect("metadata must be restored");
        assert_eq!(mb.source, PeerSource::Dns);
        assert!(mb.last_success.is_none());
        assert!(!mb.anchor);
    }

    /// PHASE2-2B / D5: the send side relays a bounded sample, never the whole
    /// table, and never the recipient's own address back at it.
    #[test]
    fn test_pex_send_bounded() {
        let local = addr("127.0.0.1:31001");
        let recipient = addr("198.51.100.9:25565");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        for i in 0..500u16 {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 30000 + i)
                .parse()
                .unwrap();
            entries.insert(a, AddressEntry::new(PeerSource::Pex, 1, Instant::now()));
        }
        entries.insert(
            local,
            AddressEntry::new(PeerSource::Restored, 1, Instant::now()),
        );
        let scores = HashMap::new();
        let origins = HashMap::new();

        let out = pex_sample(
            &entries,
            &scores,
            &origins,
            local,
            recipient,
            10,
            PEX_MAX_SEND,
        );
        assert_eq!(out.len(), PEX_MAX_SEND, "send side must be capped");
        assert!(
            out.len() < entries.len(),
            "must not relay the entire table"
        );
        assert!(!out.contains(&local), "never send our own address");
        assert!(!out.contains(&recipient), "never send the address back to its owner");
        let unique: HashSet<SocketAddr> = out.iter().copied().collect();
        assert_eq!(unique.len(), out.len(), "no duplicates in one message");
    }

    /// PHASE2-2B / D5: an address the recipient itself gave us is never echoed
    /// straight back to it, and hints old enough stop being gossiped.
    #[test]
    fn test_pex_origin_and_aging() {
        let local = addr("127.0.0.1:31001");
        let recipient = addr("198.51.100.9:25565");
        let from_recipient = addr("203.0.113.60:25565");
        let fresh = addr("203.0.113.61:25565");
        let stale = addr("203.0.113.62:25565");

        let now = 10_000_000u64;
        let aged_out = now - PEX_SHARE_MAX_AGE_SECS - 10;
        assert!(aged_out > 0, "test clock must stay positive");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        entries.insert(
            from_recipient,
            AddressEntry::new(PeerSource::Pex, now, Instant::now()),
        );
        entries.insert(
            fresh,
            AddressEntry::new(PeerSource::Pex, now, Instant::now()),
        );
        entries.insert(
            stale,
            AddressEntry::new(PeerSource::Pex, aged_out, Instant::now()),
        );

        // `from_recipient` is exactly the hint `recipient` sent us.
        let mut origins = HashMap::new();
        origins.insert(from_recipient, recipient);

        let scores = HashMap::new();

        let out = pex_sample(
            &entries,
            &scores,
            &origins,
            local,
            recipient,
            now,
            PEX_MAX_SEND,
        );
        assert!(out.contains(&fresh), "a fresh address is shared");
        assert!(!out.contains(&from_recipient), "never echo back to the source");
        assert!(!out.contains(&stale), "aged-out hints stop being gossiped");
    }

    /// PHASE2-2B / D6: a PEX hint may never point at a private, loopback,
    /// link-local or otherwise reserved host — that is exactly how a peer
    /// steers us into dialing its own LAN or our own loopback services.
    #[test]
    fn test_pex_ignores_private_addresses() {
        for s in [
            "127.0.0.1:30333",
            "10.1.2.3:30333",
            "172.16.0.1:30333",
            "172.31.255.255:30333",
            "192.168.1.1:30333",
            "169.254.5.5:30333",
            "100.64.0.1:30333",
            "100.127.255.255:30333",
            "0.0.0.0:30333",
            "224.0.0.1:30333",
            "240.0.0.1:30333",
            "255.255.255.255:30333",
            "[::1]:30333",
            "[::]:30333",
            "[fe80::1]:30333",
            "[fc00::1]:30333",
            "[fd12:3456::1]:30333",
            "[ff02::1]:30333",
            "[::ffff:192.168.0.1]:30333",
        ] {
            assert!(is_private_or_reserved(addr(s)), "{} must be filtered", s);
        }

        for s in [
            "203.0.113.10:30333",
            "198.51.100.7:30333",
            "1.1.1.1:30333",
            "8.8.8.8:30333",
            "[2001:4860:4860::8888]:30333",
        ] {
            assert!(!is_private_or_reserved(addr(s)), "{} must stay dialable", s);
        }
    }

    /// PHASE2-2B / R4: the private-address gate applies ONLY to PEX-sourced
    /// dials. An operator-configured bootnode on a LAN stays dialable, or
    /// private/LAN testnets break.
    #[test]
    fn test_pex_still_dials_operator_bootnode() {
        let local = addr("127.0.0.1:31001");
        let lan_boot = addr("192.168.1.50:30333");
        let public_peer = addr("203.0.113.5:25565");

        let known = vec![public_peer];
        let out = P2PNetwork::redial_candidates(&known, &[lan_boot], local);
        assert!(
            out.contains(&lan_boot),
            "an operator bootnode must not be gated by the PEX filter"
        );
        assert!(
            is_private_or_reserved(lan_boot),
            "the address itself is private; only the PEX path consults this"
        );
    }

    /// PHASE2-2B / D9: anchors are several and bounded — never one, never
    /// unbounded — and rotate in favour of the most recent successful contact.
    #[test]
    fn test_anchor_rotation_bounded() {
        let local = addr("127.0.0.1:31001");
        let current: Vec<(SocketAddr, u64)> = Vec::new();

        let mut candidates: Vec<(SocketAddr, u64)> = Vec::new();
        for i in 0..20u8 {
            let a = addr(&format!("203.0.113.{}:25565", i + 1));
            candidates.push((a, 1_000 + u64::from(i)));
        }

        let out = promote_anchors(&current, &candidates, local);
        assert!(out.len() <= MAX_ANCHORS, "anchor set must be bounded");
        assert!(out.len() >= MIN_ANCHORS, "enough anchors for resilience");
        assert!(out.len() > 1, "anchors must never collapse to a single point");

        // Rotation keeps the most recently successful candidates (1_019 .. 1_012).
        let kept: Vec<u64> = out
            .iter()
            .map(|a| candidates.iter().find(|(x, _)| x == a).unwrap().1)
            .collect();
        let min_kept = kept.iter().copied().min().unwrap();
        assert!(
            min_kept >= 1_000 + 20 - MAX_ANCHORS as u64,
            "rotation must retain the freshest anchors (min={})",
            min_kept
        );

        // The local address can never become an anchor.
        let mut with_local = candidates.clone();
        with_local.push((local, 9_999_999));
        let out2 = promote_anchors(&current, &with_local, local);
        assert!(!out2.contains(&local));
        assert!(out2.len() <= MAX_ANCHORS);

        // Re-promotion does not duplicate or grow the set.
        let again = promote_anchors(&current, &out2.iter().map(|a| (*a, 1)).collect::<Vec<_>>(), local);
        assert_eq!(again.len(), out2.len());
    }

    /// PHASE2-2B / D9: anchors are replaceable and expire — a dead one is
    /// dropped rather than kept as a permanent authority.
    #[test]
    fn test_anchor_expiry() {
        let a = addr("203.0.113.40:25565");
        let b = addr("203.0.113.41:25565");
        let now = 10_000_000u64;

        let anchors = vec![(a, now - ANCHOR_TTL_SECS - 1), (b, now)];
        let dead = expire_anchors(&anchors, now);
        assert_eq!(dead, vec![a], "anchors past the TTL must be expired");

        let dead2 = expire_anchors(&anchors, now - ANCHOR_TTL_SECS);
        assert!(dead2.is_empty(), "anchors still inside the TTL stay");
    }

    /// PHASE2-2B / D7: the five categories are derived from live state, with
    /// security first — a penalized peer is never counted as active, and a live
    /// session outranks an anchor's standing.
    #[test]
    fn test_categories_derived_from_state() {
        let now = 50_000_000u64;
        let recent = now - 60;
        let stale = now - RECENT_PEER_WINDOW_SECS - 1;

        assert_eq!(
            categorise(false, false, false, None, now),
            PeerCategory::Candidate
        );
        assert_eq!(
            categorise(true, false, false, None, now),
            PeerCategory::Active
        );
        assert_eq!(
            categorise(false, false, false, Some(recent), now),
            PeerCategory::Recent
        );
        assert_eq!(
            categorise(false, true, false, Some(stale), now),
            PeerCategory::Anchor
        );
        assert_eq!(
            categorise(false, true, false, None, now),
            PeerCategory::Anchor,
            "an anchor never degrades to a mere candidate"
        );
        assert_eq!(
            categorise(false, false, false, Some(stale), now),
            PeerCategory::Candidate,
            "a success outside the recent window leaves it a candidate"
        );
        // Security first: penalized beats active and anchor alike.
        assert_eq!(
            categorise(true, true, true, Some(recent), now),
            PeerCategory::Penalized
        );
        // Liveness beats standing.
        assert_eq!(
            categorise(true, true, false, Some(recent), now),
            PeerCategory::Active
        );
    }

    /// PHASE2-2B / D8: at capacity the store evicts its weakest entry instead
    /// of refusing newcomers, so a hostile PEX burst cannot fill the table with
    /// junk and then freeze it. Live sessions and anchors are never victims.
    #[test]
    fn test_quality_eviction_replaces_junk() {
        let incoming = addr("203.0.113.80:25565");

        let mut entries: HashMap<SocketAddr, AddressEntry> = HashMap::new();
        for i in 0..MAX_KNOWN_PEERS {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 20000 + i as u16)
                .parse()
                .unwrap();
            let mut e = AddressEntry::new(PeerSource::Pex, 1, Instant::now());
            e.quality = 1;
            e.failures = 10;
            entries.insert(a, e);
        }
        assert_eq!(entries.len(), MAX_KNOWN_PEERS, "table must start full");

        let scores = HashMap::new();
        let connected: HashSet<SocketAddr> = HashSet::new();

        let victim = admit_peer(&entries, &scores, &connected, incoming, PEER_QUALITY_MAX)
            .expect("a full table of junk must yield a victim");
        assert_eq!(
            entries.get(&victim).unwrap().quality,
            1,
            "the weakest entry must be the victim"
        );

        // An address weaker than everything present displaces nobody.
        let weaker = admit_peer(&entries, &scores, &connected, incoming, 0);
        assert!(weaker.is_none(), "a worse address must not displace anyone");

        // A live session is never evicted to make room.
        let all_connected: HashSet<SocketAddr> = entries.keys().copied().collect();
        assert!(
            admit_peer(
                &entries,
                &scores,
                &all_connected,
                incoming,
                PEER_QUALITY_MAX
            )
            .is_none(),
            "a connected peer must never be evicted"
        );

        // Neither is an anchor.
        let mut anchored = entries.clone();
        for e in anchored.values_mut() {
            e.anchor = true;
        }
        assert!(
            admit_peer(&anchored, &scores, &connected, incoming, PEER_QUALITY_MAX).is_none(),
            "anchors must never be evicted"
        );

        // A banned entry is the first victim even when its quality looks fine.
        let banned_addr = *entries.keys().next().unwrap();
        let mut scores2 = HashMap::new();
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        scores2.insert(banned_addr, s);
        let mut entries2 = entries.clone();
        entries2.get_mut(&banned_addr).unwrap().quality = PEER_QUALITY_MAX;
        let victim = admit_peer(
            &entries2,
            &scores2,
            &connected,
            incoming,
            PEER_QUALITY_MAX,
        )
        .unwrap();
        assert_eq!(
            victim, banned_addr,
            "a banned entry is always the preferred victim"
        );
    }

    // -----------------------------------------------------------------------
    // AddressManager — the single owner of address state
    //
    // These drive the manager directly. The sixteen tests above cover the same
    // invariants through `P2PNetwork` wiring (on-disk store, PEX loop, TTL
    // task), so nothing here repeats them.
    // -----------------------------------------------------------------------

    /// Membership, TTL clock and metadata enter through `observe`, and
    /// `remove` takes them all back out together.
    #[test]
    fn test_address_manager_insert() {
        let mut mgr = AddressManager::new();
        let a = addr("203.0.113.1:25565");
        let b = addr("203.0.113.2:25565");
        let unknown = addr("203.0.113.3:25565");

        assert_eq!(mgr.len(), 0);
        mgr.observe(a, PeerSource::Dns, 1_000, Instant::now());
        mgr.observe(b, PeerSource::Pex, 1_001, Instant::now());
        assert_eq!(mgr.len(), 2);
        assert!(mgr.contains(a) && mgr.contains(b));
        assert!(!mgr.contains(unknown));

        // Re-observing something we already hold never duplicates it, and the
        // clock is the only thing that moves.
        let clock_before = mgr.entry(a).unwrap().last_seen;
        mgr.observe(a, PeerSource::Pex, 9_999, Instant::now());
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.entry(a).unwrap().first_seen, 1_000, "first_seen is written once");
        assert!(mgr.entry(a).unwrap().last_seen >= clock_before);

        // Eviction removes the entry entirely, twice is reported as removed once.
        assert!(mgr.remove(&b));
        assert!(!mgr.remove(&b));
        assert!(!mgr.contains(b));
        assert_eq!(mgr.len(), 1);
    }

    /// `to_store` / `load_v2` carry every field v1 could not express, and the
    /// node's own address is never round-tripped back into the table.
    #[test]
    fn test_address_manager_metadata_roundtrip() {
        let local = addr("127.0.0.1:31001");
        let a = addr("203.0.113.11:25565");
        let b = addr("203.0.113.12:25565");

        let mut src = AddressManager::new();
        src.observe(a, PeerSource::Pex, 1_000, Instant::now());
        src.record_success(a, 1_500);
        {
            let e = src.entries_mut().get_mut(&a).unwrap();
            e.anchor = true;
            e.failures = 3;
        }
        src.observe(b, PeerSource::Dns, 2_000, Instant::now());
        src.observe(local, PeerSource::Configured, 3_000, Instant::now());

        let file = src.to_store();
        assert_eq!(file.version, PEER_STORE_VERSION);
        assert_eq!(file.entries.len(), 3, "nothing on disk is dropped");

        let mut dst = AddressManager::new();
        assert_eq!(
            dst.load_v2(&file, local, 5_000, Instant::now()),
            2,
            "our own address is skipped on load"
        );
        assert!(!dst.contains(local));

        let ea = dst.entry(a).expect("a must round-trip");
        assert_eq!(ea.source, PeerSource::Pex);
        assert_eq!(ea.first_seen, 1_000);
        assert_eq!(ea.last_success, Some(1_500));
        assert_eq!(ea.attempts, 1);
        assert_eq!(ea.failures, 3);
        assert!(ea.quality > default_peer_quality(), "a success raises quality");
        assert!(ea.anchor, "the anchor flag must survive");

        let eb = dst.entry(b).expect("b must round-trip");
        assert_eq!(eb.source, PeerSource::Dns);
        assert_eq!(eb.first_seen, 2_000);
        assert!(eb.last_success.is_none());
        assert!(!eb.anchor);
    }

    /// R3: a bare `Vec<String>` from a pre-versioned store is adopted rather
    /// than discarded — skipping anything unparseable and our own address.
    #[test]
    fn test_address_manager_legacy_fallback() {
        let local = addr("127.0.0.1:31001");
        let a = addr("203.0.113.21:25565");
        let b = addr("203.0.113.22:25565");
        let legacy = vec![
            a.to_string(),
            "not-an-address".to_string(),
            b.to_string(),
            local.to_string(),
        ];

        let mut mgr = AddressManager::new();
        assert_eq!(mgr.load_legacy(&legacy, local, 7_000, Instant::now()), 2);
        assert!(mgr.contains(a) && mgr.contains(b));
        assert!(!mgr.contains(local), "our own address is never adopted");
        let ea = mgr.entry(a).unwrap();
        assert_eq!(ea.source, PeerSource::Restored, "v1 carried no origin");
        assert_eq!(ea.first_seen, 7_000, "v1 carried no clock");
        assert!(ea.last_success.is_none());
    }

    /// D8: the three admission outcomes — adopted, already present, and
    /// refused because nothing present is worth displacing.
    #[test]
    fn test_address_manager_admission() {
        let connected = HashSet::new();
        let mut mgr = AddressManager::new();

        let first = addr("203.0.113.31:25565");
        assert_eq!(
            mgr.admit(first, PeerSource::Pex, 50, 1_000, Instant::now(), &connected),
            Admission::Inserted { evicted: None },
            "below capacity the address is simply adopted"
        );
        assert_eq!(
            mgr.admit(first, PeerSource::Dns, 50, 1_000, Instant::now(), &connected),
            Admission::AlreadyKnown,
            "admitting twice never duplicates"
        );

        // Fill to capacity with junk so a newcomer must displace someone.
        let mut junk: Vec<SocketAddr> = Vec::new();
        for i in 0..(MAX_KNOWN_PEERS - 1) {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 40000 + i as u16)
                .parse()
                .unwrap();
            mgr.observe(a, PeerSource::Pex, 1, Instant::now());
            mgr.entries_mut().get_mut(&a).unwrap().quality = 1;
            junk.push(a);
        }
        assert_eq!(mgr.len(), MAX_KNOWN_PEERS, "table is at capacity");

        let newcomer = addr("198.51.100.77:25565");
        match mgr.admit(
            newcomer,
            PeerSource::Pex,
            PEER_QUALITY_MAX,
            1_000,
            Instant::now(),
            &connected,
        ) {
            Admission::Inserted { evicted: Some(victim) } => {
                assert!(
                    junk.contains(&victim),
                    "only an existing junk entry can be displaced"
                );
                assert!(!mgr.contains(victim), "the victim must be gone");
            }
            other => panic!("a full table of junk must evict, got {:?}", other),
        }
        assert_eq!(mgr.len(), MAX_KNOWN_PEERS, "capacity stays a hard cap");
        assert!(mgr.contains(newcomer));

        // A table where nothing is worth dropping refuses instead.
        let mut keepers = AddressManager::new();
        for i in 0..MAX_KNOWN_PEERS {
            let a: SocketAddr = format!("198.51.100.{}:{}", (i % 254) + 1, 50000 + i as u16)
                .parse()
                .unwrap();
            keepers.observe(a, PeerSource::Dns, 1, Instant::now());
            keepers.entries_mut().get_mut(&a).unwrap().anchor = true;
        }
        assert_eq!(
            keepers.admit(
                newcomer,
                PeerSource::Pex,
                PEER_QUALITY_MAX,
                1_000,
                Instant::now(),
                &connected
            ),
            Admission::Refused,
            "anchors are never displaced, so the newcomer is refused"
        );
    }

    /// D8: live sessions are protected even when every other entry is equally
    /// worthless, so a full table can never evict its own working peers.
    #[test]
    fn test_address_manager_quality_eviction() {
        let mut mgr = AddressManager::new();
        let mut all: Vec<SocketAddr> = Vec::new();
        for i in 0..MAX_KNOWN_PEERS {
            let a: SocketAddr = format!("203.0.113.{}:{}", (i % 254) + 1, 60000 + i as u16)
                .parse()
                .unwrap();
            mgr.observe(a, PeerSource::Pex, 1, Instant::now());
            mgr.entries_mut().get_mut(&a).unwrap().quality = 1;
            all.push(a);
        }

        let live = all[0];
        let mut live_set = HashSet::new();
        live_set.insert(live);

        let newcomer = addr("198.51.100.88:25565");
        let Admission::Inserted { evicted: Some(victim) } = mgr.admit(
            newcomer,
            PeerSource::Pex,
            PEER_QUALITY_MAX,
            1_000,
            Instant::now(),
            &live_set,
        ) else {
            panic!("a full table must yield a victim");
        };
        assert_ne!(victim, live, "a live session is never evicted");
        assert!(!mgr.contains(victim));
        assert!(mgr.contains(live), "the working peer stays");
        assert!(mgr.contains(newcomer));
    }

    /// D9: anchors come only from sessions that completed a handshake, are
    /// applied as a whole set, and record their promotion as a source change.
    #[test]
    fn test_address_manager_anchor_rotation() {
        let local = addr("127.0.0.1:31001");
        let a = addr("203.0.113.41:25565");
        let b = addr("203.0.113.42:25565");
        let c = addr("203.0.113.43:25565");
        let d = addr("203.0.113.44:25565");

        let mut mgr = AddressManager::new();
        for x in [a, b, c, d] {
            mgr.observe(x, PeerSource::Pex, 1, Instant::now());
        }
        // `c` never reaches a handshake, so it can never become an anchor.
        mgr.record_success(a, 100);
        mgr.record_success(b, 200);
        mgr.record_success(d, 300);

        let live: HashSet<SocketAddr> = [a, b, d].into_iter().collect();
        let candidates = mgr.anchor_candidates(&live);
        assert_eq!(candidates.len(), 3, "only proven sessions are candidates");
        assert!(
            !candidates.iter().any(|(x, _)| *x == c),
            "an address with no success is never a candidate"
        );
        // A known address with no live session is not a candidate either.
        let idle_live: HashSet<SocketAddr> = [c].into_iter().collect();
        assert!(mgr.anchor_candidates(&idle_live).is_empty());

        let wanted = promote_anchors(&[], &candidates, local);
        assert!(wanted.len() <= MAX_ANCHORS && wanted.len() >= MIN_ANCHORS);
        let (promoted, demoted) = mgr.apply_anchors(&wanted);
        assert_eq!(promoted, wanted.len(), "they were plain addresses before");
        assert_eq!(demoted, 0);
        assert_eq!(mgr.anchor_addresses().len(), wanted.len());
        assert_eq!(
            mgr.entry(a).unwrap().source,
            PeerSource::Anchor,
            "promotion records how the address became an anchor"
        );

        // Shrinking the wanted set demotes, never silently keeps stale anchors.
        let (promoted2, demoted2) = mgr.apply_anchors(&[a].into_iter().collect::<HashSet<_>>());
        assert_eq!(promoted2, 0);
        assert_eq!(demoted2, 2);
        assert!(!mgr.entry(b).unwrap().anchor);
        assert_eq!(
            mgr.anchor_addresses(),
            vec![(a, 100)],
            "the surviving anchor keeps its last-success time"
        );
    }

    /// D9 + Phase 1 TTL: an address we stop hearing from is swept out of the
    /// table — and an anchor among them stops being an anchor.
    #[test]
    fn test_address_manager_anchor_expiry() {
        let stale = addr("203.0.113.51:25565");
        let fresh = addr("203.0.113.52:25565");

        let mut mgr = AddressManager::new();
        mgr.observe(stale, PeerSource::Dns, 1, Instant::now());
        mgr.observe(fresh, PeerSource::Dns, 2, Instant::now());
        mgr.record_success(stale, 10);
        mgr.entries_mut().get_mut(&stale).unwrap().anchor = true;
        assert_eq!(mgr.anchor_addresses().len(), 1);

        // Give the sweep a window: `fresh` is reachable, `stale` is not.
        std::thread::sleep(Duration::from_millis(10));
        let mut live = HashSet::new();
        live.insert(fresh);
        let (refreshed, expired) =
            mgr.refresh_and_expire(&live, Instant::now(), Duration::from_millis(1));

        assert_eq!(refreshed, 1, "the live session's clock was refreshed");
        assert_eq!(expired, 1, "only the unheard-from address is swept");
        assert!(!mgr.contains(stale));
        assert!(mgr.contains(fresh), "a refreshed address stays");
        assert!(
            mgr.anchor_addresses().is_empty(),
            "an expired anchor stops being an anchor"
        );
    }

    /// D5: the per-recipient sample honours the recipient exclusion, origin
    /// echo suppression, PEX aging, the ban table and our own listen address.
    #[test]
    fn test_address_manager_pex_sampling() {
        let local = addr("127.0.0.1:31001");
        let recipient = addr("198.51.100.9:25565");
        let from_recipient = addr("203.0.113.61:25565");
        let fresh = addr("203.0.113.62:25565");
        let stale = addr("203.0.113.63:25565");
        let banned = addr("203.0.113.64:25565");

        let now = 10_000_000u64;
        let aged_out = now - PEX_SHARE_MAX_AGE_SECS - 10;
        assert!(aged_out > 0, "test clock must stay positive");

        let mut mgr = AddressManager::new();
        for (a, seen) in [
            (recipient, now),
            (from_recipient, now),
            (fresh, now),
            (stale, aged_out),
            (banned, now),
        ] {
            mgr.observe(a, PeerSource::Pex, seen, Instant::now());
        }
        mgr.observe(local, PeerSource::Restored, now, Instant::now());
        mgr.set_origin(from_recipient, recipient);
        mgr.scores_mut().insert(banned, banned_score());

        let out = mgr.sample_for_pex(local, recipient, now, PEX_MAX_SEND);
        assert!(out.contains(&fresh), "a fresh, healthy address is shared");
        assert!(!out.contains(&recipient), "never send the address back to its owner");
        assert!(!out.contains(&from_recipient), "never echo an address to its own source");
        assert!(!out.contains(&stale), "aged-out hints stop being gossiped");
        assert!(!out.contains(&banned), "we never re-share what we banned");
        assert!(!out.contains(&local), "never send our own listen address");
        assert!(out.len() <= PEX_MAX_SEND, "the sample stays bounded");
    }

    /// The first observer names an address; later hints never relabel it, and
    /// the hint's own origin is tracked separately from that source.
    #[test]
    fn test_address_manager_source_tracking() {
        let a = addr("203.0.113.71:25565");
        let peer = addr("198.51.100.5:25565");
        let mut mgr = AddressManager::new();

        mgr.observe(a, PeerSource::Dns, 1_000, Instant::now());
        assert_eq!(mgr.entry(a).unwrap().source, PeerSource::Dns);

        mgr.observe(a, PeerSource::Pex, 9_999, Instant::now());
        assert_eq!(mgr.entry(a).unwrap().source, PeerSource::Dns, "first observer names it");
        assert_eq!(mgr.entry(a).unwrap().first_seen, 1_000);
        assert!(mgr.origin_of(a).is_none(), "no origin was recorded yet");

        mgr.set_origin(a, peer);
        assert_eq!(mgr.origin_of(a), Some(peer));
        mgr.observe(a, PeerSource::Configured, 9_999, Instant::now());
        assert_eq!(mgr.entry(a).unwrap().source, PeerSource::Dns, "still not relabelled");
        assert_eq!(mgr.origin_of(a), Some(peer), "the origin is independent");
    }

    /// Quality follows dial outcomes, bans only bite once the threshold is
    /// crossed, and a ban survives the TTL sweep that removes its address.
    #[test]
    fn test_address_manager_failure_scoring() {
        let a = addr("203.0.113.81:25565");
        let mut mgr = AddressManager::new();
        mgr.observe(a, PeerSource::Outbound, 1_000, Instant::now());
        let base = mgr.entry(a).unwrap().quality;

        for _ in 0..3 {
            mgr.record_failure(a);
        }
        {
            let e = mgr.entry(a).unwrap();
            assert_eq!(e.attempts, 3);
            assert_eq!(e.failures, 3);
            assert!(e.quality < base, "repeated dial failures must lower quality");
        }

        mgr.record_success(a, 2_000);
        {
            let e = mgr.entry(a).unwrap();
            assert_eq!(e.last_success, Some(2_000));
            assert_eq!(e.attempts, 4);
            assert!(e.quality > base - 15, "a success pays some of it back");
        }

        // An address we do not track is left completely alone.
        let unknown = addr("203.0.113.82:25565");
        mgr.record_failure(unknown);
        assert!(!mgr.contains(unknown));

        // An address with no score is never silently banned by a penalty.
        let unscored = addr("203.0.113.84:25565");
        mgr.observe(unscored, PeerSource::Inbound, 1_000, Instant::now());
        assert!(
            mgr.penalize_and_ban(unscored, -10_000).is_none(),
            "penalties only apply to a score we already keep"
        );
        assert!(!mgr.is_banned(unscored));

        // One point short of the threshold is not a ban; the next one is.
        let hot = addr("203.0.113.83:25565");
        mgr.observe(hot, PeerSource::Inbound, 1_000, Instant::now());
        mgr.decay_score(hot);
        assert!(
            mgr.penalize_and_ban(hot, PEER_SCORE_BAN_THRESHOLD + 1 - PEER_SCORE_INITIAL)
                .is_none(),
            "score still above the threshold"
        );
        assert!(!mgr.is_banned(hot));
        assert_eq!(
            mgr.penalize_and_ban(hot, -1),
            Some(PEER_SCORE_BAN_THRESHOLD),
            "crossing the threshold bans and reports the score"
        );
        assert!(mgr.is_banned(hot));

        // A ban must outlive the address it belongs to: sweeping the entry out
        // of the table must never quietly un-ban it.
        let evicted = addr("203.0.113.85:25565");
        let mut ban_mgr = AddressManager::new();
        ban_mgr.observe(evicted, PeerSource::Pex, 1_000, Instant::now());
        ban_mgr.scores_mut().insert(evicted, banned_score());
        assert!(ban_mgr.is_banned(evicted));

        std::thread::sleep(Duration::from_millis(10));
        let (_, expired) =
            ban_mgr.refresh_and_expire(&HashSet::new(), Instant::now(), Duration::from_millis(1));
        assert_eq!(expired, 1, "the stale entry is swept");
        assert!(!ban_mgr.contains(evicted), "membership is gone");
        assert!(
            ban_mgr.is_banned(evicted),
            "the ban must survive the sweep, or expiry becomes an un-ban"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 2C — eclipse resistance. Every property below is one line of
// docs/AETHER_PHASE2_ECLIPSE_AUDIT.md §14; nothing here asserts on a number
// that was chosen to make it pass.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod phase2_eclipse_tests {
    use super::*;

    /// Selection is replayed, not observed: metadata timestamps are persisted
    /// Unix seconds, so they must not move between two runs of one test.
    const NOW: u64 = 1_700_000_000;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn no_scores() -> HashMap<SocketAddr, PeerScore> {
        HashMap::new()
    }

    fn banned_score() -> PeerScore {
        let mut s = PeerScore::new();
        s.score = PEER_SCORE_BAN_THRESHOLD;
        s.ban();
        s
    }

    fn entry() -> AddressEntry {
        AddressEntry::new(PeerSource::Restored, NOW, Instant::now())
    }

    /// A store of fresh, healthy, non-anchor entries — the state an honest node
    /// is in right after restoring its peer store.
    fn store(addrs: &[SocketAddr]) -> HashMap<SocketAddr, AddressEntry> {
        addrs.iter().map(|a| (*a, entry())).collect()
    }

    /// `count` distinct addresses inside the /24 `o1.o2.o3.0`.
    fn net4(o1: u8, o2: u8, o3: u8, count: usize) -> Vec<SocketAddr> {
        assert!(count <= 256, "a /24 only holds 256 addresses");
        (0..count)
            .map(|i| addr(&format!("{o1}.{o2}.{o3}.{i}:25565")))
            .collect()
    }

    /// `count` distinct addresses inside the /24 `203.0.x.0`, one group per
    /// value of `x`. Convenience for building a pool of several groups.
    fn groups(start: u8, count: usize, per_group: usize) -> Vec<Vec<SocketAddr>> {
        (0..count)
            .map(|i| net4(203, 0, start + i as u8, per_group))
            .collect()
    }

    fn flatten(gs: &[Vec<SocketAddr>]) -> Vec<SocketAddr> {
        gs.iter().flatten().copied().collect()
    }

    /// Exactly what `P2PNetwork::outbound_candidates` computes, with the RNG
    /// injected so a round can be replayed byte for byte.
    fn round(
        known: &[SocketAddr],
        seeds: &[SocketAddr],
        local: SocketAddr,
        entries: &HashMap<SocketAddr, AddressEntry>,
        scores: &HashMap<SocketAddr, PeerScore>,
        connected: &HashSet<SocketAddr>,
        limit: usize,
        seed: u64,
    ) -> Vec<SocketAddr> {
        let ordered = P2PNetwork::redial_candidates(known, seeds, local);
        let known_len = known.iter().filter(|a| **a != local).count();
        let tail: HashSet<SocketAddr> = ordered.iter().skip(known_len).copied().collect();
        let mut rng = StdRng::seed_from_u64(seed);
        select_outbound(&ordered, &tail, entries, scores, connected, limit, NOW, &mut rng)
    }

    fn counts_of(addrs: &[SocketAddr]) -> HashMap<NetworkGroup, usize> {
        group_counts(addrs.iter().copied())
    }

    /// L2 / L4: a round does not simply fill its budget from whichever
    /// addresses happen to hash first — it spans the network groups the pool
    /// actually offers.
    #[test]
    fn test_outbound_diversity() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 8, 4); // 8 groups, 4 addresses each, no sessions
        let known = flatten(&gs);
        let entries = store(&known);

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            16,
            7,
        );

        assert_eq!(picked.len(), 16, "the pool supports a full round");
        assert_eq!(
            counts_of(&picked).len(),
            8,
            "a round of 16 must reach all 8 available network groups, got {:?}",
            counts_of(&picked)
        );
        for (g, c) in counts_of(&picked) {
            assert!(
                c <= MAX_CANDIDATES_PER_GROUP,
                "group {g:?} took {c} of a round it may only contribute {MAX_CANDIDATES_PER_GROUP} to"
            );
        }
    }

    /// L4: one dominant network group can never take more than its round
    /// quota, and once it also holds the maximum number of live sessions its
    /// quota drops to zero and the round moves elsewhere.
    #[test]
    fn test_same_network_group_limited() {
        let local = addr("127.0.0.1:31001");
        let mut known = net4(10, 0, 0, 60);
        known.extend(net4(203, 0, 113, 4));
        let entries = store(&known);
        let attacker = network_group(addr("10.0.0.1:25565"));
        let honest = network_group(addr("203.0.113.1:25565"));

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            32,
            3,
        );
        let counts = counts_of(&picked);
        assert_eq!(
            counts.get(&attacker).copied(),
            Some(MAX_CANDIDATES_PER_GROUP),
            "60 addresses in one /24 may still only open the round quota"
        );
        assert_eq!(counts.get(&honest).copied(), Some(MAX_CANDIDATES_PER_GROUP));

        // Four live sessions already: the group is at MAX_PEERS_PER_SUBNET and
        // must contribute nothing at all.
        let saturated: HashSet<SocketAddr> = known
            .iter()
            .filter(|a| network_group(**a) == attacker)
            .take(MAX_PEERS_PER_SUBNET)
            .copied()
            .collect();
        assert_eq!(saturated.len(), MAX_PEERS_PER_SUBNET);

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &saturated,
            32,
            3,
        );
        let counts = counts_of(&picked);
        assert_eq!(
            counts.get(&attacker).copied().unwrap_or(0),
            0,
            "a group already holding MAX_PEERS_PER_SUBNET sessions gets no candidate"
        );
        assert!(
            counts.get(&honest).copied().unwrap_or(0) > 0,
            "the round must fall back to a group that still has room"
        );
    }

    /// L4: several groups stay live at once and each one is held inside its
    /// bound, including when live sessions already eat into the round quota.
    #[test]
    fn test_multi_group_selection() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 4, 8);
        let known = flatten(&gs);
        let entries = store(&known);

        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            16,
            12,
        );
        let counts = counts_of(&picked);
        assert_eq!(counts.len(), 4, "every group stays in the round");
        assert_eq!(
            picked.len(),
            4 * MAX_CANDIDATES_PER_GROUP,
            "the round is capped per group, not at the requested limit"
        );
        for (g, c) in &counts {
            assert!(*c <= MAX_CANDIDATES_PER_GROUP, "group {g:?} over its quota");
        }

        // Three live sessions per group: only one slot is left below
        // MAX_PEERS_PER_SUBNET, so the round quota narrows to a single address.
        let nearly_full: HashSet<SocketAddr> = gs
            .iter()
            .flat_map(|g| g.iter().take(MAX_PEERS_PER_SUBNET - 1).copied())
            .collect();
        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &nearly_full,
            16,
            12,
        );
        let counts = counts_of(&picked);
        assert_eq!(counts.len(), 4);
        assert_eq!(picked.len(), 4, "one further candidate per group");
        for (g, c) in &counts {
            assert_eq!(*c, 1, "group {g:?} narrowed its quota with its live sessions");
        }
    }

    /// L1: the outbound reservation is a real invariant over the whole state
    /// space, not a value observed once. Whenever inbound is admitted, the
    /// reservation still fits in the table afterwards.
    #[test]
    fn test_protected_outbound_slots() {
        assert!(
            PROTECTED_OUTBOUND_SLOTS >= 2 * MAX_PEERS_PER_SUBNET,
            "the reservation must cover at least two complete network groups"
        );

        let mut admitted = 0usize;
        for total in 0..=(MAX_PEERS + 2) {
            for outbound in 0..=total {
                if !inbound_admitted(total, outbound) {
                    continue;
                }
                admitted += 1;
                assert!(
                    total - outbound + PROTECTED_OUTBOUND_SLOTS <= MAX_PEERS,
                    "inbound admitted at total={total} outbound={outbound} but the \
                     outbound reservation no longer fits"
                );
                assert!(outbound_admitted(total), "outbound must keep working");
                assert!(total < MAX_PEERS, "never admit past the table size");
            }
        }
        assert!(admitted > 0, "the invariant must describe reachable states");

        // An inbound-only node stops at MAX_PEERS - PROTECTED_OUTBOUND_SLOTS.
        assert!(inbound_admitted(
            MAX_PEERS - PROTECTED_OUTBOUND_SLOTS - 1,
            0
        ));
        assert!(!inbound_admitted(MAX_PEERS - PROTECTED_OUTBOUND_SLOTS, 0));

        // An outbound-heavy node already holds its reservation, so inbound may
        // fill the rest of the table rather than being throttled by it.
        assert!(inbound_admitted(MAX_PEERS - 1, PROTECTED_OUTBOUND_SLOTS));
        assert!(!inbound_admitted(MAX_PEERS, PROTECTED_OUTBOUND_SLOTS));

        assert!(outbound_admitted(MAX_PEERS - 1));
        assert!(!outbound_admitted(MAX_PEERS));
        assert!(
            !inbound_admitted(0, 1),
            "outbound can never exceed the sessions that exist"
        );
    }

    /// L9: rotation of the *selection*, not forced disconnection. Each round is
    /// a fresh draw, so the union of successive rounds widens instead of the
    /// node replaying one fixed order forever.
    #[test]
    fn test_outbound_rotation() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 8, 6);
        let known = flatten(&gs);
        let entries = store(&known);

        let rounds: Vec<Vec<SocketAddr>> = (0..6)
            .map(|s| {
                round(
                    &known,
                    &[],
                    local,
                    &entries,
                    &no_scores(),
                    &HashSet::new(),
                    8,
                    s,
                )
            })
            .collect();

        for (i, r) in rounds.iter().enumerate() {
            assert_eq!(r.len(), 8, "round {i} did not fill its budget");
        }
        for (i, w) in rounds.windows(2).enumerate() {
            assert_ne!(
                w[0], w[1],
  "round {i} and round {} drew the same order  -  the RNG is not re-seeded",
                i + 1
            );
        }
        let union: HashSet<SocketAddr> = rounds.iter().flatten().copied().collect();
        assert!(
            union.len() > 8,
            "successive rounds must widen the set actually dialled ({} of 48)",
            union.len()
        );
    }

    /// L3: a compromised bootnode is still only a seed. It never outranks an
    /// address the node already holds, it is never picked when banned, and
    /// when the budget is tiny it still gets its reserved slice rather than
    /// being squeezed out by a large store.
    #[test]
    fn test_bootnode_compromised() {
        let local = addr("127.0.0.1:31001");
        let bootnode = addr("198.51.100.9:25565");
        let seeds = vec![bootnode];
        let known = flatten(&groups(100, 6, 5));
        let entries = store(&known);

        let picked = round(
            &known,
            &seeds,
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            16,
            11,
        );
        let at = picked
            .iter()
            .position(|a| *a == bootnode)
            .expect("an unprivileged seed still gets its slice of the round");
        for (i, a) in picked.iter().enumerate() {
            if i < at {
                assert!(
                    known.contains(a),
                    "only addresses we already hold may precede the bootnode"
                );
            }
        }
        assert_eq!(
            picked.last(),
            Some(&bootnode),
            "the bootnode belongs at the tail of the round, never the head"
        );

        // A banned bootnode is not a candidate at all.
        let mut scores = HashMap::new();
        scores.insert(bootnode, banned_score());
        let picked = round(&known, &seeds, local, &entries, &scores, &HashSet::new(), 16, 11);
        assert!(
            !picked.contains(&bootnode),
            "a banned bootnode must never be dialled"
        );
        assert!(!picked.is_empty(), "the rest of the round still proceeds");

        // A budget of four is entirely spoken for by known addresses plus the
        // single reserved seed slot.
        let picked = round(
            &known,
            &seeds,
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            4,
            11,
        );
        assert_eq!(picked.len(), 4);
        assert_eq!(
            picked.last(),
            Some(&bootnode),
            "even a four-slot round keeps the bootnode last"
        );
    }

    /// L3 / L4: a swarm of configured seeds cannot buy more than one round
    /// quota of slots, no matter how many are configured.
    #[test]
    fn test_seed_compromised() {
        let local = addr("127.0.0.1:31001");
        let known = flatten(&groups(100, 4, 8));
        let seeds = net4(198, 51, 100, 10);
        let entries = store(&known);

        let picked = round(
            &known,
            &seeds,
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            8,
            5,
        );

        let seed_count = picked.iter().filter(|a| seeds.contains(a)).count();
        let known_count = picked.iter().filter(|a| known.contains(a)).count();

        assert_eq!(picked.len(), 8, "the round fills its budget");
        assert_eq!(
            seed_count, MAX_CANDIDATES_PER_GROUP,
            "ten configured seeds may only take the round quota"
        );
        assert_eq!(
            known_count,
            8 - MAX_CANDIDATES_PER_GROUP,
            "the remainder belongs to addresses the node already holds"
        );
    }

    /// L6 / L7 / L8: the store stays bounded, gossip cannot displace a peer we
    /// observed ourselves, degraded entries remain evictable, and the score map
    /// stops growing without bound.
    #[test]
    fn test_peer_store_poisoning() {
        let healthy: Vec<SocketAddr> = (0..MAX_KNOWN_PEERS)
            .map(|i| addr(&format!("203.0.{}.{}:25565", i / 256, i % 256)))
            .collect();
        let mut mgr = AddressManager::new();
        for a in &healthy {
            mgr.observe(*a, PeerSource::Outbound, NOW, Instant::now());
        }
        assert_eq!(mgr.len(), MAX_KNOWN_PEERS, "the store is at capacity");

        let connected = HashSet::new();
        let noisy = addr("198.51.100.7:25565");

        // A PEX hint at half quality may not displace an entry we observed.
        let (entries, scores) = mgr.selection_tables();
        assert_eq!(
            admit_peer(
                entries,
                scores,
                &connected,
                noisy,
                admission_quality(PeerSource::Pex)
            ),
            None,
            "gossip must never evict a healthy entry it merely outnumbers"
        );
        assert_eq!(
            admission_quality(PeerSource::Pex),
            PEX_ADMISSION_QUALITY,
            "a pure gossip hint enters at half the score we give our own observations"
        );
        assert!(
            admission_quality(PeerSource::Pex) < admission_quality(PeerSource::Outbound),
            "gossip must rank below anything we observed ourselves"
        );

        // Degrade exactly one entry: now gossip may target it, and only it.
        let weak = healthy[42];
        mgr.entries_mut().get_mut(&weak).unwrap().quality = PEX_ADMISSION_QUALITY;
        let (entries, scores) = mgr.selection_tables();
        assert_eq!(
            admit_peer(
                entries,
                scores,
                &connected,
                noisy,
                admission_quality(PeerSource::Pex)
            ),
            Some(weak),
            "an already-degraded entry is exactly what gossip is allowed to replace"
        );

        // L7: a score that is neither banned nor attached to anything we still
        // track carries no information and must not accumulate.
        let orphan = addr("192.0.2.99:25565");
        let banned = addr("192.0.2.100:25565");
        mgr.scores_mut().insert(orphan, PeerScore::new());
        mgr.scores_mut().insert(banned, banned_score());
        assert!(mgr.scores.len() >= 2);

        let (_refreshed, _expired) =
            mgr.refresh_and_expire(&HashSet::new(), Instant::now(), Duration::from_secs(365 * 86_400));
        assert!(
            !mgr.scores.contains_key(&orphan),
            "an unattached, unbanned score must be purged"
        );
        assert!(
            mgr.scores.contains_key(&banned),
  "a ban always survives the sweep  -  that is why scores are a separate map"
        );
        assert_eq!(
            mgr.len(),
            MAX_KNOWN_PEERS,
            "the sweep must not have evicted anything the store still holds"
        );
    }

    /// L3: after a restart under attack, the anchors the node persisted are
    /// restored, still win their slots, and the rebuilt round spans several
    /// independent network groups rather than the attacker's.
    #[test]
    fn test_restart_under_peer_attack() {
        let local = addr("127.0.0.1:31001");
        let attacker = net4(10, 0, 0, 40);
        let anchors: Vec<SocketAddr> = net4(203, 0, 113, 2)
            .into_iter()
            .chain(net4(192, 0, 2, 2))
            .chain(net4(198, 51, 100, 2))
            .collect();
        let known: Vec<SocketAddr> = attacker.iter().chain(anchors.iter()).copied().collect();

        let mut mgr = AddressManager::new();
        for a in &known {
            mgr.observe(*a, PeerSource::Outbound, NOW, Instant::now());
        }
        for a in &anchors {
            let e = mgr.entries_mut().get_mut(a).unwrap();
            e.anchor = true;
            e.record_success(NOW);
        }

        // Restart: everything is re-read from the versioned store.
        let file = mgr.to_store();
        let mut restored = AddressManager::new();
        let loaded = restored.load_v2(&file, local, NOW, Instant::now());
        assert_eq!(loaded, known.len(), "the whole store comes back");
        for a in &anchors {
            let e = restored.entry(*a).expect("anchor must survive the restart");
            assert!(e.anchor, "the anchor flag is persisted, not re-derived");
        }

        let (entries, scores) = restored.selection_tables();
        let known = restored.addresses();
        let picked = round(
            &known,
            &[],
            local,
            entries,
            scores,
            &HashSet::new(),
            8,
            21,
        );

        assert_eq!(picked.len(), 8, "the round fills its budget after restart");
        for a in &anchors {
            assert!(
                picked.contains(a),
                "every persisted anchor must be offered first, got {:?}",
                picked
            );
        }
        let counts = counts_of(&picked);
        assert!(
            counts.len() >= 2,
            "reconnect must offer several independent network groups, got {counts:?}"
        );
        assert!(
            counts
                .get(&network_group(attacker[0]))
                .copied()
                .unwrap_or(0)
                <= MAX_CANDIDATES_PER_GROUP,
            "the attacker's group stays inside the round quota after a restart"
        );
    }

    /// L2 / L3: losing every session must not lose the ability to choose. The
    /// addresses are still known, so the very next round is both non-empty and
    /// spread across groups.
    #[test]
    fn test_mass_peer_loss() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 4, 6);
        let known = flatten(&gs);
        let entries = store(&known);

        // Before: every group already holds MAX_PEERS_PER_SUBNET sessions, so
        // there is nothing left to dial.
        let saturated: HashSet<SocketAddr> = gs
            .iter()
            .flat_map(|g| g.iter().take(MAX_PEERS_PER_SUBNET).copied())
            .collect();
        assert_eq!(saturated.len(), 4 * MAX_PEERS_PER_SUBNET);
        let before = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &saturated,
            32,
            9,
        );
        assert!(
            before.is_empty(),
            "a saturated node correctly offers no dial at all"
        );

        // After: every session is gone, the addresses are not.
        let after = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &HashSet::new(),
            32,
            9,
        );
        assert!(!after.is_empty(), "the node must rebuild after a mass loss");
        assert_eq!(
            after.len(),
            4 * MAX_CANDIDATES_PER_GROUP,
            "each group contributes its round quota"
        );
        assert!(
            counts_of(&after).len() >= 2,
            "the rebuild spans several network groups: {:?}",
            counts_of(&after)
        );
    }

    /// L3: an anchor is never a victim of admission, and in selection it is
    /// ranked above an unknown candidate of the same quality.
    #[test]
    fn test_anchor_protection() {
        let local = addr("127.0.0.1:31001");

        // (a) Admission: a table made entirely of anchors yields no victim,
        // even for an incoming address of arbitrary quality.
        let full: Vec<SocketAddr> = (0..MAX_KNOWN_PEERS)
            .map(|i| addr(&format!("203.0.{}.{}:25565", i / 256, i % 256)))
            .collect();
        let mut entries = store(&full);
        for e in entries.values_mut() {
            e.anchor = true;
        }
        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &HashSet::new(),
                addr("198.51.100.1:25565"),
                i32::MAX
            ),
            None,
            "an anchor is never offered up for eviction"
        );

        // (b) Selection: one anchor against one unknown candidate, one slot.
        let anchor = addr("203.0.113.1:25565");
        let plain = addr("192.0.2.1:25565");
        let known = vec![anchor, plain];
        let mut entries = store(&known);
        let e = entries.get_mut(&anchor).unwrap();
        e.anchor = true;
        e.record_success(NOW);

        let mut anchor_wins = 0usize;
        for s in 0..128u64 {
            let picked = round(
                &known,
                &[],
                local,
                &entries,
                &no_scores(),
                &HashSet::new(),
                1,
                s,
            );
            assert_eq!(picked.len(), 1);
            if picked[0] == anchor {
                anchor_wins += 1;
            }
        }
        assert!(
            anchor_wins * 2 > 128,
            "an anchor must be preferred over an unknown candidate ({anchor_wins}/128)"
        );
    }

    /// L6: a PEX hint at half quality never displaces a healthy peer, but a
    /// degraded one remains replaceable so the table cannot freeze.
    #[test]
    fn test_low_quality_candidate_eviction() {
        assert!(
            admission_quality(PeerSource::Pex) < default_peer_quality(),
            "gossip must enter below the quality we grant our own observations"
        );

        let healthy: Vec<SocketAddr> = (0..MAX_KNOWN_PEERS)
            .map(|i| addr(&format!("198.51.{}.{}:25565", i / 256, i % 256)))
            .collect();
        let entries = store(&healthy);
        let incoming = addr("203.0.113.50:25565");
        let connected = HashSet::new();

        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &connected,
                incoming,
                admission_quality(PeerSource::Pex)
            ),
            None,
            "a full table of healthy peers is not open to gossip"
        );

        // Same table, one entry degraded: now gossip has a legitimate target.
        let mut entries = entries;
        let weak = healthy[7];
        entries.get_mut(&weak).unwrap().quality = PEX_ADMISSION_QUALITY - 1;
        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &connected,
                incoming,
                admission_quality(PeerSource::Pex)
            ),
            Some(weak),
            "only the degraded entry may be replaced"
        );

        // A connected peer is never a victim either, healthy or not.
        let mut connected = HashSet::new();
        connected.insert(weak);
        entries.get_mut(&healthy[8]).unwrap().quality = 0;
        assert_eq!(
            admit_peer(
                &entries,
                &no_scores(),
                &connected,
                incoming,
                admission_quality(PeerSource::Pex)
            ),
            Some(healthy[8]),
            "the victim must come from the entries we are not holding a session with"
        );
    }

    /// L9: the round quota is recomputed from live sessions, so a saturated
    /// group falls to zero and the selection necessarily moves elsewhere.
    #[test]
    fn test_peer_group_rotation() {
        let local = addr("127.0.0.1:31001");
        let group_a = net4(10, 0, 0, 8);
        let group_b = net4(203, 0, 113, 8);
        let known: Vec<SocketAddr> = group_a.iter().chain(group_b.iter()).copied().collect();
        let entries = store(&known);
        let a = network_group(group_a[0]);
        let b = network_group(group_b[0]);

        let saturated: HashSet<SocketAddr> = group_a
            .iter()
            .take(MAX_PEERS_PER_SUBNET)
            .copied()
            .collect();
        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &saturated,
            16,
            4,
        );
        let counts = counts_of(&picked);
        assert!(
            !counts.contains_key(&a),
            "a saturated group must not be offered at all"
        );
        assert!(
            counts.get(&b).copied().unwrap_or(0) > 0,
            "the selection has to fall back to a group with room"
        );

        // One session released: exactly one slot is left in the group, so its
        // round quota is one and the group is reachable again.
        let partial: HashSet<SocketAddr> = group_a
            .iter()
            .take(MAX_PEERS_PER_SUBNET - 1)
            .copied()
            .collect();
        assert_eq!(partial.len(), MAX_PEERS_PER_SUBNET - 1);
        let picked = round(
            &known,
            &[],
            local,
            &entries,
            &no_scores(),
            &partial,
            16,
            4,
        );
        let counts = counts_of(&picked);
        assert_eq!(
            counts.get(&a).copied(),
            Some(1),
            "the last free slot in a group yields exactly one candidate"
        );
        assert_eq!(
            counts.get(&b).copied(),
            Some(MAX_CANDIDATES_PER_GROUP),
            "the untouched group keeps its full quota"
        );
    }

    /// L2: the selection is a pure function of (order, metadata, sessions,
    /// limit, seed). Same seed, same list; a different seed, a different one.
    #[test]
    fn test_selection_deterministic_under_seed() {
        let local = addr("127.0.0.1:31001");
        let gs = groups(100, 6, 5);
        let known = flatten(&gs);
        let entries = store(&known);
        let connected: HashSet<SocketAddr> = known.iter().take(3).copied().collect();

        let run = |seed: u64| {
            round(
                &known,
                &[],
                local,
                &entries,
                &no_scores(),
                &connected,
                8,
                seed,
            )
        };

        let a = run(42);
        let b = run(42);
        assert_eq!(a, b, "the same seed must replay the same selection");

        let c = run(43);
        assert_eq!(c.len(), a.len(), "only the order may differ");
        assert_ne!(a, c, "a different seed must draw a different selection");

        // Determinism does not depend on HashMap iteration order: rebuilding
        // the metadata table must not move a single address.
        let rebuilt = store(&known);
        let d = round(
            &known,
            &[],
            local,
            &rebuilt,
            &no_scores(),
            &connected,
            8,
            42,
        );
        assert_eq!(a, d, "selection must not depend on hash iteration order");
    }

    /// L5: the grouping rule unwraps IPv4-mapped IPv6 instead of collapsing
    /// every dual-stack listener into the single group `[0, 0, 0]`.
    #[test]
    fn test_network_group_unwraps_ipv4_mapped() {
        let plain = addr("203.0.113.7:25565");
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:25565".parse().unwrap();
        let compatible: SocketAddr = "[::203.0.113.7]:25565".parse().unwrap();

        assert_eq!(network_group(plain), NetworkGroup::V4([203, 0, 113]));
        assert_eq!(
            network_group(mapped),
            network_group(plain),
            "a mapped address belongs to the IPv4 group it embeds"
        );
        assert_eq!(
            network_group(compatible),
            network_group(plain),
            "the IPv4-compatible form is judged the same way"
        );

        // subnet_24 is a projection of the same rule, never a second opinion.
        assert_eq!(subnet_24(mapped), Some([203, 0, 113]));
        assert_eq!(subnet_24(plain), Some([203, 0, 113]));

        // Native IPv6 groups on its first 24 bits — `2001:0db8:abcd::1` and
        // `2001:0db8:ffff::9` differ only after that prefix, so a whole
        // provider allocation lands in one group, never one group per address.
        let v6: SocketAddr = "[2001:db8:abcd::1]:25565".parse().unwrap();
        let v6_other: SocketAddr = "[2001:db8:ffff::9]:25565".parse().unwrap();
        assert_eq!(network_group(v6), NetworkGroup::V6([0x20, 0x01, 0x0d]));
        assert_eq!(
            network_group(v6),
            network_group(v6_other),
            "the first 24 bits are fixed inside one provider allocation"
        );
    }
}

#[cfg(test)]
mod phase2_self_healing_tests {
    use super::*;
    use std::net::SocketAddr;

    /// Fixed metadata timestamp, so nothing depends on wall-clock time.
    const NOW: u64 = 1_700_000_000;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// `count` distinct addresses inside the /24 `o1.o2.o3.0`.
    fn net4(o1: u8, o2: u8, o3: u8, count: usize) -> Vec<SocketAddr> {
        (0..count)
            .map(|i| addr(&format!("{o1}.{o2}.{o3}.{i}:25565")))
            .collect()
    }

    /// `count` network groups, `per_group` addresses each.
    fn groups(start: u8, count: usize, per_group: usize) -> Vec<Vec<SocketAddr>> {
        (0..count)
            .map(|i| net4(203, 0, start + i as u8, per_group))
            .collect()
    }

    fn flatten(gs: &[Vec<SocketAddr>]) -> Vec<SocketAddr> {
        gs.iter().flatten().copied().collect()
    }

    fn not_banned(_: &SocketAddr) -> bool {
        false
    }

    fn fresh() -> PeerRecoveryController {
        PeerRecoveryController::new()
    }

    /// Anchors as `anchor_addresses()` reports them: `(address, last success)`,
    /// the first element being the most recently proven one.
    fn anchor_list(addrs: &[SocketAddr]) -> Vec<(SocketAddr, u64)> {
        addrs.iter()
            .enumerate()
            .map(|(i, a)| (*a, NOW - i as u64))
            .collect()
    }

    fn plan(
        count: usize,
        anchors: &[(SocketAddr, u64)],
        known: &[SocketAddr],
        seeds: &[SocketAddr],
        connected: &HashSet<SocketAddr>,
        ctl: &PeerRecoveryController,
    ) -> RecoveryRound {
        plan_recovery(
            addr("127.0.0.1:31001"),
            count,
            anchors,
            known,
            seeds,
            connected,
            &not_banned,
            ctl,
            Instant::now(),
        )
    }

    fn net_with(bootnodes: Vec<SocketAddr>) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes,
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
})
    }

    fn net_at(path: std::path::PathBuf) -> P2PNetwork {
        net_at_config(P2PConfig {
            listen_addr: addr("127.0.0.1:31001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
})
    }

    fn net_at_config(cfg: P2PConfig) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt,
            empty,
            sync_ctx,
            is_orphan,
        )
    }

    /// A listener that accepts and holds, standing in for a live peer. Loopback
    /// is a single network group, so one of these can host at most
    /// `MAX_PEERS_PER_SUBNET` real sessions — which is exactly the invariant
    /// recovery must respect.
    async fn live_peer() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut sock, _)) => {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            loop {
                                match tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(_) => {}
                                }
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        local
    }

    /// Modelled sessions for peers the ladder is not expected to dial.
    ///
    /// Used only to move the *count* to `RECOVERY_COMFORT_PEERS`: a test host
    /// only has loopback, and loopback is one `/24`, so no more than
    /// `MAX_PEERS_PER_SUBNET` real sockets can ever be opened here.
    async fn insert_session(net: &P2PNetwork, a: SocketAddr) {
        let (tx, _rx) = mpsc::unbounded_channel();
        net.peers.write().await.insert(a, tx);
    }

    // -----------------------------------------------------------------------
    // Controller transitions and bounds (pure).
    // -----------------------------------------------------------------------

    /// S1 — one peer of eight disappears. Seven is still above the entry
    /// threshold, so recovery must not start: no state change, no dial, and
    /// nothing disturbs the seven sessions that remain.
    #[test]
    fn test_self_healing_single_peer_loss() {
        let peers: Vec<SocketAddr> = flatten(&groups(100, 8, 1));
        let connected: HashSet<SocketAddr> = peers[..7].iter().copied().collect();

        let round = plan(
            7,
            &anchor_list(&peers),
            &peers,
            &[],
            &connected,
            &fresh(),
        );

        assert_eq!(
            round.state,
            RecoveryState::Healthy,
            "losing one peer of eight must not trigger recovery"
        );
        assert!(round.sources_left, "the lost peer is still a known candidate");
        assert_eq!(connected.len(), 7, "existing sessions are untouched");
    }

    /// S2 — eight peers collapse to two. Recovery starts, and the round stays
    /// inside `MAX_DIALS_PER_ROUND`.
    #[test]
    fn test_self_healing_majority_peer_loss() {
        let peers: Vec<SocketAddr> = flatten(&groups(100, 8, 1));
        let connected: HashSet<SocketAddr> = peers[..2].iter().copied().collect();
        let anchors = anchor_list(&peers[..3]);

        let round = plan(2, &anchors, &peers, &[], &connected, &fresh());

        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND, "rounds are bounded");
        assert!(!round.dial.is_empty(), "recovery must actually plan dials");
        assert!(round.tier1_anchors >= 1, "an anchor that dropped leads");
        assert!(round.tier2_known >= 1, "the rest of the store fills in");
        for a in &round.dial {
            assert!(!connected.contains(a), "never re-dial a live session");
        }
    }

    /// S3 — the table is empty: anchors first, then everything else the node
    /// knows. Configured seeds stay out of it while primaries exist.
    #[test]
    fn test_self_healing_zero_peers() {
        let anchors_src: Vec<SocketAddr> = flatten(&groups(100, 3, 1));
        let known: Vec<SocketAddr> = flatten(&groups(110, 10, 1));
        let seeds: Vec<SocketAddr> = flatten(&groups(120, 2, 1));

        let round = plan(
            0,
            &anchor_list(&anchors_src),
            &known,
            &seeds,
            &HashSet::new(),
            &fresh(),
        );

        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, anchors_src.len(), "anchors lead");
        for (i, a) in anchors_src.iter().enumerate() {
            assert_eq!(round.dial[i], *a, "most recently proven anchor first");
        }
        assert!(round.tier2_known > 0, "the address manager fills the rest");
        assert_eq!(round.tier3_seeds, 0, "seeds are a last resort");
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND);
    }

    /// S4 — the bootnode is gone entirely. Recovery runs off anchors and the
    /// peer store, never touches the seed, and is not blocked on it.
    #[test]
    fn test_self_healing_bootnode_down() {
        let dead_seed = addr("192.0.2.9:25565");
        let anchors_src: Vec<SocketAddr> = flatten(&groups(100, 4, 1));
        let known: Vec<SocketAddr> = flatten(&groups(110, 6, 1));

        let round = plan(
            0,
            &anchor_list(&anchors_src),
            &known,
            &[dead_seed],
            &HashSet::new(),
            &fresh(),
        );

        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(!round.dial.contains(&dead_seed), "the dead seed is not dialed");
        assert!(!round.dial.is_empty(), "recovery proceeds without it");
        assert!(round.sources_left);

        // Same setup with the seed removed changes nothing: it was never a
        // dependency, only a candidate.
        let without = plan(
            0,
            &anchor_list(&anchors_src),
            &known,
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert_eq!(without.dial, round.dial);
        assert_eq!(without.sources_left, true);
    }

    /// S6 — dials fail: the address is penalised, rounds stay bounded, and a
    /// run of them terminates in `Exhausted` rather than looping forever.
    #[test]
    fn test_self_healing_dial_failures() {
        // (a) `record_failure` — the path `connect_to_peer_inner` takes after
        // a refused or timed-out dial — lowers the address's quality.
        let mut mgr = AddressManager::new();
        let miss = addr("198.51.100.7:25565");
        mgr.observe(miss, PeerSource::Restored, NOW, Instant::now());
        let before = mgr.selection_tables().0.get(&miss).unwrap().quality;
        mgr.record_failure(miss);
        let after = mgr.selection_tables().0.get(&miss).unwrap().quality;
        assert_eq!(after, before - 5, "each failed dial must cost quality");

        // (b) Six rounds that open nothing exhaust the controller, and a plan
        // built from it is therefore not dialable.
        let mut ctl = fresh();
        let t = Instant::now();
        for i in 0..RECOVERY_MAX_CONSECUTIVE_FAILURES {
            ctl.record_round(0, t + Duration::from_secs(3600 * (i as u64 + 1)));
        }
        assert_eq!(ctl.consecutive_failures, RECOVERY_MAX_CONSECUTIVE_FAILURES);
        assert_eq!(ctl.backoff_level, RECOVERY_MAX_LEVEL);

        let candidate: Vec<SocketAddr> = flatten(&groups(130, 8, 1));
        let round = plan(
            0,
            &anchor_list(&candidate),
            &[],
            &[],
            &HashSet::new(),
            &ctl,
        );
        assert_eq!(round.state, RecoveryState::Exhausted);

        // (c) While recovering, every round is bounded and offers *fresh*
        // candidates rather than replaying one bad address.
        let early = plan(
            0,
            &[],
            &flatten(&groups(140, 20, 1)),
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert_eq!(early.state, RecoveryState::Recovering);
        assert!(early.dial.len() <= MAX_DIALS_PER_ROUND);
        assert_eq!(
            early.dial.iter().collect::<HashSet<_>>().len(),
            early.dial.len(),
            "no address is planned twice in one round"
        );
    }

    /// The backoff is bounded and monotone: 0, 5, 10, 20, 40, 60, 60 seconds.
    #[test]
    fn test_self_healing_backoff() {
        let levels: Vec<u64> = (0..=RECOVERY_MAX_LEVEL)
            .map(|l| recovery_backoff(l).as_secs())
            .collect();

        assert_eq!(levels, vec![0, 5, 10, 20, 40, 60, 60]);
        assert!(
            levels.windows(2).all(|w| w[0] <= w[1]),
            "backoff must never shrink as failures accumulate"
        );
        assert!(
            levels.iter().all(|s| *s <= RECOVERY_BACKOFF_MAX_SECS),
            "backoff is capped"
        );
        assert_eq!(recovery_backoff(RECOVERY_MAX_LEVEL + 99), recovery_backoff(RECOVERY_MAX_LEVEL));
    }

    /// One opened session clears the throttle completely; a failed round
    /// climbs exactly one level.
    #[test]
    fn test_self_healing_backoff_reset() {
        let mut ctl = fresh();
        let t = Instant::now();

        ctl.record_round(0, t);
        ctl.record_round(0, t + Duration::from_secs(10));
        ctl.record_round(0, t + Duration::from_secs(30));
        assert_eq!(ctl.backoff_level, 3);
        assert_eq!(ctl.consecutive_failures, 3);
        assert!(!ctl.backoff_due(t));

        ctl.record_round(2, t + Duration::from_secs(60));
        assert_eq!(ctl.backoff_level, 0, "success resets the backoff");
        assert_eq!(ctl.consecutive_failures, 0, "success resets the failures");
        assert_eq!(ctl.backoff(), Duration::ZERO);
        assert!(ctl.backoff_due(t + Duration::from_secs(61)));
    }

    /// A round never exceeds `MAX_DIALS_PER_ROUND`, whatever the store holds,
    /// and never over-fills one network group.
    #[test]
    fn test_self_healing_respects_outbound_limits() {
        assert!(MAX_DIALS_PER_ROUND <= MAX_REDIAL_PER_CYCLE);
        assert_eq!(MAX_DIALS_PER_ROUND, PROTECTED_OUTBOUND_SLOTS);

        // 200 candidates, 200 distinct network groups.
        let spread: Vec<SocketAddr> = (0..200u16)
            .map(|i| addr(&format!("10.{}.{}.7:25565", i / 256, i % 256)))
            .collect();
        let round = plan(
            0,
            &anchor_list(&spread),
            &spread,
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert_eq!(
            round.dial.len(),
            MAX_DIALS_PER_ROUND,
            "a large store yields exactly one bounded round"
        );

        // 64 candidates all inside a single /24: the subnet gate caps it.
        let one_group = net4(198, 51, 100, 64);
        let round = plan(
            0,
            &anchor_list(&one_group),
            &[],
            &[],
            &HashSet::new(),
            &fresh(),
        );
        assert!(
            round.dial.len() <= MAX_PEERS_PER_SUBNET,
            "one /24 can never fill a round: {} > {}",
            round.dial.len(),
            MAX_PEERS_PER_SUBNET
        );
    }

    /// The `/24` invariant of Phase 2C still holds while recovering, even for
    /// the tiers that bypass `select_outbound`.
    #[test]
    fn test_self_healing_preserves_diversity() {
        let crowded = net4(203, 0, 100, 8);
        let connected: HashSet<SocketAddr> = crowded[..3].iter().copied().collect();

        let mut candidates: Vec<SocketAddr> = crowded[3..].to_vec();
        candidates.extend(flatten(&groups(110, 8, 4)));

        let round = plan(
            3,
            &anchor_list(&candidates),
            &[],
            &[],
            &connected,
            &fresh(),
        );

        let mut all: Vec<SocketAddr> = connected.iter().copied().collect();
        all.extend(round.dial.iter().copied());

        let counts = group_counts(all.iter().copied());
        assert!(
            counts.values().all(|n| *n <= MAX_PEERS_PER_SUBNET),
            "recovery must never push a group past {}: {:?}",
            MAX_PEERS_PER_SUBNET,
            counts
        );
        assert_eq!(
            counts.get(&network_group(crowded[0])).copied().unwrap(),
            MAX_PEERS_PER_SUBNET,
            "the crowded group gains exactly the one slot it still had"
        );
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND);
    }

    /// Tier 1 is the anchor set, ordered by recency, and it goes first.
    #[test]
    fn test_self_healing_uses_anchors() {
        let older = addr("203.0.113.1:25565");
        let newer = addr("203.0.114.1:25565");
        let anchors = vec![(older, NOW - 100), (newer, NOW)];
        let known = vec![
            addr("203.0.115.1:25565"),
            addr("203.0.116.1:25565"),
        ];

        let round = plan(0, &anchors, &known, &[], &HashSet::new(), &fresh());

        assert_eq!(round.tier1_anchors, 2);
        assert_eq!(round.dial[0], newer, "most recently proven anchor first");
        assert_eq!(round.dial[1], older);
        assert_eq!(round.tier2_known, known.len());
        assert_eq!(&round.dial[2..], &known[..]);
    }

    /// With no anchors at all, tier 2 — the Phase 2C view of the address
    /// manager — supplies the whole round.
    #[test]
    fn test_self_healing_uses_address_manager() {
        let known: Vec<SocketAddr> = flatten(&groups(100, 6, 1));

        let round = plan(0, &[], &known, &[], &HashSet::new(), &fresh());

        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, 0);
        assert_eq!(round.tier2_known, known.len());
        assert_eq!(round.dial, known);
    }

    /// An address learned only from PEX still reaches the ladder, at the
    /// quality Phase 2B assigns to gossip.
    #[tokio::test]
    async fn test_self_healing_uses_pex() {
        let net = net_with(vec![]);
        let hint = addr("203.0.113.42:25565");

        let ok = ingress_address(
            &net.addresses,
            &net.peers,
            net.config.listen_addr,
            hint,
            PeerSource::Pex,
        )
        .await;
        assert!(ok, "the hint must be admitted to the store");
        {
            let mgr = net.addresses.read().await;
            let (entries, _) = mgr.selection_tables();
            let e = entries.get(&hint).expect("PEX hint is stored");
            assert_eq!(e.source, PeerSource::Pex);
        }
        // The table is not full, so `admit` inserted at the default quality;
        // what matters is that the *admission decision* weighed the hint at
        // gossip quality, below anything the node observed itself.
        assert_eq!(admission_quality(PeerSource::Pex), PEX_ADMISSION_QUALITY);
        assert!(
            admission_quality(PeerSource::Pex) < admission_quality(PeerSource::Outbound),
            "a gossip hint may never outrank direct evidence"
        );

        let ranked = net.outbound_candidates(MAX_DIALS_PER_ROUND).await;
        let seeds: HashSet<SocketAddr> = net.config.bootnodes.iter().copied().collect();
        let known: Vec<SocketAddr> = ranked
            .iter()
            .copied()
            .filter(|a| !seeds.contains(a))
            .collect();
        assert!(known.contains(&hint), "the PEX hint reaches the ladder");

        let ctl = *net.recovery.read().await;
        let connected: HashSet<SocketAddr> = net.peers.read().await.keys().copied().collect();
        let round = plan_recovery(
            net.config.listen_addr,
            connected.len(),
            &[],
            &known,
            &net.config.bootnodes,
            &connected,
            &not_banned,
            &ctl,
            Instant::now(),
        );
        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(round.dial.contains(&hint), "the PEX hint is dialed");
    }

    /// The seed is withheld while anything else is left to try, offered when
    /// there is nothing else, and released after a round has failed.
    #[test]
    fn test_self_healing_seed_last_resort() {
        let seed = addr("192.0.2.9:25565");
        let known: Vec<SocketAddr> = flatten(&groups(100, 6, 1));

        let first = plan(0, &[], &known, &[seed], &HashSet::new(), &fresh());
        assert!(
            !first.dial.contains(&seed),
            "with known candidates the seed must not appear"
        );
        assert_eq!(first.tier3_seeds, 0);

        let empty = plan(0, &[], &[], &[seed], &HashSet::new(), &fresh());
        assert_eq!(empty.tier3_seeds, 1, "with nothing else, the seed is used");
        assert!(empty.sources_left);

        let mut failed = fresh();
        failed.record_round(0, Instant::now() - Duration::from_secs(3600));
        let after = plan(0, &[], &known, &[seed], &HashSet::new(), &failed);
        assert!(
            after.dial.contains(&seed),
            "a failed round releases the last resort"
        );
    }

    /// S7 — a restarted node with an empty table rebuilds from its peer store
    /// and anchors, without waiting on a bootnode.
    #[tokio::test]
    async fn test_self_healing_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let a1 = addr("203.0.113.1:25565");
        let a2 = addr("203.0.114.1:25565");
        {
            let net = net_at(path.clone());
            {
                let mut mgr = net.addresses.write().await;
                mgr.observe(a1, PeerSource::Restored, unix_now(), Instant::now());
                mgr.observe(a2, PeerSource::Restored, unix_now(), Instant::now());
                mgr.apply_anchors(&HashSet::from([a1, a2]));
            }
            net.save_known_peers().await;
        }

        let net2 = net_at(path.clone());
        assert_eq!(net2.peer_count().await, 0, "restart opens with no session");
        net2.load_known_peers().await;
        {
            let mgr = net2.addresses.read().await;
            assert!(mgr.contains(a1) && mgr.contains(a2));
            assert_eq!(mgr.anchor_addresses().len(), 2, "anchors survived the restart");
        }

        let ctl = *net2.recovery.read().await;
        let round = plan_recovery(
            net2.config.listen_addr,
            0,
            &net2.addresses.read().await.anchor_addresses(),
            &[],
            &[],
            &HashSet::new(),
            &not_banned,
            &ctl,
            Instant::now(),
        );
        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, 2, "the restored anchors lead");
        let mut got = round.dial.clone();
        got.sort();
        assert_eq!(got, vec![a1, a2], "both restored anchors are dialed");
    }

    /// S8 — loss plus a poisoned store plus a dead bootnode: recovery stays
    /// group-quota'd, leads with anchors, withholds the seed, and stops.
    #[test]
    fn test_self_healing_attack_scenario() {
        // The attacker owns one routable /24 and floods it with 64 candidates.
        let evil: Vec<SocketAddr> = net4(198, 51, 100, 64);
        // Honest anchors live in four other groups.
        let good: Vec<SocketAddr> = flatten(&groups(203, 4, 1));
        let seed = addr("192.0.2.9:25565");

        let mut known: Vec<SocketAddr> = evil.clone();
        known.extend(good.iter().copied());

        let round = plan(
            0,
            &anchor_list(&good),
            &known,
            &[seed],
            &HashSet::new(),
            &fresh(),
        );

        assert_eq!(round.state, RecoveryState::Recovering);
        assert!(round.dial.len() <= MAX_DIALS_PER_ROUND);
        for a in &round.dial[..round.tier1_anchors] {
            assert!(good.contains(a), "anchors always lead");
        }
        let evil_taken = round.dial.iter().filter(|a| evil.contains(a)).count();
        assert!(
            evil_taken <= MAX_PEERS_PER_SUBNET,
            "one attacker allocation can take at most a subnet's worth: {}",
            evil_taken
        );
        assert!(!round.dial.contains(&seed), "the seed is not the way out");

        // Bounded: six fruitless rounds end it instead of feeding the attacker.
        let mut ctl = fresh();
        let t = Instant::now();
        for i in 0..RECOVERY_MAX_CONSECUTIVE_FAILURES {
            ctl.record_round(0, t + Duration::from_secs(3600 * (i as u64 + 1)));
        }
        let stopped = plan(0, &anchor_list(&good), &known, &[seed], &HashSet::new(), &ctl);
        assert_eq!(stopped.state, RecoveryState::Exhausted);
    }

    // -----------------------------------------------------------------------
    // Integration: the production round, real sockets, real address manager.
    // -----------------------------------------------------------------------

    /// Loss of the majority with the bootnode cut, then recovery to a
    /// converged, healthy neighbourhood.
    ///
    /// Drives `recovery_round` — the exact function the background task calls.
    #[tokio::test]
    async fn test_self_healing_integration_bootnode_down_convergence() {
        let mut peers_live = Vec::new();
        for _ in 0..MAX_PEERS_PER_SUBNET {
            peers_live.push(live_peer().await);
        }
        let bootnode = addr("127.0.0.1:9"); // present in config, answers nothing

        let net = net_with(vec![bootnode]);
        // 4CP-Y: this harness drives the real dial path (recovery_round), which
        // now requires a live cycle snapshot instead of an implicit mode.
        net.open_cycle_for_test(P2PProtocolMode::LegacyV5).await;
        {
            let mut mgr = net.addresses.write().await;
            for a in &peers_live {
                mgr.observe(*a, PeerSource::Restored, unix_now(), Instant::now());
            }
            let wanted: HashSet<SocketAddr> = peers_live.iter().copied().collect();
            mgr.apply_anchors(&wanted);
        }

        // The node has just lost every session it had.
        assert_eq!(net.peer_count().await, 0);

        let round = net.recovery_round().await;
        assert_eq!(round.state, RecoveryState::Recovering, "S2 detection");
        assert_eq!(round.tier1_anchors, peers_live.len(), "anchors lead");
        assert!(
            !round.dial.contains(&bootnode),
            "SEED_LAST_RESORT: the bootnode is not dialed while anchors exist"
        );
        assert_eq!(
            net.peer_count().await,
            peers_live.len(),
            "S4: recovery opened the neighbourhood without the bootnode"
        );
        {
            let ctl = net.recovery.read().await;
            assert_eq!(ctl.consecutive_failures, 0, "success clears the throttle");
            assert_eq!(ctl.backoff_level, 0);
        }

        // Bring the table to comfort and confirm the loop stands down.
        for i in 0..RECOVERY_COMFORT_PEERS.saturating_sub(peers_live.len()) {
            insert_session(
                &net,
                addr(&format!("203.0.{}.1:25565", 100 + i)),
            )
            .await;
        }
        let round = net.recovery_round().await;
        assert_eq!(
            round.state,
            RecoveryState::Healthy,
            "recovery ends once the count reaches comfort"
        );
        assert!(round.dial.is_empty(), "Healthy issues no dial at all");
        {
            let ctl = net.recovery.read().await;
            assert_eq!(ctl.backoff_level, 0);
            assert_eq!(ctl.consecutive_failures, 0);
        }
    }

    /// Restart with nothing connected, rebuild from the store and its anchors,
    /// and return to `Healthy`.
    #[tokio::test]
    async fn test_self_healing_integration_restart_to_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let first = live_peer().await;
        let second = live_peer().await;
        {
            let net = net_at(path.clone());
            {
                let mut mgr = net.addresses.write().await;
                mgr.observe(first, PeerSource::Restored, unix_now(), Instant::now());
                mgr.observe(second, PeerSource::Restored, unix_now(), Instant::now());
                mgr.apply_anchors(&HashSet::from([first, second]));
            }
            net.save_known_peers().await;
        }

        // Restart: zero sessions, store and anchors on disk.
        let net = net_at(path.clone());
        // 4CP-Y: arm a live test cycle so the real recovery dial path can run.
        net.open_cycle_for_test(P2PProtocolMode::LegacyV5).await;
        assert_eq!(net.peer_count().await, 0);
        net.load_known_peers().await;

        let round = net.recovery_round().await;
        assert_eq!(round.state, RecoveryState::Recovering);
        assert_eq!(round.tier1_anchors, 2, "recovered from the restored anchors");
        assert_eq!(net.peer_count().await, 2, "sessions reopened from the store");
        {
            let ctl = net.recovery.read().await;
            assert_eq!(ctl.consecutive_failures, 0);
            assert_eq!(ctl.backoff_level, 0);
        }

        for i in 0..RECOVERY_COMFORT_PEERS.saturating_sub(2) {
            insert_session(&net, addr(&format!("203.0.{}.1:25565", 120 + i))).await;
        }
        let round = net.recovery_round().await;
        assert_eq!(round.state, RecoveryState::Healthy, "back to a healthy count");
        assert!(round.dial.is_empty());
    }
}

#[cfg(test)]
mod bootstrap_phase1_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// PEER_PERSISTENCE: save then reload restores the same address set.
    #[tokio::test]
    async fn test_peer_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30001"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path.clone()),
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );

        net.addresses
            .write()
            .await
            .observe(addr("10.0.0.1:25565"), PeerSource::Restored, unix_now(), Instant::now());
        net.addresses
            .write()
            .await
            .observe(addr("10.0.0.2:25565"), PeerSource::Restored, unix_now(), Instant::now());
        net.save_known_peers().await;
        assert!(path.exists());

        // Simulate restart: fresh instance, same path.
        let cfg2 = P2PConfig {
            listen_addr: addr("127.0.0.1:30002"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: Some(path),
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let sync_ctx2 = Arc::new(SyncContext::default());
        let net2 = P2PNetwork::new(
            cfg2,
            tx2,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx2,
            is_orphan.clone(),
        );
        assert_eq!(net2.addresses.read().await.len(), 0);
        net2.load_known_peers().await;
        let known = net2.addresses.read().await;
        assert!(known.contains(addr("10.0.0.1:25565")));
        assert!(known.contains(addr("10.0.0.2:25565")));
        assert_eq!(known.len(), 2);
    }

    /// PEER_TTL: disconnect path keeps the address in known_peers (TTL, not remove).
    #[tokio::test]
    async fn test_peer_ttl_keeps_address_after_disconnect() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30003"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );

        let peer = addr("192.168.1.10:25565");
        net.addresses
            .write()
            .await
            .observe(peer, PeerSource::Outbound, unix_now(), Instant::now());
        // Simulate disconnect bookkeeping (what handle_peer does at exit):
        net.peers.write().await.remove(&peer);
        net.addresses.write().await.touch(peer, Instant::now());
        // Address must still be known (TTL keeps it).
        assert!(net.addresses.read().await.contains(peer));
        // TTL clock is recorded.
        assert!(
            net.addresses
                .read()
                .await
                .entry(peer)
                .expect("known address carries a TTL clock")
                .last_seen
                .elapsed()
                < PEER_TTL
        );
        // Expire only after PEER_TTL.
        assert!(PEER_TTL > Duration::from_secs(60));
    }

    /// MULTI_SEED: default config exposes more than one bootnode.
    #[test]
    fn test_multi_seed_default_bootnodes() {
        let cfg = crate::config::NodeConfig::default();
        assert!(
            cfg.bootnodes.len() >= 2,
            "multi-seed requires >=2 default bootnodes, got {}",
            cfg.bootnodes.len()
        );
        // Distinct entries.
        let unique: std::collections::HashSet<_> = cfg.bootnodes.iter().collect();
        assert_eq!(unique.len(), cfg.bootnodes.len());
    }

    /// MULTI_SEED: P2PConfig accepts an arbitrary seed list.
    #[test]
    fn test_multi_seed_p2p_config_accepts_list() {
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30004"),
            bootnodes: vec![
                addr("10.0.0.1:25565"),
                addr("10.0.0.2:25565"),
                addr("10.0.0.3:25565"),
            ],
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        assert_eq!(cfg.bootnodes.len(), 3);
    }

    /// GENERAL_REDIAL: heartbeat/reconnection candidate set includes non-bootnode peers.
    #[tokio::test]
    async fn test_general_redial_includes_known_peers() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let boot = addr("10.0.0.1:25565");
        let non_boot = addr("10.0.0.99:25565");
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30005"),
            bootnodes: vec![boot],
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        net.addresses.write().await.observe(boot, PeerSource::Restored, unix_now(), Instant::now());
        net.addresses
            .write()
            .await
            .observe(non_boot, PeerSource::Restored, unix_now(), Instant::now());

        // Reconstruct the candidate set the way start_reconnection_task does.
        let local = net.config.listen_addr;
        let mut candidates: Vec<SocketAddr> = net.config.bootnodes.clone();
        for a in net.addresses.read().await.addresses() {
            if a != local && !candidates.contains(&a) {
                candidates.push(a);
            }
        }
        assert!(candidates.contains(&boot), "bootnode must be a candidate");
        assert!(
            candidates.contains(&non_boot),
            "known non-bootnode peer must be a general-redial candidate"
        );
    }

    /// PEX: Peers message carries known addresses for discovery.
    #[test]
    fn test_pex_message_carries_known_peers() {
        let list = vec![addr("10.0.0.1:25565"), addr("10.0.0.2:25565")];
        let msg = P2PMessage::Peers(list.clone());
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: P2PMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            P2PMessage::Peers(got) => assert_eq!(got, list),
            _ => panic!("wrong variant"),
        }
    }

    /// COLD_START: loading a peer store yields dial candidates without bootnodes.
    #[tokio::test]
    async fn test_cold_start_restores_dial_candidates_without_bootnode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let peer = addr("203.0.113.10:25565");
        std::fs::write(&path, format!("[\"{}\"]", peer)).unwrap();

        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30006"),
            bootnodes: vec![], // bootnode is down / absent
            dns_seeds: vec![],
            peer_store_path: Some(path),
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        net.load_known_peers().await;
        let known = net.addresses.read().await;
        assert!(known.contains(peer), "cold start must restore the peer");
        // General redial set (what start() dials after bootnodes) is non-empty.
        let candidates: Vec<SocketAddr> = known
            .addresses()
            .into_iter()
            .filter(|a| *a != net.config.listen_addr && !net.config.bootnodes.contains(a))
            .collect();
        assert_eq!(candidates.len(), 1);
    }

    /// P2P_CRYPTO_AUDIT: equal counters only collide under the SAME direction
    /// byte; the fix assigns opposite directions to the two session senders.
    #[test]
    fn test_nonce_collision_detected() {
        // Legacy/shared-direction view: equal counters under same dir collide.
        assert!(P2PNetwork::nonce_collision_possible(1, 0x01, 1, 0x01));
        assert!(P2PNetwork::nonce_collision_possible(42, 0x01, 42, 0x01));
        // Different counters under same dir: no collision.
        assert!(!P2PNetwork::nonce_collision_possible(1, 0x01, 2, 0x01));
        // Equal counters under OPPOSITE directions (the fixed scheme): no collision.
        assert!(!P2PNetwork::nonce_collision_possible(1, 0x01, 1, 0x02));
        assert!(!P2PNetwork::nonce_collision_possible(42, 0x02, 42, 0x01));
    }

    /// Nonce uniqueness: direction byte separates the two send directions, and
    /// counters are unique within a direction.
    #[test]
    fn test_nonce_uniqueness_across_directions() {
        let mut seen = std::collections::HashSet::new();
        for dir in [0x01u8, 0x02u8] {
            for counter in 1..=1000u64 {
                let n = P2PNetwork::build_nonce(counter, dir);
                assert!(seen.insert(n), "duplicate (K, nonce) at counter={counter} dir={dir:#04x}");
            }
        }
        // Opposite directions at the same counter must differ.
        assert_ne!(
            P2PNetwork::build_nonce(1, 0x01),
            P2PNetwork::build_nonce(1, 0x02)
        );
    }

    /// Direction assignment is deterministic and opposite for the two peers.
    #[test]
    fn test_send_direction_is_opposite() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let dir_a = P2PNetwork::send_direction(&a, &b);
        let dir_b = P2PNetwork::send_direction(&b, &a);
        assert_eq!(dir_a, 0x01);
        assert_eq!(dir_b, 0x02);
        assert_ne!(dir_a, dir_b);
    }

    /// Encrypt/decrypt roundtrip with direction nonces (both directions).
    #[test]
    fn test_encrypt_decrypt_roundtrip_bidirectional() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [7u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let msg_a = b"GET_INVENTORY_MESSAGE_A";
        let msg_b = b"SYNC_REQUEST_MESSAGE_B";

        let nonce_a = P2PNetwork::build_nonce(1, 0x01);
        let nonce_b = P2PNetwork::build_nonce(1, 0x02);
        assert_ne!(nonce_a, nonce_b);

        let ct_a = cipher.encrypt(Nonce::from_slice(&nonce_a), msg_a.as_ref()).unwrap();
        let ct_b = cipher.encrypt(Nonce::from_slice(&nonce_b), msg_b.as_ref()).unwrap();

        let pt_a = cipher.decrypt(Nonce::from_slice(&nonce_a), ct_a.as_ref()).unwrap();
        let pt_b = cipher.decrypt(Nonce::from_slice(&nonce_b), ct_b.as_ref()).unwrap();
        assert_eq!(pt_a, msg_a);
        assert_eq!(pt_b, msg_b);

        // Cross-direction decrypt must fail (wrong nonce / auth tag).
        assert!(cipher.decrypt(Nonce::from_slice(&nonce_b), ct_a.as_ref()).is_err());
    }

    /// Tampered ciphertext is rejected by Poly1305.
    #[test]
    fn test_tampered_ciphertext_fails() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [9u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = P2PNetwork::build_nonce(1, 0x01);
        let mut ct = cipher.encrypt(Nonce::from_slice(&nonce), b"integrity".as_ref()).unwrap();
        ct[0] ^= 0xff;
        assert!(cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).is_err());
    }

    // ===== PHASE 3E (M6): inter-session replay =====
    //
    // Sessions derive FRESH ephemeral X25519 keys per connection (handshake:
    // EphemeralSecret::random_from_rng, both sides), hashed into the session
    // key — keys differ across sessions. A captured session-A frame replayed
    // into session B therefore fails AEAD authentication BEFORE any
    // counter/content processing (production: warn + peer ban + disconnect),
    // with the strictly-increasing per-session counter as second-layer
    // defense inside a session. Verdict: ALREADY_PROTECTED; these tests pin
    // the key-separation proof (pure crypto, no network, FAST).

    /// M6: a VERBATIM captured wire frame (nonce bytes + ciphertext) from
    /// session A is rejected under session B's key — the literal cross-
    /// session replay attempt, counters looking "fresh" or not.
    #[test]
    fn test_replay_across_sessions() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key_a = [0xA1u8; 32];
        let key_b = [0xB2u8; 32];
        assert_ne!(key_a, key_b, "sessions must hold distinct keys");
        let cipher_a = ChaCha20Poly1305::new(Key::from_slice(&key_a));
        let cipher_b = ChaCha20Poly1305::new(Key::from_slice(&key_b));
        // Capture three session-A frames (the attacker's recording).
        let mut captured = Vec::new();
        for counter in [1u64, 2, 9999] {
            let nonce = P2PNetwork::build_nonce(counter, 0x01);
            let ct = cipher_a
                .encrypt(Nonce::from_slice(&nonce), b"payload".as_ref())
                .unwrap();
            captured.push((nonce, ct));
        }
        // Replay each VERBATIM into session B: all must fail to open.
        for (nonce, ct) in &captured {
            assert!(
                cipher_b
                    .decrypt(Nonce::from_slice(nonce), ct.as_ref())
                    .is_err(),
                "captured session-A frame must not open in session B"
            );
        }
        // Control: the captures open fine under their own session key.
        for (nonce, ct) in &captured {
            assert!(cipher_a
                .decrypt(Nonce::from_slice(nonce), ct.as_ref())
                .is_ok());
        }
    }

    /// M6: systematic key separation — session-A ciphertext over a
    /// counter × direction matrix never opens under session B's key, while
    /// same-key roundtrips always work.
    #[test]
    fn test_old_ciphertext_rejected_new_session() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key_a = [0xC3u8; 32];
        let key_b = [0xD4u8; 32];
        let cipher_a = ChaCha20Poly1305::new(Key::from_slice(&key_a));
        let cipher_b = ChaCha20Poly1305::new(Key::from_slice(&key_b));
        for counter in [1u64, 2, 100, 9999, u64::MAX - 1] {
            for dir in [0x01u8, 0x02u8] {
                let nonce = P2PNetwork::build_nonce(counter, dir);
                let ct = cipher_a
                    .encrypt(Nonce::from_slice(&nonce), b"payload".as_ref())
                    .unwrap();
                assert!(
                    cipher_b
                        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                        .is_err(),
                    "counter {} dir {:02x}: cross-session open must fail",
                    counter,
                    dir
                );
            }
        }
        let nonce = P2PNetwork::build_nonce(7, 0x01);
        let ct = cipher_a
            .encrypt(Nonce::from_slice(&nonce), b"payload".as_ref())
            .unwrap();
        assert!(cipher_a
            .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
            .is_ok());
    }

    /// Long message sequence: all nonces unique under one key; encrypt/decrypt
    /// succeeds for every frame in both directions.
    #[test]
    fn test_long_message_sequence_unique_nonces() {
        use chacha20poly1305::aead::{Aead, NewAead};
        let key = [3u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut seen = std::collections::HashSet::new();
        for dir in [0x01u8, 0x02u8] {
            for counter in 1..=10_000u64 {
                let n = P2PNetwork::build_nonce(counter, dir);
                assert!(seen.insert(n));
                let ct = cipher.encrypt(Nonce::from_slice(&n), counter.to_le_bytes().as_ref()).unwrap();
                let pt = cipher.decrypt(Nonce::from_slice(&n), ct.as_ref()).unwrap();
                assert_eq!(pt, counter.to_le_bytes());
            }
        }
        assert_eq!(seen.len(), 20_000);
    }

    /// Concurrent send counters remain unique (atomic fetch_add).
    #[test]
    fn test_concurrent_send_unique_counters() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let counter = Arc::new(AtomicU64::new(1));
        let mut nonces = std::collections::HashSet::new();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let c = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let mut local = Vec::with_capacity(1000);
                    for _ in 0..1000 {
                        let v = c.fetch_add(1, Ordering::Relaxed);
                        local.push(P2PNetwork::build_nonce(v, 0x01));
                    }
                    local
                })
            })
            .collect();
        for h in handles {
            for n in h.join().unwrap() {
                assert!(nonces.insert(n), "duplicate nonce under concurrent send");
            }
        }
        assert_eq!(nonces.len(), 8000);
    }

    /// Reconnect / session rotation: each handshake yields a fresh ephemeral
    /// key, so (K, N) pairs from a prior session are never reused.
    #[tokio::test]
    async fn test_reconnect_session_rotation() {
        for _ in 0..8 {
            let (mut a_r, mut b_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_r, mut a_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_r, &mut a_w, 0);
            let b = P2PNetwork::handshake(&mut b_r, &mut b_w, 0);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, dir_a) = ra.expect("handshake A");
            let (key_b, dir_b) = rb.expect("handshake B");
            assert_eq!(key_a, key_b, "both ends share the session key");
            assert_ne!(dir_a, dir_b, "session directions must be opposite");
            assert!(dir_a == 0x01 || dir_a == 0x02);
        }
        // Distinct handshakes must not collide on keys (ephemeral X25519).
        let mut keys = std::collections::HashSet::new();
        for _ in 0..8 {
            let (mut a_r, mut b_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_r, mut a_w) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_r, &mut a_w, 0);
            let b = P2PNetwork::handshake(&mut b_r, &mut b_w, 0);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, _) = ra.expect("handshake A");
            let (key_b, _) = rb.expect("handshake B");
            assert_eq!(key_a, key_b);
            assert!(keys.insert(key_a), "reconnect must rotate the session key");
        }
        assert_eq!(keys.len(), 8);
    }

    /// Session handshake test (updated signature): shared key + opposite dirs.
    #[tokio::test]
    async fn test_handshake_derives_shared_key_bootstrap() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer, 0);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer, 0);
        let (ra, rb) = tokio::join!(a, b);

        let (key_a, dir_a) = ra.expect("side A handshake must succeed");
        let (key_b, dir_b) = rb.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
        assert_ne!(dir_a, dir_b, "directions must be opposite");
    }

    /// Replay behaviour (logic-level): a repeated/regressed counter is rejected
    /// by the receiver's strict-increase check (mirrors handle_peer logic).
    #[test]
    fn test_replay_rejected_by_counter_check() {
        let mut last: u64 = 0;
        let mut accept = |counter: u64| -> bool {
            if counter <= last {
                false
            } else {
                last = counter;
                true
            }
        };
        assert!(accept(1));
        assert!(accept(2));
        assert!(!accept(2), "replay of counter=2 must fail");
        assert!(!accept(1), "regression to 1 must fail");
        assert!(accept(3));
    }

    /// PARTITION/RECONNECT: known_peers survives an active-map wipe (partition).
    #[tokio::test]
    async fn test_partition_keeps_known_peers_for_reconnect() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let cfg = P2PConfig {
            listen_addr: addr("127.0.0.1:30007"),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        let peer = addr("198.51.100.7:25565");
        net.addresses
            .write()
            .await
            .observe(peer, PeerSource::Pex, unix_now(), Instant::now());

        // Simulate a partition: active map wiped, known set retained (TTL).
        net.peers.write().await.clear();
        net.addresses.write().await.touch(peer, Instant::now());
        assert!(net.addresses.read().await.contains(peer));
        // Reconnect candidate reconstruction (same as start_reconnection_task).
        let mut candidates: Vec<SocketAddr> = net.config.bootnodes.clone();
        for a in net.addresses.read().await.addresses() {
            if a != net.config.listen_addr && !candidates.contains(&a) {
                candidates.push(a);
            }
        }
        assert!(candidates.contains(&peer));
    }

    /// BOOTNODE_LOSS: once A↔B know each other, killing the bootnode leaves
    /// the pair as mutual redial candidates (logic-level scenario).
    #[tokio::test]
    async fn test_bootnode_loss_pair_stays_connected() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> =
            Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        let boot = addr("10.0.0.1:25565");
        let a = addr("127.0.0.1:40001");
        let b = addr("127.0.0.1:40002");
        let cfg = P2PConfig {
            listen_addr: a,
            bootnodes: vec![boot],
            dns_seeds: vec![],
            peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
};
        let net = P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt.clone(),
            empty.clone(),
            sync_ctx,
            is_orphan.clone(),
        );
        // After PEX, A knows B and (locally) itself is not redialled.
        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(b, PeerSource::Pex, unix_now(), Instant::now());
            mgr.observe(boot, PeerSource::Restored, unix_now(), Instant::now());
        }

        // Bootnode dies: it is no longer a usable dial target, but B remains.
        let mut candidates: Vec<SocketAddr> = Vec::new();
        for x in net.addresses.read().await.addresses() {
            if x != a {
                candidates.push(x);
            }
        }
        // B survives as a general-redial candidate even if boot is removed.
        net.addresses.write().await.remove(&boot);
        let after: Vec<SocketAddr> = net
            .addresses
            .read()
            .await
            .addresses()
            .into_iter()
            .filter(|x| *x != a)
            .collect();
        assert!(after.contains(&b), "A must still redial B after bootnode loss");
        assert!(!after.contains(&boot));
        let _ = candidates;
    }
}

// ---------------------------------------------------------------------------
// Phase 2E-A — metadata hardening tests. Every test here covers a change that
// actually shipped in this commit; nothing is a placeholder. See
// docs/AETHER_PHASE2_METADATA_HARDENING.md for the threat each one binds to.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod phase2_privacy_tests {
    use super::*;

    /// Payload sizes spanning several buckets, including the exact boundaries.
    fn sample_lengths() -> Vec<usize> {
        vec![
            0, 1, 2, 17, 63, 64, 100, 162, 163, 200, 226, 227, 300, 449, 450, 1000, 4096, 32000,
        ]
    }

    fn unique_hashes(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut h = vec![0u8; 32];
                h[0] = ((i >> 8) & 0xff) as u8;
                h[1] = (i & 0xff) as u8;
                h[2] = 0xA5;
                h
            })
            .collect()
    }

    // --- A.3 protocol version / handshake metadata -------------------------

    /// Phase 4B: exactly ONE bump for this consensus change, and an old peer
    /// is refused at the handshake (magic first, then version).
    #[test]
    fn test_protocol_version_bump() {
        assert_eq!(
            P2P_PROTOCOL_VERSION, 5,
            "4B bumps the wire version exactly once (4 -> 5) for the CDW
             consensus break: mixed-version nodes would resolve the same
             conflicts differently, so they must split loudly, never silently"
        );

        // v3 peer: literal ASCII magic → refused by the magic check.
        let mut v3 = vec![0u8; HANDSHAKE_FRAME_LEN];
        v3[..4].copy_from_slice(&HANDSHAKE_MAGIC);
        v3[4] = 3;
        v3[5..37].copy_from_slice(&crate::genesis::GENESIS_HASH);
        let err = P2PNetwork::verify_handshake_identity(&v3, 0).unwrap_err();
        assert!(err.contains("magic"), "old magic must fail first: {err}");

        // Correct magic, stale version → refused by the version check.
        let mut stale = v3.clone();
        stale[..4].copy_from_slice(&P2PNetwork::handshake_wire_magic());
        stale[4] = P2P_PROTOCOL_VERSION - 1;
        let err = P2PNetwork::verify_handshake_identity(&stale, 0).unwrap_err();
        assert!(err.contains("version"), "old version must be refused: {err}");

        stale[4] = P2P_PROTOCOL_VERSION;
        assert!(
            P2PNetwork::verify_handshake_identity(&stale, 0).is_ok(),
            "a current-version same-network frame must pass"
        );
    }

    /// A.3: the ASCII signature "AETH" is no longer the bytes on the wire.
    /// XOR is an involution — this is obfuscation of a public constant, NOT
    /// secrecy, and the test says so rather than overclaiming.
    #[test]
    fn test_handshake_magic_is_obfuscated() {
        let wire = P2PNetwork::handshake_wire_magic();
        assert_ne!(wire, HANDSHAKE_MAGIC, "wire magic must differ");
        assert_ne!(&wire, b"AETH", "the literal signature must not be sent");
        let mut back = [0u8; 4];
        for i in 0..4 {
            back[i] = wire[i] ^ HANDSHAKE_MAGIC_MASK[i];
        }
        assert_eq!(back, HANDSHAKE_MAGIC, "peers must still be able to recover it");
    }

    /// A.3: the handshake is exactly 77 bytes decomposing into magic(4) |
    /// version(1) | genesis(32) | network(8) | ephemeral key(32) — every byte
    /// accounted for by a declared field (PHASE 4V adds the network u64 LE;
    /// see test_handshake_network_isolation for its semantics). (Encrypting
    /// or authenticating the handshake is OUT OF SCOPE for 2E-A.)
    #[test]
    fn test_handshake_metadata_exposure() {
        assert_eq!(HANDSHAKE_FRAME_LEN, 77, "layout is magic4+ver1+genesis32+net8+key32");
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        key[31] = 0xCD;

        let mut frame = Vec::with_capacity(HANDSHAKE_FRAME_LEN);
        frame.extend_from_slice(&P2PNetwork::handshake_wire_magic());
        frame.push(P2P_PROTOCOL_VERSION);
        frame.extend_from_slice(&crate::genesis::GENESIS_HASH);
        frame.extend_from_slice(&7u64.to_le_bytes());
        frame.extend_from_slice(&key);

        assert_eq!(frame.len(), HANDSHAKE_FRAME_LEN);
        assert!(P2PNetwork::verify_handshake_identity(&frame, 7).is_ok());
        // Byte-exact decomposition: every byte is accounted for by a declared
        // field, so there is no room for a peer address or an identifier
        // beyond the declared network id.
        assert_eq!(&frame[..4], &P2PNetwork::handshake_wire_magic());
        assert_ne!(&frame[..4], b"AETH", "signature never on the wire");
        assert_eq!(frame[4], P2P_PROTOCOL_VERSION);
        assert_eq!(&frame[5..37], &crate::genesis::GENESIS_HASH[..]);
        assert_eq!(&frame[37..45], &7u64.to_le_bytes()[..]);
        assert_eq!(&frame[45..77], &key[..]);
    }

    // --- A.3 frame length padding -----------------------------------------

    /// A.3: every emitted length lands on a bucket, and two different payload
    /// sizes inside one bucket are indistinguishable by `total_len`.
    #[test]
    fn test_frame_size_buckets() {
        for len in sample_lengths() {
            let msg = vec![0x5Au8; len];
            let padded = P2PNetwork::pad_message(&msg).expect("sample must pad");
            let total = NONCE_LEN + (padded.len() + AEAD_TAG_LEN);
            assert_eq!(total % FRAME_PAD_BUCKET, 0, "len={len} total={total}");
            assert_eq!(Some(total), P2PNetwork::padded_total_len(len));
            assert!(P2PNetwork::valid_frame_len(total), "len={len} total={total}");
        }
        // The actual privacy property: 100 B and 200 B share a bucket, so the
        // clear length cannot tell them apart; 1000 B lands elsewhere.
        assert_eq!(
            P2PNetwork::padded_total_len(100),
            P2PNetwork::padded_total_len(200),
            "same bucket must give the same clear length"
        );
        assert_ne!(
            P2PNetwork::padded_total_len(100),
            P2PNetwork::padded_total_len(1000)
        );
    }

    /// A.3: padding is bounded, reversible and never overflows the bucket.
    #[test]
    fn test_padding_bounds() {
        for len in sample_lengths() {
            let msg = vec![7u8; len];
            let padded = P2PNetwork::pad_message(&msg).expect("sample must pad");
            assert!(padded.len() >= len, "padding must never shrink");
            let pad = padded.len() - len - FRAME_PAD_TAIL;
            assert!(pad <= MAX_FRAME_PADDING, "len={len} pad={pad}");
            let back = P2PNetwork::unpad_message(&padded).expect("must unpad");
            assert_eq!(back, msg, "roundtrip must be exact");
        }
    }

    /// A.3: `MAX_FRAME_PADDING` is reachable (so the bound is tight, not
    /// decorative) and never exceeded across a dense sweep.
    #[test]
    fn test_max_padding() {
        // FRAME_FIXED_OVERHEAD(30) + 227 = 257 ≡ 1 (mod 256) → pad = 255.
        let msg = vec![1u8; 227];
        let padded = P2PNetwork::pad_message(&msg).expect("must pad");
        assert_eq!(
            padded.len() - 227 - FRAME_PAD_TAIL,
            MAX_FRAME_PADDING,
            "the bound must be reachable, otherwise it proves nothing"
        );
        for len in 0..2000usize {
            let p = P2PNetwork::pad_message(&vec![0u8; len]).expect("must pad");
            assert!(p.len() - len - FRAME_PAD_TAIL <= MAX_FRAME_PADDING, "len={len}");
        }
    }

    /// A.3: padding is a pure function of the payload — no RNG in the frame
    /// path, so tests and reproductions stay deterministic.
    #[test]
    fn test_padding_determinism() {
        let a = P2PNetwork::pad_message(b"deterministic").expect("must pad");
        let b = P2PNetwork::pad_message(b"deterministic").expect("must pad");
        assert_eq!(a, b, "same payload → same padding");
        let c = P2PNetwork::pad_message(b"deterministiC").expect("must pad");
        assert_ne!(a, c, "different payloads must not collide");
        assert_eq!(
            P2PNetwork::padded_total_len(500),
            P2PNetwork::padded_total_len(500)
        );
        // A payload that cannot be padded under MAX_MESSAGE_SIZE is refused
        // (returns None) rather than emitted mis-aligned.
        assert!(P2PNetwork::padded_total_len(FRAME_MAX_EMIT - FRAME_FIXED_OVERHEAD).is_some());
        assert!(P2PNetwork::padded_total_len(FRAME_MAX_EMIT - FRAME_FIXED_OVERHEAD + 1).is_none());
    }

    /// A.3: an unaligned (v3 / forged) length is refused before any
    /// allocation happens.
    #[test]
    fn test_old_frame_rejected() {
        // Typical v3 frame: raw message size, never bucket-aligned.
        assert!(!P2PNetwork::valid_frame_len(12 + 37));
        assert!(!P2PNetwork::valid_frame_len(0));
        assert!(!P2PNetwork::valid_frame_len(FRAME_PAD_BUCKET - 1));
        assert!(!P2PNetwork::valid_frame_len(FRAME_PAD_BUCKET + 1));
        assert!(P2PNetwork::valid_frame_len(FRAME_PAD_BUCKET));
        assert!(P2PNetwork::valid_frame_len(2 * FRAME_PAD_BUCKET));
        assert!(P2PNetwork::valid_frame_len(MAX_MESSAGE_SIZE));
        assert!(!P2PNetwork::valid_frame_len(MAX_MESSAGE_SIZE + FRAME_PAD_BUCKET));
    }

    // --- A.3 frame metadata end-to-end ------------------------------------

    /// A.3: one real frame on the wire. The clear part is length + nonce
    /// only, the length is bucket-aligned, and the address travels solely
    /// inside the AEAD.
    #[test]
    fn test_frame_metadata_hardening() {
        let key = [0x2Au8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let addr: SocketAddr = "203.0.113.7:40001".parse().unwrap();
        let payload = bincode::serialize(&P2PMessage::Peers(vec![addr])).expect("serialize");
        // The peer address as it really appears on the wire (bincode writes
        // a `SocketAddr` as octets + port, not as text).
        let addr_bytes = bincode::serialize(&addr).expect("serialize addr");
        assert!(
            payload
                .windows(addr_bytes.len())
                .any(|w| w == addr_bytes),
            "sanity: the address really is in the payload"
        );

        let padded = P2PNetwork::pad_message(&payload).expect("must pad");
        let nonce = P2PNetwork::build_nonce(1, 0x01);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), padded.as_ref())
            .expect("encrypt");
        let total = NONCE_LEN + ct.len();

        let mut frame = Vec::new();
        frame.extend_from_slice(&(total as u32).to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ct);

        // Clear length is bucketed and matches the declared layout.
        assert_eq!(total % FRAME_PAD_BUCKET, 0);
        assert_eq!(Some(total), P2PNetwork::padded_total_len(payload.len()));
        assert!(P2PNetwork::valid_frame_len(total));
        // Nothing identifying survives outside the ciphertext.
        assert!(
            !frame.windows(addr_bytes.len()).any(|w| w == addr_bytes),
            "peer address leaked outside the ciphertext"
        );
        // And the frame still round-trips through the real unpad path.
        let on_wire_header = 4 + NONCE_LEN;
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), &frame[on_wire_header..])
            .expect("decrypt");
        assert_eq!(P2PNetwork::unpad_message(&pt).expect("unpad"), payload);
    }

    /// A.3: for several message types carrying peer metadata, no part of the
    /// serialized message appears anywhere in the bytes handed to the socket.
    #[test]
    fn test_no_plaintext_peer_metadata() {
        let key = [0x77u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        let peers: Vec<SocketAddr> = vec![
            "198.51.100.10:40001".parse().unwrap(),
            "198.51.100.11:40002".parse().unwrap(),
            "[2001:db8::1]:40003".parse().unwrap(),
        ];
        let inventory = unique_hashes(64);
        // Needles are the identifying bytes as bincode really emits them:
        // `SocketAddr` as octets+port, inventory entries as raw digests.
        let cases: Vec<(Vec<u8>, Vec<Vec<u8>>)> = vec![
            (
                bincode::serialize(&P2PMessage::Peers(peers.clone())).expect("ser"),
                vec![
                    bincode::serialize(&peers[0]).expect("ser"),
                    bincode::serialize(&peers[2]).expect("ser"),
                ],
            ),
            (
                bincode::serialize(&P2PMessage::Inventory(inventory.clone())).expect("ser"),
                vec![inventory[7].clone(), inventory[63].clone()],
            ),
        ];

        for (idx, (payload, needles)) in cases.iter().enumerate() {
            for needle in needles {
                assert!(
                    payload.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "case {idx}: needle must be in the payload"
                );
            }
            let padded = P2PNetwork::pad_message(payload).expect("must pad");
            let nonce = P2PNetwork::build_nonce(u64::from(idx as u32) + 1, 0x01);
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), padded.as_ref())
                .expect("encrypt");
            let total = NONCE_LEN + ct.len();
            let mut frame = Vec::new();
            frame.extend_from_slice(&(total as u32).to_be_bytes());
            frame.extend_from_slice(&nonce);
            frame.extend_from_slice(&ct);

            assert_eq!(total % FRAME_PAD_BUCKET, 0, "case {idx}: length must be bucketed");
            for needle in needles {
                assert!(
                    !frame.windows(needle.len()).any(|w| w == needle.as_slice()),
                    "case {idx}: peer metadata on the wire outside the ciphertext"
                );
            }
        }
    }

    /// A.3: the padding lives INSIDE the AEAD, so flipping it is a
    /// cryptographic failure and cannot be used to reallocate a frame.
    #[test]
    fn test_padding_is_authenticated() {
        let key = [0x5Cu8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let payload = vec![0xEEu8; 100];
        let padded = P2PNetwork::pad_message(&payload).expect("must pad");
        assert!(
            padded.len() > payload.len(),
            "there must be padding to tamper with"
        );
        let nonce = P2PNetwork::build_nonce(9, 0x02);
        let mut ct = cipher
            .encrypt(Nonce::from_slice(&nonce), padded.as_ref())
            .expect("encrypt");
        // Flip a byte inside the padded tail (just before the 16-byte tag).
        let target = ct.len() - AEAD_TAG_LEN - 1;
        ct[target] ^= 0xFF;
        assert!(
            cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()).is_err(),
            "tampered padding must fail Poly1305"
        );
    }

    // --- A.2 (i) DAG size -------------------------------------------------

    /// A.2: the `SyncRequest` answer is bounded at `MAX_INV_ITEMS` whatever
    /// the DAG holds, so `total_len` stops being a DAG-size oracle — while
    /// rotating, so the whole set is still advertised over time.
    #[test]
    fn test_inventory_size_not_leaked() {
        let small = unique_hashes(10);
        let c_small = AtomicU64::new(0);
        assert_eq!(
            P2PNetwork::inventory_window(&small, &c_small).len(),
            10,
            "a small DAG is returned whole (nothing to hide behind a cap)"
        );

        let big = unique_hashes(MAX_INV_ITEMS * 5);
        let c1 = AtomicU64::new(0);
        let w1 = P2PNetwork::inventory_window(&big, &c1);
        assert_eq!(w1.len(), MAX_INV_ITEMS, "advertised set must be bounded");

        let bigger = unique_hashes(MAX_INV_ITEMS * 9);
        let c2 = AtomicU64::new(0);
        let w2 = P2PNetwork::inventory_window(&bigger, &c2);
        assert_eq!(
            w1.len(),
            w2.len(),
  "frame size must not track DAG size  -  that is the leak"
        );

        // Rotation: five consecutive windows are disjoint and cover the DAG,
        // which is what keeps a plain `take()` from stranding a late joiner.
        let c3 = AtomicU64::new(0);
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..5 {
            for h in P2PNetwork::inventory_window(&big, &c3) {
                assert!(seen.insert(h), "windows must not repeat while rotating");
            }
        }
        assert_eq!(seen.len(), MAX_INV_ITEMS * 5, "rotation must cover the whole set");
    }

    // --- A.2 (ii)/(iii) cadence jitter ------------------------------------

    /// A.2: the PEX period stays inside its declared band — never faster
    /// than baseline (that would raise traffic), never unbounded.
    #[test]
    fn test_pex_privacy_bounds() {
        for r in 0..10_000u64 {
            let d = P2PNetwork::jittered_interval(PEX_INTERVAL, PEX_INTERVAL_JITTER, r);
            assert!(d >= PEX_INTERVAL, "r={r}: jitter must not shorten the period");
            assert!(
                d <= PEX_INTERVAL + PEX_INTERVAL_JITTER,
                "r={r}: jitter must stay bounded"
            );
        }
    }

    /// A.2: the jitter is real (the fixed 15s metronome is gone) and it never
    /// lets any of the three loops beat its baseline rate. Deterministic in
    /// `r`, so the assertions are exact rather than statistical.
    #[test]
    fn test_pex_rate_limit() {
        let mut seen: HashSet<Duration> = HashSet::new();
        for r in 0..1000u64 {
            seen.insert(P2PNetwork::jittered_interval(PEX_INTERVAL, PEX_INTERVAL_JITTER, r));
        }
        assert!(seen.len() > 1, "a constant period is not jitter");
        assert_eq!(
            *seen.iter().min().expect("non-empty"),
            PEX_INTERVAL,
            "the baseline must still be reachable"
        );
        assert!(*seen.iter().max().expect("non-empty") <= PEX_INTERVAL + PEX_INTERVAL_JITTER);

        for r in 0..1000u64 {
            let rec = P2PNetwork::jittered_interval(RECOVERY_INTERVAL, RECOVERY_INTERVAL_JITTER, r);
            assert!(rec >= RECOVERY_INTERVAL);
            assert!(rec <= RECOVERY_INTERVAL + RECOVERY_INTERVAL_JITTER);
            let red = P2PNetwork::jittered_interval(
                Duration::from_secs(5),
                REDIAL_INTERVAL_JITTER,
                r,
            );
            assert!(red >= Duration::from_secs(5));
            assert!(red <= Duration::from_secs(5) + REDIAL_INTERVAL_JITTER);
        }

        // Zero jitter degenerates to the exact baseline (no silent drift).
        assert_eq!(
            P2PNetwork::jittered_interval(PEX_INTERVAL, Duration::ZERO, 12345),
            PEX_INTERVAL
        );
    }

    // --- A.1 local metadata -----------------------------------------------

    /// A.1: the peer store (every IP this node ever dialled) is written
    /// owner-only on Unix. Windows has no POSIX mode bits, so there the test
    /// still pins the write path — it must create the file and preserve the
    /// bytes exactly.
    #[test]
    fn test_peer_store_privacy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let body = r#"{"version":2,"peers":[]}"#;
        write_private_file(&path, body).expect("write");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), body);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "peer store must be owner-only");

            // A `.tmp` left wide by a previous crash must be re-tightened:
            // `OpenOptions::mode()` only applies at creation.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .expect("widen");
            write_private_file(&path, body).expect("rewrite");
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "an existing file must be re-tightened");
        }
    }

    /// A.1: an INFO line exactly as `NodeLineFormat` emits it reaches the
    /// file without a raw address, while the timestamp, target and peer
    /// distinguishability survive.
    #[test]
    fn test_peer_store_no_addresses_in_logs() {
        let line = "2026-01-01T00:00:00Z | node1 | INFO | aether_unified::p2p | \u{1f510} P2P encrypted handshake complete with 10.0.0.5:40001";
        let masked = crate::log_privacy::mask_socket_addrs_with_salt(line, 0xdead_beef);
        assert!(
            !masked.contains("10.0.0.5"),
            "raw IP must never reach node.log: {masked}"
        );
        assert!(masked.contains("p2p."), "peer must stay distinguishable: {masked}");
        assert!(
            masked.contains("2026-01-01T00:00:00Z"),
            "timestamp must survive: {masked}"
        );
        assert!(
            masked.contains("aether_unified::p2p"),
            "target must survive: {masked}"
        );
    }

    // --- cost benchmark ----------------------------------------------------
    //
    // Deterministic parts (byte overhead) are ASSERTED; timing parts are only
    // reported, never asserted, because wall-clock assertions are flaky.
    // Run: cargo test --release --lib p2p::phase2_privacy_tests::bench_2e_a_costs -- --ignored --nocapture

    /// v3 on-wire `total_len` for a payload of `msg_len` bytes: nonce + tag,
    /// no padding.
    fn v3_total_len(msg_len: usize) -> usize {
        NONCE_LEN + msg_len + AEAD_TAG_LEN
    }

    #[test]
    #[ignore = "2E-A cost benchmark: run with --ignored --nocapture in release mode"]
    fn bench_2e_a_costs() {
        use std::time::Instant;

        // ---- METADATA_OVERHEAD: exact, asserted -------------------------
        //
        // Sweep every payload size in [0, 4096] and report the real
        // overhead distribution rather than a single cherry-picked figure.
        let mut pad_sum = 0u64;
        let mut worst = 0usize;
        let mut count = 0u64;
        for len in 0..=4096usize {
            let new = P2PNetwork::padded_total_len(len).expect("fits");
            let old = v3_total_len(len);
            assert!(new >= old, "len={len}: padding must never shrink a frame");
            let extra = new - old;
            assert!(extra <= 2 + MAX_FRAME_PADDING, "len={len}: extra={extra}");
            assert_eq!(new % FRAME_PAD_BUCKET, 0, "len={len}");
            pad_sum += extra as u64;
            worst = worst.max(extra);
            count += 1;
        }
        let mean = pad_sum as f64 / count as f64;
        println!("METADATA_OVERHEAD mean_bytes={mean:.1} worst_bytes={worst} (sweep 0..=4096, {count} sizes)");
        assert_eq!(worst, 2 + MAX_FRAME_PADDING, "worst case must be reachable");

        // Representative real messages.
        let addrs: Vec<SocketAddr> = (0..8)
            .map(|i| format!("203.0.113.{}:40001", i + 1).parse().unwrap())
            .collect();
        let msgs: Vec<(&str, Vec<u8>)> = vec![
            ("peers(8)", bincode::serialize(&P2PMessage::Peers(addrs)).unwrap()),
            ("inventory(100)", bincode::serialize(&P2PMessage::Inventory(unique_hashes(100))).unwrap()),
            ("inventory(1000)", bincode::serialize(&P2PMessage::Inventory(unique_hashes(1000))).unwrap()),
        ];
        let mut worst_pct = 0f64;
        for (name, payload) in &msgs {
            let old = v3_total_len(payload.len());
            let new = P2PNetwork::padded_total_len(payload.len()).expect("fits");
            let pct = (new as f64 - old as f64) / old as f64 * 100.0;
            worst_pct = worst_pct.max(pct);
            println!(
                "METADATA_OVERHEAD {name}: msg={}B old_total_len={new_display} new_total_len={new} extra={e} ({p:.2}%)",
                payload.len(),
                new_display = old,
                e = new - old,
                p = pct,
            );
            assert!(new >= old);
            assert_eq!(new % FRAME_PAD_BUCKET, 0);
        }
        println!("METADATA_OVERHEAD worst_case_pct={worst_pct:.2}");

        // ---- LATENCY_IMPACT / THROUGHPUT_IMPACT: measured, not asserted --
        let key = [0x33u8; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = P2PNetwork::build_nonce(1, 0x01);
        let payload = unique_hashes(1000); // ~32 KB, the SyncResponse shape
        let raw = bincode::serialize(&P2PMessage::Inventory(payload)).unwrap();
        let padded = P2PNetwork::pad_message(&raw).expect("must pad");

        // pad + unpad round trip, per frame — small frame first, so the
        // padding-specific cost can be separated from the payload memcpy.
        let iters = 200_000u32;
        let small = vec![0u8; 92];
        let t_small = Instant::now();
        for _ in 0..iters {
            let p = P2PNetwork::pad_message(&small).expect("pad");
            std::hint::black_box(P2PNetwork::unpad_message(&p).expect("unpad"));
        }
        let pad_small_ns = t_small.elapsed().as_nanos() as f64 / iters as f64;
        println!("LATENCY_IMPACT pad+unpad small frame (92B): {pad_small_ns:.1} ns");

        let t0 = Instant::now();
        for _ in 0..iters {
            let p = P2PNetwork::pad_message(&raw).expect("pad");
            std::hint::black_box(P2PNetwork::unpad_message(&p).expect("unpad"));
        }
        let pad_ns = t0.elapsed().as_nanos() as f64 / iters as f64;
        println!("LATENCY_IMPACT pad+unpad large frame ({}B): {pad_ns:.1} ns", raw.len());
        println!(
            "LATENCY_IMPACT payload-copy share: {:.1} ns/frame (large - small)",
            pad_ns - pad_small_ns
        );

        // encrypt throughput, un-padded (v3 shape) vs padded (v4 shape)
        let bench_cipher = |data: &[u8]| -> (f64, f64) {
            let runs = 6u32;
            let mut best = f64::MAX;
            for _ in 0..runs {
                let iters = 300u32;
                let t = Instant::now();
                for _ in 0..iters {
                    std::hint::black_box(cipher.encrypt(Nonce::from_slice(&nonce), data).expect("enc"));
                }
                let secs = t.elapsed().as_secs_f64() / iters as f64;
                best = best.min(secs);
            }
            let mbps = data.len() as f64 / best / 1e6;
            (best * 1e9, mbps)
        };
        let (old_ns, old_mbps) = bench_cipher(&raw);
        let (new_ns, new_mbps) = bench_cipher(&padded);
        let delta_ns = new_ns - old_ns;
        let impact = delta_ns / old_ns * 100.0;
        println!(
            "THROUGHPUT_IMPACT old={old_mbps:.1} MB/s new={new_mbps:.1} MB/s (best of 6 runs)",
        );
        println!(
            "LATENCY_IMPACT encrypt per frame: old={old_ns:.0} ns new={new_ns:.0} ns delta={delta_ns:+.0} ns ({impact:+.2}%)"
        );

        // Extra bytes really do cost encrypt time, and both directions are
        // consistent: the added work is proportional to the added bytes.
        assert!(new_ns >= old_ns * 0.9, "padded must not be dramatically faster (sanity)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transaction;
    use tokio::sync::mpsc;

    #[test]
    fn test_seen_tx_entry() {
        // The seen cache holds a timestamp for eviction decisions.
        let now = Instant::now();
        let entry = SeenTxEntry {
            timestamp: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
        };
        // 60s-old entry must be evictable (older than the 30s cleanup window).
        assert!(now.duration_since(entry.timestamp) >= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_seen_transactions_deduplication() {
        // Test that seen_transactions correctly tracks and deduplicates
        let seen = Arc::new(RwLock::new(HashMap::new()));

        let tx_bytes = vec![1u8, 2, 3, 4];

        // First insert should succeed
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                },
            );
        }

        // Check that it's present
        {
            let seen_read = seen.read().await;
            assert!(seen_read.contains_key(&tx_bytes));
            assert_eq!(seen_read.len(), 1);
        }

        // Second insert should not duplicate (just update)
        {
            let mut seen_write = seen.write().await;
            seen_write.insert(
                tx_bytes.clone(),
                SeenTxEntry {
                    timestamp: Instant::now(),
                },
            );
        }

        // Should still be only one entry
        {
            let seen_read = seen.read().await;
            assert_eq!(seen_read.len(), 1);
        }
    }

  /// PHASE 4G: stake ingress is format-only (strict decode + dedup),
  /// mirroring accept_inbound_transaction. A well-formed vote with a
  /// BOGUS signature is still queued here (signatures are admission's
  /// job); garbage, wrong-kind bytes and replays are dropped.
    #[tokio::test]
  async fn test_stake_ingress_format_only_dedup() {
  use crate::transaction::VOTE_FORMAT_VERSION;
        let seen = Arc::new(RwLock::new(HashMap::new()));
  let prop = Arc::new(RwLock::new(HashMap::new()));
  let (tx, mut rx) = mpsc::unbounded_channel::<StakePayload>();
  let source: SocketAddr = "127.0.0.1:30333".parse().unwrap();

  let vote = Vote {
  format_version: VOTE_FORMAT_VERSION,
  network_id: 0,
  validator: [0x11u8; 32],
  epoch: 600_000,
  conflict_sender: [0x22u8; 32],
  conflict_nonce: 5,
  side: [0x33u8; 32],
  stake_epoch: 600_000,
  stake_amount: 200,
  parents: [[0u8; 32]; 2],
  // Bogus signature ON PURPOSE: ingress must not check it.
  signature: [0xABu8; 64],
  };
  let bytes = vote.encode();
  assert!(accept_inbound_stake("vote", bytes.clone(), source, &seen, &prop, &tx).await);
  // Queued (decoded, round-trips byte-identical).
  match rx.try_recv().expect("vote queued") {
  StakePayload::Vote(v) => assert_eq!(v.encode(), bytes),
  other => panic!("expected vote, got {:?}", other),
            }
  // Replay dropped (dedup ahead of everything).
  assert!(!accept_inbound_stake("vote", bytes, source, &seen, &prop, &tx).await);
  // Garbage dropped.
  assert!(!accept_inbound_stake("vote", vec![0u8; 10], source, &seen, &prop, &tx).await);
  // Wrong-kind bytes dropped (bond encoding as vote).
  let bond = Bond {
  format_version: crate::transaction::BOND_FORMAT_VERSION,
  network_id: 0,
  validator: [0x11u8; 32],
  amount: 30_000_000,
  epoch: 1,
  signature: [0u8; 64],
  };
  assert!(!accept_inbound_stake("vote", bond.encode(), source, &seen, &prop, &tx).await);
  // Unknown kind dropped.
  assert!(!accept_inbound_stake("nope", vec![1u8; 257], source, &seen, &prop, &tx).await);
        }

    /// H2: read_exact_timeout must fail with ErrorKind::TimedOut when the peer
    /// sends nothing, and succeed when the bytes arrive. A stalled peer can no
    /// longer hold a task + socket forever (slow-loris guard).
    #[tokio::test]
    async fn test_read_exact_timeout() {
        // A duplex stream with no writer activity: the read must time out.
        let (mut reader, _silent_writer) = tokio::io::duplex(64);
        let mut buf = [0u8; 36];
        let err = P2PNetwork::read_exact_timeout(&mut reader, &mut buf, Duration::from_millis(100))
            .await
            .expect_err("silent peer must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        // A duplex stream that delivers the bytes: the read must succeed.
        let (mut reader2, mut writer2) = tokio::io::duplex(64);
        writer2.write_all(&[0xAAu8; 36]).await.unwrap();
        P2PNetwork::read_exact_timeout(&mut reader2, &mut buf, Duration::from_secs(5))
            .await
            .expect("bytes must be read within the budget");
        assert_eq!(buf, [0xAAu8; 36]);

        // A stream that closes mid-read: an io error, not a timeout.
        let (mut reader3, mut writer3) = tokio::io::duplex(64);
        writer3.write_all(&[0xBBu8; 4]).await.unwrap();
        drop(writer3);
        let err = P2PNetwork::read_exact_timeout(&mut reader3, &mut buf, Duration::from_secs(5))
            .await
            .expect_err("truncated frame must error");
        assert_ne!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn test_seen_transactions_cleanup() {
        // Test that old entries are evicted
        let seen = Arc::new(RwLock::new(HashMap::new()));

        let tx_bytes1 = vec![1u8, 2, 3, 4];
        let tx_bytes2 = vec![5u8, 6, 7, 8];

        // Insert one entry with old timestamp (use smaller duration to avoid overflow)
        {
            let mut seen_write = seen.write().await;
            let now = Instant::now();
            seen_write.insert(
                tx_bytes1.clone(),
                SeenTxEntry {
                    timestamp: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
                },
            );
            seen_write.insert(tx_bytes2.clone(), SeenTxEntry { timestamp: now });
        }

        // Simulate cleanup (remove entries older than 30 seconds)
        let now = Instant::now();
        {
            let mut seen_write = seen.write().await;
            seen_write.retain(|_, entry| {
                now.checked_duration_since(entry.timestamp)
                    .map_or(false, |d| d < Duration::from_secs(30))
            });
        }

        // Old entry should be removed, new entry should remain
        {
            let seen_read = seen.read().await;
            assert!(!seen_read.contains_key(&tx_bytes1));
            assert!(seen_read.contains_key(&tx_bytes2));
            assert_eq!(seen_read.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_seen_cache_bounded() {
        // insert_seen must keep the cache bounded: once at MAX_SEEN_TXS it
        // evicts before inserting.
        let seen = Arc::new(RwLock::new(HashMap::new()));

        // Fill past the cap with fresh entries (eviction removes one per insert
        // once the cap is reached).
        for i in 0..(MAX_SEEN_TXS + 100) {
            insert_seen(&seen, vec![(i % 256) as u8; 4]).await;
        }

        let size = seen.read().await.len();
        assert!(size <= MAX_SEEN_TXS);
    }

    #[tokio::test]
    async fn test_seen_cache_dedup_preserved_under_cap() {
        let seen = Arc::new(RwLock::new(HashMap::new()));
        let key = vec![7u8; 4];
        insert_seen(&seen, key.clone()).await;
        insert_seen(&seen, key.clone()).await;
        let map = seen.read().await;
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_limit_constants_sane() {
        // A 16 MiB frame cap + 400 msgs/s caps per-peer throughput at ~6.4 GiB/s
        // worst case, but more importantly caps single-allocation size.
        assert!(MAX_MESSAGE_SIZE <= 16 * 1024 * 1024);
        assert!(MAX_MSGS_PER_SEC >= 1);
        assert!(MAX_PEERS >= 1);
        assert!(MAX_INV_ITEMS >= 1);
    }

    /// H4/V-24: handshake identity check — a peer from another network
    /// (different genesis hash) or another protocol version must be rejected,
    /// while a same-network frame passes.
    /// PHASE 4V: the trailing network id is checked exactly (0 == 0 keeps
    /// legacy behavior; nonzero networks isolate testnets sharing binary).
    #[test]
    fn test_handshake_identity_mismatch_rejected() {
        let mut frame = vec![0u8; HANDSHAKE_FRAME_LEN];
        // 2E-A: the wire carries the obfuscated magic, not the ASCII "AETH".
        // Fixture update for the intentional v3→v4 change; the assertions
        // below are untouched.
        frame[..4].copy_from_slice(&P2PNetwork::handshake_wire_magic());
        frame[4] = P2P_PROTOCOL_VERSION;
        frame[5..37].copy_from_slice(&crate::genesis::GENESIS_HASH);
        // Network bytes zero -> legacy network 0.

        // Correct same-network frame passes.
        assert!(
            P2PNetwork::verify_handshake_identity(&frame, 0).is_ok(),
            "a same-network frame must pass"
        );

        // Wrong magic is rejected.
        let mut wrong_magic = frame.clone();
        wrong_magic[0] = 0x00;
        let err = P2PNetwork::verify_handshake_identity(&wrong_magic, 0).unwrap_err();
        assert!(err.contains("magic"), "got: {}", err);

        // Version mismatch is rejected.
        let mut wrong_version = frame.clone();
        wrong_version[4] = P2P_PROTOCOL_VERSION + 1;
        let err = P2PNetwork::verify_handshake_identity(&wrong_version, 0).unwrap_err();
        assert!(err.contains("version"), "got: {}", err);

        // Genesis (network) mismatch is rejected.
        let mut wrong_genesis = frame.clone();
        wrong_genesis[5] = 0x42;
        let err = P2PNetwork::verify_handshake_identity(&wrong_genesis, 0).unwrap_err();
        assert!(err.contains("genesis"), "got: {}", err);

        // Truncated frame is rejected.
        assert!(P2PNetwork::verify_handshake_identity(&frame[..8], 0).is_err());

        // PHASE 4V: foreign network id is rejected even when everything
        // else matches.
        let mut foreign = frame.clone();
        foreign[37..45].copy_from_slice(&7u64.to_le_bytes());
        let err = P2PNetwork::verify_handshake_identity(&foreign, 0).unwrap_err();
        assert!(err.contains("network"), "got: {}", err);
        // ...and accepted by its own network.
        assert!(P2PNetwork::verify_handshake_identity(&foreign, 7).is_ok());

        // PHASE 4V: pre-change 69-byte frame (no network field) is too
        // short -> clean length rejection, never silent acceptance.
        assert!(P2PNetwork::verify_handshake_identity(&frame[..69], 0).is_err());
    }

    /// H4/V-24: two ends of the SAME network complete the X25519 handshake
    /// and derive the SAME session key with opposite send directions.
    #[tokio::test]
    async fn test_handshake_derives_shared_key() {
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);

        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer, 0);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer, 0);
        let (ra, rb) = tokio::join!(a, b);

        let (key_a, dir_a) = ra.expect("side A handshake must succeed");
        let (key_b, dir_b) = rb.expect("side B handshake must succeed");
        assert_eq!(key_a, key_b, "both ends must derive the same session key");
        assert_ne!(dir_a, dir_b, "directions must be opposite");
    }

    /// PHASE 4V: same-network duplex handshakes complete on nonzero
    /// networks, and cross-network duplex handshakes fail on BOTH ends
    /// (neither side accepts silently).
    #[tokio::test]
    async fn test_handshake_network_isolation() {
        for net in [7u64, 9u64] {
            let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
            let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer, net);
            let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer, net);
            let (ra, rb) = tokio::join!(a, b);
            let (key_a, _) = ra.expect("same-network handshake must succeed");
            let (key_b, _) = rb.expect("same-network handshake must succeed");
            assert_eq!(key_a, key_b);
        }
        // Cross-network: A=7 advertises 7, B=9 advertises 9; each side
        // rejects the other's frame, so both futures fail.
        let (mut a_reader, mut b_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let (mut b_reader, mut a_writer) = tokio::io::duplex(HANDSHAKE_FRAME_LEN * 2);
        let a = P2PNetwork::handshake(&mut a_reader, &mut a_writer, 7);
        let b = P2PNetwork::handshake(&mut b_reader, &mut b_writer, 9);
        let (ra, rb) = tokio::join!(a, b);
        assert!(ra.is_err(), "A=7 must reject B=9 frame");
        assert!(rb.is_err(), "B=9 must reject A=7 frame");
    }

    #[tokio::test]
    async fn test_broadcast_marks_as_local() {
        // Test that broadcast_transaction marks tx as Local before sending
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            Arc::new(crate::sync_stats::SyncContext::default()),
            Arc::new(|_| false),
        );

        let tx = Transaction::new(
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

        let tx_bytes = bincode::serialize(&tx).unwrap();

        // Broadcast should mark as seen
        p2p.broadcast_transaction(tx.clone()).await;

        // Check that it's in seen_transactions
        let seen = p2p.seen_transactions.read().await;
        assert!(seen.contains_key(&tx_bytes));
    }

    /// B4: partition_batch must be ORDER-INDEPENDENT. A chain A->B->C->D is
    /// fully deliverable in parent-first order, and the same set in
    /// child-first order must yield the SAME deliverable set (parents first).
    #[test]
    fn test_partition_batch_order_independent() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [b.id, genesis]);
        let d = mk(4, [c.id, genesis]);

        // DAG already contains genesis (and nothing else): lookup by id.
        let has_in_dag = |id: &[u8]| -> Option<Transaction> {
            let ids: [[u8; 32]; 4] = [a.id, b.id, c.id, d.id];
            if ids.iter().any(|x| x.as_slice() == id) {
                None
            } else {
                Some(a.clone())
            }
        };
        let serialize = |tx: &Transaction| bincode::serialize(tx).unwrap();

        // Parent-first order: everything deliverable.
        let (del, wait) = P2PNetwork::partition_batch(
            vec![
                (serialize(&a), a.clone()),
                (serialize(&b), b.clone()),
                (serialize(&c), c.clone()),
                (serialize(&d), d.clone()),
            ],
            &has_in_dag,
        );
        assert_eq!(del.len(), 4, "parent-first chain must be fully deliverable");
        assert!(wait.is_empty());

        // Child-first order: the SAME deliverable set. The head (a) is
        // deliverable (parents = genesis); once inserted in-batch, b, c and d
        // unlock in the same passes -> identical partition, no orphans.
        let (del2, wait2) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
                (serialize(&a), a.clone()),
            ],
            &has_in_dag,
        );
        assert_eq!(del2.len(), 4, "child-first chain must also fully resolve");
        assert!(wait2.is_empty());
        let mut del_ids: Vec<[u8; 32]> = del.into_iter().map(|(_, t)| t.id).collect();
        let mut del2_ids: Vec<[u8; 32]> = del2.into_iter().map(|(_, t)| t.id).collect();
        del_ids.sort();
        del2_ids.sort();
        assert_eq!(
            del_ids, del2_ids,
            "deliverable set must be order-independent"
        );

        // Without the head (a missing from the DAG AND the batch): everything
        // waits. Parents are requested via the orphan flow instead.
        let (del3, wait3) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
            ],
            &has_in_dag,
        );
        assert!(del3.is_empty(), "no head -> nothing deliverable in-batch");
        assert_eq!(wait3.len(), 3, "all members wait for the missing parent");
    }

    /// B4: a diamond A->(B,C)->D: B and C are both deliverable once A is in
    /// the DAG; D waits for both.
    #[test]
    fn test_partition_batch_diamond() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [a.id, genesis]);
        let d = mk(4, [b.id, c.id]);

        let has_in_dag = |id: &[u8]| -> Option<Transaction> {
            let known: Vec<[u8; 32]> = vec![a.id, b.id, c.id, d.id];
            if known.iter().any(|x| x.as_slice() == id) {
                None
            } else {
                Some(a.clone())
            }
        };
        let serialize = |tx: &Transaction| bincode::serialize(tx).unwrap();

        // Arrive in worst order: D, C, B, A.
        let (del, wait) = P2PNetwork::partition_batch(
            vec![
                (serialize(&d), d.clone()),
                (serialize(&c), c.clone()),
                (serialize(&b), b.clone()),
                (serialize(&a), a.clone()),
            ],
            &has_in_dag,
        );
        // After the passes: A deliverable (parents=genesis); then B and C
        // (parent A now inserted in-batch); D still waits for C/B? No: B and C
        // are inserted, so D becomes deliverable in the same pass chain.
        assert_eq!(del.len(), 4, "diamond must resolve fully in-batch");
        assert!(wait.is_empty());
    }

    /// B4: parent-request dedup. Two immediate requests for the same parent
    /// must produce ONE actual request; the second is counted as
    /// already-known (backoff).
    #[tokio::test]
    async fn test_request_transaction_dedup() {
        let (tx_channel, _tx_receiver) = mpsc::unbounded_channel::<Transaction>();
        let ctx = Arc::new(crate::sync_stats::SyncContext::default());
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            ctx.clone(),
            Arc::new(|_| false),
        );

        let hash = vec![0xABu8; 32];
        p2p.request_transaction(hash.clone()).await;
        p2p.request_transaction(hash.clone()).await;
        p2p.request_transaction(hash).await;

        let snap = ctx.stats.snapshot();
        assert_eq!(snap.parent_requested, 1, "only the first request is sent");
        assert_eq!(
            snap.parent_already_known, 2,
            "repeats within the cooldown are deduplicated"
        );
    }

    /// VPS-2 helper: build a linear chain root -> ... -> tip on top of
    /// genesis parents. Returns txs oldest-first.
    #[cfg(test)]
    fn test_chain(n: usize, start: u8) -> Vec<Transaction> {
        use crate::Transaction;
        let genesis = [0u8; 32];
        let mut chain = Vec::new();
        let mut parent = genesis;
        for i in 0..n {
            let tx = Transaction::new(
                [parent, genesis],
                [start.wrapping_add(i as u8); 32],
                [200u8; 32],
                100,
                10,
                1234567890 + i as u64,
                0,
                i as u64,
                vec![0u8; 64],
                vec![0u8; 32],
            );
            parent = tx.id;
            chain.push(tx);
        }
        chain
    }

    /// VPS-2: requesting only the tip of a chain returns the whole
    /// ancestor-closed set (chain length < budget).
    #[test]
    fn test_ancestor_closed_page_closes_chain() {
        let chain = test_chain(10, 50);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let page = P2PNetwork::ancestor_closed_page(vec![tip.clone()], &lookup);
        assert_eq!(page.len(), 10, "full chain must be included");
        assert!(page.contains(&tip));
        assert!(page.contains(&chain[0].id.to_vec()));
        // Deterministic: same input twice, same output.
        let again = P2PNetwork::ancestor_closed_page(vec![tip], &lookup);
        assert_eq!(page, again);
    }

    /// VPS-2 §12 anti-loop/bound: a 600-deep chain with budget 400 returns
    /// exactly tip + 400 nearest ancestors (401), terminates, no dupes.
    #[test]
    fn test_ancestor_closed_page_budget_bound() {
        let chain = test_chain(600, 10);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let page = P2PNetwork::ancestor_closed_page(vec![tip], &lookup);
        assert_eq!(page.len(), 401, "tip + exactly 400 ancestors");
        // Nearest 400 present (indices 199..=598), the next one excluded.
        assert!(page.contains(&chain[599].id.to_vec()));
        assert!(page.contains(&chain[200].id.to_vec()));
        assert!(page.contains(&chain[199].id.to_vec()));
        assert!(!page.contains(&chain[198].id.to_vec()));
        let mut sorted = page.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), page.len(), "no duplicates in page");
    }

    /// VPS-2 §12: unknown hashes are skipped (never invented), duplicate
    /// requests deduped, genesis terminates.
    #[test]
    fn test_ancestor_closed_page_skips_unknown_and_dupes() {
        let chain = test_chain(5, 80);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> =
            chain.iter().map(|t| (t.id.to_vec(), t.clone())).collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };
        let tip = chain.last().unwrap().id.to_vec();
        let ghost = vec![0xFFu8; 32];
        let page = P2PNetwork::ancestor_closed_page(
            vec![tip.clone(), ghost.clone(), tip.clone()],
            &lookup,
        );
        assert_eq!(page.len(), 5, "chain once, ghost skipped, dupe dropped");
        assert!(!page.contains(&ghost));
    }

    /// C2-004: topological_order must emit parents before children.
    /// The previous implementation incremented the PARENT's counter
    /// (counting children), serving tips-first: joining nodes parked
    /// every batch as orphans and the re-request storm collapsed serving
    /// nodes at ~10k txs.    #[test]
    fn test_topological_order_parents_first() {
        let mk = |id: u8, parents: [[u8; 32]; 2]| -> Transaction {
            Transaction::new(
                parents,
                [id; 32],
                [id + 1; 32],
                100,
                10,
                1234567890 + id as u64,
                0,
                1,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        };
        let genesis = [0u8; 32];
        let a = mk(1, [genesis, genesis]);
        let b = mk(2, [a.id, genesis]);
        let c = mk(3, [a.id, genesis]);
        let d = mk(4, [b.id, c.id]);
        let by_id: std::collections::HashMap<Vec<u8>, Transaction> = [&a, &b, &c, &d]
            .into_iter()
            .map(|t| (t.id.to_vec(), t.clone()))
            .collect();
        let lookup = |h: &[u8]| -> Option<Transaction> { by_id.get(h).cloned() };

        // Feed child-first: the order must still come out parents-first.
        let hashes = vec![d.id.to_vec(), c.id.to_vec(), b.id.to_vec(), a.id.to_vec()];
        let order =
            P2PNetwork::topological_order(hashes, &lookup).expect("chain+diamond must sort");
        assert_eq!(order.len(), 4);
        let pos = |id: &[u8; 32]| order.iter().position(|h| h.as_slice() == id).unwrap();
        assert!(pos(&a.id) < pos(&b.id), "A before B");
        assert!(pos(&a.id) < pos(&c.id), "A before C");
        assert!(pos(&b.id) < pos(&d.id), "B before D");
        assert!(pos(&c.id) < pos(&d.id), "C before D");
    }

    #[test]
    fn test_subnet_24_ipv4() {
        let addr: SocketAddr = "192.168.1.100:30333".parse().unwrap();
        assert_eq!(subnet_24(addr), Some([192, 168, 1]));
        let same: SocketAddr = "192.168.1.200:30333".parse().unwrap();
        assert_eq!(subnet_24(same), Some([192, 168, 1]));
        let diff: SocketAddr = "192.168.2.100:30333".parse().unwrap();
        assert_eq!(subnet_24(diff), Some([192, 168, 2]));
    }

    #[test]
    fn test_subnet_24_ipv6() {
        let addr: SocketAddr = "[2a0c:b641:1a0:800::ba]:30333".parse().unwrap();
        let sub = subnet_24(addr);
        assert!(sub.is_some(), "IPv6 must return a subnet");
    }

    #[test]
    fn test_count_subnet_peers() {
        let peers: HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
        let addr: SocketAddr = "10.0.0.1:30333".parse().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let count = rt.block_on(count_subnet_peers(addr, &peers));
        assert_eq!(count, 0);
    }

    #[test]
    fn test_diversity_constants() {
        assert!(
            MAX_PEERS_PER_SUBNET >= 2,
            "must allow at least 2 peers per /24"
        );
        assert!(MAX_PEERS_PER_SUBNET <= 16, "must limit to prevent eclipse");
        assert!(
            PROTECTED_OUTBOUND_SLOTS >= 4,
            "must protect at least 4 outbound slots"
        );
        assert!(
            PROTECTED_OUTBOUND_SLOTS < MAX_PEERS,
            "protected must be less than total"
        );
    }

    // === Phase 8: Adversarial P2P Tests ===

    #[test]
    fn test_peer_score_initial() {
        let score = PeerScore::new();
        assert_eq!(score.score, PEER_SCORE_INITIAL);
        assert!(!score.is_banned());
        assert_eq!(score.temp_bans, 0);
    }

    #[test]
    fn test_peer_score_penalize() {
        let mut score = PeerScore::new();
        assert!(!score.penalize(PEER_PENALTY_INVALID_MSG));
        assert_eq!(score.score, PEER_SCORE_INITIAL + PEER_PENALTY_INVALID_MSG);
        // Enough penalties to drop below threshold
        for _ in 0..10 {
            if score.penalize(PEER_PENALTY_INVALID_MSG) {
                break;
            }
        }
        assert!(score.score <= PEER_SCORE_BAN_THRESHOLD);
    }

    #[test]
    fn test_peer_score_ban_temp_then_perm() {
        let mut score = PeerScore::new();
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert!(score.is_banned());
        assert_eq!(score.temp_bans, 1);
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert_eq!(score.temp_bans, 2);
        score.score = PEER_SCORE_BAN_THRESHOLD;
        score.ban();
        assert_eq!(score.temp_bans, 3);
        assert!(score.is_banned());
    }

    #[test]
    fn test_peer_score_decay() {
        let mut score = PeerScore::new();
        score.score = 50;
        score.last_decay = Instant::now() - Duration::from_secs(600);
        score.decay();
        assert_eq!(score.score, 51);
    }

    #[test]
    fn test_peer_score_decay_no_op() {
        let mut score = PeerScore::new();
        score.last_decay = Instant::now() - Duration::from_secs(600);
        score.decay();
        assert_eq!(score.score, PEER_SCORE_INITIAL);
    }

    #[test]
    fn test_peer_score_reward() {
        let mut score = PeerScore::new();
        score.reward(PEER_BONUS_SYNC);
        assert_eq!(score.score, PEER_SCORE_INITIAL + PEER_BONUS_SYNC);
        score.reward(100);
        assert_eq!(score.score, PEER_SCORE_INITIAL + 50);
    }

    #[test]
    fn test_subnet_diversity_limit() {
        let mut count = 0;
        for i in 1..=5 {
            let addr: SocketAddr = format!("192.168.1.{}:30333", i).parse().unwrap();
            if subnet_24(addr) == Some([192, 168, 1]) {
                count += 1;
            }
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn test_eclipse_attack_blocked() {
        let attacker_subnet = [10, 0, 0];
        let mut allowed = 0;
        for i in 1..=10 {
            let addr: SocketAddr = format!("10.0.0.{}:30333", i).parse().unwrap();
            if subnet_24(addr) == Some(attacker_subnet) && allowed < MAX_PEERS_PER_SUBNET {
                allowed += 1;
            }
        }
        assert_eq!(allowed, MAX_PEERS_PER_SUBNET);
    }

    #[test]
    fn test_scoring_flood_bans() {
        let mut score = PeerScore::new();
        for _ in 0..7 {
            if score.penalize(PEER_PENALTY_FLOOD) {
                score.ban();
                break;
            }
        }
        assert!(score.is_banned());
    }

    #[test]
    fn test_scoring_slow_not_banned() {
        let mut score = PeerScore::new();
        for _ in 0..10 {
            score.penalize(PEER_PENALTY_TIMEOUT);
        }
        assert!(score.score > PEER_SCORE_BAN_THRESHOLD);
        assert!(!score.is_banned());
    }

    // ===== DEEP SYNC TESTS =====

    /// Helper: build a linear chain of `n` transactions in a lookup table.
    /// Returns (tip_hash, lookup_fn).
    fn build_linear_chain(n: usize) -> (Vec<u8>, impl Fn(&[u8]) -> Option<Transaction>) {
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let mut prev_hash = [0u8; 32]; // genesis parent
        for i in 0..n {
            let mut parents = [[0u8; 32]; 2];
            parents[0] = prev_hash;
            parents[1] = [0u8; 32];
            let tx = Transaction::new(
                parents,
                [1u8; 32],       // sender
                [2u8; 32],       // receiver
                100,             // amount
                1,               // fee
                1000 + i as u64, // timestamp
                0,               // nonce
                0,               // account_nonce
                vec![],          // signature
                vec![],          // public_key
            );
            prev_hash = tx.id;
            chain.insert(tx.id.to_vec(), tx);
        }
        let tip = prev_hash.to_vec();
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        (tip, lookup)
    }

    #[test]
    fn test_ancestor_full_closure_linear_chain() {
        let (tip, lookup) = build_linear_chain(10);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, 100);
        // Full closure of a 10-tx chain should include all 10 txs.
        assert_eq!(
            closure.len(),
            10,
            "full closure should include all ancestors"
        );
        // The tip itself should be in the closure.
        assert!(closure.iter().any(|h| h == &tip));
    }

    #[test]
    fn test_ancestor_full_closure_respects_max_entries() {
        let (tip, lookup) = build_linear_chain(50);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, 20);
        // Should be capped at max_entries (20), not the full chain (50).
        assert!(
            closure.len() <= 20,
            "closure should respect max_entries bound"
        );
        assert!(closure.len() > 0, "closure should not be empty");
    }

    #[test]
    fn test_ancestor_full_closure_empty_request() {
        let (_tip, lookup) = build_linear_chain(10);
        let closure = P2PNetwork::ancestor_full_closure(&[], &lookup, 100);
        assert_eq!(
            closure.len(),
            0,
            "empty request should produce empty closure"
        );
    }

    #[test]
    fn test_ancestor_full_closure_unknown_hashes_skipped() {
        let (_tip, lookup) = build_linear_chain(10);
        let unknown = vec![99u8; 32];
        let closure = P2PNetwork::ancestor_full_closure(&[unknown], &lookup, 100);
        assert_eq!(closure.len(), 0, "unknown hashes should be skipped");
    }

    #[test]
    fn test_ancestor_full_closure_duplicate_requests_deduped() {
        let (tip, lookup) = build_linear_chain(5);
        let closure = P2PNetwork::ancestor_full_closure(&[tip.clone(), tip.clone()], &lookup, 100);
        // Duplicate request hashes should be deduplicated.
        assert_eq!(closure.len(), 5, "duplicates should be deduped");
    }

    #[test]
    fn test_ancestor_full_closure_genesis_terminated() {
        // Chain where a tx has genesis parent [0; 32].
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let genesis_parent = [0u8; 32];
        let tx = Transaction::new(
            [genesis_parent, [0u8; 32]],
            [1u8; 32],
            [2u8; 32],
            100,
            1,
            1000,
            0,
            0,
            vec![],
            vec![],
        );
        let id = tx.id.to_vec();
        chain.insert(id.clone(), tx);
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        let closure = P2PNetwork::ancestor_full_closure(&[id.clone()], &lookup, 100);
        // Genesis parent [0; 32] should not be in the closure.
        assert_eq!(closure.len(), 1, "genesis parent should be terminated");
    }

    #[test]
    fn test_ancestor_full_closure_bounded_by_max_entries() {
        // Build a deep chain and verify the bound is strict.
        let (tip, lookup) = build_linear_chain(100);
        for max in [5, 10, 25, 50] {
            let closure = P2PNetwork::ancestor_full_closure(&[tip.clone()], &lookup, max);
            assert!(
                closure.len() <= max,
                "closure len {} should be <= max_entries {}",
                closure.len(),
                max
            );
        }
    }

    #[test]
    fn test_ancestor_full_closure_diamond_dag() {
        // Build a diamond DAG: genesis -> A, genesis -> B, A+B -> C (tip).
        let mut chain: HashMap<Vec<u8>, Transaction> = HashMap::new();
        let genesis = [0u8; 32];
        let tx_a = Transaction::new(
            [genesis, genesis],
            [1u8; 32],
            [2u8; 32],
            10,
            1,
            100,
            0,
            0,
            vec![],
            vec![],
        );
        let tx_b = Transaction::new(
            [genesis, genesis],
            [1u8; 32],
            [2u8; 32],
            20,
            1,
            101,
            0,
            1,
            vec![],
            vec![],
        );
        let id_a = tx_a.id;
        let id_b = tx_b.id;
        chain.insert(id_a.to_vec(), tx_a);
        chain.insert(id_b.to_vec(), tx_b);
        let tx_c = Transaction::new(
            [id_a, id_b],
            [1u8; 32],
            [2u8; 32],
            30,
            1,
            102,
            0,
            2,
            vec![],
            vec![],
        );
        let id_c = tx_c.id;
        chain.insert(id_c.to_vec(), tx_c);
        let lookup = move |hash: &[u8]| -> Option<Transaction> { chain.get(hash).cloned() };
        let closure = P2PNetwork::ancestor_full_closure(&[id_c.to_vec()], &lookup, 100);
        // Should include C, A, B = 3 txs (genesis [0;32] is terminated).
        assert_eq!(closure.len(), 3, "diamond closure should include all 3 txs");
        assert!(closure.iter().any(|h| h == &id_a.to_vec()));
        assert!(closure.iter().any(|h| h == &id_b.to_vec()));
        assert!(closure.iter().any(|h| h == &id_c.to_vec()));
    }
}

/// Phase 2E-D — privacy-aware transaction propagation.
///
/// The step is judged on one number, `TRANSACTION_CORRELATION_RISK`
/// (`HIGH` → `REDUCED`), decomposed into the five mechanisms it is built
/// from: jitter, bounded fan-out, scheduling dedup, validation-before-relay
/// and network-group diversity. Every assertion here maps to one of them,
/// plus the two convergence/independence properties the step must NOT have
/// broken (`MULTIHOP_CONVERGENCE`, `BOOTNODE_INDEPENDENCE`).
///
/// Nothing in this module starts a TCP connection or sleeps on a real
/// schedule longer than `PROPAGATION_JITTER_MAX + 50 ms`.
#[cfg(test)]
mod phase2_privacy_propagation_tests {
    use super::*;
    use crate::transaction_processor::TransactionProcessor;
    use crate::validation::ValidationMode;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// `groups` distinct /24s with `per_group` hosts in each. The group key
    /// is `10.<g>.0.x`, so the host index never moves an address into a
    /// different group — `peer_grid(4, 8)` really is 4 groups, not 32.
    fn peer_grid(groups: usize, per_group: usize) -> Vec<SocketAddr> {
        let mut v = Vec::with_capacity(groups * per_group);
        for g in 0..groups {
            for h in 0..per_group {
                v.push(addr(&format!("10.{}.0.{}:9000", g, h + 1)));
            }
        }
        v
    }

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn make_tx(tag: u64) -> Transaction {
        let mut sender = [0u8; 32];
        sender[..8].copy_from_slice(&tag.to_le_bytes());
        sender[8] = 0x5A;
        Transaction::new(
            [[0u8; 32]; 2],
            sender,
            [7u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        )
    }

    /// A node with `addrs` already in its session table, each with a
    /// live outbound channel. The receivers come back so a test can count
    /// what actually went on the wire.
    async fn network_with_peers(
        addrs: &[SocketAddr],
    ) -> (P2PNetwork, Vec<mpsc::UnboundedReceiver<Vec<u8>>>) {
        let (tx_channel, _rx) = mpsc::unbounded_channel::<Transaction>();
        let p2p = P2PNetwork::new(
            P2PConfig::default(),
            tx_channel,
            Arc::new(|| vec![]),
            Arc::new(|_| None),
            Arc::new(|| vec![]),
            Arc::new(crate::sync_stats::SyncContext::default()),
            Arc::new(|_| false),
        );
        let mut rxs = Vec::with_capacity(addrs.len());
        for a in addrs {
            let (sx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            p2p.peers.write().await.insert(*a, sx);
            rxs.push(rx);
        }
        (p2p, rxs)
    }

    /// Drain everything a peer received since the last call.
    fn drain(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> usize {
        let mut n = 0;
        while rx.try_recv().is_ok() {
            n += 1;
        }
        n
    }

    // --- relay timing -------------------------------------------------------

    /// JITTER: every draw sits inside the declared window, both ends of it
    /// are actually reached (so nothing is clamped toward zero), and zero
    /// itself is impossible — `relay_t == receive_t` cannot be constructed.
    #[test]
    fn test_relay_delay_bounds_and_spread() {
        assert!(
            PROPAGATION_JITTER_MIN > Duration::ZERO,
            "a zero minimum would make `relay_t == receive_t` reachable"
        );
        assert!(PROPAGATION_JITTER_MAX > PROPAGATION_JITTER_MIN);

        let mut r = rng(1);
        let mut lo = Duration::MAX;
        let mut hi = Duration::ZERO;
        for _ in 0..10_000 {
            let d = propagation_delay(&mut r);
            assert!(
                d >= PROPAGATION_JITTER_MIN && d <= PROPAGATION_JITTER_MAX,
                "out of window: {:?}",
                d
            );
            lo = lo.min(d);
            hi = hi.max(d);
        }
        assert_eq!(lo, PROPAGATION_JITTER_MIN, "window floor never reached");
        assert_eq!(hi, PROPAGATION_JITTER_MAX, "window ceiling never reached");
    }

    /// JITTER: the delay is a function of the RNG and of nothing else — same
    /// seed replays, a different seed does not, and a single wave is never one
    /// fixed offset. There is deliberately no content parameter to derive from,
    /// so a transaction cannot imprint its own timing signature.
    #[test]
    fn test_relay_delay_depends_only_on_the_rng() {
        let mut r1 = rng(7);
        let mut r2 = rng(7);
        let mut r3 = rng(8);
        let a: Vec<Duration> = (0..16).map(|_| propagation_delay(&mut r1)).collect();
        let b: Vec<Duration> = (0..16).map(|_| propagation_delay(&mut r2)).collect();
        let c: Vec<Duration> = (0..16).map(|_| propagation_delay(&mut r3)).collect();

        assert_eq!(a, b, "identical seeds must replay an identical wave");
        assert_ne!(a, c, "a different seed must produce a different schedule");
        assert!(
            a.iter().any(|d| *d != a[0]),
            "a wave must not collapse to one fixed offset (that is the leak 2E-D removes)"
        );
    }

    // --- fan-out / peer selection ------------------------------------------

    /// BOUNDED FANOUT: never more peers than the constant, never a duplicate
    /// target, never empty while the table is populated — and the constant
    /// itself stays at the reviewed value.
    #[test]
    fn test_fanout_is_bounded() {
        assert_eq!(
            MAX_PROPAGATION_FANOUT, 4,
            "2E-D picks fan-out 4 (>= 3-5 is the standard gossip working point); \
             changing it needs a fresh derivation, not a tweak"
        );

        let peers = peer_grid(1, 128);
        for seed in 0..64 {
            let t = propagation_targets(&peers, None, MAX_PROPAGATION_FANOUT, &mut rng(seed));
            assert!(t.len() <= MAX_PROPAGATION_FANOUT, "seed {seed}: {}", t.len());
            assert!(!t.is_empty());
            let unique: HashSet<_> = t.iter().collect();
            assert_eq!(unique.len(), t.len(), "seed {seed}: duplicate target");
        }
    }

    /// NOT BACK TO THE SENDER: the upstream peer is always dropped, and the
    /// wave still reaches its full size — excluding one peer must not shrink
    /// coverage (it never was the peer's own turn).
    #[test]
    fn test_upstream_peer_is_excluded_without_shrinking_the_wave() {
        let peers = peer_grid(4, 4);
        let source = peers[7];
        for seed in 0..64 {
            let t = propagation_targets(&peers, Some(source), 4, &mut rng(seed));
            assert!(!t.contains(&source), "seed {seed}: sent back to the sender");
            assert_eq!(t.len(), 4, "seed {seed}: exclusion shrank the wave");
        }
    }

    /// NETWORK DIVERSITY: with four groups and a fan-out of four, one group
    /// may not own the wave. This is the reuse of the Phase 2C primitive that
    /// makes the observing set span independent networks.
    #[test]
    fn test_fanout_spans_network_groups() {
        let peers = peer_grid(4, 8);
        for seed in 0..32 {
            let t = propagation_targets(&peers, None, 4, &mut rng(seed));
            let groups: HashSet<_> = t.iter().map(|a| network_group(*a)).collect();
            assert_eq!(groups.len(), 4, "seed {seed}: only {:?} groups", groups);
        }
    }

    /// DIVERSITY must not cost coverage: a node whose peers sit in two groups
    /// still reaches `MAX_PROPAGATION_FANOUT`, because the quota is relaxed.
    #[test]
    fn test_topology_cannot_shrink_the_fanout() {
        let mut peers = peer_grid(1, 4);
        peers.push(addr("10.1.0.1:9000"));
        for seed in 0..32 {
            let t = propagation_targets(&peers, None, 4, &mut rng(seed));
            assert_eq!(
                t.len(),
                4,
                "seed {seed}: two-group topology must still reach the fan-out"
            );
        }
    }

    /// SELECTION is random, not the `HashMap` iteration order: the chosen set
    /// varies across seeds rather than repeating one fixed ordering.
    #[test]
    fn test_fanout_selection_varies_by_seed() {
        let peers = peer_grid(8, 4);
        let mut seen: HashSet<Vec<SocketAddr>> = HashSet::new();
        for seed in 0..64 {
            seen.insert(propagation_targets(&peers, None, 4, &mut rng(seed)));
        }
        assert!(
            seen.len() > 8,
            "selection looks fixed: only {} distinct choices in 64 seeds",
            seen.len()
        );
    }

    /// BOOTNODE INDEPENDENCE: no address is systematically excluded (which
    /// would mean a hard-coded allow-list) and none dominates the wave (which
    /// would mean a privileged, named relay position). Every connected peer
    /// is reachable, and the observed share stays near the fair `fanout/n`.
    #[test]
    fn test_no_privileged_relay_address() {
        let peers = peer_grid(8, 4);
        const ROUNDS: usize = 1024;
        let mut hits: HashMap<SocketAddr, usize> = HashMap::new();
        for seed in 0..ROUNDS as u64 {
            for a in propagation_targets(&peers, None, 4, &mut rng(seed)) {
                *hits.entry(a).or_insert(0) += 1;
            }
        }
        assert_eq!(
            hits.len(),
            peers.len(),
  "some address is never selected  -  that is a privileged relay role"
        );

        let fair = 4.0 / peers.len() as f64;
        let worst = hits.values().copied().max().unwrap() as f64 / ROUNDS as f64;
        assert!(
            worst < fair * 2.5,
            "one address appears in {:.1}% of waves (fair share is {:.1}%)",
            worst * 100.0,
            fair * 100.0
        );
    }

    // --- receive stage: no relay, ever -------------------------------------

    /// VALIDATION BEFORE RELAY, structurally: receiving a payload records the
    /// upstream peer and queues it for validation, but leaves `scheduled` at
    /// false. The flag can only be set from `broadcast_transaction`, which is
    /// downstream of `validate_pure` — so `scheduled == false` here IS the
    /// proof that the receive stage transmits nothing.
    #[tokio::test]
    async fn test_receive_stage_schedules_no_relay() {
        let seen: RwLock<HashMap<Vec<u8>, SeenTxEntry>> = RwLock::new(HashMap::new());
        let state: RwLock<PropagationState> = RwLock::new(HashMap::new());
        let (tx_channel, mut rx) = mpsc::unbounded_channel::<Transaction>();

        let tx = make_tx(1);
        let bytes = bincode::serialize(&tx).unwrap();
        let source = addr("10.0.0.9:9000");

        let accepted = accept_inbound_transaction(
            bytes.clone(),
            source,
            &seen,
            &state,
            &tx_channel,
        )
        .await;
        assert!(accepted, "a well-formed payload must reach the validator");
        assert!(rx.try_recv().is_ok(), "and must be queued for validation");

        let st = state.read().await;
        let entry = st.get(&bytes).expect("ingress must record the payload");
        assert_eq!(entry.source, Some(source), "upstream peer must be recorded");
        assert!(
            !entry.scheduled,
  "receiving must not schedule a relay wave  -  that is the double relay, gone"
        );
    }

    /// DEDUPLICATION: a payload already scheduled never schedules a second
    /// wave, whether the duplicate arrives from the network or is re-submitted
    /// locally. This is the check that takes the per-link copy count 2 -> 1.
    #[tokio::test]
    async fn test_a_payload_schedules_exactly_one_wave() {
        let state: RwLock<PropagationState> = RwLock::new(HashMap::new());
        let bytes = vec![9u8; 32];

        assert!(
            take_propagation_slot(&state, &bytes).await.is_some(),
            "the first claim owns the wave"
        );
        assert!(
            take_propagation_slot(&state, &bytes).await.is_none(),
            "a duplicate must not open a second wave"
        );
        assert!(
            take_propagation_slot(&state, &bytes).await.is_none(),
            "…nor a third"
        );
        assert_eq!(state.read().await.len(), 1, "state stays payload-keyed");
    }

    /// First observation wins: a payload seen from A then from B is still
    /// attributed to A, so the wave excludes A and not some other peer.
    #[tokio::test]
    async fn test_upstream_peer_is_first_observation() {
        let state: RwLock<PropagationState> = RwLock::new(HashMap::new());
        let bytes = vec![4u8; 32];
        let a = addr("10.0.0.1:9000");
        let b = addr("10.1.0.1:9000");

        record_propagation_source(&state, &bytes, a).await;
        record_propagation_source(&state, &bytes, b).await;

        let claimed = take_propagation_slot(&state, &bytes)
            .await
            .expect("first claim owns the wave");
        assert_eq!(claimed, Some(a), "first observation must be preserved");
    }

    /// A locally created payload (RPC, faucet, miner) has no upstream peer:
    /// the wave must still open, with `None`, so a local submission is not
    /// silently dropped from propagation.
    #[tokio::test]
    async fn test_local_payload_still_propagates() {
        let state: RwLock<PropagationState> = RwLock::new(HashMap::new());
        let bytes = vec![5u8; 32];
        let claimed = take_propagation_slot(&state, &bytes)
            .await
            .expect("a local submission must schedule a wave");
        assert_eq!(claimed, None, "…with no upstream peer to exclude");
    }

    // --- end to end ---------------------------------------------------------

    /// DUPLICATION: every connected peer receives AT MOST ONE copy of a given
    /// payload, and a second broadcast of the same payload delivers nothing at
    /// all. (Before 2E-D the same link carried two — receive-relay plus
    /// post-validation broadcast.)
    #[tokio::test]
    async fn test_each_peer_receives_at_most_one_copy() {
        let peers = peer_grid(2, 4);
        let (p2p, mut rxs) = network_with_peers(&peers).await;

        let tx = make_tx(11);
        p2p.broadcast_transaction(tx.clone()).await;
        tokio::time::sleep(PROPAGATION_JITTER_MAX + Duration::from_millis(50)).await;

        let first: Vec<usize> = rxs.iter_mut().map(drain).collect();
        assert!(first.iter().sum::<usize>() >= 1, "the wave must reach someone");
        assert!(
            first.iter().all(|n| *n <= 1),
            "a peer received more than one copy: {:?}",
            first
        );
        assert!(
            *first.iter().max().unwrap() <= MAX_PROPAGATION_FANOUT,
            "fan-out exceeded"
        );

        // Re-broadcasting the same payload must schedule nothing.
        p2p.broadcast_transaction(tx).await;
        tokio::time::sleep(PROPAGATION_JITTER_MAX + Duration::from_millis(50)).await;
        let second: usize = rxs.iter_mut().map(drain).sum();
        assert_eq!(second, 0, "a duplicate opened a second wave");
    }

    /// NOT BACK TO THE SENDER, end to end: the peer the payload came from is
    /// left out of the wave, and the wave is still fully sized.
    #[tokio::test]
    async fn test_upstream_peer_never_receives_the_relay() {
        let peers = peer_grid(4, 4);
        let source = peers[7];
        let (p2p, mut rxs) = network_with_peers(&peers).await;

        let tx = make_tx(21);
        let bytes = bincode::serialize(&tx).unwrap();
        record_propagation_source(&p2p.propagation_state, &bytes, source).await;

        p2p.broadcast_transaction(tx).await;
        tokio::time::sleep(PROPAGATION_JITTER_MAX + Duration::from_millis(50)).await;

        let idx = peers.iter().position(|a| *a == source).unwrap();
        assert_eq!(
            drain(&mut rxs[idx]),
            0,
            "the upstream peer was told about a payload it already had"
        );

        let total: usize = rxs.iter_mut().map(drain).sum();
        assert_eq!(
            total,
            MAX_PROPAGATION_FANOUT,
            "exclusion must not shrink the wave"
        );
    }

    /// The in-flight counter returns to zero: scheduled relays are tasks that
    /// finish, not a queue that accumulates without bound.
    #[tokio::test]
    async fn test_inflight_relays_drain_to_zero() {
        let peers = peer_grid(4, 4);
        let (p2p, mut rxs) = network_with_peers(&peers).await;

        for i in 0..32u64 {
            p2p.broadcast_transaction(make_tx(100 + i)).await;
            assert!(
                p2p.propagation_inflight() <= 32 * MAX_PROPAGATION_FANOUT,
                "in-flight must stay proportional to concurrent waves"
            );
        }

        tokio::time::sleep(PROPAGATION_JITTER_MAX + Duration::from_millis(50)).await;
        assert_eq!(
            p2p.propagation_inflight(),
            0,
            "relays must complete rather than queue up"
        );
        let delivered: usize = rxs.iter_mut().map(drain).sum();
        assert!(delivered <= 32 * MAX_PROPAGATION_FANOUT);
    }

    // --- validation ordering ------------------------------------------------

    /// VALIDATION BEFORE RELAY: the relay call site sits strictly downstream
    /// of the pure gate in `process_transaction`, and the receive arm holds
    /// no peer-table access at all. A payload the gate rejects therefore never
    /// reaches a socket, and there is no second, hidden relay path to fall
    /// back on.
    #[test]
    fn test_relay_is_reachable_only_after_the_pure_gate() {
        let rpc_src = include_str!("rpc.rs");
        let gate = rpc_src
            .find("processor.validate_pure")
            .expect("the pure gate must exist in process_transaction");
        let relay = rpc_src
            .find("p2p_network.broadcast_transaction")
            .expect("the relay call site must exist");
        assert!(
            gate < relay,
  "relay moved upstream of validate_pure  -  invalid payloads would hit the wire"
        );
        assert_eq!(
            rpc_src.matches("broadcast_transaction").count(),
            1,
            "exactly one relay call site; a second one would bypass the gate"
        );

        let p2p_src = include_str!("p2p.rs");
        let header = "P2PMessage::Transaction(tx_bytes) => {";
        let start = p2p_src
            .find(header)
            .expect("the receive arm must exist")
            + header.len();
        let end = p2p_src[start..]
            .find("P2PMessage::Inventory")
            .map(|i| i + start)
            .expect("the following arm must exist");
        let body = &p2p_src[start..end];
        assert!(
            !body.contains("peers.read()"),
  "the receive arm touches the peer table  -  that is a relay"
        );
        assert!(
            !body.contains("P2PMessage::Transaction("),
            "the receive arm constructs a relay message"
        );
    }

    /// A payload the pure gate rejects is never claimed for a wave: the gate
    /// rejects it before `process_transaction` reaches the relay, so the
    /// scheduling flag stays false exactly as it did at ingress.
    #[tokio::test]
    async fn test_invalid_transaction_is_never_scheduled_for_relay() {
        // No PoW and a zeroed signature: `validate_pure` must refuse it.
        let junk = Transaction::new(
            [[0u8; 32]; 2],
            [3u8; 32],
            [4u8; 32],
            100,
            10,
            1234567890,
            0,
            1,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        let processor = TransactionProcessor::new();
        assert!(
            processor
                .validate_pure(&junk, ValidationMode::Historical)
                .is_err(),
            "the fixture must actually be invalid, or this test proves nothing"
        );

        // The receive stage is format-only by design, so the payload does
        // enter the pipeline — but nothing downstream can have scheduled it.
        let seen: RwLock<HashMap<Vec<u8>, SeenTxEntry>> = RwLock::new(HashMap::new());
        let state: RwLock<PropagationState> = RwLock::new(HashMap::new());
        let (tx_channel, _rx) = mpsc::unbounded_channel::<Transaction>();
        let bytes = bincode::serialize(&junk).unwrap();
        accept_inbound_transaction(
            bytes.clone(),
            addr("10.2.0.4:9000"),
            &seen,
            &state,
            &tx_channel,
        )
        .await;

        assert!(
            !state.read().await.get(&bytes).unwrap().scheduled,
            "a payload the pure gate rejects must never be marked for relay"
        );
    }

    // --- convergence --------------------------------------------------------

    /// MULTIHOP CONVERGENCE: the added delay of a full relay chain stays a
    /// small fraction of both clocks that already bound propagation — the 10 s
    /// inventory sync backstop and the 30 s `FRAME_TIMEOUT`. 2E-D must not
    /// weaken either.
    #[test]
    fn test_multihop_convergence_stays_within_the_existing_bounds() {
        const SYNC_BACKSTOP: Duration = Duration::from_secs(10);

        // A 128-node table covered by fan-out 4 converges in 4 hops; allow 8.
        for hops in 1..=8u32 {
            let worst = PROPAGATION_JITTER_MAX * hops;
            assert!(
                worst < SYNC_BACKSTOP / 4,
                "hops={hops}: worst-case chain {:?} eats into the sync backstop",
                worst
            );
            assert!(
                worst < FRAME_TIMEOUT / 4,
                "hops={hops}: worst-case chain {:?} approaches FRAME_TIMEOUT",
                worst
            );
        }

        let expected_per_hop = (PROPAGATION_JITTER_MIN + PROPAGATION_JITTER_MAX) / 2;
        assert!(
            expected_per_hop * 8 < SYNC_BACKSTOP,
            "the expected cost of an 8-hop chain must stay far below the backstop"
        );
    }

    // --- measurement --------------------------------------------------------

    /// Release-only measurement of the three numbers 2E-D is reported on.
    ///
    /// ```text
    /// cargo test --release --lib bench_transaction_propagation -- --ignored --nocapture
    /// ```
    ///
    /// * `TRANSACTION_PROPAGATION_OVERHEAD` — frames actually sent versus the
    ///   pre-2E-D behaviour (every peer, twice).
    /// * `TRANSACTION_PROPAGATION_LATENCY` — how far apart neighbours first
    ///   see the payload. Pre-2E-D this was 0 ms by construction.
    /// * `TRANSACTION_DUPLICATION_RATE` — copies delivered per link.
    #[tokio::test]
    #[ignore]
    async fn bench_transaction_propagation() {
        const N_PEERS: usize = 32;
        const N_TX: usize = 1000;

        let peers: Vec<SocketAddr> = (0..N_PEERS)
            .map(|i| addr(&format!("10.9.{}.1:9000", i)))
            .collect();
        let (p2p, mut rxs) = network_with_peers(&peers).await;

        // --- latency: one wave, spread between first and last neighbour ----
        // Arrival times are polled rather than sampled after the fact: the
        // tasks all complete during the wait, so reading the clock once at
        // the end would report the wait itself and hide the spread.
        let started = std::time::Instant::now();
        p2p.broadcast_transaction(make_tx(0)).await;
        let mut arrivals: Vec<Option<Duration>> = vec![None; N_PEERS];
        let timeout = PROPAGATION_JITTER_MAX + Duration::from_millis(1000);
        loop {
            let mut got = 0usize;
            for (i, rx) in rxs.iter_mut().enumerate() {
                if arrivals[i].is_none() && rx.try_recv().is_ok() {
                    arrivals[i] = Some(started.elapsed());
                }
                if arrivals[i].is_some() {
                    got += 1;
                }
            }
            if got >= MAX_PROPAGATION_FANOUT || started.elapsed() > timeout {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let times: Vec<Duration> = arrivals.into_iter().flatten().collect();
        assert!(
            !times.is_empty(),
            "the wave must reach at least one neighbour"
        );
        let (first, last) = (*times.iter().min().unwrap(), *times.iter().max().unwrap());
        let spread = last - first;
        println!(
            "TRANSACTION_PROPAGATION_LATENCY: first={:?} last={:?} spread={:?} recipients={}",
            first,
            last,
            spread,
            times.len()
        );
        assert!(
            first >= PROPAGATION_JITTER_MIN,
            "a neighbour saw the payload in the same instant it was scheduled"
        );
        assert!(
            spread >= Duration::from_millis(1),
  "all neighbours saw it together  -  that is the fixed-timing signal"
        );

        // --- overhead / duplication: a sustained stream ----------------------
        for i in 1..=N_TX {
            p2p.broadcast_transaction(make_tx(i as u64)).await;
        }
        tokio::time::sleep(PROPAGATION_JITTER_MAX + Duration::from_millis(50)).await;

        let mut frames = 0usize;
        for rx in rxs.iter_mut() {
            frames += drain(rx);
        }
        // Pre-2E-D: every connected peer, every payload, twice.
        let old_frames = N_TX * N_PEERS * 2;
        let new_frames = frames;

        let overhead = new_frames as f64 / old_frames as f64;
        // Per LINK, not per wave: how many copies of a payload an average
        // neighbour received. Pre-2E-D this was exactly 2.
        let duplication = new_frames as f64 / (N_TX * N_PEERS) as f64;
        println!(
            "TRANSACTION_PROPAGATION_OVERHEAD: {} -> {} frames ({:.2} of the old cost)",
            old_frames, new_frames, overhead
        );
        println!(
            "TRANSACTION_DUPLICATION_RATE: {:.2} copies per link (was 2.00)",
            duplication
        );

        assert!(
            new_frames <= N_TX * MAX_PROPAGATION_FANOUT,
            "fan-out exceeded: {} frames for {} payloads",
            new_frames,
            N_TX
        );
        assert!(
            new_frames * 2 < old_frames,
            "2E-D must strictly reduce wire copies"
        );
        assert!(
            duplication <= 1.0001,
            "some link still carries more than one copy"
        );
    }
}

// ---------------------------------------------------------------------------
// PHASE 4CE: redial hygiene + inbound-only rediscovery contracts.
//
// Address model (four categories, NOT interchangeable):
//  1. configured bootnode — config membership; always redialed (operator
//     intent outranks hygiene; a dialed seed carries source Outbound, so the
//     exemption is membership-tested, never source-tested).
//  2. inbound-observed socket addr — the peer's EPHEMERAL source port, never
//     its listen addr (4CD live proof); redialing it fails until TTL expiry.
//  3. outbound/PEX target — a dialable listen addr (or hint); redialed with
//     per-candidate backoff (1,2,4..60s) inside the 5s redial cycle.
//  4. verified listen addr — DOES NOT EXIST: no advertisement, no persistent
//     peer identity binds an addr to a peer (handshake authenticates the
//     socket only). See the §5 proposal below; no wire change is made here.
//
// Hygiene rule (redial-candidate management ONLY, DAG/consensus untouched):
// a never-successful, non-seed entry with >= MAX_DIAL_FAILURES_SLEEP
// consecutive dial failures sleeps out of `outbound_candidates` until a
// completed handshake resets it or the TTL expires and the address is
// admitted fresh. A PEX re-announcement reaches held addresses since 4CH
// (the receive arm refreshes them once per announce, duplicates collapsed),
// halving — never resetting — the debt; `pex_refresh` is also still reached
// on membership races. Functional PEX wiring is pinned by
// `phase4ch_pex_wiring_tests`. Sleep never deletes; inbound always works.
//
// §5 PROPOSAL (not implemented — needs a protocol decision first):
// durable inbound-only rediscovery requires the peer's listen addr bound to
// an authenticated identity. Candidate: self-announced listen addr carried
// over the ALREADY-encrypted session, verified by dial-back before admission
// (callback verification — the dialer proves control of the claimed addr),
// then admitted through the EXISTING D6/private gates (never bypassing them)
// with the existing quality/ban machinery applied. Wire impact: additive
// message kind (enum tail, like 4G/4I) + version consideration; spam bounded
// by per-peer announce rate-limit + table capacity. Until then, a restarted
// inbound-only peer is rediscovered iff it dials out (>= 1 bootnode) or an
// operator configures its listen addr — an OPERATIONAL requirement, not a
// code defect.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod phase4ce_hygiene_tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn mgr_with(entries: Vec<(SocketAddr, PeerSource, u32, Option<u64>)>) -> AddressManager {
        // (addr, source, failures, last_success)
        let mut mgr = AddressManager::new();
        let now = unix_now();
        let at = Instant::now();
        for (a, src, fails, succ) in entries {
            mgr.observe(a, src, now, at);
            let e = mgr.entries_mut().get_mut(&a).expect("inserted");
            e.failures = fails;
            e.last_success = succ;
        }
        mgr
    }

    fn net_seeded(seeds: Vec<SocketAddr>) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
        P2PNetwork::new(
            P2PConfig {
                listen_addr: addr("127.0.0.1:31991"),
                bootnodes: seeds,
                dns_seeds: vec![],
                peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
            },
            tx,
            empty.clone(),
            empty_opt,
            empty,
            Arc::new(SyncContext::default()),
            Arc::new(|_| false),
        )
    }

    // --- cost reproduction: dead entries stay candidates until TTL ---------

    /// Pre-fix behavior, pinned: a never-successful entry past the threshold
    /// is STILL returned by the selection path it feeds (the waste 4CE
    /// bounds: ~1 dial per backoff window per dead entry until the 3600s
    /// TTL expires it — quantified here through the real functions).
    #[test]
    fn ce_cost_dead_entry_returned_every_round_pre_ttl() {
        let dead = addr("203.0.113.77:25565");
        let mgr = mgr_with(vec![(dead, PeerSource::Pex, 9, None)]);
        // Still a member, not expired (fresh clock), and the redial order
        // still yields it: every redial cycle would dial it again.
        assert!(mgr.entry(dead).is_some(), "dead entry retained pre-TTL");
        let out = P2PNetwork::redial_candidates(&[dead], &[], addr("127.0.0.1:31991"));
        assert_eq!(out, vec![dead], "pre-fix: dead entry returned every round");
        // ...which is exactly what the sleep predicate now gates:
        assert!(
            mgr.redial_sleep(&dead),
            "sleep predicate fires at failures=9, never-success"
        );
    }

    /// Unknown addresses report false: there is nothing to rest, and failed
    /// dials to them create nothing (`record_failure` is a no-op without an
    /// entry — the 4CD audit, pinned here).
    #[test]
    fn ce_unknown_addr_never_sleeps_and_gains_no_entry() {
        let mut mgr = AddressManager::new();
        let ghost = addr("203.0.113.99:25565");
        assert!(!mgr.redial_sleep(&ghost));
        mgr.record_failure(ghost);
        assert!(
            mgr.entry(ghost).is_none(),
            "failed dial to unknown creates no entry"
        );
    }

    // --- sleep predicate boundaries ----------------------------------------

    #[test]
    fn ce_sleep_boundaries_success_and_threshold() {
        let flop = addr("203.0.113.10:25565");
        let proven = addr("203.0.113.11:25565");
        let mgr = mgr_with(vec![
            (flop, PeerSource::Pex, MAX_DIAL_FAILURES_SLEEP - 1, None),
            (proven, PeerSource::Pex, 100, Some(1_700_000_000)),
        ]);
        assert!(
            !mgr.redial_sleep(&flop),
            "below threshold stays a candidate (flaky peers unaffected)"
        );
        assert!(
            !mgr.redial_sleep(&proven),
            "proven peers never sleep, however many past failures"
        );
    }

    #[test]
    fn ce_sleep_fires_at_threshold_never_success() {
        let dead = addr("203.0.113.12:25565");
        let mgr = mgr_with(vec![(
            dead,
            PeerSource::Inbound,
            MAX_DIAL_FAILURES_SLEEP,
            None,
        )]);
        assert!(
            mgr.redial_sleep(&dead),
            "inbound-observed ephemeral sleeps at threshold (it can never answer)"
        );
    }

    // --- pex_refresh halves debt (FUNCTION-LEVEL; the wired path is 4CH) ----

    // 4CH NOTE: this test exercises `pex_refresh` IN ISOLATION. The wired
    // network path — a real `P2PMessage::Peers` frame over a real session —
    // is validated by `phase4ch_pex_wiring_tests` (in-module, real sockets,
    // real sealed frames); this function-level pin stays as the cheap
    // contract check. Handshake success and TTL expiry + fresh admission
    // remain covered by the ce01/ce02 integration tests plus the TTL/store
    // round-trip tests below.
    #[test]
    fn ce_pex_refresh_fn_isolated_halves_debt() {
        let mut mgr = mgr_with(vec![(addr("203.0.113.13:25565"), PeerSource::Pex, 5, None)]);
        let a = addr("203.0.113.13:25565");
        assert!(mgr.redial_sleep(&a), "asleep at 5");
        mgr.pex_refresh(a, Instant::now());
        assert_eq!(
            mgr.entry(a).expect("entry").failures,
            2,
            "one wave halves 5→2"
        );
        assert!(!mgr.redial_sleep(&a), "halved debt reactivates");
        // ...but sustained failure re-sleeps (one wave does not forgive):
        for _ in 0..3 {
            mgr.record_failure(a);
        }
        assert_eq!(mgr.entry(a).expect("entry").failures, 5);
        assert!(mgr.redial_sleep(&a), "re-sleeps after 3 more fails");
    }

    // --- success forgives ----------------------------------------------------

    #[test]
    fn ce_success_resets_failure_debt() {
        let mut mgr = mgr_with(vec![(addr("203.0.113.14:25565"), PeerSource::Pex, 4, None)]);
        let a = addr("203.0.113.14:25565");
        mgr.record_success(a, unix_now());
        assert_eq!(
            mgr.entry(a).expect("entry").failures,
            0,
            "handshake clears debt"
        );
        assert!(!mgr.redial_sleep(&a));
    }

    // --- seed exemption through the real selection path ----------------------

    /// A configured seed with failures past the threshold is STILL yielded by
    /// `outbound_candidates` (membership exemption); a non-seed peer with the
    /// same debt is NOT. Runs the production async selection, no network.
    #[tokio::test]
    async fn ce_seed_exempt_nonseed_sleeps_in_outbound_candidates() {
        let seed = addr("127.0.0.1:31982");
        let peer = addr("127.0.0.1:31983");
        let net = net_seeded(vec![seed]);
        // Ingress exactly as the production paths do: seed via the outbound
        // dial path (source Outbound — NOT Configured), peer via PEX.
        let empty_sessions = Arc::new(RwLock::new(HashMap::new()));
        let local = addr("127.0.0.1:31991");
        assert!(
            ingress_address(
                &net.addresses,
                &empty_sessions,
                local,
                seed,
                PeerSource::Outbound
            )
            .await
        );
        assert!(
            ingress_address(
                &net.addresses,
                &empty_sessions,
                local,
                peer,
                PeerSource::Pex
            )
            .await
        );
        {
            let mut mgr = net.addresses.write().await;
            for _ in 0..9 {
                mgr.record_failure(seed);
                mgr.record_failure(peer);
            }
        }
        let cands = net.outbound_candidates(32).await;
        assert!(
            cands.contains(&seed),
            "configured seed retried despite 9 failures, got {:?}",
            cands
        );
        assert!(
            !cands.contains(&peer),
            "slept non-seed excluded despite table membership, got {:?}",
            cands
        );
        // Membership retained (sleep ≠ delete): TTL/store still own it.
        assert!(net.addresses.read().await.entry(peer).is_some());
    }

    // --- TTL still owns lifetime ----------------------------------------------

    #[test]
    fn ce_ttl_expiry_evicts_slept_entries() {
        let mut mgr = mgr_with(vec![(addr("203.0.113.15:25565"), PeerSource::Pex, 9, None)]);
        let a = addr("203.0.113.15:25565");
        assert!(mgr.redial_sleep(&a));
        // Age past the 3600s TTL (direct state construction — no clock
        // abstraction needed, no production delay touched).
        mgr.entries_mut().get_mut(&a).expect("entry").last_seen =
            Instant::now() - StdDuration::from_secs(3601);
        let (kept, expired) = mgr.refresh_and_expire(
            &HashSet::new(),
            Instant::now(),
            StdDuration::from_secs(3600),
        );
        assert_eq!(kept, 0);
        assert_eq!(expired, 1, "slept entry still expires on TTL");
        assert!(mgr.entry(a).is_none());
    }

    // --- store round-trip preserves sleep state ---------------------------------

    #[test]
    fn ce_store_roundtrip_preserves_sleep() {
        let mut mgr = mgr_with(vec![(addr("203.0.113.16:25565"), PeerSource::Pex, 7, None)]);
        let a = addr("203.0.113.16:25565");
        assert!(mgr.redial_sleep(&a));
        let file = mgr.to_store();
        let mut re = AddressManager::new();
        let n = re.load_v2(&file, addr("127.0.0.1:31991"), unix_now(), Instant::now());
        assert_eq!(n, 1);
        assert!(re.redial_sleep(&a), "sleep survives peer-store restart");
    }

    // --- contracts: D6/R4 filters + inbound-only gap -----------------------------

    /// Contract (must hold under ANY future change): loopback is rejected on
    /// the PEX receive path but unrestricted on direct/operator paths.
    #[test]
    fn ce_contract_private_gate_and_operator_freedom() {
        assert!(
            is_private_or_reserved(addr("127.0.0.1:44783")),
            "D6: loopback is private/reserved (PEX receive path must drop it)"
        );
        assert!(
            !is_private_or_reserved(addr("203.0.113.20:25565")),
            "public addrs stay PEX-eligible"
        );
    }

    /// Contract gap demo (structural, 4CD finding): an inbound-observed entry
    /// keys the EPHEMERAL port; redial can only ever dial that key (which
    /// fails), and after threshold failures it sleeps — bounding, not
    /// closing, the gap. Durable rediscovery needs the §5 proposal.
    #[test]
    fn ce_contract_inbound_key_is_ephemeral_only() {
        let eph = addr("127.0.0.1:54124");
        let mgr = mgr_with(vec![(
            eph,
            PeerSource::Inbound,
            MAX_DIAL_FAILURES_SLEEP,
            None,
        )]);
        // The entry's key IS the only dialable identity redial will ever use:
        let out = P2PNetwork::redial_candidates(&[eph], &[], addr("127.0.0.1:31991"));
        assert_eq!(out, vec![eph], "no listen-addr derivation exists pre-fix");
        // ...and hygiene at least stops paying for it:
        assert!(mgr.redial_sleep(&eph), "dead ephemeral sleeps at threshold");
    }
}

// ======== PHASE 4CH: real-path PEX refresh wiring ============================
//
// Corrects the 4CF finding: `pex_refresh` existed but the production
// `P2PMessage::Peers` arm skipped addresses the table already held, so a
// held or sleeping entry was refreshed only via a membership race or an
// intra-batch duplicate. The arm now refreshes every held, admissible
// address once per announce (duplicates collapsed), without forcing a dial.
//
// This suite is the AUTHENTICATED path proof (§5 of the 4CH brief): a real
// peer socket completes the production X25519 handshake and sends REAL
// sealed `P2PMessage::Peers` frames (pad + ChaCha20-Poly1305 + length
// prefix, mirrored through the production helpers themselves); assertions
// read the AddressManager state those frames actually changed. Synthetic
// public addresses go through a dial-refusing test transport (the 4CH
// `new_with_transport` seam): every outbound attempt is recorded, NO socket
// is ever opened toward the Internet, and `bind` still delegates to real
// TCP so the inbound session is genuine loopback. Exact debt values and
// intra-message dedup are observable here because the cfg(test) state
// accessors exist only inside this crate build; the foreign-client wire
// interop twin lives in `tests/phase4ch_pex_refresh_tests.rs`.
#[cfg(test)]
mod phase4ch_pex_wiring_tests {
    use super::*;
    use crate::transport::TransportError;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration as StdDuration;

    /// Dial-refusing transport: records every dial attempt, never opens a
    /// socket. `bind` delegates to the real TCP transport so the node still
    /// accepts genuine loopback connections.
    struct RejectAllTransport {
        log: Arc<StdMutex<Vec<SocketAddr>>>,
    }

    impl Transport for RejectAllTransport {
        fn dial(
            &self,
            addr: &PeerAddr,
        ) -> crate::transport::BoxFuture<'_, Result<TransportStream, TransportError>> {
            let target = match *addr {
                PeerAddr::Ip(a) => a,
            };
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(target);
            Box::pin(async move {
                Err(TransportError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "4CH test transport: outbound dial refused (no Internet traffic)",
                )))
            })
        }

        fn bind(
            &self,
            addr: &PeerAddr,
        ) -> crate::transport::BoxFuture<'_, Result<TransportListener, TransportError>> {
            let transport = TcpTransport::new();
            let endpoint = *addr;
            Box::pin(async move { transport.bind(&endpoint).await })
        }
    }

    fn dial_count(log: &Arc<StdMutex<Vec<SocketAddr>>>, target: SocketAddr) -> usize {
        log.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|a| **a == target)
            .count()
    }

    async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut cond: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        tokio::time::timeout(timeout, async {
            loop {
                if cond().await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT waiting for: {}", what));
    }

    /// A real peer over a real loopback socket: the production handshake,
    /// then real sealed frames built through the production helpers
    /// (`pad_message`, `valid_frame_len`, `build_nonce`, `send_direction`),
    /// so the wire format cannot drift from what `handle_peer` decodes.
    struct RawPeer {
        writer: tokio::net::tcp::OwnedWriteHalf,
        // Kept alive so the node's session stays open for the test window.
        _reader: tokio::net::tcp::OwnedReadHalf,
        key: [u8; 32],
        dir: u8,
        counter: u64,
    }

    impl RawPeer {
        async fn connect(port: u16) -> Self {
            let stream = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
            )
            .await
            .expect("raw connect must not hang")
            .expect("raw connect");
            let (mut reader, mut writer) = stream.into_split();
            let (key, dir) = Self::handshake(&mut reader, &mut writer).await;
            Self {
                writer,
                _reader: reader,
                key,
                dir,
                counter: 0,
            }
        }

        /// Mirror of the production `handshake()` from the client side:
        /// ephemeral X25519, DH, SHA256("aether-p2p-key-v1"), direction byte.
        async fn handshake(
            reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
            writer: &mut (impl tokio::io::AsyncWriteExt + Unpin),
        ) -> ([u8; 32], u8) {
            let secret = EphemeralSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            let mut outgoing = Vec::with_capacity(HANDSHAKE_FRAME_LEN);
            let mut magic = [0u8; 4];
            for i in 0..4 {
                magic[i] = HANDSHAKE_MAGIC[i] ^ HANDSHAKE_MAGIC_MASK[i];
            }
            outgoing.extend_from_slice(&magic);
            outgoing.push(P2P_PROTOCOL_VERSION);
            outgoing.extend_from_slice(&crate::genesis::GENESIS_HASH);
            outgoing.extend_from_slice(&crate::transaction::DEFAULT_NETWORK_ID.to_le_bytes());
            outgoing.extend_from_slice(public.as_bytes());
            writer.write_all(&outgoing).await.expect("hs write");
            let mut incoming = [0u8; HANDSHAKE_FRAME_LEN];
            tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut incoming))
                .await
                .expect("server handshake reply must not hang")
                .expect("server handshake reply");
            assert_eq!(&incoming[..4], &magic, "server wire magic");
            assert_eq!(incoming[4], P2P_PROTOCOL_VERSION, "server protocol version");
            assert_eq!(
                &incoming[5..37],
                &crate::genesis::GENESIS_HASH,
                "server genesis"
            );
            let mut peer_pk = [0u8; 32];
            peer_pk.copy_from_slice(&incoming[HANDSHAKE_FRAME_LEN - 32..]);
            let shared = secret.diffie_hellman(&PublicKey::from(peer_pk));
            let mut hasher = Sha256::new();
            hasher.update(b"aether-p2p-key-v1");
            hasher.update(shared.as_bytes());
            let mut key = [0u8; 32];
            key.copy_from_slice(&hasher.finalize());
            let dir = P2PNetwork::send_direction(public.as_bytes(), &peer_pk);
            (key, dir)
        }

        /// One production-shaped frame: pad, seal, length-prefix.
        async fn send(&mut self, msg: &P2PMessage) {
            let payload = bincode::serialize(msg).expect("serialize P2PMessage");
            let padded = P2PNetwork::pad_message(&payload).expect("pad");
            self.counter += 1;
            let nonce_bytes = P2PNetwork::build_nonce(self.counter, self.dir);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, padded.as_ref()).expect("seal");
            let total_len = 12 + ciphertext.len();
            assert!(
                P2PNetwork::valid_frame_len(total_len),
                "test frame must be bucket-legal like production frames"
            );
            self.writer
                .write_all(&(total_len as u32).to_be_bytes())
                .await
                .expect("frame len");
            self.writer
                .write_all(&nonce_bytes)
                .await
                .expect("frame nonce");
            self.writer.write_all(&ciphertext).await.expect("frame ct");
        }
    }

    /// §5 end-to-end: one real `P2PMessage::Peers` frame refreshes a held
    /// sleeping address exactly once (dedup), filters D6 addrs, preserves the
    /// unknown-address admission path, forces no dial, and hands the address
    /// back to the normal bounded redial selection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ch_real_path_peers_frame_wires_refresh() {
        const PORT: u16 = 44805;
        let x: SocketAddr = "203.0.113.50:25565".parse().unwrap();
        let y: SocketAddr = "203.0.113.99:25565".parse().unwrap();
        let filtered: Vec<SocketAddr> = ["10.0.0.7:8080", "192.168.44.9:4001", "127.0.0.1:6666"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        let dial_log = Arc::new(StdMutex::new(Vec::new()));
        let transport = Arc::new(RejectAllTransport {
            log: Arc::clone(&dial_log),
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
        let net = P2PNetwork::new_with_transport(
            P2PConfig {
                listen_addr: format!("127.0.0.1:{}", PORT).parse().unwrap(),
                bootnodes: vec![],
                dns_seeds: vec![],
                peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
            },
            tx,
            empty.clone(),
            empty_opt,
            empty,
            Arc::new(SyncContext::default()),
            Arc::new(|_| false),
            transport,
        );

        // (5.1) The address is already known and past the sleep threshold —
        // constructed directly through the cfg(test) state accessors, so no
        // real dial toward the synthetic public address ever happens.
        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(x, PeerSource::Pex, unix_now(), Instant::now());
            let e = mgr.entries_mut().get_mut(&x).expect("seeded entry");
            e.failures = MAX_DIAL_FAILURES_SLEEP * 2 + 2; // 12: asleep, room to observe a wrong double-halving (3)
            e.last_success = None;
        }
        // 4CP-W (V-3): the protocol mode is now an explicit prerequisite.
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start()
            .await
            .expect("start must bind the loopback listener");
        assert!(
            net.addresses.read().await.redial_sleep(&x),
            "asleep before any announce"
        );
        assert!(
            !net.outbound_candidates(16).await.contains(&x),
            "asleep entry excluded from every candidate source (redial AND recovery)"
        );
        {
            let log = dial_log.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                log.is_empty(),
                "no source dials an asleep address before any announce: {:?}",
                *log
            );
        }

        // (5.2) A connected real peer transmits a REAL sealed PEX frame:
        // held X three times (duplicate stress), D6-filtered addrs, unknown Y.
        let mut peer = RawPeer::connect(PORT).await;
        wait_for("session registered", Duration::from_secs(10), || async {
            net.peer_count().await == 1
        })
        .await;
        peer.send(&P2PMessage::Peers(vec![
            x,
            x,
            filtered[0],
            filtered[1],
            filtered[2],
            y,
            x,
        ]))
        .await;

        // (5.3)(5.4)(5.5) Exactly one halving: 12 → 6. A missed wire would
        // leave 12; a double refresh (dedup broken) would give 3; a debt
        // reset would give 0. The entry staying asleep at 6 is also the
        // backbone of (5.7): while asleep, NO legitimate dial source can
        // pick X, so any dial attempt on X could only come from a forced
        // dial inside PEX processing itself.
        wait_for(
            "refresh applied exactly once (12->6)",
            Duration::from_secs(10),
            || async { net.addresses.read().await.entry(x).map(|e| e.failures) == Some(6) },
        )
        .await;
        assert!(
            net.addresses.read().await.redial_sleep(&x),
            "6 failures remain past the threshold — no source may dial X"
        );
        // Settle window: a handler-forced dial (discovery channel) would
        // land here, within milliseconds of the frame.
        tokio::time::sleep(StdDuration::from_millis(800)).await;
        {
            let log = dial_log.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                !log.contains(&x),
                "PEX processing forced no dial on the refreshed address: {:?}",
                *log
            );
        }

        // (5.6) D6: private/loopback announces neither enter the table nor
        // ever reach a dial.
        {
            let mgr = net.addresses.read().await;
            for p in &filtered {
                assert!(mgr.entry(*p).is_none(), "{} must stay filtered", p);
                let log = dial_log.lock().unwrap_or_else(|e| e.into_inner());
                assert!(!log.contains(p), "{} must never be dialed", p);
            }
        }
        // The unknown-address admission path keeps its exact pre-4CH shape:
        // admitted with the announcing session as origin, then pushed to the
        // discovery channel (which dials — refused by the test transport, so
        // nothing leaves the machine).
        {
            let mgr = net.addresses.read().await;
            let ye = mgr.entry(y).expect("unknown public address still admitted");
            assert_eq!(ye.source, PeerSource::Pex, "admitted via PEX");
            assert!(
                matches!(mgr.origin_of(y), Some(a) if a.ip().is_loopback()),
                "D5 origin recorded as the announcing session"
            );
        }
        wait_for(
            "admission path still dials the unknown address (via transport)",
            Duration::from_secs(10),
            || async { dial_count(&dial_log, y) >= 1 },
        )
        .await;
        {
            let log = dial_log.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                !log.contains(&x),
                "admission of Y must not dial X: {:?}",
                *log
            );
        }

        // Second announce: progressive halving (6 -> 3), still never a reset,
        // still once per message.
        peer.send(&P2PMessage::Peers(vec![x])).await;
        wait_for(
            "second wave halves again (6->3)",
            Duration::from_secs(10),
            || async { net.addresses.read().await.entry(x).map(|e| e.failures) == Some(3) },
        )
        .await;

        // (5.8) Debt back under the threshold: the REAL selection function
        // yields the address again, and the normal bounded mechanism really
        // dials it (the attempt is the observable; the transport refuses, so
        // zero traffic leaves the process).
        assert!(
            !net.addresses.read().await.redial_sleep(&x),
            "3 failures: no longer asleep"
        );
        assert!(
            net.outbound_candidates(16).await.contains(&x),
            "normal selection yields the refreshed address"
        );
        wait_for(
            "normal redial/recovery attempts X after refresh",
            Duration::from_secs(25),
            || async { dial_count(&dial_log, x) >= 1 },
        )
        .await;

        // (5.9) Clean stop: client gone, sessions released, port free.
        let _ = peer.send(&P2PMessage::Ping).await; // keepalive in case the wait ran long
        drop(peer);
        tokio::time::timeout(Duration::from_secs(15), net.shutdown())
            .await
            .expect("TIMEOUT: shutdown hung")
            .expect("shutdown must succeed");
        wait_for(
            "peer_count==0 after shutdown",
            Duration::from_secs(10),
            || async { net.peer_count().await == 0 },
        )
        .await;
        std::net::TcpListener::bind(format!("127.0.0.1:{}", PORT))
            .expect("port must be released after shutdown");
        // Bounded growth: the whole exchange ever created at most three
        // table entries (X, Y, the client's ephemeral) and two dial targets.
        let table_len = net.addresses.read().await.addresses().len();
        assert!(table_len <= 3, "address table bounded: {}", table_len);
        drop(net);
    }

    // =====================================================================
    // PHASE 4CP-U (4CPT-04): real loopback lifecycle tests.
    //
    // These drive the production accept path (`start()` -> `accept_loop` ->
    // `handle_peer`) over genuine TCP sockets, so the session registry is
    // exercised end to end, not through the test-only accessors alone.
    // =====================================================================

    /// Build a real loopback network for the 4CP-U lifecycle tests.
    fn cpu_net(port: u16) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
        P2PNetwork::new(
            P2PConfig {
                listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
                bootnodes: vec![],
                dns_seeds: vec![],
                peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
            },
            tx,
            empty.clone(),
            empty_opt,
            empty,
            Arc::new(SyncContext::default()),
            Arc::new(|_| false),
        )
    }

    /// 4CPT-04(1): a real connection whose handshake fails records no session
    /// and keeps no peer — the failure path writes nothing to the registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_failed_handshake_leaves_no_session() {
        const P: u16 = 44912;
        let net = cpu_net(P);
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("bind loopback");

        // A full-length frame with broken magic: the server's v5 handshake
        // rejects it immediately (no 10s stall waiting for more bytes).
        let junk = vec![0u8; HANDSHAKE_FRAME_LEN];
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", P))
            .await
            .expect("connect");
        sock.write_all(&junk).await.expect("write junk frame");
        sock.flush().await.expect("flush");
        // Drain the server's own frame so the socket never wedges, then let
        // `handle_peer` run its failure teardown.
        let mut sink = [0u8; HANDSHAKE_FRAME_LEN];
        let _ = tokio::time::timeout(
            StdDuration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut sock, &mut sink),
        )
        .await;
        tokio::time::sleep(StdDuration::from_millis(300)).await;

        assert_eq!(
            net.session_auth_len().await,
            0,
            "a failed handshake must record no session state"
        );
        assert_eq!(
            net.peer_count().await,
            0,
            "no peer is kept when the handshake fails"
        );
        drop(sock);
        let _ = net.shutdown().await;
    }

    /// 4CPT-04(2/3): two real concurrent sessions are independent — distinct
    /// ids, their own state — and closing one never removes the other.
    ///
    /// Same-endpoint isolation is covered at the registry level by
    /// `two_sessions_same_addr_do_not_overwrite`: two TCP connections from one
    /// host necessarily use distinct source ports, so they are distinct
    /// endpoints here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_real_sessions_are_independent() {
        const P: u16 = 44913;
        let net = cpu_net(P);
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("bind loopback");

        let p1 = RawPeer::connect(P).await;
        wait_for("first session", StdDuration::from_secs(10), || async {
            net.session_auth_len().await == 1
        })
        .await;
        let p2 = RawPeer::connect(P).await;
        wait_for("second session", StdDuration::from_secs(10), || async {
            net.session_auth_len().await == 2
        })
        .await;

        let before: Vec<SocketAddr> = net.get_peers().await;
        assert_eq!(before.len(), 2, "two live peers");
        let mut before_ids: Vec<(SocketAddr, u64)> = Vec::new();
        for a in &before {
            let entries = net.session_auth_for_addr(a).await;
            assert_eq!(entries.len(), 1, "one session per endpoint here");
            before_ids.push((*a, entries[0].0));
        }
        assert_ne!(
            before_ids[0].1, before_ids[1].1,
            "the two sessions have distinct ids"
        );

        // Close ONE real connection and prove the other survives untouched.
        drop(p1);
        wait_for(
            "one session after closing one peer",
            StdDuration::from_secs(10),
            || async { net.session_auth_len().await == 1 },
        )
        .await;
        let mut alive: Vec<SocketAddr> = Vec::new();
        for a in &before {
            if !net.session_auth_for_addr(a).await.is_empty() {
                alive.push(*a);
            }
        }
        assert_eq!(alive.len(), 1, "exactly one session survives");
        let surviving_id = net.session_auth_for_addr(&alive[0]).await[0].0;
        let expected = before_ids
            .iter()
            .find(|(a, _)| *a == alive[0])
            .map(|(_, id)| *id)
            .expect("survivor was known before");
        assert_eq!(
            surviving_id, expected,
            "closing one session never removes the other"
        );

        drop(p2);
        let _ = net.shutdown().await;
    }

    /// 4CPT-04(4): a reconnect gets a FRESH session id and inherits no prior
    /// provenance (a legacy session is never authenticated).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_real_reconnect_does_not_inherit() {
        const P: u16 = 44914;
        let net = cpu_net(P);
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("bind loopback");

        let p1 = RawPeer::connect(P).await;
        wait_for("first session", StdDuration::from_secs(10), || async {
            net.session_auth_len().await == 1
        })
        .await;
        let first_addr = net.get_peers().await[0];
        let (id1, state1) = net.session_auth_for_addr(&first_addr).await[0].clone();
        assert_eq!(
            state1,
            P2PSessionAuth::EncryptedUnauthenticated,
            "a legacy session is never authenticated"
        );
        drop(p1);
        wait_for("session released", StdDuration::from_secs(10), || async {
            net.session_auth_len().await == 0
        })
        .await;

        let p2 = RawPeer::connect(P).await;
        wait_for("reconnect session", StdDuration::from_secs(10), || async {
            net.session_auth_len().await == 1
        })
        .await;
        let second_addr = net.get_peers().await[0];
        let (id2, state2) = net.session_auth_for_addr(&second_addr).await[0].clone();
        assert_ne!(id2, id1, "a reconnect gets a fresh session id");
        assert_eq!(
            state2,
            P2PSessionAuth::EncryptedUnauthenticated,
            "a reconnect inherits no prior provenance"
        );
        drop(p2);
        let _ = net.shutdown().await;
    }

    /// 4CPT-04(5): shutdown tears down the live session and releases the port.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_real_shutdown_clears_sessions() {
        const P: u16 = 44915;
        let net = cpu_net(P);
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("bind loopback");

        let p = RawPeer::connect(P).await;
        wait_for("session", StdDuration::from_secs(10), || async {
            net.session_auth_len().await == 1
        })
        .await;

        tokio::time::timeout(StdDuration::from_secs(15), net.shutdown())
            .await
            .expect("shutdown must not hang")
            .expect("shutdown must succeed");
        assert_eq!(
            net.session_auth_len().await,
            0,
            "shutdown releases every session"
        );
        assert_eq!(net.peer_count().await, 0, "shutdown drops every peer");
        std::net::TcpListener::bind(format!("127.0.0.1:{}", P))
            .expect("port must be released after shutdown");
        drop(p);
    }
}

/// PHASE 4CP: contract tests for the authenticated v6 handshake.
///
/// Every test drives the REAL handshake code (`handshake_v6` / `handshake`)
/// over an in-memory duplex; the `fake_peer` below speaks the actual v6 wire
/// format so a tampered frame is rejected by production verification, not by
/// a re-implementation.
#[cfg(test)]
mod phase4cp_v6_tests {
    use super::*;
    use crate::node_identity::{IdentityOutcome, NodeIdentity};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[derive(Clone, Copy)]
    enum Tamper {
        None,
        BadSig,
        WrongRole,
        WrongNetwork,
        WrongGenesis,
        OtherKey,
        Replay([u8; 64]),
        /// Send an all-zero (low-order) X25519 ephemeral with a VALID signature
        /// over the resulting transcript (4CP-S / F2).
        LowOrderEph,
    }

    /// Build the exact v6 Hello bytes for chosen fields (mirrors the wire
    /// layout asserted by `V6_HELLO_LEN`).
    fn hello_bytes(network_id: u64, h: &super::V6Hello) -> Vec<u8> {
        let mut v = Vec::with_capacity(V6_HELLO_LEN);
        v.extend_from_slice(&P2PNetwork::handshake_wire_magic());
        v.push(P2P_PROTOCOL_VERSION_V6);
        v.extend_from_slice(&crate::genesis::GENESIS_HASH);
        v.extend_from_slice(&network_id.to_le_bytes());
        v.extend_from_slice(&h.eph);
        v.extend_from_slice(&h.nonce);
        v.extend_from_slice(&h.node_id);
        debug_assert_eq!(v.len(), V6_HELLO_LEN);
        v
    }

    /// A peer that speaks the real v6 wire format. Returns the 64-byte
    /// signature it sent (used by the replay test).
    async fn fake_peer<R, W>(
        reader: &mut R,
        writer: &mut W,
        network_id: u64,
        identity: &NodeIdentity,
        is_initiator: bool,
        tamper: Tamper,
    ) -> [u8; 64]
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let pubk = PublicKey::from(&secret);
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let nid = identity.node_id();
        let ours = super::V6Hello {
            eph: match tamper {
                Tamper::LowOrderEph => [0u8; 32],
                _ => *pubk.as_bytes(),
            },
            nonce,
            node_id: *nid.as_bytes(),
        };

        let mut hello = hello_bytes(network_id, &ours);
        match tamper {
            Tamper::WrongNetwork => {
                hello[37..45].copy_from_slice(&network_id.wrapping_add(1).to_le_bytes())
            }
            Tamper::WrongGenesis => hello[5] ^= 0xff,
            _ => {}
        }
        writer.write_all(&hello).await.unwrap();
        writer.flush().await.unwrap();

        let mut inc = [0u8; V6_HELLO_LEN];
        reader.read_exact(&mut inc).await.unwrap();
        let theirs = super::V6Hello {
            eph: {
                let mut a = [0u8; 32];
                a.copy_from_slice(&inc[45..77]);
                a
            },
            nonce: {
                let mut a = [0u8; 32];
                a.copy_from_slice(&inc[77..109]);
                a
            },
            node_id: {
                let mut a = [0u8; 32];
                a.copy_from_slice(&inc[109..141]);
                a
            },
        };

        let (initiator, responder) = if is_initiator {
            (&ours, &theirs)
        } else {
            (&theirs, &ours)
        };
        let transcript = P2PNetwork::v6_transcript(network_id, initiator, responder);
        let role = if is_initiator {
            V6_ROLE_INITIATOR
        } else {
            V6_ROLE_RESPONDER
        };
        let sign_role = match tamper {
            Tamper::WrongRole => {
                if role == V6_ROLE_INITIATOR {
                    V6_ROLE_RESPONDER
                } else {
                    V6_ROLE_INITIATOR
                }
            }
            _ => role,
        };
        let message = P2PNetwork::v6_signed_message(sign_role, &transcript);

        let sig = match tamper {
            Tamper::Replay(s) => s,
            Tamper::OtherKey => NodeIdentity::generate().sign_message(&message),
            Tamper::BadSig => {
                let mut s = identity.sign_message(&message);
                s[0] ^= 0xff;
                s
            }
            _ => identity.sign_message(&message),
        };
        writer.write_all(&sig).await.unwrap();
        writer.flush().await.unwrap();
        sig
    }

    fn duplex_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (a_r, b_w) = tokio::io::duplex(512);
        let (b_r, a_w) = tokio::io::duplex(512);
        (a_r, a_w, b_r, b_w)
    }

    /// Contract 1: two v6 nodes mutually authenticate and share a session key.
    #[tokio::test]
    async fn v6_mutual_authentication_succeeds() {
        let a_id = NodeIdentity::generate();
        let b_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let a = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &a_id, true);
        let b = P2PNetwork::handshake_v6(&mut b_r, &mut b_w, 0, &b_id, false);
        let (ra, rb) = tokio::join!(a, b);
        let (ka, da, pa) = ra.expect("A must authenticate");
        let (kb, db, pb) = rb.expect("B must authenticate");
        assert_eq!(ka, kb, "both ends derive the same v6 session key");
        assert_ne!(da, db, "send directions must be opposite");
        assert_eq!(pa, b_id.node_id(), "A learned B's real NodeId");
        assert_eq!(pb, a_id.node_id(), "B learned A's real NodeId");
        // The v6 key must be domain-separated from the v5 derivation.
        let (mut c_r, mut c_w, mut d_r, mut d_w) = duplex_pair();
        let cv5 = P2PNetwork::handshake(&mut c_r, &mut c_w, 0);
        let dv5 = P2PNetwork::handshake(&mut d_r, &mut d_w, 0);
        let (rc, rd) = tokio::join!(cv5, dv5);
        let (kv5, _) = rc.expect("v5 handshake");
        let (kv5b, _) = rd.expect("v5 handshake");
        assert_eq!(kv5, kv5b);
        assert_ne!(ka, kv5, "v6 and v5 keys must differ (domain separation)");
    }

    /// Contract 4: the legacy v5 path is unchanged (77-byte frame, v5 key).
    #[tokio::test]
    async fn v5_legacy_handshake_unchanged() {
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let a = P2PNetwork::handshake(&mut a_r, &mut a_w, 0);
        let b = P2PNetwork::handshake(&mut b_r, &mut b_w, 0);
        let (ra, rb) = tokio::join!(a, b);
        let (ka, da) = ra.expect("v5 A");
        let (kb, db) = rb.expect("v5 B");
        assert_eq!(ka, kb);
        assert_ne!(da, db);
    }

    /// Contract 5: an authenticated v6 node and a v5 peer fail BOTH sides —
    /// no silent downgrade is possible.
    #[tokio::test]
    async fn v6_and_v5_peers_fail_both_ends() {
        let a_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let six = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &a_id, true);
        let five = P2PNetwork::handshake(&mut b_r, &mut b_w, 0);
        let (r6, r5) = tokio::join!(six, five);
        assert!(r6.is_err(), "v6 side must reject the v5 peer");
        assert!(r5.is_err(), "v5 side must reject the v6 frame");
    }

    /// Contract 7: a corrupted Ed25519 signature is rejected.
    #[tokio::test]
    async fn v6_rejects_tampered_signature() {
        let real_id = NodeIdentity::generate();
        let peer_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let real = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &real_id, true);
        let fake = fake_peer(&mut b_r, &mut b_w, 0, &peer_id, false, Tamper::BadSig);
        let (rr, _) = tokio::join!(real, fake);
        assert!(rr.is_err(), "tampered signature must be rejected");
    }

    /// Contract 7b: a signature from a different key than the advertised
    /// NodeId is rejected (possession of the named key is required).
    #[tokio::test]
    async fn v6_rejects_signature_from_wrong_key() {
        let real_id = NodeIdentity::generate();
        let peer_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let real = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &real_id, true);
        let fake = fake_peer(&mut b_r, &mut b_w, 0, &peer_id, false, Tamper::OtherKey);
        let (rr, _) = tokio::join!(real, fake);
        assert!(
            rr.is_err(),
            "signature must verify against the advertised NodeId"
        );
    }

    /// Contract 9: a wrong network id is rejected before any signature check.
    #[tokio::test]
    async fn v6_rejects_wrong_network_id() {
        let real_id = NodeIdentity::generate();
        let peer_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let real = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &real_id, true);
        let fake = fake_peer(&mut b_r, &mut b_w, 0, &peer_id, false, Tamper::WrongNetwork);
        let (rr, _) = tokio::join!(real, fake);
        assert!(rr.is_err(), "network id mismatch must fail");
    }

    /// Contract 9b: a wrong genesis hash is rejected.
    #[tokio::test]
    async fn v6_rejects_wrong_genesis() {
        let real_id = NodeIdentity::generate();
        let peer_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let real = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &real_id, true);
        let fake = fake_peer(&mut b_r, &mut b_w, 0, &peer_id, false, Tamper::WrongGenesis);
        let (rr, _) = tokio::join!(real, fake);
        assert!(rr.is_err(), "genesis mismatch must fail");
    }

    /// Contract 8/12: a signature bound to the WRONG role (reflection) is
    /// rejected — the signed message pins the signer's role.
    #[tokio::test]
    async fn v6_rejects_reflected_signature() {
        let real_id = NodeIdentity::generate();
        let peer_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let real = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &real_id, true);
        let fake = fake_peer(&mut b_r, &mut b_w, 0, &peer_id, false, Tamper::WrongRole);
        let (rr, _) = tokio::join!(real, fake);
        assert!(rr.is_err(), "role-bound signature must reject reflection");
    }

    /// Contract 11: a signature captured from a different session (different
    /// ephemerals/nonces) does not verify here.
    #[tokio::test]
    async fn v6_rejects_replayed_signature() {
        let peer_id = NodeIdentity::generate();

        // Session 1: capture a genuinely valid signature for that transcript.
        let s1_real = NodeIdentity::generate();
        let (mut a1_r, mut a1_w, mut b1_r, mut b1_w) = duplex_pair();
        let real1 = P2PNetwork::handshake_v6(&mut a1_r, &mut a1_w, 0, &s1_real, true);
        let fake1 = fake_peer(&mut b1_r, &mut b1_w, 0, &peer_id, false, Tamper::None);
        let (r1, captured) = tokio::join!(real1, fake1);
        assert!(r1.is_ok(), "session 1 must authenticate");
        let captured_sig = captured;

        // Session 2: replay the captured signature against a fresh transcript.
        let s2_real = NodeIdentity::generate();
        let (mut a2_r, mut a2_w, mut b2_r, mut b2_w) = duplex_pair();
        let real2 = P2PNetwork::handshake_v6(&mut a2_r, &mut a2_w, 0, &s2_real, true);
        let fake2 = fake_peer(
            &mut b2_r,
            &mut b2_w,
            0,
            &peer_id,
            false,
            Tamper::Replay(captured_sig),
        );
        let (r2, _) = tokio::join!(real2, fake2);
        assert!(r2.is_err(), "a replayed signature must not verify");
    }

    /// Contract 12 (roles): if both ends believe they are the initiator, the
    /// transcripts diverge and both signatures fail — roles never confuse.
    #[tokio::test]
    async fn v6_conflicting_roles_fail() {
        let a_id = NodeIdentity::generate();
        let b_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let a = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &a_id, true);
        let b = P2PNetwork::handshake_v6(&mut b_r, &mut b_w, 0, &b_id, true);
        let (ra, rb) = tokio::join!(a, b);
        assert!(ra.is_err(), "conflicting roles must fail on both ends");
        assert!(rb.is_err(), "conflicting roles must fail on both ends");
    }

    /// Contract 13: a truncated Hello (peer closes early) fails cleanly.
    #[tokio::test]
    async fn v6_rejects_truncated_hello() {
        let id = NodeIdentity::generate();
        let (mut a_r, mut a_w) = tokio::io::duplex(256);
        let (_sink_r, mut b_w) = tokio::io::duplex(256);
        b_w.write_all(&[0u8; 20]).await.unwrap();
        drop(b_w);
        let r = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &id, true).await;
        assert!(r.is_err(), "truncated Hello must fail");
    }

    /// 4CP-S / F2: a low-order (non-contributory) peer ephemeral is rejected
    /// even though the peer presents a VALID Ed25519 signature over the
    /// transcript carrying it — the signature is not a substitute for the DH
    /// check.
    #[tokio::test]
    async fn v6_rejects_non_contributory_peer_key() {
        let real_id = NodeIdentity::generate();
        let peer_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let real = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &real_id, true);
        let fake = fake_peer(&mut b_r, &mut b_w, 0, &peer_id, false, Tamper::LowOrderEph);
        let (rr, _) = tokio::join!(real, fake);
        assert!(
            rr.is_err(),
            "non-contributory X25519 must be rejected despite a valid signature"
        );
    }

    /// 4CP-S / F2: the legacy v5 path also rejects a non-contributory peer key.
    /// An ordinary v5 peer is unaffected (see `v5_legacy_handshake_unchanged`),
    /// so only cryptographically invalid exchanges are refused.
    #[tokio::test]
    async fn v5_rejects_non_contributory_peer_key() {
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let mut frame = Vec::with_capacity(HANDSHAKE_FRAME_LEN);
        frame.extend_from_slice(&P2PNetwork::handshake_wire_magic());
        frame.push(P2P_PROTOCOL_VERSION);
        frame.extend_from_slice(&crate::genesis::GENESIS_HASH);
        frame.extend_from_slice(&0u64.to_le_bytes());
        frame.extend_from_slice(&[0u8; 32]); // all-zero (low-order) ephemeral
        assert_eq!(frame.len(), HANDSHAKE_FRAME_LEN);
        b_w.write_all(&frame).await.unwrap();
        b_w.flush().await.unwrap();
        let r = P2PNetwork::handshake(&mut a_r, &mut a_w, 0).await;
        // Drain the real side's outgoing frame so the duplex never wedges.
        let mut sink = [0u8; HANDSHAKE_FRAME_LEN];
        let _ = b_r.read_exact(&mut sink).await;
        assert!(r.is_err(), "v5 must reject a non-contributory peer key");
    }

    /// 4CP-S / F7: a v6 node rejects a v5 peer FAST — the version is read from
    /// the 5-byte prefix, so the failure is bounded well inside the 10s
    /// handshake budget instead of waiting for the full Hello.
    #[tokio::test]
    async fn v6_rejects_v5_peer_quickly() {
        let id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let six = P2PNetwork::handshake_v6(&mut a_r, &mut a_w, 0, &id, true);
        let five = P2PNetwork::handshake(&mut b_r, &mut b_w, 0);
        let both = async { tokio::join!(six, five) };
        let (r6, r5) = tokio::time::timeout(Duration::from_secs(2), both)
            .await
            .expect("v6<->v5 rejection must come from the prefix, not the 10s timeout");
        assert!(r6.is_err(), "v6 side must reject the v5 peer");
        assert!(r5.is_err(), "v5 side must reject the v6 frame");
    }

    /// Contract 15: the session classifier NEVER labels a legacy session as
    /// authenticated, and only a verified v6 peer is `Authenticated`.
    #[test]
    fn legacy_never_classified_as_authenticated() {
        match P2PNetwork::session_auth_for(None) {
            P2PSessionAuth::EncryptedUnauthenticated => {}
            other => panic!("legacy session must be unauthenticated, got {:?}", other),
        }
        let nid = NodeIdentity::generate().node_id();
        match P2PNetwork::session_auth_for(Some(nid)) {
            P2PSessionAuth::Authenticated { node_id } => assert_eq!(node_id, nid),
            other => panic!("verified v6 session must be authenticated, got {:?}", other),
        }
    }

    /// Contracts 2/3: the identity persists across a reload and distinct data
    /// directories yield distinct identities.
    #[test]
    fn identity_persists_and_dirs_differ() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();

        let (a, o1) = crate::node_identity::load_or_create(d1.path()).unwrap();
        assert_eq!(o1, IdentityOutcome::Created);
        let (a2, o2) = crate::node_identity::load_or_create(d1.path()).unwrap();
        assert_eq!(o2, IdentityOutcome::Loaded);
        assert_eq!(a.node_id(), a2.node_id(), "identity must survive a restart");

        let (b, _) = crate::node_identity::load_or_create(d2.path()).unwrap();
        assert_ne!(
            a.node_id(),
            b.node_id(),
            "distinct data dirs must yield distinct identities"
        );
    }

    // --- 4CP-AC (4CPT-07): the v6 handshake carries ONE global budget ---

    /// Send the fixed 5-byte v6 prefix (magic + version) and flush; the caller
    /// then stalls. Used to prove a peer cannot restart the budget per step.
    async fn send_prefix_then_stall<W: AsyncWriteExt + Unpin>(w: &mut W) {
        let mut pre = Vec::with_capacity(5);
        pre.extend_from_slice(&P2PNetwork::handshake_wire_magic());
        pre.push(P2P_PROTOCOL_VERSION_V6);
        w.write_all(&pre).await.unwrap();
        w.flush().await.unwrap();
    }

    fn err_string<T: std::fmt::Debug>(r: Result<T, Box<dyn std::error::Error>>) -> String {
        match r {
            Ok(_) => panic!("expected the handshake to fail, got success"),
            Err(e) => e.to_string(),
        }
    }

    /// Scenario 1: a peer that sends the 5-byte prefix then stops is bounded by
    /// the GLOBAL budget, and the failure is a timeout (not a disconnect).
    #[tokio::test]
    async fn v6_global_budget_rejects_peer_stalling_after_prefix() {
        let id = NodeIdentity::generate();
        let budget = Duration::from_millis(300);
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let peer = tokio::spawn(async move {
            send_prefix_then_stall(&mut b_w).await;
            std::future::pending::<()>().await;
            drop(b_r);
        });

        let started = tokio::time::Instant::now();
        let r = P2PNetwork::handshake_v6_with_budget(&mut a_r, &mut a_w, 0, &id, true, budget).await;
        let elapsed = started.elapsed();
        let msg = err_string(r);

        assert!(msg.contains("timeout"), "must be a budget expiry, got: {}", msg);
        assert!(elapsed >= budget / 2, "must spend its budget, took {:?}", elapsed);
        assert!(
            elapsed < budget * 3,
            "must NOT stack a fresh budget per step, took {:?}",
            elapsed
        );
        peer.abort();
    }

    /// Scenario 2: a peer that sends the prefix plus a PARTIAL remainder then
    /// stalls is still bounded by the same single deadline.
    #[tokio::test]
    async fn v6_global_budget_rejects_partial_hello_peer() {
        let id = NodeIdentity::generate();
        let budget = Duration::from_millis(300);
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let peer = tokio::spawn(async move {
            send_prefix_then_stall(&mut b_w).await;
            b_w.write_all(&[0u8; 40]).await.unwrap();
            b_w.flush().await.unwrap();
            std::future::pending::<()>().await;
            drop(b_r);
        });

        let started = tokio::time::Instant::now();
        let r = P2PNetwork::handshake_v6_with_budget(&mut a_r, &mut a_w, 0, &id, true, budget).await;
        let elapsed = started.elapsed();
        let msg = err_string(r);

        assert!(msg.contains("timeout"), "must be a budget expiry, got: {}", msg);
        assert!(elapsed >= budget / 2, "must spend its budget, took {:?}", elapsed);
        assert!(elapsed < budget * 3, "must not stack budgets, took {:?}", elapsed);
        peer.abort();
    }

    /// Scenario 3: a peer that progresses step by step — prefix, then the rest
    /// of the Hello, then the signature — each gap well inside one budget but
    /// whose TOTAL exceeds it must still fail. A per-step design would let it
    /// succeed; the single absolute deadline does not.
    #[tokio::test]
    async fn v6_global_budget_bounds_stepwise_progress() {
        let id = NodeIdentity::generate();
        let budget = Duration::from_millis(400);
        let step = Duration::from_millis(250); // each gap < budget, total > budget
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();

        let peer = tokio::spawn(async move {
            let mut local_hello = [0u8; V6_HELLO_LEN];
            b_r.read_exact(&mut local_hello).await.unwrap(); // drain the local Hello
            send_prefix_then_stall(&mut b_w).await;
            tokio::time::sleep(step).await;
            let hello = hello_bytes(
                0,
                &super::V6Hello {
                    eph: [1u8; 32],
                    nonce: [2u8; 32],
                    node_id: [3u8; 32],
                },
            );
            b_w.write_all(&hello[5..]).await.unwrap();
            b_w.flush().await.unwrap();
            tokio::time::sleep(step).await;
            b_w.write_all(&[0u8; V6_SIG_LEN]).await.unwrap();
            b_w.flush().await.unwrap();
            std::future::pending::<()>().await;
        });

        let started = tokio::time::Instant::now();
        let r = P2PNetwork::handshake_v6_with_budget(&mut a_r, &mut a_w, 0, &id, true, budget).await;
        let elapsed = started.elapsed();
        let msg = err_string(r);

        assert!(
            msg.contains("timeout"),
            "step-wise slow peer must fail under a global budget, got: {}",
            msg
        );
        assert!(
            elapsed < budget + Duration::from_millis(200),
            "must fail at the shared deadline, not after each step (took {:?})",
            elapsed
        );
        peer.abort();
    }

    /// Scenario 4: the budget expires during the signature exchange — the peer
    /// sends a complete, network-valid Hello but never its signature.
    #[tokio::test]
    async fn v6_global_budget_rejects_peer_stalling_before_signature() {
        let id = NodeIdentity::generate();
        let budget = Duration::from_millis(300);
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let peer = tokio::spawn(async move {
            let hello = hello_bytes(
                0,
                &super::V6Hello {
                    eph: [4u8; 32],
                    nonce: [5u8; 32],
                    node_id: [6u8; 32],
                },
            );
            b_w.write_all(&hello).await.unwrap();
            b_w.flush().await.unwrap();
            let mut sink = [0u8; V6_HELLO_LEN];
            let _ = b_r.read_exact(&mut sink).await; // drain the local Hello
            std::future::pending::<()>().await;
        });

        let started = tokio::time::Instant::now();
        let r = P2PNetwork::handshake_v6_with_budget(&mut a_r, &mut a_w, 0, &id, true, budget).await;
        let elapsed = started.elapsed();
        let msg = err_string(r);

        assert!(
            msg.contains("timeout") && msg.contains("signature"),
            "must expire during the signature step, got: {}",
            msg
        );
        assert!(elapsed >= budget / 2, "must spend its budget, took {:?}", elapsed);
        assert!(elapsed < budget * 3, "must not stack budgets, took {:?}", elapsed);
        peer.abort();
    }

    /// Scenario 5: a normal v6 handshake completes well inside the budget and
    /// keeps its behaviour (same key, opposite directions, real NodeIds).
    #[tokio::test]
    async fn v6_global_budget_allows_normal_handshake() {
        let a_id = NodeIdentity::generate();
        let b_id = NodeIdentity::generate();
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let budget = Duration::from_secs(5);
        let a = P2PNetwork::handshake_v6_with_budget(&mut a_r, &mut a_w, 0, &a_id, true, budget);
        let b = P2PNetwork::handshake_v6_with_budget(&mut b_r, &mut b_w, 0, &b_id, false, budget);
        let (ra, rb) = tokio::join!(a, b);
        let (ka, da, pa) = ra.expect("A must authenticate within budget");
        let (kb, db, pb) = rb.expect("B must authenticate within budget");
        assert_eq!(ka, kb, "both ends derive the same session key");
        assert_ne!(da, db, "send directions must be opposite");
        assert_eq!(pa, b_id.node_id(), "A learned B's real NodeId");
        assert_eq!(pb, a_id.node_id(), "B learned A's real NodeId");
    }

    /// The global budget applies identically to the RESPONDER role.
    #[tokio::test]
    async fn v6_global_budget_applies_to_responder_role() {
        let id = NodeIdentity::generate();
        let budget = Duration::from_millis(300);
        let (mut a_r, mut a_w, mut b_r, mut b_w) = duplex_pair();
        let peer = tokio::spawn(async move {
            send_prefix_then_stall(&mut b_w).await;
            std::future::pending::<()>().await;
            drop(b_r);
        });
        let r =
            P2PNetwork::handshake_v6_with_budget(&mut a_r, &mut a_w, 0, &id, false, budget).await;
        let msg = err_string(r);
        assert!(
            msg.contains("timeout"),
            "responder must also enforce the global budget, got: {}",
            msg
        );
        peer.abort();
    }
}

/// PHASE 4CP-S: contract tests for session-scoped authentication state (F1).
///
/// These drive the SAME registry methods `handle_peer` uses
/// (`next_session_id` / `record_session_auth` / `clear_session_auth`) and the
/// same global teardown path (`shutdown`), so the invariants below hold for the
/// real code, not a re-implementation.
#[cfg(test)]
mod phase4cp_session_tests {
    use super::*;
    use crate::node_identity::{NodeId, NodeIdentity};
    use std::net::SocketAddr;

    fn auth_net_cfg(cfg: P2PConfig) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
        P2PNetwork::new(
            cfg,
            tx,
            empty.clone(),
            empty_opt,
            empty,
            Arc::new(SyncContext::default()),
            Arc::new(|_| false),
        )
    }

    fn auth_net() -> P2PNetwork {
        auth_net_cfg(P2PConfig::default())
    }

    fn nid() -> NodeId {
        NodeIdentity::generate().node_id()
    }

    fn ep() -> SocketAddr {
        "203.0.113.9:40000".parse().unwrap()
    }

    /// Obligatory 1: two sessions sharing one endpoint keep distinct state.
    #[tokio::test]
    async fn two_sessions_same_addr_do_not_overwrite() {
        let net = auth_net();
        let x = ep();
        let id1 = net.next_session_id();
        let id2 = net.next_session_id();
        assert_ne!(id1, id2, "session ids must be unique");
        net.record_session_auth(id1, x, P2PSessionAuth::Authenticated { node_id: nid() })
            .await;
        net.record_session_auth(id2, x, P2PSessionAuth::EncryptedUnauthenticated)
            .await;
        assert!(matches!(
            net.session_auth_by_id(id1).await,
            Some(P2PSessionAuth::Authenticated { .. })
        ));
        assert_eq!(
            net.session_auth_by_id(id2).await,
            Some(P2PSessionAuth::EncryptedUnauthenticated)
        );
        assert_eq!(
            net.session_auth_for_addr(&x).await.len(),
            2,
            "both sessions must be tracked at the shared endpoint"
        );
    }

    /// Obligatory 2: closing the first session leaves the second intact.
    #[tokio::test]
    async fn closing_one_session_leaves_the_other() {
        let net = auth_net();
        let x = ep();
        let id1 = net.next_session_id();
        let id2 = net.next_session_id();
        net.record_session_auth(id1, x, P2PSessionAuth::Authenticated { node_id: nid() })
            .await;
        net.record_session_auth(id2, x, P2PSessionAuth::EncryptedUnauthenticated)
            .await;
        net.clear_session_auth(id1).await;
        assert_eq!(net.session_auth_by_id(id1).await, None);
        assert_eq!(
            net.session_auth_by_id(id2).await,
            Some(P2PSessionAuth::EncryptedUnauthenticated),
            "an older session's teardown must never erase a newer one"
        );
    }

    /// Obligatory 3: a legacy session cannot replace another session's
    /// authenticated identity.
    #[tokio::test]
    async fn legacy_session_cannot_replace_authenticated_identity() {
        let net = auth_net();
        let x = ep();
        let real = nid();
        let id_auth = net.next_session_id();
        net.record_session_auth(id_auth, x, P2PSessionAuth::Authenticated { node_id: real })
            .await;
        let id_legacy = net.next_session_id();
        net.record_session_auth(id_legacy, x, P2PSessionAuth::EncryptedUnauthenticated)
            .await;
        net.clear_session_auth(id_legacy).await;
        match net.session_auth_by_id(id_auth).await {
            Some(P2PSessionAuth::Authenticated { node_id }) => assert_eq!(node_id, real),
            other => panic!("authenticated identity lost: {:?}", other),
        }
    }

    /// Obligatory 4: a reconnect at the same endpoint inherits no old state.
    #[tokio::test]
    async fn reconnect_does_not_inherit_state() {
        let net = auth_net();
        let x = ep();
        let id1 = net.next_session_id();
        net.record_session_auth(id1, x, P2PSessionAuth::Authenticated { node_id: nid() })
            .await;
        net.clear_session_auth(id1).await; // old session ends
        let id2 = net.next_session_id(); // fresh session, same endpoint
        assert_eq!(
            net.session_auth_by_id(id2).await,
            None,
            "a reconnect must not inherit the previous session's provenance"
        );
        assert!(net.session_auth_for_addr(&x).await.is_empty());
        net.record_session_auth(id2, x, P2PSessionAuth::EncryptedUnauthenticated)
            .await;
        assert_eq!(
            net.session_auth_by_id(id2).await,
            Some(P2PSessionAuth::EncryptedUnauthenticated)
        );
    }

    /// Obligatory 5: a failed handshake leaves no authenticated state, and a
    /// torn-down session is fully removed.
    #[tokio::test]
    async fn failed_handshake_leaves_no_residual_state() {
        let net = auth_net();
        let x = ep();
        // handle_peer's failure branch records NOTHING for the session id.
        let failed = net.next_session_id();
        assert_eq!(net.session_auth_by_id(failed).await, None);
        assert!(net.session_auth_for_addr(&x).await.is_empty());
        assert_eq!(net.session_auth_len().await, 0);
        net.record_session_auth(failed, x, P2PSessionAuth::Authenticated { node_id: nid() })
            .await;
        net.clear_session_auth(failed).await;
        assert_eq!(net.session_auth_len().await, 0, "no residual state");
    }

    /// Obligatory 6: global shutdown frees every session state.
    #[tokio::test]
    async fn shutdown_releases_all_session_state() {
        let net = auth_net();
        let x = ep();
        for _ in 0..5 {
            let id = net.next_session_id();
            net.record_session_auth(id, x, P2PSessionAuth::Authenticated { node_id: nid() })
                .await;
        }
        assert_eq!(net.session_auth_len().await, 5);
        net.shutdown()
            .await
            .expect("shutdown of an unstarted net is Ok");
        assert_eq!(
            net.session_auth_len().await,
            0,
            "shutdown must free every session"
        );
        assert!(net.session_auth_for_addr(&x).await.is_empty());
    }

    /// F3: the protocol mode is immutable once the node has started.
    /// 4CP-U (4CPT-02): v6 also requires an identity, so one is installed.
    #[tokio::test]
    async fn protocol_mode_is_immutable_after_start() {
        let net = auth_net_cfg(P2PConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..P2PConfig::default()
        });
        net.set_node_identity(NodeIdentity::generate());
        net.set_protocol_mode(P2PProtocolMode::AuthenticatedV6);
        assert_eq!(net.protocol_mode(), P2PProtocolMode::AuthenticatedV6);
        net.start().await.expect("bind loopback");
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        assert_eq!(
            net.protocol_mode(),
            P2PProtocolMode::AuthenticatedV6,
            "mode must stay frozen after start()"
        );
        assert_eq!(
            net.started_protocol_mode(),
            Some(P2PProtocolMode::AuthenticatedV6),
            "the live snapshot is the frozen mode"
        );
        let _ = net.shutdown().await;
    }

    /// 4CPT-02: `AuthenticatedV6` refuses to start without an identity, leaves
    /// the lifecycle un-frozen, and succeeds once one is installed.
    #[tokio::test]
    async fn v6_start_requires_identity() {
        let net = auth_net_cfg(P2PConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..P2PConfig::default()
        });
        net.set_protocol_mode(P2PProtocolMode::AuthenticatedV6);
        let err = net
            .start()
            .await
            .expect_err("v6 without an identity must not start");
        assert!(
            err.to_string().contains("identity"),
            "the error must name the missing identity: {}",
            err
        );
        // Not frozen: the operator can fix the configuration and retry.
        assert_ne!(net.lifecycle_state(), P2PNetworkState::Started);
        assert_eq!(net.started_protocol_mode(), None);
        net.set_node_identity(NodeIdentity::generate());
        net.start().await.expect("v6 with an identity must start");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Started);
        let _ = net.shutdown().await;
    }

    /// 4CPT-10: a bind failure must not leave the network looking started, and
    /// the lifecycle must stay recoverable (setters accepted again).
    #[tokio::test]
    async fn bind_failure_does_not_leave_started() {
        // A public address this host cannot assign: bind fails deterministically
        // without any traffic leaving the machine.
        let net = auth_net_cfg(P2PConfig {
            listen_addr: "203.0.113.9:25565".parse().unwrap(),
            ..P2PConfig::default()
        });
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start()
            .await
            .expect_err("binding a non-local address must fail");
        assert_eq!(
            net.lifecycle_state(),
            P2PNetworkState::Failed,
            "a failed start must not be reported as Started"
        );
        assert_eq!(net.started_protocol_mode(), None, "no lingering snapshot");
        // Recoverable: the configuration can be changed and start retried.
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Configured);
    }

    /// 4CPT-01: a setter racing `start()` can never leave the live snapshot and
    /// the reported mode disagreeing — both are decided under one lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_setters_race_start_consistently() {
        let net = auth_net_cfg(P2PConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..P2PConfig::default()
        });
        // An identity is installed up front so both candidate modes are valid
        // and `start()` always succeeds regardless of which setter wins.
        net.set_node_identity(NodeIdentity::generate());
        // 4CP-W (V-3): the network must be explicitly configured before start()
        // can run; seed it with one of the two candidates the setters race.
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);

        let mut handles = Vec::new();
        for i in 0..64u32 {
            let net = net.clone();
            handles.push(tokio::spawn(async move {
                let mode = if i % 2 == 0 {
                    P2PProtocolMode::AuthenticatedV6
                } else {
                    P2PProtocolMode::LegacyV5
                };
                net.set_protocol_mode(mode);
            }));
        }
        // Race the start against the setters. The error is stringified inside
        // the task so the spawned future's output is `Send`.
        let start = {
            let net = net.clone();
            tokio::spawn(async move { net.start().await.map_err(|e| e.to_string()) })
        };
        for h in handles {
            h.await.unwrap();
        }
        start
            .await
            .unwrap()
            .expect("start on loopback must succeed");

        // The frozen snapshot and the reported mode are one and the same value,
        // and it is one of the two candidates — never a torn read.
        let started = net
            .started_protocol_mode()
            .expect("a started network has a snapshot");
        assert_eq!(
            net.protocol_mode(),
            started,
            "live snapshot and reported mode must agree"
        );
        assert!(matches!(
            started,
            P2PProtocolMode::LegacyV5 | P2PProtocolMode::AuthenticatedV6
        ));
        // And it is now frozen: a late setter cannot change it.
        let late = if started == P2PProtocolMode::LegacyV5 {
            P2PProtocolMode::AuthenticatedV6
        } else {
            P2PProtocolMode::LegacyV5
        };
        net.set_protocol_mode(late);
        assert_eq!(net.protocol_mode(), started, "mode must stay frozen");
        let _ = net.shutdown().await;
    }

    /// 4CPT-01: a clone shares the lifecycle, so a setter through one handle is
    /// visible (and frozen) through every other.
    #[tokio::test]
    async fn clones_share_lifecycle() {
        let net = auth_net();
        let clone = net.clone();
        clone.set_protocol_mode(P2PProtocolMode::LegacyV5);
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Configured);
    }
}

/// PHASE 4CP-W: deterministic tests for the start/shutdown serialisation (V-1),
/// the atomic session admission (V-2) and the explicit-mode requirement (V-3).
///
/// Every test drives the REAL lifecycle and registry functions. Ordering is
/// enforced with `Notify`/`Barrier` rendezvous, never with `sleep()`.
#[cfg(test)]
mod phase4cpw_cycle_tests {
    use super::*;
    use crate::node_identity::NodeIdentity;
    use std::net::SocketAddr;

    fn cpw_net() -> P2PNetwork {
        cpw_net_on("127.0.0.1:0")
    }

    /// 4CP-AA (X-6): same construction as `cpw_net`, but with an explicit listen
    /// address so a test can force a deterministic `bind()` failure.
    fn cpw_net_on(listen_addr: &str) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
        P2PNetwork::new(
            P2PConfig {
                listen_addr: listen_addr.parse().unwrap(),
                bootnodes: vec![],
                dns_seeds: vec![],
                peer_store_path: None,
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
            },
            tx,
            empty.clone(),
            empty_opt,
            empty,
            Arc::new(SyncContext::default()),
            Arc::new(|_| false),
        )
    }

    fn ep() -> SocketAddr {
        "203.0.113.9:40000".parse().unwrap()
    }

    /// V-3: a freshly built network is unconfigured and refuses to start; an
    /// explicit mode makes it start.
    #[tokio::test]
    async fn unconfigured_network_refuses_to_start() {
        let net = cpw_net();
        let err = net
            .start()
            .await
            .expect_err("an unconfigured network must not start");
        assert!(
            err.to_string().contains("not configured"),
            "the error must name the missing choice: {}",
            err
        );
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Unconfigured);
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("explicit legacy starts");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Started);
        let _ = net.shutdown().await;
    }

    /// V-3: v6 still requires an identity, and the failure stays recoverable.
    #[tokio::test]
    async fn v6_requires_identity_on_public_start() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::AuthenticatedV6);
        assert!(net.start().await.is_err());
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Configured);
        net.set_node_identity(NodeIdentity::generate());
        net.start().await.expect("v6 with identity starts");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Started);
        let _ = net.shutdown().await;
    }

    /// V-1: a shutdown() engaged during start() wins. start() must not flip the
    /// lifecycle back to `Started`; the state stays `Stopped` and the call
    /// reports the supersession.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_start_never_reaches_started() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        let gate = net.install_start_gate();
        let n2 = net.clone();
        let start = tokio::spawn(async move { n2.start().await.map_err(|e| e.to_string()) });
        // Wait until start() has committed `Starting` and parked at the gate.
        gate.arrived.notified().await;
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Starting);
        // Engage the stop while start() is parked.
        net.shutdown().await.expect("shutdown must succeed");
        // Release start() and collect its result.
        gate.release.notify_one();
        let res = start.await.unwrap();
        assert!(
            res.is_err(),
            "a start superseded by shutdown must fail, got {:?}",
            res
        );
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Stopped);
        assert_eq!(net.started_protocol_mode(), None, "no lingering snapshot");
    }

    /// V-1: the reachable restart path after Stopped still works.
    #[tokio::test]
    async fn restart_after_stopped_succeeds() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("first start");
        let gen1 = net.generation();
        net.shutdown().await.expect("shutdown");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Stopped);
        net.start().await.expect("restart");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Started);
        assert!(net.generation() > gen1, "restart bumps the cycle generation");
        let _ = net.shutdown().await;
    }

    /// V-1: two concurrent start() calls — exactly one wins, the other errors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_starts_only_one_wins() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        let a = {
            let net = net.clone();
            tokio::spawn(async move { net.start().await.map_err(|e| e.to_string()) })
        };
        let b = {
            let net = net.clone();
            tokio::spawn(async move { net.start().await.map_err(|e| e.to_string()) })
        };
        let ra = a.await.unwrap();
        let rb = b.await.unwrap();
        assert!(
            ra.is_ok() ^ rb.is_ok(),
            "exactly one start must win: {:?} vs {:?}",
            ra,
            rb
        );
        let _ = net.shutdown().await;
    }

    /// V-1: two concurrent shutdown() calls both succeed (serialised).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_shutdowns_are_serialised() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        let a = {
            let net = net.clone();
            tokio::spawn(async move { net.shutdown().await })
        };
        let b = {
            let net = net.clone();
            tokio::spawn(async move { net.shutdown().await })
        };
        assert!(a.await.unwrap().is_ok());
        assert!(b.await.unwrap().is_ok());
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Stopped);
        assert_eq!(net.session_auth_len().await, 0);
    }

    /// V-2 (1): a handshake that reaches the registration point AFTER shutdown
    /// closed the registry records nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_session_cannot_register_after_shutdown() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        let generation = net.generation();

        let pre = Arc::new(tokio::sync::Barrier::new(2));
        let go = Arc::new(tokio::sync::Barrier::new(2));
        let id = 4242u64;
        let addr = ep();
        let n2 = net.clone();
        let (pre2, go2) = (pre.clone(), go.clone());
        let task = tokio::spawn(async move {
            pre2.wait().await; // "handshake reached the point before record"
            go2.wait().await; // wait for the test to finish shutdown()
            n2.record_session_auth_if_active(
                generation,
                id,
                addr,
                P2PSessionAuth::EncryptedUnauthenticated,
            )
            .await
        });
        pre.wait().await; // rendezvous: handshake is parked before recording
        net.shutdown().await.expect("shutdown");
        go.wait().await; // let the late record proceed
        let recorded = task.await.unwrap();
        assert!(!recorded, "a late handshake must not register after shutdown");
        assert_eq!(net.session_auth_len().await, 0, "no residual session");
    }

    /// V-2 (3): a task from an old cycle cannot register into a later one, even
    /// after a restart with the SAME configuration.
    #[tokio::test]
    async fn old_generation_cannot_register_in_new_cycle() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start cycle 1");
        let gen1 = net.generation();
        net.shutdown().await.expect("shutdown cycle 1");
        net.start().await.expect("start cycle 2");
        let gen2 = net.generation();
        assert_ne!(gen1, gen2, "a restart is a new generation");

        let addr = ep();
        // A late task belonging to cycle 1 must be rejected by the new cycle…
        assert!(
            !net.record_session_auth_if_active(
                gen1,
                7,
                addr,
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await,
            "old-generation registration must be refused"
        );
        assert_eq!(net.session_auth_len().await, 0);
        // …while the live cycle registers normally.
        assert!(
            net.record_session_auth_if_active(
                gen2,
                8,
                addr,
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await,
            "the live cycle must register"
        );
        assert_eq!(net.session_auth_len().await, 1);
        let _ = net.shutdown().await;
    }

    /// V-2 (4): closing one session (in the live generation) never removes
    /// another, and a clear from an old generation is a no-op.
    #[tokio::test]
    async fn clear_is_generation_scoped_and_session_scoped() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        let generation = net.generation();
        let addr = ep();
        assert!(
            net.record_session_auth_if_active(
                generation,
                1,
                addr,
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await
        );
        assert!(
            net.record_session_auth_if_active(
                generation,
                2,
                addr,
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await
        );
        // An old generation cannot clear.
        assert!(!net.clear_session_auth_if_active(generation + 99, 1).await);
        assert_eq!(net.session_auth_len().await, 2);
        // The live generation clears exactly one.
        assert!(net.clear_session_auth_if_active(generation, 1).await);
        assert_eq!(net.session_auth_len().await, 1);
        assert_eq!(
            net.session_auth_by_id(2).await,
            Some(P2PSessionAuth::EncryptedUnauthenticated)
        );
        let _ = net.shutdown().await;
    }

    /// V-2 (6): once shutdown() has returned Ok, the old cycle's registry is
    /// sealed — a registration attempt with the old generation is refused.
    #[tokio::test]
    async fn shutdown_ok_closes_the_registry() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        let generation = net.generation();
        net.shutdown().await.expect("shutdown");
        assert!(
            !net.record_session_auth_if_active(
                generation,
                99,
                ep(),
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await,
            "after a successful shutdown the old cycle must be sealed"
        );
        assert_eq!(net.session_auth_len().await, 0);
    }

    /// 4CP-Y (X-4/X-6, real path): a genuine `handle_peer` session — real
    /// socket, real production handshake — that reaches its registration point
    /// while a `shutdown()` closes the cycle must register nothing. Unlike
    /// `late_session_cannot_register_after_shutdown`, this drives the actual
    /// per-session function through a `record_gate` rendezvous, so it proves the
    /// guard on the production code path rather than a mirror helper.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_session_cannot_register_after_shutdown() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        let generation = net.generation();

        // A real peer endpoint this host can connect to.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Client side: connect, complete the production handshake, then hold the
        // socket open for the duration of the test.
        let client = tokio::spawn(async move {
            let sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let (mut reader, mut writer) = sock.into_split();
            let _ = P2PNetwork::handshake(
                &mut reader,
                &mut writer,
                crate::transaction::DEFAULT_NETWORK_ID,
            )
            .await;
            std::future::pending::<()>().await;
        });

        let (server_stream, peer_addr) = listener.accept().await.unwrap();

        // 4CP-Y: park the real session just before its registry write.
        let gate = Arc::new(StartGate::default());
        let gate_for_task = gate.clone();
        let net2 = net.clone();
        let session = tokio::spawn(async move {
            let (msg_sender, msg_receiver) = mpsc::unbounded_channel();
            let (pdtx, _pdrx) = mpsc::unbounded_channel();
            P2PNetwork::handle_peer(
                TransportStream::Tcp(server_stream),
                peer_addr,
                net2.peers.clone(),
                net2.config.listen_addr,
                net2.addresses.clone(),
                net2.tx_channel.clone(),
                net2.get_dag_hashes.clone(),
                net2.get_transaction_by_hash.clone(),
                net2.get_tips.clone(),
                net2.seen_transactions.clone(),
                net2.propagation_state.clone(),
                msg_sender,
                msg_receiver,
                pdtx,
                net2.sync_ctx.clone(),
                net2.is_orphan.clone(),
                net2.stake_hooks.clone(),
                net2.config.network_id,
                P2PProtocolMode::LegacyV5,
                None,
                false,
                net2.session_auth.clone(),
                net2.session_seq.clone(),
                generation,
                Some(gate_for_task),
                net2.admission.clone(),
                HANDSHAKE_TIMEOUT,
            )
            .await;
        });

        // The real session has completed the handshake and is parked.
        gate.arrived.notified().await;
        assert_eq!(net.peer_count().await, 0, "not recorded yet");

        // Close the cycle, THEN let the real session race for registration.
        net.shutdown().await.expect("shutdown");
        gate.release.notify_one();
        session.await.unwrap();

        assert_eq!(
            net.session_auth_len().await,
            0,
            "a real session reaching registration after shutdown must register nothing"
        );
        assert_eq!(net.peer_count().await, 0, "no half-open peer left behind");
        client.abort();
    }

    // ---- 4CP-AA (X-6): shutdown across every lifecycle state ----------------

    /// X-6/4CP-AA: `shutdown()` on a network that was configured but never
    /// started freezes it as `Stopped` (no live cycle existed), releases the
    /// snapshot, closes admission and seals the registry; a later `start()` is
    /// still permitted from `Stopped`.
    #[tokio::test]
    async fn shutdown_on_configured_freezes_without_a_cycle() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Configured);

        net.shutdown()
            .await
            .expect("shutdown of a configured-but-unstarted network");
        assert_eq!(
            net.lifecycle_state(),
            P2PNetworkState::Stopped,
            "an engaged stop freezes a never-live cycle too (X-6)"
        );
        assert_eq!(net.started_protocol_mode(), None, "no snapshot survives");
        assert!(net.is_shutting_down());
        // Consistency: state, snapshot, admission and registry all agree.
        assert!(
            !net.spawn_tracked(async {}),
            "admission must be closed after shutdown"
        );
        assert_eq!(net.session_auth_len().await, 0);

        // A pre-start shutdown freezes the configuration but does not forbid a
        // later start.
        net.start().await.expect("restart after a pre-start shutdown");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Started);
        net.shutdown().await.expect("final shutdown");
    }

    /// X-6: `shutdown()` on a network whose `start()` failed at `bind()` (state
    /// `Failed`) freezes it as `Stopped` and leaves no live cycle.
    #[tokio::test]
    async fn shutdown_on_failed_freezes() {
        // A non-local address guarantees a deterministic bind failure without
        // any traffic leaving the machine (same technique as 4CPT-10).
        let net = cpw_net_on("203.0.113.9:25565");
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start()
            .await
            .expect_err("binding a non-local address must fail");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Failed);

        net.shutdown().await.expect("shutdown on Failed");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Stopped);
        assert_eq!(net.started_protocol_mode(), None);
        assert!(!net.spawn_tracked(async {}));
        assert_eq!(net.session_auth_len().await, 0);
    }

    /// X-6: `shutdown()` on a never-configured network must not invent a
    /// `Stopped` state — there was no cycle — and the "no implicit v5" refusal
    /// (X-1) still holds afterwards.
    #[tokio::test]
    async fn shutdown_on_unconfigured_stays_unconfigured() {
        let net = cpw_net();
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Unconfigured);
        net.shutdown().await.expect("shutdown on Unconfigured");
        assert_eq!(
            net.lifecycle_state(),
            P2PNetworkState::Unconfigured,
            "an unconfigured network is not a live cycle"
        );
        assert_eq!(net.started_protocol_mode(), None);
        assert!(!net.spawn_tracked(async {}));
        assert!(
            net.start().await.is_err(),
            "still no implicit v5 after an unconfigured shutdown"
        );
    }

    /// X-6: two sequential `shutdown()` calls are idempotent — the second is a
    /// no-op that still reports success.
    #[tokio::test]
    async fn sequential_shutdown_is_idempotent() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        net.shutdown().await.expect("first shutdown");
        net.shutdown()
            .await
            .expect("second shutdown must be a clean no-op");
        assert_eq!(net.lifecycle_state(), P2PNetworkState::Stopped);
        assert_eq!(net.session_auth_len().await, 0);
    }

    /// X-6: after `shutdown()` the four pieces of cycle state agree — frozen
    /// lifecycle, released snapshot, closed admission and sealed+empty
    /// registry — and a restart re-opens all four under a new generation.
    #[tokio::test]
    async fn shutdown_then_restart_reopens_every_guard() {
        let net = cpw_net();
        net.set_protocol_mode(P2PProtocolMode::LegacyV5);
        net.start().await.expect("start");
        let gen1 = net.generation();
        // Live cycle: snapshot present, admission open, registry open.
        assert!(net.started_protocol_mode().is_some());
        assert!(net.spawn_tracked(async {}), "live admission accepts");
        assert!(net
            .record_session_auth_if_active(
                gen1,
                1,
                ep(),
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await);

        net.shutdown().await.expect("shutdown");
        assert!(net.started_protocol_mode().is_none());
        assert!(!net.spawn_tracked(async {}), "admission closed");
        assert_eq!(net.session_auth_len().await, 0, "registry sealed+cleared");
        assert!(
            !net.record_session_auth_if_active(
                gen1,
                2,
                ep(),
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await,
            "old cycle cannot register after shutdown"
        );

        net.start().await.expect("restart");
        let gen2 = net.generation();
        assert_ne!(gen1, gen2, "restart is a new generation");
        assert!(net.started_protocol_mode().is_some());
        assert!(net.spawn_tracked(async {}), "restart re-opens admission");
        assert!(
            net.record_session_auth_if_active(
                gen2,
                3,
                ep(),
                P2PSessionAuth::EncryptedUnauthenticated
            )
            .await,
            "restart re-opens the registry under the new generation"
        );
        let _ = net.shutdown().await;
    }

    // ---- 4CP-AA (Y-5): the outbound registration path -----------------------

    /// Y-5: a genuine OUTBOUND `handle_peer` (`is_initiator = true`) over a real
    /// socket — the mirror of `real_session_cannot_register_after_shutdown` —
    /// reaches the point just before registration, is released after a
    /// concurrent `shutdown()`, and registers nothing. This is the untracked
    /// variant, so the resumed session is refused by the registry seal itself
    /// (not merely aborted).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outbound_session_cannot_register_after_shutdown() {
        let net = cpw_net();
        net.open_cycle_for_test(P2PProtocolMode::LegacyV5).await;
        let generation = net.generation();

        // Remote responder: production handshake, then hold the socket.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = sock.into_split();
            let _ = P2PNetwork::handshake(
                &mut reader,
                &mut writer,
                crate::transaction::DEFAULT_NETWORK_ID,
            )
            .await;
            std::future::pending::<()>().await;
        });

        let sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let peer_addr = sock.peer_addr().unwrap();

        let gate = Arc::new(StartGate::default());
        let gate_for_task = gate.clone();
        let net2 = net.clone();
        let session = tokio::spawn(async move {
            let (msg_sender, msg_receiver) = mpsc::unbounded_channel();
            let (pdtx, _pdrx) = mpsc::unbounded_channel();
            P2PNetwork::handle_peer(
                TransportStream::Tcp(sock),
                peer_addr,
                net2.peers.clone(),
                net2.config.listen_addr,
                net2.addresses.clone(),
                net2.tx_channel.clone(),
                net2.get_dag_hashes.clone(),
                net2.get_transaction_by_hash.clone(),
                net2.get_tips.clone(),
                net2.seen_transactions.clone(),
                net2.propagation_state.clone(),
                msg_sender,
                msg_receiver,
                pdtx,
                net2.sync_ctx.clone(),
                net2.is_orphan.clone(),
                net2.stake_hooks.clone(),
                net2.config.network_id,
                P2PProtocolMode::LegacyV5,
                None,
                true, // 4CP-AA: outbound role — this is the path under test.
                net2.session_auth.clone(),
                net2.session_seq.clone(),
                generation,
                Some(gate_for_task),
                net2.admission.clone(),
                HANDSHAKE_TIMEOUT,
            )
            .await;
        });

        gate.arrived.notified().await;
        net.shutdown().await.expect("shutdown");
        gate.release.notify_one();
        session.await.unwrap();

        assert_eq!(
            net.session_auth_len().await,
            0,
            "an outbound session reaching registration after shutdown must register nothing"
        );
        assert_eq!(net.peer_count().await, 0, "no half-open peer left behind");
        server.abort();
    }

    /// Y-5: the same guarantee through the REAL production dialer
    /// (`connect_to_peer` -> `connect_to_peer_inner` -> `handle_peer`) with the
    /// test-only outbound rendezvous. After `shutdown()` the parked session is
    /// aborted, a follow-up dial is refused, and no residue (session, peer,
    /// dial reservation, outbound reservation) survives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_dial_cannot_leave_residue_across_shutdown() {
        let net = cpw_net();
        net.open_cycle_for_test(P2PProtocolMode::LegacyV5).await;
        let gate = net.install_outbound_record_gate();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = sock.into_split();
                    let _ = P2PNetwork::handshake(
                        &mut reader,
                        &mut writer,
                        crate::transaction::DEFAULT_NETWORK_ID,
                    )
                    .await;
                    std::future::pending::<()>().await;
                });
            }
        });

        // Real outbound dial: parks the session just before registration. The
        // dialer has already taken its optimistic `peers` + `outbound_sessions`
        // reservations, which the teardown must clear.
        net.connect_to_peer(server_addr).await;
        gate.arrived.notified().await;

        net.shutdown().await.expect("shutdown");
        gate.release.notify_one();
        // A dial issued after shutdown must be refused outright.
        net.connect_to_peer(server_addr).await;

        assert_eq!(net.session_auth_len().await, 0, "no residual session");
        assert_eq!(net.peer_count().await, 0, "no half-open peer");
        assert!(net.dialing.read().await.is_empty(), "no dial reservation");
        assert!(
            net.outbound_sessions.read().await.is_empty(),
            "no outbound reservation"
        );
        server.abort();
    }

    // --- 4CP-AC (4CPT-07): global-budget expiry tears the session down ---

    /// An INBOUND v6 session whose peer stalls after the 5-byte prefix must
    /// expire under the global budget, register NO session, and leave NO
    /// half-open peer behind. Drives the real `handle_peer` (responder role)
    /// with a short budget so the production teardown path runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_slow_v6_peer_expiry_leaves_no_inbound_session() {
        let net = cpw_net();
        net.open_cycle_for_test(P2PProtocolMode::AuthenticatedV6).await;
        let generation = net.generation();
        let identity = Arc::new(NodeIdentity::generate());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            let (_reader, mut writer) = sock.into_split();
            let mut pre = Vec::new();
            pre.extend_from_slice(&P2PNetwork::handshake_wire_magic());
            pre.push(P2P_PROTOCOL_VERSION_V6);
            writer.write_all(&pre).await.unwrap();
            writer.flush().await.unwrap();
            std::future::pending::<()>().await;
        });

        let (stream, peer_addr) = listener.accept().await.unwrap();
        // Emulate the optimistic insert the accept loop performs before the
        // session task, so the assertion below proves `handle_peer` removes it.
        let (ptx, _prx) = mpsc::unbounded_channel();
        net.peers.write().await.insert(peer_addr, ptx);

        let (msg_sender, msg_receiver) = mpsc::unbounded_channel();
        let (pdtx, _pdrx) = mpsc::unbounded_channel();
        let started = tokio::time::Instant::now();
        P2PNetwork::handle_peer(
            TransportStream::Tcp(stream),
            peer_addr,
            net.peers.clone(),
            net.config.listen_addr,
            net.addresses.clone(),
            net.tx_channel.clone(),
            net.get_dag_hashes.clone(),
            net.get_transaction_by_hash.clone(),
            net.get_tips.clone(),
            net.seen_transactions.clone(),
            net.propagation_state.clone(),
            msg_sender,
            msg_receiver,
            pdtx,
            net.sync_ctx.clone(),
            net.is_orphan.clone(),
            net.stake_hooks.clone(),
            net.config.network_id,
            P2PProtocolMode::AuthenticatedV6,
            Some(identity),
            false,
            net.session_auth.clone(),
            net.session_seq.clone(),
            generation,
            None,
            net.admission.clone(),
            Duration::from_millis(300),
        )
        .await;
        let elapsed = started.elapsed();

        assert!(elapsed >= Duration::from_millis(150), "must spend the budget");
        assert_eq!(net.session_auth_len().await, 0, "no session on budget expiry");
        assert_eq!(net.peer_count().await, 0, "no half-open peer after expiry");
        peer.abort();
    }

    /// The OUTBOUND (initiator) role under the same expiry: no session, no
    /// half-open peer, no dial/outbound residue left by the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_slow_v6_peer_expiry_leaves_no_outbound_session() {
        let net = cpw_net();
        net.open_cycle_for_test(P2PProtocolMode::AuthenticatedV6).await;
        let generation = net.generation();
        let identity = Arc::new(NodeIdentity::generate());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let remote = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (_reader, mut writer) = sock.into_split();
            let mut pre = Vec::new();
            pre.extend_from_slice(&P2PNetwork::handshake_wire_magic());
            pre.push(P2P_PROTOCOL_VERSION_V6);
            writer.write_all(&pre).await.unwrap();
            writer.flush().await.unwrap();
            std::future::pending::<()>().await;
        });

        let sock = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let peer_addr = sock.peer_addr().unwrap();
        let (ptx, _prx) = mpsc::unbounded_channel();
        net.peers.write().await.insert(peer_addr, ptx);

        let (msg_sender, msg_receiver) = mpsc::unbounded_channel();
        let (pdtx, _pdrx) = mpsc::unbounded_channel();
        let started = tokio::time::Instant::now();
        P2PNetwork::handle_peer(
            TransportStream::Tcp(sock),
            peer_addr,
            net.peers.clone(),
            net.config.listen_addr,
            net.addresses.clone(),
            net.tx_channel.clone(),
            net.get_dag_hashes.clone(),
            net.get_transaction_by_hash.clone(),
            net.get_tips.clone(),
            net.seen_transactions.clone(),
            net.propagation_state.clone(),
            msg_sender,
            msg_receiver,
            pdtx,
            net.sync_ctx.clone(),
            net.is_orphan.clone(),
            net.stake_hooks.clone(),
            net.config.network_id,
            P2PProtocolMode::AuthenticatedV6,
            Some(identity),
            true,
            net.session_auth.clone(),
            net.session_seq.clone(),
            generation,
            None,
            net.admission.clone(),
            Duration::from_millis(300),
        )
        .await;
        let elapsed = started.elapsed();

        assert!(elapsed >= Duration::from_millis(150), "must spend the budget");
        assert_eq!(net.session_auth_len().await, 0, "no outbound session on expiry");
        assert_eq!(net.peer_count().await, 0, "no half-open peer after expiry");
        remote.abort();
    }
}

#[cfg(test)]
mod phase4ak_peer_store_save_tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn net_at(path: std::path::PathBuf) -> P2PNetwork {
        let (tx, _rx) = mpsc::unbounded_channel();
        let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
        let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
        let sync_ctx = Arc::new(SyncContext::default());
        let is_orphan: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(|_| false);
        P2PNetwork::new(
            P2PConfig {
                listen_addr: addr("127.0.0.1:31001"),
                bootnodes: vec![],
                dns_seeds: vec![],
                peer_store_path: Some(path),
                network_id: crate::transaction::DEFAULT_NETWORK_ID,
            },
            tx,
            empty.clone(),
            empty_opt,
            empty,
            sync_ctx,
            is_orphan,
        )
    }

    fn read(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn no_staging_left(dir: &std::path::Path) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "leftover staging file: {name}");
        }
    }

    fn hook_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_peer_store_hook(hook: Option<Arc<dyn Fn(u64) + Send + Sync>>) {
        *PEER_STORE_TEST_HOOK.lock().unwrap_or_else(|e| e.into_inner()) = hook;
    }

    struct HookScope;
    impl Drop for HookScope {
        fn drop(&mut self) {
            set_peer_store_hook(None);
        }
    }

    /// A staging path is unique per save, a hidden sibling of the destination,
    /// and never the destination itself.
    #[test]
    fn staging_paths_are_unique_and_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let a = peer_store_staging_path(&path, 1);
        let b = peer_store_staging_path(&path, 2);
        let c = peer_store_staging_path(&path, 1);
        assert_ne!(a, path);
        assert_ne!(a, b);
        assert_ne!(a, c, "same generation, different save: still unique");
        assert_eq!(a.parent(), path.parent());
        let name = a.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with('.'), "staging is hidden: {name}");
        assert!(name.ends_with(".tmp"));
    }

    /// The staging file is created exclusively, so two saves can never truncate
    /// the same staging file, and it carries owner-only permissions on Unix.
    #[test]
    fn staging_write_is_exclusive_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path().join(".peers.tmp");
        write_private_file_new(&tmp, "first").unwrap();
        let err = write_private_file_new(&tmp, "second").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(read(&tmp), "first", "the first write is never truncated");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tmp).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "staging must be owner-only");
        }
    }

    /// Concurrent saves to one path: distinct staging files, the newest
    /// generation wins, and no staging file is left behind.
    #[test]
    fn concurrent_saves_keep_newest_and_never_share_a_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let n = 8usize;
        let gens: Vec<u64> = (0..n)
            .map(|_| PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1)
            .collect();
        let mut handles = Vec::new();
        for i in 0..n {
            let p = path.clone();
            let g = gens[i];
            let body = format!("{{\"save\":{}}}", i);
            handles.push(std::thread::spawn(move || {
                save_peer_store_blocking(&p, &body, g).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let winner = (0..n).max_by_key(|i| gens[*i]).unwrap();
        assert_eq!(read(&path), format!("{{\"save\":{}}}", winner));
        no_staging_left(dir.path());
    }

    /// AB-1 core: a save carrying an OLDER generation that runs AFTER a newer
    /// snapshot was published must be discarded, never allowed to replace it.
    /// This is the shape of a `spawn_blocking` survivor resuming after the
    /// `shutdown()` deadline expired.
    #[test]
    fn stale_generation_cannot_replace_a_newer_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let stale_gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        let new_gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        assert!(new_gen > stale_gen);

        save_peer_store_blocking(&path, "NEW", new_gen).unwrap();
        assert_eq!(read(&path), "NEW");

        save_peer_store_blocking(&path, "OLD", stale_gen).unwrap();
        assert_eq!(read(&path), "NEW", "stale save must not overwrite newer");
        no_staging_left(dir.path());
    }

    /// The same guarantee with the older write genuinely held before it takes
    /// the slot, then released after the newer save completed. Order is pinned
    /// with an internal test hook, so the assertion is deterministic.
    #[test]
    fn held_older_write_is_discarded_on_resume() {
        let _lock = hook_lock();
        let _scope = HookScope;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let old_gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        set_peer_store_hook(Some({
            let gate = gate.clone();
            Arc::new(move |g| {
                if g == old_gen {
                    parked_tx.send(()).unwrap();
                    let (m, cv) = &*gate;
                    let mut released = m.lock().unwrap_or_else(|e| e.into_inner());
                    while !*released {
                        released = cv.wait(released).unwrap_or_else(|e| e.into_inner());
                    }
                }
            })
        }));

        let p = path.clone();
        let survivor = std::thread::spawn(move || save_peer_store_blocking(&p, "OLD", old_gen));
        parked_rx.recv().unwrap();

        let new_gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        save_peer_store_blocking(&path, "NEW", new_gen).unwrap();
        assert_eq!(read(&path), "NEW");

        {
            let (m, cv) = &*gate;
            *m.lock().unwrap_or_else(|e| e.into_inner()) = true;
            cv.notify_all();
        }
        survivor.join().unwrap().unwrap();
        assert_eq!(read(&path), "NEW", "resumed older write must not win");
        no_staging_left(dir.path());
    }

    /// A fresh instance started after a timed-out shutdown shares the same slot
    /// as the survivor, so the new instance's snapshot survives the survivor
    /// resuming later. This models the restart / `P2PNetwork` boundary.
    #[tokio::test]
    async fn new_instance_snapshot_survives_older_survivor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");

        let stale_gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

        let net = net_at(path.clone());
        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(
                addr("203.0.113.77:25565"),
                PeerSource::Pex,
                1,
                Instant::now(),
            );
        }
        net.try_save_known_peers().await.unwrap();
        let after_new = read(&path);
        assert!(after_new.contains("203.0.113.77"));

        save_peer_store_blocking(&path, "OLD", stale_gen).unwrap();
        assert_eq!(read(&path), after_new, "older survivor must not win");
        no_staging_left(dir.path());
    }

    /// Two concurrent flushes through the async entry point settle on one valid
    /// document and leave no staging file behind.
    #[tokio::test]
    async fn concurrent_try_save_settles_on_one_valid_document() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        let net = net_at(path.clone());
        {
            let mut mgr = net.addresses.write().await;
            mgr.observe(
                addr("203.0.113.88:25565"),
                PeerSource::Pex,
                1,
                Instant::now(),
            );
        }
        let (a, b) = tokio::join!(net.try_save_known_peers(), net.try_save_known_peers());
        a.unwrap();
        b.unwrap();
        let file: PeerStoreFile = serde_json::from_str(&read(&path)).unwrap();
        assert_eq!(file.version, PEER_STORE_VERSION);
        assert_eq!(file.entries.len(), 1);
        no_staging_left(dir.path());
    }

    /// A publish failure is reported, and the staging file is cleaned up.
    #[test]
    fn failed_publish_is_reported_and_leaves_no_staging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        // A directory where the destination file should be makes `rename` fail.
        // The staging write itself succeeds, so this exercises the publish
        // error path and its cleanup.
        std::fs::create_dir(&path).unwrap();

        let gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        let err = save_peer_store_blocking(&path, "{}", gen).unwrap_err();
        assert!(err.contains("replace peer store"), "got: {err}");
        no_staging_left(dir.path());
    }

    /// A missing parent directory is created, not treated as a failure.
    #[test]
    fn missing_parent_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("known_peers.json");
        let gen = PEER_STORE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        save_peer_store_blocking(&path, "{}", gen).unwrap();
        assert_eq!(read(&path), "{}");
        no_staging_left(&dir.path().join("nested"));
    }
}
