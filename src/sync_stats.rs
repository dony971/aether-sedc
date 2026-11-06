//! # Sync bootstrap instrumentation + shared sync context
//!
//! PHASE B4: deterministic dependency-based bootstrap/sync. This module holds:
//!
//! - `SyncStats`: atomic counters for the bootstrap pipeline (exposed through
//!   `aether_getSyncStats` and periodic log lines). They prove the invariant
//!   `orphans up -> parents fetched -> orphans down -> DAG up -> convergence`.
//! - `SyncContext`: the state shared by the P2P task, the transaction receiver
//!   and the periodic maintenance loop:
//!   - `requested_parents`: per-hash (last request, attempt count) used to
//!     deduplicate parent re-requests with an escalating backoff. This kills
//!     the B4 livelock: previously every orphan re-requested its missing
//!     parents unconditionally, flooding the peer with 1-tx GetData responses
//!     that starved the real sync batches (16/s forever, DAG frozen).
//!   - `orphan_births`: orphan id -> creation instant, so stale orphans can be
//!     purged (TTL safety net) instead of accumulating forever.
//!
//! No consensus logic lives here: weights, VQV/min-id, pruning, ledger,
//! finality, parent selection and genesis are untouched.

use crate::validation::ValidationMode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// B4: a missing parent is re-requested at most once per cooldown (see
/// `PARENT_BACKOFF_STEPS`). Without this, every parked orphan re-requested its
/// parents unconditionally (2 requests per orphan, amplification forever).
pub const PARENT_REQUEST_COOLDOWN: Duration = Duration::from_secs(2);

/// B4: escalating backoff (seconds) per attempt count of a missing parent.
/// Attempt 1 -> 2s, 2 -> 5s, 3+ -> 15s. Bounded re-request rate.
pub const PARENT_BACKOFF_STEPS: [u64; 3] = [2, 5, 15];

/// B4: maximum distinct missing-parent hashes tracked for request dedup.
pub const MAX_INFLIGHT_PARENTS: usize = 4096;

/// B4: orphans older than this are purged (store + disk). They are re-fetched
/// by the periodic full sync when (and if) their parents arrive. Safety net
/// so the orphan store cannot fill with undeliverable junk over days.
pub const ORPHAN_TTL: Duration = Duration::from_secs(15 * 60);

/// B4: fixpoint resolution passes cap in `process_orphans`. One resolved
/// orphan unlocks its children in the SAME cycle; the loop is bounded so a
/// pathological store cannot stall the maintenance loop forever.
pub const ORPHAN_FIXPOINT_MAX_PASSES: usize = 64;

/// B4: above this DAG size the topological-order serving falls back to
/// timestamp order (cost guard; the topological walk is O(V+E) per call).
pub const TOPO_ORDER_CAP: usize = 50_000;

/// Snapshot of the bootstrap counters (JSON via `aether_getSyncStats`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncStatsSnapshot {
    /// SyncRequest/GetData requests we sent
    pub sync_requested: u64,
    /// Transactions received through SyncResponse (post-dedup)
    pub sync_received: u64,
    /// SyncResponse transactions successfully applied to the DAG
    pub sync_progress: u64,
    /// SyncResponse batches processed
    pub sync_batches: u64,
    /// Transactions parked as orphans
    pub orphan_created: u64,
    /// Orphans successfully re-processed (resolved)
    pub orphan_resolved: u64,
    /// Orphans purged after TTL
    pub orphan_purged: u64,
    /// Missing-parent GetData requests actually sent
    pub parent_requested: u64,
    /// Missing-parent requests skipped (already requested, in backoff)
    pub parent_already_known: u64,
    /// Transactions ignored by sync dedup (already in DAG or orphan store)
    pub duplicate_ignored: u64,
    /// Orphan re-processing attempts (retries)
    pub retry_count: u64,
    /// C2 (missing-winner diagnostics): total tx hashes ever advertised
    /// by peer Inventory messages. If a tx we lack is never advertised,
    /// the gap is on the SERVING side.
    pub inventory_advertised: u64,
    /// C2: advertised hashes skipped because already parked as orphans
    /// (is_orphan dedup). A stuck high count with zero resolutions means
    /// parents never arrive for the parked set: request-side stall.
    pub inventory_skipped_orphan: u64,
    /// C2: raw tx items inside received SyncResponse batches, BEFORE the
    /// DAG/orphan dedup. sync_received <= this number; a wide gap means
    /// peers keep re-sending what we already track (serving blind spot).
    pub sync_response_items: u64,
    /// VPS-2 §5: advertised hashes we actually lack (inventory diff size).
    /// Persistently high with flat sync_received = peers advertise but
    /// deliveries never arrive (serving/requesting stall, not emptiness).
    pub inventory_missing: u64,
    /// VPS-2 §5: missing-parent sets collected per orphan-solver cycle
    /// (before backoff dedup). Compares against parent_requested (sent).
    pub parent_missing: u64,
    /// VPS-2 §6: monotone sync frontier = max DAG total observed after a
    /// SyncResponse transaction was really applied. progress(t+1) >=
    /// progress(t) BY CONSTRUCTION (max-update); a flat frontier alongside
    /// pending requests = stall evidence.
    pub sync_frontier: u64,
    /// INC-01: persisted transactions loaded at boot (Sled + JSON)
    pub rebuild_total: u64,
    /// INC-01: boot rebuild - transactions inserted into the DAG
    pub rebuild_inserted: u64,
    /// INC-01: boot rebuild - transactions skipped (with explicit reason logged)
    pub rebuild_skipped: u64,
    /// INC-01: boot rebuild - transactions left orphaned (parents missing from local store)
    pub rebuild_orphaned: u64,
    /// INC-01: boot rebuild - elapsed milliseconds
    pub rebuild_duration_ms: u64,
    /// INC-01: times the orphan solver found a missing parent in the local store
    pub store_hits: u64,
    /// INC-01: times the orphan solver looked for a missing parent in the local store and missed
    pub store_misses: u64,
    /// INC-01: GetData responses served from the local store
    pub getdata_local: u64,
    /// INC-01: GetData responses served from memory (DAG/mempool)
    pub getdata_remote: u64,
    /// INC-01: orphans resolved with parents found in the local store
    pub orphan_resolved_local: u64,
    /// INC-01: orphans resolved with parents fetched over P2P
    pub orphan_resolved_remote: u64,
    /// INC-01: crash/wal recovery events handled at boot
    pub wal_recovery: u64,
    /// C2-004: GetData serving order taken from the topo cache (no re-sort)
    pub topo_cache_hits: u64,
    /// C2-004: GetData serving order recomputed (cache empty/stale/capped)
    pub topo_cache_miss: u64,
    /// 4CP-BN: SyncResponse pages whose bounded emission expired before the
    /// per-session writer accepted them. Counted once per request that could
    /// not be fully emitted; the request is refused as a whole (the peer
    /// re-requests via the frontier). Distinct from `session_drops`, which
    /// also counts pre-emission refusals at the bounded serve-job queue.
    pub sync_response_timeouts: u64,
    /// 4CP-BX v2: inventory hashes NOT requested because this node had already
    /// admitted them and the drainer had not taken them yet. Each one is a
    /// duplicate admission avoided upstream (the ingress keeps delivering
    /// every copy; the funnel stays the single deduplicator).
    pub inventory_skipped_inflight: u64,
    /// 4CP-BX v2.1 (M1): inventory hashes skipped because a GetData for them is
    /// already outstanding and still inside its serving window.
    pub inventory_skipped_requested: u64,
    /// 4CP-BX v2.2 (R1): inventory hashes skipped because the node's own
    /// pipeline still holds them (drained from ingress, not yet applied).
    /// Nothing is lost: the delivery in flight is the original one.
    pub inventory_skipped_pipeline: u64,
    /// 4CP-BX v2.5 (P2): inventory hashes skipped because ANOTHER session
    /// already holds a live claim on them — the arbitration worked.
    pub inventory_skipped_claim_held: u64,
    /// 4CP-BX v2.5 (P2): inventory hashes skipped because the claim table was
    /// FULL of live claims. A capacity signal, not an arbitration loss.
    pub inventory_skipped_claim_capacity: u64,
    /// 4CP-BX v2.3: ingress→funnel handoffs started (total).
    pub ingress_handoffs: u64,
    /// 4CP-BX v2.3: handoffs currently open. Non-zero means a transaction has
    /// left the ingress channel but has not reached the funnel yet — the exact
    /// instant a redundant `GetData` could otherwise be emitted.
    pub ingress_handoffs_active: u64,
}

/// Atomic bootstrap counters.
#[derive(Debug, Default)]
pub struct SyncStats {
    pub sync_requested: AtomicU64,
    pub sync_received: AtomicU64,
    pub sync_progress: AtomicU64,
    pub sync_batches: AtomicU64,
    pub orphan_created: AtomicU64,
    pub orphan_resolved: AtomicU64,
    pub orphan_purged: AtomicU64,
    pub parent_requested: AtomicU64,
    pub parent_already_known: AtomicU64,
    pub duplicate_ignored: AtomicU64,
    pub retry_count: AtomicU64,
    pub inventory_advertised: AtomicU64,
    pub inventory_skipped_orphan: AtomicU64,
    pub sync_response_items: AtomicU64,
    pub inventory_missing: AtomicU64,
    pub parent_missing: AtomicU64,
    pub sync_frontier: AtomicU64,
    pub rebuild_total: AtomicU64,
    pub rebuild_inserted: AtomicU64,
    pub rebuild_skipped: AtomicU64,
    pub rebuild_orphaned: AtomicU64,
    pub rebuild_duration_ms: AtomicU64,
    pub store_hits: AtomicU64,
    pub store_misses: AtomicU64,
    pub getdata_local: AtomicU64,
    pub getdata_remote: AtomicU64,
    pub orphan_resolved_local: AtomicU64,
    pub orphan_resolved_remote: AtomicU64,
    pub wal_recovery: AtomicU64,
    pub topo_cache_hits: AtomicU64,
    pub topo_cache_miss: AtomicU64,
    /// 4CP-BN: SyncResponse emission expirations (one per refused request).
    pub sync_response_timeouts: AtomicU64,
    /// 4CP-BX v2: inventory hashes skipped because they are already admitted
    /// and still in flight (see `SyncContext::ingress_mode`).
    pub inventory_skipped_inflight: AtomicU64,
    /// 4CP-BX v2.1 (M1): see `SyncStatsSnapshot::inventory_skipped_requested`.
    pub inventory_skipped_requested: AtomicU64,
    /// 4CP-BX v2.2 (R1): see `SyncStatsSnapshot::inventory_skipped_pipeline`.
    pub inventory_skipped_pipeline: AtomicU64,
    /// 4CP-BX v2.5 (P2): see `SyncStatsSnapshot::inventory_skipped_claim_held`.
    pub inventory_skipped_claim_held: AtomicU64,
    /// 4CP-BX v2.5 (P2): see `SyncStatsSnapshot::inventory_skipped_claim_capacity`.
    pub inventory_skipped_claim_capacity: AtomicU64,
    /// 4CP-BX v2.3: see `SyncStatsSnapshot::ingress_handoffs`.
    pub ingress_handoffs: AtomicU64,
    /// 4CP-BX v2.3: see `SyncStatsSnapshot::ingress_handoffs_active`.
    pub ingress_handoffs_active: AtomicU64,
}

impl SyncStats {
    pub fn snapshot(&self) -> SyncStatsSnapshot {
        SyncStatsSnapshot {
            sync_requested: self.sync_requested.load(Ordering::Relaxed),
            sync_received: self.sync_received.load(Ordering::Relaxed),
            sync_progress: self.sync_progress.load(Ordering::Relaxed),
            sync_batches: self.sync_batches.load(Ordering::Relaxed),
            orphan_created: self.orphan_created.load(Ordering::Relaxed),
            orphan_resolved: self.orphan_resolved.load(Ordering::Relaxed),
            orphan_purged: self.orphan_purged.load(Ordering::Relaxed),
            parent_requested: self.parent_requested.load(Ordering::Relaxed),
            parent_already_known: self.parent_already_known.load(Ordering::Relaxed),
            duplicate_ignored: self.duplicate_ignored.load(Ordering::Relaxed),
            retry_count: self.retry_count.load(Ordering::Relaxed),
            inventory_advertised: self.inventory_advertised.load(Ordering::Relaxed),
            inventory_skipped_orphan: self.inventory_skipped_orphan.load(Ordering::Relaxed),
            sync_response_items: self.sync_response_items.load(Ordering::Relaxed),
            inventory_missing: self.inventory_missing.load(Ordering::Relaxed),
            parent_missing: self.parent_missing.load(Ordering::Relaxed),
            sync_frontier: self.sync_frontier.load(Ordering::Relaxed),
            rebuild_total: self.rebuild_total.load(Ordering::Relaxed),
            rebuild_inserted: self.rebuild_inserted.load(Ordering::Relaxed),
            rebuild_skipped: self.rebuild_skipped.load(Ordering::Relaxed),
            rebuild_orphaned: self.rebuild_orphaned.load(Ordering::Relaxed),
            rebuild_duration_ms: self.rebuild_duration_ms.load(Ordering::Relaxed),
            store_hits: self.store_hits.load(Ordering::Relaxed),
            store_misses: self.store_misses.load(Ordering::Relaxed),
            getdata_local: self.getdata_local.load(Ordering::Relaxed),
            getdata_remote: self.getdata_remote.load(Ordering::Relaxed),
            orphan_resolved_local: self.orphan_resolved_local.load(Ordering::Relaxed),
            orphan_resolved_remote: self.orphan_resolved_remote.load(Ordering::Relaxed),
            wal_recovery: self.wal_recovery.load(Ordering::Relaxed),
            topo_cache_hits: self.topo_cache_hits.load(Ordering::Relaxed),
            topo_cache_miss: self.topo_cache_miss.load(Ordering::Relaxed),
            sync_response_timeouts: self.sync_response_timeouts.load(Ordering::Relaxed),
            inventory_skipped_inflight: self.inventory_skipped_inflight.load(Ordering::Relaxed),
            inventory_skipped_requested: self.inventory_skipped_requested.load(Ordering::Relaxed),
            inventory_skipped_pipeline: self.inventory_skipped_pipeline.load(Ordering::Relaxed),
            inventory_skipped_claim_held: self.inventory_skipped_claim_held.load(Ordering::Relaxed),
            inventory_skipped_claim_capacity: self
                .inventory_skipped_claim_capacity
                .load(Ordering::Relaxed),
            ingress_handoffs: self.ingress_handoffs.load(Ordering::Relaxed),
            ingress_handoffs_active: self.ingress_handoffs_active.load(Ordering::Relaxed),
        }
    }

    /// 4CP-BX v2.4 (R3): close ONE live handoff entry.
    ///
    /// The gauge is maintained by removal, not by call pairing: an entry marked
    /// `handoff` is counted once when it is inserted and uncounted once when it
    /// is removed, under the registry lock. A double release therefore cannot
    /// reach this function (the entry is already gone, so the token no longer
    /// matches and the caller returns `false`), and a foreign token cannot
    /// reach it either. `saturating_sub` plus the debug assertion is a belt for
    /// a future regression: the gauge can no longer wrap to `u64::MAX`, and any
    /// drift is loud in tests.
    #[inline]
    fn close_handoff(&self) {
        let previous = self
            .ingress_handoffs_active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .unwrap_or(0);
        debug_assert!(previous > 0, "ingress_handoffs_active underflow");
    }
}

/// 4CP-BX v2.2 (R1): snapshot of the ids the node's own pipeline still holds —
/// queued or selected in the funnel, not yet applied, not yet disposed.
///
/// A closure rather than a direct `Mempool` handle: the mempool lives behind
/// `AetherRpcImpl` in `rpc.rs`, which already depends on `p2p.rs`; handing P2P
/// the concrete type would close a module cycle, and widening the P2P
/// constructors would touch every harness in the tree. The optional oracle is
/// installed by the node on the shared `SyncContext`, so harnesses that drive
/// P2P without a funnel simply leave it `None` and keep the previous behaviour.
pub type PipelineSnapshotFn =
    Arc<dyn Fn() -> crate::transport::BoxFuture<'static, Vec<[u8; 32]>> + Send + Sync>;

/// 4CP-BX v2.3: one ingress reservation.
///
/// `token` identifies the WRITER that created it. Two deliveries of the same
/// transaction can both be in the ingress at once, and the handoff between the
/// drainer and the funnel briefly re-reserves an id that was already consumed —
/// so "this entry exists" is not the same question as "this entry is mine".
/// A release compares the token and leaves any other writer's reservation in
/// place, which is what keeps a queued delivery's provenance from being erased
/// by the handoff of a different copy.
#[derive(Debug, Clone, Copy)]
pub struct IngressReservation {
    /// Validation policy recorded at first delivery (first-delivery-wins).
    pub mode: ValidationMode,
    /// Instant the reservation was taken (oldest-first eviction key, and the
    /// lease reference point for a handoff).
    pub at: Instant,
    /// Writer identity for conditional release. Opaque; compare for equality.
    pub token: u64,
    /// 4CP-BX v2.4 (R3): was this entry created by `begin_ingress_handoff`?
    /// Only handoff entries own a unit of `ingress_handoffs_active`, so the
    /// gauge is tightened to "live handoff entries" and no caller can move it
    /// by releasing something it does not own.
    pub handoff: bool,
}

impl IngressReservation {
    /// 4CP-BX v2.4 (R2): may this entry still suppress an `Inventory` request?
    ///
    /// A QUEUED entry (not a handoff) is owned by a channel that is bounded and
    /// drained, so it suppresses until the drainer takes it — no timer needed.
    ///
    /// A HANDOFF entry is held across the funnel call by a task that can panic
    /// or be cancelled; because a `Drop` cannot await the registry lock, a
    /// leaked handoff entry would otherwise suppress the id for the lifetime of
    /// the process and the node would never re-request a transaction it does
    /// not actually have. The handoff is therefore a LEASE: past
    /// `INGRESS_HANDOFF_LEASE` the entry stops suppressing, so a lost release
    /// costs at most one redundant request race window, never liveness. The
    /// lease is far longer than any real funnel call (verification plus
    /// persistence is milliseconds), so the nominal path keeps full suppression.
    pub fn suppresses_inventory(&self, now: Instant) -> bool {
        !self.handoff || now.saturating_duration_since(self.at) < INGRESS_HANDOFF_LEASE
    }
}

/// 4CP-BX v2.4 (R2): how long a handoff may suppress an `Inventory` request.
/// Twice the serving window (`SYNC_RESPONSE_PAGE_TIMEOUT`): long enough that a
/// real funnel call always keeps the id hidden, short enough that an
/// interrupted handoff self-heals instead of pinning the id forever.
pub const INGRESS_HANDOFF_LEASE: Duration = Duration::from_secs(60);

/// 4CP-BX v2.3: source of reservation tokens. Monotonic and process-wide; a
/// token is only ever compared for equality with the reservation it created.
static NEXT_INGRESS_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Oldest-first eviction once the map reaches its cap. Same policy as before:
/// self-healing, because an evicted id simply re-records on the next delivery.
fn evict_oldest_ingress(map: &mut HashMap<[u8; 32], IngressReservation>, stats: &SyncStats) {
    if map.len() < MAX_INGRESS_MODE_ENTRIES {
        return;
    }
    if let Some(oldest) = map.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| *k) {
        // 4CP-BX v2.4 (R3): the gauge counts LIVE handoff entries, so whoever
        // removes one closes it. Eviction is a removal like any other.
        if map.remove(&oldest).map(|e| e.handoff).unwrap_or(false) {
            stats.close_handoff();
        }
    }
}

/// Shared bootstrap/sync state (one instance per node).
#[derive(Clone, Default)]
pub struct SyncContext {
    pub stats: Arc<SyncStats>,
    /// missing-parent hash -> (last request, attempt count)
    pub requested_parents: Arc<RwLock<HashMap<Vec<u8>, (Instant, u32)>>>,
    /// orphan id -> creation instant (TTL)
    pub orphan_births: Arc<RwLock<HashMap<[u8; 32], Instant>>>,
    /// INC-01: parent hashes delivered from the local store by the orphan
    /// solver (classifies orphan resolutions local vs remote).
    pub store_sourced_parents: Arc<RwLock<HashSet<Vec<u8>>>>,
    /// C2-004: cached topological serving order, keyed by DAG length.
    /// Recomputing Kahn's sort over the whole DAG for EVERY GetData
    /// collapsed serving nodes at ~10k txs (measured +34M hash lookups
    /// in 60 s). The order is a SERVING HINT ONLY, never consensus: a
    /// stale entry (e.g. same length after a prune+add) merely batches
    /// less optimally, never wrong data.
    pub topo_cache: Arc<RwLock<Option<(u64, Vec<Vec<u8>>)>>>,
    /// DEEP SYNC: monotone frontier tracker for sync progress.
    pub frontier: Arc<RwLock<SyncFrontier>>,
    // NOTE (4CP-BX v2): `ingress_mode` below is ALSO the in-flight admission
    // registry used by the Inventory diff. 4CP-BX v2.1 reserves the entry just
    // BEFORE the enqueue and cancels it if the admission is refused, so it
    // holds exactly "admitted, not yet applied" — the window BX counts as a
    // duplicate — with no race against the drainer. No second registry.
    /// PHASE 3B (C1/H1): ingress provenance for validation-mode selection.
    /// tx id -> (mode recorded at first delivery, record instant). Written by
    /// the P2P ingress (live relay = Fresh, sync backfill = Historical;
    /// first-delivery-wins), consumed (take) by the node P2P receiver, which
    /// forwards the mode to process_transaction so the WHOLE pipeline (accept
    /// gate, drainer, STEP 0, STEP 1) evaluates one tx under ONE policy.
    /// Absent = Historical (timeless evaluation = pre-3B behavior; every live
    /// path records explicitly).
    pub ingress_mode: Arc<RwLock<HashMap<[u8; 32], IngressReservation>>>,
    /// 4CP-BX v2.2 (R1): what the node's funnel still holds. Consulted by the
    /// Inventory diff AFTER `ingress_mode`, to close the window between the
    /// drainer taking the provenance and the transaction being applied: in that
    /// window the id is in no other store, so the node would ask a peer for the
    /// very bytes it is already processing. Installed by the node from its
    /// mempool (`Mempool::held_ids`); `None` in harnesses without a funnel.
    pub pipeline_holds: Arc<RwLock<Option<PipelineSnapshotFn>>>,
}

impl SyncContext {
    /// 4CP-BX v2.2 (R1): install the pipeline-liveness oracle.
    ///
    /// It only ever suppresses a REQUEST. Every delivery is still admitted and
    /// the funnel stays the single deduplicator. A transaction the funnel
    /// refused never enters the snapshot, and a disposed one leaves it at once,
    /// so the retry path re-opens by itself — no timer and nothing to expire.
    pub async fn set_pipeline_holds(&self, oracle: PipelineSnapshotFn) {
        *self.pipeline_holds.write().await = Some(oracle);
    }

    /// 4CP-BX v2.2 (R1): is an oracle installed? (diagnostics / tests)
    pub async fn has_pipeline_holds(&self) -> bool {
        self.pipeline_holds.read().await.is_some()
    }
}

/// DEEP SYNC: maximum in-flight requests at any time.
pub const MAX_INFLIGHT_REQUESTS: usize = 64;

/// DEEP SYNC: maximum hashes tracked in the frontier (pending + resolved + applied).
pub const MAX_FRONTIER_ENTRIES: usize = 100_000;

/// DEEP SYNC: stall detection threshold — no progress for this duration → STALLED.
pub const STALL_THRESHOLD: Duration = Duration::from_secs(30);

/// DEEP SYNC: maximum retry attempts per hash before marking as FAILED.
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

/// PHASE 3B (C1/H1): bound for the ingress-provenance map (mirrors the
/// frontier bound style). Steady-state size tracks the in-flight channel
/// depth: every insert pairs with a channel send and every send with a take.
pub const MAX_INGRESS_MODE_ENTRIES: usize = 100_000;

// ===== Frontier types =====

/// Page/transaction state in the sync pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PageState {
    /// Hash is pending (known needed, not yet requested).
    Pending,
    /// GetData request sent, awaiting SyncResponse.
    Requested,
    /// SyncResponse received, being validated/inserted.
    Received,
    /// Successfully inserted into the DAG.
    Applied,
    /// Validation failed or peer returned bad data.
    Rejected,
}

/// Overall frontier sync state (stall detection machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FrontierSyncState {
    /// DAG is growing / frontier is advancing.
    #[default]
    Progressing,
    /// Requests in flight, awaiting responses.
    Waiting,
    /// No real progress for STALL_THRESHOLD.
    Stalled,
    /// Peer(s) available but no valid data received.
    Failed,
}

/// A single in-flight request to a peer.
#[derive(Debug, Clone)]
pub struct InflightRequest {
    pub hash: Vec<u8>,
    pub peer: SocketAddr,
    pub requested_at: Instant,
    pub attempt: u32,
}

/// A single entry in the frontier (tracked hash).
#[derive(Debug, Clone)]
pub struct FrontierEntry {
    pub hash: Vec<u8>,
    pub state: PageState,
    pub first_seen: Instant,
    pub last_updated: Instant,
    pub peer: Option<SocketAddr>,
}

/// Read-only snapshot of the frontier for logging/RPC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrontierSnapshot {
    pub pending: u64,
    pub inflight: u64,
    pub resolved: u64,
    pub applied: u64,
    pub rejected: u64,
    pub pages_requested: u64,
    pub pages_received: u64,
    pub pages_applied: u64,
    pub pages_rejected: u64,
    pub last_progress_secs_ago: Option<f64>,
    pub state: FrontierSyncState,
    pub stall_count: u64,
    pub total_tracked: u64,
}

/// Monotone sync frontier tracker.
///
/// Guarantees:
/// - Hash state transitions are monotone: Pending → Requested → Received → Applied
///   (or Rejected from Requested/Received).
/// - A hash never moves backwards (e.g. Applied → Pending).
/// - Inflight count never exceeds MAX_INFLIGHT_REQUESTS.
/// - Total tracked entries never exceed MAX_FRONTIER_ENTRIES.
/// - Progress timestamp advances only on real DAG growth events.
pub struct SyncFrontier {
    pending: VecDeque<Vec<u8>>,
    inflight: HashMap<Vec<u8>, InflightRequest>,
    entries: HashMap<Vec<u8>, FrontierEntry>,
    /// 4CP-BX v2.4 (R1): hashes this node has ALREADY asked a peer for, with
    /// the instant the request was claimed.
    ///
    /// `inflight` cannot carry this role. It is a state-machine record capped at
    /// `MAX_INFLIGHT_REQUESTS` (64) by design, while ONE `GetData` frame carries
    /// up to `MAX_INV_ITEMS` (1000) hashes: past the 64th hash of a batch there
    /// is no `inflight` record at all, so a second session (or the next round)
    /// saw those hashes as requestable and asked again — the funnel then counted
    /// the extra copies as duplicates. `claims` is the authoritative
    /// "asked recently" set: bounded by `MAX_FRONTIER_ENTRIES`, expired by the
    /// same horizon as `inflight`, and cleared on every terminal transition.
    claims: HashMap<Vec<u8>, Instant>,
    /// 4CP-BX v2.5 (R1): how many times the expired-claim sweep actually ran.
    /// Diagnostic for the "one sweep per frame" contract: the P2P Inventory
    /// path sweeps at most once per frame, and only when the table is full.
    claim_sweeps: u64,
    pages_requested: u64,
    pages_received: u64,
    pages_applied: u64,
    pages_rejected: u64,
    last_progress: Option<Instant>,
    sync_state: FrontierSyncState,
    stall_count: u64,
    started_at: Instant,
}

/// 4CP-BX v2.5 (P2): why a `claim_request` did or did not take the claim.
///
/// `claim_request` keeps its `bool` contract for every existing caller and
/// test; the P2P Inventory path uses this richer form so the two ways of
/// losing a claim are counted apart — `Held` means another session won the
/// arbitration, `Capacity` means the table was full of LIVE claims (a capacity
/// signal, not an arbitration loss).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// This caller owns the claim and must put the hash on the wire.
    Claimed,
    /// Another caller claimed it inside the horizon: do NOT ask again.
    Held,
    /// The table is full of live claims: the hash was not claimed.
    Capacity,
}

impl SyncFrontier {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            inflight: HashMap::new(),
            entries: HashMap::new(),
            claims: HashMap::new(),
            claim_sweeps: 0,
            pages_requested: 0,
            pages_received: 0,
            pages_applied: 0,
            pages_rejected: 0,
            last_progress: None,
            sync_state: FrontierSyncState::Progressing,
            stall_count: 0,
            started_at: Instant::now(),
        }
    }

    /// Add a hash to the frontier as pending.
    /// Returns false if the hash is already tracked or the frontier is full.
    pub fn add_pending(&mut self, hash: Vec<u8>) -> bool {
        if self.entries.contains_key(&hash) {
            return false; // duplicate suppression
        }
        if self.total_tracked() >= MAX_FRONTIER_ENTRIES {
            return false; // frontier full → backpressure
        }
        let now = Instant::now();
        self.entries.insert(
            hash.clone(),
            FrontierEntry {
                hash: hash.clone(),
                state: PageState::Pending,
                first_seen: now,
                last_updated: now,
                peer: None,
            },
        );
        self.pending.push_back(hash);
        true
    }

    /// 4CP-BX v2.1 (M1): is a GetData for this hash still outstanding and
    /// recent? `Requested` inside `horizon` means the peer is still inside its
    /// own serving window, so asking again would fetch the same bytes twice and
    /// the funnel would count the second copy as a duplicate. Past the horizon
    /// the request is treated as lost and becomes requestable again (see
    /// `rearm_expired`), so a dropped response never blocks the hash forever.
    pub fn request_is_fresh(&self, hash: &[u8], horizon: Duration) -> bool {
        match self.entries.get(hash) {
            Some(entry) if entry.state == PageState::Requested => {
                // A `Requested` entry always has an inflight record
                // (`mark_requested` writes both). Treat a missing record as
                // expired rather than fresh: liveness beats suppression.
                self.inflight
                    .get(hash)
                    .map(|req| req.requested_at.elapsed() < horizon)
                    .unwrap_or(false)
            }
            _ => false,
        }
    }

    /// 4CP-BX v2.1 (M1): snapshot of the hashes whose GetData is outstanding
    /// and still inside `horizon`. Bounded by `MAX_INFLIGHT_REQUESTS`, so the
    /// caller can hold it without any further locking.
    pub fn fresh_requests(&self, horizon: Duration) -> Vec<[u8; 32]> {
        self.inflight
            .keys()
            .filter(|hash| self.request_is_fresh(hash, horizon))
            .filter_map(|hash| <[u8; 32]>::try_from(hash.as_slice()).ok())
            .collect()
    }

    /// 4CP-BX v2.4 (R1): claim the request for `hash` — "I am about to emit a
    /// GetData for it" — atomically, so two sessions cannot both ask.
    ///
    /// Returns `true` when this caller owns the claim. `false` means another
    /// caller claimed it inside `horizon`, or the claim table is full; either
    /// way the hash must NOT be put on the wire now. The claim expires on its
    /// own after `horizon`, so a lost or refused frame never pins a hash.
    ///
    /// This is deliberately independent of the state machine: `mark_requested`
    /// stops recording past `MAX_INFLIGHT_REQUESTS`, and refusing to request
    /// hash 65 of a 1000-hash batch would stall bootstrap. The claim table has
    /// the frontier's own bound instead.
    pub fn claim_request(&mut self, hash: &[u8], horizon: Duration) -> bool {
        matches!(
            self.claim_request_detailed(hash, horizon),
            ClaimOutcome::Claimed
        )
    }

    /// 4CP-BX v2.5 (P1): claim `hash`, reporting WHY it was refused.
    ///
    /// v2.4 swept the whole table HERE, on every call, once the table was full:
    /// with 100 000 live claims and 1 000 hashes per frame that is a
    /// 10^8-operation stall INSIDE the frontier write guard (measured on the
    /// v2.4 tree: 476 ms for one frame at the cap, versus 133 us below it).
    /// The sweep is now a caller concern — the P2P Inventory path calls
    /// [`Self::sweep_expired_claims`] at most ONCE per frame, and only when the
    /// table is actually at capacity — so this function stays O(1).
    ///
    /// Refusing at capacity is deliberate and unchanged: a LIVE claim is never
    /// evicted to make room. The hash stays `Pending` in the frontier and the
    /// next advertised round claims it, because claims expire after `horizon`.
    pub fn claim_request_detailed(&mut self, hash: &[u8], horizon: Duration) -> ClaimOutcome {
        let now = Instant::now();
        if let Some(at) = self.claims.get(hash) {
            if now.saturating_duration_since(*at) < horizon {
                return ClaimOutcome::Held;
            }
        }
        if self.claims.len() >= MAX_FRONTIER_ENTRIES {
            return ClaimOutcome::Capacity;
        }
        self.claims.insert(hash.to_vec(), now);
        ClaimOutcome::Claimed
    }

    /// 4CP-BX v2.5 (P1): drop every EXPIRED claim, once, for a whole frame.
    ///
    /// Returns the number of claims released. The caller invokes this at most
    /// once per frame and only when [`Self::claim_table_at_capacity`] is true,
    /// which is the only moment expired entries can block a live claim: below
    /// the cap a new claim always has room, and a stale hash is already
    /// re-claimable per hash (it overwrites its own entry).
    ///
    /// Expired claims are released, NEVER live ones — capacity pressure must
    /// not cost a session the claim it is about to use.
    pub fn sweep_expired_claims(&mut self, now: Instant, horizon: Duration) -> usize {
        self.claim_sweeps = self.claim_sweeps.saturating_add(1);
        if self.claims.is_empty() {
            return 0;
        }
        let before = self.claims.len();
        self.claims
            .retain(|_, at| now.saturating_duration_since(*at) < horizon);
        before - self.claims.len()
    }

    /// 4CP-BX v2.5 (P1): is the claim table at its cap (so a sweep can matter)?
    #[inline]
    pub fn claim_table_at_capacity(&self) -> bool {
        self.claims.len() >= MAX_FRONTIER_ENTRIES
    }

    /// 4CP-BX v2.5 (P1): how many expired-claim sweeps have run (diagnostics).
    #[inline]
    pub fn claim_sweeps(&self) -> u64 {
        self.claim_sweeps
    }

    /// 4CP-BX v2.4 (R1): give a claim back because no frame was emitted
    /// (refused by the session/global budget, or not serializable). The hash is
    /// immediately requestable again instead of waiting out the horizon.
    pub fn release_claim(&mut self, hash: &[u8]) -> bool {
        self.claims.remove(hash).is_some()
    }

    /// 4CP-BX v2.4: number of live claims (diagnostics and tests).
    pub fn claimed_requests(&self) -> usize {
        self.claims.len()
    }

    /// 4CP-BX v2.1 (M1): re-arm an EXPIRED outstanding request so the next
    /// inventory round can ask for it again — the retry path for a response
    /// that never came while the session stayed up (`on_peer_disconnect`
    /// covers the session-loss case). No-op unless the entry is `Requested` and
    /// past `horizon`.
    pub fn rearm_expired(&mut self, hash: &[u8], horizon: Duration) -> bool {
        let stale = match self.entries.get(hash) {
            Some(entry) if entry.state == PageState::Requested => {
                !self.request_is_fresh(hash, horizon)
            }
            _ => return false,
        };
        if !stale {
            return false;
        }
        self.inflight.remove(hash);
        // 4CP-BX v2.4 (R1): the claim follows the REQUEST, so the retry path
        // releases it here. `rearm_expired` is the frontier's own "that request
        // is over" transition; leaving the claim behind would suppress the
        // retry for the rest of the horizon.
        self.claims.remove(hash);
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.state = PageState::Pending;
            entry.last_updated = Instant::now();
            entry.peer = None;
        }
        if !self.pending.iter().any(|h| h.as_slice() == hash) {
            self.pending.push_back(hash.to_vec());
        }
        true
    }

    /// Move a hash from pending to in-flight (request sent to peer).
    /// Returns false if the hash is not pending, already in-flight, or inflight is full.
    pub fn mark_requested(&mut self, hash: &[u8], peer: SocketAddr) -> bool {
        if self.inflight.len() >= MAX_INFLIGHT_REQUESTS {
            return false; // inflight cap
        }
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state != PageState::Pending {
            return false; // monotone guard
        }
        let now = Instant::now();
        entry.state = PageState::Requested;
        entry.last_updated = now;
        entry.peer = Some(peer);
        // Remove from pending queue
        if let Some(pos) = self.pending.iter().position(|h| h.as_slice() == hash) {
            self.pending.remove(pos);
        }
        self.inflight.insert(
            hash.to_vec(),
            InflightRequest {
                hash: hash.to_vec(),
                peer,
                requested_at: now,
                attempt: 1,
            },
        );
        self.pages_requested += 1;
        true
    }

    /// Mark an in-flight request as received (SyncResponse arrived).
    pub fn mark_received(&mut self, hash: &[u8]) -> bool {
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state != PageState::Requested {
            return false; // monotone guard
        }
        entry.state = PageState::Received;
        entry.last_updated = Instant::now();
        self.inflight.remove(hash);
        self.pages_received += 1;
        true
    }

    pub fn mark_received_external(&mut self, hash: &[u8]) -> bool {
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state != PageState::Pending && entry.state != PageState::Requested {
            return false;
        }
        entry.state = PageState::Received;
        entry.last_updated = Instant::now();
        entry.peer = None;
        self.inflight.remove(hash);
        if let Some(pos) = self.pending.iter().position(|h| h.as_slice() == hash) {
            self.pending.remove(pos);
        }
        true
    }

    /// Mark a received hash as applied (inserted into DAG). This is the terminal
    /// success state — the hash is now resolved and will never be re-requested.
    pub fn mark_applied(&mut self, hash: &[u8]) -> bool {
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state != PageState::Received {
            return false; // monotone guard: only Received → Applied
        }
        let now = Instant::now();
        entry.state = PageState::Applied;
        entry.last_updated = now;
        // 4CP-BX v2.4 (R1): terminal — the hash is in the DAG, so the request
        // claim has done its job and must not outlive it.
        self.claims.remove(hash);
        self.last_progress = Some(now);
        self.sync_state = FrontierSyncState::Progressing;
        self.pages_applied += 1;
        true
    }

    /// Mark a received hash as already resident in the DAG (a duplicate
    /// response). The terminal state is true, but no new DAG growth happened,
    /// so the progress timestamp is deliberately not advanced.
    pub fn mark_applied_existing(&mut self, hash: &[u8]) -> bool {
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state != PageState::Received {
            return false;
        }
        entry.state = PageState::Applied;
        entry.last_updated = Instant::now();
        // 4CP-BX v2.4 (R1): terminal (already resident in the DAG).
        self.claims.remove(hash);
        self.pages_applied += 1;
        true
    }

    /// Mark a request as rejected (bad data, peer error, timeout).
    /// The hash goes back to Pending if retries remain, otherwise stays Rejected.
    pub fn mark_rejected(&mut self, hash: &[u8]) -> bool {
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state == PageState::Applied || entry.state == PageState::Rejected {
            return false;
        }
        entry.state = PageState::Rejected;
        entry.last_updated = Instant::now();
        self.inflight.remove(hash);
        // 4CP-BX v2.4 (R1): a rejected hash is not re-requested by this node
        // (a retry, if any, goes through `requeue`), so the claim is dropped.
        self.claims.remove(hash);
        self.pages_rejected += 1;
        true
    }

    /// Re-queue a rejected/failed hash back to pending for retry with another peer.
    pub fn requeue(&mut self, hash: &[u8]) -> bool {
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.state != PageState::Rejected {
            return false;
        }
        let now = Instant::now();
        entry.state = PageState::Pending;
        entry.last_updated = now;
        entry.peer = None;
        self.pending.push_back(hash.to_vec());
        true
    }

    /// Notify frontier of a real progress event (tx inserted into DAG).
    /// Advances the monotone progress timestamp.
    pub fn record_progress(&mut self) {
        let now = Instant::now();
        self.last_progress = Some(now);
        self.sync_state = FrontierSyncState::Progressing;
    }

    /// Evict the oldest applied entries beyond a keep count to bound memory.
    pub fn evict_applied(&mut self, keep: usize) -> usize {
        let applied: Vec<Vec<u8>> = self
            .entries
            .iter()
            .filter(|(_, e)| e.state == PageState::Applied)
            .map(|(h, _)| h.clone())
            .collect();
        let to_remove = applied.len().saturating_sub(keep);
        for hash in applied.into_iter().take(to_remove) {
            self.entries.remove(&hash);
        }
        to_remove
    }

    /// Handle peer disconnect: move all in-flight requests from that peer back to pending.
    pub fn on_peer_disconnect(&mut self, peer: &SocketAddr) -> usize {
        let disconnected: Vec<Vec<u8>> = self
            .inflight
            .iter()
            .filter(|(_, r)| r.peer == *peer)
            .map(|(h, _)| h.clone())
            .collect();
        let count = disconnected.len();
        for hash in &disconnected {
            self.inflight.remove(hash);
            // 4CP-BX v2.4 (R1): the peer that owned the request is gone, so the
            // claim goes with it — a session loss must never leave a hash
            // suppressed until the horizon runs out.
            self.claims.remove(hash);
            if let Some(entry) = self.entries.get_mut(hash) {
                let now = Instant::now();
                entry.state = PageState::Pending;
                entry.last_updated = now;
                entry.peer = None;
                self.pending.push_back(hash.clone());
            }
        }
        count
    }

    /// Update the sync state machine based on current state and elapsed time.
    pub fn update_state(&mut self) {
        let now = Instant::now();
        match self.sync_state {
            FrontierSyncState::Progressing => {
                if let Some(last) = self.last_progress {
                    if now.duration_since(last) > STALL_THRESHOLD {
                        if self.inflight.is_empty() && self.pending.is_empty() {
                            // Nothing in flight, nothing pending → done
                        } else if !self.inflight.is_empty() {
                            self.sync_state = FrontierSyncState::Waiting;
                        } else {
                            self.sync_state = FrontierSyncState::Stalled;
                            self.stall_count += 1;
                        }
                    }
                }
            }
            FrontierSyncState::Waiting => {
                if let Some(last) = self.last_progress {
                    if now.duration_since(last) > STALL_THRESHOLD * 2 {
                        self.sync_state = FrontierSyncState::Stalled;
                        self.stall_count += 1;
                    }
                } else if self.started_at.elapsed() > STALL_THRESHOLD * 2 {
                    self.sync_state = FrontierSyncState::Stalled;
                    self.stall_count += 1;
                }
            }
            FrontierSyncState::Stalled => {
                // Stay stalled until record_progress() is called
            }
            FrontierSyncState::Failed => {
                // Manual reset required
            }
        }
    }

    /// Force state to Failed (e.g. all peers returned invalid data).
    pub fn mark_failed(&mut self) {
        self.sync_state = FrontierSyncState::Failed;
    }

    /// Reset state to Progressing (e.g. new peer connected).
    pub fn reset_state(&mut self) {
        self.sync_state = FrontierSyncState::Progressing;
    }

    // ===== Queries =====

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    pub fn resolved_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.state == PageState::Received || e.state == PageState::Applied)
            .count()
    }

    pub fn applied_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.state == PageState::Applied)
            .count()
    }

    pub fn total_tracked(&self) -> usize {
        self.entries.len()
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn pop_pending(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    pub fn get_inflight_for_peer(&self, peer: &SocketAddr) -> Vec<Vec<u8>> {
        self.inflight
            .iter()
            .filter(|(_, r)| r.peer == *peer)
            .map(|(h, _)| h.clone())
            .collect()
    }

    pub fn state(&self) -> FrontierSyncState {
        self.sync_state
    }

    pub fn last_progress(&self) -> Option<Instant> {
        self.last_progress
    }

    /// TEST-ONLY: set last_progress for stall simulation.
    #[cfg(test)]
    pub fn set_last_progress(&mut self, t: Option<Instant>) {
        self.last_progress = t;
    }

    /// TEST-ONLY: set started_at for stall simulation.
    #[cfg(test)]
    pub fn set_started_at(&mut self, t: Instant) {
        self.started_at = t;
    }

    /// Read-only state of a specific tracked hash.
    pub fn entry_state(&self, hash: &[u8]) -> Option<PageState> {
        self.entries.get(hash).map(|e| e.state)
    }

    pub fn snapshot(&self) -> FrontierSnapshot {
        let now = Instant::now();
        FrontierSnapshot {
            pending: self.pending.len() as u64,
            inflight: self.inflight.len() as u64,
            resolved: self.resolved_count() as u64,
            applied: self.applied_count() as u64,
            rejected: self
                .entries
                .values()
                .filter(|e| e.state == PageState::Rejected)
                .count() as u64,
            pages_requested: self.pages_requested,
            pages_received: self.pages_received,
            pages_applied: self.pages_applied,
            pages_rejected: self.pages_rejected,
            last_progress_secs_ago: self
                .last_progress
                .map(|t| now.duration_since(t).as_secs_f64()),
            state: self.sync_state,
            stall_count: self.stall_count,
            total_tracked: self.total_tracked() as u64,
        }
    }

    /// Format a structured log line for SYNC_FRONTIER.
    pub fn log_line(&self) -> String {
        let snap = self.snapshot();
        let progress_str = snap
            .last_progress_secs_ago
            .map(|s| format!("{:.1}s ago", s))
            .unwrap_or_else(|| "never".to_string());
        format!(
            "SYNC_FRONTIER pending={} inflight={} resolved={} applied={} pages_req={} pages_recv={} pages_applied={} last_progress={} state={:?} stall_count={} total={}",
            snap.pending,
            snap.inflight,
            snap.resolved,
            snap.applied,
            snap.pages_requested,
            snap.pages_received,
            snap.pages_applied,
            progress_str,
            snap.state,
            snap.stall_count,
            snap.total_tracked,
        )
    }
}

impl Default for SyncFrontier {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncContext {
    /// Cooldown for a missing parent given its previous attempt count.
    pub(crate) fn backoff_for(attempts: u32) -> Duration {
        let idx = (attempts
            .saturating_sub(1)
            .min(PARENT_BACKOFF_STEPS.len() as u32 - 1)) as usize;
        Duration::from_secs(PARENT_BACKOFF_STEPS[idx])
    }

    /// PHASE 3B (C1/H1): record ingress provenance. First-delivery-wins: a
    /// re-delivery of an already-recorded tx keeps the ORIGINAL mode (the
    /// queued instance came from the first delivery). MUST be called BEFORE
    /// the channel send it annotates: the receiver takes on read, so
    /// insert-then-send ordering is load-bearing (a miss defaults to
    /// Historical). Oldest-evicted past the cap (self-healing: an evicted tx
    /// re-records on re-delivery; a queued instance keeps its
    /// mempool-recorded mode regardless).
    ///
    /// 4CP-BX v2.1 (M2) / v2.3: returns `Some(token)` when THIS call created
    /// the entry. The caller therefore owns the reservation and must cancel it
    /// with that token if the admission it annotates is refused — otherwise a
    /// refusal (queue full, budget, forged id) would leave a phantom "in
    /// flight" entry that the drainer can never take, and the Inventory diff
    /// would stop re-requesting a transaction that was never queued. `None`
    /// means another delivery already reserved the id: that entry belongs to a
    /// queued instance and must be left alone.
    ///
    /// The reserve-then-send order is what makes the pair race-free: by the
    /// time the item is visible to the drainer, the entry is already present,
    /// so `take_ingress_mode` can never miss it and then be followed by a late
    /// insert that nobody removes.
    pub async fn note_ingress_mode(&self, id: [u8; 32], mode: ValidationMode) -> Option<u64> {
        let mut map = self.ingress_mode.write().await;
        if map.contains_key(&id) {
            return None;
        }
        evict_oldest_ingress(&mut map, &self.stats);
        let token = NEXT_INGRESS_TOKEN.fetch_add(1, Ordering::Relaxed);
        map.insert(
            id,
            IngressReservation {
                mode,
                at: Instant::now(),
                token,
                // A queued delivery is owned by a bounded channel that the
                // drainer empties: it suppresses until taken, and it owns no
                // unit of the handoff gauge.
                handoff: false,
            },
        );
        Some(token)
    }

    /// 4CP-BX v2.3: cancel a reservation THIS caller created, identified by its
    /// token, because the admission it annotated was refused. Conditional on
    /// the token: if another writer has since taken the id, its reservation is
    /// left untouched. Nothing was queued by the refused send, so the entry is
    /// ours whenever the token still matches — and a refusal still records
    /// NOTHING (the pre-4CP-BA contract).
    pub async fn cancel_ingress_reservation(&self, id: [u8; 32], token: u64) -> bool {
        let mut map = self.ingress_mode.write().await;
        match map.get(&id) {
            Some(entry) if entry.token == token => {
                let removed = map.remove(&id);
                // 4CP-BX v2.4 (R3): removal, not call pairing, moves the gauge.
                // (A delivery never owns a handoff token, so this is normally a
                // no-op; it keeps the invariant true for every removal path.)
                if removed.map(|e| e.handoff).unwrap_or(false) {
                    self.stats.close_handoff();
                }
                true
            }
            _ => false,
        }
    }

    /// 4CP-BX v2.3: hand the id from the ingress to the funnel WITHOUT an
    /// instant in which no store holds it.
    ///
    /// The drainer used to `take` the provenance and only then call into
    /// `process_transaction`, which inserts into the mempool at its very end —
    /// after PoW/signature verification. An `Inventory` arriving in that gap
    /// saw the id in no store at all (not the DAG, not the orphan store, not
    /// the ingress, not the mempool, and the frontier has no request for it)
    /// and re-requested bytes the node was already processing.
    ///
    /// This is ONE lock acquisition: it removes the previous entry and installs
    /// a handoff reservation under the same guard, returning the mode to use
    /// and the token that owns the new reservation. The caller MUST release it
    /// with `end_ingress_handoff` once the funnel call returns, whatever the
    /// outcome.
    pub async fn begin_ingress_handoff(&self, id: [u8; 32]) -> (ValidationMode, u64) {
        let mut map = self.ingress_mode.write().await;
        let previous = map.remove(&id);
        // 4CP-BX v2.4 (R3): keep the gauge equal to the number of LIVE handoff
        // entries even if an entry is replaced (a second handoff for the same
        // id: impossible with the single receiver, but the invariant must not
        // depend on that).
        if previous.map(|e| e.handoff).unwrap_or(false) {
            self.stats.close_handoff();
        }
        let mode = previous
            .map(|entry| entry.mode)
            .unwrap_or(ValidationMode::Historical);
        evict_oldest_ingress(&mut map, &self.stats);
        let token = NEXT_INGRESS_TOKEN.fetch_add(1, Ordering::Relaxed);
        map.insert(
            id,
            IngressReservation {
                mode,
                at: Instant::now(),
                token,
                handoff: true,
            },
        );
        self.stats.ingress_handoffs.fetch_add(1, Ordering::Relaxed);
        self.stats
            .ingress_handoffs_active
            .fetch_add(1, Ordering::Relaxed);
        (mode, token)
    }

    /// 4CP-BX v2.3: end a handoff started by `begin_ingress_handoff`.
    ///
    /// Releases the reservation only if `token` still owns it, so a delivery
    /// that re-reserved the id in the meantime keeps its provenance. Returns
    /// whether the reservation was actually removed (diagnostics).
    /// 4CP-BX v2.4 (R3): the gauge moves ONLY when this token really releases a
    /// handoff entry. A stale token (already released, evicted, or superseded)
    /// returns `false` and leaves every counter untouched, so a double release
    /// or a foreign token can neither wrap the gauge nor steal another
    /// handoff's slot.
    pub async fn end_ingress_handoff(&self, id: [u8; 32], token: u64) -> bool {
        let mut map = self.ingress_mode.write().await;
        match map.get(&id) {
            Some(entry) if entry.token == token => {
                let removed = map.remove(&id);
                if removed.map(|e| e.handoff).unwrap_or(false) {
                    self.stats.close_handoff();
                }
                true
            }
            _ => false,
        }
    }

    /// PHASE 3B (C1/H1): consume ingress provenance. Absent (tests, races,
    /// boot paths that never crossed the P2P ingress) defaults to Historical
    /// = timeless evaluation = pre-3B behavior.
    pub async fn take_ingress_mode(&self, id: [u8; 32]) -> ValidationMode {
        let removed = self.ingress_mode.write().await.remove(&id);
        // 4CP-BX v2.4 (R3): whoever removes a handoff entry closes it; no
        // production caller takes a handoff (the drainer uses the atomic
        // handoff pair), but the gauge must not depend on that.
        if let Some(entry) = removed {
            if entry.handoff {
                self.stats.close_handoff();
            }
            entry.mode
        } else {
            ValidationMode::Historical
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_defaults_zero() {
        let stats = SyncStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.sync_requested, 0);
        assert_eq!(snap.sync_progress, 0);
        assert_eq!(snap.orphan_created, 0);
        assert_eq!(snap.parent_already_known, 0);
    }

    /// C2 (missing-winner diagnostics): the new counters exist, default
    /// to zero, and round-trip through the snapshot (they are exposed via
    /// `aether_getSyncStats` for the next canary).
    #[test]
    fn test_p2_diagnostic_counters() {
        let stats = SyncStats::default();
        stats.inventory_advertised.fetch_add(10, Ordering::Relaxed);
        stats
            .inventory_skipped_orphan
            .fetch_add(3, Ordering::Relaxed);
        stats.sync_response_items.fetch_add(7, Ordering::Relaxed);
        stats.topo_cache_hits.fetch_add(5, Ordering::Relaxed);
        stats.topo_cache_miss.fetch_add(1, Ordering::Relaxed);
        let snap = stats.snapshot();
        assert_eq!(snap.inventory_advertised, 10);
        assert_eq!(snap.inventory_skipped_orphan, 3);
        assert_eq!(snap.sync_response_items, 7);
        assert_eq!(snap.topo_cache_hits, 5);
        assert_eq!(snap.topo_cache_miss, 1);
    }

    #[test]
    fn test_backoff_escalates() {
        assert_eq!(SyncContext::backoff_for(1), Duration::from_secs(2));
        assert_eq!(SyncContext::backoff_for(2), Duration::from_secs(5));
        assert_eq!(SyncContext::backoff_for(3), Duration::from_secs(15));
        // High attempt counts stay capped at the longest backoff.
        assert_eq!(SyncContext::backoff_for(99), Duration::from_secs(15));
    }

    // ===== SyncFrontier unit tests =====

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 25565))
    }

    #[test]
    fn test_frontier_empty() {
        let f = SyncFrontier::new();
        assert_eq!(f.pending_count(), 0);
        assert_eq!(f.inflight_count(), 0);
        assert_eq!(f.resolved_count(), 0);
        assert_eq!(f.applied_count(), 0);
        assert_eq!(f.total_tracked(), 0);
        assert_eq!(f.state(), FrontierSyncState::Progressing);
        assert!(f.last_progress().is_none());
    }

    #[test]
    fn test_frontier_add_pending() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        assert!(f.add_pending(h.clone()));
        assert_eq!(f.pending_count(), 1);
        assert_eq!(f.total_tracked(), 1);
        let entry = f.entries.get(&h).unwrap();
        assert_eq!(entry.state, PageState::Pending);
    }

    #[test]
    fn test_frontier_mark_received_applied() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        assert!(f.mark_requested(&h, addr(1)));
        assert_eq!(f.inflight_count(), 1);
        assert_eq!(f.pending_count(), 0);
        assert!(f.mark_received(&h));
        assert_eq!(f.inflight_count(), 0);
        assert!(f.mark_applied(&h));
        assert_eq!(f.applied_count(), 1);
        assert!(f.last_progress().is_some());
    }

    #[test]
    fn test_frontier_external_delivery_promotes_pending_without_page_count() {
        let mut f = SyncFrontier::new();
        let h = vec![7u8; 32];
        f.add_pending(h.clone());
        assert!(f.mark_received_external(&h));
        assert_eq!(f.pending_count(), 0);
        assert_eq!(f.inflight_count(), 0);
        assert_eq!(f.entry_state(&h), Some(PageState::Received));
        assert_eq!(f.snapshot().pages_received, 0);
        assert!(f.mark_applied(&h));
        assert_eq!(f.entry_state(&h), Some(PageState::Applied));
    }

    #[test]
    fn test_frontier_external_delivery_promotes_requested_and_clears_inflight() {
        let mut f = SyncFrontier::new();
        let h = vec![8u8; 32];
        f.add_pending(h.clone());
        assert!(f.mark_requested(&h, addr(1)));
        assert!(f.mark_received_external(&h));
        assert_eq!(f.inflight_count(), 0);
        assert_eq!(f.entry_state(&h), Some(PageState::Received));
        assert_eq!(f.snapshot().pages_requested, 1);
        assert_eq!(f.snapshot().pages_received, 0);
        assert!(!f.mark_received_external(&h));
    }

    #[test]
    fn test_frontier_rejection_never_overwrites_applied_or_recounts() {
        let mut f = SyncFrontier::new();
        let applied = vec![3u8; 32];
        f.add_pending(applied.clone());
        f.mark_requested(&applied, addr(1));
        f.mark_received(&applied);
        f.mark_applied(&applied);
        assert!(!f.mark_rejected(&applied));
        assert_eq!(f.entry_state(&applied), Some(PageState::Applied));

        let rejected = vec![4u8; 32];
        f.add_pending(rejected.clone());
        f.mark_requested(&rejected, addr(1));
        f.mark_received(&rejected);
        assert!(f.mark_rejected(&rejected));
        assert!(!f.mark_rejected(&rejected));
        assert_eq!(f.entry_state(&rejected), Some(PageState::Rejected));
        assert_eq!(f.snapshot().pages_rejected, 1);
    }

    #[test]
    fn test_frontier_applied_existing_preserves_progress_timestamp() {
        let mut f = SyncFrontier::new();
        let h = vec![9u8; 32];
        f.add_pending(h.clone());
        assert!(f.mark_requested(&h, addr(1)));
        assert!(f.mark_received(&h));
        assert!(f.mark_applied_existing(&h));
        assert_eq!(f.applied_count(), 1);
        assert!(
            f.last_progress().is_none(),
            "a duplicate already in the DAG is not new progress"
        );
    }

    #[test]
    fn test_frontier_duplicate_suppression() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        assert!(f.add_pending(h.clone()));
        // Second add returns false (already tracked)
        assert!(!f.add_pending(h));
        assert_eq!(f.total_tracked(), 1);
    }

    #[test]
    fn test_frontier_monotone_advancement() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        // Cannot go back to Pending from Requested
        assert!(!f.add_pending(h.clone()));
        // Cannot skip to Applied from Requested
        assert!(!f.mark_applied(&h));
        // Normal path works
        assert!(f.mark_received(&h));
        assert!(f.mark_applied(&h));
        // Cannot apply again
        assert!(!f.mark_applied(&h));
    }

    #[test]
    fn test_frontier_inflight_cap() {
        let mut f = SyncFrontier::new();
        // Fill up to MAX_INFLIGHT_REQUESTS
        for i in 0..MAX_INFLIGHT_REQUESTS {
            let h = vec![i as u8; 32];
            f.add_pending(h.clone());
            assert!(f.mark_requested(&h, addr(1)));
        }
        assert_eq!(f.inflight_count(), MAX_INFLIGHT_REQUESTS);
        // Next request should fail
        let extra = vec![99u8; 32];
        f.add_pending(extra.clone());
        assert!(!f.mark_requested(&extra, addr(1)));
    }

    #[test]
    fn test_frontier_peer_failover() {
        let mut f = SyncFrontier::new();
        let h1 = vec![1u8; 32];
        let h2 = vec![2u8; 32];
        f.add_pending(h1.clone());
        f.add_pending(h2.clone());
        f.mark_requested(&h1, addr(1));
        f.mark_requested(&h2, addr(1));
        // Peer 1 disconnects
        let requeued = f.on_peer_disconnect(&addr(1));
        assert_eq!(requeued, 2);
        assert_eq!(f.inflight_count(), 0);
        assert_eq!(f.pending_count(), 2);
        // Can now request from peer 2
        assert!(f.mark_requested(&h1, addr(2)));
        assert!(f.mark_requested(&h2, addr(2)));
        assert_eq!(f.inflight_count(), 2);
    }

    #[test]
    fn test_frontier_stall_detection() {
        let mut f = SyncFrontier::new();
        // No progress, no inflight → stays Progressing (nothing to stall)
        f.update_state();
        assert_eq!(f.state(), FrontierSyncState::Progressing);
        // Add a hash and request it, then age progress to trigger stall
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        // Move inflight back to pending so inflight is empty → Stalled (not Waiting)
        f.on_peer_disconnect(&addr(1));
        // Manually age the last_progress to simulate stall
        f.last_progress = Some(Instant::now() - STALL_THRESHOLD * 3);
        f.started_at = Instant::now() - STALL_THRESHOLD * 3;
        f.update_state();
        assert_eq!(f.state(), FrontierSyncState::Stalled);
        assert_eq!(f.stall_count, 1);
    }

    #[test]
    fn test_frontier_requeue_after_reject() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        f.mark_received(&h);
        f.mark_rejected(&h);
        assert_eq!(f.entries.get(&h).unwrap().state, PageState::Rejected);
        assert!(f.requeue(&h));
        assert_eq!(f.entries.get(&h).unwrap().state, PageState::Pending);
        assert_eq!(f.pending_count(), 1);
    }

    #[test]
    fn test_frontier_snapshot() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        f.mark_received(&h);
        f.mark_applied(&h);
        let snap = f.snapshot();
        assert_eq!(snap.applied, 1);
        assert_eq!(snap.pages_requested, 1);
        assert_eq!(snap.pages_received, 1);
        assert_eq!(snap.pages_applied, 1);
    }

    #[test]
    fn test_frontier_evict_applied() {
        let mut f = SyncFrontier::new();
        for i in 0..10 {
            let h = vec![i as u8; 32];
            f.add_pending(h.clone());
            f.mark_requested(&h, addr(1));
            f.mark_received(&h);
            f.mark_applied(&h);
        }
        assert_eq!(f.applied_count(), 10);
        let evicted = f.evict_applied(3);
        assert_eq!(evicted, 7);
        assert_eq!(f.applied_count(), 3);
    }

    #[test]
    fn test_frontier_log_line() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h);
        let line = f.log_line();
        assert!(line.contains("SYNC_FRONTIER"));
        assert!(line.contains("pending=1"));
    }

    // ===== Invariant tests =====

    #[test]
    fn test_invariant_frontier_never_negative() {
        let mut f = SyncFrontier::new();
        for i in 0..50 {
            let h = vec![i as u8; 32];
            f.add_pending(h.clone());
            f.mark_requested(&h, addr(1));
            f.mark_received(&h);
            f.mark_applied(&h);
        }
        // All u64 fields are inherently >= 0; verify counts are consistent
        let snap = f.snapshot();
        assert!(snap.applied <= snap.resolved);
        assert!(snap.resolved <= snap.total_tracked);
        assert!(snap.pending + snap.inflight <= snap.total_tracked);
    }

    #[test]
    fn test_invariant_inflight_bound() {
        let mut f = SyncFrontier::new();
        for i in 0..MAX_INFLIGHT_REQUESTS + 10 {
            let h = vec![i as u8; 32];
            f.add_pending(h.clone());
            f.mark_requested(&h, addr(1));
        }
        assert!(f.inflight_count() <= MAX_INFLIGHT_REQUESTS);
    }

    #[test]
    fn test_invariant_resolved_lte_received() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        f.mark_received(&h);
        assert!(f.resolved_count() <= f.pages_received as usize + 1);
    }

    #[test]
    fn test_invariant_applied_lte_received() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        f.mark_received(&h);
        f.mark_applied(&h);
        assert!(f.applied_count() <= f.resolved_count());
    }

    #[test]
    fn test_invariant_same_hash_not_applied_twice() {
        let mut f = SyncFrontier::new();
        let h = vec![1u8; 32];
        f.add_pending(h.clone());
        f.mark_requested(&h, addr(1));
        f.mark_received(&h);
        assert!(f.mark_applied(&h));
        // Second apply should fail (monotone guard)
        assert!(!f.mark_applied(&h));
        assert_eq!(f.applied_count(), 1);
    }

    #[test]
    fn test_invariant_progress_timestamp_advances_only_on_real_progress() {
        let mut f = SyncFrontier::new();
        assert!(f.last_progress().is_none());
        let h1 = vec![1u8; 32];
        f.add_pending(h1.clone());
        f.mark_requested(&h1, addr(1));
        f.mark_received(&h1);
        f.mark_applied(&h1);
        let t1 = f.last_progress().unwrap();
        // A rejected hash should NOT advance progress
        let h2 = vec![2u8; 32];
        f.add_pending(h2.clone());
        f.mark_requested(&h2, addr(1));
        f.mark_received(&h2);
        f.mark_rejected(&h2);
        assert!(f.last_progress().unwrap() >= t1);
    }

    #[test]
    fn test_invariant_frontier_memory_bounded() {
        let mut f = SyncFrontier::new();
        // Try to add more than MAX_FRONTIER_ENTRIES
        for i in 0..MAX_FRONTIER_ENTRIES + 100 {
            let mut h = vec![0u8; 32];
            h[0] = (i % 256) as u8;
            h[1] = (i / 256) as u8;
            f.add_pending(h);
        }
        assert!(f.total_tracked() <= MAX_FRONTIER_ENTRIES);
    }

    // ===== PHASE 3B (C1/H1): ingress-provenance helpers =====

    /// Roundtrip + default: absent → Historical (pre-3B timeless behavior);
    /// take consumes.
    #[tokio::test]
    async fn test_ingress_mode_roundtrip_and_default() {
        let ctx = SyncContext::default();
        let id = [0xABu8; 32];
        assert_eq!(
            ctx.take_ingress_mode(id).await,
            ValidationMode::Historical,
            "absent provenance must default to Historical"
        );
        ctx.note_ingress_mode(id, ValidationMode::Fresh).await;
        assert_eq!(
            ctx.take_ingress_mode(id).await,
            ValidationMode::Fresh,
            "recorded Fresh must roundtrip"
        );
        assert_eq!(
            ctx.take_ingress_mode(id).await,
            ValidationMode::Historical,
            "take must consume"
        );
    }

    /// First-delivery-wins: a duplicate arriving via the other ingress path
    /// keeps the ORIGINAL mode (the queued instance came from the first
    /// delivery).
    #[tokio::test]
    async fn test_ingress_mode_first_delivery_wins() {
        let ctx = SyncContext::default();
        let id = [0xCDu8; 32];
        ctx
            .note_ingress_mode(id, ValidationMode::Historical)
            .await;
        ctx.note_ingress_mode(id, ValidationMode::Fresh).await;
        assert_eq!(
            ctx.take_ingress_mode(id).await,
            ValidationMode::Historical,
            "re-delivery must not flip provenance"
        );
    }

    /// Bounded: past the cap the oldest record is evicted (self-healing — an
    /// evicted tx re-records on re-delivery; a queued instance keeps its
    /// mempool-recorded mode regardless).
    #[tokio::test]
    async fn test_ingress_mode_bounded() {
        let ctx = SyncContext::default();
        for i in 0..(MAX_INGRESS_MODE_ENTRIES + 100) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            id[8..16].copy_from_slice(&(i as u64).to_be_bytes());
            ctx.note_ingress_mode(id, ValidationMode::Fresh).await;
        }
        assert!(
            ctx.ingress_mode.read().await.len() <= MAX_INGRESS_MODE_ENTRIES,
            "provenance map must stay bounded"
        );
    }

    /// 4CP-BX v2.1 (M2): the reserve/cancel pair. A reservation created by this
    /// caller is reportable and cancellable; one that belongs to an earlier
    /// delivery is neither, so a refusal can never erase the provenance of a
    /// transaction that really is queued.
    #[tokio::test]
    async fn test_ingress_reservation_is_owned_and_cancellable() {
        let ctx = SyncContext::default();
        let id = [0xEFu8; 32];
        let token = ctx
            .note_ingress_mode(id, ValidationMode::Fresh)
            .await
            .expect("the first reserve is ours");
        assert!(
            ctx.note_ingress_mode(id, ValidationMode::Historical)
                .await
                .is_none(),
            "a re-delivery owns nothing: the entry is the first delivery's"
        );
        assert!(
            ctx.cancel_ingress_reservation(id, token).await,
            "cancelling our own reservation removes it"
        );
        assert!(
            ctx.ingress_mode.read().await.is_empty(),
            "cancelling our own reservation leaves nothing behind"
        );
        assert!(
            ctx.note_ingress_mode(id, ValidationMode::Historical)
                .await
                .is_some(),
            "the next delivery records from scratch"
        );
        assert_eq!(ctx.take_ingress_mode(id).await, ValidationMode::Historical);
    }

    /// 4CP-BX v2.3: the handoff is ONE transition — there is no instant in which
    /// the id is held by no store, which is the window that let an Inventory
    /// re-request a transaction the funnel was already processing.
    #[tokio::test]
    async fn test_ingress_handoff_leaves_no_uncovered_instant() {
        let ctx = SyncContext::default();
        let id = [0x1Au8; 32];
        let before = ctx.stats.ingress_handoffs.load(Ordering::Relaxed);
        ctx.note_ingress_mode(id, ValidationMode::Fresh).await;

        let (mode, token) = ctx.begin_ingress_handoff(id).await;
        assert_eq!(mode, ValidationMode::Fresh, "the mode crosses the handoff");
        assert!(
            ctx.ingress_mode.read().await.contains_key(&id),
            "the id is covered at the instant the handoff starts"
        );
        assert_eq!(
            ctx.stats.ingress_handoffs.load(Ordering::Relaxed),
            before + 1
        );
        assert_eq!(
            ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed),
            1,
            "the open handoff is observable"
        );

        assert!(ctx.end_ingress_handoff(id, token).await);
        assert!(
            !ctx.ingress_mode.read().await.contains_key(&id),
            "release leaves nothing behind: the funnel owns it now"
        );
        assert_eq!(ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed), 0);
    }

    /// 4CP-BX v2.3: a handoff releases ONLY its own reservation. When a second
    /// delivery re-reserved the id in the meantime, its provenance survives —
    /// the queued copy must still be evaluated under the mode it arrived with.
    #[tokio::test]
    async fn test_ingress_handoff_releases_only_its_own_reservation() {
        let ctx = SyncContext::default();
        let id = [0x2Bu8; 32];
        let (_mode, handoff) = ctx.begin_ingress_handoff(id).await;

        // A re-delivery during the handoff does not own the entry...
        assert!(ctx
            .note_ingress_mode(id, ValidationMode::Historical)
            .await
            .is_none());
        // ...but a later writer that re-reserves after the handoff released it
        // is the one that must be preserved.
        assert!(ctx.end_ingress_handoff(id, handoff).await);
        let delivery = ctx
            .note_ingress_mode(id, ValidationMode::Historical)
            .await
            .expect("new delivery owns it");
        assert!(
            !ctx.end_ingress_handoff(id, handoff).await,
            "a stale handoff token must never remove another writer's entry"
        );
        assert_eq!(
            ctx.ingress_mode.read().await.get(&id).map(|e| e.token),
            Some(delivery),
            "the delivery's reservation is untouched"
        );
        assert_eq!(ctx.take_ingress_mode(id).await, ValidationMode::Historical);
    }

    /// 4CP-BX v2.3: a refused admission cancels with its own token, so the id is
    /// requestable again while any other writer's reservation is left alone.
    #[tokio::test]
    async fn test_ingress_cancel_is_token_scoped() {
        let ctx = SyncContext::default();
        let id = [0x3Cu8; 32];
        let token = ctx
            .note_ingress_mode(id, ValidationMode::Fresh)
            .await
            .expect("reserved");
        assert!(
            !ctx.cancel_ingress_reservation(id, token + 1).await,
            "a foreign token cancels nothing"
        );
        assert!(ctx.ingress_mode.read().await.contains_key(&id));
        assert!(ctx.cancel_ingress_reservation(id, token).await);
        assert!(ctx.ingress_mode.read().await.is_empty());
    }

    /// 4CP-BX v2.4 (R3): the gauge counts LIVE handoff entries and is moved by
    /// REMOVAL only — so a double release can neither underflow it (the old
    /// code decremented before checking ownership and wrapped to `u64::MAX`) nor
    /// steal the slot of a handoff that is still open.
    #[tokio::test]
    async fn test_ingress_handoff_gauge_is_release_driven() {
        let ctx = SyncContext::default();
        let id = [0x4Du8; 32];
        let active = || ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed);
        assert_eq!(active(), 0);

        let (_mode, token) = ctx.begin_ingress_handoff(id).await;
        assert_eq!(active(), 1, "an open handoff is counted once");
        assert!(ctx.end_ingress_handoff(id, token).await);
        assert_eq!(active(), 0);

        // The entry is gone, so this token owns nothing any more. Releasing it
        // again must be a no-op, not a decrement.
        assert!(
            !ctx.end_ingress_handoff(id, token).await,
            "a second release has nothing to release"
        );
        assert_eq!(active(), 0, "a double release must not move the gauge");
        assert!(!ctx.ingress_mode.read().await.contains_key(&id));

        // Two successive handoffs: the gauge must track both exactly.
        let (_m1, t1) = ctx.begin_ingress_handoff([0x4Eu8; 32]).await;
        let (_m2, t2) = ctx.begin_ingress_handoff([0x4Fu8; 32]).await;
        assert_eq!(active(), 2);
        assert!(ctx.end_ingress_handoff([0x4Eu8; 32], t1).await);
        assert_eq!(active(), 1);
        assert!(ctx.end_ingress_handoff([0x4Fu8; 32], t2).await);
        assert_eq!(active(), 0);
    }

    /// 4CP-BX v2.4 (R3): a foreign token releases nothing, moves no counter and
    /// leaves the entry for its owner.
    #[tokio::test]
    async fn test_ingress_handoff_foreign_token_cannot_close() {
        let ctx = SyncContext::default();
        let id = [0x5Eu8; 32];
        let (_mode, token) = ctx.begin_ingress_handoff(id).await;

        assert!(
            !ctx.end_ingress_handoff(id, token.wrapping_add(1)).await,
            "a foreign token releases nothing"
        );
        assert_eq!(
            ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed),
            1,
            "a foreign token must not move the gauge"
        );
        assert!(ctx.ingress_mode.read().await.contains_key(&id));

        assert!(ctx.end_ingress_handoff(id, token).await);
        assert_eq!(ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed), 0);
    }

    /// 4CP-BX v2.4 (R3): every removal path closes the handoff it removes, and a
    /// queued delivery never owns a gauge slot.
    #[tokio::test]
    async fn test_ingress_gauge_follows_every_removal_path() {
        let ctx = SyncContext::default();
        let active = || ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed);

        let id = [0x6Fu8; 32];
        let (mode, token) = ctx.begin_ingress_handoff(id).await;
        assert_eq!(mode, ValidationMode::Historical);
        assert_eq!(active(), 1);
        // Legacy take (harnesses only) still closes the handoff it consumed.
        assert_eq!(ctx.take_ingress_mode(id).await, ValidationMode::Historical);
        assert_eq!(active(), 0, "take closes the handoff it removes");
        assert!(!ctx.end_ingress_handoff(id, token).await);
        assert_eq!(active(), 0);

        let queued = [0x70u8; 32];
        let delivery = ctx
            .note_ingress_mode(queued, ValidationMode::Fresh)
            .await
            .expect("reserved");
        assert_eq!(active(), 0, "a queued delivery is not a handoff");
        assert!(ctx.cancel_ingress_reservation(queued, delivery).await);
        assert_eq!(active(), 0);
    }

    // -----------------------------------------------------------------------
    // 4CP-BX v2.5 (R2) — a live handoff evicted before its release
    // -----------------------------------------------------------------------

    /// 4CP-BX v2.5 (R2): evicting a LIVE handoff closes its gauge unit exactly
    /// once, the evicted writer's late release is a no-op, and the id becomes
    /// requestable again (absence from the registry is what suppresses it).
    #[tokio::test]
    async fn test_evicted_handoff_closes_gauge_once_and_frees_the_id() {
        let ctx = SyncContext::default();
        let live = [0xE7u8; 32];
        let (_mode, token) = ctx.begin_ingress_handoff(live).await;
        assert_eq!(
            ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed),
            1,
            "an open handoff is counted once"
        );

        // Fill the registry to its cap with QUEUED entries, all older than the
        // handoff, then age the handoff itself so it is the oldest of all.
        {
            let mut map = ctx.ingress_mode.write().await;
            for i in 0..(MAX_INGRESS_MODE_ENTRIES - 1) {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                id[31] = 0x42;
                map.insert(
                    id,
                    IngressReservation {
                        mode: ValidationMode::Historical,
                        at: Instant::now() - Duration::from_secs(3600),
                        token: 9_000_000 + i as u64,
                        handoff: false,
                    },
                );
            }
            map.get_mut(&live).expect("handoff present").at =
                Instant::now() - Duration::from_secs(7200);
        }

        // A new reservation at the cap evicts the oldest entry: our handoff.
        let queued = [0xE8u8; 32];
        assert!(
            ctx.note_ingress_mode(queued, ValidationMode::Fresh)
                .await
                .is_some(),
            "a new reservation is admitted at the cap"
        );
        assert_eq!(
            ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed),
            0,
            "the evicted handoff closed its gauge unit exactly once"
        );
        assert!(
            !ctx.ingress_mode.read().await.contains_key(&live),
            "oldest-first eviction took the handoff"
        );
        assert!(
            !ctx.end_ingress_handoff(live, token).await,
            "the evicted writer no longer owns the entry"
        );
        assert_eq!(
            ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed),
            0,
            "a late release must not decrement a second time"
        );
    }

    // -----------------------------------------------------------------------
    // 4CP-BX v2.5 (R4) — behaviour past the handoff lease
    // -----------------------------------------------------------------------

    /// 4CP-BX v2.5 (R4): a lease that has EXPIRED reopens the request, but it
    /// does not open a second admission path — a duplicate delivery of the same
    /// id is still refused by the ingestion guard, and the funnel's DAG dedup
    /// sits on top of that. Suppression is a bandwidth optimisation; admission
    /// stays the deduplicator.
    #[tokio::test]
    async fn test_expired_lease_reopens_request_but_not_admission() {
        let ctx = SyncContext::default();
        let id = [0xB7u8; 32];
        ctx.ingress_mode.write().await.insert(
            id,
            IngressReservation {
                mode: ValidationMode::Historical,
                at: Instant::now() - (INGRESS_HANDOFF_LEASE + Duration::from_secs(5)),
                token: 7_777,
                handoff: true,
            },
        );
        let now = Instant::now();
        assert!(
            !ctx.ingress_mode
                .read()
                .await
                .get(&id)
                .expect("entry")
                .suppresses_inventory(now),
            "an expired lease must stop hiding the id"
        );
        assert!(
            ctx.note_ingress_mode(id, ValidationMode::Fresh)
                .await
                .is_none(),
            "the id is still reserved: a duplicate cannot re-enter the pipeline"
        );
    }

    // -----------------------------------------------------------------------
    // 4CP-BX v2.5 (R5) — gauge equals the live handoff entries
    // -----------------------------------------------------------------------

    /// 4CP-BX v2.5 (R5): after every kind of operation the gauge equals the
    /// number of LIVE `handoff` entries in the registry — the structural
    /// invariant, not a hand-maintained tally.
    #[tokio::test]
    async fn test_gauge_equals_live_handoff_entries_after_mixed_operations() {
        let ctx = SyncContext::default();
        let gauge = || ctx.stats.ingress_handoffs_active.load(Ordering::Relaxed) as usize;
        macro_rules! check {
            ($step:expr) => {
                assert_eq!(
                    gauge(),
                    ctx.ingress_mode
                        .read()
                        .await
                        .values()
                        .filter(|e| e.handoff)
                        .count(),
                    "gauge must equal the live handoff entries after {}",
                    $step
                );
            };
        }

        // begin + end
        let a = [0xA1u8; 32];
        let (_m, ta) = ctx.begin_ingress_handoff(a).await;
        check!("begin");
        assert!(ctx.end_ingress_handoff(a, ta).await);
        check!("end");
        // double end (nothing left to release)
        assert!(!ctx.end_ingress_handoff(a, ta).await);
        check!("double end");
        // foreign token
        let b = [0xA2u8; 32];
        let (_m, tb) = ctx.begin_ingress_handoff(b).await;
        assert!(!ctx.end_ingress_handoff(b, tb.wrapping_add(77)).await);
        check!("foreign token");
        // cancel of a queued reservation (never owns a gauge unit)
        let c = [0xA3u8; 32];
        let tc = ctx
            .note_ingress_mode(c, ValidationMode::Fresh)
            .await
            .expect("reserved");
        assert!(ctx.cancel_ingress_reservation(c, tc).await);
        check!("cancel");
        // take consumes (and closes) a handoff
        assert_eq!(ctx.take_ingress_mode(b).await, ValidationMode::Historical);
        check!("take");
        // stale token after take
        assert!(!ctx.end_ingress_handoff(b, tb).await);
        check!("stale token");
        // replacement: a second handoff for the same id
        let d = [0xA4u8; 32];
        let (_m1, _t1) = ctx.begin_ingress_handoff(d).await;
        let (_m2, t2) = ctx.begin_ingress_handoff(d).await;
        check!("replacement");
        // eviction at capacity: the fillers are older than `d`, so `d` survives
        {
            let mut map = ctx.ingress_mode.write().await;
            let target = MAX_INGRESS_MODE_ENTRIES - map.len();
            for i in 0..target {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                id[31] = 0x43;
                map.insert(
                    id,
                    IngressReservation {
                        mode: ValidationMode::Historical,
                        at: Instant::now() - Duration::from_secs(3600),
                        token: 5_000_000 + i as u64,
                        handoff: false,
                    },
                );
            }
        }
        check!("fill to cap");
        let q = [0xA5u8; 32];
        assert!(
            ctx.note_ingress_mode(q, ValidationMode::Fresh)
                .await
                .is_some(),
            "a reservation is admitted at the cap"
        );
        check!("eviction");
        assert!(ctx.end_ingress_handoff(d, t2).await);
        check!("final end");
        assert_eq!(gauge(), 0, "every handoff is closed");
    }

    /// 4CP-BX v2.4 (R2): an interrupted handoff (panic or task cancellation
    /// between `begin` and `end`) is a LEASE. A `Drop` cannot await the registry
    /// lock, so the lease is what keeps liveness: after it the id stops
    /// suppressing `Inventory` requests and can be fetched again. Queued
    /// provenance is drained by its channel and never expires.
    #[test]
    fn test_ingress_handoff_lease_expires() {
        let now = Instant::now();
        let open = IngressReservation {
            mode: ValidationMode::Fresh,
            at: now,
            token: 1,
            handoff: true,
        };
        assert!(
            open.suppresses_inventory(now),
            "an open handoff must keep the id visible-in-flight"
        );

        let leaked = IngressReservation {
            at: now - (INGRESS_HANDOFF_LEASE + Duration::from_secs(1)),
            ..open
        };
        assert!(
            !leaked.suppresses_inventory(now),
            "a lost release must not hide the id for the process lifetime"
        );
        assert!(
            leaked.suppresses_inventory(now - Duration::from_secs(2)),
            "the lease is relative to the handoff instant"
        );

        let queued = IngressReservation {
            handoff: false,
            at: now - Duration::from_secs(3600),
            ..open
        };
        assert!(
            queued.suppresses_inventory(now),
            "queued provenance keeps suppressing until the drainer takes it"
        );
    }

    /// 4CP-BX v2.4 (R1): the claim is the arbitration point between sessions —
    /// one wins, the other is told to skip, and the state machine still records
    /// the request exactly once.
    #[test]
    fn test_frontier_claim_is_exclusive() {
        let mut f = SyncFrontier::new();
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let h = vec![9u8; 32];
        f.add_pending(h.clone());

        assert!(f.claim_request(&h, Duration::from_secs(30)), "the first claim wins");
        assert_eq!(f.claimed_requests(), 1);
        assert!(
            !f.claim_request(&h, Duration::from_secs(30)),
            "a concurrent session must lose the claim"
        );
        assert_eq!(f.claimed_requests(), 1, "a lost claim adds nothing");

        assert!(f.mark_requested(&h, peer));
        assert!(f.request_is_fresh(&h, Duration::from_secs(30)));
        assert_eq!(f.pages_requested, 1, "the request is counted once");
    }

    /// 4CP-BX v2.4 (R1): claims are per hash — claiming one id must never
    /// suppress a different one in the same advertisement.
    #[test]
    fn test_frontier_claim_is_per_hash() {
        let mut f = SyncFrontier::new();
        let a = vec![1u8; 32];
        let b = vec![2u8; 32];
        assert!(f.claim_request(&a, Duration::from_secs(30)));
        assert!(
            f.claim_request(&b, Duration::from_secs(30)),
            "a second hash must still be requestable"
        );
        assert_eq!(f.claimed_requests(), 2);
    }

    /// 4CP-BX v2.4 (R1): a claim expires with the same horizon as an in-flight
    /// request, so a lost or unanswered request is retried and never pins the
    /// hash — no new timer, no arbitrary delay.
    #[test]
    fn test_frontier_claim_expires_with_the_horizon() {
        let mut f = SyncFrontier::new();
        let h = vec![0xAAu8; 32];
        assert!(f.claim_request(&h, Duration::from_secs(30)));
        assert!(!f.claim_request(&h, Duration::from_secs(30)));

        // Age the claim past the horizon (the peer had its whole window).
        f.claims
            .insert(h.clone(), Instant::now() - Duration::from_secs(31));
        assert!(
            f.claim_request(&h, Duration::from_secs(30)),
            "an expired claim must be re-claimable: retry beats suppression"
        );
    }

    /// 4CP-BX v2.4 (R1): one frame carries up to MAX_INV_ITEMS hashes but the
    /// inflight record stops at MAX_INFLIGHT_REQUESTS — which is exactly why the
    /// claim table exists. Every hash of the batch must be claimed so the next
    /// round (or another session) does not re-ask for the tail.
    #[test]
    fn test_frontier_claim_covers_batches_beyond_inflight_cap() {
        let mut f = SyncFrontier::new();
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let horizon = Duration::from_secs(30);
        let hashes: Vec<Vec<u8>> = (0..(MAX_INFLIGHT_REQUESTS + 8))
            .map(|i| {
                let mut h = vec![0u8; 32];
                h[0] = i as u8;
                h[1] = (i >> 8) as u8;
                h
            })
            .collect();

        for h in &hashes {
            f.add_pending(h.clone());
            assert!(f.claim_request(h, horizon), "every hash of the frame is claimed");
        }
        let mut recorded = 0;
        for h in &hashes {
            if f.mark_requested(h, peer) {
                recorded += 1;
            }
        }
        assert_eq!(
            recorded, MAX_INFLIGHT_REQUESTS,
            "the inflight record is capped by design"
        );
        assert_eq!(
            f.claimed_requests(),
            hashes.len(),
            "the claim table covers the whole frame, including the tail"
        );
        for h in &hashes {
            assert!(
                !f.claim_request(h, horizon),
                "the tail must not look requestable to the next round"
            );
        }
    }

    /// 4CP-BX v2.4 (R1): a frame refused by the egress budget releases its
    /// claims, so the next inventory round retries immediately instead of
    /// waiting out the horizon.
    #[test]
    fn test_frontier_release_claim_reopens_request() {
        let mut f = SyncFrontier::new();
        let h = vec![0xBBu8; 32];
        let horizon = Duration::from_secs(30);
        assert!(f.claim_request(&h, horizon));
        assert!(!f.claim_request(&h, horizon));
        assert!(f.release_claim(&h), "the refused frame gives the claim back");
        assert!(f.claim_request(&h, horizon), "the hash is requestable again at once");
        assert!(!f.release_claim(&vec![0xCCu8; 32]), "releasing an unknown hash is a no-op");
    }

    /// 4CP-BX v2.4 (R1): the claim follows the REQUEST through both retry
    /// transitions — an expired request (`rearm_expired`, the retry the
    /// Inventory path performs) and a lost session (`on_peer_disconnect`).
    /// Otherwise a retry would be suppressed for the rest of the horizon.
    #[test]
    fn test_frontier_claim_follows_the_retry_paths() {
        let mut f = SyncFrontier::new();
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let horizon = Duration::from_secs(30);

        let expired = vec![0xE1u8; 32];
        f.add_pending(expired.clone());
        assert!(f.claim_request(&expired, horizon));
        assert!(f.mark_requested(&expired, peer));
        assert!(
            f.rearm_expired(&expired, Duration::ZERO),
            "a request past its window returns to Pending"
        );
        assert_eq!(f.claimed_requests(), 0, "re-arm releases the claim");
        assert!(
            f.claim_request(&expired, horizon),
            "the retry must be claimable immediately"
        );

        let lost = vec![0xE2u8; 32];
        f.add_pending(lost.clone());
        assert!(f.claim_request(&lost, horizon));
        assert!(f.mark_requested(&lost, peer));
        assert_eq!(f.on_peer_disconnect(&peer), 1);
        assert!(
            !f.claims.contains_key(&lost),
            "a lost session releases the claim"
        );
        assert!(
            f.claim_request(&lost, horizon),
            "the hash is requestable from another peer at once"
        );
    }

    /// 4CP-BX v2.4 (R1): terminal transitions drop the claim. A `Received` hash
    /// keeps it (the answer is on its way), a duplicate response that resolves
    /// to an existing DAG entry drops it, and a rejected hash is not re-asked.
    #[test]
    fn test_frontier_claim_cleared_on_terminal_states() {
        let mut f = SyncFrontier::new();
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let horizon = Duration::from_secs(30);

        let applied = vec![0xD1u8; 32];
        f.add_pending(applied.clone());
        assert!(f.claim_request(&applied, horizon));
        assert!(f.mark_requested(&applied, peer));
        assert!(f.mark_received(&applied));
        assert_eq!(f.claimed_requests(), 1, "Received keeps the claim: bytes are in flight");
        assert!(f.mark_applied(&applied));
        assert_eq!(f.claimed_requests(), 0, "Applied drops the claim");

        let existing = vec![0xD2u8; 32];
        f.add_pending(existing.clone());
        assert!(f.claim_request(&existing, horizon));
        assert!(f.mark_requested(&existing, peer));
        assert!(f.mark_received(&existing));
        assert!(f.mark_applied_existing(&existing));
        assert_eq!(f.claimed_requests(), 0, "a DAG duplicate is terminal too");

        let rejected = vec![0xD3u8; 32];
        f.add_pending(rejected.clone());
        assert!(f.claim_request(&rejected, horizon));
        assert!(f.mark_requested(&rejected, peer));
        assert!(f.mark_rejected(&rejected));
        assert_eq!(f.claimed_requests(), 0, "a rejected hash is not re-requested");
    }

    // -----------------------------------------------------------------------
    // 4CP-BX v2.5 (R1) — saturation of the claim table
    // -----------------------------------------------------------------------

    /// 4CP-BX v2.5 (R1/P1): a table full of LIVE claims refuses new ones WITHOUT
    /// evicting anything, one frame triggers exactly ONE sweep, and expiring a
    /// single entry frees exactly one slot for the next frame.
    #[test]
    fn test_frontier_claim_saturation_refuses_then_frees_exactly_one_slot() {
        let mut f = SyncFrontier::new();
        let horizon = Duration::from_secs(30);
        let now = Instant::now();
        for i in 0..MAX_FRONTIER_ENTRIES {
            let mut h = vec![0u8; 32];
            h[0] = 0x51;
            h[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            f.claims.insert(h, now);
        }
        assert!(f.claim_table_at_capacity());
        assert_eq!(f.claimed_requests(), MAX_FRONTIER_ENTRIES);
        let sweeps_before = f.claim_sweeps();

        // ONE sweep for the whole frame: every claim is live, nothing is freed.
        assert_eq!(f.sweep_expired_claims(now, horizon), 0);
        assert_eq!(f.claim_sweeps(), sweeps_before + 1, "one sweep per frame");

        // The frame is refused at capacity, and no live claim is evicted.
        for i in 0..1000u64 {
            let mut h = vec![0u8; 32];
            h[0] = 0x52;
            h[1..9].copy_from_slice(&i.to_le_bytes());
            assert_eq!(
                f.claim_request_detailed(&h, horizon),
                ClaimOutcome::Capacity,
                "a full table of live claims must refuse, not evict"
            );
        }
        assert_eq!(
            f.claimed_requests(),
            MAX_FRONTIER_ENTRIES,
            "no live claim may be evicted to make room"
        );

        // Expire exactly one entry: the next frame frees exactly one slot.
        let mut victim = vec![0u8; 32];
        victim[0] = 0x51;
        victim[1..9].copy_from_slice(&0u64.to_le_bytes());
        f.claims
            .insert(victim, now - (horizon + Duration::from_secs(1)));
        assert_eq!(
            f.sweep_expired_claims(now, horizon),
            1,
            "exactly one expired claim is released"
        );
        assert_eq!(f.claimed_requests(), MAX_FRONTIER_ENTRIES - 1);
        let mut fresh = vec![0u8; 32];
        fresh[0] = 0x53;
        assert_eq!(
            f.claim_request_detailed(&fresh, horizon),
            ClaimOutcome::Claimed,
            "the freed slot is immediately usable"
        );
        assert_eq!(f.claimed_requests(), MAX_FRONTIER_ENTRIES);
    }

    /// 4CP-BX v2.5 (R1): the sweep drops EXPIRED claims only — never a live one.
    #[test]
    fn test_frontier_claim_sweep_drops_only_expired() {
        let mut f = SyncFrontier::new();
        let horizon = Duration::from_secs(30);
        let now = Instant::now();
        f.claims.insert(vec![1u8; 32], now);
        f.claims.insert(vec![2u8; 32], now - Duration::from_secs(10));
        f.claims
            .insert(vec![3u8; 32], now - (horizon + Duration::from_secs(1)));
        f.claims
            .insert(vec![4u8; 32], now - (horizon + Duration::from_secs(60)));
        assert_eq!(f.sweep_expired_claims(now, horizon), 2);
        assert_eq!(f.claimed_requests(), 2);
        assert!(f.claims.contains_key(&vec![1u8; 32]));
        assert!(
            f.claims.contains_key(&vec![2u8; 32]),
            "a claim inside the horizon survives the sweep"
        );
    }

    /// 4CP-BX v2.5 (R3): the claim arbitrates between PEERS, not within one
    /// session — another peer's advertisement is refused while the claim is
    /// live, accepted once the horizon has passed, and released immediately
    /// when the session that owned it disconnects.
    #[test]
    fn test_frontier_claim_blocks_another_peer_until_horizon() {
        let mut f = SyncFrontier::new();
        let horizon = Duration::from_secs(30);
        let peer_a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:9102".parse().unwrap();

        let h = vec![0x7Au8; 32];
        f.add_pending(h.clone());
        assert!(f.claim_request(&h, horizon));
        assert!(f.mark_requested(&h, peer_a));
        // Peer B advertises the same hash while A is silent: suppressed.
        assert_eq!(f.claim_request_detailed(&h, horizon), ClaimOutcome::Held);
        // Past the horizon the claim is re-claimable: availability wins.
        f.claims
            .insert(h.clone(), Instant::now() - (horizon + Duration::from_secs(1)));
        assert_eq!(f.claim_request_detailed(&h, horizon), ClaimOutcome::Claimed);

        // A lost session releases the claim at once (no 30 s wait).
        let h2 = vec![0x7Bu8; 32];
        f.add_pending(h2.clone());
        assert!(f.claim_request(&h2, horizon));
        assert!(f.mark_requested(&h2, peer_b));
        assert_eq!(f.on_peer_disconnect(&peer_b), 1);
        assert!(
            !f.claims.contains_key(&h2),
            "a lost session releases the claim"
        );
        assert_eq!(f.claim_request_detailed(&h2, horizon), ClaimOutcome::Claimed);
    }

    /// 4CP-BX v2.1 (M1): an outstanding request suppresses a re-request only
    /// while it is fresh; past the horizon it is re-armed as Pending so the
    /// retry can fire. This is the predicate the Inventory diff consults.
    #[test]
    fn test_request_freshness_and_rearm() {
        let mut f = SyncFrontier::new();
        let h = vec![7u8; 32];
        assert!(
            !f.request_is_fresh(&h, Duration::from_secs(30)),
            "an untracked hash is not outstanding"
        );
        assert!(f.add_pending(h.clone()));
        assert!(f.mark_requested(&h, addr(1)));
        assert!(
            f.request_is_fresh(&h, Duration::from_secs(30)),
            "a just-sent request is fresh"
        );
        assert_eq!(f.fresh_requests(Duration::from_secs(30)), vec![[7u8; 32]]);
        // Zero horizon: the request is already past it, so it is not fresh and
        // may be re-armed — the retry path for a response that never came.
        assert!(!f.request_is_fresh(&h, Duration::ZERO));
        assert!(!f.fresh_requests(Duration::ZERO).contains(&[7u8; 32]));
        assert!(f.rearm_expired(&h, Duration::ZERO));
        assert!(!f.rearm_expired(&h, Duration::ZERO), "re-arm is one-shot");
        assert!(
            !f.request_is_fresh(&h, Duration::from_secs(30)),
            "a re-armed hash is pending, not outstanding"
        );
        assert_eq!(f.pending_count(), 1, "the retry waits in pending");
        assert!(
            f.mark_requested(&h, addr(1)),
            "the retry can request the same hash again"
        );
        assert_eq!(f.pending_count(), 0);
    }
}
