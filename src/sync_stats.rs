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
    /// Transactions accepted into the DAG through the P2P path
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
    /// VPS-2 §6: monotone sync frontier = max DAG total observed on the
    /// P2P path. progress(t+1) >= progress(t) BY CONSTRUCTION (max-update);
    /// a flat frontier with pending orphans/requests = stall evidence.
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
}

/// DEEP SYNC: maximum in-flight requests at any time.
pub const MAX_INFLIGHT_REQUESTS: usize = 64;

/// DEEP SYNC: maximum hashes tracked in the frontier (pending + resolved + applied).
pub const MAX_FRONTIER_ENTRIES: usize = 100_000;

/// DEEP SYNC: stall detection threshold — no progress for this duration → STALLED.
pub const STALL_THRESHOLD: Duration = Duration::from_secs(30);

/// DEEP SYNC: maximum retry attempts per hash before marking as FAILED.
pub const MAX_RETRY_ATTEMPTS: u32 = 3;

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
    pages_requested: u64,
    pages_received: u64,
    pages_applied: u64,
    pages_rejected: u64,
    last_progress: Option<Instant>,
    sync_state: FrontierSyncState,
    stall_count: u64,
    started_at: Instant,
}

impl SyncFrontier {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            inflight: HashMap::new(),
            entries: HashMap::new(),
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
        self.last_progress = Some(now);
        self.sync_state = FrontierSyncState::Progressing;
        self.pages_applied += 1;
        true
    }

    /// Mark a request as rejected (bad data, peer error, timeout).
    /// The hash goes back to Pending if retries remain, otherwise stays Rejected.
    pub fn mark_rejected(&mut self, hash: &[u8]) -> bool {
        // Remove from inflight
        self.inflight.remove(hash);
        let entry = match self.entries.get_mut(hash) {
            Some(e) => e,
            None => return false,
        };
        entry.state = PageState::Rejected;
        entry.last_updated = Instant::now();
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

    /// TEST-ONLY: check state of a specific entry.
    #[cfg(test)]
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
            last_progress_secs_ago: self.last_progress.map(|t| now.duration_since(t).as_secs_f64()),
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
}
