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
use std::collections::{HashMap, HashSet};
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

    #[test]
    fn test_backoff_escalates() {
        assert_eq!(SyncContext::backoff_for(1), Duration::from_secs(2));
        assert_eq!(SyncContext::backoff_for(2), Duration::from_secs(5));
        assert_eq!(SyncContext::backoff_for(3), Duration::from_secs(15));
        // High attempt counts stay capped at the longest backoff.
        assert_eq!(SyncContext::backoff_for(99), Duration::from_secs(15));
    }
}
