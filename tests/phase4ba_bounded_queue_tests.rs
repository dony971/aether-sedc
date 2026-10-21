//! 4CP-BA: bounded queues, explicit saturation, and recovery.
//!
//! The three queues that were unbounded before this phase are exercised
//! through their REAL paths (production accept arms, production session
//! writer, production serving code):
//!
//! * node ingress `tx_channel` (bounded count + byte budget),
//! * node ingress `stake_channel` (bounded count, await back-pressure),
//! * per-session outbound queues (bounded count + byte budget).
//!
//! Scenario map (phase specification §7):
//! * A/B — `ba01_*`: fill the ingress queue through gossip, prove the cap
//!   and the byte budget hold, prove a REFUSED payload was not marked seen
//!   (it is admitted and applied on re-gossip, exactly once), then prove the
//!   same for a saturated `SyncResponse` batch (frontier marks only what was
//!   really queued; Applied requires DAG insertion, and re-delivery converges
//!   without double application).
//! * C — `ba02_*`: a peer that never reads cannot grow its outbound queue
//!   past the cap; the server refuses instead of buffering; a normal peer
//!   stays fully served during the storm; after the slow peer resumes, a new
//!   request and a reconnect both recover the closure.
//! * D/§6 — `ba03_*`: a full stake queue BLOCKS the offending session
//!   (back-pressure) and loses nothing; another peer's traffic is unaffected.
//! * E — `ba04_*`: repeated fill → refuse → drain cycles are deterministic,
//!   the reservation accounting returns to zero after each drain, and the
//!   funnel set stays exact (no duplicate application, no leak).
//!
//! Ports 44841-44844 are unique to this suite (44801 = 4CH, 44805 = in-module
//! 4CH, 44811-44820 = 4CP-AY/AZ).
//!
//! Honesty boundaries: the harness consumer stands in for the node's
//! TransactionProcessor (funnel dedup is modelled by a set keyed on tx id);
//! production funnel idempotence itself is covered by the AZ/AY suites. The
//! tests assert the queue CONTRACT (bounds, refusal visibility, recovery),
//! not consensus.

use aether_unified::genesis::GENESIS_HASH;
use aether_unified::p2p::{
    IngressTx, P2PConfig, P2PMessage, P2PNetwork, P2PProtocolMode, StakePayload,
    P2P_PROTOCOL_VERSION, STAKE_CHANNEL_CAPACITY_MSGS, TX_INGRESS_CAPACITY_BYTES,
    TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::sync_stats::{PageState, SyncContext};
use aether_unified::transaction::{Transaction, Vote, DEFAULT_NETWORK_ID, VOTE_FORMAT_VERSION};
use aether_unified::transport::{
    BoxFuture, PeerAddr, TcpTransport, Transport, TransportError, TransportListener,
    TransportStream,
};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};

const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;
const FRAME_PAD_BUCKET: usize = 256;
const FRAME_FIXED_OVERHEAD: usize = 30;

struct RejectAllTransport;

impl Transport for RejectAllTransport {
    fn dial(&self, _addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
        Box::pin(async move {
            Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "4BA test transport: outbound dial refused",
            )))
        })
    }
    fn bind(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>> {
        let transport = TcpTransport::new();
        let endpoint = *addr;
        Box::pin(async move { transport.bind(&endpoint).await })
    }
}

// ---------------------------------------------------------------------------
// Synthetic data (no PoW: these tests exercise queues, not consensus)
// ---------------------------------------------------------------------------

/// Free-standing transactions, distinct ids, no parent requirements (used for
/// gossip ingress saturation, where the harness consumer is a set).
fn flat_txs(tag: u64, n: usize) -> Vec<Transaction> {
    (0..n)
        .map(|i| {
            Transaction::new(
                [[0u8; 32]; 2],
                [(tag & 0xff) as u8; 32],
                [0xAA; 32],
                tag * 1_000 + i as u64,
                1,
                1_700_000_000_000 + tag * 1_000 + i as u64,
                i as u64,
                0,
                vec![0u8; 64],
                vec![0u8; 32],
            )
        })
        .collect()
}

/// Ancestor-closed chain: each tx's parents are the previous two (the first
/// references the provided base tip twice).
fn chain_from(base: [u8; 32], tag: u64, n: usize) -> Vec<Transaction> {
    let mut prev = base;
    let mut prev2 = base;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let tx = Transaction::new(
            [prev, prev2],
            [(tag & 0xff) as u8; 32],
            [0xBB; 32],
            tag * 10_000 + i as u64,
            1,
            1_700_000_000_000 + tag * 10_000 + i as u64,
            i as u64,
            0,
            vec![0u8; 64],
            vec![0u8; 32],
        );
        prev2 = prev;
        prev = tx.id;
        out.push(tx);
    }
    out
}

fn tx_map(txs: &[Transaction]) -> Arc<HashMap<[u8; 32], Transaction>> {
    Arc::new(txs.iter().map(|t| (t.id, t.clone())).collect())
}

/// A vote with a canonical, decodable (but deliberately unverifiable)
/// signature. The receive stage is format-only by design; admission is
/// downstream and is not what this suite exercises.
fn craft_vote(tag: u64) -> Vote {
    Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: DEFAULT_NETWORK_ID,
        validator: [(tag & 0xff) as u8; 32],
        epoch: 1,
        conflict_sender: [0x11; 32],
        conflict_nonce: tag,
        side: [0x22; 32],
        stake_epoch: 1,
        stake_amount: 1_000,
        parents: [[0u8; 32]; 2],
        signature: [0u8; 64],
    }
}

// ---------------------------------------------------------------------------
// Raw wire peer (mirror of the production handshake/frame format)
// ---------------------------------------------------------------------------

struct RawPeer {
    writer: tokio::net::tcp::OwnedWriteHalf,
    reader: tokio::net::tcp::OwnedReadHalf,
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
            reader,
            key,
            dir,
            counter: 0,
        }
    }

    async fn handshake(
        reader: &mut (impl AsyncReadExt + Unpin),
        writer: &mut (impl AsyncWriteExt + Unpin),
    ) -> ([u8; 32], u8) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut outgoing = Vec::with_capacity(HANDSHAKE_LEN);
        outgoing.extend_from_slice(&WIRE_MAGIC);
        outgoing.push(P2P_PROTOCOL_VERSION);
        outgoing.extend_from_slice(&GENESIS_HASH);
        outgoing.extend_from_slice(&DEFAULT_NETWORK_ID.to_le_bytes());
        outgoing.extend_from_slice(public.as_bytes());
        writer.write_all(&outgoing).await.expect("hs write");
        let mut incoming = [0u8; HANDSHAKE_LEN];
        tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut incoming))
            .await
            .expect("server handshake reply must not hang")
            .expect("server handshake reply");
        assert_eq!(&incoming[..4], &WIRE_MAGIC, "server wire magic");
        assert_eq!(incoming[4], P2P_PROTOCOL_VERSION, "server protocol version");
        assert_eq!(&incoming[5..37], &GENESIS_HASH, "server genesis");
        let mut peer_pk = [0u8; 32];
        peer_pk.copy_from_slice(&incoming[HANDSHAKE_LEN - 32..]);
        let shared = secret.diffie_hellman(&PublicKey::from(peer_pk));
        let mut hasher = Sha256::new();
        hasher.update(b"aether-p2p-key-v1");
        hasher.update(shared.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        let dir = if public.as_bytes() < &peer_pk {
            0x01
        } else {
            0x02
        };
        (key, dir)
    }

    async fn send(&mut self, msg: &P2PMessage) {
        let payload = bincode::serialize(msg).expect("serialize P2PMessage");
        let unpadded = FRAME_FIXED_OVERHEAD + payload.len();
        assert!(unpadded <= 16 * 1024 * 1024 - FRAME_PAD_BUCKET, "pad cap");
        let pad = (FRAME_PAD_BUCKET - (unpadded % FRAME_PAD_BUCKET)) % FRAME_PAD_BUCKET;
        let mut padded = Vec::with_capacity(payload.len() + pad + 2);
        padded.extend_from_slice(&payload);
        padded.resize(payload.len() + pad, 0u8);
        padded.extend_from_slice(&(pad as u16).to_le_bytes());
        self.counter += 1;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.counter.to_be_bytes());
        nonce_bytes[8] = self.dir;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), padded.as_ref())
            .expect("seal");
        let total_len = 12 + ciphertext.len();
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

    /// Mirror of the production frame read. `None` on timeout/EOF/decode
    /// failure (all three mean "nothing more arrived").
    async fn recv(&mut self, timeout: Duration) -> Option<P2PMessage> {
        let mut len_buf = [0u8; 4];
        tokio::time::timeout(timeout, self.reader.read_exact(&mut len_buf))
            .await
            .ok()?
            .ok()?;
        let total_len = u32::from_be_bytes(len_buf) as usize;
        assert!(total_len >= FRAME_PAD_BUCKET, "frame len floor");
        assert_eq!(total_len % FRAME_PAD_BUCKET, 0, "frame bucket alignment");
        let mut buf = vec![0u8; total_len];
        tokio::time::timeout(timeout, self.reader.read_exact(&mut buf))
            .await
            .ok()?
            .ok()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let padded = cipher
            .decrypt(Nonce::from_slice(&buf[..12]), &buf[12..])
            .ok()?;
        assert!(padded.len() >= 2, "pad tail present");
        let pad = u16::from_le_bytes([padded[padded.len() - 2], padded[padded.len() - 1]]) as usize;
        let payload = &padded[..padded.len() - 2 - pad];
        bincode::deserialize::<P2PMessage>(payload).ok()
    }

    /// Collect every `SyncResponse` page available within `idle` of silence.
    async fn collect_pages(&mut self, idle: Duration) -> Vec<Vec<Vec<u8>>> {
        let mut pages = Vec::new();
        loop {
            match self.recv(idle).await {
                Some(P2PMessage::SyncResponse(items)) => pages.push(items),
                Some(_) => continue,
                None => return pages,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Node harness
// ---------------------------------------------------------------------------

struct Harness {
    net: P2PNetwork,
    rx: mpsc::Receiver<IngressTx>,
    sync_ctx: Arc<SyncContext>,
}

fn boot_node(
    port: u16,
    store: Arc<HashMap<[u8; 32], Transaction>>,
    order: Vec<Vec<u8>>,
) -> Harness {
    let (tx, rx) = mpsc::channel::<IngressTx>(TX_INGRESS_CAPACITY_MSGS);
    let hashes = Arc::new(order);
    let get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> =
        Arc::new(move || hashes.as_ref().clone());
    let get_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(move |h| {
        let mut id = [0u8; 32];
        if h.len() == 32 {
            id.copy_from_slice(h);
            store.get(&id).cloned()
        } else {
            None
        }
    });
    let tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
    let sync_ctx = Arc::new(SyncContext::default());
    let net = P2PNetwork::new_with_transport(
        P2PConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: DEFAULT_NETWORK_ID,
        },
        tx,
        get_dag_hashes,
        get_by_hash,
        tips,
        Arc::clone(&sync_ctx),
        Arc::new(|_| false),
        Arc::new(RejectAllTransport),
    );
    Harness { net, rx, sync_ctx }
}

async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("TIMEOUT waiting for: {}", what);
}

async fn wait_peers(net: &P2PNetwork, want: usize) {
    wait_for(
        &format!("peer_count == {}", want),
        Duration::from_secs(15),
        || async { net.peer_count().await == want },
    )
    .await;
}

/// Drain everything currently queued into the modelled funnel. Returns the
/// number of newly applied ids; duplicates (id already in the set) are
/// counted separately, mirroring `dag.add_transaction_validated`.
fn drain_ingress(
    rx: &mut mpsc::Receiver<IngressTx>,
    applied: &mut HashSet<[u8; 32]>,
    duplicates: &mut u64,
) -> usize {
    let mut newly = 0;
    while let Ok(item) = rx.try_recv() {
        let tx = item.into_tx();
        if applied.insert(tx.id) {
            newly += 1;
        } else {
            *duplicates += 1;
        }
    }
    newly
}

// ---------------------------------------------------------------------------
// ba01 — ingress saturation: cap, byte budget, refusal visibility, recovery
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ba01_ingress_saturation_refuses_visibly_and_recovers() {
    const PORT: u16 = 44841;
    let (base_store, base_order, base_tip) = {
        let base = chain_from([0u8; 32], 1, 2);
        let tip = base.last().unwrap().id;
        (
            tx_map(&base),
            base.iter().map(|t| t.id.to_vec()).collect::<Vec<_>>(),
            tip,
        )
    };
    let mut h = boot_node(PORT, base_store, base_order);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");

    let mut p1 = RawPeer::connect(PORT).await;
    let mut p2 = RawPeer::connect(PORT).await;
    let mut p3 = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 3).await;

    let limits = h.net.queue_limits();
    assert_eq!(limits.tx_ingress_msgs, TX_INGRESS_CAPACITY_MSGS);
    assert_eq!(limits.tx_ingress_bytes, TX_INGRESS_CAPACITY_BYTES);

    // Fill the queue while the consumer is intentionally not draining: three
    // providers gossip 264 distinct transactions.
    let fill: Vec<Transaction> = flat_txs(10, 264);
    let extras = &fill[256..];
    for (peer, range) in [(&mut p1, 0..90), (&mut p2, 90..177), (&mut p3, 177..264)] {
        for tx in &fill[range] {
            peer.send(&P2PMessage::Transaction(bincode::serialize(tx).unwrap()))
                .await;
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
    }

    // Exactly the capacity is admitted; nothing was consumed.
    wait_for(
        "ingress queue at capacity",
        Duration::from_secs(20),
        || async { h.rx.len() == TX_INGRESS_CAPACITY_MSGS },
    )
    .await;
    assert_eq!(
        h.net.ingress_drops(),
        8,
        "264 arrivals: 256 admitted, 8 refused"
    );
    assert!(h.rx.len() <= TX_INGRESS_CAPACITY_MSGS);

    // While FULL: eight new payloads plus three duplicate copies of an
    // already-attempted extra are all refused — and, crucially, none of them
    // is marked seen, which the recovery phase below proves by re-admitting
    // them successfully.
    for tx in extras {
        p1.send(&P2PMessage::Transaction(bincode::serialize(tx).unwrap()))
            .await;
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    let dup_payload = bincode::serialize(&extras[0]).unwrap();
    for peer in [&mut p1, &mut p2, &mut p3] {
        peer.send(&P2PMessage::Transaction(dup_payload.clone()))
            .await;
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        h.rx.len(),
        TX_INGRESS_CAPACITY_MSGS,
        "queue never exceeds cap"
    );
    assert_eq!(
        h.net.ingress_drops(),
        19,
        "8 overflow arrivals + 8 extras + 3 duplicates refused"
    );
    let reserved = h.net.ingress_reserved_bytes();
    assert!(reserved > 0, "byte budget accounts for the queued payloads");
    assert!(
        reserved <= limits.tx_ingress_bytes,
        "reserved bytes ({}) exceed the budget ({})",
        reserved,
        limits.tx_ingress_bytes
    );

    // Recover: drain the models funnel.
    let mut applied: HashSet<[u8; 32]> = HashSet::new();
    let mut duplicates = 0u64;
    assert_eq!(drain_ingress(&mut h.rx, &mut applied, &mut duplicates), 256);
    assert_eq!(
        h.net.ingress_reserved_bytes(),
        0,
        "reservations released on dequeue"
    );
    assert!(applied.iter().all(|id| !extras.iter().any(|t| t.id == *id)));

    // The refused payloads were NOT poisoned as seen: re-gossip on a
    // different peer succeeds. A trailing duplicate copy is absorbed by the
    // wire seen-cache (it is dedup, not a drop) so it never reaches the
    // funnel — funnel idempotence is covered by the attribute tests.
    let drops_before = h.net.ingress_drops();
    for tx in extras {
        p2.send(&P2PMessage::Transaction(bincode::serialize(tx).unwrap()))
            .await;
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    p3.send(&P2PMessage::Transaction(
        bincode::serialize(&extras[1]).unwrap(),
    ))
    .await;
    wait_for(
        "re-gossip admitted after refusal",
        Duration::from_secs(10),
        || async { h.rx.len() == 8 },
    )
    .await;
    assert_eq!(h.net.ingress_drops(), drops_before, "dedup is not a drop");
    assert_eq!(drain_ingress(&mut h.rx, &mut applied, &mut duplicates), 8);
    assert_eq!(
        duplicates, 0,
        "duplicate absorbed by seen-cache, never queued"
    );
    assert_eq!(applied.len(), 264, "every payload applied exactly once");

    // ------------------------------------------------------------------
    // Same contract on the SyncResponse ingress path: 3 self-contained
    // ancestor-closed pages (100 each) against a 256-slot queue. The page
    // items are NOT in the store (so they are not wire-duplicates); each
    // page hangs off the pre-seeded base tip so partition_batch delivers it.
    // ------------------------------------------------------------------
    let pages: Vec<Vec<Transaction>> = (0..3).map(|p| chain_from(base_tip, 20 + p, 100)).collect();
    let admitted_registered: Vec<[u8; 32]> = pages[0].iter().take(32).map(|tx| tx.id).collect();
    let refused_registered: Vec<[u8; 32]> = pages[2]
        .iter()
        .skip(56)
        .take(32)
        .map(|tx| tx.id)
        .collect();
    // Frontier marks are only recorded for ids the node actually requested.
    // Register 64 (the in-flight cap): 32 admitted in page 1, and 32 in page
    // 3's refused tail (indices 56..88). If marks were recorded BEFORE
    // admission, the refused tail would show up as received.
    {
        let peer = sock_of(&p1);
        let mut frontier = h.sync_ctx.frontier.write().await;
        for id in admitted_registered
            .iter()
            .chain(refused_registered.iter())
            .cloned()
        {
            assert!(frontier.add_pending(id.to_vec()));
            assert!(frontier.mark_requested(&id, peer));
        }
    }
    for page in &pages {
        let payload: Vec<Vec<u8>> = page
            .iter()
            .map(|t| bincode::serialize(t).unwrap())
            .collect();
        p1.send(&P2PMessage::SyncResponse(payload)).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    wait_for(
        "sync ingress at capacity",
        Duration::from_secs(15),
        || async { h.rx.len() == TX_INGRESS_CAPACITY_MSGS && h.net.ingress_drops() == 63 },
    )
    .await;
    assert_eq!(
        h.net.ingress_drops(),
        63,
        "19 earlier + page 3 exceeds the queue by 44 items"
    );
    assert!(
        h.net.ingress_reserved_bytes() <= limits.tx_ingress_bytes,
        "sync ingress stays inside the byte budget"
    );
    // Queue admission is not DAG insertion: the 32 registered ids that were
    // admitted are Received, while the 32 refused with page 3's tail remain
    // Requested. Neither set may be marked Applied yet.
    {
        let frontier = h.sync_ctx.frontier.read().await;
        for id in &admitted_registered {
            assert_eq!(frontier.entry_state(id), Some(PageState::Received));
        }
        for id in &refused_registered {
            assert_eq!(frontier.entry_state(id), Some(PageState::Requested));
        }
        assert_eq!(
            frontier.applied_count(),
            0,
            "queue admission must NOT be marked as applied"
        );
    }

    assert_eq!(drain_ingress(&mut h.rx, &mut applied, &mut duplicates), 256);
    assert_eq!(h.net.ingress_reserved_bytes(), 0);

    // Model the production drainer: only the payloads really inserted into
    // the DAG become Applied. The refused tail was never dequeued.
    {
        let mut frontier = h.sync_ctx.frontier.write().await;
        for id in &admitted_registered {
            assert!(frontier.mark_applied(id));
        }
    }
    assert_eq!(h.sync_ctx.frontier.read().await.applied_count(), 32);
    {
        let frontier = h.sync_ctx.frontier.read().await;
        for id in &refused_registered {
            assert_eq!(frontier.entry_state(id), Some(PageState::Requested));
        }
    }

    // Re-deliver page 3 (the saturated one): the 44 refused items are
    // admitted, the 56 already-inserted items are re-delivered duplicates the
    // funnel rejects. Final state: 300 sync txs applied once.
    let third: Vec<Vec<u8>> = pages[2]
        .iter()
        .map(|t| bincode::serialize(t).unwrap())
        .collect();
    p1.send(&P2PMessage::SyncResponse(third)).await;
    wait_for("re-delivered page admitted", Duration::from_secs(10), || async {
        h.rx.len() == 100
            && {
                let frontier = h.sync_ctx.frontier.read().await;
                refused_registered
                    .iter()
                    .all(|id| frontier.entry_state(id) == Some(PageState::Received))
            }
    })
    .await;
    let newly = drain_ingress(&mut h.rx, &mut applied, &mut duplicates);
    assert_eq!(newly, 44, "exactly the refused tail is new");
    {
        let mut frontier = h.sync_ctx.frontier.write().await;
        for id in &refused_registered {
            assert!(frontier.mark_applied(id));
        }
    }
    assert_eq!(
        h.sync_ctx.frontier.read().await.applied_count(),
        64,
        "the re-admitted tail is now applied (32 + 32)"
    );
    println!(
        "BA01 ingress_msgs={} ingress_bytes={} drops_total={} applied={} dup={} reserved_after=0",
        limits.tx_ingress_msgs,
        limits.tx_ingress_bytes,
        h.net.ingress_drops(),
        applied.len(),
        duplicates
    );

    drop(p1);
    drop(p2);
    drop(p3);
    h.net.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// ba02 — slow peer: outbound bound, isolation, request/reconnect recovery
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ba02_slow_peer_outbound_queue_is_bounded_and_recovers() {
    const PORT: u16 = 44842;
    let dag = chain_from([0u8; 32], 2, 60);
    let store = tx_map(&dag);
    let order: Vec<Vec<u8>> = dag.iter().map(|t| t.id.to_vec()).collect();
    let tip = dag.last().unwrap().id;
    let mut h = boot_node(PORT, store, order);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");

    let mut slow = RawPeer::connect(PORT).await;
    let mut normal = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 2).await;
    let limits = h.net.queue_limits();

    // Normal peer sends a transaction; it must reach ingress even while the
    // slow peer's session is being saturated.
    let gossip = flat_txs(77, 1).remove(0);
    normal
        .send(&P2PMessage::Transaction(
            bincode::serialize(&gossip).unwrap(),
        ))
        .await;

    // Storm: identical GetData requests, peer reading NOTHING. The volume
    // must exceed the largest plausible kernel buffering (Linux loopback
    // autotuning can absorb ~10 MiB across send+receive buffers), so the
    // writer blocks and the bounded queue itself must refuse; Windows fills
    // its much smaller buffers long before this. Batches stay well below the
    // 400 msgs/s read-path flood limit (a burst is a ban, not a drop), and
    // the ~19 MiB volume still finishes inside the 15s write timeout.
    const BATCH: usize = 200;
    const BATCHES: usize = 6;
    let requests = BATCH * BATCHES;
    let mut max_slow_queue = 0usize;
    for batch in 0..BATCHES {
        for _ in 0..BATCH {
            slow.send(&P2PMessage::GetData(vec![tip.to_vec()])).await;
            if let Some(q) = h.net.session_queued_bytes(sock_of(&slow)).await {
                max_slow_queue = max_slow_queue.max(q);
                assert!(
                    q <= limits.session_bytes,
                    "session queue bytes {} exceed bound {}",
                    q,
                    limits.session_bytes
                );
            }
        }
        if batch + 1 < BATCHES {
            tokio::time::sleep(Duration::from_millis(1050)).await;
        }
    }
    // Keep not reading: the writer blocks on TCP and the bounded queue fills.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if let Some(q) = h.net.session_queued_bytes(sock_of(&slow)).await {
            max_slow_queue = max_slow_queue.max(q);
            assert!(q <= limits.session_bytes);
        }
    }
    assert!(
        h.net.session_drops() > 0,
        "a stalled peer must cause explicit refusals, not unbounded buffering"
    );
    let queued_now = h.net.session_queued_bytes(sock_of(&slow)).await;
    assert!(queued_now.is_some(), "slow session still registered");
    assert!(queued_now.unwrap() <= limits.session_bytes);

    // Normal peer is unaffected: a GetData request is served in full.
    normal.send(&P2PMessage::GetData(vec![tip.to_vec()])).await;
    let pages = normal.collect_pages(Duration::from_secs(3)).await;
    let normal_ids: HashSet<[u8; 32]> = pages
        .iter()
        .flatten()
        .map(|b| bincode::deserialize::<Transaction>(b).unwrap().id)
        .collect();
    assert_eq!(normal_ids.len(), 60, "normal peer gets the full closure");
    // ...and its gossip reached the (paused) node ingress.
    let mut applied = HashSet::new();
    let mut duplicates = 0u64;
    assert_eq!(drain_ingress(&mut h.rx, &mut applied, &mut duplicates), 1);
    assert!(applied.contains(&gossip.id));
    assert_eq!(h.net.peer_count().await, 2);

    // The slow peer resumes reading: it gets SOME pages (the ones whose bytes
    // were already accepted) but strictly fewer than the requests sent —
    // the rest were refused, not silently buffered.
    let first_pages = slow.collect_pages(Duration::from_secs(10)).await;
    let first_ids: HashSet<[u8; 32]> = first_pages
        .iter()
        .flatten()
        .map(|b| bincode::deserialize::<Transaction>(b).unwrap().id)
        .collect();
    assert_eq!(first_ids.len(), 60, "each served page is ancestor-complete");
    assert!(
        first_pages.len() < requests,
        "pre-fix verification: expected refusals, got {} pages",
        first_pages.len()
    );

    // Recovery 1 (same session): a new request is still served.
    slow.send(&P2PMessage::GetData(vec![tip.to_vec()])).await;
    let after_req = slow.collect_pages(Duration::from_secs(5)).await;
    assert!(
        !after_req.is_empty(),
        "requests keep working after saturation"
    );

    // Recovery 2 (session loss): close, wait for teardown, reconnect fresh.
    drop(slow);
    wait_peers(&h.net, 1).await;
    let mut fresh = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 2).await;
    fresh.send(&P2PMessage::GetData(vec![tip.to_vec()])).await;
    let pages = fresh.collect_pages(Duration::from_secs(5)).await;
    let ids: HashSet<[u8; 32]> = pages
        .iter()
        .flatten()
        .map(|b| bincode::deserialize::<Transaction>(b).unwrap().id)
        .collect();
    assert_eq!(ids.len(), 60, "fresh session recovers the full closure");
    assert!(h.net.session_queued_bytes(sock_of(&fresh)).await.is_some());

    println!(
        "BA02 requests={} pages_first={} max_session_bytes={} bound_bytes={} drops={} sessions_after=2",
        requests,
        first_pages.len(),
        max_slow_queue,
        limits.session_bytes,
        h.net.session_drops()
    );

    drop(normal);
    drop(fresh);
    h.net.shutdown().await.expect("shutdown");
}

/// The raw peer's local address is not exposed by `RawPeer`; the session map
/// keys on the client's ephemeral loopback address. These tests use a single
/// slow peer at a time, so they take the address from the node's peer list by
/// excluding the address of the other, freshly known peer when possible. To
/// keep this deterministic we record the address at connect time instead.
fn sock_of(peer: &RawPeer) -> SocketAddr {
    // `TcpStream::local_addr` is not copied into RawPeer, so recover it from
    // the reader half (both halves expose the same local endpoint).
    peer.reader.local_addr().expect("raw local addr")
}

// ---------------------------------------------------------------------------
// ba03 — stake channel: bounded, back-pressure, zero loss
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ba03_full_stake_queue_applies_backpressure_without_loss() {
    const PORT: u16 = 44843;
    // Empty tx DAG; stake traffic and one gossip tx are all this test needs.
    let mut h = boot_node(PORT, Arc::new(HashMap::new()), Vec::new());
    // Stake receiver is HELD (not consumed) so the bounded channel can fill.
    let (stake_tx, mut stake_rx) = mpsc::channel::<StakePayload>(STAKE_CHANNEL_CAPACITY_MSGS);
    h.net.set_stake_channel(stake_tx);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");
    let limits = h.net.queue_limits();
    assert_eq!(limits.stake_msgs, STAKE_CHANNEL_CAPACITY_MSGS);

    let mut voter = RawPeer::connect(PORT).await;
    let mut other = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 2).await;

    let votes: Vec<Vote> = (0..300).map(craft_vote).collect();
    let vote_ids: HashSet<[u8; 32]> = votes.iter().map(|v| v.id()).collect();
    assert_eq!(vote_ids.len(), 300);

    // Send at < 400 msg/s (per-session flood gate) while nobody consumes.
    for v in &votes {
        voter.send(&P2PMessage::Vote(v.encode())).await;
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    // Back-pressure: the queue sits exactly at capacity; the session task is
    // blocked in `send().await`, NOT dropping. No loss counter exists for
    // stake by design.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        stake_rx.len(),
        STAKE_CHANNEL_CAPACITY_MSGS,
        "stake queue is bounded at capacity, with the sender blocked"
    );

    // Another peer's transaction is still admitted: one blocked session does
    // not freeze the node.
    let other_tx = flat_txs(88, 1).remove(0);
    other
        .send(&P2PMessage::Transaction(
            bincode::serialize(&other_tx).unwrap(),
        ))
        .await;
    let mut applied = HashSet::new();
    let mut duplicates = 0u64;
    wait_for(
        "other peer tx admitted",
        Duration::from_secs(10),
        || async { !h.rx.is_empty() },
    )
    .await;
    assert_eq!(drain_ingress(&mut h.rx, &mut applied, &mut duplicates), 1);
    assert!(applied.contains(&other_tx.id));

    // Drain and prove ALL 300 votes arrive exactly once (the blocked sends
    // resume as slots free up).
    let mut received: HashSet<[u8; 32]> = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while received.len() < 300 && Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), stake_rx.recv()).await {
            Ok(Some(StakePayload::Vote(v))) => {
                assert!(received.insert(v.id()), "duplicate stake delivery");
            }
            Ok(Some(_)) => panic!("unexpected stake payload kind"),
            Ok(None) => break,
            Err(_) => {}
        }
    }
    assert_eq!(received.len(), 300, "no stake payload is ever lost");
    assert_eq!(received, vote_ids);
    assert_eq!(stake_rx.len(), 0);

    println!(
        "BA03 stake_msgs={} queued_at_capacity={} delivered={} loss=0",
        limits.stake_msgs,
        STAKE_CHANNEL_CAPACITY_MSGS,
        received.len()
    );

    drop(voter);
    drop(other);
    h.net.shutdown().await.expect("shutdown");
}

// ---------------------------------------------------------------------------
// ba04 — repeatability: 3 fill/refuse/drain cycles, accounting returns to 0
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ba04_repeated_saturation_cycles_are_deterministic_and_leak_free() {
    const PORT: u16 = 44844;
    let mut h = boot_node(PORT, Arc::new(HashMap::new()), Vec::new());
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");
    let mut p1 = RawPeer::connect(PORT).await;
    let mut p2 = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 2).await;

    let mut applied: HashSet<[u8; 32]> = HashSet::new();
    let mut duplicates = 0u64;
    let mut expected_drops = 0u64;

    for cycle in 0..3u64 {
        let fill = flat_txs(100 + cycle, TX_INGRESS_CAPACITY_MSGS + 4);
        let extras = &fill[TX_INGRESS_CAPACITY_MSGS..];
        for (i, tx) in fill.iter().enumerate() {
            let peer = if i % 2 == 0 { &mut p1 } else { &mut p2 };
            peer.send(&P2PMessage::Transaction(bincode::serialize(tx).unwrap()))
                .await;
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        expected_drops += 4;
        wait_for("cycle: full + refused", Duration::from_secs(15), || async {
            h.rx.len() == TX_INGRESS_CAPACITY_MSGS && h.net.ingress_drops() == expected_drops
        })
        .await;
        assert!(
            h.net.ingress_reserved_bytes() <= TX_INGRESS_CAPACITY_BYTES,
            "cycle {} exceeded the byte budget",
            cycle
        );
        let before = applied.len();
        let newly = drain_ingress(&mut h.rx, &mut applied, &mut duplicates);
        assert_eq!(newly, TX_INGRESS_CAPACITY_MSGS);
        assert_eq!(applied.len(), before + TX_INGRESS_CAPACITY_MSGS);
        assert_eq!(
            h.net.ingress_reserved_bytes(),
            0,
            "cycle {}: ingress reservations return to zero",
            cycle
        );
        assert!(
            extras.iter().all(|t| !applied.contains(&t.id)),
            "cycle {}: refused payloads are absent from the funnel",
            cycle
        );
    }

    assert_eq!(applied.len(), 3 * TX_INGRESS_CAPACITY_MSGS);
    assert_eq!(duplicates, 0);
    assert_eq!(h.net.ingress_drops(), 12);
    assert_eq!(h.net.peer_count().await, 2, "sessions survived all cycles");

    println!(
        "BA04 cycles=3 per_cycle={} refused_total={} applied={} reserved_after=0",
        TX_INGRESS_CAPACITY_MSGS,
        h.net.ingress_drops(),
        applied.len()
    );

    drop(p1);
    drop(p2);
    h.net.shutdown().await.expect("shutdown");
}
