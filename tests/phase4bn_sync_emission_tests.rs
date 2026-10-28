//! 4CP-BN: decoupled SyncResponse emission — reader responsiveness, explicit
//! refusals, per-request page order, and transient-saturation recovery.
//!
//! These four tests pin the PROPERTIES the BA02 fix must provide, not just the
//! BA02 verdict:
//!
//! * `bn01_*` (A) — while a peer's SyncResponse emission is stalled against a
//!   peer that reads nothing, the SESSION READER still processes other
//!   messages from that same peer. Pre-fix the reader was parked inside
//!   `timeout(30s, msg_sender.send()).await`, so this message could only be
//!   observed after the emission timeout expired (or never, with the queue
//!   full). The assertion window is 5s, i.e. strictly inside the 30s page
//!   timeout: passing cannot be explained by the timeout firing.
//! * `bn02_*` (B) — saturating a non-reading peer produces EXPLICIT refusals:
//!   `session_drops` moves, the queue stays inside its byte bound, no global
//!   budget refusal appears, every delivered page is a whole ancestor closure
//!   (never a truncated page), and no page ever reached the 30s timeout.
//! * `bn03_*` (C) — pages of one request are emitted in topological order and
//!   responses of successive requests on one session keep request order, both
//!   while another session is saturated.
//! * `bn04_*` (D) — a transient consumer stall recovers: queued responses are
//!   delivered when the peer resumes, a fresh request is served, the queue
//!   drains to zero, and the counters stop moving (no re-request storm, no
//!   lingering backlog).
//!
//! No PoW is mined here: these tests exercise the session/queue contract with
//! synthetic transactions (the same harness style as phase 4BA). Consensus is
//! covered by AY/AZ/BD/BE.
//!
//! Ports 44851-44854 are unique to this suite (44841-44844 = 4BA).

use aether_unified::genesis::GENESIS_HASH;
use aether_unified::p2p::{
    IngressTx, P2PConfig, P2PMessage, P2PNetwork, P2PProtocolMode, P2P_PROTOCOL_VERSION,
    TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::sync_stats::SyncContext;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
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
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};

const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;
const FRAME_PAD_BUCKET: usize = 256;
const FRAME_FIXED_OVERHEAD: usize = 30;

/// Page timeout used by the production responder (30s). The reader-hang
/// assertions below must succeed well inside it.
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);

struct RejectAllTransport;

impl Transport for RejectAllTransport {
    fn dial(&self, _addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
        Box::pin(async move {
            Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "4BN test transport: outbound dial refused",
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
// Synthetic ancestor chain (no PoW)
// ---------------------------------------------------------------------------

/// Ancestor-closed chain: each tx's parents are the previous two (the first
/// references the provided base tip twice). Index order IS a topological
/// order: parents always precede children.
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

/// Free-standing tx (distinct id, no parent requirement) used as gossip.
fn flat_tx(tag: u64) -> Transaction {
    Transaction::new(
        [[0u8; 32]; 2],
        [(tag & 0xff) as u8; 32],
        [0xAA; 32],
        tag,
        1,
        1_700_000_000_000 + tag,
        0,
        0,
        vec![0u8; 64],
        vec![0u8; 32],
    )
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

fn sock_of(peer: &RawPeer) -> SocketAddr {
    peer.reader.local_addr().expect("raw local addr")
}

fn page_ids(page: &[Vec<u8>]) -> Vec<[u8; 32]> {
    page.iter()
        .map(|b| {
            bincode::deserialize::<Transaction>(b)
                .expect("page item is a Transaction")
                .id
        })
        .collect()
}

/// Every tx in `page` must come AFTER all of its parents that are also in the
/// page: the serving contract is "ancestors first, no orphans".
fn assert_topological(page: &[Vec<u8>], what: &str) {
    let ids = page_ids(page);
    let present: HashSet<[u8; 32]> = ids.iter().copied().collect();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for bytes in page {
        let tx = bincode::deserialize::<Transaction>(bytes).expect("tx");
        for parent in tx.parents.iter() {
            if *parent == [0u8; 32] || !present.contains(parent) {
                continue;
            }
            assert!(
                seen.contains(parent),
                "{}: tx {:02x?} emitted before its parent {:02x?}",
                what,
                &tx.id[..4],
                &parent[..4]
            );
        }
        seen.insert(tx.id);
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

fn boot_node(port: u16, store: Arc<HashMap<[u8; 32], Transaction>>, order: Vec<Vec<u8>>) -> Harness {
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

/// Drive `count` GetData requests from a peer that reads NOTHING, in bursts
/// that stay below the 400 msgs/s read-path flood gate.
async fn saturate(peer: &mut RawPeer, tip: [u8; 32], batches: usize) {
    const BATCH: usize = 200;
    for batch in 0..batches {
        for _ in 0..BATCH {
            peer.send(&P2PMessage::GetData(vec![tip.to_vec()])).await;
        }
        if batch + 1 < batches {
            tokio::time::sleep(Duration::from_millis(1050)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// A — the reader keeps processing messages while emission is stalled
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bn01_reader_processes_messages_while_emission_is_stalled() {
    const PORT: u16 = 44851;
    const BATCHES: usize = 3;
    const REQUESTS: usize = 200 * BATCHES;

    let chain = chain_from([0u8; 32], 11, 60);
    let store = tx_map(&chain);
    let order: Vec<Vec<u8>> = chain.iter().map(|t| t.id.to_vec()).collect();
    let tip = chain.last().unwrap().id;
    let mut h = boot_node(PORT, store, order);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");

    let mut slow = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 1).await;
    let limits = h.net.queue_limits();

    // Storm against a peer that never reads: the session writer blocks on TCP
    // and the bounded queues fill, so the responder is parked inside a page
    // handoff that cannot complete.
    saturate(&mut slow, tip, BATCHES).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let queued = h
        .net
        .session_queued_bytes(sock_of(&slow))
        .await
        .expect("stalled session is still registered");
    assert!(queued > 0, "the stalled session must still hold queued bytes");
    assert!(queued <= limits.session_bytes, "session queue stays bounded");
    let drops_before = h.net.session_drops();

    // THE PROPERTY: a further message from the SAME stalled session is read
    // and processed now — strictly inside the 30s page timeout, so this cannot
    // be explained by the timeout releasing the reader.
    let gossip = flat_tx(0x4B4E_0001);
    let sent_at = Instant::now();
    slow.send(&P2PMessage::Transaction(
        bincode::serialize(&gossip).unwrap(),
    ))
    .await;
    let admitted = tokio::time::timeout(Duration::from_secs(5), h.rx.recv())
        .await
        .expect("reader must process a same-session message while emission is stalled")
        .expect("ingress channel alive")
        .into_tx();
    let latency = sent_at.elapsed();

    assert_eq!(admitted.id, gossip.id, "the gossip tx reached ingress");
    assert!(
        latency < Duration::from_secs(5) && latency < PAGE_TIMEOUT,
        "same-session message was read in {:?}; a reader blocked in the page \
         handoff could only observe it after the {:?} timeout",
        latency,
        PAGE_TIMEOUT
    );
    assert!(
        drops_before > 0,
        "the storm must have produced explicit refusals (a reader parked in the \
         handoff instead silently buffers)"
    );
    // The emission was NOT quietly abandoned to make the reader responsive.
    let queued_after = h.net.session_queued_bytes(sock_of(&slow)).await;
    assert!(
        queued_after.is_some(),
        "session must remain registered after the storm"
    );
    assert!(
        h.net.session_queued_bytes(sock_of(&slow)).await.unwrap() > 0,
        "emission is still saturated after the reader processed the message"
    );

    println!(
        "BN01 requests={} queued_before={} queued_after={} drop_refusals={} gossip_latency={:?} page_timeout={:?}",
        REQUESTS,
        queued,
        queued_after.unwrap(),
        drops_before,
        latency,
        PAGE_TIMEOUT
    );
}

// ---------------------------------------------------------------------------
// B — refusals are explicit, counted, and never truncated
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bn02_refusals_are_explicit_counted_and_whole() {
    const PORT: u16 = 44852;
    const BATCHES: usize = 3;
    const REQUESTS: usize = 200 * BATCHES;

    let chain = chain_from([0u8; 32], 12, 60);
    let store = tx_map(&chain);
    let order: Vec<Vec<u8>> = chain.iter().map(|t| t.id.to_vec()).collect();
    let tip = chain.last().unwrap().id;
    let mut h = boot_node(PORT, store, order);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");

    let mut slow = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 1).await;
    let limits = h.net.queue_limits();

    saturate(&mut slow, tip, BATCHES).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let drops = h.net.session_drops();
    assert!(drops > 0, "saturation must be refused, not buffered forever");
    assert!(
        drops <= REQUESTS as u64,
        "refusals are counted once per refused request ({} drops for {} requests)",
        drops,
        REQUESTS
    );
    assert_eq!(
        h.net.outbound_budget_drops(),
        0,
        "the refusals are session-local, never global-budget evictions"
    );
    assert!(
        h.net.session_queued_bytes(sock_of(&slow)).await.unwrap() <= limits.session_bytes,
        "no refusal path may bypass the byte bound"
    );
    assert_eq!(
        h.sync_ctx
            .stats
            .sync_response_timeouts
            .load(Ordering::Relaxed),
        0,
        "refusals must be decided immediately at admission, not by waiting out a page timeout"
    );

    // Resume reading: what was accepted is delivered, and it is delivered
    // WHOLE (each page is a complete ancestor closure of 60 txs).
    let pages = slow.collect_pages(Duration::from_secs(5)).await;
    assert!(
        !pages.is_empty(),
        "the requests that WERE admitted must still be delivered"
    );
    assert!(
        pages.len() < REQUESTS,
        "an unbounded queue would have delivered all {} requests (got {})",
        REQUESTS,
        pages.len()
    );
    for (i, page) in pages.iter().enumerate() {
        assert_eq!(
            page.len(),
            60,
            "page {} carries a truncated closure ({} of 60 txs)",
            i,
            page.len()
        );
        assert_topological(page, &format!("bn02 page {}", i));
    }

    println!(
        "BN02 requests={} pages_served={} refused={} bound_bytes={} max_queued_seen={} global_drops={} timeouts=0",
        REQUESTS,
        pages.len(),
        drops,
        limits.session_bytes,
        h.net.session_queued_bytes(sock_of(&slow)).await.unwrap_or(0),
        h.net.outbound_budget_drops()
    );
}

// ---------------------------------------------------------------------------
// C — per-request page order, under concurrent sessions and saturation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bn03_responses_keep_per_request_order_and_topology() {
    const PORT: u16 = 44853;

    let chain = chain_from([0u8; 32], 13, 300);
    let store = tx_map(&chain);
    let order: Vec<Vec<u8>> = chain.iter().map(|t| t.id.to_vec()).collect();
    let tip300 = chain.last().unwrap().id;
    let tip150 = chain[149].id;
    let mut h = boot_node(PORT, store, order);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");

    let mut reader_a = RawPeer::connect(PORT).await;
    let mut reader_b = RawPeer::connect(PORT).await;
    let mut slow = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 3).await;

    // Reader A asks for the full chain, then a prefix, then the full chain
    // again — back to back, so the responder must preserve request order.
    reader_a
        .send(&P2PMessage::GetData(vec![tip300.to_vec()]))
        .await;
    reader_a
        .send(&P2PMessage::GetData(vec![tip150.to_vec()]))
        .await;
    reader_a
        .send(&P2PMessage::GetData(vec![tip300.to_vec()]))
        .await;
    // Reader B asks concurrently for the prefix.
    reader_b
        .send(&P2PMessage::GetData(vec![tip150.to_vec()]))
        .await;
    // ...while a third session saturates and refuses.
    saturate(&mut slow, tip300, 2).await;

    let pages_a = reader_a.collect_pages(Duration::from_secs(5)).await;
    assert_eq!(
        pages_a.len(),
        3,
        "one response per request (got {})",
        pages_a.len()
    );
    let lens: Vec<usize> = pages_a.iter().map(|p| p.len()).collect();
    assert_eq!(
        lens,
        vec![300, 150, 300],
        "responses must be emitted in REQUEST order with full closures"
    );
    for (i, page) in pages_a.iter().enumerate() {
        assert_topological(page, &format!("bn03 A response {}", i));
        let ids: HashSet<[u8; 32]> = page_ids(page).into_iter().collect();
        assert_eq!(ids.len(), page.len(), "no duplicate tx in response {}", i);
    }
    let first: Vec<[u8; 32]> = page_ids(&pages_a[0]);
    assert_eq!(first.first().copied(), Some(chain[0].id));
    assert_eq!(first.last().copied(), Some(tip300));

    let pages_b = reader_b.collect_pages(Duration::from_secs(5)).await;
    assert_eq!(pages_b.len(), 1, "concurrent peer gets its own response");
    assert_eq!(pages_b[0].len(), 150);
    assert_topological(&pages_b[0], "bn03 B response");

    // Saturation on the third session must not have disturbed A/B ordering.
    assert!(
        h.net.session_drops() > 0,
        "the third session really did saturate"
    );

    println!(
        "BN03 a_pages={:?} b_pages={} saturation_drops={}",
        lens,
        pages_b[0].len(),
        h.net.session_drops()
    );
}

// ---------------------------------------------------------------------------
// D — transient saturation recovers without storm amplification
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bn04_transient_saturation_recovers_without_amplification() {
    const PORT: u16 = 44854;
    const BATCHES: usize = 2;
    const REQUESTS: usize = 200 * BATCHES;

    let chain = chain_from([0u8; 32], 14, 60);
    let store = tx_map(&chain);
    let order: Vec<Vec<u8>> = chain.iter().map(|t| t.id.to_vec()).collect();
    let tip = chain.last().unwrap().id;
    let mut h = boot_node(PORT, store, order);
    h.net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    h.net.start().await.expect("start");

    let mut peer = RawPeer::connect(PORT).await;
    wait_peers(&h.net, 1).await;

    // Transient stall: requests pile up behind a consumer that is not reading.
    saturate(&mut peer, tip, BATCHES).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let drops_during = h.net.session_drops();
    assert!(drops_during > 0, "the stall must be refused explicitly");

    // Consumer resumes: the accepted responses are delivered.
    let resumed = peer.collect_pages(Duration::from_secs(5)).await;
    assert!(
        !resumed.is_empty(),
        "responses accepted before saturation must be delivered on resume"
    );
    for (i, page) in resumed.iter().enumerate() {
        assert_eq!(page.len(), 60, "resumed page {} is a whole closure", i);
    }
    assert!(
        resumed.len() <= REQUESTS,
        "no amplification: {} pages for {} requests",
        resumed.len(),
        REQUESTS
    );

    // No lingering backlog and no re-request storm: an idle window produces
    // nothing, the queue drains to zero and the counters stop moving.
    let extra = peer.collect_pages(Duration::from_secs(3)).await;
    assert!(
        extra.is_empty(),
        "no unsolicited responses after the queue drained (got {})",
        extra.len()
    );
    assert_eq!(
        h.net.session_queued_bytes(sock_of(&peer)).await,
        Some(0),
        "the session queue drains to zero after recovery"
    );
    let drops_after = h.net.session_drops();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(
        h.net.session_drops(),
        drops_after,
        "no refusals are produced once the consumer resumed"
    );

    // Recovery: a fresh request is served in full.
    peer.send(&P2PMessage::GetData(vec![tip.to_vec()])).await;
    let after = peer.collect_pages(Duration::from_secs(5)).await;
    assert_eq!(after.len(), 1, "one response for the recovery request");
    assert_eq!(after[0].len(), 60, "recovery response is a whole closure");
    assert_topological(&after[0], "bn04 recovery response");

    // EPILOGUE: the recovery was genuine traffic, not a timeout-driven retry.
    assert_eq!(
        h.sync_ctx
            .stats
            .sync_response_timeouts
            .load(Ordering::Relaxed),
        0,
        "no page ever stalled for the full timeout in this scenario"
    );

    println!(
        "BN04 requests={} resumed_pages={} drops_during={} drops_after={} timeouts=0",
        REQUESTS,
        resumed.len(),
        drops_during,
        drops_after
    );
}
