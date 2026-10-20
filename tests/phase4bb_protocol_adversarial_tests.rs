//! PHASE 4CP-BB: adversarial P2P protocol, framing and state-machine audit.
//!
//! Every scenario drives the REAL production paths over loopback TCP:
//! handshake (v5), encrypted framing, length guard, AEAD, padding, bincode
//! decode, rate limit, nonce monotonicity, ingress admission and teardown.
//! The one exception is the transaction-id invariant, which is also asserted
//! directly against `validate_pure` (the gate the P2P funnel eventually calls).
//!
//! Covered:
//! * frame-length matrix (below bucket, unaligned, above 16 MiB, u32::MAX);
//! * fragmented handshake / frames, and multiple frames coalesced per write;
//! * valid AEAD carrying an undecodable P2PMessage (fail closed);
//! * padding tail violations inside a valid AEAD (fail closed);
//! * anti-replay counter (duplicate, zero, gaps) and stale-session frames;
//! * pre-handshake data and a post-handshake Hello replay;
//! * forged transaction id on gossip and sync ingress (4CP-BB fix);
//! * liveness after every adversarial session (a clean peer still delivers).
//!
//! Ports 44901-44908 are unique to this suite.
//!
//! Honesty boundaries: the harness consumer is an mpsc receiver, so the tests
//! assert the ingress contract (what the protocol hands the node), not DAG
//! consensus. Mined/funded transactions are only used where validity itself is
//! the property under test.

use aether_unified::genesis::GENESIS_HASH;
use aether_unified::p2p::{
    IngressTx, P2PConfig, P2PMessage, P2PNetwork, P2PProtocolMode, P2P_PROTOCOL_VERSION,
    TX_INGRESS_CAPACITY_MSGS,
};
use aether_unified::sync_stats::SyncContext;
use aether_unified::transaction::{Transaction, DEFAULT_NETWORK_ID};
use aether_unified::transaction_processor::TransactionProcessor;
use aether_unified::transport::{
    BoxFuture, PeerAddr, TcpTransport, Transport, TransportError, TransportListener,
    TransportStream,
};
use aether_unified::validation::ValidationMode;
use aether_unified::wallet::Wallet;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};

const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;
const FRAME_PAD_BUCKET: usize = 256;
const FRAME_FIXED_OVERHEAD: usize = 30;
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const FRAME_MAX_EMIT: usize = MAX_MESSAGE_SIZE - FRAME_PAD_BUCKET;

struct RejectAllTransport;

impl Transport for RejectAllTransport {
    fn dial(&self, _addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
        Box::pin(async move {
            Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "4BB test transport: outbound dial refused",
            )))
        })
    }
    fn bind(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>> {
        let transport = TcpTransport::new();
        let endpoint = *addr;
        Box::pin(async move { transport.bind(&endpoint).await })
    }
}

fn synth_tx(tag: u64) -> Transaction {
    Transaction::new(
        [[0u8; 32]; 2],
        [(tag & 0xff) as u8; 32],
        [0xAA; 32],
        tag * 1_000,
        1,
        1_770_000_000,
        0,
        0,
        vec![0u8; 64],
        vec![0u8; 32],
    )
}

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn make_valid_tx(wallet: &Wallet, tag: u64) -> Transaction {
    let mut tx = Transaction::new(
        [[0u8; 32]; 2],
        wallet.address(),
        [0xAAu8; 32],
        1000,
        1,
        1_770_000_000 + tag,
        0,
        0,
        vec![0u8; 64],
        wallet.public_key_bytes(),
    );
    tx.nonce = tx.mine_nonce(20);
    tx.signature = wallet.sign_transaction(&tx).expect("sign");
    tx.id = tx.compute_hash();
    assert!(tx.verify_hash());
    TransactionProcessor::new()
        .validate_pure(&tx, ValidationMode::Historical)
        .expect("fresh test tx must pass the pure gate");
    tx
}

fn nonce_bytes(counter: u64, dir: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n[8] = dir;
    n
}

/// Encrypt an already padded plaintext (length must satisfy `total % 256 == 0`).
fn wire_frame_custom(key: &[u8; 32], dir: u8, counter: u64, padded: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = nonce_bytes(counter, dir);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), padded)
        .expect("seal");
    let total_len = 12 + ciphertext.len();
    assert_eq!(
        total_len % FRAME_PAD_BUCKET,
        0,
        "custom frame must be bucket-aligned"
    );
    let mut out = Vec::with_capacity(4 + total_len);
    out.extend_from_slice(&(total_len as u32).to_be_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Production padding + encryption for an arbitrary payload (which may be an
/// invalid P2PMessage on purpose).
fn wire_frame(key: &[u8; 32], dir: u8, counter: u64, payload: &[u8]) -> Vec<u8> {
    let unpadded = FRAME_FIXED_OVERHEAD + payload.len();
    assert!(unpadded <= FRAME_MAX_EMIT, "payload too large");
    let pad = (FRAME_PAD_BUCKET - (unpadded % FRAME_PAD_BUCKET)) % FRAME_PAD_BUCKET;
    let mut padded = Vec::with_capacity(payload.len() + pad + 2);
    padded.extend_from_slice(payload);
    padded.resize(payload.len() + pad, 0u8);
    padded.extend_from_slice(&(pad as u16).to_le_bytes());
    wire_frame_custom(key, dir, counter, &padded)
}

struct RawPeer {
    writer: tokio::net::tcp::OwnedWriteHalf,
    reader: tokio::net::tcp::OwnedReadHalf,
    key: [u8; 32],
    dir: u8,
    counter: u64,
}

impl RawPeer {
    async fn connect(port: u16) -> Self {
        Self::connect_impl(port, 77).await
    }

    /// Fragmented handshake: writes the 77-byte Hello in chunks of
    /// `chunk_size` with a 1 ms pause, so the server really consumes partial
    /// reads instead of one coalesced segment.
    async fn connect_fragmented(port: u16) -> Self {
        Self::connect_impl(port, 1).await
    }

    async fn connect_impl(port: u16, chunk_size: usize) -> Self {
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await
        .expect("raw connect must not hang")
        .expect("raw connect");
        let (mut reader, mut writer) = stream.into_split();

        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut outgoing = Vec::with_capacity(HANDSHAKE_LEN);
        outgoing.extend_from_slice(&WIRE_MAGIC);
        outgoing.push(P2P_PROTOCOL_VERSION);
        outgoing.extend_from_slice(&GENESIS_HASH);
        outgoing.extend_from_slice(&DEFAULT_NETWORK_ID.to_le_bytes());
        outgoing.extend_from_slice(public.as_bytes());
        for chunk in outgoing.chunks(chunk_size) {
            writer.write_all(chunk).await.expect("hs write");
            if chunk_size < HANDSHAKE_LEN {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        let mut incoming = [0u8; HANDSHAKE_LEN];
        tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut incoming))
            .await
            .expect("server handshake reply must not hang")
            .expect("server handshake reply");
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
        Self {
            writer,
            reader,
            key,
            dir,
            counter: 0,
        }
    }

    fn build_next(&mut self, payload: &[u8]) -> Vec<u8> {
        self.counter += 1;
        wire_frame(&self.key, self.dir, self.counter, payload)
    }

    async fn send_payload(&mut self, payload: &[u8]) {
        let frame = self.build_next(payload);
        self.send_raw(&frame).await;
    }

    async fn send(&mut self, msg: &P2PMessage) {
        let bytes = bincode::serialize(msg).expect("serialize P2PMessage");
        self.send_payload(&bytes).await;
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("frame write");
    }

    /// The server must close this session (EOF, not merely silence).
    async fn expect_close(mut self, what: &str) {
        let mut buf = [0u8; 256];
        let r = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match self.reader.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(_) => continue,
                    Err(_) => return,
                }
            }
        })
        .await;
        assert!(r.is_ok(), "{} must close within 10s", what);
    }
}

async fn expect_close_stream(mut s: tokio::net::TcpStream, what: &str) {
    let mut buf = [0u8; 256];
    let r = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) => return,
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    })
    .await;
    assert!(r.is_ok(), "{} must close within 10s", what);
}

struct Harness {
    net: P2PNetwork,
    rx: mpsc::Receiver<IngressTx>,
    #[allow(dead_code)]
    sync_ctx: Arc<SyncContext>,
}

async fn boot_node(port: u16) -> Harness {
    let (tx, rx) = mpsc::channel::<IngressTx>(TX_INGRESS_CAPACITY_MSGS);
    let get_dag_hashes: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| Vec::new());
    let get_by_hash: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
    let tips: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| Vec::new());
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
    net.set_protocol_mode(P2PProtocolMode::LegacyV5);
    tokio::time::timeout(Duration::from_secs(20), net.start())
        .await
        .expect("P2P start must not hang")
        .expect("P2P start binds");
    Harness { net, rx, sync_ctx }
}

async fn wait_for<F, Fut>(what: &str, timeout: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("TIMEOUT waiting for: {}", what);
}

async fn wait_peers(h: &Harness, want: usize) {
    wait_for(
        &format!("peer_count == {}", want),
        Duration::from_secs(15),
        || async { h.net.peer_count().await == want },
    )
    .await;
}

async fn recv_tx(rx: &mut mpsc::Receiver<IngressTx>, what: &str) -> Transaction {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT waiting for {}", what))
        .unwrap_or_else(|| panic!("ingress closed while waiting for {}", what))
        .into_tx()
}

async fn assert_no_tx(rx: &mut mpsc::Receiver<IngressTx>, what: &str) {
    if let Ok(item) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        let tx = item.expect("live channel").into_tx();
        panic!(
            "{}: unexpected ingress transaction {}",
            what,
            hex::encode(tx.id)
        );
    }
}

async fn shutdown(h: Harness) {
    tokio::time::timeout(Duration::from_secs(30), h.net.shutdown())
        .await
        .expect("shutdown must not hang")
        .expect("shutdown reports no error");
    wait_for(
        "peer_count == 0 after shutdown",
        Duration::from_secs(15),
        || async { h.net.peer_count().await == 0 },
    )
    .await;
}

// ---------------------------------------------------------------------------
// bb01 — clear length matrix: rejected BEFORE allocation/payload read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb01_length_matrix_rejected_before_allocation() {
    const PORT: u16 = 44901;
    let mut h = boot_node(PORT).await;

    for len in [
        0u32,
        1,
        12,
        255,
        FRAME_PAD_BUCKET as u32 + 1,
        300,
        511,
        (MAX_MESSAGE_SIZE + 1) as u32,
        u32::MAX,
    ] {
        let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PORT))
            .await
            .expect("connect");
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let mut hs = Vec::with_capacity(HANDSHAKE_LEN);
        hs.extend_from_slice(&WIRE_MAGIC);
        hs.push(P2P_PROTOCOL_VERSION);
        hs.extend_from_slice(&GENESIS_HASH);
        hs.extend_from_slice(&DEFAULT_NETWORK_ID.to_le_bytes());
        hs.extend_from_slice(public.as_bytes());
        s.write_all(&hs).await.expect("hs write");
        let mut reply = [0u8; HANDSHAKE_LEN];
        s.read_exact(&mut reply).await.expect("hs reply");
        s.write_all(&len.to_be_bytes()).await.expect("len write");
        expect_close_stream(s, &format!("length {}", len)).await;
    }

    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "no payload after length-only frames").await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb02 — fragmented handshake + fragmented/coalesced frames
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb02_fragmented_and_coalesced_frames_are_equivalent() {
    const PORT: u16 = 44902;
    let mut h = boot_node(PORT).await;
    let a = synth_tx(902);
    let b = synth_tx(903);
    assert!(a.verify_hash() && b.verify_hash());
    let a_msg =
        bincode::serialize(&P2PMessage::Transaction(bincode::serialize(&a).unwrap())).unwrap();
    let b_msg =
        bincode::serialize(&P2PMessage::Transaction(bincode::serialize(&b).unwrap())).unwrap();

    let mut peer = RawPeer::connect_fragmented(PORT).await;

    // Both frames in ONE buffer: the first 40 bytes dribble in one-by-one
    // (partial length/nonce/ciphertext across reads), then the rest arrives
    // in a single write (two frames coalesced behind a split prefix).
    let mut both = peer.build_next(&a_msg);
    both.extend_from_slice(&peer.build_next(&b_msg));
    let split = 40.min(both.len());
    for byte in &both[..split] {
        peer.send_raw(&[*byte]).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    peer.send_raw(&both[split..]).await;

    let got_a = recv_tx(&mut h.rx, "fragmented/coalesced frame A").await;
    let got_b = recv_tx(&mut h.rx, "fragmented/coalesced frame B").await;
    assert_eq!(got_a.id, a.id, "first frame order preserved");
    assert_eq!(got_b.id, b.id, "second frame order preserved");
    assert_no_tx(&mut h.rx, "no duplication").await;

    drop(peer);
    wait_peers(&h, 0).await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb03 — valid AEAD, undecodable P2PMessage: explicit close (fail closed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb03_undecodable_payload_closes_session() {
    const PORT: u16 = 44903;
    let mut h = boot_node(PORT).await;

    let mut peer = RawPeer::connect(PORT).await;
    peer.send_payload(&[0xFFu8; 64]).await;
    peer.expect_close("undecodable P2PMessage").await;
    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "undecodable payload").await;

    // The node survives the protocol violation and serves a clean session.
    let mut clean = RawPeer::connect(PORT).await;
    let tx = synth_tx(904);
    clean
        .send(&P2PMessage::Transaction(bincode::serialize(&tx).unwrap()))
        .await;
    let got = recv_tx(&mut h.rx, "post-violation delivery").await;
    assert_eq!(got.id, tx.id);
    drop(clean);
    wait_peers(&h, 0).await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb04 — authenticated padding violations close the session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb04_padding_tail_violations_close_session() {
    const PORT: u16 = 44904;
    let mut h = boot_node(PORT).await;

    // Plaintext length for a bucket-aligned encrypted frame: 228 mod 256.
    for (name, body, pad) in [
        ("pad > MAX_FRAME_PADDING", 482usize, 300u16),
        ("pad > body", 226, 227),
    ] {
        let mut peer = RawPeer::connect(PORT).await;
        let mut padded = vec![0u8; body + 2];
        padded[body..].copy_from_slice(&pad.to_le_bytes());
        assert_eq!(padded.len() % 256, 228, "fixture must be frame-sized");
        let frame = wire_frame_custom(&peer.key, peer.dir, 1, &padded);
        peer.send_raw(&frame).await;
        peer.expect_close(name).await;
        wait_peers(&h, 0).await;
    }

    assert_no_tx(&mut h.rx, "padding violations").await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb05 — anti-replay: duplicate counter, zero counter, monotone with gaps
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb05_nonce_monotonicity_is_enforced() {
    const PORT: u16 = 44905;
    let mut h = boot_node(PORT).await;

    // Duplicate counter: first accepted, replay closes the session.
    let mut peer = RawPeer::connect(PORT).await;
    let tx1 = synth_tx(905);
    let msg1 =
        bincode::serialize(&P2PMessage::Transaction(bincode::serialize(&tx1).unwrap())).unwrap();
    let frame = peer.build_next(&msg1);
    peer.send_raw(&frame).await;
    let got = recv_tx(&mut h.rx, "first nonce-1 frame").await;
    assert_eq!(got.id, tx1.id);
    peer.send_raw(&frame).await;
    peer.expect_close("duplicate nonce").await;
    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "duplicate nonce").await;

    // Counter zero is outside the valid range (first frame must be >= 1).
    let mut peer = RawPeer::connect(PORT).await;
    let tx2 = synth_tx(906);
    let msg2 =
        bincode::serialize(&P2PMessage::Transaction(bincode::serialize(&tx2).unwrap())).unwrap();
    let zero = wire_frame(&peer.key, peer.dir, 0, &msg2);
    peer.send_raw(&zero).await;
    peer.expect_close("nonce zero").await;
    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "nonce zero").await;

    // Gaps are legal: 2 then 3 both deliver, in order.
    let mut peer = RawPeer::connect(PORT).await;
    let tx3 = synth_tx(907);
    let tx4 = synth_tx(908);
    let msg3 =
        bincode::serialize(&P2PMessage::Transaction(bincode::serialize(&tx3).unwrap())).unwrap();
    let msg4 =
        bincode::serialize(&P2PMessage::Transaction(bincode::serialize(&tx4).unwrap())).unwrap();
    peer.send_raw(&wire_frame(&peer.key, peer.dir, 2, &msg3))
        .await;
    peer.send_raw(&wire_frame(&peer.key, peer.dir, 3, &msg4))
        .await;
    assert_eq!(recv_tx(&mut h.rx, "nonce 2").await.id, tx3.id);
    assert_eq!(recv_tx(&mut h.rx, "nonce 3").await.id, tx4.id);
    drop(peer);
    wait_peers(&h, 0).await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb06 — pre-handshake data and post-handshake Hello replay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb06_handshake_ordering_is_strict() {
    const PORT: u16 = 44906;
    let mut h = boot_node(PORT).await;

    // Pre-handshake: a perfectly valid encrypted frame is not a handshake.
    let tx_bytes = bincode::serialize(&synth_tx(909)).unwrap();
    let payload = bincode::serialize(&P2PMessage::Transaction(tx_bytes)).unwrap();
    let frame = wire_frame(&[0x11u8; 32], 0x01, 1, &payload);
    let mut s = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", PORT))
        .await
        .expect("connect");
    s.write_all(&frame).await.expect("pre-handshake frame");
    expect_close_stream(s, "pre-handshake data").await;
    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "pre-handshake data").await;

    // Post-handshake: replaying the 77-byte Hello is read as a length prefix
    // (wire magic 0x7E34F154 > 16 MiB) and must close the session.
    let mut peer = RawPeer::connect(PORT).await;
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let mut hello = Vec::with_capacity(HANDSHAKE_LEN);
    hello.extend_from_slice(&WIRE_MAGIC);
    hello.push(P2P_PROTOCOL_VERSION);
    hello.extend_from_slice(&GENESIS_HASH);
    hello.extend_from_slice(&DEFAULT_NETWORK_ID.to_le_bytes());
    hello.extend_from_slice(public.as_bytes());
    peer.send_raw(&hello).await;
    peer.expect_close("post-handshake Hello replay").await;
    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "post-handshake Hello").await;

    // Clean session still works.
    let mut clean = RawPeer::connect(PORT).await;
    let tx = synth_tx(910);
    clean
        .send(&P2PMessage::Transaction(bincode::serialize(&tx).unwrap()))
        .await;
    assert_eq!(
        recv_tx(&mut h.rx, "clean session after handshake abuse")
            .await
            .id,
        tx.id
    );
    drop(clean);
    wait_peers(&h, 0).await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb07 — a frame sealed by a dead session cannot cross reconnect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb07_stale_session_frame_is_rejected() {
    const PORT: u16 = 44907;
    let mut h = boot_node(PORT).await;

    let mut old = RawPeer::connect(PORT).await;
    let old_key = old.key;
    let old_dir = old.dir;
    let tx1 = synth_tx(911);
    old.send(&P2PMessage::Transaction(bincode::serialize(&tx1).unwrap()))
        .await;
    assert_eq!(recv_tx(&mut h.rx, "live session delivery").await.id, tx1.id);
    drop(old);
    wait_peers(&h, 0).await;

    // New session, old ciphertext.
    let mut peer = RawPeer::connect(PORT).await;
    let stale_payload = bincode::serialize(&P2PMessage::Transaction(
        bincode::serialize(&synth_tx(912)).unwrap(),
    ))
    .unwrap();
    let stale = wire_frame(&old_key, old_dir, 9, &stale_payload);
    peer.send_raw(&stale).await;
    peer.expect_close("stale-session frame").await;
    wait_peers(&h, 0).await;
    assert_no_tx(&mut h.rx, "stale-session frame").await;

    // A fresh session with the right key still delivers.
    let mut clean = RawPeer::connect(PORT).await;
    let tx3 = synth_tx(913);
    clean
        .send(&P2PMessage::Transaction(bincode::serialize(&tx3).unwrap()))
        .await;
    assert_eq!(recv_tx(&mut h.rx, "post-stale delivery").await.id, tx3.id);
    drop(clean);
    wait_peers(&h, 0).await;
    shutdown(h).await;
}

// ---------------------------------------------------------------------------
// bb08 — forged transaction id: root gate + both P2P ingress paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bb08_forged_transaction_id_is_refused() {
    const PORT: u16 = 44908;
    let mut h = boot_node(PORT).await;
    let wallet = wallet_n(913_001);
    let valid = make_valid_tx(&wallet, 1);

    let mut forged = valid.clone();
    forged.id = [0x42u8; 32];
    assert!(!forged.verify_hash(), "fixture must have a forged id");
    assert!(
        TransactionProcessor::new()
            .validate_pure(&forged, ValidationMode::Historical)
            .is_err(),
        "the pure gate must reject an id != compute_hash()"
    );

    let valid_bytes = bincode::serialize(&valid).unwrap();
    let forged_bytes = bincode::serialize(&forged).unwrap();
    let mut peer = RawPeer::connect(PORT).await;

    // Live gossip path.
    peer.send(&P2PMessage::Transaction(forged_bytes.clone()))
        .await;
    assert_no_tx(&mut h.rx, "forged-id gossip").await;
    peer.send(&P2PMessage::Transaction(valid_bytes.clone()))
        .await;
    let got = recv_tx(&mut h.rx, "valid gossip").await;
    assert_eq!(got.id, valid.id);

    // Sync backfill path: a forged item must not be admitted (nor marked).
    peer.send(&P2PMessage::SyncResponse(vec![forged_bytes]))
        .await;
    assert_no_tx(&mut h.rx, "forged-id SyncResponse").await;
    peer.send(&P2PMessage::SyncResponse(vec![valid_bytes]))
        .await;
    let got = recv_tx(&mut h.rx, "valid SyncResponse").await;
    assert_eq!(got.id, valid.id);

    drop(peer);
    wait_peers(&h, 0).await;
    shutdown(h).await;
}
