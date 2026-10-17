//! PHASE 4CH: real-path PEX refresh — foreign-client wire integration twin.
//!
//! Complements the authoritative in-module suite
//! (`src/p2p.rs::phase4ch_pex_wiring_tests`), which asserts the exact debt
//! arithmetic (12 -> 6 -> 3), intra-message dedup and candidacy through the
//! cfg(test) state accessors that exist only inside the crate build. This
//! external suite proves the same receive path from OUTSIDE the crate: a
//! foreign peer socket speaks the REAL handshake and sends REAL sealed
//! `P2PMessage::Peers` frames (pad + ChaCha20-Poly1305 + length prefix),
//! and every observable assertion runs through public APIs plus the 4CH
//! dial-refusing transport seam (`P2PNetwork::new_with_transport`).
//!
//! All loopback. Synthetic public addresses (203.0.113.0/24, TEST-NET-3)
//! pass the production D6 filter genuinely; the test transport records every
//! outbound dial attempt and NEVER opens a socket, so no connection leaves
//! the machine. Port 44801 is test-unique (never 4CA 44731/32,
//! 4CB 44751/52, 4CC 44761-44774, 4CD 44781-44787, 4CE 44791-44794, nor
//! the in-module 4CH port 44805).
//!
//! Honesty boundaries:
//! - Refresh EFFECT on the failure debt is not directly observable through
//!   the public API (no address-table introspection exists), and an asleep
//!   entry cannot be constructed externally without either real failed
//!   dials toward a public address (forbidden here) or a production
//!   introspection API (rejected). The asleep-refresh story (threshold,
//!   one-halving arithmetic, no forced dial, restored candidacy) is
//!   therefore asserted in the in-module suite, where it is exact and
//!   deterministic. This file asserts what the public surface can see:
//!   admission of unknowns, D6 filtering, dedup-bounded growth under
//!   repeated announces, clean shutdown, and — structurally — that every
//!   outbound dial went through the refusing transport (zero sockets).
//! - Valid SEALED peer-exchange frames with real session keys are covered
//!   here (4CC documented that as residual risk); arbitrary encrypted-frame
//!   fuzzing beyond PEX remains out of scope.

use aether_unified::genesis::GENESIS_HASH;
use aether_unified::p2p::{P2PConfig, P2PMessage, P2PNetwork, P2P_PROTOCOL_VERSION};
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
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Wire magic as sent on the wire: HANDSHAKE_MAGIC ^ HANDSHAKE_MAGIC_MASK
/// (p2p.rs: [0x41,0x45,0x54,0x48] ^ [0x3F,0x71,0xA5,0x1C]).
const WIRE_MAGIC: [u8; 4] = [0x7E, 0x34, 0xF1, 0x54];
const HANDSHAKE_LEN: usize = 4 + 1 + 32 + 8 + 32;
/// Mirror of p2p.rs FRAME_PAD_BUCKET (256) and FRAME_FIXED_OVERHEAD (30 =
/// nonce 12 + AEAD tag 16 + pad-length tail 2).
const FRAME_PAD_BUCKET: usize = 256;
const FRAME_FIXED_OVERHEAD: usize = 30;

const START_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

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

/// Dial-refusing transport: records every dial attempt, never opens a
/// socket. `bind` delegates to real TCP so the node accepts genuine loopback
/// connections.
struct RejectAllTransport {
    log: Arc<StdMutex<Vec<SocketAddr>>>,
}

impl Transport for RejectAllTransport {
    fn dial(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
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

    fn bind(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>> {
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

fn dial_log_len(log: &Arc<StdMutex<Vec<SocketAddr>>>) -> usize {
    log.lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// A foreign peer: the REAL production handshake over a real loopback
/// socket, then REAL sealed frames (pad + ChaCha20-Poly1305 + length
/// prefix), mirroring the production send path byte for byte.
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

    /// Mirror of p2p.rs handshake() from the client side: ephemeral X25519,
    /// DH, SHA256("aether-p2p-key-v1"), direction byte (lower key sends 0x01).
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
        // Mirror of p2p.rs send_direction: lower public key sends 0x01.
        let dir = if public.as_bytes() < &peer_pk {
            0x01
        } else {
            0x02
        };
        (key, dir)
    }

    /// One production-shaped frame: pad to bucket, seal, length-prefix.
    async fn send(&mut self, msg: &P2PMessage) {
        let payload = bincode::serialize(msg).expect("serialize P2PMessage");
        // Mirror of p2p.rs pad_message: zeros + u16-LE pad length so the
        // padded plaintext plus FRAME_FIXED_OVERHEAD fills whole buckets.
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
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, padded.as_ref()).expect("seal");
        let total_len = 12 + ciphertext.len();
        assert_eq!(
            total_len % FRAME_PAD_BUCKET,
            0,
            "every emitted frame must land on a bucket"
        );
        assert!(total_len >= FRAME_PAD_BUCKET, "minimum frame size");
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

fn boot_node(port: u16, transport: Arc<dyn Transport>) -> P2PNetwork {
    let (tx, _rx) = mpsc::unbounded_channel::<Transaction>();
    let empty: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync> = Arc::new(|| vec![]);
    let empty_opt: Arc<dyn Fn(&[u8]) -> Option<Transaction> + Send + Sync> = Arc::new(|_| None);
    P2PNetwork::new_with_transport(
        P2PConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: DEFAULT_NETWORK_ID,
        },
        tx,
        empty.clone(),
        empty_opt,
        empty,
        Arc::new(SyncContext::default()),
        Arc::new(|_| false),
        transport,
    )
}

/// ch01: a foreign sealed Peers frame drives the REAL receive arm from
/// outside the crate — unknown public addresses are admitted and dialed
/// through the (refusing) transport, D6-filtered addresses are never even
/// attempted, repeated identical announces stay bounded, and shutdown
/// releases the session and the port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ch01_foreign_sealed_peers_frame_exercises_real_receive_path() {
    const PORT: u16 = 44801;
    let x: SocketAddr = "203.0.113.50:25565".parse().unwrap();
    let y: SocketAddr = "203.0.113.99:25565".parse().unwrap();
    let privs: Vec<SocketAddr> = ["10.0.0.7:8080", "192.168.44.9:4001", "127.0.0.1:6666"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();

    let dial_log = Arc::new(StdMutex::new(Vec::new()));
    let transport = Arc::new(RejectAllTransport {
        log: Arc::clone(&dial_log),
    });
    let net = boot_node(PORT, transport);
    tokio::time::timeout(START_TIMEOUT, net.start())
        .await
        .expect("TIMEOUT: start hung")
        .expect("start must bind");

    let mut peer = RawPeer::connect(PORT).await;
    wait_for("session registered", STEP_TIMEOUT, || async {
        net.peer_count().await == 1
    })
    .await;

    // One REAL sealed frame: unknown X and Y (admission path), private and
    // loopback announces (D6 must drop them before admission — and thus
    // before any dial), plus duplicates (a doubled entry must not trigger
    // extra dials of known addresses).
    peer.send(&P2PMessage::Peers(vec![
        x, x, privs[0], privs[1], privs[2], y, x,
    ]))
    .await;

    // Unknown public addresses keep their exact pre-4CH admission shape:
    // admitted, then dialed via the discovery channel. The dial is
    // REFUSED by the test transport, so the recorded attempt is the whole
    // observable — no socket ever leaves the machine.
    wait_for(
        "admission dial recorded for X (refused transport)",
        STEP_TIMEOUT,
        || async { dial_count(&dial_log, x) >= 1 },
    )
    .await;
    wait_for(
        "admission dial recorded for Y (refused transport)",
        STEP_TIMEOUT,
        || async { dial_count(&dial_log, y) >= 1 },
    )
    .await;

    // D6: filtered announces never reach admission, hence never a dial.
    {
        let log = dial_log.lock().unwrap_or_else(|e| e.into_inner());
        for p in &privs {
            assert!(!log.contains(p), "{} must never be dialed", p);
        }
    }

    // Repeated identical announces (X and Y now held): bounded — no new
    // dial per message (refresh forces no dial), no session growth, no
    // panic. The dial log may see at most a couple of NORMAL redial
    // attempts inside this short window (5s cycle); five handler-forced
    // dials would blow straight past the bound.
    let before = dial_log_len(&dial_log);
    for _ in 0..5 {
        peer.send(&P2PMessage::Peers(vec![x, x, privs[0], y, x]))
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let growth = dial_log_len(&dial_log).saturating_sub(before);
    assert!(
        growth <= 2,
        "repeated announces must not force dials (growth {})",
        growth
    );
    assert_eq!(net.peer_count().await, 1, "no session growth");

    // Clean stop: session released, port free.
    drop(peer);
    tokio::time::timeout(SHUTDOWN_TIMEOUT, net.shutdown())
        .await
        .unwrap_or_else(|_| panic!("TIMEOUT: {} shutdown hung", PORT))
        .unwrap_or_else(|e| panic!("{} shutdown reported: {}", PORT, e));
    wait_for("peer_count==0 after shutdown", STEP_TIMEOUT, || async {
        net.peer_count().await == 0
    })
    .await;
    std::net::TcpListener::bind(format!("127.0.0.1:{}", PORT))
        .expect("port must be released after shutdown");
    drop(net);
}
