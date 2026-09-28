//! # Transport abstraction (Phase 2E-B)
//!
//! Until this module existed the P2P layer reached the wire through
//! `tokio::net` directly: `TcpStream::connect` on the dial path,
//! `TcpListener::bind` / `accept` on the inbound path, and `into_split`
//! inside `handle_peer`. Those three points live here now. The peer manager,
//! the address book and the self-healing machinery speak `PeerAddr` +
//! `Transport` and no longer name a socket type.
//!
//! **Only TCP is implemented.** `PeerAddr` has a single `Ip` variant and
//! `TcpTransport` the single implementation. There is no Tor, no I2P and no
//! anonymity layer in this build and none is claimed: `ANONYMITY = NONE`.
//! The point of the abstraction is that a later transport is an addition,
//! not a rewrite of the peer manager.
//!
//! Deliberately *not* here, because they are policy rather than mechanism:
//! `CONNECT_TIMEOUT` (p2p.rs), the /24 diversity rule and `select_outbound`
//! (Phase 2C), address scoring and the peer store schema. The transport is
//! the mechanism; everything that decides *when*, *whether* and *whom* to
//! connect stays above it.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

/// Where a peer can be reached, as the transport layer sees it.
///
/// Only `Ip` exists today. Further variants are deliberately not stubbed in
/// "for show": adding one forces every `match` on this type to grow an arm at
/// compile time, which is the failure mode we want. Nothing here panics on an
/// address it cannot represent — conversions report `Err` instead.
///
/// This is a transport-layer type only. Session keys, the address book, the
/// PEX wire format and `sync_stats` stay on `SocketAddr`; see the boundary
/// conversions in `p2p.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeerAddr {
    /// A TCP/IP endpoint.
    Ip(SocketAddr),
}

impl PeerAddr {
    /// The address as the legacy `SocketAddr`-keyed code sees it.
    ///
    /// `None` once a non-IP variant exists and cannot be expressed that way.
    /// Callers must handle `None`; there is no fallback that invents an IP.
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            PeerAddr::Ip(addr) => Some(*addr),
        }
    }
}

impl From<SocketAddr> for PeerAddr {
    fn from(addr: SocketAddr) -> Self {
        PeerAddr::Ip(addr)
    }
}

impl TryFrom<PeerAddr> for SocketAddr {
    type Error = TransportError;

    fn try_from(addr: PeerAddr) -> Result<Self, Self::Error> {
        addr.as_socket_addr()
            .ok_or(TransportError::UnsupportedAddr(addr))
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Ip(addr) => write!(f, "{}", addr),
        }
    }
}

impl std::str::FromStr for PeerAddr {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<SocketAddr>()
            .map(PeerAddr::Ip)
            .map_err(|_| TransportError::InvalidAddr(s.to_string()))
    }
}

/// Why a transport operation failed.
///
/// Every arm is reported to the caller. There is no `panic!`, `unwrap` or
/// `unreachable!` on this path, so a future `PeerAddr` variant that TCP
/// cannot dial produces an error, never a crash.
#[derive(Debug)]
pub enum TransportError {
    /// The endpoint cannot be expressed on this transport, e.g. a non-IP
    /// address handed to `TcpTransport`.
    UnsupportedAddr(PeerAddr),
    /// The endpoint string could not be parsed.
    InvalidAddr(String),
    /// The socket layer failed.
    Io(std::io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::UnsupportedAddr(addr) => {
                write!(f, "transport does not support endpoint {}", addr)
            }
            TransportError::InvalidAddr(s) => write!(f, "invalid endpoint address: {}", s),
            TransportError::Io(e) => write!(f, "transport io error: {}", e),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// An in-flight transport operation.
///
/// Boxing keeps `Transport` dyn-compatible, so `P2PNetwork` can hold
/// `Arc<dyn Transport>` without making the whole node generic over the
/// transport type. No `async_trait` crate is involved.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The complete wire-facing API of a transport: open a stream, and listen.
///
/// Connection timeouts, retry policy, ban checks, subnet caps and peer
/// scoring are all questions the P2P layer answers, so none of them appear
/// here. A transport only reports whether a socket exists.
pub trait Transport: Send + Sync + 'static {
    /// Open a stream to `addr`.
    fn dial(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>>;

    /// Start listening on `addr`.
    fn bind(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>>;
}

/// An established bidirectional byte stream to a peer.
///
/// This is what `handle_peer` receives, so the session code is independent of
/// whichever transport produced it. The handshake reads and writes it through
/// the ordinary `AsyncRead` / `AsyncWrite` bounds it already used.
#[derive(Debug)]
pub enum TransportStream {
    /// A connected TCP socket.
    Tcp(TcpStream),
}

impl TransportStream {
    /// Split the stream into halves that are owned, `Send` and `'static`.
    ///
    /// `handle_peer` moves the write half into a `tokio::spawn`ed task, so a
    /// borrowed split (`tokio::io::split(&s)`) would not compile here. Each
    /// variant splits itself, exactly as `TcpStream::into_split` does.
    pub fn into_split(self) -> (TransportReadHalf, TransportWriteHalf) {
        match self {
            TransportStream::Tcp(stream) => {
                let (reader, writer) = stream.into_split();
                (TransportReadHalf::Tcp(reader), TransportWriteHalf::Tcp(writer))
            }
        }
    }
}

/// Owned read half of a [`TransportStream`].
#[derive(Debug)]
pub enum TransportReadHalf {
    /// Read half of a TCP socket.
    Tcp(OwnedReadHalf),
}

/// Owned write half of a [`TransportStream`].
#[derive(Debug)]
pub enum TransportWriteHalf {
    /// Write half of a TCP socket.
    Tcp(OwnedWriteHalf),
}

impl AsyncRead for TransportReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportReadHalf::Tcp(half) => Pin::new(half).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TransportWriteHalf::Tcp(half) => Pin::new(half).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportWriteHalf::Tcp(half) => Pin::new(half).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportWriteHalf::Tcp(half) => Pin::new(half).poll_shutdown(cx),
        }
    }
}

/// A bound endpoint waiting for incoming connections.
#[derive(Debug)]
pub enum TransportListener {
    /// A listening TCP socket.
    Tcp(TcpListener),
}

impl TransportListener {
    /// Wait for the next connection, returning its stream and the remote
    /// endpoint as a [`PeerAddr`].
    pub async fn accept(&self) -> Result<(TransportStream, PeerAddr), TransportError> {
        match self {
            TransportListener::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((TransportStream::Tcp(stream), PeerAddr::Ip(addr)))
            }
        }
    }

    /// The endpoint this listener is bound to, as reported by the OS.
    ///
    /// `None` when the socket cannot report it. Never panics and never
    /// substitutes a fabricated address.
    pub fn local_addr(&self) -> Option<PeerAddr> {
        match self {
            TransportListener::Tcp(listener) => listener.local_addr().ok().map(PeerAddr::Ip),
        }
    }
}

/// The one transport this build actually implements.
///
/// `TcpTransport` performs mechanics only: connect, bind, accept, and the
/// conversion between `PeerAddr` and `SocketAddr`. It deliberately does not
/// own `CONNECT_TIMEOUT`, retries or any peer policy.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpTransport;

impl TcpTransport {
    /// Create a TCP transport.
    pub fn new() -> Self {
        Self
    }
}

impl Transport for TcpTransport {
    fn dial(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportStream, TransportError>> {
        let target = match *addr {
            PeerAddr::Ip(target) => target,
        };
        Box::pin(async move {
            let stream = TcpStream::connect(target).await?;
            Ok(TransportStream::Tcp(stream))
        })
    }

    fn bind(&self, addr: &PeerAddr) -> BoxFuture<'_, Result<TransportListener, TransportError>> {
        let endpoint = match *addr {
            PeerAddr::Ip(endpoint) => endpoint,
        };
        Box::pin(async move {
            let listener = TcpListener::bind(endpoint).await?;
            Ok(TransportListener::Tcp(listener))
        })
    }
}

#[cfg(test)]
mod phase2_transport_tests {
    use super::*;
    use crate::p2p::{NetworkGroup, TransportGroupKey};
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn bound_listener() -> (TransportListener, SocketAddr) {
        let listener = TcpTransport::new()
            .bind(&PeerAddr::Ip("127.0.0.1:0".parse().unwrap()))
            .await
            .expect("bind a loopback listener");
        let endpoint = listener
            .local_addr()
            .expect("a bound listener reports its endpoint");
        let addr = endpoint.as_socket_addr().expect("bound endpoint is IP");
        (listener, addr)
    }

    #[test]
    fn test_peer_addr_ip_roundtrip() {
        let raw: SocketAddr = "203.0.113.7:4000".parse().unwrap();
        let peer = PeerAddr::from(raw);

        assert_eq!(peer, PeerAddr::Ip(raw));
        assert_eq!(peer.as_socket_addr(), Some(raw));
        assert_eq!(SocketAddr::try_from(peer).unwrap(), raw);
        assert_eq!(peer.to_string(), "203.0.113.7:4000");
        assert_eq!("203.0.113.7:4000".parse::<PeerAddr>().unwrap(), peer);
    }

    #[test]
    fn test_peer_addr_invalid_conversion() {
        // Every rejection is a returned error, never a panic.
        assert!("not-an-address".parse::<PeerAddr>().is_err());
        assert!("999.999.999.999:80".parse::<PeerAddr>().is_err());
        assert!("203.0.113.7".parse::<PeerAddr>().is_err());
        assert!("".parse::<PeerAddr>().is_err());

        let raw: SocketAddr = "203.0.113.7:4000".parse().unwrap();
        assert!(PeerAddr::try_from(PeerAddr::Ip(raw)).is_ok());
    }

    #[tokio::test]
    async fn test_tcp_transport_dial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();

        let stream = TcpTransport::new()
            .dial(&PeerAddr::Ip(target))
            .await
            .expect("dial a listener that exists");

        assert!(matches!(stream, TransportStream::Tcp(_)));
    }

    #[tokio::test]
    async fn test_tcp_transport_accept() {
        let (listener, endpoint) = bound_listener().await;

        let client = TcpTransport::new().dial(&PeerAddr::Ip(endpoint)).await;
        assert!(client.is_ok());

        let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept must not hang")
            .expect("accept the pending connection");

        assert!(matches!(accepted.0, TransportStream::Tcp(_)));
    }

    #[tokio::test]
    async fn test_tcp_transport_roundtrip() {
        let (listener, endpoint) = bound_listener().await;

        let client = TcpTransport::new()
            .dial(&PeerAddr::Ip(endpoint))
            .await
            .expect("dial");
        let (server, _) = listener.accept().await.expect("accept");

        let (mut client_reader, mut client_writer) = client.into_split();
        let (mut server_reader, mut server_writer) = server.into_split();

        server_writer.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        client_writer.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        server_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    /// The halves `into_split` hands back must be movable into independent
    /// tasks: `handle_peer` moves the write half into a `tokio::spawn`.
    #[tokio::test]
    async fn test_transport_stream_split_owned() {
        let (listener, endpoint) = bound_listener().await;

        let client = TcpTransport::new()
            .dial(&PeerAddr::Ip(endpoint))
            .await
            .expect("dial");
        let (server, _) = listener.accept().await.expect("accept");

        let (server_reader, server_writer) = server.into_split();
        let (mut client_reader, mut client_writer) = client.into_split();

        let writer_task = tokio::spawn(async move {
            let mut writer = server_writer;
            writer.write_all(b"spawned").await.unwrap();
        });
        let reader_task = tokio::spawn(async move {
            let mut reader = server_reader;
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await.unwrap();
            buf
        });

        let mut buf = [0u8; 7];
        client_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"spawned");
        writer_task.await.unwrap();

        client_writer.write_all(b"pong").await.unwrap();
        assert_eq!(&reader_task.await.unwrap(), b"pong");
    }

    #[tokio::test]
    async fn test_transport_listener_returns_peer_addr() {
        let (listener, endpoint) = bound_listener().await;

        let client = TcpTransport::new()
            .dial(&PeerAddr::Ip(endpoint))
            .await
            .expect("dial");
        let (_, peer) = listener.accept().await.expect("accept");

        let PeerAddr::Ip(addr) = peer;
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);
        assert!(peer.as_socket_addr().is_some());
        drop(client);
    }

    #[tokio::test]
    async fn test_tcp_transport_bind_reports_endpoint() {
        let listener = TcpTransport::new()
            .bind(&PeerAddr::Ip("127.0.0.1:0".parse().unwrap()))
            .await
            .expect("bind");

        let endpoint = listener.local_addr().expect("endpoint");
        let addr = endpoint.as_socket_addr().expect("IP endpoint");
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn test_transport_group_ip() {
        let v4: SocketAddr = "203.0.113.7:4000".parse().unwrap();
        assert_eq!(
            TransportGroupKey::from_peer_addr(&PeerAddr::Ip(v4)),
            TransportGroupKey::Ip(NetworkGroup::V4([203, 0, 113]))
        );

        let v6: SocketAddr = "[2001:db8::1]:4000".parse().unwrap();
        assert_eq!(
            TransportGroupKey::from_peer_addr(&PeerAddr::Ip(v6)),
            TransportGroupKey::Ip(NetworkGroup::V6([0x20, 0x01, 0x0d]))
        );
    }

    /// A transport with no subnet notion gets its own bucket. It is never
    /// folded into an IP group, because inventing a /24 for it would let a
    /// non-IP endpoint inherit subnet capacity it does not have.
    #[test]
    fn test_transport_group_no_network_group() {
        let no_ip = TransportGroupKey::NoNetworkGroup;

        assert_eq!(no_ip, TransportGroupKey::NoNetworkGroup);
        assert_ne!(no_ip, TransportGroupKey::Ip(NetworkGroup::V4([203, 0, 113])));
        assert_ne!(no_ip, TransportGroupKey::Ip(NetworkGroup::V6([0x20, 0x01, 0x0d])));
    }

    /// v1 (`Vec<String>`) and v2 (`PeerStoreEntry.addr: String`) stores keep
    /// addresses as plain strings. Passing them through `PeerAddr` must be
    /// byte-identical, which is why no `PEER_STORE_VERSION` bump is needed.
    #[test]
    fn test_legacy_peer_store_transport_boundary() {
        for stored in ["198.51.100.20:30333", "[2001:db8::5]:30333"] {
            let parsed: SocketAddr = stored.parse().unwrap();
            let peer = PeerAddr::from(parsed);

            assert_eq!(peer.as_socket_addr().unwrap().to_string(), stored);
            assert_eq!(peer.to_string(), stored);
            assert_eq!(SocketAddr::try_from(peer).unwrap().to_string(), stored);
        }

        // A string the legacy loader would already reject still fails cleanly.
        assert!("198.51.100.20".parse::<PeerAddr>().is_err());
    }
}
