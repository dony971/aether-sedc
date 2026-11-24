//! Blocking TCP transport with bounded framing and hard timeouts (mission BE).
//!
//! Blocking sockets rather than an async runtime, deliberately: determinism in
//! tests matters more than concurrency here, and every timeout is explicit. A
//! node runs one reader thread per connection; the frame layout lives in
//! [`crate::network::protocol`], never here.
//!
//! # Failure containment
//!
//! Every method returns `io::Result`, and a failure poisons **the connection**,
//! never the node: the caller drops the stream and continues. A timed-out
//! `read_frame` leaves the stream at an unknown offset, so it is documented as
//! unusable afterwards — the caller must close, not retry.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::network::peer::PeerLimits;
use crate::network::protocol::{Envelope, WireError, MAX_FRAME};

/// A TCP connection that reads and writes whole frames under limits.
#[derive(Debug)]
pub struct FramedStream {
    stream: TcpStream,
    limits: PeerLimits,
    written: u64,
    read: u64,
}

impl FramedStream {
    /// Wrap a connected socket.
    pub fn new(stream: TcpStream, limits: PeerLimits) -> std::io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(limits.read_timeout))?;
        stream.set_write_timeout(Some(limits.write_timeout))?;
        Ok(Self {
            stream,
            limits,
            written: 0,
            read: 0,
        })
    }

    /// Dial `addr`, giving up after `limits.read_timeout`.
    pub fn connect(addr: SocketAddr, limits: PeerLimits) -> std::io::Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, limits.read_timeout)?;
        Self::new(stream, limits)
    }

    /// Accept one connection from `listener`; the listener must be non-blocking
    /// or already have an incoming connection.
    pub fn accept(listener: &TcpListener, limits: PeerLimits) -> std::io::Result<Self> {
        let (stream, _) = listener.accept()?;
        Self::new(stream, limits)
    }

    /// Remote address, for logs only. Never an identity.
    pub fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    /// Local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Bytes written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Bytes read so far.
    pub fn read_bytes(&self) -> u64 {
        self.read
    }

    /// Write one frame, provided its length already fits the limits.
    pub fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        if frame.len() > MAX_FRAME + 4 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "frame exceeds the wire limit",
            ));
        }
        self.stream.write_all(frame)?;
        self.stream.flush()?;
        self.written += frame.len() as u64;
        Ok(())
    }

    /// Encode and write an envelope.
    pub fn send(&mut self, envelope: &Envelope) -> Result<(), TransportError> {
        let frame = envelope.encode().map_err(TransportError::Wire)?;
        self.write_frame(&frame).map_err(TransportError::Io)?;
        Ok(())
    }

    /// Read one frame. The length is validated **before** the body is allocated.
    pub fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut prefix = [0u8; 4];
        self.stream
            .read_exact(&mut prefix)
            .map_err(TransportError::Io)?;
        let declared = Envelope::declared_frame_len(prefix).map_err(TransportError::Wire)?;
        let mut body = vec![0u8; declared];
        self.stream
            .read_exact(&mut body)
            .map_err(TransportError::Io)?;
        self.read += (declared + 4) as u64;
        let mut frame = Vec::with_capacity(declared + 4);
        frame.extend_from_slice(&prefix);
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    /// Read and decode one envelope.
    pub fn recv(&mut self) -> Result<Envelope, TransportError> {
        let frame = self.read_frame()?;
        Envelope::decode_frame(&frame).map_err(TransportError::Wire)
    }

    /// Half-close the writing side.
    pub fn shutdown(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Limits in force.
    pub fn limits(&self) -> &PeerLimits {
        &self.limits
    }
}

/// Why a transport operation failed.
#[derive(Debug)]
pub enum TransportError {
    /// Socket error, including timeouts.
    Io(std::io::Error),
    /// The bytes were not an acceptable frame.
    Wire(WireError),
    /// The connection closed cleanly.
    Closed,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "socket: {error}"),
            Self::Wire(error) => write!(f, "wire: {error}"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for TransportError {}

impl TransportError {
    /// Whether this failure is a peer hanging or dying rather than misbehaving.
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            Self::Io(error)
                if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut
        )
    }

    /// Whether the connection is finished for good.
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::Closed => true,
            Self::Wire(_) => true,
            Self::Io(error) => !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        }
    }
}

/// Bind a listener on `addr`, with `127.0.0.1:0` giving an ephemeral port.
pub fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accept with a bound, so a listener thread cannot block forever.
pub fn accept_with_timeout(
    listener: &TcpListener,
    timeout: Duration,
) -> std::io::Result<Option<TcpStream>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(Some(stream)),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}
