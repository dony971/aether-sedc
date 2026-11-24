//! Versioned wire format for the validator network (mission BE).
//!
//! # What this format is, and what it is not
//!
//! It is a **transport envelope**. The bodies it carries are the canonical
//! encodings that already exist (`ConsensusVote::encode`, `SignedReady::encode`,
//! `PrecommitCertificate::encode`, `Checkpoint::encode`), and they are **not**
//! touched here. BE adds no field to any signed consensus object: a vote signed
//! by a validator has exactly the bytes it had before, and the envelope's own
//! signature is a separate, additional commitment by the peer.
//!
//! ```text
//! frame   := u32 len ‖ body
//! body    := header ‖ payload ‖ signature
//! header  := version(1) ‖ network(8) ‖ kind(1) ‖ sender(32) ‖ generation(32)
//!            ‖ height(8) ‖ round(4) ‖ message_id(32) ‖ payload_len(4)
//! ```
//!
//! `message_id = BLAKE3(DOMAIN_WIRE ‖ header-without-id ‖ payload)`, so a peer
//! cannot relabel a message without invalidating it, and a replay is detectable
//! by identifier alone.
//!
//! # Limits
//!
//! Every length is bounded **before** it is used to allocate: a frame declares
//! at most [`MAX_FRAME`] bytes and a payload at most [`MAX_PAYLOAD`]. A peer that
//! sends a larger length is disconnected without any allocation proportional to
//! the claim.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

use crate::l2crypto::frame::frame_hash;

/// Domain of the transport envelope.
pub const DOMAIN_WIRE: &[u8] = b"AETHER-L2-WIRE-v1";

/// Wire protocol version.
pub const WIRE_VERSION: u8 = 1;

/// Largest accepted frame (length prefix included).
pub const MAX_FRAME: usize = 1 << 20;

/// Largest accepted payload.
pub const MAX_PAYLOAD: usize = 1 << 18;

/// Size of the fixed header.
pub const HEADER_LEN: usize = 1 + 8 + 1 + 32 + 32 + 8 + 4 + 32 + 4;

/// Size of a fully framed body without payload.
pub const BODY_OVERHEAD: usize = HEADER_LEN + 64;

/// Message types a peer may send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessageKind {
    /// Opening handshake.
    Hello,
    /// Handshake reply.
    HelloAck,
    /// A proposal: the checkpoint identifier to decide.
    Proposal,
    /// A `ConsensusVote` in the prevote phase.
    Prevote,
    /// A `ConsensusVote` in the precommit phase.
    Precommit,
    /// A `PrecommitCertificate` (a QC).
    QuorumCertificate,
    /// A `PrevoteCertificate` used as proof of lock.
    ProofOfLock,
    /// A `SignedReady` attestation.
    Ready,
    /// A `Checkpoint` record.
    Checkpoint,
    /// A halt record, so the cluster stops together.
    HaltEvidence,
    /// A synchronisation request (mission BD).
    SyncRequest,
    /// A synchronisation bundle.
    BootstrapResponse,
    /// A round-change request, in its canonical byte form (mission BF codec).
    RoundChange,
    /// A DAG transaction, in its existing canonical encoding (mission BZ.3 §4).
    ///
    /// This kind carries a **transaction**, never a consensus decision: it is not
    /// listed in [`MessageKind::is_consensus`], it never reaches the BFT engine,
    /// and a decided checkpoint does not finalise it. The relation between a BFT
    /// height and a DAG transaction is not defined by the protocol, and this
    /// message does not invent one.
    Transaction,
    /// Liveness probe.
    Ping,
}

impl MessageKind {
    /// Stable wire tag.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Hello => 0,
            Self::HelloAck => 1,
            Self::Proposal => 2,
            Self::Prevote => 3,
            Self::Precommit => 4,
            Self::QuorumCertificate => 5,
            Self::ProofOfLock => 6,
            Self::Ready => 7,
            Self::Checkpoint => 8,
            Self::HaltEvidence => 9,
            Self::SyncRequest => 10,
            Self::BootstrapResponse => 11,
            Self::RoundChange => 13,
            Self::Transaction => 14,
            Self::Ping => 12,
        }
    }

    /// Strict inverse.
    pub fn from_u8(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::Hello,
            1 => Self::HelloAck,
            2 => Self::Proposal,
            3 => Self::Prevote,
            4 => Self::Precommit,
            5 => Self::QuorumCertificate,
            6 => Self::ProofOfLock,
            7 => Self::Ready,
            8 => Self::Checkpoint,
            9 => Self::HaltEvidence,
            10 => Self::SyncRequest,
            11 => Self::BootstrapResponse,
            12 => Self::Ping,
            13 => Self::RoundChange,
            14 => Self::Transaction,
            _ => return None,
        })
    }

    /// Human name, for logs and test messages.
    pub fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::HelloAck => "hello-ack",
            Self::Proposal => "proposal",
            Self::Prevote => "prevote",
            Self::Precommit => "precommit",
            Self::QuorumCertificate => "qc",
            Self::ProofOfLock => "pol",
            Self::Ready => "ready",
            Self::Checkpoint => "checkpoint",
            Self::HaltEvidence => "halt",
            Self::SyncRequest => "sync-request",
            Self::BootstrapResponse => "bootstrap",
            Self::RoundChange => "round-change",
            Self::Transaction => "transaction",
            Self::Ping => "ping",
        }
    }

    /// Whether a message may carry a consensus decision.
    ///
    /// Only these are handed to the engine; everything else is either transport
    /// bookkeeping or synchronisation data, which BD verifies separately.
    pub fn is_consensus(self) -> bool {
        matches!(
            self,
            Self::Proposal
                | Self::Prevote
                | Self::Precommit
                | Self::QuorumCertificate
                | Self::ProofOfLock
        )
    }
}

/// Why a frame could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WireError {
    /// Truncated or over-long frame.
    #[error("malformed frame: {0}")]
    Malformed(&'static str),

    /// The declared length exceeds the limit.
    #[error("frame declares {declared} bytes, limit is {limit}")]
    TooLarge {
        /// Declared length.
        declared: usize,
        /// Limit.
        limit: usize,
    },

    /// The version is not the one this node speaks.
    #[error("unsupported wire version {0}")]
    Version(u8),

    /// The kind tag is unknown.
    #[error("unknown message kind {0}")]
    Kind(u8),

    /// The identifier does not match the content.
    #[error("message id does not match its content")]
    IdMismatch,

    /// The signature does not verify against the claimed key.
    #[error("envelope signature does not verify")]
    BadSignature,

    /// The network does not match.
    #[error("wrong network: {0}")]
    Network(u64),
}

/// A transport envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol version.
    pub version: u8,
    /// Network discriminator.
    pub network: u64,
    /// Message type.
    pub kind: MessageKind,
    /// Sender's validator identity (derived from its key, never claimed).
    pub sender: [u8; 32],
    /// Generation the sender believes is in force.
    pub generation: [u8; 32],
    /// Height the sender is talking about.
    pub height: u64,
    /// Round, when the message belongs to one.
    pub round: u32,
    /// Content identifier.
    pub message_id: [u8; 32],
    /// Body, still in its own canonical encoding.
    pub payload: Vec<u8>,
    /// Envelope signature by the sender.
    pub signature: [u8; 64],
}

impl Envelope {
    /// Build an unsigned envelope; the identifier is computed immediately.
    pub fn new(
        network: u64,
        kind: MessageKind,
        sender: [u8; 32],
        generation: [u8; 32],
        height: u64,
        round: u32,
        payload: Vec<u8>,
    ) -> Self {
        let mut envelope = Self {
            version: WIRE_VERSION,
            network,
            kind,
            sender,
            generation,
            height,
            round,
            message_id: [0u8; 32],
            payload,
            signature: [0u8; 64],
        };
        envelope.message_id = envelope.compute_id();
        envelope
    }

    /// The sender's identity, as carried in the header.
    ///
    /// Derived from the peer's key at handshake time, so a mismatch with the
    /// authenticated peer is a refusal, never a re-routing.
    pub fn sender_id(&self) -> crate::consensus::generation::ValidatorId {
        crate::consensus::generation::ValidatorId(self.sender)
    }

    /// Bytes covered by the identifier: everything except the signature, with the
    /// identifier field zeroed so the hash is well defined.
    fn id_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_OVERHEAD + self.payload.len());
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.generation);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.round.to_le_bytes());
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// `BLAKE3(DOMAIN_WIRE ‖ header ‖ payload)`.
    pub fn compute_id(&self) -> [u8; 32] {
        frame_hash(DOMAIN_WIRE, &[&self.id_bytes()])
    }

    /// Bytes this envelope signs: the whole body with the signature field empty.
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.id_bytes()
    }

    /// Attach the peer's signature.
    pub fn sign(mut self, key: &SigningKey) -> Self {
        self.signature = key.sign(&self.signing_bytes()).to_bytes();
        self
    }

    /// Verify the envelope signature against `public_key`.
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> bool {
        if self.compute_id() != self.message_id {
            return false;
        }
        let key = match VerifyingKey::from_bytes(public_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        key.verify_strict(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }

    /// Encode as a length-prefixed frame, refusing an over-sized payload.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(WireError::TooLarge {
                declared: self.payload.len(),
                limit: MAX_PAYLOAD,
            });
        }
        let body_len = BODY_OVERHEAD + self.payload.len();
        if body_len + 4 > MAX_FRAME {
            return Err(WireError::TooLarge {
                declared: body_len + 4,
                limit: MAX_FRAME,
            });
        }
        let mut out = Vec::with_capacity(body_len + 4);
        out.extend_from_slice(&(body_len as u32).to_le_bytes());
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.generation);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.round.to_le_bytes());
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Decode a body (without the length prefix).
    ///
    /// Strict: fixed layout, bounded payload, exact length, known kind and
    /// version, identifier recomputed.
    pub fn decode_body(body: &[u8]) -> Result<Self, WireError> {
        if body.len() < BODY_OVERHEAD {
            return Err(WireError::Malformed("shorter than the header"));
        }
        let version = body[0];
        if version != WIRE_VERSION {
            return Err(WireError::Version(version));
        }
        let mut network = [0u8; 8];
        network.copy_from_slice(&body[1..9]);
        let kind = MessageKind::from_u8(body[9]).ok_or(WireError::Kind(body[9]))?;
        let mut sender = [0u8; 32];
        sender.copy_from_slice(&body[10..42]);
        let mut generation = [0u8; 32];
        generation.copy_from_slice(&body[42..74]);
        let mut height = [0u8; 8];
        height.copy_from_slice(&body[74..82]);
        let mut round = [0u8; 4];
        round.copy_from_slice(&body[82..86]);
        let mut message_id = [0u8; 32];
        message_id.copy_from_slice(&body[86..118]);
        let mut payload_len = [0u8; 4];
        payload_len.copy_from_slice(&body[118..122]);
        let declared = u32::from_le_bytes(payload_len) as usize;
        if declared > MAX_PAYLOAD {
            return Err(WireError::TooLarge {
                declared,
                limit: MAX_PAYLOAD,
            });
        }
        if body.len() != BODY_OVERHEAD + declared {
            return Err(WireError::Malformed("payload length disagrees with frame"));
        }
        let payload = body[HEADER_LEN..HEADER_LEN + declared].to_vec();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&body[HEADER_LEN + declared..]);
        let envelope = Self {
            version,
            network: u64::from_le_bytes(network),
            kind,
            sender,
            generation,
            height: u64::from_le_bytes(height),
            round: u32::from_le_bytes(round),
            message_id,
            payload,
            signature,
        };
        if envelope.compute_id() != envelope.message_id {
            return Err(WireError::IdMismatch);
        }
        Ok(envelope)
    }

    /// Decode a frame, length prefix included.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, WireError> {
        if frame.len() < 4 {
            return Err(WireError::Malformed("shorter than the length prefix"));
        }
        let mut len = [0u8; 4];
        len.copy_from_slice(&frame[..4]);
        let declared = u32::from_le_bytes(len) as usize;
        if declared > MAX_FRAME {
            return Err(WireError::TooLarge {
                declared,
                limit: MAX_FRAME,
            });
        }
        if frame.len() != declared + 4 {
            return Err(WireError::Malformed("frame length disagrees with prefix"));
        }
        Self::decode_body(&frame[4..])
    }

    /// Read a length prefix and decide whether the frame is acceptable, **before**
    /// allocating anything for the payload.
    pub fn declared_frame_len(prefix: [u8; 4]) -> Result<usize, WireError> {
        let declared = u32::from_le_bytes(prefix) as usize;
        if declared > MAX_FRAME {
            return Err(WireError::TooLarge {
                declared,
                limit: MAX_FRAME,
            });
        }
        if declared < BODY_OVERHEAD {
            return Err(WireError::Malformed(
                "declared body shorter than the header",
            ));
        }
        Ok(declared)
    }
}

/// Payload of a `Hello` / `HelloAck`: a key and a nonce, nothing self-declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// Version.
    pub version: u8,
    /// Network.
    pub network: u64,
    /// Peer's Ed25519 public key; the identity is derived from it.
    pub public_key: [u8; 32],
    /// Sender's height, so a peer can refuse an obviously stale connection.
    pub height: u64,
}

impl Hello {
    /// Encode: 1 + 8 + 32 + 8 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        out.push(self.version);
        out.extend_from_slice(&self.network.to_le_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.height.to_le_bytes());
        out
    }

    /// Strict decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != 49 {
            return Err(WireError::Malformed("hello must be 49 bytes"));
        }
        let mut network = [0u8; 8];
        network.copy_from_slice(&bytes[1..9]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[9..41]);
        let mut height = [0u8; 8];
        height.copy_from_slice(&bytes[41..49]);
        Ok(Self {
            version: bytes[0],
            network: u64::from_le_bytes(network),
            public_key,
            height: u64::from_le_bytes(height),
        })
    }
}
