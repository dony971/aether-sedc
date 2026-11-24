//! Message validation and routing into the engine (mission BE).
//!
//! # The rule this module exists to enforce
//!
//! > An authenticated peer is a known **sender**, not a trusted **authority**.
//!
//! So every consensus message passes three gates in this order:
//!
//! 1. **peer gate** — is this envelope the peer's, unaltered, fresh, within rate?
//! 2. **content gate** — does the body decode in its existing canonical format?
//! 3. **engine gate** — does [`BftState`] accept it, under its own generation,
//!    lock, POL and HALT rules?
//!
//! This module performs gates 1 and 2 and *calls* gate 3. It never decides
//! finality, never collects a quorum itself, and never signs. The only way a
//! vote becomes a decision is [`BftState::finalize`], reached by the driver.

use thiserror::Error;

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::ValidatorId;
use crate::l2bft::cert::{PrecommitCertificate, PrevoteCertificate};
use crate::l2bft::context::VoteOutcome;
use crate::l2bft::engine::BftState;
use crate::l2bft::halt_proof::{HaltProof, HALT_PROOF_TAG};
use crate::l2bft::round::RoundChange;
use crate::l2bft::sync::SyncBundle;
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2crypto::vote::ConsensusVote;
use crate::network::wire_sync::SyncRequest;
use crate::transaction::Transaction;

use crate::network::peer::{PeerError, PeerState};
use crate::network::protocol::{Envelope, MessageKind, WireError};

/// A vote the dispatcher decoded, together with the engine's verdict on it.
///
/// Mission BZ.3: the earlier variant carried only [`VoteOutcome`], so a node that
/// received a vote could not pass it on — the bytes were dropped once the engine
/// had looked at them. The vote now travels with its verdict, so relaying is
/// possible, and the rule that matters is stated once:
///
/// > **A vote is relayed only when `outcome` is `Accepted`.**
///
/// A refused vote — bad signature, wrong generation, wrong round, duplicate — is
/// never forwarded. Relaying it would let this node launder a vote its own engine
/// rejected, and a peer that trusted the relay would be trusting this node's
/// opinion instead of the engine's.
#[derive(Debug, Clone)]
pub struct AcceptedVote {
    vote: ConsensusVote,
    outcome: VoteOutcome,
}

impl AcceptedVote {
    /// Pair a decoded vote with the engine's verdict.
    pub fn new(vote: ConsensusVote, outcome: VoteOutcome) -> Self {
        Self { vote, outcome }
    }

    /// The vote exactly as it arrived (or as this node signed it).
    pub fn vote(&self) -> &ConsensusVote {
        &self.vote
    }

    /// The engine's verdict.
    pub fn outcome(&self) -> &VoteOutcome {
        &self.outcome
    }

    /// The verdict, by value.
    pub fn into_outcome(self) -> VoteOutcome {
        self.outcome
    }

    /// Whether the engine accepted this vote into its round.
    pub fn is_accepted(&self) -> bool {
        matches!(self.outcome, VoteOutcome::Accepted { .. })
    }
}

/// What the dispatcher accepted.
#[derive(Debug)]
pub enum Dispatched {
    /// A vote, with the engine's own verdict and the bytes that produced it.
    Vote(AcceptedVote),
    /// A proposal the engine accepted as its value for this height.
    Proposal([u8; 32]),
    /// A checkpoint record, decoded and structurally valid.
    Checkpoint(Box<Checkpoint>),
    /// A QC whose signatures and quorum were re-verified from its bytes.
    ///
    /// Verification here means "this is a well-formed certificate for this
    /// network"; whether it decides anything is [`BftState::finalize`]'s call.
    Certificate(Box<PrecommitCertificate>),
    /// A proof of lock, re-verified the same way.
    LockProof(Box<PrevoteCertificate>),
    /// A round change, decoded and signature-checked against its generation.
    RoundChange(Box<RoundChange>),
    /// A peer asking for history.
    SyncRequested(SyncRequest),
    /// A synchronisation bundle, decoded with every embedded certificate
    /// re-verified. Not verified as a chain: `verify_history` does that, and the
    /// node calls it before installing anything.
    Bundle(Box<SyncBundle>),
    /// A halt **alert**: a peer says it saw something wrong. No authority, stops
    /// nothing, kept only so an operator can look.
    HaltAlert([u8; 32]),
    /// A halt **proof**, decoded and with both certificates re-verified from their
    /// bytes. Whether it halts the engine is decided by [`HaltProof::verify`] and
    /// then by [`BftState::halt_with`], never here.
    HaltProof(Box<HaltProof>),
    /// A DAG transaction whose identifier and signature were checked against its
    /// own bytes. Whether it may enter the DAG (parents known, not a duplicate,
    /// node not halted) is the node's call, in `Node::admit_transaction`.
    Transaction(Box<Transaction>),
    /// A message this node carries but does not act on.
    Carried(MessageKind),
}

/// Why a message was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Reject {
    /// The envelope is not the peer's, or was altered in transit.
    #[error("not authentic: {0}")]
    Unauthenticated(&'static str),

    /// The peer's key does not derive the identity it routes by.
    #[error("sender does not match the authenticated peer")]
    SenderMismatch,

    /// The payload is not valid in its own format.
    #[error("malformed {kind}: {detail}")]
    Malformed {
        /// Kind.
        kind: &'static str,
        /// Detail.
        detail: String,
    },

    /// The peer is over its budget.
    #[error("rate limited")]
    RateLimited,

    /// The node is halted: no consensus message is processed any more.
    #[error("node is halted")]
    Halted,

    /// The message belongs to another network.
    #[error("wrong network {0}")]
    Network(u64),

    /// The engine refused.
    #[error("engine refused: {0}")]
    Engine(String),
}

impl From<PeerError> for Reject {
    fn from(error: PeerError) -> Self {
        Self::Unauthenticated(match error {
            PeerError::Version { .. } => "version",
            PeerError::Network { .. } => "network",
            PeerError::IdentityMismatch => "identity",
            PeerError::TooManyConnections(_) => "connection limit",
            PeerError::AddressLimitReached { .. } => "address connection limit",
            PeerError::RateLimited(_) => "rate limit",
            PeerError::NotAValidator => "not a validator",
            PeerError::Refused(reason) => reason,
        })
    }
}

impl From<WireError> for Reject {
    fn from(error: WireError) -> Self {
        Self::Unauthenticated(match error {
            WireError::Malformed(_) => "malformed frame",
            WireError::TooLarge { .. } => "oversized frame",
            WireError::Version(_) => "version",
            WireError::Kind(_) => "kind",
            WireError::IdMismatch => "identifier",
            WireError::BadSignature => "signature",
            WireError::Network(_) => "network",
        })
    }
}

/// Outcome of one incoming message.
#[derive(Debug)]
pub enum Incoming {
    /// Accepted; the caller may act on it.
    Accepted(Dispatched),
    /// A duplicate: already seen, dropped without error.
    Duplicate,
    /// Refused, with a named reason. The connection may or may not be dropped;
    /// see [`verdict_keeps_connection`].
    Refused(Reject),
}

/// Whether a refusal should tear the connection down.
///
/// Authentication failures are fatal for the connection; a bad body is not, so a
/// single malformed message does not cost a working peer.
pub fn verdict_keeps_connection(reject: &Reject) -> bool {
    !matches!(
        reject,
        Reject::Unauthenticated(_) | Reject::SenderMismatch | Reject::Network(_)
    )
}

/// Gate 1: is this envelope authentically from `peer`, fresh, and within budget?
///
/// `envelope.sender` must equal the peer's derived identity; the signature covers
/// the whole body; the identifier must reproduce; a replay is refused by the
/// window. `HALT` state is checked by the caller for consensus kinds.
pub fn authenticate(
    peer: &mut PeerState,
    envelope: &Envelope,
    network: u64,
    now: std::time::Instant,
) -> Result<(), Reject> {
    if envelope.network != network {
        return Err(Reject::Network(envelope.network));
    }
    if envelope.sender != peer.identity.id.0 {
        return Err(Reject::SenderMismatch);
    }
    if !envelope.verify_signature(&peer.identity.public_key) {
        return Err(Reject::Unauthenticated("signature"));
    }
    if !peer.limiter.allow(now) {
        peer.refused += 1;
        return Err(Reject::RateLimited);
    }
    peer.last_seen = now;
    Ok(())
}

/// Whether this envelope is attributable to the peer it claims.
///
/// A message whose `sender` is not the admitted peer's identity is never
/// accounted against that peer's quota, and never reaches the engine: it is a
/// different party, and the only correct treatment is refusal.
pub fn dispatcher_admits(peer: &PeerState, envelope: &Envelope) -> bool {
    peer.authenticated && envelope.sender == peer.identity.id.0
}

/// Gate 2 + 3: decode the body in its own format, then let the engine decide.
///
/// The dispatcher never inspects a vote's weight, a certificate's support, or a
/// generation's validity: those checks live in the engine and in `l2crypto`, and
/// duplicating them here would be a second, divergent authority.
pub fn dispatch(
    peer: &mut PeerState,
    envelope: &Envelope,
    state: &mut BftState,
    registry: &ValidatorRegistry,
    halted: bool,
) -> Incoming {
    if !peer.replay.accept(envelope.message_id) {
        return Incoming::Duplicate;
    }
    if halted && envelope.kind.is_consensus() {
        return Incoming::Refused(Reject::Halted);
    }
    match envelope.kind {
        MessageKind::Prevote | MessageKind::Precommit => {
            let vote = match ConsensusVote::decode(&envelope.payload) {
                Ok(vote) => vote,
                Err(error) => {
                    peer.refused += 1;
                    return Incoming::Refused(Reject::Malformed {
                        kind: envelope.kind.name(),
                        detail: error.to_string(),
                    });
                }
            };
            let phase_ok = matches!(
                (envelope.kind, vote.phase),
                (
                    MessageKind::Prevote,
                    crate::l2crypto::vote::VotePhase::Prevote
                ) | (
                    MessageKind::Precommit,
                    crate::l2crypto::vote::VotePhase::Precommit
                )
            );
            if !phase_ok {
                peer.refused += 1;
                return Incoming::Refused(Reject::Malformed {
                    kind: envelope.kind.name(),
                    detail: "payload phase disagrees with the message kind".into(),
                });
            }
            let outcome = state.accept_vote(&vote, registry);
            peer.accepted += 1;
            Incoming::Accepted(Dispatched::Vote(AcceptedVote::new(vote, outcome)))
        }
        MessageKind::Proposal => {
            if envelope.payload.len() != 32 {
                peer.refused += 1;
                return Incoming::Refused(Reject::Malformed {
                    kind: "proposal",
                    detail: "a proposal is a 32-byte value".into(),
                });
            }
            let mut value = [0u8; 32];
            value.copy_from_slice(&envelope.payload);
            // N-1: a proposal is receivable only from the elected proposer for
            // this `(generation, height, round)`. The engine owns the rule; the
            // dispatcher only supplies the authenticated sender.
            match state.accept_proposal(value, ValidatorId(envelope.sender), registry) {
                Ok(()) => {
                    peer.accepted += 1;
                    Incoming::Accepted(Dispatched::Proposal(value))
                }
                Err(error) => {
                    peer.refused += 1;
                    Incoming::Refused(Reject::Engine(error.to_string()))
                }
            }
        }
        MessageKind::Checkpoint => match Checkpoint::decode(&envelope.payload) {
            Ok(checkpoint) => {
                peer.accepted += 1;
                Incoming::Accepted(Dispatched::Checkpoint(Box::new(checkpoint)))
            }
            Err(error) => {
                peer.refused += 1;
                Incoming::Refused(Reject::Malformed {
                    kind: "checkpoint",
                    detail: error.to_string(),
                })
            }
        },
        MessageKind::QuorumCertificate => {
            match PrecommitCertificate::from_bytes(&envelope.payload, registry, envelope.network) {
                Ok(certificate) => {
                    peer.accepted += 1;
                    Incoming::Accepted(Dispatched::Certificate(Box::new(certificate)))
                }
                Err(error) => {
                    peer.refused += 1;
                    Incoming::Refused(Reject::Malformed {
                        kind: "qc",
                        detail: error.to_string(),
                    })
                }
            }
        }
        MessageKind::ProofOfLock => {
            match PrevoteCertificate::from_bytes(&envelope.payload, registry, envelope.network) {
                Ok(certificate) => {
                    peer.accepted += 1;
                    Incoming::Accepted(Dispatched::LockProof(Box::new(certificate)))
                }
                Err(error) => {
                    peer.refused += 1;
                    Incoming::Refused(Reject::Malformed {
                        kind: "pol",
                        detail: error.to_string(),
                    })
                }
            }
        }
        MessageKind::RoundChange => {
            match RoundChange::decode(&envelope.payload, registry, envelope.network) {
                Ok(change) => {
                    peer.accepted += 1;
                    Incoming::Accepted(Dispatched::RoundChange(Box::new(change)))
                }
                Err(error) => {
                    peer.refused += 1;
                    Incoming::Refused(Reject::Malformed {
                        kind: "round-change",
                        detail: error.to_string(),
                    })
                }
            }
        }
        MessageKind::SyncRequest => match SyncRequest::decode(&envelope.payload) {
            Ok(request) if request.network == envelope.network => {
                peer.accepted += 1;
                Incoming::Accepted(Dispatched::SyncRequested(request))
            }
            Ok(_) => {
                peer.refused += 1;
                Incoming::Refused(Reject::Network(envelope.network))
            }
            Err(error) => {
                peer.refused += 1;
                Incoming::Refused(Reject::Malformed {
                    kind: "sync-request",
                    detail: error.to_string(),
                })
            }
        },
        MessageKind::BootstrapResponse => match SyncBundle::decode(&envelope.payload) {
            Ok(bundle) => {
                peer.accepted += 1;
                Incoming::Accepted(Dispatched::Bundle(Box::new(bundle)))
            }
            Err(error) => {
                peer.refused += 1;
                Incoming::Refused(Reject::Malformed {
                    kind: "bundle",
                    detail: error.to_string(),
                })
            }
        },
        MessageKind::HaltEvidence => {
            // A 32-byte payload is an alert (mission BE format), anything carrying
            // the proof tag must be a complete proof. The two are never conflated:
            // an alert cannot halt a node, and a proof cannot be mistaken for one.
            if envelope.payload.first() == Some(&HALT_PROOF_TAG) {
                match HaltProof::decode(&envelope.payload, registry) {
                    Ok(proof) => {
                        peer.accepted += 1;
                        Incoming::Accepted(Dispatched::HaltProof(Box::new(proof)))
                    }
                    Err(error) => {
                        peer.refused += 1;
                        Incoming::Refused(Reject::Malformed {
                            kind: "halt-proof",
                            detail: error.to_string(),
                        })
                    }
                }
            } else if envelope.payload.len() == 32 {
                let mut alert = [0u8; 32];
                alert.copy_from_slice(&envelope.payload);
                peer.accepted += 1;
                Incoming::Accepted(Dispatched::HaltAlert(alert))
            } else {
                peer.refused += 1;
                Incoming::Refused(Reject::Malformed {
                    kind: "halt",
                    detail: "an alert is 32 bytes, a proof carries the proof tag".into(),
                })
            }
        }
        MessageKind::Transaction => match bincode::deserialize::<Transaction>(&envelope.payload) {
            Ok(transaction) => {
                // Gate 2 is the transaction's own canonical format: its identifier
                // must reproduce from its fields, and its signature must verify
                // against its own public key. The check is the one the rest of the
                // node already uses (`Wallet::verify_transaction`), not a second
                // implementation of it.
                if !transaction.verify_hash_compatible() {
                    peer.refused += 1;
                    return Incoming::Refused(Reject::Malformed {
                        kind: "transaction",
                        detail: "identifier does not reproduce from its fields".into(),
                    });
                }
                if !crate::wallet::Wallet::verify_transaction(&transaction) {
                    peer.refused += 1;
                    return Incoming::Refused(Reject::Malformed {
                        kind: "transaction",
                        detail: "signature does not verify".into(),
                    });
                }
                peer.accepted += 1;
                Incoming::Accepted(Dispatched::Transaction(Box::new(transaction)))
            }
            Err(error) => {
                peer.refused += 1;
                Incoming::Refused(Reject::Malformed {
                    kind: "transaction",
                    detail: error.to_string(),
                })
            }
        },
        other => {
            peer.accepted += 1;
            Incoming::Accepted(Dispatched::Carried(other))
        }
    }
}
