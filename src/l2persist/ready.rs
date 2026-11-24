//! Durable READY certificates (`R-SET-7`, mission BC / R-BB-2).
//!
//! # Why READY must be durable
//!
//! A `TRANSITION` is decided on the strength of `q_new` READY signatures. If those
//! signatures only live in memory, a restarted node can no longer prove that the
//! set it activated was ever ready — it would have to trust its own logs. This
//! module makes the certificate survive the process.
//!
//! # What is stored, and what is checked on the way in and out
//!
//! One record per `(candidate_id, signer)`, keyed so that historical candidates
//! never overwrite each other. Each record is:
//!
//! - verified **against the candidate registry** before it is written, so a
//!   signature that does not check out is never made durable;
//! - re-verified **after** it is read, so a record edited on disk is rejected;
//! - compared byte-for-byte against any existing record for the same key, so two
//!   different attestations from one signer for one candidate are a contradiction
//!   that blocks, never an arbitration;
//! - weighted by the registry, never by a declared field — [`SignedReady`] has no
//!   weight field at all.
//!
//! A corrupted, incomplete or contradictory store is an error. Nothing here
//! returns a partial or "best effort" evidence set.

use thiserror::Error;

use crate::consensus::generation::{quorum_threshold, ValidatorId, ValidatorWeight};
use crate::l2crypto::ready::{
    evaluate_signed, ReadyReject, SignedReadinessOutcome, SignedReady, SignedReadyExpectation,
};
use crate::l2crypto::registry::ValidatorRegistry;
use crate::l2persist::slotlock::{open_sealed, seal, CasStore, SlotStoreError};

/// Format version of a stored READY record.
pub const READY_FORMAT_VERSION: u8 = 1;

/// Storage prefix of every READY record.
pub const READY_PREFIX: &str = "l2/v3/ready/";

/// Errors of the READY store.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadyStoreError {
    /// The attestation does not verify against the candidate registry.
    #[error("ready for {signer} rejected: {reason:?}")]
    Rejected {
        /// Signer, hex.
        signer: String,
        /// Rejection reason.
        reason: ReadyReject,
    },

    /// The registry is not the candidate set the expectation names.
    #[error("candidate registry root {found} is not the expected {expected}")]
    WrongRegistry {
        /// Expected root.
        expected: String,
        /// Registry root.
        found: String,
    },

    /// Two different attestations from one signer for one candidate.
    #[error("contradictory READY for {signer} at candidate {candidate}: stored bytes differ")]
    Contradictory {
        /// Candidate, hex.
        candidate: String,
        /// Signer, hex.
        signer: String,
    },

    /// A stored record could not be read.
    #[error("ready record unreadable: {0}")]
    Corrupt(String),

    /// The underlying store failed.
    #[error("ready store error: {0}")]
    Store(String),
}

impl From<SlotStoreError> for ReadyStoreError {
    fn from(e: SlotStoreError) -> Self {
        Self::Store(e.to_string())
    }
}

/// What the store can prove about one candidate after a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyEvidence {
    /// Candidate the evidence is about.
    pub candidate: [u8; 32],
    /// Weight of the accepted READY, from the candidate registry.
    pub support: ValidatorWeight,
    /// Total weight of the candidate set.
    pub total: ValidatorWeight,
    /// Quorum `q_new = ceil(2W/3)`.
    pub quorum: ValidatorWeight,
    /// Whether `support` reaches `quorum`.
    pub reached: bool,
    /// Accepted signers, sorted.
    pub accepted: Vec<ValidatorId>,
    /// Rejected records, with the reason.
    pub rejected: Vec<(ValidatorId, ReadyReject)>,
    /// Number of records read for this candidate.
    pub records: usize,
}

impl ReadyEvidence {
    /// Evidence that reaches the quorum is what `R-SET-7` requires. It still
    /// proves only a past intent: see [`SignedReadinessOutcome::is_past_intent_only`].
    pub fn is_quorate(&self) -> bool {
        self.reached
    }
}

/// Key of one READY record.
///
/// The candidate is part of the key, so a failed candidate leaves its READY
/// behind as history instead of being overwritten by the next attempt. The signer
/// is part of the key, so one signer cannot hide another.
pub fn ready_key(candidate: &[u8; 32], signer: &ValidatorId) -> String {
    format!(
        "{READY_PREFIX}{}/{}",
        hex::encode(candidate),
        hex::encode(signer.0)
    )
}

fn prefix_for(candidate: &[u8; 32]) -> String {
    format!("{READY_PREFIX}{}/", hex::encode(candidate))
}

fn check_registry(
    registry: &ValidatorRegistry,
    expected: &SignedReadyExpectation,
) -> Result<(), ReadyStoreError> {
    if registry.set_root() != expected.new_set_root {
        return Err(ReadyStoreError::WrongRegistry {
            expected: hex::encode(expected.new_set_root),
            found: hex::encode(registry.set_root()),
        });
    }
    Ok(())
}

/// Verify and store one READY.
///
/// Idempotent: re-storing the exact same attestation succeeds and changes
/// nothing. A **different** attestation for the same `(candidate, signer)` is a
/// contradiction and is refused.
pub fn record_ready(
    store: &dyn CasStore,
    registry: &ValidatorRegistry,
    expected: &SignedReadyExpectation,
    ready: &SignedReady,
) -> Result<(), ReadyStoreError> {
    check_registry(registry, expected)?;
    ready
        .verify(registry, expected)
        .map_err(|reason| ReadyStoreError::Rejected {
            signer: hex::encode(ready.signer.0),
            reason,
        })?;
    if ready.candidate != expected.candidate {
        return Err(ReadyStoreError::Rejected {
            signer: hex::encode(ready.signer.0),
            reason: ReadyReject::WrongCandidate,
        });
    }
    let key = ready_key(&ready.candidate, &ready.signer);
    let payload = seal(&ready.encode());
    let current = store.get(&key)?;
    match current {
        Some(existing) => {
            if existing == payload {
                return Ok(());
            }
            // A different attestation is not "newer wins": both are signed
            // intents, and choosing one would be arbitration between them.
            let stored =
                open_sealed(&existing).map_err(|e| ReadyStoreError::Corrupt(e.to_string()))?;
            if stored == ready.encode() {
                return Ok(());
            }
            return Err(ReadyStoreError::Contradictory {
                candidate: hex::encode(ready.candidate),
                signer: hex::encode(ready.signer.0),
            });
        }
        None => {
            if !store.cas(&key, None, &payload)? {
                return Err(ReadyStoreError::Store(
                    "concurrent writer inserted a READY for this signer".to_string(),
                ));
            }
            store.flush()?;
            Ok(())
        }
    }
}

/// Read back every READY recorded for `expected.candidate` and recompute the
/// quorum from the candidate registry.
///
/// Records for other candidates are skipped and left untouched: they are history,
/// not noise.
pub fn load_ready_evidence(
    store: &dyn CasStore,
    registry: &ValidatorRegistry,
    expected: &SignedReadyExpectation,
) -> Result<ReadyEvidence, ReadyStoreError> {
    check_registry(registry, expected)?;
    let prefix = prefix_for(&expected.candidate);
    let records = store.scan(&prefix)?;
    let mut readys: Vec<SignedReady> = Vec::new();
    let mut by_signer: std::collections::BTreeMap<ValidatorId, Vec<u8>> =
        std::collections::BTreeMap::new();
    for (_, bytes) in records {
        let payload = open_sealed(&bytes)
            .map_err(|e| ReadyStoreError::Corrupt(e.to_string()))?
            .to_vec();
        let ready = SignedReady::decode(&payload)
            .map_err(|e| ReadyStoreError::Corrupt(format!("undecodable READY: {e}")))?;
        if ready.candidate != expected.candidate {
            return Err(ReadyStoreError::Corrupt(format!(
                "record under candidate {} names candidate {}",
                hex::encode(expected.candidate),
                hex::encode(ready.candidate)
            )));
        }
        if let Some(previous) = by_signer.get(&ready.signer) {
            if previous != &payload {
                // Two different attestations were made durable for one signer.
                return Err(ReadyStoreError::Contradictory {
                    candidate: hex::encode(expected.candidate),
                    signer: hex::encode(ready.signer.0),
                });
            }
            continue;
        }
        by_signer.insert(ready.signer, payload);
        readys.push(ready);
    }
    let outcome: SignedReadinessOutcome = evaluate_signed(&readys, expected, registry);
    let total = registry.total_voting_weight();
    let quorum = quorum_threshold(total);
    Ok(ReadyEvidence {
        candidate: expected.candidate,
        support: outcome.weight,
        total,
        quorum,
        reached: outcome.reached && outcome.weight.get() >= quorum.get(),
        accepted: outcome.accepted,
        rejected: outcome.rejected,
        records: readys.len(),
    })
}

/// Record a batch, stopping at the first refusal.
///
/// Deliberately not atomic across records: a batch that fails halfway leaves the
/// verified prefix durable, which is correct — those attestations **were** made,
/// and re-reading recomputes the quorum from what is actually there.
pub fn record_readys(
    store: &dyn CasStore,
    registry: &ValidatorRegistry,
    expected: &SignedReadyExpectation,
    readys: &[SignedReady],
) -> Result<ReadyEvidence, ReadyStoreError> {
    for ready in readys {
        record_ready(store, registry, expected, ready)?;
    }
    load_ready_evidence(store, registry, expected)
}

/// Every candidate for which at least one READY record exists.
///
/// Used to enumerate historical candidates without decoding every record twice.
pub fn recorded_candidates(store: &dyn CasStore) -> Result<Vec<[u8; 32]>, ReadyStoreError> {
    let records = store.scan(READY_PREFIX)?;
    let mut seen: Vec<[u8; 32]> = Vec::new();
    for (key, _) in records {
        let rest = key
            .strip_prefix(READY_PREFIX)
            .ok_or_else(|| ReadyStoreError::Corrupt(format!("foreign key {key}")))?;
        let hex_candidate = rest
            .split('/')
            .next()
            .ok_or_else(|| ReadyStoreError::Corrupt(format!("malformed key {key}")))?;
        let bytes = hex::decode(hex_candidate)
            .map_err(|e| ReadyStoreError::Corrupt(format!("malformed candidate in {key}: {e}")))?;
        if bytes.len() != 32 {
            return Err(ReadyStoreError::Corrupt(format!(
                "candidate in {key} is {} bytes",
                bytes.len()
            )));
        }
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&bytes);
        if !seen.contains(&candidate) {
            seen.push(candidate);
        }
    }
    Ok(seen)
}
