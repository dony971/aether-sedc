//! Deterministic network simulator (mission BH, priority 4).
//!
//! # What this is
//!
//! A reproducible, single-threaded network between real [`BftState`] engines. Every
//! message is an object in a queue with a **virtual** delivery time in steps; the
//! simulator advances that time one step at a time and nothing else in it reads a
//! clock. The same configuration therefore produces the same run, on any machine,
//! in any order, every time.
//!
//! What it controls, explicitly and per run:
//!
//! | Knob | Where |
//! |---|---|
//! | latency, jitter | [`SimConfig::latency_steps`], [`SimConfig::jitter_steps`] |
//! | message loss | [`SimConfig::loss_ppm`] |
//! | duplication | [`SimConfig::duplicate_ppm`] |
//! | reordering | inherent: delivery order is the queue order, which jitter breaks |
//! | partitions | [`Sim::partition`], [`Sim::heal`] |
//! | a validator stopping | [`Sim::set_up`] |
//! | a validator restarting | [`Sim::restart`] |
//! | slow synchronisation | [`SimConfig::latency_steps`] applied to every message |
//!
//! # What the simulator does **not** do
//!
//! - It does not implement consensus. Every vote, certificate, lock, round change
//!   and finality decision is produced by [`BftState`] through its public API; the
//!   simulator only moves messages and calls the engine.
//! - It does not elect a proposer. `T-AA` needs H2, which the corpus does not
//!   specify for this implementation, so the **driver** (this file, not the
//!   engine) decides which value is proposed at a height. That is a simulation
//!   choice, stated as such, and it is why no liveness claim is derived from it.
//! - It does not prove anything. A run that decides is an observation, not a
//!   theorem: see `remaining-risks.md`.
//!
//! # Measured
//!
//! [`SimMetrics`] counts messages sent, delivered, dropped by loss, dropped by
//! partition, dropped because the target was down, duplicated, reordered,
//! retransmissions, round changes emitted, rounds adopted, and the virtual time of
//! the first decision. Counts are observations of one run.

use ed25519_dalek::{Signer, SigningKey};

use crate::consensus::checkpoint::Checkpoint;
use crate::consensus::generation::{
    quorum_threshold, CheckpointHeight, GenerationId, Round, ValidatorId, ValidatorWeight,
};
use crate::l2bft::engine::BftState;
use crate::l2bft::round::RoundChange;
use crate::l2bft::timer::RoundTimer;
use crate::l2crypto::registry::{validator_id, Admissibility, RegistryEntry, ValidatorRegistry};
use crate::l2crypto::vote::ConsensusVote;
use crate::l2persist::MemoryAtomicSlotStore;

/// Configuration of one simulated network.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Network discriminator.
    pub network: u64,
    /// Generation identity.
    pub generation: [u8; 32],
    /// Store anchor.
    pub anchor: [u8; 32],
    /// One seed per validator; the validator identity is derived from the key.
    pub seeds: Vec<u8>,
    /// Weight of every validator.
    pub weight: u64,
    /// Base latency, in steps.
    pub latency_steps: u64,
    /// Extra latency drawn in `0..=jitter_steps`.
    pub jitter_steps: u64,
    /// Messages lost, in parts per million.
    pub loss_ppm: u64,
    /// Messages duplicated, in parts per million.
    pub duplicate_ppm: u64,
    /// Seed of the deterministic PRNG.
    pub seed: u64,
    /// Steps before a round is considered timed out.
    pub timeout_steps: u64,
    /// Steps between two retransmissions of this node's own votes (0 disables).
    pub retransmit_every: u64,
    /// Elect a proposer with `l2bft::proposer` instead of letting every validator
    /// propose (mission BI). Off by default so that every BH result keeps its exact
    /// meaning: the runs that use it say so explicitly.
    pub elect_proposer: bool,
}

impl SimConfig {
    /// A lossless, low-latency network over `seeds`.
    pub fn new(network: u64, seeds: Vec<u8>, weight: u64) -> Self {
        Self {
            network,
            generation: [7u8; 32],
            anchor: [0x5A; 32],
            seeds,
            weight,
            latency_steps: 1,
            jitter_steps: 0,
            loss_ppm: 0,
            duplicate_ppm: 0,
            seed: 0x5EED_1234_ABCD_0001,
            timeout_steps: 8,
            retransmit_every: 4,
            elect_proposer: false,
        }
    }

    /// Set the latency profile.
    pub fn with_latency(mut self, base: u64, jitter: u64) -> Self {
        self.latency_steps = base;
        self.jitter_steps = jitter;
        self
    }

    /// Set loss and duplication, in parts per million.
    pub fn with_faults(mut self, loss_ppm: u64, duplicate_ppm: u64) -> Self {
        self.loss_ppm = loss_ppm;
        self.duplicate_ppm = duplicate_ppm;
        self
    }

    /// Set the deterministic PRNG seed.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Set the timeout budget, in steps.
    pub fn with_timeout(mut self, steps: u64) -> Self {
        self.timeout_steps = steps;
        self
    }
}

/// A message the simulator carries.
#[derive(Debug, Clone)]
pub enum Body {
    /// A proposal: only the elected proposer may send one when the simulator
    /// elects a proposer (mission BI).
    Proposal([u8; 32]),
    /// A prevote.
    Prevote(ConsensusVote),
    /// A precommit.
    Precommit(ConsensusVote),
    /// A round change.
    RoundChange(Box<RoundChange>),
}

/// One queued message.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// Virtual step at which it is delivered.
    pub at: u64,
    /// Sender index.
    pub from: usize,
    /// Receiver index.
    pub to: usize,
    /// Monotone sequence number, used to detect reordering.
    pub seq: u64,
    /// Payload.
    pub body: Body,
}

/// Counters of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimMetrics {
    /// Messages handed to the network.
    pub sent: u64,
    /// Messages actually delivered.
    pub delivered: u64,
    /// Messages dropped by the configured loss.
    pub dropped_loss: u64,
    /// Messages dropped because sender and receiver are in different partitions.
    pub dropped_partition: u64,
    /// Messages dropped because the receiver was down.
    pub dropped_down: u64,
    /// Messages delivered twice (duplication).
    pub duplicated: u64,
    /// Messages delivered out of sequence order.
    pub reordered: u64,
    /// Votes re-sent after a timeout (no new signature).
    pub retransmissions: u64,
    /// Round changes emitted by timers.
    pub round_changes: u64,
    /// Proposals emitted by the elected proposer.
    pub proposals: u64,
    /// Round adoptions observed by the engines.
    pub rounds_adopted: u64,
    /// Decisions taken (one per validator that decided).
    pub decisions: u64,
}

/// Result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimOutcome {
    /// Virtual time of the first decision, if any.
    pub decided_at: Option<u64>,
    /// Value decided by the first validator that decided.
    pub decided_value: Option<[u8; 32]>,
    /// Number of validators that decided.
    pub decided_count: usize,
    /// Whether every validator that decided agrees.
    pub agreed: bool,
    /// Highest round reached by any engine.
    pub max_round: u32,
    /// Counters.
    pub metrics: SimMetrics,
    /// Total virtual steps run.
    pub steps: u64,
}

/// A deterministic simulated network of validators.
pub struct Sim {
    /// Configuration.
    pub config: SimConfig,
    /// Registry in force.
    pub registry: ValidatorRegistry,
    /// One engine per validator.
    pub engines: Vec<BftState>,
    /// Metrics of the current run.
    pub metrics: SimMetrics,
    /// Virtual time, in steps.
    pub time: u64,
    /// Height under test.
    pub height: CheckpointHeight,
    keys: Vec<SigningKey>,
    ids: Vec<ValidatorId>,
    stores: Vec<MemoryAtomicSlotStore>,
    timers: Vec<RoundTimer>,
    up: Vec<bool>,
    group: Vec<u8>,
    queue: Vec<Envelope>,
    decided: Vec<Option<[u8; 32]>>,
    last_cp: Option<Checkpoint>,
    value: [u8; 32],
    seq: u64,
    rng: u64,
    last_delivered_seq: Vec<u64>,
    first_decision_at: Option<u64>,
    first_decision_value: Option<[u8; 32]>,
}

impl Sim {
    /// Build a simulator over `config.seeds`.
    pub fn new(config: SimConfig) -> Self {
        let keys: Vec<SigningKey> = config
            .seeds
            .iter()
            .map(|seed| SigningKey::from_bytes(&[*seed; 32]))
            .collect();
        let entries: Vec<RegistryEntry> = config
            .seeds
            .iter()
            .map(|seed| RegistryEntry {
                id: validator_id(
                    &SigningKey::from_bytes(&[*seed; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                public_key: SigningKey::from_bytes(&[*seed; 32])
                    .verifying_key()
                    .to_bytes(),
                weight: ValidatorWeight(config.weight),
                admissibility: Admissibility::Eligible,
            })
            .collect();
        let registry =
            ValidatorRegistry::new(GenerationId(config.generation), &entries).expect("registry");
        let ids: Vec<ValidatorId> = keys
            .iter()
            .map(|key| validator_id(&key.verifying_key().to_bytes()))
            .collect();
        let count = config.seeds.len();
        let engines = (0..count)
            .map(|_| {
                BftState::new(
                    config.network,
                    &registry,
                    CheckpointHeight(0),
                    config.anchor,
                )
            })
            .collect();
        let timers = (0..count)
            .map(|_| RoundTimer::new(config.timeout_steps))
            .collect();
        let value = [0u8; 32];
        let mut sim = Self {
            metrics: SimMetrics::default(),
            time: 0,
            height: CheckpointHeight(0),
            keys,
            ids,
            stores: (0..count).map(|_| MemoryAtomicSlotStore::new()).collect(),
            timers,
            up: vec![true; count],
            group: vec![0; count],
            queue: Vec::new(),
            decided: vec![None; count],
            last_cp: None,
            value,
            seq: 0,
            rng: config.seed | 1,
            last_delivered_seq: vec![0; count],
            first_decision_at: None,
            first_decision_value: None,
            registry,
            engines,
            config,
        };
        // `finalize` requires the certified value to be the checkpoint's own
        // identifier, so the driver proposes exactly that.
        sim.value = sim.canonical_checkpoint().id();
        sim
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.engines.len()
    }

    /// Whether there is no validator at all.
    pub fn is_empty(&self) -> bool {
        self.engines.is_empty()
    }

    /// Identity of validator `index`.
    pub fn id_of(&self, index: usize) -> ValidatorId {
        self.ids[index]
    }

    /// Stop (`up = false`) or restart a validator, keeping its store.
    pub fn set_up(&mut self, index: usize, up: bool) {
        self.up[index] = up;
    }

    /// Restart a validator: it comes back with the **same** store, which is what
    /// the engine must recover from.
    pub fn restart(&mut self, index: usize) {
        let store = std::mem::take(&mut self.stores[index]);
        let recovered = crate::l2bft::restore_engine(
            &store,
            &self.registry,
            Some(self.config.anchor),
            self.config.network,
            self.height,
        );
        self.stores[index] = store;
        self.engines[index] = recovered.state;
        self.timers[index] = RoundTimer::new(self.config.timeout_steps);
        self.decided[index] = None;
        self.up[index] = true;
        self.group[index] = 0;
    }

    /// Split the network: each inner slice becomes one partition.
    ///
    /// Validators named in no group stay in a partition of their own.
    pub fn partition(&mut self, groups: &[&[usize]]) {
        let mut next = 1u8;
        for group in groups {
            for index in *group {
                self.group[*index] = next;
            }
            next += 1;
        }
        for index in 0..self.group.len() {
            if !groups.iter().any(|group| group.contains(&index)) {
                self.group[index] = 200u8.saturating_add(index as u8);
            }
        }
    }

    /// Put everybody back in one partition.
    pub fn heal(&mut self) {
        for group in &mut self.group {
            *group = 0;
        }
    }

    /// Run one virtual step: deliver what is due, then let the engines act.
    pub fn step(&mut self) {
        self.time += 1;
        self.deliver_due();
        let outgoing = self.drive();
        for (from, body) in outgoing {
            self.enqueue(from, body);
        }
    }

    /// Run `steps` virtual steps.
    pub fn run(&mut self, steps: usize) {
        for _ in 0..steps {
            self.step();
        }
    }

    /// Run until at least one validator decided, or `max_steps` is reached.
    pub fn run_until_decided(&mut self, max_steps: usize) -> Option<u64> {
        for _ in 0..max_steps {
            if self.first_decision_at.is_some() {
                return self.first_decision_at;
            }
            self.step();
        }
        self.first_decision_at
    }

    /// Observation of the run.
    pub fn outcome(&self, steps: u64) -> SimOutcome {
        let values: Vec<[u8; 32]> = self.decided.iter().flatten().copied().collect();
        let agreed = values.windows(2).all(|pair| pair[0] == pair[1]);
        SimOutcome {
            decided_at: self.first_decision_at,
            decided_value: self.first_decision_value,
            decided_count: values.len(),
            agreed,
            max_round: self
                .engines
                .iter()
                .map(|engine| engine.round.get())
                .max()
                .unwrap_or(0),
            metrics: self.metrics.clone(),
            steps,
        }
    }

    /// Values decided by each validator at the current height.
    pub fn decided_values(&self) -> Vec<Option<[u8; 32]>> {
        self.decided.clone()
    }

    /// Whether every validator that decided agrees, i.e. no contradictory
    /// finality was observed.
    pub fn no_contradiction(&self) -> bool {
        let values: Vec<[u8; 32]> = self.decided.iter().flatten().copied().collect();
        values.windows(2).all(|pair| pair[0] == pair[1])
    }

    // -- internals ----------------------------------------------------------

    fn rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn chance(&mut self, ppm: u64) -> bool {
        if ppm == 0 {
            return false;
        }
        self.rand() % 1_000_000 < ppm
    }

    fn enqueue(&mut self, from: usize, body: Body) {
        for to in 0..self.engines.len() {
            if to == from {
                continue;
            }
            self.metrics.sent += 1;
            if self.chance(self.config.loss_ppm) {
                self.metrics.dropped_loss += 1;
                continue;
            }
            let copies = if self.chance(self.config.duplicate_ppm) {
                self.metrics.duplicated += 1;
                2
            } else {
                1
            };
            for copy in 0..copies {
                let jitter = if self.config.jitter_steps == 0 {
                    0
                } else {
                    self.rand() % (self.config.jitter_steps + 1)
                };
                let at = self.time + self.config.latency_steps + jitter + copy;
                self.seq += 1;
                self.queue.push(Envelope {
                    at,
                    from,
                    to,
                    seq: self.seq,
                    body: body.clone(),
                });
            }
        }
    }

    fn deliver_due(&mut self) {
        let now = self.time;
        let mut due: Vec<Envelope> = Vec::new();
        let mut keep: Vec<Envelope> = Vec::new();
        for envelope in std::mem::take(&mut self.queue) {
            if envelope.at <= now {
                due.push(envelope);
            } else {
                keep.push(envelope);
            }
        }
        self.queue = keep;
        due.sort_by_key(|envelope| (envelope.seq, envelope.at));

        for envelope in due {
            if !self.up[envelope.to] {
                self.metrics.dropped_down += 1;
                continue;
            }
            if self.group[envelope.from] != self.group[envelope.to] {
                self.metrics.dropped_partition += 1;
                continue;
            }
            if envelope.seq < self.last_delivered_seq[envelope.to] {
                self.metrics.reordered += 1;
            }
            self.last_delivered_seq[envelope.to] =
                self.last_delivered_seq[envelope.to].max(envelope.seq);
            self.metrics.delivered += 1;
            match &envelope.body {
                Body::Proposal(value) => {
                    // N-1: the receiver admits a proposal only from the proposer
                    // elected for its own position.
                    let _ = self.engines[envelope.to].accept_proposal(
                        *value,
                        self.ids[envelope.from],
                        &self.registry,
                    );
                }
                Body::Prevote(vote) => {
                    let _ = self.engines[envelope.to].accept_vote(vote, &self.registry);
                }
                Body::Precommit(vote) => {
                    let _ = self.engines[envelope.to].accept_vote(vote, &self.registry);
                }
                Body::RoundChange(change) => {
                    match self.engines[envelope.to].process_round_change(
                        (**change).clone(),
                        &self.registry,
                        self.config.network,
                    ) {
                        Ok(crate::l2bft::RoundChangeOutcome::Adopted { .. }) => {
                            self.metrics.rounds_adopted += 1;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn drive(&mut self) -> Vec<(usize, Body)> {
        let mut outgoing: Vec<(usize, Body)> = Vec::new();
        let value = self.value;
        let checkpoint = self.canonical_checkpoint();
        let quorum = quorum_threshold(self.registry.total_voting_weight());
        let signers_needed = if self.config.weight == 0 {
            u64::MAX
        } else {
            (quorum.get() + self.config.weight - 1) / self.config.weight
        };
        let parent = self.last_cp.clone();

        for index in 0..self.engines.len() {
            if !self.up[index] {
                continue;
            }
            if self.engines[index].is_halted() {
                continue;
            }
            self.timers[index].sync_round(self.engines[index].round);

            // 1. Timeout: retransmit what this round already holds, then ask to move.
            if let Some(target) = self.timers[index].tick(1) {
                let retransmit: Vec<Body> = self.engines[index]
                    .round_state
                    .prevotes
                    .iter()
                    .filter(|vote| vote.validator() == self.ids[index])
                    .map(|vote| Body::Prevote(vote.vote().clone()))
                    .collect();
                if !retransmit.is_empty() {
                    self.metrics.retransmissions += retransmit.len() as u64;
                }
                for body in retransmit {
                    outgoing.push((index, body));
                }
                let change = match crate::l2bft::timer::round_change_for_persisted(
                    &mut self.engines[index],
                    target,
                    &self.keys[index],
                    &self.stores[index],
                ) {
                    Ok(change) => change,
                    Err(_) => continue,
                };
                self.metrics.round_changes += 1;
                // A node counts its own round change: it is one of the signatures
                // of the quorum it needs. Without this the cluster could never
                // reach the threshold, since only the *other* changes arrive.
                if let Ok(crate::l2bft::RoundChangeOutcome::Adopted { .. }) = self.engines[index]
                    .process_round_change_persisted(
                        change.clone(),
                        &self.registry,
                        self.config.network,
                        &self.stores[index],
                    )
                {
                    self.metrics.rounds_adopted += 1;
                }
                outgoing.push((index, Body::RoundChange(Box::new(change))));
            }

            // 2. The driver proposes, the engine votes.
            //
            // With `elect_proposer`, only the member elected by
            // `l2bft::proposer` for this (generation, height, round) opens the
            // round, and its proposal is carried to the others. A validator that is
            // not elected waits for that message; if the elected one is down, the
            // round timer has to fire and the next round elects somebody else. That
            // is the whole point: an absent proposer costs rounds, never safety.
            if self.engines[index].round_state.proposal.is_none() {
                let elected_me = if self.config.elect_proposer {
                    crate::l2bft::proposer::proposer_for(
                        &self.registry,
                        self.engines[index].generation,
                        self.engines[index].height,
                        self.engines[index].round,
                    )
                    .map(|choice| choice.validator == self.ids[index])
                    .unwrap_or(false)
                } else {
                    true
                };
                if elected_me
                    && self.engines[index]
                        .propose_as_proposer(value, &self.registry, self.ids[index])
                        .is_ok()
                {
                    if self.config.elect_proposer {
                        self.metrics.proposals += 1;
                    }
                    outgoing.push((index, Body::Proposal(value)));
                }
            }
            let already_prevoted = self.engines[index]
                .round_state
                .prevotes
                .iter()
                .any(|vote| vote.validator() == self.ids[index]);
            let has_proposal = self.engines[index].round_state.proposal.is_some();
            if !already_prevoted && (!self.config.elect_proposer || has_proposal) {
                let key = self.keys[index].clone();
                let signed = self.engines[index].prevote(
                    value,
                    self.ids[index],
                    &self.registry,
                    &self.stores[index],
                    move |message: &[u8]| key.sign(message).to_bytes(),
                );
                if let Ok(prevote) = signed {
                    outgoing.push((index, Body::Prevote(prevote.vote().clone())));
                }
            }

            // 3. A quorum of prevotes authorizes the precommit (and writes the lock).
            let already_precommitted = self.engines[index]
                .round_state
                .precommits
                .iter()
                .any(|vote| vote.validator() == self.ids[index]);
            let enough_prevotes =
                self.engines[index].round_state.prevotes.len() as u64 >= signers_needed;
            if !already_precommitted && enough_prevotes {
                if let Ok(certificate) =
                    self.engines[index].certify_prevotes_for(value, &self.registry)
                {
                    let key = self.keys[index].clone();
                    let signed = self.engines[index].precommit(
                        &certificate,
                        self.ids[index],
                        &self.registry,
                        &self.stores[index],
                        move |message: &[u8]| key.sign(message).to_bytes(),
                    );
                    if let Ok(precommit) = signed {
                        outgoing.push((index, Body::Precommit(precommit.vote().clone())));
                    }
                }
            }

            // 4. A quorum of precommits decides.
            let enough_precommits =
                self.engines[index].round_state.precommits.len() as u64 >= signers_needed;
            if self.decided[index].is_none() && enough_precommits {
                if let Ok(certificate) =
                    self.engines[index].certify_precommits_for(value, &self.registry)
                {
                    let decided = self.engines[index].finalize(
                        &certificate,
                        &checkpoint,
                        parent.as_ref(),
                        &self.registry,
                        &self.stores[index],
                    );
                    if decided.is_ok() {
                        self.decided[index] = Some(checkpoint.id());
                        self.metrics.decisions += 1;
                        if self.first_decision_at.is_none() {
                            self.first_decision_at = Some(self.time);
                            self.first_decision_value = Some(checkpoint.id());
                        }
                    }
                }
            }

            // 5. Periodic retransmission, as a real node does on its gossip timer.
            // Without it, a validator that already sent its votes stays silent for
            // ever and a healed partition never converges: the messages that were
            // dropped while the network was split are never sent again.
            if self.config.retransmit_every > 0
                && self.time % self.config.retransmit_every == 0
                && self.decided[index].is_none()
            {
                if self.config.elect_proposer {
                    if let Some(proposed) = self.engines[index].round_state.proposal {
                        // A proposal lost to a partition has to be repeatable, or the
                        // round can never be opened for the validators that missed it.
                        self.metrics.retransmissions += 1;
                        outgoing.push((index, Body::Proposal(proposed)));
                    }
                }
                let own_prevote = self.engines[index]
                    .round_state
                    .prevotes
                    .iter()
                    .find(|vote| vote.validator() == self.ids[index])
                    .map(|vote| vote.vote().clone());
                if let Some(vote) = own_prevote {
                    self.metrics.retransmissions += 1;
                    outgoing.push((index, Body::Prevote(vote)));
                }
                let own_precommit = self.engines[index]
                    .round_state
                    .precommits
                    .iter()
                    .find(|vote| vote.validator() == self.ids[index])
                    .map(|vote| vote.vote().clone());
                if let Some(vote) = own_precommit {
                    self.metrics.retransmissions += 1;
                    outgoing.push((index, Body::Precommit(vote)));
                }
            }
        }
        outgoing
    }

    fn canonical_checkpoint(&self) -> Checkpoint {
        Checkpoint::new(
            self.registry.generation(),
            self.height,
            self.last_cp.as_ref().map(|cp| cp.id()).unwrap_or([0u8; 32]),
            [0x22u8 ^ self.height.get() as u8; 32],
            [0x33u8 ^ self.height.get() as u8; 32],
            self.registry.set_root(),
            None,
        )
        .expect("simulated checkpoint")
    }

    /// Move every engine to the next height and reset the run counters that are
    /// per-height. The decided checkpoint becomes the parent of the next one.
    pub fn advance_height(&mut self) {
        let next = CheckpointHeight(self.height.get() + 1);
        let decided = self.decided.iter().flatten().next().copied();
        if let Some(id) = decided {
            let parent = self.canonical_checkpoint();
            debug_assert_eq!(parent.id(), id, "the decided value is the canonical one");
            self.last_cp = Some(parent);
        }
        for index in 0..self.engines.len() {
            let _ = self.engines[index].advance_height(next, &self.stores[index]);
            self.timers[index].at_height(next);
            self.decided[index] = None;
        }
        self.height = next;
        self.value = self.canonical_checkpoint().id();
        self.first_decision_at = None;
        self.first_decision_value = None;
        self.queue.clear();
    }
}

/// The value the simulator's driver proposes at `height`.
///
/// A deterministic function of the height and nothing else: two runs of the same
/// configuration propose the same value, so a difference between runs is a
/// difference in the network, never in the proposition.
pub fn value_for_height(height: u64) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[0] = 0xB1;
    value[1..9].copy_from_slice(&height.to_le_bytes());
    value
}

/// `n` consecutive seeds starting at 1, the usual way tests name validators.
pub fn seeds(n: usize) -> Vec<u8> {
    (1..=n).map(|seed| seed as u8).collect()
}

/// Convenience: a validator index from a seed, for assertions.
pub fn index_of_seed(seed: u8) -> usize {
    seed as usize - 1
}

/// `Round` reached by validator `index`.
pub fn round_of(engine: &BftState) -> Round {
    engine.round
}
