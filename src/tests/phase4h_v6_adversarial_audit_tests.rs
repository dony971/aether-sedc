//! PHASE 4H: adversarial audit measurements for the dormant v6.
//!
//! AUDIT ONLY. This file adds TESTS, zero production changes. Every test
//! below measures a property the 4G suite does not cover (dormant-gate
//! boundaries, quorum percentage sweep, split invariance at scale,
//! order-permutation convergence, partition merge, restart equivalence,
//! storage corruption posture, maturation edges, evidence determinism,
//! old-wire rejection, RPC abuse, vote/DAG arrival inversion,
//! equivocation-order convergence, performance timings).
//! All fixtures deterministic (fixed keys/seeds, no clock reads except
//! current_epoch-relative arithmetic, no mining). Timings are REPORTED
//! (eprintln), never asserted (debug-profile variance is not evidence).

use crate::ledger::Ledger;
use crate::p2p::P2PMessage;
use crate::parent_selection::DAG;
use crate::stake::{current_epoch, StakeRegistry, VoteInsertOutcome, MIN_STAKE};
use crate::storage::Storage;
use crate::transaction::{Bond, Transaction, Vote, BOND_FORMAT_VERSION, VOTE_FORMAT_VERSION};
use crate::validation::{TransactionValidator, ValidationError, ValidationMode};
use crate::wallet::Wallet;
use std::sync::Arc;
use tokio::sync::RwLock;

fn wallet_n(n: u64) -> Wallet {
    Wallet::from_secret_key(&format!("{:064x}", n.max(1))).expect("key")
}

fn wallet_a() -> Wallet {
    Wallet::from_secret_key("1111111111111111111111111111111111111111111111111111111111111111")
        .expect("fixed key A")
}

fn wallet_b() -> Wallet {
    Wallet::from_secret_key("2222222222222222222222222222222222222222222222222222222222222222")
        .expect("fixed key B")
}

fn signed_vote(
    w: &Wallet,
    epoch: u64,
    key: ([u8; 32], u64),
    side: [u8; 32],
    stake_amount: u64,
) -> Vote {
    let mut v = Vote {
        format_version: VOTE_FORMAT_VERSION,
        network_id: 0,
        validator: w.address(),
        epoch,
        conflict_sender: key.0,
        conflict_nonce: key.1,
        side,
        stake_epoch: epoch,
        stake_amount,
        parents: [[0u8; 32]; 2],
        signature: [0u8; 64],
    };
    let sig = w
        .sign_transaction_hash(&v.signing_bytes())
        .expect("sign vote");
    v.signature = sig.to_bytes();
    assert!(v.verify_signature());
    v
}

fn signed_bond(w: &Wallet, amount: u64, epoch: u64) -> Bond {
    let mut b = Bond {
        format_version: BOND_FORMAT_VERSION,
        network_id: 0,
        validator: w.address(),
        amount,
        epoch,
        signature: [0u8; 64],
    };
    let sig = w
        .sign_transaction_hash(&b.signing_bytes())
        .expect("sign bond");
    b.signature = sig.to_bytes();
    assert!(b.verify_signature());
    b
}

/// Deterministic LCG (no rand dependency in audit scope).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) ^ self.0
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}

fn dag_tx(
    parents: [[u8; 32]; 2],
    sender: [u8; 32],
    receiver: [u8; 32],
    timestamp: u64,
    account_nonce: u64,
) -> Transaction {
    let mut tx = Transaction::new(
        parents,
        sender,
        receiver,
        100,
        100,
        timestamp,
        0,
        account_nonce,
        vec![0u8; 64],
        vec![0u8; 32],
    );
    tx.id = tx.compute_hash();
    tx
}

// ---------------------------------------------------------------- dormant gate

#[test]
fn h01_pow_gate_exactly_at_activation_boundary() {
    // validate_pure is timestamp-pure: V6-1 keeps the gate even with the
    // same invalid PoW that V6+1 skips. Fresh mode independently rejects
    // far-future timestamps (wall-clock gate, unchanged by 4G).
    let val = TransactionValidator::new();
    let w = wallet_a();
    let mk = |ts: u64| {
        let mut tx = Transaction::new(
            [[0u8; 32]; 2],
            w.address(),
            [2u8; 32],
            100,
            1000,
            ts,
            0,
            1,
            vec![0u8; 64],
            w.public_key_bytes(),
        );
        tx.signature = w.sign_transaction(&tx).expect("sign");
        tx.id = tx.compute_hash();
        tx
    };
    // Shape invalid PoW deterministically (unsigned loop in g23 covers the
    // general case; here fixed timestamps + nonce 0 suffice: assert miss).
    let mut pre = mk(Transaction::V6_ACTIVATION_TS - 1);
    if pre.verify_pow(24) {
        pre.nonce = 1;
        pre.id = pre.compute_hash();
    }
    assert!(!pre.verify_pow(24), "fixture must miss PoW");
    assert_eq!(
        val.validate_pure(&pre, ValidationMode::Historical),
        Err(ValidationError::InvalidPoW { difficulty: 24 }),
        "activation-1 keeps the legacy gate"
    );
    let post = mk(Transaction::V6_ACTIVATION_TS);
    // 4I F-D2: post-activation timestamps are REJECTED on every mode
    // while the wall clock is pre-activation (era gate precedes the PoW
    // skip). Post-wall-activation behavior is covered by the D2 pure-fn
    // boundary matrix (no clock control needed there).
    assert_eq!(
        val.validate_pure(&post, ValidationMode::Historical),
        Err(ValidationError::FutureEraTransaction {
            tx_ts: Transaction::V6_ACTIVATION_TS,
            activation_ts: Transaction::V6_ACTIVATION_TS,
        }),
        "activation timestamp rejected while wall-clock pre-activation"
    );
    // Fresh mode still time-gates far-future (4G changed nothing here).
    assert!(matches!(
        val.validate_pure(&post, ValidationMode::Fresh),
        Err(ValidationError::FutureTimestamp { .. })
    ));
}

#[test]
fn h02_era_routing_by_newest_member_mixed_key() {
    // Mixed-era key (one pre-V6 member, one post-V6 member): the NEWEST
    // member decides (v6 branch), per 4F P8. All-pre key delegates.
    let v6 = Transaction::V6_ACTIVATION_TS;
    let sender = [0x77u8; 32];
    let mut dag = DAG::new();
    let old = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], v6 - 1_000_000, 5);
    let new = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], v6 + 1000, 5);
    dag.add_transaction_validated(old.clone()).expect("old");
    dag.add_transaction_validated(new.clone()).expect("new");
    let reg = StakeRegistry::new();
    let at = 600_000u64;
    let v6_winner = dag
        .resolve_conflict_key_v6(&sender, 5, &reg, at)
        .expect("decided");
    // Empty registry: v6 plurality is 0/0 -> min-id tiebreak (NOT legacy
    // CDW  -  the era gate demonstrably switched rules on newest member).
    assert_eq!(v6_winner, old.id.min(new.id));
    // All-pre key with same shape delegates to legacy exactly.
    let mut dag2 = DAG::new();
    let a = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], v6 - 2_000_000, 6);
    let b = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], v6 - 1_000_000, 6);
    dag2.add_transaction_validated(a.clone()).expect("a");
    dag2.add_transaction_validated(b.clone()).expect("b");
    assert_eq!(
        dag2.resolve_conflict_key_v6(&sender, 6, &reg, at),
        dag2.resolve_conflict_key(&sender, 6),
        "all-pre delegates bit-identically"
    );
}

// ---------------------------------------------------------------- quorum sweep

#[test]
fn h03_quorum_percentage_sweep_exact() {
    // support/total pairs across the decision boundary. Rule: 3S >= 2T.
    // 66% (66/100: 198 < 200) FAILS; exact 2/3 (2/3: 6 >= 6) PASSES.
    let cases: Vec<(u64, u64, bool)> = vec![
        (0, 100, false),  // 0%
        (1, 100, false),  // 1%
        (33, 100, false), // 33%
        (50, 100, false), // 50%
        (60, 100, false), // 60%
        (65, 100, false), // 65%
        (66, 100, false), // 66% (below exact two-thirds)
        (67, 100, true),  // 67%
        (75, 100, true),  // 75%
        (100, 100, true), // 100%
        (2, 3, true),     // exact 2/3
        (1, 3, false),    // exact 1/3
        (666_666, 1_000_000, false),
        (666_667, 1_000_000, true),
        (1_999_999, 3_000_000, false),
        (2_000_000, 3_000_000, true),
        (0, 0, false), // T = 0 never quorate
        // NOTE: the predicate is total arithmetic (no panic, no wrap);
        // S > T is excluded STRUCTURALLY by callers (support_for caps
        // each validator at its live weight; see h04), not by the
        // predicate: (MAX, 1) is arithmetically TRUE and must stay so.
        (u64::MAX, 1, true),
        // (MAX-1)/MAX is ~100% (far above 2/3): TRUE (3(MAX-1) - 2MAX = MAX-3 > 0).
        (u64::MAX - 1, u64::MAX, true),
        // MAX = 3k exactly (k = MAX/3): (2k, 3k) is exact two-thirds: TRUE.
        (u64::MAX / 3 * 2, u64::MAX, true),
        (u64::MAX / 3 * 2 + 1, u64::MAX, true),
        // One unit below exact two-thirds at MAX: FALSE (6k-3 < 6k).
        (u64::MAX / 3 * 2 - 1, u64::MAX, false),
    ];
    for (s, t, want) in cases {
        assert_eq!(
            StakeRegistry::quorum_met(s, t),
            want,
            "quorum_met({}, {})",
            s,
            t
        );
    }
    // S > T is unreachable through support_for (latest-per-validator caps
    // each validator at its live weight; weights sum to the eligible
    // total)  -  asserted structurally in h04 below.
}

// ---------------------------------------------------------------- split invariance

#[test]
fn h04_split_invariance_identity_count_irrelevant() {
    // 100 as one vs 40+30+30: identical total support for the same side.
    // Then 10/100/1000 deterministic identities splitting the same total.
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let side = [0xAAu8; 32];
    let build = |parts: &[(u64, u64)]| -> StakeRegistry {
        // (wallet_seed, amount)
        let mut reg = StakeRegistry::new();
        for (seed, amount) in parts {
            let w = wallet_n(*seed);
            reg.apply_bond(w.address(), *amount, 0).expect("bond");
            reg.insert_vote(signed_vote(&w, at, key, side, *amount));
        }
        reg
    };
    let single = build(&[(1000, 100)]);
    let split = build(&[(2000, 40), (2001, 30), (2002, 30)]);
    let no_desc = |_: &[u8; 32]| false;
    assert_eq!(
        single.support_for(key, &side, at, no_desc),
        split.support_for(key, &side, at, no_desc),
        "40+30+30 == 100"
    );
    assert_eq!(
        single.eligible_stake_total(at),
        split.eligible_stake_total(at)
    );
    // Structural S <= T on real registries (the predicate never sees
    // S > T from support_for: latest-per-validator caps each validator
    // at its live weight, and weights sum to the eligible total).
    for reg in [&single, &split] {
        let total = reg.eligible_stake_total(at);
        let s = reg.support_for(key, &side, at, no_desc);
        assert!(s <= total, "support {} exceeds total {}", s, total);
    }
    for n in [10u64, 100, 1000] {
        let per = 1_000_000u64 / n;
        let parts: Vec<(u64, u64)> = (0..n).map(|i| (50_000 + i, per)).collect();
        let reg = build(&parts);
        let got = reg.support_for(key, &side, at, no_desc);
        // Integer division remainder: expected = per * n (exact, computed).
        assert_eq!(got, per * n, "{} identities preserve sum exactly", n);
    }
}

// ---------------------------------------------------------------- order independence

#[test]
fn h05_equivocation_before_bond_loses_slash_findings() {
    // 4H FINDING F-A1 (now FIXED in 4I via slash-tombstone): an
    // equivocation arriving BEFORE the accused bonded used to slash
    // nothing, and the later bond minted a clean record. Post-fix both
    // orders converge: pre-bond equivocation writes a tombstone
    // (Slashed, weight 0) and the later bond is REJECTED.
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let wc = wallet_n(999);

    // Order 1 (bond first): deterministic slash, weight zero.
    let mut r_bond_first = StakeRegistry::new();
    r_bond_first.apply_bond(wc.address(), 200, 0).expect("bond");
    r_bond_first.insert_vote(signed_vote(&wc, at, key, side_b, 200));
    match r_bond_first.insert_vote(signed_vote(&wc, at, key, side_a, 200)) {
        VoteInsertOutcome::Equivocated { .. } => {}
        other => panic!("expected equivocation, got {:?}", other),
    }
    assert_eq!(r_bond_first.voting_weight(&wc.address(), at), 0);
    assert_eq!(
        r_bond_first.validator_state(&wc.address()),
        Some(crate::stake::ValidatorState::Slashed)
    );

    // Order 2 (equivocation before bond): tombstone written at insert;
    // the later bond is rejected; weight stays zero.
    let mut r_vote_first = StakeRegistry::new();
    r_vote_first.insert_vote(signed_vote(&wc, at, key, side_b, 200));
    match r_vote_first.insert_vote(signed_vote(&wc, at, key, side_a, 200)) {
        VoteInsertOutcome::Equivocated { .. } => {}
        other => panic!("expected equivocation, got {:?}", other),
    }
    assert_eq!(
        r_vote_first.validator_state(&wc.address()),
        Some(crate::stake::ValidatorState::Slashed),
        "4I: pre-bond equivocation leaves a tombstone"
    );
    assert!(r_vote_first.apply_bond(wc.address(), 200, 0).is_err());
    assert_eq!(r_vote_first.voting_weight(&wc.address(), at), 0);
    // Both bonds at epoch 0 here, so records (and whole snapshots, via
    // the F-A2 canonical slot) are now byte-identical across orders.
    assert_eq!(r_bond_first.snapshot(), r_vote_first.snapshot());
}

/// Semantic registry equality for convergence proofs: every
/// consensus-relevant projection must match. EXCLUDED: raw vote bytes
/// in map slots (canonical-min slot keeps them order-independent since
/// 4I F-A2, but byte-equality is still stronger than needed here) and
/// bonded_epoch OF SLASHED RECORDS ONLY (tombstone path records 0,
/// bond-first path records the true bond epoch; proven consensus-
/// irrelevant: no reader branches on it once Slashed).
fn assert_semantically_equal(
    r1: &StakeRegistry,
    r2: &StakeRegistry,
    keys: &[([u8; 32], u64)],
    sides: &[([u8; 32], u64, [u8; 32])],
    at: u64,
    ctx: &str,
) {
    // Normalize slashed records' bonded_epoch (tombstone path records 0,
    // bond-first path the true epoch; proven consensus-irrelevant: no
    // reader branches on bonded_epoch once Slashed).
    let norm = |snap: crate::stake::RegistrySnapshot| {
        let mut s = snap;
        for rec in s.validators.iter_mut() {
            if rec.state == crate::stake::ValidatorState::Slashed {
                rec.bonded_epoch = 0;
            }
        }
        s
    };
    let s1 = norm(r1.snapshot());
    let s2 = norm(r2.snapshot());
    assert_eq!(s1.validators, s2.validators, "{}: validators", ctx);
    assert_eq!(s1.finalized, s2.finalized, "{}: finalized", ctx);
    assert_eq!(s1.evidence, s2.evidence, "{}: evidence", ctx);
    assert_eq!(s1.seen_bonds, s2.seen_bonds, "{}: seen_bonds", ctx);
    assert_eq!(
        r1.eligible_stake_total(at),
        r2.eligible_stake_total(at),
        "{}: total",
        ctx
    );
    for key in keys {
        assert_eq!(
            r1.finalized_winner(key),
            r2.finalized_winner(key),
            "{}: finality {:?}",
            ctx,
            key
        );
    }
    for (sender, nonce, side) in sides {
        let key = (*sender, *nonce);
        let no_desc = |_: &[u8; 32]| false;
        assert_eq!(
            r1.support_for(key, side, at, no_desc),
            r2.support_for(key, side, at, no_desc),
            "{}: support",
            ctx
        );
    }
}

#[test]
fn h05b_bonds_before_votes_permutations_converge() {
    // Safe subset: ALL bonds before ALL votes (equivocation included).
    // 20 shuffled vote orders within that constraint: identical snapshots.
    // (The unsafe subset  -  votes before bonds  -  is h05/F-A1 above.)
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let wa = wallet_a();
    let wb = wallet_b();
    let wc = wallet_n(999);
    let wd = wallet_n(1000);
    let bonds = vec![
        (wa.address(), 200u64, 0u64),
        (wb.address(), 200u64, 0u64),
        (wc.address(), 200u64, 0u64),
        (wd.address(), 100u64, 0u64),
    ];
    let votes = vec![
        signed_vote(&wa, at, key, side_a, 200),
        signed_vote(&wb, at, key, side_a, 200),
        signed_vote(&wc, at, key, side_b, 200),
        signed_vote(&wc, at, key, side_a, 200), // equivocation (bonded: slashed)
        signed_vote(&wd, at, key, side_b, 100),
    ];
    let build = |vote_order: &[crate::transaction::Vote]| {
        let mut reg = StakeRegistry::new();
        for (a, amt, ep) in &bonds {
            reg.apply_bond(*a, *amt, *ep).expect("bond");
        }
        for v in vote_order {
            reg.insert_vote(v.clone());
        }
        reg
    };
    let reference = build(&votes);
    let mut rng = Lcg(0x4a6173685F3432);
    for perm in 0..20 {
        let mut shuffled = votes.clone();
        rng.shuffle(&mut shuffled);
        let reg = build(&shuffled);
        assert_semantically_equal(
            &reg,
            &reference,
            &[key],
            &[(key.0, key.1, side_a), (key.0, key.1, side_b)],
            at,
            &format!("permutation {}", perm),
        );
    }
}

// ---------------------------------------------------------------- partition merge

#[test]
fn h06_partition_merge_converges_regardless_of_side_order() {
    // A votes X (+ key setup), B votes Y; heal in both orders; also
    // DAG-before-votes vs votes-before-DAG on the joiner.
    let at = 600_000u64;
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let sender = [0x77u8; 32];
    let mut dag = DAG::new();
    let a = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], v6_ts, 5);
    let b = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], v6_ts + 1, 5);
    let (id_a, id_b) = (a.id, b.id);
    dag.add_transaction_validated(a).expect("A");
    dag.add_transaction_validated(b).expect("B");
    let key = (sender, 5u64);
    let wx = wallet_n(11);
    let wy = wallet_n(12);
    let vxa = signed_vote(&wx, at, key, id_a, 200);
    let vyb = signed_vote(&wy, at, key, id_b, 100);

    // Heal order 1: X-votes then Y-votes.
    let mut r1 = StakeRegistry::new();
    r1.apply_bond(wx.address(), 200, 0).expect("bond");
    r1.apply_bond(wy.address(), 100, 0).expect("bond");
    r1.insert_vote(vxa.clone());
    r1.insert_vote(vyb.clone());
    // Heal order 2: Y-votes then X-votes.
    let mut r2 = StakeRegistry::new();
    r2.apply_bond(wy.address(), 100, 0).expect("bond");
    r2.apply_bond(wx.address(), 200, 0).expect("bond");
    r2.insert_vote(vyb);
    r2.insert_vote(vxa);
    assert_eq!(r1.snapshot(), r2.snapshot(), "heal order irrelevant");
    // Same fork choice on the merged set (dag shared here; votes merged).
    let w1 = dag.resolve_conflict_key_v6(&sender, 5, &r1, at);
    let w2 = dag.resolve_conflict_key_v6(&sender, 5, &r2, at);
    assert_eq!(w1, w2);
    assert_eq!(w1, Some(id_a), "heavier stake wins on both sides");
}

// ---------------------------------------------------------------- live vs rebuild vs reload

#[test]
fn h07_live_rebuild_reload_triple_equality() {
    // Same logical registry built three ways: live inserts, snapshot
    // restore, storage save/load. Snapshots + fork choice identical.
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let wa = wallet_a();
    let wb = wallet_b();
    let wc = wallet_n(777);
    let mut live = StakeRegistry::new();
    live.apply_bond(wa.address(), 200, 0).expect("bond");
    live.apply_bond(wb.address(), 200, 0).expect("bond");
    live.apply_bond(wc.address(), 200, 0).expect("bond");
    live.insert_vote(signed_vote(&wa, at, key, side_a, 200));
    live.insert_vote(signed_vote(&wb, at, key, side_b, 200));
    live.insert_vote(signed_vote(&wc, at, key, side_a, 200));
    let members = [side_a, side_b];
    // 400/600 is exactly 2/3 (3*400 = 2*600): finalizes.
    live.try_finalize(key, &members, at, |_, _| false)
        .expect("exact-quorum finality");
    let snap = live.snapshot();
    let restored = StakeRegistry::restore(snap.clone()).expect("restore works");
    assert_eq!(restored.snapshot(), snap, "restore == live");
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(dir.path()).expect("open");
    storage.save_registry(&live).expect("save");
    let reloaded = storage.load_registry().expect("load").expect("present");
    assert_eq!(reloaded.snapshot(), snap, "reload == live");
}

// ---------------------------------------------------------------- restart after finality

#[test]
fn h08_finality_survives_save_load_identically() {
    // Finalized decision + supporting weights identical after a
    // save/load cycle (restart equivalence for finalized state).
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let wa = wallet_a();
    let wb = wallet_b();
    let wc = wallet_n(555);
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), 200, 0).expect("bond");
    reg.apply_bond(wb.address(), 200, 0).expect("bond");
    reg.apply_bond(wc.address(), 200, 0).expect("bond");
    reg.insert_vote(signed_vote(&wa, at, key, side_a, 200));
    reg.insert_vote(signed_vote(&wb, at, key, side_a, 200));
    reg.insert_vote(signed_vote(&wc, at, key, side_b, 200));
    let members = [side_a, side_b];
    // 400/600 is exactly 2/3: finalizes side_a.
    let rec = reg
        .try_finalize(key, &members, at, |_, _| false)
        .expect("exact-quorum finality");
    assert_eq!(rec.winner, side_a);
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(dir.path()).expect("open");
    storage.save_registry(&reg).expect("save");
    let back = storage.load_registry().expect("load").expect("present");
    assert_eq!(back.finalized_winner(&key), reg.finalized_winner(&key));
    assert_eq!(back.snapshot(), reg.snapshot());
}

// ---------------------------------------------------------------- maturation edges

#[test]
fn h09_bond_epoch_window_edges_and_replay_across_reload() {
    // Window is exactly at+/-1 (inclusive); at+/-2 rejected both ways.
    // seen_bonds survives save/load: replay after reload is idempotent.
    let val = TransactionValidator::new();
    let wa = wallet_a();
    let at = 10u64;
    let mut ledger = Ledger::new();
    ledger.set_balance(&wa.address(), MIN_STAKE * 4);
    let reg = StakeRegistry::new();
    for epoch in [at - 1, at, at + 1] {
        assert!(
            val.validate_bond(&signed_bond(&wa, MIN_STAKE, epoch), &ledger, &reg, at)
                .is_ok(),
            "epoch {} accepted",
            epoch
        );
    }
    for epoch in [at - 2, at + 2] {
        assert!(
            matches!(
                val.validate_bond(&signed_bond(&wa, MIN_STAKE, epoch), &ledger, &reg, at),
                Err(ValidationError::EpochOutOfWindow { .. })
            ),
            "epoch {} rejected",
            epoch
        );
    }
    // Replay across reload: admit once, save, load, re-admit same bytes.
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(dir.path()).expect("open");
    let mut reg2 = StakeRegistry::new();
    let bond = signed_bond(&wa, MIN_STAKE, at);
    let bid = bond.id();
    assert!(reg2.note_bond_seen(bid));
    reg2.apply_bond(wa.address(), MIN_STAKE, at).expect("bond");
    storage.save_registry(&reg2).expect("save");
    let mut back = storage.load_registry().expect("load").expect("present");
    assert!(
        !back.note_bond_seen(bid),
        "replay after reload is a no-op (seen_bonds persisted)"
    );
    assert_eq!(
        back.voting_weight(&wa.address(), at + 100),
        MIN_STAKE,
        "no double top-up across restart"
    );
}

// ---------------------------------------------------------------- evidence determinism

#[test]
fn h10_equivocation_repeated_is_idempotent_same_id() {
    // Same conflicting pair submitted twice: same evidence id, slash
    // applied once (second apply_slash is a no-op), registry converges.
    // 4I refinement: replays of ALREADY-SEEN votes (either side) are
    // Duplicate, not re-Equivocated (no rebuild/re-relay storms on
    // re-gossip; the proof is already on file).
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let wa = wallet_a();
    let mut reg = StakeRegistry::new();
    reg.apply_bond(wa.address(), 200, 0).expect("bond");
    let v1 = signed_vote(&wa, at, key, [0xAAu8; 32], 200);
    let v2 = signed_vote(&wa, at, key, [0xBBu8; 32], 200);
    assert_eq!(reg.insert_vote(v1.clone()), VoteInsertOutcome::Accepted);
    let id1 = match reg.insert_vote(v2.clone()) {
        VoteInsertOutcome::Equivocated { evidence_id } => evidence_id,
        other => panic!("expected equivocation, got {:?}", other),
    };
    // Same pair again (as after a re-gossip): Duplicates, same id stable.
    assert_eq!(reg.insert_vote(v1.clone()), VoteInsertOutcome::Duplicate);
    assert_eq!(reg.insert_vote(v2.clone()), VoteInsertOutcome::Duplicate);
    assert_eq!(reg.evidence_count(), 1, "no duplicate evidence rows");
    // Tampered evidence bytes fail closed on decode.
    let ev = reg.get_evidence(&id1).expect("evidence").clone();
    let mut bad = ev.clone();
    bad.vote_a_encoding = vec![0u8; 10];
    assert!(bad.votes().is_err(), "corrupt embedded vote fails closed");
    let _ = ev;
}

// ---------------------------------------------------------------- old wire rejection

/// Pre-4G wire shape (9 variants, indices frozen). Simulates an old peer
/// decoding a new stake message: must fail (never misread as valid V5).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum OldP2PMessage {
    Transaction(Vec<u8>),
    Inventory(Vec<Vec<u8>>),
    GetData(Vec<Vec<u8>>),
    GetInventory { tips: Vec<Vec<u8>> },
    SyncRequest,
    SyncResponse(Vec<Vec<u8>>),
    Ping,
    Pong,
    Peers(Vec<std::net::SocketAddr>),
}

#[test]
fn h11_old_peer_rejects_new_kinds_never_misreads() {
    // New kinds serialize at indices 9/10/11; the old 9-variant enum
    // fails on all of them (error-disconnect per existing discipline).
    for msg in [
        P2PMessage::Vote(vec![9u8; 257]),
        P2PMessage::Bond(vec![9u8; 113]),
        P2PMessage::Unbond(vec![9u8; 105]),
    ] {
        let bytes = bincode::serialize(&msg).expect("ser");
        let idx = u32::from_le_bytes(bytes[..4].try_into().expect("idx"));
        assert!(idx >= 9, "new kinds at tail, got {}", idx);
        assert!(
            bincode::deserialize::<OldP2PMessage>(&bytes).is_err(),
            "old peer must fail, never misread"
        );
    }
    // Old-valid messages still decode under the new enum at the same
    // indices (Ping=6/Pong=7 locked in g35; re-assert Ping here).
    let ping = bincode::serialize(&P2PMessage::Ping).expect("ser");
    let back: OldP2PMessage = bincode::deserialize(&ping).expect("old Ping");
    assert!(matches!(back, OldP2PMessage::Ping));
}

// ---------------------------------------------------------------- RPC abuse

#[tokio::test]
async fn h12_rpc_rejects_unsigned_tampered_replayed() {
    use crate::p2p::P2PConfig;
    use crate::rpc::{AetherRpcImpl, Mempool};
    let dir = tempfile::tempdir().expect("tempdir");
    let dag = Arc::new(RwLock::new(DAG::new()));
    let ledger = Arc::new(RwLock::new(Ledger::new()));
    let storage = Arc::new(RwLock::new(
        Storage::open(dir.path().join("sled")).expect("open"),
    ));
    let mempool = Arc::new(RwLock::new(Mempool::new(1000, 10)));
    let (tx_channel, _rx) = tokio::sync::mpsc::unbounded_channel::<Transaction>();
    let p2p = Arc::new(crate::p2p::P2PNetwork::new(
        P2PConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            bootnodes: vec![],
            dns_seeds: vec![],
            peer_store_path: None,
            network_id: crate::transaction::DEFAULT_NETWORK_ID,
        },
        tx_channel,
        Arc::new(|| Vec::new()),
        Arc::new(|_| None),
        Arc::new(|| Vec::new()),
        Arc::new(crate::sync_stats::SyncContext::default()),
        Arc::new(|_| false),
    ));
    let mut rpc_impl = AetherRpcImpl::new(
        dag,
        ledger.clone(),
        storage,
        dir.path().join("ledger.json"),
        mempool,
        p2p,
        Arc::new(RwLock::new(true)),
        Arc::new(RwLock::new(std::collections::HashMap::new())),
        Arc::new(crate::sync_stats::SyncContext::default()),
    );
    let at = current_epoch();
    let wa = wallet_a();
    let key = ([9u8; 32], 3u64);
    {
        let mut reg = StakeRegistry::new();
        reg.apply_bond(wa.address(), MIN_STAKE, at - 10)
            .expect("bond");
        rpc_impl.set_stake_registry(Arc::new(RwLock::new(reg)));
    }
    // Unsigned/tampered vote: strict decode ok, signature gate refuses.
    let mut bad = signed_vote(&wa, at, key, [0xAAu8; 32], MIN_STAKE);
    bad.side = [0xBBu8; 32];
    assert!(rpc_impl
        .submit_vote(serde_json::json!([hex::encode(bad.encode())]))
        .await
        .is_err());
    // Malformed hex / short bytes: rejected before decode.
    assert!(rpc_impl
        .submit_vote(serde_json::json!(["zz"]))
        .await
        .is_err());
    assert!(rpc_impl
        .submit_vote(serde_json::json!([hex::encode(vec![0u8; 10])]))
        .await
        .is_err());
    // Valid vote accepted once, then idempotent duplicate (replay safe).
    let good = signed_vote(&wa, at, key, [0xAAu8; 32], MIN_STAKE);
    let first = rpc_impl
        .submit_vote(serde_json::json!([hex::encode(good.encode())]))
        .await
        .expect("accept");
    assert_eq!(first.status, "accepted");
    let second = rpc_impl
        .submit_vote(serde_json::json!([hex::encode(good.encode())]))
        .await
        .expect("replay ok");
    assert_eq!(second.status, "duplicate");
}

// ---------------------------------------------------------------- vote/DAG arrival inversion

#[test]
fn h13_vote_before_dag_members_converges() {
    // Votes reference keys with no DAG members yet (admission needs no
    // DAG): accepted. Members arrive later: same fork choice as the
    // DAG-first order. (Validates the no-existence-check design decision.)
    let at = 600_000u64;
    let v6_ts = Transaction::V6_ACTIVATION_TS + 1000;
    let sender = [0x77u8; 32];
    let key = (sender, 5u64);
    let wx = wallet_n(21);
    let wy = wallet_n(22);
    let mk_reg = || {
        let mut reg = StakeRegistry::new();
        reg.apply_bond(wx.address(), 200, 0).expect("bond");
        reg.apply_bond(wy.address(), 100, 0).expect("bond");
        reg
    };
    // Order 1: DAG members first, then votes.
    let mut dag1 = DAG::new();
    let a1 = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], v6_ts, 5);
    let b1 = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], v6_ts + 1, 5);
    let (id_a, id_b) = (a1.id, b1.id);
    dag1.add_transaction_validated(a1).expect("A");
    dag1.add_transaction_validated(b1).expect("B");
    let mut reg1 = mk_reg();
    reg1.insert_vote(signed_vote(&wx, at, key, id_a, 200));
    reg1.insert_vote(signed_vote(&wy, at, key, id_b, 100));
    // Order 2: votes first (no members yet  -  still Accepted), then DAG.
    let mut reg2 = mk_reg();
    // NOTE: vote sides must equal the eventual member ids; ids are
    // deterministic from content, so precompute via a scratch DAG.
    let mut scratch = DAG::new();
    let sa = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], v6_ts, 5);
    let sb = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], v6_ts + 1, 5);
    scratch.add_transaction_validated(sa).expect("sa");
    scratch.add_transaction_validated(sb).expect("sb");
    assert_eq!(scratch.find_sender_nonce_conflicts(&sender, 5).len(), 2);
    reg2.insert_vote(signed_vote(&wx, at, key, id_a, 200));
    reg2.insert_vote(signed_vote(&wy, at, key, id_b, 100));
    let mut dag2 = DAG::new();
    let a2 = dag_tx([[0u8; 32]; 2], sender, [1u8; 32], v6_ts, 5);
    let b2 = dag_tx([[0u8; 32]; 2], sender, [2u8; 32], v6_ts + 1, 5);
    assert_eq!(a2.id, id_a);
    assert_eq!(b2.id, id_b);
    dag2.add_transaction_validated(a2).expect("A2");
    dag2.add_transaction_validated(b2).expect("B2");
    assert_eq!(reg1.snapshot(), reg2.snapshot());
    assert_eq!(
        dag1.resolve_conflict_key_v6(&sender, 5, &reg1, at),
        dag2.resolve_conflict_key_v6(&sender, 5, &reg2, at)
    );
}

// ---------------------------------------------------------------- equivocation-order convergence

#[test]
fn h14_equivocation_arrival_orders_converge() {
    // Same equivocation pair in both arrival orders. 4I F-A2 (canonical
    // min-id slot): snapshots are now BYTE-identical across orders, and
    // every consensus-relevant projection matches trivially: both
    // slashed (weight 0 either way), same support, same evidence
    // (canonical id), same finality outcome.
    let at = 600_000u64;
    let key = ([9u8; 32], 3u64);
    let side_a = [0xAAu8; 32];
    let side_b = [0xBBu8; 32];
    let wx = wallet_n(31);
    let wy = wallet_n(32);
    let build = |first_a: bool| {
        let mut reg = StakeRegistry::new();
        reg.apply_bond(wx.address(), 300, 0).expect("bond");
        reg.apply_bond(wy.address(), 300, 0).expect("bond");
        reg.insert_vote(signed_vote(&wy, at, key, side_a, 300));
        let first = signed_vote(&wx, at, key, if first_a { side_a } else { side_b }, 300);
        let second = signed_vote(&wx, at, key, if first_a { side_b } else { side_a }, 300);
        reg.insert_vote(first);
        reg.insert_vote(second);
        reg
    };
    let r1 = build(true);
    let r2 = build(false);
    // Byte-identical (canonical slot): the F-A2 fix proof.
    assert_eq!(r1.snapshot(), r2.snapshot());
    // Semantic convergence asserted (defense in depth).
    assert_eq!(
        r1.validator_state(&wx.address()),
        r2.validator_state(&wx.address())
    );
    assert_eq!(
        r1.voting_weight(&wx.address(), at),
        r2.voting_weight(&wx.address(), at)
    );
    assert_eq!(r1.voting_weight(&wx.address(), at), 0);
    let no_desc = |_: &[u8; 32]| false;
    assert_eq!(
        r1.support_for(key, &side_a, at, no_desc),
        r2.support_for(key, &side_a, at, no_desc)
    );
    assert_eq!(
        r1.support_for(key, &side_b, at, no_desc),
        r2.support_for(key, &side_b, at, no_desc)
    );
    // Slashed weight is zero on both: only Y's 300 counts for side_a.
    assert_eq!(r1.support_for(key, &side_a, at, no_desc), 300);
    assert_eq!(
        r1.finalized_winner(&key),
        r2.finalized_winner(&key),
        "no unilateral finality from order alone"
    );
}

// ---------------------------------------------------------------- performance timings

#[test]
fn h15_registry_timings_reported_not_asserted() {
    // Scales: 100 and 1000 validators voting one key. Measures insert,
    // support, finalize, snapshot, save/load. Correctness asserted;
    // timings only reported (debug-profile variance is not evidence).
    for n in [100u64, 1000] {
        let at = 600_000u64;
        let key = ([9u8; 32], 3u64);
        let side = [0xAAu8; 32];
        let t0 = std::time::Instant::now();
        let mut reg = StakeRegistry::new();
        for i in 0..n {
            let w = wallet_n(100_000 + i);
            reg.apply_bond(w.address(), 1000, 0).expect("bond");
            reg.insert_vote(signed_vote(&w, at, key, side, 1000));
        }
        let t_insert = t0.elapsed();
        let t1 = std::time::Instant::now();
        let s = reg.support_for(key, &side, at, |_| false);
        let t_support = t1.elapsed();
        assert_eq!(s, 1000 * n);
        let members = [side];
        let t2 = std::time::Instant::now();
        let rec = reg.try_finalize(key, &members, at, |_, _| false);
        let t_finalize = t2.elapsed();
        assert!(rec.is_some());
        let t3 = std::time::Instant::now();
        let snap = reg.snapshot();
        let t_snapshot = t3.elapsed();
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("open");
        let t4 = std::time::Instant::now();
        storage.save_registry(&reg).expect("save");
        let t_save = t4.elapsed();
        let t5 = std::time::Instant::now();
        let back = storage.load_registry().expect("load").expect("present");
        let t_load = t5.elapsed();
        assert_eq!(back.snapshot(), snap);
        eprintln!(
  "4H PERF n={}: insert={:?} support={:?} finalize={:?} snapshot={:?} save={:?} load={:?}",
  n, t_insert, t_support, t_finalize, t_snapshot, t_save, t_load
  );
    }
}
