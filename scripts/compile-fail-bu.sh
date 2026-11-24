#!/usr/bin/env bash
# BU — negative compilation cases for the BFT API hardening.
#
# Each snippet is compiled against the *real* rlib produced by `cargo build
# --lib`, and the script fails unless rustc rejects it with the expected error
# code. This is the evidence for mission BU §7: a module outside the crate cannot
# construct a VoteAuthorization, cannot write `persisted`, cannot call the signing
# primitive without an authorisation, and cannot unlock.
#
# A positive control is compiled too, so a snippet that fails because the crate
# is unusable (or because the flag set is wrong) cannot be mistaken for a pass.
#
# Usage: scripts/compile-fail-bu.sh [--rlib PATH]
# Exit: 0 when every case behaves as expected, 1 otherwise.
set -u

cd "$(dirname "$0")/.."
OUT="${TMPDIR:-/tmp}/opencode/a066bu-bft-api-hardening/logs"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

RLIB=""
if [ "${1:-}" = "--rlib" ] && [ -n "${2:-}" ]; then
  RLIB="$2"
else
  RLIB="$(ls -t target/debug/libaether_unified.rlib 2>/dev/null | head -1)"
fi
if [ -z "$RLIB" ] || [ ! -f "$RLIB" ]; then
  echo "compile-fail-bu: no rlib; run 'cargo build --lib' first" >&2
  exit 1
fi

RUSTC="${RUSTC:-rustc}"
DEPS="target/debug/deps"
LOG="$OUT/compile-fail-bu.txt"
: > "$LOG"

pass=0
fail=0

compile() { # $1 = name, $2 = expected code ("" for must-succeed), $3 = source
  local name="$1" expect="$2" src="$3"
  local file="$WORK/$name.rs"
  printf '%s\n' "$src" > "$file"
  local out
  out="$("$RUSTC" --edition 2021 --crate-type lib --crate-name "bu_$name" \
      --extern "aether_unified=$RLIB" -L "dependency=$DEPS" \
      -o "$WORK/libbu_$name.rlib" "$file" 2>&1)"
  local rc=$?
  {
    echo "=== $name (expected: ${expect:-compiles}) ==="
    echo "$out"
    echo "--- rc=$rc"
    echo
  } >> "$LOG"

  if [ -z "$expect" ]; then
    if [ $rc -eq 0 ]; then
      echo "PASS $name: compiles (positive control)"
      pass=$((pass + 1))
    else
      echo "FAIL $name: the positive control must compile"
      echo "$out" | sed 's/^/    /'
      fail=$((fail + 1))
    fi
    return
  fi

  if [ $rc -eq 0 ]; then
    echo "FAIL $name: compiled, but must be rejected with $expect"
    fail=$((fail + 1))
    return
  fi
  if printf '%s' "$out" | grep -q "$expect"; then
    echo "PASS $name: rejected with $expect"
    pass=$((pass + 1))
  else
    echo "FAIL $name: rejected, but without $expect"
    echo "$out" | sed 's/^/    /'
    fail=$((fail + 1))
  fi
}

PRELUDE='#![allow(unused_imports, dead_code)]
use aether_unified::l2bft::BftState;
use aether_unified::l2crypto::registry::ValidatorRegistry;
use aether_unified::l2crypto::vote::{ConsensusVote, VotePhase};
use aether_unified::l2persist::{
    sign_vote, AtomicSlotStore, PersistentConsensusState, VoteAuthorization,
};
'

# --- CF-1: a foreign module cannot write a VoteAuthorization -----------------
compile cf1_construct_authorization E0451 "$PRELUDE
use aether_unified::consensus::generation::{CheckpointHeight, GenerationId, Round};
pub fn forge() -> VoteAuthorization {
    VoteAuthorization {
        network: 1,
        generation: GenerationId([0u8; 32]),
        height: CheckpointHeight(0),
        round: Round(0),
        phase: VotePhase::Prevote,
        checkpoint_id: [0u8; 32],
        lock_value: [0u8; 32],
        lock_round: None,
        pol_qc_id: None,
    }
}"

# --- CF-2: a foreign module cannot write `persisted` -------------------------
compile cf2_write_persisted_field E0616 "$PRELUDE
pub fn erase(engine: &mut BftState) {
    engine.persisted.locked = None;
}"

# --- CF-3: the signing primitive is unreachable without an authorisation -----
compile cf3_sign_vote_without_authorization E0061 "$PRELUDE
pub fn sign_without_authorization(
    state: &PersistentConsensusState,
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    vote: &ConsensusVote,
    sign: fn(&[u8]) -> [u8; 64],
) {
    let _ = sign_vote(state, store, registry, vote, sign);
}"

# --- CF-4: the provisional unlock no longer exists ---------------------------
compile cf4_apply_provisional_unlock E0599 "$PRELUDE
pub fn unlock(state: &mut PersistentConsensusState) {
    let _ = state.apply_provisional_unlock(&[0u8; 32]);
}"

# --- CF-5: the one-step unlock-and-persist no longer exists ------------------
compile cf5_apply_and_persist E0432 "use aether_unified::l2persist::apply_and_persist;
pub fn unlock(state: &mut PersistentConsensusState) {
    let _ = apply_and_persist;
}"

# --- CF-6: the authorisation is opaque, even for reading --------------------
compile cf6_read_authorization_field E0616 "$PRELUDE
pub fn peek(auth: &VoteAuthorization) -> u64 {
    auth.network
}"

# --- CF-7: the read-only accessor does not hand out a writable view --------
compile cf7_mutate_through_accessor E0594 "$PRELUDE
pub fn erase(engine: &mut BftState) {
    engine.persisted().locked = None;
}"

# --- OK: the legitimate API still compiles ---------------------------------
compile ok_legitimate_api "" "$PRELUDE
use aether_unified::consensus::generation::CheckpointHeight;
pub fn read(engine: &BftState) -> Option<[u8; 32]> {
    engine.persisted().locked.map(|lock| lock.checkpoint_id)
}
pub fn authorise<'a>(
    state: &'a PersistentConsensusState,
    registry: &'a ValidatorRegistry,
    vote: &'a ConsensusVote,
) -> Result<VoteAuthorization, aether_unified::l2persist::EmitError> {
    let _ = CheckpointHeight(0);
    VoteAuthorization::for_prevote(state, vote, None, registry)
}
pub fn sign(
    state: &PersistentConsensusState,
    store: &dyn AtomicSlotStore,
    registry: &ValidatorRegistry,
    vote: &ConsensusVote,
    authorization: &VoteAuthorization,
    sign: fn(&[u8]) -> [u8; 64],
) -> Result<aether_unified::l2persist::SignedOutcome, aether_unified::l2persist::EmitError> {
    sign_vote(state, store, registry, vote, authorization, sign)
}"

echo
echo "compile-fail-bu: $pass passed, $fail failed (log: $LOG)"
[ "$fail" -eq 0 ]
