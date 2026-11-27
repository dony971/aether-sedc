#!/usr/bin/env bash
# M3 - four real OS processes on loopback, scenarios A / B / C.
#
# SCOPE: LOOPBACK ONLY. The four validators are separate processes with separate
# Ed25519 seeds, ports, stores and logs, talking over 127.0.0.1 TCP. They are NOT
# in separate network namespaces -- the namespaced variant is m3_ns_lab.sh, which
# is gated on NETNS_OK. This script never claims namespace isolation.
#
# CLI contract (src/bin/bz3_node.rs, main()):
#   bz3_node run <seed> <listen> <store-dir> <peer,peer,...>
# The seed is a DECIMAL u8; "0xA1" fails to parse and silently falls back to 1.
#
# usage: m3_lab.sh <path-to-bz3_node> <output-dir>
set -uo pipefail

BIN="${1:?binary path required}"
OUT="${2:?output dir required}"
HEIGHTS="${BZ3_HEIGHTS:-3}"
RUN_SECONDS="${BZ3_SECONDS:-60}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

mkdir -p "$OUT"/{logs,state,scenarioA,scenarioB,scenarioC}
PIDS_FILE="$OUT/pids.txt"
: >"$PIDS_FILE"
CLEANUP_REPORT="$OUT/CLEANUP-REPORT.txt"
CLEANED=0

# ---------------------------------------------------------------- cleanup
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ "$CLEANED" -eq 1 ]; then exit "$status"; fi
  CLEANED=1

  local terminated=0 forced=0 failed=0 alive=0 p i
  # Identity guard: only signal a PID whose /proc entry still is our validator.
  # Without this, a reaped PID could have been reused by an unrelated process.
  is_ours() { grep -qa 'bz3_node' "/proc/$1/cmdline" 2>/dev/null; }

  while read -r p; do
    [ -n "${p:-}" ] || continue
    is_ours "$p" || continue
    if kill -0 "$p" 2>/dev/null && kill -TERM "$p" 2>/dev/null; then terminated=$((terminated + 1)); fi
  done <"$PIDS_FILE"

  for i in 1 2 3 4 5; do
    alive=0
    while read -r p; do
      [ -n "${p:-}" ] || continue
      kill -0 "$p" 2>/dev/null && alive=$((alive + 1))
    done <"$PIDS_FILE"
    [ "$alive" -eq 0 ] && break
    sleep 1
  done

  while read -r p; do
    [ -n "${p:-}" ] || continue
    is_ours "$p" || continue
    if kill -0 "$p" 2>/dev/null; then
      if kill -KILL "$p" 2>/dev/null; then forced=$((forced + 1)); else failed=$((failed + 1)); fi
    fi
  done <"$PIDS_FILE"

  while read -r p; do
    [ -n "${p:-}" ] || continue
    wait "$p" 2>/dev/null
  done <"$PIDS_FILE"

  {
    echo "CLEANUP_SCRIPT=m3_lab.sh"
    echo "CLEANUP_SCOPE=loopback"
    echo "CLEANUP_TRACKED=$(grep -c . "$PIDS_FILE" 2>/dev/null || echo 0)"
    echo "CLEANUP_TERMINATED=$terminated"
    echo "CLEANUP_FORCED_KILL=$forced"
    echo "CLEANUP_FAILED=$failed"
    echo "CLEANUP_NAMESPACES_CREATED=0"
    echo "CLEANUP_INTERFACES_CREATED=0"
    echo "CLEANUP_METHOD=kill on recorded PIDs whose /proc cmdline is still bz3_node; no pkill, no pattern match"
    # A missing /proc would make every is_ours() check silently return false and
    # turn the cleanup into a no-op that still reported PASS. Fail loudly instead.
    if [ -r /proc/self/cmdline ]; then echo "CLEANUP_PROCFS=AVAILABLE"; else echo "CLEANUP_PROCFS=UNAVAILABLE"; fi
    if [ "$failed" -eq 0 ] && [ -r /proc/self/cmdline ]; then
      echo "CLEANUP_RESULT=PASS"
    else
      echo "CLEANUP_RESULT=FAIL"
      if [ "$failed" -ne 0 ]; then echo "CLEANUP_ERROR=$failed process(es) survived SIGKILL"; fi
      if [ ! -r /proc/self/cmdline ]; then echo "CLEANUP_ERROR=procfs_unavailable_cannot_verify_identity"; fi
    fi
    echo "CLEANUP_EXIT_STATUS=$status"
  } >"$CLEANUP_REPORT"
}

trap cleanup EXIT INT TERM

echo "INFO scope=loopback binary=$BIN heights=$HEIGHTS run_seconds=$RUN_SECONDS"
echo "INFO binary_sha256=$(sha256sum "$BIN" | cut -d' ' -f1)"

PORTS=(27601 27602 27603 27604)
SEEDS=(161 162 163 164)
ADDR=(127.0.0.1:27601 127.0.0.1:27602 127.0.0.1:27603 127.0.0.1:27604)

peers_excluding() {  # peers_excluding <index 0..3>
  local self=$1 out="" i
  for i in 0 1 2 3; do
    [ "$i" -eq "$self" ] && continue
    [ -n "$out" ] && out="$out,"
    out="$out${ADDR[$i]}"
  done
  printf '%s' "$out"
}

start_node() {  # start_node <scenario> <index>
  local sc=$1 i=$2
  local store="$OUT/state/$sc-v$((i + 1))"
  mkdir -p "$store"
  BZ3_HEIGHTS="$HEIGHTS" BZ3_SECONDS="$RUN_SECONDS" \
    "$BIN" run "${SEEDS[$i]}" "${ADDR[$i]}" "$store" "$(peers_excluding "$i")" \
    >"$OUT/logs/$sc-v$((i + 1)).log" 2>&1 &
  local pid=$!
  echo "$pid" >>"$PIDS_FILE"
  echo "$pid"
}

wait_tracked() {
  while read -r p; do [ -n "${p:-}" ] || continue; wait "$p" 2>/dev/null; done <"$PIDS_FILE"
}

scenario_a() {
  echo "== scenario A: 4 of 4 active (loopback) =="
  local pids=() i pid
  for i in 0 1 2 3; do
    pid=$(start_node A "$i")
    pids+=("$pid")
  done
  # Sockets are captured WHILE the validators are alive: an `ss` taken after they
  # exit would prove nothing about real TCP traffic.
  sleep 6
  ss -tn 2>/dev/null | grep -E ':2760[1-4]' >"$OUT/scenarioA/connections.txt"
  ss -tnp 2>/dev/null | grep -E ':2760[1-4]' >>"$OUT/scenarioA/connections.txt"
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  cp "$OUT"/logs/A-v*.log "$OUT/scenarioA/"
}

scenario_b() {
  echo "== scenario B: 3 of 4 active, v4 never started (loopback) =="
  local pids=() i pid
  for i in 0 1 2; do
    pid=$(start_node B "$i")
    pids+=("$pid")
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  cp "$OUT"/logs/B-v*.log "$OUT/scenarioB/"
}

scenario_c() {
  echo "== scenario C: 2 of 4 active, v3 and v4 never started (loopback) =="
  local pids=() i pid
  for i in 0 1; do
    pid=$(start_node C "$i")
    pids+=("$pid")
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  cp "$OUT"/logs/C-v*.log "$OUT/scenarioC/"
}

scenario_a
scenario_b
scenario_c

python3 "$SCRIPT_DIR/m3_assert.py" "$OUT" --require-tcp
RC=$?
echo "QUORUM_EXIT=$RC"
exit "$RC"
