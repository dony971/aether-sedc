#!/usr/bin/env bash
# M3 - four validators in four separate Linux network namespaces.
#
# SCOPE: ISOLATED. Each validator lives in its own netns (m3q1..m3q4) behind its own
# veth pair attached to a private bridge (m3qbr) with distinct addresses
# 10.77.1.N/24. Packets cross real interfaces; `ss` is read inside each namespace,
# so the observed TCP connections cannot come from a shared socket table.
#
# Preconditions: NETNS_OK and VETH_OK reported PASS by environment-precheck.
# If any `ip` command fails, this script exits non-zero with ISOLATED_LAB=BLOCKED.
# It never falls back to loopback and never reports PASS without namespaces.
#
# usage: m3_ns_lab.sh <path-to-bz3_node> <output-dir>   (as root)
set -uo pipefail

BIN="${1:?binary path required}"
OUT="${2:?output dir required}"
HEIGHTS="${BZ3_HEIGHTS:-3}"
RUN_SECONDS="${BZ3_SECONDS:-60}"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CLEANUP_REPORT="$OUT/CLEANUP-REPORT.txt"
PIDS_FILE="$OUT/pids.txt"
CLEANED=0

if [ "$(id -u)" -ne 0 ]; then
  echo "ISOLATED_LAB=BLOCKED reason=not_root"
  exit 3
fi

mkdir -p "$OUT"/{logs,state,scenarioA,scenarioB,scenarioC}
: >"$PIDS_FILE"

NS=(m3q1 m3q2 m3q3 m3q4)
BR=m3qbr
SEEDS=(161 162 163 164)

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ "$CLEANED" -eq 1 ]; then exit "$status"; fi
  CLEANED=1

  local terminated=0 forced=0 failed=0 p i ns_removed=0 if_removed=0
  is_ours() { grep -qa 'bz3_node' "/proc/$1/cmdline" 2>/dev/null; }

  while read -r p; do
    [ -n "${p:-}" ] || continue
    is_ours "$p" || continue
    if kill -0 "$p" 2>/dev/null && kill -TERM "$p" 2>/dev/null; then terminated=$((terminated + 1)); fi
  done <"$PIDS_FILE"
  sleep 2
  while read -r p; do
    [ -n "${p:-}" ] || continue
    is_ours "$p" || continue
    if kill -0 "$p" 2>/dev/null; then
      if kill -KILL "$p" 2>/dev/null; then forced=$((forced + 1)); else failed=$((failed + 1)); fi
    fi
  done <"$PIDS_FILE"
  while read -r p; do [ -n "${p:-}" ] || continue; wait "$p" 2>/dev/null; done <"$PIDS_FILE"

  # Remove ONLY the namespaces and links this script created, by exact name.
  for i in 1 2 3 4; do
    if ip netns list 2>/dev/null | grep -q "^m3q$i"; then
      ip netns del "m3q$i" 2>/dev/null && ns_removed=$((ns_removed + 1)) || failed=$((failed + 1))
    fi
    if ip link show "vq$i" >/dev/null 2>&1; then
      ip link del "vq$i" 2>/dev/null && if_removed=$((if_removed + 1)) || failed=$((failed + 1))
    fi
  done
  if ip link show "$BR" >/dev/null 2>&1; then
    ip link del "$BR" 2>/dev/null && if_removed=$((if_removed + 1)) || failed=$((failed + 1))
  fi

  {
    echo "CLEANUP_SCRIPT=m3_ns_lab.sh"
    echo "CLEANUP_SCOPE=namespaces"
    echo "CLEANUP_TRACKED=$(grep -c . "$PIDS_FILE" 2>/dev/null || echo 0)"
    echo "CLEANUP_TERMINATED=$terminated"
    echo "CLEANUP_FORCED_KILL=$forced"
    echo "CLEANUP_NAMESPACES_REMOVED=$ns_removed"
    echo "CLEANUP_INTERFACES_REMOVED=$if_removed"
    echo "CLEANUP_METHOD=kill on recorded PIDs whose /proc cmdline is bz3_node; ip netns/link del by exact name; no pkill"
    if [ -r /proc/self/cmdline ]; then echo "CLEANUP_PROCFS=AVAILABLE"; else echo "CLEANUP_PROCFS=UNAVAILABLE"; fi
    if [ "$failed" -eq 0 ] && [ -r /proc/self/cmdline ]; then echo "CLEANUP_RESULT=PASS"; else
      echo "CLEANUP_RESULT=FAIL"
      if [ "$failed" -ne 0 ]; then echo "CLEANUP_ERROR=$failed cleanup operation(s) failed"; fi
      if [ ! -r /proc/self/cmdline ]; then echo "CLEANUP_ERROR=procfs_unavailable_cannot_verify_identity"; fi
    fi
    echo "CLEANUP_EXIT_STATUS=$status"
  } >"$CLEANUP_REPORT"
  exit "$status"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- topology
echo "== building four namespaces + bridge $BR =="
ip link add "$BR" type bridge || { echo "ISOLATED_LAB=BLOCKED reason=bridge_create_failed"; exit 3; }
ip addr add 10.77.1.254/24 dev "$BR" || { echo "ISOLATED_LAB=BLOCKED reason=bridge_addr_failed"; exit 3; }
ip link set "$BR" up

for i in 1 2 3 4; do
  ip netns add "m3q$i" || { echo "ISOLATED_LAB=BLOCKED reason=netns_add_failed_$i"; exit 3; }
  ip -n "m3q$i" link set lo up
  ip link add "vq$i" type veth peer name "bq$i" || { echo "ISOLATED_LAB=BLOCKED reason=veth_failed_$i"; exit 3; }
  ip link set "bq$i" master "$BR"
  ip link set "bq$i" up
  ip link set "vq$i" netns "m3q$i"
  ip -n "m3q$i" addr add "10.77.1.$i/24" dev "vq$i"
  ip -n "m3q$i" link set "vq$i" up
done

if ! ip netns exec m3q1 ping -c1 -W2 10.77.1.4 >/dev/null 2>&1; then
  echo "ISOLATED_LAB=BLOCKED reason=namespaces_unreachable"
  exit 3
fi
echo "ISOLATED_LAB=AVAILABLE"

addr() { echo "10.77.1.$1:27601"; }

peers_excluding() {  # peers_excluding <1..4>
  local self=$1 out="" i
  for i in 1 2 3 4; do
    [ "$i" -eq "$self" ] && continue
    [ -n "$out" ] && out="$out,"
    out="$out$(addr "$i")"
  done
  printf '%s' "$out"
}

start_node() {  # start_node <scenario> <1..4>
  local sc=$1 i=$2
  mkdir -p "$OUT/state/$sc-v$i"
  ip netns exec "m3q$i" env BZ3_HEIGHTS="$HEIGHTS" BZ3_SECONDS="$RUN_SECONDS" \
    "$BIN" run "${SEEDS[$((i - 1))]}" "$(addr "$i")" "$OUT/state/$sc-v$i" "$(peers_excluding "$i")" \
    >"$OUT/logs/$sc-v$i.log" 2>&1 &
  local pid=$!
  echo "$pid" >>"$PIDS_FILE"
  echo "$pid"
}

snapshot_sockets() {  # snapshot_sockets <scenario> <count>
  local sc=$1 n=$2 i
  : >"$OUT/scenario$sc/connections.txt"
  for i in $(seq 1 "$n"); do
    echo "### netns m3q$i" >>"$OUT/scenario$sc/connections.txt"
    ip netns exec "m3q$i" ss -tn 2>/dev/null | grep ':27601' >>"$OUT/scenario$sc/connections.txt"
  done
}

echo "== scenario A: 4 namespaces, 4 of 4 =="
for i in 1 2 3 4; do start_node A "$i" >/dev/null; done
sleep 8
snapshot_sockets A 4
wait_all() { while read -r p; do [ -n "${p:-}" ] || continue; wait "$p" 2>/dev/null; done <"$PIDS_FILE"; }
wait_all
cp "$OUT"/logs/A-v*.log "$OUT/scenarioA/"

echo "== scenario B: 3 namespaces, 3 of 4 =="
: >"$PIDS_FILE"
for i in 1 2 3; do start_node B "$i" >/dev/null; done
sleep 8
snapshot_sockets B 3
wait_all
cp "$OUT"/logs/B-v*.log "$OUT/scenarioB/"

echo "== scenario C: 2 namespaces, 2 of 4 =="
: >"$PIDS_FILE"
for i in 1 2; do start_node C "$i" >/dev/null; done
wait_all
cp "$OUT"/logs/C-v*.log "$OUT/scenarioC/"

python3 "$SCRIPT_DIR/m3_assert.py" "$OUT" --require-tcp
RC=$?
echo "ISOLATED_QUORUM_EXIT=$RC"
exit "$RC"
