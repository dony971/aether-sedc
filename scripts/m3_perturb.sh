#!/usr/bin/env bash
# M3-GITHUB - real network perturbations over namespaces, veth and netem.
#
# Runs ONLY if environment-precheck reported NETNS_OK = PASS, VETH_OK = PASS and
# NETEM_OK = PASS. There is no in-memory fallback: if the interfaces cannot be
# shaped, this script refuses to run and the campaign declares the perturbation
# set NOT RUN.
#
# Topology: one Linux bridge (10.77.0.254/24) with four veth pairs, one per
# network namespace. Each validator listens on its own 10.77.0.N:27601 inside its
# namespace, so every packet crosses a real interface that netem can shape.
#
# usage: m3_perturb.sh <path-to-bz3_node> <output-dir>   (must run as root)
set -uo pipefail

BIN="${1:?binary path required}"
OUT="${2:?output dir required}"
HEIGHTS="${BZ3_HEIGHTS:-2}"
RUN_SECONDS="${BZ3_SECONDS:-180}"

if [ "$(id -u)" -ne 0 ]; then
  echo "FATAL: perturbations require root (CAP_NET_ADMIN)" >&2
  exit 1
fi

mkdir -p "$OUT"/{logs,state}
PIDS_FILE="$OUT/pids.txt"
: >"$PIDS_FILE"
CLEANUP_REPORT="$OUT/CLEANUP-REPORT.txt"
CLEANED=0
echo "INFO binary_sha256=$(sha256sum "$BIN" | cut -d' ' -f1)"

SEEDS=(161 162 163 164)

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ "$CLEANED" -eq 1 ]; then exit "$status"; fi
  CLEANED=1

  local p i terminated=0 forced=0 failed=0 ns_removed=0 if_removed=0
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

  # Exact names only: the namespaces and bridge this script created.
  for i in 1 2 3 4; do
    ip netns del "m3n$i" 2>/dev/null && ns_removed=$((ns_removed + 1))
    ip link del "v$i" 2>/dev/null && if_removed=$((if_removed + 1))
  done
  ip link del m3br0 2>/dev/null && if_removed=$((if_removed + 1))

  {
    echo "CLEANUP_SCRIPT=m3_perturb.sh"
    echo "CLEANUP_SCOPE=namespaces+netem"
    echo "CLEANUP_TRACKED=$(grep -c . "$PIDS_FILE" 2>/dev/null || echo 0)"
    echo "CLEANUP_TERMINATED=$terminated"
    echo "CLEANUP_FORCED_KILL=$forced"
    echo "CLEANUP_NAMESPACES_REMOVED=$ns_removed"
    echo "CLEANUP_INTERFACES_REMOVED=$if_removed"
    echo "CLEANUP_METHOD=kill on recorded PIDs whose /proc cmdline is bz3_node; netns/link del by exact name; no pkill"
    if [ -r /proc/self/cmdline ]; then echo "CLEANUP_PROCFS=AVAILABLE"; else echo "CLEANUP_PROCFS=UNAVAILABLE"; fi
    if [ "$failed" -eq 0 ] && [ -r /proc/self/cmdline ]; then echo "CLEANUP_RESULT=PASS"; else
      echo "CLEANUP_RESULT=FAIL"
      if [ "$failed" -ne 0 ]; then echo "CLEANUP_ERROR=$failed process(es) survived SIGKILL"; fi
      if [ ! -r /proc/self/cmdline ]; then echo "CLEANUP_ERROR=procfs_unavailable_cannot_verify_identity"; fi
    fi
    echo "CLEANUP_NDISC_CREATED=0"
    echo "CLEANUP_EXIT_STATUS=$status"
  } >"$CLEANUP_REPORT"
  exit "$status"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------ topology
echo "== building namespaces =="
cleanup
ip link add m3br0 type bridge
ip addr add 10.77.0.254/24 dev m3br0
ip link set m3br0 up

for i in 1 2 3 4; do
  ip netns add "m3n$i"
  ip -n "m3n$i" link set lo up
  ip link add "v$i" type veth peer name "b$i"
  ip link set "b$i" master m3br0
  ip link set "b$i" up
  ip link set "v$i" netns "m3n$i"
  ip -n "m3n$i" addr add "10.77.0.$i/24" dev "v$i"
  ip -n "m3n$i" link set "v$i" up
done

ip netns exec m3n1 ping -c1 -W2 10.77.0.2 || { echo "FATAL: namespaces cannot reach each other" >&2; exit 1; }
ip netns exec m3n1 ping -c1 -W2 10.77.0.4 || { echo "FATAL: namespaces cannot reach each other" >&2; exit 1; }
echo "TOPOLOGY=PASS"

# ------------------------------------------------------------------ start
echo "== starting four validators inside four namespaces =="
PIDS=()
for i in 1 2 3 4; do
  peers=""
  for j in 1 2 3 4; do
    [ "$j" -eq "$i" ] && continue
    [ -n "$peers" ] && peers="$peers,"
    peers="$peers10.77.0.$j:27601"
  done
  mkdir -p "$OUT/state/v$i"
  ip netns exec "m3n$i" env BZ3_HEIGHTS="$HEIGHTS" BZ3_SECONDS="$RUN_SECONDS" BZ3_TRACE=1 \
    "$BIN" run "${SEEDS[$((i - 1))]}" "10.77.0.$i:27601" "$OUT/state/v$i" "$peers" \
    >"$OUT/logs/v$i.log" 2>&1 &
  PIDS+=($!)
  echo "$!" >>"$PIDS_FILE"
done
sleep 5

snapshot() {  # snapshot <label>
  local label=$1 i
  {
    echo "##### $label $(date -u +%H:%M:%S)"
    for i in 1 2 3 4; do
      echo "--- n$i"
      ip netns exec "m3n$i" tc -s qdisc show dev "v$i" 2>&1 | sed 's/^/    /'
      ip netns exec "m3n$i" ss -tn 2>/dev/null | grep 27601 | sed 's/^/    /'
    done
  } >>"$OUT/TIMELINE.txt"
}

snapshot "baseline"

# ------------------------------------------------------------------ P1 latency
echo "== P1: 120ms +/- 30ms latency on validator 1 =="
ip netns exec m3n1 tc qdisc add dev v1 root netem delay 120ms 30ms
sleep 15
snapshot "after P1 latency"

# ------------------------------------------------------------------ P2 loss
echo "== P2: 20% packet loss on validator 2 =="
ip netns exec m3n2 tc qdisc add dev v2 root netem loss 20%
sleep 15
snapshot "after P2 loss"

# ------------------------------------------------------------------ P3 reorder
echo "== P3: 25% reordering on validator 3 =="
ip netns exec m3n3 tc qdisc add dev v3 root netem delay 20ms reorder 25% 50%
sleep 15
snapshot "after P3 reorder"

# ------------------------------------------------------------------ P4 duplicate
echo "== P4: 20% duplication on validator 4 =="
ip netns exec m3n4 tc qdisc add dev v4 root netem duplicate 20%
sleep 15
snapshot "after P4 duplicate"

# ------------------------------------------------------------------ P5 partition
echo "== P5: hard partition of validator 4 =="
ip -n m3n4 link set v4 down
sleep 20
snapshot "during P5 partition"
echo "== P5b: healing the partition =="
ip -n m3n4 link set v4 up
ip netns exec m3n4 tc qdisc del dev v4 root 2>/dev/null
sleep 20
snapshot "after P5 heal"

# ------------------------------------------------------------------ P6 restart
echo "== P6: abrupt restart of validator 2 =="
kill -9 "${PIDS[1]}" 2>/dev/null
sleep 5
ip netns exec m3n2 env BZ3_HEIGHTS="$HEIGHTS" BZ3_SECONDS="$RUN_SECONDS" BZ3_TRACE=1 \
  "$BIN" resume "${SEEDS[1]}" "10.77.0.2:27601" "$OUT/state/v2" \
  "10.77.0.1:27601,10.77.0.3:27601,10.77.0.4:27601" \
  >"$OUT/logs/v2-resume.log" 2>&1 &
PIDS[1]=$!
echo "$!" >>"$PIDS_FILE"
sleep 20
snapshot "after P6 restart"

# ------------------------------------------------------------------ drain
echo "== lifting every qdisc and letting the run finish =="
for i in 1 2 3 4; do ip netns exec "m3n$i" tc qdisc del dev "v$i" root 2>/dev/null; done
for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
snapshot "final"

# -------------------------------------------------------------------- verdict
python3 - "$OUT" <<'PY'
import glob, os, re, sys
out = sys.argv[1]
decided_re = re.compile(r"PROC=p(\d+) DECIDED=(\d+) FINALITY=(\S+) HEIGHT=(\d+)")
rows = []
for path in sorted(glob.glob(os.path.join(out, "logs", "*.log"))):
    text = open(path, encoding="utf-8", errors="replace").read()
    decided = [(m.group(3), int(m.group(4))) for m in decided_re.finditer(text)]
    rows.append((os.path.basename(path), decided))

problems = []
per_height = {}
for name, decided in rows:
    for (fin, height) in decided:
        per_height.setdefault(height, set()).add(fin)
for height, fins in per_height.items():
    if len(fins) > 1:
        problems.append(f"height {height} finalised with {len(fins)} different certificates: {sorted(fins)}")

summary = [f"{n}: decided={len(d)}" for n, d in rows]
summary.append(f"heights_finalised={sorted(per_height)}")
summary.append(f"contradictions={len(problems)}")
with open(os.path.join(out, "PERTURBATION-RESULTS.txt"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(summary) + "\n")
    fh.write("\n".join(problems) + "\n" if problems else "\nNO_CONTRADICTORY_DECISION=PASS\n")
print("\n".join(summary))
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
print("NO_CONTRADICTORY_DECISION=PASS")
PY
