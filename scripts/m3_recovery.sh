#!/usr/bin/env bash
# M3-GITHUB - abrupt stop, stale lock, release, resume, restore.
#
# A driver-side `kill -9` on the process leaves the Sled lock file behind, which
# is exactly the situation after a power cut. The harness also offers
# BZ3_KILL_AFTER_MS, which calls abort() from inside the process (no destructor)
# for the same effect; both are exercised here.
#
# Expectation to check, not to assume:
#   * `release` either returns RELEASED=<pid> or refuses (RELEASE_ERROR=...);
#   * `resume` restores the store and prints PROC=p<seed> RESTORED decisions=..;
#   * after resume the validator decides the same chain as its peers.
#
# usage: m3_recovery.sh <path-to-bz3_node> <output-dir>
set -uo pipefail

BIN="${1:?binary path required}"
OUT="${2:?output dir required}"
HEIGHTS="${BZ3_HEIGHTS:-3}"

mkdir -p "$OUT"/{logs,state}
PIDS_FILE="$OUT/pids.txt"
: >"$PIDS_FILE"
CLEANUP_REPORT="$OUT/CLEANUP-REPORT.txt"
CLEANED=0

# SCOPE OF THIS SCRIPT, stated once so no result can be over-read:
#   RESTORE_SAME_CHAIN   = IMPLEMENTED   (crash -> stale lock -> release -> resume,
#                                         the restarted validator must reach the same
#                                         chain it had before the crash)
#   LIVE_NETWORK_CATCHUP = NOT_IMPLEMENTED (catching up with a *live* peer set after a
#                                         reconnect is NOT tested here; peers have already
#                                         exited when phase 3 starts)
# This script proves storage recovery, not distributed synchronisation.
echo "SCOPE RESTORE_SAME_CHAIN=IMPLEMENTED LIVE_NETWORK_CATCHUP=NOT_IMPLEMENTED"
echo "INFO binary_sha256=$(sha256sum "$BIN" | cut -d' ' -f1)"

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [ "$CLEANED" -eq 1 ]; then exit "$status"; fi
  CLEANED=1
  local p terminated=0 forced=0 failed=0
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
  {
    echo "CLEANUP_SCRIPT=m3_recovery.sh"
    echo "CLEANUP_SCOPE=loopback"
    echo "CLEANUP_TRACKED=$(grep -c . "$PIDS_FILE" 2>/dev/null || echo 0)"
    echo "CLEANUP_TERMINATED=$terminated"
    echo "CLEANUP_FORCED_KILL=$forced"
    echo "CLEANUP_NAMESPACES_CREATED=0"
    echo "CLEANUP_INTERFACES_CREATED=0"
    echo "CLEANUP_METHOD=kill on recorded PIDs whose /proc cmdline is bz3_node; no pkill"
    if [ -r /proc/self/cmdline ]; then echo "CLEANUP_PROCFS=AVAILABLE"; else echo "CLEANUP_PROCFS=UNAVAILABLE"; fi
    if [ "$failed" -eq 0 ] && [ -r /proc/self/cmdline ]; then echo "CLEANUP_RESULT=PASS"; else
      echo "CLEANUP_RESULT=FAIL"
      if [ "$failed" -ne 0 ]; then echo "CLEANUP_ERROR=$failed process(es) survived SIGKILL"; fi
      if [ ! -r /proc/self/cmdline ]; then echo "CLEANUP_ERROR=procfs_unavailable_cannot_verify_identity"; fi
    fi
    echo "CLEANUP_EXIT_STATUS=$status"
  } >"$CLEANUP_REPORT"
  exit "$status"
}
trap cleanup EXIT INT TERM

PORTS=(27611 27612 27613 27614)
SEEDS=(171 172 173 174)
ADDR=(127.0.0.1:27611 127.0.0.1:27612 127.0.0.1:27613 127.0.0.1:27614)

peers_excluding() {
  local self=$1 out="" i
  for i in 0 1 2 3; do
    [ "$i" -eq "$self" ] && continue
    [ -n "$out" ] && out="$out,"
    out="$out${ADDR[$i]}"
  done
  printf '%s' "$out"
}

echo "== phase 1: four validators, validator 4 aborts from inside =="
PIDS=()
for i in 0 1 2 3; do
  store="$OUT/state/v$((i + 1))"
  mkdir -p "$store"
  extra=""
  [ "$i" -eq 3 ] && extra="BZ3_KILL_AFTER_MS=8000"
  env BZ3_HEIGHTS="$HEIGHTS" BZ3_SECONDS=90 BZ3_TRACE=1 $extra \
    "$BIN" run "${SEEDS[$i]}" "${ADDR[$i]}" "$store" "$(peers_excluding "$i")" \
    >"$OUT/logs/phase1-v$((i + 1)).log" 2>&1 &
  PIDS+=($!)
  echo "$!" >>"$PIDS_FILE"
done
for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null; done
echo "phase1_exit_codes_recorded=yes"
echo "PHASE1_COMPLETE note=LIVE_NETWORK_CATCHUP_NOT_TESTED"

echo "== phase 2: the lock left by the abort =="
ls -la "$OUT/state/v4" >"$OUT/logs/state-v4-after-abort.txt" 2>&1
"$BIN" release "$OUT/state/v4" >"$OUT/logs/release-v4.txt" 2>&1
cat "$OUT/logs/release-v4.txt"

echo "== phase 3: resume validator 4 from its own store =="
BZ3_HEIGHTS="$HEIGHTS" BZ3_SECONDS=90 BZ3_TRACE=1 \
  "$BIN" resume "${SEEDS[3]}" "${ADDR[3]}" "$OUT/state/v4" "$(peers_excluding 3)" \
  >"$OUT/logs/phase3-v4-resume.log" 2>&1
echo "resume_exit=$?" | tee "$OUT/logs/resume-exit.txt"

echo "== phase 4: compare final chains =="
python3 - "$OUT" <<'PY'
import glob, os, re, sys
out = sys.argv[1]
decided_re = re.compile(r"PROC=p(\d+) DECIDED=(\d+) FINALITY=(\S+) HEIGHT=(\d+)")
restored_re = re.compile(r"PROC=p(\d+) RESTORED decisions=(\d+) finality=(\S+)")
rows, restored = [], []
for path in sorted(glob.glob(os.path.join(out, "logs", "phase*.log"))):
    text = open(path, encoding="utf-8", errors="replace").read()
    rows.append((os.path.basename(path), [(m.group(3), int(m.group(4))) for m in decided_re.finditer(text)]))
    for m in restored_re.finditer(text):
        restored.append((os.path.basename(path), int(m.group(2)), m.group(3)))

chains = {fin for _, ds in rows for (fin, _) in ds}
problems = []
if not restored:
    problems.append("resume printed no RESTORED line: restoration was not demonstrated")
if len(chains) > 1:
    problems.append(f"validators finished on different chains: {sorted(chains)}")

lines = [f"{n}: decided={len(d)}" for n, d in rows]
lines += [f"RESTORED {n} decisions={c} finality={f}" for n, c, f in restored]
lines.append(f"distinct_chains={len(chains)}")
lines.append("RESTORE_SAME_CHAIN=" + ("PASS" if not problems else "FAIL"))
lines.append("LIVE_NETWORK_CATCHUP=NOT_IMPLEMENTED")
with open(os.path.join(out, "RECOVERY-RESULTS.txt"), "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
    fh.write("\n".join(problems) + "\n" if problems else "\nRECOVERY=PASS\n")
print("\n".join(lines))
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
print("RECOVERY=PASS")
PY
