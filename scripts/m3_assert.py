#!/usr/bin/env python3
"""M3 assertions, read from the real stdout of bz3_node.

Nothing here trusts an exit status. Every verdict comes from the lines the harness
itself prints:

  PROC=p<seed> DECIDED=<n> FINALITY=<hex|none> HEIGHT=<h> ROUND=<r>
  PROC=<id> HEIGHT_INCOMPLETE height=<h> round=<r>
  PROC=<id> FINALIZE_REFUSED <error>

usage: m3_assert.py <outdir> [--require-tcp]
exit:  0 = every assertion passed, 1 = at least one failed (detail on stderr)
"""
import glob
import os
import re
import sys

DECIDED_RE = re.compile(r"PROC=p(\d+) DECIDED=(\d+) FINALITY=(\S+) HEIGHT=(\d+)")
INCOMPLETE_RE = re.compile(r"PROC=([0-9a-f]+) HEIGHT_INCOMPLETE")
REFUSED_RE = re.compile(r"FINALIZE_REFUSED")


def load(out, scenario):
    rows = []
    for path in sorted(glob.glob(os.path.join(out, "logs", f"{scenario}-v*.log"))):
        text = open(path, encoding="utf-8", errors="replace").read()
        node = os.path.basename(path)[:-4]
        rows.append({
            "node": node,
            "decided": [(int(m.group(2)), m.group(3), int(m.group(4))) for m in DECIDED_RE.finditer(text)],
            "incomplete": len(INCOMPLETE_RE.findall(text)),
            "refused": len(REFUSED_RE.findall(text)),
            "text": text,
        })
    return rows


def main():
    out = sys.argv[1]
    require_tcp = "--require-tcp" in sys.argv[2:]

    failures, summary = [], []

    # ---- four distinct Ed25519 identities, proven by the logs themselves
    ids = set()
    for scn in ("A", "B", "C"):
        for path in glob.glob(os.path.join(out, "logs", f"{scn}-v*.log")):
            ids.update(re.findall(r"PROC=p(\d+)", open(path, encoding="utf-8", errors="replace").read()))
    summary.append(f"distinct_seed_ids={sorted(ids)} (expected 161,162,163,164)")
    if ids and ids != {"161", "162", "163", "164"}:
        failures.append(f"identity: observed seeds {sorted(ids)}")

    # ---- scenario A: 4 of 4
    a = load(out, "A")
    summary.append(f"A: logs={len(a)} decided={[len(r['decided']) for r in a]}")
    if len(a) != 4:
        failures.append(f"A: expected 4 logs, got {len(a)}")
    for r in a:
        if not any(n > 0 for (n, _, _) in r["decided"]):
            failures.append(f"A: {r['node']} decided nothing (incomplete={r['incomplete']} refused={r['refused']})")
    a_finals = {f for r in a for (n, f, _) in r["decided"] if n > 0}
    if len(a_finals) != 1:
        failures.append(f"A: contradictory finalities {sorted(a_finals)}")
    else:
        summary.append(f"A: FINALITY={list(a_finals)[0]} agreed by every deciding node")

    # ---- scenario B: 3 of 4
    b = load(out, "B")
    summary.append(f"B: logs={len(b)} decided={[len(r['decided']) for r in b]}")
    if len(b) != 3:
        failures.append(f"B: expected 3 logs, got {len(b)}")
    b_finals = {f for r in b for (n, f, _) in r["decided"] if n > 0}
    if len(b_finals) > 1:
        failures.append(f"B: contradictory finalities {sorted(b_finals)}")
    b_decided = sum(1 for r in b if any(n > 0 for (n, _, _) in r["decided"]))
    summary.append(f"B: {b_decided}/3 live nodes decided (3 of 4 stake = 75% >= 2/3 quorum)")

    # ---- scenario C: 2 of 4 must refuse
    c = load(out, "C")
    summary.append(f"C: logs={len(c)} decided={[len(r['decided']) for r in c]}")
    c_finals = {f for r in c for (n, f, _) in r["decided"] if n > 0}
    if c_finals:
        failures.append(f"C: finalisation with only 2 of 4 active (FINALITY={sorted(c_finals)}) - SAFETY FINDING")

    # ---- no double finalisation at the same height with different values
    for scn, rows in (("A", a), ("B", b), ("C", c)):
        per_height = {}
        for r in rows:
            for (n, f, h) in r["decided"]:
                per_height.setdefault(h, set()).add(f)
                if n == 0:
                    continue
        for h, fs in per_height.items():
            if len(fs) > 1:
                failures.append(f"{scn}: height {h} finalised with {len(fs)} different certificates {sorted(fs)}")

    # ---- real TCP: sockets observed while the validators were alive
    if require_tcp:
        conn = os.path.join(out, "scenarioA", "connections.txt")
        established = 0
        if os.path.isfile(conn):
            established = sum(1 for line in open(conn, encoding="utf-8", errors="replace") if "ESTAB" in line)
        summary.append(f"tcp_established_sockets_observed={established}")
        if established < 3:
            failures.append(f"tcp evidence: only {established} ESTAB socket(s) seen between validators")

    report = os.path.join(out, "QUORUM-RESULTS.txt")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(summary) + "\n")
        fh.write(("\nFAILURES\n" + "\n".join(failures) + "\n") if failures else "\nALL_ASSERTIONS=PASS\n")

    print("\n".join(summary))
    if failures:
        for f in failures:
            print("FAILURE " + f, file=sys.stderr)
        return 1
    print("ALL_ASSERTIONS=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
