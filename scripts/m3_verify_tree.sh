#!/usr/bin/env bash
# M3-GITHUB - identity gate.
#
# Verifies that the checked-out tree is EXACTLY the M1+M2 tree that M2-FINAL
# sealed. Any mismatch aborts before a single compile, so the campaign can never
# silently validate a different tree (in particular the historical C2 branch).
#
# usage: m3_verify_tree.sh <manifest>
set -euo pipefail

MANIFEST="${1:-expected-sources.sha256}"

if [ ! -f "$MANIFEST" ]; then
  echo "FATAL: manifest $MANIFEST not found" >&2
  exit 1
fi

echo "== identity gate =="
echo "HEAD            = $(git rev-parse HEAD)"
echo "branch          = $(git rev-parse --abbrev-ref HEAD)"
echo "worktree        = $(git status --porcelain | wc -l) modified/untracked entries"
echo "manifest        = $MANIFEST"

if [ -n "$(git status --porcelain)" ]; then
  echo "FATAL: worktree is not clean; refusing to test an uncommitted tree" >&2
  git status --porcelain >&2
  exit 1
fi

FAILED=0
while read -r want path; do
  [ -z "${want:-}" ] && continue
  case "$want" in \#*) continue ;; esac
  if [ ! -f "$path" ]; then
    echo "MISSING  $path"
    FAILED=$((FAILED + 1))
    continue
  fi
  got=$(sha256sum "$path" | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then
    echo "OK       $path"
  else
    echo "MISMATCH $path"
    echo "         expected $want"
    echo "         actual   $got"
    FAILED=$((FAILED + 1))
  fi
done < "$MANIFEST"

if [ "$FAILED" -ne 0 ]; then
  echo "FATAL: $FAILED source identity mismatch(es); the tree is not M1+M2" >&2
  exit 1
fi

echo "IDENTITY_GATE=PASS"
