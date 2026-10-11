# AETHER PHASE 4AB -- PREFLIGHT PATH HARDENING (F4AA-1 closure)

- Status: IMPLEMENTED as a targeted fix (src/bin/v6_preflight.rs only) + kept tests. No consensus, activation, genesis, wire, or release change. No push, merge, tag, deploy. v1.4.0-testnet/ad08e30 intact (verified at close).
- Baseline: HEAD 54a16db at start; preexisting untracked preserved (never git add .).
- ASCII pure, CRLF.

## 1. Scope

Close audit finding F4AA-1 (Windows path bypass in artifact validation) with lexical + confinement checks, prove it with host-independent and integration tests, and preserve every prior guarantee. Nothing else in the tool was redesigned.

## 2. F4AA Finding

The 4Z artifact guard was POSIX-shaped (`starts_with('/')`, `split('/')`): on Windows, backslash traversal (`..\outside`), absolute paths (`C:\...`), drive-relative (`C:...`), rooted (`\...`), UNC/device (`\\server\...`, `\\?\...`, `\\.\...`), and mixed separators bypassed it, so an operator-supplied manifest could direct hashing at out-of-repo files with matching checksums. Rated LOW (read-only impact on the operator's own machine, no write primitive, no network).

## 3. Root Cause

Single predicate, two blind spots: (a) absolute-path detection tested only the POSIX root, while Windows has five absolute/rooted forms plus drive-relative syntax; (b) traversal detection split on `/` only, while Windows accepts `\` and mixed runs. The guard predates any Windows threat model and was never tested against Windows forms (4Z fixtures used POSIX shapes only).

## 4. Path Contract

Strict lexical rules over the manifest string (no host `Path` semantics, so they hold identically on Linux builders): relative only; rejects empty, POSIX absolutes, Windows rooted, drive prefixes (`^[A-Za-z]:`, covering `C:\`, `C:/`, bare `C:`), UNC/device/`//` prefixes, and any `..` component under either separator (forward, backslash, mixed). `.` components allowed (canonical layer normalizes; cannot escape). Reserved names need no rule (reads fail closed). Violations map to the preexisting stable code E_ARTIFACT_PATH (no code churn downstream).

## 5. Confinement

After the lexical gate, both sides are canonicalized (repo root included: tempdirs/junctions may alias) and the target must start with the root. Symlinks escaping the root are rejected (E_ARTIFACT_PATH); symlinks resolving inside are accepted (same-content guarantee: the hash covers the bytes actually read). Absent/unreadable targets keep mapping to E_ARTIFACT_MISSING (unchanged code). Single read feeds both hash and report (no re-read, no replacement).

## 6. TOCTOU

Residual documented, not pretended away: std offers no openat2-style primitive, so a hostile writer holding the operator's paths could swap a symlink between canonicalization and read. Impact stays read-only (a hash over bytes into a local coherence report); exploitation requires write access the threat model already grants the operator. No new mechanism invented to chase it.

## 7. Tests

Unit (host-independent, in-bin): legitimate relatives incl. `./` forms accepted; POSIX absolute/parent, all drive forms, UNC/device/rooted, backslash/mixed traversals, empty and bare `..` rejected (6 tests). Integration (kept suite): former bypasses now fail (backslash traversal, drive absolute/relative, UNC/device/rooted, mixed, empty/malformed), legitimate nested layout verifies (committed, so the clean-tree correspondence holds), external file with correct checksum fails (confinement, not hashing, decides), escaping symlink fails or records NOT_RUN without privileges, inside symlink verifies, all 21 prior fixtures green unchanged (29/29 total).

## 8. Non-regression

Unchanged: manifest parsing (dup/unknown-field/strict-type gates), seven-input rules incl. defaults-rejected, cryptographic reuse (anchor/set/quorum), commit/type/history checks, source-correspondence honesty bounds, exit 0/1/2 semantics, verdict aggregation incl. constant G=NO, SCOPE disclaimer on every run, read-only/dry-run guarantees (re-proven by the byte-stability fixture). Lib code untouched: prior suite results stand undisturbed.

## 9. Residuals

R1 TOCTOU window above (by construction, std-limited). R2 reserved names rely on read-failure fail-closed (platform behavior, reviewed, no explicit table). R3 case-insensitive filesystems (Windows/macOS): canonicalization resolves actual on-disk names deterministically; byte-compare of two spellings is out of scope (hash covers bytes read). R4 4Z residuals unchanged (authenticity unprovable offline, reproducibility unclaimed, git binary required). No new findings opened.

## 10. Final Verdict

F4AA-1 closed by construction + tests on both layers (lexical forms, confinement direction); every prior guarantee re-proven green. The tool remains what 4Z claimed, now on Windows paths too.
