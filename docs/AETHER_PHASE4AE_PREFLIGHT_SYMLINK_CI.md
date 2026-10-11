# AETHER PHASE 4AE -- PREFLIGHT SYMLINK CI (required execution gate)

- Status: DELIVERED as CI configuration + strict tests (no production change: lib, binary logic, and consensus untouched; the only binary-adjacent edit is none -- this phase adds a workflow file and test code only). No activation, no values chosen, no v1.4.0 change. No push, merge, tag, deploy (workflow runs on pull_request/dispatch in CI, never executed here).
- Baseline: HEAD f2649aa at work; preexisting untracked preserved (never git add .).
- ASCII pure, CRLF (workflow file verified ASCII, LF endings per YAML convention).

## 1. Scope

Turn the 4AC/4AD NOT_RUN symlink rows into either executed proof or loud failure: a CI job that really creates links (inside, outbound, chained, dangling) on ephemeral hosted runners, with a strict gate that forbids silent NOT_RUN from ever reading as PASS.

## 2. Baseline

HEAD f2649aa27224edab1cbb1564b52a8f079b5ab774 verified; branch dev/phase2-decentralized-network; tracked tree clean except this phase's three staged files (sec.13); local host still privilege-less (1314 re-confirmed), so no local execution claim is made anywhere below.

## 3. CI Provider

GitHub Actions: confirmed by the repository itself (.github/workflows/ci.yml, release.yml, security.yml, build-linux.yml using actions/checkout@v4, dtolnay/rust-toolchain@stable, Swatinem/rust-cache@v2). No provider invented, no new action pinned beyond the exact versions already in use.

## 4. Runner Selection

Ephemeral hosted runners only: ubuntu-latest + windows-latest matrix (same pair as the existing ci.yml build matrix). Rationale: Ubuntu runners create symlinks unprivileged (POSIX semantics); Windows runners ship with Developer Mode enabled, so file symlinks work without elevation -- both cover their native path semantics (sec.12 limits honestly kept: neither proves the other's filesystem). No persistent/trusted runners, no excess grants.

## 5. Required Permissions

Workflow-level `permissions: contents: read` (checkout only; strictly less than release.yml's contents:write). No secrets referenced or injected anywhere in the file. No network targets contacted by any step (checkout + toolchain + cache + cargo test only). No OS protections disabled; no local 1314 bypass attempted or documented as a procedure.

## 6. Internal Symlink

Case A policy (inside-resolving link verifies): covered by the kept g08 inside-leg, now strict-aware (creation failure panics under PREFLIGHT_SYMLINK_STRICT instead of printing NOT_RUN). Not executed here (local 1314); CI executes it.

## 7. Outbound Symlink

Case B policy (escaping link refused E_ARTIFACT_PATH): covered by the kept g08 escape leg, strict-aware the same way. Not executed here; CI executes it.

## 8. Chained Symlink

Case C (link2 -> link1 -> outside refused): NEW kept test g09 (chain built link-by-link, both creations strict-gated). Not executed here; CI executes it. Design note: no chain-specific code exists to test -- canonicalization collapses chains, so this test guards against future refactors that might resolve only one level.

## 9. Missing Target

Case D (dangling link refused E_ARTIFACT_MISSING): NEW kept test g10. Not executed here; CI executes it. Distinguishes absent-target (missing) from escape-attempt (path) in the verdict codes.

## 10. External Artifact

Case E policy (correct-hash outside file refused): covered by kept g01/g07 (lexical + confinement, no links involved) -- green locally in this window (full 29+2 suite re-verified: 31/31).

## 11. Regular File

Case F policy (ordinary in-root file verifies): covered by kept f17/g06, re-verified green locally.

## 12. Cross-Platform Coverage

Lexical Windows-form tests (bin unit tests, 6/6) run on ANY os by construction (pure string rules, no FS): host-independent proof, green locally. Filesystem symlink behavior is OS-native by definition: the ubuntu leg proves Linux semantics, the windows leg proves Windows semantics (backslash forms at FS level, Developer-Mode creation). Neither leg claims the other's filesystem; the verdict matrix records per-OS rows after the first CI run.

## 13. Workflow Results

Workflow DEFINED, not yet executed (no push allowed, no runner reachable from here): CI_WORKFLOW = CREATED, CI_RUN_EXECUTED = NO. Local evidence gathered instead: default-mode suite 31/31 green (NOT_RUN recorded, not hidden); strict-mode gate proven to fail loudly on this host (g08 STRICT run red with the exact intended message); workflow YAML checked (ASCII, no tabs, minimal permissions, no publish/deploy/push steps, no node launch, no governance manifest beyond synthetic fixtures).

## 14. Regression Results

Unchanged behavior re-proven locally: full manifest suite 31/31 (21 prior + g09/g10), bin unit 6/6, strict-mode failure semantics. Lib, consensus, manifest rules, checksums, exit codes, offline/dry-run, seven-input requirements, dormant gate, and release history all untouched (zero production diff in this phase; status shows only the three staged files).

## 15. Remaining Gaps

G1 first CI run pending (needs a pull_request or dispatch event -- deliberately not triggered from here). G2 symlink rows stay NOT_RUN until that run (unchanged status, now with an execution vehicle). G3 Windows Developer-Mode assumption documented in-workflow; if it ever lapses, the strict gate fails loudly rather than degrading silently. G4 4Z residuals carried (authenticity offline-unprovable, reproducibility unclaimed). No new findings opened.

## 16. Final Verdict

The gate is built, the tests are strict, the docs are honest: execution is the only missing piece, and it is explicitly pending rather than pretended.
