# AETHER PHASE 4Z -- V6 RELEASE PREFLIGHT (offline tool)

- Status: IMPLEMENTED as a read-only CLI (src/bin/v6_preflight.rs) + 40 black-box fixture tests (tests/v6_preflight_manifest.rs) plus the inventory suites (tests/phase4aq_inventory_tests.rs, tests/phase4bh_inventory_tests.rs). No activation, no values chosen, no v1.4.0 change. No push, merge, tag, deploy.
- Baseline: HEAD 4832e9c at build; preexisting untracked preserved (never git add .). Bins follow repo convention (src/bin/*.rs, lib via aether_unified::); no new dependencies (serde_json/sha2/hex/blake3/clap-free arg parsing all preexisting).
- Audit conclusion (charter sec.4): formats sufficient WITHOUT new protocols -- manifest envelope is this tool's documented input contract (not network behavior); anchor bundle reuses the 4Q parser; validator records reuse derived Deserialize; votes reuse canonical encodings; commits reuse local git objects; checksums reuse sha2. NOT BLOCKED.
- ASCII pure, CRLF.

## 1. Scope

Offline, dry-run-only pre-verification of a future governance manifest: seven inputs, validator-set/stake recomputation, anchor verification, release/commit/artifacts, optional explicit release-root inventory, network/activation rules, separated verdicts A-H, stable error codes, exit 0/1/2. The tool proves manifest coherence; it never proves authenticity or authority (printed SCOPE note on every run).

## 2. Existing Formats

Anchor bundle JSON: existing parse_anchor_bundle (strict lengths/version). Validator set: ValidatorRecord derived Deserialize (verified against live decoding in the PASS fixture). Votes: canonical encodings incl. version gate. Commits: local git objects via read-only plumbing. Checksums: sha256 hex (dep present, no additions). Version/network/timestamp: strict JSON scalars. Manifest envelope: NEW input contract defined sec.3 (tool scope, documented here, no wire/network semantics attached).

## 3. Input Manifest

JSON object, deny_unknown_fields + duplicate-key rejection (custom scanner: serde_json is last-wins), format: 1. Keys: format, activation_ts (nonzero u64 ms), network_id (u64), release_version (nonempty string), release_commit (40 hex), validator_set (array), stake: {claimed_eligible_total}, anchor (4Q bundle object), artifacts ([{path, sha256}]). Paths must be relative without dotdot segments (fail closed).

## 4. Seven Governance Inputs

Each checked present + well-formed + independently re-verifiable + cross-linked: activation_ts (presence/format; never defaulted from code const), network_id (present; 0 rejected as governance), release_version (nonempty, != v1.4.0-testnet), release_commit (40-hex, exists locally, != ad08e30), validator_set (nonempty, parsed, see sec.5), stake (see sec.6), anchor (see sec.7). Absent input = MISSING code; code defaults never count (network 0 fails explicitly even when everything else passes).

## 5. Validator Set

Structural (nonempty, no duplicate address, amounts nonzero) + recomputation: set_root recomputed at the anchor epoch via existing validator_set_root and compared; per-record eligibility NOT reimplemented (consensus rule stays single-sourced; weights flow from the same recomputation the anchor uses).

## 6. Stake State

claimed_eligible_total compared to the independently recomputed eligible sum (copied claims rejected, e.g. off-by-one). No ledger object required: coherence here means set/anchor/claims agree; ledger reconciliation stays a node-boot property (INC-01 guards, cited).

## 7. Anchor Verification

Existing verifier reused wholesale (structure/encoding/epoch/network/root/votes/signatures/quorum/chain/tag): empty sets, bad signatures, wrong roots/denominators/epochs/networks all refuse with their codes. STATE_BINDING stays RESERVED (no state-root check invented). Anchor bytes are verified, never rewritten or replaced by the tool.

## 8. Network ID

Explicit nonzero required (absent -> parse-level MISSING; 0 -> E_NETWORK_ZERO even fully coherent; bundle-vs-manifest mismatch -> E_NETWORK_MISMATCH). Coherence checked against config expectation only where a config exists (tool scope: manifest-internal + anchor consistency).

## 9. Activation Timestamp

Presence + nonzero format from the manifest only. Never defaulted from code const (no substitution path exists in the tool). Transition-rule compatibility is by design review (predicate unchanged), not by tool assertion beyond format.

## 10. Release Commit

Exists locally as a commit object (cat-file), distinct from ad08e30; version string distinct from v1.4.0-testnet. Source correspondence best-effort and honestly bounded: HEAD equality + clean tree proves the CHECKED-OUT source matches, never that a shipped binary was built from it (reproducibility explicitly NOT claimed).

## 11. Artifact Checksums

Each declared file must exist under the repo, stay inside it (no absolute/parent paths), carry 64-hex, and hash-match (sha256 recomputed). Missing/unreadable/mismatched each fail distinctly. Empty artifact list allowed and recorded (nothing to hash is not a failure).

### 11.1 Optional Release-Root Inventory (opt-in)

`--inventory-root <path>` walks a release tree, binds every declared artifact path (normalized with the same host semantics as the inventory) to its sha256, and fails on unexpected files. `--inventory-exclude <glob>` is repeatable and explicitly allowlists generated paths. `--require-inventory` fails with `E_INVENTORY_CONFIG` when no root is supplied. Without `--inventory-root` the verdict line reports `H INVENTORY_CHECKS: NOT_RUN`; no release root or default gate is invented.

The inventory gate is strict: structural directories are allowed, while symlinks, special files, unreadables, case collisions, hardlink groups, external/ambiguous link references and non-file declared entries fail closed. A manifest path that cannot be normalized fails with `E_INVENTORY_PATH`; walk/verification failures use `E_INVENTORY_WALK` / `E_INVENTORY_VERIFY`. The gate is opt-in because no authoritative release-root contract exists in this phase; the existing A-G gates are unchanged and H reports NOT_RUN.

## 12. Verdicts

A INPUTS_COMPLETE (PASS/FAIL/NOT_EVALUATED), B CRYPTOGRAPHIC_CHECKS, C CONFIGURATION_COHERENCE, D RELEASE_ARTIFACT_CHECKS, E GOVERNANCE_READY (inputs complete+consistent ONLY; authenticity disclaimed same line), F TECHNICAL_READY (B+C green; suite evidence separate per 4R), G OPERATIONAL_READY (always NO: preflight observes nothing operational), H INVENTORY_CHECKS (PASS/FAIL/NOT_RUN; opt-in, see 11.1). Stable E_ codes on every failure with plain messages. Exit 0 = all checks pass; 1 = checks failed; 2 = manifest unusable.

## 13. Dry-Run Safety

Read-only by construction (fs reads, git rev-parse/cat-file/status, stdout). No writes, no sockets, no node state access, no V6_ACTIVATION_TS/genesis/storage/v1.4.0 contact. Proven: coherent-PASS run leaves every file byte-identical (fixture re-reads all inputs). No activate/deploy/publish/start-network verbs exist (unknown verbs exit 2).

## 14. Tests

40 black-box fixtures (deterministic, fictitious network 7/9, temp git repos, never governance values): empty, missing field, absent network, zero network, explicit nonzero, absent timestamp, missing commit, bad checksum, duplicate validator, incoherent total, wrong root, wrong denominator, empty votes, bad signature, foreign-network anchor, out-of-window epoch, coherent PASS + byte-stability, truncated file, duplicate key + ambiguous type, default-as-decision, unknown verbs, path-hardening cases, and opt-in inventory gate cases h01-h08 (absent/NOT_RUN, pass, extra/missing artifact, symlink, require-without-root, exclusion, dot normalization). Each asserts exact exit codes and error codes. Inventory hardening itself is covered by tests/phase4aq_inventory_tests.rs and tests/phase4bh_inventory_tests.rs.

## 15. Known Limits

Cannot prove authenticity/authority (offline by design); cannot prove binary reproducibility (source correspondence only); cannot observe operations (G always NO); git binary required for commit checks; anchor-epoch vs activation-ts linkage has no specified rule (checked independently, documented); empty artifact lists vacuous-pass by policy. The release-root inventory is opt-in and strict; its symlink policy is intentionally narrower than the legacy internal-symlink artifact fixture policy, and no authoritative default release root exists.

## 16. Operational Handoff

Usage: v6-preflight --manifest <path> [--repo <path>] [--inventory-root <path>] [--inventory-exclude <glob>]... [--require-inventory]; gate releases on exit 0 + E/F/G/H reading with the SCOPE note; inventory checks are skipped explicitly as NOT_RUN unless a root is supplied. Provenance confirmation stays a human governance act. Fixtures must never be mistaken for a manifest (values fictitious, temp repos ephemeral, documented here and in-test).

## 17. Final Verdict

Offline gate delivered without touching consensus, activation, or history. Inventory hardening and the optional release-root gate are added; the existing A-G gates remain and H reports NOT_RUN without an explicit root.
