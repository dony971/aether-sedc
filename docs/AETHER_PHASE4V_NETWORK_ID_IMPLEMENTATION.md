# AETHER PHASE 4V -- V6 NETWORK IDENTITY ISOLATION

- Status: IMPLEMENTED as a mini-evolution. No consensus rule moved (quorum/stake/epoch/slash/finality/fork-choice/tokenomics untouched: zero diff on their logic; only additive network checks). No economics invented. V6 dormant, V5 behavior preserved under default 0, v1.4.0-testnet/ad08e30 intact. No push, merge, tag, deploy.
- Baseline: HEAD 1235989 at start; preexisting untracked preserved (never git add .); 4h test harness left untracked per standing practice (compatibility edits kept in tree, not absorbed).
- Rule check: 4U asked whether an identity already exists. Answer: NO reusable distinguisher exists (genesis constant is zeros on every build; P2P v5 shared; no magic/chain-id). The handshake frame + verify function ARE reusable primitives (extended, not duplicated). Hence COMMIT != NONE: the evolution was necessary.
- ASCII pure, CRLF.

## 1. Motivation

Two testnets sharing one binary interconnect freely (same magic/version/genesis) and accept each other's V6 stake objects (votes carry no network context). Threats closed here: peer mixing, vote/cert/anchor cross-network replay, testnet/mainnet confusion, accidental bootstrap on the wrong network. Out of scope (residual): plain-transfer (non-stake) replay and checkpoint-distribution operation.

## 2. Existing Network Separation

Peer-visible: handshake magic ("AETH" obfuscated), P2P_PROTOCOL_VERSION = 5, genesis hash ([0;32] constant) checked exactly with clean rejection (H4/V-24) -- all three IDENTICAL across testnets of one binary, so no isolation. Operator-local: ports, bootnodes/DNS, data_dir, RPC bind -- procedural only, unverifiable by peers. Reusable without duplication: the 69B frame layout + verify_handshake_identity (extended to 77B + expected-network param) and the version-gate discipline. Nothing else peer-verifiable was found (no magic, no chain id anywhere in config/handshake/storage/RPC).

## 3. Network ID Design

Explicit u64 (choice A): DEFAULT_NETWORK_ID = 0 (legacy/unspecified neutral element), NodeConfig.network_id (TOML-compatible via existing serde-default pattern + Default 0, old files parse), CLI --network-id (opt-in like --rpc-bind), threaded to P2PConfig/handshake, TransactionValidator/Processor (field + setters, default 0), AetherRpcImpl (field + setter). Choice B (derivative) rejected: no entropic identifier exists (genesis zeros, version shared, faucet address is money config, not network config). Choice C (identity+genesis) adds nothing today but stays compatible: the genesis check is RETAINED in the handshake (defense in depth, zero extra cost). Choice D: nothing else found. Canonical form le64 everywhere; governed nonzero values stay UNSET (4U sheet): 0 here is the neutral default, never a governance choice.

## 4. Domain Separation

Bound (signed + encoded + verified) exactly where replay has real consequence: handshake peering (network confusion), votes (decide OTHERS' conflicts: replayed quorums would finalize unvoted outcomes), bonds (weight minting), unbonds (cross-network grief-lock of reused keys: victim exits + 72-epoch freeze), anchors/certs (trust objects). NOT bound: plain transfers (residual sec.16: same-binary-same-rules replay gives the attacker nothing unobtainable locally, keys must already match; documented, not hidden). Ledger/DAG: no network concept (state follows content; storage isolated separately). P2P vote/bond/unbond kinds stay opaque byte carriers (sizes noted, no kind change). Evidence/snapshots/seen_bonds derive automatically (embedded encodings/ids).

## 5. P2P Handshake

Frame 69 -> 77 bytes: magic4|ver1|genesis32|network8|key32 appended at END (existing offsets stable for readers). verify_handshake_identity(frame, expected): length, magic, version, genesis, then EXACT network match (0 == 0 preserves legacy). Send side advertises own id; both ends check (duplex cross test: A=7/B=9 fails on BOTH sides, nothing silent). V5 compatibility: default-0 networks behave exactly as before; new-vs-old-binary fails the length check cleanly (same breaking-change discipline as v3->v4/v4->v5; v1.4.0 is separate history, tag verified intact).

## 6. Vote Binding

Vote gains network_id u64 after format_version: signed (signing_bytes), encoded (257 -> 265B), validated (WrongNetwork{expected,found} after version/signature, before epoch/registry checks). VOTE_FORMAT_VERSION 1 -> 2 (old bytes fail explicitly: length AND version gates; v1 rejection pinned in-test). vote(A)->verify(A) PASS; vote(A)->verify(B) FAIL with identical keys/stake/epoch and valid crypto (harness v05). No other vote rule touched (window/registry/eligibility paths identical; 4g green unchanged apart from size asserts).

## 7. Anchor Binding

V6Anchor gains network_id: covered by anchor_id tag, checked against the expected network AND against every quorum vote's network (mixed bundles fail). build_anchor/verify_anchor/verify_bootstrap_anchor take explicit network params (node hook passes the NODE's id, never the bundle's claim). Bundle JSON carries network_id (required field; absent -> parse failure). anchor(A)->verify(A) PASS with identical summary; anchor(A)->verify(B) FAIL (WrongNetwork). State/root/chain semantics otherwise untouched (4p/4q suites green with network 0).

## 8. Certificate Binding

verify_certificate gains expected_network: every vote's network_id must equal it (checked before signature, with the other per-vote checks). certificate(A)->verify(A) PASS; certificate(A)->verify(B) FAIL deterministically (harness v08 + 22 updated call sites passing explicit networks). No quorum/closure/evidence rule touched.

## 9. Storage

data_dir/network.id sidecar (u64 LE), enforced in run_node before Sled open via testable verify_data_dir_network(): fresh dir adopts caller's id; pre-4V dir without marker adopts once (logged, single-network assumption); mismatch or corrupt marker refuses boot fail-closed (same pattern as the stake manifest path). NOT a schema change: no tree/key/manifest touched. Matrix green: fresh/match/mismatch/corrupt/adopt-then-pin (harness v10/v12). Same-dir A+B writes are structurally prevented.

## 10. RPC

No new authentication (explicitly forbidden to invent): isolation inherits validator admission (stake_processor applies the node's id; submitVote/Bond/Unbond paths unchanged otherwise) + the storage marker (no shared dirs). Proven: foreign vote via submitVote rejected, same-network accepted end-to-end (harness v13 on a g36-pattern RpcImpl). Read paths never depended on network.

## 11. Dormant Gate

Default 0 is behavior-neutral, proven three ways: (1) all pre-4V suites green with network-0 fixtures and default validators (no test changed expectations except sizes/offsets); (2) consensus math is network-blind by construction (identical votes differing ONLY in network give identical support totals, harness v14); (3) activation suites green + era predicate has no network input + new code reads no clock and branches on no timestamp. Pre/post activation behave as before; V6 wakes on timestamps alone, never on network config.

## 12. V1.4 Compatibility

Tag v1.4.0-testnet (c230cde) and ad08e30 verified byte-identical at close; no release artifact touched; no history rewritten; no release branch used (work on dev/phase2-decentralized-network). Old binaries meeting new ones fail handshake length cleanly (no silent mixing, no crash class introduced: read_exact_timeout + length gate precede parsing). v1-encoded stake bytes explicitly rejected (pinned).

## 13. Governance

4U sheet update: NETWORK_ID is now technically defined (u64 config + handshake + admission + storage), verifiable (14 harness vectors + rerun suites), governable (single value, validation procedure = compare + verify on all nodes), non-arbitrary (0 reserved as legacy neutral). Value stays UNSET pending real governance (this phase chooses nothing).

## 14. Tests

14 charter items green (harness v04-v17, 0.15s) + handshake self/cross/malformed inside p2p.rs (network isolation duplex test + extended identity test): A/A and B/B handshakes pass; A/B duplex fails both ends; malformed (short/old-69B/bad magic/version/genesis/network) each rejected with its error; vote A/A pass, A/B WrongNetwork exact; anchor A/A summary-equal, A/B WrongNetwork; cert A/B deterministic reject; malformed (truncation/version/bundle-field) rejected; restart marker matrix; processor-level sync rejection with network-named error; storage matrix incl. corrupt/adopt; RPC foreign-reject/local-accept; dormant neutrality (default fixtures + cross-network support equality + era predicate); bond/unbond cross WrongNetwork exact; v1-bytes rejected; perfs (frame ~12us, vote-verify ~10ms sig-dominated, anchor 41ms/4 and 1.02s/100 unchanged). Reruns on final code: 4g 36, 4h 16, 4i 63, 4n 12, 4p 18, 4q 16, 4l 13 (incl. 10k), 4c 12, p2p 152, config 1, double-spend 1, step0 2.

## 15. Performance

Network checks are O(1) field compares (+8B copies): frame build ~12us, vote path dominated by existing Ed25519 (~10ms debug), anchor 100-vote verify 1.03s (identical to pre-4V within noise), bootstrap hook ~64ms/6 votes + file (4Q, unchanged shape). No new bottleneck, no optimization needed.

## 16. Residuals

R1 plain-transfer replay (documented sec.4 reasoning; keys must already match across nets). R2 full sweeps PARTIAL/TIMEOUT carried (validation/ledger/parent_selection heavy suites are PoW-fixture-bound; stake paths they cover are green in targeted suites). R3 50k scale unmeasured. R4 distribution operation + 4J-file + d1fd8d7-message carried. R5 4h harness stays untracked (compat edits kept in tree). No new findings opened.

## 17. Final Verdict

Mini-evolution complete and proportionate: explicit identity where none existed, bindings only where replay has consequence, legacy behavior bit-preserved under default 0, all gates green.
