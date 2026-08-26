# ADR 0043: Phase 5 v1 archive, explicit CLI, and release candidate

Status: accepted for implementation

## Context

PR1 freezes one governed reviewed market reference and PR2 compiles one preserved dual-panel
request and invokes the byte-pinned `owner-valuation-kernel v2.0.0-rc.2` once. The system still
lacks a portable exact-byte run archive and an explicit user entry point. Ordinary research must
remain price-blind, while a release candidate needs one bounded path that can prove the reviewed
market, request, execution, and result were the same run.

The original orchestration sketch did not carry the immutable price-blind freeze, security
compilation, private kernel checkout, runtime manifest, private CAS, or injected clocks later
required by PR1 and PR2. Inferring or fabricating those authorities would weaken the accepted
boundary.

## Decision

1. Add one explicit `run_owner_valuation` entry point. Group the omitted immutable authorities in
   a typed `ValuationRunAuthority`; require them rather than infer them.
2. Add a canonical `valuation-run-input.json` bridge for the CLI. It binds the exact ContractGraph,
   canonical ResearchBundle/RunManifest bytes, price-blind freeze, security authority, assumption
   proposals/reviews, component lock, and injected clocks. It contains no market quote or kernel
   result.
3. Add the `owner-research-valuation complete` command. It accepts only the price-blind directory,
   reviewed market receipt, raw market evidence, content-addressed pinned kernel wheel, output
   directory, and explicit private-kernel authority. It accepts no price flag and performs no live
   market or brokerage access.
4. Replay the complete accepted chain. Missing evidence returns `blocked`; unsupported issuer or
   security paths return `specialist_required`; neither path invokes the kernel or writes an
   archive.
5. A completed run invokes the accepted pinned runner once and atomically writes exactly:
   `valuation-handoff.json`, `price-blind-input.json`, `market-reference.json`,
   `valuation-request.json`, `valuation-result.json`, and `valuation-run-manifest.json`.
6. Preserve the request and result bytes used by PR2. Serialize the other four files as canonical
   UTF-8 JSON with one trailing newline. Fsync every member and directory before atomic rename.
7. Strict reload rejects symlinks, extra/missing members, duplicate keys, noncanonical JSON,
   unsafe metadata, and any drift in file hashes, protected hashes, component/kernel identity,
   Snapshot/Handoff/request/result fingerprints, receipts, or deterministic archive ID.
8. Make the primary Skill the sole implicit Skill. Ordinary research routes to the price-blind
   workflow. Only explicit valuation language reaches the orchestrator; audit remains explicit and
   read-only. Keep the primary Skill below 200 lines with three on-demand workflow references.
9. Release version `1.0.0rc1 / 1.0.0-rc.1` only after PR CI and independent fresh-context review
   report P0=P1=P2=P3=0 and the exact merged commit passes the required RC tag checks.

## Consequences

- Public Schema count and bytes remain unchanged.
- The package gains one explicit Python orchestration surface, one explicit console script, and a
  strict archive/reloader. Existing research calls do not gain implicit market access.
- McKinsey and Penman remain separate panels; no weighted target price is introduced.
- No Score-driven valuation, recommendation, report, PDF, Publisher, live provider, trading
  connector, or account mutation is added.
- Stable `v1.0.0` remains a separate gate and requires independently verified Futu legal rights,
  account authority, and isolation evidence. Failure of any gate blocks stable without blocking
  the reviewed-file RC. The dated fail-closed decision is recorded in
  `docs/phase5-v1-stable-release-block.json`; technical API documentation is not a substitute for
  signed account-specific rights and runtime receipts.
