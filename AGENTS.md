# Owner Equity Research Instructions

## Phase boundary

- Current product label: `Phase 5 v1 market-reference vertical slice`.
- `docs/phase5-v1-status.json` is the current authority; the phase is `in_progress`, and only
  `PR1 market-reference vertical slice` is authorized.
- ADR 0041 retires the recursive G1-G5 and acceptance-only path from required governance.
  `docs/phase-status.json` and the former recursive controller remain frozen as
  `legacy_governance`; their closeouts are historical evidence, not current authorization.

### Historical phase record

The phase bullets below through Phase 5E-2B.1-2A record the authority and constraints that applied
at each closeout. Present-tense wording inside this historical record has no current normative
force; ADR 0041 and `docs/phase5-v1-status.json` supersede it.

- Phase 1 is frozen at `v0.1.0-alpha.1`.
- Phase 2 is frozen at `v0.2.0-alpha.1` / `feac934`.
- Phase 3 is frozen at `v0.3.0-alpha.1` / `41dcb27`.
- Phase 4A is accepted and closed at merge `a70c4e7`; it has no release tag.
- Phase 4B-0 is complete at PR #8.
- Phase 4B-1 is complete at PR #9.
- Phase 4B-2 is complete at PR #10.
- Phase 4B-3 is complete at PR #11.
- Phase 4B-4 closes the deterministic ManagementReview and fixed-date metadata-only shadow. Phase
  4B creates no release tag and does not enter Phase 4C.
- Phase 4C is accepted and frozen at `e51e0e9`; it has no release tag.
- Phase 4D-0 is accepted and frozen at merge `fe69e3b`; it has no release tag.
- Phase 4D-1 is accepted and frozen at merge `8bbdd4c`; it has no release tag.
- Phase 4D-2 is accepted and frozen at merge `7fb2b3d`; it has no release tag.
- Phase 4D-3 is accepted and frozen at merge `4308306`; it has no release tag.
- Phase 4D-4 is completed at merge `0407c41`; its original semantic acceptance was conditional.
- Phase 4D-5 closes carryover activity selection, machine-readable source searches, and phase
  transition. When this closeout is present on `main` with passing CI, Phase 4D is accepted and
  frozen.
- Phase 4E-0 is accepted and closed when its single PR is on `main` with passing CI. It adds only
  the validation-only `ResearchBundle 1.0.0` contract.
- Phase 4E-1 is accepted and closed when its single PR is on `main` with passing CI. It adds only
  the deterministic Bundle builder and atomically bound RunManifest result.
- Phase 4E-2 adds only deterministic, atomic materialization and reload of the validated
  `research-bundle.json` / `run-manifest.json` pair plus complete/partial/blocked integration
  proofs. When its PR, main CI, exact-head audit, annotated `v0.4.0-alpha.1` tag, and tag CI pass,
  Phase 4 and Phase 4E are accepted and frozen.
- Phase 5P records the valuation-handoff plan, method boundary, pinned interface matrix, failure
  modes, and acceptance gates. It adds no public Schema, production adapter, market access,
  valuation request/result, kernel invocation, Score, report, PDF, or Publisher.
- Phase 5P is accepted and closed when its single PR is on `main` with passing main CI and exact-head
  read-only audit `1.8.0`. At that closeout, only Phase 5A contract work was authorized.
- Phase 5A is accepted/closed when its single PR is on `main` with passing CI and exact-head
  read-only audit `1.9.0`. It contains four public contracts and validation-only ContractGraph
  gates, with no builder, market access, or kernel execution.
- Phase 5B-0 contains only closed source/concept/unit/period/calculation registries, immutable
  internal mapping/readiness types, adversarial fixtures, and read-only audit `2.0.0`.
- Phase 5B-1 strictly reloads the canonical Bundle pair, replays the complete ContractGraph, and
  compiles only registered official-source raw Facts into the pinned FactLedger Schema. It exposes
  no package-root, CLI, writer, market, assumption, request, result, or kernel-execution surface.
- Phase 5B-2 maps only registered quarterly single-quarter and TTM CalculationResults whose
  assumption-free fingerprints, periods, parents, and single official-source lineage replay.
- Phase 5B-3 deterministically classifies the issuer from current SEC industry identity, material
  scope, and human-confirmed specialist Claims, then recomputes separate McKinsey and Penman
  readiness panels. Method `ready` means only that Phase 5B evidence may enter Phase 5C.
- Phase 5B-4 closes deterministic replay, amendment/conflict behavior, eight routing goldens, and
  the full mapping/readiness audit. Phase 5B is accepted and closed.
- Phase 5C-0 contains only ADR 0026, closed account/period/quality/adjustment/MethodView/
  equity-bridge/de-duplication/readiness policies, immutable internal types, adversarial fixtures,
  and read-only audit `2.1.0`. It exposes no compiler, package-root API, CLI, writer, market,
  assumption, request/result, kernel-execution, Score, report, PDF, or Publisher capability.
- Phase 5C-0 is accepted/closed through the Phase 5C-0.1 governance closeout. PR #35, its merge,
  main CI, and the exact-head `2.1.0` audit are recorded in `docs/phase-status.json`; audit gate
  `2.1.0.1` enforces P0-P3 all zero. Phase 5C-1 accounting reconciliation work was then authorized.
- Phase 5C-1 may add only the internal `compile_accounting_reformulation` entrypoint. It must
  strictly reload the canonical Bundle pair, replay Phase 5B, classify registered accounting
  evidence, derive common equity/NOA/NFO/invested capital/owner distributions, and recompute the
  balance-sheet, economic-identity, and clean-surplus controls. Audit `2.1.1` keeps the compiler
  off the package root, CLI, Skills, and writers and limits pinned-kernel use to FactLedger shape
  plus the three approved accounting compatibility interfaces.
- Phase 5C-1 is accepted/closed through PR #38, merge `34ef5b1463c2...`, main CI
  `29268975345`, and exact-head audit `2.1.1` with P0-P3 all zero. Phase 5C-2 accounting-quality
  and assumption-free adjustment work is accepted/closed through PR #39, merge `2d8d900fa524...`,
  main CI `29270484340`, and exact-head audit `2.1.2` with P0-P3 all zero.
- Phase 5C-3 MethodView work is accepted/closed through PR #40, merge `a6c6d85ae062...`, main CI
  `29271863942`, and exact-head audit `2.1.3` with P0-P3 all zero.
- Phase 5C-4 equity-bridge work is accepted/closed through PR #41, merge `f16595e50f6d...`, main
  CI `29273390412`, and exact-head audit `2.1.4` with P0-P3 all zero.
- Phase 5C-5 successor-readiness and replay closeout is accepted/closed through PR #42, merge
  `0ad92bb3206b...`, main CI `29274820514`, and exact-head audit `2.1.5` with P0-P3 all zero.
  At that closeout, Phase 5C was accepted/closed; only Phase 5D assumption governance and
  price-blind freeze work was authorized, while later phases remained prohibited pending separate
  authorization.
- Phase 5D-0 is accepted/closed through PR #44, merge `4814029d9c5a...`, main CI
  `29295736044`, and exact-head audit `2.2.0` with P0-P3 all zero. It adds only
  `ValuationAssumptionCandidate 2.0.0`, `ValuationHandoff 2.0.0`, the
  internal immutable `PriceBlindReferenceClosure`, closed slot/evidence/freeze policies, and
  validation-only ContractGraph gates. It must not add a Candidate compiler, AssumptionLedger
  compiler, market client, price-blind artifact writer, valuation request/result, kernel execution,
  Score, report, PDF, or Publisher. At that closeout, only Phase 5D-1 Candidate compilation was
  authorized; later phases remained prohibited.
- Phase 5D-1 is accepted/closed through implementation PR #46, acceptance PR #47, merge
  `7c13073aa70a...`, main CI `29297468611`, and exact-head audit `2.2.1` with P0-P3 all zero.
  It adds only the internal, keyword-only `compile_valuation_assumption_candidates`
  entrypoint and immutable proposal/result types. It must strictly reload the Bundle pair, replay
  complete Phase 5C readiness, derive Candidate and binding IDs, and stop before human Decisions.
  It may not export the compiler from the package root or add a Decision resolver, AssumptionLedger,
  scenario compiler, price-blind writer, market client, request/result, or kernel execution.
- Phase 5D-2 is accepted/closed through PR #49, merge `43fffa76d3eb...`, main CI
  `29299088854`, and exact-head audit `2.2.2` with P0-P3 all zero. Its internal
  named-human Decision resolver and pinned-schema AssumptionLedger compiler remain price-blind,
  in-memory, and outside all Skill and package-root entry points.
- Phase 5D-3 is accepted/closed through PR #51, merge `dcbc5d5bbbb6...`, main CI
  `29300664978`, and exact-head audit `2.2.3` with P0-P3 all zero. Its internal compiler
  replays Phase 5D-2, compiles exactly four price-blind scenario blocks, and runs only the pinned
  ForecastPeriod/SteadyStateEvidence preflight without invoking valuation mathematics.
- Phase 5D-4 is accepted/closed through PR #53, merge `e3ef484f42ca...`, main CI
  `29302120207`, and exact-head audit `2.2.4` with P0-P3 all zero. Its internal compiler
  replays Phase 5D-2, compiles governed price-blind Penman forecast, hurdle/growth grids, and
  challenge-path references, forces CAP diagnostics off, and omits market-equity identity.
- Phase 5D-5 is accepted/closed through PR #55, merge `a63e3dcb5c57...`, main CI
  `29303730712`, and exact-head audit `2.2.5` with P0-P3 all zero. Its internal compiler freezes
  one canonical nonmarket artifact, derives protected hashes, and advances only adjacent immutable
  Handoff states through `market_reference_allowed`.
- Phase 5D-6 is accepted/closed through PR #57, merge `38be7b66ea20...`, main CI
  `29305219309`, and exact-head audit `2.2.6` with P0-P3 all zero. Its clean-room replay proves
  byte-stable price-blind artifacts, unrelated-history independence, immutable protected hashes,
  and the absence of market, request/result, valuation, public API, CLI, report, Publisher,
  marketplace, or release capability. Phase 5D is accepted and frozen.
- Phase 5E-0 is accepted/closed under audit `2.3.0`. It adds only closed market-quote,
  security-identity, point-in-time-share-basis, final-request-preservation, and isolated-kernel
  policies plus internal immutable record types. It adds no network client, Snapshot builder,
  final-request compiler, kernel invocation, writer, public contract, or implicit Skill entry.
- Phase 5E-1 passed its original engineering boundary under audit `2.3.1`. Its internal-only
  entrypoint strictly reloads the price-blind artifact, selects the exact current v4 authorization,
  owns both access timestamps, invokes the adapter once without retry, and returns either a
  replayable Request/Receipt or a hash-only quarantine. Independent semantic review subsequently
  found unresolved authority boundaries in provider registration, parsing, calendars, security
  identity, decimals, and endpoint secrets.
- Phase 5E-1.1 is accepted/closed under audit `2.3.1.1`. The repository-owned Provider, parser,
  content-addressed 2026 XNYS/XNAS calendars, and evidence-bound security identity form the only
  market-access authority.
- Phase 5E-2A passed its original PR/CI audit under `2.3.2`, and Phase 5E-2A.1 is accepted/closed
  under audit `2.3.2.1`. It derives dilution authority from the frozen Phase 5C bridge and aligns
  Schema/Python positive decimals.
- Phase 5E-2A.2 pins the annotated `owner-valuation-kernel@v2.0.0-rc.2` release and upgrades only
  `MarketReferenceSnapshot` to current-common-share v3 semantics. It may add no share compiler,
  market-evidence generator, Snapshot builder, request compiler, kernel call, or writer. It is
  accepted/closed under audit `2.3.2.2`.
- Phase 5E-2A.2.1 is the validation-only recursive current-share evidence closeout. It derives raw
  numeric roots, cutoff-safe formal sources, all-family corporate-action coverage and completed
  claim transitions under audit `2.3.2.2.1`. It is accepted/closed after separate implementation
  and acceptance PRs. Phase 5E-2B adds only the internal compiler-owned quote-date current common
  shares selection, derivation, replay, and immutable evidence result under audit `2.3.2.3`.
  Its implementation and separate acceptance closeout remain historical governance records.
  Independent semantic review found that source identity could let one legal event enter the
  roll-forward more than once. Phase 5E-2B.1 is therefore a corrective semantic closeout under
  audit `2.3.2.3.1`. Phase 5E-2B.1-1 production grouping is accepted/closed under audit
  `2.3.2.3.2`; it groups reviewed corroborating evidence and blocks semantic conflicts without
  changing the current-share compiler. Phase 5E-2B.1-2A defines immutable canonical-event,
  exactly-once consumption, group-bound coverage/Claim-transition, Bundle-binding, and recursive
  closure contracts under audit `2.3.2.3.3`; exact per-category coverage, unique
  category/security-specific N/A review chains, direct-Fact and cutoff-safe evidence, exact
  graph-byte binding for every typed coverage/transition object, typed evidence cardinality, and
  the option-only standard Claim authority are mandatory. Convertible and warrant transitions
  remain specialist routes. One official occurrence cannot split across economic-event keys;
  opening/output evidence stays official and high confidence; multi-root Claims without an
  aggregate balance, generated-ID collisions, and multiple transition review chains are blocked.
  Exact source-byte code identity and independently replayed tests bootstrap a
  credential-partitioned gate; only candidate execution is secret-isolated,
  the gate introduction itself requires independent review and only subsequent closeout use is
  base-owned. It creates no
  production Fact or compiler. The former two-file closeout, special branch, preinstalled judge,
  and successor prohibitions are retained in `legacy_governance` only; they no longer authorize or
  block current Phase 5 v1 work. Phase 6 through Phase 9 still require separate reviewed
  authorization after Phase 5.
- Phase 5D-2 may add only the internal, keyword-only `compile_reviewed_assumption_ledger`
  entrypoint and immutable review/result types. It must replay the exact Candidate compilation,
  derive Decision and reserved assumption IDs, accept only `human:<name>` reviewers, augment only
  confirmed supplemental price-blind Facts as kernel `evidence`, and validate only FactLedger plus
  AssumptionLedger against the pinned kernel. It must not export the compiler from the package
  root or add McKinsey/Penman method inputs, a price-blind writer, market client, request/result,
  or valuation execution.
- Phase 5D-3 may add only the internal, keyword-only `compile_mckinsey_scenario_inputs`
  entrypoint and immutable result type. It must replay Phase 5D-2, require the four closed
  scenarios on one annual timeline, derive the current base invested-capital Fact, and use only
  the pinned `ForecastPeriod` and `SteadyStateEvidence` preflight. It must not export the compiler,
  call DCF/economic-profit math, compile Penman inputs, write an artifact, read market data, build a
  request/result, or execute valuation.
- Phase 5D-4 may add only the internal, keyword-only `compile_penman_price_blind_inputs`
  input-reference compiler and immutable
  result type. It must replay Phase 5D-2, require governed near-term forecast, hurdle/growth grids,
  and a price-blind challenge path, validate only pinned Penman input shapes, and stop before
  persistence, market reference, reverse-price analysis, request/result, or valuation execution.
- Phase 5D-5 may add only the internal canonical price-blind input compiler, strict atomic writer
  and reloader, protected-subtree hashes, and adjacent immutable Handoff transitions through
  `price_blind_input_frozen` and `market_reference_allowed`. It must replay the accepted Phase 5D
  chain and may not read market data, compile a full valuation request/result, invoke valuation
  mathematics, or expose a package-root, CLI, or implicit Skill entry point.
- Phase 5D-6 may add only deterministic replay goldens, clean-room closeout checks, frozen-baseline
  verification, and Phase 5D acceptance governance. It may not add market access, a
  MarketReferenceSnapshot, valuation request/result construction, kernel execution, a public API,
  CLI, report, Publisher, or release tag.

### Current repository constraints

- Do not copy source code, prompts, personas, templates, or valuation logic from the legacy repository.
- Treat `/Users/mingji/Documents/New project/institutional-value-investing-legacy` and `/Users/mingji/Documents/New project/owner-valuation-kernel` as read-only dependencies.

## Contract rules

- JSON Schemas use Draft 2020-12 and reject unknown properties.
- Python contract objects are immutable and serialize deterministically.
- Facts, claims, assumptions, calculations, and scores remain distinct domains.
- A `CalculationResult` may only be produced by a deterministic program.
- A `Score` is always labeled `PROJECT_EXTENSION`; it may consume evidence but may not influence facts, claims, assumptions, calculations, or valuation.
- Historical reports remain quarantined until the current conclusion is frozen.

## Verification

- Use Python 3.11 or newer.
- Run `python scripts/verify_phase5_v1.py --mode verify` for the current non-legacy suite.
- The exact required contexts are `verify (3.11)`, `verify (3.12)`, `verify (3.13)`, and
  `phase5/semantic-audit`. The Actions context runs deterministic candidate replay once at the
  exact PR head and must not be represented as an independent review.
- A separate fresh-context reviewer must bind the exact commit/tree, test counts, P0-P3 counts and
  report SHA in PR evidence. Pull requests require P0 and P1 equal to zero in both gates. Release
  candidates require P0, P1, P2, and P3 equal to zero. Merged `main` runs smoke and deterministic
  replay.
- Canonical audit summaries stay outside the repository and may be uploaded as CI artifacts. Do
  not write new CI run IDs into product state.
- CI may resolve dependencies before verification; candidate tests and audit execution must remain
  netless. Live SEC access is limited to explicit shadow runs.
- Phase 4E-2 requires P0, P1, P2, and P3 equal to zero. Its annotated release tag is
  `v0.4.0-alpha.1` and must point to the audited main merge commit.
- Phase 5B is the accepted deterministic FactLedger-mapping and dual-method readiness boundary.
  Phase 5C is accepted/closed through exact-head audit `2.1.5` and governance closeout audit
  `2.1.5.1`. Phase 5D-0, Phase 5D-1, and Phase 5D-2 are accepted/closed under audits `2.2.0`,
  `2.2.1`, and `2.2.2`; Phase 5D-3, Phase 5D-4, and Phase 5D-5 are accepted/closed under audits
  `2.2.3`, `2.2.4`, and `2.2.5`; Phase 5D-6 is accepted/closed under audit `2.2.6`. Phase 5D is
  accepted and frozen. Phase 5E-0 policy hardening is accepted/closed under audit `2.3.0`;
  Phase 5E-1 passed the original engineering audit `2.3.1`; Phase 5E-1.1 is accepted/closed under
  audit `2.3.1.1`; Phase 5E-2A.1 is accepted/closed under audit `2.3.2.1`. Phase 5E-2A.2 is the
  accepted validation-only rc.2/current-share boundary under audit `2.3.2.2`. Phase 5E-2A.2.1
  is accepted/closed under audit `2.3.2.2.1`; Phase 5E-2B passed its original governance closeout
  under audit `2.3.2.3`, while Phase 5E-2B.1-0 is frozen under audit `2.3.2.3.1` and the
  Phase 5E-2B.1-1 production grouping is accepted/closed under audit `2.3.2.3.2`. Phase
  5E-2B.1-2A used the now-retired dual-state closeout rule under audit `2.3.2.3.3`. Those P0-P3
  closeout requirements remain historical evidence and do not replace the ADR 0041 thresholds.

## Phase 5 v1 vertical-slice authority

- Advance Phase 5 through complete, bounded vertical slices governed by ADR 0041 and
  `docs/phase5-v1-status.json`.
- The PR1 slice must keep market-reference evidence, current-share lineage, provider review, and
  preparation behavior deterministic and fail closed; it still cannot invoke valuation
  mathematics, scoring, reporting, or publishing unless separately authorized.
- The old G1-G5 controller, acceptance-only branches, dynamic successor profiles, protected status
  publication, and next-gate seeding are `legacy_governance`. The legacy workflow is manual only
  and its checks must not be required by branch protection.
