---
name: owner-research-audit
description: Use only when explicitly invoked with $owner-research-audit to audit the completed research and price-blind chain plus the active Phase 5 v1 vertical slice, including current-share evidence, reviewed market references, component locks, determinism, and forbidden outputs.
---

# Owner Research Audit

This is the explicit read-only audit workflow for the Phase 1-5D evidence and price-blind chain and
the Phase 5 v1 vertical slices. Historical recursive controller, recovery-seal, G1-G5, and
acceptance-only PR records are evidence, not active workflow. Normal implementation PRs block on
P0/P1; release audits block on P0/P1/P2/P3.

## Audit

1. Run schema, immutability, fingerprint, and dangling-reference checks.
2. Verify domain separation and one-way `Score` dependencies.
3. Verify the pinned valuation-kernel component lock.
4. Verify that only the main research skill permits implicit invocation.
5. Classify findings as P0, P1, P2, or P3 and provide file-level evidence.
6. Verify SEC identity/rate/cache boundaries, candidate promotion policy, segment reconciliation,
   complete footnote coverage, and Claim-confirmed accounting-quality severity.
7. Verify all ten Phase 4A schemas and immutable types, official-evidence promotion boundaries,
   Claim counterevidence/falsification, KPI-definition bridges, commitment timing, unique capital
   event keys, outcome evidence roles, Review coverage, and one-way dependency constraints.
8. Confirm that management production is limited to the Statement, Commitment, Outcome, and Review
   ledger and business-quality production is limited to context, descriptive business models,
   registered diagnostics, reviewed Claims, hypotheses, coverage Reviews, and metadata shadows.
9. Verify official-source host allowlists, exact text/hash provenance, Candidate-only language-model
   output, machine-readable human decisions, and one confirmation decision per confirmed Statement.
10. Verify that Commitment compilation rejects narrative-only Statements, unconfirmed evidence,
    unregistered policies, ambiguous fiscal dates, scope/basis mismatches, and missing KPI bridges.
11. Verify all ten policy evaluators, assumption-free growth/cumulative/KPI calculations,
    official-source and comparability gates, lifecycle Outcomes, and Claim-result evidence coverage.
12. Verify code-selected ManagementReview objects, recomputed coverage, latest-Outcome selection,
    and complete/partial/blocked status rules.
13. Verify Salesforce and Amazon fixed-cutoff shadows contain only source IDs, scoped hashes,
    object IDs, coverage, blocked reasons, and RunManifest metadata.
14. Confirm that no management grade, score, valuation handoff, report, PDF, or Publisher is present.
15. Verify that external issuer, regulator, customer, supplier, and industry evidence remains in
    ContextObservation and never becomes a target-company Fact or CalculationResult input.
16. Verify AnalyticalClaimCandidate fingerprints, evidence-graph hashes, one human Decision per
    confirmed Claim, BusinessModel component coverage, versioned mechanism roles, retained
    counterevidence, scope matching, lifecycle acyclicity, and replayable trend evidence.
17. Verify diagnostic registry units, periods, scopes, input roles, minimum observations, code SHA,
    and forbidden valuation or shortcut concepts.
18. Verify that `build_business_quality_review` selects the latest exact-scope objects and
    recomputes every coverage and status field. A complete Review may have zero supported
    hypotheses but cannot contain blocked key coverage.
19. Verify Amazon, Salesforce, and Union Pacific fixed-cutoff shadows contain only official filing
    metadata, explicitly scoped hashes, object IDs, status counts, blocked reasons, and RunManifest
    metadata. A metadata hash must not be represented as a content hash.
20. Confirm capital-allocation production stops at coverage Reviews and metadata-only Shadows: no
    grade, score, valuation handoff, market-price input,
    target price, recommendation, report, PDF, Publisher, or Phase 4 release tag exists.
21. Verify CapitalAllocationEventCandidate and human ReviewDecision fingerprints, official-source
    eligibility, economic-event identity, same-key version chains, retained evidence, registered
    source/Fact/result roles, unit families, currencies, and cutoff dates.
22. Verify Outcome absence states and lifecycle Outcomes, plus all eight formal source families and
    thirteen event-type rows in CapitalAllocationReview. Complete means coverage closure only.
23. Verify the SEC lifecycle selector, issuer-IR authority gate, exact source hash/span, Candidate
    v2 dates and growth semantics, human Decision fingerprint, same-key disclosure deduplication,
    deterministic lifecycle, retained predecessor Decisions, contiguous versions, and idempotent
    replay.
24. Verify every conservation bridge uses a registered policy, exact Event-bound Fact roles, one
    issuer/period/currency, official cutoff-safe sources, unit-safe arithmetic, no Assumptions, and
    deterministic fingerprints. Confirm missing roles never become zero and gross buybacks include
    SBC and other issuance before any net-share calculation.
25. Verify the Outcome evaluator; Outcome status is code-derived, lifecycle Events contain no results, and every observed role
    has one official result and reviewed Claim coverage; nondisclosure has a completed official
    search; calculations are assumption-free and fingerprint-valid; and one Event/window is
    idempotent.
26. Verify `build_capital_allocation_review` selects latest logical Events and Outcomes, fills all
    eight source and thirteen event-type rows, recomputes every count, and derives Review status.
27. Verify Amazon, Salesforce, and Union Pacific fixed-cutoff Shadows contain only source metadata
    hashes, expected event types, object IDs, counts, blocked reasons, and RunManifest metadata.
28. Verify SourceSearchReceipt request fingerprints, all-eight-family and all-thirteen-type search
    scope, carryover Event activity, cross-version Outcome selection, and deterministic Review v3
    replay. Confirm Phase 4D-5 and Phase 4E-0 status is consistent across repository instructions.
29. Verify `ResearchBundle 1.0.0` has closed fields; exact module taxonomy and cardinality; current
    cutoff-safe object selection; one business-quality reference per material scope; event-driven
    freshness; deterministic artifact, source, dependency, identity, and semantic hashes; matching
    component lock and RunManifest output hash; and no `Score`, `Assumption`, valuation,
    ReportSpec-output, Publisher, or Legacy dependency. Confirm no Bundle builder, CLI,
    orchestration, Shadow, release, or marketplace update exists.
30. Verify `build_research_bundle` accepts only a ContractGraph and keyword-only run ID; derives all
    module, scope, freshness, status, missing-evidence, and hash fields; returns an immutable Bundle
    plus atomically updated RunManifest; preserves other manifest outputs; is order-independent and
    idempotent; fails closed on ties and conflicting replay; and adds no persistence, CLI,
    orchestration, Shadow, valuation, scoring, Publisher, or release surface.
31. Verify `write_research_bundle_artifacts` and `load_research_bundle_artifacts` accept only the
    validated Bundle/RunManifest pair; write exactly two canonical JSON files atomically; reject
    symlink paths, unrelated entries, unsafe overwrite, tampering, and noncanonical JSON; and replay
    the complete ContractGraph after reload.
32. Verify complete, partial, and blocked integration goldens; source-publication watermarks;
    order-independent hashes; unrelated-history stability; and the rule that metadata-only company
    Shadows cannot be represented as complete ResearchBundle graphs.
33. Verify the frozen Phase 4 annotated tag `v0.4.0-alpha.1` still targets its audited merge and
    the current tree continues to exclude CLI, orchestration, valuation execution, scoring,
    report, PDF, Publisher, or marketplace surfaces.
34. Verify `ValuationAssumptionCandidate`, `ValuationAssumptionReviewDecision`,
    `MarketReferenceSnapshot`, and `ValuationHandoff` schemas, immutable types, typed
    ResearchBundle-closure evidence, named-human Decision uniqueness, reserved kernel assumption
    IDs, exact adjacent Handoff state transitions, frozen protected hashes, market authorization,
    quote/share/calculation round trip, fixed kernel identity, and the absence of any builder,
    fetcher, compiler, kernel call, or valuation-artifact writer.
35. Verify Python `0.5.0.dev2`, Plugin/component lock `0.5.0-dev.2`, 43 public Schema hashes, the
    unchanged Phase 5A merge and audit `1.9.0`, and exact-head no-remote Phase 5B audit `2.0.4`.
36. Verify the five closed Phase 5B mapping registries, exact pinned FactLedger Schema SHA,
    immutable mapping/readiness types, strict Bundle/graph reload, official deterministic
    SourceRefs, raw Fact period/unit conversion, conflict fail-closed behavior, registered
    single-quarter/TTM lineage, and the absence of fuzzy concepts, valuation calculations,
    fabricated FX, market access, AssumptionLedger compilation, request/result generation, or
    valuation-kernel invocation.
37. Verify official SIC identity, current material-scope priority, human-confirmed specialist
    Claims, all six routing assessments, independent McKinsey/Penman roles, specialist routing,
    and the invariant that Phase 5B never asserts complete valuation-request data.
38. Verify eight deterministic routing goldens, byte-identical and unrelated-history-independent
    replay, amendment precedence, unversioned-conflict blocking, and that reviewed specialist
    Candidate/Decision/Claim evidence is present in the ResearchBundle dependency closure.
39. Verify Python `0.5.0.dev3`, Plugin/component lock `0.5.0-dev.3`, unchanged 43 public Schema
    hashes, the byte-frozen Phase 5B merge and audit `2.0.4`, and exact-head no-remote Phase 5C-0
    audits `2.1.0` and `2.1.0.1`. Verify the closed account, period, accounting-quality, MethodView target,
    nine-role equity-bridge, de-duplication, and successor-readiness policies; immutable internal
    types; corrected non-common-claim perimeter; stable-capital evidence package; empty-bridge
    compatibility limitation; and absence at the frozen Phase 5C-0 boundary of any compiler,
    market, assumption, request/result, kernel execution, Score, report, PDF, or Publisher surface.
40. Verify the sole Phase 5C-1 internal compiler strictly reloads the canonical Bundle pair,
    replays Phase 5B, selects only current registered official accounting Facts, creates one
    classification decision per candidate, requires named-human review for mixed/perimeter items,
    rejects aggregate/component overlap, closes all six owner-flow components, and recomputes the
    balance-sheet, NOA-NFO, and clean-surplus controls. Confirm no residual plug can promote
    readiness and pinned-kernel compatibility uses only FactLedger shape plus the approved
    balance-sheet and clean-surplus validators.
41. Verify the sole Phase 5C-2 internal quality compiler selects the current Bundle-bound
    AccountingQualityReview and Findings, requires a confirmed named-human AnalyticalClaim chain
    for final semantics, maps provisional or blocked evidence without inventing severity, keeps
    method-specific effects separate, and records the pinned kernel global-gate mismatch. Confirm
    adjustment amounts use only registered same-period, single-source, zero-Assumption lineage;
    Findings never create amounts; and no MethodView, bridge, market, request/result, or valuation
    surface is exposed.
42. Verify the sole Phase 5C-3 internal MethodView compiler replays the accepted quality chain,
    emits only closed McKinsey/Penman fragments, and derives every adjustment and root-consumption
    record from registered evidence. Confirm callers cannot add, remove, relabel, self-target, or
    duplicate a claim; the pinned checkout is used only for FactLedger, MethodAdjustment, and
    MethodView compatibility; and no bridge, successor readiness, market, request/result, kernel
    valuation, CLI, writer, or Skill execution surface is exposed.
43. Verify the sole Phase 5C-4 internal equity-bridge compiler replays the accepted MethodView
    chain and closes exactly nine role decisions from frozen current official evidence. Confirm
    modeled items are positive same-source derived aggregates; formal zero and reviewed N/A stay
    non-modeled assertions; cash, dilution, roots, roles, and economic claims cannot be double
    counted; the rc.1 empty-item limitation remains explicit; and pinned compatibility uses only
    FactLedger shape. Confirm no successor readiness, market, request/result, valuation execution,
    CLI, writer, or Skill entrypoint is exposed.
44. Verify the sole Phase 5C-5 internal successor-readiness assessor strictly reloads and replays
    the accepted bridge chain, selects an exact current typed stable-capital evidence package,
    preserves specialist routing, and recomputes all six routing assessments plus separate
    McKinsey/Penman panels. Confirm empty account evidence cannot pass separability, ambiguous or
    missing stable-capital evidence fails closed, `credible_near_term_earnings` remains pending,
    `required_data_complete` remains false, and no aggregate readiness, model weight, market,
    assumption, request/result, valuation execution, CLI, writer, or Skill entrypoint is exposed.
45. Verify Candidate/Handoff v2, closed slot and evidence roles, the separately hashed internal
    price-blind reference closure, named-human Decision uniqueness by slot, exact policy hashes,
    chronological adjacent Handoff transitions, protected-hash immutability, and target-security
    market exclusion. Confirm no Phase 5D compiler, network client, writer, kernel invocation,
    Score, report, PDF, or Publisher surface exists.
46. Verify the sole Phase 5D-1 Candidate compiler strictly reloads the canonical Bundle pair,
    replays Phase 5C readiness, accepts only closed typed proposals, derives Candidate and binding
    IDs, and validates its temporary ContractGraph. Confirm it remains price-blind and internal and
    creates no Decision, AssumptionLedger, method input, artifact, market reference, or kernel run.
47. Verify the sole Phase 5D-2 review and AssumptionLedger compiler binds exact Candidate and
    evidence fingerprints, accepts only named-human reviewers, derives IDs, retains only active
    confirmed Decisions, maps only numeric support lineage, and validates the pinned FactLedger
    and AssumptionLedger. Confirm supplemental references remain price-blind `evidence` Facts and
    no method compiler, artifact writer, market client, request/result, or valuation run exists.
48. Verify the sole Phase 5D-3 McKinsey compiler replays the accepted Decision and AssumptionLedger
    chain, requires black-swan/bear/base/bull scenarios on one exact annual timeline, derives base
    invested capital from the current ledger, and uses only the pinned steady-state preflight.
    Confirm no caller-authored status or input IDs, Penman input, artifact writer, market client,
    request/result, DCF, economic-profit, equity-bridge, or valuation execution surface exists.
49. Verify the sole Phase 5D-4 Penman compiler replays the accepted named-human AssumptionLedger,
    derives one current NOA/NFO pair, requires exact contiguous forecast and challenge periods,
    and preserves ordered governed hurdle/growth grids. Confirm it uses only the pinned
    `PenmanForecastPeriod` shape preflight, omits market-equity identity, disables CAP diagnostics,
    writes no artifact, and calls no accounting-anchor, reverse-price, fade, hurdle-comparison,
    growth-return, request/result, market, or valuation surface.
50. Verify Phase 5D-5 compiles and strictly reloads one canonical price-blind input artifact,
    derives the full-input fingerprint plus protected McKinsey and Penman-assumption hashes, and
    advances only adjacent immutable Handoff states through `market_reference_allowed`. Confirm
    no target-security market data, complete valuation request/result, valuation mathematics,
    package-root API, CLI, or implicit Skill execution surface exists.
51. Verify Phase 5D-6 replays the complete frozen chain byte-for-byte across closed goldens,
    remains independent of input order and unrelated history, preserves both protected hashes and
    immutable Handoff versions, and adds no market, request/result, valuation, public API, CLI,
    report, Publisher, marketplace, or release capability.
52. Verify the v1 current-share compiler consumes each canonical legal event exactly once, retains
    all corroborating sources, closes the twelve event categories and eight source families, and
    blocks occurrence drift, conflicting amounts/dates/securities, dangling lineage, or duplicate
    claim transitions.
53. Verify the reviewed-file Provider is invoked only after `market_reference_allowed`, rejects
    symlinks and non-regular files, recomputes content hashes, requires the named-human review and a
    credential-free HTTPS source, and has no network or trading-account capability.
54. Independently recompute the authoritative Decimal close-times-current-shares arithmetic and
    validate `MarketReferenceSnapshot 4.0.0`, its source/security/current-share lineage, protected
    hashes, component lock, release-candidate usage scope, and single-authorization consumption.
55. Confirm ordinary research remains price-blind and that the current slice exposes no
    package-root/CLI market entry, final FactLedger/request, kernel invocation, archive, Score,
    recommendation, report, PDF, or Publisher.
56. Treat the exact PR-head Actions semantic profile as deterministic candidate replay, not as an
    independent review. Separately perform a fresh-context review, bind its exact commit/tree,
    test counts, P0-P3 counts and report SHA in PR evidence, and do not use a production parser,
    selector, builder, or compiler as its sole oracle. Normal PR acceptance requires P0=P1=0 in
    both gates; an RC or stable release requires P0=P1=P2=P3=0.

Do not edit files, repair findings, generate research, or publish artifacts. Historical recursive
gate/controller workflows may be inspected as evidence but must not be treated as active authority.
