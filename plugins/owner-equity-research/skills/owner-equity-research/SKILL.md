---
name: owner-equity-research
description: Use for source-backed research on a listed general US-GAAP nonfinancial company when the work requires SEC filing provenance, deterministic extraction, governed Fact promotion, segment or footnote review, accounting-quality findings, a deterministic management ledger, governed business-quality evidence, or a human-reviewed capital-allocation Event ledger. This is the only implicitly invocable entry point. Do not use for financial institutions, insurers, REITs, resource companies, grading, scoring, valuation, reports, PDF, or publishing.
---

# Owner Equity Research

Build a Phase 3 evidence package, the completed Phase 4B management ledger, the completed
Phase 4C business-quality evidence layer, or the Phase 4D-5 capital-allocation evidence layer. Keep official artifacts, extraction
candidates, promoted Facts, Claims, segment views, footnote reviews, and accounting-quality
findings as separate typed domains.

Phase 4D-1 through 4D-5 capital-allocation Event, bridge, Outcome, Review, search-receipt, and metadata-only Shadow
workflows run only when that ledger is explicitly requested.

## Workflow

1. Require one issuer, CIK, a data cutoff date, and `OWNER_RESEARCH_SEC_USER_AGENT`.
2. Read [SEC intake](references/sec-intake.md), select only qualifying 10-K/10-Q filings at or
   before the cutoff, and preserve accession, URL, raw/normalized hashes, and parser version.
3. Extract deterministic table/iXBRL candidates. A language model may draft narrative candidates
   or Claims only; it cannot create a Fact, final finding, or final severity.
4. Apply the evidence-promotion boundary described in [SEC intake](references/sec-intake.md). Keep ambiguities, duplicate/restatement
   conflicts, missing periods, and unresolved units blocked.
5. Build reportable-segment definitions and snapshots from existing Facts. Keep geography,
   customer concentration, corporate items, and eliminations distinct. Use display precision for
   reconciliation tolerance and do not infer undisclosed metrics.
6. Read [footnote topics](references/footnote-topics.md), represent every mandatory topic, and add
   dynamically discovered material notes.
7. Read [accounting-quality rules](references/accounting-quality-rules.md). Run deterministic
   rules as suggestions; require an evidence-backed Claim with counterevidence search and a
   falsification condition before confirming severity.
8. Validate the complete contract graph and RunManifest. Return JSON contracts and blocked/missing
   evidence only, not a company report or recommendation.
9. When management Statements are requested, read [management source policy](references/management-source-policy.md)
   and [statement intake](references/management-statement-intake.md). Stop language-model output at
   a Candidate and require a machine-readable human decision before emitting a Statement or target
   Fact.
10. When a measurable confirmed Statement has an explicit metric, scope, basis, target, policy,
    and deadline, read [Commitment compiler](references/management-commitment-compiler.md) and
    compile it deterministically. Keep narrative-only Statements out of the Commitment ledger and
    record the exclusion reason in the run manifest.
11. When result evidence is requested, read [Outcome evaluator](references/management-outcome-evaluator.md).
    Require official, comparable evidence and let the registered policy compute the status. Keep
    unresolved scope, unit, currency, basis, period, component, or KPI bridges blocked. Do not build
    a ManagementReview until all selected objects pass these gates.
12. Read [Management review and shadow](references/management-review-shadow.md). Let code select
    the latest eligible objects and recompute every coverage count. A complete Review cannot contain
    blocked or unverifiable due Outcomes. Fixed-date shadows store metadata and hashes only.
13. When business-model analysis is requested, read [Business model](references/business-model.md).
    Let code derive material scopes and bind each reviewed attribute to its exact Fact, Candidate,
    human Decision, and Claim. Do not generalize across reportable segments.
14. Read [Mechanism diagnostics](references/mechanism-diagnostics.md) before calculating mechanism
    evidence. Use only registered, assumption-free primitives over target-company Facts and keep
    external context outside CalculationResult.
15. Read [Hypothesis review](references/hypothesis-review.md). Stop language-model output at a
    Candidate, require a human Decision, and let the resolver compute hypothesis status and trend.
16. Read [Business-quality Review and shadow](references/business-quality-review-shadow.md). Let
    code select the latest exact-scope objects and recompute coverage. Complete means closed
    evidence coverage, not a good company or investment conclusion.
17. When a capital-allocation Event ledger is requested, read [Capital-allocation Event
    ledger](references/capital-allocation-event-ledger.md). Preserve exact official-source spans,
    stop language-model output at Candidate, require a human Decision, and let code derive event
    identity, deduplication, lifecycle, and versioning.
18. When a reviewed Event requires a consideration, financing, cash, liquidity, dividend, or
    share bridge, read [Capital-allocation conservation
    bridges](references/capital-allocation-conservation-bridges.md). Use a registered policy over
    exact Event-bound Facts and emit only an assumption-free CalculationResult.
19. When post-Event result evidence is requested, read [Capital-allocation Outcome
    evaluator](references/capital-allocation-outcome-evaluator.md). Supply every policy role,
    reviewed Claim chain, completed-search nondisclosure, and missing evidence; let code derive the
    evidence-state Outcome.
20. For coverage closure, read [Capital-allocation Review and
    Shadow](references/capital-allocation-review-shadow.md). Require SourceSearchReceipt coverage
    for all eight families, let code select current and carryover objects, recompute every
    source/type/status count, and keep fixed-cutoff Shadows metadata-only.
21. When a validated integrated evidence package is requested, read [ResearchBundle contract and
    builder](references/research-bundle-contract.md). Call `build_research_bundle` with the complete
    ContractGraph and explicit RunManifest ID. Insert both returned immutable objects into the same
    graph and validate it. Do not let the caller choose modules, status, scope, freshness, or hashes.
22. Materialize the validated result only with `write_research_bundle_artifacts`, producing exactly
    canonical `research-bundle.json` and `run-manifest.json`. Reload with
    `load_research_bundle_artifacts` and replay the ContractGraph before delivery. Do not expose a
    CLI or treat a complete Bundle as a quality or investment conclusion.
23. The four Phase 5A valuation-handoff contracts are described in [Valuation handoff
    contracts](references/valuation-handoff-contracts.md). They are validation-only. Do not build
    them, fetch a quote, compile a kernel ledger or request, invoke the kernel, or write valuation
    artifacts.
24. Phase 5B strictly reloads the canonical Bundle pair with its complete ContractGraph and can
    compile registered official-source raw Facts plus registered quarterly single-quarter/TTM
    derived Facts into an in-memory price-blind FactLedger. It deterministically classifies official
    company identity and material scope, then keeps McKinsey and Penman readiness separate. Neither
    internal entrypoint is exposed through this Skill or the package root. Do not fuzzy-match
    concepts, invent FX lineage, accept market sources, add valuation calculations, infer readiness
    from Bundle completeness, or treat 5B `ready` as valuation-ready.
25. Phase 5C-0 defines only closed internal policies and immutable result shapes for common-equity
    perimeter, NOA/NFO and clean-surplus checks, accounting-quality dispositions, assumption-free
    MethodView targets, nine equity-bridge roles, root-lineage de-duplication, and separate
    successor readiness. It exposes no compiler through this Skill or the package root. Do not
    create a reconciliation, adjustment, MethodView, bridge item, or Phase 5C readiness result.
26. Phase 5C-1 provides one internal accounting-reconciliation compiler. It strictly reloads the
    Bundle pair and complete graph, replays Phase 5B, selects registered official accounting Facts,
    closes the common-equity perimeter and six owner-flow components, and recomputes the balance
    sheet, NOA-NFO identity, and clean-surplus checks. This Skill does not invoke or expose it.
    Do not let a caller choose Facts, classifications, status, residual plugs, or outputs, and do
    not extend it into accounting-quality adjustments, MethodViews, equity bridge, assumptions,
    market data, requests/results, or valuation execution.
27. Phase 5C-2 provides one additional internal compiler for the current AccountingQualityReview,
    its Findings, and registered zero-Assumption adjustment amounts. It requires confirmed human
    AnalyticalClaim review for final Finding semantics, maps incomplete evidence to partial or
    blocked, keeps McKinsey and Penman method effects separate, and records the pinned kernel's
    global-gate incompatibilities explicitly. This Skill does not invoke or expose the compiler.
    Do not let a Finding create an adjustment amount or permit subjective R&D, brand, useful-life,
    market, assumption, MethodView, equity-bridge, request/result, or valuation behavior.
28. Phase 5C-3 provides one additional internal compiler for closed McKinsey and Penman MethodView
    fragments. It replays the accepted Phase 5C-2 chain, accepts only registered zero-Assumption
    adjustments, records deterministic root-consumption claims, and validates only the pinned
    FactLedger, MethodAdjustment, and MethodView interfaces. This Skill does not invoke or expose
    the compiler. Do not let a caller add, remove, relabel, or duplicate adjustments or consumption
    roots, and do not extend it into an equity bridge, readiness, market, request/result, or
    valuation behavior.
29. Phase 5C-4 provides one additional internal compiler for the nine registered equity-bridge
    roles. It replays the accepted MethodView chain, uses only frozen current official evidence,
    emits same-source positive derived aggregates, preserves numeric zero and reviewed N/A as
    assertions, and rejects root or dilution overlap. This Skill does not invoke or expose the
    compiler. Do not let a caller supply roles, statuses, aggregates, sources, bridge items, or
    counts, and do not extend it into successor readiness, market, request/result, or valuation.
30. Phase 5C-5 provides one internal successor-readiness assessor. It replays the accepted bridge
    chain, selects the exact current typed stable-capital evidence package, preserves specialist
    routing, and recomputes separate McKinsey/Penman panels. This Skill does not invoke or expose
    the assessor. Do not let callers supply routing booleans, evidence selections, panel states,
    counts, or fingerprints, and do not interpret `ready_for_phase5d` as valuation-ready.
31. Phase 5D-0 defines the validation-only [valuation-assumption governance](references/valuation-assumption-governance.md)
    boundary. It upgrades Candidate and Handoff contracts to v2, binds each Candidate to one closed
    slot, and isolates macro, industry-risk, and owner-hurdle Facts in a separately hashed internal
    closure. This Skill does not build Candidates, compile assumptions, read market data, write a
    price-blind artifact or invoke the kernel. Phase 5D-0 is accepted/closed under audit `2.2.0`.
32. Phase 5D-1 compiles only unreviewed price-blind Candidates after strict Bundle and Phase 5C
    replay. It owns IDs and typed evidence edges and remains internal; this Skill cannot invoke it.
    Phase 5D-1 is accepted/closed under audit `2.2.1`.
33. Phase 5D-2 resolves exact Candidate fingerprints through named-human Decisions and compiles
    only a pinned-schema AssumptionLedger plus augmented price-blind FactLedger in memory. This
    Skill cannot invoke it, supply review results, or extend it into method inputs or persistence.
    Phase 5D-2 is accepted/closed under audit `2.2.2`; Phase 5D-3 McKinsey four-scenario input
    compilation is accepted/closed under audit `2.2.3`, and it remains outside this Skill.
34. Phase 5D-3 compiles exactly four price-blind McKinsey input-reference blocks and runs only the
    pinned steady-state credibility preflight. This Skill cannot invoke it, supply scenarios or
    status, or extend it into Penman inputs, persistence, market access, request/result, DCF,
    economic profit, or valuation execution.
35. Phase 5D-4 may compile only price-blind Penman forecast, hurdle/growth-grid, and challenge-path
    input references. This Skill cannot invoke it, supply inputs or status, or extend it into
    persistence, market access, reverse-price analysis, request/result, or valuation execution.
    Phase 5D-4 is accepted/closed under audit `2.2.4`; the fragment omits market-equity identity
    and keeps CAP diagnostics disabled.
36. Phase 5D-5 may compile, atomically persist, and strictly reload only the canonical price-blind
    input artifact, derive its protected hashes, and advance immutable Handoff versions through
    adjacent price-blind states. This Skill cannot invoke it, select inputs or state, read market
    data, compile a full request/result, or execute valuation. Phase 5D-5 is accepted/closed under
    audit `2.2.5`.
37. Phase 5D-6 may add only deterministic replay goldens, clean-room closeout verification, and
    Phase 5D acceptance governance. This Skill cannot invoke an internal compiler or expose market,
    request/result, kernel execution, report, Publisher, or release behavior. Phase 5D-6 is
    accepted/closed under audit `2.2.6`, and Phase 5D is frozen.
38. Read [market-execution policy](references/market-execution-policy.md) before any explicit
    valuation preparation. Market evidence may enter only after the price-blind artifact reaches
    `market_reference_allowed`; ordinary research remains price-blind.
39. The Phase 5 v1 market slice can internally compile quote-date current common shares and a
    provider-neutral `MarketReferenceSnapshot 4.0.0`. A reviewed-file provider must recompute the
    external evidence hash and bind a named-human review. It cannot accept a command-line price,
    access a network, read a trading account, or produce a final request or kernel result.
40. Cross-source disclosures of one legal share event are grouped once for arithmetic while all
    corroborating evidence is retained. Conflicting amount, date, security, or remaining-claim
    evidence blocks the lineage; convertible and warrant cases remain specialist routes.

## Stop conditions

Stop as `partial` or `blocked` for unsupported issuer types, missing identity, non-SEC sources,
cutoff conflicts, source/hash mismatches, candidate ambiguity, noncomparable segment mappings,
unreconciled totals, or incomplete footnote evidence. Missing evidence is never a red flag and
never evidence of no risk.

Do not score or grade management or capital allocation, build valuation inputs, generate a
target price, render a report/PDF, or invoke a Publisher. Do not copy legacy prompts, personas,
templates, or valuation logic. Phase 4E-2 persists only the validated two-file Bundle pair; it does
not expose a CLI, run a new company Shadow, orchestrate downstream work, or publish. Phase 5B adds
only internal raw/derived mapping, deterministic classification, separate method readiness, and
audited replay. Phase 5C-0 adds only internal policy registries and immutable types. Phase 5C-1
adds only the internal accounting-reconciliation compiler; Phase 5C-2 adds only the internal
quality/adjustment compiler; Phase 5C-3 adds only the internal MethodView compiler and root-
consumption replay; Phase 5C-4 adds only the internal equity-bridge compiler. None adds a Skill
entry point, output writer, market access, complete routing request, handoff execution, or
valuation execution. Phase 5C-5 adds only the internal successor-readiness assessor and no Skill
entry point, output writer, market access, assumption compilation, request/result, or kernel call.
Phase 5D remains the frozen price-blind boundary. The v1 market slice is internal and can stop only
at a validated release-candidate Snapshot; it does not expose a package-root API, CLI, final
valuation request, kernel execution, archive, report, or publishing surface. Recursive controller,
gate-author, recovery-seal, and acceptance-only PR instructions are historical governance records
and are not active Skill workflow.
