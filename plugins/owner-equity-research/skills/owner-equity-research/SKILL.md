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
38. Phase 5E-0 defines only the validation policy in
    [market-execution policy](references/market-execution-policy.md): explicit post-authorization
    access timing, single-security/reporting-currency routing, quote-date current common shares,
    split-factor-one fail-closed semantics, final-request byte preservation, and isolated pinned
    wheel execution. It exposes no network, builder, compiler, kernel call, writer, or implicit
    Skill entry point and is accepted/closed under audit `2.3.0`.
39. Phase 5E-1.1 closes the internal market authority boundary: strict price-blind reload,
    evidence-bound security replay, component-locked Provider/adapter/parser, content-addressed
    2026 XNYS/XNAS sessions, orchestrator-owned timestamps, exactly one raw-response call, and a
    governed Receipt-or-quarantine result. This Skill cannot invoke or configure the gate. Phase
    5E-1.1 is accepted/closed under audit `2.3.1.1`.
40. Phase 5E-2A upgrades only `MarketReferenceSnapshot` and adds an
    internal validation witness so ContractGraph can replay authorization, authority, security,
    raw evidence, quote, share-basis, dilution-overlap, and market-equity lineage. It exposes no
    builder or market operation. Phase 5E-2A.1 is accepted/closed under audit `2.3.2.1`.
41. Phase 5E-2A.2 pins the complete annotated rc.2 kernel release and validates Snapshot v3
    current-common-share evidence, Claim-control separation, and the future request-v2 mapping
    witness under audit `2.3.2.2`. It exposes no production compiler or execution surface.
42. Phase 5E-2A.2.1 recursively derives current-share roots, exact-security bindings, cutoff-safe
    formal sources, complete corporate-action search coverage, and completed-claim transitions.
    It is accepted/closed as a validation-only internal boundary.
43. Phase 5E-2B contains one internal deterministic quote-date current-common-share compiler. It
    strictly reloads the price-blind artifact, replays security, governed access, dilution and
    recursive evidence, owns path selection, and returns an immutable result. This Skill cannot
    invoke it or select its Fact, date, path, status, or ShareBasisDecision. Implementation and
    acceptance closeout remain historical governance records under audit `2.3.2.3`.
44. Independent semantic review found that one legal share event can be represented by multiple
    formal-source Facts. Phase 5E-2B.1-0 adds only the internal identity policy, immutable records,
    adversarial fixtures, and baseline oracle under audit `2.3.2.3.1`. Phase 5E-2B.1-1 adds an
    internal production grouping boundary accepted/closed under audit `2.3.2.3.2`, but this Skill
    cannot invoke it. Phase 5E-2B.1-2A defines internal contract-only exactly-once integration
    records under audit `2.3.2.3.3`; exact category coverage, unique category/security-specific N/A
    review chains, direct-Fact and cutoff-safe evidence, graph-byte-bound coverage/transition
    objects, typed evidence cardinality, and option-only standard Claim authority are mandatory.
    Convertible and warrant transitions require specialist handling. Exact source-byte code
    identity and independent test replay bootstrap a credential-partitioned gate; only candidate
    execution is secret-isolated, while protected Controller and kernel jobs use separate
    environment-scoped credentials; the gate introduction
    cannot self-certify and only its later closeout use is base-owned. Official-occurrence key
    drift, nonofficial or non-high opening roots, multi-root Claims without an aggregate balance,
    generated-ID collisions, and multiple transition review chains are blocked. It exposes no
    compiler. Before the validated two-file closeout exists, only the acceptance closeout is
    authorized and 2B is prohibited; after the base-owned gate validates it, only
    `feature/phase5e2b12b-canonical-rollforward` may make the exact compiler/test/state change.
    Its 2B verifier, trust, oracle, and gate tests are preinstalled and frozen by 2A. Phase
    5E-2B.1-2C and Phase 5E-2C through Phase 5E-2F remain prohibited.

Phase 4 and Phase 4E are accepted/frozen at `v0.4.0-alpha.1` after merge, audit, and tag CI.
Phase 5A, Phase 5B, and Phase 5C are accepted/closed. Phase 5D-0 contract and policy hardening and
Phase 5D-1 Candidate compilation are accepted/closed and this Skill does not expose them
implicitly. Phase 5D-2 named-human Decision and AssumptionLedger work is accepted/closed. Phase
5D-3 McKinsey four-scenario input compilation,
Phase 5D-4 Penman input compilation, Phase 5D-5 canonical freeze, and Phase 5D-6 deterministic
replay are accepted/closed under audits `2.2.3`, `2.2.4`, `2.2.5`, and `2.2.6`. Phase 5D is
accepted/frozen. Phase 5E-0 policy hardening and Phase 5E-1.1 authority closeout are
accepted/closed under audits `2.3.0` and `2.3.1.1`; this Skill must not trigger or expose the access
gate implicitly. Phase 5E-2A.1 is accepted/closed after deriving dilution roots from the frozen
Phase 5C bridge and aligning public/Python decimal domains under audit `2.3.2.1`. Phase 5E-2A.2
is accepted/closed after pinning rc.2 and validating current-common-share lineage under audit
`2.3.2.2`. Phase 5E-2A.2.1 recursive evidence is accepted/closed under audit `2.3.2.2.1`.
Phase 5E-2B retains its original governance record under audit `2.3.2.3`; Phase 5E-2B.1-0 is
frozen under audit `2.3.2.3.1`, and Phase 5E-2B.1-1 production grouping is accepted/closed under
audit `2.3.2.3.2`. Phase 5E-2B.1-2A is contract-only under audit `2.3.2.3.3` and uses the
dual-state closeout rule above. Before validation only acceptance is authorized; afterward 2A is
accepted/closed and only 2B is authorized. Phase 5E-2C, Phase 5E-2D, Phase 5F, and later phases
remain prohibited in both states.
Governance audits
`2.1.0.1` and `2.1.5.1` plus
implementation audits `2.1.1`, `2.1.2`, `2.1.3`, `2.1.4`, and `2.1.5` require P0-P3 all zero.

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
Phase 5D-0 through Phase 5D-6, Phase 5E-0, Phase 5E-1.1, and Phase 5E-2A.1 are accepted/closed and
remain internal to the audited handoff boundary. Phase 5E-2A.2 is accepted and validation-only.
Phase 5E-2A.2.1 recursive evidence is accepted/closed. Phase 5E-2B keeps its historical closeout
but requires the Phase 5E-2B.1 semantic correction. Phase 5E-2C and later remain prohibited, and
this Skill has no grouping, market, or valuation entry point.

The post-S3 control plane is a protected-base recursive G1/G2/G3/G4/G5 sequence: inert gate,
accepted gate, successor pending acceptance, accepted successor, then total closeout and the exact
next inert seed. Dynamic audit profiles come from the deepest validated gate; candidate oracle
text remains inert. Treat `Phase 5E-2B.1-2C` (current-share recursive closure) and `Phase 5E-2C`
(exact market evidence) as distinct phases. Phase 6 through Phase 9 remain outside this map and
require a separate reviewed authorization. The current GitHub Free private repository has no
pinned Controller App, kernel-only read-only Kernel Reader App, or protected environments, so
remote acceptance remains prohibited.

Phase 5 current authority: S3 -> G1 -> G2 -> G3 -> G4 -> G5 -> external 2C-P; after feasibility a new protected gate is required; Phase 6-9 require separate reviewed control-plane authorization; Phase 5E-2B.1-2C != Phase 5E-2C.
