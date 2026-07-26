# Phase 1-4A architecture

## One evidence system, separate domains

`SourceDocument` records provenance. `Fact` records source-linked observations and permits
research scalars; numeric facts require a registered unit and period, while currency is required
only for monetary unit families. `Claim` interprets evidence
and must record both support and either counterevidence or the counterevidence search performed.
`Assumption` is explicitly scenario-bound and never masquerades as a fact.
`CalculationResult` is deterministic program output with versioned inputs. `Score` is a
`PROJECT_EXTENSION` consumer and has no reverse edge into evidence or valuation.

The research `Fact` is intentionally broader than the valuation kernel's numeric `FactLedger`.
No implicit conversion exists. A future Phase 5 adapter must select eligible numeric facts,
preserve provenance, declare every transformation, and validate against the pinned valuation
schema before handoff.

## Anti-anchoring state machine

Historical reports and earlier recommendations are prohibited during `pre_conclusion`.
They may only be accessed in `comparison` after a conclusion hash and freeze timestamp have
been recorded. The graph validator rejects an early access record.

## Dependency direction

```text
SourceDocument -> Fact -> Claim
                    |       |
                    +-> Assumption -> CalculationResult
                           |                |
                           +----------------+-> Score (PROJECT_EXTENSION)

RunManifest records the run; ReportSpec describes structure only.
```

## Phase 2 quarterly vertical slice

Phase 2 adds three reference-only contracts and one deterministic calculation module:

```text
SourceDocument -> Fact -> FiscalPeriod
                    |          |
                    |          +-> QuarterlyReconciliation
                    |                       |
                    +-> CalculationResult <-+
                    |                       |
                    +-> Claim --------------+-> QuarterlyUpdate
```

`FiscalPeriod` makes calendar, 52/53-week, discrete-quarter, cumulative and TTM windows
explicit. Its identifier and full fingerprint are calculation inputs whenever fiscal metadata
affects a result. `QuarterlyReconciliation` declares a single-quarter or YTD basis, selects
regulatory authority by deterministic rules, compares every candidate and blocks unresolved
conflicts. `QuarterlyUpdate` stores only validated identifiers; it cannot contain valuation
outputs, scores or rendered reports. The calculation module derives discrete quarters, TTM
values, per-week diagnostics, ratios, changes, free cash flow and growth-bridge residuals from
typed evidence with versioned fingerprints and explicit role bindings.

## Phase 3 SEC filing and accounting-quality vertical slice

Phase 3 keeps the existing Fact ledger and introduces a promotion boundary before it:

```text
SourceDocument -> FilingArtifact -> ExtractionCandidate -> EvidencePromotion -> Fact
                                                           |                    |
                                                           +-> Claim            +-> SegmentSnapshot
                                                                                     |
SourceDocument -> SegmentDefinition -----------------------------> SegmentSnapshot  |
SourceDocument -> FootnoteReview <- Fact / Claim / CalculationResult                 |
                         |                                                           |
                         +-> AccountingQualityFinding -> AccountingQualityReview <---+
```

Only deterministic, fully resolved primary-regulatory table/iXBRL candidates can auto-promote.
Language-model output stops at a candidate or Claim draft. Segment metrics remain Facts; the
snapshot binds them to reportable, corporate, or elimination definitions and uses disclosed
precision to test reconciliation. Geography and customer concentration are separate disclosure
types, never silently treated as reportable segments.

Every mandatory footnote topic has an explicit status, while material additional Notes are added
dynamically. Accounting-quality rules suggest severity; only a Claim with supporting evidence,
counterevidence search, confidence, and a falsification condition can confirm final severity.
Missing evidence remains blocked.

No Phase 1-3 module performs business or management analysis, scoring, valuation handoff,
rendering, PDF generation, or publication. Phase 3 does not generate company reports,
recommendations, or target prices.

## Phase 4A contract-only judgment boundary

Phase 4A adds typed evidence organization without adding a production judgment engine:

```text
SourceDocument / Fact / Claim / CalculationResult
        |                    |
        +-> BusinessModelSnapshot -> CompetitiveAdvantageHypothesis
        |                                  |
        |                                  +-> BusinessQualityReview
        |
        +-> ManagementStatement -> ManagementCommitment -> ManagementOutcome
        |                                                     |
        |                                                     +-> ManagementReview
        |
        +-> CapitalAllocationEvent -> CapitalAllocationOutcome
                                              |
                                              +-> CapitalAllocationReview
```

Official SEC or company-IR evidence is required for confirmed statements and complete or
supported conclusions. Third-party evidence may supply counterevidence or a low-confidence Claim,
but cannot by itself promote a hypothesis or review. Every non-blocked conclusion consumes a
Claim with supporting facts, a recorded counterevidence search, and a falsification condition.
Phase 4A calculations may not depend directly or transitively on Assumptions.

Management statements, commitments, and outcomes are separate objects. A language-model extract
must be human-confirmed before it can support a commitment or review. KPI definition changes need
a predecessor statement and deterministic reconciliation before comparison. Capital-allocation
events use deterministic issuer-scoped keys so repeated filing disclosures enrich one event.
Outcome roles keep gross execution, SBC, issuance, net share change, impairment, and synergy
evidence distinct.

The dependencies remain one-way: Phase 4A objects consume the existing evidence system; Facts,
Claims, calculations, and the valuation kernel never depend on Phase 4A reviews. No Phase 4A
contract consumes Score, valuation, target price, recommendation, ReportSpec output, PDF, or
Publisher. Production business-quality, management, and capital-allocation engines begin only in
later Phase 4 slices.

## Phase 4B-0 management semantic boundary

The management chain now binds confirmed target Facts to explicit components and roles, records
scope and measurement basis, accepts only registered evaluation policies, and assigns result
evidence an actual or milestone role. These structures are prerequisites for deterministic
production code; Phase 4B-0 itself does not compile commitments or evaluate outcomes.

Withdrawn and superseded commitments close through lifecycle Outcomes and never flow into ordinary
due or missed counts. Narrative-only statements remain Statements or Claims and cannot be promoted
to Commitments.

## Phase 4B-1 Statement ledger

```text
official SourceDocument -> ManagementStatementCandidate -> human ReviewDecision
                                                       -> ManagementStatement + target Facts
```

Candidates preserve an exact normalized text span and hashes. A language model may propose a
Candidate but cannot confirm it. Every confirmed Statement is linked to exactly one named human
decision, and every emitted target Fact must reproduce a reviewed metric mention. Non-SEC official
retrieval requires an issuer-specific HTTPS host allowlist and keeps raw content outside the repo.

## Phase 4B-2 Commitment compiler

```text
confirmed Statement + reviewed target Facts + explicit scope/basis/policy/deadline
    -> deterministic compile_commitment
    -> open ManagementCommitment or a recorded non-measurable exclusion
```

The compiler accepts only official evidence, exact registered-policy roles, and either an explicit
date or a controlled relative deadline that resolves to one fiscal period. It does not convert
narrative Statements into blocked Commitments. KPI definition changes require an assumption-free
deterministic bridge. Withdrawal and supersession compilers close lifecycle state without creating
an ordinary operating Outcome. Phase 4B-2 performs no result comparison.

## Phase 4B-3 Outcome evaluator

```text
Commitment + official result evidence + explanatory Claims
    -> comparability gate -> registered policy arithmetic -> ManagementOutcome
```

The evaluator computes all ten registered policies. Reported growth and cumulative results are
materialized as assumption-free `CalculationResult` objects. Adjusted growth and KPI definition
changes require named deterministic calculations. Claims must cover formal result inputs but cannot
change `met`, `partially_met`, or `missed`. Missing disclosure is `unverifiable`; unresolved source
or comparability is `blocked`; lifecycle Outcomes never become ordinary performance failures.

## Phase 4B-4 Review and shadow closeout

`build_management_review` selects issuer objects at the cutoff, keeps the latest eligible Outcome
per Commitment, and recomputes all coverage counts. Missing final due Outcomes and lifecycle gaps
block the Review. Unverifiable official results can only produce a partial Review. Complete Reviews
contain neither blocked nor unverifiable Outcomes.

The Salesforce and Amazon acceptance shadows are fixed at `2026-07-11`. They retain official URLs,
SEC accessions, scoped evidence hashes, object IDs, coverage, blocked reasons, and a RunManifest.
They contain no raw source text, Facts, Claims, report, score, valuation, target price,
recommendation, PDF, or Publisher output. When issuer IR blocks direct automated retrieval, the
manifest labels the hash scope as a normalized official excerpt verified through the web snapshot;
it never represents that hash as a full response hash.

## Phase 4C-0 business-quality semantic boundary

```text
external SourceDocument -> ContextObservation -> CompetitiveContextSnapshot

target Fact / CalculationResult ----+
ContextObservation -----------------+-> AnalyticalClaimCandidate
                                      -> human ReviewDecision -> Claim

BusinessModelSnapshot + CompetitiveContextSnapshot + reviewed Claim
    -> typed mechanism evidence -> CompetitiveAdvantageHypothesis
    -> coverage-only BusinessQualityReview
```

Target Facts and calculations remain single-issuer. External issuer, regulator, customer,
supplier, and industry evidence never becomes a target Fact and cannot enter CalculationResult or
valuation inputs. Complete means evidence coverage is closed, not that an advantage exists.

## Phase 4C-2 business-model construction

The builder consumes only target-issuer Facts and analytically reviewed Claims. It records the
controlled business attributes carried by each of the eight component types and verifies that
customer, revenue, and cost evidence is present for every declared material scope. Missing core
scope evidence blocks the snapshot; noncritical gaps remain partial; reviewed not-applicable
Claims prevent synthetic components. The output is descriptive and cannot express a score,
quality grade, competitive-advantage status, valuation, or recommendation.

## Phase 4C-3 deterministic mechanism diagnostics

The diagnostics registry binds each calculator primitive to one controlled mechanism role,
polarity, input-role contract, unit rule, period rule, eligible scope, minimum observation count,
and forbidden shortcuts. The only arithmetic primitives are same-unit difference, growth,
same-unit ratio/share, bounded-rate complement, and a registered monetary-per-location measure.

Every result is an assumption-free `CalculationResult` whose fingerprint includes its target
Facts, FiscalPeriods, typed input-role bindings, calculator version, and source-code hash. A
segment diagnostic must prove each period's Fact assignment through its corresponding
`SegmentSnapshot`; product-market Facts without a deterministic mapping fail closed. External
`ContextObservation` evidence remains outside calculations. Intellectual-property, regulatory-
license, and data-uniqueness roles remain direct-evidence or blocked rather than receiving
invented numeric proxies. Valuation concepts, including NOPAT, invested capital, ROIC, economic
profit, and DCF, are rejected.

## Phase 4C-4 reviewed Claims and hypothesis resolution

A language model can produce only an `AnalyticalClaimCandidate`. A named human decision over the
exact Candidate fingerprint and evidence-graph hash is the sole production path to a `Claim`.
The promoted Claim reproduces the reviewed statement, target-company Fact support,
counterevidence search, confidence, and falsification boundary; later edits invalidate the graph.

`resolve_competitive_advantage_hypothesis` does not accept a status. It rechecks mechanism roles,
polarity, target and external source provenance, cutoff dates, scope mapping, reviewed positive
Claims, every reviewed counter Claim and disposition, and forbidden single-indicator shortcuts.
The fixed priority is blocked, falsified, contested, supported, then proposed. ContractGraph
recomputes the same state so a caller cannot bypass the resolver by constructing a contract
directly. Comparable predecessors retain their counterevidence, while trend remains unknown unless
a reviewed strengthening, stable, or eroding Claim matches the same mechanism and scope.

## Phase 4C-5 Review and shadow closeout

`build_business_quality_review` selects the latest eligible exact-scope competitive context,
business model, and hypothesis for every mechanism at the cutoff. It recomputes material-component,
hypothesis, trend, confirmed-Claim, and unresolved-counterevidence coverage. A caller cannot make a
blocked graph complete by editing coverage or status. Complete means the evidence loop is closed;
it explicitly permits zero supported hypotheses and carries no company grade or investment result.

Amazon, Salesforce, and Union Pacific acceptance shadows are fixed at `2026-07-11`. They retain
official SEC filing identifiers, metadata-tuple hashes with an explicit hash scope, expected scope
boundaries, formal object IDs, status counts, blocked reasons, and a RunManifest. When the formal
promotion chain is unavailable, object IDs remain empty and the shadow stays blocked. The files
contain no raw filing content, Facts, Claims, scores, market prices, valuation, target prices,
recommendations, reports, PDFs, or Publisher output.

## Phase 4D-0 capital-allocation contract boundary

```text
official SourceDocument -> EventCandidate -> human ReviewDecision
    -> economic-event key -> versioned Event -> evidence-state Outcome
    -> source and event-type coverage Review
```

The event key excludes accessions and repeated disclosure dates except where a registered identity
policy explicitly requires an announcement, approval, or declaration date. Same-key versions form
a contiguous chain and retain confirmed evidence. Fact and result bindings carry registered roles
with unit-family and currency gates. Missing results remain not disclosed or blocked; they do not
become zero, a red flag, or a value-destruction conclusion. This layer has no production intake,
compiler, evaluator, Review builder, score, valuation, or publishing dependency.

## Phase 4D-1 capital-allocation Event ledger

```text
official filing or issuer IR -> exact source span -> EventCandidate v2
    -> human ReviewDecision -> deterministic compiler
    -> one economic-event key -> contiguous Event versions
```

The filing selector retains all eligible lifecycle filings through the cutoff. Candidate
construction verifies official authority, content hash, locator, policy identity, dates, source
role, and role-typed Facts. A language model may propose a Candidate but cannot confirm or compile
it. Confirmed Decisions cover the exact Candidate fingerprint.

The compiler groups repeated official disclosures by economic identity, rejects conflicting
issuer/scope/announcement semantics, retains predecessor review Decisions, derives lifecycle from
registered source and Fact roles, and returns the existing Event on an identical replay. Candidate
v1 cannot be migrated by inference. Cash-deployment bridges, Outcomes, Reviews, and Shadows remain
outside Phase 4D-1.

## Phase 4D-2 conservation bridges

```text
reviewed Event Fact roles -> closed bridge policy -> unit/period/source gates
    -> assumption-free CalculationResult
```

Nine registered policies reconcile consideration, net proceeds, refinancing, cash-funded debt
repayment, gross-versus-net buyback shares, per-share cash, dividends, and gross liquidity. A
bridge consumes only Facts already bound to the Event and preserves official-source and cutoff
constraints. Missing roles block the calculation rather than becoming numeric zero. This layer
does not emit an Outcome status or a value-creation conclusion.

## Phase 4D-3 deterministic Outcome evaluation

```text
latest Event + policy-complete role evidence + reviewed Claims
    -> official-source / cutoff / unit / calculation gates
    -> code-derived evidence-state CapitalAllocationOutcome
```

The evaluator derives lifecycle and evidence status without accepting a caller-supplied verdict.
Observed roles have exactly one result and a reviewed Claim covering its Facts. Completed official
searches distinguish nondisclosure from blocked evidence, while absence and not-applicable states
require reviewed Claims. Lifecycle Outcomes contain no results. The same Event/window is
idempotent and cannot be rewritten with different evidence.

## Phase 4D-4 Review and shadow closeout

`build_capital_allocation_review` selects the latest cutoff-safe Event per economic key and latest
Outcome per selected Event. It fills every formal source and event-type row, recomputes counts, and
derives complete/partial/blocked. Complete means evidence closure only.

Amazon, Salesforce, and Union Pacific Shadows are fixed at `2026-07-11`. They contain official
metadata tuple hashes, expected event types, formal object IDs, counts, blocked reasons, and a
RunManifest. Missing formal promotion stays blocked; no raw content or investment output is stored.

## Phase 4E-0 validation-only integration contract

```text
validated ContractGraph + caller-supplied ResearchBundle
    -> current-object and material-scope replay
    -> event-driven freshness
    -> module artifact + source graph + dependency closure hashes
    -> component-lock and RunManifest output-hash gate
    -> valid complete / partial / blocked envelope
```

The Bundle references seven research-module types and copies no Fact, Claim, calculation, or
narrative conclusion. Every module except footnotes and business quality has exactly one reference;
business quality has exactly one reference for every material scope in the current business model.
The latest eligible module wins even when partial or blocked, and tied latest objects fail closed.

The dependency closure excludes RunManifest to avoid circular hashing. Score, Assumption,
valuation, market-price, target-price, recommendation, ReportSpec output, Publisher, and Legacy
runtime dependencies are rejected. Phase 4E-0 validates only and contains no production Bundle
builder or integration entry point.

## Phase 4E-1 deterministic Bundle construction

```text
validated pre-Bundle ContractGraph + explicit RunManifest ID
    -> policy-owned current module and material-scope selection
    -> deterministic references, freshness, status, and hashes
    -> immutable ResearchBundle
    -> immutable RunManifest with Bundle output hash
    -> full ContractGraph replay
```

`build_research_bundle` accepts no caller-authored derived fields. It returns both objects without
mutating or persisting the input graph. Equal latest objects become blocked references, existing
RunManifest outputs are preserved, and unchanged semantic inputs replay to the same Bundle ID and
fingerprint. A conflicting existing Bundle is rejected. Phase 4E-1 adds no CLI, orchestration,
Shadow, valuation adapter, score, report, Publisher, release tag, or marketplace update.

## Phase 4E-2 deterministic artifact closeout

```text
validated ContractGraph -> build_research_bundle
    -> canonical Bundle/RunManifest bytes
    -> staged and fsynced directory
    -> atomic publish
    -> strict reload -> full ContractGraph replay
```

The public materialization surface writes exactly `research-bundle.json` and `run-manifest.json`.
It rejects symlink path components, unrelated entries, implicit overwrite, partial pairs,
noncanonical JSON, fingerprint drift, component-lock mismatch, and graph-inconsistent replay.
Identical writes are idempotent.

Complete, partial, and blocked synthetic graphs prove the status gates end to end. Freshness uses
the selected module's transitive evidence-publication watermark, while a newer qualifying source
without a corresponding module update makes the Bundle stale rather than selecting an older
complete module. Metadata-only company Shadows remain boundary evidence and are never fabricated
into complete integration graphs. Phase 4E-2 adds no CLI, orchestration, valuation, scoring,
reporting, PDF, Publisher, or marketplace surface.

## Phase 5B price-blind mapping boundary

The accepted Phase 5B implementation strictly reloads the canonical Bundle/RunManifest pair and
replays its ContractGraph before compiling registered official-source raw Facts and registered
single-quarter/TTM derived Facts into an in-memory, price-blind FactLedger payload. Company routing
and McKinsey/Penman readiness remain separate and do not claim complete valuation-request data.

## Phase 5C-0 accounting and equity-bridge policy boundary

```text
strict Bundle/graph reload + fresh Phase 5B replay
    -> closed accounting and evidence policies
    -> immutable internal decision/result shapes
    -> Phase 5C-1 implementation boundary
```

Phase 5C-0 fixes a common-equity perimeter, separates balance-sheet non-common claims from the
financial and non-common-equity claims used in NFO, and defines same-date NOA/NFO/common-equity and
period-aligned clean-surplus checks with explicit six-component owner-transaction coverage. It
closes accounting-quality disposition, base MethodView targets, the later nine-role bridge target
fragment, per-method root/economic-claim de-duplication, registered cross-method sharing, and
closed-set successor-readiness policies.

Formula inputs are represented by closed role bindings with reviewed non-common-claim inclusion
proof. Accounting, MethodView, diluted-share, and bridge conservation all expand derived aliases to
ultimate raw roots and deterministic exact-disclosure identities. A versioned, code-SHA-bound
zero-Assumption calculator replays monetary method adjustments, while every modeled bridge item is
a derived aggregate that replays the deterministic sum of evidence frozen before the bridge stage;
official absence accepts only raw numeric zero evidence.

The internal envelopes canonicalize the fixed FactLedger shape and bind issuer/cutoff before any
policy result can exist. Account candidates, registered formula outputs, six owner-flow inputs,
quality Review Finding coverage, MethodView targets and consumption records, bridge evidence, and
successor dependency states must replay their upstream objects exactly. Reconciliation arithmetic
is recomputed from role bindings; quality decisions bind Finding fingerprint/status/severity; and
MethodView rejects self-targeting roots plus duplicate category-target or group-target keys. This is
validation-only:
no Phase 5C-1 evidence selection or accounting compiler is present.
The readiness envelope binds complete typed stable-capital evidence rather than placeholder IDs.
It also records the pinned kernel's global accounting-quality route effect separately from the
project's method-specific readiness, so an incompatible future execution fails before market access.
The exact-head verifier allows only the two Phase 5C policy modules to be newly present beneath the
research package, so an unexported compiler or writer cannot bypass the stop boundary.

The fixed kernel is only a future compatibility oracle through an explicit public allowlist.
Phase 5C-0 imports no kernel code in production and creates no compiler, valuation artifact,
market access, assumption, request/result, Score, report, PDF, or Publisher surface.

## Phase 5C-1 deterministic accounting reconciliation

```text
canonical ResearchBundle + RunManifest + complete ContractGraph
    -> replay Phase 5B FactLedger mapping and method readiness
    -> select current registered official accounting Facts
    -> classify every account root once
    -> derive common equity / adjusted liabilities / NOA / NFO / invested capital
    -> close all six owner-transaction components
    -> recompute balance sheet / NOA-NFO identity / clean surplus
    -> validate FactLedger shape and accounting checks against the pinned kernel interfaces
```

`compile_accounting_reformulation` is an internal, keyword-only, in-memory entrypoint. The caller
cannot select Facts, reporting currency, classifications, statuses, control differences, or
outputs. Mixed accounts and non-common equity claims require an exact, named-human reviewed Claim
and Decision; aggregate and component representations cannot coexist in one role. Beginning and
ending common equity must align with the attributable-to-common comprehensive-income period, and
all six registered owner-transaction components must be present. A residual may be reported only
as blocked or by-construction evidence and never becomes a plug or an independent reconciliation.

The compiler does not implement accounting-quality adjustments, MethodViews, the nine-role equity
bridge, successor readiness, assumptions, market access, valuation requests/results, or valuation
math. It does not import the kernel package into the research runtime; a subprocess validates only
the pinned FactLedger shape plus `validate_balance_sheet` and `validate_clean_surplus`.

## Phase 5C-2 accounting-quality and zero-Assumption adjustments

```text
accepted Phase 5C-1 reconciliation + canonical Bundle closure
    -> select the current AccountingQualityReview and every referenced Finding
    -> replay confirmed AnalyticalClaimCandidate / human Decision / Claim chains
    -> derive method-specific quality disposition without inventing severity or absence
    -> compile only registered same-period, single-source, zero-Assumption adjustment amounts
    -> record pinned-kernel global quality-gate compatibility by method
```

`compile_accounting_quality_adjustments` is the second internal, keyword-only, in-memory Phase 5C
entrypoint. It cannot select an older Review, accept a Finding whose evidence is outside the frozen
reconciliation ledger, or treat provisional/blocked evidence as a red flag. Final nonmaterial,
resolved, or material-unresolved semantics require the exact reviewed analytical Candidate and a
named-human Decision whose fingerprint and evidence graph replay at the Bundle cutoff.

Findings never create monetary adjustments. An amount is emitted only when an existing registered
accounting Fact independently meets the category, period, currency, source, root-lineage, and
zero-Assumption calculator policy. Subjective R&D, brand, useful-life, recurring-item, and other
forecast judgments remain excluded for Phase 5D. The pinned kernel is called only in a subprocess
through `AccountingQualityIssue` and `accounting_quality_gate`; the project preserves its separate
McKinsey/Penman method effects and explicitly records any mismatch with that global kernel gate.

Phase 5C-2 adds no public Schema, package-root export, CLI, writer, MethodView, equity bridge,
successor readiness, market access, assumption ledger, valuation request/result, or valuation
execution surface.

## Phase 5C-3 deterministic MethodViews and root conservation

```text
accepted Phase 5C-2 quality ledger
    -> bind each compiled adjustment to its registered method and base target
    -> emit closed McKinsey/Penman MethodView fragments
    -> expand every base and adjustment to reviewed ultimate raw roots
    -> enforce one economic treatment per claim and method
    -> validate FactLedger + MethodAdjustment + MethodView against the pinned kernel
```

`compile_method_views` accepts only the canonical Bundle artifact directory, complete ContractGraph,
and pinned kernel checkout. It reruns the Phase 5C-2 chain instead of accepting caller-authored
adjustments, status, ledger bytes, or roots. McKinsey consumes the invested-capital base; Penman
consumes NOA and NFO as one accounting view. Both methods may share registered roots, but one
method cannot consume the same economic claim through two groups or relabel a named claim to evade
de-duplication. A composite `method_base` Claim may be partitioned only at recorded raw-root
boundaries; named debt, lease, option, pension, or other claims remain indivisible.

The pinned compatibility subprocess constructs only `FactLedger`, `MethodAdjustment`, and
`MethodView` and exercises the affected values and source roots. It never invokes routing, an
AssumptionLedger, an equity bridge, valuation math, request builders, a CLI, or a writer. Phase
5C-3 adds no public Schema or implicit Skill entrypoint.

## Phase 5C-4 deterministic equity bridge

```text
accepted Phase 5C-3 MethodView ledger
    -> select current registered bridge Facts and diluted-share lineage
    -> close exactly nine role decisions
    -> emit only same-source positive derived aggregates
    -> retain official numeric zero and reviewed N/A as non-modeled assertions
    -> replay economic-claim and diluted-share root conservation
    -> validate the enriched FactLedger shape against the pinned kernel
```

`compile_equity_bridge` reruns the complete Bundle-to-MethodView chain and accepts no caller-
selected Fact, role, status, aggregate, source, or count. It never turns search absence or narrative
absence into zero, never treats cash as nonoperating without the registered concept, and never
introduces raw evidence after MethodView freeze. If all roles close without a positive modeled item,
the result retains the rc.1 `kernel_bridge_item_required` limitation instead of fabricating a zero
item. The compiler exposes no package-root, CLI, writer, successor-readiness, market, request/result,
or valuation-execution surface.

## Phase 5C-5 deterministic successor readiness

```text
accepted Phase 5C-4 equity-bridge result
    -> reload the canonical Bundle/RunManifest pair and replay the full ContractGraph
    -> select the exact current typed stable-capital evidence package
    -> recompute six routing assessments from Phase 5C evidence
    -> preserve specialist routing and method-specific accounting gates
    -> emit separate McKinsey and Penman successor-readiness panels
```

`assess_phase5c_readiness` accepts only the canonical artifact directory, complete graph, and
pinned kernel checkout. It reruns the accepted compiler chain, never accepts caller-authored
routing booleans or panel status, and treats ambiguous or incomplete stable-capital evidence as a
method-specific block. `credible_near_term_earnings` remains `pending_phase5d` and
`required_data_complete` remains false. The result therefore authorizes evidence to proceed only
to Phase 5D governance; it is not a complete valuation request, model consensus, or investment
conclusion. The assessor has no package-root, CLI, writer, market, assumption, request/result, or
valuation-execution surface.

## Phase 5D-0 governed assumption boundary

```text
accepted Phase 5C successor readiness + canonical ResearchBundle closure
    + separately hashed PriceBlindReferenceClosure
    -> ValuationAssumptionCandidate 2.0.0
    -> named-human ValuationAssumptionReviewDecision
    -> ValuationHandoff 2.0.0 validation-only state machine
```

The ResearchBundle remains unchanged, target-issuer, and price-blind. Macro, industry-risk, and
owner-hurdle references use an internal immutable closure rather than being inserted into the
research graph or RunManifest. Each Candidate binds exactly one registered downstream assumption
slot and labels every evidence object by domain and role. The supplemental closure accepts only
raw numeric Facts with exact SourceDocument identity; target-security price, market capitalization,
trading multiples, and implied-return evidence are forbidden.

The Handoff root locks the Bundle, supplemental closure, mapping policy, slot/evidence/freeze
policies, component lock, and pinned kernel. Candidate and Decision sets freeze before any input
artifact is frozen. Three protected hashes freeze before market authorization. Every transition is
adjacent and chronological; drift starts a new run and quarantines prior market references.

Phase 5D-0 adds no Candidate compiler, AssumptionLedger compiler, network client, artifact writer,
valuation request/result, kernel import or execution, Score, report, PDF, or Publisher surface.

## Phase 5D-1 deterministic Candidate compilation

The internal `compile_valuation_assumption_candidates` entrypoint strictly reloads the canonical
ResearchBundle/RunManifest pair, replays the complete Phase 5C chain, and accepts only closed
`AssumptionCandidateProposal` objects. It owns Candidate IDs and evidence binding IDs, validates
the method readiness panel, preserves the separately hashed supplemental closure, and inserts the
result into a temporary ContractGraph for replay validation.

The compiler is price-blind and in-memory. It does not confirm a Candidate, reserve a kernel
assumption ID, compile an AssumptionLedger, create scenario inputs, write an artifact, read market
data, or invoke the valuation kernel.

## Phase 5D-2 named-human Decisions and AssumptionLedger

The internal `compile_reviewed_assumption_ledger` entrypoint reloads the same Bundle pair, replays
Phase 5C readiness and the exact Candidate compilation context, and accepts only immutable review
requests whose reviewer identity starts with `human:`. The resolver owns Decision IDs and reserved
kernel assumption IDs; stale fingerprints, duplicate slot confirmations, invalid supersession, and
non-confirmed Candidates fail closed.

Only support Facts or mapped deterministic CalculationResults become kernel `source_fact_ids`.
Confirmed supplemental price-blind Facts are deterministically scaled, inserted into an augmented
FactLedger as category `evidence`, and retain document content hashes in SourceRef locators. Claim
and Review objects remain judgment evidence and never become numeric kernel Facts. The compiler
validates only the pinned FactLedger and AssumptionLedger surfaces in an isolated subprocess. It
does not build McKinsey scenarios, Penman inputs, a price-blind artifact, market evidence, a
valuation request/result, or any valuation calculation.

## Phase 5D-3 McKinsey four-scenario inputs

The internal `compile_mckinsey_scenario_inputs` entrypoint replays the complete Phase 5D-2 review
and AssumptionLedger chain. It accepts no caller-selected status, assumption ID, timeline, terminal
value, or steady-state result. Exactly four scenarios are required: `black_swan`, `bear`, `base`,
and `bull`. Every scenario must use the same annual periods and contain exactly one confirmed
revenue, NOPAT, and ending-invested-capital assumption for each year, plus confirmed WACC,
terminal-growth, terminal-RONIC, terminal-margin, terminal-ROIC, and tolerance assumptions.

The compiler derives the current base invested-capital Fact from the accepted price-blind ledger,
checks unit and terminal-economics identities, and invokes only the pinned kernel's
`ForecastPeriod` and `SteadyStateEvidence` validation surface in an isolated subprocess. It never
calls enterprise DCF, economic profit, reconciliation, equity bridge, request construction, or a
valuation pipeline. Its output is an immutable in-memory reference fragment and replayable
steady-state evidence; no artifact is written and no market data is read.

## Phase 5D-4 Penman price-blind inputs

The internal `compile_penman_price_blind_inputs` entrypoint replays Phase 5D-2 and selects the
current derived NOA/NFO pair from the accepted price-blind ledger. It requires a contiguous annual
near-term sales, after-tax operating-income, and ending-NOA forecast, plus named-human-confirmed
primary hurdle, ordered hurdle/growth grids, long-run growth, and a future sales/NOA challenge
path. No caller may choose IDs, reorder grids, repair periods, or assert readiness.

The compiler uses the pinned kernel only to instantiate `PenmanForecastPeriod` in an isolated
subprocess. It does not call the accounting anchor, residual-income, reverse-price, fade, CAP,
hurdle-comparison, growth-return, or driver-tree functions. Its immutable fragment deliberately
omits `market_equity_value_fact_id`, forces `include_cap_diagnostic` to false, remains invalid as a
complete valuation request, writes no artifact, and reads no target-security market evidence.

## Phase 5D-5 canonical price-blind freeze

The internal `compile_price_blind_input_freeze` entrypoint replays the Phase 5C successor result,
the Phase 5D-2 reviewed FactLedger and AssumptionLedger, and both accepted method-input compilers.
It accepts only a named-human freeze authorization in addition to the existing reviewed inputs;
the compiler derives all Handoff IDs, states, protected hashes, and artifact identity.

`price-blind-input.json` is a closed internal artifact containing the complete nonmarket evidence,
accounting/readiness layer, reviewed assumptions, and McKinsey/Penman input references. The full
fingerprint excludes only itself. Separate protected hashes bind the McKinsey subtree and Penman
assumption/reference subtree. A strict atomic writer persists exactly this one file, while the
loader requires canonical bytes and equality with a freshly replayed freeze result.

The compiler emits four adjacent immutable Handoff versions ending at
`market_reference_allowed`, but it does not access any quote or create a MarketReferenceSnapshot.
It cannot compile a complete kernel request because the Penman market-equity Fact remains absent.
No package-root, CLI, Skill, kernel valuation, request/result, report, or Publisher surface is
added.

## Phase 5E-1 explicit market-access gate

The internal `acquire_governed_market_quote` entrypoint strictly reloads the canonical price-blind
artifact and accepts only the unique current v4 `market_reference_allowed` Handoff. It validates a
single-security decision, immutable Provider registration, and deterministic completed regular
session before it constructs a request. The orchestrator owns both UTC timestamps and invokes the
injected adapter exactly once without retries or fallback.

Eligible responses produce an internal `MarketQuoteRequest` and `MarketQuoteReceipt`. Invalid
responses retain only their SHA-256 and registered issue codes; raw response bytes are never
returned or written by the research core. Phase 5E-1 creates no `MarketReferenceSnapshot`, Fact,
CalculationResult, full request, kernel result, or artifact. The controlled public
`MarketReferenceSnapshot 2.0.0` upgrade belongs exclusively to Phase 5E-2.

## Phase 5E-1.1 authority closeout

The component lock is the sole trust root for market access. It content-addresses the offline
Provider registrations, exact adapter classes, raw-response parser, secret policy, and explicit
2026 XNYS/XNAS calendar datasets. The orchestration accepts no caller registry, parsed quote, or
calendar. It replays an evidence-bound security identity, invokes the exact registered adapter
once, parses raw bytes with the pinned parser, and returns a `GovernedMarketQuoteReceipt` that
binds the legacy receipt to every authority hash. Recorded fixtures remain test evidence only.
Phase 5E-2A may change the existing Snapshot contract; it may not yet compile share basis or
market evidence.
