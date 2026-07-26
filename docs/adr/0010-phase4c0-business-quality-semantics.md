# ADR 0010: Phase 4C-0 business-quality semantics

Status: accepted for Phase 4C-0 implementation

## Decision

Phase 4C separates target-company evidence from competitive and industry context. Target Facts,
Claims, calculations, and every non-context contract remain single-issuer. External filings and
regulatory or industry sources may coexist in the graph only through `ContextObservation`; they
cannot be relabeled as target-company Facts or enter a `CalculationResult`.

`AnalyticalClaimCandidate` and `AnalyticalClaimReviewDecision` add a human-review boundary without
changing the Phase 1 `Claim` contract. A confirmed analytical Claim must reproduce the reviewed
statement, target Fact support, counterevidence search, confidence, and falsification condition.
Changing the Candidate or its evidence graph invalidates the Decision.

`BusinessModelSnapshot`, `CompetitiveAdvantageHypothesis`, and `BusinessQualityReview` move to
schema version 2.0.0. Complete business-model coverage permits confirmed `not_applicable`
components. Hypotheses bind versioned mechanism roles, counterevidence resolution, scope,
predecessor, and trend evidence. Review coverage is validated from selected objects and never
means that the issuer has a competitive advantage.

## Boundaries

Phase 4C-0 contains no source intake, builder, diagnostic calculator, resolver, shadow run, score,
valuation, report, PDF, Publisher, or persona. The valuation kernel and legacy repository remain
read-only. The Phase 4 release tag remains reserved for Phase 4E.
