# ADR 0024: Phase 5A valuation-handoff contracts

Status: accepted for Phase 5A implementation

## Decision

Phase 5A adds exactly four long-lived public contracts:

- `ValuationAssumptionCandidate`
- `ValuationAssumptionReviewDecision`
- `MarketReferenceSnapshot`
- `ValuationHandoff`

The contracts are validation surfaces only. They do not select research evidence, compile a
kernel ledger, fetch a quote, create a valuation request, invoke the valuation kernel, or write an
archive. Those capabilities remain assigned to Phase 5B through Phase 5F.

Research assumptions never enter the kernel directly. A price-blind valuation assumption starts
as a Candidate and requires a matching named human Decision. Market evidence remains outside the
Phase 4 ResearchBundle and may appear only after an immutable handoff version authorizes market
reference access.

`ValuationHandoff` is an immutable, versioned reference envelope. It binds the validated
ResearchBundle, the pinned valuation-kernel identity, reviewed assumption candidates, protected
price-blind hashes, and later artifact hashes without copying valuation results. Lifecycle
transitions are one-way. Input drift starts a new run and quarantines market references already
observed by the invalidated run.

## Consequences

- The public contract count increases from 39 to 43 and no fifth Phase 5 contract is permitted.
- The valuation kernel remains fixed at `v2.0.0-rc.1` / `a7dd1528...` with eight locked schemas.
- A complete ResearchBundle is not valuation-ready and does not authorize market access.
- Candidate and Decision validation is distinct from future assumption compilation.
- Phase 5A may validate a supplied market snapshot but cannot acquire one.
- Request/result hashes are lifecycle placeholders until their owning phases verify artifact bytes.

## Rejected alternatives

- Adding readiness, mapping-result, price-blind-input, or valuation-run-manifest public contracts.
- Allowing a language model, management statement, moat hypothesis, or Research Assumption to
  create a kernel assumption.
- Adding market evidence to ResearchBundle or any McKinsey lineage.
- Reimplementing kernel schemas, formulas, routing, or valuation results in this repository.
- Exposing a builder, compiler, network client, CLI command, publisher, or fifth Skill.
