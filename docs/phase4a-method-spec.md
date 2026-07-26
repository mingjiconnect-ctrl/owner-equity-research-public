# Phase 4A method specification

## Scope

Phase 4A defines evidence contracts and validation policy only. It covers general US-GAAP
nonfinancial issuers and consumes Phase 1-3 evidence. It contains no production evaluator.

## Business quality

`BusinessModelSnapshot` partitions disclosed evidence into customer, value proposition, revenue
model, cost structure, distribution, key resource, key partner, and regulatory dependency
components. Segment-specific components bind existing `SegmentDefinition` identifiers; no second
fact ledger is created.

`CompetitiveAdvantageHypothesis` uses exactly one controlled mechanism and keeps the core,
durability, reinvestment, and counterevidence Claims distinct. `supported` requires official
evidence for all positive roles. `contested` and `falsified` require separate counterevidence
Claims. `BusinessQualityReview` records coverage of all ten mechanisms and never emits a score or
company-quality label.

## Management

`ManagementStatement` preserves speaker, role, date, official source locator, exact text hash,
extraction method, human-confirmation state, and KPI-definition lineage. `ManagementCommitment`
records a measurable target, baseline, term, and versioned evaluation policy only after statement
confirmation. `ManagementOutcome` evaluates a unique period after respecting the due date and
references observable result Facts, deterministic calculations, and Claims.

## Capital allocation

`CapitalAllocationEvent` de-duplicates announcements and later disclosures with a deterministic
issuer-scoped event key. It records announced and executed amounts, financing, share/debt/cash,
goodwill/intangible and SBC effects, and confirmed management rationale without labeling value
creation. `CapitalAllocationOutcome` preserves distinct result roles and uses only pending,
observed, partial, unverifiable, or blocked states. `CapitalAllocationReview` reports evidence
coverage, not a score or valuation conclusion.

## Forbidden dependencies

Phase 4A objects cannot consume Score, valuation, target price, recommendation, ReportSpec
output, PDF, or Publisher. Facts, Claims, Assumptions, calculations, and the valuation kernel
cannot depend on Phase 4A contracts. Any calculation referenced by Phase 4A must be deterministic
and free of direct or transitive Assumption inputs.
