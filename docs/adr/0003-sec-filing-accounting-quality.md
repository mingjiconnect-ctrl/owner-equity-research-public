# ADR 0003: SEC filing, segment, footnote, and accounting-quality vertical slice

Status: accepted for Phase 3

## Decision

Phase 3 supports general US-GAAP nonfinancial issuers filing SEC Forms 10-K and 10-Q. It adds
eight immutable public contracts: `FilingArtifact`, `ExtractionCandidate`, `EvidencePromotion`,
`SegmentDefinition`, `SegmentSnapshot`, `FootnoteReview`, `AccountingQualityFinding`, and
`AccountingQualityReview`.

The existing `Fact` remains the sole research fact ledger. An extraction candidate is never a
Fact. Every candidate disposition produces an `EvidencePromotion`. Only a deterministic
table/iXBRL candidate from a primary SEC filing may be promoted automatically, and only after
source, locator, hash, type, unit, currency, period, duplicate, and reconciliation checks pass.
Language-model output may draft narrative candidates or Claims but cannot create Facts, final
findings, or final severity.

Segment values remain Facts associated with a `SegmentDefinition` by
`SegmentSnapshot.metric_assignments`. Geographic disclosures, customer concentrations,
corporate items, and eliminations are not reportable segments. Comparability mappings are
`exact`, `partial`, or `not_comparable`; missing disclosure is never inferred.

All mandatory footnote topics are represented explicitly by `reviewed`, `not_disclosed`,
`not_applicable`, or `blocked`. Accounting-quality rules produce suggestions only. A final
severity requires an evidence-backed Claim with a falsification condition. Missing evidence is
blocked, not a red flag and not evidence of no risk. No Phase 3 contract contains a score,
valuation, report, PDF, or publisher dependency.

## SEC boundary

The explicit SEC client uses `httpx`, requires `OWNER_RESEARCH_SEC_USER_AGENT`, defaults to five
requests per second, and rejects any configured rate above ten. HTML/iXBRL parsing uses `lxml`.
Raw filings are stored only in a content-addressed cache outside the repository. CI uses small
normalized fixtures and never makes network calls.

## Consequences

Phase 1 and Phase 2 schemas remain backward compatible. `CalculationResult` remains version 2.
The primary research Skill becomes the only implicit Phase 3 entry point; quarterly, audit, and
publish Skills remain explicit, and publish remains an unimplemented shell.
