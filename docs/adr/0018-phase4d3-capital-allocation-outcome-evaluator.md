# ADR 0018: Phase 4D-3 capital-allocation Outcome evaluator

Status: accepted for Phase 4D-3 implementation

## Decision

Phase 4D-3 adds a deterministic evaluator for `CapitalAllocationOutcome v2`. The evaluator accepts
one reviewed Event, policy-complete role evidence, official sources, deterministic calculations,
and analytically reviewed Claims. It derives lifecycle and evidence states; callers cannot provide
or override the overall Outcome status.

Observed roles require exactly one Fact or CalculationResult plus a human-reviewed Claim covering
the result Facts. Reviewed absence and not-applicable roles require reviewed Claims. Nondisclosure
requires a completed official-source search, source IDs, a search note, and missing-evidence text.
Blocked evidence requires an explicit reason.

## Consequences

- Status is derived as `not_due`, `observed`, `partial`, `unverifiable`, `blocked`, `cancelled`, or
  `superseded`; no success, failure, or value-created label exists.
- Cancelled Events and superseded Event versions receive lifecycle Outcomes with no result
  bindings.
- Calculations must be deterministic, fingerprint-valid, assumption-free, issuer-consistent, and
  based on official cutoff-safe Facts.
- Claims must reproduce the exact reviewed Candidate/evidence graph, match Event scope, preserve
  counterevidence search and falsification, and cover every observed result Fact.
- One Event/observation window is idempotent and cannot be silently rewritten.
- Phase 4D-3 contains no Review builder, Shadow, score, valuation, market-price input,
  recommendation, report, PDF, or Publisher.

`v0.4.0-alpha.1` remains reserved for Phase 4E.
