# ADR 0015: Phase 4D-0 capital-allocation semantics

Status: accepted for Phase 4D-0 implementation

## Decision

Capital-allocation evidence enters the formal graph only through
`CapitalAllocationEventCandidate -> human ReviewDecision -> CapitalAllocationEvent`.
An economic-event key is derived from the issuer, registered event type and subtype, and the
policy-required identity components. Filing accessions and repeated disclosures are evidence, not
event identity.

Event, Outcome, and Review contracts move to v2. Event evidence is role-bound to its reviewed
Candidate and Decision. Outcome roles distinguish observed results, reviewed absence, non-
disclosure, not-due states, and blocked evidence. Review completeness means official-source,
event, lifecycle, and result coverage closure; it does not mean capital was allocated well.

## Consequences

- Language-model output stops at Candidate.
- Same-key event versions are contiguous and cannot silently delete confirmed evidence.
- Monetary, share, rate, time, and employee roles enforce registered unit families.
- Authorization is not execution; gross repurchases are not net dilution; refinancing is not new
  debt; acquired revenue is not organic growth; EPS accretion is not an outcome verdict.
- Missing impairment, synergy, or execution disclosure remains missing or blocked, never numeric
  zero and never a failure conclusion.
- Phase 4D-0 contains no source intake, Event compiler, Outcome evaluator, Review builder, Shadow,
  score, valuation, market-price input, recommendation, report, PDF, or Publisher.

`v0.4.0-alpha.1` remains reserved for Phase 4E.
