# ADR 0016: Phase 4D-1 capital-allocation event ledger

Status: accepted for Phase 4D-1 implementation

## Decision

Phase 4D-1 turns the Phase 4D-0 capital-allocation contracts into a narrow production ledger.
Official SEC filings and issuer IR documents may produce source-backed
`CapitalAllocationEventCandidate` objects. A language model may identify a candidate span, but a
machine-readable human `CapitalAllocationEventReviewDecision` is required before deterministic
compilation can create or revise an Event.

Candidate v2 records the reviewed announcement date, execution period, and growth classification.
The compiler derives the economic-event key, deduplicates repeated disclosures, retains reviewed
source and Fact roles, derives lifecycle status, and emits a contiguous Event version chain.
Filing accession and document family remain evidence attributes rather than event identity.

## Consequences

- Same-event 8-K, 10-Q, 10-K, registration, tender, and official-IR disclosures compile into one
  logical Event rather than duplicate transactions.
- A change to reviewed semantics requires a new Candidate and Decision. A stale fingerprint or
  omitted predecessor Decision fails closed.
- Authorization, execution, completion, cancellation, refinancing, and growth classification are
  determined only from registered source and Fact roles.
- Candidate v1 objects are not guessed into v2 because they lack reviewed dates and growth
  semantics; they must be re-reviewed or remain blocked.
- Phase 4D-1 contains no cash-deployment bridge, Outcome evaluator, Review builder, Shadow, score,
  valuation, market-price input, recommendation, report, PDF, or Publisher.

`v0.4.0-alpha.1` remains reserved for Phase 4E.
