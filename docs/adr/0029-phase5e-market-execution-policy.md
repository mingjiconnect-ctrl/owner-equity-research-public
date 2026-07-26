# ADR 0029: Phase 5E market access, final request, and isolated kernel boundary

Status: accepted for Phase 5E-0 implementation

## Context

Phase 5D freezes every nonmarket Fact, assumption entry, McKinsey input, and Penman challenge
input before target-security price access. The existing Phase 5A market contract does not prove
when the physical request began, does not use `split_basis.factor` in its round trip, and does not
distinguish point-in-time fully diluted shares from the weighted-average EPS denominator.

## Decision

Phase 5E uses five closed internal policies for market quotes, security identity, share basis,
final request assembly, and pinned-kernel execution. Market access must start only after the exact
`market_reference_allowed` transition. Only an official unadjusted close from the latest completed
regular session on or before cutoff is eligible.

The v0.5 alpha path supports one primary traded common share class in the FactLedger reporting
currency. ADR/local aggregation, different-price dual classes, cross listings, multi-security
aggregation, and foreign-currency quotes require a specialist route. Shares must be point-in-time
fully diluted common shares on the quote date. A split factor other than one is not modeled in this
release and therefore fails closed as `specialist_required`.

The final request may append only one market SourceRef, one quote Fact, and one derived
market-equity Fact. Existing Fact bytes, all assumption entries, the price-blind artifact, and both
protected method hashes remain unchanged. Market lineage is forbidden from McKinsey, routing,
accounting checks, MethodViews, the equity bridge, and assumptions.

The pinned kernel is built as a hash-recorded wheel and executed in an isolated subprocess from a
hash-locked local wheelhouse. A research-owned minimal runner carries canonical JSON over
stdin/stdout, disables network access, invokes only public `run_dual_panel`, and preserves the
validated result without editorial changes. The kernel repository itself remains read-only.

## Method boundary

- `MCKINSEY_BOOK_CORE`: market price cannot change the independent operating valuation inputs.
- `PENMAN_BOOK_CORE`: price is introduced only after the accounting anchor and challenge inputs
  are frozen, and is used to challenge market expectations.
- `PROJECT_OPERATIONALIZATION`: request timestamps, provider registration, security/share-basis
  routing, exact hashes, subprocess isolation, and result preservation.

Attribution inherits only the verified source manifest and locators pinned at kernel commit
`a7dd1528c34f09702686b32ffbb8a397439665f0`. This ADR adds no book citation or valuation method.

## Consequences

Phase 5E-0 remains policy-only. It exposes no market client, Snapshot builder, request compiler,
kernel invocation, artifact writer, Score, target, recommendation, report, PDF, or Publisher.
Phase 5D artifacts and the four public Phase 5 contracts remain unchanged.
The accepted Phase 5P interface and failure matrices also remain byte-identical; Phase 5E records
its additional strategies and failure IDs in versioned overlay matrices.
