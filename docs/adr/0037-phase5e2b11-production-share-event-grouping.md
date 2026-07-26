# ADR 0037: Production cross-source share-event grouping

Status: accepted for Phase 5E-2B.1-1 implementation

## Decision

Phase 5E-2B.1-1 adds one internal, non-exported grouping entry point. It replays a raw completed
share Fact through the cutoff-safe latest CapitalAllocationEvent, its Candidate, and an active
named-human ReviewDecision before deriving a legal event identity. Evidence from different
official sources that describes the same reviewed legal occurrence is retained as corroboration
but produces exactly one canonical group and one reserved derived-Fact ID.

The implementation fails closed when the reviewed chain, exact common-security binding,
incremental execution date, legal identifier, or source agreement cannot be proved. It does not
choose a preferred filing to resolve conflicting amounts. Acquisition and stock-compensation
identities that lack an explicit security-class component remain blocked.

## Boundary

This step does not create a Fact, change the current-share roll-forward, consume coverage
receipts, transition dilution Claims, prove ResearchBundle dependency closure, create market
evidence, build a Snapshot, compile a valuation request, or invoke the valuation kernel. Those
integration duties remain Phase 5E-2B.1-2 or later. Phase 5E-2C remains prohibited.

## Determinism

Fact IDs, SourceDocument IDs, locators, and retrieval timestamps identify evidence members but
never legal events. A canonical identity is derived only from issuer, governed security,
reviewed economic-event identity, reviewed legal identifier, and a single reviewed execution
date. Input ordering is normalized. Adding corroborating evidence changes the group and result
fingerprints, but not the canonical magnitude or reserved derived-Fact ID.
