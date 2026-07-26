# ADR 0025: Phase 5B deterministic FactLedger mapping boundary

Status: accepted for sequential Phase 5B implementation

## Decision

Phase 5B maps only cutoff-safe evidence already present in a strictly reloaded ResearchBundle and
its matching complete ContractGraph. It uses closed source, concept, unit, period, and calculation
registries. It does not infer a valuation input from a Bundle ID, perform fuzzy concept matching,
manufacture an FX conversion, or convert a Claim or management statement into a numeric Fact.

The adapter reads the pinned `fact-ledger.schema.json` from an explicit checkout of
`owner-valuation-kernel` at `a7dd1528c34f09702686b32ffbb8a397439665f0`, verifies its SHA-256,
and emits a canonical internal payload. It never copies or imports the kernel's valuation code.

Phase 5B readiness means evidence readiness for Phase 5C. McKinsey and Penman are assessed
separately. A specialist route is a fail-closed applicability result, not a substitute valuation.

## Consequences

- The 43 public research Schemas remain unchanged.
- Raw research Facts require empty lineage; derived kernel Facts come only from registered,
  assumption-free CalculationResults with replayable parents.
- Phase 5B assigns no equity-bridge role. Phase 5C owns all nine role assertions and accounting
  adjustments.
- No market source, AssumptionLedger, request, result, kernel invocation, Score, report, PDF, or
  Publisher enters this phase.
