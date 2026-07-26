# Phase 5D-0 valuation-assumption governance

This reference describes validation-only contracts. It is not an implicit valuation workflow.

- `ValuationAssumptionCandidate 2.0.0` binds one closed assumption slot and typed evidence roles.
- Issuer evidence stays in the ResearchBundle closure.
- Macro, industry-risk, and owner-hurdle evidence stays in a separate internal price-blind closure.
- Only a named human may confirm a Candidate through `ValuationAssumptionReviewDecision`.
- `ValuationHandoff 2.0.0` enforces adjacent chronological transitions and immutable policy,
  component, kernel, Candidate, Decision, and protected-hash state.

Never read or infer the target security's price, market capitalization, trading multiple, implied
return, or implied beta before `market_reference_allowed`. Phase 5D-0 exposes no Candidate builder,
AssumptionLedger compiler, price-blind artifact writer, market client, valuation request, kernel
execution, report, Score, or Publisher.
