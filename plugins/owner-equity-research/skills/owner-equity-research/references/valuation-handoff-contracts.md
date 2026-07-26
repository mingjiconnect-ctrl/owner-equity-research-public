# Phase 5A valuation-handoff contracts

Phase 5A exposes four validation-only public contracts: `ValuationAssumptionCandidate`,
`ValuationAssumptionReviewDecision`, `MarketReferenceSnapshot`, and `ValuationHandoff`.

The ResearchBundle remains price-blind. A language model or management statement may support a
Candidate, but only a named human Decision may reserve a future kernel assumption identity. Market
evidence is representable only after the immutable handoff lifecycle reaches
`market_reference_allowed`. The market snapshot must bind an exact quote Fact, a price-blind
diluted-share Fact, and an assumption-free CalculationResult that round-trips market equity value.

This reference does not authorize building a handoff, compiling a FactLedger or AssumptionLedger,
fetching a quote, creating a valuation request, invoking the valuation kernel, or writing valuation
artifacts. Phase 5A only validates caller-supplied contract objects and fails closed on evidence,
identity, cutoff, state-transition, or protected-hash conflicts.
