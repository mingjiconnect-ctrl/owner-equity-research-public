# Phase 5A contract specification

Status: implementation contract for `0.5.0.dev1`. This is `PROJECT_OPERATIONALIZATION`, not a
valuation method.

## Assumption review boundary

`ValuationAssumptionCandidate` is numeric and price-blind. It binds one ResearchBundle, one method,
one controlled kernel concept, a unit-safe value and horizon, and typed evidence that is already in
the Bundle dependency closure. McKinsey candidates use one of `black_swan`, `bear`, `base`, or
`bull`; Penman candidates have no scenario. Neither method accepts market evidence.

`ValuationAssumptionReviewDecision` records a named human decision over the exact Candidate
fingerprint and evidence-graph hash. A confirmed Decision reserves one unique future kernel
assumption ID. It does not create an AssumptionLedger entry in Phase 5A.

## Market-reference boundary

`MarketReferenceSnapshot` is representable only after a `market_reference_allowed` Handoff. The
snapshot binds a market-reference SourceDocument, a quote Fact, a price-blind diluted-share Fact,
and an assumption-free CalculationResult that round-trips market equity value. It cannot be added
to ResearchBundle or used by valuation candidates.

## Handoff lifecycle

The only legal same-run state path is:

```text
evidence_open
  -> price_blind_candidates_reviewed
  -> price_blind_input_frozen
  -> market_reference_allowed
  -> request_compiled
  -> kernel_result_frozen
```

Each state is a new immutable Handoff version. A same-run predecessor must be the immediately prior
state and version. Once candidates are reviewed, their identities and Decisions cannot change.
Once the price-blind input is frozen, its fingerprint, protected McKinsey hash, protected Penman
assumption hash, Bundle identity, mapping policy, component lock, and kernel identity cannot change.

A replacement run starts at `evidence_open`, has no same-run predecessor, identifies the Handoff it
supersedes, and records any prior market snapshots as quarantined. Quarantined market evidence may
not enter the replacement run's Candidates.

## Phase boundary

Phase 5A validates caller-supplied contract objects. It does not verify future request/result file
bytes, build a price-blind payload, fetch market data, compile kernel ledgers, invoke the kernel, or
materialize any valuation artifact.
