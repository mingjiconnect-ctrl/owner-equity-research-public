# Phase 5 methodology and anti-anchoring boundary

Status: `PROJECT_OPERATIONALIZATION`. This document does not add a valuation method.

## Source fidelity

Method attribution is inherited only from the pinned kernel's verified materials:

- `references/source_manifest.json`
- `docs/methodology/source-audit.md`
- `docs/methodology/fidelity-matrix.csv`
- `docs/methodology/mckinsey.md`
- `docs/methodology/penman.md`

Their identities, SHA-256 values, and verified locators are fixed at kernel commit
`a7dd1528c34f09702686b32ffbb8a397439665f0`. Phase 5 does not create new page citations or
reinterpret project extensions as book prescriptions.

## McKinsey channel

The kernel owns enterprise DCF, economic profit, continuing value, steady-state checks, and the
equity bridge. Phase 5 supplies only reviewed evidence and human-approved assumptions.

- DCF and economic profit consume the same facts, assumptions, adjustments, and forecast path.
- Growth, NOPAT, invested capital, RONIC, reinvestment, and terminal state must remain internally
  consistent through kernel validation.
- Financing rearrangements, distributions, EPS accretion, or leverage do not become operating
  value creation merely because a research Claim says so.
- Market price and all of its lineage are forbidden from the McKinsey channel.

The Phase 5 protected McKinsey hash is calculated from canonical bytes of the full McKinsey
request subtree plus every referenced nonmarket Fact, SourceRef, assumption entry, routing input,
accounting check, method adjustment, and equity-bridge assertion. Adding market evidence must not
change this hash.

## Penman channel

The kernel owns the accounting anchor, residual operating income, reverse price, declining-growth
diagnostic, hurdle comparisons, growth-return profile, and operating driver challenge. Phase 5
does not turn the Penman panel into a second target-price engine.

- Credible near-term sales, after-tax operating income, NOA, hurdle inputs, growth grids, and the
  challenge path are frozen before market access.
- Market price is introduced only after the price-blind input is frozen, and only to challenge
  what the market requires.
- Accounting-anchor and speculative-value outputs remain distinct from the McKinsey value range.
- The panels may disagree. They are never averaged or voted into a synthetic target.

The protected Penman assumption hash covers canonical assumption entries and all nonmarket
forecast/challenge references. The final AssumptionLedger must bind to the augmented FactLedger,
but its assumption-entry bytes must equal the price-blind version exactly.

## Research-to-kernel evidence rules

Research objects preserve evidence semantics; kernel objects preserve deterministic modeling
semantics. The adapter may map but may not blur these domains.

- Research Facts map only through registered concepts. Text, boolean, null, low-confidence,
  future, cross-issuer, or ambiguous-period facts are ineligible.
- Research Claims explain reviewed judgments but never become numeric kernel Facts.
- A deterministic, assumption-free CalculationResult may become a derived kernel Fact only when
  its calculator and every input mapping are registered and replayable.
- Research Assumptions are not kernel assumptions. Only an approved valuation Candidate/Decision
  pair may compile into the kernel AssumptionLedger.
- `explicitly_absent` requires affirmative official evidence. A completed search with no result is
  still not a reported zero.

## Price-blind state machine

```text
evidence_open
  -> price_blind_candidates_reviewed
  -> price_blind_input_frozen
  -> market_reference_allowed
  -> request_compiled
  -> kernel_result_frozen
```

Transitions are one-way for one run. If evidence, mapping policy, an approved assumption, a
protected subtree, component lock, or kernel schema changes, the run is invalidated and returns to
`evidence_open`. Market data already retrieved for the invalidated run is quarantined and cannot
be reused to set replacement assumptions.

The price-blind artifact cannot validate as the kernel `valuation-request.json`, because the pinned
Penman request requires `market_equity_value_fact_id`. Phase 5E creates the first complete request
only after a valid `MarketReferenceSnapshot` exists.

## Project extensions

Candidate review, readiness states, interface registries, protected hashes, market snapshots,
handoff archives, Shadow runs, and owner workflow controls are `PROJECT_OPERATIONALIZATION` or
`PROJECT_EXTENSION`. They must remain labeled and cannot be attributed to either source book.

Phase 5 produces no company-quality grade, Score, recommendation, report, or Publisher output.
