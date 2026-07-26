# ADR 0023: research-to-valuation boundary

Status: accepted for Phase 5 planning after the Phase 5P PR and main CI pass

## Decision

Phase 5 is an audited adapter to the immutable `owner-valuation-kernel`, not a valuation
implementation. The research repository may map, review, compile, invoke, validate, and archive.
All DCF, economic-profit, continuing-value, accounting-anchor, residual-operating-income,
reverse-price, fade, and driver calculations remain exclusively in the pinned kernel.

The adapter consumes both the strictly reloaded `ResearchBundle`/`RunManifest` pair and the
matching complete ContractGraph. The two-file Bundle artifact is an integrity envelope and does
not contain enough object payload to infer valuation inputs by itself.

The Phase 4 Bundle remains price-blind. Human-approved assumptions and all nonmarket request
inputs are frozen into an internal canonical artifact before market access. Because the kernel's
Penman request requires market equity value, that artifact is explicitly not a valuation request.
The final request is compiled only after a separately governed `MarketReferenceSnapshot` exists.

Phase 5A may add exactly four long-lived public contracts: `ValuationHandoff`,
`MarketReferenceSnapshot`, `ValuationAssumptionCandidate`, and
`ValuationAssumptionReviewDecision`. Readiness, price-blind compiler state, and the valuation run
manifest are internal typed artifacts, not new research evidence domains.

## Consequences

- Research `Assumption` cannot flow directly into the kernel.
- McKinsey and Penman readiness are independent of ResearchBundle completeness and of one another.
- Market evidence may change the final FactLedger fingerprint and its AssumptionLedger binding,
  but cannot change assumption entries or protected McKinsey/Penman nonmarket hashes.
- The adapter fails closed on unregistered concepts, ambiguous evidence, missing bridge roles,
  foreign-currency model inputs unsupported by kernel rc.1, schema drift, or component drift.
- Kernel results are validated and archived verbatim; the research layer does not recalculate or
  editorialize them.
- Method panels remain separate and cannot be averaged.

## Rejected alternatives

- Copying kernel formulas into the research repository.
- Adding market price to ResearchBundle.
- Treating Bundle `complete` as valuation-ready.
- Auto-converting management guidance or moat hypotheses into assumptions.
- Creating a partial kernel request before market access.
- Inventing numeric classification Facts or zero-valued missing disclosures.
- Adding valuation personas, model voting, Score, reporting, or publishing to Phase 5.
