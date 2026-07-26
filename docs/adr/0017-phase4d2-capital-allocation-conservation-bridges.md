# ADR 0017: Phase 4D-2 capital-allocation conservation bridges

Status: accepted for Phase 4D-2 implementation

## Decision

Phase 4D-2 adds a closed registry of assumption-free calculations over Facts already reviewed into
the latest capital-allocation Event. The calculations reconcile consideration, financing, cash,
liquidity, dividends, and gross-versus-net share effects. They emit ordinary deterministic
`CalculationResult` objects and create no second capital-allocation ledger.

Every policy fixes the Event type, exact input roles, unit rules, arithmetic operation, output
concept, and output unit. Inputs must have one issuer, one comparable period, one currency where
applicable, official sources within the cutoff, and exact Event Fact bindings. Missing components
block calculation; they are never silently replaced with zero.

## Consequences

- Acquisition and divestiture bridges expose an unexplained residual instead of assuming omitted
  consideration components are zero.
- Refinancing is separated from incremental debt and cash-funded repayment.
- Buyback share effects require repurchases, SBC issuance, and other issuance; gross repurchases
  cannot masquerade as net share reduction.
- EPS, ROE, accretion, stock-price performance, valuation, NPV, ROIC, and DCF concepts are forbidden
  bridge inputs.
- `currency_per_share` is added as a backward-compatible Fact v2 unit.
- Phase 4D-2 contains no Outcome evaluator, Review builder, Shadow, score, valuation, market-price
  input, recommendation, report, PDF, or Publisher.

`v0.4.0-alpha.1` remains reserved for Phase 4E.
