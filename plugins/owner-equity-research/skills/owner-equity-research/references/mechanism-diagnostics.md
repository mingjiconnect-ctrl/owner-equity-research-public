# Mechanism diagnostics

Use only registered Phase 4C diagnostic policies and `run_diagnostic`.

- Eligible primitives are same-unit difference, same-unit growth, same-unit ratio/share, bounded
  rate complement, and registered monetary-per-location calculations.
- Require exact issuer, unit family, period semantics, scope, input role, observation count, and
  segment assignment. Product-market Facts without a deterministic mapping are blocked.
- Inputs are target-company Facts and FiscalPeriods only. External ContextObservations and
  Assumptions cannot enter a CalculationResult.
- Preserve calculator ID/version, code SHA, typed input bindings, and stable fingerprint.
- Treat intellectual-property protection, regulatory access, and data uniqueness as direct
  evidence or blocked; do not invent a numeric proxy.
- Reject NOPAT, invested capital, ROIC, incremental ROIC, economic profit, DCF, and every
  registered single-indicator shortcut.

A diagnostic is evidence for a reviewed Claim. It never determines a hypothesis status by itself.
