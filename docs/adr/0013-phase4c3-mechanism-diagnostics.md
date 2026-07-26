# ADR 0013: Assumption-free mechanism diagnostics

Status: accepted for Phase 4C-3 development

Mechanism diagnostics use a fixed registry and deterministic arithmetic only. Each policy records
its calculator, mechanism, evidence role, polarity, typed input roles, unit semantics, period
semantics, eligible scope, minimum observation count, and forbidden shortcuts. Results retain
exact Fact and FiscalPeriod bindings, code hash, calculator version, and stable fingerprints.
External ContextObservations never enter CalculationResult, product-market Facts without
deterministic scope mapping fail closed, and direct-only evidence roles remain uncalculated.

Segment calculations require one applicable SegmentSnapshot for each input period and prove that
each input Fact is assigned to the declared reportable segment. This prevents an issuer-wide Fact
from silently becoming segment evidence and prevents cross-period growth from using only the
current-period segment mapping.

The registry forbids NOPAT, invested capital, ROIC, incremental ROIC, economic profit, and DCF so
the research repository cannot create a second valuation model.
