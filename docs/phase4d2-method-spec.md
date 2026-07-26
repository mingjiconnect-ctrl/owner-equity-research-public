# Phase 4D-2 capital-allocation conservation-bridge specification

## Boundary

This phase calculates conservation bridges from reviewed Event Facts. A bridge describes how
reported components reconcile; it does not decide whether capital allocation was successful or
value creating.

## Registered policies

`bridge-policy/1.0.0` contains nine policies:

- acquisition and divestiture consideration residuals;
- equity net proceeds;
- incremental debt issued and cash-funded debt repayment;
- buyback net share effect and cash per share repurchased;
- aggregate dividend declared;
- gross liquidity.

Each policy requires its full input-role set. A missing contingent consideration, debt-assumed,
SBC issuance, other issuance, refinancing amount, restricted cash, or marketable-security Fact
blocks the corresponding bridge. An official zero Fact may be used when the issuer actually
discloses zero; absence is not zero.

```text
latest reviewed CapitalAllocationEvent
    + exact role-bound official Facts through cutoff
    -> registered unit and period gates
    -> assumption-free arithmetic
    -> CalculationResult v2 with code/input/output fingerprints
```

Monetary inputs normalize to currency units before arithmetic. Share bridges use shares, and
per-share multiplication/division uses `currency_per_share`. All inputs must share one period;
cross-period or cross-currency arithmetic fails closed. The generated calculation records no
Assumption and cannot consume market price or valuation outputs.

Phase 4D-3 may consume these calculations when evaluating evidence-state Outcomes. It must still
apply result-role coverage, Claim review, lifecycle, comparability, and missing-evidence gates.
