# ADR 0002: Quarterly vertical slice

Status: accepted for Phase 2 implementation

## Decision

Phase 2 adds a deterministic quarterly module around the Phase 1 evidence contracts. It does not
create another fact ledger. Reported observations remain `Fact`; derived values remain
`CalculationResult`; interpretations remain `Claim`.

Three new public contracts are allowed:

- `FiscalPeriod`: fiscal-quarter, cumulative, TTM, week-count, calendar, comparison, and
  restatement metadata.
- `QuarterlyReconciliation`: deterministic selection and difference record across filings and
  company releases.
- `QuarterlyUpdate`: reference-only quarterly output containing change, cause, durability,
  guidance, thesis-impact, and assumption-review Claim IDs.

## Deterministic calculations

The module must support:

1. YTD or fiscal-year cumulative values converted to a discrete quarter.
2. TTM rebuilt as current YTD plus prior fiscal year minus prior comparable YTD.
3. Per-week growth diagnostics for 52/53-week comparisons, explicitly labeled diagnostic rather
   than GAAP restatement.
4. Regulatory filing versus earnings-release reconciliation and amended-filing precedence.
5. FCF as operating cash flow minus positive capital-expenditure outflow.
6. SBC/revenue, diluted-share change, lease-liability change, and working-capital change.
7. FX, acquisition, price, and volume bridge residuals only when every required component exists.
8. Comparability status driven only by explicit evidence Facts, never by an unstated model guess.

Every calculation must use the Phase 1 deterministic constructor, include source identifiers,
record calculator and code versions, and pass graph fingerprint validation. FiscalPeriod inputs
and role-to-evidence bindings are first-class calculation inputs: their identifiers and content
fingerprints must change the calculation identity and input fingerprint.

This is a breaking change to `CalculationResult`, so that contract uses `schema_version=2.0.0`.
Phase 1 v1 artifacts remain tied to the immutable Phase 1 tag and require explicit migration;
they are never accepted as v2 without reconstructed period inputs and fingerprints.

QuarterlyUpdate comparability is never trusted as a caller-supplied label. The builder and graph
validator independently recompute it from the update's referenced acquisition, bridge, FX, and
one-time-tax Facts, including their quarter windows. Missing evidence therefore cannot be hidden
behind a manually constructed `comparable` assessment.

Reconciliation declares whether candidate Facts are `single_quarter` or `ytd`, requires an exact
match to that FiscalPeriod window, selects regulatory authority deterministically, and measures
the maximum absolute difference against every other candidate rather than hiding a third-source
conflict.
Candidate Facts and their maximum-delta result must also share numeric type, unit, and currency.
Period-labeled change calculations require a FiscalPeriod input and may use only its exact
quarter or cumulative window.

## Failure policy

Stop or return `blocked` when periods overlap incorrectly, currencies or units differ, cumulative
inputs are missing, a required growth driver is absent, restated and original filings cannot be
reconciled, or acquisition comparability lacks an explicit bridge.

Do not infer missing quarter cash flow, FX, price, volume, acquisition contribution, lease data,
SBC, guidance, or one-time items. Comparability evidence is true/false/unknown: absent explicit
acquisition, FX, or one-time-tax Facts produces `unknown` and blocks completion.

## Explicit exclusions

Phase 2 does not implement segments, footnotes, accounting-quality judgments, business quality,
management, capital allocation, valuation handoff, scoring, target prices, reports, PDF, or
publishing. Qualitative output is expressed only as referenced `Claim` objects supplied by the
research workflow.
