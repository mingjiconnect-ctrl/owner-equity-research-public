# Phase 5E-0 market, final-request, and kernel-execution policy

Status: `PROJECT_OPERATIONALIZATION`

## Anti-anchoring access order

An eligible request records the exact v4 Handoff, its transition timestamp, a registered provider
identity, endpoint, security identity, requested price basis, and request-start timestamp. The
request cannot start before authorization. A successful receipt also records retrieval time,
completed session identity, exact decimal quote, and raw-response hash.

Only the official unadjusted close for the latest completed regular trading session on or before
the data cutoff is eligible. Adjusted close, intraday, after-hours, VWAP, stale, halted, incomplete,
or future observations are blocked.

## Security and share basis

The alpha path supports exactly one primary listed common share class and requires quote currency
to equal the FactLedger reporting currency. ADR ratios, cross listings, differently priced share
classes, multi-security aggregation, and cross-currency structures are `specialist_required`.

Market equity uses point-in-time fully diluted common shares measured on the quote date. The EPS
weighted-average denominator and basic shares are not substitutes. Corporate actions, options,
convertibles, issuance, and repurchases require formal evidence and deterministic lineage. The
alpha policy permits only split factor one; non-one factors fail closed rather than being ignored.

## Final request and kernel boundary

The final request adds exactly one market SourceRef and two Facts: the quote and derived market
equity. Existing facts and assumption entries remain canonical-byte identical. Only the
AssumptionLedger FactLedger binding changes. The price-blind artifact and protected McKinsey and
Penman assumption hashes do not change.

Kernel execution uses only the wheel built from the fixed tag and commit, verifies the package and
eight Schema hashes, installs from a hash-recorded local wheelhouse, disables network access, and
passes canonical JSON through an isolated subprocess. Research validates and preserves output; it
does not recompute, round, relabel, omit, select, or average kernel results.

Phase 5E-0 defines types and registries only. Production access begins no earlier than Phase 5E-1.
The accepted Phase 5P matrices remain immutable; Phase 5E adds only the versioned overlays in
`phase5e-interface-matrix.json` and `phase5e-failure-mode-matrix.json`.
