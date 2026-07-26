# Phase 5B mapping and readiness policy

Status: Phase 5B accepted/closed `PROJECT_OPERATIONALIZATION` for `0.5.0.dev2`.

## Inputs

Compilation requires the canonical `research-bundle.json` and `run-manifest.json` pair, the full
ContractGraph that replays the Bundle dependency hash, the repository component lock, and an
explicit checkout of the pinned valuation kernel. A Bundle without its graph is never sufficient.

The compiler selects evidence from the dependency closure. Callers cannot provide a Fact allowlist,
reporting currency, mapping status, or readiness status. Derived mapping is limited to registered
quarterly single-quarter/TTM outputs with replayed fingerprints and a single official-source
lineage. The internal readiness entrypoint additionally requires the exact ResearchBundle and
updated RunManifest to be present in the validated ContractGraph; it does not accept caller-authored
classification, route, role coverage, or status.

## Registered mapping

The `research-to-kernel-fact-mapping/1.0.0` registry controls:

- official source eligibility and deterministic SourceRef identity;
- exact concept, category, origin, scope, method, and unit-family mappings;
- auditable scale conversion to reporting-currency millions, millions of shares, or decimals;
- stock and flow measurement-date rules;
- assumption-free CalculationResult identity, code, lineage, and output eligibility.

No publication date is a measurement date. An amended filing displaces an earlier filing only when
the current FiscalPeriod or QuarterlyReconciliation establishes the version relationship. Other
same-period conflicts are blocked.

## Readiness

Readiness states are `ready`, `partial`, `specialist_required`, and `blocked`. The priority is
blocked integrity, specialist applicability, partial Phase 5C prerequisites, then ready. A complete
ResearchBundle is only an evidence-closure statement and cannot promote readiness.

The company classification policy uses official classification evidence, current material segment
scope, and human-confirmed evidence for asset-based or distress routes. It never creates numeric
classification flags. `ready` means the mapped evidence may proceed to Phase 5C; it does not mean a
valuation request can be compiled or the kernel can run.

Deterministic priority is unresolved integrity, official bank/insurance identity, multiple material
segment scopes, human-confirmed asset/distress classification, then the core nonfinancial route.
The six future kernel routing assessments remain evidence-bound: Phase 5B never marks
`required_data_complete` or `equity_bridge_complete` true because those controls belong to Phase
5C. McKinsey and Penman role coverage can differ and is never averaged.
