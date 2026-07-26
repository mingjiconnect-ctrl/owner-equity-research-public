# ADR 0020: Phase 4E-0 ResearchBundle validation contract

Status: accepted for Phase 4E-0

## Decision

Phase 4E-0 adds one closed Draft 2020-12 public contract, `ResearchBundle 1.0.0`, and a
validation-only `research-bundle/1.0.0` policy. The Bundle contains references, coverage states,
cutoff-safe scope metadata, deterministic hashes, a component-lock hash, and one RunManifest ID.
It does not copy research facts, calculations, narrative conclusions, scores, or valuation data.

`ContractGraph` validates a caller-supplied Bundle only. It replays current-object selection,
material business scopes, event-driven freshness, the source graph, the complete transitive
dependency closure, component lock, Bundle identity, Bundle fingerprint, and RunManifest output
hash. It always selects the newest eligible object even when that object is partial or blocked.
Ambiguous current objects fail closed.

## Boundaries

- Phase 4E-0 exports no `build_research_bundle`, CLI, orchestrator, Shadow, release, or publisher.
- `RunManifest` is excluded from the dependency closure to avoid a circular hash.
- `Score`, `Assumption`, valuation, market price, target price, recommendation, `ReportSpec`
  output, Publisher, and Legacy runtime are forbidden dependencies.
- `complete` means that evidence coverage and integration gates close. It is not a company-quality
  grade or investment conclusion.
- This contract is `PROJECT_OPERATIONALIZATION`; it is not represented as McKinsey or Penman book
  core.

Phase 4E-0 creates no release tag. Production Bundle construction remains Phase 4E-1 work.
