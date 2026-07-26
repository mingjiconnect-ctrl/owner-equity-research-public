# ADR 0021: Phase 4E-1 deterministic ResearchBundle builder

Status: accepted for Phase 4E-1

## Decision

Phase 4E-1 exports one production function, `build_research_bundle(graph, *, run_id)`. It accepts
no caller-authored module selection, scope, freshness, status, hash, or missing-evidence controls.
It reuses the Phase 4E-0 selection and validation policy, constructs one `ResearchBundle 1.0.0`,
and atomically returns the matching RunManifest with
`output_artifact_hashes["research-bundle.json"]` set to the Bundle fingerprint.

The builder first validates the source ContractGraph without Bundle objects. It then derives
current module references, material business scopes, event-driven freshness, module artifacts,
the source graph, dependency closure, Bundle identity, component lock, status, and missing
evidence. Finally, it validates the constructed Bundle in a complete ContractGraph replay.

## Boundaries

- Equal current candidates fail closed as a blocked module reference with no selected object.
- A newer partial or blocked object is never replaced by an older complete object.
- Replaying an unchanged graph is idempotent; a conflicting existing Bundle is rejected.
- Existing RunManifest output hashes are preserved while the Bundle binding is added.
- No source intake, persistence, CLI, orchestration, Shadow, score, valuation handoff, market
  price, report, PDF, Publisher, release tag, or marketplace update is added.

Phase 4E-1 creates no release tag. Phase 4E-2 remains a separate closeout and release plan.
