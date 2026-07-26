# Phase 4E-1 Builder policy

The public builder interface is deliberately narrow:

```python
build_research_bundle(graph, *, run_id) -> ResearchBundleBuildResult
```

The result contains exactly the immutable Bundle and the updated immutable RunManifest. Callers
must insert both into the same ContractGraph and validate it before persistence. The input graph is
not mutated.

The builder follows these deterministic steps:

1. Select exactly one same-issuer RunManifest by explicit run ID and validate the full pre-Bundle
   graph.
2. Reuse the Phase 4E-0 current-object, period, restatement, material-scope, carryover, taxonomy,
   and freshness rules.
3. Fail closed on missing or ambiguous modules; retain partial and blocked states rather than
   falling back to older complete objects.
4. Compute module artifact, source graph, dependency closure, Bundle identity, component-lock,
   and semantic fingerprint values from canonical sorted inputs.
5. Preserve existing RunManifest outputs, add the Bundle output hash, and replay full ContractGraph
   validation.
6. Return the same result for the same semantic graph regardless of collection ordering. Reject a
   stale or conflicting existing Bundle.

This phase does not write `research-bundle.json`. Persistence, CLI, Shadow acceptance, and release
packaging are outside Phase 4E-1.
