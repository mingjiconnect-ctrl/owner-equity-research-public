# Phase 4E-2 integration closeout policy

Phase 4E-2 closes the Phase 4 evidence system without adding a downstream research orchestrator.

## Deterministic flow

```text
validated ContractGraph
  -> build_research_bundle
  -> Bundle-bound RunManifest
  -> write exactly two canonical JSON artifacts
  -> reload both artifacts
  -> full ContractGraph replay
```

The complete golden requires every selected module to be complete and current. A later qualifying
source without an updated module produces partial/stale and cannot fall back to an older complete
object. Missing required modules remain blocked through write, reload, and replay.

Artifact writing is idempotent for identical bytes. Changed output requires explicit overwrite and
may replace only an existing safe directory containing exactly the expected pair. Symlink paths,
foreign files, partial pairs, malformed JSON, noncanonical JSON, forged hashes, mismatched component
locks, or graph-inconsistent objects fail closed.

Input ordering and unrelated older sources do not change the Bundle fingerprint. Later
policy-relevant evidence changes freshness or current selection as required by the integration
policy.

This closeout does not expose a CLI, perform network access, build a company Shadow, invoke the
valuation kernel, score, render, publish, or update a marketplace.
