# ADR 0022: Phase 4E-2 integration closeout

Status: accepted for Phase 4E-2 after merge, exact-head audit, and tag CI

## Decision

Phase 4E-2 exports deterministic artifact materialization for the existing `ResearchBundle 1.0.0`
and its atomically bound `RunManifest`. The public artifact set is exactly:

- `research-bundle.json`
- `run-manifest.json`

The writer replays the complete ContractGraph before writing, uses canonical JSON, fsyncs staged
files and directories, publishes by directory rename, rejects symlink paths and unrelated entries,
and requires explicit safe overwrite when content changes. The loader requires the exact pair,
revalidates both schemas and hashes, rejects noncanonical serialization, and replays the complete
ContractGraph.

Module freshness uses the latest policy-relevant source publication in each selected module's
transitive dependency closure. This preserves period semantics while preventing an ordinary filing
published after period end from making its own period module permanently stale.

## Boundaries

Phase 4E-2 adds no CLI, network intake, orchestration, company Shadow, valuation adapter, Score,
market-price logic, report, PDF, Publisher, or marketplace update. Existing metadata-only company
Shadows are not promoted into fabricated complete integration graphs.

## Release

The Phase 4 integration release is Python `0.4.0a1`, Plugin/component lock
`0.4.0-alpha.1`, annotated tag `v0.4.0-alpha.1`, and read-only audit `1.7.2`. Phase 5 planning is
authorized only after the PR, main CI, exact-head audit, annotated tag, and tag CI pass.
