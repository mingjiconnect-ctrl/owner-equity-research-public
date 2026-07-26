# ResearchBundle contract, builder, and artifact pair

Phase 4E-0 defines `ResearchBundle 1.0.0` as an integration envelope. It references
the current quarterly, segment, footnote, accounting-quality, management, business-quality, and
capital-allocation modules; it never copies their Facts, Claims, calculations, or conclusions.

Phase 4E-1 adds `build_research_bundle(graph, *, run_id)`. The builder selects every current object
and material scope, computes freshness and hashes, and returns the Bundle plus the matching
RunManifest with its output hash bound. The caller supplies neither module choices nor derived
fields. Insert both returned objects into the same graph and run `ContractGraph.validate()` to
replay current-object selection, material scopes, event-driven freshness, dependency and source
hashes, component lock, and the matching RunManifest output hash. A newer partial or blocked module
cannot be replaced by an older complete object. `complete` means integration coverage closed, not
that the company is high quality or investable.

Phase 4E-2 adds `write_research_bundle_artifacts` and `load_research_bundle_artifacts`. The writer
accepts only a graph-validated builder result, writes exactly canonical `research-bundle.json` and
`run-manifest.json` through a staged atomic directory rename, rejects symlink paths and unrelated
entries, and requires explicit safe overwrite for changed artifacts. The loader requires exactly
the same pair, canonical serialization, matching fingerprints and component lock, and a successful
ContractGraph replay. Identical writes are idempotent.

Do not expose an integration CLI, start orchestration, fabricate full company integration graphs
from metadata-only Shadows, create a valuation handoff, score, report, or publish. A complete Bundle
means integration evidence closure only.
