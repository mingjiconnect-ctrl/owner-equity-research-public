# Phase 4E-0 integration policy

`ResearchBundle 1.0.0` is a validation envelope over seven existing research-module types:
quarterly update, segment snapshot, footnote reviews, accounting-quality review, management
review, business-quality reviews, and capital-allocation review.

Each non-business-quality module has exactly one reference; footnotes may contain multiple review
objects. Business quality has exactly one reference for each material scope in the current
`BusinessModelSnapshot`. An unresolved material-scope identity produces one blocked unresolved
reference and a blocked Bundle.

The validator replays these controls:

1. The latest cutoff-safe module is selected; a newer partial or blocked object cannot be replaced
   by an older complete object. Equal latest ordering keys are ambiguous and blocked.
2. Freshness follows policy-relevant source-document watermarks. It never uses a fixed age.
3. The current SegmentDefinition chain must agree across segment and business-quality evidence.
4. Analytical Claims used in business-quality or capital-allocation conclusions require one
   confirmed human `AnalyticalClaimReviewDecision`.
5. Module artifact hashes cover selected module objects. The source graph and dependency closure
   hashes cover only selected modules and transitive dependencies, so unrelated history does not
   change the Bundle.
6. The Bundle identity is derived from issuer, cutoff, and dependency-closure hash. Its semantic
   fingerprint is invariant to input ordering.
7. One same-issuer, same-cutoff `RunManifest` must carry the same component-lock hash and record the
   Bundle fingerprint at `output_artifact_hashes["research-bundle.json"]`.

The policy validates only. There is no public or internal production Bundle builder in Phase
4E-0.
