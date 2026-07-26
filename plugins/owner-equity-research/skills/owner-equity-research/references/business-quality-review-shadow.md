# Business-quality Review and shadow

Use `build_business_quality_review`; do not select objects or write coverage counts manually.

- At the cutoff, select the latest exact-scope competitive context, business model, and eligible
  hypothesis for each mechanism.
- Recompute component, hypothesis, trend, confirmed-Claim, and unresolved-counterevidence counts.
- `complete` means evidence coverage is closed. It may contain zero supported hypotheses and must
  never be interpreted as a quality grade or investment conclusion.
- Missing formal objects, incomplete context, blocked material scope, unresolved reviewed evidence,
  or incomplete mechanism coverage remains partial or blocked.
- Acceptance shadows are metadata-only. Keep raw source content outside the repository and store
  only official identifiers, explicitly scoped hashes, formal object IDs, status counts, missing
  evidence, and a RunManifest.
- A hash of an SEC filing metadata tuple must be labeled `official_metadata_tuple`; it is not a
  filing-content hash. If source access cannot be reproduced, fail closed.

Never include Facts, Claims, scores, market prices, valuation, target prices, recommendations,
reports, PDFs, or Publisher output in a shadow file.
