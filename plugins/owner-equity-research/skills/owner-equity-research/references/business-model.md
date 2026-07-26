# Business-model snapshot

Use `build_business_model_snapshot`; do not hand-construct a completed snapshot.

- Derive material scopes from the latest eligible `FiscalPeriod`, `SegmentDefinition`, and
  `SegmentSnapshot` at the cutoff. Never accept caller-declared material scopes.
- Treat each reportable segment as a separate material scope. Issuer-wide scope is permitted only
  for a single reportable segment. A product-market scope requires an exact-scope reviewed
  materiality Claim.
- Review customer, value proposition, revenue model, cost structure, and distribution separately
  for every material scope. Key resources, key partners, and regulatory dependencies can be shared
  only through an explicit reviewed shared-scope relation.
- Bind every attribute to a confirmed analytical Candidate, its human ReviewDecision, the promoted
  Claim, and supporting target-company Facts. Do not relabel evidence after review.
- Only key partner and regulatory dependency may be not applicable. A partial or blocked segment
  universe blocks the snapshot when it cannot prove scope completeness.

The result is descriptive evidence coverage. It is not a company grade, moat conclusion,
valuation input, report, or recommendation.
