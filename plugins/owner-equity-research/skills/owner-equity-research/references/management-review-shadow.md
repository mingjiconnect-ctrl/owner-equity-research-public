# Management Review and shadow

Build a `ManagementReview` from all issuer objects available at the cutoff. Select commitments that
overlap the review period, their source Statements, and the latest eligible Outcome per Commitment.
Recompute every coverage field in code. Active due Commitments require a final Outcome; lifecycle
Commitments require a matching withdrawn or superseded Outcome.

Use `complete` only when every due active Commitment is evaluable and no selected Outcome is
blocked or unverifiable. Use `partial` for bounded missing evidence such as an unverifiable official
result. Use `blocked` when the review lacks required Statements, Claims, lifecycle closure, or a
final due Outcome. Never convert missing evidence into a negative management judgment.

The fixed `2026-07-11` Salesforce and Amazon shadows are explicit acceptance runs. Store only
official source identifiers, scoped evidence hashes, object IDs, coverage, blocked reasons, and a
`RunManifest`. Raw source content stays outside the repository. Do not generate a report, score,
valuation, target price, recommendation, PDF, or Publisher output.
