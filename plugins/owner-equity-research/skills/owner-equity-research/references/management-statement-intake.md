# Management statement intake

1. Normalize the official source and select an exact character span.
2. Create a `ManagementStatementCandidate` with speaker, role, date, statement type, hashes, and
   structured metric mentions. A language model may suggest this candidate but cannot confirm it.
3. Check metric values, units, periods, scope, and measurement basis against the exact span.
4. Require a named human reviewer and machine-readable `ManagementStatementReviewDecision`.
5. A confirmed decision emits one `ManagementStatement` plus target Facts for every confirmed
   metric mention. Blocked and rejected decisions emit neither.
6. Keep statements without measurable metrics as `narrative_only`; do not create a Commitment.

Do not compile Commitments or assess Outcomes in Phase 4B-1.
