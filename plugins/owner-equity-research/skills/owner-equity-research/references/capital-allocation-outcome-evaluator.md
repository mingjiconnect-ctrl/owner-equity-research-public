# Capital-allocation Outcome evaluator

Use this reference only after Event identity/lifecycle and any required conservation bridge have
passed their gates.

1. Provide every registered result role for the Event type. Do not provide an overall Outcome
   status; code derives it.
2. Bind an observed role to exactly one official Fact or deterministic, assumption-free
   CalculationResult within the observation window and cutoff.
3. Require a human-reviewed analytical Claim covering the Facts behind every observed result.
   Claims explain evidence but cannot change arithmetic or status.
4. Use `not_disclosed` only after a completed official-source search with source IDs, a search note,
   and missing-evidence text. Use `blocked` for unresolved source, scope, period, unit, currency,
   calculation, or review conflicts.
5. Let code derive `not_due`, `observed`, `partial`, `unverifiable`, `blocked`, `cancelled`, or
   `superseded`. Missing disclosure is not zero and not failure.
6. Preserve idempotency for the same Event and observation window; changed evidence requires a new
   assessment window rather than silent rewriting.

Do not create a success/failure or value-created label, build a CapitalAllocationReview, run a
Shadow, score capital allocation, use market prices, value the issuer, recommend an investment,
render a report/PDF, or invoke a Publisher.
