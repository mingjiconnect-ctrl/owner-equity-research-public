# ADR 0005: Phase 4B-0 management-ledger semantic hardening

Status: accepted for implementation

## Decision

Before any management production pipeline, upgrade `Fact`, `ManagementStatement`,
`ManagementCommitment`, `ManagementOutcome`, and `ManagementReview` to explicit unit, target-role,
result-role, policy, scope, basis, and lifecycle semantics. Historical v1 contracts remain
reproducible at their existing tags; current code does not silently reinterpret them.

Only registered evaluation policies and units are valid. Narrative statements cannot create a
Commitment. Baseline evidence cannot be reused as a target. Withdrawn and superseded commitments
have lifecycle Outcomes and are excluded from ordinary due and missed counts.

## Consequences

Phase 4B-0 contains no network intake, statement extractor, commitment compiler, status evaluator,
management score, valuation, report, or publisher. The next PR implements the official-source and
human-confirmed Statement ledger.
