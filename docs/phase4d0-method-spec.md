# Phase 4D-0 capital-allocation method specification

## Boundary

This phase defines replayable evidence and lifecycle semantics. It does not decide whether a
transaction created value and does not calculate NPV, ROIC, valuation, or a score.

## Evidence flow

```text
official SEC or issuer IR SourceDocument
    -> CapitalAllocationEventCandidate
    -> human CapitalAllocationEventReviewDecision
    -> versioned CapitalAllocationEvent
    -> evidence-state CapitalAllocationOutcome
    -> coverage-only CapitalAllocationReview
```

Each Candidate binds one precise source location to a registered source role and zero or more
role-typed Facts. A confirmed Decision covers the exact Candidate fingerprint and deterministic
economic-event key. Multiple official documents describing one transaction retain one key and
become evidence bindings or later Event versions, not duplicate transactions.

`event-policy/1.0.0` closes the thirteen event types, their subtypes, identity alternatives, Fact
roles, and lifecycle evidence. `outcome-policy/1.0.0` closes result roles. Free policies, roles,
subtypes, and identity components are rejected.

Event versions form a contiguous, acyclic chain. A later version retains earlier confirmed
evidence unless a later human Decision explicitly supersedes it. Cross-event supersession is
separate from same-key versioning.

Outcome coverage distinguishes `observed`, `none_recognized_after_review`, `not_disclosed`,
`not_due`, `not_applicable`, and `blocked`. A reviewed absence requires a human-reviewed analytical
Claim. Non-disclosure never becomes zero. Cancelled and superseded Events receive lifecycle
Outcomes, not ordinary operating Outcomes.

CapitalAllocationReview requires explicit coverage of eight formal source families and all
thirteen event types. `not_found` requires completed official-source search evidence;
`not_applicable` requires a reviewed Claim; `blocked` records the missing evidence. Complete means
coverage closure only.

The McKinsey channel contributes the conservation-of-value boundary and separation of operating
performance from financing rearrangements. The Penman channel contributes the operating/financing
separation and the rejection of leverage or EPS growth as operating growth. Candidate review,
economic identity, evidence roles, missing-evidence states, and coverage closure are project
operationalization, not claims that either book prescribes these software contracts.
