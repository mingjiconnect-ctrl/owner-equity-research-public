# Phase 4D-3 capital-allocation Outcome evaluator specification

## Boundary

This evaluator records the state and completeness of post-Event evidence. It does not determine
whether management created value or whether an investment should be made.

## Evaluation flow

```text
latest reviewed Event
    + complete policy role rows
    + official Facts / deterministic Calculations
    + reviewed analytical Claims
    -> lifecycle and evidence gates
    -> code-derived CapitalAllocationOutcome v2
```

For completed Events, each registered result role must be `observed`,
`none_recognized_after_review`, `not_disclosed`, `not_applicable`, or `blocked`. Observed evidence
uses exactly one Fact or CalculationResult. A partial Outcome requires both observed evidence and
unresolved nondisclosure; an Outcome with only completed-search nondisclosure is unverifiable.
Blocked evidence has priority. The evaluator does not turn missing disclosure into zero or into a
negative conclusion.

Announced or in-progress Events without result evidence remain not due. Cancelled Events and older
same-key Event versions produce cancelled or superseded lifecycle Outcomes. A repeated evaluation
of the same Event/window/evidence returns the existing Outcome; changed evidence for the same
window is rejected.

Result Facts and all transitive calculation inputs must belong to the issuer, use official sources,
fall within the cutoff and observation window, and match the registered result role's unit family.
Per-share calculations cannot be presented as aggregate cash roles. Calculations with Assumptions,
invalid fingerprints, dependency cycles, or future inputs are blocked.

Every observed role is interpreted by a Claim promoted through the exact
`AnalyticalClaimCandidate -> human ReviewDecision -> Claim` chain. Claims explain evidence and
counterevidence but cannot modify the derived status.
