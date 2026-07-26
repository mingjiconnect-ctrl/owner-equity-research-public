# ADR 0006: Phase 4B-1 official-source Statement ledger

Status: accepted for implementation

## Decision

Management language enters the evidence system through `ManagementStatementCandidate`. Candidate
text is bound to an exact normalized source span and hashes. Language-model extraction is allowed
only at this candidate layer.

A named human reviewer records `ManagementStatementReviewDecision`. Only a confirmed decision over
an SEC or explicitly allowlisted issuer-hosted source may emit a `ManagementStatement` and target
Facts. The graph requires one confirmation decision for every human-confirmed Statement and checks
that every target Fact matches the reviewed metric mention.

## Consequences

Raw material stays in the external content-addressed cache and CI remains offline. Phase 4B-1 does
not compile Commitments, evaluate Outcomes, grade management, score, value, report, or publish.
