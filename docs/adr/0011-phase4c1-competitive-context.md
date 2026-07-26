# ADR 0011: Phase 4C-1 competitive-context intake

Status: accepted for Phase 4C-1 implementation

## Decision

Competitive context uses explicit issuer or authority host allowlists, a required caller identity,
HTTPS-only retrieval, a maximum of ten requests per second, redirect revalidation, and a
content-addressed cache outside the repository. SEC retrieval continues through the existing SEC
client rather than the general context client.

Only deterministic or manual exact-source review can create a confirmed `ContextObservation`.
Language-model output cannot cross that boundary. `build_competitive_context_snapshot` covers all
thirteen context topics, requires an analytical competitor-selection Claim, and fails closed when
the competitor set or a critical product-market topic is unresolved. Complete context requires
both target-company primary evidence and an independent competitor, regulator, or audited-industry
source.

## Boundaries

This slice does not build a BusinessModelSnapshot, diagnose a mechanism, resolve a Hypothesis,
run a live shadow, score a company, value a security, or publish a report.
