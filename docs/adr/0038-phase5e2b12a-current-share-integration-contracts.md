# ADR 0038: Phase 5E-2B.1-2A current-share integration contracts

Status: implementation complete pending independent acceptance

Semantic trust-boundary hardening discovered during independent review is governed by ADR 0039.
ADR 0038 remains the original integration decision and is not evidence of final acceptance.

## Context

Phase 5E-2B.1-1 identifies one reviewed legal share event across multiple formal disclosures and
reserves one canonical derived-event Fact ID. It intentionally stops before creating that Fact or
changing current shares. The accepted Phase 5E-2B compiler still consumes raw event Facts, so
coverage, Claim transitions, and recursive lineage need a group-bound successor contract before
production integration can be authorized.

## Decision

Phase 5E-2B.1-2A adds internal immutable records and a content-addressable policy for:

- materializing one canonical event Fact whose direct parents are all and only the corroborating
  raw event Facts;
- consuming each canonical group once in a current-share roll-forward;
- closing all twelve corporate-action categories by canonical group rather than raw Fact;
- applying one reviewed Claim transition per claim-sensitive canonical group; and
- hashing the exact transitive Bundle, numeric, source, temporal, coverage, and transition closure.

The output current-share Fact must have exactly the opening Fact and canonical event Facts as its
direct parents. The ultimate numeric roots must be exactly the opening Fact and every corroborating
raw event Fact. Adding a corroborating source changes the evidence closure but cannot change the
canonical event magnitude or current-share arithmetic.

## Boundaries

This phase exports no package-root, CLI, Skill, writer, builder, compiler, market-evidence,
Snapshot, request, or kernel-execution surface. Production materialization and roll-forward remain
Phase 5E-2B.1-2B; coverage, Claim-transition, and recursive-closure production integration remains
Phase 5E-2B.1-2C. Phase 5E-2C and every later phase remain prohibited.

The 43 public Schemas, market-access authority, and rc.2 kernel identity remain unchanged. The
research package and Plugin advance to dev11; the component lock changes only its generated date
and research-Plugin version. The internal policy and module are verified independently and do not
create a new component-lock authority subtree. Because the component-lock fingerprint changes,
existing price-blind and downstream artifacts are invalid and must never be patched in place.

## Independent oracle

The audit reconstructs a synthetic lineage without invoking a production compiler:

```text
opening current common shares                         100,000,000
one reviewed repurchase group (8-K + 10-Q + IR)       -5,000,000
expected quote-date current common shares              95,000,000
```

The three evidence members must be direct parents of one canonical event Fact. That canonical Fact
must be consumed once. Input-order reversal must preserve fingerprints; adding a fourth consistent
source must preserve 95,000,000 while changing the evidence closure.
