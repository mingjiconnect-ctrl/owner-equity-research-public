# ADR 0034: Recursive current-share evidence authority

## Status

Accepted/closed for Phase 5E-2A.2.1 under audit `2.3.2.2.1`. This decision is
`PROJECT_OPERATIONALIZATION`; it is not presented as a new McKinsey or Penman method.

## Context

Phase 5E-2A.2 validated the immediate current-share formula, but an immediate parent could still
hide an unauthorized, reserved, potential, future, or low-confidence ultimate root. A completed
event roll-forward also proved only arithmetic over submitted events, not that the activity
window had been completely searched. The registered repurchase concept was misspelled.

These defects share one trust-boundary cause: current shares did not have one code-derived,
recursive, cutoff-safe evidence closure. Because the denominator directly changes market equity
and future per-share value, the boundary must fail closed before any production share compiler.

## Decision

The validation layer derives an immutable `CurrentShareEvidenceClosure` from the exact
`ContractGraph`. Callers cannot submit roots, coverage states, transitions, or final status.

- Direct evidence is a raw, high-confidence, formal, quote-date leaf for the exact common
  security.
- Issued-less-treasury evidence has exactly two raw roots on one date, with no nested aliases.
- A roll-forward starts from a valid direct or issued-less-treasury opening; every event is a raw,
  high-confidence, formal, cutoff-safe leaf for the same security.
- Every activity category closes through observed facts, an official zero fact, or a reviewed
  not-applicable claim, and all eight official source families have completed search receipts.
  Search silence is never converted to zero.
- Completed exercise or conversion events bind a reviewed transition from the affected claim to
  the remaining claim. An extinguished claim cannot remain in the frozen Phase 5C bridge.
- `common_shares_repurchased_completed` is canonical. The legacy `repurched` spelling is an
  explicit negative fixture and is not an alias.

The market-evidence closure now commits to every numeric root, source document, search receipt,
coverage decision, and claim transition. Phase 5E-2A.2.1 remains validation-only and exports no
share compiler, Snapshot builder, market-evidence generator, final-request compiler, kernel call,
writer, CLI, or implicit Skill entry point.

## Consequences

Some apparently balanced roll-forwards will be blocked until official-source search coverage is
complete. That is intentional. Phase 5E-2B may later select or derive quote-date shares only from
this accepted authority; it may not weaken or replace the closure.
