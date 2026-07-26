# ADR 0035: Phase 5E-2B quote-date current-common-share compiler

## Status

Accepted for Phase 5E-2B implementation.

## Decision

Phase 5E-2B adds one internal deterministic compiler that strictly reloads the frozen price-blind
artifact, replays the reviewed security identity, binds the governed quote date, and selects or
derives one `common_shares_outstanding` Fact. Callers may not submit a Fact ID, share count,
measurement date, evidence kind, status, or `ShareBasisDecision`.

The only eligible paths are direct point-in-time disclosure, same-date issued less treasury, and a
completed-event roll-forward from the latest unambiguous direct or issued-less-treasury opening.
Conflicting current evidence fails closed. A split or reverse split inside a roll-forward window is
`specialist_required`; v0.5 alpha never applies a split factor.

The compiler returns immutable internal path decisions, its output Fact, a compiler-owned
`ShareBasisDecision`, and the recursive `CurrentShareEvidenceClosure`. Derived Facts preserve all
parent IDs and use a deterministic primary formal source while the closure preserves every source.

`MarketReferenceValidationContext` consumes the exact compilation result and no longer accepts a
bare share-basis decision. No public Schema, market evidence, Snapshot builder, valuation request,
kernel execution, writer, CLI, or implicit Skill surface is added.

## Method boundary

This is `PROJECT_OPERATIONALIZATION`. It implements evidence identity, temporal closure, duplicate
resolution, deterministic arithmetic, and fail-closed routing. It does not claim to be McKinsey or
Penman valuation mathematics.

