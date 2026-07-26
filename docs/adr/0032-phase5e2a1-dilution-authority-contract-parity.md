# ADR 0032: Phase 5E-2A.1 dilution authority and decimal-domain parity

## Status

Accepted. PR #63, main merge `945834597553bb8ff4df12d77c402bee0433e572`, main CI
`29345441770`, and merge-commit audit `2.3.2.1` completed with `P0=P1=P2=P3=0` and 845/845
tests. Phase 5E-2B governed point-in-time share-basis work is authorized.

## Context

The Phase 5E-2A validation context accepted caller-provided share-basis and equity-bridge root
sets. ContractGraph replayed the share Fact lineage, but it did not independently reconstruct the
option/dilution bridge roots from the Phase 5C readiness object sealed into the price-blind
artifact. A caller could therefore omit a real bridge root from the witness. Separately, the
public `positiveDecimal` Schema accepted zero strings even though the Python contract rejected
them.

## Decision

The validation context no longer accepts final dilution-root collections. It deterministically
derives an immutable `Phase5CDilutionRootAuthority` from the frozen Phase 5C readiness payload:

1. the exact nested `EquityBridgeCompilationResult` fingerprint;
2. option/dilution economic-claim bindings and included, excluded, or blocked treatments;
3. the Phase 5C diluted-share Fact and its ultimate roots;
4. the option bridge role decision; and
5. the complete consumption-record fingerprint.

Included option roots must be consumed through both McKinsey and Penman diluted-share channels
and must not be modeled in the bridge. Excluded option roots must be absent from denominator
consumption and must exactly equal the modeled option bridge roots. Blocked roots make an
eligible share basis impossible. The current point-in-time share lineage must retain the frozen
Phase 5C diluted-share roots, and the public overlap witness must equal the recomputed modeled
bridge roots.

The authority fingerprint is part of both the overlap fingerprint and market-evidence closure.
The public positive-decimal regex now rejects all zero representations while continuing to allow
strictly positive canonical decimals. Schema-only and Python construction tests cover the same
domain.

## Consequences

- Phase 5E-2A.1 remains validation-only and adds no share-basis compiler or Snapshot builder.
- The public Schema count remains 43; only the existing Snapshot v2 Schema hash changes.
- The Phase 5E-1.1 Provider, parser, calendar, security authority, and fixed valuation kernel stay
  byte-for-byte unchanged.
- Python advances to `0.5.0.dev7`, Plugin/component lock to `0.5.0-dev.7`, and audit to `2.3.2.1`.
- The acceptance-state closeout records the merged evidence and authorizes only Phase 5E-2B.

## Prohibited

Phase 5E-2B may implement only governed point-in-time share-basis work. Market evidence
generation, Snapshot building, final request compilation, kernel execution, live Provider
onboarding, Shadow runs, release tags, Marketplace updates, Score, report, PDF, and Publisher
work remain prohibited.
