# ADR 0027: Phase 5D-0 assumption governance and supplemental price-blind closure

Status: accepted for Phase 5D-0 implementation

## Context

Phase 5A required every valuation-assumption Candidate to use only the ResearchBundle dependency
closure. That is correct for issuer evidence but cannot represent independently sourced risk-free
rates, macro bounds, ERP, industry risk, opportunity cost, or a versioned owner hurdle policy.
The v1 Candidate also lacked a slot identity, so several Penman hurdle and growth-grid entries could
share the same concept without a deterministic downstream position.

## Decision

Upgrade `ValuationAssumptionCandidate` and `ValuationHandoff` to `2.0.0` without adding another
public contract. Keep ResearchBundle permanently price-blind and unchanged. Represent approved
non-target references in an internal immutable `PriceBlindReferenceClosure`, whose canonical hash
is bound by every Candidate and Handoff version.

Each Candidate names one closed assumption slot and labels every evidence binding with both an
evidence domain and a slot-specific role. Bundle evidence remains same-issuer and closure-bound.
Supplemental evidence is limited to raw numeric Facts from separately hashed official,
methodology-backed, or commit-pinned policy sources. Target-security price, market capitalization,
trading multiples, and implied-return evidence are always forbidden.

Every Handoff version records its transition time and the exact slot, evidence, and freeze policy
hashes. Once candidates are reviewed, their IDs and Decisions cannot change. Once the price-blind
input is frozen, all three protected hashes are immutable. Drift requires a new `evidence_open`
root and quarantine of any market snapshot seen by the prior run.

## Method boundary

- `MCKINSEY_BOOK_CORE`: operating forecasts, reinvestment, capital returns, and terminal state must
  remain internally consistent; the pinned kernel owns all valuation mathematics.
- `PENMAN_BOOK_CORE`: near-term accounting forecasts, hurdle sensitivity, growth grids, and the
  operating challenge path are frozen before market price is introduced.
- `PROJECT_OPERATIONALIZATION`: slot IDs, supplemental closures, human Decisions, protected hashes,
  state transitions, and market-access quarantine.

Attribution uses only the pinned kernel source manifest at commit
`a7dd1528c34f09702686b32ffbb8a397439665f0`: McKinsey source SHA
`a8239ec1273596b0658bfe58d01d3d53cc0af9f2cd0beb3c11ca8f096981221a` and Penman/Pope source SHA
`3f9233a79ef5b716bbbeaf0dfb6f692a7ada7000cffb3d24987ea04557040621`.

## Consequences

Phase 5D-0 remains validation-only. It provides no Candidate builder, AssumptionLedger compiler,
market client, price-blind artifact writer, valuation request, kernel execution, Score, report, or
Publisher. v1 Candidate and Handoff payloads are not guessed into v2; they must be rebuilt or remain
blocked.
