# Phase 5 acceptance policy

## Phase 5P

Phase 5P is accepted only when one PR from `feature/phase5p-valuation-handoff-planning` is merged
from the fixed Phase 4 release baseline and all of the following hold:

- six planning deliverables and the Phase 5P audit are present;
- every required object in the pinned FactLedger, AssumptionLedger, valuation-request, and
  valuation-result schemas is represented exactly once in the interface coverage matrix;
- all P0/P1 failure modes have a fail-closed behavior and a future test owner;
- the price-blind/full-request incompatibility is explicitly resolved;
- Phase 1-4 tests, Python 3.11/3.12/3.13, Ruff, compileall, wheel, component lock, Plugin, and four
  Skill checks remain green;
- exact-head no-remote read-only audit `1.8.0` reports `P0=P1=P2=P3=0`;
- no public Schema, production module, Plugin payload, component lock, package version, release
  tag, or marketplace state changes.

After merge and successful main CI, only Phase 5A contract work is authorized.

## Phase 5A

Accept exactly four closed public contracts, immutable types, stable fingerprints, ContractGraph
gates, and adversarial fixtures. No builder, network access, FactLedger compilation, request,
result, or kernel execution is allowed. P0/P1 must be zero; no release tag is created.

## Phase 5B

Accept only registered source/concept/unit/period mappings, deterministic eligible Fact and
CalculationResult conversion, and separately replayed McKinsey/Penman readiness. Unknown,
low-confidence, cross-currency, cross-issuer, future, or ambiguous evidence fails closed. No
market access or kernel call is allowed.

## Phase 5C

Accept balance-sheet and clean-surplus checks, method views with root-level deduplication, and all
nine equity-bridge roles. Missing disclosure cannot become zero or `explicitly_absent`. Options,
diluted shares, leases, pensions, SBC, noncontrolling interest, preferred stock, debt equivalents,
and other claims must not be omitted or double counted.

## Phase 5D

Accept human-reviewed valuation assumptions, exactly four McKinsey scenarios, complete Penman
price-blind paths, canonical `price-blind-input.json`, and reproducible protected hashes. Any
market-source access before the freeze is a P0 and invalidates the run.

## Phase 5E

Accept a governed market snapshot, deterministic market-equity derivation, unchanged price-blind
assumption entries, protected-hash equality, a complete kernel request, pinned in-process kernel
execution, and an unmodified validated result. Any market lineage in McKinsey inputs is a P0.

## Phase 5F

Accept the strict six-file archive, atomic write/reload, full hash binding, ResearchBundle replay,
kernel request/result round trip, and clean-room replay across supported Python versions. Shadow
runs cover at least a conventional nonfinancial issuer, a multi-segment issuer, and an honestly
blocked/partial case. Success is judged by evidence and deterministic replay, never by closeness
to market price.

Final release requirements:

- exact-head and independent read-only audit: `P0=P1=P2=P3=0`;
- PR CI, merge commit main CI, annotated `v0.5.0-alpha.1`, and tag CI all pass;
- tag resolves to the audited main merge commit;
- no authorization of Phase 6 is implied.

Final Phase 5 wording:

```text
Phase 5 audited valuation handoff to the pinned dual-panel kernel
accepted at v0.5.0-alpha.1.
```
