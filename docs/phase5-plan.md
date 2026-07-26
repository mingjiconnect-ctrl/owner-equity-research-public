# Phase 5 valuation-handoff plan

Status: Phase 5P planning baseline. No Phase 5 production capability is implemented here.

## Fixed baselines

- Research release: `v0.4.0-alpha.1` at
  `30d6e77780175deeffc5c211749bcb0169aa1dde`.
- Valuation kernel: `v2.0.0-rc.1` at
  `a7dd1528c34f09702686b32ffbb8a397439665f0`.
- Phase 4 and its `ResearchBundle 1.0.0` remain immutable and price-blind.
- The valuation kernel remains a read-only, hash-pinned dependency. This repository never copies
  its DCF, economic-profit, continuing-value, residual-operating-income, reverse-price, or fade
  calculations.

## End-to-end boundary

```text
strictly reloaded ResearchBundle / RunManifest pair
  + matching validated ContractGraph
  -> method-specific readiness
  -> registered research evidence mapping
  -> accounting checks, method views, and equity bridge
  -> human-approved price-blind assumptions
  -> canonical price-blind-input.json and protected hashes
  -> market access becomes eligible
  -> MarketReferenceSnapshot
  -> complete valuation-request.json
  -> pinned owner-valuation-kernel
  -> unmodified valuation-result.json
  -> audited ValuationHandoff archive
```

The Bundle artifact alone cannot compile valuation inputs: it contains IDs and hashes, not the
referenced Fact, Claim, CalculationResult, or Review payloads. Every compiler therefore requires
the strictly reloaded artifact pair plus the complete ContractGraph whose dependency closure
replays to the Bundle hash.

The kernel's Penman request requires `market_equity_value_fact_id`. Consequently,
`price-blind-input.json` is not and must never be represented as a valid
`valuation-request.json`. It is a closed, canonical internal compiler artifact whose fingerprint
and protected subtrees are later bound by `ValuationHandoff`.

## Sequential delivery

| Phase | Branch | Python / Plugin version | Authorized delivery | Release |
| --- | --- | --- | --- | --- |
| 5A | `feature/phase5a-handoff-contracts` | `0.5.0.dev1` / `0.5.0-dev.1` | Four public contracts and validation-only ContractGraph gates | none |
| 5B | `feature/phase5b-fact-readiness` | `0.5.0.dev2` / `0.5.0-dev.2` | FactLedger mapping and separate McKinsey/Penman readiness | none |
| 5C | `feature/phase5c-accounting-equity-bridge` | `0.5.0.dev3` / `0.5.0-dev.3` | Accounting checks, method views, and all nine equity-bridge roles | none |
| 5D | `feature/phase5d-price-blind-assumptions` | `0.5.0.dev4` / `0.5.0-dev.4` | Human-approved assumptions, four scenarios, and price-blind freeze | none |
| 5E | `feature/phase5e-kernel-execution` | `0.5.0.dev5` / `0.5.0-dev.5` | Market reference, final request, pinned kernel execution | none |
| 5F | `feature/phase5f-handoff-closeout` | `0.5.0a1` / `0.5.0-alpha.1` | Six-file archive, Shadow, clean-room replay, final audit | `v0.5.0-alpha.1` |

Every phase starts from the prior phase's merged `main` after successful main CI. A later phase is
not authorized by code existing on an unmerged branch.

### Phase 5A - contracts only

Add exactly four long-lived public contracts:

- `ValuationHandoff`
- `MarketReferenceSnapshot`
- `ValuationAssumptionCandidate`
- `ValuationAssumptionReviewDecision`

They use closed Draft 2020-12 schemas, immutable Python types, stable fingerprints, and
ContractGraph gates. No builder, market fetch, FactLedger compilation, request, kernel call, or
archive writer is authorized in 5A. Readiness and price-blind compiler payloads remain internal
typed results rather than additional public research domains.

### Phase 5B - evidence mapping and readiness

Create versioned, exact concept/source/unit/period registries. Consume the validated graph and
Bundle together. Emit separate McKinsey and Penman readiness states:
`ready`, `partial`, `specialist_required`, or `blocked`. Bundle completeness is evidence-closure
state only and cannot promote either readiness state.

The first release supports a single reporting currency. A monetary input in another currency is
blocked under kernel rc.1; the adapter does not manufacture an unauditable FX lineage. Unknown
concepts, nonnumeric Facts, insufficient confidence, ambiguous dates, or missing sources are also
blocked.

### Phase 5C - accounting and equity bridge

Compile balance-sheet and clean-surplus checks, method-specific adjustments, and all nine
equity-bridge roles. An absent disclosure is not zero. Each role is `modeled`,
`explicitly_absent`, `not_applicable`, or `unresolved`; only official evidence can support the
first three states. Options and diluted shares must not be counted twice. Method-adjustment roots
must be complete and disjoint across groups.

### Phase 5D - human assumptions and price-blind freeze

Management guidance, business-quality evidence, and competitive-advantage hypotheses may create
only `ValuationAssumptionCandidate` objects. A matching human Decision is required before a kernel
assumption exists. McKinsey receives exactly `black_swan`, `bear`, `base`, and `bull`, with one
shared explicit timeline. Penman near-term forecast, hurdle inputs, growth grid, and challenge path
are also frozen before market access.

Materialize canonical `price-blind-input.json` and record:

- `price_blind_input_fingerprint`
- `protected_mckinsey_sha256`
- `protected_penman_assumptions_sha256`

The internal artifact is not a complete kernel request. Its hash excludes no substantive
nonmarket input. It may exclude only self-hash fields and the final FactLedger binding that must be
recomputed when market facts are appended.

### Phase 5E - market reference and kernel execution

Only after the price-blind freeze may an explicit run acquire a quote. Build a human-auditable
`MarketReferenceSnapshot`, derive market equity value from the quote and reviewed diluted shares,
append market Facts, rebuild the AssumptionLedger binding without changing any assumption entry,
and compile the complete kernel request.

Before invocation, recompute the two protected hashes and prove canonical-byte equality. Run only
the pinned kernel package, validate all eight pinned schema hashes, and preserve the kernel result
without post-processing its values or labels.

### Phase 5F - archive and release

The final directory contains exactly:

```text
valuation-handoff.json
price-blind-input.json
market-reference.json
valuation-request.json
valuation-result.json
valuation-run-manifest.json
```

`valuation-run-manifest.json` is a Phase 5 internal archive manifest. It does not reuse or alter
the Phase 4 RunManifest anti-anchoring meaning. The archive requires canonical JSON, a strict file
set, no symlinks, atomic publication, complete hash binding, Bundle replay, kernel request/result
replay, and clean-room installation. Phase 5F does not authorize Phase 6.

## Permanent prohibitions

- No model or panel weighting.
- No market price in McKinsey facts, assumptions, routing, accounting checks, or adjustments.
- No direct Research `Assumption` to kernel Assumption mapping.
- No LLM-confirmed Fact, assumption, readiness, bridge state, or valuation result.
- No research-layer reimplementation or modification of kernel calculations.
- No Score, target price, recommendation, report, PDF, Publisher, persona agent, or Legacy runtime.
