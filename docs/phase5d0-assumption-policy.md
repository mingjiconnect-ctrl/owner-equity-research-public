# Phase 5D-0 assumption-slot, evidence, and freeze policy

Status: `PROJECT_OPERATIONALIZATION`

## Closed evidence domains

`research_bundle` evidence must be present in the bound Bundle dependency closure, use the target
issuer, and remain cutoff-safe. It may contain mapped Facts, assumption-free CalculationResults,
and reviewed Claims or Reviews, but never a Research `Assumption`, Score, market quote, or later
valuation artifact.

`supplemental_price_blind` evidence lives in a separate internal closure. It accepts only raw,
numeric, high/medium-confidence Facts whose SourceDocument belongs to the same external subject,
has a verified content hash, and is no later than the valuation cutoff. The allowed roles are:

- official macro risk-free, inflation, and long-run growth references;
- methodology-backed ERP, industry beta, and opportunity-cost references;
- a commit-pinned named owner hurdle policy;
- independently sourced counterevidence, falsification evidence, and limitations.

Target-issuer quote, share price, market capitalization, trading multiple, implied return, and
implied beta concepts are forbidden even if their source is otherwise authoritative. Company debt,
capital structure, and tax evidence must stay in the ResearchBundle domain.

## Slot rules

McKinsey uses exactly `black_swan`, `bear`, `base`, and `bull`. Annual revenue, NOPAT, and ending
invested capital slots are explicit by fiscal year. WACC requires separate risk-free, ERP, industry
risk, debt-cost, capital-structure, and tax evidence. Terminal growth requires an official macro
bound; terminal RONIC/ROIC requires historical operating evidence and reviewed business-quality
evidence; terminal margin requires historical and reviewed accounting-quality evidence.

Penman has no scenario label. Annual sales, after-tax operating income, and ending NOA are explicit
by fiscal year. Primary hurdle, ordered hurdle grid, ordered growth grid, long-run growth, and each
challenge-path year are distinct slots. The primary hurdle requires a named owner policy and an
independent opportunity-cost reference.

One current confirmed human Decision is allowed per slot. A changed Candidate or evidence graph
invalidates its Decision; replacement uses an explicit acyclic supersession chain.

## Freeze rules

The Handoff locks Bundle identity, supplemental closure, mapping policy, slot/evidence/freeze
policy hashes, component lock, and pinned kernel identity from the root. Candidate and Decision sets
freeze at `price_blind_candidates_reviewed`. Price-blind and protected method hashes freeze at
`price_blind_input_frozen`. Every transition is adjacent and strictly chronological.

No target-security market reference may exist before `market_reference_allowed`. Any protected
input drift starts a new run; previously observed market evidence is quarantined rather than reused.
