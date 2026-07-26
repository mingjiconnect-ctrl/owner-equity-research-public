# Phase 5C accounting, method-view, and equity-bridge policy

Status: Phase 5C-0 policy boundary. Production compilers begin only after Phase 5C-0 is accepted.

## Fixed inputs and validation boundary

Every later Phase 5C compiler must strictly reload the canonical ResearchBundle/RunManifest pair,
replay the complete ContractGraph, and rerun the Phase 5B mapping and readiness functions under the
current component lock. Caller-selected Facts, old complete objects, prior lock hashes, and
caller-authored readiness are rejected.

The research repository performs semantic preflight for issuer, cutoff, scope, concept, unit,
period, source, confidence, lineage, account perimeter, Claim review, and root consumption. The
pinned kernel may then be loaded from an explicit fixed checkout only to validate compatibility
through this exact allowlist:

```text
owner_valuation.FactLedger
owner_valuation.MethodAdjustment
owner_valuation.MethodView
owner_valuation.validation.validate_balance_sheet
owner_valuation.validation.validate_clean_surplus
owner_valuation.validation.accounting_quality_gate
```

Phase 5C-0 imports none of these in production code. Future use must first validate the pinned
FactLedger Schema bytes, then construct `FactLedger`. Kernel private pipeline helpers are never
imported or copied.

## Closed accounting perimeter

Each account root is classified exactly once as `operating_asset`, `operating_liability`,
`financial_asset`, `financial_obligation`, `non_common_claim`, `common_equity`, or `unresolved`.
Classification requires an official source, exact period, model currency, and explicit issuer-wide
perimeter.

Every internal result consumes the closed kernel FactLedger envelope. Its issuer and valuation date
must equal the result issuer and cutoff; source and Fact IDs are unique, all Fact sources exist,
market categories are forbidden, and sources, Facts, parent IDs, and other set-like sequences are
canonicalized before fingerprinting. Account decisions exactly cover the classifiable raw stock
Facts in that ledger, replay each Fact concept, and assign every raw root once.

The balance-sheet control uses:

```text
common_equity
= total_equity
- only those NCI/preferred/other claims proven to be included in total_equity

balance_sheet_non_common_claims
= total_liabilities
+ only those NCI/preferred/other claims classified outside total liabilities

total_assets = balance_sheet_non_common_claims + common_equity
```

The Penman reformulation instead uses disjoint account components:

```text
NOA = operating_assets - operating_liabilities

NFO
= financial_obligations
+ nfo_non_common_equity_claims
- financial_assets

common_equity = NOA - NFO
```

`total_liabilities` is never added wholesale to NFO. Accounts already contained in total
liabilities or total equity cannot be added again. `total_equity` remains an unresolved perimeter
input until included NCI/preferred claims are proved and common equity is derived. Missing perimeter metadata blocks the
identity.

Every formula decision contains one closed binding for every registered input role. The binding
lists the exact input Facts and, for non-common claims, records whether those Facts are included in
total equity, outside reported liabilities, or outside reported liabilities for NFO. Each such
relationship, including a reviewed conclusion that no claim was identified, requires a named
analytical Claim and human ReviewDecision. The validator replays role cardinality, Fact concepts,
currency, unit, period, formal source, arithmetic, direct parents, and ultimate raw roots; a
derived alias cannot conceal duplicate inputs.
If inclusion cannot be established, a non-emitted blocked decision records `unresolved`, missing
evidence, and a registered reason without inventing a Claim. Emitted formulas cannot contain an
unresolved term.

Clean surplus uses the same common-equity perimeter:

```text
net_distributions_to_common_owners
= common_dividends
+ common_share_repurchases
- common_equity_issuance
- equity_settled_sbc_owner_contribution
+ registered_other_common_owner_distributions

ending_common_equity
= beginning_common_equity
+ comprehensive_income_attributable_to_common
- net_distributions_to_common_owners
```

Net income cannot replace comprehensive income. A residual plug cannot become an independent Fact.
The beginning common-equity stock must be dated exactly one day before the flow period starts; the
ending stock must equal the flow period end. Currency, unit, and common-equity perimeter must match.
Independent status also requires a finite difference within finite nonnegative tolerance. The
reported difference and status are recomputed from the closed role-to-Fact bindings and registered
equation coefficients; callers cannot supply arithmetic outcomes. The
balance-sheet, clean-surplus ending stock, and NOA/NFO control share the same ending date, reporting
unit, perimeter ID, and common-equity root lineage.
Each dividend, repurchase, issuance, equity-settled SBC contribution, and registered other-owner
component has an explicit observed/official-zero/reviewed-N/A/blocked coverage decision. Omission
never means zero. Those six Facts exactly equal the inputs to the net-distribution derivation; the
derived Fact must replay its registered concept, direct parents, roots, and derivation identity.
Overlapping root lineage is reported as `reconciles_by_construction` and cannot promote Phase 5C
readiness.

## Accounting quality and method views

Only the current cutoff-safe AccountingQualityReview and its complete reviewed Finding/Claim chain
may enter the quality gate:

- confirmed `red_flag` -> material unresolved;
- cleared -> resolved while preserving reviewed final materiality;
- `watch` or `informational` -> nonmaterial but still unresolved/open;
- provisional, blocked, stale, or incomplete evidence -> partial/blocked.

A Finding never creates a discount or adjustment amount.
The compilation binds the current Review fingerprint, status, and complete Finding ID set. Every
Finding has exactly one decision binding its fingerprint, source status, final severity, and closed
evidence-state mapping. Eligible decisions round-trip byte-for-byte into the kernel issue shape,
and Review/Finding/gate states deterministically produce pass, partial, or blocked.

The pinned kernel exposes one global quality gate, but its current routing uses that gate only for
Penman. Phase 5C therefore preserves both the project method-specific quality disposition and the
literal kernel route effect. Every quality result records `kernel_gate_scope=global`, the route
effect and execution compatibility for each method, and a closed incompatibility reason whenever
the two disagree. A successor may remain research-ready while being incompatible with rc.1
execution. Phase 5E must fail before market access, request compilation, or kernel execution for
any incompatible method; it must not suppress a Finding or trim a returned panel to manufacture
compatibility.

Method adjustments require a registered, assumption-free, derived
`method_adjustment_amount` Fact, complete same-source lineage, model unit, accounting/evidence
category, eligible target, and reviewed official evidence. Free numeric amounts, market lineage,
cross-source derivations, arbitrary useful lives, and root reuse are rejected.
The sole Phase 5C-0 calculator policy is a versioned, code-SHA-bound signed sum over registered
monetary Facts from one formal source and one measurement period. Its inputs and output must use
reporting-currency millions, its Assumption list is empty, and the output value and derivation label
must replay exactly. Share counts, ratios, free calculator identities, and derived root aliases are
ineligible.
Each compiled adjustment has an exact registered consumption record for every root. Its target and
amount Facts must exist in the canonical ledger; the target concept/bridge role, derived amount
parents, and same-source lineage must replay the decision. Free channel names and missing
consumption records are rejected. Validation-only consumption records must also name real ledger
roots. A target's ultimate roots must be disjoint from the adjustment roots, so an adjustment
cannot consume itself. Within each method, category-target and adjustment-group-target pairs are
unique, matching the fixed kernel MethodView shape.

Phase 5C-3 compiles only the accounting base of each MethodView:

- McKinsey: base invested capital;
- Penman: current NOA and NFO.

The complete rc.1 MethodView target allowlist remains McKinsey invested capital plus the nine real
equity-bridge concepts/roles, and Penman NOA/NFO. Phase 5C-4 alone appends the bridge fragment after
its nine-role review. This staging prevents a late bridge Fact from bypassing accounting,
accounting-quality, or MethodView evidence freezing.

Historical operating-profit, NOPAT, SBC-expense, or non-recurring-income adjustments are not
pretended to be MethodView targets. Forecast effects requiring judgment remain Phase 5D Candidate
evidence. Penman retains conservative expensing by default; McKinsey cannot invent an R&D asset or
amortization period.

## Cross-channel conservation

A root Fact may support an accounting identity and one registered economic treatment per method.
Within one method it cannot be deducted through NFO, a MethodView adjustment, an equity-bridge item,
or diluted shares more than once. Exact-role sharing between Penman NFO and the separate McKinsey
equity bridge is explicitly registered and limited to once in each method; it is not a second
deduction inside either panel.

The consumption registry distinguishes `validation` from `economic_deduction`. The entire
method-base root set is protected, not only the individual adjustment target. NCI, preferred,
leases, pensions, debt, options, and dilution retain one economic identity even when different Fact
IDs or derived aliases are used to prove multiple relationships. When the identity cannot be
deterministically closed from exact official disclosure, period, unit, currency, and lineage, the
candidate remains unresolved; a caller-authored identity is never accepted.

## Nine-role equity bridge

Exactly one decision is required for each role:

```text
nonoperating_asset
debt
debt_equivalent
lease_liability
unfunded_pension
preferred_stock
noncontrolling_interest
option_or_dilution_claim
other_senior_claim
```

`modeled` requires one positive-magnitude aggregate Fact with same-source, complete, disjoint
lineage whose value equals the deterministic sum of its registered nonnegative raw roots.
`explicitly_absent` requires an official raw numeric zero Fact; a derived zero is not absence.
`not_applicable` requires a
named-human confirmed analytical Claim and a mappable official numeric Fact for the kernel evidence
reference. Otherwise the state is `unresolved`. Search completion or narrative absence is not zero.
Modeled Fact IDs are unique across roles. Modeled and zero evidence must carry the registered role's
actual concept, category, reporting currency, and unit; only modeled aggregates receive the bridge
role tag. Every modeled bridge Fact, including a one-root item, is a reviewed derived aggregate
whose parents exactly equal the registered raw roots and whose value exactly replays their sum.
All overlap checks expand both ultimate raw roots and deterministic economic-claim identity.
Diluted shares likewise require positive, unit-correct, non-currency lineage.

Bridge roots are mutually exclusive and cannot overlap diluted-share roots. Cash is not assumed to
be nonoperating. Gross repurchases do not prove net dilution improvement. A role zero Fact supports
an absence assertion but is not tagged as a modeled bridge item.
The bridge consumes the already frozen MethodView ledger and source registry. It may add only the
registered derived aggregate Facts; it cannot introduce a raw Fact, an official-zero Fact, a source,
or other evidence after MethodView compilation. New evidence requires replaying reconciliation,
quality, and MethodView before a bridge can be considered.

If all nine roles close as absent/not-applicable and no modeled item exists, research coverage may
be closed but kernel rc.1 request compatibility remains partial with
`kernel_bridge_item_required`; no zero item is fabricated.

## Successor readiness

Phase 5C recomputes separate McKinsey and Penman panels with states
`ready_for_phase5d`, `partial`, `specialist_required`, or `blocked`. It never forwards Phase 5B
routing booleans or emits an aggregate score.

Each panel must cover its complete registered role set. McKinsey requires accounting
reconciliation, accounting quality, its MethodView, stable capital structure,
operating/financing separability, and the equity bridge. Penman requires accounting
reconciliation, accounting quality, its MethodView, credible NOA, and operating/financing
separability. Arbitrary satisfied-role labels cannot produce readiness, and a core route cannot
emit `specialist_required`.

Panels replay closed upstream statuses for reconciliation, quality, both MethodViews, and the
equity bridge together with the six routing assessments. A blocked dependency cannot be presented
as satisfied; blocked takes precedence over specialist routing, while a resolved specialist route
uses `specialist_required`.

- operating/financing separability requires complete account classification;
- credible NOA requires same-date `NOA - NFO = common_equity` reconciliation;
- equity-bridge completeness requires all nine roles and kernel-shape compatibility;
- credible near-term earnings remains `pending_phase5d`;
- required valuation data remains false before Phase 5E.

Stable capital structure requires at least three comparable annual debt/cash/common-equity
snapshots, current debt/covenant/liquidity footnotes, current CapitalAllocationReview coverage, and
a named-human confirmed issuer-wide Claim with counterevidence and falsification. Evidence gaps are
blocked; a confirmed unstable structure requires a specialist route. No arbitrary leverage
threshold is introduced.
The readiness result binds the actual `FootnoteReview`, `CapitalAllocationReview`, `Claim`,
`AnalyticalClaimCandidate`, and `AnalyticalClaimReviewDecision` objects. Their IDs, fingerprints,
evidence graph, scope, cutoff, source coverage, and Claim-to-Decision chain are replayed. Annual
snapshot roles contain real ledger Fact IDs, and the recorded Fact/research evidence sets must equal
the typed-object unions exactly. Placeholder IDs, partial typed proofs, and caller-authored
summaries are rejected.

## Phase 5C-0 stop boundary

This subphase defines policy registries, immutable internal types, fixtures, tests, and audit only.
It exposes no compiler, builder, fetcher, runner, writer, CLI, market access, AssumptionLedger,
valuation request/result, kernel execution, valuation math, Score, report, PDF, or Publisher.
The audit permits exactly the two new policy modules under `src/owner_research`; an additional
compiler, writer, market, or otherwise unapproved Python module fails the boundary even when it is
not exported from the package root.
