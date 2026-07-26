# ADR 0026: Phase 5C accounting and equity-bridge policy boundary

Status: accepted/closed after PR #35, passing main CI, read-only audit `2.1.0`, and governance
closeout audit `2.1.0.1`

## Decision

Phase 5C consumes only a strictly reloaded ResearchBundle/RunManifest pair, its matching complete
ContractGraph, and freshly replayed Phase 5B mapping/readiness results. Phase 5C-0 defines closed
policies and immutable internal result types only. It does not classify accounts, derive Facts,
compile a method view or equity bridge, write artifacts, or call valuation mathematics.

The accounting perimeter distinguishes two sets that must never be conflated:

```text
balance_sheet_non_common_claims
= total_liabilities
+ equity-classified NCI
+ equity-classified preferred claims
+ other verified equity-classified non-common claims

nfo_non_common_equity_claims
= NCI
+ preferred claims
+ other verified non-common equity claims
```

The first set is used only to reconcile assets with common equity. The second is added to net
financial obligations alongside financial obligations and net of financial assets. The exact
Phase 5B `total_liabilities` concept is not added to NFO as a single amount, and no renamed alias is
inferred. Each underlying account must instead be classified exactly once as operating or
financing. Whether total equity already excludes NCI, preferred, or other non-common claims is an
explicit perimeter decision; ambiguity blocks the reformulation.

Formula decisions therefore carry closed term-role bindings rather than flat, caller-labeled input
lists. Non-common term bindings require a human-reviewed inclusion or exclusion Claim, and all
bindings replay registered concepts, cardinality, arithmetic, period, source, direct parents, and
ultimate raw lineage.

Clean surplus binds the prior-day beginning stock to the full flow period and the ending stock to
its period end. All six owner-transaction components require explicit evidence coverage. Root
consumption is limited once per method, while the same registered claim may appear once in Penman
NFO and once in the separate McKinsey equity bridge. Phase 5C-3 freezes the McKinsey invested-
capital base and the Penman NOA/NFO base; Phase 5C-4 alone appends reviewed bridge items under the
fixed kernel target allowlist. The bridge cannot add raw Facts, absence evidence, or sources after
the MethodView freeze.

Method-adjustment amounts are limited to a single versioned, code-SHA-bound, zero-Assumption
signed-sum calculator over registered reporting-currency Facts from one source and period. Bridge
aggregates replay the sum of their ultimate raw magnitude roots; official absence requires a raw
numeric zero, not a constructed zero.

Internal results validate a canonical, price-blind FactLedger envelope whose issuer and valuation
date equal the result identity. Account candidates, derived formula Facts, owner-flow inputs,
quality Review Findings, MethodView root consumption, bridge role evidence, and successor roles are
closed against that ledger or their named upstream status set. Independent reconciliations must be
recomputed from closed role bindings and remain within finite tolerance; all three accounting
controls share the same ending common-equity lineage. Finding decisions bind the reviewed Finding
fingerprint, status, and severity. Method adjustments cannot share ultimate roots with their target,
or with any other root in the method base, and their category-target and group-target keys are
unique within each method. Conservation expands aliases and also compares deterministic economic-
claim identity so a duplicated official disclosure cannot evade the gate by changing Fact ID. If
cross-document identity cannot be closed deterministically, the treatment remains unresolved.
This validation remains policy enforcement only and does not select evidence or calculate a new
Fact.

The pinned rc.1 accounting-quality gate is global but its routing only blocks Penman. Phase 5C
records the literal kernel route effect and method-specific execution compatibility separately from
project readiness. A mismatch is fail-closed for future market access, request compilation, and
kernel execution; reviewed Findings may not be discarded to fit the pinned route behavior.

Stable-capital evidence is not represented by IDs alone. The readiness envelope binds the existing
typed FootnoteReview, CapitalAllocationReview, Claim, AnalyticalClaimCandidate, and human
ReviewDecision objects and replays their fingerprints, evidence graph, scope, cutoff, coverage, and
exact evidence unions together with three consecutive annual ledger snapshots.

The Phase 5C verifier also closes the filesystem surface: only the two approved policy modules may
be added under the research package before Phase 5C-1.

The fixed valuation kernel is a read-only compatibility oracle. Future Phase 5C implementations
may use only the six named public/module-level validation interfaces after checking the fixed tag,
commit, and eight public Schema hashes. Private pipeline functions, routing, assumptions, request
assembly, valuation functions, CLI, and writers remain prohibited.

## Method boundary

- `MCKINSEY_BOOK_CORE`: reorganize operating and financing claims, preserve conservation of value,
  and bridge operating value to diluted common equity without double counting.
- `PENMAN_BOOK_CORE`: reformulate operating and financing activities, reconcile NOA, NFO, and
  common equity, and retain conservative accounting unless an adjustment is directly evidenced.
- `PROJECT_OPERATIONALIZATION`: candidate/review gates, closed account roles, source and root
  conservation, explicit absence semantics, stable-capital evidence, immutable internal results,
  and exact-head audit controls.

The book identities and hashes are inherited from the pinned kernel
`references/source_manifest.json`. Existing verified locators in the kernel methodology and
fidelity matrix are authoritative; Phase 5C adds no new page claims.

## Consequences

- The 43 public research Schemas remain byte-identical.
- Phase 5B policy, implementation, fixtures, tests, and audit `2.0.4` remain byte-frozen at
  `17afbdc9464af2310f2bf5be72df87f3da9fbbc2`.
- Phase 5C internal types are not package-root exports and are not a fifth Phase 5 public contract.
- A residual accounting plug may be recorded as `reconciles_by_construction` but can never be
  represented as independent evidence or promote readiness.
- Missing or narrative evidence never becomes a numeric zero.
- Every modeled bridge item is a deterministic derived aggregate over evidence frozen before the
  bridge stage, even when it has one raw root.
- Research readiness and pinned-kernel execution compatibility remain separate, explicit states.
- Phase 5C reads no market evidence and creates no assumption, request, result, score, report, PDF,
  or publication artifact.
