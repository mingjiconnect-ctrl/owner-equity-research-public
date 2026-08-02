# owner-equity-research

Canonical repository:
[`mingjiconnect-ctrl/owner-equity-research-public`](https://github.com/mingjiconnect-ctrl/owner-equity-research-public).
It starts from a content-addressed clean root; the former private repository and
its commit graph are retained only as historical provenance. Public visibility
does not expose the private valuation kernel, credentials, or licensed market
data and does not by itself grant an open-source license.

Private, engineering-grade foundations for auditable public-equity research.

## Current Phase 5 authority

`Phase 5 v1 market-reference vertical slice` is `in_progress` under ADR 0041 and
`docs/phase5-v1-status.json`. Only `PR1 market-reference vertical slice` is authorized. The former
recursive G1-G5 controller, acceptance-only branches, and `docs/phase-status.json` are retained as
`legacy_governance`; they are historical evidence rather than the current required path.

Pull requests require exactly `verify (3.11)`, `verify (3.12)`, `verify (3.13)`, and
`phase5/semantic-audit`. That Actions context is a deterministic candidate replay at the exact
pull-request head; it is not an independent review. Before merge, a separate fresh-context review
must bind the exact commit/tree, test counts, P0-P3 counts and report SHA in pull-request evidence.
Both gates require P0=P1=0. Release candidates require P0=P1=P2=P3=0, while merged `main` runs smoke
and deterministic replay. Canonical summaries stay outside product state.

## Historical phase record

The chronology below records constraints and authority at each closeout; it does not override the
current Phase 5 v1 authority above.

Phase 4E-0 and Phase 4E-1 are accepted/closed. Phase 4E-2 closes and freezes the Phase 4
integration layer at `v0.4.0-alpha.1`. Phase 5P fixes the valuation-handoff plan and pinned
interface audit without adding production capability. Phase 5A adds four closed, validation-only
valuation-handoff contracts. Phase 5B-0 closes the five mapping registries and internal result
types. Phase 5B-1 adds strict Bundle/graph replay and official-source raw Fact compilation. Phase
5B-2 adds registered single-quarter/TTM lineage. Phase 5B-3 adds deterministic company routing and
separate McKinsey/Penman readiness. Phase 5B-4 closes replay, amendment/conflict behavior, eight
routing goldens, and audit `2.0.4`. Phase 5C-0 adds closed accounting, MethodView, nine-role
equity-bridge, de-duplication, and successor-readiness policies plus immutable internal types and
audit `2.1.0`; it implements no compiler. Phase 5C-0 is accepted/closed through governance
closeout audit `2.1.0.1`. Phase 5C-1 adds the internal, price-blind accounting-reconciliation
compiler under audit `2.1.1`; it has no package-root, CLI, Skill, writer, market, assumption,
request/result, or valuation-execution surface. Phase 5C-1 accounting reconciliation work remains
accepted/closed after PR #38 and audit `2.1.1`. Phase 5C-2 accounting-quality and deterministic
adjustment work is accepted/closed after PR #39 and audit `2.1.2`. Phase 5C-3 deterministic
MethodView work is accepted/closed after PR #40 and audit `2.1.3`. Phase 5C-4 deterministic
equity-bridge work is accepted/closed after PR #41 and audit `2.1.4`. Phase 5C-5 deterministic
successor-readiness and replay closeout is accepted/closed after PR #42 and audit `2.1.5`. Phase 5C
is accepted/closed after governance audit `2.1.5.1`; only Phase 5D assumption governance and
price-blind freeze work is authorized. Phase 5D-0 upgrades the Candidate and Handoff contracts to
v2, adds closed assumption slots and a separately hashed internal supplemental-reference closure,
and keeps target-security market evidence forbidden. It remains validation-only under audit
`2.2.0`. It is accepted/closed through PR #44 and main CI `29295736044`.
Phase 5D-1 implements only an internal price-blind Candidate compiler, replays Phase 5C readiness,
and emits no human Decision or kernel assumption. It is accepted/closed through implementation PR
#46, acceptance PR #47, merge `7c13073aa70a...`, main CI `29297468611`, and audit `2.2.1`.
Phase 5D-2 is accepted/closed through PR #49, merge `43fffa76d3eb...`, main CI `29299088854`,
and audit `2.2.2`. Its internal review resolver and pinned-schema AssumptionLedger compiler map
only confirmed support Facts, including separately governed supplemental macro evidence, and
create no method input or artifact. Phase 5D-3 is accepted/closed through PR #51, merge
`dcbc5d5bbbb6...`, main CI `29300664978`, and audit `2.2.3`. Its internal four-scenario reference
compiler and pinned steady-state preflight write no artifact and invoke no DCF, economic profit,
bridge, request, result, or valuation pipeline. Phase 5D-4 is accepted/closed through PR #53,
merge `e3ef484f42ca...`, main CI `29302120207`, and audit `2.2.4`. Its compiler produces only an
immutable nonmarket reference fragment, forces CAP diagnostics off, and deliberately omits
market-equity identity. Phase 5D-5 is accepted/closed through PR #55, merge `a63e3dcb5c57...`,
main CI `29303730712`, and audit `2.2.5`; its internal canonical artifact, protected hashes,
strict persistence/reload, and adjacent Handoff chain remain price-blind. Phase 5D-6 is
accepted/closed through PR #57, merge `38be7b66ea20...`, main CI `29305219309`, and audit `2.2.6`;
its clean-room replay is byte-stable and adds no market or valuation capability. Phase 5D is
accepted/frozen. Phase 5E-0 policy hardening and Phase 5E-1.1 authority closeout are
accepted/closed under audits `2.3.0` and `2.3.1.1`. The internal gate reloads the price-blind
artifact, replays an evidence-bound security identity, selects a locked calendar session, parses
one raw response with repository-owned code, and preserves only governed lineage or hash-only
quarantine. Phase 5E-2A.1 remains accepted/closed under audit `2.3.2.1`. Phase 5E-2A.2 pins the
complete annotated `owner-valuation-kernel@v2.0.0-rc.2` release identity and upgrades only
`MarketReferenceSnapshot` to the validation-only v3 current-common-share contract. Its
implementation and governance closeout are accepted under exact-head audit `2.3.2.2`. Independent
semantic review required Phase 5E-2A.2.1 to add recursive raw-root, cutoff, search-coverage and
completed-claim validation under audit `2.3.2.2.1`. Separate implementation and acceptance PRs
are complete. Phase 5E-2B deterministically compiles quote-date current common shares from the
strictly replayed price-blind, security, market-access, dilution, restatement, and recursive
evidence authorities. Its implementation and separate acceptance closeout remain historical
records under audit `2.3.2.3`. A later independent P0 review found that the same legal event could
be consumed once per source. Phase 5E-2B.1-0 freezes the corrective identity policy; the internal
Phase 5E-2B.1-1 production grouping is accepted/closed under audit `2.3.2.3.2`.
Phase 5E-2B.1-2A now defines the contract-only exactly-once integration boundary under audit
`2.3.2.3.3`, including exact category coverage, unique category/security-specific N/A human
review chains, direct-Fact and cutoff-safe evidence, graph-byte-bound coverage and transition
objects, duplicate typed-evidence rejection, and option-only standard Claim authority with
convertible/warrant specialist deferral. The boundary also blocks one official occurrence split by
economic-key drift, nonofficial or non-high-confidence opening roots, multi-root Claims without an
aggregate balance, generated-ID collisions, and non-single review chains. Exact source-byte code
identity and independent regression replay bootstrapped the historical credential-partitioned
gate. That gate, its two-file closeout, special branch, trust snapshot, oracle, and successor
prohibitions are retained as `legacy_governance`; ADR 0041 supersedes them as current authority.

Phase 1 is frozen at `v0.1.0-alpha.1`; Phase 2 is frozen at
`v0.2.0-alpha.1` / `feac934`; Phase 3 is frozen at `v0.3.0-alpha.1` / `41dcb27`.
Phase 4A added a contract-only layer on top of the Phase 3 evidence system. Phase 4B-0 hardened
the management-ledger semantics, Phase 4B-1 adds official-source Statement intake, Phase 4B-2
adds deterministic Commitment compilation, Phase 4B-3 adds deterministic Outcome evaluation, and
Phase 4B-4 closes code-built Reviews plus fixed-date metadata shadows. Phase 4C adds governed
external context, descriptive material-scope business models, registered diagnostics, reviewed
Claims, deterministic hypotheses, and coverage-only BusinessQualityReviews. Phase 4D-0 adds
governed capital-allocation contracts and policy gates; Phase 4D-1 adds the source-backed Event
ledger; Phase 4D-2 adds assumption-free conservation bridges; Phase 4D-3 adds deterministic
evidence-state Outcomes; Phase 4D-4 adds code-built coverage Reviews and metadata-only Shadows;
Phase 4D-5 closes carryover activity selection and machine-readable source-search coverage. Phase
4E-0 adds the `ResearchBundle 1.0.0` integration envelope and 4E-1 adds its deterministic builder:

- forty-three Draft 2020-12 public contracts and immutable Python counterparts;
- Fact v2 registered monetary and nonmonetary units with deterministic migration from known v1
  monetary scales;
- measurable target and result roles, controlled management policies, explicit scope and basis,
  and closed withdrawn/superseded lifecycles;
- exact-span Statement candidates, issuer-host allowlists, and machine-readable human decisions;
- policy-bound Commitment compilation, explicit or uniquely resolved fiscal deadlines, and closed
  withdrawal/supersession transitions;
- ten policy evaluators with assumption-free growth/cumulative calculations and hard comparability
  gates;
- code-selected ManagementReviews with recomputed coverage and Salesforce/Amazon shadow manifests;
- code-selected BusinessQualityReviews with recomputed scope, mechanism, trend, Claim, and
  counterevidence coverage;
- deterministic fingerprints, cross-reference validation, and a component lock for
  `owner-valuation-kernel@v2.0.0-rc.2`;
- SEC 10-K/10-Q intake with required caller identity, bounded rate, external content-addressed
  cache, and offline CI fixtures;
- deterministic table/iXBRL candidates and a governed, auditable Fact-promotion boundary;
- reportable-segment identity, mapping, Fact assignment, display-precision reconciliation, and
  disclosed-only diagnostics;
- mandatory plus dynamic footnote coverage and Claim-confirmed accounting-quality findings;
- ten contracts for business-model snapshots, competitive-advantage hypotheses, management
  statements/commitments/outcomes, capital-allocation events/outcomes, and evidence coverage;
- graph rules for official-source support, counterevidence and falsification, KPI definition
  changes, commitment timing, event de-duplication, outcome evidence roles, and review coverage;
- twelve synthetic adversarial fixtures covering false moat signals, KPI changes, commitment
  timing, buyback/SBC dilution, acquisition accounting, duplicate events, and missing outcomes;
- reviewed capital-allocation Candidates, deterministic economic-event identity, repeated-
  disclosure deduplication, contiguous Event versions, role-typed Outcomes, and coverage-only
  Reviews;
- registered consideration, financing, cash, liquidity, dividend, and net-share bridges that
  consume only official Facts already reviewed into an Event;
- code-derived capital-allocation lifecycle and result-evidence statuses with human-reviewed Claim
  coverage and completed-search nondisclosure semantics;
- code-selected latest Event/Outcome Reviews with recomputed source/type counts and fixed-cutoff
  Amazon, Salesforce, and Union Pacific metadata-only Shadows;
- SourceSearchReceipt provenance for all eight source families, Review v3 replay, and selection of
  prior-period Events that remain active through execution, lifecycle evidence, or Outcomes;
- current-module and material-scope ResearchBundle gates with event-driven freshness, stable module
  artifacts, source/dependency closure hashes, component-lock replay, and RunManifest binding;
- an idempotent production Bundle builder that accepts no caller-authored selections, status,
  freshness, scope, or hashes and returns the Bundle with its atomically updated RunManifest;
- an atomic, deterministic writer and strict reloader for exactly `research-bundle.json` and
  `run-manifest.json`, with complete/partial/blocked end-to-end replay proofs;
- four validation-only Phase 5A contracts for price-blind assumption candidates, named-human
  decisions, governed market references, and immutable handoff lifecycle versions;
- five closed Phase 5B mapping registries plus immutable internal mapping and method-readiness
  results, without a public Schema;
- a strict price-blind raw Fact compiler that accepts no caller-selected Facts, currency, status,
  or output path and validates its payload against the pinned kernel FactLedger Schema;
- registered single-quarter and TTM derived Facts with replayed fingerprints, direct kernel-parent
  lineage, lowest-parent confidence, single-source enforcement, and controlled derivation text;
- official SIC and reviewed-scope company classification with financial-institution, SOTP,
  asset/NAV, distress/APV, and unresolved specialist routes;
- independently recomputed McKinsey and Penman role coverage, with six evidence-bound routing
  assessments and no aggregate score, model weight, or claim that valuation inputs are complete;
- byte-identical mapping/readiness replay, closure-history independence, deterministic amendment
  selection, conflict blocking, and eight classification/readiness golden cases;
- closed Phase 5C-0 policies for common-equity perimeter, NOA/NFO reconciliation, clean surplus,
  accounting-quality gates, assumption-free MethodView targets, nine equity-bridge roles,
  cross-channel root-lineage de-duplication, and separate successor readiness;
- nine immutable Phase 5C internal result/decision types with canonical ordering and fingerprints,
  no public Schema, package-root API, writer, market access, or valuation-kernel execution;
- an internal Phase 5C-1 compiler that strictly reloads the canonical Bundle pair, replays Phase
  5B, derives common equity, adjusted liabilities, NOA, NFO, invested capital, and six-component
  owner distributions, and recomputes balance-sheet, economic-identity, and clean-surplus checks;
- an internal Phase 5C-2 compiler that selects the current accounting-quality Review and Findings,
  requires confirmed human-reviewed analytical Claims for final semantics, applies method-specific
  gates, and emits only registered same-period, single-source, zero-Assumption adjustment amounts;
- an internal Phase 5C-3 compiler that emits closed McKinsey/Penman MethodView fragments, replays
  economic-claim root consumption, and validates only the pinned FactLedger/MethodView interfaces;
- an internal Phase 5C-4 compiler that closes all nine equity-bridge roles, emits only reviewed
  same-source aggregates, preserves official zero/N/A semantics, and blocks dilution/root overlap;
- an internal Phase 5C-5 assessor that replays the accepted bridge chain, binds typed
  stable-capital evidence, preserves specialist routing, and recomputes separate McKinsey/Penman
  successor-readiness panels without an aggregate state or model weight;
- four Codex Skills inside one Plugin; only the main SEC research entry is implicit.

Phase 4C preserves external evidence as ContextObservation, requires human review before an
analytical Claim exists, derives material scopes from segment evidence, and resolves hypothesis
status from fixed policy gates. A complete Review means evidence closure and can contain zero
supported hypotheses. Phase 4D-5 closes the capital-allocation evidence vertical slice after
correcting carryover activity and search completeness. Phase 4D is accepted and frozen. Phase
4E-2 materializes and reloads only the validated two-file artifact pair; it deliberately provides
no CLI, orchestration, new company Shadow, valuation handoff, score, report, PDF, or Publisher.
Phase 4 and Phase 4E are frozen after the audited `v0.4.0-alpha.1` release. Phase 5P adds only
planning documents and a read-only planning audit. Phase 5A validates caller-supplied handoff
contracts but does not build them or fetch market data. Phase 5B compiles a price-blind FactLedger
in memory with registered raw and derived Facts, assesses company routing plus separate method
readiness, and closes deterministic replay under audit `2.0.4`. Phase 5C-0 fixes the accounting
and equity-bridge policy boundary under audits `2.1.0` and `2.1.0.1`; it does not itself compile a
reconciliation, MethodView, bridge, or Phase 5C readiness result. Phase 5C-1 compiles only the
accounting reconciliation in memory under audit `2.1.1`; Phase 5C-2 compiles only reviewed
accounting-quality dispositions and eligible zero-Assumption adjustments under audit `2.1.2`.
Phase 5C-3 compiles only MethodView fragments and root-consumption records under audit `2.1.3`;
Phase 5C-4 compiles only the nine-role equity-bridge fragment under audit `2.1.4`.
Phase 5C-5 assesses only successor readiness and deterministic replay under audit `2.1.5`.
The governance closeout audit `2.1.5.1` freezes Phase 5C and authorizes only Phase 5D assumption
governance and price-blind freeze work. Phase 5D-0 is accepted/closed and adds only v2 contract semantics, immutable
supplemental reference data, policy registries, and validation gates; it exposes no compiler,
network, writer, or valuation execution. Phase 5D-1 Candidate compilation is accepted/closed.
The compiler remains internal and in-memory and cannot trigger from a Skill. Phase 5D-2
named-human Decision and AssumptionLedger compilation is accepted/closed; Phase 5D-3 McKinsey
four-scenario input compilation, Phase 5D-4 Penman input compilation, Phase 5D-5 canonical
price-blind freeze, and Phase 5D-6 deterministic replay are accepted/closed. Phase 5D is frozen;
Phase 5E-0 policy hardening and Phase 5E-1.1 authority closeout are accepted/closed under audits
`2.3.0` and `2.3.1.1`. The access gate remains internal and has no implicit Skill entry point.
Phase 5E-2A.1, Phase 5E-2A.2, and Phase 5E-2A.2.1 are accepted/closed. Phase 5E-2B passed its
original implementation and governance audit `2.3.2.3`, but independent semantic review found a
P0 cross-source share-event identity gap. Phase 5E-2B.1-0 is frozen under audit `2.3.2.3.1`;
production grouping is accepted/closed under audit `2.3.2.3.2`, and the contract-only successor
remains historical under audit `2.3.2.3.3`. Its former dual-state authorization is retired.
None of these phases asserts complete valuation-request
data, invokes the kernel, or writes valuation artifacts. The system does
**not** implement company or management grading,
scoring, valuation execution, recommendations, target prices, report generation, PDF, or
publishing.

## Verify

```bash
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python scripts/verify_phase5_v1.py --mode verify
```

The current verifier excludes the retired recursive-governance tests. Those tests can be replayed
only through the manual `legacy-governance-phase5-recursive` workflow at its frozen baseline.

Live shadow runs are explicit; after dependency installation, CI verification executes without
network access. Raw caches are outside the repository. The fixed-date metadata-only runners are
`scripts/sec_shadow_run.py`, `scripts/management_shadow_run.py`, and
`scripts/business_quality_shadow_run.py`; they write only source/accession metadata with explicitly
scoped hashes, object IDs, coverage, blocked reasons, and manifests.

```bash
OWNER_RESEARCH_SEC_USER_AGENT='Your firm name contact@example.com' \
  python scripts/sec_shadow_run.py --issuer amazon --cutoff 2026-07-11 \
  --output /outside/repository/amazon-shadow.json
```

When an issuer IR site blocks direct automated retrieval, a separately reviewed official-web
snapshot may be supplied from outside the repository. The management manifest labels its hash as
`normalized_official_excerpt`; it never treats it as full response bytes.

```bash
python scripts/management_shadow_run.py --issuer salesforce --cutoff 2026-07-11 \
  --verified-snapshot /outside/repository/verified-official-snapshots.json \
  --output /outside/repository/salesforce-management-shadow.json
```

The committed Phase 4C acceptance shadows use independently verified SEC index metadata. Their
`official_metadata_tuple` hashes are not filing-content hashes, and missing formal evidence remains
blocked.

```bash
python scripts/business_quality_shadow_run.py --issuer amazon --cutoff 2026-07-11 \
  --output /outside/repository/amazon-business-quality-shadow.json
```

For the release preflight, provide a clean checkout of the pinned valuation kernel:

```bash
python scripts/verify_component_lock.py \
  --source-repo ../owner-valuation-kernel \
  --require-clean --require-pinned-head
```

Current pull-request CI uses only the dedicated Kernel Reader App to check out the exact private
rc.2 source. That installation token is read-only, scoped to one repository, revoked before
candidate code runs, and never persisted in the checkout; verification then runs without network
access. CI uploads only canonical, credential-free verification summaries. The former
protected-base Controller, external Gate Author, recursive status publication, and merged-main
acceptance audit remain frozen under `legacy_governance`; the narrowly scoped Kernel Reader is the
only retained App authority. Phase 6 through Phase 9 still require a separate reviewed
authorization after Phase 5.
