# Public contract versioning

Each contract's `schema_version` describes that contract shape, independently of the package
version. A backward-incompatible required-field change increments the contract's major version.

Phase 2 changes `CalculationResult` from `1.0.0` to `2.0.0` because deterministic calculations
now require `input_period_ids` and `input_bindings`. Phase 1 artifacts remain reproducible under
the immutable `v0.1.0-alpha.1` repository tag. Phase 2 does not silently reinterpret them: a
consumer must either validate them with that tagged v1 schema or explicitly migrate them by
adding verified period references and role bindings, then recomputing calculation identity and
both fingerprints through the v2 deterministic constructor.

All other Phase 2 public contracts retain `1.0.0` because their required shapes were introduced
in this phase rather than changed after release.

Phase 4B-0 changes `Fact` to `2.0.0` because the former contract treated every numeric Fact as
monetary. V2 uses a versioned unit registry and requires currency only for monetary units. The
deterministic migration accepts known legacy monetary scales and blocks unknown units.

`ManagementStatement`, `ManagementCommitment`, `ManagementOutcome`, and `ManagementReview` also
move to `2.0.0`. Their v1 identifier-only target/result fields cannot safely express measurable
roles, scope, basis, registered policies, or withdrawn/superseded coverage. Phase 4A remains
reproducible at its accepted merge; current callers must construct the v2 contracts explicitly.

Phase 4C-0 changes `BusinessModelSnapshot`, `CompetitiveAdvantageHypothesis`, and
`BusinessQualityReview` to `2.0.0`. The v1 shapes cannot represent confirmed not-applicable
components, isolated external context, reviewed analytical Claims, typed mechanism evidence,
counterevidence resolution, lifecycle, trend, or recomputed coverage. The four new context and
analytical-review contracts begin at `1.0.0`. Phase 4A remains reproducible at merge `a70c4e7`.

Phase 4C-2 changes `BusinessModelSnapshot` to `3.0.0`: the v2 component-wide evidence sets cannot
prove which evidence supports each attribute or which reportable scope was covered. V3 adds
deterministically derived material scopes, per-attribute evidence bindings, scope-specific coverage,
and explicit shared-scope relations. `AnalyticalClaimCandidate` moves to `2.0.0` so human review
also confirms the business attribute or not-applicable component semantics. These meanings cannot
be inferred from v1/v2 data, so migration must remain blocked rather than guessing.

Phase 4D-0 introduces `CapitalAllocationEventCandidate` and
`CapitalAllocationEventReviewDecision` at `1.0.0`. `CapitalAllocationEvent`,
`CapitalAllocationOutcome`, and `CapitalAllocationReview` move to `2.0.0`. Their v1 parallel Fact
arrays and unversioned event keys cannot prove economic identity, reviewed role semantics,
lifecycle evidence, reviewed absence, or official-source search coverage. No automatic v1-to-v2
migration exists: an old object must be re-reviewed from its official source or remain blocked.

Phase 4D-1 changes `CapitalAllocationEventCandidate` to `2.0.0`. Candidate v1 did not record the
reviewed announcement date, execution period, or growth classification, so a compiler could not
replay lifecycle and organic/inorganic gates from the human-reviewed object. Those fields must not
be inferred from an Event or filing date. V1 Candidates require a new source-backed Candidate and
human Decision, or remain blocked.

Phase 4D-2 adds `currency_per_share` to the registered Fact v2 units. This is backward compatible:
existing v2 Facts retain their meaning, while new per-share Facts require an ISO currency and may
only enter registered unit-safe calculations.

Phase 4E-0 introduces `ResearchBundle 1.0.0`. Its nested ModuleReference,
FreshnessAssessment, and ScopeReference definitions are part of that public contract rather than
separate contract domains. The Bundle is validation-only and binds current module objects,
deterministic source/dependency hashes, the component lock, and a same-issuer/cutoff RunManifest.
