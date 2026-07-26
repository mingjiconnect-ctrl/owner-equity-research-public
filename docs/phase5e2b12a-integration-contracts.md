# Phase 5E-2B.1-2A integration-contract boundary

Phase 5E-2B.1-2A is a contract-only subphase under
`canonical-share-event-current-share-integration/2.0.0`.

## Inputs frozen from Phase 5E-2B.1-1

- one `ShareEventGroupingResult`;
- its canonical groups and reserved derived-event Fact IDs;
- every reviewed `ShareEventEvidenceMember`;
- the immutable public ResearchBundle and RunManifest dependency closure;
- an exact, versioned post-Bundle current-share extension rooted only in graph-owned reviewed
  evidence; and
- the fixed `cross-source-share-event-grouping/1.0.0` identity policy.

## New internal records

- `CanonicalShareEventMemberBinding`
- `CanonicalShareEventFactMaterialization`
- `ShareEventNumericConsumption`
- `CorporateActionCoverageEntryV2`
- `CorporateActionCoverageLedgerV2`
- `GroupBoundDilutionClaimAuthority`
- `GroupBoundClaimTransition`
- `GroupBoundClaimTransitionReconciliation`
- `CurrentShareBundleEvidenceClosure`
- `CurrentShareEvidenceClosureV2`

All records are frozen, closed, canonically ordered, and fingerprinted. None is a public contract.

## Required invariants

1. The canonical event Fact ID must equal the ID reserved by the reviewed identity fingerprint.
   A graph Fact at that ID is accepted only when it byte-equals the canonical Fact independently
   derived by the bound materialization authority; a synchronously re-signed caller binding cannot
   redefine those bytes. The reserved output-share ID must be completely unoccupied. The
   independent collision domain
   `(issuer, security, official legal event ID, legal effective date)` prevents a drifting reviewed
   `economic_event_key` from splitting one official occurrence into multiple numeric groups.
2. Its immediate parents are all and only the corroborating raw event Facts.
3. The roll-forward consumes each canonical group exactly once and has no raw event Fact as a
   direct parent.
4. Coverage binds every group to the category registered for its event concept, retains every
   typed member Fact and SourceDocument, and proves each observed source was returned by the
   matching one of eight closed, authority-bound official-source searches. The ledger contains
   exactly one entry for each registered category. A not-applicable entry has the canonical
   category/security statement, empty issuer-wide business scope, direct-Fact-only evidence dated
   and published no later than the Candidate, whose date is no earlier than the covered period end
   and no later than cutoff, and a unique Candidate/named-human Decision/Claim chain reviewed no
   later than cutoff; support and counterevidence are governed identically, and the chain cannot
   close another category. Binding IDs are
   unique across both evidence polarities. All typed coverage objects must match the graph-owned
   Bundle closure by ID and fingerprint. Typed Bundle and security-evidence objects reject
   duplicate cardinality hidden by set equality.
5. Standard option transitions bind the canonical group and an authority replayed
   from the exact full price-blind freeze and current validated ContractGraph. The current
   component lock, one unique current unsuperseded graph-owned v1-v4 Handoff chain,
   Bundle/RunManifest, and each Phase 5C root Fact/formal Source/Candidate/named-human
   Decision/Claim must all replay. A synchronized artifact
   and Handoff resign is insufficient. Typed review arrays reject duplicate IDs and must correspond
   exactly to the binding set, and each typed object is referenced by exactly one binding. Confirmed
   bindings require Candidate, named-human confirmed Decision, and Claim; blocked bindings require
   Candidate and named-human blocked Decision and omit Claim. Root-Fact concepts determine the
   economic identity; a blocked binding or positive option claim marked not-applicable cannot enter
   the eligible standard path. Every binding's semantic chain is
   replayed against the current graph; every
   consumption root/key/identity resolves to its reviewed binding,
   and each excluded option root permits only its exact registered bridge deduction.
   Each transition review is an exact, cutoff-safe Candidate/Decision/Claim projection and every
   typed transition Fact, source, Claim, Candidate, and Decision is byte-bound to the graph-owned
   Bundle closure. Each initial root uses its exact human-reviewed Phase 5C `economic_claim_key`.
   Because this boundary has no graph-owned aggregate opening-balance Fact, more than one root for
   the same economic Claim is blocked rather than allowing a caller to consume only one component.
   Each supported transition has exactly one Candidate, one named-human Decision, and one Claim in
   a non-branching, date-ordered lineage. Completed convertible and warrant transitions are outside the frozen
   Phase 5C option authority and therefore require a specialist route; this contract rejects any
   attempt to relabel them as generic option roots.
6. The recursive numeric graph is acyclic, contains no dangling or extra edge, and has exactly the
   output-to-opening-and-canonical plus canonical-to-corroborating-raw parent relations. It
   terminates exactly at the opening Fact and corroborating raw event Facts. The opening Fact and
   its source must be raw, official-primary, and high confidence; the output points to that same
   official SourceDocument, remains high confidence, and cannot inherit a medium-confidence root.
7. Every reviewed Candidate, Decision, Claim, supporting Fact, counterevidence Fact, and source
   content fingerprint is in the exact recursive extension closure.
8. Security identity and grouping are replayed against the current validated ContractGraph;
   caller-supplied stale groupings or self-attested security objects are rejected.
9. Canonical Fact primary-source selection is deterministic and input-order independent.
10. No evidence after cutoff, outside the issuer/security, outside the immutable public Bundle
    closure, or outside its governed post-Bundle extension is eligible.
11. The authority carries a stable evidence-subclosure fingerprint. Every object in that
    subclosure must occur byte-identically in the outer `CurrentShareBundleEvidenceClosure`. Its
    post-Bundle traversal uses a closed target-typed edge registry, so an ID-like string cannot
    cross contract domains or invent a dependency. The outer closure replays the full authority
    against its own validation graph. The Bundle graph fingerprint covers
    only this exact scoped dependency set plus the component lock. This prevents authority
    transplant without making unrelated graph history change the result.
12. Materialization code identity is the SHA-256 of the exact validation-module source bytes.
    Acceptance uses an executable independent arithmetic/hash oracle, an exact adversarial
    case-to-expected-result registry, an independently collected and replayed test inventory, and
    an every-PR-classifying same-repository main-only acceptance gate that executes no
    candidate-head code in a credential-bearing job, gives candidate execution no Actions or
    environment secret, prevents non-acceptance branches from changing the
    pending acceptance trust root, pins every Action/runtime identity, accepts one direct non-merge
    commit changing exactly two governance files, and replays the exact four-file audit evidence,
    thirteen evidence-bearing checks, complete total-count-bound Actions pagination, exact
    PR-head/base and acceptance-head/base CI associations, exact workflow file/ref/ID/name/active
    state, and exactly one completed successful acceptance run for that association. The initial
    gate introduction is a one-time trust bootstrap and therefore cannot retroactively certify
    itself; its implementation PR requires an independent read-only audit and external repository
    review. Only the later acceptance-only PR is certified by the now base-owned gate. After 2A
    acceptance, the historical gate, verifier, and closeout stay permanently immutable. The 2B
    verifier, trust snapshot, semantic oracle, and gate tests are already installed and frozen by
    2A; the exact 2B branch can change only compiler, dedicated test, and state. Evidence uses
    the pinned pytest JUnit grammar with zero failures, errors, and skips and one unique node ID per
    testcase, canonical governance JSON, closed typed canonical evidence JSON, the complete audited
    path/hash set, merged-main tree equality with the acceptance head, and merged-main provenance.

Every Claim-transition direct evidence Fact period and formal SourceDocument publication must be
no later than its Candidate and the data cutoff. A category-specific N/A Candidate may be confirmed
from the covered period end through the data cutoff; this positive window does not relax the
Candidate-safe support and counterevidence, named-human Decision, or exact Claim-projection
requirements.

The extension does not mutate `ResearchBundle`. It is a separately identified and hashed closure
whose roots and transitive dependencies are recomputed from the current ContractGraph. A missing
or extra object, changed source content hash, unregistered search endpoint/tool, or stale grouping
invalidates the integration record.

## Deferred

No production Fact is created in 2A. No existing compiler, coverage ledger, Claim transition, or
Snapshot validation path is changed. Before the validated two-file closeout exists, only the 2A
acceptance closeout is authorized and 2B is prohibited. After the base-owned gate validates that
exact single-commit closeout, 2A is accepted/closed and only 2B is authorized. Phase 5E-2C and
later remain prohibited in both states. The implementation and acceptance PRs must pass exact-head
semantic audit `2.3.2.3.3` with `P0=P1=P2=P3=0`.

## Recursive successor handoff

The legacy S3 state may install only the exact inert next gate. Thereafter the protected-base
controller repeats G1 (inert gate), G2 (accepted gate), G3 (successor pending acceptance), G4
(successor accepted), and G5 (total closeout with the exact next-gate seed). Dynamic profiles bind
the deepest validated gate and candidate oracle content stays inert. `Phase 5E-2B.1-2C` denotes
current-share coverage/Claim-transition/recursive closure; `Phase 5E-2C` denotes exact market
evidence. Phase 6 through Phase 9 remain outside this map. The public canonical repository has
pinned Controller, Gate Author, and kernel-only Reader Apps; external acceptance remains blocked
until their protected environments, exact main protection, CI, and P0-P3-zero audits verify the
separately administered authority.

Phase 5 current authority: S3 -> G1 -> G2 -> G3 -> G4 -> G5 -> external 2C-P; after feasibility a new protected gate is required; Phase 6-9 require separate reviewed control-plane authorization; Phase 5E-2B.1-2C != Phase 5E-2C.
