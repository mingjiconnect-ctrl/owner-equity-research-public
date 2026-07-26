# ADR 0039: Phase 5E-2B.1-2A semantic trust boundaries

Status: implementation complete pending independent acceptance

## Context

The first integration-contract implementation proved canonical arithmetic and typed lineage, but an
independent review identified trust inputs that could still be caller-attested: grouping freshness,
security identity, search endpoint/tool authority, observed-source coverage, Claim-transition
authority, primary-source choice, and the recursive inclusion of counterevidence and source content
fingerprints.

The public `ResearchBundle` is immutable and price blind. Current-share evidence can arrive after
that public bundle was frozen, so rejecting every post-Bundle object would make governed current
shares impossible; silently accepting arbitrary additions would destroy the bundle boundary.

## Decision

The public Bundle dependency closure remains byte-for-byte immutable. Phase 5E uses a separate
`research-bundle-current-share-extension/1.0.0` closure whose roots are derived from graph-owned
current-share evidence and whose complete transitive dependencies are recomputed from the current
validated `ContractGraph`.

The integration validator additionally:

- replays the production cross-source grouping against that exact graph and reconstructs the
  security identity from its formal Facts and human-reviewed Claim chain, rather than trusting a
  synchronously rewritten result. The separate official-occurrence collision domain blocks one
  official legal ID/effective date from being split by drifting reviewed economic-event keys;
- binds eight source-family searches to closed endpoint IDs, a fixed tool version, deterministic
  receipt identity, and each observed SourceDocument;
- requires exactly one coverage entry for each of the twelve registered categories. A reviewed
  not-applicable entry uses the exact category/security statement, an empty issuer-wide business
  scope, direct-Fact-only formal support and counterevidence available no later than the Candidate
  date, a Candidate dated no earlier than the covered period end, and one
  Candidate/named-human Decision/Claim chain reviewed no later than the data cutoff that may not
  be reused by another category. Binding IDs are unique across support and counterevidence.
  Every typed coverage source, receipt, zero/observed/support/counterevidence Fact, Candidate,
  Decision, and Claim
  must match the graph-owned Bundle object by both ID and fingerprint. Typed Bundle
  SourceDocuments and security-evidence Fact, source, and object identities also have exact
  cardinality rather than set-only equality;
- selects a canonical Fact primary source by a deterministic authority/date/identity ordering;
- derives sensitive-transition authority only from the exact graph-owned
  `PriceBlindFreezeCompilationResult`: the current component lock, immutable Bundle/RunManifest,
  one unique current unsuperseded adjacent v1-v4 Handoff chain, frozen assumption reviews, and
  every Phase 5C root Fact, formal
  SourceDocument, Candidate, named-human Decision, and Claim are replayed against the current
  validated `ContractGraph`; a self-consistent artifact or synchronized artifact/Handoff resign is
  not authority;
- rejects duplicate or conflicting typed Phase 5C Candidate/Decision/Claim identities, requires the
  typed arrays to match all economic-claim bindings exactly with each typed object referenced by
  one and only one binding, requires confirmed bindings to retain Candidate, named-human confirmed
  Decision, and Claim while blocked bindings retain Candidate and named-human blocked Decision but
  no Claim, derives each economic identity from its registered root-Fact concepts, rejects blocked
  bindings and positive option claims marked not-applicable on the eligible path, and replays every
  binding's semantic review chain against the current graph; requires each consumption
  root/key/identity to resolve to its reviewed binding, and permits only the exact registered bridge
  deduction for each excluded option root;
- replays the authority again inside the `CurrentShareBundleEvidenceClosure` against that exact
  closure's validation graph, rather than trusting an authority validated against another graph;
- preserves the reviewed Phase 5C `root Fact -> economic_claim_key` mapping and blocks a
  multi-root economic Claim until one graph-owned aggregate opening-balance Fact exists. It binds
  the canonical event Fact and enforces one lineage per reviewed economic Claim through exactly
  one Candidate, one named-human Decision, and one Claim whose projection is exact and cutoff-safe.
  Every typed
  transition Fact, source, Claim, Candidate, and Decision must occur byte-identically in the
  graph-owned Bundle closure. The standard path is limited to the frozen Phase 5C
  option-or-dilution authority;
  completed convertible and warrant events require a separately authorized specialist route and
  cannot be silently relabeled as option roots; and
- includes Candidate support, counterevidence, every source fingerprint, and every typed transition
  dependency in the exact recursive extension closure. The extension follows a closed target-typed
  edge registry, while the numeric lineage permits only its exact deterministic parent edges;
- accepts a graph Fact at a reserved canonical Fact ID only when it byte-equals the independently
  derived materialization authority, rejects caller-rewritten bindings and any occupied
  output-share Fact ID, and requires the raw opening Fact plus official source and output Fact to
  remain high confidence; the output must retain the same official SourceDocument as the opening
  root.

The graph fingerprint is scoped to the exact validated Bundle dependency and governed extension
objects plus the component lock. Unrelated graph history is intentionally excluded, so adding an
unreferenced historical object cannot change the closure SHA.

Any stale grouping, changed source content, omitted counterevidence, unregistered search authority,
cross-issuer/security evidence, future evidence, or extra unrelated object invalidates the record.

The audit trust root is independent of caller attestations:

- `materialization_code_sha256` is the SHA-256 of the exact validation-module source bytes, not a
  semantic label selected by the implementation;
- the semantic oracle independently canonicalizes and hashes the production baseline, checks the
  hand-calculated `100,000,000 - 5,000,000 = 95,000,000` result, executes every registered
  adversarial case through its bound production test, and pins the complete case/expected-result
  registry;
- the read-only audit independently collects the exact test node IDs, runs a second full JUnit
  suite, requires the executed JUnit node IDs to equal that collection, and requires the fixed
  count and node-ID hash to match the implementation audit; and
- the acceptance-only PR is checked by a base-owned, read-only, credential-partitioned workflow.
  Candidate execution receives no Actions/environment secret or private-kernel credential;
  protected Controller jobs use the Controller App credential, and the separate kernel-interface
  job uses a second GitHub App installed only on the private kernel repository with exactly
  `contents: read` and `metadata: read`. Its short-lived token is verified before checkout and the
  job never executes candidate code. The PR that
  first introduces this trust root cannot retroactively self-certify: it requires a separate
  independent read-only audit and external repository review as the explicit bootstrap. Once on
  `main`, the workflow classifies
  every same-repository PR, materializes the candidate only as a local Git-object source, and never
  executes candidate-head code. Non-acceptance branches cannot change the pending closeout's
  status, evidence, workflow, audit, writer, or test-identity trust root. The acceptance branch is
  one direct non-merge commit changing exactly two regular governance files. The gate replays the
  same-repository main implementation PR; exact PR-head/base and acceptance-head/base
  associations; the exact workflow file, ref, numeric identity, name, and active state; complete
  total-count-bound pagination; and exactly one completed successful acceptance run. Its four
  root-level evidence files use closed canonical finite duplicate-key-free JSON with exact integer
  types, all thirteen checks and their evidence hashes, and the pinned pytest JUnit grammar
  (`testsuites -> testsuite -> testcase -> properties -> property`) with zero failures, errors, and
  skips and one unique executed node ID per testcase. Post-merge acceptance also requires the
  merged-main tree to equal the acceptance-head tree before replaying canonical governance JSON,
  the complete audited implementation-tree path/hash set, and GitHub provenance.
  Every Action and runtime identity in the pending trust root is immutable. After acceptance, the
  historical workflow, verifier, and closeout remain permanently immutable. Phase 2A preinstalls
  and byte-locks the 2B verifier, trust snapshot, semantic oracle, and gate tests. The only
  authorized 2B implementation branch may modify exactly the compiler, its dedicated production
  test, and machine state; it cannot install or modify its own judge. Shared CI, audit, writer, and
  test-inventory governance stay frozen.

Claim-transition evidence has the same temporal authority as coverage evidence: every direct
support or counterevidence Fact period and formal SourceDocument publication must be no later than
the Candidate and data cutoff. A category-specific N/A Candidate may legitimately be confirmed
from the covered activity period end, provided its support and counterevidence are Candidate-safe
and the Candidate, Decision, and Claim all remain no later than the data cutoff.

## Boundary

This ADR authorizes validation-only internal contracts. It adds no public Schema and no builder,
compiler, market evidence, Snapshot, request, writer, network access, or kernel invocation. Before
acceptance, Phase 5E-2B.1-2B and every part of Phase 5E-2C remain prohibited. A separate
acceptance-only PR plus merged-main audit at `P0=P1=P2=P3=0` may authorize only
Phase 5E-2B.1-2B; every part of Phase 5E-2C remains prohibited until its own later gate.
