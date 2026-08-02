# Roadmap

## Active authority

- `Phase 5 v1 market-reference vertical slice` is `in_progress` under ADR 0041 and
  `docs/phase5-v1-status.json`.
- Only `PR1 market-reference vertical slice` is authorized. It must deliver one bounded,
  end-to-end market-reference slice without adding valuation execution, scoring, reporting, or
  publishing.
- Required pull-request checks are exactly `verify (3.11)`, `verify (3.12)`, `verify (3.13)`, and
  `phase5/semantic-audit`. Pull requests require P0=P1=0; release candidates require
  P0=P1=P2=P3=0; merged `main` runs smoke and deterministic replay.
- The former recursive G1-G5 and acceptance-only path is retired as `legacy_governance`. Its
  status, closeouts, and tests remain frozen historical evidence and run only by explicit manual
  replay.

## Historical phase record

- Phase 1: public research contracts, frozen at `v0.1.0-alpha.1`.
- Phase 2: quarterly vertical slice, frozen at `v0.2.0-alpha.1` / `feac934`.
- Phase 3: frozen at `v0.3.0-alpha.1` / `41dcb27`; SEC filing intake, evidence promotion,
  reportable segments, footnotes, and accounting-quality findings.
- Phase 4A: accepted and closed at merge `a70c4e7`; no release tag.
- Phase 4B-0: completed at PR #8; hardens Fact units, measurable target roles, registered policies, outcome
  roles, and withdrawn/superseded review semantics before production implementation.
- Phase 4B-1: completed at PR #9; official-source Candidate intake and human-confirmed Statement ledger.
- Phase 4B-2: completed at PR #10; deterministic Commitment compiler and lifecycle transitions.
- Phase 4B-3: completed at PR #11; deterministic ten-policy Outcome evaluator and comparability gates.
- Phase 4B-4: completed at PR #12; Phase 4B is accepted and closed at `e4fd317` with no tag.
- Phase 4C-0: completed at PR #13; business-quality contracts, external-context isolation,
  analytical Claim review, mechanism roles, component coverage, lifecycle, and trend semantics.
- Phase 4C-1: completed at PR #14; governed competitive-context sources, confirmed observations,
  and fail-closed context snapshot construction.
- Phase 4C-2: completed at PR #15; source-backed business-model construction with material-scope
  and explicit attribute coverage.
- Phase 4C-3: completed at PR #16; assumption-free deterministic mechanism diagnostics.
- Phase 4C-4: completed at PR #17; human-reviewed analytical Claims and deterministic hypothesis
  status.
- Phase 4C-5: completed at PR #18; code-built BusinessQualityReview, three fixed-cutoff
  metadata-only shadows, Skill references, and Phase 4C closeout. Phase 4C is accepted and closed
  with no release tag.
- Phase 4D-0: completed with no release tag; Candidate review, v2 capital-allocation contracts,
  economic-event identity, policy registries, lifecycle, evidence roles, and ContractGraph gates.
- Phase 4D-1: completed at PR #20 / merge `8bbdd4c`; official-source selection, source-backed
  Candidate v2, human review, economic-event deduplication, and versioned lifecycle compilation.
- Phase 4D-2: completed at PR #21 / merge `7fb2b3d`; registered assumption-free cash,
  consideration, financing, liquidity, dividend, and share-conservation bridges.
- Phase 4D-3: completed at PR #22 / merge `4308306`; deterministic lifecycle and evidence-state
  CapitalAllocationOutcome evaluation.
- Phase 4D-4: completed at PR #23 / merge `0407c41`; code-built CapitalAllocationReview and
  fixed-cutoff metadata-only shadows.
- Phase 4D-5: accepted/frozen closeout; carryover activity windows, machine-readable
  SourceSearchReceipt coverage, deterministic Review v3 replay, and consistent phase state.
- Phase 4E-0: accepted/closed with no release tag; `ResearchBundle 1.0.0`, validation-only
  integration policy, deterministic source/dependency hashes, current-object and material-scope
  gates, component-lock replay, and RunManifest binding.
- Phase 4E-1: accepted/closed with no release tag; deterministic current-module Bundle builder,
  atomic RunManifest output binding, idempotent replay, and fail-closed ambiguity handling.
- Phase 4E-2: accepted/frozen closeout at `v0.4.0-alpha.1`; deterministic atomic materialization
  and strict reload of the Bundle/RunManifest pair, complete/partial/blocked end-to-end replay,
  exact-head audit, and release gates. Phase 4 and Phase 4E are frozen.
- Phase 5P: accepted/closed planning boundary with no release tag; fixes the research-to-kernel
  ADR, exact interface and failure-mode matrices, price-blind boundary, sequential Phase 5A-5F
  plan, and read-only planning audit. Only Phase 5A contract work is authorized next.
- Phase 5A: accepted/closed contract boundary with no release tag; four public
  handoff/market/assumption-review contracts, immutable types, exact anti-anchoring state
  transitions, and validation-only ContractGraph gates.
- Phase 5B-0: accepted/closed mapping-policy boundary with no release tag; five closed registries,
  immutable internal mapping/readiness types, reason codes, fixtures, and audit `2.0.0`.
- Phase 5B-1: accepted/closed raw-Fact compiler boundary with no release tag; strict Bundle/graph
  replay, official SourceRef compilation, deterministic units/periods, conflict gates, pinned
  FactLedger Schema validation, and audit `2.0.1`.
- Phase 5B-2: accepted/closed derived-lineage boundary with no release tag; registered quarterly
  single-quarter/TTM outputs, replayed fingerprints, direct parents, single-source evidence,
  controlled derivations, and audit `2.0.2`.
- Phase 5B-3: accepted/closed company-routing and method-readiness boundary with no release tag;
  official SIC identity, current material scope, reviewed specialist Claims, six routing
  assessments, independent McKinsey/Penman role coverage, and audit `2.0.3`.
- Phase 5B-4: accepted/closed replay boundary with no release tag; eight routing goldens,
  byte-identical and history-independent replay, amendment selection, unversioned-conflict
  blocking, complete reviewed-Claim closure, and exact-head audit `2.0.4`.
- Phase 5B: accepted/closed deterministic FactLedger mapping and separate McKinsey/Penman
  readiness.
- Phase 5C-0: accepted/closed with no release tag; ADR 0026, closed accounting,
  quality, MethodView, nine-role equity-bridge, de-duplication, and successor-readiness registries,
  immutable internal types, adversarial fixtures, exact-head audit `2.1.0`, and governance closeout
  audit `2.1.0.1`.
- Phase 5C-1: accepted/closed accounting-reconciliation implementation under exact-head audit `2.1.1`; the sole
  internal compiler strictly reloads the Bundle pair, replays Phase 5B, derives the registered
  accounting perimeter and owner flows, and recomputes all three controls.
- Phase 5C-2: accepted/closed accounting-quality and assumption-free adjustment implementation
  under exact-head audit `2.1.2`.
- Phase 5C-3: accepted/closed deterministic MethodView and cross-channel root-consumption
  implementation through PR #40, merge `a6c6d85ae062...`, main CI `29271863942`, and audit `2.1.3`.
- Phase 5C-4: accepted/closed deterministic nine-role equity-bridge implementation through PR #41,
  merge `f16595e50f6d...`, main CI `29273390412`, and exact-head audit `2.1.4`.
- Phase 5C-5: accepted/closed deterministic successor-readiness and replay closeout through PR #42,
  merge `0ad92bb3206b...`, main CI `29274820514`, and exact-head audit `2.1.5`.
- Phase 5C: accepted/closed after governance audit `2.1.5.1`; Phase 5D assumption governance and
  price-blind freeze work is authorized, while Phase 5E and later remain prohibited.
- Phase 5C: deferred completion of accounting checks, method views, and all nine equity-bridge
  roles across the authorized sequential PRs.
- Phase 5D-0: accepted/closed through PR #44, merge `4814029d9c5a...`, main CI `29295736044`,
  Candidate/Handoff v2, closed assumption slots, supplemental price-blind reference closure,
  protected-hash policy, and validation-only audit `2.2.0`.
- Phase 5D-1: accepted/closed through implementation PR #46, acceptance PR #47, merge
  `7c13073aa70a...`, main CI `29297468611`, and audit `2.2.1`; internal price-blind Candidate
  compilation has deterministic IDs, full Phase 5C replay, and typed evidence gates. Phase 5D-2
  through 5D-6 remain sequentially
  deferred until the preceding merge, main CI, and exact-head
  audit pass. They will add Candidate compilation, human Decision resolution, McKinsey inputs,
  Penman inputs, canonical price-blind freeze, and governance closeout respectively.
- Phase 5D-2: accepted/closed through PR #49, merge `43fffa76d3eb...`, main CI `29299088854`,
  and audit `2.2.2`; named-human Decision resolution, deterministic reserved assumption IDs,
  supplemental evidence-Fact augmentation, and pinned AssumptionLedger compatibility stop before
  method-input compilation or persistence.
- Phase 5D-3: accepted/closed through PR #51, merge `dcbc5d5bbbb6...`, main CI `29300664978`,
  and audit `2.2.3`; compiles exactly four price-blind McKinsey scenario reference blocks on one
  annual timeline, derives current base invested capital, and runs only the pinned steady-state
  preflight. It stops before Penman inputs, persistence, market access, request/result construction,
  or valuation mathematics.
- Phase 5D-4: accepted/closed through PR #53, merge `e3ef484f42ca...`, main CI `29302120207`,
  and audit `2.2.4`; compiles only governed price-blind Penman near-term forecast, primary hurdle
  and hurdle/growth grids, and challenge-path input references. It reads no market data, runs no
  reverse-price analysis, persists no artifact, and invokes no valuation mathematics.
- Phase 5D-5: accepted/closed through PR #55, merge `a63e3dcb5c57...`, main CI `29303730712`,
  and audit `2.2.5`; freezes one canonical price-blind input, replays strict persistence/reload,
  protects both method subtrees, and advances only adjacent Handoff states.
- Phase 5D-6: accepted/closed through PR #57, merge `38be7b66ea20...`, main CI `29305219309`,
  and audit `2.2.6`; deterministic replay, clean-room closeout, goldens, and final governance
  freeze Phase 5D with no market or valuation capability.
- Phase 5E-0: accepted/closed under audit `2.3.0`; defines only closed market timing,
  single-security, point-in-time-share-basis, final-request preservation, and isolated pinned-wheel
  policies plus immutable internal records. It performs no network access or valuation operation.
- Phase 5E-1: original engineering boundary accepted under audit `2.3.1`.
- Phase 5E-1.1: accepted/closed under audit `2.3.1.1`; pins the Provider, raw parser, explicit
  2026 XNYS/XNAS calendar datasets, and evidence-bound security identity to the component lock.
- Phase 5E-2A: original PR/CI boundary passed under audit `2.3.2`.
- Phase 5E-2A.1: accepted/closed under audit `2.3.2.1`; replaces the caller-provided dilution-root
  witness with a frozen Phase 5C replay and aligns the public/Python decimal domain.
- Phase 5E-2A.2: accepted/closed after a separate governance closeout; pins the complete
  annotated rc.2 kernel identity and changes the sole Snapshot contract to current-common-share
  evidence with numeric lineage separated from dilution-claim control under audit `2.3.2.2`.
- Phase 5E-2A.2.1: recursive current-share numeric roots, cutoff-safe sources, all-family activity
  search coverage, canonical event concepts, and completed-claim transitions are accepted/closed
  as a validation-only boundary under audit `2.3.2.2.1`.
- Phase 5E-2B: the internal compiler strictly replays the frozen identities, owns current-share
  path selection, derives direct/issued-less-treasury/roll-forward evidence, and fails closed on
  conflicts. Implementation and the separate acceptance closeout remain historical governance
  records under audit `2.3.2.3`.
- Phase 5E-2B.1: corrective semantic closeout for cross-source share-event identity. Step 0 adds
  only policy, immutable internal records, red fixtures, and the baseline vulnerability oracle
  under audit `2.3.2.3.1`. Step 1 production grouping is accepted/closed under audit
  `2.3.2.3.2`. Step 2A defines immutable canonical-event, exactly-once consumption,
  group-bound coverage/Claim-transition, Bundle-binding, and recursive-closure contracts under
  audit `2.3.2.3.3`; its pre-acceptance semantic correction also requires exact per-category
  coverage, unique category/security-specific N/A review chains, direct-Fact and cutoff-safe
  evidence, graph-byte-bound coverage/transition objects, duplicate typed-evidence rejection,
  specialist deferral for convertible/warrant transitions, exact source-byte code identity,
  independent JUnit/node-ID replay, official-occurrence collision detection, official/high opening
  roots, multi-root-Claim blocking, generated-ID reservations, exact one-chain transitions, and a
  credential-partitioned acceptance gate whose candidate execution is secret-isolated and whose
  introduction is independently audited before it becomes
  base-owned. The resulting two-file closeout, special branch, and successor prohibitions are
  retained as historical `legacy_governance`; ADR 0041 supersedes them as current authority.
- Phase 5F: strict handoff archive, Shadow, final audit, and proposed `v0.5.0-alpha.1` release.
- Phase 6: Buffett-Munger-style scoring, always marked `PROJECT_EXTENSION`.
- Phase 7: Publisher consuming only validated research and valuation outputs.
- Phase 8: multi-company shadow runs judged by audit quality, not target-price proximity.
- Phase 9: legacy cleanup only after coverage acceptance.
- Phase 0.5: archive-only recovery verification immediately before local Legacy deletion.

Phase 4B stops at deterministic ManagementReviews and metadata-only shadows. Phase 4C ends at
governed context intake, descriptive business models, registered diagnostics, human-reviewed
Claims, deterministic hypotheses, code-built coverage Reviews, and metadata-only shadows.
Phase 4E-1 builds and validates Bundles. Phase 4E-2 writes and reloads only the validated canonical
two-file pair; it does not publish, orchestrate, value, score, or report. Phase 5P is planning and
interface audit only. Phase 5A, Phase 5B, Phase 5C, and Phase 5D-0 through Phase 5D-6 are
accepted/closed. Phase 5D is accepted/frozen; Phase 5E-0 and Phase 5E-1.1 are accepted/closed.
Phase 5E-2A.1, Phase 5E-2A.2, and Phase 5E-2A.2.1 are accepted/closed. Phase 5E-2B and its
Phase 5E-2B.1 corrections retain their original governance evidence. The former dual-state gate,
G1-G5 progression, dynamic successor profiles, and acceptance-only branches are now historical
`legacy_governance`; none can authorize or block the current Phase 5 v1 slice. Phase 6 through
Phase 9 still require separate reviewed authorization after Phase 5.
