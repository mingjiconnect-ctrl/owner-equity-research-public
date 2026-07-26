# Phase 5 completion overlay v1

Status: current planning authority; historical Phase 5P documents remain immutable evidence.

Baseline: research `4fd643df73108b1fa3ab3ce1eb258ae3c3ce8a6d`; kernel
`v2.0.0-rc.2 / be9b0773d5a78f5f8a33ba982494512668df85fe`; 43 public Schemas.

This overlay supersedes only stale planning assumptions in Phase 5P: rc.1, diluted-share market
denominators, and in-process kernel execution. It does not rewrite an accepted contract or closeout.

## Mandatory subphase loop

Every remaining subphase follows this sequence:

```text
latest accepted main
→ red tests and one implementation branch
→ local full verification
→ PR-head independent semantic audit
→ repair every P0-P3
→ merge and main CI
→ merged-main independent audit
→ acceptance-only PR
→ acceptance PR/main CI and exact-head no-remote read-only audit
→ P0=P1=P2=P3=0
→ authorize exactly one successor
```

The root agent is the only writer. Review agents are read-only and cannot use the production
compiler as their sole oracle. Any component-lock, Schema, Provider authority, Handoff, or
price-blind-input change invalidates all dependent artifacts and requires a new root run.

For Phase 5E-2B.1-2A, the implementation merge must freeze a base-owned acceptance gate before the
acceptance-only PR is opened. That gate runs from the protected implementation merge, never from
candidate-head code, has no secrets, pins its Action/runtime identities, and permits one direct
non-merge commit changing exactly the two regular governance files. It replays the same-repository
main implementation PR, exact PR/main workflow identity, exact four-file merged-main audit
evidence, all thirteen audit checks, the exact test node-ID inventory, and the complete audited
path/hash set. Test totals and code identities are derived from source bytes and independent JUnit
replay; self-reported minimum counts or semantic labels are not acceptance evidence.

The implementation documents use one immutable dual-state statement. Before the validated
two-file closeout exists, only the 2A acceptance closeout is authorized and 2B is prohibited.
After the base-owned gate validates that exact single-commit closeout, 2A is accepted/closed and
only 2B is authorized. Phase 5E-2C and later remain prohibited in both states. Post-merge
acceptance-gate and main-CI run evidence is retained externally because a closeout commit cannot
self-attest future runs.

For current-share integration, the public ResearchBundle closure remains immutable. Evidence that
is reviewed after Bundle freeze enters only through the separately versioned
`research-bundle-current-share-extension/1.0.0`; its roots, transitive dependencies, supporting and
counterevidence, source fingerprints, security identity, grouping result, and search receipts are
replayed from the current validated ContractGraph. This extension cannot silently broaden or
rewrite the public Bundle. Coverage has exactly one entry per registered category; every N/A
closure is category/security-specific and uses its own named-human review chain. Frozen Phase 5C
authority closes standard option transitions only. Coverage support is direct-Fact-only,
Candidate-safe, reviewed by cutoff, and every typed coverage/transition object is byte-bound to
the graph-owned Bundle closure. A category-specific N/A Candidate may follow the covered period
end through cutoff. Every Claim-transition evidence Fact period and formal source publication must
be no later than its Candidate and cutoff. Convertible and warrant transitions remain a specialist
route rather than being relabeled as option claims.

## Remaining authoritative sequence

1. Phase 5E-2B.1-2A through 2C and 2B.1-3: canonical Fact, exactly-once roll-forward, group-bound
   coverage/Claim transition, recursive closure, and acceptance.
2. Phase 5E-2C: exact Decimal and binary64 projection witness, raw replay, market SourceDocument,
   quote Fact, and exact market-equity CalculationResult. No Snapshot builder.
3. Phase 5E-2D/2E: deterministic Snapshot v4 construction and complete market-reference replay.
4. Phase 5E-2F: licensed XNAS Nasdaq Fundamental Data/NOCP and XNYS NYSE TAQ Closing Prices
   authority onboarding. Without licensed data and retention authority, release remains blocked.
5. Phase 5E-3: rc.2-compatible current-share lineage, final FactLedger, AssumptionLedger rebinding,
   valuation request v2, and adjacent Handoff transition.
6. Phase 5E-4: tag-CI wheel, hash-locked wheelhouse, digest-pinned Linux container with no network,
   one public `run_dual_panel` call, and byte-preserved result.
7. Phase 5E-5/6: adversarial replay and Phase 5E closeout.
8. Phase 5F: alpha pre-freeze, six-file archive, licensed Shadows, clean-room replay, full Phase 5
   semantic audit, correction loop, final acceptance, annotated tag, and tag CI.

## Fixed economic and governance boundaries

- ResearchBundle and all price-blind assumptions remain market-price blind.
- Real assumption decisions are made only by named human `human:mingji` before market access.
- McKinsey and Penman remain separate panels and are never weighted or averaged.
- Research preserves authoritative Decimal values. rc.2 receives only a deterministic binary64
  projection that exactly replays through the recorded witness; no tolerance or rounding is allowed.
- Phase 5 produces no Score, target price, recommendation, report, PDF, Publisher, or Legacy call.
- No Phase 5 release tag exists until the final clean-room audit reports all four priority counts at
  zero. A failed alpha tag is never moved; the correction releases alpha.2.
