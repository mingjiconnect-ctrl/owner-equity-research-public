# ADR 0042: Phase 5 v1 final request and pinned-kernel slice

Status: accepted for implementation

## Context

PR1 is accepted on merged `main` and ends at a validated reviewed-file market reference. Phase 5
still needs one complete valuation request and one reproducible invocation of the fixed
`owner-valuation-kernel v2.0.0-rc.2` without reopening market access or copying valuation math.

The rc.2 release evidence records wheel SHA-256
`fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5`, but the release did not
retain the wheel asset. An independent reconstruction proved that the exact bytes are reproducible
from the pinned source commit by the original build followed by one closed normalization of five
registered `.dist-info` ZIP timestamps. The kernel repository and release remain read-only.

## Decision

PR2 adds only internal deterministic request projection and isolated execution:

1. Consume the accepted `OwnerValuationPreparationResult`; never reacquire a quote.
2. Require market trading date, current-share date, and the frozen FactLedger valuation date to be
   identical. A prior-session quote for a non-trading-day cutoff is not silently relabelled.
3. Preserve every existing FactLedger SourceRef and Fact byte-for-byte. Append only the formally
   required current-share lineage, one market SourceRef, one quote Fact, and one derived
   market-equity Fact.
4. Preserve the canonical assumption-entry array byte-for-byte and update only its binding to the
   final FactLedger fingerprint.
5. Project authoritative Decimal evidence into rc.2 binary64 values with an explicit bit-level
   witness. Derived values replay the kernel operation order; tolerance, rounding, quantization,
   and independent re-projection of derived outputs are forbidden.
6. Validate the request against the eight pinned schemas and rc.2 public runtime types. Both panels
   use the same current-share Fact ID, and no model weighting is introduced.
7. Materialize the unavailable wheel only from the pinned commit under a closed build policy. Only
   the five registered ZIP timestamps may change, the byte-diff must match the registered oracle,
   and the final wheel SHA must equal the release evidence exactly. Store it outside the repository.
8. Execute one public `run_dual_panel` call in a fresh, hash-locked runtime with proven network
   denial. Preserve canonical stdout bytes unchanged; do not recalculate or rewrite the result.

`ValuationHandoff 2.0.0` remains a state-continuity contract, not execution authority. The rc.2
tag, commit, schemas, wheel, runtime manifest, runner, and isolation evidence are internal
execution authority bound by the component lock and receipts.

## Consequences

- Public Schema count remains 43 and all public Schema bytes remain unchanged.
- Python/Plugin version becomes `0.6.0.dev2 / 0.6.0-dev.2`.
- No package-root, CLI, implicit Skill, archive writer, live provider, Score, recommendation,
  report, PDF, Publisher, or Marketplace surface is added.
- Missing exact wheel bytes, runtime wheels, Linux network isolation, date alignment, or any
  projection invariant returns a blocked result rather than a weaker execution.
- PR3 remains unauthorized until this slice is merged, main CI succeeds, and independent semantic
  review reports P0=P1=0.
