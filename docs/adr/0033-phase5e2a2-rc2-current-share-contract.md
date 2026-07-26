# ADR 0033: rc.2 current-common-share market-reference boundary

## Status

Accepted for Phase 5E-2A.2 implementation. This ADR is `PROJECT_OPERATIONALIZATION` and does
not alter either source book or the frozen valuation kernel.

## Context

`MarketReferenceSnapshot 2.0.0` uses a point-in-time fully diluted denominator and requires the
frozen Phase 5C diluted-share roots to be numeric ancestors. The accepted and frozen
`owner-valuation-kernel v2.0.0-rc.2` instead distinguishes current common shares outstanding from
the specialist conversion-value diluted path. The kernel's standard request requires
`share_denominator_kind=current_common_shares_outstanding` and one of three closed evidence kinds.

Fully diluted shares and current shares outstanding are different economic quantities. A field
rename or automatic migration would silently move option and conversion claims between the share
denominator and the McKinsey equity bridge.

## Decision

1. Pin the complete immutable rc.2 release identity in component-lock `1.2.0`, including the
   annotated tag object and peeled commit.
2. Hard-break `MarketReferenceSnapshot 2.0.0` to `3.0.0`; do not migrate or dual-write v2.
3. Use `current_common_shares_outstanding` and exactly one evidence kind:
   `direct_point_in_time`, `issued_less_treasury`, or `completed_event_rollforward`.
4. Compute market equity as official unadjusted close multiplied by quote-date current common
   shares outstanding.
5. Treat Phase 5C dilution authority only as claim-control lineage:
   - `excluded` claims remain separately modeled in the equity bridge and cannot enter current-
     share numeric lineage;
   - `included` claims route `specialist_required` and cannot form a validated Snapshot v3;
   - `blocked` claims block Snapshot validation.
6. Preserve one canonical current-share Fact as the future Penman market-equity parent and the
   future McKinsey request-v2 share denominator.

## Evidence-path semantics

- `direct_point_in_time`: a raw `common_shares_outstanding` Fact on the quote date, with no parents
  or derivation.
- `issued_less_treasury`: a deterministic current-share Fact whose only numeric inputs are same-
  date, same-security `common_shares_issued` and `treasury_shares`; the exact difference replays.
- `completed_event_rollforward`: a deterministic current-share Fact from an earlier current-share
  Fact plus only registered, legally completed issuance, repurchase, cancellation, exercise, RSU
  settlement, or conversion events through the quote date.

Weighted-average EPS shares, basic-share shortcuts, authorized/reserved shares, unexercised
options, unsettled awards, and unconverted instruments are never standard current shares.

## Boundary

Phase 5E-2A.2 remains validation-only. It adds no share compiler, market-evidence generator,
Snapshot builder, final-request compiler, kernel invocation, writer, report, score, or publisher.
Phase 5E-2B remains prohibited until a separate governance closeout records the implementation
merge, CI, exact-head audit, component lock, and Schema hashes.
