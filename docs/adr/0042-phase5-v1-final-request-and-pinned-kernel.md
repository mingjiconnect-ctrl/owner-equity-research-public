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
6. Resolve the company display name only from one cutoff-safe official text Fact in the bound
   ResearchBundle closure, and resolve the market publisher only from the governed provider
   receipt. Issuer IDs and quoted-security subjects are not substituted for either provenance
   field.
7. Validate the request against the eight pinned schemas before execution. The pinned runtime
   types are loaded only from the verified wheel inside the isolated runtime, never from a mutable
   source checkout in a network-capable subprocess. Both panels use the same current-share Fact ID,
   and no model weighting is introduced.
8. Materialize the unavailable wheel only from the pinned commit under a closed build policy. Only
   the five registered ZIP timestamps may change, the byte-diff must match the registered oracle,
   and the final wheel SHA must equal the release evidence exactly. Store it outside the repository.
9. Execute one public `run_dual_panel` call in the pinned Linux/amd64
   `python:3.11.15-bookworm` image, addressed by its OCI manifest and config digests, with
   `--network=none`, a read-only root filesystem, all capabilities dropped, no-new-privileges,
   bounded resources, and no Docker socket in the candidate environment. Python 3.11 is the sole
   production kernel runtime; Python 3.12 and 3.13 remain research-package compatibility checks.
10. Support two closed execution boundaries: a trusted host may launch the pinned Docker command
    after independently inspecting the local image, while required CI launches the entire private
    3.11 verification phase in that already-pulled container and supplies a trusted workflow
    attestation. Candidate code never receives the Docker client or daemon socket in CI.
11. Validate canonical stdout in the parent boundary against the pinned result Schema and exact
    request fingerprints. Preserve those stdout bytes unchanged; do not recalculate or rewrite the
    result.

`ValuationHandoff 2.0.0` remains a state-continuity contract, not execution authority. The rc.2
tag, commit, schemas, wheel, runtime manifest, runner, and isolation evidence are internal
execution authority bound by the component lock and receipts.

## Consequences

- Public Schema count remains 43 and all public Schema bytes remain unchanged.
- Python/Plugin version becomes `0.6.0.dev2 / 0.6.0-dev.2`.
- No package-root, CLI, implicit Skill, archive writer, live provider, Score, recommendation,
  report, PDF, Publisher, or Marketplace surface is added.
- Missing exact wheel bytes, runtime wheels, the pinned container, proven network denial, date
  alignment, governed name/provider provenance, or any
  projection invariant returns a blocked result rather than a weaker execution.
- CI prefetches closed binary supplies and the pinned image before private credentials are minted,
  revokes the credential before candidate execution, sanitizes its outward artifact through a
  fixed allowlist, and treats the repository owner as the trusted code-author boundary. This does
  not claim arbitrary untrusted pull-request code can safely inspect the private kernel.
- PR3 remains unauthorized until this slice is merged, main CI succeeds, and independent semantic
  review reports P0=P1=0.
