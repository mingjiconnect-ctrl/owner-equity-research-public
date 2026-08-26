# Explicit valuation workflow

## Preconditions

Proceed only after an explicit valuation request and all of these authorities exist:

- a strictly reloaded canonical price-blind artifact with current `market_reference_allowed`
  Handoff and unchanged McKinsey/Penman protected hashes;
- the exact validated ContractGraph and canonical ResearchBundle/RunManifest bytes;
- governed security identity and current-share evidence;
- current signed Futu Legal, Account Entitlement, Supply Chain, pre-run Runtime Isolation
  Authorization, and Security Identity receipts, plus a private encrypted CAS authority; the
  completed Runtime Isolation and sidecar-execution receipts are post-run evidence and must be
  obtained from the signed session-finalization handshake, never supplied in advance;
- the exact verified private quote-only sidecar distribution, SDK/descriptor registry, protocol
  guard, rootless launcher, SBOM, provenance, UDS peer identity, and signing-key authority; a
  client-only wheel or protocol document is insufficient;
- the pinned private kernel checkout, content-addressed kernel wheel, runtime manifest, and private
  CAS required by the runtime authority;
- injected market and execution clocks with causal ordering.

If any authority is absent, return `blocked`. If the issuer or security route is unsupported,
return `specialist_required`. Neither stopped status may retain kernel stdout or create an archive.

## Execution

1. Replay assumption proposals and named-human reviews against the frozen Candidates and Decisions.
2. Call only allowlisted Futu non-price protocols for secondary financial/company/corporate-action
   verification. Preserve SEC/IR as primary and block material conflicts. Refreeze the canonical
   price-blind input after cross-checks and before any price access.
3. Require `qotLogined=true` and `trdLogined=false` before and after every Futu request. Request
   one eligible completed-trading-day bar with `K_DAY`, `AuType.NONE`, `Session.RTH`, and
   `extended_time=false`. The request token is not semantic proof: require the signed pinned
   canary or written authority before the governed adapter may admit the unadjusted RTH close.
   Never use a caller-authored, scraped, simulated, free-API, snapshot, after-hours, or
   account-derived price.
4. Compile quote-date current common shares from the closed event lineage. Consume every legal
   event once; retain corroboration; route convertibles and warrants to a specialist.
5. Append only governed current-share and market lineage to the frozen FactLedger. Preserve every
   prior Fact and assumption entry byte-for-byte.
6. Compile one canonical request containing separate McKinsey and Penman panels. Do not weight or
   average panel outputs.
7. Execute the byte-pinned kernel once inside the authorized no-network runtime. Preserve exact
   canonical stdout and require `call_count=1`.
8. Write and strictly reload exactly:

   - `valuation-handoff.json`
   - `price-blind-input.json`
   - `market-reference.json`
   - `valuation-request.json`
   - `valuation-result.json`
   - `valuation-run-manifest.json`

9. Recompute all six-file hashes, protected hashes, component/kernel identities, request/result
   fingerprints, execution receipts, and final `kernel_result_frozen` Handoff before success.
10. Downstream of the immutable archive, build the McKinsey target adapter, independent
    `PROJECT_EXTENSION_PENMAN_FORWARD_REOI`, and named-human reviewed comparables. Require all three
    compatible panels for both current and twelve-month unweighted medians; missing one yields
    `null`, while dispersion above 50% yields `contested`. Comparable Current Period Policy v1 uses
    only reviewed FY/TTM Facts whose inclusive duration is 364, 365, 366, or 371 days and whose
    period end is within 456 days of the valuation date. Select both the metric and
    `weighted_average_diluted_shares` by the maximum
    `(period_end, SourceDocument.published_date)` key, and require their `start` and `end` to match.
    Never mix an instant denominator into a duration measure or choose among different values or
    bases tied at one latest key. One stale selection, conflicting latest key, or otherwise
    ineligible preselected peer fails the complete-case panel closed and no comparable value enters
    either median.
11. Build four isolated 5x20 scoring lenses and the deterministic recommendation. Scores cannot
    change any valuation input, eligibility, weight, or output. Retain the frozen scorecard label
    for audit, but expose a separate run-level effective recommendation: any later partial,
    blocked, specialist, or contested outcome is `无法评级` and never rewrites the frozen score.
12. Read analyst consensus/ratings/vendor valuation multiples only after the internal valuation and
    conclusion are frozen. Finalize the signed sidecar session, verify its completed Runtime
    Isolation and execution-attestation receipts, then build and strictly publish the local
    full-valuation report package.

## CLI

The low-level explicit command remains available for deterministic development/replay after
producing canonical `valuation-run-input.json` beside the price-blind artifact directory:

```text
owner-research-valuation complete \
  --price-blind-dir <dir> \
  --market-receipt <reviewed.json> \
  --raw-market-evidence <file> \
  --kernel-wheel <cas-wheel> \
  --output <dir>
```

Set `OWNER_VALUATION_REPO` or pass `--kernel-repository`. `--run-input` may override the default
context path. Success returns one canonical summary and exit 0; blocked or specialist routes return
exit 2 and never publish a partial archive. A reviewed-file low-level replay is not a real Futu
canary and cannot authorize `v1.0.0-rc.1`; use `owner-equity-research valuation` for the
comprehensive route.
