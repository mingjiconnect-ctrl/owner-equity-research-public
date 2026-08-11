# Phase 5 v1 market-reference policy

Ordinary research remains price-blind. Market evidence may enter only after the exact immutable
Handoff reaches `market_reference_allowed` and the price-blind artifact, component lock, security
identity, assumption entries, and both protected method hashes replay without drift.

The v1 release-candidate path uses a provider-neutral interface and a reviewed-file Provider. The
core package does not fetch a quote, import a network client, or read a trading account. The
Provider reads a repository-external review receipt and raw evidence file, rejects symlinks and
non-regular files, recomputes both content hashes, requires a credential-free HTTPS source, and
binds the named reviewer `human:mingji`. A caller cannot pass a price, trading date, security,
status, Fact, or Snapshot.

The current-share compiler owns path selection: direct quote-date common shares, then
issued-minus-treasury, then a reviewed completed-event roll-forward. Cross-source disclosures of
one legal event are grouped once for arithmetic while every corroborating Fact and source remains
in the evidence closure. Conflicting amounts, dates, securities, remaining claims, dangling
lineage, or unsupported convertible/warrant transitions fail closed.

`MarketReferenceSnapshot 4.0.0` is provider-neutral. Reviewed-file evidence has
`source_authority_kind=human_reviewed_file` and `usage_scope=release_candidate`; it cannot be
represented as production evidence. Quote and market-equity arithmetic use authoritative Decimal
strings. Any numeric projection into the existing Fact contract must round-trip exactly.

The current vertical slice stops at a validated Snapshot. It does not expose a package-root API,
CLI, final FactLedger or valuation request, kernel execution, archive writer, Score,
recommendation, report, PDF, or Publisher. Recursive controller, recovery-seal, G1-G5, and
acceptance-only PR instructions are historical governance records, not active workflow.
