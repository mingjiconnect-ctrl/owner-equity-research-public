# Phase 5E-2A MarketReferenceSnapshot 2.0.0

Phase 5E-2A changes exactly one public Schema: `MarketReferenceSnapshot` advances from `1.0.0`
to `2.0.0`. The remaining 42 public Schemas, the Phase 5E-1.1 authority resources, and the pinned
valuation kernel remain frozen.

The original Phase 5E-2A PR/CI boundary passed under audit `2.3.2`. Phase 5E-2A.1 then passed
audit `2.3.2.1`, proving dilution-root authority is derived from frozen Phase 5C evidence and that
public/Python decimal domains match. Phase 5E-2A.2 pins kernel rc.2 and upgrades this contract to
v3 current-common-share semantics. Phase 5E-2A.2.1 closes recursive numeric roots, temporal
authority, corporate-action search coverage, and completed-claim transitions. It is accepted/closed
under audit `2.3.2.2.1`; Phase 5E-2B is authorized and Phase 5E-2C and later remain prohibited.

## Contract semantics

The Snapshot binds these immutable evidence groups:

1. v4 authorization Handoff and all three price-blind hashes;
2. eligible MarketAccessResult, exact MarketQuoteRequest, and GovernedMarketQuoteReceipt;
3. component lock, authority, Provider, adapter, parser, and calendar hashes;
4. reviewed security identity and evidence closure;
5. raw-response storage locator, raw SHA, content type, and parser-replay fingerprint;
6. quote-date current common shares, a recursively derived numeric-root and source closure,
   complete corporate-action search coverage, completed-claim transitions, and a dilution-overlap
   witness recomputed from frozen Phase 5C economic claims and consumption;
7. market SourceDocument, quote Fact, current-share Fact, and assumption-free market-equity
   CalculationResult;
8. market-evidence closure and Snapshot self-fingerprint.

The authoritative decimal fields are `quote_price_decimal`,
`current_common_shares_decimal`, `split_factor_decimal`, and
`market_equity_value_decimal`. The latter must equal the first multiplied by the second using
`Decimal`; the split factor must be exactly `"1"`.

## Evidence storage

`repo://tests/fixtures/...` is allowed only for test evidence and must resolve inside the repository
to bytes whose SHA equals `raw_response_sha256`. `cas://sha256/<digest>` is content-addressed and
its digest must equal the same raw SHA. Query strings, fragments, user information, parent-path
segments, absolute paths, whitespace, and credential-like content are forbidden.

## Fingerprints

- parser replay hashes the raw SHA, content type, Provider registration SHA, parser SHA, request
  fingerprint, and the exact parsed quote fields;
- market-evidence closure hashes canonically sorted typed identities for the Handoff, access
  result, Request, Receipt, security compilation, share-basis decision, raw response, market
  SourceDocument, both Facts, CalculationResult, every current-share numeric root and source,
  every SourceSearchReceipt and category disposition, completed-claim transitions, and the
  derived Phase 5C dilution authority;
- Snapshot fingerprint hashes the entire canonical payload except `snapshot_fingerprint`.

No builder, compiler, fetcher, writer, or kernel entry point is part of this phase.
