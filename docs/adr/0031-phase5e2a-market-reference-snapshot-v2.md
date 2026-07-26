# ADR 0031: MarketReferenceSnapshot v2 contract boundary

## Status

Superseded in part by ADR 0032 after independent semantic review. The original PR/CI boundary
passed audit `2.3.2`; Phase 5E-2A.1 completed final semantic acceptance under audit `2.3.2.1`.

## Context

Phase 5E-1.1 freezes the price-blind authorization, repository-owned Provider, raw parser,
content-addressed calendar, and reviewed security identity before any market evidence may be
promoted. `MarketReferenceSnapshot 1.0.0` predates that authority chain, stores authoritative
market numbers as JSON numbers, and cannot prove clean-room replay of the raw response.

## Decision

Upgrade the existing public contract to `MarketReferenceSnapshot 2.0.0` without adding another
public contract. The v2 contract is a validated, reference-only audit envelope. It binds the v4
authorization, governed access receipt, authority hashes, security evidence, raw response,
point-in-time fully diluted share basis, exact decimal values, and the deterministic market-equity
calculation.

The public Schema count remains 43. All v2 objects have `status=validated`; blocked and specialist
outcomes remain internal. The contract uses canonical decimal strings and requires split factor
`1` in the v0.5 alpha path. Recorded and loopback evidence is test-only. Live evidence is valuation
eligible only when a future component-locked live Provider exists.

ContractGraph receives one internal, non-Schema validation context so it can replay the accepted
price-blind artifact and the Phase 5E-1.1 access/security records. This context is not exported
from the package root and is not a production builder.

## Migration

This is a preproduction hard break:

- v1 is rejected at runtime after this change;
- v1 is not automatically migrated;
- the old v1 synthetic payload remains only as negative-test evidence;
- no dual writer or compatibility alias is introduced.

## Prohibited in Phase 5E-2A

- share-basis compilation;
- market SourceDocument, Fact, or CalculationResult creation;
- Snapshot production building or artifact writing;
- final FactLedger or AssumptionLedger rebinding;
- valuation-request construction or kernel execution;
- Score, report, PDF, Publisher, release tag, or Marketplace work.
