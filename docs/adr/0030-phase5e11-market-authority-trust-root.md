# ADR 0030: Phase 5E-1.1 market-access authority trust root

Status: accepted for implementation on `feature/phase5e11-authority-closeout`

## Context

Phase 5E-1 proved that access followed a price-blind authorization and that a provider was called
at most once. Independent semantic review found that four authorities were still supplied by the
caller: provider registration, parsed quote fields, the trading calendar, and the security identity.
The same review found that non-finite/non-canonical decimals and credential-bearing endpoints were
not closed. Passing the original audit therefore did not establish a repository-owned trust root.

## Decision

Phase 5E-1.1 makes the installed wheel and `component-lock.json` the authority for market access.

1. Provider registration, exact adapter class, parser function, endpoint identifier, calendar data,
   and security/secret policies are content-addressed resources in the wheel.
2. A provider returns raw bytes only. The locked parser is the sole producer of parsed quote fields.
3. The trading calendar is an explicit 2026 XNYS/XNAS dataset with UTC session boundaries, official
   source identity, and a verified content hash. Unknown MICs and uncovered dates fail closed.
4. A security identity is compiled from formal evidence and a named-human analytical review. The
   caller supplies only evidence IDs and cannot supply ticker, MIC, class, currency, or security ID.
5. Quote decimals are finite, positive, and match one canonical non-exponent grammar.
6. Public and serialized surfaces carry endpoint IDs only. Credential-like material is rejected and
   audited before any provider call.

The Phase 5E-0 policy records and public contracts remain byte-for-byte frozen. The component lock
receives one additive internal authority section; old price-blind artifacts bound to the prior lock
cannot be used for market access and are never modified.

## Consequences

- Phase 5E-2 authorization is suspended until this closeout is merged and independently audited.
- Recorded and loopback adapters are the only registered adapters in this phase. No live provider or
  credential is introduced.
- `MarketQuoteRequest` and `MarketQuoteReceipt` remain unchanged. An internal governed wrapper binds
  the legacy receipt to the new authority lineage for Phase 5E-2.
- Recorded evidence is test-only and must be rejected by the future Phase 5E-3 request compiler.
- MarketReferenceSnapshot, share-basis compilation, market Facts, final requests, and kernel
  execution remain outside this phase.

