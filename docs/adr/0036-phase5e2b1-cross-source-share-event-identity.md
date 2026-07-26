# ADR 0036: Phase 5E-2B.1 cross-source share-event identity

## Status

Accepted for corrective contract work only. Production grouping remains separately authorized.

## Context

Phase 5E-2B originally treated `(concept, period end, SourceDocument ID, source locator)` as the
duplicate key for completed share events. Those fields identify evidence objects, not the legal or
economic event described by the evidence. One repurchase disclosed in an 8-K, 10-Q, and official
press release could therefore enter the roll-forward three times.

PR #69 and #70 remain valid records of the original implementation and governance audit, but the
independent semantic finding is P0 because the resulting current-share count would contaminate
market equity and every later per-share denominator. Phase 5E-2C is withdrawn until the corrective
sequence closes.

## Decision

`cross-source-share-event-grouping/1.0.0` separates a legal-event key from an evidence-member
fingerprint. A legal-event key is derived only from the issuer, governed common security, reviewed
capital-allocation economic-event key, official legal-event identity, and reviewed execution
occurrence. Fact IDs, document IDs, locators, and retrieval timestamps never identify the event.

Evidence with the same legal-event key may form one canonical group only when concept, security,
legal effective date, incremental event grain, and exact share magnitude agree. All corroborating
Facts and sources remain in the evidence closure, but the eventual roll-forward consumes one
derived canonical event Fact. A conflict blocks the numeric lineage; source priority must not
silently choose a value.

Two same-date, same-magnitude events require different reviewed legal IDs. Without them the result
is `blocked_share_event_identity_ambiguous`. Cumulative-to-date disclosure is not an incremental
completed event and must first be transformed by a separately registered assumption-free
calculation or remain blocked.

Claim transitions bind the canonical group, not a raw event Fact, so repeated option, warrant, or
convertible disclosures cannot execute the same transition twice.

## Phase boundary

Phase 5E-2B.1-0 adds only immutable internal records, closed policy, adversarial fixtures, the
baseline vulnerability oracle, documentation, and audit governance. It does not modify the current
compiler or evidence closure and adds no grouping implementation, market SourceDocument, quote
Fact, market-equity calculation, Snapshot, valuation request, writer, or kernel execution.

This boundary is `PROJECT_OPERATIONALIZATION`; it is not valuation mathematics attributed to
McKinsey or Penman.
