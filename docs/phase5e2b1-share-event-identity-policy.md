# Phase 5E-2B.1 cross-source share-event identity policy

The corrective sequence closes one P0: multiple formal documents may describe the same completed
share event, but a current-share roll-forward must consume the economic event exactly once.

## Identity and corroboration

The legal-event key uses reviewed capital-allocation identity and execution occurrence. Evidence
identity remains separate:

```text
legal event
  -> one canonical evidence group
       -> one or more corroborating Facts and SourceDocuments
       -> eventually one derived canonical event Fact
  -> one roll-forward consumption
```

The event concept, common security, legal effective date, incremental grain, and exact share
magnitude must agree inside the group. Conflicts block the lineage. Same-date, same-magnitude
events are distinct only when reviewed official legal IDs distinguish them.

Completed-event concepts are mapped to existing Phase 4D event types and frozen fact roles by the
closed `cross-source-share-event-grouping/1.0.0` registry. The historical `shares_repurched` role
spelling is referenced as-is and is not migrated.

## Evidence and closure

Every evidence member must be cutoff-safe, high-confidence, formally sourced, bound to one current
reviewed CapitalAllocationEvent identity chain, and use an incremental completed-event grain.
Future, low-confidence, secondary, cumulative, cross-issuer, cross-security, unreviewed, or
closure-external evidence cannot become a canonical member.

The production closeout must retain the canonical group ID, full identity fingerprint, all member
Facts and SourceDocuments, search receipts, coverage decisions, reviewed claim transitions, and
grouping policy/version/code SHA. Adding corroboration changes the group and closure fingerprints
without changing the canonical event value.

## Corrective sequence

1. `5E-2B.1-0`: this policy, internal records, red fixtures, baseline reproducer, and audit gate.
2. `5E-2B.1-1`: production discovery, reviewed identity derivation, grouping, conflict detection,
   and exactly-once consumption.
3. `5E-2B.1-2`: coverage, claim transitions, derived event Facts, recursive closure, and replay.
4. `5E-2B.1-3`: acceptance-only closeout with remote evidence and P0-P3 all zero.

Phase 5E-2C remains prohibited throughout the first three steps and may be reauthorized only by
the acceptance-only closeout.
