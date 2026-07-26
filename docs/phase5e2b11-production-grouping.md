# Phase 5E-2B.1-1 production grouping

Phase 5E-2B.1-1 closes the production grouping portion of the cross-source share-event P0.

The internal entry point:

```python
group_governed_completed_share_events(
    *,
    graph,
    issuer_id,
    security_compilation_result,
    opening_date,
    quote_date,
    data_cutoff_date,
)
```

performs only these operations:

1. validate the supplied ContractGraph;
2. replay each eligible raw share-event Fact through the latest cutoff-safe Event and one active
   named-human Candidate decision;
3. require an exact single-day incremental occurrence and explicit common-security identity;
4. group corroborating official evidence by the reviewed legal event key;
5. block conflicting or ambiguous evidence; and
6. reserve, but never create, one deterministic derived event Fact ID per canonical group.

The function intentionally does not accept caller-selected Facts, Event IDs, legal IDs, group
status, or canonical values. It is not exported from the package root, CLI, Plugin, or Skills.

## Deferred to Phase 5E-2B.1-2

- ResearchBundle dependency-closure proof;
- coverage-receipt and coverage-decision integration;
- option, warrant, and convertible Claim transition de-duplication;
- canonical derived event Fact creation;
- recursive current-share closure; and
- exactly-once consumption by the current-share roll-forward.

Until that successor is accepted, Phase 5E-2C and every market-evidence capability remain
prohibited.

## Acceptance

Phase 5E-2B.1-1 is accepted/closed after its separate governance closeout. This accepts only the
reviewed event-chain replay, legal-event identity derivation, corroborating evidence grouping,
semantic conflict detection, and reserved derived-event Fact identity described above. The
deferred integration list remains the sole scope of Phase 5E-2B.1-2.
