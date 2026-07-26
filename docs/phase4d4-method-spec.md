# Phase 4D-4 capital-allocation Review and Shadow specification

## Review builder

The builder accepts one issuer, one review period, a cutoff, official SourceDocuments, versioned
Events, evidence-state Outcomes, registered calculations, and explicit source/event-type coverage
inputs. It selects current logical objects and constructs the Review; there is no caller-supplied
event list, Outcome list, count table, or final status.

```text
official source coverage
    + latest Event per economic key
    + latest cutoff-safe Outcome per Event
    + reviewed not-applicable Claims
    -> recomputed source/type/count coverage
    -> complete / partial / blocked Review
```

All eight source families and thirteen event types are mandatory. Reviewed types contain Events;
not-found types contain a completed official search; not-applicable types contain a reviewed Claim;
blocked rows record missing evidence. Missing latest Outcomes prevent a complete Review.

## Metadata-only Shadows

The fixed cutoff is `2026-07-11`. Amazon, Salesforce, and Union Pacific shadows record SEC
accessions as metadata tuples with explicit hash scope, event types examined, empty formal IDs when
promotion has not occurred, zero status counts, blocked reasons, and a RunManifest. They perform no
network access in CI and cannot contain raw source content or investment outputs.
