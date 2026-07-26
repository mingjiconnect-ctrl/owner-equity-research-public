# ADR 0019: Phase 4D-4 capital-allocation Review and Shadow

Status: accepted for Phase 4D-4 implementation

## Decision

Phase 4D-4 closes the capital-allocation vertical slice with a deterministic
`CapitalAllocationReview v2` builder and fixed-cutoff metadata-only Shadows. The builder selects
the latest Event version per economic key and latest Outcome per selected Event, fills all eight
source-family and thirteen event-type rows, recomputes every count, and derives Review status.

`complete` means source, event, and Outcome coverage is closed. Missing Outcomes or
partial/unverifiable Outcomes produce `partial`; any blocked source, event type, or Outcome produces
`blocked`. No quality grade or value-created conclusion is introduced.

## Consequences

- Callers cannot select stale Event/Outcome versions or hand-edit coverage counts.
- `not_found` event types require completed official-source searches; `not_applicable` requires a
  reviewed not-applicable Claim.
- Amazon, Salesforce, and Union Pacific Shadows are fixed at `2026-07-11` and retain only source
  metadata/hashes, expected event types, formal object IDs, counts, missing evidence, and a
  RunManifest.
- Shadows fail closed when formal promotion chains are unavailable and contain no raw text, Facts,
  Claims, score, market price, valuation, target price, recommendation, report, PDF, or Publisher.
- Phase 4D-4 creates no release tag. Phase 4E remains the integration and release gate.
