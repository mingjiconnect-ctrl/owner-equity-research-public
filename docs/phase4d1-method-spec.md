# Phase 4D-1 capital-allocation event-ledger specification

## Boundary

This phase implements official-source selection, source-backed Candidate creation, human review,
economic-event deduplication, and deterministic Event lifecycle compilation. It records what the
issuer announced and executed. It does not judge whether the allocation created value.

## Production flow

```text
official SEC or issuer IR SourceDocument
    -> exact source span and registered evidence roles
    -> CapitalAllocationEventCandidate v2
    -> human CapitalAllocationEventReviewDecision
    -> deterministic economic-event key
    -> deduplicated, versioned CapitalAllocationEvent v2
```

SEC selection preserves all eligible lifecycle filings through the cutoff. Official IR is accepted
only when already represented as a `company_primary` SourceDocument. Repository tests and CI never
fetch live data; raw documents remain outside the repository.

Candidate construction verifies the raw content hash, exact normalized-text span, issuer, cutoff,
event policy, identity components, source role, Fact source, Fact unit family, currency semantics,
announcement date, execution period, and growth classification. A language model cannot confirm
any of these fields.

Human review covers the exact Candidate fingerprint. Confirmed Decisions emit the deterministic
logical Event ID and economic-event key. Blocked and rejected Decisions emit neither. Corrections
and semantic changes require superseding Candidates and Decisions.

The compiler consumes confirmed, non-superseded Decisions for one economic event. It retains all
reviewed evidence, rejects conflicting issuer/scope/announcement semantics, deduplicates repeated
official disclosures, and derives `announced`, `in_progress`, `completed`, `cancelled`, or
`blocked`. Completion requires a completion source, a registered completion Fact role, and a
reviewed execution end. Refinancing requires an explicit debt-refinanced bridge and acquisitions
cannot be classified as organic growth.

Each material change produces the next contiguous Event version; an identical replay returns the
latest version with `no_change=true`. The compiler refuses a later run that omits predecessor
review Decisions. Phase 4D-2 will build cash-deployment bridges; Phase 4D-3 will evaluate Outcomes;
Phase 4D-4 will build Reviews and metadata-only Shadows.
