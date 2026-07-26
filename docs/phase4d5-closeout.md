# Phase 4D-5 closeout

Phase 4D-5 closes the three semantic blockers left after Phase 4D-4: prior-period economic Events
that remain active in the Review period, source-family searches that previously lacked replayable
receipts, and contradictory repository phase state.

`SourceSearchReceipt v1` records the issuer, source family, complete event-type scope, period,
cutoff, endpoints, results, tool version, and deterministic request fingerprint. Review policy
`2.0.0` requires all eight formal source families for all thirteen event types. An empty completed
search is `searched_not_found`; a missing or failed search is `blocked`. The currently supported
issuer class has no source-family shortcut to `not_applicable`.

`CapitalAllocationReview v3` derives source and event-type status from receipts and evidence. It
selects a logical Event when announcement, execution, a lifecycle/update source, or an Outcome is
active in the Review period, and then selects the latest cutoff-safe Event version and Outcome
across that economic-event version chain.

When this closeout is merged to `main`, main CI passes, and the exact-head read-only audit reports
P0=P1=P2=P3=0, Phase 4D is accepted and frozen. Phase 4E-0 contract work is authorized; Phase 4E-1
and Phase 5 through Phase 9 remain prohibited. No Phase 4 release tag is created here.
