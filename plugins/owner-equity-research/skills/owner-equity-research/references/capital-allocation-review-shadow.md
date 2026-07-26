# Capital-allocation Review and Shadow

Use this reference after Event and Outcome production is complete for the cutoff.

1. Provide machine-readable SourceSearchReceipt objects for all eight formal source families. Each
   receipt must cover all thirteen event types, the exact Review period and cutoff, official
   endpoints, result documents, tool version, and a replayable request fingerprint.
2. Let code derive `reviewed_present`, `searched_not_found`, or `blocked`; never mark an unsearched
   family not applicable. Let code derive event-type coverage rather than accepting hand-filled
   status or free-text search notes.
3. Select an economic Event when its announcement, execution period, lifecycle/update source, or
   Outcome is active in the Review period. Then select the latest cutoff-safe Event version and
   latest Outcome across that economic-event version chain.
4. Never hand-select stale versions or hand-edit coverage counts.
5. Let code derive complete, partial, or blocked. Complete means evidence closure only, not good
   capital allocation.
6. Fixed-cutoff Shadows store metadata tuple hashes, expected event types, object IDs, counts,
   blocked reasons, and RunManifest only. Empty formal IDs remain blocked.

Do not include raw source content, Facts, Claims, scores, market prices, valuation, target prices,
recommendations, reports, PDFs, or Publisher output in a Shadow.
