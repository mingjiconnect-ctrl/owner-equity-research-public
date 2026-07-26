# Analytical Claim and hypothesis review

Language-model analysis stops at `AnalyticalClaimCandidate`.

1. Bind proposed support, counterevidence, falsification, and trend statements to exact typed
   evidence and an evidence-graph hash.
2. Require a named human `AnalyticalClaimReviewDecision` over the unchanged Candidate fingerprint
   and graph hash before creating a Claim.
3. Pass the reviewed Claims and all retained evidence to
   `resolve_competitive_advantage_hypothesis`. Do not provide or edit a status.
4. Let the resolver apply the fixed priority: blocked, falsified, contested, supported, proposed.
5. `supported` requires core, durability, and reinvestment Claims; every policy support and
   counterevidence role; official target-company evidence; independent authoritative evidence;
   resolved counterevidence; complete context and business-model scope; and no shortcut.
6. Preserve predecessor counterevidence. A trend remains unknown unless the predecessor is
   comparable and an exact-scope reviewed trend Claim exists.

Claims explain evidence and falsification paths. They cannot override deterministic gates.
