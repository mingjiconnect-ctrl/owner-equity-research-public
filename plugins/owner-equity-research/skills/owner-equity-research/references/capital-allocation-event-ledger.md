# Capital-allocation Event ledger

Use this reference only when the user explicitly requests capital-allocation event intake or a
source-backed event ledger.

1. Select eligible SEC lifecycle filings through the data cutoff. Accept issuer IR only through an
   already-governed `company_primary` SourceDocument. Keep raw content outside the repository.
2. Build a `CapitalAllocationEventCandidate` from the exact normalized source span. Verify the raw
   content hash, issuer, cutoff, registered type/subtype, identity components, source role, dates,
   growth classification, and role-typed Facts.
3. A language model may propose a Candidate only. Require a machine-readable human
   `CapitalAllocationEventReviewDecision` over the exact Candidate fingerprint.
4. Compile confirmed Decisions deterministically. Repeated disclosures of one transaction retain
   one economic-event key. Preserve all predecessor Decisions and create the next contiguous Event
   version only when reviewed content changes.
5. Derive lifecycle from registered source and Fact roles. Authorization is not execution, partial
   execution is not completion, refinancing is not new debt, and acquired revenue is not organic.
6. Stop with blocked evidence for identity, scope, date, source, Fact role, unit, currency,
   predecessor, or lifecycle conflicts. Do not infer missing values.

Do not build a cash-deployment bridge, evaluate an Outcome, build a CapitalAllocationReview, run a
Shadow, score capital allocation, use market prices, value the issuer, recommend an investment,
render a report/PDF, or invoke a Publisher.
