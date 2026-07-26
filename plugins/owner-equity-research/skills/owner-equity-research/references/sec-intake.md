# SEC intake and evidence promotion

Use only SEC Submissions, Company Facts, and primary filing HTML/iXBRL for automatic evidence.
Require `OWNER_RESEARCH_SEC_USER_AGENT`. Default to five requests per second and never configure
more than ten. Keep raw content in the external content-addressed cache; retain only accession,
URL, hashes, parser version, and normalized fixtures in the repository. Never use live network
access in CI.

Create an `ExtractionCandidate` before any Fact. Permit `auto_fact` only for a deterministic
table/iXBRL numeric candidate from a primary 10-K/10-Q when locator, artifact hashes, value, unit,
currency, period, duplicates/restatements, and reconciliation are all resolved. Record every
decision as `EvidencePromotion` with the candidate fingerprint and policy version.

Language-model output can create a narrative candidate or Claim draft only. Require human
confirmation for narrative evidence, high-impact statements, unit conflicts, missing periods,
ambiguous tables, conflicting restatements, or unresolved duplicates. Never silently choose one
candidate.
