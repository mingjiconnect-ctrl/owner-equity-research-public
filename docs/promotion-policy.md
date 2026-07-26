# Evidence promotion policy

`auto_fact` is allowed only when every condition below is true:

- the source is an SEC primary regulatory 10-K, 10-K/A, 10-Q, or 10-Q/A;
- extraction is deterministic table or deterministic iXBRL;
- the source locator and artifact hashes are resolved;
- value type, value, unit, currency, and period are resolved;
- duplicate and restatement checks are resolved;
- any required reconciliation passes within display-precision tolerance;
- the candidate is not high-impact narrative evidence.

Language-model candidates can only be `human_confirmed_claim`, `blocked`, or `rejected`.
Ambiguous values, unit conflicts, missing periods, conflicting restatements, and high-impact
narrative evidence require human confirmation or remain blocked. Every decision records the
candidate fingerprint, policy version, checks, reviewer provenance, and any output identifier.
