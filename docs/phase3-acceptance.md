# Phase 3 acceptance contract

Phase 3 is accepted only when:

- historical Phase 1/2 tags remain unchanged;
- all nineteen Draft 2020-12 schemas reject unknown properties and have immutable Python types;
- SEC intake requires caller identity, permits only SEC HTTPS URLs, defaults to 5 rps, rejects
  rates above 10 rps, and writes raw data only to an external content-addressed cache;
- CI is offline and synthetic fixtures cover complex tables, iXBRL dimensions, eliminations,
  restatements/duplicates, footnote discovery, and missing disclosure;
- every candidate disposition records an `EvidencePromotion`, and model output cannot auto-create
  Facts or final findings;
- segment reconciliation derives tolerance from display precision and does not infer missing data;
- all mandatory footnote topics are present and blocked evidence cannot masquerade as a red flag;
- final accounting-quality severity has an evidence-backed Claim and falsification condition;
- no Phase 3 dependency points to Score, valuation, reports, PDF, or Publisher;
- Amazon and Salesforce shadow manifests at cutoff `2026-07-11` contain only accessions, hashes,
  coverage, blocked items, and validation state;
- Python 3.11/3.12/3.13 CI, wheel contents, Skill/Plugin validation, component lock, isolated
  read-only audit, main CI, and annotated tag CI all pass with P0/P1/P2/P3 equal to zero.
