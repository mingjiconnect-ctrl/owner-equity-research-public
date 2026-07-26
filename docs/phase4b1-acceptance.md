# Phase 4B-1 acceptance contract

Phase 4B-1 is ready to merge only when:

- SEC and issuer-hosted official sources are separated from third-party material;
- non-SEC requests require an explicit HTTPS host allowlist and validate final redirects;
- every Candidate preserves exact normalized text, locator, and hashes;
- language-model output cannot directly create a Statement or Fact;
- every human-confirmed Statement has exactly one named, machine-readable ReviewDecision;
- every emitted target Fact matches the reviewed metric value, unit, period, scope, and basis;
- CI remains offline and raw sources remain in the external content-addressed cache;
- Phase 1 through 4B-0 regressions, Plugin/Skill validation, component lock, and read-only audit pass;
- no Commitment compiler, Outcome evaluator, score, valuation, report, or Publisher is present.

Phase 4B-2 is the next stage. Phase 4B-1 creates no release tag.
