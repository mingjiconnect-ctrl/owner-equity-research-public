# Phase 4B-0 acceptance contract

Phase 4B-0 is ready to merge only when:

- Phase 4A remains accepted and historical tags are unchanged;
- Fact v2 accepts registered nonmonetary units with `currency=null` and requires currency for
  monetary units;
- narrative-only Statements cannot create Commitments;
- target roles, scope, measurement basis, policy identity, result roles, and lifecycle states are
  structurally validated;
- withdrawn and superseded Commitments are excluded from ordinary due and missed counts;
- all prior tests plus the four blocker regressions pass;
- the isolated no-remote read-only audit reports machine-derived test counts and P0=P1=0;
- no statement intake, compiler, evaluator, score, valuation, report, or publisher is present.

The accepted completion statement is:
`Phase 4B contract semantics hardened for production`.
