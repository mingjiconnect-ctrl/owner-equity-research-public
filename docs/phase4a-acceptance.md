# Phase 4A acceptance contract

Phase 4A is ready for later implementation only when:

- Phase 1-3 tags and the Phase 3 baseline remain unchanged;
- all ten Phase 4A schemas are Draft 2020-12, reject unknown fields, have immutable Python types,
  and produce stable fingerprints;
- ContractGraph rejects dangling and cross-issuer references, lineage cycles, duplicate event
  keys, duplicate evaluation windows, unconfirmed statements, early missed outcomes, unsupported
  KPI comparisons, incomplete capital outcome roles, and reverse dependencies;
- all non-blocked conclusions have Claims with evidence, counterevidence search, confidence, and
  falsification conditions;
- twelve named adversarial fixtures are exercised by tests;
- all Phase 1-3 tests continue to pass;
- Python 3.11/3.12/3.13, wheel, Plugin/Skill, component-lock, and isolated read-only checks pass;
- an external `phase4a-audit.json` records the reviewed commit, tool/version, timestamps, P0-P3
  counts derived from machine-readable audit findings, canonical report hash, and CI run IDs;
- P0 and P1 are zero, and no Phase 4A release tag exists.

The only accepted completion statement is: `Phase 4A contracts ready for implementation`.
Phase 4B is the next phase and is not part of this acceptance.
