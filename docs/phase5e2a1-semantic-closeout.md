# Phase 5E-2A.1 semantic closeout

Phase 5E-2A.1 is a narrow repair to the accepted Snapshot v2 boundary. It does not reopen the
Phase 5E-1.1 market-access authority and does not implement Phase 5E-2B.

## Closed findings

- `P0`: the final equity-bridge dilution root set is no longer supplied by the validation caller.
  It is reconstructed from the Phase 5C readiness, economic-claim treatment, bridge role, and
  consumption records already sealed in the price-blind artifact.
- `P1`: the public Snapshot Schema and Python runtime now both require strictly positive decimal
  strings; `"0"`, `"0.0"`, and `"0.000"` are rejected by Schema validation alone.

## Required replay

The derived witness records included, excluded, and blocked option roots; the frozen Phase 5C
diluted-share Fact and roots; the option bridge disposition; and the consumption-record hash.
ContractGraph independently recomputes the current share roots and rejects an overlap payload
that omits a real modeled option root.

## Governance state

PR #63, main merge `945834597553bb8ff4df12d77c402bee0433e572`, main CI
`29345441770`, and merge-commit audit `2.3.2.1` passed with 845/845 tests and no P0-P3 findings.
The machine state is `accepted_closed` and authorizes only Phase 5E-2B governed point-in-time
share-basis work. Phase 5E-2C and later remain prohibited.
