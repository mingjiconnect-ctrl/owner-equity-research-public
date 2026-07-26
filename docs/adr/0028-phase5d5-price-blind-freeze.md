# ADR 0028: canonical price-blind input freeze

Status: accepted for Phase 5D-5 implementation

## Decision

Phase 5D-5 adds one internal compiler for the canonical `price-blind-input.json` artifact. The
compiler must replay the accepted Phase 5C readiness, Phase 5D-2 reviewed AssumptionLedger,
Phase 5D-3 McKinsey scenarios, and Phase 5D-4 Penman inputs. It derives all artifact hashes and
four adjacent immutable `ValuationHandoff` versions; callers cannot provide state, IDs, hashes,
method inputs, or market evidence.

The artifact is closed and canonical but remains an internal project type, not a fifth Phase 5
public contract and not a kernel valuation request. It contains the complete nonmarket Fact and
assumption ledgers, accounting/readiness evidence, method inputs, policy identities, and named-
human freeze authorization. It deliberately omits target-security market evidence and the Penman
`market_equity_value_fact_id` required by the complete kernel request.

Three hashes are replayed from canonical payloads:

- `protected_mckinsey_sha256` binds the nonmarket ledger, accounting/readiness layer, and full
  McKinsey input subtree;
- `protected_penman_assumptions_sha256` binds assumption-entry bytes and every nonmarket Penman
  forecast/challenge reference;
- `price_blind_input_fingerprint` binds the entire artifact except that self-hash field.

Only a named human may authorize the freeze. The compiler deterministically creates the adjacent
states `evidence_open`, `price_blind_candidates_reviewed`, `price_blind_input_frozen`, and
`market_reference_allowed`. The writer persists exactly one canonical JSON file atomically, and
the strict loader requires byte-for-byte equality with a fully replayed expected freeze.

## Consequences

Phase 5D-5 may persist `price-blind-input.json`, but it cannot access a quote, create a
`MarketReferenceSnapshot`, compile a complete request/result, import valuation mathematics, or
expose a package-root, CLI, or implicit Skill entry point. Any protected-subtree drift requires a
new Handoff run; the existing run cannot be edited or rolled back.
