# Research workflow

## Intake and evidence

1. Require one issuer, CIK, data cutoff date, and `OWNER_RESEARCH_SEC_USER_AGENT`.
2. Use only qualifying official evidence published at or before the cutoff. Preserve accession,
   source URL and locator, raw/normalized hashes, parser/code version, period, unit, currency,
   scope, and retrieval time.
3. Read the specialized policy file only when its topic enters scope:
   [SEC intake](sec-intake.md), [footnotes](footnote-topics.md),
   [accounting quality](accounting-quality-rules.md),
   [management sources](management-source-policy.md),
   [statement intake](management-statement-intake.md),
   [commitments](management-commitment-compiler.md),
   [management outcomes](management-outcome-evaluator.md),
   [management review](management-review-shadow.md),
   [business model](business-model.md),
   [mechanism diagnostics](mechanism-diagnostics.md),
   [hypothesis review](hypothesis-review.md),
   [business-quality review](business-quality-review-shadow.md),
   [capital-allocation events](capital-allocation-event-ledger.md),
   [conservation bridges](capital-allocation-conservation-bridges.md),
   [capital-allocation outcomes](capital-allocation-outcome-evaluator.md),
   [capital-allocation review](capital-allocation-review-shadow.md), or
   [ResearchBundle construction](research-bundle-contract.md).
4. Let a language model stop at ExtractionCandidate, StatementCandidate, EventCandidate, or Claim
   draft. Require the registered deterministic promotion policy and machine-readable named-human
   decision before a final contract exists.
5. Keep external context in ContextObservation. Never promote an issuer, regulator, customer,
   supplier, industry, or market observation into a target-company Fact.

## Deterministic research chain

1. Validate source eligibility, issuer identity, cutoff, exact text/hash provenance, period/unit,
   restatements, duplicates, and counterevidence before Fact or Claim promotion.
2. Build segment, footnote, accounting-quality, management, business-quality, and
   capital-allocation objects only when requested and supported by their registered policy.
3. Keep all arithmetic assumption-free unless it belongs to the separately governed price-blind
   valuation-assumption chain. Missing roles stay missing; they never become zero.
4. Validate the complete ContractGraph. Build `ResearchBundle 1.0.0` and its matching RunManifest
   from that graph; do not let callers choose status, coverage, freshness, modules, or hashes.
5. Write and reload exactly canonical `research-bundle.json` and `run-manifest.json`. Replay the
   complete graph before delivery.

## Price-blind valuation preparation

When the user explicitly asks to prepare valuation inputs but not to execute valuation:

1. Reload the canonical Bundle pair and replay registered accounting mappings, reconciliation,
   quality adjustments, method views, equity bridge, and separate method-readiness panels.
2. Compile only governed, price-blind assumption Candidates. Require named-human Decisions and
   preserve exact evidence edges.
3. Freeze the canonical price-blind artifact and adjacent immutable Handoffs through
   `market_reference_allowed`.
4. Stop before market acquisition, final request compilation, kernel execution, or archive
   publication.

## Stop conditions

Stop as partial or blocked for unsupported issuer type; missing legal/security identity; source,
hash, cutoff, period, unit, currency, or scope conflict; unresolved restatement; incomplete formal
source search; candidate ambiguity; missing named-human decision; or incomplete dependency
closure. State the missing evidence and the next falsifiable check.
