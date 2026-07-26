# ADR 0012: Source-backed business-model builder

Status: accepted for Phase 4C-2 development

## Decision

Construct `BusinessModelSnapshot` deterministically from the latest eligible segment ledger,
target-issuer Facts, and human-reviewed Claims. Every attribute binds its exact Fact, Claim, and
ReviewDecision. Material scopes are derived from reportable segments or confirmed product-market
materiality; callers cannot declare them freely. Coverage is recomputed per scope and component.

`not_applicable` is limited to key partners and regulatory dependencies and requires an exact-scope
Candidate whose reviewed role is `not_applicable`. Shared issuer-wide resources require an explicit
reviewed relation to each covered scope. Missing core evidence or an unresolved segment boundary
fails closed as `blocked`; other unresolved components remain `partial`. `complete` means evidence
coverage only.

## Boundaries

- External competitive observations do not become business-model Facts.
- The builder emits no score, quality grade, moat conclusion, valuation, or recommendation.
- It does not infer undisclosed customers, pricing, capital requirements, concentration, or
  business units.
- Only target-company regulatory or official company evidence can support a complete snapshot.
