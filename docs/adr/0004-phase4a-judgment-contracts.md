# ADR 0004: Phase 4A business, management, and capital-allocation contracts

Status: accepted for Phase 4A implementation

## Decision

Phase 4A adds ten Draft 2020-12 contracts and immutable Python counterparts:
`BusinessModelSnapshot`, `CompetitiveAdvantageHypothesis`, `BusinessQualityReview`,
`ManagementStatement`, `ManagementCommitment`, `ManagementOutcome`, `CapitalAllocationEvent`,
`CapitalAllocationOutcome`, `ManagementReview`, and `CapitalAllocationReview`.

These contracts organize existing `SourceDocument`, `Fact`, `Claim`, and deterministic
`CalculationResult` evidence. They do not calculate a business-quality grade, management score,
capital-allocation verdict, valuation, target price, or recommendation. No production judgment
module is added in Phase 4A.

## Evidence and promotion rules

Confirmed management statements and supported or complete conclusions require SEC or official
company-IR evidence. Third-party material may be counterevidence or support a low-confidence
Claim, but cannot be the sole basis for promotion. Every non-blocked hypothesis, outcome, or
review conclusion references a Claim with support, counterevidence or a documented search, and a
falsification condition.

A language-model extract is not a confirmed `ManagementStatement`. Commitments require a
human-confirmed statement. Outcomes remain separate from statements and commitments. A
commitment assessed before its due date is pending; absent outcome evidence after maturity is
unverifiable or blocked, never automatically missed.

KPI renames and redefinitions create new statements with predecessor links. Cross-definition
comparison requires a deterministic calculation consuming both definition-evidence sets and no
Assumptions. Capital events use a deterministic key over issuer, event type, announcement date,
and transaction identity. Repeated disclosures append sources to one event.

Buyback outcomes distinguish gross execution, SBC, equity issuance, and net share change.
Acquisition outcomes distinguish synergy evidence and impairment evidence. Acquired revenue is
not organic growth, and EPS accretion alone cannot establish that a capital action worked.

## Consequences

The main research Skill remains the implicit Phase 3 SEC entry point and does not run Phase 4A
analysis. The explicit audit Skill gains Phase 4A checks. No new Skill is added. The package uses
`0.4.0.dev1` and the Plugin/component lock use `0.4.0-dev.1`. Phase 4A creates no tag;
`v0.4.0-alpha.1` remains reserved for Phase 4E.
