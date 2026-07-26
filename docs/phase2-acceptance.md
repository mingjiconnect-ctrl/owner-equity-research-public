# Phase 2 acceptance contract

## Required artifacts

- Three Draft 2020-12 public Schemas and immutable Python types: `FiscalPeriod`,
  `QuarterlyReconciliation`, and `QuarterlyUpdate`.
- Synthetic, explicitly labeled golden cases for a non-calendar 53-week company, a
  restatement/acquisition case, and an SBC/lease-heavy case.
- Deterministic quarterly functions with no network, market-price, valuation, report, or LLM
  dependency.
- An explicit-only `owner-quarterly-update` Skill using validated JSON artifacts.

## Required positive cases

- Q1 copies YTD; Q2–Q4 subtract the preceding cumulative period.
- TTM uses current YTD + prior FY - prior comparable YTD.
- A 14-week quarter can be compared with a 13-week quarter through a labeled per-week diagnostic.
- A later regulatory amendment supersedes the original filing and company release.
- SBC/revenue, diluted-share change, lease change, working-capital change, YTD FCF, and discrete
  quarter FCF reconcile to their inputs.
- Complete FX/acquisition/price/volume bridges reconcile to reported growth.

## Required negative cases

- Calendar, period, unit, currency, concept, or issuer mismatch.
- Missing previous YTD for Q2–Q4 or missing prior FY/prior YTD for TTM.
- A purported prior fiscal year that is shorter or longer than a complete 52/53-week or calendar
  fiscal year.
- 52/53-week metadata inconsistent with actual dates.
- Original/restated filing ambiguity or absent regulatory authority.
- FiscalPeriod metadata or role bindings omitted from a dependent calculation fingerprint.
- A reconciliation candidate outside its declared single-quarter or YTD basis, or a delta that
  omits any candidate source.
- Reconciliation candidates or delta results with inconsistent units or currencies.
- Material acquisition without an explicit comparable organic bridge.
- Missing explicit acquisition, FX, or one-time-tax comparability evidence.
- Missing FX, acquisition, price, or volume component.
- Reused or role-mismatched growth-bridge evidence.
- Negative capital expenditure supplied under the positive-outflow convention.
- Quarterly output containing narrative values instead of Claim references, valuation results,
  report artifacts, Score dependencies, or Phase 3–7 modules.
- A complete QuarterlyUpdate with blocked reconciliation, unresolved comparability, or missing
  cause, durability, guidance, or long-term thesis Claim dimensions.
- A caller-supplied comparability label that differs from the update's referenced evidence, or a
  change result labeled with a period outside its FiscalPeriod quarter/cumulative windows.

## Release gate

- Local verification and Python 3.11/3.12/3.13 CI pass.
- Plugin and Skill validators pass.
- Independent read-only audit reports P0=0 and P1=0.
- The release tag is `v0.2.0-alpha.1`; `v0.1.0-alpha.1` remains unchanged.
