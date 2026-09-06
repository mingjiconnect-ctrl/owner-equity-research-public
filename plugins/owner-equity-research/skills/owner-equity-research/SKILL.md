---
name: owner-equity-research
description: Build source-backed, auditable owner research for a supported SEC-reporting XNYS/XNAS common stock. This is the sole implicitly invocable financial-research Skill. Ordinary research is price-blind and makes zero Futu calls. Only an explicit valuation, target-price, intrinsic-value, margin-of-safety, buy-price, or full-valuation-report request may activate the signed quote-only Futu path, one pinned-kernel call, three-panel synthesis, four-lens scoring, Chinese PDF, and local Publisher. Financial institutions, insurers, funds, REITs, ADRs, multiple share classes, and dual listings require a specialist. Never trade or access holdings, balances, positions, or orders.
---

# Owner Equity Research

Choose exactly one route from the user's explicit request.

In this Skill, **security** means the listed financial instrument and its share-class identity.
It never means cybersecurity. Do not invoke Codex Security, cyber, attack-analysis, penetration-test,
or Trusted Access workflows for any route; the audit route below is a read-only research-artifact
and calculation audit only.

Before invoking an installed command, read the exact
[unified CLI and runtime configuration guide](references/runtime-cli.md).

## Ordinary research route

Use this route by default. Read [research workflow](references/research-workflow.md).

- Ordinary research remains price-blind.
- Build SEC/IR-first evidence, immutable contracts, the validated ContractGraph, and the canonical
  ResearchBundle/RunManifest pair.
- Keep target-security price, market capitalization, valuation requests, and kernel results out of
  research.
- Stop as partial or blocked when evidence, identity, period, unit, scope, or named-human review is
  incomplete. Never convert missing evidence into a negative conclusion.

## Explicit valuation route

Use this route only for an explicit valuation intent. Read
[valuation workflow](references/valuation-workflow.md) and the closed
[market execution policy](references/market-execution-policy.md) before activating Futu.

- Freeze official research, perform entitled Futu non-price cross-checks without replacing SEC/IR
  Facts, then refreeze the price-blind input before reading any price.
- Require signed Legal, Account Entitlement, Supply Chain, pre-run Runtime Isolation Authorization,
  and Security Identity receipts. After the last request, require the signed completed Runtime
  Isolation and sidecar-execution receipts. Require `qotLogined=true`; record `trdLogined` as
  OpenD server-connection state, never as permission to trade or a standalone reason to block.
  The closed read-only protocol allowlist remains mandatory. Raw licensed data stays in the private encrypted
  CAS.
- Read the final completed trading-day market reference only through the closed governed adapter.
  Never accept a caller-authored, manual, scraped, simulated, or free-API price.
- Invoke the byte-pinned kernel exactly once and strictly reload its six-file archive. Then build
  independent McKinsey, forward Penman ReOI, and reviewed-comparables panels; all three are required
  for the unweighted median current value and twelve-month target.
- Apply the four isolated five-item Graham, Buffett, Munger, and Duan Yongping lenses only after
  valuation. Missing evidence remains `Unknown`, never zero; scoring cannot change valuation.
- Build the simplified-Chinese LaTeX PDF and local package only from strictly reloaded typed inputs.
- Return `specialist_required` without kernel execution for unsupported issuer/security paths.
  Return `blocked` without an archive when any authority or evidence is missing.

## Report and local Publisher routes

- A report-only request is always `research_only`: zero Futu calls and no market or target price.
- A full-valuation report is part of the explicit valuation route and must retain the three panels,
  composite result, scorecard, market-expectations comparison, report receipt, and publication
  manifest. Read [publication workflow](references/publication-workflow.md).
- Publisher is local-only, atomic, idempotent for identical bytes, and strictly reloadable. It never
  uploads, emails, releases, or reacquires data.

## Audit route

Use only for an explicit audit request. Read [audit workflow](references/audit-workflow.md), remain
read-only, bind findings to exact bytes, and classify every finding P0-P3.

## Global invariants

- Preserve Facts, Claims, Assumptions, CalculationResults, vendor observations, valuation panels,
  and Scores as separate domains.
- A language model may draft candidates or Claims; it cannot create a Fact, final human decision,
  or deterministic CalculationResult.
- Prefer SEC filings, issuer investor-relations material, and other formal official evidence.
- Preserve source URL/locator, cutoff, raw and normalized hashes, parser/code identity, period,
  unit, currency, scope, and lineage.
- Treat historical market, analyst, and vendor valuation reports as quarantined until the current
  conclusion is frozen. SEC filings and issuer IR evidence remain available under the ordinary
  official-evidence rules.
- Do not copy legacy prompts, personas, templates, or valuation logic.
- Do not let Scores affect Facts, assumptions, panel eligibility, weights, or target prices.
- Never implement trading, orders, holdings, positions, balances, or account mutation.
