---
name: owner-quarterly-update
description: Use only when explicitly invoked with $owner-quarterly-update to build or validate a source-backed quarterly vertical slice from existing owner-research contracts, including fiscal-calendar normalization, YTD-to-quarter and TTM calculations, filing reconciliation, 52/53-week diagnostics, acquisition comparability, SBC, dilution, leases, working capital, and FCF. Do not use for full company research, valuation, scoring, reports, or publishing.
---

# Owner Quarterly Update

Build a reference-only quarterly JSON package from validated source documents, facts, periods,
calculations, reconciliations, and claims.

## Workflow

1. Require an issuer, data cutoff date, regulatory filings or company releases, content hashes,
   source locators, current fiscal period, and comparison period.
2. Validate `SourceDocument`, `Fact`, and `FiscalPeriod` artifacts before calculating.
3. Use `owner_research.quarterly` for every numerical transformation. Do not calculate inside
   narrative text. Emit `CalculationResult` v2 with explicit period IDs and role bindings; do
   not relabel a Phase 1 v1 calculation as v2 without rebuilding its fingerprints.
4. Reconcile amendments and regulatory filings before company releases. Preserve conflicts and
   blocked states. Declare `single_quarter` or `ytd`, match the exact fiscal window, and compare
   the authority with every candidate source.
5. Build `QuarterlyReconciliation` and `QuarterlyUpdate` objects that reference Facts,
   CalculationResults, and Claims rather than copying narrative conclusions. Comparability is
   recomputed from referenced acquisition, bridge, FX, and one-time-tax Facts; never inject a
   caller-authored comparability label without matching evidence.
6. Validate the complete reference graph and RunManifest before returning JSON.

## Required output dimensions

- what changed;
- why it changed;
- temporary or structural;
- guidance change;
- impact on the long-term thesis;
- whether valuation assumptions require later review, without calculating valuation;
- supporting and counterevidence, confidence, missing evidence, and red flags.

## Stop conditions

Stop with `partial` or `blocked` when cumulative inputs, comparison periods, source authority,
growth-bridge components, acquisition bridges, units, currencies, or fiscal-calendar metadata are
missing or inconsistent. Missing explicit acquisition, FX, or one-time-tax evidence means
comparability is `unknown`, not false, and requires a blocked update. Never infer unavailable
quarter cash flow or operating drivers.

Do not implement or invoke segments, footnotes, accounting quality, management, capital
allocation, scoring, valuation handoff, target prices, report rendering, PDF, or publishing.
