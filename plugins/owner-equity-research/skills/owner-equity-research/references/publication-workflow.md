# Report and local publication workflow

## Report profiles

- `research_only` consumes the strictly reloaded ResearchBundle/RunManifest, remains price-blind,
  makes zero Futu calls, and must not contain a market price or target price.
- `full_valuation` additionally requires the strictly reloaded six-file archive, all three eligible
  valuation panels, the composite result, four-lens Score 2.0 and OwnerScorecard 1.0, and the typed
  Futu evidence/cross-check receipts. Missing or contested synthesis produces `无法评级`.

## PDF build

1. Render the fixed simplified-Chinese LaTeX template with the packaged, hash-pinned open font.
2. Generate model tables, sensitivities, reverse-price diagnostics, score tables, and charts from
   Python-produced typed data. Do not calculate inside narrative or TeX.
3. Require 30-60 pages, extractable Chinese text, every required section, all-page rasterization,
   renderer executable identity, font/license identity, and a deterministic ReportBuildReceipt.
4. Never include credentials, account identifiers, raw licensed Futu payloads, or private CAS
   bytes in Markdown, TeX, PDF, charts, logs, or receipts.

## Publisher

1. Consume only strictly reloaded typed research/report objects and, for `full_valuation`, the
   strictly reloaded six-file archive and typed downstream valuation/score objects.
2. Write to a random local staging directory through no-follow directory descriptors. Enforce at
   most 512 members and 512 MiB cumulative bytes.
3. Fsync every member and directory, freeze files to `0444` and directories to `0555`, atomically
   rename, then reload the final location and verify every byte and the root manifest.
4. Identical manifest bytes are idempotent. A different existing package is never overwritten.
5. Do not fetch data, call Futu, invoke the kernel, upload, email, create a GitHub Release, or mutate
   any external service.
