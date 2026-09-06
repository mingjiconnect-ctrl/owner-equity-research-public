# Comprehensive Skill market-reference policy

Ordinary research and report-only requests remain price-blind and make zero Futu calls. Market
evidence may enter only after official SEC/IR research is frozen, entitled Futu non-price
observations have been reconciled without replacing Facts, and the price-blind artifact is frozen
again with its current `market_reference_allowed` Handoff.

## Closed quote-only path

- Use only the separately verified private Futu OpenD sidecar. Require current signed Legal,
  Account Entitlement, Supply Chain, Runtime Isolation Authorization, and Security Identity
  receipts before the session, plus signed completed isolation and execution attestations after
  it. Every request must prove `qotLogined=true` and retain the actual boolean `trdLogined`
  observations. The latter describes OpenD's server connection and is not a trading capability;
  true alone does not block a run. Enforce the closed read-only protocol allowlist throughout.
- Admit either the v1 Linux VM profile or the user-approved `macos_local_read_only`
  profile with v2 supply/runtime receipts. Native Mac mode runs a separate non-root
  sidecar against the user's existing OpenD at `127.0.0.1:11111`, uses a null VM hash,
  and never claims VM isolation. Neither profile relaxes data rights, signed request
  plans, encrypted CAS, or strict session finalization. A setup-only GlobalState probe
  is not authority to fetch data or complete a canary.
- Validate protocol `3202` as exactly one active reviewed US common stock whose vendor code, MIC,
  currency, listing, and security type agree with official identity. Futu static and financial
  observations are secondary cross-checks only.
- Request the last completed XNYS/XNAS trading day's daily bar exactly once with `K_DAY`,
  `AuType.NONE`, `Session.RTH`, and `extended_time=false`, limited to close and volume. Reject
  snapshots, last/previous price, intraday, adjusted, stale, after-hours, overnight, fallback, and
  caller-authored prices.
- `Session.RTH` in the request does not by itself prove daily-bar RTH semantics. The private parser
  records `vendor_unadjusted_daily_close_rth_requested` with
  `rth_semantics_attested=false`. Map it to the governed valuation close only when the signed
  Supply Chain receipt binds a current pinned OpenD canary or written authority. Describe it as a
  vendor unadjusted regular-session daily close, never as an exchange-official close.
- Preserve raw Protobuf only in the authorized private encrypted CAS. Public receipts, wheel,
  Plugin, report, PDF, and release contain hashes and typed references, never credentials, account
  data, or licensed raw responses.

## Shares, arithmetic, and failure

The official current-share compiler owns the quote-date common-share lineage: direct disclosure,
issued-minus-treasury, or a reviewed completed-event roll-forward. Futu cannot supply or overwrite
current shares. Conflicting identity, currency, period, split treatment, share count, or material
financial observations fail closed. Unsupported convertibles, warrants, ADRs, multiple share
classes, dual listings, banks, insurers, funds, and REITs return `specialist_required`.

Market equity uses the exact governed binary64-to-decimal interpretation and the accepted integer
common-share count without tolerance or implicit rounding. Manual prices, simulated accounts,
free APIs, scraping, trading data, holdings, balances, positions, orders, and automatic fallback
are forbidden. A reviewed-file replay remains development-only and cannot satisfy the real
`v1.0.0-rc.1` canary.
