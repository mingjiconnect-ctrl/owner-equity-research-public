# ADR 0044: Owner Equity Research comprehensive Skill in one PR3

Status: accepted for implementation

Date: 2026-08-15

## Context

PR1 and PR2 are accepted on merged `main`. The original PR3 authorization in ADR 0043 stopped at
an explicit valuation CLI and a strict six-file archive. That boundary intentionally deferred
Futu data, scoring, valuation synthesis, reports, PDF rendering, and Publisher behavior.

The product decision is now to finish one callable, comprehensive Skill rather than release that
narrow intermediate product. The implementation must still preserve the accepted price-blind,
kernel-isolation, archive-integrity, and no-trading boundaries. Reintroducing recursive successor
gates would add control-plane work without improving the exact-head product review.

## Decision

1. This ADR and `docs/phase5-v1-status.json` are the current product authority. They supersede only
   the present-product scope and release consequences in ADR 0043, the ADR 0041 consequence that
   kept Phase 6 through Phase 9 outside the current authorization, and the product-scope
   prohibitions in Futu market-authority policy v1. The historical decisions and evidence remain
   unchanged.
2. All remaining work is delivered in one PR3 with four ordered, bounded implementation slices:
   trusted run/archive core; SEC/IR research plus valuation-intent-only Futu data plane;
   independent valuation synthesis plus four-lens scoring; and report/PDF/local Publisher plus the
   callable Skill. These are reviewable implementation groups, not successor gates. No
   acceptance-only branch, dynamic profile, protected-status publisher, or next-gate seeding is
   authorized.
3. PR3 has one acceptance point: its exact final commit and tree. The existing four required
   Actions contexts remain unchanged. A separate fresh-context reviewer must bind the exact
   commit, tree, test inventory, P0-P3 counts, and report SHA-256. Because PR3 is the release
   candidate delivery, both candidate replay and independent review require P0=P1=P2=P3=0.
4. The initial supported production universe is one USD-denominated, SEC-reporting ordinary
   common stock on XNYS or XNAS. Financial institutions, insurers, funds, REITs, resource
   companies, ADRs, dual listings, multiple share classes, other venues, and complex securities
   remain `specialist_required` until a later reviewed policy authorizes them.
5. SEC filings, issuer investor-relations materials, and audited statements remain the authority
   for financial-statement Facts. A new immutable Futu policy v2 may authorize quote-only Futu
   access to market data, financial statements, revenue breakdown, company information, corporate
   actions, and separately entitled contextual data. Futu financial and company data are
   secondary corroboration or context and can never silently replace an official Fact. Every
   endpoint family requires typed legal, account, entitlement, retention/replay, parser, and
   isolation receipts. The pinned Futu buyback endpoint does not support the current US universe,
   so US repurchases remain SEC/IR-primary and the sidecar records the typed
   `not_supported_for_us_sec_primary` disposition instead of calling that endpoint or fabricating
   a vendor observation.
6. Ordinary research remains target-price and market-capitalization blind and makes exactly zero
   Futu calls. Futu access, including non-price financial-statement and company-information
   cross-checks, is activated only by explicit valuation intent. SEC/IR Facts are established as
   the primary record; entitled Futu non-price data may then corroborate or contest them without
   silently replacing them. Target-security and peer prices become accessible only after the
   canonical research and price-blind valuation inputs are frozen. Analyst consensus, ratings,
   third-party reports, news, and historical recommendations remain quarantined until the current
   conclusion is frozen.
7. The Futu boundary remains read-only and quote-only. Every live run must attest
   `qotLogined=true` and retain the actual boolean `trdLogined` observations. As explicitly
   approved by the user on 2026-09-06, `trdLogined=true` alone is not a rejection condition:
   the official GlobalState API defines it as OpenD's trading-server connection state, and its
   quote-context example returns true. Quote-only capability is enforced by the closed protocol
   allowlist, not inferred from that server connection. This supersedes the earlier false-only
   condition in this ADR, completion overlays, and historical feasibility condition labels;
   those records remain historical. Trading, orders, positions, balances, holdings, and
   account protocols are rejected before OpenD. Credentials stay outside arguments, environment
   variables, the repository, logs, receipts, and publication artifacts. Raw licensed bytes stay
   in a private encrypted content-addressed store and the public/local report package retains only
   authorized normalized fields, hashes, and receipts.
   The public `owner_research` wheel is only the verified client. A separately built private
   sidecar distribution must pin the official SDK, protobuf descriptors, closed adapter registry,
   frame guard, parser, encrypted CAS, rootless launcher, SBOM, and provenance. The host accepts
   data only through a signed, sequenced `open`/`fetch`/`finalize` session with verified peer
   credentials, a pre-run isolation authorization, and post-run runtime and execution attestations.
   A protocol document or client-only implementation is not an executable canary substitute.
8. The byte-pinned private valuation kernel remains read-only and is called exactly once for the
   accepted McKinsey and Penman execution. Its request, result, and six-file archive bytes remain
   unchanged. A downstream `PROJECT_EXTENSION` freezes three independent panels—McKinsey,
   Penman, and reviewed comparables—before it computes separate eligible medians for current value
   and a twelve-month target. Both composites require all three compatible, eligible panels. If
   any panel is missing, partial, blocked, ineligible, or contested, the affected composite is
   `null`; there is no two-panel fallback. No probability or discretionary method weighting is
   permitted. Comparable Current Period Policy v1 admits only named-human-reviewed FY/TTM duration
   Facts available by the research cutoff: their inclusive duration must be 364, 365, 366, or 371
   days and their period end may be no more than 456 days before the valuation date. For both the
   metric and its `weighted_average_diluted_shares` denominator, latest means the maximum
   `(period_end, SourceDocument.published_date)` key. The two selected Facts must have exactly the
   same `start` and `end`; instant current-share Facts are ineligible. Different values or bases at
   one latest key are contested rather than selectable. One stale selection, conflicting latest
   key, or otherwise ineligible preselected peer fails the complete-case comparable panel closed,
   so it contributes no current or twelve-month median value.
9. Four isolated scoring lenses—Graham, Buffett, Munger, and Duan Yongping—consume the same frozen
   evidence and valuation outputs without seeing one another's result. Each lens contains exactly
   five fixed items worth 0-20 points each and emits a 0-100 score only when all five items are
   assessable. `Unknown` or partial evidence remains explicitly nonnumeric and is never coerced to
   zero; it makes that item, lens score, and overall score unavailable. The overall 0-100 score is
   the deterministic equal-weight arithmetic mean of the four complete lens scores. Scores and
   their moderator synthesis may not influence Facts, Claims, Assumptions, CalculationResults,
   panel eligibility, or valuation mathematics.
10. The recommendation is a deterministic downstream label evaluated in this order. Return
    `无法评级` when the run is `partial`, `blocked`, `specialist_required`, or `contested`. Otherwise
    return `回避` when the overall score is below 50, the market price is at least 15% above
    intrinsic value, or a permanent-capital-loss critical red flag exists. Otherwise return
    `重点关注` only when overall score is at least 80, confidence is at least 80%, margin of
    safety is at least 25%, twelve-month upside is at least 20%, and no critical red flag exists;
    return `关注` only when the corresponding thresholds are 70, 70%, 15%, and 10% with no
    critical red flag; all other complete runs return `观察`. These fixed thresholds may not be
    tuned per issuer or after observing price.
11. The strict valuation archive continues to contain exactly the six members specified by ADR
    0043. Report, score, synthesis, source-index, model, chart, and rendering artifacts live in a
    separate manifest-closed publication package that binds the immutable six-file archive by ID
    and hash. Core JSON files are limited to 16 MiB each and 64 MiB across the six-file archive;
    research inputs are limited to 64 MiB each and 256 MiB cumulatively.
12. A complete report is a 30-60 page simplified-Chinese LaTeX PDF with bilingual key terms and
    Python-produced model tables, sensitivity analysis, reverse DCF, and charts. A report-only
    request uses the closed `research_only` profile and remains price-blind; the explicit valuation
    route uses `full_valuation` and includes all three panels, composite values, four-lens score,
    market-expectations comparison, risks, and falsification conditions.
13. Publisher is local-only, explicit, atomic, idempotent for identical bytes, and strictly
    reloadable. It produces the governed structured data, Markdown, LaTeX source, rendered PDF,
    data, charts, receipts, and root manifest; it accepts at most 512 members and 512 MiB of total
    content. It cannot upload, email, message, create a release, trade, or mutate any external
    account. `owner-equity-research` remains the sole implicitly invocable Skill; audit and direct
    Publisher routes remain explicit.
14. Package and plugin versions remain development versions throughout PR3. No
    `v1.0.0-rc.1` tag or GitHub Release may be created until the exact merged `main` commit passes
    all verification and one real isolated Futu canary completes the full data-to-local-PDF path.
    The canary must use an entitled XNYS/XNAS common stock, real market, financial-statement, and
    company-information data, signed Legal/Account/Protocol receipts, quote-login-only evidence,
    the exact signed private sidecar distribution, private-CAS binding, signed session finalization,
    SEC/IR reconciliation, strict archive reload, and local publication reload. Recorded fixtures,
    reviewed files, simulated prices, alternative APIs, protocol documentation, or an unsigned
    locally edited sidecar cannot substitute for that canary.
15. Stable `v1.0.0` remains separately blocked until the same external rights and isolation
    authorities are current for stable use and the release-candidate artifacts, installed Skill,
    CLI, archive reloader, and local Publisher pass a fresh clean-environment smoke test.

## Consequences

- ADR 0043 remains the historical source of the six-file archive and single-kernel invariants, but
  its prohibitions on Futu, Score, composite median values, reports, PDF, and Publisher no longer
  govern the current PR3.
- Existing public contract bytes and the six-file archive stay backward compatible. New score,
  synthesis, vendor-receipt, report, and publication contracts are downstream additions.
- PR3 corrects host filesystem compatibility for macOS's fixed, root-owned
  `/tmp`, `/var`, and `/etc` aliases into `/private`. This includes the existing reviewed-file
  reader and runtime-manifest materializer. Their source-byte pins are updated with the fixes;
  the private kernel, runtime policy, provider semantics, public Schemas, and numerical
  contracts retain their accepted identities. The additive lock refresher still cannot change
  these core pins. Nested caller-created symlinks remain rejected, with production read/write
  and reload regressions included in the same final PR review.
- CI remains deterministic and networkless. Live Futu evidence is a release precondition bound to
  the exact merged commit, not a new recursive branch-protection gate.
- Until the real canary exists, PR3 may be developed and merged after exact-head acceptance, but
  the repository must remain on a development version with no RC or stable tag.
