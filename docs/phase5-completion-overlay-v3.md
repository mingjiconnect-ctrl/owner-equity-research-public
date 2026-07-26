# Phase 5 completion overlay v3

This overlay narrowly supersedes the market-source and provider portions of
`phase5-completion-overlay-v2.md` for the external Phase 5E-2C-P feasibility gate and later
market-reference subsections.  Every non-conflicting v2 control remains mandatory.  Overlay v2
also remains immutable historical evidence; it is not the current Futu authority policy.

## Governed market authority

Futu may be used only as a governed broker-vendor source.  Its accepted price basis is
`vendor_unadjusted_regular_session_daily_close`; it is not described as an exchange official
closing price.  Production retrieval is one specified-date `K_DAY` history request with
`AuType.NONE`, `Session.RTH`, `extended_time=false`, and only date, close, and volume fields.
Snapshot/`last_price`, `prev_close`, adjusted, intraday, after-hours, overnight, stale, and
fallback prices are forbidden.  Exactly one row must match the expected completed trading day and
its volume must be positive.

The Protobuf `double` wire bit pattern is the authoritative numeric transport.  The repository
records the binary64 hex value, shortest round-trip decimal, and exact decimal expansion.  It does
not claim that Futu supplied a native Decimal.  Market equity is calculated without tolerance or
implicit rounding from the exact binary64 decimal and the accepted current-common-share integer.

## Account and runtime isolation

The existing Futu account may be considered by the feasibility gate even when it has a brokerage
relationship or holdings, but only when every run independently proves `qotLogined=true` and
`trdLogined=false`.  Account value, cash, positions, orders, and the existing Xiaomi holding are
never read.  A small balance or small holding is not an isolation control.  If trade login cannot
remain false, the only permitted remediation is a dedicated quote-only Futu ID; the system does
not fall back to scraping, a free API, or manual price entry.

OpenD and the necessary protocol material remain outside the research wheel and Plugin in a
rootless isolated Linux VM.  The host reaches only a stdin/stdout quote facade.  No OpenD port is
mapped to the host, credentials live only in VM tmpfs, and every trading/account protocol is
rejected before reaching OpenD.  Raw licensed responses live only in an encrypted private CAS.

Every live run rechecks quote entitlement, delay class, quota, protocol version, promotion state,
`qotLogined=true`, and `trdLogined=false` before requesting data.  Any ambiguity or drift blocks
the run.  Credentials may not enter environment variables, command arguments, Git, logs, receipts,
or audit artifacts.

## Scope and evidence

No Futu Skill is installed or copied.  Phase 5E-2C-P is an external, repository-write-free
feasibility review.  Phase 5E-2C through 2E remain provider-neutral.  Only Phase 5E-2F, after 2D
and 2E acceptance, may onboard OpenD, the required protocol descriptors, and a repository-owned
read-only adapter.  Futu does not replace SEC, issuer IR, or regulatory evidence and does not
supply current shares.
Financial data, news, signals, flows, derivatives, account data, positions, or trading operations
are outside Phase 5 and require a separate post-release Vendor Track.

The feasibility gate must independently prove all four conditions: the actual account agreement
permits internal valuation use; the data rights permit encrypted private-CAS retention and
independent audit replay; raw Protobuf S2C bytes can be captured stably; and quote login can remain
true while trade login remains false.  Failure of any condition blocks Phase 5 without a lower
quality fallback.

OpenD build, protocol descriptor, parser, adapter, facade image, licenses, SBOM, and runtime policy
are content-addressed supply-chain inputs.  A change to any public Schema, component lock, provider
authority, parser, or price-blind input invalidates the old Handoff, Snapshot, request, result, and
archive and requires the plan-defined new-root replay.  Licensed raw data is never uploaded to
GitHub; GitHub receives hashes and non-secret receipts only.

The closed machine policy is `scripts/phase5e-futu-market-authority-policy-v1.json`.  Its canonical
bytes and SHA-256 are part of the protected-base trust root.  External feasibility receipts and the
post-feasibility 2C-0 authority must bind that exact policy; neither the external author App nor a
candidate branch may add, replace, release, or rewrite it.

The signed feasibility handoff may authorize only the exact 2C-0 contract surface. It must leave
`next_gate_authority_sha256` null and the 2C-0 total-closeout state must authorize no 2C-1
implementation. A later protected-base Controller review must install a separately audited 2C-1
authority. This deliberate reauthorization boundary prevents the feasibility author from
pre-authorizing later Provider, OpenD, parser, market-evidence, or kernel-execution code.
