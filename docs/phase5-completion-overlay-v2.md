# Phase 5 completion overlay v2

This document supersedes `phase5-completion-overlay-v1.md` for work after Phase 5E-2B.1-2A.
The older overlay remains immutable historical planning evidence.

## Current authority

- The valuation kernel remains pinned to annotated `v2.0.0-rc.2`, commit
  `be9b0773d5a78f5f8a33ba982494512668df85fe`.
- Phase 5E-2B.1-2A remains validation-only. It creates no canonical event Fact, market evidence,
  Snapshot, valuation request, kernel result, report, Score, or Publisher output.
- Its implementation PR is a one-time trust bootstrap because the preceding `main` did not contain
  this base-owned gate. It must be reviewed as such and cannot claim retroactive self-certification.
- After that merge, the installed workflow, 2A verifier/trust/oracles, and preinstalled 2B
  verifier/trust/oracle/tests are protected-base controls. Candidate 2B code cannot modify them.

## Closed legacy bootstrap and recursive successor state machine

| State | Machine state | Only permitted pull request |
|---|---|---|
| S0 | 2A `implementation_complete_pending_acceptance` | exact 2A acceptance-only PR |
| S1 | 2A `accepted_closed` | `feature/phase5e2b12b-canonical-rollforward` |
| S2 | 2B `implementation_complete_pending_acceptance` | exact 2B acceptance-only PR |
| S3 | 2B `accepted_closed` | only the exact inert `Phase 5E-2B.1-2C` gate bootstrap |

S3 enters one protected-base gate cycle. Here `Phase 5E-2B.1-2C` means the current-share
coverage/Claim-transition/recursive-closure subsection; `Phase 5E-2C` means the later exact market
evidence phase. They are distinct and must never be abbreviated to an ambiguous "2C".

| Gate state | Meaning | Only permitted transition |
|---|---|---|
| G1 | inert gate bundle pending acceptance | gate acceptance-only PR |
| G2 | gate accepted | exact successor implementation named by the accepted bundle |
| G3 | successor implementation pending acceptance | successor acceptance-only PR |
| G4 | successor accepted | post-successor/total-closeout acceptance-only PR |
| G5 | total closeout accepted | repository-external `Phase 5E-2C-P` Futu feasibility gate |

Each gate ID, directory, governed path, branch, predecessor fingerprint, test inventory, and audit
profile is unique and acyclic. The current protected authority deliberately ends at the external
feasibility gate with no repository successor seed. After feasibility succeeds, a separately
reviewed protected-controller change must install the exact `Phase 5E-2C-0` authority and its
executable semantic oracle. Candidate-authored policy cannot bridge that boundary. Missing
authority, weak or candidate-only semantic evidence, unknown phases, mixed/reversed/skipped
states, and reuse of any prior production or test path fail closed.

The candidate semantic-oracle file is an inert five-literal manifest only: no imports, calls,
control flow, reflection, file access, or execution. Arithmetic, Git-object replay, hashes, exact
diffs, transition validation, and adversarial cases are owned by the protected-base independent
oracle. Dynamic audit profiles are derived from the deepest validated gate: S3/G1 use bootstrap,
G2/G3 use the accepted successor profile, G4 uses the transition profile, and the current G5 uses
the external-feasibility profile. It does not authorize candidate Python or market access.

Phase 5E-2B.1-2C production, Phase 5E-2B.1-3, Phase 5E-2C through Phase 5E-2F, Phase 5E-3 through
5E-6, and Phase 5F remain prohibited until their mapped G1-G5 state reaches the applicable
accepted state. Phase 6 through Phase 9 are outside this Phase 5 successor map and remain
prohibited until a separate reviewed control-plane change explicitly authorizes them.

Phase 5 current authority: S3 -> G1 -> G2 -> G3 -> G4 -> G5 -> external 2C-P; after feasibility a new protected gate is required; Phase 6-9 require separate reviewed control-plane authorization; Phase 5E-2B.1-2C != Phase 5E-2C.

Before the validated two-file closeout, only 2A acceptance is authorized; afterward 2A is
accepted/closed, while later production remains prohibited in both states except for the exact
successor named by the table.

## Remaining Phase 5 order

The required order is 2B canonical exactly-once consumption; Phase 5E-2B.1-2C coverage, Claim
transition, and recursive closure; 2B.1 total closeout; the repository-external Phase 5E-2C-P Futu
feasibility gate; provider-neutral vendor-close/numeric-transport contracts and raw evidence;
Snapshot v4;
market-layer replay; governed Futu OpenD onboarding at Phase 5E-2F; final request; isolated
pinned-kernel execution; replay/adversarial closeout; six-file archive; live shadows; clean-room
replay; final Phase 5 audit; annotated `v0.5.0-alpha.1`.

Phase 5E-2C-P is not a repository branch, Plugin version, or ordinary PR. It is three ordered,
repository-external gates whose signed receipts are later consumed by a separately reviewed,
protected-controller PR that installs the exact provider-neutral Phase 5E-2C-0 gate:

1. `2C-P-Legal` proves the exact contracting entity, account region, agreement version, internal
   valuation right, encrypted private-CAS retention right, retention period, and clean-room audit
   replay right before any live payload is captured.
2. `2C-P-Account` proves a dedicated Futu ID with no brokerage/trading account. The existing account
   with holdings may be used only for manual feasibility observation and can never become the live
   production authority.
3. `2C-P-Protocol` proves safe OpenD configuration, authoritative protocol descriptors, governed
   vendor-symbol mapping, daily-bar finality, the vendor's canonical US daily-close price precision
   and rounding rule, bounded raw transcript capture, and quote-only runtime isolation.

Failure of any item blocks Phase 5 without a web-scraping, free-API, trading-account, or manually
entered fallback. API success proves technical access only; it does not prove internal-use,
retention, or replay rights.

Until the vendor's daily-bar semantics are documented or confirmed in writing, the Futu price
authority is named `vendor_unadjusted_daily_close`, not an exchange official close and not a
regular-session close. Production requests use one specified-date daily K-line with `AuType.NONE`,
exactly one matching finalized row, and positive volume. `Session.RTH` is not treated as evidence
for a daily bar. Snapshot/`last_price`, adjusted, intraday, after-hours, overnight, stale, or
automatically substituted prices are forbidden.

The Protobuf `double` bit pattern is authoritative transport evidence only. The research layer
records `wire_binary64_hex` and its exact binary64 decimal interpretation for replay, but neither
value automatically becomes the economic quote. The economic `vendor_price_decimal` must be
derived under the locked vendor precision/rounding policy established by `2C-P-Protocol`;
otherwise compilation is blocked. Market equity is the exact Decimal product of that governed
vendor price and current common shares. Tolerance comparison, guessed decimal places, implicit
rounding, and describing the wire value as vendor-native Decimal are forbidden.

Raw evidence binds one complete, bounded protocol exchange rather than an isolated response:
canonical C2S and S2C frame hashes, protocol ID `3103`, serial-number pairing, header/body length
and SHA-1 checks, Protobuf descriptor SHA, request fields, response identity, `retType/errCode`, and
an empty `nextReqKey`. Login and credential frames never enter CAS. The public Snapshot remains
provider-neutral; OpenD- and Futu-specific lineage stays in internal receipts and component lock.

Formal ticker, MIC, currency, and share class remain price-blind research evidence. A governed
vendor-symbol mapping must additionally bind the Futu vendor security ID/code, exchange type,
security type, and effective period through quote-only static-security evidence. `US.<ticker>` is
never inferred to prove MIC or share class; ambiguous mappings are blocked or specialist-routed.

No Futu Skill is installed or copied. OpenD, the necessary protocol descriptors, parser, and
quote-only facade live in a separately built private sidecar image outside the research wheel and
Plugin; the research repository locks only its digest, SBOM, provenance/signature evidence, and
component hashes. A locally calculated download hash is never represented as a vendor signature.
Futu financial data, news, technical signals, flows, derivatives, account data, positions, and
trading APIs are outside Phase 5. SEC, issuer IR, and regulatory filings remain the sole upstream
authority for research Facts and current common shares.

The live sidecar runs in an isolated rootless Linux VM with loopback-only OpenD, no host port
mapping, telnet/websocket disabled, logging disabled, reminder push disabled, automatic quote-right
takeover disabled, Protobuf-only transport, and an ephemeral profile. It accepts only the closed
quote protocol set needed for init/heartbeat, global state, history quota, static security identity,
and historical K-line retrieval; it exposes no generic raw-send surface. No trading password or
unlock material is supplied. Startup, pre-quote, post-quote, and pre-shutdown checks must each prove
`qotLogined=true` and `trdLogined=false`; any trade-login transition quarantines the entire run.
Credentials remain in VM tmpfs and never enter environment variables, command lines, Git, logs,
artifacts, or audit reports. All `Trd_*`, unlock, account, funds, position, order, modify, and cancel
protocols are rejected before OpenD.

The encrypted private CAS records separate plaintext-evidence and encrypted-object hashes,
envelope-key identity, nonce, rights/retention policy, and deletion state. Audit artifacts receive
only non-secret receipts and hashes, never keys, credentials, or licensed raw market payloads.

Every subsection requires implementation review, PR-head semantic audit, merged-main replay, a
separate acceptance-only PR, and P0=P1=P2=P3=0 before its successor is authorized. A change to a
Schema, component lock, provider authority, Handoff, or price-blind input invalidates all dependent
artifacts; they must be regenerated rather than patched.

## CI and remote-governance boundary

Candidate-owned pull-request CI receives no Actions/environment secret or private-kernel
credential. A protected-base job may create a credential-free but source-bearing,
content-addressed kernel interface pack without checking out candidate code; the candidate audit
consumes only that pack in a no-network, read-only sandbox. Trusted
audit manifests are written by protected-base controls, not candidate scripts. Before publishing
that one-day private artifact, the remote gate requires the personal research repository to have
exactly one collaborator (its owner) and no pending invitations; any broader artifact audience
blocks acceptance.

Private-repository branch protection, protected environments, a pre-pinned dedicated Controller
App, a separate one-repository read-only Kernel Reader App, and
Administration/Actions/Secrets/Variables/Environments read evidence are external
prerequisites. Because the repository currently has one human administrator, the protected
controller's independently generated structure and read-only-audit statuses are the non-self-signed
acceptance authority; the branch rule deliberately requires zero human approvals and permits no
bypass. If the GitHub account cannot enforce those controls, remote acceptance remains blocked even
when local semantic tests pass.

Current external state is explicitly blocked at Controller bootstrap: the private repository is on
GitHub Free, the branch-protection endpoint returns 403, no protected environments or pinned
Controller/Kernel Reader App installations exist, and merge/squash/rebase are all enabled. Until
GitHub Pro (or an
equivalent enforceable private-repository authority), the dedicated App, both protected
environments, exact main protection, and merge-mode restrictions are verified and pinned, no
acceptance-only PR may be created and no successor may be declared accepted/closed. This external
blocker does not change `docs/phase-status.json` or authorize later production work.
