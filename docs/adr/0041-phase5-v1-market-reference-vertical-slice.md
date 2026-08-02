# ADR 0041: Phase 5 v1 market-reference vertical-slice governance

Status: accepted

Date: 2026-08-02

## Context

The recursive Phase 5 G1-G5 controller and its acceptance-only pull requests were designed to
bootstrap a protected-base oracle one successor at a time. That mechanism accumulated control
plane machinery faster than it delivered an executable market-reference product slice. Its
historical closeouts remain useful evidence, but the recursive controller is no longer the
required path for current Phase 5 work.

Phase 5 now needs a smaller, product-facing loop: one pull request must integrate a bounded
market-reference slice, exercise it on every supported Python runtime, and receive one semantic
review of the exact pull-request head. Release candidates require a stricter finding threshold,
while merged `main` needs a fast smoke and deterministic replay rather than a second PR audit.

## Decision

1. `docs/phase5-v1-status.json` is the canonical current product state. Its current label is
   `Phase 5 v1 market-reference vertical slice`, its state is `in_progress`, and its sole
   authorization is `PR1 market-reference vertical slice`.
2. `docs/phase-status.json`, the recursive gate bundles, acceptance closeouts, audit tools, and
   their recorded CI identifiers are frozen as `legacy_governance`. The exact former workflow is
   archived outside the active Actions directory at
   `legacy_governance/phase5e2b12a-acceptance-gate.yml`. These materials remain historical evidence
   and are not current authorization.
3. The only required pull-request checks are exactly `verify (3.11)`, `verify (3.12)`,
   `verify (3.13)`, and `phase5/semantic-audit`.
4. Each `verify` job runs the non-legacy suite on its named runtime. The Actions context named
   `phase5/semantic-audit` runs one deterministic semantic replay against the exact pull-request
   head and requires `P0=0` and `P1=0`. It is a candidate audit executed by PR-controlled code; it
   is not, and must not be described as, an independent fresh-context review.
5. A release-candidate tag matching `v*-rc*` requires `P0=P1=P2=P3=0`. A push to `main` runs
   smoke and deterministic replay under the same `phase5/semantic-audit` check name; it does not
   repeat the full pull-request audit.
6. Before merge, a separate fresh-context reviewer must inspect the actual code paths without
   using a production parser, selector, builder, or compiler as its only oracle. Its report stays
   outside the repository, binds the exact commit and tree, test counts, `P0`-`P3` counts and its
   own SHA-256, and leaves that evidence on the pull request. Ordinary PRs require independently
   confirmed `P0=P1=0`; release candidates require `P0=P1=P2=P3=0`. The merge operator enforces
   this external review gate in addition to the four required Actions contexts.
7. `scripts/verify_phase5_v1.py` writes a canonical candidate-replay JSON report outside the
   repository. CI may retain that report as an artifact, but it cannot self-certify independence,
   and new workflow or run identifiers must never be written into product state.
8. `.github/workflows/phase5e2b12a-acceptance-gate.yml` is replaced by a small, manually
   dispatched legacy replay with no credentials or status-writing jobs. It checks out the frozen
   baseline and runs only historical governance tests. It has no pull-request, push, schedule, or
   workflow-run trigger and cannot publish current acceptance.
9. A reviewed-file market authorization is reserved in the component-locked per-user state store
   before the provider reads any market evidence. The store root is derived at module import from
   the operating-system account database, not from caller input or mutable `HOME` state. Its key is
   only the immutable Handoff ID and fingerprint, so copying the price-blind directory cannot fork
   a second quote. A successful access adds a completion record and seals the authorization
   directory. Both records are bound into the validation context and market-evidence closure.
10. The one-use store is an acquisition-time authority, not a portable archive. PR3 must preserve
   the immutable reservation and completion attestations in `market-reference.json`; clean-room
   archive replay verifies those attestations, their component-lock authority, and their Handoff
   bindings without pretending that the originating machine's inode is portable. Acquiring a new
   quote still requires a fresh Handoff and a live one-use store.
11. The operating-system account and the component-locked code are trusted boundaries. Mode `0400`
    records and a completed `0500` subdirectory protect against accidental mutation and other
    local accounts; they cannot protect against a malicious process already running as the same
    UID, which could change permissions or replace code. Any such local compromise invalidates the
    run and its audit environment rather than being treated as a successfully enforced
    application-level guarantee.
12. Current-share V2 coverage uses the purpose-specific tool namespace
    `owner-research-current-share-coverage/`. This is an identity break, so the internal
    integration policy advances from `2.0.0` to `2.1.0` and the search authority from `1.0.0` to
    `2.0.0`. Phase 4 source-search receipts may use the same SEC or IR endpoints, but cannot become
    V2 authority merely by sharing infrastructure. A partial or drifted receipt inside the
    reserved namespace fails closed; the exact V2 ledger consumes only the registered version and
    endpoint set. Historical policy identities remain reproducible at their original commits.
13. The three verify jobs may use only the dedicated Kernel Reader GitHub App to obtain the exact
    private rc.2 checkout. The App is restricted to contents/metadata read on that one repository;
    the checkout persists no credential, its remote is removed, and the installation token is
    revoked before project installation or candidate code executes. The test process then runs
    without network access. Its key and ID remain in the `phase5e-private-kernel-readonly`
    environment, whose deployment policy admits only `main`, `refs/pull/*/merge`, the reviewed
    Phase 5 v1 branch families, and `v*-rc*` tags. Fork pull requests still receive no secret. No
    Controller or Gate Author credential is part of current CI.
14. This public repository currently has exactly one write-capable collaborator, the owner. A
    same-repository writer can change an Actions workflow and therefore already belongs to the
    Kernel Reader secret trust boundary; the static verifier closes the token step, checkout,
    revocation order and scalar-use paths, while the separate fresh-context review checks the exact
    head. Fork pull requests receive no environment secret and fail closed. Adding another writer
    requires a new security review before that writer may use a Phase 5 v1 deployment branch.

## Consequences

- G1-G5 transitions, acceptance-only branches, dynamic successor profiles, protected status
  publication, and recursive gate seeding are retired as current requirements.
- Existing technical contracts and historical closeouts are not deleted or rewritten by this
  decision.
- The reviewed-file release-candidate path has no network, account, or trading surface. Its
  one-use state store is machine-local by design; portable auditability comes from the bound
  attestations, while portable re-acquisition is forbidden.
- Branch protection must use the four exact Phase 5 v1 check contexts above and remove the old
  recursive acceptance contexts from its required set.
- ADR 0039 remains historical design evidence. Its acceptance-only and recursive-control
  provisions are superseded by this ADR; its product-semantic findings remain valid unless a
  later product ADR changes them.
- Phase 6 through Phase 9 remain outside the authorization granted here.
