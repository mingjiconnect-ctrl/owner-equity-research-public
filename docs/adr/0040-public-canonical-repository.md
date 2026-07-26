# ADR 0040: Public canonical repository and isolated private authorities

Status: accepted

## Decision

`mingjiconnect-ctrl/owner-equity-research-public` is the canonical public source
repository. It begins with one clean root commit whose content-addressed
provenance identifies the last verified private source snapshot. The private
development commit graph is intentionally not imported.

Public visibility changes the audit-artifact trust boundary:

- source code, synthetic fixtures, dependency wheels, and normalized
  credential-free audit manifests may be public;
- private-kernel source packs, GitHub App credentials, Futu credentials,
  licensed raw market responses, and private CAS objects may not be uploaded as
  public repository artifacts;
- repository-scoped Actions secrets and variables remain empty;
- credentials live only in branch-restricted protected environments.

Three single-installation GitHub Apps enforce separation:

1. `owner-equity-p5-controller` reads public control state and writes only the
   pinned controller status contexts.
2. `owner-equity-kernel-reader` has `contents:read` and `metadata:read` on only
   the private pinned valuation-kernel repository.
3. `owner-equity-gate-author` has the minimal contents/pull-request write
   authority on only the public research repository.

Public visibility does not make licensed market data public and does not grant
an open-source license. A license may be added only by an explicit later
decision.

## Consequences

- Historical private closeouts are verified from the immutable public-root
  snapshot plus their recorded commit, tree, CI, and audit hashes.
- New changes are verified entirely through the public commit graph.
- Any public Actions artifact outside the closed sanitized allowlist blocks the
  remote gate.
- The Skill remains installable from a public tag without exposing kernel
  credentials or raw vendor data.

