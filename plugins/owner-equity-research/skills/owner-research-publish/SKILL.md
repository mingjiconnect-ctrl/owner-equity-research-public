---
name: owner-research-publish
description: Use only when explicitly invoked with $owner-research-publish to assess whether a future owner-research package satisfies Phase 1 validation gates. Phase 7 publishing is not implemented.
---

# Owner Research Publish

This is a Phase 1 shell. It can assess readiness but cannot publish.

## Readiness check

1. Require validated contracts, a clean reference graph, and a complete `RunManifest`.
2. Require a frozen current conclusion before any historical comparison.
3. Require zero open P0 or P1 audit findings.
4. Return `NOT_IMPLEMENTED_PHASE_7` after the readiness result.

Do not render PDF, Markdown, HTML, or other reports. Do not upload, message, release, or publish
anything, and do not infer permission to do so.
