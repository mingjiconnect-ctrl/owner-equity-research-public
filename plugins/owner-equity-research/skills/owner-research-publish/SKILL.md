---
name: owner-research-publish
description: Use only when explicitly invoked with $owner-research-publish to build or strictly reload one local research_only or full_valuation Owner Research package. Consume existing strict typed artifacts only. Do not acquire data, call Futu or the valuation kernel, upload, message, release, or mutate external services.
---

# Owner Research Publish

Publish one closed local audit package. This Skill is explicit and never implicitly invoked.

## Preconditions

1. Require the strictly reloaded ResearchBundle/RunManifest and completed ReportBuildResult.
2. For `research_only`, require price-blind report bytes and no Futu, market, target, or valuation
   members.
3. For `full_valuation`, additionally require the exact strictly reloaded six-file archive, all
   three valuation panels, CompositeValuationResult, OwnerScorecard, Futu Evidence Bundle, and
   report receipt.
4. Reject caller-supplied paths or free hashes as identity authority.

## Local publication

Use the main Skill's
[publication workflow](../owner-equity-research/references/publication-workflow.md). Enforce the
exact profile member set, 512-member/512-MiB limits, no-follow staging, fsync, `0444` files, `0555`
directories, atomic rename, idempotence for identical manifests, and final strict reload. Never
overwrite different content.

Do not render or reacquire anything during publication. Do not upload, email, create a GitHub
Release, trade, or access account state.
