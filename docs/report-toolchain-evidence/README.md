# Report toolchain evidence status

The packaged authority registry in
`src/owner_research/resources/report/report-toolchain-authority-v1.json` is the
current authority for callable report builds.

`macos-arm64/macos-arm64-report-toolchain-runtime-audit.json` is an immutable
historical audit dated 2026-08-24. It binds the registry version that existed on
that date and must not be treated as a current-registry audit. Current report
builds record the exact packaged authority fingerprint in their typed build
receipt and are reloaded against that authority before publication.
