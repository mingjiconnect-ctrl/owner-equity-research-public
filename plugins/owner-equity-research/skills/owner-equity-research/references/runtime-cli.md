# Unified CLI and runtime configuration

Use the installed `owner-equity-research` entry point for the comprehensive workflow. It exposes
exactly these routes:

```text
owner-equity-research research
owner-equity-research quarterly
owner-equity-research valuation
owner-equity-research report
owner-equity-research publish
owner-equity-research audit
```

Every route requires `--runtime-config`, `--issuer-id`, `--data-cutoff-date`, `--requested-by`, and
`--requested-at`. `--requested-by` must identify a named human as `human:<name>` and
`--requested-at` must be timezone-aware. `publish` additionally requires
`--profile research_only|full_valuation`. The `report` route fixes the profile to
`research_only` and additionally requires `--output <new-package-directory>`; the `valuation`
route fixes it to `full_valuation`.

For example, an ordinary price-blind invocation is:

```sh
owner-equity-research research \
  --runtime-config /absolute/path/owner-equity-runtime-config.json \
  --issuer-id issuer:us:example \
  --data-cutoff-date 2026-08-26 \
  --requested-by human:reviewer-name \
  --requested-at 2026-08-26T09:00:00+08:00
```

The runtime configuration is a canonical JSON locator, not research evidence or permission. Its
top-level fields are exactly `schema_version`, `artifact_type`, `research`, `report`, `publication`,
`audit`, and `valuation`. All supplied paths must be absolute. The `research` object supplies
`research_graph_file` and `research_bundle_directory`; those artifacts must already have been built
and validated. The runtime strictly reloads them before orchestration.
This CLI does not acquire SEC/IR evidence or fabricate a research graph.

A report invocation atomically publishes the report already built in that same price-blind run:

```sh
owner-equity-research report \
  --runtime-config /absolute/path/owner-equity-runtime-config.json \
  --issuer-id issuer:us:example \
  --data-cutoff-date 2026-08-26 \
  --requested-by human:reviewer-name \
  --requested-at 2026-08-26T09:00:00+08:00 \
  --output /absolute/private-parent/example-research-report
```

The usable PDF is `example-research-report/report/report.pdf`. The output is a strictly reloaded
`research_only` package containing the other report formats, build receipt, and frozen research
inputs; delivery does not reacquire research or invoke Futu or valuation. The output parent must
already exist, be owned by the current user, and not be group/world writable.

Use only the capabilities required by the selected route:

| Route | Non-null blocks needed for a complete run | Blocks that must be null |
| --- | --- | --- |
| `research`, `quarterly` | `research` | `report`, `publication`, `audit`, `valuation` |
| `report` | `research`, `report` | `publication`, `audit`, `valuation` |
| `publish --profile research_only` | `publication` | `research`, `report`, `audit`, `valuation` |
| `audit` | `audit` | `research`, `report`, `publication`, `valuation` |
| `valuation` | `research`, `report`, `publication`, `valuation` | `audit` |
| `publish --profile full_valuation` | `publication` | `research`, `report`, `audit`, `valuation` |

The report route's CLI `--output` is only its local delivery destination; it does not populate or
authorize the runtime `publication` block, which remains `null` for that price-blind route.
Price-blind routes must set `valuation` to `null`; the loader rejects dormant valuation authority.
For a full-valuation route, `valuation: null` is admitted only as a fail-closed configuration that
cannot complete the live valuation path; a complete run needs the governed valuation locators.
The read-only `audit` route loads only `audit.package_directory`; `research` must be `null`, so an
audit cannot acquire or rebind an unrelated research graph. The `publish` route is likewise a
strict existing-package operation: its `publication` block contains `input_package_directory` and
`output_directory`, while every acquisition, Futu, kernel, scoring, and report-build block must be
null. It reloads the source package, reproduces the exact byte set atomically, and rejects any
profile, issuer, cutoff, manifest, or byte drift. The valuation route's `publication` block contains
only `output_directory`; the `report` block contains `report_spec_file`,
and the `audit` block contains `package_directory`. The closed `valuation` locator contains the
signed Futu authority/evidence paths, private sidecar endpoint, pinned-kernel inputs, reviewed panel
inputs, and output locations required by the valuation route. Never invent, copy, or weaken these
authorities to make a configuration load.

Inspect the exact installed options with:

```sh
owner-equity-research --help
owner-equity-research research --help
owner-equity-research quarterly --help
owner-equity-research valuation --help
owner-equity-research report --help
owner-equity-research publish --help
owner-equity-research audit --help
owner-research-validate --help
owner-research-valuation --help
```

`owner-research-validate` remains the compatibility validator. `owner-research-valuation` remains
the low-level deterministic kernel runner and is not a substitute for the governed comprehensive
valuation route.

## Native Mac OpenD setup

When the user explicitly asks to check their logged-in Mac OpenD, use the separate
verified sidecar environment's `python -I -B -m owner_research_futu_sidecar.native_preflight`.
This is a bounded connection check, not research or valuation: one InitConnect plus
one GlobalState request, no data/price/account calls, no retry, and a 45-second timeout.
It connects only to `127.0.0.1:11111`, does not copy login credentials, and prints a
status/identity/hash observation. A true `trdLogined` is recorded, not rejected.
Never invoke this check implicitly during ordinary research or treat success as a
financial API entitlement, signed rights receipt, or full release canary.

The complete native run uses `macos_local_read_only`: parallel v2 supply and runtime
receipts, `vm_image_sha256: null`, and `credentials_location: user_managed_macos_opend`.
The separate non-root sidecar and supervisor retain the same signed plan, protocol
whitelist, encrypted CAS and finalization used by the v1 Linux VM profile. Native
Mac mode does not claim a VM or separate network namespace. Use the existing signed
authority locators in the unified runtime config; there is no new public CLI route.
