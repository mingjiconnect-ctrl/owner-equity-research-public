#!/usr/bin/env python3
"""Independent Phase 5E-2A.2 rc.2 and current-share contract oracle."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "d7197942f447a011590a503c69da065fdbdc07c0"
SNAPSHOT_SCHEMA = "schemas/market-reference-snapshot.schema.json"
KERNEL_TAG = "v2.0.0-rc.2"
KERNEL_TAG_OBJECT = "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
KERNEL_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
REQUEST_SHA = "67e991484943897585a79a8a1d3d0d52ebb36ec0ba4245cad9b17972877cca3d"
RESULT_SHA = "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683"
FORBIDDEN_NAMES = {
    "build_market_reference_snapshot",
    "compile_market_reference_snapshot",
    "compile_share_basis",
    "generate_market_evidence",
    "compile_final_request",
    "run_valuation_kernel",
    "write_valuation_artifacts",
}


def _git(repository: Path, *args: str, text: bool = True) -> str | bytes:
    output = subprocess.check_output(
        ["git", "-C", str(repository), *args], text=text, stderr=subprocess.STDOUT
    )
    return output.strip() if text else output


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _schemas(revision: str | None = None) -> dict[str, str]:
    result = {}
    for path in sorted((ROOT / "schemas").glob("*.json")):
        relative = path.relative_to(ROOT).as_posix()
        payload = path.read_bytes() if revision is None else _git(
            ROOT, "show", f"{revision}:{relative}", text=False
        )
        result[relative] = _sha(payload)
    return result


def _assert_no_production_surface() -> None:
    for relative in (
        "src/owner_research/valuation_market_reference_types.py",
        "src/owner_research/valuation_handoff_validation.py",
        "src/owner_research/valuation_market_execution_types.py",
    ):
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        if names.intersection(FORBIDDEN_NAMES):
            raise SystemExit(f"{relative} exposes a prohibited Phase 5E-2B+ surface")


def main() -> int:
    if subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", BASELINE, "HEAD"]
    ).returncode:
        raise SystemExit("HEAD is not descended from the accepted Phase 5E-2A.1 baseline")
    sys.path.insert(0, str(ROOT / "src"))
    import owner_research

    if owner_research.__version__ != "0.5.0.dev10":
        raise SystemExit("Phase 5E-2A.2.1 Python version is not dev9")
    current = _schemas()
    baseline = _schemas(BASELINE)
    if len(current) != 43 or {path for path in current if current[path] != baseline[path]} != {
        SNAPSHOT_SCHEMA
    }:
        raise SystemExit("Phase 5E-2A.2 must change exactly the Snapshot public Schema")
    schema = json.loads((ROOT / SNAPSHOT_SCHEMA).read_text(encoding="utf-8"))
    encoded = json.dumps(schema, sort_keys=True)
    if (
        schema["properties"]["schema_version"] != {"const": "3.0.0"}
        or schema["properties"]["market_policy_version"] != {"const": "3.0.0"}
        or schema.get("additionalProperties") is not False
        or any(
            token in encoded
            for token in (
                "point_in_time_fully_diluted_common",
                "diluted_share_fact_id",
                "point_in_time_diluted_shares_decimal",
            )
        )
    ):
        raise SystemExit("Snapshot v3 hard break or current-share semantics drifted")
    share = schema["$defs"]["shareBasis"]["properties"]
    if set(share["evidence_kind"]["enum"]) != {
        "direct_point_in_time",
        "issued_less_treasury",
        "completed_event_rollforward",
    }:
        raise SystemExit("Snapshot v3 evidence-kind registry drifted")

    lock = json.loads((ROOT / "component-lock.json").read_text(encoding="utf-8"))
    kernel = lock["valuation_kernel"]
    if (
        lock["lock_version"] != "1.2.0"
        or lock["owner_equity_research"]["plugin_version"] != "0.5.0-dev.10"
        or lock["owner_equity_research"]["public_schema_sha256"] != current
        or kernel["tag"] != KERNEL_TAG
        or kernel["annotated_tag_object"] != KERNEL_TAG_OBJECT
        or kernel["commit"] != KERNEL_COMMIT
        or kernel["package_version"] != "2.0.0rc2"
        or kernel["plugin_version"] != "2.0.0-rc.2"
        or kernel["public_schema_sha256"]["schemas/valuation-request.schema.json"]
        != REQUEST_SHA
        or kernel["public_schema_sha256"]["schemas/valuation-result.schema.json"]
        != RESULT_SHA
    ):
        raise SystemExit("component-lock 1.2.0 does not pin the complete rc.2 identity")
    baseline_lock = json.loads(_git(ROOT, "show", f"{BASELINE}:component-lock.json"))
    if lock["market_access_authority"] != baseline_lock["market_access_authority"]:
        raise SystemExit("frozen market-access authority subtree changed")

    kernel_repository = Path(
        __import__("os").environ.get(
            "OWNER_VALUATION_REPO", str(ROOT.parent / "owner-valuation-kernel")
        )
    ).resolve()
    if (
        _git(kernel_repository, "rev-parse", "HEAD") != KERNEL_COMMIT
        or _git(kernel_repository, "rev-parse", KERNEL_TAG) != KERNEL_TAG_OBJECT
        or _git(kernel_repository, "cat-file", "-t", KERNEL_TAG) != "tag"
        or _git(kernel_repository, "rev-parse", f"{KERNEL_TAG}^{{}}") != KERNEL_COMMIT
    ):
        raise SystemExit("local kernel checkout does not replay the annotated rc.2 tag")
    for relative, expected in kernel["public_schema_sha256"].items():
        if _sha((kernel_repository / relative).read_bytes()) != expected:
            raise SystemExit(f"pinned rc.2 Schema drifted: {relative}")
    request = json.loads((kernel_repository / "schemas/valuation-request.schema.json").read_text())
    bridge = request["$defs"]["mckinsey"]["properties"]["equity_bridge"]
    required = set(bridge["required"])
    if not {
        "share_denominator_fact_id",
        "share_denominator_kind",
        "share_denominator_evidence_kind",
    }.issubset(required):
        raise SystemExit("rc.2 request-v2 current-share mapping fields are unavailable")

    source = "\n".join(
        (
            (ROOT / "src/owner_research/valuation_handoff_validation.py").read_text(
                encoding="utf-8"
            ),
            (ROOT / "src/owner_research/valuation_current_share_evidence.py").read_text(
                encoding="utf-8"
            ),
        )
    )
    required_tokens = {
        "claim_control_fingerprint",
        "future_request_v2_mapping_fingerprint",
        "common_shares_outstanding",
        "issued-less-treasury/1.0.0",
        "completed-event-rollforward/1.0.0",
    }
    if any(token not in source for token in required_tokens):
        raise SystemExit("current-share or claim-control validation surface is incomplete")
    _assert_no_production_surface()

    state = json.loads((ROOT / "docs/phase-status.json").read_text(encoding="utf-8"))
    if state["release_tag"] is not None:
        raise SystemExit("Phase 5E-2A.2.1 successor created an unauthorized release tag")
    closeouts = [*state.get("prior_closeouts", ()), state.get("closeout", {})]
    accepted = next(
        (item for item in closeouts if item.get("phase") == "Phase 5E-2A.2.1"),
        None,
    )
    if (
        accepted is None
        or accepted.get("substantive_merge_commit")
        != "973a98a8e8b03ba1f8efa681b8c528c064467a2c"
        or accepted.get("audit", {}).get("version") != "2.3.2.2.1"
        or any(accepted.get("audit", {}).get("finding_counts", {}).values())
    ):
        raise SystemExit("accepted Phase 5E-2A.2.1 closeout identity drifted")
    print("Phase 5E-2A.2 rc.2 current-share contract baseline passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
