#!/usr/bin/env python3
"""Protected independent behavior oracle for Phase 5E-2B.1-2B.

The protected parent process never imports candidate Python.  Each behavior case runs in a fresh
worker process which imports the candidate production package but constructs its graph from the
frozen 2A control fixtures.  The worker returns one closed canonical observation; the parent owns
all expected arithmetic and metamorphic comparisons.

Phase boundary: 2B may materialize canonical share-event Facts and consume each canonical group
once.  Coverage, Claim-transition reconciliation and ``CurrentShareEvidenceClosureV2`` remain 2C.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

CONTROL_ROOT = Path(__file__).resolve().parents[1]
COMPILER_PATH = Path("src/owner_research/valuation_current_share_compiler.py")
REQUIRED_TEST_PATH = Path("tests/test_phase5e2b12b_canonical_event_consumption.py")

def _protected_added_test_nodeids() -> tuple[str, ...]:
    """Load the protected profile by absolute path under ``python -I``."""

    profile_path = Path(__file__).with_name("phase5e_audit_profiles.py")
    if profile_path.is_symlink() or not profile_path.is_file():
        raise RuntimeError("protected audit-profile registry is not a regular local file")
    module_name = "_phase5e2b12b_semantic_oracle_profiles"
    spec = importlib.util.spec_from_file_location(module_name, profile_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected audit-profile registry cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        nodeids = tuple(module.PHASE5E2B12B_ADDED_TEST_NODEIDS)
    finally:
        if prior is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior
    return nodeids


PHASE5E2B12B_ADDED_TEST_NODEIDS = _protected_added_test_nodeids()

REQUIRED_TEST_NAMES = frozenset(item.rsplit("::", 1)[1] for item in PHASE5E2B12B_ADDED_TEST_NODEIDS)
WORKER_CASES = (
    "two-corroborating-sources",
    "three-corroborating-sources",
    "reversed-input-order",
    "two-distinct-groups",
)
FORBIDDEN_2C_TYPES = frozenset(
    {
        "CorporateActionCoverageLedgerV2",
        "CurrentShareEvidenceClosureV2",
        "GroupBoundClaimTransitionReconciliation",
    }
)
REQUIRED_2B_TYPES = frozenset(
    {
        "CanonicalShareEventFactMaterialization",
        "ShareEventNumericConsumption",
    }
)


def _canonical_bytes(value: object) -> bytes:
    payload = json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":"))
    return (payload + "\n").encode()


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SystemExit(f"{label} contains duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite token {token}")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is not strict canonical JSON") from exc
    if not isinstance(value, dict) or raw != _canonical_bytes(value):
        raise SystemExit(f"{label} is not strict canonical JSON")
    return value


def independent_rollforward(
    opening: str,
    canonical_events: tuple[tuple[str, str], ...],
) -> str:
    """Independent exactly-once arithmetic used by the protected parent."""

    seen: set[str] = set()
    value = Decimal(opening)
    for group_id, signed_magnitude in canonical_events:
        if group_id in seen:
            raise ValueError("canonical group consumed more than once")
        seen.add(group_id)
        value += Decimal(signed_magnitude)
    return format(value, "f")


def _top_level_names(tree: ast.Module) -> set[str]:
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def _imported_names(tree: ast.Module, module_suffix: str) -> set[str]:
    return {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and isinstance(node.module, str)
        and node.module.endswith(module_suffix)
        for alias in node.names
    }


def verify_candidate_surface(repository: Path) -> None:
    compiler = repository / COMPILER_PATH
    tests = repository / REQUIRED_TEST_PATH
    if not compiler.is_file() or not tests.is_file():
        raise SystemExit("2B compiler or its exact dedicated test file is missing")
    compiler_raw = compiler.read_bytes()
    test_raw = tests.read_bytes()
    compiler_tree = ast.parse(compiler_raw.decode("utf-8"), type_comments=True)
    test_tree = ast.parse(test_raw.decode("utf-8"), type_comments=True)
    imported = _imported_names(compiler_tree, "valuation_share_event_integration_types")
    if not REQUIRED_2B_TYPES.issubset(imported):
        raise SystemExit("2B compiler omits frozen materialization or numeric-consumption types")
    if imported & FORBIDDEN_2C_TYPES:
        raise SystemExit("2B compiler crossed into coverage, Claim-transition or V2 closure work")
    names = _top_level_names(compiler_tree)
    if "CanonicalRollforwardResult" not in names:
        raise SystemExit("2B compiler lacks its frozen observable canonical-rollforward result")
    test_names = _top_level_names(test_tree)
    if not REQUIRED_TEST_NAMES.issubset(test_names):
        raise SystemExit("2B dedicated tests omit a protected-profile semantic case")
    source = compiler_raw.decode("utf-8")
    forbidden_import_roots = {
        "builtins",
        "ctypes",
        "importlib",
        "inspect",
        "multiprocessing",
        "os",
        "posix",
        "signal",
        "socket",
        "subprocess",
        "sys",
        "types",
    }
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(compiler_tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(compiler_tree)
        if isinstance(node, ast.ImportFrom) and isinstance(node.module, str)
    }
    forbidden_tokens = {
        "__main__",
        "_canonical_bytes",
        "sys.modules",
        "sys._getframe",
        "__code__",
        "__import__",
    }
    forbidden_call_names = {
        "breakpoint",
        "compile",
        "delattr",
        "eval",
        "exec",
        "exit",
        "getattr",
        "globals",
        "input",
        "locals",
        "open",
        "print",
        "quit",
        "setattr",
        "vars",
    }
    invalid_dunder = any(
        (
            isinstance(node, ast.Attribute)
            and "__" in node.attr
            and not (
                node.attr == "__setattr__"
                and isinstance(node.value, ast.Name)
                and node.value.id == "object"
            )
        )
        or (
            isinstance(node, ast.Name)
            and "__" in node.id
            and node.id != "__all__"
        )
        or (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and "__" in node.name
            and node.name != "__post_init__"
        )
        or (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "__" in node.value
        )
        or (
            isinstance(node, ast.ImportFrom)
            and isinstance(node.module, str)
            and "__" in node.module
            and node.module != "__future__"
        )
        for node in ast.walk(compiler_tree)
    )
    forbidden_call = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in forbidden_call_names
        for node in ast.walk(compiler_tree)
    )
    if (
        "source_document_id, source_locator" in source
        or "source_locator, source_document_id" in source
        or imported_roots & forbidden_import_roots
        or any(token in source for token in forbidden_tokens)
        or invalid_dunder
        or forbidden_call
    ):
        raise SystemExit("2B compiler exposes a duplicate-key or audit-process attack surface")
    compile_node = next(
        (
            node
            for node in compiler_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "compile_quote_date_current_common_shares"
        ),
        None,
    )
    if compile_node is None or not any(
        isinstance(node, ast.Name) and node.id == "CanonicalRollforwardResult"
        for node in ast.walk(compile_node)
    ):
        raise SystemExit("the authoritative current-share entrypoint does not construct 2B output")
    if hashlib.sha256(test_raw).digest() == hashlib.sha256(compiler_raw).digest():
        raise SystemExit("2B candidate test and compiler bytes unexpectedly match")


@dataclass(frozen=True)
class _ClosureProbe:
    output_share_fact_id: str
    object_fingerprints: tuple[tuple[str, str, str], ...] = ()


class _Artifact:
    fingerprint = "f" * 64

    def to_dict(self) -> dict[str, str]:
        return {
            "issuer_id": "issuer:acme",
            "data_cutoff_date": "2026-06-30",
            "protected_mckinsey_sha256": "a" * 64,
            "protected_penman_assumptions_sha256": "b" * 64,
        }


def _worker_observation(repository: Path, case_id: str) -> dict[str, Any]:
    # Candidate import is deliberately confined to this disposable subprocess.
    prior_path = list(sys.path)
    sys.path.append(str(CONTROL_ROOT / "tests"))
    sys.path.append(str(repository / "src"))
    try:
        import test_phase5e2b12a_integration_contracts as fixture

        import owner_research.valuation_current_share_compiler as compiler
        from owner_research.validation import ContractGraph
    finally:
        sys.path[:] = prior_path

    if case_id == "two-corroborating-sources":
        group_specs = ((2, "common_shares_repurchased_completed", "repurchase-a"),)
        reverse_inputs = False
    elif case_id == "three-corroborating-sources":
        group_specs = ((3, "common_shares_repurchased_completed", "repurchase-a"),)
        reverse_inputs = False
    elif case_id == "reversed-input-order":
        group_specs = ((3, "common_shares_repurchased_completed", "repurchase-a"),)
        reverse_inputs = True
    elif case_id == "two-distinct-groups":
        group_specs = (
            (2, "common_shares_repurchased_completed", "repurchase-a"),
            (2, "common_shares_issued_completed", "issuance-b"),
        )
        reverse_inputs = False
    else:  # pragma: no cover - protected parent fixes the case registry
        raise SystemExit("unknown worker case")

    groupings = []
    raw_facts = []
    sources = []
    candidates = []
    decisions = []
    events = []
    for count, concept, suffix in group_specs:
        grouping, raw, group_sources, group_candidates, group_decisions, event = fixture._grouping(
            corroborating_count=count,
            concept=concept,
            identity_suffix=suffix,
        )
        groupings.append(grouping)
        raw_facts.extend(raw)
        sources.extend(group_sources)
        candidates.extend(group_candidates)
        decisions.extend(group_decisions)
        events.append(event)

    opening_source, _ = fixture._coverage_documents()
    opening = fixture._fact(
        fact_id="fact:oracle:opening",
        concept="common_shares_outstanding",
        value=100_000_000,
        source=opening_source,
        end=fixture.OPENING_DATE,
    )
    security_facts, claim, analytical_candidate, analytical_review, security = (
        fixture._security_evidence(opening_source)
    )
    values: dict[str, tuple[Any, ...]] = {
        "documents": (*sources, opening_source),
        "facts": (*raw_facts, opening, *security_facts),
        "capital_allocation_event_candidates": tuple(candidates),
        "capital_allocation_event_review_decisions": tuple(decisions),
        "capital_allocation_events": tuple(events),
    }
    if reverse_inputs:
        values = {key: tuple(reversed(value)) for key, value in values.items()}
    graph = ContractGraph(
        documents=values["documents"],
        facts=values["facts"],
        claims=(claim,),
        analytical_claim_candidates=(analytical_candidate,),
        analytical_claim_review_decisions=(analytical_review,),
        capital_allocation_event_candidates=values["capital_allocation_event_candidates"],
        capital_allocation_event_review_decisions=values[
            "capital_allocation_event_review_decisions"
        ],
        capital_allocation_events=values["capital_allocation_events"],
        component_lock_path=CONTROL_ROOT / "component-lock.json",
    )
    graph.validate()

    artifact = _Artifact()
    freeze = SimpleNamespace(
        artifact=artifact,
        handoffs=(SimpleNamespace(handoff_id="handoff:oracle"),),
    )
    request = SimpleNamespace(
        authorization_handoff_id="handoff:oracle",
        security_id=fixture.SECURITY,
    )
    receipt = SimpleNamespace(
        security_compilation_fingerprint=security.fingerprint,
        receipt=SimpleNamespace(trading_date=fixture.QUOTE_DATE),
    )
    access = SimpleNamespace(
        status="eligible",
        request=request,
        receipt=receipt,
        issuer_id=fixture.ISSUER,
        data_cutoff_date=fixture.CUTOFF,
        authorization_handoff_id="handoff:oracle",
        price_blind_input_fingerprint=artifact.fingerprint,
        protected_mckinsey_sha256="a" * 64,
        protected_penman_assumptions_sha256="b" * 64,
    )

    class _Authority:
        standard_path_disposition = "eligible"

        @classmethod
        def from_price_blind_artifact(cls, _artifact: object) -> _Authority:
            return cls()

    originals = (
        compiler.load_price_blind_input_artifact,
        compiler.compile_security_identity,
        compiler.Phase5CDilutionClaimAuthority,
        compiler.derive_current_share_evidence_closure,
    )
    compiler.load_price_blind_input_artifact = lambda *args, **kwargs: freeze
    compiler.compile_security_identity = lambda *args, **kwargs: security
    compiler.Phase5CDilutionClaimAuthority = _Authority
    compiler.derive_current_share_evidence_closure = lambda **kwargs: _ClosureProbe(
        kwargs["share_fact"].fact_id
    )
    try:
        result = compiler.compile_quote_date_current_common_shares(
            price_blind_artifact_directory=Path("/unused"),
            graph=graph,
            expected_freeze=freeze,
            expected_security=security,
            expected_market_access=access,
        )
    finally:
        (
            compiler.load_price_blind_input_artifact,
            compiler.compile_security_identity,
            compiler.Phase5CDilutionClaimAuthority,
            compiler.derive_current_share_evidence_closure,
        ) = originals

    rollforward = getattr(result, "canonical_rollforward", None)
    output = result.output_fact
    if result.status != "eligible" or output is None or rollforward is None:
        return {
            "case_id": case_id,
            "status": result.status,
            "issue_codes": list(result.issue_codes),
        }
    materializations = tuple(rollforward.materializations)
    consumptions = tuple(rollforward.numeric_consumptions)
    return {
        "case_id": case_id,
        "status": result.status,
        "output_value": str(output.value),
        "output_derivation": output.derivation,
        "output_parent_fact_ids": list(output.parent_fact_ids),
        "rollforward_fingerprint": rollforward.rollforward_fingerprint,
        "opening_fact_id": rollforward.opening_share_fact_id,
        "output_fact_id": rollforward.output_share_fact_id,
        "materializations": [
            {
                "group_id": item.group_id,
                "canonical_fact_id": item.canonical_event_fact.fact_id,
                "canonical_parent_fact_ids": list(item.canonical_event_fact.parent_fact_ids),
                "member_fact_ids": [member.fact_id for member in item.members],
                "materialization_fingerprint": item.materialization_fingerprint,
            }
            for item in materializations
        ],
        "numeric_consumptions": [
            {
                "group_id": item.group_id,
                "canonical_fact_id": item.canonical_event_fact_id,
                "sign": item.sign,
                "magnitude": item.canonical_share_magnitude,
            }
            for item in consumptions
        ],
    }


def _run_worker(repository: Path, case_id: str) -> dict[str, Any]:
    environment = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    completed = subprocess.run(
        (
            sys.executable,
            "-I",
            str(Path(__file__).resolve()),
            "--worker",
            "--repository",
            str(repository),
            "--case",
            case_id,
        ),
        cwd=CONTROL_ROOT,
        env=environment,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise SystemExit(f"2B behavior worker failed for {case_id}")
    return _strict_json(completed.stdout, f"2B behavior worker {case_id}")


def _verify_observation(observation: dict[str, Any], *, groups: int, expected_value: str) -> None:
    expected_keys = {
        "case_id",
        "status",
        "output_value",
        "output_derivation",
        "output_parent_fact_ids",
        "rollforward_fingerprint",
        "opening_fact_id",
        "output_fact_id",
        "materializations",
        "numeric_consumptions",
    }
    materials = observation.get("materializations")
    consumptions = observation.get("numeric_consumptions")
    if (
        set(observation) != expected_keys
        or observation.get("status") != "eligible"
        or observation.get("output_value") != expected_value
        or observation.get("output_derivation") != "completed-event-rollforward/2.0.0"
        or not isinstance(materials, list)
        or not isinstance(consumptions, list)
        or len(materials) != groups
        or len(consumptions) != groups
    ):
        raise SystemExit("2B full-entrypoint observation violates exactly-once arithmetic")
    group_ids = [item.get("group_id") for item in materials if isinstance(item, dict)]
    consumption_groups = [
        item.get("group_id") for item in consumptions if isinstance(item, dict)
    ]
    canonical_ids = [
        item.get("canonical_fact_id") for item in materials if isinstance(item, dict)
    ]
    if (
        len(group_ids) != groups
        or len(set(group_ids)) != groups
        or sorted(group_ids) != sorted(consumption_groups)
        or len(canonical_ids) != groups
        or len(set(canonical_ids)) != groups
        or sorted(observation["output_parent_fact_ids"])
        != sorted((observation["opening_fact_id"], *canonical_ids))
    ):
        raise SystemExit("2B full-entrypoint lineage is not canonical-group bound")
    for material in materials:
        if (
            sorted(material["canonical_parent_fact_ids"])
            != sorted(material["member_fact_ids"])
            or len(material["member_fact_ids"]) < 2
        ):
            raise SystemExit("canonical event Fact omits corroborating raw parents")
    for consumption in consumptions:
        if consumption["canonical_fact_id"] not in canonical_ids:
            raise SystemExit("numeric consumption does not reference a materialized canonical Fact")


def verify_candidate(repository: Path) -> None:
    verify_candidate_surface(repository)
    observations = {case: _run_worker(repository, case) for case in WORKER_CASES}
    _verify_observation(
        observations["two-corroborating-sources"], groups=1, expected_value="95000000"
    )
    _verify_observation(
        observations["three-corroborating-sources"], groups=1, expected_value="95000000"
    )
    _verify_observation(
        observations["reversed-input-order"], groups=1, expected_value="95000000"
    )
    _verify_observation(observations["two-distinct-groups"], groups=2, expected_value="100000000")

    two = observations["two-corroborating-sources"]
    three = observations["three-corroborating-sources"]
    reverse = observations["reversed-input-order"]
    if (
        two["output_value"] != three["output_value"]
        or two["rollforward_fingerprint"] == three["rollforward_fingerprint"]
        or three != {**reverse, "case_id": "three-corroborating-sources"}
    ):
        raise SystemExit("2B corroboration or input-order metamorphism failed")
    if independent_rollforward(
        "100000000", (("repurchase", "-5000000"),)
    ) != "95000000":
        raise SystemExit("independent 100m minus 5m arithmetic failed")
    if independent_rollforward(
        "100000000", (("repurchase", "-5000000"), ("issuance", "5000000"))
    ) != "100000000":
        raise SystemExit("independent two-group arithmetic failed")
    try:
        independent_rollforward(
            "100000000", (("same-group", "-5000000"), ("same-group", "-5000000"))
        )
    except ValueError:
        pass
    else:
        raise SystemExit("independent duplicate-group oracle did not fail closed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--protected-load-only", action="store_true")
    parser.add_argument("--case", choices=WORKER_CASES)
    args = parser.parse_args()
    repository = args.repository.resolve()
    if args.protected_load_only:
        if args.worker or args.case is not None:
            raise SystemExit("protected-load self-check does not accept worker arguments")
        print("Phase 5E-2B.1-2B protected profile load passed")
        return 0
    if args.worker:
        if args.case is None:
            raise SystemExit("worker requires one closed case")
        # Keep a private local reference across the candidate import.  Combined with the static
        # import/token boundary above, this prevents candidate code from replacing the protected
        # module-global serializer through ``sys.modules['__main__']``.
        protected_serializer = _canonical_bytes
        observation = _worker_observation(repository, args.case)
        if _canonical_bytes is not protected_serializer:
            raise SystemExit("candidate mutated the protected worker serializer")
        sys.stdout.buffer.write(protected_serializer(observation))
        return 0
    if args.case is not None:
        raise SystemExit("parent mode does not accept a worker case")
    verify_candidate(repository)
    print("Phase 5E-2B.1-2B independent full-entrypoint semantic oracle passed")
    return 0


def _fail_closed_main() -> int:
    """Never let candidate import-time ``BaseException`` become worker success."""

    try:
        return main()
    except BaseException:
        return 1


if __name__ == "__main__":
    raise SystemExit(_fail_closed_main())
