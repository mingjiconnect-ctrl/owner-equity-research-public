#!/usr/bin/env python3
"""Protected behavior floor for Phase 5E-2B.1-2C.

The candidate may change only the current-share compiler and add its dedicated tests.  This
controller-owned oracle therefore replays the already-frozen V2 evidence contracts and also
requires the compiler to replace the legacy evidence closure with the V2 integration surface.
Candidate tests remain regression evidence; they are not this oracle's source of truth.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import os
import subprocess
import sys
from pathlib import Path

CONTROL_ROOT = Path(__file__).resolve().parents[1]
COMPILER = Path("src/owner_research/valuation_current_share_compiler.py")
FROZEN_CONTRACT_ORACLE = Path("scripts/verify_phase5e2b12a_semantic_oracle.py")

_REQUIRED_V2_IMPORTS = frozenset(
    {
        "CorporateActionCoverageLedgerV2",
        "CurrentShareBundleEvidenceClosure",
        "CurrentShareEvidenceClosureV2",
        "GroupBoundClaimTransitionReconciliation",
    }
)
_DERIVATION_FUNCTION = "derive_current_share_evidence_closure_v2"
_DERIVATION_PARAMETERS = (
    "graph",
    "grouping_result",
    "opening_share_fact",
    "security_compilation_result",
    "claim_control_authority",
    "quote_date",
    "data_cutoff_date",
)
_LEGACY_NAMES = frozenset(
    {
        "CurrentShareEvidenceClosure",
        "derive_current_share_evidence_closure",
    }
)
_FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "builtins",
        "ctypes",
        "importlib",
        "inspect",
        "multiprocessing",
        "os",
        "signal",
        "socket",
        "subprocess",
        "sys",
    }
)
_FORBIDDEN_CALLS = frozenset(
    {
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "locals",
        "open",
        "setattr",
        "vars",
    }
)


def _imported_names(tree: ast.Module) -> set[str]:
    return {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and isinstance(node.module, str)
        and node.module.endswith("valuation_share_event_integration_types")
        for alias in node.names
    }


def _import_roots(tree: ast.Module) -> set[str]:
    return {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.lstrip(".").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and isinstance(node.module, str)
    }


def verify_surface(repository: Path) -> None:
    compiler = repository / COMPILER
    if compiler.is_symlink() or not compiler.is_file():
        raise SystemExit("current-share compiler is not a regular file")
    tree = ast.parse(compiler.read_text(encoding="utf-8"), type_comments=True)
    imported = _imported_names(tree)
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    if not _REQUIRED_V2_IMPORTS.issubset(imported):
        raise SystemExit("current-share compiler omits the protected V2 closure surface")
    if imported & _LEGACY_NAMES or calls & _LEGACY_NAMES:
        raise SystemExit("current-share compiler still consumes the legacy closure surface")
    if _import_roots(tree) & _FORBIDDEN_IMPORT_ROOTS:
        raise SystemExit("current-share compiler imports a forbidden observation surface")
    if calls & _FORBIDDEN_CALLS:
        raise SystemExit("current-share compiler invokes a forbidden dynamic surface")
    derivations = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == _DERIVATION_FUNCTION
    ]
    if len(derivations) != 1 or isinstance(derivations[0], ast.AsyncFunctionDef):
        raise SystemExit("protected V2 derivation entry point is missing or duplicated")
    arguments = derivations[0].args
    if (
        arguments.posonlyargs
        or arguments.args
        or arguments.vararg is not None
        or arguments.kwarg is not None
        or tuple(item.arg for item in arguments.kwonlyargs) != _DERIVATION_PARAMETERS
        or any(default is not None for default in arguments.kw_defaults)
    ):
        raise SystemExit("protected V2 derivation signature is open or caller-selectable")
    compile_functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "compile_quote_date_current_common_shares"
    ]
    if len(compile_functions) != 1:
        raise SystemExit("current-share compiler entry point is missing or duplicated")
    if not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == _DERIVATION_FUNCTION
        for node in ast.walk(compile_functions[0])
    ):
        raise SystemExit("compiler entry point does not execute the V2 closure derivation")


def execute_compiler_vectors(repository: Path) -> None:
    """Replay protected rich-graph vectors through the candidate compiler's V2 derivation."""

    tests_path = CONTROL_ROOT / "tests"
    candidate_src = repository / "src"
    prior_path = list(sys.path)
    sys.path.append(str(tests_path))
    sys.path.append(str(candidate_src))
    try:
        conftest = importlib.import_module("conftest")
        support = importlib.import_module("test_phase5e2b12a_integration_contracts")
        compiler = importlib.import_module(
            "owner_research.valuation_current_share_compiler"
        )
        integration_types = importlib.import_module(
            "owner_research.valuation_share_event_integration_types"
        )
    finally:
        sys.path[:] = prior_path

    derivation = getattr(compiler, _DERIVATION_FUNCTION, None)
    if not callable(derivation):
        raise SystemExit("protected V2 derivation is not executable")
    signature = inspect.signature(derivation)
    if tuple(signature.parameters) != _DERIVATION_PARAMETERS or any(
        parameter.kind is not inspect.Parameter.KEYWORD_ONLY
        or parameter.default is not inspect.Parameter.empty
        for parameter in signature.parameters.values()
    ):
        raise SystemExit("runtime V2 derivation signature differs from protected policy")

    sample_payloads = conftest.sample_payloads.__wrapped__()
    vectors = (
        support._accepted_context(
            sample_payloads=sample_payloads,
            corroborating_count=1,
        ),
        support._accepted_context(
            sample_payloads=sample_payloads,
            corroborating_count=2,
        ),
        support._accepted_empty_context(sample_payloads=sample_payloads),
    )
    results = []
    for expected, graph in vectors:
        actual = derivation(
            graph=graph,
            grouping_result=expected.grouping_result,
            opening_share_fact=expected.opening_share_fact,
            security_compilation_result=(
                expected.bundle_evidence_closure.security_compilation_result
            ),
            claim_control_authority=(
                expected.claim_transition_reconciliation.claim_control_authority
            ),
            quote_date=expected.quote_date,
            data_cutoff_date=expected.data_cutoff_date,
        )
        if type(actual) is not integration_types.CurrentShareEvidenceClosureV2:
            raise SystemExit("V2 derivation returned the wrong closed contract type")
        if actual.to_dict() != expected.to_dict():
            raise SystemExit("V2 derivation differs from protected exact closure replay")
        results.append(actual)
    if (
        results[0].output_share_fact.value != results[1].output_share_fact.value
        or results[0].closure_sha256 == results[1].closure_sha256
        or results[2].numeric_consumptions
        or results[2].output_share_fact.value
        != results[2].opening_share_fact.value
    ):
        raise SystemExit("V2 derivation violates corroboration or zero-event metamorphism")


def replay_frozen_contract_oracle(repository: Path) -> None:
    oracle = CONTROL_ROOT / FROZEN_CONTRACT_ORACLE
    if oracle.is_symlink() or not oracle.is_file():
        raise SystemExit("frozen V2 contract oracle is unavailable")
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PHASE5E_CANDIDATE_REPOSITORY": str(repository),
        "PYTHONHASHSEED": "0",
        "PYTHONSAFEPATH": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-I", str(oracle)],
        cwd="/",
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit("frozen V2 contract behavior replay failed:\n" + completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    verify_surface(repository)
    replay_frozen_contract_oracle(repository)
    execute_compiler_vectors(repository)
    print("phase5e2b12c protected compiler/closure semantic oracle: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
