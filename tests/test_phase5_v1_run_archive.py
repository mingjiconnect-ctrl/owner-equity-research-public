from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import test_phase5_v1_valuation_synthesis as synthesis_fixtures
from test_phase5_v1_run_orchestration import (
    _authority,
    _candidate_compilation,
    _run_clock,
    _typed_runtime_authority,
)

import owner_research.valuation_run as run_module
import owner_research.valuation_run_archive as archive_module
from owner_research.fingerprints import canonical_json, canonical_sha256
from owner_research.valuation_run import RuntimeManifestInputAuthority
from owner_research.valuation_run_archive import (
    VALUATION_RUN_ARCHIVE_FILENAMES,
    ValuationRunArchiveError,
    load_valuation_run_archive,
)
from owner_research.valuation_run_archive import (
    write_valuation_run_archive as _write_valuation_run_archive,
)

_ARCHIVE_RUN_RESULT_CACHE: Any | None = None
_ARCHIVE_CACHE_DIRECTORY: tempfile.TemporaryDirectory[str] | None = None
_ARCHIVE_CACHE_STATE_BASE: Path | None = None


def write_valuation_run_archive(execution: Any, *, output_directory: Path) -> Any:
    return _write_valuation_run_archive(
        execution,
        output_directory=output_directory,
        runtime_manifest_authority=_typed_runtime_authority(),
    )


def _completed(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    _tmp_path: Path,
) -> Any:
    global _ARCHIVE_CACHE_DIRECTORY, _ARCHIVE_CACHE_STATE_BASE, _ARCHIVE_RUN_RESULT_CACHE
    if _ARCHIVE_RUN_RESULT_CACHE is None:
        _ARCHIVE_CACHE_DIRECTORY = tempfile.TemporaryDirectory(
            prefix="owner-research-archive-tests-"
        )
        cache_root = Path(_ARCHIVE_CACHE_DIRECTORY.name).resolve()
        builder_patch = pytest.MonkeyPatch()
        try:
            run_result, *_ = synthesis_fixtures._completed_run(
                sample_payloads,
                builder_patch,
                cache_root,
            )
        finally:
            builder_patch.undo()
        assert run_result.execution is not None
        _ARCHIVE_RUN_RESULT_CACHE = run_result
        _ARCHIVE_CACHE_STATE_BASE = cache_root / "owner-research-state"
    assert _ARCHIVE_CACHE_STATE_BASE is not None
    monkeypatch.setattr(
        synthesis_fixtures,
        "_SYNTHESIS_CACHE_STATE_BASE",
        _ARCHIVE_CACHE_STATE_BASE,
    )
    synthesis_fixtures._activate_cached_run_replay(
        monkeypatch,
        _ARCHIVE_RUN_RESULT_CACHE,
    )
    return _ARCHIVE_RUN_RESULT_CACHE.execution


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _rebind_schema_invalid_archive(
    output: Path,
    filename: str,
    *,
    invalid_datetime: bool = False,
) -> None:
    handoff = json.loads((output / "valuation-handoff.json").read_bytes())
    request = json.loads((output / "valuation-request.json").read_bytes())
    result = json.loads((output / "valuation-result.json").read_bytes())
    manifest = json.loads((output / "valuation-run-manifest.json").read_bytes())

    if invalid_datetime:
        request["fact_ledger"]["sources"][0]["retrieved_at"] = (
            "definitely-not-a-date-time"
        )
    else:
        payload = request if filename == "valuation-request.json" else result
        payload["schema_probe_extra_property"] = True
    request_bytes = canonical_json(request).encode("utf-8")
    request_sha256 = _sha256(request_bytes)
    result["model_input_fingerprint"] = request_sha256
    result_bytes = canonical_json(result).encode("utf-8")
    result_sha256 = _sha256(result_bytes)

    handoff["valuation_request_sha256"] = request_sha256
    handoff["valuation_result_sha256"] = result_sha256
    handoff_bytes = (canonical_json(handoff) + "\n").encode("utf-8")

    final_projection = manifest["final_request_projection"]
    final_projection["valuation_request_sha256"] = request_sha256
    kernel_projection = manifest["kernel_execution_projection"]
    kernel_projection.update(
        {
            "request_sha256": request_sha256,
            "result_sha256": result_sha256,
            "model_input_fingerprint": request_sha256,
        }
    )

    manifest["valuation_handoff_fingerprint"] = canonical_sha256(handoff)
    manifest["valuation_request_sha256"] = request_sha256
    manifest["valuation_result_sha256"] = result_sha256
    manifest["valuation_result_fingerprint"] = canonical_sha256(result)
    manifest["file_sha256"].update(
        {
            "valuation-handoff.json": _sha256(handoff_bytes),
            "valuation-request.json": request_sha256,
            "valuation-result.json": result_sha256,
        }
    )
    archive_identity = {
        "issuer_id": manifest["issuer_id"],
        "data_cutoff_date": manifest["data_cutoff_date"],
        "valuation_handoff_id": manifest["valuation_handoff_id"],
        "valuation_request_sha256": request_sha256,
        "valuation_result_sha256": result_sha256,
    }
    manifest["archive_id"] = (
        f"valuation-run-archive:{manifest['issuer_id']}:"
        f"{canonical_sha256(archive_identity)[:24]}"
    )
    manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    manifest_bytes = (canonical_json(manifest) + "\n").encode("utf-8")

    output.chmod(0o755)
    for name, content in (
        ("valuation-handoff.json", handoff_bytes),
        ("valuation-request.json", request_bytes),
        ("valuation-result.json", result_bytes),
        ("valuation-run-manifest.json", manifest_bytes),
    ):
        path = output / name
        path.chmod(0o644)
        path.write_bytes(content)
        path.chmod(0o444)
    output.chmod(0o555)


def _receipt_company_binding(receipt: dict[str, Any]) -> str:
    return canonical_sha256(
        {
            "issuer_id": receipt["issuer_id"],
            "legal_name": receipt["company_legal_name_value"],
            "fact": [
                receipt["company_name_fact_id"],
                receipt["company_name_fact_fingerprint"],
            ],
            "source_document": [
                receipt["company_name_source_document_id"],
                receipt["company_name_source_document_fingerprint"],
            ],
        }
    )


def _rewrite_manifest_receipt(
    output: Path,
    *,
    receipt_name: str,
    mutate: Any,
) -> None:
    manifest_path = output / "valuation-run-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    receipt = manifest[receipt_name]
    mutate(receipt)
    manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    output.chmod(0o755)
    manifest_path.chmod(0o644)
    manifest_path.write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    manifest_path.chmod(0o444)
    output.chmod(0o555)


def _rewrite_coordinated_request_result(
    output: Path,
    *,
    mutate_request: Any | None = None,
    mutate_result: Any | None = None,
) -> None:
    handoff = json.loads((output / "valuation-handoff.json").read_bytes())
    request = json.loads((output / "valuation-request.json").read_bytes())
    result = json.loads((output / "valuation-result.json").read_bytes())
    manifest = json.loads((output / "valuation-run-manifest.json").read_bytes())
    if mutate_request is not None:
        mutate_request(request)
    fact_sha = canonical_sha256(request["fact_ledger"])
    request["assumption_ledger"]["fact_ledger_fingerprint"] = fact_sha
    assumption_sha = canonical_sha256(request["assumption_ledger"])
    request_bytes = canonical_json(request).encode("utf-8")
    request_sha = _sha256(request_bytes)
    result.update(
        {
            "fact_ledger_fingerprint": fact_sha,
            "assumption_ledger_fingerprint": assumption_sha,
            "model_input_fingerprint": request_sha,
        }
    )
    if mutate_result is not None:
        mutate_result(result)
    result_bytes = canonical_json(result).encode("utf-8")
    result_sha = _sha256(result_bytes)

    handoff["valuation_request_sha256"] = request_sha
    handoff["valuation_result_sha256"] = result_sha
    handoff_bytes = (canonical_json(handoff) + "\n").encode("utf-8")

    final_receipt = manifest["final_request_projection"]
    entries_sha = canonical_sha256(request["assumption_ledger"]["assumptions"])
    final_receipt.update(
        {
            "company_legal_name_value": request["company"]["name"],
            "valuation_request_sha256": request_sha,
            "final_fact_ledger_sha256": fact_sha,
            "assumption_entries_before_sha256": entries_sha,
            "assumption_entries_after_sha256": entries_sha,
        }
    )
    kernel_projection = manifest["kernel_execution_projection"]
    kernel_projection.update(
        {
            "request_sha256": request_sha,
            "result_sha256": result_sha,
            "fact_ledger_fingerprint": fact_sha,
            "assumption_ledger_fingerprint": assumption_sha,
            "model_input_fingerprint": request_sha,
        }
    )

    manifest["valuation_handoff_fingerprint"] = canonical_sha256(handoff)
    manifest["valuation_request_sha256"] = request_sha
    manifest["valuation_result_sha256"] = result_sha
    manifest["valuation_result_fingerprint"] = canonical_sha256(result)
    manifest["file_sha256"].update(
        {
            "valuation-handoff.json": _sha256(handoff_bytes),
            "valuation-request.json": request_sha,
            "valuation-result.json": result_sha,
        }
    )
    identity = {
        "issuer_id": manifest["issuer_id"],
        "data_cutoff_date": manifest["data_cutoff_date"],
        "valuation_handoff_id": manifest["valuation_handoff_id"],
        "valuation_request_sha256": request_sha,
        "valuation_result_sha256": result_sha,
    }
    manifest["archive_id"] = (
        f"valuation-run-archive:{manifest['issuer_id']}:"
        f"{canonical_sha256(identity)[:24]}"
    )
    manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)

    output.chmod(0o755)
    for name, content in (
        ("valuation-handoff.json", handoff_bytes),
        ("valuation-request.json", request_bytes),
        ("valuation-result.json", result_bytes),
        (
            "valuation-run-manifest.json",
            (canonical_json(manifest) + "\n").encode("utf-8"),
        ),
    ):
        path = output / name
        path.chmod(0o644)
        path.write_bytes(content)
        path.chmod(0o444)
    output.chmod(0o555)


def test_completed_execution_writes_and_reloads_exact_six_file_archive(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"

    written = write_valuation_run_archive(execution, output_directory=output)
    loaded = load_valuation_run_archive(output, expected_execution=execution)

    assert written == loaded
    assert tuple(sorted(item.name for item in output.iterdir())) == tuple(
        sorted(VALUATION_RUN_ARCHIVE_FILENAMES)
    )
    assert (output / "valuation-request.json").read_bytes() == (
        execution.final_request_result.canonical_request_json.encode("utf-8")
    )
    assert (output / "valuation-result.json").read_bytes() == execution.result_bytes
    assert loaded.handoff == execution.execution_handoffs[-1]
    assert loaded.market_reference == execution.preparation.prepared_market_reference.snapshot
    assert loaded.price_blind_input == execution.expected_freeze.artifact
    assert loaded.fingerprint == loaded.manifest["manifest_fingerprint"]
    assert stat.S_IMODE(output.stat().st_mode) == 0o555
    for name in VALUATION_RUN_ARCHIVE_FILENAMES:
        assert stat.S_IMODE((output / name).stat().st_mode) == 0o444
        assert loaded.file_sha256[name] == hashlib.sha256((output / name).read_bytes()).hexdigest()


def test_archive_projections_omit_nonreplayable_execution_observations(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    manifest = json.loads((output / "valuation-run-manifest.json").read_bytes())

    assert {
        "market_validation_context_fingerprint",
        "market_access_result_fingerprint",
        "current_share_compilation_fingerprint",
        "market_equity_calculation_fingerprint",
        "market_raw_response_sha256",
        "current_share_projection_sha256",
    }.isdisjoint(manifest["final_request_projection"])
    assert {
        "execution_boundary",
        "docker_executable_sha256",
        "container_identity_sha256",
        "docker_image_inspect_sha256",
        "container_security_profile_sha256",
        "trusted_workflow_attestation_sha256",
        "runtime_manifest_file_sha256",
        "runtime_manifest_fingerprint",
        "wheel_inventory_sha256",
    }.isdisjoint(manifest["kernel_execution_projection"])
    assert "kernel_runtime_manifest" not in manifest
    assert set(manifest["kernel_runtime_authority"]) == {
        "schema_version",
        "manifest_policy_id",
        "manifest_policy_version",
        "runtime_authority_sha256",
        "kernel",
        "result_schema_sha256",
        "transport",
    }


@pytest.mark.parametrize(
    ("manifest_field", "manifest_value", "projection_field"),
    (
        ("request", "coordinated_host_file", "request_transport"),
        ("result", "coordinated_host_file", "result_transport"),
        ("network_mode", "host", "network_mode"),
        ("result_bytes_preserved", False, "result_preserved"),
    ),
)
def test_reloader_rejects_coordinated_runtime_transport_rebinding(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    manifest_field: str,
    manifest_value: Any,
    projection_field: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    path = output / "valuation-run-manifest.json"
    manifest = json.loads(path.read_bytes())
    runtime = manifest["kernel_runtime_authority"]
    runtime["transport"][manifest_field] = manifest_value
    projection = manifest["kernel_execution_projection"]
    projection[projection_field] = manifest_value
    manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    output.chmod(0o755)
    path.chmod(0o644)
    path.write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)


@pytest.mark.parametrize(
    ("scope", "field"),
    (
        ("authority", "producer"),
        ("authority", "target"),
        ("authority", "container"),
        ("authority", "trusted_workflow"),
        ("authority", "result_schema"),
        ("authority", "wheels"),
        ("kernel", "tag_object"),
        ("kernel", "tree"),
        ("kernel", "filename"),
        ("kernel", "uri"),
    ),
)
def test_reloader_rejects_reintroduced_host_runtime_metadata(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scope: str,
    field: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    path = output / "valuation-run-manifest.json"
    manifest = json.loads(path.read_bytes())
    runtime = manifest["kernel_runtime_authority"]
    target = runtime if scope == "authority" else runtime["kernel"]
    target[field] = {"rebound": True} if scope == "authority" else "rebound"
    manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    output.chmod(0o755)
    path.chmod(0o644)
    path.write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)


def test_reloader_rejects_rebound_current_share_compilation_attestation(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    path = output / "valuation-run-manifest.json"
    manifest = json.loads(path.read_bytes())
    projection = manifest["final_request_replay_evidence"][
        "current_share_projection"
    ]
    attestation = projection["research_evidence_attestation"]
    assert "current_share_compilation_fingerprint" not in attestation
    attestation["current_share_compilation_fingerprint"] = "0" * 64
    projection["research_evidence_sha256"] = canonical_sha256(attestation)
    manifest.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest)
    output.chmod(0o755)
    path.chmod(0o644)
    path.write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)


def test_real_execution_cache_does_not_rebind_synthesis_fixture_state(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_state_base = synthesis_fixtures._SYNTHESIS_CACHE_STATE_BASE
    with monkeypatch.context() as scoped_patch:
        assert _completed(sample_payloads, scoped_patch, tmp_path) is not None
        assert synthesis_fixtures._SYNTHESIS_CACHE_STATE_BASE == (
            _ARCHIVE_CACHE_STATE_BASE
        )
    assert synthesis_fixtures._SYNTHESIS_CACHE_STATE_BASE == original_state_base


def test_archive_is_byte_stable_across_directories_and_idempotent(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    write_valuation_run_archive(execution, output_directory=first)
    first_result = write_valuation_run_archive(execution, output_directory=first)
    second_result = write_valuation_run_archive(execution, output_directory=second)

    for name in VALUATION_RUN_ARCHIVE_FILENAMES:
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert first_result.fingerprint == second_result.fingerprint


@pytest.mark.parametrize(
    "filename",
    (
        "valuation-handoff.json",
        "price-blind-input.json",
        "market-reference.json",
        "valuation-request.json",
        "valuation-result.json",
        "valuation-run-manifest.json",
    ),
)
def test_reloader_rejects_any_mutated_archive_member(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    path = output / filename
    output.chmod(0o755)
    path.chmod(0o644)
    payload = json.loads(path.read_bytes())
    if filename == "valuation-result.json":
        payload["model_input_fingerprint"] = "f" * 64
        path.write_bytes(canonical_json(payload).encode("utf-8"))
    elif filename == "valuation-request.json":
        payload["company"]["name"] = "Rebound Company"
        path.write_bytes(canonical_json(payload).encode("utf-8"))
    else:
        payload["schema_version"] = "9.9.9"
        path.write_bytes((canonical_json(payload) + "\n").encode("utf-8"))
    path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)


@pytest.mark.parametrize(
    "filename,label",
    (
        ("valuation-request.json", "valuation request"),
        ("valuation-result.json", "valuation result"),
    ),
)
def test_reloader_applies_pinned_kernel_schemas_after_coordinated_rebinding(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    filename: str,
    label: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    _rebind_schema_invalid_archive(output, filename)

    with pytest.raises(
        ValuationRunArchiveError,
        match=rf"{label} failed the pinned kernel Schema",
    ):
        load_valuation_run_archive(output)

    monkeypatch.setattr(
        archive_module,
        "_validate_pinned_kernel_payloads",
        lambda **_kwargs: None,
    )
    assert load_valuation_run_archive(output).output_directory == output


def test_reloader_enforces_rfc3339_without_optional_jsonschema_formats(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    _rebind_schema_invalid_archive(
        output,
        "valuation-request.json",
        invalid_datetime=True,
    )

    with pytest.raises(
        ValuationRunArchiveError,
        match=r"valuation request failed the pinned kernel Schema.*retrieved_at",
    ):
        load_valuation_run_archive(output)


@pytest.mark.parametrize("token", ("NaN", "Infinity", "-Infinity", "1e999"))
def test_reloader_rejects_nonfinite_json_without_leaking_value_error(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    token: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    result_path = output / "valuation-result.json"
    original = result_path.read_bytes()
    assert original.endswith(b"}")
    output.chmod(0o755)
    result_path.chmod(0o644)
    result_path.write_bytes(original[:-1] + f',"nonfinite_probe":{token}}}'.encode())
    result_path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError, match="not valid UTF-8 JSON"):
        load_valuation_run_archive(output)


def test_archive_canonicalization_wraps_nonfinite_in_memory_values() -> None:
    with pytest.raises(ValuationRunArchiveError, match="not canonical JSON"):
        archive_module._canonical_file({"nonfinite_probe": float("inf")})


def test_reloader_rejects_blocked_request_receipt_in_completed_archive(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    manifest_path = output / "valuation-run-manifest.json"
    output.chmod(0o755)
    manifest_path.chmod(0o644)
    manifest = json.loads(manifest_path.read_bytes())
    receipt = manifest["final_request_projection"]
    receipt["status"] = "blocked"
    receipt["reason_codes"] = ["kernel_component_drift"]
    manifest_payload = dict(manifest)
    manifest_payload.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest_payload)
    manifest_path.write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    manifest_path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError, match="final-request projection"):
        load_valuation_run_archive(output)


@pytest.mark.parametrize(
    "drift",
    (
        "company_lineage",
        "final_fact_ledger",
        "assumption_entries",
        "provider_route",
        "calculation_id",
        "market_source_document",
        "market_quote_fact",
        "runtime_authority",
        "runner",
    ),
)
def test_reloader_rejects_receipt_drift_after_receipt_and_manifest_rebinding(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    drift: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)

    if drift in {"runtime_authority", "runner"}:
        field = {
            "runtime_authority": "runtime_authority_sha256",
            "runner": "runner_sha256",
        }[drift]

        def mutate(receipt: dict[str, Any]) -> None:
            receipt[field] = "0" * 64

        receipt_name = "kernel_execution_projection"
    else:

        def mutate(receipt: dict[str, Any]) -> None:
            if drift == "company_lineage":
                receipt["company_name_fact_id"] = "fact:rebound:issuer-legal-name"
                receipt["company_name_fact_fingerprint"] = "1" * 64
                receipt["company_name_source_document_id"] = (
                    "doc:rebound:issuer-legal-name"
                )
                receipt["company_name_source_document_fingerprint"] = "2" * 64
                receipt["company_identity_binding_sha256"] = (
                    _receipt_company_binding(receipt)
                )
            elif drift == "final_fact_ledger":
                receipt["final_fact_ledger_sha256"] = "0" * 64
            elif drift == "assumption_entries":
                receipt["assumption_entries_before_sha256"] = "0" * 64
                receipt["assumption_entries_after_sha256"] = "0" * 64
            elif drift == "provider_route":
                receipt["market_provider_id"] = "provider:coordinated-rebind"
            elif drift == "calculation_id":
                receipt["market_equity_calculation_id"] = (
                    "calc:issuer:coordinated-market-equity"
                )
            elif drift == "market_source_document":
                receipt["market_source_document_fingerprint"] = "0" * 64
            else:
                receipt["market_quote_fact_fingerprint"] = "0" * 64

        receipt_name = "final_request_projection"

    _rewrite_manifest_receipt(
        output,
        receipt_name=receipt_name,
        mutate=mutate,
    )
    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)


@pytest.mark.parametrize("drift", ("issuer", "valuation_date", "company_lineage"))
def test_reloader_rejects_coordinated_request_identity_drift(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    drift: str,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)

    def mutate(request: dict[str, Any]) -> None:
        if drift == "issuer":
            request["fact_ledger"]["entity_id"] = "issuer:coordinated-rebind"
        elif drift == "valuation_date":
            request["fact_ledger"]["valuation_date"] = "2026-03-30"
        else:
            original = set(request["company"]["source_fact_ids"])
            replacement = next(
                item["fact_id"]
                for item in request["fact_ledger"]["facts"]
                if item["fact_id"] not in original
            )
            request["company"]["source_fact_ids"] = [replacement]

    _rewrite_coordinated_request_result(output, mutate_request=mutate)
    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)


def test_reloader_rejects_result_company_drift_after_full_hash_rebinding(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)

    def mutate(result: dict[str, Any]) -> None:
        result["company"]["name"] = "Coordinated Rebound Corporation"

    _rewrite_coordinated_request_result(output, mutate_result=mutate)
    with pytest.raises(
        ValuationRunArchiveError,
        match="request identity, ledgers, or result company",
    ):
        load_valuation_run_archive(output)


def test_archive_rejects_extra_files_symlinks_and_noncompleted_execution(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    output.chmod(0o755)
    (output / "extra.json").write_text("{}", encoding="utf-8")
    (output / "extra.json").chmod(0o444)
    output.chmod(0o555)
    with pytest.raises(ValuationRunArchiveError, match="exactly the six"):
        load_valuation_run_archive(output)
    output.chmod(0o755)
    (output / "extra.json").unlink()
    request = output / "valuation-request.json"
    request.chmod(0o644)
    request.unlink()
    request.symlink_to(output / "valuation-result.json")
    output.chmod(0o555)
    with pytest.raises(ValuationRunArchiveError):
        load_valuation_run_archive(output)

    with pytest.raises((ValueError, ValuationRunArchiveError)):
        stopped = replace(
            execution,
            status="blocked",
            kernel_execution_result=None,
            kernel_execution_receipt=None,
            execution_handoffs=(),
            validated_graph=None,
            result_bytes=None,
            issue_codes=("blocked",),
        )
        write_valuation_run_archive(stopped, output_directory=tmp_path / "blocked")


def test_archive_publication_failure_leaves_no_partial_target(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"

    monkeypatch.setattr(
        archive_module,
        "_write_all",
        lambda *_args: (_ for _ in ()).throw(OSError("injected short write")),
    )
    with pytest.raises(ValuationRunArchiveError, match="publication failed"):
        write_valuation_run_archive(execution, output_directory=output)

    assert not output.exists()
    assert not list(tmp_path.glob(".valuation-run.staging-*"))


def test_final_strict_reload_failure_rolls_back_and_allows_retry(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_load = archive_module._load_valuation_run_archive_unlocked

    def fail_final_reload(input_directory, **_kwargs):
        if Path(input_directory) == output:
            raise RuntimeError("injected final strict reload failure")
        return original_load(input_directory, **_kwargs)

    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        fail_final_reload,
    )
    with pytest.raises(ValuationRunArchiveError, match="publication failed: RuntimeError"):
        write_valuation_run_archive(execution, output_directory=output)

    assert not output.exists()
    assert not list(tmp_path.glob(".valuation-run.staging-*"))
    assert not list(tmp_path.glob(".valuation-run.rollback-*"))

    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        original_load,
    )
    assert write_valuation_run_archive(
        execution,
        output_directory=output,
    ).output_directory == output


def test_identical_concurrent_writer_waits_for_failed_publisher_rollback(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_load = archive_module._load_valuation_run_archive_unlocked
    original_payloads = archive_module._archive_payloads
    first_final_reload = threading.Event()
    release_first_reload = threading.Event()
    second_payloads_ready = threading.Event()
    second_reload_entered = threading.Event()
    first_done = threading.Event()
    second_done = threading.Event()
    results: dict[str, Any] = {}
    errors: dict[str, BaseException] = {}

    def coordinated_payloads(candidate, **kwargs):
        payloads = original_payloads(candidate, **kwargs)
        if threading.current_thread().name == "archive-writer-2":
            second_payloads_ready.set()
        return payloads

    def coordinated_load(input_directory, **kwargs):
        if Path(input_directory) == output:
            if threading.current_thread().name == "archive-writer-1":
                first_final_reload.set()
                if not release_first_reload.wait(15):
                    raise AssertionError("timed out waiting to release first final reload")
                raise RuntimeError("injected first final reload failure")
            if threading.current_thread().name == "archive-writer-2":
                second_reload_entered.set()
        return original_load(input_directory, **kwargs)

    def run_writer(label: str, done: threading.Event) -> None:
        try:
            results[label] = write_valuation_run_archive(
                execution,
                output_directory=output,
            )
        except BaseException as exc:  # recorded and asserted in the spawning thread
            errors[label] = exc
        finally:
            done.set()

    monkeypatch.setattr(archive_module, "_archive_payloads", coordinated_payloads)
    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        coordinated_load,
    )
    first = threading.Thread(
        target=run_writer,
        args=("first", first_done),
        name="archive-writer-1",
        daemon=True,
    )
    second = threading.Thread(
        target=run_writer,
        args=("second", second_done),
        name="archive-writer-2",
        daemon=True,
    )
    first.start()
    try:
        assert first_final_reload.wait(15), "first writer never reached final reload"
        assert output.is_dir()
        second.start()
        assert second_payloads_ready.wait(15), "second writer never entered write path"
        assert not second_reload_entered.wait(0.25)
        assert not second_done.is_set()
    finally:
        release_first_reload.set()
        first.join(15)
        if second.ident is not None:
            second.join(15)

    assert not first.is_alive()
    assert not second.is_alive()
    assert first_done.is_set()
    assert second_done.is_set()
    assert isinstance(errors.get("first"), ValuationRunArchiveError)
    assert "publication failed: RuntimeError" in str(errors["first"])
    assert "second" not in errors
    assert second_reload_entered.is_set()
    assert results["second"].output_directory == output
    reloaded = load_valuation_run_archive(output, expected_execution=execution)
    assert (
        results["second"].directory_device,
        results["second"].directory_inode,
        results["second"].fingerprint,
    ) == (
        reloaded.directory_device,
        reloaded.directory_inode,
        reloaded.fingerprint,
    )
    assert not list(tmp_path.glob(".valuation-run.staging-*"))
    assert not list(tmp_path.glob(".valuation-run.rollback-*"))


def test_final_reload_detected_member_injection_removes_target_and_does_not_wedge_retry(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_load = archive_module._load_valuation_run_archive_unlocked
    injected = False

    def inject_before_final_reload(input_directory, **kwargs):
        nonlocal injected
        path = Path(input_directory)
        if path == output and not injected:
            injected = True
            path.chmod(0o755)
            extra = path / "extra.json"
            extra.write_text("{}\n", encoding="utf-8")
            extra.chmod(0o444)
            path.chmod(0o555)
        return original_load(input_directory, **kwargs)

    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        inject_before_final_reload,
    )
    with pytest.raises(ValuationRunArchiveError):
        write_valuation_run_archive(execution, output_directory=output)

    assert injected
    assert not output.exists()
    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        original_load,
    )
    assert write_valuation_run_archive(
        execution,
        output_directory=output,
    ).output_directory == output


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin rollback quarantine regression")
def test_darwin_unknown_final_member_leaves_only_sealed_quarantine_and_allows_retry(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_load = archive_module._load_valuation_run_archive_unlocked
    injected = False

    def inject_unknown_member(input_directory, **kwargs):
        nonlocal injected
        path = Path(input_directory)
        if path == output and not injected:
            injected = True
            path.chmod(0o755)
            unknown = path / "attacker-unknown.json"
            unknown.write_text("{}\n", encoding="utf-8")
            path.chmod(0o555)
        return original_load(input_directory, **kwargs)

    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        inject_unknown_member,
    )
    with pytest.raises(ValuationRunArchiveError):
        write_valuation_run_archive(execution, output_directory=output)

    assert injected
    assert not output.exists()
    assert not list(tmp_path.glob(".valuation-run.staging-*"))
    quarantines = list(tmp_path.glob(".valuation-run.rollback-*"))
    assert len(quarantines) == 1
    for quarantine in quarantines:
        assert quarantine.is_dir()
        assert stat.S_IMODE(quarantine.stat().st_mode) == 0o555
        assert {member.name for member in quarantine.iterdir()} == {
            *VALUATION_RUN_ARCHIVE_FILENAMES,
            "attacker-unknown.json",
        }
        for member in quarantine.iterdir():
            assert stat.S_ISREG(member.stat(follow_symlinks=False).st_mode)
            assert stat.S_IMODE(member.stat(follow_symlinks=False).st_mode) == 0o444

    monkeypatch.setattr(
        archive_module,
        "_load_valuation_run_archive_unlocked",
        original_load,
    )
    retry = write_valuation_run_archive(execution, output_directory=output)
    assert retry.output_directory == output
    assert load_valuation_run_archive(
        output,
        expected_execution=execution,
    ).fingerprint == retry.fingerprint
    assert not list(tmp_path.glob(".valuation-run.staging-*"))
    assert list(tmp_path.glob(".valuation-run.rollback-*")) == quarantines
    assert stat.S_IMODE(quarantines[0].stat().st_mode) == 0o555


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin clone publication regression")
def test_darwin_clone_first_exposes_only_sealed_archive(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_clone = archive_module._clone_directory_noreplace
    observed: dict[str, Any] = {}

    def clone_and_observe(parent_descriptor: int, source: str, target: str) -> None:
        original_clone(parent_descriptor, source, target)
        root = os.stat(target, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(
            target,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            observed["root_mode"] = stat.S_IMODE(root.st_mode)
            observed["member_modes"] = {
                name: stat.S_IMODE(
                    os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode
                )
                for name in os.listdir(descriptor)
            }
        finally:
            os.close(descriptor)

    monkeypatch.setattr(
        archive_module,
        "_clone_directory_noreplace",
        clone_and_observe,
    )
    write_valuation_run_archive(execution, output_directory=output)

    assert observed["root_mode"] == 0o555
    assert observed["member_modes"] == {
        name: 0o444 for name in VALUATION_RUN_ARCHIVE_FILENAMES
    }


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fail-closed regression")
def test_darwin_clone_unsupported_does_not_fallback_to_rename(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"

    def unsupported(*_args) -> None:
        raise OSError(errno.ENOTSUP, "clone unavailable")

    monkeypatch.setattr(archive_module, "_clone_directory_noreplace", unsupported)
    monkeypatch.setattr(
        archive_module,
        "_rename_directory_noreplace",
        lambda *_args: (_ for _ in ()).throw(AssertionError("rename fallback used")),
    )
    with pytest.raises(ValuationRunArchiveError, match="publication failed: OSError"):
        write_valuation_run_archive(execution, output_directory=output)

    assert not output.exists()
    assert not list(tmp_path.glob(".valuation-run.staging-*"))


def test_rollback_placeholder_creation_failure_leaves_no_orphan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent_descriptor = archive_module._open_directory(tmp_path)
    placeholder_name = ".valuation-run.rollback-test"

    def reject_placeholder(_descriptor: int, label: str) -> None:
        if label == "valuation archive rollback placeholder":
            raise ValuationRunArchiveError("injected placeholder rejection")

    monkeypatch.setattr(archive_module, "_reject_extended_acl", reject_placeholder)
    try:
        with pytest.raises(ValuationRunArchiveError, match="placeholder rejection"):
            archive_module._write_read_only_placeholder(
                parent_descriptor,
                placeholder_name,
            )
        assert placeholder_name not in os.listdir(parent_descriptor)
    finally:
        os.close(parent_descriptor)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin swap rollback regression")
def test_darwin_rollback_verifies_both_swapped_identities(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target_name = "valuation-run"
    placeholder_name = ".valuation-run.rollback-fixed"
    target = tmp_path / target_name
    target.mkdir(mode=0o700)
    target.chmod(0o555)
    details = target.stat()
    published_identity = (details.st_dev, details.st_ino)
    parent_descriptor = archive_module._open_directory(tmp_path)
    original_stat = os.stat

    class FixedUUID:
        hex = "fixed"

    monkeypatch.setattr(archive_module.uuid, "uuid4", lambda: FixedUUID())
    falsified = False

    def falsify_displaced_identity(path, *args, **kwargs):
        nonlocal falsified
        observed = original_stat(path, *args, **kwargs)
        if (
            path == placeholder_name
            and stat.S_ISDIR(observed.st_mode)
            and not falsified
        ):
            falsified = True
            values = list(observed)
            values[stat.ST_INO] += 1
            return os.stat_result(values)
        return observed

    monkeypatch.setattr(archive_module.os, "stat", falsify_displaced_identity)
    try:
        with pytest.raises(ValuationRunArchiveError, match="rollback target changed"):
            archive_module._rollback_published_directory(
                parent_descriptor,
                target_name=target_name,
                staging_name="unused-staging",
                published_identity=published_identity,
                source_moved=False,
            )
        assert falsified
        monkeypatch.setattr(archive_module.os, "stat", original_stat)
        assert stat.S_ISREG(
            original_stat(
                target_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            ).st_mode
        )
        displaced = original_stat(
            placeholder_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        assert stat.S_ISDIR(displaced.st_mode)
        assert (displaced.st_dev, displaced.st_ino) == published_identity
    finally:
        monkeypatch.setattr(archive_module.os, "stat", original_stat)
        if target_name in os.listdir(parent_descriptor) and placeholder_name in os.listdir(
            parent_descriptor
        ):
            archive_module._rename_exchange(
                parent_descriptor,
                target_name,
                placeholder_name,
            )
        if placeholder_name in os.listdir(parent_descriptor):
            os.unlink(placeholder_name, dir_fd=parent_descriptor)
        if target_name in os.listdir(parent_descriptor):
            descriptor = os.open(
                target_name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                dir_fd=parent_descriptor,
            )
            try:
                os.fchmod(descriptor, 0o700)
            finally:
                os.close(descriptor)
            os.rmdir(target_name, dir_fd=parent_descriptor)
        os.close(parent_descriptor)


def test_archive_staging_is_0555_and_byte_replayed_before_publication(
    tmp_path: Path,
) -> None:
    contents = {
        name: (f'{{"member":"{name}"}}\n').encode()
        for name in VALUATION_RUN_ARCHIVE_FILENAMES
    }
    parent_descriptor = archive_module._open_directory(tmp_path)
    staging_name = ".valuation-run.staging-test"
    try:
        archive_module._write_staging(parent_descriptor, staging_name, contents)
        descriptor = os.open(
            staging_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o555
            assert archive_module._verify_staging_directory(descriptor, contents) == (
                os.fstat(descriptor).st_dev,
                os.fstat(descriptor).st_ino,
            )
        finally:
            os.close(descriptor)
    finally:
        if staging_name in os.listdir(parent_descriptor):
            archive_module._remove_staging_directory(parent_descriptor, staging_name)
        os.close(parent_descriptor)


def test_archive_root_sealing_failure_rolls_back_published_target(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_reject_acl = archive_module._reject_extended_acl

    def reject_published_root(descriptor: int, label: str) -> None:
        if label == "published valuation archive directory":
            raise ValuationRunArchiveError("injected archive root sealing failure")
        original_reject_acl(descriptor, label)

    monkeypatch.setattr(archive_module, "_reject_extended_acl", reject_published_root)
    with pytest.raises(ValuationRunArchiveError, match="injected archive root sealing failure"):
        write_valuation_run_archive(execution, output_directory=output)

    assert not output.exists()
    assert not list(tmp_path.glob(".valuation-run.staging-*"))


def test_reloader_rejects_writable_directory_member_and_byte_limits(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)

    output.chmod(0o755)
    with pytest.raises(ValuationRunArchiveError, match="directory must be read-only"):
        load_valuation_run_archive(output)
    output.chmod(0o555)

    request = output / "valuation-request.json"
    request.chmod(0o644)
    with pytest.raises(ValuationRunArchiveError, match="must be read-only"):
        load_valuation_run_archive(output)
    request.chmod(0o444)

    monkeypatch.setattr(archive_module, "VALUATION_RUN_MEMBER_MAX_BYTES", 32)
    with pytest.raises(ValuationRunArchiveError, match="byte limit"):
        load_valuation_run_archive(output)


def test_reloader_rejects_fifo_member_without_blocking(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    member = output / "valuation-handoff.json"
    output.chmod(0o755)
    member.unlink()
    os.mkfifo(member, mode=0o444)
    member.chmod(0o444)
    output.chmod(0o555)

    probe = subprocess.run(
        (
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "from owner_research.valuation_run_archive import "
                "ValuationRunArchiveError,load_valuation_run_archive; "
                "\ntry: load_valuation_run_archive(Path(__import__('sys').argv[1]))"
                "\nexcept ValuationRunArchiveError: raise SystemExit(0)"
                "\nraise SystemExit(2)"
            ),
            str(output),
        ),
        cwd=Path(__file__).resolve().parents[1],
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                filter(
                    None,
                    (
                        str(Path(__file__).resolve().parents[1] / "src"),
                        os.environ.get("PYTHONPATH", ""),
                    ),
                )
            ),
        },
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr


def test_archive_component_lock_read_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    component_lock = tmp_path / "component-lock.json"
    component_lock.write_bytes(b"{}   ")
    monkeypatch.setattr(archive_module, "VALUATION_RUN_MEMBER_MAX_BYTES", 4)

    with pytest.raises(ValuationRunArchiveError, match="bounded regular file"):
        archive_module._component_lock(component_lock)


def test_archive_component_lock_rejects_symlinked_parent_and_ambient_writers(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    component_lock = real_parent / "component-lock.json"
    component_lock.write_bytes(b"{}")
    parent_alias = tmp_path / "parent-alias"
    parent_alias.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValuationRunArchiveError, match="symlinked component"):
        archive_module._component_lock(parent_alias / component_lock.name)
    component_lock.chmod(0o666)
    with pytest.raises(ValuationRunArchiveError, match="bounded regular file"):
        archive_module._component_lock(component_lock)


@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="Linux O_PATH behavior")
def test_archive_component_lock_traverses_execute_only_ancestor(
    tmp_path: Path,
) -> None:
    traversal = tmp_path / "execute-only"
    protected = traversal / "protected"
    protected.mkdir(parents=True)
    component_lock = protected / "component-lock.json"
    component_lock.write_bytes(b"{}")
    component_lock.chmod(0o444)
    protected.chmod(0o555)
    traversal.chmod(0o111)
    try:
        payload, digest = archive_module._component_lock(component_lock)
    finally:
        traversal.chmod(0o700)

    assert payload == {}
    assert digest == _sha256(b"{}")


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fixed root alias")
@pytest.mark.parametrize("temporary_root", ("/tmp", "/var/tmp"))
def test_archive_component_lock_accepts_platform_tmp_root_alias(temporary_root: str) -> None:
    with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
        component_lock = Path(directory) / "component-lock.json"
        component_lock.write_bytes(b"{}")
        component_lock.chmod(0o444)

        payload, digest = archive_module._component_lock(component_lock)

    assert payload == {}
    assert digest == _sha256(b"{}")


def test_archive_object_path_or_manifest_rebind_is_rejected_by_completed_result(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    archive = write_valuation_run_archive(execution, output_directory=output)
    graph = execution.preparation.prepared_market_reference.graph
    receipt = run_module._input_receipt(
        graph=graph,
        candidate_compilation=_candidate_compilation(execution.expected_freeze),
        authority=_authority(execution.preparation, execution.expected_freeze, tmp_path),
        runtime_manifest_authority=_typed_runtime_authority(),
        clock=_run_clock(execution.preparation),
    )
    result = run_module._valuation_run_result(
        status="completed",
        issuer_id=execution.issuer_id,
        data_cutoff_date=execution.data_cutoff_date,
        input_receipt=receipt,
        preparation=execution.preparation,
        execution=execution,
        archive=archive,
        issue_codes=(),
    )
    assert result.archive == archive
    with pytest.raises((ValueError, ValuationRunArchiveError)):
        replace(result, archive=replace(archive, output_directory=tmp_path / "other"))
    with pytest.raises((ValueError, ValuationRunArchiveError)):
        replace(
            result,
            archive=replace(
                archive,
                manifest={**dict(archive.manifest), "archive_id": "rebound"},
            ),
        )
    rebound_manifest = json.loads(canonical_json(_typed_runtime_authority().manifest_payload))
    rebound_manifest["authority"]["sha256"] = "e" * 64
    rebound_manifest.pop("manifest_fingerprint")
    rebound_manifest["manifest_fingerprint"] = canonical_sha256(rebound_manifest)
    rebound_receipt = run_module._input_receipt(
        graph=graph,
        candidate_compilation=_candidate_compilation(execution.expected_freeze),
        authority=_authority(execution.preparation, execution.expected_freeze, tmp_path),
        runtime_manifest_authority=RuntimeManifestInputAuthority.verified(rebound_manifest),
        clock=_run_clock(execution.preparation),
    )
    with pytest.raises(ValueError, match="typed input authorities"):
        replace(result, input_receipt=rebound_receipt)

    duplicate_archive = write_valuation_run_archive(
        execution,
        output_directory=tmp_path / "byte-identical-archive",
    )
    with pytest.raises(ValueError, match="integrity binding"):
        replace(result, archive=duplicate_archive)

    template_document = next(
        item for item in graph.documents if item.authority_level == "market_reference"
    )
    rebound_document = replace(
        template_document,
        document_id="doc:issuer:acme:archive-rebind-probe",
        source_url="https://market.example.invalid/rebind-probe",
        content_sha256="0" * 64,
    )
    rebound_graph = replace(
        graph,
        documents=(*graph.documents, rebound_document),
    )
    rebound_graph.validate()
    reduced_receipt = run_module._input_receipt(
        graph=rebound_graph,
        candidate_compilation=_candidate_compilation(execution.expected_freeze),
        authority=_authority(execution.preparation, execution.expected_freeze, tmp_path),
        runtime_manifest_authority=_typed_runtime_authority(),
        clock=_run_clock(execution.preparation),
    )
    with pytest.raises(ValueError):
        replace(result, input_receipt=reduced_receipt)


def test_archive_writer_and_expected_reload_bind_the_full_runtime_authority(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    rebound_manifest = json.loads(
        canonical_json(_typed_runtime_authority().manifest_payload)
    )
    rebound_manifest["producer"]["fixture"] = "coordinated-rebound-producer"
    rebound_manifest.pop("manifest_fingerprint")
    rebound_manifest["manifest_fingerprint"] = canonical_sha256(rebound_manifest)
    rebound_authority = RuntimeManifestInputAuthority.verified(rebound_manifest)

    with pytest.raises(
        ValuationRunArchiveError,
        match="differs from the completed kernel receipt",
    ):
        _write_valuation_run_archive(
            execution,
            output_directory=tmp_path / "rebound-runtime-authority",
            runtime_manifest_authority=rebound_authority,
        )
    with pytest.raises(
        ValuationRunArchiveError,
        match="differs from the completed kernel receipt",
    ):
        load_valuation_run_archive(
            output,
            expected_execution=execution,
            expected_runtime_manifest_authority=rebound_authority,
        )


def test_archive_publication_never_replaces_a_racing_target(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    original_write_staging = archive_module._write_staging
    racing_inode: int | None = None

    def write_then_race(parent_descriptor, name, contents):
        nonlocal racing_inode
        original_write_staging(parent_descriptor, name, contents)
        output.mkdir(mode=0o700)
        racing_inode = output.stat().st_ino

    monkeypatch.setattr(archive_module, "_write_staging", write_then_race)
    with pytest.raises(ValuationRunArchiveError, match="different content"):
        write_valuation_run_archive(execution, output_directory=output)

    assert output.is_dir()
    assert output.stat().st_ino == racing_inode
    assert tuple(output.iterdir()) == ()
    assert not list(tmp_path.glob(".valuation-run.staging-*"))


def test_archive_reload_rejects_a_coordinated_path_inode_swap(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced"
    write_valuation_run_archive(execution, output_directory=output)
    write_valuation_run_archive(execution, output_directory=replacement)
    original_validate = archive_module._validate_manifest

    def validate_then_swap(**kwargs):
        value = original_validate(**kwargs)
        output.chmod(0o755)
        replacement.chmod(0o755)
        output.rename(displaced)
        replacement.rename(output)
        displaced.chmod(0o555)
        output.chmod(0o555)
        return value

    monkeypatch.setattr(archive_module, "_validate_manifest", validate_then_swap)
    with pytest.raises(ValuationRunArchiveError, match="path or bytes changed"):
        load_valuation_run_archive(output, expected_execution=execution)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin extended ACL regression")
def test_archive_reloader_rejects_extended_acl_write_authority(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    execution = _completed(sample_payloads, monkeypatch, tmp_path)
    output = tmp_path / "valuation-run"
    write_valuation_run_archive(execution, output_directory=output)
    member = output / "valuation-run-manifest.json"
    try:
        subprocess.run(
            ["chmod", "+a", "everyone allow add_file,delete_child", str(output)],
            check=True,
        )
        with pytest.raises(ValuationRunArchiveError, match="extended ACL"):
            load_valuation_run_archive(output)
        subprocess.run(["chmod", "-a#", "0", str(output)], check=True)
        subprocess.run(
            ["chmod", "+a", "everyone allow write", str(member)],
            check=True,
        )
        with pytest.raises(ValuationRunArchiveError, match="extended ACL"):
            load_valuation_run_archive(output)
    finally:
        subprocess.run(["chmod", "-N", str(member)], check=False)
        subprocess.run(["chmod", "-N", str(output)], check=False)
