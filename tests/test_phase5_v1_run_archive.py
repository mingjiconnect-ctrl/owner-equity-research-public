from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_phase5_v1_owner_execution import (
    _compiled,
    _completed_result,
    _prepared_inputs,
)
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
    write_valuation_run_archive,
)


def _completed(
    sample_payloads: dict[str, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Any:
    preparation, freeze = _prepared_inputs(sample_payloads, monkeypatch, tmp_path)
    compiled = _compiled(preparation)
    return _completed_result(
        preparation=preparation,
        freeze_result=freeze,
        compiled=compiled,
        monkeypatch=monkeypatch,
    )


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
    receipt = manifest["final_request_receipt"]
    receipt["status"] = "blocked"
    receipt["reason_codes"] = ["kernel_component_drift"]
    receipt_payload = dict(receipt)
    receipt_payload.pop("receipt_id")
    receipt["receipt_id"] = (
        f"final-request-receipt:{receipt['issuer_id']}:{canonical_sha256(receipt_payload)[:24]}"
    )
    manifest_payload = dict(manifest)
    manifest_payload.pop("manifest_fingerprint")
    manifest["manifest_fingerprint"] = canonical_sha256(manifest_payload)
    manifest_path.write_bytes((canonical_json(manifest) + "\n").encode("utf-8"))
    manifest_path.chmod(0o444)
    output.chmod(0o555)

    with pytest.raises(ValuationRunArchiveError, match="receipts do not bind"):
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


def test_archive_component_lock_read_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    component_lock = tmp_path / "component-lock.json"
    component_lock.write_bytes(b"{}   ")
    monkeypatch.setattr(archive_module, "VALUATION_RUN_MEMBER_MAX_BYTES", 4)

    with pytest.raises(ValuationRunArchiveError, match="bounded regular file"):
        archive_module._component_lock(component_lock)


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

    rebound_graph = replace(
        graph,
        facts=tuple(item for item in graph.facts if item.fact_id != "fact:acme:issuer-legal-name"),
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
