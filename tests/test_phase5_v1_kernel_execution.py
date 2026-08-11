from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path

import pytest

from owner_research.valuation_pinned_kernel import (
    PinnedKernelExecutionError,
    _canonical_bytes,
    _deny_runtime_side_effects,
    _extract_runtime_wheels,
    _validate_canonical_request,
    _validated_executable,
    _verify_result_input_bindings,
    execute_pinned_kernel,
)

ROOT = Path(__file__).parents[1]


def _request() -> dict[str, object]:
    fact_ledger = {
        "entity_id": "issuer:test",
        "facts": [],
        "reporting_currency": "USD",
        "schema_version": "1.0.0",
        "sources": [],
        "valuation_date": "2026-07-10",
    }
    fact_fingerprint = hashlib.sha256(_canonical_bytes(fact_ledger)).hexdigest()
    return {
        "assumption_ledger": {
            "assumptions": [],
            "fact_ledger_fingerprint": fact_fingerprint,
            "schema_version": "1.0.0",
        },
        "fact_ledger": fact_ledger,
        "schema_version": "2.0.0",
    }


def test_request_transport_requires_byte_canonical_object() -> None:
    canonical = _canonical_bytes(_request())
    assert _validate_canonical_request(canonical) == _request()
    with pytest.raises(PinnedKernelExecutionError, match="canonical"):
        _validate_canonical_request(b'{"schema_version": "2.0.0"}')
    with pytest.raises(PinnedKernelExecutionError, match="JSON"):
        _validate_canonical_request(b"not json")


def test_result_fingerprints_must_round_trip_exact_request_subtrees() -> None:
    request = _request()
    request_bytes = _canonical_bytes(request)
    expected = {
        "fact_ledger_fingerprint": hashlib.sha256(
            _canonical_bytes(request["fact_ledger"])
        ).hexdigest(),
        "assumption_ledger_fingerprint": hashlib.sha256(
            _canonical_bytes(request["assumption_ledger"])
        ).hexdigest(),
        "model_input_fingerprint": hashlib.sha256(request_bytes).hexdigest(),
    }
    assert _verify_result_input_bindings(request_bytes, request, expected) == tuple(
        expected.values()
    )
    tampered = dict(expected)
    tampered["model_input_fingerprint"] = "0" * 64
    with pytest.raises(PinnedKernelExecutionError, match="do not round-trip"):
        _verify_result_input_bindings(request_bytes, request, tampered)


def test_execution_fails_before_manifest_on_non_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("owner_research.valuation_pinned_kernel.platform.system", lambda: "Darwin")
    with pytest.raises(PinnedKernelExecutionError, match="Linux x86_64"):
        execute_pinned_kernel(
            _canonical_bytes(_request()),
            runtime_manifest=Path("/does/not/exist"),
            runtime_manifest_file_sha256="0" * 64,
            cas_root=Path("/does/not/exist"),
            python_executable=Path(os.path.realpath(os.sys.executable)),
        )


def test_runtime_executable_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "python"
    target.write_bytes(b"binary")
    target.chmod(0o700)
    link = tmp_path / "python-link"
    link.symlink_to(target)
    with pytest.raises(PinnedKernelExecutionError, match="non-symlink"):
        _validated_executable(link, "runtime Python")


def test_runtime_audit_hook_denies_network_process_and_writes() -> None:
    for event, args in (
        ("socket.__new__", ()),
        ("subprocess.Popen", ()),
        ("open", ("output", "wb", 0)),
        ("os.rename", ("a", "b")),
    ):
        with pytest.raises(PermissionError):
            _deny_runtime_side_effects(event, args)
    _deny_runtime_side_effects("open", ("schema.json", "rb", 0))


def test_runtime_wheel_extraction_rejects_cross_wheel_path_collision(tmp_path: Path) -> None:
    cas = tmp_path / "cas"
    objects = cas / "sha256"
    objects.mkdir(parents=True)
    wheel_items = []
    for index in range(2):
        wheel = tmp_path / f"wheel-{index}.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("same/module.py", f"value={index}".encode())
        raw = wheel.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        (objects / digest).write_bytes(raw)
        wheel_items.append({"sha256": digest})
    with pytest.raises(PinnedKernelExecutionError, match="path collision"):
        _extract_runtime_wheels(
            manifest={"wheels": wheel_items},
            cas_root=cas,
            destination=tmp_path / "site",
        )


def test_runtime_wheel_extraction_rejects_symbolic_link_member(tmp_path: Path) -> None:
    cas = tmp_path / "cas"
    objects = cas / "sha256"
    objects.mkdir(parents=True)
    wheel = tmp_path / "link.whl"
    link = zipfile.ZipInfo("package/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(link, b"target")
    raw = wheel.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    (objects / digest).write_bytes(raw)
    with pytest.raises(PinnedKernelExecutionError, match="symbolic link"):
        _extract_runtime_wheels(
            manifest={"wheels": [{"sha256": digest}]},
            cas_root=cas,
            destination=tmp_path / "site",
        )


def test_runner_source_has_one_public_kernel_call_and_no_network_client() -> None:
    source = (ROOT / "src/owner_research/valuation_pinned_kernel.py").read_text(encoding="utf-8")
    assert source.count("owner_valuation.run_dual_panel(request)") == 1
    assert "requests." not in source
    assert "httpx" not in source
    package_root = (ROOT / "src/owner_research/__init__.py").read_text(encoding="utf-8")
    cli = (ROOT / "src/owner_research/cli.py").read_text(encoding="utf-8")
    assert "execute_pinned_kernel" not in package_root
    assert "execute_pinned_kernel" not in cli
