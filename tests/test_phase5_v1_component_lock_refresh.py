from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import owner_research.component_lock as component_lock

ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "scripts" / "refresh_pr3_component_lock.py"
SCRIPT = runpy.run_path(str(SCRIPT_PATH))
BUILD = SCRIPT["build_refreshed_component_lock"]
CHECK = SCRIPT["check_pr3_component_lock"]
WRITE = SCRIPT["write_pr3_component_lock"]
CANONICAL = SCRIPT["_canonical_json_bytes"]
FROZEN = SCRIPT["_frozen_projection"]


def _copy_lock(destination: Path) -> Path:
    shutil.copy2(ROOT / "component-lock.json", destination)
    destination.chmod(0o644)
    return destination


def _load(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw)
    assert isinstance(value, dict)
    return value


def _make_drifted_lock(destination: Path) -> Path:
    _copy_lock(destination)
    payload = _load(destination.read_bytes())
    payload["owner_equity_research"]["pr3_comprehensive"]["module_sha256"][
        "workflow_cli.py"
    ] = "0" * 64
    destination.write_bytes(CANONICAL(payload))
    destination.chmod(0o644)
    return destination


def test_refresher_is_deterministic_and_changes_only_the_authorized_surface() -> None:
    lock_path = ROOT / "component-lock.json"
    before = _load(lock_path.read_bytes())
    first = BUILD(repository_root=ROOT, lock_path=lock_path)
    second = BUILD(repository_root=ROOT, lock_path=lock_path)
    assert first.output_bytes == second.output_bytes
    assert first.output_bytes == CANONICAL(_load(first.output_bytes))

    after = _load(first.output_bytes)
    assert FROZEN(before) == FROZEN(after)
    assert after["generated_date"] == before["generated_date"]
    assert after["owner_equity_research"]["public_schema_sha256"] == before[
        "owner_equity_research"
    ]["public_schema_sha256"]
    for frozen_key in (
        "market_access_authority",
        "valuation_kernel_runtime",
        "valuation_kernel",
    ):
        assert CANONICAL(after[frozen_key]) == CANONICAL(before[frozen_key])


def test_refreshed_manifest_replays_the_exact_component_lock_projection() -> None:
    refreshed = BUILD(
        repository_root=ROOT,
        lock_path=ROOT / "component-lock.json",
    )
    payload = _load(refreshed.output_bytes)
    owner = payload["owner_equity_research"]
    manifest = owner["pr3_comprehensive"]
    assert manifest["manifest_version"] == component_lock._PR3_MANIFEST_VERSION
    assert manifest["package_version"] == component_lock._PR3_PACKAGE_VERSION
    assert owner["plugin_version"] == "1.0.0-dev.0"
    assert tuple(manifest["module_sha256"]) == tuple(sorted(component_lock._PR3_MODULE_PATHS))
    assert "refresh_pr3_component_lock.py" not in manifest["module_sha256"]
    for map_name in (
        "extension_schema_sha256",
        "futu_resource_sha256",
        "kernel_schema_resource_sha256",
        "report_asset_sha256",
        "module_sha256",
    ):
        assert list(manifest[map_name]) == sorted(manifest[map_name])

    members = component_lock._pr3_locked_snapshot(repository_root=ROOT, package_root=None)
    verification = component_lock.verify_pr3_comprehensive_snapshot(
        lock_bytes=refreshed.output_bytes,
        members=members,
    )
    assert verification.ok, "\n".join(verification.errors)


def test_coordinated_extra_kernel_schema_and_manifest_rebinding_is_rejected() -> None:
    refreshed = BUILD(
        repository_root=ROOT,
        lock_path=ROOT / "component-lock.json",
    )
    payload = _load(refreshed.output_bytes)
    members = component_lock._pr3_locked_snapshot(repository_root=ROOT, package_root=None)
    extra_path = "resources/phase5-v1-kernel-schemas/unapproved.schema.json"
    extra_bytes = b'{"$schema":"https://json-schema.org/draft/2020-12/schema"}'
    members[extra_path] = extra_bytes
    payload["owner_equity_research"]["pr3_comprehensive"][
        "kernel_schema_resource_sha256"
    ][extra_path] = hashlib.sha256(extra_bytes).hexdigest()

    verification = component_lock.verify_pr3_comprehensive_snapshot(
        lock_bytes=CANONICAL(payload),
        members=members,
    )

    assert not verification.ok
    assert "inventory differs from the pinned kernel subset" in "\n".join(
        verification.errors
    )


def test_check_reports_drift_and_accepts_the_refreshed_bytes(tmp_path: Path) -> None:
    lock_path = _make_drifted_lock(tmp_path / "component-lock.json")
    assert CHECK(repository_root=ROOT, lock_path=lock_path) == (
        "PR3 component-lock is not the exact deterministic source projection",
    )
    refreshed = BUILD(repository_root=ROOT, lock_path=lock_path)
    lock_path.write_bytes(refreshed.output_bytes)
    lock_path.chmod(0o644)
    assert CHECK(repository_root=ROOT, lock_path=lock_path) == ()


def test_write_is_atomic_fsynced_safe_mode_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_path = _make_drifted_lock(tmp_path / "component-lock.json")
    real_fsync = os.fsync
    fsynced: list[int] = []

    def recording_fsync(descriptor: int) -> None:
        fsynced.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    assert WRITE(repository_root=ROOT, lock_path=lock_path) is True
    assert len(fsynced) >= 3
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o644
    assert CHECK(repository_root=ROOT, lock_path=lock_path) == ()
    assert not tuple(tmp_path.glob(".component-lock.json.refresh-*.tmp"))

    inode = lock_path.stat().st_ino
    identity = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    assert WRITE(repository_root=ROOT, lock_path=lock_path) is False
    assert lock_path.stat().st_ino == inode
    assert hashlib.sha256(lock_path.read_bytes()).hexdigest() == identity


@pytest.mark.parametrize("kind", ("duplicate", "noncanonical", "open"))
def test_refresher_rejects_duplicate_noncanonical_and_open_input(
    tmp_path: Path,
    kind: str,
) -> None:
    lock_path = _copy_lock(tmp_path / f"{kind}.json")
    raw = lock_path.read_bytes()
    if kind == "duplicate":
        raw = b'{"lock_version":"1.2.0",' + raw[1:]
    elif kind == "noncanonical":
        raw = json.dumps(_load(raw), ensure_ascii=False, separators=(",", ":")).encode()
    else:
        payload = _load(raw)
        payload["owner_equity_research"]["pr3_comprehensive"]["open_member"] = True
        raw = CANONICAL(payload)
    lock_path.write_bytes(raw)
    lock_path.chmod(0o644)
    with pytest.raises(ValueError, match="duplicate JSON key|not canonical|not closed"):
        BUILD(repository_root=ROOT, lock_path=lock_path)


def test_refresher_rejects_unsafe_lock_path_modes_and_links(tmp_path: Path) -> None:
    writable = _copy_lock(tmp_path / "writable.json")
    writable.chmod(0o666)
    with pytest.raises(ValueError, match="bounded 0644 regular file"):
        BUILD(repository_root=ROOT, lock_path=writable)

    source = _copy_lock(tmp_path / "source.json")
    hardlink = tmp_path / "hardlink.json"
    os.link(source, hardlink)
    with pytest.raises(ValueError, match="bounded 0644 regular file"):
        BUILD(repository_root=ROOT, lock_path=hardlink)

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(source)
    with pytest.raises(ValueError, match="bounded 0644 regular file"):
        BUILD(repository_root=ROOT, lock_path=symlink)


def test_refresher_rejects_open_or_reordered_frozen_pr1_pr2_fields(tmp_path: Path) -> None:
    lock_path = _copy_lock(tmp_path / "frozen-open.json")
    payload = _load(lock_path.read_bytes())
    payload["market_access_authority"]["open_member"] = True
    lock_path.write_bytes(CANONICAL(payload))
    lock_path.chmod(0o644)
    with pytest.raises(ValueError, match="frozen PR1/PR2.*open, reordered, or drifted"):
        BUILD(repository_root=ROOT, lock_path=lock_path)

    lock_path = _copy_lock(tmp_path / "frozen-reordered.json")
    payload = _load(lock_path.read_bytes())
    market = payload["market_access_authority"]
    payload["market_access_authority"] = {key: market[key] for key in reversed(market)}
    lock_path.write_bytes(CANONICAL(payload))
    lock_path.chmod(0o644)
    with pytest.raises(ValueError, match="frozen PR1/PR2.*open, reordered, or drifted"):
        BUILD(repository_root=ROOT, lock_path=lock_path)


def test_cli_check_and_write_have_closed_exit_semantics(tmp_path: Path) -> None:
    lock_path = _make_drifted_lock(tmp_path / "component-lock.json")
    base_command = (
        sys.executable,
        str(SCRIPT_PATH),
        "--repository-root",
        str(ROOT),
        "--lock",
        str(lock_path),
    )
    checked = subprocess.run((*base_command, "--check"), check=False, capture_output=True)
    assert checked.returncode == 1
    assert b"not the exact deterministic source projection" in checked.stdout
    written = subprocess.run((*base_command, "--write"), check=False, capture_output=True)
    assert written.returncode == 0
    assert b"refreshed" in written.stdout
    rechecked = subprocess.run((*base_command, "--check"), check=False, capture_output=True)
    assert rechecked.returncode == 0
    assert b"check passed" in rechecked.stdout
