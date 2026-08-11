from __future__ import annotations

import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from owner_research.component_lock import verify_kernel_runtime_lock
from owner_research.valuation_kernel_materializer import (
    AUTHORITY_RESOURCE,
    KernelMaterializationError,
    _normalize_registered_zip_timestamps,
    _verify_registered_wheel,
    materialize_pinned_kernel_runtime,
    verify_pinned_kernel_checkout,
)

ROOT = Path(__file__).parents[1]
KERNEL = Path(os.environ.get("OWNER_VALUATION_REPO", ROOT.parent / "owner-valuation-kernel"))
KERNEL_AVAILABLE = KERNEL.is_dir()
EXPECTED_COMMIT = "be9b0773d5a78f5f8a33ba982494512668df85fe"
EXPECTED_WHEEL_SHA256 = "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"


def test_runtime_authority_is_exactly_pinned() -> None:
    assert verify_kernel_runtime_lock().ok
    authority = json.loads(AUTHORITY_RESOURCE.read_bytes())
    assert authority["kernel"]["commit"] == EXPECTED_COMMIT
    assert authority["kernel"]["wheel_sha256"] == EXPECTED_WHEEL_SHA256


@pytest.mark.skipif(not KERNEL_AVAILABLE, reason="private kernel checkout is verify-job only")
def test_private_checkout_is_exactly_pinned() -> None:
    attestation = verify_pinned_kernel_checkout(KERNEL)
    assert attestation.commit == EXPECTED_COMMIT
    assert attestation.tag_object == "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
    assert attestation.tracked_source_count == 24


def test_real_supply_identity_mismatch_blocks_before_build(tmp_path: Path) -> None:
    wrong = tmp_path / "wrong-kernel"
    wrong.mkdir()
    subprocess.run(("git", "init", "-q", str(wrong)), check=True)
    with pytest.raises(KernelMaterializationError, match="git verification failed|tag object"):
        verify_pinned_kernel_checkout(wrong)


@pytest.mark.skipif(not KERNEL_AVAILABLE, reason="private kernel checkout is verify-job only")
def test_missing_runtime_dependency_inventory_blocks_before_backend(tmp_path: Path) -> None:
    fake_backend = tmp_path / "setuptools-80.9.0-py3-none-any.whl"
    fake_backend.write_bytes(b"not a wheel")
    with pytest.raises(KernelMaterializationError, match="dependency wheel inventory mismatch"):
        materialize_pinned_kernel_runtime(
            kernel_checkout=KERNEL,
            cas_root=tmp_path / "private-cas",
            build_python=Path(os.path.realpath(os.sys.executable)),
            setuptools_wheel=fake_backend,
            dependency_wheels=(),
            target_python_minor="3.11",
        )


def test_registered_wheel_reader_rejects_symlink_even_when_target_exists(tmp_path: Path) -> None:
    target = tmp_path / "bytes.whl"
    target.write_bytes(b"not relevant")
    link = tmp_path / "setuptools-80.9.0-py3-none-any.whl"
    link.symlink_to(target)
    with pytest.raises(KernelMaterializationError, match="not a regular file"):
        _verify_registered_wheel(link, link.name, "0" * 64)


def test_timestamp_normalizer_changes_only_registered_dist_info(tmp_path: Path) -> None:
    wheel = tmp_path / "probe.whl"
    registered = {
        "owner_valuation_kernel-2.0.0rc2.dist-info/METADATA",
        "owner_valuation_kernel-2.0.0rc2.dist-info/RECORD",
        "owner_valuation_kernel-2.0.0rc2.dist-info/WHEEL",
        "owner_valuation_kernel-2.0.0rc2.dist-info/entry_points.txt",
        "owner_valuation_kernel-2.0.0rc2.dist-info/top_level.txt",
    }
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        source = zipfile.ZipInfo("owner_valuation/__init__.py", (2026, 7, 15, 4, 12, 50))
        archive.writestr(source, b"source")
        for name in sorted(registered):
            item = zipfile.ZipInfo(name, (2026, 8, 11, 1, 2, 4))
            archive.writestr(item, name.encode())
    before = wheel.read_bytes()
    _normalize_registered_zip_timestamps(
        wheel,
        names=frozenset(registered),
        timestamp="2026-07-15T04:14:26Z",
    )
    after = wheel.read_bytes()
    assert before != after
    with zipfile.ZipFile(wheel) as archive:
        assert archive.getinfo("owner_valuation/__init__.py").date_time == (
            2026,
            7,
            15,
            4,
            12,
            50,
        )
        assert {archive.getinfo(name).date_time for name in registered} == {
            (2026, 7, 15, 4, 14, 26)
        }


@pytest.mark.skipif(not KERNEL_AVAILABLE, reason="private kernel checkout is verify-job only")
def test_private_cas_inside_repository_is_rejected(tmp_path: Path) -> None:
    fake_backend = tmp_path / "setuptools-80.9.0-py3-none-any.whl"
    fake_backend.write_bytes(b"not a wheel")
    with pytest.raises(KernelMaterializationError, match="private CAS"):
        materialize_pinned_kernel_runtime(
            kernel_checkout=KERNEL,
            cas_root=ROOT / ".forbidden-private-cas",
            build_python=Path(os.path.realpath(os.sys.executable)),
            setuptools_wheel=fake_backend,
            dependency_wheels=(),
            target_python_minor="3.11",
        )


def test_materializer_has_no_public_package_or_cli_surface() -> None:
    package_root = (ROOT / "src/owner_research/__init__.py").read_text(encoding="utf-8")
    cli = (ROOT / "src/owner_research/cli.py").read_text(encoding="utf-8")
    assert "valuation_kernel_materializer" not in package_root
    assert "materialize_pinned_kernel_runtime" not in package_root
    assert "materialize_pinned_kernel_runtime" not in cli
