from __future__ import annotations

import base64
import hashlib
import inspect
import json
import tempfile
from importlib.metadata import FileHash, PackagePath
from pathlib import Path

import pytest

import owner_research.research_report as report_module
from owner_research.research_report import ResearchReportError

ROOT = Path(__file__).parents[1]


class _FakeDistribution:
    def __init__(self, root: Path, files: tuple[PackagePath, ...]) -> None:
        self._root = root
        self.files = files
        self.version = "1.0.0"

    def locate_file(self, member: PackagePath) -> Path:
        return self._root / Path(str(member))


def _record_sha256(content: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()


def _recorded_member(
    root: Path,
    relative: str,
    content: bytes,
    *,
    record_sha256: str | None = None,
    record_size: int | None = None,
) -> PackagePath:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    member = PackagePath(relative)
    if record_sha256 is not None:
        member.hash = FileHash(f"sha256={record_sha256}")
    else:
        member.hash = None
    member.size = record_size
    return member


def _stable_member(root: Path, relative: str, content: bytes) -> PackagePath:
    return _recorded_member(
        root,
        relative,
        content,
        record_sha256=_record_sha256(content),
        record_size=len(content),
    )


def test_bounded_resource_read_accepts_the_platform_tmp_root_alias() -> None:
    with tempfile.TemporaryDirectory(
        prefix="owner-research-report-resource-",
        dir="/tmp",
    ) as directory:
        resource = Path(directory) / "resource.json"
        content = b'{"status":"available"}\n'
        resource.write_bytes(content)

        assert report_module._read_bounded_regular_file(
            resource,
            limit=1024,
            label="temporary installed resource",
        ) == content


def test_report_children_always_receive_the_private_output_umask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    completed = object()

    def fake_run(*args: object, **kwargs: object) -> object:
        calls.append(dict(kwargs))
        return completed

    monkeypatch.setattr(report_module.subprocess, "run", fake_run)

    assert report_module._run_private_subprocess(["renderer"], check=False) is completed
    assert calls == [{"check": False, "umask": 0o077}]
    assert inspect.getsource(report_module).count("subprocess.run(") == 1


def test_tectonic_cache_snapshot_selects_the_exact_authority_order(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache = tmp_path / ".cache" / "tectonic"
    nested = cache / "a"
    nested.mkdir(parents=True)
    (cache / "a-plain.txt").write_bytes(b"plain")
    (nested / "z.txt").write_bytes(b"nested")
    monkeypatch.setattr(report_module.Path, "home", classmethod(lambda _cls: tmp_path))

    depth_first = report_module._trusted_tectonic_cache()

    expected = hashlib.sha256()
    for relative, marker in (
        ("a", b"directory\0"),
        ("a-plain.txt", b"5\0" + hashlib.sha256(b"plain").digest()),
        ("a/z.txt", b"6\0" + hashlib.sha256(b"nested").digest()),
    ):
        expected.update(relative.encode("utf-8"))
        expected.update(b"\0")
        expected.update(marker)
    expected_identity = {
        "tree_sha256": expected.hexdigest(),
        "member_count": 3,
        "total_bytes": 11,
    }
    snapshot = report_module._tectonic_cache_snapshot_for_authority(
        depth_first,
        expected_identity,
    )

    assert depth_first.tree_sha256 != expected.hexdigest()
    assert snapshot.tree_sha256 == expected.hexdigest()
    assert tuple(entry.relative_path for entry in snapshot.entries) == (
        "a",
        "a-plain.txt",
        "a/z.txt",
    )


def test_distribution_identity_ignores_hashless_bytecode_and_installer_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stable = _stable_member(tmp_path, "sample/__init__.py", b"VERSION = '1.0.0'\n")
    metadata = _stable_member(tmp_path, "sample-1.0.0.dist-info/METADATA", b"Name: sample\n")
    bytecode = _stable_member(
        tmp_path,
        "sample/__pycache__/__init__.cpython-311.pyc",
        b"derived-bytecode",
    )
    hashless = _recorded_member(
        tmp_path,
        "sample/generated.txt",
        b"installer-generated",
        record_size=None,
    )
    installer = _stable_member(tmp_path, "sample-1.0.0.dist-info/INSTALLER", b"pip\n")
    installer_cache = _stable_member(
        tmp_path,
        "sample-1.0.0.dist-info/uv_cache.json",
        b'{"cache":true}\n',
    )
    distribution = _FakeDistribution(
        tmp_path,
        (stable, metadata, bytecode, hashless, installer, installer_cache),
    )
    monkeypatch.setattr(
        report_module.importlib.metadata,
        "distribution",
        lambda _name: distribution,
    )

    before = report_module._trusted_distribution_snapshot("sample")
    (tmp_path / str(bytecode)).write_bytes(b"different-python-minor-bytecode")
    (tmp_path / str(hashless)).write_bytes(b"different-installer-output")
    (tmp_path / str(installer)).write_bytes(b"uv\n")
    (tmp_path / str(installer_cache)).write_bytes(b'{"cache":false}\n')
    after = report_module._trusted_distribution_snapshot("sample")

    assert before.identity() == after.identity()
    assert tuple(entry.relative_path for entry in before.entries) == (
        "sample-1.0.0.dist-info/METADATA",
        "sample/__init__.py",
    )


def test_distribution_identity_rejects_record_sha256_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    content = b"trusted module\n"
    member = _recorded_member(
        tmp_path,
        "sample/module.py",
        content,
        record_sha256=_record_sha256(b"different module\n"),
        record_size=len(content),
    )
    distribution = _FakeDistribution(tmp_path, (member,))
    monkeypatch.setattr(
        report_module.importlib.metadata,
        "distribution",
        lambda _name: distribution,
    )

    with pytest.raises(ResearchReportError, match="differs from RECORD SHA-256"):
        report_module._trusted_distribution_snapshot("sample")


def test_distribution_identity_rejects_record_size_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    content = b"trusted module\n"
    member = _recorded_member(
        tmp_path,
        "sample/module.py",
        content,
        record_sha256=_record_sha256(content),
        record_size=len(content) + 1,
    )
    distribution = _FakeDistribution(tmp_path, (member,))
    monkeypatch.setattr(
        report_module.importlib.metadata,
        "distribution",
        lambda _name: distribution,
    )

    with pytest.raises(ResearchReportError, match="differs from RECORD size"):
        report_module._trusted_distribution_snapshot("sample")


def test_linux_authority_evidence_excludes_interpreter_and_kernel_release() -> None:
    evidence = json.loads(
        (
            ROOT
            / "docs/report-toolchain-evidence/linux-x64/"
            "linux-x64-report-toolchain-evidence.json"
        ).read_bytes()
    )
    assert evidence["platform"] == {
        "machine": "x86_64",
        "system": "Linux",
        "target": "linux-x64",
    }
    source = (ROOT / "scripts/bootstrap_linux_x64_report_toolchain.py").read_text(
        encoding="utf-8"
    )
    assert "platform.release()" not in source
    assert "platform.python_version()" not in source
