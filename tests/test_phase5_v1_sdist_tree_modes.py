from __future__ import annotations

import copy
import gzip
import io
import os
import runpy
import subprocess
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
ROOT_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_sdist.py"))
SIDECAR_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_sidecar_distribution.py"))
VERIFY_SIDECAR: Callable[..., tuple[str, ...]] = SIDECAR_VERIFIER["verify_sdist"]
ROOT_EXPECTED_PROJECTION = ROOT_VERIFIER["_expected_projection"]
ROOT_COMMIT_MODES = ROOT_VERIFIER["_validate_exact_commit_regular_blobs"]
SIDECAR_COMMIT_MODES = SIDECAR_VERIFIER["_validate_sdist_commit_regular_blobs"]
SIDECAR_PREFIX = SIDECAR_VERIFIER["SDIST_PREFIX"]
FIXED_TAR_TIME = SIDECAR_VERIFIER["FIXED_TAR_TIME"]

_GIT_ENVIRONMENT = {
    "GIT_AUTHOR_EMAIL": "supply-chain@example.invalid",
    "GIT_AUTHOR_NAME": "Supply Chain Test",
    "GIT_COMMITTER_EMAIL": "supply-chain@example.invalid",
    "GIT_COMMITTER_NAME": "Supply Chain Test",
}


def _commit(repository: Path, message: str) -> str:
    environment = os.environ.copy()
    environment.update(_GIT_ENVIRONMENT)
    subprocess.run(("git", "add", "-A"), cwd=repository, check=True)
    subprocess.run(
        ("git", "commit", "-q", "-m", message),
        cwd=repository,
        env=environment,
        check=True,
    )
    return subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()


def _new_repository(tmp_path: Path, relative: str) -> tuple[Path, Path, str]:
    repository = tmp_path / "trusted"
    repository.mkdir()
    subprocess.run(("git", "init", "-q"), cwd=repository, check=True)
    path = repository / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"trusted release source\n")
    path.chmod(0o644)
    return repository, path, _commit(repository, "trusted regular source")


@pytest.mark.parametrize("mutation", ("executable", "symlink"))
def test_root_sdist_exact_commit_rejects_mode_or_symlink_rebinding(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, source, regular_commit = _new_repository(tmp_path, "README.md")
    ROOT_COMMIT_MODES(repository, regular_commit, {"README.md"})
    if mutation == "executable":
        source.chmod(0o755)
    else:
        source.unlink()
        source.symlink_to("missing-trusted-source")
    rebound_commit = _commit(repository, f"{mutation} rebind")
    with pytest.raises(ValueError, match="not a 100644 regular blob: README.md"):
        ROOT_COMMIT_MODES(repository, rebound_commit, {"README.md"})


@pytest.mark.parametrize("mutation", ("executable", "symlink"))
def test_sidecar_sdist_exact_commit_rejects_mode_or_symlink_rebinding(
    tmp_path: Path,
    mutation: str,
) -> None:
    relative = "sidecars/futu-opend/launcher/launch-rootless.sh"
    repository, source, regular_commit = _new_repository(tmp_path, relative)
    projection = {"launcher/launch-rootless.sh": (b"trusted release source\n", 0o644)}
    SIDECAR_COMMIT_MODES(repository, regular_commit, projection)
    if mutation == "executable":
        source.chmod(0o755)
    else:
        source.unlink()
        source.symlink_to("missing-trusted-source")
    rebound_commit = _commit(repository, f"{mutation} rebind")
    with pytest.raises(ValueError, match="expected 100644 regular blob mode:.*launch-rootless"):
        SIDECAR_COMMIT_MODES(
            repository,
            rebound_commit,
            projection,
        )


def test_sidecar_sdist_exact_commit_accepts_a_path_pinned_as_executable(
    tmp_path: Path,
) -> None:
    relative = "sidecars/futu-opend/launcher/launch-rootless.sh"
    repository, source, _regular_commit = _new_repository(tmp_path, relative)
    source.chmod(0o755)
    executable_commit = _commit(repository, "trusted executable launcher")
    SIDECAR_COMMIT_MODES(
        repository,
        executable_commit,
        {"launcher/launch-rootless.sh": (b"trusted release source\n", 0o755)},
    )


def test_root_expected_commit_projection_invokes_the_tree_mode_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "root-integration"
    repository.mkdir()
    subprocess.run(("git", "init", "-q"), cwd=repository, check=True)
    members = {
        "src/owner_research/contracts.py": b"trusted module\n",
        "pyproject.toml": b"[project]\nname='test'\n",
        "README.md": b"trusted readme\n",
        ".gitignore": b"*.pyc\n",
    }
    members.update(
        {
            relative: b"trusted supply member\n"
            for relative in ROOT_EXPECTED_PROJECTION.__globals__["_SDIST_SUPPLY_MEMBERS"]
        }
    )
    for relative, raw in members.items():
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
    readme = repository / "README.md"
    readme.chmod(0o755)
    commit = _commit(repository, "executable readme rebind")

    globals_ = ROOT_EXPECTED_PROJECTION.__globals__
    monkeypatch.setitem(
        globals_,
        "_source_projection",
        lambda _root, *, expected_commit: (
            {"owner_research/contracts.py": members["src/owner_research/contracts.py"]},
            b"trusted metadata",
            members["pyproject.toml"],
        ),
    )
    monkeypatch.setitem(
        globals_,
        "_trusted_file",
        lambda _root, relative, *, expected_commit: members[relative],
    )
    with pytest.raises(ValueError, match="not a 100644 regular blob: README.md"):
        ROOT_EXPECTED_PROJECTION(repository, expected_commit=commit)


def test_sidecar_public_sdist_verifier_invokes_the_tree_mode_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = "sidecars/futu-opend/src/owner_research_futu_sidecar/__init__.py"
    repository, source, _regular_commit = _new_repository(tmp_path, relative)
    source.chmod(0o755)
    commit = _commit(repository, "executable sidecar rebind")
    tree = subprocess.check_output(
        ("git", "rev-parse", f"{commit}^{{tree}}"), cwd=repository, text=True
    ).strip()
    monkeypatch.setitem(
        VERIFY_SIDECAR.__globals__,
        "_source_projection",
        lambda _root, *, expected_commit: (
            {
                "src/owner_research_futu_sidecar/__init__.py": (
                    b"trusted release source\n",
                    0o644,
                )
            },
            b"trusted pyproject",
            tree,
        ),
    )
    errors = VERIFY_SIDECAR(
        tmp_path / "not-reached.tar.gz",
        source_root=repository,
        expected_commit=commit,
        expected_tree=tree,
    )
    assert "expected 100644 regular blob mode" in "\n".join(errors)


@pytest.fixture(scope="module")
def trusted_sidecar_sdist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("phase5-v1-sidecar-sdist-metadata")
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(FIXED_TAR_TIME)
    subprocess.run(
        (
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--outdir",
            str(destination),
            str(ROOT / "sidecars/futu-opend"),
        ),
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    archives = tuple(destination.glob("*.tar.gz"))
    assert len(archives) == 1
    assert VERIFY_SIDECAR(archives[0], source_root=ROOT) == ()
    return archives[0]


def _canonical_sidecar_gzip(payload: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=output,
        mtime=FIXED_TAR_TIME,
    ) as archive:
        archive.write(payload)
    return output.getvalue()


def _rewrite_member_type(source: Path, destination: Path, target: str) -> Path:
    with tarfile.open(source, "r:gz") as incoming:
        entries: list[tuple[tarfile.TarInfo, bytes]] = []
        for original in incoming.getmembers():
            extracted = incoming.extractfile(original)
            assert extracted is not None
            entries.append((copy.copy(original), extracted.read()))
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:", format=tarfile.USTAR_FORMAT) as outgoing:
        for member, raw in entries:
            if member.name == target:
                member.type = tarfile.AREGTYPE
            outgoing.addfile(member, io.BytesIO(raw))
    destination.write_bytes(_canonical_sidecar_gzip(payload.getvalue()))
    return destination


def _tar_octal_field(value: int) -> bytes:
    return f"{value:07o}\0".encode("ascii")


def _rewrite_device_field(
    source: Path,
    destination: Path,
    target: str,
    *,
    field_offset: int,
) -> Path:
    payload = bytearray(gzip.decompress(source.read_bytes()))
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        member = archive.getmember(target)
    header_start = member.offset
    payload[header_start + field_offset : header_start + field_offset + 8] = _tar_octal_field(1)
    checksum_start = header_start + 148
    payload[checksum_start : checksum_start + 8] = b" " * 8
    checksum = sum(payload[header_start : header_start + 512])
    payload[checksum_start : checksum_start + 8] = f"{checksum:06o}\0 ".encode("ascii")
    destination.write_bytes(_canonical_sidecar_gzip(bytes(payload)))
    return destination


def test_sidecar_sdist_rejects_oldstyle_regular_type_rebinding(
    trusted_sidecar_sdist: Path,
    tmp_path: Path,
) -> None:
    target = SIDECAR_PREFIX + "src/owner_research_futu_sidecar/__init__.py"
    rebound = _rewrite_member_type(
        trusted_sidecar_sdist,
        tmp_path / "aregtype.tar.gz",
        target,
    )
    errors = VERIFY_SIDECAR(rebound, source_root=ROOT)
    assert f"sidecar sdist member metadata is unsafe or drifted: {target}" in errors


@pytest.mark.parametrize("field_offset", (329, 337))
def test_sidecar_sdist_rejects_coordinated_device_field_rebinding(
    trusted_sidecar_sdist: Path,
    tmp_path: Path,
    field_offset: int,
) -> None:
    target = SIDECAR_PREFIX + "src/owner_research_futu_sidecar/__init__.py"
    rebound = _rewrite_device_field(
        trusted_sidecar_sdist,
        tmp_path / f"device-{field_offset}.tar.gz",
        target,
        field_offset=field_offset,
    )
    errors = VERIFY_SIDECAR(rebound, source_root=ROOT)
    assert f"sidecar sdist member metadata is unsafe or drifted: {target}" in errors
