from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import runpy
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from owner_research.component_lock import verify_pr3_comprehensive_lock

ROOT = Path(__file__).parents[1]
WHEEL_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_wheel.py"))
SDIST_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_sdist.py"))
VERIFY_WHEEL = WHEEL_VERIFIER["verify"]
VERIFY_SDIST = SDIST_VERIFIER["verify"]
DIST_INFO_STEM = WHEEL_VERIFIER["DIST_INFO_STEM"]
RECORD_NAME = f"{DIST_INFO_STEM}/RECORD"
CANONICAL_SOURCE_DATE_EPOCH = "1580601600"
TRUSTED_SOURCE_NAMES = (
    ".gitignore",
    "README.md",
    "component-lock.json",
    "extension_schemas",
    "plugins",
    "pyproject.toml",
    "schemas",
    "scripts",
    "src",
)


@pytest.fixture(scope="module")
def release_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    destination = tmp_path_factory.mktemp("phase5-v1-release-distributions")
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = CANONICAL_SOURCE_DATE_EPOCH
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(destination),
            str(ROOT),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    wheels = tuple(destination.glob("*.whl"))
    sdists = tuple(destination.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    assert VERIFY_WHEEL(wheels[0], source_root=ROOT) == ()
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", CANONICAL_SOURCE_DATE_EPOCH)
        assert VERIFY_SDIST(sdists[0], source_root=ROOT) == ()
    return wheels[0], sdists[0]


def _rebound_wheel(
    source: Path,
    destination: Path,
    replacements: dict[str, bytes],
    *,
    additions: tuple[tuple[str, bytes], ...] = (),
    reordered: bool = False,
    mode_member: str | None = None,
) -> Path:
    with zipfile.ZipFile(source) as incoming:
        infos = incoming.infolist()
        names = [item.filename for item in infos]
        member_bytes = {item.filename: incoming.read(item) for item in infos}
    member_bytes.update(replacements)
    names.extend(name for name, _raw in additions)
    member_bytes.update(additions)
    if reordered:
        names[0], names[1] = names[1], names[0]
    member_bytes[RECORD_NAME] = WHEEL_VERIFIER["_record_bytes"](member_bytes, names)
    with zipfile.ZipFile(destination, "w") as outgoing:
        by_name = {item.filename: item for item in infos}
        for name in names:
            item = by_name.get(name)
            if item is None:
                item = zipfile.ZipInfo(name)
            else:
                item = copy.copy(item)
            if name == mode_member:
                item.external_attr = (0o100600) << 16
            outgoing.writestr(item, member_bytes[name])
    return destination


def _mutate_sdist(source: Path, destination: Path, member_name: str) -> Path:
    with tarfile.open(source, "r:gz") as incoming, tarfile.open(destination, "w:gz") as outgoing:
        for original in incoming.getmembers():
            member = copy.copy(original)
            extracted = incoming.extractfile(original)
            assert extracted is not None
            raw = extracted.read()
            if member.name == member_name:
                raw += b"\n# rebound\n"
                member.size = len(raw)
            outgoing.addfile(member, io.BytesIO(raw))
    return destination


def _replace_sdist_member(
    source: Path,
    destination: Path,
    member_name: str,
    old: bytes,
    new: bytes,
) -> Path:
    with tarfile.open(source, "r:gz") as incoming, tarfile.open(destination, "w:gz") as outgoing:
        for original in incoming.getmembers():
            member = copy.copy(original)
            extracted = incoming.extractfile(original)
            assert extracted is not None
            raw = extracted.read()
            if member.name == member_name:
                assert old in raw
                raw = raw.replace(old, new, 1)
                member.size = len(raw)
            outgoing.addfile(member, io.BytesIO(raw))
    return destination


def _unrebound_wheel(source: Path, destination: Path, member_name: str, raw: bytes) -> Path:
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(destination, "w") as outgoing:
        for item in incoming.infolist():
            outgoing.writestr(item, raw if item.filename == member_name else incoming.read(item))
    return destination


def _copy_trusted_source(destination: Path) -> None:
    for name in TRUSTED_SOURCE_NAMES:
        source = ROOT / name
        target = destination / name
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)


def test_release_version_and_console_script_surface_is_development_only() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "1.0.0.dev0"
    assert project["dependencies"] == [
        "cryptography==50.0.0",
        "jsonschema>=4.23,<5",
        "httpx>=0.27,<1",
        "lxml>=5.3,<7",
        "pypdf==6.16.1",
        "pypdfium2==5.13.0",
    ]
    assert project["scripts"] == {
        "owner-equity-research": "owner_research.workflow_cli:main",
        "owner-research-validate": "owner_research.cli:main",
        "owner-research-valuation": "owner_research.valuation_cli:main",
    }
    plugin = json.loads(
        (ROOT / "plugins/owner-equity-research/.codex-plugin/plugin.json").read_bytes()
    )
    lock = json.loads((ROOT / "component-lock.json").read_bytes())
    assert plugin["version"] == "1.0.0-dev.0"
    assert lock["owner_equity_research"]["plugin_version"] == "1.0.0-dev.0"


@pytest.mark.parametrize(
    "replacement",
    (
        "",
        '  "cryptography==49.0.0",\n',
    ),
)
def test_source_projection_rejects_missing_or_tampered_crypto_dependency(
    tmp_path: Path, replacement: str
) -> None:
    _copy_trusted_source(tmp_path)
    project_path = tmp_path / "pyproject.toml"
    raw = project_path.read_text(encoding="utf-8")
    expected = '  "cryptography==50.0.0",\n'
    assert expected in raw
    project_path.write_text(raw.replace(expected, replacement, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="dependency inventory"):
        WHEEL_VERIFIER["_source_projection"](tmp_path, expected_commit=None)


def test_distributions_bind_the_pr3_policy_and_exclude_shadow_evals(
    release_artifacts: tuple[Path, Path],
) -> None:
    wheel, sdist = release_artifacts
    policy_member = "owner_research/resources/futu/market-authority-policy-v2.json"
    with zipfile.ZipFile(wheel) as archive:
        policy_raw = archive.read(policy_member)
        lock = json.loads(archive.read("owner_research/component-lock.json"))
    assert hashlib.sha256(policy_raw).hexdigest() == (
        "796126006627db64c0e9b3d0b8d7910b5c8cb375777e4a5da9991f65181dfd67"
    )
    assert lock["owner_equity_research"]["pr3_comprehensive"][
        "futu_authority_policy"
    ] == {
        "path": "resources/futu/market-authority-policy-v2.json",
        "sha256": "796126006627db64c0e9b3d0b8d7910b5c8cb375777e4a5da9991f65181dfd67",
    }
    with tarfile.open(sdist, "r:gz") as archive:
        names = {member.name for member in archive.getmembers()}
    prefix = "owner_equity_research-1.0.0.dev0/"
    assert prefix + "scripts/phase5e-futu-market-authority-policy-v2.json" in names
    assert not any(name.startswith(prefix + "evals/") for name in names)


def test_installed_package_projection_replays_the_pr3_component_lock(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(tmp_path)
    package_root = tmp_path / "owner_research"
    result = verify_pr3_comprehensive_lock(
        package_root / "component-lock.json",
        package_root=package_root,
    )
    assert result.ok, "\n".join(result.errors)
    (package_root / "resources/futu/unlocked-extra.json").write_text("{}", encoding="utf-8")
    drifted = verify_pr3_comprehensive_lock(
        package_root / "component-lock.json",
        package_root=package_root,
    )
    assert not drifted.ok
    assert "futu_resource_sha256 map mismatch" in "\n".join(drifted.errors)


def test_wheel_projection_rejects_coordinated_extra_kernel_schema_rebinding() -> None:
    projection, _metadata, _pyproject = WHEEL_VERIFIER["_source_projection"](
        ROOT,
        expected_commit=None,
    )
    projection = dict(projection)
    member = "owner_research/resources/phase5-v1-kernel-schemas/unapproved.schema.json"
    raw = b'{"$schema":"https://json-schema.org/draft/2020-12/schema"}'
    projection[member] = raw
    lock = json.loads(projection["owner_research/component-lock.json"])
    lock["owner_equity_research"]["pr3_comprehensive"][
        "kernel_schema_resource_sha256"
    ][member.removeprefix("owner_research/")] = hashlib.sha256(raw).hexdigest()
    projection["owner_research/component-lock.json"] = json.dumps(
        lock,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    errors = WHEEL_VERIFIER["_release_content_errors"](projection)

    assert "release kernel Schema resource inventory is not the pinned subset" in errors


@pytest.mark.parametrize(
    "member",
    (
        "owner_research/contracts.py",
        "owner_research/valuation_cli.py",
    ),
)
def test_wheel_rejects_source_or_cli_tamper_with_rebound_record(
    release_artifacts: tuple[Path, Path], tmp_path: Path, member: str
) -> None:
    wheel, _sdist = release_artifacts
    with zipfile.ZipFile(wheel) as archive:
        rebound_raw = archive.read(member) + b"\n# rebound\n"
    mutated = _rebound_wheel(
        wheel,
        tmp_path / f"rebound-{Path(member).name}.whl",
        {member: rebound_raw},
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert f"differs from trusted source bytes: {member}" in errors
    assert "RECORD" not in errors


@pytest.mark.parametrize(
    ("member", "old", "new", "expected"),
    (
        (
            f"{DIST_INFO_STEM}/entry_points.txt",
            b"owner_research.workflow_cli:main",
            b"owner_research.cli:main",
            "console entry points are not the exact closed interface",
        ),
        (
            f"{DIST_INFO_STEM}/METADATA",
            b"Version: 1.0.0.dev0",
            b"Version: 1.0.0rc1",
            "METADATA is not the exact trusted project metadata",
        ),
        (
            f"{DIST_INFO_STEM}/METADATA",
            b"Requires-Dist: cryptography==50.0.0\n",
            b"",
            "METADATA is not the exact trusted project metadata",
        ),
        (
            f"{DIST_INFO_STEM}/METADATA",
            b"Requires-Dist: cryptography==50.0.0",
            b"Requires-Dist: cryptography==49.0.0",
            "METADATA is not the exact trusted project metadata",
        ),
        (
            f"{DIST_INFO_STEM}/WHEEL",
            b"Generator: hatchling 1.27.0",
            b"Generator: rebound 9.9.9",
            "WHEEL metadata is not the exact trusted build identity",
        ),
    ),
)
def test_wheel_rejects_metadata_or_entrypoint_tamper_with_rebound_record(
    release_artifacts: tuple[Path, Path],
    tmp_path: Path,
    member: str,
    old: bytes,
    new: bytes,
    expected: str,
) -> None:
    wheel, _sdist = release_artifacts
    with zipfile.ZipFile(wheel) as archive:
        original = archive.read(member)
    assert old in original
    mutated = _rebound_wheel(
        wheel,
        tmp_path / f"rebound-{Path(member).name}.whl",
        {member: original.replace(old, new, 1)},
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert expected in errors
    assert "RECORD hashes" not in errors


def test_wheel_rejects_raw_futu_member_even_with_rebound_record(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    raw_member = "owner_research/resources/futu/raw/response.json"
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "raw-futu-rebound.whl",
        {},
        additions=((raw_member, b'{"account":"forbidden"}'),),
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert "member inventory is not the exact public projection" in errors
    assert "private-kernel, or generated runtime content" in errors
    assert "Futu resource inventory is not the closed public projection" in errors


def test_wheel_rejects_policy_and_lock_rebinding_with_rebound_record(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    policy_member = "owner_research/resources/futu/market-authority-policy-v2.json"
    lock_member = "owner_research/component-lock.json"
    with zipfile.ZipFile(wheel) as archive:
        policy_raw = archive.read(policy_member) + b"\n"
        lock = json.loads(archive.read(lock_member))
    lock["owner_equity_research"]["pr3_comprehensive"]["futu_authority_policy"][
        "sha256"
    ] = hashlib.sha256(policy_raw).hexdigest()
    rebound_lock = json.dumps(lock, separators=(",", ":"), sort_keys=True).encode()
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "policy-lock-record-rebound.whl",
        {policy_member: policy_raw, lock_member: rebound_lock},
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert (
        "wheel member differs from trusted source bytes: "
        "owner_research/resources/futu/market-authority-policy-v2.json"
    ) in errors
    assert (
        "wheel member differs from trusted source bytes: "
        "owner_research/component-lock.json"
    ) in errors
    assert f"differs from trusted source bytes: {policy_member}" in errors
    assert f"differs from trusted source bytes: {lock_member}" in errors


def test_wheel_rejects_record_hash_or_size_drift(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    member = "owner_research/contracts.py"
    with zipfile.ZipFile(wheel) as archive:
        raw = archive.read(member) + b"\n# record drift\n"
    mutated = _unrebound_wheel(wheel, tmp_path / "record-drift.whl", member, raw)
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert "RECORD hashes, sizes, order, or member set drifted" in errors


def test_wheel_rejects_reordered_members_with_fully_rebound_record(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "reordered-with-record.whl",
        {},
        reordered=True,
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert "member order is not the exact trusted build order" in errors
    assert "RECORD hashes" not in errors


def test_wheel_rejects_member_mode_attack_with_valid_record(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    member = "owner_research/contracts.py"
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "mode-with-record.whl",
        {},
        mode_member=member,
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert f"member metadata drifted from the trusted build: {member}" in errors
    assert "RECORD hashes" not in errors


def test_sdist_rejects_source_tamper(release_artifacts: tuple[Path, Path], tmp_path: Path) -> None:
    _wheel, sdist = release_artifacts
    member = "owner_equity_research-1.0.0.dev0/src/owner_research/contracts.py"
    mutated = _mutate_sdist(sdist, tmp_path / "rebound.tar.gz", member)
    errors = "\n".join(VERIFY_SDIST(mutated, source_root=ROOT))
    assert f"differs from trusted source bytes: {member}" in errors


@pytest.mark.parametrize(
    ("new"),
    (
        b"",
        b"Requires-Dist: cryptography==49.0.0\n",
    ),
)
def test_sdist_rejects_missing_or_tampered_crypto_dependency_metadata(
    release_artifacts: tuple[Path, Path], tmp_path: Path, new: bytes
) -> None:
    _wheel, sdist = release_artifacts
    member = "owner_equity_research-1.0.0.dev0/PKG-INFO"
    old = b"Requires-Dist: cryptography==50.0.0\n"
    mutated = _replace_sdist_member(
        sdist,
        tmp_path / f"crypto-metadata-{len(new)}.tar.gz",
        member,
        old,
        new,
    )
    errors = "\n".join(VERIFY_SDIST(mutated, source_root=ROOT))
    assert "PKG-INFO is not the exact trusted project metadata" in errors


def test_exact_commit_binding_ignores_a_rebound_worktree_authority(
    release_artifacts: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = release_artifacts
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    _copy_trusted_source(trusted)
    subprocess.run(("git", "init", "-q"), cwd=trusted, check=True)
    subprocess.run(("git", "add", "-A"), cwd=trusted, check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "supply-chain@example.invalid",
            "GIT_AUTHOR_NAME": "Supply Chain Test",
            "GIT_COMMITTER_EMAIL": "supply-chain@example.invalid",
            "GIT_COMMITTER_NAME": "Supply Chain Test",
        }
    )
    subprocess.run(
        ("git", "commit", "-q", "-m", "trusted projection"),
        cwd=trusted,
        env=environment,
        check=True,
    )
    commit = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=trusted, text=True).strip()
    assert VERIFY_WHEEL(wheel, source_root=trusted, expected_commit=commit) == ()

    source_member = trusted / "src/owner_research/contracts.py"
    rebound_raw = source_member.read_bytes() + b"\n# rebound authority\n"
    source_member.write_bytes(rebound_raw)
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "worktree-and-record-rebound.whl",
        {"owner_research/contracts.py": rebound_raw},
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=trusted, expected_commit=commit))
    assert "differs from trusted source bytes: owner_research/contracts.py" in errors


def test_root_wheel_exact_commit_rejects_metadata_mode_rebind(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    _copy_trusted_source(trusted)
    subprocess.run(("git", "init", "-q"), cwd=trusted, check=True)
    subprocess.run(("git", "add", "-A"), cwd=trusted, check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "supply-chain@example.invalid",
            "GIT_AUTHOR_NAME": "Supply Chain Test",
            "GIT_COMMITTER_EMAIL": "supply-chain@example.invalid",
            "GIT_COMMITTER_NAME": "Supply Chain Test",
        }
    )
    subprocess.run(
        ("git", "commit", "-q", "-m", "trusted wheel metadata"),
        cwd=trusted,
        env=environment,
        check=True,
    )
    regular_commit = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=trusted, text=True
    ).strip()
    WHEEL_VERIFIER["_source_projection"](trusted, expected_commit=regular_commit)

    candidate = tmp_path / "wheel-must-not-be-opened.whl"
    candidate.write_bytes(b"")
    for relative in ("pyproject.toml", "README.md"):
        object_id = subprocess.check_output(
            ("git", "rev-parse", f"{regular_commit}:{relative}"),
            cwd=trusted,
            text=True,
        ).strip()
        for mode in ("100755", "120000"):
            subprocess.run(("git", "read-tree", regular_commit), cwd=trusted, check=True)
            subprocess.run(
                ("git", "update-index", "--cacheinfo", f"{mode},{object_id},{relative}"),
                cwd=trusted,
                check=True,
            )
            subprocess.run(
                ("git", "commit", "-q", "-m", f"rebind {relative} as {mode}"),
                cwd=trusted,
                env=environment,
                check=True,
            )
            rebound_commit = subprocess.check_output(
                ("git", "rev-parse", "HEAD"), cwd=trusted, text=True
            ).strip()
            errors = "\n".join(
                VERIFY_WHEEL(candidate, source_root=trusted, expected_commit=rebound_commit)
            )
            assert f"not a 100644 regular blob: {relative}" in errors
