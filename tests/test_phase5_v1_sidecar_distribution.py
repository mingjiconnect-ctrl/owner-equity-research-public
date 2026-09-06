from __future__ import annotations

import copy
import io
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_sidecar_distribution.py"))
SUPPLY_GENERATOR = runpy.run_path(
    str(ROOT / "sidecars/futu-opend/tools/generate_supply_artifacts.py")
)
VERIFY_WHEEL = VERIFIER["verify_wheel"]
VERIFY_SDIST = VERIFIER["verify_sdist"]
SOURCE_IDENTITY = VERIFIER["source_identity"]
DIST_INFO = VERIFIER["DIST_INFO"]
RECORD_NAME = f"{DIST_INFO}/RECORD"
CANONICAL_SOURCE_DATE_EPOCH = str(VERIFIER["FIXED_TAR_TIME"])


def test_private_project_license_is_explicit_without_relicensing_futu() -> None:
    sidecar = ROOT / "sidecars/futu-opend"
    project = tomllib.loads((sidecar / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["license"] == "LicenseRef-Owner-Research-Proprietary"
    license_text = (sidecar / "LICENSE").read_text(encoding="utf-8")
    normalized_license = " ".join(license_text.split())
    assert "No public, open-source, or implied license is granted" in normalized_license
    assert "does not relicense any third-party material" in normalized_license
    readme = (sidecar / "supply/README.md").read_text(encoding="utf-8")
    assert "must not be attached to a public GitHub Release" in readme

    sbom = json.loads((sidecar / "supply/sbom.cdx.json").read_bytes())
    assert sbom["metadata"]["component"]["licenses"] == [
        {"expression": "LicenseRef-Owner-Research-Proprietary"}
    ]
    futu = next(item for item in sbom["components"] if item["name"] == "futu-api")
    assert futu["licenses"] == [{"expression": "Apache-2.0"}]
    assert b"License-Expression: LicenseRef-Owner-Research-Proprietary\n" in VERIFIER[
        "EXPECTED_METADATA"
    ]


def test_supply_generator_uses_bounded_stable_nofollow_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read_budget = SUPPLY_GENERATOR["_ReadBudget"]
    read_json = SUPPLY_GENERATOR["_read_json"]
    source = tmp_path / "source.json"
    source.write_bytes(b'{"schema_version":"1.0.0"}')

    def forbidden(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("unbounded Path read is forbidden")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    budget = read_budget(maximum_members=1, maximum_bytes=64)
    value, raw = read_json(source, budget=budget)
    assert value == {"schema_version": "1.0.0"}
    assert raw == b'{"schema_version":"1.0.0"}'
    assert budget.consumed_members == 1
    assert budget.consumed_bytes == len(raw)
    assert budget.read(source).raw == raw
    assert budget.consumed_members == 1


def test_supply_generator_rejects_symlink_oversize_race_and_cumulative_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read_budget = SUPPLY_GENERATOR["_ReadBudget"]
    target = tmp_path / "target"
    target.write_bytes(b"safe")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="opened safely"):
        read_budget().read(link)

    oversized = tmp_path / "oversized"
    with oversized.open("wb") as handle:
        handle.truncate(17)
    with pytest.raises(ValueError, match="byte limit"):
        read_budget().read(oversized, maximum_bytes=16)

    raced = tmp_path / "raced"
    raced.write_bytes(b"before")
    original_read = SUPPLY_GENERATOR["os"].read
    changed = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, size)
        if chunk and not changed:
            changed = True
            raced.write_bytes(b"after!")
        return chunk

    monkeypatch.setattr(SUPPLY_GENERATOR["os"], "read", racing_read)
    with pytest.raises(ValueError, match="changed while being read"):
        read_budget().read(raced)
    monkeypatch.setattr(SUPPLY_GENERATOR["os"], "read", original_read)

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_bytes(b"1234")
    second.write_bytes(b"5678")
    budget = read_budget(maximum_members=2, maximum_bytes=7)
    assert budget.read(first).raw == b"1234"
    with pytest.raises(ValueError, match="cumulative byte budget"):
        budget.read(second)

    member_budget = read_budget(maximum_members=1, maximum_bytes=8)
    member_budget.read(first)
    with pytest.raises(ValueError, match="member-count budget"):
        member_budget.read(second)


@pytest.mark.parametrize("argument", ("--help", "--check", "--unknown"))
def test_supply_generator_rejects_arguments_without_writing(argument: str) -> None:
    generator = ROOT / "sidecars/futu-opend/tools/generate_supply_artifacts.py"
    generated = tuple(
        ROOT / "sidecars/futu-opend/supply" / name
        for name in (
            "provenance-build-definition-v1.json",
            "sbom.cdx.json",
            "sidecar-source-manifest-v1.json",
            "source-inputs-v1.json",
        )
    )
    before = {path: path.read_bytes() for path in generated}
    result = subprocess.run(
        (sys.executable, str(generator), argument),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "usage: generate_supply_artifacts.py\n"
    assert {path: path.read_bytes() for path in generated} == before


@pytest.fixture(scope="module")
def sidecar_distributions(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    output = tmp_path_factory.mktemp("futu-sidecar-distributions")
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = CANONICAL_SOURCE_DATE_EPOCH
    subprocess.run(
        (
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(output),
            str(ROOT / "sidecars/futu-opend"),
        ),
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    wheels = tuple(output.glob("*.whl"))
    sdists = tuple(output.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1
    assert VERIFY_WHEEL(wheels[0], source_root=ROOT) == ()
    assert VERIFY_SDIST(sdists[0], source_root=ROOT) == ()
    return wheels[0], sdists[0]


def _rebound_wheel(
    source: Path,
    destination: Path,
    replacements: dict[str, bytes],
    *,
    reordered: bool = False,
    mode_member: str | None = None,
) -> Path:
    with zipfile.ZipFile(source) as incoming:
        infos = [copy.copy(item) for item in incoming.infolist()]
        member_bytes = {item.filename: incoming.read(item) for item in incoming.infolist()}
    member_bytes.update(replacements)
    if reordered:
        infos[0], infos[1] = infos[1], infos[0]
    if mode_member is not None:
        item = next(info for info in infos if info.filename == mode_member)
        item.external_attr = (stat.S_IFREG | 0o600) << 16
    names = [item.filename for item in infos]
    member_bytes[RECORD_NAME] = VERIFIER["_record_bytes"](member_bytes, names)
    with zipfile.ZipFile(destination, "w") as outgoing:
        for item in infos:
            outgoing.writestr(item, member_bytes[item.filename])
    return destination


def _mutate_sdist(
    source: Path,
    destination: Path,
    *,
    mutate_name: str | None = None,
    reordered: bool = False,
    mode_name: str | None = None,
) -> Path:
    with tarfile.open(source, "r:gz") as incoming:
        entries = []
        for original in incoming.getmembers():
            extracted = incoming.extractfile(original)
            assert extracted is not None
            entries.append((copy.copy(original), extracted.read()))
    if reordered:
        entries[0], entries[1] = entries[1], entries[0]
    with tarfile.open(destination, "w:gz") as outgoing:
        for member, raw in entries:
            if member.name == mutate_name:
                raw += b"\n# rebound\n"
                member.size = len(raw)
            if member.name == mode_name:
                member.mode = 0o600
            outgoing.addfile(member, io.BytesIO(raw))
    return destination


def _copy_sidecar_source(destination: Path) -> None:
    shutil.copytree(ROOT / "sidecars/futu-opend", destination / "sidecars/futu-opend")
    shutil.copy2(ROOT / ".gitignore", destination / ".gitignore")


def test_sidecar_wheel_has_exact_three_entrypoints_and_no_private_runtime_data(
    sidecar_distributions: tuple[Path, Path],
) -> None:
    wheel, _sdist = sidecar_distributions
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        entrypoints = archive.read(f"{DIST_INFO}/entry_points.txt")
    assert entrypoints == VERIFIER["EXPECTED_ENTRY_POINTS"]
    assert "numpy==2.4.2; python_version < '3.14'" in VERIFIER[
        "EXPECTED_DEPENDENCIES"
    ]
    assert b"Requires-Dist: numpy==2.4.2; python_version < '3.14'\n" in VERIFIER[
        "EXPECTED_METADATA"
    ]
    assert len(names) <= VERIFIER["MAXIMUM_MEMBERS"]
    assert not any(
        part in {"raw", "credentials", "private-cas", "audit-output"}
        for name in names
        for part in Path(name).parts
    )


@pytest.mark.parametrize(
    "member",
    (
        "owner_research_futu_sidecar/opend_adapter.py",
        f"{DIST_INFO}/entry_points.txt",
        f"{DIST_INFO}/licenses/LICENSE",
    ),
)
def test_sidecar_wheel_rejects_module_or_entrypoint_tamper_with_rebound_record(
    sidecar_distributions: tuple[Path, Path],
    tmp_path: Path,
    member: str,
) -> None:
    wheel, _sdist = sidecar_distributions
    with zipfile.ZipFile(wheel) as archive:
        raw = archive.read(member) + b"\n# rebound\n"
    mutated = _rebound_wheel(
        wheel,
        tmp_path / f"rebound-{Path(member).name}.whl",
        {member: raw},
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    if member.endswith("entry_points.txt"):
        assert "entry points are not the exact closed interface" in errors
    else:
        assert f"member differs from trusted source bytes: {member}" in errors
    assert "RECORD hashes" not in errors


def test_sidecar_wheel_rejects_reordered_members_with_rebound_record(
    sidecar_distributions: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = sidecar_distributions
    mutated = _rebound_wheel(wheel, tmp_path / "reordered.whl", {}, reordered=True)
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert "inventory or order is not the exact trusted build" in errors
    assert "RECORD hashes" not in errors


def test_sidecar_wheel_rejects_member_mode_attack(
    sidecar_distributions: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = sidecar_distributions
    member = "owner_research_futu_sidecar/opend_adapter.py"
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "mode.whl",
        {},
        mode_member=member,
    )
    errors = "\n".join(VERIFY_WHEEL(mutated, source_root=ROOT))
    assert f"metadata is unsafe or drifted: {member}" in errors


def test_sidecar_sdist_rejects_source_tamper_order_and_mode(
    sidecar_distributions: tuple[Path, Path], tmp_path: Path
) -> None:
    _wheel, sdist = sidecar_distributions
    prefix = VERIFIER["SDIST_PREFIX"]
    member = prefix + "src/owner_research_futu_sidecar/opend_adapter.py"
    tampered = _mutate_sdist(sdist, tmp_path / "tampered.tar.gz", mutate_name=member)
    assert f"differs from trusted source bytes: {member}" in "\n".join(
        VERIFY_SDIST(tampered, source_root=ROOT)
    )
    reordered = _mutate_sdist(sdist, tmp_path / "reordered.tar.gz", reordered=True)
    assert "inventory or order is not the exact trusted build" in "\n".join(
        VERIFY_SDIST(reordered, source_root=ROOT)
    )
    mode = _mutate_sdist(sdist, tmp_path / "mode.tar.gz", mode_name=member)
    assert f"metadata is unsafe or drifted: {member}" in "\n".join(
        VERIFY_SDIST(mode, source_root=ROOT)
    )
    license_member = prefix + "LICENSE"
    license_tamper = _mutate_sdist(
        sdist,
        tmp_path / "license-tampered.tar.gz",
        mutate_name=license_member,
    )
    assert f"differs from trusted source bytes: {license_member}" in "\n".join(
        VERIFY_SDIST(license_tamper, source_root=ROOT)
    )


def test_sidecar_exact_commit_and_tree_ignore_rebound_worktree(
    sidecar_distributions: tuple[Path, Path], tmp_path: Path
) -> None:
    wheel, _sdist = sidecar_distributions
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    _copy_sidecar_source(trusted)
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
        ("git", "commit", "-q", "-m", "trusted sidecar source"),
        cwd=trusted,
        env=environment,
        check=True,
    )
    commit = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=trusted, text=True
    ).strip()
    _commit, tree = SOURCE_IDENTITY(trusted, commit)
    assert VERIFY_WHEEL(
        wheel,
        source_root=trusted,
        expected_commit=commit,
        expected_tree=tree,
    ) == ()
    assert "commit tree does not match expected tree" in "\n".join(
        VERIFY_WHEEL(
            wheel,
            source_root=trusted,
            expected_commit=commit,
            expected_tree="0" * 40,
        )
    )

    source = trusted / "sidecars/futu-opend/src/owner_research_futu_sidecar/opend_adapter.py"
    rebound = source.read_bytes() + b"\n# rebound worktree authority\n"
    source.write_bytes(rebound)
    mutated = _rebound_wheel(
        wheel,
        tmp_path / "worktree-rebound.whl",
        {"owner_research_futu_sidecar/opend_adapter.py": rebound},
    )
    errors = "\n".join(
        VERIFY_WHEEL(
            mutated,
            source_root=trusted,
            expected_commit=commit,
            expected_tree=tree,
        )
    )
    assert "member differs from trusted source bytes" in errors


def test_sidecar_wheel_exact_commit_rejects_metadata_mode_rebind(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    _copy_sidecar_source(trusted)
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
        ("git", "commit", "-q", "-m", "trusted sidecar wheel metadata"),
        cwd=trusted,
        env=environment,
        check=True,
    )
    regular_commit = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=trusted, text=True
    ).strip()
    VERIFIER["_source_projection"](trusted, expected_commit=regular_commit)

    candidate = tmp_path / "wheel-must-not-be-opened.whl"
    candidate.write_bytes(b"")
    for relative in (
        "sidecars/futu-opend/pyproject.toml",
        "sidecars/futu-opend/LICENSE",
        ".gitignore",
    ):
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
            _commit, tree = SOURCE_IDENTITY(trusted, rebound_commit)
            errors = "\n".join(
                VERIFY_WHEEL(
                    candidate,
                    source_root=trusted,
                    expected_commit=rebound_commit,
                    expected_tree=tree,
                )
            )
            assert f"not a 100644 regular blob: {relative}" in errors
