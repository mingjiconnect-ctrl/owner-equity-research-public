from __future__ import annotations

import copy
import importlib.util
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "phase5_v1_dependency_lock.py"

_SPEC = importlib.util.spec_from_file_location("phase5_v1_dependency_lock", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
dependency_lock = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(dependency_lock)


def _copy_release_supply_fixture(destination: Path) -> None:
    for relative in (
        "pyproject.toml",
        ".github/workflows/ci.yml",
        "sidecars/futu-opend/pyproject.toml",
        "sidecars/futu-opend/supply/dependency-lock-v1.json",
        "scripts/phase5_v1_dependency_lock.py",
        "scripts/phase5-v1-release-dependency-lock.json",
        "scripts/phase5-v1-reviewed-artifact-metadata.json",
        "scripts/phase5-v1-release-supply-manifest.json",
        "scripts/phase5-v1-release-supply-identity.json",
    ):
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o644)


def _canonical_write(path: Path, value: object) -> None:
    path.write_bytes(dependency_lock.canonical_bytes(value))


def _init_git_repository(path: Path) -> str:
    for command in (
        ("git", "init", "-q"),
        ("git", "config", "user.email", "tests@example.invalid"),
        ("git", "config", "user.name", "tests"),
        ("git", "add", "."),
        ("git", "commit", "-qm", "supply fixture"),
    ):
        subprocess.run(command, cwd=path, check=True)
    return subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=path, text=True).strip()


def _write_ci_lock(path: Path, entries: dict[tuple[str, str], set[str]]) -> None:
    lines = [
        f"{name}=={version} " + " ".join(f"--hash=sha256:{value}" for value in sorted(hashes))
        for (name, version), hashes in sorted(entries.items())
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o644)


def _manifest_direct_entries(manifest: dict[str, object]) -> dict[tuple[str, str], set[str]]:
    result: dict[tuple[str, str], set[str]] = {}
    for artifact in manifest["artifacts"]:  # type: ignore[index]
        key = (
            artifact["component"],  # type: ignore[index]
            dependency_lock._artifact_version_from_filename(artifact["filename"]),  # type: ignore[index]
        )
        result.setdefault(key, set()).add(artifact["sha256"])  # type: ignore[index]
    return result


def _write_derived_wheel(path: Path, *, metadata: bytes, license_bytes: bytes) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("futu_api-10.10.7008.dist-info/METADATA", metadata)
        archive.writestr("futu_api-10.10.7008.dist-info/licenses/LICENSE", license_bytes)
    path.chmod(0o644)
    return path.read_bytes()


def test_release_dependency_lock_has_closed_direct_runtime_inventory() -> None:
    identity = dependency_lock.validate_repository(ROOT)
    lock = dependency_lock._read_json(ROOT / dependency_lock.LOCK_RELATIVE_PATH)
    manifest = dependency_lock._read_json(ROOT / dependency_lock.MANIFEST_RELATIVE_PATH)

    assert lock["inventory_scope"] == "direct_runtime_only"
    assert lock["python_targets"] == ["3.11", "3.12", "3.13"]
    assert identity["lock_sha256"] == dependency_lock.canonical_sha256(lock)
    assert identity["supply_manifest_sha256"] == dependency_lock.canonical_sha256(manifest)
    assert manifest["lock_sha256"] == identity["lock_sha256"]
    assert manifest["artifacts"] == sorted(
        manifest["artifacts"],
        key=lambda item: (item["component"], item["filename"], item["sha256"]),
    )

    futu = next(item for item in manifest["artifacts"] if item["component"] == "futu-api")
    assert futu["filename"] == "futu_api-10.10.7008.tar.gz"
    assert futu["target"]["kind"] == "sdist"
    assert futu["derived_wheel"]["recipe"]["source_date_epoch"] == 1580601600
    assert futu["derived_wheel"]["sha256"] == (
        "5aa0c0cfae77213d5d16bf67426c28f53a76c1dc1273f8627fb87cd40d78168e"
    )

    for component in lock["components"]:
        assert component["license_expression"]
        assert component["license_evidence"]["record_id"]
        for artifact in component["artifacts"]:
            target = artifact["target"]
            assert target["python_targets"]
            if target["kind"] == "wheel":
                assert target["python_tags"] and target["abi_tags"] and target["platform_tags"]
    expressions = {item["name"]: item["license_expression"] for item in lock["components"]}
    assert expressions["cffi"] == "MIT-0"
    assert expressions["futu-api"] == "Apache-2.0"
    assert expressions["numpy"] == "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0"
    assert expressions["pycryptodome"] == "BSD-2-Clause AND Unlicense"
    assert expressions["simplejson"] == "MIT OR AFL-2.1"
    assert expressions["pypdfium2"] == (
        "BSD-3-Clause AND Apache-2.0 AND LicenseRef-pypdfium2-5.13.0-dependency-licenses"
    )
    metadata = dependency_lock._read_json(ROOT / dependency_lock.REVIEWED_METADATA_RELATIVE_PATH)
    pypdfium2 = next(item for item in metadata["records"] if item["component"] == "pypdfium2")
    assert pypdfium2["artifacts"][0]["metadata_license"] == (
        "License: BSD-3-Clause, Apache-2.0, dependency licenses"
    )
    # The exact 5.13.0 Linux wheel currently declares 19 License-File entries.
    assert len(pypdfium2["artifacts"][0]["license_files"]) == 19


def test_closed_specifier_marker_and_wheel_filename_evaluation() -> None:
    assert dependency_lock._satisfies_specifier("0.28.1", ">=0.27,<1")
    assert not dependency_lock._satisfies_specifier("1.0.0", ">=0.27,<1")
    assert dependency_lock._compare_versions("2.9.0", "2.9.0.post0") < 0
    assert dependency_lock._marker_applies("python_version < '3.14'", python_target="3.13")
    assert not dependency_lock._marker_applies("python_version < '3.13'", python_target="3.13")
    assert dependency_lock._marker_applies(
        "platform_python_implementation != 'PyPy'", python_target="3.11"
    )
    assert dependency_lock._marker_applies(
        "platform_python_implementation >= 'CPython'", python_target="3.11"
    )

    lock = dependency_lock._read_json(ROOT / dependency_lock.LOCK_RELATIVE_PATH)
    cffi = next(item for item in lock["components"] if item["name"] == "cffi")
    bad_name = copy.deepcopy(cffi["artifacts"][0])
    bad_name["filename"] = bad_name["filename"].replace("cffi", "other", 1)
    with pytest.raises(dependency_lock.DependencyLockError, match="normalized component name"):
        dependency_lock._validate_artifact(
            bad_name, component_name="cffi", component_version="2.1.1"
        )
    bad_version = copy.deepcopy(cffi["artifacts"][0])
    bad_version["filename"] = bad_version["filename"].replace("2.1.1", "2.1.2", 1)
    with pytest.raises(dependency_lock.DependencyLockError, match="name and version"):
        dependency_lock._validate_artifact(
            bad_version, component_name="cffi", component_version="2.1.1"
        )
    bad_tag = copy.deepcopy(cffi["artifacts"][0])
    bad_tag["target"]["python_targets"] = ["3.12"]
    with pytest.raises(dependency_lock.DependencyLockError, match="filename tags"):
        dependency_lock._validate_artifact(
            bad_tag, component_name="cffi", component_version="2.1.1"
        )
    with pytest.raises(dependency_lock.DependencyLockError, match="mixes CPython minor"):
        dependency_lock._wheel_target_from_filename(
            "cffi-2.1.1-cp311.cp312-cp311.cp312-manylinux_2_28_x86_64.whl"
        )
    with pytest.raises(dependency_lock.DependencyLockError, match="platform tags"):
        dependency_lock._wheel_target_from_filename(
            "cffi-2.1.1-cp311-cp311-manylinux_2_28_x86_64.win_amd64.whl"
        )


def test_validator_rejects_manifest_exchange_and_requirement_drift(tmp_path: Path) -> None:
    _copy_release_supply_fixture(tmp_path)
    manifest_path = tmp_path / dependency_lock.MANIFEST_RELATIVE_PATH
    manifest = dependency_lock._read_json(manifest_path)
    first, second = manifest["artifacts"][:2]
    first["sha256"], second["sha256"] = second["sha256"], first["sha256"]
    _canonical_write(manifest_path, manifest)
    with pytest.raises(dependency_lock.DependencyLockError, match="supply manifest"):
        dependency_lock.validate_repository(tmp_path)

    _copy_release_supply_fixture(tmp_path)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace("httpx>=0.27,<1", "httpx>=0.28,<1"),
        encoding="utf-8",
    )
    with pytest.raises(dependency_lock.DependencyLockError, match="requirements"):
        dependency_lock.validate_repository(tmp_path)

    _copy_release_supply_fixture(tmp_path)
    sidecar_lock = tmp_path / dependency_lock.SIDECAR_REVIEWED_LOCK_RELATIVE_PATH
    sidecar_lock.write_text(
        sidecar_lock.read_text(encoding="utf-8").replace('"license":"MIT-0"', '"license":"MIT"'),
        encoding="utf-8",
    )
    with pytest.raises(dependency_lock.DependencyLockError, match="sidecar reviewed lock bytes"):
        dependency_lock.validate_repository(tmp_path)


def test_validator_closes_project_and_ci_python_support(tmp_path: Path) -> None:
    _copy_release_supply_fixture(tmp_path)
    dependency_lock.validate_repository(tmp_path)

    root_project = tmp_path / "pyproject.toml"
    root_project.write_text(
        root_project.read_text(encoding="utf-8").replace(
            'requires-python = ">=3.11,<3.14"', 'requires-python = ">=3.11"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(dependency_lock.DependencyLockError, match="requires-python"):
        dependency_lock.validate_repository(tmp_path)

    _copy_release_supply_fixture(tmp_path)
    sidecar_project = tmp_path / "sidecars/futu-opend/pyproject.toml"
    sidecar_project.write_text(
        sidecar_project.read_text(encoding="utf-8").replace(
            'requires-python = ">=3.11,<3.14"', 'requires-python = ">=3.12,<3.14"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(dependency_lock.DependencyLockError, match="requires-python"):
        dependency_lock.validate_repository(tmp_path)

    _copy_release_supply_fixture(tmp_path)
    workflow = tmp_path / dependency_lock.CI_RELATIVE_PATH
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            'python-version: ["3.11", "3.12", "3.13"]',
            'python-version: ["3.11", "3.12", "3.13", "3.14"]',
        ),
        encoding="utf-8",
    )
    with pytest.raises(dependency_lock.DependencyLockError, match="CI Python matrix"):
        dependency_lock.validate_repository(tmp_path)

    _copy_release_supply_fixture(tmp_path)
    workflow = tmp_path / dependency_lock.CI_RELATIVE_PATH
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            'python-version: "3.11"',
            'python-version: "3.14"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(dependency_lock.DependencyLockError, match="CI Python matrix"):
        dependency_lock.validate_repository(tmp_path)


def test_ci_direct_lock_projection_is_exact_but_allows_other_dependencies(tmp_path: Path) -> None:
    manifest = dependency_lock._read_json(ROOT / dependency_lock.MANIFEST_RELATIVE_PATH)
    expected = _manifest_direct_entries(manifest)
    expected[("build", "1.3.0")] = {"a" * 64}
    lock_path = tmp_path / "supply.lock"
    _write_ci_lock(lock_path, expected)
    dependency_lock._validate_ci_lock_projection(manifest, ci_locks=[lock_path])

    rebound = copy.deepcopy(expected)
    direct_key = next(key for key in rebound if key[0] != "build")
    rebound[direct_key].add("b" * 64)
    _write_ci_lock(lock_path, rebound)
    with pytest.raises(dependency_lock.DependencyLockError, match="exactly equal manifest"):
        dependency_lock._validate_ci_lock_projection(manifest, ci_locks=[lock_path])

    extra_version = copy.deepcopy(expected)
    extra_version[(direct_key[0], "999.0.0")] = {"c" * 64}
    _write_ci_lock(lock_path, extra_version)
    with pytest.raises(dependency_lock.DependencyLockError, match="exactly equal manifest"):
        dependency_lock._validate_ci_lock_projection(manifest, ci_locks=[lock_path])


def test_validator_rejects_identity_rebinding_and_nonregular_git_modes(tmp_path: Path) -> None:
    _copy_release_supply_fixture(tmp_path)
    commit = _init_git_repository(tmp_path)
    dependency_lock.validate_repository(tmp_path, expected_git_commit=commit)

    lock_path = tmp_path / dependency_lock.LOCK_RELATIVE_PATH
    lock_path.chmod(0o755)
    with pytest.raises(dependency_lock.DependencyLockError, match="regular 0644"):
        dependency_lock.validate_repository(tmp_path, expected_git_commit=commit)
    lock_path.chmod(0o644)

    lock = dependency_lock._read_json(lock_path)
    metadata_path = tmp_path / dependency_lock.REVIEWED_METADATA_RELATIVE_PATH
    metadata = dependency_lock._read_json(metadata_path)
    record = next(item for item in metadata["records"] if item["component"] == "httpx")
    record["license_expression"] = "Apache-2.0 OR MIT"
    _canonical_write(metadata_path, metadata)
    httpx = next(item for item in lock["components"] if item["name"] == "httpx")
    httpx["license_expression"] = "Apache-2.0 OR MIT"
    httpx["license_evidence"]["record_sha256"] = dependency_lock.canonical_sha256(record)
    lock["reviewed_artifact_metadata"]["sha256"] = dependency_lock.file_sha256(metadata_path)
    _canonical_write(lock_path, lock)
    # Rebinding all in-repository hashes cannot alter a previously reviewed exact
    # commit: the validator compares mode and blob identity, not just JSON hashes.
    manifest = dependency_lock.expected_supply_manifest(
        lock, dependency_lock.validate_lock(lock, root=tmp_path)
    )
    _canonical_write(tmp_path / dependency_lock.MANIFEST_RELATIVE_PATH, manifest)
    identity = dependency_lock.expected_identity(tmp_path, lock=lock, manifest=manifest)
    _canonical_write(tmp_path / dependency_lock.IDENTITY_RELATIVE_PATH, identity)
    with pytest.raises(dependency_lock.DependencyLockError, match="expected Git blob"):
        dependency_lock.validate_repository(tmp_path, expected_git_commit=commit)


def test_ci_consumes_machine_readable_supply_validator() -> None:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["verify"]["steps"]
    matching = [
        step
        for step in steps
        if step.get("name") == "Validate the machine-readable direct-runtime supply identity"
    ]
    assert len(matching) == 1
    command = matching[0]["run"]
    assert "phase5_v1_dependency_lock.py validate" in command
    assert "--expected-git-commit" in command
    for job in ("verify", "semantic-audit"):
        prefetch = next(
            step["run"]
            for step in workflow["jobs"][job]["steps"]
            if step["name"].startswith("Prefetch and seal the exact")
        )
        assert "phase5_v1_dependency_lock.py" in prefetch
        assert "verify-artifacts" in prefetch
        assert "--downloaded-only" in prefetch
        assert "--ci-supply-lock \"$supply_lock\"" in prefetch
    workflow_source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert workflow_source.count('--derived-futu-wheel "$futu_wheel"') == 2
    assert workflow_source.count("--downloaded-only") == 2
    for job in ("verify", "semantic-audit"):
        job_source = "\n".join(
            step.get("run", "") for step in workflow["jobs"][job]["steps"]
        )
        derived_check = job_source.index('--derived-futu-wheel "$futu_wheel"')
        install = job_source.index(
            '"$sidecar_python" -I -m pip install',
            derived_check,
        )
        assert derived_check < install


def test_git_binding_rejects_symlink_rebind(tmp_path: Path) -> None:
    _copy_release_supply_fixture(tmp_path)
    commit = _init_git_repository(tmp_path)
    manifest_path = tmp_path / dependency_lock.MANIFEST_RELATIVE_PATH
    replacement = tmp_path / "replacement.json"
    shutil.copyfile(manifest_path, replacement)
    manifest_path.unlink()
    manifest_path.symlink_to(f"../{replacement.name}")
    assert stat.S_ISLNK(manifest_path.lstat().st_mode)
    with pytest.raises(dependency_lock.DependencyLockError, match="regular 0644"):
        dependency_lock.validate_repository(tmp_path, expected_git_commit=commit)


def test_authority_files_and_actual_wheel_metadata_cannot_be_rebound(tmp_path: Path) -> None:
    _copy_release_supply_fixture(tmp_path)
    commit = _init_git_repository(tmp_path)
    # Every authority, including the source requirements and sidecar reviewed
    # lock, is a no-follow exact-Git regular file.
    authority = tmp_path / "sidecars/futu-opend/pyproject.toml"
    authority.chmod(0o600)
    with pytest.raises(dependency_lock.DependencyLockError, match="regular 0644"):
        dependency_lock.validate_repository(tmp_path, expected_git_commit=commit)
    authority.chmod(0o644)

    metadata_path = "demo-1.0.0.dist-info/METADATA"
    license_path = "demo-1.0.0.dist-info/licenses/LICENSE"
    metadata = b"Name: demo\nVersion: 1.0.0\nLicense: MIT\n\n"
    license_bytes = b"MIT license\n"
    wheel = tmp_path / "demo-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(metadata_path, metadata)
        archive.writestr(license_path, license_bytes)
    record = {
        "component": "demo",
        "version": "1.0.0",
        "metadata_path": metadata_path,
        "metadata_sha256": dependency_lock.hashlib.sha256(metadata).hexdigest(),
        "metadata_license": "License: MIT",
        "license_file_headers": [],
        "license_files": [
            {
                "path": "licenses/LICENSE",
                "sha256": dependency_lock.hashlib.sha256(license_bytes).hexdigest(),
            }
        ],
    }
    dependency_lock._verify_wheel_metadata(wheel.read_bytes(), record=record)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(metadata_path, metadata.replace(b"MIT", b"Apache-2.0"))
        archive.writestr(license_path, license_bytes)
    with pytest.raises(dependency_lock.DependencyLockError, match="METADATA bytes"):
        dependency_lock._verify_wheel_metadata(wheel.read_bytes(), record=record)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(metadata_path, metadata)
        archive.writestr(license_path, b"rebound license\n")
    with pytest.raises(dependency_lock.DependencyLockError, match="License-File inventory"):
        dependency_lock._verify_wheel_metadata(wheel.read_bytes(), record=record)


def test_actual_derived_futu_wheel_is_fully_verified_before_install(tmp_path: Path) -> None:
    metadata_bytes = (
        b"Name: futu-api\n"
        b"Version: 10.10.7008\n"
        b"License: Apache License 2.0\n"
        b"License-File: LICENSE\n\n"
    )
    license_bytes = b"reviewed Apache license bytes\n"
    wheel = tmp_path / "futu_api-10.10.7008-py3-none-any.whl"
    raw = _write_derived_wheel(wheel, metadata=metadata_bytes, license_bytes=license_bytes)
    digest = dependency_lock.hashlib.sha256(raw).hexdigest()
    artifact_evidence = {
        "filename": wheel.name,
        "license_file_headers": ["LICENSE"],
        "license_files": [
            {
                "path": "licenses/LICENSE",
                "sha256": dependency_lock.hashlib.sha256(license_bytes).hexdigest(),
            }
        ],
        "metadata_license": "License: Apache License 2.0",
        "metadata_path": "futu_api-10.10.7008.dist-info/METADATA",
        "metadata_sha256": dependency_lock.hashlib.sha256(metadata_bytes).hexdigest(),
        "sha256": digest,
    }
    record = {
        "artifacts": [artifact_evidence],
        "component": "futu-api",
        "license_expression": "Apache-2.0",
        "record_id": "futu-api-derived-wheel@10.10.7008",
        "version": "10.10.7008",
    }
    manifest = {
        "artifacts": [
            {
                "component": "futu-api",
                "derived_wheel": {"filename": wheel.name, "sha256": digest},
                "filename": "futu_api-10.10.7008.tar.gz",
            }
        ]
    }
    reviewed = {record["record_id"]: record}
    assert dependency_lock._verify_derived_futu_wheel(
        wheel, manifest=manifest, metadata=reviewed
    ) == digest

    with pytest.raises(dependency_lock.DependencyLockError, match="cannot open sealed artifact"):
        dependency_lock._verify_derived_futu_wheel(
            tmp_path / "missing" / wheel.name,
            manifest=manifest,
            metadata=reviewed,
        )

    manifest["artifacts"][0]["derived_wheel"]["sha256"] = "0" * 64
    artifact_evidence["sha256"] = "0" * 64
    with pytest.raises(dependency_lock.DependencyLockError, match="actual Futu derived wheel hash"):
        dependency_lock._verify_derived_futu_wheel(
            wheel, manifest=manifest, metadata=reviewed
        )

    tampered_metadata = metadata_bytes.replace(b"Apache License 2.0", b"MIT               ")
    raw = _write_derived_wheel(
        wheel,
        metadata=tampered_metadata,
        license_bytes=license_bytes,
    )
    rebound_digest = dependency_lock.hashlib.sha256(raw).hexdigest()
    manifest["artifacts"][0]["derived_wheel"]["sha256"] = rebound_digest
    artifact_evidence["sha256"] = rebound_digest
    with pytest.raises(dependency_lock.DependencyLockError, match="METADATA bytes"):
        dependency_lock._verify_derived_futu_wheel(
            wheel, manifest=manifest, metadata=reviewed
        )

    tampered_license = b"rebound license bytes\n"
    raw = _write_derived_wheel(
        wheel,
        metadata=metadata_bytes,
        license_bytes=tampered_license,
    )
    rebound_digest = dependency_lock.hashlib.sha256(raw).hexdigest()
    manifest["artifacts"][0]["derived_wheel"]["sha256"] = rebound_digest
    artifact_evidence["sha256"] = rebound_digest
    with pytest.raises(dependency_lock.DependencyLockError, match="License-File inventory"):
        dependency_lock._verify_derived_futu_wheel(
            wheel, manifest=manifest, metadata=reviewed
        )


def test_verify_artifacts_cli_requires_explicit_downloaded_or_derived_mode(
    tmp_path: Path,
) -> None:
    base = [
        "verify-artifacts",
        "--repository",
        str(ROOT),
        "--wheelhouse",
        str(tmp_path),
        "--python-target",
        "3.11",
    ]
    assert dependency_lock.main(base) == 2
    assert dependency_lock.main(
        [*base, "--downloaded-only", "--derived-futu-wheel", str(tmp_path / "futu.whl")]
    ) == 2
