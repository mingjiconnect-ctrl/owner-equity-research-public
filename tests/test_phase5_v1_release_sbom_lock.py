from __future__ import annotations

import copy
import hashlib
import json
import os
import runpy
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
NAMESPACE = runpy.run_path(str(ROOT / "scripts/assemble_release_artifacts.py"))
ERROR = NAMESPACE["ReleaseAssemblyError"]
AUTHORITY_PATHS = NAMESPACE["DEPENDENCY_SUPPLY_AUTHORITY_PATHS"]
ARTIFACT_ROLES = NAMESPACE["ARTIFACT_ROLES"]
LOAD_SOURCE = NAMESPACE["_release_source_metadata"]
BUILD_SBOM = NAMESPACE["_build_sbom"]
VERIFY_SBOM = NAMESPACE["_verify_sbom_closure"]


def _commit_authorities(
    tmp_path: Path,
    *,
    content_overrides: dict[str, bytes] | None = None,
    mode_overrides: dict[str, int] | None = None,
) -> tuple[Path, str, str]:
    repository = tmp_path / "source"
    for relative in (*AUTHORITY_PATHS, "plugins/owner-equity-research/.codex-plugin/plugin.json"):
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            (content_overrides or {}).get(relative, (ROOT / relative).read_bytes())
        )
        target.chmod((mode_overrides or {}).get(relative, 0o644))
    subprocess.run(("git", "init", "-q"), cwd=repository, check=True)
    subprocess.run(("git", "add", "-A"), cwd=repository, check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "release-sbom@example.invalid",
            "GIT_AUTHOR_NAME": "Release SBOM Test",
            "GIT_COMMITTER_EMAIL": "release-sbom@example.invalid",
            "GIT_COMMITTER_NAME": "Release SBOM Test",
        }
    )
    subprocess.run(
        ("git", "commit", "-q", "-m", "exact dependency authorities"),
        cwd=repository,
        check=True,
        env=environment,
    )
    commit = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()
    tree = subprocess.check_output(
        ("git", "rev-parse", "HEAD^{tree}"), cwd=repository, text=True
    ).strip()
    return repository, commit, tree


def _artifact_records() -> dict[str, dict[str, str]]:
    return {
        role: {"sha256": hashlib.sha256(f"release:{role}".encode()).hexdigest()}
        for role in ARTIFACT_ROLES
    }


def _sbom_case(tmp_path: Path, *, mode: str = "preview") -> tuple[dict[str, Any], dict[str, Any]]:
    repository, commit, tree = _commit_authorities(tmp_path)
    source = LOAD_SOURCE(repository, commit)
    sbom = BUILD_SBOM(
        source=source,
        commit=commit,
        tree=tree,
        artifact_by_role=_artifact_records(),
        assembled_at="2026-07-14T01:08:45Z",
        mode=mode,
    )
    return source, sbom


def _properties(component: dict[str, Any]) -> dict[str, str]:
    return {item["name"]: item["value"] for item in component["properties"]}


@pytest.mark.parametrize("mode", ("preview", "rc"))
def test_exact_commit_supply_emits_one_exact_library_and_artifact_graph(
    tmp_path: Path,
    mode: str,
) -> None:
    repository, commit, tree = _commit_authorities(tmp_path)
    # The checkout is not an authority: corrupt it after committing and prove the
    # commit-tree blobs still drive validation and SBOM construction.
    (repository / NAMESPACE["DEPENDENCY_LOCK_PATH"]).write_bytes(b"not-json\n")
    source = LOAD_SOURCE(repository, commit)
    sbom = BUILD_SBOM(
        source=source,
        commit=commit,
        tree=tree,
        artifact_by_role=_artifact_records(),
        assembled_at="2026-07-14T01:08:45Z",
        mode=mode,
    )
    VERIFY_SBOM(sbom, expected_sbom=sbom)

    components = sbom["components"]
    libraries = [item for item in components if item["type"] == "library"]
    files = [item for item in components if item["type"] == "file"]
    assert len(libraries) == len(source["supply"]["lock"]["components"])
    assert len({item["name"] for item in libraries}) == len(libraries)
    assert len(files) == len(source["supply"]["manifest"]["artifacts"]) + 1

    httpx = next(item for item in libraries if item["name"] == "httpx")
    assert httpx["version"] == "0.28.1"
    assert httpx["purl"] == "pkg:pypi/httpx@0.28.1"
    assert ">=0.27,<1" in _properties(httpx)["owner.dependency.requirements"]
    assert httpx["licenses"] == [{"expression": "BSD-3-Clause"}]

    file_references_by_library: dict[str, set[str]] = {}
    for component in files:
        values = _properties(component)
        file_references_by_library.setdefault(values["owner.artifact.component"], set()).add(
            component["bom-ref"]
        )
        assert json.loads(values["owner.artifact.target.kind"]) in {"sdist", "wheel"}
        assert json.loads(values["owner.artifact.target.python_targets"]) == [
            "3.11",
            "3.12",
            "3.13",
        ] or json.loads(values["owner.artifact.target.python_targets"]) in (
            ["3.11"],
            ["3.12"],
            ["3.13"],
        )
    edge_by_reference = {item["ref"]: set(item["dependsOn"]) for item in sbom["dependencies"]}
    for library in libraries:
        assert edge_by_reference[library["bom-ref"]] == file_references_by_library[
            library["name"]
        ]

    owner_direct = {
        f"pkg:pypi/{component['name']}@{component['version']}"
        for component in source["supply"]["lock"]["components"]
        if any(item["project"] == "owner" for item in component["requirements"])
    }
    owner_reference = next(
        item["bom-ref"]
        for item in components
        if item["type"] == "application" and item["bom-ref"].startswith("application:owner:")
    )
    assert edge_by_reference[owner_reference] == owner_direct

    metadata = _properties(sbom["metadata"])
    assert metadata["owner.release.mode"] == mode
    assert metadata["owner.source.commit"] == commit
    assert metadata["owner.source.tree"] == tree
    for relative, digest in source["supply"]["sha256_by_path"].items():
        if relative == NAMESPACE["DEPENDENCY_LOCK_PATH"]:
            assert metadata["owner.dependency.lock.sha256"] == digest
        elif relative == NAMESPACE["DEPENDENCY_SUPPLY_MANIFEST_PATH"]:
            assert metadata["owner.dependency.supply_manifest.sha256"] == digest
        elif relative == NAMESPACE["DEPENDENCY_SUPPLY_IDENTITY_PATH"]:
            assert metadata["owner.dependency.supply_identity.sha256"] == digest
        elif relative == NAMESPACE["DEPENDENCY_VALIDATOR_PATH"]:
            assert metadata["owner.dependency.validator.sha256"] == digest


def _rebind_component_reference(
    sbom: dict[str, Any],
    *,
    old: str,
    new: str,
) -> None:
    component = next(item for item in sbom["components"] if item["bom-ref"] == old)
    component["bom-ref"] = new
    component["purl"] = new
    for edge in sbom["dependencies"]:
        if edge["ref"] == old:
            edge["ref"] = new
        edge["dependsOn"] = sorted(new if item == old else item for item in edge["dependsOn"])
    sbom["components"].sort(key=lambda item: item["bom-ref"])
    sbom["dependencies"].sort(key=lambda item: item["ref"])


def _mutate_range_version(sbom: dict[str, Any]) -> None:
    old = "pkg:pypi/httpx@0.28.1"
    new = "pkg:pypi/httpx@>=0.27,<1"
    _rebind_component_reference(sbom, old=old, new=new)
    next(item for item in sbom["components"] if item["bom-ref"] == new)["version"] = (
        ">=0.27,<1"
    )


def _mutate_license(sbom: dict[str, Any]) -> None:
    next(item for item in sbom["components"] if item.get("name") == "httpx")["licenses"] = [
        {"expression": "MIT"}
    ]


def _mutate_artifact_hash(sbom: dict[str, Any]) -> None:
    component = next(item for item in sbom["components"] if item["type"] == "file")
    old = component["bom-ref"]
    digest = "0" * 64
    new = f"artifact:{digest}:{component['name']}"
    component["bom-ref"] = new
    component["hashes"][0]["content"] = digest
    for edge in sbom["dependencies"]:
        if edge["ref"] == old:
            edge["ref"] = new
        edge["dependsOn"] = sorted(new if item == old else item for item in edge["dependsOn"])
    sbom["components"].sort(key=lambda item: item["bom-ref"])
    sbom["dependencies"].sort(key=lambda item: item["ref"])


def _mutate_artifact_target(sbom: dict[str, Any]) -> None:
    component = next(item for item in sbom["components"] if item["type"] == "file")
    next(
        item
        for item in component["properties"]
        if item["name"] == "owner.artifact.target.python_targets"
    )["value"] = '["3.13"]'


def _mutate_dependency_edge(sbom: dict[str, Any]) -> None:
    edge = next(
        item
        for item in sbom["dependencies"]
        if item["ref"].startswith("application:owner:")
    )
    edge["dependsOn"] = edge["dependsOn"][1:]


def _mutate_metadata_binding(sbom: dict[str, Any]) -> None:
    replacements = {
        "owner.dependency.lock.sha256": "f" * 64,
        "owner.dependency.supply_identity.sha256": "e" * 64,
        "owner.dependency.supply_manifest.sha256": "d" * 64,
    }
    for item in sbom["metadata"]["properties"]:
        if item["name"] in replacements:
            item["value"] = replacements[item["name"]]
    sbom["serialNumber"] = "urn:uuid:00000000-0000-4000-8000-000000000000"


@pytest.mark.parametrize(
    "mutation",
    (
        _mutate_range_version,
        _mutate_license,
        _mutate_artifact_hash,
        _mutate_artifact_target,
        _mutate_dependency_edge,
        _mutate_metadata_binding,
    ),
    ids=(
        "range-version",
        "license",
        "artifact-hash",
        "artifact-target",
        "dependency-edge",
        "metadata-binding",
    ),
)
def test_exact_sbom_replay_rejects_coordinated_rebinding(
    tmp_path: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    _source, expected = _sbom_case(tmp_path)
    rebound = copy.deepcopy(expected)
    mutation(rebound)
    with pytest.raises(ERROR, match="SBOM|library"):
        VERIFY_SBOM(rebound, expected_sbom=expected)


def test_supply_authorities_must_be_regular_100644_commit_blobs(tmp_path: Path) -> None:
    repository, commit, _tree = _commit_authorities(
        tmp_path,
        mode_overrides={NAMESPACE["DEPENDENCY_VALIDATOR_PATH"]: 0o755},
    )
    with pytest.raises(ERROR, match="not a 100644 blob"):
        LOAD_SOURCE(repository, commit)


def test_release_supply_json_must_use_its_canonical_profile(tmp_path: Path) -> None:
    lock_path = NAMESPACE["DEPENDENCY_LOCK_PATH"]
    noncanonical = json.dumps(
        json.loads((ROOT / lock_path).read_bytes()), sort_keys=True, separators=(",", ":")
    ).encode() + b"\n"
    repository, commit, _tree = _commit_authorities(
        tmp_path,
        content_overrides={lock_path: noncanonical},
    )
    with pytest.raises(ERROR, match="not canonical dependency JSON"):
        LOAD_SOURCE(repository, commit)
