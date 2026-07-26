"""Atomic, deterministic Phase 4E-2 ResearchBundle artifact materialization."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from .contracts import ResearchBundle, RunManifest, contract_from_dict
from .fingerprints import canonical_json
from .research_bundle_builder import ResearchBundleBuildResult
from .research_bundle_policies import bundle_payload_sha256
from .validation import ContractGraph, ContractGraphError

ARTIFACT_FILENAMES = ("research-bundle.json", "run-manifest.json")


class ResearchBundleArtifactError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResearchBundleArtifactResult:
    output_directory: Path
    research_bundle_path: Path
    run_manifest_path: Path
    research_bundle_file_sha256: str
    run_manifest_file_sha256: str


def _artifact_bytes(payload: dict[str, object]) -> bytes:
    return (canonical_json(payload) + "\n").encode("utf-8")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_result(
    graph: ContractGraph,
    result: ResearchBundleBuildResult,
) -> None:
    bundle = result.bundle
    manifest = result.run_manifest
    if bundle.run_id != manifest.run_id:
        raise ResearchBundleArtifactError("Bundle and RunManifest run IDs differ")
    if bundle.issuer_id != manifest.issuer_id:
        raise ResearchBundleArtifactError("Bundle and RunManifest issuers differ")
    if bundle.data_cutoff_date != manifest.data_cutoff_date:
        raise ResearchBundleArtifactError("Bundle and RunManifest cutoffs differ")
    if bundle.component_lock_sha256 != manifest.component_lock_sha256:
        raise ResearchBundleArtifactError("Bundle and RunManifest component locks differ")
    if manifest.output_artifact_hashes.get("research-bundle.json") != (
        bundle.bundle_fingerprint
    ):
        raise ResearchBundleArtifactError(
            "RunManifest does not bind the ResearchBundle fingerprint"
        )
    if bundle.bundle_fingerprint != bundle_payload_sha256(bundle.to_dict()):
        raise ResearchBundleArtifactError("ResearchBundle semantic fingerprint is invalid")
    if any(item.fingerprint != bundle.fingerprint for item in graph.research_bundles):
        raise ResearchBundleArtifactError(
            "ContractGraph contains a different ResearchBundle"
        )
    manifests = tuple(
        manifest if item.run_id == manifest.run_id else item for item in graph.manifests
    )
    if not any(item.run_id == manifest.run_id for item in graph.manifests):
        raise ResearchBundleArtifactError("RunManifest is absent from the ContractGraph")
    candidate_graph = replace(
        graph,
        manifests=manifests,
        research_bundles=(bundle,),
    )
    try:
        candidate_graph.validate()
    except ContractGraphError as exc:
        raise ResearchBundleArtifactError(
            f"Artifact pair does not replay in the ContractGraph: {exc}"
        ) from exc


def _expected_contents(
    graph: ContractGraph,
    result: ResearchBundleBuildResult,
) -> dict[str, bytes]:
    _validate_result(graph, result)
    return {
        "research-bundle.json": _artifact_bytes(result.bundle.to_dict()),
        "run-manifest.json": _artifact_bytes(result.run_manifest.to_dict()),
    }


def _ensure_safe_existing_directory(path: Path) -> None:
    if path.is_symlink():
        raise ResearchBundleArtifactError("Artifact output directory cannot be a symlink")
    if not path.is_dir():
        raise ResearchBundleArtifactError("Artifact output path is not a directory")
    entries = {item.name: item for item in path.iterdir()}
    unexpected = sorted(set(entries) - set(ARTIFACT_FILENAMES))
    if unexpected:
        raise ResearchBundleArtifactError(
            f"Artifact output directory contains unexpected entries: {unexpected}"
        )
    for item in entries.values():
        if item.is_symlink() or not item.is_file():
            raise ResearchBundleArtifactError(
                "Artifact output directory contains an unsafe entry"
            )


def _reject_symlink_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ResearchBundleArtifactError(
                "Artifact path cannot contain a symlink"
            )


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _matches(path: Path, contents: dict[str, bytes]) -> bool:
    _ensure_safe_existing_directory(path)
    if {item.name for item in path.iterdir()} != set(ARTIFACT_FILENAMES):
        return False
    return all((path / name).read_bytes() == content for name, content in contents.items())


def _write_staging(path: Path, contents: dict[str, bytes]) -> None:
    path.mkdir(mode=0o700)
    try:
        for name, content in contents.items():
            artifact = path / name
            with artifact.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        _fsync_directory(path)
    except Exception:
        shutil.rmtree(path, ignore_errors=True)
        raise


def _publish_directory(staging: Path, target: Path, *, overwrite: bool) -> None:
    parent = target.parent
    if not target.exists() and not target.is_symlink():
        staging.rename(target)
        _fsync_directory(parent)
        return
    _ensure_safe_existing_directory(target)
    if not overwrite:
        raise ResearchBundleArtifactError(
            "Artifact output already exists with different content"
        )
    backup = parent / f".{target.name}.backup-{uuid.uuid4().hex}"
    target.rename(backup)
    try:
        staging.rename(target)
    except Exception:
        backup.rename(target)
        _fsync_directory(parent)
        raise
    _fsync_directory(parent)
    for name in ARTIFACT_FILENAMES:
        artifact = backup / name
        if artifact.exists():
            artifact.unlink()
    backup.rmdir()
    _fsync_directory(parent)


def write_research_bundle_artifacts(
    graph: ContractGraph,
    result: ResearchBundleBuildResult,
    *,
    output_directory: Path,
    overwrite: bool = False,
) -> ResearchBundleArtifactResult:
    """Atomically materialize exactly two canonical JSON artifacts."""

    target = Path(output_directory).expanduser().absolute()
    if not target.name or target == target.parent:
        raise ResearchBundleArtifactError("Artifact output directory is unsafe")
    _reject_symlink_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_path(target)
    contents = _expected_contents(graph, result)
    if target.exists() or target.is_symlink():
        if _matches(target, contents):
            return _artifact_result(target, contents)
        if not overwrite:
            raise ResearchBundleArtifactError(
                "Artifact output already exists with different content"
            )
    staging = target.parent / f".{target.name}.staging-{uuid.uuid4().hex}"
    try:
        _write_staging(staging, contents)
        _publish_directory(staging, target, overwrite=overwrite)
    except OSError as exc:
        raise ResearchBundleArtifactError(
            f"Artifact publication failed: {exc}"
        ) from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return _artifact_result(target, contents)


def _artifact_result(
    output_directory: Path,
    contents: dict[str, bytes],
) -> ResearchBundleArtifactResult:
    return ResearchBundleArtifactResult(
        output_directory=output_directory,
        research_bundle_path=output_directory / "research-bundle.json",
        run_manifest_path=output_directory / "run-manifest.json",
        research_bundle_file_sha256=_sha256(contents["research-bundle.json"]),
        run_manifest_file_sha256=_sha256(contents["run-manifest.json"]),
    )


def load_research_bundle_artifacts(
    input_directory: Path,
    *,
    graph: ContractGraph,
) -> ResearchBundleBuildResult:
    """Load the exact artifact pair and recheck its internal binding."""

    source = Path(input_directory).expanduser().absolute()
    _reject_symlink_path(source)
    _ensure_safe_existing_directory(source)
    entries = {item.name for item in source.iterdir()}
    if entries != set(ARTIFACT_FILENAMES):
        raise ResearchBundleArtifactError(
            "Artifact directory must contain exactly the Bundle and RunManifest"
        )
    try:
        bundle_payload = json.loads((source / "research-bundle.json").read_text("utf-8"))
        manifest_payload = json.loads((source / "run-manifest.json").read_text("utf-8"))
        bundle = contract_from_dict("research-bundle", bundle_payload)
        manifest = contract_from_dict("run-manifest", manifest_payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ResearchBundleArtifactError(f"Artifact payload is invalid: {exc}") from exc
    if not isinstance(bundle, ResearchBundle) or not isinstance(manifest, RunManifest):
        raise ResearchBundleArtifactError("Artifact contract types are invalid")
    result = ResearchBundleBuildResult(bundle=bundle, run_manifest=manifest)
    _validate_result(graph, result)
    expected = _expected_contents(graph, result)
    if any((source / name).read_bytes() != content for name, content in expected.items()):
        raise ResearchBundleArtifactError("Artifact JSON is not canonically serialized")
    return result
