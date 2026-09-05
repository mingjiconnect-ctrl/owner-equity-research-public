"""Atomic, deterministic Phase 4E-2 ResearchBundle artifact materialization."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from .contracts import ResearchBundle, RunManifest, contract_from_dict
from .fingerprints import canonical_json
from .research_bundle_builder import ResearchBundleBuildResult
from .research_bundle_policies import bundle_payload_sha256
from .validation import ContractGraph, ContractGraphError

ARTIFACT_FILENAMES = ("research-bundle.json", "run-manifest.json")
RESEARCH_ARTIFACT_MEMBER_MAX_BYTES = 64 * 1024 * 1024
RESEARCH_ARTIFACT_LOAD_MAX_BYTES = 256 * 1024 * 1024

ResearchArtifactReadCallback = Callable[
    [Path, int, Callable[[], bytes]],
    bytes,
]


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
    absolute = Path(path).expanduser().absolute()
    allowed_alias: Path | None = None
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        root_alias = Path(absolute.anchor) / absolute.parts[1]
        expected_target = Path("/private") / absolute.parts[1]
        try:
            alias_details = root_alias.lstat()
            alias_target = root_alias.resolve(strict=True)
        except OSError:
            pass
        else:
            if (
                stat.S_ISLNK(alias_details.st_mode)
                and alias_details.st_uid == 0
                and alias_target == expected_target
                and alias_target.is_dir()
            ):
                allowed_alias = root_alias
    for candidate in (absolute, *absolute.parents):
        if candidate.is_symlink() and candidate != allowed_alias:
            raise ResearchBundleArtifactError(
                "Artifact path cannot contain a symlink"
            )


def _fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_artifact_snapshot(
    path: Path,
    *,
    maximum_total_bytes: int = RESEARCH_ARTIFACT_LOAD_MAX_BYTES,
    read_callback: ResearchArtifactReadCallback | None = None,
) -> dict[str, bytes]:
    """Capture the exact pair once through stable no-follow descriptors."""

    if type(maximum_total_bytes) is not int or maximum_total_bytes < 0:
        raise ResearchBundleArtifactError("Artifact cumulative byte limit is invalid")
    _reject_symlink_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError as exc:
        raise ResearchBundleArtifactError(
            f"Artifact directory is not safely readable: {exc}"
        ) from exc
    try:
        before_directory = os.fstat(directory_fd)
        names = tuple(sorted(os.listdir(directory_fd)))
        unexpected = sorted(set(names) - set(ARTIFACT_FILENAMES))
        if unexpected:
            raise ResearchBundleArtifactError(
                f"Artifact output directory contains unexpected entries: {unexpected}"
            )
        if names != tuple(sorted(ARTIFACT_FILENAMES)):
            raise ResearchBundleArtifactError(
                "Artifact directory must contain exactly the Bundle and RunManifest"
            )
        contents: dict[str, bytes] = {}
        remaining = min(RESEARCH_ARTIFACT_LOAD_MAX_BYTES, maximum_total_bytes)
        for name in names:
            try:
                descriptor = os.open(
                    name,
                    flags & ~getattr(os, "O_DIRECTORY", 0),
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise ResearchBundleArtifactError(
                    f"Artifact member is not safely readable: {name}"
                ) from exc
            try:
                before = os.fstat(descriptor)
                maximum = min(RESEARCH_ARTIFACT_MEMBER_MAX_BYTES, remaining)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise ResearchBundleArtifactError(
                        f"Artifact member is unsafe: {name}"
                    )
                if before.st_size > RESEARCH_ARTIFACT_MEMBER_MAX_BYTES:
                    raise ResearchBundleArtifactError(
                        f"Artifact member exceeds its byte limit: {name}"
                    )
                if before.st_size > remaining:
                    raise ResearchBundleArtifactError(
                        "Artifact pair exceeds its cumulative byte limit"
                    )
                read_started = False

                def read_member(
                    *,
                    _name: str = name,
                    _descriptor: int = descriptor,
                    _maximum: int = maximum,
                ) -> bytes:
                    nonlocal read_started
                    if read_started:
                        raise ResearchBundleArtifactError(
                            f"Artifact member reader may be invoked only once: {_name}"
                        )
                    read_started = True
                    chunks: list[bytes] = []
                    consumed = 0
                    while True:
                        chunk = os.read(
                            _descriptor,
                            min(1024 * 1024, _maximum - consumed + 1),
                        )
                        if not chunk:
                            break
                        consumed += len(chunk)
                        if consumed > _maximum:
                            raise ResearchBundleArtifactError(
                                f"Artifact member exceeds its byte limit: {_name}"
                            )
                        chunks.append(chunk)
                    return b"".join(chunks)

                raw = (
                    read_member()
                    if read_callback is None
                    else read_callback(path / name, before.st_size, read_member)
                )
                if type(raw) is not bytes or not read_started:
                    raise ResearchBundleArtifactError(
                        f"Artifact read callback did not return the exact byte snapshot: {name}"
                    )
                consumed = len(raw)
                after = os.fstat(descriptor)
                identity = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    before.st_mode,
                    before.st_nlink,
                    before.st_uid,
                    before.st_gid,
                )
                if consumed != before.st_size or identity != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                    after.st_mode,
                    after.st_nlink,
                    after.st_uid,
                    after.st_gid,
                ):
                    raise ResearchBundleArtifactError(
                        f"Artifact member changed while read: {name}"
                    )
                contents[name] = raw
                remaining -= consumed
            finally:
                os.close(descriptor)
        after_directory = os.fstat(directory_fd)
        if tuple(sorted(os.listdir(directory_fd))) != names or (
            before_directory.st_dev,
            before_directory.st_ino,
            before_directory.st_mtime_ns,
            before_directory.st_ctime_ns,
            before_directory.st_mode,
            before_directory.st_uid,
            before_directory.st_gid,
        ) != (
            after_directory.st_dev,
            after_directory.st_ino,
            after_directory.st_mtime_ns,
            after_directory.st_ctime_ns,
            after_directory.st_mode,
            after_directory.st_uid,
            after_directory.st_gid,
        ):
            raise ResearchBundleArtifactError("Artifact directory changed while read")
        return contents
    finally:
        os.close(directory_fd)


def _matches(path: Path, contents: dict[str, bytes]) -> bool:
    observed = _read_artifact_snapshot(path)
    return observed == contents


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

    result, _ = load_research_bundle_artifact_snapshot(input_directory, graph=graph)
    return result


def load_research_bundle_artifact_snapshot(
    input_directory: Path,
    *,
    graph: ContractGraph,
    maximum_total_bytes: int = RESEARCH_ARTIFACT_LOAD_MAX_BYTES,
    read_callback: ResearchArtifactReadCallback | None = None,
) -> tuple[ResearchBundleBuildResult, dict[str, bytes]]:
    """Load and return the exact bounded byte snapshot used for typed replay."""

    source = Path(input_directory).expanduser().absolute()
    contents = _read_artifact_snapshot(
        source,
        maximum_total_bytes=maximum_total_bytes,
        read_callback=read_callback,
    )
    return replay_research_bundle_artifact_snapshot(contents, graph=graph), contents


def replay_research_bundle_artifact_snapshot(
    file_bytes: Mapping[str, bytes],
    *,
    graph: ContractGraph,
) -> ResearchBundleBuildResult:
    """Replay one already captured canonical pair without reopening its source path."""

    if type(graph) is not ContractGraph:
        raise ResearchBundleArtifactError("Artifact replay requires an exact ContractGraph")
    if set(file_bytes) != set(ARTIFACT_FILENAMES):
        raise ResearchBundleArtifactError(
            "Artifact snapshot must contain exactly the Bundle and RunManifest"
        )
    contents: dict[str, bytes] = {}
    total = 0
    for name in ARTIFACT_FILENAMES:
        raw = file_bytes[name]
        if type(raw) is not bytes or len(raw) > RESEARCH_ARTIFACT_MEMBER_MAX_BYTES:
            raise ResearchBundleArtifactError(
                f"Artifact snapshot member is untyped or exceeds its byte limit: {name}"
            )
        total += len(raw)
        if total > RESEARCH_ARTIFACT_LOAD_MAX_BYTES:
            raise ResearchBundleArtifactError(
                "Artifact snapshot exceeds its cumulative byte limit"
            )
        contents[name] = raw
    try:
        bundle_payload = json.loads(contents["research-bundle.json"].decode("utf-8"))
        manifest_payload = json.loads(contents["run-manifest.json"].decode("utf-8"))
        bundle = contract_from_dict("research-bundle", bundle_payload)
        manifest = contract_from_dict("run-manifest", manifest_payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ResearchBundleArtifactError(f"Artifact payload is invalid: {exc}") from exc
    if not isinstance(bundle, ResearchBundle) or not isinstance(manifest, RunManifest):
        raise ResearchBundleArtifactError("Artifact contract types are invalid")
    result = ResearchBundleBuildResult(bundle=bundle, run_manifest=manifest)
    _validate_result(graph, result)
    expected = _expected_contents(graph, result)
    if contents != expected:
        raise ResearchBundleArtifactError("Artifact JSON is not canonically serialized")
    return result
