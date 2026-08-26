from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_phase4e1_research_bundle_builder import _completed_graph, _input_graph

import owner_research.research_bundle_artifacts as artifact_module
from owner_research.fingerprints import canonical_json
from owner_research.research_bundle_artifacts import (
    ARTIFACT_FILENAMES,
    RESEARCH_ARTIFACT_MEMBER_MAX_BYTES,
    ResearchBundleArtifactError,
    load_research_bundle_artifact_snapshot,
    load_research_bundle_artifacts,
    replay_research_bundle_artifact_snapshot,
    write_research_bundle_artifacts,
)
from owner_research.research_bundle_builder import (
    ResearchBundleBuildResult,
    build_research_bundle,
)


def _result(sample_payloads):
    graph = _input_graph(sample_payloads)
    result = build_research_bundle(graph, run_id=graph.manifests[0].run_id)
    return graph, result


def test_artifact_writer_round_trips_canonical_pair_through_contract_graph(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bundle"
    receipt = write_research_bundle_artifacts(
        graph,
        result,
        output_directory=output,
    )

    assert {item.name for item in output.iterdir()} == set(ARTIFACT_FILENAMES)
    assert receipt.output_directory == output.absolute()
    assert len(receipt.research_bundle_file_sha256) == 64
    assert len(receipt.run_manifest_file_sha256) == 64
    loaded = load_research_bundle_artifacts(output, graph=graph)
    assert loaded == result
    _completed_graph(graph, loaded).validate()
    for path, contract in (
        (receipt.research_bundle_path, result.bundle),
        (receipt.run_manifest_path, result.run_manifest),
    ):
        assert path.read_text("utf-8") == canonical_json(contract.to_dict()) + "\n"


def test_identical_replay_does_not_rewrite_artifacts(sample_payloads, tmp_path: Path) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bundle"
    first = write_research_bundle_artifacts(graph, result, output_directory=output)
    mtimes = {item.name: item.stat().st_mtime_ns for item in output.iterdir()}
    second = write_research_bundle_artifacts(graph, result, output_directory=output)

    assert first == second
    assert {item.name: item.stat().st_mtime_ns for item in output.iterdir()} == mtimes


def test_different_artifacts_require_explicit_safe_overwrite(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    changed_manifest = replace(
        result.run_manifest,
        output_artifact_hashes={
            **dict(result.run_manifest.output_artifact_hashes),
            "research-package.json": "7" * 64,
        },
    )
    changed = ResearchBundleBuildResult(
        bundle=result.bundle,
        run_manifest=changed_manifest,
    )
    changed_graph = replace(
        graph,
        manifests=(changed_manifest,),
    )
    with pytest.raises(ResearchBundleArtifactError, match="already exists"):
        write_research_bundle_artifacts(
            changed_graph,
            changed,
            output_directory=output,
        )
    receipt = write_research_bundle_artifacts(
        changed_graph,
        changed,
        output_directory=output,
        overwrite=True,
    )
    assert load_research_bundle_artifacts(output, graph=changed_graph) == changed
    assert receipt.run_manifest_file_sha256 != result.bundle.bundle_fingerprint


def test_writer_refuses_unexpected_entries_and_symlinks(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bundle"
    output.mkdir()
    (output / "unrelated.txt").write_text("preserve me", encoding="utf-8")
    with pytest.raises(ResearchBundleArtifactError, match="unexpected entries"):
        write_research_bundle_artifacts(
            graph,
            result,
            output_directory=output,
            overwrite=True,
        )
    assert (output / "unrelated.txt").read_text("utf-8") == "preserve me"

    symlink = tmp_path / "symlink-output"
    symlink.symlink_to(output, target_is_directory=True)
    with pytest.raises(ResearchBundleArtifactError, match="symlink"):
        write_research_bundle_artifacts(
            graph,
            result,
            output_directory=symlink,
        )

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ResearchBundleArtifactError, match="symlink"):
        write_research_bundle_artifacts(
            graph,
            result,
            output_directory=symlink_parent / "nested" / "bundle",
        )


def test_loader_rejects_noncanonical_tampered_or_incomplete_pair(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    bundle_path = output / "research-bundle.json"
    payload = json.loads(bundle_path.read_text("utf-8"))
    bundle_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ResearchBundleArtifactError, match="not canonically serialized"):
        load_research_bundle_artifacts(output, graph=graph)

    bundle_path.write_text(canonical_json(payload) + "\n", encoding="utf-8")
    (output / "run-manifest.json").unlink()
    with pytest.raises(ResearchBundleArtifactError, match="exactly"):
        load_research_bundle_artifacts(output, graph=graph)


def test_loader_and_idempotent_writer_bound_and_no_follow_existing_members(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bounded-bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    bundle = output / "research-bundle.json"
    bundle.unlink()
    external = tmp_path / "external.json"
    external.write_text(canonical_json(result.bundle.to_dict()) + "\n", encoding="utf-8")
    bundle.symlink_to(external)
    with pytest.raises(ResearchBundleArtifactError, match="safely readable"):
        load_research_bundle_artifacts(output, graph=graph)

    bundle.unlink()
    with bundle.open("wb") as stream:
        stream.truncate(RESEARCH_ARTIFACT_MEMBER_MAX_BYTES + 1)
    with pytest.raises(ResearchBundleArtifactError, match="byte limit"):
        load_research_bundle_artifacts(output, graph=graph)
    with pytest.raises(ResearchBundleArtifactError, match="byte limit"):
        write_research_bundle_artifacts(graph, result, output_directory=output)


def test_loader_rejects_member_identity_race(
    sample_payloads,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "racing-bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    bundle = output / "research-bundle.json"
    before = bundle.stat()
    original_read = os.read
    raced = False

    def racing_read(descriptor: int, size: int) -> bytes:
        nonlocal raced
        content = original_read(descriptor, size)
        if content and not raced:
            raced = True
            os.utime(
                bundle,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000),
            )
        return content

    monkeypatch.setattr(artifact_module.os, "read", racing_read)
    with pytest.raises(ResearchBundleArtifactError, match="changed while read"):
        load_research_bundle_artifacts(output, graph=graph)


def test_loader_callback_gates_the_same_descriptor_snapshot_before_read(
    sample_payloads,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "callback-bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    callback_active = False
    completed_members = 0
    observed: list[tuple[str, int]] = []
    original_read = artifact_module.os.read

    def guarded_read(descriptor: int, size: int) -> bytes:
        if completed_members < len(ARTIFACT_FILENAMES):
            assert callback_active
        return original_read(descriptor, size)

    def read_callback(path: Path, declared_size: int, reader) -> bytes:
        nonlocal callback_active, completed_members
        assert declared_size == path.stat().st_size
        observed.append((path.name, declared_size))
        callback_active = True
        try:
            return reader()
        finally:
            callback_active = False
            completed_members += 1

    monkeypatch.setattr(artifact_module.os, "read", guarded_read)
    loaded, snapshot = load_research_bundle_artifact_snapshot(
        output,
        graph=graph,
        read_callback=read_callback,
    )

    assert loaded == result
    assert [name for name, _ in observed] == sorted(ARTIFACT_FILENAMES)
    monkeypatch.setattr(
        artifact_module,
        "_read_artifact_snapshot",
        lambda *_args, **_kwargs: pytest.fail("captured replay reopened its source path"),
    )
    assert replay_research_bundle_artifact_snapshot(snapshot, graph=graph) == result


def test_loader_callback_can_reject_invocation_budget_before_any_member_read(
    sample_payloads,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "pre-read-budget-bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)

    def reject_before_read(_path: Path, _declared_size: int, _reader) -> bytes:
        raise ResearchBundleArtifactError("invocation budget exhausted before member read")

    monkeypatch.setattr(
        artifact_module.os,
        "read",
        lambda *_args, **_kwargs: pytest.fail("budget rejection occurred after a member read"),
    )
    with pytest.raises(ResearchBundleArtifactError, match="before member read"):
        load_research_bundle_artifact_snapshot(
            output,
            graph=graph,
            read_callback=reject_before_read,
        )


def test_failed_overwrite_restores_original_artifact_pair(
    sample_payloads,
    tmp_path: Path,
    monkeypatch,
) -> None:
    graph, result = _result(sample_payloads)
    output = tmp_path / "bundle"
    write_research_bundle_artifacts(graph, result, output_directory=output)
    original_bytes = {item.name: item.read_bytes() for item in output.iterdir()}
    changed_manifest = replace(
        result.run_manifest,
        output_artifact_hashes={
            **dict(result.run_manifest.output_artifact_hashes),
            "research-package.json": "7" * 64,
        },
    )
    changed = ResearchBundleBuildResult(result.bundle, changed_manifest)
    changed_graph = replace(graph, manifests=(changed_manifest,))
    original_rename = Path.rename

    def fail_staging_publish(path: Path, target: Path):
        if path.name.startswith(".bundle.staging-") and target == output:
            raise OSError("synthetic publish failure")
        return original_rename(path, target)

    monkeypatch.setattr(Path, "rename", fail_staging_publish)
    with pytest.raises(ResearchBundleArtifactError, match="publication failed"):
        write_research_bundle_artifacts(
            changed_graph,
            changed,
            output_directory=output,
            overwrite=True,
        )
    assert {item.name: item.read_bytes() for item in output.iterdir()} == original_bytes
    assert load_research_bundle_artifacts(output, graph=graph) == result


def test_writer_rejects_forged_complete_bundle_without_graph_support(
    sample_payloads,
    tmp_path: Path,
) -> None:
    graph, result = _result(sample_payloads)
    payload = result.bundle.to_dict()
    payload["status"] = "complete"
    payload["missing_evidence"] = []
    payload["bundle_fingerprint"] = "1" * 64
    forged_bundle = replace(
        result.bundle,
        status="complete",
        missing_evidence=(),
        bundle_fingerprint="1" * 64,
    )
    forged_manifest = replace(
        result.run_manifest,
        output_artifact_hashes={"research-bundle.json": "1" * 64},
    )
    with pytest.raises(ResearchBundleArtifactError, match="fingerprint|replay"):
        write_research_bundle_artifacts(
            replace(graph, manifests=(forged_manifest,)),
            ResearchBundleBuildResult(forged_bundle, forged_manifest),
            output_directory=tmp_path / "forged",
        )


def test_artifact_api_has_no_network_cli_report_or_publisher_side_effects() -> None:
    import owner_research

    assert owner_research.write_research_bundle_artifacts is write_research_bundle_artifacts
    assert owner_research.load_research_bundle_artifacts is load_research_bundle_artifacts
    for forbidden in (
        "publish_research_bundle",
        "render_research_bundle",
        "value_research_bundle",
        "score_research_bundle",
    ):
        assert not hasattr(owner_research, forbidden)
