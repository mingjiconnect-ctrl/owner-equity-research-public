from __future__ import annotations

import hashlib
import itertools
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
NAMESPACE = runpy.run_path(str(ROOT / "scripts/assemble_release_artifacts.py"))
ASSEMBLE = NAMESPACE["assemble_release"]
ERROR = NAMESPACE["ReleaseAssemblyError"]
CANONICAL = NAMESPACE["canonical_json_bytes"]
ARTIFACT_ROLES = NAMESPACE["ARTIFACT_ROLES"]
PUBLIC_ARTIFACT_ROLES = NAMESPACE["PUBLIC_ARTIFACT_ROLES"]
GENERATED_PUBLIC_FILES = NAMESPACE["GENERATED_PUBLIC_FILES"]


def _source_repository(tmp_path: Path) -> tuple[Path, str, str]:
    source = tmp_path / "source"
    (source / "sidecars/futu-opend").mkdir(parents=True)
    (source / "plugins/owner-equity-research/.codex-plugin").mkdir(parents=True)
    (source / "pyproject.toml").write_bytes(
        (ROOT / "pyproject.toml")
        .read_bytes()
        .replace(b'version = "1.0.0.dev0"', b'version = "1.0.0rc1"', 1)
    )
    (source / "sidecars/futu-opend/pyproject.toml").write_bytes(
        (ROOT / "sidecars/futu-opend/pyproject.toml")
        .read_bytes()
        .replace(b'version = "1.0.0.dev0"', b'version = "1.0.0rc1"', 1)
    )
    for relative in NAMESPACE["DEPENDENCY_SUPPLY_AUTHORITY_PATHS"]:
        if relative in {"pyproject.toml", "sidecars/futu-opend/pyproject.toml"}:
            continue
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
        target.chmod(0o644)
    (source / "plugins/owner-equity-research/.codex-plugin/plugin.json").write_bytes(
        CANONICAL({"name": "owner-equity-research", "version": "1.0.0-rc.1"})
    )
    subprocess.run(("git", "init", "-q"), cwd=source, check=True)
    subprocess.run(("git", "add", "-A"), cwd=source, check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "release@example.invalid",
            "GIT_AUTHOR_NAME": "Release Test",
            "GIT_COMMITTER_EMAIL": "release@example.invalid",
            "GIT_COMMITTER_NAME": "Release Test",
        }
    )
    subprocess.run(
        ("git", "commit", "-q", "-m", "exact release source"),
        cwd=source,
        env=environment,
        check=True,
    )
    commit = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=source, text=True
    ).strip()
    tree = subprocess.check_output(
        ("git", "rev-parse", "HEAD^{tree}"), cwd=source, text=True
    ).strip()
    return source, commit, tree


def _artifacts(tmp_path: Path) -> dict[str, Path]:
    directory = tmp_path / "inputs"
    directory.mkdir()
    names = {
        "owner_wheel": "owner_equity_research-1.0.0rc1-py3-none-any.whl",
        "owner_sdist": "owner_equity_research-1.0.0rc1.tar.gz",
        "plugin_bundle": "owner-equity-research-plugin-1.0.0-rc.1.zip",
        "sidecar_wheel": "owner_research_futu_sidecar-1.0.0rc1-py3-none-any.whl",
        "sidecar_sdist": "owner_research_futu_sidecar-1.0.0rc1.tar.gz",
    }
    artifacts: dict[str, Path] = {}
    for role, name in names.items():
        path = directory / name
        path.write_bytes(f"verified-{role}\n".encode())
        artifacts[role] = path
    return artifacts


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    source, commit, tree = _source_repository(tmp_path)
    for name in (
        "ROOT_WHEEL_VERIFY",
        "ROOT_SDIST_VERIFY",
        "PLUGIN_VERIFY",
        "SIDECAR_WHEEL_VERIFY",
        "SIDECAR_SDIST_VERIFY",
    ):
        monkeypatch.setitem(ASSEMBLE.__globals__, name, lambda *_args, **_kwargs: ())
    monkeypatch.setitem(ASSEMBLE.__globals__, "_rc_readiness_blockers", lambda: ["preview"])
    return {
        "mode": "preview",
        "source_root": source,
        "expected_commit": commit,
        "expected_tree": tree,
        "output_directory": tmp_path / "release",
        "assembled_at": "2026-07-14T01:08:45Z",
        **_artifacts(tmp_path),
    }


def _expected_files(output: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in output.iterdir()}


def _canonical_names(kwargs: dict[str, Any]) -> dict[str, str]:
    source = NAMESPACE["_release_source_metadata"](
        kwargs["source_root"], kwargs["expected_commit"]
    )
    return NAMESPACE["_canonical_artifact_basenames"](source)


def _rewrite(path: Path, raw: bytes) -> None:
    path.chmod(0o644)
    path.write_bytes(raw)
    path.chmod(0o444)


def _remove_read_only_tree(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    for directory in (path, *(item for item in path.rglob("*") if item.is_dir())):
        directory.chmod(0o700)
    shutil.rmtree(path)


def _recompute_checksums(output: Path) -> None:
    values = {
        path.name: path.read_bytes()
        for path in output.iterdir()
        if path.name != "SHA256SUMS"
    }
    raw = "".join(
        f"{hashlib.sha256(values[name]).hexdigest()}  {name}\n" for name in sorted(values)
    ).encode("ascii")
    _rewrite(output / "SHA256SUMS", raw)


def _rebind_generated_indexes(output: Path) -> dict[str, bytes]:
    manifest = json.loads((output / "release-manifest.json").read_bytes())
    sbom_raw = (output / "sbom.cdx.json").read_bytes()
    sbom_record = next(
        item for item in manifest["artifacts"] if item["role"] == "public_sbom"
    )
    sbom_record["sha256"] = hashlib.sha256(sbom_raw).hexdigest()
    sbom_record["size"] = len(sbom_raw)
    _rewrite(output / "release-manifest.json", CANONICAL(manifest))
    _recompute_checksums(output)
    return _expected_files(output)


def test_exact_names_publish_and_strictly_reload_one_closed_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    real_reload = NAMESPACE["_strict_reload_release_directory"]
    calls = 0

    def counted_reload(*args: Any, **keywords: Any) -> None:
        nonlocal calls
        calls += 1
        real_reload(*args, **keywords)

    monkeypatch.setitem(ASSEMBLE.__globals__, "_strict_reload_release_directory", counted_reload)
    output = ASSEMBLE(**kwargs)
    assert calls == 1
    canonical_names = _canonical_names(kwargs)
    assert {path.name for path in output.iterdir()} == {
        *(canonical_names[role] for role in PUBLIC_ARTIFACT_ROLES),
        *GENERATED_PUBLIC_FILES,
    }
    assert stat.S_IMODE(output.stat().st_mode) == 0o555
    assert {stat.S_IMODE(path.stat().st_mode) for path in output.iterdir()} == {0o444}
    assert not tuple(output.parent.glob(".release.staging-*"))
    assert not tuple(output.parent.glob(".release.invalid-*"))
    real_reload(
        output,
        expected_files=_expected_files(output),
        canonical_names=canonical_names,
    )
    user_alias = tmp_path / "publication-user-alias"
    user_alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ERROR, match="unsafe"):
        real_reload(
            user_alias / output.name,
            expected_files=_expected_files(output),
            canonical_names=canonical_names,
        )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fixed root aliases only")
def test_fixed_tmp_alias_can_publish_and_strictly_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    output = Path("/tmp") / f"owner-release-{os.getpid()}-{tmp_path.name}"
    assert not output.exists()
    kwargs["output_directory"] = output
    try:
        published = ASSEMBLE(**kwargs)
        assert published == output
        NAMESPACE["_strict_reload_release_directory"](
            published,
            expected_files=_expected_files(published),
            canonical_names=_canonical_names(kwargs),
        )
    finally:
        _remove_read_only_tree(output)


def test_release_output_parent_rejects_nested_user_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    physical_parent = tmp_path / "physical-publication"
    nested_parent = physical_parent / "nested"
    nested_parent.mkdir(parents=True)
    user_alias = tmp_path / "publication-user-alias"
    user_alias.symlink_to(physical_parent, target_is_directory=True)
    kwargs["output_directory"] = user_alias / nested_parent.name / "release"

    with pytest.raises(ERROR, match="unsafe or unavailable"):
        ASSEMBLE(**kwargs)
    assert not (nested_parent / "release").exists()


@pytest.mark.parametrize("generated_name", GENERATED_PUBLIC_FILES)
def test_generated_names_cannot_replace_a_public_wheel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generated_name: str,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    kwargs["owner_wheel"] = tmp_path / generated_name
    with pytest.raises(ERROR, match="owner_wheel basename is not canonical"):
        ASSEMBLE(**kwargs)


@pytest.mark.parametrize("first,second", tuple(itertools.combinations(ARTIFACT_ROLES, 2)))
def test_artifact_roles_cannot_exchange_canonical_basenames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    first: str,
    second: str,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    kwargs[first], kwargs[second] = kwargs[second], kwargs[first]
    with pytest.raises(ERROR, match="basename is not canonical"):
        ASSEMBLE(**kwargs)


def test_atomic_publication_never_replaces_an_existing_target(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    target = tmp_path / "target"
    staging.mkdir()
    target.mkdir()
    (staging / "candidate").write_bytes(b"candidate")
    (target / "existing").write_bytes(b"existing")
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(FileExistsError):
            NAMESPACE["_rename_directory_noreplace"](
                descriptor,
                staging.name,
                target.name,
            )
    finally:
        os.close(descriptor)
    assert (staging / "candidate").read_bytes() == b"candidate"
    assert (target / "existing").read_bytes() == b"existing"


def test_parent_inode_rebind_fails_and_quarantines_only_the_bound_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    parent = tmp_path / "publication"
    parent.mkdir()
    kwargs["output_directory"] = parent / "release"
    moved_parent = tmp_path / "bound-publication"
    real_write = NAMESPACE["_write_file_at"]
    rebound = False

    def rebind_parent(directory_descriptor: int, name: str, raw: bytes) -> None:
        nonlocal rebound
        if not rebound:
            parent.rename(moved_parent)
            parent.mkdir()
            rebound = True
        real_write(directory_descriptor, name, raw)

    monkeypatch.setitem(ASSEMBLE.__globals__, "_write_file_at", rebind_parent)
    with pytest.raises(ERROR, match="parent"):
        ASSEMBLE(**kwargs)
    assert not (parent / "release").exists()
    assert not (moved_parent / "release").exists()
    assert len(tuple(moved_parent.glob(".release.invalid-*"))) == 1


def test_staging_cleanup_never_follows_a_rebound_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    parent = tmp_path / "publication"
    parent.mkdir()
    kwargs["output_directory"] = parent / "release"
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    marker = victim / "keep.txt"
    marker.write_bytes(b"do-not-touch")

    def rebound_write(_descriptor: int, _name: str, _raw: bytes) -> None:
        staging = next(parent.glob(".release.staging-*"))
        staging.rename(parent / ".moved-staging")
        os.symlink(victim, staging)
        raise OSError("forced staging failure")

    monkeypatch.setitem(ASSEMBLE.__globals__, "_write_file_at", rebound_write)
    with pytest.raises(OSError, match="forced staging failure"):
        ASSEMBLE(**kwargs)
    assert marker.read_bytes() == b"do-not-touch"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755
    assert not (parent / "release").exists()


def test_failed_final_reload_removes_requested_name_and_quarantines_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)

    def reject_reload(*_args: Any, **_kwargs: Any) -> None:
        raise ERROR("forced final reload failure")

    monkeypatch.setitem(
        ASSEMBLE.__globals__, "_strict_reload_release_directory", reject_reload
    )
    with pytest.raises(ERROR, match="forced final reload failure"):
        ASSEMBLE(**kwargs)
    assert not kwargs["output_directory"].exists()
    quarantines = tuple(tmp_path.glob(".release.invalid-*"))
    assert len(quarantines) == 1
    assert stat.S_IMODE(quarantines[0].stat().st_mode) == 0o700


def test_post_index_member_tamper_is_caught_before_successful_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    canonical_names = _canonical_names(kwargs)
    real_verify = NAMESPACE["_verify_reloaded_release_indexes"]

    def verify_then_tamper(*args: Any, **keywords: Any) -> None:
        real_verify(*args, **keywords)
        wheel = kwargs["output_directory"] / canonical_names["owner_wheel"]
        wheel.chmod(0o600)
        wheel.write_bytes(b"post-index-member-tamper")
        wheel.chmod(0o444)

    monkeypatch.setitem(
        ASSEMBLE.__globals__,
        "_verify_reloaded_release_indexes",
        verify_then_tamper,
    )
    with pytest.raises(ERROR, match="changed after index verification"):
        ASSEMBLE(**kwargs)
    assert not kwargs["output_directory"].exists()
    assert len(tuple(tmp_path.glob(".release.invalid-*"))) == 1


def test_quarantine_renames_while_verified_directory_descriptor_is_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = tmp_path / "release"
    release.mkdir()
    (release / "artifact").write_bytes(b"verified-release")
    release.chmod(0o555)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "marker").write_bytes(b"unrelated")
    moved = tmp_path / "moved-release"
    parent_descriptor = os.open(
        tmp_path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    expected_identity = NAMESPACE["_release_stat_identity"](release.lstat())
    real_close = os.close

    def swap_on_close(descriptor: int) -> None:
        if release.exists():
            release.rename(moved)
            victim.rename(release)
        real_close(descriptor)

    monkeypatch.setattr(NAMESPACE["os"], "close", swap_on_close)
    try:
        quarantine_name = NAMESPACE["_quarantine_published_directory_at"](
            parent_descriptor,
            release.name,
            expected_identity=expected_identity,
        )
    finally:
        real_close(parent_descriptor)
    quarantine = tmp_path / quarantine_name
    assert not release.exists()
    assert (quarantine / "artifact").read_bytes() == b"verified-release"
    assert (victim / "marker").read_bytes() == b"unrelated"
    assert not moved.exists()


@pytest.mark.parametrize("mutation", ("application_hash", "source_identity"))
def test_strict_reload_rejects_coordinated_sbom_semantic_rebinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    output = ASSEMBLE(**kwargs)
    canonical_names = _canonical_names(kwargs)
    manifest_before = json.loads((output / "release-manifest.json").read_bytes())
    expected_source = manifest_before["source"]
    expected_application_hashes = {
        "owner": hashlib.sha256(
            (output / canonical_names["owner_wheel"]).read_bytes()
        ).hexdigest(),
        "plugin": hashlib.sha256(
            (output / canonical_names["plugin_bundle"]).read_bytes()
        ).hexdigest(),
        "sidecar": next(
            item["sha256"]
            for item in manifest_before["private_canary_inputs"]
            if item["role"] == "sidecar_wheel"
        ),
    }
    output.chmod(0o755)
    sbom = json.loads((output / "sbom.cdx.json").read_bytes())
    if mutation == "application_hash":
        owner = next(
            item for item in sbom["components"] if item["bom-ref"].startswith("application:owner:")
        )
        owner["hashes"][0]["content"] = "0" * 64
    else:
        rebound_commit = "1" * 40
        rebound_tree = "2" * 40
        for component in sbom["components"]:
            if not component.get("bom-ref", "").startswith("application:"):
                continue
            for item in component["properties"]:
                if item["name"] == "owner.source.commit":
                    item["value"] = rebound_commit
                elif item["name"] == "owner.source.tree":
                    item["value"] = rebound_tree
        manifest = manifest_before
        manifest["source"] = {"commit": rebound_commit, "tree": rebound_tree}
        _rewrite(output / "release-manifest.json", CANONICAL(manifest))
    _rewrite(output / "sbom.cdx.json", CANONICAL(sbom))
    expected = _rebind_generated_indexes(output)
    output.chmod(0o555)
    with pytest.raises(ERROR, match="application hash|source identity"):
        NAMESPACE["_strict_reload_release_directory"](
            output,
            expected_files=expected,
            canonical_names=canonical_names,
            expected_source_identity=expected_source,
            expected_application_hashes=expected_application_hashes,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "extra",
        "missing",
        "file_mode",
        "hardlink",
        "symlink",
        "directory_mode",
        "artifact_bytes",
        "manifest_hash",
        "sbom_hash",
        "checksums",
    ),
)
def test_strict_final_reload_rejects_inventory_mode_and_index_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    kwargs = _case(tmp_path, monkeypatch)
    output = ASSEMBLE(**kwargs)
    canonical_names = _canonical_names(kwargs)
    expected = _expected_files(output)
    output.chmod(0o755)
    owner_name = canonical_names["owner_wheel"]
    if mutation == "extra":
        (output / "extra.bin").write_bytes(b"extra")
    elif mutation == "missing":
        (output / owner_name).unlink()
    elif mutation == "file_mode":
        (output / owner_name).chmod(0o644)
    elif mutation == "hardlink":
        (output / owner_name).unlink()
        os.link(output / canonical_names["plugin_bundle"], output / owner_name)
    elif mutation == "symlink":
        (output / owner_name).unlink()
        os.symlink(canonical_names["plugin_bundle"], output / owner_name)
    elif mutation == "directory_mode":
        pass
    elif mutation == "artifact_bytes":
        _rewrite(output / owner_name, b"rebound")
    elif mutation == "manifest_hash":
        manifest = json.loads((output / "release-manifest.json").read_bytes())
        manifest["artifacts"][0]["sha256"] = "0" * 64
        _rewrite(output / "release-manifest.json", CANONICAL(manifest))
        _recompute_checksums(output)
        expected = _expected_files(output)
    elif mutation == "sbom_hash":
        sbom = json.loads((output / "sbom.cdx.json").read_bytes())
        sbom["version"] = 2
        _rewrite(output / "sbom.cdx.json", CANONICAL(sbom))
        _recompute_checksums(output)
        expected = _expected_files(output)
    else:
        _rewrite(output / "SHA256SUMS", b"0" * 64 + b"  rebound\n")
        expected = _expected_files(output)
    if mutation != "directory_mode":
        output.chmod(0o555)
    with pytest.raises((ERROR, OSError)):
        NAMESPACE["_strict_reload_release_directory"](
            output,
            expected_files=expected,
            canonical_names=canonical_names,
        )
