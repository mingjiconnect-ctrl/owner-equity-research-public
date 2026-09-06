from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import owner_research.component_lock as component_lock_module
from owner_research import __version__
from owner_research.component_lock import (
    file_sha256,
    load_component_lock,
    verify_component_lock,
    verify_future_mapping_contract,
    verify_kernel_runtime_lock,
    verify_kernel_runtime_snapshot,
    verify_pr3_comprehensive_lock,
    verify_research_schema_lock,
)
from owner_research.fingerprints import canonical_sha256

ROOT = Path(__file__).parents[1]
PRIVATE_KERNEL_REPOSITORY = os.environ.get("OWNER_VALUATION_REPO")
FILE_SHA256_MAXIMUM_SIZE = 16 * 1024 * 1024


def test_component_lock_has_exact_pinned_identity() -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    assert set(lock) == {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel",
        "valuation_kernel_runtime",
    }
    assert lock["lock_version"] == "1.2.0"
    assert set(lock["owner_equity_research"]) == {
        "plugin_version",
        "public_schema_sha256",
        "pr3_comprehensive",
    }
    assert lock["owner_equity_research"]["plugin_version"] == "1.0.0-dev.0"
    assert __version__ == "1.0.0.dev0"
    pr3 = lock["owner_equity_research"]["pr3_comprehensive"]
    assert set(pr3) == {
        "manifest_version",
        "package_version",
        "extension_schema_sha256",
        "futu_authority_policy",
        "futu_resource_sha256",
        "kernel_schema_resource_sha256",
        "report_asset_sha256",
        "module_sha256",
    }
    assert pr3["manifest_version"] == "1.0.0"
    assert pr3["package_version"] == "1.0.0.dev0"
    assert pr3["futu_authority_policy"] == {
        "path": "resources/futu/market-authority-policy-v2.json",
        "sha256": "b41d2c8b169f7dc4e2fdd400d27e5aa93003437b9b7986111fe99e240abf7a74",
    }
    assert pr3["kernel_schema_resource_sha256"] == {
        "resources/phase5-v1-kernel-schemas/assumption-ledger.schema.json": (
            "2232642332dc6444c784e21746cbd16bf8d4cd74fc483a0a345d95f98fc97a7a"
        ),
        "resources/phase5-v1-kernel-schemas/fact-ledger.schema.json": (
            "55be5aadad21629db1cdbe7fce386656eb930b52af8644d1314ba7404e384706"
        ),
        "resources/phase5-v1-kernel-schemas/valuation-request.schema.json": (
            "67e991484943897585a79a8a1d3d0d52ebb36ec0ba4245cad9b17972877cca3d"
        ),
        "resources/phase5-v1-kernel-schemas/valuation-result.schema.json": (
            "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683"
        ),
    }
    kernel = lock["valuation_kernel"]
    assert kernel["repository"] == "mingjiconnect-ctrl/owner-valuation-kernel"
    assert kernel["tag"] == "v2.0.0-rc.2"
    assert kernel["annotated_tag_object"] == "4e19ce6a59bc4321ebcd368e807ed764f4e8abde"
    assert kernel["commit"] == "be9b0773d5a78f5f8a33ba982494512668df85fe"
    assert kernel["package_version"] == "2.0.0rc2"
    assert kernel["plugin_version"] == "2.0.0-rc.2"
    assert kernel["release_evidence"]["tag_ci_run_id"] == 29388946546
    authority = lock["market_access_authority"]
    assert authority["authority_version"] == "1.0.0"
    assert set(authority) == {
        "authority_version",
        "provider_registry",
        "calendar_registry",
        "security_identity_policy",
        "secret_policy",
        "adapter_code",
        "parser_code",
        "reviewed_file_provider",
        "authorization_consumption_store",
    }
    reviewed = authority["reviewed_file_provider"]
    assert reviewed["provider_id"] == "provider:human-reviewed-file"
    assert reviewed["authority_kind"] == "human_reviewed_file"
    assert reviewed["endpoint_id"] == "reviewed-file"
    store = authority["authorization_consumption_store"]
    assert store["policy_id"] == "handoff-global-filesystem-reservation"
    assert store["root_policy"] == "module_import_user_state_home"
    runtime = lock["valuation_kernel_runtime"]
    assert set(runtime) == {
        "authority_version",
        "runtime_authority",
        "materializer_code",
        "runner_code",
        "expected_release_wheel_sha256",
        "manifest_policy_id",
        "manifest_policy_version",
    }
    assert runtime["expected_release_wheel_sha256"] == (
        "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"
    )


def test_kernel_runtime_lock_binds_packaged_authority_and_code() -> None:
    result = verify_kernel_runtime_lock()
    assert result.ok, "\n".join(result.errors)


def test_pr3_comprehensive_lock_binds_source_projection() -> None:
    result = verify_pr3_comprehensive_lock(
        ROOT / "component-lock.json",
        repository_root=ROOT,
    )
    assert result.ok, "\n".join(result.errors)


def test_pr3_comprehensive_lock_rejects_manifest_drift(tmp_path: Path) -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    lock["owner_equity_research"]["pr3_comprehensive"]["module_sha256"][
        "workflow_cli.py"
    ] = "0" * 64
    drifted = tmp_path / "component-lock.json"
    drifted.write_text(json.dumps(lock), encoding="utf-8")
    result = verify_pr3_comprehensive_lock(drifted, repository_root=ROOT)
    assert not result.ok
    assert "module_sha256 map mismatch" in "\n".join(result.errors)


def test_runtime_compatibility_pins_preserve_kernel_and_schema_maps() -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    assert canonical_sha256(lock["market_access_authority"]) == (
        "637f038e4322f8c5f5bfae4b57ccb89f7a2e98ff98e8b9e211f39573003fa0f6"
    )
    assert canonical_sha256(lock["valuation_kernel"]) == (
        "45bd321a26673d46627d9a260d2fd699a994cc74cb1fb018282a20beee1e83ac"
    )
    assert canonical_sha256(lock["owner_equity_research"]["public_schema_sha256"]) == (
        "23c7b640337b6cae5e54881579d16ac9f298e67b0709661589f6528b891a75d4"
    )
    raw = (ROOT / "component-lock.json").read_bytes()
    start = raw.index(b'  "market_access_authority": {')
    end = raw.index(b'  "valuation_kernel_runtime": {')
    frozen_market_block = raw[start:end]
    assert len(frozen_market_block) == 2073
    assert hashlib.sha256(frozen_market_block).hexdigest() == (
        "097f7d75acd1b9f897af878dd4a7d2efdf4238ad4e10f28c9d1a26a91b8ce8da"
    )
    # The Darwin correction changes only the three pins of the same host module;
    # replay the accepted block to prove every other authority byte is preserved.
    assert frozen_market_block.count(
        b"f3a56e3f10facebf293ef24a4e7d4f4d2b74df57d7a65c888555dbc81f39009d"
    ) == 3
    accepted_market_block = frozen_market_block.replace(
        b"f3a56e3f10facebf293ef24a4e7d4f4d2b74df57d7a65c888555dbc81f39009d",
        b"b0a3fbe8076e8e061dc70f2cdafed1ac24d07649c9cda76ff2511d1719f04174",
    )
    assert hashlib.sha256(accepted_market_block).hexdigest() == (
        "70aee6f53ae941f70be39b8a6978577fe2e5a585985cd1a9670ea6e73dab2272"
    )


def test_kernel_runtime_lock_rejects_drift_and_duplicate_json_keys(tmp_path: Path) -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    lock["valuation_kernel_runtime"]["runner_code"]["sha256"] = "0" * 64
    drifted = tmp_path / "drifted.json"
    drifted.write_text(json.dumps(lock), encoding="utf-8")
    result = verify_kernel_runtime_lock(drifted)
    assert not result.ok
    assert "runner_code hash mismatch" in "\n".join(result.errors)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"lock_version":"1.2.0","lock_version":"9.9.9"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_component_lock(duplicate)

    symlink = tmp_path / "component-lock-link.json"
    symlink.symlink_to(ROOT / "component-lock.json")
    with pytest.raises(OSError):
        load_component_lock(symlink)

    shadowed = load_component_lock(ROOT / "component-lock.json")
    shadowed["shadow_runtime_authority"] = {"trusted": False}
    shadowed_path = tmp_path / "shadowed.json"
    shadowed_path.write_text(json.dumps(shadowed), encoding="utf-8")
    result = verify_kernel_runtime_lock(shadowed_path)
    assert not result.ok
    assert "top-level component-lock shape mismatch" in "\n".join(result.errors)


def test_file_sha256_accepts_only_one_bounded_regular_nofollow_file(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b'{"stable":true}\n')
    assert file_sha256(source) == hashlib.sha256(source.read_bytes()).hexdigest()

    symlink = tmp_path / "source-link.json"
    symlink.symlink_to(source)
    with pytest.raises(OSError):
        file_sha256(symlink)

    with pytest.raises(ValueError, match="bounded regular file"):
        file_sha256(tmp_path)

    oversized = tmp_path / "oversized.json"
    with oversized.open("wb") as handle:
        handle.truncate(FILE_SHA256_MAXIMUM_SIZE + 1)
    with pytest.raises(ValueError, match="bounded regular file"):
        file_sha256(oversized)


def test_file_sha256_rejects_growth_while_reading(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "growing.json"
    source.write_bytes(b"a" * (1024 * 1024 + 1))
    source_identity = (source.stat().st_dev, source.stat().st_ino)
    real_read = os.read
    changed = False

    def read_then_grow(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, size)
        details = os.fstat(descriptor)
        if chunk and not changed and (details.st_dev, details.st_ino) == source_identity:
            changed = True
            with source.open("ab") as handle:
                handle.write(b"b")
        return chunk

    monkeypatch.setattr(component_lock_module.os, "read", read_then_grow)
    with pytest.raises(ValueError, match="changed while being read"):
        file_sha256(source)


def test_file_sha256_rejects_path_replacement_while_reading(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "replaced.json"
    source.write_bytes(b"original")
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(b"replacement")
    source_identity = (source.stat().st_dev, source.stat().st_ino)
    real_read = os.read
    changed = False

    def read_then_replace(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = real_read(descriptor, size)
        details = os.fstat(descriptor)
        if chunk and not changed and (details.st_dev, details.st_ino) == source_identity:
            changed = True
            os.replace(replacement, source)
        return chunk

    monkeypatch.setattr(component_lock_module.os, "read", read_then_replace)
    with pytest.raises(ValueError, match="changed while being read"):
        file_sha256(source)


def test_pr3_snapshot_budget_gates_members_and_bytes_before_later_opens(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "members"
    source.mkdir()
    (source / "a.json").write_bytes(b"aa")
    (source / "b.json").write_bytes(b"bb")

    monkeypatch.setattr(component_lock_module, "_PR3_MAXIMUM_MEMBERS", 1)
    with pytest.raises(ValueError, match="member limit"):
        component_lock_module._collect_pr3_directory(
            source,
            "resources/test",
            component_lock_module._PR3ReadBudget(),
        )

    monkeypatch.setattr(component_lock_module, "_PR3_MAXIMUM_MEMBERS", 512)
    monkeypatch.setattr(component_lock_module, "_PR3_MAXIMUM_TOTAL_BYTES", 3)
    with pytest.raises(ValueError, match="cumulative byte limit"):
        component_lock_module._collect_pr3_directory(
            source,
            "resources/test",
            component_lock_module._PR3ReadBudget(),
        )


def test_component_lock_source_repo_reads_are_bounded_and_nofollow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    kernel = lock["valuation_kernel"]

    def fake_git(_repository: Path, *args: str) -> str:
        if args == ("rev-parse", "HEAD") or args == (
            "rev-parse",
            f'{kernel["tag"]}^{{}}',
        ):
            return kernel["commit"]
        if args == ("rev-parse", kernel["tag"]):
            return kernel["annotated_tag_object"]
        if args == ("cat-file", "-t", kernel["tag"]):
            return "tag"
        if args == ("status", "--porcelain"):
            return ""
        raise AssertionError(args)

    monkeypatch.setattr(component_lock_module, "_git", fake_git)
    monkeypatch.setattr(
        component_lock_module,
        "verify_kernel_runtime_lock",
        lambda *_args, **_kwargs: component_lock_module.VerificationResult(()),
    )
    monkeypatch.setattr(
        component_lock_module,
        "verify_pr3_comprehensive_lock",
        lambda *_args, **_kwargs: component_lock_module.VerificationResult(()),
    )

    project = tmp_path / "pyproject.toml"
    with project.open("wb") as stream:
        stream.truncate(FILE_SHA256_MAXIMUM_SIZE + 1)
    plugin = tmp_path / "plugins" / "owner-valuation" / ".codex-plugin" / "plugin.json"
    plugin.parent.mkdir(parents=True)
    outside = tmp_path / "outside-plugin.json"
    outside.write_text(json.dumps({"version": kernel["plugin_version"]}), encoding="utf-8")
    plugin.symlink_to(outside)

    result = verify_component_lock(ROOT / "component-lock.json", source_repo=tmp_path)
    joined = "\n".join(result.errors)
    assert "package version" in joined
    assert "plugin manifest is missing" in joined


def test_kernel_runtime_lock_rejects_alternate_authority_paths(tmp_path: Path) -> None:
    lock = load_component_lock(ROOT / "component-lock.json")
    lock["valuation_kernel_runtime"]["runtime_authority"]["path"] = (
        "resources/market_access/provider-registry.json"
    )
    path = tmp_path / "alternate.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    result = verify_kernel_runtime_lock(path)
    assert not result.ok
    assert "runtime_authority path is not the closed package member" in "\n".join(
        result.errors
    )


def test_kernel_runtime_snapshot_rejects_duplicate_lock_keys() -> None:
    package = ROOT / "src/owner_research"
    lock_bytes = (ROOT / "component-lock.json").read_bytes()
    duplicate = b'{"lock_version":"9.9.9",' + lock_bytes[1:]
    result = verify_kernel_runtime_snapshot(
        lock_bytes=duplicate,
        runtime_authority_bytes=(
            package
            / "resources/phase5-v1-kernel-runtime/runtime-authority.json"
        ).read_bytes(),
        materializer_bytes=(package / "valuation_kernel_materializer.py").read_bytes(),
        runner_bytes=(package / "valuation_pinned_kernel.py").read_bytes(),
    )
    assert not result.ok
    assert "duplicate JSON key" in "\n".join(result.errors)


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    (
        ("build", "backend", "unregistered.backend"),
        ("kernel", "schema_sha256", []),
        ("runtime", "python_minors", [[]]),
        ("container", "cap_drop", []),
    ),
)
def test_kernel_runtime_snapshot_rejects_joint_authority_and_lock_drift(
    section: str,
    field: str,
    replacement: object,
) -> None:
    package = ROOT / "src/owner_research"
    authority_path = (
        package / "resources/phase5-v1-kernel-runtime/runtime-authority.json"
    )
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    if section == "container":
        authority["runtime"]["container"][field] = replacement
    else:
        authority[section][field] = replacement
    authority_bytes = json.dumps(
        authority,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    lock = load_component_lock(ROOT / "component-lock.json")
    lock["valuation_kernel_runtime"]["runtime_authority"]["sha256"] = (
        hashlib.sha256(authority_bytes).hexdigest()
    )
    result = verify_kernel_runtime_snapshot(
        lock_bytes=json.dumps(
            lock,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        runtime_authority_bytes=authority_bytes,
        materializer_bytes=(package / "valuation_kernel_materializer.py").read_bytes(),
        runner_bytes=(package / "valuation_pinned_kernel.py").read_bytes(),
    )
    assert not result.ok
    assert "authority drifted from its closed 1.0.0 payload" in "\n".join(
        result.errors
    )


@pytest.mark.skipif(
    PRIVATE_KERNEL_REPOSITORY is None,
    reason="private kernel checkout is supplied only to authorized verification jobs",
)
def test_component_lock_matches_pinned_local_checkout() -> None:
    assert PRIVATE_KERNEL_REPOSITORY is not None
    kernel_repo = Path(PRIVATE_KERNEL_REPOSITORY)
    result = verify_component_lock(
        ROOT / "component-lock.json",
        source_repo=kernel_repo,
        require_clean=True,
        require_pinned_head=True,
    )
    assert result.ok, "\n".join(result.errors)


def test_component_lock_matches_research_schema_files() -> None:
    result = verify_research_schema_lock(ROOT / "component-lock.json", ROOT)
    assert result.ok, "\n".join(result.errors)


@pytest.mark.skipif(
    PRIVATE_KERNEL_REPOSITORY is None,
    reason="private kernel checkout is supplied only to authorized verification jobs",
)
def test_compatibility_fixture_uses_only_future_mappable_numeric_fields() -> None:
    fixture = json.loads(
        (ROOT / "evals" / "future-valuation-mapping.json").read_text(encoding="utf-8")
    )
    assert fixture["mapping_status"] == "IMPLEMENTED_PHASE_5B"
    assert fixture["eligible_fact"]["value_type"] == "number"
    assert fixture["target_schema"] == "fact-ledger.schema.json"
    assert PRIVATE_KERNEL_REPOSITORY is not None
    kernel_repo = Path(PRIVATE_KERNEL_REPOSITORY)
    result = verify_future_mapping_contract(
        ROOT / "evals" / "future-valuation-mapping.json",
        source_repo=kernel_repo,
    )
    assert result.ok, "\n".join(result.errors)
