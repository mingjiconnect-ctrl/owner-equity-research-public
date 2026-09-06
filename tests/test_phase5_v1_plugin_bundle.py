from __future__ import annotations

import copy
import json
import os
import runpy
import shutil
import stat
import subprocess
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

ROOT = Path(__file__).parents[1]
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_plugin_bundle.py"))
BUILD_BUNDLE = VERIFIER["build_bundle"]
VERIFY_BUNDLE = VERIFIER["verify"]


def _rewrite_bundle(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    reordered: bool = False,
    mode_member: str | None = None,
    additions: int = 0,
    removals: set[str] | None = None,
) -> Path:
    with ZipFile(source) as incoming:
        infos = [
            copy.copy(item)
            for item in incoming.infolist()
            if item.filename not in (removals or set())
        ]
        payloads = {
            item.filename: incoming.read(item)
            for item in incoming.infolist()
            if item.filename not in (removals or set())
        }
    payloads.update(replacements or {})
    if reordered:
        infos[0], infos[1] = infos[1], infos[0]
    if mode_member is not None:
        info = next(item for item in infos if item.filename == mode_member)
        info.external_attr = (stat.S_IFREG | 0o600) << 16
    for index in range(additions):
        name = f"plugins/owner-equity-research/untrusted/member-{index:04d}.txt"
        info = ZipInfo(name, date_time=(2020, 2, 2, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = ZIP_DEFLATED
        infos.append(info)
        payloads[name] = b"x"
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as outgoing:
        for info in infos:
            outgoing.writestr(
                info,
                payloads[info.filename],
                compress_type=ZIP_DEFLATED,
                compresslevel=9,
            )
    return destination


def _copy_trusted_source(destination: Path) -> Path:
    plugin = destination / "plugins/owner-equity-research"
    plugin.parent.mkdir(parents=True)
    shutil.copytree(ROOT / "plugins/owner-equity-research", plugin)
    marketplace = destination / ".agents/plugins/marketplace.json"
    marketplace.parent.mkdir(parents=True)
    shutil.copy2(ROOT / ".agents/plugins/marketplace.json", marketplace)
    shutil.copy2(ROOT / "pyproject.toml", destination / "pyproject.toml")
    return destination


@pytest.fixture(scope="module")
def plugin_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("owner-equity-plugin") / "owner-equity-research.zip"
    BUILD_BUNDLE(output, source_root=ROOT)
    assert VERIFY_BUNDLE(output, source_root=ROOT) == ()
    return output


def test_plugin_bundle_contains_only_the_four_skill_surface(plugin_bundle: Path) -> None:
    with ZipFile(plugin_bundle) as archive:
        names = {item.filename for item in archive.infolist()}
    skills = {
        Path(name).parts[3]
        for name in names
        if name.endswith("/SKILL.md") and len(Path(name).parts) == 5
    }
    assert skills == {
        "owner-equity-research",
        "owner-quarterly-update",
        "owner-research-audit",
        "owner-research-publish",
    }
    assert ".agents/plugins/marketplace.json" in names
    assert not any("sidecars/" in name or "raw" in Path(name).parts for name in names)


def test_plugin_bundle_is_one_closed_version_bound_marketplace(
    plugin_bundle: Path,
) -> None:
    with ZipFile(plugin_bundle) as archive:
        marketplace = json.loads(archive.read(".agents/plugins/marketplace.json"))
        plugin = json.loads(
            archive.read(
                "plugins/owner-equity-research/.codex-plugin/plugin.json"
            )
        )
    assert marketplace == VERIFIER["EXPECTED_MARKETPLACE"]
    assert plugin["version"] == VERIFIER["_expected_plugin_version"](ROOT, None)


def test_plugin_bundle_rejects_missing_marketplace_manifest(
    plugin_bundle: Path,
    tmp_path: Path,
) -> None:
    mutated = _rewrite_bundle(
        plugin_bundle,
        tmp_path / "missing-marketplace.zip",
        removals={".agents/plugins/marketplace.json"},
    )
    assert "inventory or order differs from trusted source" in "\n".join(
        VERIFY_BUNDLE(mutated, source_root=ROOT)
    )


def test_plugin_source_rejects_marketplace_path_and_extra_plugin_rebinding(
    tmp_path: Path,
) -> None:
    path_source = _copy_trusted_source(tmp_path / "path-source")
    path_manifest = path_source / ".agents/plugins/marketplace.json"
    path_value = json.loads(path_manifest.read_bytes())
    path_value["plugins"][0]["source"]["path"] = "./plugins/rebound"
    path_manifest.write_text(json.dumps(path_value), encoding="utf-8")
    with pytest.raises(ValueError, match="marketplace name, path, policy"):
        VERIFIER["_projection"](path_source, None)

    extra_source = _copy_trusted_source(tmp_path / "extra-source")
    extra_manifest = extra_source / ".agents/plugins/marketplace.json"
    extra_value = json.loads(extra_manifest.read_bytes())
    rebound = copy.deepcopy(extra_value["plugins"][0])
    rebound["name"] = "rebound-plugin"
    rebound["source"]["path"] = "./plugins/rebound-plugin"
    extra_value["plugins"].append(rebound)
    extra_manifest.write_text(json.dumps(extra_value), encoding="utf-8")
    with pytest.raises(ValueError, match="closed inventory drifted"):
        VERIFIER["_projection"](extra_source, None)


def test_plugin_source_rejects_project_version_rebinding(tmp_path: Path) -> None:
    source = _copy_trusted_source(tmp_path / "version-source")
    manifest_path = source / "plugins/owner-equity-research/.codex-plugin/plugin.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["version"] = "1.0.0-rc.1"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="project-bound version"):
        VERIFIER["_projection"](source, None)


def test_plugin_bundle_rejects_skill_tamper_with_rebuilt_zip(
    plugin_bundle: Path,
    tmp_path: Path,
) -> None:
    member = "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md"
    with ZipFile(plugin_bundle) as incoming:
        rebound = incoming.read(member) + b"\n# rebound route\n"
    mutated = _rewrite_bundle(
        plugin_bundle,
        tmp_path / "rebound-plugin.zip",
        replacements={member: rebound},
    )
    errors = "\n".join(VERIFY_BUNDLE(mutated, source_root=ROOT))
    assert f"differs from trusted source bytes: {member}" in errors


def test_plugin_source_rejects_a_second_implicit_skill(tmp_path: Path) -> None:
    source = _copy_trusted_source(tmp_path / "source")
    plugin = source / "plugins/owner-equity-research"
    authority = plugin / "skills/owner-research-audit/agents/openai.yaml"
    authority.write_text(
        authority.read_text(encoding="utf-8").replace(
            "allow_implicit_invocation: false",
            "allow_implicit_invocation: true",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="implicit-routing policy"):
        VERIFIER["_projection"](source, None)


def test_plugin_bundle_rejects_reordered_members_and_mode_attack(
    plugin_bundle: Path,
    tmp_path: Path,
) -> None:
    reordered = _rewrite_bundle(
        plugin_bundle,
        tmp_path / "reordered-plugin.zip",
        reordered=True,
    )
    assert "inventory or order differs from trusted source" in "\n".join(
        VERIFY_BUNDLE(reordered, source_root=ROOT)
    )

    member = "plugins/owner-equity-research/.codex-plugin/plugin.json"
    mode_attack = _rewrite_bundle(
        plugin_bundle,
        tmp_path / "mode-plugin.zip",
        mode_member=member,
    )
    assert f"unsafe member: {member!r}" in "\n".join(
        VERIFY_BUNDLE(mode_attack, source_root=ROOT)
    )


def test_plugin_bundle_enforces_member_count_limit(
    plugin_bundle: Path,
    tmp_path: Path,
) -> None:
    additions = VERIFIER["MAXIMUM_MEMBERS"] - len(VERIFIER["_projection"](ROOT, None)) + 1
    oversized = _rewrite_bundle(
        plugin_bundle,
        tmp_path / "too-many-members.zip",
        additions=additions,
    )
    assert "exceeds the member-count limit" in "\n".join(
        VERIFY_BUNDLE(oversized, source_root=ROOT)
    )


def test_plugin_exact_commit_binding_ignores_rebound_worktree(tmp_path: Path) -> None:
    trusted = _copy_trusted_source(tmp_path / "trusted")
    plugin = trusted / "plugins/owner-equity-research"
    subprocess.run(("git", "init", "-q"), cwd=trusted, check=True)
    subprocess.run(("git", "add", "-A"), cwd=trusted, check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "plugin-supply@example.invalid",
            "GIT_AUTHOR_NAME": "Plugin Supply Test",
            "GIT_COMMITTER_EMAIL": "plugin-supply@example.invalid",
            "GIT_COMMITTER_NAME": "Plugin Supply Test",
        }
    )
    subprocess.run(
        ("git", "commit", "-q", "-m", "trusted plugin"),
        cwd=trusted,
        env=environment,
        check=True,
    )
    commit = subprocess.check_output(
        ("git", "rev-parse", "HEAD"), cwd=trusted, text=True
    ).strip()
    bundle = tmp_path / "commit-plugin.zip"
    BUILD_BUNDLE(bundle, source_root=trusted, expected_commit=commit)
    assert VERIFY_BUNDLE(bundle, source_root=trusted, expected_commit=commit) == ()

    source_member = plugin / "skills/owner-equity-research/SKILL.md"
    rebound = source_member.read_bytes() + b"\n# rebound worktree\n"
    source_member.write_bytes(rebound)
    member = "plugins/owner-equity-research/skills/owner-equity-research/SKILL.md"
    mutated = _rewrite_bundle(
        bundle,
        tmp_path / "commit-rebound-plugin.zip",
        replacements={member: rebound},
    )
    errors = "\n".join(
        VERIFY_BUNDLE(mutated, source_root=trusted, expected_commit=commit)
    )
    assert f"differs from trusted source bytes: {member}" in errors


def test_plugin_bundle_installs_in_clean_codex_0_139_0_home(
    plugin_bundle: Path,
    tmp_path: Path,
) -> None:
    codex = shutil.which("codex")
    if codex is None:
        pytest.skip("Codex CLI is not installed in this verification environment")
    version = subprocess.run(
        (codex, "--version"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if version != "codex-cli 0.139.0":
        pytest.skip(f"Codex 0.139.0 compatibility smoke requires 0.139.0, found {version}")

    release_root = tmp_path / "release-plugin"
    release_root.mkdir()
    with ZipFile(plugin_bundle) as archive:
        archive.extractall(release_root)
    clean_home = tmp_path / "clean-home"
    clean_home.mkdir(mode=0o700)
    codex_home = clean_home / ".codex"
    codex_home.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment["HOME"] = str(clean_home)
    environment["CODEX_HOME"] = str(codex_home)

    def run_codex(*arguments: str) -> dict | list:
        completed = subprocess.run(
            (codex, *arguments),
            cwd=tmp_path,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    marketplace = run_codex(
        "plugin",
        "marketplace",
        "add",
        str(release_root),
        "--json",
    )
    assert marketplace["marketplaceName"] == VERIFIER["MARKETPLACE_NAME"]
    installed = run_codex(
        "plugin",
        "add",
        f"owner-equity-research@{VERIFIER['MARKETPLACE_NAME']}",
        "--json",
    )
    expected_version = VERIFIER["_expected_plugin_version"](ROOT, None)
    assert installed == {
        "pluginId": f"owner-equity-research@{VERIFIER['MARKETPLACE_NAME']}",
        "name": "owner-equity-research",
        "marketplaceName": VERIFIER["MARKETPLACE_NAME"],
        "version": expected_version,
        "installedPath": installed["installedPath"],
        "authPolicy": "ON_INSTALL",
    }
    plugin_list = run_codex("plugin", "list", "--json")
    assert len(plugin_list["installed"]) == 1
    assert plugin_list["installed"][0]["pluginId"] == installed["pluginId"]
    assert plugin_list["installed"][0]["version"] == expected_version
    assert plugin_list["installed"][0]["authPolicy"] == "ON_INSTALL"

    prompt_input = run_codex(
        "debug",
        "prompt-input",
        "Perform an ordinary price-blind owner research routing preflight.",
    )
    model_context = json.dumps(prompt_input[:-1], ensure_ascii=False)
    visible_owner_skills = {
        skill for skill in VERIFIER["EXPECTED_SKILLS"] if skill in model_context
    }
    assert visible_owner_skills == {"owner-equity-research"}
