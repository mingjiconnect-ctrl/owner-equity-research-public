from __future__ import annotations

import copy
import runpy
import shutil
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
CI_PATH = ROOT / ".github/workflows/ci.yml"
VERIFY = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
KERNEL_FINDINGS = VERIFY["_kernel_reader_ci_findings"]
WORKFLOW_FINDINGS = VERIFY["_active_workflow_findings"]


def _workflow() -> dict:
    return yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))


def _render(workflow: dict) -> str:
    return yaml.safe_dump(workflow, sort_keys=False)


def test_kernel_reader_ci_closed_projection_is_accepted() -> None:
    assert KERNEL_FINDINGS(CI_PATH.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "mutation",
    (
        "workflow_secret",
        "disabled_revocation",
        "late_revocation",
        "job_environment",
        "continue_on_error",
        "token_escape",
        "bracket_secret_escape",
        "fake_netless_commands",
        "missing_privilege_drop",
        "missing_no_new_privs",
        "missing_privileged_channel_mask",
        "candidate_before_privilege_drop",
        "runner_identity_reuse",
        "replaceable_container_logs",
        "missing_log_recheck",
        "missing_container_git_authority",
        "missing_private_checkout_ownership",
        "writable_private_checkout_source_alias",
        "missing_fixed_runtime_inputs",
        "missing_candidate_tmpfs",
        "late_candidate_tmpfs",
        "private_tmpdir_reuse",
        "orphan_private_tmpdir",
        "missing_candidate_tmpfs_evidence",
        "workspace_candidate_ownership",
        "top_level_defaults",
        "semantic_secret",
        "extra_secret_job",
        "shallow_candidate_checkout",
    ),
)
def test_kernel_reader_ci_adversarial_mutations_are_rejected(mutation: str) -> None:
    workflow = copy.deepcopy(_workflow())
    verify = workflow["jobs"]["verify"]
    steps = verify["steps"]
    candidate_checkout = next(
        step
        for step in steps
        if step.get("name") == "Check out the exact current candidate"
    )
    stage = next(
        step
        for step in steps
        if step.get("name")
        == "Stage netless, then verify in the authorized 3.11 container"
    )
    container = next(
        step
        for step in steps
        if step.get("name")
        == "Run the exact candidate in the authorized 3.11 container"
    )
    if mutation == "workflow_secret":
        workflow["env"]["LEAKED_KERNEL_PRIVATE_KEY"] = (
            "${{ secrets.PHASE5E_KERNEL_READER_PRIVATE_KEY }}"
        )
        steps[1]["with"]["private-key"] = "${{ env.LEAKED_KERNEL_PRIVATE_KEY }}"
    elif mutation == "disabled_revocation":
        steps[4]["if"] = "false"
    elif mutation == "late_revocation":
        steps[4], steps[6] = steps[6], steps[4]
    elif mutation == "job_environment":
        verify["env"] = {"KERNEL_TOKEN": "${{ steps.kernel-reader-token.outputs.token }}"}
    elif mutation == "continue_on_error":
        steps[4]["continue-on-error"] = True
    elif mutation == "token_escape":
        steps[8]["env"] = {"LEAKED": "${{ steps.kernel-reader-token.outputs.token }}"}
    elif mutation == "bracket_secret_escape":
        steps[6]["env"] = {
            "LEAKED": "${{ secrets['PHASE5E_KERNEL_READER_PRIVATE_KEY'] }}"
        }
    elif mutation == "fake_netless_commands":
        stage["run"] = (
            "sudo unshare --net -- true\n"
            "python -I scripts/verify_phase5_v1.py --mode verify\n"
        )
    elif mutation == "missing_privilege_drop":
        stage["run"] = stage["run"].replace(
            "  --clear-groups \\\n", ""
        )
    elif mutation == "missing_no_new_privs":
        stage["run"] = stage["run"].replace(
            "  --no-new-privs \\\n", ""
        )
    elif mutation == "missing_privileged_channel_mask":
        stage["run"] = stage["run"].replace(
            "for privileged_channel in /usr/bin/docker /usr/bin/sudo; do\n",
            "for privileged_channel in /usr/bin/docker; do\n",
        )
    elif mutation == "candidate_before_privilege_drop":
        stage["run"] = stage["run"].replace(
            'exec /usr/bin/setpriv \\\n',
            '"$runner_python" -I "$validator" "$wheelhouse" "$python_minor"\n'
            'exec /usr/bin/setpriv \\\n',
        )
    elif mutation == "runner_identity_reuse":
        stage["run"] = stage["run"].replace(
            '--reuid="$candidate_uid"', '--reuid="$host_uid"'
        )
    elif mutation == "replaceable_container_logs":
        stage["run"] = stage["run"].replace(
            'chmod 0711 "$private_root"\n',
            'chmod 0711 "$private_root"\n'
            'chown --no-dereference "$candidate_uid:$candidate_gid" '
            '"$private_root"\n',
            1,
        )
    elif mutation == "missing_log_recheck":
        stage["run"] = stage["run"].replace(
            "for protected_log in stage.stdout stage.stderr container.stdout "
            "container.stderr; do\n",
            "for log in stage.stdout stage.stderr container.stdout container.stderr; do\n",
            1,
        )
    elif mutation == "missing_container_git_authority":
        container["run"] = container["run"].replace(
            "  GIT_CONFIG_VALUE_0=/workspace \\\n", "", 1
        )
    elif mutation == "missing_private_checkout_ownership":
        stage["run"] = stage["run"].replace(
            'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
            '"$kernel_source"\n',
            "",
            1,
        )
    elif mutation == "writable_private_checkout_source_alias":
        stage["run"] = stage["run"].replace(
            'mount --bind "$kernel_source" "$kernel_source"\n'
            'mount -o remount,bind,ro "$kernel_source"\n',
            "",
            1,
        )
    elif mutation == "missing_fixed_runtime_inputs":
        stage["run"] = stage["run"].replace(
            'mount --bind "$validator_source" "$validator"\n'
            'mount -o remount,bind,ro,noexec,nosuid,nodev "$validator"\n',
            "",
            1,
        )
    elif mutation == "missing_candidate_tmpfs":
        stage["run"] = stage["run"].replace(
            "mount -t tmpfs \\\n"
            "  -o rw,exec,nosuid,nodev,size=1073741824,mode=0700 \\\n"
            "  tmpfs /run/owner-research/tmp\n",
            "",
            1,
        )
    elif mutation == "late_candidate_tmpfs":
        tmp_mount = (
            "mount -t tmpfs \\\n"
            "  -o rw,exec,nosuid,nodev,size=1073741824,mode=0700 \\\n"
            "  tmpfs /run/owner-research/tmp\n"
        )
        stage["run"] = stage["run"].replace(tmp_mount, "", 1).replace(
            'cd "$workspace"\n',
            f'{tmp_mount}cd "$workspace"\n',
            1,
        )
    elif mutation == "private_tmpdir_reuse":
        stage["run"] = stage["run"].replace(
            "TMPDIR=/run/owner-research/tmp", 'TMPDIR="$private_root/tmp"', 1
        )
    elif mutation == "orphan_private_tmpdir":
        stage["run"] = stage["run"].replace(
            '  "$private_root/home" \\\n',
            '  "$private_root/home" \\\n  "$private_root/tmp" \\\n',
            1,
        )
    elif mutation == "missing_candidate_tmpfs_evidence":
        stage["run"] = stage["run"].replace(
            'tmp_mount_options=$(findmnt -n -o OPTIONS --target "$TMPDIR")\n'
            "for required_option in rw nosuid nodev; do\n"
            "  printf '%s\\n' \"$tmp_mount_options\" | tr ',' '\\n' | "
            'grep -Fx "$required_option"\n'
            "done\n",
            "",
            1,
        )
    elif mutation == "workspace_candidate_ownership":
        stage["run"] = stage["run"].replace(
            'mount --bind "$workspace_source" "$workspace"\n',
            'chown -R --no-dereference "$candidate_uid:$candidate_gid" '
            '"$workspace_source"\nmount --bind "$workspace_source" "$workspace"\n',
            1,
        )
    elif mutation == "top_level_defaults":
        workflow["defaults"] = {"run": {"shell": "bash -c 'exit 0; bash {0}'"}}
    elif mutation == "semantic_secret":
        semantic = workflow["jobs"]["semantic-audit"]
        semantic["environment"] = "phase5e-controller-main-only"
        semantic["steps"][0]["env"] = {
            "LEAKED": "${{ secrets.PHASE5E_CONTROLLER_PRIVATE_KEY }}"
        }
    elif mutation == "extra_secret_job":
        workflow["jobs"]["leak"] = {
            "runs-on": "ubuntu-24.04",
            "environment": "phase5e-private-kernel-readonly",
            "steps": [
                {
                    "run": "echo leak",
                    "env": {
                        "LEAKED": "${{ secrets['PHASE5E_KERNEL_READER_PRIVATE_KEY'] }}"
                    },
                }
            ],
        }
    elif mutation == "shallow_candidate_checkout":
        candidate_checkout["with"]["fetch-depth"] = 1
    else:  # pragma: no cover - parameter list is closed above
        raise AssertionError(mutation)
    findings = KERNEL_FINDINGS(_render(workflow))
    assert findings
    assert all(finding.code == "P5V1-KERNEL-READER-CI" for finding in findings)


def test_active_workflow_inventory_rejects_an_added_workflow(tmp_path: Path) -> None:
    for name in VERIFY["ACTIVE_WORKFLOW_NAMES"]:
        shutil.copy2(ROOT / ".github/workflows" / name, tmp_path / name)
    assert WORKFLOW_FINDINGS(tmp_path) == []
    (tmp_path / "credential-leak.yml").write_text("name: leak\n", encoding="utf-8")
    findings = WORKFLOW_FINDINGS(tmp_path)
    assert findings
    assert findings[0].code == "P5V1-WORKFLOW-INVENTORY"


def test_active_workflow_projection_rejects_legacy_secret_mutation(tmp_path: Path) -> None:
    for name in VERIFY["ACTIVE_WORKFLOW_NAMES"]:
        shutil.copy2(ROOT / ".github/workflows" / name, tmp_path / name)
    legacy = tmp_path / "phase5e2b12a-acceptance-gate.yml"
    legacy.write_text(
        legacy.read_text(encoding="utf-8")
        + "\n# ${{ secrets['PHASE5E_KERNEL_READER_PRIVATE_KEY'] }}\n",
        encoding="utf-8",
    )
    findings = WORKFLOW_FINDINGS(tmp_path)
    assert findings
    assert findings[0].code == "P5V1-WORKFLOW-PROJECTION"
