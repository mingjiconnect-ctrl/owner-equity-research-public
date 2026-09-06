from __future__ import annotations

import os
import runpy
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PHASE_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
CANONICAL_SOURCE_DATE_EPOCH = PHASE_VERIFIER["CANONICAL_SOURCE_DATE_EPOCH"]
CONFLICTING_SOURCE_DATE_EPOCH = "1784088771"
FIXED_ZIP_TIME = (2020, 2, 2, 0, 0, 0)


def test_distribution_runner_overrides_a_conflicting_parent_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", CONFLICTING_SOURCE_DATE_EPOCH)
    observed_environment: dict[str, str] = {}

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        env: dict[str, str],
        check: bool,
        timeout: float | None,
    ) -> subprocess.CompletedProcess[str]:
        assert cwd == ROOT
        assert check is False
        assert timeout is None
        observed_environment.update(env)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert PHASE_VERIFIER["_run_distribution"](["distribution-control"]) == 0
    assert observed_environment["SOURCE_DATE_EPOCH"] == CANONICAL_SOURCE_DATE_EPOCH


def test_full_verifier_pytest_subprocess_overrides_a_conflicting_parent_epoch(
    tmp_path: Path,
) -> None:
    module = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str],
        *,
        hash_seed: str = "0",
        environment_overrides: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
    ) -> int:
        observed.update(
            command=tuple(command),
            environment_overrides=environment_overrides,
            hash_seed=hash_seed,
            timeout_seconds=timeout_seconds,
        )
        return 0

    module["_pytest"].__globals__["_run"] = fake_run
    result, _counts = module["_pytest"](
        tmp_path,
        label="epoch-spy",
        paths=("tests/test_phase5_v1_distribution_epoch.py",),
        hash_seed="17",
    )
    assert result == 0
    assert observed["hash_seed"] == "17"
    assert observed["timeout_seconds"] is None
    assert observed["environment_overrides"] == {
        "SOURCE_DATE_EPOCH": CANONICAL_SOURCE_DATE_EPOCH
    }


def test_both_full_verifier_distribution_paths_use_the_canonical_runner(
    tmp_path: Path,
) -> None:
    module = runpy.run_path(str(ROOT / "scripts/verify_phase5_v1.py"))
    calls: list[tuple[str, ...]] = []

    def fake_distribution_run(command: list[str]) -> int:
        calls.append(tuple(command))
        if "build" in command:
            output = Path(command[command.index("--outdir") + 1])
            if command[-1].endswith("sidecars/futu-opend"):
                stem = "owner_research_futu_sidecar-1.0.0.dev0"
            else:
                stem = "owner_equity_research-1.0.0.dev0"
            (output / f"{stem}-py3-none-any.whl").write_bytes(b"wheel")
            (output / f"{stem}.tar.gz").write_bytes(b"sdist")
        return 0

    verifier_globals = module["_verify_research_distributions"].__globals__
    verifier_globals["_run_distribution"] = fake_distribution_run
    verifier_globals["_git"] = lambda *_arguments: "a" * 40
    research_root = tmp_path / "research"
    sidecar_root = tmp_path / "sidecar"
    research_root.mkdir()
    sidecar_root.mkdir()
    assert module["_verify_research_distributions"](research_root) == 0
    assert module["_verify_sidecar_distributions"](sidecar_root) == 0
    assert len(calls) == 6
    assert sum("build" in command for command in calls) == 2
    assert sum("verify_wheel.py" in " ".join(command) for command in calls) == 1
    assert sum("verify_sdist.py" in " ".join(command) for command in calls) == 1
    assert sum("verify_sidecar_distribution.py" in " ".join(command) for command in calls) == 2


@pytest.mark.parametrize(
    "source",
    (ROOT, ROOT / "sidecars/futu-opend"),
    ids=("research", "sidecar"),
)
def test_real_hatch_distributions_use_the_canonical_epoch_under_conflicting_parent(
    source: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", CONFLICTING_SOURCE_DATE_EPOCH)
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = CANONICAL_SOURCE_DATE_EPOCH
    subprocess.run(
        (
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
            str(source),
        ),
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    wheels = tuple(tmp_path.glob("*.whl"))
    sdists = tuple(tmp_path.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        assert archive.infolist()
        assert {item.date_time for item in archive.infolist()} == {FIXED_ZIP_TIME}
    gzip_header = sdists[0].read_bytes()[:10]
    assert int.from_bytes(gzip_header[4:8], "little") == int(
        CANONICAL_SOURCE_DATE_EPOCH
    )
    with tarfile.open(sdists[0], mode="r:gz") as archive:
        members = archive.getmembers()
    assert members
    assert {member.mtime for member in members} == {int(CANONICAL_SOURCE_DATE_EPOCH)}


def test_ci_has_one_canonical_distribution_epoch() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert CONFLICTING_SOURCE_DATE_EPOCH not in workflow
    assert workflow.count(f"SOURCE_DATE_EPOCH={CANONICAL_SOURCE_DATE_EPOCH}") == 11
    assert (
        f'SOURCE_DATE_EPOCH={CANONICAL_SOURCE_DATE_EPOCH} \\\n'
        '            "$venv_python" -I -m build'
    ) in workflow
    assert (
        f'SOURCE_DATE_EPOCH={CANONICAL_SOURCE_DATE_EPOCH} \\\n'
        '            "$semantic_python" -I -m build'
    ) in workflow
