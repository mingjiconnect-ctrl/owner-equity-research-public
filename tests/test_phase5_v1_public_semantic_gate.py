from __future__ import annotations

from pathlib import Path

import pytest

import scripts.verify_phase5_v1 as verifier


def test_dedicated_public_semantic_files_are_zero_skip() -> None:
    for relative in verifier.PUBLIC_ZERO_SKIP_SEMANTIC_TEST_PATHS:
        source = (verifier.ROOT / relative).read_text(encoding="utf-8")
        assert "pytest.skip" not in source
        assert "pytest.mark.skip" not in source


def test_verifier_fails_closed_when_a_dedicated_public_semantic_test_skips(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dedicated = sorted(verifier.PUBLIC_ZERO_SKIP_SEMANTIC_TEST_PATHS)[0]
    monkeypatch.setattr(
        verifier,
        "_expanded_test_files",
        lambda _paths, *, ignore_legacy: (dedicated,),
    )
    monkeypatch.setattr(
        verifier,
        "_pytest",
        lambda *_args, **_kwargs: (
            0,
            {"collected": 1, "passed": 0, "skipped": 1, "failed": 0},
        ),
    )

    result, counts = verifier._pytest_by_file(
        tmp_path,
        label="public-zero-skip",
        paths=(dedicated,),
    )

    assert result == 1
    assert counts == {"collected": 1, "passed": 0, "skipped": 1, "failed": 0}
