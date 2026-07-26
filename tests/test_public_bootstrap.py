from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.public_bootstrap import (
    load_public_bootstrap_provenance,
    verify_public_bootstrap_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]


def test_clean_public_root_replays_private_source_snapshot() -> None:
    payload = verify_public_bootstrap_snapshot(ROOT)
    assert payload["private_source"] == {
        "commit": "253c869af34d3aa6dc2068171b5a8bd06a0cff95",
        "repository": "mingjiconnect-ctrl/owner-equity-research",
        "tree": "66a3fff1d1c0029477780595a279029aefb444bb",
    }
    assert payload["public_destination"] == {
        "repository": "mingjiconnect-ctrl/owner-equity-research-public",
        "repository_id": 1312436919,
    }


def test_public_bootstrap_rejects_noncanonical_or_drifted_provenance(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "repo"
    (destination / "docs").mkdir(parents=True)
    payload = load_public_bootstrap_provenance(ROOT)
    (destination / "docs/public-bootstrap-provenance.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="malformed"):
        load_public_bootstrap_provenance(destination)

