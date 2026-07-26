"""Content-addressed provenance helpers for the clean public repository root.

The public repository intentionally does not import the private development
repository's commit graph.  Historical acceptance records therefore remain
verifiable through the byte-for-byte source snapshot recorded at bootstrap,
while all new public work is verified against the public commit graph.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_PATH = ROOT / "docs" / "public-bootstrap-provenance.json"
_PROVENANCE_KEYS = {
    "bootstrap_policy",
    "private_source",
    "public_destination",
    "schema_version",
    "source_snapshot_file_digest_sha256",
}
_PRIVATE_SOURCE_KEYS = {"commit", "repository", "tree"}
_PUBLIC_DESTINATION_KEYS = {"repository", "repository_id"}


def canonical_json(payload: object) -> bytes:
    return (
        json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def load_public_bootstrap_provenance(root: Path = ROOT) -> dict[str, Any]:
    path = root / "docs" / "public-bootstrap-provenance.json"
    raw = path.read_bytes()
    payload = json.loads(raw)
    if (
        not isinstance(payload, dict)
        or set(payload) != _PROVENANCE_KEYS
        or payload.get("schema_version") != "1.0.0"
        or payload.get("bootstrap_policy")
        != "single_clean_public_root_from_verified_private_source_snapshot"
        or raw != canonical_json(payload)
    ):
        raise ValueError("public bootstrap provenance is malformed")
    private_source = payload["private_source"]
    public_destination = payload["public_destination"]
    if (
        not isinstance(private_source, dict)
        or set(private_source) != _PRIVATE_SOURCE_KEYS
        or private_source.get("repository")
        != "mingjiconnect-ctrl/owner-equity-research"
        or not _is_hex(private_source.get("commit"), 40)
        or not _is_hex(private_source.get("tree"), 40)
        or not isinstance(public_destination, dict)
        or set(public_destination) != _PUBLIC_DESTINATION_KEYS
        or public_destination
        != {
            "repository": "mingjiconnect-ctrl/owner-equity-research-public",
            "repository_id": 1312436919,
        }
        or not _is_hex(payload.get("source_snapshot_file_digest_sha256"), 64)
    ):
        raise ValueError("public bootstrap identity is malformed")
    return payload


def source_snapshot_digest(root: Path = ROOT) -> str:
    """Reproduce the immutable public-root snapshot digest.

    Successor work is allowed to change working-tree files.  Provenance is
    therefore checked against the unique root commit, never against mutable
    successor bytes.
    """

    root_commit = public_root_commit(root)
    paths = subprocess.check_output(
        ["git", "-C", str(root), "ls-tree", "-r", "--name-only", root_commit],
        text=True,
    ).splitlines()
    digest = hashlib.sha256()
    for relative_path in sorted(paths):
        if relative_path == "docs/public-bootstrap-provenance.json":
            continue
        content = subprocess.check_output(
            ["git", "-C", str(root), "show", f"{root_commit}:{relative_path}"]
        )
        file_digest = hashlib.sha256(content).hexdigest()
        digest.update(f"{file_digest}  ./{relative_path}\n".encode())
    return digest.hexdigest()


def public_root_commit(root: Path = ROOT) -> str:
    roots = subprocess.check_output(
        ["git", "-C", str(root), "rev-list", "--max-parents=0", "HEAD"],
        text=True,
    ).splitlines()
    if len(roots) != 1:
        raise ValueError("public repository must have exactly one clean root commit")
    return roots[0]


def public_root_file(relative_path: str, root: Path = ROOT) -> bytes:
    return subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "show",
            f"{public_root_commit(root)}:{relative_path}",
        ]
    )


def public_root_paths(prefix: str, root: Path = ROOT) -> tuple[str, ...]:
    value = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "ls-tree",
            "-r",
            "--name-only",
            public_root_commit(root),
            prefix,
        ],
        text=True,
    )
    return tuple(item for item in value.splitlines() if item)


def verify_public_bootstrap_snapshot(root: Path = ROOT) -> dict[str, Any]:
    payload = load_public_bootstrap_provenance(root)
    actual = source_snapshot_digest(root)
    expected = payload["source_snapshot_file_digest_sha256"]
    if actual != expected:
        raise ValueError("public bootstrap source snapshot bytes drifted")
    return payload


def commit_exists(commit: str, root: Path = ROOT) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-e", f"{commit}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


def _is_hex(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True
