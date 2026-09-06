from __future__ import annotations

import copy
import gzip
import io
import os
import runpy
import subprocess
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_sdist.py"))
VERIFY: Callable[..., tuple[str, ...]] = VERIFIER["verify"]
SOURCE_DATE_EPOCH = "1580601600"


@pytest.fixture(scope="module")
def trusted_sdist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("phase5-v1-sdist-metadata")
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--outdir",
            str(destination),
            str(ROOT),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
    )
    archives = tuple(destination.glob("*.tar.gz"))
    assert len(archives) == 1
    return archives[0]


def _verify(sdist: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", SOURCE_DATE_EPOCH)
    return VERIFY(sdist, source_root=ROOT)


def _rewrite_sdist(
    source: Path,
    destination: Path,
    mutation: Callable[[tarfile.TarInfo], None],
    *,
    swap_first_two: bool = False,
) -> Path:
    with tarfile.open(source, "r:gz") as incoming:
        entries = [
            (copy.copy(member), incoming.extractfile(member).read())
            for member in incoming.getmembers()
        ]
    if swap_first_two:
        entries[0], entries[1] = entries[1], entries[0]
    with tarfile.open(destination, "w:gz", format=tarfile.PAX_FORMAT) as outgoing:
        for member, raw in entries:
            member.pax_headers = dict(member.pax_headers)
            mutation(member)
            if member.isreg():
                member.size = len(raw)
                outgoing.addfile(member, io.BytesIO(raw))
            else:
                member.size = 0
                outgoing.addfile(member)
    return destination


def _metadata_errors(errors: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(error for error in errors if error.startswith("sdist "))


def _canonical_gzip(payload: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=output,
        mtime=int(SOURCE_DATE_EPOCH),
    ) as archive:
        archive.write(payload)
    return output.getvalue()


def test_real_hatch_sdist_has_the_exact_closed_metadata(
    trusted_sdist: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _metadata_errors(_verify(trusted_sdist, monkeypatch)) == ()


def test_sdist_rejects_a_conflicting_ambient_source_date_epoch(
    trusted_sdist: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(SOURCE_DATE_EPOCH) + 1))
    errors = VERIFY(trusted_sdist, source_root=ROOT)
    assert any(
        "SOURCE_DATE_EPOCH conflicts with the fixed trusted sdist build timestamp" in error
        for error in errors
    )


def test_sdist_uses_the_fixed_timestamp_when_the_ambient_epoch_is_absent(
    trusted_sdist: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    assert _metadata_errors(VERIFY(trusted_sdist, source_root=ROOT)) == ()


@pytest.mark.parametrize(
    "mutation",
    ("prefix", "suffix", "concatenated_gzip", "extra_tar_block", "concatenated_tar"),
)
def test_sdist_rejects_gzip_and_tar_envelope_smuggling(
    trusted_sdist: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    raw = trusted_sdist.read_bytes()
    if mutation == "prefix":
        candidate_raw = b"SMUGGLED-PREFIX" + raw
    elif mutation == "suffix":
        candidate_raw = raw + b"SMUGGLED-SUFFIX"
    elif mutation == "concatenated_gzip":
        candidate_raw = raw + raw
    else:
        tar_payload = gzip.decompress(raw)
        candidate_raw = _canonical_gzip(
            tar_payload + (b"\0" * 512 if mutation == "extra_tar_block" else tar_payload)
        )
    candidate = tmp_path / f"{mutation}.tar.gz"
    candidate.write_bytes(candidate_raw)
    errors = "\n".join(_verify(candidate, monkeypatch))
    assert "sdist gzip envelope" in errors or "sdist tar envelope" in errors


@pytest.mark.parametrize("mode", (0o4644, 0o664, 0o666))
def test_sdist_rejects_special_or_additional_writable_mode(
    trusted_sdist: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
) -> None:
    target = "owner_equity_research-1.0.0.dev0/src/owner_research/contracts.py"

    def mutate(member: tarfile.TarInfo) -> None:
        if member.name == target:
            member.mode = mode

    rebound = _rewrite_sdist(trusted_sdist, tmp_path / f"mode-{mode:o}.tar.gz", mutate)
    errors = _verify(rebound, monkeypatch)
    assert f"sdist member metadata is unsafe or drifted: {target}" in errors


def test_sdist_rejects_member_reordering(
    trusted_sdist: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rebound = _rewrite_sdist(
        trusted_sdist,
        tmp_path / "reordered.tar.gz",
        lambda _member: None,
        swap_first_two=True,
    )
    assert "sdist member order is not the exact trusted build order" in _verify(
        rebound, monkeypatch
    )


@pytest.mark.parametrize(
    ("attribute", "value"),
    (
        ("uid", 7),
        ("gid", 7),
        ("uname", "root"),
        ("gname", "root"),
        ("mtime", int(SOURCE_DATE_EPOCH) + 1),
    ),
)
def test_sdist_rejects_identity_time_and_device_header_rebinding(
    trusted_sdist: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
    value: int | str,
) -> None:
    target = "owner_equity_research-1.0.0.dev0/src/owner_research/contracts.py"

    def mutate(member: tarfile.TarInfo) -> None:
        if member.name == target:
            setattr(member, attribute, value)

    rebound = _rewrite_sdist(
        trusted_sdist, tmp_path / f"header-{attribute}.tar.gz", mutate
    )
    errors = _verify(rebound, monkeypatch)
    assert f"sdist member metadata is unsafe or drifted: {target}" in errors


def test_sdist_rejects_pax_override_even_when_logical_identity_is_unchanged(
    trusted_sdist: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = (
        "owner_equity_research-1.0.0.dev0/src/owner_research/resources/futu/"
        "extension_schemas/v1/futu-market-execution-publication-manifest.schema.json"
    )

    def mutate(member: tarfile.TarInfo) -> None:
        if member.name == target:
            member.uid = 7
            member.pax_headers["uid"] = "0"

    rebound = _rewrite_sdist(trusted_sdist, tmp_path / "pax-rebind.tar.gz", mutate)
    errors = _verify(rebound, monkeypatch)
    assert f"sdist member metadata is unsafe or drifted: {target}" in errors


@pytest.mark.parametrize("member_type", (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE))
def test_sdist_rejects_link_and_directory_type_rebinding(
    trusted_sdist: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    member_type: bytes,
) -> None:
    target = "owner_equity_research-1.0.0.dev0/src/owner_research/contracts.py"

    def mutate(member: tarfile.TarInfo) -> None:
        if member.name == target:
            member.type = member_type
            member.linkname = "owner_equity_research-1.0.0.dev0/README.md"

    rebound = _rewrite_sdist(
        trusted_sdist, tmp_path / f"type-{member_type.hex()}.tar.gz", mutate
    )
    errors = _verify(rebound, monkeypatch)
    assert f"sdist contains an unsafe member: {target!r}" in errors
