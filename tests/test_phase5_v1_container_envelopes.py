from __future__ import annotations

import gzip
import io
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WHEEL_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_wheel.py"))
PLUGIN_VERIFIER = runpy.run_path(str(ROOT / "scripts/verify_plugin_bundle.py"))
SIDECAR_VERIFIER = runpy.run_path(
    str(ROOT / "scripts/verify_sidecar_distribution.py")
)


@pytest.fixture(scope="module")
def container_artifacts(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Path]:
    output = tmp_path_factory.mktemp("phase5-v1-container-envelopes")
    build_environment = os.environ.copy()
    build_environment["SOURCE_DATE_EPOCH"] = str(
        SIDECAR_VERIFIER["FIXED_TAR_TIME"]
    )
    root_distribution = output / "root"
    sidecar_distribution = output / "sidecar"
    root_distribution.mkdir()
    sidecar_distribution.mkdir()
    subprocess.run(
        (
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(root_distribution),
            str(ROOT),
        ),
        cwd=ROOT,
        env=build_environment,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        (
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(sidecar_distribution),
            str(ROOT / "sidecars/futu-opend"),
        ),
        cwd=ROOT,
        env=build_environment,
        check=True,
        capture_output=True,
    )
    plugin = PLUGIN_VERIFIER["build_bundle"](
        output / "owner-equity-research-plugin.zip",
        source_root=ROOT,
    )
    research_wheels = tuple(root_distribution.glob("*.whl"))
    sidecar_wheels = tuple(sidecar_distribution.glob("*.whl"))
    sidecar_sdists = tuple(sidecar_distribution.glob("*.tar.gz"))
    assert len(research_wheels) == len(sidecar_wheels) == len(sidecar_sdists) == 1
    assert PLUGIN_VERIFIER["verify"](plugin, source_root=ROOT) == ()
    assert SIDECAR_VERIFIER["verify_wheel"](
        sidecar_wheels[0], source_root=ROOT
    ) == ()
    assert SIDECAR_VERIFIER["verify_sdist"](
        sidecar_sdists[0], source_root=ROOT
    ) == ()
    # The release verifier may simultaneously report a component-lock drift while
    # another PR3 slice is being frozen.  The canonical wheel itself must still have
    # one exact container envelope; existing release tests own the full lock assertion.
    root_errors = WHEEL_VERIFIER["verify"](research_wheels[0], source_root=ROOT)
    assert not any("container envelope" in error for error in root_errors)
    return {
        "research_wheel": research_wheels[0],
        "plugin": plugin,
        "sidecar_wheel": sidecar_wheels[0],
        "sidecar_sdist": sidecar_sdists[0],
    }


def _zip_variant(raw: bytes, mutation: str) -> bytes:
    if mutation == "prefix":
        return b"SMUGGLED-PREFIX" + raw
    if mutation == "suffix":
        return raw + b"SMUGGLED-SUFFIX"
    if mutation == "concatenated":
        return raw + raw
    if mutation == "comment":
        comment = b"SMUGGLED-COMMENT"
        assert raw[-22:-18] == b"PK\x05\x06"
        return raw[:-2] + len(comment).to_bytes(2, "little") + comment
    raise AssertionError(f"unknown ZIP mutation: {mutation}")


@pytest.mark.parametrize("mutation", ("prefix", "suffix", "comment", "concatenated"))
@pytest.mark.parametrize(
    ("artifact_name", "verifier_name", "expected_error"),
    (
        ("research_wheel", "research", "wheel ZIP container envelope"),
        ("plugin", "plugin", "Plugin ZIP container envelope"),
        ("sidecar_wheel", "sidecar", "sidecar wheel ZIP container envelope"),
    ),
)
def test_zip_verifiers_reject_bytes_outside_one_exact_archive(
    container_artifacts: dict[str, Path],
    tmp_path: Path,
    mutation: str,
    artifact_name: str,
    verifier_name: str,
    expected_error: str,
) -> None:
    source = container_artifacts[artifact_name]
    candidate = tmp_path / f"{artifact_name}-{mutation}.zip"
    candidate.write_bytes(_zip_variant(source.read_bytes(), mutation))
    if verifier_name == "research":
        errors = WHEEL_VERIFIER["verify"](candidate, source_root=ROOT)
    elif verifier_name == "plugin":
        errors = PLUGIN_VERIFIER["verify"](candidate, source_root=ROOT)
    else:
        errors = SIDECAR_VERIFIER["verify_wheel"](candidate, source_root=ROOT)
    assert expected_error in "\n".join(errors)


def _canonical_gzip(payload: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=output,
        mtime=SIDECAR_VERIFIER["FIXED_TAR_TIME"],
    ) as compressed:
        compressed.write(payload)
    raw = output.getvalue()
    assert raw[:10] == SIDECAR_VERIFIER["_CANONICAL_GZIP_HEADER"]
    return raw


def _with_canonical_tar_checksum(header: bytearray) -> bytes:
    assert len(header) == 512
    header[148:156] = b"        "
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    return bytes(header)


@pytest.mark.parametrize("mutation", ("aregtype", "devmajor", "devminor"))
def test_sidecar_sdist_rejects_alternate_regular_type_and_device_fields(
    container_artifacts: dict[str, Path],
    tmp_path: Path,
    mutation: str,
) -> None:
    source = container_artifacts["sidecar_sdist"]
    payload = bytearray(gzip.decompress(source.read_bytes()))
    header = bytearray(payload[:512])
    assert header[156:157] == b"0"
    if mutation == "aregtype":
        header[156:157] = b"\0"
    elif mutation == "devmajor":
        header[329:337] = b"0000001\0"
    else:
        header[337:345] = b"0000001\0"
    payload[:512] = _with_canonical_tar_checksum(header)
    candidate = tmp_path / f"sidecar-{mutation}.tar.gz"
    candidate.write_bytes(_canonical_gzip(bytes(payload)))
    errors = SIDECAR_VERIFIER["verify_sdist"](candidate, source_root=ROOT)
    assert any("member metadata is unsafe or drifted" in error for error in errors)


def _hide_archive_inside_last_member(raw: bytes) -> bytes:
    """Extend the last declared compressed span across a complete extra ZIP."""
    eocd_offset = len(raw) - 22
    assert raw[eocd_offset : eocd_offset + 4] == b"PK\x05\x06"
    central_offset = int.from_bytes(raw[eocd_offset + 16 : eocd_offset + 20], "little")
    central_position = central_offset
    last_central_position: int | None = None
    while central_position < eocd_offset:
        assert raw[central_position : central_position + 4] == b"PK\x01\x02"
        last_central_position = central_position
        name_size = int.from_bytes(
            raw[central_position + 28 : central_position + 30], "little"
        )
        extra_size = int.from_bytes(
            raw[central_position + 30 : central_position + 32], "little"
        )
        comment_size = int.from_bytes(
            raw[central_position + 32 : central_position + 34], "little"
        )
        central_position += 46 + name_size + extra_size + comment_size
    assert central_position == eocd_offset
    assert last_central_position is not None
    local_offset = int.from_bytes(
        raw[last_central_position + 42 : last_central_position + 46], "little"
    )
    compressed_size = int.from_bytes(
        raw[last_central_position + 20 : last_central_position + 24], "little"
    )
    hidden_size = len(raw)
    candidate = bytearray(raw[:central_offset] + raw + raw[central_offset:])
    candidate[local_offset + 18 : local_offset + 22] = (
        compressed_size + hidden_size
    ).to_bytes(4, "little")
    shifted_central_position = last_central_position + hidden_size
    candidate[shifted_central_position + 20 : shifted_central_position + 24] = (
        compressed_size + hidden_size
    ).to_bytes(4, "little")
    shifted_eocd_offset = eocd_offset + hidden_size
    candidate[shifted_eocd_offset + 16 : shifted_eocd_offset + 20] = (
        central_offset + hidden_size
    ).to_bytes(4, "little")
    return bytes(candidate)


@pytest.mark.parametrize(
    ("artifact_name", "verifier_name", "expected_error"),
    (
        ("research_wheel", "research", "wheel ZIP member compressed stream"),
        ("plugin", "plugin", "Plugin ZIP member compressed stream"),
        ("sidecar_wheel", "sidecar", "sidecar wheel ZIP member compressed stream"),
    ),
)
def test_zip_verifiers_fully_consume_each_declared_deflate_stream(
    container_artifacts: dict[str, Path],
    tmp_path: Path,
    artifact_name: str,
    verifier_name: str,
    expected_error: str,
) -> None:
    source = container_artifacts[artifact_name]
    candidate = tmp_path / f"{artifact_name}-hidden-member-data.zip"
    candidate.write_bytes(_hide_archive_inside_last_member(source.read_bytes()))
    if verifier_name == "research":
        errors = WHEEL_VERIFIER["verify"](candidate, source_root=ROOT)
    elif verifier_name == "plugin":
        errors = PLUGIN_VERIFIER["verify"](candidate, source_root=ROOT)
    else:
        errors = SIDECAR_VERIFIER["verify_wheel"](candidate, source_root=ROOT)
    assert expected_error in "\n".join(errors)


@pytest.mark.parametrize("local_field_offset", (4, 10, 12))
@pytest.mark.parametrize(
    ("artifact_name", "verifier_name", "expected_error"),
    (
        ("research_wheel", "research", "wheel ZIP local-file envelope"),
        ("plugin", "plugin", "Plugin ZIP local-file envelope"),
        ("sidecar_wheel", "sidecar", "sidecar wheel ZIP local-file envelope"),
    ),
)
def test_zip_verifiers_bind_local_header_version_and_timestamp(
    container_artifacts: dict[str, Path],
    tmp_path: Path,
    local_field_offset: int,
    artifact_name: str,
    verifier_name: str,
    expected_error: str,
) -> None:
    raw = bytearray(container_artifacts[artifact_name].read_bytes())
    assert raw[:4] == b"PK\x03\x04"
    raw[local_field_offset] ^= 1
    candidate = tmp_path / f"{artifact_name}-local-{local_field_offset}.zip"
    candidate.write_bytes(raw)
    if verifier_name == "research":
        errors = WHEEL_VERIFIER["verify"](candidate, source_root=ROOT)
    elif verifier_name == "plugin":
        errors = PLUGIN_VERIFIER["verify"](candidate, source_root=ROOT)
    else:
        errors = SIDECAR_VERIFIER["verify_wheel"](candidate, source_root=ROOT)
    assert expected_error in "\n".join(errors)


@pytest.mark.parametrize(
    "mutation",
    ("prefix", "suffix", "concatenated_gzip", "noncanonical_tar", "concatenated_tar"),
)
def test_sidecar_sdist_rejects_gzip_and_tar_envelope_smuggling(
    container_artifacts: dict[str, Path],
    tmp_path: Path,
    mutation: str,
) -> None:
    source = container_artifacts["sidecar_sdist"]
    raw = source.read_bytes()
    if mutation == "prefix":
        candidate_raw = b"SMUGGLED-PREFIX" + raw
    elif mutation == "suffix":
        candidate_raw = raw + b"SMUGGLED-SUFFIX"
    elif mutation == "concatenated_gzip":
        candidate_raw = raw + raw
    else:
        tar_payload = gzip.decompress(raw)
        if mutation == "noncanonical_tar":
            candidate_raw = _canonical_gzip(tar_payload + b"\0" * 512)
        else:
            candidate_raw = _canonical_gzip(tar_payload + tar_payload)
    candidate = tmp_path / f"sidecar-{mutation}.tar.gz"
    candidate.write_bytes(candidate_raw)
    errors = SIDECAR_VERIFIER["verify_sdist"](candidate, source_root=ROOT)
    assert any(
        marker in "\n".join(errors)
        for marker in (
            "gzip envelope",
            "tar envelope",
        )
    )
