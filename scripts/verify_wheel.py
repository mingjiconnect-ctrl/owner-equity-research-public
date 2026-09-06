#!/usr/bin/env python3
"""Verify the closed public contents and runtime bindings of a research wheel."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import struct
import subprocess
import tomllib
import zlib
from pathlib import Path, PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "owner-equity-research"
PROJECT_VERSION = "1.0.0.dev0"
EXPECTED_PROJECT_DEPENDENCIES = [
    "cryptography==50.0.0",
    "jsonschema>=4.23,<5",
    "httpx>=0.27,<1",
    "lxml>=5.3,<7",
    "pypdf==6.16.1",
    "pypdfium2==5.13.0",
]
DIST_INFO_STEM = "owner_equity_research-1.0.0.dev0.dist-info"
SOURCE_PROJECTION = (
    ("src/owner_research", "owner_research"),
    ("schemas", "owner_research/schemas"),
    ("extension_schemas", "owner_research/extension_schemas"),
    (
        "plugins/owner-equity-research/skills/owner-equity-research/assets",
        "owner_research/report_assets",
    ),
    (
        "scripts/phase5e-futu-market-authority-policy-v2.json",
        "owner_research/resources/futu/market-authority-policy-v2.json",
    ),
    ("component-lock.json", "owner_research/component-lock.json"),
)
MAXIMUM_SOURCE_MEMBER_BYTES = 64 * 1024 * 1024
MAXIMUM_SOURCE_PROJECTION_BYTES = 512 * 1024 * 1024
MAXIMUM_WHEEL_UNCOMPRESSED_BYTES = MAXIMUM_SOURCE_PROJECTION_BYTES + 16 * 1024 * 1024
EXPECTED_ENTRY_POINTS = (
    b"[console_scripts]\n"
    b"owner-equity-research = owner_research.workflow_cli:main\n"
    b"owner-research-validate = owner_research.cli:main\n"
    b"owner-research-valuation = owner_research.valuation_cli:main\n"
)
EXPECTED_WHEEL = (
    b"Wheel-Version: 1.0\nGenerator: hatchling 1.27.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
)
EXPECTED_METADATA_PREFIX = (
    b"Metadata-Version: 2.4\n"
    b"Name: owner-equity-research\n"
    b"Version: 1.0.0.dev0\n"
    b"Summary: Auditable equity-research evidence and deterministic integration artifacts\n"
    b"Requires-Python: <3.14,>=3.11\n"
    b"Requires-Dist: cryptography==50.0.0\n"
    b"Requires-Dist: httpx<1,>=0.27\n"
    b"Requires-Dist: jsonschema<5,>=4.23\n"
    b"Requires-Dist: lxml<7,>=5.3\n"
    b"Requires-Dist: pypdf==6.16.1\n"
    b"Requires-Dist: pypdfium2==5.13.0\n"
    b"Provides-Extra: dev\n"
    b"Requires-Dist: build==1.3.0; extra == 'dev'\n"
    b"Requires-Dist: hatchling==1.27.0; extra == 'dev'\n"
    b"Requires-Dist: pytest<9,>=8.3; extra == 'dev'\n"
    b"Requires-Dist: pyyaml<7,>=6.0; extra == 'dev'\n"
    b"Requires-Dist: ruff<1,>=0.9; extra == 'dev'\n"
    b"Description-Content-Type: text/markdown\n"
    b"\n"
)
EXPECTED_DIST_INFO = {
    f"{DIST_INFO_STEM}/METADATA",
    f"{DIST_INFO_STEM}/RECORD",
    f"{DIST_INFO_STEM}/WHEEL",
    f"{DIST_INFO_STEM}/entry_points.txt",
}
EXPECTED_FUTU_PUBLIC_RESOURCES = {
    "owner_research/resources/futu/extension_schemas/v1/futu-account-entitlement-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-cross-check-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-data-request-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-data-response-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-evidence-bundle.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-frozen-conclusion-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-historical-kline-quota-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-legal-rights-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-market-execution-evidence.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-market-execution-publication-manifest.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-observation-disposition-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-observation-disposition-publication-bundle.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-observation.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-partial-session-publication-manifest.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-peer-evidence-set.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-peer-session-evidence.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-runtime-isolation-authorization.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-runtime-isolation-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-security-identity-receipt.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-session-evidence.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-session-publication-manifest.schema.json",
    "owner_research/resources/futu/extension_schemas/v1/futu-supply-chain-receipt.schema.json",
    "owner_research/resources/futu/financial-field-registry-v1.json",
    "owner_research/resources/futu/interface-authority-registry-v1.json",
    "owner_research/resources/futu/issue-code-registry-v1.json",
    "owner_research/resources/futu/market-authority-policy-v2.json",
    "owner_research/resources/futu/protocol-registry-v1.json",
    "owner_research/resources/futu/sdk-adapter-registry-v1.json",
}
EXPECTED_REPORT_ASSETS = {
    "owner_research/report_assets/NOTO-CJK-LICENSE.txt": (
        4301,
        "6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2",
    ),
    "owner_research/report_assets/NotoSansCJKsc-Regular.otf": (
        16437364,
        "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
    ),
    "owner_research/report_assets/font-manifest.json": (
        800,
        "49ddc5a5d408a7c9a54b7c0cb610dbc2667ca81ae1653c585665a529ac23c1d0",
    ),
    "owner_research/report_assets/report-template.tex": (
        1440,
        "5e5bb2a8f65ca3a1a2d0c66ffade2954ffb84e4abc815f0a4e1f8f1b14dce394",
    ),
}
PR3_FUTU_POLICY_MEMBER = "owner_research/resources/futu/market-authority-policy-v2.json"
EXPECTED_PR3_FUTU_POLICY_SHA256 = (
    "c040d23627baebd61f6e96c8cca17807ab82943b889a5dc6979fdb68a025e26c"
)
EXPECTED_PR3_KERNEL_SCHEMA_RESOURCES = {
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
PR3_REQUIRED_MODULE_MEMBERS = {
    "owner_research/__init__.py",
    "owner_research/component_lock.py",
    "owner_research/futu_crosscheck.py",
    "owner_research/futu_receipts.py",
    "owner_research/futu_session.py",
    "owner_research/futu_sidecar.py",
    "owner_research/owner_equity_research.py",
    "owner_research/owner_equity_runtime.py",
    "owner_research/owner_equity_types.py",
    "owner_research/owner_scorecard.py",
    "owner_research/research_publisher.py",
    "owner_research/research_report.py",
    "owner_research/valuation_cli.py",
    "owner_research/valuation_futu_market.py",
    "owner_research/valuation_run.py",
    "owner_research/valuation_run_archive.py",
    "owner_research/valuation_run_context.py",
    "owner_research/valuation_synthesis.py",
    "owner_research/valuation_synthesis_types.py",
    "owner_research/workflow_cli.py",
}
REQUIRED = {
    "owner_research/__init__.py",
    "owner_research/component-lock.json",
    "owner_research/component_lock.py",
    "owner_research/contracts.py",
    "owner_research/futu_crosscheck.py",
    "owner_research/futu_receipts.py",
    "owner_research/futu_sidecar.py",
    "owner_research/resources/futu/market-authority-policy-v2.json",
    "owner_research/report_assets/NOTO-CJK-LICENSE.txt",
    "owner_research/report_assets/NotoSansCJKsc-Regular.otf",
    "owner_research/report_assets/font-manifest.json",
    "owner_research/report_assets/report-template.tex",
    "owner_research/valuation_cli.py",
    "owner_research/valuation_run.py",
    "owner_research/valuation_run_archive.py",
    "owner_research/valuation_run_context.py",
} | PR3_REQUIRED_MODULE_MEMBERS
FORBIDDEN_PREFIXES = ("tests/", "evals/", "plugins/", "docs/", ".git/")
RUNTIME_RESOURCE_PREFIX = "owner_research/resources/phase5-v1-kernel-runtime/"
RUNTIME_AUTHORITY = RUNTIME_RESOURCE_PREFIX + "runtime-authority.json"
EXPECTED_RELEASE_WHEEL_SHA256 = "fb27d01b1ee75fbd542371510150e890516d306218d33f3608f2aa3caa0e55a5"
EXPECTED_RESULT_SCHEMA = {
    "filename": "valuation-result.schema.json",
    "sha256": "bbfed2049ed258b767002b74ff45fb6847eb5723ffd6c1d31c53cf119625a683",
}
EXPECTED_RUNTIME_DEPENDENCIES = [
    [
        "attrs-26.1.0-py3-none-any.whl",
        "c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
    ],
    [
        "jsonschema-4.26.0-py3-none-any.whl",
        "d489f15263b8d200f8387e64b4c3a75f06629559fb73deb8fdfb525f2dab50ce",
    ],
    [
        "jsonschema_specifications-2025.9.1-py3-none-any.whl",
        "98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe",
    ],
    [
        "referencing-0.37.0-py3-none-any.whl",
        "381329a9f99628c9069361716891d34ad94af76e461dcb0335825aecc7692231",
    ],
    [
        "rpds_py-2026.6.3-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "9c1255b302953c86a486b81d330d5ee1d5bd937691ce271b6be0ef0e299eaab7",
    ],
    [
        "typing_extensions-4.16.0-py3-none-any.whl",
        "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
    ],
]
EXPECTED_RUNTIME_CONTAINER = {
    "engine": "docker",
    "engine_path": "/usr/bin/docker",
    "image_repository": "docker.io/library/python",
    "image_tag": "3.11.15-bookworm",
    "image_manifest_digest": (
        "sha256:eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
    ),
    "image_config_digest": (
        "sha256:d299dee73063206fe64248b8eb62cbef36f6baedfc2c5e2ef4c7618ad18efb3a"
    ),
    "image_reference": (
        "docker.io/library/python@sha256:"
        "eaeffb6e8511935426934aac863940fbd004ef31dab0d7fc27a129bb7c19d9a8"
    ),
    "platform": "linux/amd64",
    "os": "linux",
    "architecture": "amd64",
    "python_minor": "3.11",
    "python_patch": "3.11.15",
    "python_executable": "/usr/local/bin/python3",
    "pull_policy": "never",
    "network_mode": "none",
    "read_only_rootfs": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "user_policy": "host_uid_gid",
    "pids_limit": 64,
    "memory_limit_bytes": 1610612736,
    "memory_swap_limit_bytes": 1610612736,
    "cpu_limit": "1.0",
    "tmpfs": ["/tmp:rw,exec,nosuid,nodev,size=268435456,mode=1777"],
    "ulimits": ["core=0:0", "fsize=67108864:67108864", "nofile=64:64"],
    "read_only_mounts": ["manifest", "request", "runner", "wheelhouse"],
}
EXPECTED_TRUSTED_WORKFLOW = {
    "attestation_path": "/run/owner-research/trusted-container-attestation.json",
    "attestation_mount_target": "/run/owner-research",
    "attestation_sha256_env": "OWNER_RESEARCH_TRUSTED_CONTAINER_ATTESTATION_SHA256",
    "read_only_mounts": [
        {"role": "candidate_workspace", "target": "/workspace"},
        {"role": "private_kernel_checkout", "target": "/private-kernel"},
        {"role": "binary_supply_wheelhouse", "target": "/supply"},
        {"role": "binary_supply_lock", "target": "/supply.lock"},
        {"role": "verified_research_wheel", "target": "/research-wheel"},
        {"role": "runtime_cas", "target": "/runtime-cas"},
        {
            "role": "trusted_attestation_directory",
            "target": "/run/owner-research",
        },
    ],
    "writable_mounts": [{"role": "canonical_summary_output", "target": "/output"}],
}
LOCKED_RUNTIME_MEMBERS = {
    "runtime_authority": RUNTIME_AUTHORITY,
    "materializer_code": "owner_research/valuation_kernel_materializer.py",
    "runner_code": "owner_research/valuation_pinned_kernel.py",
}
EXPECTED_RUNTIME_MEMBER_SHA256 = {
    "runtime_authority": ("0a317935d257e2fb406bc8efd9c90d42b1e572a6f8e6baa3c6d75b7cb48530dd"),
    "materializer_code": ("99ef65386015acfdf962140471a5277fdf492027b1f28b1aa61e3ce25e5785d6"),
    "runner_code": ("1baebaaa11aab5165ff3d6d1e1567b2dfbc2dac2cd23576572112038ca16fd0b"),
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _load_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_LOCAL_HEADER = struct.Struct("<4s5H3L2H")
_ZIP_CENTRAL_HEADER = struct.Struct("<4s6H3L5H2L")


def _exact_deflate_stream_error(
    descriptor: int,
    payload_offset: int,
    compressed_size: int,
    uncompressed_size: int,
) -> str | None:
    """Require one raw DEFLATE stream to consume its declared span exactly."""
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    position = payload_offset
    remaining = compressed_size
    total = 0
    try:
        while remaining:
            chunk_size = min(1024 * 1024, remaining)
            pending = os.pread(descriptor, chunk_size, position)
            if len(pending) != chunk_size:
                return "wheel ZIP member compressed stream is truncated"
            position += chunk_size
            remaining -= chunk_size
            while pending:
                output_limit = min(1024 * 1024, uncompressed_size - total + 1)
                decoded = decoder.decompress(pending, output_limit)
                pending = decoder.unconsumed_tail
                total += len(decoded)
                if total > uncompressed_size:
                    return "wheel ZIP member expands beyond its declared size"
                if decoder.unused_data:
                    return "wheel ZIP member compressed stream has trailing data"
                if decoder.eof:
                    if pending or remaining:
                        return "wheel ZIP member compressed stream has trailing data"
                    break
            if decoder.eof:
                break
    except zlib.error:
        return "wheel ZIP member compressed stream is invalid"
    if not decoder.eof:
        return "wheel ZIP member compressed stream is truncated"
    if total != uncompressed_size:
        return "wheel ZIP member decompressed size drifted"
    return None


def _zip_envelope_errors(
    descriptor: int,
    file_size: int,
    infos: list[Any],
) -> list[str]:
    """Reject bytes outside one canonical, comment-free classic ZIP envelope."""
    errors: list[str] = []
    if file_size < _ZIP_EOCD.size:
        return ["wheel ZIP container envelope is truncated"]
    eocd_offset = file_size - _ZIP_EOCD.size
    eocd_raw = os.pread(descriptor, _ZIP_EOCD.size, eocd_offset)
    if len(eocd_raw) != _ZIP_EOCD.size:
        return ["wheel ZIP container envelope is truncated"]
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = _ZIP_EOCD.unpack(eocd_raw)
    if (
        signature != b"PK\x05\x06"
        or comment_size != 0
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries != len(infos)
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or central_offset + central_size != eocd_offset
    ):
        errors.append(
            "wheel ZIP container envelope has prefix, suffix, comment, concatenation, "
            "or EOCD drift"
        )
        return errors

    expected_offset = 0
    central_position = central_offset
    for item in infos:
        central_header = os.pread(
            descriptor,
            _ZIP_CENTRAL_HEADER.size,
            central_position,
        )
        if len(central_header) != _ZIP_CENTRAL_HEADER.size:
            errors.append("wheel ZIP central-directory envelope is truncated")
            return errors
        (
            central_signature,
            version_made,
            central_version_needed,
            central_flags,
            central_compression,
            central_mod_time,
            central_mod_date,
            central_crc32,
            central_compressed_size,
            central_uncompressed_size,
            central_name_size,
            central_extra_size,
            central_comment_size,
            disk_start,
            internal_attr,
            external_attr,
            local_offset,
        ) = _ZIP_CENTRAL_HEADER.unpack(central_header)
        central_name = os.pread(
            descriptor,
            central_name_size,
            central_position + _ZIP_CENTRAL_HEADER.size,
        )
        expected_name = item.filename.encode("utf-8")
        if (
            central_signature != b"PK\x01\x02"
            or version_made != (item.create_system << 8) | item.create_version
            or central_version_needed != item.extract_version
            or central_flags != item.flag_bits
            or central_compression != item.compress_type
            or central_crc32 != item.CRC
            or central_compressed_size != item.compress_size
            or central_uncompressed_size != item.file_size
            or central_extra_size != 0
            or central_comment_size != 0
            or disk_start != 0
            or internal_attr != item.internal_attr
            or external_attr != item.external_attr
            or local_offset != item.header_offset
            or central_name != expected_name
        ):
            errors.append("wheel ZIP central-directory envelope is not canonical")
            return errors
        if item.header_offset != expected_offset:
            errors.append("wheel ZIP container envelope has unreferenced or prefixed bytes")
            return errors
        header = os.pread(descriptor, _ZIP_LOCAL_HEADER.size, expected_offset)
        if len(header) != _ZIP_LOCAL_HEADER.size:
            errors.append("wheel ZIP local-file envelope is truncated")
            return errors
        (
            local_signature,
            version_needed,
            flags,
            compression,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_size,
            extra_size,
        ) = _ZIP_LOCAL_HEADER.unpack(header)
        name = os.pread(
            descriptor,
            name_size,
            expected_offset + _ZIP_LOCAL_HEADER.size,
        )
        if (
            local_signature != b"PK\x03\x04"
            or version_needed != central_version_needed
            or flags != 0
            or flags != item.flag_bits
            or compression != item.compress_type
            or mod_time != central_mod_time
            or mod_date != central_mod_date
            or crc32 != item.CRC
            or compressed_size != item.compress_size
            or uncompressed_size != item.file_size
            or extra_size != 0
            or name != expected_name
        ):
            errors.append("wheel ZIP local-file envelope is not canonical")
            return errors
        payload_offset = expected_offset + _ZIP_LOCAL_HEADER.size + name_size + extra_size
        if compression != 8:
            errors.append("wheel ZIP member compression is not canonical DEFLATE")
            return errors
        stream_error = _exact_deflate_stream_error(
            descriptor,
            payload_offset,
            compressed_size,
            uncompressed_size,
        )
        if stream_error is not None:
            errors.append(stream_error)
            return errors
        expected_offset = payload_offset + compressed_size
        central_position += (
            _ZIP_CENTRAL_HEADER.size
            + central_name_size
            + central_extra_size
            + central_comment_size
        )
    if expected_offset != central_offset or central_position != eocd_offset:
        errors.append("wheel ZIP container envelope has bytes outside member payloads")
    return errors


def _read_regular_file(path: Path, *, label: str) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{label} is not a regular single-link file")
    if metadata.st_size > MAXIMUM_SOURCE_MEMBER_BYTES:
        raise ValueError(f"{label} exceeds the source member byte limit")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"{label} changed identity before read")
        chunks: list[bytes] = []
        remaining = MAXIMUM_SOURCE_MEMBER_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or len(raw) != before.st_size:
            raise ValueError(f"{label} changed while being read")
        if len(raw) > MAXIMUM_SOURCE_MEMBER_BYTES:
            raise ValueError(f"{label} exceeds the source member byte limit")
        return raw
    finally:
        os.close(descriptor)


def _ignored_local_source(path: Path) -> bool:
    return (
        "__pycache__" in path.parts or path.name == ".DS_Store" or path.suffix in {".pyc", ".pyo"}
    )


def _wheel_name(source_name: str) -> str | None:
    for source_prefix, wheel_prefix in SOURCE_PROJECTION:
        if source_name == source_prefix:
            return wheel_prefix
        prefix = source_prefix + "/"
        if source_name.startswith(prefix):
            return wheel_prefix + "/" + source_name.removeprefix(prefix)
    return None


def _filesystem_projection(source_root: Path) -> dict[str, bytes]:
    projection: dict[str, bytes] = {}
    total = 0
    for source_prefix, _wheel_prefix in SOURCE_PROJECTION:
        source = source_root / source_prefix
        metadata = source.lstat()
        if stat.S_ISREG(metadata.st_mode):
            paths = (source,)
        elif stat.S_ISDIR(metadata.st_mode):
            discovered: list[Path] = []
            for current, directories, filenames in os.walk(source, followlinks=False):
                current_path = Path(current)
                kept_directories: list[str] = []
                for directory in directories:
                    child = current_path / directory
                    child_metadata = child.lstat()
                    if stat.S_ISLNK(child_metadata.st_mode):
                        raise ValueError(f"source projection contains a symlink: {child}")
                    if not stat.S_ISDIR(child_metadata.st_mode):
                        raise ValueError(f"source projection contains a non-directory: {child}")
                    if directory != "__pycache__":
                        kept_directories.append(directory)
                directories[:] = kept_directories
                discovered.extend(current_path / name for name in filenames)
            paths = tuple(sorted(discovered))
        else:
            raise ValueError(f"source projection root is unsafe: {source}")
        for path in paths:
            relative = path.relative_to(source_root)
            if _ignored_local_source(relative):
                continue
            wheel_name = _wheel_name(relative.as_posix())
            if wheel_name is None or wheel_name in projection:
                raise ValueError(f"source projection mapping is ambiguous: {relative}")
            raw = _read_regular_file(path, label=f"source member {relative.as_posix()}")
            total += len(raw)
            if total > MAXIMUM_SOURCE_PROJECTION_BYTES:
                raise ValueError("source projection exceeds the cumulative byte limit")
            projection[wheel_name] = raw
    return projection


def _resolve_exact_commit(source_root: Path, expected_commit: str) -> str:
    if len(expected_commit) != 40 or any(
        character not in "0123456789abcdef" for character in expected_commit
    ):
        raise ValueError("expected commit must be a lowercase full SHA-1 object name")
    result = subprocess.run(
        ("git", "-C", str(source_root), "rev-parse", "--verify", f"{expected_commit}^{{commit}}"),
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode or result.stdout.strip() != expected_commit:
        raise ValueError("expected commit is unavailable from the trusted source repository")
    return expected_commit


def _git_bytes(source_root: Path, commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(source_root), "show", f"{commit}:{relative}"),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"trusted commit is missing required source: {relative}")
    if len(result.stdout) > MAXIMUM_SOURCE_MEMBER_BYTES:
        raise ValueError(f"trusted commit source exceeds the member byte limit: {relative}")
    return result.stdout


def _git_100644_bytes(source_root: Path, commit: str, relative: str) -> bytes:
    """Read one exact trusted metadata blob only when its Git mode is canonical."""

    result = subprocess.run(
        ("git", "-C", str(source_root), "ls-tree", "-z", commit, "--", relative),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError(f"trusted commit metadata could not be enumerated: {relative}")
    records = tuple(record for record in result.stdout.split(b"\0") if record)
    try:
        identity, path_raw = records[0].split(b"\t", 1)
        mode, object_type, _object_id = identity.decode("ascii").split(" ", 2)
        observed_path = path_raw.decode("utf-8")
    except (IndexError, UnicodeError, ValueError) as exc:
        raise ValueError(f"trusted commit metadata tree record is malformed: {relative}") from exc
    if (
        len(records) != 1
        or observed_path != relative
        or mode != "100644"
        or object_type != "blob"
    ):
        raise ValueError(f"trusted commit metadata is not a 100644 regular blob: {relative}")
    return _git_bytes(source_root, commit, relative)


def _git_projection(source_root: Path, commit: str) -> dict[str, bytes]:
    result = subprocess.run(
        (
            "git",
            "-C",
            str(source_root),
            "ls-tree",
            "-r",
            "-z",
            commit,
            "--",
            *(item[0] for item in SOURCE_PROJECTION),
        ),
        check=False,
        capture_output=True,
    )
    if result.returncode:
        raise ValueError("trusted commit source projection could not be enumerated")
    projection: dict[str, bytes] = {}
    total = 0
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            identity, path_raw = record.split(b"\t", 1)
            mode, object_type, _object_id = identity.decode("ascii").split(" ", 2)
            relative = path_raw.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("trusted commit tree record is malformed") from exc
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise ValueError(f"trusted commit source is not a regular blob: {relative}")
        wheel_name = _wheel_name(relative)
        if wheel_name is None or wheel_name in projection:
            raise ValueError(f"trusted commit source mapping is ambiguous: {relative}")
        raw = _git_bytes(source_root, commit, relative)
        total += len(raw)
        if total > MAXIMUM_SOURCE_PROJECTION_BYTES:
            raise ValueError("trusted commit projection exceeds the cumulative byte limit")
        projection[wheel_name] = raw
    required_roots = {item[0] for item in SOURCE_PROJECTION}
    present_roots = {
        root
        for root in required_roots
        if any(
            name == _wheel_name(root) or name.startswith((_wheel_name(root) or "") + "/")
            for name in projection
        )
    }
    if present_roots != required_roots:
        raise ValueError("trusted commit projection is missing a required source root")
    return projection


def _trusted_file(source_root: Path, relative: str, *, expected_commit: str | None) -> bytes:
    if expected_commit is None:
        return _read_regular_file(source_root / relative, label=f"trusted source {relative}")
    return _git_100644_bytes(source_root, expected_commit, relative)


def _source_projection(
    source_root: Path, *, expected_commit: str | None
) -> tuple[dict[str, bytes], bytes, bytes]:
    root_metadata = source_root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("trusted source root is not a directory")
    commit = (
        _resolve_exact_commit(source_root, expected_commit) if expected_commit is not None else None
    )
    projection = (
        _git_projection(source_root, commit)
        if commit is not None
        else _filesystem_projection(source_root)
    )
    pyproject_raw = _trusted_file(source_root, "pyproject.toml", expected_commit=commit)
    readme_raw = _trusted_file(source_root, "README.md", expected_commit=commit)
    try:
        project = tomllib.loads(pyproject_raw.decode("utf-8"))["project"]
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("trusted pyproject metadata is unavailable") from exc
    if (
        not isinstance(project, dict)
        or project.get("name") != PROJECT_NAME
        or project.get("version") != PROJECT_VERSION
        or project.get("dependencies") != EXPECTED_PROJECT_DEPENDENCIES
        or project.get("scripts")
        != {
            "owner-equity-research": "owner_research.workflow_cli:main",
            "owner-research-validate": "owner_research.cli:main",
            "owner-research-valuation": "owner_research.valuation_cli:main",
        }
    ):
        raise ValueError(
            "trusted pyproject project identity, dependency inventory, or console scripts drifted"
        )
    if not REQUIRED.issubset(projection):
        raise ValueError("trusted source projection is missing a required package member")
    return projection, EXPECTED_METADATA_PREFIX + readme_raw, pyproject_raw


def _files_before_subdirectories(names: set[str], prefix: str) -> list[str]:
    direct: list[str] = []
    child_directories: set[str] = set()
    prefix_with_separator = f"{prefix}/" if prefix else ""
    for name in names:
        relative = name.removeprefix(prefix_with_separator)
        if "/" not in relative:
            direct.append(name)
        else:
            child_directories.add(relative.split("/", 1)[0])
    ordered = sorted(direct)
    for directory in sorted(child_directories):
        child_prefix = f"{prefix_with_separator}{directory}"
        ordered.extend(
            _files_before_subdirectories(
                {name for name in names if name.startswith(f"{child_prefix}/")},
                child_prefix,
            )
        )
    return ordered


def _trusted_wheel_member_order(projection: dict[str, bytes]) -> list[str]:
    """Reproduce Hatchling's package-first, force-include-source order."""

    forced_groups = (
        ("owner_research/component-lock.json",),
        tuple(
            sorted(
                name
                for name in projection
                if name.startswith("owner_research/extension_schemas/")
            )
        ),
        tuple(
            sorted(
                name
                for name in projection
                if name.startswith("owner_research/report_assets/")
            )
        ),
        tuple(
            sorted(
                name
                for name in projection
                if name.startswith("owner_research/schemas/")
            )
        ),
        (PR3_FUTU_POLICY_MEMBER,),
    )
    forced = {name for group in forced_groups for name in group}
    if not forced.issubset(projection):
        raise ValueError("trusted source projection lacks a forced wheel member")
    native = set(projection) - forced
    native_python = sorted(name for name in native if name.endswith(".py"))
    native_data = _files_before_subdirectories(
        native - set(native_python),
        "owner_research",
    )
    ordered = [
        *native_python,
        *native_data,
        *(name for group in forced_groups for name in group),
    ]
    if len(ordered) != len(projection) or set(ordered) != set(projection):
        raise ValueError("trusted wheel member order does not cover the source projection")
    return ordered


def _forbidden_release_path(name: str) -> bool:
    path = PurePosixPath(name)
    forbidden_components = {
        ".git",
        "cas",
        "credentials",
        "licensed",
        "private",
        "private-cas",
        "raw",
        "raw-data",
        "raw_data",
        "secrets",
    }
    forbidden_names = {".env", "credentials.json", "id_ed25519", "id_rsa", "secrets.json"}
    forbidden_suffixes = {
        ".db",
        ".har",
        ".key",
        ".log",
        ".p12",
        ".pcap",
        ".pem",
        ".pfx",
        ".sqlite",
        ".sqlite3",
        ".whl",
    }
    lowered_parts = {part.lower() for part in path.parts}
    return bool(
        lowered_parts & forbidden_components
        or path.name.lower() in forbidden_names
        or path.suffix.lower() in forbidden_suffixes
    )


def _pr3_binding_errors(projection: dict[str, bytes]) -> list[str]:
    try:
        lock = _load_json(projection["owner_research/component-lock.json"], "component lock")
        owner = lock["owner_equity_research"]
        manifest = owner["pr3_comprehensive"]
    except (KeyError, TypeError, ValueError) as exc:
        return [f"release PR3 comprehensive lock is unavailable: {exc}"]
    errors: list[str] = []
    if not isinstance(owner, dict) or set(owner) != {
        "plugin_version",
        "public_schema_sha256",
        "pr3_comprehensive",
    }:
        return ["release Owner Equity Research component-lock shape is not closed"]
    if owner.get("plugin_version") != "1.0.0-dev.0":
        errors.append("release Owner Equity Research plugin version is not development-only")
    if not isinstance(manifest, dict) or set(manifest) != {
        "manifest_version",
        "package_version",
        "extension_schema_sha256",
        "futu_authority_policy",
        "futu_resource_sha256",
        "kernel_schema_resource_sha256",
        "report_asset_sha256",
        "module_sha256",
    }:
        return [*errors, "release PR3 comprehensive manifest shape is not closed"]
    if manifest.get("manifest_version") != "1.0.0":
        errors.append("release PR3 comprehensive manifest version drifted")
    if manifest.get("package_version") != PROJECT_VERSION:
        errors.append("release PR3 comprehensive package version drifted")

    expected_maps = {
        "extension_schema_sha256": {
            name.removeprefix("owner_research/"): _sha256(raw)
            for name, raw in projection.items()
            if name.startswith("owner_research/extension_schemas/")
        },
        "futu_resource_sha256": {
            name.removeprefix("owner_research/"): _sha256(raw)
            for name, raw in projection.items()
            if name.startswith("owner_research/resources/futu/")
            and name != PR3_FUTU_POLICY_MEMBER
        },
        "kernel_schema_resource_sha256": {
            name.removeprefix("owner_research/"): _sha256(raw)
            for name, raw in projection.items()
            if name.startswith("owner_research/resources/phase5-v1-kernel-schemas/")
        },
        "report_asset_sha256": {
            name.removeprefix("owner_research/"): _sha256(raw)
            for name, raw in projection.items()
            if name.startswith("owner_research/report_assets/")
        },
        "module_sha256": {
            name.removeprefix("owner_research/"): _sha256(projection[name])
            for name in PR3_REQUIRED_MODULE_MEMBERS
            if name in projection
        },
    }
    for key, expected in expected_maps.items():
        if manifest.get(key) != expected:
            errors.append(f"release PR3 comprehensive {key} map mismatch")
    if expected_maps["kernel_schema_resource_sha256"] != (
        EXPECTED_PR3_KERNEL_SCHEMA_RESOURCES
    ):
        errors.append("release kernel Schema resource inventory is not the pinned subset")
    try:
        kernel_schema_hashes = lock["valuation_kernel"]["public_schema_sha256"]
        selected_kernel_hashes = {
            resource_path: kernel_schema_hashes[
                f"schemas/{resource_path.removeprefix('resources/phase5-v1-kernel-schemas/')}"
            ]
            for resource_path in EXPECTED_PR3_KERNEL_SCHEMA_RESOURCES
        }
    except (KeyError, TypeError):
        selected_kernel_hashes = {}
    if selected_kernel_hashes != EXPECTED_PR3_KERNEL_SCHEMA_RESOURCES:
        errors.append("release kernel Schema resources differ from the valuation-kernel lock")
    if set(expected_maps["module_sha256"]) != {
        name.removeprefix("owner_research/") for name in PR3_REQUIRED_MODULE_MEMBERS
    }:
        errors.append("release PR3 comprehensive required module inventory is incomplete")

    policy = manifest.get("futu_authority_policy")
    policy_raw = projection.get(PR3_FUTU_POLICY_MEMBER)
    if policy_raw is None or _sha256(policy_raw) != EXPECTED_PR3_FUTU_POLICY_SHA256:
        errors.append("release Futu authority policy is not the pinned v2 payload")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"path", "sha256"}
        or policy.get("path") != PR3_FUTU_POLICY_MEMBER.removeprefix("owner_research/")
        or policy.get("sha256") != EXPECTED_PR3_FUTU_POLICY_SHA256
    ):
        errors.append("release PR3 comprehensive Futu authority policy binding mismatch")
    return errors


def _release_content_errors(projection: dict[str, bytes]) -> list[str]:
    errors: list[str] = []
    secret_markers = (
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
    )
    for name, raw in projection.items():
        if _forbidden_release_path(name) or any(marker in raw for marker in secret_markers):
            errors.append(f"release source projection contains private or raw data: {name}")
    if "owner_research/__init__.py" in projection:
        futu_members = {
            name for name in projection if name.startswith("owner_research/resources/futu/")
        }
        if futu_members != EXPECTED_FUTU_PUBLIC_RESOURCES:
            errors.append("release Futu resource inventory is not the closed public projection")
        report_assets = {
            name: raw
            for name, raw in projection.items()
            if name.startswith("owner_research/report_assets/")
        }
        if set(report_assets) != set(EXPECTED_REPORT_ASSETS):
            errors.append("release report asset inventory is not the closed public projection")
        for name, (expected_size, expected_sha256) in EXPECTED_REPORT_ASSETS.items():
            raw = report_assets.get(name)
            if raw is not None and (len(raw) != expected_size or _sha256(raw) != expected_sha256):
                errors.append(f"release report asset identity drifted: {name}")
        errors.extend(_pr3_binding_errors(projection))
    return errors


def _record_bytes(member_bytes: dict[str, bytes], ordered_names: list[str]) -> bytes:
    record_name = f"{DIST_INFO_STEM}/RECORD"
    lines: list[str] = []
    for name in ordered_names:
        if name == record_name:
            lines.append(f"{name},,")
            continue
        raw = member_bytes[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        lines.append(f"{name},sha256={digest},{len(raw)}")
    return ("\n".join(lines) + "\n").encode()


def _runtime_binding_errors(archive: ZipFile) -> list[str]:
    errors: list[str] = []
    try:
        lock = _load_json(archive.read("owner_research/component-lock.json"), "component lock")
        authority = _load_json(archive.read(RUNTIME_AUTHORITY), "runtime authority")
        runtime_lock = lock["valuation_kernel_runtime"]
        kernel_lock = lock["valuation_kernel"]
    except (KeyError, ValueError) as exc:
        return [f"wheel runtime authority is unavailable: {exc}"]

    expected_runtime_keys = {
        "authority_version",
        "runtime_authority",
        "materializer_code",
        "runner_code",
        "expected_release_wheel_sha256",
        "manifest_policy_id",
        "manifest_policy_version",
    }
    if set(lock) != {
        "lock_version",
        "generated_date",
        "owner_equity_research",
        "market_access_authority",
        "valuation_kernel_runtime",
        "valuation_kernel",
    }:
        errors.append("embedded component-lock top-level shape is not closed")
    if lock.get("lock_version") != "1.2.0":
        errors.append("embedded component-lock version is not 1.2.0")
    if not isinstance(runtime_lock, dict) or set(runtime_lock) != expected_runtime_keys:
        return [*errors, "embedded kernel-runtime lock shape is not closed"]
    if not isinstance(kernel_lock, dict):
        return [*errors, "embedded valuation-kernel lock is not an object"]

    for key, member in LOCKED_RUNTIME_MEMBERS.items():
        entry = runtime_lock.get(key)
        expected_path = member.removeprefix("owner_research/")
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            errors.append(f"embedded runtime lock entry is invalid: {key}")
            continue
        if entry.get("path") != expected_path:
            errors.append(f"embedded runtime lock path drifted: {key}")
            continue
        raw = archive.read(member)
        expected_sha256 = EXPECTED_RUNTIME_MEMBER_SHA256[key]
        if entry.get("sha256") != expected_sha256:
            errors.append(f"embedded runtime lock hash is not pinned: {key}")
        if _sha256(raw) != expected_sha256:
            errors.append(f"embedded runtime member hash mismatch: {key}")

    kernel = authority.get("kernel")
    if not isinstance(kernel, dict):
        return [*errors, "embedded runtime authority kernel is not an object"]
    runtime = authority.get("runtime")
    if set(authority) != {
        "schema_version",
        "policy_id",
        "policy_version",
        "kernel",
        "build",
        "runtime",
    }:
        errors.append("runtime authority top-level shape is not closed")
    if not isinstance(runtime, dict):
        return [*errors, "runtime authority runtime is not an object"]
    if runtime.get("container") != EXPECTED_RUNTIME_CONTAINER:
        errors.append("runtime container identity is not the pinned image")
    if runtime.get("trusted_workflow") != EXPECTED_TRUSTED_WORKFLOW:
        errors.append("runtime trusted-workflow boundary is not pinned")
    if runtime.get("result_schema") != EXPECTED_RESULT_SCHEMA:
        errors.append("runtime result Schema identity is not pinned")
    if (
        isinstance(kernel.get("schema_sha256"), dict)
        and kernel["schema_sha256"].get(EXPECTED_RESULT_SCHEMA["filename"])
        != EXPECTED_RESULT_SCHEMA["sha256"]
    ):
        errors.append("runtime result Schema differs from the kernel Schema map")
    if set(runtime) != {
        "platform",
        "python_implementations",
        "result_schema",
        "container",
        "trusted_workflow",
        "python_minors",
        "request_transport",
        "result_transport",
        "kernel_call",
        "kernel_call_count",
        "network_mode",
        "result_bytes_preserved",
    }:
        errors.append("runtime authority runtime shape is not closed")
    if runtime.get("python_minors") != {"3.11": EXPECTED_RUNTIME_DEPENDENCIES}:
        errors.append("runtime Python-minor inventory is not closed")
    expected_runtime_transport = {
        "platform": "linux_x86_64",
        "python_implementations": ["cpython"],
        "request_transport": "canonical_json_stdin",
        "result_transport": "canonical_json_stdout",
        "kernel_call": "owner_valuation.run_dual_panel",
        "kernel_call_count": 1,
        "network_mode": "docker_network_none",
        "result_bytes_preserved": True,
    }
    if any(runtime.get(key) != value for key, value in expected_runtime_transport.items()):
        errors.append("runtime transport authority is not pinned")
    if runtime_lock.get("authority_version") != "1.0.0":
        errors.append("runtime authority version is not the pinned value")
    if (
        runtime_lock.get("manifest_policy_id") != "owner-research-pinned-kernel-runtime"
        or runtime_lock.get("manifest_policy_version") != "1.0.0"
    ):
        errors.append("runtime policy identity is not the pinned value")
    if runtime_lock.get("expected_release_wheel_sha256") != EXPECTED_RELEASE_WHEEL_SHA256:
        errors.append("runtime release-wheel hash is not the pinned value")
    if authority.get("schema_version") != runtime_lock.get("authority_version"):
        errors.append("runtime authority version differs from the component lock")
    if authority.get("policy_id") != runtime_lock.get("manifest_policy_id") or authority.get(
        "policy_version"
    ) != runtime_lock.get("manifest_policy_version"):
        errors.append("runtime policy identity differs from the component lock")
    wheel_sha256 = kernel.get("wheel_sha256")
    if wheel_sha256 != runtime_lock.get("expected_release_wheel_sha256"):
        errors.append("runtime release-wheel hash differs from the runtime lock")
    release_evidence = kernel_lock.get("release_evidence")
    if not isinstance(release_evidence, dict) or wheel_sha256 != release_evidence.get(
        "wheel_sha256"
    ):
        errors.append("runtime release-wheel hash differs from release evidence")

    cross_links = {
        "repository": "repository",
        "tag": "tag",
        "tag_object": "annotated_tag_object",
        "commit": "commit",
        "package_version": "package_version",
        "plugin_version": "plugin_version",
        "source_manifest_sha256": "source_manifest_sha256",
        "release_manifest_sha256": "release_manifest_sha256",
    }
    for authority_key, lock_key in cross_links.items():
        if kernel.get(authority_key) != kernel_lock.get(lock_key):
            errors.append(f"runtime kernel identity drifted: {authority_key}")
    schemas = kernel.get("schema_sha256")
    locked_schemas = kernel_lock.get("public_schema_sha256")
    if not isinstance(schemas, dict) or not isinstance(locked_schemas, dict):
        errors.append("runtime Schema hash maps are invalid")
    elif {f"schemas/{name}": digest for name, digest in schemas.items()} != locked_schemas:
        errors.append("runtime Schema hashes differ from the valuation-kernel lock")
    return errors


def verify(
    wheel: Path,
    *,
    source_root: Path | None = None,
    expected_commit: str | None = None,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        trusted_root = source_root if source_root is not None else ROOT
        projection, expected_metadata, _pyproject_raw = _source_projection(
            trusted_root, expected_commit=expected_commit
        )
        errors.extend(_release_content_errors(projection))
        metadata_name = f"{DIST_INFO_STEM}/METADATA"
        record_name = f"{DIST_INFO_STEM}/RECORD"
        wheel_name = f"{DIST_INFO_STEM}/WHEEL"
        entry_points_name = f"{DIST_INFO_STEM}/entry_points.txt"
        expected_order = [
            *_trusted_wheel_member_order(projection),
            metadata_name,
            wheel_name,
            entry_points_name,
            record_name,
        ]
        expected_names = set(expected_order)
        metadata = wheel.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return ("wheel path is not a regular single-link non-symlink file",)
        if metadata.st_size > MAXIMUM_SOURCE_PROJECTION_BYTES:
            return ("wheel exceeds the cumulative release byte limit",)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(wheel, flags)
        try:
            before = os.fstat(descriptor)
            with os.fdopen(descriptor, "rb", closefd=False) as handle, ZipFile(handle) as archive:
                infos = archive.infolist()
                errors.extend(_zip_envelope_errors(descriptor, before.st_size, infos))
                ordered_names = [item.filename for item in infos]
                names = set(ordered_names)
                duplicate_members = len(ordered_names) != len(names)
                if duplicate_members:
                    errors.append("wheel contains duplicate archive members")
                if ordered_names != expected_order:
                    errors.append("wheel member order is not the exact trusted build order")
                if archive.comment:
                    errors.append("wheel archive comment is forbidden")
                uncompressed_size = sum(item.file_size for item in infos)
                if uncompressed_size > MAXIMUM_WHEEL_UNCOMPRESSED_BYTES:
                    errors.append("wheel exceeds the cumulative uncompressed byte limit")
                for item in infos:
                    logical = PurePosixPath(item.filename)
                    mode = item.external_attr >> 16
                    expected_mode = 0o644 if item.filename in EXPECTED_DIST_INFO else 0o100644
                    if (
                        not item.filename
                        or item.filename.startswith("/")
                        or "\\" in item.filename
                        or ".." in logical.parts
                        or item.is_dir()
                        or stat.S_ISLNK(mode)
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        or item.flag_bits & 0x1
                        or item.file_size > MAXIMUM_SOURCE_MEMBER_BYTES
                    ):
                        errors.append(f"wheel contains an unsafe member: {item.filename!r}")
                    if (
                        item.create_system != 3
                        or mode != expected_mode
                        or item.date_time != (2020, 2, 2, 0, 0, 0)
                        or item.compress_type != 8
                        or item.flag_bits != 0
                        or item.extra
                        or item.comment
                    ):
                        errors.append(
                            f"wheel member metadata drifted from the trusted build: {item.filename}"
                        )
                if (
                    uncompressed_size <= MAXIMUM_WHEEL_UNCOMPRESSED_BYTES
                    and archive.testzip() is not None
                ):
                    errors.append("wheel CRC verification failed")
                missing = sorted(expected_names - names)
                if missing:
                    errors.append(f"wheel is missing required entries: {missing}")
                dist_info = {name for name in names if ".dist-info/" in name}
                if names != expected_names or dist_info != EXPECTED_DIST_INFO:
                    errors.append("wheel member inventory is not the exact public projection")
                futu_members = {
                    name for name in names if name.startswith("owner_research/resources/futu/")
                }
                if futu_members != EXPECTED_FUTU_PUBLIC_RESOURCES:
                    errors.append(
                        "wheel Futu resource inventory is not the closed public projection"
                    )
                forbidden = sorted(
                    name
                    for name in names
                    if name.startswith(FORBIDDEN_PREFIXES)
                    or name.endswith(".html")
                    or name.lower().endswith(".whl")
                    or _forbidden_release_path(name)
                    or "owner_valuation" in PurePosixPath(name).parts
                    or (name.startswith(RUNTIME_RESOURCE_PREFIX) and name != RUNTIME_AUTHORITY)
                )
                if forbidden:
                    errors.append(
                        "wheel contains repository-only, private-kernel, or generated runtime "
                        f"content: {forbidden}"
                    )
                member_bytes: dict[str, bytes] = {}
                if not duplicate_members and uncompressed_size <= MAXIMUM_WHEEL_UNCOMPRESSED_BYTES:
                    for item in infos:
                        if item.file_size <= MAXIMUM_SOURCE_MEMBER_BYTES:
                            member_bytes[item.filename] = archive.read(item)
                for name, trusted_raw in projection.items():
                    wheel_raw = member_bytes.get(name)
                    if wheel_raw is not None and wheel_raw != trusted_raw:
                        errors.append(f"wheel member differs from trusted source bytes: {name}")
                if member_bytes.get(metadata_name) != expected_metadata:
                    errors.append("wheel METADATA is not the exact trusted project metadata")
                if member_bytes.get(wheel_name) != EXPECTED_WHEEL:
                    errors.append("wheel WHEEL metadata is not the exact trusted build identity")
                if member_bytes.get(entry_points_name) != EXPECTED_ENTRY_POINTS:
                    errors.append("wheel console entry points are not the exact closed interface")
                if names == expected_names and not duplicate_members:
                    expected_record = _record_bytes(member_bytes, ordered_names)
                    if member_bytes.get(record_name) != expected_record:
                        errors.append("wheel RECORD hashes, sizes, order, or member set drifted")
                if not duplicate_members and REQUIRED.issubset(names):
                    errors.extend(_runtime_binding_errors(archive))
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                errors.append("wheel changed while being verified")
        finally:
            os.close(descriptor)
    except (BadZipFile, KeyError, OSError, RuntimeError, ValueError) as exc:
        errors.append(f"wheel could not be verified: {exc}")
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--expected-commit")
    args = parser.parse_args()
    errors = verify(
        args.wheel,
        source_root=args.source_root,
        expected_commit=args.expected_commit,
    )
    for error in errors:
        print(error)
    if errors:
        return 1
    binding = f" at commit {args.expected_commit}" if args.expected_commit else ""
    print(f"wheel content verification passed{binding}: {args.wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
