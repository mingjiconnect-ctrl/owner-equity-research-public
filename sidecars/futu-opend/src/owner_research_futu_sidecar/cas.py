from __future__ import annotations

import os
import stat
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import (
    SidecarContractError,
    bytes_sha256,
    canonical_bytes,
    expected_resolved_local_path,
    require_sha256,
)

CAS_MAGIC = b"OERFUTUCASv1\0\0\0\0"
MAXIMUM_CAS_OBJECT_BYTES = 16 * 1024 * 1024
MAXIMUM_KEY_ID_BYTES = 128
MAXIMUM_ENCRYPTED_OBJECT_BYTES = (
    len(CAS_MAGIC) + 2 + MAXIMUM_KEY_ID_BYTES + 12 + MAXIMUM_CAS_OBJECT_BYTES + 16
)


class CasError(SidecarContractError):
    """Raised when private encrypted CAS invariants fail."""


@dataclass(frozen=True, slots=True)
class CasReceipt:
    raw_plaintext_sha256: str
    encrypted_object_sha256: str
    cas_locator: str
    envelope_key_id: str
    raw_byte_count: int

    def __post_init__(self) -> None:
        raw = require_sha256(self.raw_plaintext_sha256, "raw plaintext SHA-256")
        encrypted = require_sha256(
            self.encrypted_object_sha256, "encrypted object SHA-256"
        )
        if (
            raw == encrypted
            or self.cas_locator != f"cas://sha256/{encrypted}"
            or not isinstance(self.envelope_key_id, str)
            or not 1 <= len(self.envelope_key_id.encode("utf-8")) <= MAXIMUM_KEY_ID_BYTES
            or type(self.raw_byte_count) is not int
            or not 1 <= self.raw_byte_count <= MAXIMUM_CAS_OBJECT_BYTES
        ):
            raise CasError("CAS receipt does not bind one encrypted raw object")

    def to_dict(self) -> dict[str, str | int]:
        return {
            "raw_plaintext_sha256": self.raw_plaintext_sha256,
            "encrypted_object_sha256": self.encrypted_object_sha256,
            "cas_locator": self.cas_locator,
            "envelope_key_id": self.envelope_key_id,
            "raw_byte_count": self.raw_byte_count,
        }


class EncryptedCas:
    """Small private AES-256-GCM content-addressed store.

    The public locator is keyed by ciphertext, never plaintext.  Keys and nonces do not
    appear in public research artifacts; the nonce is retained inside the encrypted
    object envelope and the key is supplied by the isolated launcher.
    """

    def __init__(self, *, root: Path, key: bytes, key_id: str) -> None:
        root = Path(root)
        if not root.is_absolute() or "\0" in os.fspath(root):
            raise CasError("CAS root must be an absolute local path")
        if not isinstance(key, bytes) or len(key) != 32:
            raise CasError("CAS requires one exact 256-bit key")
        encoded_key_id = key_id.encode("utf-8") if isinstance(key_id, str) else b""
        if not encoded_key_id or len(encoded_key_id) > MAXIMUM_KEY_ID_BYTES:
            raise CasError("CAS envelope key ID is invalid")
        self.root = root
        self._key = key
        self.key_id = key_id
        self._validate_root()

    def _validate_root(self) -> None:
        try:
            root_stat = self.root.lstat()
            resolved = self.root.resolve(strict=True)
        except OSError as exc:
            raise CasError("CAS root is unavailable") from exc
        if (
            resolved != expected_resolved_local_path(self.root)
            or not stat.S_ISDIR(root_stat.st_mode)
        ):
            raise CasError("CAS root cannot be a symbolic link")
        if root_stat.st_uid != os.getuid() or root_stat.st_mode & 0o077:
            raise CasError("CAS root must be private to the runtime UID")

    def store(self, plaintext: bytes) -> CasReceipt:
        if not isinstance(plaintext, bytes) or not plaintext:
            raise CasError("CAS plaintext must be non-empty exact bytes")
        if len(plaintext) > MAXIMUM_CAS_OBJECT_BYTES:
            raise CasError("CAS plaintext exceeds the per-object byte limit")
        plaintext_sha = bytes_sha256(plaintext)
        key_id_bytes = self.key_id.encode("utf-8")
        nonce = os.urandom(12)
        aad = canonical_bytes(
            {
                "schema_version": "1.0.0",
                "envelope_key_id": self.key_id,
                "raw_plaintext_sha256": plaintext_sha,
                "raw_byte_count": len(plaintext),
            }
        )
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, aad)
        blob = (
            CAS_MAGIC
            + struct.pack(">H", len(key_id_bytes))
            + key_id_bytes
            + nonce
            + ciphertext
        )
        encrypted_sha = bytes_sha256(blob)
        if encrypted_sha == plaintext_sha:
            raise CasError("CAS ciphertext cannot reuse the plaintext identity")
        self._atomic_store(encrypted_sha, blob)
        return CasReceipt(
            raw_plaintext_sha256=plaintext_sha,
            encrypted_object_sha256=encrypted_sha,
            cas_locator=f"cas://sha256/{encrypted_sha}",
            envelope_key_id=self.key_id,
            raw_byte_count=len(plaintext),
        )

    def load(self, receipt: CasReceipt) -> bytes:
        if not isinstance(receipt, CasReceipt):
            raise CasError("CAS reload requires the exact receipt type")
        encrypted_sha = require_sha256(
            receipt.encrypted_object_sha256, "encrypted object SHA-256"
        )
        if receipt.cas_locator != f"cas://sha256/{encrypted_sha}":
            raise CasError("CAS locator does not bind the encrypted object")
        path = self.root / encrypted_sha[:2] / encrypted_sha
        blob = self._read_member(path)
        if bytes_sha256(blob) != encrypted_sha:
            raise CasError("CAS ciphertext hash does not replay")
        if not blob.startswith(CAS_MAGIC):
            raise CasError("CAS object envelope magic is invalid")
        try:
            offset = len(CAS_MAGIC)
            key_id_size = struct.unpack(">H", blob[offset : offset + 2])[0]
            if not 1 <= key_id_size <= MAXIMUM_KEY_ID_BYTES:
                raise CasError("CAS object key ID length is invalid")
            offset += 2
            key_id = blob[offset : offset + key_id_size].decode("utf-8")
            offset += key_id_size
            nonce = blob[offset : offset + 12]
            ciphertext = blob[offset + 12 :]
        except (struct.error, UnicodeDecodeError) as exc:
            raise CasError("CAS object envelope is truncated or malformed") from exc
        if key_id != self.key_id or len(nonce) != 12 or not ciphertext:
            raise CasError("CAS object envelope is rebound")
        aad = canonical_bytes(
            {
                "schema_version": "1.0.0",
                "envelope_key_id": receipt.envelope_key_id,
                "raw_plaintext_sha256": receipt.raw_plaintext_sha256,
                "raw_byte_count": receipt.raw_byte_count,
            }
        )
        try:
            plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise CasError("CAS object authentication failed") from exc
        if (
            len(plaintext) != receipt.raw_byte_count
            or bytes_sha256(plaintext) != receipt.raw_plaintext_sha256
        ):
            raise CasError("CAS plaintext identity does not replay")
        return plaintext

    def _atomic_store(self, digest: str, blob: bytes) -> None:
        shard = self.root / digest[:2]
        try:
            shard.mkdir(mode=0o700, exist_ok=True)
            os.chmod(shard, 0o700)
        except OSError as exc:
            raise CasError("CAS shard cannot be created") from exc
        shard_stat = shard.lstat()
        if (
            shard.resolve(strict=True) != expected_resolved_local_path(shard)
            or not stat.S_ISDIR(shard_stat.st_mode)
            or shard_stat.st_uid != os.getuid()
            or shard_stat.st_mode & 0o077
        ):
            raise CasError("CAS shard is not private and owner-controlled")
        destination = shard / digest
        temporary = shard / f".{digest}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(temporary, flags, 0o400)
            view = memoryview(blob)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CasError("CAS object write did not make progress")
                view = view[written:]
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            try:
                os.link(temporary, destination, follow_symlinks=False)
            except FileExistsError:
                existing = self._read_member(destination)
                if existing != blob:
                    raise CasError("CAS digest collision or rebound object") from None
            temporary.unlink()
            destination_stat = destination.lstat()
            descriptor_stat = os.fstat(descriptor)
            if (
                destination_stat.st_dev != descriptor_stat.st_dev
                or destination_stat.st_ino != descriptor_stat.st_ino
            ):
                existing = self._read_member(destination)
                if existing != blob:
                    raise CasError("CAS publication destination was replaced")
            else:
                self._validate_member_stat(descriptor_stat)
            directory_descriptor = os.open(shard, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except (OSError, CasError) as exc:
            try:
                temporary.unlink()
            except OSError:
                pass
            if isinstance(exc, CasError):
                raise
            raise CasError("CAS atomic write failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _validate_member(self, path: Path) -> None:
        try:
            member_stat = path.lstat()
        except OSError as exc:
            raise CasError("CAS member is unavailable") from exc
        if path.resolve(strict=True) != expected_resolved_local_path(path):
            raise CasError("CAS member is not immutable and owner-controlled")
        self._validate_member_stat(member_stat)

    @staticmethod
    def _validate_member_stat(member_stat: os.stat_result) -> None:
        if (
            not stat.S_ISREG(member_stat.st_mode)
            or member_stat.st_uid != os.getuid()
            or stat.S_IMODE(member_stat.st_mode) != 0o400
            or member_stat.st_nlink != 1
        ):
            raise CasError("CAS member is not immutable and singly linked")

    def _read_member(self, path: Path) -> bytes:
        try:
            path_before = path.lstat()
            self._validate_member_stat(path_before)
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as exc:
            raise CasError("CAS encrypted object cannot be opened safely") from exc
        try:
            before = os.fstat(descriptor)
            if (
                before.st_dev != path_before.st_dev
                or before.st_ino != path_before.st_ino
            ):
                raise CasError("CAS member changed before it was opened")
            self._validate_member_stat(before)
            value = _read_bounded(descriptor, MAXIMUM_ENCRYPTED_OBJECT_BYTES)
            after = os.fstat(descriptor)
            self._validate_member_stat(after)
            path_after = path.lstat()
            self._validate_member_stat(path_after)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
                or after.st_dev != path_after.st_dev
                or after.st_ino != path_after.st_ino
                or len(value) != after.st_size
            ):
                raise CasError("CAS member changed while it was read")
            return value
        except OSError as exc:
            raise CasError("CAS encrypted object cannot be replayed") from exc
        finally:
            os.close(descriptor)


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > maximum:
        raise CasError("CAS encrypted object exceeds its byte limit")
    return value


__all__ = ("CasError", "CasReceipt", "EncryptedCas")
