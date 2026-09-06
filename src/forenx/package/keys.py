from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class KeyManagementError(RuntimeError):
    """Raised when a signing key cannot be stored or loaded safely."""


def generate_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_fingerprint(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes_raw()
    return hashlib.sha256(public_bytes).hexdigest()


def save_private_key(
    private_key: Ed25519PrivateKey,
    destination: str | Path,
    *,
    password: bytes,
) -> Path:
    if len(password) < 12:
        raise KeyManagementError("Signing-key password must contain at least 12 bytes")
    target = _safe_new_path(destination)
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    _write_exclusive(target, key_bytes, mode=0o600)
    return target


def load_private_key(path: str | Path, *, password: bytes) -> Ed25519PrivateKey:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise KeyManagementError("Signing key cannot be loaded through a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise KeyManagementError("Signing key does not exist") from exc
    if not resolved.is_file():
        raise KeyManagementError("Signing key must be a regular file")
    if stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise KeyManagementError("Signing key permissions must not allow group or public access")
    if resolved.stat().st_size > 64 * 1024:
        raise KeyManagementError("Signing key file exceeds the safety limit")

    try:
        loaded = serialization.load_pem_private_key(resolved.read_bytes(), password=password)
    except (TypeError, ValueError) as exc:
        raise KeyManagementError("Signing key or password is invalid") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise KeyManagementError("Signing key is not an Ed25519 private key")
    return loaded


def _safe_new_path(destination: str | Path) -> Path:
    path = Path(destination).expanduser()
    if not path.name:
        raise KeyManagementError("Signing-key destination requires a file name")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise KeyManagementError("Signing-key destination directory does not exist") from exc
    if not parent.is_dir():
        raise KeyManagementError("Signing-key destination parent is not a directory")
    return parent / path.name


def _write_exclusive(target: Path, data: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, mode)
    except FileExistsError as exc:
        raise KeyManagementError("Signing-key destination already exists") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise KeyManagementError("Signing-key destination returned a short write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        target.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
