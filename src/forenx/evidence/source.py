from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from types import TracebackType


class EvidenceSourceError(ValueError):
    """Raised when an evidence source cannot be read safely."""


class RawEvidenceSource:
    """Bounded, read-only random access to a single raw evidence image.

    `os.pread` keeps reads independent of a shared file cursor. The source is
    opened read-only and the descriptor is never exposed to adapter code.
    """

    DEFAULT_MAX_READ = 64 * 1024 * 1024

    def __init__(self, path: str | Path, *, max_read_size: int = DEFAULT_MAX_READ) -> None:
        self.path = Path(path).expanduser().resolve(strict=True)
        if not self.path.is_file():
            raise EvidenceSourceError("Evidence source must be a regular file")
        if isinstance(max_read_size, bool) or max_read_size <= 0:
            raise EvidenceSourceError("Maximum read size must be a positive integer")

        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        self._descriptor = os.open(self.path, flags)
        stat_result = os.fstat(self._descriptor)
        if not self.path.is_file():
            self.close()
            raise EvidenceSourceError("Evidence source must remain a regular file")
        self._size = stat_result.st_size
        self._max_read_size = max_read_size

    @property
    def size(self) -> int:
        return self._size

    @property
    def closed(self) -> bool:
        return self._descriptor < 0

    def close(self) -> None:
        if not self.closed:
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> RawEvidenceSource:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _validate_range(self, offset: int, length: int) -> None:
        if self.closed:
            raise EvidenceSourceError("Evidence source is closed")
        if isinstance(offset, bool) or isinstance(length, bool):
            raise EvidenceSourceError("Offset and length must be integers")
        if not isinstance(offset, int) or not isinstance(length, int):
            raise EvidenceSourceError("Offset and length must be integers")
        if offset < 0 or length < 0:
            raise EvidenceSourceError("Offset and length cannot be negative")
        if length > self._max_read_size:
            raise EvidenceSourceError("Requested read exceeds the configured safety limit")
        if offset > self._size or length > self._size - offset:
            raise EvidenceSourceError("Requested range is outside the evidence source")

    def read_at(self, offset: int, length: int) -> bytes:
        self._validate_range(offset, length)
        if length == 0:
            return b""
        data = os.pread(self._descriptor, length, offset)
        if len(data) != length:
            raise EvidenceSourceError("Unexpected short read from evidence source")
        return data

    def sha256(self, *, chunk_size: int = 8 * 1024 * 1024) -> str:
        if self.closed:
            raise EvidenceSourceError("Evidence source is closed")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise EvidenceSourceError("Hash chunk size must be a positive integer")

        digest = hashlib.sha256()
        position = 0
        while position < self._size:
            length = min(chunk_size, self._size - position)
            # Hash chunks may be larger than the adapter read limit only if explicitly requested.
            if length > self._max_read_size:
                length = self._max_read_size
            digest.update(self.read_at(position, length))
            position += length
        return digest.hexdigest()

    def verify_sha256(self, expected_digest: str) -> bool:
        normalized = expected_digest.strip().lower()
        if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
            raise EvidenceSourceError(
                "Expected SHA-256 digest must contain 64 hexadecimal characters"
            )
        return hmac.compare_digest(self.sha256(), normalized)
