from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path


class Role(StrEnum):
    INTAKE_OFFICER = "intake-officer"
    EXAMINER = "examiner"
    SUPERVISOR = "supervisor"
    INVESTIGATOR = "investigator"
    AUDITOR = "auditor"
    ADMINISTRATOR = "administrator"


class Permission(StrEnum):
    CASE_CREATE = "case:create"
    CASE_READ = "case:read"
    EXHIBIT_CREATE = "exhibit:create"
    EVIDENCE_INGEST = "evidence:ingest"
    CASE_PROCESS = "case:process"
    CASE_APPROVE = "case:approve"
    BIOMETRIC_AUTHORIZE = "biometric:authorize"
    USER_MANAGE = "user:manage"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.INTAKE_OFFICER: frozenset(
        {
            Permission.CASE_CREATE,
            Permission.CASE_READ,
            Permission.EXHIBIT_CREATE,
            Permission.EVIDENCE_INGEST,
        }
    ),
    Role.EXAMINER: frozenset({Permission.CASE_READ, Permission.CASE_PROCESS}),
    Role.SUPERVISOR: frozenset(
        {
            Permission.CASE_READ,
            Permission.CASE_PROCESS,
            Permission.CASE_APPROVE,
            Permission.BIOMETRIC_AUTHORIZE,
        }
    ),
    Role.INVESTIGATOR: frozenset({Permission.CASE_READ}),
    Role.AUDITOR: frozenset({Permission.CASE_READ}),
    Role.ADMINISTRATOR: frozenset(Permission),
}


class AuthenticationError(RuntimeError):
    """Generic authentication failure that does not disclose account existence."""


class AuthorizationError(RuntimeError):
    pass


class AuthStoreError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class UserRecord:
    user_id: str
    username: str
    display_name: str
    role: Role
    active: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    token: str
    expires_at: datetime
    user: UserRecord


class PasswordHasher:
    N = 2**14
    R = 8
    P = 1
    SALT_SIZE = 16
    KEY_SIZE = 32

    def hash(self, password: str) -> str:
        password_bytes = self._validate_password(password)
        salt = secrets.token_bytes(self.SALT_SIZE)
        derived = hashlib.scrypt(
            password_bytes,
            salt=salt,
            n=self.N,
            r=self.R,
            p=self.P,
            dklen=self.KEY_SIZE,
        )
        return (
            f"forenx-scrypt-v1${self.N}${self.R}${self.P}$"
            f"{salt.hex()}${derived.hex()}"
        )

    def verify(self, password: str, encoded: str) -> bool:
        try:
            password_bytes = password.encode("utf-8")
            if not password_bytes or len(password_bytes) > 1024:
                return False
            scheme, n_text, r_text, p_text, salt_hex, expected_hex = encoded.split("$")
            if scheme != "forenx-scrypt-v1":
                return False
            n = int(n_text)
            r = int(r_text)
            p = int(p_text)
            if (n, r, p) != (self.N, self.R, self.P):
                return False
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(expected_hex)
            if len(salt) != self.SALT_SIZE or len(expected) != self.KEY_SIZE:
                return False
            observed = hashlib.scrypt(
                password_bytes,
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=len(expected),
            )
        except (UnicodeError, ValueError):
            return False
        return hmac.compare_digest(observed, expected)

    @staticmethod
    def _validate_password(password: str) -> bytes:
        encoded = password.encode("utf-8")
        if len(encoded) < 12:
            raise ValueError("Password must contain at least 12 bytes")
        if len(encoded) > 1024:
            raise ValueError("Password exceeds the maximum length")
        return encoded


class AuthStore:
    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        session_lifetime: timedelta = timedelta(hours=8),
        password_hasher: PasswordHasher | None = None,
    ) -> None:
        if session_lifetime <= timedelta(0) or session_lifetime > timedelta(days=7):
            raise ValueError("Session lifetime must be between zero and seven days")
        self._session_lifetime = session_lifetime
        self._password_hasher = password_hasher or PasswordHasher()
        self._lock = threading.RLock()
        self._closed = False

        database_target, file_path = _database_target(database)
        self._connection = sqlite3.connect(
            database_target,
            check_same_thread=False,
            timeout=5,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if file_path is not None:
            self._connection.execute("PRAGMA journal_mode = WAL")
            os.chmod(file_path, 0o600)
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
                """
            )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def count_users(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"]) if row is not None else 0

    def bootstrap_administrator(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        occurred_at: datetime | None = None,
    ) -> UserRecord:
        with self._lock, self._connection:
            row = self._connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
            if row is not None and int(row["count"]) != 0:
                raise AuthStoreError("Administrator bootstrap is disabled after first user")
            return self._create_user(
                username=username,
                display_name=display_name,
                password=password,
                role=Role.ADMINISTRATOR,
                occurred_at=occurred_at,
            )

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        role: Role,
        occurred_at: datetime | None = None,
    ) -> UserRecord:
        with self._lock, self._connection:
            return self._create_user(
                username=username,
                display_name=display_name,
                password=password,
                role=role,
                occurred_at=occurred_at,
            )

    def _create_user(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        role: Role,
        occurred_at: datetime | None,
    ) -> UserRecord:
        normalized_username = _normalized_username(username)
        if not display_name.strip():
            raise ValueError("Display name cannot be empty")
        password_hash = self._password_hasher.hash(password)
        user_id = secrets.token_hex(16)
        created_at = occurred_at or datetime.now(UTC)
        created = _normalized_time(created_at)
        try:
            self._connection.execute(
                """
                INSERT INTO users(
                    user_id, username, display_name, password_hash, role, active, created_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?)
                """,
                (
                    user_id,
                    normalized_username,
                    display_name.strip(),
                    password_hash,
                    role.value,
                    created,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AuthStoreError("Username already exists") from exc
        return UserRecord(
            user_id=user_id,
            username=normalized_username,
            display_name=display_name.strip(),
            role=role,
            active=True,
            created_at=created_at.astimezone(UTC),
        )

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        now: datetime | None = None,
    ) -> AuthenticatedSession:
        normalized_username = _normalized_username(username)
        authentication_time = now or datetime.now(UTC)
        _normalized_time(authentication_time)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (normalized_username,),
            ).fetchone()
            if row is None:
                self._password_hasher.verify(
                    password,
                    "forenx-scrypt-v1$16384$8$1$"
                    "00000000000000000000000000000000$"
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                raise AuthenticationError("Invalid username or password")
            if not bool(row["active"]) or not self._password_hasher.verify(
                password, str(row["password_hash"])
            ):
                raise AuthenticationError("Invalid username or password")

            token = secrets.token_urlsafe(32)
            token_hash = _token_hash(token)
            expires_at = authentication_time + self._session_lifetime
            self._connection.execute(
                """
                INSERT INTO sessions(token_hash, user_id, created_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, NULL)
                """,
                (
                    token_hash,
                    str(row["user_id"]),
                    _normalized_time(authentication_time),
                    _normalized_time(expires_at),
                ),
            )
        return AuthenticatedSession(token, expires_at, _user_from_row(row))

    def resolve_session(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> UserRecord:
        if not token or len(token) > 512:
            raise AuthenticationError("Session is invalid or expired")
        current_time = now or datetime.now(UTC)
        current = _normalized_time(current_time)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT users.* FROM sessions
                JOIN users ON users.user_id = sessions.user_id
                WHERE sessions.token_hash = ?
                  AND sessions.revoked_at IS NULL
                  AND sessions.expires_at > ?
                  AND users.active = 1
                """,
                (_token_hash(token), current),
            ).fetchone()
        if row is None:
            raise AuthenticationError("Session is invalid or expired")
        return _user_from_row(row)

    def revoke_session(self, token: str, *, now: datetime | None = None) -> None:
        if not token or len(token) > 512:
            raise AuthenticationError("Session is invalid or expired")
        revoked_at = _normalized_time(now or datetime.now(UTC))
        with self._lock, self._connection:
            updated = self._connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (revoked_at, _token_hash(token)),
            )
        if updated.rowcount != 1:
            raise AuthenticationError("Session is invalid or expired")


def require_permission(user: UserRecord, permission: Permission) -> None:
    if permission not in ROLE_PERMISSIONS[user.role]:
        raise AuthorizationError(f"Role {user.role.value} lacks {permission.value}")


def _database_target(database: str | Path) -> tuple[str, Path | None]:
    if str(database) == ":memory:":
        return ":memory:", None
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise AuthStoreError("Authentication database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise AuthStoreError("Authentication database directory does not exist") from exc
    if not parent.is_dir():
        raise AuthStoreError("Authentication database parent is not a directory")
    resolved = parent / candidate.name
    return str(resolved), resolved


def _normalized_username(username: str) -> str:
    normalized = username.strip().casefold()
    if len(normalized) < 3 or len(normalized) > 64:
        raise ValueError("Username must contain between 3 and 64 characters")
    return normalized


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Authentication timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _user_from_row(row: sqlite3.Row) -> UserRecord:
    return UserRecord(
        user_id=str(row["user_id"]),
        username=str(row["username"]),
        display_name=str(row["display_name"]),
        role=Role(row["role"]),
        active=bool(row["active"]),
        created_at=_parsed_time(str(row["created_at"])),
    )
