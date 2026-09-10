from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import cast


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
    CASE_ASSIGN = "case:assign"
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
            Permission.CASE_ASSIGN,
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


class AuthenticationThrottled(AuthenticationError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many authentication attempts; try again later")
        self.retry_after = retry_after


class PasswordChangeRequired(AuthenticationError):
    """The session may only be used for changing the temporary password or logout."""


class AuthorizationError(RuntimeError):
    pass


class AuthStoreError(RuntimeError):
    pass


class UserNotFoundError(AuthStoreError):
    pass


class LoginChallengeError(AuthStoreError):
    pass


@dataclass(frozen=True, slots=True)
class UserRecord:
    user_id: str
    username: str
    display_name: str
    role: Role
    active: bool
    created_at: datetime
    must_change_password: bool = False


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    token: str
    expires_at: datetime
    user: UserRecord
    idle_timeout_seconds: int = 1800


@dataclass(frozen=True, slots=True)
class LoginChallenge:
    challenge_id: str
    answer: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AuthEvent:
    sequence: int
    actor_id: str | None
    subject: str
    action: str
    occurred_at: datetime
    details: dict[str, object]
    previous_hash: str
    event_hash: str


@dataclass(frozen=True, slots=True)
class AuthAuditVerification:
    valid: bool
    checked_events: int


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
        return f"forenx-scrypt-v1${self.N}${self.R}${self.P}${salt.hex()}${derived.hex()}"

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
    FAILURE_WINDOW = timedelta(minutes=15)
    ACCOUNT_FAILURE_LIMIT = 5
    GLOBAL_FAILURE_LIMIT = 50
    MAX_OUTSTANDING_CHALLENGES = 256

    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        session_lifetime: timedelta = timedelta(hours=8),
        idle_timeout: timedelta = timedelta(minutes=30),
        password_hasher: PasswordHasher | None = None,
    ) -> None:
        if session_lifetime <= timedelta(0) or session_lifetime > timedelta(days=7):
            raise ValueError("Session lifetime must be between zero and seven days")
        if idle_timeout < timedelta(seconds=1) or idle_timeout > timedelta(days=7):
            raise ValueError("Idle timeout must be between one second and seven days")
        self._session_lifetime = session_lifetime
        self._idle_timeout = idle_timeout
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
        with self._lock, self._write_transaction():
            statements = (
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    created_at TEXT NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0
                        CHECK(must_change_password IN (0, 1))
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    last_seen_at TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)",
                """
                CREATE TABLE IF NOT EXISTS auth_failures (
                    account_key TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_auth_failures_account
                ON auth_failures(account_key, occurred_at)
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_auth_failures_time ON auth_failures(occurred_at)
                """,
                """
                CREATE TABLE IF NOT EXISTS login_challenges (
                    challenge_hash TEXT PRIMARY KEY,
                    answer TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS idx_login_challenges_expiry
                ON login_challenges(expires_at)
                """,
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    sequence INTEGER PRIMARY KEY,
                    actor_id TEXT,
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    details TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                )
                """,
                """
                CREATE TRIGGER IF NOT EXISTS auth_events_no_update
                BEFORE UPDATE ON auth_events BEGIN
                    SELECT RAISE(ABORT, 'Authentication events are append-only');
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS auth_events_no_delete
                BEFORE DELETE ON auth_events BEGIN
                    SELECT RAISE(ABORT, 'Authentication events are append-only');
                END
                """,
            )
            for statement in statements:
                self._connection.execute(statement)
            user_columns = {
                str(row["name"]) for row in self._connection.execute("PRAGMA table_info(users)")
            }
            if "must_change_password" not in user_columns:
                self._connection.execute(
                    "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL "
                    "DEFAULT 0 CHECK(must_change_password IN (0, 1))"
                )
            session_columns = {
                str(row["name"]) for row in self._connection.execute("PRAGMA table_info(sessions)")
            }
            if "last_seen_at" not in session_columns:
                self._connection.execute("ALTER TABLE sessions ADD COLUMN last_seen_at TEXT")
                self._connection.execute("UPDATE sessions SET last_seen_at = created_at")

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        # An immediate write lock also serializes independent AuthStore connections.
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except AuthenticationError:
            # Authentication failures intentionally persist counters and audit events.
            self._connection.commit()
            raise
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def count_users(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"]) if row is not None else 0

    def issue_login_challenge(self, *, now: datetime | None = None) -> LoginChallenge:
        current_time = now or datetime.now(UTC)
        expires_at = current_time + timedelta(minutes=2)
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        answer = "".join(secrets.choice(alphabet) for _ in range(6))
        token = secrets.token_urlsafe(32)
        with self._lock, self._write_transaction():
            self._connection.execute(
                "DELETE FROM login_challenges WHERE expires_at <= ?",
                (_normalized_time(current_time),),
            )
            count = self._connection.execute(
                "SELECT COUNT(*) AS count FROM login_challenges"
            ).fetchone()
            if (
                count is not None
                and int(count["count"]) >= self.MAX_OUTSTANDING_CHALLENGES
            ):
                raise AuthStoreError("Login verification is temporarily unavailable")
            self._connection.execute(
                "INSERT INTO login_challenges(challenge_hash, answer, expires_at) "
                "VALUES (?, ?, ?)",
                (_token_hash(token), answer, _normalized_time(expires_at)),
            )
        return LoginChallenge(token, answer, expires_at)

    def consume_login_challenge(
        self, challenge_id: str, answer: str, *, now: datetime | None = None
    ) -> None:
        current_time = now or datetime.now(UTC)
        if not challenge_id or len(challenge_id) > 256:
            raise LoginChallengeError("Login verification failed")
        valid = False
        challenge_hash = _token_hash(challenge_id)
        with self._lock, self._write_transaction():
            row = self._connection.execute(
                "SELECT answer, expires_at FROM login_challenges WHERE challenge_hash = ?",
                (challenge_hash,),
            ).fetchone()
            if row is not None:
                self._connection.execute(
                    "DELETE FROM login_challenges WHERE challenge_hash = ?",
                    (challenge_hash,),
                )
                valid = (
                    _parsed_time(str(row["expires_at"])) > current_time
                    and hmac.compare_digest(str(row["answer"]), answer.strip().upper())
                )
        if not valid:
            raise LoginChallengeError("Login verification failed")

    def get_user(self, user_id: str) -> UserRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            raise UserNotFoundError("User was not found")
        return _user_from_row(row)

    def list_users(self) -> tuple[UserRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM users ORDER BY display_name COLLATE NOCASE, user_id"
            ).fetchall()
        return tuple(_user_from_row(row) for row in rows)

    def bootstrap_administrator(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        occurred_at: datetime | None = None,
    ) -> UserRecord:
        with self._lock, self._write_transaction():
            row = self._connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
            if row is not None and int(row["count"]) != 0:
                raise AuthStoreError("Administrator bootstrap is disabled after first user")
            user = self._create_user(
                username=username,
                display_name=display_name,
                password=password,
                role=Role.ADMINISTRATOR,
                occurred_at=occurred_at,
            )
            self._append_event(
                actor_id=user.user_id,
                subject=user.user_id,
                action="ADMINISTRATOR_BOOTSTRAPPED",
                now=user.created_at,
            )
            return user

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        role: Role,
        occurred_at: datetime | None = None,
        actor_id: str | None = None,
        must_change_password: bool = False,
    ) -> UserRecord:
        with self._lock, self._write_transaction():
            if actor_id is not None:
                self._require_administrator(actor_id)
            user = self._create_user(
                username=username,
                display_name=display_name,
                password=password,
                role=role,
                occurred_at=occurred_at,
                must_change_password=must_change_password,
            )
            self._append_event(
                actor_id=actor_id,
                subject=user.user_id,
                action="USER_CREATED",
                now=user.created_at,
                details={"role": role.value, "must_change_password": must_change_password},
            )
            return user

    def _create_user(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        role: Role,
        occurred_at: datetime | None,
        must_change_password: bool = False,
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
                    user_id, username, display_name, password_hash, role, active, created_at,
                    must_change_password
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    user_id,
                    normalized_username,
                    display_name.strip(),
                    password_hash,
                    role.value,
                    created,
                    int(must_change_password),
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
            must_change_password=must_change_password,
        )

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        now: datetime | None = None,
    ) -> AuthenticatedSession:
        try:
            normalized_username = _normalized_username(username)
        except ValueError:
            normalized_username = ""
        authentication_time = now or datetime.now(UTC)
        _normalized_time(authentication_time)
        with self._lock, self._write_transaction():
            row = self._connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (normalized_username,),
            ).fetchone()
            self._check_password(
                row, normalized_username, password, authentication_time, purpose="login"
            )
            if row is None:  # _check_password always raises for a missing user.
                raise AuthenticationError("Invalid username or password")
            token = secrets.token_urlsafe(32)
            token_hash = _token_hash(token)
            expires_at = authentication_time + self._session_lifetime
            self._connection.execute(
                """
                INSERT INTO sessions(
                    token_hash, user_id, created_at, expires_at, revoked_at, last_seen_at
                ) VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (
                    token_hash,
                    str(row["user_id"]),
                    _normalized_time(authentication_time),
                    _normalized_time(expires_at),
                    _normalized_time(authentication_time),
                ),
            )
            self._append_event(
                actor_id=str(row["user_id"]),
                subject=str(row["user_id"]),
                action="LOGIN_SUCCEEDED",
                now=authentication_time,
                details={"password_change_required": bool(row["must_change_password"])},
            )
        return AuthenticatedSession(
            token, expires_at, _user_from_row(row), int(self._idle_timeout.total_seconds())
        )

    def resolve_session(
        self,
        token: str,
        *,
        now: datetime | None = None,
        allow_password_change: bool = False,
    ) -> UserRecord:
        if not token or len(token) > 512:
            raise AuthenticationError("Session is invalid or expired")
        current_time = now or datetime.now(UTC)
        current = _normalized_time(current_time)
        with self._lock, self._write_transaction():
            row = self._connection.execute(
                """
                SELECT users.* FROM sessions
                JOIN users ON users.user_id = sessions.user_id
                WHERE sessions.token_hash = ?
                  AND sessions.revoked_at IS NULL
                  AND sessions.expires_at > ?
                  AND sessions.created_at <= ?
                  AND sessions.last_seen_at > ?
                  AND users.active = 1
                """,
                (
                    _token_hash(token),
                    current,
                    current,
                    _normalized_time(current_time - self._idle_timeout),
                ),
            ).fetchone()
            if row is None:
                raise AuthenticationError("Session is invalid or expired")
            user = _user_from_row(row)
            if user.must_change_password and not allow_password_change:
                raise PasswordChangeRequired("Change your temporary password before continuing")
            self._connection.execute(
                "UPDATE sessions SET last_seen_at = MAX(last_seen_at, ?) WHERE token_hash = ?",
                (current, _token_hash(token)),
            )
            return user

    def revoke_session(self, token: str, *, now: datetime | None = None) -> None:
        if not token or len(token) > 512:
            raise AuthenticationError("Session is invalid or expired")
        current_time = now or datetime.now(UTC)
        revoked_at = _normalized_time(current_time)
        with self._lock, self._write_transaction():
            row = self._connection.execute(
                "SELECT user_id, revoked_at FROM sessions WHERE token_hash = ?",
                (_token_hash(token),),
            ).fetchone()
            if row is None:
                raise AuthenticationError("Session is invalid or expired")
            if row["revoked_at"] is not None:
                return
            self._connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE token_hash = ? AND revoked_at IS NULL
                """,
                (revoked_at, _token_hash(token)),
            )
            self._append_event(
                actor_id=str(row["user_id"]),
                subject=str(row["user_id"]),
                action="SESSION_REVOKED",
                now=current_time,
            )

    def revoke_all_sessions(self, user_id: str, *, now: datetime | None = None) -> None:
        current_time = now or datetime.now(UTC)
        with self._lock, self._write_transaction():
            self.get_user(user_id)
            self._revoke_user_sessions(user_id, current_time)
            self._append_event(
                actor_id=user_id,
                subject=user_id,
                action="ALL_SESSIONS_REVOKED",
                now=current_time,
            )

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        *,
        now: datetime | None = None,
    ) -> None:
        current_time = now or datetime.now(UTC)
        with self._lock, self._write_transaction():
            row = self._get_user_row(user_id)
            self._check_password(
                row, str(row["username"]), current_password, current_time, purpose="password-change"
            )
            if current_password == new_password:
                raise ValueError("New password must differ from your current password")
            encoded = self._password_hasher.hash(new_password)
            self._connection.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE user_id = ?",
                (encoded, user_id),
            )
            self._revoke_user_sessions(user_id, current_time)
            self._append_event(
                actor_id=user_id,
                subject=user_id,
                action="PASSWORD_CHANGED",
                now=current_time,
            )

    def set_user_active(
        self,
        actor_id: str,
        user_id: str,
        active: bool,
        current_password: str,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> UserRecord:
        current_time = now or datetime.now(UTC)
        reason = _validated_reason(reason)
        with self._lock, self._write_transaction():
            self._reauthenticate_administrator(actor_id, current_password, current_time)
            target = self.get_user(user_id)
            if not active:
                if user_id == actor_id:
                    raise AuthStoreError("Administrators cannot suspend their own account")
                self._protect_last_administrator(target)
            self._connection.execute(
                "UPDATE users SET active = ? WHERE user_id = ?", (int(active), user_id)
            )
            if not active:
                self._revoke_user_sessions(user_id, current_time)
            self._append_event(
                actor_id=actor_id,
                subject=user_id,
                action="USER_ACTIVATED" if active else "USER_SUSPENDED",
                now=current_time,
                details={"reason": reason},
            )
            return self.get_user(user_id)

    def reset_password(
        self,
        actor_id: str,
        user_id: str,
        new_password: str,
        current_password: str,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> UserRecord:
        current_time = now or datetime.now(UTC)
        reason = _validated_reason(reason)
        with self._lock, self._write_transaction():
            self._reauthenticate_administrator(actor_id, current_password, current_time)
            target = self.get_user(user_id)
            if user_id == actor_id:
                raise AuthStoreError("Use password change to update your own password")
            if not target.active:
                raise AuthStoreError("Activate the account before resetting its password")
            self._protect_last_administrator(target)
            row = self._get_user_row(user_id)
            if self._password_hasher.verify(new_password, str(row["password_hash"])):
                raise ValueError("New password must differ from the existing password")
            encoded = self._password_hasher.hash(new_password)
            self._connection.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 1 WHERE user_id = ?",
                (encoded, user_id),
            )
            self._revoke_user_sessions(user_id, current_time)
            self._clear_account_failures(target.username)
            self._append_event(
                actor_id=actor_id,
                subject=user_id,
                action="PASSWORD_RESET",
                now=current_time,
                details={"reason": reason},
            )
            return self.get_user(user_id)

    def revoke_user_sessions(
        self,
        actor_id: str,
        user_id: str,
        current_password: str,
        reason: str,
        *,
        now: datetime | None = None,
    ) -> None:
        current_time = now or datetime.now(UTC)
        reason = _validated_reason(reason)
        with self._lock, self._write_transaction():
            self._reauthenticate_administrator(actor_id, current_password, current_time)
            self.get_user(user_id)
            self._revoke_user_sessions(user_id, current_time)
            self._append_event(
                actor_id=actor_id,
                subject=user_id,
                action="USER_SESSIONS_REVOKED",
                now=current_time,
                details={"reason": reason},
            )

    def recover_administrator(
        self, username: str, new_password: str, *, now: datetime | None = None
    ) -> UserRecord:
        """Offline operator recovery; never expose this method through HTTP."""
        current_time = now or datetime.now(UTC)
        normalized = _normalized_username(username)
        with self._lock, self._write_transaction():
            row = self._connection.execute(
                "SELECT * FROM users WHERE username = ?", (normalized,)
            ).fetchone()
            if row is None or Role(row["role"]) is not Role.ADMINISTRATOR:
                raise AuthStoreError("Recovery requires an existing administrator account")
            user_id = str(row["user_id"])
            encoded = self._password_hasher.hash(new_password)
            self._connection.execute(
                "UPDATE users SET password_hash = ?, active = 1, must_change_password = 0 "
                "WHERE user_id = ?",
                (encoded, user_id),
            )
            self._revoke_user_sessions(user_id, current_time)
            self._clear_account_failures(normalized)
            self._append_event(
                actor_id="local-operator",
                subject=user_id,
                action="ADMINISTRATOR_RECOVERED",
                now=current_time,
            )
            return self.get_user(user_id)

    def _get_user_row(self, user_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        if row is None:
            raise UserNotFoundError("User was not found")
        return cast(sqlite3.Row, row)

    def _require_administrator(self, actor_id: str) -> sqlite3.Row:
        row = self._get_user_row(actor_id)
        if (
            Role(row["role"]) is not Role.ADMINISTRATOR
            or not bool(row["active"])
            or bool(row["must_change_password"])
        ):
            raise AuthorizationError(
                "An active administrator with a permanent password is required"
            )
        return row

    def _reauthenticate_administrator(
        self, actor_id: str, current_password: str, now: datetime
    ) -> None:
        row = self._require_administrator(actor_id)
        self._check_password(
            row, str(row["username"]), current_password, now, purpose="administrator-action"
        )

    def _protect_last_administrator(self, user: UserRecord) -> None:
        if user.role is Role.ADMINISTRATOR and user.active and not user.must_change_password:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = ? AND active = 1 "
                "AND must_change_password = 0",
                (Role.ADMINISTRATOR.value,),
            ).fetchone()
            if row is None or int(row["count"]) <= 1:
                raise AuthStoreError("The last active administrator must remain available")

    def _revoke_user_sessions(self, user_id: str, now: datetime) -> None:
        self._connection.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (_normalized_time(now), user_id),
        )

    def _clear_account_failures(self, username: str) -> None:
        # Keep failures in the global bucket: success must not reset spray protection.
        self._connection.execute(
            "UPDATE auth_failures SET account_key = '' WHERE account_key = ?",
            (_account_key(username),),
        )

    def _check_password(
        self,
        row: sqlite3.Row | None,
        username: str,
        password: str,
        now: datetime,
        *,
        purpose: str,
    ) -> None:
        current = _normalized_time(now)
        cutoff = _normalized_time(now - self.FAILURE_WINDOW)
        self._connection.execute("DELETE FROM auth_failures WHERE occurred_at <= ?", (cutoff,))
        key = _account_key(username)
        failures = self._connection.execute(
            "SELECT account_key, occurred_at FROM auth_failures ORDER BY occurred_at"
        ).fetchall()
        account_failures = [failure for failure in failures if failure["account_key"] == key]
        retry_times = []
        if len(account_failures) >= self.ACCOUNT_FAILURE_LIMIT:
            retry_times.append(_parsed_time(str(account_failures[0]["occurred_at"])))
        if len(failures) >= self.GLOBAL_FAILURE_LIMIT:
            retry_times.append(_parsed_time(str(failures[0]["occurred_at"])))
        if retry_times:
            retry_after = max(
                1, math.ceil((max(retry_times) + self.FAILURE_WINDOW - now).total_seconds())
            )
            self._append_event(
                actor_id=None,
                subject=username,
                action="AUTHENTICATION_THROTTLED",
                now=now,
                details={"purpose": purpose, "retry_after": retry_after},
            )
            raise AuthenticationThrottled(retry_after)
        encoded = (
            str(row["password_hash"])
            if row is not None
            else "forenx-scrypt-v1$16384$8$1$"
            "00000000000000000000000000000000$"
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        valid = self._password_hasher.verify(password, encoded)
        if row is None or not bool(row["active"]) or not valid:
            self._connection.execute(
                "INSERT INTO auth_failures(account_key, occurred_at) VALUES (?, ?)", (key, current)
            )
            self._append_event(
                actor_id=None,
                subject=username,
                action="LOGIN_FAILED" if purpose == "login" else "REAUTHENTICATION_FAILED",
                now=now,
                details={"purpose": purpose},
            )
            raise AuthenticationError("Invalid username or password")
        self._clear_account_failures(username)

    def _append_event(
        self,
        *,
        actor_id: str | None,
        subject: str,
        action: str,
        now: datetime,
        details: dict[str, object] | None = None,
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, event_hash FROM auth_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous is not None else 1
        previous_hash = str(previous["event_hash"]) if previous is not None else "0" * 64
        occurred_at = _normalized_time(now)
        event_details = details or {}
        event_hash = _event_digest(
            sequence, actor_id, subject, action, occurred_at, event_details, previous_hash
        )
        self._connection.execute(
            "INSERT INTO auth_events(sequence, actor_id, subject, action, occurred_at, "
            "details, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                actor_id,
                subject,
                action,
                occurred_at,
                json.dumps(event_details, sort_keys=True, separators=(",", ":")),
                previous_hash,
                event_hash,
            ),
        )

    def list_auth_events(
        self, limit: int = 100, before: int | None = None
    ) -> tuple[AuthEvent, ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("Audit event limit must be between 1 and 1000")
        if before is not None and before < 1:
            raise ValueError("Audit cursor must be a positive sequence number")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM auth_events WHERE (? IS NULL OR sequence < ?) "
                "ORDER BY sequence DESC LIMIT ?",
                (before, before, limit),
            ).fetchall()
        return tuple(_auth_event_from_row(row) for row in rows)

    def verify_auth_events(self) -> AuthAuditVerification:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM auth_events ORDER BY sequence"
            ).fetchall()
        previous_hash = "0" * 64
        checked = 0
        for row in rows:
            try:
                event = _auth_event_from_row(row)
                expected = _event_digest(
                    event.sequence,
                    event.actor_id,
                    event.subject,
                    event.action,
                    str(row["occurred_at"]),
                    event.details,
                    event.previous_hash,
                )
                valid = (
                    event.sequence == checked + 1
                    and event.previous_hash == previous_hash
                    and hmac.compare_digest(event.event_hash, expected)
                )
            except (ValueError, TypeError):
                return AuthAuditVerification(False, checked)
            if not valid:
                return AuthAuditVerification(False, checked)
            previous_hash = event.event_hash
            checked += 1
        return AuthAuditVerification(True, checked)


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
    if any(character.isspace() or not character.isprintable() for character in normalized):
        raise ValueError("Username cannot contain spaces or control characters")
    return normalized


def _account_key(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8")).hexdigest()


def _validated_reason(reason: str) -> str:
    normalized = reason.strip()
    if not normalized or len(normalized) > 1000:
        raise ValueError("A reason containing between 1 and 1000 characters is required")
    return normalized


def _event_digest(
    sequence: int,
    actor_id: str | None,
    subject: str,
    action: str,
    occurred_at: str,
    details: dict[str, object],
    previous_hash: str,
) -> str:
    payload = {
        "sequence": sequence,
        "actor_id": actor_id,
        "subject": subject,
        "action": action,
        "occurred_at": occurred_at,
        "details": details,
        "previous_hash": previous_hash,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _auth_event_from_row(row: sqlite3.Row) -> AuthEvent:
    details = json.loads(str(row["details"]))
    if not isinstance(details, dict):
        raise ValueError("Authentication event details must be an object")
    return AuthEvent(
        sequence=int(row["sequence"]),
        actor_id=str(row["actor_id"]) if row["actor_id"] is not None else None,
        subject=str(row["subject"]),
        action=str(row["action"]),
        occurred_at=_parsed_time(str(row["occurred_at"])),
        details=details,
        previous_hash=str(row["previous_hash"]),
        event_hash=str(row["event_hash"]),
    )


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
        must_change_password=bool(row["must_change_password"]),
    )
