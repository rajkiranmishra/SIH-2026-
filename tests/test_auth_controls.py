from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forenx.auth import (
    AuthenticationError,
    AuthenticationThrottled,
    AuthorizationError,
    AuthStore,
    AuthStoreError,
    LoginChallengeError,
    PasswordChangeRequired,
    PasswordHasher,
    Role,
    UserNotFoundError,
)

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
PASSWORD = "administrator original password"
USER_PASSWORD = "examiner original password"
NEW_PASSWORD = "a different strong password"


def bootstrap(store: AuthStore):
    return store.bootstrap_administrator(
        username="Administrator", display_name="Administrator", password=PASSWORD, occurred_at=NOW
    )


def test_login_challenge_expires_and_is_consumed_once():
    store = AuthStore()
    challenge = store.issue_login_challenge(now=NOW)
    with pytest.raises(LoginChallengeError, match="verification"):
        store.consume_login_challenge(
            challenge.challenge_id, challenge.answer, now=NOW + timedelta(minutes=3),
        )
    with pytest.raises(LoginChallengeError, match="verification"):
        store.consume_login_challenge(challenge.challenge_id, challenge.answer, now=NOW)


def test_login_challenge_issuance_is_bounded_and_recovers_after_expiry():
    store = AuthStore()
    for _ in range(store.MAX_OUTSTANDING_CHALLENGES):
        store.issue_login_challenge(now=NOW)
    with pytest.raises(AuthStoreError, match="temporarily unavailable"):
        store.issue_login_challenge(now=NOW)
    assert store.issue_login_challenge(now=NOW + timedelta(minutes=3)).challenge_id


def create_user(store: AuthStore, *, name="examiner", role=Role.EXAMINER, temporary=False):
    return store.create_user(
        username=name,
        display_name=name.title(),
        password=USER_PASSWORD,
        role=role,
        must_change_password=temporary,
        occurred_at=NOW,
    )


def login(store: AuthStore, *, username="administrator", password=PASSWORD, now=NOW):
    return store.authenticate(username=username, password=password, now=now)


def test_failed_login_budget_persists_across_restart_and_normalizes_aliases(tmp_path: Path):
    database = tmp_path / "auth.db"
    store = AuthStore(database)
    bootstrap(store)
    aliases = [
        "Administrator",
        " administrator ",
        "ADMINISTRATOR",
        "administrator",
        "\tadministrator",
    ]
    for index, username in enumerate(aliases):
        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            login(
                store,
                username=username,
                password="wrong password",
                now=NOW + timedelta(seconds=index),
            )
        store.close()
        store = AuthStore(database)
    with pytest.raises(AuthenticationThrottled) as throttled:
        login(store, now=NOW + timedelta(seconds=5))
    assert throttled.value.retry_after == 895
    assert [event.action for event in store.list_auth_events()].count("LOGIN_FAILED") == 5
    assert store.list_auth_events()[0].action == "AUTHENTICATION_THROTTLED"
    session = login(store, now=NOW + timedelta(minutes=15))
    assert session.user.username == "administrator"
    store.close()


def test_successful_login_clears_account_budget_but_not_global_spray_budget(tmp_path: Path):
    database = tmp_path / "auth.db"
    store = AuthStore(database)
    bootstrap(store)
    for _ in range(4):
        with pytest.raises(AuthenticationError):
            login(store, password="wrong password")
    login(store)
    for _ in range(4):
        with pytest.raises(AuthenticationError):
            login(store, password="wrong again")
    login(store)
    for index in range(42):
        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            login(store, username=f"missing-{index}", password="wrong password")
    store.close()
    store = AuthStore(database)
    with pytest.raises(AuthenticationThrottled) as throttled:
        login(store)
    assert throttled.value.retry_after == 900
    assert login(store, now=NOW + timedelta(minutes=15)).user.username == "administrator"
    store.close()


@pytest.mark.parametrize("username", ["", " \t\n", "ab", "a" * 65, "admin istrator", "admin\x00"])
def test_invalid_usernames_fail_uniformly_and_are_budgeted(username: str):
    store = AuthStore()
    bootstrap(store)
    for _ in range(5):
        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            login(store, username=username)
    with pytest.raises(AuthenticationThrottled):
        login(store, username=username)
    assert store.verify_auth_events().valid
    store.close()


def test_session_idle_deadline_slides_but_absolute_deadline_does_not():
    store = AuthStore(session_lifetime=timedelta(minutes=60), idle_timeout=timedelta(minutes=20))
    user = bootstrap(store)
    session = login(store)
    assert session.idle_timeout_seconds == 1200
    assert session.expires_at == NOW + timedelta(minutes=60)
    for minute in (19, 38, 57, 59):
        assert store.resolve_session(session.token, now=NOW + timedelta(minutes=minute)) == user
    with pytest.raises(AuthenticationError, match="invalid or expired"):
        store.resolve_session(session.token, now=NOW + timedelta(minutes=60))
    other = login(store)
    with pytest.raises(AuthenticationError):
        store.resolve_session(other.token, now=NOW + timedelta(minutes=20))
    with pytest.raises(AuthenticationError):
        store.resolve_session(other.token, now=NOW - timedelta(seconds=1))
    store.close()


def test_temporary_password_has_restricted_session_until_changed_and_all_sessions_revoked():
    store = AuthStore()
    bootstrap(store)
    user = create_user(store, temporary=True)
    first = login(store, username=user.username, password=USER_PASSWORD)
    second = login(store, username=user.username, password=USER_PASSWORD)
    assert first.user.must_change_password
    with pytest.raises(PasswordChangeRequired):
        store.resolve_session(first.token, now=NOW)
    assert store.resolve_session(first.token, now=NOW, allow_password_change=True) == user
    store.change_password(user.user_id, USER_PASSWORD, NEW_PASSWORD, now=NOW)
    assert not store.get_user(user.user_id).must_change_password
    for token in (first.token, second.token):
        with pytest.raises(AuthenticationError):
            store.resolve_session(token, now=NOW, allow_password_change=True)
    with pytest.raises(AuthenticationError):
        login(store, username=user.username, password=USER_PASSWORD)
    session = login(store, username=user.username, password=NEW_PASSWORD)
    assert store.resolve_session(session.token, now=NOW).user_id == user.user_id
    store.close()


def test_denied_temporary_session_does_not_extend_idle_deadline():
    store = AuthStore()
    bootstrap(store)
    user = create_user(store, temporary=True)
    session = login(store, username=user.username, password=USER_PASSWORD)
    with pytest.raises(PasswordChangeRequired):
        store.resolve_session(session.token, now=NOW + timedelta(minutes=29))
    with pytest.raises(AuthenticationError, match="invalid or expired"):
        store.resolve_session(
            session.token, now=NOW + timedelta(minutes=30), allow_password_change=True
        )
    store.close()


def test_password_change_reauthentication_shares_failed_login_budget(tmp_path: Path):
    database = tmp_path / "auth.db"
    store = AuthStore(database)
    user = bootstrap(store)
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            login(store, password="wrong login guess")
    for _ in range(2):
        with pytest.raises(AuthenticationError):
            store.change_password(user.user_id, "wrong current password", NEW_PASSWORD, now=NOW)
    store.close()
    store = AuthStore(database)
    with pytest.raises(AuthenticationThrottled):
        store.change_password(user.user_id, PASSWORD, NEW_PASSWORD, now=NOW)
    assert [event.action for event in store.list_auth_events()].count(
        "REAUTHENTICATION_FAILED"
    ) == 2
    store.change_password(user.user_id, PASSWORD, NEW_PASSWORD, now=NOW + timedelta(minutes=15))
    login(store, password=NEW_PASSWORD, now=NOW + timedelta(minutes=15))
    store.close()


@pytest.mark.parametrize("new_password", [PASSWORD, "short"])
def test_invalid_password_change_keeps_password_and_session(new_password: str):
    store = AuthStore()
    user = bootstrap(store)
    session = login(store)
    with pytest.raises(ValueError):
        store.change_password(user.user_id, PASSWORD, new_password, now=NOW)
    assert store.resolve_session(session.token, now=NOW) == user
    login(store)
    store.close()


def test_administrator_suspend_reactivate_and_reset_force_password_change():
    store = AuthStore()
    administrator = bootstrap(store)
    user = create_user(store)
    original = login(store, username=user.username, password=USER_PASSWORD)
    suspended = store.set_user_active(
        administrator.user_id, user.user_id, False, PASSWORD, "Employment paused", now=NOW
    )
    assert not suspended.active
    with pytest.raises(AuthenticationError):
        store.resolve_session(original.token, now=NOW)
    with pytest.raises(AuthenticationError):
        login(store, username=user.username, password=USER_PASSWORD)
    with pytest.raises(AuthStoreError, match="Activate"):
        store.reset_password(
            administrator.user_id, user.user_id, NEW_PASSWORD, PASSWORD, "Account recovery", now=NOW
        )
    active = store.set_user_active(
        administrator.user_id, user.user_id, True, PASSWORD, "Employment resumed", now=NOW
    )
    assert active.active
    with pytest.raises(AuthenticationError):
        store.resolve_session(original.token, now=NOW)
    new_session = login(store, username=user.username, password=USER_PASSWORD)
    reset = store.reset_password(
        administrator.user_id, user.user_id, NEW_PASSWORD, PASSWORD, "Identity verified", now=NOW
    )
    assert reset.must_change_password
    with pytest.raises(AuthenticationError):
        store.resolve_session(new_session.token, now=NOW)
    with pytest.raises(AuthenticationError):
        login(store, username=user.username, password=USER_PASSWORD)
    restricted = login(store, username=user.username, password=NEW_PASSWORD)
    with pytest.raises(PasswordChangeRequired):
        store.resolve_session(restricted.token, now=NOW)
    assert store.resolve_session(restricted.token, now=NOW, allow_password_change=True) == reset
    assert store.list_auth_events()[1].action == "LOGIN_FAILED"
    assert store.verify_auth_events().valid
    store.close()


def test_administrator_control_reauthentication_is_rate_limited_and_no_change_on_failure():
    store = AuthStore()
    administrator = bootstrap(store)
    user = create_user(store)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            store.set_user_active(
                administrator.user_id, user.user_id, False, "bad password", "Reason", now=NOW
            )
    with pytest.raises(AuthenticationThrottled):
        store.reset_password(
            administrator.user_id, user.user_id, NEW_PASSWORD, PASSWORD, "Reason", now=NOW
        )
    assert store.get_user(user.user_id) == user
    store.close()


def test_only_active_unrestricted_administrator_can_issue_accounts_or_manage_users():
    store = AuthStore()
    administrator = bootstrap(store)
    examiner = create_user(store)
    limited_admin = create_user(
        store, name="limited-admin", role=Role.ADMINISTRATOR, temporary=True
    )
    inactive_admin = create_user(store, name="inactive-admin", role=Role.ADMINISTRATOR)
    store.set_user_active(
        administrator.user_id, inactive_admin.user_id, False, PASSWORD, "Account held", now=NOW
    )
    for actor in (examiner, limited_admin, inactive_admin):
        with pytest.raises(AuthorizationError):
            store.create_user(
                username="unauthorized-new",
                display_name="New",
                password=USER_PASSWORD,
                role=Role.ADMINISTRATOR,
                actor_id=actor.user_id,
            )
        with pytest.raises(AuthorizationError):
            store.set_user_active(
                actor.user_id, examiner.user_id, False, USER_PASSWORD, "Reason", now=NOW
            )
    created = store.create_user(
        username="issued-user",
        display_name="New",
        password=USER_PASSWORD,
        role=Role.EXAMINER,
        actor_id=administrator.user_id,
        must_change_password=True,
        occurred_at=NOW,
    )
    assert created.must_change_password
    assert store.list_auth_events()[0].actor_id == administrator.user_id
    store.close()


def test_admin_actions_require_reason_and_cannot_self_suspend_or_self_reset():
    store = AuthStore()
    administrator = bootstrap(store)
    with pytest.raises(ValueError, match="reason"):
        store.set_user_active(administrator.user_id, administrator.user_id, False, PASSWORD, " ")
    with pytest.raises(ValueError, match="reason"):
        store.reset_password(
            administrator.user_id, administrator.user_id, NEW_PASSWORD, PASSWORD, "x" * 1001
        )
    with pytest.raises(AuthStoreError, match="own account"):
        store.set_user_active(
            administrator.user_id, administrator.user_id, False, PASSWORD, "Reason"
        )
    with pytest.raises(AuthStoreError, match="own password"):
        store.reset_password(
            administrator.user_id, administrator.user_id, NEW_PASSWORD, PASSWORD, "Reason"
        )
    user = create_user(store)
    with pytest.raises(ValueError, match="differ"):
        store.reset_password(administrator.user_id, user.user_id, USER_PASSWORD, PASSWORD, "Reason")
    assert store.get_user(administrator.user_id).active
    store.close()


def test_revoke_session_is_idempotent_and_revoke_all_covers_independent_sessions():
    store = AuthStore()
    user = bootstrap(store)
    first = login(store)
    second = login(store)
    store.revoke_session(first.token, now=NOW)
    count = store.verify_auth_events().checked_events
    store.revoke_session(first.token, now=NOW)
    assert store.verify_auth_events().checked_events == count
    with pytest.raises(AuthenticationError):
        store.resolve_session(first.token, now=NOW)
    assert store.resolve_session(second.token, now=NOW) == user
    store.revoke_all_sessions(user.user_id, now=NOW)
    with pytest.raises(AuthenticationError):
        store.resolve_session(second.token, now=NOW)
    with pytest.raises(UserNotFoundError):
        store.revoke_all_sessions("unknown", now=NOW)
    for token in ("", "x" * 513, "unknown"):
        with pytest.raises(AuthenticationError):
            store.revoke_session(token, now=NOW)
        with pytest.raises(AuthenticationError):
            store.resolve_session(token, now=NOW)
    store.close()


def test_admin_can_revoke_target_sessions_with_audited_reason():
    store = AuthStore()
    administrator = bootstrap(store)
    user = create_user(store)
    session = login(store, username=user.username, password=USER_PASSWORD)
    with pytest.raises(AuthenticationError):
        store.revoke_user_sessions(
            administrator.user_id, user.user_id, "wrong", "Investigation", now=NOW
        )
    assert store.resolve_session(session.token, now=NOW) == user
    store.revoke_user_sessions(
        administrator.user_id, user.user_id, PASSWORD, "Investigation", now=NOW
    )
    with pytest.raises(AuthenticationError):
        store.resolve_session(session.token, now=NOW)
    event = store.list_auth_events()[0]
    assert event.action == "USER_SESSIONS_REVOKED"
    assert event.details == {"reason": "Investigation"}
    assert event.actor_id == administrator.user_id
    assert event.subject == user.user_id
    store.close()


def test_offline_recovery_only_restores_existing_administrator_and_revokes_credentials():
    store = AuthStore()
    administrator = bootstrap(store)
    backup = create_user(store, name="backup-admin", role=Role.ADMINISTRATOR, temporary=True)
    examiner = create_user(store)
    session = login(store, username=backup.username, password=USER_PASSWORD)
    store.set_user_active(administrator.user_id, backup.user_id, False, PASSWORD, "Held", now=NOW)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            login(store, username=backup.username, password="wrong")
    for username in ("unknown", examiner.username):
        with pytest.raises(AuthStoreError, match="existing administrator"):
            store.recover_administrator(username, NEW_PASSWORD, now=NOW)
    recovered = store.recover_administrator(" BACKUP-ADMIN ", NEW_PASSWORD, now=NOW)
    assert recovered.active and not recovered.must_change_password
    event = store.list_auth_events()[0]
    assert event.action == "ADMINISTRATOR_RECOVERED"
    assert event.actor_id == "local-operator"
    with pytest.raises(AuthenticationError):
        store.resolve_session(session.token, now=NOW, allow_password_change=True)
    assert login(store, username=backup.username, password=NEW_PASSWORD).user == recovered
    store.close()


def test_legacy_database_migration_preserves_password_and_conservatively_expires_sessions(
    tmp_path: Path,
):
    database = tmp_path / "legacy.db"
    token = "old-token"
    created = NOW.isoformat(timespec="microseconds").replace("+00:00", "Z")
    expires = (NOW + timedelta(hours=8)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE users (
                user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL,
                active INTEGER NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE sessions (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id),
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO users VALUES "
            "('legacy', 'administrator', 'Legacy Admin', ?, 'administrator', 1, ?)",
            (PasswordHasher().hash(PASSWORD), created),
        )
        connection.execute(
            "INSERT INTO sessions VALUES (?, 'legacy', ?, ?, NULL)",
            (hashlib.sha256(token.encode()).hexdigest(), created, expires),
        )
    store = AuthStore(database)
    assert not store.get_user("legacy").must_change_password
    with pytest.raises(AuthenticationError):
        store.resolve_session(token, now=NOW + timedelta(minutes=30))
    assert login(store, now=NOW + timedelta(hours=1)).user.user_id == "legacy"
    store.close()
    store = AuthStore(database)
    assert store.verify_auth_events().valid
    store.close()


def test_bootstrap_is_serialized_across_independent_connections(tmp_path: Path):
    database = tmp_path / "auth.db"
    stores = (AuthStore(database), AuthStore(database))
    barrier = threading.Barrier(2)

    def attempt(store: AuthStore) -> bool:
        barrier.wait(timeout=5)
        try:
            bootstrap(store)
        except AuthStoreError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, stores))
    assert sorted(results) == [False, True]
    assert stores[0].count_users() == 1
    assert stores[0].verify_auth_events().checked_events == 1
    for store in stores:
        store.close()


@pytest.mark.parametrize("action", ["suspend", "reset"])
def test_concurrent_administrator_controls_cannot_remove_all_unrestricted_admins(
    tmp_path: Path, action: str
):
    database = tmp_path / "auth.db"
    first = AuthStore(database)
    first_admin = bootstrap(first)
    second_admin = create_user(first, name="second-admin", role=Role.ADMINISTRATOR)
    second = AuthStore(database)
    barrier = threading.Barrier(2)

    def attempt(store: AuthStore, actor: str, target: str, password: str) -> bool:
        barrier.wait(timeout=5)
        try:
            if action == "suspend":
                store.set_user_active(
                    actor, target, False, password, "Administrative change", now=NOW
                )
            else:
                store.reset_password(actor, target, NEW_PASSWORD, password, "Recovery", now=NOW)
        except AuthorizationError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(attempt, first, first_admin.user_id, second_admin.user_id, PASSWORD),
            executor.submit(
                attempt, second, second_admin.user_id, first_admin.user_id, USER_PASSWORD
            ),
        ]
        results = [future.result(timeout=10) for future in futures]
    assert sorted(results) == [False, True]
    available = [
        user for user in first.list_users() if user.active and not user.must_change_password
    ]
    assert len(available) == 1
    assert first.verify_auth_events().valid
    first.close()
    second.close()


def test_authentication_audit_is_append_only_paginated_and_has_no_passwords_or_tokens(
    tmp_path: Path,
):
    database = tmp_path / "auth.db"
    store = AuthStore(database)
    user = bootstrap(store)
    session = login(store)
    with pytest.raises(AuthenticationError):
        login(store, password="unique wrong-password secret")
    store.change_password(user.user_id, PASSWORD, NEW_PASSWORD, now=NOW)
    events = store.list_auth_events()
    assert store.verify_auth_events().checked_events == len(events) == 4
    assert store.verify_auth_events().valid
    assert store.list_auth_events(limit=2) == events[:2]
    assert store.list_auth_events(before=events[1].sequence) == events[2:]
    assert store.list_auth_events(before=1) == ()
    exported = repr(events)
    for secret in (PASSWORD, NEW_PASSWORD, "unique wrong-password secret", session.token, "scrypt"):
        assert secret not in exported
    with sqlite3.connect(database) as connection:
        for statement in ("UPDATE auth_events SET action = 'TAMPERED'", "DELETE FROM auth_events"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(statement)
    assert store.verify_auth_events().valid
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER auth_events_no_update")
        connection.execute(
            "UPDATE auth_events SET details = ? WHERE sequence = 3",
            (json.dumps({"tampered": True}),),
        )
    verification = store.verify_auth_events()
    assert not verification.valid and verification.checked_events == 2
    store.close()


def test_audit_verification_detects_malformed_details_and_sequence_gaps(tmp_path: Path):
    database = tmp_path / "auth.db"
    store = AuthStore(database)
    bootstrap(store)
    login(store)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER auth_events_no_update")
        connection.execute("UPDATE auth_events SET details = '[]' WHERE sequence = 2")
    assert not store.verify_auth_events().valid
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE auth_events SET details = '{' WHERE sequence = 2")
    assert not store.verify_auth_events().valid
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE auth_events SET details = '{}', sequence = 3 WHERE sequence = 2")
    assert not store.verify_auth_events().valid
    store.close()


@pytest.mark.parametrize("limit,before", [(0, None), (1001, None), (10, 0)])
def test_audit_pagination_rejects_invalid_bounds(limit: int, before: int | None):
    store = AuthStore()
    with pytest.raises(ValueError):
        store.list_auth_events(limit=limit, before=before)
    store.close()


@pytest.mark.parametrize("timeout", [timedelta(0), timedelta(days=8)])
def test_idle_timeout_rejects_unsafe_values(timeout: timedelta):
    with pytest.raises(ValueError, match="Idle timeout"):
        AuthStore(idle_timeout=timeout)
