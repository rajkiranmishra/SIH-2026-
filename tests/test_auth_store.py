from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forenx.auth import (
    AuthenticationError,
    AuthorizationError,
    AuthStore,
    AuthStoreError,
    PasswordHasher,
    Permission,
    Role,
    require_permission,
)

AUTH_TIME = datetime(2026, 9, 6, 11, 0, tzinfo=UTC)


def _bootstrap(store: AuthStore):
    return store.bootstrap_administrator(
        username="Administrator",
        display_name="Laboratory Administrator",
        password="correct horse battery staple",
        occurred_at=AUTH_TIME,
    )


def test_password_hasher_uses_salt_and_constant_result_verification():
    hasher = PasswordHasher()
    first = hasher.hash("correct horse battery staple")
    second = hasher.hash("correct horse battery staple")

    assert first != second
    assert hasher.verify("correct horse battery staple", first)
    assert not hasher.verify("wrong password value", first)
    assert not hasher.verify("correct horse battery staple", "malformed")


def test_administrator_bootstrap_is_one_time_and_username_is_normalized():
    store = AuthStore()
    user = _bootstrap(store)

    assert user.username == "administrator"
    assert user.role is Role.ADMINISTRATOR
    assert store.count_users() == 1
    with pytest.raises(AuthStoreError, match="disabled"):
        _bootstrap(store)


def test_session_authentication_expiry_and_revocation():
    store = AuthStore(session_lifetime=timedelta(hours=1))
    user = _bootstrap(store)
    session = store.authenticate(
        username="ADMINISTRATOR",
        password="correct horse battery staple",
        now=AUTH_TIME,
    )

    assert session.user == user
    assert store.resolve_session(session.token, now=AUTH_TIME) == user
    with pytest.raises(AuthenticationError, match="invalid or expired"):
        store.resolve_session(session.token, now=AUTH_TIME + timedelta(hours=2))

    store.revoke_session(session.token, now=AUTH_TIME + timedelta(minutes=1))
    with pytest.raises(AuthenticationError, match="invalid or expired"):
        store.resolve_session(session.token, now=AUTH_TIME + timedelta(minutes=2))


def test_invalid_credentials_do_not_disclose_account_existence():
    store = AuthStore()
    _bootstrap(store)

    with pytest.raises(AuthenticationError) as wrong_password:
        store.authenticate(username="administrator", password="incorrect password value")
    with pytest.raises(AuthenticationError) as missing_user:
        store.authenticate(username="missing-user", password="incorrect password value")

    assert str(wrong_password.value) == str(missing_user.value)


def test_role_permissions_separate_intake_examination_and_approval():
    store = AuthStore()
    _bootstrap(store)
    examiner = store.create_user(
        username="examiner-1",
        display_name="Forensic Examiner",
        password="examiner secure password",
        role=Role.EXAMINER,
    )

    require_permission(examiner, Permission.CASE_READ)
    require_permission(examiner, Permission.CASE_PROCESS)
    with pytest.raises(AuthorizationError, match="lacks"):
        require_permission(examiner, Permission.CASE_APPROVE)


def test_duplicate_username_is_case_insensitive():
    store = AuthStore()
    _bootstrap(store)
    with pytest.raises(AuthStoreError, match="already exists"):
        store.create_user(
            username="ADMINISTRATOR",
            display_name="Duplicate",
            password="another secure password",
            role=Role.INTAKE_OFFICER,
        )


def test_authentication_database_is_private_and_rejects_symlink(tmp_path: Path):
    database = tmp_path / "auth.db"
    store = AuthStore(database)
    _bootstrap(store)
    store.close()

    assert database.stat().st_mode & 0o777 == 0o600
    link = tmp_path / "auth-link.db"
    link.symlink_to(database)
    with pytest.raises(AuthStoreError, match="symbolic link"):
        AuthStore(link)


@pytest.mark.parametrize("lifetime", [timedelta(0), timedelta(days=8)])
def test_unsafe_session_lifetime_is_rejected(lifetime: timedelta):
    with pytest.raises(ValueError, match="seven days"):
        AuthStore(session_lifetime=lifetime)


@pytest.mark.parametrize("password", ["short", "x" * 1025])
def test_password_length_policy_is_enforced(password: str):
    with pytest.raises(ValueError, match="Password"):
        PasswordHasher().hash(password)
