from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from security_helpers import TEST_SETUP_CODE, complete_initial_password_change, installation_code

from forenx.api.app import PLAYBACK_COOKIE, create_app
from forenx.auth import AuthStore
from forenx.runtime import RuntimeConfigurationError, create_product_app

ADMIN_PASSWORD = "controlled administrator passphrase"
TEMP_PASSWORD = "controlled initial passphrase"


def setup(client):
    response = client.post("/api/v1/setup", json={
        "setup_code": installation_code(client), "username": "admin",
        "display_name": "Local administrator", "password": ADMIN_PASSWORD,
    })
    assert response.status_code == 201, response.text
    response = client.post("/api/v1/auth/login", json={
        "username": "admin", "password": ADMIN_PASSWORD,
    })
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def create_examiner(client, headers):
    created = client.post("/api/v1/users", headers=headers, json={
        "username": "examiner", "display_name": "Test examiner", "role": "examiner",
        "password": TEMP_PASSWORD,
    })
    assert created.status_code == 201, created.text
    assert created.json()["must_change_password"]
    return created.json()


def test_setup_requires_private_code_and_stays_closed_after_initialization(tmp_path):
    unconfigured = TestClient(create_app())
    payload = {"username": "admin", "display_name": "Admin", "password": ADMIN_PASSWORD}
    assert unconfigured.post("/api/v1/setup", json=payload).status_code == 403
    app = create_product_app(tmp_path / "product")
    client = TestClient(app)
    assert client.post("/api/v1/setup", json=payload).status_code == 403
    assert client.post("/api/v1/setup", json={**payload, "setup_code": "wrong"}).status_code == 403
    assert client.post("/api/v1/setup", json={**payload, "setup_code": "🔑"}).status_code == 403
    code = installation_code(client)
    assert code not in client.get("/api/v1/setup/status").text
    assert code not in client.get("/app/").text
    assert app.state.setup_code_path.stat().st_mode & 0o777 == 0o600
    assert installation_code(TestClient(create_product_app(tmp_path / "product"))) == code
    setup(client)
    assert client.post("/api/v1/setup", json={**payload, "setup_code": code}).status_code == 409
    restarted = TestClient(create_product_app(tmp_path / "product"))
    assert restarted.get("/api/v1/setup/status").json() == {"initialized": True}
    assert restarted.post("/api/v1/setup", json={**payload, "setup_code": code}).status_code == 409


def test_setup_code_symlink_and_world_readable_files_fail_closed(tmp_path):
    data = tmp_path / "lab"
    data.mkdir()
    target = tmp_path / "external"
    target.write_text("x" * 43)
    code = data / "setup-code.txt"
    code.symlink_to(target)
    with pytest.raises(RuntimeConfigurationError, match="code"):
        create_product_app(data)
    code.unlink()
    code.write_text("x" * 43)
    code.chmod(0o644)
    with pytest.raises(RuntimeConfigurationError, match="owner-only"):
        create_product_app(data)


def test_login_throttling_is_generic_and_persists_across_application_restart(tmp_path):
    data = tmp_path / "lab"
    client = TestClient(create_product_app(data))
    setup(client)
    for _ in range(5):
        response = client.post("/api/v1/auth/login", json={
            "username": "  ADMIN ", "password": "incorrect guess",
        })
        assert response.status_code in {401, 429}
    restarted = TestClient(create_product_app(data))
    blocked = restarted.post("/api/v1/auth/login", json={
        "username": "admin", "password": ADMIN_PASSWORD,
    })
    assert blocked.status_code == 429
    assert 0 < int(blocked.headers["retry-after"]) <= 900
    assert restarted.post("/api/v1/auth/login", json={
        "username": "   ", "password": "incorrect guess",
    }).status_code == 401


def test_password_gate_applies_to_api_playback_and_previews_and_allows_recovery():
    app = create_app(setup_code=TEST_SETUP_CODE)
    admin = TestClient(app)
    headers = setup(admin)
    assert TestClient(app).post("/api/v1/users", json={
        "username": "outsider", "display_name": "Outsider", "role": "administrator",
        "password": TEMP_PASSWORD,
    }).status_code == 401
    create_examiner(admin, headers)
    examiner = TestClient(app)
    login = examiner.post("/api/v1/auth/login", json={
        "username": "examiner", "password": TEMP_PASSWORD,
    })
    restricted = {"Authorization": f"Bearer {login.json()['token']}"}
    assert examiner.get("/api/v1/auth/me", headers=restricted).status_code == 200
    denied = examiner.get("/api/v1/cases", headers=restricted)
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Password change required"
    assert examiner.get("/api/v1/evidence/any/content").status_code == 401
    assert examiner.get("/api/v1/evidence/any/face-detections/any/preview").status_code == 401
    login = complete_initial_password_change(examiner, login, TEMP_PASSWORD)
    allowed = {"Authorization": f"Bearer {login.json()['token']}"}
    assert examiner.get("/api/v1/cases", headers=allowed).status_code == 200
    assert examiner.get("/api/v1/auth/events", headers=allowed).status_code == 403
    assert examiner.post("/api/v1/users", headers=allowed, json={
        "username": "outsider", "display_name": "Outsider", "role": "administrator",
        "password": TEMP_PASSWORD,
    }).status_code == 403


def test_admin_suspension_reset_and_revocation_cover_old_bearer_and_cookie_sessions():
    app = create_app(setup_code=TEST_SETUP_CODE)
    admin = TestClient(app)
    admin_headers = setup(admin)
    user = create_examiner(admin, admin_headers)
    examiner = TestClient(app)
    login = examiner.post("/api/v1/auth/login", json={
        "username": "examiner", "password": TEMP_PASSWORD,
    })
    login = complete_initial_password_change(examiner, login, TEMP_PASSWORD)
    old_headers = {"Authorization": f"Bearer {login.json()['token']}"}
    user_path = f"/api/v1/users/{user['user_id']}"
    wrong = admin.patch(user_path + "/status", headers=admin_headers, json={
        "active": False, "current_password": "wrong password", "reason": "Test rejection",
    })
    assert wrong.status_code == 400
    assert examiner.get("/api/v1/auth/me", headers=old_headers).status_code == 200
    suspended = admin.patch(user_path + "/status", headers=admin_headers, json={
        "active": False, "current_password": ADMIN_PASSWORD, "reason": "Access review",
    })
    assert suspended.status_code == 200, suspended.text
    assert not suspended.json()["active"]
    assert examiner.get("/api/v1/auth/me", headers=old_headers).status_code == 401
    assert examiner.get("/api/v1/evidence/any/content").status_code == 401
    assert examiner.get("/api/v1/evidence/any/face-detections/any/preview").status_code == 401
    assert examiner.post("/api/v1/auth/login", json={
        "username": "examiner", "password": TEMP_PASSWORD + " changed",
    }).status_code == 401
    active = admin.patch(user_path + "/status", headers=admin_headers, json={
        "active": True, "current_password": ADMIN_PASSWORD, "reason": "Review completed",
    })
    assert active.status_code == 200
    assert examiner.get("/api/v1/auth/me", headers=old_headers).status_code == 401
    reset = admin.post(user_path + "/reset-password", headers=admin_headers, json={
        "new_password": "replacement temporary password", "current_password": ADMIN_PASSWORD,
        "reason": "Verified user recovery request",
    })
    assert reset.status_code == 200, reset.text
    assert reset.json()["must_change_password"]
    next_login = examiner.post("/api/v1/auth/login", json={
        "username": "examiner", "password": "replacement temporary password",
    })
    next_login = complete_initial_password_change(
        examiner, next_login, "replacement temporary password",
    )
    new_headers = {"Authorization": f"Bearer {next_login.json()['token']}"}
    revoke = admin.post(user_path + "/revoke-sessions", headers=admin_headers, json={
        "current_password": ADMIN_PASSWORD, "reason": "Demonstrate remote revocation",
    })
    assert revoke.status_code == 204, revoke.text
    assert examiner.get("/api/v1/auth/me", headers=new_headers).status_code == 401
    events = admin.get("/api/v1/auth/events?limit=100", headers=admin_headers)
    assert events.status_code == 200
    assert "Verified user recovery request" in events.text
    assert ADMIN_PASSWORD not in events.text
    assert TEMP_PASSWORD not in events.text
    sequences = [event["sequence"] for event in events.json()]
    assert sequences == sorted(sequences, reverse=True)
    page = admin.get(
        f"/api/v1/auth/events?limit=2&before={sequences[0]}", headers=admin_headers,
    ).json()
    assert len(page) == 2
    assert all(event["sequence"] < sequences[0] for event in page)
    assert admin.get("/api/v1/auth/events/verify", headers=admin_headers).json()["valid"]


def test_logout_all_and_idle_expiry_reject_bearer_and_playback():
    store = AuthStore(idle_timeout=timedelta(minutes=30))
    app = create_app(auth_store=store, setup_code=TEST_SETUP_CODE)
    first = TestClient(app)
    first_headers = setup(first)
    second = TestClient(app)
    login = second.post(
        "/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD},
    )
    second_headers = {"Authorization": f"Bearer {login.json()['token']}"}
    response = first.post("/api/v1/auth/logout-all", headers=first_headers)
    assert response.status_code == 204
    assert second.get("/api/v1/auth/me", headers=second_headers).status_code == 401
    assert second.get("/api/v1/evidence/any/content").status_code == 401
    expired = store.authenticate(
        username="admin", password=ADMIN_PASSWORD, now=datetime.now(UTC) - timedelta(minutes=31),
    )
    expired_headers = {"Authorization": f"Bearer {expired.token}"}
    second.cookies.clear()
    second.cookies.set(PLAYBACK_COOKIE, expired.token)
    assert second.get("/api/v1/auth/me", headers=expired_headers).status_code == 401
    assert second.get("/api/v1/evidence/any/content").status_code == 401
    assert second.get("/api/v1/evidence/any/face-detections/any/preview").status_code == 401


def test_local_recovery_cli_requires_existing_admin_and_audits_recovery(
    tmp_path, monkeypatch, capsys,
):
    from forenx.auth import cli

    data = tmp_path / "lab"
    client = TestClient(create_product_app(data))
    headers = setup(client)
    monkeypatch.setattr("sys.argv", ["forenx-admin-recover", "admin", "--data-dir", str(data)])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "new local recovery passphrase")
    cli.main()
    assert "recovered" in capsys.readouterr().out
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.post("/api/v1/auth/login", json={
        "username": "admin", "password": "new local recovery passphrase",
    }).status_code == 200


def test_local_recovery_rejects_unknown_database_and_mismatching_passwords(tmp_path, monkeypatch):
    from forenx.auth import cli

    monkeypatch.setattr("sys.argv", ["recover", "admin", "--data-dir", str(tmp_path)])
    with pytest.raises(SystemExit):
        cli.main()
    setup(TestClient(create_product_app(tmp_path)))
    answers = iter(["one safe password", "a different password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(answers))
    with pytest.raises(SystemExit):
        cli.main()


@pytest.mark.parametrize("bad_code", ["", "x" * 500, "invalid code"])
def test_malformed_installation_code_does_not_create_account(tmp_path: Path, bad_code: str):
    data = tmp_path / "lab"
    data.mkdir()
    code = data / "setup-code.txt"
    code.write_text(bad_code)
    code.chmod(0o600)
    with pytest.raises(RuntimeConfigurationError):
        create_product_app(data)
