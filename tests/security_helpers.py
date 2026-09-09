from fastapi.testclient import TestClient

TEST_SETUP_CODE = "test-only-installation-code"


def installation_code(client: TestClient) -> str:
    path = getattr(client.app.state, "setup_code_path", None)
    return path.read_text().strip() if path is not None else TEST_SETUP_CODE


def complete_initial_password_change(client, login, current_password):
    """Exercise the real forced-change flow before continuing existing role/case tests."""
    assert login.status_code == 200
    assert login.json()["user"]["must_change_password"]
    username = login.json()["user"]["username"]
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    assert client.get("/api/v1/cases", headers=headers).status_code == 403
    new_password = current_password + " changed"
    changed = client.post(
        "/api/v1/auth/password", headers=headers,
        json={"current_password": current_password, "new_password": new_password},
    )
    assert changed.status_code == 204, changed.text
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    return client.post(
        "/api/v1/auth/login", json={"username": username, "password": new_password},
    )
