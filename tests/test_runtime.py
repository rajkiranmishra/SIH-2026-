from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forenx.runtime import RuntimeConfigurationError, create_product_app


def test_product_runtime_persists_accounts_and_cases(tmp_path: Path):
    data_directory = tmp_path / "laboratory-data"
    first_client = TestClient(create_product_app(data_directory))
    setup = first_client.post(
        "/api/v1/setup",
        json={
            "username": "administrator",
            "display_name": "Lab Administrator",
            "password": "persistent secure password",
        },
    )
    assert setup.status_code == 201
    login = first_client.post(
        "/api/v1/auth/login",
        json={
            "username": "administrator",
            "password": "persistent secure password",
        },
    )
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    created = first_client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_reference": "PERSIST/2026/01",
            "agency": "Test Laboratory",
            "investigating_officer": "Inspector Test",
            "classification": "Restricted",
        },
    )
    assert created.status_code == 201

    second_client = TestClient(create_product_app(data_directory))
    repeated_login = second_client.post(
        "/api/v1/auth/login",
        json={
            "username": "administrator",
            "password": "persistent secure password",
        },
    )
    repeated_headers = {
        "Authorization": f"Bearer {repeated_login.json()['token']}"
    }
    cases = second_client.get("/api/v1/cases", headers=repeated_headers)

    assert repeated_login.status_code == 200
    assert cases.status_code == 200
    assert [case["case_reference"] for case in cases.json()] == ["PERSIST/2026/01"]
    assert data_directory.stat().st_mode & 0o777 == 0o700
    assert (data_directory / "forenx.sqlite3").stat().st_mode & 0o777 == 0o600


def test_product_runtime_rejects_symlink_data_directory(tmp_path: Path):
    target = tmp_path / "real-data"
    target.mkdir()
    link = tmp_path / "linked-data"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(RuntimeConfigurationError, match="symbolic link"):
        create_product_app(link)
