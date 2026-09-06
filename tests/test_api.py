from fastapi.testclient import TestClient

from forenx.api.app import create_app

ADMIN_PASSWORD = "correct horse battery staple"


def _setup_admin(client: TestClient) -> str:
    response = client.post(
        "/api/v1/setup",
        json={
            "username": "administrator",
            "display_name": "Lab Administrator",
            "password": ADMIN_PASSWORD,
        },
    )
    assert response.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "administrator", "password": ADMIN_PASSWORD},
    )
    assert login.status_code == 200
    return str(login.json()["token"])


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoints_report_service_version():
    client = TestClient(create_app())

    assert client.get("/", follow_redirects=False).headers["location"] == "/app/"
    assert client.get("/app/").status_code == 200
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {
        "status": "ready",
        "service": "forenx-api",
        "version": "0.1.0",
    }


def test_vendor_endpoint_reports_truthful_validation_status():
    client = TestClient(create_app())

    response = client.get("/api/v1/vendors")
    vendor = response.json()["vendors"][0]

    assert response.status_code == 200
    assert vendor["adapter_id"] == "hikvision"
    assert vendor["maturity"] == "experimental"
    assert vendor["validated_models"] == []
    assert vendor["capabilities"] == [
        "device-metadata",
        "enumerate-active",
        "extract",
    ]


def test_setup_is_one_time_and_invalid_login_is_generic():
    client = TestClient(create_app())

    assert client.get("/api/v1/setup/status").json() == {"initialized": False}
    _setup_admin(client)
    assert client.get("/api/v1/setup/status").json() == {"initialized": True}
    repeated = client.post(
        "/api/v1/setup",
        json={
            "username": "another-admin",
            "display_name": "Another Administrator",
            "password": ADMIN_PASSWORD,
        },
    )
    invalid = client.post(
        "/api/v1/auth/login",
        json={"username": "missing-user", "password": "wrong password"},
    )

    assert repeated.status_code == 409
    assert invalid.status_code == 401
    assert invalid.json()["detail"] == "Invalid username or password"


def test_case_workflow_requires_authentication_and_respects_roles():
    client = TestClient(create_app())
    admin_token = _setup_admin(client)
    admin_headers = _authorization(admin_token)

    assert client.get("/api/v1/cases").status_code == 401

    created_user = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "intake-one",
            "display_name": "Intake Officer One",
            "password": "intake secure password",
            "role": "intake-officer",
        },
    )
    assert created_user.status_code == 201

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "intake-one", "password": "intake secure password"},
    )
    intake_headers = _authorization(str(login.json()["token"]))
    created_case = client.post(
        "/api/v1/cases",
        headers=intake_headers,
        json={
            "case_reference": "FSL/2026/0042",
            "agency": "State Forensic Science Laboratory",
            "police_station": "Central Police Station",
            "investigating_officer": "Inspector A. Rao",
            "classification": "Restricted",
        },
    )

    assert created_case.status_code == 201
    case = created_case.json()
    assert case["status"] == "intake"

    exhibit = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits",
        headers=intake_headers,
        json={
            "exhibit_number": "EX-01",
            "device_type": "DVR",
            "manufacturer": "Hikvision",
            "model": "Test model - unvalidated",
            "serial_number": "SANITISED-001",
            "channel_count": 8,
            "working_channels_observed": 6,
            "recorder_time_observed": "2026-09-06T09:30:00+05:30",
            "clock_offset_seconds": 95,
            "seal_number": "SEAL-0042",
            "seal_condition": "Intact on receipt",
            "packaging": "Anti-static evidence bag",
            "collector": "Inspector A. Rao",
            "collection_location": "Central Police Station evidence room",
            "collected_at": "2026-09-06T10:00:00+05:30",
            "authorization_reference": "Court order CO-2026-42",
        },
    )
    denied_transition = client.post(
        f"/api/v1/cases/{case['case_id']}/transition",
        headers=intake_headers,
        json={
            "target_status": "acquisition",
            "expected_version": case["version"],
            "reason": "Evidence registered",
        },
    )

    assert exhibit.status_code == 201
    assert denied_transition.status_code == 403

    transitioned = client.post(
        f"/api/v1/cases/{case['case_id']}/transition",
        headers=admin_headers,
        json={
            "target_status": "acquisition",
            "expected_version": case["version"],
            "reason": "Intake verified by administrator",
        },
    )
    activity = client.get(
        f"/api/v1/cases/{case['case_id']}/activity",
        headers=admin_headers,
    )

    assert transitioned.status_code == 200
    assert transitioned.json()["status"] == "acquisition"
    assert [event["action"] for event in activity.json()] == [
        "CASE_CREATED",
        "EXHIBIT_REGISTERED",
        "CASE_STATUS_CHANGED",
    ]


def test_duplicate_case_stale_update_and_logout_fail_safely():
    client = TestClient(create_app())
    token = _setup_admin(client)
    headers = _authorization(token)
    case_request = {
        "case_reference": "FSL/2026/0043",
        "agency": "State FSL",
        "investigating_officer": "Inspector B. Singh",
        "classification": "Restricted",
    }

    created = client.post("/api/v1/cases", headers=headers, json=case_request)
    duplicate = client.post("/api/v1/cases", headers=headers, json=case_request)
    stale = client.post(
        f"/api/v1/cases/{created.json()['case_id']}/transition",
        headers=headers,
        json={
            "target_status": "acquisition",
            "expected_version": 999,
            "reason": "Stale screen",
        },
    )
    logout = client.post("/api/v1/auth/logout", headers=headers)
    after_logout = client.get("/api/v1/cases", headers=headers)

    assert duplicate.status_code == 409
    assert stale.status_code == 409
    assert logout.status_code == 204
    assert after_logout.status_code == 401
