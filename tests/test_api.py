import hashlib
import io
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from pypdf import PdfReader

from forenx.api.app import create_app
from forenx.package import verify_evidence_package
from forenx.runtime import create_product_app

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


def test_evidence_ingest_hash_verification_and_activity_are_integrated(tmp_path: Path):
    client = TestClient(create_product_app(tmp_path / "product-data"))
    token = _setup_admin(client)
    headers = _authorization(token)
    case = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_reference": "FSL/2026/UPLOAD-1",
            "agency": "State FSL",
            "investigating_officer": "Inspector Evidence",
            "classification": "Restricted",
        },
    ).json()
    exhibit = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits",
        headers=headers,
        json={
            "exhibit_number": "EX-UPLOAD-1",
            "device_type": "Disk image",
            "seal_condition": "Intact",
            "packaging": "Evidence bag",
            "collector": "Inspector Evidence",
            "collection_location": "Laboratory intake",
            "collected_at": "2026-09-06T10:00:00+05:30",
            "authorization_reference": "AUTH-UPLOAD-1",
        },
    ).json()

    uploaded = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **headers,
            "X-ForenX-Filename": "sanitised-recorder.img",
            "X-ForenX-Media-Kind": "raw-disk-image",
        },
        content=b"synthetic recorder image",
    )

    assert uploaded.status_code == 201
    evidence = uploaded.json()
    assert evidence["original_filename"] == "sanitised-recorder.img"
    assert evidence["byte_size"] == 24
    assert "stored_path" not in evidence

    listed = client.get(
        f"/api/v1/cases/{case['case_id']}/evidence",
        headers=headers,
    )
    verified = client.post(
        f"/api/v1/evidence/{evidence['source_id']}/verify",
        headers=headers,
    )
    raw_playback = client.get(
        f"/api/v1/evidence/{evidence['source_id']}/content",
    )
    raw_inspection = client.post(
        f"/api/v1/evidence/{evidence['source_id']}/inspect",
        headers=headers,
    )
    activity = client.get(
        f"/api/v1/cases/{case['case_id']}/activity",
        headers=headers,
    ).json()

    assert listed.json() == [evidence]
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert raw_playback.status_code == 409
    assert raw_inspection.status_code == 409
    assert [event["action"] for event in activity][-3:] == [
        "EVIDENCE_INGEST_STARTED",
        "EVIDENCE_INGEST_COMPLETED",
        "EVIDENCE_INTEGRITY_VERIFIED",
    ]


def test_video_inspection_range_playback_and_bookmark_workflow(
    tmp_path: Path,
    sample_mp4: bytes,
):
    application = create_product_app(tmp_path / "video-product")
    client = TestClient(application)
    token = _setup_admin(client)
    headers = _authorization(token)
    case = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_reference": "FSL/2026/VIDEO-1",
            "agency": "State FSL",
            "investigating_officer": "Inspector Video",
            "classification": "Restricted",
        },
    ).json()
    exhibit = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits",
        headers=headers,
        json={
            "exhibit_number": "VIDEO-01",
            "device_type": "Video export",
            "seal_condition": "Intact",
            "packaging": "Digital evidence transfer",
            "collector": "Inspector Video",
            "collection_location": "Laboratory",
            "collected_at": "2026-09-06T10:00:00+05:30",
            "authorization_reference": "AUTH-VIDEO-1",
        },
    ).json()
    source = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **headers,
            "X-ForenX-Filename": "controlled-cctv.mp4",
            "X-ForenX-Media-Kind": "video-file",
        },
        content=sample_mp4,
    ).json()

    uninspected = client.get(
        f"/api/v1/evidence/{source['source_id']}/inspection",
        headers=headers,
    )
    premature_bookmark = client.post(
        f"/api/v1/evidence/{source['source_id']}/bookmarks",
        headers=headers,
        json={"timestamp_ms": 100, "title": "Too early"},
    )
    anonymous_playback = TestClient(application).get(
        f"/api/v1/evidence/{source['source_id']}/content",
    )

    inspected = client.post(
        f"/api/v1/evidence/{source['source_id']}/inspect",
        headers=headers,
    )
    playback = client.get(
        f"/api/v1/evidence/{source['source_id']}/content",
        headers={"Range": "bytes=0-9"},
    )
    bookmark = client.post(
        f"/api/v1/evidence/{source['source_id']}/bookmarks",
        headers=headers,
        json={
            "timestamp_ms": 250,
            "title": "Person enters frame",
            "note": "Controlled validation event",
        },
    )
    bookmarks = client.get(
        f"/api/v1/evidence/{source['source_id']}/bookmarks",
        headers=headers,
    )
    out_of_range = client.post(
        f"/api/v1/evidence/{source['source_id']}/bookmarks",
        headers=headers,
        json={"timestamp_ms": 5000, "title": "Outside duration"},
    )

    assert uninspected.status_code == 404
    assert premature_bookmark.status_code == 422
    assert anonymous_playback.status_code == 401
    assert inspected.status_code == 200
    result = inspected.json()["result"]
    assert result["duration_seconds"] == 1.0
    assert result["streams"][0]["codec_name"] == "mpeg4"
    assert result["streams"][0]["width"] == 160
    assert playback.status_code == 206
    assert playback.content == sample_mp4[:10]
    assert bookmark.status_code == 201
    assert bookmarks.json() == [bookmark.json()]
    assert out_of_range.status_code == 422

    premature_report = client.post(
        f"/api/v1/evidence/{source['source_id']}/reports",
        headers=headers,
        json={
            "signing_password": "laboratory report passphrase",
            "report_title": "Controlled CCTV examination",
            "purpose": "Validate the protected video examination workflow.",
            "examiner_conclusion": "The controlled entry event is visible at the bookmark.",
        },
    )
    assert premature_report.status_code == 422
    assert "approved" in premature_report.json()["detail"]

    current_case = case
    for target in (
        "acquisition",
        "processing",
        "examiner-review",
        "supervisor-review",
        "approved",
    ):
        transition = client.post(
            f"/api/v1/cases/{case['case_id']}/transition",
            headers=headers,
            json={
                "target_status": target,
                "expected_version": current_case["version"],
                "reason": f"Controlled validation: advance to {target}",
            },
        )
        assert transition.status_code == 200
        current_case = transition.json()

    report = client.post(
        f"/api/v1/evidence/{source['source_id']}/reports",
        headers=headers,
        json={
            "signing_password": "laboratory report passphrase",
            "report_title": "Controlled CCTV examination",
            "purpose": "Validate the protected video examination workflow.",
            "examiner_conclusion": "The controlled entry event is visible at the bookmark.",
            "limitations": ["The clip was produced specifically for controlled testing."],
        },
    )
    assert report.status_code == 201
    report_record = report.json()
    assert report_record["source_id"] == source["source_id"]
    assert len(report_record["manifest_sha256"]) == 64
    assert len(report_record["public_key_fingerprint"]) == 64

    listed_reports = client.get(
        f"/api/v1/cases/{case['case_id']}/reports",
        headers=headers,
    )
    assert listed_reports.json() == [report_record]

    downloaded = client.get(
        f"/api/v1/reports/{report_record['package_id']}/download",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.headers["x-forenx-archive-sha256"] == hashlib.sha256(
        downloaded.content
    ).hexdigest()
    with zipfile.ZipFile(io.BytesIO(downloaded.content)) as archive:
        assert set(archive.namelist()) == {
            "examination-report.json",
            "examination-report.pdf",
            "manifest.json",
            "manifest.signature.json",
        }
        archive.extractall(tmp_path / "verified-report")
        pdf = PdfReader(io.BytesIO(archive.read("examination-report.pdf")))
        text = "\n".join(page.extract_text() or "" for page in pdf.pages)
    verification = verify_evidence_package(
        tmp_path / "verified-report",
        trusted_public_key_fingerprint=report_record["public_key_fingerprint"],
    )
    assert "Controlled CCTV examination" in text
    assert source["sha256"] in text.replace("\n", "")
    assert verification.valid
    assert verification.checked_artifacts == 2

    archive_path = (
        application.state.data_directory
        / "report-exports"
        / "packages"
        / f"{report_record['package_id']}.forenx.zip"
    )
    archive_path.chmod(0o600)
    archive_path.write_bytes(archive_path.read_bytes() + b"tampered")
    archive_path.chmod(0o400)
    refused_tampered_download = client.get(
        f"/api/v1/reports/{report_record['package_id']}/download",
        headers=headers,
    )
    assert refused_tampered_download.status_code == 422
    assert "integrity" in refused_tampered_download.json()["detail"]

    wrong_password = client.post(
        f"/api/v1/evidence/{source['source_id']}/reports",
        headers=headers,
        json={
            "signing_password": "incorrect signing password",
            "report_title": "Second report",
            "purpose": "Confirm key protection.",
            "examiner_conclusion": "This export must fail.",
        },
    )
    assert wrong_password.status_code == 422
    assert "invalid" in wrong_password.json()["detail"]
