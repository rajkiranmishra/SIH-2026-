from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forenx.biometrics import (
    BiometricAuthorizationError,
    BiometricAuthorizationNotFoundError,
    BiometricAuthorizationStore,
    BiometricComparisonMode,
)
from forenx.cases import CaseStore
from forenx.evidence import EvidenceCatalog, EvidenceMediaKind
from forenx.runtime import create_product_app

ADMIN_PASSWORD = "correct horse battery staple"


async def _content(value: bytes) -> AsyncIterator[bytes]:
    yield value


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _setup_admin(client: TestClient) -> str:
    setup = client.post(
        "/api/v1/setup",
        json={
            "username": "administrator",
            "display_name": "Lab Administrator",
            "password": ADMIN_PASSWORD,
        },
    )
    assert setup.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "administrator", "password": ADMIN_PASSWORD},
    )
    assert login.status_code == 200
    return str(login.json()["token"])


def _create_source(database: Path, vault: Path) -> tuple[str, str]:
    cases = CaseStore(database)
    case = cases.create_case(
        case_reference="BIO/2026/01",
        agency="Test Laboratory",
        investigating_officer="Inspector Test",
        classification="Restricted",
        actor_id="intake-1",
    )
    exhibit = cases.add_exhibit(
        case.case_id,
        exhibit_number="VIDEO-01",
        device_type="Video export",
        seal_condition="Intact",
        packaging="Evidence bag",
        collector="Inspector Test",
        collection_location="Laboratory",
        collected_at=datetime(2026, 9, 6, 10, 0, tzinfo=UTC),
        authorization_reference="AUTH-BIO-1",
        actor_id="intake-1",
    )
    catalog = EvidenceCatalog(database, vault)
    source = asyncio.run(
        catalog.ingest(
            _content(b"controlled video bytes"),
            case_id=case.case_id,
            exhibit_id=exhibit.exhibit_id,
            original_filename="controlled-cctv.mp4",
            media_kind=EvidenceMediaKind.VIDEO_FILE,
            created_by="intake-1",
        )
    )
    return case.case_id, source.source_id


def test_biometric_authorization_is_immutable_persistent_and_expires(tmp_path: Path):
    database = tmp_path / "forenx.sqlite3"
    case_id, source_id = _create_source(database, tmp_path / "vault")
    store = BiometricAuthorizationStore(database)
    authorized_at = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
    retention_until = authorized_at + timedelta(days=30)

    authorization = store.authorize(
        case_id=case_id,
        source_id=source_id,
        mode=BiometricComparisonMode.ONE_TO_ONE,
        purpose="Compare one selected CCTV face with one case reference.",
        legal_authority_reference="Court order CO-BIO-01",
        reference_provenance="Custody photograph REF-01 supplied by investigator.",
        retention_until=retention_until,
        threshold_policy="Return no result below validated quality and similarity thresholds.",
        authorized_by="supervisor-1",
        authorized_at=authorized_at,
    )

    assert store.get(authorization.authorization_id) == authorization
    assert store.list_for_source(source_id) == (authorization,)
    assert store.latest_active(
        source_id,
        at=retention_until - timedelta(microseconds=1),
    ) == authorization
    with pytest.raises(BiometricAuthorizationNotFoundError, match="No active"):
        store.latest_active(source_id, at=retention_until)

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE biometric_authorizations SET purpose = ? WHERE authorization_id = ?",
                ("Changed", authorization.authorization_id),
            )

    store.close()
    reopened = BiometricAuthorizationStore(database)
    assert reopened.get(authorization.authorization_id) == authorization


def test_biometric_authorization_rejects_invalid_retention(tmp_path: Path):
    database = tmp_path / "forenx.sqlite3"
    case_id, source_id = _create_source(database, tmp_path / "vault")
    store = BiometricAuthorizationStore(database)
    authorized_at = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)

    with pytest.raises(BiometricAuthorizationError, match="deadline"):
        store.authorize(
            case_id=case_id,
            source_id=source_id,
            mode=BiometricComparisonMode.ONE_TO_ONE,
            purpose="Controlled comparison",
            legal_authority_reference="AUTH-1",
            reference_provenance="Reference REF-1",
            retention_until=authorized_at,
            threshold_policy="Predetermined threshold",
            authorized_by="supervisor-1",
            authorized_at=authorized_at,
        )


def test_biometric_authorization_api_is_supervisor_gated_and_requires_inspection(
    tmp_path: Path,
    sample_mp4: bytes,
):
    application = create_product_app(tmp_path / "biometric-product")
    client = TestClient(application)
    admin_token = _setup_admin(client)
    admin_headers = _authorization(admin_token)
    case = client.post(
        "/api/v1/cases",
        headers=admin_headers,
        json={
            "case_reference": "FSL/2026/BIO-API-1",
            "agency": "State FSL",
            "investigating_officer": "Inspector Biometric",
            "classification": "Restricted",
        },
    ).json()
    exhibit = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits",
        headers=admin_headers,
        json={
            "exhibit_number": "BIO-VIDEO-01",
            "device_type": "Video export",
            "seal_condition": "Intact",
            "packaging": "Digital evidence transfer",
            "collector": "Inspector Biometric",
            "collection_location": "Laboratory",
            "collected_at": "2026-09-06T10:00:00+05:30",
            "authorization_reference": "AUTH-BIO-API-1",
        },
    ).json()
    source = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **admin_headers,
            "X-ForenX-Filename": "controlled-cctv.mp4",
            "X-ForenX-Media-Kind": "video-file",
        },
        content=sample_mp4,
    ).json()
    raw_source = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **admin_headers,
            "X-ForenX-Filename": "recorder.img",
            "X-ForenX-Media-Kind": "raw-disk-image",
        },
        content=b"synthetic recorder bytes",
    ).json()
    request = {
        "mode": "one-to-one",
        "purpose": "Compare one selected CCTV face with one case reference.",
        "legal_authority_reference": "Court order CO-BIO-API-1",
        "reference_provenance": "Custody photograph REF-01 supplied by investigator.",
        "retention_until": "2027-09-06T12:00:00+05:30",
        "threshold_policy": "Return no result below validated thresholds.",
    }

    raw_denied = client.post(
        f"/api/v1/evidence/{raw_source['source_id']}/biometric-authorizations",
        headers=admin_headers,
        json=request,
    )
    assert raw_denied.status_code == 409

    before_inspection = client.post(
        f"/api/v1/evidence/{source['source_id']}/biometric-authorizations",
        headers=admin_headers,
        json=request,
    )
    assert before_inspection.status_code == 409

    inspected = client.post(
        f"/api/v1/evidence/{source['source_id']}/inspect",
        headers=admin_headers,
    )
    assert inspected.status_code == 200

    detection_without_authorization = client.post(
        f"/api/v1/evidence/{source['source_id']}/face-detections",
        headers=admin_headers,
        json={"timestamp_ms": 250},
    )
    assert detection_without_authorization.status_code == 409

    created_user = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": "examiner-bio",
            "display_name": "Biometric Examiner",
            "password": "examiner secure password",
            "role": "examiner",
        },
    )
    assert created_user.status_code == 201
    examiner_login = client.post(
        "/api/v1/auth/login",
        json={"username": "examiner-bio", "password": "examiner secure password"},
    )
    examiner_headers = _authorization(str(examiner_login.json()["token"]))
    denied = client.post(
        f"/api/v1/evidence/{source['source_id']}/biometric-authorizations",
        headers=examiner_headers,
        json=request,
    )
    assert denied.status_code == 403

    unsupported_mode = client.post(
        f"/api/v1/evidence/{source['source_id']}/biometric-authorizations",
        headers=admin_headers,
        json={**request, "mode": "one-to-many"},
    )
    assert unsupported_mode.status_code == 422

    authorization = client.post(
        f"/api/v1/evidence/{source['source_id']}/biometric-authorizations",
        headers=admin_headers,
        json=request,
    )
    assert authorization.status_code == 201
    record = authorization.json()
    assert record["mode"] == "one-to-one"
    assert record["source_id"] == source["source_id"]
    assert record["authorized_by"] == client.get(
        "/api/v1/auth/me", headers=admin_headers
    ).json()["user_id"]

    assigned = client.post(
        f"/api/v1/cases/{case['case_id']}/assignments",
        headers=admin_headers,
        json={"user_id": created_user.json()["user_id"]},
    )
    assert assigned.status_code == 201

    listed = client.get(
        f"/api/v1/evidence/{source['source_id']}/biometric-authorizations",
        headers=examiner_headers,
    )
    assert listed.json() == [record]
    activity = client.get(
        f"/api/v1/cases/{case['case_id']}/activity",
        headers=admin_headers,
    ).json()
    assert activity[-2]["action"] == "BIOMETRIC_ANALYSIS_AUTHORIZED"
    assert activity[-1]["action"] == "CASE_ACCESS_GRANTED"
    assert activity[-2]["details"]["authorization_id"] == record["authorization_id"]

    detection = client.post(
        f"/api/v1/evidence/{source['source_id']}/face-detections",
        headers=admin_headers,
        json={"timestamp_ms": 250},
    )
    assert detection.status_code == 201
    run = detection.json()
    assert run["authorization_id"] == record["authorization_id"]
    assert run["requested_timestamp_ms"] == 250
    assert run["observed_timestamp_ms"] == 200
    assert run["model_id"] == "opencv-yunet-2026may"
    assert run["model_license"] == "MIT"
    assert len(run["model_sha256"]) == 64
    assert run["faces"] == []

    listed_detections = client.get(
        f"/api/v1/evidence/{source['source_id']}/face-detections",
        headers=examiner_headers,
    )
    assert listed_detections.json() == [run]
    anonymous_preview = TestClient(application).get(
        f"/api/v1/evidence/{source['source_id']}/face-detections/{run['run_id']}/preview"
    )
    assert anonymous_preview.status_code == 401
    preview = client.get(
        f"/api/v1/evidence/{source['source_id']}/face-detections/{run['run_id']}/preview"
    )
    assert preview.status_code == 200
    assert preview.headers["x-forenx-preview-sha256"] == hashlib.sha256(
        preview.content
    ).hexdigest()
    assert preview.content.startswith(b"\x89PNG\r\n\x1a\n")

    preview_path = (
        application.state.data_directory
        / "analysis-vault"
        / "face-detection-frames"
        / f"{run['run_id']}.png"
    )
    preview_path.chmod(0o600)
    preview_path.write_bytes(preview_path.read_bytes() + b"tampered")
    preview_path.chmod(0o400)
    refused_tampered_preview = client.get(
        f"/api/v1/evidence/{source['source_id']}/face-detections/{run['run_id']}/preview"
    )
    assert refused_tampered_preview.status_code == 422

    current_case = case
    for target in (
        "acquisition",
        "processing",
        "examiner-review",
        "supervisor-review",
        "approved",
        "closed",
    ):
        transitioned = client.post(
            f"/api/v1/cases/{case['case_id']}/transition",
            headers=admin_headers,
            json={
                "target_status": target,
                "expected_version": current_case["version"],
                "reason": f"Controlled validation: advance to {target}",
            },
        )
        assert transitioned.status_code == 200
        current_case = transitioned.json()

    closed_denied = client.post(
        f"/api/v1/evidence/{source['source_id']}/biometric-authorizations",
        headers=admin_headers,
        json=request,
    )
    assert closed_denied.status_code == 409
    closed_detection = client.post(
        f"/api/v1/evidence/{source['source_id']}/face-detections",
        headers=admin_headers,
        json={"timestamp_ms": 250},
    )
    assert closed_detection.status_code == 409
    report_with_tampered_preview = client.post(
        f"/api/v1/evidence/{source['source_id']}/reports",
        headers=admin_headers,
        json={
            "signing_password": "laboratory report passphrase",
            "report_title": "Controlled face analysis",
            "purpose": "Verify that analysis-preview tampering blocks export.",
            "examiner_conclusion": "No conclusion because the preview failed integrity.",
        },
    )
    assert report_with_tampered_preview.status_code == 422
    assert "integrity" in report_with_tampered_preview.json()["detail"]
