from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from forenx.api.app import create_app
from forenx.reporting import (
    ReportPackageError,
    ReportPackageService,
    ReportRenderingError,
    render_examination_report,
)
from forenx.runtime import create_product_app


def _admin_headers(client: TestClient) -> dict[str, str]:
    client.post(
        "/api/v1/setup",
        json={
            "username": "administrator",
            "display_name": "Lab Administrator",
            "password": "secure laboratory password",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={
            "username": "administrator",
            "password": "secure laboratory password",
        },
    )
    return {"Authorization": f"Bearer {login.json()['token']}"}


def test_report_routes_fail_safely_without_service_or_record(tmp_path: Path):
    unconfigured = TestClient(create_app())
    headers = _admin_headers(unconfigured)
    case = unconfigured.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_reference": "REPORT/UNCONFIGURED",
            "agency": "Test laboratory",
            "investigating_officer": "Test officer",
            "classification": "Restricted",
        },
    ).json()

    unavailable = unconfigured.get(
        f"/api/v1/cases/{case['case_id']}/reports",
        headers=headers,
    )
    configured = TestClient(create_product_app(tmp_path / "product"))
    configured_headers = _admin_headers(configured)
    missing = configured.get(
        "/api/v1/reports/unknown-package/download",
        headers=configured_headers,
    )
    unknown_case = configured.get(
        "/api/v1/cases/unknown-case/reports",
        headers=configured_headers,
    )

    assert unavailable.status_code == 503
    assert missing.status_code == 404
    assert unknown_case.status_code == 404


def test_report_renderer_and_export_root_reject_invalid_inputs(tmp_path: Path):
    with pytest.raises(ReportRenderingError, match="incomplete"):
        render_examination_report({})

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(ReportPackageError, match="symbolic link"):
        ReportPackageService(
            ":memory:",
            linked_root,
            cases=Mock(),
            evidence=Mock(),
            media=Mock(),
        )
