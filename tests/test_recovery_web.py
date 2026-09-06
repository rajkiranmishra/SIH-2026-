import hashlib
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from forenx.adapters import (
    AdapterCapability,
    AdapterMaturity,
    AdapterRegistration,
    AdapterRegistry,
    DvrFilesystemAdapter,
    ExtractionResult,
    PhysicalExtent,
    ProbeEvidence,
    ProbeResult,
    ReadableEvidence,
    RecordingDescriptor,
    RecordingState,
)
from forenx.runtime import create_product_app

ADMIN_PASSWORD = "correct horse battery staple"


class FixtureRecoveryAdapter(DvrFilesystemAdapter):
    adapter_id = "fixture-recorder"
    version = "1.0"

    def probe(self, source: ReadableEvidence) -> ProbeResult:
        matches = source.size >= 8 and source.read_at(0, 4) == b"DVR!"
        return ProbeResult(
            adapter_id=self.adapter_id,
            vendor="Fixture Vendor",
            filesystem="Controlled fixture filesystem",
            confidence=0.99 if matches else 0.0,
            evidence=(
                ProbeEvidence(
                    description="Controlled fixture signature",
                    offset=0,
                    observed_hex="44565221",
                ),
            )
            if matches
            else (),
            capabilities=frozenset(
                {AdapterCapability.ENUMERATE_ACTIVE, AdapterCapability.EXTRACT}
            )
            if matches
            else frozenset(),
            warnings=("Controlled test adapter",),
        )

    def enumerate_recordings(
        self, source: ReadableEvidence
    ) -> Sequence[RecordingDescriptor]:
        return (
            RecordingDescriptor(
                recording_id="fixture-channel-1",
                channel="1",
                start_time=datetime(2026, 9, 6, 6, 0, tzinfo=UTC),
                end_time=datetime(2026, 9, 6, 6, 1, tzinfo=UTC),
                timestamp_source="controlled-fixture",
                state=RecordingState.ACTIVE,
                extents=(PhysicalExtent(offset=4, length=source.size - 4),),
                codec_hint="h264",
                confidence=0.9,
                warnings=("Synthetic fixture",),
            ),
        )

    def extract(
        self,
        source: ReadableEvidence,
        recording: RecordingDescriptor,
        destination: Path,
    ) -> ExtractionResult:
        data = b"".join(
            source.read_at(extent.offset, extent.length) for extent in recording.extents
        )
        destination.write_bytes(data)
        return ExtractionResult(
            output_path=destination,
            sha256=hashlib.sha256(data).hexdigest(),
            bytes_written=len(data),
            source_extents=recording.extents,
            warnings=("Exact controlled-fixture copy",),
            format_hint="h264",
            validation_evidence=("Fixture bitstream accepted",),
        )


def _registry() -> AdapterRegistry:
    adapter = FixtureRecoveryAdapter()
    return AdapterRegistry(
        (
            AdapterRegistration(
                adapter=adapter,
                vendor="Fixture Vendor",
                family="Controlled test fixture",
                maturity=AdapterMaturity.EXPERIMENTAL,
                available_capabilities=frozenset(
                    {AdapterCapability.ENUMERATE_ACTIVE, AdapterCapability.EXTRACT}
                ),
            ),
        )
    )


def _setup_case(client: TestClient) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    client.post(
        "/api/v1/setup",
        json={
            "username": "administrator",
            "display_name": "Lab Administrator",
            "password": ADMIN_PASSWORD,
        },
    )
    token = client.post(
        "/api/v1/auth/login",
        json={"username": "administrator", "password": ADMIN_PASSWORD},
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    case = client.post(
        "/api/v1/cases",
        headers=headers,
        json={
            "case_reference": "FSL/2026/RECOVERY-WEB",
            "agency": "State FSL",
            "investigating_officer": "Inspector Recovery",
            "classification": "Restricted",
        },
    ).json()
    exhibit = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits",
        headers=headers,
        json={
            "exhibit_number": "RECOVERY-01",
            "device_type": "DVR disk image",
            "seal_condition": "Intact",
            "packaging": "Forensic image container",
            "collector": "Inspector Recovery",
            "collection_location": "Laboratory",
            "collected_at": "2026-09-06T10:00:00+05:30",
            "authorization_reference": "AUTH-RECOVERY-WEB",
        },
    ).json()
    return headers, case, exhibit


def test_raw_image_recovery_scan_extract_and_verified_download(tmp_path: Path):
    data_directory = tmp_path / "recovery-product"
    application = create_product_app(data_directory, adapter_registry=_registry())
    client = TestClient(application)
    headers, case, exhibit = _setup_case(client)
    source_bytes = b"DVR!" + b"synthetic-h264-recording"
    source = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **headers,
            "X-ForenX-Filename": "controlled-recorder.img",
            "X-ForenX-Media-Kind": "raw-disk-image",
        },
        content=source_bytes,
    ).json()

    scan_response = client.post(
        f"/api/v1/evidence/{source['source_id']}/recovery-scans",
        headers=headers,
    )
    assert scan_response.status_code == 201
    scan = scan_response.json()
    assert scan["source_sha256"] == hashlib.sha256(source_bytes).hexdigest()
    assert scan["adapter_id"] == "fixture-recorder"
    assert scan["recordings"][0]["recording_id"] == "fixture-channel-1"
    assert scan["recordings"][0]["extents"] == [
        {"offset": 4, "length": len(source_bytes) - 4}
    ]
    assert client.get(
        f"/api/v1/evidence/{source['source_id']}/recovery-scans",
        headers=headers,
    ).json() == [scan]

    extract_response = client.post(
        f"/api/v1/recovery-scans/{scan['scan_id']}/recordings/fixture-channel-1/extract",
        headers=headers,
    )
    assert extract_response.status_code == 201
    artifact = extract_response.json()
    assert artifact["source_extents"] == scan["recordings"][0]["extents"]
    assert artifact["sha256"] == hashlib.sha256(source_bytes[4:]).hexdigest()
    assert client.get(
        f"/api/v1/recovery-scans/{scan['scan_id']}/artifacts",
        headers=headers,
    ).json() == [artifact]
    assert client.get(
        f"/api/v1/recovery-artifacts/{artifact['artifact_id']}/download"
    ).status_code == 401
    downloaded = client.get(
        f"/api/v1/recovery-artifacts/{artifact['artifact_id']}/download",
        headers=headers,
    )
    assert downloaded.content == source_bytes[4:]
    assert downloaded.headers["x-forenx-artifact-sha256"] == artifact["sha256"]
    assert client.post(
        f"/api/v1/recovery-scans/{scan['scan_id']}/recordings/fixture-channel-1/extract",
        headers=headers,
    ).status_code == 409

    activity = client.get(
        f"/api/v1/cases/{case['case_id']}/activity",
        headers=headers,
    ).json()
    assert [item["action"] for item in activity][-6:] == [
        "RECOVERY_SCAN_STARTED",
        "RECOVERY_SCAN_COMPLETED",
        "RECOVERY_EXTRACTION_STARTED",
        "RECOVERY_EXTRACTION_COMPLETED",
        "RECOVERY_EXTRACTION_STARTED",
        "RECOVERY_EXTRACTION_FAILED",
    ]

    artifact_path = data_directory / "recovery-vault" / f"{artifact['artifact_id']}.bin"
    artifact_path.chmod(0o600)
    artifact_path.write_bytes(artifact_path.read_bytes() + b"tampered")
    artifact_path.chmod(0o400)
    refused = client.get(
        f"/api/v1/recovery-artifacts/{artifact['artifact_id']}/download",
        headers=headers,
    )
    assert refused.status_code == 422
    assert "integrity" in refused.json()["detail"]

    database = sqlite3.connect(data_directory / "forenx.sqlite3")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute(
            "UPDATE recovery_scans SET confidence = 0 WHERE scan_id = ?",
            (scan["scan_id"],),
        )
    database.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute(
            "DELETE FROM recovery_artifacts WHERE artifact_id = ?",
            (artifact["artifact_id"],),
        )
    database.close()


def test_recovery_scan_rejects_unsupported_and_video_sources(tmp_path: Path):
    client = TestClient(
        create_product_app(tmp_path / "recovery-negative", adapter_registry=_registry())
    )
    headers, case, exhibit = _setup_case(client)
    unsupported = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **headers,
            "X-ForenX-Filename": "unknown.img",
            "X-ForenX-Media-Kind": "raw-disk-image",
        },
        content=b"UNKNOWN-DISK",
    ).json()
    video = client.post(
        f"/api/v1/cases/{case['case_id']}/exhibits/{exhibit['exhibit_id']}/evidence",
        headers={
            **headers,
            "X-ForenX-Filename": "clip.mp4",
            "X-ForenX-Media-Kind": "video-file",
        },
        content=b"not-a-real-video",
    ).json()

    unsupported_response = client.post(
        f"/api/v1/evidence/{unsupported['source_id']}/recovery-scans",
        headers=headers,
    )
    video_response = client.post(
        f"/api/v1/evidence/{video['source_id']}/recovery-scans",
        headers=headers,
    )
    assert unsupported_response.status_code == 422
    assert "No adapter" in unsupported_response.json()["detail"]
    assert video_response.status_code == 409
