from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from PIL import Image

from forenx.biometrics import (
    BiometricAuthorizationStore,
    BiometricComparisonMode,
    DetectedFace,
    DetectorModelError,
    FaceDetectionError,
    FaceDetectionRunNotFoundError,
    FaceDetectionStore,
    FaceDetectionStoreError,
    FaceDetector,
    FacePoint,
    bundled_face_detector,
)
from forenx.cases import CaseStore
from forenx.evidence import EvidenceCatalog, EvidenceMediaKind


async def _content(value: bytes) -> AsyncIterator[bytes]:
    yield value


def _worker_payload(preview: bytes) -> dict[str, object]:
    model = bundled_face_detector()
    return {
        "requested_timestamp_ms": 100,
        "observed_timestamp_ms": 80,
        "source_frame_sha256": "1" * 64,
        "frame_width": 100,
        "frame_height": 80,
        "analysis_width": 100,
        "analysis_height": 80,
        "model_sha256": model.sha256,
        "runtime": "test-runtime",
        "runtime_version": "1.0",
        "score_threshold": 0.9,
        "nms_threshold": 0.3,
        "max_dimension": 1280,
        "preview_sha256": hashlib.sha256(preview).hexdigest(),
        "faces": [
            {
                "sequence": 1,
                "x": 10,
                "y": 15,
                "width": 30,
                "height": 35,
                "landmarks": [
                    {"x": 15 + index, "y": 20 + index} for index in range(5)
                ],
                "confidence": 0.97,
                "quality_flags": ["small-face"],
            }
        ],
    }


def test_bundled_yunet_model_and_blank_video_detection_are_hash_pinned(
    tmp_path: Path,
    sample_mp4: bytes,
):
    source = tmp_path / "controlled-cctv.mp4"
    source.write_bytes(sample_mp4)
    model = bundled_face_detector()

    result = FaceDetector().detect(source, timestamp_ms=250)

    assert model.model_id == "opencv-yunet-2026may"
    assert model.license_spdx == "MIT"
    assert model.sha256 == hashlib.sha256(model.path.read_bytes()).hexdigest()
    assert result.model == model
    assert result.requested_timestamp_ms == 250
    assert result.observed_timestamp_ms == 200
    assert (result.frame_width, result.frame_height) == (160, 120)
    assert result.faces == ()
    assert result.preview_sha256 == hashlib.sha256(result.preview_png).hexdigest()
    preview = tmp_path / "preview.png"
    preview.write_bytes(result.preview_png)
    with Image.open(preview) as image:
        assert image.size == (160, 120)


def test_face_detector_rejects_unsafe_paths_timestamps_and_timeout(tmp_path: Path):
    detector = FaceDetector()
    with pytest.raises(FaceDetectionError, match="safe regular"):
        detector.detect(tmp_path / "missing.mp4", timestamp_ms=0)
    source = tmp_path / "source.mp4"
    source.write_bytes(b"media")
    link = tmp_path / "linked.mp4"
    link.symlink_to(source)
    with pytest.raises(FaceDetectionError, match="safe regular"):
        detector.detect(link, timestamp_ms=0)
    with pytest.raises(ValueError, match="negative"):
        detector.detect(source, timestamp_ms=-1)

    detector._worker = tmp_path / "worker.py"  # type: ignore[attr-defined]
    detector._worker.write_text("worker")  # type: ignore[attr-defined]
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            subprocess,
            "run",
            Mock(side_effect=subprocess.TimeoutExpired(cmd="worker", timeout=1)),
        )
        with pytest.raises(FaceDetectionError, match="time limit"):
            detector.detect(source, timestamp_ms=0)


def test_face_detector_validates_a_successful_worker_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "source.mp4"
    source.write_bytes(b"bounded media")
    preview = b"bounded preview"
    payload = _worker_payload(preview)

    def successful_worker(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        Path(command[5]).write_bytes(preview)
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(subprocess, "run", successful_worker)
    result = FaceDetector().detect(source, timestamp_ms=100)

    assert result.observed_timestamp_ms == 80
    assert result.preview_png == preview
    assert result.faces[0].confidence == 0.97
    assert result.faces[0].quality_flags == ("small-face",)
    assert len(result.faces[0].landmarks) == 5


def test_face_detector_fails_closed_on_untrusted_worker_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "source.mp4"
    source.write_bytes(b"bounded media")
    detector = FaceDetector()

    monkeypatch.setattr(subprocess, "run", Mock(side_effect=OSError("refused")))
    with pytest.raises(FaceDetectionError, match="could not start"):
        detector.detect(source, timestamp_ms=0)

    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0, "x" * (2 * 1024 * 1024 + 1), "")),
    )
    with pytest.raises(FaceDetectionError, match="excessive"):
        detector.detect(source, timestamp_ms=0)

    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0, "not-json", "")),
    )
    with pytest.raises(FaceDetectionError, match="invalid result"):
        detector.detect(source, timestamp_ms=0)

    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess(
                [], 1, json.dumps({"detail": "decoder rejected input"}), ""
            )
        ),
    )
    with pytest.raises(FaceDetectionError, match="decoder rejected"):
        detector.detect(source, timestamp_ms=0)

    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps({}), "")),
    )
    with pytest.raises(FaceDetectionError, match="safe preview"):
        detector.detect(source, timestamp_ms=0)

    preview = b"preview"
    payload = _worker_payload(preview)

    def mismatched_worker(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        Path(command[5]).write_bytes(b"different")
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    monkeypatch.setattr(subprocess, "run", mismatched_worker)
    with pytest.raises(FaceDetectionError, match="integrity"):
        detector.detect(source, timestamp_ms=0)

    def incomplete_worker(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        Path(command[5]).write_bytes(preview)
        incomplete = {**payload, "model_sha256": "0" * 64}
        return subprocess.CompletedProcess(command, 0, json.dumps(incomplete), "")

    monkeypatch.setattr(subprocess, "run", incomplete_worker)
    with pytest.raises(FaceDetectionError, match="incomplete"):
        detector.detect(source, timestamp_ms=0)


def test_face_detection_store_preserves_faces_and_fails_closed(
    tmp_path: Path,
    sample_mp4: bytes,
    monkeypatch: pytest.MonkeyPatch,
):
    database = tmp_path / "forenx.sqlite3"
    cases = CaseStore(database)
    case = cases.create_case(
        case_reference="FACE/2026/01",
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
        authorization_reference="AUTH-FACE-1",
        actor_id="intake-1",
    )
    catalog = EvidenceCatalog(database, tmp_path / "evidence-vault")
    source = asyncio.run(
        catalog.ingest(
            _content(sample_mp4),
            case_id=case.case_id,
            exhibit_id=exhibit.exhibit_id,
            original_filename="controlled-cctv.mp4",
            media_kind=EvidenceMediaKind.VIDEO_FILE,
            created_by="intake-1",
        )
    )
    authorization_time = datetime.now(UTC) - timedelta(minutes=1)
    authorization = BiometricAuthorizationStore(database).authorize(
        case_id=case.case_id,
        source_id=source.source_id,
        mode=BiometricComparisonMode.ONE_TO_ONE,
        purpose="Locate faces in one controlled source.",
        legal_authority_reference="AUTH-FACE-1",
        reference_provenance="Case photograph REF-1.",
        retention_until=authorization_time + timedelta(days=1),
        threshold_policy="Detector threshold fixed before the run.",
        authorized_by="supervisor-1",
        authorized_at=authorization_time,
    )
    result = FaceDetector().detect(source.stored_path, timestamp_ms=250)
    result = replace(
        result,
        faces=(
            DetectedFace(
                sequence=1,
                x=10,
                y=12,
                width=30,
                height=32,
                landmarks=tuple(FacePoint(15 + index, 20 + index) for index in range(5)),
                confidence=0.98,
                quality_flags=("small-face",),
            ),
        ),
    )
    vault = tmp_path / "analysis-vault"
    store = FaceDetectionStore(database, vault)
    saved = store.save(
        case_id=case.case_id,
        source_id=source.source_id,
        authorization_id=authorization.authorization_id,
        result=result,
        created_by="examiner-1",
    )

    assert saved.faces[0].landmarks[4] == FacePoint(19, 24)
    assert store.list_for_source(source.source_id) == (saved,)
    assert store.preview(saved.run_id)[1] == result.preview_sha256
    with pytest.raises(FaceDetectionRunNotFoundError):
        store.get("missing")
    with pytest.raises(FaceDetectionRunNotFoundError):
        store.preview("missing")
    with pytest.raises(ValueError, match="Creator"):
        store.save(
            case_id=case.case_id,
            source_id=source.source_id,
            authorization_id=authorization.authorization_id,
            result=result,
            created_by="",
        )
    with pytest.raises(FaceDetectionStoreError, match="hash"):
        store.save(
            case_id=case.case_id,
            source_id=source.source_id,
            authorization_id=authorization.authorization_id,
            result=replace(result, preview_sha256="0" * 64),
            created_by="examiner-1",
        )
    before = set(vault.iterdir())
    with pytest.raises(ValueError, match="timezone-aware"):
        store.save(
            case_id=case.case_id,
            source_id=source.source_id,
            authorization_id=authorization.authorization_id,
            result=result,
            created_by="examiner-1",
            created_at=datetime(2026, 9, 6),
        )
    assert set(vault.iterdir()) == before

    monkeypatch.setattr(
        "forenx.biometrics.detection_store._write_immutable",
        Mock(side_effect=OSError("read-only volume")),
    )
    with pytest.raises(FaceDetectionStoreError, match="could not be stored"):
        store.save(
            case_id=case.case_id,
            source_id=source.source_id,
            authorization_id=authorization.authorization_id,
            result=result,
            created_by="examiner-1",
        )

    store.close()
    store.close()


def test_bundled_detector_rejects_integrity_mismatch(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "forenx.biometrics.models.YUNET_2026MAY_SHA256",
        "0" * 64,
    )
    with pytest.raises(DetectorModelError, match="integrity"):
        bundled_face_detector()


@pytest.mark.parametrize("timeout", [0, 601])
def test_face_detector_rejects_unsafe_timeout(timeout: int):
    with pytest.raises(ValueError, match="timeout"):
        FaceDetector(timeout_seconds=timeout)
