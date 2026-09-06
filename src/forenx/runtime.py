from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi import FastAPI

from forenx.adapters import AdapterRegistry
from forenx.api.app import create_app
from forenx.auth import AuthStore
from forenx.biometrics import (
    BiometricAuthorizationStore,
    FaceDetectionStore,
    FaceDetector,
    FaceTrackingStore,
)
from forenx.cases import CaseStore
from forenx.evidence import EvidenceCatalog
from forenx.recovery import RecoveryStore
from forenx.reporting import ReportPackageService
from forenx.video import MediaInspector, MediaStore


class RuntimeConfigurationError(RuntimeError):
    pass


def default_data_directory() -> Path:
    configured = os.environ.get("FORENX_DATA_DIR")
    if configured:
        return Path(configured).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ForenX"
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "ForenX"
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "forenx"
    return Path.home() / ".local" / "share" / "forenx"


def create_product_app(
    data_directory: str | Path | None = None,
    *,
    adapter_registry: AdapterRegistry | None = None,
) -> FastAPI:
    directory = _prepare_data_directory(
        default_data_directory() if data_directory is None else Path(data_directory)
    )
    database = directory / "forenx.sqlite3"
    case_store = CaseStore(database)
    auth_store = AuthStore(database)
    evidence_catalog = EvidenceCatalog(database, directory / "evidence-vault")
    media_store = MediaStore(database)
    biometric_authorizations = BiometricAuthorizationStore(database)
    face_detection_store = FaceDetectionStore(
        database,
        directory / "analysis-vault" / "face-detection-frames",
    )
    face_tracking_store = FaceTrackingStore(database)
    recovery_store = RecoveryStore(database, directory / "recovery-vault")
    report_service = ReportPackageService(
        database,
        directory / "report-exports",
        cases=case_store,
        evidence=evidence_catalog,
        media=media_store,
        biometric_authorizations=biometric_authorizations,
        face_detections=face_detection_store,
        face_tracks=face_tracking_store,
    )
    application = create_app(
        adapter_registry=adapter_registry,
        case_store=case_store,
        auth_store=auth_store,
        evidence_catalog=evidence_catalog,
        media_store=media_store,
        media_inspector=MediaInspector(),
        report_service=report_service,
        biometric_authorization_store=biometric_authorizations,
        face_detection_store=face_detection_store,
        face_detector=FaceDetector(),
        face_tracking_store=face_tracking_store,
        recovery_store=recovery_store,
    )
    application.state.data_directory = directory
    application.state.database = database
    return application


def _prepare_data_directory(candidate: Path) -> Path:
    expanded = candidate.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise RuntimeConfigurationError("ForenX data directory cannot be a symbolic link")
    try:
        expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = expanded.resolve(strict=True)
        if not resolved.is_dir():
            raise RuntimeConfigurationError("ForenX data location is not a directory")
        os.chmod(resolved, 0o700)
    except OSError as exc:
        raise RuntimeConfigurationError(
            "ForenX data directory could not be created securely"
        ) from exc
    return resolved
