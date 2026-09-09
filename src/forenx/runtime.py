from __future__ import annotations

import os
import secrets
import stat
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
    setup_code_path = directory / "setup-code.txt"
    setup_code = _installation_code(setup_code_path) if auth_store.count_users() == 0 else None
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
        setup_code=setup_code,
    )
    application.state.data_directory = directory
    application.state.database = database
    application.state.setup_code_path = setup_code_path if setup_code is not None else None
    return application


def _installation_code(path: Path) -> str:
    """Create a private installation credential without overwriting another launch's code."""
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow, 0o600)
    except FileExistsError:
        try:
            descriptor = os.open(path, os.O_RDONLY | no_follow)
            with os.fdopen(descriptor, "r", encoding="ascii") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    raise RuntimeConfigurationError("Installation code must be an owner-only file")
                code = handle.read(257).strip()
            if len(code) != 43 or any(c not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in code):
                raise RuntimeConfigurationError("Installation code file is invalid; retry startup")
            return code
        except (OSError, UnicodeError) as exc:
            raise RuntimeConfigurationError("Installation code could not be read securely") from exc
    except OSError as exc:
        raise RuntimeConfigurationError("Installation code could not be created securely") from exc
    code = secrets.token_urlsafe(32)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(code + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return code


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
