from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forenx.adapters import PhysicalExtent
from forenx.custody.ledger import CustodyLedger
from forenx.package import (
    ArtifactInput,
    KeyManagementError,
    PackageError,
    SourceEvidenceRecord,
    build_evidence_package,
    generate_signing_key,
    load_private_key,
    public_key_fingerprint,
    save_private_key,
    verify_evidence_package,
)
from forenx.package.cli import main as verifier_main

FIXED_TIME = datetime(2026, 9, 6, 9, 30, tzinfo=UTC)


def _source_record() -> SourceEvidenceRecord:
    return SourceEvidenceRecord(
        source_id="SOURCE-001",
        original_filename="dvr-image.dd",
        size=1024 * 1024,
        hashes={"sha256": "a" * 64},
        acquisition_method="forensic image import",
        read_only=True,
    )


def _custody() -> CustodyLedger:
    ledger = CustodyLedger()
    ledger.append(
        case_id="CASE-001",
        actor_id="intake-1",
        actor_role="evidence-intake-officer",
        action="EVIDENCE_RECEIVED",
        occurred_at=FIXED_TIME,
    )
    ledger.append(
        case_id="CASE-001",
        actor_id="examiner-1",
        actor_role="forensic-examiner",
        action="ARTIFACT_EXTRACTED",
        evidence_hashes={"sha256": "b" * 64},
        occurred_at=datetime(2026, 9, 6, 9, 35, tzinfo=UTC),
    )
    return ledger


def _build_package(root: Path, key: Ed25519PrivateKey):
    artifacts = root / "artifacts"
    artifacts.mkdir()
    (artifacts / "video.h264").write_bytes(b"forensic-video-derivative")
    return build_evidence_package(
        root,
        case_id="CASE-001",
        exhibit_id="EXHIBIT-01",
        source=_source_record(),
        artifacts=(
            ArtifactInput(
                relative_path="artifacts/video.h264",
                role="extracted-video-block",
                source_extents=(PhysicalExtent(offset=65536, length=25),),
                transformation="exact source extent copy",
                media_type="video/H264",
            ),
        ),
        custody=_custody(),
        private_key=key,
        signer_id="supervisor-1",
        limitations=("DVR timezone not independently established",),
        created_at=FIXED_TIME,
        package_id="PKG-001",
    )


def _resign_manifest(root: Path, key: Ed25519PrivateKey) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest_bytes = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    manifest_path.write_bytes(manifest_bytes)
    public_bytes = key.public_key().public_bytes_raw()
    envelope = {
        "algorithm": "Ed25519",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "public_key_base64": base64.b64encode(public_bytes).decode(),
        "public_key_fingerprint_sha256": hashlib.sha256(public_bytes).hexdigest(),
        "signature_base64": base64.b64encode(key.sign(manifest_bytes)).decode(),
        "signed_at": "2026-09-06T09:30:00.000000Z",
        "signer_id": "supervisor-1",
    }
    (root / "manifest.signature.json").write_text(
        json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    )


def test_signed_package_verifies_artifacts_custody_and_trust_anchor(tmp_path: Path):
    key = generate_signing_key()
    result = _build_package(tmp_path, key)

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=result.public_key_fingerprint,
    )

    assert result.package_id == "PKG-001"
    assert result.artifact_count == 1
    assert verification.valid
    assert verification.signature_valid
    assert verification.signer_trusted
    assert verification.checked_artifacts == 1
    assert verification.checked_custody_events == 2
    assert verification.issues == ()


def test_valid_signature_without_external_trust_anchor_reports_warning(tmp_path: Path):
    _build_package(tmp_path, generate_signing_key())

    verification = verify_evidence_package(tmp_path)

    assert verification.valid
    assert verification.signature_valid
    assert not verification.signer_trusted
    assert "identity is not established" in verification.warnings[0]


def test_modified_artifact_fails_hash_and_size_verification(tmp_path: Path):
    key = generate_signing_key()
    result = _build_package(tmp_path, key)
    artifact = tmp_path / "artifacts" / "video.h264"
    artifact.write_bytes(artifact.read_bytes() + b"tampered")

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=result.public_key_fingerprint,
    )

    assert not verification.valid
    assert {issue.code for issue in verification.issues} >= {
        "ARTIFACT_HASH_MISMATCH",
        "ARTIFACT_SIZE_MISMATCH",
    }


def test_modified_manifest_fails_ed25519_signature(tmp_path: Path):
    result = _build_package(tmp_path, generate_signing_key())
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=result.public_key_fingerprint,
    )

    assert not verification.valid
    assert not verification.signature_valid
    assert any(issue.code == "SIGNATURE_INVALID" for issue in verification.issues)


def test_resigned_but_modified_custody_event_still_fails_chain_check(tmp_path: Path):
    key = generate_signing_key()
    _build_package(tmp_path, key)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["custody_events"][0]["action"] = "EVIDENCE_REPLACED"
    manifest_path.write_text(json.dumps(manifest))
    _resign_manifest(tmp_path, key)

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=public_key_fingerprint(key),
    )

    assert not verification.valid
    assert verification.signature_valid
    assert any(issue.code == "CUSTODY_HASH_MISMATCH" for issue in verification.issues)


def test_resigned_path_traversal_is_rejected_without_reading_outside_file(tmp_path: Path):
    key = generate_signing_key()
    _build_package(tmp_path, key)
    outside = tmp_path.parent / "outside-evidence.txt"
    outside.write_text("must not be inventoried")
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"][0]["path"] = "../outside-evidence.txt"
    manifest_path.write_text(json.dumps(manifest))
    _resign_manifest(tmp_path, key)

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=public_key_fingerprint(key),
    )

    assert not verification.valid
    assert any(issue.code == "ARTIFACT_UNREADABLE" for issue in verification.issues)
    assert outside.read_text() == "must not be inventoried"


def test_wrong_trust_fingerprint_invalidates_otherwise_valid_package(tmp_path: Path):
    _build_package(tmp_path, generate_signing_key())

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint="0" * 64,
    )

    assert not verification.valid
    assert any(issue.code == "SIGNER_TRUST_MISMATCH" for issue in verification.issues)


def test_verifier_cli_returns_machine_readable_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    result = _build_package(tmp_path, generate_signing_key())

    exit_code = verifier_main(
        [str(tmp_path), "--trusted-key-fingerprint", result.public_key_fingerprint]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["valid"] is True
    assert output["checked_artifacts"] == 1


def test_private_key_is_encrypted_non_overwriting_and_permission_checked(tmp_path: Path):
    key = generate_signing_key()
    key_path = tmp_path / "laboratory-signing-key.pem"

    saved = save_private_key(key, key_path, password=b"correct horse battery staple")

    assert saved == key_path.resolve()
    assert saved.stat().st_mode & 0o777 == 0o600
    loaded = load_private_key(saved, password=b"correct horse battery staple")
    assert public_key_fingerprint(loaded) == public_key_fingerprint(key)
    with pytest.raises(KeyManagementError, match="already exists"):
        save_private_key(key, key_path, password=b"correct horse battery staple")

    os.chmod(saved, 0o644)
    with pytest.raises(KeyManagementError, match="permissions"):
        load_private_key(saved, password=b"correct horse battery staple")


def test_builder_rejects_symlink_artifacts_and_existing_control_files(tmp_path: Path):
    outside = tmp_path.parent / "outside-video.bin"
    outside.write_bytes(b"outside")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "linked.bin").symlink_to(outside)
    key = generate_signing_key()

    with pytest.raises(PackageError, match="symbolic link"):
        build_evidence_package(
            tmp_path,
            case_id="CASE-001",
            exhibit_id="EX-01",
            source=_source_record(),
            artifacts=(
                ArtifactInput(
                    relative_path="artifacts/linked.bin",
                    role="video",
                    source_extents=(PhysicalExtent(0, 1),),
                    transformation="copy",
                ),
            ),
            custody=_custody(),
            private_key=key,
            signer_id="supervisor-1",
        )

    (tmp_path / "manifest.json").write_text("existing")
    with pytest.raises(PackageError, match="already exist"):
        build_evidence_package(
            tmp_path,
            case_id="CASE-001",
            exhibit_id="EX-01",
            source=_source_record(),
            artifacts=(),
            custody=_custody(),
            private_key=key,
            signer_id="supervisor-1",
        )


def test_artifact_input_rejects_path_traversal():
    with pytest.raises(ValueError, match="inside"):
        ArtifactInput(
            relative_path="../outside.bin",
            role="video",
            source_extents=(PhysicalExtent(0, 1),),
            transformation="copy",
        )


def test_missing_package_control_files_return_structured_failure(tmp_path: Path):
    verification = verify_evidence_package(tmp_path)

    assert not verification.valid
    assert verification.issues[0].code == "CONTROL_FILE_ERROR"


def test_resigned_invalid_schema_fields_and_lists_are_reported(tmp_path: Path):
    key = generate_signing_key()
    _build_package(tmp_path, key)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["schema"] = "unknown/v9"
    manifest["case_id"] = ""
    manifest["artifacts"] = "not-a-list"
    manifest["custody_events"] = "not-a-list"
    manifest_path.write_text(json.dumps(manifest))
    _resign_manifest(tmp_path, key)

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=public_key_fingerprint(key),
    )
    codes = {issue.code for issue in verification.issues}

    assert not verification.valid
    assert codes >= {
        "SCHEMA_UNSUPPORTED",
        "MANIFEST_FIELD_INVALID",
        "ARTIFACT_LIST_INVALID",
        "CUSTODY_LIST_INVALID",
    }


def test_missing_artifact_is_reported_without_crashing_verifier(tmp_path: Path):
    result = _build_package(tmp_path, generate_signing_key())
    (tmp_path / "artifacts" / "video.h264").unlink()

    verification = verify_evidence_package(
        tmp_path,
        trusted_public_key_fingerprint=result.public_key_fingerprint,
    )

    assert not verification.valid
    assert any(issue.code == "ARTIFACT_UNREADABLE" for issue in verification.issues)


def test_malformed_signature_encoding_is_reported(tmp_path: Path):
    _build_package(tmp_path, generate_signing_key())
    signature_path = tmp_path / "manifest.signature.json"
    envelope = json.loads(signature_path.read_text())
    envelope["signature_base64"] = "not-valid-base64***"
    signature_path.write_text(json.dumps(envelope))

    verification = verify_evidence_package(tmp_path)

    assert not verification.signature_valid
    assert any(issue.code == "SIGNATURE_INVALID" for issue in verification.issues)


def test_builder_rejects_custody_from_another_case(tmp_path: Path):
    ledger = CustodyLedger()
    ledger.append(
        case_id="CASE-OTHER",
        actor_id="intake-1",
        actor_role="officer",
        action="RECEIVED",
    )

    with pytest.raises(PackageError, match="do not match"):
        build_evidence_package(
            tmp_path,
            case_id="CASE-001",
            exhibit_id="EX-01",
            source=_source_record(),
            artifacts=(),
            custody=ledger,
            private_key=generate_signing_key(),
            signer_id="supervisor-1",
        )


def test_private_key_rejects_short_password_wrong_password_and_symlink(tmp_path: Path):
    key = generate_signing_key()
    key_path = tmp_path / "key.pem"
    with pytest.raises(KeyManagementError, match="at least 12"):
        save_private_key(key, key_path, password=b"short")

    save_private_key(key, key_path, password=b"correct horse battery staple")
    with pytest.raises(KeyManagementError, match="invalid"):
        load_private_key(key_path, password=b"incorrect password value")

    link_path = tmp_path / "key-link.pem"
    link_path.symlink_to(key_path)
    with pytest.raises(KeyManagementError, match="symbolic link"):
        load_private_key(link_path, password=b"correct horse battery staple")


def test_source_record_rejects_invalid_sha256_and_empty_hashes():
    with pytest.raises(ValueError, match="at least one"):
        SourceEvidenceRecord("source", "image.dd", 1, {}, "import", True)
    with pytest.raises(ValueError, match="SHA-256"):
        SourceEvidenceRecord(
            "source",
            "image.dd",
            1,
            {"sha256": "invalid"},
            "import",
            True,
        )
