from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forenx.cases import CaseStore
from forenx.evidence import (
    EvidenceCatalog,
    EvidenceCatalogError,
    EvidenceMediaKind,
)


async def _chunks(*values: bytes) -> AsyncIterator[bytes]:
    for value in values:
        yield value


def _case_and_exhibit(database: Path) -> tuple[str, str]:
    cases = CaseStore(database)
    case = cases.create_case(
        case_reference="CATALOG/2026/01",
        agency="Test Laboratory",
        investigating_officer="Inspector Test",
        classification="Restricted",
        actor_id="intake-1",
    )
    exhibit = cases.add_exhibit(
        case.case_id,
        exhibit_number="EX-01",
        device_type="Disk image",
        seal_condition="Intact",
        packaging="Evidence bag",
        collector="Inspector Test",
        collection_location="Laboratory intake",
        collected_at=datetime(2026, 9, 6, 10, 0, tzinfo=UTC),
        authorization_reference="AUTH-001",
        actor_id="intake-1",
    )
    return case.case_id, exhibit.exhibit_id


def test_streamed_evidence_is_hashed_private_and_persistent(tmp_path: Path):
    database = tmp_path / "forenx.sqlite3"
    case_id, exhibit_id = _case_and_exhibit(database)
    vault = tmp_path / "vault"
    catalog = EvidenceCatalog(database, vault)

    record = asyncio.run(
        catalog.ingest(
            _chunks(b"forensic ", b"evidence"),
            case_id=case_id,
            exhibit_id=exhibit_id,
            original_filename="recorder.img",
            media_kind=EvidenceMediaKind.RAW_DISK_IMAGE,
            created_by="intake-1",
            declared_size=17,
        )
    )

    assert record.byte_size == 17
    assert record.sha256 == "9c9ed3e2ac7b161a83827c1d28ebcb2fd7f701709d368b013b1a3f46905052bb"
    assert record.stored_path.read_bytes() == b"forensic evidence"
    assert record.stored_path.stat().st_mode & 0o777 == 0o400
    assert vault.stat().st_mode & 0o777 == 0o700
    assert catalog.verify(record.source_id) == (True, record.sha256)
    assert catalog.list_for_case(case_id) == (record,)

    catalog.close()
    reopened = EvidenceCatalog(database, vault)
    assert reopened.get(record.source_id) == record


def test_invalid_or_oversize_ingest_leaves_no_partial_file(tmp_path: Path):
    database = tmp_path / "forenx.sqlite3"
    case_id, exhibit_id = _case_and_exhibit(database)
    vault = tmp_path / "vault"
    catalog = EvidenceCatalog(database, vault, max_ingest_bytes=3)

    with pytest.raises(EvidenceCatalogError, match="filename"):
        asyncio.run(
            catalog.ingest(
                _chunks(b"abc"),
                case_id=case_id,
                exhibit_id=exhibit_id,
                original_filename="../escape.img",
                media_kind=EvidenceMediaKind.RAW_DISK_IMAGE,
                created_by="intake-1",
            )
        )
    with pytest.raises(EvidenceCatalogError, match="ingest limit"):
        asyncio.run(
            catalog.ingest(
                _chunks(b"four"),
                case_id=case_id,
                exhibit_id=exhibit_id,
                original_filename="oversize.img",
                media_kind=EvidenceMediaKind.RAW_DISK_IMAGE,
                created_by="intake-1",
            )
        )

    assert list(vault.iterdir()) == []


def test_declared_size_mismatch_is_rejected(tmp_path: Path):
    database = tmp_path / "forenx.sqlite3"
    case_id, exhibit_id = _case_and_exhibit(database)
    vault = tmp_path / "vault"
    catalog = EvidenceCatalog(database, vault)

    with pytest.raises(EvidenceCatalogError, match="did not match"):
        asyncio.run(
            catalog.ingest(
                _chunks(b"abc"),
                case_id=case_id,
                exhibit_id=exhibit_id,
                original_filename="source.raw",
                media_kind=EvidenceMediaKind.RAW_DISK_IMAGE,
                created_by="intake-1",
                declared_size=4,
            )
        )

    assert list(vault.iterdir()) == []
