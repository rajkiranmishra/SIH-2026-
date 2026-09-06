from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forenx.cases import CaseStore
from forenx.evidence import EvidenceCatalog, EvidenceMediaKind
from forenx.video import MediaInspectionNotFoundError, MediaInspector, MediaStore


async def _content(value: bytes) -> AsyncIterator[bytes]:
    yield value


def _create_source(
    database: Path,
    vault: Path,
    sample_mp4: bytes,
) -> tuple[str, str, Path]:
    cases = CaseStore(database)
    case = cases.create_case(
        case_reference="MEDIA/2026/01",
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
        authorization_reference="AUTH-MEDIA-1",
        actor_id="intake-1",
    )
    catalog = EvidenceCatalog(database, vault)
    source = asyncio.run(
        catalog.ingest(
            _content(sample_mp4),
            case_id=case.case_id,
            exhibit_id=exhibit.exhibit_id,
            original_filename="controlled-cctv.mp4",
            media_kind=EvidenceMediaKind.VIDEO_FILE,
            created_by="intake-1",
            declared_size=len(sample_mp4),
        )
    )
    return case.case_id, source.source_id, source.stored_path


def test_media_inspection_and_bookmarks_are_persistent(
    tmp_path: Path,
    sample_mp4: bytes,
):
    database = tmp_path / "forenx.sqlite3"
    case_id, source_id, source_path = _create_source(
        database,
        tmp_path / "vault",
        sample_mp4,
    )
    store = MediaStore(database)
    inspection = MediaInspector().inspect(source_path)

    saved = store.save_inspection(
        source_id,
        inspection,
        inspected_by="examiner-1",
        inspected_at=datetime(2026, 9, 6, 11, 0, tzinfo=UTC),
    )
    bookmark = store.add_bookmark(
        case_id=case_id,
        source_id=source_id,
        timestamp_ms=250,
        title="Person enters frame",
        note="Controlled validation event",
        created_by="examiner-1",
        created_at=datetime(2026, 9, 6, 11, 1, tzinfo=UTC),
    )

    assert store.latest_inspection(source_id) == saved
    assert saved.result.streams[0].width == 160
    assert store.list_bookmarks(source_id) == (bookmark,)


def test_media_store_rejects_missing_inspection_and_negative_bookmark(
    tmp_path: Path,
    sample_mp4: bytes,
):
    database = tmp_path / "forenx.sqlite3"
    case_id, source_id, _source_path = _create_source(
        database,
        tmp_path / "vault",
        sample_mp4,
    )
    store = MediaStore(database)

    with pytest.raises(MediaInspectionNotFoundError, match="not been inspected"):
        store.latest_inspection(source_id)
    with pytest.raises(ValueError, match="negative"):
        store.add_bookmark(
            case_id=case_id,
            source_id=source_id,
            timestamp_ms=-1,
            title="Invalid",
            note=None,
            created_by="examiner-1",
        )
