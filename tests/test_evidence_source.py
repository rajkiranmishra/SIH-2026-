import hashlib

import pytest

from forenx.evidence import EvidenceSourceError, RawEvidenceSource


def test_raw_source_reads_only_requested_bytes(tmp_path):
    evidence = tmp_path / "evidence.dd"
    evidence.write_bytes(b"HIKVISION@HANGZHOU" + bytes(range(32)))

    with RawEvidenceSource(evidence) as source:
        assert source.size == evidence.stat().st_size
        assert source.read_at(0, 18) == b"HIKVISION@HANGZHOU"
        assert source.read_at(18, 4) == bytes(range(4))


@pytest.mark.parametrize(
    ("offset", "length"),
    [(-1, 1), (0, -1), (9, 2), (10, 1), (False, 1), (0, True)],
)
def test_raw_source_rejects_unsafe_ranges(tmp_path, offset, length):
    evidence = tmp_path / "evidence.dd"
    evidence.write_bytes(b"0123456789")

    with RawEvidenceSource(evidence) as source:
        with pytest.raises(EvidenceSourceError):
            source.read_at(offset, length)


def test_raw_source_hashes_and_verifies_without_writing(tmp_path):
    evidence = tmp_path / "evidence.dd"
    content = b"forensic-source" * 100
    evidence.write_bytes(content)
    before = evidence.read_bytes()

    with RawEvidenceSource(evidence, max_read_size=64) as source:
        expected = hashlib.sha256(content).hexdigest()
        assert source.sha256(chunk_size=31) == expected
        assert source.verify_sha256(expected.upper())
        assert not source.verify_sha256("0" * 64)

    assert evidence.read_bytes() == before


def test_closed_source_cannot_be_read(tmp_path):
    evidence = tmp_path / "evidence.dd"
    evidence.write_bytes(b"data")
    source = RawEvidenceSource(evidence)
    source.close()

    with pytest.raises(EvidenceSourceError, match="closed"):
        source.read_at(0, 1)


def test_raw_source_enforces_per_read_limit(tmp_path):
    evidence = tmp_path / "evidence.dd"
    evidence.write_bytes(b"0123456789")
    with RawEvidenceSource(evidence, max_read_size=4) as source:
        with pytest.raises(EvidenceSourceError, match="safety limit"):
            source.read_at(0, 5)


@pytest.mark.parametrize("max_read_size", [0, -1, False])
def test_raw_source_requires_positive_read_limit(tmp_path, max_read_size):
    evidence = tmp_path / "evidence.dd"
    evidence.write_bytes(b"data")
    with pytest.raises(EvidenceSourceError, match="positive integer"):
        RawEvidenceSource(evidence, max_read_size=max_read_size)


def test_raw_source_rejects_directory_and_invalid_hash_inputs(tmp_path):
    with pytest.raises(EvidenceSourceError, match="regular file"):
        RawEvidenceSource(tmp_path)

    evidence = tmp_path / "evidence.dd"
    evidence.write_bytes(b"data")
    with RawEvidenceSource(evidence) as source:
        with pytest.raises(EvidenceSourceError, match="64 hexadecimal"):
            source.verify_sha256("not-a-digest")
        with pytest.raises(EvidenceSourceError, match="positive integer"):
            source.sha256(chunk_size=0)
