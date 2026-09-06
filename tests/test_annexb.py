import pytest

from forenx.video import VideoCodec, validate_annex_b, validate_annex_b_chunks

H264_STREAM = (
    b"prefix"
    b"\x00\x00\x00\x01\x67\x64\x00\x1f"
    b"\x00\x00\x01\x68\xee\x3c\x80"
    b"\x00\x00\x00\x01\x65\x88\x84"
)

H265_STREAM = (
    b"\x00\x00\x00\x01\x40\x01"
    b"\x00\x00\x01\x42\x01"
    b"\x00\x00\x00\x01\x44\x01"
    b"\x00\x00\x01\x26\x01"
)


def test_h264_parameter_sets_and_idr_are_reported_with_offsets():
    result = validate_annex_b(H264_STREAM, source_offset=4096)

    assert result.codec is VideoCodec.H264
    assert result.is_valid
    assert result.confidence == 0.98
    assert result.observations[0].start_code_offset == 4096 + len(b"prefix")
    assert result.observations[0].h264_type == 7
    assert len(result.evidence) == 3


def test_h265_parameter_sets_and_idr_are_identified():
    result = validate_annex_b(H265_STREAM)

    assert result.codec is VideoCodec.H265
    assert result.confidence == 0.98
    assert {item.h265_type for item in result.observations} >= {19, 32, 33, 34}


def test_parameter_sets_can_be_observed_across_separate_physical_extents():
    result = validate_annex_b_chunks(
        (
            (b"\x00\x00\x01\x67\x00", 100),
            (b"\x00\x00\x01\x68\x00", 500),
        )
    )

    assert result.codec is VideoCodec.H264
    assert result.confidence == 0.9
    assert [item.header_offset for item in result.observations] == [103, 503]


def test_random_or_incomplete_bytes_are_not_called_video():
    result = validate_annex_b(b"random\x00\x00\x01\x67only-sps")

    assert not result.is_valid
    assert result.codec is None
    assert "No complete" in result.warnings[0]


def test_conflicting_parameter_sets_are_rejected():
    result = validate_annex_b(H264_STREAM + H265_STREAM)

    assert not result.is_valid
    assert "conflicting" in result.warnings[0]


def test_negative_source_offset_is_rejected():
    with pytest.raises(ValueError, match="cannot be negative"):
        validate_annex_b(b"data", source_offset=-1)
