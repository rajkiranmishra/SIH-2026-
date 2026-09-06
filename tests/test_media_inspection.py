import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from forenx.video import MediaInspectionError, MediaInspector


def test_media_inspector_reads_container_and_video_stream(
    tmp_path: Path,
    sample_mp4: bytes,
):
    source = tmp_path / "source.mp4"
    source.write_bytes(sample_mp4)

    result = MediaInspector().inspect(source)

    assert result.format_name == "mov,mp4,m4a,3gp,3g2,mj2"
    assert result.duration_seconds == pytest.approx(1.0)
    assert result.library == "PyAV"
    video = result.streams[0]
    assert video.type == "video"
    assert video.codec_name == "mpeg4"
    assert (video.width, video.height) == (160, 120)
    assert video.average_frame_rate == pytest.approx(10.0)
    assert video.frame_count == 10


def test_media_inspector_rejects_invalid_media(tmp_path: Path):
    source = tmp_path / "invalid.mp4"
    source.write_bytes(b"not a media container")

    with pytest.raises(MediaInspectionError, match="failed"):
        MediaInspector().inspect(source)


def test_media_inspector_rejects_symlink(tmp_path: Path):
    source = tmp_path / "source.mp4"
    source.write_bytes(b"media")
    link = tmp_path / "linked.mp4"
    link.symlink_to(source)

    with pytest.raises(MediaInspectionError, match="safe regular file"):
        MediaInspector().inspect(link)


def test_media_inspector_handles_worker_timeout_and_start_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "source.mp4"
    source.write_bytes(b"media")
    inspector = MediaInspector()
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(side_effect=subprocess.TimeoutExpired(cmd="worker", timeout=1)),
    )
    with pytest.raises(MediaInspectionError, match="time limit"):
        inspector.inspect(source)

    monkeypatch.setattr(subprocess, "run", Mock(side_effect=OSError("blocked")))
    with pytest.raises(MediaInspectionError, match="could not start"):
        inspector.inspect(source)


@pytest.mark.parametrize(
    ("stdout", "returncode", "message"),
    [
        ("not-json", 0, "invalid result"),
        ('{"error":"media inspection failed","detail":"bad codec"}', 1, "bad codec"),
        ('{"format_name":"mp4"}', 0, "incomplete"),
    ],
)
def test_media_inspector_rejects_untrusted_worker_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    returncode: int,
    message: str,
):
    source = tmp_path / "source.mp4"
    source.write_bytes(b"media")
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess([], returncode, stdout, "")),
    )

    with pytest.raises(MediaInspectionError, match=message):
        MediaInspector().inspect(source)


def test_media_inspector_rejects_excessive_worker_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = tmp_path / "source.mp4"
    source.write_bytes(b"media")
    monkeypatch.setattr(
        subprocess,
        "run",
        Mock(
            return_value=subprocess.CompletedProcess(
                [],
                0,
                "x" * (2 * 1024 * 1024 + 1),
                "",
            )
        ),
    )

    with pytest.raises(MediaInspectionError, match="excessive"):
        MediaInspector().inspect(source)


@pytest.mark.parametrize("timeout", [0, 601])
def test_media_inspector_rejects_unsafe_timeout(timeout: int):
    with pytest.raises(ValueError, match="timeout"):
        MediaInspector(timeout_seconds=timeout)
