from pathlib import Path

import av
import pytest


@pytest.fixture
def sample_mp4(tmp_path: Path) -> bytes:
    path = tmp_path / "controlled-cctv.mp4"
    container = av.open(str(path), mode="w")
    stream = container.add_stream("mpeg4", rate=10)
    stream.width = 160
    stream.height = 120
    stream.pix_fmt = "yuv420p"
    for index in range(10):
        frame = av.VideoFrame(160, 120, "yuv420p")
        frame.pts = index
        for plane in frame.planes:
            plane.update(bytes(plane.buffer_size))
        for packet in stream.encode(frame):
            container.mux(packet)
    for packet in stream.encode():
        container.mux(packet)
    container.close()
    return path.read_bytes()
