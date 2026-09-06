from unittest.mock import Mock

import pytest

from forenx import server


def test_server_uses_loopback_and_configured_port(monkeypatch: pytest.MonkeyPatch):
    application = object()
    run = Mock()
    monkeypatch.setenv("FORENX_PORT", "9123")
    monkeypatch.setattr(server, "create_product_app", lambda: application)
    monkeypatch.setattr(server.uvicorn, "run", run)

    server.main()

    run.assert_called_once_with(
        application,
        host="127.0.0.1",
        port=9123,
        access_log=False,
        server_header=False,
    )


@pytest.mark.parametrize("value", ["not-a-port", "80", "70000"])
def test_server_rejects_invalid_port(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
):
    monkeypatch.setenv("FORENX_PORT", value)

    with pytest.raises(SystemExit, match="FORENX_PORT"):
        server._configured_port()
