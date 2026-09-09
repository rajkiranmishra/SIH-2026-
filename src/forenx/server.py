from __future__ import annotations

import os

import uvicorn

from forenx.runtime import create_product_app


def main() -> None:
    port = _configured_port()
    application = create_product_app()
    code_path = getattr(getattr(application, "state", None), "setup_code_path", None)
    if code_path is not None:
        print(f"First-run setup: enter the installation code from {code_path}")
    uvicorn.run(
        application,
        host="127.0.0.1",
        port=port,
        access_log=False,
        server_header=False,
    )


def _configured_port() -> int:
    raw_port = os.environ.get("FORENX_PORT", "8765")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise SystemExit("FORENX_PORT must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise SystemExit("FORENX_PORT must be between 1024 and 65535")
    return port


if __name__ == "__main__":
    main()
