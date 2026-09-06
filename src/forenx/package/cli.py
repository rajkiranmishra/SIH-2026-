from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from forenx.package.manifest import verify_evidence_package


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="forenx-verify",
        description="Verify a signed ForenX evidence package without opening the main application.",
    )
    parser.add_argument("package", type=Path, help="Evidence package directory")
    parser.add_argument(
        "--trusted-key-fingerprint",
        help="Expected SHA-256 fingerprint of the laboratory Ed25519 public key",
    )
    arguments = parser.parse_args(argv)
    result = verify_evidence_package(
        arguments.package,
        trusted_public_key_fingerprint=arguments.trusted_key_fingerprint,
    )
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.valid else 2
