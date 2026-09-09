"""Local-operator recovery; deliberately not exposed through the web application."""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from forenx.auth import AuthStore, AuthStoreError
from forenx.runtime import default_data_directory


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover an existing local ForenX administrator")
    parser.add_argument("username", help="Existing administrator username")
    parser.add_argument(
        "--data-dir", type=Path, default=None, help="Existing laboratory data folder",
    )
    args = parser.parse_args()
    directory = args.data_dir or default_data_directory()
    database = directory / "forenx.sqlite3"
    if directory.is_symlink() or database.is_symlink() or not database.is_file():
        parser.error("Use the existing laboratory data folder, without symbolic links")
    try:
        password = getpass.getpass("New administrator password (at least 12 characters): ")
        confirmation = getpass.getpass("Confirm new password: ")
        if password != confirmation:
            parser.error("Passwords do not match; no account was changed")
        store = AuthStore(database)
        try:
            store.recover_administrator(args.username, password)
        finally:
            store.close()
    except (AuthStoreError, ValueError) as exc:
        parser.error(str(exc))
    print("Administrator recovered. All previous sessions were revoked and recovery was audited.")


if __name__ == "__main__":
    main()
