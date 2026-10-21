#!/usr/bin/env python3
"""Stage an exact local app archive for the owned disposable Splunk lab."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_release import _read_archive, _verify_checksum  # noqa: E402


def stage_package(archive: Path, destination: Path) -> str:
    """Verify the retained checksum and every member before writing anything."""
    app = destination / "splunk_adm"
    if app.exists() or app.is_symlink():
        raise ValueError("staging destination already contains splunk_adm")
    _verify_checksum(archive)
    package = _read_archive(archive)
    if "splunk_adm/default/app.conf" not in package.files:
        raise ValueError("app archive lacks default/app.conf")
    for name in sorted(package.directories):
        (destination / PurePosixPath(name)).mkdir(parents=True, exist_ok=True)
    for name, data in sorted(package.files.items()):
        target = destination / PurePosixPath(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(data)
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print("Staged candidate SHA-256:", stage_package(args.archive, args.destination))


if __name__ == "__main__":
    main()
