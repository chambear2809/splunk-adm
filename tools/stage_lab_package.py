#!/usr/bin/env python3
"""Stage an exact local app archive for the owned disposable Splunk lab."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import tarfile


def stage_package(archive: Path, destination: Path) -> str:
    """Validate every member before writing, refusing links and path escapes."""
    app = destination / "splunk_adm"
    if app.exists() or app.is_symlink():
        raise ValueError("staging destination already contains splunk_adm")
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        seen: set[str] = set()
        total = 0
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] != "splunk_adm"
                or not (member.isfile() or member.isdir())
                or str(path) in seen
            ):
                raise ValueError(
                    f"unsafe or duplicate app archive member: {member.name}"
                )
            seen.add(str(path))
            total += member.size
        if total > 128 * 1024 * 1024 or "splunk_adm/default/app.conf" not in seen:
            raise ValueError("app archive is oversized or lacks default/app.conf")
        for member in members:
            target = destination / PurePosixPath(member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                content = package.extractfile(member)
                if content is None:
                    raise ValueError("archive file is unreadable")
                with content, target.open("xb") as output:
                    shutil.copyfileobj(content, output)
                target.chmod(member.mode & 0o777)
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print("Staged candidate SHA-256:", stage_package(args.archive, args.destination))


if __name__ == "__main__":
    main()
