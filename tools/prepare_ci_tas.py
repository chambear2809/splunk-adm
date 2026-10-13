#!/usr/bin/env python3
"""Verify and extract the licensed TA archives needed by the CI Splunk lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path

REQUIRED = {
    "Stream Wire Data": (
        "splunk-add-on-for-stream-wire-data_816.tgz",
        "splunk-add-on-for-stream-wire-data_816",
    ),
    "Cisco Security Cloud": (
        "cisco-security-cloud_372.tar.gz",
        "cisco-security-cloud_372",
    ),
    "Cisco DC Networking": (
        "cisco-dc-networking_122.tar.gz",
        "cisco-dc-networking_122",
    ),
}


def _archive_map(manifest: dict) -> dict[str, tuple[Path, str]]:
    found: dict[str, tuple[Path, str]] = {}
    for package in manifest["packages"]:
        title = package.get("title")
        archive = Path(package.get("archive_path", "")).name
        if title in REQUIRED and archive == REQUIRED[title][0]:
            if title in found:
                raise ValueError(f"duplicate manifest entry for {title}")
            found[title] = (Path(archive), package["sha256"])
    missing = set(REQUIRED) - set(found)
    if missing:
        raise ValueError(f"manifest has no required entries: {sorted(missing)}")
    return found


def _verify(path: Path, expected: str) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected:
        raise ValueError(f"checksum mismatch for {path}: {digest} != {expected}")


def _safe_extract(archive: Path, destination: Path) -> set[str]:
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for member in members:
            target = Path(member.name)
            if target.is_absolute() or ".." in target.parts:
                raise ValueError(f"unsafe archive member in {archive}: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"links are not allowed in {archive}: {member.name}")
            if not member.isdir() and not member.isfile():
                raise ValueError(
                    f"special files are not allowed in {archive}: {member.name}"
                )
        try:
            tar.extractall(destination, members=members, filter="data")
        except TypeError:  # Python 3.11 compatibility for local tooling.
            tar.extractall(destination, members=members)
        return {Path(member.name).parts[0] for member in members if member.name}


def prepare(manifest_path: Path, package_root: Path, output_root: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archives = _archive_map(manifest)
    if output_root.exists() or output_root.is_symlink():
        raise ValueError(f"refusing to replace existing output: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".ci-ta-", dir=output_root.parent
    ) as staging:
        staging_root = Path(staging)
        for title, (archive_name, expected) in archives.items():
            archive = package_root / archive_name
            if not archive.is_file():
                raise FileNotFoundError(archive)
            _verify(archive, expected)
            wrapper = REQUIRED[title][1]
            roots = _safe_extract(archive, staging_root)
            if len(roots) != 1:
                raise ValueError(
                    f"archive must contain one top-level directory: {archive}"
                )
            wrapper_root = staging_root / wrapper
            wrapper_root.mkdir()
            root_name = roots.pop()
            (staging_root / root_name).rename(wrapper_root / root_name)
            print(f"verified and extracted {title}")
        os.replace(staging_root, output_root)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.manifest, args.package_root, args.output_root)


if __name__ == "__main__":
    main()
