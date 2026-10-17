#!/usr/bin/env python3
"""Verify and extract the licensed TA archives needed by the CI Splunk lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
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
    "Cisco Enterprise Networking App for Splunk": (
        "cisco-enterprise-networking-app-for-splunk_4020.tgz",
        "cisco-enterprise-networking-app-for-splunk_4020",
    ),
    "Cisco Enterprise Networking Add-on for Splunk": (
        "cisco-enterprise-networking-add-on-for-splunk_4050.tgz",
        "cisco-enterprise-networking-add-on-for-splunk_4050",
    ),
    "Cisco Enterprise Networking NetFlow Add-on for Splunk": (
        "cisco-enterprise-networking-netflow-add-on-for-splunk_400.tgz",
        "cisco-enterprise-networking-netflow-add-on-for-splunk_400",
    ),
    "Cisco Meraki Add-on for Splunk": (
        "cisco-meraki-add-on-for-splunk_350.tgz",
        "cisco-meraki-add-on-for-splunk_350",
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
        if len(members) > 20000:
            raise ValueError(f"too many archive members in {archive}")
        paths = set()
        total_size = 0
        for member in members:
            target = Path(member.name)
            if (
                target.is_absolute()
                or ".." in target.parts
                or not target.parts
                or "\\" in member.name
                or ":" in target.parts[0]
            ):
                raise ValueError(f"unsafe archive member in {archive}: {member.name}")
            if target in paths:
                raise ValueError(f"duplicate archive path in {archive}: {member.name}")
            paths.add(target)
            if member.issym() or member.islnk():
                raise ValueError(f"links are not allowed in {archive}: {member.name}")
            if not member.isdir() and not member.isfile():
                raise ValueError(
                    f"special files are not allowed in {archive}: {member.name}"
                )
            total_size += member.size
            if (
                member.size < 0
                or member.size > 256 * 1024 * 1024
                or total_size > 2 * 1024**3
            ):
                raise ValueError(f"archive exceeds extraction size limits: {archive}")
        # Extract as research data. Do not honor vendor ownership, special modes,
        # timestamps, or execute permissions. All paths are validated before any
        # file is written, and the caller supplies a fresh staging directory.
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError(f"archive file content is missing: {member.name}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o600)
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
