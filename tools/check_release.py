#!/usr/bin/env python3
"""Validate the archives and checksums produced by ``npm run package``."""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import posixpath
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path


MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
DEPLOYMENT_OWNED = "splunk_adm/lookups/adm_observer_scope.csv"
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})  ([^\s]+)$")
FORBIDDEN_COMPONENTS = {"local", "secrets", "secret", "credentials"}
FORBIDDEN_NAMES = {".env", ".env.local", "credentials", "secrets.json"}


@dataclass(frozen=True)
class Archive:
    path: Path
    files: dict[str, bytes]
    directories: frozenset[str]


def _member_name(name: str) -> str:
    if "\\" in name or name.startswith("/"):
        raise ValueError(f"unsafe archive member path: {name!r}")
    normalized = posixpath.normpath(name)
    if normalized == "." or normalized.startswith("../") or "/../" in normalized:
        raise ValueError(f"unsafe archive member path: {name!r}")
    if normalized != name.rstrip("/"):
        raise ValueError(f"non-canonical archive member path: {name!r}")
    if not normalized.startswith("splunk_adm/") and normalized != "splunk_adm":
        raise ValueError(f"archive member outside app root: {name!r}")
    return normalized


def _read_archive(path: Path) -> Archive:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"archive is too large: {path}")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    with tarfile.open(path, "r:gz") as tar:
        total = 0
        member_count = 0
        for member in tar:
            member_count += 1
            if member_count > MAX_MEMBERS:
                raise ValueError(f"archive has too many members: {path}")
            name = _member_name(member.name)
            if name in files or name in directories:
                raise ValueError(f"duplicate archive member: {name}")
            if (
                member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError(
                    f"links or special files are not allowed: {member.name!r}"
                )
            if member.isdir():
                directories.add(name)
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise ValueError(f"archive member is too large: {name}")
            total += member.size
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError(f"archive contents are too large: {path}")
            source = tar.extractfile(member)
            if source is None:
                raise ValueError(f"unable to read archive member: {name}")
            data = source.read(MAX_MEMBER_BYTES + 1)
            if len(data) != member.size:
                raise ValueError(f"archive member size mismatch: {name}")
            files[name] = data
    return Archive(path, files, frozenset(directories))


def _assert_safe_files(files: dict[str, bytes]) -> None:
    for name in files:
        relative = name.removeprefix("splunk_adm/")
        components = {component.casefold() for component in relative.split("/")}
        if components & FORBIDDEN_COMPONENTS:
            raise ValueError(f"deployment-local path in archive: {name}")
        basename = relative.rsplit("/", 1)[-1].casefold()
        if (
            basename in FORBIDDEN_NAMES
            or basename.startswith(".env")
            or basename.endswith((".pem", ".key", ".p12", ".pfx"))
        ):
            raise ValueError(f"secret-like path in archive: {name}")


def _verify_checksum(archive: Path) -> None:
    checksum_path = Path(f"{archive}.sha256")
    try:
        line = checksum_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"missing checksum file: {checksum_path}") from exc
    match = CHECKSUM_RE.fullmatch(line)
    if not match or match.group(2) != archive.name:
        raise ValueError(f"invalid checksum record: {checksum_path}")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"archive is too large: {archive}")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != match.group(1).lower():
        raise ValueError(f"checksum mismatch: {archive}")


def _required_files(files: dict[str, bytes], version: str) -> None:
    required = {
        "splunk_adm/appserver/static/adm.bundle.js",
        "splunk_adm/appserver/static/adm.css",
        "splunk_adm/default/app.conf",
        "splunk_adm/LICENSE",
        "splunk_adm/NOTICE",
        "splunk_adm/THIRD_PARTY_NOTICES.txt",
        "splunk_adm/docs/DATA_LAYER.md",
        "splunk_adm/default/collections.conf",
        "splunk_adm/default/limits.conf",
        "splunk_adm/default/macros.conf",
        "splunk_adm/default/savedsearches.conf",
        "splunk_adm/default/transforms.conf",
        "splunk_adm/default/data/ui/nav/default.xml",
        "splunk_adm/default/data/ui/views/dependency_map.xml",
        "splunk_adm/metadata/default.meta",
    }
    missing = sorted(required - files.keys())
    if missing:
        raise ValueError(f"archive missing required files: {', '.join(missing)}")
    config = configparser.RawConfigParser(strict=True)
    try:
        config.read_string(files["splunk_adm/default/app.conf"].decode("utf-8"))
    except (configparser.Error, UnicodeDecodeError) as exc:
        raise ValueError("invalid packaged app.conf") from exc
    if config.defaults():
        raise ValueError("packaged app.conf must not define [DEFAULT] values")
    for stanza in ("id", "launcher"):
        if config.get(stanza, "version", fallback=None) != version:
            raise ValueError(f"app.conf [{stanza}] version does not match {version}")
    if config.get("package", "id", fallback=None) != "splunk_adm":
        raise ValueError("app.conf [package] id does not match splunk_adm")
    if not config.has_section("install"):
        raise ValueError("packaged app.conf is missing [install]")
    build = config.get("install", "build", fallback=None)
    if build is None or not re.fullmatch(r"[1-9]\d*", build):
        raise ValueError("app.conf [install] build must be a positive integer")


def check_release(dist: Path, package_json: Path | None = None) -> None:
    package_json = package_json or Path("package.json")
    version = json.loads(package_json.read_text(encoding="utf-8"))["version"]
    install_path = dist / f"splunk_adm-{version}.tar.gz"
    upgrade_path = dist / f"splunk_adm-{version}-upgrade.tar.gz"
    for archive in (install_path, upgrade_path):
        if not archive.is_file():
            raise FileNotFoundError(archive)
        _verify_checksum(archive)
    install = _read_archive(install_path)
    upgrade = _read_archive(upgrade_path)
    for archive in (install, upgrade):
        _assert_safe_files(archive.files)
        _required_files(archive.files, version)
    if DEPLOYMENT_OWNED not in install.files or DEPLOYMENT_OWNED in upgrade.files:
        raise ValueError(
            "scope CSV must be present in install and omitted from upgrade"
        )
    if set(install.files) - {DEPLOYMENT_OWNED} != set(upgrade.files):
        raise ValueError(
            "install and upgrade archives differ beyond the deployment-owned scope CSV"
        )
    for name in upgrade.files:
        if install.files[name] != upgrade.files[name]:
            raise ValueError(f"install and upgrade bytes differ: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--package-json", type=Path, default=Path("package.json"))
    args = parser.parse_args()
    check_release(args.dist, args.package_json)
    print(f"Release archives verified in {args.dist}")


if __name__ == "__main__":
    main()
