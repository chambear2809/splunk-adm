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
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})  ([^\s]+)$")
FORBIDDEN_COMPONENTS = {"local", "secrets", "secret", "credentials"}
# Custom Mako templates are deprecated as of Splunk Enterprise 10.4.
MAKO_DIRS = ("appserver/templates/", "appserver/modules/")
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


def _check_scope_transform(data: bytes, source: str, *, require_kv=False) -> None:
    config = configparser.RawConfigParser()
    try:
        config.read_string(data.decode("utf-8"))
    except (configparser.Error, UnicodeDecodeError):
        raise ValueError(f"invalid transforms.conf: {source}") from None
    if not config.has_section("adm_observer_scope"):
        if require_kv:
            raise ValueError(f"missing scope KV lookup: {source}")
        return
    scope = config["adm_observer_scope"]
    if scope.get("filename", "").strip():
        raise ValueError(
            f"legacy CSV scope lookup in {source}; migrate and remove the stale override"
        )
    for key, expected in (
        ("external_type", "kvstore"),
        ("collection", "adm_observer_scope"),
    ):
        if (require_kv or key in scope) and scope.get(key) != expected:
            raise ValueError(
                f"scope lookup must target adm_observer_scope KV: {source}"
            )


def _assert_safe_files(files: dict[str, bytes]) -> None:
    for name in files:
        if name.casefold() == "splunk_adm/local/transforms.conf":
            _check_scope_transform(files[name], name)
        if name.casefold() == "splunk_adm/lookups/adm_observer_scope.csv":
            raise ValueError(f"deployment-owned scope CSV must not ship: {name}")
        relative = name.removeprefix("splunk_adm/")
        if relative.casefold().startswith(MAKO_DIRS):
            raise ValueError(f"custom Mako template path in archive: {name}")
        components = {component.casefold() for component in relative.split("/")}
        if components & FORBIDDEN_COMPONENTS:
            raise ValueError(f"deployment-local path in archive: {name}")
        basename = relative.rsplit("/", 1)[-1].casefold()
        if basename == "limits.conf":
            raise ValueError(f"packaged limits.conf is disallowed for Cloud: {name}")
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
        "splunk_adm/appserver/static/adm.css",
        "splunk_adm/appserver/static/pages/atlas.js",
        *{
            f"splunk_adm/appserver/static/demo/{name}.json"
            for name in (
                "demo-scopes",
                "demo-rows",
                "demo-rows-aci",
                "demo-topology",
                "demo-topology-aci",
            )
        },
        *{
            f"splunk_adm/default/data/ui/views/{page}.xml"
            for page in ("applications", "map", "data_health", "setup", "help")
        },
        "splunk_adm/default/app.conf",
        "splunk_adm/LICENSE",
        "splunk_adm/NOTICE",
        "splunk_adm/THIRD_PARTY_NOTICES.txt",
        "splunk_adm/docs/DATA_LAYER.md",
        "splunk_adm/docs/UPGRADES.md",
        "splunk_adm/default/collections.conf",
        "splunk_adm/default/adm_recovery.conf",
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
    _check_scope_transform(
        files["splunk_adm/default/transforms.conf"],
        "packaged default/transforms.conf",
        require_kv=True,
    )
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
    if config.get("triggers", "reload.adm_recovery", fallback=None) != "simple":
        raise ValueError("app.conf [triggers] reload.adm_recovery must be simple")
    if not config.has_section("install"):
        raise ValueError("packaged app.conf is missing [install]")
    build = config.get("install", "build", fallback=None)
    if build is None or not re.fullmatch(r"[1-9]\d*", build):
        raise ValueError("app.conf [install] build must be a positive integer")


def check_release(
    dist: Path, package_json: Path | None = None, *, installed_app: Path | None = None
) -> None:
    if installed_app is not None:
        if not installed_app.is_dir():
            raise ValueError(f"installed app directory does not exist: {installed_app}")
        local_transforms = installed_app / "local/transforms.conf"
        if local_transforms.is_file():
            _check_scope_transform(local_transforms.read_bytes(), str(local_transforms))
    package_json = package_json or Path("package.json")
    version = json.loads(package_json.read_text(encoding="utf-8"))["version"]
    archive_path = dist / f"splunk_adm-{version}.tar.gz"
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)
    _verify_checksum(archive_path)
    archive = _read_archive(archive_path)
    _assert_safe_files(archive.files)
    _required_files(archive.files, version)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--package-json", type=Path, default=Path("package.json"))
    parser.add_argument(
        "--installed-app",
        type=Path,
        help="also reject stale local scope lookup overrides in an installed app directory",
    )
    args = parser.parse_args()
    check_release(args.dist, args.package_json, installed_app=args.installed_app)
    print(f"Release archive verified in {args.dist}")


if __name__ == "__main__":
    main()
