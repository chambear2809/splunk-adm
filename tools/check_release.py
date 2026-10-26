#!/usr/bin/env python3
"""Validate the archives and checksums produced by ``npm run package``."""

from __future__ import annotations

import argparse
import ast
import configparser
import gzip
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
# Optional AppDynamics/detector inspection extends the existing single-IIFE page.
# Same-runtime baseline and measured growth are recorded in the evidence contract.
MAX_ATLAS_GZIP_BYTES = 670 * 1024
ATLAS_BUNDLE_PATH = "splunk_adm/appserver/static/pages/atlas.js"
ALERT_ACTIONS_PATH = "splunk_adm/default/alert_actions.conf"
RECOVERY_DOC_PATH = "splunk_adm/docs/RECOVERY.md"
RETENTION_DOC_PATH = "splunk_adm/docs/RETENTION_MAINTENANCE.md"
SETTINGS_ENTRYPOINT = "splunk_adm/bin/adm_settings.py"
SETTINGS_REGISTRY_PATH = "splunk_adm/bin/adm_settings_registry.json"
SETTINGS_RUNTIME_FILES = frozenset(
    {
        SETTINGS_ENTRYPOINT,
        "splunk_adm/bin/adm_settings_lib/__init__.py",
        "splunk_adm/bin/adm_settings_lib/rest.py",
    }
)
SETTINGS_CONFIG_FILES = frozenset(
    {
        "splunk_adm/default/restmap.conf",
        "splunk_adm/default/web.conf",
        "splunk_adm/default/adm_settings.conf",
        "splunk_adm/README/adm_settings.conf.spec",
    }
)
BUNDLED_RUNTIME_FILES = frozenset(
    {
        *SETTINGS_RUNTIME_FILES,
        "splunk_adm/bin/adm_recovery.py",
        "splunk_adm/bin/adm_recovery_lib/__init__.py",
        "splunk_adm/bin/adm_recovery_lib/core.py",
        "splunk_adm/bin/adm_recovery_lib/planner.py",
        "splunk_adm/bin/adm_recovery_lib/rest.py",
        "splunk_adm/bin/lib/SPLUNK_SDK_LICENSE.txt",
        "splunk_adm/bin/lib/SPLUNK_SDK_PROVENANCE.md",
        "splunk_adm/bin/lib/splunklib/__init__.py",
        "splunk_adm/bin/lib/splunklib/binding.py",
        "splunk_adm/bin/lib/splunklib/client.py",
        "splunk_adm/bin/lib/splunklib/data.py",
        "splunk_adm/bin/lib/splunklib/results.py",
        "splunk_adm/bin/lib/splunklib/six.py",
        "splunk_adm/bin/lib/splunklib/utils.py",
        *{
            f"splunk_adm/bin/lib/splunklib/{pkg}/{name}.py"
            for pkg, names in {
                "modularinput": (
                    "__init__",
                    "argument",
                    "event",
                    "event_writer",
                    "input_definition",
                    "scheme",
                    "script",
                    "utils",
                    "validation_definition",
                ),
                "searchcommands": (
                    "__init__",
                    "decorators",
                    "environment",
                    "eventing_command",
                    "external_search_command",
                    "generating_command",
                    "internals",
                    "reporting_command",
                    "search_command",
                    "streaming_command",
                    "validators",
                ),
            }.items()
            for name in names
        },
    }
)
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})  ([^\s]+)$")
FORBIDDEN_COMPONENTS = {"local", "secrets", "secret", "credentials"}
# Custom Mako templates are deprecated as of Splunk Enterprise 10.4.
DEV_RECORD_DIRS = ("research/", "docs/benchmarks/")
MAKO_DIRS = ("appserver/templates/", "appserver/modules/")
FORBIDDEN_NAMES = {".env", ".env.local", "credentials", "secrets.json"}
DEVELOPMENT_COMPONENTS = {".git", "node_modules", "__pycache__"}
DEVELOPMENT_NAMES = {".ds_store"}
DEVELOPMENT_SUFFIXES = (".pyc", ".pyo")


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
        if name.casefold() in {
            "splunk_adm/lookups/adm_observer_scope.csv",
            "splunk_adm/lookups/adm_network_source_scope.csv",
        }:
            raise ValueError(f"deployment-owned scope CSV must not ship: {name}")
        relative = name.removeprefix("splunk_adm/")
        if relative.casefold().startswith(DEV_RECORD_DIRS):
            raise ValueError(f"development record must not ship: {name}")
        if relative.casefold().startswith(MAKO_DIRS):
            raise ValueError(f"custom Mako template path in archive: {name}")
        components = {component.casefold() for component in relative.split("/")}
        basename = relative.rsplit("/", 1)[-1].casefold()
        if components & FORBIDDEN_COMPONENTS or basename == "local.meta":
            raise ValueError(f"deployment-local path in archive: {name}")
        if (
            components & DEVELOPMENT_COMPONENTS
            or basename in DEVELOPMENT_NAMES
            or basename.startswith("._")
            or basename.endswith(DEVELOPMENT_SUFFIXES)
        ):
            raise ValueError(f"development artifact in archive: {name}")
        if basename == "limits.conf":
            raise ValueError(f"packaged limits.conf is disallowed for Cloud: {name}")
        if (
            basename in FORBIDDEN_NAMES
            or basename.startswith(".env")
            or basename.endswith((".pem", ".key", ".p12", ".pfx"))
        ):
            raise ValueError(f"secret-like path in archive: {name}")


def _assert_safe_directories(directories: frozenset[str]) -> None:
    for name in directories:
        relative = name.removeprefix("splunk_adm").lstrip("/")
        components = {component.casefold() for component in relative.split("/")}
        if components & FORBIDDEN_COMPONENTS:
            raise ValueError(f"deployment-local path in archive: {name}")
        if components & DEVELOPMENT_COMPONENTS:
            raise ValueError(f"development artifact in archive: {name}")


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


def _packaged_config(
    files: dict[str, bytes], relative: str
) -> configparser.RawConfigParser:
    config = configparser.RawConfigParser(strict=True)
    try:
        text = files[f"splunk_adm/{relative}"].decode("utf-8")
        if relative.endswith(".meta"):
            text = text.replace("[]", "[app]", 1)
        config.read_string(text)
    except (configparser.Error, UnicodeDecodeError) as exc:
        raise ValueError(
            f"invalid packaged settings configuration: {relative}"
        ) from exc
    if config.defaults():
        raise ValueError(
            f"packaged settings configuration must not inherit DEFAULT values: {relative}"
        )
    return config


def _check_settings_contract(files: dict[str, bytes], registry: bytes) -> None:
    for name in SETTINGS_RUNTIME_FILES:
        try:
            tree = ast.parse(files[name], filename=name)
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(
                f"invalid packaged settings Python runtime: {name}"
            ) from exc
        if name == SETTINGS_ENTRYPOINT and not any(
            isinstance(node, ast.ClassDef) and node.name == "SettingsHandler"
            for node in tree.body
        ):
            raise ValueError("settings entrypoint must define shipped SettingsHandler")
    rest = _packaged_config(files, "default/restmap.conf")
    stanza = "script:adm_deployment_settings"
    expected = {
        "match": "/adm/deployment-settings",
        "script": "adm_settings.py",
        "scripttype": "persist",
        "handler": "adm_settings.SettingsHandler",
        "python.required": "3.13",
        "python.version": "python3",
        "capability.post": "admin_all_objects",
        "output_modes": "json",
    }
    if not rest.has_section(stanza) or any(
        rest.get(stanza, key, fallback=None) != value for key, value in expected.items()
    ):
        raise ValueError(
            "settings registration must reference the shipped authenticated SettingsHandler"
        )
    for key, value in (
        ("requireAuthentication", True),
        ("passPayload", True),
        ("passSession", True),
        ("passSystemAuth", False),
    ):
        try:
            valid = (
                rest.has_option(stanza, key) and rest.getboolean(stanza, key) is value
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError(
                f"settings registration requires {key} = {str(value).lower()}"
            )
    if rest.get(stanza, "capability", fallback="") or rest.get(
        stanza, "capability.get", fallback=""
    ):
        raise ValueError(
            "settings registration must preserve authenticated reader access"
        )
    if rest.get(stanza, "restReplay", fallback="false").casefold() not in (
        "false",
        "0",
    ):
        raise ValueError("settings registration must not enable REST replay")
    if [
        name
        for name in rest.sections()
        if rest.get(name, "match", fallback="") == expected["match"]
    ] != [stanza]:
        raise ValueError("settings endpoint must have one unambiguous registration")
    web = _packaged_config(files, "default/web.conf")
    exposure = "expose:adm_deployment_settings"
    if (
        not web.has_section(exposure)
        or web.get(exposure, "pattern", fallback=None) != "adm/deployment-settings"
        or set(web.get(exposure, "methods", fallback="").split(",")) != {"GET", "POST"}
    ):
        raise ValueError(
            "settings browser exposure must match the supported GET/POST endpoint"
        )
    # Splunk Cloud permits only these two exposure fields. Omitting the
    # skipCSRFProtection override retains the native web.conf.spec default 0.
    if set(web[exposure]) != {"pattern", "methods"}:
        raise ValueError(
            "settings browser exposure must use only pattern/methods and inherit CSRF protection"
        )
    if [
        name
        for name in web.sections()
        if web.get(name, "pattern", fallback="") == "adm/deployment-settings"
    ] != [exposure]:
        raise ValueError("settings browser exposure must be unambiguous")
    config = _packaged_config(files, "default/adm_settings.conf")
    if (
        config.get("persistence", "write_mode", fallback=None) != "disabled"
        or config.get("persistence", "platform", fallback=None) != "unqualified"
    ):
        raise ValueError(
            "packaged settings defaults must remain disabled and unqualified"
        )
    collections = _packaged_config(files, "default/collections.conf")
    if any(
        collections.get("adm_deployment_settings", field, fallback=None) != "string"
        for field in ("field.revision", "field.settings_json")
    ):
        raise ValueError(
            "packaged settings collection must preserve revision/settings schema"
        )
    metadata = _packaged_config(files, "metadata/default.meta")
    acl = metadata.get("collections/adm_deployment_settings", "access", fallback="")
    if re.sub(r"\s+", "", acl) != "read:[*],write:[admin,sc_admin]":
        raise ValueError(
            "packaged settings ACL must preserve readers and admin/sc_admin writers"
        )
    spec = files["splunk_adm/README/adm_settings.conf.spec"]
    if any(
        token not in spec
        for token in (b"[persistence]", b"write_mode =", b"platform =")
    ):
        raise ValueError(
            "packaged settings spec must document the persistence controls"
        )
    try:
        value = json.loads(files[SETTINGS_REGISTRY_PATH])
        source = json.loads(registry)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(
            "invalid packaged or canonical deployment-health registry"
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("schemaVersion") != 1
        or not isinstance(value.get("sources"), list)
        or not value["sources"]
        or value != source
        or files[SETTINGS_REGISTRY_PATH] != registry
    ):
        raise ValueError(
            "packaged settings registry must match the canonical deployment-health registry"
        )


def _required_files(files: dict[str, bytes], version: str, registry: bytes) -> None:
    required = {
        "splunk_adm/appserver/static/adm.css",
        "splunk_adm/appserver/static/pages/atlas.js",
        *{
            f"splunk_adm/appserver/static/demo/{name}.json"
            for name in (
                "demo-scopes",
                "demo-catalog",
                "demo-find",
                "demo-rows",
                "demo-rows-aci",
                "demo-rows-aci-prev",
                "demo-topology",
                "demo-topology-aci",
                "demo-networking-aci",
                "demo-networking-nxos",
                "demo-networking-topology",
                "demo-networking-scopes",
                "demo-networking-catalog",
                "demo-networking-find",
            )
        },
        *{
            f"splunk_adm/default/data/ui/views/{page}.xml"
            for page in (
                "applications",
                "map",
                "endpoints",
                "data_health",
                "setup",
                "help",
            )
        },
        "splunk_adm/default/app.conf",
        "splunk_adm/LICENSE",
        "splunk_adm/NOTICE",
        "splunk_adm/THIRD_PARTY_NOTICES.txt",
        "splunk_adm/docs/DATA_LAYER.md",
        "splunk_adm/docs/DEPLOYMENT_HEALTH.md",
        "splunk_adm/docs/LATE_CATALYST_RECEIPTS.md",
        "splunk_adm/docs/UPGRADES.md",
        "splunk_adm/docs/CISCO_CONTRACT_MIGRATION.md",
        "splunk_adm/docs/CISCO_NETWORKING_QUALIFICATION.md",
        "splunk_adm/docs/operators/cisco-enterprise-networking.md",
        "splunk_adm/docs/DNS_EVIDENCE_QUALIFICATION.md",
        "splunk_adm/docs/DNS_EVIDENCE_SCENARIOS.md",
        "splunk_adm/docs/DNS_EVIDENCE_DESIGN.md",
        "splunk_adm/docs/DNS_INGESTION_RESEARCH.md",
        "splunk_adm/docs/operators/dns-evidence.md",
        RECOVERY_DOC_PATH,
        RETENTION_DOC_PATH,
        "splunk_adm/default/collections.conf",
        "splunk_adm/default/adm_recovery.conf",
        ALERT_ACTIONS_PATH,
        "splunk_adm/default/macros.conf",
        "splunk_adm/default/savedsearches.conf",
        "splunk_adm/default/transforms.conf",
        "splunk_adm/default/data/ui/nav/default.xml",
        "splunk_adm/default/data/ui/views/dependency_map.xml",
        "splunk_adm/metadata/default.meta",
        *BUNDLED_RUNTIME_FILES,
        *SETTINGS_CONFIG_FILES,
        SETTINGS_REGISTRY_PATH,
    }
    missing = sorted(required - files.keys())
    if missing:
        raise ValueError(f"archive missing required files: {', '.join(missing)}")
    _check_settings_contract(files, registry)
    _check_scope_transform(
        files["splunk_adm/default/transforms.conf"],
        "packaged default/transforms.conf",
        require_kv=True,
    )
    # Python's default compression level varies across supported host runtimes.
    # Keep the established CI level explicit so headroom means the same thing
    # in the build report and on operator machines.
    atlas_gzip_bytes = len(
        gzip.compress(files[ATLAS_BUNDLE_PATH], compresslevel=9, mtime=0)
    )
    if atlas_gzip_bytes > MAX_ATLAS_GZIP_BYTES:
        raise ValueError(
            f"atlas.js gzip bundle is {atlas_gzip_bytes} bytes; "
            f"maximum is {MAX_ATLAS_GZIP_BYTES} bytes"
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
    if config.get("triggers", "reload.adm_settings", fallback=None) != "simple":
        raise ValueError("app.conf [triggers] reload.adm_settings must be simple")
    actions = configparser.RawConfigParser(strict=True)
    try:
        actions.read_string(files[ALERT_ACTIONS_PATH].decode("utf-8"))
    except (configparser.Error, UnicodeDecodeError) as exc:
        raise ValueError("invalid packaged alert_actions.conf") from exc
    if not actions.has_section("adm_recovery"):
        raise ValueError("packaged alert_actions.conf is missing [adm_recovery]")
    command = actions.get("adm_recovery", "alert.execute.cmd", fallback="").strip()
    entrypoint = "splunk_adm/bin/adm_recovery.py"
    if command != "adm_recovery.py" or entrypoint not in files:
        raise ValueError(
            "adm_recovery alert registration must reference shipped adm_recovery.py"
        )
    if not files[entrypoint].startswith(b"#!"):
        raise ValueError("shipped adm_recovery.py is not an executable script")
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
    _assert_safe_directories(archive.directories)
    registry_path = package_json.parent / "config/deployment-health.json"
    try:
        registry = registry_path.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"unable to read canonical deployment-health registry: {registry_path}"
        ) from exc
    _required_files(archive.files, version, registry)


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
