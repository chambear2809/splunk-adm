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
MAX_ATLAS_GZIP_BYTES = 680 * 1024
ATLAS_BUNDLE_PATH = "splunk_adm/appserver/static/pages/atlas.js"
THOUSANDEYES_BUNDLE_PATH = "splunk_adm/appserver/static/pages/thousandeyes.js"
THOUSANDEYES_MANIFEST_PATH = "splunk_adm/appserver/static/thousandeyes-manifest.json"
THOUSANDEYES_CSS_PATH = "splunk_adm/appserver/static/thousandeyes.css"
# This optional asset loads only when the user opens a ThousandEyes investigation.
# The existing initial Atlas bundle ceiling remains unchanged.
MAX_THOUSANDEYES_GZIP_BYTES = 48 * 1024
MAX_THOUSANDEYES_CSS_BYTES = 16 * 1024
JOURNEYS_BUNDLE_PATH = "splunk_adm/appserver/static/pages/journeys.js"
JOURNEYS_MANIFEST_PATH = "splunk_adm/appserver/static/journeys-manifest.json"
JOURNEYS_CSS_PATH = "splunk_adm/appserver/static/journeys.css"
JOURNEYS_DOC_PATH = "splunk_adm/docs/CONNECTED_JOURNEYS.md"
MAX_JOURNEYS_GZIP_BYTES = 32 * 1024
MAX_JOURNEYS_CSS_BYTES = 16 * 1024
IMPACT_BUNDLE_PATH = "splunk_adm/appserver/static/pages/impact.js"
IMPACT_MANIFEST_PATH = "splunk_adm/appserver/static/impact-manifest.json"
IMPACT_CSS_PATH = "splunk_adm/appserver/static/impact.css"
MAX_IMPACT_GZIP_BYTES = 64 * 1024
MAX_IMPACT_CSS_BYTES = 16 * 1024
MULTICAST_BUNDLE_PATH = "splunk_adm/appserver/static/pages/multicast.js"
MULTICAST_MANIFEST_PATH = "splunk_adm/appserver/static/multicast-manifest.json"
MULTICAST_CSS_PATH = "splunk_adm/appserver/static/multicast.css"
MAX_MULTICAST_GZIP_BYTES = 64 * 1024
MAX_MULTICAST_CSS_BYTES = 16 * 1024
HISTORY_BUNDLE_PATH = "splunk_adm/appserver/static/pages/history.js"
HISTORY_MANIFEST_PATH = "splunk_adm/appserver/static/history-manifest.json"
HISTORY_CSS_PATH = "splunk_adm/appserver/static/history.css"
MAX_HISTORY_GZIP_BYTES = 48 * 1024
MAX_HISTORY_CSS_BYTES = 16 * 1024
MIGRATION_BUNDLE_PATH = "splunk_adm/appserver/static/pages/migration.js"
MIGRATION_MANIFEST_PATH = "splunk_adm/appserver/static/migration-manifest.json"
MIGRATION_CSS_PATH = "splunk_adm/appserver/static/migration.css"
MAX_MIGRATION_GZIP_BYTES = 48 * 1024
MAX_MIGRATION_CSS_BYTES = 16 * 1024
# Segmentation policy workbench: optional asset, loaded only when opened from the map.
SEGMENTATION_BUNDLE_PATH = "splunk_adm/appserver/static/pages/segmentation.js"
SEGMENTATION_MANIFEST_PATH = "splunk_adm/appserver/static/segmentation-manifest.json"
SEGMENTATION_CSS_PATH = "splunk_adm/appserver/static/segmentation.css"
MAX_SEGMENTATION_GZIP_BYTES = 40 * 1024
MAX_SEGMENTATION_CSS_BYTES = 16 * 1024
# End segmentation policy workbench.
# Map investigation workspace: optional asset, loaded only when opened from the map.
INCIDENT_BUNDLE_PATH = "splunk_adm/appserver/static/pages/incident.js"
INCIDENT_MANIFEST_PATH = "splunk_adm/appserver/static/incident-manifest.json"
INCIDENT_CSS_PATH = "splunk_adm/appserver/static/incident.css"
MAX_INCIDENT_GZIP_BYTES = 32 * 1024
MAX_INCIDENT_CSS_BYTES = 16 * 1024
ECOSYSTEM_BUNDLE_PATH = "splunk_adm/appserver/static/pages/ecosystem.js"
ECOSYSTEM_MANIFEST_PATH = "splunk_adm/appserver/static/ecosystem-manifest.json"
ECOSYSTEM_CSS_PATH = "splunk_adm/appserver/static/ecosystem.css"
MAX_ECOSYSTEM_GZIP_BYTES = 48 * 1024
MAX_ECOSYSTEM_CSS_BYTES = 16 * 1024
ALERT_ACTIONS_PATH = "splunk_adm/default/alert_actions.conf"
RECOVERY_DOC_PATH = "splunk_adm/docs/RECOVERY.md"
RETENTION_DOC_PATH = "splunk_adm/docs/RETENTION_MAINTENANCE.md"
SETTINGS_ENTRYPOINT = "splunk_adm/bin/adm_settings.py"
SETTINGS_REGISTRY_PATH = "splunk_adm/bin/adm_settings_registry.json"
CASE_RUNTIME_FILES = frozenset(
    {
        "splunk_adm/bin/adm_cases.py",
        *{
            f"splunk_adm/bin/adm_cases_lib/{name}"
            for name in (
                "__init__.py",
                "api.py",
                "store.py",
                "splunk_host.py",
                "source.py",
                "native.py",
                "transport.py",
                "transport_worker.py",
                "request_supervisor.py",
                "request_worker.py",
                "job_ledger.py",
                "README.md",
            )
        },
    }
)
CASE_CONFIG_FILES = frozenset(
    {
        "splunk_adm/default/adm_investigations.conf",
        "splunk_adm/default/authorize.conf",
        "splunk_adm/README/adm_investigations.conf.spec",
    }
)
# Whitespace-free metadata ACLs. Derived lookups aggregate every configured
# source index, so no packaged object may be readable by everyone.
VIEWER_ACL = "read:[adm_investigate,adm_viewer,admin,sc_admin],write:[admin,sc_admin]"
ADMIN_ACL = "read:[admin,sc_admin],write:[admin,sc_admin]"
ADMIN_ONLY_METADATA = frozenset(
    {
        "savedsearches",
        "alert_actions/adm_recovery",
        "adm_recovery",
        "alert_actions/adm_dependency_watch",
        "adm_dependency_watch",
        "collections/adm_recovery_state",
        "collections/adm_recovery_audit",
        "transforms/adm_recovery_state",
        "transforms/adm_recovery_audit",
        "views/setup",
        "transforms/adm_ip_identity_all",
    }
)
VIEWER_ROLE = {
    "edit_own_objects": "disabled",
    "list_all_objects": "disabled",
    "run_collect": "disabled",
    "run_mcollect": "disabled",
    "schedule_rtsearch": "disabled",
}
CASE_EXPOSURES = {
    "expose:adm_case_capabilities": ("adm/investigations/capabilities", "GET"),
    "expose:adm_cases": ("adm/investigations/cases", "GET,POST"),
    "expose:adm_case_resources": ("adm/investigations/cases/*", "GET,DELETE"),
    "expose:adm_case_entries": ("adm/investigations/cases/*/entries", "POST"),
    "expose:adm_case_captures": ("adm/investigations/cases/*/captures", "POST"),
    "expose:adm_case_attachments": ("adm/investigations/cases/*/attachments", "POST"),
    "expose:adm_case_sharing": ("adm/investigations/cases/*/share", "POST"),
    "expose:adm_case_export": ("adm/investigations/cases/*/export", "GET"),
    "expose:adm_case_audit": ("adm/investigations/cases/*/audit", "GET"),
}
BASELINE_RUNTIME_FILES = frozenset(
    {
        "splunk_adm/bin/adm_baselines.py",
        "splunk_adm/bin/adm_dependency_watch.py",
        "splunk_adm/bin/adm_baseline_provision.py",
        *(
            f"splunk_adm/bin/adm_baselines_lib/{name}.py"
            for name in (
                "__init__",
                "api",
                "store",
                "splunk_host",
                "executor",
                "run_store",
                "watch_management",
                "retained_artifacts",
                "source_provider",
                "qualified_snapshot",
            )
        ),
    }
)
BASELINE_CONFIG_FILES = frozenset(
    {
        "splunk_adm/default/adm_baselines.conf",
        "splunk_adm/README/adm_baselines.conf.spec",
        "splunk_adm/default/adm_dependency_watch.conf",
        "splunk_adm/README/adm_dependency_watch.conf.spec",
    }
)
BASELINE_EXPOSURES = {
    "expose:adm_baseline_capabilities": (
        "adm/dependency-monitoring/capabilities",
        "GET",
    ),
    "expose:adm_baseline_capture": ("adm/dependency-monitoring/capture", "GET"),
    "expose:adm_baselines": ("adm/dependency-monitoring/baselines", "GET,POST"),
    "expose:adm_baseline_resource": (
        "adm/dependency-monitoring/baselines/*",
        "GET,DELETE",
    ),
    "expose:adm_baseline_versions": (
        "adm/dependency-monitoring/baselines/*/versions",
        "GET,POST",
    ),
    "expose:adm_baseline_version": (
        "adm/dependency-monitoring/baselines/*/versions/*",
        "GET",
    ),
    "expose:adm_baseline_watches": (
        "adm/dependency-monitoring/baselines/*/watches",
        "GET,POST",
    ),
    "expose:adm_baseline_occurrences": (
        "adm/dependency-monitoring/baselines/*/watches/*/occurrences",
        "GET,POST",
    ),
    "expose:adm_baseline_evaluate": (
        "adm/dependency-monitoring/baselines/*/watches/*/evaluate",
        "GET,POST",
    ),
    "expose:adm_baseline_export": (
        "adm/dependency-monitoring/baselines/*/export",
        "GET",
    ),
    "expose:adm_baseline_share": (
        "adm/dependency-monitoring/baselines/*/share",
        "POST",
    ),
    "expose:adm_watch_management_disable": (
        "adm/dependency-monitoring/watch-management/disable",
        "POST",
    ),
}
COLLABORATION_RUNTIME_FILES = frozenset(
    {
        "splunk_adm/bin/adm_collaboration.py",
        "splunk_adm/bin/adm_observer_mapping.py",
        "splunk_adm/bin/adm_kv_lib/__init__.py",
        "splunk_adm/bin/adm_kv_lib/ledger.py",
        "splunk_adm/bin/adm_kv_lib/store.py",
        "splunk_adm/bin/adm_collaboration_lib/__init__.py",
        "splunk_adm/bin/adm_collaboration_lib/payload.py",
        "splunk_adm/bin/adm_collaboration_lib/rest.py",
        "splunk_adm/bin/adm_collaboration_lib/assertions.py",
        "splunk_adm/bin/adm_observer_lib/__init__.py",
        "splunk_adm/bin/adm_observer_lib/rest.py",
        "splunk_adm/bin/adm_ops_lib/__init__.py",
        "splunk_adm/bin/adm_ops_lib/ecosystem.py",
    }
)
COLLABORATION_EXPOSURES = {
    "expose:adm_collaboration": ("adm/collaboration", "GET,POST"),
    "expose:adm_observer_mapping": ("adm/observer-mapping", "GET,POST"),
}
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
QUALIFIED_RUNTIME_FILES = frozenset(
    {
        "splunk_adm/bin/admqualified.py",
        "splunk_adm/bin/admacipoll.py",
        *{
            f"splunk_adm/bin/adm_identity_lib/{name}.py"
            for name in (
                "__init__",
                "native_network",
                "network_graph",
                "protocol",
                "qualified",
                "rollup",
                "search",
                "slices",
            )
        },
        *{
            f"splunk_adm/bin/adm_aci_lib/{name}.py"
            for name in (
                "__init__",
                "config",
                "context",
                "fabric",
                "reader",
                "schema",
                "validation",
            )
        },
    }
)
BUNDLED_RUNTIME_FILES = frozenset(
    {
        *BASELINE_RUNTIME_FILES,
        *CASE_RUNTIME_FILES,
        *SETTINGS_RUNTIME_FILES,
        *QUALIFIED_RUNTIME_FILES,
        *COLLABORATION_RUNTIME_FILES,
        "splunk_adm/bin/adm_recovery.py",
        "splunk_adm/bin/adm_recovery_lib/__init__.py",
        "splunk_adm/bin/adm_recovery_lib/core.py",
        "splunk_adm/bin/adm_recovery_lib/planner.py",
        "splunk_adm/bin/adm_recovery_lib/rest.py",
        "splunk_adm/bin/adm_log_lib/__init__.py",
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
QUALIFIED_CONFIG_FILES = frozenset(
    {
        "splunk_adm/default/commands.conf",
        "splunk_adm/default/adm_identity.conf",
        "splunk_adm/default/adm_aci_poll.conf",
        "splunk_adm/default/adm_aci_bindings.conf",
        "splunk_adm/README/adm_identity.conf.spec",
        "splunk_adm/README/adm_aci_poll.conf.spec",
        "splunk_adm/README/adm_aci_bindings.conf.spec",
    }
)
LOGGING_CONFIG_FILES = frozenset(
    {
        "splunk_adm/default/adm_logging.conf",
        "splunk_adm/README/adm_logging.conf.spec",
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


def _check_cases_contract(files, rest, web):
    stanza = "script:adm_investigations"
    present = (
        bool((CASE_RUNTIME_FILES | CASE_CONFIG_FILES) & files.keys())
        or rest.has_section(stanza)
        or bool(set(CASE_EXPOSURES) & set(web.sections()))
    )
    if not present:
        return set()
    missing = sorted((CASE_RUNTIME_FILES | CASE_CONFIG_FILES) - files.keys())
    if missing:
        raise ValueError(
            f"case registration missing required files: {', '.join(missing)}"
        )
    expected = {
        "match": "/adm/investigations",
        "script": "adm_cases.py",
        "scripttype": "persist",
        "handler": "adm_cases.CasesHandler",
        "python.version": "python3",
        "python.required": "3.13",
        "requireauthentication": "true",
        "capability": "adm_investigate",
        "output_modes": "json",
        "passpayload": "true",
        "passsession": "true",
        "passsystemauth": "false",
        "passhttpheaders": "true",
    }
    if (
        not rest.has_section(stanza)
        or dict(rest[stanza]) != expected
        or set(rest.sections())
        != {
            "script:adm_deployment_settings",
            stanza,
            "script:adm_dependency_monitoring",
            "script:adm_collaboration",
            "script:adm_observer_mapping",
        }
    ):
        raise ValueError(
            "case registration must use the exact authenticated capability and handler"
        )
    for section, (pattern, methods) in CASE_EXPOSURES.items():
        if not web.has_section(section) or dict(web[section]) != {
            "pattern": pattern,
            "methods": methods,
        }:
            raise ValueError(
                "case browser exposure must use exact routes, methods, and native CSRF"
            )
    config = _packaged_config(files, "default/adm_investigations.conf")
    if (
        not config.has_section("persistence")
        or dict(config["persistence"])
        != {"mode": "disabled", "platform": "unqualified", "capture_mode": "disabled"}
        or not config.has_section("capture_transport")
        or dict(config["capture_transport"])
        != {"management_uri": "unconfigured", "ca_file": "unconfigured"}
        or set(config.sections()) != {"persistence", "capture_transport"}
    ):
        raise ValueError(
            "case defaults must remain disabled and unqualified with transport trust unconfigured"
        )
    authorize = _packaged_config(files, "default/authorize.conf")
    investigate_grant = {"adm_investigate": "enabled"}
    investigator_role = {
        **investigate_grant,
        **VIEWER_ROLE,
        "importroles": "adm_viewer",
    }
    if (
        set(authorize.sections())
        != {
            "capability::adm_investigate",
            "role_adm_viewer",
            "role_adm_investigate",
            "role_admin",
            "role_sc_admin",
        }
        or dict(authorize["capability::adm_investigate"])
        or dict(authorize["role_adm_investigate"]) != investigator_role
        or dict(authorize["role_admin"]) != investigate_grant
        or dict(authorize["role_sc_admin"]) != investigate_grant
    ):
        raise ValueError(
            "case capability must grant adm_investigate only to admin, sc_admin, and the adm_investigate role"
        )
    for name in CASE_RUNTIME_FILES:
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(files[name], filename=name)
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid case Python runtime: {name}") from exc
        if name.endswith("/adm_cases.py") and not any(
            isinstance(node, ast.ClassDef) and node.name == "CasesHandler"
            for node in tree.body
        ):
            raise ValueError("case entrypoint must define CasesHandler")
    return set(CASE_EXPOSURES)


def _check_baselines_contract(files, rest, web):
    if (CASE_RUNTIME_FILES | CASE_CONFIG_FILES) - files.keys():
        raise ValueError(
            "baseline host requires the case runtime and authorization configuration"
        )
    missing = sorted((BASELINE_RUNTIME_FILES | BASELINE_CONFIG_FILES) - files.keys())
    if missing:
        raise ValueError(
            f"baseline registration missing required files: {', '.join(missing)}"
        )
    expected = {
        "match": "/adm/dependency-monitoring",
        "script": "adm_baselines.py",
        "scripttype": "persist",
        "handler": "adm_baselines.BaselinesHandler",
        "python.version": "python3",
        "python.required": "3.13",
        "requireauthentication": "true",
        "capability": "adm_investigate",
        "output_modes": "json",
        "passpayload": "true",
        "passsession": "true",
        "passsystemauth": "false",
        "passhttpheaders": "true",
    }
    stanza = "script:adm_dependency_monitoring"
    if not rest.has_section(stanza) or dict(rest[stanza]) != expected:
        raise ValueError(
            "baseline registration must use the exact authenticated capability and handler"
        )
    for section, (pattern, methods) in BASELINE_EXPOSURES.items():
        if not web.has_section(section) or dict(web[section]) != {
            "pattern": pattern,
            "methods": methods,
        }:
            raise ValueError(
                "baseline browser exposure must use exact routes, methods, and native CSRF"
            )
    config = _packaged_config(files, "default/adm_baselines.conf")
    if set(config.sections()) != {"persistence"} or dict(config["persistence"]) != {
        "mode": "disabled",
        "platform": "unqualified",
        "source_mode": "unavailable",
    }:
        raise ValueError(
            "baseline defaults must remain disabled, unqualified and source unavailable"
        )
    for name in BASELINE_RUNTIME_FILES:
        try:
            tree = ast.parse(files[name], filename=name)
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid baseline Python runtime: {name}") from exc
        if name.endswith("/adm_baselines.py") and not any(
            isinstance(node, ast.ClassDef) and node.name == "BaselinesHandler"
            for node in tree.body
        ):
            raise ValueError("baseline entrypoint must define BaselinesHandler")
    return set(BASELINE_EXPOSURES)


def _check_collaboration_contract(files, rest, web):
    missing = sorted(COLLABORATION_RUNTIME_FILES - files.keys())
    if missing:
        raise ValueError(
            f"collaboration registration missing required files: {', '.join(missing)}"
        )
    expected_collaboration = {
        "match": "/adm/collaboration",
        "script": "adm_collaboration.py",
        "scripttype": "persist",
        "handler": "adm_collaboration.CollaborationHandler",
        "python.version": "python3",
        "python.required": "3.13",
        "requireauthentication": "true",
        "capability": "adm_investigate",
        "output_modes": "json",
        "passpayload": "true",
        "passsession": "true",
        "passsystemauth": "false",
        "passhttpheaders": "true",
    }
    expected_mapping = {
        "match": "/adm/observer-mapping",
        "script": "adm_observer_mapping.py",
        "scripttype": "persist",
        "handler": "adm_observer_mapping.ObserverMappingHandler",
        "python.version": "python3",
        "python.required": "3.13",
        "requireauthentication": "true",
        "capability.post": "admin_all_objects",
        "output_modes": "json",
        "passpayload": "true",
        "passsession": "true",
        "passsystemauth": "false",
    }
    if (
        not rest.has_section("script:adm_collaboration")
        or dict(rest["script:adm_collaboration"]) != expected_collaboration
    ):
        raise ValueError(
            "collaboration registration must use the exact authenticated capability and handler"
        )
    if (
        not rest.has_section("script:adm_observer_mapping")
        or dict(rest["script:adm_observer_mapping"]) != expected_mapping
    ):
        raise ValueError(
            "observer mapping registration must use authenticated administrator writes"
        )
    for section, (pattern, methods) in COLLABORATION_EXPOSURES.items():
        if not web.has_section(section) or dict(web[section]) != {
            "pattern": pattern,
            "methods": methods,
        }:
            raise ValueError(
                "collaboration browser exposure must use exact routes, methods, and native CSRF"
            )
    collections = _packaged_config(files, "default/collections.conf")
    ledger_fields = {
        "field.format": "number",
        "field.kind": "string",
        "field.previous_revision": "string",
        "field.request_id": "string",
        "field.operation_fingerprint": "string",
        "field.revision": "string",
        "field.payload_json": "string",
        "replicate": "false",
    }
    for name in ("adm_saved_views", "adm_business_ownership", "adm_change_assertions"):
        if (
            not collections.has_section(name)
            or dict(collections[name]) != ledger_fields
        ):
            raise ValueError(
                f"packaged collaboration collection {name} must preserve insert-only schema and replicate = false"
            )
    metadata = _packaged_config(files, "metadata/default.meta")
    for stanza in (
        "collections/adm_saved_views",
        "collections/adm_business_ownership",
        "collections/adm_change_assertions",
        "collections/adm_observer_scope",
    ):
        acl = re.sub(r"\s+", "", metadata.get(stanza, "access", fallback=""))
        if acl != VIEWER_ACL:
            raise ValueError(
                f"packaged {stanza} ACL must preserve Atlas viewer readers and admin/sc_admin writers"
            )
    for name in COLLABORATION_RUNTIME_FILES:
        if not name.endswith(".py"):
            continue
        try:
            tree = ast.parse(files[name], filename=name)
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid collaboration Python runtime: {name}") from exc
        if name.endswith("/adm_collaboration.py") and not any(
            isinstance(node, ast.ClassDef) and node.name == "CollaborationHandler"
            for node in tree.body
        ):
            raise ValueError(
                "collaboration entrypoint must define CollaborationHandler"
            )
        if name.endswith("/adm_observer_mapping.py") and not any(
            isinstance(node, ast.ClassDef) and node.name == "ObserverMappingHandler"
            for node in tree.body
        ):
            raise ValueError(
                "observer mapping entrypoint must define ObserverMappingHandler"
            )
    return set(COLLABORATION_EXPOSURES)


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
    case_exposures = _check_cases_contract(files, rest, web)
    baseline_exposures = _check_baselines_contract(files, rest, web)
    collaboration_exposures = _check_collaboration_contract(files, rest, web)
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
    macro_read = "expose:adm_macro_stanza_read"
    if (
        not web.has_section(macro_read)
        or set(web[macro_read]) != {"pattern", "methods"}
        or web.get(macro_read, "pattern", fallback="")
        != "configs/v1/conftypes/macros/stanzas:get"
        or web.get(macro_read, "methods", fallback="") != "POST"
        or set(web.sections())
        != {exposure, macro_read}
        | case_exposures
        | baseline_exposures
        | collaboration_exposures
    ):
        raise ValueError(
            "metadata browser exposure must use the exact read-only macro getter, POST only, and native CSRF protection"
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
    if re.sub(r"\s+", "", acl) != VIEWER_ACL:
        raise ValueError(
            "packaged settings ACL must preserve Atlas viewer readers and admin/sc_admin writers"
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


# Demo captures and the demo client run only on the development server. These
# markers come from frontend/src/data/demoClient.ts, catalogDemo.ts and the
# fixtures/demo-*.json captures; none of them may reach the packaged app.
DEMO_BUNDLE_MARKERS = (
    b"app/splunk_adm/demo/",
    b"Demo data is not prepared",
    b"Catalog fixture",
    b"ACI pilot fabric",
    b"adm_device_flows-shaped rows for the ACI demo",
)


# The only web assets a release may ship. Anything else under static/ (demo
# rows, captured fixtures, source maps, stray files) fails the check.
STATIC_ALLOWLIST = frozenset(
    {
        "splunk_adm/appserver/static/adm.css",
        "splunk_adm/appserver/static/pages/atlas.js",
        THOUSANDEYES_BUNDLE_PATH,
        THOUSANDEYES_MANIFEST_PATH,
        THOUSANDEYES_CSS_PATH,
        JOURNEYS_BUNDLE_PATH,
        JOURNEYS_MANIFEST_PATH,
        JOURNEYS_CSS_PATH,
        IMPACT_BUNDLE_PATH,
        IMPACT_MANIFEST_PATH,
        IMPACT_CSS_PATH,
        MULTICAST_BUNDLE_PATH,
        MULTICAST_MANIFEST_PATH,
        MULTICAST_CSS_PATH,
        HISTORY_BUNDLE_PATH,
        HISTORY_MANIFEST_PATH,
        HISTORY_CSS_PATH,
        MIGRATION_BUNDLE_PATH,
        MIGRATION_MANIFEST_PATH,
        MIGRATION_CSS_PATH,
        # Segmentation policy workbench.
        SEGMENTATION_BUNDLE_PATH,
        SEGMENTATION_MANIFEST_PATH,
        SEGMENTATION_CSS_PATH,
        INCIDENT_BUNDLE_PATH,
        INCIDENT_MANIFEST_PATH,
        INCIDENT_CSS_PATH,
        ECOSYSTEM_BUNDLE_PATH,
        ECOSYSTEM_MANIFEST_PATH,
        ECOSYSTEM_CSS_PATH,
    }
)


def _is_fixture(name: str) -> bool:
    """Synthetic or captured fixture data (fixtures/** shapes), anywhere."""
    parts = name.split("/")
    base = parts[-1]
    return (
        "fixtures" in parts[:-1]
        or "demo" in parts[:-1]
        or any(part.startswith("raw-") for part in parts[:-1])
        or (base.startswith(("demo-", "path-trace-")) and base.endswith(".json"))
        or base == "scenario.json"
        or base.endswith(".ndjson")
    )


INTERNAL_EVIDENCE_DOCS = frozenset(
    {
        "splunk_adm/docs/FEATURE_DELIVERY.md",
        "splunk_adm/docs/FEATURE_QUALIFICATION.json",
    }
)


def _check_no_demo(files: dict[str, bytes]) -> None:
    static = "splunk_adm/appserver/static/"
    for name in sorted(files):
        if name.startswith(static) and name.endswith(".js"):
            for marker in DEMO_BUNDLE_MARKERS:
                if marker in files[name]:
                    raise ValueError(
                        f"archive ships demo code in {name}: {marker.decode()}"
                    )
    for name in sorted(files):
        if _is_fixture(name):
            raise ValueError(f"archive ships demo fixture: {name}")
        if name in INTERNAL_EVIDENCE_DOCS:
            raise ValueError(f"archive ships internal evidence doc: {name}")
        if name.startswith(static) and name not in STATIC_ALLOWLIST:
            raise ValueError(f"archive ships unlisted static file: {name}")


def _required_files(files: dict[str, bytes], version: str, registry: bytes) -> None:
    required = {
        "splunk_adm/appserver/static/adm.css",
        "splunk_adm/appserver/static/pages/atlas.js",
        THOUSANDEYES_BUNDLE_PATH,
        THOUSANDEYES_MANIFEST_PATH,
        THOUSANDEYES_CSS_PATH,
        *{
            f"splunk_adm/default/data/ui/views/{page}.xml"
            for page in (
                "applications",
                "map",
                "endpoints",
                "multicast",
                "data_health",
                "setup",
                "help",
                "device",
                "impact",
                "cases",
                "migration",
            )
        },
        "splunk_adm/default/app.conf",
        "splunk_adm/LICENSE",
        "splunk_adm/NOTICE",
        "splunk_adm/THIRD_PARTY_NOTICES.txt",
        "splunk_adm/docs/DATA_LAYER.md",
        "splunk_adm/docs/DEPENDENCY_BASELINES.md",
        "splunk_adm/docs/DEPENDENCY_WATCH_EXECUTION.md",
        "splunk_adm/docs/BASELINE_SOURCE_PROVIDER.md",
        "splunk_adm/docs/CASE_REQUEST_SUPERVISION.md",
        "splunk_adm/docs/CASE_SOURCE_QUALIFICATION.md",
        "splunk_adm/docs/INCIDENT_SOURCE_ASSOCIATIONS.md",
        "splunk_adm/docs/INVESTIGATION_RECORDS.md",
        "splunk_adm/docs/FEATURE_SOURCE_OBSERVATIONS.md",
        "splunk_adm/docs/FEATURE_FOUNDATIONS.md",
        "splunk_adm/docs/DEPLOYMENT_HEALTH.md",
        "splunk_adm/docs/LATE_CATALYST_RECEIPTS.md",
        "splunk_adm/docs/UPGRADES.md",
        "splunk_adm/docs/CISCO_CONTRACT_MIGRATION.md",
        "splunk_adm/docs/CISCO_NETWORKING_QUALIFICATION.md",
        "splunk_adm/docs/operators/cisco-enterprise-networking.md",
        "splunk_adm/docs/DNS_EVIDENCE_QUALIFICATION.md",
        "splunk_adm/docs/DNS_EVIDENCE_SCENARIOS.md",
        "splunk_adm/docs/DNS_EVIDENCE_DESIGN.md",
        "splunk_adm/docs/VSPHERE_SWITCH_DESIGN.md",
        "splunk_adm/docs/DNS_INGESTION_RESEARCH.md",
        "splunk_adm/docs/operators/dns-evidence.md",
        "splunk_adm/docs/operators/multicast.md",
        "splunk_adm/docs/multicast-source-qualification.md",
        RECOVERY_DOC_PATH,
        RETENTION_DOC_PATH,
        "splunk_adm/docs/operators/qualified-native-network.md",
        "splunk_adm/default/collections.conf",
        "splunk_adm/default/adm_recovery.conf",
        ALERT_ACTIONS_PATH,
        "splunk_adm/default/macros.conf",
        "splunk_adm/default/savedsearches.conf",
        "splunk_adm/default/transforms.conf",
        "splunk_adm/default/data/ui/nav/default.xml",
        "splunk_adm/default/data/ui/views/dependency_map.xml",
        "splunk_adm/metadata/default.meta",
        *(BUNDLED_RUNTIME_FILES - CASE_RUNTIME_FILES),
        *SETTINGS_CONFIG_FILES,
        *BASELINE_CONFIG_FILES,
        *QUALIFIED_CONFIG_FILES,
        *LOGGING_CONFIG_FILES,
        SETTINGS_REGISTRY_PATH,
    }
    missing = sorted(required - files.keys())
    if missing:
        raise ValueError(f"archive missing required files: {', '.join(missing)}")
    _check_no_demo(files)
    _check_settings_contract(files, registry)
    _check_qualified_contract(files)
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
    optional_gzip = len(
        gzip.compress(files[THOUSANDEYES_BUNDLE_PATH], compresslevel=9, mtime=0)
    )
    if optional_gzip > MAX_THOUSANDEYES_GZIP_BYTES:
        raise ValueError("ThousandEyes optional bundle exceeds its 48 KiB gzip budget")
    if len(files[THOUSANDEYES_CSS_PATH]) > MAX_THOUSANDEYES_CSS_BYTES:
        raise ValueError("ThousandEyes optional CSS exceeds its 16 KiB budget")
    try:
        optional_manifest = json.loads(files[THOUSANDEYES_MANIFEST_PATH])
        asset_version = optional_manifest["assetVersion"]
        if (
            optional_manifest.get("schemaVersion") != 1
            or not isinstance(asset_version, str)
            or not re.fullmatch(r"[0-9a-f]{24}", asset_version)
            or optional_manifest.get("javascriptSha256")
            != hashlib.sha256(files[THOUSANDEYES_BUNDLE_PATH]).hexdigest()
            or asset_version.encode() not in files[ATLAS_BUNDLE_PATH]
            or asset_version.encode() not in files[THOUSANDEYES_BUNDLE_PATH]
        ):
            raise ValueError("mismatch")
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError(
            "ThousandEyes asset version/hash does not match the main bundle"
        ) from exc
    # Older packages without Journey registration remain valid. Once any part is
    # present, require the complete independently versioned bundle and guide.
    journey_files = {
        JOURNEYS_BUNDLE_PATH,
        JOURNEYS_MANIFEST_PATH,
        JOURNEYS_CSS_PATH,
        JOURNEYS_DOC_PATH,
    }
    journey_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (
            b"ApplicationAtlasJourneys",
            b"__AtlasJourneysHost",
            b"pages/journeys.js",
        )
    )
    if journey_registered or journey_files.intersection(files):
        missing = sorted(journey_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Journey files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[JOURNEYS_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_JOURNEYS_GZIP_BYTES
        ):
            raise ValueError("Journey optional bundle exceeds its 32 KiB gzip budget")
        if len(files[JOURNEYS_CSS_PATH]) > MAX_JOURNEYS_CSS_BYTES:
            raise ValueError("Journey optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[JOURNEYS_MANIFEST_PATH])
            journey_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(journey_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", journey_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[JOURNEYS_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[JOURNEYS_CSS_PATH]).hexdigest()
                or journey_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or journey_version.encode() not in files[JOURNEYS_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Journey asset version/hash does not match the main bundle"
            ) from exc
    # Impact is an independently versioned optional page. Once the main bundle
    # registers its host, or any one asset is present, require the complete set.
    impact_files = {
        IMPACT_BUNDLE_PATH,
        IMPACT_MANIFEST_PATH,
        IMPACT_CSS_PATH,
    }
    impact_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasImpactHost", b"pages/impact.js")
    )
    if impact_registered or impact_files.intersection(files):
        missing = sorted(impact_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Impact files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[IMPACT_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_IMPACT_GZIP_BYTES
        ):
            raise ValueError("Impact optional bundle exceeds its 64 KiB gzip budget")
        if len(files[IMPACT_CSS_PATH]) > MAX_IMPACT_CSS_BYTES:
            raise ValueError("Impact optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[IMPACT_MANIFEST_PATH])
            impact_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(impact_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", impact_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[IMPACT_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[IMPACT_CSS_PATH]).hexdigest()
                or impact_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or impact_version.encode() not in files[IMPACT_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Impact asset version/hash does not match the main bundle"
            ) from exc
    # Multicast is an independently versioned optional page. Once the main bundle
    # registers its host, or any one asset is present, require the complete set.
    multicast_files = {
        MULTICAST_BUNDLE_PATH,
        MULTICAST_MANIFEST_PATH,
        MULTICAST_CSS_PATH,
    }
    multicast_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasMulticastHost", b"pages/multicast.js")
    )
    if multicast_registered or multicast_files.intersection(files):
        missing = sorted(multicast_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Multicast files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[MULTICAST_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_MULTICAST_GZIP_BYTES
        ):
            raise ValueError("Multicast optional bundle exceeds its 64 KiB gzip budget")
        if len(files[MULTICAST_CSS_PATH]) > MAX_MULTICAST_CSS_BYTES:
            raise ValueError("Multicast optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[MULTICAST_MANIFEST_PATH])
            multicast_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(multicast_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", multicast_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[MULTICAST_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[MULTICAST_CSS_PATH]).hexdigest()
                or multicast_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or multicast_version.encode() not in files[MULTICAST_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Multicast asset version/hash does not match the main bundle"
            ) from exc
    # Configuration history is an independently versioned, live-only asset.
    # Once the main bundle registers its host, or any one asset is present,
    # require and validate the complete set.
    history_files = {HISTORY_BUNDLE_PATH, HISTORY_MANIFEST_PATH, HISTORY_CSS_PATH}
    history_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasHistoryHost", b"pages/history.js")
    )
    if history_registered or history_files.intersection(files):
        missing = sorted(history_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required History files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[HISTORY_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_HISTORY_GZIP_BYTES
        ):
            raise ValueError("History optional bundle exceeds its 48 KiB gzip budget")
        if len(files[HISTORY_CSS_PATH]) > MAX_HISTORY_CSS_BYTES:
            raise ValueError("History optional CSS exceeds its 16 KiB gzip budget")
        try:
            manifest = json.loads(files[HISTORY_MANIFEST_PATH])
            history_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(history_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", history_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[HISTORY_BUNDLE_PATH]).hexdigest()
                or history_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or history_version.encode() not in files[HISTORY_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "History asset version/hash does not match the main bundle"
            ) from exc
    # The migration move-group planner is an independently versioned optional
    # page. Once the main bundle registers its host, or any one asset is
    # present, require and validate the complete set.
    migration_files = {
        MIGRATION_BUNDLE_PATH,
        MIGRATION_MANIFEST_PATH,
        MIGRATION_CSS_PATH,
    }
    migration_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasMigrationHost", b"pages/migration.js")
    )
    if migration_registered or migration_files.intersection(files):
        missing = sorted(migration_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Migration files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[MIGRATION_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_MIGRATION_GZIP_BYTES
        ):
            raise ValueError("Migration optional bundle exceeds its 48 KiB gzip budget")
        if len(files[MIGRATION_CSS_PATH]) > MAX_MIGRATION_CSS_BYTES:
            raise ValueError("Migration optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[MIGRATION_MANIFEST_PATH])
            migration_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(migration_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", migration_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[MIGRATION_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[MIGRATION_CSS_PATH]).hexdigest()
                or migration_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or migration_version.encode() not in files[MIGRATION_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Migration asset version/hash does not match the main bundle"
            ) from exc
    # Segmentation policy workbench: an independently versioned optional asset.
    # Once the main bundle registers its host, or any one asset is present,
    # require and validate the complete set.
    segmentation_files = {
        SEGMENTATION_BUNDLE_PATH,
        SEGMENTATION_MANIFEST_PATH,
        SEGMENTATION_CSS_PATH,
    }
    segmentation_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasSegmentationHost", b"pages/segmentation.js")
    )
    if segmentation_registered or segmentation_files.intersection(files):
        missing = sorted(segmentation_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Segmentation files: {', '.join(missing)}"
            )
        if (
            len(
                gzip.compress(files[SEGMENTATION_BUNDLE_PATH], compresslevel=9, mtime=0)
            )
            > MAX_SEGMENTATION_GZIP_BYTES
        ):
            raise ValueError(
                "Segmentation optional bundle exceeds its 40 KiB gzip budget"
            )
        if len(files[SEGMENTATION_CSS_PATH]) > MAX_SEGMENTATION_CSS_BYTES:
            raise ValueError("Segmentation optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[SEGMENTATION_MANIFEST_PATH])
            segmentation_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(segmentation_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", segmentation_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[SEGMENTATION_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[SEGMENTATION_CSS_PATH]).hexdigest()
                or segmentation_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or segmentation_version.encode() not in files[SEGMENTATION_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Segmentation asset version/hash does not match the main bundle"
            ) from exc
    # End segmentation policy workbench.
    # The map investigation workspace is an independently versioned optional
    # asset. Once the main bundle registers its host, or any one asset is
    # present, require and validate the complete set.
    incident_files = {INCIDENT_BUNDLE_PATH, INCIDENT_MANIFEST_PATH, INCIDENT_CSS_PATH}
    incident_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasIncidentHost", b"pages/incident.js")
    )
    if incident_registered or incident_files.intersection(files):
        missing = sorted(incident_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Incident files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[INCIDENT_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_INCIDENT_GZIP_BYTES
        ):
            raise ValueError("Incident optional bundle exceeds its 32 KiB gzip budget")
        if len(files[INCIDENT_CSS_PATH]) > MAX_INCIDENT_CSS_BYTES:
            raise ValueError("Incident optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[INCIDENT_MANIFEST_PATH])
            incident_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(incident_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", incident_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[INCIDENT_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[INCIDENT_CSS_PATH]).hexdigest()
                or incident_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or incident_version.encode() not in files[INCIDENT_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Incident asset version/hash does not match the main bundle"
            ) from exc
    # Ecosystem firewall evidence is an independently versioned optional asset.
    # Once the main bundle registers its host, or any one asset is present,
    # require and validate the complete set.
    ecosystem_files = {
        ECOSYSTEM_BUNDLE_PATH,
        ECOSYSTEM_MANIFEST_PATH,
        ECOSYSTEM_CSS_PATH,
    }
    ecosystem_registered = any(
        marker in files[ATLAS_BUNDLE_PATH]
        for marker in (b"__AtlasEcosystemHost", b"pages/ecosystem.js")
    )
    if ecosystem_registered or ecosystem_files.intersection(files):
        missing = sorted(ecosystem_files - files.keys())
        if missing:
            raise ValueError(
                f"archive missing required Ecosystem files: {', '.join(missing)}"
            )
        if (
            len(gzip.compress(files[ECOSYSTEM_BUNDLE_PATH], compresslevel=9, mtime=0))
            > MAX_ECOSYSTEM_GZIP_BYTES
        ):
            raise ValueError("Ecosystem optional bundle exceeds its 48 KiB gzip budget")
        if len(files[ECOSYSTEM_CSS_PATH]) > MAX_ECOSYSTEM_CSS_BYTES:
            raise ValueError("Ecosystem optional CSS exceeds its 16 KiB budget")
        try:
            manifest = json.loads(files[ECOSYSTEM_MANIFEST_PATH])
            ecosystem_version = manifest["assetVersion"]
            if (
                manifest.get("schemaVersion") != 1
                or not isinstance(ecosystem_version, str)
                or not re.fullmatch(r"[0-9a-f]{24}", ecosystem_version)
                or manifest.get("javascriptSha256")
                != hashlib.sha256(files[ECOSYSTEM_BUNDLE_PATH]).hexdigest()
                or manifest.get("cssSha256")
                != hashlib.sha256(files[ECOSYSTEM_CSS_PATH]).hexdigest()
                or ecosystem_version.encode() not in files[ATLAS_BUNDLE_PATH]
                or ecosystem_version.encode() not in files[ECOSYSTEM_BUNDLE_PATH]
            ):
                raise ValueError("mismatch")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ValueError(
                "Ecosystem asset version/hash does not match the main bundle"
            ) from exc
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
    simple_reload = {
        "adm_recovery",
        "adm_settings",
        "adm_dependency_watch",
        "adm_identity",
        "adm_aci_poll",
        "adm_aci_bindings",
        "adm_investigations",
        "adm_baselines",
        "adm_logging",
    }
    custom = set(simple_reload)
    for path in files:
        match = re.fullmatch(
            r"splunk_adm/(?:default/(adm_[a-z0-9_]+)\.conf|README/([a-zA-Z][a-zA-Z0-9_.-]*)\.conf\.spec)",
            path,
        )
        if match:
            custom.add(match.group(1) or match.group(2))
    for name in sorted(custom):
        value = config.get("triggers", f"reload.{name}", fallback="").strip()
        if name in simple_reload and value != "simple":
            raise ValueError(f"app.conf [triggers] reload.{name} must be simple")
        if not value:
            raise ValueError(f"app.conf [triggers] reload.{name} must be declared")
    actions = configparser.RawConfigParser(strict=True)
    try:
        actions.read_string(files[ALERT_ACTIONS_PATH].decode("utf-8"))
    except (configparser.Error, UnicodeDecodeError) as exc:
        raise ValueError("invalid packaged alert_actions.conf") from exc
    if "splunk_adm/default/inputs.conf" in files:
        raise ValueError("packaged app must not ship default/inputs.conf")
    if not actions.has_section("adm_recovery"):
        raise ValueError("packaged alert_actions.conf is missing [adm_recovery]")
    command = actions.get("adm_recovery", "alert.execute.cmd", fallback="").strip()
    entrypoint = "splunk_adm/bin/adm_recovery.py"
    if command != "adm_recovery.py" or entrypoint not in files:
        raise ValueError(
            "adm_recovery alert registration must reference shipped adm_recovery.py"
        )
    if set(actions.sections()) != {"adm_recovery", "adm_dependency_watch"}:
        raise ValueError("packaged alert_actions.conf contains unreviewed stanzas")
    if not files[entrypoint].startswith(b"#!"):
        raise ValueError("shipped adm_recovery.py is not an executable script")
    if actions.get("adm_recovery", "passSystemAuth", fallback="").lower() != "false":
        raise ValueError("adm_recovery alert action must set passSystemAuth = false")
    logging_config = _packaged_config(files, "default/adm_logging.conf")
    if set(logging_config.sections()) != {"logging"} or dict(
        logging_config["logging"]
    ) != {"level": "INFO"}:
        raise ValueError("adm_logging.conf must ship with level = INFO only")
    if (
        actions.get("adm_recovery", "python.version", fallback="") != "python3"
        or actions.get("adm_recovery", "python.required", fallback="") != "3.13"
    ):
        raise ValueError(
            "adm_recovery alert action must use the exact Python 3.13 settings"
        )
    recovery = _packaged_config(files, "default/adm_recovery.conf")
    if (
        not recovery.has_section("recovery")
        or recovery.get("recovery", "enabled", fallback=None) != "0"
    ):
        raise ValueError("adm_recovery.conf must ship with enabled = 0")
    _check_watch_action(files, actions, config)
    if not config.has_section("install"):
        raise ValueError("packaged app.conf is missing [install]")
    build = config.get("install", "build", fallback=None)
    if build is None or not re.fullmatch(r"[1-9]\d*", build):
        raise ValueError("app.conf [install] build must be a positive integer")
    _check_viewer_boundary(files)


def _check_watch_action(files, actions, app):
    config = _packaged_config(files, "default/adm_dependency_watch.conf")
    if set(config.sections()) != {"execution"} or dict(config["execution"]) != {
        "enabled": "false"
    }:
        raise ValueError("dependency watch execution must ship disabled")
    expected = {
        "is_custom": "1",
        "payload_format": "json",
        "python.version": "python3",
        "python.required": "3.13",
        "passsystemauth": "false",
        "alert.execute.cmd": "adm_dependency_watch.py",
        "maxtime": "1m",
        "label": "Application Atlas dependency watch",
        "description": "Disabled administrator-only explicit-window findings action; no production source provider is shipped.",
    }
    if (
        not actions.has_section("adm_dependency_watch")
        or dict(actions["adm_dependency_watch"]) != expected
    ):
        raise ValueError(
            "dependency watch action must preserve disabled owner-session contract"
        )
    if not files["splunk_adm/bin/adm_dependency_watch.py"].startswith(b"#!"):
        raise ValueError("dependency watch action must ship its executable entrypoint")
    if app.get("triggers", "reload.adm_dependency_watch", fallback=None) != "simple":
        raise ValueError("reload.adm_dependency_watch must be simple")
    metadata = _packaged_config(files, "metadata/default.meta")
    for stanza in (
        "alert_actions/adm_dependency_watch",
        "adm_dependency_watch",
        "savedsearches",
    ):
        acl = re.sub(r"\s+", "", metadata.get(stanza, "access", fallback=""))
        if acl != "read:[admin,sc_admin],write:[admin,sc_admin]":
            raise ValueError(
                "dependency watch action and owner searches must remain administrator-only"
            )
    searches = _packaged_config(files, "default/savedsearches.conf")
    webhook_alerts = {
        "ADM - Newly blocked production dependency",
        "ADM - Redundancy loss",
        "ADM - Unexpected new dependency",
        "ADM - Telemetry blindness",
    }
    for stanza in searches.sections():
        if searches.get(stanza, "disabled", fallback="0").lower() not in ("1", "true"):
            raise ValueError(f"saved search must ship disabled: {stanza}")
        if searches.get(stanza, "dispatchAs", fallback="") != "owner":
            raise ValueError(f"saved search must set dispatchAs = owner: {stanza}")
        actions_list = {
            value.strip()
            for value in searches.get(stanza, "actions", fallback="").split(",")
            if value.strip()
        }
        if (
            searches.get(stanza, "action.adm_dependency_watch", fallback="0").lower()
            not in ("0", "false")
            or "adm_dependency_watch" in actions_list
        ):
            raise ValueError("dependency watch schedules must not ship")
        if (
            searches.get(stanza, "action.webhook", fallback="0").lower()
            not in ("0", "false")
            or "webhook" in actions_list
            or searches.has_option(stanza, "action.webhook.param.url")
        ):
            raise ValueError(f"webhook action must ship disabled: {stanza}")
        if stanza in webhook_alerts and searches.get(
            stanza, "enableSched", fallback="1"
        ).lower() not in ("0", "false"):
            raise ValueError(f"opt-in alert schedule must ship disabled: {stanza}")
    current_macro = ""
    for raw_line in (
        files["splunk_adm/default/macros.conf"].decode("utf-8").splitlines()
    ):
        stripped = raw_line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current_macro = stripped[1:-1].strip()
        elif current_macro.endswith("_schema_qualified") and re.fullmatch(
            r"iseval\s*=\s*(?:1|true|t|yes|y|on)", stripped, flags=re.IGNORECASE
        ):
            raise ValueError(
                f"schema qualification macro must not set iseval = 1: {current_macro}"
            )


def _check_qualified_contract(files: dict[str, bytes]) -> None:
    """Keep the qualified commands portable, disabled, and fully bundled."""
    for name in QUALIFIED_RUNTIME_FILES:
        try:
            tree = ast.parse(files[name], filename=name)
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid packaged qualified runtime: {name}") from exc
        if name.endswith("admqualified.py") and not any(
            isinstance(node, ast.ClassDef) and node.name == "AdmQualified"
            for node in tree.body
        ):
            raise ValueError("qualified identity entrypoint must define AdmQualified")
        if name.endswith("admacipoll.py") and not any(
            isinstance(node, ast.ClassDef) and node.name == "AdmAciPoll"
            for node in tree.body
        ):
            raise ValueError("ACI poll entrypoint must define AdmAciPoll")

    commands = _packaged_config(files, "default/commands.conf")
    if set(commands.sections()) != {"admqualified", "admacipoll"}:
        raise ValueError("packaged commands.conf contains unreviewed stanzas")
    expected = {
        "chunked": "true",
        "local": "true",
        "generating": "true",
        "python.version": "python3",
        "python.required": "3.13",
    }
    for stanza, filename in (
        ("admqualified", "admqualified.py"),
        ("admacipoll", "admacipoll.py"),
    ):
        if (
            not commands.has_section(stanza)
            or commands.get(stanza, "filename", fallback="") != filename
        ):
            raise ValueError("qualified command registration has an invalid filename")
        if any(
            commands.get(stanza, key, fallback=None) != value
            for key, value in expected.items()
        ):
            raise ValueError(
                "qualified command registration must use the exact local Python 3.13 settings"
            )

    identity = _packaged_config(files, "default/adm_identity.conf")
    if set(identity.sections()) != {"profile", "network", "summary"}:
        raise ValueError("identity defaults contain unreviewed sections")
    if set(identity["summary"]) != {"enabled", "index", "lateness"} or (
        identity.get("summary", "enabled", fallback=None) != "false"
    ):
        raise ValueError("qualified summaries must ship disabled with reviewed keys")
    if set(identity["profile"]) != {
        "enabled",
        "cluster",
        "environment",
        "scope",
        "producer_id",
        "interval_source",
        "span_source",
        "interval_index",
        "span_index",
        "interval_sourcetype",
        "span_sourcetype",
        "namespaces",
    } or set(identity["network"]) != {"enabled", "profiles_json", "frontends_json"}:
        raise ValueError("identity defaults contain unreviewed keys")
    if identity.get("profile", "enabled", fallback=None) != "false":
        raise ValueError("identity profile must be disabled in the package")
    for key in (
        "cluster",
        "environment",
        "scope",
        "producer_id",
        "interval_source",
        "span_source",
        "namespaces",
    ):
        if identity.get("profile", key, fallback=None) != "placeholder":
            raise ValueError("identity defaults must retain portable placeholders")
    if any(
        identity.get("profile", key, fallback=None) != value
        for key, value in {
            "interval_index": "adm_identity_intervals",
            "span_index": "adm_identity_spans",
            "interval_sourcetype": "adm:pod_ip_interval:v2",
            "span_sourcetype": "otel:traces",
        }.items()
    ):
        raise ValueError("identity defaults contain unreviewed source selectors")
    if identity.get("network", "enabled", fallback=None) != "false" or any(
        identity.get("network", key, fallback=None) != "[]"
        for key in ("profiles_json", "frontends_json")
    ):
        raise ValueError("native network defaults must be disabled and empty")
    aci = _packaged_config(files, "default/adm_aci_poll.conf")
    bindings = _packaged_config(files, "default/adm_aci_bindings.conf")
    if set(aci.sections()) != {"profile"} or set(aci["profile"]) != {"enabled"}:
        raise ValueError("ACI poll defaults must contain only disabled profile state")
    if set(bindings.sections()) != {"bindings"} or set(bindings["bindings"]) != {
        "enabled"
    }:
        raise ValueError("ACI bindings defaults must contain only disabled state")
    if (
        aci.get("profile", "enabled", fallback=None) != "false"
        or bindings.get("bindings", "enabled", fallback=None) != "false"
    ):
        raise ValueError("ACI poll and bindings defaults must be disabled")
    for name in QUALIFIED_CONFIG_FILES:
        if name.endswith(".spec") and not files[name].strip():
            raise ValueError(f"empty qualified configuration specification: {name}")
    macro_text = files["splunk_adm/default/macros.conf"].decode("utf-8")

    def macro_section(name: str) -> str:
        match = re.search(
            rf"(?ms)^\[{re.escape(name)}\]\s*\n(.*?)(?=^\[|\Z)", macro_text
        )
        return match.group(1) if match else ""

    catalog = macro_section("adm_application_catalog_read")
    graph = macro_section("adm_application_graph_read(4)")
    if not re.search(r"(?m)^definition\s*=\s*inputlookup adm_app_catalog\s*$", catalog):
        raise ValueError("catalog wrapper must retain the legacy catalog reader")
    if not re.search(r"(?m)^iseval\s*=\s*0\s*$", catalog):
        raise ValueError("catalog wrapper must be a command macro")
    if not re.search(
        r'(?m)^definition\s*=\s*search `adm_graph\("\$service\$", "\$environment\$", "\$cluster\$", "\$namespace\$"\)`\s*$',
        graph,
    ) or not re.search(r"(?m)^iseval\s*=\s*0\s*$", graph):
        raise ValueError("graph wrapper must retain the legacy graph reader")
    if not re.search(
        r"(?m)^args\s*=\s*service, environment, cluster, namespace\s*$", graph
    ) or not re.search(r"(?m)^validation\s*=\s*.+$", graph):
        raise ValueError("graph wrapper must retain argument validation")
    metadata = _packaged_config(files, "metadata/default.meta")
    global_acl = re.sub(r"\s+", "", metadata.get("app", "access", fallback=""))
    if global_acl != VIEWER_ACL:
        raise ValueError("qualified configuration ACL must remain admin-owned")
    for section in metadata.sections():
        lowered = section.casefold()
        if any(token in lowered for token in ("adm_identity", "adm_aci", "commands")):
            acl = re.sub(r"\s+", "", metadata.get(section, "access", fallback=""))
            if acl and acl != VIEWER_ACL:
                raise ValueError("qualified configuration ACL must remain admin-owned")


def _check_viewer_boundary(files: dict[str, bytes]) -> None:
    if "splunk_adm/default/authorize.conf" not in files:
        raise ValueError("archive must ship the adm_viewer role in authorize.conf")
    authorize = _packaged_config(files, "default/authorize.conf")
    if (
        not authorize.has_section("role_adm_viewer")
        or dict(authorize["role_adm_viewer"]) != VIEWER_ROLE
    ):
        raise ValueError("adm_viewer must grant no capability, index or imported role")
    if (
        authorize.get("role_adm_investigate", "importRoles", fallback="")
        != "adm_viewer"
    ):
        raise ValueError("adm_investigate must inherit exactly the adm_viewer role")
    metadata = _packaged_config(files, "metadata/default.meta")
    for section in metadata.sections():
        acl = re.sub(r"\s+", "", metadata.get(section, "access", fallback=""))
        if "*" in acl:
            raise ValueError(f"metadata must not grant everyone access: {section}")
        if metadata.get(section, "export", fallback="none") != "none":
            raise ValueError(f"metadata must not export app objects: {section}")
        expected = ADMIN_ACL if section in ADMIN_ONLY_METADATA else VIEWER_ACL
        if metadata.has_option(section, "access") and acl != expected:
            raise ValueError(
                f"metadata {section} must grant read only to Atlas viewers or administrators"
            )
    missing = sorted(ADMIN_ONLY_METADATA - set(metadata.sections()))
    if missing:
        raise ValueError(
            f"administrator-only metadata stanzas are missing: {', '.join(missing)}"
        )
    for kind in ("collections", "transforms"):
        for name in _packaged_config(files, f"default/{kind}.conf").sections():
            if not metadata.has_option(f"{kind}/{name}", "access"):
                raise ValueError(
                    f"derived lookup {kind}/{name} requires an explicit metadata ACL"
                )


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
