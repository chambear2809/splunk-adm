#!/usr/bin/env python3
"""Validate an AppDynamics snapshot and render separate HEC NDJSON captures.

The AppDynamics hierarchy/backend output uses the versioned source contract
``application_atlas.appdynamics_inventory.v1``. Node IP observations are
validated and rendered through the existing ``adm:asset_history`` v1 importer.
This command does not send data to Splunk.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from tools.export_appdynamics import (
    MAX_OUTPUT_BYTES,
    SCHEMA,
    SCHEMA_VERSION,
    SOURCE,
    SOURCETYPE,
    _canonical,
)
from tools.import_asset_history import (
    BatchImportError,
    find_conflicts,
    prepare,
    render_ndjson as render_asset_history_ndjson,
)

MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_HEC_LINE_BYTES = 65_535
AUTHORITY_RE = re.compile(r"^[a-z0-9][a-z0-9._:/@-]{0,254}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$")
HEX_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
SECRET_PROPERTY_RE = re.compile(
    r"(?:pass(?:word)?|secret|token|credential|authorization|api.?key|access.?key|user(?:name)?)",
    re.IGNORECASE,
)
RECORD_TYPES = {"snapshot", "application", "tier", "node", "backend"}
COMMON_FIELDS = {
    "schema_version",
    "schema",
    "source",
    "controller_authority",
    "scope",
    "snapshot_id",
    "snapshot_at",
    "collection_started_at",
    "collection_completed_at",
    "collection_skew_seconds",
    "snapshot_complete",
    "record_type",
    "record_id",
    "observed_at",
    "identity_basis",
    "record_fingerprint",
}
TYPE_FIELDS = {
    "snapshot": COMMON_FIELDS | {"record_counts", "empty_inventory"},
    "application": COMMON_FIELDS | {"application_id", "application_name"},
    "tier": COMMON_FIELDS
    | {
        "application_id",
        "application_name",
        "tier_id",
        "tier_name",
        "tier_type",
        "agent_type",
        "reported_node_count",
    },
    "node": COMMON_FIELDS
    | {
        "application_id",
        "application_name",
        "tier_id",
        "tier_name",
        "node_id",
        "node_name",
        "machine_id",
        "machine_name",
        "machine_os_type",
        "machine_agent_present",
        "machine_agent_version",
        "application_agent_present",
        "application_agent_version",
        "agent_type",
        "ip_addresses",
        "ip_address_observation",
        "relationship_basis",
    },
    "backend": COMMON_FIELDS
    | {
        "application_id",
        "application_name",
        "backend_id",
        "backend_name",
        "exit_point_type",
        "reported_tier_id",
        "reported_application_component_node_id",
        "association_status",
        "association_basis",
        "verified_tier_id",
        "verified_node_id",
        "properties",
        "endpoint_candidates",
        "relationship_basis",
    },
}
TEMP_PREFIX = ".appdynamics-import-"


class ImportErrorDetail(Exception):
    """A sanitized AppDynamics snapshot validation error."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _read_json(path: Path) -> dict[str, Any]:
    try:
        # Bound the allocation itself; a stat followed by read_bytes is subject
        # to growth between the size check and the read.
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ImportErrorDetail("input_size_limit")
        root = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
    except ImportErrorDetail:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ImportErrorDetail("invalid_json") from exc
    if not isinstance(root, dict):
        raise ImportErrorDetail("invalid_document")
    return root


def _text(value: Any, *, required: bool = True, max_length: int = 2048) -> str | None:
    if value is None or value == "":
        if required:
            raise ImportErrorDetail("invalid_field")
        return None
    if not isinstance(value, str):
        raise ImportErrorDetail("invalid_field")
    if len(value) > max_length or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ImportErrorDetail("invalid_field")
    return value


def _number(value: Any, *, integer: bool = False, minimum: float = 0) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ImportErrorDetail("invalid_number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ImportErrorDetail("invalid_number")
    if (
        value < minimum
        or value > 253_402_300_799
        or isinstance(value, float)
        and not value.is_integer()
        and integer
    ):
        raise ImportErrorDetail("invalid_number")
    return int(value) if integer else float(value)


def _id(value: Any, *, allow_zero: bool = False) -> int:
    result = _number(value, integer=True, minimum=0 if allow_zero else 1)
    if result > 2**53 - 1:
        raise ImportErrorDetail("invalid_identity")
    return int(result)


def _ip(value: Any) -> str:
    address = _text(value, max_length=128)
    assert address is not None
    if "%" in address:
        raise ImportErrorDetail("invalid_address")
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ImportErrorDetail("invalid_address") from exc
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return parsed.compressed.lower()


def _timestamp(value: Any) -> float:
    return float(_number(value))


def _validate_bundle(
    root: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if root.get("schema_version") != SCHEMA_VERSION or root.get("schema") != SCHEMA:
        raise ImportErrorDetail("unsupported_schema")
    authority = _text(root.get("controller_authority"), max_length=255)
    scope = _text(root.get("scope"), max_length=253)
    assert authority is not None and scope is not None
    if not AUTHORITY_RE.fullmatch(authority) or authority != authority.lower():
        raise ImportErrorDetail("invalid_authority")
    if not SCOPE_RE.fullmatch(scope) or re.match(
        r"^(unmapped|unknown|reserved)(:|$)", scope, re.IGNORECASE
    ):
        raise ImportErrorDetail("invalid_scope")
    snapshot_id = _text(root.get("snapshot_id"), max_length=128)
    assert snapshot_id is not None
    try:
        if str(uuid.UUID(snapshot_id)) != snapshot_id:
            raise ValueError
    except ValueError as exc:
        raise ImportErrorDetail("invalid_snapshot_id") from exc
    snapshot_at = _timestamp(root.get("snapshot_at"))
    started = _timestamp(root.get("collection_started_at"))
    completed = _timestamp(root.get("collection_completed_at"))
    skew = _number(root.get("collection_skew_seconds"), minimum=0)
    if (
        completed < started
        or completed != snapshot_at
        or abs(skew - (completed - started)) > 0.01
    ):
        raise ImportErrorDetail("invalid_collection_interval")
    if root.get("snapshot_complete") is not True:
        raise ImportErrorDetail("incomplete_snapshot")
    if root.get("identity_basis") != "controller_application_model_ids":
        raise ImportErrorDetail("invalid_identity_basis")
    source_records = root.get("records")
    if (
        not isinstance(source_records, list)
        or not 1 <= len(source_records) <= MAX_RECORDS
    ):
        raise ImportErrorDetail("record_limit")
    counts = root.get("record_counts")
    if not isinstance(counts, dict) or counts.get("total_records") != len(
        source_records
    ):
        raise ImportErrorDetail("record_count_mismatch")
    for name in (
        "applications",
        "tiers",
        "nodes",
        "backends",
        "total_records",
        "node_ip_addresses",
    ):
        _number(counts.get(name), integer=True, minimum=0)
    records: list[dict[str, Any]] = []
    record_ids: set[str] = set()
    application_ids: set[int] = set()
    tier_keys: set[tuple[int, int]] = set()
    node_tier_refs: list[tuple[int, int]] = []
    child_application_refs: list[int] = []
    node_keys: set[tuple[int, int, int]] = set()
    verified_backend_links: list[tuple[int, int, int]] = []
    type_counts = {name: 0 for name in RECORD_TYPES}
    snapshot_rows = 0
    for row in source_records:
        if not isinstance(row, dict):
            raise ImportErrorDetail("invalid_record")
        if row.get("schema_version") != SCHEMA_VERSION or row.get("schema") != SCHEMA:
            raise ImportErrorDetail("unsupported_schema")
        if row.get("source") != SOURCE or row.get("controller_authority") != authority:
            raise ImportErrorDetail("authority_mismatch")
        if row.get("scope") != scope or row.get("snapshot_id") != snapshot_id:
            raise ImportErrorDetail("snapshot_mismatch")
        if row.get("snapshot_at") != snapshot_at:
            raise ImportErrorDetail("snapshot_mismatch")
        if (
            row.get("collection_started_at") != started
            or row.get("collection_completed_at") != completed
        ):
            raise ImportErrorDetail("snapshot_mismatch")
        if (
            row.get("collection_skew_seconds") != skew
            or row.get("snapshot_complete") is not True
        ):
            raise ImportErrorDetail("snapshot_mismatch")
        if row.get("identity_basis") != "controller_application_model_ids":
            raise ImportErrorDetail("invalid_identity_basis")
        record_type = _text(row.get("record_type"), max_length=32)
        record_id = _text(row.get("record_id"), max_length=512)
        assert record_type is not None and record_id is not None
        if record_type not in RECORD_TYPES or record_id in record_ids:
            raise ImportErrorDetail("duplicate_identity")
        if set(row) != TYPE_FIELDS[record_type]:
            raise ImportErrorDetail("invalid_record_fields")
        record_ids.add(record_id)
        observed_at = _timestamp(row.get("observed_at"))
        if observed_at < started or observed_at > completed:
            raise ImportErrorDetail("invalid_observation_time")
        fingerprint = _text(row.get("record_fingerprint"), max_length=64)
        assert fingerprint is not None
        if not HEX_DIGEST_RE.fullmatch(fingerprint):
            raise ImportErrorDetail("invalid_fingerprint")
        semantic = {
            key: value for key, value in row.items() if key != "record_fingerprint"
        }
        if hashlib.sha256(_canonical(semantic)).hexdigest() != fingerprint:
            raise ImportErrorDetail("fingerprint_mismatch")
        if record_type == "snapshot":
            snapshot_rows += 1
            if record_id != f"snapshot:{snapshot_id}":
                raise ImportErrorDetail("invalid_snapshot_record")
            expected_counts = row.get("record_counts")
            if expected_counts != counts:
                raise ImportErrorDetail("record_count_mismatch")
            if row.get("empty_inventory") is not (counts["applications"] == 0):
                raise ImportErrorDetail("invalid_snapshot_record")
        elif record_type == "application":
            app_id = _id(row.get("application_id"))
            _text(row.get("application_name"))
            if record_id != f"application:{app_id}":
                raise ImportErrorDetail("invalid_identity")
            application_ids.add(app_id)
        elif record_type == "tier":
            app_id = _id(row.get("application_id"))
            tier_id = _id(row.get("tier_id"))
            _text(row.get("application_name"))
            _text(row.get("tier_name"))
            if record_id != f"application:{app_id}:tier:{tier_id}":
                raise ImportErrorDetail("invalid_identity")
            child_application_refs.append(app_id)
            tier_keys.add((app_id, tier_id))
        elif record_type == "node":
            app_id = _id(row.get("application_id"))
            tier_id = _id(row.get("tier_id"))
            node_id = _id(row.get("node_id"))
            _text(row.get("application_name"))
            _text(row.get("tier_name"))
            _text(row.get("node_name"))
            if record_id != f"application:{app_id}:tier:{tier_id}:node:{node_id}":
                raise ImportErrorDetail("invalid_identity")
            if (app_id, tier_id, node_id) in node_keys:
                raise ImportErrorDetail("duplicate_identity")
            node_keys.add((app_id, tier_id, node_id))
            child_application_refs.append(app_id)
            node_tier_refs.append((app_id, tier_id))
            ip_values = row.get("ip_addresses")
            if not isinstance(ip_values, list) or len(ip_values) > 64:
                raise ImportErrorDetail("invalid_addresses")
            seen_ips: set[str] = set()
            for address in ip_values:
                if not isinstance(address, dict) or not isinstance(
                    address.get("matchable"), bool
                ):
                    raise ImportErrorDetail("invalid_addresses")
                reported = _text(address.get("reported"), max_length=128)
                assert reported is not None
                if address["matchable"]:
                    normalized = _ip(address.get("ip"))
                    if normalized in seen_ips:
                        continue
                    seen_ips.add(normalized)
                elif (
                    address.get("status") != "zone_scoped_address_unmatchable"
                    or "%" not in reported
                    or "ip" in address
                ):
                    raise ImportErrorDetail("invalid_addresses")
            if row.get("relationship_basis") != "application_model_tier_nodes_endpoint":
                raise ImportErrorDetail("invalid_relationship_basis")
        elif record_type == "backend":
            app_id = _id(row.get("application_id"))
            backend_id = _id(row.get("backend_id"))
            _text(row.get("application_name"))
            _text(row.get("backend_name"))
            if record_id != f"application:{app_id}:backend:{backend_id}":
                raise ImportErrorDetail("invalid_identity")
            reported_tier = row.get("reported_tier_id")
            reported_node = row.get("reported_application_component_node_id")
            if reported_tier is not None:
                _id(reported_tier, allow_zero=True)
            if reported_node is not None:
                _id(reported_node, allow_zero=True)
            association = row.get("association_status")
            basis = row.get("association_basis")
            if association == "verified_node":
                tier_id = _id(row.get("verified_tier_id"))
                node_id = _id(row.get("verified_node_id"))
                if (
                    reported_tier != tier_id
                    or reported_node != node_id
                    or basis != "same_snapshot_application_tier_node_id_match"
                ):
                    raise ImportErrorDetail("invalid_backend_association")
                verified_backend_links.append((app_id, tier_id, node_id))
            elif association in {"application_scope_only", "unverified_reported_ids"}:
                if (
                    row.get("verified_tier_id") is not None
                    or row.get("verified_node_id") is not None
                ):
                    raise ImportErrorDetail("invalid_backend_association")
                if basis != "application_model_backend_record_only":
                    raise ImportErrorDetail("invalid_backend_association")
                if association == "application_scope_only" and (
                    (reported_tier or 0) > 0 or (reported_node or 0) > 0
                ):
                    raise ImportErrorDetail("invalid_backend_association")
                if (
                    association == "unverified_reported_ids"
                    and (reported_tier or 0) <= 0
                    and (reported_node or 0) <= 0
                ):
                    raise ImportErrorDetail("invalid_backend_association")
            else:
                raise ImportErrorDetail("invalid_backend_association")
            child_application_refs.append(app_id)
            _text(row.get("relationship_basis"), max_length=128)
            properties = row.get("properties")
            if not isinstance(properties, list) or len(properties) > 200:
                raise ImportErrorDetail("invalid_properties")
            for prop in properties:
                if not isinstance(prop, dict):
                    raise ImportErrorDetail("invalid_properties")
                name = _text(prop.get("name"), max_length=128)
                value = _text(prop.get("value"), required=False, max_length=2048)
                redacted = prop.get("redacted")
                if not isinstance(redacted, bool):
                    raise ImportErrorDetail("invalid_properties")
                if SECRET_PROPERTY_RE.search(name or "") and (
                    not redacted or value is not None
                ):
                    raise ImportErrorDetail("sensitive_property")
            candidates = row.get("endpoint_candidates")
            if not isinstance(candidates, list) or len(candidates) > 200:
                raise ImportErrorDetail("invalid_endpoint_candidates")
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    raise ImportErrorDetail("invalid_endpoint_candidates")
                kind = candidate.get("kind")
                if kind == "ip":
                    _ip(candidate.get("value"))
                elif kind == "hostname_unresolved":
                    _text(candidate.get("value"), max_length=255)
                elif kind == "port":
                    port = _number(candidate.get("value"), integer=True, minimum=1)
                    if port > 65_535:
                        raise ImportErrorDetail("invalid_endpoint_candidates")
                else:
                    raise ImportErrorDetail("invalid_endpoint_candidates")
                if "port" in candidate:
                    port = _number(candidate["port"], integer=True, minimum=1)
                    if port > 65_535:
                        raise ImportErrorDetail("invalid_endpoint_candidates")
        type_counts[record_type] += 1
        records.append(row)
    if snapshot_rows != 1 or not records or records[0].get("record_type") != "snapshot":
        raise ImportErrorDetail("snapshot_record_missing")
    if any(link not in node_keys for link in verified_backend_links):
        raise ImportErrorDetail("invalid_backend_association")
    if any(app_id not in application_ids for app_id in child_application_refs):
        raise ImportErrorDetail("application_identity_missing")
    if any(tier_key not in tier_keys for tier_key in node_tier_refs):
        raise ImportErrorDetail("tier_identity_missing")
    if type_counts["application"] != counts.get("applications"):
        raise ImportErrorDetail("record_count_mismatch")
    if type_counts["tier"] != counts.get("tiers"):
        raise ImportErrorDetail("record_count_mismatch")
    if type_counts["node"] != counts.get("nodes"):
        raise ImportErrorDetail("record_count_mismatch")
    if type_counts["backend"] != counts.get("backends"):
        raise ImportErrorDetail("record_count_mismatch")
    if counts.get("node_ip_addresses") != sum(
        1
        for row in records
        if row.get("record_type") == "node"
        for address in row.get("ip_addresses", [])
        if address.get("matchable") is True
    ):
        raise ImportErrorDetail("record_count_mismatch")
    return records, root


def render_appdynamics_ndjson(records: list[dict[str, Any]]) -> str:
    lines = []
    for event in records:
        line = _canonical(
            {
                "time": event["snapshot_at"],
                "source": SOURCE,
                "sourcetype": SOURCETYPE,
                "event": event,
            }
        )
        if len(line) > MAX_HEC_LINE_BYTES:
            raise ImportErrorDetail("record_size_limit")
        lines.append(line.decode("utf-8"))
    rendered = "\n".join(lines) + "\n"
    if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ImportErrorDetail("output_size_limit")
    return rendered


def _validate_asset_history_manifest(
    manifest: Any, records: list[dict[str, Any]], root: dict[str, Any]
) -> None:
    expected_records: list[dict[str, Any]] = []
    authority = root["controller_authority"]
    snapshot_id = root["snapshot_id"]
    scope = root["scope"]
    for node in records:
        if node.get("record_type") != "node":
            continue
        app_id = node["application_id"]
        tier_id = node["tier_id"]
        node_id = node["node_id"]
        asset_id = (
            f"appd:{authority}:application:{app_id}:tier:{tier_id}:node:{node_id}"
        )
        service_id = f"appd:{authority}:application:{app_id}:tier:{tier_id}"
        service_name = f"{node['application_name']} / {node['tier_name']}"
        addresses = sorted(
            {
                _ip(address["ip"])
                for address in node["ip_addresses"]
                if address.get("matchable") is True
            }
        )
        for address in addresses:
            expected_records.append(
                {
                    "record_id": (
                        f"{snapshot_id}:application:{app_id}:tier:{tier_id}:"
                        f"node:{node_id}:ip:{address}"
                    ),
                    "revision": 0,
                    "asset_id": asset_id,
                    "asset_name": node["node_name"],
                    "service_id": service_id,
                    "service_name": service_name,
                    "scope": scope,
                    "ip": address,
                    "validity_basis": "snapshot_current",
                }
            )
    expected = {
        "schema_version": 1,
        "authority": authority,
        "snapshot_id": snapshot_id,
        "snapshot_at": root["snapshot_at"],
        "snapshot_complete": True,
        "records": expected_records,
    }
    if not isinstance(manifest, dict) or _canonical(manifest) != _canonical(expected):
        raise ImportErrorDetail("asset_history_manifest_mismatch")


def _asset_history_output(manifest: dict[str, Any]) -> tuple[str, int, int]:
    if not isinstance(manifest, dict):
        raise ImportErrorDetail("asset_history_manifest_missing")
    try:
        with tempfile.TemporaryDirectory(prefix="atlas-appdynamics-") as name:
            directory = Path(name)
            os.chmod(directory, 0o700)
            input_path = directory / "asset-history.json"
            fd = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(_canonical(manifest))
            rows, normalized_manifest, input_count, _duplicates = prepare(input_path)
            if normalized_manifest["authority"] != manifest.get("authority"):
                raise ImportErrorDetail("asset_history_authority_mismatch")
            _conflicts, conflict_count = find_conflicts(rows)
            text = render_asset_history_ndjson(rows)
            if any(
                len(line.encode("utf-8")) > MAX_HEC_LINE_BYTES
                for line in text.split("\n")
                if line
            ):
                raise ImportErrorDetail("record_size_limit")
            if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
                raise ImportErrorDetail("asset_history_output_size_limit")
            return text, conflict_count, len(rows)
    except BatchImportError as exc:
        raise ImportErrorDetail("asset_history_validation_failed") from exc
    except ImportErrorDetail:
        raise
    except OSError as exc:
        raise ImportErrorDetail("asset_history_validation_failed") from exc


def _outside_repository(path: Path) -> Path:
    resolved = path.resolve()
    if any(
        (parent / ".git").exists() or (parent / ".git").is_symlink()
        for parent in (resolved, *resolved.parents)
    ):
        raise ImportErrorDetail("output_must_be_outside_repository")
    return resolved


def _write_many(files: dict[Path, bytes]) -> None:
    if not files or len(set(files)) != len(files):
        raise ImportErrorDetail("invalid_output_paths")
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise ImportErrorDetail("output_exists")
    staged: dict[Path, Path] = {}
    linked: list[Path] = []
    try:
        for path, payload in files.items():
            fd, temp_name = tempfile.mkstemp(prefix=TEMP_PREFIX, dir=path.parent)
            temp_path = Path(temp_name)
            os.chmod(temp_path, 0o600)
            staged[path] = temp_path
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        for target, temp_path in staged.items():
            os.link(temp_path, target)
            linked.append(target)
    except (FileExistsError, OSError) as exc:
        for target in linked:
            try:
                target.unlink()
            except OSError:
                pass
        raise ImportErrorDetail("output_write_failed") from exc
    finally:
        for temp_path in staged.values():
            try:
                temp_path.unlink()
            except OSError:
                pass


def convert_snapshot(path: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    root = _read_json(path)
    records, validated = _validate_bundle(root)
    _validate_asset_history_manifest(
        validated.get("asset_history_manifest"), records, validated
    )
    appd_text = render_appdynamics_ndjson(records)
    asset_text, conflict_count, asset_count = _asset_history_output(
        validated.get("asset_history_manifest")
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "schema": SCHEMA,
        "controller_authority": validated["controller_authority"],
        "scope": validated["scope"],
        "snapshot_id": validated["snapshot_id"],
        "snapshot_complete": True,
        "collection_skew_seconds": validated["collection_skew_seconds"],
        "appdynamics_records": len(records),
        "asset_history_records": asset_count,
        "asset_history_conflict_count": conflict_count,
        "accepted": True,
    }
    payloads = {
        "appdynamics.ndjson": appd_text.encode(),
        "asset_history.ndjson": asset_text.encode(),
    }
    return payloads, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="AppDynamics snapshot bundle JSON")
    parser.add_argument(
        "--appd-output", type=Path, required=True, help="AppDynamics HEC NDJSON output"
    )
    parser.add_argument(
        "--asset-history-output",
        type=Path,
        required=True,
        help="Asset-history HEC NDJSON output",
    )
    parser.add_argument(
        "--report", type=Path, help="Sanitized validation report output"
    )
    args = parser.parse_args(argv)
    try:
        appd_path = _outside_repository(args.appd_output)
        asset_path = _outside_repository(args.asset_history_output)
        report_path = _outside_repository(
            args.report
            or args.appd_output.with_suffix(args.appd_output.suffix + ".report.json")
        )
        if len({appd_path, asset_path, report_path}) != 3:
            raise ImportErrorDetail("invalid_output_paths")
        payloads, report = convert_snapshot(args.snapshot)
        report_bytes = _canonical(report) + b"\n"
        if len(report_bytes) > MAX_REPORT_BYTES:
            raise ImportErrorDetail("report_size_limit")
        _write_many(
            {
                appd_path: payloads["appdynamics.ndjson"],
                asset_path: payloads["asset_history.ndjson"],
                report_path: report_bytes,
            }
        )
        print(
            json.dumps(
                {
                    "status": "validated",
                    "snapshot_id": report["snapshot_id"],
                    "appdynamics_records": report["appdynamics_records"],
                    "asset_history_records": report["asset_history_records"],
                    "asset_history_conflict_count": report[
                        "asset_history_conflict_count"
                    ],
                },
                sort_keys=True,
            )
        )
        return 0
    except ImportErrorDetail as exc:
        print(json.dumps({"status": "failed", "error": exc.code}), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"status": "failed", "error": "io_error"}), file=sys.stderr)
        return 2
    except Exception:
        print(
            json.dumps({"status": "failed", "error": "import_failed"}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
