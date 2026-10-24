#!/usr/bin/env python3
"""Validate asset history exports and render deterministic Splunk HEC NDJSON.

This utility only reads local CSV/JSON and writes local output/report files. It
does not connect to a CMDB, IPAM system, or Splunk deployment.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import re
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
SOURCETYPE = "adm:asset_history"
MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_RECORDS = 50_000
MAX_REPORT_CONFLICTS = 500
MAX_TEXT = 512
MAX_EPOCH = 253_402_300_799
AUTHORITY_RE = re.compile(r"^[a-z0-9][a-z0-9._:/@-]{0,254}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$")
VALIDITY_BASES = {"source_interval", "snapshot_current"}
JSON_ROOT_KEYS = {
    "schema_version",
    "authority",
    "snapshot_id",
    "snapshot_at",
    "snapshot_complete",
    "records",
}
JSON_RECORD_KEYS = {
    "record_id",
    "revision",
    "asset_id",
    "asset_name",
    "service_id",
    "service_name",
    "environment",
    "owner_id",
    "owner_name",
    "network_id",
    "scope",
    "ip",
    "validity_basis",
    "valid_from",
    "valid_to",
    "retired_at",
}
CSV_COLUMNS = {
    "schema_version",
    "authority",
    "snapshot_id",
    "snapshot_at",
    "snapshot_complete",
    *JSON_RECORD_KEYS,
}


class ImportErrorDetail(Exception):
    """A user-correctable input error with stable machine-readable metadata."""

    def __init__(self, code: str, message: str, row: int | None = None):
        super().__init__(message)
        self.code = code
        self.row = row


def _fail(code: str, message: str) -> None:
    raise ImportErrorDetail(code, message)


def _text(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None or value == "":
        if required:
            _fail("missing_field", f"{field} is required.")
        return None
    if not isinstance(value, str):
        _fail("invalid_field", f"{field} must be text.")
    value = value.strip()
    if not value:
        if required:
            _fail("missing_field", f"{field} is required.")
        return None
    if len(value) > MAX_TEXT or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        _fail("invalid_field", f"{field} is too long or contains control characters.")
    return value


def _timestamp(value: Any, field: str, *, required: bool = False) -> float | None:
    if value is None or value == "":
        if required:
            _fail("missing_time", f"{field} is required.")
        return None
    if isinstance(value, bool):
        _fail(
            "invalid_time",
            f"{field} must be an epoch number or timezone-aware ISO-8601 timestamp.",
        )
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            if required:
                _fail("missing_time", f"{field} is required.")
            return None
        try:
            if re.fullmatch(r"\d+(?:\.\d+)?", text_value):
                result = float(text_value)
            else:
                parsed = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    _fail("invalid_time", f"{field} must include a UTC offset or Z.")
                result = parsed.astimezone(timezone.utc).timestamp()
        except ValueError:
            _fail(
                "invalid_time",
                f"{field} must be an epoch number or timezone-aware ISO-8601 timestamp.",
            )
    else:
        _fail(
            "invalid_time",
            f"{field} must be an epoch number or timezone-aware ISO-8601 timestamp.",
        )
    if not math.isfinite(result) or result < 0 or result > MAX_EPOCH:
        _fail("invalid_time", f"{field} is outside the supported timestamp range.")
    return int(result) if result.is_integer() else result


def _ip(value: Any) -> str:
    text_value = _text(value, "ip", required=True)
    if "%" in text_value:
        _fail("invalid_ip", "ip must not include an IPv6 zone identifier.")
    try:
        parsed = ipaddress.ip_address(text_value)
    except ValueError:
        _fail("invalid_ip", "ip must be one literal IPv4 or IPv6 address.")
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return parsed.compressed.lower()


def _bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    _fail("invalid_boolean", f"{field} must be true or false.")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_json(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        root = json.loads(
            path.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ImportErrorDetail(
            "invalid_json", f"Could not read JSON input: {exc}"
        ) from exc
    if not isinstance(root, dict):
        _fail("invalid_document", "JSON input must be a manifest object.")
    unknown = sorted(set(root) - JSON_ROOT_KEYS)
    missing = sorted(
        {
            "schema_version",
            "authority",
            "snapshot_id",
            "snapshot_at",
            "snapshot_complete",
            "records",
        }
        - set(root)
    )
    if unknown or missing:
        _fail(
            "invalid_document",
            f"JSON manifest fields are invalid (unknown={unknown}, missing={missing}).",
        )
    if not isinstance(root["records"], list):
        _fail("invalid_document", "records must be an array.")
    if len(root["records"]) > MAX_RECORDS:
        _fail("record_limit", f"Input exceeds the {MAX_RECORDS:,}-record import limit.")
    if any(not isinstance(row, dict) for row in root["records"]):
        _fail("invalid_record", "Every records item must be an object.")
    for row in root["records"]:
        unknown_row = sorted(set(row) - JSON_RECORD_KEYS)
        if unknown_row:
            _fail("invalid_record", f"Unknown record fields: {unknown_row}.")
    return root, root["records"]


def read_csv(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames is None:
                _fail("invalid_csv", "CSV input must include a header row.")
            headers = [name.strip() if name else "" for name in reader.fieldnames]
            if len(headers) != len(set(headers)):
                _fail("invalid_csv", "CSV contains duplicate column names.")
            unknown = sorted(set(headers) - CSV_COLUMNS)
            missing = sorted(
                CSV_COLUMNS
                - {
                    "service_id",
                    "service_name",
                    "environment",
                    "owner_id",
                    "owner_name",
                    "network_id",
                    "valid_to",
                    "retired_at",
                    "revision",
                    "valid_from",
                }
                - set(headers)
            )
            if unknown or missing:
                _fail(
                    "invalid_csv",
                    f"CSV columns are invalid (unknown={unknown}, missing={missing}).",
                )
            records: list[dict[str, Any]] = []
            metadata: dict[str, Any] | None = None
            for line, raw in enumerate(reader, start=2):
                if len(records) >= MAX_RECORDS:
                    _fail(
                        "record_limit",
                        f"Input exceeds the {MAX_RECORDS:,}-record import limit.",
                    )
                if None in raw:
                    raise ImportErrorDetail(
                        "invalid_csv", "CSV row has more values than the header.", line
                    )
                row = {
                    key.strip(): value for key, value in raw.items() if key is not None
                }
                row_meta = {
                    "schema_version": row.get("schema_version", ""),
                    "authority": row.get("authority", ""),
                    "snapshot_id": row.get("snapshot_id", ""),
                    "snapshot_at": row.get("snapshot_at", ""),
                    "snapshot_complete": row.get("snapshot_complete", ""),
                }
                if metadata is None:
                    metadata = row_meta
                elif row_meta != metadata:
                    raise ImportErrorDetail(
                        "inconsistent_manifest",
                        "Manifest columns must have the same values on every CSV row.",
                        line,
                    )
                records.append({key: row.get(key, "") for key in JSON_RECORD_KEYS})
    except ImportErrorDetail:
        raise
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ImportErrorDetail(
            "invalid_csv", f"Could not read CSV input: {exc}"
        ) from exc
    if metadata is None:
        _fail(
            "empty_csv", "CSV input has no data rows from which to read the manifest."
        )
    return metadata, records


def normalize_manifest(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schema_version") not in (SCHEMA_VERSION, str(SCHEMA_VERSION)):
        _fail(
            "unsupported_schema", f"Only schema_version {SCHEMA_VERSION} is supported."
        )
    authority = _text(raw.get("authority"), "authority", required=True)
    assert authority is not None
    authority = authority.lower()
    if not AUTHORITY_RE.fullmatch(authority):
        _fail(
            "invalid_authority",
            "authority must be a lowercase literal identifier usable in the shared asset_authority mapping.",
        )
    snapshot_id = _text(raw.get("snapshot_id"), "snapshot_id", required=True)
    assert snapshot_id is not None
    snapshot_at = _timestamp(raw.get("snapshot_at"), "snapshot_at", required=True)
    complete = _bool(raw.get("snapshot_complete"), "snapshot_complete")
    return {
        "authority": authority,
        "snapshot_id": snapshot_id,
        "snapshot_at": snapshot_at,
        "snapshot_complete": complete,
    }


def normalize_record(
    raw: dict[str, Any], manifest: dict[str, Any], row_number: int
) -> dict[str, Any]:
    try:
        record_id = _text(raw.get("record_id"), "record_id", required=True)
        assert record_id is not None
        revision_raw = raw.get("revision", 0)
        if revision_raw in (None, ""):
            revision_raw = 0
        if isinstance(revision_raw, bool) or not str(revision_raw).isdigit():
            _fail("invalid_revision", "revision must be a nonnegative integer.")
        revision = int(revision_raw)
        if revision > 2**53 - 1:
            _fail("invalid_revision", "revision exceeds the safe integer range.")
        asset_id = _text(raw.get("asset_id"), "asset_id", required=True)
        assert asset_id is not None
        asset_name = _text(raw.get("asset_name"), "asset_name")
        service_id = _text(raw.get("service_id"), "service_id")
        service_name = _text(raw.get("service_name"), "service_name")
        environment = _text(raw.get("environment"), "environment")
        owner_id = _text(raw.get("owner_id"), "owner_id")
        owner_name = _text(raw.get("owner_name"), "owner_name")
        network_id = _text(raw.get("network_id"), "network_id")
        if service_name and not service_id:
            _fail("service_identity", "service_name requires a stable service_id.")
        if owner_name and not owner_id:
            _fail("owner_identity", "owner_name requires a stable owner_id.")
        scope = _text(raw.get("scope"), "scope", required=True)
        assert scope is not None
        if not SCOPE_RE.fullmatch(scope) or re.match(
            r"^(unmapped|unknown|reserved)(:|$)", scope, re.I
        ):
            _fail(
                "invalid_scope",
                "scope must be a verified, non-reserved routing-scope literal.",
            )
        address = _ip(raw.get("ip"))
        basis = _text(raw.get("validity_basis"), "validity_basis", required=True)
        assert basis is not None
        if basis not in VALIDITY_BASES:
            _fail(
                "invalid_validity_basis",
                "validity_basis must be source_interval or snapshot_current.",
            )
        valid_from = _timestamp(raw.get("valid_from"), "valid_from")
        valid_to = _timestamp(raw.get("valid_to"), "valid_to")
        retired_at = _timestamp(raw.get("retired_at"), "retired_at")
        if basis == "source_interval":
            if valid_from is None:
                _fail(
                    "missing_valid_from", "source_interval records require valid_from."
                )
            if valid_from > manifest["snapshot_at"]:
                _fail(
                    "future_valid_from",
                    "valid_from cannot be later than snapshot_at for an observed interval.",
                )
            if valid_to is not None and valid_to <= valid_from:
                _fail(
                    "invalid_interval",
                    "valid_to must be greater than valid_from; intervals are [from,to).",
                )
            if retired_at is not None and valid_to != retired_at:
                _fail(
                    "invalid_retirement",
                    "retired_at must equal the explicit exclusive valid_to.",
                )
        else:
            if valid_from is not None or valid_to is not None or retired_at is not None:
                _fail(
                    "snapshot_interval",
                    "snapshot_current records cannot claim historical valid_from, valid_to or retirement.",
                )
            valid_from = manifest["snapshot_at"]
        normalized = {
            "record_id": record_id,
            "revision": revision,
            "asset_id": asset_id,
            "asset_name": asset_name,
            "service_id": service_id,
            "service_name": service_name,
            "environment": environment,
            "owner_id": owner_id,
            "owner_name": owner_name,
            "network_id": network_id,
            "scope": scope,
            "ip": address,
            "validity_basis": basis,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "retired_at": retired_at,
        }
        event = {
            "schema_version": SCHEMA_VERSION,
            "source": "asset_history",
            "asset_authority": manifest["authority"],
            "snapshot_id": manifest["snapshot_id"],
            "snapshot_at": manifest["snapshot_at"],
            "snapshot_complete": manifest["snapshot_complete"],
            **{key: value for key, value in normalized.items() if value is not None},
        }
        digest = hashlib.sha256(_canonical_json(event)).hexdigest()
        event["record_fingerprint"] = digest
        return {"row": row_number, "event": event}
    except ImportErrorDetail as exc:
        if exc.row is None:
            exc.row = row_number
        raise


def _interval(row: dict[str, Any]) -> tuple[float, float]:
    event = row["event"]
    start = float(event["valid_from"])
    if event["validity_basis"] == "snapshot_current":
        return start, start
    end = event.get("valid_to")
    observed_end = event["snapshot_at"] if end is None else end
    return start, max(start, float(observed_end))


def find_conflicts(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Find conflicts in latest revisions while retaining tied variants."""
    latest: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        event = row["event"]
        key = (event["asset_authority"], event["record_id"])
        current = latest.get(key, [])
        current_revision = current[0]["event"]["revision"] if current else -1
        if event["revision"] > current_revision:
            latest[key] = [row]
        elif event["revision"] == current_revision:
            current.append(row)
            latest[key] = current
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    conflicts: list[dict[str, Any]] = []
    total = 0
    current_rows: list[dict[str, Any]] = []
    semantic_fields = (
        "asset_id",
        "asset_name",
        "service_id",
        "service_name",
        "environment",
        "owner_id",
        "owner_name",
        "network_id",
        "scope",
        "ip",
        "validity_basis",
        "valid_from",
        "valid_to",
        "retired_at",
    )
    for (authority, record_id), candidates in sorted(latest.items()):
        semantics = {
            _canonical_json(
                {field: candidate["event"].get(field) for field in semantic_fields}
            )
            for candidate in candidates
        }
        if len(semantics) > 1:
            total += 1
            if len(conflicts) < MAX_REPORT_CONFLICTS:
                variants_by_semantic = {
                    _canonical_json(
                        {field: item["event"].get(field) for field in semantic_fields}
                    ): {field: item["event"].get(field) for field in semantic_fields}
                    for item in candidates
                }
                variants = [
                    variants_by_semantic[key] for key in sorted(variants_by_semantic)
                ]
                conflicts.append(
                    {
                        "kind": "same_revision_disagreement",
                        "authority": authority,
                        "record_id": record_id,
                        "revision": candidates[0]["event"]["revision"],
                        "candidate_count": len(variants),
                        "candidates": variants[:20],
                        "candidates_capped": len(variants) > 20,
                    }
                )
            continue
        current_rows.append(candidates[0])
    for row in current_rows:
        event = row["event"]
        groups[(event["scope"], event["ip"])].append(row)
    for (scope, address), group in sorted(groups.items()):
        Signature = tuple[str, str, str, str, str]
        changes: dict[float, dict[str, list[Signature]]] = defaultdict(
            lambda: {"start": [], "end": []}
        )
        points: dict[float, list[Signature]] = defaultdict(list)
        for row in group:
            event = row["event"]
            signature = (
                event["asset_id"],
                event.get("owner_id", ""),
                event.get("environment", ""),
                event.get("network_id", ""),
                event.get("service_id", ""),
            )
            start, end = _interval(row)
            if event["validity_basis"] == "snapshot_current":
                points[start].append(signature)
            else:
                if end <= start:
                    continue
                changes[start]["start"].append(signature)
                if math.isfinite(end):
                    changes[end]["end"].append(signature)
        times = sorted(set(changes) | set(points))
        active: dict[Signature, int] = defaultdict(int)
        asset_counts: dict[str, int] = defaultdict(int)
        context_counts: dict[tuple[str, int, str], int] = defaultdict(int)
        context_values: dict[tuple[str, int], int] = defaultdict(int)
        context_conflicts = 0
        previous: float | None = None

        def change(signature: Signature, amount: int) -> None:
            nonlocal context_conflicts
            asset_id = signature[0]
            asset_counts[asset_id] += amount
            if asset_counts[asset_id] <= 0:
                asset_counts.pop(asset_id, None)
            for field_position in range(1, len(signature)):
                value = signature[field_position]
                if not value:
                    continue
                key = (asset_id, field_position, value)
                group_key = (asset_id, field_position)
                before_count = context_counts[key]
                after_count = before_count + amount
                if before_count == 0 and after_count > 0:
                    before_values = context_values[group_key]
                    context_counts[key] = after_count
                    context_values[group_key] += 1
                    if before_values == 1:
                        context_conflicts += 1
                elif before_count > 0 and after_count <= 0:
                    before_values = context_values[group_key]
                    context_counts.pop(key, None)
                    context_values[group_key] -= 1
                    if context_values[group_key] <= 0:
                        context_values.pop(group_key, None)
                    elif before_values == 2:
                        context_conflicts -= 1
                else:
                    context_counts[key] = after_count
            active[signature] += amount
            if active[signature] <= 0:
                active.pop(signature, None)

        def add_conflict(start: float, end: float | None) -> None:
            nonlocal total
            if len(asset_counts) < 2 and context_conflicts == 0:
                return
            total += 1
            if len(conflicts) >= MAX_REPORT_CONFLICTS:
                return
            context_disagreements = []
            for (asset_id, field_position, value), count in context_counts.items():
                if count > 0 and context_values[(asset_id, field_position)] > 1:
                    context_disagreements.append((asset_id, field_position, value))
            field_names = {
                1: "owner_id",
                2: "environment",
                3: "network_id",
                4: "service_id",
            }
            conflicts.append(
                {
                    "kind": "overlapping_asset_or_context_claims",
                    "scope": scope,
                    "ip": address,
                    "from": start,
                    "to": end,
                    "asset_ids": sorted(asset_counts)[:20],
                    "asset_ids_capped": len(asset_counts) > 20,
                    "context_conflicts": [
                        {
                            "asset_id": asset_id,
                            "field": field_names[position],
                            "values": sorted(
                                value
                                for (
                                    candidate,
                                    field,
                                    value,
                                ), count in context_counts.items()
                                if candidate == asset_id
                                and field == position
                                and count > 0
                            )[:20],
                        }
                        for asset_id, position in sorted(
                            {
                                (asset_id, position)
                                for asset_id, position, _ in context_disagreements
                            }
                        )
                    ],
                }
            )

        for timestamp in times:
            if previous is not None and timestamp > previous:
                add_conflict(previous, timestamp)
            for signature in changes[timestamp]["end"]:
                change(signature, -1)
            for signature in changes[timestamp]["start"]:
                change(signature, 1)
            for signature in points.get(timestamp, []):
                change(signature, 1)
            if points.get(timestamp):
                add_conflict(timestamp, timestamp)
                for signature in points[timestamp]:
                    change(signature, -1)
            previous = timestamp
        if previous is not None:
            add_conflict(previous, None)
    return conflicts, total


def prepare(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], int, int]:
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        _fail(
            "input_size",
            f"Input exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit.",
        )
    if path.suffix.lower() == ".json":
        raw_manifest, raw_records = read_json(path)
    elif path.suffix.lower() == ".csv":
        raw_manifest, raw_records = read_csv(path)
    else:
        _fail("input_format", "Input filename must end in .json or .csv.")
    manifest = normalize_manifest(raw_manifest)
    errors: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    record_ids: dict[str, bytes] = {}
    duplicate_count = 0
    for row_number, raw in enumerate(raw_records, start=1):
        try:
            normalized = normalize_record(raw, manifest, row_number)
            event = normalized["event"]
            key = f"{event['record_id']}@{event['revision']}"
            semantic = _canonical_json(
                {
                    key: value
                    for key, value in event.items()
                    if key
                    not in {
                        "snapshot_id",
                        "snapshot_at",
                        "snapshot_complete",
                        "record_fingerprint",
                    }
                }
            )
            if key in record_ids:
                if record_ids[key] == semantic:
                    duplicate_count += 1
                    continue
                raise ImportErrorDetail(
                    "duplicate_record_revision",
                    "A record_id and revision pair has conflicting contents.",
                    row_number,
                )
            record_ids[key] = semantic
            accepted.append(normalized)
        except ImportErrorDetail as exc:
            errors.append(
                {"row": exc.row or row_number, "code": exc.code, "message": str(exc)}
            )
    if errors:
        raise BatchImportError(manifest, len(raw_records), len(accepted), errors)
    accepted.sort(
        key=lambda item: (
            item["event"]["asset_authority"],
            item["event"]["scope"],
            item["event"]["ip"],
            item["event"]["asset_id"],
            item["event"]["valid_from"],
            item["event"]["record_id"],
            item["event"]["revision"],
        )
    )
    return accepted, manifest, len(raw_records), duplicate_count


class BatchImportError(ImportErrorDetail):
    def __init__(
        self,
        manifest: dict[str, Any],
        input_count: int,
        accepted: int,
        errors: list[dict[str, Any]],
    ):
        super().__init__(
            "validation_failed", f"{len(errors)} input record(s) failed validation."
        )
        self.manifest = manifest
        self.input_count = input_count
        self.accepted = accepted
        self.errors = errors


def render_ndjson(rows: list[dict[str, Any]]) -> str:
    lines = []
    for item in rows:
        event = item["event"]
        body = {
            "time": event["valid_from"],
            "source": "asset_history",
            "sourcetype": SOURCETYPE,
            "event": event,
        }
        lines.append(_canonical_json(body).decode("utf-8"))
    return "\n".join(lines) + ("\n" if lines else "")


def _atomic_write(path: Path, text: str, *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(
            f"Refusing to overwrite {path}; pass --overwrite to replace it."
        )
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temp_name, path)
        else:
            try:
                os.link(temp_name, path)
            except FileExistsError:
                raise FileExistsError(
                    f"Refusing to overwrite {path}; pass --overwrite to replace it."
                ) from None
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input", type=Path, help="Version 1 JSON manifest or CSV export"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Output HEC NDJSON file"
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Validation report JSON path (default: OUTPUT.report.json)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing output and report files",
    )
    parser.add_argument(
        "--fail-on-conflict",
        action="store_true",
        help="Return status 2 if overlapping owners are found",
    )
    args = parser.parse_args(argv)
    report_path = args.report or args.output.with_suffix(
        args.output.suffix + ".report.json"
    )
    try:
        rows, manifest, input_count, duplicate_count = prepare(args.input)
        conflicts, conflict_count = find_conflicts(rows)
        report = {
            "schema_version": SCHEMA_VERSION,
            "manifest": manifest,
            "input_records": input_count,
            "accepted_records": len(rows),
            "rejected_records": 0,
            "duplicate_records": duplicate_count,
            "conflict_count": conflict_count,
            "conflicts": conflicts,
            "conflicts_capped": conflict_count > len(conflicts),
            "errors": [],
        }
        if args.fail_on_conflict and conflict_count:
            _atomic_write(
                report_path,
                json.dumps(report, sort_keys=True, indent=2) + "\n",
                overwrite=args.overwrite,
            )
            print(
                f"Found {conflict_count} overlapping owner conflict(s); NDJSON was not written.",
                file=sys.stderr,
            )
            return 2
        _atomic_write(args.output, render_ndjson(rows), overwrite=args.overwrite)
        _atomic_write(
            report_path,
            json.dumps(report, sort_keys=True, indent=2) + "\n",
            overwrite=args.overwrite,
        )
        print(
            f"Wrote {len(rows)} records; {conflict_count} overlap conflict(s) reported."
        )
        return 0
    except BatchImportError as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "manifest": exc.manifest,
            "input_records": exc.input_count,
            "accepted_records": exc.accepted,
            "rejected_records": len(exc.errors),
            "conflict_count": 0,
            "conflicts": [],
            "conflicts_capped": False,
            "errors": exc.errors,
        }
        try:
            _atomic_write(
                report_path,
                json.dumps(report, sort_keys=True, indent=2) + "\n",
                overwrite=args.overwrite,
            )
        except OSError as write_error:
            print(
                f"Validation failed and report could not be written: {write_error}",
                file=sys.stderr,
            )
        print(str(exc), file=sys.stderr)
        return 1
    except (ImportErrorDetail, OSError, FileExistsError) as exc:
        error = {
            "row": getattr(exc, "row", None),
            "code": getattr(exc, "code", "io_error"),
            "message": str(exc),
        }
        report = {
            "schema_version": SCHEMA_VERSION,
            "input_records": 0,
            "accepted_records": 0,
            "rejected_records": 1,
            "conflict_count": 0,
            "conflicts": [],
            "conflicts_capped": False,
            "errors": [error],
        }
        try:
            _atomic_write(
                report_path,
                json.dumps(report, sort_keys=True, indent=2) + "\n",
                overwrite=args.overwrite,
            )
        except OSError as write_error:
            print(
                f"Input failed and report could not be written: {write_error}",
                file=sys.stderr,
            )
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
