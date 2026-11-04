"""Pure integrity checks for quarantined TA-native ACI poll events."""

from __future__ import annotations
import hashlib
import json
import math
import re
import uuid
from typing import Any
from .schema import CLASSES, CLASSES_V2, VOLATILE_ATTRIBUTES

SCHEMA = "application_atlas.aci_poll.v1"
MAX_EVENTS = 10_001
MAX_CAPTURE_SECONDS = 300.0
MAX_FRESHNESS_SECONDS = 86_400.0
PAGE_SIZE = 500
PIN_RE = re.compile(r"^[0-9a-f]{64}$")


class PollQualificationError(ValueError):
    """The event set cannot support an integrity report."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    except (TypeError, ValueError, OverflowError) as exc:
        raise PollQualificationError("noncanonical_data") from exc


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PollQualificationError(f"{name}_invalid")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise PollQualificationError(f"{name}_invalid")
    return result


def _digest(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(b"\n".join(_canonical(row) for row in rows)).hexdigest()


def _passes(
    manifest: dict[str, Any],
    classes: tuple[str, ...],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    raw = manifest.get("passes")
    if not isinstance(raw, list) or len(raw) != 2:
        raise PollQualificationError("passes_missing")
    result = []
    for item in raw:
        if not isinstance(item, dict):
            raise PollQualificationError("pass_invalid")
        current = {}
        for class_name in classes:
            entry = item.get(class_name)
            if not isinstance(entry, dict):
                raise PollQualificationError("class_pass_missing")
            expected, observed, pages = (
                entry.get("expected_total"),
                entry.get("observed_total"),
                entry.get("pages"),
            )
            if any(type(x) is not int or x < 0 for x in (expected, observed)):
                raise PollQualificationError("class_count_invalid")
            if type(pages) is not int or pages < 1:
                raise PollQualificationError("page_count_invalid")
            windows = entry.get("request_windows")
            if not isinstance(windows, list) or len(windows) != pages:
                raise PollQualificationError("request_windows_invalid")
            previous_end = None
            for window in windows:
                if not isinstance(window, dict):
                    raise PollQualificationError("request_window_invalid")
                start, end = (
                    _number(window.get("started_at"), "request_started_at"),
                    _number(window.get("completed_at"), "request_completed_at"),
                )
                if end < start or (previous_end is not None and start < previous_end):
                    raise PollQualificationError("request_window_order")
                previous_end = end
            for name in ("canonical_digest", "comparison_digest"):
                if not isinstance(entry.get(name), str) or not re.fullmatch(
                    r"[0-9a-f]{64}", entry[name]
                ):
                    raise PollQualificationError("class_digest_invalid")
            if entry.get("comparison_omissions") != sorted(
                VOLATILE_ATTRIBUTES.get(class_name, ())
            ):
                raise PollQualificationError("comparison_omissions_invalid")
            if (not VOLATILE_ATTRIBUTES.get(class_name) or observed == 0) and entry[
                "canonical_digest"
            ] != entry["comparison_digest"]:
                raise PollQualificationError("nonvolatile_digest_mismatch")
            current[class_name] = {
                "expected": expected,
                "observed": observed,
                "pages": pages,
                "windows": windows,
                "canonical": entry["canonical_digest"],
                "comparison": entry["comparison_digest"],
            }
        result.append(current)
    return result[0], result[1]


def validate_events(
    events: list[Any],
    *,
    expected_authority: str,
    expected_fabric: str,
    expected_scope: str,
    expected_apic_pin: str,
    expected_apic_host: str,
    now: float | None = None,
    expected_version: int = 1,
) -> dict[str, Any]:
    """Validate wrapper output; report integrity only and retain quarantine."""
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise PollQualificationError("event_count_invalid")
    parsed = []
    for value in events:
        if not isinstance(value, dict):
            raise PollQualificationError("event_invalid")
        if set(value) == {"event"} and isinstance(value["event"], dict):
            value = value["event"]
        _canonical(value)
        parsed.append(value)
    if type(expected_version) is not int or expected_version not in (1, 2):
        raise PollQualificationError("schema_invalid")
    classes = CLASSES if expected_version == 1 else CLASSES_V2
    expected_schema = f"application_atlas.aci_poll.v{expected_version}"
    manifests = [item for item in parsed if item.get("record_type") == "manifest"]
    objects = [item for item in parsed if item.get("record_type") == "object"]
    if len(manifests) != 1 or len(objects) != len(parsed) - 1:
        raise PollQualificationError("manifest_or_record_count")
    manifest = manifests[0]
    if (
        manifest.get("schema") != expected_schema
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != expected_version
    ):
        raise PollQualificationError("schema_invalid")
    if (
        manifest.get("complete") is not True
        or manifest.get("consumer_quarantine") is not True
    ):
        raise PollQualificationError("quarantine_required")
    if not isinstance(expected_apic_pin, str) or not PIN_RE.fullmatch(
        expected_apic_pin
    ):
        raise PollQualificationError("expected_pin_invalid")
    for key, expected in (
        ("authority", expected_authority),
        ("fabric", expected_fabric),
        ("scope", expected_scope),
        ("apic_address", expected_apic_host),
        ("apic_certificate_sha256", expected_apic_pin),
    ):
        if not isinstance(expected, str) or manifest.get(key) != expected:
            raise PollQualificationError(f"{key}_binding_mismatch")
    capture_id = manifest.get("capture_id")
    try:
        if str(uuid.UUID(capture_id)) != capture_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError) as exc:
        raise PollQualificationError("capture_id_invalid") from exc
    common = (
        "schema",
        "schema_version",
        "capture_id",
        "authority",
        "fabric",
        "scope",
        "capture_started_at",
        "capture_completed_at",
        "consumer_quarantine",
    )
    for item in parsed:
        if (
            type(item.get("schema_version")) is not int
            or item.get("schema_version") != expected_version
        ):
            raise PollQualificationError("schema_invalid")
        if any(item.get(key) != manifest.get(key) for key in common):
            raise PollQualificationError("common_metadata_mismatch")
    started, completed = (
        _number(manifest.get("capture_started_at"), "capture_started_at"),
        _number(manifest.get("capture_completed_at"), "capture_completed_at"),
    )
    if completed < started or completed - started > MAX_CAPTURE_SECONDS:
        raise PollQualificationError("capture_time_invalid")
    if now is not None:
        current = _number(now, "now")
        if completed > current or current - completed > MAX_FRESHNESS_SECONDS:
            raise PollQualificationError("capture_stale")
    if manifest.get("page_size") != PAGE_SIZE or manifest.get("classes") != list(
        classes
    ):
        raise PollQualificationError("capture_metadata_mismatch")
    if type(manifest.get("record_count")) is not int or manifest["record_count"] != len(
        objects
    ):
        raise PollQualificationError("record_count_mismatch")
    first, second = _passes(manifest, classes)
    previous_window_end = None
    for pass_info in (first, second):
        for class_name in classes:
            for window in pass_info[class_name]["windows"]:
                start, end = window["started_at"], window["completed_at"]
                if start < started or end > completed:
                    raise PollQualificationError("request_window_outside_capture")
                if previous_window_end is not None and start < previous_window_end:
                    raise PollQualificationError("request_window_global_order")
                previous_window_end = end
    by_class = {name: [] for name in classes}
    seen = set()
    for row in objects:
        class_name, dn, attrs = row.get("class"), row.get("dn"), row.get("attributes")
        if (
            class_name not in by_class
            or not isinstance(dn, str)
            or not isinstance(attrs, dict)
            or attrs.get("dn") != dn
        ):
            raise PollQualificationError("object_shape_invalid")
        key = (class_name, dn)
        if key in seen:
            raise PollQualificationError("duplicate_object")
        seen.add(key)
        if hashlib.sha256(
            _canonical({class_name: {"attributes": attrs}})
        ).hexdigest() != row.get("record_fingerprint"):
            raise PollQualificationError("fingerprint_mismatch")
        observation_start, observation_end = (
            _number(row.get("observation_started_at"), "observation_started_at"),
            _number(row.get("observation_completed_at"), "observation_completed_at"),
        )
        if (
            observation_start < started
            or observation_end > completed
            or observation_end < observation_start
        ):
            raise PollQualificationError("observation_window_invalid")
        by_class[class_name].append((dn, attrs, observation_start, observation_end))
    counts = {}
    for class_name in classes:
        entries = sorted(by_class[class_name], key=lambda value: value[0])
        rows = [{class_name: {"attributes": attrs}} for _, attrs, _, _ in entries]
        info = first[class_name]
        expected_pages = max(1, (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE)
        if (
            len(rows) != info["expected"]
            or info["observed"] != len(rows)
            or info["pages"] != expected_pages
        ):
            raise PollQualificationError("object_count_mismatch")
        if _digest(rows) != info["canonical"]:
            raise PollQualificationError("first_digest_mismatch")
        comparison_rows = []
        for index, (_, attrs, observation_start, observation_end) in enumerate(entries):
            window = info["windows"][index // PAGE_SIZE]
            if (observation_start, observation_end) != (
                window["started_at"],
                window["completed_at"],
            ):
                raise PollQualificationError("observation_window_mismatch")
            comparison_rows.append(
                {
                    class_name: {
                        "attributes": {
                            key: value
                            for key, value in attrs.items()
                            if key not in VOLATILE_ATTRIBUTES.get(class_name, ())
                        }
                    }
                }
            )
        if _digest(comparison_rows) != info["comparison"]:
            raise PollQualificationError("comparison_digest_mismatch")
        if (
            second[class_name]["expected"] != info["expected"]
            or second[class_name]["observed"] != info["observed"]
            or second[class_name]["pages"] != expected_pages
            or second[class_name]["comparison"] != info["comparison"]
        ):
            raise PollQualificationError("pass_comparison_mismatch")
        counts[class_name] = len(rows)
    if (
        manifest.get("capture_digest")
        != hashlib.sha256(
            _canonical({name: first[name]["canonical"] for name in classes})
        ).hexdigest()
    ):
        raise PollQualificationError("capture_digest_mismatch")
    return {
        "schema": expected_schema,
        "capture_id": capture_id,
        "complete": True,
        "consumer_quarantine": True,
        "record_count": len(objects),
        "class_counts": counts,
        "integrity_validated": True,
    }
