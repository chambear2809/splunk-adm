"""Bounded, transport-agnostic APIC class snapshot capture.

The callback is deliberately narrower than an HTTP client: it receives only a
class, page number, and page size and must return one decoded APIC response.
This module performs no network I/O, authentication, persistence, or indexing.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

CLASSES = (
    "fvCEp",
    "fvIp",
    "fvRsCEpToPathEp",
    "fabricLink",
    "lldpAdjEp",
    "topSystem",
    "fabricNode",
    "l1PhysIf",
    "ethpmPhysIf",
    "l3EncRtdIf",
    "fvRsBd",
    "fvCtx",
    "fvBD",
    "fvAEPg",
    "netflowExporterPol",
    "netflowMonitorPol",
    "netflowRecordPol",
    "netflowRsMonitorToExporter",
    "netflowRsMonitorToRecord",
    "netflowRtBDToNetflowMonitorPol",
    "netflowRsExporterToCtx",
    "netflowRsExporterToEPg",
)

# Poll versions are distinct fixed contracts; v1 remains the default.
CLASSES_V1 = CLASSES
CLASSES_V2 = CLASSES_V1 + ("fvRsCtx",)


class SnapshotError(ValueError):
    """The APIC response cannot support a bounded complete capture."""


@dataclass(frozen=True)
class CaptureLimits:
    page_size: int = 2000
    max_pages_per_class: int = 1000
    max_rows_per_class: int = 100_000
    max_payload_bytes: int = 16 * 1024 * 1024
    deadline_seconds: float = 300.0


MAX_DEADLINE_SECONDS = 3600.0
MAX_CAPTURE_PAYLOAD_BYTES = 64 * 1024 * 1024
# These APIC clock measurements advance without an inventory change. They stay
# in the retained records and full digest, but not the stability comparison.
VOLATILE_ATTRIBUTES = {
    "topSystem": frozenset({"currentTime", "systemUpTime", "clusterTimeDiff"})
}


Request = Callable[[str, int, int], dict[str, Any]]


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError, OverflowError) as exc:
        raise SnapshotError("noncanonical_data") from exc


def _finite_json(value: Any) -> None:
    if value is None or isinstance(value, (str, int, bool)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SnapshotError("nonfinite_data")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SnapshotError("invalid_json_key")
            _finite_json(child)
    elif isinstance(value, list):
        for child in value:
            _finite_json(child)
    else:
        raise SnapshotError("unsupported_data")


def _clock(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SnapshotError(f"{label}_invalid")
    try:
        value = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SnapshotError(f"{label}_invalid") from exc
    if not math.isfinite(value) or value < 0:
        raise SnapshotError(f"{label}_invalid")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise SnapshotError(f"{label}_invalid")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SnapshotError(f"{label}_invalid") from exc
    if str(parsed) != str(value).strip() and not isinstance(value, int):
        raise SnapshotError(f"{label}_invalid")
    if parsed < 0:
        raise SnapshotError(f"{label}_negative")
    return parsed


def _rows(
    response: dict[str, Any], class_name: str
) -> tuple[int, list[dict[str, Any]]]:
    if not isinstance(response, dict) or "error" in response or "errors" in response:
        raise SnapshotError("apic_error")
    _finite_json(response)
    total = _integer(response.get("totalCount"), "total_count")
    data = response.get("imdata")
    if not isinstance(data, list):
        raise SnapshotError("missing_page")
    result: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict) or set(item) != {class_name}:
            raise SnapshotError("row_class_mismatch")
        payload = item[class_name]
        if not isinstance(payload, dict) or set(payload) != {"attributes"}:
            raise SnapshotError("row_shape_invalid")
        attrs = payload["attributes"]
        if (
            not isinstance(attrs, dict)
            or not isinstance(attrs.get("dn"), str)
            or not attrs["dn"]
        ):
            raise SnapshotError("row_dn_missing")
        # Detach callback-owned nested values before any later request can
        # mutate its response object.
        detached = json.loads(_canonical({class_name: {"attributes": attrs}}))
        result.append(detached)
    return total, result


def _one_pass(
    request: Request,
    classes: tuple[str, ...],
    limits: CaptureLimits,
    wall_now: Callable[[], float],
    mono_now: Callable[[], float],
    deadline: float,
    previous_wall: float,
    previous_mono: float,
    payload_budget: int,
) -> tuple[dict[str, Any], float, float, int]:
    output: dict[str, Any] = {}
    for class_name in classes:
        page = 0
        total: int | None = None
        rows: list[dict[str, Any]] = []
        canonical_rows: list[bytes] = []
        comparison_rows: list[bytes] = []
        class_payload = 0
        seen: set[str] = set()
        windows: list[dict[str, float]] = []
        while True:
            current_mono = _clock(mono_now(), "monotonic_clock")
            if current_mono < previous_mono:
                raise SnapshotError("monotonic_regressed")
            previous_mono = current_mono
            if current_mono > deadline:
                raise SnapshotError("deadline_exceeded")
            if page >= limits.max_pages_per_class:
                raise SnapshotError("page_cap_exceeded")
            started = _clock(wall_now(), "wall_clock")
            if started < previous_wall:
                raise SnapshotError("clock_regressed")
            response = request(class_name, page, limits.page_size)
            current_mono = _clock(mono_now(), "monotonic_clock")
            if current_mono < previous_mono:
                raise SnapshotError("monotonic_regressed")
            previous_mono = current_mono
            if current_mono > deadline:
                raise SnapshotError("deadline_exceeded")
            finished = _clock(wall_now(), "wall_clock")
            if finished < started:
                raise SnapshotError("clock_regressed")
            previous_wall = finished
            windows.append({"started_at": started, "completed_at": finished})
            current_total, page_rows = _rows(response, class_name)
            if total is None:
                total = current_total
                if total > limits.max_rows_per_class:
                    raise SnapshotError("row_cap_exceeded")
            elif current_total != total:
                raise SnapshotError("total_count_changed")
            if len(page_rows) > limits.page_size:
                raise SnapshotError("page_truncated")
            remaining = total - len(rows)
            expected_page_len = min(limits.page_size, remaining)
            if len(page_rows) != expected_page_len:
                raise SnapshotError("missing_page")
            for row in page_rows:
                dn = row[class_name]["attributes"]["dn"]
                if dn in seen:
                    raise SnapshotError("duplicate_dn")
                if rows and dn <= rows[-1][class_name]["attributes"]["dn"]:
                    raise SnapshotError("dn_order_invalid")
                seen.add(dn)
                rows.append(row)
                encoded = _canonical(row)
                canonical_rows.append(encoded)
                comparison_rows.append(
                    _canonical(
                        {
                            class_name: {
                                "attributes": {
                                    key: value
                                    for key, value in row[class_name][
                                        "attributes"
                                    ].items()
                                    if key
                                    not in VOLATILE_ATTRIBUTES.get(class_name, ())
                                }
                            }
                        }
                    )
                )
                class_payload += len(encoded) + (1 if len(canonical_rows) > 1 else 0)
                payload_budget += len(encoded) + (1 if len(canonical_rows) > 1 else 0)
                if class_payload > limits.max_payload_bytes:
                    raise SnapshotError("payload_cap_exceeded")
                if payload_budget > MAX_CAPTURE_PAYLOAD_BYTES:
                    raise SnapshotError("capture_payload_cap_exceeded")
            if len(rows) > limits.max_rows_per_class:
                raise SnapshotError("row_cap_exceeded")
            if len(rows) >= total:
                if len(rows) != total:
                    raise SnapshotError("row_count_mismatch")
                break
            page += 1
        payload = b"\n".join(canonical_rows)
        output[class_name] = {
            "expected_total": total,
            "observed_total": len(rows),
            "pages": page + 1,
            "rows": rows,
            "request_windows": windows,
            "canonical_digest": hashlib.sha256(payload).hexdigest(),
            "comparison_digest": hashlib.sha256(
                b"\n".join(comparison_rows)
            ).hexdigest(),
            "comparison_omissions": sorted(VOLATILE_ATTRIBUTES.get(class_name, ())),
        }
    return output, previous_wall, previous_mono, payload_budget


def capture(
    request: Request,
    *,
    classes: tuple[str, ...] = CLASSES,
    limits: CaptureLimits = CaptureLimits(),
    now: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    capture_id: str | None = None,
) -> dict[str, Any]:
    """Capture two stable complete passes from a fixed-class/page callback."""
    if (
        not classes
        or any(c not in CLASSES_V2 for c in classes)
        or len(set(classes)) != len(classes)
    ):
        raise SnapshotError("class_allowlist")
    if (
        isinstance(limits.deadline_seconds, bool)
        or not isinstance(limits.deadline_seconds, (int, float))
        or not math.isfinite(limits.deadline_seconds)
    ):
        raise SnapshotError("deadline_invalid")
    if limits.deadline_seconds <= 0 or limits.deadline_seconds > MAX_DEADLINE_SECONDS:
        raise SnapshotError("deadline_invalid")
    for value in (
        limits.page_size,
        limits.max_pages_per_class,
        limits.max_rows_per_class,
        limits.max_payload_bytes,
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise SnapshotError("limits_invalid")
    cid = capture_id or str(uuid.uuid4())
    try:
        if str(uuid.UUID(cid)) != cid:
            raise ValueError
    except ValueError as exc:
        raise SnapshotError("capture_id_invalid") from exc
    started = _clock(now(), "wall_clock")
    mono_started = _clock(monotonic(), "monotonic_clock")
    deadline = mono_started + limits.deadline_seconds
    first, previous_wall, previous_mono, payload_budget = _one_pass(
        request,
        classes,
        limits,
        now,
        monotonic,
        deadline,
        started,
        mono_started,
        0,
    )
    second, previous_wall, previous_mono, payload_budget = _one_pass(
        request,
        classes,
        limits,
        now,
        monotonic,
        deadline,
        previous_wall,
        previous_mono,
        payload_budget,
    )
    for class_name in classes:
        if (
            first[class_name]["expected_total"],
            first[class_name]["comparison_digest"],
        ) != (
            second[class_name]["expected_total"],
            second[class_name]["comparison_digest"],
        ):
            raise SnapshotError("passes_changed")
    final_mono = _clock(monotonic(), "monotonic_clock")
    if final_mono < previous_mono:
        raise SnapshotError("monotonic_regressed")
    if final_mono > deadline:
        raise SnapshotError("deadline_exceeded")
    completed = _clock(now(), "wall_clock")
    if completed < previous_wall:
        raise SnapshotError("clock_regressed")
    version = 2 if "fvRsCtx" in classes else 1
    return {
        "schema": f"application_atlas.aci_snapshot.v{version}",
        "schema_version": version,
        "capture_id": cid,
        "capture_started_at": started,
        "capture_completed_at": completed,
        "classes": list(classes),
        "complete": True,
        "passes": [
            {
                k: {x: v for x, v in value.items() if x != "rows"}
                for k, value in first.items()
            },
            {
                k: {x: v for x, v in value.items() if x != "rows"}
                for k, value in second.items()
            },
        ],
        "records": {k: value["rows"] for k, value in first.items()},
        "capture_digest": hashlib.sha256(
            _canonical({k: first[k]["canonical_digest"] for k in classes})
        ).hexdigest(),
        "consumer_quarantine": True,
    }
