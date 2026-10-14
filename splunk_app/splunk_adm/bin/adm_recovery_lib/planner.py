"""Pure planning helpers for replaying missed continuous saved-search slots."""

from __future__ import annotations

import math
from numbers import Real
import re
from typing import Any, Iterable

_PERIOD = 300
_EVENT_EARLIEST = -86400
_EVENT_LATEST = 900
TARGET_WINDOWS = {
    "ADM - Identity builder": {
        "offset": 60,
        "period": _PERIOD,
        "index_earliest": -600,
        "index_latest": 0,
        "event_earliest": _EVENT_EARLIEST,
        "event_latest": _EVENT_LATEST,
    },
    "ADM - Service binding": {
        "offset": 120,
        "period": _PERIOD,
        "index_earliest": -600,
        "index_latest": 0,
        "event_earliest": _EVENT_EARLIEST,
        "event_latest": _EVENT_LATEST,
    },
    "ADM - Service backends": {
        "offset": 180,
        "period": _PERIOD,
        "index_earliest": -600,
        "index_latest": 0,
        "event_earliest": _EVENT_EARLIEST,
        "event_latest": _EVENT_LATEST,
    },
    "ADM - Conversation rollup": {
        "offset": 0,
        "period": _PERIOD,
        "index_earliest": -600,
        "index_latest": -300,
        "event_earliest": _EVENT_EARLIEST,
        "event_latest": _EVENT_LATEST,
    },
}
_TARGETS = frozenset(TARGET_WINDOWS)
_MAX_RANGE = 86400
_MAX_PLANS = 4 * 288 + 4


def _integer(value: Any, label: str) -> int:
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError(f"{label} must be a finite integer timestamp")
        return int(value)
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{label} must be a finite integer timestamp")
    if not math.isfinite(value) or not float(value).is_integer():
        raise ValueError(f"{label} must be a finite integer timestamp")
    return int(value)


def _slot_floor(through: int, offset: int, period: int) -> int:
    return through - ((through - offset) % period)


def _through_bound(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, Real)
        or not math.isfinite(value)
    ):
        raise ValueError("through must be a finite numeric timestamp")
    return math.floor(value)


def _outage_bound(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, Real)
        or not math.isfinite(value)
    ):
        raise ValueError("outage_start must be a finite numeric timestamp")
    return float(value)


def _selected_targets(targets: Iterable[str] | None) -> tuple[str, ...]:
    if targets is None:
        return tuple(TARGET_WINDOWS)
    selected = tuple(targets)
    unknown = set(selected) - _TARGETS
    if unknown:
        raise ValueError(f"unknown recovery target(s): {', '.join(sorted(unknown))}")
    if len(set(selected)) != len(selected):
        raise ValueError("recovery targets must be unique")
    return selected


def build_recovery_plan(
    rows: list[dict[str, Any]],
    outage_start: Real,
    through: Real,
    targets: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Build absolute replay windows for successful-slot gaps after an outage."""
    outage = _outage_bound(outage_start)
    end = _through_bound(through)
    selected = _selected_targets(targets)
    if outage <= 0 or end <= 0:
        raise ValueError("outage_start and through must be positive")
    if end < outage:
        raise ValueError("through must be at least outage_start")
    if end - outage > _MAX_RANGE:
        raise ValueError("recovery range must not exceed 24 hours")

    successes: dict[str, set[int]] = {name: set() for name in selected}
    for row in rows:
        name = row.get("savedsearch_name")
        if name not in successes or row.get("status") != "success":
            continue
        timestamp = _integer(row.get("scheduled_time"), "scheduled_time")
        if timestamp <= 0:
            raise ValueError("scheduled_time must be positive")
        window = TARGET_WINDOWS[name]
        if (timestamp - window["offset"]) % window["period"]:
            raise ValueError(f"{name}: scheduled_time is not aligned to its cron")
        successes[name].add(timestamp)

    plans: list[dict[str, Any]] = []
    for name in selected:
        window = TARGET_WINDOWS[name]
        before = [slot for slot in successes[name] if slot < outage]
        if not before:
            raise ValueError(f"{name}: no pre-outage successful checkpoint")
        checkpoint = max(before)
        first = checkpoint + window["period"]
        if first < outage:
            raise ValueError(f"{name}: successful checkpoint is stale")
        last = _slot_floor(end, window["offset"], window["period"])
        for slot in range(first, last + 1, window["period"]):
            if slot in successes[name]:
                continue
            plans.append(
                {
                    "name": name,
                    "scheduled_time": slot,
                    "earliest": slot + window["event_earliest"],
                    "latest": slot + window["event_latest"],
                    "index_earliest": slot + window["index_earliest"],
                    "index_latest": slot + window["index_latest"],
                }
            )
    if len(plans) > _MAX_PLANS:
        raise ValueError("recovery plan exceeds bounded replay limit")
    plans = sorted(plans, key=lambda item: (item["scheduled_time"], item["name"]))
    validate_recovery_plan(plans, end)
    return plans


def validate_recovery_plan(plan: list[dict[str, Any]], through: Real) -> None:
    """Validate replay bounds and ordering before any dispatch is attempted."""
    end = _through_bound(through)
    by_target: dict[str, list[dict[str, Any]]] = {name: [] for name in TARGET_WINDOWS}
    seen: set[tuple[str, int]] = set()
    for item in plan:
        name = item.get("name")
        if name not in TARGET_WINDOWS:
            raise ValueError(f"unknown recovery target: {name}")
        window = TARGET_WINDOWS[name]
        fields = (
            "scheduled_time",
            "earliest",
            "latest",
            "index_earliest",
            "index_latest",
        )
        try:
            values = {field: _integer(item.get(field), field) for field in fields}
        except ValueError as exc:
            raise ValueError(f"{name}: invalid replay bounds: {exc}") from exc
        slot = values["scheduled_time"]
        if slot <= 0 or (slot - window["offset"]) % window["period"]:
            raise ValueError(f"{name}: scheduled_time is not aligned to its cron")
        key = (name, slot)
        if key in seen:
            raise ValueError(f"{name}: duplicate scheduled slot {slot}")
        seen.add(key)
        expected = {
            "earliest": slot + window["event_earliest"],
            "latest": slot + window["event_latest"],
            "index_earliest": slot + window["index_earliest"],
            "index_latest": slot + window["index_latest"],
        }
        if any(values[field] != expected[field] for field in expected):
            raise ValueError(f"{name}: replay bounds do not match shipped window")
        if slot > end or values["index_latest"] > end:
            raise ValueError(f"{name}: replay slot is not closed through {end}")
        if (
            values["earliest"] > values["latest"]
            or values["index_earliest"] > values["index_latest"]
        ):
            raise ValueError(f"{name}: replay bounds are not ordered")
        by_target[name].append(item)

    for name, items in by_target.items():
        ordered = sorted(items, key=lambda item: item["scheduled_time"])
        if items != ordered:
            raise ValueError(f"{name}: replay slots must be chronological")
        previous = None
        for item in ordered:
            slot = item["scheduled_time"]
            if previous is not None and slot <= previous:
                raise ValueError(f"{name}: replay slots must be strictly increasing")
            previous = slot
        if name == "ADM - Conversation rollup":
            for left, right in zip(ordered, ordered[1:]):
                if right["index_earliest"] < left["index_latest"]:
                    raise ValueError("ADM - Conversation rollup: overlapping slices")
