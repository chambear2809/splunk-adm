"""Pure planning helpers for replaying missed continuous saved-search slots."""

from __future__ import annotations

import math
from numbers import Real
import re
from typing import Any


_PERIOD = 300
_EVENT_EARLIEST = -86400
_EVENT_LATEST = 900

# The offsets and bounds mirror splunk_app/splunk_adm/default/savedsearches.conf.
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
    """Return a finite integer, accepting scheduler's decimal string values."""
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
    """Accept a finite numeric through-bound and close it at the prior second."""
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


def build_recovery_plan(
    rows: list[dict[str, Any]], outage_start: Real, through: Real
) -> list[dict[str, Any]]:
    """Build absolute replay windows for successful-slot gaps after an outage.

    A successful run immediately before the outage is required for every target;
    this prevents a missing earlier history checkpoint from being silently hidden
    by a later successful run.
    """
    outage = _outage_bound(outage_start)
    end = _through_bound(through)
    if outage <= 0 or end <= 0:
        raise ValueError("outage_start and through must be positive")
    if end < outage:
        raise ValueError("through must be at least outage_start")
    if end - outage > _MAX_RANGE:
        raise ValueError("recovery range must not exceed 24 hours")

    successes: dict[str, set[int]] = {name: set() for name in TARGET_WINDOWS}
    for row in rows:
        if row.get("savedsearch_name") not in _TARGETS:
            continue
        if row.get("status") != "success":
            continue
        name = row["savedsearch_name"]
        timestamp = _integer(row.get("scheduled_time"), "scheduled_time")
        if timestamp <= 0:
            raise ValueError("scheduled_time must be positive")
        window = TARGET_WINDOWS[name]
        if (timestamp - window["offset"]) % window["period"]:
            raise ValueError(f"{name}: scheduled_time is not aligned to its cron")
        successes[name].add(timestamp)

    plans: list[dict[str, Any]] = []
    for name, window in TARGET_WINDOWS.items():
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
    return sorted(plans, key=lambda item: (item["scheduled_time"], item["name"]))
