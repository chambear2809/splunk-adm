"""Bounded reader for a single explicitly bound, quarantined ACI capture."""

from __future__ import annotations

import json
import math
import re

from adm_identity_lib.search import SearchError, complete_rows
from .validation import PollQualificationError, validate_events
from .fabric import project_fabric_snapshot

SOURCE = "atlas:aci_poll"
SOURCETYPE = "adm:aci_poll:v1"
MAX_ROWS = 10_001
MAX_RAW_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_WINDOW = 300
MAX_RECEIPT_DELAY = 300
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}\Z")
INDEX = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
PIN = re.compile(r"[0-9a-f]{64}\Z")


def profile_config(profile):
    if not isinstance(profile, dict) or profile.get("enabled") is not True:
        raise SearchError("ACI poll reader is disabled.")
    for field in ("authority", "fabric", "scope", "apic_host", "host"):
        if not isinstance(profile.get(field), str) or not TOKEN.fullmatch(
            profile[field]
        ):
            raise SearchError("Invalid ACI poll trusted binding.")
    if not isinstance(profile.get("index"), str) or not INDEX.fullmatch(
        profile["index"]
    ):
        raise SearchError("Invalid ACI poll index binding.")
    if not isinstance(profile.get("apic_pin"), str) or not PIN.fullmatch(
        profile["apic_pin"]
    ):
        raise SearchError("Invalid ACI poll certificate binding.")
    if profile.get("poll_version", "1") not in ("1", "2"):
        raise SearchError("Invalid ACI poll schema version.")
    return profile


def bounds(start, as_of, now):
    try:
        values = [float(x) for x in (start, as_of, now)]
    except (TypeError, ValueError, OverflowError):
        raise SearchError("Invalid ACI poll time bounds.") from None
    start, as_of, now = values
    if (
        not all(math.isfinite(v) and v >= 0 for v in values)
        or not start < as_of <= now
        or now - as_of > 60
        or as_of - start > MAX_WINDOW
    ):
        raise SearchError("Invalid ACI poll time bounds.")
    return start, as_of


def query(profile, start, as_of, now):
    profile_config(profile)
    start, as_of = bounds(start, as_of, now)
    sourcetype = f"adm:aci_poll:v{profile.get('poll_version', '1')}"
    return (
        f'search index={profile["index"]} host="{profile["host"]}" source="{SOURCE}" sourcetype="{sourcetype}" '
        f"earliest={start} latest={as_of} _index_latest={as_of} "
        "| eval event_time=_time,receipt_time=_indextime "
        "| fields _raw index host source sourcetype event_time receipt_time "
        "| eventstats count AS _atlas_total | head 10002"
    )


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON key")
        result[name] = value
    return result


def read_rows(rows, profile, start, as_of, now):
    profile_config(profile)
    start, as_of = bounds(start, as_of, now)
    complete_rows(rows)
    if len(rows) > MAX_ROWS:
        raise SearchError("ACI poll evidence exceeds its cap.")
    events = []
    receipts = {}
    total_bytes = 0
    for row in rows:
        if (
            row.get("index") != profile["index"]
            or row.get("host") != profile["host"]
            or row.get("source") != SOURCE
            or row.get("sourcetype")
            != f"adm:aci_poll:v{profile.get('poll_version', '1')}"
        ):
            raise SearchError("ACI poll source binding mismatch.")
        try:
            event_time = float(row["event_time"])
            receipt = float(row["receipt_time"])
            raw = row["_raw"]
            if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_RAW_BYTES:
                raise ValueError()
            total_bytes += len(raw.encode("utf-8"))
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError()
            event = json.loads(raw, object_pairs_hook=unique_object)
            if not isinstance(event, dict):
                raise ValueError()
            completed = event["capture_completed_at"]
            if isinstance(completed, bool) or not isinstance(completed, (int, float)):
                raise ValueError()
            if (
                not all(math.isfinite(x) for x in (event_time, receipt, completed))
                or not start <= event_time < as_of
                or not start <= completed < as_of
                or abs(event_time - completed) > 0.000001
                or not completed - 1 <= receipt < as_of
                or receipt - completed > MAX_RECEIPT_DELAY
                or now - completed > MAX_WINDOW
            ):
                raise ValueError()
        except (ValueError, TypeError, KeyError, OverflowError):
            raise SearchError("Invalid ACI poll event or receipt time.") from None
        event_receipt = receipt
        events.append(event)
        receipts[(event.get("record_type"), event.get("class"), event.get("dn"))] = (
            event_receipt
        )
    try:
        report = validate_events(
            events,
            expected_authority=profile["authority"],
            expected_fabric=profile["fabric"],
            expected_scope=profile["scope"],
            expected_apic_pin=profile["apic_pin"],
            expected_apic_host=profile["apic_host"],
            now=as_of,
            expected_version=int(profile.get("poll_version", "1")),
        )
    except PollQualificationError as exc:
        raise SearchError("ACI poll integrity validation failed: " + str(exc)) from None
    # Raw objects are candidates, not asserted joins, endpoints, or traversed paths.
    # Explicitly expose unknown VRF and preserve all path-relation alternatives.
    objects = [
        {
            "schema": "application_atlas.aci_attachment_context.v1",
            "poll_schema": report["schema"],
            "poll_version": int(profile.get("poll_version", "1")),
            "qualification": "quarantined",
            "basis": "complete_two_pass_current_poll",
            "traversal": "not_observed",
            "capture_id": report["capture_id"],
            "authority": profile["authority"],
            "fabric": profile["fabric"],
            "scope": profile["scope"],
            "routing_domain": None,
            "record_class": e["class"],
            "dn": e["dn"],
            "received_at": receipts[(e["record_type"], e["class"], e["dn"])],
            "observation_started_at": e["observation_started_at"],
            "observation_completed_at": e["observation_completed_at"],
            "record_fingerprint": e["record_fingerprint"],
            "attributes": json.dumps(
                e["attributes"], sort_keys=True, separators=(",", ":")
            ),
        }
        for e in events
        if e["record_type"] == "object"
        and e["class"] in ("fvCEp", "fvIp", "fvRsCEpToPathEp", "fvRsCtx")
    ]

    return [
        {
            "schema": "application_atlas.aci_attachment_context.v1",
            "poll_schema": report["schema"],
            "poll_version": int(profile.get("poll_version", "1")),
            "qualification": "quarantined",
            "basis": "complete_two_pass_current_poll",
            "traversal": "not_observed",
            "record_class": "completion",
            "capture_id": report["capture_id"],
            "authority": profile["authority"],
            "fabric": profile["fabric"],
            "scope": profile["scope"],
            "routing_domain": None,
            "candidate_count": len(objects),
        }
    ] + objects


def read_fabric_snapshot(rows, profile, start, as_of, now):
    """Read one validated poll and project only fabric inventory facts."""
    profile_config(profile)
    start, as_of = bounds(start, as_of, now)
    complete_rows(rows)
    if len(rows) > MAX_ROWS:
        raise SearchError("ACI poll evidence exceeds its cap.")
    events, receipts, total_bytes = [], {}, 0
    for row in rows:
        if (
            row.get("index"),
            row.get("host"),
            row.get("source"),
            row.get("sourcetype"),
        ) != (
            profile["index"],
            profile["host"],
            SOURCE,
            f"adm:aci_poll:v{profile.get('poll_version', '1')}",
        ):
            raise SearchError("ACI poll source binding mismatch.")
        try:
            event_time, receipt, raw = (
                float(row["event_time"]),
                float(row["receipt_time"]),
                row["_raw"],
            )
            if not isinstance(raw, str):
                raise ValueError
            raw_bytes = len(raw.encode("utf-8"))
            total_bytes += raw_bytes
            if raw_bytes > MAX_RAW_BYTES or total_bytes > MAX_TOTAL_BYTES:
                raise ValueError
            event = json.loads(raw, object_pairs_hook=unique_object)
            completed = event["capture_completed_at"]
            if (
                not isinstance(event, dict)
                or isinstance(completed, bool)
                or not isinstance(completed, (int, float))
            ):
                raise ValueError
            if (
                not start <= event_time < as_of
                or not start <= completed < as_of
                or abs(event_time - completed) > 0.000001
            ):
                raise ValueError
            if (
                not completed - 1 <= receipt < as_of
                or receipt - completed > MAX_RECEIPT_DELAY
                or now - completed > MAX_WINDOW
            ):
                raise ValueError
            events.append(event)
            receipts[
                (
                    event.get("capture_id"),
                    event.get("record_type"),
                    event.get("class"),
                    event.get("dn"),
                )
            ] = receipt
        except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
            raise SearchError("Invalid ACI poll event or receipt time.") from None
    groups = {}
    group_receipts = {}
    for event in events:
        capture_id = event.get("capture_id")
        groups.setdefault(capture_id, []).append(event)
        key = (
            capture_id,
            event.get("record_type"),
            event.get("class"),
            event.get("dn"),
        )
        group_receipts.setdefault(capture_id, {})[
            (event.get("record_type"), event.get("class"), event.get("dn"))
        ] = receipts[key]
    candidates = []
    rejected = []
    for capture_id, candidate_events in groups.items():
        completed_values = [
            item.get("capture_completed_at")
            for item in candidate_events
            if isinstance(item.get("capture_completed_at"), (int, float))
        ]
        # Rank rejected groups by every observed clock, not only their manifest;
        # malformed groups must not hide a newer object set behind an old manifest.
        completed = max(completed_values, default=-1)
        try:
            snapshot = project_fabric_snapshot(
                candidate_events,
                profile,
                receipts=group_receipts[capture_id],
                as_of=as_of,
            )
            candidates.append(
                (
                    float(completed),
                    float(max(group_receipts[capture_id].values())),
                    snapshot,
                )
            )
        except (PollQualificationError, ValueError, KeyError, TypeError) as exc:
            rejected.append(
                {
                    "capture_id": capture_id,
                    "capture_completed": completed,
                    "reason": str(exc),
                }
            )
    if not candidates:
        reason = rejected[-1]["reason"] if rejected else "no_capture"
        raise SearchError("ACI fabric snapshot validation failed: " + reason)
    latest_completed = max(value[0] for value in candidates)
    latest = [value for value in candidates if value[0] == latest_completed]
    if len(latest) > 1:
        raise SearchError(
            "ACI fabric snapshot validation failed: ambiguous_capture_tie"
        )
    latest_receipts = max(value[1] for value in latest)
    tied = [value for value in latest if value[1] == latest_receipts]
    if len(tied) > 1:
        raise SearchError(
            "ACI fabric snapshot validation failed: ambiguous_capture_tie"
        )
    rejected_completed = []
    for item in rejected:
        try:
            rejected_completed.append(float(item["capture_completed"]))
        except (TypeError, ValueError, OverflowError):
            continue
    if any(value >= latest_completed for value in rejected_completed):
        raise SearchError(
            "ACI fabric snapshot validation failed: newer_capture_invalid"
        )
    _, _, snapshot = tied[0]
    snapshot["provenance"]["capture_selection"] = "latest_complete"
    snapshot["provenance"]["excluded_captures"] = sorted(
        rejected,
        key=lambda value: (str(value["capture_completed"]), str(value["capture_id"])),
    )
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return [{"row_type": "aci_fabric_snapshot", "snapshot": encoded}]
