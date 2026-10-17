#!/usr/bin/env python3
"""Bounded, local synthetic probe of Cisco history and staged v2 schedules.

This records observed cycles and retained identities; it does not qualify scale.
The probe is restricted to the disposable localhost Splunk lab and requires an
explicit acknowledgement before it changes scheduler state or adds fixtures.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import hashlib
import math
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "splunk"))
sys.path.insert(0, str(ROOT / "tools"))
import lab  # noqa: E402
from lab_lock import run_main, with_lab_lock  # noqa: E402
from capture_networking_fixtures import require_complete, require_local_lab  # noqa: E402

CONTAINER = "adm-splunk-lab"
SAVED_SEARCHES = (
    "ADM - Network client history builder",
    "ADM - Conversation rollup v2",
    "ADM - Traffic observation rollup v2",
)
SCHEDULE_FIELDS = ("disabled", "is_scheduled")
SCHEDULE_CONTRACT_FIELDS = (
    "cron_schedule",
    "dispatch.index_earliest",
    "dispatch.index_latest",
)
PRODUCTION_CADENCE_SECONDS = 300
MAX_DURATION_SECONDS = 3600
MAX_RATE_EVENTS_PER_SECOND = 250
KNOWN_JOB_STATES = {"success", "skipped", "failed", "auto_skipped", "delegated"}
EXPECTED_CRON = {
    "ADM - Network client history builder": "1-56/5 * * * *",
    "ADM - Conversation rollup v2": "*/5 * * * *",
    "ADM - Traffic observation rollup v2": "*/5 * * * *",
}
EXPECTED_INDEX_WINDOWS = {
    "ADM - Network client history builder": ("-10m@m", "@m"),
    "ADM - Conversation rollup v2": ("-10m@m", "-5m@m"),
    "ADM - Traffic observation rollup v2": ("-10m@m", "-5m@m"),
}
TRAFFIC_CONTENT_FIELDS = (
    "_time contract_version adm_record rollup_id replay_protected scope cluster routing_domain "
    "source_port destination_port source_mac destination_mac raw_bytes raw_packets raw_sampling "
    "counter_semantics metrics_authoritative adm_profile_status adm_scope_source adm_scope_authority "
    "adm_scope_domain_kind adm_scope_observation_domain_present adm_scope_observation_domain_id "
    "adm_scope_vpn_id adm_scope_routing_domain adm_registered_profiles adm_quality_status "
    "adm_quality_errors adm_quality_warnings quality_status quality_errors quality_warnings "
    "source_ip destination_ip server_port transport first_seen last_seen received_time direction "
    "records traffic_observations"
)
TRAFFIC_OPTIONAL_EMPTY_FIELDS = (
    "routing_domain",
    "adm_scope_authority",
    "adm_scope_observation_domain_id",
    "adm_scope_vpn_id",
    "adm_scope_routing_domain",
)
TRAFFIC_MULTIVALUE_FIELDS = {
    "adm_quality_errors",
    "adm_quality_warnings",
    "quality_errors",
    "quality_warnings",
}

TRAFFIC_OBSERVATION_SEARCH = "search `adm_traffic_observations_v2`"
TRAFFIC_IDENTITY_RESULT_FIELDS = (
    "compared_identities",
    "expected_unique",
    "retained_unique",
    "identity_mismatch",
    "content_mismatch",
    "duplicate_count",
    "conflicting_count",
    "invalid_identity_count",
)
HISTORY_CONTENT_FIELDS = (
    "contract_version source source_authority native_id event_fingerprint client_mac client_ip scope "
    "cluster routing_domain domain_kind profile mapping_status source_time collected_time event_type "
    "client_type connected_device_type attachment_status attachment_basis attachment_device_id "
    "attachment_device_name attachment_device_mac device_serial ssid_number interface quality_reason raw_ref"
)
CONVERSATION_CONTENT_FIELDS = (
    "_time contract_version rollup_id replay_protected adm_record scope client_ip server_ip server_port "
    "transport flow_source observer observations bytes_c2s bytes_s2c packets records client_ports "
    "client_port_list conns conns_capped sampled first_seen last_seen direction_basis encapsulation "
    "acl_permits acl_drops xlate_ip xff trace_ids vlan_observations vlan_observations_truncated"
)


def _traffic_content_value(row: dict) -> str:
    """Canonicalize documented optional and multivalue serialization forms."""
    values = []
    for field in TRAFFIC_CONTENT_FIELDS.split():
        value = row.get(field)
        if field in TRAFFIC_OPTIONAL_EMPTY_FIELDS and value in (None, ""):
            value = None
        if field in TRAFFIC_MULTIVALUE_FIELDS:
            if value is None or value == "":
                value = []
            elif isinstance(value, str):
                value = value.splitlines()
        values.append(value)
    return json.dumps(values, sort_keys=True, separators=(",", ":"), default=str)


_TRAFFIC_ROLLUP_ID = re.compile(r"[0-9a-f]{64}\Z")


def _traffic_cycle_bounds(cycles: list[dict]) -> list[tuple[int, int, int, int]]:
    """Return successful traffic job pairs as input lo/hi, event lo/hi."""
    bounds = []
    for cycle in cycles:
        if cycle.get("status") != "success":
            continue
        input_window = cycle.get("input_window")
        search_window = cycle.get("search_window")
        if not input_window or not search_window:
            continue
        input_lower, input_upper = map(int, input_window)
        event_lower, event_upper = map(int, search_window)
        if input_lower < input_upper and event_lower < event_upper:
            bounds.append((input_lower, input_upper, event_lower, event_upper))
    return sorted(bounds)


def _traffic_expected_rows(cycles: list[dict]) -> list[dict]:
    """Fetch raw rows once per successful job with both actual request windows."""
    rows = []
    for input_lower, input_upper, event_lower, event_upper in _traffic_cycle_bounds(
        cycles
    ):
        rows.extend(
            _search_complete(
                TRAFFIC_OBSERVATION_SEARCH,
                str(event_lower),
                str(event_upper),
                index_earliest=str(input_lower),
                index_latest=str(input_upper),
            )
        )
    return rows


def _traffic_retained_search(started: int, end: int, fields: str) -> str:
    """Select every traffic summary written during the measurement interval."""
    return (
        'index=adm_summary_v2 source="adm:traffic_observation" '
        f"| where _indextime>={started} AND _indextime<{end} | fields {fields}"
    )


def _traffic_identity_comparison(
    expected_rows: list[dict], retained_rows: list[dict]
) -> dict[str, int]:
    """Compare expected and retained physical rows as per-ID content multisets."""
    expected: dict[str, dict[str, int]] = {}
    retained: dict[str, dict[str, int]] = {}
    invalid_identity_count = 0
    for row in expected_rows:
        rollup_id = row.get("rollup_id")
        if not isinstance(rollup_id, str) or not _TRAFFIC_ROLLUP_ID.fullmatch(
            rollup_id
        ):
            invalid_identity_count += 1
            continue
        content = _traffic_content_value(row)
        bucket = expected.setdefault(rollup_id, {})
        bucket[content] = bucket.get(content, 0) + 1
    for row in retained_rows:
        rollup_id = row.get("rollup_id")
        if not isinstance(rollup_id, str) or not _TRAFFIC_ROLLUP_ID.fullmatch(
            rollup_id
        ):
            invalid_identity_count += 1
            continue
        content = _traffic_content_value(row)
        bucket = retained.setdefault(rollup_id, {})
        bucket[content] = bucket.get(content, 0) + 1

    expected_ids, retained_ids = set(expected), set(retained)
    common = expected_ids & retained_ids
    content_mismatch = sum(
        1 for rollup_id in common if expected[rollup_id] != retained[rollup_id]
    )
    unexpected_duplicates = sum(
        sum(retained[rollup_id].values()) > sum(expected.get(rollup_id, {}).values())
        for rollup_id in retained_ids
    )
    return {
        "compared_identities": len(expected_ids | retained_ids),
        "expected_unique": len(expected_ids),
        "retained_unique": len(retained_ids),
        "identity_mismatch": len(expected_ids ^ retained_ids),
        "content_mismatch": content_mismatch,
        "duplicate_count": unexpected_duplicates,
        "expected_duplicate_count": sum(
            sum(contents.values()) > 1 for contents in expected.values()
        ),
        "conflicting_count": sum(len(contents) > 1 for contents in retained.values()),
        "invalid_identity_count": invalid_identity_count,
    }


_CONVERSATION_ROLLUP_ID = re.compile(r"[0-9a-f]{64}\Z")


def _conversation_content_value(row: dict) -> str:
    return json.dumps(
        [row.get(field) for field in CONVERSATION_CONTENT_FIELDS.split()],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _conversation_identity_comparison(
    expected_rows: list[dict], retained_rows: list[dict]
) -> dict[str, int]:
    """Compare conversation output using Python content and physical multiplicity."""
    expected: dict[str, dict[str, int]] = {}
    retained: dict[str, dict[str, int]] = {}
    invalid_identity_count = 0
    for rows, grouped in ((expected_rows, expected), (retained_rows, retained)):
        for row in rows:
            rollup_id = row.get("rollup_id")
            if not isinstance(rollup_id, str) or not _CONVERSATION_ROLLUP_ID.fullmatch(
                rollup_id
            ):
                invalid_identity_count += 1
                continue
            content = _conversation_content_value(row)
            bucket = grouped.setdefault(rollup_id, {})
            bucket[content] = bucket.get(content, 0) + 1

    expected_ids, retained_ids = set(expected), set(retained)
    common = expected_ids & retained_ids
    content_mismatch = sum(1 for key in common if expected[key] != retained[key])
    return {
        "expected_unique": len(expected_ids),
        "retained_unique": len(retained_ids),
        "identity_mismatch": len(expected_ids ^ retained_ids),
        "content_mismatch": content_mismatch,
        "duplicate_count": sum(
            sum(retained[key].values()) > sum(expected.get(key, {}).values())
            for key in retained_ids
        ),
        "expected_duplicate_count": sum(
            sum(contents.values()) > 1 for contents in expected.values()
        ),
        "conflicting_count": sum(len(contents) > 1 for contents in retained.values()),
        "invalid_identity_count": invalid_identity_count,
    }


def _latest_job_cycles(ordered_samples: list[dict]) -> dict[str, list[dict]]:
    """Select the latest available metadata for each real job name/SID pair."""
    by_identity: dict[tuple[str, str], dict] = {}
    for sample in ordered_samples:
        for name, cycles in sample.get("job_cycles", {}).items():
            for cycle in cycles:
                sid = cycle.get("sid")
                if not isinstance(sid, str) or not sid.strip():
                    continue
                identity = (str(name), sid)
                latest = by_identity.setdefault(identity, {})
                # Poll snapshots can omit fields while job metadata resolves.
                # Keep the most recent actual non-null value for each field.
                latest.update(
                    {
                        field: value
                        for field, value in cycle.items()
                        if value is not None
                    }
                )
    result: dict[str, list[dict]] = {}
    for (name, _sid), cycle in by_identity.items():
        result.setdefault(name, []).append(cycle)
    return result


def _finite_float(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


@dataclass(frozen=True)
class ProbeConfig:
    duration_seconds: int = 900
    events_per_second: int = 5

    def validate(self) -> None:
        if (
            isinstance(self.duration_seconds, bool)
            or not PRODUCTION_CADENCE_SECONDS * 2 + 20
            <= self.duration_seconds
            <= MAX_DURATION_SECONDS
        ):
            raise ValueError(
                f"duration must be between {PRODUCTION_CADENCE_SECONDS * 2 + 20} and {MAX_DURATION_SECONDS} seconds"
            )
        if (
            isinstance(self.events_per_second, bool)
            or not 1 <= self.events_per_second <= MAX_RATE_EVENTS_PER_SECOND
        ):
            raise ValueError(
                f"event rate must be between 1 and {MAX_RATE_EVENTS_PER_SECOND}"
            )

    @property
    def evidence_class(self) -> str:
        return "production-cadence-observation"


def assess_samples(samples: list[dict], required_cycles: int = 2) -> dict:
    """Summarize observations without converting records into traffic totals."""
    ordered = sorted(samples, key=lambda row: float(row["observed_at"]))
    issues: list[str] = []
    cycle_gaps = []
    cycle_counts: dict[str, int] = {}
    cycle_failures: dict[str, list[str]] = {}
    cycle_times: dict[str, list[float]] = {}
    for row in ordered:
        for name, cycles in row.get("job_cycles", {}).items():
            for cycle in cycles:
                status = str(cycle.get("status", "unknown")).lower()
                if status != "success":
                    cycle_failures.setdefault(name, []).append(status)
    required_names = {name for row in ordered for name in row.get("required_jobs", [])}
    unique_cycles = _latest_job_cycles(ordered)
    for name, cycles in unique_cycles.items():
        cycle_counts[name] = len(cycles)
        for cycle in cycles:
            if (
                name in required_names
                and str(cycle.get("status", "unknown")).lower() == "success"
                and any(
                    _finite_float(cycle.get(field)) is None
                    for field in (
                        "scheduled_time",
                        "run_duration_seconds",
                        "schedule_latency_seconds",
                    )
                )
            ):
                issues.append("cycle_timing_metric_unavailable")
            scheduled = _finite_float(cycle.get("scheduled_time"))
            if scheduled is not None:
                cycle_times.setdefault(name, []).append(scheduled)
            runtime = _finite_float(cycle.get("run_duration_seconds"))
            if runtime is not None and runtime > PRODUCTION_CADENCE_SECONDS:
                cycle_gaps.append(runtime)
    for times in cycle_times.values():
        ordered_times = sorted(set(times))
        cycle_gaps.extend(
            later - earlier
            for earlier, later in zip(ordered_times, ordered_times[1:])
            if later - earlier > PRODUCTION_CADENCE_SECONDS * 1.25
        )
    if cycle_gaps:
        issues.append("missed_or_late_cycle")
    missing_cycles = sorted(
        name for name in required_names if cycle_counts.get(name, 0) < required_cycles
    )
    if missing_cycles:
        issues.append("required_cycles_missing")
    if cycle_failures:
        issues.append("required_cycle_not_successful")
    if any(
        str(cycle.get("status", "")).lower() == "success"
        and (not cycle.get("input_window") or not cycle.get("search_window"))
        for row in ordered
        for cycles in row.get("job_cycles", {}).values()
        for cycle in cycles
    ):
        issues.append("scheduled_window_unavailable")
    all_states = [
        str(cycle.get("status", "unknown")).lower()
        for row in ordered
        for cycles in row.get("job_cycles", {}).values()
        for cycle in cycles
    ]
    unknown_states = sorted(set(all_states) - KNOWN_JOB_STATES)
    if unknown_states:
        issues.append("unknown_job_state")
    if (
        any(
            (duration := _finite_float(row.get("max_run_duration_seconds"))) is not None
            and duration > PRODUCTION_CADENCE_SECONDS
            for row in ordered
        )
        or cycle_gaps
    ):
        issues.append("work_exceeded_cadence")
    if ordered and ordered[-1].get("final_drain") and ordered[-1].get("active_jobs"):
        issues.append("active_jobs_not_drained")
    final = ordered[-1] if ordered else {}
    if (
        ordered
        and final.get("final_drain")
        and not final.get("scheduled_input_coverage", False)
    ):
        issues.append("scheduled_input_coverage_incomplete")
    if ordered and final.get("final_drain"):
        pending = final.get("pending_input_count")
        if not isinstance(pending, (int, float)):
            issues.append("pending_metric_unavailable")
        elif pending > 0:
            issues.append("pending_input_records")
    if ordered and (
        int(final.get("raw_count", -1)) != int(final.get("raw_expected_count", -2))
        or not final.get("raw_counts_match", False)
    ):
        issues.append("raw_count_mismatch")
    if ordered and not final.get("raw_source_counts_match", False):
        issues.append("raw_source_count_mismatch")
    if ordered and int(final.get("history_expected_unique", -1)) != int(
        final.get("history_unique_count", -2)
    ):
        issues.append("history_identity_mismatch")
    if ordered and int(final.get("traffic_expected_unique", -1)) != int(
        final.get("traffic_unique_count", -2)
    ):
        issues.append("traffic_identity_mismatch")
    if ordered and final.get("final_drain"):
        if int(final.get("traffic_content_mismatch", 0) or 0) > 0:
            issues.append("traffic_content_mismatch")
        if int(final.get("traffic_identity_mismatch_count", 0) or 0) > 0:
            issues.append("traffic_identity_mismatch")
        if int(final.get("traffic_duplicate_rollup_ids", 0) or 0) > 0:
            issues.append("duplicate_traffic_rollup_ids")
        if int(final.get("traffic_conflicting_rollup_ids", 0) or 0) > 0:
            issues.append("conflicting_traffic_rollup_ids")
        if int(final.get("traffic_invalid_identity_count", 0) or 0) > 0:
            issues.append("invalid_traffic_rollup_id")
        if int(final.get("mapped_traffic_expected_unique", 0) or 0) <= 0:
            issues.append("empty_traffic_expectation")
        if int(final.get("history_expected_unique", 0) or 0) <= 0:
            issues.append("empty_history_expectation")
        if int(final.get("history_content_mismatch", 0) or 0) > 0:
            issues.append("history_content_mismatch")
        if int(final.get("history_receipt_mismatch", 0) or 0) > 0:
            issues.append("history_receipt_mismatch")
        if int(final.get("mapped_client_count", 0) or 0) <= 0:
            issues.append("no_mapped_client_identity")
        if int(final.get("conversation_expected_unique", 0) or 0) <= 0:
            issues.append("empty_conversation_expectation")
        if int(final.get("conversation_expected_unique", -1)) != int(
            final.get("conversation_unique_count", -2)
        ):
            issues.append("conversation_identity_mismatch")
        if int(final.get("conversation_identity_mismatch_count", 0) or 0) > 0:
            issues.append("conversation_identity_mismatch")
        if int(final.get("conversation_content_mismatch", 0) or 0) > 0:
            issues.append("conversation_content_mismatch")
        if int(final.get("conversation_duplicate_rollup_ids", 0) or 0) > 0:
            issues.append("duplicate_conversation_rollup_ids")
        if int(final.get("conversation_conflicting_rollup_ids", 0) or 0) > 0:
            issues.append("conflicting_conversation_rollup_ids")
        if int(final.get("conversation_invalid_identity_count", 0) or 0) > 0:
            issues.append("invalid_conversation_rollup_id")
    if ordered and int(final.get("traffic_count", 0)) > int(
        final.get("traffic_unique_count", 0)
    ):
        issues.append("duplicate_traffic_observations")
    backlog = [row.get("unprocessed_backlog") for row in ordered]
    numeric_backlog = [
        int(value) for value in backlog if isinstance(value, (int, float))
    ]
    if len(numeric_backlog) >= 3 and all(
        b > a for a, b in zip(numeric_backlog[-3:], numeric_backlog[-2:])
    ):
        issues.append("increasing_unprocessed_backlog")
    if any(value is None for value in backlog):
        issues.append("backlog_metric_unavailable")
    raw_counts = [int(row.get("raw_count", 0)) for row in ordered]
    raw_unique = [int(row.get("raw_unique_count", 0)) for row in ordered]
    if any(unique > count for count, unique in zip(raw_counts, raw_unique)):
        issues.append("unique_raw_count_exceeds_raw_count")
    latencies = sorted(
        value
        for cycles in unique_cycles.values()
        for cycle in cycles
        if (value := _finite_float(cycle.get("schedule_latency_seconds"))) is not None
    )
    runtimes = sorted(
        value
        for cycles in unique_cycles.values()
        for cycle in cycles
        if (value := _finite_float(cycle.get("run_duration_seconds"))) is not None
    )

    def percentile(values, p):
        if not values:
            return None
        return values[min(len(values) - 1, int((len(values) - 1) * p))]

    return {
        "samples": len(ordered),
        "cycle_gaps_seconds": cycle_gaps,
        "cycle_counts": cycle_counts,
        "cycle_failures": cycle_failures,
        "missing_cycles": missing_cycles,
        "unknown_job_states": unknown_states,
        "max_run_duration_seconds": max(
            (
                duration
                for row in ordered
                if (duration := _finite_float(row.get("max_run_duration_seconds")))
                is not None
            ),
            default=None,
        ),
        "schedule_latency_seconds": {
            "samples": len(latencies),
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "max": max(latencies, default=None),
        },
        "run_duration_seconds": {
            "samples": len(runtimes),
            "p50": percentile(runtimes, 0.50),
            "p95": percentile(runtimes, 0.95),
            "max": max(runtimes, default=None),
        },
        "raw_count_first_last": [raw_counts[0], raw_counts[-1]] if raw_counts else [],
        "raw_unique_count_first_last": [raw_unique[0], raw_unique[-1]]
        if raw_unique
        else [],
        "retained_unique_history_first_last": [
            int(ordered[0].get("history_unique_count", 0)),
            int(ordered[-1].get("history_unique_count", 0)),
        ]
        if ordered
        else [],
        "retained_unique_traffic_first_last": [
            int(ordered[0].get("traffic_unique_count", 0)),
            int(ordered[-1].get("traffic_unique_count", 0)),
        ]
        if ordered
        else [],
        "unprocessed_backlog_first_last": [backlog[0], backlog[-1]]
        if backlog and all(value is not None for value in (backlog[0], backlog[-1]))
        else [],
        "unprocessed_backlog_available": len(numeric_backlog) == len(backlog)
        and bool(backlog),
        "pending_input_count": final.get("pending_input_count"),
        "scheduled_input_coverage": final.get("scheduled_input_coverage"),
        "issues": sorted(set(issues)),
        "complete": not issues,
    }


def _windows_cover_interval(
    windows: list[tuple[int, int]], start: int, end: int
) -> bool:
    """Return whether adjacent successful dispatch windows cover [start, end)."""
    if start >= end:
        return False
    cursor = start
    for lower, upper in sorted(windows):
        if upper <= cursor:
            continue
        if lower > cursor:
            return False
        cursor = max(cursor, upper)
        if cursor >= end:
            return True
    return False


def _positive_time_window(start: int, end: int) -> bool:
    return end > start


def _resolved_scheduler_window(name: str, entry: dict) -> tuple[int, int] | None:
    """Resolve a successful scheduled job's input interval from its request.

    The V2 jobs' absolute event-time request is anchored against their exact
    relative index-time request. The history builder has a minute cadence and
    an open-ended event-time search, so its verified request is paired with its
    scheduler minute. Observed event extrema are deliberately ignored.
    """
    content = entry.get("content") or {}
    request = content.get("request") or {}
    expected = EXPECTED_INDEX_WINDOWS.get(name)
    if (
        expected is None
        or (request.get("index_earliest"), request.get("index_latest")) != expected
    ):
        return None
    if (
        content.get("dispatchState") != "DONE"
        or content.get("isDone") is not True
        or content.get("isFinalized") is not False
        or content.get("eventIsTruncated") is not False
        or str(content.get("dropCount")) != "0"
        or not _job_messages_are_acceptable(name, content)
    ):
        return None
    search_window = _resolved_search_window(name, entry)
    if search_window is None:
        return None
    earliest, latest = search_window
    if name == SAVED_SEARCHES[0]:
        anchor = latest - 900
        close = anchor // 60 * 60
        return close - 600, close

    anchor_from_earliest = earliest + 24 * 60 * 60
    anchor_from_latest = latest - 15 * 60
    if anchor_from_earliest != anchor_from_latest or anchor_from_earliest % 300:
        return None
    lower = anchor_from_earliest // 300 * 300 - 600
    return lower, lower + 300


def _resolved_search_window(name: str, entry: dict) -> tuple[int, int] | None:
    """Return the job's actual absolute event-time bounds, without re-anchoring."""
    content = entry.get("content") or {}
    earliest = content.get("searchEarliestTime")
    latest = content.get("searchLatestTime")
    if name == SAVED_SEARCHES[0]:
        request = content.get("request") or {}
        if request.get("earliest_time") != "0":
            return None
        if earliest is None:
            earliest = 0
    try:
        earliest, latest = int(earliest), int(latest)
    except (TypeError, ValueError):
        return None
    if name == SAVED_SEARCHES[0]:
        if earliest != 0 or latest <= 900:
            return None
        return earliest, latest
    if name not in SAVED_SEARCHES[1:] or earliest < 0 or latest <= earliest:
        return None
    anchor_from_earliest = earliest + 24 * 60 * 60
    anchor_from_latest = latest - 15 * 60
    if anchor_from_earliest != anchor_from_latest or anchor_from_earliest % 300:
        return None
    return earliest, latest


def _job_messages_are_acceptable(name: str, content: dict) -> bool:
    messages = content.get("messages")
    if not isinstance(messages, list):
        return False
    if all(
        isinstance(message, dict) and str(message.get("type", "")).upper() == "INFO"
        for message in messages
    ):
        return True
    return name in SAVED_SEARCHES[1:] and _known_empty_summary_warning(content, [])


def _fixture_source_counts(paths: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            envelope = json.loads(line)
            source = _indexed_sourcetype(envelope)
            counts[source] = counts.get(source, 0) + 1
    return counts


def _indexed_sourcetype(envelope: dict) -> str:
    """Resolve only the documented TA index-time sourcetype rewrite."""
    sourcetype = str(envelope.get("sourcetype", ""))
    if (
        envelope.get("index") == "cisco_isovalent"
        and sourcetype == "cisco:isovalent"
        and isinstance(envelope.get("event"), dict)
        and isinstance(envelope["event"].get("process_connect"), dict)
    ):
        return "cisco:isovalent:processConnect"
    return sourcetype


def _history_receipt_baseline(rows: list[dict]) -> dict[str, tuple[float, float]]:
    """Validate and snapshot the pre-run collection receipt bounds by key."""
    baseline: dict[str, tuple[float, float]] = {}
    for row in rows:
        key = str(row.get("_key", ""))
        if not key or key in baseline:
            raise RuntimeError("history baseline contains a missing or duplicate key")
        first = _finite_number(row.get("received_time"))
        latest = _finite_number(row.get("latest_received_time"))
        if first is None or latest is None or first > latest:
            raise RuntimeError("history baseline receipt bounds are invalid")
        baseline[key] = (first, latest)
    return baseline


def _require_numeric_single_row(
    rows: list[dict], fields: tuple[str, ...], label: str
) -> dict:
    if len(rows) != 1:
        raise RuntimeError(f"{label} was incomplete")
    row = rows[0]
    for field in fields:
        try:
            value = float(row[field])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"{label} returned invalid {field}") from exc
        if not math.isfinite(value):
            raise RuntimeError(f"{label} returned invalid {field}")
    return row


def _finite_number(value) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _history_retention_mismatches(
    rows: list[dict], baseline: dict[str, tuple[float, float]]
) -> tuple[int, int, int]:
    """Compare retained history content and exact baseline+current receipts."""
    content_mismatches = 0
    receipt_mismatches = 0
    retained_count = 0
    for row in rows:
        key = str(row.get("_key", ""))
        stored_key = str(row.get("stored_key", ""))
        if key and key == stored_key:
            retained_count += 1
        if (
            not key
            or key != stored_key
            or not row.get("expected_content")
            or row.get("expected_content") != row.get("retained_content")
        ):
            content_mismatches += 1

        current_first = _finite_number(row.get("expected_first_received"))
        current_latest = _finite_number(row.get("expected_latest_received"))
        stored_first = _finite_number(row.get("stored_first_received"))
        stored_latest = _finite_number(row.get("stored_latest_received"))
        previous = baseline.get(key)
        if (
            current_first is None
            or current_latest is None
            or current_first > current_latest
        ):
            receipt_mismatches += 1
        elif stored_first is None or stored_latest is None:
            receipt_mismatches += 1
        else:
            expected_first = (
                min(current_first, previous[0]) if previous else current_first
            )
            expected_latest = (
                max(current_latest, previous[1]) if previous else current_latest
            )
            if (
                abs(stored_first - expected_first) > 1e-6
                or abs(stored_latest - expected_latest) > 1e-6
            ):
                receipt_mismatches += 1
    return content_mismatches, receipt_mismatches, retained_count


def _visible_input_watermark(
    rows: list[dict],
    expected_by_index: dict[str, int],
    expected_by_source: dict[str, int],
    expected_by_index_source: dict[str, dict[str, int]] | None = None,
) -> int | None:
    """Return an exclusive index-time watermark only for the full acked set."""
    actual_by_index: dict[str, int] = {}
    actual_by_source: dict[str, int] = {}
    actual_by_index_source: dict[str, dict[str, int]] = {}
    max_index_time = None
    for row in rows:
        index = str(row.get("index", ""))
        source = str(row.get("sourcetype", ""))
        if not index or not source:
            return None
        count = int(row.get("count", 0) or 0)
        actual_by_index[index] = actual_by_index.get(index, 0) + count
        actual_by_source[source] = actual_by_source.get(source, 0) + count
        source_counts = actual_by_index_source.setdefault(index, {})
        source_counts[source] = source_counts.get(source, 0) + count
        try:
            value = float(row["max_index_time"])
        except (KeyError, TypeError, ValueError):
            return None
        max_index_time = value if max_index_time is None else max(max_index_time, value)
    if (
        not rows
        or actual_by_index != expected_by_index
        or actual_by_source != expected_by_source
        or (
            expected_by_index_source is not None
            and actual_by_index_source != expected_by_index_source
        )
        or max_index_time is None
    ):
        return None
    return int(max_index_time) + 1


def _wait_for_acknowledged_input(
    started: int,
    fixture_earliest: int,
    fixture_latest: int,
    raw_indexes: list[str],
    expected_by_index: dict[str, int],
    expected_by_source: dict[str, int],
    expected_by_index_source: dict[str, dict[str, int]] | None = None,
    timeout_seconds: int = 300,
) -> int:
    """Wait until every HEC-acknowledged event is searchable, then close at max+1."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        rows = _search_complete(
            "(" + " OR ".join(f"index={name}" for name in raw_indexes) + ") "
            f"| where _indextime>={started} AND _time>={fixture_earliest} AND _time<{fixture_latest} "
            "| stats count AS count max(_indextime) AS max_index_time by index sourcetype",
            str(fixture_earliest),
            str(fixture_latest),
        )
        watermark = _visible_input_watermark(
            rows, expected_by_index, expected_by_source, expected_by_index_source
        )
        if watermark is not None:
            return watermark
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "not every HEC-acknowledged fixture event became searchable before the input watermark deadline"
            )
        time.sleep(2)


def _record_journal(path: Path, journal: dict) -> None:
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "existing operation journal is unreadable; refusing to overwrite it"
            ) from exc
        if (
            previous.get("operation_id") != journal.get("operation_id")
            and previous.get("state") != "complete"
        ):
            raise RuntimeError(
                "an existing unresolved operation journal must be reconciled first"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(journal, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tmp.chmod(0o600)
    tmp.replace(path)


def _saved_search(name: str) -> tuple[str, dict]:
    path = "/servicesNS/nobody/splunk_adm/saved/searches/" + quote(name, safe="")
    response = lab._json("GET", path)
    entries = response.get("entry")
    if (
        not isinstance(entries, list)
        or len(entries) != 1
        or not isinstance(entries[0].get("content"), dict)
    ):
        raise RuntimeError(f"saved search state unavailable: {name}")
    content = entries[0]["content"]
    if any(
        field not in content or not isinstance(content[field], (bool, int, str))
        for field in SCHEDULE_FIELDS
    ):
        raise RuntimeError(f"saved search schedule state unknown: {name}")
    schedule = {field: content[field] for field in SCHEDULE_FIELDS}
    schedule.update({field: content.get(field) for field in SCHEDULE_CONTRACT_FIELDS})
    if (
        content.get("cron_schedule") != EXPECTED_CRON[name]
        or (
            content.get("dispatch.index_earliest"),
            content.get("dispatch.index_latest"),
        )
        != EXPECTED_INDEX_WINDOWS[name]
    ):
        raise RuntimeError(
            f"saved search is not on the verified five-minute schedule: {name}"
        )
    return path, schedule


def _boolean(value) -> bool | None:
    if value is True or str(value).lower() in {"1", "true", "yes"}:
        return True
    if value is False or str(value).lower() in {"0", "false", "no"}:
        return False
    return None


def _search_complete(
    spl: str,
    earliest: str,
    latest: str,
    *,
    index_earliest: str | None = None,
    index_latest: str | None = None,
    allow_empty_summary_warning: bool = False,
) -> list[dict]:
    data = {
        "search": lab._query(spl),
        "exec_mode": "blocking",
        "earliest_time": earliest,
        "latest_time": latest,
    }
    if index_earliest is not None:
        data["index_earliest"] = index_earliest
    if index_latest is not None:
        data["index_latest"] = index_latest
    with lab._mgmt(
        "POST",
        f"/servicesNS/admin/{lab.APP}/search/v2/jobs?output_mode=json",
        data,
        900,
    ) as response:
        sid = json.load(response)["sid"]
    status = lab._wait_job(sid)
    rows = lab._results(sid)
    try:
        require_complete(status, rows)
    except RuntimeError:
        if not allow_empty_summary_warning or not _known_empty_summary_warning(
            status, rows
        ):
            raise
    return rows


def _known_empty_summary_warning(status: dict, rows: list[dict]) -> bool:
    """Accept only Splunk's exact no-results warning for an empty rollup job."""
    if (
        status.get("dispatchState") != "DONE"
        or status.get("isDone") is not True
        or status.get("isFinalized") is not False
        or status.get("eventIsTruncated") is not False
        or str(status.get("dropCount")) != "0"
        or str(status.get("resultCount")) != "0"
        or rows
    ):
        return False
    messages = status.get("messages")
    if not isinstance(messages, list):
        return False
    warnings = [
        message
        for message in messages
        if isinstance(message, dict) and str(message.get("type", "")).upper() == "WARN"
    ]
    if len(warnings) != 1 or warnings[0].get("text") != "No results to summary index.":
        return False
    return all(
        isinstance(message, dict)
        and str(message.get("type", "")).upper() in {"INFO", "WARN"}
        for message in messages
    )


def _search_job_metadata_path(sid: str) -> str:
    return f"/servicesNS/nobody/{lab.APP}/search/jobs/{quote(sid, safe='')}"


def _sample(
    started: int,
    end: int,
    fixture_earliest: int,
    fixture_latest: int,
    raw_indexes: list[str],
    expected_raw: dict[str, int],
    expected_sources: dict[str, int] | None = None,
    producer_stop_index_time: int | None = None,
    final_drain: bool = False,
    baseline_history_receipts: dict[str, tuple[float, float]] | None = None,
) -> dict:
    sched_rows = _search_complete(
        'index=_internal source=*scheduler.log* app="splunk_adm" '
        f"| where _time>={started} AND savedsearch_name IN ({', '.join(json.dumps(name) for name in SAVED_SEARCHES)}) "
        "| sort 0 -_time | dedup sid | table _time savedsearch_name scheduled_time dispatch_time status sid run_time reason",
        str(started),
        str(end),
    )
    fresh_cycles = {}
    max_duration: float | None = None
    active_jobs = []
    for row in sched_rows:
        sid = str(row.get("sid", ""))
        if not sid or not sid.startswith("scheduler__"):
            continue
        name = str(row.get("savedsearch_name", ""))
        status = str(row.get("status", "unknown")).lower()
        if status in {"continued", "running", "in_progress"}:
            active_jobs.append(name)
            continue
        runtime = _finite_float(row.get("run_time"))
        if runtime is not None:
            max_duration = (
                runtime if max_duration is None else max(max_duration, runtime)
            )
        scheduled = _finite_float(row.get("scheduled_time"))
        dispatch_time = _finite_float(row.get("dispatch_time"))
        latency = (
            max(0.0, dispatch_time - scheduled)
            if scheduled is not None and dispatch_time is not None
            else None
        )
        fresh_cycles.setdefault(name, []).append(
            {
                "sid": sid,
                "scheduled_time": scheduled,
                "status": status,
                "run_duration_seconds": runtime,
                "schedule_latency_seconds": latency,
                "reason": row.get("reason"),
            }
        )

    for name, cycles in fresh_cycles.items():
        for cycle in cycles:
            if cycle["status"] != "success":
                continue
            sid = cycle["sid"]
            cycle["search_window"] = None
            try:
                response = lab._json(
                    "GET",
                    _search_job_metadata_path(sid),
                )
                entries = response.get("entry")
                if not isinstance(entries, list) or len(entries) != 1:
                    cycle["window_metadata_complete"] = False
                    continue
                search_window = _resolved_search_window(name, entries[0])
                bounds = _resolved_scheduler_window(name, entries[0])
                cycle["search_window"] = (
                    list(search_window) if search_window is not None else None
                )
            except Exception:
                bounds = None
            cycle["input_window"] = list(bounds) if bounds else None
            cycle["window_metadata_complete"] = (
                bounds is not None and cycle["search_window"] is not None
            )

    # Only input slices whose scheduled search completed successfully count as
    # processed. The resolved request window on the completed job is the source
    # of truth; neither the SID timestamp nor observed index extrema count.
    def completed_windows(name):
        windows = set()
        for cycle in fresh_cycles.get(name, []):
            bounds = cycle.get("input_window")
            if cycle["status"] != "success" or not bounds:
                continue
            windows.add(tuple(map(int, bounds)))
        return sorted(windows)

    history_windows = completed_windows(SAVED_SEARCHES[0])
    conversation_windows = completed_windows(SAVED_SEARCHES[1])
    traffic_windows = completed_windows(SAVED_SEARCHES[2])
    coverage_end = (
        producer_stop_index_time if producer_stop_index_time is not None else end
    )
    history_covered = _windows_cover_interval(history_windows, started, coverage_end)
    conversation_covered = _windows_cover_interval(
        conversation_windows, started, coverage_end
    )
    traffic_covered = _windows_cover_interval(traffic_windows, started, coverage_end)

    def window_filter(windows, field):
        return (
            " OR ".join(f"({field}>={lo} AND {field}<{hi})" for lo, hi in windows)
            or "false()"
        )

    raw = _search_complete(
        "(" + " OR ".join(f"index={name}" for name in raw_indexes) + ") "
        f"| where _indextime>={started} AND _indextime<{end} AND _time>={fixture_earliest} AND _time<{fixture_latest} "
        "| stats count AS count dc(sha256(_raw)) AS unique_count by index sourcetype",
        str(fixture_earliest),
        str(fixture_latest),
    )
    actual: dict[str, int] = {}
    actual_sources: dict[str, int] = {}
    for row in raw:
        index = str(row["index"])
        source = str(row["sourcetype"])
        count = int(row["count"])
        actual[index] = actual.get(index, 0) + count
        actual_sources[source] = actual_sources.get(source, 0) + count
    raw_count = sum(actual.values())
    raw_expected_count = sum(expected_raw.values())
    if actual != expected_raw:
        # Keep the mismatch visible in the sample; the final assessment blocks completion.
        pass

    history_expected_content = (
        "sha256(json_array(" + ",".join(HISTORY_CONTENT_FIELDS.split()) + "))"
    )
    history_retained_content = (
        "sha256(json_array("
        + ",".join("stored_" + field for field in HISTORY_CONTENT_FIELDS.split())
        + "))"
    )
    history_rows = _search_complete(
        f"| `adm_network_client_history_observations` | where received_time>={started} AND received_time<{end} AND ({window_filter(history_windows, 'received_time')}) "
        "| stats first(contract_version) AS contract_version first(source) AS source first(source_authority) AS source_authority "
        "first(native_id) AS native_id first(event_fingerprint) AS event_fingerprint first(client_mac) AS client_mac "
        "first(client_ip) AS client_ip first(scope) AS scope first(cluster) AS cluster first(routing_domain) AS routing_domain "
        "first(adm_domain_kind) AS domain_kind first(adm_profile) AS profile first(mapping_status) AS mapping_status "
        "first(source_time) AS source_time first(collected_time) AS collected_time first(event_type) AS event_type "
        "first(client_type) AS client_type first(connected_device_type) AS connected_device_type "
        "first(attachment_status) AS attachment_status first(attachment_basis) AS attachment_basis "
        "first(attachment_device_id) AS attachment_device_id first(attachment_device_name) AS attachment_device_name "
        "first(attachment_device_mac) AS attachment_device_mac first(device_serial) AS device_serial "
        "first(ssid_number) AS ssid_number first(interface) AS interface first(quality_reason) AS quality_reason "
        "first(raw_ref) AS raw_ref min(received_time) AS expected_first_received "
        "max(received_time) AS expected_latest_received by _key "
        "| lookup local=true adm_network_client_history _key OUTPUT _key AS stored_key "
        "received_time AS stored_first_received latest_received_time AS stored_latest_received "
        "contract_version AS stored_contract_version source AS stored_source "
        "source_authority AS stored_source_authority native_id AS stored_native_id "
        "event_fingerprint AS stored_event_fingerprint client_mac AS stored_client_mac "
        "client_ip AS stored_client_ip scope AS stored_scope cluster AS stored_cluster "
        "routing_domain AS stored_routing_domain domain_kind AS stored_domain_kind profile AS stored_profile "
        "mapping_status AS stored_mapping_status source_time AS stored_source_time "
        "collected_time AS stored_collected_time event_type AS stored_event_type client_type AS stored_client_type "
        "connected_device_type AS stored_connected_device_type attachment_status AS stored_attachment_status "
        "attachment_basis AS stored_attachment_basis attachment_device_id AS stored_attachment_device_id "
        "attachment_device_name AS stored_attachment_device_name attachment_device_mac AS stored_attachment_device_mac "
        "device_serial AS stored_device_serial ssid_number AS stored_ssid_number interface AS stored_interface "
        "quality_reason AS stored_quality_reason raw_ref AS stored_raw_ref "
        f"| eval expected_content={history_expected_content}, retained_content={history_retained_content} "
        "| fields _key stored_key expected_content retained_content expected_first_received "
        "expected_latest_received stored_first_received stored_latest_received",
        str(fixture_earliest),
        str(end),
    )
    (
        history_content_mismatch,
        history_receipt_mismatch,
        retained_history,
    ) = _history_retention_mismatches(history_rows, baseline_history_receipts or {})
    mapped_client_rows = _search_complete(
        f'| `adm_network_client_history_observations` | where received_time>={started} AND received_time<{end} AND ({window_filter(history_windows, "received_time")}) AND mapping_status="mapped" '
        "| stats dc(client_mac) AS mapped_clients",
        str(fixture_earliest),
        str(end),
    )
    if len(mapped_client_rows) != 1:
        raise RuntimeError("mapped client identity comparison was incomplete")
    all_history_rows = _search_complete(
        f"| `adm_network_client_history_observations` | where received_time>={started} AND received_time<{coverage_end} "
        "| dedup _key | stats dc(_key) AS expected",
        str(fixture_earliest),
        str(end),
    )
    traffic_fields = " ".join(TRAFFIC_CONTENT_FIELDS.split())
    traffic_cycles = [
        cycle
        for cycle in fresh_cycles.get(SAVED_SEARCHES[2], [])
        if cycle.get("status") == "success"
        and cycle.get("input_window")
        and cycle.get("search_window")
    ]
    traffic_expected_rows = _traffic_expected_rows(traffic_cycles)
    traffic_retained_rows = _search_complete(
        _traffic_retained_search(started, end, traffic_fields),
        "0",
        "+10y",
    )
    traffic_identity_row = _traffic_identity_comparison(
        traffic_expected_rows, traffic_retained_rows
    )
    mapped_traffic_rows = _search_complete(
        f"| `adm_flows_v2` | where _indextime>={started} AND _indextime<{end} AND ({window_filter(traffic_windows, '_indextime')}) "
        'AND adm_source="netflow" AND adm_quality_status!="excluded" AND adm_profile_status="mapped" '
        "| stats dc(adm_event_id) AS expected",
        str(fixture_earliest),
        str(end),
    )
    mapped_retained_rows = _search_complete(
        'index=adm_summary_v2 source="adm:traffic_observation" '
        f"| where _indextime>={started} AND _indextime<{end} AND ({window_filter(traffic_windows, 'received_time')}) "
        "| join type=inner max=50000 rollup_id "
        f"[| `adm_flows_v2` | where _indextime>={started} AND _indextime<{end} AND ({window_filter(traffic_windows, '_indextime')}) "
        'AND adm_source="netflow" AND adm_quality_status!="excluded" AND adm_profile_status="mapped" '
        "| rename adm_event_id AS rollup_id | dedup rollup_id | fields rollup_id] "
        "| stats dc(rollup_id) AS retained",
        str(fixture_earliest),
        str(end),
    )
    all_traffic_rows = _search_complete(
        f"| `adm_flows_v2` | where _indextime>={started} AND _indextime<{coverage_end} "
        'AND adm_source="netflow" AND adm_quality_status!="excluded" AND adm_profile_status="mapped" '
        "| stats dc(adm_event_id) AS expected",
        str(fixture_earliest),
        str(end),
    )
    if (
        len(all_history_rows) != 1
        or len(mapped_traffic_rows) != 1
        or len(mapped_retained_rows) != 1
        or len(all_traffic_rows) != 1
    ):
        raise RuntimeError("full-run identity comparison was incomplete")

    conversation_comparison = {
        "expected_unique": 0,
        "retained_unique": 0,
        "identity_mismatch": 0,
        "content_mismatch": 0,
        "duplicate_count": 0,
        "expected_duplicate_count": 0,
        "conflicting_count": 0,
        "invalid_identity_count": 0,
    }
    if final_drain:
        conversation_expected_rows = []
        for cycle in fresh_cycles.get(SAVED_SEARCHES[1], []):
            input_window = cycle.get("input_window")
            event_window = cycle.get("search_window")
            if cycle.get("status") != "success" or not input_window or not event_window:
                continue
            lower, upper = input_window
            event_earliest, event_latest = event_window
            expected_rows = _search_complete(
                "| `adm_conversation_rollup_v2`",
                str(event_earliest),
                str(event_latest),
                index_earliest=str(lower),
                index_latest=str(upper),
                allow_empty_summary_warning=True,
            )
            conversation_expected_rows.extend(expected_rows)
        conversation_fields = " ".join(CONVERSATION_CONTENT_FIELDS.split())
        retained_rows = _search_complete(
            'index=adm_summary_v2 source="adm:conversation" '
            f"| where _indextime>={started} AND _indextime<{end} "
            f"| fields {conversation_fields}",
            str(fixture_earliest),
            str(end),
        )
        conversation_comparison = _conversation_identity_comparison(
            conversation_expected_rows, retained_rows
        )

    eligible_traffic = int(mapped_traffic_rows[0].get("expected", 0) or 0)
    retained_traffic = int(mapped_retained_rows[0].get("retained", 0) or 0)
    expected_history = len(history_rows)
    all_history = int(all_history_rows[0].get("expected", 0) or 0)
    all_traffic = int(all_traffic_rows[0].get("expected", 0) or 0)
    pending_history = max(0, all_history - expected_history)
    pending_traffic = max(0, all_traffic - eligible_traffic)
    pending = pending_history + pending_traffic
    # Count only closed, scheduled input windows as backlog during production.
    # The newest tail is reported separately until its writer windows close.
    backlog = max(0, eligible_traffic - retained_traffic)
    return {
        "observed_at": time.time(),
        "required_jobs": list(SAVED_SEARCHES),
        "job_cycles": fresh_cycles,
        "active_jobs": sorted(set(active_jobs)),
        "final_drain": final_drain,
        "producer_stop_index_time": producer_stop_index_time,
        "history_window_coverage": history_covered,
        "conversation_window_coverage": conversation_covered,
        "traffic_window_coverage": traffic_covered,
        "scheduled_input_coverage": (
            history_covered and conversation_covered and traffic_covered
        ),
        "pending_history_count": pending_history,
        "pending_traffic_count": pending_traffic,
        "pending_input_count": pending,
        "max_run_duration_seconds": max_duration,
        "raw_count": raw_count,
        "raw_expected_count": raw_expected_count,
        "raw_counts_by_index": actual,
        "raw_expected_by_index": expected_raw.copy(),
        "raw_counts_by_source": actual_sources,
        "raw_expected_by_source": (expected_sources or {}).copy(),
        "raw_counts_match": actual == expected_raw,
        "raw_source_counts_match": actual_sources == (expected_sources or {}),
        "raw_unique_count": sum(int(row.get("unique_count", 0)) for row in raw),
        "history_count": expected_history,
        "history_expected_unique": expected_history,
        "history_unique_count": retained_history,
        "history_content_mismatch": history_content_mismatch,
        "history_receipt_mismatch": history_receipt_mismatch,
        "mapped_client_count": int(mapped_client_rows[0].get("mapped_clients", 0) or 0),
        "traffic_count": int(traffic_identity_row["retained_unique"]),
        "traffic_content_mismatch": int(traffic_identity_row["content_mismatch"]),
        "traffic_identity_mismatch_count": int(
            traffic_identity_row["identity_mismatch"]
        ),
        "traffic_duplicate_rollup_ids": int(traffic_identity_row["duplicate_count"]),
        "traffic_expected_duplicate_rollup_ids": int(
            traffic_identity_row["expected_duplicate_count"]
        ),
        "traffic_conflicting_rollup_ids": int(
            traffic_identity_row["conflicting_count"]
        ),
        "traffic_invalid_identity_count": int(
            traffic_identity_row["invalid_identity_count"]
        ),
        "conversation_expected_unique": conversation_comparison["expected_unique"],
        "conversation_unique_count": conversation_comparison["retained_unique"],
        "conversation_identity_mismatch_count": conversation_comparison[
            "identity_mismatch"
        ],
        "conversation_content_mismatch": conversation_comparison["content_mismatch"],
        "conversation_duplicate_rollup_ids": conversation_comparison["duplicate_count"],
        "conversation_expected_duplicate_rollup_ids": conversation_comparison[
            "expected_duplicate_count"
        ],
        "conversation_conflicting_rollup_ids": conversation_comparison[
            "conflicting_count"
        ],
        "conversation_invalid_identity_count": conversation_comparison[
            "invalid_identity_count"
        ],
        "traffic_expected_unique": int(traffic_identity_row["expected_unique"]),
        "traffic_unique_count": int(traffic_identity_row["retained_unique"]),
        "mapped_traffic_expected_unique": eligible_traffic,
        "mapped_traffic_retained_unique": retained_traffic,
        "unprocessed_backlog": backlog,
    }


def _fixture_files(directory: Path) -> tuple[list[Path], dict, int, int]:
    # Generate only the repository's TA-grounded Cisco scenario. The bounded
    # rate is applied by paced HEC submission; this does not synthesize fields.
    # Put fixture event time safely behind wall clock so both event-time
    # searches and the scheduled index-time windows can see the full corpus.
    base = (
        datetime.fromtimestamp(time.time() - 3600, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/gen_raw_fixtures.py"),
            "--scenario",
            "networking",
            "--base-time",
            base,
            "--output-dir",
            str(directory),
        ],
        check=True,
        cwd=ROOT,
    )
    manifest = json.loads(
        (directory / "capture-manifest.json").read_text(encoding="utf-8")
    )
    paths = [directory / name for name in manifest["output_events"]]
    if not paths or any(not path.is_file() for path in paths):
        raise RuntimeError("TA-grounded generator returned missing event files")
    event_count = sum(
        1
        for path in paths
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    if event_count == 0:
        raise RuntimeError("TA-grounded generator returned no events")
    window = manifest["ingestion_window"]
    fixture_earliest = int(datetime.fromisoformat(window["start"]).timestamp())
    fixture_latest = int(datetime.fromisoformat(window["end"]).timestamp()) + 1
    return paths, manifest, fixture_earliest, fixture_latest


def _fixture_lines(paths: list[Path]) -> list[tuple[bytes, str, str]]:
    lines = []
    for path in paths:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"invalid generated event at {path}:{line_number}"
                ) from exc
            index = envelope.get("index")
            sourcetype = _indexed_sourcetype(envelope)
            if not isinstance(index, str) or not index:
                raise RuntimeError(
                    f"generated event lacks an index at {path}:{line_number}"
                )
            if not isinstance(sourcetype, str) or not sourcetype:
                raise RuntimeError(
                    f"generated event lacks a sourcetype at {path}:{line_number}"
                )
            lines.append((line.encode("utf-8"), index, sourcetype))
    if not lines:
        raise RuntimeError("TA-grounded fixture corpus is empty")
    return lines


def _produce_load(
    paths: list[Path],
    events_per_second: int,
    stop: threading.Event,
    counts: dict,
    lock: threading.Lock,
    errors: list[Exception],
) -> None:
    """Replay only generated fixture records at the requested bounded rate."""
    try:
        lines = _fixture_lines(paths)
        cursor = 0
        batch_size = events_per_second
        while not stop.is_set():
            batch = [
                lines[(cursor + offset) % len(lines)] for offset in range(batch_size)
            ]
            batch_started = time.monotonic()
            with lock:
                lab._hec_post(b"\n".join(line for line, _index, _source in batch))
                counts["raw"] += len(batch)
                for _line, index, source in batch:
                    counts["by_index"][index] = counts["by_index"].get(index, 0) + 1
                    counts["by_source"][source] = counts["by_source"].get(source, 0) + 1
                    pair_counts = counts["by_index_source"].setdefault(index, {})
                    pair_counts[source] = pair_counts.get(source, 0) + 1
            cursor = (cursor + batch_size) % len(lines)
            remaining = 1.0 - (time.monotonic() - batch_started)
            if remaining > 0:
                stop.wait(remaining)
    except Exception as exc:
        errors.append(exc)
        stop.set()


def run_probe(config: ProbeConfig, journal_path: Path) -> dict:
    config.validate()
    require_local_lab(lab)
    started_epoch = int(time.time())
    journal = {
        "operation": "cisco-local-load-probe",
        "operation_id": f"{started_epoch}-{uuid.uuid4().hex}",
        "state": "preparing",
        "started_at": started_epoch,
        "scheduler": {},
        "samples": [],
    }
    _record_journal(journal_path, journal)
    paths_and_states = {}
    mutation_pending = False
    changed_names: list[str] = []
    producer_stop = threading.Event()
    producer_lock = threading.Lock()
    producer_counts = {
        "raw": 0,
        "by_index": {},
        "by_source": {},
        "by_index_source": {},
    }
    producer_errors: list[Exception] = []
    producer = None
    temp_dir = Path(tempfile.mkdtemp(prefix="adm-cisco-load-"))
    previous_signal_handlers = {}

    def interrupt_probe(signum, _frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_signal_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, interrupt_probe)
    try:
        paths, manifest, fixture_earliest, fixture_latest = _fixture_files(temp_dir)
        journal["fixture_manifest"] = manifest
        fixture_source_counts = _fixture_source_counts(paths)
        journal["fixture_sourcetype_counts"] = fixture_source_counts
        journal["fixture_files"] = {
            path.name: {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
            for path in paths
        }
        journal["fixture_event_window"] = [fixture_earliest, fixture_latest]
        _record_journal(journal_path, journal)
        raw_indexes = sorted(manifest["index_events"])
        for name in SAVED_SEARCHES:
            path, saved = _saved_search(name)
            if any(_boolean(saved[field]) is None for field in SCHEDULE_FIELDS):
                raise RuntimeError(f"unrecognized schedule state: {name}")
            paths_and_states[name] = (path, saved)
        journal["scheduler"] = {
            name: state for name, (_, state) in paths_and_states.items()
        }
        journal["state"] = "scheduler_state_captured"
        _record_journal(journal_path, journal)

        baseline_rows = _search_complete(
            "| inputlookup strict=true adm_network_client_history "
            "| table _key received_time latest_received_time",
            "0",
            "+10y",
        )
        baseline_history_receipts = _history_receipt_baseline(baseline_rows)
        journal["history_baseline_key_count"] = len(baseline_history_receipts)
        _record_journal(journal_path, journal)

        # Keep shipped cron and dispatch windows intact. Journal intent before
        # each mutating call so an unknown response always triggers fail-closed.
        for name, (path, _) in paths_and_states.items():
            journal.update(state="schedule_change_pending", pending_schedule=name)
            _record_journal(journal_path, journal)
            mutation_pending = True
            lab._json("POST", path, {"disabled": "0", "is_scheduled": "1"})
            changed_names.append(name)
            mutation_pending = False
            _, verified = _saved_search(name)
            if (
                _boolean(verified["disabled"]) is not False
                or _boolean(verified["is_scheduled"]) is not True
            ):
                raise RuntimeError(f"scheduler state did not confirm enabled: {name}")
        journal["state"] = "schedules_enabled"
        _record_journal(journal_path, journal)

        started_epoch = int(time.time())
        producer = threading.Thread(
            target=_produce_load,
            args=(
                paths,
                config.events_per_second,
                producer_stop,
                producer_counts,
                producer_lock,
                producer_errors,
            ),
            daemon=True,
        )
        producer.start()
        producer_started_monotonic = time.monotonic()
        journal.update(
            state="sustained_load_started",
            measurement_started_at=started_epoch,
            raw_indexes=raw_indexes,
            fixture_event_window=[fixture_earliest, fixture_latest],
        )
        _record_journal(journal_path, journal)
        measurement_started = time.monotonic()
        end = measurement_started + config.duration_seconds
        while time.monotonic() < end:
            if producer_errors:
                raise RuntimeError(f"fixture producer failed: {producer_errors[0]}")
            with producer_lock:
                expected_raw = producer_counts["by_index"].copy()
                expected_sources = producer_counts["by_source"].copy()
                sample_end = int(time.time())
            if not _positive_time_window(started_epoch, sample_end):
                time.sleep(min(1, max(0, end - time.monotonic())))
                continue
            sample = _sample(
                started_epoch,
                sample_end,
                fixture_earliest,
                fixture_latest,
                raw_indexes,
                expected_raw,
                expected_sources=expected_sources,
                baseline_history_receipts=baseline_history_receipts,
            )
            journal["samples"].append(sample)
            journal["state"] = "observing"
            _record_journal(journal_path, journal)
            time.sleep(min(10, max(0, end - time.monotonic())))

        producer_stop.set()
        producer.join(timeout=130)
        if producer.is_alive():
            raise RuntimeError(
                "fixture producer did not stop within the HEC request timeout"
            )
        if producer_errors:
            raise RuntimeError(f"fixture producer failed: {producer_errors[0]}")
        producer_stop_monotonic = time.monotonic()
        with producer_lock:
            acknowledged_by_index = producer_counts["by_index"].copy()
            acknowledged_by_source = producer_counts["by_source"].copy()
            acknowledged_by_index_source = {
                index: counts.copy()
                for index, counts in producer_counts["by_index_source"].items()
            }
        producer_stop_index_time = _wait_for_acknowledged_input(
            started_epoch,
            fixture_earliest,
            fixture_latest,
            raw_indexes,
            acknowledged_by_index,
            acknowledged_by_source,
            acknowledged_by_index_source,
        )
        producer_active_seconds = max(
            0.001, producer_stop_monotonic - producer_started_monotonic
        )
        journal.update(
            producer_stop_index_time=producer_stop_index_time,
            producer_acknowledged_input_visible=True,
            producer_active_seconds=round(producer_active_seconds, 3),
        )
        _record_journal(journal_path, journal)

        # Drain the final closed input window and wait for two completed cycles
        # per required search and contiguous schedule windows through the last
        # producer index time. The production cadence remains the shipped 5m.
        drain_deadline = time.monotonic() + 900
        while True:
            with producer_lock:
                expected_raw = producer_counts["by_index"].copy()
                expected_sources = producer_counts["by_source"].copy()
                sample_end = int(time.time())
            sample = _sample(
                started_epoch,
                sample_end,
                fixture_earliest,
                fixture_latest,
                raw_indexes,
                expected_raw,
                expected_sources=expected_sources,
                producer_stop_index_time=producer_stop_index_time,
                final_drain=True,
                baseline_history_receipts=baseline_history_receipts,
            )
            journal["samples"].append(sample)
            assessment = assess_samples(journal["samples"])
            journal.update(state="draining", assessment=assessment)
            _record_journal(journal_path, journal)
            if assessment["complete"]:
                break
            if time.monotonic() >= drain_deadline:
                raise RuntimeError(
                    "scheduled writers did not cover and drain the complete producer input window"
                )
            time.sleep(10)

        assessment = assess_samples(journal["samples"])
        if not assessment["complete"]:
            journal.update(state="unresolved", assessment=assessment)
            _record_journal(journal_path, journal)
            raise RuntimeError(
                "probe evidence is incomplete or identifies a regression"
            )

        # Restore previous scheduler state only after complete evidence.
        for name, (path, saved) in paths_and_states.items():
            journal.update(state="restore_pending", pending_schedule=name)
            _record_journal(journal_path, journal)
            mutation_pending = True
            lab._json(
                "POST",
                path,
                {
                    field: str(saved[field]).lower()
                    if isinstance(saved[field], bool)
                    else str(saved[field])
                    for field in SCHEDULE_FIELDS
                },
            )
            _, verified = _saved_search(name)
            if any(
                _boolean(verified[field]) != _boolean(saved[field])
                for field in SCHEDULE_FIELDS
            ):
                raise RuntimeError(f"restored scheduler state did not verify: {name}")
            if any(
                verified[field] != saved[field] for field in SCHEDULE_CONTRACT_FIELDS
            ):
                raise RuntimeError(
                    f"saved search cadence/bounds changed during probe: {name}"
                )
            mutation_pending = False

        journal.update(
            state="complete",
            finished_at=int(time.time()),
            evidence_class=config.evidence_class,
            measurement_scope=(
                "Raw ingestion, scheduled history/v2 retention, and observed scheduler "
                "latency/capacity only; does not qualify client attachment or end-to-end path correlation."
            ),
            configuration=asdict(config),
            producer_counts=producer_counts,
            production_duration_seconds=round(producer_active_seconds, 3),
            observed_events_per_second=round(
                producer_counts["raw"] / producer_active_seconds,
                3,
            ),
            assessment=assessment,
        )
        _record_journal(journal_path, journal)
        return journal
    except (Exception, KeyboardInterrupt) as exc:
        journal.update(
            state="unresolved",
            error=f"{type(exc).__name__}: {exc}",
            finished_at=int(time.time()),
        )
        if producer is not None and producer.is_alive():
            producer_stop.set()
            producer.join(timeout=130)
        if mutation_pending or changed_names:
            for name, (path, _) in paths_and_states.items():
                try:
                    lab._json("POST", path, {"disabled": "1", "is_scheduled": "0"})
                    journal.setdefault("fail_closed", {})[name] = "disabled_confirmed"
                except Exception:
                    journal.setdefault("fail_closed", {})[name] = "unconfirmed"
        _record_journal(journal_path, journal)
        raise
    finally:
        import shutil

        for signum, handler in previous_signal_handlers.items():
            signal.signal(signum, handler)

        if producer is None or not producer.is_alive():
            shutil.rmtree(temp_dir, ignore_errors=True)
            journal["fixture_cleanup"] = "removed"
            _record_journal(journal_path, journal)
        else:
            journal["fixture_cleanup"] = "pending_producer_stop"
            journal["fixture_cleanup_path"] = str(temp_dir)
            _record_journal(journal_path, journal)


@with_lab_lock(root=ROOT)
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-local-lab-state-change",
        action="store_true",
        required=True,
        help="acknowledge adding generated events and temporarily changing only the three Cisco schedules",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=900,
        help="bounded sustained-load duration in seconds (620..3600); shipped 5-minute schedules are unchanged",
    )
    parser.add_argument(
        "--events-per-second",
        type=int,
        default=5,
        help="bounded fixture submission rate (1..250)",
    )
    parser.add_argument(
        "--journal", type=Path, default=ROOT / "dist/cisco-load-probe.json"
    )
    args = parser.parse_args()
    config = ProbeConfig(args.duration, args.events_per_second)
    config.validate()
    result = run_probe(config, args.journal.resolve())
    print(
        json.dumps(
            {
                "state": result["state"],
                "evidence_class": result["evidence_class"],
                "assessment": result["assessment"],
                "journal": str(args.journal),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_main(main, root=ROOT))
