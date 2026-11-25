"""Offline scenario templates and immutable run-plan helpers.

This module never starts a service, contacts a source, or writes a plan unless
the caller explicitly supplies a destination. Scenario templates describe
relative facts and assertions; product adapters remain responsible for native
source parsing and records.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.change_correlation.contracts import canonical_json

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCENARIO_ROOT = ROOT / "fixtures" / "change-correlation" / "scenarios"
SCENARIO_IDS = ("track-a-firewall", "track-b-fabric")
TEMPLATE_REVISION = 2
PLAN_KIND = "configuration-change-run-plan-v1"
MINIMUM_T_LEAD_SECONDS = 180
DEFAULT_T_LEAD_SECONDS = 300
MAX_PLAN_BYTES = 512 * 1024
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class ScenarioError(ValueError):
    """Safe validation error for templates, readiness, and run plans."""


def sha256_hex(value: bytes | Any) -> str:
    content = value if isinstance(value, bytes) else canonical_json(value)
    return hashlib.sha256(content).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _epoch(value: Any, label: str) -> int:
    if not _is_int(value) or value < 0 or value > 253_402_300_799:
        raise ScenarioError(f"{label} must be an integer UTC epoch in range.")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ScenarioError(f"{label} must be a lowercase SHA-256 digest.")
    return value


def _utc(epoch: int) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def load_scenario(scenario_id: str) -> dict[str, Any]:
    """Load one of the two approved scenario templates by its stable ID."""

    if scenario_id not in SCENARIO_IDS:
        raise ScenarioError("Unknown change scenario ID.")
    path = SCENARIO_ROOT / f"{scenario_id}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScenarioError("Scenario template cannot be read as JSON.") from exc
    validate_scenario(payload, expected_id=scenario_id)
    return payload


def scenario_template_hash(scenario: dict[str, Any]) -> str:
    validate_scenario(scenario)
    return sha256_hex(scenario)


def validate_scenario(
    scenario: Any, *, expected_id: str | None = None
) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        raise ScenarioError("Scenario template must be an object.")
    scenario_id = scenario.get("scenario_id")
    if scenario_id not in SCENARIO_IDS or (
        expected_id is not None and scenario_id != expected_id
    ):
        raise ScenarioError("Scenario ID is not one of the two approved tracks.")
    if scenario.get("schema_version") != 1 or scenario.get("template_revision") != 2:
        raise ScenarioError("Scenario schema or template revision is unsupported.")
    if not isinstance(scenario.get("title"), str) or not scenario["title"].strip():
        raise ScenarioError("Scenario title is required.")
    app = scenario.get("application")
    if not isinstance(app, dict) or set(app) != {
        "service",
        "environment",
        "cluster",
        "namespace",
    }:
        raise ScenarioError("Application selection must contain four dimensions.")
    if any(not isinstance(value, str) or not value for value in app.values()):
        raise ScenarioError("Application dimensions must be non-empty text.")
    selection = scenario.get("selection")
    if not isinstance(selection, dict) or not isinstance(
        selection.get("change_scope"), str
    ):
        raise ScenarioError("Scenario selection must include its change scope.")
    clock = scenario.get("clock")
    if not isinstance(clock, dict):
        raise ScenarioError("Scenario clock is missing.")
    if (
        clock.get("basis") != "utc_epoch_seconds_with_monotonic_waits"
        or clock.get("prelude_offset_seconds") != -120
        or clock.get("minimum_t_lead_seconds") != MINIMUM_T_LEAD_SECONDS
        or clock.get("duration_seconds") != 1200
    ):
        raise ScenarioError("Scenario must use the approved 20-minute phase clock.")
    phases = clock.get("phases")
    if not isinstance(phases, list) or len(phases) != 4:
        raise ScenarioError("Scenario requires four ordered phases.")
    expected_phases = [
        ("baseline", 0, 300),
        ("change", 300, 420),
        ("impact", 420, 900),
        ("recovery", 900, 1200),
    ]
    actual_phases = [
        (
            phase.get("id"),
            phase.get("start_offset_seconds"),
            phase.get("end_offset_seconds"),
        )
        if isinstance(phase, dict)
        else None
        for phase in phases
    ]
    if actual_phases != expected_phases:
        raise ScenarioError("Scenario phase windows do not match revision 2.")
    schedule = scenario.get("evidence_schedule")
    if not isinstance(schedule, list) or not schedule:
        raise ScenarioError("Scenario evidence schedule is empty.")
    schedule_ids: set[str] = set()
    for event in schedule:
        if not isinstance(event, dict):
            raise ScenarioError("Scenario schedule entries must be objects.")
        event_id = event.get("id")
        if not isinstance(event_id, str) or not re.fullmatch(
            r"[a-z0-9-]{1,80}", event_id
        ):
            raise ScenarioError("Scenario schedule entry has an invalid ID.")
        if event_id in schedule_ids:
            raise ScenarioError("Scenario schedule entry IDs must be unique.")
        schedule_ids.add(event_id)
        if event.get("status") not in {"planned", "blocked"}:
            raise ScenarioError("Scenario schedule status is unsupported.")
        if not isinstance(event.get("product"), str) or not isinstance(
            event.get("family"), str
        ):
            raise ScenarioError("Scenario schedule entry requires a product family.")
        has_offset = "offset_seconds" in event
        has_window = (
            "window_start_offset_seconds" in event
            or "window_end_offset_seconds" in event
        )
        if has_offset == has_window:
            raise ScenarioError("Schedule entry needs one instant or one interval.")
        if has_offset:
            offset = event["offset_seconds"]
            if not _is_int(offset) or not -120 <= offset <= clock["duration_seconds"]:
                raise ScenarioError("Schedule instant is outside the phase clock.")
        else:
            start, end = (
                event.get("window_start_offset_seconds"),
                event.get("window_end_offset_seconds"),
            )
            if (
                not _is_int(start)
                or not _is_int(end)
                or start < -120
                or start >= end
                or end > clock["duration_seconds"]
            ):
                raise ScenarioError("Schedule interval is outside the phase clock.")
        if not isinstance(event.get("required"), bool):
            raise ScenarioError("Schedule required flag must be boolean.")
        purpose = event.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 512:
            raise ScenarioError("Scenario schedule purpose is missing or too long.")
    blocked = scenario.get("blocked_gates")
    if not isinstance(blocked, list) or any(
        not isinstance(item, str) for item in blocked
    ):
        raise ScenarioError("blocked_gates must be a list of text reasons.")
    return scenario


def offline_preflight(scenario: dict[str, Any]) -> dict[str, Any]:
    """Return a template-only preflight; it never assigns an anchor or emits facts."""

    validate_scenario(scenario)
    return {
        "schema_version": 1,
        "kind": "offline_scenario_preflight",
        "scenario_id": scenario["scenario_id"],
        "template_revision": scenario["template_revision"],
        "template_sha256": scenario_template_hash(scenario),
        "presentation_status": scenario.get("presentation_status", "blocked"),
        "planned_t_epoch": None,
        "blocked_gates": list(scenario["blocked_gates"]),
        "scheduled_items": len(scenario["evidence_schedule"]),
        "services_contacted": False,
    }


def _validate_readiness(readiness: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(readiness, dict) or readiness.get("schema_version") != 1:
        raise ScenarioError("A versioned readiness record is required.")
    if readiness.get("scenario_id") != scenario["scenario_id"]:
        raise ScenarioError("Readiness record belongs to a different scenario.")
    required_hashes = (
        "lab_allocation_sha256",
        "target_identity_sha256",
        "package_sha256",
        "execution_inventory_sha256",
        "source_mapping_sha256",
        "configuration_sha256",
        "contract_sha256",
    )
    for key in required_hashes:
        _hash(readiness.get(key), key)
    checks = readiness.get("checks")
    required_checks = {
        "lab_owned",
        "package_ready",
        "source_mappings_ready",
        "clock_agrees",
        "queries_ready",
        "lifecycle_authorized",
    }
    if not isinstance(checks, dict) or any(
        checks.get(key) is not True for key in required_checks
    ):
        raise ScenarioError("Readiness checks are incomplete; no run plan was written.")
    clock = readiness.get("clock")
    if not isinstance(clock, dict):
        raise ScenarioError("Readiness clock measurement is missing.")
    offset_ms = clock.get("measured_offset_milliseconds")
    tolerance_ms = clock.get("tolerance_milliseconds")
    if (
        not _is_int(offset_ms)
        or not _is_int(tolerance_ms)
        or not 0 <= tolerance_ms <= 5_000
        or abs(offset_ms) > tolerance_ms
    ):
        raise ScenarioError("Readiness clock disagreement exceeds its tolerance.")
    queries = readiness.get("query_definitions")
    if not isinstance(queries, dict) or not queries:
        raise ScenarioError("Readiness must bind exact query definition hashes.")
    for key, value in queries.items():
        if not isinstance(key, str) or not key or len(key) > 120:
            raise ScenarioError("Query definition key is invalid.")
        _hash(value, f"query_definitions.{key}")
    fixtures = readiness.get("fixture_sha256", {})
    if not isinstance(fixtures, dict):
        raise ScenarioError("Fixture hash map must be an object.")
    for path, value in fixtures.items():
        if (
            not isinstance(path, str)
            or path.startswith("/")
            or ".." in Path(path).parts
            or "\\" in path
        ):
            raise ScenarioError("Fixture hash path must be repository-relative.")
        _hash(value, f"fixture_sha256.{path}")
    if any(
        event["required"] and event["status"] != "planned"
        for event in scenario["evidence_schedule"]
    ):
        raise ScenarioError(
            "Required source facts are still blocked in the scenario template."
        )
    return readiness


def build_run_plan(
    scenario: dict[str, Any],
    readiness: dict[str, Any],
    *,
    now_epoch: int,
    lead_seconds: int = DEFAULT_T_LEAD_SECONDS,
    anchor_epoch: int | None = None,
    execution_id: str | None = None,
) -> dict[str, Any]:
    """Build a write-once, future-anchored plan after all readiness gates pass."""

    validate_scenario(scenario)
    readiness = _validate_readiness(readiness, scenario)
    now = _epoch(now_epoch, "now_epoch")
    if not _is_int(lead_seconds) or lead_seconds < MINIMUM_T_LEAD_SECONDS:
        raise ScenarioError("T must leave at least 180 seconds after plan creation.")
    minimum_t = now + lead_seconds
    anchor = minimum_t if anchor_epoch is None else _epoch(anchor_epoch, "anchor_epoch")
    if anchor < minimum_t:
        raise ScenarioError("T is too close to plan creation to deliver the prelude.")
    if execution_id is None:
        execution_id = str(uuid.uuid4())
    try:
        execution_id = str(uuid.UUID(execution_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ScenarioError("execution_id must be a UUID.") from exc

    scheduled = []
    for event in scenario["evidence_schedule"]:
        item = {
            "id": event["id"],
            "product": event["product"],
            "family": event["family"],
            "required": event["required"],
            "status": event["status"],
            "planned_source_time_basis": "synthetic_scenario_clock",
            "actual_emission_epoch": None,
            "transport_acknowledgment_epoch": None,
            "indexed_receipt_epoch": None,
            "readback_epoch": None,
        }
        if "offset_seconds" in event:
            item["offset_seconds"] = event["offset_seconds"]
            item["planned_source_epoch"] = anchor + event["offset_seconds"]
        else:
            start = event["window_start_offset_seconds"]
            end = event["window_end_offset_seconds"]
            item["window_start_offset_seconds"] = start
            item["window_end_offset_seconds"] = end
            item["planned_collection_start_epoch"] = anchor + start
            item["planned_collection_end_epoch"] = anchor + end
        scheduled.append(item)
    scheduled.sort(
        key=lambda item: (
            item.get(
                "planned_source_epoch", item.get("planned_collection_start_epoch")
            ),
            item["id"],
        )
    )
    body = {
        "schema_version": 1,
        "kind": PLAN_KIND,
        "scenario_id": scenario["scenario_id"],
        "template_revision": scenario["template_revision"],
        "template_sha256": scenario_template_hash(scenario),
        "execution_id": execution_id,
        "run_plan_revision": 1,
        "plan_created_epoch": now,
        "plan_created_utc": _utc(now),
        "anchor_t_epoch": anchor,
        "anchor_t_utc": _utc(anchor),
        "planned_run_end_epoch": anchor + scenario["clock"]["duration_seconds"],
        "planned_run_end_utc": _utc(anchor + scenario["clock"]["duration_seconds"]),
        "clock": {
            "basis": scenario["clock"]["basis"],
            "prelude_offset_seconds": scenario["clock"]["prelude_offset_seconds"],
            "minimum_t_lead_seconds": lead_seconds,
            "maximum_offset_milliseconds": readiness["clock"]["tolerance_milliseconds"],
        },
        "phase_windows": [
            {
                "id": phase["id"],
                "earliest_epoch": anchor + phase["start_offset_seconds"],
                "latest_epoch": anchor + phase["end_offset_seconds"],
            }
            for phase in scenario["clock"]["phases"]
        ],
        "planned_source_time_bounds": {
            "earliest_epoch": anchor + scenario["clock"]["prelude_offset_seconds"],
            "latest_epoch": anchor + scenario["clock"]["duration_seconds"],
            "basis": "synthetic_scenario_clock",
        },
        "readiness": {
            "lab_allocation_sha256": readiness["lab_allocation_sha256"],
            "target_identity_sha256": readiness["target_identity_sha256"],
            "package_sha256": readiness["package_sha256"],
            "execution_inventory_sha256": readiness["execution_inventory_sha256"],
            "source_mapping_sha256": readiness["source_mapping_sha256"],
            "configuration_sha256": readiness["configuration_sha256"],
            "contract_sha256": readiness["contract_sha256"],
            "fixture_sha256": dict(sorted(readiness.get("fixture_sha256", {}).items())),
            "query_definitions": dict(sorted(readiness["query_definitions"].items())),
            "clock": dict(readiness["clock"]),
        },
        "schedule": scheduled,
        "services_contacted": False,
    }
    if len(canonical_json(body)) > MAX_PLAN_BYTES:
        raise ScenarioError("Run plan exceeds the bounded 512 KiB limit.")
    return {**body, "plan_sha256": sha256_hex(body)}


def verify_run_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("kind") != PLAN_KIND:
        raise ScenarioError("Run plan kind is unsupported.")
    plan_hash = _hash(plan.get("plan_sha256"), "plan_sha256")
    body = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if sha256_hex(body) != plan_hash:
        raise ScenarioError("Run plan content does not match its immutable hash.")
    scenario = load_scenario(plan.get("scenario_id"))
    if plan.get("template_revision") != scenario["template_revision"] or plan.get(
        "template_sha256"
    ) != scenario_template_hash(scenario):
        raise ScenarioError("Run plan references a different scenario template.")
    anchor = _epoch(plan.get("anchor_t_epoch"), "anchor_t_epoch")
    created = _epoch(plan.get("plan_created_epoch"), "plan_created_epoch")
    clock = plan.get("clock")
    if not isinstance(clock, dict):
        raise ScenarioError("Run plan clock metadata is missing.")
    lead = clock.get("minimum_t_lead_seconds")
    if not _is_int(lead) or lead < MINIMUM_T_LEAD_SECONDS or anchor < created + lead:
        raise ScenarioError("Run plan T anchor does not preserve its readiness lead.")
    if (
        clock.get("basis") != scenario["clock"]["basis"]
        or clock.get("prelude_offset_seconds") != -120
        or not _is_int(clock.get("maximum_offset_milliseconds"))
        or not 0 <= clock["maximum_offset_milliseconds"] <= 5_000
        or plan.get("services_contacted") is not False
    ):
        raise ScenarioError("Run plan clock or preparation state is invalid.")
    if (
        plan.get("planned_run_end_epoch")
        != anchor + scenario["clock"]["duration_seconds"]
    ):
        raise ScenarioError("Run plan duration differs from the revision 2 clock.")
    earliest = _epoch(
        plan.get("planned_source_time_bounds", {}).get("earliest_epoch"), "prelude"
    )
    if earliest != anchor - 120:
        raise ScenarioError("Run plan prelude must be scheduled at T-120.")
    if earliest <= created:
        raise ScenarioError(
            "Run plan prelude must remain in the future after readiness."
        )
    expected_windows = [
        {
            "id": phase["id"],
            "earliest_epoch": anchor + phase["start_offset_seconds"],
            "latest_epoch": anchor + phase["end_offset_seconds"],
        }
        for phase in scenario["clock"]["phases"]
    ]
    if plan.get("phase_windows") != expected_windows:
        raise ScenarioError("Run plan phase windows differ from the approved clock.")
    readiness = plan.get("readiness")
    if not isinstance(readiness, dict):
        raise ScenarioError("Run plan readiness bindings are missing.")
    for field in (
        "lab_allocation_sha256",
        "target_identity_sha256",
        "package_sha256",
        "execution_inventory_sha256",
        "source_mapping_sha256",
        "configuration_sha256",
        "contract_sha256",
    ):
        _hash(readiness.get(field), f"readiness.{field}")
    schedule = plan.get("schedule")
    template_schedule = {item["id"]: item for item in scenario["evidence_schedule"]}
    if not isinstance(schedule, list) or len(schedule) != len(template_schedule):
        raise ScenarioError("Run plan schedule is missing.")
    schedule_ids = [item.get("id") for item in schedule if isinstance(item, dict)]
    if len(schedule_ids) != len(schedule) or len(set(schedule_ids)) != len(schedule):
        raise ScenarioError("Run plan schedule IDs must be unique.")
    for item in schedule:
        if not isinstance(item, dict):
            raise ScenarioError("Run plan schedule entry is invalid.")
        template_item = template_schedule.get(item.get("id"))
        if template_item is None or any(
            item.get(key) != template_item.get(key)
            for key in ("product", "family", "required", "status")
        ):
            raise ScenarioError("Run plan event does not match the scenario template.")
        if item.get("status") not in {"planned", "blocked"}:
            raise ScenarioError("Run plan event status is invalid.")
        for key in (
            "actual_emission_epoch",
            "transport_acknowledgment_epoch",
            "indexed_receipt_epoch",
            "readback_epoch",
        ):
            if item.get(key) is not None:
                raise ScenarioError("Run plan actual-time fields are immutable nulls.")
        instant = "offset_seconds" in template_item
        expected_target = anchor + (
            template_item["offset_seconds"]
            if instant
            else template_item["window_start_offset_seconds"]
        )
        source_epoch = item.get(
            "planned_source_epoch", item.get("planned_collection_start_epoch")
        )
        if source_epoch != expected_target or source_epoch < earliest:
            raise ScenarioError("Planned event does not match its source time.")
        if instant:
            if (
                item.get("offset_seconds") != template_item["offset_seconds"]
                or "planned_collection_end_epoch" in item
            ):
                raise ScenarioError(
                    "Run plan instant differs from the template schedule."
                )
        else:
            expected_end = anchor + template_item["window_end_offset_seconds"]
            if (
                item.get("window_start_offset_seconds")
                != template_item["window_start_offset_seconds"]
                or item.get("window_end_offset_seconds")
                != template_item["window_end_offset_seconds"]
                or item.get("planned_collection_end_epoch") != expected_end
            ):
                raise ScenarioError(
                    "Run plan interval differs from the template schedule."
                )
        if item["required"] and item["status"] != "planned":
            raise ScenarioError("A required source fact remains blocked.")
    return plan


def write_once_json(path: Path, payload: dict[str, Any], *, max_bytes: int) -> None:
    """Create a private immutable JSON output without replacing an existing file."""

    raw = canonical_json(payload) + b"\n"
    if len(raw) > max_bytes:
        raise ScenarioError("Output exceeds its configured size limit.")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
