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
from urllib.parse import unquote, urlsplit

from tools.change_correlation.contracts import canonical_json

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCENARIO_ROOT = ROOT / "fixtures" / "change-correlation-v2" / "scenarios"
SCENARIO_IDS = ("track-a-firewall", "track-b-fabric")
TEMPLATE_REVISION = 2
PLAN_KIND = "configuration-change-run-plan-v1"
VARIANT_REGISTRY_NAME = "variants.json"
VARIANT_CONTRACT_VERSION = 2
CONNECTED_SERVICE_RESULT_KEYS = (
    "graph.baseline",
    "graph.change",
    "graph.impact",
    "graph.recovery",
    "topology.baseline",
    "topology.impact",
    "topology.recovery",
    "catalog.selected",
    "find.service",
)
MINIMUM_T_LEAD_SECONDS = 180
DEFAULT_T_LEAD_SECONDS = 300
MAX_PLAN_BYTES = 512 * 1024
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SUMMARY_BUCKET_PHASE_FAMILIES = frozenset(
    {
        "connection_observation",
        "ms390_client_flow",
        "catalyst_client_flow",
        "hubble_client_tuple",
        "hubble_pod_tuple",
        "flow_observation",
    }
)


class ScenarioError(ValueError):
    """Safe validation error for templates, readiness, and run plans."""


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScenarioError("Scenario JSON contains a duplicate object key.")
        result[key] = value
    return result


def _read_bounded_json(path: Path, *, maximum: int = MAX_PLAN_BYTES) -> Any:
    try:
        raw = path.read_bytes()
        if len(raw) > maximum:
            raise ScenarioError("Scenario JSON exceeds its bounded size.")
        return json.loads(raw, object_pairs_hook=_json_object)
    except ScenarioError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScenarioError("Scenario JSON cannot be read safely.") from exc


def _safe_asset_path(value: Any, *, track: str, variant_id: str, kind: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ScenarioError("Variant asset path is invalid.")
    parsed = urlsplit(value)
    decoded = unquote(value)
    parts = Path(decoded).parts
    if (
        parsed.scheme
        or parsed.netloc
        or value.startswith(("/", "\\"))
        or "\\" in value
        or "%" in value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ScenarioError("Variant asset path escapes the scenario asset root.")
    expected = (
        f"{track}.json"
        if kind == "template" and variant_id in {"a-meraki-ssid", "b-aci-policy"}
        else f"variants/{track}/{variant_id}.json"
        if kind == "template"
        else f"captures/{track}.json"
        if variant_id in {"a-meraki-ssid", "b-aci-policy"}
        else f"captures/{track}/{variant_id}.json"
    )
    if value != expected:
        raise ScenarioError("Variant asset path is not the registered track path.")
    return value


def _descriptor_shape(descriptor: Any, *, track: str) -> dict[str, Any]:
    if not isinstance(descriptor, dict):
        raise ScenarioError("Variant descriptor must be an object.")
    variant_id = descriptor.get("id")
    if not isinstance(variant_id, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{0,63}", variant_id
    ):
        raise ScenarioError("Variant ID is invalid.")
    common = {"id", "label", "products", "purpose", "status"}
    status = descriptor.get("status")
    if status == "runnable":
        required = common | {
            "template_asset",
            "template_sha256",
            "capture_asset",
            "expectation",
            "claim_limits",
        }
        if set(descriptor) != required:
            raise ScenarioError("Runnable variant descriptor has unsupported fields.")
        if descriptor.get("expectation") not in {
            "observed",
            "source_gap",
            "restricted_visibility",
        }:
            raise ScenarioError("Runnable variant expectation is unsupported.")
        _hash(descriptor.get("template_sha256"), "variant template_sha256")
        _safe_asset_path(
            descriptor.get("template_asset"),
            track=track,
            variant_id=variant_id,
            kind="template",
        )
        _safe_asset_path(
            descriptor.get("capture_asset"),
            track=track,
            variant_id=variant_id,
            kind="capture",
        )
        limits = descriptor.get("claim_limits")
        if (
            not isinstance(limits, list)
            or not limits
            or len(limits) > 24
            or any(
                not isinstance(item, str) or not item.strip() or len(item) > 512
                for item in limits
            )
        ):
            raise ScenarioError("Runnable variant claim limits are invalid.")
    elif status == "blocked":
        required = common | {
            "reason_code",
            "reason",
            "current_evidence",
            "unblock_evidence",
            "run_status",
        }
        if set(descriptor) != required:
            raise ScenarioError("Blocked variant descriptor has unsupported fields.")
        if descriptor.get("run_status") != "not_run":
            raise ScenarioError("Blocked variants must be marked not_run.")
        for key in ("reason_code", "reason", "current_evidence", "unblock_evidence"):
            value = descriptor.get(key)
            if not isinstance(value, str) or not value.strip() or len(value) > 1200:
                raise ScenarioError("Blocked variant disposition text is invalid.")
    else:
        raise ScenarioError("Variant status must be runnable or blocked.")
    if (
        not isinstance(descriptor.get("label"), str)
        or not descriptor["label"].strip()
        or len(descriptor["label"]) > 120
        or not isinstance(descriptor.get("purpose"), str)
        or not descriptor["purpose"].strip()
        or len(descriptor["purpose"]) > 512
    ):
        raise ScenarioError("Variant label or purpose is invalid.")
    products = descriptor.get("products")
    if (
        not isinstance(products, list)
        or not products
        or len(products) > 8
        or products != sorted(set(products))
        or any(
            not isinstance(item, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", item)
            for item in products
        )
    ):
        raise ScenarioError("Variant products must be a sorted unique product list.")
    return descriptor


def load_variant_registry() -> dict[str, Any]:
    """Load and validate the fixed two-track variant registry and all templates."""

    registry = _read_bounded_json(SCENARIO_ROOT / VARIANT_REGISTRY_NAME)
    if not isinstance(registry, dict) or set(registry) != {"schema_version", "tracks"}:
        raise ScenarioError("Variant registry has an unsupported shape.")
    if registry.get("schema_version") != 1 or not isinstance(
        registry.get("tracks"), dict
    ):
        raise ScenarioError("Variant registry schema is unsupported.")
    tracks = registry["tracks"]
    if set(tracks) != set(SCENARIO_IDS):
        raise ScenarioError("Variant registry must contain exactly the two tracks.")
    expected_ids = {
        "track-a-firewall": {
            "a-meraki-ssid",
            "a-backend-rollout",
            "a-nat-boundary",
            "a-wireless-reuse",
            "both-gap",
            "both-permissions",
            "a-fmc-policy-deploy",
            "a-nxos-interface",
            "both-appdynamics-control",
            "both-thousandeyes-control",
        },
        "track-b-fabric": {
            "b-aci-policy",
            "b-service-backend",
            "b-aci-attachment",
            "both-gap",
            "both-permissions",
            "b-wan-deploy",
            "b-campus-provision",
            "b-cilium-policy",
            "b-epg-move",
            "both-appdynamics-control",
            "both-thousandeyes-control",
        },
    }
    expected_defaults = {
        "track-a-firewall": "a-meraki-ssid",
        "track-b-fabric": "b-aci-policy",
    }
    for track in SCENARIO_IDS:
        entry = tracks[track]
        if not isinstance(entry, dict) or set(entry) != {
            "default_variant_id",
            "variants",
        }:
            raise ScenarioError("Variant track entry has an unsupported shape.")
        variants = entry.get("variants")
        if not isinstance(variants, list) or not variants or len(variants) > 16:
            raise ScenarioError("Variant track list is empty or oversized.")
        descriptors = [_descriptor_shape(value, track=track) for value in variants]
        ids = [value["id"] for value in descriptors]
        if len(ids) != len(set(ids)) or set(ids) != expected_ids[track]:
            raise ScenarioError("Variant IDs differ from the authored contract table.")
        if entry.get("default_variant_id") != expected_defaults[track]:
            raise ScenarioError(
                "Track default variant differs from the authored contract."
            )
        for descriptor in descriptors:
            if descriptor["status"] != "runnable":
                continue
            template_path = SCENARIO_ROOT / descriptor["template_asset"]
            template = _read_bounded_json(template_path)
            validate_scenario(
                template,
                expected_id=track,
                expected_variant_id=descriptor["id"],
            )
            if (
                template.get("variant_expectation") != descriptor["expectation"]
                or template.get("variant_claim_limits") != descriptor["claim_limits"]
            ):
                raise ScenarioError(
                    "Variant template expectations differ from its public registry descriptor."
                )
            if sha256_hex(template) != descriptor["template_sha256"]:
                raise ScenarioError("Variant template hash differs from the registry.")
    return registry


def variant_registry_hash(registry: dict[str, Any] | None = None) -> str:
    registry = load_variant_registry() if registry is None else registry
    return sha256_hex(registry)


def scenario_variant_descriptor(
    scenario_id: str, variant_id: str, registry: dict[str, Any] | None = None
) -> dict[str, Any]:
    registry = load_variant_registry() if registry is None else registry
    try:
        variants = registry["tracks"][scenario_id]["variants"]
        return next(item for item in variants if item["id"] == variant_id)
    except (KeyError, StopIteration, TypeError) as exc:
        raise ScenarioError("Unknown or cross-track scenario variant.") from exc


def scenario_asset_allowlist(registry: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the common exact registry/template/capture asset inventory view."""

    registry = load_variant_registry() if registry is None else registry
    templates = set()
    captures = set()
    for track in SCENARIO_IDS:
        for descriptor in registry["tracks"][track]["variants"]:
            if descriptor["status"] == "runnable":
                templates.add(descriptor["template_asset"])
                captures.add(descriptor["capture_asset"])
    return {
        "schema_version": 1,
        "registry_asset": VARIANT_REGISTRY_NAME,
        "template_assets": sorted(templates),
        "capture_assets": sorted(captures),
    }


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


def _validate_permission_caller(
    value: Any,
    scenario: dict[str, Any],
    query_definitions: Any,
    active_traffic_contract_sha256: str,
    *,
    target_sha256: str | None = None,
) -> dict[str, Any] | None:
    """Validate the sealed, secret-free restricted caller proof projection."""

    if scenario.get("variant_expectation") != "restricted_visibility":
        if value is not None:
            raise ScenarioError(
                "Only a restricted-visibility variant may bind a caller profile."
            )
        return None
    fields = {
        "profile",
        "selected_history_index",
        "allowed_indexes",
        "allowed_indexes_sha256",
        "capabilities",
        "disallowed_indexes",
        "principal_sha256",
        "policy_sha256",
        "role_readback_sha256",
        "target_sha256",
        "caller_context_sha256",
        "caller_proof_sha256",
        "query_sha256",
        "graph_input_contract_sha256",
        "active_traffic_contract_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ScenarioError("Restricted caller proof projection is incomplete.")
    allowed = value.get("allowed_indexes")
    denied = value.get("disallowed_indexes")
    capabilities = value.get("capabilities")
    if (
        value.get("profile") != "history_denied"
        or value.get("selected_history_index") != "atlas_changes"
        or not isinstance(allowed, list)
        or not allowed
        or allowed != sorted(set(allowed))
        or any(
            not isinstance(item, str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,79}", item)
            for item in allowed
        )
        or any(item in allowed for item in ("_audit", "_internal", "atlas_changes"))
        or denied != ["_audit", "_internal", "atlas_changes"]
        or capabilities != ["list_conf_objects", "search"]
        or value.get("allowed_indexes_sha256") != sha256_hex(canonical_json(allowed))
        or not isinstance(value.get("query_sha256"), dict)
        or set(value["query_sha256"]) != {"graph", "graph.inputs.impact"}
    ):
        raise ScenarioError("Restricted caller policy or query binding is invalid.")
    for name in (
        "allowed_indexes_sha256",
        "principal_sha256",
        "policy_sha256",
        "role_readback_sha256",
        "target_sha256",
        "caller_context_sha256",
        "caller_proof_sha256",
        "graph_input_contract_sha256",
        "active_traffic_contract_sha256",
    ):
        _hash(value.get(name), f"permission_caller.{name}")
    if target_sha256 is None:
        raise ScenarioError("Restricted caller proof is not bound to target readiness.")
    queries = query_definitions if isinstance(query_definitions, dict) else {}
    for name, readiness_name in (
        ("graph", "graph"),
        ("graph.inputs.impact", "graph.inputs.impact"),
    ):
        _hash(value["query_sha256"].get(name), f"permission_caller.query_sha256.{name}")
        if value["query_sha256"][name] != queries.get(readiness_name):
            raise ScenarioError("Restricted caller query differs from readiness.")
    if (
        value["graph_input_contract_sha256"] != active_traffic_contract_sha256
        or value["active_traffic_contract_sha256"] != active_traffic_contract_sha256
        or (value["target_sha256"] != target_sha256)
    ):
        raise ScenarioError(
            "Restricted caller is not bound to the active traffic contract and target."
        )
    return value


def _utc(epoch: int) -> str:
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def load_scenario(scenario_id: str, variant: str | None = None) -> dict[str, Any]:
    """Load a registered runnable variant, defaulting only within its parent track."""

    if scenario_id not in SCENARIO_IDS:
        raise ScenarioError("Unknown change scenario ID.")
    registry = load_variant_registry()
    track = registry["tracks"][scenario_id]
    selected_id = variant if variant is not None else track["default_variant_id"]
    descriptor = scenario_variant_descriptor(scenario_id, selected_id, registry)
    if descriptor["status"] != "runnable":
        raise ScenarioError("Blocked scenario variants cannot be executed.")
    path = SCENARIO_ROOT / descriptor["template_asset"]
    payload = _read_bounded_json(path)
    validate_scenario(
        payload,
        expected_id=scenario_id,
        expected_variant_id=selected_id,
    )
    if sha256_hex(payload) != descriptor["template_sha256"]:
        raise ScenarioError("Selected scenario template changed after registry freeze.")
    return payload


def scenario_template_hash(scenario: dict[str, Any]) -> str:
    validate_scenario(scenario)
    return sha256_hex(scenario)


def connected_service_scopes(scenario: dict[str, Any]) -> list[dict[str, str]]:
    primary = scenario.get("application")
    entries = scenario.get("connected_services")
    dimensions = {"service", "environment", "cluster", "namespace"}
    if not isinstance(primary, dict) or set(primary) != dimensions:
        raise ScenarioError("Connected services require the primary application.")
    if not isinstance(entries, list) or len(entries) != 2:
        raise ScenarioError("Connected services require inventory and pricing.")
    scopes = []
    for expected, entry in zip(("inventory", "pricing"), entries, strict=True):
        if not isinstance(entry, dict) or set(entry) != {
            "application",
            "registry_key",
            "role",
        }:
            raise ScenarioError("Connected service descriptor fields are invalid.")
        scope = entry.get("application")
        role = entry.get("role")
        if (
            not isinstance(scope, dict)
            or set(scope) != dimensions
            or any(
                not isinstance(value, str)
                or not value
                or len(value) > 255
                or any(ord(char) < 32 or ord(char) == 127 for char in value)
                for value in scope.values()
            )
            or scope.get("service") != expected
            or entry.get("registry_key") != expected
            or scope["service"] == primary["service"]
            or any(scope[field] != primary[field] for field in dimensions - {"service"})
            or not isinstance(role, str)
            or not role.strip()
            or len(role) > 256
        ):
            raise ScenarioError("Connected service scope or role is invalid.")
        scopes.append(dict(scope))
    return scopes


def _source_gap_identity_list(
    value: Any, *, schedule_id: str, partial: bool
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise ScenarioError("Source-gap collection identities are empty or oversized.")
    expected_fields = {
        "product",
        "authority",
        "family",
        "partition",
        "scope",
        "source_reference",
        "pages_expected",
        "pages_received",
        "capture_ref_strategy",
    }
    identities = []
    seen = set()
    for ordinal, item in enumerate(value, start=1):
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise ScenarioError("Source-gap collection identity fields are not exact.")
        identity_fields = ("product", "authority", "family", "partition", "scope")
        if any(
            not isinstance(item.get(field), str)
            or not item[field].strip()
            or len(item[field]) > 512
            for field in identity_fields
        ):
            raise ScenarioError("Source-gap collection identity is invalid.")
        if (
            item.get("source_reference")
            != f"documentation-shaped-synthetic:{schedule_id}:{ordinal}"
            or item.get("capture_ref_strategy") != "uuid5_url_readback_key_v1"
        ):
            raise ScenarioError("Source-gap collection references are not frozen.")
        pages_expected = item.get("pages_expected")
        pages_received = item.get("pages_received")
        counts_valid = (
            _is_int(pages_expected)
            and 1 <= pages_expected <= 10_000
            and _is_int(pages_received)
            and 1 <= pages_received <= pages_expected
        )
        if counts_valid:
            counts_valid = (
                pages_expected >= 2 and pages_received == 1
                if partial
                else pages_received == pages_expected
            )
        if not counts_valid:
            raise ScenarioError("Source-gap collection page counts are invalid.")
        identity = tuple(item[field] for field in identity_fields)
        if identity in seen:
            raise ScenarioError("Source-gap collection identities must be unique.")
        seen.add(identity)
        identities.append({"identity": identity, **item})
    return identities


def validate_scenario(
    scenario: Any,
    *,
    expected_id: str | None = None,
    expected_variant_id: str | None = None,
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
    variant_id = scenario.get("variant_id")
    if (
        scenario.get("variant_contract_version") != VARIANT_CONTRACT_VERSION
        or not isinstance(variant_id, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", variant_id)
        or (expected_variant_id is not None and variant_id != expected_variant_id)
    ):
        raise ScenarioError("Scenario variant identity is invalid.")
    variant_expectation = scenario.get("variant_expectation")
    if variant_expectation not in {
        "observed",
        "source_gap",
        "restricted_visibility",
    }:
        raise ScenarioError("Scenario variant expectation is unsupported.")
    claim_limits = scenario.get("variant_claim_limits")
    if (
        not isinstance(claim_limits, list)
        or not claim_limits
        or len(claim_limits) > 24
        or any(
            not isinstance(item, str) or not item.strip() or len(item) > 512
            for item in claim_limits
        )
    ):
        raise ScenarioError("Scenario variant claim limits are invalid.")
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
    if "connected_services" in scenario:
        connected_service_scopes(scenario)
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
        if (
            "collection_status" in event
            or "collection_pages_expected" in event
            or "collection_pages_received" in event
        ):
            if (
                variant_expectation != "source_gap"
                or event.get("collection_status") != "partial"
                or not _is_int(event.get("collection_pages_expected"))
                or event["collection_pages_expected"] < 2
                or event.get("collection_pages_received") != 1
            ):
                raise ScenarioError(
                    "Only a source-gap variant may declare a one-page partial collection."
                )
        purpose = event.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 512:
            raise ScenarioError("Scenario schedule purpose is missing or too long.")
        if event["family"] in SUMMARY_BUCKET_PHASE_FAMILIES:
            if (
                event.get("summary_bucket_phase")
                not in {phase["id"] for phase in phases}
                or not has_offset
            ):
                raise ScenarioError(
                    "Summary-producing traffic requires an instant and an explicit bucket phase."
                )
        elif "summary_bucket_phase" in event:
            raise ScenarioError(
                "Only summary-producing traffic may declare a summary bucket phase."
            )
    blocked = scenario.get("blocked_gates")
    if not isinstance(blocked, list) or any(
        not isinstance(item, str) for item in blocked
    ):
        raise ScenarioError("blocked_gates must be a list of text reasons.")
    expectations = scenario.get("variant_expectations")
    if not isinstance(expectations, dict):
        raise ScenarioError("Variant-specific acceptance expectations are required.")
    event_ids = {event["id"] for event in schedule}
    required_schedule = expectations.get("required_schedule_ids")
    if (
        not isinstance(required_schedule, list)
        or not required_schedule
        or len(required_schedule) > len(schedule)
        or len(required_schedule) != len(set(required_schedule))
        or any(item not in event_ids for item in required_schedule)
    ):
        raise ScenarioError("Variant required schedule references are invalid.")
    must_not_claim = expectations.get("must_not_claim")
    if (
        not isinstance(must_not_claim, list)
        or not must_not_claim
        or any(not isinstance(item, str) or not item.strip() for item in must_not_claim)
    ):
        raise ScenarioError("Variant claim exclusions are required.")
    extra_keys = set(expectations) - {
        "required_schedule_ids",
        "must_not_claim",
        "backend_identity_change",
        "same_ip_multiple_macs",
        "endpoint_dn_stable",
        "same_event_nat_tuple",
        "partial_schedule_id",
        "later_complete_schedule_id",
        "partial_collection_identities",
        "later_complete_collection_identities",
        "service_snapshot_schedule_ids",
        "positive_control_result_key",
        "selected_history_index",
    }
    if extra_keys:
        raise ScenarioError("Variant expectation has unsupported fields.")
    if variant_expectation == "source_gap":
        partial_id = expectations.get("partial_schedule_id")
        later_id = expectations.get("later_complete_schedule_id")
        partial = next((item for item in schedule if item["id"] == partial_id), None)
        later = next((item for item in schedule if item["id"] == later_id), None)
        if (
            not isinstance(partial, dict)
            or partial.get("collection_status") != "partial"
            or not isinstance(later, dict)
            or later.get("collection_status") is not None
        ):
            raise ScenarioError(
                "Source-gap variant must bind its partial and later complete observations."
            )
        partial_identities = _source_gap_identity_list(
            expectations.get("partial_collection_identities"),
            schedule_id=partial_id,
            partial=True,
        )
        later_identities = _source_gap_identity_list(
            expectations.get("later_complete_collection_identities"),
            schedule_id=later_id,
            partial=False,
        )
        if len(partial_identities) != len(later_identities) or [
            item["identity"] for item in partial_identities
        ] != [item["identity"] for item in later_identities]:
            raise ScenarioError(
                "Source-gap partial and later collection identities must match exactly."
            )
        partial_end = partial.get(
            "window_end_offset_seconds", partial.get("offset_seconds")
        )
        later_start = later.get(
            "window_start_offset_seconds", later.get("offset_seconds")
        )
        if later_start <= partial_end:
            raise ScenarioError(
                "Source-gap later collection must follow the partial collection."
            )
    elif expectations.get("backend_identity_change") is True:
        expected_service_schedules = (
            ["a-k8s-primary-prelude", "a-rollout-k8s-update"]
            if scenario["scenario_id"] == "track-a-firewall"
            else ["b-k8s-prelude", "b-backend-k8s-update"]
        )
        if (
            expectations.get("service_snapshot_schedule_ids")
            != expected_service_schedules
        ):
            raise ScenarioError(
                "Backend rollout must bind its exact before/update Service watch schedules."
            )
        behavior = scenario.get("variant_behavior")
        rollout = (
            behavior.get("backend_rollout") if isinstance(behavior, dict) else None
        )
        service = (
            scenario.get("identity_registry", {}).get("primary", {}).get("frontend", {})
        )
        selector_object = (
            rollout.get("service_selector_object")
            if isinstance(rollout, dict)
            else None
        )
        if (
            not isinstance(rollout, dict)
            or not isinstance(service, dict)
            or rollout.get("service_selector") != "app.kubernetes.io/name=checkout"
            or selector_object != {"app.kubernetes.io/name": "checkout"}
            or service.get("name") != "checkout-api"
        ):
            raise ScenarioError(
                "Backend rollout must bind the exact stable Service selector and identity."
            )
    elif "service_snapshot_schedule_ids" in expectations:
        raise ScenarioError(
            "Only a backend rollout may declare Service watch snapshots."
        )
    if expectations.get("same_event_nat_tuple") is True:
        nat = (
            scenario.get("identity_registry", {}).get("nat_boundary")
            if isinstance(scenario.get("identity_registry"), dict)
            else None
        )
        primary = (
            scenario.get("identity_registry", {}).get("primary")
            if isinstance(scenario.get("identity_registry"), dict)
            else None
        )
        client = primary.get("client") if isinstance(primary, dict) else None
        frontend = primary.get("frontend") if isinstance(primary, dict) else None
        if (
            not isinstance(nat, dict)
            or not isinstance(client, dict)
            or not isinstance(frontend, dict)
            or nat.get("reported_initiator_ip") != client.get("ip")
            or nat.get("reported_initiator_port") != 55220
            or nat.get("reported_responder_ip") != frontend.get("ip")
            or nat.get("reported_responder_port") != frontend.get("port")
            or nat.get("protocol") != "TCP"
            or not 1 <= nat.get("translated_initiator_port", 0) <= 65535
            or not 1 <= nat.get("downstream_destination_port", 0) <= 65535
        ):
            raise ScenarioError(
                "NAT boundary must freeze the complete reported and translated tuples."
            )
    elif variant_expectation == "restricted_visibility":
        permissions = scenario.get("permission_case")
        if (
            not isinstance(permissions, dict)
            or permissions
            != {
                "caller_profile": "history_denied",
                "visibility_surface": "timeline_activation",
                "selected_history_index": expectations.get("selected_history_index"),
                "positive_control_result_keys": [
                    "graph.impact",
                    "endpoint.primary.impact",
                ],
            }
            or expectations.get("selected_history_index") != "atlas_changes"
            or expectations.get("positive_control_result_key") != "graph.impact"
        ):
            raise ScenarioError(
                "Restricted-visibility variant expectation is not bound."
            )
    elif "permission_case" in scenario:
        raise ScenarioError(
            "Only a restricted-visibility variant may configure a caller profile."
        )
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
    descriptor = scenario_variant_descriptor(
        scenario["scenario_id"], scenario["variant_id"]
    )
    if descriptor.get("status") != "runnable":
        raise ScenarioError("Readiness cannot authorize a blocked variant.")
    if (
        readiness.get("variant_id") != scenario["variant_id"]
        or readiness.get("variant_registry_sha256") != variant_registry_hash()
        or readiness.get("variant_contract_version") != VARIANT_CONTRACT_VERSION
        or readiness.get("template_sha256") != scenario_template_hash(scenario)
    ):
        raise ScenarioError("Readiness does not bind the selected variant registry.")
    required_hashes = (
        "lab_allocation_sha256",
        "target_identity_sha256",
        "package_sha256",
        "execution_inventory_sha256",
        "source_mapping_sha256",
        "configuration_sha256",
        "contract_sha256",
        "active_traffic_contract_sha256",
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
    if "permission_caller" not in readiness:
        raise ScenarioError("Readiness must freeze the presentation caller profile.")
    _validate_permission_caller(
        readiness.get("permission_caller"),
        scenario,
        queries,
        readiness["active_traffic_contract_sha256"],
        target_sha256=readiness.get("target_sha256"),
    )
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
    descriptor = scenario_variant_descriptor(
        scenario["scenario_id"], scenario["variant_id"]
    )
    now = _epoch(now_epoch, "now_epoch")
    if not _is_int(lead_seconds) or lead_seconds < MINIMUM_T_LEAD_SECONDS:
        raise ScenarioError("T must leave at least 180 seconds after plan creation.")
    minimum_t = now + lead_seconds
    # Summary writers bucket event end times in fixed 300-second intervals.
    # Align the new anchor upward so every authored phase can be checked against
    # those exact persisted buckets without broadening a phase query.
    aligned_minimum_t = ((minimum_t + 299) // 300) * 300
    anchor = (
        aligned_minimum_t
        if anchor_epoch is None
        else _epoch(anchor_epoch, "anchor_epoch")
    )
    if anchor < minimum_t:
        raise ScenarioError("T is too close to plan creation to deliver the prelude.")
    if anchor % 300:
        raise ScenarioError("T must align to the five-minute summary bucket clock.")
    assert_summary_bucket_phases(scenario, anchor)
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
        for optional_key in (
            "collection_status",
            "collection_pages_expected",
            "collection_pages_received",
        ):
            if optional_key in event:
                item[optional_key] = event[optional_key]
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
        "variant_id": scenario["variant_id"],
        "variant_contract_version": VARIANT_CONTRACT_VERSION,
        "variant_registry_sha256": variant_registry_hash(),
        "variant_template_asset": descriptor["template_asset"],
        "variant_expectation": descriptor["expectation"],
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
            **(
                {"target_sha256": readiness["target_sha256"]}
                if readiness.get("target_sha256") is not None
                else {}
            ),
            "package_sha256": readiness["package_sha256"],
            "execution_inventory_sha256": readiness["execution_inventory_sha256"],
            "source_mapping_sha256": readiness["source_mapping_sha256"],
            "configuration_sha256": readiness["configuration_sha256"],
            "contract_sha256": readiness["contract_sha256"],
            "active_traffic_contract_sha256": readiness[
                "active_traffic_contract_sha256"
            ],
            "variant_id": readiness["variant_id"],
            "variant_contract_version": readiness["variant_contract_version"],
            "variant_registry_sha256": readiness["variant_registry_sha256"],
            "template_sha256": readiness["template_sha256"],
            "fixture_sha256": dict(sorted(readiness.get("fixture_sha256", {}).items())),
            "query_definitions": dict(sorted(readiness["query_definitions"].items())),
            "permission_caller": readiness["permission_caller"],
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
    scenario = load_scenario(plan.get("scenario_id"), plan.get("variant_id"))
    descriptor = scenario_variant_descriptor(plan["scenario_id"], plan["variant_id"])
    if plan.get("template_revision") != scenario["template_revision"] or plan.get(
        "template_sha256"
    ) != scenario_template_hash(scenario):
        raise ScenarioError("Run plan references a different scenario template.")
    if (
        plan.get("variant_contract_version") != VARIANT_CONTRACT_VERSION
        or plan.get("variant_registry_sha256") != variant_registry_hash()
        or plan.get("variant_template_asset") != descriptor["template_asset"]
        or plan.get("variant_expectation") != descriptor["expectation"]
        or plan.get("readiness", {}).get("variant_id") != scenario["variant_id"]
        or plan.get("readiness", {}).get("variant_contract_version")
        != VARIANT_CONTRACT_VERSION
        or plan.get("readiness", {}).get("variant_registry_sha256")
        != variant_registry_hash()
        or plan.get("readiness", {}).get("template_sha256")
        != scenario_template_hash(scenario)
    ):
        raise ScenarioError("Run plan does not bind the registered variant identity.")
    anchor = _epoch(plan.get("anchor_t_epoch"), "anchor_t_epoch")
    if anchor % 300:
        raise ScenarioError(
            "Run plan T must align to the five-minute summary bucket clock."
        )
    assert_summary_bucket_phases(scenario, anchor)
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
    if not isinstance(readiness, dict) or "permission_caller" not in readiness:
        raise ScenarioError("Run plan readiness bindings are missing.")
    for field in (
        "lab_allocation_sha256",
        "target_identity_sha256",
        "package_sha256",
        "execution_inventory_sha256",
        "source_mapping_sha256",
        "configuration_sha256",
        "contract_sha256",
        "active_traffic_contract_sha256",
    ):
        _hash(readiness.get(field), f"readiness.{field}")
    if (
        readiness.get("variant_id") != scenario["variant_id"]
        or readiness.get("variant_contract_version") != VARIANT_CONTRACT_VERSION
        or readiness.get("variant_registry_sha256") != variant_registry_hash()
        or readiness.get("template_sha256") != scenario_template_hash(scenario)
    ):
        raise ScenarioError("Run plan readiness variant binding is invalid.")
    _validate_permission_caller(
        readiness.get("permission_caller"),
        scenario,
        readiness.get("query_definitions"),
        readiness["active_traffic_contract_sha256"],
        target_sha256=readiness.get("target_sha256"),
    )
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
        if any(
            item.get(key) != template_item.get(key)
            for key in (
                "collection_status",
                "collection_pages_expected",
                "collection_pages_received",
            )
        ):
            raise ScenarioError(
                "Run plan collection expectation differs from template."
            )
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


def assert_summary_bucket_phases(
    scenario: dict[str, Any], anchor_epoch: int
) -> list[dict[str, Any]]:
    """Require each modeled traffic end bucket to stay inside its authored phase.

    The source-owned emitter separately validates the actual native end-time
    fields. This template-level check prevents an anchor or schedule edit from
    silently moving a five-minute summary bucket across a phase boundary.
    """

    validate_scenario(scenario)
    if not _is_int(anchor_epoch) or anchor_epoch < 0 or anchor_epoch % 300:
        raise ScenarioError("Summary bucket checks require a 300-second aligned T.")
    phase_by_id = {phase["id"]: phase for phase in scenario["clock"]["phases"]}
    checks: list[dict[str, Any]] = []
    for event in scenario["evidence_schedule"]:
        phase_id = event.get("summary_bucket_phase")
        if phase_id is None:
            continue
        modeled_adm_end = anchor_epoch + event["offset_seconds"]
        bucket_epoch = modeled_adm_end // 300 * 300
        phase = phase_by_id[phase_id]
        relative_bucket = bucket_epoch - anchor_epoch
        if not (
            phase["start_offset_seconds"]
            <= relative_bucket
            < phase["end_offset_seconds"]
        ):
            raise ScenarioError(
                f"Modeled summary bucket for {event['id']} falls outside {phase_id}."
            )
        checks.append(
            {
                "schedule_id": event["id"],
                "modeled_adm_end_epoch": modeled_adm_end,
                "bucket_epoch": bucket_epoch,
                "phase_id": phase_id,
            }
        )
    return checks


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
