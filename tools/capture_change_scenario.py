#!/usr/bin/env python3
"""Verify and freeze installed change-scenario search results.

This tool consumes results and readback metadata supplied by an installed replay
driver. It never runs a Splunk search or manufactures graph, topology, Find, or
timeline rows. Captures are written once and bind the plan, exact query text,
package/configuration hashes, indexed receipts, and a complete change generation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.change_correlation.contracts import canonical_json  # noqa: E402
from tools.change_correlation.relationships import captured_dependency_identity  # noqa: E402
from tools.change_scenarios import (  # noqa: E402
    ScenarioError,
    load_scenario,
    scenario_template_hash,
    verify_run_plan,
    write_once_json,
)

MAX_CAPTURE_BYTES = 50 * 1024 * 1024
MAX_QUERY_BYTES = 16 * 1024
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
VALID_RESULT_STATUS = {"complete", "partial", "failed", "blocked", "unavailable"}
DIRECT_RESULT_KEYS = frozenset(
    {
        "graph.baseline",
        "graph.change",
        "graph.impact",
        "graph.recovery",
        "topology.baseline",
        "topology.impact",
        "topology.recovery",
        "catalog.selected",
        "find.service",
        "find.network_client",
        "scopes.selected",
        "timeline.selected",
    }
)
ENDPOINT_RESULT_KEYS = frozenset(
    {
        "endpoint.primary.baseline",
        "endpoint.primary.change",
        "endpoint.primary.impact",
        "endpoint.primary.recovery",
        "endpoint.control.impact",
    }
)
MONITORING_RESULT_KEYS = frozenset(
    {"monitoring.appdynamics", "monitoring.thousandeyes"}
)
RESULT_KEYS = DIRECT_RESULT_KEYS | ENDPOINT_RESULT_KEYS | MONITORING_RESULT_KEYS
PHASES = {"baseline", "change", "impact", "recovery"}
PRIMARY_ENDPOINT_RESULT_KEYS = frozenset(
    {
        "endpoint.primary.baseline",
        "endpoint.primary.change",
        "endpoint.primary.impact",
        "endpoint.primary.recovery",
    }
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ScenarioError(f"{label} must be a lowercase SHA-256 digest.")
    return value


def _time(value: Any, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScenarioError(f"{label} must be a numeric UTC epoch.")
    try:
        canonical_json(value)
    except ValueError as exc:
        raise ScenarioError(f"{label} must use finite millisecond precision.") from exc
    if value < 0 or value > 253_402_300_799:
        raise ScenarioError(f"{label} is outside the UTC epoch range.")
    return value


def _bounds(value: Any, label: str) -> dict[str, int | float]:
    if not isinstance(value, dict) or set(value) != {"earliest", "latest"}:
        raise ScenarioError(f"{label} must contain earliest and latest bounds.")
    earliest = _time(value["earliest"], f"{label}.earliest")
    latest = _time(value["latest"], f"{label}.latest")
    if earliest > latest:
        raise ScenarioError(f"{label} bounds are reversed.")
    return {"earliest": earliest, "latest": latest}


def _phase_window(plan: dict[str, Any], phase_id: str) -> dict[str, int]:
    phase = next(
        (item for item in plan["phase_windows"] if item.get("id") == phase_id), None
    )
    if phase is None:
        raise ScenarioError("Run plan does not contain the requested phase.")
    return {"earliest": phase["earliest_epoch"], "latest": phase["latest_epoch"]}


def _reason(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 512
        or any(ord(char) < 0x20 and char not in "\t\n\r" for char in value)
    ):
        raise ScenarioError(f"{label} requires a bounded reason.")
    return value.strip()


def _query_digest(query: Any, label: str, hash_key: str, hashes: dict[str, str]) -> str:
    if not isinstance(query, dict) or not isinstance(query.get("literal"), str):
        raise ScenarioError(f"{label} requires its exact query literal.")
    literal = query["literal"]
    encoded = literal.encode("utf-8")
    if (
        not encoded
        or len(encoded) > MAX_QUERY_BYTES
        or any(ord(char) < 0x20 and char not in "\t\n\r" for char in literal)
    ):
        raise ScenarioError(f"{label} query literal is empty or over its bound.")
    query_hash = _digest(query.get("sha256"), f"{label}.sha256")
    if _sha256(encoded) != query_hash:
        raise ScenarioError(f"{label} query hash does not match its literal.")
    if hash_key in hashes and hashes[hash_key] != query_hash:
        raise ScenarioError(f"{label} query hash key collides with another query.")
    hashes[hash_key] = query_hash
    return query_hash


def _validate_readback(
    value: Any,
    *,
    label: str,
    plan: dict[str, Any],
    result_count: int,
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("complete") is not True:
        raise ScenarioError(f"{label} requires complete indexed readback.")
    if (
        value.get("source") != "splunk_rest"
        or value.get("execution_id") != plan["execution_id"]
        or value.get("plan_sha256") != plan["plan_sha256"]
    ):
        raise ScenarioError(f"{label} is not bound to this installed run.")
    count = value.get("result_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != result_count:
        raise ScenarioError(f"{label} count differs from its retained rows.")
    index_bounds = _bounds(value.get("index_time_bounds"), f"{label}.index_time_bounds")
    receipts = value.get("receipt_fingerprints")
    if (
        not isinstance(receipts, list)
        or (result_count > 0 and not receipts)
        or any(
            not isinstance(item, str) or not HASH_RE.fullmatch(item)
            for item in receipts
        )
        or receipts != sorted(set(receipts))
    ):
        raise ScenarioError(f"{label} requires sorted indexed receipt fingerprints.")
    return {**value, "index_time_bounds": index_bounds}


def _phase_for_endpoint(key: str) -> str:
    if key == "endpoint.control.impact":
        return "impact"
    return key.rsplit(".", 1)[1]


def _endpoint_selection(
    key: str, scenario: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    phase = _phase_for_endpoint(key)
    window = _phase_window(plan, phase)
    selection = scenario["selection"]
    is_control = key == "endpoint.control.impact"
    address = selection["control_client_ip"] if is_control else selection["client_ip"]
    scope = selection["control_scope"] if is_control else selection["change_scope"]
    start, end = window["earliest"], window["latest"]
    return {
        "schemaVersion": 1,
        "id": f"{scope}:{address}:{start}:{end}",
        "address": address,
        "scope": scope,
        "start": start,
        "end": end,
    }


def _validate_endpoint_query(
    value: Any,
    *,
    label: str,
    plan: dict[str, Any],
    expected_earliest: str,
    expected_latest: str,
    max_rows: int,
    hash_key: str,
    query_hashes: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") != "complete":
        if not isinstance(value, dict) or value.get("status") not in {
            "blocked",
            "unavailable",
            "not_applicable",
        }:
            raise ScenarioError(f"{label} has an unsupported nested state.")
        if value.get("status") == "not_applicable":
            return {
                "status": "not_applicable",
                "reason": _reason(value.get("reason"), label),
            }
        if value.get("rows") not in (None, []) or value.get("readback") not in (
            None,
            {},
        ):
            raise ScenarioError(f"Non-complete {label} cannot expose data or readback.")
        if value.get("query") is not None:
            _query_digest(value["query"], f"{label}.query", hash_key, query_hashes)
        return {**value, "reason": _reason(value.get("reason"), label), "rows": []}
    query_hash = _query_digest(value, label, hash_key, query_hashes)
    if (
        value.get("earliest") != expected_earliest
        or value.get("latest") != expected_latest
        or value.get("max_rows") != max_rows
    ):
        raise ScenarioError(f"{label} selector bounds or row cap are not exact.")
    rows = value.get("rows")
    if (
        not isinstance(rows, list)
        or len(rows) > max_rows
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ScenarioError(f"{label} raw search rows exceed their bound.")
    readback = _validate_readback(
        value.get("readback"),
        label=f"{label}.readback",
        plan=plan,
        result_count=len(rows),
    )
    return {
        **value,
        "sha256": query_hash,
        "rows": rows,
        "readback": readback,
    }


def _validate_endpoint_result(
    key: str,
    value: Any,
    *,
    scenario: dict[str, Any],
    plan: dict[str, Any],
    target_identity_sha256: str,
    query_hashes: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") not in VALID_RESULT_STATUS:
        raise ScenarioError(f"Endpoint result {key} has an unsupported state.")
    if value["status"] != "complete":
        if set(value) - {"status", "reason"}:
            raise ScenarioError(
                f"Unavailable endpoint result {key} must remain minimal."
            )
        return {"status": value["status"], "reason": _reason(value.get("reason"), key)}

    expected = _endpoint_selection(key, scenario, plan)
    selection = value.get("selection")
    if not isinstance(selection, dict) or set(selection) != {
        "schemaVersion",
        "id",
        "address",
        "scope",
        "start",
        "end",
        "configurationFingerprint",
        "trafficContract",
    }:
        raise ScenarioError(
            f"Endpoint result {key} requires the exact native selection."
        )
    if any(selection.get(field) != expected[field] for field in expected):
        raise ScenarioError(
            f"Endpoint result {key} selection differs from its scenario phase."
        )
    configuration_fingerprint = _digest(
        selection.get("configurationFingerprint"), f"{key}.configurationFingerprint"
    )
    traffic_contract = selection.get("trafficContract")
    if isinstance(traffic_contract, bool) or traffic_contract not in {1, 2}:
        raise ScenarioError(f"Endpoint result {key} traffic contract is unsupported.")

    config = value.get("config_snapshot")
    if not isinstance(config, dict):
        raise ScenarioError(
            f"Endpoint result {key} requires its caller-readable configuration snapshot."
        )
    required_config_fields = {
        "fingerprint",
        "trafficContract",
        "summaryIndexes",
        "mappings",
        "identities",
        "identityAvailable",
        "dns",
        "maxAgeSeconds",
    }
    if not required_config_fields.issubset(config):
        raise ScenarioError(
            f"Endpoint result {key} must retain the complete EvidenceConfiguration."
        )
    if (
        config.get("fingerprint") != configuration_fingerprint
        or config.get("trafficContract") != traffic_contract
        or not isinstance(config.get("summaryIndexes"), list)
        or not config["summaryIndexes"]
        or any(
            not isinstance(index, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,79}", index)
            for index in config["summaryIndexes"]
        )
        or len(set(config["summaryIndexes"])) != len(config["summaryIndexes"])
    ):
        raise ScenarioError(
            f"Endpoint result {key} configuration snapshot is inconsistent."
        )
    if not isinstance(config.get("identityAvailable"), bool) or not isinstance(
        config.get("identities"), list
    ):
        raise ScenarioError(f"Endpoint result {key} identity availability is missing.")
    if not isinstance(config.get("dns"), list):
        raise ScenarioError(f"Endpoint result {key} DNS configuration is missing.")
    max_age = config.get("maxAgeSeconds")
    if (
        isinstance(max_age, bool)
        or not isinstance(max_age, (int, float))
        or not math.isfinite(max_age)
        or max_age <= 0
    ):
        raise ScenarioError(f"Endpoint result {key} maxAgeSeconds is invalid.")
    if "supplemental" in config and not isinstance(config["supplemental"], list):
        raise ScenarioError(
            f"Endpoint result {key} supplemental configuration is invalid."
        )
    if "clockUncertaintySeconds" in config:
        uncertainty = config["clockUncertaintySeconds"]
        if (
            isinstance(uncertainty, bool)
            or not isinstance(uncertainty, (int, float))
            or not math.isfinite(uncertainty)
            or uncertainty < 0
        ):
            raise ScenarioError(f"Endpoint result {key} clock uncertainty is invalid.")
    if not config["identityAvailable"] and config["identities"]:
        raise ScenarioError(
            f"Endpoint result {key} cannot claim unavailable identity rows."
        )
    for identity in config["identities"]:
        if (
            not isinstance(identity, dict)
            or identity.get("ip") != expected["address"]
            or identity.get("scope") != expected["scope"]
            or not isinstance(identity.get("entity_id"), str)
            or not identity["entity_id"]
            or len(identity["entity_id"]) > 1024
            or not isinstance(identity.get("entity_kind"), str)
            or not identity["entity_kind"]
            or len(identity["entity_kind"]) > 128
        ):
            raise ScenarioError(
                f"Endpoint result {key} contains an invalid identity row."
            )
        _time(identity.get("valid_from"), f"{key}.identity.valid_from")
        if identity.get("valid_end") is not None:
            _time(identity["valid_end"], f"{key}.identity.valid_end")
            if identity["valid_end"] <= identity["valid_from"]:
                raise ScenarioError(
                    f"Endpoint result {key} identity interval is reversed."
                )
    mappings = config.get("mappings")
    if not isinstance(mappings, list) or not any(
        isinstance(mapping, dict)
        and mapping.get("scope") == expected["scope"]
        and mapping.get("mapping_status") == "verified"
        for mapping in mappings
    ):
        raise ScenarioError(
            f"Endpoint result {key} lacks a verified routing-scope mapping."
        )
    acl = config.get("caller_acl")
    config_readback = config.get("readback")
    if not isinstance(acl, dict) or not isinstance(config_readback, dict):
        raise ScenarioError(f"Endpoint result {key} lacks caller ACL/readback proof.")
    if (
        acl.get("status") != "owned_local_lab_admin"
        or not isinstance(acl.get("principal"), str)
        or not acl["principal"].strip()
        or len(acl["principal"]) > 256
        or acl.get("admin_all_objects") is not True
        or acl.get("target_identity_sha256") != target_identity_sha256
    ):
        raise ScenarioError(
            f"Endpoint result {key} caller is not proved as local lab admin."
        )
    _time(acl.get("checked_at"), f"{key}.caller_acl.checked_at")
    _digest(
        acl.get("target_identity_sha256"), f"{key}.caller_acl.target_identity_sha256"
    )
    if (
        config_readback.get("complete") is not True
        or config_readback.get("source") != "ToolkitEvidenceConfigClient.read"
        or config_readback.get("execution_id") != plan["execution_id"]
        or config_readback.get("plan_sha256") != plan["plan_sha256"]
        or config_readback.get("configuration_fingerprint") != configuration_fingerprint
        or config_readback.get("config_sha256")
        != _sha256(
            canonical_json(
                {
                    field: config[field]
                    for field in (
                        "fingerprint",
                        "trafficContract",
                        "summaryIndexes",
                        "mappings",
                        "identities",
                        "identityAvailable",
                        "dns",
                        "maxAgeSeconds",
                        "supplemental",
                        "clockUncertaintySeconds",
                    )
                    if field in config
                }
            )
        )
        or not isinstance(config_readback.get("settings_revision"), str)
        or not config_readback["settings_revision"]
    ):
        raise ScenarioError(
            f"Endpoint result {key} configuration readback is not run-bound."
        )
    _time(
        config_readback.get("captured_at"),
        f"{key}.config_snapshot.readback.captured_at",
    )

    selectors = value.get("selectors")
    if not isinstance(selectors, dict):
        raise ScenarioError(f"Endpoint result {key} selectors are missing.")
    summary_selector = " OR ".join(
        f"index={index}" for index in config["summaryIndexes"]
    )
    selection_window = _phase_window(plan, _phase_for_endpoint(key))
    summary_earliest = str((selection_window["earliest"] // 300) * 300)
    summary_latest = str((selection_window["latest"] // 300) * 300 + 300)
    if (
        selectors.get("summary_selector") != summary_selector
        or selectors.get("query_earliest") != summary_earliest
        or selectors.get("query_latest") != summary_latest
    ):
        raise ScenarioError(
            f"Endpoint result {key} selector metadata differs from its exact window."
        )

    queries = value.get("queries")
    if not isinstance(queries, dict) or "conversations" not in queries:
        raise ScenarioError(
            f"Endpoint result {key} must retain its conversation query."
        )
    conversation = _validate_endpoint_query(
        queries["conversations"],
        label=f"{key}.conversations",
        plan=plan,
        expected_earliest=summary_earliest,
        expected_latest=summary_latest,
        max_rows=502,
        hash_key=f"{key}.conversations",
        query_hashes=query_hashes,
    )
    observations = queries.get("observations")
    if traffic_contract == 2:
        if observations is None:
            raise ScenarioError(f"Endpoint result {key} needs V2 traffic observations.")
        observations = _validate_endpoint_query(
            observations,
            label=f"{key}.observations",
            plan=plan,
            expected_earliest=summary_earliest,
            expected_latest=summary_latest,
            max_rows=101,
            hash_key=f"{key}.observations",
            query_hashes=query_hashes,
        )
    elif observations is not None:
        observations = _validate_endpoint_query(
            observations,
            label=f"{key}.observations",
            plan=plan,
            expected_earliest=summary_earliest,
            expected_latest=summary_latest,
            max_rows=101,
            hash_key=f"{key}.observations",
            query_hashes=query_hashes,
        )
        if observations["status"] != "not_applicable":
            raise ScenarioError(
                f"Endpoint result {key} has observations for contract V1."
            )
    return {
        **value,
        "selection": selection,
        "selectors": selectors,
        "config_snapshot": config,
        "queries": {
            "conversations": conversation,
            **({"observations": observations} if observations is not None else {}),
        },
    }


def _validate_result(
    key: str,
    result: Any,
    *,
    scenario: dict[str, Any],
    plan: dict[str, Any],
    expected_query_hashes: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ScenarioError(f"Result {key} must be an object.")
    status = result.get("status")
    if status not in VALID_RESULT_STATUS:
        raise ScenarioError(f"Result {key} has an unsupported status.")
    rows = result.get("rows")
    if status != "complete":
        if rows not in (None, []):
            raise ScenarioError(f"Non-complete result {key} cannot expose rows.")
        if result.get("readback") not in (None, {}):
            raise ScenarioError(f"Non-complete result {key} cannot claim readback.")
        if status in {"blocked", "unavailable", "partial", "failed"}:
            _reason(result.get("reason"), f"Result {key}")
        if result.get("query") is not None:
            _query_digest(result["query"], f"{key}.query", key, expected_query_hashes)
        return {**result, "rows": []}
    if (
        not isinstance(rows, list)
        or len(rows) > 100_000
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ScenarioError(
            f"Complete result {key}.rows must be a bounded object array."
        )

    query = result.get("query")
    _query_digest(query, f"{key}.query", key, expected_query_hashes)

    window = result.get("window")
    if not isinstance(window, dict) or window.get("basis") != "source_time":
        raise ScenarioError(f"Result {key} requires an explicit source-time window.")
    bounds = _bounds(
        {"earliest": window.get("earliest"), "latest": window.get("latest")},
        f"{key}.window",
    )
    if key.startswith(("graph.", "topology.")):
        _, phase_id = key.split(".", 1)
        if phase_id not in PHASES or bounds != _phase_window(plan, phase_id):
            raise ScenarioError(
                f"Result {key} window does not match its planned phase."
            )
    if key == "timeline.selected" and bounds != {
        "earliest": plan["anchor_t_epoch"],
        "latest": plan["planned_run_end_epoch"],
    }:
        raise ScenarioError("Timeline result must retain the full incident window.")

    if key.startswith(("graph.", "topology.", "catalog.", "scopes.")):
        args = result.get("args")
        if args != scenario["application"]:
            raise ScenarioError(
                f"Result {key} application arguments do not match template."
            )
    if key == "find.service":
        expected_input = {
            "field": "service",
            "value": scenario["application"]["service"],
        }
        if result.get("input") != expected_input:
            raise ScenarioError("find.service input must name the exact service term.")
    if key == "find.network_client":
        expected_input = {
            "field": "client_ip",
            "value": scenario["selection"]["client_ip"],
        }
        if result.get("input") != expected_input:
            raise ScenarioError(
                "find.network_client input must name the selected client."
            )
    if key in MONITORING_RESULT_KEYS and status == "complete":
        if result.get("args") != scenario["application"] or bounds != _phase_window(
            plan, "impact"
        ):
            raise ScenarioError(
                f"{key} must use the same application and impact window."
            )

    readback = _validate_readback(
        result.get("readback"),
        label=f"{key}.readback",
        plan=plan,
        result_count=len(rows),
    )
    result = {
        **result,
        "window": {**bounds, "basis": "source_time"},
        "readback": readback,
    }
    return result


def captured_dependency_binding(
    *,
    scenario_id: str,
    execution_id: str,
    graph_result_key: str,
    edge_id: str,
    scope: str,
    window: dict[str, Any],
    query_sha256: str,
    active_traffic_contract_sha256: str,
    receipt_fingerprints: list[str],
    graph_result: dict[str, Any],
) -> dict[str, Any]:
    """Mint a dependency identity from a captured edge and its receipt evidence."""

    if scenario_id not in {"track-a-firewall", "track-b-fabric"}:
        raise ScenarioError("Captured dependency scenario is not an approved track.")
    if not isinstance(execution_id, str) or not execution_id:
        raise ScenarioError("Captured dependency requires an execution ID.")
    if graph_result_key not in {
        "graph.baseline",
        "graph.change",
        "graph.impact",
        "graph.recovery",
    }:
        raise ScenarioError("Captured dependency must refer to a phase graph result.")
    _digest(query_sha256, "query_sha256")
    _digest(active_traffic_contract_sha256, "active_traffic_contract_sha256")
    _bounds(window, "captured dependency window")
    if not isinstance(scope, str) or not scope:
        raise ScenarioError("Captured dependency requires an exact routing scope.")
    if not isinstance(receipt_fingerprints, list) or not receipt_fingerprints:
        raise ScenarioError(
            "Captured dependency requires indexed receipt fingerprints."
        )
    receipts = sorted(
        set(_digest(item, "receipt_fingerprint") for item in receipt_fingerprints)
    )
    readback = graph_result.get("readback")
    coverage = (
        readback.get("query_input_coverage") if isinstance(readback, dict) else None
    )
    summary = coverage.get("summary_readback") if isinstance(coverage, dict) else None
    expected_window = _bounds(window, "captured dependency window")
    if (
        not isinstance(coverage, dict)
        or not isinstance(summary, dict)
        or coverage.get("schema_version") != 1
        or coverage.get("basis") != "query_level_input_coverage"
        or coverage.get("qualification")
        != "eligible_input_superset_not_per_edge_lineage"
        or coverage.get("execution_id") != execution_id
        or coverage.get("query_sha256") != query_sha256
        or coverage.get("scope") != scope
        or coverage.get("graph_window") != expected_window
        or summary.get("receipt_fingerprints") != receipts
        or readback.get("receipt_fingerprints") != receipts
        or readback.get("index_time_bounds") != summary.get("index_window")
        or not isinstance(readback.get("query_job"), dict)
    ):
        raise ScenarioError(
            "Captured dependency lacks matching complete query-input coverage."
        )
    coverage_sha256 = _sha256(canonical_json(coverage))
    rows = graph_result.get("rows")
    if not isinstance(rows, list) or not any(
        isinstance(row, dict)
        and row.get("id") == edge_id
        and row.get("row_type") == "edge"
        for row in rows
    ):
        raise ScenarioError("Dependency edge ID is not in the captured graph result.")
    result_hash = _sha256(canonical_json(graph_result))
    body = {
        "authority": "atlas:observed_dependency",
        "identity_type": "captured_dependency",
        "scenario_id": scenario_id,
        "execution_id": execution_id,
        "graph_result_key": graph_result_key,
        "graph_result_sha256": result_hash,
        "edge_id": edge_id,
        "scope": scope,
        "window": expected_window,
        "query_sha256": query_sha256,
        "receipt_basis": "query_input_coverage_v1",
        "query_input_coverage_sha256": coverage_sha256,
        "active_traffic_contract_sha256": active_traffic_contract_sha256,
        "receipt_fingerprints": receipts,
    }
    try:
        identity = captured_dependency_identity(body)
    except (TypeError, ValueError) as exc:
        raise ScenarioError(
            "Captured dependency body failed shared normalization."
        ) from exc
    if (
        not isinstance(identity, dict)
        or identity.get("authority") != "atlas:observed_dependency"
        or identity.get("type") != "captured_dependency"
        or not isinstance(identity.get("id"), str)
        or identity.get("binding") != body
    ):
        raise ScenarioError("Shared captured dependency identity is malformed.")
    return identity


def _validate_timeline(
    result: dict[str, Any], scenario: dict[str, Any], plan: dict[str, Any]
) -> tuple[str, str]:
    validation = result.get("generation_validation")
    selection = result.get("selection")
    if not isinstance(validation, dict) or not isinstance(selection, dict):
        raise ScenarioError(
            "Timeline requires a generation validation and exact selection."
        )
    manifest = validation.get("manifest")
    if not isinstance(manifest, dict):
        raise ScenarioError("Timeline generation manifest is missing.")
    generation_id = _digest(validation.get("generation_id"), "generation_id")
    manifest_generation_id = _digest(
        manifest.get("generation_id"), "manifest.generation_id"
    )
    body = {key: value for key, value in manifest.items() if key != "generation_id"}
    generation_sha = _sha256(canonical_json(body))
    if generation_id != manifest_generation_id or generation_sha != generation_id:
        raise ScenarioError(
            "Timeline generation ID does not hash its immutable manifest."
        )
    complete_count = validation.get("complete_row_count")
    generation_rows = result.get("generation_rows")
    rows_sha256 = _digest(manifest.get("rows_sha256"), "generation rows_sha256")
    if (
        isinstance(complete_count, bool)
        or not isinstance(complete_count, int)
        or complete_count != manifest.get("row_count")
        or validation.get("rows_sha256") != rows_sha256
        or validation.get("validated_before_filter") is not True
        or not isinstance(generation_rows, list)
        or len(generation_rows) != complete_count
    ):
        raise ScenarioError(
            "Timeline does not retain a complete generation before filtering."
        )
    if len(generation_rows) > 10_000:
        raise ScenarioError("Timeline full generation exceeds 10,000 rows.")
    generation_ids: list[str] = []
    row_bytes: list[bytes] = []
    for row in generation_rows:
        if not isinstance(row, dict) or row.get("generation_id") != generation_id:
            raise ScenarioError(
                "Timeline generation row has an unexpected generation ID."
            )
        record_id = _digest(row.get("record_id"), "generation row record_id")
        generation_ids.append(record_id)
        row_bytes.append(
            canonical_json(
                {key: value for key, value in row.items() if key != "generation_id"}
            )
        )
    if generation_ids != sorted(set(generation_ids)):
        raise ScenarioError(
            "Timeline full generation rows must be uniquely sorted by record ID."
        )
    if _sha256(b"\n".join(row_bytes)) != rows_sha256:
        raise ScenarioError(
            "Timeline full row set does not match the immutable manifest hash."
        )
    generation_by_id = dict(zip(generation_ids, generation_rows))
    display_rows = result.get("rows")
    if not isinstance(display_rows, list) or any(
        not isinstance(row, dict)
        or row.get("generation_id") != generation_id
        or row.get("record_id") not in set(generation_ids)
        or canonical_json(row) != canonical_json(generation_by_id[row["record_id"]])
        for row in display_rows
    ):
        raise ScenarioError(
            "Timeline selected rows are not a subset of the full generation."
        )
    _bounds(validation.get("ingest_bounds"), "generation ingest bounds")
    if not isinstance(selection.get("scope"), str) or not selection["scope"]:
        raise ScenarioError("Timeline selection requires an exact routing scope.")
    if selection["scope"] != scenario["selection"]["change_scope"]:
        raise ScenarioError("Timeline selection routing scope differs from the track.")
    selected_window = selection.get("window")
    selection_bounds = _bounds(
        {"earliest": selected_window.get("start"), "latest": selected_window.get("end")}
        if isinstance(selected_window, dict)
        else None,
        "timeline selection window",
    )
    if selection_bounds != {
        "earliest": plan["anchor_t_epoch"],
        "latest": plan["planned_run_end_epoch"],
    }:
        raise ScenarioError("Timeline selection must cover the full incident window.")
    change_ids = selection.get("change_ids")
    if (
        not isinstance(change_ids, list)
        or any(not isinstance(item, str) or not item for item in change_ids)
        or len(change_ids) != len(set(change_ids))
    ):
        raise ScenarioError("Timeline selection change IDs must be text.")
    if change_ids != sorted(row["record_id"] for row in display_rows):
        raise ScenarioError("Timeline selection change IDs do not match selected rows.")
    selected_change_ids = set(change_ids)
    for row in display_rows:
        if row.get("scope") != selection["scope"]:
            raise ScenarioError("Timeline selected row scope differs from selection.")
        row_change_id = row.get("change_id")
        if row_change_id is not None and row_change_id not in selected_change_ids:
            raise ScenarioError("Timeline selected row is outside selected changes.")
        earliest = row.get("earliest_at")
        latest = row.get("latest_at")
        if earliest is not None or latest is not None:
            row_earliest = (
                _time(earliest, "timeline selected row earliest_at")
                if earliest is not None
                else float("-inf")
            )
            row_latest = (
                _time(latest, "timeline selected row latest_at")
                if latest is not None
                else float("inf")
            )
            if row_earliest > row_latest or (
                row_latest < selection_bounds["earliest"]
                or row_earliest >= selection_bounds["latest"]
            ):
                raise ScenarioError(
                    "Timeline selected row is outside selection window."
                )
        else:
            row_time = next(
                (
                    row.get(field)
                    for field in (
                        "event_at",
                        "effective_at",
                        "observed_at",
                        "received_at",
                    )
                    if row.get(field) is not None
                ),
                None,
            )
            if row_time is None or not (
                selection_bounds["earliest"]
                <= _time(row_time, "timeline selected row time")
                < selection_bounds["latest"]
            ):
                raise ScenarioError(
                    "Timeline selected row is outside selection window."
                )
    return generation_id, generation_sha


def build_capture_bundle(
    scenario: dict[str, Any],
    plan: dict[str, Any],
    execution_report: dict[str, Any],
    results: dict[str, Any],
    *,
    required_result_keys: set[str] | None = None,
    dependency_bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify installed evidence, then create a self-checking immutable bundle."""

    verify_run_plan(plan)
    if (
        scenario.get("scenario_id") != plan["scenario_id"]
        or scenario_template_hash(scenario) != plan["template_sha256"]
    ):
        raise ScenarioError("Capture template does not match the immutable run plan.")
    if not isinstance(execution_report, dict) or (
        execution_report.get("scenario_id") != plan["scenario_id"]
        or execution_report.get("execution_id") != plan["execution_id"]
        or execution_report.get("plan_sha256") != plan["plan_sha256"]
        or execution_report.get("status") != "readback_complete"
        or execution_report.get("readback_status") != "complete"
    ):
        raise ScenarioError(
            "Execution report is not a complete readback for this plan."
        )
    source_bounds = _bounds(
        execution_report.get("source_time_bounds"), "source_time_bounds"
    )
    index_bounds = _bounds(
        execution_report.get("index_time_bounds"), "index_time_bounds"
    )
    if source_bounds["earliest"] > source_bounds["latest"]:
        raise ScenarioError("Source event bounds are invalid.")
    event_receipts = execution_report.get("events")
    plan_by_id = {item["id"]: item for item in plan["schedule"]}
    planned_ids = set(plan_by_id)
    if not isinstance(event_receipts, list):
        raise ScenarioError("Execution report must retain every planned event receipt.")
    receipt_by_id = {
        item.get("id"): item for item in event_receipts if isinstance(item, dict)
    }
    if set(receipt_by_id) != planned_ids or len(receipt_by_id) != len(event_receipts):
        raise ScenarioError(
            "Execution report must retain each planned event exactly once."
        )
    actual_started = _time(
        execution_report.get("actual_run_started_epoch"), "actual_run_started_epoch"
    )
    actual_ended = _time(
        execution_report.get("actual_run_ended_epoch"), "actual_run_ended_epoch"
    )
    if actual_ended < actual_started:
        raise ScenarioError("Execution report run bounds are reversed.")
    if (
        execution_report.get("execution_inventory_sha256")
        != plan["readiness"]["execution_inventory_sha256"]
        or execution_report.get("target_identity_sha256")
        != plan["readiness"]["target_identity_sha256"]
        or execution_report.get("contract_sha256")
        != plan["readiness"]["contract_sha256"]
    ):
        raise ScenarioError(
            "Execution report inventory or contract hash differs from the plan."
        )
    planned_bounds = plan["planned_source_time_bounds"]
    if (
        source_bounds["earliest"] < planned_bounds["earliest_epoch"]
        or source_bounds["latest"] > planned_bounds["latest_epoch"]
    ):
        raise ScenarioError("Execution report source-time bounds exceed the plan.")
    for event_id in planned_ids:
        item = receipt_by_id[event_id]
        plan_item = plan_by_id[event_id]
        if not isinstance(item, dict) or item.get("status") not in {
            "delivered",
            "blocked",
        }:
            raise ScenarioError("Execution report event status is invalid.")
        if item.get("status") == "blocked":
            if (
                plan_item["status"] != "blocked"
                or plan_item["required"]
                or any(
                    item.get(key) is not None
                    for key in (
                        "actual_emission_epoch",
                        "transport_acknowledgment_epoch",
                        "indexed_receipt_epoch",
                        "readback_epoch",
                    )
                )
            ):
                raise ScenarioError(
                    "A required or emitted event cannot be marked blocked."
                )
            continue
        actual = _time(item.get("actual_emission_epoch"), f"events.{event_id}.emission")
        planned = item.get(
            "planned_source_epoch", item.get("planned_collection_start_epoch")
        )
        receipt = _time(
            item.get("indexed_receipt_epoch"), f"events.{event_id}.indexed_receipt"
        )
        readback = _time(item.get("readback_epoch"), f"events.{event_id}.readback")
        expected_planned = plan_item.get(
            "planned_source_epoch", plan_item.get("planned_collection_start_epoch")
        )
        if (
            planned != expected_planned
            or plan_item["status"] != "planned"
            or actual < planned
            or receipt < actual
            or readback < receipt
            or readback > actual_ended
            or actual_started > actual
        ):
            raise ScenarioError(
                "Event emission, indexed receipt, and readback order is invalid."
            )
        if item.get("index_time_field") != "_indextime":
            raise ScenarioError(
                "Indexed receipt must come from actual _indextime readback."
            )

    if not isinstance(results, dict) or set(results) != RESULT_KEYS:
        raise ScenarioError("Capture must include the fixed two-track result key set.")
    query_hashes: dict[str, str] = {}
    validated_results = {}
    for key in sorted(results):
        if key in ENDPOINT_RESULT_KEYS:
            validated_results[key] = _validate_endpoint_result(
                key,
                results[key],
                scenario=scenario,
                plan=plan,
                target_identity_sha256=plan["readiness"]["target_identity_sha256"],
                query_hashes=query_hashes,
            )
        else:
            validated_results[key] = _validate_result(
                key,
                results[key],
                scenario=scenario,
                plan=plan,
                expected_query_hashes=query_hashes,
            )
    timeline = validated_results["timeline.selected"]
    if timeline["status"] == "complete":
        generation_id, generation_sha = _validate_timeline(timeline, scenario, plan)
    else:
        generation_id = generation_sha = ""

    required = set(DIRECT_RESULT_KEYS | PRIMARY_ENDPOINT_RESULT_KEYS)
    if scenario["scenario_id"] == "track-a-firewall":
        required.add("endpoint.control.impact")
    if required_result_keys is not None and required_result_keys != required:
        raise ScenarioError(
            "Capture completeness cannot override the frozen primary result set."
        )
    capture_status = (
        "complete"
        if all(validated_results[key]["status"] == "complete" for key in required)
        else "partial"
    )
    active = plan["readiness"]
    if active["contract_sha256"] != execution_report.get("contract_sha256"):
        raise ScenarioError("Execution contract hash differs from the run plan.")
    traffic_contract_hash = _digest(
        execution_report.get("active_traffic_contract_sha256"),
        "active_traffic_contract_sha256",
    )
    bindings = dependency_bindings or []
    if not isinstance(bindings, list):
        raise ScenarioError("Captured dependency bindings must be an array.")
    validated_bindings: list[dict[str, Any]] = []
    for binding in bindings:
        if not isinstance(binding, dict):
            raise ScenarioError("Captured dependency binding must be an object.")
        binding_body = binding.get("binding")
        if not isinstance(binding_body, dict):
            raise ScenarioError(
                "Captured dependency identity must retain its canonical binding body."
            )
        if (
            binding.get("authority") != "atlas:observed_dependency"
            or binding.get("type") != "captured_dependency"
        ):
            raise ScenarioError("Captured dependency authority or type is invalid.")
        graph_key = binding_body.get("graph_result_key")
        if graph_key not in validated_results or not graph_key.startswith("graph."):
            raise ScenarioError(
                "Captured dependency references an unknown graph result."
            )
        graph_result = validated_results[graph_key]
        if graph_result.get("status") != "complete":
            raise ScenarioError("Captured dependency graph result is not complete.")
        query_sha = graph_result["query"]["sha256"]
        receipts = graph_result["readback"]["receipt_fingerprints"]
        graph_window = graph_result["window"]
        if (
            not isinstance(graph_window, dict)
            or graph_window.get("basis") != "source_time"
        ):
            raise ScenarioError(
                "Captured dependency graph evidence must use a source-time window."
            )
        expected_window = {
            "earliest": graph_window["earliest"],
            "latest": graph_window["latest"],
        }
        if (
            binding_body.get("scenario_id") != scenario["scenario_id"]
            or binding_body.get("execution_id") != plan["execution_id"]
            or binding_body.get("scope") != scenario["selection"]["change_scope"]
            or binding_body.get("window") != expected_window
            or binding_body.get("query_sha256") != query_sha
            or binding_body.get("active_traffic_contract_sha256")
            != traffic_contract_hash
            or binding_body.get("receipt_fingerprints") != receipts
            or binding_body.get("graph_result_sha256")
            != _sha256(canonical_json(graph_result))
        ):
            raise ScenarioError(
                "Captured dependency binding does not match its graph evidence."
            )
        expected_binding = captured_dependency_binding(
            scenario_id=scenario["scenario_id"],
            execution_id=plan["execution_id"],
            graph_result_key=graph_key,
            edge_id=binding_body.get("edge_id"),
            scope=scenario["selection"]["change_scope"],
            window=expected_window,
            query_sha256=query_sha,
            active_traffic_contract_sha256=traffic_contract_hash,
            receipt_fingerprints=receipts,
            graph_result=graph_result,
        )
        if binding != expected_binding:
            raise ScenarioError(
                "Captured dependency identity does not match its evidence."
            )
        validated_bindings.append(expected_binding)
    if [item["id"] for item in validated_bindings] != sorted(
        {item["id"] for item in validated_bindings}
    ):
        raise ScenarioError(
            "Captured dependency bindings must be unique and ID-sorted."
        )
    fixture_file_hashes = active.get("fixture_sha256", {})
    phase_windows = {
        item["id"]: {
            "earliest": item["earliest_epoch"],
            "latest": item["latest_epoch"],
        }
        for item in plan["phase_windows"]
    }
    manifest = {
        "scenario_id": scenario["scenario_id"],
        "template_revision": scenario["template_revision"],
        "template_sha256": scenario_template_hash(scenario),
        "execution_id": plan["execution_id"],
        "plan_sha256": plan["plan_sha256"],
        "application": scenario["application"],
        "selection": scenario["selection"],
        "phase_windows": phase_windows,
        "anchor_utc": plan["anchor_t_utc"],
        "anchor_epoch": plan["anchor_t_epoch"],
        "actual_run_started_epoch": _time(
            execution_report.get("actual_run_started_epoch"), "actual_run_started_epoch"
        ),
        "actual_run_ended_epoch": _time(
            execution_report.get("actual_run_ended_epoch"), "actual_run_ended_epoch"
        ),
        "source_time_bounds": source_bounds,
        "index_time_bounds": index_bounds,
        "package_sha256": active["package_sha256"],
        "execution_inventory_sha256": active["execution_inventory_sha256"],
        "fixture_sha256": _sha256(canonical_json(fixture_file_hashes)),
        "fixture_file_sha256": fixture_file_hashes,
        "query_sha256": query_hashes,
        "contract_sha256": active["contract_sha256"],
        "configuration_sha256": active["configuration_sha256"],
        "active_traffic_contract_sha256": traffic_contract_hash,
        "change_generation_id": generation_id or None,
        "change_generation_sha256": generation_sha or None,
        "captured_dependencies": validated_bindings,
        "capture_status": capture_status,
        "services_contacted": True,
    }
    manifest["capture_sha256"] = _sha256(canonical_json(validated_results))
    bundle = {"schema_version": 1, "manifest": manifest, "results": validated_results}
    if len(canonical_json(bundle)) > MAX_CAPTURE_BYTES:
        raise ScenarioError("Capture bundle exceeds 50 MiB.")
    bundle["bundle_sha256"] = _sha256(
        canonical_json({"manifest": manifest, "results": validated_results})
    )
    return bundle


def verify_capture_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict) or bundle.get("schema_version") != 1:
        raise ScenarioError("Capture bundle schema is unsupported.")
    manifest, results = bundle.get("manifest"), bundle.get("results")
    if not isinstance(manifest, dict) or not isinstance(results, dict):
        raise ScenarioError("Capture bundle manifest or results are missing.")
    _digest(
        manifest.get("execution_inventory_sha256"),
        "execution_inventory_sha256",
    )
    capture_hash = _digest(manifest.get("capture_sha256"), "capture_sha256")
    if _sha256(canonical_json(results)) != capture_hash:
        raise ScenarioError("Capture results do not match capture_sha256.")
    bundle_hash = _digest(bundle.get("bundle_sha256"), "bundle_sha256")
    body = {"manifest": manifest, "results": results}
    if _sha256(canonical_json(body)) != bundle_hash:
        raise ScenarioError("Capture bundle content does not match bundle_sha256.")
    scenario = load_scenario(manifest.get("scenario_id"))
    if (
        manifest.get("template_revision") != scenario["template_revision"]
        or manifest.get("template_sha256") != scenario_template_hash(scenario)
        or manifest.get("application") != scenario["application"]
        or manifest.get("selection") != scenario["selection"]
        or set(results) != RESULT_KEYS
        or manifest.get("capture_status") not in {"complete", "partial"}
        or manifest.get("services_contacted") is not True
    ):
        raise ScenarioError("Capture bundle is not bound to an approved template.")
    required = set(DIRECT_RESULT_KEYS | PRIMARY_ENDPOINT_RESULT_KEYS)
    if scenario["scenario_id"] == "track-a-firewall":
        required.add("endpoint.control.impact")
    if (
        any(
            not isinstance(results.get(key), dict)
            or results[key].get("status") != "complete"
            for key in required
        )
        and manifest.get("capture_status") == "complete"
    ):
        raise ScenarioError(
            "A capture marked complete has unavailable required results."
        )
    expected_capture_status = (
        "complete"
        if all(results[key].get("status") == "complete" for key in required)
        else "partial"
    )
    if manifest.get("capture_status") != expected_capture_status:
        raise ScenarioError("Capture status does not match required result statuses.")
    anchor = _time(manifest.get("anchor_epoch"), "anchor_epoch")
    expected_windows = {
        phase["id"]: {
            "earliest": anchor + phase["start_offset_seconds"],
            "latest": anchor + phase["end_offset_seconds"],
        }
        for phase in scenario["clock"]["phases"]
    }
    if manifest.get("phase_windows") != expected_windows:
        raise ScenarioError("Capture phase windows do not match its absolute anchor.")
    expected_anchor_utc = (
        datetime.fromtimestamp(anchor, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    if manifest.get("anchor_utc") != expected_anchor_utc:
        raise ScenarioError("Capture anchor UTC label differs from its epoch.")
    fixture_files = manifest.get("fixture_file_sha256")
    if not isinstance(fixture_files, dict) or _sha256(
        canonical_json(fixture_files)
    ) != manifest.get("fixture_sha256"):
        raise ScenarioError("Capture fixture hash does not match its file hash map.")
    if not isinstance(manifest.get("query_sha256"), dict):
        raise ScenarioError("Capture query hash map is missing.")
    expected_hashes: dict[str, str] = {}
    for key, result in results.items():
        if not isinstance(result, dict):
            raise ScenarioError("Capture result entry is not an object.")
        if key in ENDPOINT_RESULT_KEYS and result.get("status") == "complete":
            queries = result.get("queries", {})
            for query_name in ("conversations", "observations"):
                query = queries.get(query_name)
                if isinstance(query, dict) and isinstance(query.get("literal"), str):
                    _query_digest(
                        query,
                        f"{key}.{query_name}",
                        f"{key}.{query_name}",
                        expected_hashes,
                    )
                elif query_name == "conversations":
                    raise ScenarioError("Endpoint capture lost its conversation query.")
        elif result.get("query") is not None:
            _query_digest(result["query"], f"{key}.query", key, expected_hashes)
    if expected_hashes != manifest["query_sha256"]:
        raise ScenarioError("Capture query hash map does not match retained literals.")
    return bundle


def _read_json(path: Path) -> Any:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScenarioError("Capture input cannot be read as JSON.") from exc
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario-id", required=True, choices=("track-a-firewall", "track-b-fabric")
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--execution-report", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        scenario = load_scenario(args.scenario_id)
        bundle = build_capture_bundle(
            scenario,
            _read_json(args.plan),
            _read_json(args.execution_report),
            _read_json(args.results),
        )
        verify_capture_bundle(bundle)
        write_once_json(args.output, bundle, max_bytes=MAX_CAPTURE_BYTES)
        return 0
    except ScenarioError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
