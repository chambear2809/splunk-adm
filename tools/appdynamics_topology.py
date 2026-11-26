"""Mapper for official Splunk Add-on for AppDynamics 3.3.0 appdynamics_topology.

Grounded strictly in Splunkbase 3471 (Splunk_TA_AppDynamics 3.3.0)
``bin/appdynamics_topology.py`` (sourcetype ``appdynamics_topology``).

Official ``appdynamics_topology`` emits ``entity`` records (``application``,
``tier``, ``node``, ``backend``, ``service``, ``server``, ``network_interface``,
``database``) and ``relationship`` records (``contains``, ``uses``, ``runs_on``,
``has_interface``) with ``schema_version=1`` and ``source_system="appdynamics"``.

Node IPs are NOT present on ``node`` entities emitted by ``appdynamics_topology``.
They are available only when:
1. AppDynamics Server Visibility (SIM) is licensed and emits ``server`` plus
   ``network_interface`` records linked via ``runs_on`` / ``has_interface``
   (``ipv4_addresses`` / ``ipv6_addresses``), OR
2. An operator supplies node IPs via the external HEC collector
   (``tools/export_appdynamics.py`` + ``tools/import_appdynamics.py``) into
   ``adm:asset_history`` / ``adm:appdynamics_inventory``.
"""

from __future__ import annotations

import ipaddress
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

OFFICIAL_TA_VERSION = "3.3.0"
OFFICIAL_SPLUNKBASE_ID = "3471"
OFFICIAL_SOURCETYPE = "appdynamics_topology"
SCHEMA = "application_atlas.appdynamics_topology_map.v1"

MAX_RECORDS = 100_000
MAX_TEXT_LEN = 2048

ENTITY_KINDS = frozenset(
    {
        "application",
        "tier",
        "service",
        "backend",
        "node",
        "server",
        "network_interface",
        "database",
    }
)
RELATIONSHIP_TYPES = frozenset({"contains", "uses", "runs_on", "has_interface"})


class AppDynamicsTopologyError(ValueError):
    """Raised when official appdynamics_topology records fail validation."""


def _text(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None or value == "":
        if required:
            raise AppDynamicsTopologyError(f"missing_{field}")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise AppDynamicsTopologyError(f"invalid_{field}")
    text = str(value).strip()
    if not text:
        if required:
            raise AppDynamicsTopologyError(f"missing_{field}")
        return None
    if len(text) > MAX_TEXT_LEN or any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise AppDynamicsTopologyError(f"unsafe_{field}")
    return text


def _epoch(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AppDynamicsTopologyError(f"invalid_{field}")
    num = float(value)
    if not math.isfinite(num) or num < 0:
        raise AppDynamicsTopologyError(f"invalid_{field}")
    return num


def _matchable_ips(values: Any) -> list[str]:
    """Normalize valid, matchable IPv4/IPv6 literals from SIM network_interface."""
    if values is None:
        return []
    if not isinstance(values, list):
        raise AppDynamicsTopologyError("invalid_interface_addresses")
    out: list[str] = []
    for raw in values:
        if not isinstance(raw, str):
            raise AppDynamicsTopologyError("invalid_interface_address")
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if (
            parsed.is_unspecified
            or parsed.is_loopback
            or parsed.is_multicast
            or parsed.is_link_local
        ):
            continue
        out.append(str(parsed))
    return sorted(set(out))


def _parse_record(raw: str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            record = json.loads(raw)
        except ValueError as exc:
            raise AppDynamicsTopologyError("invalid_json") from exc
    elif isinstance(raw, Mapping):
        record = dict(raw)
    else:
        raise AppDynamicsTopologyError("invalid_record_type")
    if not isinstance(record, dict):
        raise AppDynamicsTopologyError("invalid_record_object")
    if record.get("schema_version") != 1:
        raise AppDynamicsTopologyError("unsupported_schema_version")
    if record.get("source_system") != "appdynamics":
        raise AppDynamicsTopologyError("unexpected_source_system")

    controller_id = _text(record.get("controller_id"), "controller_id", required=True)
    assert controller_id is not None
    controller_id = controller_id.lower()
    id_namespace = _text(record.get("id_namespace"), "id_namespace", required=True)
    if id_namespace != f"source:appdynamics:{controller_id}":
        raise AppDynamicsTopologyError("id_namespace_mismatch")
    snapshot_id = _text(record.get("snapshot_id"), "snapshot_id", required=True)
    observed_ts = _epoch(record.get("observed_ts"), "observed_ts")
    record_type = _text(record.get("record_type"), "record_type", required=True)
    if record_type not in ("entity", "relationship"):
        raise AppDynamicsTopologyError("unsupported_record_type")

    normalized: dict[str, Any] = {
        "schema_version": 1,
        "source_system": "appdynamics",
        "controller_id": controller_id,
        "id_namespace": id_namespace,
        "snapshot_id": snapshot_id,
        "observed_ts": observed_ts,
        "record_type": record_type,
    }
    if record_type == "entity":
        kind = _text(record.get("entity_kind"), "entity_kind", required=True)
        if kind not in ENTITY_KINDS:
            raise AppDynamicsTopologyError("unsupported_entity_kind")
        entity_id = _text(record.get("entity_id"), "entity_id", required=True)
        name = _text(record.get("name"), "name", required=True)
        normalized.update(
            entity_kind=kind,
            entity_id=entity_id,
            name=name,
            raw=record,
        )
    else:
        rel_type = _text(
            record.get("relationship_type"), "relationship_type", required=True
        )
        if rel_type not in RELATIONSHIP_TYPES:
            raise AppDynamicsTopologyError("unsupported_relationship_type")
        src_kind = _text(
            record.get("src_entity_kind"), "src_entity_kind", required=True
        )
        src_id = _text(record.get("src_entity_id"), "src_entity_id", required=True)
        dst_kind = _text(
            record.get("dst_entity_kind"), "dst_entity_kind", required=True
        )
        dst_id = _text(record.get("dst_entity_id"), "dst_entity_id", required=True)
        if src_kind not in ENTITY_KINDS or dst_kind not in ENTITY_KINDS:
            raise AppDynamicsTopologyError("unsupported_relationship_endpoint_kind")
        normalized.update(
            relationship_type=rel_type,
            src_entity_kind=src_kind,
            src_entity_id=src_id,
            dst_entity_kind=dst_kind,
            dst_entity_id=dst_id,
            properties=record.get("properties")
            if isinstance(record.get("properties"), Mapping)
            else {},
        )
    return normalized


def _extract_backend_candidates(properties: Any) -> list[dict[str, Any]]:
    """Extract safe IP/hostname/port candidates from backend properties."""
    if not isinstance(properties, Mapping):
        return []
    candidates: list[dict[str, Any]] = []
    for key in sorted(properties):
        if not isinstance(key, str) or not key.strip():
            continue
        raw_val = properties[key]
        if raw_val is None or raw_val == "" or isinstance(raw_val, bool):
            continue
        lower = key.lower()
        if "port" in lower and str(raw_val).isdigit():
            port = int(str(raw_val))
            if 1 <= port <= 65535:
                candidates.append({"property": key, "kind": "port", "value": port})
            continue
        if any(token in lower for token in ("host", "ip", "address", "server", "url")):
            val = _text(raw_val, "backend_property")
            if val is None:
                continue
            try:
                parsed = ipaddress.ip_address(val)
            except ValueError:
                candidates.append(
                    {"property": key, "kind": "hostname_unresolved", "value": val}
                )
            else:
                if not (
                    parsed.is_unspecified
                    or parsed.is_loopback
                    or parsed.is_multicast
                    or parsed.is_link_local
                ):
                    candidates.append(
                        {"property": key, "kind": "ip", "value": str(parsed)}
                    )
    return candidates


def map_appdynamics_topology(
    raw_records: Sequence[str | Mapping[str, Any]],
    *,
    expected_controller_id: str | None = None,
    external_node_ips: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Map official AppDynamics 3.3.0 appdynamics_topology records into Atlas topology.

    Selects the single latest snapshot per controller by ``observed_ts`` (failing
    closed on ambiguous snapshot ties). Maps applications, tiers, nodes, and
    backends, and joins SIM ``server`` / ``network_interface`` records when
    present.

    ``external_node_ips`` may optionally provide a mapping of ``node_id`` ->
    list of IP strings sourced from the external HEC collector
    (``tools/export_appdynamics.py`` + ``tools/import_appdynamics.py`` /
    ``adm:asset_history``) when SIM is not licensed.
    """
    if len(raw_records) > MAX_RECORDS:
        raise AppDynamicsTopologyError("record_limit_exceeded")
    parsed = [_parse_record(item) for item in raw_records]
    if expected_controller_id is not None:
        wanted = expected_controller_id.strip().lower()
        parsed = [row for row in parsed if row["controller_id"] == wanted]
    if not parsed:
        raise AppDynamicsTopologyError("no_topology_records")

    controllers = sorted({row["controller_id"] for row in parsed})
    if len(controllers) != 1:
        raise AppDynamicsTopologyError("ambiguous_controller_id")
    controller_id = controllers[0]

    latest_ts = max(row["observed_ts"] for row in parsed)
    latest_rows = [row for row in parsed if row["observed_ts"] == latest_ts]
    snapshot_ids = {row["snapshot_id"] for row in latest_rows}
    if len(snapshot_ids) != 1:
        raise AppDynamicsTopologyError("ambiguous_latest_snapshot")
    snapshot_id = next(iter(snapshot_ids))
    snapshot_rows = [row for row in parsed if row["snapshot_id"] == snapshot_id]

    entities: dict[tuple[str, str], dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []
    seen_rels: set[tuple[str, str, str, str, str]] = set()
    for row in snapshot_rows:
        if row["record_type"] == "entity":
            key = (row["entity_kind"], row["entity_id"])
            prior = entities.get(key)
            if prior is not None:
                if prior["raw"] != row["raw"]:
                    raise AppDynamicsTopologyError("conflicting_duplicate_entity")
                continue
            entities[key] = row
        else:
            rel_key = (
                row["relationship_type"],
                row["src_entity_kind"],
                row["src_entity_id"],
                row["dst_entity_kind"],
                row["dst_entity_id"],
            )
            if rel_key not in seen_rels:
                seen_rels.add(rel_key)
                relationships.append(row)

    # Index SIM server -> network_interface IPs via both explicit has_interface
    # relationships and server_id on network_interface entities.
    server_interfaces: dict[str, set[str]] = {}
    for (_, if_id), item in entities.items():
        if item["entity_kind"] != "network_interface":
            continue
        srv_id = _text(item["raw"].get("server_id"), "server_id")
        if srv_id:
            server_interfaces.setdefault(srv_id, set()).add(if_id)
    for rel in relationships:
        if (
            rel["relationship_type"] == "has_interface"
            and rel["src_entity_kind"] == "server"
            and rel["dst_entity_kind"] == "network_interface"
        ):
            server_interfaces.setdefault(rel["src_entity_id"], set()).add(
                rel["dst_entity_id"]
            )

    node_servers: dict[str, set[str]] = {}
    for rel in relationships:
        if (
            rel["relationship_type"] == "runs_on"
            and rel["src_entity_kind"] == "node"
            and rel["dst_entity_kind"] == "server"
        ):
            node_servers.setdefault(rel["src_entity_id"], set()).add(
                rel["dst_entity_id"]
            )

    apps_by_id: dict[str, dict[str, Any]] = {}
    for (_, app_id), item in sorted(entities.items()):
        if item["entity_kind"] != "application":
            continue
        apps_by_id[app_id] = {
            "id": app_id,
            "name": item["name"],
            "tiers": [],
            "backends": [],
        }

    tiers_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for (_, tier_id), item in sorted(entities.items()):
        if item["entity_kind"] != "tier":
            continue
        app_id = _text(item["raw"].get("application_id"), "application_id")
        if app_id not in apps_by_id:
            raise AppDynamicsTopologyError("tier_missing_application")
        tier = {"id": tier_id, "name": item["name"], "nodes": []}
        tiers_by_key[(app_id, tier_id)] = tier
        apps_by_id[app_id]["tiers"].append(tier)

    verified_nodes: set[tuple[str, str, str]] = set()
    node_count = 0
    nodes_with_sim_ips = 0
    nodes_with_external_ips = 0
    nodes_without_ips = 0

    for (_, node_id), item in sorted(entities.items()):
        if item["entity_kind"] != "node":
            continue
        raw = item["raw"]
        app_id = _text(raw.get("application_id"), "application_id")
        tier_id = _text(raw.get("tier_id"), "tier_id")
        if app_id not in apps_by_id or (app_id, tier_id) not in tiers_by_key:
            raise AppDynamicsTopologyError("node_missing_tier")
        props = (
            raw.get("properties") if isinstance(raw.get("properties"), Mapping) else {}
        )
        machine_id = _text(raw.get("machine_id"), "machine_id")
        server_ids = set(node_servers.get(node_id, set()))
        if machine_id:
            server_ids.add(machine_id)

        sim_ips: set[str] = set()
        for srv_id in sorted(server_ids):
            for if_id in sorted(server_interfaces.get(srv_id, set())):
                iface = entities.get(("network_interface", if_id))
                if not iface:
                    continue
                sim_ips.update(_matchable_ips(iface["raw"].get("ipv4_addresses")))
                sim_ips.update(_matchable_ips(iface["raw"].get("ipv6_addresses")))

        ext_ips = (
            set(_matchable_ips(list(external_node_ips[node_id])))
            if external_node_ips and node_id in external_node_ips
            else set()
        )
        if sim_ips and ext_ips:
            addresses = sorted(sim_ips | ext_ips)
            ip_source = "sim_and_external_hec"
            nodes_with_sim_ips += 1
            nodes_with_external_ips += 1
        elif sim_ips:
            addresses = sorted(sim_ips)
            ip_source = "sim_network_interface"
            nodes_with_sim_ips += 1
        elif ext_ips:
            addresses = sorted(ext_ips)
            ip_source = "external_hec_collector"
            nodes_with_external_ips += 1
        else:
            addresses = []
            ip_source = "not_reported_by_topology_input"
            nodes_without_ips += 1

        node_count += 1
        verified_nodes.add((app_id, tier_id, node_id))
        machine_name = _text(props.get("machineName"), "machineName")
        node_entry: dict[str, Any] = {
            "id": node_id,
            "name": item["name"],
            "addresses": addresses,
            "ip_source": ip_source,
        }
        if machine_id:
            node_entry["machine_id"] = machine_id
        if machine_name:
            node_entry["machine"] = machine_name
        if _text(props.get("agentType"), "agentType"):
            node_entry["agent_type"] = _text(props.get("agentType"), "agentType")
        tiers_by_key[(app_id, tier_id)]["nodes"].append(node_entry)

    backend_count = 0
    for (_, backend_entity_id), item in sorted(entities.items()):
        if item["entity_kind"] != "backend":
            continue
        raw = item["raw"]
        app_id = _text(raw.get("application_id"), "application_id")
        if app_id not in apps_by_id:
            raise AppDynamicsTopologyError("backend_missing_application")
        backend_id = _text(raw.get("backend_id"), "backend_id", required=True)
        reported_tier_id = _text(raw.get("tier_id"), "tier_id")
        reported_node_id = _text(
            raw.get("application_component_node_id"), "application_component_node_id"
        )
        # Positive IDs matching a node in this same snapshot verify association.
        if (
            reported_tier_id
            and reported_node_id
            and reported_tier_id != "0"
            and reported_node_id != "0"
        ):
            if (app_id, reported_tier_id, reported_node_id) in verified_nodes:
                association_status = "verified_node"
            else:
                association_status = "unverified_reported_ids"
        else:
            association_status = "application_scope_only"
        backend_entry: dict[str, Any] = {
            "id": backend_id,
            "entity_id": backend_entity_id,
            "name": item["name"],
            "association_status": association_status,
            "endpoint_candidates": _extract_backend_candidates(raw.get("properties")),
        }
        backend_type = _text(raw.get("backend_type"), "backend_type")
        if backend_type:
            backend_entry["exit_point_type"] = backend_type
        if reported_tier_id:
            backend_entry["reported_tier_id"] = reported_tier_id
        if reported_node_id:
            backend_entry["reported_application_component_node_id"] = reported_node_id
        apps_by_id[app_id]["backends"].append(backend_entry)
        backend_count += 1

    return {
        "schema": SCHEMA,
        "source_mode": "official_appdynamics_topology",
        "ta": "Splunk_TA_AppDynamics",
        "ta_version": OFFICIAL_TA_VERSION,
        "splunkbase_id": OFFICIAL_SPLUNKBASE_ID,
        "sourcetype": OFFICIAL_SOURCETYPE,
        "controller_id": controller_id,
        "id_namespace": f"source:appdynamics:{controller_id}",
        "snapshot_id": snapshot_id,
        "observed_ts": latest_ts,
        "application_count": len(apps_by_id),
        "tier_count": len(tiers_by_key),
        "node_count": node_count,
        "backend_count": backend_count,
        "node_ip_coverage": {
            "sim_network_interface": nodes_with_sim_ips,
            "external_hec_collector": nodes_with_external_ips,
            "missing": nodes_without_ips,
            "node_ip_gap": nodes_without_ips > 0,
            "remediation": (
                "Official appdynamics_topology does not emit IP addresses on node entities. "
                "Enable AppDynamics SIM (server + network_interface) or supply node IPs via "
                "tools/export_appdynamics.py + tools/import_appdynamics.py (adm:asset_history)."
                if nodes_without_ips > 0
                else None
            ),
        },
        "applications": list(apps_by_id.values()),
    }
